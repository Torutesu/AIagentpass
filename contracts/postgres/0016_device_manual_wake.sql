BEGIN;

-- A manual wake is a delivery hint only.  It is deliberately stored outside
-- the authority-generation, bundle, outbox, and ACK mutation paths.  One row
-- represents the coalesced wake event for one device and desired generation;
-- the request table below retains the per-idempotency-key replay evidence.
CREATE TABLE device_manual_wake_events (
  organization_id uuid NOT NULL,
  device_id uuid NOT NULL,
  desired_generation bigint NOT NULL CHECK (desired_generation > 0),
  active_outbox_id uuid,
  wake_count integer NOT NULL DEFAULT 1 CHECK (wake_count BETWEEN 1 AND 1000),
  first_requested_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  last_requested_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  last_actor_id uuid NOT NULL,
  PRIMARY KEY (organization_id, device_id, desired_generation),
  FOREIGN KEY (organization_id, device_id) REFERENCES devices(organization_id, id),
  FOREIGN KEY (organization_id, desired_generation)
    REFERENCES control_plane_authority_generations(organization_id, generation),
  FOREIGN KEY (organization_id, last_actor_id)
    REFERENCES memberships(organization_id, member_id),
  CHECK (last_requested_at >= first_requested_at)
);

CREATE INDEX device_manual_wake_events_active_lookup
  ON device_manual_wake_events (organization_id, device_id, desired_generation, active_outbox_id);

-- The request row is the replay ledger.  active_outbox_id is intentionally
-- historical evidence without an FK: the refresh outbox is retention-managed,
-- while an exact idempotent replay must remain reproducible after retention.
CREATE TABLE device_manual_wake_requests (
  organization_id uuid NOT NULL,
  device_id uuid NOT NULL,
  actor_id uuid NOT NULL,
  idempotency_key text NOT NULL
    CHECK (idempotency_key ~ '^[A-Za-z0-9._~-]{8,255}$'),
  request_id uuid NOT NULL,
  body_digest bytea NOT NULL CHECK (octet_length(body_digest) = 32),
  desired_generation bigint NOT NULL CHECK (desired_generation > 0),
  active_outbox_id uuid,
  result text NOT NULL CHECK (result IN ('accepted', 'coalesced', 'no_pending_refresh')),
  requested_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  response_json jsonb NOT NULL CHECK (jsonb_typeof(response_json) = 'object'),
  PRIMARY KEY (organization_id, actor_id, idempotency_key),
  UNIQUE (organization_id, request_id),
  FOREIGN KEY (organization_id, device_id) REFERENCES devices(organization_id, id),
  FOREIGN KEY (organization_id, desired_generation)
    REFERENCES control_plane_authority_generations(organization_id, generation),
  FOREIGN KEY (organization_id, actor_id)
    REFERENCES memberships(organization_id, member_id)
);

CREATE INDEX device_manual_wake_requests_device_lookup
  ON device_manual_wake_requests (organization_id, device_id, desired_generation, requested_at, request_id);

-- A direct SQL writer cannot smuggle a non-active or cross-device outbox id
-- into the coalesced event.  The repository performs the same check while it
-- holds the device-state and outbox locks; this trigger protects other writers.
CREATE FUNCTION agentpass_validate_device_manual_wake_event()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF NEW.active_outbox_id IS NOT NULL AND NOT EXISTS (
    SELECT 1
    FROM device_refresh_outbox AS outbox
    WHERE outbox.organization_id = NEW.organization_id
      AND outbox.outbox_id = NEW.active_outbox_id
      AND outbox.device_id = NEW.device_id
      AND outbox.desired_generation = NEW.desired_generation
      AND outbox.status IN ('pending', 'delivered')
  ) THEN
    RAISE EXCEPTION USING
      ERRCODE = 'foreign_key_violation',
      MESSAGE = 'manual wake active outbox is not pending or delivered';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER device_manual_wake_events_validate
  BEFORE INSERT OR UPDATE OF active_outbox_id, device_id, desired_generation
  ON device_manual_wake_events
  FOR EACH ROW
  EXECUTE FUNCTION agentpass_validate_device_manual_wake_event();

-- Keep the event's active outbox pointer current without rewriting any
-- authority or delivery data.  This also allows normal outbox retention to
-- remove terminal rows without leaving a misleading current pointer.
CREATE FUNCTION agentpass_clear_device_manual_wake_outbox()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF (TG_OP = 'DELETE') OR OLD.status IN ('pending', 'delivered') AND NEW.status NOT IN ('pending', 'delivered') THEN
    UPDATE device_manual_wake_events
    SET active_outbox_id = NULL
    WHERE organization_id = OLD.organization_id
      AND device_id = OLD.device_id
      AND desired_generation = OLD.desired_generation
      AND active_outbox_id = OLD.outbox_id;
  END IF;
  IF TG_OP = 'DELETE' THEN
    RETURN OLD;
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER device_refresh_outbox_clear_manual_wake
  AFTER UPDATE OF status OR DELETE ON device_refresh_outbox
  FOR EACH ROW
  EXECUTE FUNCTION agentpass_clear_device_manual_wake_outbox();

-- PostgreSQL queues NOTIFY messages until the surrounding transaction
-- commits.  The payload is only routing metadata; listeners must re-query
-- authoritative state.  A notification is useful only while the desired
-- generation is ahead of observed state and a live authority outbox exists.
CREATE FUNCTION agentpass_notify_device_manual_wake()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF NEW.active_outbox_id IS NULL
     OR NOT EXISTS (
       SELECT 1
       FROM device_control_plane_state AS state
       WHERE state.organization_id = NEW.organization_id
         AND state.device_id = NEW.device_id
         AND state.desired_generation = NEW.desired_generation
         AND (state.observed_generation IS NULL OR state.observed_generation < state.desired_generation)
     )
     OR NOT EXISTS (
       SELECT 1
       FROM device_refresh_outbox AS outbox
       WHERE outbox.organization_id = NEW.organization_id
         AND outbox.outbox_id = NEW.active_outbox_id
         AND outbox.device_id = NEW.device_id
         AND outbox.desired_generation = NEW.desired_generation
         AND outbox.status IN ('pending', 'delivered')
     ) THEN
    RETURN NEW;
  END IF;

  -- This is intentionally the same channel used by the device refresh
  -- listener.  pg_notify itself is not visible to listeners before COMMIT.
  PERFORM pg_notify('agentpass_refresh_hint_v1', json_build_object(
    'organization_id', NEW.organization_id,
    'device_id', NEW.device_id,
    'desired_generation', NEW.desired_generation
  )::text);
  RETURN NEW;
END;
$$;

CREATE TRIGGER device_manual_wake_events_notify
  AFTER INSERT OR UPDATE OF wake_count, last_requested_at, last_actor_id, active_outbox_id
  ON device_manual_wake_events
  FOR EACH ROW
  EXECUTE FUNCTION agentpass_notify_device_manual_wake();

COMMIT;
