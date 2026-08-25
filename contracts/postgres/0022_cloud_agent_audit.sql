BEGIN;

-- Cloud-origin consumption evidence has its own chain.  It is intentionally
-- independent from the device-origin chain so a Cloud transaction cannot
-- rewrite, seed, or advance device-origin audit state.
CREATE TABLE cloud_agent_audit_events (
  organization_id uuid NOT NULL REFERENCES organizations(id),
  event_id uuid NOT NULL,
  sequence bigint NOT NULL CHECK (sequence > 0),
  event_type text NOT NULL CHECK (event_type = 'agent_session_grant.consumed'),
  grant_id uuid NOT NULL,
  session_id uuid NOT NULL,
  device_id uuid NOT NULL,
  agent_id uuid NOT NULL,
  grant_hash text NOT NULL CHECK (grant_hash ~ '^[0-9a-f]{64}$'),
  statement_hash text NOT NULL CHECK (statement_hash ~ '^[0-9a-f]{64}$'),
  signer_key_id text NOT NULL CHECK (signer_key_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$'),
  process_binding_sha256 text NOT NULL CHECK (process_binding_sha256 ~ '^[0-9a-f]{64}$'),
  ancestry_binding_sha256 text NOT NULL CHECK (ancestry_binding_sha256 ~ '^[0-9a-f]{64}$'),
  worktree_binding_sha256 text NOT NULL CHECK (worktree_binding_sha256 ~ '^[0-9a-f]{64}$'),
  control_sequence bigint NOT NULL CHECK (control_sequence > 0),
  authority_generation bigint NOT NULL CHECK (authority_generation > 0),
  consumed_at timestamptz NOT NULL,
  previous_hash text NOT NULL CHECK (previous_hash ~ '^[0-9a-f]{64}$'),
  event_hash text NOT NULL CHECK (event_hash ~ '^[0-9a-f]{64}$'),
  recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (organization_id, event_id),
  UNIQUE (organization_id, sequence),
  UNIQUE (organization_id, event_hash),
  UNIQUE (organization_id, grant_id),
  FOREIGN KEY (organization_id, grant_id, device_id, agent_id, grant_hash)
    REFERENCES agent_session_grants(organization_id, grant_id, device_id, agent_id, grant_hash),
  FOREIGN KEY (organization_id, session_id, grant_id, device_id)
    REFERENCES agent_sessions(organization_id, session_id, grant_id, device_id)
);

CREATE TABLE cloud_agent_audit_heads (
  organization_id uuid NOT NULL REFERENCES organizations(id),
  sequence bigint NOT NULL DEFAULT 0 CHECK (sequence >= 0),
  last_event_id uuid,
  last_event_hash text NOT NULL DEFAULT repeat('0', 64)
    CHECK (last_event_hash ~ '^[0-9a-f]{64}$'),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (organization_id),
  FOREIGN KEY (organization_id, last_event_id)
    REFERENCES cloud_agent_audit_events(organization_id, event_id),
  CHECK (
    (sequence = 0 AND last_event_id IS NULL AND last_event_hash = repeat('0', 64))
    OR (sequence > 0 AND last_event_id IS NOT NULL)
  )
);

-- Serialize appends per tenant and require both the next sequence and the
-- exact predecessor hash.  The head row is created lazily for organizations
-- that have not yet consumed a Grant.
CREATE FUNCTION agentpass_validate_cloud_agent_audit_chain()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
DECLARE
  head cloud_agent_audit_heads%ROWTYPE;
BEGIN
  INSERT INTO cloud_agent_audit_heads (organization_id)
  VALUES (NEW.organization_id)
  ON CONFLICT (organization_id) DO NOTHING;

  SELECT * INTO head
  FROM cloud_agent_audit_heads
  WHERE organization_id = NEW.organization_id
  FOR UPDATE;

  IF NEW.sequence <> head.sequence + 1
     OR NEW.previous_hash <> head.last_event_hash THEN
    RAISE EXCEPTION USING
      ERRCODE = 'check_violation',
      MESSAGE = 'cloud agent audit chain predecessor is invalid',
      CONSTRAINT = 'cloud_agent_audit_events_chain_continuity';
  END IF;

  RETURN NEW;
END;
$$;

CREATE FUNCTION agentpass_record_cloud_agent_audit_head()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
  UPDATE cloud_agent_audit_heads
  SET sequence = NEW.sequence,
      last_event_id = NEW.event_id,
      last_event_hash = NEW.event_hash,
      updated_at = clock_timestamp()
  WHERE organization_id = NEW.organization_id;
  RETURN NEW;
END;
$$;

CREATE TRIGGER cloud_agent_audit_events_validate_chain
  BEFORE INSERT ON cloud_agent_audit_events
  FOR EACH ROW
  EXECUTE FUNCTION agentpass_validate_cloud_agent_audit_chain();

CREATE TRIGGER cloud_agent_audit_events_record_head
  AFTER INSERT ON cloud_agent_audit_events
  FOR EACH ROW
  EXECUTE FUNCTION agentpass_record_cloud_agent_audit_head();

CREATE FUNCTION agentpass_guard_cloud_agent_audit_event_append_only()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
  RAISE EXCEPTION USING
    ERRCODE = 'check_violation',
    MESSAGE = 'cloud agent audit events are append-only',
    CONSTRAINT = 'cloud_agent_audit_events_append_only';
END;
$$;

CREATE TRIGGER cloud_agent_audit_events_append_only
  BEFORE UPDATE OR DELETE ON cloud_agent_audit_events
  FOR EACH ROW
  EXECUTE FUNCTION agentpass_guard_cloud_agent_audit_event_append_only();

CREATE FUNCTION agentpass_guard_cloud_agent_audit_head()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION USING
      ERRCODE = 'check_violation',
      MESSAGE = 'cloud agent audit heads cannot be deleted',
      CONSTRAINT = 'cloud_agent_audit_heads_forward_only';
  END IF;
  IF NEW.organization_id <> OLD.organization_id
     OR NEW.sequence <> OLD.sequence + 1
     OR NOT EXISTS (
       SELECT 1 FROM cloud_agent_audit_events event
       WHERE event.organization_id = NEW.organization_id
         AND event.event_id = NEW.last_event_id
         AND event.sequence = NEW.sequence
         AND event.event_hash = NEW.last_event_hash
         AND event.previous_hash = OLD.last_event_hash
     ) THEN
    RAISE EXCEPTION USING
      ERRCODE = 'check_violation',
      MESSAGE = 'cloud agent audit heads advance only through a committed event',
      CONSTRAINT = 'cloud_agent_audit_heads_forward_only';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER cloud_agent_audit_heads_forward_only
  BEFORE UPDATE OR DELETE ON cloud_agent_audit_heads
  FOR EACH ROW
  EXECUTE FUNCTION agentpass_guard_cloud_agent_audit_head();

ALTER TABLE cloud_agent_audit_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE cloud_agent_audit_events FORCE ROW LEVEL SECURITY;

CREATE POLICY cloud_agent_audit_events_tenant_select
  ON cloud_agent_audit_events FOR SELECT
  USING (organization_id = agentpass_current_organization_id());

CREATE POLICY cloud_agent_audit_events_tenant_insert
  ON cloud_agent_audit_events FOR INSERT
  WITH CHECK (organization_id = agentpass_current_organization_id());

CREATE POLICY cloud_agent_audit_events_tenant_update
  ON cloud_agent_audit_events FOR UPDATE
  USING (organization_id = agentpass_current_organization_id())
  WITH CHECK (organization_id = agentpass_current_organization_id());

CREATE POLICY cloud_agent_audit_events_tenant_delete
  ON cloud_agent_audit_events FOR DELETE
  USING (organization_id = agentpass_current_organization_id());

ALTER TABLE cloud_agent_audit_heads ENABLE ROW LEVEL SECURITY;
ALTER TABLE cloud_agent_audit_heads FORCE ROW LEVEL SECURITY;

CREATE POLICY cloud_agent_audit_heads_tenant_select
  ON cloud_agent_audit_heads FOR SELECT
  USING (organization_id = agentpass_current_organization_id());

CREATE POLICY cloud_agent_audit_heads_tenant_insert
  ON cloud_agent_audit_heads FOR INSERT
  WITH CHECK (organization_id = agentpass_current_organization_id());

CREATE POLICY cloud_agent_audit_heads_tenant_update
  ON cloud_agent_audit_heads FOR UPDATE
  USING (organization_id = agentpass_current_organization_id())
  WITH CHECK (organization_id = agentpass_current_organization_id());

CREATE POLICY cloud_agent_audit_heads_tenant_delete
  ON cloud_agent_audit_heads FOR DELETE
  USING (organization_id = agentpass_current_organization_id());

COMMIT;
