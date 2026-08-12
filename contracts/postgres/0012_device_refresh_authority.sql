BEGIN;

-- G4.1 keeps authority generations as append-only rows.  Device state can
-- therefore refer to both its desired generation and an older observed
-- generation without weakening the tenant boundary or rewriting history.
CREATE TABLE control_plane_authority_generations (
  organization_id uuid NOT NULL,
  generation bigint NOT NULL CHECK (generation > 0),
  issued_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  superseded_at timestamptz,
  PRIMARY KEY (organization_id, generation),
  FOREIGN KEY (organization_id) REFERENCES organizations(id),
  CHECK (superseded_at IS NULL OR superseded_at >= issued_at)
);

CREATE UNIQUE INDEX control_plane_authority_current
  ON control_plane_authority_generations (organization_id)
  WHERE superseded_at IS NULL;

CREATE FUNCTION agentpass_guard_authority_generation_insert()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  latest_generation bigint;
BEGIN
  SELECT generation INTO latest_generation
  FROM control_plane_authority_generations
  WHERE organization_id = NEW.organization_id
  ORDER BY generation DESC
  LIMIT 1;

  IF NEW.generation <> COALESCE(latest_generation, 0) + 1 THEN
    RAISE EXCEPTION USING
      ERRCODE = 'check_violation',
      MESSAGE = 'authority generation must advance by exactly one',
      CONSTRAINT = 'control_plane_authority_generations_monotonic';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER control_plane_authority_generations_monotonic
  BEFORE INSERT ON control_plane_authority_generations
  FOR EACH ROW
  EXECUTE FUNCTION agentpass_guard_authority_generation_insert();

CREATE FUNCTION agentpass_guard_authority_generation_update()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF NEW.organization_id <> OLD.organization_id OR NEW.generation <> OLD.generation THEN
    RAISE EXCEPTION USING
      ERRCODE = 'check_violation',
      MESSAGE = 'authority generation identity is immutable',
      CONSTRAINT = 'control_plane_authority_generations_immutable';
  END IF;
  IF OLD.superseded_at IS NOT NULL AND NEW.superseded_at IS NULL THEN
    RAISE EXCEPTION USING
      ERRCODE = 'check_violation',
      MESSAGE = 'authority generation cannot be made current again',
      CONSTRAINT = 'control_plane_authority_generations_forward_only';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER control_plane_authority_generations_forward_only
  BEFORE UPDATE ON control_plane_authority_generations
  FOR EACH ROW
  EXECUTE FUNCTION agentpass_guard_authority_generation_update();

INSERT INTO control_plane_authority_generations (organization_id, generation)
SELECT id, 1
FROM organizations
ORDER BY id;

CREATE FUNCTION agentpass_advance_authority_generation(
  request_organization_id uuid,
  request_issued_at timestamptz DEFAULT clock_timestamp()
)
RETURNS TABLE (organization_id uuid, generation bigint)
LANGUAGE plpgsql
VOLATILE
AS $$
DECLARE
  current_generation bigint;
  next_generation bigint;
BEGIN
  PERFORM pg_advisory_xact_lock(hashtextextended(
    'agentpass:authority-generation:' || request_organization_id::text, 0));

  PERFORM 1 FROM organizations WHERE id = request_organization_id FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE = 'foreign_key_violation', MESSAGE = 'organization was not found';
  END IF;

  SELECT generation INTO current_generation
  FROM control_plane_authority_generations
  WHERE organization_id = request_organization_id
  ORDER BY generation DESC
  LIMIT 1
  FOR UPDATE;

  next_generation := COALESCE(current_generation, 0) + 1;
  UPDATE control_plane_authority_generations
  SET superseded_at = COALESCE(superseded_at, request_issued_at)
  WHERE organization_id = request_organization_id
    AND superseded_at IS NULL;

  INSERT INTO control_plane_authority_generations (organization_id, generation, issued_at)
  VALUES (request_organization_id, next_generation, request_issued_at);

  RETURN QUERY SELECT request_organization_id, next_generation;
END;
$$;

-- Key epochs are also append-only.  ACKs remain verifiable after a device
-- rotates its key, while every ACK is still tenant- and epoch-qualified.
CREATE TABLE device_key_epochs (
  organization_id uuid NOT NULL,
  device_id uuid NOT NULL,
  key_epoch bigint NOT NULL CHECK (key_epoch > 0),
  key_algorithm text NOT NULL CHECK (key_algorithm IN ('p256-sha256', 'ed25519')),
  public_key_pem text NOT NULL,
  status text NOT NULL CHECK (status IN ('active', 'retired')),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  retired_at timestamptz,
  PRIMARY KEY (organization_id, device_id, key_epoch),
  FOREIGN KEY (organization_id, device_id) REFERENCES devices(organization_id, id),
  CHECK ((status = 'active' AND retired_at IS NULL) OR (status = 'retired' AND retired_at IS NOT NULL)),
  CHECK (retired_at IS NULL OR retired_at >= created_at),
  CHECK (octet_length(public_key_pem) BETWEEN 64 AND 8192),
  CHECK (public_key_pem LIKE '-----BEGIN PUBLIC KEY-----%'),
  CHECK (public_key_pem LIKE '%-----END PUBLIC KEY-----'),
  CHECK (public_key_pem !~ 'PRIVATE[[:space:]]+KEY'),
  CHECK (public_key_pem ~ E'^-----BEGIN PUBLIC KEY-----\n[A-Za-z0-9+/=\n]+\n-----END PUBLIC KEY-----$'),
  CHECK (octet_length(decode(
    replace(regexp_replace(regexp_replace(public_key_pem,
      E'^-----BEGIN PUBLIC KEY-----\n', ''),
      E'\n-----END PUBLIC KEY-----$', ''), E'\n', ''),
    'base64')) BETWEEN 32 AND 4096),
  CHECK (replace(public_key_pem, E'\n', '') !~ '[[:cntrl:]]')
);

CREATE UNIQUE INDEX device_key_epochs_current
  ON device_key_epochs (organization_id, device_id)
  WHERE status = 'active';

CREATE FUNCTION agentpass_guard_device_key_epoch_insert()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  latest_epoch bigint;
BEGIN
  SELECT key_epoch INTO latest_epoch
  FROM device_key_epochs
  WHERE organization_id = NEW.organization_id AND device_id = NEW.device_id
  ORDER BY key_epoch DESC
  LIMIT 1;
  IF NEW.key_epoch <> COALESCE(latest_epoch, 0) + 1 THEN
    RAISE EXCEPTION USING
      ERRCODE = 'check_violation',
      MESSAGE = 'device key epoch must advance by exactly one',
      CONSTRAINT = 'device_key_epochs_monotonic';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER device_key_epochs_monotonic
  BEFORE INSERT ON device_key_epochs
  FOR EACH ROW
  EXECUTE FUNCTION agentpass_guard_device_key_epoch_insert();

CREATE FUNCTION agentpass_guard_device_key_epoch_update()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF NEW.organization_id <> OLD.organization_id
     OR NEW.device_id <> OLD.device_id
     OR NEW.key_epoch <> OLD.key_epoch
     OR NEW.key_algorithm <> OLD.key_algorithm
     OR NEW.public_key_pem <> OLD.public_key_pem
     OR NEW.created_at <> OLD.created_at THEN
    RAISE EXCEPTION USING
      ERRCODE = 'check_violation',
      MESSAGE = 'device key epoch identity is immutable',
      CONSTRAINT = 'device_key_epochs_forward_only';
  END IF;
  IF OLD.status = 'retired' THEN
    IF NEW.status <> OLD.status OR NEW.retired_at <> OLD.retired_at THEN
      RAISE EXCEPTION USING
        ERRCODE = 'check_violation',
        MESSAGE = 'retired device key epochs cannot be reopened or rewritten',
        CONSTRAINT = 'device_key_epochs_forward_only';
    END IF;
  ELSIF OLD.status = 'active' AND NEW.status = 'retired' THEN
    IF NEW.retired_at IS NULL THEN
      RAISE EXCEPTION USING
        ERRCODE = 'check_violation',
        MESSAGE = 'retiring a device key epoch requires retired_at',
        CONSTRAINT = 'device_key_epochs_forward_only';
    END IF;
  ELSIF NEW.status <> OLD.status THEN
    RAISE EXCEPTION USING
      ERRCODE = 'check_violation',
      MESSAGE = 'device key epoch status only moves from active to retired',
      CONSTRAINT = 'device_key_epochs_forward_only';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER device_key_epochs_forward_only
  BEFORE UPDATE ON device_key_epochs
  FOR EACH ROW
  EXECUTE FUNCTION agentpass_guard_device_key_epoch_update();

INSERT INTO device_key_epochs (organization_id, device_id, key_epoch, key_algorithm, public_key_pem, status)
SELECT organization_id, id, 1, key_algorithm, public_key_pem, 'active'
FROM devices
WHERE status = 'active' AND key_algorithm IS NOT NULL AND public_key_pem IS NOT NULL
ORDER BY organization_id, id;

CREATE TABLE device_control_plane_state (
  organization_id uuid NOT NULL,
  device_id uuid NOT NULL,
  desired_generation bigint NOT NULL CHECK (desired_generation > 0),
  observed_generation bigint,
  refresh_state text NOT NULL CHECK (refresh_state IN ('pending', 'fetching', 'applied', 'blocked', 'stale', 'offline', 'revoked')),
  refresh_requested_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  last_delivered_at timestamptz,
  last_observed_at timestamptz,
  last_error_code text,
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (organization_id, device_id),
  FOREIGN KEY (organization_id, device_id) REFERENCES devices(organization_id, id),
  FOREIGN KEY (organization_id, desired_generation)
    REFERENCES control_plane_authority_generations(organization_id, generation),
  FOREIGN KEY (organization_id, observed_generation)
    REFERENCES control_plane_authority_generations(organization_id, generation),
  CHECK (observed_generation IS NULL OR observed_generation <= desired_generation),
  CHECK (char_length(COALESCE(last_error_code, '')) <= 128),
  CHECK (last_error_code IS NULL OR last_error_code !~ '[[:cntrl:]]'),
  CHECK (refresh_state <> 'applied' OR observed_generation IS NOT NULL),
  CHECK (last_delivered_at IS NULL OR last_delivered_at >= refresh_requested_at),
  CHECK (last_observed_at IS NULL OR last_observed_at >= refresh_requested_at)
);

CREATE FUNCTION agentpass_guard_device_control_plane_state()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF TG_OP = 'UPDATE' THEN
    IF NEW.desired_generation < OLD.desired_generation
       OR (OLD.observed_generation IS NOT NULL
           AND (NEW.observed_generation IS NULL OR NEW.observed_generation < OLD.observed_generation)) THEN
      RAISE EXCEPTION USING
        ERRCODE = 'check_violation',
        MESSAGE = 'device control-plane generations cannot move backwards',
        CONSTRAINT = 'device_control_plane_state_monotonic';
    END IF;
  END IF;
  IF NEW.observed_generation IS NOT NULL AND NEW.observed_generation > NEW.desired_generation THEN
    RAISE EXCEPTION USING
      ERRCODE = 'check_violation',
      MESSAGE = 'observed generation cannot exceed desired generation',
      CONSTRAINT = 'device_control_plane_state_ordered';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER device_control_plane_state_monotonic
  BEFORE INSERT OR UPDATE ON device_control_plane_state
  FOR EACH ROW
  EXECUTE FUNCTION agentpass_guard_device_control_plane_state();

INSERT INTO device_control_plane_state (organization_id, device_id, desired_generation, refresh_state)
SELECT d.organization_id, d.id, a.generation, 'pending'
FROM devices d
JOIN control_plane_authority_generations a
  ON a.organization_id = d.organization_id AND a.superseded_at IS NULL
ORDER BY d.organization_id, d.id;

-- bundle_heads is a mutable pointer. Durable refresh and ACK evidence targets
-- this append-only history table instead of the current pointer.
CREATE TABLE control_bundle_statements (
  organization_id uuid NOT NULL,
  device_id uuid NOT NULL,
  format_epoch integer NOT NULL CHECK (format_epoch = 2),
  sequence bigint NOT NULL CHECK (sequence > 0),
  statement_hash text NOT NULL CHECK (statement_hash ~ '^[0-9a-f]{64}$'),
  authority_generation bigint NOT NULL CHECK (authority_generation > 0),
  issued_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  PRIMARY KEY (organization_id, device_id, format_epoch, sequence, statement_hash),
  UNIQUE (organization_id, device_id, format_epoch, sequence),
  FOREIGN KEY (organization_id, device_id) REFERENCES devices(organization_id, id),
  FOREIGN KEY (organization_id, authority_generation)
    REFERENCES control_plane_authority_generations(organization_id, generation),
  CHECK (expires_at > issued_at)
);

INSERT INTO control_bundle_statements
  (organization_id, device_id, format_epoch, sequence, statement_hash, authority_generation, issued_at, expires_at)
SELECT h.organization_id, h.device_id, h.format_epoch, h.sequence, h.statement_hash,
  generation.generation, h.issued_at, h.expires_at
FROM bundle_heads h
JOIN control_plane_authority_generations generation
  ON generation.organization_id = h.organization_id
 AND generation.superseded_at IS NULL
ON CONFLICT (organization_id, device_id, format_epoch, sequence) DO NOTHING;

-- 0011 attached legacy ACKs directly to bundle_heads. That FK makes a normal
-- current-head UPDATE impossible once an ACK exists. The history backfill is
-- complete and the old constraint can now be removed in the same transaction;
-- validate the replacement FK before exposing the new schema version.
ALTER TABLE bundle_acknowledgements
  DROP CONSTRAINT IF EXISTS bundle_acknowledgements_head_fk;

ALTER TABLE bundle_acknowledgements
  ADD CONSTRAINT bundle_acknowledgements_statement_history_fk
  FOREIGN KEY (organization_id, device_id, format_epoch, sequence, statement_hash)
  REFERENCES control_bundle_statements(organization_id, device_id, format_epoch, sequence, statement_hash)
  NOT VALID;

ALTER TABLE bundle_acknowledgements
  VALIDATE CONSTRAINT bundle_acknowledgements_statement_history_fk;

CREATE FUNCTION agentpass_record_control_bundle_statement()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  current_generation bigint;
  existing_hash text;
BEGIN
  SELECT generation INTO current_generation
  FROM control_plane_authority_generations
  WHERE organization_id = NEW.organization_id AND superseded_at IS NULL;
  IF current_generation IS NULL THEN
    RAISE EXCEPTION USING ERRCODE = 'foreign_key_violation', MESSAGE = 'current authority generation was not found';
  END IF;

  SELECT statement_hash INTO existing_hash
  FROM control_bundle_statements
  WHERE organization_id = NEW.organization_id AND device_id = NEW.device_id
    AND format_epoch = NEW.format_epoch AND sequence = NEW.sequence
  FOR SHARE;
  IF existing_hash IS NOT NULL AND existing_hash <> NEW.statement_hash THEN
    RAISE EXCEPTION USING ERRCODE = 'unique_violation', MESSAGE = 'bundle sequence already has a different statement';
  END IF;

  INSERT INTO control_bundle_statements
    (organization_id, device_id, format_epoch, sequence, statement_hash, authority_generation, issued_at, expires_at)
  VALUES (NEW.organization_id, NEW.device_id, NEW.format_epoch, NEW.sequence, NEW.statement_hash,
    current_generation, NEW.issued_at, NEW.expires_at)
  ON CONFLICT (organization_id, device_id, format_epoch, sequence) DO NOTHING;
  RETURN NEW;
END;
$$;

CREATE TRIGGER bundle_heads_record_statement
  AFTER INSERT OR UPDATE ON bundle_heads
  FOR EACH ROW
  EXECUTE FUNCTION agentpass_record_control_bundle_statement();

CREATE FUNCTION agentpass_protect_control_bundle_statement_history()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  RAISE EXCEPTION USING ERRCODE = 'check_violation',
    MESSAGE = 'control bundle statement history is append-only',
    CONSTRAINT = 'control_bundle_statements_append_only';
END;
$$;

CREATE TRIGGER control_bundle_statements_append_only
  BEFORE UPDATE OR DELETE ON control_bundle_statements
  FOR EACH ROW
  EXECUTE FUNCTION agentpass_protect_control_bundle_statement_history();

CREATE TABLE device_refresh_outbox (
  outbox_id uuid NOT NULL,
  organization_id uuid NOT NULL,
  device_id uuid NOT NULL,
  desired_generation bigint NOT NULL,
  refresh_nonce_digest bytea NOT NULL CHECK (octet_length(refresh_nonce_digest) = 32),
  format_epoch integer,
  sequence bigint,
  statement_hash text,
  status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'delivered', 'acknowledged', 'expired', 'failed')),
  attempt_count integer NOT NULL DEFAULT 0 CHECK (attempt_count BETWEEN 0 AND 100),
  available_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  first_delivered_at timestamptz,
  last_delivered_at timestamptz,
  acknowledged_at timestamptz,
  last_error_code text,
  PRIMARY KEY (outbox_id),
  UNIQUE (organization_id, outbox_id),
  FOREIGN KEY (organization_id, device_id) REFERENCES devices(organization_id, id),
  FOREIGN KEY (organization_id, desired_generation)
    REFERENCES control_plane_authority_generations(organization_id, generation),
  FOREIGN KEY (organization_id, device_id, format_epoch, sequence, statement_hash)
    REFERENCES control_bundle_statements(organization_id, device_id, format_epoch, sequence, statement_hash),
  CHECK (expires_at > created_at),
  CHECK (format_epoch IS NULL AND sequence IS NULL AND statement_hash IS NULL
    OR (format_epoch = 2 AND sequence > 0 AND statement_hash ~ '^[0-9a-f]{64}$')),
  CHECK (last_error_code IS NULL OR (char_length(last_error_code) BETWEEN 1 AND 128 AND last_error_code !~ '[[:cntrl:]]')),
  CHECK (status IN ('pending', 'failed') OR first_delivered_at IS NOT NULL),
  CHECK (status <> 'acknowledged' OR acknowledged_at IS NOT NULL)
);

CREATE UNIQUE INDEX device_refresh_outbox_identity
  ON device_refresh_outbox (organization_id, device_id, desired_generation, refresh_nonce_digest);

CREATE UNIQUE INDEX device_refresh_outbox_bundle_identity
  ON device_refresh_outbox (organization_id, device_id, format_epoch, sequence, statement_hash)
  WHERE statement_hash IS NOT NULL;

ALTER TABLE device_refresh_outbox
  ADD CONSTRAINT device_refresh_outbox_bundle_identity_key
  UNIQUE (organization_id, device_id, format_epoch, sequence, statement_hash);

CREATE UNIQUE INDEX device_refresh_outbox_active_generation
  ON device_refresh_outbox (organization_id, device_id, desired_generation)
  WHERE status IN ('pending', 'delivered');

CREATE INDEX device_refresh_outbox_pending_delivery
  ON device_refresh_outbox (organization_id, status, available_at, expires_at, outbox_id)
  WHERE status IN ('pending', 'delivered');

CREATE INDEX device_refresh_outbox_retention
  ON device_refresh_outbox (expires_at, organization_id, device_id, outbox_id)
  WHERE status IN ('acknowledged', 'expired', 'failed');

-- This function is the transactional refresh boundary.  The caller supplies
-- only a digest of the one-time hint nonce; the raw nonce never enters SQL.
CREATE FUNCTION agentpass_request_device_refresh(
  request_outbox_id uuid,
  request_organization_id uuid,
  request_device_id uuid,
  request_desired_generation bigint,
  request_refresh_nonce_digest bytea,
  request_expires_at timestamptz
)
RETURNS TABLE (outbox_id uuid, desired_generation bigint, replayed boolean)
LANGUAGE plpgsql
VOLATILE
AS $$
DECLARE
  existing device_refresh_outbox%ROWTYPE;
  found_outbox_id uuid;
  found_generation bigint;
BEGIN
  IF request_refresh_nonce_digest IS NULL OR octet_length(request_refresh_nonce_digest) <> 32 THEN
    RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'refresh nonce digest must be exactly 32 bytes';
  END IF;
  IF request_desired_generation < 1 OR request_expires_at <= clock_timestamp() THEN
    RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'refresh generation or expiry is invalid';
  END IF;

  SELECT * INTO existing
  FROM device_control_plane_state
  WHERE organization_id = request_organization_id AND device_id = request_device_id
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE = 'foreign_key_violation', MESSAGE = 'device control-plane state was not found';
  END IF;
  IF request_desired_generation < existing.desired_generation THEN
    RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'desired generation cannot move backwards';
  END IF;

  UPDATE device_control_plane_state
  SET desired_generation = request_desired_generation,
      refresh_state = CASE WHEN request_desired_generation > existing.desired_generation THEN 'pending' ELSE refresh_state END,
      refresh_requested_at = CASE WHEN request_desired_generation > existing.desired_generation THEN clock_timestamp() ELSE refresh_requested_at END,
      updated_at = clock_timestamp()
  WHERE organization_id = request_organization_id AND device_id = request_device_id;

  SELECT * INTO existing
  FROM device_refresh_outbox
  WHERE organization_id = request_organization_id
    AND device_id = request_device_id
    AND desired_generation = request_desired_generation
    AND status IN ('pending', 'delivered')
  ORDER BY created_at ASC, outbox_id ASC
  LIMIT 1
  FOR UPDATE;
  IF FOUND THEN
    RETURN QUERY SELECT existing.outbox_id, existing.desired_generation, true;
    RETURN;
  END IF;

  INSERT INTO device_refresh_outbox
    (outbox_id, organization_id, device_id, desired_generation, refresh_nonce_digest, expires_at)
  VALUES
    (request_outbox_id, request_organization_id, request_device_id, request_desired_generation, request_refresh_nonce_digest, request_expires_at)
  ON CONFLICT (organization_id, device_id, desired_generation, refresh_nonce_digest) DO NOTHING;

  SELECT outbox_id, desired_generation INTO found_outbox_id, found_generation
  FROM device_refresh_outbox
  WHERE organization_id = request_organization_id
    AND device_id = request_device_id
    AND desired_generation = request_desired_generation
    AND refresh_nonce_digest = request_refresh_nonce_digest;
  RETURN QUERY SELECT found_outbox_id, found_generation, found_outbox_id <> request_outbox_id;
END;
$$;

CREATE TABLE device_refresh_delivery_attempts (
  attempt_id uuid NOT NULL,
  organization_id uuid NOT NULL,
  outbox_id uuid NOT NULL,
  attempt_no integer NOT NULL CHECK (attempt_no BETWEEN 1 AND 100),
  status text NOT NULL CHECK (status IN ('started', 'delivered', 'failed')),
  started_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  completed_at timestamptz,
  response_status integer,
  error_code text,
  PRIMARY KEY (organization_id, outbox_id, attempt_no),
  UNIQUE (attempt_id),
  FOREIGN KEY (organization_id, outbox_id) REFERENCES device_refresh_outbox(organization_id, outbox_id),
  CHECK ((status = 'started' AND completed_at IS NULL) OR (status IN ('delivered', 'failed') AND completed_at IS NOT NULL)),
  CHECK (response_status IS NULL OR response_status BETWEEN 100 AND 599),
  CHECK (error_code IS NULL OR (char_length(error_code) BETWEEN 1 AND 128 AND error_code !~ '[[:cntrl:]]')),
  CHECK (status <> 'delivered' OR response_status BETWEEN 200 AND 299)
);

CREATE INDEX device_refresh_delivery_attempts_retention
  ON device_refresh_delivery_attempts (completed_at, organization_id, outbox_id, attempt_no)
  WHERE completed_at IS NOT NULL;

CREATE INDEX device_refresh_delivery_attempts_pending
  ON device_refresh_delivery_attempts (organization_id, started_at, outbox_id, attempt_no)
  WHERE status = 'started';

CREATE TABLE device_bundle_acknowledgements (
  organization_id uuid NOT NULL,
  device_id uuid NOT NULL,
  device_key_epoch bigint NOT NULL CHECK (device_key_epoch > 0),
  format_epoch integer NOT NULL CHECK (format_epoch = 2),
  sequence bigint NOT NULL CHECK (sequence > 0),
  statement_hash text NOT NULL CHECK (statement_hash ~ '^[0-9a-f]{64}$'),
  result text NOT NULL CHECK (result IN ('applied', 'blocked')),
  reason_code text,
  observed_at timestamptz NOT NULL,
  ack_nonce_digest bytea NOT NULL CHECK (octet_length(ack_nonce_digest) = 32),
  received_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (organization_id, device_id, device_key_epoch, sequence),
  UNIQUE (organization_id, device_id, device_key_epoch, sequence, statement_hash),
  UNIQUE (organization_id, device_id, device_key_epoch, ack_nonce_digest),
  FOREIGN KEY (organization_id, device_id, device_key_epoch)
    REFERENCES device_key_epochs(organization_id, device_id, key_epoch),
  FOREIGN KEY (organization_id, device_id, format_epoch, sequence, statement_hash)
    REFERENCES control_bundle_statements(organization_id, device_id, format_epoch, sequence, statement_hash),
  CHECK (date_trunc('milliseconds', observed_at) = observed_at),
  CHECK ((result = 'applied' AND reason_code IS NULL)
    OR (result = 'blocked' AND reason_code IN (
      'bundle_expired', 'bundle_not_yet_valid', 'bundle_signature_invalid',
      'bundle_signer_untrusted', 'bundle_audience_mismatch', 'bundle_sequence_rollback',
      'bundle_sequence_conflict', 'bundle_storage_failed', 'device_revoked',
      'emergency_stop', 'internal_error'))),
  CHECK (reason_code IS NULL OR reason_code !~ '[[:cntrl:]]')
);

CREATE INDEX device_bundle_acknowledgements_retention
  ON device_bundle_acknowledgements (received_at, organization_id, device_id, device_key_epoch, sequence);

CREATE FUNCTION agentpass_guard_device_ack_monotonicity()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  latest_sequence bigint;
BEGIN
  PERFORM pg_advisory_xact_lock(hashtextextended(
    'agentpass:device-ack:' || NEW.organization_id::text || ':' || NEW.device_id::text, 0));

  SELECT MAX(sequence) INTO latest_sequence
  FROM device_bundle_acknowledgements
  WHERE organization_id = NEW.organization_id
    AND device_id = NEW.device_id;
  IF latest_sequence IS NOT NULL AND NEW.sequence < latest_sequence THEN
    RAISE EXCEPTION USING
      ERRCODE = 'check_violation',
      MESSAGE = 'device ACK sequence cannot move backwards across key epochs',
      CONSTRAINT = 'device_bundle_acknowledgements_monotonic';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER device_bundle_acknowledgements_monotonic
  BEFORE INSERT ON device_bundle_acknowledgements
  FOR EACH ROW
  EXECUTE FUNCTION agentpass_guard_device_ack_monotonicity();

CREATE FUNCTION agentpass_protect_device_bundle_acknowledgement()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  RAISE EXCEPTION USING ERRCODE = 'check_violation',
    MESSAGE = 'device bundle acknowledgements are append-only',
    CONSTRAINT = 'device_bundle_acknowledgements_append_only';
END;
$$;

CREATE TRIGGER device_bundle_acknowledgements_append_only
  BEFORE UPDATE OR DELETE ON device_bundle_acknowledgements
  FOR EACH ROW
  EXECUTE FUNCTION agentpass_protect_device_bundle_acknowledgement();

-- Repository implementations can call this function with INSERT ... ON
-- CONFLICT semantics. Exact retries return duplicate=true; conflicting
-- evidence is rejected without updating the original ACK.
CREATE FUNCTION agentpass_record_device_bundle_ack(
  request_organization_id uuid,
  request_device_id uuid,
  request_device_key_epoch bigint,
  request_format_epoch integer,
  request_sequence bigint,
  request_statement_hash text,
  request_result text,
  request_reason_code text,
  request_observed_at timestamptz,
  request_ack_nonce_digest bytea
)
RETURNS TABLE (accepted boolean, duplicate boolean)
LANGUAGE plpgsql
VOLATILE
AS $$
DECLARE
  stored device_bundle_acknowledgements%ROWTYPE;
BEGIN
  INSERT INTO device_bundle_acknowledgements
    (organization_id, device_id, device_key_epoch, format_epoch, sequence,
     statement_hash, result, reason_code, observed_at, ack_nonce_digest)
  VALUES
    (request_organization_id, request_device_id, request_device_key_epoch, request_format_epoch,
     request_sequence, request_statement_hash, request_result, request_reason_code,
     request_observed_at, request_ack_nonce_digest)
  ON CONFLICT (organization_id, device_id, device_key_epoch, sequence) DO NOTHING;

  IF FOUND THEN
    RETURN QUERY SELECT true, false;
    RETURN;
  END IF;

  SELECT * INTO stored
  FROM device_bundle_acknowledgements
  WHERE organization_id = request_organization_id
    AND device_id = request_device_id
    AND device_key_epoch = request_device_key_epoch
    AND sequence = request_sequence
  FOR SHARE;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE = 'serialization_failure', MESSAGE = 'ACK insert race could not be resolved';
  END IF;
  IF stored.statement_hash <> request_statement_hash
     OR stored.format_epoch <> request_format_epoch
     OR stored.result <> request_result
     OR stored.reason_code IS DISTINCT FROM request_reason_code
     OR stored.observed_at <> request_observed_at
     OR stored.ack_nonce_digest <> request_ack_nonce_digest THEN
    RAISE EXCEPTION USING ERRCODE = 'unique_violation', MESSAGE = 'ACK identity conflicts with existing evidence';
  END IF;
  RETURN QUERY SELECT true, true;
END;
$$;

CREATE FUNCTION agentpass_apply_device_bundle_ack()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  UPDATE device_refresh_outbox
  SET status = CASE WHEN NEW.result = 'applied' THEN 'acknowledged' ELSE 'failed' END,
      acknowledged_at = CASE WHEN NEW.result = 'applied' THEN NEW.received_at ELSE acknowledged_at END
  WHERE organization_id = NEW.organization_id
    AND device_id = NEW.device_id
    AND format_epoch = NEW.format_epoch
    AND sequence = NEW.sequence
    AND statement_hash = NEW.statement_hash;

  UPDATE device_control_plane_state state
  SET observed_generation = CASE
        WHEN NEW.result = 'applied' THEN GREATEST(COALESCE(state.observed_generation, 0), outbox.desired_generation)
        ELSE state.observed_generation
      END,
      refresh_state = CASE WHEN NEW.result = 'applied' THEN 'applied' ELSE 'blocked' END,
      last_observed_at = NEW.observed_at,
      last_error_code = CASE WHEN NEW.result = 'blocked' THEN NEW.reason_code ELSE NULL END,
      updated_at = clock_timestamp()
  FROM device_refresh_outbox outbox
  WHERE outbox.organization_id = NEW.organization_id
    AND outbox.device_id = NEW.device_id
    AND outbox.format_epoch = NEW.format_epoch
    AND outbox.sequence = NEW.sequence
    AND outbox.statement_hash = NEW.statement_hash
    AND state.organization_id = outbox.organization_id
    AND state.device_id = outbox.device_id;
  RETURN NEW;
END;
$$;

CREATE TRIGGER device_bundle_acknowledgements_apply
  AFTER INSERT ON device_bundle_acknowledgements
  FOR EACH ROW
  EXECUTE FUNCTION agentpass_apply_device_bundle_ack();

-- New organizations and devices receive their initial rows in the same
-- transaction as their creation.  Existing rows were seeded above.
CREATE FUNCTION agentpass_initialize_authority_for_organization()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  INSERT INTO control_plane_authority_generations (organization_id, generation)
  VALUES (NEW.id, 1);
  RETURN NEW;
END;
$$;

CREATE TRIGGER organizations_initialize_authority
  AFTER INSERT ON organizations
  FOR EACH ROW
  EXECUTE FUNCTION agentpass_initialize_authority_for_organization();

CREATE FUNCTION agentpass_initialize_device_control_plane_state()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  authority_generation bigint;
  current_epoch device_key_epochs%ROWTYPE;
BEGIN
  SELECT generation INTO authority_generation
  FROM control_plane_authority_generations
  WHERE organization_id = NEW.organization_id AND superseded_at IS NULL;
  IF authority_generation IS NULL THEN
    RAISE EXCEPTION USING ERRCODE = 'foreign_key_violation', MESSAGE = 'current authority generation was not found';
  END IF;

  IF TG_OP = 'INSERT' THEN
    INSERT INTO device_control_plane_state (organization_id, device_id, desired_generation, refresh_state)
    VALUES (NEW.organization_id, NEW.id, authority_generation, 'pending');
  END IF;

  -- Pending reservations intentionally have no key material and no epoch.
  -- Enrollment completion sets both device key columns in one UPDATE; this
  -- same-transaction trigger creates epoch 1 from that exact public key.
  IF NEW.status = 'active' AND NEW.key_algorithm IS NOT NULL AND NEW.public_key_pem IS NOT NULL THEN
    SELECT * INTO current_epoch
    FROM device_key_epochs
    WHERE organization_id = NEW.organization_id AND device_id = NEW.id
    ORDER BY key_epoch DESC
    LIMIT 1
    FOR UPDATE;
    IF FOUND THEN
      IF current_epoch.key_algorithm <> NEW.key_algorithm
         OR current_epoch.public_key_pem <> NEW.public_key_pem THEN
        RAISE EXCEPTION USING
          ERRCODE = 'check_violation',
          MESSAGE = 'device key material must rotate through a new key epoch',
          CONSTRAINT = 'device_key_epochs_forward_only';
      END IF;
    ELSE
      INSERT INTO device_key_epochs
        (organization_id, device_id, key_epoch, key_algorithm, public_key_pem, status)
      VALUES
        (NEW.organization_id, NEW.id, 1, NEW.key_algorithm, NEW.public_key_pem, 'active');
    END IF;
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER devices_initialize_control_plane_state
  AFTER INSERT OR UPDATE OF status, key_algorithm, public_key_pem ON devices
  FOR EACH ROW
  EXECUTE FUNCTION agentpass_initialize_device_control_plane_state();

COMMIT;
