BEGIN;

-- PostgreSQL 17 treats output-column names of RETURNS TABLE functions as
-- PL/pgSQL variables. Qualify every table column so generation advancement is
-- unambiguous on all supported PostgreSQL versions.
CREATE OR REPLACE FUNCTION agentpass_advance_authority_generation(
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

  PERFORM 1 FROM organizations AS organization
  WHERE organization.id = request_organization_id
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE = 'foreign_key_violation', MESSAGE = 'organization was not found';
  END IF;

  SELECT authority.generation INTO current_generation
  FROM control_plane_authority_generations AS authority
  WHERE authority.organization_id = request_organization_id
  ORDER BY authority.generation DESC
  LIMIT 1
  FOR UPDATE;

  next_generation := COALESCE(current_generation, 0) + 1;
  UPDATE control_plane_authority_generations AS authority
  SET superseded_at = COALESCE(authority.superseded_at, request_issued_at)
  WHERE authority.organization_id = request_organization_id
    AND authority.superseded_at IS NULL;

  INSERT INTO control_plane_authority_generations (organization_id, generation, issued_at)
  VALUES (request_organization_id, next_generation, request_issued_at);

  RETURN QUERY SELECT request_organization_id, next_generation;
END;
$$;

-- 0012 stored only a digest, so a pre-codec pending delivery cannot be
-- reconstructed after restart. Fail those deliveries closed and make the
-- matching device state visibly stale before adding the immutable key identity;
-- recovery must explicitly issue a new refresh generation.
ALTER TABLE device_refresh_outbox
  ADD COLUMN refresh_nonce_key_id text NOT NULL DEFAULT 'refresh-nonce-v1';

WITH legacy_deliveries AS (
  UPDATE device_refresh_outbox
  SET status = 'failed',
      last_error_code = 'refresh_nonce_rekey_required'
  WHERE status IN ('pending', 'delivered')
  RETURNING organization_id, device_id, desired_generation
)
UPDATE device_control_plane_state state
SET refresh_state = CASE WHEN state.refresh_state = 'revoked' THEN 'revoked' ELSE 'stale' END,
    last_error_code = 'refresh_nonce_rekey_required',
    updated_at = clock_timestamp()
FROM legacy_deliveries legacy
WHERE state.organization_id = legacy.organization_id
  AND state.device_id = legacy.device_id
  AND state.desired_generation = legacy.desired_generation;

ALTER TABLE device_refresh_outbox
  ALTER COLUMN refresh_nonce_key_id DROP DEFAULT,
  ADD CONSTRAINT device_refresh_outbox_nonce_key_id_valid
    CHECK (refresh_nonce_key_id ~ '^refresh-nonce-v[1-9][0-9]{0,8}$');

DROP FUNCTION IF EXISTS agentpass_request_device_refresh(uuid, uuid, uuid, bigint, bytea, timestamptz);

CREATE FUNCTION agentpass_request_device_refresh(
  request_outbox_id uuid,
  request_organization_id uuid,
  request_device_id uuid,
  request_desired_generation bigint,
  request_refresh_nonce_key_id text,
  request_refresh_nonce_digest bytea,
  request_expires_at timestamptz
)
RETURNS TABLE (
  outbox_id uuid,
  desired_generation bigint,
  refresh_nonce_key_id text,
  refresh_nonce_digest bytea,
  replayed boolean
)
LANGUAGE plpgsql
VOLATILE
AS $$
DECLARE
  existing_state device_control_plane_state%ROWTYPE;
  existing_outbox device_refresh_outbox%ROWTYPE;
  found_outbox_id uuid;
  found_generation bigint;
  found_key_id text;
  found_digest bytea;
BEGIN
  IF request_refresh_nonce_key_id IS NULL
     OR request_refresh_nonce_key_id !~ '^refresh-nonce-v[1-9][0-9]{0,8}$' THEN
    RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'refresh nonce key id is invalid';
  END IF;
  IF request_refresh_nonce_digest IS NULL OR octet_length(request_refresh_nonce_digest) <> 32 THEN
    RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'refresh nonce digest must be exactly 32 bytes';
  END IF;
  IF request_desired_generation < 1 OR request_expires_at <= clock_timestamp() THEN
    RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'refresh generation or expiry is invalid';
  END IF;

  SELECT state.* INTO existing_state
  FROM device_control_plane_state AS state
  WHERE state.organization_id = request_organization_id AND state.device_id = request_device_id
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE = 'foreign_key_violation', MESSAGE = 'device control-plane state was not found';
  END IF;
  IF request_desired_generation < existing_state.desired_generation THEN
    RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'desired generation cannot move backwards';
  END IF;

  UPDATE device_control_plane_state AS state
  SET desired_generation = request_desired_generation,
      refresh_state = CASE WHEN request_desired_generation > existing_state.desired_generation THEN 'pending' ELSE state.refresh_state END,
      refresh_requested_at = CASE WHEN request_desired_generation > existing_state.desired_generation THEN clock_timestamp() ELSE state.refresh_requested_at END,
      updated_at = clock_timestamp()
  WHERE state.organization_id = request_organization_id AND state.device_id = request_device_id;

  SELECT queued.* INTO existing_outbox
  FROM device_refresh_outbox AS queued
  WHERE queued.organization_id = request_organization_id
    AND queued.device_id = request_device_id
    AND queued.desired_generation = request_desired_generation
    AND queued.status IN ('pending', 'delivered')
  ORDER BY queued.created_at ASC, queued.outbox_id ASC
  LIMIT 1
  FOR UPDATE;
  IF FOUND THEN
    RETURN QUERY SELECT existing_outbox.outbox_id, existing_outbox.desired_generation,
      existing_outbox.refresh_nonce_key_id, existing_outbox.refresh_nonce_digest, true;
    RETURN;
  END IF;

  INSERT INTO device_refresh_outbox
    (outbox_id, organization_id, device_id, desired_generation,
     refresh_nonce_key_id, refresh_nonce_digest, expires_at)
  VALUES
    (request_outbox_id, request_organization_id, request_device_id,
     request_desired_generation, request_refresh_nonce_key_id,
     request_refresh_nonce_digest, request_expires_at)
  ON CONFLICT DO NOTHING;

  SELECT queued.outbox_id, queued.desired_generation, queued.refresh_nonce_key_id, queued.refresh_nonce_digest
    INTO found_outbox_id, found_generation, found_key_id, found_digest
  FROM device_refresh_outbox AS queued
  WHERE queued.organization_id = request_organization_id
    AND queued.device_id = request_device_id
    AND queued.desired_generation = request_desired_generation
    AND queued.refresh_nonce_digest = request_refresh_nonce_digest;
  RETURN QUERY SELECT found_outbox_id, found_generation, found_key_id, found_digest,
    found_outbox_id <> request_outbox_id;
END;
$$;

-- Bind every ACK to the nonce of the exact outbox statement. Device-key
-- possession alone is not sufficient: the device must prove receipt of this
-- refresh delivery, and exact retries remain idempotent after acknowledgement.
CREATE OR REPLACE FUNCTION agentpass_record_device_bundle_ack(
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
  expected_nonce_digest bytea;
BEGIN
  SELECT refresh.refresh_nonce_digest INTO expected_nonce_digest
  FROM device_refresh_outbox AS refresh
  WHERE refresh.organization_id = request_organization_id
    AND refresh.device_id = request_device_id
    AND refresh.format_epoch = request_format_epoch
    AND refresh.sequence = request_sequence
    AND refresh.statement_hash = request_statement_hash
  LIMIT 1
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE = 'foreign_key_violation', MESSAGE = 'ACK refresh binding was not found';
  END IF;
  IF expected_nonce_digest IS DISTINCT FROM request_ack_nonce_digest THEN
    RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'ACK refresh nonce does not match';
  END IF;

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

  SELECT acknowledgement.* INTO stored
  FROM device_bundle_acknowledgements AS acknowledgement
  WHERE acknowledgement.organization_id = request_organization_id
    AND acknowledgement.device_id = request_device_id
    AND acknowledgement.device_key_epoch = request_device_key_epoch
    AND acknowledgement.sequence = request_sequence
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

-- A blocked ACK still proves that the device observed this authority
-- generation. Persist that observation while retaining the blocked state and
-- reason, so a successfully committed ACK never turns into an HTTP failure.
CREATE OR REPLACE FUNCTION agentpass_apply_device_bundle_ack()
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

  UPDATE device_control_plane_state AS state
  SET observed_generation = GREATEST(COALESCE(state.observed_generation, 0), refresh.desired_generation),
      refresh_state = CASE WHEN NEW.result = 'applied' THEN 'applied' ELSE 'blocked' END,
      last_observed_at = NEW.observed_at,
      last_error_code = CASE WHEN NEW.result = 'blocked' THEN NEW.reason_code ELSE NULL END,
      updated_at = clock_timestamp()
  FROM device_refresh_outbox AS refresh
  WHERE refresh.organization_id = NEW.organization_id
    AND refresh.device_id = NEW.device_id
    AND refresh.format_epoch = NEW.format_epoch
    AND refresh.sequence = NEW.sequence
    AND refresh.statement_hash = NEW.statement_hash
    AND state.organization_id = refresh.organization_id
    AND state.device_id = refresh.device_id;
  RETURN NEW;
END;
$$;

COMMIT;
