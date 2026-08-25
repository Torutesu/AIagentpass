BEGIN;

-- A new desired generation starts a new delivery cycle. Historical delivery
-- timestamps and errors belong to the prior generation and must not violate
-- the state table's ordering constraints after refresh_requested_at advances.
CREATE OR REPLACE FUNCTION agentpass_request_device_refresh(
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
  advances_generation boolean;
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

  advances_generation := request_desired_generation > existing_state.desired_generation;
  UPDATE device_control_plane_state AS state
  SET desired_generation = request_desired_generation,
      refresh_state = CASE WHEN advances_generation THEN 'pending' ELSE state.refresh_state END,
      refresh_requested_at = CASE WHEN advances_generation THEN clock_timestamp() ELSE state.refresh_requested_at END,
      last_delivered_at = CASE WHEN advances_generation THEN NULL ELSE state.last_delivered_at END,
      last_observed_at = CASE WHEN advances_generation THEN NULL ELSE state.last_observed_at END,
      last_error_code = CASE WHEN advances_generation THEN NULL ELSE state.last_error_code END,
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

COMMIT;
