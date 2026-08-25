BEGIN;

-- A pending/delivered row is active only while its wall-clock expiry is in
-- the future.  Delivery maintenance may not have classified an expired row
-- yet, so the enqueue boundary terminalizes it while holding the same device
-- state lock before deciding whether an active request can be replayed.
CREATE OR REPLACE FUNCTION public.agentpass_request_device_refresh(
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
SET search_path = pg_catalog, public
AS $$
DECLARE
  existing_state public.device_control_plane_state%ROWTYPE;
  existing_outbox public.device_refresh_outbox%ROWTYPE;
  found_outbox_id uuid;
  found_generation bigint;
  found_key_id text;
  found_digest bytea;
  advances_generation boolean;
  now_value timestamptz := clock_timestamp();
BEGIN
  IF request_refresh_nonce_key_id IS NULL
     OR request_refresh_nonce_key_id !~ '^refresh-nonce-v[1-9][0-9]{0,8}$' THEN
    RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'refresh nonce key id is invalid';
  END IF;
  IF request_refresh_nonce_digest IS NULL OR octet_length(request_refresh_nonce_digest) <> 32 THEN
    RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'refresh nonce digest must be exactly 32 bytes';
  END IF;
  IF request_desired_generation < 1 OR request_expires_at <= now_value THEN
    RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'refresh generation or expiry is invalid';
  END IF;

  SELECT state.* INTO existing_state
  FROM public.device_control_plane_state AS state
  WHERE state.organization_id = request_organization_id
    AND state.device_id = request_device_id
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE = 'foreign_key_violation', MESSAGE = 'device control-plane state was not found';
  END IF;
  IF request_desired_generation < existing_state.desired_generation THEN
    RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'desired generation cannot move backwards';
  END IF;

  advances_generation := request_desired_generation > existing_state.desired_generation;
  UPDATE public.device_control_plane_state AS state
  SET desired_generation = request_desired_generation,
      refresh_state = CASE WHEN advances_generation THEN 'pending' ELSE state.refresh_state END,
      refresh_requested_at = CASE WHEN advances_generation THEN now_value ELSE state.refresh_requested_at END,
      last_delivered_at = CASE WHEN advances_generation THEN NULL ELSE state.last_delivered_at END,
      last_observed_at = CASE WHEN advances_generation THEN NULL ELSE state.last_observed_at END,
      last_error_code = CASE WHEN advances_generation THEN NULL ELSE state.last_error_code END,
      updated_at = now_value
  WHERE state.organization_id = request_organization_id
    AND state.device_id = request_device_id;

  -- An undelivered expired row cannot use status=expired under the historical
  -- table constraint, so classify it as failed.  A delivered row has the
  -- required delivery timestamp and is classified as expired.
  UPDATE public.device_refresh_outbox AS queued
  SET status = CASE WHEN queued.status = 'pending' THEN 'failed' ELSE 'expired' END,
      last_error_code = 'refresh_expired'
  WHERE queued.organization_id = request_organization_id
    AND queued.device_id = request_device_id
    AND queued.desired_generation = request_desired_generation
    AND queued.status IN ('pending', 'delivered')
    AND queued.expires_at <= now_value;

  SELECT queued.* INTO existing_outbox
  FROM public.device_refresh_outbox AS queued
  WHERE queued.organization_id = request_organization_id
    AND queued.device_id = request_device_id
    AND queued.desired_generation = request_desired_generation
    AND queued.status IN ('pending', 'delivered')
    AND queued.expires_at > now_value
  ORDER BY queued.created_at ASC, queued.outbox_id ASC
  LIMIT 1
  FOR UPDATE;
  IF FOUND THEN
    RETURN QUERY SELECT existing_outbox.outbox_id, existing_outbox.desired_generation,
      existing_outbox.refresh_nonce_key_id, existing_outbox.refresh_nonce_digest, true;
    RETURN;
  END IF;

  INSERT INTO public.device_refresh_outbox
    (outbox_id, organization_id, device_id, desired_generation,
     refresh_nonce_key_id, refresh_nonce_digest, expires_at)
  VALUES
    (request_outbox_id, request_organization_id, request_device_id,
     request_desired_generation, request_refresh_nonce_key_id,
     request_refresh_nonce_digest, request_expires_at)
  ON CONFLICT DO NOTHING;

  SELECT queued.outbox_id, queued.desired_generation,
      queued.refresh_nonce_key_id, queued.refresh_nonce_digest
    INTO found_outbox_id, found_generation, found_key_id, found_digest
  FROM public.device_refresh_outbox AS queued
  WHERE queued.organization_id = request_organization_id
    AND queued.device_id = request_device_id
    AND queued.desired_generation = request_desired_generation
    AND queued.refresh_nonce_digest = request_refresh_nonce_digest
    AND queued.status IN ('pending', 'delivered')
    AND queued.expires_at > now_value;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE = 'serialization_failure',
      MESSAGE = 'active device refresh outbox could not be resolved';
  END IF;
  RETURN QUERY SELECT found_outbox_id, found_generation, found_key_id, found_digest,
    found_outbox_id <> request_outbox_id;
END;
$$;

COMMIT;
