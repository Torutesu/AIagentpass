BEGIN;

-- Owner-recovery activation is invalidated by the owner_recovery_requests
-- state trigger.  This function is the post-transition authority check and
-- epoch read used by the repository; it deliberately does not invoke the
-- invalidation primitive and does not trust a caller-controlled GUC.
CREATE FUNCTION public.agentpass_owner_recovery_activate_authority(
  p_organization_id uuid,
  p_request_id uuid,
  p_recovery_session_id uuid,
  p_member_id uuid,
  p_authorization_id uuid,
  p_credential_id bytea
)
RETURNS TABLE (
  session_epoch bigint,
  revoked_count integer
)
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  request_member_id uuid;
  request_state text;
  request_expires_at timestamptz;
  session_member_id uuid;
  session_request_id uuid;
  session_credential_id bytea;
  challenge_member_id uuid;
BEGIN
  IF p_organization_id IS NULL OR p_request_id IS NULL OR p_recovery_session_id IS NULL
     OR p_member_id IS NULL OR p_authorization_id IS NULL OR p_credential_id IS NULL
     OR octet_length(p_credential_id) < 16 THEN
    RAISE EXCEPTION 'owner recovery activation authority requires the reviewed activation binding'
      USING ERRCODE = '22023';
  END IF;

  SELECT r.subject_member_id, r.state, r.expires_at
    INTO request_member_id, request_state, request_expires_at
  FROM public.owner_recovery_requests AS r
  WHERE r.organization_id = p_organization_id
    AND r.request_id = p_request_id
  FOR UPDATE;
  IF NOT FOUND OR request_member_id <> p_member_id
     OR request_state <> 'activated'
     OR request_expires_at <= pg_catalog.clock_timestamp() THEN
    RAISE EXCEPTION 'owner recovery activation request is not activated'
      USING ERRCODE = '42501';
  END IF;

  SELECT s.member_id, s.request_id, s.credential_id
    INTO session_member_id, session_request_id, session_credential_id
  FROM public.owner_recovery_sessions AS s
  WHERE s.organization_id = p_organization_id
    AND s.recovery_session_id = p_recovery_session_id
    AND s.member_id = p_member_id
    AND s.request_id = p_request_id
    AND s.stage = 'credential_enrolled'
    AND s.expires_at > pg_catalog.clock_timestamp()
    AND s.idle_expires_at > pg_catalog.clock_timestamp()
  FOR UPDATE;
  IF NOT FOUND OR session_member_id <> p_member_id
     OR session_request_id <> p_request_id
     OR session_credential_id IS DISTINCT FROM p_credential_id THEN
    RAISE EXCEPTION 'owner recovery activation session is not eligible'
      USING ERRCODE = '42501';
  END IF;

  SELECT w.member_id
    INTO challenge_member_id
  FROM public.owner_recovery_webauthn_challenges AS w
  WHERE w.organization_id = p_organization_id
    AND w.challenge_id = p_authorization_id
    AND w.recovery_session_id = p_recovery_session_id
    AND w.request_id = p_request_id
    AND w.member_id = p_member_id
    AND w.ceremony = 'authentication'
    AND w.operation = 'human.recovery.activate'
    AND w.status = 'consuming'
    AND w.consume_started_at IS NOT NULL
    AND w.consumed_at IS NULL
    AND w.expires_at > pg_catalog.clock_timestamp()
  FOR UPDATE;
  IF NOT FOUND OR challenge_member_id <> p_member_id THEN
    RAISE EXCEPTION 'owner recovery activation proof is not claimable'
      USING ERRCODE = '42501';
  END IF;

  RETURN QUERY SELECT
    m.session_epoch,
    0::integer
  FROM public.memberships AS m
  WHERE m.organization_id = p_organization_id
    AND m.member_id = p_member_id
  FOR SHARE;
END;
$$;

ALTER FUNCTION public.agentpass_owner_recovery_activate_authority(uuid, uuid, uuid, uuid, uuid, bytea)
  OWNER TO agentpass_migrator;

REVOKE ALL PRIVILEGES ON FUNCTION public.agentpass_owner_recovery_activate_authority(uuid, uuid, uuid, uuid, uuid, bytea)
  FROM PUBLIC, agentpass_signer, agentpass_backup, agentpass_maintenance;
GRANT EXECUTE ON FUNCTION public.agentpass_owner_recovery_activate_authority(uuid, uuid, uuid, uuid, uuid, bytea)
  TO agentpass_app;

COMMIT;
