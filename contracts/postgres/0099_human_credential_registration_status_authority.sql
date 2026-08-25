BEGIN;

-- Registration conflict and quota checks are session-authority reads.  Keep
-- the session/membership/organization binding and the credential counts in
-- one SECURITY DEFINER function so the application cannot widen the lookup
-- to another member or organization.
CREATE FUNCTION public.agentpass_human_credential_registration_status(
  p_session_id uuid,
  p_member_id uuid,
  p_organization_id uuid,
  p_credential_id bytea
)
RETURNS TABLE (
  credential_exists boolean,
  active_count bigint,
  total_count bigint
)
LANGUAGE plpgsql
STABLE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
  IF p_session_id IS NULL OR p_member_id IS NULL OR p_organization_id IS NULL
     OR p_credential_id IS NULL OR pg_catalog.octet_length(p_credential_id) < 16 THEN
    RAISE EXCEPTION 'human credential registration status requires a complete binding'
      USING ERRCODE = '22023';
  END IF;

  IF NOT EXISTS (
    SELECT 1
    FROM public.human_sessions AS s
    JOIN public.memberships AS m
      ON m.organization_id = s.organization_id
     AND m.member_id = s.member_id
     AND m.id = s.membership_id
    JOIN public.organizations AS o ON o.id = s.organization_id
    WHERE s.id = p_session_id
      AND s.member_id = p_member_id
      AND s.organization_id = p_organization_id
      AND s.revoked_at IS NULL
      AND s.expires_at > pg_catalog.clock_timestamp()
      AND (s.idle_expires_at IS NULL OR s.idle_expires_at > pg_catalog.clock_timestamp())
      AND m.status = 'active'
      AND m.role = s.role
      AND o.authority_epoch = s.organization_authority_epoch
      AND m.session_epoch = s.membership_session_epoch
  ) THEN
    RETURN;
  END IF;

  RETURN QUERY
  SELECT EXISTS (
           SELECT 1 FROM public.webauthn_credentials AS c
           WHERE c.member_id = p_member_id AND c.id = p_credential_id
         ),
         count(*) FILTER (WHERE c.revoked_at IS NULL AND c.clone_detected_at IS NULL
                           AND c.sign_count_state <> 'clone-detected'),
         count(*)
  FROM public.webauthn_credentials AS c
  WHERE c.member_id = p_member_id;
END;
$$;

ALTER FUNCTION public.agentpass_human_credential_registration_status(uuid,uuid,uuid,bytea)
  OWNER TO agentpass_migrator;

REVOKE ALL PRIVILEGES ON FUNCTION public.agentpass_human_credential_registration_status(uuid,uuid,uuid,bytea)
  FROM PUBLIC, agentpass_signer, agentpass_backup, agentpass_maintenance;
GRANT EXECUTE ON FUNCTION public.agentpass_human_credential_registration_status(uuid,uuid,uuid,bytea)
  TO agentpass_app;

COMMIT;
