BEGIN;

-- Human WebAuthn credential lookups are session-authority reads.  Keep the
-- session, membership, organization, and credential joins inside narrowly
-- scoped SECURITY DEFINER functions so the application role cannot recreate
-- the lookup with a broader direct SELECT.
CREATE FUNCTION public.agentpass_human_list_credentials_for_session(
  p_session_id uuid,
  p_organization_id uuid
)
RETURNS TABLE (
  id bytea,
  transports text[]
)
LANGUAGE sql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
  SELECT c.id, c.transports
  FROM public.webauthn_credentials AS c
  JOIN public.human_sessions AS s
    ON s.member_id = c.member_id
  JOIN public.memberships AS m
    ON m.organization_id = s.organization_id
   AND m.member_id = s.member_id
   AND m.id = s.membership_id
  JOIN public.organizations AS o
    ON o.id = s.organization_id
  WHERE s.id = p_session_id
    AND s.organization_id = p_organization_id
    AND s.revoked_at IS NULL
    AND s.expires_at > pg_catalog.clock_timestamp()
    AND (s.idle_expires_at IS NULL
         OR s.idle_expires_at > pg_catalog.clock_timestamp())
    AND m.status = 'active'
    AND m.role = s.role
    AND o.authority_epoch = s.organization_authority_epoch
    AND m.session_epoch = s.membership_session_epoch
    AND c.revoked_at IS NULL
    AND c.clone_detected_at IS NULL
    AND c.sign_count_state <> 'clone-detected'
  ORDER BY c.created_at ASC, c.id ASC
  LIMIT 64;
$$;

CREATE FUNCTION public.agentpass_human_find_credential_for_session(
  p_session_id uuid,
  p_organization_id uuid,
  p_credential_id bytea
)
RETURNS TABLE (
  id bytea,
  public_key bytea,
  sign_count bigint,
  transports text[],
  backup_eligible boolean,
  backup_state boolean
)
LANGUAGE sql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
  SELECT c.id,
         c.public_key,
         c.sign_count,
         c.transports,
         c.backup_eligible,
         c.backup_state
  FROM public.webauthn_credentials AS c
  JOIN public.human_sessions AS s
    ON s.member_id = c.member_id
  JOIN public.memberships AS m
    ON m.organization_id = s.organization_id
   AND m.member_id = s.member_id
   AND m.id = s.membership_id
  JOIN public.organizations AS o
    ON o.id = s.organization_id
  WHERE s.id = p_session_id
    AND s.organization_id = p_organization_id
    AND c.id = p_credential_id
    AND s.revoked_at IS NULL
    AND s.expires_at > pg_catalog.clock_timestamp()
    AND (s.idle_expires_at IS NULL
         OR s.idle_expires_at > pg_catalog.clock_timestamp())
    AND m.status = 'active'
    AND m.role = s.role
    AND o.authority_epoch = s.organization_authority_epoch
    AND m.session_epoch = s.membership_session_epoch
    AND c.revoked_at IS NULL
    AND c.clone_detected_at IS NULL
    AND c.sign_count_state <> 'clone-detected'
  LIMIT 1;
$$;

ALTER FUNCTION public.agentpass_human_list_credentials_for_session(uuid, uuid)
  OWNER TO agentpass_migrator;
ALTER FUNCTION public.agentpass_human_find_credential_for_session(uuid, uuid, bytea)
  OWNER TO agentpass_migrator;

REVOKE ALL PRIVILEGES ON FUNCTION public.agentpass_human_list_credentials_for_session(uuid, uuid)
  FROM PUBLIC, agentpass_signer, agentpass_backup, agentpass_maintenance;
REVOKE ALL PRIVILEGES ON FUNCTION public.agentpass_human_find_credential_for_session(uuid, uuid, bytea)
  FROM PUBLIC, agentpass_signer, agentpass_backup, agentpass_maintenance;
GRANT EXECUTE ON FUNCTION public.agentpass_human_list_credentials_for_session(uuid, uuid)
  TO agentpass_app;
GRANT EXECUTE ON FUNCTION public.agentpass_human_find_credential_for_session(uuid, uuid, bytea)
  TO agentpass_app;

COMMIT;
