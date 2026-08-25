BEGIN;

-- WebAuthn registration needs only the non-sensitive user identity.  Keep the
-- complete session, member, organization, membership, role, epoch, and
-- lifetime binding inside one SECURITY DEFINER read primitive; never expose
-- session bearer material or WebAuthn public-key material from this function.
CREATE FUNCTION public.agentpass_human_get_registration_user(
  p_session_id uuid,
  p_member_id uuid,
  p_organization_id uuid
)
RETURNS TABLE (
  member_id uuid,
  display_name text
)
LANGUAGE sql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
  SELECT s.member_id,
         mbr.display_name
  FROM public.human_sessions AS s
  JOIN public.members AS mbr
    ON mbr.id = s.member_id
  JOIN public.memberships AS m
    ON m.organization_id = s.organization_id
   AND m.member_id = s.member_id
   AND m.id = s.membership_id
  JOIN public.organizations AS o
    ON o.id = s.organization_id
  WHERE s.id = p_session_id
    AND s.member_id = p_member_id
    AND s.organization_id = p_organization_id
    AND s.revoked_at IS NULL
    AND s.expires_at > pg_catalog.clock_timestamp()
    AND (s.idle_expires_at IS NULL
         OR s.idle_expires_at > pg_catalog.clock_timestamp())
    AND m.status = 'active'
    AND m.role = s.role
    AND o.authority_epoch = s.organization_authority_epoch
    AND m.session_epoch = s.membership_session_epoch
  LIMIT 1;
$$;

ALTER FUNCTION public.agentpass_human_get_registration_user(uuid, uuid, uuid)
  OWNER TO agentpass_migrator;

REVOKE ALL PRIVILEGES ON FUNCTION public.agentpass_human_get_registration_user(uuid, uuid, uuid)
  FROM PUBLIC, agentpass_signer, agentpass_backup, agentpass_maintenance;
GRANT EXECUTE ON FUNCTION public.agentpass_human_get_registration_user(uuid, uuid, uuid)
  TO agentpass_app;

COMMIT;
