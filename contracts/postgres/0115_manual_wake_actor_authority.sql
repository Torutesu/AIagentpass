BEGIN;

-- Keep the online role away from the memberships base table for manual-wake
-- authorization. The existing migrator-owned registration projection exposes
-- only the active session binding and membership role; the authority function
-- returns only the bounded role value needed by the repository.
CREATE FUNCTION public.agentpass_manual_wake_actor_role(
  p_organization_id uuid,
  p_member_id uuid
)
RETURNS text
LANGUAGE sql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
  SELECT m.membership_role
  FROM public.agentpass_webauthn_registration_sessions AS m
  WHERE m.organization_id = p_organization_id
    AND m.member_id = p_member_id
    AND m.membership_status = 'active'
  FOR SHARE;
$$;

ALTER FUNCTION public.agentpass_manual_wake_actor_role(uuid,uuid) OWNER TO agentpass_migrator;
GRANT SELECT ON TABLE public.memberships TO agentpass_migrator;
REVOKE ALL PRIVILEGES ON FUNCTION public.agentpass_manual_wake_actor_role(uuid,uuid)
  FROM PUBLIC, agentpass_signer, agentpass_backup, agentpass_maintenance;
GRANT EXECUTE ON FUNCTION public.agentpass_manual_wake_actor_role(uuid,uuid) TO agentpass_app;

COMMIT;
