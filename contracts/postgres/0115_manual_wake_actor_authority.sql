BEGIN;

-- Manual wake authorization is a narrow, migrator-owned projection. The app
-- receives only the active membership role through a SECURITY DEFINER function.
CREATE VIEW public.agentpass_manual_wake_actor_memberships
WITH (security_barrier = true) AS
SELECT organization_id, member_id, role
FROM public.memberships
WHERE status = 'active';

ALTER VIEW public.agentpass_manual_wake_actor_memberships OWNER TO agentpass_migrator;
REVOKE ALL PRIVILEGES ON TABLE public.agentpass_manual_wake_actor_memberships
  FROM PUBLIC, agentpass_signer, agentpass_backup, agentpass_maintenance;
GRANT SELECT ON TABLE public.agentpass_manual_wake_actor_memberships TO agentpass_app;

CREATE FUNCTION public.agentpass_manual_wake_actor_role(
  p_organization_id uuid,
  p_member_id uuid
)
RETURNS text
LANGUAGE sql
STABLE
PARALLEL SAFE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
  SELECT m.role
  FROM public.agentpass_manual_wake_actor_memberships AS m
  WHERE m.organization_id = p_organization_id
    AND m.member_id = p_member_id
  LIMIT 2;
$$;

ALTER FUNCTION public.agentpass_manual_wake_actor_role(uuid,uuid) OWNER TO agentpass_migrator;
GRANT SELECT ON TABLE public.memberships TO agentpass_migrator;
REVOKE ALL PRIVILEGES ON FUNCTION public.agentpass_manual_wake_actor_role(uuid,uuid)
  FROM PUBLIC, agentpass_signer, agentpass_backup, agentpass_maintenance;
GRANT EXECUTE ON FUNCTION public.agentpass_manual_wake_actor_role(uuid,uuid) TO agentpass_app;

COMMIT;
