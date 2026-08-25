BEGIN;
CREATE TABLE public.maintenance_repository_installations (
  installation_id uuid PRIMARY KEY DEFAULT gen_random_uuid(), organization_id uuid NOT NULL REFERENCES public.organizations(id), provider_name text NOT NULL DEFAULT 'github', external_installation_id text NOT NULL, status text NOT NULL DEFAULT 'active' CHECK (status IN ('active','paused','revoked')), created_at timestamptz NOT NULL DEFAULT clock_timestamp(), UNIQUE(organization_id,provider_name,external_installation_id)
);
CREATE TABLE public.maintenance_repository_snapshots (
  snapshot_id uuid PRIMARY KEY DEFAULT gen_random_uuid(), installation_id uuid NOT NULL REFERENCES public.maintenance_repository_installations(installation_id), organization_id uuid NOT NULL REFERENCES public.organizations(id), repository_id text NOT NULL, repository_name text NOT NULL, default_branch text NOT NULL, base_commit text NOT NULL, captured_at timestamptz NOT NULL DEFAULT clock_timestamp(), UNIQUE(organization_id,repository_id,base_commit)
);
ALTER TABLE public.maintenance_repository_installations ENABLE ROW LEVEL SECURITY; ALTER TABLE public.maintenance_repository_snapshots ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.maintenance_repository_installations FORCE ROW LEVEL SECURITY; ALTER TABLE public.maintenance_repository_snapshots FORCE ROW LEVEL SECURITY;
CREATE POLICY maintenance_installations_tenant ON public.maintenance_repository_installations USING (organization_id = current_setting('agentpass.organization_id', true)::uuid) WITH CHECK (organization_id = current_setting('agentpass.organization_id', true)::uuid);
CREATE POLICY maintenance_snapshots_tenant ON public.maintenance_repository_snapshots USING (organization_id = current_setting('agentpass.organization_id', true)::uuid) WITH CHECK (organization_id = current_setting('agentpass.organization_id', true)::uuid);
ALTER TABLE public.maintenance_repository_installations OWNER TO agentpass_migrator; ALTER TABLE public.maintenance_repository_snapshots OWNER TO agentpass_migrator;
REVOKE ALL ON public.maintenance_repository_installations, public.maintenance_repository_snapshots FROM PUBLIC, agentpass_app, agentpass_signer, agentpass_backup, agentpass_maintenance;
GRANT SELECT ON public.maintenance_repository_installations, public.maintenance_repository_snapshots TO agentpass_app;
COMMIT;
