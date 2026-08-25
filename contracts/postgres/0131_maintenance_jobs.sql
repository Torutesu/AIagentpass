BEGIN;
CREATE TABLE public.maintenance_jobs (
  job_id uuid PRIMARY KEY DEFAULT gen_random_uuid(), organization_id uuid NOT NULL REFERENCES public.organizations(id), provider_id uuid NOT NULL REFERENCES public.maintenance_providers(provider_id), advisory_id uuid NOT NULL REFERENCES public.maintenance_advisories(advisory_id), snapshot_id uuid NOT NULL REFERENCES public.maintenance_repository_snapshots(snapshot_id), policy_generation bigint NOT NULL, status text NOT NULL DEFAULT 'reserved' CHECK (status IN ('reserved','running','completed','cancelled','failed','uncertain')), plan_digest bytea NOT NULL, created_at timestamptz NOT NULL DEFAULT clock_timestamp(), updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
ALTER TABLE public.maintenance_jobs ENABLE ROW LEVEL SECURITY; ALTER TABLE public.maintenance_jobs FORCE ROW LEVEL SECURITY;
CREATE POLICY maintenance_jobs_tenant ON public.maintenance_jobs USING (organization_id = current_setting('agentpass.organization_id', true)::uuid) WITH CHECK (organization_id = current_setting('agentpass.organization_id', true)::uuid);
ALTER TABLE public.maintenance_jobs OWNER TO agentpass_migrator; REVOKE ALL ON public.maintenance_jobs FROM PUBLIC, agentpass_app, agentpass_signer, agentpass_backup, agentpass_maintenance; GRANT SELECT ON public.maintenance_jobs TO agentpass_app;
COMMIT;
