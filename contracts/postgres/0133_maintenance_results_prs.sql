BEGIN;
CREATE TABLE public.maintenance_results (
  result_id uuid PRIMARY KEY DEFAULT gen_random_uuid(), job_id uuid NOT NULL REFERENCES public.maintenance_jobs(job_id), organization_id uuid NOT NULL REFERENCES public.organizations(id), result_commit text, result_tree text, patch_digest bytea, evidence jsonb NOT NULL DEFAULT '{}'::jsonb, status text NOT NULL CHECK (status IN ('passed','failed','uncertain')), created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE public.maintenance_pull_requests (
  pull_request_id uuid PRIMARY KEY DEFAULT gen_random_uuid(), job_id uuid NOT NULL REFERENCES public.maintenance_jobs(job_id), organization_id uuid NOT NULL REFERENCES public.organizations(id), repository_id text NOT NULL, external_number bigint NOT NULL, head_commit text NOT NULL, base_commit text NOT NULL, state text NOT NULL CHECK (state IN ('draft','open','closed','merged')), created_at timestamptz NOT NULL DEFAULT clock_timestamp(), UNIQUE(repository_id,external_number)
);
ALTER TABLE public.maintenance_results ENABLE ROW LEVEL SECURITY; ALTER TABLE public.maintenance_pull_requests ENABLE ROW LEVEL SECURITY; ALTER TABLE public.maintenance_results FORCE ROW LEVEL SECURITY; ALTER TABLE public.maintenance_pull_requests FORCE ROW LEVEL SECURITY;
CREATE POLICY maintenance_results_tenant ON public.maintenance_results USING (organization_id = current_setting('agentpass.organization_id', true)::uuid) WITH CHECK (organization_id = current_setting('agentpass.organization_id', true)::uuid); CREATE POLICY maintenance_prs_tenant ON public.maintenance_pull_requests USING (organization_id = current_setting('agentpass.organization_id', true)::uuid) WITH CHECK (organization_id = current_setting('agentpass.organization_id', true)::uuid);
ALTER TABLE public.maintenance_results OWNER TO agentpass_migrator; ALTER TABLE public.maintenance_pull_requests OWNER TO agentpass_migrator; REVOKE ALL ON public.maintenance_results, public.maintenance_pull_requests FROM PUBLIC, agentpass_app, agentpass_signer, agentpass_backup, agentpass_maintenance; GRANT SELECT ON public.maintenance_results, public.maintenance_pull_requests TO agentpass_app;
COMMIT;
