BEGIN;
CREATE TABLE public.maintenance_receipts (
  receipt_id uuid PRIMARY KEY DEFAULT gen_random_uuid(), job_id uuid NOT NULL REFERENCES public.maintenance_jobs(job_id), organization_id uuid NOT NULL REFERENCES public.organizations(id), receipt_digest bytea NOT NULL UNIQUE, receipt jsonb NOT NULL, signed_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE public.maintenance_exceptions (
  exception_id uuid PRIMARY KEY DEFAULT gen_random_uuid(), job_id uuid NOT NULL REFERENCES public.maintenance_jobs(job_id), organization_id uuid NOT NULL REFERENCES public.organizations(id), reason text NOT NULL, expires_at timestamptz NOT NULL, resolved_at timestamptz
);
ALTER TABLE public.maintenance_receipts ENABLE ROW LEVEL SECURITY; ALTER TABLE public.maintenance_exceptions ENABLE ROW LEVEL SECURITY; ALTER TABLE public.maintenance_receipts FORCE ROW LEVEL SECURITY; ALTER TABLE public.maintenance_exceptions FORCE ROW LEVEL SECURITY;
CREATE POLICY maintenance_receipts_tenant ON public.maintenance_receipts USING (organization_id = current_setting('agentpass.organization_id', true)::uuid) WITH CHECK (organization_id = current_setting('agentpass.organization_id', true)::uuid); CREATE POLICY maintenance_exceptions_tenant ON public.maintenance_exceptions USING (organization_id = current_setting('agentpass.organization_id', true)::uuid) WITH CHECK (organization_id = current_setting('agentpass.organization_id', true)::uuid);
ALTER TABLE public.maintenance_receipts OWNER TO agentpass_migrator; ALTER TABLE public.maintenance_exceptions OWNER TO agentpass_migrator; REVOKE ALL ON public.maintenance_receipts, public.maintenance_exceptions FROM PUBLIC, agentpass_app, agentpass_signer, agentpass_backup, agentpass_maintenance; GRANT SELECT ON public.maintenance_receipts, public.maintenance_exceptions TO agentpass_app;
COMMIT;
