BEGIN;
CREATE TABLE public.maintenance_usage_attestations (
  attestation_id uuid PRIMARY KEY DEFAULT gen_random_uuid(), organization_id uuid NOT NULL REFERENCES public.organizations(id), snapshot_id uuid NOT NULL REFERENCES public.maintenance_repository_snapshots(snapshot_id), provider_id uuid NOT NULL REFERENCES public.maintenance_providers(provider_id), release_id text NOT NULL, source_commit text NOT NULL, classification text NOT NULL CHECK (classification IN ('confirmed','probable','possible','not_affected','unknown')), evidence jsonb NOT NULL, result_digest bytea NOT NULL, fresh_until timestamptz NOT NULL, created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE public.maintenance_policies (
  policy_id uuid PRIMARY KEY DEFAULT gen_random_uuid(), organization_id uuid NOT NULL REFERENCES public.organizations(id), generation bigint NOT NULL CHECK (generation > 0), policy jsonb NOT NULL, approved_by uuid, approved_at timestamptz, active boolean NOT NULL DEFAULT true, created_at timestamptz NOT NULL DEFAULT clock_timestamp(), UNIQUE(organization_id,generation)
);
ALTER TABLE public.maintenance_usage_attestations ENABLE ROW LEVEL SECURITY; ALTER TABLE public.maintenance_policies ENABLE ROW LEVEL SECURITY; ALTER TABLE public.maintenance_usage_attestations FORCE ROW LEVEL SECURITY; ALTER TABLE public.maintenance_policies FORCE ROW LEVEL SECURITY;
CREATE POLICY maintenance_usage_tenant ON public.maintenance_usage_attestations USING (organization_id = current_setting('agentpass.organization_id', true)::uuid) WITH CHECK (organization_id = current_setting('agentpass.organization_id', true)::uuid);
CREATE POLICY maintenance_policy_tenant ON public.maintenance_policies USING (organization_id = current_setting('agentpass.organization_id', true)::uuid) WITH CHECK (organization_id = current_setting('agentpass.organization_id', true)::uuid);
ALTER TABLE public.maintenance_usage_attestations OWNER TO agentpass_migrator; ALTER TABLE public.maintenance_policies OWNER TO agentpass_migrator; REVOKE ALL ON public.maintenance_usage_attestations, public.maintenance_policies FROM PUBLIC, agentpass_app, agentpass_signer, agentpass_backup, agentpass_maintenance; GRANT SELECT ON public.maintenance_usage_attestations, public.maintenance_policies TO agentpass_app;
COMMIT;
