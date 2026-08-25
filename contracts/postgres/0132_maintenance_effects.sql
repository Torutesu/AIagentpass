BEGIN;
CREATE TABLE public.maintenance_effects (
  effect_id uuid PRIMARY KEY DEFAULT gen_random_uuid(), job_id uuid NOT NULL REFERENCES public.maintenance_jobs(job_id), organization_id uuid NOT NULL REFERENCES public.organizations(id), effect_kind text NOT NULL CHECK (effect_kind IN ('snapshot_read','patch_propose','branch_create','pull_request_create','test_execute','conformance_execute')), idempotency_key text NOT NULL, state text NOT NULL DEFAULT 'reserved' CHECK (state IN ('reserved','started','accepted','completed','cancelled','uncertain','failed')), request_digest bytea NOT NULL, response_digest bytea, reserved_at timestamptz NOT NULL DEFAULT clock_timestamp(), completed_at timestamptz, UNIQUE(job_id,effect_kind,idempotency_key)
);
ALTER TABLE public.maintenance_effects ENABLE ROW LEVEL SECURITY; ALTER TABLE public.maintenance_effects FORCE ROW LEVEL SECURITY; CREATE POLICY maintenance_effects_tenant ON public.maintenance_effects USING (organization_id = current_setting('agentpass.organization_id', true)::uuid) WITH CHECK (organization_id = current_setting('agentpass.organization_id', true)::uuid);
ALTER TABLE public.maintenance_effects OWNER TO agentpass_migrator; REVOKE ALL ON public.maintenance_effects FROM PUBLIC, agentpass_app, agentpass_signer, agentpass_backup, agentpass_maintenance; GRANT SELECT ON public.maintenance_effects TO agentpass_app;
COMMIT;
