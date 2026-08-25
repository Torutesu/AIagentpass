BEGIN;
CREATE TABLE public.maintenance_providers (
  provider_id uuid PRIMARY KEY DEFAULT gen_random_uuid(), provider_slug text NOT NULL UNIQUE,
  display_name text NOT NULL, status text NOT NULL DEFAULT 'active' CHECK (status IN ('active','suspended','revoked')),
  verified_domains jsonb NOT NULL DEFAULT '[]'::jsonb, created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  status_changed_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE public.maintenance_provider_keys (
  provider_id uuid NOT NULL REFERENCES public.maintenance_providers(provider_id), key_id text NOT NULL,
  algorithm text NOT NULL, public_key bytea NOT NULL, purpose text NOT NULL,
  valid_from timestamptz NOT NULL, valid_until timestamptz, compromised_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(), PRIMARY KEY (provider_id,key_id,purpose),
  CHECK (valid_until IS NULL OR valid_until > valid_from)
);
ALTER TABLE public.maintenance_providers OWNER TO agentpass_migrator;
ALTER TABLE public.maintenance_provider_keys OWNER TO agentpass_migrator;
REVOKE ALL ON public.maintenance_providers, public.maintenance_provider_keys FROM PUBLIC, agentpass_app, agentpass_signer, agentpass_backup, agentpass_maintenance;
GRANT SELECT ON public.maintenance_providers, public.maintenance_provider_keys TO agentpass_maintenance;
COMMIT;
