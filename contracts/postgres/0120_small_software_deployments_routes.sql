BEGIN;
CREATE TABLE public.small_software_deployments (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(), organization_id uuid NOT NULL, app_id uuid NOT NULL, release_id uuid NOT NULL,
  plan_digest bytea NOT NULL, artifact_digest bytea NOT NULL, provider text NOT NULL, provider_deployment_id text,
  state text NOT NULL DEFAULT 'reserved' CHECK (state IN ('reserved','submitted','unknown','reconciled','failed','suspended','deleted')),
  operation_key text NOT NULL, receipt_json jsonb, generation bigint, created_at timestamptz NOT NULL DEFAULT clock_timestamp(), reconciled_at timestamptz,
  UNIQUE (organization_id, id), UNIQUE (organization_id, operation_key),
  FOREIGN KEY (organization_id, app_id) REFERENCES public.small_software_apps(organization_id, id),
  FOREIGN KEY (organization_id, release_id) REFERENCES public.small_software_releases(organization_id, id)
);
CREATE TABLE public.small_software_routes (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(), organization_id uuid NOT NULL, app_id uuid NOT NULL, release_id uuid NOT NULL,
  route text NOT NULL, active_generation bigint NOT NULL DEFAULT 0, state text NOT NULL DEFAULT 'inactive' CHECK (state IN ('inactive','active','suspended','deleted')),
  deployment_id uuid, activated_at timestamptz, updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  UNIQUE (organization_id, id), UNIQUE (organization_id, route), UNIQUE (organization_id, app_id),
  FOREIGN KEY (organization_id, app_id) REFERENCES public.small_software_apps(organization_id, id),
  FOREIGN KEY (organization_id, release_id) REFERENCES public.small_software_releases(organization_id, id),
  FOREIGN KEY (organization_id, deployment_id) REFERENCES public.small_software_deployments(organization_id, id)
);
CREATE INDEX small_software_deployments_release ON public.small_software_deployments(organization_id, release_id, state);
COMMIT;
