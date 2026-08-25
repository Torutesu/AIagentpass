BEGIN;

-- Small Software's durable, tenant-qualified identity and approval preimages.
CREATE TABLE public.small_software_apps (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(), organization_id uuid NOT NULL REFERENCES public.organizations(id),
  owner_member_id uuid NOT NULL, slug text NOT NULL, name text NOT NULL, project_binding_digest bytea NOT NULL,
  lifecycle_state text NOT NULL DEFAULT 'draft' CHECK (lifecycle_state IN ('draft','private_preview','active','suspended','expired','deleting','deleted')),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(), updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  UNIQUE (organization_id, id), UNIQUE (organization_id, slug),
  FOREIGN KEY (organization_id, owner_member_id) REFERENCES public.memberships(organization_id, member_id)
);
CREATE TABLE public.small_software_releases (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(), organization_id uuid NOT NULL, app_id uuid NOT NULL,
  source_digest bytea NOT NULL, build_digest bytea NOT NULL, artifact_digest bytea NOT NULL, plan_digest bytea,
  state text NOT NULL DEFAULT 'requested' CHECK (state IN ('requested','source_received','analyzing','building','preview_ready','awaiting_approval','approved','deploying','active','rejected','build_failed','deployment_failed','superseded','suspended','expired','deleting','deleted','reconciliation_required')),
  requested_by_member_id uuid NOT NULL, created_at timestamptz NOT NULL DEFAULT clock_timestamp(), approved_at timestamptz, activated_at timestamptz,
  UNIQUE (organization_id, id), UNIQUE (organization_id, app_id, source_digest),
  FOREIGN KEY (organization_id, app_id) REFERENCES public.small_software_apps(organization_id, id),
  FOREIGN KEY (organization_id, requested_by_member_id) REFERENCES public.memberships(organization_id, member_id),
  CHECK (octet_length(source_digest) BETWEEN 16 AND 128), CHECK (octet_length(build_digest) BETWEEN 16 AND 128), CHECK (octet_length(artifact_digest) BETWEEN 16 AND 128)
);
CREATE TABLE public.small_software_publish_plans (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(), organization_id uuid NOT NULL, app_id uuid NOT NULL, release_id uuid NOT NULL,
  plan_digest bytea NOT NULL, requested_json jsonb NOT NULL, effective_json jsonb NOT NULL, risk_class text NOT NULL,
  authority_delta_digest bytea NOT NULL, created_by_member_id uuid NOT NULL, created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  UNIQUE (organization_id, id), UNIQUE (organization_id, release_id, plan_digest),
  FOREIGN KEY (organization_id, app_id) REFERENCES public.small_software_apps(organization_id, id),
  FOREIGN KEY (organization_id, release_id) REFERENCES public.small_software_releases(organization_id, id),
  FOREIGN KEY (organization_id, created_by_member_id) REFERENCES public.memberships(organization_id, member_id),
  CHECK (jsonb_typeof(requested_json) = 'object' AND jsonb_typeof(effective_json) = 'object')
);
CREATE TABLE public.small_software_approvals (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(), organization_id uuid NOT NULL, app_id uuid NOT NULL, release_id uuid NOT NULL, plan_id uuid NOT NULL,
  plan_digest bytea NOT NULL, artifact_digest bytea NOT NULL, approver_member_id uuid NOT NULL, session_operation_id uuid,
  assertion_digest bytea NOT NULL, state text NOT NULL DEFAULT 'approved' CHECK (state IN ('approved','revoked')),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  UNIQUE (organization_id, id), UNIQUE (organization_id, release_id, plan_digest),
  FOREIGN KEY (organization_id, app_id) REFERENCES public.small_software_apps(organization_id, id),
  FOREIGN KEY (organization_id, release_id) REFERENCES public.small_software_releases(organization_id, id),
  FOREIGN KEY (organization_id, plan_id) REFERENCES public.small_software_publish_plans(organization_id, id),
  FOREIGN KEY (organization_id, approver_member_id) REFERENCES public.memberships(organization_id, member_id)
);
CREATE INDEX small_software_releases_app_state ON public.small_software_releases(organization_id, app_id, state);
CREATE INDEX small_software_plans_release ON public.small_software_publish_plans(organization_id, release_id);
COMMENT ON TABLE public.small_software_releases IS 'Immutable source/build/artifact identity; mutation only through authority functions.';
COMMIT;
