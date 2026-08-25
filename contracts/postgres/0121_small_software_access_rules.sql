BEGIN;
CREATE TABLE public.small_software_access_rules (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(), organization_id uuid NOT NULL, app_id uuid NOT NULL,
  subject_kind text NOT NULL CHECK (subject_kind IN ('member','group','organization')), subject_id uuid, app_role text NOT NULL CHECK (app_role IN ('viewer','admin')),
  state text NOT NULL DEFAULT 'active' CHECK (state IN ('pending','active','expired','revoked')), approved_plan_id uuid, expires_at timestamptz,
  created_by_member_id uuid NOT NULL, created_at timestamptz NOT NULL DEFAULT clock_timestamp(), revoked_at timestamptz,
  UNIQUE (organization_id, id), UNIQUE (organization_id, app_id, subject_kind, subject_id),
  FOREIGN KEY (organization_id, app_id) REFERENCES public.small_software_apps(organization_id, id),
  FOREIGN KEY (organization_id, approved_plan_id) REFERENCES public.small_software_publish_plans(organization_id, id),
  FOREIGN KEY (organization_id, created_by_member_id) REFERENCES public.memberships(organization_id, member_id),
  CHECK ((subject_kind = 'organization' AND subject_id IS NULL) OR (subject_kind <> 'organization' AND subject_id IS NOT NULL))
);
CREATE TABLE public.small_software_egress_rules (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(), organization_id uuid NOT NULL, app_id uuid NOT NULL, release_id uuid NOT NULL,
  origin text NOT NULL, methods text[] NOT NULL, operations text[] NOT NULL DEFAULT '{}', max_calls bigint, max_bytes bigint,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(), UNIQUE (organization_id, id),
  FOREIGN KEY (organization_id, app_id) REFERENCES public.small_software_apps(organization_id, id),
  FOREIGN KEY (organization_id, release_id) REFERENCES public.small_software_releases(organization_id, id), CHECK (origin LIKE 'https://%')
);
CREATE INDEX small_software_access_app_state ON public.small_software_access_rules(organization_id, app_id, state);
COMMIT;
