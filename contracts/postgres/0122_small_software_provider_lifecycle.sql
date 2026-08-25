BEGIN;
CREATE TABLE public.small_software_provider_operations (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(), organization_id uuid NOT NULL, app_id uuid NOT NULL, release_id uuid,
  operation_kind text NOT NULL, operation_key text NOT NULL, request_digest bytea NOT NULL, provider text NOT NULL,
  state text NOT NULL DEFAULT 'reserved' CHECK (state IN ('reserved','submitted','unknown','succeeded','failed','cancelled','reconciled')),
  provider_operation_id text, result_digest bytea, created_at timestamptz NOT NULL DEFAULT clock_timestamp(), reconciled_at timestamptz,
  UNIQUE (organization_id, id), UNIQUE (organization_id, operation_key),
  FOREIGN KEY (organization_id, app_id) REFERENCES public.small_software_apps(organization_id, id),
  FOREIGN KEY (organization_id, release_id) REFERENCES public.small_software_releases(organization_id, id)
);
CREATE TABLE public.small_software_lifecycle_jobs (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(), organization_id uuid NOT NULL, app_id uuid NOT NULL, release_id uuid,
  job_kind text NOT NULL CHECK (job_kind IN ('expire','suspend','delete','rollback','reconcile')), run_after timestamptz NOT NULL,
  state text NOT NULL DEFAULT 'queued' CHECK (state IN ('queued','leased','running','succeeded','failed','reconciliation_required','cancelled')),
  idempotency_key text NOT NULL, attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0), locked_until timestamptz, created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  UNIQUE (organization_id, idempotency_key), FOREIGN KEY (organization_id, app_id) REFERENCES public.small_software_apps(organization_id, id),
  FOREIGN KEY (organization_id, release_id) REFERENCES public.small_software_releases(organization_id, id)
);
CREATE INDEX small_software_lifecycle_due ON public.small_software_lifecycle_jobs(state, run_after);
COMMIT;
