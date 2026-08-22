BEGIN;

-- Organization core authority boundary.
--
-- The organization repository currently owns the surrounding transaction: it
-- authenticates the human session, appends the admin-audit/outbox records,
-- and completes or abandons the idempotency record.  These functions own the
-- base organization/membership DML only.  The create primitive also acquires
-- the idempotency record because idempotency_records has a foreign key to the
-- organization and therefore cannot be acquired before the organization row
-- exists.  It deliberately leaves the acquired row in its pending state so
-- the repository can append audit/outbox and then complete it in the same
-- transaction.

CREATE FUNCTION public.agentpass_organization_create_with_owner(
  p_organization_id uuid,
  p_owner_member_id uuid,
  p_owner_membership_id uuid,
  p_name text,
  p_actor_principal text,
  p_idempotency_key text,
  p_request_hash text,
  p_created_at timestamptz DEFAULT NULL
)
RETURNS TABLE (
  outcome text,
  replayed boolean,
  organization_id uuid,
  name text,
  version bigint,
  created_at timestamptz,
  updated_at timestamptz,
  membership_id uuid,
  member_id uuid,
  role text,
  status text,
  membership_version bigint,
  membership_created_at timestamptz,
  membership_updated_at timestamptz,
  response_json jsonb
)
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  organization_row public.organizations%ROWTYPE;
  membership_row public.memberships%ROWTYPE;
  idempotency_row public.idempotency_records%ROWTYPE;
  created_timestamp timestamptz;
  inserted_organization boolean := false;
BEGIN
  -- Match the repository's bounded input contract.  The table constraints
  -- remain the final authority for values such as UUID format and names.
  IF p_organization_id IS NULL
     OR p_organization_id = '00000000-0000-0000-0000-000000000000'::uuid
     OR p_owner_member_id IS NULL
     OR p_owner_member_id = '00000000-0000-0000-0000-000000000000'::uuid
     OR p_owner_membership_id IS NULL
     OR p_owner_membership_id = '00000000-0000-0000-0000-000000000000'::uuid
     OR p_name IS NULL
     OR char_length(p_name) NOT BETWEEN 1 AND 128
     OR p_name ~ '[[:cntrl:]]'
     OR (p_created_at IS NOT NULL AND NOT pg_catalog.isfinite(p_created_at))
     OR p_actor_principal IS NULL
     OR char_length(p_actor_principal) NOT BETWEEN 1 AND 256
     OR p_actor_principal ~ '[[:cntrl:]]'
     OR p_idempotency_key IS NULL
     OR p_idempotency_key !~ '^[A-Za-z0-9._~-]{8,255}$'
     OR p_request_hash IS NULL
     OR p_request_hash !~ '^[0-9a-f]{64}$' THEN
    RAISE EXCEPTION USING
      ERRCODE = 'invalid_parameter_value',
      MESSAGE = 'organization creation authority input is invalid';
  END IF;

  -- This is the same outer order used by the human-session and membership
  -- authority paths: human authority, then organization.  It also makes a
  -- direct function call safe when the repository has not acquired the
  -- advisory locks yet.
  PERFORM pg_advisory_xact_lock(
    hashtextextended('agentpass:human:authority:' || p_owner_member_id::text, 0)
  );
  PERFORM pg_advisory_xact_lock(
    hashtextextended('agentpass:organization:' || p_organization_id::text, 0)
  );

  -- Use one database timestamp for both columns when the caller did not
  -- supply one.  This preserves the repository's explicit created_at option
  -- without allowing the two initial timestamps to drift.
  created_timestamp := COALESCE(p_created_at, pg_catalog.clock_timestamp());

  INSERT INTO public.organizations (id, name, created_at, updated_at)
  VALUES (p_organization_id, p_name, created_timestamp, created_timestamp)
  ON CONFLICT (id) DO NOTHING
  RETURNING * INTO organization_row;
  inserted_organization := FOUND;

  -- The organization row is deliberately established before this lookup: the
  -- idempotency relation has an FK to organizations.  This is the same
  -- ordering as the current repository implementation.
  DELETE FROM public.idempotency_records
  WHERE organization_id = p_organization_id
    AND principal_id = p_actor_principal
    AND idempotency_key = p_idempotency_key
    AND expires_at <= pg_catalog.clock_timestamp();

  INSERT INTO public.idempotency_records (
    organization_id,
    principal_id,
    idempotency_key,
    request_hash,
    response_status,
    response_json,
    expires_at
  ) VALUES (
    p_organization_id,
    p_actor_principal,
    p_idempotency_key,
    p_request_hash,
    102,
    '{}'::jsonb,
    pg_catalog.clock_timestamp() + interval '24 hours'
  )
  ON CONFLICT (organization_id, principal_id, idempotency_key) DO NOTHING;

  SELECT *
    INTO idempotency_row
  FROM public.idempotency_records
  WHERE organization_id = p_organization_id
    AND principal_id = p_actor_principal
    AND idempotency_key = p_idempotency_key
  FOR UPDATE;

  IF NOT FOUND THEN
    RAISE EXCEPTION USING
      ERRCODE = 'serialization_failure',
      MESSAGE = 'organization idempotency record could not be acquired';
  END IF;

  IF idempotency_row.request_hash IS DISTINCT FROM p_request_hash THEN
    RAISE EXCEPTION USING
      ERRCODE = 'unique_violation',
      MESSAGE = 'idempotency key was already used with a different request';
  END IF;

  IF idempotency_row.response_status <> 102
     OR idempotency_row.response_json IS DISTINCT FROM '{}'::jsonb THEN
    -- A completed row is a replay.  No organization or membership DML is
    -- attempted after this branch, so a retry cannot create a second owner.
    IF NOT inserted_organization THEN
      RETURN QUERY SELECT
        'replayed'::text,
        true,
        NULL::uuid,
        NULL::text,
        NULL::bigint,
        NULL::timestamptz,
        NULL::timestamptz,
        NULL::uuid,
        NULL::uuid,
        NULL::text,
        NULL::text,
        NULL::bigint,
        NULL::timestamptz,
        NULL::timestamptz,
        idempotency_row.response_json;
      RETURN;
    END IF;

    -- A completed idempotency row must correspond to an already committed
    -- organization.  Seeing a newly inserted row here means the database
    -- state is inconsistent with the FK-backed idempotency contract.
    RAISE EXCEPTION USING
      ERRCODE = 'serialization_failure',
      MESSAGE = 'organization idempotency state is inconsistent';
  END IF;

  IF NOT inserted_organization THEN
    -- The repository will abandon this still-pending row and return its
    -- existing null/no-op result.  Do not delete it here: keeping ownership
    -- of completion/abandonment at the repository layer preserves the
    -- existing transaction choreography.
    RETURN QUERY SELECT
      'not_created'::text,
      false,
      NULL::uuid,
      NULL::text,
      NULL::bigint,
      NULL::timestamptz,
      NULL::timestamptz,
      NULL::uuid,
      NULL::uuid,
      NULL::text,
      NULL::text,
      NULL::bigint,
      NULL::timestamptz,
      NULL::timestamptz,
      NULL::jsonb;
    RETURN;
  END IF;

  -- The owner is the only membership created by this primitive.  The
  -- memberships_last_active_owner trigger remains installed and unchanged;
  -- this INSERT therefore retains the existing owner invariant and all FK /
  -- epoch trigger behavior.
  INSERT INTO public.memberships (
    organization_id, id, member_id, role, status
  ) VALUES (
    p_organization_id, p_owner_membership_id, p_owner_member_id, 'owner', 'active'
  )
  RETURNING * INTO membership_row;

  RETURN QUERY SELECT
    'created'::text,
    false,
    organization_row.id,
    organization_row.name,
    organization_row.version,
    organization_row.created_at,
    organization_row.updated_at,
    membership_row.id,
    membership_row.member_id,
    membership_row.role,
    membership_row.status,
    membership_row.version,
    membership_row.created_at,
    membership_row.updated_at,
    NULL::jsonb;
END;
$$;

-- Rename is intentionally narrower than create.  The repository's mutate()
-- transaction still acquires/checks idempotency and appends audit/outbox;
-- this function only performs the tenant-scoped optimistic update and returns
-- the exact row needed to build those existing records.
CREATE FUNCTION public.agentpass_organization_rename(
  p_organization_id uuid,
  p_actor_member_id uuid,
  p_name text,
  p_expected_version bigint
)
RETURNS TABLE (
  organization_id uuid,
  name text,
  version bigint,
  created_at timestamptz,
  updated_at timestamptz
)
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  organization_row public.organizations%ROWTYPE;
  actor_role text;
BEGIN
  IF p_organization_id IS NULL
     OR p_organization_id = '00000000-0000-0000-0000-000000000000'::uuid
     OR p_actor_member_id IS NULL
     OR p_actor_member_id = '00000000-0000-0000-0000-000000000000'::uuid
     OR p_name IS NULL
     OR char_length(p_name) NOT BETWEEN 1 AND 128
     OR p_name ~ '[[:cntrl:]]'
     OR p_expected_version IS NULL
     OR p_expected_version < 1 THEN
    RAISE EXCEPTION USING
      ERRCODE = 'invalid_parameter_value',
      MESSAGE = 'organization rename authority input is invalid';
  END IF;

  PERFORM pg_advisory_xact_lock(
    hashtextextended('agentpass:organization:' || p_organization_id::text, 0)
  );

  -- Lock in the same organization -> membership order used by the other
  -- organization mutation paths.  Checking role under the row lock prevents
  -- a concurrent revocation/demotion from authorizing a rename after it has
  -- committed.
  SELECT o.*
    INTO organization_row
  FROM public.organizations AS o
  WHERE o.id = p_organization_id
  FOR UPDATE;
  IF NOT FOUND THEN
    RETURN;
  END IF;

  SELECT m.role
    INTO actor_role
  FROM public.memberships AS m
  WHERE m.organization_id = p_organization_id
    AND m.member_id = p_actor_member_id
    AND m.status = 'active'
  FOR UPDATE;
  IF NOT FOUND OR actor_role NOT IN ('owner', 'admin') THEN
    RETURN;
  END IF;

  IF organization_row.version IS DISTINCT FROM p_expected_version THEN
    RETURN;
  END IF;

  UPDATE public.organizations AS o
  SET name = p_name,
      version = o.version + 1,
      updated_at = pg_catalog.clock_timestamp()
  WHERE o.id = p_organization_id
    AND o.version = p_expected_version
  RETURNING o.* INTO organization_row;

  IF NOT FOUND THEN
    RETURN;
  END IF;

  RETURN QUERY SELECT
    organization_row.id,
    organization_row.name,
    organization_row.version,
    organization_row.created_at,
    organization_row.updated_at;
END;
$$;

ALTER FUNCTION public.agentpass_organization_create_with_owner(
  uuid, uuid, uuid, text, text, text, text, timestamptz
) OWNER TO agentpass_migrator;
ALTER FUNCTION public.agentpass_organization_rename(
  uuid, uuid, text, bigint
) OWNER TO agentpass_migrator;

REVOKE ALL PRIVILEGES ON FUNCTION public.agentpass_organization_create_with_owner(
  uuid, uuid, uuid, text, text, text, text, timestamptz
) FROM PUBLIC, agentpass_signer, agentpass_backup, agentpass_maintenance;
REVOKE ALL PRIVILEGES ON FUNCTION public.agentpass_organization_rename(
  uuid, uuid, text, bigint
) FROM PUBLIC, agentpass_signer, agentpass_backup, agentpass_maintenance;

GRANT EXECUTE ON FUNCTION public.agentpass_organization_create_with_owner(
  uuid, uuid, uuid, text, text, text, text, timestamptz
) TO agentpass_app;
GRANT EXECUTE ON FUNCTION public.agentpass_organization_rename(
  uuid, uuid, text, bigint
) TO agentpass_app;

COMMIT;
