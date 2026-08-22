BEGIN;

-- Membership administration authority boundary.
--
-- The online application may read organizations and memberships, but it must
-- not update membership role/status directly.  These two entry points own
-- only the membership mutation itself and the database-local consequences
-- that must be atomic with it.  Request idempotency, the tamper-evident
-- admin-audit/outbox append, and onAuthorityReduction propagation remain
-- repository-level orchestration and therefore happen in the same caller
-- transaction after this function returns.
--
-- Public signatures:
--   agentpass_human_membership_role_update(
--     organization_id uuid,
--     actor_member_id uuid,
--     target_member_id uuid,
--     role text,
--     expected_version bigint,
--     revoked_at timestamptz
--   ) RETURNS the updated membership row
--
--   agentpass_human_membership_remove(
--     organization_id uuid,
--     actor_member_id uuid,
--     target_member_id uuid,
--     expected_version bigint,
--     removed_at timestamptz
--   ) RETURNS the revoked membership row
--
-- Lock order is deliberately identical for both operations and for the
-- 0106 human authority wrappers:
--   human-authority(target member) -> organization -> session set(target)
--   -> membership rows -> owner-set (when the owner invariant is relevant).
-- The existing membership BEFORE/AFTER triggers then advance session_epoch
-- and invalidate identity state.  The explicit session revoke call below is
-- retained because it is the existing row/challenge revocation contract and
-- must remain part of the same transaction.

CREATE FUNCTION public.agentpass_human_membership_role_update(
  p_organization_id uuid,
  p_actor_member_id uuid,
  p_target_member_id uuid,
  p_role text,
  p_expected_version bigint,
  p_revoked_at timestamptz
)
RETURNS TABLE (
  organization_id uuid,
  membership_id uuid,
  member_id uuid,
  role text,
  status text,
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
  max_bigint constant bigint := 9223372036854775807::bigint;
  actor_row public.memberships%ROWTYPE;
  target_row public.memberships%ROWTYPE;
  updated_row public.memberships%ROWTYPE;
  session_revoke_result jsonb;
BEGIN
  IF p_organization_id IS NULL
     OR p_actor_member_id IS NULL
     OR p_target_member_id IS NULL
     OR p_role IS NULL
     OR p_role NOT IN ('owner', 'admin', 'auditor', 'viewer')
     OR p_expected_version IS NULL
     OR p_expected_version < 1
     OR p_revoked_at IS NULL
     OR NOT pg_catalog.isfinite(p_revoked_at) THEN
    RAISE EXCEPTION USING
      ERRCODE = 'invalid_parameter_value',
      MESSAGE = 'membership role update input is invalid';
  END IF;

  -- This is the same target-member boundary used by session issue/rotation
  -- and by the repository's transition lock.  It is taken before the tenant
  -- lock so a session operation and a membership operation cannot invert the
  -- human-authority edge.
  PERFORM pg_advisory_xact_lock(
    hashtextextended('agentpass:human:authority:' || p_target_member_id::text, 0)
  );
  PERFORM pg_advisory_xact_lock(
    hashtextextended('agentpass:organization:' || p_organization_id::text, 0)
  );
  PERFORM pg_advisory_xact_lock(
    hashtextextended('agentpass:human:sessions:' || p_target_member_id::text, 0)
  );

  -- The actor is tenant-qualified and must be an active owner/admin.  The
  -- row lock makes a concurrent actor-role reduction serialize with this
  -- authorization decision.
  SELECT m.*
    INTO actor_row
  FROM public.memberships AS m
  WHERE m.organization_id = p_organization_id
    AND m.member_id = p_actor_member_id
  FOR UPDATE;

  IF NOT FOUND
     OR actor_row.status IS DISTINCT FROM 'active'
     OR actor_row.role IS NULL
     OR actor_row.role NOT IN ('owner', 'admin') THEN
    RAISE EXCEPTION USING
      ERRCODE = 'insufficient_privilege',
      MESSAGE = 'membership operation is not allowed';
  END IF;

  -- The target lookup is tenant-bound and is the authoritative optimistic
  -- concurrency fence.  A stale version is a serialization failure so the
  -- repository's existing retry/error mapping treats it as a version
  -- conflict rather than accepting a lost update.
  SELECT m.*
    INTO target_row
  FROM public.memberships AS m
  WHERE m.organization_id = p_organization_id
    AND m.member_id = p_target_member_id
  FOR UPDATE;

  IF NOT FOUND OR target_row.status IS DISTINCT FROM 'active' THEN
    RAISE EXCEPTION USING
      ERRCODE = 'foreign_key_violation',
      CONSTRAINT = 'memberships_active_target',
      MESSAGE = 'organization member was not found';
  END IF;

  IF target_row.version IS DISTINCT FROM p_expected_version THEN
    RAISE EXCEPTION USING
      ERRCODE = 'serialization_failure',
      CONSTRAINT = 'memberships_version',
      MESSAGE = 'organization member version is stale';
  END IF;

  -- Only an owner may change an owner, and only an owner may grant owner.
  -- This preserves the current repository authorization semantics even when
  -- the function is invoked directly through the application role.
  IF (target_row.role = 'owner' AND actor_row.role IS DISTINCT FROM 'owner')
     OR (p_role = 'owner' AND actor_row.role IS DISTINCT FROM 'owner') THEN
    RAISE EXCEPTION USING
      ERRCODE = 'insufficient_privilege',
      MESSAGE = 'membership operation is not allowed';
  END IF;

  -- The existing last-owner trigger is the final authority, but take its
  -- namespace lock before the UPDATE so the explicit precheck and the trigger
  -- observe the same owner set.  Locking it after the membership row matches
  -- the legacy trigger order and avoids an owner-lock -> row-lock inversion.
  IF target_row.role = 'owner' OR p_role = 'owner' THEN
    PERFORM pg_advisory_xact_lock(
      hashtextextended('agentpass:memberships:owners:' || p_organization_id::text, 0)
    );
  END IF;

  IF target_row.role = 'owner'
     AND p_role IS DISTINCT FROM 'owner'
     AND NOT EXISTS (
       SELECT 1
       FROM public.memberships AS m
       WHERE m.organization_id = p_organization_id
         AND m.role = 'owner'
         AND m.status = 'active'
         AND m.id IS DISTINCT FROM target_row.id
     ) THEN
    RAISE EXCEPTION USING
      ERRCODE = 'check_violation',
      CONSTRAINT = 'memberships_last_active_owner',
      MESSAGE = 'cannot remove the last active organization owner';
  END IF;

  IF target_row.version = max_bigint THEN
    RAISE EXCEPTION USING
      ERRCODE = 'numeric_value_out_of_range',
      CONSTRAINT = 'memberships_version_positive',
      MESSAGE = 'membership version cannot advance beyond bigint';
  END IF;

  UPDATE public.memberships AS target
     SET role = p_role,
         version = target.version + 1,
         updated_at = pg_catalog.clock_timestamp()
   WHERE target.organization_id = p_organization_id
     AND target.member_id = p_target_member_id
     AND target.status = 'active'
     AND target.version = p_expected_version
     AND (target.role <> 'owner' OR actor_row.role = 'owner')
     AND (p_role <> 'owner' OR actor_row.role = 'owner')
  RETURNING target.* INTO updated_row;

  IF NOT FOUND THEN
    RAISE EXCEPTION USING
      ERRCODE = 'serialization_failure',
      CONSTRAINT = 'memberships_mutation_cas',
      MESSAGE = 'membership role update lost its authority binding';
  END IF;

  -- The UPDATE triggers have already advanced the membership authority epoch
  -- and invalidated identity state.  This call is intentionally retained for
  -- the existing explicit human-session/challenge revoke contract and is
  -- atomic with both the role transition and the caller's audit/outbox work.
  SELECT public.agentpass_human_member_session_revoke(
    p_target_member_id,
    p_organization_id,
    p_revoked_at,
    'membership_role_changed'
  ) INTO session_revoke_result;
  IF session_revoke_result IS NULL THEN
    RAISE EXCEPTION USING
      ERRCODE = 'serialization_failure',
      MESSAGE = 'human session authority is unavailable';
  END IF;

  RETURN QUERY
  SELECT updated_row.organization_id,
         updated_row.id,
         updated_row.member_id,
         updated_row.role,
         updated_row.status,
         updated_row.version,
         updated_row.created_at,
         updated_row.updated_at;
END;
$$;

CREATE FUNCTION public.agentpass_human_membership_remove(
  p_organization_id uuid,
  p_actor_member_id uuid,
  p_target_member_id uuid,
  p_expected_version bigint,
  p_removed_at timestamptz
)
RETURNS TABLE (
  organization_id uuid,
  membership_id uuid,
  member_id uuid,
  role text,
  status text,
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
  max_bigint constant bigint := 9223372036854775807::bigint;
  actor_row public.memberships%ROWTYPE;
  target_row public.memberships%ROWTYPE;
  updated_row public.memberships%ROWTYPE;
  session_revoke_result jsonb;
BEGIN
  IF p_organization_id IS NULL
     OR p_actor_member_id IS NULL
     OR p_target_member_id IS NULL
     OR p_expected_version IS NULL
     OR p_expected_version < 1
     OR p_removed_at IS NULL
     OR NOT pg_catalog.isfinite(p_removed_at) THEN
    RAISE EXCEPTION USING
      ERRCODE = 'invalid_parameter_value',
      MESSAGE = 'membership removal input is invalid';
  END IF;

  PERFORM pg_advisory_xact_lock(
    hashtextextended('agentpass:human:authority:' || p_target_member_id::text, 0)
  );
  PERFORM pg_advisory_xact_lock(
    hashtextextended('agentpass:organization:' || p_organization_id::text, 0)
  );
  PERFORM pg_advisory_xact_lock(
    hashtextextended('agentpass:human:sessions:' || p_target_member_id::text, 0)
  );

  SELECT m.*
    INTO actor_row
  FROM public.memberships AS m
  WHERE m.organization_id = p_organization_id
    AND m.member_id = p_actor_member_id
  FOR UPDATE;

  IF NOT FOUND
     OR actor_row.status IS DISTINCT FROM 'active'
     OR actor_row.role IS NULL
     OR actor_row.role NOT IN ('owner', 'admin') THEN
    RAISE EXCEPTION USING
      ERRCODE = 'insufficient_privilege',
      MESSAGE = 'membership operation is not allowed';
  END IF;

  SELECT m.*
    INTO target_row
  FROM public.memberships AS m
  WHERE m.organization_id = p_organization_id
    AND m.member_id = p_target_member_id
  FOR UPDATE;

  IF NOT FOUND OR target_row.status IS DISTINCT FROM 'active' THEN
    RAISE EXCEPTION USING
      ERRCODE = 'foreign_key_violation',
      CONSTRAINT = 'memberships_active_target',
      MESSAGE = 'organization member was not found';
  END IF;

  IF target_row.version IS DISTINCT FROM p_expected_version THEN
    RAISE EXCEPTION USING
      ERRCODE = 'serialization_failure',
      CONSTRAINT = 'memberships_version',
      MESSAGE = 'organization member version is stale';
  END IF;

  IF target_row.role = 'owner' AND actor_row.role IS DISTINCT FROM 'owner' THEN
    RAISE EXCEPTION USING
      ERRCODE = 'insufficient_privilege',
      MESSAGE = 'membership operation is not allowed';
  END IF;

  -- The owner trigger and this precheck share the same advisory namespace.
  -- The target row is already locked, so this order cannot invert the legacy
  -- BEFORE trigger's row -> owner-set sequence.
  IF target_row.role = 'owner' THEN
    PERFORM pg_advisory_xact_lock(
      hashtextextended('agentpass:memberships:owners:' || p_organization_id::text, 0)
    );

    IF NOT EXISTS (
      SELECT 1
      FROM public.memberships AS m
      WHERE m.organization_id = p_organization_id
        AND m.role = 'owner'
        AND m.status = 'active'
        AND m.id IS DISTINCT FROM target_row.id
    ) THEN
      RAISE EXCEPTION USING
        ERRCODE = 'check_violation',
        CONSTRAINT = 'memberships_last_active_owner',
        MESSAGE = 'cannot remove the last active organization owner';
    END IF;
  END IF;

  IF target_row.version = max_bigint THEN
    RAISE EXCEPTION USING
      ERRCODE = 'numeric_value_out_of_range',
      CONSTRAINT = 'memberships_version_positive',
      MESSAGE = 'membership version cannot advance beyond bigint';
  END IF;

  UPDATE public.memberships AS target
     SET status = 'revoked',
         version = target.version + 1,
         updated_at = p_removed_at
   WHERE target.organization_id = p_organization_id
     AND target.member_id = p_target_member_id
     AND target.status = 'active'
     AND target.version = p_expected_version
     AND (target.role <> 'owner' OR actor_row.role = 'owner')
  RETURNING target.* INTO updated_row;

  IF NOT FOUND THEN
    RAISE EXCEPTION USING
      ERRCODE = 'serialization_failure',
      CONSTRAINT = 'memberships_mutation_cas',
      MESSAGE = 'membership removal lost its authority binding';
  END IF;

  SELECT public.agentpass_human_member_session_revoke(
    p_target_member_id,
    p_organization_id,
    p_removed_at,
    'membership_removed'
  ) INTO session_revoke_result;
  IF session_revoke_result IS NULL THEN
    RAISE EXCEPTION USING
      ERRCODE = 'serialization_failure',
      MESSAGE = 'human session authority is unavailable';
  END IF;

  RETURN QUERY
  SELECT updated_row.organization_id,
         updated_row.id,
         updated_row.member_id,
         updated_row.role,
         updated_row.status,
         updated_row.version,
         updated_row.created_at,
         updated_row.updated_at;
END;
$$;

ALTER FUNCTION public.agentpass_human_membership_role_update(
  uuid,uuid,uuid,text,bigint,timestamptz
) OWNER TO agentpass_migrator;
ALTER FUNCTION public.agentpass_human_membership_remove(
  uuid,uuid,uuid,bigint,timestamptz
) OWNER TO agentpass_migrator;

REVOKE ALL PRIVILEGES ON FUNCTION public.agentpass_human_membership_role_update(
  uuid,uuid,uuid,text,bigint,timestamptz
) FROM PUBLIC, agentpass_signer, agentpass_backup, agentpass_maintenance;
REVOKE ALL PRIVILEGES ON FUNCTION public.agentpass_human_membership_remove(
  uuid,uuid,uuid,bigint,timestamptz
) FROM PUBLIC, agentpass_signer, agentpass_backup, agentpass_maintenance;

GRANT EXECUTE ON FUNCTION public.agentpass_human_membership_role_update(
  uuid,uuid,uuid,text,bigint,timestamptz
) TO agentpass_app;
GRANT EXECUTE ON FUNCTION public.agentpass_human_membership_remove(
  uuid,uuid,uuid,bigint,timestamptz
) TO agentpass_app;

COMMENT ON FUNCTION public.agentpass_human_membership_role_update(
  uuid,uuid,uuid,text,bigint,timestamptz
) IS 'SECURITY DEFINER tenant/actor/version/final-owner checked membership role mutation; membership triggers and human-session authority remain atomic.';
COMMENT ON FUNCTION public.agentpass_human_membership_remove(
  uuid,uuid,uuid,bigint,timestamptz
) IS 'SECURITY DEFINER tenant/actor/version/final-owner checked membership removal; membership triggers and human-session authority remain atomic.';

COMMIT;
