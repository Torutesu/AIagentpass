BEGIN;

-- S3 identity invalidation boundary.
--
-- 0024 made authority epochs monotonic, but left session and recent-auth
-- invalidation to individual repositories.  This migration makes the
-- database boundary authoritative: every security-bearing transition below
-- reaches this one SECURITY DEFINER primitive in the same transaction.
--
-- Lock order for this boundary is deliberately fixed:
--   organization advisory lock -> member session advisory lock
--   -> organization row -> membership row -> affected session rows
-- Trigger callers must not acquire these locks in the reverse order.
CREATE FUNCTION public.agentpass_invalidate_identity_epoch(
  p_organization_id uuid,
  p_member_id uuid,
  p_event text
)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  max_bigint constant bigint := 9223372036854775807::bigint;
  now_value timestamptz := clock_timestamp();
  organization_epoch bigint;
  membership_epoch bigint;
  organization_exists boolean := false;
  membership_exists boolean := false;
  invalidated_human_sessions integer := 0;
  invalidated_recent_authorizations integer := 0;
  invalidated_platform_sessions integer := 0;
  consumed_challenges integer := 0;
  revoked_capabilities integer := 0;
  member_event boolean;
BEGIN
  IF p_organization_id IS NULL
     OR p_event NOT IN (
       'membership_changed',
       'membership_removed',
       'membership_deleted',
       'webauthn_credential_revoked',
       'platform_credential_revoked',
       'recovery_transition',
       'organization_security_event'
     ) THEN
    RAISE EXCEPTION USING
      ERRCODE = 'invalid_parameter_value',
      MESSAGE = 'identity invalidation request is outside the reviewed event set';
  END IF;

  member_event := p_event <> 'organization_security_event';
  IF member_event AND p_member_id IS NULL THEN
    RAISE EXCEPTION USING
      ERRCODE = 'invalid_parameter_value',
      MESSAGE = 'member-scoped identity invalidation requires a member';
  END IF;
  IF NOT member_event AND p_member_id IS NOT NULL THEN
    RAISE EXCEPTION USING
      ERRCODE = 'invalid_parameter_value',
      MESSAGE = 'organization-scoped identity invalidation cannot carry a member';
  END IF;

  -- Match the advisory namespace used by the human repositories.  The
  -- primitive itself never trusts a caller-supplied actor or role.
  PERFORM pg_advisory_xact_lock(
    hashtextextended('agentpass:organization:' || p_organization_id::text, 0)
  );
  IF member_event THEN
    PERFORM pg_advisory_xact_lock(
      hashtextextended('agentpass:human:sessions:' || p_member_id::text, 0)
    );
  END IF;

  SELECT authority_epoch
    INTO organization_epoch
  FROM organizations
  WHERE id = p_organization_id
  FOR UPDATE;
  organization_exists := FOUND;
  IF NOT organization_exists THEN
    RAISE EXCEPTION USING
      ERRCODE = 'foreign_key_violation',
      CONSTRAINT = 'organizations_authority_epoch_positive',
      MESSAGE = 'organization was not found';
  END IF;

  IF NOT member_event THEN
    IF organization_epoch = max_bigint THEN
      RAISE EXCEPTION USING
        ERRCODE = 'numeric_value_out_of_range',
        CONSTRAINT = 'organizations_authority_epoch_positive',
        MESSAGE = 'organization authority epoch cannot advance beyond bigint';
    END IF;

    UPDATE organizations
    SET authority_epoch = authority_epoch + 1,
        updated_at = now_value
    WHERE id = p_organization_id;
  ELSE
    -- A membership row is present for ordinary transitions.  Credential
    -- revocation and a post-delete trigger may legitimately reach this
    -- boundary after the membership row has disappeared; their sessions are
    -- still invalidated, while no synthetic membership epoch is invented.
    SELECT session_epoch
      INTO membership_epoch
    FROM memberships
    WHERE organization_id = p_organization_id
      AND member_id = p_member_id
    ORDER BY id ASC
    LIMIT 1
    FOR UPDATE;
    membership_exists := FOUND;
    IF NOT membership_exists
       AND p_event IN ('membership_changed', 'recovery_transition') THEN
      RAISE EXCEPTION USING
        ERRCODE = 'foreign_key_violation',
        CONSTRAINT = 'memberships_session_epoch_positive',
        MESSAGE = 'member is not bound to the requested organization';
    END IF;
    IF membership_exists THEN
      IF membership_epoch = max_bigint THEN
        RAISE EXCEPTION USING
          ERRCODE = 'numeric_value_out_of_range',
          CONSTRAINT = 'memberships_session_epoch_positive',
          MESSAGE = 'membership session epoch cannot advance beyond bigint';
      END IF;

      -- 0025 had one compatibility caller that already advances the
      -- membership epoch before the recovery request state transition.  It
      -- remains accepted during this migration boundary; the primitive still
      -- owns DB-clock session/recent-auth invalidation for that transition.
      IF NOT (p_event = 'recovery_transition'
              AND COALESCE(current_setting('agentpass.recovery_epoch_bump', true), '') = 'on') THEN
        UPDATE memberships
        SET session_epoch = session_epoch + 1,
            updated_at = now_value
        WHERE organization_id = p_organization_id
          AND member_id = p_member_id;
        membership_epoch := membership_epoch + 1;
      END IF;
    END IF;
  END IF;

  -- All of these changes are deliberately inside the same transaction as the
  -- triggering mutation.  DB time is captured once and caller timestamps are
  -- not accepted by this primitive.
  IF member_event THEN
    UPDATE webauthn_challenges
    SET status = 'consumed', consumed_at = now_value
    WHERE organization_id = p_organization_id
      AND member_id = p_member_id
      AND status IN ('pending', 'consuming')
      AND consumed_at IS NULL;
  ELSE
    UPDATE webauthn_challenges
    SET status = 'consumed', consumed_at = now_value
    WHERE organization_id = p_organization_id
      AND status IN ('pending', 'consuming')
      AND consumed_at IS NULL;
  END IF;
  GET DIAGNOSTICS consumed_challenges = ROW_COUNT;

  IF member_event THEN
    SELECT count(*)::integer
      INTO invalidated_recent_authorizations
    FROM human_sessions
    WHERE organization_id = p_organization_id
      AND member_id = p_member_id
      AND (
        recent_auth_at IS NOT NULL
        OR recent_auth_challenge_id IS NOT NULL
        OR recent_auth_organization_id IS NOT NULL
        OR recent_auth_operation IS NOT NULL
        OR recent_auth_context_hash IS NOT NULL
        OR recent_auth_consumed_at IS NOT NULL
      );
  ELSE
    SELECT count(*)::integer
      INTO invalidated_recent_authorizations
    FROM human_sessions
    WHERE organization_id = p_organization_id
      AND (
        recent_auth_at IS NOT NULL
        OR recent_auth_challenge_id IS NOT NULL
        OR recent_auth_organization_id IS NOT NULL
        OR recent_auth_operation IS NOT NULL
        OR recent_auth_context_hash IS NOT NULL
        OR recent_auth_consumed_at IS NOT NULL
      );
  END IF;

  IF member_event THEN
    UPDATE human_sessions
    SET revoked_at = CASE WHEN p_event = 'recovery_transition' THEN now_value ELSE COALESCE(revoked_at, now_value) END,
        revoke_reason = COALESCE(revoke_reason, p_event),
        version = version + 1,
        recent_auth_at = NULL,
        recent_auth_challenge_id = NULL,
        recent_auth_organization_id = NULL,
        recent_auth_operation = NULL,
        recent_auth_context_hash = NULL,
        recent_auth_consumed_at = NULL
    WHERE organization_id = p_organization_id
      AND member_id = p_member_id
      AND (
        revoked_at IS NULL
        OR recent_auth_at IS NOT NULL
        OR recent_auth_challenge_id IS NOT NULL
        OR recent_auth_organization_id IS NOT NULL
        OR recent_auth_operation IS NOT NULL
        OR recent_auth_context_hash IS NOT NULL
        OR recent_auth_consumed_at IS NOT NULL
      );
  ELSE
    UPDATE human_sessions
    SET revoked_at = CASE WHEN p_event = 'recovery_transition' THEN now_value ELSE COALESCE(revoked_at, now_value) END,
        revoke_reason = COALESCE(revoke_reason, p_event),
        version = version + 1,
        recent_auth_at = NULL,
        recent_auth_challenge_id = NULL,
        recent_auth_organization_id = NULL,
        recent_auth_operation = NULL,
        recent_auth_context_hash = NULL,
        recent_auth_consumed_at = NULL
    WHERE organization_id = p_organization_id
      AND (
        revoked_at IS NULL
        OR recent_auth_at IS NOT NULL
        OR recent_auth_challenge_id IS NOT NULL
        OR recent_auth_organization_id IS NOT NULL
        OR recent_auth_operation IS NOT NULL
        OR recent_auth_context_hash IS NOT NULL
        OR recent_auth_consumed_at IS NOT NULL
      );
  END IF;
  GET DIAGNOSTICS invalidated_human_sessions = ROW_COUNT;

  IF member_event THEN
    UPDATE capabilities
    SET revoked_at = now_value
    WHERE organization_id = p_organization_id
      AND issued_by_member_id = p_member_id
      AND revoked_at IS NULL;
    GET DIAGNOSTICS revoked_capabilities = ROW_COUNT;

    UPDATE platform_sessions
    SET status = 'revoked',
        revoked_at = now_value,
        revoke_reason = COALESCE(revoke_reason, p_event),
        version = version + 1
    WHERE organization_id = p_organization_id
      AND member_id = p_member_id
      AND status = 'active';
  ELSE
    UPDATE capabilities
    SET revoked_at = now_value
    WHERE organization_id = p_organization_id
      AND revoked_at IS NULL;
    GET DIAGNOSTICS revoked_capabilities = ROW_COUNT;

    UPDATE platform_sessions
    SET status = 'revoked',
        revoked_at = now_value,
        revoke_reason = COALESCE(revoke_reason, p_event),
        version = version + 1
    WHERE organization_id = p_organization_id
      AND status = 'active';
  END IF;
  GET DIAGNOSTICS invalidated_platform_sessions = ROW_COUNT;

  RETURN jsonb_build_object(
    'event', p_event,
    'organization_id', p_organization_id,
    'member_id', p_member_id,
    'organization_authority_epoch', CASE WHEN member_event THEN NULL ELSE organization_epoch + 1 END,
    'membership_session_epoch', CASE WHEN membership_exists THEN membership_epoch ELSE NULL END,
    'invalidated_human_sessions', invalidated_human_sessions,
    'invalidated_recent_authorizations', invalidated_recent_authorizations,
    'invalidated_platform_sessions', invalidated_platform_sessions,
    'consumed_challenges', consumed_challenges,
    'revoked_capabilities', revoked_capabilities
  );
END;
$$;

-- Only trusted database-owned trigger paths may invoke the primitive.  The
-- service roles receive no EXECUTE privilege for it.
CREATE FUNCTION public.agentpass_invalidate_membership_after_change()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    PERFORM public.agentpass_invalidate_identity_epoch(OLD.organization_id, OLD.member_id, 'membership_deleted');
    RETURN OLD;
  END IF;

  IF OLD.organization_id IS DISTINCT FROM NEW.organization_id
     OR OLD.member_id IS DISTINCT FROM NEW.member_id
     OR OLD.role IS DISTINCT FROM NEW.role
     OR OLD.status IS DISTINCT FROM NEW.status THEN
    PERFORM public.agentpass_invalidate_identity_epoch(
      OLD.organization_id,
      OLD.member_id,
      CASE WHEN OLD.status = 'active' AND NEW.status <> 'active'
        THEN 'membership_removed' ELSE 'membership_changed' END
    );
    IF NEW.organization_id IS DISTINCT FROM OLD.organization_id THEN
      PERFORM public.agentpass_invalidate_identity_epoch(NEW.organization_id, NEW.member_id, 'membership_changed');
    END IF;
  END IF;
  RETURN NEW;
END;
$$;

CREATE FUNCTION public.agentpass_invalidate_credential_after_revoke()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  scoped_organization_id uuid;
  event_name text := CASE WHEN TG_TABLE_NAME = 'webauthn_credentials'
    THEN 'webauthn_credential_revoked' ELSE 'platform_credential_revoked' END;
BEGIN
  FOR scoped_organization_id IN
    SELECT organization_id
    FROM (
      SELECT organization_id FROM memberships WHERE member_id = NEW.member_id
      UNION
      SELECT organization_id FROM platform_sessions WHERE member_id = NEW.member_id
    ) AS scopes
    ORDER BY organization_id ASC
  LOOP
    PERFORM public.agentpass_invalidate_identity_epoch(scoped_organization_id, NEW.member_id, event_name);
  END LOOP;
  RETURN NEW;
END;
$$;

CREATE FUNCTION public.agentpass_invalidate_recovery_transition()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
  IF NEW.state IS DISTINCT FROM OLD.state THEN
    PERFORM public.agentpass_invalidate_identity_epoch(
      NEW.organization_id,
      NEW.subject_member_id,
      'recovery_transition'
    );
  END IF;
  RETURN NEW;
END;
$$;

CREATE FUNCTION public.agentpass_invalidate_organization_security_event()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
  IF NEW.target_type = 'organization'
     AND NEW.status = 'active'
     AND (TG_OP = 'INSERT' OR OLD.target_type IS DISTINCT FROM 'organization' OR OLD.status IS DISTINCT FROM 'active') THEN
    PERFORM public.agentpass_invalidate_identity_epoch(NEW.organization_id, NULL, 'organization_security_event');
  END IF;
  RETURN NEW;
END;
$$;

-- The old 0024 BEFORE trigger performed an epoch-only increment.  Replace it
-- with a guard so direct service-role writes cannot bypass the primitive while
-- the primitive's SECURITY DEFINER update remains the sole forward path.
DROP TRIGGER memberships_bump_session_epoch ON memberships;

CREATE OR REPLACE FUNCTION public.agentpass_guard_membership_session_epoch()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
  IF NEW.session_epoch IS DISTINCT FROM OLD.session_epoch THEN
    IF (current_user <> pg_get_userbyid(
          (SELECT relowner FROM pg_class WHERE oid = TG_RELID)
        )
        AND COALESCE(current_setting('agentpass.recovery_epoch_bump', true), '') <> 'on')
       OR NEW.session_epoch <> OLD.session_epoch + 1 THEN
      RAISE EXCEPTION USING
        ERRCODE = 'check_violation',
        CONSTRAINT = 'memberships_session_epoch_forward_only',
        MESSAGE = 'membership session epoch is managed by the identity invalidation boundary';
    END IF;
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER memberships_guard_session_epoch
  BEFORE UPDATE OF session_epoch ON memberships
  FOR EACH ROW
  EXECUTE FUNCTION public.agentpass_guard_membership_session_epoch();

CREATE OR REPLACE FUNCTION public.agentpass_guard_organization_authority_epoch()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
  IF NEW.authority_epoch IS DISTINCT FROM OLD.authority_epoch THEN
    IF current_user <> pg_get_userbyid(
         (SELECT relowner FROM pg_class WHERE oid = TG_RELID)
       )
       OR NEW.authority_epoch <> OLD.authority_epoch + 1 THEN
      RAISE EXCEPTION USING
        ERRCODE = 'check_violation',
        CONSTRAINT = 'organizations_authority_epoch_forward_only',
        MESSAGE = 'organization authority epoch is managed by the identity invalidation boundary';
    END IF;
  END IF;
  RETURN NEW;
END;
$$;

-- Preserve the 0024 helper signature for callers that still use it, but route
-- it through the same atomic invalidation boundary.
CREATE OR REPLACE FUNCTION public.agentpass_bump_organization_authority_epoch(
  request_organization_id uuid
)
RETURNS bigint
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  result jsonb;
BEGIN
  result := public.agentpass_invalidate_identity_epoch(request_organization_id, NULL, 'organization_security_event');
  RETURN (result->>'organization_authority_epoch')::bigint;
END;
$$;

CREATE TRIGGER memberships_invalidate_identity_epoch
  AFTER UPDATE OF organization_id, member_id, role, status OR DELETE ON memberships
  FOR EACH ROW
  EXECUTE FUNCTION public.agentpass_invalidate_membership_after_change();

CREATE TRIGGER webauthn_credentials_invalidate_identity_epoch
  AFTER UPDATE OF revoked_at ON webauthn_credentials
  FOR EACH ROW
  WHEN (OLD.revoked_at IS NULL AND NEW.revoked_at IS NOT NULL)
  EXECUTE FUNCTION public.agentpass_invalidate_credential_after_revoke();

CREATE TRIGGER platform_credentials_invalidate_identity_epoch
  AFTER UPDATE OF status, revoked_at ON platform_credentials
  FOR EACH ROW
  WHEN (OLD.status IS DISTINCT FROM 'revoked' AND NEW.status = 'revoked')
  EXECUTE FUNCTION public.agentpass_invalidate_credential_after_revoke();

CREATE TRIGGER owner_recovery_requests_invalidate_identity_epoch
  AFTER UPDATE OF state ON owner_recovery_requests
  FOR EACH ROW
  EXECUTE FUNCTION public.agentpass_invalidate_recovery_transition();

CREATE TRIGGER revocations_invalidate_organization_identity_epoch_insert
  AFTER INSERT ON revocations
  FOR EACH ROW
  EXECUTE FUNCTION public.agentpass_invalidate_organization_security_event();

CREATE TRIGGER revocations_invalidate_organization_identity_epoch_update
  AFTER UPDATE OF target_type, status ON revocations
  FOR EACH ROW
  EXECUTE FUNCTION public.agentpass_invalidate_organization_security_event();

-- Keep every entry point private to its owner. Deployment-specific service
-- roles are deliberately absent from migrations: roles.sql reconciles their
-- exact grants after every migration, while generic PostgreSQL installations
-- can apply this history without pre-creating Agentpass role names.
REVOKE ALL PRIVILEGES ON FUNCTION public.agentpass_invalidate_identity_epoch(uuid,uuid,text) FROM PUBLIC;
REVOKE ALL PRIVILEGES ON FUNCTION public.agentpass_invalidate_membership_after_change() FROM PUBLIC;
REVOKE ALL PRIVILEGES ON FUNCTION public.agentpass_invalidate_credential_after_revoke() FROM PUBLIC;
REVOKE ALL PRIVILEGES ON FUNCTION public.agentpass_invalidate_recovery_transition() FROM PUBLIC;
REVOKE ALL PRIVILEGES ON FUNCTION public.agentpass_invalidate_organization_security_event() FROM PUBLIC;
REVOKE ALL PRIVILEGES ON FUNCTION public.agentpass_guard_membership_session_epoch() FROM PUBLIC;
REVOKE ALL PRIVILEGES ON FUNCTION public.agentpass_guard_organization_authority_epoch() FROM PUBLIC;
REVOKE ALL PRIVILEGES ON FUNCTION public.agentpass_bump_organization_authority_epoch(uuid) FROM PUBLIC;

COMMIT;
