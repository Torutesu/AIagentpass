BEGIN;

-- The status boundary is deliberately narrower than the Hosted mutation
-- functions.  It accepts only the two server-side SHA-256 selectors, owns
-- expiry decisions with the database clock, and exposes no durable identity
-- or CSRF material to the application role.
CREATE OR REPLACE FUNCTION public.agentpass_guard_hosted_identity_bootstrap_attempt()
RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
DECLARE
  membership_member_id uuid;
  membership_status text;
  membership_role text;
BEGIN
  IF current_user <> pg_get_userbyid((
    SELECT relowner FROM pg_catalog.pg_class WHERE oid = TG_RELID
  )) THEN
    RAISE EXCEPTION USING ERRCODE = 'insufficient_privilege',
      MESSAGE = 'hosted bootstrap trigger requires relation owner';
  END IF;
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION USING ERRCODE = 'restrict_violation',
      MESSAGE = 'hosted bootstrap attempts are append-only';
  END IF;
  IF TG_OP = 'UPDATE' AND OLD.state IS DISTINCT FROM NEW.state AND NOT (
    (OLD.state = 'oauth_started' AND NEW.state IN ('identity_verified', 'organization_required', 'no_membership', 'expired'))
    OR (OLD.state = 'identity_verified' AND NEW.state IN ('organization_required', 'webauthn_required', 'ready', 'no_membership', 'expired'))
    OR (OLD.state = 'organization_required' AND NEW.state IN ('webauthn_required', 'expired'))
    OR (OLD.state = 'webauthn_required' AND NEW.state IN ('completed', 'ready', 'expired'))
    OR (OLD.state = 'no_membership' AND NEW.state = 'expired')
    OR (OLD.state = 'ready' AND NEW.state = 'completed')
  ) THEN
    RAISE EXCEPTION USING ERRCODE = 'invalid_parameter_value',
      MESSAGE = 'hosted bootstrap state transition is not forward-only';
  END IF;
  IF TG_OP = 'UPDATE'
     AND OLD.bootstrap_cookie_hash IS DISTINCT FROM NEW.bootstrap_cookie_hash
     AND OLD.bootstrap_cookie_hash IS NOT NULL THEN
    RAISE EXCEPTION USING ERRCODE = 'restrict_violation',
      MESSAGE = 'hosted bootstrap cookie binding is immutable';
  END IF;
  IF TG_OP = 'UPDATE'
     AND OLD.csrf_token_hash IS DISTINCT FROM NEW.csrf_token_hash
     AND OLD.csrf_token_hash IS NOT NULL THEN
    RAISE EXCEPTION USING ERRCODE = 'restrict_violation',
      MESSAGE = 'hosted bootstrap CSRF binding is immutable';
  END IF;
  IF NEW.organization_id IS NOT NULL THEN
    SELECT m.member_id, m.status, m.role
    INTO membership_member_id, membership_status, membership_role
    FROM public.memberships AS m
    WHERE m.organization_id = NEW.organization_id
      AND m.id = NEW.membership_id;
    IF NOT FOUND
       OR membership_member_id IS DISTINCT FROM NEW.member_id
       OR membership_status <> 'active'
       OR membership_role <> 'owner' THEN
      RAISE EXCEPTION USING ERRCODE = 'foreign_key_violation',
        MESSAGE = 'hosted bootstrap organization binding is not the active owner membership';
    END IF;
  END IF;
  IF NEW.state <> 'oauth_started'
     AND (NEW.member_id IS NULL OR NEW.bootstrap_cookie_hash IS NULL) THEN
    RAISE EXCEPTION USING ERRCODE = 'check_violation',
      MESSAGE = 'verified bootstrap state requires server-bound identity';
  END IF;
  IF NEW.state IN ('webauthn_required', 'ready', 'completed')
     AND NEW.organization_id IS NULL THEN
    RAISE EXCEPTION USING ERRCODE = 'check_violation',
      MESSAGE = 'WebAuthn bootstrap state requires a bound organization';
  END IF;
  RETURN NEW;
END;
$$;

CREATE FUNCTION public.agentpass_hosted_identity_bootstrap_status_v2(
  p_bootstrap_cookie_hash bytea,
  p_csrf_token_hash bytea
)
RETURNS TABLE (
  state text,
  organization_count bigint,
  webauthn_required boolean,
  can_create_first_organization boolean,
  expires_at timestamptz
)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public AS $$
#variable_conflict use_column
DECLARE
  attempt_row public.hosted_identity_bootstrap_attempts%ROWTYPE;
  membership_count bigint;
  active_organization_count bigint;
  now_value timestamptz;
BEGIN
  IF octet_length(p_bootstrap_cookie_hash) IS DISTINCT FROM 32
     OR octet_length(p_csrf_token_hash) IS DISTINCT FROM 32 THEN
    RAISE EXCEPTION USING ERRCODE = 'invalid_parameter_value',
      MESSAGE = 'bootstrap and CSRF selectors must be SHA-256 digests';
  END IF;

  -- Lock before sampling the clock so a status request cannot validate a
  -- cookie against a stale attempt while a state-changing function advances it.
  SELECT a.*
  INTO attempt_row
  FROM public.hosted_identity_bootstrap_attempts AS a
  WHERE a.bootstrap_cookie_hash = p_bootstrap_cookie_hash
  FOR UPDATE;
  IF NOT FOUND THEN
    RETURN;
  END IF;
  now_value := clock_timestamp();

  IF attempt_row.state = 'expired' THEN
    RETURN QUERY SELECT
      'expired'::text,
      0::bigint,
      false,
      false,
      attempt_row.expires_at;
    RETURN;
  END IF;

  IF attempt_row.state = 'completed' THEN
    PERFORM 1
    FROM public.members AS m
    WHERE m.id = attempt_row.member_id
    FOR UPDATE;
    IF NOT FOUND THEN
      RETURN;
    END IF;
    SELECT count(DISTINCT m.organization_id) FILTER (WHERE m.status = 'active')
    INTO active_organization_count
    FROM public.memberships AS m
    WHERE m.member_id = attempt_row.member_id;
    RETURN QUERY SELECT
      'completed'::text,
      active_organization_count,
      false,
      false,
      attempt_row.expires_at;
    RETURN;
  END IF;

  IF attempt_row.state IN (
       'identity_verified', 'organization_required', 'webauthn_required',
       'ready', 'no_membership'
     ) AND attempt_row.expires_at <= now_value THEN
    UPDATE public.hosted_identity_bootstrap_attempts
    SET state = 'expired', expired_at = now_value,
        failure_code = 'bootstrap_expired', version = version + 1
    WHERE id = attempt_row.id AND state = attempt_row.state;
    RETURN QUERY SELECT
      'expired'::text,
      0::bigint,
      false,
      false,
      attempt_row.expires_at;
    RETURN;
  END IF;
  IF attempt_row.state NOT IN (
       'identity_verified', 'organization_required', 'webauthn_required',
       'ready', 'no_membership'
     ) OR attempt_row.expires_at <= now_value THEN
    RETURN;
  END IF;

  -- The first status request installs the digest. Every later request must
  -- present the exact same digest; a mismatched digest is indistinguishable
  -- from an unavailable bootstrap to the caller.
  IF attempt_row.csrf_token_hash IS NULL THEN
    UPDATE public.hosted_identity_bootstrap_attempts
    SET csrf_token_hash = p_csrf_token_hash, version = version + 1
    WHERE id = attempt_row.id
      AND csrf_token_hash IS NULL
      AND expires_at > now_value;
    IF NOT FOUND THEN
      RETURN;
    END IF;
  ELSIF attempt_row.csrf_token_hash IS DISTINCT FROM p_csrf_token_hash THEN
    RETURN;
  END IF;

  -- Serialize the membership history decision with first-organization
  -- creation. The status response and its can_create flag are one snapshot.
  PERFORM 1
  FROM public.members AS m
  WHERE m.id = attempt_row.member_id
  FOR UPDATE;
  IF NOT FOUND THEN
    RETURN;
  END IF;
  SELECT count(*),
         count(DISTINCT m.organization_id) FILTER (WHERE m.status = 'active')
  INTO membership_count, active_organization_count
  FROM public.memberships AS m
  WHERE m.member_id = attempt_row.member_id;

  RETURN QUERY SELECT
    attempt_row.state,
    active_organization_count,
    attempt_row.state = 'webauthn_required',
    attempt_row.state = 'organization_required' AND membership_count = 0,
    attempt_row.expires_at;
END;
$$;

CREATE FUNCTION public.agentpass_hosted_identity_bootstrap_csrf_verify_v2(
  p_bootstrap_cookie_hash bytea,
  p_csrf_token_hash bytea
)
RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public AS $$
DECLARE
  attempt_row public.hosted_identity_bootstrap_attempts%ROWTYPE;
  now_value timestamptz;
BEGIN
  IF octet_length(p_bootstrap_cookie_hash) IS DISTINCT FROM 32
     OR octet_length(p_csrf_token_hash) IS DISTINCT FROM 32 THEN
    RAISE EXCEPTION USING ERRCODE = 'invalid_parameter_value',
      MESSAGE = 'bootstrap and CSRF selectors must be SHA-256 digests';
  END IF;

  SELECT a.*
  INTO attempt_row
  FROM public.hosted_identity_bootstrap_attempts AS a
  WHERE a.bootstrap_cookie_hash = p_bootstrap_cookie_hash
  FOR UPDATE;
  IF NOT FOUND THEN
    RETURN false;
  END IF;
  now_value := clock_timestamp();

  IF attempt_row.state IN (
       'identity_verified', 'organization_required', 'webauthn_required',
       'ready'
     ) AND attempt_row.expires_at <= now_value THEN
    UPDATE public.hosted_identity_bootstrap_attempts
    SET state = 'expired', expired_at = now_value,
        failure_code = 'bootstrap_expired', version = version + 1
    WHERE id = attempt_row.id AND state = attempt_row.state;
    RETURN false;
  END IF;
  IF attempt_row.state NOT IN (
       'identity_verified', 'organization_required', 'webauthn_required',
       'ready'
     ) OR attempt_row.expires_at <= now_value THEN
    RETURN false;
  END IF;

  RETURN attempt_row.csrf_token_hash IS NOT NULL
    AND attempt_row.csrf_token_hash = p_csrf_token_hash;
END;
$$;

REVOKE ALL PRIVILEGES ON FUNCTION public.agentpass_hosted_identity_bootstrap_status_v2(bytea, bytea) FROM PUBLIC;
REVOKE ALL PRIVILEGES ON FUNCTION public.agentpass_hosted_identity_bootstrap_csrf_verify_v2(bytea, bytea) FROM PUBLIC;

COMMIT;
