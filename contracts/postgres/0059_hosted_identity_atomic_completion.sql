BEGIN;

-- The v1 bootstrap state machine originally required an intermediate
-- identity_verified write.  The atomic completion boundary resolves the
-- membership decision in the same transaction, so permit the two terminal
-- identity-classification transitions directly from oauth_started.
CREATE OR REPLACE FUNCTION public.agentpass_guard_hosted_identity_bootstrap_attempt()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE membership_member_id uuid; membership_status text; membership_role text;
BEGIN
  IF current_user <> pg_get_userbyid((SELECT relowner FROM pg_catalog.pg_class WHERE oid = TG_RELID)) THEN
    RAISE EXCEPTION USING ERRCODE = 'insufficient_privilege', MESSAGE = 'hosted bootstrap trigger requires relation owner';
  END IF;
  IF TG_OP = 'DELETE' THEN RAISE EXCEPTION USING ERRCODE = 'restrict_violation', MESSAGE = 'hosted bootstrap attempts are append-only'; END IF;
  IF TG_OP = 'UPDATE' AND OLD.state IS DISTINCT FROM NEW.state AND NOT (
    (OLD.state = 'oauth_started' AND NEW.state IN ('identity_verified', 'organization_required', 'no_membership', 'expired'))
    OR (OLD.state = 'identity_verified' AND NEW.state IN ('organization_required', 'webauthn_required', 'ready', 'no_membership', 'expired'))
    OR (OLD.state = 'organization_required' AND NEW.state IN ('webauthn_required', 'expired'))
    OR (OLD.state = 'webauthn_required' AND NEW.state IN ('completed', 'ready', 'expired'))
    OR (OLD.state = 'ready' AND NEW.state = 'completed')
  ) THEN RAISE EXCEPTION USING ERRCODE = 'invalid_parameter_value', MESSAGE = 'hosted bootstrap state transition is not forward-only'; END IF;
  IF NEW.organization_id IS NOT NULL THEN
    SELECT m.member_id, m.status, m.role INTO membership_member_id, membership_status, membership_role FROM public.memberships AS m WHERE m.organization_id = NEW.organization_id AND m.id = NEW.membership_id;
    IF NOT FOUND OR membership_member_id IS DISTINCT FROM NEW.member_id OR membership_status <> 'active' OR membership_role <> 'owner' THEN
      RAISE EXCEPTION USING ERRCODE = 'foreign_key_violation', MESSAGE = 'hosted bootstrap organization binding is not the active owner membership';
    END IF;
  END IF;
  IF NEW.state <> 'oauth_started' AND (NEW.member_id IS NULL OR NEW.bootstrap_cookie_hash IS NULL) THEN RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'verified bootstrap state requires server-bound identity'; END IF;
  IF NEW.state IN ('webauthn_required', 'ready', 'completed') AND NEW.organization_id IS NULL THEN RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'WebAuthn bootstrap state requires a bound organization'; END IF;
  RETURN NEW;
END;
$$;

CREATE FUNCTION public.agentpass_hosted_identity_oauth_complete_v2(
  p_oauth_state_id uuid,
  p_attempt_id uuid,
  p_bootstrap_cookie_hash bytea,
  p_candidate_member_id uuid,
  p_provider text,
  p_subject text,
  p_subject_digest bytea
)
RETURNS TABLE (attempt_id uuid, state text, organization_count bigint, expires_at timestamptz)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
  oauth_row public.hosted_identity_oauth_states%ROWTYPE;
  attempt_row public.hosted_identity_bootstrap_attempts%ROWTYPE;
  resolved_member_id uuid;
  membership_count bigint;
  active_organization_count bigint;
  target_state text;
  now_value timestamptz := clock_timestamp();
BEGIN
  IF octet_length(p_bootstrap_cookie_hash) IS DISTINCT FROM 32 OR octet_length(p_subject_digest) IS DISTINCT FROM 32 THEN
    RAISE EXCEPTION USING ERRCODE = 'invalid_parameter_value', MESSAGE = 'bootstrap selector and identity digest must be SHA-256 digests';
  END IF;
  IF p_candidate_member_id = '00000000-0000-0000-0000-000000000000'::uuid THEN
    RAISE EXCEPTION USING ERRCODE = 'invalid_parameter_value', MESSAGE = 'candidate member identifier is invalid';
  END IF;
  IF p_provider IS DISTINCT FROM 'github' OR p_subject IS NULL OR p_subject !~ '^[1-9][0-9]{0,19}$' THEN
    RAISE EXCEPTION USING ERRCODE = 'invalid_parameter_value', MESSAGE = 'verified upstream identity is invalid';
  END IF;

  -- Serialize all first-seen completions for the same immutable identity. A
  -- hash collision only adds serialization and cannot merge identities.
  PERFORM pg_advisory_xact_lock(hashtextextended(p_provider || chr(31) || p_subject, 0));

  SELECT * INTO oauth_row
  FROM public.hosted_identity_oauth_states AS s
  WHERE s.id = p_oauth_state_id AND s.attempt_id = p_attempt_id AND s.status = 'consuming'
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE = 'invalid_authorization_specification', MESSAGE = 'OAuth callback is absent, mismatched, or already consumed';
  END IF;

  SELECT * INTO attempt_row
  FROM public.hosted_identity_bootstrap_attempts AS a
  WHERE a.id = p_attempt_id AND a.oauth_state_id = p_oauth_state_id
  FOR UPDATE;
  IF NOT FOUND OR attempt_row.state <> 'oauth_started' OR attempt_row.provider <> p_provider THEN
    RAISE EXCEPTION USING ERRCODE = 'invalid_authorization_specification', MESSAGE = 'bootstrap attempt is not eligible for identity completion';
  END IF;

  IF oauth_row.expires_at <= now_value OR attempt_row.expires_at <= now_value THEN
    UPDATE public.hosted_identity_oauth_states
    SET status = 'expired', expired_at = now_value, failure_code = 'identity_completion_expired'
    WHERE id = oauth_row.id;
    UPDATE public.hosted_identity_bootstrap_attempts
    SET state = 'expired', expired_at = now_value, failure_code = 'identity_completion_expired', version = version + 1
    WHERE id = attempt_row.id;
    DELETE FROM public.hosted_identity_oauth_pkce_envelopes WHERE oauth_state_id = oauth_row.id;
    RETURN;
  END IF;

  SELECT i.member_id INTO resolved_member_id
  FROM public.upstream_identities AS i
  WHERE i.provider = p_provider AND i.subject = p_subject
  FOR KEY SHARE;

  IF NOT FOUND THEN
    INSERT INTO public.members (id, github_subject, display_name)
    VALUES (p_candidate_member_id, NULL, NULL);
    INSERT INTO public.upstream_identities (provider, subject, member_id)
    VALUES (p_provider, p_subject, p_candidate_member_id);
    resolved_member_id := p_candidate_member_id;
  END IF;

  -- Locking the referenced member also blocks concurrent membership FK checks
  -- until classification commits, preventing a zero-history decision racing a
  -- membership insertion.
  PERFORM 1 FROM public.members AS m WHERE m.id = resolved_member_id FOR UPDATE;
  SELECT count(*), count(DISTINCT m.organization_id) FILTER (WHERE m.status = 'active')
  INTO membership_count, active_organization_count
  FROM public.memberships AS m
  WHERE m.member_id = resolved_member_id;

  target_state := CASE
    WHEN active_organization_count > 0 THEN 'identity_verified'
    WHEN membership_count = 0 THEN 'organization_required'
    ELSE 'no_membership'
  END;

  UPDATE public.hosted_identity_oauth_states
  SET status = 'consumed', consumed_at = now_value
  WHERE id = oauth_row.id AND status = 'consuming';
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE = 'serialization_failure', MESSAGE = 'OAuth state changed during identity completion';
  END IF;

  UPDATE public.hosted_identity_bootstrap_attempts
  SET state = target_state,
      bootstrap_cookie_hash = p_bootstrap_cookie_hash,
      member_id = resolved_member_id,
      identity_subject_digest = p_subject_digest,
      identity_verified_at = now_value,
      version = version + 1
  WHERE id = attempt_row.id AND state = 'oauth_started';
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE = 'serialization_failure', MESSAGE = 'bootstrap attempt changed during identity completion';
  END IF;

  DELETE FROM public.hosted_identity_oauth_pkce_envelopes WHERE oauth_state_id = oauth_row.id;
  RETURN QUERY SELECT attempt_row.id, target_state, active_organization_count, attempt_row.expires_at;
END;
$$;

REVOKE ALL PRIVILEGES ON FUNCTION public.agentpass_hosted_identity_oauth_complete_v2(uuid, uuid, bytea, uuid, text, text, bytea) FROM PUBLIC;

COMMIT;
