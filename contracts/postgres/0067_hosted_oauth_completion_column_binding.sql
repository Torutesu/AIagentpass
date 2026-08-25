BEGIN;

-- RETURNS TABLE exposes `state` as a PL/pgSQL output variable. Pin conflict
-- handling and qualify the mutable target so PostgreSQL 16/17 cannot treat
-- the attempt column as an ambiguous variable reference.
CREATE OR REPLACE FUNCTION public.agentpass_hosted_identity_oauth_complete_v2(
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
#variable_conflict use_column
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

  PERFORM pg_advisory_xact_lock(hashtextextended(p_provider || chr(31) || p_subject, 0));

  SELECT s.* INTO oauth_row
  FROM public.hosted_identity_oauth_states AS s
  WHERE s.id = p_oauth_state_id AND s.attempt_id = p_attempt_id AND s.status = 'consuming'
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE = 'invalid_authorization_specification', MESSAGE = 'OAuth callback is absent, mismatched, or already consumed';
  END IF;

  SELECT a.* INTO attempt_row
  FROM public.hosted_identity_bootstrap_attempts AS a
  WHERE a.id = p_attempt_id AND a.oauth_state_id = p_oauth_state_id
  FOR UPDATE;
  IF NOT FOUND OR attempt_row.state <> 'oauth_started' OR attempt_row.provider <> p_provider THEN
    RAISE EXCEPTION USING ERRCODE = 'invalid_authorization_specification', MESSAGE = 'bootstrap attempt is not eligible for identity completion';
  END IF;

  IF oauth_row.expires_at <= now_value OR attempt_row.expires_at <= now_value THEN
    UPDATE public.hosted_identity_oauth_states AS oauth_state
    SET status = 'expired', expired_at = now_value, failure_code = 'identity_completion_expired'
    WHERE oauth_state.id = oauth_row.id;
    UPDATE public.hosted_identity_bootstrap_attempts AS attempt
    SET state = 'expired', expired_at = now_value, failure_code = 'identity_completion_expired', version = attempt.version + 1
    WHERE attempt.id = attempt_row.id;
    DELETE FROM public.hosted_identity_oauth_pkce_envelopes AS envelope WHERE envelope.oauth_state_id = oauth_row.id;
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

  UPDATE public.hosted_identity_oauth_states AS oauth_state
  SET status = 'consumed', consumed_at = now_value
  WHERE oauth_state.id = oauth_row.id AND oauth_state.status = 'consuming';
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE = 'serialization_failure', MESSAGE = 'OAuth state changed during identity completion';
  END IF;

  UPDATE public.hosted_identity_bootstrap_attempts AS attempt
  SET state = target_state,
      bootstrap_cookie_hash = p_bootstrap_cookie_hash,
      member_id = resolved_member_id,
      identity_subject_digest = p_subject_digest,
      identity_verified_at = now_value,
      version = attempt.version + 1
  WHERE attempt.id = attempt_row.id AND attempt.state = 'oauth_started';
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE = 'serialization_failure', MESSAGE = 'bootstrap attempt changed during identity completion';
  END IF;

  DELETE FROM public.hosted_identity_oauth_pkce_envelopes AS envelope WHERE envelope.oauth_state_id = oauth_row.id;
  RETURN QUERY SELECT attempt_row.id, target_state, active_organization_count, attempt_row.expires_at;
END;
$$;

REVOKE ALL PRIVILEGES ON FUNCTION public.agentpass_hosted_identity_oauth_complete_v2(
  uuid, uuid, bytea, uuid, text, text, bytea
) FROM PUBLIC;

COMMIT;
