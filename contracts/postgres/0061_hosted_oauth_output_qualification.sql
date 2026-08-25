BEGIN;

-- PostgreSQL treats RETURNS TABLE names as PL/pgSQL variables. 0058 used the
-- public `oauth_state_id` output name and the same physical column name, which
-- made INSERT/DELETE qualification depend on variable-conflict resolution.
-- Preserve the frozen function signatures while pinning column resolution.
CREATE OR REPLACE FUNCTION public.agentpass_hosted_identity_bootstrap_start_v2(
  p_attempt_id uuid,
  p_oauth_state_id uuid,
  p_state_hash bytea,
  p_pkce_challenge text,
  p_client_id text,
  p_redirect_uri text,
  p_key_id text,
  p_nonce bytea,
  p_ciphertext bytea,
  p_auth_tag bytea,
  p_envelope_expires_at timestamptz
)
RETURNS TABLE (attempt_id uuid, oauth_state_id uuid, state_expires_at timestamptz, attempt_expires_at timestamptz)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
#variable_conflict use_column
DECLARE now_value timestamptz := clock_timestamp(); state_expiry timestamptz; attempt_expiry timestamptz;
BEGIN
  IF octet_length(p_state_hash) IS DISTINCT FROM 32 THEN
    RAISE EXCEPTION USING ERRCODE = 'invalid_parameter_value', MESSAGE = 'OAuth state selector must be a SHA-256 digest';
  END IF;
  state_expiry := now_value + interval '10 minutes';
  attempt_expiry := now_value + interval '15 minutes';
  IF p_envelope_expires_at <= now_value OR p_envelope_expires_at > state_expiry THEN
    RAISE EXCEPTION USING ERRCODE = 'invalid_parameter_value', MESSAGE = 'OAuth PKCE envelope expiry is outside the state lifetime';
  END IF;
  INSERT INTO public.hosted_identity_bootstrap_attempts
    (id, oauth_state_id, state, provider, created_at, expires_at)
  VALUES
    (p_attempt_id, p_oauth_state_id, 'oauth_started', 'github', now_value, attempt_expiry);
  INSERT INTO public.hosted_identity_oauth_states
    (id, attempt_id, state_hash, provider, client_id, redirect_uri, pkce_challenge, pkce_method, status, created_at, expires_at)
  VALUES
    (p_oauth_state_id, p_attempt_id, p_state_hash, 'github', p_client_id, p_redirect_uri, p_pkce_challenge, 'S256', 'pending', now_value, state_expiry);
  INSERT INTO public.hosted_identity_oauth_pkce_envelopes
    (oauth_state_id, key_id, nonce, ciphertext, auth_tag, aad_version, created_at, expires_at)
  VALUES
    (p_oauth_state_id, p_key_id, p_nonce, p_ciphertext, p_auth_tag, 1, now_value, p_envelope_expires_at);
  RETURN QUERY SELECT p_attempt_id, p_oauth_state_id, state_expiry, attempt_expiry;
END;
$$;

CREATE OR REPLACE FUNCTION public.agentpass_hosted_identity_oauth_state_claim_v2(
  p_oauth_state_id uuid,
  p_state_hash bytea,
  p_code_hash bytea,
  p_redirect_uri text
)
RETURNS TABLE (
  attempt_id uuid,
  oauth_state_id uuid,
  pkce_challenge text,
  client_id text,
  redirect_uri text,
  key_id text,
  nonce bytea,
  ciphertext bytea,
  auth_tag bytea,
  expires_at timestamptz
)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
#variable_conflict use_column
DECLARE state_row public.hosted_identity_oauth_states%ROWTYPE; envelope_row public.hosted_identity_oauth_pkce_envelopes%ROWTYPE; now_value timestamptz := clock_timestamp();
BEGIN
  IF octet_length(p_state_hash) IS DISTINCT FROM 32 OR octet_length(p_code_hash) IS DISTINCT FROM 32 THEN
    RAISE EXCEPTION USING ERRCODE = 'invalid_parameter_value', MESSAGE = 'OAuth selectors must be SHA-256 digests';
  END IF;
  SELECT s.* INTO state_row
  FROM public.hosted_identity_oauth_states AS s
  WHERE s.id = p_oauth_state_id
  FOR UPDATE;
  IF NOT FOUND OR state_row.status <> 'pending' THEN RETURN; END IF;

  SELECT e.* INTO envelope_row
  FROM public.hosted_identity_oauth_pkce_envelopes AS e
  WHERE e.oauth_state_id = state_row.id
  FOR UPDATE;
  IF NOT FOUND THEN
    UPDATE public.hosted_identity_oauth_states SET status = 'failed', failed_at = now_value, failure_code = 'pkce_envelope_missing' WHERE id = state_row.id;
    UPDATE public.hosted_identity_bootstrap_attempts SET state = 'expired', expired_at = now_value, failure_code = 'pkce_envelope_missing', version = version + 1 WHERE id = state_row.attempt_id AND state = 'oauth_started';
    RETURN;
  END IF;

  IF state_row.expires_at <= now_value OR envelope_row.expires_at <= now_value THEN
    UPDATE public.hosted_identity_oauth_states SET status = 'expired', expired_at = now_value, failure_code = 'oauth_state_expired' WHERE id = state_row.id;
    UPDATE public.hosted_identity_bootstrap_attempts SET state = 'expired', expired_at = now_value, failure_code = 'oauth_state_expired', version = version + 1 WHERE id = state_row.attempt_id AND state = 'oauth_started';
    DELETE FROM public.hosted_identity_oauth_pkce_envelopes AS e WHERE e.oauth_state_id = state_row.id;
    RETURN;
  END IF;

  IF state_row.state_hash IS DISTINCT FROM p_state_hash OR state_row.redirect_uri <> p_redirect_uri THEN
    UPDATE public.hosted_identity_oauth_states SET status = 'failed', code_hash = p_code_hash, failed_at = now_value, failure_code = 'oauth_binding_mismatch' WHERE id = state_row.id;
    UPDATE public.hosted_identity_bootstrap_attempts SET state = 'expired', expired_at = now_value, failure_code = 'oauth_binding_mismatch', version = version + 1 WHERE id = state_row.attempt_id AND state = 'oauth_started';
    DELETE FROM public.hosted_identity_oauth_pkce_envelopes AS e WHERE e.oauth_state_id = state_row.id;
    RETURN;
  END IF;

  UPDATE public.hosted_identity_oauth_states
  SET status = 'consuming', code_hash = p_code_hash, consume_started_at = now_value
  WHERE id = state_row.id;
  DELETE FROM public.hosted_identity_oauth_pkce_envelopes AS e WHERE e.oauth_state_id = state_row.id;
  RETURN QUERY SELECT state_row.attempt_id, state_row.id, state_row.pkce_challenge,
    state_row.client_id, state_row.redirect_uri, envelope_row.key_id,
    envelope_row.nonce, envelope_row.ciphertext, envelope_row.auth_tag,
    envelope_row.expires_at;
END;
$$;

REVOKE ALL PRIVILEGES ON FUNCTION public.agentpass_hosted_identity_bootstrap_start_v2(uuid, uuid, bytea, text, text, text, text, bytea, bytea, bytea, timestamptz) FROM PUBLIC;
REVOKE ALL PRIVILEGES ON FUNCTION public.agentpass_hosted_identity_oauth_state_claim_v2(uuid, bytea, bytea, text) FROM PUBLIC;

COMMIT;
