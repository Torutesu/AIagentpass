BEGIN;

-- Hosted bootstrap authority is additive and function-only.  Selectors are
-- supplied to this boundary as SHA-256 digests; provider credentials and raw
-- browser secrets are intentionally not durable columns.

CREATE TABLE public.hosted_identity_bootstrap_attempts (
  id uuid PRIMARY KEY,
  oauth_state_id uuid NOT NULL UNIQUE,
  state text NOT NULL CHECK (state IN (
    'oauth_started', 'identity_verified', 'organization_required',
    'webauthn_required', 'ready', 'no_membership', 'completed', 'expired'
  )),
  bootstrap_cookie_hash bytea CHECK (bootstrap_cookie_hash IS NULL OR octet_length(bootstrap_cookie_hash) = 32),
  csrf_token_hash bytea CHECK (csrf_token_hash IS NULL OR octet_length(csrf_token_hash) = 32),
  provider text NOT NULL CHECK (provider = 'github'),
  member_id uuid REFERENCES public.members(id),
  organization_id uuid REFERENCES public.organizations(id),
  membership_id uuid,
  identity_subject_digest bytea CHECK (identity_subject_digest IS NULL OR octet_length(identity_subject_digest) = 32),
  created_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  identity_verified_at timestamptz,
  completed_at timestamptz,
  expired_at timestamptz,
  failure_code text CHECK (failure_code IS NULL OR failure_code ~ '^[a-z][a-z0-9_]{0,63}$'),
  version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
  CHECK (expires_at > created_at AND expires_at <= created_at + interval '15 minutes'),
  CHECK ((organization_id IS NULL) = (membership_id IS NULL)),
  CHECK (
    (state = 'oauth_started' AND member_id IS NULL AND bootstrap_cookie_hash IS NULL AND csrf_token_hash IS NULL AND identity_subject_digest IS NULL AND organization_id IS NULL)
    OR (state IN ('identity_verified', 'organization_required', 'no_membership') AND member_id IS NOT NULL AND bootstrap_cookie_hash IS NOT NULL AND organization_id IS NULL)
    OR (state IN ('webauthn_required', 'ready', 'completed') AND member_id IS NOT NULL AND bootstrap_cookie_hash IS NOT NULL AND organization_id IS NOT NULL)
    OR state = 'expired'
  )
);

CREATE TABLE public.hosted_identity_oauth_states (
  id uuid PRIMARY KEY,
  attempt_id uuid NOT NULL REFERENCES public.hosted_identity_bootstrap_attempts(id),
  state_hash bytea NOT NULL UNIQUE CHECK (octet_length(state_hash) = 32),
  code_hash bytea UNIQUE CHECK (code_hash IS NULL OR octet_length(code_hash) = 32),
  provider text NOT NULL CHECK (provider = 'github'),
  client_id text NOT NULL CHECK (char_length(client_id) BETWEEN 1 AND 256 AND client_id !~ '[[:cntrl:]]'),
  redirect_uri text NOT NULL CHECK (char_length(redirect_uri) BETWEEN 9 AND 2048 AND redirect_uri LIKE 'https://%' AND redirect_uri !~ '[[:cntrl:]#]'),
  pkce_challenge text NOT NULL CHECK (pkce_challenge ~ '^[A-Za-z0-9_-]{43,128}$'),
  pkce_method text NOT NULL CHECK (pkce_method = 'S256'),
  status text NOT NULL CHECK (status IN ('pending', 'consuming', 'consumed', 'failed', 'expired')),
  created_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  consume_started_at timestamptz,
  consumed_at timestamptz,
  failed_at timestamptz,
  expired_at timestamptz,
  failure_code text CHECK (failure_code IS NULL OR failure_code ~ '^[a-z][a-z0-9_]{0,63}$'),
  CHECK (expires_at > created_at AND expires_at <= created_at + interval '10 minutes'),
  CHECK (
    (status = 'pending' AND code_hash IS NULL AND consume_started_at IS NULL AND consumed_at IS NULL AND failed_at IS NULL AND expired_at IS NULL AND failure_code IS NULL)
    OR (status = 'consuming' AND code_hash IS NOT NULL AND consume_started_at IS NOT NULL AND consumed_at IS NULL AND failed_at IS NULL AND expired_at IS NULL AND failure_code IS NULL)
    OR (status = 'consumed' AND code_hash IS NOT NULL AND consume_started_at IS NOT NULL AND consumed_at IS NOT NULL AND failed_at IS NULL AND expired_at IS NULL AND failure_code IS NULL)
    OR (status = 'failed' AND consume_started_at IS NOT NULL AND consumed_at IS NOT NULL AND failed_at IS NOT NULL AND expired_at IS NULL AND failure_code IS NOT NULL)
    OR (status = 'expired' AND consumed_at IS NULL AND failed_at IS NULL AND expired_at IS NOT NULL AND failure_code IS NOT NULL)
  )
);

ALTER TABLE public.hosted_identity_bootstrap_attempts
  ADD CONSTRAINT hosted_identity_bootstrap_attempts_oauth_state_fk
  FOREIGN KEY (oauth_state_id) REFERENCES public.hosted_identity_oauth_states(id)
  DEFERRABLE INITIALLY DEFERRED;

CREATE TABLE public.hosted_identity_bootstrap_idempotency (
  attempt_id uuid NOT NULL REFERENCES public.hosted_identity_bootstrap_attempts(id),
  member_id uuid NOT NULL REFERENCES public.members(id),
  organization_id uuid NOT NULL REFERENCES public.organizations(id),
  membership_id uuid NOT NULL,
  operation text NOT NULL CHECK (operation = 'first_organization_create'),
  idempotency_key text NOT NULL CHECK (idempotency_key ~ '^[A-Za-z0-9._~-]{8,255}$'),
  request_hash bytea NOT NULL CHECK (octet_length(request_hash) = 32),
  response_status integer NOT NULL CHECK (response_status = 201),
  response_json jsonb NOT NULL CHECK (
    jsonb_typeof(response_json) = 'object'
    AND response_json - 'version' - 'organization' - 'onboarding' = '{}'::jsonb
    AND response_json ? 'version' AND response_json ? 'organization' AND response_json ? 'onboarding'
    AND jsonb_typeof(response_json->'organization') = 'object'
    AND jsonb_typeof(response_json->'onboarding') = 'object'
    AND response_json->'onboarding'->>'state' = 'webauthn_required'
    AND NOT (response_json ?| ARRAY['provider', 'subject', 'github_subject', 'email', 'member_id', 'organization_id', 'membership_id', 'role'])
  ),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  committed_at timestamptz NOT NULL,
  PRIMARY KEY (member_id, operation, idempotency_key),
  UNIQUE (attempt_id, operation, idempotency_key),
  FOREIGN KEY (organization_id, membership_id) REFERENCES public.memberships(organization_id, id)
);

CREATE TABLE public.hosted_identity_bootstrap_webauthn_challenges (
  id uuid PRIMARY KEY,
  attempt_id uuid NOT NULL REFERENCES public.hosted_identity_bootstrap_attempts(id),
  member_id uuid NOT NULL REFERENCES public.members(id),
  organization_id uuid NOT NULL REFERENCES public.organizations(id),
  challenge_hash bytea NOT NULL UNIQUE CHECK (octet_length(challenge_hash) = 32),
  operation text NOT NULL CHECK (operation = 'bootstrap_registration'),
  rp_id text NOT NULL CHECK (char_length(rp_id) BETWEEN 1 AND 253 AND rp_id ~ '^[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$'),
  origin text NOT NULL CHECK (char_length(origin) BETWEEN 9 AND 512 AND origin ~ '^https://[^/?#@]+(?::[0-9]{1,5})?$'),
  user_verification text NOT NULL CHECK (user_verification = 'required'),
  status text NOT NULL CHECK (status IN ('pending', 'consuming', 'consumed', 'failed', 'expired')),
  created_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  consume_started_at timestamptz,
  consumed_at timestamptz,
  failed_at timestamptz,
  expired_at timestamptz,
  failure_code text CHECK (failure_code IS NULL OR failure_code ~ '^[a-z][a-z0-9_]{0,63}$'),
  CHECK (expires_at > created_at AND expires_at <= created_at + interval '10 minutes'),
  CHECK (
    (status = 'pending' AND consume_started_at IS NULL AND consumed_at IS NULL AND failed_at IS NULL AND expired_at IS NULL AND failure_code IS NULL)
    OR (status = 'consuming' AND consume_started_at IS NOT NULL AND consumed_at IS NULL AND failed_at IS NULL AND expired_at IS NULL AND failure_code IS NULL)
    OR (status = 'consumed' AND consume_started_at IS NOT NULL AND consumed_at IS NOT NULL AND failed_at IS NULL AND expired_at IS NULL AND failure_code IS NULL)
    OR (status = 'failed' AND consume_started_at IS NOT NULL AND consumed_at IS NOT NULL AND failed_at IS NOT NULL AND expired_at IS NULL AND failure_code IS NOT NULL)
    OR (status = 'expired' AND consumed_at IS NULL AND failed_at IS NULL AND expired_at IS NOT NULL AND failure_code IS NOT NULL)
  )
);

CREATE UNIQUE INDEX hosted_identity_bootstrap_attempts_member_first_org ON public.hosted_identity_bootstrap_attempts (member_id) WHERE organization_id IS NOT NULL;
CREATE UNIQUE INDEX hosted_identity_oauth_states_live_attempt ON public.hosted_identity_oauth_states (attempt_id) WHERE status IN ('pending', 'consuming');
CREATE INDEX hosted_identity_oauth_states_expiry ON public.hosted_identity_oauth_states (expires_at) WHERE status IN ('pending', 'consuming');
CREATE INDEX hosted_identity_bootstrap_attempts_cookie ON public.hosted_identity_bootstrap_attempts (bootstrap_cookie_hash) WHERE bootstrap_cookie_hash IS NOT NULL AND state <> 'expired';
CREATE INDEX hosted_identity_bootstrap_attempts_expiry ON public.hosted_identity_bootstrap_attempts (expires_at) WHERE state NOT IN ('completed', 'expired');
CREATE UNIQUE INDEX hosted_identity_bootstrap_webauthn_live_operation ON public.hosted_identity_bootstrap_webauthn_challenges (attempt_id, operation) WHERE status IN ('pending', 'consuming');
CREATE INDEX hosted_identity_bootstrap_webauthn_expiry ON public.hosted_identity_bootstrap_webauthn_challenges (expires_at) WHERE status IN ('pending', 'consuming');

CREATE FUNCTION public.agentpass_guard_hosted_identity_bootstrap_attempt()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE membership_member_id uuid; membership_status text; membership_role text;
BEGIN
  IF current_user <> pg_get_userbyid((SELECT relowner FROM pg_catalog.pg_class WHERE oid = TG_RELID)) THEN
    RAISE EXCEPTION USING ERRCODE = 'insufficient_privilege', MESSAGE = 'hosted bootstrap trigger requires relation owner';
  END IF;
  IF TG_OP = 'DELETE' THEN RAISE EXCEPTION USING ERRCODE = 'restrict_violation', MESSAGE = 'hosted bootstrap attempts are append-only'; END IF;
  IF TG_OP = 'UPDATE' AND OLD.state IS DISTINCT FROM NEW.state AND NOT (
    (OLD.state = 'oauth_started' AND NEW.state IN ('identity_verified', 'expired'))
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

CREATE TRIGGER hosted_identity_bootstrap_attempt_guard BEFORE INSERT OR UPDATE OR DELETE ON public.hosted_identity_bootstrap_attempts FOR EACH ROW EXECUTE FUNCTION public.agentpass_guard_hosted_identity_bootstrap_attempt();

CREATE FUNCTION public.agentpass_guard_hosted_identity_oauth_state()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF current_user <> pg_get_userbyid((SELECT relowner FROM pg_catalog.pg_class WHERE oid = TG_RELID)) THEN RAISE EXCEPTION USING ERRCODE = 'insufficient_privilege', MESSAGE = 'hosted OAuth trigger requires relation owner'; END IF;
  IF TG_OP = 'DELETE' THEN RAISE EXCEPTION USING ERRCODE = 'restrict_violation', MESSAGE = 'hosted OAuth states are append-only'; END IF;
  IF TG_OP = 'UPDATE' AND (OLD.state_hash IS DISTINCT FROM NEW.state_hash OR OLD.attempt_id IS DISTINCT FROM NEW.attempt_id OR OLD.client_id IS DISTINCT FROM NEW.client_id OR OLD.redirect_uri IS DISTINCT FROM NEW.redirect_uri OR OLD.pkce_challenge IS DISTINCT FROM NEW.pkce_challenge OR OLD.pkce_method IS DISTINCT FROM NEW.pkce_method) THEN RAISE EXCEPTION USING ERRCODE = 'restrict_violation', MESSAGE = 'hosted OAuth binding metadata is immutable'; END IF;
  IF TG_OP = 'UPDATE' AND OLD.status IS DISTINCT FROM NEW.status AND NOT ((OLD.status = 'pending' AND NEW.status IN ('consuming', 'failed', 'expired')) OR (OLD.status = 'consuming' AND NEW.status IN ('consumed', 'failed', 'expired'))) THEN RAISE EXCEPTION USING ERRCODE = 'invalid_parameter_value', MESSAGE = 'hosted OAuth state is not forward-only'; END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER hosted_identity_oauth_state_guard BEFORE INSERT OR UPDATE OR DELETE ON public.hosted_identity_oauth_states FOR EACH ROW EXECUTE FUNCTION public.agentpass_guard_hosted_identity_oauth_state();

CREATE FUNCTION public.agentpass_guard_hosted_identity_bootstrap_idempotency()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF current_user <> pg_get_userbyid((SELECT relowner FROM pg_catalog.pg_class WHERE oid = TG_RELID)) THEN RAISE EXCEPTION USING ERRCODE = 'insufficient_privilege', MESSAGE = 'hosted idempotency trigger requires relation owner'; END IF;
  IF TG_OP <> 'INSERT' THEN RAISE EXCEPTION USING ERRCODE = 'restrict_violation', MESSAGE = 'hosted bootstrap idempotency records are immutable'; END IF;
  IF NOT EXISTS (SELECT 1 FROM public.hosted_identity_bootstrap_attempts AS a WHERE a.id = NEW.attempt_id AND a.state = 'organization_required' AND a.member_id = NEW.member_id AND a.organization_id IS NULL) THEN RAISE EXCEPTION USING ERRCODE = 'foreign_key_violation', MESSAGE = 'idempotency record is not bound to an organization-required attempt'; END IF;
  IF NOT EXISTS (SELECT 1 FROM public.memberships AS m WHERE m.organization_id = NEW.organization_id AND m.id = NEW.membership_id AND m.member_id = NEW.member_id AND m.status = 'active' AND m.role = 'owner') THEN RAISE EXCEPTION USING ERRCODE = 'foreign_key_violation', MESSAGE = 'idempotency record is not bound to the server owner membership'; END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER hosted_identity_bootstrap_idempotency_guard BEFORE INSERT OR UPDATE OR DELETE ON public.hosted_identity_bootstrap_idempotency FOR EACH ROW EXECUTE FUNCTION public.agentpass_guard_hosted_identity_bootstrap_idempotency();

CREATE FUNCTION public.agentpass_guard_hosted_identity_bootstrap_webauthn_challenge()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE attempt_member_id uuid; attempt_organization_id uuid;
BEGIN
  IF current_user <> pg_get_userbyid((SELECT relowner FROM pg_catalog.pg_class WHERE oid = TG_RELID)) THEN RAISE EXCEPTION USING ERRCODE = 'insufficient_privilege', MESSAGE = 'hosted WebAuthn trigger requires relation owner'; END IF;
  IF TG_OP = 'DELETE' THEN RAISE EXCEPTION USING ERRCODE = 'restrict_violation', MESSAGE = 'hosted WebAuthn challenges are append-only'; END IF;
  IF TG_OP = 'UPDATE' AND (OLD.attempt_id IS DISTINCT FROM NEW.attempt_id OR OLD.member_id IS DISTINCT FROM NEW.member_id OR OLD.organization_id IS DISTINCT FROM NEW.organization_id OR OLD.challenge_hash IS DISTINCT FROM NEW.challenge_hash OR OLD.rp_id IS DISTINCT FROM NEW.rp_id OR OLD.origin IS DISTINCT FROM NEW.origin OR OLD.user_verification IS DISTINCT FROM NEW.user_verification) THEN RAISE EXCEPTION USING ERRCODE = 'restrict_violation', MESSAGE = 'hosted WebAuthn binding is immutable'; END IF;
  IF TG_OP = 'UPDATE' AND OLD.status IS DISTINCT FROM NEW.status AND NOT ((OLD.status = 'pending' AND NEW.status IN ('consuming', 'failed', 'expired')) OR (OLD.status = 'consuming' AND NEW.status IN ('consumed', 'failed', 'expired'))) THEN RAISE EXCEPTION USING ERRCODE = 'invalid_parameter_value', MESSAGE = 'hosted WebAuthn challenge is not forward-only'; END IF;
  SELECT a.member_id, a.organization_id INTO attempt_member_id, attempt_organization_id FROM public.hosted_identity_bootstrap_attempts AS a WHERE a.id = NEW.attempt_id;
  IF NOT FOUND OR attempt_member_id IS DISTINCT FROM NEW.member_id OR attempt_organization_id IS DISTINCT FROM NEW.organization_id THEN RAISE EXCEPTION USING ERRCODE = 'foreign_key_violation', MESSAGE = 'WebAuthn challenge is not bound to its bootstrap attempt'; END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER hosted_identity_bootstrap_webauthn_guard BEFORE INSERT OR UPDATE OR DELETE ON public.hosted_identity_bootstrap_webauthn_challenges FOR EACH ROW EXECUTE FUNCTION public.agentpass_guard_hosted_identity_bootstrap_webauthn_challenge();

CREATE FUNCTION public.agentpass_hosted_identity_bootstrap_start(p_attempt_id uuid, p_oauth_state_id uuid, p_state_hash bytea, p_pkce_challenge text, p_client_id text, p_redirect_uri text)
RETURNS TABLE (attempt_id uuid, oauth_state_id uuid, state_expires_at timestamptz, attempt_expires_at timestamptz)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE now_value timestamptz := clock_timestamp();
BEGIN
  INSERT INTO public.hosted_identity_bootstrap_attempts (id, oauth_state_id, state, provider, created_at, expires_at) VALUES (p_attempt_id, p_oauth_state_id, 'oauth_started', 'github', now_value, now_value + interval '15 minutes');
  INSERT INTO public.hosted_identity_oauth_states (id, attempt_id, state_hash, provider, client_id, redirect_uri, pkce_challenge, pkce_method, status, created_at, expires_at) VALUES (p_oauth_state_id, p_attempt_id, p_state_hash, 'github', p_client_id, p_redirect_uri, p_pkce_challenge, 'S256', 'pending', now_value, now_value + interval '10 minutes');
  RETURN QUERY SELECT p_attempt_id, p_oauth_state_id, now_value + interval '10 minutes', now_value + interval '15 minutes';
END; $$;

CREATE FUNCTION public.agentpass_hosted_identity_oauth_state_consume(p_oauth_state_id uuid, p_code_hash bytea, p_redirect_uri text)
RETURNS TABLE (attempt_id uuid, pkce_challenge text, pkce_method text, client_id text, redirect_uri text)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE oauth_row public.hosted_identity_oauth_states%ROWTYPE; now_value timestamptz := clock_timestamp();
BEGIN
  IF octet_length(p_code_hash) IS DISTINCT FROM 32 THEN RAISE EXCEPTION USING ERRCODE = 'invalid_parameter_value', MESSAGE = 'OAuth code selector must be a SHA-256 digest'; END IF;
  SELECT * INTO oauth_row FROM public.hosted_identity_oauth_states WHERE id = p_oauth_state_id FOR UPDATE;
  IF NOT FOUND OR oauth_row.status <> 'pending' THEN RAISE EXCEPTION USING ERRCODE = 'invalid_authorization_specification', MESSAGE = 'OAuth state is absent or already consumed'; END IF;
  IF oauth_row.expires_at <= now_value THEN
    UPDATE public.hosted_identity_oauth_states SET status = 'expired', expired_at = now_value, failure_code = 'oauth_state_expired' WHERE id = oauth_row.id;
    UPDATE public.hosted_identity_bootstrap_attempts SET state = 'expired', expired_at = now_value, failure_code = 'oauth_state_expired', version = version + 1 WHERE id = oauth_row.attempt_id AND state = 'oauth_started';
    RETURN;
  END IF;
  IF oauth_row.redirect_uri <> p_redirect_uri THEN
    UPDATE public.hosted_identity_oauth_states SET status = 'failed', code_hash = p_code_hash, consume_started_at = now_value, consumed_at = now_value, failed_at = now_value, failure_code = 'redirect_uri_mismatch' WHERE id = oauth_row.id;
    UPDATE public.hosted_identity_bootstrap_attempts SET state = 'expired', expired_at = now_value, failure_code = 'redirect_uri_mismatch', version = version + 1 WHERE id = oauth_row.attempt_id AND state = 'oauth_started';
    RETURN;
  END IF;
  UPDATE public.hosted_identity_oauth_states SET status = 'consuming', code_hash = p_code_hash, consume_started_at = now_value WHERE id = oauth_row.id;
  RETURN QUERY SELECT oauth_row.attempt_id, oauth_row.pkce_challenge, oauth_row.pkce_method, oauth_row.client_id, oauth_row.redirect_uri;
END; $$;

CREATE FUNCTION public.agentpass_hosted_identity_oauth_state_complete(p_oauth_state_id uuid, p_bootstrap_cookie_hash bytea, p_member_id uuid, p_subject text, p_subject_digest bytea)
RETURNS uuid LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE oauth_row public.hosted_identity_oauth_states%ROWTYPE; now_value timestamptz := clock_timestamp();
BEGIN
  IF octet_length(p_bootstrap_cookie_hash) IS DISTINCT FROM 32 OR octet_length(p_subject_digest) IS DISTINCT FROM 32 THEN RAISE EXCEPTION USING ERRCODE = 'invalid_parameter_value', MESSAGE = 'bootstrap selectors and identity digest must be SHA-256 digests'; END IF;
  IF p_subject IS NULL OR char_length(p_subject) < 1 OR char_length(p_subject) > 512 OR p_subject ~ '[[:cntrl:]]' THEN RAISE EXCEPTION USING ERRCODE = 'invalid_parameter_value', MESSAGE = 'verified identity subject is invalid'; END IF;
  IF NOT EXISTS (SELECT 1 FROM public.members AS m WHERE m.id = p_member_id) OR NOT EXISTS (SELECT 1 FROM public.upstream_identities AS i WHERE i.provider = 'github' AND i.subject = p_subject AND i.member_id = p_member_id) THEN RAISE EXCEPTION USING ERRCODE = 'foreign_key_violation', MESSAGE = 'verified identity has no immutable upstream mapping'; END IF;
  SELECT * INTO oauth_row FROM public.hosted_identity_oauth_states WHERE id = p_oauth_state_id AND status = 'consuming' FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE = 'invalid_authorization_specification', MESSAGE = 'OAuth callback is not consuming'; END IF;
  UPDATE public.hosted_identity_oauth_states SET status = 'consumed', consumed_at = now_value WHERE id = oauth_row.id;
  UPDATE public.hosted_identity_bootstrap_attempts SET state = 'identity_verified', bootstrap_cookie_hash = p_bootstrap_cookie_hash, member_id = p_member_id, identity_subject_digest = p_subject_digest, identity_verified_at = now_value, version = version + 1 WHERE id = oauth_row.attempt_id AND state = 'oauth_started';
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE = 'serialization_failure', MESSAGE = 'bootstrap attempt changed during OAuth completion'; END IF;
  RETURN oauth_row.attempt_id;
END; $$;

CREATE FUNCTION public.agentpass_hosted_identity_oauth_state_fail(p_oauth_state_id uuid, p_failure_code text)
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE oauth_row public.hosted_identity_oauth_states%ROWTYPE; now_value timestamptz := clock_timestamp();
BEGIN
  IF p_failure_code IS NULL OR p_failure_code !~ '^[a-z][a-z0-9_]{0,63}$' THEN RAISE EXCEPTION USING ERRCODE = 'invalid_parameter_value', MESSAGE = 'OAuth failure code is invalid'; END IF;
  SELECT * INTO oauth_row FROM public.hosted_identity_oauth_states WHERE id = p_oauth_state_id AND status = 'consuming' FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE = 'invalid_authorization_specification', MESSAGE = 'OAuth state cannot be failed from its current state'; END IF;
  UPDATE public.hosted_identity_oauth_states SET status = 'failed', consumed_at = now_value, failed_at = now_value, failure_code = p_failure_code WHERE id = oauth_row.id;
  UPDATE public.hosted_identity_bootstrap_attempts SET state = 'expired', expired_at = now_value, failure_code = p_failure_code, version = version + 1 WHERE id = oauth_row.attempt_id AND state = 'oauth_started';
END; $$;

CREATE FUNCTION public.agentpass_hosted_identity_bootstrap_csrf_issue(p_bootstrap_cookie_hash bytea, p_csrf_token_hash bytea)
RETURNS boolean LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
BEGIN
  IF octet_length(p_bootstrap_cookie_hash) IS DISTINCT FROM 32 OR octet_length(p_csrf_token_hash) IS DISTINCT FROM 32 THEN RAISE EXCEPTION USING ERRCODE = 'invalid_parameter_value', MESSAGE = 'bootstrap and CSRF selectors must be SHA-256 digests'; END IF;
  UPDATE public.hosted_identity_bootstrap_attempts SET csrf_token_hash = COALESCE(csrf_token_hash, p_csrf_token_hash), version = version + 1 WHERE bootstrap_cookie_hash = p_bootstrap_cookie_hash AND state IN ('identity_verified', 'organization_required', 'webauthn_required', 'ready') AND expires_at > clock_timestamp();
  RETURN FOUND;
END; $$;

CREATE FUNCTION public.agentpass_hosted_identity_bootstrap_organization_commit(p_bootstrap_cookie_hash bytea, p_idempotency_key text, p_request_hash bytea, p_organization_id uuid, p_membership_id uuid, p_public_response jsonb)
RETURNS TABLE (response_status integer, response_json jsonb, replayed boolean)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE attempt_row public.hosted_identity_bootstrap_attempts%ROWTYPE; prior_row public.hosted_identity_bootstrap_idempotency%ROWTYPE; now_value timestamptz := clock_timestamp();
BEGIN
  IF octet_length(p_bootstrap_cookie_hash) IS DISTINCT FROM 32 OR octet_length(p_request_hash) IS DISTINCT FROM 32 THEN RAISE EXCEPTION USING ERRCODE = 'invalid_parameter_value', MESSAGE = 'bootstrap selectors and request hash must be SHA-256 digests'; END IF;
  SELECT * INTO attempt_row FROM public.hosted_identity_bootstrap_attempts WHERE bootstrap_cookie_hash = p_bootstrap_cookie_hash FOR UPDATE;
  IF NOT FOUND OR attempt_row.expires_at <= now_value OR attempt_row.state = 'expired' THEN RAISE EXCEPTION USING ERRCODE = 'invalid_authorization_specification', MESSAGE = 'bootstrap attempt is absent or expired'; END IF;
  SELECT * INTO prior_row FROM public.hosted_identity_bootstrap_idempotency WHERE member_id = attempt_row.member_id AND operation = 'first_organization_create' AND idempotency_key = p_idempotency_key FOR UPDATE;
  IF FOUND THEN
    IF prior_row.request_hash IS DISTINCT FROM p_request_hash THEN RAISE EXCEPTION USING ERRCODE = 'unique_violation', MESSAGE = 'idempotency key was reused with a different request'; END IF;
    RETURN QUERY SELECT 200, prior_row.response_json, true; RETURN;
  END IF;
  IF attempt_row.state <> 'organization_required' THEN RAISE EXCEPTION USING ERRCODE = 'unique_violation', MESSAGE = 'first organization bootstrap is already completed'; END IF;
  INSERT INTO public.hosted_identity_bootstrap_idempotency (attempt_id, member_id, organization_id, membership_id, operation, idempotency_key, request_hash, response_status, response_json, committed_at) VALUES (attempt_row.id, attempt_row.member_id, p_organization_id, p_membership_id, 'first_organization_create', p_idempotency_key, p_request_hash, 201, p_public_response, now_value);
  UPDATE public.hosted_identity_bootstrap_attempts SET state = 'webauthn_required', organization_id = p_organization_id, membership_id = p_membership_id, version = version + 1 WHERE id = attempt_row.id;
  RETURN QUERY SELECT 201, p_public_response, false;
END; $$;

CREATE FUNCTION public.agentpass_hosted_identity_bootstrap_challenge_create(p_bootstrap_cookie_hash bytea, p_challenge_id uuid, p_challenge_hash bytea, p_rp_id text, p_origin text, p_expires_at timestamptz)
RETURNS TABLE (challenge_id uuid, member_id uuid, organization_id uuid, rp_id text, origin text, expires_at timestamptz)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE attempt_row public.hosted_identity_bootstrap_attempts%ROWTYPE; now_value timestamptz := clock_timestamp();
BEGIN
  IF octet_length(p_bootstrap_cookie_hash) IS DISTINCT FROM 32 OR octet_length(p_challenge_hash) IS DISTINCT FROM 32 THEN RAISE EXCEPTION USING ERRCODE = 'invalid_parameter_value', MESSAGE = 'bootstrap and WebAuthn selectors must be SHA-256 digests'; END IF;
  SELECT * INTO attempt_row FROM public.hosted_identity_bootstrap_attempts WHERE bootstrap_cookie_hash = p_bootstrap_cookie_hash FOR UPDATE;
  IF NOT FOUND OR attempt_row.state <> 'webauthn_required' OR attempt_row.expires_at <= now_value THEN RAISE EXCEPTION USING ERRCODE = 'invalid_authorization_specification', MESSAGE = 'bootstrap WebAuthn is not currently required'; END IF;
  IF p_expires_at <= now_value OR p_expires_at > LEAST(attempt_row.expires_at, now_value + interval '10 minutes') THEN RAISE EXCEPTION USING ERRCODE = 'invalid_parameter_value', MESSAGE = 'WebAuthn challenge expiry is outside the attempt'; END IF;
  INSERT INTO public.hosted_identity_bootstrap_webauthn_challenges (id, attempt_id, member_id, organization_id, challenge_hash, operation, rp_id, origin, user_verification, status, created_at, expires_at) VALUES (p_challenge_id, attempt_row.id, attempt_row.member_id, attempt_row.organization_id, p_challenge_hash, 'bootstrap_registration', p_rp_id, p_origin, 'required', 'pending', now_value, p_expires_at);
  RETURN QUERY SELECT p_challenge_id, attempt_row.member_id, attempt_row.organization_id, p_rp_id, p_origin, p_expires_at;
END; $$;

CREATE FUNCTION public.agentpass_hosted_identity_bootstrap_challenge_consume(p_bootstrap_cookie_hash bytea, p_challenge_id uuid, p_challenge_hash bytea)
RETURNS TABLE (attempt_id uuid, member_id uuid, organization_id uuid, rp_id text, origin text, user_verification text)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE challenge_row public.hosted_identity_bootstrap_webauthn_challenges%ROWTYPE; attempt_row public.hosted_identity_bootstrap_attempts%ROWTYPE; now_value timestamptz := clock_timestamp();
BEGIN
  IF octet_length(p_bootstrap_cookie_hash) IS DISTINCT FROM 32 OR octet_length(p_challenge_hash) IS DISTINCT FROM 32 THEN RAISE EXCEPTION USING ERRCODE = 'invalid_parameter_value', MESSAGE = 'bootstrap and WebAuthn selectors must be SHA-256 digests'; END IF;
  SELECT * INTO attempt_row FROM public.hosted_identity_bootstrap_attempts WHERE bootstrap_cookie_hash = p_bootstrap_cookie_hash FOR UPDATE;
  IF NOT FOUND OR attempt_row.state <> 'webauthn_required' OR attempt_row.expires_at <= now_value THEN RAISE EXCEPTION USING ERRCODE = 'invalid_authorization_specification', MESSAGE = 'bootstrap WebAuthn attempt is absent or expired'; END IF;
  SELECT c.* INTO challenge_row FROM public.hosted_identity_bootstrap_webauthn_challenges AS c WHERE c.id = p_challenge_id AND c.attempt_id = attempt_row.id AND c.challenge_hash = p_challenge_hash FOR UPDATE;
  IF NOT FOUND OR challenge_row.status <> 'pending' THEN RAISE EXCEPTION USING ERRCODE = 'invalid_authorization_specification', MESSAGE = 'bootstrap WebAuthn challenge is absent or already consumed'; END IF;
  IF challenge_row.expires_at <= now_value THEN UPDATE public.hosted_identity_bootstrap_webauthn_challenges SET status = 'expired', expired_at = now_value, failure_code = 'challenge_expired' WHERE id = challenge_row.id; RETURN; END IF;
  UPDATE public.hosted_identity_bootstrap_webauthn_challenges SET status = 'consuming', consume_started_at = now_value WHERE id = challenge_row.id;
  RETURN QUERY SELECT attempt_row.id, attempt_row.member_id, attempt_row.organization_id, challenge_row.rp_id, challenge_row.origin, challenge_row.user_verification;
END; $$;

CREATE FUNCTION public.agentpass_hosted_identity_bootstrap_challenge_complete(p_bootstrap_cookie_hash bytea, p_challenge_id uuid, p_challenge_hash bytea)
RETURNS uuid LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE challenge_row public.hosted_identity_bootstrap_webauthn_challenges%ROWTYPE; attempt_id_value uuid; now_value timestamptz := clock_timestamp();
BEGIN
  SELECT c INTO challenge_row FROM public.hosted_identity_bootstrap_webauthn_challenges AS c JOIN public.hosted_identity_bootstrap_attempts AS a ON a.id = c.attempt_id WHERE a.bootstrap_cookie_hash = p_bootstrap_cookie_hash AND c.id = p_challenge_id AND c.challenge_hash = p_challenge_hash AND c.status = 'consuming' AND a.state = 'webauthn_required' FOR UPDATE OF c, a;
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE = 'invalid_authorization_specification', MESSAGE = 'bootstrap WebAuthn challenge is not consuming'; END IF;
  attempt_id_value := challenge_row.attempt_id;
  UPDATE public.hosted_identity_bootstrap_webauthn_challenges SET status = 'consumed', consumed_at = now_value WHERE id = challenge_row.id;
  UPDATE public.hosted_identity_bootstrap_attempts SET state = 'completed', completed_at = now_value, version = version + 1 WHERE id = attempt_id_value;
  RETURN attempt_id_value;
END; $$;

CREATE FUNCTION public.agentpass_hosted_identity_bootstrap_challenge_fail(p_bootstrap_cookie_hash bytea, p_challenge_id uuid, p_challenge_hash bytea, p_failure_code text)
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE challenge_attempt_id uuid; now_value timestamptz := clock_timestamp();
BEGIN
  IF p_failure_code IS NULL OR p_failure_code !~ '^[a-z][a-z0-9_]{0,63}$' THEN RAISE EXCEPTION USING ERRCODE = 'invalid_parameter_value', MESSAGE = 'WebAuthn failure code is invalid'; END IF;
  SELECT c.attempt_id INTO challenge_attempt_id FROM public.hosted_identity_bootstrap_webauthn_challenges AS c JOIN public.hosted_identity_bootstrap_attempts AS a ON a.id = c.attempt_id WHERE a.bootstrap_cookie_hash = p_bootstrap_cookie_hash AND c.id = p_challenge_id AND c.challenge_hash = p_challenge_hash AND c.status = 'consuming' AND a.state = 'webauthn_required' FOR UPDATE OF c, a;
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE = 'invalid_authorization_specification', MESSAGE = 'bootstrap WebAuthn challenge cannot be failed from its current state'; END IF;
  UPDATE public.hosted_identity_bootstrap_webauthn_challenges SET status = 'failed', consumed_at = now_value, failed_at = now_value, failure_code = p_failure_code WHERE id = p_challenge_id;
END; $$;

-- Deployment-specific roles are deliberately absent here.  The deployment
-- role policy owns all non-PUBLIC grants after generic migration apply.
REVOKE ALL PRIVILEGES ON TABLE public.hosted_identity_bootstrap_attempts, public.hosted_identity_oauth_states, public.hosted_identity_bootstrap_idempotency, public.hosted_identity_bootstrap_webauthn_challenges FROM PUBLIC;
REVOKE ALL PRIVILEGES ON FUNCTION public.agentpass_guard_hosted_identity_bootstrap_attempt() FROM PUBLIC;
REVOKE ALL PRIVILEGES ON FUNCTION public.agentpass_guard_hosted_identity_oauth_state() FROM PUBLIC;
REVOKE ALL PRIVILEGES ON FUNCTION public.agentpass_guard_hosted_identity_bootstrap_idempotency() FROM PUBLIC;
REVOKE ALL PRIVILEGES ON FUNCTION public.agentpass_guard_hosted_identity_bootstrap_webauthn_challenge() FROM PUBLIC;
REVOKE ALL PRIVILEGES ON FUNCTION public.agentpass_hosted_identity_bootstrap_start(uuid, uuid, bytea, text, text, text) FROM PUBLIC;
REVOKE ALL PRIVILEGES ON FUNCTION public.agentpass_hosted_identity_oauth_state_consume(uuid, bytea, text) FROM PUBLIC;
REVOKE ALL PRIVILEGES ON FUNCTION public.agentpass_hosted_identity_oauth_state_complete(uuid, bytea, uuid, text, bytea) FROM PUBLIC;
REVOKE ALL PRIVILEGES ON FUNCTION public.agentpass_hosted_identity_oauth_state_fail(uuid, text) FROM PUBLIC;
REVOKE ALL PRIVILEGES ON FUNCTION public.agentpass_hosted_identity_bootstrap_csrf_issue(bytea, bytea) FROM PUBLIC;
REVOKE ALL PRIVILEGES ON FUNCTION public.agentpass_hosted_identity_bootstrap_organization_commit(bytea, text, bytea, uuid, uuid, jsonb) FROM PUBLIC;
REVOKE ALL PRIVILEGES ON FUNCTION public.agentpass_hosted_identity_bootstrap_challenge_create(bytea, uuid, bytea, text, text, timestamptz) FROM PUBLIC;
REVOKE ALL PRIVILEGES ON FUNCTION public.agentpass_hosted_identity_bootstrap_challenge_consume(bytea, uuid, bytea) FROM PUBLIC;
REVOKE ALL PRIVILEGES ON FUNCTION public.agentpass_hosted_identity_bootstrap_challenge_complete(bytea, uuid, bytea) FROM PUBLIC;
REVOKE ALL PRIVILEGES ON FUNCTION public.agentpass_hosted_identity_bootstrap_challenge_fail(bytea, uuid, bytea, text) FROM PUBLIC;

COMMIT;
