BEGIN;

-- Verification happens outside PostgreSQL and can outlive an API process.
-- Bind that work to a short database-clock lease. The browser never receives
-- the claim token; the Hosted service deterministically reconstructs it from
-- the exact attestation response, while PostgreSQL stores only its digest.
ALTER TABLE public.hosted_identity_bootstrap_webauthn_challenges
  ADD COLUMN claim_token_hash bytea,
  ADD COLUMN claim_expires_at timestamptz,
  ADD COLUMN claim_generation bigint NOT NULL DEFAULT 0;

-- A pre-0063 process may have died after the legacy consume operation. Such a
-- claim has no recoverable owner, so make it terminal before enforcing the new
-- shape. Already consumed/failed evidence remains readable but cannot be
-- replayed through the new claim-bound entry point.
UPDATE public.hosted_identity_bootstrap_webauthn_challenges
SET status = 'expired',
    expired_at = clock_timestamp(),
    failure_code = 'claim_migration_expired'
WHERE status = 'consuming';

ALTER TABLE public.hosted_identity_bootstrap_webauthn_challenges
  ADD CONSTRAINT hosted_identity_bootstrap_webauthn_claim_shape CHECK (
    (status = 'pending'
      AND claim_token_hash IS NULL
      AND claim_expires_at IS NULL
      AND claim_generation = 0)
    OR (status = 'consuming'
      AND octet_length(claim_token_hash) = 32
      AND claim_expires_at IS NOT NULL
      AND claim_expires_at > consume_started_at
      AND claim_expires_at <= expires_at
      AND claim_generation >= 1)
    OR (status IN ('consumed', 'failed', 'expired') AND (
      (claim_token_hash IS NULL
        AND claim_expires_at IS NULL
        AND claim_generation = 0)
      OR (octet_length(claim_token_hash) = 32
        AND claim_expires_at IS NOT NULL
        AND claim_generation >= 1)
    ))
  );

CREATE TABLE public.hosted_identity_bootstrap_webauthn_claim_events (
  challenge_id uuid NOT NULL
    REFERENCES public.hosted_identity_bootstrap_webauthn_challenges(id),
  generation bigint NOT NULL CHECK (generation > 0),
  event_type text NOT NULL CHECK (event_type IN (
    'claimed', 'takeover', 'completed', 'replayed', 'failed', 'expired'
  )),
  claim_token_hash bytea NOT NULL CHECK (octet_length(claim_token_hash) = 32),
  observed_at timestamptz NOT NULL,
  previous_generation bigint CHECK (previous_generation IS NULL OR previous_generation > 0),
  previous_lease_expires_at timestamptz,
  lease_expires_at timestamptz,
  failure_code text CHECK (failure_code IS NULL OR failure_code ~ '^[a-z][a-z0-9_]{0,63}$'),
  PRIMARY KEY (challenge_id, generation, event_type),
  CHECK ((event_type = 'takeover') = (previous_generation IS NOT NULL)),
  CHECK ((event_type = 'failed') = (failure_code IS NOT NULL))
);

CREATE FUNCTION public.agentpass_guard_hosted_identity_bootstrap_webauthn_claim_event()
RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
BEGIN
  IF current_user <> pg_get_userbyid((
    SELECT relowner FROM pg_catalog.pg_class WHERE oid = TG_RELID
  )) THEN
    RAISE EXCEPTION USING ERRCODE = 'insufficient_privilege',
      MESSAGE = 'hosted WebAuthn claim event trigger requires relation owner';
  END IF;
  IF TG_OP <> 'INSERT' THEN
    RAISE EXCEPTION USING ERRCODE = 'restrict_violation',
      MESSAGE = 'hosted WebAuthn claim events are append-only';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER hosted_identity_bootstrap_webauthn_claim_events_immutable
  BEFORE UPDATE OR DELETE ON public.hosted_identity_bootstrap_webauthn_claim_events
  FOR EACH ROW EXECUTE FUNCTION public.agentpass_guard_hosted_identity_bootstrap_webauthn_claim_event();

CREATE OR REPLACE FUNCTION public.agentpass_guard_hosted_identity_bootstrap_webauthn_challenge()
RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
DECLARE
  attempt_member_id uuid;
  attempt_organization_id uuid;
  claim_changed boolean;
BEGIN
  IF current_user <> pg_get_userbyid((
    SELECT relowner FROM pg_catalog.pg_class WHERE oid = TG_RELID
  )) THEN
    RAISE EXCEPTION USING ERRCODE = 'insufficient_privilege',
      MESSAGE = 'hosted WebAuthn trigger requires relation owner';
  END IF;
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION USING ERRCODE = 'restrict_violation',
      MESSAGE = 'hosted WebAuthn challenges are append-only';
  END IF;
  IF TG_OP = 'UPDATE' AND (
    OLD.attempt_id IS DISTINCT FROM NEW.attempt_id
    OR OLD.member_id IS DISTINCT FROM NEW.member_id
    OR OLD.organization_id IS DISTINCT FROM NEW.organization_id
    OR OLD.challenge_hash IS DISTINCT FROM NEW.challenge_hash
    OR OLD.operation IS DISTINCT FROM NEW.operation
    OR OLD.rp_id IS DISTINCT FROM NEW.rp_id
    OR OLD.origin IS DISTINCT FROM NEW.origin
    OR OLD.user_verification IS DISTINCT FROM NEW.user_verification
    OR OLD.created_at IS DISTINCT FROM NEW.created_at
    OR OLD.expires_at IS DISTINCT FROM NEW.expires_at
  ) THEN
    RAISE EXCEPTION USING ERRCODE = 'restrict_violation',
      MESSAGE = 'hosted WebAuthn binding is immutable';
  END IF;
  IF TG_OP = 'UPDATE' AND OLD.status IS DISTINCT FROM NEW.status AND NOT (
    (OLD.status = 'pending' AND NEW.status IN ('consuming', 'failed', 'expired'))
    OR (OLD.status = 'consuming' AND NEW.status IN ('consumed', 'failed', 'expired'))
  ) THEN
    RAISE EXCEPTION USING ERRCODE = 'invalid_parameter_value',
      MESSAGE = 'hosted WebAuthn challenge is not forward-only';
  END IF;

  IF TG_OP = 'UPDATE' THEN
    claim_changed := OLD.claim_token_hash IS DISTINCT FROM NEW.claim_token_hash
      OR OLD.claim_expires_at IS DISTINCT FROM NEW.claim_expires_at
      OR OLD.claim_generation IS DISTINCT FROM NEW.claim_generation;
    IF claim_changed AND NOT (
      (OLD.status = 'pending'
        AND NEW.status = 'consuming'
        AND OLD.claim_token_hash IS NULL
        AND NEW.claim_generation = 1)
      OR (OLD.status = 'consuming'
        AND NEW.status = 'consuming'
        AND NEW.claim_generation = OLD.claim_generation + 1
        AND (OLD.claim_token_hash = NEW.claim_token_hash
          OR OLD.claim_expires_at <= clock_timestamp()))
    ) THEN
      RAISE EXCEPTION USING ERRCODE = 'restrict_violation',
        MESSAGE = 'hosted WebAuthn claim binding is immutable';
    END IF;
    IF NOT claim_changed AND OLD.status = 'pending' AND NEW.status = 'consuming' THEN
      RAISE EXCEPTION USING ERRCODE = 'check_violation',
        MESSAGE = 'hosted WebAuthn consuming state requires a claim';
    END IF;
  END IF;

  SELECT a.member_id, a.organization_id
  INTO attempt_member_id, attempt_organization_id
  FROM public.hosted_identity_bootstrap_attempts AS a
  WHERE a.id = NEW.attempt_id;
  IF NOT FOUND
     OR attempt_member_id IS DISTINCT FROM NEW.member_id
     OR attempt_organization_id IS DISTINCT FROM NEW.organization_id THEN
    RAISE EXCEPTION USING ERRCODE = 'foreign_key_violation',
      MESSAGE = 'WebAuthn challenge is not bound to its bootstrap attempt';
  END IF;
  RETURN NEW;
END;
$$;

CREATE FUNCTION public.agentpass_hosted_identity_bootstrap_webauthn_claim_v2(
  p_bootstrap_cookie_hash bytea,
  p_challenge_id uuid,
  p_challenge_hash bytea,
  p_claim_token_hash bytea
)
RETURNS TABLE (
  attempt_id uuid,
  member_id uuid,
  organization_id uuid,
  rp_id text,
  origin text,
  user_verification text,
  claim_generation bigint,
  claim_expires_at timestamptz
)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public AS $$
#variable_conflict use_column
DECLARE
  attempt_row public.hosted_identity_bootstrap_attempts%ROWTYPE;
  challenge_row public.hosted_identity_bootstrap_webauthn_challenges%ROWTYPE;
  completion_row public.hosted_identity_bootstrap_completions%ROWTYPE;
  now_value timestamptz;
  lease_expiry timestamptz;
BEGIN
  IF octet_length(p_bootstrap_cookie_hash) IS DISTINCT FROM 32
     OR octet_length(p_challenge_hash) IS DISTINCT FROM 32
     OR octet_length(p_claim_token_hash) IS DISTINCT FROM 32 THEN
    RAISE EXCEPTION USING ERRCODE = 'invalid_parameter_value',
      MESSAGE = 'Hosted WebAuthn claim selectors must be SHA-256 digests';
  END IF;

  SELECT a.* INTO attempt_row
  FROM public.hosted_identity_bootstrap_attempts AS a
  WHERE a.bootstrap_cookie_hash = p_bootstrap_cookie_hash
  FOR UPDATE;
  IF NOT FOUND OR attempt_row.state NOT IN ('webauthn_required', 'completed') THEN
    RETURN;
  END IF;

  SELECT c.* INTO challenge_row
  FROM public.hosted_identity_bootstrap_webauthn_challenges AS c
  WHERE c.id = p_challenge_id
    AND c.attempt_id = attempt_row.id
    AND c.member_id = attempt_row.member_id
    AND c.organization_id = attempt_row.organization_id
    AND c.challenge_hash = p_challenge_hash
    AND c.operation = 'bootstrap_registration'
  FOR UPDATE;
  IF NOT FOUND THEN RETURN; END IF;
  now_value := clock_timestamp();

  IF attempt_row.state = 'completed' THEN
    SELECT completion.* INTO completion_row
    FROM public.hosted_identity_bootstrap_completions AS completion
    WHERE completion.attempt_id = attempt_row.id
      AND completion.challenge_id = challenge_row.id
      AND completion.replay_expires_at > now_value
      AND completion.replayed_at IS NULL
    FOR UPDATE;
    IF NOT FOUND OR challenge_row.status <> 'consumed'
       OR challenge_row.claim_token_hash IS DISTINCT FROM p_claim_token_hash THEN
      RETURN;
    END IF;
    RETURN QUERY SELECT attempt_row.id, attempt_row.member_id,
      attempt_row.organization_id, challenge_row.rp_id, challenge_row.origin,
      challenge_row.user_verification, challenge_row.claim_generation,
      completion_row.replay_expires_at;
    RETURN;
  END IF;

  IF attempt_row.expires_at <= now_value OR challenge_row.expires_at <= now_value THEN
    IF challenge_row.status IN ('pending', 'consuming') THEN
      UPDATE public.hosted_identity_bootstrap_webauthn_challenges
      SET status = 'expired', expired_at = now_value,
          failure_code = 'challenge_expired'
      WHERE id = challenge_row.id;
      IF challenge_row.claim_generation > 0 THEN
        INSERT INTO public.hosted_identity_bootstrap_webauthn_claim_events
          (challenge_id, generation, event_type, claim_token_hash, observed_at,
           lease_expires_at)
        VALUES
          (challenge_row.id, challenge_row.claim_generation, 'expired',
           challenge_row.claim_token_hash, now_value,
           challenge_row.claim_expires_at)
        ON CONFLICT DO NOTHING;
      END IF;
    END IF;
    RETURN;
  END IF;

  lease_expiry := LEAST(challenge_row.expires_at, now_value + interval '30 seconds');
  IF challenge_row.status = 'pending' THEN
    UPDATE public.hosted_identity_bootstrap_webauthn_challenges
    SET status = 'consuming', consume_started_at = now_value,
        claim_token_hash = p_claim_token_hash,
        claim_expires_at = lease_expiry, claim_generation = 1
    WHERE id = challenge_row.id;
    INSERT INTO public.hosted_identity_bootstrap_webauthn_claim_events
      (challenge_id, generation, event_type, claim_token_hash, observed_at,
       lease_expires_at)
    VALUES
      (challenge_row.id, 1, 'claimed', p_claim_token_hash, now_value,
       lease_expiry);
  ELSIF challenge_row.status = 'consuming'
        AND challenge_row.claim_token_hash = p_claim_token_hash
        AND challenge_row.claim_expires_at > now_value THEN
    lease_expiry := challenge_row.claim_expires_at;
  ELSIF challenge_row.status = 'consuming'
        AND challenge_row.claim_expires_at <= now_value THEN
    UPDATE public.hosted_identity_bootstrap_webauthn_challenges
    SET consume_started_at = now_value,
        claim_token_hash = p_claim_token_hash,
        claim_expires_at = lease_expiry,
        claim_generation = claim_generation + 1
    WHERE id = challenge_row.id;
    INSERT INTO public.hosted_identity_bootstrap_webauthn_claim_events
      (challenge_id, generation, event_type, claim_token_hash, observed_at,
       previous_generation, previous_lease_expires_at, lease_expires_at)
    VALUES
      (challenge_row.id, challenge_row.claim_generation + 1, 'takeover',
       p_claim_token_hash, now_value, challenge_row.claim_generation,
       challenge_row.claim_expires_at, lease_expiry);
  ELSE
    RETURN;
  END IF;

  RETURN QUERY SELECT attempt_row.id, attempt_row.member_id,
    attempt_row.organization_id, challenge_row.rp_id, challenge_row.origin,
    challenge_row.user_verification,
    CASE
      WHEN challenge_row.status = 'pending' THEN 1
      WHEN challenge_row.claim_token_hash = p_claim_token_hash
        AND challenge_row.claim_expires_at > now_value
        THEN challenge_row.claim_generation
      ELSE challenge_row.claim_generation + 1
    END,
    lease_expiry;
END;
$$;

CREATE FUNCTION public.agentpass_hosted_identity_bootstrap_webauthn_fail_v3(
  p_bootstrap_cookie_hash bytea,
  p_challenge_id uuid,
  p_challenge_hash bytea,
  p_claim_token_hash bytea,
  p_claim_generation bigint,
  p_failure_code text
)
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public AS $$
DECLARE
  attempt_id_value uuid;
  now_value timestamptz;
BEGIN
  IF octet_length(p_bootstrap_cookie_hash) IS DISTINCT FROM 32
     OR octet_length(p_challenge_hash) IS DISTINCT FROM 32
     OR octet_length(p_claim_token_hash) IS DISTINCT FROM 32
     OR p_claim_generation IS NULL OR p_claim_generation < 1
     OR p_failure_code IS NULL
     OR p_failure_code !~ '^[a-z][a-z0-9_]{0,63}$' THEN
    RAISE EXCEPTION USING ERRCODE = 'invalid_parameter_value',
      MESSAGE = 'Hosted WebAuthn failure binding is invalid';
  END IF;
  SELECT a.id INTO attempt_id_value
  FROM public.hosted_identity_bootstrap_attempts AS a
  WHERE a.bootstrap_cookie_hash = p_bootstrap_cookie_hash
    AND a.state = 'webauthn_required'
  FOR UPDATE;
  IF NOT FOUND THEN RETURN; END IF;

  PERFORM 1
  FROM public.hosted_identity_bootstrap_webauthn_challenges AS c
  WHERE c.id = p_challenge_id
    AND c.attempt_id = attempt_id_value
    AND c.challenge_hash = p_challenge_hash
    AND c.claim_token_hash = p_claim_token_hash
    AND c.claim_generation = p_claim_generation
    AND c.status = 'consuming'
  FOR UPDATE;
  IF NOT FOUND THEN RETURN; END IF;
  now_value := clock_timestamp();

  UPDATE public.hosted_identity_bootstrap_webauthn_challenges
  SET status = 'failed', consumed_at = now_value, failed_at = now_value,
      failure_code = p_failure_code
  WHERE id = p_challenge_id AND status = 'consuming'
    AND claim_token_hash = p_claim_token_hash
    AND claim_generation = p_claim_generation
    AND claim_expires_at > now_value;
  IF FOUND THEN
    INSERT INTO public.hosted_identity_bootstrap_webauthn_claim_events
      (challenge_id, generation, event_type, claim_token_hash, observed_at,
       lease_expires_at, failure_code)
    SELECT p_challenge_id, p_claim_generation, 'failed', p_claim_token_hash,
      now_value, c.claim_expires_at, p_failure_code
    FROM public.hosted_identity_bootstrap_webauthn_challenges AS c
    WHERE c.id = p_challenge_id;
  END IF;
END;
$$;

CREATE FUNCTION public.agentpass_hosted_identity_bootstrap_webauthn_complete_v3(
  p_attempt_id uuid,
  p_bootstrap_cookie_hash bytea,
  p_challenge_id uuid,
  p_challenge_hash bytea,
  p_claim_token_hash bytea,
  p_claim_generation bigint,
  p_request_hash bytea,
  p_credential_id bytea,
  p_public_key bytea,
  p_sign_count bigint,
  p_transports text[],
  p_label text,
  p_backup_eligible boolean,
  p_backup_state boolean,
  p_session_token_hash bytea,
  p_session_csrf_token_hash bytea
)
RETURNS TABLE (
  attempt_id uuid,
  session_id uuid,
  member_id uuid,
  organization_id uuid,
  membership_id uuid,
  role text,
  created_at timestamptz,
  expires_at timestamptz,
  replayed boolean
)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public AS $$
#variable_conflict use_column
DECLARE
  attempt_state text;
  challenge_status text;
  claim_hash bytea;
  claim_generation_value bigint;
  claim_expiry timestamptz;
  completion_result record;
  now_value timestamptz;
BEGIN
  IF octet_length(p_claim_token_hash) IS DISTINCT FROM 32
     OR p_claim_generation IS NULL OR p_claim_generation < 1 THEN
    RAISE EXCEPTION USING ERRCODE = 'invalid_parameter_value',
      MESSAGE = 'Hosted WebAuthn completion claim must be a SHA-256 digest';
  END IF;

  SELECT a.state INTO attempt_state
  FROM public.hosted_identity_bootstrap_attempts AS a
  WHERE a.id = p_attempt_id
    AND a.bootstrap_cookie_hash = p_bootstrap_cookie_hash
    AND a.state IN ('webauthn_required', 'completed')
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE = 'invalid_authorization_specification',
      MESSAGE = 'Hosted WebAuthn completion attempt is unavailable';
  END IF;

  SELECT c.status, c.claim_token_hash, c.claim_generation, c.claim_expires_at
  INTO challenge_status, claim_hash, claim_generation_value, claim_expiry
  FROM public.hosted_identity_bootstrap_webauthn_challenges AS c
  WHERE c.id = p_challenge_id
    AND c.attempt_id = p_attempt_id
    AND c.challenge_hash = p_challenge_hash
  FOR UPDATE;
  now_value := clock_timestamp();
  IF NOT FOUND OR claim_hash IS DISTINCT FROM p_claim_token_hash
     OR claim_generation_value IS DISTINCT FROM p_claim_generation
     OR (attempt_state = 'webauthn_required'
       AND (challenge_status <> 'consuming' OR claim_expiry <= now_value))
     OR (attempt_state = 'completed' AND challenge_status <> 'consumed') THEN
    RAISE EXCEPTION USING ERRCODE = 'invalid_authorization_specification',
      MESSAGE = 'Hosted WebAuthn completion claim is unavailable';
  END IF;

  SELECT result.* INTO completion_result
  FROM public.agentpass_hosted_identity_bootstrap_webauthn_complete_v2(
    p_attempt_id, p_bootstrap_cookie_hash, p_challenge_id, p_challenge_hash,
    p_request_hash, p_credential_id, p_public_key, p_sign_count, p_transports,
    p_label, p_backup_eligible, p_backup_state, p_session_token_hash,
    p_session_csrf_token_hash
  ) AS result;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE = 'data_exception',
      MESSAGE = 'Hosted WebAuthn completion returned no result';
  END IF;

  INSERT INTO public.hosted_identity_bootstrap_webauthn_claim_events
    (challenge_id, generation, event_type, claim_token_hash, observed_at,
     lease_expires_at)
  VALUES
    (p_challenge_id, p_claim_generation,
     CASE WHEN completion_result.replayed THEN 'replayed' ELSE 'completed' END,
     p_claim_token_hash, clock_timestamp(), claim_expiry);

  RETURN QUERY SELECT completion_result.attempt_id,
    completion_result.session_id, completion_result.member_id,
    completion_result.organization_id, completion_result.membership_id,
    completion_result.role, completion_result.created_at,
    completion_result.expires_at, completion_result.replayed;
END;
$$;

REVOKE ALL PRIVILEGES ON TABLE public.hosted_identity_bootstrap_webauthn_claim_events FROM PUBLIC;
REVOKE ALL PRIVILEGES ON FUNCTION public.agentpass_guard_hosted_identity_bootstrap_webauthn_claim_event() FROM PUBLIC;
REVOKE ALL PRIVILEGES ON FUNCTION public.agentpass_hosted_identity_bootstrap_webauthn_claim_v2(bytea, uuid, bytea, bytea) FROM PUBLIC;
REVOKE ALL PRIVILEGES ON FUNCTION public.agentpass_hosted_identity_bootstrap_webauthn_fail_v3(bytea, uuid, bytea, bytea, bigint, text) FROM PUBLIC;
REVOKE ALL PRIVILEGES ON FUNCTION public.agentpass_hosted_identity_bootstrap_webauthn_complete_v3(uuid, bytea, uuid, bytea, bytea, bigint, bytea, bytea, bytea, bigint, text[], text, boolean, boolean, bytea, bytea) FROM PUBLIC;

COMMIT;
