BEGIN;

-- A successful Hosted registration must not leave a consumed challenge
-- without its credential and ordinary Human Session (or the inverse).  Keep a
-- short, digest-only replay record so an identical retry after response loss
-- can recover the already-issued public session without repeating writes.
CREATE TABLE public.hosted_identity_bootstrap_completions (
  attempt_id uuid PRIMARY KEY REFERENCES public.hosted_identity_bootstrap_attempts(id),
  challenge_id uuid NOT NULL UNIQUE REFERENCES public.hosted_identity_bootstrap_webauthn_challenges(id),
  member_id uuid NOT NULL REFERENCES public.members(id),
  organization_id uuid NOT NULL REFERENCES public.organizations(id),
  membership_id uuid NOT NULL,
  credential_id bytea NOT NULL REFERENCES public.webauthn_credentials(id),
  session_id uuid NOT NULL UNIQUE REFERENCES public.human_sessions(id),
  request_hash bytea NOT NULL CHECK (octet_length(request_hash) = 32),
  committed_at timestamptz NOT NULL,
  replay_expires_at timestamptz NOT NULL,
  replayed_at timestamptz,
  FOREIGN KEY (organization_id, membership_id)
    REFERENCES public.memberships(organization_id, id),
  CHECK (replay_expires_at > committed_at
    AND replay_expires_at <= committed_at + interval '2 minutes'),
  CHECK (replayed_at IS NULL
    OR (replayed_at >= committed_at AND replayed_at < replay_expires_at))
);

CREATE INDEX hosted_identity_bootstrap_completions_replay_expiry
  ON public.hosted_identity_bootstrap_completions (replay_expires_at);

CREATE FUNCTION public.agentpass_guard_hosted_identity_bootstrap_completion()
RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
BEGIN
  IF current_user <> pg_get_userbyid((
    SELECT relowner FROM pg_catalog.pg_class WHERE oid = TG_RELID
  )) THEN
    RAISE EXCEPTION USING ERRCODE = 'insufficient_privilege',
      MESSAGE = 'hosted bootstrap completion trigger requires relation owner';
  END IF;
  IF TG_OP = 'UPDATE'
     AND OLD.replayed_at IS NULL AND NEW.replayed_at IS NOT NULL
     AND NEW.attempt_id IS NOT DISTINCT FROM OLD.attempt_id
     AND NEW.challenge_id IS NOT DISTINCT FROM OLD.challenge_id
     AND NEW.member_id IS NOT DISTINCT FROM OLD.member_id
     AND NEW.organization_id IS NOT DISTINCT FROM OLD.organization_id
     AND NEW.membership_id IS NOT DISTINCT FROM OLD.membership_id
     AND NEW.credential_id IS NOT DISTINCT FROM OLD.credential_id
     AND NEW.session_id IS NOT DISTINCT FROM OLD.session_id
     AND NEW.request_hash IS NOT DISTINCT FROM OLD.request_hash
     AND NEW.committed_at IS NOT DISTINCT FROM OLD.committed_at
     AND NEW.replay_expires_at IS NOT DISTINCT FROM OLD.replay_expires_at THEN
    RETURN NEW;
  END IF;
  RAISE EXCEPTION USING ERRCODE = 'restrict_violation',
    MESSAGE = 'hosted bootstrap completion binding is immutable';
END;
$$;

CREATE TRIGGER hosted_identity_bootstrap_completions_immutable
  BEFORE UPDATE OR DELETE ON public.hosted_identity_bootstrap_completions
  FOR EACH ROW EXECUTE FUNCTION public.agentpass_guard_hosted_identity_bootstrap_completion();

CREATE FUNCTION public.agentpass_hosted_identity_bootstrap_webauthn_replay_context(
  p_bootstrap_cookie_hash bytea,
  p_challenge_id uuid,
  p_challenge_hash bytea
)
RETURNS TABLE (
  attempt_id uuid,
  member_id uuid,
  organization_id uuid,
  rp_id text,
  origin text,
  user_verification text
)
LANGUAGE sql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public AS $$
  SELECT a.id, a.member_id, a.organization_id, c.rp_id, c.origin,
    c.user_verification
  FROM public.hosted_identity_bootstrap_attempts AS a
  JOIN public.hosted_identity_bootstrap_webauthn_challenges AS c
    ON c.attempt_id = a.id
   AND c.member_id = a.member_id
   AND c.organization_id = a.organization_id
  JOIN public.hosted_identity_bootstrap_completions AS completion
    ON completion.attempt_id = a.id
   AND completion.challenge_id = c.id
  WHERE a.bootstrap_cookie_hash = p_bootstrap_cookie_hash
    AND a.state = 'completed'
    AND c.id = p_challenge_id
    AND c.challenge_hash = p_challenge_hash
    AND c.status = 'consumed'
    AND completion.replay_expires_at > clock_timestamp()
    AND completion.replayed_at IS NULL
    AND octet_length(p_bootstrap_cookie_hash) = 32
    AND octet_length(p_challenge_hash) = 32
$$;

CREATE FUNCTION public.agentpass_hosted_identity_bootstrap_webauthn_complete_v2(
  p_attempt_id uuid,
  p_bootstrap_cookie_hash bytea,
  p_challenge_id uuid,
  p_challenge_hash bytea,
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
  attempt_row public.hosted_identity_bootstrap_attempts%ROWTYPE;
  challenge_row public.hosted_identity_bootstrap_webauthn_challenges%ROWTYPE;
  completion_row public.hosted_identity_bootstrap_completions%ROWTYPE;
  membership_row public.memberships%ROWTYPE;
  organization_epoch bigint;
  session_row public.human_sessions%ROWTYPE;
  now_value timestamptz := clock_timestamp();
  replay_expiry timestamptz;
  session_expiry timestamptz;
  session_idle_expiry timestamptz;
BEGIN
  IF octet_length(p_bootstrap_cookie_hash) IS DISTINCT FROM 32
     OR octet_length(p_challenge_hash) IS DISTINCT FROM 32
     OR octet_length(p_request_hash) IS DISTINCT FROM 32
     OR octet_length(p_session_token_hash) IS DISTINCT FROM 32
     OR octet_length(p_session_csrf_token_hash) IS DISTINCT FROM 32 THEN
    RAISE EXCEPTION USING ERRCODE = 'invalid_parameter_value',
      MESSAGE = 'Hosted completion selectors must be SHA-256 digests';
  END IF;
  IF p_credential_id IS NULL OR octet_length(p_credential_id) NOT BETWEEN 16 AND 1024
     OR p_public_key IS NULL OR octet_length(p_public_key) NOT BETWEEN 32 AND 4096
     OR p_sign_count IS NULL OR p_sign_count < 0
     OR p_transports IS NULL OR NOT public.agentpass_valid_webauthn_transports(p_transports)
     OR p_label IS NULL OR char_length(p_label) NOT BETWEEN 1 AND 128
     OR p_label ~ '[[:cntrl:]]'
     OR p_backup_eligible IS NULL OR p_backup_state IS NULL
     OR (p_backup_state AND NOT p_backup_eligible) THEN
    RAISE EXCEPTION USING ERRCODE = 'invalid_parameter_value',
      MESSAGE = 'Verified WebAuthn credential metadata is invalid';
  END IF;
  SELECT a.* INTO attempt_row
  FROM public.hosted_identity_bootstrap_attempts AS a
  WHERE a.id = p_attempt_id
    AND a.bootstrap_cookie_hash = p_bootstrap_cookie_hash
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE = 'invalid_authorization_specification',
      MESSAGE = 'Hosted bootstrap attempt is absent';
  END IF;

  -- Response-loss replay is exact, short-lived, and still requires the same
  -- bootstrap cookie, challenge selector, and request digest. No token hash is
  -- returned; the service reconstructs the same opaque response credentials.
  IF attempt_row.state = 'completed' THEN
    SELECT c.* INTO completion_row
    FROM public.hosted_identity_bootstrap_completions AS c
    WHERE c.attempt_id = attempt_row.id
      AND c.challenge_id = p_challenge_id
    FOR UPDATE;
    IF NOT FOUND OR completion_row.request_hash IS DISTINCT FROM p_request_hash
       OR completion_row.replay_expires_at <= now_value
       OR completion_row.replayed_at IS NOT NULL THEN
      RAISE EXCEPTION USING ERRCODE = 'unique_violation',
        MESSAGE = 'Hosted bootstrap completion cannot be replayed';
    END IF;
    SELECT s.* INTO session_row
    FROM public.human_sessions AS s
    JOIN public.memberships AS m
      ON m.organization_id = s.organization_id
     AND m.id = s.membership_id
     AND m.member_id = s.member_id
    JOIN public.organizations AS o ON o.id = s.organization_id
    WHERE s.id = completion_row.session_id
      AND s.token_hash = p_session_token_hash
      AND s.csrf_token_hash = p_session_csrf_token_hash
      AND s.revoked_at IS NULL AND s.expires_at > now_value
      AND (s.idle_expires_at IS NULL OR s.idle_expires_at > now_value)
      AND m.status = 'active' AND m.role = s.role
      AND m.session_epoch = s.membership_session_epoch
      AND o.authority_epoch = s.organization_authority_epoch
    FOR SHARE OF s, m, o;
    IF NOT FOUND THEN
      RAISE EXCEPTION USING ERRCODE = 'invalid_authorization_specification',
        MESSAGE = 'Hosted bootstrap session replay is unavailable';
    END IF;
    UPDATE public.hosted_identity_bootstrap_completions
    SET replayed_at = now_value
    WHERE attempt_id = completion_row.attempt_id AND replayed_at IS NULL;
    IF NOT FOUND THEN
      RAISE EXCEPTION USING ERRCODE = 'serialization_failure',
        MESSAGE = 'Hosted bootstrap response recovery was already consumed';
    END IF;
    RETURN QUERY SELECT attempt_row.id, session_row.id, session_row.member_id,
      session_row.organization_id, session_row.membership_id, session_row.role,
      session_row.created_at, session_row.expires_at, true;
    RETURN;
  END IF;

  IF attempt_row.state <> 'webauthn_required' OR attempt_row.expires_at <= now_value
     OR attempt_row.member_id IS NULL OR attempt_row.organization_id IS NULL
     OR attempt_row.membership_id IS NULL THEN
    RAISE EXCEPTION USING ERRCODE = 'invalid_authorization_specification',
      MESSAGE = 'Hosted bootstrap WebAuthn is not currently required';
  END IF;
  session_expiry := now_value + interval '8 hours';
  session_idle_expiry := now_value + interval '30 minutes';

  SELECT c.* INTO challenge_row
  FROM public.hosted_identity_bootstrap_webauthn_challenges AS c
  WHERE c.id = p_challenge_id
    AND c.attempt_id = attempt_row.id
    AND c.member_id = attempt_row.member_id
    AND c.organization_id = attempt_row.organization_id
    AND c.challenge_hash = p_challenge_hash
    AND c.operation = 'bootstrap_registration'
  FOR UPDATE;
  IF NOT FOUND OR challenge_row.status <> 'consuming'
     OR challenge_row.expires_at <= now_value THEN
    RAISE EXCEPTION USING ERRCODE = 'invalid_authorization_specification',
      MESSAGE = 'Hosted bootstrap WebAuthn challenge is not consuming';
  END IF;

  -- Keep the composite membership target out of a multi-item INTO list:
  -- PL/pgSQL rejects a %ROWTYPE record combined with scalar targets. Lock the
  -- organization first, then the tenant-qualified membership in fixed order.
  SELECT o.authority_epoch INTO organization_epoch
  FROM public.organizations AS o
  WHERE o.id = attempt_row.organization_id
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE = 'invalid_authorization_specification',
      MESSAGE = 'Hosted bootstrap organization is absent';
  END IF;

  SELECT m.* INTO membership_row
  FROM public.memberships AS m
  WHERE m.organization_id = attempt_row.organization_id
    AND m.id = attempt_row.membership_id
    AND m.member_id = attempt_row.member_id
    AND m.status = 'active'
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE = 'invalid_authorization_specification',
      MESSAGE = 'Hosted bootstrap membership is not active';
  END IF;

  PERFORM pg_advisory_xact_lock(
    hashtextextended('agentpass:webauthn:credentials:' || attempt_row.member_id::text, 0)
  );
  INSERT INTO public.webauthn_credentials
    (id, member_id, public_key, sign_count, transports, label,
     backup_eligible, backup_state, created_at)
  VALUES
    (p_credential_id, attempt_row.member_id, p_public_key, p_sign_count,
     p_transports, p_label, p_backup_eligible, p_backup_state, now_value)
  ON CONFLICT (id) DO NOTHING;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE = 'unique_violation',
      MESSAGE = 'WebAuthn credential is already registered';
  END IF;

  PERFORM pg_advisory_xact_lock(
    hashtextextended('agentpass:human:sessions:' || attempt_row.member_id::text, 0)
  );
  WITH ranked AS (
    SELECT s.id, row_number() OVER (ORDER BY s.created_at DESC, s.id DESC) AS position
    FROM public.human_sessions AS s
    JOIN public.memberships AS m
      ON m.organization_id = s.organization_id
     AND m.id = s.membership_id
     AND m.member_id = s.member_id
    JOIN public.organizations AS o ON o.id = s.organization_id
    WHERE s.member_id = attempt_row.member_id
      AND s.revoked_at IS NULL AND s.expires_at > now_value
      AND (s.idle_expires_at IS NULL OR s.idle_expires_at > now_value)
      AND m.status = 'active' AND m.role = s.role
      AND m.session_epoch = s.membership_session_epoch
      AND o.authority_epoch = s.organization_authority_epoch
  ), excess AS (
    SELECT id FROM ranked WHERE position >= 5
  )
  UPDATE public.human_sessions AS target
  SET revoked_at = now_value,
      revoke_reason = COALESCE(target.revoke_reason, 'concurrent_session_limit')
  FROM excess
  WHERE target.id = excess.id AND target.revoked_at IS NULL;

  INSERT INTO public.human_sessions
    (id, member_id, organization_id, membership_id, role,
     organization_authority_epoch, membership_session_epoch,
     token_hash, csrf_token_hash, created_at, expires_at, last_seen_at,
     idle_expires_at, recent_auth_at, revoked_at, revoke_reason)
  VALUES
    (gen_random_uuid(), attempt_row.member_id, attempt_row.organization_id,
     attempt_row.membership_id, membership_row.role, organization_epoch,
     membership_row.session_epoch, p_session_token_hash,
     p_session_csrf_token_hash, now_value, session_expiry, now_value,
     session_idle_expiry, NULL, NULL, NULL)
  RETURNING * INTO session_row;

  UPDATE public.hosted_identity_bootstrap_webauthn_challenges
  SET status = 'consumed', consumed_at = now_value
  WHERE id = challenge_row.id AND status = 'consuming';
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE = 'serialization_failure',
      MESSAGE = 'Hosted bootstrap WebAuthn challenge changed during completion';
  END IF;

  UPDATE public.hosted_identity_bootstrap_attempts
  SET state = 'completed', completed_at = now_value, version = version + 1
  WHERE id = attempt_row.id AND state = 'webauthn_required';
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE = 'serialization_failure',
      MESSAGE = 'Hosted bootstrap attempt changed during completion';
  END IF;

  replay_expiry := LEAST(attempt_row.expires_at, now_value + interval '2 minutes');
  INSERT INTO public.hosted_identity_bootstrap_completions
    (attempt_id, challenge_id, member_id, organization_id, membership_id,
     credential_id, session_id, request_hash, committed_at, replay_expires_at)
  VALUES
    (attempt_row.id, challenge_row.id, attempt_row.member_id,
     attempt_row.organization_id, attempt_row.membership_id, p_credential_id,
     session_row.id, p_request_hash, now_value, replay_expiry);

  RETURN QUERY SELECT attempt_row.id, session_row.id, session_row.member_id,
    session_row.organization_id, session_row.membership_id, session_row.role,
    session_row.created_at, session_row.expires_at, false;
END;
$$;

REVOKE ALL PRIVILEGES ON TABLE public.hosted_identity_bootstrap_completions FROM PUBLIC;
REVOKE ALL PRIVILEGES ON FUNCTION public.agentpass_guard_hosted_identity_bootstrap_completion() FROM PUBLIC;
REVOKE ALL PRIVILEGES ON FUNCTION public.agentpass_hosted_identity_bootstrap_webauthn_replay_context(bytea, uuid, bytea) FROM PUBLIC;
REVOKE ALL PRIVILEGES ON FUNCTION public.agentpass_hosted_identity_bootstrap_webauthn_complete_v2(uuid, bytea, uuid, bytea, bytea, bytea, bytea, bigint, text[], text, boolean, boolean, bytea, bytea) FROM PUBLIC;

COMMIT;
