BEGIN;

-- 0054 closes the gap left by 0053: a platform session is now a two-token
-- state-changing capability (bearer + private CSRF namespace), a WebAuthn
-- challenge becomes a durable one-use proof, and promotion reservation can
-- consume that proof in the same transaction.  Raw challenges, JTIs,
-- bearers, CSRF values, assertions, and claim tokens never cross this SQL
-- boundary; only their fixed-width digests do.

CREATE FUNCTION public.agentpass_platform_bytea_equal(
  p_left bytea,
  p_right bytea
)
RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog, public
AS $$
DECLARE
  left_length integer := COALESCE(octet_length(p_left), -1);
  right_length integer := COALESCE(octet_length(p_right), -1);
  maximum_length integer;
  index_value integer;
  left_byte integer;
  right_byte integer;
  difference integer := 0;
BEGIN
  IF left_length < 0 OR right_length < 0 THEN
    RETURN false;
  END IF;
  maximum_length := GREATEST(left_length, right_length);
  IF maximum_length = 0 THEN
    RETURN left_length = right_length;
  END IF;

  -- Do not return on the first mismatch.  PostgreSQL cannot promise a
  -- hardware constant-time primitive, but this fixed-loop comparison avoids
  -- the usual short-circuit equality path for bearer and CSRF digests.
  FOR index_value IN 0..(maximum_length - 1) LOOP
    left_byte := CASE WHEN index_value < left_length THEN get_byte(p_left, index_value) ELSE 0 END;
    right_byte := CASE WHEN index_value < right_length THEN get_byte(p_right, index_value) ELSE 0 END;
    difference := difference | (left_byte # right_byte);
  END LOOP;
  RETURN left_length = right_length AND difference = 0;
END;
$$;

CREATE FUNCTION public.agentpass_platform_webauthn_id_array_valid(
  p_ids bytea[]
)
RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog, public
AS $$
DECLARE
  item bytea;
  previous bytea;
BEGIN
  IF p_ids IS NULL OR array_ndims(p_ids) <> 1
     OR cardinality(p_ids) NOT BETWEEN 1 AND 16
  THEN
    RETURN false;
  END IF;
  FOREACH item IN ARRAY p_ids LOOP
    IF item IS NULL OR octet_length(item) NOT BETWEEN 16 AND 1024
       OR (previous IS NOT NULL AND item <= previous)
    THEN
      RETURN false;
    END IF;
    previous := item;
  END LOOP;
  RETURN true;
END;
$$;

CREATE FUNCTION public.agentpass_platform_authorization_request_digest(
  p_operation text,
  p_organization_id uuid,
  p_promotion_id uuid,
  p_deployment_id text,
  p_environment text,
  p_candidate_id text,
  p_idempotency_key text
)
RETURNS bytea
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog, public
AS $$
  SELECT sha256(convert_to(
    '{"candidate_id":' || to_json(p_candidate_id)::text ||
    ',"deployment_id":' || to_json(p_deployment_id)::text ||
    ',"environment":' || to_json(p_environment)::text ||
    ',"idempotency_key":' || to_json(p_idempotency_key)::text ||
    ',"operation":' || to_json(p_operation)::text ||
    ',"organization_id":' || to_json(p_organization_id::text)::text ||
    ',"promotion_id":' || to_json(p_promotion_id::text)::text || '}',
    'UTF8'
  ));
$$;

-- 0053 sessions created before request binding cannot be safely upgraded:
-- invalidate them, retain only fixed-width migration digests, and then make
-- the new binding columns mandatory.  The UPDATE follows the 0053 trigger's
-- version-forward contract and never exposes or invents a usable capability.
ALTER TABLE public.platform_sessions
  ADD COLUMN csrf_token_hash bytea,
  ADD COLUMN request_digest_sha256 bytea,
  ADD COLUMN allowed_webauthn_credential_ids bytea[];

UPDATE public.platform_sessions AS session_row
SET csrf_token_hash = sha256(convert_to('agentpass:0054:csrf:' || session_row.session_id::text, 'UTF8')),
    request_digest_sha256 = sha256(convert_to('agentpass:0054:request:' || session_row.session_id::text, 'UTF8')),
    allowed_webauthn_credential_ids = ARRAY[credential.webauthn_credential_id],
    status = CASE WHEN session_row.status = 'active' THEN 'revoked' ELSE session_row.status END,
    revoked_at = CASE WHEN session_row.status = 'active' THEN clock_timestamp() ELSE session_row.revoked_at END,
    revoke_reason = CASE WHEN session_row.status = 'active' THEN 'request_binding_migration' ELSE session_row.revoke_reason END,
    version = session_row.version + 1
FROM public.platform_credentials AS credential
WHERE credential.credential_id = session_row.credential_id;

ALTER TABLE public.platform_sessions
  ALTER COLUMN csrf_token_hash SET NOT NULL,
  ALTER COLUMN request_digest_sha256 SET NOT NULL,
  ALTER COLUMN allowed_webauthn_credential_ids SET NOT NULL,
  ADD CONSTRAINT platform_sessions_csrf_token_hash_length
    CHECK (octet_length(csrf_token_hash) = 32),
  ADD CONSTRAINT platform_sessions_request_digest_length
    CHECK (octet_length(request_digest_sha256) = 32),
  ADD CONSTRAINT platform_sessions_allowed_webauthn_ids_valid
    CHECK (public.agentpass_platform_webauthn_id_array_valid(allowed_webauthn_credential_ids)),
  ADD CONSTRAINT platform_sessions_csrf_token_hash_unique UNIQUE (csrf_token_hash);

-- A session's selected internal credential must remain one of the public
-- WebAuthn IDs that were approved by the challenge.  This is a second trigger
-- because the 0053 forward-only trigger intentionally did not know these
-- N3c columns.
CREATE FUNCTION public.agentpass_guard_platform_session_request_binding()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
  IF TG_OP = 'UPDATE'
     AND (NEW.csrf_token_hash IS DISTINCT FROM OLD.csrf_token_hash
       OR NEW.request_digest_sha256 IS DISTINCT FROM OLD.request_digest_sha256
       OR NEW.allowed_webauthn_credential_ids IS DISTINCT FROM OLD.allowed_webauthn_credential_ids)
  THEN
    RAISE EXCEPTION USING ERRCODE = 'check_violation',
      CONSTRAINT = 'platform_sessions_request_binding_immutable',
      MESSAGE = 'platform session request binding is immutable';
  END IF;
  IF octet_length(NEW.csrf_token_hash) <> 32
     OR octet_length(NEW.request_digest_sha256) <> 32
     OR NOT public.agentpass_platform_webauthn_id_array_valid(NEW.allowed_webauthn_credential_ids)
  THEN
    RAISE EXCEPTION USING ERRCODE = 'check_violation',
      CONSTRAINT = 'platform_sessions_request_binding_valid',
      MESSAGE = 'platform session request binding is invalid';
  END IF;

  IF NOT EXISTS (
    SELECT 1
    FROM public.platform_credentials AS credential
    WHERE credential.credential_id = NEW.credential_id
      AND credential.webauthn_credential_id = ANY(NEW.allowed_webauthn_credential_ids)
  )
  THEN
    RAISE EXCEPTION USING ERRCODE = 'foreign_key_violation',
      CONSTRAINT = 'platform_sessions_allowed_credential_binding',
      MESSAGE = 'platform session credential is outside the allowed WebAuthn set';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER platform_sessions_request_binding
  BEFORE INSERT OR UPDATE ON public.platform_sessions
  FOR EACH ROW
  EXECUTE FUNCTION public.agentpass_guard_platform_session_request_binding();

CREATE TABLE public.platform_session_challenges (
  challenge_id uuid PRIMARY KEY,
  platform_session_id uuid NOT NULL UNIQUE,
  jti_hash bytea NOT NULL CHECK (octet_length(jti_hash) = 32),
  challenge_hash bytea NOT NULL CHECK (octet_length(challenge_hash) = 32),
  binding_hash bytea NOT NULL CHECK (octet_length(binding_hash) = 32),
  request_digest_sha256 bytea NOT NULL CHECK (octet_length(request_digest_sha256) = 32),
  allowed_webauthn_credential_ids bytea[] NOT NULL
    CHECK (public.agentpass_platform_webauthn_id_array_valid(allowed_webauthn_credential_ids)),
  principal_id uuid NOT NULL,
  member_id uuid NOT NULL REFERENCES public.members(id),
  organization_id uuid NOT NULL REFERENCES public.organizations(id),
  assignment_id uuid NOT NULL REFERENCES public.platform_operator_assignments(assignment_id),
  authority_generation bigint NOT NULL CHECK (authority_generation > 0),
  operation text NOT NULL CHECK (operation = capability),
  capability text NOT NULL CHECK (capability IN (
    'platform.assignment.manage',
    'platform.promotion.issue',
    'platform.promotion.replay',
    'platform.promotion.verify',
    'platform.promotion.reconcile'
  )),
  rp_id text NOT NULL CHECK (char_length(rp_id) BETWEEN 1 AND 253 AND rp_id !~ '[[:cntrl:]]'),
  origin text NOT NULL CHECK (char_length(origin) BETWEEN 1 AND 512 AND origin !~ '[[:cntrl:]]'),
  user_verification text NOT NULL CHECK (user_verification = 'required'),
  status text NOT NULL DEFAULT 'pending'
    CHECK (status IN ('pending', 'consuming', 'consumed', 'failed', 'expired')),
  version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
  issued_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  expires_at timestamptz NOT NULL,
  claimed_at timestamptz,
  completed_at timestamptz,
  failed_at timestamptz,
  failure_reason text CHECK (failure_reason IS NULL OR (
    char_length(failure_reason) BETWEEN 1 AND 128 AND failure_reason !~ '[[:cntrl:]]'
  )),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  FOREIGN KEY (principal_id, member_id)
    REFERENCES public.platform_principals(principal_id, member_id),
  CHECK (expires_at > issued_at),
  CHECK (created_at <= issued_at),
  CHECK (claimed_at IS NULL OR claimed_at >= issued_at),
  CHECK (completed_at IS NULL OR completed_at >= issued_at),
  CHECK (failed_at IS NULL OR failed_at >= issued_at),
  CHECK ((status IN ('pending', 'consuming') AND completed_at IS NULL AND failed_at IS NULL)
      OR (status = 'consumed' AND completed_at IS NOT NULL AND failed_at IS NULL)
      OR (status = 'failed' AND failed_at IS NOT NULL AND completed_at IS NULL)
      OR (status = 'expired' AND completed_at IS NULL AND failed_at IS NULL))
);

CREATE INDEX platform_session_challenges_lookup
  ON public.platform_session_challenges (challenge_id, status, expires_at);

CREATE FUNCTION public.agentpass_guard_platform_session_challenge()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION USING ERRCODE = 'restrict_violation',
      CONSTRAINT = 'platform_session_challenges_forward_only',
      MESSAGE = 'platform session challenges cannot be deleted';
  END IF;
  IF TG_OP = 'UPDATE' THEN
    IF NEW.challenge_id IS DISTINCT FROM OLD.challenge_id
       OR NEW.platform_session_id IS DISTINCT FROM OLD.platform_session_id
       OR NEW.jti_hash IS DISTINCT FROM OLD.jti_hash
       OR NEW.challenge_hash IS DISTINCT FROM OLD.challenge_hash
       OR NEW.binding_hash IS DISTINCT FROM OLD.binding_hash
       OR NEW.request_digest_sha256 IS DISTINCT FROM OLD.request_digest_sha256
       OR NEW.allowed_webauthn_credential_ids IS DISTINCT FROM OLD.allowed_webauthn_credential_ids
       OR NEW.principal_id IS DISTINCT FROM OLD.principal_id
       OR NEW.member_id IS DISTINCT FROM OLD.member_id
       OR NEW.organization_id IS DISTINCT FROM OLD.organization_id
       OR NEW.assignment_id IS DISTINCT FROM OLD.assignment_id
       OR NEW.authority_generation IS DISTINCT FROM OLD.authority_generation
       OR NEW.operation IS DISTINCT FROM OLD.operation
       OR NEW.capability IS DISTINCT FROM OLD.capability
       OR NEW.rp_id IS DISTINCT FROM OLD.rp_id
       OR NEW.origin IS DISTINCT FROM OLD.origin
       OR NEW.user_verification IS DISTINCT FROM OLD.user_verification
       OR NEW.issued_at IS DISTINCT FROM OLD.issued_at
       OR NEW.created_at IS DISTINCT FROM OLD.created_at
       OR NEW.version IS DISTINCT FROM OLD.version + 1
    THEN
      RAISE EXCEPTION USING ERRCODE = 'check_violation',
        CONSTRAINT = 'platform_session_challenges_immutable_binding',
        MESSAGE = 'platform session challenge binding is immutable';
    END IF;
    IF OLD.status = 'pending' AND NEW.status NOT IN ('pending', 'consuming', 'failed', 'expired')
       OR OLD.status = 'consuming' AND NEW.status NOT IN ('consuming', 'consumed', 'failed')
       OR OLD.status IN ('consumed', 'failed', 'expired') AND NEW.status <> OLD.status
    THEN
      RAISE EXCEPTION USING ERRCODE = 'check_violation',
        CONSTRAINT = 'platform_session_challenges_transition',
        MESSAGE = 'platform session challenge transition is invalid';
    END IF;
  END IF;
  IF NEW.issued_at > clock_timestamp()
     OR NEW.created_at > clock_timestamp()
     OR NEW.expires_at <= NEW.issued_at
  THEN
    RAISE EXCEPTION USING ERRCODE = 'check_violation',
      CONSTRAINT = 'platform_session_challenges_db_clock',
      MESSAGE = 'platform session challenge time is invalid';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER platform_session_challenges_forward_only
  BEFORE INSERT OR UPDATE OR DELETE ON public.platform_session_challenges
  FOR EACH ROW
  EXECUTE FUNCTION public.agentpass_guard_platform_session_challenge();

CREATE TABLE public.platform_authorization_proofs (
  proof_id uuid PRIMARY KEY,
  challenge_id uuid NOT NULL UNIQUE REFERENCES public.platform_session_challenges(challenge_id),
  platform_session_id uuid NOT NULL,
  jti_hash bytea NOT NULL CHECK (octet_length(jti_hash) = 32),
  binding_hash bytea NOT NULL CHECK (octet_length(binding_hash) = 32),
  request_digest_sha256 bytea NOT NULL CHECK (octet_length(request_digest_sha256) = 32),
  allowed_webauthn_credential_ids bytea[] NOT NULL
    CHECK (public.agentpass_platform_webauthn_id_array_valid(allowed_webauthn_credential_ids)),
  principal_id uuid NOT NULL,
  member_id uuid NOT NULL REFERENCES public.members(id),
  organization_id uuid NOT NULL REFERENCES public.organizations(id),
  assignment_id uuid NOT NULL REFERENCES public.platform_operator_assignments(assignment_id),
  authority_generation bigint NOT NULL CHECK (authority_generation > 0),
  operation text NOT NULL,
  capability text NOT NULL CHECK (operation = capability),
  platform_credential_id uuid NOT NULL REFERENCES public.platform_credentials(credential_id),
  webauthn_credential_id bytea NOT NULL REFERENCES public.webauthn_credentials(id),
  status text NOT NULL DEFAULT 'available' CHECK (status IN ('available', 'consumed')),
  version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz,
  consumed_promotion_id uuid,
  consumed_deployment_id text,
  consumed_environment text,
  consumed_candidate_id text,
  consumed_idempotency_key text,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  FOREIGN KEY (principal_id, member_id)
    REFERENCES public.platform_principals(principal_id, member_id),
  CHECK ((status = 'available'
      AND consumed_at IS NULL AND consumed_promotion_id IS NULL
      AND consumed_deployment_id IS NULL AND consumed_environment IS NULL
      AND consumed_candidate_id IS NULL AND consumed_idempotency_key IS NULL)
    OR (status = 'consumed'
      AND consumed_at IS NOT NULL AND consumed_promotion_id IS NOT NULL
      AND consumed_deployment_id IS NOT NULL AND consumed_environment IS NOT NULL
      AND consumed_candidate_id IS NOT NULL AND consumed_idempotency_key IS NOT NULL)),
  CHECK (consumed_environment IS NULL OR consumed_environment IN ('staging', 'production')),
  CHECK (consumed_at IS NULL OR consumed_at >= created_at)
);

CREATE INDEX platform_authorization_proofs_available
  ON public.platform_authorization_proofs (platform_session_id, status, expires_at, proof_id);

CREATE FUNCTION public.agentpass_guard_platform_authorization_proof()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION USING ERRCODE = 'restrict_violation',
      CONSTRAINT = 'platform_authorization_proofs_forward_only',
      MESSAGE = 'platform authorization proofs cannot be deleted';
  END IF;
  IF TG_OP = 'UPDATE' THEN
    IF NEW.proof_id IS DISTINCT FROM OLD.proof_id
       OR NEW.challenge_id IS DISTINCT FROM OLD.challenge_id
       OR NEW.platform_session_id IS DISTINCT FROM OLD.platform_session_id
       OR NEW.jti_hash IS DISTINCT FROM OLD.jti_hash
       OR NEW.binding_hash IS DISTINCT FROM OLD.binding_hash
       OR NEW.request_digest_sha256 IS DISTINCT FROM OLD.request_digest_sha256
       OR NEW.allowed_webauthn_credential_ids IS DISTINCT FROM OLD.allowed_webauthn_credential_ids
       OR NEW.principal_id IS DISTINCT FROM OLD.principal_id
       OR NEW.member_id IS DISTINCT FROM OLD.member_id
       OR NEW.organization_id IS DISTINCT FROM OLD.organization_id
       OR NEW.assignment_id IS DISTINCT FROM OLD.assignment_id
       OR NEW.authority_generation IS DISTINCT FROM OLD.authority_generation
       OR NEW.operation IS DISTINCT FROM OLD.operation
       OR NEW.capability IS DISTINCT FROM OLD.capability
       OR NEW.platform_credential_id IS DISTINCT FROM OLD.platform_credential_id
       OR NEW.webauthn_credential_id IS DISTINCT FROM OLD.webauthn_credential_id
       OR NEW.expires_at IS DISTINCT FROM OLD.expires_at
       OR NEW.created_at IS DISTINCT FROM OLD.created_at
       OR NEW.version IS DISTINCT FROM OLD.version + 1
    THEN
      RAISE EXCEPTION USING ERRCODE = 'check_violation',
        CONSTRAINT = 'platform_authorization_proofs_immutable_binding',
        MESSAGE = 'platform authorization proof binding is immutable';
    END IF;
    IF OLD.status <> 'available' OR NEW.status <> 'consumed' THEN
      RAISE EXCEPTION USING ERRCODE = 'check_violation',
        CONSTRAINT = 'platform_authorization_proofs_one_use',
        MESSAGE = 'platform authorization proof is one-use';
    END IF;
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER platform_authorization_proofs_forward_only
  BEFORE INSERT OR UPDATE OR DELETE ON public.platform_authorization_proofs
  FOR EACH ROW
  EXECUTE FUNCTION public.agentpass_guard_platform_authorization_proof();

-- The old 0053 routines accepted a caller-selected authority tuple and a
-- session UUID for revocation.  Remove those call shapes before publishing
-- the new hash-and-challenge-bound entry points.
DROP FUNCTION public.agentpass_platform_session_issue(uuid, bytea, uuid, uuid, uuid, uuid, uuid, text, text, integer, integer);
DROP FUNCTION public.agentpass_platform_session_touch(bytea, uuid, text, text);
DROP FUNCTION public.agentpass_platform_session_revoke(uuid, text);

CREATE FUNCTION public.agentpass_platform_session_challenge_json(
  p_challenge public.platform_session_challenges
)
RETURNS jsonb
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog, public
AS $$
  SELECT jsonb_build_object(
    'challenge_id', p_challenge.challenge_id,
    'platform_session_id', p_challenge.platform_session_id,
    'jti_hash', encode(p_challenge.jti_hash, 'hex'),
    'challenge_hash', encode(p_challenge.challenge_hash, 'hex'),
    'binding_hash', encode(p_challenge.binding_hash, 'hex'),
    'request_digest_sha256', encode(p_challenge.request_digest_sha256, 'hex'),
    'allowed_credential_ids', ARRAY(
      SELECT rtrim(translate(replace(encode(item, 'base64'), chr(10), ''), '+/', '-_'), '=')
      FROM unnest(p_challenge.allowed_webauthn_credential_ids) AS item
    ),
    'principal_id', p_challenge.principal_id,
    'member_id', p_challenge.member_id,
    'organization_id', p_challenge.organization_id,
    'assignment_id', p_challenge.assignment_id,
    'authority_generation', p_challenge.authority_generation,
    'operation', p_challenge.operation,
    'capability', p_challenge.capability,
    'rp_id', p_challenge.rp_id,
    'origin', p_challenge.origin,
    'user_verification', p_challenge.user_verification,
    'status', p_challenge.status,
    'version', p_challenge.version,
    'issued_at', p_challenge.issued_at,
    'expires_at', p_challenge.expires_at,
    'claimed_at', p_challenge.claimed_at,
    'completed_at', p_challenge.completed_at,
    'failed_at', p_challenge.failed_at,
    'failure_reason', p_challenge.failure_reason
  );
$$;

CREATE FUNCTION public.agentpass_platform_session_challenge_create(
  p_challenge_id uuid,
  p_platform_session_id uuid,
  p_jti_hash bytea,
  p_challenge_hash bytea,
  p_binding_hash bytea,
  p_request_digest_sha256 bytea,
  p_allowed_webauthn_credential_ids bytea[],
  p_principal_id uuid,
  p_member_id uuid,
  p_organization_id uuid,
  p_assignment_id uuid,
  p_authority_generation bigint,
  p_operation text,
  p_capability text,
  p_rp_id text,
  p_origin text,
  p_user_verification text,
  p_ttl_ms integer
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  principal_row record;
  assignment_row record;
  credential_count integer;
  challenge_row public.platform_session_challenges%ROWTYPE;
  now_value timestamptz := clock_timestamp();
BEGIN
  IF p_challenge_id IS NULL OR p_platform_session_id IS NULL
     OR p_jti_hash IS NULL OR octet_length(p_jti_hash) <> 32
     OR p_challenge_hash IS NULL OR octet_length(p_challenge_hash) <> 32
     OR p_binding_hash IS NULL OR octet_length(p_binding_hash) <> 32
     OR p_request_digest_sha256 IS NULL OR octet_length(p_request_digest_sha256) <> 32
     OR NOT public.agentpass_platform_webauthn_id_array_valid(p_allowed_webauthn_credential_ids)
     OR p_authority_generation < 1
     OR p_operation IS NULL OR p_capability IS NULL OR p_operation <> p_capability
     OR p_capability NOT IN (
       'platform.assignment.manage', 'platform.promotion.issue',
       'platform.promotion.replay', 'platform.promotion.verify',
       'platform.promotion.reconcile'
     )
     OR p_user_verification <> 'required'
     OR p_ttl_ms NOT BETWEEN 1000 AND 300000
  THEN
    RAISE EXCEPTION USING ERRCODE = 'invalid_parameter_value', MESSAGE = 'platform challenge input is invalid';
  END IF;

  -- Challenge creation lock order: principal -> assignment -> credential
  -- rows.  The same authority order is used by the issue and counter paths.
  SELECT * INTO principal_row
  FROM public.platform_principals
  WHERE principal_id = p_principal_id AND member_id = p_member_id
  FOR SHARE;
  IF NOT FOUND OR principal_row.status <> 'active'
     OR principal_row.authority_generation <> p_authority_generation
  THEN
    RAISE EXCEPTION USING ERRCODE = 'insufficient_privilege', MESSAGE = 'platform principal is unavailable';
  END IF;

  SELECT * INTO assignment_row
  FROM public.platform_operator_assignments
  WHERE assignment_id = p_assignment_id
    AND principal_id = p_principal_id AND member_id = p_member_id
    AND organization_id = p_organization_id
    AND operation = p_operation AND capability = p_capability
    AND status = 'active' AND issued_at <= now_value AND expires_at > now_value
  FOR SHARE;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE = 'insufficient_privilege', MESSAGE = 'platform assignment is unavailable';
  END IF;

  SELECT count(*) INTO credential_count
  FROM public.platform_credentials AS platform_credential
  JOIN public.webauthn_credentials AS webauthn
    ON webauthn.id = platform_credential.webauthn_credential_id
   AND webauthn.member_id = platform_credential.member_id
   AND webauthn.revoked_at IS NULL
  WHERE platform_credential.principal_id = p_principal_id
    AND platform_credential.member_id = p_member_id
    AND platform_credential.status = 'active'
    AND platform_credential.webauthn_credential_id = ANY(p_allowed_webauthn_credential_ids);
  IF credential_count <> cardinality(p_allowed_webauthn_credential_ids) THEN
    RAISE EXCEPTION USING ERRCODE = 'insufficient_privilege', MESSAGE = 'allowed WebAuthn credential set is unavailable';
  END IF;

  INSERT INTO public.platform_session_challenges (
    challenge_id, platform_session_id, jti_hash, challenge_hash, binding_hash,
    request_digest_sha256, allowed_webauthn_credential_ids, principal_id, member_id,
    organization_id, assignment_id, authority_generation, operation, capability,
    rp_id, origin, user_verification, issued_at, expires_at
  ) VALUES (
    p_challenge_id, p_platform_session_id, p_jti_hash, p_challenge_hash, p_binding_hash,
    p_request_digest_sha256, p_allowed_webauthn_credential_ids, p_principal_id, p_member_id,
    p_organization_id, p_assignment_id, p_authority_generation, p_operation, p_capability,
    p_rp_id, p_origin, p_user_verification, now_value,
    now_value + (p_ttl_ms::double precision * interval '1 millisecond')
  )
  RETURNING * INTO challenge_row;
  RETURN public.agentpass_platform_session_challenge_json(challenge_row);
EXCEPTION WHEN unique_violation THEN
  RAISE EXCEPTION USING ERRCODE = 'unique_violation', MESSAGE = 'platform challenge identity conflicts with durable state';
END;
$$;

CREATE FUNCTION public.agentpass_platform_session_challenge_find(
  p_challenge_id uuid
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  challenge_row public.platform_session_challenges%ROWTYPE;
BEGIN
  SELECT * INTO challenge_row FROM public.platform_session_challenges WHERE challenge_id = p_challenge_id;
  IF NOT FOUND THEN RETURN NULL; END IF;
  IF challenge_row.status IN ('pending', 'consuming') AND challenge_row.expires_at <= clock_timestamp() THEN
    RETURN jsonb_set(public.agentpass_platform_session_challenge_json(challenge_row), '{status}', '"expired"'::jsonb);
  END IF;
  RETURN public.agentpass_platform_session_challenge_json(challenge_row);
END;
$$;

CREATE FUNCTION public.agentpass_platform_session_challenge_claim(
  p_challenge_id uuid,
  p_jti_hash bytea,
  p_challenge_hash bytea,
  p_binding_hash bytea,
  p_request_digest_sha256 bytea
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  challenge_row public.platform_session_challenges%ROWTYPE;
  now_value timestamptz := clock_timestamp();
BEGIN
  SELECT * INTO challenge_row
  FROM public.platform_session_challenges
  WHERE challenge_id = p_challenge_id
  FOR UPDATE;
  IF NOT FOUND THEN RETURN jsonb_build_object('outcome', 'replayed'); END IF;
  IF NOT public.agentpass_platform_bytea_equal(challenge_row.jti_hash, p_jti_hash)
     OR NOT public.agentpass_platform_bytea_equal(challenge_row.challenge_hash, p_challenge_hash)
     OR NOT public.agentpass_platform_bytea_equal(challenge_row.binding_hash, p_binding_hash)
     OR NOT public.agentpass_platform_bytea_equal(challenge_row.request_digest_sha256, p_request_digest_sha256)
  THEN
    RETURN jsonb_build_object('outcome', 'mismatch');
  END IF;
  IF challenge_row.status = 'consuming' THEN RETURN jsonb_build_object('outcome', 'busy'); END IF;
  IF challenge_row.status = 'pending' AND challenge_row.expires_at <= now_value THEN
    UPDATE public.platform_session_challenges
    SET status = 'expired', version = version + 1
    WHERE challenge_id = p_challenge_id;
    RETURN jsonb_build_object('outcome', 'expired');
  END IF;
  IF challenge_row.status <> 'pending' THEN RETURN jsonb_build_object('outcome', 'replayed'); END IF;
  UPDATE public.platform_session_challenges
  SET status = 'consuming', claimed_at = now_value, version = version + 1
  WHERE challenge_id = p_challenge_id AND status = 'pending';
  SELECT * INTO challenge_row FROM public.platform_session_challenges WHERE challenge_id = p_challenge_id FOR UPDATE;
  RETURN jsonb_build_object('claimed', true, 'record', public.agentpass_platform_session_challenge_json(challenge_row));
END;
$$;

CREATE FUNCTION public.agentpass_platform_session_challenge_fail(
  p_challenge_id uuid,
  p_jti_hash bytea,
  p_challenge_hash bytea,
  p_binding_hash bytea,
  p_request_digest_sha256 bytea,
  p_failure_reason text DEFAULT 'verification_failed'
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  challenge_row public.platform_session_challenges%ROWTYPE;
  now_value timestamptz := clock_timestamp();
BEGIN
  SELECT * INTO challenge_row FROM public.platform_session_challenges WHERE challenge_id = p_challenge_id FOR UPDATE;
  IF NOT FOUND OR NOT public.agentpass_platform_bytea_equal(challenge_row.jti_hash, p_jti_hash)
     OR NOT public.agentpass_platform_bytea_equal(challenge_row.challenge_hash, p_challenge_hash)
     OR NOT public.agentpass_platform_bytea_equal(challenge_row.binding_hash, p_binding_hash)
     OR NOT public.agentpass_platform_bytea_equal(challenge_row.request_digest_sha256, p_request_digest_sha256)
  THEN
    RETURN jsonb_build_object('outcome', 'mismatch');
  END IF;
  IF challenge_row.status = 'failed' THEN
    RETURN jsonb_build_object('outcome', 'already-failed');
  END IF;
  IF challenge_row.status <> 'consuming' THEN RETURN jsonb_build_object('outcome', 'replayed'); END IF;
  UPDATE public.platform_session_challenges
  SET status = 'failed', failed_at = now_value, failure_reason = p_failure_reason, version = version + 1
  WHERE challenge_id = p_challenge_id;
  SELECT * INTO challenge_row FROM public.platform_session_challenges WHERE challenge_id = p_challenge_id;
  RETURN jsonb_build_object('outcome', 'failed', 'record', public.agentpass_platform_session_challenge_json(challenge_row));
END;
$$;

CREATE FUNCTION public.agentpass_platform_session_credential_find(
  p_challenge_id uuid,
  p_request_digest_sha256 bytea,
  p_webauthn_credential_id bytea
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  challenge_row public.platform_session_challenges%ROWTYPE;
  credential_row record;
BEGIN
  SELECT * INTO challenge_row FROM public.platform_session_challenges WHERE challenge_id = p_challenge_id;
  IF NOT FOUND OR challenge_row.status NOT IN ('consuming', 'consumed')
     OR NOT public.agentpass_platform_bytea_equal(challenge_row.request_digest_sha256, p_request_digest_sha256)
     OR NOT (p_webauthn_credential_id = ANY(challenge_row.allowed_webauthn_credential_ids))
  THEN RETURN NULL; END IF;

  SELECT platform_credential.credential_id AS platform_credential_id,
    platform_credential.webauthn_credential_id, platform_credential.principal_id,
    platform_credential.member_id, platform_credential.status,
    platform_credential.sign_count, platform_credential.sign_count_state,
    platform_credential.backup_eligible, platform_credential.backup_state,
    platform_credential.version, webauthn.public_key, webauthn.transports,
    webauthn.revoked_at
  INTO credential_row
  FROM public.platform_credentials AS platform_credential
  JOIN public.webauthn_credentials AS webauthn
    ON webauthn.id = platform_credential.webauthn_credential_id
   AND webauthn.member_id = platform_credential.member_id
  WHERE platform_credential.credential_id = ANY(
    ARRAY(SELECT credential.credential_id
      FROM public.platform_credentials AS credential
      WHERE credential.principal_id = challenge_row.principal_id
        AND credential.member_id = challenge_row.member_id
        AND credential.webauthn_credential_id = p_webauthn_credential_id)
  )
    AND platform_credential.webauthn_credential_id = p_webauthn_credential_id
    AND platform_credential.status = 'active'
    AND webauthn.revoked_at IS NULL;
  IF NOT FOUND THEN RETURN NULL; END IF;
  RETURN jsonb_build_object(
    'platform_credential_id', credential_row.platform_credential_id,
    'webauthn_credential_id', rtrim(translate(replace(encode(credential_row.webauthn_credential_id, 'base64'), chr(10), ''), '+/', '-_'), '='),
    'principal_id', credential_row.principal_id,
    'member_id', credential_row.member_id,
    'status', credential_row.status,
    'sign_count', credential_row.sign_count,
    'sign_count_state', credential_row.sign_count_state,
    'backup_eligible', credential_row.backup_eligible,
    'backup_state', credential_row.backup_state,
    'version', credential_row.version,
    'public_key', replace(encode(credential_row.public_key, 'base64'), chr(10), ''),
    'transports', credential_row.transports
  );
END;
$$;

CREATE FUNCTION public.agentpass_platform_credential_advance_verified(
  p_challenge_id uuid,
  p_request_digest_sha256 bytea,
  p_platform_credential_id uuid,
  p_webauthn_credential_id bytea,
  p_expected_version bigint,
  p_expected_sign_count bigint,
  p_sign_count bigint,
  p_backup_eligible boolean,
  p_backup_state boolean
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  challenge_row public.platform_session_challenges%ROWTYPE;
  credential_row public.platform_credentials%ROWTYPE;
  webauthn_row public.webauthn_credentials%ROWTYPE;
  now_value timestamptz := clock_timestamp();
  outcome text := 'accepted';
BEGIN
  SELECT * INTO challenge_row FROM public.platform_session_challenges WHERE challenge_id = p_challenge_id FOR SHARE;
  IF NOT FOUND OR challenge_row.status <> 'consuming'
     OR NOT public.agentpass_platform_bytea_equal(challenge_row.request_digest_sha256, p_request_digest_sha256)
     OR NOT (p_webauthn_credential_id = ANY(challenge_row.allowed_webauthn_credential_ids))
  THEN RETURN jsonb_build_object('outcome', 'denied'); END IF;

  -- Counter lock order: platform credential -> underlying WebAuthn row.
  SELECT * INTO credential_row FROM public.platform_credentials
  WHERE credential_id = p_platform_credential_id
    AND webauthn_credential_id = p_webauthn_credential_id
    AND principal_id = challenge_row.principal_id
    AND member_id = challenge_row.member_id
  FOR UPDATE;
  IF NOT FOUND OR credential_row.status <> 'active'
     OR credential_row.version <> p_expected_version
     OR credential_row.sign_count <> p_expected_sign_count
  THEN RETURN jsonb_build_object('outcome', 'conflict'); END IF;
  SELECT * INTO webauthn_row FROM public.webauthn_credentials
  WHERE id = p_webauthn_credential_id AND member_id = challenge_row.member_id
  FOR UPDATE;
  IF NOT FOUND OR webauthn_row.revoked_at IS NOT NULL
     OR webauthn_row.backup_eligible IS DISTINCT FROM p_backup_eligible
  THEN RETURN jsonb_build_object('outcome', 'denied'); END IF;

  IF (credential_row.sign_count > 0 AND p_sign_count = 0)
     OR (p_sign_count > 0 AND p_sign_count <= credential_row.sign_count)
  THEN
    outcome := 'clone-detected';
    UPDATE public.platform_credentials
    SET sign_count_state = 'clone-detected', clone_detected_at = now_value, version = version + 1
    WHERE credential_id = p_platform_credential_id AND version = p_expected_version;
  ELSE
    UPDATE public.webauthn_credentials
    SET sign_count = p_sign_count, backup_state = p_backup_state,
        last_used_at = now_value, version = version + 1
    WHERE id = p_webauthn_credential_id AND version = webauthn_row.version;
    IF NOT FOUND THEN RETURN jsonb_build_object('outcome', 'conflict'); END IF;
    UPDATE public.platform_credentials
    SET sign_count = p_sign_count,
        sign_count_state = CASE WHEN p_sign_count = 0 THEN 'zero-counter' ELSE 'monotonic' END,
        backup_state = p_backup_state, last_used_at = now_value, version = version + 1
    WHERE credential_id = p_platform_credential_id AND version = p_expected_version;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE = 'serialization_failure', MESSAGE = 'platform credential counter CAS lost'; END IF;
  END IF;
  SELECT * INTO credential_row FROM public.platform_credentials WHERE credential_id = p_platform_credential_id;
  RETURN jsonb_build_object(
    'outcome', outcome,
    'credential', jsonb_build_object(
      'platform_credential_id', credential_row.credential_id,
      'webauthn_credential_id', rtrim(translate(replace(encode(credential_row.webauthn_credential_id, 'base64'), chr(10), ''), '+/', '-_'), '='),
      'status', credential_row.status, 'sign_count', credential_row.sign_count,
      'sign_count_state', credential_row.sign_count_state,
      'backup_eligible', credential_row.backup_eligible, 'backup_state', credential_row.backup_state,
      'version', credential_row.version, 'clone_detected_at', credential_row.clone_detected_at
    )
  );
END;
$$;

CREATE FUNCTION public.agentpass_platform_session_issue(
  p_session_id uuid,
  p_session_material_hash bytea,
  p_csrf_token_hash bytea,
  p_challenge_id uuid,
  p_jti_hash bytea,
  p_request_digest_sha256 bytea,
  p_webauthn_credential_id bytea,
  p_ttl_seconds integer,
  p_idle_timeout_seconds integer
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  existing public.platform_sessions%ROWTYPE;
  challenge_row public.platform_session_challenges%ROWTYPE;
  principal_row record;
  assignment_row record;
  credential_row public.platform_credentials%ROWTYPE;
  session_row public.platform_sessions%ROWTYPE;
  now_value timestamptz := clock_timestamp();
  session_expires_at timestamptz;
  session_idle_expires_at timestamptz;
BEGIN
  IF p_session_id IS NULL OR p_session_material_hash IS NULL OR octet_length(p_session_material_hash) <> 32
     OR p_csrf_token_hash IS NULL OR octet_length(p_csrf_token_hash) <> 32
     OR p_jti_hash IS NULL OR octet_length(p_jti_hash) <> 32
     OR p_request_digest_sha256 IS NULL OR octet_length(p_request_digest_sha256) <> 32
     OR p_ttl_seconds NOT BETWEEN 1 AND 86400
     OR p_idle_timeout_seconds NOT BETWEEN 1 AND p_ttl_seconds
  THEN RAISE EXCEPTION USING ERRCODE = 'invalid_parameter_value', MESSAGE = 'platform session issue input is invalid'; END IF;

  -- Lost-response replay is resolved before mutable authority is consulted.
  SELECT * INTO existing FROM public.platform_sessions
  WHERE session_id = p_session_id OR session_material_hash = p_session_material_hash
  FOR UPDATE;
  IF FOUND THEN
    IF existing.session_id <> p_session_id
       OR NOT public.agentpass_platform_bytea_equal(existing.session_material_hash, p_session_material_hash)
       OR NOT public.agentpass_platform_bytea_equal(existing.csrf_token_hash, p_csrf_token_hash)
       OR existing.request_digest_sha256 IS DISTINCT FROM p_request_digest_sha256
    THEN RAISE EXCEPTION USING ERRCODE = 'unique_violation', MESSAGE = 'platform session issue replay does not match'; END IF;
    RETURN public.agentpass_platform_session_json(existing);
  END IF;

  -- Issue lock order: challenge -> principal -> assignment -> credential.
  SELECT * INTO challenge_row FROM public.platform_session_challenges
  WHERE challenge_id = p_challenge_id FOR SHARE;
  IF NOT FOUND OR challenge_row.status <> 'consuming'
     OR challenge_row.expires_at <= now_value
     OR NOT public.agentpass_platform_bytea_equal(challenge_row.jti_hash, p_jti_hash)
     OR NOT public.agentpass_platform_bytea_equal(challenge_row.request_digest_sha256, p_request_digest_sha256)
     OR NOT (p_webauthn_credential_id = ANY(challenge_row.allowed_webauthn_credential_ids))
  THEN RAISE EXCEPTION USING ERRCODE = 'serialization_failure', MESSAGE = 'platform challenge is not issuable'; END IF;

  SELECT * INTO principal_row FROM public.platform_principals
  WHERE principal_id = challenge_row.principal_id AND member_id = challenge_row.member_id
    AND status = 'active' AND authority_generation = challenge_row.authority_generation
  FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE = 'serialization_failure', MESSAGE = 'platform principal generation is stale'; END IF;
  SELECT * INTO assignment_row FROM public.platform_operator_assignments
  WHERE assignment_id = challenge_row.assignment_id
    AND principal_id = challenge_row.principal_id AND member_id = challenge_row.member_id
    AND organization_id = challenge_row.organization_id
    AND operation = challenge_row.operation AND capability = challenge_row.capability
    AND status = 'active' AND issued_at <= now_value AND expires_at > now_value
  FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE = 'serialization_failure', MESSAGE = 'platform assignment is stale'; END IF;
  SELECT * INTO credential_row FROM public.platform_credentials
  WHERE webauthn_credential_id = p_webauthn_credential_id
    AND principal_id = challenge_row.principal_id AND member_id = challenge_row.member_id
    AND status = 'active'
  FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE = 'insufficient_privilege', MESSAGE = 'platform credential is unavailable'; END IF;

  session_expires_at := LEAST(now_value + (p_ttl_seconds::double precision * interval '1 second'), assignment_row.expires_at);
  IF session_expires_at <= now_value THEN RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'platform assignment expires before session'; END IF;
  session_idle_expires_at := LEAST(session_expires_at, now_value + (p_idle_timeout_seconds::double precision * interval '1 second'));
  INSERT INTO public.platform_sessions (
    session_id, session_material_hash, csrf_token_hash, request_digest_sha256,
    allowed_webauthn_credential_ids, principal_id, member_id, organization_id,
    assignment_id, credential_id, operation, capability,
    principal_authority_generation, assignment_version, credential_version,
    idle_timeout_seconds, status, authenticated_at, last_seen_at, expires_at, idle_expires_at
  ) VALUES (
    p_session_id, p_session_material_hash, p_csrf_token_hash, p_request_digest_sha256,
    challenge_row.allowed_webauthn_credential_ids, challenge_row.principal_id, challenge_row.member_id,
    challenge_row.organization_id, challenge_row.assignment_id, credential_row.credential_id,
    challenge_row.operation, challenge_row.capability, principal_row.authority_generation,
    assignment_row.version, credential_row.version, p_idle_timeout_seconds, 'active', now_value,
    now_value, session_expires_at, session_idle_expires_at
  ) RETURNING * INTO session_row;
  RETURN public.agentpass_platform_session_json(session_row);
END;
$$;

CREATE FUNCTION public.agentpass_platform_session_touch(
  p_session_material_hash bytea,
  p_csrf_token_hash bytea,
  p_organization_id uuid,
  p_operation text,
  p_capability text
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  session_row public.platform_sessions%ROWTYPE;
  now_value timestamptz := clock_timestamp();
BEGIN
  SELECT * INTO session_row FROM public.platform_sessions
  WHERE session_material_hash = p_session_material_hash
    AND organization_id = p_organization_id AND operation = p_operation AND capability = p_capability
  FOR UPDATE;
  IF NOT FOUND OR NOT public.agentpass_platform_bytea_equal(session_row.session_material_hash, p_session_material_hash)
     OR NOT public.agentpass_platform_bytea_equal(session_row.csrf_token_hash, p_csrf_token_hash)
  THEN RETURN NULL; END IF;
  IF session_row.status <> 'active' THEN RETURN public.agentpass_platform_session_json(session_row); END IF;
  IF session_row.expires_at <= now_value OR session_row.idle_expires_at <= now_value THEN
    UPDATE public.platform_sessions SET status = 'expired', expired_at = now_value, version = version + 1 WHERE session_id = session_row.session_id;
    SELECT * INTO session_row FROM public.platform_sessions WHERE session_id = session_row.session_id;
    RETURN public.agentpass_platform_session_json(session_row);
  END IF;
  UPDATE public.platform_sessions
  SET last_seen_at = now_value,
      idle_expires_at = LEAST(expires_at, now_value + (idle_timeout_seconds::double precision * interval '1 second')),
      version = version + 1
  WHERE session_id = session_row.session_id;
  SELECT * INTO session_row FROM public.platform_sessions WHERE session_id = session_row.session_id;
  RETURN public.agentpass_platform_session_json(session_row);
END;
$$;

CREATE FUNCTION public.agentpass_platform_session_revoke(
  p_session_material_hash bytea,
  p_csrf_token_hash bytea,
  p_reason text
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  session_row public.platform_sessions%ROWTYPE;
  now_value timestamptz := clock_timestamp();
BEGIN
  IF p_reason IS NULL OR char_length(p_reason) NOT BETWEEN 1 AND 256 OR p_reason ~ '[[:cntrl:]]' THEN
    RAISE EXCEPTION USING ERRCODE = 'invalid_parameter_value', MESSAGE = 'platform session revoke reason is invalid';
  END IF;
  SELECT * INTO session_row FROM public.platform_sessions
  WHERE session_material_hash = p_session_material_hash
  FOR UPDATE;
  IF NOT FOUND OR NOT public.agentpass_platform_bytea_equal(session_row.session_material_hash, p_session_material_hash)
     OR NOT public.agentpass_platform_bytea_equal(session_row.csrf_token_hash, p_csrf_token_hash)
  THEN RETURN jsonb_build_object('outcome', 'absent'); END IF;
  IF session_row.status <> 'active' THEN
    RETURN jsonb_build_object('outcome', 'already-terminal', 'session', public.agentpass_platform_session_json(session_row));
  END IF;
  UPDATE public.platform_sessions
  SET status = 'revoked', revoked_at = now_value, revoke_reason = p_reason, version = version + 1
  WHERE session_id = session_row.session_id;
  SELECT * INTO session_row FROM public.platform_sessions WHERE session_id = session_row.session_id;
  RETURN jsonb_build_object('outcome', 'revoked', 'session', public.agentpass_platform_session_json(session_row));
END;
$$;

CREATE FUNCTION public.agentpass_platform_session_challenge_complete(
  p_challenge_id uuid,
  p_jti_hash bytea,
  p_challenge_hash bytea,
  p_binding_hash bytea,
  p_request_digest_sha256 bytea,
  p_webauthn_credential_id bytea
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  challenge_row public.platform_session_challenges%ROWTYPE;
  credential_row public.platform_credentials%ROWTYPE;
  proof_row public.platform_authorization_proofs%ROWTYPE;
  now_value timestamptz := clock_timestamp();
BEGIN
  SELECT * INTO challenge_row FROM public.platform_session_challenges WHERE challenge_id = p_challenge_id FOR UPDATE;
  IF NOT FOUND OR NOT public.agentpass_platform_bytea_equal(challenge_row.jti_hash, p_jti_hash)
     OR NOT public.agentpass_platform_bytea_equal(challenge_row.challenge_hash, p_challenge_hash)
     OR NOT public.agentpass_platform_bytea_equal(challenge_row.binding_hash, p_binding_hash)
     OR NOT public.agentpass_platform_bytea_equal(challenge_row.request_digest_sha256, p_request_digest_sha256)
     OR NOT (p_webauthn_credential_id = ANY(challenge_row.allowed_webauthn_credential_ids))
  THEN RETURN jsonb_build_object('outcome', 'mismatch'); END IF;
  IF challenge_row.status = 'consuming' AND challenge_row.expires_at <= now_value THEN
    UPDATE public.platform_session_challenges
    SET status = 'expired', version = version + 1
    WHERE challenge_id = p_challenge_id;
    RETURN jsonb_build_object('outcome', 'expired');
  END IF;
  IF challenge_row.status = 'consumed' THEN
    SELECT * INTO proof_row FROM public.platform_authorization_proofs WHERE proof_id = p_challenge_id;
    RETURN jsonb_build_object('outcome', 'already-completed', 'record', public.agentpass_platform_session_challenge_json(challenge_row));
  END IF;
  IF challenge_row.status <> 'consuming' THEN RETURN jsonb_build_object('outcome', 'replayed'); END IF;

  -- Completion lock order: challenge -> platform credential -> WebAuthn row.
  SELECT * INTO credential_row FROM public.platform_credentials
  WHERE webauthn_credential_id = p_webauthn_credential_id
    AND principal_id = challenge_row.principal_id AND member_id = challenge_row.member_id
    AND status = 'active'
  FOR UPDATE;
  IF NOT FOUND THEN RETURN jsonb_build_object('outcome', 'credential-unavailable'); END IF;
  UPDATE public.platform_session_challenges
  SET status = 'consumed', completed_at = now_value, version = version + 1
  WHERE challenge_id = p_challenge_id AND status = 'consuming';
  INSERT INTO public.platform_authorization_proofs (
    proof_id, challenge_id, platform_session_id, jti_hash, binding_hash,
    request_digest_sha256, allowed_webauthn_credential_ids, principal_id, member_id,
    organization_id, assignment_id, authority_generation, operation, capability,
    platform_credential_id, webauthn_credential_id, expires_at
  ) VALUES (
    p_challenge_id, challenge_row.challenge_id, challenge_row.platform_session_id,
    challenge_row.jti_hash, challenge_row.binding_hash, challenge_row.request_digest_sha256,
    challenge_row.allowed_webauthn_credential_ids, challenge_row.principal_id, challenge_row.member_id,
    challenge_row.organization_id, challenge_row.assignment_id, challenge_row.authority_generation,
    challenge_row.operation, challenge_row.capability, credential_row.credential_id,
    credential_row.webauthn_credential_id, challenge_row.expires_at
  )
  ON CONFLICT (proof_id) DO NOTHING;
  SELECT * INTO challenge_row FROM public.platform_session_challenges WHERE challenge_id = p_challenge_id;
  RETURN jsonb_build_object('outcome', 'completed', 'record', public.agentpass_platform_session_challenge_json(challenge_row));
END;
$$;

-- WebAuthn verification, challenge completion, proof creation, and session
-- issuance are one database statement.  The two lower-level routines above
-- are kept as SECURITY DEFINER implementation helpers but are never granted
-- to the application role; this wrapper is the sole online ceremony commit.
CREATE FUNCTION public.agentpass_platform_session_complete_and_issue(
  p_session_id uuid,
  p_session_material_hash bytea,
  p_csrf_token_hash bytea,
  p_challenge_id uuid,
  p_jti_hash bytea,
  p_challenge_hash bytea,
  p_binding_hash bytea,
  p_request_digest_sha256 bytea,
  p_webauthn_credential_id bytea,
  p_ttl_seconds integer,
  p_idle_timeout_seconds integer
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  session_result jsonb;
  completion_result jsonb;
BEGIN
  session_result := public.agentpass_platform_session_issue(
    p_session_id, p_session_material_hash, p_csrf_token_hash, p_challenge_id,
    p_jti_hash, p_request_digest_sha256, p_webauthn_credential_id,
    p_ttl_seconds, p_idle_timeout_seconds
  );
  completion_result := public.agentpass_platform_session_challenge_complete(
    p_challenge_id, p_jti_hash, p_challenge_hash, p_binding_hash,
    p_request_digest_sha256, p_webauthn_credential_id
  );
  IF completion_result->>'outcome' NOT IN ('completed', 'already-completed') THEN
    RAISE EXCEPTION USING ERRCODE = 'serialization_failure', MESSAGE = 'platform challenge completion failed';
  END IF;
  RETURN jsonb_build_object('session', session_result, 'challenge', completion_result);
END;
$$;

-- The only online promotion mutation boundary.  It deliberately consumes the
-- proof before calling the already-reviewed 0048 reservation function, but
-- the proof update and reservation are in this one transaction.  Lock order:
-- session -> proof -> principal -> assignment -> platform credential ->
-- WebAuthn credential -> 0048 promotion advisory/deployment/issuance locks.
-- Any error rolls back both the proof consumption and the reservation.
CREATE FUNCTION public.agentpass_consume_platform_authorization_and_reserve(
  p_session_material_hash bytea,
  p_csrf_token_hash bytea,
  p_proof_id uuid,
  p_jti_hash bytea,
  p_request_digest_sha256 bytea,
  p_promotion_id uuid,
  p_deployment_id text,
  p_environment text,
  p_candidate_id text,
  p_idempotency_key text,
  p_claim_token_digest bytea,
  p_claim_lease_ms integer,
  p_evidence_ttl_ms integer,
  p_key_id text DEFAULT NULL,
  p_key_version bigint DEFAULT NULL,
  p_lifecycle_version bigint DEFAULT NULL
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  session_row public.platform_sessions%ROWTYPE;
  proof_row public.platform_authorization_proofs%ROWTYPE;
  principal_row record;
  assignment_row record;
  credential_row record;
  webauthn_row record;
  issuance_row public.platform_promotion_issuances%ROWTYPE;
  promotion_result jsonb;
  expected_request_digest bytea;
  now_value timestamptz := clock_timestamp();
BEGIN
  IF p_session_material_hash IS NULL OR octet_length(p_session_material_hash) <> 32
     OR p_csrf_token_hash IS NULL OR octet_length(p_csrf_token_hash) <> 32
     OR p_jti_hash IS NULL OR octet_length(p_jti_hash) <> 32
     OR p_request_digest_sha256 IS NULL OR octet_length(p_request_digest_sha256) <> 32
     OR p_claim_token_digest IS NULL OR octet_length(p_claim_token_digest) <> 32
     OR p_promotion_id IS NULL OR p_environment NOT IN ('staging', 'production')
  THEN RAISE EXCEPTION USING ERRCODE = 'invalid_parameter_value', MESSAGE = 'platform authorization input is invalid'; END IF;

  -- State-changing authentication requires both namespaces.  The indexed
  -- lookup narrows to one row; both supplied digests are then compared by the
  -- fixed-loop helper before any mutable row is touched.
  SELECT * INTO session_row FROM public.platform_sessions
  WHERE session_material_hash = p_session_material_hash
  FOR UPDATE;
  IF NOT FOUND OR NOT public.agentpass_platform_bytea_equal(session_row.session_material_hash, p_session_material_hash)
     OR NOT public.agentpass_platform_bytea_equal(session_row.csrf_token_hash, p_csrf_token_hash)
  THEN RAISE EXCEPTION USING ERRCODE = 'insufficient_privilege', MESSAGE = 'platform session is unavailable'; END IF;
  expected_request_digest := public.agentpass_platform_authorization_request_digest(
    'platform.promotion.issue', session_row.organization_id, p_promotion_id,
    p_deployment_id, p_environment, p_candidate_id, p_idempotency_key
  );
  IF NOT public.agentpass_platform_bytea_equal(expected_request_digest, p_request_digest_sha256) THEN
    RAISE EXCEPTION USING ERRCODE = 'integrity_constraint_violation', MESSAGE = 'canonical promotion request digest is invalid';
  END IF;
  IF session_row.status <> 'active' OR session_row.expires_at <= now_value OR session_row.idle_expires_at <= now_value
     OR NOT public.agentpass_platform_bytea_equal(session_row.request_digest_sha256, p_request_digest_sha256)
  THEN RAISE EXCEPTION USING ERRCODE = 'serialization_failure', MESSAGE = 'platform session is stale'; END IF;

  SELECT * INTO proof_row FROM public.platform_authorization_proofs
  WHERE proof_id = p_proof_id FOR UPDATE;
  IF NOT FOUND OR NOT public.agentpass_platform_bytea_equal(proof_row.jti_hash, p_jti_hash)
     OR (proof_row.status = 'available' AND proof_row.expires_at <= now_value)
     OR proof_row.platform_session_id <> session_row.session_id
     OR proof_row.principal_id <> session_row.principal_id
     OR proof_row.member_id <> session_row.member_id
     OR proof_row.organization_id <> session_row.organization_id
     OR proof_row.assignment_id <> session_row.assignment_id
     OR proof_row.operation <> session_row.operation
     OR proof_row.capability <> session_row.capability
     OR proof_row.platform_credential_id <> session_row.credential_id
     OR proof_row.authority_generation <> session_row.principal_authority_generation
     OR proof_row.allowed_webauthn_credential_ids IS DISTINCT FROM session_row.allowed_webauthn_credential_ids
     OR proof_row.request_digest_sha256 IS DISTINCT FROM session_row.request_digest_sha256
     OR NOT public.agentpass_platform_bytea_equal(proof_row.request_digest_sha256, p_request_digest_sha256)
  THEN RAISE EXCEPTION USING ERRCODE = 'serialization_failure', MESSAGE = 'platform authorization proof is unavailable'; END IF;

  -- Safe exact retry is checked only after both session namespaces and the
  -- proof binding have been authenticated.  It returns durable promotion
  -- metadata only; no bearer, proof, CSRF, or claim token is ever replayed.
  IF proof_row.status = 'consumed' THEN
    IF proof_row.consumed_promotion_id <> p_promotion_id
       OR proof_row.consumed_deployment_id <> p_deployment_id
       OR proof_row.consumed_environment <> p_environment
       OR proof_row.consumed_candidate_id <> p_candidate_id
       OR proof_row.consumed_idempotency_key <> p_idempotency_key
    THEN RAISE EXCEPTION USING ERRCODE = 'serialization_failure', MESSAGE = 'platform proof replay binding is invalid'; END IF;
    SELECT * INTO issuance_row FROM public.platform_promotion_issuances
    WHERE promotion_id = p_promotion_id FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE = 'serialization_failure', MESSAGE = 'consumed proof has no promotion'; END IF;
    RETURN public.agentpass_platform_promotion_issuance_result(issuance_row, false);
  END IF;
  IF proof_row.status <> 'available' THEN
    RAISE EXCEPTION USING ERRCODE = 'serialization_failure', MESSAGE = 'platform authorization proof is not available';
  END IF;

  SELECT * INTO issuance_row
  FROM public.platform_promotion_issuances
  WHERE promotion_id = p_promotion_id
     OR (deployment_id = p_deployment_id AND environment = p_environment
       AND candidate_id = p_candidate_id AND idempotency_key = p_idempotency_key)
  FOR UPDATE;
  IF FOUND THEN
    IF issuance_row.promotion_id <> p_promotion_id OR issuance_row.deployment_id <> p_deployment_id
       OR issuance_row.environment <> p_environment OR issuance_row.candidate_id <> p_candidate_id
       OR issuance_row.idempotency_key <> p_idempotency_key
    THEN RAISE EXCEPTION USING ERRCODE = 'unique_violation', MESSAGE = 'promotion identity conflicts with durable state'; END IF;
    RAISE EXCEPTION USING ERRCODE = 'serialization_failure', MESSAGE = 'promotion already has a different authorization proof';
  END IF;

  SELECT * INTO principal_row FROM public.platform_principals
  WHERE principal_id = session_row.principal_id AND member_id = session_row.member_id
    AND status = 'active' AND authority_generation = session_row.principal_authority_generation
  FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE = 'serialization_failure', MESSAGE = 'platform principal generation is stale'; END IF;
  SELECT * INTO assignment_row FROM public.platform_operator_assignments
  WHERE assignment_id = session_row.assignment_id
    AND principal_id = session_row.principal_id AND member_id = session_row.member_id
    AND organization_id = session_row.organization_id
    AND operation = session_row.operation AND capability = session_row.capability
    AND status = 'active' AND version = session_row.assignment_version
    AND issued_at <= now_value AND expires_at > now_value
  FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE = 'serialization_failure', MESSAGE = 'platform assignment version is stale'; END IF;
  SELECT platform_credential.*, webauthn.revoked_at AS webauthn_revoked_at,
    webauthn.sign_count AS webauthn_sign_count
  INTO credential_row
  FROM public.platform_credentials AS platform_credential
  JOIN public.webauthn_credentials AS webauthn
    ON webauthn.id = platform_credential.webauthn_credential_id
   AND webauthn.member_id = platform_credential.member_id
  WHERE platform_credential.credential_id = proof_row.platform_credential_id
    AND platform_credential.webauthn_credential_id = proof_row.webauthn_credential_id
    AND platform_credential.status = 'active'
    AND platform_credential.version = session_row.credential_version
    AND webauthn.revoked_at IS NULL
  FOR UPDATE OF platform_credential, webauthn;
  IF NOT FOUND OR credential_row.sign_count_state = 'clone-detected' THEN
    RAISE EXCEPTION USING ERRCODE = 'insufficient_privilege', MESSAGE = 'platform credential is stale';
  END IF;

  promotion_result := public.agentpass_platform_promotion_issuance_reserve(
    p_promotion_id, p_deployment_id, p_environment, p_candidate_id, p_idempotency_key,
    p_claim_token_digest, p_claim_lease_ms, p_evidence_ttl_ms,
    p_key_id, p_key_version, p_lifecycle_version
  );
  IF promotion_result->>'state' = 'reserved' AND (promotion_result->>'claim_issued')::boolean IS TRUE THEN
    UPDATE public.platform_authorization_proofs
    SET status = 'consumed', consumed_at = clock_timestamp(), consumed_promotion_id = p_promotion_id,
        consumed_deployment_id = p_deployment_id, consumed_environment = p_environment,
        consumed_candidate_id = p_candidate_id, consumed_idempotency_key = p_idempotency_key,
        version = version + 1
    WHERE proof_id = p_proof_id AND status = 'available';
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE = 'serialization_failure', MESSAGE = 'platform proof consume lost its claim'; END IF;
  END IF;
  RETURN promotion_result;
END;
$$;

-- No table DML is granted to runtime roles.  The legacy direct reserve path
-- is revoked from the application; only this proof-consuming wrapper may
-- start an online platform promotion.
REVOKE ALL PRIVILEGES ON TABLE
  public.platform_session_challenges,
  public.platform_authorization_proofs
FROM PUBLIC, agentpass_app, agentpass_signer, agentpass_backup;

REVOKE ALL PRIVILEGES ON FUNCTION public.agentpass_platform_bytea_equal(bytea, bytea) FROM PUBLIC, agentpass_app, agentpass_signer, agentpass_backup;
REVOKE ALL PRIVILEGES ON FUNCTION public.agentpass_platform_webauthn_id_array_valid(bytea[]) FROM PUBLIC, agentpass_app, agentpass_signer, agentpass_backup;
REVOKE ALL PRIVILEGES ON FUNCTION public.agentpass_platform_authorization_request_digest(text, uuid, uuid, text, text, text, text) FROM PUBLIC, agentpass_app, agentpass_signer, agentpass_backup;
REVOKE ALL PRIVILEGES ON FUNCTION public.agentpass_guard_platform_session_request_binding() FROM PUBLIC, agentpass_app, agentpass_signer, agentpass_backup;
REVOKE ALL PRIVILEGES ON FUNCTION public.agentpass_guard_platform_session_challenge() FROM PUBLIC, agentpass_app, agentpass_signer, agentpass_backup;
REVOKE ALL PRIVILEGES ON FUNCTION public.agentpass_guard_platform_authorization_proof() FROM PUBLIC, agentpass_app, agentpass_signer, agentpass_backup;

REVOKE ALL PRIVILEGES ON FUNCTION public.agentpass_platform_session_issue(uuid, bytea, bytea, uuid, bytea, bytea, bytea, integer, integer) FROM PUBLIC, agentpass_app, agentpass_signer, agentpass_backup;
REVOKE ALL PRIVILEGES ON FUNCTION public.agentpass_platform_session_find_active(bytea, uuid, text, text) FROM PUBLIC, agentpass_signer, agentpass_backup;
REVOKE ALL PRIVILEGES ON FUNCTION public.agentpass_platform_session_touch(bytea, bytea, uuid, text, text) FROM PUBLIC, agentpass_signer, agentpass_backup;
REVOKE ALL PRIVILEGES ON FUNCTION public.agentpass_platform_session_revoke(bytea, bytea, text) FROM PUBLIC, agentpass_signer, agentpass_backup;
REVOKE ALL PRIVILEGES ON FUNCTION public.agentpass_platform_session_challenge_json(public.platform_session_challenges) FROM PUBLIC, agentpass_app, agentpass_signer, agentpass_backup;
REVOKE ALL PRIVILEGES ON FUNCTION public.agentpass_platform_session_challenge_complete(uuid, bytea, bytea, bytea, bytea, bytea) FROM PUBLIC, agentpass_app, agentpass_signer, agentpass_backup;
REVOKE ALL PRIVILEGES ON FUNCTION public.agentpass_platform_session_complete_and_issue(uuid, bytea, bytea, uuid, bytea, bytea, bytea, bytea, bytea, integer, integer) FROM PUBLIC, agentpass_signer, agentpass_backup;
REVOKE ALL PRIVILEGES ON FUNCTION public.agentpass_platform_promotion_issuance_reserve(uuid, text, text, text, text, bytea, integer, integer, text, bigint, bigint) FROM agentpass_app;

GRANT EXECUTE ON FUNCTION public.agentpass_platform_session_challenge_create(uuid, uuid, bytea, bytea, bytea, bytea, bytea[], uuid, uuid, uuid, uuid, bigint, text, text, text, text, text, integer) TO agentpass_app;
GRANT EXECUTE ON FUNCTION public.agentpass_platform_session_challenge_find(uuid) TO agentpass_app;
GRANT EXECUTE ON FUNCTION public.agentpass_platform_session_challenge_claim(uuid, bytea, bytea, bytea, bytea) TO agentpass_app;
GRANT EXECUTE ON FUNCTION public.agentpass_platform_session_challenge_fail(uuid, bytea, bytea, bytea, bytea, text) TO agentpass_app;
GRANT EXECUTE ON FUNCTION public.agentpass_platform_session_credential_find(uuid, bytea, bytea) TO agentpass_app;
GRANT EXECUTE ON FUNCTION public.agentpass_platform_credential_advance_verified(uuid, bytea, uuid, bytea, bigint, bigint, bigint, boolean, boolean) TO agentpass_app;
GRANT EXECUTE ON FUNCTION public.agentpass_platform_session_find_active(bytea, uuid, text, text) TO agentpass_app;
GRANT EXECUTE ON FUNCTION public.agentpass_platform_session_touch(bytea, bytea, uuid, text, text) TO agentpass_app;
GRANT EXECUTE ON FUNCTION public.agentpass_platform_session_revoke(bytea, bytea, text) TO agentpass_app;
GRANT EXECUTE ON FUNCTION public.agentpass_platform_session_complete_and_issue(uuid, bytea, bytea, uuid, bytea, bytea, bytea, bytea, bytea, integer, integer) TO agentpass_app;
GRANT EXECUTE ON FUNCTION public.agentpass_consume_platform_authorization_and_reserve(bytea, bytea, uuid, bytea, bytea, uuid, text, text, text, text, bytea, integer, integer, text, bigint, bigint) TO agentpass_app;

COMMIT;
