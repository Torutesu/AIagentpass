BEGIN;

-- 0054 fixed issued_at to a clock_timestamp() captured before the INSERT but
-- left created_at on a later clock_timestamp() default. The table invariant
-- requires created_at <= issued_at, so bind both fields to the same database
-- instant rather than weakening the invariant.
CREATE OR REPLACE FUNCTION public.agentpass_platform_session_challenge_create(
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
    rp_id, origin, user_verification, issued_at, expires_at, created_at
  ) VALUES (
    p_challenge_id, p_platform_session_id, p_jti_hash, p_challenge_hash, p_binding_hash,
    p_request_digest_sha256, p_allowed_webauthn_credential_ids, p_principal_id, p_member_id,
    p_organization_id, p_assignment_id, p_authority_generation, p_operation, p_capability,
    p_rp_id, p_origin, p_user_verification, now_value,
    now_value + (p_ttl_ms::double precision * interval '1 millisecond'), now_value
  )
  RETURNING * INTO challenge_row;
  RETURN public.agentpass_platform_session_challenge_json(challenge_row);
EXCEPTION WHEN unique_violation THEN
  RAISE EXCEPTION USING ERRCODE = 'unique_violation', MESSAGE = 'platform challenge identity conflicts with durable state';
END;
$$;

REVOKE ALL ON FUNCTION public.agentpass_platform_session_challenge_create(
  uuid, uuid, bytea, bytea, bytea, bytea, bytea[], uuid, uuid, uuid, uuid,
  bigint, text, text, text, text, text, integer
) FROM PUBLIC;

COMMENT ON FUNCTION public.agentpass_platform_session_challenge_create(
  uuid, uuid, bytea, bytea, bytea, bytea, bytea[], uuid, uuid, uuid, uuid,
  bigint, text, text, text, text, text, integer
) IS 'Creates a Platform WebAuthn challenge with issued_at and created_at bound to one database-clock instant.';

COMMIT;
