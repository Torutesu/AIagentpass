BEGIN;

-- Owner-recovery credentials are still stored in the shared WebAuthn table,
-- but the recovery ceremony must not inherit the ordinary human-session
-- credential authority.  These entry points keep the recovery challenge,
-- request, restricted session, member, and organization bindings inside the
-- database boundary.  They deliberately do not start or finish a
-- transaction: registration and counter advancement are composed with the
-- surrounding challenge-consumption and recovery-state transaction.

CREATE FUNCTION public.agentpass_owner_recovery_register_credential(
  p_organization_id uuid,
  p_request_id uuid,
  p_recovery_session_id uuid,
  p_member_id uuid,
  p_challenge_id uuid,
  p_credential_id bytea,
  p_public_key bytea,
  p_sign_count bigint,
  p_transports text[],
  p_label text,
  p_backup_eligible boolean,
  p_backup_state boolean,
  p_completed_at timestamptz
)
RETURNS TABLE (
  id bytea,
  member_id uuid,
  public_key bytea,
  sign_count bigint,
  transports text[],
  label text,
  backup_eligible boolean,
  backup_state boolean,
  created_at timestamptz,
  last_used_at timestamptz,
  revoked_at timestamptz
)
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  now_value timestamptz;
  recovery_session public.owner_recovery_sessions%ROWTYPE;
  created public.webauthn_credentials%ROWTYPE;
BEGIN
  now_value := pg_catalog.clock_timestamp();
  IF p_organization_id IS NULL
     OR p_request_id IS NULL
     OR p_recovery_session_id IS NULL
     OR p_member_id IS NULL
     OR p_challenge_id IS NULL
     OR p_credential_id IS NULL
     OR octet_length(p_credential_id) NOT BETWEEN 16 AND 1024
     OR p_public_key IS NULL
     OR octet_length(p_public_key) NOT BETWEEN 32 AND 4096
     OR p_sign_count IS NULL
     OR p_sign_count < 0
     OR p_transports IS NULL
     OR NOT COALESCE(public.agentpass_valid_webauthn_transports(p_transports), false)
     OR p_label IS NULL
     OR char_length(p_label) NOT BETWEEN 1 AND 128
     OR p_label ~ '[[:cntrl:]]'
     OR p_backup_eligible IS NULL
     OR p_backup_state IS NULL
     OR p_completed_at IS NULL
     OR p_completed_at > now_value THEN
    RAISE EXCEPTION USING
      ERRCODE = 'invalid_parameter_value',
      MESSAGE = 'owner recovery credential registration input is invalid';
  END IF;

  IF p_backup_state IS TRUE AND p_backup_eligible IS NOT TRUE THEN
    RAISE EXCEPTION USING
      ERRCODE = 'check_violation',
      CONSTRAINT = 'webauthn_credentials_backup_state_valid',
      MESSAGE = 'backup_state requires backup_eligible';
  END IF;

  -- Registration, recovery activation, and ordinary credential revocation
  -- serialize on the same member-scoped lock.  Row locks then make the
  -- challenge/request/session observation stable for the rest of the caller's
  -- transaction.
  PERFORM pg_catalog.pg_advisory_xact_lock(
    pg_catalog.hashtextextended(
      'agentpass:webauthn:credentials:' || p_member_id::text, 0
    )
  );

  SELECT s.*
    INTO recovery_session
  FROM public.owner_recovery_sessions AS s
  JOIN public.owner_recovery_requests AS r
    ON r.organization_id = s.organization_id
   AND r.request_id = s.request_id
  JOIN public.owner_recovery_webauthn_challenges AS w
    ON w.organization_id = s.organization_id
   AND w.recovery_session_id = s.recovery_session_id
   AND w.request_id = s.request_id
   AND w.member_id = s.member_id
  WHERE s.organization_id = p_organization_id
    AND s.recovery_session_id = p_recovery_session_id
    AND s.request_id = p_request_id
    AND s.member_id = p_member_id
    AND s.stage = 'session_issued'
    AND s.expires_at > now_value
    AND s.expires_at > p_completed_at
    AND s.idle_expires_at > now_value
    AND s.idle_expires_at > p_completed_at
    AND r.state = 'session_issued'
    AND r.subject_member_id = p_member_id
    AND r.expires_at > now_value
    AND r.expires_at > p_completed_at
    AND w.challenge_id = p_challenge_id
    AND w.ceremony = 'registration'
    AND w.operation = 'human.recovery.credential.register'
    AND w.status = 'consuming'
    AND w.consume_started_at IS NOT NULL
    AND w.consumed_at IS NULL
    AND w.failed_at IS NULL
    AND w.expires_at > now_value
    AND w.expires_at > p_completed_at
    AND w.verified_credential_id IS NULL
    AND w.authorization_consumed_at IS NULL
  FOR UPDATE OF s, r, w;

  IF NOT FOUND THEN
    RETURN;
  END IF;

  INSERT INTO public.webauthn_credentials (
    id,
    member_id,
    public_key,
    sign_count,
    transports,
    label,
    backup_eligible,
    backup_state,
    sign_count_state
  ) VALUES (
    p_credential_id,
    recovery_session.member_id,
    p_public_key,
    p_sign_count,
    p_transports,
    p_label,
    p_backup_eligible,
    p_backup_state,
    CASE WHEN p_sign_count = 0 THEN 'zero-counter' ELSE 'monotonic' END
  )
  ON CONFLICT (id) DO NOTHING
  RETURNING * INTO created;

  -- An existing identifier is deliberately represented by an empty result;
  -- callers can map that to the stable recovery conflict without receiving
  -- another tenant's credential metadata.
  IF NOT FOUND THEN
    RETURN;
  END IF;

  RETURN QUERY
  SELECT created.id,
         created.member_id,
         created.public_key,
         created.sign_count,
         created.transports,
         created.label,
         created.backup_eligible,
         created.backup_state,
         created.created_at,
         created.last_used_at,
         created.revoked_at;
END;
$$;

CREATE FUNCTION public.agentpass_owner_recovery_find_credential(
  p_organization_id uuid,
  p_request_id uuid,
  p_recovery_session_id uuid,
  p_member_id uuid,
  p_credential_id bytea,
  p_session_digest bytea,
  p_now timestamptz
)
RETURNS TABLE (
  id bytea,
  member_id uuid,
  public_key bytea,
  sign_count bigint,
  transports text[],
  label text,
  backup_eligible boolean,
  backup_state boolean,
  created_at timestamptz,
  last_used_at timestamptz,
  revoked_at timestamptz
)
LANGUAGE sql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
  SELECT c.id,
         c.member_id,
         c.public_key,
         c.sign_count,
         c.transports,
         c.label,
         c.backup_eligible,
         c.backup_state,
         c.created_at,
         c.last_used_at,
         c.revoked_at
  FROM public.owner_recovery_sessions AS s
  JOIN public.owner_recovery_requests AS r
    ON r.organization_id = s.organization_id
   AND r.request_id = s.request_id
  JOIN public.webauthn_credentials AS c
    ON c.member_id = s.member_id
   AND c.id = s.credential_id
  WHERE s.organization_id = p_organization_id
    AND s.recovery_session_id = p_recovery_session_id
    AND s.request_id = p_request_id
    AND s.member_id = p_member_id
    AND s.stage = 'credential_enrolled'
    AND s.credential_id IS NOT NULL
    AND s.expires_at > pg_catalog.clock_timestamp()
    AND s.expires_at > p_now
    AND s.idle_expires_at > pg_catalog.clock_timestamp()
    AND s.idle_expires_at > p_now
    AND r.state = 'credential_enrolled'
    AND r.subject_member_id = p_member_id
    AND r.expires_at > pg_catalog.clock_timestamp()
    AND r.expires_at > p_now
    AND (p_credential_id IS NULL OR c.id = p_credential_id)
    AND (p_session_digest IS NULL OR s.session_digest = p_session_digest)
    AND p_now IS NOT NULL
    AND p_now <= pg_catalog.clock_timestamp()
    AND c.revoked_at IS NULL
    AND c.clone_detected_at IS NULL
    AND c.sign_count_state <> 'clone-detected'
  LIMIT 1;
$$;

CREATE FUNCTION public.agentpass_owner_recovery_update_credential_counter(
  p_organization_id uuid,
  p_request_id uuid,
  p_recovery_session_id uuid,
  p_member_id uuid,
  p_challenge_id uuid,
  p_credential_id bytea,
  p_sign_count bigint,
  p_expected_sign_count bigint,
  p_backup_eligible boolean,
  p_backup_state boolean,
  p_expected_backup_eligible boolean,
  p_expected_backup_state boolean,
  p_updated_at timestamptz
)
RETURNS TABLE (
  id bytea,
  member_id uuid,
  sign_count bigint,
  backup_eligible boolean,
  backup_state boolean,
  last_used_at timestamptz
)
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  now_value timestamptz;
BEGIN
  now_value := pg_catalog.clock_timestamp();
  IF p_organization_id IS NULL
     OR p_request_id IS NULL
     OR p_recovery_session_id IS NULL
     OR p_member_id IS NULL
     OR p_challenge_id IS NULL
     OR p_credential_id IS NULL
     OR octet_length(p_credential_id) NOT BETWEEN 16 AND 1024
     OR p_sign_count IS NULL
     OR p_sign_count < 0
     OR p_expected_sign_count IS NULL
     OR p_expected_sign_count < 0
     OR p_updated_at IS NULL
     OR p_updated_at > now_value THEN
    RAISE EXCEPTION USING
      ERRCODE = 'invalid_parameter_value',
      MESSAGE = 'owner recovery credential counter input is invalid';
  END IF;

  IF (p_backup_eligible IS NULL) <> (p_backup_state IS NULL)
     OR (p_expected_backup_eligible IS NULL) <> (p_expected_backup_state IS NULL)
     OR (p_backup_eligible IS NULL) <> (p_expected_backup_eligible IS NULL) THEN
    RAISE EXCEPTION USING
      ERRCODE = 'invalid_parameter_value',
      MESSAGE = 'owner recovery backup metadata is incomplete';
  END IF;

  IF p_backup_state IS TRUE AND p_backup_eligible IS NOT TRUE THEN
    RAISE EXCEPTION USING
      ERRCODE = 'check_violation',
      CONSTRAINT = 'webauthn_credentials_backup_state_valid',
      MESSAGE = 'backup_state requires backup_eligible';
  END IF;
  IF p_expected_backup_state IS TRUE AND p_expected_backup_eligible IS NOT TRUE THEN
    RAISE EXCEPTION USING
      ERRCODE = 'check_violation',
      CONSTRAINT = 'webauthn_credentials_backup_state_valid',
      MESSAGE = 'expected backup_state requires backup_eligible';
  END IF;
  IF NOT ((p_expected_sign_count = 0 AND p_sign_count = 0)
          OR p_sign_count > p_expected_sign_count) THEN
    RAISE EXCEPTION USING
      ERRCODE = 'check_violation',
      CONSTRAINT = 'webauthn_credentials_sign_count_monotonic',
      MESSAGE = 'credential counter must increase monotonically';
  END IF;

  -- The challenge remains consuming until the coordinator records its
  -- one-time completion.  This function intentionally only advances the
  -- credential; the caller can therefore roll both changes back together.
  RETURN QUERY
  UPDATE public.webauthn_credentials AS c
     SET sign_count = p_sign_count,
         sign_count_state = CASE WHEN p_sign_count = 0
                                  THEN 'zero-counter'
                                  ELSE 'monotonic'
                             END,
         backup_eligible = COALESCE(p_backup_eligible, c.backup_eligible),
         backup_state = COALESCE(p_backup_state, c.backup_state),
         last_used_at = now_value
    FROM public.owner_recovery_sessions AS s
    JOIN public.owner_recovery_requests AS r
      ON r.organization_id = s.organization_id
     AND r.request_id = s.request_id
    JOIN public.owner_recovery_webauthn_challenges AS w
      ON w.organization_id = s.organization_id
     AND w.recovery_session_id = s.recovery_session_id
     AND w.request_id = s.request_id
     AND w.member_id = s.member_id
   WHERE s.organization_id = p_organization_id
     AND s.recovery_session_id = p_recovery_session_id
     AND s.request_id = p_request_id
     AND s.member_id = p_member_id
     AND s.stage = 'credential_enrolled'
     AND s.credential_id = p_credential_id
     AND s.expires_at > now_value
     AND s.expires_at > p_updated_at
     AND s.idle_expires_at > now_value
     AND s.idle_expires_at > p_updated_at
     AND r.state = 'credential_enrolled'
     AND r.subject_member_id = p_member_id
     AND r.expires_at > now_value
     AND r.expires_at > p_updated_at
     AND w.challenge_id = p_challenge_id
     AND w.ceremony = 'authentication'
     AND w.operation = 'human.recovery.activate'
     AND w.status = 'consuming'
     AND w.consume_started_at IS NOT NULL
     AND w.consumed_at IS NULL
     AND w.failed_at IS NULL
     AND w.expires_at > now_value
     AND w.expires_at > p_updated_at
     AND w.authorization_consumed_at IS NULL
     AND (w.verified_credential_id IS NULL OR w.verified_credential_id = p_credential_id)
     AND c.id = p_credential_id
     AND c.member_id = s.member_id
     AND c.sign_count = p_expected_sign_count
     AND (p_expected_backup_eligible IS NULL
          OR c.backup_eligible = p_expected_backup_eligible)
     AND (p_expected_backup_state IS NULL
          OR c.backup_state = p_expected_backup_state)
     AND c.revoked_at IS NULL
     AND c.clone_detected_at IS NULL
     AND c.sign_count_state <> 'clone-detected'
   RETURNING c.id, c.member_id, c.sign_count, c.backup_eligible,
             c.backup_state, c.last_used_at;
END;
$$;

CREATE FUNCTION public.agentpass_owner_recovery_credential_exists(
  p_organization_id uuid,
  p_request_id uuid,
  p_recovery_session_id uuid,
  p_member_id uuid,
  p_credential_id bytea,
  p_now timestamptz
)
RETURNS TABLE(id bytea)
LANGUAGE sql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
  SELECT c.id
  FROM public.owner_recovery_sessions AS s
  JOIN public.owner_recovery_requests AS r
    ON r.organization_id = s.organization_id AND r.request_id = s.request_id
  JOIN public.webauthn_credentials AS c
    ON c.id = s.credential_id AND c.member_id = s.member_id
  WHERE s.organization_id = p_organization_id
    AND s.request_id = p_request_id
    AND s.recovery_session_id = p_recovery_session_id
    AND s.member_id = p_member_id
    AND s.stage IN ('session_issued', 'credential_enrolled', 'activated')
    AND s.credential_id = p_credential_id
    AND s.expires_at > p_now
    AND s.idle_expires_at > p_now
    AND r.subject_member_id = p_member_id
    AND r.state IN ('session_issued', 'credential_enrolled', 'activated')
    AND r.expires_at > p_now
    AND c.revoked_at IS NULL
    AND c.clone_detected_at IS NULL
    AND c.sign_count_state <> 'clone-detected'
  LIMIT 1;
$$;

ALTER FUNCTION public.agentpass_owner_recovery_register_credential(
  uuid, uuid, uuid, uuid, uuid, bytea, bytea, bigint, text[], text,
  boolean, boolean, timestamptz
) OWNER TO agentpass_migrator;
ALTER FUNCTION public.agentpass_owner_recovery_find_credential(
  uuid, uuid, uuid, uuid, bytea, bytea, timestamptz
) OWNER TO agentpass_migrator;
ALTER FUNCTION public.agentpass_owner_recovery_update_credential_counter(
  uuid, uuid, uuid, uuid, uuid, bytea, bigint, bigint, boolean, boolean,
  boolean, boolean, timestamptz
) OWNER TO agentpass_migrator;
ALTER FUNCTION public.agentpass_owner_recovery_credential_exists(
  uuid, uuid, uuid, uuid, bytea, timestamptz
) OWNER TO agentpass_migrator;

REVOKE ALL PRIVILEGES ON FUNCTION public.agentpass_owner_recovery_register_credential(
  uuid, uuid, uuid, uuid, uuid, bytea, bytea, bigint, text[], text,
  boolean, boolean, timestamptz
) FROM PUBLIC, agentpass_app, agentpass_signer, agentpass_backup,
     agentpass_maintenance;
REVOKE ALL PRIVILEGES ON FUNCTION public.agentpass_owner_recovery_find_credential(
  uuid, uuid, uuid, uuid, bytea, bytea, timestamptz
) FROM PUBLIC, agentpass_app, agentpass_signer, agentpass_backup,
     agentpass_maintenance;
REVOKE ALL PRIVILEGES ON FUNCTION public.agentpass_owner_recovery_update_credential_counter(
  uuid, uuid, uuid, uuid, uuid, bytea, bigint, bigint, boolean, boolean,
  boolean, boolean, timestamptz
) FROM PUBLIC, agentpass_app, agentpass_signer, agentpass_backup,
     agentpass_maintenance;

GRANT EXECUTE ON FUNCTION public.agentpass_owner_recovery_register_credential(
  uuid, uuid, uuid, uuid, uuid, bytea, bytea, bigint, text[], text,
  boolean, boolean, timestamptz
) TO agentpass_app;
GRANT EXECUTE ON FUNCTION public.agentpass_owner_recovery_find_credential(
  uuid, uuid, uuid, uuid, bytea, bytea, timestamptz
) TO agentpass_app;
GRANT EXECUTE ON FUNCTION public.agentpass_owner_recovery_update_credential_counter(
  uuid, uuid, uuid, uuid, uuid, bytea, bigint, bigint, boolean, boolean,
  boolean, boolean, timestamptz
) TO agentpass_app;
GRANT EXECUTE ON FUNCTION public.agentpass_owner_recovery_credential_exists(
  uuid, uuid, uuid, uuid, bytea, timestamptz
) TO agentpass_app;

-- Mutation privileges are function-only at this stage.  SELECT remains a
-- temporary compatibility privilege for the still-migrating duplicate/count
-- read paths; a later ACL cutover removes it after those paths use read
-- authority functions as well.
REVOKE INSERT, UPDATE, DELETE ON TABLE public.webauthn_credentials
  FROM PUBLIC, agentpass_app, agentpass_signer, agentpass_maintenance;
REVOKE INSERT, UPDATE, DELETE ON TABLE public.webauthn_credentials
  FROM agentpass_backup;
GRANT SELECT ON TABLE public.webauthn_credentials TO agentpass_backup;

COMMIT;
