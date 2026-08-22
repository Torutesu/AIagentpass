BEGIN;

-- Human credential metadata mutations are authority operations.  Keep the
-- session/member/organization binding and the credential compare-and-swap in
-- the same SECURITY DEFINER primitive; idempotency records and authority
-- reduction publication remain transaction-level repository orchestration.
CREATE FUNCTION public.agentpass_human_update_credential_label(
  p_session_id uuid,
  p_member_id uuid,
  p_organization_id uuid,
  p_credential_id bytea,
  p_label text,
  p_expected_version bigint
)
RETURNS TABLE (
  id bytea,
  member_id uuid,
  label text,
  transports text[],
  backup_eligible boolean,
  backup_state boolean,
  created_at timestamptz,
  last_used_at timestamptz,
  revoked_at timestamptz,
  version bigint
)
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  now_value timestamptz;
  session_row public.human_sessions%ROWTYPE;
  updated public.webauthn_credentials%ROWTYPE;
BEGIN
  IF p_session_id IS NULL
     OR p_member_id IS NULL
     OR p_organization_id IS NULL
     OR p_credential_id IS NULL
     OR octet_length(p_credential_id) NOT BETWEEN 16 AND 1024
     OR p_label IS NULL
     OR char_length(p_label) NOT BETWEEN 1 AND 128
     OR p_label ~ '[[:cntrl:]]'
     OR p_expected_version IS NULL
     OR p_expected_version < 1 THEN
    RAISE EXCEPTION USING
      ERRCODE = 'invalid_parameter_value',
      MESSAGE = 'WebAuthn credential label update input is invalid';
  END IF;

  -- Registration, counter updates, clone quarantine, and credential
  -- revocation use this same member-scoped lock.  It makes the CAS and the
  -- last-usable-credential invariant serialize across application instances.
  PERFORM pg_advisory_xact_lock(
    hashtextextended('agentpass:webauthn:credentials:' || p_member_id::text, 0)
  );
  now_value := pg_catalog.clock_timestamp();

  -- Lock the authority rows before observing their binding.  The predicates
  -- are repeated by the mutation statement so the returned row is justified
  -- by the same authority boundary even if this primitive is reused later.
  SELECT s.*
    INTO session_row
  FROM public.human_sessions AS s
  JOIN public.memberships AS m
    ON m.organization_id = s.organization_id
   AND m.member_id = s.member_id
   AND m.id = s.membership_id
  JOIN public.organizations AS o
    ON o.id = s.organization_id
  WHERE s.id = p_session_id
    AND s.member_id = p_member_id
    AND s.organization_id = p_organization_id
    AND s.revoked_at IS NULL
    AND s.expires_at > now_value
    AND (s.idle_expires_at IS NULL OR s.idle_expires_at > now_value)
    AND m.status = 'active'
    AND m.role = s.role
    AND o.authority_epoch = s.organization_authority_epoch
    AND m.session_epoch = s.membership_session_epoch
  FOR UPDATE OF s, m, o;

  IF NOT FOUND THEN
    RETURN;
  END IF;

  UPDATE public.webauthn_credentials AS c
     SET label = p_label,
         version = c.version + 1
    FROM public.human_sessions AS s
    JOIN public.memberships AS m
      ON m.organization_id = s.organization_id
     AND m.member_id = s.member_id
     AND m.id = s.membership_id
    JOIN public.organizations AS o
      ON o.id = s.organization_id
   WHERE s.id = p_session_id
     AND s.member_id = p_member_id
     AND s.organization_id = p_organization_id
     AND s.revoked_at IS NULL
     AND s.expires_at > now_value
     AND (s.idle_expires_at IS NULL OR s.idle_expires_at > now_value)
     AND m.status = 'active'
     AND m.role = s.role
     AND o.authority_epoch = s.organization_authority_epoch
     AND m.session_epoch = s.membership_session_epoch
     AND c.id = p_credential_id
     AND c.member_id = s.member_id
     AND c.revoked_at IS NULL
     AND c.clone_detected_at IS NULL
     AND c.sign_count_state <> 'clone-detected'
     AND c.version = p_expected_version
  RETURNING c.* INTO updated;

  IF NOT FOUND THEN
    RETURN;
  END IF;

  RETURN QUERY
  SELECT updated.id,
         updated.member_id,
         updated.label,
         updated.transports,
         updated.backup_eligible,
         updated.backup_state,
         updated.created_at,
         updated.last_used_at,
         updated.revoked_at,
         updated.version;
END;
$$;

-- Revocation intentionally accepts a clone-quarantined credential: it is no
-- longer usable, and the last-active guard must count only usable credentials.
-- A previously revoked credential and a stale CAS never produce a mutation.
CREATE FUNCTION public.agentpass_human_revoke_credential(
  p_session_id uuid,
  p_member_id uuid,
  p_organization_id uuid,
  p_credential_id bytea,
  p_expected_version bigint,
  p_revoked_at timestamptz,
  p_revoke_reason text DEFAULT NULL
)
RETURNS TABLE (
  id bytea,
  member_id uuid,
  label text,
  transports text[],
  backup_eligible boolean,
  backup_state boolean,
  created_at timestamptz,
  last_used_at timestamptz,
  revoked_at timestamptz,
  version bigint
)
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  now_value timestamptz;
  session_row public.human_sessions%ROWTYPE;
  target public.webauthn_credentials%ROWTYPE;
  active_count bigint;
  updated public.webauthn_credentials%ROWTYPE;
BEGIN
  IF p_session_id IS NULL
     OR p_member_id IS NULL
     OR p_organization_id IS NULL
     OR p_credential_id IS NULL
     OR octet_length(p_credential_id) NOT BETWEEN 16 AND 1024
     OR p_expected_version IS NULL
     OR p_expected_version < 1
     OR p_revoked_at IS NULL
     OR (p_revoke_reason IS NOT NULL AND (
       char_length(p_revoke_reason) NOT BETWEEN 1 AND 128
       OR p_revoke_reason ~ '[[:cntrl:]]'
     )) THEN
    RAISE EXCEPTION USING
      ERRCODE = 'invalid_parameter_value',
      MESSAGE = 'WebAuthn credential revoke input is invalid';
  END IF;

  PERFORM pg_advisory_xact_lock(
    hashtextextended('agentpass:webauthn:credentials:' || p_member_id::text, 0)
  );
  now_value := pg_catalog.clock_timestamp();

  SELECT s.*
    INTO session_row
  FROM public.human_sessions AS s
  JOIN public.memberships AS m
    ON m.organization_id = s.organization_id
   AND m.member_id = s.member_id
   AND m.id = s.membership_id
  JOIN public.organizations AS o
    ON o.id = s.organization_id
  WHERE s.id = p_session_id
    AND s.member_id = p_member_id
    AND s.organization_id = p_organization_id
    AND s.revoked_at IS NULL
    AND s.expires_at > now_value
    AND (s.idle_expires_at IS NULL OR s.idle_expires_at > now_value)
    AND m.status = 'active'
    AND m.role = s.role
    AND o.authority_epoch = s.organization_authority_epoch
    AND m.session_epoch = s.membership_session_epoch
  FOR UPDATE OF s, m, o;

  IF NOT FOUND THEN
    RETURN;
  END IF;

  -- Lock and validate the target before counting.  The CAS is checked here
  -- and again by the UPDATE, preserving a clean NULL result for a missing,
  -- revoked, or stale-version credential.
  SELECT c.*
    INTO target
  FROM public.webauthn_credentials AS c
  JOIN public.human_sessions AS s
    ON s.member_id = c.member_id
  JOIN public.memberships AS m
    ON m.organization_id = s.organization_id
   AND m.member_id = s.member_id
   AND m.id = s.membership_id
  JOIN public.organizations AS o
    ON o.id = s.organization_id
  WHERE s.id = p_session_id
    AND s.member_id = p_member_id
    AND s.organization_id = p_organization_id
    AND s.revoked_at IS NULL
    AND s.expires_at > now_value
    AND (s.idle_expires_at IS NULL OR s.idle_expires_at > now_value)
    AND m.status = 'active'
    AND m.role = s.role
    AND o.authority_epoch = s.organization_authority_epoch
    AND m.session_epoch = s.membership_session_epoch
    AND c.id = p_credential_id
    AND c.member_id = s.member_id
    AND c.revoked_at IS NULL
    AND c.version = p_expected_version
  FOR UPDATE OF c;

  IF NOT FOUND THEN
    RETURN;
  END IF;

  IF target.clone_detected_at IS NULL
     AND target.sign_count_state <> 'clone-detected' THEN
    SELECT count(*)
      INTO active_count
    FROM public.webauthn_credentials AS c
    WHERE c.member_id = p_member_id
      AND c.revoked_at IS NULL
      AND c.clone_detected_at IS NULL
      AND c.sign_count_state <> 'clone-detected';

    IF active_count <= 1 THEN
      RAISE EXCEPTION USING
        ERRCODE = 'check_violation',
        CONSTRAINT = 'webauthn_credentials_last_active',
        MESSAGE = 'cannot revoke the last usable WebAuthn credential';
    END IF;
  END IF;

  UPDATE public.webauthn_credentials AS c
     SET revoked_at = p_revoked_at,
         revoke_reason = COALESCE(p_revoke_reason, c.revoke_reason),
         version = c.version + 1
    FROM public.human_sessions AS s
    JOIN public.memberships AS m
      ON m.organization_id = s.organization_id
     AND m.member_id = s.member_id
     AND m.id = s.membership_id
    JOIN public.organizations AS o
      ON o.id = s.organization_id
   WHERE s.id = p_session_id
     AND s.member_id = p_member_id
     AND s.organization_id = p_organization_id
     AND s.revoked_at IS NULL
     AND s.expires_at > now_value
     AND (s.idle_expires_at IS NULL OR s.idle_expires_at > now_value)
     AND m.status = 'active'
     AND m.role = s.role
     AND o.authority_epoch = s.organization_authority_epoch
     AND m.session_epoch = s.membership_session_epoch
     AND c.id = p_credential_id
     AND c.member_id = s.member_id
     AND c.revoked_at IS NULL
     AND c.version = p_expected_version
  RETURNING c.* INTO updated;

  IF NOT FOUND THEN
    RETURN;
  END IF;

  RETURN QUERY
  SELECT updated.id,
         updated.member_id,
         updated.label,
         updated.transports,
         updated.backup_eligible,
         updated.backup_state,
         updated.created_at,
         updated.last_used_at,
         updated.revoked_at,
         updated.version;
END;
$$;

ALTER FUNCTION public.agentpass_human_update_credential_label(
  uuid, uuid, uuid, bytea, text, bigint
) OWNER TO agentpass_migrator;
ALTER FUNCTION public.agentpass_human_revoke_credential(
  uuid, uuid, uuid, bytea, bigint, timestamptz, text
) OWNER TO agentpass_migrator;

REVOKE ALL PRIVILEGES ON FUNCTION public.agentpass_human_update_credential_label(
  uuid, uuid, uuid, bytea, text, bigint
) FROM PUBLIC, agentpass_signer, agentpass_backup, agentpass_maintenance;
REVOKE ALL PRIVILEGES ON FUNCTION public.agentpass_human_revoke_credential(
  uuid, uuid, uuid, bytea, bigint, timestamptz, text
) FROM PUBLIC, agentpass_signer, agentpass_backup, agentpass_maintenance;
GRANT EXECUTE ON FUNCTION public.agentpass_human_update_credential_label(
  uuid, uuid, uuid, bytea, text, bigint
) TO agentpass_app;
GRANT EXECUTE ON FUNCTION public.agentpass_human_revoke_credential(
  uuid, uuid, uuid, bytea, bigint, timestamptz, text
) TO agentpass_app;

COMMIT;
