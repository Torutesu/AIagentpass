BEGIN;

-- WebAuthn assertion state is an authority boundary.  Keep the complete
-- session, membership, organization, epoch, lifetime, and credential checks
-- in the same statement as the compare-and-swap mutation.
CREATE FUNCTION public.agentpass_human_update_credential_counter(
  p_session_id uuid,
  p_organization_id uuid,
  p_credential_id bytea,
  p_sign_count bigint,
  p_expected_sign_count bigint,
  p_backup_eligible boolean DEFAULT NULL,
  p_backup_state boolean DEFAULT NULL,
  p_expected_backup_eligible boolean DEFAULT NULL,
  p_expected_backup_state boolean DEFAULT NULL
)
RETURNS boolean
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  v_changed boolean;
BEGIN
  IF p_sign_count < 0 OR p_expected_sign_count < 0 THEN
    RAISE EXCEPTION USING ERRCODE = 'check_violation',
      CONSTRAINT = 'webauthn_credentials_sign_count_valid',
      MESSAGE = 'credential counter is invalid';
  END IF;
  IF p_backup_state IS TRUE AND p_backup_eligible IS NOT TRUE THEN
    RAISE EXCEPTION USING ERRCODE = 'check_violation',
      CONSTRAINT = 'webauthn_credentials_backup_state_valid',
      MESSAGE = 'backup_state requires backup_eligible';
  END IF;
  IF p_expected_backup_state IS TRUE AND p_expected_backup_eligible IS NOT TRUE THEN
    RAISE EXCEPTION USING ERRCODE = 'check_violation',
      CONSTRAINT = 'webauthn_credentials_backup_state_valid',
      MESSAGE = 'expected backup_state requires expected backup_eligible';
  END IF;
  IF NOT ((p_expected_sign_count = 0 AND p_sign_count = 0) OR p_sign_count > p_expected_sign_count) THEN
    RAISE EXCEPTION USING ERRCODE = 'check_violation',
      CONSTRAINT = 'webauthn_credentials_sign_count_monotonic',
      MESSAGE = 'credential counter must increase monotonically';
  END IF;

  WITH changed AS (
    UPDATE public.webauthn_credentials AS c
       SET sign_count = p_sign_count,
           sign_count_state = CASE WHEN p_sign_count = 0
                                    THEN 'zero-counter'
                                    ELSE 'monotonic'
                               END,
           backup_eligible = COALESCE(p_backup_eligible, c.backup_eligible),
           backup_state = COALESCE(p_backup_state, c.backup_state),
           last_used_at = pg_catalog.clock_timestamp()
      FROM public.human_sessions AS s
      JOIN public.memberships AS m
        ON m.organization_id = s.organization_id
       AND m.member_id = s.member_id
       AND m.id = s.membership_id
      JOIN public.organizations AS o
        ON o.id = s.organization_id
     WHERE s.id = p_session_id
       AND s.organization_id = p_organization_id
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
       AND s.revoked_at IS NULL
       AND s.expires_at > pg_catalog.clock_timestamp()
       AND (s.idle_expires_at IS NULL
            OR s.idle_expires_at > pg_catalog.clock_timestamp())
       AND m.status = 'active'
       AND m.role = s.role
       AND o.authority_epoch = s.organization_authority_epoch
       AND m.session_epoch = s.membership_session_epoch
     RETURNING c.id
  )
  SELECT pg_catalog.count(*) = 1 INTO v_changed FROM changed;

  RETURN v_changed;
END;
$$;

-- Clone quarantine must not authorize a credential with a session lookup and
-- mutate it in a later statement.  The session/member/organization binding
-- is therefore part of the one UPDATE statement below.  The clone-state
-- trigger from 0072 supplies the irreversible-transition invariant.
CREATE FUNCTION public.agentpass_human_quarantine_credential_clone(
  p_session_id uuid,
  p_organization_id uuid,
  p_credential_id bytea,
  p_expected_sign_count bigint,
  p_observed_sign_count bigint
)
RETURNS TABLE(id bytea, member_id uuid, clone_detected_at timestamptz)
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
  IF p_expected_sign_count < 0 OR p_observed_sign_count < 0 THEN
    RAISE EXCEPTION USING ERRCODE = 'check_violation',
      CONSTRAINT = 'webauthn_credentials_sign_count_valid',
      MESSAGE = 'credential counter is invalid';
  END IF;
  IF (p_expected_sign_count = 0 AND p_observed_sign_count = 0)
     OR p_observed_sign_count > p_expected_sign_count THEN
    RAISE EXCEPTION USING ERRCODE = 'check_violation',
      CONSTRAINT = 'webauthn_credentials_clone_evidence_valid',
      MESSAGE = 'clone counter evidence is invalid';
  END IF;

  RETURN QUERY
  WITH changed AS (
    UPDATE public.webauthn_credentials AS c
       SET sign_count_state = 'clone-detected',
           clone_detected_at = pg_catalog.clock_timestamp(),
           version = c.version + 1
      FROM public.human_sessions AS s
      JOIN public.memberships AS m
        ON m.organization_id = s.organization_id
       AND m.member_id = s.member_id
       AND m.id = s.membership_id
      JOIN public.organizations AS o
        ON o.id = s.organization_id
     WHERE s.id = p_session_id
       AND s.organization_id = p_organization_id
       AND c.id = p_credential_id
       AND c.member_id = s.member_id
       AND c.revoked_at IS NULL
       AND c.clone_detected_at IS NULL
       AND c.sign_count_state <> 'clone-detected'
       AND c.sign_count > 0
       AND c.sign_count >= p_expected_sign_count
       AND s.revoked_at IS NULL
       AND s.expires_at > pg_catalog.clock_timestamp()
       AND (s.idle_expires_at IS NULL
            OR s.idle_expires_at > pg_catalog.clock_timestamp())
       AND m.status = 'active'
       AND m.role = s.role
       AND o.authority_epoch = s.organization_authority_epoch
       AND m.session_epoch = s.membership_session_epoch
     RETURNING c.id, c.member_id, c.clone_detected_at
  )
  SELECT changed.id, changed.member_id, changed.clone_detected_at FROM changed;
END;
$$;

ALTER FUNCTION public.agentpass_human_update_credential_counter(
  uuid, uuid, bytea, bigint, bigint, boolean, boolean, boolean, boolean
) OWNER TO agentpass_migrator;
ALTER FUNCTION public.agentpass_human_quarantine_credential_clone(
  uuid, uuid, bytea, bigint, bigint
) OWNER TO agentpass_migrator;

REVOKE ALL PRIVILEGES ON FUNCTION public.agentpass_human_update_credential_counter(
  uuid, uuid, bytea, bigint, bigint, boolean, boolean, boolean, boolean
) FROM PUBLIC, agentpass_signer, agentpass_migrator, agentpass_backup, agentpass_maintenance;
REVOKE ALL PRIVILEGES ON FUNCTION public.agentpass_human_quarantine_credential_clone(
  uuid, uuid, bytea, bigint, bigint
) FROM PUBLIC, agentpass_signer, agentpass_migrator, agentpass_backup, agentpass_maintenance;

GRANT EXECUTE ON FUNCTION public.agentpass_human_update_credential_counter(
  uuid, uuid, bytea, bigint, bigint, boolean, boolean, boolean, boolean
) TO agentpass_app;
GRANT EXECUTE ON FUNCTION public.agentpass_human_quarantine_credential_clone(
  uuid, uuid, bytea, bigint, bigint
) TO agentpass_app;

COMMIT;
