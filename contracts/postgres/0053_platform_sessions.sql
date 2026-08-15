BEGIN;

-- 0053 adds the deployment-global platform authentication namespace.  These
-- tables are deliberately separate from human_sessions: an organization
-- membership session is not a platform-operator session, and a human bearer
-- token must never be accepted at a platform boundary.
--
-- Only SHA-256-sized digests cross this boundary.  The raw session bearer,
-- cookie, JTI, challenge, and assertion material are owned by the caller and
-- are never persisted here.  A WebAuthn credential id is a public identifier,
-- not bearer material; its public credential row remains the source of key and
-- member metadata.

CREATE TABLE platform_credentials (
  credential_id uuid PRIMARY KEY,
  principal_id uuid NOT NULL,
  member_id uuid NOT NULL REFERENCES members(id),
  webauthn_credential_id bytea NOT NULL REFERENCES webauthn_credentials(id),
  label text NOT NULL CHECK (
    char_length(label) BETWEEN 1 AND 128
    AND label !~ '[[:cntrl:]]'
  ),
  status text NOT NULL CHECK (status IN ('active', 'revoked')),
  sign_count bigint NOT NULL DEFAULT 0 CHECK (sign_count >= 0),
  sign_count_state text NOT NULL DEFAULT 'unknown' CHECK (
    sign_count_state IN ('unknown', 'zero-counter', 'monotonic', 'clone-detected')
  ),
  backup_eligible boolean NOT NULL,
  backup_state boolean NOT NULL,
  version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  last_used_at timestamptz,
  clone_detected_at timestamptz,
  revoked_at timestamptz,
  revoke_reason text CHECK (
    revoke_reason IS NULL
    OR (char_length(revoke_reason) BETWEEN 1 AND 256 AND revoke_reason !~ '[[:cntrl:]]')
  ),
  FOREIGN KEY (principal_id, member_id)
    REFERENCES platform_principals(principal_id, member_id),
  UNIQUE (webauthn_credential_id),
  CHECK (backup_state = false OR backup_eligible = true),
  CHECK (
    (sign_count_state <> 'clone-detected' AND clone_detected_at IS NULL)
    OR (sign_count_state = 'clone-detected' AND clone_detected_at IS NOT NULL)
  ),
  CHECK (status <> 'revoked' OR revoked_at IS NOT NULL),
  CHECK (status = 'revoked' OR revoked_at IS NULL),
  CHECK (revoked_at IS NULL OR revoked_at >= created_at),
  CHECK (clone_detected_at IS NULL OR clone_detected_at >= created_at),
  CHECK (last_used_at IS NULL OR last_used_at >= created_at)
);

CREATE INDEX platform_credentials_principal_active
  ON platform_credentials (principal_id, member_id, credential_id)
  WHERE status = 'active';

CREATE INDEX platform_credentials_webauthn_lookup
  ON platform_credentials (webauthn_credential_id, member_id, credential_id);

-- The database is the final guard for identity binding and the monotonic
-- lifecycle.  In particular, the application cannot move a credential to a
-- different principal by bypassing the reviewed entry points.
CREATE FUNCTION public.agentpass_guard_platform_credential()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
DECLARE
  principal_member_id uuid;
  principal_status text;
  webauthn_member_id uuid;
  webauthn_revoked_at timestamptz;
  webauthn_backup_eligible boolean;
  webauthn_backup_state boolean;
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION USING
      ERRCODE = 'restrict_violation',
      CONSTRAINT = 'platform_credentials_forward_only',
      MESSAGE = 'platform credentials cannot be deleted';
  END IF;

  IF TG_OP = 'UPDATE' THEN
    IF NEW.credential_id IS DISTINCT FROM OLD.credential_id
       OR NEW.principal_id IS DISTINCT FROM OLD.principal_id
       OR NEW.member_id IS DISTINCT FROM OLD.member_id
       OR NEW.webauthn_credential_id IS DISTINCT FROM OLD.webauthn_credential_id
       OR NEW.created_at IS DISTINCT FROM OLD.created_at
       OR NEW.backup_eligible IS DISTINCT FROM OLD.backup_eligible
       OR NEW.backup_state IS DISTINCT FROM OLD.backup_state
    THEN
      RAISE EXCEPTION USING
        ERRCODE = 'check_violation',
        CONSTRAINT = 'platform_credentials_immutable_binding',
        MESSAGE = 'platform credential binding is immutable';
    END IF;

    IF NEW.version IS DISTINCT FROM OLD.version + 1 THEN
      RAISE EXCEPTION USING
        ERRCODE = 'check_violation',
        CONSTRAINT = 'platform_credentials_version_forward_only',
        MESSAGE = 'platform credential version must advance by one';
    END IF;

    IF OLD.status = 'revoked' AND NEW.status <> 'revoked' THEN
      RAISE EXCEPTION USING
        ERRCODE = 'check_violation',
        CONSTRAINT = 'platform_credentials_revoked_terminal',
        MESSAGE = 'revoked platform credentials cannot be restored';
    END IF;

    IF NEW.sign_count < OLD.sign_count THEN
      RAISE EXCEPTION USING
        ERRCODE = 'check_violation',
        CONSTRAINT = 'platform_credentials_sign_count_forward_only',
        MESSAGE = 'WebAuthn sign count cannot decrease';
    END IF;

    IF OLD.sign_count_state = 'clone-detected'
       AND NEW.sign_count_state <> 'clone-detected'
    THEN
      RAISE EXCEPTION USING
        ERRCODE = 'check_violation',
        CONSTRAINT = 'platform_credentials_clone_detected_terminal',
        MESSAGE = 'clone-detected credentials cannot be restored';
    END IF;

    IF NEW.last_used_at IS NOT NULL
       AND NEW.last_used_at > clock_timestamp()
    THEN
      RAISE EXCEPTION USING
        ERRCODE = 'check_violation',
        CONSTRAINT = 'platform_credentials_db_clock',
        MESSAGE = 'credential use time cannot be in the future';
    END IF;
  ELSE
    IF NEW.created_at > clock_timestamp()
       OR NEW.updated_at > clock_timestamp()
    THEN
      RAISE EXCEPTION USING
        ERRCODE = 'check_violation',
        CONSTRAINT = 'platform_credentials_db_clock',
        MESSAGE = 'credential creation time cannot be in the future';
    END IF;
  END IF;

  SELECT principal.member_id, principal.status
    INTO principal_member_id, principal_status
  FROM platform_principals AS principal
  WHERE principal.principal_id = NEW.principal_id
  FOR SHARE;

  IF NOT FOUND
     OR principal_member_id IS DISTINCT FROM NEW.member_id
     OR principal_status = 'revoked'
  THEN
    RAISE EXCEPTION USING
      ERRCODE = 'foreign_key_violation',
      CONSTRAINT = 'platform_credentials_principal_binding',
      MESSAGE = 'platform credential principal binding is invalid';
  END IF;

  SELECT credential.member_id, credential.revoked_at,
    credential.backup_eligible, credential.backup_state
    INTO webauthn_member_id, webauthn_revoked_at,
      webauthn_backup_eligible, webauthn_backup_state
  FROM webauthn_credentials AS credential
  WHERE credential.id = NEW.webauthn_credential_id
  FOR SHARE;

  IF NOT FOUND
     OR webauthn_member_id IS DISTINCT FROM NEW.member_id
     OR webauthn_revoked_at IS NOT NULL
     OR webauthn_backup_eligible IS DISTINCT FROM NEW.backup_eligible
     OR webauthn_backup_state IS DISTINCT FROM NEW.backup_state
  THEN
    RAISE EXCEPTION USING
      ERRCODE = 'foreign_key_violation',
      CONSTRAINT = 'platform_credentials_webauthn_binding',
      MESSAGE = 'platform WebAuthn credential binding is invalid';
  END IF;

  NEW.updated_at := clock_timestamp();
  RETURN NEW;
END;
$$;

CREATE TRIGGER platform_credentials_forward_only
  BEFORE INSERT OR UPDATE OR DELETE ON platform_credentials
  FOR EACH ROW
  EXECUTE FUNCTION public.agentpass_guard_platform_credential();

CREATE TABLE platform_sessions (
  session_id uuid PRIMARY KEY,
  session_material_hash bytea NOT NULL UNIQUE CHECK (octet_length(session_material_hash) = 32),
  principal_id uuid NOT NULL,
  member_id uuid NOT NULL REFERENCES members(id),
  organization_id uuid NOT NULL REFERENCES organizations(id),
  assignment_id uuid NOT NULL REFERENCES platform_operator_assignments(assignment_id),
  credential_id uuid NOT NULL REFERENCES platform_credentials(credential_id),
  operation text NOT NULL CHECK (
    char_length(operation) BETWEEN 1 AND 128
    AND operation ~ '^[a-z][a-z0-9]*(?:[._:-][a-z0-9]+){0,15}$'
  ),
  capability text NOT NULL CHECK (
    capability IN (
      'platform.assignment.manage',
      'platform.promotion.issue',
      'platform.promotion.replay',
      'platform.promotion.verify',
      'platform.promotion.reconcile'
    )
  ),
  principal_authority_generation bigint NOT NULL CHECK (principal_authority_generation > 0),
  assignment_version bigint NOT NULL CHECK (assignment_version > 0),
  credential_version bigint NOT NULL CHECK (credential_version > 0),
  idle_timeout_seconds integer NOT NULL CHECK (idle_timeout_seconds BETWEEN 1 AND 86400),
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'expired', 'revoked')),
  version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  authenticated_at timestamptz NOT NULL,
  last_seen_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  idle_expires_at timestamptz NOT NULL,
  expired_at timestamptz,
  revoked_at timestamptz,
  revoke_reason text CHECK (
    revoke_reason IS NULL
    OR (char_length(revoke_reason) BETWEEN 1 AND 256 AND revoke_reason !~ '[[:cntrl:]]')
  ),
  FOREIGN KEY (principal_id, member_id)
    REFERENCES platform_principals(principal_id, member_id),
  CHECK (operation = capability),
  CHECK (expires_at > authenticated_at),
  CHECK (idle_expires_at > authenticated_at AND idle_expires_at <= expires_at),
  CHECK (created_at <= authenticated_at),
  CHECK (last_seen_at >= authenticated_at AND last_seen_at <= expires_at),
  CHECK (
    (status = 'active' AND expired_at IS NULL AND revoked_at IS NULL)
    OR (status = 'expired' AND expired_at IS NOT NULL AND revoked_at IS NULL)
    OR (status = 'revoked' AND revoked_at IS NOT NULL AND expired_at IS NULL)
  ),
  CHECK (expired_at IS NULL OR expired_at >= created_at),
  CHECK (revoked_at IS NULL OR revoked_at >= created_at)
);

CREATE INDEX platform_sessions_active_material_lookup
  ON platform_sessions (session_material_hash, organization_id, operation, capability, session_id)
  WHERE status = 'active';

CREATE INDEX platform_sessions_principal_active_lookup
  ON platform_sessions (principal_id, organization_id, operation, capability, expires_at, session_id)
  WHERE status = 'active';

CREATE INDEX platform_sessions_expiry_lookup
  ON platform_sessions (status, expires_at, idle_expires_at, session_id)
  WHERE status = 'active';

-- Session identity, authority observations, and credential binding are
-- issuance snapshots.  They are never rewritten by a refresh or revocation.
-- Only status, lifecycle timestamps, and the monotonic version can advance.
CREATE FUNCTION public.agentpass_guard_platform_session()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
DECLARE
  assignment_row record;
  credential_row record;
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION USING
      ERRCODE = 'restrict_violation',
      CONSTRAINT = 'platform_sessions_forward_only',
      MESSAGE = 'platform sessions cannot be deleted';
  END IF;

  IF TG_OP = 'UPDATE' THEN
    IF NEW.session_id IS DISTINCT FROM OLD.session_id
       OR NEW.session_material_hash IS DISTINCT FROM OLD.session_material_hash
       OR NEW.principal_id IS DISTINCT FROM OLD.principal_id
       OR NEW.member_id IS DISTINCT FROM OLD.member_id
       OR NEW.organization_id IS DISTINCT FROM OLD.organization_id
       OR NEW.assignment_id IS DISTINCT FROM OLD.assignment_id
       OR NEW.credential_id IS DISTINCT FROM OLD.credential_id
       OR NEW.operation IS DISTINCT FROM OLD.operation
       OR NEW.capability IS DISTINCT FROM OLD.capability
       OR NEW.principal_authority_generation IS DISTINCT FROM OLD.principal_authority_generation
       OR NEW.assignment_version IS DISTINCT FROM OLD.assignment_version
       OR NEW.credential_version IS DISTINCT FROM OLD.credential_version
       OR NEW.idle_timeout_seconds IS DISTINCT FROM OLD.idle_timeout_seconds
       OR NEW.created_at IS DISTINCT FROM OLD.created_at
       OR NEW.authenticated_at IS DISTINCT FROM OLD.authenticated_at
       OR NEW.expires_at IS DISTINCT FROM OLD.expires_at
    THEN
      RAISE EXCEPTION USING
        ERRCODE = 'check_violation',
        CONSTRAINT = 'platform_sessions_immutable_binding',
        MESSAGE = 'platform session binding is immutable';
    END IF;

    IF NEW.version IS DISTINCT FROM OLD.version + 1 THEN
      RAISE EXCEPTION USING
        ERRCODE = 'check_violation',
        CONSTRAINT = 'platform_sessions_version_forward_only',
        MESSAGE = 'platform session version must advance by one';
    END IF;

    IF OLD.status IN ('expired', 'revoked') AND NEW.status <> OLD.status THEN
      RAISE EXCEPTION USING
        ERRCODE = 'check_violation',
        CONSTRAINT = 'platform_sessions_terminal',
        MESSAGE = 'terminal platform sessions cannot change state';
    END IF;

    IF OLD.status = 'active' AND NEW.status NOT IN ('active', 'expired', 'revoked') THEN
      RAISE EXCEPTION USING
        ERRCODE = 'check_violation',
        CONSTRAINT = 'platform_sessions_transition',
        MESSAGE = 'active platform sessions have no backward transition';
    END IF;

    IF NEW.last_seen_at < OLD.last_seen_at
       OR NEW.idle_expires_at < OLD.idle_expires_at
    THEN
      RAISE EXCEPTION USING
        ERRCODE = 'check_violation',
        CONSTRAINT = 'platform_sessions_lifecycle_forward_only',
        MESSAGE = 'platform session activity cannot move backward';
    END IF;
  END IF;

  IF NEW.created_at > clock_timestamp()
     OR NEW.authenticated_at > clock_timestamp()
     OR NEW.last_seen_at > clock_timestamp()
     OR (NEW.expired_at IS NOT NULL AND NEW.expired_at > clock_timestamp())
     OR (NEW.revoked_at IS NOT NULL AND NEW.revoked_at > clock_timestamp())
  THEN
    RAISE EXCEPTION USING
      ERRCODE = 'check_violation',
      CONSTRAINT = 'platform_sessions_db_clock',
      MESSAGE = 'platform session time cannot be in the future';
  END IF;

  -- Snapshot bindings are checked only on insert. A later authority change
  -- invalidates lookup but must not prevent stale rows from being revoked.
  IF TG_OP = 'INSERT' THEN
    SELECT assignment.* INTO assignment_row
    FROM platform_operator_assignments AS assignment
    WHERE assignment.assignment_id = NEW.assignment_id
    FOR SHARE;
    IF NOT FOUND
       OR assignment_row.principal_id IS DISTINCT FROM NEW.principal_id
       OR assignment_row.member_id IS DISTINCT FROM NEW.member_id
       OR assignment_row.organization_id IS DISTINCT FROM NEW.organization_id
       OR assignment_row.operation IS DISTINCT FROM NEW.operation
       OR assignment_row.capability IS DISTINCT FROM NEW.capability
       OR assignment_row.version IS DISTINCT FROM NEW.assignment_version
    THEN
      RAISE EXCEPTION USING ERRCODE = 'foreign_key_violation',
        CONSTRAINT = 'platform_sessions_assignment_binding',
        MESSAGE = 'platform session assignment binding is invalid';
    END IF;

    SELECT credential.* INTO credential_row
    FROM platform_credentials AS credential
    WHERE credential.credential_id = NEW.credential_id
    FOR SHARE;
    IF NOT FOUND
       OR credential_row.principal_id IS DISTINCT FROM NEW.principal_id
       OR credential_row.member_id IS DISTINCT FROM NEW.member_id
       OR credential_row.version IS DISTINCT FROM NEW.credential_version
    THEN
      RAISE EXCEPTION USING ERRCODE = 'foreign_key_violation',
        CONSTRAINT = 'platform_sessions_credential_binding',
        MESSAGE = 'platform session credential binding is invalid';
    END IF;
  END IF;

  RETURN NEW;
END;
$$;

CREATE TRIGGER platform_sessions_forward_only
  BEFORE INSERT OR UPDATE OR DELETE ON platform_sessions
  FOR EACH ROW
  EXECUTE FUNCTION public.agentpass_guard_platform_session();

CREATE FUNCTION public.agentpass_platform_credential_json(
  p_credential platform_credentials
)
RETURNS jsonb
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog, public
AS $$
  SELECT jsonb_build_object(
    'credential_id', p_credential.credential_id,
    'principal_id', p_credential.principal_id,
    'member_id', p_credential.member_id,
    'status', p_credential.status,
    'sign_count', p_credential.sign_count,
    'sign_count_state', p_credential.sign_count_state,
    'backup_eligible', p_credential.backup_eligible,
    'backup_state', p_credential.backup_state,
    'version', p_credential.version,
    'created_at', p_credential.created_at,
    'last_used_at', p_credential.last_used_at,
    'clone_detected_at', p_credential.clone_detected_at,
    'revoked_at', p_credential.revoked_at,
    'revoke_reason', p_credential.revoke_reason
  )
$$;

CREATE FUNCTION public.agentpass_platform_session_json(
  p_session platform_sessions
)
RETURNS jsonb
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog, public
AS $$
  SELECT jsonb_build_object(
    'session_id', p_session.session_id,
    'principal_id', p_session.principal_id,
    'member_id', p_session.member_id,
    'organization_id', p_session.organization_id,
    'assignment_id', p_session.assignment_id,
    'credential_id', p_session.credential_id,
    'operation', p_session.operation,
    'capability', p_session.capability,
    'principal_authority_generation', p_session.principal_authority_generation,
    'assignment_version', p_session.assignment_version,
    'credential_version', p_session.credential_version,
    'status', p_session.status,
    'version', p_session.version,
    'created_at', p_session.created_at,
    'authenticated_at', p_session.authenticated_at,
    'last_seen_at', p_session.last_seen_at,
    'expires_at', p_session.expires_at,
    'idle_expires_at', p_session.idle_expires_at,
    'expired_at', p_session.expired_at,
    'revoked_at', p_session.revoked_at,
    'revoke_reason', p_session.revoke_reason
  )
$$;

-- Provisioning is explicit and idempotent only for the exact same binding.
-- It never creates a principal, assignment, member, or WebAuthn credential.
CREATE FUNCTION public.agentpass_platform_credential_provision(
  p_credential_id uuid,
  p_principal_id uuid,
  p_member_id uuid,
  p_webauthn_credential_id bytea,
  p_label text
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  existing platform_credentials%ROWTYPE;
  principal_row record;
  webauthn_row record;
  created platform_credentials%ROWTYPE;
BEGIN
  IF p_webauthn_credential_id IS NULL
     OR octet_length(p_webauthn_credential_id) NOT BETWEEN 16 AND 1024
  THEN
    RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'invalid WebAuthn credential id';
  END IF;

  SELECT * INTO existing
  FROM platform_credentials
  WHERE credential_id = p_credential_id
     OR webauthn_credential_id = p_webauthn_credential_id
  FOR UPDATE;
  IF FOUND THEN
    IF existing.credential_id <> p_credential_id
       OR existing.principal_id <> p_principal_id
       OR existing.member_id <> p_member_id
       OR existing.webauthn_credential_id <> p_webauthn_credential_id
       OR existing.label <> p_label
    THEN
      RAISE EXCEPTION USING
        ERRCODE = 'unique_violation',
        CONSTRAINT = 'platform_credentials_binding_replay',
        MESSAGE = 'platform credential provision replay does not match';
    END IF;
    RETURN public.agentpass_platform_credential_json(existing);
  END IF;

  SELECT principal.* INTO principal_row
  FROM platform_principals AS principal
  WHERE principal.principal_id = p_principal_id
    AND principal.member_id = p_member_id
  FOR SHARE;
  IF NOT FOUND OR principal_row.status <> 'active' THEN
    RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'platform principal is not active';
  END IF;

  SELECT credential.* INTO webauthn_row
  FROM webauthn_credentials AS credential
  WHERE credential.id = p_webauthn_credential_id
    AND credential.member_id = p_member_id
  FOR SHARE;
  IF NOT FOUND OR webauthn_row.revoked_at IS NOT NULL THEN
    RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'WebAuthn credential is not active for member';
  END IF;

  INSERT INTO platform_credentials (
    credential_id, principal_id, member_id, webauthn_credential_id, label,
    status, backup_eligible, backup_state
  ) VALUES (
    p_credential_id, p_principal_id, p_member_id, p_webauthn_credential_id, p_label,
    'active', webauthn_row.backup_eligible, webauthn_row.backup_state
  )
  RETURNING * INTO created;

  RETURN public.agentpass_platform_credential_json(created);
END;
$$;

-- This routine is deliberately a narrow counter state machine.  WebAuthn
-- signature verification happens in the ceremony adapter; this function
-- persists only its already-verified counter observation.  A non-monotonic
-- non-zero observation is recorded as clone-detected and returns a denial
-- outcome instead of silently accepting the assertion.
CREATE FUNCTION public.agentpass_platform_credential_advance_sign_count(
  p_credential_id uuid,
  p_sign_count bigint
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  credential_row platform_credentials%ROWTYPE;
  now_value timestamptz := clock_timestamp();
  outcome text := 'accepted';
BEGIN
  IF p_sign_count IS NULL OR p_sign_count < 0 THEN
    RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'WebAuthn sign count must be non-negative';
  END IF;

  SELECT * INTO credential_row
  FROM platform_credentials
  WHERE credential_id = p_credential_id
  FOR UPDATE;
  IF NOT FOUND THEN
    RETURN jsonb_build_object('outcome', 'absent');
  END IF;
  IF credential_row.status <> 'active'
     OR credential_row.sign_count_state = 'clone-detected'
  THEN
    RETURN jsonb_build_object(
      'outcome', 'denied',
      'reason', 'credential_not_active',
      'credential', public.agentpass_platform_credential_json(credential_row)
    );
  END IF;

  IF (credential_row.sign_count > 0 AND p_sign_count = 0)
     OR (p_sign_count > 0 AND p_sign_count <= credential_row.sign_count)
  THEN
    outcome := 'clone-detected';
    UPDATE platform_credentials
    SET sign_count_state = 'clone-detected',
        clone_detected_at = now_value,
        version = version + 1
    WHERE credential_id = p_credential_id;
  ELSE
    UPDATE platform_credentials
    SET sign_count = p_sign_count,
        sign_count_state = CASE
          WHEN p_sign_count = 0 THEN 'zero-counter'
          ELSE 'monotonic'
        END,
        last_used_at = now_value,
        version = version + 1
    WHERE credential_id = p_credential_id;
  END IF;

  SELECT * INTO credential_row
  FROM platform_credentials
  WHERE credential_id = p_credential_id;
  RETURN jsonb_build_object(
    'outcome', outcome,
    'credential', public.agentpass_platform_credential_json(credential_row)
  );
END;
$$;

CREATE FUNCTION public.agentpass_platform_credential_revoke(
  p_credential_id uuid,
  p_reason text
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  credential_row platform_credentials%ROWTYPE;
  now_value timestamptz := clock_timestamp();
BEGIN
  SELECT * INTO credential_row
  FROM platform_credentials
  WHERE credential_id = p_credential_id
  FOR UPDATE;
  IF NOT FOUND THEN
    RETURN jsonb_build_object('outcome', 'absent');
  END IF;
  IF credential_row.status = 'revoked' THEN
    RETURN jsonb_build_object(
      'outcome', 'already-revoked',
      'credential', public.agentpass_platform_credential_json(credential_row)
    );
  END IF;

  UPDATE platform_credentials
  SET status = 'revoked',
      revoked_at = now_value,
      revoke_reason = p_reason,
      version = version + 1
  WHERE credential_id = p_credential_id;

  SELECT * INTO credential_row
  FROM platform_credentials
  WHERE credential_id = p_credential_id;
  RETURN jsonb_build_object(
    'outcome', 'revoked',
    'credential', public.agentpass_platform_credential_json(credential_row)
  );
END;
$$;

-- Session issuance binds all authority observations in one transaction.  TTLs
-- are durations, not caller-supplied timestamps; the database clock chooses
-- authenticated_at, expiry, and idle expiry.  The explicit idempotency key is
-- session_id, while the bearer remains only its SHA-256 digest.
CREATE FUNCTION public.agentpass_platform_session_issue(
  p_session_id uuid,
  p_session_material_hash bytea,
  p_principal_id uuid,
  p_member_id uuid,
  p_organization_id uuid,
  p_assignment_id uuid,
  p_credential_id uuid,
  p_operation text,
  p_capability text,
  p_ttl_seconds integer,
  p_idle_timeout_seconds integer
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  existing platform_sessions%ROWTYPE;
  principal_row record;
  assignment_row record;
  credential_row record;
  session_row platform_sessions%ROWTYPE;
  now_value timestamptz := clock_timestamp();
  session_expires_at timestamptz;
  session_idle_expires_at timestamptz;
BEGIN
  IF p_session_material_hash IS NULL OR octet_length(p_session_material_hash) <> 32 THEN
    RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'session material must be a 32-byte digest';
  END IF;
  IF p_ttl_seconds NOT BETWEEN 1 AND 86400
     OR p_idle_timeout_seconds NOT BETWEEN 1 AND p_ttl_seconds
  THEN
    RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'platform session TTL is outside the allowed bounds';
  END IF;

  SELECT * INTO existing
  FROM platform_sessions
  WHERE session_id = p_session_id
     OR session_material_hash = p_session_material_hash
  FOR UPDATE;
  IF FOUND THEN
    IF existing.session_id <> p_session_id
       OR existing.session_material_hash <> p_session_material_hash
       OR existing.principal_id <> p_principal_id
       OR existing.member_id <> p_member_id
       OR existing.organization_id <> p_organization_id
       OR existing.assignment_id <> p_assignment_id
       OR existing.credential_id <> p_credential_id
       OR existing.operation <> p_operation
       OR existing.capability <> p_capability
    THEN
      RAISE EXCEPTION USING ERRCODE = 'unique_violation',
        CONSTRAINT = 'platform_sessions_binding_replay',
        MESSAGE = 'platform session issue replay does not match';
    END IF;
    RETURN public.agentpass_platform_session_json(existing);
  END IF;

  SELECT * INTO principal_row
  FROM platform_principals AS principal
  WHERE principal.principal_id = p_principal_id
    AND principal.member_id = p_member_id
  FOR UPDATE;
  IF NOT FOUND OR principal_row.status <> 'active' THEN
    RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'platform principal is not active';
  END IF;

  SELECT * INTO assignment_row
  FROM platform_operator_assignments AS assignment
  WHERE assignment.assignment_id = p_assignment_id
  FOR UPDATE;
  IF NOT FOUND
     OR assignment_row.principal_id IS DISTINCT FROM p_principal_id
     OR assignment_row.member_id IS DISTINCT FROM p_member_id
     OR assignment_row.organization_id IS DISTINCT FROM p_organization_id
     OR assignment_row.operation IS DISTINCT FROM p_operation
     OR assignment_row.capability IS DISTINCT FROM p_capability
     OR assignment_row.status <> 'active'
     OR assignment_row.issued_at > now_value
     OR assignment_row.expires_at <= now_value
  THEN
    RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'platform assignment is not active for session';
  END IF;

  SELECT * INTO credential_row
  FROM platform_credentials AS credential
  WHERE credential.credential_id = p_credential_id
    AND credential.principal_id = p_principal_id
    AND credential.member_id = p_member_id
  FOR UPDATE;
  IF NOT FOUND OR credential_row.status <> 'active' THEN
    RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'platform credential is not active for session';
  END IF;

  session_expires_at := LEAST(
    now_value + (p_ttl_seconds::double precision * interval '1 second'),
    assignment_row.expires_at
  );
  IF session_expires_at <= now_value THEN
    RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'platform assignment expires before session can start';
  END IF;
  session_idle_expires_at := LEAST(
    session_expires_at,
    now_value + (p_idle_timeout_seconds::double precision * interval '1 second')
  );

  INSERT INTO platform_sessions (
    session_id, session_material_hash, principal_id, member_id, organization_id,
    assignment_id, credential_id, operation, capability,
    principal_authority_generation, assignment_version, credential_version,
    idle_timeout_seconds, status, authenticated_at, last_seen_at,
    expires_at, idle_expires_at
  ) VALUES (
    p_session_id, p_session_material_hash, p_principal_id, p_member_id, p_organization_id,
    p_assignment_id, p_credential_id, p_operation, p_capability,
    principal_row.authority_generation, assignment_row.version, credential_row.version,
    p_idle_timeout_seconds, 'active', now_value, now_value,
    session_expires_at, session_idle_expires_at
  )
  RETURNING * INTO session_row;

  RETURN public.agentpass_platform_session_json(session_row);
END;
$$;

-- This is a non-locking precheck.  N3a intentionally does not claim that a
-- SELECT lookup is the final authorization boundary: N3b/N3c must consume a
-- one-use, operation-bound proof and reserve the mutation in the same
-- transaction.  The current-generation and current-version predicates here
-- still make stale sessions fail closed before that consume path exists.
CREATE FUNCTION public.agentpass_platform_session_find_active(
  p_session_material_hash bytea,
  p_organization_id uuid,
  p_operation text,
  p_capability text
)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  now_value timestamptz := clock_timestamp();
  session jsonb;
BEGIN
  IF p_session_material_hash IS NULL OR octet_length(p_session_material_hash) <> 32 THEN
    RETURN NULL;
  END IF;

  SELECT public.agentpass_platform_session_json(platform_session)
    INTO session
  FROM platform_sessions AS platform_session
  JOIN platform_principals AS principal
    ON principal.principal_id = platform_session.principal_id
   AND principal.member_id = platform_session.member_id
   AND principal.status = 'active'
   AND principal.authority_generation = platform_session.principal_authority_generation
  JOIN platform_operator_assignments AS assignment
    ON assignment.assignment_id = platform_session.assignment_id
   AND assignment.principal_id = platform_session.principal_id
   AND assignment.member_id = platform_session.member_id
   AND assignment.organization_id = platform_session.organization_id
   AND assignment.operation = platform_session.operation
   AND assignment.capability = platform_session.capability
   AND assignment.status = 'active'
   AND assignment.version = platform_session.assignment_version
   AND assignment.expires_at > now_value
  JOIN platform_credentials AS credential
    ON credential.credential_id = platform_session.credential_id
   AND credential.principal_id = platform_session.principal_id
   AND credential.member_id = platform_session.member_id
   AND credential.status = 'active'
   AND credential.version = platform_session.credential_version
  JOIN webauthn_credentials AS webauthn
    ON webauthn.id = credential.webauthn_credential_id
   AND webauthn.member_id = credential.member_id
   AND webauthn.revoked_at IS NULL
  WHERE platform_session.session_material_hash = p_session_material_hash
    AND platform_session.organization_id = p_organization_id
    AND platform_session.operation = p_operation
    AND platform_session.capability = p_capability
    AND platform_session.status = 'active'
    AND platform_session.authenticated_at <= now_value
    AND platform_session.expires_at > now_value
    AND platform_session.idle_expires_at > now_value;

  RETURN session;
END;
$$;

-- Refreshing idle state is separate from lookup so a read cannot silently
-- prolong a session.  It locks exactly one session row and rechecks every
-- authority snapshot before advancing the lifecycle version.
CREATE FUNCTION public.agentpass_platform_session_touch(
  p_session_material_hash bytea,
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
  session_row platform_sessions%ROWTYPE;
  principal_row record;
  assignment_row record;
  credential_row record;
  now_value timestamptz := clock_timestamp();
BEGIN
  IF p_session_material_hash IS NULL OR octet_length(p_session_material_hash) <> 32 THEN
    RETURN NULL;
  END IF;

  SELECT * INTO session_row
  FROM platform_sessions
  WHERE session_material_hash = p_session_material_hash
    AND organization_id = p_organization_id
    AND operation = p_operation
    AND capability = p_capability
  FOR UPDATE;
  IF NOT FOUND THEN
    RETURN NULL;
  END IF;

  IF session_row.status <> 'active' THEN
    RETURN public.agentpass_platform_session_json(session_row);
  END IF;

  IF session_row.expires_at <= now_value OR session_row.idle_expires_at <= now_value THEN
    UPDATE platform_sessions
    SET status = 'expired', expired_at = now_value, version = version + 1
    WHERE session_id = session_row.session_id;
    SELECT * INTO session_row FROM platform_sessions WHERE session_id = session_row.session_id;
    RETURN public.agentpass_platform_session_json(session_row);
  END IF;

  SELECT * INTO principal_row
  FROM platform_principals AS principal
  WHERE principal.principal_id = session_row.principal_id
    AND principal.member_id = session_row.member_id
    AND principal.status = 'active'
    AND principal.authority_generation = session_row.principal_authority_generation
  FOR SHARE;
  SELECT * INTO assignment_row
  FROM platform_operator_assignments AS assignment
  WHERE assignment.assignment_id = session_row.assignment_id
    AND assignment.principal_id = session_row.principal_id
    AND assignment.member_id = session_row.member_id
    AND assignment.organization_id = session_row.organization_id
    AND assignment.operation = session_row.operation
    AND assignment.capability = session_row.capability
    AND assignment.status = 'active'
    AND assignment.version = session_row.assignment_version
    AND assignment.expires_at > now_value
  FOR SHARE;
  SELECT * INTO credential_row
  FROM platform_credentials AS credential
  JOIN webauthn_credentials AS webauthn
    ON webauthn.id = credential.webauthn_credential_id
   AND webauthn.member_id = credential.member_id
   AND webauthn.revoked_at IS NULL
  WHERE credential.credential_id = session_row.credential_id
    AND credential.principal_id = session_row.principal_id
    AND credential.member_id = session_row.member_id
    AND credential.status = 'active'
    AND credential.version = session_row.credential_version
  FOR SHARE;

  IF NOT FOUND OR principal_row IS NULL OR assignment_row IS NULL OR credential_row IS NULL THEN
    RETURN NULL;
  END IF;

  UPDATE platform_sessions
  SET last_seen_at = now_value,
      idle_expires_at = LEAST(
        expires_at,
        now_value + (idle_timeout_seconds::double precision * interval '1 second')
      ),
      version = version + 1
  WHERE session_id = session_row.session_id;
  SELECT * INTO session_row FROM platform_sessions WHERE session_id = session_row.session_id;
  RETURN public.agentpass_platform_session_json(session_row);
END;
$$;

CREATE FUNCTION public.agentpass_platform_session_revoke(
  p_session_id uuid,
  p_reason text
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  session_row platform_sessions%ROWTYPE;
  now_value timestamptz := clock_timestamp();
BEGIN
  SELECT * INTO session_row
  FROM platform_sessions
  WHERE session_id = p_session_id
  FOR UPDATE;
  IF NOT FOUND THEN
    RETURN jsonb_build_object('outcome', 'absent');
  END IF;
  IF session_row.status <> 'active' THEN
    RETURN jsonb_build_object(
      'outcome', 'already-terminal',
      'session', public.agentpass_platform_session_json(session_row)
    );
  END IF;

  UPDATE platform_sessions
  SET status = 'revoked', revoked_at = now_value, revoke_reason = p_reason, version = version + 1
  WHERE session_id = p_session_id;
  SELECT * INTO session_row FROM platform_sessions WHERE session_id = p_session_id;
  RETURN jsonb_build_object(
    'outcome', 'revoked',
    'session', public.agentpass_platform_session_json(session_row)
  );
END;
$$;

-- Authority tables are function-only.  The application can perform only the
-- two narrow read/refresh operations above; it cannot INSERT, UPDATE, DELETE,
-- TRUNCATE, create triggers, or obtain REFERENCES on either table.
REVOKE ALL PRIVILEGES ON TABLE
  public.platform_credentials,
  public.platform_sessions
FROM PUBLIC, agentpass_app, agentpass_signer, agentpass_backup;

REVOKE ALL PRIVILEGES ON FUNCTION public.agentpass_guard_platform_credential() FROM PUBLIC, agentpass_app, agentpass_signer, agentpass_backup;
REVOKE ALL PRIVILEGES ON FUNCTION public.agentpass_guard_platform_session() FROM PUBLIC, agentpass_app, agentpass_signer, agentpass_backup;
REVOKE ALL PRIVILEGES ON FUNCTION public.agentpass_platform_credential_json(platform_credentials) FROM PUBLIC, agentpass_app, agentpass_signer, agentpass_backup;
REVOKE ALL PRIVILEGES ON FUNCTION public.agentpass_platform_session_json(platform_sessions) FROM PUBLIC, agentpass_app, agentpass_signer, agentpass_backup;

REVOKE ALL PRIVILEGES ON FUNCTION public.agentpass_platform_credential_provision(uuid, uuid, uuid, bytea, text) FROM PUBLIC, agentpass_app, agentpass_signer, agentpass_backup;
REVOKE ALL PRIVILEGES ON FUNCTION public.agentpass_platform_credential_advance_sign_count(uuid, bigint) FROM PUBLIC, agentpass_app, agentpass_signer, agentpass_backup;
REVOKE ALL PRIVILEGES ON FUNCTION public.agentpass_platform_credential_revoke(uuid, text) FROM PUBLIC, agentpass_app, agentpass_signer, agentpass_backup;
REVOKE ALL PRIVILEGES ON FUNCTION public.agentpass_platform_session_issue(uuid, bytea, uuid, uuid, uuid, uuid, uuid, text, text, integer, integer) FROM PUBLIC, agentpass_app, agentpass_signer, agentpass_backup;
REVOKE ALL PRIVILEGES ON FUNCTION public.agentpass_platform_session_find_active(bytea, uuid, text, text) FROM PUBLIC, agentpass_signer, agentpass_backup;
REVOKE ALL PRIVILEGES ON FUNCTION public.agentpass_platform_session_touch(bytea, uuid, text, text) FROM PUBLIC, agentpass_signer, agentpass_backup;
REVOKE ALL PRIVILEGES ON FUNCTION public.agentpass_platform_session_revoke(uuid, text) FROM PUBLIC, agentpass_app, agentpass_signer, agentpass_backup;

GRANT EXECUTE ON FUNCTION public.agentpass_platform_credential_provision(uuid, uuid, uuid, bytea, text) TO agentpass_migrator;
GRANT EXECUTE ON FUNCTION public.agentpass_platform_credential_advance_sign_count(uuid, bigint) TO agentpass_migrator;
GRANT EXECUTE ON FUNCTION public.agentpass_platform_credential_revoke(uuid, text) TO agentpass_migrator;
GRANT EXECUTE ON FUNCTION public.agentpass_platform_session_issue(uuid, bytea, uuid, uuid, uuid, uuid, uuid, text, text, integer, integer) TO agentpass_migrator;
GRANT EXECUTE ON FUNCTION public.agentpass_platform_session_find_active(bytea, uuid, text, text) TO agentpass_migrator, agentpass_app;
GRANT EXECUTE ON FUNCTION public.agentpass_platform_session_touch(bytea, uuid, text, text) TO agentpass_migrator, agentpass_app;
GRANT EXECUTE ON FUNCTION public.agentpass_platform_session_revoke(uuid, text) TO agentpass_migrator;

COMMIT;
