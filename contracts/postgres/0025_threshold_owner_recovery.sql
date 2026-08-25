BEGIN;

-- Recovery activation must invalidate sessions even when the subject already
-- has the owner role.  The prior epoch trigger permits this one explicit,
-- transaction-local recovery bump while preserving the forward-only rule for
-- every ordinary caller.
CREATE OR REPLACE FUNCTION agentpass_bump_membership_session_epoch()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
DECLARE
  authority_changed boolean;
  recovery_bump boolean;
BEGIN
  IF TG_OP <> 'UPDATE' THEN
    RETURN NEW;
  END IF;
  IF NEW.session_epoch IS DISTINCT FROM OLD.session_epoch
     AND NEW.session_epoch IS DISTINCT FROM OLD.session_epoch + 1 THEN
    RAISE EXCEPTION USING ERRCODE = 'check_violation', CONSTRAINT = 'memberships_session_epoch_forward_only', MESSAGE = 'membership session epoch may only advance by one';
  END IF;
  authority_changed := (NEW.status IS DISTINCT FROM OLD.status)
    OR (NEW.role IS DISTINCT FROM OLD.role)
    OR (NEW.organization_id IS DISTINCT FROM OLD.organization_id);
  recovery_bump := current_setting('agentpass.recovery_epoch_bump', true) = 'on';
  IF authority_changed OR recovery_bump THEN
    IF OLD.session_epoch = 9223372036854775807::bigint THEN
      RAISE EXCEPTION USING ERRCODE = 'numeric_value_out_of_range', CONSTRAINT = 'memberships_session_epoch_positive', MESSAGE = 'membership session epoch cannot advance beyond bigint';
    END IF;
    NEW.session_epoch := OLD.session_epoch + 1;
  ELSIF NEW.session_epoch IS DISTINCT FROM OLD.session_epoch THEN
    RAISE EXCEPTION USING ERRCODE = 'check_violation', CONSTRAINT = 'memberships_session_epoch_forward_only', MESSAGE = 'membership session epoch is managed by the authority trigger';
  END IF;
  RETURN NEW;
END;
$$;

-- Threshold recovery never stores an approval secret, exchange value, session
-- token, WebAuthn challenge/assertion, private key, or notification target.
-- Only one-way digests and public state-machine metadata are durable here.
CREATE TABLE owner_recovery_requests (
  organization_id uuid NOT NULL REFERENCES organizations(id),
  request_id uuid NOT NULL,
  schema_version integer NOT NULL CHECK (schema_version = 1),
  kind text NOT NULL CHECK (kind = 'threshold-owner-recovery'),
  subject_member_id uuid NOT NULL,
  creator_member_id uuid NOT NULL,
  creator_session_id uuid NOT NULL,
  state text NOT NULL DEFAULT 'pending'
    CHECK (state IN ('pending', 'approved', 'delayed', 'session_issued',
      'credential_enrolled', 'activated', 'cancelled', 'expired', 'failed')),
  threshold smallint NOT NULL CHECK (threshold BETWEEN 2 AND 32),
  approved_owner_count smallint NOT NULL DEFAULT 0
    CHECK (approved_owner_count BETWEEN 0 AND 32),
  approved_at timestamptz,
  delay_until timestamptz,
  session_issued_at timestamptz,
  credential_enrolled_at timestamptz,
  activated_at timestamptz,
  expires_at timestamptz NOT NULL,
  terminal_reason text
    CHECK (terminal_reason IS NULL OR (char_length(terminal_reason) BETWEEN 1 AND 128 AND terminal_reason !~ '[[:cntrl:]]')),
  version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (organization_id, request_id),
  FOREIGN KEY (organization_id, subject_member_id)
    REFERENCES memberships(organization_id, member_id),
  FOREIGN KEY (organization_id, creator_member_id)
    REFERENCES memberships(organization_id, member_id),
  FOREIGN KEY (organization_id, creator_session_id)
    REFERENCES human_sessions(organization_id, id),
  CHECK (expires_at > created_at),
  CHECK (delay_until IS NULL OR approved_at IS NOT NULL),
  CHECK (delay_until IS NULL OR delay_until > approved_at),
  CHECK (session_issued_at IS NULL OR delay_until IS NOT NULL),
  CHECK (credential_enrolled_at IS NULL OR session_issued_at IS NOT NULL),
  CHECK (activated_at IS NULL OR credential_enrolled_at IS NOT NULL),
  CHECK ((state IN ('pending', 'approved') AND session_issued_at IS NULL AND credential_enrolled_at IS NULL AND activated_at IS NULL)
    OR (state = 'delayed' AND delay_until IS NOT NULL AND session_issued_at IS NULL AND credential_enrolled_at IS NULL AND activated_at IS NULL)
    OR (state = 'session_issued' AND session_issued_at IS NOT NULL AND credential_enrolled_at IS NULL AND activated_at IS NULL)
    OR (state = 'credential_enrolled' AND credential_enrolled_at IS NOT NULL AND activated_at IS NULL)
    OR (state = 'activated' AND activated_at IS NOT NULL)
    OR (state IN ('cancelled', 'expired', 'failed') AND terminal_reason IS NOT NULL)),
  CHECK ((state IN ('cancelled', 'expired', 'failed')) = (terminal_reason IS NOT NULL))
);

CREATE INDEX owner_recovery_requests_subject_lookup
  ON owner_recovery_requests (organization_id, subject_member_id, created_at DESC, request_id);

CREATE INDEX owner_recovery_requests_expiry_lookup
  ON owner_recovery_requests (expires_at, organization_id, request_id)
  WHERE state IN ('pending', 'approved', 'delayed', 'session_issued', 'credential_enrolled');

CREATE UNIQUE INDEX owner_recovery_one_live_subject
  ON owner_recovery_requests (organization_id, subject_member_id)
  WHERE state IN ('pending', 'approved', 'delayed', 'session_issued', 'credential_enrolled');

CREATE TABLE owner_recovery_approvals (
  organization_id uuid NOT NULL,
  request_id uuid NOT NULL,
  approval_id uuid NOT NULL,
  owner_member_id uuid NOT NULL,
  owner_session_id uuid NOT NULL,
  authorization_id uuid NOT NULL,
  authorization_operation text NOT NULL
    CHECK (authorization_operation = 'human.recovery.approve'),
  authorized_at timestamptz NOT NULL,
  owner_membership_session_epoch bigint NOT NULL CHECK (owner_membership_session_epoch > 0),
  approved_at timestamptz NOT NULL,
  invalidated_at timestamptz,
  invalidation_reason text
    CHECK (invalidation_reason IS NULL OR (char_length(invalidation_reason) BETWEEN 1 AND 128 AND invalidation_reason !~ '[[:cntrl:]]')),
  PRIMARY KEY (organization_id, approval_id),
  UNIQUE (organization_id, request_id, owner_member_id),
  UNIQUE (organization_id, request_id, authorization_id),
  FOREIGN KEY (organization_id, request_id)
    REFERENCES owner_recovery_requests(organization_id, request_id),
  FOREIGN KEY (organization_id, owner_member_id)
    REFERENCES memberships(organization_id, member_id),
  FOREIGN KEY (organization_id, owner_session_id)
    REFERENCES human_sessions(organization_id, id),
  FOREIGN KEY (organization_id, authorization_id)
    REFERENCES webauthn_challenges(organization_id, id),
  CHECK ((invalidated_at IS NULL AND invalidation_reason IS NULL)
    OR (invalidated_at IS NOT NULL AND invalidation_reason IS NOT NULL)),
  CHECK (approved_at >= authorized_at)
);

CREATE INDEX owner_recovery_approvals_active_lookup
  ON owner_recovery_approvals (organization_id, request_id, owner_member_id)
  WHERE invalidated_at IS NULL;

CREATE TABLE owner_recovery_exchanges (
  organization_id uuid NOT NULL,
  request_id uuid NOT NULL,
  exchange_id uuid NOT NULL,
  exchange_digest bytea NOT NULL UNIQUE CHECK (octet_length(exchange_digest) = 32),
  issued_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz,
  consumed_recovery_session_id uuid,
  PRIMARY KEY (organization_id, exchange_id),
  UNIQUE (organization_id, request_id),
  FOREIGN KEY (organization_id, request_id)
    REFERENCES owner_recovery_requests(organization_id, request_id),
  CHECK (expires_at > issued_at),
  CHECK ((consumed_at IS NULL AND consumed_recovery_session_id IS NULL)
    OR (consumed_at IS NOT NULL AND consumed_recovery_session_id IS NOT NULL)),
  CHECK (consumed_at IS NULL OR consumed_at >= issued_at)
);

CREATE TABLE owner_recovery_sessions (
  organization_id uuid NOT NULL,
  recovery_session_id uuid NOT NULL,
  request_id uuid NOT NULL,
  member_id uuid NOT NULL,
  session_digest bytea NOT NULL UNIQUE CHECK (octet_length(session_digest) = 32),
  stage text NOT NULL DEFAULT 'session_issued'
    CHECK (stage IN ('session_issued', 'credential_enrolled', 'activated', 'revoked', 'expired')),
  issued_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  idle_expires_at timestamptz NOT NULL,
  last_seen_at timestamptz NOT NULL,
  credential_id bytea CHECK (credential_id IS NULL OR octet_length(credential_id) BETWEEN 16 AND 1024),
  credential_enrolled_at timestamptz,
  activation_authorization_id uuid,
  activation_authorized_at timestamptz,
  activated_at timestamptz,
  revoked_at timestamptz,
  revoke_reason text
    CHECK (revoke_reason IS NULL OR (char_length(revoke_reason) BETWEEN 1 AND 128 AND revoke_reason !~ '[[:cntrl:]]')),
  PRIMARY KEY (organization_id, recovery_session_id),
  UNIQUE (organization_id, request_id),
  FOREIGN KEY (organization_id, request_id)
    REFERENCES owner_recovery_requests(organization_id, request_id),
  FOREIGN KEY (organization_id, member_id)
    REFERENCES memberships(organization_id, member_id),
  CHECK (expires_at > issued_at),
  CHECK (idle_expires_at > issued_at AND idle_expires_at <= expires_at),
  CHECK (credential_enrolled_at IS NULL OR credential_id IS NOT NULL),
  CHECK (activation_authorized_at IS NULL OR activation_authorization_id IS NOT NULL),
  CHECK (activated_at IS NULL OR activation_authorized_at IS NOT NULL),
  CHECK ((stage IN ('session_issued', 'revoked', 'expired') AND activated_at IS NULL)
    OR (stage = 'credential_enrolled' AND credential_enrolled_at IS NOT NULL AND activated_at IS NULL)
    OR (stage = 'activated' AND activated_at IS NOT NULL)),
  CHECK ((stage IN ('revoked', 'expired')) = (revoked_at IS NOT NULL)),
  CHECK ((revoked_at IS NULL AND revoke_reason IS NULL) OR (revoked_at IS NOT NULL AND revoke_reason IS NOT NULL))
);

CREATE INDEX owner_recovery_sessions_active_lookup
  ON owner_recovery_sessions (organization_id, member_id, expires_at, idle_expires_at)
  WHERE stage IN ('session_issued', 'credential_enrolled');

CREATE TABLE owner_recovery_outbox (
  organization_id uuid NOT NULL,
  event_id uuid NOT NULL,
  request_id uuid NOT NULL,
  subject_member_id uuid NOT NULL,
  event_type text NOT NULL CHECK (event_type IN (
    'recovery.request.created', 'recovery.approval.recorded',
    'recovery.delay.started', 'recovery.session.issued',
    'recovery.credential.enrolled', 'recovery.activated',
    'recovery.cancelled', 'recovery.expired', 'recovery.failed')),
  status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'published')),
  attempts integer NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 100),
  available_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  published_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (organization_id, event_id),
  FOREIGN KEY (organization_id, request_id)
    REFERENCES owner_recovery_requests(organization_id, request_id),
  FOREIGN KEY (organization_id, subject_member_id)
    REFERENCES memberships(organization_id, member_id),
  CHECK ((status = 'pending' AND published_at IS NULL)
    OR (status = 'published' AND published_at IS NOT NULL))
);

CREATE INDEX owner_recovery_outbox_pending
  ON owner_recovery_outbox (available_at, organization_id, created_at, event_id)
  WHERE status = 'pending';

-- Restrict direct state mutation to the forward-only transition graph. The
-- repository still performs row-lock/CAS checks; this trigger is the final
-- database boundary for an internal caller that bypasses the repository.
CREATE FUNCTION agentpass_guard_owner_recovery_state()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
  IF NEW.organization_id IS DISTINCT FROM OLD.organization_id
     OR NEW.request_id IS DISTINCT FROM OLD.request_id
     OR NEW.schema_version IS DISTINCT FROM OLD.schema_version
     OR NEW.kind IS DISTINCT FROM OLD.kind
     OR NEW.subject_member_id IS DISTINCT FROM OLD.subject_member_id
     OR NEW.creator_member_id IS DISTINCT FROM OLD.creator_member_id
     OR NEW.creator_session_id IS DISTINCT FROM OLD.creator_session_id
     OR NEW.threshold IS DISTINCT FROM OLD.threshold
     OR NEW.created_at IS DISTINCT FROM OLD.created_at
  THEN
    RAISE EXCEPTION USING ERRCODE = 'check_violation',
      CONSTRAINT = 'owner_recovery_request_identity_immutable',
      MESSAGE = 'owner recovery request identity is immutable';
  END IF;

  IF NEW.version <> OLD.version + 1 THEN
    RAISE EXCEPTION USING ERRCODE = 'check_violation',
      CONSTRAINT = 'owner_recovery_request_version_forward_only',
      MESSAGE = 'owner recovery request version must advance by one';
  END IF;

  IF NOT (
    NEW.state = OLD.state
    OR (OLD.state = 'pending' AND NEW.state = 'approved')
    OR (OLD.state = 'approved' AND NEW.state = 'delayed')
    OR (OLD.state = 'delayed' AND NEW.state = 'session_issued')
    OR (OLD.state = 'session_issued' AND NEW.state = 'credential_enrolled')
    OR (OLD.state = 'credential_enrolled' AND NEW.state = 'activated')
    OR (OLD.state IN ('pending', 'approved', 'delayed', 'session_issued', 'credential_enrolled')
        AND NEW.state IN ('cancelled', 'expired', 'failed'))
  ) THEN
    RAISE EXCEPTION USING ERRCODE = 'check_violation',
      CONSTRAINT = 'owner_recovery_request_state_forward_only',
      MESSAGE = 'owner recovery request transition is not allowed';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER owner_recovery_request_state_guard
  BEFORE UPDATE ON owner_recovery_requests
  FOR EACH ROW EXECUTE FUNCTION agentpass_guard_owner_recovery_state();

COMMIT;
