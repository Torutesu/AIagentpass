BEGIN;

CREATE TABLE agent_sessions (
  organization_id uuid NOT NULL,
  session_id uuid NOT NULL,
  grant_id uuid NOT NULL,
  device_id uuid NOT NULL,
  agent_id uuid NOT NULL,
  agent_kind text NOT NULL
    CHECK (agent_kind IN ('claude-code', 'cursor')),
  adapter_id uuid NOT NULL,
  adapter_version text NOT NULL
    CHECK (adapter_version ~ '^(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$'),
  process_binding_policy_id text NOT NULL
    CHECK (process_binding_policy_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$'),
  grant_hash text NOT NULL
    CHECK (grant_hash ~ '^[0-9a-f]{64}$'),
  process_binding_sha256 text NOT NULL
    CHECK (process_binding_sha256 ~ '^[0-9a-f]{64}$'),
  ancestry_binding_sha256 text NOT NULL
    CHECK (ancestry_binding_sha256 ~ '^[0-9a-f]{64}$'),
  worktree_binding_sha256 text NOT NULL
    CHECK (worktree_binding_sha256 ~ '^[0-9a-f]{64}$'),
  control_sequence bigint NOT NULL CHECK (control_sequence > 0),
  max_signatures integer NOT NULL CHECK (max_signatures BETWEEN 1 AND 64),
  used_signatures integer NOT NULL DEFAULT 0 CHECK (used_signatures >= 0),
  reserved_signatures integer NOT NULL DEFAULT 0 CHECK (reserved_signatures >= 0),
  status text NOT NULL DEFAULT 'challenge_pending'
    CHECK (status IN (
      'challenge_pending', 'active', 'request_reserved', 'signing_intent',
      'signed', 'closed', 'expired', 'revoked', 'process_lost',
      'outcome_unknown'
    )),
  active_request_id uuid,
  last_request_id uuid,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  not_before timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  closed_at timestamptz,
  expired_at timestamptz,
  revoked_at timestamptz,
  process_lost_at timestamptz,
  outcome_unknown_at timestamptz,
  PRIMARY KEY (organization_id, session_id),
  UNIQUE (organization_id, grant_id),
  UNIQUE (organization_id, session_id, grant_id, device_id),
  FOREIGN KEY (organization_id, grant_id, device_id, agent_id, grant_hash)
    REFERENCES agent_session_grants(organization_id, grant_id, device_id, agent_id, grant_hash),
  FOREIGN KEY (organization_id, agent_id, device_id)
    REFERENCES agents(organization_id, id, device_id),
  FOREIGN KEY (organization_id, device_id) REFERENCES devices(organization_id, id),
  CHECK (expires_at > not_before),
  CHECK (created_at >= not_before),
  CHECK (used_signatures <= max_signatures),
  CHECK (used_signatures + reserved_signatures <= max_signatures),
  CHECK (active_request_id IS NULL OR active_request_id IS DISTINCT FROM last_request_id),
  CHECK (
    (status = 'challenge_pending'
      AND active_request_id IS NULL AND last_request_id IS NULL)
    OR (status = 'active'
      AND active_request_id IS NULL)
    OR (status IN ('request_reserved', 'signing_intent')
      AND active_request_id IS NOT NULL)
    OR (status = 'signed'
      AND active_request_id IS NULL AND last_request_id IS NOT NULL)
    OR (status IN ('closed', 'expired', 'revoked', 'process_lost')
      AND active_request_id IS NULL)
    OR (status = 'outcome_unknown'
      AND active_request_id IS NULL AND last_request_id IS NOT NULL)
  ),
  CHECK (
    (status IN ('challenge_pending', 'active', 'request_reserved', 'signing_intent', 'signed')
      AND closed_at IS NULL AND expired_at IS NULL AND revoked_at IS NULL
      AND process_lost_at IS NULL AND outcome_unknown_at IS NULL)
    OR
    (status = 'closed'
      AND closed_at IS NOT NULL AND expired_at IS NULL AND revoked_at IS NULL
      AND process_lost_at IS NULL AND outcome_unknown_at IS NULL
      AND active_request_id IS NULL)
    OR
    (status = 'expired'
      AND closed_at IS NULL AND expired_at IS NOT NULL AND revoked_at IS NULL
      AND process_lost_at IS NULL AND outcome_unknown_at IS NULL
      AND active_request_id IS NULL)
    OR
    (status = 'revoked'
      AND closed_at IS NULL AND expired_at IS NULL AND revoked_at IS NOT NULL
      AND process_lost_at IS NULL AND outcome_unknown_at IS NULL
      AND active_request_id IS NULL)
    OR
    (status = 'process_lost'
      AND closed_at IS NULL AND expired_at IS NULL AND revoked_at IS NULL
      AND process_lost_at IS NOT NULL AND outcome_unknown_at IS NULL
      AND active_request_id IS NULL)
    OR
    (status = 'outcome_unknown'
      AND closed_at IS NULL AND expired_at IS NULL AND revoked_at IS NULL
      AND process_lost_at IS NULL AND outcome_unknown_at IS NOT NULL
      AND active_request_id IS NULL AND last_request_id IS NOT NULL)
  ),
  CHECK (closed_at IS NULL OR closed_at >= created_at),
  CHECK (expired_at IS NULL OR expired_at >= expires_at),
  CHECK (revoked_at IS NULL OR revoked_at >= created_at),
  CHECK (process_lost_at IS NULL OR process_lost_at >= created_at),
  CHECK (outcome_unknown_at IS NULL OR outcome_unknown_at >= created_at)
);

-- A grant can be consumed by only one session ever. The partial index makes
-- the active-session rule visible even though the full grant uniqueness also
-- preserves terminal history for replay and incident review.
CREATE UNIQUE INDEX agent_sessions_one_active_per_grant
  ON agent_sessions (organization_id, grant_id)
  WHERE status IN ('challenge_pending', 'active', 'request_reserved', 'signing_intent', 'signed');

CREATE UNIQUE INDEX agent_sessions_grant_process_binding_identity
  ON agent_sessions (organization_id, grant_hash, process_binding_sha256);

CREATE INDEX agent_sessions_process_lookup
  ON agent_sessions (organization_id, device_id, process_binding_sha256, expires_at, session_id)
  WHERE status IN ('challenge_pending', 'active', 'request_reserved', 'signing_intent', 'signed');

CREATE INDEX agent_sessions_expiry_lookup
  ON agent_sessions (organization_id, expires_at, session_id)
  WHERE status IN ('challenge_pending', 'active', 'request_reserved', 'signing_intent', 'signed');

-- Session insertion is the single durable grant-consumption boundary. The
-- grant row is locked before it is changed, so concurrent consumers serialize;
-- a transaction rollback restores the issued grant and leaves no session.
CREATE FUNCTION agentpass_consume_agent_session_grant_for_session()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
DECLARE
  grant_row agent_session_grants%ROWTYPE;
  existing_session agent_sessions%ROWTYPE;
  changed integer;
BEGIN
  IF TG_OP <> 'INSERT' THEN
    RETURN NEW;
  END IF;

  SELECT session.* INTO existing_session
  FROM agent_sessions AS session
  WHERE session.organization_id = NEW.organization_id
    AND session.session_id = NEW.session_id
  FOR SHARE;
  IF FOUND THEN
    IF existing_session.grant_id <> NEW.grant_id
       OR existing_session.device_id <> NEW.device_id
       OR existing_session.agent_id <> NEW.agent_id
       OR existing_session.grant_hash <> NEW.grant_hash
       OR existing_session.process_binding_sha256 <> NEW.process_binding_sha256
       OR existing_session.worktree_binding_sha256 <> NEW.worktree_binding_sha256 THEN
      RAISE EXCEPTION USING
        ERRCODE = 'unique_violation',
        MESSAGE = 'session_id is already bound to a different session',
        CONSTRAINT = 'agent_sessions_identity_immutable';
    END IF;
    RETURN NEW;
  END IF;

  SELECT grant_record.* INTO grant_row
  FROM agent_session_grants AS grant_record
  WHERE grant_record.organization_id = NEW.organization_id
    AND grant_record.grant_id = NEW.grant_id
    AND grant_record.device_id = NEW.device_id
    AND grant_record.agent_id = NEW.agent_id
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING
      ERRCODE = 'foreign_key_violation',
      MESSAGE = 'agent session grant identity was not found',
      CONSTRAINT = 'agent_session_grants_identity_fk';
  END IF;

  IF NEW.status <> 'challenge_pending'
     OR grant_row.status <> 'issued'
     OR NEW.grant_hash <> grant_row.grant_hash
     OR clock_timestamp() < grant_row.not_before
     OR clock_timestamp() >= grant_row.expires_at
     OR NEW.not_before <> grant_row.not_before
     OR NEW.expires_at <> grant_row.expires_at
     OR NEW.agent_kind <> grant_row.agent_kind
     OR NEW.adapter_id <> grant_row.adapter_id
     OR NEW.adapter_version <> grant_row.adapter_version
     OR NEW.process_binding_policy_id <> grant_row.process_binding_policy_id
     OR NEW.worktree_binding_sha256 <> grant_row.worktree_binding_sha256
     OR NEW.control_sequence <> grant_row.control_sequence
     OR NEW.max_signatures <> grant_row.max_signatures THEN
    RAISE EXCEPTION USING
      ERRCODE = 'check_violation',
      MESSAGE = 'agent session does not match a live grant',
      CONSTRAINT = 'agent_sessions_grant_binding';
  END IF;

  UPDATE agent_session_grants
  SET status = 'consumed',
      consumed_at = clock_timestamp(),
      consumed_session_id = NEW.session_id,
      consumed_process_binding_sha256 = NEW.process_binding_sha256
  WHERE organization_id = grant_row.organization_id
    AND grant_id = grant_row.grant_id
    AND status = 'issued';
  GET DIAGNOSTICS changed = ROW_COUNT;
  IF changed <> 1 THEN
    RAISE EXCEPTION USING
      ERRCODE = 'serialization_failure',
      MESSAGE = 'agent session grant was consumed concurrently',
      CONSTRAINT = 'agent_session_grants_one_time_consumption';
  END IF;

  RETURN NEW;
END;
$$;

CREATE TRIGGER agent_sessions_consume_grant
  BEFORE INSERT ON agent_sessions
  FOR EACH ROW
  EXECUTE FUNCTION agentpass_consume_agent_session_grant_for_session();

CREATE FUNCTION agentpass_guard_agent_session_forward_only()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
DECLARE
  allowed_transition boolean := false;
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION USING
      ERRCODE = 'check_violation',
      MESSAGE = 'agent sessions cannot be deleted',
      CONSTRAINT = 'agent_sessions_forward_only';
  END IF;

  IF NEW.organization_id <> OLD.organization_id
     OR NEW.session_id <> OLD.session_id
     OR NEW.grant_id <> OLD.grant_id
     OR NEW.device_id <> OLD.device_id
     OR NEW.agent_id <> OLD.agent_id
     OR NEW.grant_hash <> OLD.grant_hash
     OR NEW.agent_kind <> OLD.agent_kind
     OR NEW.adapter_id <> OLD.adapter_id
     OR NEW.adapter_version <> OLD.adapter_version
     OR NEW.process_binding_policy_id <> OLD.process_binding_policy_id
     OR NEW.process_binding_sha256 <> OLD.process_binding_sha256
     OR NEW.ancestry_binding_sha256 <> OLD.ancestry_binding_sha256
     OR NEW.worktree_binding_sha256 <> OLD.worktree_binding_sha256
     OR NEW.control_sequence <> OLD.control_sequence
     OR NEW.max_signatures <> OLD.max_signatures
     OR NEW.created_at <> OLD.created_at
     OR NEW.not_before <> OLD.not_before
     OR NEW.expires_at <> OLD.expires_at THEN
    RAISE EXCEPTION USING
      ERRCODE = 'check_violation',
      MESSAGE = 'agent session identity is immutable',
      CONSTRAINT = 'agent_sessions_identity_immutable';
  END IF;

  IF NEW.used_signatures < OLD.used_signatures
     OR NEW.reserved_signatures < 0
     OR NEW.used_signatures > NEW.max_signatures
     OR NEW.used_signatures + NEW.reserved_signatures > NEW.max_signatures THEN
    RAISE EXCEPTION USING
      ERRCODE = 'check_violation',
      MESSAGE = 'agent session signature budget cannot move backwards or exceed max',
      CONSTRAINT = 'agent_sessions_signature_budget';
  END IF;

  IF NEW.status = OLD.status AND (
    NEW.used_signatures <> OLD.used_signatures
    OR NEW.reserved_signatures <> OLD.reserved_signatures
    OR NEW.active_request_id IS DISTINCT FROM OLD.active_request_id
    OR NEW.last_request_id IS DISTINCT FROM OLD.last_request_id
    OR NEW.closed_at IS DISTINCT FROM OLD.closed_at
    OR NEW.expired_at IS DISTINCT FROM OLD.expired_at
    OR NEW.revoked_at IS DISTINCT FROM OLD.revoked_at
    OR NEW.process_lost_at IS DISTINCT FROM OLD.process_lost_at
    OR NEW.outcome_unknown_at IS DISTINCT FROM OLD.outcome_unknown_at
  ) THEN
    RAISE EXCEPTION USING
      ERRCODE = 'check_violation',
      MESSAGE = 'agent session state is immutable within a lifecycle state',
      CONSTRAINT = 'agent_sessions_forward_only';
  END IF;

  IF OLD.status = 'challenge_pending' THEN
    allowed_transition := NEW.status IN ('active', 'expired', 'revoked', 'process_lost', 'closed');
  ELSIF OLD.status = 'active' THEN
    allowed_transition := NEW.status IN ('request_reserved', 'expired', 'revoked', 'process_lost', 'closed');
  ELSIF OLD.status = 'request_reserved' THEN
    allowed_transition := NEW.status IN ('signing_intent', 'outcome_unknown', 'expired', 'revoked', 'process_lost', 'closed');
  ELSIF OLD.status = 'signing_intent' THEN
    allowed_transition := NEW.status IN ('signed', 'outcome_unknown');
  ELSIF OLD.status = 'signed' THEN
    allowed_transition := NEW.status IN ('active', 'expired', 'revoked', 'closed');
  ELSE
    allowed_transition := NEW.status = OLD.status;
  END IF;

  IF NEW.status <> OLD.status AND NOT allowed_transition THEN
    RAISE EXCEPTION USING
      ERRCODE = 'check_violation',
      MESSAGE = 'agent session lifecycle transition is not allowed',
      CONSTRAINT = 'agent_sessions_forward_only';
  END IF;

  IF NEW.status IN ('expired', 'revoked') AND clock_timestamp() >= OLD.expires_at
     AND NEW.status = 'revoked' THEN
    RAISE EXCEPTION USING
      ERRCODE = 'check_violation',
      MESSAGE = 'expired sessions must transition to expired, not revoked',
      CONSTRAINT = 'agent_sessions_expiry_forward_only';
  END IF;
  IF NEW.status = 'expired' AND clock_timestamp() < OLD.expires_at THEN
    RAISE EXCEPTION USING
      ERRCODE = 'check_violation',
      MESSAGE = 'agent session cannot expire before its deadline',
      CONSTRAINT = 'agent_sessions_expiry_forward_only';
  END IF;

  IF OLD.status = 'challenge_pending' AND NEW.status = 'active' THEN
    IF NEW.used_signatures <> 0
       OR NEW.reserved_signatures <> 0
       OR NEW.active_request_id IS NOT NULL
       OR NEW.last_request_id IS NOT NULL THEN
      RAISE EXCEPTION USING
        ERRCODE = 'check_violation',
        MESSAGE = 'new agent sessions must start with an empty signature budget',
        CONSTRAINT = 'agent_sessions_signature_budget';
    END IF;
  ELSIF OLD.status = 'active' AND NEW.status = 'request_reserved' THEN
    IF NEW.reserved_signatures <> OLD.reserved_signatures + 1
       OR NEW.used_signatures <> OLD.used_signatures
       OR NEW.active_request_id IS NULL
       OR NEW.active_request_id = OLD.last_request_id THEN
      RAISE EXCEPTION USING
        ERRCODE = 'check_violation',
        MESSAGE = 'signature reservation must be one bounded request',
        CONSTRAINT = 'agent_sessions_signature_budget';
    END IF;
  ELSIF OLD.status = 'request_reserved' AND NEW.status = 'signing_intent' THEN
    IF NEW.active_request_id IS NULL
       OR NEW.active_request_id <> OLD.active_request_id
       OR NEW.reserved_signatures <> OLD.reserved_signatures
       OR NEW.used_signatures <> OLD.used_signatures THEN
      RAISE EXCEPTION USING
        ERRCODE = 'check_violation',
        MESSAGE = 'signing intent must retain its reserved request',
        CONSTRAINT = 'agent_sessions_request_binding';
    END IF;
  ELSIF OLD.status = 'signing_intent' AND NEW.status = 'signed' THEN
    IF NEW.active_request_id IS NOT NULL
       OR NEW.last_request_id IS DISTINCT FROM OLD.active_request_id
       OR NEW.used_signatures <> OLD.used_signatures + 1
       OR NEW.reserved_signatures <> OLD.reserved_signatures - 1 THEN
      RAISE EXCEPTION USING
        ERRCODE = 'check_violation',
        MESSAGE = 'signed session must consume exactly one reservation',
        CONSTRAINT = 'agent_sessions_signature_budget';
    END IF;
  ELSIF OLD.status = 'signing_intent' AND NEW.status = 'outcome_unknown' THEN
    IF NEW.active_request_id IS NOT NULL
       OR NEW.last_request_id IS DISTINCT FROM OLD.active_request_id
       OR NEW.reserved_signatures <> 0 THEN
      RAISE EXCEPTION USING
        ERRCODE = 'check_violation',
        MESSAGE = 'outcome-unknown session must close the active request',
        CONSTRAINT = 'agent_sessions_outcome_unknown';
    END IF;
  ELSIF OLD.status = 'request_reserved' AND NEW.status = 'outcome_unknown' THEN
    IF NEW.active_request_id IS NOT NULL
       OR NEW.last_request_id IS DISTINCT FROM OLD.active_request_id
       OR NEW.reserved_signatures <> 0 THEN
      RAISE EXCEPTION USING
        ERRCODE = 'check_violation',
        MESSAGE = 'outcome-unknown session must close the active request',
        CONSTRAINT = 'agent_sessions_outcome_unknown';
    END IF;
  END IF;

  IF NEW.status IN ('closed', 'expired', 'revoked', 'process_lost')
     AND NEW.reserved_signatures <> 0 THEN
    RAISE EXCEPTION USING
      ERRCODE = 'check_violation',
      MESSAGE = 'terminal agent sessions cannot retain a signature reservation',
      CONSTRAINT = 'agent_sessions_signature_budget';
  END IF;

  IF OLD.status IN ('closed', 'expired', 'revoked', 'process_lost', 'outcome_unknown')
     AND NEW.status <> OLD.status THEN
    RAISE EXCEPTION USING
      ERRCODE = 'check_violation',
      MESSAGE = 'terminal agent sessions cannot be reactivated',
      CONSTRAINT = 'agent_sessions_forward_only';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER agent_sessions_forward_only
  BEFORE UPDATE OR DELETE ON agent_sessions
  FOR EACH ROW
  EXECUTE FUNCTION agentpass_guard_agent_session_forward_only();

-- Complete the one-to-one grant/session identity after both tables exist. It
-- is deferred so the INSERT trigger can consume a grant before the new
-- session row becomes visible, while COMMIT still requires both rows.
ALTER TABLE agent_session_grants
  ADD CONSTRAINT agent_session_grants_consumed_session_fk
    FOREIGN KEY (organization_id, consumed_session_id)
    REFERENCES agent_sessions(organization_id, session_id)
    DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE agent_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_sessions FORCE ROW LEVEL SECURITY;

CREATE POLICY agent_sessions_tenant_select
  ON agent_sessions FOR SELECT
  USING (organization_id = agentpass_current_organization_id());

CREATE POLICY agent_sessions_tenant_insert
  ON agent_sessions FOR INSERT
  WITH CHECK (organization_id = agentpass_current_organization_id());

CREATE POLICY agent_sessions_tenant_update
  ON agent_sessions FOR UPDATE
  USING (organization_id = agentpass_current_organization_id())
  WITH CHECK (organization_id = agentpass_current_organization_id());

CREATE POLICY agent_sessions_tenant_delete
  ON agent_sessions FOR DELETE
  USING (organization_id = agentpass_current_organization_id());

COMMIT;
