BEGIN;

-- M2 tenant context. Application transactions must set this with SET LOCAL
-- before touching an M2 table. An absent or malformed context matches no row.
-- The function is intentionally invoker-security scoped; it never derives a
-- tenant from request data or from a row being queried.
CREATE FUNCTION agentpass_current_organization_id()
RETURNS uuid
LANGUAGE plpgsql
STABLE
SET search_path = pg_catalog
AS $$
DECLARE
  configured text;
BEGIN
  configured := current_setting('agentpass.organization_id', true);
  IF configured IS NULL OR configured = '' THEN
    RETURN NULL;
  END IF;
  RETURN configured::uuid;
EXCEPTION WHEN invalid_text_representation THEN
  RETURN NULL;
END;
$$;

CREATE FUNCTION agentpass_public_scope_json_valid(scope_value jsonb)
RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
SET search_path = pg_catalog
AS $$
BEGIN
  IF jsonb_typeof(scope_value) <> 'object'
     OR octet_length(scope_value::text) > 16384
     OR scope_value::text ~* '(private[ _-]*key|secret|password|bearer|token|credential|authorization|cookie|api[ _-]*key|refresh[ _-]*key|BEGIN[[:space:]]+[^-]*PRIVATE[[:space:]]+KEY)' THEN
    RETURN false;
  END IF;
  RETURN true;
END;
$$;

-- agents already carry device_id, but their primary key does not include it.
-- This unique identity is the target of the composite grant/session foreign
-- keys below and prevents an agent from being rebound across devices.
ALTER TABLE agents
  ADD CONSTRAINT agents_tenant_device_identity
    UNIQUE (organization_id, id, device_id);

CREATE TABLE agent_session_grants (
  organization_id uuid NOT NULL,
  grant_id uuid NOT NULL,
  device_id uuid NOT NULL,
  agent_id uuid NOT NULL,
  agent_kind text NOT NULL
    CHECK (agent_kind IN ('claude-code', 'cursor')),
  adapter_id uuid NOT NULL,
  adapter_version text NOT NULL
    CHECK (adapter_version ~ '^(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$'),
  worktree_binding_sha256 text NOT NULL
    CHECK (worktree_binding_sha256 ~ '^[0-9a-f]{64}$'),
  process_binding_policy_id text NOT NULL
    CHECK (process_binding_policy_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$'),
  scope_json jsonb NOT NULL
    CHECK (agentpass_public_scope_json_valid(scope_json)),
  max_signatures integer NOT NULL
    CHECK (max_signatures BETWEEN 1 AND 64),
  not_before timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  control_sequence bigint NOT NULL CHECK (control_sequence > 0),
  issuer text NOT NULL
    CHECK (issuer IN ('agentpass-cloud')),
  signer_key_id text NOT NULL
    CHECK (char_length(signer_key_id) BETWEEN 1 AND 64
      AND signer_key_id !~ '[[:cntrl:]]'),
  statement_hash text NOT NULL
    CHECK (statement_hash ~ '^[0-9a-f]{64}$'),
  grant_hash text NOT NULL
    CHECK (grant_hash ~ '^[0-9a-f]{64}$'),
  signature_base64url text NOT NULL
    CHECK (signature_base64url ~ '^[A-Za-z0-9_-]{86}$'),
  status text NOT NULL DEFAULT 'issued'
    CHECK (status IN ('issued', 'consumed', 'expired', 'revoked')),
  issued_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  consumed_at timestamptz,
  consumed_session_id uuid,
  consumed_process_binding_sha256 text
    CHECK (consumed_process_binding_sha256 IS NULL
      OR consumed_process_binding_sha256 ~ '^[0-9a-f]{64}$'),
  expired_at timestamptz,
  revoked_at timestamptz,
  created_by uuid NOT NULL,
  PRIMARY KEY (organization_id, grant_id),
  UNIQUE (organization_id, grant_id, device_id, agent_id),
  UNIQUE (organization_id, grant_id, device_id, agent_id, grant_hash),
  UNIQUE (organization_id, consumed_session_id),
  FOREIGN KEY (organization_id) REFERENCES organizations(id),
  FOREIGN KEY (organization_id, device_id) REFERENCES devices(organization_id, id),
  FOREIGN KEY (organization_id, agent_id, device_id)
    REFERENCES agents(organization_id, id, device_id),
  FOREIGN KEY (organization_id, created_by)
    REFERENCES memberships(organization_id, member_id),
  -- Signing necessarily precedes INSERT by a small amount. Permit only a
  -- bounded future not-before skew; requiring not_before >= issued_at would
  -- reject normally signed grants as soon as the database clock advances.
  CHECK (not_before <= issued_at + interval '5 minutes'),
  CHECK (expires_at > not_before),
  CHECK (expires_at > issued_at),
  CHECK (
    (status = 'issued'
      AND consumed_at IS NULL AND consumed_session_id IS NULL
      AND consumed_process_binding_sha256 IS NULL
      AND expired_at IS NULL AND revoked_at IS NULL)
    OR
    (status = 'consumed'
      AND consumed_at IS NOT NULL AND consumed_session_id IS NOT NULL
      AND consumed_process_binding_sha256 IS NOT NULL
      AND expired_at IS NULL AND revoked_at IS NULL
      AND consumed_at >= not_before AND consumed_at <= expires_at)
    OR
    (status = 'expired'
      AND consumed_at IS NULL AND consumed_session_id IS NULL
      AND consumed_process_binding_sha256 IS NULL
      AND expired_at IS NOT NULL AND revoked_at IS NULL
      AND expired_at >= expires_at)
    OR
    (status = 'revoked'
      AND consumed_at IS NULL AND consumed_session_id IS NULL
      AND consumed_process_binding_sha256 IS NULL
      AND expired_at IS NULL AND revoked_at IS NOT NULL
      AND revoked_at >= issued_at)
  )
);

CREATE INDEX agent_session_grants_issued_expiry
  ON agent_session_grants (organization_id, expires_at, grant_id)
  WHERE status = 'issued';

CREATE INDEX agent_session_grants_agent_lookup
  ON agent_session_grants (organization_id, agent_id, device_id, issued_at DESC, grant_id);

CREATE INDEX agent_session_grants_consumed_session_lookup
  ON agent_session_grants (organization_id, consumed_session_id)
  WHERE consumed_session_id IS NOT NULL;

CREATE UNIQUE INDEX agent_session_grants_consumed_binding
  ON agent_session_grants (organization_id, grant_hash, consumed_process_binding_sha256)
  WHERE status = 'consumed';

-- Grant identity and the signed public statement are immutable. Only the
-- forward lifecycle transition is writable; terminal rows cannot be reopened,
-- deleted, or rewritten. Expiration is checked against the database clock so
-- a caller cannot mark a live grant expired early or consume an expired one.
CREATE FUNCTION agentpass_guard_agent_session_grant_forward_only()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION USING
      ERRCODE = 'check_violation',
      MESSAGE = 'agent session grants cannot be deleted',
      CONSTRAINT = 'agent_session_grants_forward_only';
  END IF;

  IF NEW.organization_id <> OLD.organization_id
     OR NEW.grant_id <> OLD.grant_id
     OR NEW.device_id <> OLD.device_id
     OR NEW.agent_id <> OLD.agent_id
     OR NEW.agent_kind <> OLD.agent_kind
     OR NEW.adapter_id <> OLD.adapter_id
     OR NEW.adapter_version <> OLD.adapter_version
     OR NEW.worktree_binding_sha256 <> OLD.worktree_binding_sha256
     OR NEW.process_binding_policy_id <> OLD.process_binding_policy_id
     OR NEW.scope_json IS DISTINCT FROM OLD.scope_json
     OR NEW.max_signatures <> OLD.max_signatures
     OR NEW.not_before <> OLD.not_before
     OR NEW.expires_at <> OLD.expires_at
     OR NEW.control_sequence <> OLD.control_sequence
     OR NEW.issuer <> OLD.issuer
     OR NEW.signer_key_id <> OLD.signer_key_id
     OR NEW.statement_hash <> OLD.statement_hash
      OR NEW.grant_hash <> OLD.grant_hash
     OR NEW.signature_base64url <> OLD.signature_base64url
      OR NEW.issued_at <> OLD.issued_at
     OR NEW.created_by <> OLD.created_by THEN
    RAISE EXCEPTION USING
      ERRCODE = 'check_violation',
      MESSAGE = 'agent session grant identity is immutable',
      CONSTRAINT = 'agent_session_grants_identity_immutable';
  END IF;

  IF OLD.status <> NEW.status THEN
    IF OLD.status <> 'issued' OR NEW.status NOT IN ('consumed', 'expired', 'revoked') THEN
      RAISE EXCEPTION USING
        ERRCODE = 'check_violation',
        MESSAGE = 'agent session grant lifecycle cannot be reactivated',
        CONSTRAINT = 'agent_session_grants_forward_only';
    END IF;

    IF NEW.status = 'consumed' THEN
      IF NEW.consumed_session_id IS NULL OR NEW.consumed_at IS NULL
         OR NEW.consumed_at < NEW.not_before
         OR NEW.consumed_at > NEW.expires_at
         OR clock_timestamp() < NEW.not_before
         OR clock_timestamp() >= NEW.expires_at THEN
        RAISE EXCEPTION USING
          ERRCODE = 'check_violation',
          MESSAGE = 'agent session grant is outside its consumption window',
          CONSTRAINT = 'agent_session_grants_consumption_window';
      END IF;
    ELSIF NEW.status = 'expired' THEN
      IF NEW.expired_at IS NULL OR clock_timestamp() < OLD.expires_at THEN
        RAISE EXCEPTION USING
          ERRCODE = 'check_violation',
          MESSAGE = 'agent session grant cannot expire before its deadline',
          CONSTRAINT = 'agent_session_grants_expiry_forward_only';
      END IF;
    ELSIF NEW.status = 'revoked' AND clock_timestamp() >= OLD.expires_at THEN
      RAISE EXCEPTION USING
        ERRCODE = 'check_violation',
        MESSAGE = 'expired grants must transition to expired, not revoked',
        CONSTRAINT = 'agent_session_grants_expiry_forward_only';
    END IF;
  ELSE
    IF NEW.consumed_at IS DISTINCT FROM OLD.consumed_at
       OR NEW.consumed_session_id IS DISTINCT FROM OLD.consumed_session_id
       OR NEW.consumed_process_binding_sha256 IS DISTINCT FROM OLD.consumed_process_binding_sha256
       OR NEW.expired_at IS DISTINCT FROM OLD.expired_at
       OR NEW.revoked_at IS DISTINCT FROM OLD.revoked_at THEN
      RAISE EXCEPTION USING
        ERRCODE = 'check_violation',
        MESSAGE = 'agent session grant lifecycle fields are immutable within a state',
        CONSTRAINT = 'agent_session_grants_forward_only';
    END IF;
  END IF;

  IF OLD.status <> 'issued' AND NEW.status <> OLD.status THEN
    RAISE EXCEPTION USING
      ERRCODE = 'check_violation',
      MESSAGE = 'terminal agent session grants cannot be reopened',
      CONSTRAINT = 'agent_session_grants_forward_only';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER agent_session_grants_forward_only
  BEFORE UPDATE OR DELETE ON agent_session_grants
  FOR EACH ROW
  EXECUTE FUNCTION agentpass_guard_agent_session_grant_forward_only();

ALTER TABLE agent_session_grants ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_session_grants FORCE ROW LEVEL SECURITY;

CREATE POLICY agent_session_grants_tenant_select
  ON agent_session_grants FOR SELECT
  USING (organization_id = agentpass_current_organization_id());

CREATE POLICY agent_session_grants_tenant_insert
  ON agent_session_grants FOR INSERT
  WITH CHECK (organization_id = agentpass_current_organization_id());

CREATE POLICY agent_session_grants_tenant_update
  ON agent_session_grants FOR UPDATE
  USING (organization_id = agentpass_current_organization_id())
  WITH CHECK (organization_id = agentpass_current_organization_id());

CREATE POLICY agent_session_grants_tenant_delete
  ON agent_session_grants FOR DELETE
  USING (organization_id = agentpass_current_organization_id());

COMMIT;
