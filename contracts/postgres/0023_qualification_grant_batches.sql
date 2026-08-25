BEGIN;

-- A qualification batch is a Human/WebAuthn-authorized container for exactly
-- seven normal agent_session_grants.  The batch tables never contain a
-- private key, bearer token, WebAuthn assertion, or a second Grant format.
-- Batch steps point at the existing agent_session_grants rows and therefore
-- remain consumable by the normal Agent Session API.

-- These composite identities make every new foreign key tenant-qualified.
ALTER TABLE human_sessions
  ADD CONSTRAINT human_sessions_organization_id_id_unique
    UNIQUE (organization_id, id);

ALTER TABLE webauthn_challenges
  ADD CONSTRAINT webauthn_challenges_organization_id_id_unique
    UNIQUE (organization_id, id);

ALTER TABLE release_candidates
  ADD CONSTRAINT release_candidates_release_identity_unique
    UNIQUE (source_commit, artifact_sha256, manifest_sha256, team_id);

CREATE TABLE qualification_grant_control_heads (
  organization_id uuid NOT NULL,
  device_id uuid NOT NULL,
  last_control_sequence bigint NOT NULL DEFAULT 0 CHECK (last_control_sequence >= 0),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (organization_id, device_id),
  FOREIGN KEY (organization_id, device_id)
    REFERENCES devices(organization_id, id)
);

CREATE FUNCTION agentpass_guard_qualification_grant_control_head()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
  IF TG_OP = 'DELETE'
     OR NEW.organization_id <> OLD.organization_id
     OR NEW.device_id <> OLD.device_id
     OR NEW.last_control_sequence < OLD.last_control_sequence THEN
    RAISE EXCEPTION USING
      ERRCODE = 'check_violation',
      MESSAGE = 'qualification Grant control sequence heads are forward-only',
      CONSTRAINT = 'qualification_grant_control_heads_forward_only';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER qualification_grant_control_heads_forward_only
  BEFORE UPDATE OR DELETE ON qualification_grant_control_heads
  FOR EACH ROW
  EXECUTE FUNCTION agentpass_guard_qualification_grant_control_head();

CREATE TABLE qualification_grant_batches (
  organization_id uuid NOT NULL,
  batch_id uuid NOT NULL,
  request_id uuid NOT NULL,
  schema_version integer NOT NULL DEFAULT 1 CHECK (schema_version = 1),
  kind text NOT NULL
    CHECK (kind = 'agentpass-n3e-qualification-grant-batch'),
  device_id uuid NOT NULL,
  agent_id uuid NOT NULL,
  agent_kind text NOT NULL CHECK (agent_kind IN ('claude-code', 'cursor')),
  requested_ttl_seconds integer NOT NULL CHECK (requested_ttl_seconds BETWEEN 60 AND 3600),
  candidate_sha256 text NOT NULL CHECK (candidate_sha256 ~ '^[0-9a-f]{64}$'),
  artifact_sha256 text NOT NULL CHECK (artifact_sha256 ~ '^[0-9a-f]{64}$'),
  release_trust_sha256 text NOT NULL CHECK (release_trust_sha256 ~ '^[0-9a-f]{64}$'),
  candidate_checkpoint_sha256 text NOT NULL CHECK (candidate_checkpoint_sha256 ~ '^[0-9a-f]{64}$'),
  source_commit text NOT NULL CHECK (source_commit ~ '^[0-9a-f]{40}$'),
  team_id text NOT NULL CHECK (team_id ~ '^[A-Z0-9]{10}$'),
  manifest_json jsonb NOT NULL
    CHECK (jsonb_typeof(manifest_json) = 'object'
      AND octet_length(manifest_json::text) <= 65536
      AND manifest_json::text !~* '(private[ _-]*key|secret|password|bearer|token|credential|cookie)'),
  manifest_hash text NOT NULL CHECK (manifest_hash ~ '^[0-9a-f]{64}$'),
  manifest_signature_base64url text NOT NULL CHECK (manifest_signature_base64url ~ '^[A-Za-z0-9_-]{86}$'),
  manifest_signer_key_id text NOT NULL
    CHECK (manifest_signer_key_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$'),
  authorized_session_id uuid NOT NULL,
  authorized_member_id uuid NOT NULL,
  authorization_id uuid NOT NULL,
  authorized_at timestamptz NOT NULL,
  status text NOT NULL DEFAULT 'issued'
    CHECK (status IN ('issued', 'claimed', 'expired', 'revoked')),
  issued_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  claimed_at timestamptz,
  expired_at timestamptz,
  revoked_at timestamptz,
  claimed_device_id uuid,
  claim_identity_sha256 text
    CHECK (claim_identity_sha256 IS NULL OR claim_identity_sha256 ~ '^[0-9a-f]{64}$'),
  claim_request_sha256 text
    CHECK (claim_request_sha256 IS NULL OR claim_request_sha256 ~ '^[0-9a-f]{64}$'),
  created_by uuid NOT NULL,
  PRIMARY KEY (organization_id, batch_id),
  UNIQUE (organization_id, request_id),
  FOREIGN KEY (organization_id, device_id)
    REFERENCES devices(organization_id, id),
  FOREIGN KEY (organization_id, agent_id, device_id)
    REFERENCES agents(organization_id, id, device_id),
  FOREIGN KEY (organization_id, authorized_session_id)
    REFERENCES human_sessions(organization_id, id),
  FOREIGN KEY (organization_id, authorized_member_id)
    REFERENCES memberships(organization_id, member_id),
  FOREIGN KEY (organization_id, authorization_id)
    REFERENCES webauthn_challenges(organization_id, id),
  FOREIGN KEY (organization_id, created_by)
    REFERENCES memberships(organization_id, member_id),
  FOREIGN KEY (source_commit, artifact_sha256, release_trust_sha256, team_id)
    REFERENCES release_candidates(source_commit, artifact_sha256, manifest_sha256, team_id),
  CHECK (expires_at > issued_at
    AND expires_at <= issued_at + (requested_ttl_seconds * interval '1 second')),
  CHECK (claimed_at IS NULL OR claimed_at >= issued_at),
  CHECK (claimed_at IS NULL OR claimed_at < expires_at),
  CHECK (expired_at IS NULL OR expired_at >= expires_at),
  CHECK (revoked_at IS NULL OR revoked_at >= issued_at),
  CHECK (
    (status IN ('issued', 'claimed') AND expired_at IS NULL AND revoked_at IS NULL)
    OR (status = 'expired' AND expired_at IS NOT NULL AND revoked_at IS NULL)
    OR (status = 'revoked' AND revoked_at IS NOT NULL AND expired_at IS NULL)
  ),
  CHECK (
    (status = 'issued'
      AND claimed_at IS NULL AND claimed_device_id IS NULL
      AND claim_identity_sha256 IS NULL AND claim_request_sha256 IS NULL)
    OR (status = 'claimed'
      AND claimed_at IS NOT NULL AND claimed_device_id IS NOT NULL
      AND claim_identity_sha256 IS NOT NULL AND claim_request_sha256 IS NOT NULL)
    OR (status IN ('expired', 'revoked')
      AND claimed_at IS NULL AND claimed_device_id IS NULL
      AND claim_identity_sha256 IS NULL AND claim_request_sha256 IS NULL)
  )
);

CREATE INDEX qualification_grant_batches_claim_lookup
  ON qualification_grant_batches (organization_id, device_id, status, expires_at)
  WHERE status IN ('issued', 'claimed');

CREATE TABLE qualification_grant_batch_steps (
  organization_id uuid NOT NULL,
  batch_id uuid NOT NULL,
  step_index integer NOT NULL CHECK (step_index BETWEEN 0 AND 6),
  kind text NOT NULL CHECK (kind IN ('unarmed-control', 'scenario')),
  scenario text,
  phase text,
  run_binding text NOT NULL
    CHECK (run_binding ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
  grant_id uuid NOT NULL,
  device_id uuid NOT NULL,
  agent_id uuid NOT NULL,
  grant_hash text NOT NULL CHECK (grant_hash ~ '^[0-9a-f]{64}$'),
  statement_hash text NOT NULL CHECK (statement_hash ~ '^[0-9a-f]{64}$'),
  PRIMARY KEY (organization_id, batch_id, step_index),
  UNIQUE (organization_id, grant_id),
  UNIQUE (organization_id, batch_id, run_binding),
  FOREIGN KEY (organization_id, batch_id)
    REFERENCES qualification_grant_batches(organization_id, batch_id)
    DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY (organization_id, grant_id, device_id, agent_id, grant_hash)
    REFERENCES agent_session_grants(organization_id, grant_id, device_id, agent_id, grant_hash)
    DEFERRABLE INITIALLY DEFERRED,
  CHECK ((kind = 'unarmed-control' AND step_index = 0 AND scenario IS NULL AND phase IS NULL)
    OR (kind = 'scenario' AND step_index > 0 AND scenario IS NOT NULL AND phase IS NOT NULL))
);

CREATE INDEX qualification_grant_batch_steps_order
  ON qualification_grant_batch_steps (organization_id, batch_id, step_index);

CREATE FUNCTION agentpass_validate_qualification_grant_batch_authorization()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM human_sessions session
    JOIN memberships membership
      ON membership.organization_id = session.organization_id
     AND membership.id = session.membership_id
     AND membership.member_id = NEW.authorized_member_id
     AND membership.status = 'active'
     AND membership.role IN ('owner', 'admin')
    JOIN webauthn_challenges challenge
      ON challenge.organization_id = session.organization_id
     AND challenge.id = NEW.authorization_id
     AND challenge.session_id = session.id
     AND challenge.member_id = NEW.authorized_member_id
     AND challenge.operation = 'qualification.grant_batch.issue'
    WHERE session.organization_id = NEW.organization_id
      AND session.id = NEW.authorized_session_id
      AND session.member_id = NEW.authorized_member_id
      AND session.role = membership.role
      AND session.revoked_at IS NULL
      AND session.expires_at > NEW.authorized_at
      AND session.recent_auth_challenge_id = NEW.authorization_id
      AND session.recent_auth_organization_id = NEW.organization_id
      AND session.recent_auth_operation = 'qualification.grant_batch.issue'
      AND session.recent_auth_at = NEW.authorized_at
      AND session.recent_auth_consumed_at IS NOT NULL
  ) THEN
    RAISE EXCEPTION USING
      ERRCODE = 'check_violation',
      MESSAGE = 'qualification Grant batch requires a current Human/WebAuthn authorization',
      CONSTRAINT = 'qualification_grant_batches_webauthn_authorization';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER qualification_grant_batches_webauthn_authorization
  BEFORE INSERT ON qualification_grant_batches
  FOR EACH ROW
  EXECUTE FUNCTION agentpass_validate_qualification_grant_batch_authorization();

CREATE FUNCTION agentpass_validate_qualification_grant_batch_steps()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
DECLARE
  batch_row qualification_grant_batches%ROWTYPE;
  step_count integer;
  distinct_grants integer;
  expected_sequences integer;
BEGIN
  SELECT * INTO batch_row
  FROM qualification_grant_batches
  WHERE organization_id = NEW.organization_id AND batch_id = NEW.batch_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE = 'foreign_key_violation', MESSAGE = 'qualification Grant batch does not exist';
  END IF;

  SELECT count(*), count(DISTINCT grant_id), count(DISTINCT grant_record.control_sequence)
    INTO step_count, distinct_grants, expected_sequences
  FROM qualification_grant_batch_steps step
  JOIN agent_session_grants grant_record
    ON grant_record.organization_id = step.organization_id
   AND grant_record.grant_id = step.grant_id
  WHERE step.organization_id = NEW.organization_id AND step.batch_id = NEW.batch_id;

  IF step_count <> 7 OR distinct_grants <> 7 OR expected_sequences <> 7 THEN
    RAISE EXCEPTION USING
      ERRCODE = 'check_violation',
      MESSAGE = 'qualification Grant batches must contain exactly seven distinct Grants and sequences',
      CONSTRAINT = 'qualification_grant_batches_exactly_seven_steps';
  END IF;

  IF EXISTS (
    SELECT 1
    FROM qualification_grant_batch_steps step
    JOIN agent_session_grants grant_record
      ON grant_record.organization_id = step.organization_id
     AND grant_record.grant_id = step.grant_id
    WHERE step.organization_id = NEW.organization_id AND step.batch_id = NEW.batch_id
      AND (grant_record.status <> 'issued'
        OR step.device_id <> batch_row.device_id
        OR step.agent_id <> batch_row.agent_id
        OR grant_record.device_id <> batch_row.device_id
        OR grant_record.agent_id <> batch_row.agent_id
        OR grant_record.agent_kind <> batch_row.agent_kind
        OR grant_record.grant_hash <> step.grant_hash
        OR grant_record.statement_hash <> step.statement_hash
        OR grant_record.expires_at <= grant_record.not_before)
  ) THEN
    RAISE EXCEPTION USING
      ERRCODE = 'check_violation',
      MESSAGE = 'qualification Grant batch step does not match its existing Agent Session Grant',
      CONSTRAINT = 'qualification_grant_batch_step_grant_binding';
  END IF;

  IF EXISTS (
    SELECT 1
    FROM (
      SELECT grant_record.control_sequence,
        lag(grant_record.control_sequence) OVER (ORDER BY step.step_index) AS previous_sequence
      FROM qualification_grant_batch_steps step
      JOIN agent_session_grants grant_record
        ON grant_record.organization_id = step.organization_id
       AND grant_record.grant_id = step.grant_id
      WHERE step.organization_id = NEW.organization_id AND step.batch_id = NEW.batch_id
    ) ordered
    WHERE ordered.previous_sequence IS NOT NULL
      AND ordered.control_sequence <= ordered.previous_sequence
  ) THEN
    RAISE EXCEPTION USING
      ERRCODE = 'check_violation',
      MESSAGE = 'qualification Grant control sequences must be strictly increasing by step',
      CONSTRAINT = 'qualification_grant_batches_control_sequences_monotonic';
  END IF;

  IF EXISTS (
    SELECT 1
    FROM qualification_grant_batch_steps step
    WHERE step.organization_id = NEW.organization_id AND step.batch_id = NEW.batch_id
      AND ((step.step_index = 0 AND (step.kind <> 'unarmed-control' OR step.scenario IS NOT NULL OR step.phase IS NOT NULL))
        OR (step.step_index > 0 AND (step.kind <> 'scenario' OR step.scenario IS NULL OR step.phase IS NULL)))
  ) THEN
    RAISE EXCEPTION USING
      ERRCODE = 'check_violation',
      MESSAGE = 'qualification Grant batch step order is invalid',
      CONSTRAINT = 'qualification_grant_batches_step_order';
  END IF;
  RETURN NEW;
END;
$$;

CREATE CONSTRAINT TRIGGER qualification_grant_batches_exactly_seven_steps
  AFTER INSERT OR UPDATE ON qualification_grant_batches
  DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW
  EXECUTE FUNCTION agentpass_validate_qualification_grant_batch_steps();

CREATE CONSTRAINT TRIGGER qualification_grant_batch_steps_exactly_seven
  AFTER INSERT OR UPDATE ON qualification_grant_batch_steps
  DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW
  EXECUTE FUNCTION agentpass_validate_qualification_grant_batch_steps();

CREATE FUNCTION agentpass_guard_qualification_grant_batch_forward_only()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION USING
      ERRCODE = 'check_violation',
      MESSAGE = 'qualification Grant batches cannot be deleted',
      CONSTRAINT = 'qualification_grant_batches_forward_only';
  END IF;

  IF NEW.organization_id <> OLD.organization_id
     OR NEW.batch_id <> OLD.batch_id
     OR NEW.request_id <> OLD.request_id
     OR NEW.schema_version <> OLD.schema_version
     OR NEW.kind <> OLD.kind
     OR NEW.device_id <> OLD.device_id
     OR NEW.agent_id <> OLD.agent_id
     OR NEW.agent_kind <> OLD.agent_kind
     OR NEW.requested_ttl_seconds <> OLD.requested_ttl_seconds
     OR NEW.candidate_sha256 <> OLD.candidate_sha256
     OR NEW.artifact_sha256 <> OLD.artifact_sha256
     OR NEW.release_trust_sha256 <> OLD.release_trust_sha256
     OR NEW.candidate_checkpoint_sha256 <> OLD.candidate_checkpoint_sha256
     OR NEW.source_commit <> OLD.source_commit
     OR NEW.team_id <> OLD.team_id
     OR NEW.manifest_json IS DISTINCT FROM OLD.manifest_json
     OR NEW.manifest_hash <> OLD.manifest_hash
     OR NEW.manifest_signature_base64url <> OLD.manifest_signature_base64url
     OR NEW.manifest_signer_key_id <> OLD.manifest_signer_key_id
     OR NEW.authorized_session_id <> OLD.authorized_session_id
     OR NEW.authorized_member_id <> OLD.authorized_member_id
     OR NEW.authorization_id <> OLD.authorization_id
     OR NEW.authorized_at <> OLD.authorized_at
     OR NEW.issued_at <> OLD.issued_at
     OR NEW.expires_at <> OLD.expires_at
     OR NEW.created_by <> OLD.created_by THEN
    RAISE EXCEPTION USING
      ERRCODE = 'check_violation',
      MESSAGE = 'qualification Grant batch identity is immutable',
      CONSTRAINT = 'qualification_grant_batches_identity_immutable';
  END IF;

  IF OLD.status = 'issued' THEN
    IF NEW.status = 'claimed' THEN
      IF NEW.claimed_at IS NULL OR NEW.claimed_device_id IS NULL
         OR NEW.claim_identity_sha256 IS NULL OR NEW.claim_request_sha256 IS NULL
         OR NEW.expired_at IS NOT NULL OR NEW.revoked_at IS NOT NULL
         OR clock_timestamp() >= OLD.expires_at THEN
        RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'qualification Grant batch cannot be claimed outside its window';
      END IF;
    ELSIF NEW.status = 'expired' THEN
      IF NEW.expired_at IS NULL
         OR clock_timestamp() < OLD.expires_at THEN
        RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'qualification Grant batch cannot expire before its deadline';
      END IF;
    ELSIF NEW.status <> 'revoked' THEN
      IF NEW.status <> OLD.status THEN
        RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'qualification Grant batch lifecycle transition is invalid';
      END IF;
    END IF;
  ELSIF NEW.status <> OLD.status THEN
    RAISE EXCEPTION USING
      ERRCODE = 'check_violation',
      MESSAGE = 'terminal qualification Grant batches cannot be reopened',
      CONSTRAINT = 'qualification_grant_batches_forward_only';
  END IF;

  IF NEW.status = OLD.status
     AND (NEW.claimed_at IS DISTINCT FROM OLD.claimed_at
       OR NEW.expired_at IS DISTINCT FROM OLD.expired_at
       OR NEW.revoked_at IS DISTINCT FROM OLD.revoked_at
       OR NEW.claimed_device_id IS DISTINCT FROM OLD.claimed_device_id
       OR NEW.claim_identity_sha256 IS DISTINCT FROM OLD.claim_identity_sha256
       OR NEW.claim_request_sha256 IS DISTINCT FROM OLD.claim_request_sha256) THEN
    RAISE EXCEPTION USING
      ERRCODE = 'check_violation',
      MESSAGE = 'qualification Grant batch lifecycle fields are immutable within a state',
      CONSTRAINT = 'qualification_grant_batches_forward_only';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER qualification_grant_batches_forward_only
  BEFORE UPDATE OR DELETE ON qualification_grant_batches
  FOR EACH ROW
  EXECUTE FUNCTION agentpass_guard_qualification_grant_batch_forward_only();

CREATE FUNCTION agentpass_guard_qualification_grant_batch_step_immutable()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
  RAISE EXCEPTION USING
    ERRCODE = 'check_violation',
    MESSAGE = 'qualification Grant batch steps are immutable',
    CONSTRAINT = 'qualification_grant_batch_steps_immutable';
END;
$$;

CREATE TRIGGER qualification_grant_batch_steps_immutable
  BEFORE UPDATE OR DELETE ON qualification_grant_batch_steps
  FOR EACH ROW
  EXECUTE FUNCTION agentpass_guard_qualification_grant_batch_step_immutable();

ALTER TABLE qualification_grant_control_heads ENABLE ROW LEVEL SECURITY;
ALTER TABLE qualification_grant_control_heads FORCE ROW LEVEL SECURITY;
CREATE POLICY qualification_grant_control_heads_tenant_select
  ON qualification_grant_control_heads FOR SELECT
  USING (organization_id = agentpass_current_organization_id());
CREATE POLICY qualification_grant_control_heads_tenant_insert
  ON qualification_grant_control_heads FOR INSERT
  WITH CHECK (organization_id = agentpass_current_organization_id());
CREATE POLICY qualification_grant_control_heads_tenant_update
  ON qualification_grant_control_heads FOR UPDATE
  USING (organization_id = agentpass_current_organization_id())
  WITH CHECK (organization_id = agentpass_current_organization_id());

ALTER TABLE qualification_grant_batches ENABLE ROW LEVEL SECURITY;
ALTER TABLE qualification_grant_batches FORCE ROW LEVEL SECURITY;
CREATE POLICY qualification_grant_batches_tenant_select
  ON qualification_grant_batches FOR SELECT
  USING (organization_id = agentpass_current_organization_id());
CREATE POLICY qualification_grant_batches_tenant_insert
  ON qualification_grant_batches FOR INSERT
  WITH CHECK (organization_id = agentpass_current_organization_id());
CREATE POLICY qualification_grant_batches_tenant_update
  ON qualification_grant_batches FOR UPDATE
  USING (organization_id = agentpass_current_organization_id())
  WITH CHECK (organization_id = agentpass_current_organization_id());

ALTER TABLE qualification_grant_batch_steps ENABLE ROW LEVEL SECURITY;
ALTER TABLE qualification_grant_batch_steps FORCE ROW LEVEL SECURITY;
CREATE POLICY qualification_grant_batch_steps_tenant_select
  ON qualification_grant_batch_steps FOR SELECT
  USING (organization_id = agentpass_current_organization_id());
CREATE POLICY qualification_grant_batch_steps_tenant_insert
  ON qualification_grant_batch_steps FOR INSERT
  WITH CHECK (organization_id = agentpass_current_organization_id());

COMMIT;
