BEGIN;

ALTER TABLE schema_migrations
  ADD COLUMN application_version text NOT NULL DEFAULT 'legacy'
    CHECK (char_length(application_version) BETWEEN 1 AND 64);

CREATE TABLE schema_migration_attempts (
  id uuid PRIMARY KEY,
  version bigint NOT NULL,
  checksum text NOT NULL CHECK (checksum ~ '^[0-9a-f]{64}$'),
  application_version text NOT NULL CHECK (char_length(application_version) BETWEEN 1 AND 64),
  status text NOT NULL CHECK (status IN ('running', 'applied', 'failed')),
  started_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  finished_at timestamptz,
  error_code text CHECK (error_code IS NULL OR char_length(error_code) BETWEEN 1 AND 64),
  CHECK ((status = 'running' AND finished_at IS NULL) OR (status <> 'running' AND finished_at IS NOT NULL))
);

CREATE TABLE webauthn_challenges (
  id uuid PRIMARY KEY,
  session_id uuid NOT NULL REFERENCES human_sessions(id) ON DELETE CASCADE,
  member_id uuid NOT NULL REFERENCES members(id),
  organization_id uuid NOT NULL REFERENCES organizations(id),
  ceremony text NOT NULL CHECK (ceremony IN ('registration', 'authentication')),
  operation text NOT NULL CHECK (char_length(operation) BETWEEN 1 AND 128),
  challenge_hash bytea NOT NULL UNIQUE CHECK (octet_length(challenge_hash) = 32),
  created_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL CHECK (expires_at > created_at),
  consumed_at timestamptz,
  CHECK (consumed_at IS NULL OR consumed_at >= created_at)
);

ALTER TABLE human_sessions
  ADD COLUMN organization_id uuid REFERENCES organizations(id),
  ADD COLUMN membership_id uuid,
  ADD COLUMN role text CHECK (role IS NULL OR role IN ('owner', 'admin', 'auditor', 'viewer')),
  ADD COLUMN csrf_token_hash bytea CHECK (csrf_token_hash IS NULL OR octet_length(csrf_token_hash) = 32),
  ADD COLUMN last_seen_at timestamptz,
  ADD COLUMN idle_expires_at timestamptz,
  ADD COLUMN revoke_reason text CHECK (revoke_reason IS NULL OR char_length(revoke_reason) BETWEEN 1 AND 128),
  ADD COLUMN recent_auth_challenge_id uuid REFERENCES webauthn_challenges(id),
  ADD COLUMN recent_auth_organization_id uuid REFERENCES organizations(id),
  ADD COLUMN recent_auth_operation text CHECK (recent_auth_operation IS NULL OR char_length(recent_auth_operation) BETWEEN 1 AND 128),
  ADD COLUMN recent_auth_consumed_at timestamptz,
  ADD CONSTRAINT human_sessions_recent_auth_complete CHECK (
    (recent_auth_at IS NULL AND recent_auth_challenge_id IS NULL AND recent_auth_organization_id IS NULL AND recent_auth_operation IS NULL AND recent_auth_consumed_at IS NULL)
    OR
    (recent_auth_at IS NOT NULL AND recent_auth_challenge_id IS NOT NULL AND recent_auth_organization_id IS NOT NULL AND recent_auth_operation IS NOT NULL)
  ),
  ADD CONSTRAINT human_sessions_membership_fk FOREIGN KEY (organization_id, membership_id) REFERENCES memberships(organization_id, id),
  ADD CONSTRAINT human_sessions_idle_bounds CHECK (idle_expires_at IS NULL OR (idle_expires_at > created_at AND idle_expires_at <= expires_at));

CREATE UNIQUE INDEX webauthn_challenges_one_live_operation
  ON webauthn_challenges (session_id, organization_id, operation)
  WHERE consumed_at IS NULL;

CREATE INDEX webauthn_challenges_expiry
  ON webauthn_challenges (expires_at)
  WHERE consumed_at IS NULL;

COMMIT;
