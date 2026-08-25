BEGIN;

CREATE TABLE schema_migrations (
  version bigint PRIMARY KEY,
  checksum text NOT NULL CHECK (checksum ~ '^[0-9a-f]{64}$'),
  applied_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE organizations (
  id uuid PRIMARY KEY,
  name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 128),
  version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE members (
  id uuid PRIMARY KEY,
  github_subject text NOT NULL UNIQUE CHECK (char_length(github_subject) BETWEEN 1 AND 255),
  display_name text CHECK (display_name IS NULL OR char_length(display_name) <= 128),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE memberships (
  organization_id uuid NOT NULL REFERENCES organizations(id),
  id uuid NOT NULL,
  member_id uuid NOT NULL REFERENCES members(id),
  role text NOT NULL CHECK (role IN ('owner', 'admin', 'auditor', 'viewer')),
  status text NOT NULL CHECK (status IN ('active', 'revoked')),
  version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (organization_id, id),
  UNIQUE (organization_id, member_id)
);

CREATE TABLE human_sessions (
  id uuid PRIMARY KEY,
  member_id uuid NOT NULL REFERENCES members(id),
  token_hash bytea NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
  created_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL CHECK (expires_at > created_at),
  recent_auth_at timestamptz,
  revoked_at timestamptz
);

CREATE TABLE webauthn_credentials (
  id bytea PRIMARY KEY CHECK (octet_length(id) BETWEEN 16 AND 1024),
  member_id uuid NOT NULL REFERENCES members(id),
  public_key bytea NOT NULL CHECK (octet_length(public_key) BETWEEN 32 AND 4096),
  sign_count bigint NOT NULL DEFAULT 0 CHECK (sign_count >= 0),
  transports text[] NOT NULL DEFAULT '{}',
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  last_used_at timestamptz,
  revoked_at timestamptz
);

CREATE TABLE devices (
  organization_id uuid NOT NULL REFERENCES organizations(id),
  id uuid NOT NULL,
  label text NOT NULL CHECK (char_length(label) BETWEEN 1 AND 128),
  key_algorithm text NOT NULL CHECK (key_algorithm IN ('p256-sha256', 'ed25519')),
  public_key_pem text,
  status text NOT NULL CHECK (status IN ('pending', 'active', 'disabled', 'revoked')),
  version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  last_seen_at timestamptz,
  PRIMARY KEY (organization_id, id),
  CHECK ((status = 'pending' AND public_key_pem IS NULL) OR (status <> 'pending' AND public_key_pem LIKE '-----BEGIN PUBLIC KEY-----%')),
  UNIQUE (organization_id, public_key_pem)
);

CREATE TABLE device_enrollments (
  id uuid PRIMARY KEY,
  organization_id uuid NOT NULL REFERENCES organizations(id),
  device_id uuid NOT NULL,
  secret_hash bytea NOT NULL UNIQUE CHECK (octet_length(secret_hash) = 32),
  created_by uuid NOT NULL REFERENCES members(id),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz,
  CHECK (expires_at > created_at),
  FOREIGN KEY (organization_id, device_id) REFERENCES devices(organization_id, id)
);

CREATE TABLE agents (
  organization_id uuid NOT NULL,
  id uuid NOT NULL,
  device_id uuid NOT NULL,
  kind text NOT NULL CHECK (kind IN ('claude-code', 'cursor', 'mcp', 'cli', 'custom')),
  name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 128),
  public_key_pem text NOT NULL,
  status text NOT NULL CHECK (status IN ('active', 'revoked')),
  version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  last_seen_at timestamptz,
  PRIMARY KEY (organization_id, id),
  FOREIGN KEY (organization_id, device_id) REFERENCES devices(organization_id, id),
  UNIQUE (organization_id, public_key_pem)
);

CREATE TABLE policies (
  organization_id uuid NOT NULL REFERENCES organizations(id),
  id uuid NOT NULL,
  sequence bigint NOT NULL CHECK (sequence > 0),
  name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 128),
  scope_json jsonb NOT NULL CHECK (jsonb_typeof(scope_json) = 'object'),
  status text NOT NULL CHECK (status IN ('active', 'disabled')),
  created_by uuid NOT NULL REFERENCES members(id),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (organization_id, id),
  UNIQUE (organization_id, sequence),
  UNIQUE (organization_id, name)
);

CREATE TABLE revocations (
  organization_id uuid NOT NULL REFERENCES organizations(id),
  id uuid NOT NULL,
  target_type text NOT NULL CHECK (target_type IN ('organization', 'device', 'agent', 'capability')),
  target_id uuid,
  sequence bigint NOT NULL CHECK (sequence > 0),
  reason text NOT NULL CHECK (char_length(reason) BETWEEN 1 AND 256),
  status text NOT NULL CHECK (status IN ('active', 'superseded')),
  created_by uuid NOT NULL REFERENCES members(id),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (organization_id, id),
  UNIQUE (organization_id, sequence),
  CHECK ((target_type = 'organization' AND target_id IS NULL) OR (target_type <> 'organization' AND target_id IS NOT NULL))
);

CREATE TABLE capabilities (
  organization_id uuid NOT NULL REFERENCES organizations(id),
  id uuid NOT NULL,
  agent_id uuid NOT NULL,
  device_id uuid NOT NULL,
  sequence bigint NOT NULL CHECK (sequence > 0),
  statement_hash text NOT NULL CHECK (statement_hash ~ '^[0-9a-f]{64}$'),
  expires_at timestamptz NOT NULL,
  revoked_at timestamptz,
  PRIMARY KEY (organization_id, id),
  UNIQUE (organization_id, agent_id, sequence),
  FOREIGN KEY (organization_id, agent_id) REFERENCES agents(organization_id, id),
  FOREIGN KEY (organization_id, device_id) REFERENCES devices(organization_id, id)
);

CREATE TABLE bundle_heads (
  organization_id uuid NOT NULL,
  device_id uuid NOT NULL,
  format_epoch integer NOT NULL CHECK (format_epoch >= 2),
  sequence bigint NOT NULL CHECK (sequence > 0),
  statement_hash text NOT NULL CHECK (statement_hash ~ '^[0-9a-f]{64}$'),
  issued_at timestamptz NOT NULL,
  PRIMARY KEY (organization_id, device_id),
  UNIQUE (organization_id, device_id, format_epoch, sequence, statement_hash),
  FOREIGN KEY (organization_id, device_id) REFERENCES devices(organization_id, id)
);

CREATE TABLE bundle_acknowledgements (
  organization_id uuid NOT NULL,
  device_id uuid NOT NULL,
  format_epoch integer NOT NULL,
  sequence bigint NOT NULL,
  statement_hash text NOT NULL CHECK (statement_hash ~ '^[0-9a-f]{64}$'),
  status text NOT NULL CHECK (status IN ('applied', 'blocked')),
  reason text,
  applied_at timestamptz NOT NULL,
  received_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (organization_id, device_id, format_epoch, sequence),
  FOREIGN KEY (organization_id, device_id) REFERENCES devices(organization_id, id),
  CHECK ((status = 'blocked' AND reason IS NOT NULL) OR status = 'applied')
);

CREATE TABLE device_audit_events (
  organization_id uuid NOT NULL,
  device_id uuid NOT NULL,
  event_id uuid NOT NULL,
  previous_hash text NOT NULL CHECK (previous_hash ~ '^[0-9a-f]{64}$'),
  event_hash text NOT NULL CHECK (event_hash ~ '^[0-9a-f]{64}$'),
  redacted_json jsonb NOT NULL CHECK (jsonb_typeof(redacted_json) = 'object'),
  received_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (organization_id, device_id, event_id),
  UNIQUE (organization_id, device_id, event_hash),
  FOREIGN KEY (organization_id, device_id) REFERENCES devices(organization_id, id)
);

CREATE TABLE idempotency_records (
  organization_id uuid NOT NULL REFERENCES organizations(id),
  principal_id text NOT NULL,
  idempotency_key text NOT NULL CHECK (char_length(idempotency_key) BETWEEN 8 AND 255),
  request_hash text NOT NULL CHECK (request_hash ~ '^[0-9a-f]{64}$'),
  response_status integer NOT NULL CHECK (response_status BETWEEN 100 AND 599),
  response_json jsonb NOT NULL,
  expires_at timestamptz NOT NULL,
  PRIMARY KEY (organization_id, principal_id, idempotency_key)
);

CREATE TABLE admin_audit_events (
  organization_id uuid NOT NULL REFERENCES organizations(id),
  id uuid NOT NULL,
  actor_id uuid NOT NULL REFERENCES members(id),
  action text NOT NULL CHECK (char_length(action) BETWEEN 1 AND 128),
  target_type text NOT NULL CHECK (char_length(target_type) BETWEEN 1 AND 64),
  target_id uuid,
  previous_hash text NOT NULL CHECK (previous_hash ~ '^[0-9a-f]{64}$'),
  event_hash text NOT NULL CHECK (event_hash ~ '^[0-9a-f]{64}$'),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (organization_id, id),
  UNIQUE (organization_id, event_hash)
);

COMMIT;
