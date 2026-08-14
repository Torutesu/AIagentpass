BEGIN;

-- Recovery ceremonies are deliberately separate from webauthn_challenges:
-- the latter is owned by a normal human_session, while this table is bound
-- to the restricted, purpose-specific owner_recovery_session. Browser
-- challenge bytes and WebAuthn responses are never durable; only digests and
-- the public credential identifier needed for exact retry are retained.
CREATE TABLE owner_recovery_webauthn_challenges (
  organization_id uuid NOT NULL,
  challenge_id uuid NOT NULL,
  recovery_session_id uuid NOT NULL,
  request_id uuid NOT NULL,
  member_id uuid NOT NULL,
  ceremony text NOT NULL CHECK (ceremony IN ('registration', 'authentication')),
  operation text NOT NULL CHECK (
    (ceremony = 'registration' AND operation = 'human.recovery.credential.register')
    OR (ceremony = 'authentication' AND operation = 'human.recovery.activate')
  ),
  challenge_digest bytea NOT NULL UNIQUE CHECK (octet_length(challenge_digest) = 32),
  rp_id text NOT NULL CHECK (
    char_length(rp_id) BETWEEN 1 AND 253
    AND rp_id ~ '^[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$'
  ),
  origin text NOT NULL CHECK (
    char_length(origin) BETWEEN 9 AND 512
    AND origin ~ '^https://[^/?#@]+(?::[0-9]{1,5})?$'
  ),
  user_verification text NOT NULL CHECK (user_verification = 'required'),
  status text NOT NULL DEFAULT 'pending'
    CHECK (status IN ('pending', 'consuming', 'consumed', 'failed', 'expired')),
  created_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  consume_started_at timestamptz,
  consumed_at timestamptz,
  failed_at timestamptz,
  verified_credential_id bytea
    CHECK (verified_credential_id IS NULL OR octet_length(verified_credential_id) BETWEEN 16 AND 1024),
  authorization_consumed_at timestamptz,
  PRIMARY KEY (organization_id, challenge_id),
  FOREIGN KEY (organization_id, recovery_session_id)
    REFERENCES owner_recovery_sessions(organization_id, recovery_session_id),
  FOREIGN KEY (organization_id, request_id)
    REFERENCES owner_recovery_requests(organization_id, request_id),
  FOREIGN KEY (organization_id, member_id)
    REFERENCES memberships(organization_id, member_id),
  CHECK (expires_at > created_at),
  CHECK (
    (status = 'pending' AND consume_started_at IS NULL AND consumed_at IS NULL AND failed_at IS NULL AND verified_credential_id IS NULL)
    OR (status = 'consuming' AND consume_started_at IS NOT NULL AND consumed_at IS NULL AND failed_at IS NULL AND verified_credential_id IS NULL)
    OR (status = 'consumed' AND consume_started_at IS NOT NULL AND consumed_at IS NOT NULL AND failed_at IS NULL AND verified_credential_id IS NOT NULL)
    OR (status = 'failed' AND consume_started_at IS NOT NULL AND consumed_at IS NOT NULL AND failed_at IS NOT NULL)
    OR (status = 'expired' AND consumed_at IS NULL AND failed_at IS NULL AND verified_credential_id IS NULL)
  ),
  CHECK (authorization_consumed_at IS NULL OR (
    ceremony = 'authentication'
    AND status = 'consumed'
    AND authorization_consumed_at >= consumed_at
  ))
);

CREATE UNIQUE INDEX owner_recovery_webauthn_one_live_operation
  ON owner_recovery_webauthn_challenges
    (organization_id, recovery_session_id, operation)
  WHERE status IN ('pending', 'consuming');

CREATE INDEX owner_recovery_webauthn_expiry
  ON owner_recovery_webauthn_challenges
    (expires_at, organization_id, challenge_id)
  WHERE status IN ('pending', 'consuming');

CREATE INDEX owner_recovery_webauthn_activation_proof
  ON owner_recovery_webauthn_challenges
    (organization_id, request_id, recovery_session_id, challenge_id)
  WHERE ceremony = 'authentication'
    AND status = 'consumed'
    AND authorization_consumed_at IS NULL;

ALTER TABLE owner_recovery_sessions
  ADD CONSTRAINT owner_recovery_sessions_activation_authorization_fk
  FOREIGN KEY (organization_id, activation_authorization_id)
  REFERENCES owner_recovery_webauthn_challenges(organization_id, challenge_id);

COMMIT;
