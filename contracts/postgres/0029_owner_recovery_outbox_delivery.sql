BEGIN;

ALTER TABLE owner_recovery_outbox
  DROP CONSTRAINT owner_recovery_outbox_status_check,
  DROP CONSTRAINT owner_recovery_outbox_check,
  ADD COLUMN claim_token_digest bytea
    CHECK (claim_token_digest IS NULL OR octet_length(claim_token_digest) = 32),
  ADD COLUMN claim_expires_at timestamptz,
  ADD COLUMN last_error_code text
    CHECK (last_error_code IS NULL OR (
      char_length(last_error_code) BETWEEN 1 AND 128
      AND last_error_code ~ '^[a-z][a-z0-9_]*$'
    ));

ALTER TABLE owner_recovery_outbox
  ADD CONSTRAINT owner_recovery_outbox_status_check
    CHECK (status IN ('pending', 'published', 'dead_letter')),
  ADD CONSTRAINT owner_recovery_outbox_delivery_state_check CHECK (
    (status = 'pending' AND published_at IS NULL)
    OR
    (status = 'published' AND published_at IS NOT NULL
      AND claim_token_digest IS NULL AND claim_expires_at IS NULL
      AND last_error_code IS NULL)
    OR
    (status = 'dead_letter' AND published_at IS NULL
      AND attempts = 100
      AND claim_token_digest IS NULL AND claim_expires_at IS NULL
      AND last_error_code IS NOT NULL)
  ),
  ADD CONSTRAINT owner_recovery_outbox_claim_state_check CHECK (
    (claim_token_digest IS NULL AND claim_expires_at IS NULL)
    OR
    (status = 'pending' AND claim_token_digest IS NOT NULL
      AND claim_expires_at IS NOT NULL AND claim_expires_at > updated_at)
  );

CREATE INDEX owner_recovery_outbox_claim_expiry
  ON owner_recovery_outbox (claim_expires_at, organization_id, created_at, event_id)
  WHERE status = 'pending' AND claim_token_digest IS NOT NULL;

COMMENT ON COLUMN owner_recovery_outbox.claim_token_digest IS
  'One-way worker lease token digest; the raw claim token is process-local only.';
COMMENT ON COLUMN owner_recovery_outbox.last_error_code IS
  'Bounded stable delivery category; provider messages and response bodies are never stored.';

COMMIT;
