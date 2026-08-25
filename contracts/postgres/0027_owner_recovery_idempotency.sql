BEGIN;

-- Owner-recovery replay records are separate from the shared control-plane
-- table. Request and claim material are digests only; one-time exchanges are
-- intentionally not durable response material.
CREATE TABLE owner_recovery_idempotency_records (
  organization_id uuid NOT NULL REFERENCES organizations(id),
  operation text NOT NULL CHECK (
    char_length(operation) BETWEEN 1 AND 128
    AND operation ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
  ),
  principal_id text NOT NULL CHECK (
    char_length(principal_id) BETWEEN 1 AND 255
    AND principal_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
  ),
  idempotency_key text NOT NULL CHECK (
    char_length(idempotency_key) BETWEEN 8 AND 255
    AND idempotency_key ~ '^[A-Za-z0-9._~-]+$'
  ),
  request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
  lifecycle text NOT NULL CHECK (lifecycle IN ('in_progress', 'completed')),
  response_status integer,
  response_body jsonb,
  claim_token_digest bytea CHECK (
    claim_token_digest IS NULL OR octet_length(claim_token_digest) = 32
  ),
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  PRIMARY KEY (organization_id, operation, principal_id, idempotency_key),
  CHECK (expires_at > created_at),
  CHECK (updated_at >= created_at),
  CHECK (
    (lifecycle = 'in_progress'
      AND response_status IS NULL
      AND response_body IS NULL
      AND claim_token_digest IS NOT NULL)
    OR
    (lifecycle = 'completed'
      AND response_status BETWEEN 100 AND 599
      AND response_status <> 102
      AND response_body IS NOT NULL
      AND claim_token_digest IS NULL)
  )
);

CREATE INDEX owner_recovery_idempotency_expiry
  ON owner_recovery_idempotency_records (expires_at);

COMMENT ON TABLE owner_recovery_idempotency_records IS
  'Durable owner-recovery replay records; raw request, claim, session, and exchange secrets are not stored.';

COMMIT;
