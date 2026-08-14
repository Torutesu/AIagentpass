BEGIN;

-- A provider operation is deployment-global signing metadata.  It is
-- deliberately tenant-neutral: purpose, key, operation, and request digest
-- are the authorization boundary for a hosted signer.  No organization id,
-- private key, provider credential, or request bytes are stored here.
CREATE TABLE managed_signer_provider_operations (
  purpose text NOT NULL
    CHECK (purpose ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$'),
  operation_id text NOT NULL
    CHECK (operation_id ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$'),
  algorithm text NOT NULL
    CHECK (algorithm = 'ed25519'),
  bytes_length integer NOT NULL
    CHECK (bytes_length BETWEEN 1 AND 1048576),
  request_digest bytea NOT NULL
    CHECK (octet_length(request_digest) = 32),
  key_id text NOT NULL
    CHECK (key_id ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$'),
  key_version bigint NOT NULL
    CHECK (key_version BETWEEN 1 AND 9223372036854775807),
  state text NOT NULL
    CHECK (state IN ('pending', 'started', 'accepted', 'uncertain', 'committed', 'rejected', 'failed')),
  claim_token_digest bytea
    CHECK (claim_token_digest IS NULL OR octet_length(claim_token_digest) = 32),
  claim_expires_at timestamptz,
  provider_started_at timestamptz,
  signature bytea,
  public_key_der bytea,
  provider_receipt_provider text,
  provider_receipt_id text,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  expires_at timestamptz NOT NULL,
  PRIMARY KEY (purpose, operation_id),
  CHECK (expires_at > created_at),
  CHECK (
    (signature IS NULL AND public_key_der IS NULL
      AND provider_receipt_provider IS NULL AND provider_receipt_id IS NULL)
    OR (octet_length(signature) = 64
      AND octet_length(public_key_der) = 44
      AND provider_receipt_provider ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$'
      AND provider_receipt_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
      AND provider_receipt_provider !~* '(private|secret|credential|diagnostic|debug|trace|token|pem)'
      AND provider_receipt_id !~* '(private|secret|credential|diagnostic|debug|trace|token|pem)')
  ),
  CHECK (
    (state IN ('pending', 'started')
      AND signature IS NULL AND public_key_der IS NULL
      AND provider_receipt_provider IS NULL AND provider_receipt_id IS NULL)
    OR (state IN ('accepted', 'committed')
      AND signature IS NOT NULL AND public_key_der IS NOT NULL
      AND provider_receipt_provider IS NOT NULL AND provider_receipt_id IS NOT NULL)
    OR state = 'uncertain'
    OR (state IN ('rejected', 'failed')
      AND signature IS NULL AND public_key_der IS NULL
      AND provider_receipt_provider IS NULL AND provider_receipt_id IS NULL)
  ),
  CHECK (
    (state IN ('pending', 'started', 'accepted')
      AND claim_token_digest IS NOT NULL AND claim_expires_at IS NOT NULL)
    OR (state = 'uncertain'
      AND ((claim_token_digest IS NULL AND claim_expires_at IS NULL)
        OR (claim_token_digest IS NOT NULL AND claim_expires_at IS NOT NULL)))
    OR (state IN ('committed', 'rejected', 'failed')
      AND claim_token_digest IS NULL AND claim_expires_at IS NULL)
  ),
  CHECK ((state = 'pending' AND provider_started_at IS NULL)
    OR (state <> 'pending' AND provider_started_at IS NOT NULL))
);

CREATE INDEX managed_signer_provider_operations_claim_expiry
  ON managed_signer_provider_operations (purpose, claim_expires_at, operation_id)
  WHERE state IN ('pending', 'started', 'accepted');

CREATE INDEX managed_signer_provider_operations_retention
  ON managed_signer_provider_operations (purpose, expires_at, operation_id);

CREATE FUNCTION agentpass_guard_managed_signer_provider_operation()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
  IF NEW.purpose IS DISTINCT FROM OLD.purpose
     OR NEW.operation_id IS DISTINCT FROM OLD.operation_id
     OR NEW.algorithm IS DISTINCT FROM OLD.algorithm
     OR NEW.bytes_length IS DISTINCT FROM OLD.bytes_length
     OR NEW.request_digest IS DISTINCT FROM OLD.request_digest
     OR NEW.key_id IS DISTINCT FROM OLD.key_id
     OR NEW.key_version IS DISTINCT FROM OLD.key_version
     OR NEW.created_at IS DISTINCT FROM OLD.created_at
  THEN
    RAISE EXCEPTION USING
      ERRCODE = 'check_violation',
      CONSTRAINT = 'managed_signer_provider_operation_identity_immutable',
      MESSAGE = 'managed signer provider operation identity is immutable';
  END IF;

  IF OLD.state IN ('committed', 'rejected', 'failed') AND NEW IS DISTINCT FROM OLD THEN
    RAISE EXCEPTION USING
      ERRCODE = 'check_violation',
      CONSTRAINT = 'managed_signer_provider_operation_terminal_immutable',
      MESSAGE = 'terminal managed signer provider operation is immutable';
  END IF;

  IF NOT (
    NEW.state = OLD.state
    OR (OLD.state = 'pending' AND NEW.state IN ('started', 'uncertain', 'rejected', 'failed'))
    OR (OLD.state = 'started' AND NEW.state IN ('accepted', 'uncertain', 'failed'))
    OR (OLD.state = 'uncertain' AND NEW.state IN ('accepted', 'committed', 'uncertain', 'failed'))
    OR (OLD.state = 'accepted' AND NEW.state IN ('committed', 'accepted', 'uncertain'))
  ) THEN
    RAISE EXCEPTION USING
      ERRCODE = 'check_violation',
      CONSTRAINT = 'managed_signer_provider_operation_transition',
      MESSAGE = 'managed signer provider operation transition is not permitted';
  END IF;

  NEW.updated_at := clock_timestamp();
  RETURN NEW;
END;
$$;

CREATE TRIGGER managed_signer_provider_operations_guard
  BEFORE UPDATE ON managed_signer_provider_operations
  FOR EACH ROW EXECUTE FUNCTION agentpass_guard_managed_signer_provider_operation();

COMMENT ON TABLE managed_signer_provider_operations IS
  'Tenant-neutral durable provider-operation ledger; stores only public signing output and bounded receipt metadata.';
COMMENT ON COLUMN managed_signer_provider_operations.claim_token_digest IS
  'Digest of the opaque fencing claim token; the clear token is never persisted.';
COMMENT ON COLUMN managed_signer_provider_operations.public_key_der IS
  'Canonical Ed25519 SubjectPublicKeyInfo DER; private key material is not accepted.';

COMMIT;
