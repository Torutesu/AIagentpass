BEGIN;

-- 0037 deliberately made pending claims durable.  This slice adds a bounded
-- lease and a fencing token without changing the reviewed base migration.
ALTER TABLE managed_signer_signing_idempotency
  DROP CONSTRAINT managed_signer_signing_idempotency_status_check;

ALTER TABLE managed_signer_signing_idempotency
  ADD COLUMN claim_token_digest bytea,
  ADD COLUMN claim_expires_at timestamptz,
  ADD COLUMN provider_started_at timestamptz,
  ADD COLUMN reserved_lifecycle_version bigint;

-- Rows created by 0037 cannot be proven to have been before or after the
-- provider boundary.  Quarantine pending rows before making the new binding
-- mandatory; a retry must never infer that an old provider call was harmless.
UPDATE managed_signer_signing_idempotency signing
SET status = CASE WHEN signing.status = 'pending' THEN 'uncertain' ELSE signing.status END,
    claim_token_digest = NULL,
    claim_expires_at = NULL,
    provider_started_at = CASE WHEN signing.status IN ('pending', 'uncertain') THEN clock_timestamp() ELSE signing.provider_started_at END,
    reserved_lifecycle_version = lifecycle.version,
    updated_at = clock_timestamp()
FROM managed_signer_key_lifecycles lifecycle
WHERE lifecycle.purpose = signing.purpose;

ALTER TABLE managed_signer_signing_idempotency
  ALTER COLUMN reserved_lifecycle_version SET NOT NULL,
  ADD CONSTRAINT managed_signer_signing_status_check CHECK (status IN ('pending', 'uncertain', 'committed', 'aborted')),
  ADD CONSTRAINT managed_signer_signing_claim_lease CHECK (
    (status = 'pending' AND claim_token_digest IS NOT NULL AND octet_length(claim_token_digest) = 32 AND claim_expires_at IS NOT NULL)
    OR (status <> 'pending' AND claim_token_digest IS NULL AND claim_expires_at IS NULL)
  ),
  ADD CONSTRAINT managed_signer_signing_reserved_version CHECK (reserved_lifecycle_version BETWEEN 1 AND 9223372036854775807),
  ADD CONSTRAINT managed_signer_signing_provider_boundary CHECK (
    provider_started_at IS NULL OR status IN ('pending', 'uncertain', 'committed')
  );

CREATE INDEX managed_signer_signing_claim_expiry
  ON managed_signer_signing_idempotency (purpose, claim_expires_at, operation_id)
  WHERE status = 'pending';

CREATE OR REPLACE FUNCTION agentpass_guard_managed_signer_signing_idempotency()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
  IF NEW.purpose IS DISTINCT FROM OLD.purpose
     OR NEW.operation_id IS DISTINCT FROM OLD.operation_id
     OR NEW.request_digest IS DISTINCT FROM OLD.request_digest
     OR NEW.key_id IS DISTINCT FROM OLD.key_id
     OR NEW.key_version IS DISTINCT FROM OLD.key_version
     OR NEW.created_at IS DISTINCT FROM OLD.created_at
     OR NEW.reserved_lifecycle_version IS DISTINCT FROM OLD.reserved_lifecycle_version
  THEN
    RAISE EXCEPTION USING
      ERRCODE = 'check_violation',
      CONSTRAINT = 'managed_signer_signing_identity_immutable',
      MESSAGE = 'managed signer signing identity is immutable';
  END IF;
  IF OLD.status = 'committed' AND NEW IS DISTINCT FROM OLD THEN
    RAISE EXCEPTION USING
      ERRCODE = 'check_violation',
      CONSTRAINT = 'managed_signer_signing_committed_immutable',
      MESSAGE = 'committed managed signer response is immutable';
  END IF;
  IF OLD.status = 'pending' AND NEW.status NOT IN ('pending', 'uncertain', 'committed', 'aborted') THEN
    RAISE EXCEPTION USING
      ERRCODE = 'check_violation',
      CONSTRAINT = 'managed_signer_signing_transition',
      MESSAGE = 'managed signer signing transition is not permitted';
  END IF;
  IF OLD.status = 'uncertain' AND NEW.status NOT IN ('uncertain', 'committed') THEN
    RAISE EXCEPTION USING
      ERRCODE = 'check_violation',
      CONSTRAINT = 'managed_signer_signing_transition',
      MESSAGE = 'managed signer uncertain response cannot be reopened';
  END IF;
  IF OLD.status = 'aborted' AND NEW.status NOT IN ('aborted', 'pending') THEN
    RAISE EXCEPTION USING
      ERRCODE = 'check_violation',
      CONSTRAINT = 'managed_signer_signing_transition',
      MESSAGE = 'managed signer aborted claim can only be reclaimed';
  END IF;
  IF OLD.provider_started_at IS NOT NULL AND NEW.provider_started_at IS NULL THEN
    RAISE EXCEPTION USING
      ERRCODE = 'check_violation',
      CONSTRAINT = 'managed_signer_signing_provider_boundary',
      MESSAGE = 'managed signer provider boundary cannot be erased';
  END IF;
  NEW.updated_at := clock_timestamp();
  RETURN NEW;
END;
$$;

COMMENT ON COLUMN managed_signer_signing_idempotency.claim_token_digest IS
  'Digest of the opaque fencing token held by the current reservation owner; the token is never persisted in cleartext.';
COMMENT ON COLUMN managed_signer_signing_idempotency.claim_expires_at IS
  'Database-clock lease expiry for a pending signing reservation.';
COMMENT ON COLUMN managed_signer_signing_idempotency.provider_started_at IS
  'Database-clock evidence that the external provider boundary was entered; once set, expiry is uncertain, not retryable.';
COMMENT ON COLUMN managed_signer_signing_idempotency.reserved_lifecycle_version IS
  'Lifecycle version and fencing epoch captured by the reservation; commits must match the still-active key.';

COMMIT;
