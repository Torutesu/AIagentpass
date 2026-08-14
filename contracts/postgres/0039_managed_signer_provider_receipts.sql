BEGIN;

-- Provider receipts are deliberately stored as two closed columns instead of
-- opaque provider JSON.  The existing operation/purpose/key/request_digest
-- columns remain the authoritative binding; these columns contain only the
-- provider's stable receipt identity needed for reconciliation.
ALTER TABLE managed_signer_signing_idempotency
  ADD COLUMN provider_receipt_provider text,
  ADD COLUMN provider_receipt_id text;

ALTER TABLE managed_signer_signing_idempotency
  ADD CONSTRAINT managed_signer_provider_receipt_shape CHECK (
    (provider_receipt_provider IS NULL AND provider_receipt_id IS NULL)
    OR (
      status = 'committed'
      AND provider_receipt_provider ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$'
      AND provider_receipt_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
      AND provider_receipt_provider !~* '(private|secret|credential|diagnostic|debug|trace|token|pem)'
      AND provider_receipt_id !~* '(private|secret|credential|diagnostic|debug|trace|token|pem)'
    )
  );

COMMENT ON COLUMN managed_signer_signing_idempotency.provider_receipt_provider IS
  'Closed provider receipt provider identifier; no provider response JSON is persisted.';
COMMENT ON COLUMN managed_signer_signing_idempotency.provider_receipt_id IS
  'Closed provider receipt identifier bound to the operation, purpose, key, version, and request digest.';

COMMIT;
