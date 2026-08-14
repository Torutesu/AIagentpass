BEGIN;

-- 0040 intentionally allowed an uncertain operation to carry no reason.  Keep
-- this column physically nullable because it is meaningful only for the
-- uncertain state, while the state-linked constraint below makes the value
-- mandatory whenever an operation is uncertain.
ALTER TABLE managed_signer_provider_operations
  ADD COLUMN uncertain_reason text;

-- Rows created before this migration have no more precise provenance.  Mark
-- them conservatively as requiring recovery; do not infer provider or request
-- details that were never persisted.
UPDATE managed_signer_provider_operations
SET uncertain_reason = 'process_interrupted'
WHERE state = 'uncertain';

ALTER TABLE managed_signer_provider_operations
  ADD CONSTRAINT managed_signer_provider_operation_uncertain_reason_shape
  CHECK (
    (state = 'uncertain'
      AND uncertain_reason IN (
        'process_interrupted',
        'provider_timeout',
        'provider_response_lost',
        'provider_output_invalid',
        'commit_response_lost',
        'claim_expired_after_start',
        'lifecycle_fenced',
        'recovery_exhausted'
      ))
    OR (state <> 'uncertain' AND uncertain_reason IS NULL)
  ) NOT VALID;

ALTER TABLE managed_signer_provider_operations
  VALIDATE CONSTRAINT managed_signer_provider_operation_uncertain_reason_shape;

-- Deployment-wide aggregate health queries can remain bounded by state and
-- purpose without exposing operation identifiers.  The claim and retention
-- indexes below keep the maintenance paths selective and bounded as well.
CREATE INDEX managed_signer_provider_operations_health_state
  ON managed_signer_provider_operations (state, purpose, updated_at)
  WHERE state IN (
    'pending', 'started', 'accepted', 'uncertain', 'committed', 'rejected', 'failed'
  );

CREATE INDEX managed_signer_provider_operations_started_claim_expiry
  ON managed_signer_provider_operations (claim_expires_at, purpose, operation_id)
  WHERE state = 'started' AND claim_expires_at IS NOT NULL;

CREATE INDEX managed_signer_provider_operations_terminal_retention
  ON managed_signer_provider_operations (expires_at, state, purpose, operation_id)
  WHERE state IN ('committed', 'rejected', 'failed');

-- Move only provider-started operations whose fencing claim has expired into
-- uncertain.  Pending operations have not crossed the provider boundary and
-- must never be quarantined by this function.  The existing 0040 trigger
-- continues to enforce terminal immutability and the started->uncertain
-- transition; this function returns only the aggregate number moved.
CREATE FUNCTION agentpass_quarantine_expired_managed_signer_provider_operations(
  p_limit integer
)
RETURNS integer
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SET search_path = pg_catalog, public
AS $$
DECLARE
  quarantined_count integer;
BEGIN
  IF p_limit IS NULL OR p_limit < 1 OR p_limit > 1000 THEN
    RAISE EXCEPTION USING
      ERRCODE = 'invalid_parameter_value',
      MESSAGE = 'p_limit must be between 1 and 1000';
  END IF;

  WITH expired_started AS MATERIALIZED (
    SELECT purpose, operation_id
    FROM managed_signer_provider_operations
    WHERE state = 'started'
      AND claim_expires_at IS NOT NULL
      AND claim_expires_at <= clock_timestamp()
    ORDER BY claim_expires_at, purpose, operation_id
    LIMIT p_limit
    FOR UPDATE SKIP LOCKED
  ), quarantined AS (
    UPDATE managed_signer_provider_operations AS operation
    SET state = 'uncertain',
        uncertain_reason = 'claim_expired_after_start',
        claim_token_digest = NULL,
        claim_expires_at = NULL
    FROM expired_started
    WHERE operation.purpose = expired_started.purpose
      AND operation.operation_id = expired_started.operation_id
      AND operation.state = 'started'
    RETURNING 1
  )
  SELECT count(*)::integer
  INTO quarantined_count
  FROM quarantined;

  RETURN quarantined_count;
END;
$$;

COMMENT ON COLUMN managed_signer_provider_operations.uncertain_reason IS
  'Closed reason vocabulary required only for uncertain operations; no provider response or secret material is stored.';

COMMENT ON FUNCTION agentpass_quarantine_expired_managed_signer_provider_operations(integer) IS
  'Quarantines only expired started provider-operation claims in a bounded SKIP LOCKED batch and returns the moved-row count.';

COMMIT;
