BEGIN;

-- W1 maintenance is a database-owned boundary.  The signer worker receives
-- only a bounded aggregate result; it never receives a candidate identifier
-- and never builds ledger SQL in application code.
CREATE FUNCTION public.agentpass_maintain_managed_signer_provider_operations(
  p_limit integer
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
VOLATILE
PARALLEL UNSAFE
SET search_path = pg_catalog, public
AS $$
DECLARE
  database_now timestamptz := clock_timestamp();
  remaining integer;
  quarantined_count integer;
  reconciled_count integer := 0;
  pruned_count integer := 0;
  total_count integer;
BEGIN
  IF p_limit IS NULL OR p_limit < 1 OR p_limit > 1000 THEN
    RAISE EXCEPTION USING
      ERRCODE = 'invalid_parameter_value',
      MESSAGE = 'p_limit must be between 1 and 1000';
  END IF;

  -- A single bounded claim batch prevents an expired provider claim from
  -- consuming more than the caller's total maintenance budget.
  WITH expired_started AS MATERIALIZED (
    SELECT purpose, operation_id
    FROM managed_signer_provider_operations
    WHERE state = 'started'
      AND claim_expires_at IS NOT NULL
      AND claim_expires_at <= database_now
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
  SELECT count(*)::integer INTO quarantined_count FROM quarantined;

  remaining := p_limit - quarantined_count;

  -- Reconcile only an exact durable correlation.  No provider call, request
  -- bytes, or opaque provider response is possible in this SQL-only path.
  IF remaining > 0 THEN
    WITH candidates AS MATERIALIZED (
      SELECT provider.purpose, provider.operation_id
      FROM managed_signer_provider_operations AS provider
      JOIN managed_signer_signing_idempotency AS signing
        ON signing.purpose = provider.purpose
       AND signing.operation_id = provider.operation_id
      WHERE provider.state IN ('accepted', 'uncertain')
        AND signing.status = 'committed'
        AND provider.request_digest = signing.request_digest
        AND provider.key_id = signing.key_id
        AND provider.key_version = signing.key_version
        AND provider.signature = signing.signature
        AND provider.provider_receipt_provider = signing.provider_receipt_provider
        AND provider.provider_receipt_id = signing.provider_receipt_id
      ORDER BY provider.updated_at, provider.purpose, provider.operation_id
      LIMIT remaining
      FOR UPDATE OF provider, signing SKIP LOCKED
    ), reconciled AS (
      UPDATE managed_signer_provider_operations AS provider
      SET state = 'committed',
          uncertain_reason = NULL,
          claim_token_digest = NULL,
          claim_expires_at = NULL
      FROM candidates
      WHERE provider.purpose = candidates.purpose
        AND provider.operation_id = candidates.operation_id
      RETURNING 1
    )
    SELECT count(*)::integer INTO reconciled_count FROM reconciled;
    remaining := remaining - reconciled_count;
  END IF;

  -- Retain only committed rows whose signing and provider records are still
  -- exactly correlated and both expired at the same database clock instant.
  IF remaining > 0 THEN
    WITH candidates AS MATERIALIZED (
      SELECT provider.purpose, provider.operation_id
      FROM managed_signer_provider_operations AS provider
      JOIN managed_signer_signing_idempotency AS signing
        ON signing.purpose = provider.purpose
       AND signing.operation_id = provider.operation_id
      WHERE provider.state = 'committed'
        AND signing.status = 'committed'
        AND provider.request_digest = signing.request_digest
        AND provider.key_id = signing.key_id
        AND provider.key_version = signing.key_version
        AND provider.signature = signing.signature
        AND provider.provider_receipt_provider = signing.provider_receipt_provider
        AND provider.provider_receipt_id = signing.provider_receipt_id
        AND provider.expires_at <= database_now
        AND signing.expires_at <= database_now
      ORDER BY provider.expires_at, signing.expires_at, provider.purpose, provider.operation_id
      LIMIT remaining
      FOR UPDATE OF provider, signing SKIP LOCKED
    ), deleted_signing AS (
      DELETE FROM managed_signer_signing_idempotency AS signing
      USING candidates
      WHERE signing.purpose = candidates.purpose
        AND signing.operation_id = candidates.operation_id
      RETURNING signing.purpose, signing.operation_id
    ), deleted_provider AS (
      DELETE FROM managed_signer_provider_operations AS provider
      USING deleted_signing
      WHERE provider.purpose = deleted_signing.purpose
        AND provider.operation_id = deleted_signing.operation_id
      RETURNING 1
    )
    SELECT count(*)::integer INTO pruned_count FROM deleted_provider;
  END IF;

  total_count := quarantined_count + reconciled_count + pruned_count;
  IF total_count > p_limit THEN
    RAISE EXCEPTION USING
      ERRCODE = 'integrity_constraint_violation',
      MESSAGE = 'provider operation maintenance budget was exceeded';
  END IF;

  RETURN jsonb_build_object(
    'quarantined', quarantined_count,
    'reconciled', reconciled_count,
    'pruned', pruned_count,
    'total', total_count
  );
END;
$$;

-- Health is intentionally deployment-wide and aggregate-only.  Each state
-- count is capped before aggregation and the result has fixed cardinality;
-- no operation, tenant, receipt, key, or provider identifier is returned.
CREATE FUNCTION public.agentpass_health_managed_signer_provider_operations()
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
VOLATILE
PARALLEL UNSAFE
SET search_path = pg_catalog, public
AS $$
DECLARE
  database_now timestamptz := clock_timestamp();
BEGIN
  RETURN jsonb_build_object(
    'version', 1,
    'states', jsonb_build_object(
      'pending', (SELECT count(*)::integer FROM (
        SELECT 1 FROM managed_signer_provider_operations WHERE state = 'pending' LIMIT 10000
      ) AS bounded),
      'started', (SELECT count(*)::integer FROM (
        SELECT 1 FROM managed_signer_provider_operations WHERE state = 'started' LIMIT 10000
      ) AS bounded),
      'accepted', (SELECT count(*)::integer FROM (
        SELECT 1 FROM managed_signer_provider_operations WHERE state = 'accepted' LIMIT 10000
      ) AS bounded),
      'uncertain', (SELECT count(*)::integer FROM (
        SELECT 1 FROM managed_signer_provider_operations WHERE state = 'uncertain' LIMIT 10000
      ) AS bounded),
      'committed', (SELECT count(*)::integer FROM (
        SELECT 1 FROM managed_signer_provider_operations WHERE state = 'committed' LIMIT 10000
      ) AS bounded),
      'rejected', (SELECT count(*)::integer FROM (
        SELECT 1 FROM managed_signer_provider_operations WHERE state = 'rejected' LIMIT 10000
      ) AS bounded),
      'failed', (SELECT count(*)::integer FROM (
        SELECT 1 FROM managed_signer_provider_operations WHERE state = 'failed' LIMIT 10000
      ) AS bounded)
    ),
    'stale_started', (SELECT count(*)::integer FROM (
      SELECT 1
      FROM managed_signer_provider_operations
      WHERE state = 'started'
        AND claim_expires_at IS NOT NULL
        AND claim_expires_at <= database_now
      LIMIT 10000
    ) AS bounded),
    'oldest_nonterminal_at', (SELECT created_at
      FROM managed_signer_provider_operations
      WHERE state IN ('pending', 'started', 'accepted', 'uncertain')
      ORDER BY created_at, purpose, operation_id
      LIMIT 1)
  );
END;
$$;

-- Function EXECUTE defaults to PUBLIC in PostgreSQL.  Only the deployment's
-- signer role may invoke these two maintenance authorities.
REVOKE ALL ON FUNCTION public.agentpass_maintain_managed_signer_provider_operations(integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.agentpass_health_managed_signer_provider_operations() FROM PUBLIC;

COMMENT ON FUNCTION public.agentpass_maintain_managed_signer_provider_operations(integer)
  IS 'Atomic bounded provider-operation maintenance: quarantine, exact-correlation reconcile, and exact-correlation prune with SKIP LOCKED.';
COMMENT ON FUNCTION public.agentpass_health_managed_signer_provider_operations()
  IS 'Fixed-cardinality capped aggregate provider-operation health with no identifiers.';

COMMIT;
