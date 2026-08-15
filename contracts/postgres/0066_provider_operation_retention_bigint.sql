BEGIN;

-- Millisecond retention values intentionally support up to 365 days. That
-- range exceeds PostgreSQL integer at 24.85 days, so expose a bigint overload
-- while retaining the 0049 integer signature for older callers.
CREATE FUNCTION public.agentpass_managed_signer_provider_operation_reserve(
  p_purpose text,
  p_operation_id text,
  p_algorithm text,
  p_bytes_length integer,
  p_request_digest bytea,
  p_key_id text,
  p_key_version bigint,
  p_claim_token_digest bytea,
  p_claim_lease_ms integer,
  p_retention_ms bigint
)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  operation public.managed_signer_provider_operations%ROWTYPE;
BEGIN
  IF NOT public.agentpass_managed_signer_provider_operation_binding_valid(
    p_purpose, p_operation_id, p_algorithm, p_bytes_length, p_request_digest, p_key_id, p_key_version
  ) OR p_claim_token_digest IS NULL OR pg_catalog.octet_length(p_claim_token_digest) <> 32
    OR p_claim_lease_ms IS NULL OR p_claim_lease_ms NOT BETWEEN 1 AND 300000
    OR p_retention_ms IS NULL OR p_retention_ms < p_claim_lease_ms OR p_retention_ms > 31536000000
  THEN
    RETURN public.agentpass_managed_signer_provider_operation_error('INPUT');
  END IF;

  INSERT INTO public.managed_signer_provider_operations (
    purpose, operation_id, algorithm, bytes_length, request_digest, key_id, key_version, state,
    claim_token_digest, claim_expires_at, provider_started_at, uncertain_reason, signature,
    public_key_der, provider_receipt_provider, provider_receipt_id, expires_at
  ) VALUES (
    p_purpose, p_operation_id, p_algorithm, p_bytes_length, p_request_digest, p_key_id, p_key_version, 'pending',
    p_claim_token_digest, pg_catalog.clock_timestamp() + (p_claim_lease_ms * interval '1 millisecond'),
    NULL, NULL, NULL, NULL, NULL, NULL,
    pg_catalog.clock_timestamp() + (p_retention_ms * interval '1 millisecond')
  )
  ON CONFLICT (purpose, operation_id) DO NOTHING
  RETURNING * INTO operation;

  IF FOUND THEN
    RETURN public.agentpass_managed_signer_provider_operation_record(
      operation.purpose, operation.operation_id, operation.algorithm, operation.bytes_length,
      operation.request_digest, operation.key_id, operation.key_version, operation.state,
      operation.claim_expires_at, operation.provider_started_at, operation.uncertain_reason,
      operation.signature, operation.public_key_der, operation.provider_receipt_provider,
      operation.provider_receipt_id, true
    );
  END IF;

  SELECT * INTO operation
  FROM public.managed_signer_provider_operations
  WHERE purpose = p_purpose AND operation_id = p_operation_id
  FOR UPDATE;
  IF NOT FOUND THEN
    RETURN public.agentpass_managed_signer_provider_operation_error('DATABASE');
  END IF;
  IF operation.algorithm IS DISTINCT FROM p_algorithm
     OR operation.bytes_length IS DISTINCT FROM p_bytes_length
     OR operation.request_digest IS DISTINCT FROM p_request_digest
     OR operation.key_id IS DISTINCT FROM p_key_id
     OR operation.key_version IS DISTINCT FROM p_key_version
  THEN
    RETURN public.agentpass_managed_signer_provider_operation_error('CONFLICT');
  END IF;

  IF operation.state = 'pending'
     AND operation.claim_expires_at IS NOT NULL
     AND operation.claim_expires_at <= pg_catalog.clock_timestamp()
  THEN
    UPDATE public.managed_signer_provider_operations
    SET claim_token_digest = p_claim_token_digest,
        claim_expires_at = pg_catalog.clock_timestamp() + (p_claim_lease_ms * interval '1 millisecond')
    WHERE purpose = operation.purpose AND operation_id = operation.operation_id
    RETURNING * INTO operation;
    IF NOT FOUND THEN
      RETURN public.agentpass_managed_signer_provider_operation_error('CLAIM_LOST');
    END IF;
    RETURN public.agentpass_managed_signer_provider_operation_record(
      operation.purpose, operation.operation_id, operation.algorithm, operation.bytes_length,
      operation.request_digest, operation.key_id, operation.key_version, operation.state,
      operation.claim_expires_at, operation.provider_started_at, operation.uncertain_reason,
      operation.signature, operation.public_key_der, operation.provider_receipt_provider,
      operation.provider_receipt_id, true
    );
  END IF;

  RETURN public.agentpass_managed_signer_provider_operation_record(
    operation.purpose, operation.operation_id, operation.algorithm, operation.bytes_length,
    operation.request_digest, operation.key_id, operation.key_version, operation.state,
    operation.claim_expires_at, operation.provider_started_at, operation.uncertain_reason,
    operation.signature, operation.public_key_der, operation.provider_receipt_provider,
    operation.provider_receipt_id, false
  );
END;
$$;

REVOKE ALL ON FUNCTION public.agentpass_managed_signer_provider_operation_reserve(
  text, text, text, integer, bytea, text, bigint, bytea, integer, bigint
) FROM PUBLIC;

COMMENT ON FUNCTION public.agentpass_managed_signer_provider_operation_reserve(
  text, text, text, integer, bytea, text, bigint, bytea, integer, bigint
) IS 'Atomically reserves a provider operation with a bigint millisecond retention range up to 365 days.';

COMMIT;
