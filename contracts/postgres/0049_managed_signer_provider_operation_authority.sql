BEGIN;

-- W1 authority boundary for the deployment-global provider-operation ledger.
-- The application role receives no direct table mutation path.  It calls only
-- these closed, purpose-specific SECURITY DEFINER functions as the signer
-- role.  Every function pins name resolution and uses the database clock for
-- leases, retention, stale-claim checks, and provider-boundary timestamps.

CREATE FUNCTION public.agentpass_managed_signer_provider_operation_error(
  p_code text
)
RETURNS jsonb
LANGUAGE sql
IMMUTABLE
SECURITY INVOKER
SET search_path = pg_catalog, public
AS $$
  SELECT pg_catalog.jsonb_build_object(
    'status', 'error',
    'error_code', CASE WHEN p_code IN ('INPUT', 'CONFLICT', 'CLAIM_LOST', 'STATE', 'DATABASE')
      THEN p_code ELSE 'DATABASE' END
  )
$$;

CREATE FUNCTION public.agentpass_managed_signer_provider_operation_not_found()
RETURNS jsonb
LANGUAGE sql
IMMUTABLE
SECURITY INVOKER
SET search_path = pg_catalog, public
AS $$
  SELECT pg_catalog.jsonb_build_object('status', 'not_found')
$$;

CREATE FUNCTION public.agentpass_managed_signer_provider_operation_binding_valid(
  p_purpose text,
  p_operation_id text,
  p_algorithm text,
  p_bytes_length integer,
  p_request_digest bytea,
  p_key_id text,
  p_key_version bigint
)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
SECURITY INVOKER
SET search_path = pg_catalog, public
AS $$
  SELECT p_purpose IS NOT NULL
    AND p_purpose ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$'
    AND p_operation_id IS NOT NULL
    AND p_operation_id ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$'
    AND p_algorithm IS NOT NULL
    AND p_algorithm = 'ed25519'
    AND p_bytes_length IS NOT NULL
    AND p_bytes_length BETWEEN 1 AND 1048576
    AND p_request_digest IS NOT NULL
    AND pg_catalog.octet_length(p_request_digest) = 32
    AND p_key_id IS NOT NULL
    AND p_key_id ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$'
    AND p_key_version IS NOT NULL
    AND p_key_version BETWEEN 1 AND 9223372036854775807
$$;

-- JSONB is deliberately fixed-cardinality and contains only the public
-- operation snapshot.  Signature material is transported as bounded hex so
-- the application can reconstruct canonical base64url without locale or
-- padding ambiguity.  The claim digest is never returned.
CREATE FUNCTION public.agentpass_managed_signer_provider_operation_record(
  p_purpose text,
  p_operation_id text,
  p_algorithm text,
  p_bytes_length integer,
  p_request_digest bytea,
  p_key_id text,
  p_key_version bigint,
  p_state text,
  p_claim_expires_at timestamptz,
  p_provider_started_at timestamptz,
  p_uncertain_reason text,
  p_signature bytea,
  p_public_key_der bytea,
  p_provider_receipt_provider text,
  p_provider_receipt_id text,
  p_claim_acquired boolean
)
RETURNS jsonb
LANGUAGE sql
STABLE
SECURITY INVOKER
SET search_path = pg_catalog, public
AS $$
  SELECT pg_catalog.jsonb_build_object(
    'status', 'ok',
    'claim_acquired', p_claim_acquired,
    'record', pg_catalog.jsonb_strip_nulls(pg_catalog.jsonb_build_object(
      'algorithm', p_algorithm,
      'bytes_length', p_bytes_length,
      'key_id', p_key_id,
      'key_version', p_key_version::text,
      'operation_id', p_operation_id,
      'purpose', p_purpose,
      'request_digest', pg_catalog.encode(p_request_digest, 'hex'),
      'state', p_state,
      'uncertain_reason', CASE WHEN p_state = 'uncertain' THEN p_uncertain_reason END,
      'signature_hex', CASE WHEN p_signature IS NOT NULL THEN pg_catalog.encode(p_signature, 'hex') END,
      'public_key_der_hex', CASE WHEN p_public_key_der IS NOT NULL THEN pg_catalog.encode(p_public_key_der, 'hex') END,
      'provider_receipt_provider', p_provider_receipt_provider,
      'provider_receipt_id', p_provider_receipt_id
    ))
  )
$$;

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
  p_retention_ms integer
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

  -- The unique key and ON CONFLICT are the reservation linearization point.
  -- Lock the winner before checking its immutable binding or reclaiming an
  -- expired pending lease.
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

CREATE FUNCTION public.agentpass_managed_signer_provider_operation_claim(
  p_purpose text,
  p_operation_id text,
  p_algorithm text,
  p_bytes_length integer,
  p_request_digest bytea,
  p_key_id text,
  p_key_version bigint,
  p_claim_token_digest bytea,
  p_claim_lease_ms integer
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
  THEN
    RETURN public.agentpass_managed_signer_provider_operation_error('INPUT');
  END IF;

  SELECT * INTO operation
  FROM public.managed_signer_provider_operations
  WHERE purpose = p_purpose AND operation_id = p_operation_id
  FOR UPDATE;
  IF NOT FOUND THEN RETURN public.agentpass_managed_signer_provider_operation_not_found(); END IF;
  IF operation.algorithm IS DISTINCT FROM p_algorithm
     OR operation.bytes_length IS DISTINCT FROM p_bytes_length
     OR operation.request_digest IS DISTINCT FROM p_request_digest
     OR operation.key_id IS DISTINCT FROM p_key_id
     OR operation.key_version IS DISTINCT FROM p_key_version
  THEN
    RETURN public.agentpass_managed_signer_provider_operation_error('CONFLICT');
  END IF;
  IF operation.state IN ('committed', 'rejected', 'failed')
     OR (operation.claim_token_digest IS NOT NULL
       AND operation.claim_expires_at IS NOT NULL
       AND operation.claim_expires_at > pg_catalog.clock_timestamp())
  THEN
    RETURN public.agentpass_managed_signer_provider_operation_record(
      operation.purpose, operation.operation_id, operation.algorithm, operation.bytes_length,
      operation.request_digest, operation.key_id, operation.key_version, operation.state,
      operation.claim_expires_at, operation.provider_started_at, operation.uncertain_reason,
      operation.signature, operation.public_key_der, operation.provider_receipt_provider,
      operation.provider_receipt_id, false
    );
  END IF;

  UPDATE public.managed_signer_provider_operations
  SET claim_token_digest = p_claim_token_digest,
      claim_expires_at = pg_catalog.clock_timestamp() + (p_claim_lease_ms * interval '1 millisecond')
  WHERE purpose = operation.purpose AND operation_id = operation.operation_id
  RETURNING * INTO operation;
  IF NOT FOUND THEN RETURN public.agentpass_managed_signer_provider_operation_error('CLAIM_LOST'); END IF;
  RETURN public.agentpass_managed_signer_provider_operation_record(
    operation.purpose, operation.operation_id, operation.algorithm, operation.bytes_length,
    operation.request_digest, operation.key_id, operation.key_version, operation.state,
    operation.claim_expires_at, operation.provider_started_at, operation.uncertain_reason,
    operation.signature, operation.public_key_der, operation.provider_receipt_provider,
    operation.provider_receipt_id, true
  );
END;
$$;

CREATE FUNCTION public.agentpass_managed_signer_provider_operation_start(
  p_purpose text, p_operation_id text, p_algorithm text, p_bytes_length integer,
  p_request_digest bytea, p_key_id text, p_key_version bigint, p_claim_token_digest bytea
)
RETURNS jsonb
LANGUAGE plpgsql VOLATILE PARALLEL UNSAFE SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE operation public.managed_signer_provider_operations%ROWTYPE;
BEGIN
  IF NOT public.agentpass_managed_signer_provider_operation_binding_valid(p_purpose,p_operation_id,p_algorithm,p_bytes_length,p_request_digest,p_key_id,p_key_version)
    OR p_claim_token_digest IS NULL OR pg_catalog.octet_length(p_claim_token_digest) <> 32
  THEN RETURN public.agentpass_managed_signer_provider_operation_error('INPUT'); END IF;
  SELECT * INTO operation FROM public.managed_signer_provider_operations
    WHERE purpose=p_purpose AND operation_id=p_operation_id FOR UPDATE;
  IF NOT FOUND THEN RETURN public.agentpass_managed_signer_provider_operation_error('CLAIM_LOST'); END IF;
  IF operation.algorithm IS DISTINCT FROM p_algorithm OR operation.bytes_length IS DISTINCT FROM p_bytes_length
    OR operation.request_digest IS DISTINCT FROM p_request_digest OR operation.key_id IS DISTINCT FROM p_key_id
    OR operation.key_version IS DISTINCT FROM p_key_version THEN
    RETURN public.agentpass_managed_signer_provider_operation_error('CONFLICT');
  END IF;
  IF operation.state NOT IN ('pending','started') OR operation.claim_token_digest IS DISTINCT FROM p_claim_token_digest
    OR operation.claim_expires_at IS NULL OR operation.claim_expires_at <= pg_catalog.clock_timestamp()
  THEN RETURN public.agentpass_managed_signer_provider_operation_error('CLAIM_LOST'); END IF;
  UPDATE public.managed_signer_provider_operations
  SET state='started', provider_started_at=COALESCE(provider_started_at, pg_catalog.clock_timestamp())
  WHERE purpose=operation.purpose AND operation_id=operation.operation_id
  RETURNING * INTO operation;
  IF NOT FOUND THEN RETURN public.agentpass_managed_signer_provider_operation_error('STATE'); END IF;
  RETURN public.agentpass_managed_signer_provider_operation_record(operation.purpose,operation.operation_id,operation.algorithm,operation.bytes_length,operation.request_digest,operation.key_id,operation.key_version,operation.state,operation.claim_expires_at,operation.provider_started_at,operation.uncertain_reason,operation.signature,operation.public_key_der,operation.provider_receipt_provider,operation.provider_receipt_id,false);
END;
$$;

CREATE FUNCTION public.agentpass_managed_signer_provider_operation_accept(
  p_purpose text, p_operation_id text, p_algorithm text, p_bytes_length integer,
  p_request_digest bytea, p_key_id text, p_key_version bigint, p_claim_token_digest bytea,
  p_signature bytea, p_public_key_der bytea, p_provider_receipt_provider text,
  p_provider_receipt_id text, p_receipt_operation_id text, p_receipt_key_id text,
  p_receipt_key_version text
)
RETURNS jsonb
LANGUAGE plpgsql VOLATILE PARALLEL UNSAFE SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE operation public.managed_signer_provider_operations%ROWTYPE;
BEGIN
  IF NOT public.agentpass_managed_signer_provider_operation_binding_valid(p_purpose,p_operation_id,p_algorithm,p_bytes_length,p_request_digest,p_key_id,p_key_version)
    OR p_claim_token_digest IS NULL OR pg_catalog.octet_length(p_claim_token_digest) <> 32
    OR p_signature IS NULL OR pg_catalog.octet_length(p_signature) <> 64
    OR p_public_key_der IS NULL OR pg_catalog.octet_length(p_public_key_der) <> 44
    OR p_provider_receipt_provider IS NULL OR p_provider_receipt_provider !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$'
    OR p_provider_receipt_id IS NULL OR p_provider_receipt_id !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
    OR p_provider_receipt_provider ~* '(private|secret|credential|diagnostic|debug|trace|token|pem)'
    OR p_provider_receipt_id ~* '(private|secret|credential|diagnostic|debug|trace|token|pem)'
    OR p_receipt_operation_id IS DISTINCT FROM p_operation_id
    OR p_receipt_key_id IS DISTINCT FROM p_key_id
    OR p_receipt_key_version IS DISTINCT FROM p_key_version::text
  THEN RETURN public.agentpass_managed_signer_provider_operation_error('INPUT'); END IF;
  SELECT * INTO operation FROM public.managed_signer_provider_operations
    WHERE purpose=p_purpose AND operation_id=p_operation_id FOR UPDATE;
  IF NOT FOUND THEN RETURN public.agentpass_managed_signer_provider_operation_error('CLAIM_LOST'); END IF;
  IF operation.algorithm IS DISTINCT FROM p_algorithm OR operation.bytes_length IS DISTINCT FROM p_bytes_length
    OR operation.request_digest IS DISTINCT FROM p_request_digest OR operation.key_id IS DISTINCT FROM p_key_id
    OR operation.key_version IS DISTINCT FROM p_key_version THEN
    RETURN public.agentpass_managed_signer_provider_operation_error('CONFLICT');
  END IF;
  IF operation.state NOT IN ('started','uncertain','accepted') OR operation.claim_token_digest IS DISTINCT FROM p_claim_token_digest
    OR operation.claim_expires_at IS NULL OR operation.claim_expires_at <= pg_catalog.clock_timestamp()
  THEN RETURN public.agentpass_managed_signer_provider_operation_error('CLAIM_LOST'); END IF;
  IF operation.state = 'accepted' THEN
    IF operation.signature IS DISTINCT FROM p_signature OR operation.public_key_der IS DISTINCT FROM p_public_key_der
      OR operation.provider_receipt_provider IS DISTINCT FROM p_provider_receipt_provider
      OR operation.provider_receipt_id IS DISTINCT FROM p_provider_receipt_id
    THEN RETURN public.agentpass_managed_signer_provider_operation_error('CONFLICT'); END IF;
    RETURN public.agentpass_managed_signer_provider_operation_record(operation.purpose,operation.operation_id,operation.algorithm,operation.bytes_length,operation.request_digest,operation.key_id,operation.key_version,operation.state,operation.claim_expires_at,operation.provider_started_at,operation.uncertain_reason,operation.signature,operation.public_key_der,operation.provider_receipt_provider,operation.provider_receipt_id,false);
  END IF;
  UPDATE public.managed_signer_provider_operations
  SET state='accepted', uncertain_reason=NULL, signature=p_signature, public_key_der=p_public_key_der,
      provider_receipt_provider=p_provider_receipt_provider, provider_receipt_id=p_provider_receipt_id
  WHERE purpose=operation.purpose AND operation_id=operation.operation_id
  RETURNING * INTO operation;
  IF NOT FOUND THEN RETURN public.agentpass_managed_signer_provider_operation_error('STATE'); END IF;
  RETURN public.agentpass_managed_signer_provider_operation_record(operation.purpose,operation.operation_id,operation.algorithm,operation.bytes_length,operation.request_digest,operation.key_id,operation.key_version,operation.state,operation.claim_expires_at,operation.provider_started_at,operation.uncertain_reason,operation.signature,operation.public_key_der,operation.provider_receipt_provider,operation.provider_receipt_id,false);
END;
$$;

CREATE FUNCTION public.agentpass_managed_signer_provider_operation_commit(
  p_purpose text, p_operation_id text, p_algorithm text, p_bytes_length integer,
  p_request_digest bytea, p_key_id text, p_key_version bigint, p_claim_token_digest bytea
)
RETURNS jsonb
LANGUAGE plpgsql VOLATILE PARALLEL UNSAFE SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE operation public.managed_signer_provider_operations%ROWTYPE;
BEGIN
  IF NOT public.agentpass_managed_signer_provider_operation_binding_valid(p_purpose,p_operation_id,p_algorithm,p_bytes_length,p_request_digest,p_key_id,p_key_version)
    OR p_claim_token_digest IS NULL OR pg_catalog.octet_length(p_claim_token_digest) <> 32
  THEN RETURN public.agentpass_managed_signer_provider_operation_error('INPUT'); END IF;
  SELECT * INTO operation FROM public.managed_signer_provider_operations
    WHERE purpose=p_purpose AND operation_id=p_operation_id FOR UPDATE;
  IF NOT FOUND THEN RETURN public.agentpass_managed_signer_provider_operation_error('CLAIM_LOST'); END IF;
  IF operation.algorithm IS DISTINCT FROM p_algorithm OR operation.bytes_length IS DISTINCT FROM p_bytes_length
    OR operation.request_digest IS DISTINCT FROM p_request_digest OR operation.key_id IS DISTINCT FROM p_key_id
    OR operation.key_version IS DISTINCT FROM p_key_version THEN
    RETURN public.agentpass_managed_signer_provider_operation_error('CONFLICT');
  END IF;
  IF operation.state = 'committed' THEN
    RETURN public.agentpass_managed_signer_provider_operation_record(operation.purpose,operation.operation_id,operation.algorithm,operation.bytes_length,operation.request_digest,operation.key_id,operation.key_version,operation.state,operation.claim_expires_at,operation.provider_started_at,operation.uncertain_reason,operation.signature,operation.public_key_der,operation.provider_receipt_provider,operation.provider_receipt_id,false);
  END IF;
  IF operation.state <> 'accepted' OR operation.claim_token_digest IS DISTINCT FROM p_claim_token_digest
    OR operation.claim_expires_at IS NULL OR operation.claim_expires_at <= pg_catalog.clock_timestamp()
  THEN RETURN public.agentpass_managed_signer_provider_operation_error('CLAIM_LOST'); END IF;
  UPDATE public.managed_signer_provider_operations
  SET state='committed', uncertain_reason=NULL, claim_token_digest=NULL, claim_expires_at=NULL
  WHERE purpose=operation.purpose AND operation_id=operation.operation_id
  RETURNING * INTO operation;
  IF NOT FOUND THEN RETURN public.agentpass_managed_signer_provider_operation_error('STATE'); END IF;
  RETURN public.agentpass_managed_signer_provider_operation_record(operation.purpose,operation.operation_id,operation.algorithm,operation.bytes_length,operation.request_digest,operation.key_id,operation.key_version,operation.state,operation.claim_expires_at,operation.provider_started_at,operation.uncertain_reason,operation.signature,operation.public_key_der,operation.provider_receipt_provider,operation.provider_receipt_id,false);
END;
$$;

CREATE FUNCTION public.agentpass_managed_signer_provider_operation_reconcile(
  p_purpose text, p_operation_id text, p_algorithm text, p_bytes_length integer,
  p_request_digest bytea, p_key_id text, p_key_version bigint
)
RETURNS jsonb
LANGUAGE plpgsql VOLATILE PARALLEL UNSAFE SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE operation public.managed_signer_provider_operations%ROWTYPE;
BEGIN
  IF NOT public.agentpass_managed_signer_provider_operation_binding_valid(p_purpose,p_operation_id,p_algorithm,p_bytes_length,p_request_digest,p_key_id,p_key_version)
  THEN RETURN public.agentpass_managed_signer_provider_operation_error('INPUT'); END IF;
  SELECT * INTO operation FROM public.managed_signer_provider_operations
    WHERE purpose=p_purpose AND operation_id=p_operation_id FOR UPDATE;
  IF NOT FOUND THEN RETURN public.agentpass_managed_signer_provider_operation_not_found(); END IF;
  IF operation.algorithm IS DISTINCT FROM p_algorithm OR operation.bytes_length IS DISTINCT FROM p_bytes_length
    OR operation.request_digest IS DISTINCT FROM p_request_digest OR operation.key_id IS DISTINCT FROM p_key_id
    OR operation.key_version IS DISTINCT FROM p_key_version THEN
    RETURN public.agentpass_managed_signer_provider_operation_error('CONFLICT');
  END IF;
  IF operation.state = 'committed' THEN
    RETURN public.agentpass_managed_signer_provider_operation_record(operation.purpose,operation.operation_id,operation.algorithm,operation.bytes_length,operation.request_digest,operation.key_id,operation.key_version,operation.state,operation.claim_expires_at,operation.provider_started_at,operation.uncertain_reason,operation.signature,operation.public_key_der,operation.provider_receipt_provider,operation.provider_receipt_id,false);
  END IF;
  IF operation.state NOT IN ('accepted','uncertain') OR operation.signature IS NULL OR operation.public_key_der IS NULL
    OR operation.provider_receipt_provider IS NULL OR operation.provider_receipt_id IS NULL
  THEN RETURN public.agentpass_managed_signer_provider_operation_error('STATE'); END IF;
  UPDATE public.managed_signer_provider_operations
  SET state='committed', uncertain_reason=NULL, claim_token_digest=NULL, claim_expires_at=NULL
  WHERE purpose=operation.purpose AND operation_id=operation.operation_id
  RETURNING * INTO operation;
  IF NOT FOUND THEN RETURN public.agentpass_managed_signer_provider_operation_error('STATE'); END IF;
  RETURN public.agentpass_managed_signer_provider_operation_record(operation.purpose,operation.operation_id,operation.algorithm,operation.bytes_length,operation.request_digest,operation.key_id,operation.key_version,operation.state,operation.claim_expires_at,operation.provider_started_at,operation.uncertain_reason,operation.signature,operation.public_key_der,operation.provider_receipt_provider,operation.provider_receipt_id,false);
END;
$$;

CREATE FUNCTION public.agentpass_managed_signer_provider_operation_uncertain(
  p_purpose text, p_operation_id text, p_algorithm text, p_bytes_length integer,
  p_request_digest bytea, p_key_id text, p_key_version bigint, p_claim_token_digest bytea,
  p_uncertain_reason text
)
RETURNS jsonb
LANGUAGE plpgsql VOLATILE PARALLEL UNSAFE SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE operation public.managed_signer_provider_operations%ROWTYPE;
BEGIN
  IF NOT public.agentpass_managed_signer_provider_operation_binding_valid(p_purpose,p_operation_id,p_algorithm,p_bytes_length,p_request_digest,p_key_id,p_key_version)
    OR p_claim_token_digest IS NULL OR pg_catalog.octet_length(p_claim_token_digest) <> 32
    OR p_uncertain_reason IS NULL OR p_uncertain_reason NOT IN ('process_interrupted','provider_timeout','provider_response_lost','provider_output_invalid','commit_response_lost','claim_expired_after_start','lifecycle_fenced','recovery_exhausted')
  THEN RETURN public.agentpass_managed_signer_provider_operation_error('INPUT'); END IF;
  SELECT * INTO operation FROM public.managed_signer_provider_operations
    WHERE purpose=p_purpose AND operation_id=p_operation_id FOR UPDATE;
  IF NOT FOUND THEN RETURN public.agentpass_managed_signer_provider_operation_not_found(); END IF;
  IF operation.algorithm IS DISTINCT FROM p_algorithm OR operation.bytes_length IS DISTINCT FROM p_bytes_length
    OR operation.request_digest IS DISTINCT FROM p_request_digest OR operation.key_id IS DISTINCT FROM p_key_id
    OR operation.key_version IS DISTINCT FROM p_key_version THEN
    RETURN public.agentpass_managed_signer_provider_operation_error('CONFLICT');
  END IF;
  IF operation.state IN ('committed','rejected','failed') THEN
    RETURN public.agentpass_managed_signer_provider_operation_record(operation.purpose,operation.operation_id,operation.algorithm,operation.bytes_length,operation.request_digest,operation.key_id,operation.key_version,operation.state,operation.claim_expires_at,operation.provider_started_at,operation.uncertain_reason,operation.signature,operation.public_key_der,operation.provider_receipt_provider,operation.provider_receipt_id,false);
  END IF;
  IF operation.state NOT IN ('pending','started','accepted','uncertain') OR operation.claim_token_digest IS DISTINCT FROM p_claim_token_digest
    OR operation.claim_expires_at IS NULL OR operation.claim_expires_at <= pg_catalog.clock_timestamp()
  THEN RETURN public.agentpass_managed_signer_provider_operation_error('CLAIM_LOST'); END IF;
  UPDATE public.managed_signer_provider_operations
  SET state='uncertain', uncertain_reason=p_uncertain_reason, claim_token_digest=NULL, claim_expires_at=NULL,
      provider_started_at=COALESCE(provider_started_at, pg_catalog.clock_timestamp())
  WHERE purpose=operation.purpose AND operation_id=operation.operation_id
  RETURNING * INTO operation;
  IF NOT FOUND THEN RETURN public.agentpass_managed_signer_provider_operation_error('STATE'); END IF;
  RETURN public.agentpass_managed_signer_provider_operation_record(operation.purpose,operation.operation_id,operation.algorithm,operation.bytes_length,operation.request_digest,operation.key_id,operation.key_version,operation.state,operation.claim_expires_at,operation.provider_started_at,operation.uncertain_reason,operation.signature,operation.public_key_der,operation.provider_receipt_provider,operation.provider_receipt_id,false);
END;
$$;

CREATE FUNCTION public.agentpass_managed_signer_provider_operation_get(
  p_purpose text, p_operation_id text, p_algorithm text, p_bytes_length integer,
  p_request_digest bytea, p_key_id text, p_key_version bigint
)
RETURNS jsonb
LANGUAGE plpgsql STABLE PARALLEL SAFE SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE operation public.managed_signer_provider_operations%ROWTYPE;
BEGIN
  IF NOT public.agentpass_managed_signer_provider_operation_binding_valid(p_purpose,p_operation_id,p_algorithm,p_bytes_length,p_request_digest,p_key_id,p_key_version)
  THEN RETURN public.agentpass_managed_signer_provider_operation_error('INPUT'); END IF;
  SELECT * INTO operation FROM public.managed_signer_provider_operations
    WHERE purpose=p_purpose AND operation_id=p_operation_id;
  IF NOT FOUND THEN RETURN public.agentpass_managed_signer_provider_operation_not_found(); END IF;
  IF operation.algorithm IS DISTINCT FROM p_algorithm OR operation.bytes_length IS DISTINCT FROM p_bytes_length
    OR operation.request_digest IS DISTINCT FROM p_request_digest OR operation.key_id IS DISTINCT FROM p_key_id
    OR operation.key_version IS DISTINCT FROM p_key_version THEN
    RETURN public.agentpass_managed_signer_provider_operation_error('CONFLICT');
  END IF;
  RETURN public.agentpass_managed_signer_provider_operation_record(operation.purpose,operation.operation_id,operation.algorithm,operation.bytes_length,operation.request_digest,operation.key_id,operation.key_version,operation.state,operation.claim_expires_at,operation.provider_started_at,operation.uncertain_reason,operation.signature,operation.public_key_der,operation.provider_receipt_provider,operation.provider_receipt_id,false);
END;
$$;

CREATE FUNCTION public.agentpass_managed_signer_provider_operation_health(
  p_purpose text, p_key_id text, p_key_version bigint, p_algorithm text
)
RETURNS jsonb
LANGUAGE plpgsql STABLE PARALLEL SAFE SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  pending_count bigint; started_count bigint; accepted_count bigint; uncertain_count bigint;
  committed_count bigint; rejected_count bigint; failed_count bigint; stale_count bigint;
  oldest_nonterminal timestamptz;
BEGIN
  IF p_purpose IS NULL OR p_purpose !~ '^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$'
    OR p_key_id IS NULL OR p_key_id !~ '^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$'
    OR p_key_version IS NULL OR p_key_version < 1 OR p_algorithm <> 'ed25519'
  THEN RETURN public.agentpass_managed_signer_provider_operation_error('INPUT'); END IF;
  SELECT count(*) FILTER (WHERE state='pending'), count(*) FILTER (WHERE state='started'),
    count(*) FILTER (WHERE state='accepted'), count(*) FILTER (WHERE state='uncertain'),
    count(*) FILTER (WHERE state='committed'), count(*) FILTER (WHERE state='rejected'),
    count(*) FILTER (WHERE state='failed'),
    count(*) FILTER (WHERE state IN ('pending','started','accepted','uncertain')
      AND claim_expires_at IS NOT NULL AND claim_expires_at <= pg_catalog.clock_timestamp()),
    min(created_at) FILTER (WHERE state IN ('pending','started','accepted','uncertain'))
  INTO pending_count,started_count,accepted_count,uncertain_count,committed_count,rejected_count,failed_count,stale_count,oldest_nonterminal
  FROM public.managed_signer_provider_operations
  WHERE purpose=p_purpose AND key_id=p_key_id AND key_version=p_key_version;
  RETURN pg_catalog.jsonb_build_object('status','ok','health',pg_catalog.jsonb_build_object(
    'version',1,'purpose',p_purpose,'algorithm',p_algorithm,'key_id',p_key_id,'key_version',p_key_version::text,
    'states',pg_catalog.jsonb_build_object('pending',pending_count,'started',started_count,'accepted',accepted_count,'uncertain',uncertain_count,'committed',committed_count,'rejected',rejected_count,'failed',failed_count),
    'stale_claims',stale_count,'oldest_nonterminal_at',oldest_nonterminal
  ));
END;
$$;

CREATE FUNCTION public.agentpass_managed_signer_provider_operation_prune(
  p_purpose text, p_key_id text, p_key_version bigint, p_algorithm text, p_before timestamptz, p_limit integer
)
RETURNS jsonb
LANGUAGE plpgsql VOLATILE PARALLEL UNSAFE SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE pruned_count integer;
BEGIN
  IF p_purpose IS NULL OR p_purpose !~ '^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$'
    OR p_key_id IS NULL OR p_key_id !~ '^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$'
    OR p_key_version IS NULL OR p_key_version < 1 OR p_algorithm IS DISTINCT FROM 'ed25519'
    OR p_before IS NULL OR p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 1000
  THEN RETURN public.agentpass_managed_signer_provider_operation_error('INPUT'); END IF;
  WITH doomed AS MATERIALIZED (
    SELECT provider.purpose, provider.operation_id
    FROM public.managed_signer_provider_operations AS provider
    JOIN public.managed_signer_signing_idempotency AS signing
      ON signing.purpose=provider.purpose AND signing.operation_id=provider.operation_id
    WHERE provider.purpose=p_purpose AND provider.key_id=p_key_id AND provider.key_version=p_key_version
      AND provider.state='committed' AND signing.status='committed'
      AND provider.expires_at <= p_before AND provider.expires_at <= pg_catalog.clock_timestamp()
      AND signing.expires_at <= p_before AND signing.expires_at <= pg_catalog.clock_timestamp()
    ORDER BY provider.expires_at ASC, provider.operation_id ASC
    LIMIT p_limit
    FOR UPDATE OF provider SKIP LOCKED
  ), deleted AS (
    DELETE FROM public.managed_signer_provider_operations AS provider
    USING doomed
    WHERE provider.purpose=doomed.purpose AND provider.operation_id=doomed.operation_id
    RETURNING provider.operation_id
  )
  SELECT count(*)::integer INTO pruned_count FROM deleted;
  RETURN pg_catalog.jsonb_build_object('status','ok','pruned',pruned_count);
END;
$$;

-- Helper functions are not an application API.  Only the ten operation
-- functions are executable by the isolated signer role; PUBLIC receives none.
REVOKE ALL ON FUNCTION public.agentpass_managed_signer_provider_operation_error(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.agentpass_managed_signer_provider_operation_not_found() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.agentpass_managed_signer_provider_operation_binding_valid(text,text,text,integer,bytea,text,bigint) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.agentpass_managed_signer_provider_operation_record(text,text,text,integer,bytea,text,bigint,text,timestamptz,timestamptz,text,bytea,bytea,text,text,boolean) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.agentpass_managed_signer_provider_operation_reserve(text,text,text,integer,bytea,text,bigint,bytea,integer,integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.agentpass_managed_signer_provider_operation_claim(text,text,text,integer,bytea,text,bigint,bytea,integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.agentpass_managed_signer_provider_operation_start(text,text,text,integer,bytea,text,bigint,bytea) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.agentpass_managed_signer_provider_operation_accept(text,text,text,integer,bytea,text,bigint,bytea,bytea,bytea,text,text,text,text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.agentpass_managed_signer_provider_operation_commit(text,text,text,integer,bytea,text,bigint,bytea) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.agentpass_managed_signer_provider_operation_reconcile(text,text,text,integer,bytea,text,bigint) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.agentpass_managed_signer_provider_operation_uncertain(text,text,text,integer,bytea,text,bigint,bytea,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.agentpass_managed_signer_provider_operation_get(text,text,text,integer,bytea,text,bigint) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.agentpass_managed_signer_provider_operation_health(text,text,bigint,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.agentpass_managed_signer_provider_operation_prune(text,text,bigint,text,timestamptz,integer) FROM PUBLIC;

COMMENT ON FUNCTION public.agentpass_managed_signer_provider_operation_reserve(text,text,text,integer,bytea,text,bigint,bytea,integer,integer) IS 'Atomically inserts or reclaims one bound pending provider operation using the database clock.';
COMMENT ON FUNCTION public.agentpass_managed_signer_provider_operation_claim(text,text,text,integer,bytea,text,bigint,bytea,integer) IS 'Claims one provider operation under a database-clock fencing lease.';
COMMENT ON FUNCTION public.agentpass_managed_signer_provider_operation_accept(text,text,text,integer,bytea,text,bigint,bytea,bytea,bytea,text,text,text,text,text) IS 'Persists one validated public provider result under the exact operation claim.';
COMMENT ON FUNCTION public.agentpass_managed_signer_provider_operation_prune(text,text,bigint,text,timestamptz,integer) IS 'Prunes a bounded set of jointly committed, expired provider and signing records with SKIP LOCKED.';

COMMIT;
