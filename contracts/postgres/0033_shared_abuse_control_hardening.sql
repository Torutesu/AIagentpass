BEGIN;

-- The transaction-stable timestamp used for a newly-created bucket is
-- deliberately not clock_timestamp().  The first wall-clock sample must be
-- taken only after the existing row has been locked.  Otherwise a request
-- that waited on a contended bucket could refill from a timestamp captured
-- before the wait.
CREATE OR REPLACE FUNCTION agentpass_acquire_rate_limit(
  request_organization_id uuid,
  request_principal_type text,
  request_principal_id uuid,
  request_capacity integer,
  request_refill_per_second numeric,
  request_cost integer,
  idle_ttl_ms integer
)
RETURNS TABLE (
  allowed boolean,
  rate_limit integer,
  remaining integer,
  retry_after_ms bigint,
  reset_at timestamptz
)
LANGUAGE plpgsql
VOLATILE
AS $$
DECLARE
  bucket rate_limit_buckets%ROWTYPE;
  now_value timestamptz;
  elapsed_seconds numeric;
  new_tokens numeric;
  retry_ms bigint := 0;
  decision boolean;
  next_reset timestamptz;
BEGIN
  IF request_principal_type NOT IN ('human', 'device')
     OR request_capacity IS NULL
     OR request_capacity < 1
     OR request_refill_per_second IS NULL
     OR request_refill_per_second <= 0
     OR request_cost IS NULL
     OR request_cost < 1
     OR request_cost > request_capacity
     OR idle_ttl_ms IS NULL
     OR idle_ttl_ms < 1000
     OR idle_ttl_ms > 86400000 THEN
    RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'invalid rate-limit parameters';
  END IF;

  INSERT INTO rate_limit_buckets
    (organization_id, principal_type, principal_id, capacity, refill_per_second, tokens, updated_at, expires_at)
  VALUES
    (request_organization_id, request_principal_type, request_principal_id,
     request_capacity, request_refill_per_second, request_capacity, CURRENT_TIMESTAMP,
     CURRENT_TIMESTAMP + (idle_ttl_ms * interval '1 millisecond'))
  ON CONFLICT (organization_id, principal_type, principal_id) DO NOTHING;

  SELECT * INTO bucket
  FROM rate_limit_buckets
  WHERE organization_id = request_organization_id
    AND principal_type = request_principal_type
    AND principal_id = request_principal_id
  FOR UPDATE;

  -- Sample only after FOR UPDATE has acquired the row lock.  GREATEST also
  -- prevents a clock adjustment from moving updated_at backwards.
  now_value := GREATEST(clock_timestamp(), bucket.updated_at);
  elapsed_seconds := GREATEST(0, EXTRACT(EPOCH FROM (now_value - bucket.updated_at)));
  new_tokens := LEAST(request_capacity::numeric, bucket.tokens + elapsed_seconds * request_refill_per_second);
  decision := new_tokens >= request_cost;
  IF decision THEN
    new_tokens := new_tokens - request_cost;
    next_reset := now_value;
  ELSE
    retry_ms := CEIL(((request_cost - new_tokens) / request_refill_per_second) * 1000)::bigint;
    next_reset := now_value + (((request_cost - new_tokens) / request_refill_per_second) * interval '1 second');
  END IF;

  UPDATE rate_limit_buckets
  SET capacity = request_capacity,
      refill_per_second = request_refill_per_second,
      tokens = new_tokens,
      updated_at = now_value,
      expires_at = now_value + (idle_ttl_ms * interval '1 millisecond')
  WHERE organization_id = request_organization_id
    AND principal_type = request_principal_type
    AND principal_id = request_principal_id;

  RETURN QUERY SELECT decision, request_capacity, FLOOR(new_tokens)::integer, retry_ms, next_reset;
END;
$$;

CREATE OR REPLACE FUNCTION agentpass_acquire_anonymous_rate_limit(
  request_operation text,
  request_principal_id uuid,
  request_capacity integer,
  request_refill_per_second numeric,
  request_cost integer,
  idle_ttl_ms integer
)
RETURNS TABLE (
  allowed boolean,
  rate_limit integer,
  remaining integer,
  retry_after_ms bigint,
  reset_at timestamptz
)
LANGUAGE plpgsql
VOLATILE
AS $$
DECLARE
  bucket anonymous_rate_limit_buckets%ROWTYPE;
  now_value timestamptz;
  elapsed_seconds numeric;
  new_tokens numeric;
  retry_ms bigint := 0;
  decision boolean;
  next_reset timestamptz;
BEGIN
  IF request_operation IS NULL
     OR char_length(request_operation) NOT BETWEEN 1 AND 128
     OR request_operation !~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
     OR request_principal_id IS NULL
     OR request_capacity IS NULL OR request_capacity < 1
     OR request_refill_per_second IS NULL OR request_refill_per_second <= 0
     OR request_cost IS NULL OR request_cost < 1 OR request_cost > request_capacity
     OR idle_ttl_ms IS NULL OR idle_ttl_ms < 1000 OR idle_ttl_ms > 86400000 THEN
    RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'invalid anonymous rate-limit parameters';
  END IF;

  INSERT INTO anonymous_rate_limit_buckets
    (operation, principal_id, capacity, refill_per_second, tokens, updated_at, expires_at)
  VALUES
    (request_operation, request_principal_id, request_capacity,
     request_refill_per_second, request_capacity, CURRENT_TIMESTAMP,
     CURRENT_TIMESTAMP + (idle_ttl_ms * interval '1 millisecond'))
  ON CONFLICT (operation, principal_id) DO NOTHING;

  SELECT * INTO bucket
  FROM anonymous_rate_limit_buckets
  WHERE operation = request_operation AND principal_id = request_principal_id
  FOR UPDATE;

  now_value := GREATEST(clock_timestamp(), bucket.updated_at);
  elapsed_seconds := GREATEST(0, EXTRACT(EPOCH FROM (now_value - bucket.updated_at)));
  new_tokens := LEAST(request_capacity::numeric, bucket.tokens + elapsed_seconds * request_refill_per_second);
  decision := new_tokens >= request_cost;
  IF decision THEN
    new_tokens := new_tokens - request_cost;
    next_reset := now_value;
  ELSE
    retry_ms := CEIL(((request_cost - new_tokens) / request_refill_per_second) * 1000)::bigint;
    next_reset := now_value + (((request_cost - new_tokens) / request_refill_per_second) * interval '1 second');
  END IF;

  UPDATE anonymous_rate_limit_buckets
  SET capacity = request_capacity,
      refill_per_second = request_refill_per_second,
      tokens = new_tokens,
      updated_at = now_value,
      expires_at = now_value + (idle_ttl_ms * interval '1 millisecond')
  WHERE operation = request_operation AND principal_id = request_principal_id;

  RETURN QUERY SELECT decision, request_capacity, FLOOR(new_tokens)::integer, retry_ms, next_reset;
END;
$$;

-- Every candidate query locks its bounded batch before deletion.  This makes
-- concurrent maintenance workers cooperate instead of selecting the same
-- expired rows and waiting on a delete lock after the bound was chosen.
CREATE OR REPLACE FUNCTION agentpass_prune_shared_control_expired(prune_limit integer)
RETURNS TABLE (removed bigint)
LANGUAGE plpgsql
VOLATILE
AS $$
DECLARE
  remaining integer := prune_limit;
  deleted_count bigint;
  total_removed bigint := 0;
BEGIN
  IF prune_limit IS NULL OR prune_limit < 1 OR prune_limit > 10000 THEN
    RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'invalid prune limit';
  END IF;

  DELETE FROM idempotency_records
  WHERE ctid IN (
    SELECT ctid FROM idempotency_records
    WHERE expires_at <= clock_timestamp()
    ORDER BY expires_at, organization_id, principal_id, idempotency_key
    FOR UPDATE SKIP LOCKED
    LIMIT remaining
  );
  GET DIAGNOSTICS deleted_count = ROW_COUNT;
  total_removed := total_removed + deleted_count;
  remaining := remaining - deleted_count::integer;

  IF remaining > 0 THEN
    DELETE FROM device_request_nonces
    WHERE ctid IN (
      SELECT ctid FROM device_request_nonces
      WHERE expires_at <= clock_timestamp()
      ORDER BY expires_at, organization_id, device_id, nonce_digest
      FOR UPDATE SKIP LOCKED
      LIMIT remaining
    );
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    total_removed := total_removed + deleted_count;
    remaining := remaining - deleted_count::integer;
  END IF;

  IF remaining > 0 THEN
    DELETE FROM rate_limit_buckets
    WHERE ctid IN (
      SELECT ctid FROM rate_limit_buckets
      WHERE expires_at <= clock_timestamp()
      ORDER BY expires_at, organization_id, principal_type, principal_id
      FOR UPDATE SKIP LOCKED
      LIMIT remaining
    );
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    total_removed := total_removed + deleted_count;
    remaining := remaining - deleted_count::integer;
  END IF;

  IF remaining > 0 THEN
    DELETE FROM human_identity_assertion_replays
    WHERE ctid IN (
      SELECT ctid FROM human_identity_assertion_replays
      WHERE expires_at <= clock_timestamp()
      ORDER BY expires_at, jti_digest
      FOR UPDATE SKIP LOCKED
      LIMIT remaining
    );
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    total_removed := total_removed + deleted_count;
  END IF;

  RETURN QUERY SELECT total_removed;
END;
$$;

CREATE OR REPLACE FUNCTION agentpass_prune_anonymous_rate_limits(prune_limit integer)
RETURNS TABLE (removed bigint)
LANGUAGE plpgsql
VOLATILE
AS $$
DECLARE
  deleted_count bigint;
BEGIN
  IF prune_limit IS NULL OR prune_limit < 1 OR prune_limit > 10000 THEN
    RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'invalid anonymous rate-limit prune limit';
  END IF;

  DELETE FROM anonymous_rate_limit_buckets
  WHERE ctid IN (
    SELECT ctid FROM anonymous_rate_limit_buckets
    WHERE expires_at <= clock_timestamp()
    ORDER BY expires_at, operation, principal_id
    FOR UPDATE SKIP LOCKED
    LIMIT prune_limit
  );
  GET DIAGNOSTICS deleted_count = ROW_COUNT;
  RETURN QUERY SELECT deleted_count;
END;
$$;

CREATE OR REPLACE FUNCTION agentpass_prune_human_identity_assertion_replays(prune_limit integer)
RETURNS TABLE (removed bigint)
LANGUAGE plpgsql
VOLATILE
AS $$
DECLARE
  deleted_count bigint;
BEGIN
  IF prune_limit IS NULL OR prune_limit < 1 OR prune_limit > 10000 THEN
    RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE = 'invalid human identity assertion replay prune limit';
  END IF;

  DELETE FROM human_identity_assertion_replays
  WHERE ctid IN (
    SELECT ctid FROM human_identity_assertion_replays
    WHERE expires_at <= clock_timestamp()
    ORDER BY expires_at, jti_digest
    FOR UPDATE SKIP LOCKED
    LIMIT prune_limit
  );
  GET DIAGNOSTICS deleted_count = ROW_COUNT;
  RETURN QUERY SELECT deleted_count;
END;
$$;

COMMIT;
