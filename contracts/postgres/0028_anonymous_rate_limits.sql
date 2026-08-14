BEGIN;

-- Anonymous recovery exchanges cannot use rate_limit_buckets because that
-- table is tenant-bound. Only a one-way, UUID-shaped principal digest is
-- stored here; raw exchanges and network identifiers are never persisted.
CREATE TABLE anonymous_rate_limit_buckets (
  operation text NOT NULL CHECK (
    char_length(operation) BETWEEN 1 AND 128
    AND operation ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
  ),
  principal_id uuid NOT NULL,
  capacity integer NOT NULL CHECK (capacity > 0),
  refill_per_second numeric NOT NULL CHECK (refill_per_second > 0),
  tokens numeric NOT NULL CHECK (tokens >= 0 AND tokens <= capacity),
  updated_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  PRIMARY KEY (operation, principal_id),
  CHECK (expires_at > updated_at)
);

CREATE INDEX anonymous_rate_limit_buckets_expiry
  ON anonymous_rate_limit_buckets (expires_at, operation, principal_id);

CREATE FUNCTION agentpass_acquire_anonymous_rate_limit(
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
  now_value timestamptz := clock_timestamp();
  bucket anonymous_rate_limit_buckets%ROWTYPE;
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
     request_refill_per_second, request_capacity, now_value,
     now_value + (idle_ttl_ms * interval '1 millisecond'))
  ON CONFLICT (operation, principal_id) DO NOTHING;

  SELECT * INTO bucket
  FROM anonymous_rate_limit_buckets
  WHERE operation = request_operation AND principal_id = request_principal_id
  FOR UPDATE;

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

CREATE FUNCTION agentpass_prune_anonymous_rate_limits(prune_limit integer)
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
    LIMIT prune_limit
  );
  GET DIAGNOSTICS deleted_count = ROW_COUNT;
  RETURN QUERY SELECT deleted_count;
END;
$$;

COMMENT ON TABLE anonymous_rate_limit_buckets IS
  'Global anonymous admission control keyed only by operation and one-way principal identifiers.';

COMMIT;
