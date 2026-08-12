BEGIN;

-- Cutover preflight: the legacy schema only enforced member existence, not
-- same-organization attribution. Do not let PostgreSQL surface a generic
-- foreign-key failure after partially preparing the hosted schema. Keep this
-- diagnostic stable for deployment tooling and incident runbooks.
DO $agentpass_0011_preflight$
DECLARE
  total_violations bigint;
  table_counts text;
BEGIN
  WITH violations(table_name, violation_count) AS (
    SELECT 'device_enrollments', count(*)
    FROM device_enrollments e
    WHERE NOT EXISTS (
      SELECT 1
      FROM memberships m
      WHERE m.organization_id = e.organization_id
        AND m.member_id = e.created_by
    )
    UNION ALL
    SELECT 'policies', count(*)
    FROM policies p
    WHERE NOT EXISTS (
      SELECT 1
      FROM memberships m
      WHERE m.organization_id = p.organization_id
        AND m.member_id = p.created_by
    )
    UNION ALL
    SELECT 'revocations', count(*)
    FROM revocations r
    WHERE NOT EXISTS (
      SELECT 1
      FROM memberships m
      WHERE m.organization_id = r.organization_id
        AND m.member_id = r.created_by
    )
  )
  SELECT COALESCE(sum(violation_count), 0)::bigint,
    COALESCE(string_agg(format('%s=%s', table_name, violation_count), ', ' ORDER BY table_name), 'none')
  INTO total_violations, table_counts
  FROM violations
  WHERE violation_count > 0;

  IF total_violations > 0 THEN
    RAISE EXCEPTION USING
      ERRCODE = 'check_violation',
      MESSAGE = 'AGENTPASS_0011_PREFLIGHT_CROSS_TENANT_CREATED_BY',
      DETAIL = format('same-organization membership attribution violations: %s', table_counts),
      HINT = 'Repair or quarantine the listed rows so created_by is an active or historical membership in the same organization, rerun the preflight, then retry migration 0011.';
  END IF;
END;
$agentpass_0011_preflight$;

-- Hosted control-plane writes need a bounded, structured metadata field.  The
-- existing key/state check is repeated with a named constraint so the pending
-- reservation rule remains visible to schema inspection and future changes.
ALTER TABLE devices
  ALTER COLUMN key_algorithm DROP NOT NULL,
  ADD COLUMN metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  ADD CONSTRAINT devices_metadata_object CHECK (
    jsonb_typeof(metadata) = 'object'
    AND octet_length(metadata::text) <= 16384
  ),
  ADD CONSTRAINT devices_pending_key_state CHECK (
    (status = 'pending' AND public_key_pem IS NULL)
    OR (status <> 'pending' AND key_algorithm IS NOT NULL AND public_key_pem LIKE '-----BEGIN PUBLIC KEY-----%')
  );

-- A reservation carries the user-visible device binding and its intended
-- platform.  Completion evidence is a digest only; legacy consumed rows are
-- retained as historical rows without fabricated completion evidence.
ALTER TABLE device_enrollments
  ADD COLUMN label text NOT NULL DEFAULT 'Unnamed device',
  ADD COLUMN platform text NOT NULL DEFAULT 'macos',
  ADD COLUMN completion_hash text;

UPDATE device_enrollments e
SET label = d.label,
    platform = 'macos'
FROM devices d
WHERE d.organization_id = e.organization_id
  AND d.id = e.device_id;

UPDATE device_enrollments
SET label = 'Unnamed device'
WHERE label IS NULL;

UPDATE device_enrollments
SET platform = 'macos'
WHERE platform IS NULL;

ALTER TABLE device_enrollments
  ALTER COLUMN label SET NOT NULL,
  ALTER COLUMN platform SET NOT NULL,
  ADD CONSTRAINT device_enrollments_label_valid CHECK (
    char_length(label) BETWEEN 1 AND 128
    AND label !~ '[[:cntrl:]]'
  ),
  ADD CONSTRAINT device_enrollments_platform_valid CHECK (
    platform IN ('macos')
  ),
  ADD CONSTRAINT device_enrollments_completion_hash_valid CHECK (
    completion_hash IS NULL OR completion_hash ~ '^[0-9a-f]{64}$'
  ),
  ADD CONSTRAINT device_enrollments_completion_evidence_complete CHECK (
    (consumed_at IS NULL AND completion_hash IS NULL)
    OR (consumed_at IS NOT NULL AND completion_hash IS NOT NULL)
  ) NOT VALID,
  ADD CONSTRAINT device_enrollments_created_by_tenant_fk
    FOREIGN KEY (organization_id, created_by) REFERENCES memberships(organization_id, member_id)
    NOT VALID;

CREATE INDEX device_enrollments_expiry
  ON device_enrollments (organization_id, expires_at, id)
  WHERE consumed_at IS NULL;

ALTER TABLE policies
  ADD COLUMN version bigint NOT NULL DEFAULT 1,
  ADD COLUMN updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  ADD CONSTRAINT policies_version_valid CHECK (version > 0),
  ADD CONSTRAINT policies_updated_at_valid CHECK (updated_at >= created_at),
  ADD CONSTRAINT policies_created_by_tenant_fk
    FOREIGN KEY (organization_id, created_by) REFERENCES memberships(organization_id, member_id)
    NOT VALID;

UPDATE policies
SET updated_at = created_at;

ALTER TABLE revocations
  ADD COLUMN revoked_by uuid,
  ADD COLUMN revoked_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  ADD COLUMN version bigint NOT NULL DEFAULT 1,
  ADD CONSTRAINT revocations_version_valid CHECK (version > 0),
  ADD CONSTRAINT revocations_revoked_at_valid CHECK (revoked_at >= created_at),
  ADD CONSTRAINT revocations_revoked_by_fk
    FOREIGN KEY (revoked_by) REFERENCES members(id),
  ADD CONSTRAINT revocations_created_by_tenant_fk
    FOREIGN KEY (organization_id, created_by) REFERENCES memberships(organization_id, member_id)
    NOT VALID,
  ADD CONSTRAINT revocations_revoked_by_tenant_fk
    FOREIGN KEY (organization_id, revoked_by) REFERENCES memberships(organization_id, member_id)
    NOT VALID;

UPDATE revocations
SET revoked_by = created_by,
    revoked_at = created_at;

CREATE INDEX revocations_active_lookup
  ON revocations (organization_id, target_type, target_id, sequence)
  WHERE status = 'active';

-- 0007 already added issued_by_member_id and issued_membership_version.  Keep
-- their tenant-qualified authority constraints. Hosted reservations persist
-- the complete public statement metadata plus only a digest of the derived
-- nonce, never the nonce itself.
ALTER TABLE capabilities
  ADD COLUMN issuer text,
  ADD COLUMN key_id text,
  ADD COLUMN scope_json jsonb,
  ADD COLUMN not_before timestamptz,
  ADD COLUMN nonce_digest bytea,
  ADD COLUMN version bigint NOT NULL DEFAULT 1,
  ADD CONSTRAINT capabilities_issuer_valid CHECK (
    issuer IS NULL OR (char_length(issuer) BETWEEN 1 AND 128 AND issuer !~ '[[:cntrl:]]')
  ),
  ADD CONSTRAINT capabilities_key_id_valid CHECK (
    key_id IS NULL OR (char_length(key_id) BETWEEN 1 AND 128 AND key_id !~ '[[:cntrl:]]')
  ),
  ADD CONSTRAINT capabilities_scope_object CHECK (
    scope_json IS NULL OR jsonb_typeof(scope_json) = 'object'
  ),
  ADD CONSTRAINT capabilities_nonce_digest_valid CHECK (
    nonce_digest IS NULL OR octet_length(nonce_digest) = 32
  ),
  ADD CONSTRAINT capabilities_version_valid CHECK (version > 0);

CREATE INDEX capabilities_expiry
  ON capabilities (organization_id, expires_at, id)
  WHERE revoked_at IS NULL;

ALTER TABLE bundle_heads
  ADD COLUMN expires_at timestamptz DEFAULT (clock_timestamp() + interval '1 microsecond');

-- Existing heads have no trustworthy historical TTL.  Expire them immediately
-- after their issuance boundary rather than extending authority on cutover.
UPDATE bundle_heads
SET expires_at = issued_at + interval '1 microsecond';

ALTER TABLE bundle_heads
  ALTER COLUMN expires_at SET NOT NULL,
  ADD CONSTRAINT bundle_heads_expiry_valid CHECK (expires_at > issued_at);

CREATE INDEX bundle_heads_expiry
  ON bundle_heads (organization_id, expires_at, device_id);

ALTER TABLE bundle_acknowledgements
  ADD CONSTRAINT bundle_acknowledgements_format_epoch_valid CHECK (format_epoch >= 2),
  ADD CONSTRAINT bundle_acknowledgements_sequence_valid CHECK (sequence > 0),
  ADD CONSTRAINT bundle_acknowledgements_reason_valid CHECK (
    reason IS NULL OR (char_length(reason) BETWEEN 1 AND 128 AND reason !~ '[[:cntrl:]]')
  ),
  ADD CONSTRAINT bundle_acknowledgements_applied_reason_valid CHECK (
    (status = 'blocked' AND reason IS NOT NULL)
    OR (status = 'applied' AND reason IS NULL)
  ),
  ADD CONSTRAINT bundle_acknowledgements_head_fk
    FOREIGN KEY (organization_id, device_id, format_epoch, sequence, statement_hash)
    REFERENCES bundle_heads(organization_id, device_id, format_epoch, sequence, statement_hash)
    NOT VALID;

-- Device audit state is durable and tenant-qualified.  A head records the
-- latest accepted event and cumulative gap state; a gap records the exact
-- predecessor mismatch without retaining request credentials or payloads.
CREATE TABLE device_audit_heads (
  organization_id uuid NOT NULL,
  device_id uuid NOT NULL,
  sequence bigint NOT NULL DEFAULT 0 CHECK (sequence >= 0),
  last_event_id uuid,
  last_event_hash text NOT NULL DEFAULT repeat('0', 64) CHECK (last_event_hash ~ '^[0-9a-f]{64}$'),
  chain_status text NOT NULL DEFAULT 'continuous' CHECK (chain_status IN ('continuous', 'gap')),
  gap_count bigint NOT NULL DEFAULT 0 CHECK (gap_count >= 0),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (organization_id, device_id),
  FOREIGN KEY (organization_id, device_id) REFERENCES devices(organization_id, id),
  FOREIGN KEY (organization_id, device_id, last_event_id)
    REFERENCES device_audit_events(organization_id, device_id, event_id),
  CHECK (
    (sequence = 0 AND last_event_id IS NULL AND last_event_hash = repeat('0', 64) AND gap_count = 0)
    OR (sequence > 0 AND last_event_id IS NOT NULL)
  ),
  CHECK ((chain_status = 'continuous' AND gap_count = 0) OR chain_status = 'gap')
);

CREATE TABLE device_audit_gaps (
  organization_id uuid NOT NULL,
  device_id uuid NOT NULL,
  gap_id uuid NOT NULL,
  event_id uuid NOT NULL,
  expected_previous_hash text NOT NULL CHECK (expected_previous_hash ~ '^[0-9a-f]{64}$'),
  received_previous_hash text NOT NULL CHECK (received_previous_hash ~ '^[0-9a-f]{64}$'),
  recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  resolved_at timestamptz,
  PRIMARY KEY (organization_id, device_id, gap_id),
  UNIQUE (organization_id, device_id, event_id),
  FOREIGN KEY (organization_id, device_id) REFERENCES devices(organization_id, id),
  FOREIGN KEY (organization_id, device_id, event_id)
    REFERENCES device_audit_events(organization_id, device_id, event_id),
  CHECK (resolved_at IS NULL OR resolved_at >= recorded_at)
);

WITH ranked AS (
  SELECT e.organization_id,
    e.device_id,
    e.event_id,
    e.previous_hash,
    e.event_hash,
    e.received_at,
    row_number() OVER (PARTITION BY e.organization_id, e.device_id ORDER BY e.received_at, e.event_id) AS sequence,
    lag(e.event_hash, 1, repeat('0', 64)) OVER (PARTITION BY e.organization_id, e.device_id ORDER BY e.received_at, e.event_id) AS expected_previous_hash
  FROM device_audit_events e
), stats AS (
  SELECT organization_id,
    device_id,
    count(*) AS sequence,
    count(*) FILTER (WHERE previous_hash <> expected_previous_hash) AS gap_count
  FROM ranked
  GROUP BY organization_id, device_id
), latest AS (
  SELECT DISTINCT ON (organization_id, device_id)
    organization_id, device_id, event_id, event_hash
  FROM ranked
  ORDER BY organization_id, device_id, sequence DESC
)
INSERT INTO device_audit_heads
  (organization_id, device_id, sequence, last_event_id, last_event_hash, chain_status, gap_count)
SELECT d.organization_id,
  d.id,
  COALESCE(stats.sequence, 0),
  latest.event_id,
  COALESCE(latest.event_hash, repeat('0', 64)),
  CASE WHEN COALESCE(stats.gap_count, 0) > 0 THEN 'gap' ELSE 'continuous' END,
  COALESCE(stats.gap_count, 0)
FROM devices d
LEFT JOIN stats ON stats.organization_id = d.organization_id AND stats.device_id = d.id
LEFT JOIN latest ON latest.organization_id = d.organization_id AND latest.device_id = d.id;

WITH ranked AS (
  SELECT e.organization_id,
    e.device_id,
    e.event_id,
    e.previous_hash,
    e.received_at,
    lag(e.event_hash, 1, repeat('0', 64)) OVER (PARTITION BY e.organization_id, e.device_id ORDER BY e.received_at, e.event_id) AS expected_previous_hash
  FROM device_audit_events e
)
INSERT INTO device_audit_gaps
  (organization_id, device_id, gap_id, event_id, expected_previous_hash, received_previous_hash, recorded_at)
SELECT organization_id,
  device_id,
  event_id,
  event_id,
  expected_previous_hash,
  previous_hash,
  received_at
FROM ranked
WHERE previous_hash <> expected_previous_hash;

CREATE FUNCTION agentpass_record_device_audit_head()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  head device_audit_heads%ROWTYPE;
  gap boolean;
BEGIN
  INSERT INTO device_audit_heads (organization_id, device_id)
  VALUES (NEW.organization_id, NEW.device_id)
  ON CONFLICT (organization_id, device_id) DO NOTHING;

  SELECT * INTO head
  FROM device_audit_heads
  WHERE organization_id = NEW.organization_id AND device_id = NEW.device_id
  FOR UPDATE;

  gap := NEW.previous_hash <> head.last_event_hash;
  IF gap THEN
    INSERT INTO device_audit_gaps
      (organization_id, device_id, gap_id, event_id, expected_previous_hash, received_previous_hash, recorded_at)
    VALUES
      (NEW.organization_id, NEW.device_id, NEW.event_id, NEW.event_id, head.last_event_hash, NEW.previous_hash, NEW.received_at)
    ON CONFLICT (organization_id, device_id, event_id) DO NOTHING;
  END IF;

  UPDATE device_audit_heads
  SET sequence = head.sequence + 1,
      last_event_id = NEW.event_id,
      last_event_hash = NEW.event_hash,
      chain_status = CASE WHEN gap OR head.chain_status = 'gap' THEN 'gap' ELSE 'continuous' END,
      gap_count = head.gap_count + CASE WHEN gap THEN 1 ELSE 0 END,
      updated_at = clock_timestamp()
  WHERE organization_id = NEW.organization_id AND device_id = NEW.device_id;
  RETURN NEW;
END;
$$;

CREATE TRIGGER device_audit_events_record_head
  AFTER INSERT ON device_audit_events
  FOR EACH ROW
  EXECUTE FUNCTION agentpass_record_device_audit_head();

CREATE INDEX device_audit_heads_status
  ON device_audit_heads (organization_id, chain_status, updated_at);

CREATE INDEX device_audit_gaps_open
  ON device_audit_gaps (organization_id, device_id, recorded_at, gap_id)
  WHERE resolved_at IS NULL;

CREATE TABLE device_request_nonces (
  organization_id uuid NOT NULL,
  device_id uuid NOT NULL,
  nonce_digest bytea NOT NULL CHECK (octet_length(nonce_digest) = 32),
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (organization_id, device_id, nonce_digest),
  FOREIGN KEY (organization_id, device_id) REFERENCES devices(organization_id, id),
  CHECK (expires_at > created_at)
);

CREATE INDEX device_request_nonces_expiry
  ON device_request_nonces (expires_at, organization_id, device_id, nonce_digest);

CREATE TABLE rate_limit_buckets (
  organization_id uuid NOT NULL REFERENCES organizations(id),
  principal_type text NOT NULL CHECK (principal_type IN ('human', 'device')),
  principal_id uuid NOT NULL,
  capacity integer NOT NULL CHECK (capacity > 0),
  refill_per_second numeric NOT NULL CHECK (refill_per_second > 0),
  tokens numeric NOT NULL CHECK (tokens >= 0 AND tokens <= capacity),
  updated_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  PRIMARY KEY (organization_id, principal_type, principal_id),
  CHECK (expires_at > updated_at)
);

CREATE INDEX rate_limit_buckets_expiry
  ON rate_limit_buckets (expires_at, organization_id, principal_type, principal_id);

CREATE INDEX idempotency_records_expiry
  ON idempotency_records (expires_at, organization_id, principal_id, idempotency_key);

CREATE FUNCTION agentpass_consume_device_request_nonce(
  request_organization_id uuid,
  request_device_id uuid,
  request_nonce_digest bytea,
  ttl_ms integer
)
RETURNS TABLE (accepted boolean)
LANGUAGE plpgsql
VOLATILE
AS $$
BEGIN
  IF request_nonce_digest IS NULL
     OR octet_length(request_nonce_digest) <> 32
     OR ttl_ms IS NULL
     OR ttl_ms < 1000
     OR ttl_ms > 900000 THEN
    RETURN QUERY SELECT false;
    RETURN;
  END IF;

  DELETE FROM device_request_nonces
  WHERE organization_id = request_organization_id
    AND device_id = request_device_id
    AND nonce_digest = request_nonce_digest
    AND expires_at <= clock_timestamp();

  INSERT INTO device_request_nonces
    (organization_id, device_id, nonce_digest, expires_at)
  VALUES
    (request_organization_id, request_device_id, request_nonce_digest,
     clock_timestamp() + (ttl_ms * interval '1 millisecond'))
  ON CONFLICT (organization_id, device_id, nonce_digest) DO NOTHING;

  RETURN QUERY SELECT FOUND;
END;
$$;

CREATE FUNCTION agentpass_acquire_rate_limit(
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
  now_value timestamptz := clock_timestamp();
  bucket rate_limit_buckets%ROWTYPE;
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
     request_capacity, request_refill_per_second, request_capacity, now_value,
     now_value + (idle_ttl_ms * interval '1 millisecond'))
  ON CONFLICT (organization_id, principal_type, principal_id) DO NOTHING;

  SELECT * INTO bucket
  FROM rate_limit_buckets
  WHERE organization_id = request_organization_id
    AND principal_type = request_principal_type
    AND principal_id = request_principal_id
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

CREATE FUNCTION agentpass_prune_shared_control_expired(prune_limit integer)
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
      LIMIT remaining
    );
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    total_removed := total_removed + deleted_count;
  END IF;

  RETURN QUERY SELECT total_removed;
END;
$$;

COMMIT;
