BEGIN;

-- Audit export issuance is the organization-scoped authority for one frozen
-- export request.  The caller supplies only the identity columns; all range,
-- digest, time, and signer columns are the repository's authoritative snapshot.
-- Claim material is a digest only, and the signed envelope is public evidence.
CREATE FUNCTION agentpass_jsonb_object_key_count(p_value jsonb)
RETURNS integer
LANGUAGE sql
IMMUTABLE
STRICT
PARALLEL SAFE
SET search_path = pg_catalog
AS $$
  SELECT count(*)::integer FROM jsonb_object_keys(p_value);
$$;

CREATE TABLE audit_export_issuances (
  organization_id uuid NOT NULL REFERENCES organizations(id),
  export_id uuid NOT NULL,
  environment text NOT NULL CHECK (environment IN ('staging', 'production')),
  chain text NOT NULL CHECK (chain IN ('admin', 'device', 'cloud_agent')),
  idempotency_key text NOT NULL CHECK (
    char_length(idempotency_key) BETWEEN 8 AND 255
    AND idempotency_key ~ '^[A-Za-z0-9][A-Za-z0-9._~:-]{7,254}$'
  ),

  from_audit_position bigint NOT NULL
    CHECK (from_audit_position BETWEEN 1 AND 9007199254740991),
  to_audit_position bigint NOT NULL
    CHECK (to_audit_position BETWEEN 1 AND 9007199254740991),
  previous_root_digest bytea NOT NULL
    CHECK (octet_length(previous_root_digest) = 32),
  root_digest bytea NOT NULL
    CHECK (octet_length(root_digest) = 32
      AND root_digest <> decode(repeat('00', 32), 'hex')),
  record_count bigint NOT NULL
    CHECK (record_count BETWEEN 1 AND 9007199254740991),
  payload_digest bytea NOT NULL
    CHECK (octet_length(payload_digest) = 32
      AND payload_digest <> decode(repeat('00', 32), 'hex')),
  request_digest bytea NOT NULL
    CHECK (octet_length(request_digest) = 32),

  issued_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  key_id text NOT NULL
    CHECK (key_id ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$'),
  key_version bigint NOT NULL
    CHECK (key_version BETWEEN 1 AND 9007199254740991),
  lifecycle_version bigint NOT NULL
    CHECK (lifecycle_version BETWEEN 1 AND 9007199254740991),

  state text NOT NULL CHECK (state IN ('reserved', 'uncertain', 'committed')),
  claim_token_digest bytea
    CHECK (claim_token_digest IS NULL OR octet_length(claim_token_digest) = 32),
  claim_expires_at timestamptz,
  uncertain_reason text,
  audit_anchor jsonb,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),

  PRIMARY KEY (organization_id, export_id, environment, chain, idempotency_key),
  UNIQUE (organization_id, export_id),
  UNIQUE (organization_id, environment, chain, idempotency_key),
  CHECK (to_audit_position >= from_audit_position),
  CHECK (record_count = to_audit_position - from_audit_position + 1),
  CHECK (
    (from_audit_position = 1
      AND previous_root_digest = decode(repeat('00', 32), 'hex'))
    OR (from_audit_position > 1
      AND previous_root_digest <> decode(repeat('00', 32), 'hex'))
  ),
  CHECK (expires_at > issued_at),
  CHECK (expires_at <= issued_at + interval '1 hour'),
  CHECK (updated_at >= created_at),
  CHECK (
    (state = 'reserved'
      AND claim_token_digest IS NOT NULL
      AND claim_expires_at IS NOT NULL
      AND claim_expires_at > created_at
      AND uncertain_reason IS NULL
      AND audit_anchor IS NULL)
    OR (state = 'uncertain'
      AND claim_token_digest IS NULL
      AND claim_expires_at IS NULL
      AND uncertain_reason IN (
        'signer_failure', 'stale_lifecycle', 'signer_output', 'commit_failure'
      )
      AND audit_anchor IS NULL)
    OR (state = 'committed'
      AND claim_token_digest IS NULL
      AND claim_expires_at IS NULL
      AND uncertain_reason IS NULL
      AND audit_anchor IS NOT NULL)
  ),
  -- The service's canonical request is the sorted-key JSON object below.
  -- The explicit preimage avoids depending on jsonb's display ordering.
  CHECK (request_digest = sha256(convert_to(concat(
    '{"chain":', to_json(chain)::text,
    ',"environment":', to_json(environment)::text,
    ',"export_id":', to_json(export_id::text)::text,
    ',"idempotency_key":', to_json(idempotency_key)::text,
    ',"organization_id":', to_json(organization_id::text)::text,
    ',"payload_digest":', to_json(encode(payload_digest, 'hex'))::text,
    ',"range":{"from_audit_position":', from_audit_position::text,
    ',"previous_root_digest":', to_json(encode(previous_root_digest, 'hex'))::text,
    ',"record_count":', record_count::text,
    ',"root_digest":', to_json(encode(root_digest, 'hex'))::text,
    ',"to_audit_position":', to_audit_position::text,
    '},"version":1}'
  ), 'UTF8'))),
  -- JSONB is structurally canonicalized, while this check closes the public
  -- envelope to exactly the audited protocol fields and public signature data.
  CHECK (
    state <> 'committed'
    OR (
      jsonb_typeof(audit_anchor) = 'object'
      AND agentpass_jsonb_object_key_count(audit_anchor) = 7
      AND audit_anchor ?& ARRAY[
        'version', 'type', 'statement', 'statement_hash',
        'signature_algorithm', 'signer_key_fingerprint', 'signature'
      ]
      AND audit_anchor->>'version' = '1'
      AND audit_anchor->>'type' = 'agentpass.audit-anchor'
      AND audit_anchor->>'statement_hash' ~ '^[0-9a-f]{64}$'
      AND audit_anchor->>'signature_algorithm' = 'ed25519'
      AND audit_anchor->>'signer_key_fingerprint' ~ '^SHA256:[A-Za-z0-9_-]{43}$'
      AND audit_anchor->>'signature' ~ '^[A-Za-z0-9_-]{86}$'
      AND jsonb_typeof(audit_anchor->'statement') = 'object'
      AND agentpass_jsonb_object_key_count(audit_anchor->'statement') = 20
      AND audit_anchor->'statement' ?& ARRAY[
        'version', 'type', 'organization_id', 'environment', 'chain',
        'export_id', 'audit_position', 'previous_audit_position',
        'root_digest', 'previous_root_digest', 'export_digest',
        'record_count', 'purpose', 'protocol_version', 'signing_version',
        'lifecycle_version', 'key_id', 'key_version', 'issued_at', 'expires_at'
      ]
      AND audit_anchor->'statement'->>'version' = '1'
      AND audit_anchor->'statement'->>'type' = 'agentpass.audit-anchor'
      AND audit_anchor->'statement'->>'organization_id' = organization_id::text
      AND audit_anchor->'statement'->>'environment' = environment
      AND audit_anchor->'statement'->>'chain' = chain
      AND audit_anchor->'statement'->>'export_id' = export_id::text
      AND audit_anchor->'statement'->>'audit_position' = to_audit_position::text
      AND audit_anchor->'statement'->>'previous_audit_position' = (from_audit_position - 1)::text
      AND audit_anchor->'statement'->>'root_digest' = encode(root_digest, 'hex')
      AND audit_anchor->'statement'->>'previous_root_digest' = encode(previous_root_digest, 'hex')
      AND audit_anchor->'statement'->>'export_digest' = encode(payload_digest, 'hex')
      AND audit_anchor->'statement'->>'record_count' = record_count::text
      AND audit_anchor->'statement'->>'purpose' = 'agentpass.audit-anchor'
      AND audit_anchor->'statement'->>'protocol_version' = '1'
      AND audit_anchor->'statement'->>'signing_version' = '1'
      AND audit_anchor->'statement'->>'lifecycle_version' = lifecycle_version::text
      AND audit_anchor->'statement'->>'key_id' = key_id
      AND audit_anchor->'statement'->>'key_version' = key_version::text
      AND audit_anchor->'statement'->>'issued_at' = to_char(issued_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')
      AND audit_anchor->'statement'->>'expires_at' = to_char(expires_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')
      AND audit_anchor::text !~* '(private[[:space:]_-]*key|provider[[:space:]_-]*(diagnostic|response|credential)|raw[[:space:]_-]*signing|clear[[:space:]_-]*claim|claim[[:space:]_-]*token)'
    )
  ),
  CHECK (audit_anchor IS NULL OR state = 'committed')
);

-- Only one unresolved authoritative reservation may exist for a lane.  This
-- serializes range selection while retaining a durable uncertain row.
CREATE UNIQUE INDEX audit_export_issuances_one_open_export
  ON audit_export_issuances (organization_id, environment, chain)
  WHERE state IN ('reserved', 'uncertain');

CREATE INDEX audit_export_issuances_lease
  ON audit_export_issuances (
    claim_expires_at, organization_id, environment, chain, export_id, idempotency_key
  )
  WHERE state = 'reserved';

CREATE INDEX audit_export_issuances_uncertain_reconciliation
  ON audit_export_issuances (
    organization_id, environment, chain, updated_at, export_id, idempotency_key
  )
  WHERE state = 'uncertain';

CREATE INDEX audit_export_issuances_retention
  ON audit_export_issuances (
    expires_at, organization_id, environment, chain, export_id, idempotency_key
  )
  WHERE state = 'committed';

CREATE FUNCTION agentpass_guard_audit_export_issuance()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION USING
      ERRCODE = 'check_violation',
      CONSTRAINT = 'audit_export_issuances_append_only',
      MESSAGE = 'audit export issuances are append-only';
  END IF;

  IF TG_OP = 'INSERT' THEN
    -- Serialize the complete lane even for callers that bypass the repository,
    -- then reject any inclusive range overlap without requiring btree_gist or
    -- extension-creation authority in the production migrator role.
    PERFORM pg_advisory_xact_lock(hashtextextended(
      'agentpass:audit-export:' || NEW.organization_id::text || ':' ||
      NEW.environment || ':' || NEW.chain,
      0
    ));
    IF EXISTS (
      SELECT 1 FROM public.audit_export_issuances existing
      WHERE existing.organization_id=NEW.organization_id
        AND existing.environment=NEW.environment
        AND existing.chain=NEW.chain
        AND existing.from_audit_position <= NEW.to_audit_position
        AND existing.to_audit_position >= NEW.from_audit_position
    ) THEN
      RAISE EXCEPTION USING
        ERRCODE = 'exclusion_violation',
        CONSTRAINT = 'audit_export_issuances_non_overlapping_ranges',
        MESSAGE = 'audit export issuance range overlaps committed authority';
    END IF;
    IF NEW.state = 'reserved' AND NEW.claim_expires_at <= clock_timestamp() THEN
      RAISE EXCEPTION USING
        ERRCODE = 'check_violation',
        CONSTRAINT = 'audit_export_issuances_claim_lease',
        MESSAGE = 'audit export reservation lease must be in the future on the database clock';
    END IF;
    RETURN NEW;
  END IF;

  IF NEW.organization_id IS DISTINCT FROM OLD.organization_id
     OR NEW.export_id IS DISTINCT FROM OLD.export_id
     OR NEW.environment IS DISTINCT FROM OLD.environment
     OR NEW.chain IS DISTINCT FROM OLD.chain
     OR NEW.idempotency_key IS DISTINCT FROM OLD.idempotency_key
     OR NEW.from_audit_position IS DISTINCT FROM OLD.from_audit_position
     OR NEW.to_audit_position IS DISTINCT FROM OLD.to_audit_position
     OR NEW.previous_root_digest IS DISTINCT FROM OLD.previous_root_digest
     OR NEW.root_digest IS DISTINCT FROM OLD.root_digest
     OR NEW.record_count IS DISTINCT FROM OLD.record_count
     OR NEW.payload_digest IS DISTINCT FROM OLD.payload_digest
     OR NEW.request_digest IS DISTINCT FROM OLD.request_digest
     OR NEW.issued_at IS DISTINCT FROM OLD.issued_at
     OR NEW.expires_at IS DISTINCT FROM OLD.expires_at
     OR NEW.key_id IS DISTINCT FROM OLD.key_id
     OR NEW.key_version IS DISTINCT FROM OLD.key_version
     OR NEW.lifecycle_version IS DISTINCT FROM OLD.lifecycle_version
     OR NEW.created_at IS DISTINCT FROM OLD.created_at
  THEN
    RAISE EXCEPTION USING
      ERRCODE = 'check_violation',
      CONSTRAINT = 'audit_export_issuances_authority_immutable',
      MESSAGE = 'audit export issuance identity and authority snapshot are immutable';
  END IF;

  IF OLD.state = 'committed' THEN
    RAISE EXCEPTION USING
      ERRCODE = 'check_violation',
      CONSTRAINT = 'audit_export_issuances_committed_immutable',
      MESSAGE = 'committed audit export issuance is immutable';
  END IF;

  IF NOT (
    NEW.state = OLD.state
    OR (OLD.state = 'reserved' AND NEW.state IN ('uncertain', 'committed'))
    OR (OLD.state = 'uncertain' AND NEW.state = 'committed')
  ) THEN
    RAISE EXCEPTION USING
      ERRCODE = 'check_violation',
      CONSTRAINT = 'audit_export_issuances_transition',
      MESSAGE = 'audit export issuance transition is not permitted';
  END IF;

  IF NEW.state = OLD.state
     AND NEW.uncertain_reason IS DISTINCT FROM OLD.uncertain_reason
  THEN
    RAISE EXCEPTION USING
      ERRCODE = 'check_violation',
      CONSTRAINT = 'audit_export_issuances_uncertain_reason_immutable',
      MESSAGE = 'audit export uncertainty reason is immutable within a state';
  END IF;

  IF NEW.state = 'reserved' AND NEW.claim_expires_at <= clock_timestamp() THEN
    RAISE EXCEPTION USING
      ERRCODE = 'check_violation',
      CONSTRAINT = 'audit_export_issuances_claim_lease',
      MESSAGE = 'audit export reservation lease must be in the future on the database clock';
  END IF;

  NEW.updated_at := clock_timestamp();
  RETURN NEW;
END;
$$;

CREATE TRIGGER audit_export_issuances_guard
  BEFORE INSERT OR UPDATE OR DELETE ON audit_export_issuances
  FOR EACH ROW
  EXECUTE FUNCTION agentpass_guard_audit_export_issuance();

ALTER TABLE audit_export_issuances ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_export_issuances FORCE ROW LEVEL SECURITY;

CREATE POLICY audit_export_issuances_tenant_select
  ON audit_export_issuances FOR SELECT
  USING (organization_id = agentpass_current_organization_id());

CREATE POLICY audit_export_issuances_tenant_insert
  ON audit_export_issuances FOR INSERT
  WITH CHECK (organization_id = agentpass_current_organization_id());

CREATE POLICY audit_export_issuances_tenant_update
  ON audit_export_issuances FOR UPDATE
  USING (organization_id = agentpass_current_organization_id())
  WITH CHECK (organization_id = agentpass_current_organization_id());

-- The explicit tenant policy keeps the table's RLS contract complete.  The
-- append-only trigger is the authoritative application/database prohibition.
CREATE POLICY audit_export_issuances_tenant_delete
  ON audit_export_issuances FOR DELETE
  USING (organization_id = agentpass_current_organization_id());

COMMENT ON TABLE audit_export_issuances IS
  'Organization-scoped authoritative audit-export issuance ledger; clear claim tokens, private keys, provider diagnostics, and raw signing bytes are never stored.';
COMMENT ON COLUMN audit_export_issuances.claim_token_digest IS
  'SHA-256 digest of the opaque reservation claim; the public claim token is never persisted.';
COMMENT ON COLUMN audit_export_issuances.audit_anchor IS
  'Complete canonical public audit-anchor envelope; private/provider material is excluded by shape and content checks.';

COMMIT;
