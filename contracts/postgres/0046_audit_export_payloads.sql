BEGIN;

-- The export payload is captured in the same reservation transaction as its
-- issuance.  It is public canonical evidence: claim material, private key
-- material, provider responses, and raw signing bytes are not persisted.
CREATE TABLE audit_export_payloads (
  organization_id uuid NOT NULL,
  export_id uuid NOT NULL,
  environment text NOT NULL CHECK (environment IN ('staging', 'production')),
  chain text NOT NULL CHECK (chain IN ('admin', 'device', 'cloud_agent')),
  idempotency_key text NOT NULL CHECK (
    char_length(idempotency_key) BETWEEN 8 AND 255
    AND idempotency_key ~ '^[A-Za-z0-9][A-Za-z0-9._~:-]{7,254}$'
  ),

  payload_bytes bytea NOT NULL
    CHECK (octet_length(payload_bytes) BETWEEN 1 AND 262144),
  payload_json jsonb NOT NULL
    CHECK (jsonb_typeof(payload_json) = 'object'),
  payload_digest bytea NOT NULL
    CHECK (octet_length(payload_digest) = 32
      AND payload_digest <> decode(repeat('00', 32), 'hex')),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),

  PRIMARY KEY (organization_id, export_id, environment, chain, idempotency_key),
  FOREIGN KEY (organization_id, export_id, environment, chain, idempotency_key)
    REFERENCES audit_export_issuances
      (organization_id, export_id, environment, chain, idempotency_key),
  -- PostgreSQL validates JSON structurally; the repository additionally
  -- verifies that payload_bytes are the exact protocol canonical encoding.
  CHECK (convert_from(payload_bytes, 'UTF8')::jsonb = payload_json),
  CHECK (payload_digest = sha256(payload_bytes)),
  -- Match field names, not arbitrary public event text: actions such as
  -- "credential.deleted" are legitimate audit data. Explicit private-key
  -- PEM values are independently rejected below.
  CHECK (NOT jsonb_path_exists(
    payload_json,
    '$.** ? (@.type() == "object").keyvalue() ? (@.key like_regex "(private[ _-]*(key|material)|clear[ _-]*claim|claim[ _-]*token|raw[ _-]*(signing|signature)|provider[ _-]*(response|credential|diagnostic)|password|secret|authorization|bearer|cookie)" flag "i")'
  )),
  CHECK (payload_json::text !~* '-----BEGIN [^-]*PRIVATE KEY-----')
);

CREATE FUNCTION agentpass_bind_audit_export_payload()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
DECLARE
  issuance_state text;
  issuance_digest bytea;
BEGIN
  IF TG_OP = 'INSERT' THEN
    SELECT state, payload_digest
      INTO issuance_state, issuance_digest
    FROM public.audit_export_issuances
    WHERE organization_id = NEW.organization_id
      AND export_id = NEW.export_id
      AND environment = NEW.environment
      AND chain = NEW.chain
      AND idempotency_key = NEW.idempotency_key;

    IF issuance_state IS DISTINCT FROM 'reserved'
       OR issuance_digest IS DISTINCT FROM NEW.payload_digest
    THEN
      RAISE EXCEPTION USING
        ERRCODE = 'check_violation',
        CONSTRAINT = 'audit_export_payloads_reservation_binding',
        MESSAGE = 'audit export payload must bind to its reserved issuance digest';
    END IF;
    RETURN NEW;
  END IF;

  RAISE EXCEPTION USING
    ERRCODE = 'check_violation',
    CONSTRAINT = 'audit_export_payloads_immutable',
    MESSAGE = 'audit export payloads are immutable after reservation insert';
END;
$$;

CREATE TRIGGER audit_export_payloads_immutable
  BEFORE INSERT OR UPDATE OR DELETE ON audit_export_payloads
  FOR EACH ROW
  EXECUTE FUNCTION agentpass_bind_audit_export_payload();

-- A reservation without its payload is not a valid durable reservation.  The
-- deferred check permits the application to insert the issuance and payload
-- within one reservation transaction, while rejecting an issuance that
-- would otherwise survive a crash/restart without replayable bytes.
CREATE FUNCTION agentpass_require_audit_export_payload()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM public.audit_export_payloads payload
    WHERE payload.organization_id = NEW.organization_id
      AND payload.export_id = NEW.export_id
      AND payload.environment = NEW.environment
      AND payload.chain = NEW.chain
      AND payload.idempotency_key = NEW.idempotency_key
      AND payload.payload_digest = NEW.payload_digest
  ) THEN
    RAISE EXCEPTION USING
      ERRCODE = 'check_violation',
      CONSTRAINT = 'audit_export_issuances_payload_required',
      MESSAGE = 'reserved audit export issuance requires an immutable payload';
  END IF;
  RETURN NEW;
END;
$$;

CREATE CONSTRAINT TRIGGER audit_export_issuances_payload_required
  AFTER INSERT ON audit_export_issuances
  DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW
  EXECUTE FUNCTION agentpass_require_audit_export_payload();

-- The primary key serves exact-identity lookup; this covering index keeps the
-- committed read model cheap without duplicating mutable issuance state.
CREATE INDEX audit_export_payloads_retrieval
  ON audit_export_payloads
    (organization_id, export_id, environment, chain, idempotency_key);

-- Retrieval is deliberately limited to committed issuance authority.  The
-- security-invoker view preserves both base-table tenant policies and FORCE
-- RLS for callers using the normal organization context.
CREATE VIEW audit_export_committed_payloads
WITH (security_invoker = true)
AS
SELECT
  payload.organization_id,
  payload.export_id,
  payload.environment,
  payload.chain,
  payload.idempotency_key,
  payload.payload_bytes,
  payload.payload_json,
  payload.payload_digest,
  payload.created_at
FROM public.audit_export_payloads payload
JOIN public.audit_export_issuances issuance
  ON issuance.organization_id = payload.organization_id
 AND issuance.export_id = payload.export_id
 AND issuance.environment = payload.environment
 AND issuance.chain = payload.chain
 AND issuance.idempotency_key = payload.idempotency_key
 AND issuance.payload_digest = payload.payload_digest
WHERE issuance.state = 'committed';

ALTER TABLE audit_export_payloads ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_export_payloads FORCE ROW LEVEL SECURITY;

CREATE POLICY audit_export_payloads_tenant_select
  ON audit_export_payloads FOR SELECT
  USING (organization_id = agentpass_current_organization_id());

CREATE POLICY audit_export_payloads_tenant_insert
  ON audit_export_payloads FOR INSERT
  WITH CHECK (organization_id = agentpass_current_organization_id());

COMMENT ON TABLE audit_export_payloads IS
  'Immutable tenant-scoped canonical audit-export payload bytes captured during reservation; no clear claim, private, credential, provider, or raw signing material is stored.';
COMMENT ON COLUMN audit_export_payloads.payload_bytes IS
  'Protocol canonical UTF-8 JSON bytes; byte-for-byte canonicality is revalidated by the repository.';
COMMENT ON COLUMN audit_export_payloads.payload_json IS
  'Structural JSONB parse of payload_bytes used for bounded database retrieval and sensitive-material rejection.';
COMMENT ON COLUMN audit_export_payloads.payload_digest IS
  'SHA-256(payload_bytes), also bound to the exact audit_export_issuances identity and authority digest.';
COMMENT ON VIEW audit_export_committed_payloads IS
  'Tenant-scoped retrieval view exposing payload evidence only after its exact issuance reaches committed state.';

COMMIT;
