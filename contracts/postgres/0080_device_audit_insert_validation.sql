BEGIN;

-- The existing PostgreSQL repository intentionally uses a direct INSERT for
-- audit ingestion.  Keep that interface, but make the INSERT itself a
-- validated boundary: the head trigger must never see an event whose stored
-- identity, content hash, or agent/device binding is fabricated.
CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public;

-- jsonb::text is not the protocol canonical JSON encoding (it inserts spaces
-- and has implementation-specific presentation details). Keep the database
-- verifier byte-compatible with the Native/Cloud canonical encoder for the
-- closed audit value types: objects are key-sorted, arrays preserve order,
-- and scalar JSON encodings are delegated to PostgreSQL's JSON encoder.
CREATE OR REPLACE FUNCTION public.agentpass_canonical_audit_json(value jsonb)
RETURNS text
LANGUAGE plpgsql
IMMUTABLE
STRICT
PARALLEL SAFE
AS $$
DECLARE
  result text;
BEGIN
  CASE jsonb_typeof(value)
    WHEN 'object' THEN
      SELECT '{' || COALESCE(string_agg(to_jsonb(entry.key)::text || ':' || public.agentpass_canonical_audit_json(entry.value), ',' ORDER BY entry.key), '') || '}'
        INTO result
        FROM jsonb_each(value) AS entry;
    WHEN 'array' THEN
      SELECT '[' || COALESCE(string_agg(public.agentpass_canonical_audit_json(entry), ',' ORDER BY entry.ordinality), '') || ']'
        INTO result
        FROM jsonb_array_elements(value) WITH ORDINALITY AS entry(value, ordinality);
    ELSE
      result := value::text;
  END CASE;
  RETURN result;
END;
$$;

CREATE OR REPLACE FUNCTION public.agentpass_validate_device_audit_event()
RETURNS trigger
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  bound_device_id uuid;
BEGIN
  IF NEW.redacted_json->>'event_id' IS DISTINCT FROM NEW.event_id::text
     OR NEW.redacted_json->>'previous_hash' IS DISTINCT FROM NEW.previous_hash
     OR NEW.redacted_json->>'event_hash' IS DISTINCT FROM NEW.event_hash THEN
    RAISE EXCEPTION 'device audit identity does not match redacted evidence'
      USING ERRCODE = '23514';
  END IF;

  IF encode(digest(convert_to(public.agentpass_canonical_audit_json(NEW.redacted_json - 'event_hash'), 'UTF8'), 'sha256'), 'hex') IS DISTINCT FROM NEW.event_hash THEN
    RAISE EXCEPTION 'device audit event_hash does not match redacted evidence'
      USING ERRCODE = '23514';
  END IF;

  SELECT a.device_id
    INTO bound_device_id
    FROM public.agents AS a
   WHERE a.organization_id = NEW.organization_id
     AND a.id = (NEW.redacted_json->>'agent_id')::uuid;
  IF NOT FOUND OR bound_device_id IS DISTINCT FROM NEW.device_id THEN
    RAISE EXCEPTION 'device audit agent is not bound to the device'
      USING ERRCODE = '23514';
  END IF;

  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS device_audit_events_validate_insert ON public.device_audit_events;
CREATE TRIGGER device_audit_events_validate_insert
  BEFORE INSERT ON public.device_audit_events
  FOR EACH ROW
  EXECUTE FUNCTION public.agentpass_validate_device_audit_event();

REVOKE ALL PRIVILEGES ON FUNCTION public.agentpass_validate_device_audit_event() FROM PUBLIC, agentpass_app, agentpass_signer, agentpass_backup;
REVOKE ALL PRIVILEGES ON FUNCTION public.agentpass_canonical_audit_json(jsonb) FROM PUBLIC, agentpass_app, agentpass_signer, agentpass_backup;

COMMENT ON FUNCTION public.agentpass_validate_device_audit_event() IS
  'Rejects device audit inserts whose redacted identity, SHA-256 event hash, or tenant agent/device binding is invalid before head advancement.';

COMMIT;
