BEGIN;

-- Device audit events are hash-chained per device. Audit exports, however,
-- are organization scoped, so a stable organization-wide position must be
-- assigned at commit time. This additive index never rewrites device evidence
-- and carries no request credential, secret, or unredacted payload.
CREATE TABLE device_audit_export_heads (
  organization_id uuid PRIMARY KEY REFERENCES organizations(id),
  sequence bigint NOT NULL DEFAULT 0 CHECK (sequence >= 0),
  last_device_id uuid,
  last_event_id uuid,
  last_event_hash text NOT NULL DEFAULT repeat('0', 64)
    CHECK (last_event_hash ~ '^[0-9a-f]{64}$'),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CHECK (
    (sequence = 0 AND last_device_id IS NULL AND last_event_id IS NULL
      AND last_event_hash = repeat('0', 64))
    OR (sequence > 0 AND last_device_id IS NOT NULL AND last_event_id IS NOT NULL
      AND last_event_hash <> repeat('0', 64))
  )
);

CREATE UNIQUE INDEX device_audit_events_export_identity
  ON device_audit_events (organization_id,device_id,event_id,event_hash);

CREATE TABLE device_audit_export_entries (
  organization_id uuid NOT NULL REFERENCES organizations(id),
  sequence bigint NOT NULL CHECK (sequence > 0),
  device_id uuid NOT NULL,
  event_id uuid NOT NULL,
  event_hash text NOT NULL CHECK (
    event_hash ~ '^[0-9a-f]{64}$' AND event_hash <> repeat('0', 64)
  ),
  indexed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (organization_id, sequence),
  UNIQUE (organization_id, device_id, event_id),
  FOREIGN KEY (organization_id, device_id, event_id, event_hash)
    REFERENCES device_audit_events(organization_id, device_id, event_id, event_hash)
);

-- Existing rows receive one deterministic migration-time order. New rows are
-- serialized by the trigger below and therefore never depend on wall-clock
-- monotonicity or a caller-supplied device timestamp.
WITH ordered AS (
  SELECT organization_id,device_id,event_id,event_hash,
    row_number() OVER (
      PARTITION BY organization_id
      ORDER BY received_at,device_id,event_id
    ) AS export_sequence
  FROM device_audit_events
)
INSERT INTO device_audit_export_entries
  (organization_id,sequence,device_id,event_id,event_hash)
SELECT organization_id,export_sequence,device_id,event_id,event_hash
FROM ordered
ORDER BY organization_id,export_sequence;

INSERT INTO device_audit_export_heads
  (organization_id,sequence,last_device_id,last_event_id,last_event_hash)
SELECT organization.id,
  COALESCE(latest.sequence,0),
  latest.device_id,
  latest.event_id,
  COALESCE(latest.event_hash,repeat('0',64))
FROM organizations organization
LEFT JOIN LATERAL (
  SELECT entry.sequence,entry.device_id,entry.event_id,entry.event_hash
  FROM device_audit_export_entries entry
  WHERE entry.organization_id=organization.id
  ORDER BY entry.sequence DESC
  LIMIT 1
) latest ON true;

CREATE FUNCTION agentpass_record_device_audit_export_entry()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
DECLARE
  current_sequence bigint;
BEGIN
  INSERT INTO public.device_audit_export_heads (organization_id)
  VALUES (NEW.organization_id)
  ON CONFLICT (organization_id) DO NOTHING;

  SELECT sequence INTO current_sequence
  FROM public.device_audit_export_heads
  WHERE organization_id=NEW.organization_id
  FOR UPDATE;

  INSERT INTO public.device_audit_export_entries
    (organization_id,sequence,device_id,event_id,event_hash)
  VALUES
    (NEW.organization_id,current_sequence+1,NEW.device_id,NEW.event_id,NEW.event_hash);

  UPDATE public.device_audit_export_heads
  SET sequence=current_sequence+1,
      last_device_id=NEW.device_id,
      last_event_id=NEW.event_id,
      last_event_hash=NEW.event_hash,
      updated_at=clock_timestamp()
  WHERE organization_id=NEW.organization_id AND sequence=current_sequence;

  IF NOT FOUND THEN
    RAISE EXCEPTION USING
      ERRCODE = 'serialization_failure',
      CONSTRAINT = 'device_audit_export_head_advance',
      MESSAGE = 'device audit export head did not advance';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER device_audit_events_record_export_entry
  AFTER INSERT ON device_audit_events
  FOR EACH ROW EXECUTE FUNCTION agentpass_record_device_audit_export_entry();

CREATE FUNCTION agentpass_guard_device_audit_export_entry()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
  IF TG_OP = 'INSERT' AND pg_trigger_depth() = 2 THEN
    RETURN NEW;
  END IF;
  RAISE EXCEPTION USING
    ERRCODE = 'check_violation',
    CONSTRAINT = 'device_audit_export_entries_append_only',
    MESSAGE = 'device audit export entries are append-only and source-trigger managed';
END;
$$;

CREATE TRIGGER device_audit_export_entries_append_only
  BEFORE INSERT OR UPDATE OR DELETE ON device_audit_export_entries
  FOR EACH ROW EXECUTE FUNCTION agentpass_guard_device_audit_export_entry();

CREATE FUNCTION agentpass_guard_device_audit_export_head()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    IF NEW.sequence <> 0
       OR NEW.last_device_id IS NOT NULL
       OR NEW.last_event_id IS NOT NULL
       OR NEW.last_event_hash <> repeat('0',64)
    THEN
      RAISE EXCEPTION USING
        ERRCODE = 'check_violation',
        CONSTRAINT = 'device_audit_export_heads_initial_state',
        MESSAGE = 'device audit export heads begin at the zero boundary';
    END IF;
    NEW.updated_at := clock_timestamp();
    RETURN NEW;
  END IF;

  IF TG_OP = 'DELETE'
     OR NEW.organization_id IS DISTINCT FROM OLD.organization_id
     OR NEW.sequence <> OLD.sequence + 1
     OR NOT EXISTS (
       SELECT 1 FROM public.device_audit_export_entries entry
       WHERE entry.organization_id=NEW.organization_id
         AND entry.sequence=NEW.sequence
         AND entry.device_id=NEW.last_device_id
         AND entry.event_id=NEW.last_event_id
         AND entry.event_hash=NEW.last_event_hash
     )
  THEN
    RAISE EXCEPTION USING
      ERRCODE = 'check_violation',
      CONSTRAINT = 'device_audit_export_heads_forward_only',
      MESSAGE = 'device audit export heads advance only through an indexed event';
  END IF;
  NEW.updated_at := clock_timestamp();
  RETURN NEW;
END;
$$;

CREATE TRIGGER device_audit_export_heads_forward_only
  BEFORE INSERT OR UPDATE OR DELETE ON device_audit_export_heads
  FOR EACH ROW EXECUTE FUNCTION agentpass_guard_device_audit_export_head();

CREATE INDEX device_audit_export_entries_source_lookup
  ON device_audit_export_entries (organization_id,device_id,event_id,sequence);

ALTER TABLE device_audit_export_entries ENABLE ROW LEVEL SECURITY;
ALTER TABLE device_audit_export_entries FORCE ROW LEVEL SECURITY;
CREATE POLICY device_audit_export_entries_tenant_select
  ON device_audit_export_entries FOR SELECT
  USING (organization_id=agentpass_current_organization_id());
CREATE POLICY device_audit_export_entries_tenant_insert
  ON device_audit_export_entries FOR INSERT
  WITH CHECK (organization_id=agentpass_current_organization_id());

ALTER TABLE device_audit_export_heads ENABLE ROW LEVEL SECURITY;
ALTER TABLE device_audit_export_heads FORCE ROW LEVEL SECURITY;
CREATE POLICY device_audit_export_heads_tenant_select
  ON device_audit_export_heads FOR SELECT
  USING (organization_id=agentpass_current_organization_id());
CREATE POLICY device_audit_export_heads_tenant_insert
  ON device_audit_export_heads FOR INSERT
  WITH CHECK (organization_id=agentpass_current_organization_id());
CREATE POLICY device_audit_export_heads_tenant_update
  ON device_audit_export_heads FOR UPDATE
  USING (organization_id=agentpass_current_organization_id())
  WITH CHECK (organization_id=agentpass_current_organization_id());

COMMENT ON TABLE device_audit_export_entries IS
  'Append-only organization-wide position index over redacted per-device audit evidence.';
COMMENT ON COLUMN device_audit_export_entries.event_hash IS
  'Public source-event boundary digest; export payloads are independently canonicalized and hashed by the authoritative producer.';

COMMIT;
