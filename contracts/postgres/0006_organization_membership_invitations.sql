BEGIN;

CREATE TABLE organization_invitations (
  organization_id uuid NOT NULL REFERENCES organizations(id),
  id uuid NOT NULL,
  token_hash bytea NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
  role text NOT NULL CHECK (role IN ('admin', 'auditor', 'viewer')),
  created_by uuid NOT NULL REFERENCES members(id),
  expires_at timestamptz NOT NULL,
  consumed_by uuid REFERENCES members(id),
  consumed_at timestamptz,
  revoked_by uuid REFERENCES members(id),
  revoked_at timestamptz,
  revoke_reason text,
  version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (organization_id, id),
  FOREIGN KEY (organization_id, created_by) REFERENCES memberships(organization_id, member_id),
  FOREIGN KEY (organization_id, consumed_by) REFERENCES memberships(organization_id, member_id),
  FOREIGN KEY (organization_id, revoked_by) REFERENCES memberships(organization_id, member_id),
  CHECK (expires_at > created_at),
  CHECK (
    (consumed_by IS NULL AND consumed_at IS NULL)
    OR (consumed_by IS NOT NULL AND consumed_at IS NOT NULL)
  ),
  CHECK (
    (revoked_by IS NULL AND revoked_at IS NULL AND revoke_reason IS NULL)
    OR (revoked_by IS NOT NULL AND revoked_at IS NOT NULL AND revoke_reason IS NOT NULL)
  ),
  CHECK (NOT (consumed_at IS NOT NULL AND revoked_at IS NOT NULL)),
  CHECK (consumed_at IS NULL OR consumed_at >= created_at),
  CHECK (revoked_at IS NULL OR revoked_at >= created_at),
  CHECK (revoke_reason IS NULL OR (char_length(revoke_reason) BETWEEN 1 AND 256 AND revoke_reason !~ '[[:cntrl:]]'))
);

CREATE INDEX organization_invitations_active_lookup
  ON organization_invitations (organization_id, created_at DESC, id)
  WHERE consumed_at IS NULL AND revoked_at IS NULL;

CREATE INDEX organization_invitations_expiry_lookup
  ON organization_invitations (organization_id, expires_at, id)
  WHERE consumed_at IS NULL AND revoked_at IS NULL;

CREATE INDEX organization_invitations_created_by_lookup
  ON organization_invitations (organization_id, created_by, created_at DESC, id);

CREATE TABLE admin_audit_heads (
  organization_id uuid PRIMARY KEY REFERENCES organizations(id),
  sequence bigint NOT NULL DEFAULT 0 CHECK (sequence >= 0),
  event_hash text NOT NULL DEFAULT repeat('0', 64) CHECK (event_hash ~ '^[0-9a-f]{64}$'),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

-- New events persist the exact canonical hash preimage and sequence. Legacy
-- rows are assigned a deterministic order and an explicit legacy projection;
-- their existing event hash remains the chain boundary.
ALTER TABLE admin_audit_events
  ADD COLUMN sequence bigint,
  ADD COLUMN event_json jsonb;

WITH ranked AS (
  SELECT organization_id,id,
    row_number() OVER (PARTITION BY organization_id ORDER BY created_at,id) AS sequence
  FROM admin_audit_events
)
UPDATE admin_audit_events e
SET sequence=ranked.sequence,
    event_json=jsonb_build_object(
      'version',0,
      'legacy',true,
      'audit_event_id',e.id,
      'organization_id',e.organization_id,
      'actor_id',e.actor_id,
      'action',e.action,
      'target_type',e.target_type,
      'target_id',e.target_id,
      'previous_hash',e.previous_hash,
      'event_hash',e.event_hash,
      'created_at',e.created_at
    )
FROM ranked
WHERE e.organization_id=ranked.organization_id AND e.id=ranked.id;

ALTER TABLE admin_audit_events
  ALTER COLUMN sequence SET NOT NULL,
  ALTER COLUMN event_json SET NOT NULL,
  ADD CONSTRAINT admin_audit_events_sequence_valid CHECK (sequence > 0),
  ADD CONSTRAINT admin_audit_events_json_object CHECK (jsonb_typeof(event_json)='object'),
  ADD CONSTRAINT admin_audit_events_organization_sequence UNIQUE (organization_id,sequence);

INSERT INTO admin_audit_heads (organization_id,sequence,event_hash)
SELECT o.id,
  COALESCE(latest.sequence,0),
  COALESCE(latest.event_hash,repeat('0',64))
FROM organizations o
LEFT JOIN LATERAL (
  SELECT e.sequence,e.event_hash
  FROM admin_audit_events e
  WHERE e.organization_id=o.id
  ORDER BY e.sequence DESC
  LIMIT 1
) latest ON true;

CREATE TABLE outbox_events (
  organization_id uuid NOT NULL REFERENCES organizations(id),
  id uuid NOT NULL,
  aggregate text NOT NULL CHECK (char_length(aggregate) BETWEEN 1 AND 128),
  action text NOT NULL CHECK (char_length(action) BETWEEN 1 AND 128),
  payload jsonb NOT NULL CHECK (jsonb_typeof(payload) = 'object'),
  status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'published')),
  attempts integer NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 100),
  available_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  published_at timestamptz,
  version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (organization_id, id),
  CHECK (
    (status = 'pending' AND published_at IS NULL)
    OR (status = 'published' AND published_at IS NOT NULL)
  )
);

CREATE INDEX outbox_events_pending_delivery
  ON outbox_events (available_at, organization_id, created_at, id)
  WHERE status = 'pending';

CREATE INDEX outbox_events_organization_pending
  ON outbox_events (organization_id, available_at, created_at, id)
  WHERE status = 'pending';

CREATE FUNCTION agentpass_create_admin_audit_head()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  INSERT INTO admin_audit_heads (organization_id)
  VALUES (NEW.id);
  RETURN NEW;
END;
$$;

CREATE TRIGGER organizations_create_admin_audit_head
  AFTER INSERT ON organizations
  FOR EACH ROW
  EXECUTE FUNCTION agentpass_create_admin_audit_head();

-- Serialize owner removals by organization before checking the remaining
-- active owners.  This trigger deliberately does not scan existing rows while
-- migrating, so legacy organizations without a valid owner remain migratable.
CREATE FUNCTION agentpass_prevent_last_active_owner()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    IF OLD.role = 'owner' AND OLD.status = 'active' THEN
      PERFORM pg_advisory_xact_lock(
        hashtextextended('agentpass:memberships:owners:' || OLD.organization_id::text, 0)
      );

      IF NOT EXISTS (
        SELECT 1
        FROM memberships
        WHERE organization_id = OLD.organization_id
          AND role = 'owner'
          AND status = 'active'
          AND id <> OLD.id
      ) THEN
        RAISE EXCEPTION USING
          ERRCODE = 'check_violation',
          CONSTRAINT = 'memberships_last_active_owner',
          MESSAGE = 'cannot remove the last active organization owner';
      END IF;
    END IF;
    RETURN OLD;
  END IF;

  IF OLD.role = 'owner' AND OLD.status = 'active'
     AND NOT (
       NEW.organization_id = OLD.organization_id
       AND NEW.role = 'owner'
       AND NEW.status = 'active'
     ) THEN
    PERFORM pg_advisory_xact_lock(
      hashtextextended('agentpass:memberships:owners:' || OLD.organization_id::text, 0)
    );

    IF NOT EXISTS (
      SELECT 1
      FROM memberships
      WHERE organization_id = OLD.organization_id
        AND role = 'owner'
        AND status = 'active'
        AND id <> OLD.id
    ) THEN
      RAISE EXCEPTION USING
        ERRCODE = 'check_violation',
        CONSTRAINT = 'memberships_last_active_owner',
        MESSAGE = 'cannot remove the last active organization owner';
    END IF;
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER memberships_protect_last_active_owner
  BEFORE UPDATE OF organization_id, role, status OR DELETE ON memberships
  FOR EACH ROW
  EXECUTE FUNCTION agentpass_prevent_last_active_owner();

COMMIT;
