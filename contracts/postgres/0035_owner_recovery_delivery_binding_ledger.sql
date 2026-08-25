BEGIN;

-- Delivery idempotency is meaningful only inside one provider namespace.
-- Existing rows cannot be bound safely from database state, so they remain
-- explicitly legacy-unbound.  New pending rows are required to carry an
-- immutable, secret-free binding tuple.
ALTER TABLE owner_recovery_outbox
  DROP CONSTRAINT owner_recovery_outbox_uncertain_reason_check,
  ADD COLUMN provider_binding_state text NOT NULL DEFAULT 'legacy_unbound',
  ADD COLUMN provider_binding_id text,
  ADD COLUMN provider_key_version integer,
  ADD COLUMN provider_binding_digest bytea,
  ADD CONSTRAINT owner_recovery_outbox_uncertain_reason_check CHECK (
    uncertain_reason IS NULL OR (
      char_length(uncertain_reason) BETWEEN 1 AND 64
      AND uncertain_reason IN (
        'provider_timeout',
        'provider_transport_error',
        'provider_response_invalid',
        'terminal_commit_unknown',
        'process_interrupted',
        'delivery_unknown',
        'provider_unconfigured',
        'legacy_unbound'
      )
    )
  ),
  ADD CONSTRAINT owner_recovery_outbox_provider_binding_check CHECK (
    (provider_binding_state = 'legacy_unbound'
      AND provider_binding_id IS NULL
      AND provider_key_version IS NULL
      AND provider_binding_digest IS NULL)
    OR
    (provider_binding_state = 'bound'
      AND provider_binding_id IS NOT NULL
      AND char_length(provider_binding_id) BETWEEN 1 AND 128
      AND provider_binding_id ~ '^[a-z0-9][a-z0-9._:-]*$'
      AND provider_key_version BETWEEN 1 AND 2147483647
      AND octet_length(provider_binding_digest) = 32)
  );

UPDATE owner_recovery_outbox
SET status = 'uncertain',
    uncertain_at = clock_timestamp(),
    uncertain_reason = 'legacy_unbound',
    last_error_code = 'delivery_uncertain',
    claim_token_digest = NULL,
    claim_expires_at = NULL,
    updated_at = clock_timestamp()
WHERE status = 'pending'
  AND provider_binding_state = 'legacy_unbound';

ALTER TABLE owner_recovery_outbox
  ADD CONSTRAINT owner_recovery_outbox_pending_provider_binding_check CHECK (
    status <> 'pending' OR provider_binding_state = 'bound'
  );

CREATE OR REPLACE FUNCTION agentpass_guard_owner_recovery_outbox_identity()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
  IF NEW.organization_id IS DISTINCT FROM OLD.organization_id
     OR NEW.event_id IS DISTINCT FROM OLD.event_id
     OR NEW.request_id IS DISTINCT FROM OLD.request_id
     OR NEW.subject_member_id IS DISTINCT FROM OLD.subject_member_id
     OR NEW.event_type IS DISTINCT FROM OLD.event_type
     OR NEW.created_at IS DISTINCT FROM OLD.created_at
     OR NEW.provider_binding_state IS DISTINCT FROM OLD.provider_binding_state
     OR NEW.provider_binding_id IS DISTINCT FROM OLD.provider_binding_id
     OR NEW.provider_key_version IS DISTINCT FROM OLD.provider_key_version
     OR NEW.provider_binding_digest IS DISTINCT FROM OLD.provider_binding_digest
  THEN
    RAISE EXCEPTION USING ERRCODE = 'check_violation',
      CONSTRAINT = 'owner_recovery_outbox_identity_immutable',
      MESSAGE = 'owner recovery outbox identity and provider binding are immutable';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TABLE owner_recovery_outbox_transition_heads (
  organization_id uuid NOT NULL,
  event_id uuid NOT NULL,
  sequence integer NOT NULL DEFAULT 0 CHECK (sequence >= 0),
  event_hash text NOT NULL DEFAULT repeat('0', 64)
    CHECK (event_hash ~ '^[0-9a-f]{64}$'),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (organization_id, event_id),
  FOREIGN KEY (organization_id) REFERENCES organizations(id)
);

CREATE TABLE owner_recovery_outbox_transition_ledger (
  organization_id uuid NOT NULL,
  event_id uuid NOT NULL,
  transition_sequence integer NOT NULL CHECK (transition_sequence >= 1),
  from_status text,
  to_status text NOT NULL CHECK (
    to_status IN ('pending', 'published', 'uncertain', 'dead_letter', 'suppressed')
  ),
  reason text NOT NULL CHECK (reason IN (
    'migration_baseline', 'event_created', 'delivery_claimed',
    'provider_acknowledged', 'provider_rejected', 'delivery_unknown',
    'process_interrupted', 'legacy_unbound', 'operator_retry',
    'operator_suppressed', 'state_updated'
  )),
  attempt integer NOT NULL CHECK (attempt BETWEEN 0 AND 100),
  total_attempts integer NOT NULL CHECK (total_attempts >= attempt),
  management_version integer NOT NULL CHECK (management_version >= 1),
  provider_binding_state text NOT NULL CHECK (
    provider_binding_state IN ('bound', 'legacy_unbound')
  ),
  provider_binding_id text,
  provider_key_version integer,
  provider_binding_digest bytea,
  actor_type text NOT NULL CHECK (actor_type IN ('migration', 'system', 'worker', 'operator')),
  actor_member_id uuid,
  occurred_at timestamptz NOT NULL,
  previous_hash text NOT NULL CHECK (previous_hash ~ '^[0-9a-f]{64}$'),
  event_hash text NOT NULL CHECK (event_hash ~ '^[0-9a-f]{64}$'),
  PRIMARY KEY (organization_id, event_id, transition_sequence),
  UNIQUE (organization_id, event_id, event_hash),
  FOREIGN KEY (organization_id) REFERENCES organizations(id),
  CHECK (from_status IS NULL OR from_status IN ('pending', 'published', 'uncertain', 'dead_letter', 'suppressed')),
  CHECK ((actor_type = 'operator') = (actor_member_id IS NOT NULL)),
  CHECK (
    (provider_binding_state = 'legacy_unbound'
      AND provider_binding_id IS NULL
      AND provider_key_version IS NULL
      AND provider_binding_digest IS NULL)
    OR
    (provider_binding_state = 'bound'
      AND provider_binding_id IS NOT NULL
      AND provider_key_version BETWEEN 1 AND 2147483647
      AND octet_length(provider_binding_digest) = 32)
  )
);

CREATE INDEX owner_recovery_outbox_transition_ledger_time
  ON owner_recovery_outbox_transition_ledger
    (organization_id, occurred_at, event_id, transition_sequence);

CREATE FUNCTION agentpass_guard_owner_recovery_outbox_transition_ledger()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
  RAISE EXCEPTION USING ERRCODE = 'check_violation',
    CONSTRAINT = 'owner_recovery_outbox_transition_ledger_immutable',
    MESSAGE = 'owner recovery outbox transition ledger is immutable';
END;
$$;

CREATE TRIGGER owner_recovery_outbox_transition_ledger_guard
  BEFORE UPDATE OR DELETE ON owner_recovery_outbox_transition_ledger
  FOR EACH ROW EXECUTE FUNCTION agentpass_guard_owner_recovery_outbox_transition_ledger();

-- Record one baseline transition for every row that predates this ledger.
WITH baseline AS MATERIALIZED (
  SELECT outbox.*,clock_timestamp() AS transition_time
  FROM owner_recovery_outbox AS outbox
)
INSERT INTO owner_recovery_outbox_transition_ledger (
  organization_id,event_id,transition_sequence,from_status,to_status,reason,
  attempt,total_attempts,management_version,provider_binding_state,
  provider_binding_id,provider_key_version,provider_binding_digest,
  actor_type,actor_member_id,occurred_at,previous_hash,event_hash
)
SELECT organization_id,event_id,1,NULL,status,'migration_baseline',
  attempts,total_attempts,management_version,provider_binding_state,
  provider_binding_id,provider_key_version,provider_binding_digest,
  'migration',NULL,transition_time,repeat('0',64),
  encode(sha256(convert_to(concat_ws('|',
    organization_id::text,event_id::text,'1','',status,'migration_baseline',
    attempts::text,total_attempts::text,management_version::text,
    provider_binding_state,COALESCE(provider_binding_id,''),
    COALESCE(provider_key_version::text,''),COALESCE(encode(provider_binding_digest,'hex'),''),
    'migration','',
    floor(extract(epoch FROM transition_time)*1000000)::bigint::text,
    repeat('0',64)), 'UTF8')), 'hex')
FROM baseline;

INSERT INTO owner_recovery_outbox_transition_heads
  (organization_id,event_id,sequence,event_hash,updated_at)
SELECT organization_id,event_id,transition_sequence,event_hash,occurred_at
FROM owner_recovery_outbox_transition_ledger;

CREATE FUNCTION agentpass_append_owner_recovery_outbox_transition()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
DECLARE
  head owner_recovery_outbox_transition_heads%ROWTYPE;
  next_sequence integer;
  transition_reason text;
  transition_actor text;
  transition_actor_member uuid;
  transition_time timestamptz := clock_timestamp();
  next_hash text;
BEGIN
  IF TG_OP = 'UPDATE'
     AND NEW.status IS NOT DISTINCT FROM OLD.status
     AND NEW.attempts IS NOT DISTINCT FROM OLD.attempts
     AND NEW.total_attempts IS NOT DISTINCT FROM OLD.total_attempts
     AND NEW.management_version IS NOT DISTINCT FROM OLD.management_version
     AND NEW.last_error_code IS NOT DISTINCT FROM OLD.last_error_code
  THEN
    RETURN NEW;
  END IF;

  INSERT INTO owner_recovery_outbox_transition_heads (organization_id,event_id)
  VALUES (NEW.organization_id,NEW.event_id)
  ON CONFLICT (organization_id,event_id) DO NOTHING;

  SELECT * INTO STRICT head
  FROM owner_recovery_outbox_transition_heads
  WHERE organization_id=NEW.organization_id AND event_id=NEW.event_id
  FOR UPDATE;

  next_sequence := head.sequence + 1;
  transition_actor := NULLIF(current_setting('agentpass.owner_recovery_actor_type', true), '');
  IF transition_actor IS NULL THEN
    transition_actor := CASE
      WHEN TG_OP='INSERT' THEN 'system'
      WHEN NEW.management_version IS DISTINCT FROM OLD.management_version THEN 'operator'
      ELSE 'worker'
    END;
  END IF;
  IF transition_actor NOT IN ('system','worker','operator') THEN
    RAISE EXCEPTION USING ERRCODE='check_violation',
      CONSTRAINT='owner_recovery_outbox_transition_actor_valid',
      MESSAGE='owner recovery outbox transition actor is invalid';
  END IF;
  IF transition_actor='operator' THEN
    BEGIN
      transition_actor_member := NULLIF(current_setting('agentpass.owner_recovery_actor_member_id', true), '')::uuid;
    EXCEPTION WHEN OTHERS THEN
      RAISE EXCEPTION USING ERRCODE='check_violation',
        CONSTRAINT='owner_recovery_outbox_transition_operator_bound',
        MESSAGE='owner recovery outbox operator transition is not bound';
    END;
    IF transition_actor_member IS NULL THEN
      RAISE EXCEPTION USING ERRCODE='check_violation',
        CONSTRAINT='owner_recovery_outbox_transition_operator_bound',
        MESSAGE='owner recovery outbox operator transition is not bound';
    END IF;
  END IF;

  transition_reason := CASE
    WHEN TG_OP='INSERT' THEN 'event_created'
    WHEN NEW.status='published' THEN 'provider_acknowledged'
    WHEN NEW.status='uncertain' AND NEW.uncertain_reason='process_interrupted' THEN 'process_interrupted'
    WHEN NEW.status='uncertain' AND NEW.uncertain_reason='legacy_unbound' THEN 'legacy_unbound'
    WHEN NEW.status='uncertain' THEN 'delivery_unknown'
    WHEN NEW.status='suppressed' THEN 'operator_suppressed'
    WHEN OLD.status IN ('dead_letter','uncertain') AND NEW.status='pending' THEN 'operator_retry'
    WHEN NEW.status='dead_letter' OR NEW.last_error_code='publisher_rejected' THEN 'provider_rejected'
    WHEN NEW.attempts > OLD.attempts THEN 'delivery_claimed'
    ELSE 'state_updated'
  END;

  next_hash := encode(sha256(convert_to(concat_ws('|',
    NEW.organization_id::text,NEW.event_id::text,next_sequence::text,
    CASE WHEN TG_OP='INSERT' THEN '' ELSE OLD.status END,NEW.status,
    transition_reason,NEW.attempts::text,NEW.total_attempts::text,
    NEW.management_version::text,NEW.provider_binding_state,
    COALESCE(NEW.provider_binding_id,''),COALESCE(NEW.provider_key_version::text,''),
    COALESCE(encode(NEW.provider_binding_digest,'hex'),''),
    transition_actor,COALESCE(transition_actor_member::text,''),
    floor(extract(epoch FROM transition_time)*1000000)::bigint::text,
    head.event_hash),
    'UTF8')), 'hex');

  INSERT INTO owner_recovery_outbox_transition_ledger (
    organization_id,event_id,transition_sequence,from_status,to_status,reason,
    attempt,total_attempts,management_version,provider_binding_state,
    provider_binding_id,provider_key_version,provider_binding_digest,
    actor_type,actor_member_id,occurred_at,previous_hash,event_hash
  ) VALUES (
    NEW.organization_id,NEW.event_id,next_sequence,
    CASE WHEN TG_OP='INSERT' THEN NULL ELSE OLD.status END,NEW.status,
    transition_reason,NEW.attempts,NEW.total_attempts,NEW.management_version,
    NEW.provider_binding_state,NEW.provider_binding_id,NEW.provider_key_version,
    NEW.provider_binding_digest,transition_actor,transition_actor_member,
    transition_time,head.event_hash,next_hash
  );

  UPDATE owner_recovery_outbox_transition_heads
  SET sequence=next_sequence,event_hash=next_hash,updated_at=transition_time
  WHERE organization_id=NEW.organization_id AND event_id=NEW.event_id;
  RETURN NEW;
END;
$$;

CREATE TRIGGER owner_recovery_outbox_transition_appender
  AFTER INSERT OR UPDATE OF status,attempts,total_attempts,management_version,last_error_code
  ON owner_recovery_outbox
  FOR EACH ROW EXECUTE FUNCTION agentpass_append_owner_recovery_outbox_transition();

COMMENT ON COLUMN owner_recovery_outbox.provider_binding_digest IS
  'SHA-256 digest of the public provider namespace binding; never a credential or response digest.';
COMMENT ON TABLE owner_recovery_outbox_transition_ledger IS
  'Append-only, hash-chained, secret-free evidence of delivery and operator state transitions.';

COMMIT;
