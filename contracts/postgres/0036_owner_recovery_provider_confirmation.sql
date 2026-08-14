BEGIN;

-- Provider confirmation is a read-only, idempotency-key-bound lookup.  A
-- bounded database schedule prevents every API replica from polling the same
-- uncertain event while preserving the uncertain state until the provider
-- supplies an exact positive acknowledgement.
ALTER TABLE owner_recovery_outbox
  ADD COLUMN provider_confirmation_attempts integer NOT NULL DEFAULT 0,
  ADD COLUMN provider_confirmation_next_at timestamptz,
  ADD CONSTRAINT owner_recovery_outbox_provider_confirmation_attempts_check
    CHECK (provider_confirmation_attempts BETWEEN 0 AND 2147483647);

UPDATE owner_recovery_outbox
SET provider_confirmation_next_at = clock_timestamp()
WHERE status = 'uncertain'
  AND provider_binding_state = 'bound';

ALTER TABLE owner_recovery_outbox
  ADD CONSTRAINT owner_recovery_outbox_provider_confirmation_state_check CHECK (
    (status = 'uncertain'
      AND provider_binding_state = 'bound'
      AND provider_confirmation_next_at IS NOT NULL)
    OR
    ((status <> 'uncertain' OR provider_binding_state <> 'bound')
      AND provider_confirmation_next_at IS NULL)
  );

CREATE INDEX owner_recovery_outbox_provider_confirmation_due
  ON owner_recovery_outbox
    (provider_binding_id,provider_key_version,provider_binding_digest,
     provider_confirmation_next_at,organization_id,event_id)
  WHERE status = 'uncertain' AND provider_binding_state = 'bound';

COMMENT ON COLUMN owner_recovery_outbox.provider_confirmation_attempts IS
  'Bounded count of automatic provider acceptance lookups; no response content is stored.';
COMMENT ON COLUMN owner_recovery_outbox.provider_confirmation_next_at IS
  'Database-clock schedule for the next exact-binding provider lookup; NULL outside bound uncertain state.';
COMMENT ON INDEX owner_recovery_outbox_provider_confirmation_due IS
  'Cross-replica bounded scheduler for exact-binding acceptance lookup of uncertain deliveries.';

COMMIT;
