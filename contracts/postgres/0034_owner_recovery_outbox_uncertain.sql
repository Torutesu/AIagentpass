BEGIN;

-- An unknown provider outcome is durable delivery evidence, not a retryable
-- pending row.  Keep the reason closed and bounded: provider payloads,
-- response bodies, destinations, and operator text never enter this table.
ALTER TABLE owner_recovery_outbox
  ADD COLUMN uncertain_at timestamptz,
  ADD COLUMN uncertain_reason text,
  ADD CONSTRAINT owner_recovery_outbox_uncertain_at_check CHECK (
    uncertain_at IS NULL OR uncertain_at >= created_at
  ),
  ADD CONSTRAINT owner_recovery_outbox_uncertain_reason_check CHECK (
    uncertain_reason IS NULL OR (
      char_length(uncertain_reason) BETWEEN 1 AND 64
      AND uncertain_reason IN (
        'provider_timeout',
        'provider_transport_error',
        'provider_response_invalid',
        'terminal_commit_unknown',
        'process_interrupted',
        'delivery_unknown'
      )
    )
  );

-- 0029/0033 workers recorded an unknown outcome as a pending row with the
-- fixed delivery_uncertain error code.  Promote those rows before installing
-- the stricter checks.  This is a forward-only state conversion: no event,
-- attempt count, or audit-relevant identity is deleted, while any old lease
-- is deliberately released so the row cannot be blindly claimed again.
UPDATE owner_recovery_outbox
SET status = 'uncertain',
    uncertain_at = GREATEST(updated_at, created_at),
    uncertain_reason = 'delivery_unknown',
    claim_token_digest = NULL,
    claim_expires_at = NULL,
    updated_at = GREATEST(updated_at, created_at)
WHERE status = 'pending'
  AND last_error_code = 'delivery_uncertain';

-- A lease that was already expired when this migration started is evidence of
-- an interrupted worker.  Quarantine it during upgrade instead of allowing the
-- first 0034 worker to resend it blindly.
UPDATE owner_recovery_outbox
SET status = 'uncertain',
    uncertain_at = GREATEST(updated_at, created_at),
    uncertain_reason = 'process_interrupted',
    last_error_code = 'delivery_uncertain',
    claim_token_digest = NULL,
    claim_expires_at = NULL,
    updated_at = GREATEST(updated_at, created_at)
WHERE status = 'pending'
  AND claim_token_digest IS NOT NULL
  AND claim_expires_at <= clock_timestamp();

-- Rebuild every outbox state invariant together so the new state cannot be
-- accepted by one older constraint while violating another.  Dropping and
-- recreating constraints is metadata-only and preserves all existing rows.
ALTER TABLE owner_recovery_outbox
  DROP CONSTRAINT owner_recovery_outbox_status_check,
  DROP CONSTRAINT owner_recovery_outbox_delivery_state_check,
  DROP CONSTRAINT owner_recovery_outbox_claim_state_check,
  DROP CONSTRAINT owner_recovery_outbox_suppression_state_check,
  ADD CONSTRAINT owner_recovery_outbox_status_check
    CHECK (status IN ('pending', 'published', 'uncertain', 'dead_letter', 'suppressed')),
  ADD CONSTRAINT owner_recovery_outbox_delivery_state_check CHECK (
    (status = 'pending'
      AND published_at IS NULL
      AND uncertain_at IS NULL
      AND uncertain_reason IS NULL
      AND (last_error_code IS NULL OR last_error_code <> 'delivery_uncertain'))
    OR
    (status = 'published'
      AND published_at IS NOT NULL
      AND uncertain_at IS NULL
      AND uncertain_reason IS NULL
      AND claim_token_digest IS NULL
      AND claim_expires_at IS NULL
      AND last_error_code IS NULL)
    OR
    (status = 'uncertain'
      AND published_at IS NULL
      AND uncertain_at IS NOT NULL
      AND uncertain_reason IS NOT NULL
      AND claim_token_digest IS NULL
      AND claim_expires_at IS NULL
      AND suppressed_at IS NULL
      AND suppression_reason IS NULL
      AND last_error_code = 'delivery_uncertain')
    OR
    (status = 'dead_letter'
      AND published_at IS NULL
      AND uncertain_at IS NULL
      AND uncertain_reason IS NULL
      AND attempts = 100
      AND claim_token_digest IS NULL
      AND claim_expires_at IS NULL
      AND last_error_code IS NOT NULL
      AND last_error_code <> 'delivery_uncertain')
    OR
    (status = 'suppressed'
      AND published_at IS NULL
      AND uncertain_at IS NULL
      AND uncertain_reason IS NULL
      AND claim_token_digest IS NULL
      AND claim_expires_at IS NULL
      AND (last_error_code IS NULL OR last_error_code <> 'delivery_uncertain'))
  ),
  ADD CONSTRAINT owner_recovery_outbox_claim_state_check CHECK (
    (status IN ('published', 'uncertain', 'dead_letter', 'suppressed')
      AND claim_token_digest IS NULL
      AND claim_expires_at IS NULL)
    OR
    (status = 'pending'
      AND (
        (claim_token_digest IS NULL AND claim_expires_at IS NULL)
        OR
        (claim_token_digest IS NOT NULL
          AND claim_expires_at IS NOT NULL
          AND claim_expires_at > updated_at)
      ))
  ),
  ADD CONSTRAINT owner_recovery_outbox_suppression_state_check CHECK (
    (status = 'suppressed'
      AND suppressed_at IS NOT NULL
      AND suppression_reason IS NOT NULL)
    OR
    (status IN ('pending', 'published', 'uncertain', 'dead_letter')
      AND suppressed_at IS NULL
      AND suppression_reason IS NULL)
  );

-- Operators and health checks must be able to find accepted-but-unconfirmed
-- rows without putting them back into the worker's pending claim path.
CREATE INDEX owner_recovery_outbox_uncertain_lookup
  ON owner_recovery_outbox (uncertain_at, organization_id, created_at, event_id)
  WHERE status = 'uncertain';

COMMENT ON COLUMN owner_recovery_outbox.uncertain_at IS
  'When provider delivery became accepted-but-unconfirmed; this state is not worker-claimable.';
COMMENT ON COLUMN owner_recovery_outbox.uncertain_reason IS
  'Closed, bounded reason for an unknown delivery outcome; provider responses and free-form text are never stored.';
COMMENT ON INDEX owner_recovery_outbox_uncertain_lookup IS
  'Tenant-scoped lookup for durable uncertain deliveries; uncertain rows are excluded from pending claims.';

COMMIT;
