BEGIN;

-- Bind the outbox subject to the subject recorded by the recovery request.
-- The existing single-column foreign keys remain in place for compatibility;
-- this tenant-qualified key closes the cross-row substitution gap.
ALTER TABLE owner_recovery_requests
  ADD CONSTRAINT owner_recovery_requests_request_subject_unique
    UNIQUE (organization_id, request_id, subject_member_id);

ALTER TABLE owner_recovery_outbox
  ADD CONSTRAINT owner_recovery_outbox_request_subject_fkey
    FOREIGN KEY (organization_id, request_id, subject_member_id)
    REFERENCES owner_recovery_requests (organization_id, request_id, subject_member_id);

-- Management metadata is deliberately non-secret and bounded.  total_attempts
-- is backfilled before becoming NOT NULL so rows created by 0025/0029 remain
-- valid even when attempts is already non-zero.
ALTER TABLE owner_recovery_outbox
  ADD COLUMN management_version integer NOT NULL DEFAULT 1,
  ADD COLUMN redrive_count integer NOT NULL DEFAULT 0,
  ADD COLUMN total_attempts integer,
  ADD COLUMN suppressed_at timestamptz,
  ADD COLUMN suppression_reason text
    CHECK (suppression_reason IS NULL OR (
      octet_length(suppression_reason) BETWEEN 1 AND 128
      AND suppression_reason !~ '[[:cntrl:]]'
    ));

UPDATE owner_recovery_outbox
SET total_attempts = attempts
WHERE total_attempts IS NULL;

ALTER TABLE owner_recovery_outbox
  ALTER COLUMN total_attempts SET DEFAULT 0,
  ALTER COLUMN total_attempts SET NOT NULL,
  ADD CONSTRAINT owner_recovery_outbox_management_version_check
    CHECK (management_version >= 1),
  ADD CONSTRAINT owner_recovery_outbox_redrive_count_check
    CHECK (redrive_count BETWEEN 0 AND 3),
  ADD CONSTRAINT owner_recovery_outbox_total_attempts_check
    CHECK (total_attempts >= attempts);

ALTER TABLE owner_recovery_outbox
  DROP CONSTRAINT owner_recovery_outbox_status_check,
  DROP CONSTRAINT owner_recovery_outbox_delivery_state_check,
  ADD CONSTRAINT owner_recovery_outbox_status_check
    CHECK (status IN ('pending', 'published', 'dead_letter', 'suppressed')),
  ADD CONSTRAINT owner_recovery_outbox_delivery_state_check CHECK (
    (status = 'pending' AND published_at IS NULL)
    OR
    (status = 'published' AND published_at IS NOT NULL
      AND claim_token_digest IS NULL AND claim_expires_at IS NULL
      AND last_error_code IS NULL)
    OR
    (status = 'dead_letter' AND published_at IS NULL
      AND attempts = 100
      AND claim_token_digest IS NULL AND claim_expires_at IS NULL
      AND last_error_code IS NOT NULL)
    OR
    (status = 'suppressed' AND published_at IS NULL
      AND claim_token_digest IS NULL AND claim_expires_at IS NULL)
  ),
  ADD CONSTRAINT owner_recovery_outbox_suppression_state_check CHECK (
    (status = 'suppressed' AND suppressed_at IS NOT NULL AND suppression_reason IS NOT NULL)
    OR
    (status <> 'suppressed' AND suppressed_at IS NULL AND suppression_reason IS NULL)
  );

-- 0029-era writers only know about attempts.  Preserve that write contract
-- while keeping the stronger cumulative invariant for new management code.
CREATE FUNCTION agentpass_normalize_owner_recovery_outbox_attempts()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    NEW.total_attempts := GREATEST(COALESCE(NEW.total_attempts, 0), NEW.attempts);
  ELSIF NEW.attempts > OLD.attempts THEN
    NEW.total_attempts := OLD.total_attempts + (NEW.attempts - OLD.attempts);
  ELSIF NEW.total_attempts < OLD.total_attempts THEN
    RAISE EXCEPTION USING ERRCODE = 'check_violation',
      CONSTRAINT = 'owner_recovery_outbox_total_attempts_monotonic',
      MESSAGE = 'owner recovery outbox total attempts cannot decrease';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER owner_recovery_outbox_attempts_normalizer
  BEFORE INSERT OR UPDATE OF attempts, total_attempts ON owner_recovery_outbox
  FOR EACH ROW EXECUTE FUNCTION agentpass_normalize_owner_recovery_outbox_attempts();

-- The outbox event identity cannot be retargeted after it is created.  This is
-- separate from the request state trigger because the outbox is a delivery
-- ledger and must remain immutable even when request state advances.
CREATE FUNCTION agentpass_guard_owner_recovery_outbox_identity()
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
  THEN
    RAISE EXCEPTION USING ERRCODE = 'check_violation',
      CONSTRAINT = 'owner_recovery_outbox_identity_immutable',
      MESSAGE = 'owner recovery outbox identity is immutable';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER owner_recovery_outbox_identity_guard
  BEFORE UPDATE ON owner_recovery_outbox
  FOR EACH ROW EXECUTE FUNCTION agentpass_guard_owner_recovery_outbox_identity();

-- A suppressed event is terminal.  It may be audited or read, but cannot be
-- moved back into delivery or published after an operator has suppressed it.
CREATE FUNCTION agentpass_guard_owner_recovery_outbox_suppressed()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
  IF OLD.status = 'suppressed' AND NEW IS DISTINCT FROM OLD THEN
    RAISE EXCEPTION USING ERRCODE = 'check_violation',
      CONSTRAINT = 'owner_recovery_outbox_suppressed_terminal',
      MESSAGE = 'suppressed owner recovery outbox event is terminal';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER owner_recovery_outbox_suppressed_guard
  BEFORE UPDATE ON owner_recovery_outbox
  FOR EACH ROW EXECUTE FUNCTION agentpass_guard_owner_recovery_outbox_suppressed();

-- These indexes are intentionally partial: management pages only walk
-- dead-letter rows, while health checks only inspect pending rows.
CREATE INDEX owner_recovery_outbox_dead_letter_tenant_page
  ON owner_recovery_outbox (organization_id, created_at, event_id)
  WHERE status = 'dead_letter';

CREATE INDEX owner_recovery_outbox_pending_health
  ON owner_recovery_outbox (organization_id, available_at, created_at, event_id)
  WHERE status = 'pending';

COMMENT ON COLUMN owner_recovery_outbox.management_version IS
  'Optimistic-concurrency version for operator management actions; never secret material.';
COMMENT ON COLUMN owner_recovery_outbox.redrive_count IS
  'Bounded number of operator redrive actions permitted for this event.';
COMMENT ON COLUMN owner_recovery_outbox.total_attempts IS
  'Cumulative delivery attempts retained across redrive operations.';
COMMENT ON COLUMN owner_recovery_outbox.suppression_reason IS
  'Bounded operator reason for terminal suppression; provider messages are never stored.';

COMMIT;
