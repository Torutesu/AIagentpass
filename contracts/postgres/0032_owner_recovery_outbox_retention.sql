BEGIN;

-- Pruning removes bulky delivery rows only after a fixed minimum retention
-- period. The compact ledger is append-only and preserves the immutable event
-- binding and terminal delivery outcome without retaining delivery
-- configuration or free-form operator text.
CREATE TABLE owner_recovery_outbox_retention_ledger (
  organization_id uuid NOT NULL,
  event_id uuid NOT NULL,
  request_id uuid NOT NULL,
  subject_member_id uuid NOT NULL,
  event_type text NOT NULL CHECK (
    char_length(event_type) BETWEEN 1 AND 128
    AND event_type ~ '^recovery\.[a-z]+(\.[a-z]+)*$'
  ),
  terminal_status text NOT NULL CHECK (terminal_status IN ('published', 'dead_letter', 'suppressed')),
  terminal_at timestamptz NOT NULL,
  pruned_at timestamptz NOT NULL,
  attempts integer NOT NULL CHECK (attempts BETWEEN 0 AND 100),
  total_attempts integer NOT NULL CHECK (total_attempts >= attempts),
  management_version integer NOT NULL CHECK (management_version >= 1),
  redrive_count integer NOT NULL CHECK (redrive_count BETWEEN 0 AND 3),
  last_error_code text CHECK (
    last_error_code IS NULL OR (
      char_length(last_error_code) BETWEEN 1 AND 128
      AND last_error_code ~ '^[a-z][a-z0-9_]*$'
    )
  ),
  PRIMARY KEY (organization_id, event_id),
  CHECK (terminal_at <= pruned_at),
  CHECK ((terminal_status = 'dead_letter') = (last_error_code IS NOT NULL))
);

CREATE INDEX owner_recovery_outbox_retention_pruned
  ON owner_recovery_outbox_retention_ledger (pruned_at, organization_id, event_id);

CREATE FUNCTION agentpass_guard_owner_recovery_outbox_retention_ledger()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
  RAISE EXCEPTION USING ERRCODE = 'check_violation',
    CONSTRAINT = 'owner_recovery_outbox_retention_ledger_immutable',
    MESSAGE = 'owner recovery outbox retention ledger is immutable';
END;
$$;

CREATE TRIGGER owner_recovery_outbox_retention_ledger_guard
  BEFORE UPDATE OR DELETE ON owner_recovery_outbox_retention_ledger
  FOR EACH ROW EXECUTE FUNCTION agentpass_guard_owner_recovery_outbox_retention_ledger();

CREATE FUNCTION agentpass_prune_owner_recovery_outbox_terminal(prune_limit integer)
RETURNS TABLE (
  published bigint,
  dead_letter bigint,
  suppressed bigint,
  total bigint
)
LANGUAGE plpgsql
VOLATILE
SET search_path = pg_catalog, public
AS $$
BEGIN
  IF prune_limit IS NULL OR prune_limit < 1 OR prune_limit > 1000 THEN
    RAISE EXCEPTION USING ERRCODE = 'check_violation',
      MESSAGE = 'invalid owner recovery outbox prune limit';
  END IF;

  RETURN QUERY
  WITH candidates AS MATERIALIZED (
    SELECT o.*,
      CASE o.status
        WHEN 'published' THEN o.published_at
        WHEN 'dead_letter' THEN o.updated_at
        WHEN 'suppressed' THEN o.suppressed_at
      END AS terminal_at
    FROM owner_recovery_outbox o
    WHERE (o.status = 'published' AND o.published_at <= clock_timestamp() - interval '30 days')
       OR (o.status = 'dead_letter' AND o.updated_at <= clock_timestamp() - interval '90 days')
       OR (o.status = 'suppressed' AND o.suppressed_at <= clock_timestamp() - interval '365 days')
    ORDER BY terminal_at ASC,o.organization_id ASC,o.event_id ASC
    FOR UPDATE SKIP LOCKED
    LIMIT prune_limit
  ), archived AS (
    INSERT INTO owner_recovery_outbox_retention_ledger (
      organization_id,event_id,request_id,subject_member_id,event_type,
      terminal_status,terminal_at,pruned_at,attempts,total_attempts,
      management_version,redrive_count,last_error_code
    )
    SELECT organization_id,event_id,request_id,subject_member_id,event_type,
      status,terminal_at,clock_timestamp(),attempts,total_attempts,
      management_version,redrive_count,
      CASE WHEN status='dead_letter' THEN last_error_code ELSE NULL END
    FROM candidates
    RETURNING organization_id,event_id
  ), deleted AS (
    DELETE FROM owner_recovery_outbox o
    USING archived a
    WHERE o.organization_id=a.organization_id AND o.event_id=a.event_id
    RETURNING o.status
  )
  SELECT
    count(*) FILTER (WHERE status='published')::bigint,
    count(*) FILTER (WHERE status='dead_letter')::bigint,
    count(*) FILTER (WHERE status='suppressed')::bigint,
    count(*)::bigint
  FROM deleted;
END;
$$;

COMMENT ON TABLE owner_recovery_outbox_retention_ledger IS
  'Append-only, secret-free evidence for terminal owner-recovery notification rows removed by bounded retention.';
COMMENT ON FUNCTION agentpass_prune_owner_recovery_outbox_terminal(integer) IS
  'Prunes at most 1000 rows after fixed 30d published, 90d dead-letter, and 365d suppression retention.';

COMMIT;
