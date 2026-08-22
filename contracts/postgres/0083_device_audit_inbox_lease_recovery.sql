BEGIN;

-- A process can die after claiming an inbox row and before settling it. The
-- lease is the only durable recovery signal; reclaiming it is safe because
-- the downstream audit write is idempotent on the event identity and exact
-- evidence. The next claim cycle moves expired processing rows back to the
-- pending state before selecting work with SKIP LOCKED.
CREATE INDEX device_audit_inbox_expired_processing
  ON public.device_audit_inbox (claim_expires_at, organization_id, inbox_id)
  WHERE state = 'processing';

CREATE OR REPLACE FUNCTION public.agentpass_device_audit_inbox_claim(
  p_claim_token_digest bytea,
  p_limit integer,
  p_lease_ms integer
)
RETURNS TABLE (organization_id uuid, inbox_id uuid, device_id uuid, batch_id text, payload_sha256 text, payload jsonb, attempt integer, claim_expires_at timestamptz)
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
  IF p_claim_token_digest IS NULL OR octet_length(p_claim_token_digest) <> 32 OR p_limit NOT BETWEEN 1 AND 100 OR p_lease_ms NOT BETWEEN 1000 AND 300000 THEN RETURN; END IF;
  RETURN QUERY
  WITH expired_candidates AS (
    SELECT i.organization_id, i.inbox_id
      FROM public.device_audit_inbox AS i
     WHERE i.state = 'processing' AND i.claim_expires_at <= clock_timestamp()
     ORDER BY i.claim_expires_at, i.created_at, i.organization_id, i.inbox_id
     FOR UPDATE SKIP LOCKED
     LIMIT p_limit
  ), expired AS (
    UPDATE public.device_audit_inbox AS i
       SET state = CASE WHEN i.attempt >= 100 THEN 'dead_letter' ELSE 'pending' END,
           claim_token_digest = NULL, claim_expires_at = NULL,
           available_at = CASE WHEN i.attempt >= 100 THEN i.available_at ELSE clock_timestamp() END,
           last_error_code = CASE WHEN i.attempt >= 100 THEN 'lease_expired_attempt_limit' ELSE 'lease_expired' END,
           updated_at = clock_timestamp()
      FROM expired_candidates AS c
     WHERE i.organization_id = c.organization_id AND i.inbox_id = c.inbox_id
    RETURNING i.organization_id, i.inbox_id
  ), candidates AS (
    SELECT i.organization_id, i.inbox_id
      FROM public.device_audit_inbox AS i
     WHERE i.state = 'pending' AND i.attempt < 100 AND i.available_at <= clock_timestamp()
       AND i.claim_token_digest IS NULL
     ORDER BY i.available_at, i.created_at, i.organization_id, i.inbox_id
     FOR UPDATE SKIP LOCKED
     LIMIT p_limit
  ), claimed AS (
    UPDATE public.device_audit_inbox AS i
       SET state = 'processing', attempt = i.attempt + 1,
           claim_token_digest = p_claim_token_digest,
           claim_expires_at = clock_timestamp() + (p_lease_ms * interval '1 millisecond'),
           available_at = clock_timestamp() + (p_lease_ms * interval '1 millisecond'),
           updated_at = clock_timestamp()
      FROM candidates AS c
     WHERE i.organization_id = c.organization_id AND i.inbox_id = c.inbox_id
    RETURNING i.*
  )
  SELECT c.organization_id, c.inbox_id, c.device_id, c.batch_id, c.payload_sha256, c.payload, c.attempt, c.claim_expires_at
    FROM claimed AS c;
END;
$$;

ALTER FUNCTION public.agentpass_device_audit_inbox_claim(bytea,integer,integer) OWNER TO agentpass_migrator;
REVOKE ALL PRIVILEGES ON FUNCTION public.agentpass_device_audit_inbox_claim(bytea,integer,integer) FROM PUBLIC, agentpass_signer, agentpass_backup;
GRANT EXECUTE ON FUNCTION public.agentpass_device_audit_inbox_claim(bytea,integer,integer) TO agentpass_app;

COMMENT ON FUNCTION public.agentpass_device_audit_inbox_claim(bytea,integer,integer) IS 'Claims pending audit inbox rows and safely requeues rows whose processing lease expired.';

COMMIT;
