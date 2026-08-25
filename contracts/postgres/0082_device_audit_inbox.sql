BEGIN;

-- Device audit uploads are accepted into this durable inbox before an
-- asynchronous worker performs the existing chain-authority ingest. The
-- application role can invoke the fixed functions below, but cannot mutate
-- inbox rows directly.
CREATE TABLE public.device_audit_inbox (
  organization_id uuid NOT NULL,
  inbox_id uuid NOT NULL,
  device_id uuid NOT NULL,
  batch_id text NOT NULL CHECK (batch_id ~ '^audit-[0-9a-f]{64}$'),
  payload_sha256 text NOT NULL CHECK (payload_sha256 ~ '^[0-9a-f]{64}$'),
  payload jsonb NOT NULL,
  state text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending','processing','accepted','uncertain','dead_letter')),
  attempt integer NOT NULL DEFAULT 0 CHECK (attempt BETWEEN 0 AND 100),
  claim_token_digest bytea,
  claim_expires_at timestamptz,
  available_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  accepted_at timestamptz,
  uncertain_at timestamptz,
  last_error_code text CHECK (last_error_code IS NULL OR last_error_code ~ '^[a-z][a-z0-9_]{0,127}$'),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (organization_id, inbox_id),
  UNIQUE (organization_id, device_id, batch_id),
  FOREIGN KEY (organization_id, device_id) REFERENCES devices(organization_id, id),
  CHECK (
    (state = 'processing' AND claim_token_digest IS NOT NULL AND claim_expires_at IS NOT NULL)
    OR (state <> 'processing' AND claim_token_digest IS NULL AND claim_expires_at IS NULL)
  ),
  CHECK (state <> 'accepted' OR accepted_at IS NOT NULL),
  CHECK (state <> 'uncertain' OR uncertain_at IS NOT NULL),
  CHECK (state NOT IN ('pending','dead_letter') OR claim_token_digest IS NULL)
);

CREATE INDEX device_audit_inbox_claimable
  ON public.device_audit_inbox (available_at, created_at, organization_id, inbox_id)
  WHERE state = 'pending' AND claim_token_digest IS NULL;
CREATE INDEX device_audit_inbox_health
  ON public.device_audit_inbox (organization_id, state, created_at, inbox_id);

ALTER TABLE public.device_audit_inbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.device_audit_inbox FORCE ROW LEVEL SECURITY;
ALTER TABLE public.device_audit_inbox OWNER TO agentpass_migrator;

CREATE POLICY device_audit_inbox_migrator_authority
  ON public.device_audit_inbox FOR ALL TO agentpass_migrator
  USING (true) WITH CHECK (true);
CREATE POLICY device_audit_inbox_tenant_select
  ON public.device_audit_inbox FOR SELECT TO agentpass_app
  USING (organization_id = public.agentpass_device_audit_current_organization_id());

REVOKE ALL PRIVILEGES ON TABLE public.device_audit_inbox FROM PUBLIC, agentpass_app, agentpass_signer, agentpass_backup;
GRANT SELECT ON TABLE public.device_audit_inbox TO agentpass_app;
GRANT SELECT ON TABLE public.device_audit_inbox TO agentpass_backup;

CREATE OR REPLACE FUNCTION public.agentpass_device_audit_inbox_enqueue(
  p_organization_id uuid,
  p_inbox_id uuid,
  p_device_id uuid,
  p_batch_id text,
  p_payload_sha256 text,
  p_payload jsonb
)
RETURNS TABLE (organization_id uuid, inbox_id uuid, device_id uuid, batch_id text, payload_sha256 text, payload jsonb, state text, attempt integer)
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  authorized uuid;
BEGIN
  authorized := public.agentpass_authorize_device_audit_device(p_organization_id, p_device_id);
  IF authorized IS NULL OR authorized <> p_organization_id THEN RETURN; END IF;
  INSERT INTO public.device_audit_inbox (organization_id, inbox_id, device_id, batch_id, payload_sha256, payload)
  VALUES (p_organization_id, p_inbox_id, p_device_id, p_batch_id, p_payload_sha256, p_payload)
  ON CONFLICT (organization_id, device_id, batch_id) DO NOTHING;
  RETURN QUERY SELECT i.organization_id, i.inbox_id, i.device_id, i.batch_id, i.payload_sha256, i.payload, i.state, i.attempt
    FROM public.device_audit_inbox AS i
   WHERE i.organization_id = p_organization_id AND i.device_id = p_device_id AND i.batch_id = p_batch_id;
END;
$$;

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
  WITH candidates AS (
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

CREATE OR REPLACE FUNCTION public.agentpass_device_audit_inbox_settle(
  p_organization_id uuid,
  p_inbox_id uuid,
  p_attempt integer,
  p_claim_token_digest bytea,
  p_outcome text,
  p_error_code text DEFAULT NULL
)
RETURNS TABLE (state text, attempt integer, accepted_at timestamptz, uncertain_at timestamptz)
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
  IF p_outcome NOT IN ('accepted','retryable_failure','uncertain') OR p_attempt NOT BETWEEN 1 AND 100
     OR p_claim_token_digest IS NULL OR octet_length(p_claim_token_digest) <> 32 THEN RETURN; END IF;
  RETURN QUERY
  UPDATE public.device_audit_inbox AS i
     SET state = CASE WHEN p_outcome = 'accepted' THEN 'accepted' WHEN p_outcome = 'uncertain' THEN 'uncertain' WHEN i.attempt >= 100 THEN 'dead_letter' ELSE 'pending' END,
         accepted_at = CASE WHEN p_outcome = 'accepted' THEN clock_timestamp() ELSE i.accepted_at END,
         uncertain_at = CASE WHEN p_outcome = 'uncertain' THEN clock_timestamp() ELSE i.uncertain_at END,
         available_at = CASE WHEN p_outcome = 'retryable_failure' AND i.attempt < 100 THEN clock_timestamp() + interval '1 second' ELSE i.available_at END,
         last_error_code = CASE WHEN p_outcome = 'accepted' THEN NULL ELSE p_error_code END,
         claim_token_digest = NULL, claim_expires_at = NULL, updated_at = clock_timestamp()
   WHERE i.organization_id = p_organization_id AND i.inbox_id = p_inbox_id AND i.state = 'processing'
     AND i.attempt = p_attempt AND i.claim_token_digest = p_claim_token_digest AND i.claim_expires_at > clock_timestamp()
  RETURNING i.state, i.attempt, i.accepted_at, i.uncertain_at;
END;
$$;

ALTER FUNCTION public.agentpass_device_audit_inbox_enqueue(uuid,uuid,uuid,text,text,jsonb) OWNER TO agentpass_migrator;
ALTER FUNCTION public.agentpass_device_audit_inbox_claim(bytea,integer,integer) OWNER TO agentpass_migrator;
ALTER FUNCTION public.agentpass_device_audit_inbox_settle(uuid,uuid,integer,bytea,text,text) OWNER TO agentpass_migrator;
REVOKE ALL PRIVILEGES ON FUNCTION public.agentpass_device_audit_inbox_enqueue(uuid,uuid,uuid,text,text,jsonb) FROM PUBLIC, agentpass_signer, agentpass_backup;
REVOKE ALL PRIVILEGES ON FUNCTION public.agentpass_device_audit_inbox_claim(bytea,integer,integer) FROM PUBLIC, agentpass_signer, agentpass_backup;
REVOKE ALL PRIVILEGES ON FUNCTION public.agentpass_device_audit_inbox_settle(uuid,uuid,integer,bytea,text,text) FROM PUBLIC, agentpass_signer, agentpass_backup;
GRANT EXECUTE ON FUNCTION public.agentpass_device_audit_inbox_enqueue(uuid,uuid,uuid,text,text,jsonb) TO agentpass_app;
GRANT EXECUTE ON FUNCTION public.agentpass_device_audit_inbox_claim(bytea,integer,integer) TO agentpass_app;
GRANT EXECUTE ON FUNCTION public.agentpass_device_audit_inbox_settle(uuid,uuid,integer,bytea,text,text) TO agentpass_app;

COMMENT ON TABLE public.device_audit_inbox IS 'Durable tenant-bound device audit upload inbox; processing is lease-based and response loss is quarantined.';

COMMIT;
