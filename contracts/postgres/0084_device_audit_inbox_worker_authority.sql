BEGIN;

-- The HTTP application may enqueue an authenticated tenant upload, but it
-- must never be able to claim and read every tenant's raw audit payload.
-- Deployment-wide processing and aggregate health belong to the dedicated
-- maintenance database identity.
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
  canonical_payload text;
  expected_digest text;
BEGIN
  IF p_payload IS NULL OR jsonb_typeof(p_payload) <> 'object'
     OR jsonb_typeof(p_payload->'events') <> 'array'
     OR jsonb_array_length(p_payload->'events') NOT BETWEEN 1 AND 64 THEN
    RAISE EXCEPTION 'device audit inbox payload is invalid' USING ERRCODE = '22023';
  END IF;
  canonical_payload := public.agentpass_canonical_audit_json(p_payload);
  expected_digest := encode(digest(convert_to(canonical_payload, 'UTF8'), 'sha256'), 'hex');
  IF p_payload_sha256 IS DISTINCT FROM expected_digest
     OR p_batch_id IS DISTINCT FROM 'audit-' || expected_digest THEN
    RAISE EXCEPTION 'device audit inbox payload identity does not match' USING ERRCODE = '23514';
  END IF;
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

-- Keep the lease transition implementation from the previous migration, but
-- move its executable authority to the isolated maintenance identity.
REVOKE ALL PRIVILEGES ON TABLE public.device_audit_inbox FROM agentpass_app;
REVOKE ALL PRIVILEGES ON FUNCTION public.agentpass_device_audit_inbox_claim(bytea,integer,integer) FROM agentpass_app;
REVOKE ALL PRIVILEGES ON FUNCTION public.agentpass_device_audit_inbox_settle(uuid,uuid,integer,bytea,text,text) FROM agentpass_app;
GRANT EXECUTE ON FUNCTION public.agentpass_device_audit_inbox_claim(bytea,integer,integer) TO agentpass_maintenance;
GRANT EXECUTE ON FUNCTION public.agentpass_device_audit_inbox_settle(uuid,uuid,integer,bytea,text,text) TO agentpass_maintenance;

CREATE OR REPLACE FUNCTION public.agentpass_device_audit_inbox_health()
RETURNS TABLE (state text, row_count bigint, oldest_at timestamptz, expired_processing bigint)
LANGUAGE sql
STABLE
PARALLEL SAFE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
  SELECT i.state,
         count(*)::bigint AS row_count,
         min(i.created_at) AS oldest_at,
         count(*) FILTER (WHERE i.state = 'processing' AND i.claim_expires_at <= clock_timestamp())::bigint AS expired_processing
    FROM public.device_audit_inbox AS i
   GROUP BY i.state;
$$;

ALTER FUNCTION public.agentpass_device_audit_inbox_enqueue(uuid,uuid,uuid,text,text,jsonb) OWNER TO agentpass_migrator;
ALTER FUNCTION public.agentpass_device_audit_inbox_health() OWNER TO agentpass_migrator;
REVOKE ALL PRIVILEGES ON FUNCTION public.agentpass_device_audit_inbox_health() FROM PUBLIC, agentpass_app, agentpass_signer, agentpass_backup;
GRANT EXECUTE ON FUNCTION public.agentpass_device_audit_inbox_health() TO agentpass_maintenance;

COMMENT ON FUNCTION public.agentpass_device_audit_inbox_health() IS
  'Returns deployment-wide aggregate inbox state through the maintenance authority without exposing payloads or tenant identifiers.';

COMMIT;
