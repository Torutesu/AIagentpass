BEGIN;

-- PostgreSQL's base64 encoder wraps output after 76 characters. Ed25519
-- signatures are 64 bytes and therefore cross that boundary. Keep the public
-- authority envelope canonical so strict consumers never have to accept
-- whitespace-bearing or otherwise ambiguous encodings.
CREATE OR REPLACE FUNCTION public.agentpass_managed_signer_signing_record_json(
  p_purpose text,
  p_operation_id text,
  p_request_digest bytea,
  p_key_id text,
  p_key_version bigint,
  p_status text,
  p_reserved_lifecycle_version bigint,
  p_created_at timestamptz,
  p_updated_at timestamptz,
  p_expires_at timestamptz,
  p_claim_expires_at timestamptz,
  p_provider_started_at timestamptz,
  p_signature bytea,
  p_provider_receipt_provider text,
  p_provider_receipt_id text
)
RETURNS jsonb
LANGUAGE sql
STABLE
PARALLEL SAFE
SECURITY INVOKER
SET search_path = pg_catalog, public
AS $$
  SELECT jsonb_strip_nulls(jsonb_build_object(
    'purpose', p_purpose,
    'operation_id', p_operation_id,
    'request_digest', encode(p_request_digest, 'hex'),
    'key_id', p_key_id,
    'key_version', p_key_version,
    'state', p_status,
    'reserved_lifecycle_version', p_reserved_lifecycle_version,
    'created_at', p_created_at,
    'updated_at', p_updated_at,
    'expires_at', p_expires_at,
    'claim_expires_at', p_claim_expires_at,
    'provider_started_at', p_provider_started_at,
    'signature', CASE WHEN p_signature IS NULL THEN NULL
      ELSE replace(encode(p_signature, 'base64'), chr(10), '') END,
    'provider_receipt', CASE
      WHEN p_provider_receipt_provider IS NULL THEN NULL
      ELSE jsonb_build_object('provider', p_provider_receipt_provider, 'receipt_id', p_provider_receipt_id)
    END
  ));
$$;

REVOKE ALL ON FUNCTION public.agentpass_managed_signer_signing_record_json(
  text, text, bytea, text, bigint, text, bigint, timestamptz, timestamptz,
  timestamptz, timestamptz, timestamptz, bytea, text, text
) FROM PUBLIC;

COMMIT;
