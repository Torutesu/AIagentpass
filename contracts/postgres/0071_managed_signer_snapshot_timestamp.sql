BEGIN;

-- PostgreSQL dollar-quoted function bodies do not require the extra
-- backslash layer used by JavaScript string literals. Migration 0051 used
-- \\d in the regular expression, which matched a literal backslash followed
-- by d and rejected every otherwise-valid retiring-key verification window.
-- Replace only the validator and preserve the historical 0051 checksum.

CREATE OR REPLACE FUNCTION public.agentpass_managed_signer_snapshot_is_valid(
  p_snapshot jsonb,
  p_purpose text,
  p_algorithm text,
  p_max_keys integer,
  p_max_verification_overlap_ms bigint,
  p_allow_expired_retiring boolean
)
RETURNS boolean
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY INVOKER
SET search_path = pg_catalog, public
AS $$
DECLARE
  key_value jsonb;
  key_version bigint;
  state_version bigint;
  snapshot_version bigint;
  key_count integer;
  active_count integer;
  now_at timestamptz := pg_catalog.clock_timestamp();
  verification_until timestamptz;
  verification_text text;
  key_id text;
  fingerprint text;
  state text;
BEGIN
  IF p_purpose IS NULL OR p_purpose !~ '^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$'
     OR p_algorithm IS DISTINCT FROM 'ed25519'
     OR p_max_keys IS NULL OR p_max_keys < 1 OR p_max_keys > 32
     OR p_max_verification_overlap_ms IS NULL
     OR p_max_verification_overlap_ms < 1
     OR p_max_verification_overlap_ms > 31536000000
     OR p_snapshot IS NULL OR jsonb_typeof(p_snapshot) IS DISTINCT FROM 'object'
  THEN
    RETURN false;
  END IF;

  IF (SELECT count(*) FROM pg_catalog.jsonb_object_keys(p_snapshot)) <> 4
     OR NOT (p_snapshot ? 'version')
     OR NOT (p_snapshot ? 'purpose')
     OR NOT (p_snapshot ? 'algorithm')
     OR NOT (p_snapshot ? 'keys')
     OR jsonb_typeof(p_snapshot->'version') IS DISTINCT FROM 'number'
     OR jsonb_typeof(p_snapshot->'purpose') IS DISTINCT FROM 'string'
     OR jsonb_typeof(p_snapshot->'algorithm') IS DISTINCT FROM 'string'
     OR jsonb_typeof(p_snapshot->'keys') IS DISTINCT FROM 'array'
     OR p_snapshot->>'purpose' IS DISTINCT FROM p_purpose
     OR p_snapshot->>'algorithm' IS DISTINCT FROM p_algorithm
     OR p_snapshot->>'version' !~ '^[1-9][0-9]{0,18}$'
  THEN
    RETURN false;
  END IF;

  snapshot_version := (p_snapshot->>'version')::bigint;
  key_count := pg_catalog.jsonb_array_length(p_snapshot->'keys');
  IF snapshot_version < 1 OR key_count < 1 OR key_count > p_max_keys THEN
    RETURN false;
  END IF;

  active_count := 0;
  FOR key_value IN SELECT value FROM pg_catalog.jsonb_array_elements(p_snapshot->'keys') LOOP
    IF jsonb_typeof(key_value) IS DISTINCT FROM 'object'
       OR (SELECT count(*) FROM pg_catalog.jsonb_object_keys(key_value)) NOT BETWEEN 7 AND 9
       OR NOT (key_value ? 'key_id')
       OR NOT (key_value ? 'key_version')
       OR NOT (key_value ? 'purpose')
       OR NOT (key_value ? 'algorithm')
       OR NOT (key_value ? 'public_key_fingerprint')
       OR NOT (key_value ? 'state')
       OR NOT (key_value ? 'state_version')
       OR EXISTS (
         SELECT 1
         FROM pg_catalog.jsonb_object_keys(key_value) AS field(name)
         WHERE field.name NOT IN (
           'key_id', 'key_version', 'purpose', 'algorithm',
           'public_key_fingerprint', 'state', 'state_version',
           'public_key', 'verification_until'
         )
       )
    THEN
      RETURN false;
    END IF;

    key_id := key_value->>'key_id';
    fingerprint := key_value->>'public_key_fingerprint';
    state := key_value->>'state';
    IF jsonb_typeof(key_value->'key_id') IS DISTINCT FROM 'string'
       OR key_id !~ '^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$'
       OR jsonb_typeof(key_value->'key_version') IS DISTINCT FROM 'number'
       OR key_value->>'key_version' !~ '^[1-9][0-9]{0,18}$'
       OR jsonb_typeof(key_value->'purpose') IS DISTINCT FROM 'string'
       OR key_value->>'purpose' IS DISTINCT FROM p_purpose
       OR jsonb_typeof(key_value->'algorithm') IS DISTINCT FROM 'string'
       OR key_value->>'algorithm' IS DISTINCT FROM p_algorithm
       OR jsonb_typeof(key_value->'public_key_fingerprint') IS DISTINCT FROM 'string'
       OR fingerprint !~ '^[0-9a-f]{64}$'
       OR jsonb_typeof(key_value->'state') IS DISTINCT FROM 'string'
       OR state NOT IN ('active', 'retiring', 'revoked', 'emergency-disabled')
       OR jsonb_typeof(key_value->'state_version') IS DISTINCT FROM 'number'
       OR key_value->>'state_version' !~ '^[1-9][0-9]{0,18}$'
    THEN
      RETURN false;
    END IF;

    key_version := (key_value->>'key_version')::bigint;
    state_version := (key_value->>'state_version')::bigint;
    IF state_version > snapshot_version THEN
      RETURN false;
    END IF;

    IF key_value ? 'public_key' THEN
      IF jsonb_typeof(key_value->'public_key') IS DISTINCT FROM 'string'
         OR octet_length(key_value->>'public_key') NOT BETWEEN 1 AND 8192
         OR key_value->>'public_key' ~* 'PRIVATE[[:space:]_-]*KEY'
      THEN
        RETURN false;
      END IF;
    END IF;

    IF state = 'active' THEN
      active_count := active_count + 1;
    END IF;

    IF state = 'retiring' THEN
      IF NOT (key_value ? 'verification_until')
         OR jsonb_typeof(key_value->'verification_until') IS DISTINCT FROM 'string'
      THEN
        RETURN false;
      END IF;
      verification_text := key_value->>'verification_until';
      IF verification_text !~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$'
         OR pg_catalog.to_char(
              verification_text::timestamptz AT TIME ZONE 'UTC',
              'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'
            ) IS DISTINCT FROM verification_text
      THEN
        RETURN false;
      END IF;
      verification_until := verification_text::timestamptz;
      IF (NOT p_allow_expired_retiring AND verification_until <= now_at)
         OR verification_until > now_at
             + (p_max_verification_overlap_ms::double precision * interval '1 millisecond')
      THEN
        RETURN false;
      END IF;
    ELSIF key_value ? 'verification_until' THEN
      RETURN false;
    END IF;
  END LOOP;

  IF active_count > 1 THEN
    RETURN false;
  END IF;

  IF (SELECT count(DISTINCT value->>'key_id')
      FROM pg_catalog.jsonb_array_elements(p_snapshot->'keys') AS item(value)) <> key_count
     OR (SELECT count(DISTINCT value->>'key_version')
         FROM pg_catalog.jsonb_array_elements(p_snapshot->'keys') AS item(value)) <> key_count
     OR (SELECT count(DISTINCT value->>'public_key_fingerprint')
         FROM pg_catalog.jsonb_array_elements(p_snapshot->'keys') AS item(value)) <> key_count
  THEN
    RETURN false;
  END IF;

  RETURN true;
EXCEPTION WHEN OTHERS THEN
  RETURN false;
END;
$$;

REVOKE ALL ON FUNCTION public.agentpass_managed_signer_snapshot_is_valid(
  jsonb, text, text, integer, bigint, boolean
) FROM PUBLIC;

COMMENT ON FUNCTION public.agentpass_managed_signer_snapshot_is_valid(
  jsonb, text, text, integer, bigint, boolean
) IS 'Validates the exact managed-signer lifecycle snapshot, including canonical retiring-key verification timestamps.';

COMMIT;
