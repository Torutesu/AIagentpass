BEGIN;

-- D2.2: the receipt is the recovery authority after an enrollment POST
-- response is lost.  Control trust metadata therefore belongs inside the
-- signed statement, not in an unsigned response field or a current signer
-- lookup.  Keep the database boundary strict so old/partial envelopes cannot
-- be replayed as authoritative recovery evidence.
CREATE OR REPLACE FUNCTION agentpass_possession_statement_json_valid(statement_value jsonb)
RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
AS $$
DECLARE
  item record;
  control_item record;
  refresh_item record;
BEGIN
  IF jsonb_typeof(statement_value) <> 'object'
     OR (SELECT count(*) FROM jsonb_object_keys(statement_value)) <> 13
     OR NOT (statement_value ?& ARRAY[
       'version', 'enrollment_id', 'organization_id', 'device_id',
       'candidate_id', 'artifact_sha256', 'source_commit', 'team_id',
       'device_key_fingerprint', 'device_key_epoch',
       'challenge_nonce_digest', 'control', 'issued_at'
     ])
     OR jsonb_typeof(statement_value->'control') <> 'object'
     OR (SELECT count(*) FROM jsonb_object_keys(statement_value->'control')) <> 6
     OR NOT (statement_value->'control' ?& ARRAY[
       'format_epoch', 'issuer', 'key_id', 'public_key', 'bundle_path', 'refresh_hint'
     ])
     OR jsonb_typeof(statement_value->'control'->'refresh_hint') <> 'object'
     OR (SELECT count(*) FROM jsonb_object_keys(statement_value->'control'->'refresh_hint')) <> 3
     OR NOT (statement_value->'control'->'refresh_hint' ?& ARRAY['key_id', 'algorithm', 'public_key']) THEN
    RETURN false;
  END IF;

  FOR item IN SELECT object_entry.key, object_entry.value
    FROM jsonb_each(statement_value) AS object_entry(key, value) LOOP
    IF item.key = 'control' THEN
      CONTINUE;
    END IF;
    IF item.key NOT IN (
      'version', 'enrollment_id', 'organization_id', 'device_id',
      'candidate_id', 'artifact_sha256', 'source_commit', 'team_id',
      'device_key_fingerprint', 'device_key_epoch',
      'challenge_nonce_digest', 'issued_at'
    ) OR jsonb_typeof(item.value) NOT IN ('string', 'number') THEN
      RETURN false;
    END IF;
  END LOOP;

  FOR control_item IN SELECT object_entry.key, object_entry.value
    FROM jsonb_each(statement_value->'control') AS object_entry(key, value) LOOP
    IF control_item.key = 'refresh_hint' THEN
      CONTINUE;
    END IF;
    IF control_item.key NOT IN ('format_epoch', 'issuer', 'key_id', 'public_key', 'bundle_path')
       OR jsonb_typeof(control_item.value) NOT IN ('string', 'number') THEN
      RETURN false;
    END IF;
  END LOOP;

  FOR refresh_item IN SELECT object_entry.key, object_entry.value
    FROM jsonb_each(statement_value->'control'->'refresh_hint') AS object_entry(key, value) LOOP
    IF refresh_item.key NOT IN ('key_id', 'algorithm', 'public_key')
       OR jsonb_typeof(refresh_item.value) <> 'string' THEN
      RETURN false;
    END IF;
  END LOOP;

  RETURN statement_value->>'version' = '1'
    AND statement_value->>'challenge_nonce_digest' ~ '^[0-9a-f]{64}$'
    AND statement_value->>'artifact_sha256' ~ '^[0-9a-f]{64}$'
    AND statement_value->>'source_commit' ~ '^[0-9a-f]{40}$'
    AND statement_value->>'team_id' ~ '^[A-Z0-9]{10}$'
    AND statement_value->>'device_key_fingerprint' ~ '^SHA256:[A-Za-z0-9_-]{43}$'
    AND statement_value->'control'->>'format_epoch' = '2'
    AND statement_value->'control'->>'issuer' ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
    AND statement_value->'control'->>'key_id' ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
    AND statement_value->'control'->>'bundle_path' ~ '^/v1/organizations/[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}/bundles/[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    AND statement_value->'control'->'refresh_hint'->>'key_id' ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
    AND statement_value->'control'->'refresh_hint'->>'algorithm' = 'ed25519'
    AND position('PRIVATE KEY' IN upper(statement_value->'control'->>'public_key')) = 0
    AND position('PRIVATE KEY' IN upper(statement_value->'control'->'refresh_hint'->>'public_key')) = 0;
END;
$$;

COMMIT;
