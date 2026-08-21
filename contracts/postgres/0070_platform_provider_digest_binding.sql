BEGIN;

-- The managed-signer lifecycle ledger binds the canonical request envelope,
-- while the lower provider-operation ledger binds SHA-256 of the exact bytes
-- sent to the provider. 0048 compared both ledgers with the canonical digest,
-- making a correctly committed provider operation impossible to promote.
-- Preserve both purpose-separated digests at the final commit boundary.
CREATE OR REPLACE FUNCTION public.agentpass_platform_promotion_issuance_commit(
  p_promotion_id uuid,
  p_deployment_id text,
  p_environment text,
  p_candidate_id text,
  p_idempotency_key text,
  p_claim_token_digest bytea,
  p_signing_bytes bytea,
  p_signature bytea,
  p_evidence_bytes bytea,
  p_evidence_digest bytea
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  issuance_row platform_promotion_issuances;
  head_row platform_promotion_deployments;
  signer_row record;
  provider_row record;
  key_row record;
  statement_text text;
  statement_json jsonb;
  evidence_json jsonb;
  expected_evidence_text text;
  expected_signing_bytes bytea;
  expected_request_digest bytea;
  expected_signature text;
  expected_fingerprint text;
  next_generation bigint;
BEGIN
  IF p_promotion_id IS NULL OR p_deployment_id IS NULL OR p_environment NOT IN ('staging', 'production')
     OR p_candidate_id IS NULL OR p_idempotency_key IS NULL
     OR p_claim_token_digest IS NULL OR octet_length(p_claim_token_digest) <> 32
     OR p_signing_bytes IS NULL OR octet_length(p_signing_bytes) NOT BETWEEN 1 AND 131072
     OR p_signature IS NULL OR octet_length(p_signature) <> 64
     OR p_evidence_bytes IS NULL OR octet_length(p_evidence_bytes) NOT BETWEEN 1 AND 131072
     OR p_evidence_digest IS NULL OR octet_length(p_evidence_digest) <> 32
     OR p_evidence_digest IS DISTINCT FROM sha256(p_evidence_bytes)
  THEN RAISE EXCEPTION USING ERRCODE = 'invalid_parameter_value', MESSAGE = 'platform promotion commit input is invalid'; END IF;

  PERFORM pg_advisory_xact_lock(hashtextextended('agentpass:platform-promotion:' || p_deployment_id || ':' || p_environment, 0));
  SELECT * INTO issuance_row FROM platform_promotion_issuances WHERE promotion_id = p_promotion_id FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE = 'no_data_found', MESSAGE = 'platform promotion issuance was not found'; END IF;
  IF issuance_row.deployment_id <> p_deployment_id OR issuance_row.environment <> p_environment
     OR issuance_row.candidate_id <> p_candidate_id OR issuance_row.idempotency_key <> p_idempotency_key
  THEN RAISE EXCEPTION USING ERRCODE = 'unique_violation', MESSAGE = 'platform promotion identity conflicts with durable state'; END IF;

  statement_text := agentpass_platform_promotion_statement_canonical_json(
    issuance_row.promotion_id, issuance_row.deployment_id, issuance_row.environment, issuance_row.candidate_id,
    issuance_row.source_commit, issuance_row.source_tree, issuance_row.product_pkg_sha256,
    issuance_row.image_digest, issuance_row.sbom_sha256, issuance_row.qualification_report_digests,
    issuance_row.release_manifest_schema_version, issuance_row.release_manifest_sha256,
    issuance_row.approval_id, issuance_row.approval_digest, issuance_row.lifecycle_version,
    issuance_row.key_id, issuance_row.key_version, issuance_row.issued_at, issuance_row.expires_at
  );
  statement_json := statement_text::jsonb;
  expected_signing_bytes := convert_to('AgentPass-Promotion-Evidence-v3', 'UTF8') || decode('00', 'hex')
    || convert_to(statement_text, 'UTF8');
  expected_request_digest := agentpass_platform_promotion_request_digest(
    expected_signing_bytes, issuance_row.key_id, issuance_row.key_version,
    issuance_row.purpose, issuance_row.signing_version
  );
  expected_signature := rtrim(translate(replace(encode(p_signature, 'base64'), chr(10), ''), '+/', '-_'), '=');
  expected_fingerprint := 'SHA256:' || rtrim(translate(replace(encode(issuance_row.signer_key_fingerprint, 'base64'), chr(10), ''), '+/', '-_'), '=');
  expected_evidence_text :=
    '{"signature":' || to_json(expected_signature)::text ||
    ',"signature_algorithm":"ed25519"' ||
    ',"signer_key_fingerprint":' || to_json(expected_fingerprint)::text ||
    ',"statement":' || statement_text ||
    ',"statement_hash":' || to_json(encode(sha256(convert_to(statement_text, 'UTF8')), 'hex'))::text ||
    ',"type":"agentpass.promotion-evidence"' ||
    ',"version":3}';

  IF p_signing_bytes IS DISTINCT FROM expected_signing_bytes
     OR substring(p_signing_bytes FROM 1 FOR octet_length(convert_to('AgentPass-Promotion-Evidence-v3', 'UTF8')) + 1)
       IS DISTINCT FROM convert_to('AgentPass-Promotion-Evidence-v3', 'UTF8') || decode('00', 'hex')
     OR issuance_row.request_digest IS DISTINCT FROM expected_request_digest
     OR issuance_row.provider_operation_id <> 'managed-signer-v1-' || encode(expected_request_digest, 'hex')
  THEN RAISE EXCEPTION USING ERRCODE = 'integrity_constraint_violation', MESSAGE = 'platform promotion signing bytes binding is invalid'; END IF;

  BEGIN
    evidence_json := convert_from(p_evidence_bytes, 'UTF8')::jsonb;
  EXCEPTION WHEN OTHERS THEN
    RAISE EXCEPTION USING ERRCODE = 'invalid_text_representation', MESSAGE = 'platform promotion evidence is not canonical JSON';
  END;
  IF convert_to(expected_evidence_text, 'UTF8') IS DISTINCT FROM p_evidence_bytes
     OR jsonb_typeof(evidence_json) <> 'object'
     OR (SELECT count(*) FROM jsonb_object_keys(evidence_json)) <> 7
     OR NOT evidence_json ?& ARRAY['version','type','statement','statement_hash','signature_algorithm','signer_key_fingerprint','signature']
     OR evidence_json->'statement' IS DISTINCT FROM statement_json
     OR evidence_json->>'version' <> '3'
     OR evidence_json->>'type' <> 'agentpass.promotion-evidence'
     OR evidence_json->>'signature_algorithm' <> 'ed25519'
     OR evidence_json->>'statement_hash' <> encode(sha256(convert_to(statement_text, 'UTF8')), 'hex')
     OR evidence_json->>'signer_key_fingerprint' <> expected_fingerprint
     OR evidence_json->>'signature' <> expected_signature
  THEN RAISE EXCEPTION USING ERRCODE = 'integrity_constraint_violation', MESSAGE = 'platform promotion evidence envelope binding is invalid'; END IF;

  SELECT lifecycle.version, key.key_id, key.key_version, key.public_key_fingerprint
  INTO key_row
  FROM managed_signer_key_lifecycles lifecycle
  JOIN managed_signer_keys key
    ON key.purpose = lifecycle.purpose AND key.key_id = issuance_row.key_id
   AND key.key_version = issuance_row.key_version AND key.state = 'active'
   AND key.state_version = lifecycle.version
  WHERE lifecycle.purpose = issuance_row.purpose AND lifecycle.algorithm = 'ed25519'
    AND lifecycle.version = issuance_row.lifecycle_version
  FOR SHARE OF lifecycle, key;
  IF NOT FOUND OR key_row.public_key_fingerprint IS DISTINCT FROM issuance_row.signer_key_fingerprint
  THEN RAISE EXCEPTION USING ERRCODE = 'integrity_constraint_violation', MESSAGE = 'platform promotion public key fingerprint binding is invalid'; END IF;

  SELECT signing.status, signing.request_digest, signing.key_id, signing.key_version,
    signing.reserved_lifecycle_version, signing.signature
  INTO signer_row
  FROM managed_signer_signing_idempotency signing
  WHERE signing.purpose = issuance_row.purpose AND signing.operation_id = issuance_row.provider_operation_id
  FOR UPDATE;
  IF NOT FOUND OR signer_row.status <> 'committed'
     OR signer_row.request_digest IS DISTINCT FROM expected_request_digest
     OR signer_row.key_id <> issuance_row.key_id OR signer_row.key_version <> issuance_row.key_version
     OR signer_row.reserved_lifecycle_version <> issuance_row.lifecycle_version
     OR signer_row.signature IS DISTINCT FROM p_signature
  THEN RAISE EXCEPTION USING ERRCODE = 'integrity_constraint_violation', MESSAGE = 'platform promotion provider ledger binding is invalid'; END IF;

  SELECT provider.state, provider.algorithm, provider.bytes_length,
    provider.request_digest, provider.key_id, provider.key_version,
    provider.provider_started_at, provider.signature, provider.public_key_der,
    provider.provider_receipt_provider, provider.provider_receipt_id,
    provider.expires_at
  INTO provider_row
  FROM managed_signer_provider_operations provider
  WHERE provider.purpose = issuance_row.purpose
    AND provider.operation_id = issuance_row.provider_operation_id
  FOR UPDATE;
  IF NOT FOUND OR provider_row.state <> 'committed'
     OR provider_row.algorithm <> 'ed25519'
     OR provider_row.bytes_length <> octet_length(expected_signing_bytes)
     OR provider_row.request_digest IS DISTINCT FROM sha256(expected_signing_bytes)
     OR provider_row.key_id <> issuance_row.key_id
     OR provider_row.key_version <> issuance_row.key_version
     OR provider_row.provider_started_at IS NULL
     OR provider_row.signature IS DISTINCT FROM p_signature
     OR provider_row.public_key_der IS NULL
     OR sha256(provider_row.public_key_der) IS DISTINCT FROM issuance_row.signer_key_fingerprint
     OR provider_row.provider_receipt_provider IS NULL
     OR provider_row.provider_receipt_id IS NULL
     OR provider_row.expires_at <= clock_timestamp()
  THEN RAISE EXCEPTION USING ERRCODE = 'integrity_constraint_violation', MESSAGE = 'platform promotion durable provider operation binding is invalid'; END IF;

  IF issuance_row.state = 'committed' THEN
    IF issuance_row.evidence_digest IS DISTINCT FROM p_evidence_digest OR issuance_row.evidence_bytes IS DISTINCT FROM p_evidence_bytes
    THEN RAISE EXCEPTION USING ERRCODE = 'unique_violation', MESSAGE = 'platform promotion evidence conflicts with durable state'; END IF;
    RETURN agentpass_platform_promotion_issuance_result(issuance_row, false);
  END IF;
  IF issuance_row.state <> 'reserved' OR issuance_row.claim_token_digest IS DISTINCT FROM p_claim_token_digest
     OR issuance_row.claim_expires_at <= clock_timestamp() OR issuance_row.approval_expires_at <= clock_timestamp()
  THEN RAISE EXCEPTION USING ERRCODE = 'serialization_failure', MESSAGE = 'platform promotion claim is invalid or expired'; END IF;

  SELECT * INTO head_row FROM platform_promotion_deployments
  WHERE deployment_id = p_deployment_id AND environment = p_environment FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE = 'foreign_key_violation', MESSAGE = 'platform promotion deployment head is unavailable'; END IF;
  next_generation := head_row.current_generation + 1;
  UPDATE platform_promotion_issuances
  SET state = 'committed', evidence_bytes = p_evidence_bytes, evidence_digest = p_evidence_digest,
      deployment_generation = next_generation, claim_token_digest = NULL, claim_expires_at = NULL,
      uncertain_reason = NULL
  WHERE promotion_id = p_promotion_id AND state = 'reserved';
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE = 'serialization_failure', MESSAGE = 'platform promotion commit lost its claim'; END IF;
  UPDATE platform_promotion_deployments
  SET current_generation = next_generation, current_candidate_id = issuance_row.candidate_id
  WHERE deployment_id = p_deployment_id AND environment = p_environment
    AND current_generation = head_row.current_generation;
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE = 'serialization_failure', MESSAGE = 'platform promotion generation advance conflicted'; END IF;
  SELECT * INTO issuance_row FROM platform_promotion_issuances WHERE promotion_id = p_promotion_id FOR UPDATE;
  RETURN agentpass_platform_promotion_issuance_result(issuance_row, false);
END;
$$;

REVOKE ALL ON FUNCTION public.agentpass_platform_promotion_issuance_commit(
  uuid, text, text, text, text, bytea, bytea, bytea, bytea, bytea
) FROM PUBLIC;

COMMENT ON FUNCTION public.agentpass_platform_promotion_issuance_commit(
  uuid, text, text, text, text, bytea, bytea, bytea, bytea, bytea
) IS 'Commits Platform promotion evidence with purpose-separated signer-envelope and exact-provider-byte digests.';

COMMIT;
