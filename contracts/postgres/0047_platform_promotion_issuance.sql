BEGIN;

-- C3 promotion issuance is deployment-scoped authority.  Candidate and
-- qualification bytes are represented only by immutable digests; no private
-- signing material, bearer token, or provider diagnostic is persisted.
CREATE FUNCTION agentpass_promotion_digest_array_valid(p_value jsonb)
RETURNS boolean LANGUAGE plpgsql IMMUTABLE STRICT PARALLEL SAFE
SET search_path = pg_catalog AS $$
DECLARE
  raw jsonb;
  item text;
  seen text[] := ARRAY[]::text[];
BEGIN
  IF jsonb_typeof(p_value) <> 'array' OR jsonb_array_length(p_value) NOT BETWEEN 1 AND 16 THEN RETURN false; END IF;
  FOR raw IN SELECT jsonb_array_elements(p_value) LOOP
    IF jsonb_typeof(raw) <> 'string' THEN RETURN false; END IF;
    item := raw #>> '{}';
    IF item !~ '^[0-9a-f]{64}$' OR item = ANY(seen) THEN RETURN false; END IF;
    seen := array_append(seen, item);
  END LOOP;
  RETURN true;
END;
$$;

-- Bind every copied approval identity field to the exact immutable approval
-- row.  approval_id alone would allow a direct SQL writer to mix an approval
-- from one deployment with authority bytes from another deployment.
CREATE UNIQUE INDEX platform_promotion_approvals_issuance_binding
  ON platform_promotion_approvals (
    approval_id,
    deployment_id,
    environment,
    candidate_id,
    source_commit,
    source_tree,
    product_pkg_sha256,
    release_manifest_sha256,
    sbom_sha256,
    image_digest,
    record_digest
  );

CREATE TABLE platform_promotion_issuances (
  deployment_id text NOT NULL
    CHECK (octet_length(deployment_id) BETWEEN 1 AND 255
      AND deployment_id ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]{0,254}$'),
  environment text NOT NULL CHECK (environment IN ('staging', 'production')),
  promotion_id uuid NOT NULL,
  idempotency_key text NOT NULL
    CHECK (octet_length(idempotency_key) BETWEEN 8 AND 255
      AND idempotency_key ~ '^[A-Za-z0-9][A-Za-z0-9._~:-]{7,254}$'),
  candidate_id text NOT NULL
    CHECK (candidate_id ~ '^release-pkg-sha256-v1-[0-9a-f]{64}$'),
  source_commit text NOT NULL CHECK (source_commit ~ '^[0-9a-f]{40}$'),
  source_tree text NOT NULL CHECK (source_tree ~ '^[0-9a-f]{40}$'),
  product_pkg_sha256 text NOT NULL CHECK (product_pkg_sha256 ~ '^[0-9a-f]{64}$'),
  release_manifest_sha256 text NOT NULL CHECK (release_manifest_sha256 ~ '^[0-9a-f]{64}$'),
  sbom_sha256 text NOT NULL CHECK (sbom_sha256 ~ '^[0-9a-f]{64}$'),
  image_digest text NOT NULL CHECK (image_digest ~ '^sha256:[0-9a-f]{64}$'),
  qualification_report_digests jsonb NOT NULL CHECK (agentpass_promotion_digest_array_valid(qualification_report_digests)),
  approval_id uuid NOT NULL REFERENCES platform_promotion_approvals(approval_id),
  approval_digest text NOT NULL CHECK (approval_digest ~ '^[0-9a-f]{64}$'),
  signer_key_id text NOT NULL CHECK (signer_key_id ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$'),
  signer_key_version bigint NOT NULL CHECK (signer_key_version BETWEEN 1 AND 9007199254740991),
  signer_lifecycle_version bigint NOT NULL CHECK (signer_lifecycle_version BETWEEN 1 AND 9007199254740991),
  expected_deployment_generation bigint NOT NULL CHECK (expected_deployment_generation BETWEEN 0 AND 9007199254740991),
  state text NOT NULL CHECK (state IN ('reserved', 'committed', 'uncertain', 'rejected')),
  claim_token_digest bytea CHECK (claim_token_digest IS NULL OR octet_length(claim_token_digest) = 32),
  claim_expires_at timestamptz,
  provider_operation_id text CHECK (provider_operation_id IS NULL OR provider_operation_id ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$'),
  provider_operation_purpose text GENERATED ALWAYS AS (
    CASE WHEN provider_operation_id IS NULL THEN NULL ELSE 'agentpass.promotion-evidence' END
  ) STORED,
  uncertain_reason text CHECK (uncertain_reason IS NULL OR uncertain_reason IN ('signer_failure', 'provider_response_loss', 'commit_failure')),
  evidence jsonb,
  rejection_reason text CHECK (rejection_reason IS NULL OR rejection_reason IN ('approval_expired', 'digest_mismatch', 'disabled', 'operator_rejected')),
  authority_digest bytea NOT NULL CHECK (octet_length(authority_digest) = 32),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (deployment_id, environment, promotion_id),
  UNIQUE (deployment_id, environment, idempotency_key),
  FOREIGN KEY (
    approval_id, deployment_id, environment, candidate_id, source_commit,
    source_tree, product_pkg_sha256, release_manifest_sha256, sbom_sha256,
    image_digest, approval_digest
  ) REFERENCES platform_promotion_approvals (
    approval_id, deployment_id, environment, candidate_id, source_commit,
    source_tree, product_pkg_sha256, release_manifest_sha256, sbom_sha256,
    image_digest, record_digest
  ),
  FOREIGN KEY (provider_operation_purpose, provider_operation_id)
    REFERENCES managed_signer_provider_operations (purpose, operation_id),
  CHECK (updated_at >= created_at),
  CHECK ((state = 'reserved' AND provider_operation_id IS NOT NULL AND claim_token_digest IS NOT NULL AND claim_expires_at IS NOT NULL AND claim_expires_at > created_at AND uncertain_reason IS NULL AND evidence IS NULL AND rejection_reason IS NULL)
    OR (state = 'uncertain' AND claim_token_digest IS NULL AND claim_expires_at IS NULL AND provider_operation_id IS NOT NULL AND uncertain_reason IS NOT NULL AND evidence IS NULL AND rejection_reason IS NULL)
    OR (state = 'committed' AND claim_token_digest IS NULL AND claim_expires_at IS NULL AND provider_operation_id IS NOT NULL AND uncertain_reason IS NULL AND evidence IS NOT NULL AND rejection_reason IS NULL)
    OR (state = 'rejected' AND claim_token_digest IS NULL AND claim_expires_at IS NULL AND uncertain_reason IS NULL AND evidence IS NULL AND rejection_reason IS NOT NULL)),
  CHECK (evidence IS NULL OR (jsonb_typeof(evidence) = 'object' AND evidence ? 'signature' AND evidence ? 'statement'
    AND evidence->>'signature' ~ '^[A-Za-z0-9_-]{86}$'
    AND evidence::text !~* '(private[[:space:]_-]*key|clear[[:space:]_-]*claim|claim[[:space:]_-]*token|provider[[:space:]_-]*(diagnostic|response|credential))'))
);

-- One unresolved promotion may own a deployment/environment.  A second
-- request cannot race a reserved or uncertain authority into another signer
-- operation.
CREATE UNIQUE INDEX platform_promotion_issuances_one_open
  ON platform_promotion_issuances (deployment_id, environment)
  WHERE state IN ('reserved', 'uncertain');

CREATE INDEX platform_promotion_issuances_claims
  ON platform_promotion_issuances (claim_expires_at, deployment_id, environment)
  WHERE state = 'reserved';

-- Keep the database-side digest preimages aligned with the protocol's
-- canonicalJson() encoding.  jsonb::text is not used for the object itself:
-- jsonb does not make the protocol's key-ordering and scalar encoding an
-- explicit contract.  The recursive helper makes object keys and array
-- elements deterministic before the security-boundary hashes below are
-- checked by the triggers.
CREATE FUNCTION agentpass_platform_promotion_json_canonical(p_value jsonb)
RETURNS text LANGUAGE plpgsql IMMUTABLE STRICT PARALLEL SAFE
SET search_path = pg_catalog AS $$
DECLARE
  result text;
BEGIN
  CASE jsonb_typeof(p_value)
    WHEN 'null' THEN RETURN 'null';
    WHEN 'string' THEN RETURN to_json(p_value #>> '{}')::text;
    WHEN 'boolean' THEN RETURN p_value::text;
    WHEN 'number' THEN RETURN p_value::text;
    WHEN 'array' THEN
      SELECT '[' || COALESCE(string_agg(
        agentpass_platform_promotion_json_canonical(value), ',' ORDER BY ordinality
      ), '') || ']'
      INTO result
      FROM jsonb_array_elements(p_value) WITH ORDINALITY AS entry(value, ordinality);
      RETURN result;
    WHEN 'object' THEN
      SELECT '{' || COALESCE(string_agg(
        to_json(key)::text || ':' || agentpass_platform_promotion_json_canonical(value),
        ',' ORDER BY key
      ), '') || '}'
      INTO result
      FROM jsonb_each(p_value) AS entry(key, value);
      RETURN result;
    ELSE
      RAISE EXCEPTION USING ERRCODE = 'check_violation',
        CONSTRAINT = 'platform_promotion_json_canonical_type',
        MESSAGE = 'unsupported JSON value in platform promotion digest preimage';
  END CASE;
END;
$$;

-- This is the exact authority object hashed by the repository before it is
-- supplied as authority_digest.  Keep the argument list explicit so a direct
-- SQL writer cannot omit or silently reorder a security-relevant field.
CREATE FUNCTION agentpass_platform_promotion_authority_digest(
  p_deployment_id text,
  p_environment text,
  p_promotion_id uuid,
  p_idempotency_key text,
  p_candidate_id text,
  p_source_commit text,
  p_source_tree text,
  p_product_pkg_sha256 text,
  p_release_manifest_sha256 text,
  p_sbom_sha256 text,
  p_image_digest text,
  p_qualification_report_digests text[],
  p_approval_id uuid,
  p_approval_digest text,
  p_signer_key_id text,
  p_signer_key_version bigint,
  p_signer_lifecycle_version bigint,
  p_expected_deployment_generation bigint
)
RETURNS bytea LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
SET search_path = pg_catalog, public AS $$
  SELECT sha256(convert_to(
    agentpass_platform_promotion_json_canonical(jsonb_build_object(
      'approval_digest', p_approval_digest,
      'approval_id', p_approval_id::text,
      'candidate_id', p_candidate_id,
      'deployment_id', p_deployment_id,
      'environment', p_environment,
      'expected_deployment_generation', p_expected_deployment_generation,
      'idempotency_key', p_idempotency_key,
      'image_digest', p_image_digest,
      'product_pkg_sha256', p_product_pkg_sha256,
      'promotion_id', p_promotion_id::text,
      'qualification_report_digests', p_qualification_report_digests,
      'release_manifest_sha256', p_release_manifest_sha256,
      'sbom_sha256', p_sbom_sha256,
      'signer_key_id', p_signer_key_id,
      'signer_key_version', p_signer_key_version,
      'signer_lifecycle_version', p_signer_lifecycle_version,
      'source_commit', p_source_commit,
      'source_tree', p_source_tree
    )),
    'UTF8'
  ));
$$;

CREATE TABLE platform_deployment_state (
  deployment_id text NOT NULL,
  environment text NOT NULL CHECK (environment IN ('staging', 'production')),
  generation bigint NOT NULL CHECK (generation BETWEEN 0 AND 9007199254740991),
  state text NOT NULL CHECK (state IN ('idle', 'promoted', 'disabled')),
  promotion_id uuid,
  evidence_digest bytea CHECK (evidence_digest IS NULL OR octet_length(evidence_digest) = 32),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (deployment_id, environment),
  FOREIGN KEY (deployment_id, environment, promotion_id)
    REFERENCES platform_promotion_issuances (deployment_id, environment, promotion_id),
  CHECK ((state = 'idle' AND generation = 0 AND promotion_id IS NULL AND evidence_digest IS NULL)
    OR (state IN ('promoted', 'disabled') AND promotion_id IS NOT NULL))
);

CREATE FUNCTION agentpass_guard_platform_promotion_issuance()
RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
DECLARE
  approval_qualification_report_digests text[];
  approval_expires_at timestamptz;
  authority_qualification_report_digests text[];
  current_deployment_generation bigint;
  current_deployment_state text;
  provider_key_id text;
  provider_key_version bigint;
  provider_state text;
  provider_expires_at timestamptz;
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION USING ERRCODE = 'check_violation', CONSTRAINT = 'platform_promotion_issuances_append_only', MESSAGE = 'promotion issuances are append-only';
  END IF;

  -- Every issuance must enter through the claim state.  Allowing a direct
  -- committed/uncertain/rejected INSERT would bypass claim ownership and
  -- make replay a database-valid operation.
  IF TG_OP = 'INSERT' AND NEW.state <> 'reserved' THEN
    RAISE EXCEPTION USING ERRCODE = 'check_violation', CONSTRAINT = 'platform_promotion_issuances_initial_state', MESSAGE = 'promotion issuances must be inserted as reserved';
  END IF;

  -- Serialize the deployment lane for direct SQL callers as well as the
  -- repository.  A stale expected generation must not be able to reserve a
  -- second promotion after a prior commit.
  PERFORM pg_advisory_xact_lock(hashtextextended(
    format('agentpass:promotion:%s:%s', NEW.deployment_id, NEW.environment), 0
  ));
  SELECT generation, state
  INTO current_deployment_generation, current_deployment_state
  FROM platform_deployment_state
  WHERE deployment_id = NEW.deployment_id AND environment = NEW.environment
  FOR UPDATE;
  IF COALESCE(current_deployment_generation, 0) IS DISTINCT FROM NEW.expected_deployment_generation
     OR current_deployment_state = 'disabled'
  THEN
    RAISE EXCEPTION USING ERRCODE = 'check_violation', CONSTRAINT = 'platform_promotion_issuances_generation_fence', MESSAGE = 'promotion issuance generation is stale or disabled';
  END IF;

  SELECT array_agg(value ORDER BY ordinality)
  INTO authority_qualification_report_digests
  FROM jsonb_array_elements_text(NEW.qualification_report_digests)
    WITH ORDINALITY AS digest(value, ordinality);
  IF NEW.authority_digest IS DISTINCT FROM agentpass_platform_promotion_authority_digest(
    NEW.deployment_id,
    NEW.environment,
    NEW.promotion_id,
    NEW.idempotency_key,
    NEW.candidate_id,
    NEW.source_commit,
    NEW.source_tree,
    NEW.product_pkg_sha256,
    NEW.release_manifest_sha256,
    NEW.sbom_sha256,
    NEW.image_digest,
    authority_qualification_report_digests,
    NEW.approval_id,
    NEW.approval_digest,
    NEW.signer_key_id,
    NEW.signer_key_version,
    NEW.signer_lifecycle_version,
    NEW.expected_deployment_generation
  ) THEN
    RAISE EXCEPTION USING ERRCODE = 'check_violation',
      CONSTRAINT = 'platform_promotion_issuances_authority_digest',
      MESSAGE = 'promotion authority digest does not match the immutable authority fields';
  END IF;

  -- The composite FK binds scalar authority fields.  Keep the JSONB digest
  -- array under the same exact-row binding as well.
  SELECT qualification_report_digests, expires_at
  INTO approval_qualification_report_digests, approval_expires_at
  FROM platform_promotion_approvals
  WHERE approval_id = NEW.approval_id;
  IF NOT FOUND
     OR NEW.qualification_report_digests IS DISTINCT FROM to_jsonb(approval_qualification_report_digests)
  THEN
    RAISE EXCEPTION USING ERRCODE = 'foreign_key_violation', CONSTRAINT = 'platform_promotion_issuances_approval_binding', MESSAGE = 'promotion issuance is not bound to the exact approval authority';
  END IF;

  -- A row cannot be reserved from an already expired approval, and a
  -- committed row cannot cross either the approval or provider clock fence.
  IF (TG_OP = 'INSERT' AND NEW.state = 'reserved' AND approval_expires_at <= clock_timestamp())
     OR (NEW.state = 'committed' AND approval_expires_at <= clock_timestamp())
  THEN
    RAISE EXCEPTION USING ERRCODE = 'check_violation', CONSTRAINT = 'platform_promotion_issuances_approval_clock_fence', MESSAGE = 'promotion approval is expired';
  END IF;

  IF NEW.provider_operation_id IS NOT NULL THEN
    SELECT key_id, key_version, state, expires_at
    INTO provider_key_id, provider_key_version, provider_state, provider_expires_at
    FROM managed_signer_provider_operations
    WHERE purpose = 'agentpass.promotion-evidence'
      AND operation_id = NEW.provider_operation_id;
    IF NOT FOUND
       OR provider_key_id IS DISTINCT FROM NEW.signer_key_id
       OR provider_key_version IS DISTINCT FROM NEW.signer_key_version
    THEN
      RAISE EXCEPTION USING ERRCODE = 'foreign_key_violation', CONSTRAINT = 'platform_promotion_issuances_provider_operation_binding', MESSAGE = 'promotion issuance is not bound to the configured provider operation';
    END IF;
    IF NEW.state = 'committed'
       AND (provider_state <> 'committed' OR provider_expires_at <= clock_timestamp())
    THEN
      RAISE EXCEPTION USING ERRCODE = 'check_violation', CONSTRAINT = 'platform_promotion_issuances_provider_clock_fence', MESSAGE = 'provider operation is not a current committed operation';
    END IF;
  END IF;

  -- SQL writers must not be able to mark arbitrary evidence as committed.
  -- Signature cryptography remains the verifier's responsibility, but the
  -- signed statement identity is a database invariant too.
  IF NEW.state = 'committed'
     AND (NEW.evidence->'statement'->>'promotion_id' IS DISTINCT FROM NEW.promotion_id::text
       OR NEW.evidence->'statement'->>'deployment_id' IS DISTINCT FROM NEW.deployment_id
       OR NEW.evidence->'statement'->>'environment' IS DISTINCT FROM NEW.environment
       OR NEW.evidence->'statement'->>'candidate_id' IS DISTINCT FROM NEW.candidate_id
       OR NEW.evidence->'statement'->>'source_commit' IS DISTINCT FROM NEW.source_commit
       OR NEW.evidence->'statement'->>'source_tree' IS DISTINCT FROM NEW.source_tree
       OR NEW.evidence->'statement'->>'product_pkg_sha256' IS DISTINCT FROM NEW.product_pkg_sha256
       OR NEW.evidence->'statement'->>'image_digest' IS DISTINCT FROM NEW.image_digest
       OR NEW.evidence->'statement'->>'sbom_sha256' IS DISTINCT FROM NEW.sbom_sha256
       OR NEW.evidence->'statement'->'qualification_report_digests' IS DISTINCT FROM NEW.qualification_report_digests
       OR NEW.evidence->'statement'->>'release_manifest_sha256' IS DISTINCT FROM NEW.release_manifest_sha256
       OR NEW.evidence->'statement'->>'platform_approval_id' IS DISTINCT FROM NEW.approval_id::text
       OR NEW.evidence->'statement'->>'platform_approval_digest' IS DISTINCT FROM NEW.approval_digest
       OR NEW.evidence->'statement'->>'key_id' IS DISTINCT FROM NEW.signer_key_id
       OR NEW.evidence->'statement'->>'key_version' IS DISTINCT FROM NEW.signer_key_version::text
       OR NEW.evidence->'statement'->>'lifecycle_version' IS DISTINCT FROM NEW.signer_lifecycle_version::text)
  THEN
    RAISE EXCEPTION USING ERRCODE = 'check_violation', CONSTRAINT = 'platform_promotion_issuances_evidence_binding', MESSAGE = 'promotion evidence is not bound to the issuance authority';
  END IF;

  IF TG_OP = 'UPDATE' THEN
    IF NEW.deployment_id IS DISTINCT FROM OLD.deployment_id OR NEW.environment IS DISTINCT FROM OLD.environment
      OR NEW.promotion_id IS DISTINCT FROM OLD.promotion_id OR NEW.idempotency_key IS DISTINCT FROM OLD.idempotency_key
      OR NEW.candidate_id IS DISTINCT FROM OLD.candidate_id OR NEW.source_commit IS DISTINCT FROM OLD.source_commit
      OR NEW.source_tree IS DISTINCT FROM OLD.source_tree OR NEW.product_pkg_sha256 IS DISTINCT FROM OLD.product_pkg_sha256
      OR NEW.release_manifest_sha256 IS DISTINCT FROM OLD.release_manifest_sha256 OR NEW.sbom_sha256 IS DISTINCT FROM OLD.sbom_sha256
      OR NEW.image_digest IS DISTINCT FROM OLD.image_digest OR NEW.qualification_report_digests IS DISTINCT FROM OLD.qualification_report_digests
      OR NEW.approval_id IS DISTINCT FROM OLD.approval_id OR NEW.approval_digest IS DISTINCT FROM OLD.approval_digest
      OR NEW.signer_key_id IS DISTINCT FROM OLD.signer_key_id OR NEW.signer_key_version IS DISTINCT FROM OLD.signer_key_version
      OR NEW.signer_lifecycle_version IS DISTINCT FROM OLD.signer_lifecycle_version
      OR NEW.expected_deployment_generation IS DISTINCT FROM OLD.expected_deployment_generation
      OR NEW.authority_digest IS DISTINCT FROM OLD.authority_digest OR NEW.created_at IS DISTINCT FROM OLD.created_at
    THEN RAISE EXCEPTION USING ERRCODE = 'check_violation', CONSTRAINT = 'platform_promotion_issuances_immutable_authority', MESSAGE = 'promotion authority is immutable'; END IF;
    IF OLD.provider_operation_id IS NOT NULL AND NEW.provider_operation_id IS DISTINCT FROM OLD.provider_operation_id
    THEN RAISE EXCEPTION USING ERRCODE = 'check_violation', CONSTRAINT = 'platform_promotion_issuances_provider_operation_immutable', MESSAGE = 'provider operation binding is immutable'; END IF;
    IF OLD.state IN ('committed', 'rejected') AND NEW IS DISTINCT FROM OLD
    THEN RAISE EXCEPTION USING ERRCODE = 'check_violation', CONSTRAINT = 'platform_promotion_issuances_terminal_immutable', MESSAGE = 'terminal promotion issuance is immutable'; END IF;
    IF (OLD.state, NEW.state) NOT IN (('reserved','committed'), ('reserved','uncertain'), ('reserved','rejected'), ('uncertain','committed'), ('uncertain','rejected'))
    THEN RAISE EXCEPTION USING ERRCODE = 'check_violation', CONSTRAINT = 'platform_promotion_issuances_transition', MESSAGE = 'invalid promotion state transition'; END IF;
    IF OLD.state = 'reserved' AND NEW.state IN ('committed', 'uncertain', 'rejected')
       AND (OLD.claim_expires_at IS NULL OR OLD.claim_expires_at <= clock_timestamp())
    THEN RAISE EXCEPTION USING ERRCODE = 'check_violation', CONSTRAINT = 'platform_promotion_issuances_claim_clock_fence', MESSAGE = 'promotion claim is expired'; END IF;
    NEW.updated_at := clock_timestamp();
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER platform_promotion_issuances_guard
  BEFORE INSERT OR UPDATE OR DELETE ON platform_promotion_issuances
  FOR EACH ROW EXECUTE FUNCTION agentpass_guard_platform_promotion_issuance();

CREATE FUNCTION agentpass_guard_platform_deployment_generation()
RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
DECLARE
  issuance_state text;
  issuance_expected_generation bigint;
  issuance_evidence_digest bytea;
BEGIN
  PERFORM pg_advisory_xact_lock(hashtextextended(
    format('agentpass:promotion:%s:%s', NEW.deployment_id, NEW.environment), 0
  ));
  IF TG_OP = 'UPDATE' AND NEW.generation < OLD.generation THEN
    RAISE EXCEPTION USING ERRCODE = 'check_violation', CONSTRAINT = 'platform_deployment_generation_monotonic', MESSAGE = 'deployment generation cannot decrease';
  END IF;
  IF TG_OP = 'UPDATE' AND NEW.generation > OLD.generation
     AND NEW.generation <> OLD.generation + 1
  THEN
    RAISE EXCEPTION USING ERRCODE = 'check_violation', CONSTRAINT = 'platform_deployment_generation_step', MESSAGE = 'deployment generation must advance by one';
  END IF;
  IF TG_OP = 'UPDATE' AND NEW.generation = OLD.generation
     AND NEW.promotion_id IS DISTINCT FROM OLD.promotion_id
  THEN
    RAISE EXCEPTION USING ERRCODE = 'check_violation', CONSTRAINT = 'platform_deployment_promotion_generation_binding', MESSAGE = 'promotion cannot change without advancing deployment generation';
  END IF;
  IF TG_OP = 'UPDATE' AND OLD.state <> 'idle' AND NEW.state = 'idle' THEN
    RAISE EXCEPTION USING ERRCODE = 'check_violation', CONSTRAINT = 'platform_deployment_state_rollback', MESSAGE = 'deployment state cannot roll back to idle';
  END IF;
  IF TG_OP = 'UPDATE' AND OLD.state = 'disabled' AND NEW IS DISTINCT FROM OLD THEN
    RAISE EXCEPTION USING ERRCODE = 'check_violation', CONSTRAINT = 'platform_deployment_disabled_immutable', MESSAGE = 'disabled deployment state is terminal';
  END IF;
  IF NEW.state IN ('promoted', 'disabled') THEN
    SELECT state, expected_deployment_generation,
           sha256(convert_to(agentpass_platform_promotion_json_canonical(evidence), 'UTF8'))
    INTO issuance_state, issuance_expected_generation, issuance_evidence_digest
    FROM platform_promotion_issuances
    WHERE deployment_id = NEW.deployment_id
      AND environment = NEW.environment
      AND promotion_id = NEW.promotion_id
    FOR UPDATE;
    IF issuance_state IS DISTINCT FROM 'committed'
       OR NEW.generation <> issuance_expected_generation + 1
       OR NEW.evidence_digest IS DISTINCT FROM issuance_evidence_digest
    THEN
      RAISE EXCEPTION USING ERRCODE = 'foreign_key_violation', CONSTRAINT = 'platform_deployment_state_committed_issuance_fk', MESSAGE = 'deployment state must reference a committed promotion issuance';
    END IF;
  END IF;
  IF TG_OP = 'UPDATE' THEN NEW.updated_at := clock_timestamp(); END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER platform_deployment_generation_guard
  BEFORE INSERT OR UPDATE ON platform_deployment_state
  FOR EACH ROW EXECUTE FUNCTION agentpass_guard_platform_deployment_generation();

-- Platform decisions are security events, not best-effort application logs.
-- Keep the record secret-free and append-only so a successful promotion can
-- never be reported without a durable audit fact.
CREATE FUNCTION agentpass_platform_promotion_audit_event_hash(
  p_request_id uuid,
  p_event_type text,
  p_actor_id text,
  p_platform_role text,
  p_target_type text,
  p_target_id uuid,
  p_idempotency_key text,
  p_details jsonb
)
RETURNS bytea LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
SET search_path = pg_catalog, public AS $$
  SELECT sha256(convert_to(
    agentpass_platform_promotion_json_canonical(jsonb_build_object(
      'actor_id', p_actor_id,
      'details', p_details,
      'event_type', p_event_type,
      'idempotency_key', p_idempotency_key,
      'kind', 'agentpass.platform-promotion-audit.v1',
      'platform_role', p_platform_role,
      'request_id', p_request_id::text,
      'target_id', p_target_id::text,
      'target_type', p_target_type
    )),
    'UTF8'
  ));
$$;

-- The application repository rejects sensitive audit keys, but the database
-- is also a security boundary. Keep the invariant true for migration,
-- backup, and emergency SQL writers by recursively rejecting secret-shaped
-- field names and obvious credential/private-material values.
CREATE FUNCTION agentpass_platform_promotion_audit_details_safe(p_value jsonb)
RETURNS boolean LANGUAGE plpgsql IMMUTABLE STRICT PARALLEL SAFE
SET search_path = pg_catalog AS $$
DECLARE
  item jsonb;
  key text;
  text_value text;
BEGIN
  CASE jsonb_typeof(p_value)
    WHEN 'object' THEN
      FOR key, item IN SELECT k, v FROM jsonb_each(p_value) AS entry(k, v) LOOP
        IF key ~* '(^|_)(authorization|bearer|cookie|credential|csrf|nonce|password|private|secret|session|signature|token)(_|$)'
          OR NOT agentpass_platform_promotion_audit_details_safe(item)
        THEN RETURN false; END IF;
      END LOOP;
      RETURN true;
    WHEN 'array' THEN
      FOR item IN SELECT value FROM jsonb_array_elements(p_value) LOOP
        IF NOT agentpass_platform_promotion_audit_details_safe(item) THEN RETURN false; END IF;
      END LOOP;
      RETURN true;
    WHEN 'string' THEN
      text_value := p_value #>> '{}';
      RETURN text_value !~* '(BEGIN[[:space:]-]+(RSA|EC|OPENSSH|PRIVATE)[[:space:]-]+KEY|(^|[[:space:]])bearer[[:space:]]+[A-Za-z0-9._~+/=-]{16,}|(^|[[:space:]])eyJ[A-Za-z0-9_-]{20,}[.]|-----BEGIN)';
    ELSE
      RETURN true;
  END CASE;
END;
$$;

CREATE TABLE platform_promotion_audit_events (
  event_id uuid PRIMARY KEY,
  request_id uuid NOT NULL,
  event_type text NOT NULL CHECK (event_type ~ '^platform[.]promotion[.][a-z_]+[.][a-z_]+$'),
  actor_id text NOT NULL CHECK (actor_id <> '' AND length(actor_id) <= 255),
  platform_role text NOT NULL CHECK (platform_role IN ('platform_admin', 'platform_operator', 'platform_auditor')),
  target_type text NOT NULL CHECK (target_type = 'platform_promotion'),
  target_id uuid NOT NULL,
  idempotency_key text NOT NULL UNIQUE CHECK (idempotency_key ~ '^[A-Za-z0-9][A-Za-z0-9._~:-]{7,254}$'),
  details jsonb NOT NULL CHECK (jsonb_typeof(details) = 'object' AND octet_length(details::text) <= 128 * 1024 AND agentpass_platform_promotion_audit_details_safe(details)),
  event_hash bytea NOT NULL CHECK (octet_length(event_hash) = 32),
  recorded_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE FUNCTION agentpass_guard_platform_promotion_audit_event()
RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    IF NEW.event_hash IS DISTINCT FROM agentpass_platform_promotion_audit_event_hash(
      NEW.request_id,
      NEW.event_type,
      NEW.actor_id,
      NEW.platform_role,
      NEW.target_type,
      NEW.target_id,
      NEW.idempotency_key,
      NEW.details
    ) THEN
      RAISE EXCEPTION USING ERRCODE = 'check_violation',
        CONSTRAINT = 'platform_promotion_audit_events_event_hash',
        MESSAGE = 'platform promotion audit event hash does not match its immutable event fields';
    END IF;
    RETURN NEW;
  END IF;

  IF TG_OP <> 'INSERT' THEN
    RAISE EXCEPTION USING ERRCODE = 'check_violation', CONSTRAINT = 'platform_promotion_audit_events_append_only', MESSAGE = 'platform promotion audit events are append-only';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER platform_promotion_audit_events_guard
  BEFORE INSERT OR UPDATE OR DELETE ON platform_promotion_audit_events
  FOR EACH ROW EXECUTE FUNCTION agentpass_guard_platform_promotion_audit_event();

-- TRUNCATE is statement-level and therefore needs its own trigger.  The
-- trigger protects even the table owner during ordinary maintenance sessions;
-- only an explicitly privileged owner-level DDL operation can remove it.
CREATE TRIGGER platform_promotion_audit_events_truncate_guard
  BEFORE TRUNCATE ON platform_promotion_audit_events
  FOR EACH STATEMENT EXECUTE FUNCTION agentpass_guard_platform_promotion_audit_event();

-- Keep the ordinary runtime and backup roles from reaching TRUNCATE through
-- ACLs as well as through the append-only trigger.
REVOKE TRUNCATE ON TABLE platform_promotion_audit_events FROM agentpass_app, agentpass_backup;

-- Do not rely on roles.sql being reapplied after this migration.  These are
-- the effective table ACLs for the three service identities, including the
-- negative write/DDL privileges that a future default-privilege change must
-- not accidentally reintroduce.
REVOKE ALL PRIVILEGES ON TABLE
  platform_promotion_approvals,
  platform_promotion_issuances,
  platform_deployment_state,
  platform_promotion_audit_events
FROM PUBLIC, agentpass_app, agentpass_backup;
GRANT SELECT ON TABLE platform_promotion_approvals,
  platform_promotion_issuances,
  platform_deployment_state,
  platform_promotion_audit_events TO agentpass_app, agentpass_backup;
GRANT INSERT, UPDATE ON TABLE platform_promotion_issuances, platform_deployment_state TO agentpass_app;
GRANT INSERT ON TABLE platform_promotion_audit_events TO agentpass_app;
GRANT ALL PRIVILEGES ON TABLE
  platform_promotion_approvals,
  platform_promotion_issuances,
  platform_deployment_state,
  platform_promotion_audit_events TO agentpass_migrator;

-- Platform promotion authority is deployment-scoped, not tenant-scoped.  The
-- runtime role may read approvals and execute the issuance state machine, but
-- it cannot write approvals or delete any authority row.  FORCE RLS also
-- subjects the migration owner to an explicit policy instead of silently
-- treating table ownership as an application bypass.
ALTER TABLE platform_promotion_approvals ENABLE ROW LEVEL SECURITY;
ALTER TABLE platform_promotion_approvals FORCE ROW LEVEL SECURITY;
CREATE POLICY platform_promotion_approvals_runtime_select
  ON platform_promotion_approvals FOR SELECT TO agentpass_app
  USING (current_user = 'agentpass_app');
CREATE POLICY platform_promotion_approvals_backup_select
  ON platform_promotion_approvals FOR SELECT TO agentpass_backup
  USING (current_user = 'agentpass_backup');
CREATE POLICY platform_promotion_approvals_migration_all
  ON platform_promotion_approvals TO agentpass_migrator
  USING (true) WITH CHECK (true);

ALTER TABLE platform_promotion_issuances ENABLE ROW LEVEL SECURITY;
ALTER TABLE platform_promotion_issuances FORCE ROW LEVEL SECURITY;
CREATE POLICY platform_promotion_issuances_runtime_select
  ON platform_promotion_issuances FOR SELECT TO agentpass_app
  USING (current_user = 'agentpass_app');
CREATE POLICY platform_promotion_issuances_runtime_insert
  ON platform_promotion_issuances FOR INSERT TO agentpass_app
  WITH CHECK (current_user = 'agentpass_app');
CREATE POLICY platform_promotion_issuances_runtime_update
  ON platform_promotion_issuances FOR UPDATE TO agentpass_app
  USING (current_user = 'agentpass_app')
  WITH CHECK (current_user = 'agentpass_app');
CREATE POLICY platform_promotion_issuances_backup_select
  ON platform_promotion_issuances FOR SELECT TO agentpass_backup
  USING (current_user = 'agentpass_backup');
CREATE POLICY platform_promotion_issuances_migration_all
  ON platform_promotion_issuances TO agentpass_migrator
  USING (true) WITH CHECK (true);

ALTER TABLE platform_deployment_state ENABLE ROW LEVEL SECURITY;
ALTER TABLE platform_deployment_state FORCE ROW LEVEL SECURITY;
CREATE POLICY platform_deployment_state_runtime_select
  ON platform_deployment_state FOR SELECT TO agentpass_app
  USING (current_user = 'agentpass_app');
CREATE POLICY platform_deployment_state_runtime_insert
  ON platform_deployment_state FOR INSERT TO agentpass_app
  WITH CHECK (current_user = 'agentpass_app');
CREATE POLICY platform_deployment_state_runtime_update
  ON platform_deployment_state FOR UPDATE TO agentpass_app
  USING (current_user = 'agentpass_app')
  WITH CHECK (current_user = 'agentpass_app');
CREATE POLICY platform_deployment_state_backup_select
  ON platform_deployment_state FOR SELECT TO agentpass_backup
  USING (current_user = 'agentpass_backup');
CREATE POLICY platform_deployment_state_migration_all
  ON platform_deployment_state TO agentpass_migrator
  USING (true) WITH CHECK (true);

ALTER TABLE platform_promotion_audit_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE platform_promotion_audit_events FORCE ROW LEVEL SECURITY;
CREATE POLICY platform_promotion_audit_events_runtime_select
  ON platform_promotion_audit_events FOR SELECT TO agentpass_app
  USING (current_user = 'agentpass_app');
CREATE POLICY platform_promotion_audit_events_runtime_insert
  ON platform_promotion_audit_events FOR INSERT TO agentpass_app
  WITH CHECK (current_user = 'agentpass_app');
CREATE POLICY platform_promotion_audit_events_backup_select
  ON platform_promotion_audit_events FOR SELECT TO agentpass_backup
  USING (current_user = 'agentpass_backup');
CREATE POLICY platform_promotion_audit_events_migration_all
  ON platform_promotion_audit_events TO agentpass_migrator
  USING (true) WITH CHECK (true);

COMMIT;
