BEGIN;

-- C3 is deployment scoped.  This head is the only mutable projection: the
-- issuance rows below retain the immutable history and the head advances one
-- generation at a time inside the same transaction as a commit.
CREATE TABLE platform_promotion_deployments (
  deployment_id text NOT NULL
    CHECK (octet_length(deployment_id) BETWEEN 1 AND 255
      AND deployment_id ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]{0,254}$'),
  environment text NOT NULL CHECK (environment IN ('staging', 'production')),
  current_generation bigint NOT NULL DEFAULT 0 CHECK (current_generation >= 0),
  current_candidate_id text,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (deployment_id, environment),
  FOREIGN KEY (current_candidate_id) REFERENCES release_candidates(candidate_id),
  CHECK ((current_generation = 0 AND current_candidate_id IS NULL)
    OR (current_generation > 0 AND current_candidate_id IS NOT NULL))
);

CREATE FUNCTION agentpass_guard_platform_promotion_deployment_head()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION USING ERRCODE = 'check_violation',
      CONSTRAINT = 'platform_promotion_deployments_forward_only',
      MESSAGE = 'platform deployment heads cannot be deleted';
  END IF;
  IF NEW.deployment_id IS DISTINCT FROM OLD.deployment_id
     OR NEW.environment IS DISTINCT FROM OLD.environment
     OR NEW.created_at IS DISTINCT FROM OLD.created_at
     OR NEW.current_generation < OLD.current_generation
     OR (NEW.current_generation > OLD.current_generation + 1)
  THEN
    RAISE EXCEPTION USING
      ERRCODE = 'check_violation',
      CONSTRAINT = 'platform_promotion_deployments_forward_only',
      MESSAGE = 'platform deployment head is immutable except for one generation advance';
  END IF;
  IF NEW.current_generation = OLD.current_generation
     AND NEW.current_candidate_id IS DISTINCT FROM OLD.current_candidate_id
  THEN
    RAISE EXCEPTION USING
      ERRCODE = 'check_violation',
      CONSTRAINT = 'platform_promotion_deployments_forward_only',
      MESSAGE = 'platform deployment candidate cannot change without a generation advance';
  END IF;
  IF OLD.current_generation > 0
     AND NEW.current_generation = OLD.current_generation + 1
     AND NEW.current_candidate_id IS NULL
  THEN
    RAISE EXCEPTION USING
      ERRCODE = 'check_violation',
      CONSTRAINT = 'platform_promotion_deployments_forward_only',
      MESSAGE = 'platform deployment generation advance requires a candidate';
  END IF;
  NEW.updated_at := clock_timestamp();
  RETURN NEW;
END;
$$;

CREATE TRIGGER platform_promotion_deployments_forward_only
  BEFORE UPDATE OR DELETE ON platform_promotion_deployments
  FOR EACH ROW EXECUTE FUNCTION agentpass_guard_platform_promotion_deployment_head();

CREATE TABLE platform_promotion_issuances (
  promotion_id uuid PRIMARY KEY,
  deployment_id text NOT NULL,
  environment text NOT NULL CHECK (environment IN ('staging', 'production')),
  candidate_id text NOT NULL,
  idempotency_key text NOT NULL
    CHECK (octet_length(idempotency_key) BETWEEN 8 AND 255
      AND idempotency_key ~ '^[A-Za-z0-9][A-Za-z0-9._~:-]{7,254}$'),
  state text NOT NULL CHECK (state IN ('reserved', 'uncertain', 'committed')),

  -- These values are copied from the one approved row and active candidate
  -- selected during reservation.  They can never be caller-selected.
  approval_id uuid NOT NULL REFERENCES platform_promotion_approvals(approval_id),
  approval_digest text NOT NULL CHECK (approval_digest ~ '^[0-9a-f]{64}$'),
  source_commit text NOT NULL CHECK (source_commit ~ '^[0-9a-f]{40}$'),
  source_tree text NOT NULL CHECK (source_tree ~ '^[0-9a-f]{40}$'),
  product_pkg_sha256 text NOT NULL CHECK (product_pkg_sha256 ~ '^[0-9a-f]{64}$'),
  image_digest text NOT NULL CHECK (image_digest ~ '^sha256:[0-9a-f]{64}$'),
  sbom_sha256 text NOT NULL CHECK (sbom_sha256 ~ '^[0-9a-f]{64}$'),
  qualification_report_digests text[] NOT NULL,
  release_manifest_schema_version integer NOT NULL CHECK (release_manifest_schema_version = 4),
  release_manifest_sha256 text NOT NULL CHECK (release_manifest_sha256 ~ '^[0-9a-f]{64}$'),
  approval_expires_at timestamptz NOT NULL,

  -- The database owns the exact v3 signing window.  The repository obtains
  -- these values from clock_timestamp() before deriving the durable signer
  -- operation id; callers cannot choose either boundary.
  issued_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,

  purpose text NOT NULL DEFAULT 'agentpass.promotion-evidence'
    CHECK (purpose = 'agentpass.promotion-evidence'),
  protocol_version integer NOT NULL DEFAULT 3 CHECK (protocol_version = 3),
  signing_version integer NOT NULL DEFAULT 3 CHECK (signing_version = 3),
  lifecycle_version bigint NOT NULL CHECK (lifecycle_version > 0),
  key_id text NOT NULL CHECK (key_id ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$'),
  key_version bigint NOT NULL CHECK (key_version > 0),
  signer_key_fingerprint bytea NOT NULL CHECK (octet_length(signer_key_fingerprint) = 32),
  provider_operation_id text NOT NULL
    CHECK (provider_operation_id ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$'),
  request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
  claim_token_digest bytea
    CHECK (claim_token_digest IS NULL OR octet_length(claim_token_digest) = 32),
  claim_expires_at timestamptz,

  evidence_bytes bytea,
  evidence_digest bytea
    CHECK (evidence_digest IS NULL OR octet_length(evidence_digest) = 32),
  CHECK ((evidence_bytes IS NULL AND evidence_digest IS NULL)
    OR (evidence_bytes IS NOT NULL AND evidence_digest = sha256(evidence_bytes))),
  deployment_generation bigint CHECK (deployment_generation IS NULL OR deployment_generation > 0),
  uncertain_reason text,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),

  UNIQUE (deployment_id, environment, candidate_id, idempotency_key),
  UNIQUE (deployment_id, environment, provider_operation_id),
  CHECK (array_ndims(qualification_report_digests) = 1
    AND cardinality(qualification_report_digests) BETWEEN 1 AND 16
    AND agentpass_platform_promotion_approval_sorted_unique_array(
      qualification_report_digests, 1, 16, '^[0-9a-f]{64}$')),
  CHECK (candidate_id = 'release-pkg-sha256-v1-' || product_pkg_sha256),
  CHECK ((state = 'reserved'
    AND claim_token_digest IS NOT NULL AND claim_expires_at IS NOT NULL
    AND evidence_bytes IS NULL AND evidence_digest IS NULL
    AND deployment_generation IS NULL AND uncertain_reason IS NULL)
    OR (state = 'uncertain'
    AND claim_token_digest IS NULL AND claim_expires_at IS NULL
    AND evidence_bytes IS NULL AND evidence_digest IS NULL
    AND deployment_generation IS NULL AND uncertain_reason IS NOT NULL)
    OR (state = 'committed'
    AND claim_token_digest IS NULL AND claim_expires_at IS NULL
    AND evidence_bytes IS NOT NULL AND octet_length(evidence_bytes) BETWEEN 1 AND 131072
    AND evidence_digest IS NOT NULL AND deployment_generation IS NOT NULL
    AND uncertain_reason IS NULL)),
  CHECK (state <> 'uncertain'
    OR uncertain_reason IN ('signer_failure', 'signer_output', 'verification_failure', 'commit_failure', 'stale_lifecycle')),
  CHECK (approval_expires_at > created_at),
  CHECK (expires_at > issued_at),
  CHECK (expires_at <= approval_expires_at),
  CHECK (expires_at - issued_at <= interval '1 hour'),
  CHECK (state <> 'reserved' OR claim_expires_at > created_at),
  FOREIGN KEY (deployment_id, environment)
    REFERENCES platform_promotion_deployments(deployment_id, environment)
);

CREATE UNIQUE INDEX platform_promotion_issuances_one_open
  ON platform_promotion_issuances (deployment_id, environment)
  WHERE state IN ('reserved', 'uncertain');

CREATE INDEX platform_promotion_issuances_expiry
  ON platform_promotion_issuances (claim_expires_at, deployment_id, environment, promotion_id)
  WHERE state = 'reserved';

CREATE INDEX platform_promotion_issuances_committed
  ON platform_promotion_issuances (deployment_id, environment, deployment_generation DESC, promotion_id)
  WHERE state = 'committed';

CREATE FUNCTION agentpass_guard_platform_promotion_issuance()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
DECLARE
  approval_row record;
  candidate_row record;
  signer_row record;
BEGIN
  IF TG_OP = 'INSERT' THEN
    SELECT approval_id, deployment_id, environment, candidate_id, source_commit, source_tree,
      product_pkg_sha256, image_digest, sbom_sha256, qualification_report_digests,
      release_manifest_schema_version, release_manifest_sha256, record_digest, expires_at,
      decision, quorum_satisfied
    INTO approval_row
    FROM platform_promotion_approvals
    WHERE approval_id = NEW.approval_id
    FOR KEY SHARE;
    IF NOT FOUND
       OR approval_row.deployment_id IS DISTINCT FROM NEW.deployment_id
       OR approval_row.environment IS DISTINCT FROM NEW.environment
       OR approval_row.candidate_id IS DISTINCT FROM NEW.candidate_id
       OR approval_row.source_commit IS DISTINCT FROM NEW.source_commit
       OR approval_row.source_tree IS DISTINCT FROM NEW.source_tree
       OR approval_row.product_pkg_sha256 IS DISTINCT FROM NEW.product_pkg_sha256
       OR approval_row.image_digest IS DISTINCT FROM NEW.image_digest
       OR approval_row.sbom_sha256 IS DISTINCT FROM NEW.sbom_sha256
       OR approval_row.qualification_report_digests IS DISTINCT FROM NEW.qualification_report_digests
       OR approval_row.release_manifest_schema_version IS DISTINCT FROM NEW.release_manifest_schema_version
       OR approval_row.release_manifest_sha256 IS DISTINCT FROM NEW.release_manifest_sha256
       OR approval_row.record_digest IS DISTINCT FROM NEW.approval_digest
       OR approval_row.expires_at IS DISTINCT FROM NEW.approval_expires_at
       OR approval_row.decision IS DISTINCT FROM 'approved'
       OR approval_row.quorum_satisfied IS DISTINCT FROM TRUE
    THEN
      RAISE EXCEPTION USING ERRCODE = 'check_violation',
        CONSTRAINT = 'platform_promotion_issuances_approval_binding',
        MESSAGE = 'platform promotion issuance approval binding is invalid';
    END IF;
    SELECT candidate_id, source_commit, artifact_sha256, manifest_sha256, status
    INTO candidate_row
    FROM release_candidates candidate
      WHERE candidate.candidate_id = NEW.candidate_id
        AND candidate.source_commit = NEW.source_commit
        AND candidate.artifact_sha256 = NEW.product_pkg_sha256
        AND candidate.manifest_sha256 = NEW.release_manifest_sha256
        AND candidate.status = 'active'
    FOR SHARE;
    IF NOT FOUND THEN
      RAISE EXCEPTION USING ERRCODE = 'check_violation',
        CONSTRAINT = 'platform_promotion_issuances_candidate_binding',
        MESSAGE = 'platform promotion issuance candidate binding is invalid';
    END IF;
    SELECT lifecycle.purpose, lifecycle.algorithm, lifecycle.version,
      key.key_id, key.key_version, key.algorithm, key.state, key.public_key_fingerprint
    INTO signer_row
    FROM managed_signer_key_lifecycles lifecycle
    JOIN managed_signer_keys key
      ON key.purpose = lifecycle.purpose
     AND key.key_id = NEW.key_id
     AND key.key_version = NEW.key_version
     AND key.algorithm = 'ed25519'
     AND key.state = 'active'
     AND key.public_key_fingerprint = NEW.signer_key_fingerprint
    WHERE lifecycle.purpose = NEW.purpose
      AND lifecycle.algorithm = 'ed25519'
      AND lifecycle.version = NEW.lifecycle_version
    FOR SHARE OF lifecycle, key;
    IF NOT FOUND THEN
      RAISE EXCEPTION USING ERRCODE = 'check_violation',
        CONSTRAINT = 'platform_promotion_issuances_signer_binding',
        MESSAGE = 'platform promotion issuance signer binding is invalid';
    END IF;
  END IF;
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION USING ERRCODE = 'check_violation',
      CONSTRAINT = 'platform_promotion_issuances_terminal_immutable',
      MESSAGE = 'platform promotion issuances cannot be deleted';
  END IF;
  IF TG_OP = 'UPDATE' AND (NEW.promotion_id IS DISTINCT FROM OLD.promotion_id
     OR NEW.deployment_id IS DISTINCT FROM OLD.deployment_id
     OR NEW.environment IS DISTINCT FROM OLD.environment
     OR NEW.candidate_id IS DISTINCT FROM OLD.candidate_id
     OR NEW.idempotency_key IS DISTINCT FROM OLD.idempotency_key
     OR NEW.approval_id IS DISTINCT FROM OLD.approval_id
     OR NEW.approval_digest IS DISTINCT FROM OLD.approval_digest
     OR NEW.source_commit IS DISTINCT FROM OLD.source_commit
     OR NEW.source_tree IS DISTINCT FROM OLD.source_tree
     OR NEW.product_pkg_sha256 IS DISTINCT FROM OLD.product_pkg_sha256
     OR NEW.image_digest IS DISTINCT FROM OLD.image_digest
     OR NEW.sbom_sha256 IS DISTINCT FROM OLD.sbom_sha256
     OR NEW.qualification_report_digests IS DISTINCT FROM OLD.qualification_report_digests
     OR NEW.release_manifest_schema_version IS DISTINCT FROM OLD.release_manifest_schema_version
     OR NEW.release_manifest_sha256 IS DISTINCT FROM OLD.release_manifest_sha256
     OR NEW.approval_expires_at IS DISTINCT FROM OLD.approval_expires_at
     OR NEW.issued_at IS DISTINCT FROM OLD.issued_at
     OR NEW.expires_at IS DISTINCT FROM OLD.expires_at
     OR NEW.purpose IS DISTINCT FROM OLD.purpose
     OR NEW.protocol_version IS DISTINCT FROM OLD.protocol_version
     OR NEW.signing_version IS DISTINCT FROM OLD.signing_version
     OR NEW.lifecycle_version IS DISTINCT FROM OLD.lifecycle_version
     OR NEW.key_id IS DISTINCT FROM OLD.key_id
     OR NEW.key_version IS DISTINCT FROM OLD.key_version
     OR NEW.signer_key_fingerprint IS DISTINCT FROM OLD.signer_key_fingerprint
     OR NEW.provider_operation_id IS DISTINCT FROM OLD.provider_operation_id
     OR NEW.request_digest IS DISTINCT FROM OLD.request_digest
     OR NEW.created_at IS DISTINCT FROM OLD.created_at)
  THEN
    RAISE EXCEPTION USING ERRCODE = 'check_violation',
      CONSTRAINT = 'platform_promotion_issuances_identity_immutable',
      MESSAGE = 'platform promotion issuance identity is immutable';
  END IF;
  IF TG_OP = 'UPDATE' AND OLD.state = 'reserved' AND NEW.state = 'reserved'
     AND (NEW.claim_token_digest IS DISTINCT FROM OLD.claim_token_digest
       OR NEW.claim_expires_at IS DISTINCT FROM OLD.claim_expires_at)
     AND (OLD.claim_expires_at > clock_timestamp()
       OR NEW.claim_token_digest IS NULL
       OR NEW.claim_expires_at IS NULL
       OR NEW.claim_expires_at <= clock_timestamp())
  THEN
    RAISE EXCEPTION USING ERRCODE = 'check_violation',
      CONSTRAINT = 'platform_promotion_issuances_claim_reclaim_fence',
      MESSAGE = 'platform promotion claim replacement requires an expired fenced lease';
  END IF;
  IF TG_OP = 'UPDATE' AND OLD.state IN ('uncertain', 'committed') AND NEW IS DISTINCT FROM OLD THEN
    RAISE EXCEPTION USING ERRCODE = 'check_violation',
      CONSTRAINT = 'platform_promotion_issuances_terminal_immutable',
      MESSAGE = 'terminal platform promotion issuance is immutable';
  END IF;
  IF TG_OP = 'UPDATE' AND OLD.state = 'reserved' AND NEW.state NOT IN ('reserved', 'uncertain', 'committed') THEN
    RAISE EXCEPTION USING ERRCODE = 'check_violation',
      CONSTRAINT = 'platform_promotion_issuances_transition',
      MESSAGE = 'platform promotion issuance transition is invalid';
  END IF;
  NEW.updated_at := clock_timestamp();
  RETURN NEW;
END;
$$;

CREATE TRIGGER platform_promotion_issuances_guard
  BEFORE INSERT OR UPDATE OR DELETE ON platform_promotion_issuances
  FOR EACH ROW EXECUTE FUNCTION agentpass_guard_platform_promotion_issuance();

CREATE VIEW platform_promotion_issuances_public AS
SELECT promotion_id, deployment_id, environment, candidate_id, idempotency_key,
  state, approval_id, approval_digest, source_commit, source_tree,
  product_pkg_sha256, image_digest, sbom_sha256, qualification_report_digests,
  release_manifest_schema_version, release_manifest_sha256, approval_expires_at,
  issued_at, expires_at, purpose, protocol_version, signing_version, lifecycle_version,
  key_id, key_version, encode(signer_key_fingerprint, 'base64') AS signer_key_fingerprint,
  provider_operation_id, deployment_generation, encode(evidence_digest, 'hex') AS evidence_digest, uncertain_reason,
  created_at, updated_at
FROM platform_promotion_issuances;

COMMENT ON TABLE platform_promotion_issuances IS
  'Immutable deployment-scoped promotion authority and v3 evidence ledger; claims are stored only as digests.';
COMMENT ON VIEW platform_promotion_issuances_public IS
  'Bounded promotion summary; no claim token, evidence bytes, platform principal IDs, or authorization evidence arrays.';

COMMIT;
