BEGIN;

-- Platform promotion approvals are deployment-scoped authority.  They are
-- intentionally independent of product membership and contain no tenant
-- authority or mutable pre-approval state.

CREATE FUNCTION agentpass_platform_promotion_approval_canonical_json(
  p_version integer,
  p_type text,
  p_approval_id uuid,
  p_deployment_id text,
  p_environment text,
  p_candidate_id text,
  p_source_commit text,
  p_source_tree text,
  p_product_pkg_sha256 text,
  p_image_digest text,
  p_sbom_sha256 text,
  p_qualification_report_digests text[],
  p_release_manifest_schema_version integer,
  p_release_manifest_sha256 text,
  p_policy_id text,
  p_policy_version integer,
  p_approval_version integer,
  p_decision text,
  p_platform_principal_ids text[],
  p_quorum_required integer,
  p_quorum_satisfied boolean,
  p_authorization_evidence_digests text[],
  p_approved_at timestamptz,
  p_expires_at timestamptz
)
RETURNS text
LANGUAGE sql
IMMUTABLE
STRICT
PARALLEL SAFE
SET search_path = pg_catalog
AS $$
  -- Build the exact whitespace-free, lexicographically-keyed JSON emitted by
  -- packages/protocol canonicalJson(). json/jsonb::text is intentionally not
  -- used for the object because PostgreSQL's display formatting and jsonb key
  -- order are not the signed protocol encoding.
  SELECT
    '{"approval_id":' || to_json(p_approval_id::text)::text ||
    ',"approval_version":' || p_approval_version::text ||
    ',"approved_at":' || to_json(to_char(p_approved_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'))::text ||
    ',"authorization_evidence_digests":' || array_to_json(p_authorization_evidence_digests)::text ||
    ',"candidate_id":' || to_json(p_candidate_id)::text ||
    ',"decision":' || to_json(p_decision)::text ||
    ',"deployment_id":' || to_json(p_deployment_id)::text ||
    ',"environment":' || to_json(p_environment)::text ||
    ',"expires_at":' || to_json(to_char(p_expires_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'))::text ||
    ',"image_digest":' || to_json(p_image_digest)::text ||
    ',"platform_principal_ids":' || array_to_json(p_platform_principal_ids)::text ||
    ',"policy_id":' || to_json(p_policy_id)::text ||
    ',"policy_version":' || p_policy_version::text ||
    ',"product_pkg_sha256":' || to_json(p_product_pkg_sha256)::text ||
    ',"qualification_report_digests":' || array_to_json(p_qualification_report_digests)::text ||
    ',"quorum":{"required":' || p_quorum_required::text ||
      ',"satisfied":' || CASE WHEN p_quorum_satisfied THEN 'true' ELSE 'false' END || '}' ||
    ',"release_manifest_schema_version":' || p_release_manifest_schema_version::text ||
    ',"release_manifest_sha256":' || to_json(p_release_manifest_sha256)::text ||
    ',"sbom_sha256":' || to_json(p_sbom_sha256)::text ||
    ',"source_commit":' || to_json(p_source_commit)::text ||
    ',"source_tree":' || to_json(p_source_tree)::text ||
    ',"type":' || to_json(p_type)::text ||
    ',"version":' || p_version::text || '}';
$$;

CREATE FUNCTION agentpass_platform_promotion_approval_record_digest(
  p_version integer,
  p_type text,
  p_approval_id uuid,
  p_deployment_id text,
  p_environment text,
  p_candidate_id text,
  p_source_commit text,
  p_source_tree text,
  p_product_pkg_sha256 text,
  p_image_digest text,
  p_sbom_sha256 text,
  p_qualification_report_digests text[],
  p_release_manifest_schema_version integer,
  p_release_manifest_sha256 text,
  p_policy_id text,
  p_policy_version integer,
  p_approval_version integer,
  p_decision text,
  p_platform_principal_ids text[],
  p_quorum_required integer,
  p_quorum_satisfied boolean,
  p_authorization_evidence_digests text[],
  p_approved_at timestamptz,
  p_expires_at timestamptz
)
RETURNS text
LANGUAGE sql
IMMUTABLE
STRICT
PARALLEL SAFE
SET search_path = pg_catalog, public
AS $$
  SELECT encode(
    sha256(convert_to(
      'AgentPass-Platform-Promotion-Approval-v1',
      'UTF8'
    ) || decode('00', 'hex') || convert_to(
      agentpass_platform_promotion_approval_canonical_json(
        p_version,
        p_type,
        p_approval_id,
        p_deployment_id,
        p_environment,
        p_candidate_id,
        p_source_commit,
        p_source_tree,
        p_product_pkg_sha256,
        p_image_digest,
        p_sbom_sha256,
        p_qualification_report_digests,
        p_release_manifest_schema_version,
        p_release_manifest_sha256,
        p_policy_id,
        p_policy_version,
        p_approval_version,
        p_decision,
        p_platform_principal_ids,
        p_quorum_required,
        p_quorum_satisfied,
        p_authorization_evidence_digests,
        p_approved_at,
        p_expires_at
      ),
      'UTF8'
    )),
    'hex'
  );
$$;

CREATE FUNCTION agentpass_platform_promotion_approval_sorted_unique_array(
  p_values text[],
  p_minimum integer,
  p_maximum integer,
  p_pattern text
)
RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
STRICT
PARALLEL SAFE
SET search_path = pg_catalog
AS $$
DECLARE
  item text;
  previous text;
BEGIN
  IF array_ndims(p_values) <> 1
     OR cardinality(p_values) < p_minimum
     OR cardinality(p_values) > p_maximum
  THEN
    RETURN false;
  END IF;

  FOREACH item IN ARRAY p_values LOOP
    IF item IS NULL
       OR item !~ p_pattern
       OR (previous IS NOT NULL AND item COLLATE "C" <= previous COLLATE "C")
    THEN
      RETURN false;
    END IF;
    previous := item;
  END LOOP;

  RETURN true;
END;
$$;

CREATE TABLE platform_promotion_approvals (
  version integer NOT NULL DEFAULT 1
    CHECK (version = 1),
  type text NOT NULL DEFAULT 'agentpass.platform-promotion-approval'
    CHECK (type = 'agentpass.platform-promotion-approval'),
  approval_id uuid PRIMARY KEY,
  deployment_id text NOT NULL
    CHECK (octet_length(deployment_id) BETWEEN 1 AND 255
      AND deployment_id ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]{0,254}$'),
  environment text NOT NULL
    CHECK (environment IN ('staging', 'production')),
  candidate_id text NOT NULL
    CHECK (candidate_id ~ '^release-pkg-sha256-v1-[0-9a-f]{64}$'),
  source_commit text NOT NULL
    CHECK (source_commit ~ '^[0-9a-f]{40}$'),
  source_tree text NOT NULL
    CHECK (source_tree ~ '^[0-9a-f]{40}$'),
  product_pkg_sha256 text NOT NULL
    CHECK (product_pkg_sha256 ~ '^[0-9a-f]{64}$'),
  image_digest text NOT NULL
    CHECK (image_digest ~ '^sha256:[0-9a-f]{64}$'),
  sbom_sha256 text NOT NULL
    CHECK (sbom_sha256 ~ '^[0-9a-f]{64}$'),
  qualification_report_digests text[] NOT NULL
    CHECK (
      array_ndims(qualification_report_digests) = 1
      AND cardinality(qualification_report_digests) BETWEEN 1 AND 16
      AND agentpass_platform_promotion_approval_sorted_unique_array(
        qualification_report_digests,
        1,
        16,
        '^[0-9a-f]{64}$'
      )
    ),
  release_manifest_schema_version integer NOT NULL
    CHECK (release_manifest_schema_version = 4),
  release_manifest_sha256 text NOT NULL
    CHECK (release_manifest_sha256 ~ '^[0-9a-f]{64}$'),
  policy_id text NOT NULL
    CHECK (octet_length(policy_id) BETWEEN 1 AND 255
      AND policy_id ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]{0,254}$'),
  policy_version integer NOT NULL
    CHECK (policy_version BETWEEN 1 AND 2147483647),
  approval_version integer NOT NULL
    CHECK (approval_version BETWEEN 1 AND 2147483647),
  decision text NOT NULL
    CHECK (decision = 'approved'),
  platform_principal_ids text[] NOT NULL
    CHECK (
      array_ndims(platform_principal_ids) = 1
      AND cardinality(platform_principal_ids) BETWEEN 1 AND 16
      AND agentpass_platform_promotion_approval_sorted_unique_array(
        platform_principal_ids,
        1,
        16,
        '^[A-Za-z0-9][A-Za-z0-9._:/-]{0,254}$'
      )
    ),
  quorum_required integer GENERATED ALWAYS AS (
    CASE environment
      WHEN 'production' THEN 2
      WHEN 'staging' THEN 1
    END
  ) STORED,
  quorum_satisfied boolean GENERATED ALWAYS AS (
    cardinality(platform_principal_ids) >= CASE environment
      WHEN 'production' THEN 2
      WHEN 'staging' THEN 1
    END
  ) STORED,
  authorization_evidence_digests text[] NOT NULL
    CHECK (
      array_ndims(authorization_evidence_digests) = 1
      AND cardinality(authorization_evidence_digests) BETWEEN 1 AND 16
      AND agentpass_platform_promotion_approval_sorted_unique_array(
        authorization_evidence_digests,
        1,
        16,
        '^[0-9a-f]{64}$'
      )
      AND cardinality(authorization_evidence_digests) = cardinality(platform_principal_ids)
    ),
  approved_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  record_digest text GENERATED ALWAYS AS (
    agentpass_platform_promotion_approval_record_digest(
      version,
      type,
      approval_id,
      deployment_id,
      environment,
      candidate_id,
      source_commit,
      source_tree,
      product_pkg_sha256,
      image_digest,
      sbom_sha256,
      qualification_report_digests,
      release_manifest_schema_version,
      release_manifest_sha256,
      policy_id,
      policy_version,
      approval_version,
      decision,
      platform_principal_ids,
      CASE environment
        WHEN 'production' THEN 2
        WHEN 'staging' THEN 1
      END,
      cardinality(platform_principal_ids) >= CASE environment
        WHEN 'production' THEN 2
        WHEN 'staging' THEN 1
      END,
      authorization_evidence_digests,
      approved_at,
      expires_at
    )
  ) STORED
    CHECK (record_digest ~ '^[0-9a-f]{64}$'),
  UNIQUE (deployment_id, environment, candidate_id, approval_version),
  CHECK (candidate_id = 'release-pkg-sha256-v1-' || product_pkg_sha256),
  CHECK (quorum_satisfied IS TRUE),
  CHECK (expires_at > approved_at
    AND expires_at <= approved_at + interval '1 hour')
);

CREATE INDEX platform_promotion_approvals_expiry
  ON platform_promotion_approvals (expires_at, deployment_id, environment, approval_id);

CREATE INDEX platform_promotion_approvals_candidate
  ON platform_promotion_approvals (
    deployment_id,
    environment,
    candidate_id,
    approved_at DESC,
    approval_id
  );

CREATE FUNCTION agentpass_guard_platform_promotion_approval_immutable()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION USING
      ERRCODE = 'check_violation',
      CONSTRAINT = 'platform_promotion_approvals_immutable',
      MESSAGE = 'platform promotion approvals cannot be deleted';
  END IF;

  RAISE EXCEPTION USING
    ERRCODE = 'check_violation',
    CONSTRAINT = 'platform_promotion_approvals_immutable',
    MESSAGE = 'platform promotion approvals are immutable after insert';
END;
$$;

CREATE TRIGGER platform_promotion_approvals_immutable
  BEFORE UPDATE OR DELETE ON platform_promotion_approvals
  FOR EACH ROW
  EXECUTE FUNCTION agentpass_guard_platform_promotion_approval_immutable();

-- The read model is deliberately a narrow public summary.  The two private
-- authorization arrays are not selected by any public-facing view.
CREATE VIEW platform_promotion_approvals_public AS
SELECT
  approval_id,
  deployment_id,
  environment,
  candidate_id,
  policy_id,
  policy_version,
  approval_version,
  jsonb_build_object(
    'required', quorum_required,
    'satisfied', quorum_satisfied
  ) AS quorum,
  approved_at,
  expires_at,
  record_digest
FROM platform_promotion_approvals;

COMMENT ON TABLE platform_promotion_approvals IS
  'Immutable deployment-scoped platform-promotion-approval v1 records; authorization arrays are private.';

COMMENT ON VIEW platform_promotion_approvals_public IS
  'Redacted platform approval summary; principal identities and authorization evidence are excluded.';

COMMIT;
