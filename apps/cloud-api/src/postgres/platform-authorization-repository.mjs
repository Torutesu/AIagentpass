import crypto from "node:crypto";

import {
  canonicalizePromotionEvidenceV3,
  PROMOTION_EVIDENCE_V3_ALGORITHM,
  PROMOTION_EVIDENCE_V3_MAX_TTL_MS,
  PROMOTION_EVIDENCE_V3_PROTOCOL_VERSION,
  PROMOTION_EVIDENCE_V3_PURPOSE,
  PROMOTION_EVIDENCE_V3_SIGNING_VERSION,
  PROMOTION_EVIDENCE_V3_TYPE,
  PROMOTION_EVIDENCE_V3_VERSION,
  normalizePromotionEvidenceV3,
  normalizePromotionEvidenceV3Statement,
  promotionEvidenceV3SigningData
} from "../promotion-evidence-v3-statement.mjs";
import {
  normalizePlatformPromotionRequest,
  platformPromotionAuthorizationRequestDigest
} from "../platform-promotion-http-contract.mjs";
import { createPlatformPromotionIssuanceService } from "../platform-promotion-issuance.mjs";
import { isPlatformSessionToken } from "../platform-session-transport.mjs";
import {
  createPostgresPlatformPromotionIssuanceRepository,
  PLATFORM_PROMOTION_ISSUANCE_ERROR_CODES,
  PlatformPromotionIssuanceRepositoryError
} from "./platform-promotion-issuance-repository.mjs";
import { canonicalManagedSignerRequestDigest } from "./managed-signer-key-lifecycle-repository.mjs";
import { withTransaction } from "./repository.mjs";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
const DIGEST = /^[0-9a-f]{64}$/u;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,254}$/u;
const CANDIDATE = /^release-pkg-sha256-v1-[0-9a-f]{64}$/u;
const IDEMPOTENCY = /^[A-Za-z0-9][A-Za-z0-9._~:-]{7,254}$/u;
const CLAIM = /^[A-Za-z0-9_-]{43}$/u;
const FINGERPRINT = /^SHA256:[A-Za-z0-9_-]{43}$/u;
const TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u;
const ENVIRONMENTS = new Set(["staging", "production"]);
const STATES = new Set(["reserved", "uncertain", "committed"]);
const UNCERTAINTY_REASONS = new Set([
  "signer_failure", "stale_lifecycle", "signer_output", "commit_failure", "verification_failure"
]);
const IDENTITY_KEYS = Object.freeze(["promotion_id", "deployment_id", "environment", "candidate_id", "idempotency_key"]);
const AUTHORIZED_RESERVE_KEYS = Object.freeze([
  ...IDENTITY_KEYS,
  "organization_id", "session_material_hash", "csrf_token", "proof_id", "jti"
]);
const AUTHORIZATION_KEYS = Object.freeze([
  "organization_id", "session_material_hash", "csrf_token", "proof_id", "jti"
]);
const PUBLIC_KEYS = Object.freeze([...IDENTITY_KEYS]);
const COMMIT_KEYS = Object.freeze([...IDENTITY_KEYS, "claim_token", "promotion_evidence"]);
const UNCERTAIN_KEYS = Object.freeze([...IDENTITY_KEYS, "claim_token", "reason"]);

/**
 * This is the sole online promotion mutation SQL for the adapter.  The
 * function owns the transaction, proof consumption, lifecycle re-check, and
 * call to the reviewed 0047 reservation function.  The legacy direct reserve
 * SQL is intentionally not present in this module.
 */
export const PLATFORM_AUTHORIZATION_RESERVE_SQL = `SELECT public.agentpass_consume_platform_authorization_and_reserve(
  $1::bytea,$2::bytea,$3::uuid,$4::bytea,$5::bytea,$6::uuid,$7::text,$8::text,
  $9::text,$10::text,$11::bytea,$12::integer,$13::integer,$14::text,$15::bigint,$16::bigint
) AS result`;

export const PLATFORM_AUTHORIZATION_REPOSITORY_SQL = Object.freeze({
  consumeAndReserve: PLATFORM_AUTHORIZATION_RESERVE_SQL
});

export const PLATFORM_AUTHORIZATION_REPOSITORY_ERROR_CODES = Object.freeze({
  CONFIG: "ERR_PLATFORM_AUTHORIZATION_REPOSITORY_CONFIG",
  INPUT: "ERR_PLATFORM_AUTHORIZATION_REPOSITORY_INPUT",
  RESULT: "ERR_PLATFORM_AUTHORIZATION_REPOSITORY_RESULT",
  DATABASE: "ERR_PLATFORM_AUTHORIZATION_REPOSITORY_DATABASE",
  BINDING: "ERR_PLATFORM_AUTHORIZATION_REPOSITORY_BINDING"
});

const MESSAGES = Object.freeze({
  [PLATFORM_AUTHORIZATION_REPOSITORY_ERROR_CODES.CONFIG]: "platform authorization repository configuration is invalid",
  [PLATFORM_AUTHORIZATION_REPOSITORY_ERROR_CODES.INPUT]: "platform authorization request is invalid",
  [PLATFORM_AUTHORIZATION_REPOSITORY_ERROR_CODES.RESULT]: "platform authorization returned an invalid result",
  [PLATFORM_AUTHORIZATION_REPOSITORY_ERROR_CODES.DATABASE]: "platform authorization storage is unavailable",
  [PLATFORM_AUTHORIZATION_REPOSITORY_ERROR_CODES.BINDING]: "platform authorization binding is invalid"
});

export class PlatformAuthorizationRepositoryError extends Error {
  constructor(code) {
    super(MESSAGES[code] ?? MESSAGES[PLATFORM_AUTHORIZATION_REPOSITORY_ERROR_CODES.DATABASE]);
    this.name = "PlatformAuthorizationRepositoryError";
    this.code = Object.hasOwn(MESSAGES, code)
      ? code
      : PLATFORM_AUTHORIZATION_REPOSITORY_ERROR_CODES.DATABASE;
  }
}

// The HTTP contract owns the canonical bytes and digest.  This alias keeps
// the adapter API discoverable without creating a second canonicalization.
export const platformAuthorizationRequestDigest = platformPromotionAuthorizationRequestDigest;

/**
 * Creates the old promotion-issuance repository contract with one important
 * difference: reservePlatformPromotion is available only through an
 * authorization scope and calls the 0054 proof-consuming function.
 */
export function createPostgresPlatformAuthorizationRepository({
  client,
  promotionRepository = undefined,
  claimLeaseMs = 60_000,
  evidenceTtlMs = PROMOTION_EVIDENCE_V3_MAX_TTL_MS,
  keyId = undefined,
  keyVersion = undefined,
  lifecycleVersion = undefined,
  randomBytes = crypto.randomBytes,
  verifyEvidence = undefined
} = {}) {
  validateConfig({ client, claimLeaseMs, evidenceTtlMs, keyId, keyVersion, lifecycleVersion, randomBytes });

  const issuanceRepository = promotionRepository ?? createPostgresPlatformPromotionIssuanceRepository({
    client,
    claimLeaseMs,
    evidenceTtlMs,
    keyId,
    keyVersion,
    lifecycleVersion,
    randomBytes,
    verifyEvidence
  });
  assertIssuanceRepository(issuanceRepository);

  async function consumeAndReserve(input = {}) {
    const values = normalizeAuthorizedReserveInput(input);
    const claimToken = makeClaimToken(randomBytes);
    try {
      const raw = await withTransaction(client, async (tx) => {
        const result = await tx.query(PLATFORM_AUTHORIZATION_RESERVE_SQL, [
          values.session_material_hash,
          values.csrf_token_hash,
          values.proof_id,
          values.jti_hash,
          values.request_digest_sha256,
          values.promotion_id,
          values.deployment_id,
          values.environment,
          values.candidate_id,
          values.idempotency_key,
          sha256Bytes(claimToken),
          claimLeaseMs,
          evidenceTtlMs,
          keyId ?? null,
          keyVersion ?? null,
          lifecycleVersion ?? null
        ]);
        return singleResult(result);
      });
      return normalizeAtomicOutcome(raw, values, claimToken, { keyId, keyVersion, lifecycleVersion });
    } catch (error) {
      if (error instanceof PlatformAuthorizationRepositoryError) throw error;
      if (error instanceof PlatformPromotionIssuanceRepositoryError) throw error;
      throw new PlatformAuthorizationRepositoryError(PLATFORM_AUTHORIZATION_REPOSITORY_ERROR_CODES.DATABASE);
    }
  }

  function forAuthorization(authorization = {}) {
    const bound = normalizeAuthorization(authorization);
    return Object.freeze({
      reservePlatformPromotion: (input = {}) => consumeAndReserve({ ...input, ...bound }),
      commitPlatformPromotion: issuanceRepository.commitPlatformPromotion,
      markPlatformPromotionUncertain: issuanceRepository.markPlatformPromotionUncertain
    });
  }

  // Deliberately require all authorization material on the unscoped method as
  // well.  Passing only the five legacy public fields can never reach SQL.
  return Object.freeze({
    reservePlatformPromotion: consumeAndReserve,
    commitPlatformPromotion: issuanceRepository.commitPlatformPromotion,
    markPlatformPromotionUncertain: issuanceRepository.markPlatformPromotionUncertain,
    forAuthorization
  });
}

export const createPostgresPlatformAuthorizedPromotionRepository = createPostgresPlatformAuthorizationRepository;
export const createPlatformAuthorizationRepository = createPostgresPlatformAuthorizationRepository;

/**
 * Small composition seam for the existing issuance service.  The service
 * receives a single exact object containing the public promotion request and
 * trusted authorization material.  It never accepts a raw platform cookie.
 */
export function createPlatformAuthorizedPromotionService({
  repository,
  signer,
  publicKeyResolver,
  now = () => Date.now(),
  maxTtlMs = PROMOTION_EVIDENCE_V3_MAX_TTL_MS
} = {}) {
  if (!repository || typeof repository.forAuthorization !== "function"
    || !signer || typeof signer.sign !== "function"
    || typeof publicKeyResolver !== "function") {
    throw new PlatformAuthorizationRepositoryError(PLATFORM_AUTHORIZATION_REPOSITORY_ERROR_CODES.CONFIG);
  }

  async function issuePlatformPromotion(input = {}) {
    const values = normalizeAuthorizedServiceInput(input);
    const scopedRepository = repository.forAuthorization(pick(values, AUTHORIZATION_KEYS));
    const service = createIssuanceService(scopedRepository);
    return service.issuePlatformPromotion(pick(values, PUBLIC_KEYS));
  }

  function createIssuanceService(scopedRepository) {
    // The existing service accepts only the five public request keys.  The
    // scope facade strips trusted authorization fields before that boundary.
    const issueRepository = Object.freeze({
      reservePlatformPromotion: scopedRepository.reservePlatformPromotion,
      commitPlatformPromotion: scopedRepository.commitPlatformPromotion,
      markPlatformPromotionUncertain: scopedRepository.markPlatformPromotionUncertain,
      // The existing service requires these methods for ambiguity recovery.
      // This seam intentionally has no authenticated replay/get SQL path.
      replayPlatformPromotion: failClosed,
      getCommittedPlatformPromotion: failClosed
    });
    return createPlatformPromotionIssuanceService({
      repository: issueRepository,
      signer,
      publicKeyResolver,
      now,
      maxTtlMs
    });
  }

  return Object.freeze({ issuePlatformPromotion });
}

export const createAuthorizedPlatformPromotionService = createPlatformAuthorizedPromotionService;

function normalizeAuthorizedServiceInput(input) {
  if (!isPlainObject(input) || !sameKeys(input, AUTHORIZED_RESERVE_KEYS)) throw inputError();
  const authorization = normalizeAuthorization(pick(input, AUTHORIZATION_KEYS));
  const request = normalizeDigestRequest(input);
  return Object.freeze({ ...request, ...authorization });
}

function normalizeAuthorizedReserveInput(input) {
  if (!isPlainObject(input) || !sameKeys(input, AUTHORIZED_RESERVE_KEYS)) throw inputError();
  const request = normalizeDigestRequest(input);
  const authorization = normalizeAuthorization(pick(input, AUTHORIZATION_KEYS));
  return Object.freeze({
    ...request,
    ...authorization,
    session_material_hash: digestBytes(input.session_material_hash, "session_material_hash"),
    csrf_token_hash: sha256Token(input.csrf_token),
    jti_hash: sha256Jti(input.jti),
    request_digest_sha256: Buffer.from(platformPromotionAuthorizationRequestDigest(request, { organizationId: authorization.organization_id }), "hex")
  });
}

function normalizeAuthorization(input) {
  if (!isPlainObject(input) || !sameKeys(input, AUTHORIZATION_KEYS)) throw inputError();
  return Object.freeze({
    organization_id: uuid(input.organization_id, "organization_id"),
    session_material_hash: digestBytes(input.session_material_hash, "session_material_hash"),
    csrf_token: rawToken(input.csrf_token, "csrf_token"),
    proof_id: uuid(input.proof_id, "proof_id"),
    jti: rawJti(input.jti)
  });
}

function normalizeDigestRequest(input) {
  if (!isPlainObject(input)) throw inputError();
  const request = normalizePlatformPromotionRequest({
    promotion_id: input.promotion_id,
    deployment_id: input.deployment_id,
    environment: input.environment,
    candidate_id: input.candidate_id
  }, input.idempotency_key);
  return Object.freeze({
    promotion_id: request.promotion_id,
    deployment_id: request.deployment_id,
    environment: request.environment,
    candidate_id: request.candidate_id,
    idempotency_key: request.idempotency_key
  });
}

function normalizeAtomicOutcome(value, input, claimToken, lifecycleBinding = {}) {
  if (!isPlainObject(value) || typeof value.state !== "string") throw resultError();
  if (value.state === "uncertain") return Object.freeze({ state: "uncertain" });
  if (value.state === "reserved" && value.claim_issued !== true) return Object.freeze({ state: "in_progress" });
  if (value.state !== "reserved" && value.state !== "committed") throw resultError();
  const row = normalizeAuthorityResult(value, value.state === "reserved" ? claimToken : undefined);
  assertResultBinding(row, input, lifecycleBinding);
  if (row.state === "committed") return committedOutcome(row);
  if (row.state !== "reserved" || value.claim_issued !== true) throw resultError();
  return reservedOutcome(row, claimToken);
}

function normalizeAuthorityResult(value, claimToken = undefined) {
  try {
    if (!isPlainObject(value) || !AUTHORITY_RESULT_KEYS.every((key) => Object.hasOwn(value, key))) throw new Error("result keys");
    if (Reflect.ownKeys(value).some((key) => typeof key !== "string" || !AUTHORITY_RESULT_KEYS.includes(key))) throw new Error("result keys");
    const evidenceBytes = value.evidence_bytes === null || value.evidence_bytes === undefined
      ? null
      : Buffer.from(String(value.evidence_bytes), "base64");
    const row = {
      promotion_id: value.promotion_id,
      deployment_id: value.deployment_id,
      environment: value.environment,
      candidate_id: value.candidate_id,
      idempotency_key: value.idempotency_key,
      state: value.state,
      approval_id: value.platform_approval_id,
      approval_digest: value.platform_approval_digest,
      source_commit: value.source_commit,
      source_tree: value.source_tree,
      product_pkg_sha256: value.product_pkg_sha256,
      image_digest: value.image_digest,
      sbom_sha256: value.sbom_sha256,
      qualification_report_digests: value.qualification_report_digests,
      release_manifest_schema_version: value.release_manifest_schema_version,
      release_manifest_sha256: value.release_manifest_sha256,
      approval_expires_at: value.approval_expires_at,
      issued_at: value.issued_at,
      expires_at: value.expires_at,
      purpose: value.purpose,
      protocol_version: value.protocol_version,
      signing_version: value.signing_version,
      lifecycle_version: value.lifecycle_version,
      key_id: value.key_id,
      key_version: value.key_version,
      signer_key_fingerprint: value.signer_key_fingerprint,
      claim_token_digest: claimToken === undefined ? null : sha256(claimToken),
      claim_expires_at: value.claim_expires_at,
      evidence_bytes: evidenceBytes,
      evidence_digest: value.evidence_digest,
      deployment_generation: value.deployment_generation,
      uncertain_reason: value.uncertain_reason,
      created_at: value.created_at,
      updated_at: value.updated_at
    };
    row.provider_operation_id = deriveProviderOperationId(row);
    row.request_digest = row.provider_operation_id.slice("managed-signer-v1-".length);
    return normalizeStoredRow(row);
  } catch (error) {
    if (error instanceof PlatformAuthorizationRepositoryError) throw error;
    throw resultError();
  }
}

const AUTHORITY_RESULT_KEYS = Object.freeze([
  "state", "promotion_id", "deployment_id", "environment", "candidate_id", "idempotency_key",
  "source_commit", "source_tree", "product_pkg_sha256", "image_digest", "sbom_sha256",
  "qualification_report_digests", "release_manifest_schema_version", "release_manifest_sha256",
  "platform_approval_id", "platform_approval_digest", "approval_state", "purpose",
  "protocol_version", "signing_version", "lifecycle_version", "key_id", "key_version",
  "signer_key_fingerprint", "issued_at", "expires_at", "approval_expires_at", "claim_expires_at",
  "evidence_bytes", "evidence_digest", "deployment_generation", "uncertain_reason", "created_at",
  "updated_at", "claim_issued"
]);

function assertResultBinding(row, input, lifecycleBinding) {
  if (row.promotion_id !== input.promotion_id || row.deployment_id !== input.deployment_id
    || row.environment !== input.environment || row.candidate_id !== input.candidate_id
    || row.idempotency_key !== input.idempotency_key
    || lifecycleBinding.keyId !== undefined && row.key_id !== lifecycleBinding.keyId
    || lifecycleBinding.keyVersion !== undefined && row.key_version !== lifecycleBinding.keyVersion
    || lifecycleBinding.lifecycleVersion !== undefined && row.lifecycle_version !== lifecycleBinding.lifecycleVersion) throw bindingError();
}

function normalizeStoredRow(row) {
  if (!row || typeof row !== "object" || Array.isArray(row)
    || !UUID.test(String(row.promotion_id)) || !IDENTIFIER.test(String(row.deployment_id))
    || !ENVIRONMENTS.has(row.environment) || !CANDIDATE.test(String(row.candidate_id))
    || !IDEMPOTENCY.test(String(row.idempotency_key)) || !STATES.has(row.state)
    || !UUID.test(String(row.approval_id)) || !DIGEST.test(String(row.approval_digest))
    || !/^[0-9a-f]{40}$/u.test(String(row.source_commit)) || !/^[0-9a-f]{40}$/u.test(String(row.source_tree))
    || !DIGEST.test(String(row.product_pkg_sha256)) || !/^sha256:[0-9a-f]{64}$/u.test(String(row.image_digest))
    || !DIGEST.test(String(row.sbom_sha256)) || String(row.candidate_id) !== `release-pkg-sha256-v1-${row.product_pkg_sha256}`
    || !Array.isArray(row.qualification_report_digests) || row.qualification_report_digests.length < 1
    || row.qualification_report_digests.length > 16
    || row.qualification_report_digests.some((value, index, values) => !DIGEST.test(String(value)) || (index > 0 && String(values[index - 1]) >= String(value)))
    || numberValue(row.release_manifest_schema_version) !== 4 || !DIGEST.test(String(row.release_manifest_sha256))
    || !TIMESTAMP.test(databaseTimestamp(row.approval_expires_at)) || !TIMESTAMP.test(databaseTimestamp(row.issued_at))
    || !TIMESTAMP.test(databaseTimestamp(row.expires_at)) || !TIMESTAMP.test(databaseTimestamp(row.created_at))
    || !TIMESTAMP.test(databaseTimestamp(row.updated_at)) || !FINGERPRINT.test(normalizeFingerprint(row.signer_key_fingerprint))
    || row.purpose !== PROMOTION_EVIDENCE_V3_PURPOSE || numberValue(row.protocol_version) !== 3
    || numberValue(row.signing_version) !== 3 || numberValue(row.lifecycle_version) < 1
    || !IDENTIFIER.test(String(row.key_id)) || numberValue(row.key_version) < 1
    || !IDENTIFIER.test(String(row.provider_operation_id)) || !isDigestBytes(row.request_digest)) throw resultError();

  const normalized = {
    ...row,
    promotion_id: String(row.promotion_id),
    deployment_id: String(row.deployment_id),
    candidate_id: String(row.candidate_id),
    approval_id: String(row.approval_id),
    approval_digest: String(row.approval_digest),
    source_commit: String(row.source_commit),
    source_tree: String(row.source_tree),
    product_pkg_sha256: String(row.product_pkg_sha256),
    image_digest: String(row.image_digest),
    sbom_sha256: String(row.sbom_sha256),
    qualification_report_digests: [...row.qualification_report_digests].map(String),
    release_manifest_sha256: String(row.release_manifest_sha256),
    approval_expires_at: databaseTimestamp(row.approval_expires_at),
    issued_at: databaseTimestamp(row.issued_at),
    expires_at: databaseTimestamp(row.expires_at),
    created_at: databaseTimestamp(row.created_at),
    updated_at: databaseTimestamp(row.updated_at),
    purpose: String(row.purpose),
    key_id: String(row.key_id),
    signer_key_fingerprint: normalizeFingerprint(row.signer_key_fingerprint),
    provider_operation_id: String(row.provider_operation_id),
    claim_token_digest: row.claim_token_digest ? String(row.claim_token_digest).toLowerCase() : null,
    evidence_digest: row.evidence_digest ? String(row.evidence_digest).toLowerCase() : null
  };
  if (Date.parse(normalized.approval_expires_at) <= Date.parse(normalized.created_at)
    || Date.parse(normalized.expires_at) <= Date.parse(normalized.issued_at)
    || Date.parse(normalized.expires_at) > Date.parse(normalized.approval_expires_at)
    || Date.parse(normalized.expires_at) - Date.parse(normalized.issued_at) > PROMOTION_EVIDENCE_V3_MAX_TTL_MS) throw resultError();
  if (normalized.state === "reserved") {
    if (!DIGEST.test(normalized.claim_token_digest ?? "") || normalized.claim_expires_at === null || normalized.claim_expires_at === undefined
      || Date.parse(databaseTimestamp(normalized.claim_expires_at)) <= Date.parse(normalized.created_at)
      || normalized.evidence_bytes !== null && normalized.evidence_bytes !== undefined
      || normalized.evidence_digest !== null || normalized.deployment_generation !== null
      || normalized.uncertain_reason !== null) throw resultError();
  } else {
    if (normalized.claim_token_digest !== null || normalized.claim_expires_at !== null && normalized.claim_expires_at !== undefined) throw resultError();
    if (normalized.state === "uncertain") {
      if (!UNCERTAINTY_REASONS.has(normalized.uncertain_reason) || normalized.evidence_bytes !== null && normalized.evidence_bytes !== undefined
        || normalized.evidence_digest !== null || normalized.deployment_generation !== null) throw resultError();
    } else if (normalized.state === "committed") {
      if (!normalized.evidence_bytes || normalized.evidence_bytes.length < 1 || normalized.evidence_bytes.length > 131072
        || !DIGEST.test(normalized.evidence_digest ?? "") || numberValue(normalized.deployment_generation) < 1
        || normalized.uncertain_reason !== null) throw resultError();
    }
  }
  if (normalized.provider_operation_id !== deriveProviderOperationId(normalized)) throw resultError();
  return normalized;
}

function committedOutcome(row) {
  const result = publicRow(row);
  try {
    const parsed = normalizeEvidence(JSON.parse(Buffer.from(row.evidence_bytes).toString("utf8")));
    const canonical = canonicalizePromotionEvidenceV3(parsed, { allowExpired: true, allowFuture: true });
    if (sha256(canonical) !== row.evidence_digest) throw new Error("evidence digest");
    result.promotion_evidence = parsed;
    return deepFreeze(result);
  } catch {
    throw resultError();
  }
}

function reservedOutcome(row, token) {
  return deepFreeze({ ...publicRow(row), claim_token: token });
}

function publicRow(row) {
  return {
    state: row.state,
    promotion_id: row.promotion_id,
    deployment_id: row.deployment_id,
    environment: row.environment,
    candidate_id: row.candidate_id,
    idempotency_key: row.idempotency_key,
    source_commit: row.source_commit,
    source_tree: row.source_tree,
    product_pkg_sha256: row.product_pkg_sha256,
    image_digest: row.image_digest,
    sbom_sha256: row.sbom_sha256,
    qualification_report_digests: [...row.qualification_report_digests],
    release_manifest_schema_version: numberValue(row.release_manifest_schema_version),
    release_manifest_sha256: row.release_manifest_sha256,
    platform_approval_id: row.approval_id,
    platform_approval_digest: row.approval_digest,
    approval_state: "approved",
    lifecycle_version: numberValue(row.lifecycle_version),
    key_id: row.key_id,
    key_version: numberValue(row.key_version),
    issued_at: databaseTimestamp(row.issued_at),
    expires_at: databaseTimestamp(row.expires_at),
    signer_key_fingerprint: normalizeFingerprint(row.signer_key_fingerprint)
  };
}

function deriveProviderOperationId(row) {
  try {
    const statement = normalizePromotionEvidenceV3Statement({
      version: PROMOTION_EVIDENCE_V3_VERSION,
      type: PROMOTION_EVIDENCE_V3_TYPE,
      promotion_id: row.promotion_id,
      deployment_id: row.deployment_id,
      environment: row.environment,
      candidate_id: row.candidate_id,
      source_commit: row.source_commit,
      source_tree: row.source_tree,
      product_pkg_sha256: row.product_pkg_sha256,
      image_digest: row.image_digest,
      sbom_sha256: row.sbom_sha256,
      qualification_report_digests: row.qualification_report_digests,
      release_manifest_schema_version: numberValue(row.release_manifest_schema_version),
      release_manifest_sha256: row.release_manifest_sha256,
      platform_approval_id: row.approval_id,
      platform_approval_digest: row.approval_digest,
      approval_state: "approved",
      purpose: PROMOTION_EVIDENCE_V3_PURPOSE,
      protocol_version: PROMOTION_EVIDENCE_V3_PROTOCOL_VERSION,
      signing_version: PROMOTION_EVIDENCE_V3_SIGNING_VERSION,
      lifecycle_version: numberValue(row.lifecycle_version),
      key_id: row.key_id,
      key_version: numberValue(row.key_version),
      issued_at: databaseTimestamp(row.issued_at),
      expires_at: databaseTimestamp(row.expires_at)
    }, { allowExpired: true, allowFuture: true, maxTtlMs: PROMOTION_EVIDENCE_V3_MAX_TTL_MS });
    const bytes = promotionEvidenceV3SigningData(statement, { allowExpired: true, allowFuture: true, maxTtlMs: PROMOTION_EVIDENCE_V3_MAX_TTL_MS });
    const digest = canonicalManagedSignerRequestDigest({
      algorithm: PROMOTION_EVIDENCE_V3_ALGORITHM,
      bytes,
      key_id: statement.key_id,
      purpose: statement.purpose,
      version: statement.signing_version,
      key_version: statement.key_version
    });
    return `managed-signer-v1-${digest}`;
  } catch {
    throw resultError();
  }
}

function normalizeEvidence(value) {
  if (typeof value === "string" || Buffer.isBuffer(value)) return normalizePromotionEvidenceV3(JSON.parse(Buffer.from(value).toString("utf8")), { allowExpired: true, allowFuture: true });
  return normalizePromotionEvidenceV3(value, { allowExpired: true, allowFuture: true });
}

function validateConfig({ client, claimLeaseMs, evidenceTtlMs, keyId, keyVersion, lifecycleVersion, randomBytes }) {
  if (!client || typeof client.query !== "function" || typeof randomBytes !== "function"
    || !Number.isSafeInteger(claimLeaseMs) || claimLeaseMs < 1_000 || claimLeaseMs > 300_000
    || !Number.isSafeInteger(evidenceTtlMs) || evidenceTtlMs < 1 || evidenceTtlMs > PROMOTION_EVIDENCE_V3_MAX_TTL_MS
    || claimLeaseMs > evidenceTtlMs || keyId !== undefined && !IDENTIFIER.test(keyId)
    || keyVersion !== undefined && (!Number.isSafeInteger(keyVersion) || keyVersion < 1)
    || lifecycleVersion !== undefined && (!Number.isSafeInteger(lifecycleVersion) || lifecycleVersion < 1)) {
    throw configError();
  }
}

function assertIssuanceRepository(repository) {
  if (!repository || typeof repository !== "object"
    || typeof repository.commitPlatformPromotion !== "function"
    || typeof repository.markPlatformPromotionUncertain !== "function") throw configError();
}

function singleResult(result) {
  if (Number(result?.rowCount ?? result?.rows?.length ?? 0) !== 1 || !Object.hasOwn(result.rows[0] ?? {}, "result")) throw resultError();
  const value = result.rows[0].result;
  if (typeof value === "string") {
    try { return parseResult(JSON.parse(value)); } catch { throw resultError(); }
  }
  return parseResult(value);
}

function parseResult(value) {
  if (!isPlainObject(value)) throw resultError();
  return value;
}

function normalizeDigestRequestForService(input) {
  return normalizeDigestRequest(input);
}

function uuid(value, field) {
  if (typeof value !== "string" || !UUID.test(value)) throw inputError(field);
  return value.toLowerCase();
}

function digestBytes(value, field) {
  if (Buffer.isBuffer(value) || value instanceof Uint8Array) {
    if (value.length !== 32) throw inputError(field);
    return Buffer.from(value);
  }
  if (typeof value === "string" && DIGEST.test(value)) return Buffer.from(value, "hex");
  throw inputError(field);
}

function sha256Token(value) {
  if (!isPlatformSessionToken(value)) throw inputError();
  return sha256Bytes(value);
}

function sha256Jti(value) {
  if (typeof value !== "string" || !UUID_V4.test(value)) throw inputError();
  return sha256Bytes(value);
}

function rawToken(value) {
  if (!isPlatformSessionToken(value)) throw inputError();
  return value;
}

function rawJti(value) {
  if (typeof value !== "string" || !UUID_V4.test(value)) throw inputError();
  return value.toLowerCase();
}

function makeClaimToken(randomBytes) {
  try {
    const value = randomBytes(32);
    if (!Buffer.isBuffer(value) && !(value instanceof Uint8Array) || value.length !== 32) throw new Error("random");
    const token = Buffer.from(value).toString("base64url");
    if (!CLAIM.test(token)) throw new Error("claim");
    return token;
  } catch {
    throw configError();
  }
}

function databaseTimestamp(value) {
  const date = value instanceof Date ? new Date(value) : new Date(String(value));
  if (!Number.isFinite(date.getTime())) throw resultError();
  return date.toISOString();
}

function normalizeFingerprint(value) {
  if (typeof value === "string" && FINGERPRINT.test(value)) return value;
  let bytes;
  if (Buffer.isBuffer(value) || value instanceof Uint8Array) bytes = Buffer.from(value);
  else if (typeof value === "string") {
    try { bytes = Buffer.from(value, "base64"); } catch { bytes = undefined; }
  }
  if (!bytes || bytes.length !== 32) throw resultError();
  return `SHA256:${bytes.toString("base64url")}`;
}

function numberValue(value) {
  const result = Number(value);
  if (!Number.isSafeInteger(result) || result < 0) throw resultError();
  return result;
}

function isDigestBytes(value) {
  return Buffer.isBuffer(value) || value instanceof Uint8Array ? value.length === 32 : DIGEST.test(String(value));
}

function sha256(value) { return crypto.createHash("sha256").update(String(value), "utf8").digest("hex"); }
function sha256Bytes(value) { return crypto.createHash("sha256").update(String(value), "utf8").digest(); }
function failClosed() { throw new PlatformAuthorizationRepositoryError(PLATFORM_AUTHORIZATION_REPOSITORY_ERROR_CODES.BINDING); }
function deepFreeze(value) { if (value && typeof value === "object" && !Object.isFrozen(value)) { Object.freeze(value); for (const child of Object.values(value)) deepFreeze(child); } return value; }
function sameKeys(value, keys) {
  const actual = Reflect.ownKeys(value);
  return actual.length === keys.length && actual.every((key) => {
    const descriptor = typeof key === "string" ? Object.getOwnPropertyDescriptor(value, key) : undefined;
    return typeof key === "string" && keys.includes(key) && descriptor?.enumerable === true && Object.hasOwn(descriptor, "value");
  });
}
function pick(value, keys) { return Object.fromEntries(keys.map((key) => [key, value[key]])); }
function isPlainObject(value) { return value !== null && typeof value === "object" && !Array.isArray(value) && (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null); }
function inputError() { return new PlatformAuthorizationRepositoryError(PLATFORM_AUTHORIZATION_REPOSITORY_ERROR_CODES.INPUT); }
function resultError() { return new PlatformAuthorizationRepositoryError(PLATFORM_AUTHORIZATION_REPOSITORY_ERROR_CODES.RESULT); }
function configError() { return new PlatformAuthorizationRepositoryError(PLATFORM_AUTHORIZATION_REPOSITORY_ERROR_CODES.CONFIG); }
function bindingError() { return new PlatformAuthorizationRepositoryError(PLATFORM_AUTHORIZATION_REPOSITORY_ERROR_CODES.BINDING); }

// Keep the old error code available to callers that use the shared issuance
// service's repository error taxonomy.
export { PLATFORM_PROMOTION_ISSUANCE_ERROR_CODES };
