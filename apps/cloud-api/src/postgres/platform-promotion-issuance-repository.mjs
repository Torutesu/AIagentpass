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
import { canonicalManagedSignerRequestDigest } from "./managed-signer-key-lifecycle-repository.mjs";
import { withTransaction } from "./repository.mjs";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,254}$/u;
const CANDIDATE = /^release-pkg-sha256-v1-[0-9a-f]{64}$/u;
const IDEMPOTENCY = /^[A-Za-z0-9][A-Za-z0-9._~:-]{7,254}$/u;
const CLAIM = /^[A-Za-z0-9_-]{43}$/u;
const DIGEST = /^[0-9a-f]{64}$/u;
const FINGERPRINT = /^SHA256:[A-Za-z0-9_-]{43}$/u;
const TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u;
const ENVIRONMENTS = new Set(["staging", "production"]);
const STATES = new Set(["reserved", "uncertain", "committed"]);
const UNCERTAINTY_REASONS = new Set([
  "signer_failure", "stale_lifecycle", "signer_output", "commit_failure", "verification_failure"
]);
const IDENTITY_KEYS = Object.freeze(["promotion_id", "deployment_id", "environment", "candidate_id", "idempotency_key"]);
const COMMIT_KEYS = Object.freeze([...IDENTITY_KEYS, "claim_token", "promotion_evidence"]);
const UNCERTAIN_KEYS = Object.freeze([...IDENTITY_KEYS, "claim_token", "reason"]);
const AUTHORITY_SQL = Object.freeze({
  reserve: `SELECT agentpass_platform_promotion_issuance_reserve(
    $1::uuid,$2::text,$3::text,$4::text,$5::text,$6::bytea,$7::integer,$8::integer,
    $9::text,$10::bigint,$11::bigint) AS result`,
  replay: `SELECT agentpass_platform_promotion_issuance_replay(
    $1::uuid,$2::text,$3::text,$4::text,$5::text) AS result`,
  commit: `SELECT agentpass_platform_promotion_issuance_commit(
    $1::uuid,$2::text,$3::text,$4::text,$5::text,$6::bytea,$7::bytea,$8::bytea,$9::bytea,$10::bytea) AS result`,
  uncertain: `SELECT agentpass_platform_promotion_issuance_uncertain(
    $1::uuid,$2::text,$3::text,$4::text,$5::text,$6::bytea,$7::text) AS result`,
  get: `SELECT agentpass_platform_promotion_issuance_get(
    $1::uuid,$2::text,$3::text,$4::text,$5::text,$6::boolean) AS result`
});

export const PLATFORM_PROMOTION_ISSUANCE_ERROR_CODES = Object.freeze({
  CONFIG: "ERR_PLATFORM_PROMOTION_ISSUANCE_CONFIG",
  INPUT: "ERR_PLATFORM_PROMOTION_ISSUANCE_INPUT",
  CONFLICT: "ERR_PLATFORM_PROMOTION_ISSUANCE_CONFLICT",
  NOT_FOUND: "ERR_PLATFORM_PROMOTION_ISSUANCE_NOT_FOUND",
  IN_PROGRESS: "ERR_PLATFORM_PROMOTION_ISSUANCE_IN_PROGRESS",
  CLAIM: "ERR_PLATFORM_PROMOTION_ISSUANCE_CLAIM",
  EXPIRED: "ERR_PLATFORM_PROMOTION_ISSUANCE_EXPIRED",
  AUTHORITY: "ERR_PLATFORM_PROMOTION_ISSUANCE_AUTHORITY",
  LIFECYCLE: "ERR_PLATFORM_PROMOTION_ISSUANCE_LIFECYCLE",
  EVIDENCE: "ERR_PLATFORM_PROMOTION_ISSUANCE_EVIDENCE",
  DATABASE: "ERR_PLATFORM_PROMOTION_ISSUANCE_DATABASE"
});

const MESSAGES = Object.freeze({
  [PLATFORM_PROMOTION_ISSUANCE_ERROR_CODES.CONFIG]: "platform promotion issuance repository configuration is invalid",
  [PLATFORM_PROMOTION_ISSUANCE_ERROR_CODES.INPUT]: "platform promotion issuance input is invalid",
  [PLATFORM_PROMOTION_ISSUANCE_ERROR_CODES.CONFLICT]: "platform promotion issuance conflicts with durable state",
  [PLATFORM_PROMOTION_ISSUANCE_ERROR_CODES.NOT_FOUND]: "platform promotion issuance was not found",
  [PLATFORM_PROMOTION_ISSUANCE_ERROR_CODES.IN_PROGRESS]: "platform promotion issuance is already in progress",
  [PLATFORM_PROMOTION_ISSUANCE_ERROR_CODES.CLAIM]: "platform promotion issuance claim is invalid or expired",
  [PLATFORM_PROMOTION_ISSUANCE_ERROR_CODES.EXPIRED]: "platform promotion approval or claim has expired",
  [PLATFORM_PROMOTION_ISSUANCE_ERROR_CODES.AUTHORITY]: "platform promotion approval authority is unavailable",
  [PLATFORM_PROMOTION_ISSUANCE_ERROR_CODES.LIFECYCLE]: "platform promotion signer lifecycle is unavailable",
  [PLATFORM_PROMOTION_ISSUANCE_ERROR_CODES.EVIDENCE]: "platform promotion evidence is invalid",
  [PLATFORM_PROMOTION_ISSUANCE_ERROR_CODES.DATABASE]: "platform promotion issuance storage is unavailable"
});

export class PlatformPromotionIssuanceRepositoryError extends Error {
  constructor(code) {
    super(MESSAGES[code] ?? MESSAGES[PLATFORM_PROMOTION_ISSUANCE_ERROR_CODES.DATABASE]);
    this.name = "PlatformPromotionIssuanceRepositoryError";
    this.code = Object.hasOwn(MESSAGES, code) ? code : PLATFORM_PROMOTION_ISSUANCE_ERROR_CODES.DATABASE;
  }
}

export function createPostgresPlatformPromotionIssuanceRepository({
  client,
  claimLeaseMs = 60_000,
  evidenceTtlMs = PROMOTION_EVIDENCE_V3_MAX_TTL_MS,
  keyId = undefined,
  keyVersion = undefined,
  lifecycleVersion = undefined,
  randomBytes = crypto.randomBytes,
  verifyEvidence = undefined
} = {}) {
  if (!client || typeof client.query !== "function" || typeof randomBytes !== "function"
    || !Number.isSafeInteger(claimLeaseMs) || claimLeaseMs < 1_000 || claimLeaseMs > 300_000
    || !Number.isSafeInteger(evidenceTtlMs) || evidenceTtlMs < 1 || evidenceTtlMs > PROMOTION_EVIDENCE_V3_MAX_TTL_MS
    || claimLeaseMs > evidenceTtlMs
    || (keyId !== undefined && !IDENTIFIER.test(keyId))
    || (keyVersion !== undefined && (!Number.isSafeInteger(keyVersion) || keyVersion < 1))
    || (lifecycleVersion !== undefined && (!Number.isSafeInteger(lifecycleVersion) || lifecycleVersion < 1))
    || typeof verifyEvidence !== "function") {
    throw new PlatformPromotionIssuanceRepositoryError(PLATFORM_PROMOTION_ISSUANCE_ERROR_CODES.CONFIG);
  }

  async function reservePlatformPromotion(input = {}) {
    const identity = normalizeIdentity(input);
    try {
      return await withTransaction(client, async (tx) => {
        const token = makeToken(randomBytes);
        const value = await callAuthority(tx, AUTHORITY_SQL.reserve, [
          identity.promotion_id, identity.deployment_id, identity.environment, identity.candidate_id,
          identity.idempotency_key, Buffer.from(sha256(token), "hex"), claimLeaseMs, evidenceTtlMs,
          keyId ?? null, keyVersion ?? null, lifecycleVersion ?? null
        ]);
        if (value?.state === "reserved" && value.claim_issued !== true) return { state: "in_progress" };
        if (value?.state === "uncertain") return { state: "uncertain" };
        const row = normalizeAuthorityResult(value, value?.claim_issued === true ? token : undefined);
        if (row.state === "committed") return verifyCommittedOutcome(row, true, verifyEvidence, evidenceTtlMs);
        if (row.state !== "reserved" || value.claim_issued !== true) throw repoError("DATABASE");
        return reservedOutcome(row, token);
      });
    } catch (error) { throw publicError(error); }
  }

  async function replayPlatformPromotion(input = {}) {
    const identity = normalizeIdentity(input);
    try {
      return await withTransaction(client, async (tx) => {
        const value = await callAuthority(tx, AUTHORITY_SQL.replay, identityParams(identity));
        if (["absent", "in_progress", "uncertain"].includes(value?.state)) return { state: value.state };
        return verifyCommittedOutcome(normalizeAuthorityResult(value), true, verifyEvidence, evidenceTtlMs);
      });
    } catch (error) { throw publicError(error); }
  }

  async function commitPlatformPromotion(input = {}) {
    const values = normalizeClaimedInput(input, COMMIT_KEYS);
    let evidence;
    try {
      evidence = normalizeEvidence(input.promotion_evidence);
    } catch { throw repoError("EVIDENCE"); }
    try {
      return await withTransaction(client, async (tx) => {
        const current = await callAuthority(tx, AUTHORITY_SQL.get, [...identityParams(values), false]);
        if (current === null) throw repoError("NOT_FOUND");
        const row = normalizeAuthorityResult(current, current.state === "reserved" ? values.claim_token : undefined);
        if (row.state === "committed") {
          assertEvidenceMatches(evidence, row);
          return verifyCommittedOutcome(row, true, verifyEvidence, evidenceTtlMs);
        }
        if (row.state === "uncertain") return { state: "uncertain" };
        if (row.state !== "reserved") throw repoError("DATABASE");
        assertEvidenceMatches(evidence, row);
        if ((await verifyEvidence(evidence, verificationContext(row, evidenceTtlMs))) !== true) throw repoError("EVIDENCE");
        const canonical = canonicalizePromotionEvidenceV3(evidence, { allowExpired: true, allowFuture: true });
        const signingBytes = promotionEvidenceV3SigningData(evidence.statement, { allowExpired: true, allowFuture: true });
        const committed = await callAuthority(tx, AUTHORITY_SQL.commit, [
          ...identityParams(values), Buffer.from(sha256(values.claim_token), "hex"), signingBytes,
          Buffer.from(evidence.signature, "base64url"), Buffer.from(canonical, "utf8"), Buffer.from(sha256(canonical), "hex")
        ]);
        return verifyCommittedOutcome(normalizeAuthorityResult(committed), true, verifyEvidence, evidenceTtlMs);
      });
    } catch (error) { throw publicError(error); }
  }

  async function markPlatformPromotionUncertain(input = {}) {
    const values = normalizeClaimedInput(input, UNCERTAIN_KEYS);
    if (!UNCERTAINTY_REASONS.has(values.reason)) throw repoError("INPUT");
    try {
      return await withTransaction(client, async (tx) => {
        const value = await callAuthority(tx, AUTHORITY_SQL.uncertain, [
          ...identityParams(values), Buffer.from(sha256(values.claim_token), "hex"), values.reason
        ]);
        if (value?.state === "committed") return verifyCommittedOutcome(normalizeAuthorityResult(value), true, verifyEvidence, evidenceTtlMs);
        if (value?.state !== "uncertain") throw repoError("DATABASE");
        return { state: "uncertain" };
      });
    } catch (error) { throw publicError(error); }
  }

  async function getCommittedPlatformPromotion(input = {}) {
    const identity = normalizeIdentity(input);
    try {
      return await withTransaction(client, async (tx) => {
        const value = await callAuthority(tx, AUTHORITY_SQL.get, [...identityParams(identity), true]);
        if (value === null) throw repoError("NOT_FOUND");
        return verifyCommittedOutcome(normalizeAuthorityResult(value), true, verifyEvidence, evidenceTtlMs);
      });
    } catch (error) { throw publicError(error); }
  }

  return Object.freeze({ reservePlatformPromotion, commitPlatformPromotion, replayPlatformPromotion, markPlatformPromotionUncertain, getCommittedPlatformPromotion });
}

export const createPlatformPromotionIssuanceRepository = createPostgresPlatformPromotionIssuanceRepository;
export default createPostgresPlatformPromotionIssuanceRepository;

async function callAuthority(tx, sql, params) {
  const result = await tx.query(sql, params);
  if (rowCount(result) !== 1 || !Object.hasOwn(result.rows[0] ?? {}, "result")) throw repoError("DATABASE");
  const value = result.rows[0].result;
  if (value === null) return null;
  if (typeof value === "string") {
    try { return JSON.parse(value); } catch { throw repoError("DATABASE"); }
  }
  if (!value || typeof value !== "object" || Array.isArray(value)) throw repoError("DATABASE");
  return value;
}

function identityParams(value) {
  return [value.promotion_id, value.deployment_id, value.environment, value.candidate_id, value.idempotency_key];
}

function normalizeAuthorityResult(value, claimToken = undefined) {
  try {
    if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("result");
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
    if (error instanceof PlatformPromotionIssuanceRepositoryError) throw error;
    throw repoError("DATABASE");
  }
}

function databaseTimestamp(value) {
  const date = value instanceof Date ? new Date(value) : new Date(String(value));
  if (!Number.isFinite(date.getTime())) throw repoError("DATABASE");
  return date.toISOString();
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
      expires_at: databaseTimestamp(row.expires_at),
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
    throw repoError("DATABASE");
  }
}

function reservedOutcome(row, token) {
  const result = publicRow(row);
  if (token !== undefined) result.claim_token = token;
  return deepFreeze(result);
}

function committedOutcome(row) {
  const result = publicRow(row);
  if (row.evidence_bytes) {
    try {
      const parsed = normalizeEvidence(JSON.parse(Buffer.from(row.evidence_bytes).toString("utf8")));
      const canonical = canonicalizePromotionEvidenceV3(parsed, { allowExpired: true, allowFuture: true });
      if (sha256(canonical) !== row.evidence_digest) throw new Error("evidence digest");
      result.promotion_evidence = parsed;
    } catch { throw repoError("DATABASE"); }
  }
  return deepFreeze(result);
}

async function verifyCommittedOutcome(row, allowExpired, verifyEvidence, evidenceTtlMs) {
  const result = committedOutcome(row);
  try {
    const verified = await verifyEvidence(
      result.promotion_evidence,
      verificationContext(row, evidenceTtlMs, allowExpired)
    );
    if (verified !== true) throw repoError("EVIDENCE");
  } catch (error) {
    if (error instanceof PlatformPromotionIssuanceRepositoryError) throw error;
    throw repoError("EVIDENCE");
  }
  return result;
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
    signer_key_fingerprint: normalizeFingerprint(row.signer_key_fingerprint),
  };
}

function assertEvidenceMatches(evidence, row) {
  const statement = evidence.statement;
  const fields = ["promotion_id", "deployment_id", "environment", "candidate_id", "source_commit", "source_tree", "product_pkg_sha256", "image_digest", "sbom_sha256", "release_manifest_schema_version", "release_manifest_sha256", "platform_approval_id", "platform_approval_digest", "purpose", "protocol_version", "signing_version", "lifecycle_version", "key_id", "key_version", "issued_at", "expires_at"];
  const expected = {
    promotion_id: row.promotion_id, deployment_id: row.deployment_id, environment: row.environment, candidate_id: row.candidate_id,
    source_commit: row.source_commit, source_tree: row.source_tree, product_pkg_sha256: row.product_pkg_sha256,
    image_digest: row.image_digest, sbom_sha256: row.sbom_sha256, release_manifest_schema_version: row.release_manifest_schema_version,
    release_manifest_sha256: row.release_manifest_sha256, platform_approval_id: row.approval_id, platform_approval_digest: row.approval_digest,
    purpose: row.purpose, protocol_version: numberValue(row.protocol_version), signing_version: numberValue(row.signing_version),
    lifecycle_version: numberValue(row.lifecycle_version), key_id: row.key_id, key_version: numberValue(row.key_version)
    , issued_at: databaseTimestamp(row.issued_at), expires_at: databaseTimestamp(row.expires_at)
  };
  for (const field of fields) if (statement[field] !== expected[field]) throw repoError("CONFLICT");
  if (JSON.stringify(statement.qualification_report_digests) !== JSON.stringify(row.qualification_report_digests)) throw repoError("CONFLICT");
  if (statement.approval_state !== "approved") throw repoError("EVIDENCE");
  if (Date.parse(statement.expires_at) > Date.parse(String(row.approval_expires_at))) throw repoError("EXPIRED");
  if (evidence.signer_key_fingerprint !== row.signer_key_fingerprint) throw repoError("CONFLICT");
  if (evidence.version !== 3 || evidence.type !== "agentpass.promotion-evidence") throw repoError("EVIDENCE");
}

function verificationContext(row, maxTtlMs, allowExpired = false) {
  const context = {
    deployment_id: row.deployment_id,
    environment: row.environment,
    candidate_id: row.candidate_id,
    product_pkg_sha256: row.product_pkg_sha256,
    image_digest: row.image_digest,
    sbom_sha256: row.sbom_sha256,
    platform_approval_id: row.approval_id,
    platform_approval_digest: row.approval_digest,
    source_commit: row.source_commit,
    source_tree: row.source_tree,
    release_manifest_sha256: row.release_manifest_sha256,
    release_manifest_schema_version: row.release_manifest_schema_version,
    qualification_report_digests: row.qualification_report_digests,
    purpose: row.purpose,
    protocol_version: numberValue(row.protocol_version),
    signing_version: numberValue(row.signing_version),
    key_id: row.key_id,
    key_version: numberValue(row.key_version),
    lifecycle_version: numberValue(row.lifecycle_version),
    signer_key_fingerprint: normalizeFingerprint(row.signer_key_fingerprint),
    allowExpired: allowExpired === true,
    maxTtlMs
  };
  if (!Number.isSafeInteger(maxTtlMs) || maxTtlMs < 1 || maxTtlMs > PROMOTION_EVIDENCE_V3_MAX_TTL_MS
    || !context.signer_key_fingerprint || Object.values(context).some((value) => value === undefined || value === null)) {
    throw repoError("EVIDENCE");
  }
  return Object.freeze({ ...context, qualification_report_digests: Object.freeze([...context.qualification_report_digests]) });
}

function normalizeEvidence(value) {
  if (typeof value === "string" || Buffer.isBuffer(value)) return normalizePromotionEvidenceV3(JSON.parse(Buffer.from(value).toString("utf8")), { allowExpired: true, allowFuture: true });
  return normalizePromotionEvidenceV3(value, { allowExpired: true, allowFuture: true });
}

function normalizeIdentity(input) { return normalizeObject(input, IDENTITY_KEYS); }

function normalizeClaimedInput(input, keys) {
  const value = normalizeObject(input, keys);
  if (!CLAIM.test(value.claim_token)) throw repoError("INPUT");
  return value;
}

function normalizeObject(input, keys) {
  if (!input || typeof input !== "object" || Array.isArray(input)) throw repoError("INPUT");
  const actual = Reflect.ownKeys(input);
  if (actual.some((key) => typeof key !== "string" || !keys.includes(key))) throw repoError("INPUT");
  for (const key of actual) if (!Object.prototype.propertyIsEnumerable.call(input, key)) throw repoError("INPUT");
  for (const key of keys) if (!Object.hasOwn(input, key) && !["provider_operation_id"].includes(key)) throw repoError("INPUT");
  const value = { ...input };
  if (!UUID.test(value.promotion_id) || !IDENTIFIER.test(value.deployment_id) || !ENVIRONMENTS.has(value.environment)
    || !CANDIDATE.test(value.candidate_id) || !IDEMPOTENCY.test(value.idempotency_key)) throw repoError("INPUT");
  return value;
}

function makeToken(randomBytes) {
  const value = randomBytes(32);
  if (!Buffer.isBuffer(value) || value.length !== 32) throw repoError("CONFIG");
  return value.toString("base64url");
}
function sha256(value) { return crypto.createHash("sha256").update(String(value), "utf8").digest("hex"); }
function numberValue(value) { const result = Number(value); if (!Number.isSafeInteger(result) || result < 0) throw repoError("DATABASE"); return result; }
function normalizeStoredRow(row) {
  try {
    if (!row || typeof row !== "object" || Array.isArray(row)) throw new Error("row");
    if (!UUID.test(String(row.promotion_id)) || !IDENTIFIER.test(String(row.deployment_id))
      || !ENVIRONMENTS.has(row.environment) || !CANDIDATE.test(String(row.candidate_id))
      || !IDEMPOTENCY.test(String(row.idempotency_key)) || !STATES.has(row.state)) throw new Error("identity");
    if (!UUID.test(String(row.approval_id)) || !DIGEST.test(String(row.approval_digest))
      || !/^[0-9a-f]{40}$/u.test(String(row.source_commit)) || !/^[0-9a-f]{40}$/u.test(String(row.source_tree))
      || !DIGEST.test(String(row.product_pkg_sha256)) || !/^sha256:[0-9a-f]{64}$/u.test(String(row.image_digest))
      || !DIGEST.test(String(row.sbom_sha256)) || String(row.candidate_id) !== `release-pkg-sha256-v1-${row.product_pkg_sha256}`
      || !Array.isArray(row.qualification_report_digests) || row.qualification_report_digests.length < 1
      || row.qualification_report_digests.length > 16
      || row.qualification_report_digests.some((value, index, values) => !DIGEST.test(String(value))
        || (index > 0 && String(values[index - 1]) >= String(value)))
      || numberValue(row.release_manifest_schema_version) !== 4 || !DIGEST.test(String(row.release_manifest_sha256))
      || !TIMESTAMP.test(databaseTimestamp(row.approval_expires_at)) || !TIMESTAMP.test(databaseTimestamp(row.issued_at))
      || !TIMESTAMP.test(databaseTimestamp(row.expires_at)) || !TIMESTAMP.test(databaseTimestamp(row.created_at))
      || !TIMESTAMP.test(databaseTimestamp(row.updated_at)) || !FINGERPRINT.test(normalizeFingerprint(row.signer_key_fingerprint))
      || row.purpose !== PROMOTION_EVIDENCE_V3_PURPOSE || numberValue(row.protocol_version) !== 3
      || numberValue(row.signing_version) !== 3 || numberValue(row.lifecycle_version) < 1
      || !IDENTIFIER.test(String(row.key_id)) || numberValue(row.key_version) < 1
      || !IDENTIFIER.test(String(row.provider_operation_id)) || !isDigestBytes(row.request_digest)) throw new Error("authority");
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
      evidence_digest: row.evidence_digest ? String(row.evidence_digest).toLowerCase() : null,
    };
    if (Date.parse(normalized.approval_expires_at) <= Date.parse(normalized.created_at)
      || Date.parse(normalized.expires_at) <= Date.parse(normalized.issued_at)
      || Date.parse(normalized.expires_at) > Date.parse(normalized.approval_expires_at)
      || Date.parse(normalized.expires_at) - Date.parse(normalized.issued_at) > PROMOTION_EVIDENCE_V3_MAX_TTL_MS) throw new Error("window");
    if (normalized.state === "reserved") {
      if (!DIGEST.test(normalized.claim_token_digest ?? "") || normalized.claim_expires_at === null || normalized.claim_expires_at === undefined
        || Date.parse(databaseTimestamp(normalized.claim_expires_at)) <= Date.parse(normalized.created_at)
        || normalized.evidence_bytes !== null && normalized.evidence_bytes !== undefined
        || normalized.evidence_digest !== null || normalized.deployment_generation !== null
        || normalized.uncertain_reason !== null) throw new Error("reserved");
    } else {
      if (normalized.claim_token_digest !== null || normalized.claim_expires_at !== null && normalized.claim_expires_at !== undefined) throw new Error("released claim");
      if (normalized.state === "uncertain") {
        if (!UNCERTAINTY_REASONS.has(normalized.uncertain_reason) || normalized.evidence_bytes !== null && normalized.evidence_bytes !== undefined
          || normalized.evidence_digest !== null || normalized.deployment_generation !== null) throw new Error("uncertain");
      } else if (normalized.state === "committed") {
        if (!normalized.evidence_bytes || normalized.evidence_bytes.length < 1 || normalized.evidence_bytes.length > 131072
          || !DIGEST.test(normalized.evidence_digest ?? "") || numberValue(normalized.deployment_generation) < 1
          || normalized.uncertain_reason !== null) throw new Error("committed");
      }
    }
    if (normalized.provider_operation_id !== deriveProviderOperationId(normalized)) throw new Error("provider operation");
    return normalized;
  } catch (error) {
    if (error instanceof PlatformPromotionIssuanceRepositoryError) throw error;
    throw repoError("DATABASE");
  }
}

function isDigestBytes(value) {
  return (Buffer.isBuffer(value) || value instanceof Uint8Array) ? value.length === 32 : DIGEST.test(String(value));
}

function normalizeFingerprint(value) {
  if (typeof value === "string" && FINGERPRINT.test(value)) return value;
  let bytes;
  if (Buffer.isBuffer(value) || value instanceof Uint8Array) bytes = Buffer.from(value);
  else if (typeof value === "string") {
    try { bytes = Buffer.from(value, "base64"); } catch { bytes = undefined; }
  }
  if (!bytes || bytes.length !== 32) throw repoError("DATABASE");
  return `SHA256:${bytes.toString("base64url")}`;
}

function rowCount(result) { return Number(result?.rowCount ?? result?.rows?.length ?? 0); }
function repoError(name) { const code = PLATFORM_PROMOTION_ISSUANCE_ERROR_CODES[name] ?? PLATFORM_PROMOTION_ISSUANCE_ERROR_CODES.DATABASE; return new PlatformPromotionIssuanceRepositoryError(code); }
function publicError(error) { if (error instanceof PlatformPromotionIssuanceRepositoryError) return error; return repoError("DATABASE"); }
function deepFreeze(value) { if (value && typeof value === "object" && !Object.isFrozen(value)) { Object.freeze(value); for (const child of Object.values(value)) deepFreeze(child); } return value; }
