import crypto from "node:crypto";

import { canonicalJson } from "../../../../packages/protocol/src/index.mjs";
import {
  canonicalizePromotionEvidenceV3,
  normalizePromotionEvidenceV3
} from "../promotion-evidence-v3-statement.mjs";
import { withTransaction } from "./repository.mjs";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,254}$/u;
const CANDIDATE = /^release-pkg-sha256-v1-[0-9a-f]{64}$/u;
const IDEMPOTENCY = /^[A-Za-z0-9][A-Za-z0-9._~:-]{7,254}$/u;
const CLAIM = /^[A-Za-z0-9_-]{43}$/u;
const DIGEST = /^[0-9a-f]{64}$/u;
const ENVIRONMENTS = new Set(["staging", "production"]);
const UNCERTAINTY_REASONS = new Set([
  "provider_timeout", "provider_response_lost", "commit_response_lost",
  "stale_claim", "stale_lifecycle", "disabled_lifecycle", "database_failure"
]);
const IDENTITY_KEYS = Object.freeze(["promotion_id", "deployment_id", "environment", "candidate_id", "idempotency_key"]);
const COMMIT_KEYS = Object.freeze([...IDENTITY_KEYS, "claim_token", "evidence", "provider_operation_id"]);
const UNCERTAIN_KEYS = Object.freeze([...IDENTITY_KEYS, "claim_token", "reason"]);
const ROW_SELECT = `promotion_id,deployment_id,environment,candidate_id,idempotency_key,state,
  approval_id,approval_digest,source_commit,source_tree,product_pkg_sha256,image_digest,sbom_sha256,
  qualification_report_digests,release_manifest_schema_version,release_manifest_sha256,approval_expires_at,
  purpose,protocol_version,signing_version,lifecycle_version,key_id,key_version,provider_operation_id,
  request_digest,encode(claim_token_digest,'hex') AS claim_token_digest,claim_expires_at,
  encode(evidence_digest,'hex') AS evidence_digest,evidence_bytes,deployment_generation,uncertain_reason,
  created_at,updated_at`;

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
  keyId = undefined,
  keyVersion = undefined,
  lifecycleVersion = undefined,
  randomBytes = crypto.randomBytes,
  verifyEvidence = undefined
} = {}) {
  if (!client || typeof client.query !== "function" || typeof randomBytes !== "function"
    || !Number.isSafeInteger(claimLeaseMs) || claimLeaseMs < 1_000 || claimLeaseMs > 300_000
    || (keyId !== undefined && !IDENTIFIER.test(keyId))
    || (keyVersion !== undefined && (!Number.isSafeInteger(keyVersion) || keyVersion < 1))
    || (lifecycleVersion !== undefined && (!Number.isSafeInteger(lifecycleVersion) || lifecycleVersion < 1))
    || (verifyEvidence !== undefined && typeof verifyEvidence !== "function")) {
    throw new PlatformPromotionIssuanceRepositoryError(PLATFORM_PROMOTION_ISSUANCE_ERROR_CODES.CONFIG);
  }

  async function reservePlatformPromotion(input = {}) {
    const identity = normalizeIdentity(input);
    try {
      return await withTransaction(client, async (tx) => {
        await lockDeployment(tx, identity);
        const existing = await selectIssuance(tx, identity, true);
        if (existing) {
          assertIdentity(existing, identity);
          if (existing.state === "reserved" && !(await claimStillActive(tx, existing))) {
            const token = makeToken(randomBytes);
            const reclaimed = await tx.query(`UPDATE platform_promotion_issuances
              SET claim_token_digest=$2,claim_expires_at=clock_timestamp()+($3 * interval '1 millisecond')
              WHERE promotion_id=$1 AND state='reserved' AND claim_expires_at<=clock_timestamp()
              RETURNING ${ROW_SELECT}`, [existing.promotion_id, Buffer.from(sha256(token), "hex"), claimLeaseMs]);
            if (rowCount(reclaimed) !== 1) throw repoError("IN_PROGRESS");
            return reservedOutcome(normalizeStoredRow(reclaimed.rows[0]), token);
          }
          return existingOutcome(existing, identity);
        }

        await tx.query(`INSERT INTO platform_promotion_deployments
          (deployment_id,environment,current_generation,current_candidate_id)
          VALUES ($1,$2,0,NULL) ON CONFLICT (deployment_id,environment) DO NOTHING`, [identity.deployment_id, identity.environment]);
        const head = await selectHead(tx, identity, true);
        if (!head) throw repoError("DATABASE");
        const open = await selectOpenIssuance(tx, identity);
        if (open) return open.state === "uncertain" ? { state: "uncertain" } : { state: "in_progress" };

        const authority = await selectAuthority(tx, identity, { keyId, keyVersion, lifecycleVersion });
        if (!authority) throw repoError("AUTHORITY");
        const token = makeToken(randomBytes);
        const requestDigest = sha256(canonicalJson({
          version: 1,
          promotion_id: identity.promotion_id,
          deployment_id: identity.deployment_id,
          environment: identity.environment,
          candidate_id: identity.candidate_id,
          idempotency_key: identity.idempotency_key,
          approval_id: authority.approval_id,
          approval_digest: authority.approval_digest,
          source_commit: authority.source_commit,
          source_tree: authority.source_tree,
          product_pkg_sha256: authority.product_pkg_sha256,
          image_digest: authority.image_digest,
          sbom_sha256: authority.sbom_sha256,
          release_manifest_sha256: authority.release_manifest_sha256,
          qualification_report_digests: authority.qualification_report_digests,
          lifecycle_version: numberValue(authority.lifecycle_version),
          key_id: authority.key_id,
          key_version: numberValue(authority.key_version)
        }));
        const providerOperationId = `platform-promotion-v3-${identity.promotion_id}`;
        const inserted = await tx.query(`INSERT INTO platform_promotion_issuances
          (promotion_id,deployment_id,environment,candidate_id,idempotency_key,state,
           approval_id,approval_digest,source_commit,source_tree,product_pkg_sha256,image_digest,sbom_sha256,
           qualification_report_digests,release_manifest_schema_version,release_manifest_sha256,approval_expires_at,
           purpose,protocol_version,signing_version,lifecycle_version,key_id,key_version,provider_operation_id,
           request_digest,claim_token_digest,claim_expires_at)
          VALUES ($1,$2,$3,$4,$5,'reserved',$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,
           'agentpass.promotion-evidence',3,3,$17,$18,$19,$20,$21,$22,clock_timestamp()+($23 * interval '1 millisecond'))
          ON CONFLICT DO NOTHING`, [
          identity.promotion_id, identity.deployment_id, identity.environment, identity.candidate_id, identity.idempotency_key,
          authority.approval_id, authority.approval_digest, authority.source_commit, authority.source_tree,
          authority.product_pkg_sha256, authority.image_digest, authority.sbom_sha256, authority.qualification_report_digests,
          authority.release_manifest_schema_version, authority.release_manifest_sha256, authority.approval_expires_at,
          authority.lifecycle_version, authority.key_id, authority.key_version, providerOperationId,
          Buffer.from(requestDigest, "hex"), Buffer.from(sha256(token), "hex"), claimLeaseMs
        ]);
        if (rowCount(inserted) === 0) {
          const raced = await selectIssuance(tx, identity, true);
          if (!raced) throw repoError("DATABASE");
          assertIdentity(raced, identity);
          return existingOutcome(raced, identity);
        }
        const row = await selectIssuance(tx, identity, true);
        if (!row) throw repoError("DATABASE");
        return reservedOutcome(row, token);
      });
    } catch (error) { throw publicError(error); }
  }

  async function replayPlatformPromotion(input = {}) {
    const identity = normalizeIdentity(input);
    try {
      return await withTransaction(client, async (tx) => {
        const row = await selectIssuance(tx, identity, false);
        if (!row) return { state: "absent" };
        assertIdentity(row, identity);
        if (row.state === "committed") return committedOutcome(row);
        if (row.state === "uncertain") return { state: "uncertain" };
        const active = await claimStillActive(tx, row);
        return active ? { state: "in_progress" } : { state: "absent" };
      });
    } catch (error) { throw publicError(error); }
  }

  async function commitPlatformPromotion(input = {}) {
    const values = normalizeClaimedInput(input, COMMIT_KEYS);
    let evidence;
    try {
      evidence = normalizeEvidence(input.evidence);
    } catch { throw repoError("EVIDENCE"); }
    try {
      if (verifyEvidence !== undefined && (await verifyEvidence(evidence)) !== true) throw repoError("EVIDENCE");
      return await withTransaction(client, async (tx) => {
        await lockDeployment(tx, values);
        const row = await selectIssuance(tx, values, true);
        if (!row) throw repoError("NOT_FOUND");
        assertIdentity(row, values);
        if (row.state === "committed") {
          assertEvidenceMatches(evidence, row);
          return committedOutcome(row);
        }
        if (row.state === "uncertain") return { state: "uncertain" };
        if (row.state !== "reserved") throw repoError("DATABASE");
        if (!claimMatches(row, values.claim_token)) throw repoError("CLAIM");
        assertEvidenceMatches(evidence, row);
        const lifecycle = await selectActiveLifecycle(tx, row);
        if (!lifecycle) throw repoError("LIFECYCLE");
        if (values.provider_operation_id !== undefined && values.provider_operation_id !== row.provider_operation_id) throw repoError("CONFLICT");
        const head = await selectHead(tx, values, true);
        if (!head) throw repoError("DATABASE");
        const nextGeneration = numberValue(head.current_generation) + 1;
        const canonical = canonicalizePromotionEvidenceV3(evidence, { allowExpired: true, allowFuture: true });
        const updated = await tx.query(`UPDATE platform_promotion_issuances
          SET state='committed',evidence_bytes=$3,evidence_digest=$4,deployment_generation=$5,
              claim_token_digest=NULL,claim_expires_at=NULL,uncertain_reason=NULL
          WHERE promotion_id=$1 AND state='reserved' AND claim_token_digest=$2
            AND claim_expires_at>clock_timestamp() AND approval_expires_at>clock_timestamp()
          RETURNING ${ROW_SELECT}`, [
          values.promotion_id, Buffer.from(sha256(values.claim_token), "hex"), Buffer.from(canonical, "utf8"),
          Buffer.from(sha256(canonical), "hex"), nextGeneration
        ]);
        if (rowCount(updated) !== 1) {
          if (Date.parse(String(row.approval_expires_at)) <= Date.now()) throw repoError("EXPIRED");
          throw repoError("CLAIM");
        }
        const advanced = await tx.query(`UPDATE platform_promotion_deployments
          SET current_generation=$3,current_candidate_id=$4
          WHERE deployment_id=$1 AND environment=$2 AND current_generation=$5
          RETURNING deployment_id,environment,current_generation,current_candidate_id`, [
          values.deployment_id, values.environment, nextGeneration, row.candidate_id, numberValue(head.current_generation)
        ]);
        if (rowCount(advanced) !== 1) throw repoError("DATABASE");
        return committedOutcome(normalizeStoredRow(updated.rows[0]));
      });
    } catch (error) { throw publicError(error); }
  }

  async function markPlatformPromotionUncertain(input = {}) {
    const values = normalizeClaimedInput(input, UNCERTAIN_KEYS);
    if (!UNCERTAINTY_REASONS.has(values.reason)) throw repoError("INPUT");
    try {
      return await withTransaction(client, async (tx) => {
        await lockDeployment(tx, values);
        const row = await selectIssuance(tx, values, true);
        if (!row) throw repoError("NOT_FOUND");
        assertIdentity(row, values);
        if (row.state === "committed") return committedOutcome(row);
        if (row.state === "uncertain") return { state: "uncertain" };
        if (!claimMatches(row, values.claim_token)) throw repoError("CLAIM");
        const updated = await tx.query(`UPDATE platform_promotion_issuances
          SET state='uncertain',claim_token_digest=NULL,claim_expires_at=NULL,uncertain_reason=$2
          WHERE promotion_id=$1 AND state='reserved' AND claim_token_digest=$3
            AND claim_expires_at>clock_timestamp()
          RETURNING ${ROW_SELECT}`, [values.promotion_id, values.reason, Buffer.from(sha256(values.claim_token), "hex")]);
        if (rowCount(updated) !== 1) throw repoError("CLAIM");
        return { state: "uncertain" };
      });
    } catch (error) { throw publicError(error); }
  }

  async function getCommittedPlatformPromotion(input = {}) {
    const identity = normalizeIdentity(input);
    try {
      return await withTransaction(client, async (tx) => {
        const row = await selectIssuance(tx, identity, false, true);
        if (!row) throw repoError("NOT_FOUND");
        assertIdentity(row, identity);
        return committedOutcome(row);
      });
    } catch (error) { throw publicError(error); }
  }

  return Object.freeze({ reservePlatformPromotion, commitPlatformPromotion, replayPlatformPromotion, markPlatformPromotionUncertain, getCommittedPlatformPromotion });
}

export const createPlatformPromotionIssuanceRepository = createPostgresPlatformPromotionIssuanceRepository;
export default createPostgresPlatformPromotionIssuanceRepository;

async function selectIssuance(tx, identity, forUpdate, committedOnly = false) {
  const result = await tx.query(`SELECT ${ROW_SELECT}
    FROM platform_promotion_issuances
    WHERE (promotion_id=$1 OR (deployment_id=$2 AND environment=$3 AND candidate_id=$4 AND idempotency_key=$5))${committedOnly ? " AND state='committed'" : ""}${forUpdate ? " FOR UPDATE" : ""}`,
  [identity.promotion_id, identity.deployment_id, identity.environment, identity.candidate_id, identity.idempotency_key]);
  if (rowCount(result) > 1) throw repoError("DATABASE");
  return rowCount(result) === 1 ? normalizeStoredRow(result.rows[0]) : undefined;
}

async function selectAuthority(tx, identity, signer = {}) {
  const result = await tx.query(`SELECT approval.approval_id,approval.record_digest AS approval_digest,
      approval.source_commit,approval.source_tree,approval.product_pkg_sha256,approval.image_digest,
      approval.sbom_sha256,approval.qualification_report_digests,approval.release_manifest_schema_version,
      approval.release_manifest_sha256,approval.expires_at AS approval_expires_at,
      candidate.candidate_id,candidate.source_commit AS candidate_source_commit,
      candidate.artifact_sha256,candidate.manifest_sha256,
      lifecycle.version AS lifecycle_version,key.key_id,key.key_version
    FROM platform_promotion_approvals approval
    JOIN release_candidates candidate
      ON candidate.candidate_id=approval.candidate_id
     AND candidate.source_commit=approval.source_commit
     AND candidate.artifact_sha256=approval.product_pkg_sha256
     AND candidate.manifest_sha256=approval.release_manifest_sha256
     AND candidate.status='active'
    JOIN managed_signer_key_lifecycles lifecycle ON lifecycle.purpose='agentpass.promotion-evidence'
    JOIN managed_signer_keys key
      ON key.purpose=lifecycle.purpose AND key.state='active'
     AND key.algorithm='ed25519' AND key.key_version > 0
    WHERE approval.deployment_id=$1 AND approval.environment=$2 AND approval.candidate_id=$3
      AND approval.decision='approved' AND approval.quorum_satisfied IS TRUE
      AND approval.expires_at>clock_timestamp()
      AND ($4::text IS NULL OR key.key_id=$4)
      AND ($5::bigint IS NULL OR key.key_version=$5)
      AND ($6::bigint IS NULL OR lifecycle.version=$6)
    ORDER BY approval.expires_at DESC,approval.approval_version DESC,approval.approval_id
    LIMIT 1`, [identity.deployment_id, identity.environment, identity.candidate_id,
      signer.keyId ?? null, signer.keyVersion ?? null, signer.lifecycleVersion ?? null]);
  return rowCount(result) === 1 ? result.rows[0] : undefined;
}

async function selectActiveLifecycle(tx, row) {
  const result = await tx.query(`SELECT lifecycle.version AS lifecycle_version,key.key_id,key.key_version,key.state
    FROM managed_signer_key_lifecycles lifecycle
    JOIN managed_signer_keys key ON key.purpose=lifecycle.purpose
      AND key.key_id=$1 AND key.key_version=$2 AND key.state='active'
    WHERE lifecycle.purpose=$3 AND lifecycle.version=$4 AND lifecycle.algorithm='ed25519'`,
  [row.key_id, numberValue(row.key_version), row.purpose, numberValue(row.lifecycle_version)]);
  return rowCount(result) === 1 ? result.rows[0] : undefined;
}

async function selectHead(tx, identity, forUpdate) {
  const result = await tx.query(`SELECT deployment_id,environment,current_generation,current_candidate_id
    FROM platform_promotion_deployments WHERE deployment_id=$1 AND environment=$2${forUpdate ? " FOR UPDATE" : ""}`,
  [identity.deployment_id, identity.environment]);
  return rowCount(result) === 1 ? result.rows[0] : undefined;
}

async function selectOpenIssuance(tx, identity) {
  const result = await tx.query(`SELECT ${ROW_SELECT}
    FROM platform_promotion_issuances
    WHERE deployment_id=$1 AND environment=$2 AND state IN ('reserved','uncertain')
    ORDER BY created_at ASC,promotion_id
    LIMIT 1 FOR UPDATE`, [identity.deployment_id, identity.environment]);
  if (rowCount(result) > 1) throw repoError("DATABASE");
  return rowCount(result) === 1 ? normalizeStoredRow(result.rows[0]) : undefined;
}

async function lockDeployment(tx, identity) {
  const result = await tx.query("SELECT pg_advisory_xact_lock(hashtextextended($1,0)) AS locked", [`agentpass:platform-promotion:${identity.deployment_id}:${identity.environment}`]);
  if (rowCount(result) !== 1) throw repoError("DATABASE");
}

async function claimStillActive(tx, row) {
  const result = await tx.query(`SELECT claim_expires_at>clock_timestamp() AS claim_active
    FROM platform_promotion_issuances WHERE promotion_id=$1 AND state='reserved'`, [row.promotion_id]);
  return rowCount(result) === 1 && result.rows[0].claim_active === true;
}

function existingOutcome(row, identity) {
  assertIdentity(row, identity);
  if (row.state === "committed") return committedOutcome(row);
  if (row.state === "uncertain") return { state: "uncertain" };
  if (row.claim_expires_at && Date.parse(String(row.claim_expires_at)) > Date.now()) return { state: "in_progress" };
  // A stale reservation is reclaimed by the caller through the normal reserve
  // path; this branch is reached only by a race that inserted the row.
  return { state: "in_progress" };
}

function reservedOutcome(row, token) {
  const result = publicRow(row);
  if (token !== undefined) result.claim_token = token;
  return deepFreeze(result);
}

function committedOutcome(row) {
  const result = publicRow(row);
  if (row.evidence_bytes) {
    try { result.evidence = JSON.parse(Buffer.from(row.evidence_bytes).toString("utf8")); }
    catch { throw repoError("DATABASE"); }
  }
  return deepFreeze(result);
}

function publicRow(row) {
  const result = { ...row };
  delete result.claim_token_digest;
  delete result.evidence_bytes;
  delete result.request_digest;
  if (result.key_version !== undefined) result.key_version = numberValue(result.key_version);
  if (result.lifecycle_version !== undefined) result.lifecycle_version = numberValue(result.lifecycle_version);
  if (result.deployment_generation !== null && result.deployment_generation !== undefined) result.deployment_generation = numberValue(result.deployment_generation);
  return result;
}

function assertEvidenceMatches(evidence, row) {
  const statement = evidence.statement;
  const fields = ["promotion_id", "deployment_id", "environment", "candidate_id", "source_commit", "source_tree", "product_pkg_sha256", "image_digest", "sbom_sha256", "release_manifest_schema_version", "release_manifest_sha256", "platform_approval_id", "platform_approval_digest", "purpose", "protocol_version", "signing_version", "lifecycle_version", "key_id", "key_version"];
  const expected = {
    promotion_id: row.promotion_id, deployment_id: row.deployment_id, environment: row.environment, candidate_id: row.candidate_id,
    source_commit: row.source_commit, source_tree: row.source_tree, product_pkg_sha256: row.product_pkg_sha256,
    image_digest: row.image_digest, sbom_sha256: row.sbom_sha256, release_manifest_schema_version: row.release_manifest_schema_version,
    release_manifest_sha256: row.release_manifest_sha256, platform_approval_id: row.approval_id, platform_approval_digest: row.approval_digest,
    purpose: row.purpose, protocol_version: numberValue(row.protocol_version), signing_version: numberValue(row.signing_version),
    lifecycle_version: numberValue(row.lifecycle_version), key_id: row.key_id, key_version: numberValue(row.key_version)
  };
  for (const field of fields) if (statement[field] !== expected[field]) throw repoError("CONFLICT");
  if (JSON.stringify(statement.qualification_report_digests) !== JSON.stringify(row.qualification_report_digests)) throw repoError("CONFLICT");
  if (statement.approval_state !== "approved") throw repoError("EVIDENCE");
  if (Date.parse(statement.expires_at) > Date.parse(String(row.approval_expires_at))) throw repoError("EXPIRED");
  if (evidence.version !== 3 || evidence.type !== "agentpass.promotion-evidence") throw repoError("EVIDENCE");
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

function claimMatches(row, token) { return row.claim_token_digest === sha256(token); }
function assertIdentity(row, identity) {
  for (const key of IDENTITY_KEYS) if (String(row[key]) !== String(identity[key])) throw repoError("CONFLICT");
}
function makeToken(randomBytes) {
  const value = randomBytes(32);
  if (!Buffer.isBuffer(value) || value.length !== 32) throw repoError("CONFIG");
  return value.toString("base64url");
}
function sha256(value) { return crypto.createHash("sha256").update(String(value), "utf8").digest("hex"); }
function numberValue(value) { const result = Number(value); if (!Number.isSafeInteger(result) || result < 0) throw repoError("DATABASE"); return result; }
function normalizeStoredRow(row) { return { ...row, claim_token_digest: row.claim_token_digest ? String(row.claim_token_digest) : null }; }
function rowCount(result) { return Number(result?.rowCount ?? result?.rows?.length ?? 0); }
function repoError(name) { const code = PLATFORM_PROMOTION_ISSUANCE_ERROR_CODES[name] ?? PLATFORM_PROMOTION_ISSUANCE_ERROR_CODES.DATABASE; return new PlatformPromotionIssuanceRepositoryError(code); }
function publicError(error) { if (error instanceof PlatformPromotionIssuanceRepositoryError) return error; return repoError("DATABASE"); }
function deepFreeze(value) { if (value && typeof value === "object" && !Object.isFrozen(value)) { Object.freeze(value); for (const child of Object.values(value)) deepFreeze(child); } return value; }
