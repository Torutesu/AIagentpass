import crypto from "node:crypto";

import { canonicalJson } from "../../../../packages/protocol/src/index.mjs";
import { withTransaction } from "./repository.mjs";
import { verifyPromotionEvidenceV3 } from "../promotion-evidence-v3-verifier.mjs";
import { PROMOTION_EVIDENCE_V3_PURPOSE, promotionEvidenceV3SigningData } from "../promotion-evidence-v3-statement.mjs";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
const DIGEST = /^[0-9a-f]{64}$/u;
const IMAGE = /^sha256:[0-9a-f]{64}$/u;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$/u;
const IDEMPOTENCY = /^[A-Za-z0-9][A-Za-z0-9._~:-]{7,254}$/u;
const CLAIM = /^[A-Za-z0-9_-]{43}$/u;
const ENVIRONMENTS = new Set(["staging", "production"]);
const STATES = new Set(["reserved", "committed", "uncertain", "rejected"]);
const UNCERTAIN_REASONS = new Set(["signer_failure", "provider_response_loss", "commit_failure"]);
const REJECTION_REASONS = new Set(["approval_expired", "digest_mismatch", "disabled", "operator_rejected"]);
const PROVIDER_OPERATION_SELECT = `SELECT purpose,operation_id,algorithm,bytes_length,
  encode(request_digest,'hex') AS request_digest,key_id,key_version::text AS key_version,state,
  signature,public_key_der,provider_receipt_provider,provider_receipt_id
  FROM managed_signer_provider_operations
  WHERE purpose=$1 AND operation_id=$2 FOR UPDATE`;

const SELECT = `deployment_id,environment,promotion_id,idempotency_key,candidate_id,source_commit,source_tree,
  product_pkg_sha256,release_manifest_sha256,sbom_sha256,image_digest,qualification_report_digests,
  approval_id,approval_digest,signer_key_id,signer_key_version,signer_lifecycle_version,
  expected_deployment_generation,state,encode(claim_token_digest,'hex') AS claim_token_digest,
  claim_expires_at,provider_operation_id,uncertain_reason,evidence,rejection_reason,encode(authority_digest,'hex') AS authority_digest,
  created_at,updated_at`;

const MESSAGES = Object.freeze({
  ERR_INPUT: "promotion issuance input is invalid",
  ERR_CONFIG: "promotion issuance repository configuration is invalid",
  ERR_CONFLICT: "promotion issuance conflicts with existing authority",
  ERR_IN_PROGRESS: "promotion issuance is already in progress",
  ERR_UNCERTAIN: "promotion signing outcome is uncertain",
  ERR_NOT_FOUND: "promotion issuance was not found",
  ERR_CLAIM: "promotion issuance claim is invalid",
  ERR_DATABASE: "promotion issuance storage is unavailable"
});

export class PromotionIssuanceRepositoryError extends Error {
  constructor(code) {
    super(MESSAGES[code] ?? MESSAGES.ERR_DATABASE);
    this.name = "PromotionIssuanceRepositoryError";
    this.code = Object.hasOwn(MESSAGES, code) ? `ERR_PROMOTION_ISSUANCE_${code.slice(4)}` : "ERR_PROMOTION_ISSUANCE_DATABASE";
  }
}

export function createPostgresPromotionIssuanceRepository({ client, claimLeaseMs = 60_000, promotionEvidencePublicKey, evidenceVerifier, providerOperationRepository } = {}) {
  if (!client || typeof client.query !== "function") throw repoError("ERR_CONFIG");
  if (!Number.isSafeInteger(claimLeaseMs) || claimLeaseMs < 1_000 || claimLeaseMs > 15 * 60_000) throw repoError("ERR_CONFIG");
  if (evidenceVerifier !== undefined && typeof evidenceVerifier !== "function") throw repoError("ERR_CONFIG");
  if (providerOperationRepository !== undefined
    && (!providerOperationRepository || typeof providerOperationRepository.reconcileOperation !== "function")) throw repoError("ERR_CONFIG");
  let activeProviderOperationRepository = providerOperationRepository;
  const verifyEvidence = evidenceVerifier ?? (promotionEvidencePublicKey === undefined ? null : (evidence, authority) => verifyPromotionEvidenceV3(evidence, { publicKey: promotionEvidencePublicKey, authority }));

  async function reservePromotion(input = {}) {
    const authority = normalizeAuthority(input);
    const providerOperationId = normalizeProviderOperationId(input.provider_operation_id, { required: true });
    const onMutation = normalizeMutationHook(input.onMutation);
    try {
      return await withTransaction(client, async (tx) => {
        await lockLane(tx, authority);
        const existing = await select(tx, authority, true);
        if (existing !== undefined) {
          const row = normalizeRow(existing);
          assertSameAuthority(authority, row);
          assertProviderOperationId(row, providerOperationId);
          if (row.state === "committed") return auditedMutation(onMutation, tx, committedOutcome(row));
          if (row.state === "uncertain") return auditedMutation(onMutation, tx, uncertainOutcome(row));
          if (row.state === "rejected") return auditedMutation(onMutation, tx, { state: "rejected", reason: row.rejection_reason });
          if (row.claim_expires_at && Date.parse(row.claim_expires_at) > Date.now()) return auditedMutation(onMutation, tx, { state: "in_progress" });
          const token = newClaimToken();
          const reclaimed = await tx.query(`UPDATE platform_promotion_issuances
            SET claim_token_digest=$7, claim_expires_at=clock_timestamp()+($8 * interval '1 millisecond'), updated_at=clock_timestamp()
            WHERE deployment_id=$1 AND environment=$2 AND promotion_id=$3 AND idempotency_key=$4
              AND state='reserved' AND claim_expires_at<=clock_timestamp() AND authority_digest=$5
              AND provider_operation_id=$6
            RETURNING ${SELECT}`, [authority.deployment_id, authority.environment, authority.promotion_id, authority.idempotency_key, hexBytes(authority.authority_digest), providerOperationId, hexBytes(digest(token)), claimLeaseMs]);
          if (reclaimed.rowCount !== 1) throw repoError("ERR_IN_PROGRESS");
          return auditedMutation(onMutation, tx, reservedOutcome(normalizeRow(reclaimed.rows[0]), token));
        }
        const generation = await deploymentGeneration(tx, authority);
        if (generation.state === "disabled" || generation.generation !== authority.expected_deployment_generation) throw repoError("ERR_CONFLICT");
        await assertApproval(tx, authority);
        const token = newClaimToken();
        const inserted = await tx.query(`INSERT INTO platform_promotion_issuances
          (deployment_id,environment,promotion_id,idempotency_key,candidate_id,source_commit,source_tree,
           product_pkg_sha256,release_manifest_sha256,sbom_sha256,image_digest,qualification_report_digests,
           approval_id,approval_digest,signer_key_id,signer_key_version,signer_lifecycle_version,
           expected_deployment_generation,state,claim_token_digest,claim_expires_at,provider_operation_id,authority_digest)
          VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,'reserved',$19,
            clock_timestamp()+($20 * interval '1 millisecond'),$21,$22) ON CONFLICT DO NOTHING`, [
          authority.deployment_id, authority.environment, authority.promotion_id, authority.idempotency_key,
          authority.candidate_id, authority.source_commit, authority.source_tree, authority.product_pkg_sha256,
          authority.release_manifest_sha256, authority.sbom_sha256, authority.image_digest,
          JSON.stringify(authority.qualification_report_digests), authority.approval_id, authority.approval_digest,
          authority.signer_key_id, authority.signer_key_version, authority.signer_lifecycle_version,
          authority.expected_deployment_generation, hexBytes(digest(token)), claimLeaseMs, providerOperationId, hexBytes(authority.authority_digest)
        ]);
        if (inserted.rowCount !== 1) throw repoError("ERR_IN_PROGRESS");
        const row = await select(tx, authority, true);
        if (row === undefined) throw repoError("ERR_DATABASE");
        const stored = normalizeRow(row);
        assertProviderOperationId(stored, providerOperationId);
        return auditedMutation(onMutation, tx, reservedOutcome(stored, token));
      });
    } catch (error) { throw publicError(error); }
  }

  async function commitPromotion(input = {}) {
    const authority = normalizeAuthority(input);
    const claimToken = normalizeClaim(input.claim_token);
    const providerOperationId = normalizeProviderOperationId(input.provider_operation_id, { required: true });
    const evidence = normalizeEvidence(input.evidence);
    const onMutation = normalizeMutationHook(input.onMutation);
    if (!verifyEvidence) throw repoError("ERR_CONFIG");
    try { verifyEvidence(evidence, authority); } catch (error) { if (error instanceof PromotionIssuanceRepositoryError) throw error; throw repoError("ERR_INPUT"); }
    try {
      const existing = await preflightCommit(client, authority, claimToken, providerOperationId, evidence, onMutation);
      if (existing !== null) return existing;
    } catch (error) { throw publicError(error); }
    let providerCommitted = await reconcileProviderOperation(authority, providerOperationId, evidence, activeProviderOperationRepository);
    try {
      return await withTransaction(client, async (tx) => {
        await lockLane(tx, authority);
        const current = await select(tx, authority, true);
        if (current === undefined) throw repoError("ERR_NOT_FOUND");
        const row = normalizeRow(current);
        assertSameAuthority(authority, row);
        assertProviderOperationId(row, providerOperationId);
        if (row.state === "committed") {
          if (canonicalJson(row.evidence) !== canonicalJson(evidence)) throw repoError("ERR_CONFLICT");
          return auditedMutation(onMutation, tx, committedOutcome(row));
        }
        if (row.state === "uncertain") throw repoError("ERR_UNCERTAIN");
        if (row.state !== "reserved" || row.claim_token_digest !== digest(claimToken)) throw repoError("ERR_CLAIM");
        if (!row.claim_expires_at || Date.parse(row.claim_expires_at) <= Date.now()) throw repoError("ERR_CLAIM");
        const generation = await deploymentGeneration(tx, authority);
        if (generation.state === "disabled" || generation.generation !== authority.expected_deployment_generation) throw repoError("ERR_CONFLICT");
        await ensureProviderOperation(tx, authority, providerOperationId, evidence);
        // With no external repository adapter, this is the durable confirmation
        // that the provider operation succeeded. Keep it across a transaction
        // rollback so a later deployment-write failure is compensated safely.
        providerCommitted = true;
        const updated = await tx.query(`UPDATE platform_promotion_issuances SET state='committed',claim_token_digest=NULL,claim_expires_at=NULL,uncertain_reason=NULL,evidence=$7::jsonb,updated_at=clock_timestamp()
          WHERE deployment_id=$1 AND environment=$2 AND promotion_id=$3 AND idempotency_key=$4 AND state='reserved' AND claim_token_digest=$5 AND claim_expires_at>clock_timestamp() AND provider_operation_id=$6`, [authority.deployment_id, authority.environment, authority.promotion_id, authority.idempotency_key, hexBytes(digest(claimToken)), providerOperationId, JSON.stringify(evidence)]);
        if (updated.rowCount !== 1) throw repoError("ERR_CLAIM");
        const deployment = await tx.query(`INSERT INTO platform_deployment_state (deployment_id,environment,generation,state,promotion_id,evidence_digest)
          VALUES ($1,$2,$3,'promoted',$4,$5)
          ON CONFLICT (deployment_id,environment) DO UPDATE SET generation=EXCLUDED.generation,state='promoted',promotion_id=EXCLUDED.promotion_id,evidence_digest=EXCLUDED.evidence_digest,updated_at=clock_timestamp()
          WHERE platform_deployment_state.generation=$6 AND platform_deployment_state.state<>'disabled'`, [authority.deployment_id, authority.environment, authority.expected_deployment_generation + 1, authority.promotion_id, hexBytes(sha256(canonicalJson(evidence))), authority.expected_deployment_generation]);
        if (deployment.rowCount !== 1) throw repoError("ERR_CONFLICT");
        const committed = await select(tx, authority, true);
        return auditedMutation(onMutation, tx, committedOutcome(normalizeRow(committed)));
      });
    } catch (error) {
      const failure = publicError(error);
      if (providerCommitted) {
        const compensation = await compensateProviderCommit(client, { authority, claimToken, providerOperationId, evidence });
        if (compensation?.state === "committed") return compensation;
        throw repoError("ERR_UNCERTAIN");
      }
      throw failure;
    }
  }

  async function markUncertain(input = {}) { return transition(input, "uncertain", normalizeUncertainReason(input.reason), normalizeProviderOperationId(input.provider_operation_id, { required: true })); }
  async function rejectPromotion(input = {}) { return transition(input, "rejected", normalizeRejectionReason(input.reason)); }
  async function reconcileUncertainPromotion(input = {}) {
    const authority = normalizeAuthority(input);
    const providerOperationId = normalizeProviderOperationId(input.provider_operation_id, { required: true });
    const evidence = normalizeEvidence(input.evidence);
    const onMutation = normalizeMutationHook(input.onMutation);
    if (!verifyEvidence) throw repoError("ERR_CONFIG");
    try { verifyEvidence(evidence, authority); } catch { throw repoError("ERR_INPUT"); }
    await reconcileProviderOperation(authority, providerOperationId, evidence, activeProviderOperationRepository);
    try {
      return await withTransaction(client, async (tx) => {
        await lockLane(tx, authority);
        const current = await select(tx, authority, true);
        if (!current) throw repoError("ERR_NOT_FOUND");
        const row = normalizeRow(current);
        assertSameAuthority(authority, row);
        assertProviderOperationId(row, providerOperationId);
        if (row.state === "committed") {
          if (row.provider_operation_id !== providerOperationId || canonicalJson(row.evidence) !== canonicalJson(evidence)) throw repoError("ERR_CONFLICT");
          return auditedMutation(onMutation, tx, committedOutcome(row));
        }
        if (row.state !== "uncertain") throw repoError("ERR_UNCERTAIN");
        const generation = await deploymentGeneration(tx, authority);
        if (generation.state === "disabled" || generation.generation !== authority.expected_deployment_generation) throw repoError("ERR_CONFLICT");
        await ensureProviderOperation(tx, authority, providerOperationId, evidence);
        const updated = await tx.query(`UPDATE platform_promotion_issuances SET state='committed',uncertain_reason=NULL,evidence=$5::jsonb,updated_at=clock_timestamp()
          WHERE deployment_id=$1 AND environment=$2 AND promotion_id=$3 AND idempotency_key=$4 AND state='uncertain' AND provider_operation_id=$6`, [authority.deployment_id, authority.environment, authority.promotion_id, authority.idempotency_key, JSON.stringify(evidence), providerOperationId]);
        if (updated.rowCount !== 1) throw repoError("ERR_UNCERTAIN");
        const deployment = await tx.query(`INSERT INTO platform_deployment_state (deployment_id,environment,generation,state,promotion_id,evidence_digest)
          VALUES ($1,$2,$3,'promoted',$4,$5)
          ON CONFLICT (deployment_id,environment) DO UPDATE SET generation=EXCLUDED.generation,state='promoted',promotion_id=EXCLUDED.promotion_id,evidence_digest=EXCLUDED.evidence_digest,updated_at=clock_timestamp()
          WHERE platform_deployment_state.generation=$6 AND platform_deployment_state.state<>'disabled'`, [authority.deployment_id, authority.environment, authority.expected_deployment_generation + 1, authority.promotion_id, hexBytes(sha256(canonicalJson(evidence))), authority.expected_deployment_generation]);
        if (deployment.rowCount !== 1) throw repoError("ERR_CONFLICT");
        return auditedMutation(onMutation, tx, committedOutcome(normalizeRow(await select(tx, authority, true))));
      });
    } catch (error) { throw publicError(error); }
  }
  async function replayPromotion(input = {}) {
    const authority = normalizeAuthority(input);
    try { return await withTransaction(client, async (tx) => { const row = await select(tx, authority, false); if (!row) return { state: "absent" }; const normalized = normalizeRow(row); assertSameAuthority(authority, normalized); return normalized.state === "committed" ? committedOutcome(normalized) : normalized.state === "uncertain" ? uncertainOutcome(normalized) : { state: normalized.state, ...(normalized.rejection_reason ? { reason: normalized.rejection_reason } : {}) }; }); }
    catch (error) { throw publicError(error); }
  }

  async function transition(input, state, reason, providerOperationId = null) {
    const authority = normalizeAuthority(input);
    const claimToken = normalizeClaim(input.claim_token);
    try {
      return await withTransaction(client, async (tx) => {
        const rowResult = await select(tx, authority, true);
        if (!rowResult) throw repoError("ERR_NOT_FOUND");
        const row = normalizeRow(rowResult);
        assertSameAuthority(authority, row);
        if (providerOperationId !== null) assertProviderOperationId(row, providerOperationId);
        if (row.state === "committed") return committedOutcome(row);
        if (row.state === "uncertain") {
          if (state !== "uncertain" || row.uncertain_reason !== reason) throw repoError("ERR_CONFLICT");
          return uncertainOutcome(row);
        }
        if (row.state === "rejected") {
          if (state !== "rejected" || row.rejection_reason !== reason) throw repoError("ERR_CONFLICT");
          return { state: "rejected", reason: row.rejection_reason };
        }
        if (row.state !== "reserved" || row.claim_token_digest !== digest(claimToken)) throw repoError("ERR_CLAIM");
        const updated = await tx.query(`UPDATE platform_promotion_issuances SET state=$6,claim_token_digest=NULL,claim_expires_at=NULL,rejection_reason=$7,provider_operation_id=COALESCE(provider_operation_id,$8),uncertain_reason=$9,updated_at=clock_timestamp()
          WHERE deployment_id=$1 AND environment=$2 AND promotion_id=$3 AND idempotency_key=$4 AND state='reserved' AND claim_token_digest=$5 AND claim_expires_at>clock_timestamp() AND ($8::text IS NULL OR provider_operation_id=$8)`, [authority.deployment_id, authority.environment, authority.promotion_id, authority.idempotency_key, hexBytes(digest(claimToken)), state, state === "rejected" ? reason : null, providerOperationId, state === "uncertain" ? reason : null]);
        if (updated.rowCount !== 1) throw repoError("ERR_CLAIM");
        if (state === "uncertain") return uncertainOutcome({ ...row, state, provider_operation_id: providerOperationId });
        return { state, ...(state === "rejected" ? { reason } : {}) };
      });
    }
    catch (error) { throw publicError(error); }
  }

  function setProviderOperationRepository(repository) {
    if (!repository || typeof repository.reconcileOperation !== "function") throw repoError("ERR_CONFIG");
    activeProviderOperationRepository = repository;
  }

  return Object.freeze({
    reservePromotion,
    commitPromotion,
    markUncertain,
    rejectPromotion,
    reconcileUncertainPromotion,
    replayPromotion,
    setProviderOperationRepository,
    supportsAtomicPromotionAudit: true
  });
}

export function normalizePromotionAuthority(value = {}) {
  return normalizeAuthority(value);
}

export function promotionAuthorityDigest(value) {
  return normalizeAuthority(value).authority_digest;
}

function normalizeAuthority(value) {
  const result = {
    deployment_id: required(value.deployment_id, IDENTIFIER), environment: required(value.environment, ENVIRONMENTS),
    promotion_id: required(value.promotion_id, UUID).toLowerCase(), idempotency_key: required(value.idempotency_key, IDEMPOTENCY),
    candidate_id: required(value.candidate_id, /^release-pkg-sha256-v1-[0-9a-f]{64}$/u), source_commit: required(value.source_commit, /^[0-9a-f]{40}$/u), source_tree: required(value.source_tree, /^[0-9a-f]{40}$/u),
    product_pkg_sha256: required(value.product_pkg_sha256, DIGEST), release_manifest_sha256: required(value.release_manifest_sha256, DIGEST), sbom_sha256: required(value.sbom_sha256, DIGEST), image_digest: required(value.image_digest, IMAGE),
    qualification_report_digests: normalizeDigests(value.qualification_report_digests), approval_id: required(value.approval_id, UUID).toLowerCase(), approval_digest: required(value.approval_digest, DIGEST),
    signer_key_id: required(value.signer_key_id, IDENTIFIER), signer_key_version: safeInteger(value.signer_key_version), signer_lifecycle_version: safeInteger(value.signer_lifecycle_version), expected_deployment_generation: safeInteger(value.expected_deployment_generation, 0)
  };
  return Object.freeze({ ...result, authority_digest: sha256(canonicalJson(result)) });
}

function normalizeRow(row) { return Object.freeze({ ...row, promotion_id: String(row.promotion_id).toLowerCase(), qualification_report_digests: typeof row.qualification_report_digests === "string" ? JSON.parse(row.qualification_report_digests) : row.qualification_report_digests, authority_digest: Buffer.isBuffer(row.authority_digest) ? row.authority_digest.toString("hex") : String(row.authority_digest ?? "").toLowerCase(), claim_token_digest: row.claim_token_digest === null ? null : Buffer.isBuffer(row.claim_token_digest) ? row.claim_token_digest.toString("hex") : String(row.claim_token_digest).toLowerCase() }); }
function committedOutcome(row) { return Object.freeze({ state: "committed", promotion_id: row.promotion_id, provider_operation_id: row.provider_operation_id, evidence: Object.freeze(row.evidence), generation: row.expected_deployment_generation + 1 }); }
function uncertainOutcome(row) { return Object.freeze({ state: "uncertain", promotion_id: row.promotion_id, provider_operation_id: row.provider_operation_id }); }
function reservedOutcome(row, claimToken) { return Object.freeze({ state: "reserved", promotion_id: row.promotion_id, provider_operation_id: row.provider_operation_id, claim_token: claimToken, authority_digest: row.authority_digest, expires_at: row.claim_expires_at }); }
function select(tx, authority, forUpdate) { return tx.query(`SELECT ${SELECT} FROM platform_promotion_issuances WHERE deployment_id=$1 AND environment=$2 AND promotion_id=$3 AND idempotency_key=$4 ${forUpdate ? "FOR UPDATE" : ""}`, [authority.deployment_id, authority.environment, authority.promotion_id, authority.idempotency_key]).then((result) => result.rows[0]); }
function lockLane(tx, authority) { return tx.query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))", [`agentpass:promotion:${authority.deployment_id}:${authority.environment}`]); }
function deploymentGeneration(tx, authority) { return tx.query("SELECT generation,state FROM platform_deployment_state WHERE deployment_id=$1 AND environment=$2 FOR UPDATE", [authority.deployment_id, authority.environment]).then((result) => result.rows[0] ? { generation: Number(result.rows[0].generation), state: result.rows[0].state } : { generation: 0, state: "idle" }); }
function assertSameAuthority(input, row) { if (row.authority_digest !== input.authority_digest || rowAuthorityDigest(row) !== input.authority_digest || row.candidate_id !== input.candidate_id || row.approval_digest !== input.approval_digest) throw repoError("ERR_CONFLICT"); }
function assertProviderOperationId(row, providerOperationId) { if (typeof row.provider_operation_id !== "string" || row.provider_operation_id !== providerOperationId) throw repoError("ERR_CONFLICT"); }
function rowAuthorityDigest(row) { return normalizeAuthority(row).authority_digest; }
async function preflightCommit(client, authority, claimToken, providerOperationId, evidence, onMutation) {
  return withTransaction(client, async (tx) => {
    const current = await select(tx, authority, true);
    if (!current) throw repoError("ERR_NOT_FOUND");
    const row = normalizeRow(current);
    assertSameAuthority(authority, row);
    assertProviderOperationId(row, providerOperationId);
    if (row.state === "committed") {
      if (canonicalJson(row.evidence) !== canonicalJson(evidence)) throw repoError("ERR_CONFLICT");
      return auditedMutation(onMutation, tx, committedOutcome(row));
    }
    if (row.state === "uncertain") throw repoError("ERR_UNCERTAIN");
    if (row.state !== "reserved" || row.claim_token_digest !== digest(claimToken)) throw repoError("ERR_CLAIM");
    if (!row.claim_expires_at || Date.parse(row.claim_expires_at) <= Date.now()) throw repoError("ERR_CLAIM");
    return null;
  });
}

function normalizeMutationHook(value) {
  if (value !== undefined && typeof value !== "function") throw repoError("ERR_INPUT");
  return value;
}

async function auditedMutation(onMutation, tx, result) {
  if (onMutation !== undefined) await onMutation({ tx, result });
  return result;
}
async function reconcileProviderOperation(authority, providerOperationId, evidence, providerOperationRepository) {
  if (providerOperationRepository === undefined) return false;
  const operation = providerOperationInput(authority, providerOperationId, evidence);
  let result;
  try { result = await providerOperationRepository.reconcileOperation(operation); }
  catch { throw repoError("ERR_UNCERTAIN"); }
  if (!result || result.state !== "committed") throw repoError("ERR_UNCERTAIN");
  return true;
}
async function compensateProviderCommit(client, { authority, claimToken, providerOperationId, evidence }) {
  try {
    return await withTransaction(client, async (tx) => {
      await lockLane(tx, authority);
      const current = await select(tx, authority, true);
      if (!current) throw repoError("ERR_NOT_FOUND");
      const row = normalizeRow(current);
      assertSameAuthority(authority, row);
      assertProviderOperationId(row, providerOperationId);
      if (row.state === "committed") {
        if (canonicalJson(row.evidence) !== canonicalJson(evidence)) throw repoError("ERR_CONFLICT");
        return committedOutcome(row);
      }
      if (row.state === "uncertain") return uncertainOutcome(row);
      if (row.state !== "reserved" || row.claim_token_digest !== digest(claimToken)) throw repoError("ERR_CLAIM");
      const updated = await tx.query(`UPDATE platform_promotion_issuances SET state='uncertain',claim_token_digest=NULL,claim_expires_at=NULL,rejection_reason=NULL,uncertain_reason='commit_failure',updated_at=clock_timestamp()
        WHERE deployment_id=$1 AND environment=$2 AND promotion_id=$3 AND idempotency_key=$4 AND state='reserved' AND claim_token_digest=$5 AND provider_operation_id=$6`, [authority.deployment_id, authority.environment, authority.promotion_id, authority.idempotency_key, hexBytes(digest(claimToken)), providerOperationId]);
      if (updated.rowCount !== 1) throw repoError("ERR_UNCERTAIN");
      return uncertainOutcome({ ...row, state: "uncertain", provider_operation_id: providerOperationId });
    });
  } catch {
    return null;
  }
}
async function ensureProviderOperation(tx, authority, providerOperationId, evidence) {
  const operation = providerOperationInput(authority, providerOperationId, evidence);
  let result;
  try { result = await tx.query(PROVIDER_OPERATION_SELECT, [PROMOTION_EVIDENCE_V3_PURPOSE, providerOperationId]); }
  catch { throw repoError("ERR_DATABASE"); }
  const row = result?.rows?.[0];
  if (!row || row.purpose !== operation.purpose || row.operation_id !== operation.operation_id
    || row.algorithm !== operation.algorithm || Number(row.bytes_length) !== operation.bytes_length
    || String(row.key_id) !== operation.key_id || String(row.key_version) !== operation.key_version
    || String(row.request_digest).toLowerCase() !== operation.request_digest || row.state !== "committed"
    || row.signature === null || row.signature === undefined || row.public_key_der === null || row.public_key_der === undefined
    || row.provider_receipt_provider === null || row.provider_receipt_id === null) throw repoError("ERR_UNCERTAIN");
  const signature = Buffer.from(evidence.signature, "base64url");
  const stored = Buffer.from(row.signature);
  if (!safeEqual(signature, stored)) throw repoError("ERR_CONFLICT");
}
function providerOperationInput(authority, providerOperationId, evidence) {
  let signingBytes;
  try { signingBytes = promotionEvidenceV3SigningData(evidence.statement, { allowExpired: true, allowFuture: true }); }
  catch { throw repoError("ERR_INPUT"); }
  return Object.freeze({
    algorithm: "ed25519",
    bytes_length: signingBytes.length,
    key_id: authority.signer_key_id,
    key_version: String(authority.signer_key_version),
    operation_id: providerOperationId,
    purpose: PROMOTION_EVIDENCE_V3_PURPOSE,
    request_digest: sha256(signingBytes)
  });
}
function safeEqual(left, right) { return left.length === right.length && crypto.timingSafeEqual(left, right); }
async function assertApproval(tx, authority) {
  const result = await tx.query(`SELECT approval_id, deployment_id, environment, candidate_id, source_commit, source_tree, product_pkg_sha256, image_digest, sbom_sha256, qualification_report_digests, release_manifest_sha256, record_digest, decision, quorum_satisfied, expires_at
    FROM platform_promotion_approvals WHERE approval_id=$1 AND decision='approved' AND quorum_satisfied IS TRUE AND expires_at>clock_timestamp() FOR UPDATE`, [authority.approval_id]);
  const approval = result.rows[0];
  if (!approval || String(approval.record_digest).toLowerCase() !== authority.approval_digest
    || approval.deployment_id !== authority.deployment_id || approval.environment !== authority.environment
    || approval.candidate_id !== authority.candidate_id || approval.source_commit !== authority.source_commit || approval.source_tree !== authority.source_tree
    || approval.product_pkg_sha256 !== authority.product_pkg_sha256 || approval.image_digest !== authority.image_digest || approval.sbom_sha256 !== authority.sbom_sha256
    || approval.release_manifest_sha256 !== authority.release_manifest_sha256
    || JSON.stringify(approval.qualification_report_digests) !== JSON.stringify(authority.qualification_report_digests)) throw repoError("ERR_CONFLICT");
}
function normalizeDigests(value) { if (!Array.isArray(value) || value.length < 1 || value.length > 16 || new Set(value).size !== value.length || value.some((item) => !DIGEST.test(item)) || value.some((item, index) => index > 0 && value[index - 1] >= item)) throw repoError("ERR_INPUT"); return Object.freeze([...value]); }
function normalizeEvidence(value) { if (!value || typeof value !== "object" || Array.isArray(value) || typeof value.signature !== "string" || !/^[A-Za-z0-9_-]{86}$/u.test(value.signature) || !value.statement || typeof value.statement !== "object") throw repoError("ERR_INPUT"); return Object.freeze({ ...value }); }
function normalizeUncertainReason(value) { if (!UNCERTAIN_REASONS.has(value)) throw repoError("ERR_INPUT"); return value; }
function normalizeRejectionReason(value) { if (!REJECTION_REASONS.has(value)) throw repoError("ERR_INPUT"); return value; }
function normalizeClaim(value) { if (typeof value !== "string" || !CLAIM.test(value)) throw repoError("ERR_CLAIM"); return value; }
function normalizeProviderOperationId(value, { required = false } = {}) { if (value === undefined || value === null) { if (required) throw repoError("ERR_INPUT"); return null; } if (typeof value !== "string" || !IDENTIFIER.test(value)) throw repoError("ERR_INPUT"); return value; }
function required(value, matcher) { if (typeof value !== "string" || (matcher instanceof Set ? !matcher.has(value) : !matcher.test(value))) throw repoError("ERR_INPUT"); return value; }
function safeInteger(value, minimum = 1) { if (!Number.isSafeInteger(value) || value < minimum) throw repoError("ERR_INPUT"); return value; }
function newClaimToken() { return crypto.randomBytes(32).toString("base64url"); }
function digest(value) { return crypto.createHash("sha256").update(value).digest("hex"); }
function sha256(value) { return crypto.createHash("sha256").update(value).digest("hex"); }
function hexBytes(value) { return Buffer.from(value, "hex"); }
function repoError(code) { return new PromotionIssuanceRepositoryError(code); }
function publicError(error) { if (error instanceof PromotionIssuanceRepositoryError) return error; return repoError("ERR_DATABASE"); }
