import crypto from "node:crypto";

import { normalizeAgentSessionGrantIssueIntent } from "./issuance-service.mjs";
import { canonicalJson } from "../../../../../packages/protocol/src/index.mjs";
import {
  QUALIFICATION_GRANT_BATCH_MANIFEST_ISSUER,
  QUALIFICATION_GRANT_BATCH_MANIFEST_TYPE,
  QUALIFICATION_GRANT_BATCH_MANIFEST_VERSION
} from "../../qualification-grant-batch-manifest.mjs";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
const SHA256 = /^[0-9a-f]{64}$/u;
const COMMIT = /^[0-9a-f]{40}$/u;
const TEAM_ID = /^[A-Z0-9]{10}$/u;
const IDEMPOTENCY_KEY = /^[A-Za-z0-9._~-]{8,255}$/u;
const ADMIN_ROLES = new Set(["owner", "admin"]);
const ISSUE_OPERATION = "qualification.grant_batch.issue";
const MIN_TTL_SECONDS = 60;
const MAX_TTL_SECONDS = 3_600;

export const QUALIFICATION_GRANT_BATCH_SCHEMA_VERSION = 1;
export const QUALIFICATION_GRANT_BATCH_KIND = "agentpass-n3e-qualification-grant-batch";
export const QUALIFICATION_GRANT_BATCH_STEPS = Object.freeze([
  Object.freeze({ index: 0, kind: "unarmed-control", scenario: null, phase: null }),
  Object.freeze({ index: 1, kind: "scenario", scenario: "pre-cloud-kill", phase: "pre-cloud" }),
  Object.freeze({ index: 2, kind: "scenario", scenario: "post-cloud-pre-local-kill", phase: "post-cloud-pre-local" }),
  Object.freeze({ index: 3, kind: "scenario", scenario: "post-activation-pre-audit-kill", phase: "post-activation-pre-audit" }),
  Object.freeze({ index: 4, kind: "scenario", scenario: "post-audit-pre-reply-loss", phase: "post-audit-pre-reply" }),
  Object.freeze({ index: 5, kind: "scenario", scenario: "audit-fsync-failure", phase: "audit-fsync" }),
  Object.freeze({ index: 6, kind: "scenario", scenario: "transport-reply-loss", phase: "transport-reply" })
]);

export const QUALIFICATION_GRANT_BATCH_ERROR_CODES = Object.freeze({
  INVALID_REQUEST: "qualification_grant_batch_invalid_request",
  FORBIDDEN: "qualification_grant_batch_forbidden",
  NOT_FOUND: "qualification_grant_batch_not_found",
  IDEMPOTENCY_CONFLICT: "qualification_grant_batch_idempotency_conflict",
  UNAVAILABLE: "qualification_grant_batch_unavailable"
});

export class QualificationGrantBatchError extends Error {
  constructor(code, { cause } = {}) {
    super(code, { cause });
    this.name = "QualificationGrantBatchError";
    this.code = code;
  }
}

/**
 * Human/WebAuthn authorization boundary for a physical qualification batch.
 *
 * The repository owns one PostgreSQL transaction. It revalidates membership,
 * device/agent identity and release-candidate registry bindings; allocates
 * seven distinct control sequences and the current authority generation; calls
 * buildGrants exactly once for a new idempotency record; and atomically stores
 * the seven grants, batch rows, admin audit event and publication intent.
 *
 * This service deliberately returns only public batch metadata to the human.
 * Authority-bearing Grant envelopes leave Cloud solely through the separately
 * device-authenticated claim endpoint.
 */
export function createQualificationGrantBatchService({
  repository,
  grantBuilder,
  manifestSigner,
  now = () => Date.now(),
  uuid = crypto.randomUUID
} = {}) {
  if (!repository || typeof repository.issueQualificationGrantBatch !== "function") throw new TypeError("qualification batch repository must expose issueQualificationGrantBatch()");
  if (!grantBuilder || typeof grantBuilder.buildSignedGrant !== "function") throw new TypeError("qualification batch grant builder must expose buildSignedGrant()");
  const signManifest = manifestSigner?.signQualificationGrantBatchManifest ?? manifestSigner?.signManifest;
  if (!manifestSigner || typeof manifestSigner.publicKeyMetadata !== "function" || typeof signManifest !== "function") throw new TypeError("qualification batch manifest signer is required");
  if (typeof now !== "function" || typeof uuid !== "function") throw new TypeError("qualification batch clock and UUID source are required");

  async function issue(input = {}) {
    const actor = normalizeActor(input.actor);
    const organizationId = requiredUuid(input.organization_id);
    const agentId = requiredUuid(input.agent_id);
    if (actor.organization_id !== organizationId) fail(QUALIFICATION_GRANT_BATCH_ERROR_CODES.NOT_FOUND);
    const request = normalizeRequest(input.request ?? input.intent);
    const idempotencyKey = normalizeIdempotencyKey(input.idempotency_key);
    const issuedAtMs = readNow(now);
    const recentAuth = normalizeRecentAuthorization(input.recent_authorization ?? input.recent_auth, actor, organizationId, issuedAtMs);
    const expiresAtMs = issuedAtMs + request.grant_intent.ttl_seconds * 1_000;
    if (!Number.isSafeInteger(expiresAtMs)) fail(QUALIFICATION_GRANT_BATCH_ERROR_CODES.UNAVAILABLE);
    const issuedAt = new Date(issuedAtMs).toISOString();
    const expiresAt = new Date(expiresAtMs).toISOString();
    const batchId = createUuid(uuid);
    const requestId = createUuid(uuid);
    const steps = QUALIFICATION_GRANT_BATCH_STEPS.map((step) => Object.freeze({
      ...step,
      grant_id: createUuid(uuid),
      run_binding: createUuid(uuid)
    }));
    const requestFingerprint = sha256(canonicalJson({ organization_id: organizationId, agent_id: agentId, ...request }));

    let result;
    try {
      result = await repository.issueQualificationGrantBatch(Object.freeze({
        actor,
        organization_id: organizationId,
        device_id: request.grant_intent.device_id,
        agent_id: agentId,
        batch_id: batchId,
        request_id: requestId,
        idempotency_key: idempotencyKey,
        request_fingerprint: requestFingerprint,
        request,
        issued_at: issuedAt,
        expires_at: expiresAt,
        recent_auth: recentAuth,
        steps: Object.freeze(steps),
        buildGrants: async ({ allocations } = {}) => buildGrants({
          allocations,
          steps,
          organizationId,
          agentId,
          intent: request.grant_intent,
          issuedAt,
          expiresAt
        }),
        buildManifest: async ({ grants } = {}) => buildManifest({
          grants,
          batchId,
          organizationId,
          agentId,
          request,
          issuedAt,
          expiresAt
        })
      }));
    } catch (error) {
      throw mapRepositoryError(error);
    }
    return normalizeResult(result, { batchId, requestId, organizationId, agentId, request, issuedAt, expiresAt });
  }

  async function buildGrants({ allocations, steps, organizationId, agentId, intent, issuedAt, expiresAt }) {
    if (!Array.isArray(allocations) || allocations.length !== QUALIFICATION_GRANT_BATCH_STEPS.length) fail(QUALIFICATION_GRANT_BATCH_ERROR_CODES.UNAVAILABLE);
    const seenSequences = new Set();
    const grants = [];
    for (let index = 0; index < allocations.length; index += 1) {
      const allocation = allocations[index];
      if (!plainObject(allocation) || !Number.isSafeInteger(allocation.control_sequence) || allocation.control_sequence < 1 || !Number.isSafeInteger(allocation.authority_generation) || allocation.authority_generation < 1 || allocation.grant_id !== steps[index].grant_id || seenSequences.has(allocation.control_sequence)) fail(QUALIFICATION_GRANT_BATCH_ERROR_CODES.UNAVAILABLE);
      seenSequences.add(allocation.control_sequence);
      const built = await grantBuilder.buildSignedGrant({
        grantId: allocation.grant_id,
        organizationId,
        agentId,
        intent,
        issuedAt,
        expiresAt,
        controlSequence: allocation.control_sequence,
        authorityGeneration: allocation.authority_generation
      });
      if (!plainObject(built) || !plainObject(built.grant) || built.grant.statement?.grant_id !== allocation.grant_id || built.control_sequence !== allocation.control_sequence || built.authority_generation !== allocation.authority_generation) fail(QUALIFICATION_GRANT_BATCH_ERROR_CODES.UNAVAILABLE);
      grants.push(Object.freeze({ ...steps[index], grant: built.grant, grant_hash: built.grant_hash, statement_hash: built.statement_hash }));
    }
    return Object.freeze(grants);
  }

  async function buildManifest({ grants, batchId, organizationId, agentId, request, issuedAt, expiresAt }) {
    if (!Array.isArray(grants) || grants.length !== QUALIFICATION_GRANT_BATCH_STEPS.length) fail(QUALIFICATION_GRANT_BATCH_ERROR_CODES.UNAVAILABLE);
    let metadata;
    try { metadata = await manifestSigner.publicKeyMetadata(); }
    catch (error) { throw new QualificationGrantBatchError(QUALIFICATION_GRANT_BATCH_ERROR_CODES.UNAVAILABLE, { cause: error }); }
    if (!plainObject(metadata) || typeof metadata.key_id !== "string") fail(QUALIFICATION_GRANT_BATCH_ERROR_CODES.UNAVAILABLE);
    const statement = {
      version: QUALIFICATION_GRANT_BATCH_MANIFEST_VERSION,
      type: QUALIFICATION_GRANT_BATCH_MANIFEST_TYPE,
      batch_id: batchId,
      organization_id: organizationId,
      device_id: request.grant_intent.device_id,
      agent_id: agentId,
      agent_kind: request.grant_intent.agent_kind,
      requested_ttl_seconds: request.grant_intent.ttl_seconds,
      candidate_sha256: request.candidate_sha256,
      artifact_sha256: request.artifact_sha256,
      source_commit: request.source_commit,
      team_id: request.team_id,
      release_trust_sha256: request.release_trust_sha256,
      candidate_checkpoint_sha256: request.candidate_checkpoint_sha256,
      issued_at: issuedAt,
      expires_at: expiresAt,
      steps: grants,
      issuer: QUALIFICATION_GRANT_BATCH_MANIFEST_ISSUER,
      key_id: metadata.key_id
    };
    try { return await signManifest.call(manifestSigner, statement); }
    catch (error) { throw new QualificationGrantBatchError(QUALIFICATION_GRANT_BATCH_ERROR_CODES.UNAVAILABLE, { cause: error }); }
  }

  return Object.freeze({ issue, issueQualificationGrantBatch: issue, buildGrants, buildManifest });
}

function normalizeRequest(value) {
  if (!plainObject(value)) invalid();
  exactKeys(value, ["artifact_sha256", "candidate_checkpoint_sha256", "candidate_sha256", "grant_intent", "release_trust_sha256", "source_commit", "team_id"]);
  if (![value.artifact_sha256, value.candidate_checkpoint_sha256, value.candidate_sha256, value.release_trust_sha256].every((item) => typeof item === "string" && SHA256.test(item)) || typeof value.source_commit !== "string" || !COMMIT.test(value.source_commit) || typeof value.team_id !== "string" || !TEAM_ID.test(value.team_id)) invalid();
  let grantIntent;
  try { grantIntent = normalizeAgentSessionGrantIssueIntent(value.grant_intent); } catch { invalid(); }
  if (grantIntent.ttl_seconds < MIN_TTL_SECONDS || grantIntent.ttl_seconds > MAX_TTL_SECONDS || grantIntent.max_signatures !== 1) invalid();
  return Object.freeze({
    artifact_sha256: value.artifact_sha256,
    candidate_checkpoint_sha256: value.candidate_checkpoint_sha256,
    candidate_sha256: value.candidate_sha256,
    grant_intent: grantIntent,
    release_trust_sha256: value.release_trust_sha256,
    source_commit: value.source_commit,
    team_id: value.team_id
  });
}

function normalizeActor(value) {
  if (!plainObject(value)) fail(QUALIFICATION_GRANT_BATCH_ERROR_CODES.FORBIDDEN);
  exactKeys(value, ["member_id", "organization_id", "role", "session_id"], QUALIFICATION_GRANT_BATCH_ERROR_CODES.FORBIDDEN);
  const actor = { session_id: requiredUuid(value.session_id, QUALIFICATION_GRANT_BATCH_ERROR_CODES.FORBIDDEN), member_id: requiredUuid(value.member_id, QUALIFICATION_GRANT_BATCH_ERROR_CODES.FORBIDDEN), organization_id: requiredUuid(value.organization_id, QUALIFICATION_GRANT_BATCH_ERROR_CODES.FORBIDDEN), role: value.role };
  if (!ADMIN_ROLES.has(actor.role)) fail(QUALIFICATION_GRANT_BATCH_ERROR_CODES.FORBIDDEN);
  return Object.freeze(actor);
}

function normalizeRecentAuthorization(value, actor, organizationId, nowMs) {
  if (!plainObject(value)) fail(QUALIFICATION_GRANT_BATCH_ERROR_CODES.FORBIDDEN);
  exactKeys(value, ["authenticated_at", "authorization_id", "member_id", "operation", "organization_id"] , QUALIFICATION_GRANT_BATCH_ERROR_CODES.FORBIDDEN);
  if (!isUuid(value.authorization_id) || value.organization_id !== organizationId || value.member_id !== actor.member_id || value.operation !== ISSUE_OPERATION || !Number.isSafeInteger(value.authenticated_at) || value.authenticated_at < 0 || value.authenticated_at > nowMs + 30_000 || nowMs - value.authenticated_at > 5 * 60_000) fail(QUALIFICATION_GRANT_BATCH_ERROR_CODES.FORBIDDEN);
  return Object.freeze({ authorization_id: value.authorization_id.toLowerCase(), authenticated_at: value.authenticated_at });
}

function normalizeResult(result, expected) {
  if (!plainObject(result)) fail(QUALIFICATION_GRANT_BATCH_ERROR_CODES.UNAVAILABLE);
  exactKeys(result, result.replayed === true ? ["batch", "replayed", "request_id"] : ["batch", "request_id"]);
  const batch = result.batch;
  if (!plainObject(batch)) fail(QUALIFICATION_GRANT_BATCH_ERROR_CODES.UNAVAILABLE);
  const keys = ["agent_id", "artifact_sha256", "batch_id", "candidate_checkpoint_sha256", "candidate_sha256", "device_id", "expires_at", "issued_at", "kind", "organization_id", "release_trust_sha256", "schema_version", "source_commit", "status", "team_id"];
  exactKeys(batch, keys, QUALIFICATION_GRANT_BATCH_ERROR_CODES.UNAVAILABLE);
  if (batch.schema_version !== QUALIFICATION_GRANT_BATCH_SCHEMA_VERSION
    || batch.kind !== QUALIFICATION_GRANT_BATCH_KIND
    || batch.status !== "issued"
    || !isUuid(batch.batch_id)
    || (result.replayed !== true && batch.batch_id !== expected.batchId)
    || batch.organization_id !== expected.organizationId
    || batch.device_id !== expected.request.grant_intent.device_id
    || batch.agent_id !== expected.agentId
    || batch.artifact_sha256 !== expected.request.artifact_sha256
    || batch.candidate_checkpoint_sha256 !== expected.request.candidate_checkpoint_sha256
    || batch.candidate_sha256 !== expected.request.candidate_sha256
    || batch.release_trust_sha256 !== expected.request.release_trust_sha256
    || batch.source_commit !== expected.request.source_commit
    || batch.team_id !== expected.request.team_id
    || !canonicalTimestamp(batch.issued_at)
    || !canonicalTimestamp(batch.expires_at)
    || Date.parse(batch.expires_at) <= Date.parse(batch.issued_at)
    || (result.replayed !== true && (batch.issued_at !== expected.issuedAt || batch.expires_at !== expected.expiresAt))
    || !isUuid(result.request_id)) fail(QUALIFICATION_GRANT_BATCH_ERROR_CODES.UNAVAILABLE);
  return Object.freeze({ batch: Object.freeze({ ...batch }), request_id: result.request_id.toLowerCase(), ...(result.replayed === true ? { replayed: true } : {}) });
}

function mapRepositoryError(error) {
  if (error instanceof QualificationGrantBatchError) return error;
  const code = String(error?.code ?? error?.name ?? "").toLowerCase();
  if (["not_found", "resource_not_found", "organization_not_found", "agent_not_found", "device_not_found", "candidate_not_found"].includes(code)) return new QualificationGrantBatchError(QUALIFICATION_GRANT_BATCH_ERROR_CODES.NOT_FOUND, { cause: error });
  if (["forbidden", "not_authorized", "role_forbidden", "tenant_scope_error"].includes(code)) return new QualificationGrantBatchError(QUALIFICATION_GRANT_BATCH_ERROR_CODES.FORBIDDEN, { cause: error });
  if (["idempotency_conflict", "idempotency_key_reused", "err_idempotency_conflict"].includes(code)) return new QualificationGrantBatchError(QUALIFICATION_GRANT_BATCH_ERROR_CODES.IDEMPOTENCY_CONFLICT, { cause: error });
  return new QualificationGrantBatchError(QUALIFICATION_GRANT_BATCH_ERROR_CODES.UNAVAILABLE, { cause: error });
}

function normalizeIdempotencyKey(value) { if (typeof value !== "string" || !IDEMPOTENCY_KEY.test(value)) invalid(); return value; }
function requiredUuid(value, code = QUALIFICATION_GRANT_BATCH_ERROR_CODES.INVALID_REQUEST) { if (!isUuid(value)) fail(code); return value.toLowerCase(); }
function createUuid(source) { let value; try { value = source(); } catch (error) { throw new QualificationGrantBatchError(QUALIFICATION_GRANT_BATCH_ERROR_CODES.UNAVAILABLE, { cause: error }); } return requiredUuid(value, QUALIFICATION_GRANT_BATCH_ERROR_CODES.UNAVAILABLE); }
function readNow(source) { let value; try { value = source(); } catch (error) { throw new QualificationGrantBatchError(QUALIFICATION_GRANT_BATCH_ERROR_CODES.UNAVAILABLE, { cause: error }); } if (!Number.isSafeInteger(value) || value < 0) fail(QUALIFICATION_GRANT_BATCH_ERROR_CODES.UNAVAILABLE); return value; }
function isUuid(value) { return typeof value === "string" && UUID.test(value); }
function canonicalTimestamp(value) { return typeof value === "string" && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(value) && Number.isFinite(Date.parse(value)) && new Date(Date.parse(value)).toISOString() === value; }
function sha256(value) { return crypto.createHash("sha256").update(value).digest("hex"); }
function plainObject(value) { return value !== null && typeof value === "object" && !Array.isArray(value) && (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null); }
function exactKeys(value, expected, code = QUALIFICATION_GRANT_BATCH_ERROR_CODES.INVALID_REQUEST) { const actual = Reflect.ownKeys(value); const wanted = [...expected].sort(); if (actual.some((key) => typeof key !== "string") || actual.length !== wanted.length || actual.sort().some((key, index) => key !== wanted[index])) fail(code); }
function invalid() { fail(QUALIFICATION_GRANT_BATCH_ERROR_CODES.INVALID_REQUEST); }
function fail(code) { throw new QualificationGrantBatchError(code); }
