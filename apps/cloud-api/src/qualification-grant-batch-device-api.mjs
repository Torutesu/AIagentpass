import crypto from "node:crypto";

import { parseBoundedJson } from "../../../lib/control-bundle-v2.mjs";
import { canonicalJson } from "../../../packages/protocol/src/index.mjs";
import { normalizeAgentSessionGrantStatement } from "./agent-session-grant.mjs";
import {
  normalizeQualificationGrantBatchManifest,
  QUALIFICATION_GRANT_BATCH_MANIFEST_TYPE
} from "./qualification-grant-batch-manifest.mjs";

/**
 * Framework-neutral Device API boundary for the physical qualification Grant
 * batch.
 *
 * The request is deliberately a small, public, closed document. It binds the
 * one claim to the candidate and its public release identities; the device
 * signature authenticates the exact canonical bytes before this module parses
 * them. The repository owns one-shot and exact-retry semantics, so this module
 * never keeps an in-process consumed flag.
 *
 * Request (canonical JSON, exact keys):
 *   { schema_version, candidate_sha256, source_commit, artifact_sha256,
 *     release_trust_sha256, candidate_checkpoint_sha256, team_id }
 *
 * The response is { batch, request_id }. A batch contains seven ordered,
 * public existing Agent Session Grant v1 envelopes. No private key,
 * credential, bearer token, or opaque secret is accepted in either contract.
 * Each Grant statement is exactly the existing 18-field
 * agent-session-grant-v1 statement; suite identity and release bindings never
 * enter that signed statement.
 */

export const QUALIFICATION_GRANT_BATCH_DEVICE_HTTP_PATH =
  "/v1/organizations/{organization_id}/devices/{device_id}/qualification-grant-batches/{batch_id}/claim";

export const QUALIFICATION_GRANT_BATCH_DEVICE_HTTP_PATHS = Object.freeze({
  claim: QUALIFICATION_GRANT_BATCH_DEVICE_HTTP_PATH
});

export const QUALIFICATION_GRANT_BATCH_DEVICE_HTTP_ERROR_CODES = Object.freeze({
  INVALID_REQUEST: "invalid_request",
  DEVICE_AUTH_FAILED: "device_auth_failed",
  AUDIENCE_MISMATCH: "audience_mismatch",
  GRANT_NOT_AUTHORIZED: "grant_not_authorized",
  NOT_FOUND: "not_found",
  BATCH_CONFLICT: "qualification_grant_batch_conflict",
  RATE_LIMITED: "rate_limited",
  UNAVAILABLE: "qualification_grant_batch_unavailable"
});

export const QUALIFICATION_GRANT_BATCH_SCHEMA_VERSION = 1;
export const QUALIFICATION_GRANT_BATCH_KIND = "agentpass-n3e-qualification-grant-batch";
export const QUALIFICATION_GRANT_TYPE = "agentpass.agent-session-grant";
// Compatibility alias for callers that used the first draft's export. The
// value is deliberately the existing Agent Session Grant v1 type.
export const QUALIFICATION_GRANT_KIND = QUALIFICATION_GRANT_TYPE;
export const QUALIFICATION_GRANT_BATCH_MAX_BODY_BYTES = 16 * 1024;
export const QUALIFICATION_GRANT_BATCH_MIN_TTL_SECONDS = 60;
export const QUALIFICATION_GRANT_BATCH_MAX_TTL_SECONDS = 3_600;

// This is intentionally duplicated at this framework-neutral boundary. The
// release runner may evolve independently, but a Cloud-issued batch must not
// silently accept a different suite order.
export const QUALIFICATION_GRANT_BATCH_STEP_IDENTITIES = Object.freeze([
  Object.freeze({ index: 0, kind: "unarmed-control", scenario: null, phase: null }),
  Object.freeze({ index: 1, kind: "scenario", scenario: "pre-cloud-kill", phase: "pre-cloud" }),
  Object.freeze({ index: 2, kind: "scenario", scenario: "post-cloud-pre-local-kill", phase: "post-cloud-pre-local" }),
  Object.freeze({ index: 3, kind: "scenario", scenario: "post-activation-pre-audit-kill", phase: "post-activation-pre-audit" }),
  Object.freeze({ index: 4, kind: "scenario", scenario: "post-audit-pre-reply-loss", phase: "post-audit-pre-reply" }),
  Object.freeze({ index: 5, kind: "scenario", scenario: "audit-fsync-failure", phase: "audit-fsync" }),
  Object.freeze({ index: 6, kind: "scenario", scenario: "transport-reply-loss", phase: "transport-reply" })
]);

const REQUEST_KEYS = new Set([
  "schema_version", "candidate_sha256", "source_commit", "artifact_sha256",
  "release_trust_sha256", "candidate_checkpoint_sha256", "team_id"
]);
const BATCH_KEYS = new Set([
  "schema_version", "kind", "batch_id", "organization_id", "device_id", "agent_id",
  "agent_kind", "requested_ttl_seconds", "candidate_sha256", "source_commit",
  "artifact_sha256", "release_trust_sha256", "candidate_checkpoint_sha256", "team_id", "expires_at", "steps", "manifest"
]);
const STEP_KEYS = new Set(["index", "kind", "scenario", "phase", "run_binding", "grant"]);
const GRANT_KEYS = new Set(["version", "type", "statement", "statement_hash", "signature"]);
const STATEMENT_KEYS = new Set([
  "version", "grant_id", "organization_id", "device_id", "agent_id", "agent_kind",
  "adapter_id", "adapter_version", "worktree_binding_sha256", "process_binding_policy_id",
  "scope", "max_signatures", "not_before", "expires_at", "control_sequence",
  "authority_generation", "issuer", "key_id"
]);
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const HASH = /^[0-9a-f]{64}$/u;
const SOURCE_COMMIT = /^[0-9a-f]{40}$/u;
const TEAM_ID = /^[A-Z0-9]{10}$/u;
const SIGNATURE = /^[A-Za-z0-9_-]{85}[AEIMQUYcgkosw048]$/u;
const RUN_BINDING = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;
const TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u;
const AGENT_KINDS = new Set(["claude-code", "cursor"]);
const METHOD = "POST";
const MAX_URL_BYTES = 8 * 1024;
const MAX_JSON_DEPTH = 32;
const RESPONSE_HEADERS = Object.freeze({
  "Cache-Control": "no-store, max-age=0",
  "Pragma": "no-cache",
  "Expires": "0",
  "Content-Type": "application/json; charset=utf-8",
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "no-referrer"
});

const ERROR_MESSAGES = Object.freeze({
  [QUALIFICATION_GRANT_BATCH_DEVICE_HTTP_ERROR_CODES.INVALID_REQUEST]: "The qualification Grant batch request is invalid",
  [QUALIFICATION_GRANT_BATCH_DEVICE_HTTP_ERROR_CODES.DEVICE_AUTH_FAILED]: "Device authentication failed",
  [QUALIFICATION_GRANT_BATCH_DEVICE_HTTP_ERROR_CODES.AUDIENCE_MISMATCH]: "The authenticated device cannot claim this batch",
  [QUALIFICATION_GRANT_BATCH_DEVICE_HTTP_ERROR_CODES.GRANT_NOT_AUTHORIZED]: "The Agent Session Grant is not authorized",
  [QUALIFICATION_GRANT_BATCH_DEVICE_HTTP_ERROR_CODES.NOT_FOUND]: "Resource not found",
  [QUALIFICATION_GRANT_BATCH_DEVICE_HTTP_ERROR_CODES.BATCH_CONFLICT]: "The qualification Grant batch conflicts with a prior claim",
  [QUALIFICATION_GRANT_BATCH_DEVICE_HTTP_ERROR_CODES.RATE_LIMITED]: "Rate limit exceeded",
  [QUALIFICATION_GRANT_BATCH_DEVICE_HTTP_ERROR_CODES.UNAVAILABLE]: "The qualification Grant batch service is unavailable"
});

export class QualificationGrantBatchDeviceHttpError extends Error {
  constructor(code, { status, retryAfterSeconds, cause } = {}) {
    super(ERROR_MESSAGES[code] ?? ERROR_MESSAGES[QUALIFICATION_GRANT_BATCH_DEVICE_HTTP_ERROR_CODES.UNAVAILABLE], { cause });
    this.name = "QualificationGrantBatchDeviceHttpError";
    this.code = code;
    this.status = status ?? statusFor(code);
    if (retryAfterSeconds !== undefined) this.retryAfterSeconds = retryAfterSeconds;
  }
}

export function createQualificationGrantBatchDeviceApi({
  deviceRequestVerifier,
  deviceRequestAuthenticator,
  verifyDeviceRequest,
  repository,
  grantVerifier,
  manifestVerifier,
  rateLimiter = undefined,
  now = () => Date.now(),
  requestIdFactory = () => crypto.randomUUID(),
  maxBodyBytes = QUALIFICATION_GRANT_BATCH_MAX_BODY_BYTES
} = {}) {
  const deviceVerifier = resolveVerifier(deviceRequestVerifier ?? deviceRequestAuthenticator ?? verifyDeviceRequest, "deviceRequestVerifier");
  const signedGrantVerifier = resolveGrantVerifier(grantVerifier);
  const signedManifestVerifier = resolveManifestVerifier(manifestVerifier);
  if (!repository || typeof repository.claimQualificationGrantBatch !== "function") {
    throw new TypeError("repository must expose claimQualificationGrantBatch()");
  }
  if (rateLimiter !== undefined && (!rateLimiter || typeof rateLimiter.acquire !== "function")) throw new TypeError("rateLimiter must expose acquire()");
  if (typeof now !== "function") throw new TypeError("now must be a function");
  if (typeof requestIdFactory !== "function") throw new TypeError("requestIdFactory must be a function");
  if (!Number.isSafeInteger(maxBodyBytes) || maxBodyBytes < 1_024 || maxBodyBytes > QUALIFICATION_GRANT_BATCH_MAX_BODY_BYTES) {
    throw new TypeError("maxBodyBytes is invalid");
  }

  async function handle(input, nodeResponse = undefined) {
    const result = await dispatch(input);
    if (nodeResponse !== undefined) writeNodeResponse(nodeResponse, result);
    return result;
  }

  async function dispatch(input) {
    const requestId = makeRequestId(requestIdFactory);
    try {
      const request = await normalizeRequest(input, maxBodyBytes);
      const route = resolveRoute(request.path);
      if (!route) return response(404, errorBody(QUALIFICATION_GRANT_BATCH_DEVICE_HTTP_ERROR_CODES.NOT_FOUND, requestId));
      if (request.method !== METHOD) throw invalidRequest();

      const clock = readClock(now);
      let authenticated;
      try {
        // No JSON operation is allowed before this call. The verifier receives
        // the exact raw method, path, headers, and bytes that were submitted.
        authenticated = await deviceVerifier({
          method: request.method,
          path: request.path,
          body: Buffer.from(request.body),
          headers: request.headers
        }, {
          organization_id: route.organizationId,
          organizationId: route.organizationId,
          device_id: route.deviceId,
          deviceId: route.deviceId,
          now: clock,
          includeAuthenticationMetadata: true
        });
      } catch (error) {
        throw mapDeviceAuthenticationError(error);
      }
      assertAuthenticatedDevice(authenticated, route);

      if (rateLimiter) {
        let decision;
        try {
          decision = await rateLimiter.acquire({ tenantId: route.organizationId, principalType: "device", principalId: route.deviceId });
        } catch (error) {
          if (isRateLimitCode(error?.code) || error?.status === 429) throw mapRepositoryError(error);
          throw unavailable(error);
        }
        if (!validRateLimitDecision(decision)) throw unavailable();
        if (!decision.allowed) throw new QualificationGrantBatchDeviceHttpError(QUALIFICATION_GRANT_BATCH_DEVICE_HTTP_ERROR_CODES.RATE_LIMITED, { status: 429, retryAfterSeconds: decision.retryAfterSeconds });
      }

      const body = parseCanonicalRequest(request.body, maxBodyBytes);
      const bodyDigest = sha256(request.body);
      const requestDigest = sha256(canonicalJson(body));
      const claimIdentity = sha256(canonicalJson({
        schema_version: 1,
        method: METHOD,
        path: request.path,
        body_sha256: bodyDigest
      }));

      let stored;
      try {
        // This is the only claim state boundary. A repository implementation
        // must atomically implement one-shot and exact-retry behavior keyed by
        // claim_identity_sha256; this module intentionally does not dedupe.
        stored = await repository.claimQualificationGrantBatch(Object.freeze({
          organization_id: route.organizationId,
          device_id: route.deviceId,
          batch_id: route.batchId,
          candidate_sha256: body.candidate_sha256,
          source_commit: body.source_commit,
          artifact_sha256: body.artifact_sha256,
          release_trust_sha256: body.release_trust_sha256,
          candidate_checkpoint_sha256: body.candidate_checkpoint_sha256,
          team_id: body.team_id,
          request: deepFreeze(clonePublicValue(body)),
          request_sha256: requestDigest,
          claim_identity_sha256: claimIdentity,
          observed_at: new Date(clock).toISOString()
        }));
      } catch (error) {
        throw mapRepositoryError(error);
      }

      let batch;
      try {
        batch = validateBatch(stored?.batch ?? stored, route, body, clock);
        const manifest = await verifyBatchManifest(batch, signedManifestVerifier, route, body, clock);
        batch = deepFreeze({ ...batch, manifest });
        await verifyBatchGrants(batch, signedGrantVerifier, route, clock);
      } catch (error) {
        if (error instanceof QualificationGrantBatchDeviceHttpError) throw error;
        throw unavailable(error);
      }
      return response(200, { batch, request_id: requestId });
    } catch (error) {
      const mapped = error instanceof QualificationGrantBatchDeviceHttpError ? error : unavailable(error);
      const headers = mapped.retryAfterSeconds === undefined ? undefined : { "Retry-After": String(mapped.retryAfterSeconds) };
      return response(mapped.status, errorBody(mapped.code, requestId), headers);
    }
  }

  return Object.freeze({
    handle,
    paths: QUALIFICATION_GRANT_BATCH_DEVICE_HTTP_PATHS,
    route: QUALIFICATION_GRANT_BATCH_DEVICE_HTTP_PATH
  });
}

export function canonicalQualificationGrantBatchRequest(value) {
  const normalized = validateRequest(value);
  return Buffer.from(canonicalJson(normalized), "utf8");
}

export function normalizeQualificationGrantBatch(value, { organization_id, device_id, batch_id, now = Date.now(), request = undefined } = {}) {
  const route = { organizationId: organization_id, deviceId: device_id, batchId: batch_id };
  const body = request === undefined ? undefined : validateRequest(request);
  return validateBatch(value, route, body, readClockValue(now));
}

async function verifyBatchManifest(batch, manifestVerifier, route, request, clock) {
  if (!isObject(batch.manifest)) throw unavailable(new Error("repository qualification Grant batch manifest is missing"));

  let verified;
  try {
    verified = await manifestVerifier(batch.manifest, {
      purpose: QUALIFICATION_GRANT_BATCH_MANIFEST_TYPE,
      organization_id: route.organizationId,
      device_id: route.deviceId,
      batch_id: route.batchId,
      candidate_sha256: request.candidate_sha256,
      artifact_sha256: request.artifact_sha256,
      source_commit: request.source_commit,
      release_trust_sha256: request.release_trust_sha256,
      candidate_checkpoint_sha256: request.candidate_checkpoint_sha256,
      team_id: request.team_id,
      now: clock,
      includeVerificationMetadata: true
    });
  } catch (error) {
    throw mapManifestVerificationError(error);
  }

  const candidate = extractVerifiedManifest(verified, batch.manifest);
  if (!candidate) {
    throw new QualificationGrantBatchDeviceHttpError(
      QUALIFICATION_GRANT_BATCH_DEVICE_HTTP_ERROR_CODES.GRANT_NOT_AUTHORIZED,
      { status: 403 }
    );
  }

  let manifest;
  try {
    // The verifier owns detached-signature and purpose checks. Normalize its
    // returned value here so a verifier cannot accidentally authorize an
    // unknown or incomplete manifest shape.
    manifest = normalizeQualificationGrantBatchManifest(candidate, {
      now: clock,
      allowExpired: false,
      allowFuture: false
    });
    assertManifestBatchBinding(manifest, batch);
  } catch (error) {
    if (error instanceof QualificationGrantBatchDeviceHttpError) throw error;
    throw unavailable(error);
  }
  return manifest;
}

function extractVerifiedManifest(result, input) {
  if (result === true) return input;
  if (!isObject(result) || result.verified === false) return undefined;
  if (result.verified === true && !result.manifest && !result.verified_manifest && !result.normalized_manifest) return input;
  if (isManifestEnvelope(result)) return result;
  for (const key of ["manifest", "verified_manifest", "normalized_manifest"]) {
    if (isManifestEnvelope(result[key])) return result[key];
  }
  return undefined;
}

function isManifestEnvelope(value) {
  return isObject(value) && isObject(value.statement) && typeof value.signature === "string";
}

function assertManifestBatchBinding(manifest, batch) {
  if (manifest.type !== QUALIFICATION_GRANT_BATCH_MANIFEST_TYPE) throw new Error("qualification Grant batch manifest purpose is invalid");
  const statement = manifest.statement;
  const bindings = [
    ["batch_id", batch.batch_id],
    ["organization_id", batch.organization_id],
    ["device_id", batch.device_id],
    ["agent_id", batch.agent_id],
    ["agent_kind", batch.agent_kind],
    ["requested_ttl_seconds", batch.requested_ttl_seconds],
    ["candidate_sha256", batch.candidate_sha256],
    ["artifact_sha256", batch.artifact_sha256],
    ["source_commit", batch.source_commit],
    ["team_id", batch.team_id],
    ["release_trust_sha256", batch.release_trust_sha256],
    ["candidate_checkpoint_sha256", batch.candidate_checkpoint_sha256],
    ["expires_at", batch.expires_at]
  ];
  if (bindings.some(([key, expected]) => statement[key] !== expected)) throw new Error("qualification Grant batch manifest binding is invalid");
  if (statement.steps.length !== batch.steps.length) throw new Error("qualification Grant batch manifest step count is invalid");

  for (let index = 0; index < batch.steps.length; index += 1) {
    const batchStep = batch.steps[index];
    const manifestStep = statement.steps[index];
    if (manifestStep.index !== batchStep.index
      || manifestStep.kind !== batchStep.kind
      || manifestStep.scenario !== batchStep.scenario
      || manifestStep.phase !== batchStep.phase
      || manifestStep.run_binding !== batchStep.run_binding
      || manifestStep.grant_id !== batchStep.grant.statement.grant_id
      || manifestStep.statement_hash !== batchStep.grant.statement_hash
      || manifestStep.grant_hash !== sha256(canonicalJson(batchStep.grant))) {
      throw new Error("qualification Grant batch manifest Grant binding is invalid");
    }
  }
}

function mapManifestVerificationError(error) {
  const code = String(error?.code ?? "").toLowerCase();
  if (isUnavailableCode(code) || code.includes("provider") || code.includes("config") || error?.status === 503) return unavailable(error);
  if (error?.status === 403 || code.includes("signature") || code.includes("expired") || code.includes("not_yet") || code.includes("unauthorized") || code.includes("input") || code.includes("hash")) {
    return new QualificationGrantBatchDeviceHttpError(QUALIFICATION_GRANT_BATCH_DEVICE_HTTP_ERROR_CODES.GRANT_NOT_AUTHORIZED, { status: 403, cause: error });
  }
  return unavailable(error);
}

async function verifyBatchGrants(batch, grantVerifier, route, clock) {
  for (const step of batch.steps) {
    let result;
    try {
      result = await grantVerifier(step.grant, {
        organization_id: route.organizationId,
        device_id: route.deviceId,
        batch_id: route.batchId,
        now: clock,
        statement_hash: step.grant.statement_hash
      });
    } catch (error) {
      throw mapGrantVerificationError(error);
    }
    assertGrantVerification(result, step.grant, batch, step, clock);
  }
}

function mapGrantVerificationError(error) {
  const code = String(error?.code ?? "").toLowerCase();
  if (isUnavailableCode(code) || error?.status === 503) return unavailable(error);
  if (code.includes("expired") || code.includes("not_yet_valid") || isConflictCode(code) || error?.status === 409) {
    return new QualificationGrantBatchDeviceHttpError(QUALIFICATION_GRANT_BATCH_DEVICE_HTTP_ERROR_CODES.BATCH_CONFLICT, { status: 409, cause: error });
  }
  if (isInputCode(code) || error?.status === 400) return invalidRequest();
  return new QualificationGrantBatchDeviceHttpError(QUALIFICATION_GRANT_BATCH_DEVICE_HTTP_ERROR_CODES.GRANT_NOT_AUTHORIZED, { status: 403, cause: error });
}

function assertGrantVerification(value, grant, batch, step, clock) {
  if (value === true) return;
  if (!value || typeof value !== "object" || Array.isArray(value) || value.verified === false) {
    throw new QualificationGrantBatchDeviceHttpError(QUALIFICATION_GRANT_BATCH_DEVICE_HTTP_ERROR_CODES.GRANT_NOT_AUTHORIZED, { status: 403 });
  }
  if (value.verified === true && value.grant === undefined && value.verified_grant === undefined) return;
  const verifiedGrant = value.grant ?? value.verified_grant ?? (value.statement && value.signature ? value : undefined);
  if (!verifiedGrant || !isObject(verifiedGrant)) {
    throw new QualificationGrantBatchDeviceHttpError(QUALIFICATION_GRANT_BATCH_DEVICE_HTTP_ERROR_CODES.GRANT_NOT_AUTHORIZED, { status: 403 });
  }
  try {
    const normalized = validateGrant(verifiedGrant, { batch, step, clock });
    if (canonicalJson(normalized) !== canonicalJson(grant)) throw new Error("verified Grant mismatch");
  } catch (error) {
    if (error instanceof QualificationGrantBatchDeviceHttpError) throw error;
    throw new QualificationGrantBatchDeviceHttpError(QUALIFICATION_GRANT_BATCH_DEVICE_HTTP_ERROR_CODES.GRANT_NOT_AUTHORIZED, { status: 403, cause: error });
  }
}

function validateRequest(value) {
  if (!isObject(value)) throw invalidRequest();
  assertExactKeys(value, REQUEST_KEYS, "qualification Grant batch request");
  if (value.schema_version !== QUALIFICATION_GRANT_BATCH_SCHEMA_VERSION
    || !HASH.test(value.candidate_sha256 ?? "")
    || !SOURCE_COMMIT.test(value.source_commit ?? "")
    || !HASH.test(value.artifact_sha256 ?? "")
    || !HASH.test(value.release_trust_sha256 ?? "")
    || !HASH.test(value.candidate_checkpoint_sha256 ?? "")
    || !TEAM_ID.test(value.team_id ?? "")) throw invalidRequest();
  return deepFreeze(clonePublicValue({
    schema_version: QUALIFICATION_GRANT_BATCH_SCHEMA_VERSION,
    candidate_sha256: value.candidate_sha256,
    source_commit: value.source_commit,
    artifact_sha256: value.artifact_sha256,
    release_trust_sha256: value.release_trust_sha256,
    candidate_checkpoint_sha256: value.candidate_checkpoint_sha256,
    team_id: value.team_id
  }));
}

function validateBatch(value, route, request, clock) {
  if (!isObject(value)) throw new Error("repository batch output is invalid");
  assertExactKeys(value, BATCH_KEYS, "qualification Grant batch", unavailable);
  if (value.schema_version !== QUALIFICATION_GRANT_BATCH_SCHEMA_VERSION
    || value.kind !== QUALIFICATION_GRANT_BATCH_KIND
    || !UUID.test(value.batch_id ?? "")
    || value.batch_id !== route.batchId
    || !UUID.test(value.organization_id ?? "")
    || value.organization_id !== route.organizationId
    || !UUID.test(value.device_id ?? "")
    || value.device_id !== route.deviceId
    || !UUID.test(value.agent_id ?? "")
    || !AGENT_KINDS.has(value.agent_kind)
    || !Number.isSafeInteger(value.requested_ttl_seconds)
    || value.requested_ttl_seconds < QUALIFICATION_GRANT_BATCH_MIN_TTL_SECONDS
    || value.requested_ttl_seconds > QUALIFICATION_GRANT_BATCH_MAX_TTL_SECONDS
    || !HASH.test(value.candidate_sha256 ?? "")
    || !SOURCE_COMMIT.test(value.source_commit ?? "")
    || !HASH.test(value.artifact_sha256 ?? "")
    || !HASH.test(value.release_trust_sha256 ?? "")
    || !HASH.test(value.candidate_checkpoint_sha256 ?? "")
    || !TEAM_ID.test(value.team_id ?? "")
    || !TIMESTAMP.test(value.expires_at ?? "")
    || !Array.isArray(value.steps)
    || value.steps.length !== QUALIFICATION_GRANT_BATCH_STEP_IDENTITIES.length
    || !isObject(value.manifest)) throw new Error("repository batch output is invalid");
  if (request && (value.candidate_sha256 !== request.candidate_sha256
    || value.source_commit !== request.source_commit
    || value.artifact_sha256 !== request.artifact_sha256
    || value.release_trust_sha256 !== request.release_trust_sha256
    || value.candidate_checkpoint_sha256 !== request.candidate_checkpoint_sha256
    || value.team_id !== request.team_id)) throw new Error("repository batch binding is invalid");

  const expiresAt = parseTimestamp(value.expires_at);
  if (expiresAt <= clock || expiresAt > clock + value.requested_ttl_seconds * 1000) throw new Error("repository batch expiry is invalid");

  const grantIds = new Set();
  const signatures = new Set();
  const statementHashes = new Set();
  const runBindings = new Set();
  const steps = value.steps.map((step, position) => {
    const expected = QUALIFICATION_GRANT_BATCH_STEP_IDENTITIES[position];
    assertExactKeys(step, STEP_KEYS, `qualification Grant batch step ${position}`, unavailable);
    if (step.index !== expected.index || step.kind !== expected.kind || step.scenario !== expected.scenario || step.phase !== expected.phase || !RUN_BINDING.test(step.run_binding ?? "")) {
      throw new Error("repository batch step order is invalid");
    }
    if (runBindings.has(step.run_binding)) throw new Error("repository batch run binding is reused");
    const grant = validateGrant(step.grant, { batch: value, step, clock });
    if (grantIds.has(grant.statement.grant_id)) throw new Error("repository batch Grant id is reused");
    if (signatures.has(grant.signature)) throw new Error("repository batch signature is reused");
    if (statementHashes.has(grant.statement_hash)) throw new Error("repository batch statement hash is reused");
    grantIds.add(grant.statement.grant_id);
    signatures.add(grant.signature);
    statementHashes.add(grant.statement_hash);
    runBindings.add(step.run_binding);
    return Object.freeze({
      index: step.index,
      kind: step.kind,
      scenario: step.scenario,
      phase: step.phase,
      run_binding: step.run_binding,
      grant
    });
  });
  return deepFreeze({
    schema_version: QUALIFICATION_GRANT_BATCH_SCHEMA_VERSION,
    kind: QUALIFICATION_GRANT_BATCH_KIND,
    batch_id: value.batch_id,
    organization_id: value.organization_id,
    device_id: value.device_id,
    agent_id: value.agent_id,
    agent_kind: value.agent_kind,
    requested_ttl_seconds: value.requested_ttl_seconds,
    candidate_sha256: value.candidate_sha256,
    source_commit: value.source_commit,
    artifact_sha256: value.artifact_sha256,
    release_trust_sha256: value.release_trust_sha256,
    candidate_checkpoint_sha256: value.candidate_checkpoint_sha256,
    team_id: value.team_id,
    expires_at: value.expires_at,
    steps: Object.freeze(steps),
    manifest: deepFreeze(clonePublicValue(value.manifest))
  });
}

function validateGrant(value, { batch, step, clock }) {
  if (!isObject(value)) throw new Error("repository Grant output is invalid");
  assertExactKeys(value, GRANT_KEYS, "qualification Grant", unavailable);
  if (value.version !== QUALIFICATION_GRANT_BATCH_SCHEMA_VERSION
    || value.type !== QUALIFICATION_GRANT_TYPE
    || !HASH.test(value.statement_hash ?? "")
    || !SIGNATURE.test(value.signature ?? "")) throw new Error("repository Grant output is invalid");
  const signatureBytes = Buffer.from(value.signature, "base64url");
  if (signatureBytes.length !== 64 || signatureBytes.toString("base64url") !== value.signature) throw new Error("repository Grant signature is invalid");

  const statement = value.statement;
  if (!isObject(statement)) throw new Error("repository Grant statement is invalid");
  assertExactKeys(statement, STATEMENT_KEYS, "Agent Session Grant v1 statement", unavailable);
  let normalizedStatement;
  try {
    // Reuse the exact v1 statement normalizer so this boundary cannot drift
    // from NativeAgentGrantLeaseHTTPConsumer's 18-field contract.
    normalizedStatement = normalizeAgentSessionGrantStatement(statement, {
      allowExpired: true,
      allowFuture: true,
      maxTtlMs: QUALIFICATION_GRANT_BATCH_MAX_TTL_SECONDS * 1000
    });
  } catch {
    throw new Error("repository Agent Session Grant statement is invalid");
  }
  if (!UUID.test(normalizedStatement.grant_id ?? "")
    || statement.organization_id !== batch.organization_id
    || statement.device_id !== batch.device_id
    || statement.agent_id !== batch.agent_id
    || statement.agent_kind !== batch.agent_kind
    || normalizedStatement.max_signatures !== 1
    || normalizedStatement.expires_at !== batch.expires_at) throw new Error("repository Agent Session Grant audience or expiry binding is invalid");
  const notBefore = parseTimestamp(normalizedStatement.not_before);
  const expiresAt = parseTimestamp(normalizedStatement.expires_at);
  if (notBefore > clock || expiresAt <= clock || expiresAt <= notBefore) throw new Error("repository Agent Session Grant validity is invalid");
  const expectedStatementHash = sha256(canonicalJson(normalizedStatement));
  if (expectedStatementHash !== value.statement_hash) throw new Error("repository Grant statement hash is invalid");
  return deepFreeze(clonePublicValue({
    version: value.version,
    type: value.type,
    statement: normalizedStatement,
    statement_hash: value.statement_hash,
    signature: value.signature
  }));
}

function parseCanonicalRequest(bytes, maxBodyBytes) {
  let value;
  try { value = parseBoundedJson(bytes, { maxBytes: maxBodyBytes, maxDepth: MAX_JSON_DEPTH }); }
  catch { throw invalidRequest(); }
  let normalized;
  try { normalized = validateRequest(value); }
  catch { throw invalidRequest(); }
  if (!Buffer.from(canonicalJson(normalized), "utf8").equals(bytes)) throw invalidRequest();
  return normalized;
}

async function normalizeRequest(input, maxBodyBytes) {
  if (!input || typeof input !== "object") throw invalidRequest();
  const method = typeof input.method === "string" ? input.method.toUpperCase() : "";
  const path = typeof input.url === "string" ? input.url : typeof input.originalUrl === "string" ? input.originalUrl : input.path;
  if (!method || typeof path !== "string" || path.length === 0 || !path.startsWith("/") || Buffer.byteLength(path, "utf8") > MAX_URL_BYTES || /[\u0000-\u0020\u007f#?\\]/u.test(path)) throw invalidRequest();
  const headers = input.headers ?? {};
  const body = await readRawBody(input, maxBodyBytes);
  return Object.freeze({ method, path, headers, body });
}

async function readRawBody(input, maxBodyBytes) {
  let raw = input.body;
  if (raw === undefined && typeof input.arrayBuffer === "function") raw = Buffer.from(await input.arrayBuffer());
  else if (raw === undefined && typeof input.text === "function") raw = await input.text();
  else if (raw === undefined && isAsyncIterable(input)) raw = await readStream(input, maxBodyBytes);
  else if (isAsyncIterable(raw)) raw = await readStream(raw, maxBodyBytes);
  const bytes = toBytes(raw);
  if (bytes.length > maxBodyBytes) throw invalidRequest();
  return bytes;
}

async function readStream(stream, maxBodyBytes) {
  const chunks = [];
  let total = 0;
  for await (const chunk of stream) {
    const bytes = toBytes(chunk);
    total += bytes.length;
    if (total > maxBodyBytes) throw invalidRequest();
    chunks.push(bytes);
  }
  return Buffer.concat(chunks);
}

function toBytes(value) {
  if (value === undefined || value === null) return Buffer.alloc(0);
  if (Buffer.isBuffer(value)) return Buffer.from(value);
  if (typeof value === "string") return Buffer.from(value, "utf8");
  if (value instanceof Uint8Array) return Buffer.from(value);
  if (value instanceof ArrayBuffer) return Buffer.from(value);
  throw invalidRequest();
}

function resolveRoute(path) {
  const match = /^\/v1\/organizations\/(?<organizationId>[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})\/devices\/(?<deviceId>[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})\/qualification-grant-batches\/(?<batchId>[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})\/claim$/u.exec(path);
  return match ? Object.freeze({ organizationId: match.groups.organizationId, deviceId: match.groups.deviceId, batchId: match.groups.batchId }) : undefined;
}

function assertAuthenticatedDevice(value, route) {
  const principal = value?.principal ?? value?.device ?? value;
  const deviceId = principal?.device_id ?? principal?.deviceId;
  const organizationId = principal?.organization_id ?? principal?.organizationId;
  if (typeof deviceId !== "string") throw new QualificationGrantBatchDeviceHttpError(QUALIFICATION_GRANT_BATCH_DEVICE_HTTP_ERROR_CODES.DEVICE_AUTH_FAILED, { status: 401 });
  if (deviceId !== route.deviceId || (organizationId !== undefined && organizationId !== route.organizationId)) {
    throw new QualificationGrantBatchDeviceHttpError(QUALIFICATION_GRANT_BATCH_DEVICE_HTTP_ERROR_CODES.AUDIENCE_MISMATCH, { status: 403 });
  }
}

function resolveVerifier(value, label) {
  if (typeof value === "function") return value;
  if (value && typeof value.verify === "function") return value.verify.bind(value);
  if (value && typeof value.authenticate === "function") return value.authenticate.bind(value);
  throw new TypeError(`${label} must be a function or expose verify()/authenticate()`);
}

function resolveGrantVerifier(value) {
  if (typeof value === "function") return value;
  if (value && typeof value.verify === "function") return value.verify.bind(value);
  if (value && typeof value.verifyGrant === "function") return value.verifyGrant.bind(value);
  throw new TypeError("grantVerifier must be a function or expose verify()/verifyGrant()");
}

function resolveManifestVerifier(value) {
  if (typeof value === "function") return value;
  if (value && typeof value.verify === "function") return value.verify.bind(value);
  if (value && typeof value.verifyManifest === "function") return value.verifyManifest.bind(value);
  if (value && typeof value.verifyQualificationGrantBatchManifest === "function") return value.verifyQualificationGrantBatchManifest.bind(value);
  throw new TypeError("manifestVerifier must be a function or expose verify()/verifyManifest()/verifyQualificationGrantBatchManifest()");
}

function assertExactKeys(value, allowed, label, failure = invalidRequest) {
  const keys = Reflect.ownKeys(value);
  if (keys.some((key) => typeof key !== "string") || keys.length !== allowed.size || keys.some((key) => !allowed.has(key))) throw failure(`invalid ${label}`);
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !("value" in descriptor) || descriptor.enumerable !== true) throw failure(`invalid ${label}`);
  }
}

function mapDeviceAuthenticationError(error) {
  const code = String(error?.code ?? "").toLowerCase();
  if (isUnavailableCode(code) || error?.status === 503) return unavailable(error);
  if (error?.status === 403 || code === "organization_mismatch" || code.includes("audience")) return new QualificationGrantBatchDeviceHttpError(QUALIFICATION_GRANT_BATCH_DEVICE_HTTP_ERROR_CODES.AUDIENCE_MISMATCH, { status: 403, cause: error });
  return new QualificationGrantBatchDeviceHttpError(QUALIFICATION_GRANT_BATCH_DEVICE_HTTP_ERROR_CODES.DEVICE_AUTH_FAILED, { status: 401, cause: error });
}

function mapRepositoryError(error) {
  const code = String(error?.code ?? "").toUpperCase();
  if (error instanceof QualificationGrantBatchDeviceHttpError) return error;
  if (isRateLimitCode(code) || error?.status === 429) return new QualificationGrantBatchDeviceHttpError(QUALIFICATION_GRANT_BATCH_DEVICE_HTTP_ERROR_CODES.RATE_LIMITED, { status: 429, retryAfterSeconds: boundedRetryAfter(error), cause: error });
  if (isNotFoundCode(code) || error?.status === 404) return new QualificationGrantBatchDeviceHttpError(QUALIFICATION_GRANT_BATCH_DEVICE_HTTP_ERROR_CODES.NOT_FOUND, { status: 404, cause: error });
  if (isConflictCode(code) || error?.status === 409) return new QualificationGrantBatchDeviceHttpError(QUALIFICATION_GRANT_BATCH_DEVICE_HTTP_ERROR_CODES.BATCH_CONFLICT, { status: 409, cause: error });
  if (isInputCode(code) || error?.status === 400) return invalidRequest();
  return unavailable(error);
}

function isUnavailableCode(code) {
  const normalized = String(code).toUpperCase();
  return normalized === "ERR_DATABASE" || normalized === "ERR_DB_UNAVAILABLE" || normalized === "ERR_UNAVAILABLE" || normalized === "ETIMEDOUT" || normalized.includes("UNAVAILABLE") || normalized.includes("PROVIDER");
}

function isNotFoundCode(code) {
  const normalized = String(code).toUpperCase();
  return normalized === "ERR_NOT_FOUND" || normalized === "ERR_ORGANIZATION_NOT_FOUND" || normalized === "ERR_DEVICE_NOT_FOUND" || normalized === "ERR_QUALIFICATION_GRANT_BATCH_NOT_FOUND" || normalized === "ERR_GRANT_BATCH_NOT_FOUND";
}

function isConflictCode(code) {
  const normalized = String(code).toUpperCase();
  return normalized === "ERR_CONFLICT" || normalized === "ERR_GRANT_BATCH_CONFLICT" || normalized === "ERR_QUALIFICATION_GRANT_BATCH_CONFLICT" || normalized === "ERR_GRANT_BATCH_CONSUMED" || normalized === "ERR_IDEMPOTENCY_CONFLICT" || normalized === "ERR_UNIQUE_CONSTRAINT" || normalized === "ERR_GRANT_BATCH_EXPIRED";
}

function isRateLimitCode(code) {
  const normalized = String(code).toUpperCase();
  return normalized === "ERR_RATE_LIMITED" || normalized === "RATE_LIMITED" || normalized === "RATE_LIMITER_CAPACITY_EXHAUSTED";
}

function isInputCode(code) {
  const normalized = String(code).toUpperCase();
  return normalized === "ERR_INPUT" || normalized === "ERR_INVALID_INPUT" || normalized === "ERR_PROTOCOL_VALIDATION" || normalized === "ERR_HASH_MISMATCH";
}

function validRateLimitDecision(value) {
  return value && typeof value === "object" && typeof value.allowed === "boolean"
    && Number.isSafeInteger(value.limit) && value.limit > 0
    && Number.isSafeInteger(value.remaining) && value.remaining >= 0 && value.remaining <= value.limit
    && Number.isSafeInteger(value.retryAfterSeconds) && value.retryAfterSeconds >= 0;
}

function boundedRetryAfter(error) {
  const value = error?.retryAfterSeconds ?? error?.retry_after_seconds;
  return Number.isSafeInteger(value) && value >= 0 && value <= 3600 ? value : 1;
}

function invalidRequest() {
  return new QualificationGrantBatchDeviceHttpError(QUALIFICATION_GRANT_BATCH_DEVICE_HTTP_ERROR_CODES.INVALID_REQUEST, { status: 400 });
}

function unavailable(cause = undefined) {
  return new QualificationGrantBatchDeviceHttpError(QUALIFICATION_GRANT_BATCH_DEVICE_HTTP_ERROR_CODES.UNAVAILABLE, { status: 503, cause });
}

function readClock(now) {
  try { return readClockValue(now()); } catch (error) { throw unavailable(error); }
}

function readClockValue(value) {
  if (!Number.isSafeInteger(value) || value < 0 || value > 8_640_000_000_000_000) throw new Error("clock is invalid");
  return value;
}

function parseTimestamp(value) {
  const parsed = Date.parse(value);
  if (!TIMESTAMP.test(value) || !Number.isFinite(parsed) || new Date(parsed).toISOString() !== value) throw new Error("timestamp is invalid");
  return parsed;
}

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function makeRequestId(factory) {
  try {
    const value = factory();
    if (typeof value === "string" && UUID.test(value)) return value;
  } catch { /* Use a fresh local correlation ID below. */ }
  return crypto.randomUUID();
}

function errorBody(code, requestId) {
  return { error: { code, message: ERROR_MESSAGES[code] ?? ERROR_MESSAGES[QUALIFICATION_GRANT_BATCH_DEVICE_HTTP_ERROR_CODES.UNAVAILABLE] }, request_id: requestId };
}

function response(status, body, extraHeaders = undefined) {
  const headers = Object.freeze({ ...RESPONSE_HEADERS, ...(extraHeaders ?? {}) });
  const json = JSON.stringify(body);
  return Object.freeze({
    status,
    ok: status >= 200 && status < 300,
    headers,
    body: deepFreeze(body),
    text: async () => json,
    json: async () => body,
    toResponse: () => new Response(json, { status, headers })
  });
}

function writeNodeResponse(nodeResponse, result) {
  if (!nodeResponse || typeof nodeResponse.end !== "function") throw new TypeError("nodeResponse is invalid");
  if (typeof nodeResponse.writeHead === "function") nodeResponse.writeHead(result.status, result.headers);
  else if (typeof nodeResponse.setHeader === "function") for (const [name, value] of Object.entries(result.headers)) nodeResponse.setHeader(name, value);
  nodeResponse.statusCode = result.status;
  nodeResponse.end(JSON.stringify(result.body));
}

function isObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function clonePublicValue(value) {
  if (Array.isArray(value)) return value.map(clonePublicValue);
  if (isObject(value)) return Object.fromEntries(Object.entries(value).map(([key, nested]) => [key, clonePublicValue(nested)]));
  return value;
}

function deepFreeze(value) {
  if (!value || typeof value !== "object" || Object.isFrozen(value)) return value;
  for (const nested of Object.values(value)) deepFreeze(nested);
  return Object.freeze(value);
}

function statusFor(code) {
  return code === QUALIFICATION_GRANT_BATCH_DEVICE_HTTP_ERROR_CODES.INVALID_REQUEST ? 400
    : code === QUALIFICATION_GRANT_BATCH_DEVICE_HTTP_ERROR_CODES.DEVICE_AUTH_FAILED ? 401
      : code === QUALIFICATION_GRANT_BATCH_DEVICE_HTTP_ERROR_CODES.AUDIENCE_MISMATCH || code === QUALIFICATION_GRANT_BATCH_DEVICE_HTTP_ERROR_CODES.GRANT_NOT_AUTHORIZED ? 403
        : code === QUALIFICATION_GRANT_BATCH_DEVICE_HTTP_ERROR_CODES.NOT_FOUND ? 404
          : code === QUALIFICATION_GRANT_BATCH_DEVICE_HTTP_ERROR_CODES.BATCH_CONFLICT ? 409
            : code === QUALIFICATION_GRANT_BATCH_DEVICE_HTTP_ERROR_CODES.RATE_LIMITED ? 429 : 503;
}

function isAsyncIterable(value) {
  return value !== null && value !== undefined && typeof value[Symbol.asyncIterator] === "function";
}
