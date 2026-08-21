import crypto from "node:crypto";

import { canonicalJson } from "../../../packages/protocol/src/index.mjs";
import { normalizePromotionAuthority } from "./postgres/promotion-issuance-repository.mjs";
import {
  PLATFORM_AUTH_ERROR_CODES,
  PLATFORM_RECENT_AUTH_MAX_AGE_MS,
  PLATFORM_RECENT_AUTH_MAX_CLOCK_SKEW_MS,
  PLATFORM_WORKLOAD_IDENTITY_MAX_TTL_MS,
  PLATFORM_ROLES
} from "./platform-auth.mjs";

export const PLATFORM_PROMOTION_PATHS = Object.freeze({
  issue: "/platform/v1/promotions/issue",
  commit: "/platform/v1/promotions/commit",
  reconcile: "/platform/v1/promotions/reconcile"
});

const AUTHORITY_KEYS = Object.freeze([
  "deployment_id",
  "environment",
  "promotion_id",
  "candidate_id",
  "source_commit",
  "source_tree",
  "product_pkg_sha256",
  "release_manifest_sha256",
  "sbom_sha256",
  "image_digest",
  "qualification_report_digests",
  "approval_id",
  "approval_digest",
  "signer_key_id",
  "signer_key_version",
  "signer_lifecycle_version",
  "expected_deployment_generation"
]);
const ISSUE_KEYS = Object.freeze([...AUTHORITY_KEYS, "provider_operation_id"]);
const RECONCILE_KEYS = Object.freeze(["provider_operation_id", "evidence"]);
const IDEMPOTENCY_KEY = /^[A-Za-z0-9][A-Za-z0-9._~:-]{7,254}$/u;
const MAX_BODY_BYTES = 256 * 1024;
const MAX_RESPONSE_BYTES = 256 * 1024;
const FORBIDDEN_ORGANIZATION_HEADERS = Object.freeze(["authorization", "cookie", "agentpass-csrf"]);
const REQUEST_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const PROVIDER_OPERATION_ID = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$/u;
const FINGERPRINT_256 = /^(?:[0-9a-f]{2}:){31}[0-9a-f]{2}$/iu;
const SPIFFE_ID = /^spiffe:\/\/[^\u0000-\u0020\u007f]{1,480}$/u;
const AUDIENCE = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$/u;
const PLATFORM_AUTH_UNAVAILABLE_CODES = new Set([
  PLATFORM_AUTH_ERROR_CODES.PRINCIPAL_UNAVAILABLE,
  PLATFORM_AUTH_ERROR_CODES.MTLS_UNAVAILABLE,
  PLATFORM_AUTH_ERROR_CODES.WORKLOAD_UNAVAILABLE,
  PLATFORM_AUTH_ERROR_CODES.WEBAUTHN_UNAVAILABLE,
  PLATFORM_AUTH_ERROR_CODES.WORKLOAD_FAILED,
  PLATFORM_AUTH_ERROR_CODES.WEBAUTHN_FAILED
]);

export class PlatformPromotionHttpApiError extends Error {
  constructor(code, status, message = "Platform promotion request was rejected") {
    super(message);
    this.name = "PlatformPromotionHttpApiError";
    this.code = code;
    this.status = status;
  }
}

/**
 * HTTP boundary for deployment-scoped C3 promotion authority.
 *
 * `authenticate` is intentionally not an organization authenticator. It must
 * return the composed result from platform-auth's authorizePlatformOperation.
 * The adapter rejects the transport headers used by bearer and Human sessions
 * before calling it, so an organization session cannot be upgraded here.
 */
export function createPlatformPromotionHttpApi({ repository, authenticate, auditAppender, requireAudit = false, expectedWorkloadAudience, expectedSpiffeId, now = () => Date.now() } = {}) {
  if (!repository || typeof repository.reservePromotion !== "function"
    || typeof repository.commitPromotion !== "function"
    || typeof repository.reconcileUncertainPromotion !== "function"
    || repository.supportsAtomicPromotionAudit !== true) {
    throw new TypeError("platform promotion repository is incomplete");
  }
  if (typeof authenticate !== "function") throw new TypeError("platform promotion authenticator is required");
  if (auditAppender !== undefined && typeof auditAppender !== "function") throw new TypeError("platform promotion audit appender is invalid");
  if (typeof requireAudit !== "boolean") throw new TypeError("platform promotion audit requirement is invalid");
  if (expectedWorkloadAudience !== undefined && (typeof expectedWorkloadAudience !== "string" || expectedWorkloadAudience.length === 0)) throw new TypeError("expected workload audience is invalid");
  if (expectedSpiffeId !== undefined && (typeof expectedSpiffeId !== "string" || !expectedSpiffeId.startsWith("spiffe://"))) throw new TypeError("expected SPIFFE identity is invalid");
  if (typeof now !== "function") throw new TypeError("platform promotion clock is invalid");

  async function appendAudit({ requestId, action, idempotencyKey, authorization, authority, providerOperationId, outcome, result, error, tx }) {
    if (auditAppender === undefined) throw platformError("platform_audit_unavailable", 503);
    const mappedError = error === undefined ? undefined : mapPlatformPromotionError(error);
    try { await auditAppender({
      ...(tx === undefined ? {} : { tx }),
      event_type: `platform.promotion.${action}.${outcome}`,
      request_id: requestId,
      actor_id: authorization?.principal?.member_id,
      platform_role: authorization?.principal?.platform_role,
      target_type: "platform_promotion",
      target_id: authority.promotion_id,
      idempotency_key: auditIdempotencyKey(action, idempotencyKey),
      details: {
        deployment_id: authority.deployment_id,
        environment: authority.environment,
        promotion_id: authority.promotion_id,
        candidate_id: authority.candidate_id,
        source_commit: authority.source_commit,
        source_tree: authority.source_tree,
        product_pkg_sha256: authority.product_pkg_sha256,
        release_manifest_sha256: authority.release_manifest_sha256,
        sbom_sha256: authority.sbom_sha256,
        image_digest: authority.image_digest,
        qualification_report_digests: authority.qualification_report_digests,
        approval_id: authority.approval_id,
        approval_digest: authority.approval_digest,
        signer_key_id: authority.signer_key_id,
        signer_key_version: authority.signer_key_version,
        signer_lifecycle_version: authority.signer_lifecycle_version,
        expected_deployment_generation: authority.expected_deployment_generation,
        provider_operation_id: providerOperationId,
        ...(result?.state === "committed" && Number.isSafeInteger(result.generation) ? { generation: result.generation } : {}),
        ...(mappedError === undefined ? {} : { error_code: mappedError.code })
      }
    }); } catch { throw platformError("platform_audit_unavailable", 503); }
  }

  async function handle({ method, url, request, headers = {}, body = Buffer.alloc(0), requestId = crypto.randomUUID() } = {}) {
    if (!REQUEST_ID.test(requestId)) throw platformError("platform_promotion_unavailable", 503);
    const path = new URL(String(url ?? ""), "http://agentpass.invalid");
    const action = method === "POST" && path.search === "" ? actionForPath(path.pathname) : undefined;
    if (!action) return response(404, { error: { code: "not_found", message: "Resource not found" }, request_id: requestId });

    const bodyBytes = Buffer.isBuffer(body) || body instanceof Uint8Array ? Buffer.from(body) : null;
    if (!bodyBytes || bodyBytes.length > MAX_BODY_BYTES) return response(400, { error: { code: "invalid_platform_request", message: "Platform promotion request is invalid" }, request_id: requestId });
    for (const name of FORBIDDEN_ORGANIZATION_HEADERS) {
      if (hasHeader(headers, name)) {
        return response(401, { error: { code: "platform_authentication_failed", message: "Authentication failed" }, request_id: requestId });
      }
    }

    let authorization;
    let input;
    let authority;
    let providerOperationId;
    let idempotencyKey;
    try {
      input = parseJson(bodyBytes);
      idempotencyKey = header(headers, "idempotency-key");
      if (!IDEMPOTENCY_KEY.test(idempotencyKey ?? "")) throw platformError("invalid_platform_request", 400);
      if (action === "issue") exactKeys(input, ISSUE_KEYS, "promotion_issue");
      if (action === "commit") exactKeys(input, [...AUTHORITY_KEYS, "claim_token", "evidence", "provider_operation_id"], "promotion_commit");
      if (action === "reconcile") exactKeys(input, [...AUTHORITY_KEYS, ...RECONCILE_KEYS], "promotion_reconcile");
      providerOperationId = normalizeProviderOperationId(input.provider_operation_id);
      if (requireAudit && auditAppender === undefined) throw platformError("platform_audit_unavailable", 503);
      authority = normalizeHttpAuthority(Object.fromEntries(AUTHORITY_KEYS.map((key) => [key, input[key]])), idempotencyKey);
      const contextHash = promotionAuthContextHash({ action, idempotencyKey, input });
      authorization = await authenticatePlatform({ authenticate, expectedWorkloadAudience, expectedSpiffeId, method, url: `${path.pathname}${path.search}`, request, headers, body: bodyBytes, operation: `promotion.${action}`, contextHash, now });
      const onMutation = async ({ tx, result }) => {
        const publicPromotion = publicOutcome(result, providerOperationId);
        await appendAudit({ requestId, action, idempotencyKey, authorization, authority, providerOperationId, outcome: publicPromotion.state, result: publicPromotion, tx });
      };
      let result;
      if (action === "issue") {
        result = await repository.reservePromotion({ ...authority, provider_operation_id: providerOperationId, onMutation });
      } else if (action === "commit") {
        result = await repository.commitPromotion({ ...authority, claim_token: input.claim_token, evidence: input.evidence, provider_operation_id: providerOperationId, onMutation });
      } else {
        result = await repository.reconcileUncertainPromotion({ ...authority, provider_operation_id: providerOperationId, evidence: input.evidence, onMutation });
      }
      const publicPromotion = publicOutcome(result, providerOperationId);
      return response(statusForOutcome(action, result), { promotion: publicPromotion, request_id: requestId });
    } catch (error) {
      if (error?.code !== "platform_audit_unavailable" && auditAppender !== undefined && authorization && authority) {
        await appendAudit({ requestId, action, idempotencyKey, authorization, authority, providerOperationId, outcome: "failed", error }).catch(() => {
          throw platformError("platform_audit_unavailable", 503);
        });
      }
      throw mapPlatformPromotionError(error);
    }
  }

  return Object.freeze({ handle });
}

export function isPlatformPromotionPath(pathname) {
  return Object.values(PLATFORM_PROMOTION_PATHS).includes(pathname);
}

async function authenticatePlatform({ authenticate, expectedWorkloadAudience, expectedSpiffeId, method, url, request, headers, body, operation, contextHash, now = () => Date.now() }) {
  const currentTime = now();
  if (!Number.isSafeInteger(currentTime) || currentTime < 0
    || typeof expectedWorkloadAudience !== "string" || !AUDIENCE.test(expectedWorkloadAudience)
    || typeof expectedSpiffeId !== "string" || !SPIFFE_ID.test(expectedSpiffeId)) {
    throw platformError("platform_authentication_unavailable", 503);
  }

  let result;
  try {
    result = await authenticate({ method, url, request, operation, context_hash: contextHash, headers: Object.freeze({ ...headers }), body: Buffer.from(body), now: currentTime });
  } catch (error) {
    if (error?.code === PLATFORM_AUTH_ERROR_CODES.ROLE_REQUIRED || error?.code === PLATFORM_AUTH_ERROR_CODES.ROLE_DENIED) {
      throw platformError("platform_authorization_denied", 403);
    }
    if (PLATFORM_AUTH_UNAVAILABLE_CODES.has(error?.code)) {
      throw platformError("platform_authentication_unavailable", 503);
    }
    throw platformError("platform_authentication_failed", 401);
  }
  const shapeValid = Boolean(result && typeof result === "object" && !Array.isArray(result)
    && Object.keys(result).sort().join(",") === "mtls,principal,webauthn,workload"
    && result.mtls && typeof result.mtls === "object" && !Array.isArray(result.mtls)
    && hasExactKeys(result.mtls, ["fingerprint256", "spiffe_id"])
    && FINGERPRINT_256.test(result.mtls.fingerprint256) && !isZeroFingerprint(result.mtls.fingerprint256)
    && typeof result.mtls.spiffe_id === "string" && result.mtls.spiffe_id.startsWith("spiffe://")
    && SPIFFE_ID.test(result.mtls.spiffe_id)
    && result.mtls.spiffe_id === expectedSpiffeId
    && result.workload && typeof result.workload === "object" && !Array.isArray(result.workload)
    && hasExactKeys(result.workload, ["audience", "expires_at", "mtls_fingerprint256", "verified", "workload_id"])
    && result.workload.verified === true
    && typeof result.workload.workload_id === "string" && result.workload.workload_id === result.mtls.spiffe_id
    && typeof result.workload.audience === "string" && result.workload.audience.length > 0
    && AUDIENCE.test(result.workload.audience)
    && result.workload.audience === expectedWorkloadAudience
    && Number.isSafeInteger(result.workload.expires_at)
    && result.workload.expires_at > currentTime
    && result.workload.expires_at - currentTime <= PLATFORM_WORKLOAD_IDENTITY_MAX_TTL_MS
    && FINGERPRINT_256.test(result.workload.mtls_fingerprint256)
    && !isZeroFingerprint(result.workload.mtls_fingerprint256)
    && result.workload.mtls_fingerprint256.toLowerCase() === result.mtls.fingerprint256.toLowerCase()
    && result.webauthn && typeof result.webauthn === "object" && !Array.isArray(result.webauthn)
    && hasExactKeys(result.webauthn, ["authenticated_at", "challenge_id", "consumed", "context_hash", "member_id", "operation", "verified"])
    && typeof result.webauthn.challenge_id === "string" && UUID_V4.test(result.webauthn.challenge_id) && result.webauthn.challenge_id === result.webauthn.challenge_id.toLowerCase()
    && Number.isSafeInteger(result.webauthn.authenticated_at) && result.webauthn.authenticated_at >= 0
    && result.webauthn.authenticated_at <= currentTime + PLATFORM_RECENT_AUTH_MAX_CLOCK_SKEW_MS
    && currentTime - result.webauthn.authenticated_at <= PLATFORM_RECENT_AUTH_MAX_AGE_MS
    && result.principal && typeof result.principal === "object" && !Array.isArray(result.principal)
    && hasExactKeys(result.principal, ["member_id", "platform_role", "session_id"])
    && typeof result.principal.member_id === "string" && result.principal.member_id.length > 0
    && typeof result.principal.session_id === "string" && result.principal.session_id.length > 0
    && PLATFORM_ROLES.includes(result.principal.platform_role)
    && result.webauthn.member_id === result.principal.member_id
    && typeof result.webauthn.context_hash === "string" && /^[0-9a-f]{64}$/u.test(result.webauthn.context_hash) && result.webauthn.context_hash === contextHash
    && result.webauthn.operation === operation
    && result.webauthn.consumed === true && result.webauthn.verified === true);
  if (!shapeValid) throw platformError("platform_authentication_failed", 401);
  if (result.principal.platform_role === "platform_auditor") throw platformError("platform_authorization_denied", 403);
  return result;
}

function actionForPath(pathname) {
  for (const [action, path] of Object.entries(PLATFORM_PROMOTION_PATHS)) if (pathname === path) return action;
  return undefined;
}

function normalizeHttpAuthority(input, idempotencyKey) {
  exactKeys(input, AUTHORITY_KEYS, "promotion_authority");
  try { return normalizePromotionAuthority({ ...input, idempotency_key: idempotencyKey }); }
  catch { throw platformError("invalid_platform_request", 400); }
}

function normalizeProviderOperationId(value) {
  if (typeof value !== "string" || !PROVIDER_OPERATION_ID.test(value)) throw platformError("invalid_platform_request", 400);
  return value;
}

function isZeroFingerprint(value) {
  return typeof value === "string" && value.replaceAll(":", "").toLowerCase() === "0".repeat(64);
}

function hasExactKeys(value, expected) {
  return Object.keys(value).sort().join("\0") === [...expected].sort().join("\0");
}

function parseJson(body) {
  if (body.length === 0) throw platformError("invalid_platform_request", 400);
  let value;
  try { value = JSON.parse(body.toString("utf8")); } catch { throw platformError("invalid_platform_request", 400); }
  if (!value || typeof value !== "object" || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) throw platformError("invalid_platform_request", 400);
  return value;
}

function exactKeys(value, expected, operation) {
  if (!value || typeof value !== "object" || Array.isArray(value) || Object.keys(value).sort().join("\0") !== [...expected].sort().join("\0")) {
    throw platformError("invalid_platform_request", 400, operation);
  }
}

function publicOutcome(result, expectedProviderOperationId) {
  if (!result || typeof result !== "object" || Array.isArray(result) || typeof result.state !== "string") throw platformError("platform_promotion_unavailable", 503);
  if (["reserved", "committed", "uncertain"].includes(result.state)
    && (typeof result.provider_operation_id !== "string" || result.provider_operation_id !== expectedProviderOperationId)) throw platformError("platform_promotion_unavailable", 503);
  if (result.state === "reserved") return {
    state: "reserved",
    promotion_id: result.promotion_id,
    provider_operation_id: result.provider_operation_id,
    authority_digest: result.authority_digest,
    claim_token: result.claim_token,
    expires_at: result.expires_at
  };
  if (result.state === "committed") return { state: "committed", promotion_id: result.promotion_id, provider_operation_id: result.provider_operation_id, evidence: result.evidence, generation: result.generation };
  if (result.state === "rejected") return { state: "rejected", reason: result.reason };
  if (result.state === "in_progress") return { state: "in_progress" };
  if (result.state === "uncertain") return { state: "uncertain", provider_operation_id: result.provider_operation_id };
  if (result.state === "absent") return { state: "absent" };
  throw platformError("platform_promotion_unavailable", 503);
}

function statusForOutcome(action, result) {
  if (action === "issue" && result?.state === "reserved") return 201;
  if (result?.state === "in_progress" || result?.state === "uncertain") return 409;
  if (result?.state === "rejected") return 409;
  return 200;
}

function response(status, body) {
  const encoded = Buffer.from(JSON.stringify(body), "utf8");
  if (encoded.length > MAX_RESPONSE_BYTES) throw platformError("platform_promotion_unavailable", 503);
  return { status, body, headers: { "cache-control": "no-store" } };
}

function header(headers, name) {
  if (!headers || typeof headers !== "object") return undefined;
  const keys = Object.keys(headers).filter((candidate) => candidate.toLowerCase() === name.toLowerCase());
  if (keys.length !== 1) return undefined;
  const value = headers[keys[0]];
  return typeof value === "string" ? value : undefined;
}

function hasHeader(headers, name) {
  if (!headers || typeof headers !== "object") return false;
  const normalized = name.toLowerCase();
  return Object.keys(headers).some((candidate) => candidate.toLowerCase() === normalized);
}

function auditIdempotencyKey(action, idempotencyKey) {
  if (typeof idempotencyKey !== "string" || !IDEMPOTENCY_KEY.test(idempotencyKey)) throw platformError("invalid_platform_request", 400);
  return `platform-promotion:${crypto.createHash("sha256").update(`${action}\u0000${idempotencyKey}`, "utf8").digest("hex")}`;
}

function promotionAuthContextHash({ action, idempotencyKey, input }) {
  return crypto.createHash("sha256").update(canonicalJson({ action, idempotency_key: idempotencyKey, request: input }), "utf8").digest("hex");
}

function platformError(code, status, detail = "") {
  return new PlatformPromotionHttpApiError(code, status, detail || "Platform promotion request was rejected");
}

function mapPlatformPromotionError(error) {
  if (error instanceof PlatformPromotionHttpApiError) return error;
  switch (error?.code) {
    case "ERR_PROMOTION_ISSUANCE_INPUT":
      return platformError("invalid_platform_request", 400);
    case "ERR_PROMOTION_ISSUANCE_NOT_FOUND":
      return platformError("not_found", 404);
    case "ERR_PROMOTION_ISSUANCE_CONFLICT":
    case "ERR_PROMOTION_ISSUANCE_IN_PROGRESS":
    case "ERR_PROMOTION_ISSUANCE_UNCERTAIN":
    case "ERR_PROMOTION_ISSUANCE_CLAIM":
      return platformError("platform_promotion_conflict", 409);
    case "ERR_PROMOTION_ISSUANCE_CONFIG":
    case "ERR_PROMOTION_ISSUANCE_DATABASE":
      return platformError("platform_promotion_unavailable", 503);
    default:
      return platformError("platform_promotion_unavailable", 503);
  }
}
