import crypto from "node:crypto";

import {
  HUMAN_RECOVERY_METRIC_KEYS,
  HUMAN_RECOVERY_OPERATIONS
} from "../postgres/operational-health.mjs";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
const MAX_RETRY_AFTER_MS = 60_000;
const MAX_RETRY_AFTER_SECONDS = Math.ceil(MAX_RETRY_AFTER_MS / 1_000);
const DEFAULT_IDLE_TTL_MS = 15 * 60_000;
const ANONYMOUS_GLOBAL_CAPACITY_MULTIPLIER = 64;
const ANONYMOUS_SUBJECT_SLOTS = 16_384;

export const HUMAN_AUTH_ABUSE_ERROR_CODES = Object.freeze({
  RATE_LIMITED: "human_auth_rate_limited",
  CONTROL_UNAVAILABLE: "human_auth_control_unavailable",
  TENANT_DENIED: "human_auth_tenant_denied"
});

export const HUMAN_AUTH_ABUSE_METRIC_KEYS = Object.freeze({
  rateLimitDenial: "human_auth_rate_limit_denial_total",
  controlUnavailable: "human_auth_rate_limit_unavailable_total",
  tenantDenial: "human_auth_tenant_denial_total"
});

export const HUMAN_AUTH_RATE_LIMIT_OPERATIONS = Object.freeze({
  sessionBootstrap: "human.session.bootstrap",
  webauthnBegin: "human.webauthn.begin",
  webauthnVerify: "human.webauthn.verify",
  registrationBegin: "human.webauthn.registration.begin",
  registrationVerify: "human.webauthn.registration.verify",
  invitationList: "human.invitation.list",
  invitationCreate: "human.invitation.create",
  invitationRevoke: "human.invitation.revoke",
  invitationAccept: "human.invitation.accept",
  recoveryCreate: HUMAN_RECOVERY_OPERATIONS.create,
  recoveryStatus: HUMAN_RECOVERY_OPERATIONS.status,
  recoveryApprove: HUMAN_RECOVERY_OPERATIONS.approve,
  recoveryCancel: HUMAN_RECOVERY_OPERATIONS.cancel,
  recoveryExchange: HUMAN_RECOVERY_OPERATIONS.exchange,
  recoveryRegistrationOptions: HUMAN_RECOVERY_OPERATIONS.registrationOptions,
  recoveryRegistrationVerify: HUMAN_RECOVERY_OPERATIONS.registrationVerify,
  recoveryActivate: HUMAN_RECOVERY_OPERATIONS.activate,
  recoveryOutboxList: "human.recovery.outbox.list",
  recoveryOutboxRedrive: "human.recovery.outbox.redrive",
  recoveryOutboxSuppress: "human.recovery.outbox.suppress",
  // Retain the original names for callers compiled against the first
  // recovery limiter contract. New recovery HTTP routes must use the
  // operation names above so each route has its own bounded bucket.
  recoveryBegin: "human.recovery.begin",
  recoveryVerify: "human.recovery.verify"
});

const DEFAULT_POLICIES = Object.freeze({
  [HUMAN_AUTH_RATE_LIMIT_OPERATIONS.sessionBootstrap]: Object.freeze({ capacity: 12, refillPerSecond: 0.2 }),
  [HUMAN_AUTH_RATE_LIMIT_OPERATIONS.webauthnBegin]: Object.freeze({ capacity: 24, refillPerSecond: 0.4 }),
  [HUMAN_AUTH_RATE_LIMIT_OPERATIONS.webauthnVerify]: Object.freeze({ capacity: 36, refillPerSecond: 0.6 }),
  [HUMAN_AUTH_RATE_LIMIT_OPERATIONS.registrationBegin]: Object.freeze({ capacity: 12, refillPerSecond: 0.2 }),
  [HUMAN_AUTH_RATE_LIMIT_OPERATIONS.registrationVerify]: Object.freeze({ capacity: 18, refillPerSecond: 0.3 }),
  [HUMAN_AUTH_RATE_LIMIT_OPERATIONS.invitationList]: Object.freeze({ capacity: 120, refillPerSecond: 2 }),
  [HUMAN_AUTH_RATE_LIMIT_OPERATIONS.invitationCreate]: Object.freeze({ capacity: 12, refillPerSecond: 0.2 }),
  [HUMAN_AUTH_RATE_LIMIT_OPERATIONS.invitationRevoke]: Object.freeze({ capacity: 24, refillPerSecond: 0.4 }),
  [HUMAN_AUTH_RATE_LIMIT_OPERATIONS.invitationAccept]: Object.freeze({ capacity: 8, refillPerSecond: 0.1 }),
  [HUMAN_AUTH_RATE_LIMIT_OPERATIONS.recoveryCreate]: Object.freeze({ capacity: 6, refillPerSecond: 0.05 }),
  [HUMAN_AUTH_RATE_LIMIT_OPERATIONS.recoveryStatus]: Object.freeze({ capacity: 60, refillPerSecond: 1 }),
  [HUMAN_AUTH_RATE_LIMIT_OPERATIONS.recoveryApprove]: Object.freeze({ capacity: 12, refillPerSecond: 0.1 }),
  [HUMAN_AUTH_RATE_LIMIT_OPERATIONS.recoveryCancel]: Object.freeze({ capacity: 12, refillPerSecond: 0.1 }),
  [HUMAN_AUTH_RATE_LIMIT_OPERATIONS.recoveryExchange]: Object.freeze({ capacity: 8, refillPerSecond: 0.1 }),
  [HUMAN_AUTH_RATE_LIMIT_OPERATIONS.recoveryRegistrationOptions]: Object.freeze({ capacity: 8, refillPerSecond: 0.1 }),
  [HUMAN_AUTH_RATE_LIMIT_OPERATIONS.recoveryRegistrationVerify]: Object.freeze({ capacity: 6, refillPerSecond: 0.05 }),
  [HUMAN_AUTH_RATE_LIMIT_OPERATIONS.recoveryActivate]: Object.freeze({ capacity: 6, refillPerSecond: 0.05 }),
  [HUMAN_AUTH_RATE_LIMIT_OPERATIONS.recoveryOutboxList]: Object.freeze({ capacity: 60, refillPerSecond: 1 }),
  [HUMAN_AUTH_RATE_LIMIT_OPERATIONS.recoveryOutboxRedrive]: Object.freeze({ capacity: 12, refillPerSecond: 0.1 }),
  [HUMAN_AUTH_RATE_LIMIT_OPERATIONS.recoveryOutboxSuppress]: Object.freeze({ capacity: 12, refillPerSecond: 0.1 }),
  [HUMAN_AUTH_RATE_LIMIT_OPERATIONS.recoveryBegin]: Object.freeze({ capacity: 6, refillPerSecond: 0.05 }),
  [HUMAN_AUTH_RATE_LIMIT_OPERATIONS.recoveryVerify]: Object.freeze({ capacity: 8, refillPerSecond: 0.1 })
});

const OPERATION_SET = new Set(Object.values(HUMAN_AUTH_RATE_LIMIT_OPERATIONS));

export class HumanAuthAbuseControlError extends Error {
  constructor(code, { retryAfterSeconds = undefined, cause = undefined } = {}) {
    const message = code === HUMAN_AUTH_ABUSE_ERROR_CODES.RATE_LIMITED
      ? "Human authentication rate limit exceeded"
      : code === HUMAN_AUTH_ABUSE_ERROR_CODES.TENANT_DENIED
        ? "The requested tenant is not available"
        : "Human authentication controls are temporarily unavailable";
    // Do not retain provider/SQL diagnostics on a public authentication
    // error. The cause parameter is accepted only so callers can deliberately
    // discard it at the boundary without changing their error plumbing.
    super(message);
    void cause;
    this.name = "HumanAuthAbuseControlError";
    this.code = code;
    this.status = code === HUMAN_AUTH_ABUSE_ERROR_CODES.RATE_LIMITED ? 429 : 503;
    if (code === HUMAN_AUTH_ABUSE_ERROR_CODES.TENANT_DENIED) this.status = 403;
    if (retryAfterSeconds !== undefined) {
      this.headers = Object.freeze({
        "Retry-After": String(retryAfterSeconds),
        "Cache-Control": "no-store, max-age=0"
      });
    }
  }
}

/**
 * Shared Human-auth admission control. Every decision is backed by the
 * PostgreSQL shared-control function; there is intentionally no in-memory
 * fallback because a fallback would make a multi-instance deployment fail
 * open. One operation has three independent buckets: session, member, and
 * organization. The operation is included in the derived UUID so policies
 * for different endpoints cannot overwrite one another in the generic
 * rate_limit_buckets table.
 */
export function createHumanAuthAbuseControls({ repository, bucketSecret, metrics, policies = {}, idleTtlMs = DEFAULT_IDLE_TTL_MS } = {}) {
  if (!repository || typeof repository.acquireRateLimit !== "function") {
    throw new TypeError("shared PostgreSQL rate-limit repository is required");
  }
  if (!Number.isSafeInteger(idleTtlMs) || idleTtlMs < 1_000 || idleTtlMs > 24 * 60 * 60 * 1000) throw new TypeError("idleTtlMs is invalid");
  const secret = normalizeBucketSecret(bucketSecret);
  const mergedPolicies = Object.freeze(Object.fromEntries([...OPERATION_SET].map((operation) => [operation, normalizePolicy(policies[operation] ?? DEFAULT_POLICIES[operation])] )));

  async function check({ operation, session, organizationId = undefined, cost = 1 } = {}) {
    if (!OPERATION_SET.has(operation)) throw new TypeError("Human auth rate-limit operation is invalid");
    recordRecoveryOperation(metrics, operation);
    const ids = normalizeSession(session);
    const targetOrganizationId = normalizeUuid(organizationId ?? ids.organizationId, "organizationId");
    if (targetOrganizationId !== ids.organizationId) {
      recordHumanAuthMetric(metrics, HUMAN_AUTH_ABUSE_METRIC_KEYS.tenantDenial);
      throw new HumanAuthAbuseControlError(HUMAN_AUTH_ABUSE_ERROR_CODES.TENANT_DENIED);
    }
    const policy = mergedPolicies[operation];
    if (!Number.isSafeInteger(cost) || cost < 1 || cost > policy.capacity) throw new TypeError("rate-limit cost is invalid");

    const scopes = [
      ["session", ids.sessionId],
      ["member", ids.memberId],
      ["organization", ids.organizationId]
    ];
    let mostRestrictive;
    try {
      for (const [scope, id] of scopes) {
        const decision = await repository.acquireRateLimit({
          organizationId: ids.organizationId,
          principalType: "human",
          principalId: deriveBucketId(secret, scope, id, operation),
          capacity: policy.capacity,
          refillPerSecond: policy.refillPerSecond,
          cost,
          idleTtlMs
        });
        const normalized = normalizeDecision(decision, policy.capacity);
        if (!normalized.allowed) mostRestrictive = mostRestrictive === undefined ? normalized : moreRestrictive(mostRestrictive, normalized);
      }
    } catch (error) {
      recordHumanAuthMetric(metrics, HUMAN_AUTH_ABUSE_METRIC_KEYS.controlUnavailable);
      throw new HumanAuthAbuseControlError(HUMAN_AUTH_ABUSE_ERROR_CODES.CONTROL_UNAVAILABLE, { cause: error });
    }
    if (mostRestrictive !== undefined) {
      recordHumanAuthMetric(metrics, HUMAN_AUTH_ABUSE_METRIC_KEYS.rateLimitDenial);
      throw new HumanAuthAbuseControlError(HUMAN_AUTH_ABUSE_ERROR_CODES.RATE_LIMITED, { retryAfterSeconds: mostRestrictive.retryAfterSeconds });
    }
    return Object.freeze({ allowed: true, operation, limit: policy.capacity });
  }

  async function checkAnonymous({ operation, principalId, cost = 1 } = {}) {
    if (operation !== HUMAN_AUTH_RATE_LIMIT_OPERATIONS.recoveryExchange) throw new TypeError("Anonymous rate-limit operation is invalid");
    recordRecoveryOperation(metrics, operation);
    const normalizedPrincipalId = normalizeUuid(principalId, "principalId");
    const policy = mergedPolicies[operation];
    if (typeof repository.acquireAnonymousRateLimit !== "function") {
      recordHumanAuthMetric(metrics, HUMAN_AUTH_ABUSE_METRIC_KEYS.controlUnavailable);
      throw new HumanAuthAbuseControlError(HUMAN_AUTH_ABUSE_ERROR_CODES.CONTROL_UNAVAILABLE);
    }
    if (!Number.isSafeInteger(cost) || cost < 1 || cost > policy.capacity) throw new TypeError("rate-limit cost is invalid");
    const globalCapacity = Math.min(1_000_000, policy.capacity * ANONYMOUS_GLOBAL_CAPACITY_MULTIPLIER);
    const globalRefill = Math.min(1_000_000, policy.refillPerSecond * ANONYMOUS_GLOBAL_CAPACITY_MULTIPLIER);
    try {
      // The global gate is intentionally first. During a spray it prevents
      // attacker-controlled exchange digests from creating unbounded rows.
      const global = normalizeDecision(await repository.acquireAnonymousRateLimit({
        operation,
        principalId: deriveHumanAuthGlobalBucketId(secret, operation),
        capacity: globalCapacity,
        refillPerSecond: globalRefill,
        cost,
        idleTtlMs
      }), globalCapacity);
      if (!global.allowed) return deny(global);
      const principal = normalizeDecision(await repository.acquireAnonymousRateLimit({
        operation,
        principalId: deriveAnonymousSubjectSlotId(secret, normalizedPrincipalId, operation),
        capacity: policy.capacity,
        refillPerSecond: policy.refillPerSecond,
        cost,
        idleTtlMs
      }), policy.capacity);
      if (!principal.allowed) return deny(principal);
    } catch (error) {
      if (error instanceof HumanAuthAbuseControlError) throw error;
      recordHumanAuthMetric(metrics, HUMAN_AUTH_ABUSE_METRIC_KEYS.controlUnavailable);
      throw new HumanAuthAbuseControlError(HUMAN_AUTH_ABUSE_ERROR_CODES.CONTROL_UNAVAILABLE, { cause: error });
    }
    return Object.freeze({ allowed: true, operation, limit: policy.capacity });

    function deny(decision) {
      recordHumanAuthMetric(metrics, HUMAN_AUTH_ABUSE_METRIC_KEYS.rateLimitDenial);
      throw new HumanAuthAbuseControlError(HUMAN_AUTH_ABUSE_ERROR_CODES.RATE_LIMITED, { retryAfterSeconds: decision.retryAfterSeconds });
    }
  }

  async function checkAnonymousGlobal({ operation, cost = 1 } = {}) {
    if (operation !== HUMAN_AUTH_RATE_LIMIT_OPERATIONS.sessionBootstrap) throw new TypeError("Anonymous global rate-limit operation is invalid");
    const policy = mergedPolicies[operation];
    if (typeof repository.acquireAnonymousRateLimit !== "function") {
      recordHumanAuthMetric(metrics, HUMAN_AUTH_ABUSE_METRIC_KEYS.controlUnavailable);
      throw new HumanAuthAbuseControlError(HUMAN_AUTH_ABUSE_ERROR_CODES.CONTROL_UNAVAILABLE);
    }
    if (!Number.isSafeInteger(cost) || cost < 1 || cost > policy.capacity) throw new TypeError("rate-limit cost is invalid");
    const globalCapacity = Math.min(1_000_000, policy.capacity * ANONYMOUS_GLOBAL_CAPACITY_MULTIPLIER);
    const globalRefill = Math.min(1_000_000, policy.refillPerSecond * ANONYMOUS_GLOBAL_CAPACITY_MULTIPLIER);
    try {
      const decision = normalizeDecision(await repository.acquireAnonymousRateLimit({
        operation,
        principalId: deriveHumanAuthGlobalBucketId(secret, operation),
        capacity: globalCapacity,
        refillPerSecond: globalRefill,
        cost,
        idleTtlMs
      }), globalCapacity);
      if (!decision.allowed) deny(decision);
    } catch (error) {
      if (error instanceof HumanAuthAbuseControlError) throw error;
      recordHumanAuthMetric(metrics, HUMAN_AUTH_ABUSE_METRIC_KEYS.controlUnavailable);
      throw new HumanAuthAbuseControlError(HUMAN_AUTH_ABUSE_ERROR_CODES.CONTROL_UNAVAILABLE, { cause: error });
    }
    return Object.freeze({ allowed: true, operation, limit: globalCapacity });

    function deny(decision) {
      recordHumanAuthMetric(metrics, HUMAN_AUTH_ABUSE_METRIC_KEYS.rateLimitDenial);
      throw new HumanAuthAbuseControlError(HUMAN_AUTH_ABUSE_ERROR_CODES.RATE_LIMITED, { retryAfterSeconds: decision.retryAfterSeconds });
    }
  }

  async function checkIdentity({ operation, identity, cost = 1 } = {}) {
    if (operation !== HUMAN_AUTH_RATE_LIMIT_OPERATIONS.sessionBootstrap) throw new TypeError("Identity rate-limit operation is invalid");
    const ids = normalizeIdentityScope(identity);
    const policy = mergedPolicies[operation];
    if (!Number.isSafeInteger(cost) || cost < 1 || cost > policy.capacity) throw new TypeError("rate-limit cost is invalid");
    let mostRestrictive;
    try {
      for (const [scope, id] of [["subject", ids.subjectBucketId], ["member", ids.memberId], ["organization", ids.organizationId]]) {
        const decision = normalizeDecision(await repository.acquireRateLimit({
          organizationId: ids.organizationId,
          principalType: "human",
          principalId: deriveBucketId(secret, scope, id, operation),
          capacity: policy.capacity,
          refillPerSecond: policy.refillPerSecond,
          cost,
          idleTtlMs
        }), policy.capacity);
        if (!decision.allowed) mostRestrictive = mostRestrictive === undefined ? decision : moreRestrictive(mostRestrictive, decision);
      }
    } catch (error) {
      recordHumanAuthMetric(metrics, HUMAN_AUTH_ABUSE_METRIC_KEYS.controlUnavailable);
      throw new HumanAuthAbuseControlError(HUMAN_AUTH_ABUSE_ERROR_CODES.CONTROL_UNAVAILABLE, { cause: error });
    }
    if (mostRestrictive !== undefined) {
      recordHumanAuthMetric(metrics, HUMAN_AUTH_ABUSE_METRIC_KEYS.rateLimitDenial);
      throw new HumanAuthAbuseControlError(HUMAN_AUTH_ABUSE_ERROR_CODES.RATE_LIMITED, { retryAfterSeconds: mostRestrictive.retryAfterSeconds });
    }
    return Object.freeze({ allowed: true, operation, limit: policy.capacity });
  }

  return Object.freeze({
    check,
    checkAnonymous,
    checkAnonymousGlobal,
    checkIdentity,
    // `authorize` is the existing public name. Keep it as a strict alias so
    // old human-auth routes and new recovery routes share identical fail-
    // closed semantics and bucket derivation.
    authorize: check,
    policies: mergedPolicies,
    maxRetryAfterSeconds: MAX_RETRY_AFTER_SECONDS
  });
}

function recordRecoveryOperation(metrics, operation) {
  const key = HUMAN_RECOVERY_METRIC_KEYS[operation];
  if (!key) return;
  try {
    if (typeof metrics?.increment === "function") metrics.increment(key, 1);
    else metrics?.recordHumanRecoveryOperation?.(operation, 1);
  } catch {
    // Telemetry must never change the authentication decision.
  }
}

export function recordHumanAuthMetric(metrics, key, amount = 1) {
  try {
    if (typeof metrics?.increment === "function") metrics.increment(key, amount);
    else if (key === HUMAN_AUTH_ABUSE_METRIC_KEYS.rateLimitDenial) metrics?.recordHumanAuthRateLimitDenial?.(amount);
    else if (key === HUMAN_AUTH_ABUSE_METRIC_KEYS.controlUnavailable) metrics?.recordHumanAuthRateLimitUnavailable?.(amount);
    else if (key === HUMAN_AUTH_ABUSE_METRIC_KEYS.tenantDenial) metrics?.recordHumanAuthTenantDenial?.(amount);
  } catch {
    // Telemetry must never change the authentication decision.
  }
}

export function boundedRetryAfterSeconds(value) {
  const milliseconds = Number.isFinite(Number(value)) ? Math.max(0, Math.min(MAX_RETRY_AFTER_MS, Number(value))) : 0;
  return Math.max(1, Math.min(MAX_RETRY_AFTER_SECONDS, Math.ceil(milliseconds / 1_000)));
}

function normalizePolicy(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new TypeError("rate-limit policy is invalid");
  if (!Number.isSafeInteger(value.capacity) || value.capacity < 1 || value.capacity > 1_000_000) throw new TypeError("rate-limit capacity is invalid");
  if (typeof value.refillPerSecond !== "number" || !Number.isFinite(value.refillPerSecond) || value.refillPerSecond <= 0 || value.refillPerSecond > 1_000_000) throw new TypeError("rate-limit refill is invalid");
  return Object.freeze({ capacity: value.capacity, refillPerSecond: value.refillPerSecond });
}

function normalizeDecision(value, fallbackLimit) {
  if (!value || typeof value !== "object" || typeof value.allowed !== "boolean") throw new Error("rate-limit decision is invalid");
  return Object.freeze({
    allowed: value.allowed,
    limit: Number.isSafeInteger(value.limit) && value.limit > 0 ? value.limit : fallbackLimit,
    remaining: Number.isSafeInteger(value.remaining) && value.remaining >= 0 ? value.remaining : 0,
    retryAfterSeconds: boundedRetryAfterSeconds(value.retryAfterMs)
  });
}

function moreRestrictive(left, right) {
  if (right.retryAfterSeconds > left.retryAfterSeconds) return right;
  if (right.remaining < left.remaining) return right;
  return left;
}

function normalizeSession(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new TypeError("authenticated Human session is invalid");
  return Object.freeze({
    sessionId: normalizeUuid(value.session_id ?? value.sessionId, "session_id"),
    memberId: normalizeUuid(value.member_id ?? value.memberId, "member_id"),
    organizationId: normalizeUuid(value.organization_id ?? value.organizationId, "organization_id")
  });
}

function normalizeIdentityScope(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new TypeError("verified Human identity is invalid");
  return Object.freeze({
    subjectBucketId: normalizeUuid(value.subject_bucket_id ?? value.subjectBucketId, "subject_bucket_id"),
    memberId: normalizeUuid(value.member_id ?? value.memberId, "member_id"),
    organizationId: normalizeUuid(value.organization_id ?? value.organizationId, "organization_id")
  });
}

export function deriveHumanAuthSubjectBucketId(bucketSecret, { provider, subject } = {}) {
  const secret = normalizeBucketSecret(bucketSecret);
  if (typeof provider !== "string" || !/^[a-z][a-z0-9._-]{0,63}$/u.test(provider)) throw new TypeError("identity provider is invalid");
  if (typeof subject !== "string" || subject.length < 1 || Buffer.byteLength(subject, "utf8") > 512 || /[\u0000-\u001f\u007f]/u.test(subject)) throw new TypeError("identity subject is invalid");
  return deriveBucketId(secret, "provider-subject", `${provider}\0${subject}`, HUMAN_AUTH_RATE_LIMIT_OPERATIONS.sessionBootstrap);
}

export function deriveHumanAuthGlobalBucketId(bucketSecret, operation) {
  const secret = normalizeBucketSecret(bucketSecret);
  if (!OPERATION_SET.has(operation)) throw new TypeError("Human auth rate-limit operation is invalid");
  return deriveBucketId(secret, "anonymous-global", "global", operation);
}

function normalizeUuid(value, name) {
  if (typeof value !== "string" || !UUID.test(value)) throw new TypeError(`${name} is invalid`);
  return value.toLowerCase();
}

function normalizeBucketSecret(value) {
  let bytes = value;
  if (typeof value === "string" && /^[A-Za-z0-9_-]{43}$/u.test(value)) bytes = Buffer.from(value, "base64url");
  if (!Buffer.isBuffer(bytes) && !(bytes instanceof Uint8Array)) throw new TypeError("Human auth bucket secret is invalid");
  const result = Buffer.from(bytes);
  if (result.length !== 32) throw new TypeError("Human auth bucket secret is invalid");
  return result;
}

function deriveAnonymousSubjectSlotId(secret, principalId, operation) {
  const digest = crypto.createHmac("sha256", secret)
    .update("agentpass:human-auth:anonymous-slot:v1\0", "utf8")
    .update(operation, "utf8")
    .update("\0", "utf8")
    .update(principalId, "utf8")
    .digest();
  const slot = digest.readUInt32BE(0) % ANONYMOUS_SUBJECT_SLOTS;
  return deriveBucketId(secret, "anonymous-subject-slot", String(slot), operation);
}

function deriveBucketId(secret, scope, id, operation) {
  const digest = crypto.createHmac("sha256", secret)
    .update("agentpass:human-auth:rate-limit:v2\0", "utf8")
    .update(scope, "utf8")
    .update("\0", "utf8")
    .update(id, "utf8")
    .update("\0", "utf8")
    .update(operation, "utf8")
    .digest();
  digest[6] = (digest[6] & 0x0f) | 0x40;
  digest[8] = (digest[8] & 0x3f) | 0x80;
  const hex = digest.subarray(0, 16).toString("hex");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}
