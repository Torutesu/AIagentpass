import crypto from "node:crypto";

import { boundedRetryAfterSeconds } from "./human-auth/rate-limit.mjs";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
const DIGEST = /^[0-9a-f]{64}$/iu;
const MAX_RETRY_AFTER_SECONDS = 60;
const MAX_IDENTIFIER_BYTES = 256;
const DEFAULT_IDLE_TTL_MS = 15 * 60 * 1000;
const ANONYMOUS_GLOBAL_CAPACITY_MULTIPLIER = 64;

// These are deliberately fixed-size slot spaces.  An attacker may influence
// the transport value or present a different challenge/proof on every request,
// but those values can never create an unbounded number of PostgreSQL buckets.
export const PLATFORM_SESSION_RATE_LIMIT_KEY_SLOTS = Object.freeze({
  transport: 64,
  session: 64,
  csrf: 64,
  jti: 64,
  proof: 64
});

export const PLATFORM_SESSION_RATE_LIMIT_PHASES = Object.freeze([
  "challenge",
  "assertion",
  "revoke",
  "promotion"
]);

export const PLATFORM_SESSION_RATE_LIMIT_OPERATIONS = Object.freeze({
  challenge: "platform.session.challenge",
  assertion: "platform.session.assertion",
  revoke: "platform.session.revoke",
  promotion: "platform.promotion.issue"
});

export const PLATFORM_SESSION_RATE_LIMIT_POLICIES = Object.freeze({
  challenge: Object.freeze({ capacity: 24, refillPerSecond: 0.4 }),
  assertion: Object.freeze({ capacity: 36, refillPerSecond: 0.6 }),
  revoke: Object.freeze({ capacity: 60, refillPerSecond: 1 }),
  promotion: Object.freeze({ capacity: 12, refillPerSecond: 0.2 })
});

export const PLATFORM_SESSION_RATE_LIMIT_ERROR_CODES = Object.freeze({
  RATE_LIMITED: "platform_session_rate_limited",
  CONTROL_UNAVAILABLE: "platform_session_rate_limit_unavailable"
});

export class PlatformSessionRateLimitError extends Error {
  constructor(code, { retryAfterSeconds = undefined, cause = undefined } = {}) {
    const limited = code === PLATFORM_SESSION_RATE_LIMIT_ERROR_CODES.RATE_LIMITED;
    super(limited ? "Platform Session rate limit exceeded" : "Platform Session rate limiter is temporarily unavailable");
    // Provider/SQL diagnostics are intentionally discarded at this boundary.
    void cause;
    this.name = "PlatformSessionRateLimitError";
    this.code = code;
    this.status = limited ? 429 : 503;
    const retryAfter = limited ? normalizeRetryAfter(retryAfterSeconds) : 1;
    this.headers = Object.freeze({
      "Retry-After": String(retryAfter),
      "Cache-Control": "no-store, max-age=0"
    });
  }
}

/**
 * PostgreSQL-backed admission control for Platform Session HTTP routes.
 *
 * The repository is intentionally anonymous-only: pre-authentication callers
 * must not be able to select a tenant bucket.  Every principalId is an HMAC
 * derived UUID in a fixed slot space, and no raw cookie, CSRF token, JTI,
 * bearer, organization, or challenge value is sent to the repository.
 */
export function createPlatformSessionRateLimiter({ repository, bucketSecret, policies = {}, idleTtlMs = DEFAULT_IDLE_TTL_MS } = {}) {
  if (!repository || typeof repository.acquireAnonymousRateLimit !== "function") {
    throw new TypeError("Platform Session shared PostgreSQL rate-limit repository is required");
  }
  const secret = normalizeBucketSecret(bucketSecret);
  const mergedPolicies = Object.freeze(Object.fromEntries(
    PLATFORM_SESSION_RATE_LIMIT_PHASES.map((phase) => [phase, normalizePolicy(policies[phase] ?? PLATFORM_SESSION_RATE_LIMIT_POLICIES[phase])])
  ));
  if (!Number.isSafeInteger(idleTtlMs) || idleTtlMs < 1_000 || idleTtlMs > 24 * 60 * 60 * 1000) {
    throw new TypeError("Platform Session rate-limit idleTtlMs is invalid");
  }

  async function acquire({ phase, transportIdentity, sessionMaterialHash, csrfTokenHash, jtiHash, proofId, cost = 1 } = {}) {
    const policy = mergedPolicies[phase];
    if (!policy) throw new TypeError("Platform Session rate-limit phase is invalid");
    if (!Number.isSafeInteger(cost) || cost < 1 || cost > policy.capacity) throw new TypeError("Platform Session rate-limit cost is invalid");

    const keys = derivePlatformSessionRateLimitKeys({
      bucketSecret: secret,
      phase,
      transportIdentity,
      sessionMaterialHash,
      csrfTokenHash,
      jtiHash,
      proofId
    });

    for (const [index, key] of keys.entries()) {
      const isGlobal = index === 0;
      const capacity = isGlobal ? Math.min(1_000_000, policy.capacity * ANONYMOUS_GLOBAL_CAPACITY_MULTIPLIER) : policy.capacity;
      const refillPerSecond = isGlobal ? Math.min(1_000_000, policy.refillPerSecond * ANONYMOUS_GLOBAL_CAPACITY_MULTIPLIER) : policy.refillPerSecond;
      let rawDecision;
      try {
        rawDecision = await repository.acquireAnonymousRateLimit({
          operation: PLATFORM_SESSION_RATE_LIMIT_OPERATIONS[phase],
          principalId: key.principalId,
          capacity,
          refillPerSecond,
          cost,
          idleTtlMs
        });
      } catch (error) {
        throw new PlatformSessionRateLimitError(PLATFORM_SESSION_RATE_LIMIT_ERROR_CODES.CONTROL_UNAVAILABLE, { cause: error });
      }

      let decision;
      try {
        decision = normalizeDecision(rawDecision, capacity);
      } catch (error) {
        throw new PlatformSessionRateLimitError(PLATFORM_SESSION_RATE_LIMIT_ERROR_CODES.CONTROL_UNAVAILABLE, { cause: error });
      }
      if (!decision.allowed) {
        throw new PlatformSessionRateLimitError(PLATFORM_SESSION_RATE_LIMIT_ERROR_CODES.RATE_LIMITED, {
          retryAfterSeconds: decision.retryAfterSeconds
        });
      }
    }

    return Object.freeze({
      allowed: true,
      phase,
      limit: policy.capacity,
      retryAfterSeconds: 0,
      headers: Object.freeze({})
    });
  }

  return Object.freeze({
    acquire,
    check: acquire,
    authorize: acquire,
    policies: mergedPolicies,
    maxRetryAfterSeconds: MAX_RETRY_AFTER_SECONDS
  });
}

/**
 * Derive the finite backend key plan without exposing any caller-provided
 * secret.  The returned values are safe opaque UUIDs and dimension labels.
 */
export function derivePlatformSessionRateLimitKeys({ bucketSecret, phase, transportIdentity, sessionMaterialHash, csrfTokenHash, jtiHash, proofId } = {}) {
  if (!PLATFORM_SESSION_RATE_LIMIT_PHASES.includes(phase)) throw new TypeError("Platform Session rate-limit phase is invalid");
  const secret = normalizeBucketSecret(bucketSecret);
  const values = [
    { dimension: "global", value: "global", slotCount: 1 },
    { dimension: "transport", value: normalizeTransportIdentity(transportIdentity), slotCount: PLATFORM_SESSION_RATE_LIMIT_KEY_SLOTS.transport },
    { dimension: "session", value: normalizeDigest(sessionMaterialHash), slotCount: PLATFORM_SESSION_RATE_LIMIT_KEY_SLOTS.session },
    { dimension: "csrf", value: normalizeDigest(csrfTokenHash), slotCount: PLATFORM_SESSION_RATE_LIMIT_KEY_SLOTS.csrf },
    { dimension: "jti", value: normalizeDigest(jtiHash), slotCount: PLATFORM_SESSION_RATE_LIMIT_KEY_SLOTS.jti },
    { dimension: "proof", value: normalizeUuid(proofId), slotCount: PLATFORM_SESSION_RATE_LIMIT_KEY_SLOTS.proof }
  ];

  const keys = [];
  for (const entry of values) {
    if (entry.value === undefined) continue;
    const slot = entry.slotCount === 1 ? 0 : deriveSlot(secret, phase, entry.dimension, entry.value, entry.slotCount);
    keys.push(Object.freeze({
      dimension: entry.dimension,
      slot,
      principalId: deriveBucketId(secret, phase, entry.dimension, slot)
    }));
  }
  return Object.freeze(keys);
}

function normalizePolicy(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new TypeError("Platform Session rate-limit policy is invalid");
  if (!Number.isSafeInteger(value.capacity) || value.capacity < 1 || value.capacity > 1_000_000) throw new TypeError("Platform Session rate-limit capacity is invalid");
  if (typeof value.refillPerSecond !== "number" || !Number.isFinite(value.refillPerSecond) || value.refillPerSecond <= 0 || value.refillPerSecond > 1_000_000) throw new TypeError("Platform Session rate-limit refill is invalid");
  return Object.freeze({ capacity: value.capacity, refillPerSecond: value.refillPerSecond });
}

function normalizeDecision(value, fallbackLimit) {
  if (!value || typeof value !== "object" || typeof value.allowed !== "boolean") throw new Error("Platform Session rate-limit decision is invalid");
  if (!Number.isSafeInteger(value.limit) || value.limit < 1 || value.limit > 1_000_000) throw new Error("Platform Session rate-limit limit is invalid");
  if (!Number.isSafeInteger(value.remaining) || value.remaining < 0 || value.remaining > value.limit) throw new Error("Platform Session rate-limit remaining is invalid");
  if (value.limit !== fallbackLimit) throw new Error("Platform Session rate-limit policy mismatch");
  if (value.allowed) return Object.freeze({ allowed: true, retryAfterSeconds: 0 });

  const retryAfterSeconds = value.retryAfterSeconds !== undefined
    ? value.retryAfterSeconds
    : Number.isSafeInteger(value.retryAfterMs) && value.retryAfterMs >= 0
      ? Math.ceil(value.retryAfterMs / 1_000)
      : undefined;
  if (!Number.isSafeInteger(retryAfterSeconds) || retryAfterSeconds < 0) throw new Error("Platform Session rate-limit retry metadata is invalid");
  return Object.freeze({ allowed: false, retryAfterSeconds: normalizeRetryAfter(retryAfterSeconds) });
}

function normalizeRetryAfter(value) {
  if (!Number.isSafeInteger(value) || value < 0) throw new TypeError("Platform Session Retry-After is invalid");
  return Math.max(1, Math.min(MAX_RETRY_AFTER_SECONDS, boundedRetryAfterSeconds(value * 1_000)));
}

function normalizeTransportIdentity(value) {
  if (value === undefined || value === null) return "unknown";
  if (typeof value !== "string" || value.length === 0 || Buffer.byteLength(value, "utf8") > MAX_IDENTIFIER_BYTES || /[\u0000-\u001f\u007f]/u.test(value)) return "unknown";
  return value;
}

function normalizeDigest(value) {
  return typeof value === "string" && DIGEST.test(value) ? value.toLowerCase() : undefined;
}

function normalizeUuid(value) {
  return typeof value === "string" && UUID.test(value) ? value.toLowerCase() : undefined;
}

function normalizeBucketSecret(value) {
  let bytes = value;
  if (typeof value === "string" && /^[A-Za-z0-9_-]{43}$/u.test(value)) bytes = Buffer.from(value, "base64url");
  if (!Buffer.isBuffer(bytes) && !(bytes instanceof Uint8Array)) throw new TypeError("Platform Session bucket secret is invalid");
  const result = Buffer.from(bytes);
  if (result.length !== 32) throw new TypeError("Platform Session bucket secret is invalid");
  return result;
}

function deriveSlot(secret, phase, dimension, value, slotCount) {
  const digest = crypto.createHmac("sha256", secret)
    .update("agentpass:platform-session:rate-limit-slot:v1\0", "utf8")
    .update(phase, "utf8")
    .update("\0", "utf8")
    .update(dimension, "utf8")
    .update("\0", "utf8")
    .update(value, "utf8")
    .digest();
  return digest.readUInt32BE(0) % slotCount;
}

function deriveBucketId(secret, phase, dimension, slot) {
  const digest = crypto.createHmac("sha256", secret)
    .update("agentpass:platform-session:rate-limit:v1\0", "utf8")
    .update(phase, "utf8")
    .update("\0", "utf8")
    .update(dimension, "utf8")
    .update("\0", "utf8")
    .update(String(slot), "utf8")
    .digest();
  digest[6] = (digest[6] & 0x0f) | 0x40;
  digest[8] = (digest[8] & 0x3f) | 0x80;
  const hex = digest.subarray(0, 16).toString("hex");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}
