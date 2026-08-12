import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const DEFAULT_HUMAN_POLICY = Object.freeze({ capacity: 120, refillPerSecond: 2 });
const DEFAULT_DEVICE_POLICY = Object.freeze({ capacity: 240, refillPerSecond: 4 });
const DEFAULT_MAX_ENTRIES = 10_000;
const DEFAULT_IDLE_TTL_MS = 15 * 60 * 1000;
const MAX_IDENTIFIER_LENGTH = 256;

export class RateLimiterConfigurationError extends Error {
  constructor(message) {
    super(message);
    this.name = "RateLimiterConfigurationError";
    this.code = "RATE_LIMITER_CONFIGURATION_INVALID";
  }
}

export class RateLimiterCapacityError extends Error {
  constructor() {
    super("Rate limiter capacity is exhausted");
    this.name = "RateLimiterCapacityError";
    this.code = "RATE_LIMITER_CAPACITY_EXHAUSTED";
  }
}

/**
 * A bounded, per-principal token bucket. Wall time is used only for response
 * metadata; refill and expiry use the injected monotonic clock so wall-clock
 * adjustments cannot mint tokens or extend bucket lifetime.
 */
export function createRateLimiter({
  now = () => Date.now(),
  monotonicNow = defaultMonotonicNow,
  maxEntries = DEFAULT_MAX_ENTRIES,
  idleTtlMs = DEFAULT_IDLE_TTL_MS,
  human = DEFAULT_HUMAN_POLICY,
  device = DEFAULT_DEVICE_POLICY,
  persistencePath
} = {}) {
  validateClock(now, "now");
  validateClock(monotonicNow, "monotonicNow");
  assertPositiveInteger(maxEntries, "maxEntries");
  assertPositiveFinite(idleTtlMs, "idleTtlMs");
  const policies = Object.freeze({ human: validatePolicy(human, "human"), device: validatePolicy(device, "device") });
  const buckets = new Map();
  if (persistencePath !== undefined) loadPersistentBuckets(persistencePath, buckets, policies, maxEntries);
  let lastMonotonic;

  function acquire({ tenantId, principalType, principalId } = {}) {
    const policy = policies[principalType];
    if (!policy) throw new RateLimiterConfigurationError("principalType must be human or device");
    assertIdentifier(tenantId, "tenantId");
    assertIdentifier(principalId, "principalId");
    const wallNow = readClock(now, "now");
    const monotonic = readMonotonic();
    purge(monotonic, wallNow);
    const key = `${principalType}:${tenantId}:${principalId}`;
    let bucket = buckets.get(key);
    if (!bucket) {
      if (buckets.size >= maxEntries) throw new RateLimiterCapacityError();
      bucket = { tokens: policy.capacity, last: monotonic, touched: monotonic, lastWall: wallNow, touchedWall: wallNow, policy, principalType };
      buckets.set(key, bucket);
    } else {
      if (bucket.restored) {
        const elapsed = Math.max(0, wallNow - bucket.lastWall);
        bucket.tokens = Math.min(policy.capacity, bucket.tokens + elapsed * policy.refillPerSecond / 1000);
        bucket.last = monotonic;
        bucket.restored = false;
      } else refill(bucket, monotonic);
      bucket.touched = monotonic;
      bucket.lastWall = wallNow;
      bucket.touchedWall = wallNow;
    }

    if (bucket.tokens < 1) {
      const waitMs = Math.max(1, Math.ceil((1 - bucket.tokens) * 1000 / policy.refillPerSecond));
      persistBuckets(persistencePath, buckets);
      return decision({ allowed: false, policy, wallNow, waitMs, bucket });
    }
    bucket.tokens -= 1;
    bucket.lastWall = wallNow;
    bucket.touchedWall = wallNow;
    persistBuckets(persistencePath, buckets);
    return decision({ allowed: true, policy, wallNow, waitMs: 0, bucket });
  }

  function reset({ tenantId, principalType, principalId } = {}) {
    if (tenantId === undefined && principalType === undefined && principalId === undefined) {
      buckets.clear();
      persistBuckets(persistencePath, buckets);
      return;
    }
    if (principalType !== "human" && principalType !== "device") throw new RateLimiterConfigurationError("principalType must be human or device");
    assertIdentifier(tenantId, "tenantId");
    assertIdentifier(principalId, "principalId");
    buckets.delete(`${principalType}:${tenantId}:${principalId}`);
    persistBuckets(persistencePath, buckets);
  }

  function purge(currentMonotonic, wallNow) {
    for (const [key, bucket] of buckets) {
      const idle = bucket.restored ? Math.max(0, wallNow - bucket.touchedWall) : currentMonotonic - bucket.touched;
      if (idle >= idleTtlMs) buckets.delete(key);
    }
  }

  function readMonotonic() {
    const value = readClock(monotonicNow, "monotonicNow");
    if (lastMonotonic !== undefined && value < lastMonotonic) throw new RateLimiterConfigurationError("monotonicNow moved backwards");
    lastMonotonic = value;
    return value;
  }

  return Object.freeze({
    acquire,
    reset,
    get size() { return buckets.size; },
    get maxEntries() { return maxEntries; },
    policies
  });
}

function loadPersistentBuckets(file, buckets, policies, maxEntries) {
  assertPersistentPath(file);
  if (!fs.existsSync(file)) return;
  const stat = fs.lstatSync(file);
  const uid = process.getuid?.();
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 || stat.size > 4 * 1024 * 1024 || (stat.mode & 0o077) !== 0 || (uid !== undefined && stat.uid !== uid)) throw new RateLimiterConfigurationError("persistent rate-limit state is unsafe");
  let state;
  try { state = JSON.parse(fs.readFileSync(file, "utf8")); } catch { throw new RateLimiterConfigurationError("persistent rate-limit state is invalid"); }
  if (state?.version !== 1 || !Array.isArray(state.buckets) || state.buckets.length > maxEntries) throw new RateLimiterConfigurationError("persistent rate-limit state is invalid");
  for (const [key, value] of state.buckets) {
    const principalType = value?.principal_type;
    const policy = policies[principalType];
    if (typeof key !== "string" || key.length > 1024 || !policy || typeof value.tokens !== "number" || !Number.isFinite(value.tokens) || value.tokens < 0 || value.tokens > policy.capacity || !Number.isSafeInteger(value.last_wall) || !Number.isSafeInteger(value.touched_wall)) throw new RateLimiterConfigurationError("persistent rate-limit bucket is invalid");
    buckets.set(key, { tokens: value.tokens, lastWall: value.last_wall, touchedWall: value.touched_wall, policy, principalType, restored: true });
  }
}

function persistBuckets(file, buckets) {
  if (file === undefined) return;
  assertPersistentPath(file);
  const content = JSON.stringify({ version: 1, buckets: [...buckets].map(([key, bucket]) => [key, { tokens: bucket.tokens, last_wall: bucket.lastWall, touched_wall: bucket.touchedWall, principal_type: bucket.principalType }]) });
  const temporary = `${file}.${process.pid}.${crypto.randomBytes(6).toString("hex")}.tmp`;
  let descriptor;
  try {
    descriptor = fs.openSync(temporary, "wx", 0o600); fs.writeFileSync(descriptor, content); fs.fsyncSync(descriptor); fs.closeSync(descriptor); descriptor = undefined; fs.renameSync(temporary, file);
  } catch (error) { if (descriptor !== undefined) try { fs.closeSync(descriptor); } catch {}; try { fs.unlinkSync(temporary); } catch {}; throw new RateLimiterConfigurationError(`persistent rate-limit state failed: ${error.code ?? "unknown"}`); }
}

function assertPersistentPath(file) {
  if (typeof file !== "string" || !path.isAbsolute(file)) throw new RateLimiterConfigurationError("persistencePath must be absolute");
  const stat = fs.lstatSync(path.dirname(file));
  const uid = process.getuid?.();
  if (!stat.isDirectory() || stat.isSymbolicLink() || (stat.mode & 0o077) !== 0 || (uid !== undefined && stat.uid !== uid)) throw new RateLimiterConfigurationError("persistent rate-limit directory is unsafe");
}

function decision({ allowed, policy, wallNow, waitMs, bucket }) {
  return {
    allowed,
    limit: policy.capacity,
    remaining: Math.max(0, Math.floor(bucket.tokens)),
    retryAfterSeconds: allowed ? 0 : Math.max(1, Math.ceil(waitMs / 1000)),
    resetAt: wallNow + waitMs
  };
}

function refill(bucket, currentMonotonic) {
  const elapsed = currentMonotonic - bucket.last;
  if (elapsed > 0) bucket.tokens = Math.min(bucket.policy.capacity, bucket.tokens + elapsed * bucket.policy.refillPerSecond / 1000);
  bucket.last = currentMonotonic;
}

function validatePolicy(value, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new RateLimiterConfigurationError(`${label} policy is invalid`);
  const policy = { capacity: value.capacity, refillPerSecond: value.refillPerSecond };
  assertPositiveInteger(policy.capacity, `${label}.capacity`);
  assertPositiveFinite(policy.refillPerSecond, `${label}.refillPerSecond`);
  if (policy.capacity > 1_000_000 || policy.refillPerSecond > 1_000_000) throw new RateLimiterConfigurationError(`${label} policy is too large`);
  return Object.freeze(policy);
}

function validateClock(value, label) {
  if (typeof value !== "function") throw new RateLimiterConfigurationError(`${label} must be a function`);
}

function readClock(clock, label) {
  let value;
  try { value = clock(); } catch { throw new RateLimiterConfigurationError(`${label} failed`); }
  if (!Number.isSafeInteger(value) || value < 0) throw new RateLimiterConfigurationError(`${label} must return a non-negative safe integer`);
  return value;
}

function assertPositiveInteger(value, label) {
  if (!Number.isSafeInteger(value) || value < 1) throw new RateLimiterConfigurationError(`${label} must be a positive safe integer`);
}

function assertPositiveFinite(value, label) {
  if (typeof value !== "number" || !Number.isFinite(value) || value <= 0) throw new RateLimiterConfigurationError(`${label} must be positive and finite`);
}

function assertIdentifier(value, label) {
  if (typeof value !== "string" || value.length === 0 || value.length > MAX_IDENTIFIER_LENGTH || /[\u0000-\u001f\u007f]/.test(value)) throw new RateLimiterConfigurationError(`${label} is invalid`);
}

function defaultMonotonicNow() {
  return Number(process.hrtime.bigint() / 1_000_000n);
}
