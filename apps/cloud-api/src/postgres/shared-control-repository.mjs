import crypto from "node:crypto";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const DIGEST = /^[0-9a-f]{64}$/i;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:~-]{0,255}$/;
const NONCE = /^[A-Za-z0-9][A-Za-z0-9._:-]{31,255}$/;
const SENSITIVE_RESPONSE_KEY = /(?:^|_)(?:access|api|authorization|bearer|cookie|credential|csrf|nonce|password|private|refresh|secret|session|signature|token)(?:_|$)/i;
const SAFE_RESPONSE_KEY = /^[A-Za-z][A-Za-z0-9_.-]{0,127}$/;

export const SHARED_CONTROL_LIMITS = Object.freeze({
  idempotencyTtlMs: Object.freeze({ min: 1_000, max: 24 * 60 * 60 * 1000, default: 24 * 60 * 60 * 1000 }),
  deviceNonceTtlMs: Object.freeze({ min: 1_000, max: 15 * 60 * 1000, default: 2 * 60 * 1000 }),
  rateLimitIdleTtlMs: Object.freeze({ min: 1_000, max: 24 * 60 * 60 * 1000, default: 15 * 60 * 1000 }),
  rateLimitCapacity: Object.freeze({ min: 1, max: 1_000_000 }),
  rateLimitRefillPerSecond: Object.freeze({ min: Number.MIN_VALUE, max: 1_000_000 }),
  rateLimitCost: Object.freeze({ min: 1, max: 1_000_000 }),
  pruneLimit: Object.freeze({ min: 1, max: 10_000, default: 1_000 }),
  responseBytes: 256 * 1024
});

export const SHARED_CONTROL_ERROR_CODES = Object.freeze({
  INVALID_REQUEST: "shared_control_invalid_request",
  IDEMPOTENCY_CONFLICT: "idempotency_conflict",
  CONTROL_UNAVAILABLE: "shared_control_unavailable",
  RATE_LIMITED: "rate_limited"
});

const PUBLIC_MESSAGES = Object.freeze({
  [SHARED_CONTROL_ERROR_CODES.INVALID_REQUEST]: "Shared control request is invalid",
  [SHARED_CONTROL_ERROR_CODES.IDEMPOTENCY_CONFLICT]: "Mutation conflict",
  [SHARED_CONTROL_ERROR_CODES.CONTROL_UNAVAILABLE]: "Shared control is temporarily unavailable",
  [SHARED_CONTROL_ERROR_CODES.RATE_LIMITED]: "Rate limit exceeded"
});

/**
 * All fields in this object are identifiers or digests.  The repository never
 * persists bearer tokens, cookies, session secrets, private keys, signatures,
 * or raw device nonces.  Callers can use these names to wire a migration and
 * health checks without depending on SQL text.
 */
export const SHARED_CONTROL_SCHEMA = Object.freeze({
  tables: Object.freeze({
    idempotency: "idempotency_records",
    deviceRequestNonces: "device_request_nonces",
    rateLimitBuckets: "rate_limit_buckets"
  }),
  indexes: Object.freeze({
    idempotencyExpiry: "idempotency_records_expiry",
    deviceRequestNoncesExpiry: "device_request_nonces_expiry",
    rateLimitBucketsExpiry: "rate_limit_buckets_expiry"
  }),
  functions: Object.freeze({
    consumeDeviceRequestNonce: "agentpass_consume_device_request_nonce",
    acquireRateLimit: "agentpass_acquire_rate_limit",
    pruneExpired: "agentpass_prune_shared_control_expired"
  })
});

export const SHARED_CONTROL_REPOSITORY_METHODS = Object.freeze([
  "withTransaction",
  "runIdempotent",
  "acquireIdempotency",
  "completeIdempotency",
  "abandonIdempotency",
  "consumeDeviceRequestNonce",
  "acquireRateLimit",
  "pruneExpired"
]);

export class SharedControlRepositoryError extends Error {
  constructor(code, cause = undefined) {
    super(PUBLIC_MESSAGES[code] ?? PUBLIC_MESSAGES[SHARED_CONTROL_ERROR_CODES.CONTROL_UNAVAILABLE], cause === undefined ? undefined : { cause });
    this.name = "SharedControlRepositoryError";
    this.code = code;
    this.status = statusFor(code);
  }
}

/**
 * Create the stateless PostgreSQL boundary for controls shared by all Cloud
 * instances.  `client` may be a pg Pool or a checked-out pg Client.  Methods
 * which accept `tx` must receive the transaction client supplied to the
 * `withTransaction` callback; this is what keeps an idempotent mutation and
 * its response in one database transaction.
 */
export function createSharedControlRepository({ client, limits = {}, hash = sha256 } = {}) {
  assertClient(client);
  if (typeof hash !== "function") throw invalidRequest();

  const configured = Object.freeze({
    idempotencyTtlMs: boundedInteger(limits.idempotencyTtlMs ?? SHARED_CONTROL_LIMITS.idempotencyTtlMs.default, SHARED_CONTROL_LIMITS.idempotencyTtlMs, "idempotencyTtlMs"),
    deviceNonceTtlMs: boundedInteger(limits.deviceNonceTtlMs ?? SHARED_CONTROL_LIMITS.deviceNonceTtlMs.default, SHARED_CONTROL_LIMITS.deviceNonceTtlMs, "deviceNonceTtlMs"),
    rateLimitIdleTtlMs: boundedInteger(limits.rateLimitIdleTtlMs ?? SHARED_CONTROL_LIMITS.rateLimitIdleTtlMs.default, SHARED_CONTROL_LIMITS.rateLimitIdleTtlMs, "rateLimitIdleTtlMs")
  });

  async function withTransaction(operation) {
    if (typeof operation !== "function") throw invalidRequest();
    const tx = typeof client.connect === "function" ? await connect(client) : client;
    let began = false;
    try {
      await tx.query("BEGIN", []);
      began = true;
      const result = await operation(tx);
      await tx.query("COMMIT", []);
      began = false;
      return result;
    } catch (error) {
      if (began) {
        try { await tx.query("ROLLBACK", []); }
        catch (rollbackError) { throw unavailable(rollbackError); }
      }
      throw error;
    } finally {
      if (tx !== client) tx.release?.();
    }
  }

  async function acquireIdempotency({ tx, organizationId, principalId, idempotencyKey, requestHash, ttlMs } = {}) {
    assertTransactionClient(tx);
    const input = normalizeIdempotency({ organizationId, principalId, idempotencyKey, requestHash, ttlMs: ttlMs ?? configured.idempotencyTtlMs });
    try {
      await tx.query(`DELETE FROM idempotency_records
        WHERE organization_id=$1 AND principal_id=$2 AND idempotency_key=$3
          AND expires_at<=clock_timestamp()`, [input.organizationId, input.principalId, input.idempotencyKey]);
      const inserted = await tx.query(`INSERT INTO idempotency_records
        (organization_id,principal_id,idempotency_key,request_hash,response_status,response_json,expires_at)
        VALUES ($1,$2,$3,$4,102,'{}'::jsonb,clock_timestamp()+($5 * interval '1 millisecond'))
        ON CONFLICT (organization_id,principal_id,idempotency_key) DO NOTHING`, [
        input.organizationId, input.principalId, input.idempotencyKey, input.requestHash, input.ttlMs
      ]);
      const record = await tx.query(`SELECT request_hash,response_status,response_json,expires_at
        FROM idempotency_records
        WHERE organization_id=$1 AND principal_id=$2 AND idempotency_key=$3
        FOR UPDATE`, [input.organizationId, input.principalId, input.idempotencyKey]);
      if (rowCount(record) !== 1) throw unavailable();
      const row = record.rows[0];
      if (String(row.request_hash).toLowerCase() !== input.requestHash) return { state: "conflict" };
      if (rowCount(inserted) === 1) return { state: "new" };
      if (Number(row.response_status) === 102) return { state: "in_progress" };
      const response = safeStoredResponse(row.response_json);
      return { state: "replay", responseStatus: normalizeResponseStatus(row.response_status), response };
    } catch (error) {
      if (error instanceof SharedControlRepositoryError) throw error;
      throw unavailable(error);
    }
  }

  async function completeIdempotency({ tx, organizationId, principalId, idempotencyKey, requestHash, responseStatus, response } = {}) {
    assertTransactionClient(tx);
    const input = normalizeIdempotency({ organizationId, principalId, idempotencyKey, requestHash });
    const status = normalizeResponseStatus(responseStatus);
    if (status === 102) throw invalidRequest();
    const responseJson = safeResponseJson(response);
    try {
      const completed = await tx.query(`UPDATE idempotency_records
        SET response_status=$4,response_json=$5::jsonb
        WHERE organization_id=$1 AND principal_id=$2 AND idempotency_key=$3
          AND request_hash=$6 AND response_status=102`, [
        input.organizationId, input.principalId, input.idempotencyKey, status, responseJson, input.requestHash
      ]);
      if (rowCount(completed) !== 1) throw new SharedControlRepositoryError(SHARED_CONTROL_ERROR_CODES.IDEMPOTENCY_CONFLICT);
      return { completed: true };
    } catch (error) {
      if (error instanceof SharedControlRepositoryError) throw error;
      throw unavailable(error);
    }
  }

  async function abandonIdempotency({ tx, organizationId, principalId, idempotencyKey, requestHash } = {}) {
    assertTransactionClient(tx);
    const input = normalizeIdempotency({ organizationId, principalId, idempotencyKey, requestHash });
    try {
      const removed = await tx.query(`DELETE FROM idempotency_records
        WHERE organization_id=$1 AND principal_id=$2 AND idempotency_key=$3
          AND request_hash=$4 AND response_status=102`, [
        input.organizationId, input.principalId, input.idempotencyKey, input.requestHash
      ]);
      return { removed: rowCount(removed) === 1 };
    } catch (error) {
      if (error instanceof SharedControlRepositoryError) throw error;
      throw unavailable(error);
    }
  }

  /**
   * Run the caller's mutation while holding the idempotency row lock.  The
   * operation must return `{ responseStatus, response }`; its response is
   * checked before it can be persisted.  If a prior completed record exists,
   * no operation is executed and the stored metadata is returned.
   */
  async function runIdempotent({ organizationId, principalId, idempotencyKey, requestHash, ttlMs, operation } = {}) {
    if (typeof operation !== "function") throw invalidRequest();
    return withTransaction(async (tx) => {
      const acquired = await acquireIdempotency({ tx, organizationId, principalId, idempotencyKey, requestHash, ttlMs });
      if (acquired.state === "replay") return acquired;
      if (acquired.state === "conflict" || acquired.state === "in_progress") return { state: acquired.state };
      let result;
      try { result = await operation(tx); }
      catch (error) { throw error; }
      if (!result || typeof result !== "object" || Array.isArray(result)) throw invalidRequest();
      await completeIdempotency({ tx, organizationId, principalId, idempotencyKey, requestHash, responseStatus: result.responseStatus, response: result.response });
      return { state: "committed", responseStatus: normalizeResponseStatus(result.responseStatus), response: safeStoredResponse(result.response) };
    });
  }

  async function consumeDeviceRequestNonce({ organizationId, deviceId, nonce, ttlMs } = {}) {
    const normalized = normalizeDeviceNonce({ organizationId, deviceId, nonce, ttlMs: ttlMs ?? configured.deviceNonceTtlMs });
    const nonceDigest = hashNonce(normalized.nonce, hash);
    try {
      const result = await client.query(`SELECT accepted
        FROM agentpass_consume_device_request_nonce($1::uuid,$2::uuid,$3::bytea,$4::integer)`, [
        normalized.organizationId, normalized.deviceId, nonceDigest, normalized.ttlMs
      ]);
      if (rowCount(result) !== 1 || typeof result.rows[0]?.accepted !== "boolean") throw unavailable();
      return { accepted: result.rows[0].accepted };
    } catch (error) {
      if (error instanceof SharedControlRepositoryError) throw error;
      throw unavailable(error);
    }
  }

  async function acquireRateLimit({ organizationId, principalType, principalId, capacity, refillPerSecond, cost = 1, idleTtlMs } = {}) {
    const input = normalizeRateLimit({ organizationId, principalType, principalId, capacity, refillPerSecond, cost, idleTtlMs: idleTtlMs ?? configured.rateLimitIdleTtlMs });
    try {
      const result = await client.query(`SELECT allowed,rate_limit,remaining,retry_after_ms,reset_at
        FROM agentpass_acquire_rate_limit($1::uuid,$2::text,$3::uuid,$4::integer,$5::numeric,$6::integer,$7::integer)`, [
        input.organizationId, input.principalType, input.principalId, input.capacity, input.refillPerSecond, input.cost, input.idleTtlMs
      ]);
      if (rowCount(result) !== 1) throw unavailable();
      return normalizeRateDecision(result.rows[0]);
    } catch (error) {
      if (error instanceof SharedControlRepositoryError) throw error;
      throw unavailable(error);
    }
  }

  async function pruneExpired({ limit = SHARED_CONTROL_LIMITS.pruneLimit.default } = {}) {
    const boundedLimit = boundedInteger(limit, SHARED_CONTROL_LIMITS.pruneLimit, "limit");
    try {
      const result = await client.query(`SELECT removed
        FROM agentpass_prune_shared_control_expired($1::integer)`, [boundedLimit]);
      if (rowCount(result) !== 1 || !Number.isSafeInteger(Number(result.rows[0]?.removed)) || Number(result.rows[0].removed) < 0) throw unavailable();
      return { removed: Number(result.rows[0].removed) };
    } catch (error) {
      if (error instanceof SharedControlRepositoryError) throw error;
      throw unavailable(error);
    }
  }

  return Object.freeze({
    limits: configured,
    withTransaction,
    runIdempotent,
    acquireIdempotency,
    completeIdempotency,
    abandonIdempotency,
    consumeDeviceRequestNonce,
    acquireRateLimit,
    pruneExpired
  });
}

export function sha256(value) {
  return crypto.createHash("sha256").update(String(value), "utf8").digest();
}

function normalizeIdempotency({ organizationId, principalId, idempotencyKey, requestHash, ttlMs } = {}) {
  assertUuid(organizationId);
  assertIdentifier(principalId);
  if (typeof idempotencyKey !== "string" || !/^[A-Za-z0-9._~-]{8,255}$/.test(idempotencyKey)) throw invalidRequest();
  if (typeof requestHash !== "string" || !DIGEST.test(requestHash)) throw invalidRequest();
  return {
    organizationId,
    principalId,
    idempotencyKey,
    requestHash: requestHash.toLowerCase(),
    ttlMs: ttlMs === undefined ? undefined : boundedInteger(ttlMs, SHARED_CONTROL_LIMITS.idempotencyTtlMs, "ttlMs")
  };
}

function normalizeDeviceNonce({ organizationId, deviceId, nonce, ttlMs }) {
  assertUuid(organizationId);
  assertUuid(deviceId);
  if (typeof nonce !== "string" || !NONCE.test(nonce)) throw invalidRequest();
  return { organizationId, deviceId, nonce, ttlMs: boundedInteger(ttlMs, SHARED_CONTROL_LIMITS.deviceNonceTtlMs, "ttlMs") };
}

function normalizeRateLimit({ organizationId, principalType, principalId, capacity, refillPerSecond, cost, idleTtlMs }) {
  assertUuid(organizationId);
  if (principalType !== "human" && principalType !== "device") throw invalidRequest();
  assertUuid(principalId);
  if (!Number.isSafeInteger(capacity) || capacity < SHARED_CONTROL_LIMITS.rateLimitCapacity.min || capacity > SHARED_CONTROL_LIMITS.rateLimitCapacity.max) throw invalidRequest();
  if (typeof refillPerSecond !== "number" || !Number.isFinite(refillPerSecond) || refillPerSecond < SHARED_CONTROL_LIMITS.rateLimitRefillPerSecond.min || refillPerSecond > SHARED_CONTROL_LIMITS.rateLimitRefillPerSecond.max) throw invalidRequest();
  if (!Number.isSafeInteger(cost) || cost < SHARED_CONTROL_LIMITS.rateLimitCost.min || cost > Math.min(capacity, SHARED_CONTROL_LIMITS.rateLimitCost.max)) throw invalidRequest();
  return { organizationId, principalType, principalId, capacity, refillPerSecond, cost, idleTtlMs: boundedInteger(idleTtlMs, SHARED_CONTROL_LIMITS.rateLimitIdleTtlMs, "idleTtlMs") };
}

function normalizeResponseStatus(value) {
  if (!Number.isSafeInteger(value) || value < 100 || value > 599 || value === 102) throw invalidRequest();
  return value;
}

function normalizeRateDecision(row) {
  if (!row || typeof row.allowed !== "boolean") throw unavailable();
  const limit = safeInteger(row.rate_limit, 1, SHARED_CONTROL_LIMITS.rateLimitCapacity.max);
  const remaining = safeInteger(row.remaining, 0, limit);
  const retryAfterMs = safeInteger(row.retry_after_ms, 0, 24 * 60 * 60 * 1000);
  const resetAt = timestampMs(row.reset_at);
  const retryAfterSeconds = row.allowed ? 0 : Math.max(1, Math.ceil(retryAfterMs / 1000));
  return { allowed: row.allowed, limit, remaining, retryAfterMs: row.allowed ? 0 : retryAfterMs, retryAfterSeconds, resetAt };
}

function safeResponseJson(value) {
  const normalized = safeResponseValue(value);
  let encoded;
  try { encoded = JSON.stringify(normalized); }
  catch { throw invalidRequest(); }
  if (typeof encoded !== "string" || Buffer.byteLength(encoded, "utf8") > SHARED_CONTROL_LIMITS.responseBytes) throw invalidRequest();
  return encoded;
}

function safeStoredResponse(value) {
  let parsed = value;
  if (typeof value === "string") {
    try { parsed = JSON.parse(value); } catch { throw unavailable(); }
  }
  safeResponseJson(parsed);
  return parsed;
}

function safeResponseValue(value, depth = 0) {
  if (depth > 16) throw invalidRequest();
  if (value === null || typeof value === "boolean") return value;
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw invalidRequest();
    return value;
  }
  if (typeof value === "string") {
    if (value.length > 16_384 || /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/u.test(value)) throw invalidRequest();
    return value;
  }
  if (Array.isArray(value)) {
    if (value.length > 10_000) throw invalidRequest();
    return value.map((item) => safeResponseValue(item, depth + 1));
  }
  if (typeof value !== "object" || Object.getPrototypeOf(value) !== Object.prototype) throw invalidRequest();
  const output = {};
  const keys = Object.keys(value);
  if (keys.length > 10_000) throw invalidRequest();
  for (const key of keys) {
    if (!SAFE_RESPONSE_KEY.test(key) || (SENSITIVE_RESPONSE_KEY.test(key) && key.toLowerCase() !== "session_id")) throw invalidRequest();
    output[key] = safeResponseValue(value[key], depth + 1);
  }
  return output;
}

function hashNonce(nonce, hash) {
  let digest;
  try { digest = hash(nonce); } catch { throw invalidRequest(); }
  if (!Buffer.isBuffer(digest) || digest.length !== 32) throw invalidRequest();
  return digest;
}

function timestampMs(value) {
  const milliseconds = value instanceof Date ? value.getTime() : Date.parse(String(value));
  if (!Number.isSafeInteger(milliseconds) || milliseconds < 0) throw unavailable();
  return milliseconds;
}

function boundedInteger(value, bounds, label) {
  if (!Number.isSafeInteger(value) || value < bounds.min || value > bounds.max) throw invalidRequest(label);
  return value;
}

function safeInteger(value, min, max) {
  const number = typeof value === "number" ? value : Number(value);
  if (!Number.isSafeInteger(number) || number < min || number > max) throw unavailable();
  return number;
}

function assertUuid(value) {
  if (typeof value !== "string" || !UUID.test(value)) throw invalidRequest();
  return value;
}

function assertIdentifier(value) {
  if (typeof value !== "string" || !IDENTIFIER.test(value)) throw invalidRequest();
  return value;
}

function assertClient(client) {
  if (!client || (typeof client.query !== "function" && typeof client.connect !== "function")) throw invalidRequest();
}

function assertTransactionClient(tx) {
  if (!tx || typeof tx.query !== "function") throw invalidRequest();
}

async function connect(pool) {
  try { return await pool.connect(); }
  catch (error) { throw unavailable(error); }
}

function rowCount(result) {
  const count = result?.rowCount;
  if (Number.isSafeInteger(count)) return count;
  return Array.isArray(result?.rows) ? result.rows.length : 0;
}

function invalidRequest() {
  return new SharedControlRepositoryError(SHARED_CONTROL_ERROR_CODES.INVALID_REQUEST);
}

function unavailable(cause = undefined) {
  return new SharedControlRepositoryError(SHARED_CONTROL_ERROR_CODES.CONTROL_UNAVAILABLE, cause);
}

function statusFor(code) {
  if (code === SHARED_CONTROL_ERROR_CODES.INVALID_REQUEST) return 400;
  if (code === SHARED_CONTROL_ERROR_CODES.IDEMPOTENCY_CONFLICT) return 409;
  if (code === SHARED_CONTROL_ERROR_CODES.RATE_LIMITED) return 429;
  return 503;
}
