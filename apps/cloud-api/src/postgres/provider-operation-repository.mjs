import crypto from "node:crypto";

const PURPOSE = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/u;
const KEY_ID = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$/u;
const OPERATION_ID = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$/u;
const DIGEST = /^[0-9a-f]{64}$/u;
const VERSION = /^[1-9][0-9]{0,31}$/u;
const CLAIM = /^[A-Za-z0-9_-]{43}$/u;
const PROVIDER = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$/u;
const RECEIPT = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;
const BASE64URL = /^[A-Za-z0-9_-]+$/u;
const HEX = /^[0-9a-f]+$/u;
const ALGORITHM = "ed25519";
const DEFAULT_LEASE_MS = 30_000;
const DEFAULT_RETENTION_MS = 30 * 24 * 60 * 60 * 1_000;
const MAX_LEASE_MS = 5 * 60 * 1_000;
const MAX_RETENTION_MS = 365 * 24 * 60 * 60 * 1_000;
const MAX_WAIT_MS = 30_000;
const MAX_BYTES = 1024 * 1024;
const MAX_PRUNE = 1_000;
const POLL_MS = 25;

export const PROVIDER_OPERATION_UNCERTAIN_REASONS = Object.freeze([
  "process_interrupted",
  "provider_timeout",
  "provider_response_lost",
  "provider_output_invalid",
  "commit_response_lost",
  "claim_expired_after_start",
  "lifecycle_fenced",
  "recovery_exhausted",
]);
const UNCERTAIN_REASON_SET = new Set(PROVIDER_OPERATION_UNCERTAIN_REASONS);

const OPERATION_FIELDS = Object.freeze([
  "algorithm", "bytes_length", "key_id", "key_version", "operation_id", "purpose", "request_digest",
]);

// Closed SQL surface: no table name, column assignment, or caller input is
// ever interpolated into a query.  Each durable operation has one exact
// purpose-specific SECURITY DEFINER entry point in migration 0049.
const FUNCTION_SQL = Object.freeze(Object.fromEntries([
  ["reserve", 10], ["claim", 9], ["start", 8], ["accept", 15], ["commit", 8],
  ["reconcile", 7], ["uncertain", 9], ["get", 7], ["health", 4], ["prune", 6],
].map(([purpose, arity]) => [purpose,
  `SELECT public.agentpass_managed_signer_provider_operation_${purpose}(${Array.from({ length: arity }, (_, index) => `$${index + 1}`).join(",")}) AS result`])));

const FUNCTION_ERROR_CODES = new Set(["INPUT", "CONFLICT", "CLAIM_LOST", "STATE", "DATABASE"]);

export const PROVIDER_OPERATION_REPOSITORY_ERROR_CODES = Object.freeze({
  CONFIG: "ERR_PROVIDER_OPERATION_REPOSITORY_CONFIG",
  INPUT: "ERR_PROVIDER_OPERATION_REPOSITORY_INPUT",
  CONFLICT: "ERR_PROVIDER_OPERATION_REPOSITORY_CONFLICT",
  CLAIM_LOST: "ERR_PROVIDER_OPERATION_REPOSITORY_CLAIM_LOST",
  STATE: "ERR_PROVIDER_OPERATION_REPOSITORY_STATE",
  DATABASE: "ERR_PROVIDER_OPERATION_REPOSITORY_DATABASE",
});

const MESSAGES = Object.freeze({
  [PROVIDER_OPERATION_REPOSITORY_ERROR_CODES.CONFIG]: "provider operation repository configuration is invalid",
  [PROVIDER_OPERATION_REPOSITORY_ERROR_CODES.INPUT]: "provider operation repository input is invalid",
  [PROVIDER_OPERATION_REPOSITORY_ERROR_CODES.CONFLICT]: "provider operation binding conflicts with durable state",
  [PROVIDER_OPERATION_REPOSITORY_ERROR_CODES.CLAIM_LOST]: "provider operation claim is unavailable",
  [PROVIDER_OPERATION_REPOSITORY_ERROR_CODES.STATE]: "provider operation state transition is invalid",
  [PROVIDER_OPERATION_REPOSITORY_ERROR_CODES.DATABASE]: "provider operation storage is unavailable",
});

export class ProviderOperationRepositoryError extends Error {
  constructor(code) {
    super(MESSAGES[code] ?? MESSAGES[PROVIDER_OPERATION_REPOSITORY_ERROR_CODES.DATABASE]);
    this.name = "ProviderOperationRepositoryError";
    this.code = Object.hasOwn(MESSAGES, code) ? code : PROVIDER_OPERATION_REPOSITORY_ERROR_CODES.DATABASE;
  }
}

export function createPostgresProviderOperationRepository({
  client,
  purpose,
  keyId,
  keyVersion,
  algorithm = ALGORITHM,
  claimLeaseMs = DEFAULT_LEASE_MS,
  retentionMs = DEFAULT_RETENTION_MS,
  randomBytes = crypto.randomBytes,
} = {}) {
  if (!client || typeof client.query !== "function" || !PURPOSE.test(purpose ?? "")
    || !KEY_ID.test(keyId ?? "") || !VERSION.test(String(keyVersion ?? ""))
    || algorithm !== ALGORITHM || !Number.isSafeInteger(claimLeaseMs) || claimLeaseMs < 1 || claimLeaseMs > MAX_LEASE_MS
    || !Number.isSafeInteger(retentionMs) || retentionMs < claimLeaseMs || retentionMs > MAX_RETENTION_MS
    || typeof randomBytes !== "function") fail(PROVIDER_OPERATION_REPOSITORY_ERROR_CODES.CONFIG);

  const binding = Object.freeze({ purpose, keyId, keyVersion: String(keyVersion), algorithm });

  async function reserveOperation(input) {
    const operation = normalizeOperation(input, binding);
    const token = makeToken(randomBytes);
    return operationCall("reserve", [
      operation.purpose, operation.operation_id, operation.algorithm, operation.bytes_length,
      Buffer.from(operation.request_digest, "hex"), operation.key_id, operation.key_version,
      Buffer.from(sha256(token), "hex"), claimLeaseMs, retentionMs,
    ], token, "claim_if_acquired", operation);
  }

  async function claimOperation(input) {
    const operation = normalizeOperation(input, binding);
    const token = makeToken(randomBytes);
    return operationCall("claim", [
      operation.purpose, operation.operation_id, operation.algorithm, operation.bytes_length,
      Buffer.from(operation.request_digest, "hex"), operation.key_id, operation.key_version,
      Buffer.from(sha256(token), "hex"), claimLeaseMs,
    ], token, "claim_if_acquired", operation);
  }

  async function startOperation(input) {
    const { operation, claimToken } = normalizeClaimedOperation(input, binding);
    return operationCall("start", operationParams(operation, Buffer.from(sha256(claimToken), "hex")), claimToken, "always", operation);
  }

  async function recordAccepted(input) {
    const { operation, claimToken } = normalizeClaimedOperation(input, binding, ["signature", "provider_receipt"]);
    const output = normalizeOutput(input.signature, input.provider_receipt, operation);
    return operationCall("accept", [
      ...operationParams(operation, Buffer.from(sha256(claimToken), "hex")),
      output.signature, output.publicKeyDer, output.provider, output.receiptId,
      input.provider_receipt.operation_id, input.provider_receipt.key_id, input.provider_receipt.key_version,
    ], claimToken, "always", operation);
  }

  async function commitOperation(input) {
    const { operation, claimToken } = normalizeClaimedOperation(input, binding);
    return operationCall("commit", operationParams(operation, Buffer.from(sha256(claimToken), "hex")), undefined, "never", operation);
  }

  async function reconcileOperation(input) {
    const operation = normalizeOperation(input, binding);
    return operationCall("reconcile", operationParams(operation), undefined, "never", operation);
  }

  async function markUncertain(input) {
    const { operation, claimToken } = normalizeClaimedOperation(input, binding, ["uncertain_reason"]);
    const uncertainReason = normalizeUncertainReason(input.uncertain_reason);
    return operationCall("uncertain", [
      ...operationParams(operation, Buffer.from(sha256(claimToken), "hex")), uncertainReason,
    ], undefined, "never", operation);
  }

  async function getOperation(input) {
    const operation = normalizeOperation(input, binding);
    return operationCall("get", operationParams(operation), undefined, "never", operation);
  }

  async function waitForOperation(input) {
    exactObject(input, ["operation", "timeout_ms"]);
    const operation = normalizeOperation(input.operation, binding);
    if (!Number.isSafeInteger(input.timeout_ms) || input.timeout_ms < 1 || input.timeout_ms > MAX_WAIT_MS) {
      fail(PROVIDER_OPERATION_REPOSITORY_ERROR_CODES.INPUT);
    }
    const deadline = Date.now() + input.timeout_ms;
    for (;;) {
      const record = await getOperation(operation);
      if (!record || !["pending", "started"].includes(record.state) || Date.now() >= deadline) return record;
      await delay(Math.min(POLL_MS, Math.max(1, deadline - Date.now())));
    }
  }

  async function health() {
    return runDatabase(async () => {
      const envelope = await callFunctionOn(client, "health", [binding.purpose, binding.keyId, binding.keyVersion, binding.algorithm]);
      const payload = unwrap(envelope);
      if (!plainObject(payload?.health)) fail(PROVIDER_OPERATION_REPOSITORY_ERROR_CODES.DATABASE);
      const health = payload.health;
      const states = Object.freeze(Object.fromEntries(PROVIDER_OPERATION_STATES_FOR_HEALTH.map((state) => [state, count(health.states?.[state])])))
      ;
      return Object.freeze({
        version: 1,
        purpose: binding.purpose,
        algorithm: binding.algorithm,
        key_id: binding.keyId,
        key_version: binding.keyVersion,
        states,
        stale_claims: count(health.stale_claims),
        oldest_nonterminal_at: timestampOrNull(health.oldest_nonterminal_at),
      });
    });
  }

  async function pruneOperations(input) {
    exactObject(input, ["before", "limit"]);
    const before = timestamp(input.before);
    if (!Number.isSafeInteger(input.limit) || input.limit < 1 || input.limit > MAX_PRUNE) {
      fail(PROVIDER_OPERATION_REPOSITORY_ERROR_CODES.INPUT);
    }
    return runDatabase(async () => {
      const envelope = await callFunctionOn(client, "prune", [binding.purpose, binding.keyId, binding.keyVersion, binding.algorithm, before, input.limit]);
      const payload = unwrap(envelope);
      if (!Number.isSafeInteger(payload?.pruned) || payload.pruned < 0 || payload.pruned > MAX_PRUNE) {
        fail(PROVIDER_OPERATION_REPOSITORY_ERROR_CODES.DATABASE);
      }
      return Object.freeze({ pruned: payload.pruned });
    });
  }

  async function operationCall(purposeName, params, claimToken, claimMode, operation) {
    return runDatabase(async () => {
      const envelope = await callFunctionOn(client, purposeName, params);
      const payload = unwrap(envelope);
      if (payload === null) return null;
      if (!plainObject(payload?.record)) fail(PROVIDER_OPERATION_REPOSITORY_ERROR_CODES.DATABASE);
      assertIdentity(payload.record, operation);
      const token = claimMode === "always" || (claimMode === "claim_if_acquired" && payload.claim_acquired === true)
        ? claimToken : undefined;
      return publicRecord(payload.record, token);
    });
  }

  return Object.freeze({ purpose, algorithm, key_id: keyId, key_version: String(keyVersion),
    reserveOperation, claimOperation, startOperation, recordAccepted, commitOperation,
    reconcileOperation, markUncertain, getOperation, waitForOperation, health, pruneOperations });
}

const PROVIDER_OPERATION_STATES_FOR_HEALTH = Object.freeze([
  "pending", "started", "accepted", "uncertain", "committed", "rejected", "failed",
]);

function operationParams(operation, claimDigest = undefined) {
  const params = [
    operation.purpose, operation.operation_id, operation.algorithm, operation.bytes_length,
    Buffer.from(operation.request_digest, "hex"), operation.key_id, operation.key_version,
  ];
  if (claimDigest !== undefined) params.push(claimDigest);
  return params;
}

async function callFunctionOn(client, purpose, params) {
  const query = FUNCTION_SQL[purpose];
  if (!query) fail(PROVIDER_OPERATION_REPOSITORY_ERROR_CODES.DATABASE);
  return decodeQueryResult(await client.query(query, params));
}

function normalizeOperation(input, binding) {
  exactObject(input, OPERATION_FIELDS);
  if (input.purpose !== binding.purpose || input.algorithm !== binding.algorithm || input.key_id !== binding.keyId
    || input.key_version !== binding.keyVersion || !OPERATION_ID.test(input.operation_id ?? "")
    || !DIGEST.test(input.request_digest ?? "") || !Number.isSafeInteger(input.bytes_length)
    || input.bytes_length < 1 || input.bytes_length > MAX_BYTES) fail(PROVIDER_OPERATION_REPOSITORY_ERROR_CODES.INPUT);
  return Object.freeze(Object.fromEntries(OPERATION_FIELDS.map((field) => [field, input[field]])));
}

function normalizeClaimedOperation(input, binding, extras = []) {
  exactObject(input, [...OPERATION_FIELDS, "claim_token", ...extras]);
  const operation = normalizeOperation(Object.fromEntries(OPERATION_FIELDS.map((field) => [field, input[field]])), binding);
  if (!CLAIM.test(input.claim_token ?? "")) fail(PROVIDER_OPERATION_REPOSITORY_ERROR_CODES.INPUT);
  return Object.freeze({ operation, claimToken: input.claim_token });
}

function normalizeOutput(signature, receipt, operation) {
  exactObject(signature, ["algorithm", "encoding", "value", "public_key"]);
  exactObject(signature.public_key, ["algorithm", "encoding", "value"]);
  exactObject(receipt, ["provider", "receipt_id", "operation_id", "key_id", "key_version"]);
  if (signature.algorithm !== ALGORITHM || signature.encoding !== "base64url" || signature.public_key.algorithm !== ALGORITHM
    || signature.public_key.encoding !== "base64url" || !BASE64URL.test(signature.value ?? "")
    || !BASE64URL.test(signature.public_key.value ?? "") || signature.value.includes("=") || signature.public_key.value.includes("=")
    || !PROVIDER.test(receipt.provider ?? "") || !RECEIPT.test(receipt.receipt_id ?? "")
    || receipt.operation_id !== operation.operation_id || receipt.key_id !== operation.key_id || receipt.key_version !== operation.key_version
    || [receipt.provider, receipt.receipt_id].some((value) => /(?:private|secret|credential|diagnostic|debug|trace|token|pem)/iu.test(value))) {
    fail(PROVIDER_OPERATION_REPOSITORY_ERROR_CODES.INPUT);
  }
  const raw = Buffer.from(signature.value, "base64url");
  const publicKeyDer = Buffer.from(signature.public_key.value, "base64url");
  if (raw.length !== 64 || publicKeyDer.length !== 44
    || raw.toString("base64url") !== signature.value || publicKeyDer.toString("base64url") !== signature.public_key.value) {
    fail(PROVIDER_OPERATION_REPOSITORY_ERROR_CODES.INPUT);
  }
  return Object.freeze({ signature: raw, publicKeyDer, provider: receipt.provider, receiptId: receipt.receipt_id });
}

function unwrap(envelope) {
  if (!plainObject(envelope) || typeof envelope.status !== "string") fail(PROVIDER_OPERATION_REPOSITORY_ERROR_CODES.DATABASE);
  if (envelope.status === "not_found") return null;
  if (envelope.status === "error") {
    const code = FUNCTION_ERROR_CODES.has(envelope.error_code) ? envelope.error_code : "DATABASE";
    fail(PROVIDER_OPERATION_REPOSITORY_ERROR_CODES[code]);
  }
  if (envelope.status !== "ok") fail(PROVIDER_OPERATION_REPOSITORY_ERROR_CODES.DATABASE);
  return envelope;
}

function decodeQueryResult(result) {
  if (rowCount(result) !== 1 || !plainObject(result.rows?.[0]?.result)) fail(PROVIDER_OPERATION_REPOSITORY_ERROR_CODES.DATABASE);
  return result.rows[0].result;
}

function publicRecord(row, claimToken = undefined) {
  const record = {
    algorithm: row.algorithm,
    bytes_length: Number(row.bytes_length),
    key_id: row.key_id,
    key_version: String(row.key_version),
    operation_id: row.operation_id,
    purpose: row.purpose,
    request_digest: row.request_digest,
    state: row.state,
  };
  if (claimToken !== undefined) record.claim_token = claimToken;
  if (row.state === "uncertain") record.uncertain_reason = normalizeStoredUncertainReason(row.uncertain_reason);
  if (row.signature_hex !== null && row.signature_hex !== undefined
    && row.public_key_der_hex !== null && row.public_key_der_hex !== undefined
    && row.provider_receipt_provider !== null && row.provider_receipt_provider !== undefined
    && row.provider_receipt_id !== null && row.provider_receipt_id !== undefined) {
    const signature = hexBuffer(row.signature_hex, 64);
    const publicKeyDer = hexBuffer(row.public_key_der_hex, 44);
    record.signature = Object.freeze({ algorithm: ALGORITHM, encoding: "base64url", value: signature.toString("base64url"),
      public_key: Object.freeze({ algorithm: ALGORITHM, encoding: "base64url", value: publicKeyDer.toString("base64url") }) });
    record.provider_receipt = Object.freeze({ provider: row.provider_receipt_provider, receipt_id: row.provider_receipt_id,
      operation_id: row.operation_id, key_id: row.key_id, key_version: String(row.key_version) });
  }
  return Object.freeze(record);
}

function assertIdentity(row, operation) {
  for (const field of OPERATION_FIELDS) {
    const value = field === "key_version" ? String(row[field]) : field === "bytes_length" ? Number(row[field]) : row[field];
    if (value !== operation[field]) fail(PROVIDER_OPERATION_REPOSITORY_ERROR_CODES.CONFLICT);
  }
}

function normalizeUncertainReason(value) {
  if (typeof value !== "string" || !UNCERTAIN_REASON_SET.has(value)) fail(PROVIDER_OPERATION_REPOSITORY_ERROR_CODES.INPUT);
  return value;
}

function normalizeStoredUncertainReason(value) {
  if (typeof value !== "string" || !UNCERTAIN_REASON_SET.has(value)) fail(PROVIDER_OPERATION_REPOSITORY_ERROR_CODES.DATABASE);
  return value;
}

function exactObject(value, keys) {
  if (!plainObject(value)) fail(PROVIDER_OPERATION_REPOSITORY_ERROR_CODES.INPUT);
  const actual = Reflect.ownKeys(value);
  if (actual.length !== keys.length || actual.some((key) => typeof key !== "string" || !keys.includes(key)
    || Object.getOwnPropertyDescriptor(value, key)?.enumerable !== true || Object.getOwnPropertyDescriptor(value, key)?.value === undefined)) {
    fail(PROVIDER_OPERATION_REPOSITORY_ERROR_CODES.INPUT);
  }
}

async function runDatabase(operation) {
  try { return await operation(); }
  catch (error) {
    if (error instanceof ProviderOperationRepositoryError) throw error;
    throw new ProviderOperationRepositoryError(PROVIDER_OPERATION_REPOSITORY_ERROR_CODES.DATABASE);
  }
}

function makeToken(randomBytes) {
  let value;
  try { value = Buffer.from(randomBytes(32)).toString("base64url"); } catch { fail(PROVIDER_OPERATION_REPOSITORY_ERROR_CODES.CONFIG); }
  if (!CLAIM.test(value)) fail(PROVIDER_OPERATION_REPOSITORY_ERROR_CODES.CONFIG);
  return value;
}

function sha256(value) { return crypto.createHash("sha256").update(value).digest("hex"); }
function rowCount(result) { return Number.isSafeInteger(result?.rowCount) ? result.rowCount : Array.isArray(result?.rows) ? result.rows.length : 0; }
function count(value) {
  const normalized = Number(value);
  if (!Number.isSafeInteger(normalized) || normalized < 0) fail(PROVIDER_OPERATION_REPOSITORY_ERROR_CODES.DATABASE);
  return normalized;
}
function timestamp(value) {
  if (typeof value !== "string" || value.length < 20 || value.length > 35) fail(PROVIDER_OPERATION_REPOSITORY_ERROR_CODES.INPUT);
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)) fail(PROVIDER_OPERATION_REPOSITORY_ERROR_CODES.INPUT);
  return new Date(parsed).toISOString();
}
function timestampOrNull(value) {
  if (value === null || value === undefined) return null;
  const parsed = value instanceof Date ? value.getTime() : Date.parse(String(value));
  if (!Number.isFinite(parsed)) fail(PROVIDER_OPERATION_REPOSITORY_ERROR_CODES.DATABASE);
  return new Date(parsed).toISOString();
}
function hexBuffer(value, expectedBytes) {
  if (typeof value !== "string" || value.length !== expectedBytes * 2 || !HEX.test(value)) {
    fail(PROVIDER_OPERATION_REPOSITORY_ERROR_CODES.DATABASE);
  }
  return Buffer.from(value, "hex");
}
function plainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    && (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null);
}
function delay(ms) { return new Promise((resolve) => setTimeout(resolve, ms)); }
function fail(code) { throw new ProviderOperationRepositoryError(code); }
