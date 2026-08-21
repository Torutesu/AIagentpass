import crypto from "node:crypto";

import { withTransaction } from "./repository.mjs";

const PURPOSE = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/u;
const KEY_ID = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$/u;
const OPERATION_ID = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$/u;
const DIGEST = /^[0-9a-f]{64}$/u;
const VERSION = /^[1-9][0-9]{0,31}$/u;
const CLAIM = /^[A-Za-z0-9_-]{43}$/u;
const PROVIDER = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$/u;
const RECEIPT = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;
const BASE64URL = /^[A-Za-z0-9_-]+$/u;
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
  "algorithm", "bytes_length", "key_id", "key_version", "operation_id", "purpose", "request_digest"
]);

const SELECT_OPERATION = `SELECT purpose,operation_id,algorithm,bytes_length,
  encode(request_digest,'hex') AS request_digest,key_id,key_version::text AS key_version,state,
  claim_token_digest,claim_expires_at,claim_expires_at > clock_timestamp() AS claim_active,
  provider_started_at,uncertain_reason,signature,public_key_der,
  provider_receipt_provider,provider_receipt_id
  FROM managed_signer_provider_operations
  WHERE purpose=$1 AND operation_id=$2`;

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
    return runDatabase(() => withTransaction(client, async (tx) => {
      let row = await selectOperation(tx, operation, true);
      if (row) {
        assertIdentity(row, operation);
        if (row.state === "pending" && claimExpired(row)) {
          const token = makeToken(randomBytes);
          row = await setClaim(tx, operation, token, "pending", claimLeaseMs);
          return publicRecord(row, token);
        }
        return publicRecord(row);
      }
      const token = makeToken(randomBytes);
      const result = await tx.query(`INSERT INTO managed_signer_provider_operations
        (purpose,operation_id,algorithm,bytes_length,request_digest,key_id,key_version,state,
         claim_token_digest,claim_expires_at,provider_started_at,uncertain_reason,signature,public_key_der,
         provider_receipt_provider,provider_receipt_id,expires_at)
        VALUES ($1,$2,$3,$4,$5,$6,$7,'pending',$8,clock_timestamp()+($9 * interval '1 millisecond'),
          NULL,NULL,NULL,NULL,NULL,NULL,clock_timestamp()+($10 * interval '1 millisecond'))
        ON CONFLICT (purpose,operation_id) DO NOTHING
        RETURNING purpose,operation_id,algorithm,bytes_length,encode(request_digest,'hex') AS request_digest,
          key_id,key_version::text AS key_version,state,claim_token_digest,claim_expires_at,
          claim_expires_at > clock_timestamp() AS claim_active,
          provider_started_at,uncertain_reason,signature,public_key_der,provider_receipt_provider,provider_receipt_id`, [
        operation.purpose, operation.operation_id, operation.algorithm, operation.bytes_length,
        Buffer.from(operation.request_digest, "hex"), operation.key_id, operation.key_version,
        Buffer.from(sha256(token), "hex"), claimLeaseMs, retentionMs,
      ]);
      if (rowCount(result) === 1) return publicRecord(result.rows[0], token);
      if (rowCount(result) !== 0) fail(PROVIDER_OPERATION_REPOSITORY_ERROR_CODES.DATABASE);

      // SELECT-then-INSERT cannot by itself serialize two first reservations:
      // both transactions may observe absence before either inserts.  The
      // unique key and ON CONFLICT are the linearization point.  After the
      // winning transaction commits, lock and validate its exact immutable
      // binding rather than surfacing a transient database error.
      row = await selectOperation(tx, operation, true);
      if (!row) fail(PROVIDER_OPERATION_REPOSITORY_ERROR_CODES.DATABASE);
      assertIdentity(row, operation);
      if (row.state === "pending" && claimExpired(row)) {
        const replacementToken = makeToken(randomBytes);
        row = await setClaim(tx, operation, replacementToken, "pending", claimLeaseMs);
        return publicRecord(row, replacementToken);
      }
      return publicRecord(row);
    }));
  }

  async function claimOperation(input) {
    const operation = normalizeOperation(input, binding);
    return runDatabase(() => withTransaction(client, async (tx) => {
      const row = await selectOperation(tx, operation, true);
      if (!row) return null;
      assertIdentity(row, operation);
      if (["committed", "rejected", "failed"].includes(row.state)) return publicRecord(row);
      if (row.claim_token_digest && !claimExpired(row)) return publicRecord(row);
      const token = makeToken(randomBytes);
      const claimed = await setClaim(tx, operation, token, row.state, claimLeaseMs);
      return publicRecord(claimed, token);
    }));
  }

  async function startOperation(input) {
    const { operation, claimToken } = normalizeClaimedOperation(input, binding);
    return claimedUpdate(operation, claimToken, ["pending", "started"], `state='started',provider_started_at=COALESCE(provider_started_at,clock_timestamp())`);
  }

  async function recordAccepted(input) {
    const { operation, claimToken } = normalizeClaimedOperation(input, binding, ["signature", "provider_receipt"]);
    const output = normalizeOutput(input.signature, input.provider_receipt, operation);
    return runDatabase(() => withTransaction(client, async (tx) => {
      const row = await selectOperation(tx, operation, true);
      requireClaim(row, operation, claimToken, ["started", "uncertain", "accepted"]);
      if (row.state === "accepted") {
        assertStoredOutput(row, output);
        return publicRecord(row, claimToken);
      }
      const result = await tx.query(`UPDATE managed_signer_provider_operations
        SET state='accepted',uncertain_reason=NULL,signature=$3,public_key_der=$4,provider_receipt_provider=$5,provider_receipt_id=$6
        WHERE purpose=$1 AND operation_id=$2 AND state IN ('started','uncertain')
        RETURNING purpose,operation_id,algorithm,bytes_length,encode(request_digest,'hex') AS request_digest,
          key_id,key_version::text AS key_version,state,claim_token_digest,claim_expires_at,
          claim_expires_at > clock_timestamp() AS claim_active,
          provider_started_at,uncertain_reason,signature,public_key_der,provider_receipt_provider,provider_receipt_id`, [
        operation.purpose, operation.operation_id, output.signature, output.publicKeyDer,
        output.provider, output.receiptId,
      ]);
      if (rowCount(result) !== 1) fail(PROVIDER_OPERATION_REPOSITORY_ERROR_CODES.STATE);
      return publicRecord(result.rows[0], claimToken);
    }));
  }

  async function commitOperation(input) {
    const { operation, claimToken } = normalizeClaimedOperation(input, binding);
    return runDatabase(() => withTransaction(client, async (tx) => {
      const row = await selectOperation(tx, operation, true);
      if (row?.state === "committed") { assertIdentity(row, operation); return publicRecord(row); }
      requireClaim(row, operation, claimToken, ["accepted"]);
      return commitRow(tx, operation, ["accepted"]);
    }));
  }

  async function reconcileOperation(input) {
    const operation = normalizeOperation(input, binding);
    return runDatabase(() => withTransaction(client, async (tx) => {
      const row = await selectOperation(tx, operation, true);
      if (!row) return null;
      assertIdentity(row, operation);
      if (row.state === "committed") return publicRecord(row);
      if (!["accepted", "uncertain"].includes(row.state) || !hasOutput(row)) {
        fail(PROVIDER_OPERATION_REPOSITORY_ERROR_CODES.STATE);
      }
      return commitRow(tx, operation, ["accepted", "uncertain"]);
    }));
  }

  async function markUncertain(input) {
    const { operation, claimToken } = normalizeClaimedOperation(input, binding, ["uncertain_reason"]);
    const uncertainReason = normalizeUncertainReason(input.uncertain_reason);
    return runDatabase(() => withTransaction(client, async (tx) => {
      const row = await selectOperation(tx, operation, true);
      if (!row) return null;
      assertIdentity(row, operation);
      if (["committed", "rejected", "failed"].includes(row.state)) return publicRecord(row);
      requireClaim(row, operation, claimToken, ["pending", "started", "accepted", "uncertain"]);
      const result = await tx.query(`UPDATE managed_signer_provider_operations
        SET state='uncertain',uncertain_reason=$3,claim_token_digest=NULL,claim_expires_at=NULL,
          provider_started_at=COALESCE(provider_started_at,clock_timestamp())
        WHERE purpose=$1 AND operation_id=$2
        RETURNING purpose,operation_id,algorithm,bytes_length,encode(request_digest,'hex') AS request_digest,
          key_id,key_version::text AS key_version,state,claim_token_digest,claim_expires_at,
          claim_expires_at > clock_timestamp() AS claim_active,
          provider_started_at,uncertain_reason,signature,public_key_der,provider_receipt_provider,provider_receipt_id`, [operation.purpose, operation.operation_id, uncertainReason]);
      if (rowCount(result) !== 1) fail(PROVIDER_OPERATION_REPOSITORY_ERROR_CODES.STATE);
      return publicRecord(result.rows[0]);
    }));
  }

  async function getOperation(input) {
    const operation = normalizeOperation(input, binding);
    return runDatabase(async () => {
      const row = await selectOperation(client, operation, false);
      if (!row) return null;
      assertIdentity(row, operation);
      return publicRecord(row);
    });
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
      const result = await client.query(`SELECT
        count(*) FILTER (WHERE state='pending') AS pending,
        count(*) FILTER (WHERE state='started') AS started,
        count(*) FILTER (WHERE state='accepted') AS accepted,
        count(*) FILTER (WHERE state='uncertain') AS uncertain,
        count(*) FILTER (WHERE state='committed') AS committed,
        count(*) FILTER (WHERE state='rejected') AS rejected,
        count(*) FILTER (WHERE state='failed') AS failed,
        count(*) FILTER (WHERE state IN ('pending','started','accepted','uncertain')
          AND claim_expires_at IS NOT NULL AND claim_expires_at<=clock_timestamp()) AS stale_claims,
        min(created_at) FILTER (WHERE state IN ('pending','started','accepted','uncertain')) AS oldest_nonterminal_at
        FROM managed_signer_provider_operations
        WHERE purpose=$1 AND key_id=$2 AND key_version=$3`, [binding.purpose, binding.keyId, binding.keyVersion]);
      if (rowCount(result) !== 1) fail(PROVIDER_OPERATION_REPOSITORY_ERROR_CODES.DATABASE);
      const row = result.rows[0];
      const states = Object.freeze(Object.fromEntries(PROVIDER_OPERATION_STATES_FOR_HEALTH.map((state) => [state, count(row[state])])));
      return Object.freeze({
        version: 1,
        purpose: binding.purpose,
        algorithm: binding.algorithm,
        key_id: binding.keyId,
        key_version: binding.keyVersion,
        states,
        stale_claims: count(row.stale_claims),
        oldest_nonterminal_at: timestampOrNull(row.oldest_nonterminal_at),
      });
    });
  }

  async function pruneOperations(input) {
    exactObject(input, ["before", "limit"]);
    const before = timestamp(input.before);
    if (!Number.isSafeInteger(input.limit) || input.limit < 1 || input.limit > MAX_PRUNE) {
      fail(PROVIDER_OPERATION_REPOSITORY_ERROR_CODES.INPUT);
    }
    return runDatabase(() => withTransaction(client, async (tx) => {
      const result = await tx.query(`WITH doomed AS (
          SELECT provider.purpose,provider.operation_id
          FROM managed_signer_provider_operations provider
          JOIN managed_signer_signing_idempotency signing
            ON signing.purpose=provider.purpose AND signing.operation_id=provider.operation_id
          WHERE provider.purpose=$1 AND provider.key_id=$2 AND provider.key_version=$3
            AND provider.state='committed' AND signing.status='committed'
            AND provider.expires_at<=$4::timestamptz AND provider.expires_at<=clock_timestamp()
            AND signing.expires_at<=$4::timestamptz AND signing.expires_at<=clock_timestamp()
          ORDER BY provider.expires_at ASC,provider.operation_id ASC
          FOR UPDATE OF provider SKIP LOCKED
          LIMIT $5
        )
        DELETE FROM managed_signer_provider_operations provider
        USING doomed
        WHERE provider.purpose=doomed.purpose AND provider.operation_id=doomed.operation_id
        RETURNING provider.operation_id`, [binding.purpose, binding.keyId, binding.keyVersion, before, input.limit]);
      return Object.freeze({ pruned: rowCount(result) });
    }));
  }

  async function claimedUpdate(operation, claimToken, states, assignment) {
    return runDatabase(() => withTransaction(client, async (tx) => {
      const row = await selectOperation(tx, operation, true);
      requireClaim(row, operation, claimToken, states);
      const result = await tx.query(`UPDATE managed_signer_provider_operations SET ${assignment}
        WHERE purpose=$1 AND operation_id=$2
        RETURNING purpose,operation_id,algorithm,bytes_length,encode(request_digest,'hex') AS request_digest,
          key_id,key_version::text AS key_version,state,claim_token_digest,claim_expires_at,
          claim_expires_at > clock_timestamp() AS claim_active,
          provider_started_at,uncertain_reason,signature,public_key_der,provider_receipt_provider,provider_receipt_id`, [operation.purpose, operation.operation_id]);
      if (rowCount(result) !== 1) fail(PROVIDER_OPERATION_REPOSITORY_ERROR_CODES.STATE);
      return publicRecord(result.rows[0], claimToken);
    }));
  }

  return Object.freeze({ purpose, algorithm, key_id: keyId, key_version: String(keyVersion),
    reserveOperation, claimOperation, startOperation, recordAccepted, commitOperation,
    reconcileOperation, markUncertain, getOperation, waitForOperation, health, pruneOperations });
}

const PROVIDER_OPERATION_STATES_FOR_HEALTH = Object.freeze([
  "pending", "started", "accepted", "uncertain", "committed", "rejected", "failed",
]);

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

async function selectOperation(client, operation, lock) {
  const result = await client.query(`${SELECT_OPERATION}${lock ? " FOR UPDATE" : ""}`, [operation.purpose, operation.operation_id]);
  return rowCount(result) === 0 ? null : result.rows[0];
}

async function setClaim(client, operation, token, state, leaseMs) {
  const result = await client.query(`UPDATE managed_signer_provider_operations
    SET state=$3,claim_token_digest=$4,claim_expires_at=clock_timestamp()+($5 * interval '1 millisecond')
    WHERE purpose=$1 AND operation_id=$2
    RETURNING purpose,operation_id,algorithm,bytes_length,encode(request_digest,'hex') AS request_digest,
      key_id,key_version::text AS key_version,state,claim_token_digest,claim_expires_at,
      claim_expires_at > clock_timestamp() AS claim_active,
      provider_started_at,uncertain_reason,signature,public_key_der,provider_receipt_provider,provider_receipt_id`, [
    operation.purpose, operation.operation_id, state, Buffer.from(sha256(token), "hex"), leaseMs,
  ]);
  if (rowCount(result) !== 1) fail(PROVIDER_OPERATION_REPOSITORY_ERROR_CODES.CLAIM_LOST);
  return result.rows[0];
}

async function commitRow(client, operation, states) {
  if (!Array.isArray(states) || states.length === 0) fail(PROVIDER_OPERATION_REPOSITORY_ERROR_CODES.STATE);
  const statePlaceholders = states.map((_, index) => `$${index + 3}`).join(",");
  const result = await client.query(`UPDATE managed_signer_provider_operations
    SET state='committed',uncertain_reason=NULL,claim_token_digest=NULL,claim_expires_at=NULL
    WHERE purpose=$1 AND operation_id=$2 AND state IN (${statePlaceholders})
    RETURNING purpose,operation_id,algorithm,bytes_length,encode(request_digest,'hex') AS request_digest,
      key_id,key_version::text AS key_version,state,claim_token_digest,claim_expires_at,
      claim_expires_at > clock_timestamp() AS claim_active,
      provider_started_at,uncertain_reason,signature,public_key_der,provider_receipt_provider,provider_receipt_id`, [operation.purpose, operation.operation_id, ...states]);
  if (rowCount(result) !== 1) fail(PROVIDER_OPERATION_REPOSITORY_ERROR_CODES.STATE);
  return publicRecord(result.rows[0]);
}

function requireClaim(row, operation, claimToken, states) {
  if (!row) fail(PROVIDER_OPERATION_REPOSITORY_ERROR_CODES.CLAIM_LOST);
  assertIdentity(row, operation);
  if (!states.includes(row.state) || !row.claim_token_digest || claimExpired(row)
    || !safeEqual(Buffer.from(row.claim_token_digest), Buffer.from(sha256(claimToken), "hex"))) {
    fail(PROVIDER_OPERATION_REPOSITORY_ERROR_CODES.CLAIM_LOST);
  }
}

function assertIdentity(row, operation) {
  for (const field of OPERATION_FIELDS) {
    const value = field === "key_version" ? String(row[field]) : field === "bytes_length" ? Number(row[field]) : row[field];
    if (value !== operation[field]) fail(PROVIDER_OPERATION_REPOSITORY_ERROR_CODES.CONFLICT);
  }
}

function assertStoredOutput(row, output) {
  if (!safeEqual(Buffer.from(row.signature ?? []), output.signature)
    || !safeEqual(Buffer.from(row.public_key_der ?? []), output.publicKeyDer)
    || row.provider_receipt_provider !== output.provider || row.provider_receipt_id !== output.receiptId) {
    fail(PROVIDER_OPERATION_REPOSITORY_ERROR_CODES.CONFLICT);
  }
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
  if (hasOutput(row)) {
    record.signature = Object.freeze({ algorithm: ALGORITHM, encoding: "base64url", value: Buffer.from(row.signature).toString("base64url"),
      public_key: Object.freeze({ algorithm: ALGORITHM, encoding: "base64url", value: Buffer.from(row.public_key_der).toString("base64url") }) });
    record.provider_receipt = Object.freeze({ provider: row.provider_receipt_provider, receipt_id: row.provider_receipt_id,
      operation_id: row.operation_id, key_id: row.key_id, key_version: String(row.key_version) });
  }
  return Object.freeze(record);
}

function hasOutput(row) {
  return row.signature != null && row.public_key_der != null
    && row.provider_receipt_provider != null && row.provider_receipt_id != null;
}

function claimExpired(row) { return row.claim_active !== true; }

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
function safeEqual(left, right) { return left.length === right.length && crypto.timingSafeEqual(left, right); }
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
  if (value === null) return null;
  const parsed = value instanceof Date ? value.getTime() : Date.parse(String(value));
  if (!Number.isFinite(parsed)) fail(PROVIDER_OPERATION_REPOSITORY_ERROR_CODES.DATABASE);
  return new Date(parsed).toISOString();
}
function plainObject(value) { return value !== null && typeof value === "object" && !Array.isArray(value) && (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null); }
function delay(ms) { return new Promise((resolve) => setTimeout(resolve, ms)); }
function fail(code) { throw new ProviderOperationRepositoryError(code); }
