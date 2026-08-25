import crypto from "node:crypto";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
const OPERATION = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;
const PRINCIPAL = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,254}$/u;
const KEY = /^[A-Za-z0-9._~-]{8,255}$/u;
const HEX_DIGEST = /^[0-9a-f]{64}$/iu;
const TOKEN = /^[A-Za-z0-9_-]{43}$/u;
const CONTROL = /[\u0000-\u001f\u007f]/u;
const RESPONSE_KEY = /^[A-Za-z][A-Za-z0-9_.-]{0,127}$/u;
const SECRET_KEY = /(?:^|_)(?:access|api|authorization|bearer|cookie|credential|csrf|exchange|nonce|password|private|raw|refresh|secret|signature|token)(?:_|$)/iu;
const DEFAULT_TTL = 24 * 60 * 60 * 1000;
const MAX_TTL = DEFAULT_TTL;
const MIN_TTL = 1000;
const MAX_RESPONSE_BYTES = 256 * 1024;

const MESSAGES = Object.freeze({
  invalid_request: "Owner recovery idempotency request is invalid",
  secret_material: "Owner recovery idempotency response contains prohibited material",
  claim_lost: "Owner recovery idempotency claim is no longer valid",
  unavailable: "Owner recovery idempotency storage is unavailable"
});

export class OwnerRecoveryIdempotencyRepositoryError extends Error {
  constructor(code) { super(MESSAGES[code] ?? MESSAGES.unavailable); this.name = "OwnerRecoveryIdempotencyRepositoryError"; this.code = code; }
}

export function createPostgresOwnerRecoveryIdempotencyRepository({ client, now = () => new Date(), randomBytes = crypto.randomBytes, ttlMs = DEFAULT_TTL } = {}) {
  assertClient(client);
  if (typeof now !== "function" || typeof randomBytes !== "function") throw new TypeError("clock and randomness sources are invalid");
  const defaultTtl = ttl(ttlMs);

  async function claim(input = {}) {
    const values = normalizeClaim(input, now, defaultTtl);
    return values.tx ? claimTx({ ...values, tx: values.tx }) : transaction((tx) => claimTx({ ...values, tx }));
  }
  async function claimInTransaction(input = {}) { const values = normalizeClaim(input, now, defaultTtl); assertTx(values.tx); return claimTx(values); }
  async function claimTx(values) {
    const ownerToken = makeToken(randomBytes);
    try {
      const inserted = await values.tx.query(`INSERT INTO owner_recovery_idempotency_records
        (organization_id,operation,principal_id,idempotency_key,request_digest,lifecycle,response_status,response_body,claim_token_digest,created_at,updated_at,expires_at)
        VALUES ($1,$2,$3,$4,$5,'in_progress',NULL,NULL,$6,$7::timestamptz,$7::timestamptz,$8::timestamptz)
        ON CONFLICT (organization_id,operation,principal_id,idempotency_key) DO UPDATE
          SET request_digest=EXCLUDED.request_digest,lifecycle='in_progress',response_status=NULL,response_body=NULL,
              claim_token_digest=EXCLUDED.claim_token_digest,created_at=EXCLUDED.created_at,
              updated_at=EXCLUDED.updated_at,expires_at=EXCLUDED.expires_at
          WHERE owner_recovery_idempotency_records.expires_at <= EXCLUDED.updated_at
        RETURNING created_at,updated_at,expires_at`, [values.organizationId, values.operation, values.principalId, values.key, values.digest, sha256(ownerToken), values.now.toISOString(), values.expiresAt.toISOString()]);
      if (count(inserted) === 1) return Object.freeze({ state: "claimed", owner_token: ownerToken, created_at: iso(inserted.rows[0]?.created_at, values.now), updated_at: iso(inserted.rows[0]?.updated_at, values.now), expires_at: iso(inserted.rows[0]?.expires_at, values.expiresAt) });
      const selected = await values.tx.query(`SELECT request_digest,lifecycle,response_status,response_body,created_at,updated_at,expires_at
        FROM owner_recovery_idempotency_records
        WHERE organization_id=$1 AND operation=$2 AND principal_id=$3 AND idempotency_key=$4 FOR UPDATE`, [values.organizationId, values.operation, values.principalId, values.key]);
      if (count(selected) !== 1) throw unavailable();
      return classify(selected.rows[0], values);
    } catch (error) { if (error instanceof OwnerRecoveryIdempotencyRepositoryError) throw error; throw unavailable(); }
  }

  async function complete(input = {}) {
    const values = normalizeComplete(input, now);
    return values.tx ? completeTx({ ...values, tx: values.tx }) : transaction((tx) => completeTx({ ...values, tx }));
  }
  async function completeInTransaction(input = {}) { const values = normalizeComplete(input, now); assertTx(values.tx); return completeTx(values); }
  async function completeTx(values) {
    try {
      const updated = await values.tx.query(`UPDATE owner_recovery_idempotency_records
        SET lifecycle='completed',response_status=$5,response_body=$6::jsonb,claim_token_digest=NULL,updated_at=$7::timestamptz
        WHERE organization_id=$1 AND operation=$2 AND principal_id=$3 AND idempotency_key=$4
          AND request_digest=$8 AND lifecycle='in_progress' AND claim_token_digest=$9 AND expires_at>$7::timestamptz
        RETURNING response_status,response_body,created_at,updated_at,expires_at`, [values.organizationId, values.operation, values.principalId, values.key, values.status, values.bodyJson, values.now.toISOString(), values.digest, values.ownerDigest]);
      if (count(updated) !== 1) throw new OwnerRecoveryIdempotencyRepositoryError("claim_lost");
      const row = updated.rows[0];
      return Object.freeze({ state: "completed", response_status: Number(row.response_status), response_body: safeStored(row.response_body), created_at: iso(row.created_at, values.now), updated_at: iso(row.updated_at, values.now), expires_at: iso(row.expires_at, values.now) });
    } catch (error) { if (error instanceof OwnerRecoveryIdempotencyRepositoryError) throw error; throw unavailable(); }
  }

  async function abandon(input = {}) {
    const values = normalizeOwner(input, now);
    return values.tx ? abandonTx({ ...values, tx: values.tx }) : transaction((tx) => abandonTx({ ...values, tx }));
  }
  async function abandonInTransaction(input = {}) { const values = normalizeOwner(input, now); assertTx(values.tx); return abandonTx(values); }
  async function abandonTx(values) {
    try {
      const removed = await values.tx.query(`DELETE FROM owner_recovery_idempotency_records
        WHERE organization_id=$1 AND operation=$2 AND principal_id=$3 AND idempotency_key=$4
          AND request_digest=$5 AND lifecycle='in_progress' AND claim_token_digest=$6`, [values.organizationId, values.operation, values.principalId, values.key, values.digest, values.ownerDigest]);
      return Object.freeze({ abandoned: count(removed) === 1 });
    } catch (error) { if (error instanceof OwnerRecoveryIdempotencyRepositoryError) throw error; throw unavailable(); }
  }

  async function transaction(work) {
    let tx;
    try { tx = typeof client.connect === "function" ? await client.connect() : client; } catch { throw unavailable(); }
    let began = false;
    try { await tx.query("BEGIN", []); began = true; const value = await work(tx); await tx.query("COMMIT", []); began = false; return value; }
    catch (error) { if (began) { try { await tx.query("ROLLBACK", []); } catch { throw unavailable(); } } if (error instanceof OwnerRecoveryIdempotencyRepositoryError) throw error; throw unavailable(); }
    finally { if (tx !== client) tx.release?.(); }
  }

  return Object.freeze({ claim, claimInTransaction, complete, completeInTransaction, abandon, abandonInTransaction, withTransaction: transaction });
}

export function sha256Digest(value) { return crypto.createHash("sha256").update(value).digest("hex"); }

function normalizeClaim(input, now, defaultTtl) {
  object(input); keys(input, ["tx", "organization_id", "organizationId", "operation", "principal_id", "principalId", "idempotency_key", "idempotencyKey", "request_digest", "requestDigest", "ttl_ms", "ttlMs", "expires_at", "expiresAt"]);
  const current = date(now()); const expiry = input.expires_at ?? input.expiresAt;
  const expiresAt = expiry === undefined ? new Date(current.getTime() + (input.ttl_ms ?? input.ttlMs ?? defaultTtl)) : date(expiry);
  const value = { tx: input.tx, organizationId: uuid(input.organization_id ?? input.organizationId), operation: operation(input.operation), principalId: principal(input.principal_id ?? input.principalId), key: idempotency(input.idempotency_key ?? input.idempotencyKey), digest: digest(input.request_digest ?? input.requestDigest), now: current, expiresAt };
  if (expiresAt <= current || expiresAt.getTime() - current.getTime() > MAX_TTL) throw invalid();
  if (input.ttl_ms !== undefined || input.ttlMs !== undefined) ttl(input.ttl_ms ?? input.ttlMs);
  return Object.freeze(value);
}
function normalizeComplete(input, now) {
  object(input); keys(input, ["tx", "organization_id", "organizationId", "operation", "principal_id", "principalId", "idempotency_key", "idempotencyKey", "request_digest", "requestDigest", "owner_token", "ownerToken", "response_status", "responseStatus", "response_body", "responseBody"]);
  const scoped = { ...input }; delete scoped.response_status; delete scoped.responseStatus; delete scoped.response_body; delete scoped.responseBody;
  const value = normalizeOwner(scoped, now); const body = safeResponse(input.response_body ?? input.responseBody);
  return Object.freeze({ ...value, status: status(input.response_status ?? input.responseStatus), bodyJson: JSON.stringify(body) });
}
function normalizeOwner(input, now) {
  object(input); keys(input, ["tx", "organization_id", "organizationId", "operation", "principal_id", "principalId", "idempotency_key", "idempotencyKey", "request_digest", "requestDigest", "owner_token", "ownerToken"]);
  return Object.freeze({ tx: input.tx, organizationId: uuid(input.organization_id ?? input.organizationId), operation: operation(input.operation), principalId: principal(input.principal_id ?? input.principalId), key: idempotency(input.idempotency_key ?? input.idempotencyKey), digest: digest(input.request_digest ?? input.requestDigest), ownerDigest: ownerDigest(input.owner_token ?? input.ownerToken), now: date(now()) });
}
function classify(row, values) {
  if (digest(row.request_digest).toString("hex") !== values.digest.toString("hex")) return Object.freeze({ state: "conflict" });
  if (row.lifecycle === "in_progress") return Object.freeze({ state: "in_progress", updated_at: iso(row.updated_at, values.now), expires_at: iso(row.expires_at, values.expiresAt) });
  if (row.lifecycle === "completed") return Object.freeze({ state: "replay", response_status: status(row.response_status), response_body: safeStored(row.response_body), created_at: iso(row.created_at, values.now), updated_at: iso(row.updated_at, values.now), expires_at: iso(row.expires_at, values.expiresAt) });
  throw unavailable();
}
function safeResponse(value, depth = 0) {
  if (depth > 16) throw invalid();
  if (value === null || typeof value === "boolean") return value;
  if (typeof value === "string") { if (value.length > 16384 || CONTROL.test(value)) throw invalid(); return value; }
  if (typeof value === "number") { if (!Number.isFinite(value)) throw invalid(); return value; }
  if (Array.isArray(value)) return value.map((item) => safeResponse(item, depth + 1));
  if (!value || typeof value !== "object" || Object.getPrototypeOf(value) !== Object.prototype) throw invalid();
  const output = {};
  for (const [key, item] of Object.entries(value)) { if (!RESPONSE_KEY.test(key) || (SECRET_KEY.test(key) && !/(?:^|_)(?:id|digest|at)$/iu.test(key))) throw new OwnerRecoveryIdempotencyRepositoryError("secret_material"); output[key] = safeResponse(item, depth + 1); }
  if (Buffer.byteLength(JSON.stringify(output), "utf8") > MAX_RESPONSE_BYTES) throw invalid();
  return output;
}
function safeStored(value) { let result = value; if (typeof value === "string") { try { result = JSON.parse(value); } catch { throw unavailable(); } } try { return safeResponse(result); } catch { throw unavailable(); } }
function makeToken(randomBytes) { let value; try { value = randomBytes(32); } catch { throw unavailable(); } if (!(Buffer.isBuffer(value) || value instanceof Uint8Array) || value.length !== 32) throw unavailable(); return Buffer.from(value).toString("base64url"); }
function ownerDigest(value) { if (typeof value !== "string" || !TOKEN.test(value)) throw invalid(); return sha256(value); }
function digest(value) { if (Buffer.isBuffer(value) || value instanceof Uint8Array) { if (value.length !== 32) throw invalid(); return Buffer.from(value); } if (typeof value !== "string" || !HEX_DIGEST.test(value)) throw invalid(); return Buffer.from(value, "hex"); }
function sha256(value) { return crypto.createHash("sha256").update(value, "utf8").digest(); }
function status(value) { if (!Number.isSafeInteger(value) || value < 100 || value > 599 || value === 102) throw invalid(); return value; }
function ttl(value) { if (!Number.isSafeInteger(value) || value < MIN_TTL || value > MAX_TTL) throw invalid(); return value; }
function uuid(value) { if (typeof value !== "string" || !UUID.test(value)) throw invalid(); return value.toLowerCase(); }
function operation(value) { if (typeof value !== "string" || !OPERATION.test(value) || CONTROL.test(value)) throw invalid(); return value; }
function principal(value) { if (typeof value !== "string" || !PRINCIPAL.test(value) || CONTROL.test(value)) throw invalid(); return value; }
function idempotency(value) { if (typeof value !== "string" || !KEY.test(value)) throw invalid(); return value; }
function date(value) { const result = value instanceof Date ? new Date(value) : new Date(value); if (Number.isNaN(result.getTime())) throw invalid(); return result; }
function iso(value, fallback) { const result = value === undefined || value === null ? fallback : new Date(value); if (!(result instanceof Date) || Number.isNaN(result.getTime())) throw unavailable(); return result.toISOString(); }
function object(value) { if (!value || typeof value !== "object" || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) throw invalid(); }
function keys(value, allowed) { const set = new Set(allowed); if (Object.keys(value).some((key) => !set.has(key))) throw invalid(); }
function count(result) { return Number(result?.rowCount ?? result?.rows?.length ?? 0); }
function invalid() { return new OwnerRecoveryIdempotencyRepositoryError("invalid_request"); }
function unavailable() { return new OwnerRecoveryIdempotencyRepositoryError("unavailable"); }
function assertClient(value) { if (!value || (typeof value.query !== "function" && typeof value.connect !== "function")) throw new TypeError("database client must provide query or connect"); }
function assertTx(value) { if (!value || typeof value.query !== "function") throw new TypeError("transaction client must provide query"); }

export default createPostgresOwnerRecoveryIdempotencyRepository;
