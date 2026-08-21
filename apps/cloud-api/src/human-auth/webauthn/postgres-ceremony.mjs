import crypto from "node:crypto";

import { WebAuthnCeremonyError, WEBAUTHN_ERROR_CODES } from "./ceremony.mjs";

const DEFAULT_TTL_MS = 120_000;
const MAX_TTL_MS = 300_000;
const MAX_PENDING = 10_000;
const DEFAULT_VERIFIER_TIMEOUT_MS = 15_000;
const MAX_VERIFIER_TIMEOUT_MS = 30_000;
const CLAIM_LEASE_MS = MAX_VERIFIER_TIMEOUT_MS + 5_000;
const CHALLENGE_BYTES = 32;
const MAX_CLIENT_DATA_BYTES = 16 * 1024;
const MAX_AUTHENTICATOR_DATA_BYTES = 4 * 1024;
const MAX_SIGNATURE_BYTES = 1024;
const MAX_CREDENTIAL_ID_BYTES = 1024;
const MAX_USER_HANDLE_BYTES = 64;
const MAX_CLOCK_SKEW_MS = 30_000;
const BASE64URL = /^[A-Za-z0-9_-]+$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/;
const OPERATION = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$/;
const CONTEXT_HASH = /^[0-9a-f]{64}$/;
const ORIGIN_SCHEMES = new Set(["https:", "http:"]);
const VERIFIER_RESULT_KEYS = new Set(["verified", "credential_id", "sign_count", "authenticated_at"]);
const CEREMONY = "authentication";
const STATUS = new Set(["pending", "consuming", "consumed", "failed", "expired"]);
const VERIFIER_TIMEOUT_CODE = "ERR_WEBAUTHN_VERIFIER_TIMEOUT";

const BEGIN_SQL = `
INSERT INTO webauthn_challenges (
  id, session_id, member_id, organization_id, ceremony, operation,
  context_hash, challenge_hash, created_at, expires_at, rp_id, origin, user_verification, status
)
SELECT $1, s.id, s.member_id, $3, 'authentication', $4, $5, $6, $7, $8, $9, $10, $11, 'pending'
FROM human_sessions s
JOIN memberships m ON m.organization_id = s.organization_id AND m.member_id = s.member_id
JOIN organizations o ON o.id = s.organization_id
WHERE s.id = $2
  AND m.id = s.membership_id
  AND s.organization_id = $3
  AND s.revoked_at IS NULL
  AND s.expires_at > $7
  AND (s.idle_expires_at IS NULL OR s.idle_expires_at > $7)
  AND m.status = 'active'
  AND m.role = s.role
  AND o.authority_epoch = s.organization_authority_epoch
  AND m.session_epoch = s.membership_session_epoch
RETURNING id, session_id, member_id, organization_id, ceremony, operation,
  encode(context_hash, 'hex') AS context_hash_hex,
  encode(challenge_hash, 'hex') AS challenge_hash_hex,
  created_at, expires_at, rp_id, origin, user_verification, status`;

const EXPIRE_SQL = `
UPDATE webauthn_challenges
SET status = 'expired'
WHERE ceremony = 'authentication'
  AND status = 'pending'
  AND consumed_at IS NULL
  AND expires_at <= $1
RETURNING id`;

const REAP_STALE_SQL = `
UPDATE webauthn_challenges
SET status = 'failed', failed_at = $1, consumed_at = $1
WHERE ceremony = 'authentication'
  AND status = 'consuming'
  AND consumed_at IS NULL
  AND consume_started_at IS NOT NULL
  AND consume_started_at <= $2
RETURNING id`;

const REAP_ONE_SQL = `
UPDATE webauthn_challenges
SET status = 'failed', failed_at = $1, consumed_at = $1
WHERE id = $3
  AND ceremony = 'authentication'
  AND session_id = $4
  AND organization_id = $5
  AND operation = $6
  AND rp_id = $7
  AND origin = $8
  AND user_verification = $9
  AND context_hash IS NOT DISTINCT FROM $10::bytea
  AND status = 'consuming'
  AND consumed_at IS NULL
  AND consume_started_at IS NOT NULL
  AND consume_started_at <= $2
RETURNING id`;

const CAPACITY_LOCK_SQL = "SELECT pg_advisory_xact_lock(hashtextextended('agentpass:webauthn:capacity', 0))";

const CAPACITY_SQL = `
SELECT count(*)::text AS pending_count
FROM webauthn_challenges
WHERE status IN ('pending', 'consuming') AND consumed_at IS NULL AND expires_at > $1`;

const LOAD_SQL = `
SELECT id, session_id, member_id, organization_id, ceremony, operation,
  encode(context_hash, 'hex') AS context_hash_hex,
  encode(challenge_hash, 'hex') AS challenge_hash_hex,
  created_at, expires_at, rp_id, origin, user_verification, status,
  consume_started_at, consumed_at, failed_at
FROM webauthn_challenges
WHERE id = $1`;

const CLAIM_SQL = `
UPDATE webauthn_challenges
SET status = 'consuming', consume_started_at = $2
WHERE id = $1
  AND ceremony = 'authentication'
  AND session_id = $3
  AND organization_id = $4
  AND operation = $5
  AND rp_id = $6
  AND origin = $7
  AND user_verification = $8
  AND context_hash IS NOT DISTINCT FROM $9::bytea
  AND challenge_hash = $10
  AND status = 'pending'
  AND consumed_at IS NULL
  AND expires_at > $2
RETURNING id, session_id, member_id, organization_id, ceremony, operation,
  encode(context_hash, 'hex') AS context_hash_hex,
  encode(challenge_hash, 'hex') AS challenge_hash_hex,
  created_at, expires_at, rp_id, origin, user_verification, status,
  consume_started_at, consumed_at, failed_at`;

const BURN_SQL = `
UPDATE webauthn_challenges
SET status = 'failed', failed_at = $2, consumed_at = $2
WHERE id = $1 AND status = 'consuming' AND consumed_at IS NULL
RETURNING id, status, failed_at, consumed_at`;

const COMPLETE_SQL = `
UPDATE webauthn_challenges
SET status = 'consumed', consumed_at = $2
WHERE id = $1 AND status = 'consuming' AND consumed_at IS NULL
RETURNING id, status, consumed_at`;

const SNAPSHOT_SQL = `
SELECT id, session_id, member_id, organization_id, ceremony, operation,
  created_at, expires_at, rp_id, origin, user_verification, status,
  consume_started_at, consumed_at, failed_at
FROM webauthn_challenges
ORDER BY created_at ASC, id ASC`;

export const POSTGRES_WEBAUTHN_SCHEMA_REQUIREMENTS = Object.freeze({
  migration: "0003_webauthn_challenge_bindings.sql",
  columns: Object.freeze([
    "webauthn_challenges.rp_id",
    "webauthn_challenges.origin",
    "webauthn_challenges.user_verification",
    "webauthn_challenges.status",
    "webauthn_challenges.consume_started_at",
    "webauthn_challenges.failed_at"
  ]),
  live_index_statuses: Object.freeze(["pending", "consuming"])
});

export class PostgresWebAuthnCeremonyError extends Error {
  constructor(code, message = "PostgreSQL WebAuthn ceremony failed", cause = undefined) {
    // Database/provider diagnostics can contain query fragments or caller
    // material. Keep the public error contract deliberately secret-free.
    super(message);
    void cause;
    this.name = "PostgresWebAuthnCeremonyError";
    this.code = code;
  }
}

/**
 * Durable WebAuthn authentication ceremony coordinator.
 *
 * The injected client may be a pg Pool or a dedicated client. `begin` acquires
 * a dedicated connection when available and uses a short transaction for
 * capacity and session binding. `consume` never
 * holds a transaction open while invoking the verifier: it claims the row with
 * a conditional UPDATE, then burns or completes that claim with another
 * conditional UPDATE. No assertion material is sent to PostgreSQL.
 */
export function createPostgresWebAuthnCeremony({
  client,
  verifyAssertion,
  now = () => Date.now(),
  ttlMs = DEFAULT_TTL_MS,
  maxPending = MAX_PENDING,
  verifierTimeoutMs = DEFAULT_VERIFIER_TIMEOUT_MS,
  metrics,
  randomUUID = crypto.randomUUID,
  randomBytes = crypto.randomBytes,
  random
} = {}) {
  assertClient(client);
  const dbQuery = (sql, params, options = {}) => query(client, sql, params, options);
  if (typeof verifyAssertion !== "function") throw new TypeError("verifyAssertion must be a function");
  const makeUuid = random?.uuid ?? randomUUID;
  const makeBytes = random?.bytes ?? randomBytes;
  if (typeof makeUuid !== "function" || typeof makeBytes !== "function") throw new TypeError("random source is invalid");
  assertClock(now());
  assertDuration(ttlMs, "ttlMs", 1_000, MAX_TTL_MS);
  if (!Number.isSafeInteger(maxPending) || maxPending < 1 || maxPending > MAX_PENDING) throw new TypeError("maxPending is invalid");
  assertDuration(verifierTimeoutMs, "verifierTimeoutMs", 1_000, MAX_VERIFIER_TIMEOUT_MS);

  async function begin(input = {}) {
    const context = normalizeContext(input);
    const issuedAt = assertClock(now());
    const requestedTtl = input.ttlMs ?? ttlMs;
    assertDuration(requestedTtl, "ttlMs", 1_000, ttlMs);
    const challengeId = requiredUuidV4(makeUuid(), "challenge_id");
    const bytes = makeBytes(CHALLENGE_BYTES);
    if (!(Buffer.isBuffer(bytes) || bytes instanceof Uint8Array) || bytes.length !== CHALLENGE_BYTES) throw new TypeError("random challenge bytes are invalid");
    const challenge = Buffer.from(bytes).toString("base64url");
    const expiresAt = issuedAt + requestedTtl;
    const createdAt = new Date(issuedAt).toISOString();
    const expiresAtIso = new Date(expiresAt).toISOString();

    const transaction = await acquireTransactionClient(client);
    try {
      const transactionQuery = (sql, params, options = {}) => query(transaction.client, sql, params, options);
      const inserted = await withTransaction(transaction.client, async () => {
        // Serialize the capacity check and insert across API instances. The
        // lock is transaction-scoped and is released by COMMIT/ROLLBACK.
        await transactionQuery(CAPACITY_LOCK_SQL, []);
        await transactionQuery(EXPIRE_SQL, [createdAt]);
        const reaped = await transactionQuery(REAP_STALE_SQL, [createdAt, new Date(Math.max(0, issuedAt - CLAIM_LEASE_MS)).toISOString()]);
        recordMetric(metrics, "recordHumanAuthStaleClaimRecovery", reaped.rows?.length ?? reaped.rowCount ?? 0);
        const capacity = await transactionQuery(CAPACITY_SQL, [createdAt]);
        const pendingCount = parseCount(capacity.rows[0]?.pending_count);
        if (pendingCount >= maxPending) fail(WEBAUTHN_ERROR_CODES.CAPACITY_EXCEEDED);
        return transactionQuery(BEGIN_SQL, [
          challengeId,
          context.session_id,
          context.organization_id,
          context.operation,
          contextHashBytes(context.context_hash),
          sha256Bytes(challenge),
          createdAt,
          expiresAtIso,
          context.rp_id,
          context.origin,
          context.user_verification
        ], { mapConstraint: true });
      });
      if (inserted.rows.length === 0) fail(WEBAUTHN_ERROR_CODES.CHALLENGE_NOT_FOUND);
      if (inserted.rows.length !== 1) throw new PostgresWebAuthnCeremonyError("ERR_WEBAUTHN_STORAGE_RESULT", "WebAuthn challenge insert returned multiple rows");
      assertBeginRow(inserted.rows[0], challengeId, context, issuedAt, expiresAt);
      return Object.freeze({
        challenge_id: challengeId,
        challenge,
        challenge_expires_at: expiresAtIso,
        rp_id: context.rp_id,
        origin: context.origin,
        user_verification: context.user_verification
      });
    } finally {
      await transaction.release();
    }
  }

  async function consume(input = {}) {
    const request = normalizeConsumeInput(input);
    const currentTime = assertClock(now());
    const currentIso = new Date(currentTime).toISOString();
    const reaped = await dbQuery(REAP_ONE_SQL, [currentIso, new Date(Math.max(0, currentTime - CLAIM_LEASE_MS)).toISOString(), request.challenge_id, request.session_id, request.organization_id, request.operation, request.rp_id, request.origin, request.user_verification, contextHashBytes(request.context_hash)]);
    recordMetric(metrics, "recordHumanAuthStaleClaimRecovery", reaped.rows?.length ?? reaped.rowCount ?? 0);
    let record = await loadRecord(request.challenge_id);
    assertRecord(record);
    if (!sameBinding(record, request)) fail(WEBAUTHN_ERROR_CODES.BINDING_MISMATCH);
    if (record.status === "consuming") fail(WEBAUTHN_ERROR_CODES.CHALLENGE_BUSY);
    if (record.status === "consumed" || record.status === "failed") {
      recordMetric(metrics, "recordHumanAuthReplayDenial");
      fail(WEBAUTHN_ERROR_CODES.CHALLENGE_REPLAYED);
    }
    if (record.status === "expired" || currentTime >= record.expires_at) fail(WEBAUTHN_ERROR_CODES.CHALLENGE_EXPIRED);
    if (!sameBinding(record, request)) fail(WEBAUTHN_ERROR_CODES.BINDING_MISMATCH);
    if (!constantTimeBufferEqual(record.challenge_hash, sha256Bytes(request.challenge))) fail(WEBAUTHN_ERROR_CODES.CHALLENGE_MISMATCH);

    const verifierInput = buildVerifierInput(record, request);
    const claimed = await dbQuery(CLAIM_SQL, [
      request.challenge_id,
      currentIso,
      request.session_id,
      request.organization_id,
      request.operation,
      request.rp_id,
      request.origin,
      request.user_verification,
      contextHashBytes(request.context_hash),
      sha256Bytes(request.challenge)
    ]);
    if (claimed.rows.length > 1) throw new PostgresWebAuthnCeremonyError("ERR_WEBAUTHN_STORAGE_RESULT", "WebAuthn challenge claim returned multiple rows");
    if (claimed.rows.length === 0) {
      record = await loadRecord(request.challenge_id);
      assertRecord(record);
      throwClaimState(record, currentTime);
    }
    assertClaimRow(claimed.rows[0], request.challenge_id, record);

    let verification;
    try {
      verification = validateVerifierResult(
        await withTimeout(
          () => verifyAssertion(verifierInput),
          Math.max(1, Math.min(verifierTimeoutMs, record.expires_at - currentTime))
        ),
        request,
        currentTime
      );
    } catch (error) {
      if (error?.code === VERIFIER_TIMEOUT_CODE) recordMetric(metrics, "recordHumanAuthVerifierTimeout");
      await burn(request.challenge_id, new Date(assertClock(now())).toISOString());
      if (error instanceof WebAuthnCeremonyError && error.code === WEBAUTHN_ERROR_CODES.INVALID_VERIFIER_RESULT) throw error;
      fail(WEBAUTHN_ERROR_CODES.VERIFICATION_FAILED);
    }

    const authenticatedAt = assertClock(now());
    if (authenticatedAt >= record.expires_at) {
      await burn(request.challenge_id, new Date(authenticatedAt).toISOString());
      fail(WEBAUTHN_ERROR_CODES.CHALLENGE_EXPIRED);
    }
    let completed;
    try {
      completed = await dbQuery(COMPLETE_SQL, [request.challenge_id, new Date(authenticatedAt).toISOString()]);
      if (completed.rows.length !== 1) throw new PostgresWebAuthnCeremonyError("ERR_WEBAUTHN_CLAIM_LOST", "WebAuthn claim could not be completed");
      assertTerminalRow(completed.rows[0], request.challenge_id, "consumed");
    } catch (error) {
      await burnBestEffort(request.challenge_id, new Date(authenticatedAt).toISOString());
      throw error;
    }
    return Object.freeze({
      verified: true,
      assertion_id: request.challenge_id,
      session_id: record.session_id,
      organization_id: record.organization_id,
      operation: record.operation,
      ...(record.context_hash === undefined ? {} : { context_hash: record.context_hash }),
      authenticated_at: authenticatedAt,
      credential_id_digest: sha256Hex(request.credential_id)
    });
  }

  async function snapshot() {
    const result = await dbQuery(SNAPSHOT_SQL, []);
    return Object.freeze(result.rows.map((row) => {
      const record = normalizeRecord(row);
      return Object.freeze({
        challenge_id: record.id,
        session_id: record.session_id,
        organization_id: record.organization_id,
        operation: record.operation,
        ...(record.context_hash === undefined ? {} : { context_hash: record.context_hash }),
        rp_id: record.rp_id,
        origin: record.origin,
        user_verification: record.user_verification,
        issued_at: record.created_at,
        expires_at: record.expires_at,
        status: record.status,
        ...(record.consume_started_at === undefined ? {} : { consume_started_at: record.consume_started_at }),
        ...(record.consumed_at === undefined ? {} : { consumed_at: record.consumed_at }),
        ...(record.failed_at === undefined ? {} : { failed_at: record.failed_at })
      });
    }));
  }

  return Object.freeze({ begin, consume, snapshot });

  async function loadRecord(id) {
    const result = await dbQuery(LOAD_SQL, [id]);
    if (result.rows.length === 0) fail(WEBAUTHN_ERROR_CODES.CHALLENGE_NOT_FOUND);
    if (result.rows.length !== 1) throw new PostgresWebAuthnCeremonyError("ERR_WEBAUTHN_STORAGE_RESULT", "WebAuthn challenge lookup returned multiple rows");
    return normalizeRecord(result.rows[0]);
  }

  async function burn(id, timestamp) {
    const result = await dbQuery(BURN_SQL, [id, timestamp]);
    if (result.rows.length !== 1) throw new PostgresWebAuthnCeremonyError("ERR_WEBAUTHN_BURN_FAILED", "WebAuthn challenge could not be burned");
    assertTerminalRow(result.rows[0], id, "failed");
  }

  async function burnBestEffort(id, timestamp) {
    try {
      const result = await dbQuery(BURN_SQL, [id, timestamp]);
      if (result.rows.length === 1) assertTerminalRow(result.rows[0], id, "failed");
    } catch {
      // Preserve the original completion error and never expose raw storage
      // diagnostics to the caller.
    }
  }
}

async function query(client, clientQuery, params, { mapConstraint = false } = {}) {
  let result;
  try {
    result = await client.query(clientQuery, params);
  } catch (error) {
    if (mapConstraint && error?.code === "23505") fail(WEBAUTHN_ERROR_CODES.CHALLENGE_BUSY);
    throw new PostgresWebAuthnCeremonyError("ERR_WEBAUTHN_STORAGE", "WebAuthn PostgreSQL operation failed", error);
  }
  if (!result || !Array.isArray(result.rows) || !Number.isSafeInteger(result.rowCount) || result.rowCount !== result.rows.length || result.rowCount < 0) {
    throw new PostgresWebAuthnCeremonyError("ERR_WEBAUTHN_STORAGE_RESULT", "WebAuthn PostgreSQL result is invalid");
  }
  return result;
}

function assertClient(client) {
  if (!client || typeof client.query !== "function") throw new TypeError("database client is invalid");
}

async function acquireTransactionClient(client) {
  if (typeof client.connect !== "function") return Object.freeze({ client, release: async () => {} });
  let transactionClient;
  try {
    transactionClient = await client.connect();
  } catch (error) {
    throw new PostgresWebAuthnCeremonyError("ERR_WEBAUTHN_CONNECTION", "WebAuthn PostgreSQL connection acquisition failed", error);
  }
  if (!transactionClient || typeof transactionClient.query !== "function") throw new PostgresWebAuthnCeremonyError("ERR_WEBAUTHN_CONNECTION", "WebAuthn PostgreSQL connection is invalid");
  let released = false;
  return Object.freeze({
    client: transactionClient,
    release: async () => {
      if (released) return;
      released = true;
      if (typeof transactionClient.release === "function") await transactionClient.release();
    }
  });
}

async function withTransaction(client, callback) {
  await client.query("BEGIN");
  try {
    const result = await callback();
    await client.query("COMMIT");
    return result;
  } catch (error) {
    try { await client.query("ROLLBACK"); } catch (rollbackError) { throw new PostgresWebAuthnCeremonyError("ERR_WEBAUTHN_TRANSACTION", "WebAuthn transaction rollback failed", rollbackError); }
    throw error;
  }
}

function normalizeContext(input) {
  if (!isObject(input)) fail(WEBAUTHN_ERROR_CODES.INVALID_CONTEXT);
  const session_id = requiredUuidContext(input.session_id ?? input.sessionId, "session_id");
  const organization_id = requiredUuidContext(input.organization_id ?? input.organizationId, "organization_id");
  const operation = requiredOperation(input.operation);
  const context_hash = optionalContextHash(input.context_hash);
  const rp_id = requiredRpId(input.rp_id ?? input.rpId);
  const origin = requiredOrigin(input.origin);
  const user_verification = input.user_verification ?? input.userVerification ?? "required";
  if (user_verification !== "required") fail(WEBAUTHN_ERROR_CODES.INVALID_CONTEXT, "user_verification");
  return Object.freeze({ session_id, organization_id, operation, rp_id, origin, user_verification, ...(context_hash === undefined ? {} : { context_hash }) });
}

function normalizeConsumeInput(input) {
  if (!isObject(input)) fail(WEBAUTHN_ERROR_CODES.INVALID_REQUEST);
  const challenge_id = requiredUuidV4(input.challenge_id ?? input.challengeId, "challenge_id");
  const challenge = requiredBase64Url(input.challenge, CHALLENGE_BYTES, "challenge");
  const credential_id = requiredBase64Url(input.credential_id ?? input.credentialId, [1, MAX_CREDENTIAL_ID_BYTES], "credential_id");
  const client_data_json = requiredBase64Url(input.client_data_json ?? input.clientDataJSON, [1, MAX_CLIENT_DATA_BYTES], "client_data_json");
  const authenticator_data = requiredBase64Url(input.authenticator_data ?? input.authenticatorData, [37, MAX_AUTHENTICATOR_DATA_BYTES], "authenticator_data");
  const signature = requiredBase64Url(input.signature, [64, MAX_SIGNATURE_BYTES], "signature");
  let user_handle;
  if (input.user_handle !== undefined || input.userHandle !== undefined) user_handle = requiredBase64Url(input.user_handle ?? input.userHandle, [1, MAX_USER_HANDLE_BYTES], "user_handle");
  const context = normalizeContext(input);
  return Object.freeze({ challenge_id, challenge, credential_id, client_data_json, authenticator_data, signature, ...(user_handle === undefined ? {} : { user_handle }), ...context });
}

function normalizeRecord(row) {
  if (!isObject(row)) throw new PostgresWebAuthnCeremonyError("ERR_WEBAUTHN_STORAGE_RESULT", "WebAuthn challenge row is invalid");
  const id = requiredUuidV4Storage(row.id, "id");
  const session_id = requiredUuidStorage(row.session_id, "session_id");
  const member_id = requiredUuidStorage(row.member_id, "member_id");
  const organization_id = requiredUuidStorage(row.organization_id, "organization_id");
  if (row.ceremony !== CEREMONY) throw new PostgresWebAuthnCeremonyError("ERR_WEBAUTHN_STORAGE_RESULT", "WebAuthn challenge ceremony is invalid");
  const operation = storageOperation(row.operation);
  const rp_id = storageRpId(row.rp_id);
  const origin = storageOrigin(row.origin);
  if (row.user_verification !== "required" || !STATUS.has(row.status)) throw new PostgresWebAuthnCeremonyError("ERR_WEBAUTHN_STORAGE_RESULT", "WebAuthn challenge binding or status is invalid");
  const created_at = storageTime(row.created_at, "created_at");
  const expires_at = storageTime(row.expires_at, "expires_at");
  if (expires_at <= created_at) throw new PostgresWebAuthnCeremonyError("ERR_WEBAUTHN_STORAGE_RESULT", "WebAuthn challenge expiry is invalid");
  const challenge_hash = storageDigest(row.challenge_hash_hex ?? row.challenge_hash, "challenge_hash");
  const context_hash = optionalStorageContextHash(row.context_hash_hex ?? row.context_hash);
  const consume_started_at = optionalStorageTime(row.consume_started_at, "consume_started_at");
  const consumed_at = optionalStorageTime(row.consumed_at, "consumed_at");
  const failed_at = optionalStorageTime(row.failed_at, "failed_at");
  if (row.status === "pending" && (consume_started_at !== undefined || consumed_at !== undefined || failed_at !== undefined)) throw new PostgresWebAuthnCeremonyError("ERR_WEBAUTHN_STORAGE_RESULT", "pending WebAuthn challenge has terminal timestamps");
  if (row.status === "consuming" && (consume_started_at === undefined || consumed_at !== undefined || failed_at !== undefined)) throw new PostgresWebAuthnCeremonyError("ERR_WEBAUTHN_STORAGE_RESULT", "consuming WebAuthn challenge timestamps are invalid");
  if (row.status === "consumed" && consumed_at === undefined) throw new PostgresWebAuthnCeremonyError("ERR_WEBAUTHN_STORAGE_RESULT", "consumed WebAuthn challenge has no consumed_at");
  if (row.status === "failed" && (failed_at === undefined || consumed_at === undefined)) throw new PostgresWebAuthnCeremonyError("ERR_WEBAUTHN_STORAGE_RESULT", "failed WebAuthn challenge has no burn timestamps");
  return Object.freeze({ id, session_id, member_id, organization_id, ceremony: row.ceremony, operation, rp_id, origin, user_verification: row.user_verification, challenge_hash, created_at, expires_at, status: row.status, ...(context_hash === undefined ? {} : { context_hash }), ...(consume_started_at === undefined ? {} : { consume_started_at }), ...(consumed_at === undefined ? {} : { consumed_at }), ...(failed_at === undefined ? {} : { failed_at }) });
}

function assertRecord(record, expectedId = undefined) {
  if (!record || (expectedId !== undefined && record.id !== expectedId)) throw new PostgresWebAuthnCeremonyError("ERR_WEBAUTHN_STORAGE_RESULT", "WebAuthn challenge row identity is invalid");
  return record;
}

function assertBeginRow(row, challengeId, context, issuedAt, expiresAt) {
  const record = normalizeRecord(row);
  if (record.id !== challengeId || record.session_id !== context.session_id || record.organization_id !== context.organization_id || record.operation !== context.operation || record.rp_id !== context.rp_id || record.origin !== context.origin || record.user_verification !== context.user_verification || record.context_hash !== context.context_hash || record.status !== "pending" || record.created_at !== issuedAt || record.expires_at !== expiresAt) throw new PostgresWebAuthnCeremonyError("ERR_WEBAUTHN_STORAGE_RESULT", "inserted WebAuthn challenge row does not match request");
}

function assertClaimRow(row, challengeId, previous) {
  const record = normalizeRecord(row);
  if (record.id !== challengeId || record.status !== "consuming" || record.session_id !== previous.session_id || record.organization_id !== previous.organization_id || record.operation !== previous.operation || record.rp_id !== previous.rp_id || record.origin !== previous.origin || record.user_verification !== previous.user_verification || record.context_hash !== previous.context_hash || !constantTimeBufferEqual(record.challenge_hash, previous.challenge_hash)) throw new PostgresWebAuthnCeremonyError("ERR_WEBAUTHN_STORAGE_RESULT", "claimed WebAuthn challenge row does not match lookup");
}

function assertTerminalRow(row, challengeId, status) {
  if (!isObject(row) || requiredUuidV4Storage(row.id, "id") !== challengeId || row.status !== status) throw new PostgresWebAuthnCeremonyError("ERR_WEBAUTHN_STORAGE_RESULT", "terminal WebAuthn challenge row is invalid");
  if (status === "consumed" && optionalStorageTime(row.consumed_at, "consumed_at") === undefined) throw new PostgresWebAuthnCeremonyError("ERR_WEBAUTHN_STORAGE_RESULT", "consumed WebAuthn challenge has no timestamp");
  if (status === "failed" && (optionalStorageTime(row.failed_at, "failed_at") === undefined || optionalStorageTime(row.consumed_at, "consumed_at") === undefined)) throw new PostgresWebAuthnCeremonyError("ERR_WEBAUTHN_STORAGE_RESULT", "burned WebAuthn challenge has no timestamp");
}

function throwClaimState(record, currentTime) {
  if (record.status === "consuming") fail(WEBAUTHN_ERROR_CODES.CHALLENGE_BUSY);
  if (record.status === "consumed" || record.status === "failed") fail(WEBAUTHN_ERROR_CODES.CHALLENGE_REPLAYED);
  if (record.status === "expired" || currentTime >= record.expires_at) fail(WEBAUTHN_ERROR_CODES.CHALLENGE_EXPIRED);
  throw new PostgresWebAuthnCeremonyError("ERR_WEBAUTHN_CLAIM_LOST", "WebAuthn challenge claim was lost");
}

function buildVerifierInput(record, request) {
  const clientData = decodeClientData(request.client_data_json, request.challenge, record.origin);
  const authenticatorData = decodeAuthenticatorData(request.authenticator_data, record.rp_id, record.user_verification);
  return Object.freeze({
    ceremony: Object.freeze({ challenge_id: request.challenge_id, session_id: record.session_id, organization_id: record.organization_id, operation: record.operation, rp_id: record.rp_id, origin: record.origin, user_verification: record.user_verification, expected_challenge: request.challenge, ...(record.context_hash === undefined ? {} : { context_hash: record.context_hash }) }),
    assertion: Object.freeze({ credential_id: request.credential_id, client_data_json: request.client_data_json, authenticator_data: request.authenticator_data, signature: request.signature, ...(request.user_handle === undefined ? {} : { user_handle: request.user_handle }) }),
    parsed: Object.freeze({ client_data: Object.freeze(clientData), authenticator_data: Object.freeze(authenticatorData) })
  });
}

function decodeClientData(encoded, expectedChallenge, expectedOrigin) {
  const bytes = decodeBase64Url(encoded, [1, MAX_CLIENT_DATA_BYTES], "client_data_json");
  const text = Buffer.from(bytes).toString("utf8");
  if (Buffer.from(text, "utf8").compare(bytes) !== 0) fail(WEBAUTHN_ERROR_CODES.INVALID_RESPONSE);
  let value;
  try { value = JSON.parse(text); } catch { fail(WEBAUTHN_ERROR_CODES.INVALID_RESPONSE); }
  if (!isObject(value) || value.type !== "webauthn.get" || value.challenge !== expectedChallenge || value.origin !== expectedOrigin) fail(WEBAUTHN_ERROR_CODES.INVALID_RESPONSE);
  if (value.crossOrigin !== undefined && value.crossOrigin !== false) fail(WEBAUTHN_ERROR_CODES.INVALID_RESPONSE);
  if (value.tokenBinding !== undefined && (!isObject(value.tokenBinding) || typeof value.tokenBinding.status !== "string")) fail(WEBAUTHN_ERROR_CODES.INVALID_RESPONSE);
  return { type: value.type, challenge: value.challenge, origin: value.origin, ...(value.crossOrigin === undefined ? {} : { cross_origin: value.crossOrigin }) };
}

function decodeAuthenticatorData(encoded, rpId, userVerification) {
  const bytes = decodeBase64Url(encoded, [37, MAX_AUTHENTICATOR_DATA_BYTES], "authenticator_data");
  const expectedRpIdHash = crypto.createHash("sha256").update(rpId).digest();
  if (!crypto.timingSafeEqual(Buffer.from(bytes.subarray(0, 32)), expectedRpIdHash)) fail(WEBAUTHN_ERROR_CODES.INVALID_RESPONSE);
  const flags = bytes[32];
  if ((flags & 0x01) === 0 || (userVerification === "required" && (flags & 0x04) === 0)) fail(WEBAUTHN_ERROR_CODES.INVALID_RESPONSE);
  return { rp_id_hash: Buffer.from(bytes.subarray(0, 32)).toString("base64url"), flags, user_present: true, user_verified: (flags & 0x04) !== 0, sign_count: Buffer.from(bytes.subarray(33, 37)).readUInt32BE(0) };
}

function validateVerifierResult(result, request, currentTime) {
  if (!isObject(result) || result.verified !== true || typeof result.credential_id !== "string" || result.credential_id !== request.credential_id || Object.keys(result).some((key) => !VERIFIER_RESULT_KEYS.has(key))) fail(WEBAUTHN_ERROR_CODES.INVALID_VERIFIER_RESULT);
  if (result.sign_count !== undefined && (!Number.isSafeInteger(result.sign_count) || result.sign_count < 0 || result.sign_count > 0xffffffff)) fail(WEBAUTHN_ERROR_CODES.INVALID_VERIFIER_RESULT);
  if (result.authenticated_at !== undefined && (!Number.isSafeInteger(result.authenticated_at) || result.authenticated_at > currentTime + MAX_CLOCK_SKEW_MS || result.authenticated_at < 0)) fail(WEBAUTHN_ERROR_CODES.INVALID_VERIFIER_RESULT);
}

function sameBinding(record, request) { return record.session_id === request.session_id && record.organization_id === request.organization_id && record.operation === request.operation && record.rp_id === request.rp_id && record.origin === request.origin && record.user_verification === request.user_verification && record.context_hash === request.context_hash; }
function sha256Bytes(value) { return crypto.createHash("sha256").update(value, "utf8").digest(); }
function sha256Hex(value) { return sha256Bytes(value).toString("hex"); }
function constantTimeBufferEqual(left, right) { return Buffer.isBuffer(left) && Buffer.isBuffer(right) && left.length === right.length && crypto.timingSafeEqual(left, right); }
function isObject(value) { return value !== null && typeof value === "object" && !Array.isArray(value); }
function assertClock(value) { if (!Number.isSafeInteger(value) || value < 0) throw new TypeError("clock value is invalid"); return value; }
function assertDuration(value, field, minimum, maximum) { if (!Number.isSafeInteger(value) || value < minimum || value > maximum) throw new TypeError(`${field} is invalid`); return value; }
function requiredUuidV4(value, field) { if (typeof value !== "string" || !UUID_V4.test(value)) fail(WEBAUTHN_ERROR_CODES.INVALID_REQUEST, field); return value.toLowerCase(); }
function requiredUuidV4Storage(value, field) { if (typeof value !== "string" || !UUID_V4.test(value)) throw new PostgresWebAuthnCeremonyError("ERR_WEBAUTHN_STORAGE_RESULT", `${field} is invalid`); return value.toLowerCase(); }
function requiredUuidContext(value, field) { if (typeof value !== "string" || !UUID.test(value)) fail(WEBAUTHN_ERROR_CODES.INVALID_CONTEXT, field); return value.toLowerCase(); }
function requiredUuidStorage(value, field) { if (typeof value !== "string" || !UUID.test(value)) throw new PostgresWebAuthnCeremonyError("ERR_WEBAUTHN_STORAGE_RESULT", `${field} is invalid`); return value.toLowerCase(); }
function requiredOperation(value) { if (typeof value !== "string" || !OPERATION.test(value) || /[\u0000-\u001f\u007f]/.test(value)) fail(WEBAUTHN_ERROR_CODES.INVALID_CONTEXT, "operation"); return value; }
function storageOperation(value) { if (typeof value !== "string" || !OPERATION.test(value) || /[\u0000-\u001f\u007f]/.test(value)) throw new PostgresWebAuthnCeremonyError("ERR_WEBAUTHN_STORAGE_RESULT", "operation is invalid"); return value; }
function requiredRpId(value) { if (typeof value !== "string" || value.length < 1 || value.length > 253 || !/^[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$/.test(value) || value.includes("..")) fail(WEBAUTHN_ERROR_CODES.INVALID_CONTEXT, "rp_id"); return value.toLowerCase(); }
function storageRpId(value) { try { return requiredRpId(value); } catch { throw new PostgresWebAuthnCeremonyError("ERR_WEBAUTHN_STORAGE_RESULT", "rp_id is invalid"); } }
function requiredOrigin(value) { if (typeof value !== "string" || value.length > 512 || /[\u0000-\u001f\u007f]/.test(value)) fail(WEBAUTHN_ERROR_CODES.INVALID_CONTEXT, "origin"); let url; try { url = new URL(value); } catch { fail(WEBAUTHN_ERROR_CODES.INVALID_CONTEXT, "origin"); } if (!ORIGIN_SCHEMES.has(url.protocol) || url.username || url.password || url.pathname !== "/" || url.search || url.hash || (url.protocol === "http:" && url.hostname !== "localhost" && url.hostname !== "127.0.0.1" && url.hostname !== "[::1]")) fail(WEBAUTHN_ERROR_CODES.INVALID_CONTEXT, "origin"); return url.origin; }
function storageOrigin(value) { try { return requiredOrigin(value); } catch { throw new PostgresWebAuthnCeremonyError("ERR_WEBAUTHN_STORAGE_RESULT", "origin is invalid"); } }
function requiredBase64Url(value, length, field) { if (typeof value !== "string" || !BASE64URL.test(value)) fail(WEBAUTHN_ERROR_CODES.INVALID_REQUEST, field); decodeBase64Url(value, length, field); return value; }
function decodeBase64Url(value, length, field) { if (typeof value !== "string" || !BASE64URL.test(value)) fail(WEBAUTHN_ERROR_CODES.INVALID_RESPONSE, field); let bytes; try { bytes = Buffer.from(value, "base64url"); } catch { fail(WEBAUTHN_ERROR_CODES.INVALID_RESPONSE, field); } const [minimum, maximum] = Array.isArray(length) ? length : [length, length]; if (bytes.length < minimum || bytes.length > maximum || bytes.toString("base64url") !== value) fail(WEBAUTHN_ERROR_CODES.INVALID_RESPONSE, field); return bytes; }
function storageDigest(value, field) { let bytes; if (Buffer.isBuffer(value)) bytes = value; else if (typeof value === "string" && /^[0-9a-f]{64}$/i.test(value)) bytes = Buffer.from(value, "hex"); else throw new PostgresWebAuthnCeremonyError("ERR_WEBAUTHN_STORAGE_RESULT", `${field} is invalid`); if (bytes.length !== 32) throw new PostgresWebAuthnCeremonyError("ERR_WEBAUTHN_STORAGE_RESULT", `${field} is invalid`); return Buffer.from(bytes); }
function contextHashBytes(value) { return value === undefined ? null : Buffer.from(optionalContextHash(value), "hex"); }
function optionalContextHash(value) { if (value === undefined) return undefined; if (typeof value !== "string" || !CONTEXT_HASH.test(value)) fail(WEBAUTHN_ERROR_CODES.INVALID_CONTEXT, "context_hash"); return value; }
function optionalStorageContextHash(value) { if (value === null || value === undefined) return undefined; if (Buffer.isBuffer(value) || value instanceof Uint8Array) { if (value.length !== 32) throw new PostgresWebAuthnCeremonyError("ERR_WEBAUTHN_STORAGE_RESULT", "context_hash is invalid"); return Buffer.from(value).toString("hex"); } if (typeof value === "string" && CONTEXT_HASH.test(value)) return value; throw new PostgresWebAuthnCeremonyError("ERR_WEBAUTHN_STORAGE_RESULT", "context_hash is invalid"); }
function storageTime(value, field) { const time = optionalStorageTime(value, field); if (time === undefined) throw new PostgresWebAuthnCeremonyError("ERR_WEBAUTHN_STORAGE_RESULT", `${field} is invalid`); return time; }
function optionalStorageTime(value, field) { if (value === null || value === undefined) return undefined; const time = value instanceof Date ? value.getTime() : typeof value === "string" ? Date.parse(value) : Number.NaN; if (!Number.isSafeInteger(time) || time < 0) throw new PostgresWebAuthnCeremonyError("ERR_WEBAUTHN_STORAGE_RESULT", `${field} is invalid`); return time; }
function parseCount(value) { if (typeof value !== "string" && typeof value !== "number") throw new PostgresWebAuthnCeremonyError("ERR_WEBAUTHN_STORAGE_RESULT", "pending count is invalid"); const count = Number(value); if (!Number.isSafeInteger(count) || count < 0) throw new PostgresWebAuthnCeremonyError("ERR_WEBAUTHN_STORAGE_RESULT", "pending count is invalid"); return count; }
function fail(code, details) { throw new WebAuthnCeremonyError(code, details); }

function withTimeout(callback, timeoutMs) {
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => {
      const error = new Error("WebAuthn verifier timed out");
      error.code = VERIFIER_TIMEOUT_CODE;
      reject(error);
    }, timeoutMs);
  });
  return Promise.race([Promise.resolve().then(callback), timeout]).finally(() => clearTimeout(timer));
}

function recordMetric(metrics, method, amount = 1) {
  if (!Number.isSafeInteger(amount) || amount < 1) return;
  try { metrics?.[method]?.(amount); } catch { /* Metrics cannot affect auth. */ }
}
