import crypto from "node:crypto";
import { isIP } from "node:net";

import {
  WebAuthnRegistrationError,
  WEBAUTHN_REGISTRATION_ERROR_CODES
} from "./registration.mjs";

const DEFAULT_TTL_MS = 120_000;
const MAX_TTL_MS = 300_000;
const MAX_PENDING = 10_000;
const DEFAULT_VERIFIER_TIMEOUT_MS = 15_000;
const MAX_VERIFIER_TIMEOUT_MS = 30_000;
const CLAIM_LEASE_MS = MAX_VERIFIER_TIMEOUT_MS + 5_000;
const CHALLENGE_BYTES = 32;
const MAX_CLIENT_DATA_BYTES = 16 * 1024;
const MAX_ATTESTATION_OBJECT_BYTES = 64 * 1024;
const MAX_CREDENTIAL_ID_BYTES = 1024;
const MAX_USER_HANDLE_BYTES = 64;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const BASE64URL = /^[A-Za-z0-9_-]+$/;
const OPERATION = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/;
const RP_ID = /^[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$/;
const ORIGIN_SCHEMES = new Set(["https:", "http:"]);
const STATUS = new Set(["pending", "consuming", "consumed", "failed", "expired"]);
const VERIFIER_TIMEOUT_CODE = "ERR_WEBAUTHN_REGISTRATION_VERIFIER_TIMEOUT";
const TRANSPORTS = new Set(["ble", "cable", "hybrid", "internal", "nfc", "smart-card", "usb"]);
const CEREMONY = "registration";

const BEGIN_SQL = `
INSERT INTO webauthn_challenges (
  id, session_id, member_id, organization_id, ceremony, operation,
  challenge_hash, created_at, expires_at, rp_id, origin, user_verification, status
)
SELECT $1, s.id, s.member_id, s.organization_id, 'registration', $5,
  $6, $7, $8, $9, $10, $11, 'pending'
FROM human_sessions s
JOIN memberships m
  ON m.organization_id = s.organization_id
 AND m.member_id = s.member_id
WHERE s.id = $2
  AND s.member_id = $3
  AND s.organization_id = $4
  AND s.revoked_at IS NULL
  AND s.expires_at > $7
  AND m.status = 'active'
  AND m.role = s.role
RETURNING id, session_id, member_id, organization_id, ceremony, operation,
  encode(challenge_hash, 'hex') AS challenge_hash_hex,
  created_at, expires_at, rp_id, origin, user_verification, status`;

const EXPIRE_SQL = `
UPDATE webauthn_challenges
SET status = 'expired'
WHERE ceremony = 'registration'
  AND status = 'pending'
  AND consumed_at IS NULL
  AND expires_at <= $1
RETURNING id`;

const REAP_STALE_SQL = `
UPDATE webauthn_challenges
SET status = 'failed', failed_at = $1, consumed_at = $1
WHERE ceremony = 'registration'
  AND status = 'consuming'
  AND consumed_at IS NULL
  AND consume_started_at IS NOT NULL
  AND consume_started_at <= $2
RETURNING id`;

const REAP_ONE_SQL = `
UPDATE webauthn_challenges
SET status = 'failed', failed_at = $1, consumed_at = $1
WHERE id = $3
  AND ceremony = 'registration'
  AND session_id = $4
  AND member_id = $5
  AND organization_id = $6
  AND operation = $7
  AND rp_id = $8
  AND origin = $9
  AND user_verification = $10
  AND status = 'consuming'
  AND consumed_at IS NULL
  AND consume_started_at IS NOT NULL
  AND consume_started_at <= $2
RETURNING id`;

const CAPACITY_LOCK_SQL = "SELECT pg_advisory_xact_lock(hashtextextended('agentpass:webauthn:capacity', 0))";

const CAPACITY_SQL = `
SELECT count(*)::text AS pending_count
FROM webauthn_challenges
WHERE ceremony = 'registration'
  AND status IN ('pending', 'consuming')
  AND consumed_at IS NULL
  AND expires_at > $1`;

const LOAD_SQL = `
SELECT id, session_id, member_id, organization_id, ceremony, operation,
  encode(challenge_hash, 'hex') AS challenge_hash_hex,
  created_at, expires_at, rp_id, origin, user_verification, status,
  consume_started_at, consumed_at, failed_at
FROM webauthn_challenges
WHERE id = $1`;

const CLAIM_SQL = `
UPDATE webauthn_challenges
SET status = 'consuming', consume_started_at = $2
WHERE id = $1
  AND ceremony = 'registration'
  AND status = 'pending'
  AND consumed_at IS NULL
  AND expires_at > $2
RETURNING id, session_id, member_id, organization_id, ceremony, operation,
  encode(challenge_hash, 'hex') AS challenge_hash_hex,
  created_at, expires_at, rp_id, origin, user_verification, status,
  consume_started_at, consumed_at, failed_at`;

const BURN_SQL = `
UPDATE webauthn_challenges
SET status = 'failed', failed_at = $2, consumed_at = $2
WHERE id = $1
  AND ceremony = 'registration'
  AND status = 'consuming'
  AND consumed_at IS NULL
RETURNING id, status, failed_at, consumed_at`;

const COMPLETE_SQL = `
UPDATE webauthn_challenges
SET status = 'consumed', consumed_at = $2
WHERE id = $1
  AND ceremony = 'registration'
  AND status = 'consuming'
  AND consumed_at IS NULL
RETURNING id, status, consumed_at`;

const SNAPSHOT_SQL = `
SELECT id, session_id, member_id, organization_id, ceremony, operation,
  created_at, expires_at, rp_id, origin, user_verification, status,
  consume_started_at, consumed_at, failed_at
FROM webauthn_challenges
WHERE ceremony = 'registration'
ORDER BY created_at ASC, id ASC`;

export const POSTGRES_WEBAUTHN_REGISTRATION_SCHEMA_REQUIREMENTS = Object.freeze({
  table: "webauthn_challenges",
  ceremony: CEREMONY,
  persisted_fields: Object.freeze([
    "challenge_hash",
    "session_id",
    "member_id",
    "organization_id",
    "operation",
    "rp_id",
    "origin",
    "user_verification",
    "status"
  ]),
  forbidden_persisted_fields: Object.freeze([
    "challenge",
    "client_data_json",
    "attestation_object",
    "credential_id",
    "public_key",
    "sign_count",
    "transports"
  ])
});

export class PostgresWebAuthnRegistrationCeremonyError extends Error {
  constructor(code, message = "PostgreSQL WebAuthn registration ceremony failed", cause = undefined) {
    // Database/provider diagnostics can contain query fragments or caller
    // material. Keep the public error contract deliberately secret-free.
    super(message);
    void cause;
    this.name = "PostgresWebAuthnRegistrationCeremonyError";
    this.code = code;
    this.kind = "storage_unavailable";
  }
}

/**
 * Durable WebAuthn registration ceremony coordinator.
 *
 * PostgreSQL receives only a SHA-256 challenge digest and public binding
 * metadata. The browser response is held in the caller's process only while
 * the verifier runs; it is never included in a SQL parameter or row.
 */
export function createPostgresWebAuthnRegistrationCeremony({
  client,
  verifyAttestation,
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
  if (typeof verifyAttestation !== "function") throw new TypeError("verifyAttestation must be a function");
  if (typeof now !== "function") throw new TypeError("now must be a function");
  assertClock(now());
  assertDuration(ttlMs, "ttlMs", 1_000, MAX_TTL_MS);
  if (!Number.isSafeInteger(maxPending) || maxPending < 1 || maxPending > MAX_PENDING) throw new TypeError("maxPending is invalid");
  assertDuration(verifierTimeoutMs, "verifierTimeoutMs", 1_000, MAX_VERIFIER_TIMEOUT_MS);
  const makeUuid = random?.uuid ?? randomUUID;
  const makeBytes = random?.bytes ?? randomBytes;
  if (typeof makeUuid !== "function" || typeof makeBytes !== "function") throw new TypeError("random source is invalid");
  const dbQuery = (sql, params, options = {}) => query(client, sql, params, options);

  async function begin(input = {}) {
    const context = normalizeContext(input);
    const issuedAt = assertClock(now());
    const requestedTtl = input.ttlMs ?? ttlMs;
    assertDuration(requestedTtl, "ttlMs", 1_000, ttlMs);
    const challengeId = requiredUuidV4(makeUuid(), "challenge_id");
    const challengeBytes = makeBytes(CHALLENGE_BYTES);
    if (!(Buffer.isBuffer(challengeBytes) || challengeBytes instanceof Uint8Array) || challengeBytes.length !== CHALLENGE_BYTES) throw new TypeError("random challenge bytes are invalid");
    const challenge = Buffer.from(challengeBytes).toString("base64url");
    const expiresAt = issuedAt + requestedTtl;
    const createdAtIso = new Date(issuedAt).toISOString();
    const expiresAtIso = new Date(expiresAt).toISOString();
    const challengeHash = sha256Bytes(challenge);

    const transaction = await acquireTransactionClient(client);
    try {
      const transactionQuery = (sql, params, options = {}) => query(transaction.client, sql, params, options);
      const inserted = await withTransaction(transaction.client, async () => {
        await transactionQuery(CAPACITY_LOCK_SQL, []);
        await transactionQuery(EXPIRE_SQL, [createdAtIso]);
        const reaped = await transactionQuery(REAP_STALE_SQL, [createdAtIso, new Date(Math.max(0, issuedAt - CLAIM_LEASE_MS)).toISOString()]);
        recordMetric(metrics, "recordHumanAuthStaleClaimRecovery", reaped.rows?.length ?? reaped.rowCount ?? 0);
        const capacity = await transactionQuery(CAPACITY_SQL, [createdAtIso]);
        if (parseCount(capacity.rows[0]?.pending_count) >= maxPending) fail(WEBAUTHN_REGISTRATION_ERROR_CODES.CAPACITY_EXCEEDED);
        return transactionQuery(BEGIN_SQL, [
          challengeId,
          context.session_id,
          context.member_id,
          context.organization_id,
          context.operation,
          challengeHash,
          createdAtIso,
          expiresAtIso,
          context.rp_id,
          context.origin,
          context.user_verification
        ], { mapConstraint: true });
      });
      if (inserted.rows.length === 0) fail(WEBAUTHN_REGISTRATION_ERROR_CODES.CHALLENGE_NOT_FOUND);
      if (inserted.rows.length !== 1) throw storageError("ERR_WEBAUTHN_REGISTRATION_STORAGE_RESULT", "registration challenge insert returned multiple rows");
      assertBeginRow(inserted.rows[0], challengeId, context, issuedAt, expiresAt, challengeHash);
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
    const reaped = await dbQuery(REAP_ONE_SQL, [currentIso, new Date(Math.max(0, currentTime - CLAIM_LEASE_MS)).toISOString(), request.challenge_id, request.session_id, request.member_id, request.organization_id, request.operation, request.rp_id, request.origin, request.user_verification]);
    recordMetric(metrics, "recordHumanAuthStaleClaimRecovery", reaped.rows?.length ?? reaped.rowCount ?? 0);
    let record = await loadRecord(request.challenge_id);
    assertRecord(record, request.challenge_id);
    if (!sameBinding(record, request)) fail(WEBAUTHN_REGISTRATION_ERROR_CODES.BINDING_MISMATCH);
    if (record.status === "consuming") fail(WEBAUTHN_REGISTRATION_ERROR_CODES.CHALLENGE_BUSY);
    if (record.status === "consumed" || record.status === "failed") {
      recordMetric(metrics, "recordHumanAuthReplayDenial");
      fail(WEBAUTHN_REGISTRATION_ERROR_CODES.CHALLENGE_REPLAYED);
    }
    if (record.status === "expired" || currentTime >= record.expires_at) fail(WEBAUTHN_REGISTRATION_ERROR_CODES.CHALLENGE_EXPIRED);
    if (!constantTimeBufferEqual(record.challenge_hash, sha256Bytes(request.challenge))) fail(WEBAUTHN_REGISTRATION_ERROR_CODES.CHALLENGE_MISMATCH);

    const verifierInput = buildVerifierInput(record, request);
    const claimed = await dbQuery(CLAIM_SQL, [request.challenge_id, currentIso]);
    if (claimed.rows.length > 1) throw storageError("ERR_WEBAUTHN_REGISTRATION_STORAGE_RESULT", "registration challenge claim returned multiple rows");
    if (claimed.rows.length === 0) {
      record = await loadRecord(request.challenge_id);
      assertRecord(record, request.challenge_id);
      throwClaimState(record, currentTime);
    }
    assertClaimRow(claimed.rows[0], request.challenge_id, record);

    let verification;
    try {
      verification = validateVerifierResult(
        await withTimeout(
          () => verifyAttestation(verifierInput),
          Math.max(1, Math.min(verifierTimeoutMs, record.expires_at - currentTime))
        ),
        request
      );
    } catch (error) {
      if (error?.code === VERIFIER_TIMEOUT_CODE) recordMetric(metrics, "recordHumanAuthVerifierTimeout");
      await burn(request.challenge_id, new Date(assertClock(now())).toISOString());
      if (error instanceof WebAuthnRegistrationError && error.code === WEBAUTHN_REGISTRATION_ERROR_CODES.INVALID_VERIFIER_RESULT) throw error;
      fail(WEBAUTHN_REGISTRATION_ERROR_CODES.VERIFICATION_FAILED);
    }

    const authenticatedAt = assertClock(now());
    if (authenticatedAt >= record.expires_at) {
      await burn(request.challenge_id, new Date(authenticatedAt).toISOString());
      fail(WEBAUTHN_REGISTRATION_ERROR_CODES.CHALLENGE_EXPIRED);
    }
    let completed;
    try {
      completed = await dbQuery(COMPLETE_SQL, [request.challenge_id, new Date(authenticatedAt).toISOString()]);
      if (completed.rows.length !== 1) throw storageError("ERR_WEBAUTHN_REGISTRATION_CLAIM_LOST", "registration challenge could not be completed");
      assertTerminalRow(completed.rows[0], request.challenge_id, "consumed");
    } catch (error) {
      await burnBestEffort(request.challenge_id, new Date(authenticatedAt).toISOString());
      throw error;
    }
    return Object.freeze({
      verified: true,
      registration_id: request.challenge_id,
      session_id: record.session_id,
      member_id: record.member_id,
      organization_id: record.organization_id,
      operation: record.operation,
      authenticated_at: authenticatedAt,
      credential_id: verification.credential_id,
      public_key: Buffer.from(verification.public_key),
      sign_count: verification.sign_count,
      transports: verification.transports,
      ...(verification.credential_device_type === undefined ? {} : { credential_device_type: verification.credential_device_type }),
      ...(verification.credential_backed_up === undefined ? {} : { credential_backed_up: verification.credential_backed_up }),
      user_verified: true
    });
  }

  async function snapshot() {
    const result = await dbQuery(SNAPSHOT_SQL, []);
    return Object.freeze(result.rows.map((row) => {
      const record = normalizeRecord(row);
      return Object.freeze({
        registration_id: record.id,
        session_id: record.session_id,
        member_id: record.member_id,
        organization_id: record.organization_id,
        operation: record.operation,
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
    if (result.rows.length === 0) fail(WEBAUTHN_REGISTRATION_ERROR_CODES.CHALLENGE_NOT_FOUND);
    if (result.rows.length !== 1) throw storageError("ERR_WEBAUTHN_REGISTRATION_STORAGE_RESULT", "registration challenge lookup returned multiple rows");
    return normalizeRecord(result.rows[0]);
  }

  async function burn(id, timestamp) {
    const result = await dbQuery(BURN_SQL, [id, timestamp]);
    if (result.rows.length !== 1) throw storageError("ERR_WEBAUTHN_REGISTRATION_BURN_FAILED", "registration challenge could not be burned");
    assertTerminalRow(result.rows[0], id, "failed");
  }

  async function burnBestEffort(id, timestamp) {
    try {
      const result = await dbQuery(BURN_SQL, [id, timestamp]);
      if (result.rows.length === 1) assertTerminalRow(result.rows[0], id, "failed");
    } catch {
      // The original completion error is safer and more actionable for the
      // caller. A best-effort burn never turns it into a raw DB error.
    }
  }
}

// A short alias keeps the factory easy to discover alongside the authentication
// coordinator without changing the explicit registration name above.
export const createPostgresWebAuthnRegistrationCoordinator = createPostgresWebAuthnRegistrationCeremony;

async function query(client, sql, params, { mapConstraint = false } = {}) {
  let result;
  try {
    result = await client.query(sql, params);
  } catch (error) {
    if (mapConstraint && error?.code === "23505") fail(WEBAUTHN_REGISTRATION_ERROR_CODES.CHALLENGE_BUSY);
    throw storageError("ERR_WEBAUTHN_REGISTRATION_STORAGE", "WebAuthn registration PostgreSQL operation failed", error);
  }
  if (!result || !Array.isArray(result.rows) || !Number.isSafeInteger(result.rowCount) || result.rowCount !== result.rows.length || result.rowCount < 0) throw storageError("ERR_WEBAUTHN_REGISTRATION_STORAGE_RESULT", "WebAuthn registration PostgreSQL result is invalid");
  return result;
}

function assertClient(client) { if (!client || typeof client.query !== "function") throw new TypeError("database client is invalid"); }

async function acquireTransactionClient(client) {
  if (typeof client.connect !== "function") return Object.freeze({ client, release: async () => {} });
  let transactionClient;
  try { transactionClient = await client.connect(); } catch (error) { throw storageError("ERR_WEBAUTHN_REGISTRATION_CONNECTION", "WebAuthn registration PostgreSQL connection acquisition failed", error); }
  if (!transactionClient || typeof transactionClient.query !== "function") throw storageError("ERR_WEBAUTHN_REGISTRATION_CONNECTION", "WebAuthn registration PostgreSQL connection is invalid");
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
    try { await client.query("ROLLBACK"); } catch (rollbackError) { throw storageError("ERR_WEBAUTHN_REGISTRATION_TRANSACTION", "WebAuthn registration transaction rollback failed", rollbackError); }
    throw error;
  }
}

function normalizeContext(input) {
  if (!isObject(input)) fail(WEBAUTHN_REGISTRATION_ERROR_CODES.INVALID_CONTEXT);
  const session_id = requiredUuidContext(input.session_id ?? input.sessionId, "session_id");
  const member_id = requiredUuidContext(input.member_id ?? input.memberId, "member_id");
  const organization_id = requiredUuidContext(input.organization_id ?? input.organizationId, "organization_id");
  const operation = requiredOperation(input.operation);
  const rp_id = requiredRpId(input.rp_id ?? input.rpId);
  const origin = requiredOrigin(input.origin);
  if (!rpIdMatchesOrigin(rp_id, origin)) fail(WEBAUTHN_REGISTRATION_ERROR_CODES.INVALID_CONTEXT, "rp_id");
  if ((input.user_verification ?? input.userVerification ?? "required") !== "required") fail(WEBAUTHN_REGISTRATION_ERROR_CODES.INVALID_CONTEXT, "user_verification");
  return Object.freeze({ session_id, member_id, organization_id, operation, rp_id, origin, user_verification: "required" });
}

function normalizeConsumeInput(input) {
  if (!isObject(input)) fail(WEBAUTHN_REGISTRATION_ERROR_CODES.INVALID_REQUEST);
  const context = normalizeContext(input);
  const challenge_id = requiredUuidV4(input.challenge_id ?? input.challengeId, "challenge_id");
  const challenge = requiredBase64Url(input.challenge, CHALLENGE_BYTES, CHALLENGE_BYTES, "challenge");
  const credential_id = requiredBase64Url(input.credential_id ?? input.credentialId, 16, MAX_CREDENTIAL_ID_BYTES, "credential_id");
  const client_data_json = requiredBase64Url(input.client_data_json ?? input.clientDataJSON, 1, MAX_CLIENT_DATA_BYTES, "client_data_json");
  const attestation_object = requiredBase64Url(input.attestation_object ?? input.attestationObject, 1, MAX_ATTESTATION_OBJECT_BYTES, "attestation_object");
  const transports = input.transports === undefined ? undefined : normalizeTransports(input.transports);
  return Object.freeze({ ...context, challenge_id, challenge, credential_id, client_data_json, attestation_object, ...(transports === undefined ? {} : { transports }) });
}

function normalizeRecord(row) {
  if (!isObject(row)) throw storageError("ERR_WEBAUTHN_REGISTRATION_STORAGE_RESULT", "WebAuthn registration challenge row is invalid");
  const id = requiredUuidV4Storage(row.id, "id");
  const session_id = requiredUuidStorage(row.session_id, "session_id");
  const member_id = requiredUuidStorage(row.member_id, "member_id");
  const organization_id = requiredUuidStorage(row.organization_id, "organization_id");
  if (row.ceremony !== CEREMONY) throw storageError("ERR_WEBAUTHN_REGISTRATION_STORAGE_RESULT", "WebAuthn challenge ceremony is invalid");
  const operation = storageOperation(row.operation);
  const rp_id = storageRpId(row.rp_id);
  const origin = storageOrigin(row.origin);
  if (!rpIdMatchesOrigin(rp_id, origin)) throw storageError("ERR_WEBAUTHN_REGISTRATION_STORAGE_RESULT", "rp_id is not valid for origin");
  if (row.user_verification !== "required" || !STATUS.has(row.status)) throw storageError("ERR_WEBAUTHN_REGISTRATION_STORAGE_RESULT", "WebAuthn challenge binding or status is invalid");
  const created_at = storageTime(row.created_at, "created_at");
  const expires_at = storageTime(row.expires_at, "expires_at");
  if (expires_at <= created_at) throw storageError("ERR_WEBAUTHN_REGISTRATION_STORAGE_RESULT", "WebAuthn challenge expiry is invalid");
  const challenge_hash = storageDigest(row.challenge_hash_hex ?? row.challenge_hash, "challenge_hash");
  const consume_started_at = optionalStorageTime(row.consume_started_at, "consume_started_at");
  const consumed_at = optionalStorageTime(row.consumed_at, "consumed_at");
  const failed_at = optionalStorageTime(row.failed_at, "failed_at");
  if (row.status === "pending" && (consume_started_at !== undefined || consumed_at !== undefined || failed_at !== undefined)) throw storageError("ERR_WEBAUTHN_REGISTRATION_STORAGE_RESULT", "pending WebAuthn challenge has terminal timestamps");
  if (row.status === "consuming" && (consume_started_at === undefined || consumed_at !== undefined || failed_at !== undefined)) throw storageError("ERR_WEBAUTHN_REGISTRATION_STORAGE_RESULT", "consuming WebAuthn challenge timestamps are invalid");
  if (row.status === "consumed" && consumed_at === undefined) throw storageError("ERR_WEBAUTHN_REGISTRATION_STORAGE_RESULT", "consumed WebAuthn challenge has no consumed_at");
  if (row.status === "failed" && (failed_at === undefined || consumed_at === undefined || consume_started_at === undefined)) throw storageError("ERR_WEBAUTHN_REGISTRATION_STORAGE_RESULT", "failed WebAuthn challenge has no burn timestamps");
  return Object.freeze({ id, session_id, member_id, organization_id, ceremony: row.ceremony, operation, rp_id, origin, user_verification: "required", challenge_hash, created_at, expires_at, status: row.status, ...(consume_started_at === undefined ? {} : { consume_started_at }), ...(consumed_at === undefined ? {} : { consumed_at }), ...(failed_at === undefined ? {} : { failed_at }) });
}

function assertRecord(record, expectedId) { if (!record || record.id !== expectedId) throw storageError("ERR_WEBAUTHN_REGISTRATION_STORAGE_RESULT", "WebAuthn challenge row identity is invalid"); return record; }

function assertBeginRow(row, challengeId, context, issuedAt, expiresAt, challengeHash) {
  const record = normalizeRecord(row);
  if (record.id !== challengeId || record.session_id !== context.session_id || record.member_id !== context.member_id || record.organization_id !== context.organization_id || record.operation !== context.operation || record.rp_id !== context.rp_id || record.origin !== context.origin || record.user_verification !== "required" || record.status !== "pending" || record.created_at !== issuedAt || record.expires_at !== expiresAt || !constantTimeBufferEqual(record.challenge_hash, challengeHash)) throw storageError("ERR_WEBAUTHN_REGISTRATION_STORAGE_RESULT", "inserted WebAuthn challenge row does not match request");
}

function assertClaimRow(row, challengeId, previous) {
  const record = normalizeRecord(row);
  if (record.id !== challengeId || record.status !== "consuming" || record.session_id !== previous.session_id || record.member_id !== previous.member_id || record.organization_id !== previous.organization_id || record.operation !== previous.operation || record.rp_id !== previous.rp_id || record.origin !== previous.origin || !constantTimeBufferEqual(record.challenge_hash, previous.challenge_hash)) throw storageError("ERR_WEBAUTHN_REGISTRATION_STORAGE_RESULT", "claimed WebAuthn challenge row does not match lookup");
}

function assertTerminalRow(row, challengeId, status) {
  if (!isObject(row) || requiredUuidV4Storage(row.id, "id") !== challengeId || row.status !== status) throw storageError("ERR_WEBAUTHN_REGISTRATION_STORAGE_RESULT", "terminal WebAuthn challenge row is invalid");
  if (status === "consumed" && optionalStorageTime(row.consumed_at, "consumed_at") === undefined) throw storageError("ERR_WEBAUTHN_REGISTRATION_STORAGE_RESULT", "consumed WebAuthn challenge has no timestamp");
  if (status === "failed" && (optionalStorageTime(row.failed_at, "failed_at") === undefined || optionalStorageTime(row.consumed_at, "consumed_at") === undefined)) throw storageError("ERR_WEBAUTHN_REGISTRATION_STORAGE_RESULT", "failed WebAuthn challenge has no burn timestamp");
}

function throwClaimState(record, currentTime) {
  if (record.status === "consuming") fail(WEBAUTHN_REGISTRATION_ERROR_CODES.CHALLENGE_BUSY);
  if (record.status === "consumed" || record.status === "failed") fail(WEBAUTHN_REGISTRATION_ERROR_CODES.CHALLENGE_REPLAYED);
  if (record.status === "expired" || currentTime >= record.expires_at) fail(WEBAUTHN_REGISTRATION_ERROR_CODES.CHALLENGE_EXPIRED);
  throw storageError("ERR_WEBAUTHN_REGISTRATION_CLAIM_LOST", "WebAuthn registration challenge claim was lost");
}

function buildVerifierInput(record, request) {
  const clientData = decodeClientData(request.client_data_json, request.challenge, record.origin);
  return Object.freeze({
    ceremony: Object.freeze({ challenge_id: request.challenge_id, session_id: record.session_id, member_id: record.member_id, organization_id: record.organization_id, operation: record.operation, rp_id: record.rp_id, origin: record.origin, user_verification: record.user_verification, expected_challenge: request.challenge }),
    attestation: Object.freeze({ credential_id: request.credential_id, client_data_json: request.client_data_json, attestation_object: request.attestation_object, ...(request.transports === undefined ? {} : { transports: request.transports }) }),
    parsed: Object.freeze({ client_data: Object.freeze(clientData) })
  });
}

function decodeClientData(encoded, expectedChallenge, expectedOrigin) {
  const bytes = decodeBase64Url(encoded, 1, MAX_CLIENT_DATA_BYTES, WEBAUTHN_REGISTRATION_ERROR_CODES.INVALID_RESPONSE);
  const text = Buffer.from(bytes).toString("utf8");
  if (Buffer.from(text, "utf8").compare(bytes) !== 0) fail(WEBAUTHN_REGISTRATION_ERROR_CODES.INVALID_RESPONSE);
  let value;
  try { value = JSON.parse(text); } catch { fail(WEBAUTHN_REGISTRATION_ERROR_CODES.INVALID_RESPONSE); }
  if (!isObject(value) || value.type !== "webauthn.create" || value.challenge !== expectedChallenge || value.origin !== expectedOrigin || (value.crossOrigin !== undefined && value.crossOrigin !== false)) fail(WEBAUTHN_REGISTRATION_ERROR_CODES.INVALID_RESPONSE);
  if (value.tokenBinding !== undefined && (!isObject(value.tokenBinding) || typeof value.tokenBinding.status !== "string")) fail(WEBAUTHN_REGISTRATION_ERROR_CODES.INVALID_RESPONSE);
  return { type: value.type, challenge: value.challenge, origin: value.origin, ...(value.crossOrigin === undefined ? {} : { cross_origin: value.crossOrigin }) };
}

function validateVerifierResult(result, request) {
  const allowed = new Set(["verified", "credential_id", "public_key", "sign_count", "transports", "credential_device_type", "credential_backed_up", "user_verified"]);
  if (!isObject(result) || result.verified !== true || Object.keys(result).some((key) => !allowed.has(key))) fail(WEBAUTHN_REGISTRATION_ERROR_CODES.INVALID_VERIFIER_RESULT);
  const credential_id = requiredBase64Url(result.credential_id, 16, MAX_CREDENTIAL_ID_BYTES, "credential_id");
  if (!sameBase64Url(credential_id, request.credential_id)) fail(WEBAUTHN_REGISTRATION_ERROR_CODES.INVALID_VERIFIER_RESULT);
  const public_key = normalizePublicKey(result.public_key);
  if (result.user_verified !== true || !Number.isSafeInteger(result.sign_count) || result.sign_count < 0 || result.sign_count > 0xffffffff) fail(WEBAUTHN_REGISTRATION_ERROR_CODES.INVALID_VERIFIER_RESULT);
  const transports = result.transports === undefined ? request.transports : normalizeTransports(result.transports);
  if (result.credential_device_type !== undefined && !["singleDevice", "multiDevice"].includes(result.credential_device_type)) fail(WEBAUTHN_REGISTRATION_ERROR_CODES.INVALID_VERIFIER_RESULT);
  if (result.credential_backed_up !== undefined && typeof result.credential_backed_up !== "boolean") fail(WEBAUTHN_REGISTRATION_ERROR_CODES.INVALID_VERIFIER_RESULT);
  validateCredentialMetadata(result.credential_device_type, result.credential_backed_up);
  return Object.freeze({ credential_id, public_key, sign_count: result.sign_count, transports, ...(result.credential_device_type === undefined ? {} : { credential_device_type: result.credential_device_type }), ...(result.credential_backed_up === undefined ? {} : { credential_backed_up: result.credential_backed_up }) });
}

function normalizeTransports(value) { if (!Array.isArray(value) || value.length > 7 || value.some((item) => typeof item !== "string" || !TRANSPORTS.has(item)) || new Set(value).size !== value.length) fail(WEBAUTHN_REGISTRATION_ERROR_CODES.INVALID_REQUEST); return Object.freeze([...value]); }
function normalizePublicKey(value) { let bytes; if (Buffer.isBuffer(value) || value instanceof Uint8Array) bytes = Buffer.from(value); else if (typeof value === "string" && isBase64Url(value, 32, 4096)) bytes = Buffer.from(value, "base64url"); else fail(WEBAUTHN_REGISTRATION_ERROR_CODES.INVALID_VERIFIER_RESULT); if (bytes.length < 32 || bytes.length > 4096) fail(WEBAUTHN_REGISTRATION_ERROR_CODES.INVALID_VERIFIER_RESULT); return Buffer.from(bytes); }
function sameBinding(record, request) { return record.session_id === request.session_id && record.member_id === request.member_id && record.organization_id === request.organization_id && record.operation === request.operation && record.rp_id === request.rp_id && record.origin === request.origin && record.user_verification === request.user_verification; }
function sha256Bytes(value) { return crypto.createHash("sha256").update(value, "utf8").digest(); }
function constantTimeBufferEqual(left, right) { return Buffer.isBuffer(left) && Buffer.isBuffer(right) && left.length === right.length && crypto.timingSafeEqual(left, right); }
function sameBase64Url(left, right) { const a = Buffer.from(left, "base64url"); const b = Buffer.from(right, "base64url"); return a.length === b.length && crypto.timingSafeEqual(a, b); }
function isObject(value) { return value !== null && typeof value === "object" && !Array.isArray(value); }
function assertClock(value) { if (!Number.isSafeInteger(value) || value < 0) throw new TypeError("clock value is invalid"); return value; }
function assertDuration(value, field, minimum, maximum) { if (!Number.isSafeInteger(value) || value < minimum || value > maximum) throw new TypeError(`${field} is invalid`); return value; }
function requiredUuidV4(value, field) { if (typeof value !== "string" || !UUID_V4.test(value)) fail(WEBAUTHN_REGISTRATION_ERROR_CODES.INVALID_REQUEST, field); return value.toLowerCase(); }
function requiredUuidV4Storage(value, field) { if (typeof value !== "string" || !UUID_V4.test(value)) throw storageError("ERR_WEBAUTHN_REGISTRATION_STORAGE_RESULT", `${field} is invalid`); return value.toLowerCase(); }
function requiredUuidContext(value, field) { if (typeof value !== "string" || !UUID.test(value)) fail(WEBAUTHN_REGISTRATION_ERROR_CODES.INVALID_CONTEXT, field); return value.toLowerCase(); }
function requiredUuidStorage(value, field) { if (typeof value !== "string" || !UUID.test(value)) throw storageError("ERR_WEBAUTHN_REGISTRATION_STORAGE_RESULT", `${field} is invalid`); return value.toLowerCase(); }
function requiredOperation(value) { if (typeof value !== "string" || !OPERATION.test(value) || /[\u0000-\u001f\u007f]/.test(value)) fail(WEBAUTHN_REGISTRATION_ERROR_CODES.INVALID_CONTEXT, "operation"); return value; }
function storageOperation(value) { if (typeof value !== "string" || !OPERATION.test(value) || /[\u0000-\u001f\u007f]/.test(value)) throw storageError("ERR_WEBAUTHN_REGISTRATION_STORAGE_RESULT", "operation is invalid"); return value; }
function requiredRpId(value) { if (typeof value !== "string" || value.length < 1 || value.length > 253 || !RP_ID.test(value) || value.includes("..")) throw new TypeError("rpId is invalid"); return value.toLowerCase(); }
function storageRpId(value) { try { return requiredRpId(value); } catch { throw storageError("ERR_WEBAUTHN_REGISTRATION_STORAGE_RESULT", "rp_id is invalid"); } }
function requiredOrigin(value) { if (typeof value !== "string" || value.length > 512 || /[\u0000-\u001f\u007f]/.test(value)) throw new TypeError("origin is invalid"); let url; try { url = new URL(value); } catch { throw new TypeError("origin is invalid"); } if (!ORIGIN_SCHEMES.has(url.protocol) || url.username || url.password || url.pathname !== "/" || url.search || url.hash || (url.protocol === "http:" && !["localhost", "127.0.0.1", "[::1]"].includes(url.hostname)) || url.origin !== value) throw new TypeError("origin is invalid"); return url.origin; }
function storageOrigin(value) { try { return requiredOrigin(value); } catch { throw storageError("ERR_WEBAUTHN_REGISTRATION_STORAGE_RESULT", "origin is invalid"); } }
function rpIdMatchesOrigin(rpId, origin) { const host = new URL(origin).hostname.toLowerCase(); const normalizedHost = host.startsWith("[") && host.endsWith("]") ? host.slice(1, -1) : host; if (isIP(normalizedHost) !== 0 || isIP(rpId) !== 0) return normalizedHost === rpId; return normalizedHost === rpId || normalizedHost.endsWith(`.${rpId}`); }
function requiredBase64Url(value, min, max, field) { if (!isBase64Url(value, min, max)) fail(WEBAUTHN_REGISTRATION_ERROR_CODES.INVALID_REQUEST, field); return value; }
function isBase64Url(value, min, max) { if (typeof value !== "string" || !BASE64URL.test(value)) return false; let bytes; try { bytes = Buffer.from(value, "base64url"); } catch { return false; } return bytes.length >= min && bytes.length <= max && bytes.toString("base64url") === value; }
function decodeBase64Url(value, min, max, errorCode) { if (!isBase64Url(value, min, max)) fail(errorCode); return Buffer.from(value, "base64url"); }
function storageDigest(value, field) { let bytes; if (Buffer.isBuffer(value) || value instanceof Uint8Array) bytes = Buffer.from(value); else if (typeof value === "string" && /^[0-9a-f]{64}$/i.test(value)) bytes = Buffer.from(value, "hex"); else throw storageError("ERR_WEBAUTHN_REGISTRATION_STORAGE_RESULT", `${field} is invalid`); if (bytes.length !== 32) throw storageError("ERR_WEBAUTHN_REGISTRATION_STORAGE_RESULT", `${field} is invalid`); return bytes; }
function storageTime(value, field) { const time = value instanceof Date ? value.getTime() : typeof value === "string" || typeof value === "number" ? Date.parse(value) : NaN; if (!Number.isSafeInteger(time) || time < 0) throw storageError("ERR_WEBAUTHN_REGISTRATION_STORAGE_RESULT", `${field} is invalid`); return time; }
function optionalStorageTime(value, field) { if (value === null || value === undefined) return undefined; return storageTime(value, field); }
function parseCount(value) { const count = typeof value === "string" && /^\d+$/.test(value) ? Number(value) : value; if (!Number.isSafeInteger(count) || count < 0) throw storageError("ERR_WEBAUTHN_REGISTRATION_STORAGE_RESULT", "pending count is invalid"); return count; }
function fail(code, details = undefined) { throw new WebAuthnRegistrationError(code, details); }
function storageError(code, message, cause = undefined) { return new PostgresWebAuthnRegistrationCeremonyError(code, message, cause); }

function withTimeout(callback, timeoutMs) {
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => {
      const error = new Error("WebAuthn verifier timed out");
      error.code = VERIFIER_TIMEOUT_CODE;
      reject(error);
    }, timeoutMs);
    timer.unref?.();
  });
  return Promise.race([Promise.resolve().then(callback), timeout]).finally(() => clearTimeout(timer));
}

function recordMetric(metrics, method, amount = 1) {
  if (!Number.isSafeInteger(amount) || amount < 1) return;
  try { metrics?.[method]?.(amount); } catch { /* Metrics cannot affect auth. */ }
}

function validateCredentialMetadata(deviceType, backedUp) {
  if (deviceType === "singleDevice" && backedUp === true) fail(WEBAUTHN_REGISTRATION_ERROR_CODES.INVALID_VERIFIER_RESULT);
  if (backedUp === true && deviceType !== "multiDevice") fail(WEBAUTHN_REGISTRATION_ERROR_CODES.INVALID_VERIFIER_RESULT);
}
