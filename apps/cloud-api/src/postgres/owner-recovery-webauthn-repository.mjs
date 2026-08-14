import crypto from "node:crypto";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
const RP_ID = /^[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$/u;
const OPERATIONS = Object.freeze({
  registration: "human.recovery.credential.register",
  authentication: "human.recovery.activate"
});
const DEFAULT_TTL_MS = 2 * 60_000;
const DEFAULT_CLAIM_LEASE_MS = 15_000;

export class OwnerRecoveryWebAuthnRepositoryError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "OwnerRecoveryWebAuthnRepositoryError";
    this.code = code;
  }
}

/**
 * Durable coordinator for WebAuthn ceremonies owned by a restricted recovery
 * session. Verifier callbacks remain outside this repository; completion takes
 * a caller callback and commits its credential mutation with challenge
 * consumption in the same transaction.
 */
export function createPostgresOwnerRecoveryWebAuthnRepository({
  client,
  now = () => Date.now(),
  randomUUID = crypto.randomUUID,
  randomBytes = crypto.randomBytes,
  ttlMs = DEFAULT_TTL_MS,
  claimLeaseMs = DEFAULT_CLAIM_LEASE_MS
} = {}) {
  if (!client || typeof client.query !== "function") throw new TypeError("PostgreSQL client is required");
  if (typeof now !== "function" || typeof randomUUID !== "function" || typeof randomBytes !== "function") throw new TypeError("recovery WebAuthn dependencies are invalid");
  if (!Number.isSafeInteger(ttlMs) || ttlMs < 30_000 || ttlMs > 5 * 60_000) throw new TypeError("ttlMs is invalid");
  if (!Number.isSafeInteger(claimLeaseMs) || claimLeaseMs < 1_000 || claimLeaseMs >= ttlMs) throw new TypeError("claimLeaseMs is invalid");

  async function begin(input = {}) {
    const values = normalizeBegin(input);
    const issuedAt = clock(now);
    const expiresAt = issuedAt + ttlMs;
    const challengeId = uuid(randomUUID(), "challenge_id");
    const challengeBytes = Buffer.from(randomBytes(32));
    if (challengeBytes.length !== 32) throw inputError("challenge entropy is invalid");
    const challenge = challengeBytes.toString("base64url");
    const digest = sha256(challengeBytes);
    return transaction(client, async (tx) => {
      await lockRecoverySession(tx, values);
      await expireDue(tx, values, issuedAt);
      const session = await tx.query(`SELECT s.stage,s.credential_id,r.state
        FROM owner_recovery_sessions s
        JOIN owner_recovery_requests r
          ON r.organization_id=s.organization_id AND r.request_id=s.request_id
        WHERE s.organization_id=$1 AND s.recovery_session_id=$2
          AND s.request_id=$3 AND s.member_id=$4
          AND s.stage=$5 AND r.state=$6
          AND s.expires_at>$7 AND s.idle_expires_at>$7
        FOR UPDATE OF s,r`, [values.organizationId, values.recoverySessionId, values.requestId, values.memberId, expectedSessionStage(values.ceremony), expectedRequestState(values.ceremony), iso(issuedAt)]);
      if (rowCount(session) !== 1) throw unavailable("recovery WebAuthn session is not eligible");
      if (values.ceremony === "authentication") {
        const enrolled = optionalBytes(session.rows[0].credential_id);
        if (!enrolled || !values.credentialId || !constantEqual(enrolled, values.credentialId)) throw unavailable("recovery credential binding is unavailable");
      }
      const inserted = await tx.query(`INSERT INTO owner_recovery_webauthn_challenges
        (organization_id,challenge_id,recovery_session_id,request_id,member_id,
         ceremony,operation,challenge_digest,rp_id,origin,user_verification,
         status,created_at,expires_at)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'required','pending',$11,$12)
        RETURNING challenge_id`, [values.organizationId, challengeId, values.recoverySessionId, values.requestId, values.memberId, values.ceremony, values.operation, digest, values.rpId, values.origin, iso(issuedAt), iso(expiresAt)]);
      if (rowCount(inserted) !== 1 || uuid(inserted.rows[0]?.challenge_id, "challenge_id") !== challengeId) throw malformed("recovery challenge insert was not confirmed");
      return Object.freeze({ challenge_id: challengeId, challenge, expires_at: iso(expiresAt), ceremony: values.ceremony, operation: values.operation, rp_id: values.rpId, origin: values.origin, user_verification: "required" });
    });
  }

  async function claim(input = {}) {
    const values = normalizeClaim(input);
    const claimedAt = clock(now);
    return transaction(client, async (tx) => {
      await lockRecoverySession(tx, values);
      await tx.query(`UPDATE owner_recovery_webauthn_challenges
        SET status='pending',consume_started_at=NULL
        WHERE organization_id=$1 AND challenge_id=$2 AND recovery_session_id=$3
          AND status='consuming' AND consume_started_at<=$4`, [values.organizationId, values.challengeId, values.recoverySessionId, iso(claimedAt - claimLeaseMs)]);
      await expireDue(tx, values, claimedAt);
      const result = await tx.query(`SELECT organization_id,challenge_id,recovery_session_id,request_id,member_id,
          ceremony,operation,challenge_digest,rp_id,origin,user_verification,status,
          created_at,expires_at,consume_started_at,consumed_at,failed_at,
          verified_credential_id,authorization_consumed_at
        FROM owner_recovery_webauthn_challenges
        WHERE organization_id=$1 AND challenge_id=$2
        FOR UPDATE`, [values.organizationId, values.challengeId]);
      if (rowCount(result) !== 1) throw notFound();
      const row = normalizeRow(result.rows[0]);
      assertClaimBinding(row, values);
      if (!constantEqual(row.challengeDigest, sha256(values.challengeBytes))) throw denied("recovery challenge did not match");
      if (row.status === "consumed") {
        if (!row.verifiedCredentialId || !constantEqual(row.verifiedCredentialId, values.credentialId)) throw replay();
        return Object.freeze({ already_consumed: true, challenge_id: row.challengeId, credential_id: row.verifiedCredentialId.toString("base64url"), consumed_at: row.consumedAt, ceremony: row.ceremony, operation: row.operation });
      }
      if (row.status === "consuming") throw busy();
      if (row.status === "failed") throw replay();
      if (row.status === "expired" || claimedAt >= row.expiresAt) throw expired();
      const updated = await tx.query(`UPDATE owner_recovery_webauthn_challenges
        SET status='consuming',consume_started_at=$5
        WHERE organization_id=$1 AND challenge_id=$2 AND recovery_session_id=$3
          AND status='pending' AND expires_at>$4
        RETURNING consume_started_at`, [values.organizationId, values.challengeId, values.recoverySessionId, iso(claimedAt), iso(claimedAt)]);
      if (rowCount(updated) !== 1) throw busy();
      return Object.freeze({
        already_consumed: false,
        organization_id: row.organizationId,
        challenge_id: row.challengeId,
        recovery_session_id: row.recoverySessionId,
        request_id: row.requestId,
        member_id: row.memberId,
        ceremony: row.ceremony,
        operation: row.operation,
        rp_id: row.rpId,
        origin: row.origin,
        user_verification: "required",
        expected_challenge: values.challenge,
        credential_id: values.credentialId.toString("base64url"),
        claim_started_at: iso(claimedAt),
        expires_at: iso(row.expiresAt)
      });
    });
  }

  async function complete(input = {}) {
    const values = normalizeCompletion(input);
    const completedAt = clock(now);
    return transaction(client, async (tx) => {
      await lockRecoverySession(tx, values);
      const row = await tx.query(`SELECT status,expires_at,consume_started_at
        FROM owner_recovery_webauthn_challenges
        WHERE organization_id=$1 AND challenge_id=$2 AND recovery_session_id=$3
          AND request_id=$4 AND member_id=$5 AND ceremony=$6 AND operation=$7
        FOR UPDATE`, [values.organizationId, values.challengeId, values.recoverySessionId, values.requestId, values.memberId, values.ceremony, values.operation]);
      if (rowCount(row) !== 1) throw notFound();
      if (row.rows[0].status !== "consuming" || isoMillis(row.rows[0].consume_started_at) !== values.claimStartedAt) throw replay();
      if (completedAt >= isoMillis(row.rows[0].expires_at)) throw expired();
      const mutationResult = await values.mutate(tx, Object.freeze({
        organization_id: values.organizationId,
        request_id: values.requestId,
        recovery_session_id: values.recoverySessionId,
        member_id: values.memberId,
        credential_id: values.credentialId.toString("base64url"),
        challenge_id: values.challengeId,
        completed_at: iso(completedAt)
      }));
      if (!mutationResult || mutationResult.committed !== true) throw unavailable("recovery credential mutation was not confirmed");
      const updated = await tx.query(`UPDATE owner_recovery_webauthn_challenges
        SET status='consumed',consumed_at=$8,verified_credential_id=$9,
            authorization_consumed_at=CASE WHEN ceremony='authentication' THEN $8 ELSE NULL END
        WHERE organization_id=$1 AND challenge_id=$2 AND recovery_session_id=$3
          AND request_id=$4 AND member_id=$5 AND ceremony=$6 AND operation=$7
          AND status='consuming' AND consume_started_at=$10
        RETURNING consumed_at`, [values.organizationId, values.challengeId, values.recoverySessionId, values.requestId, values.memberId, values.ceremony, values.operation, iso(completedAt), values.credentialId, iso(values.claimStartedAt)]);
      if (rowCount(updated) !== 1) throw replay();
      return Object.freeze({ committed: true, challenge_id: values.challengeId, credential_id: values.credentialId.toString("base64url"), consumed_at: isoMillisString(updated.rows[0].consumed_at), mutation: mutationResult });
    });
  }

  async function burn(input = {}) {
    const organizationId = uuid(input.organization_id ?? input.organizationId, "organization_id");
    const challengeId = uuid(input.challenge_id ?? input.challengeId, "challenge_id");
    const claimStartedAt = timestamp(input.claim_started_at ?? input.claimStartedAt, "claim_started_at");
    const failedAt = clock(now);
    const result = await client.query(`UPDATE owner_recovery_webauthn_challenges
      SET status='failed',consumed_at=$3,failed_at=$3
      WHERE organization_id=$1 AND challenge_id=$2 AND status='consuming'
        AND consume_started_at=$4
      RETURNING challenge_id`, [organizationId, challengeId, iso(failedAt), iso(claimStartedAt)]);
    return rowCount(result) === 1;
  }

  return Object.freeze({ begin, claim, complete, burn, ttlMs, claimLeaseMs });
}

async function transaction(client, callback) {
  const tx = typeof client.connect === "function" ? await client.connect() : client;
  try {
    await tx.query("BEGIN");
    const result = await callback(tx);
    await tx.query("COMMIT");
    return result;
  } catch (error) {
    try { await tx.query("ROLLBACK"); } catch { /* Preserve the original stable error. */ }
    if (error instanceof OwnerRecoveryWebAuthnRepositoryError) throw error;
    throw unavailable("recovery WebAuthn storage is unavailable");
  } finally {
    if (tx !== client) tx.release?.();
  }
}

async function lockRecoverySession(tx, values) {
  await tx.query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))", [`agentpass:owner-recovery:${values.organizationId}:${values.recoverySessionId}`]);
}

async function expireDue(tx, values, nowMs) {
  await tx.query(`UPDATE owner_recovery_webauthn_challenges
    SET status='expired'
    WHERE organization_id=$1 AND recovery_session_id=$2
      AND status IN ('pending','consuming') AND expires_at<=$3`, [values.organizationId, values.recoverySessionId, iso(nowMs)]);
}

function normalizeBegin(input) {
  const ceremony = enumValue(input.ceremony, new Set(Object.keys(OPERATIONS)), "ceremony");
  const operation = input.operation ?? OPERATIONS[ceremony];
  if (operation !== OPERATIONS[ceremony]) throw inputError("recovery operation is invalid");
  return Object.freeze({
    organizationId: uuid(input.organization_id ?? input.organizationId, "organization_id"),
    recoverySessionId: uuid(input.recovery_session_id ?? input.recoverySessionId, "recovery_session_id"),
    requestId: uuid(input.request_id ?? input.requestId, "request_id"),
    memberId: uuid(input.member_id ?? input.memberId, "member_id"),
    ceremony,
    operation,
    rpId: rpId(input.rp_id ?? input.rpId),
    origin: origin(input.origin),
    credentialId: optionalCredential(input.credential_id ?? input.credentialId)
  });
}

function normalizeClaim(input) {
  const begin = normalizeBegin(input);
  const challengeId = uuid(input.challenge_id ?? input.challengeId, "challenge_id");
  const challenge = base64url(input.challenge, 32, 32, "challenge");
  const credentialId = credential(input.credential_id ?? input.credentialId);
  return Object.freeze({ ...begin, challengeId, challenge, challengeBytes: Buffer.from(challenge, "base64url"), credentialId });
}

function normalizeCompletion(input) {
  const begin = normalizeBegin(input);
  const challengeId = uuid(input.challenge_id ?? input.challengeId, "challenge_id");
  const credentialId = credential(input.credential_id ?? input.credentialId);
  const claimStartedAt = timestamp(input.claim_started_at ?? input.claimStartedAt, "claim_started_at");
  if (typeof input.mutate !== "function") throw inputError("transactional recovery mutation is required");
  return Object.freeze({ ...begin, challengeId, credentialId, claimStartedAt, mutate: input.mutate });
}

function normalizeRow(row) {
  if (!row || typeof row !== "object") throw malformed("recovery challenge row is malformed");
  return Object.freeze({
    organizationId: uuid(row.organization_id, "organization_id"),
    challengeId: uuid(row.challenge_id, "challenge_id"),
    recoverySessionId: uuid(row.recovery_session_id, "recovery_session_id"),
    requestId: uuid(row.request_id, "request_id"),
    memberId: uuid(row.member_id, "member_id"),
    ceremony: enumValue(row.ceremony, new Set(Object.keys(OPERATIONS)), "ceremony"),
    operation: String(row.operation),
    challengeDigest: bytes(row.challenge_digest, 32, 32, "challenge_digest"),
    rpId: rpId(row.rp_id), origin: origin(row.origin),
    status: enumValue(row.status, new Set(["pending", "consuming", "consumed", "failed", "expired"]), "status"),
    createdAt: isoMillis(row.created_at), expiresAt: isoMillis(row.expires_at),
    consumedAt: row.consumed_at == null ? undefined : isoMillisString(row.consumed_at),
    verifiedCredentialId: optionalBytes(row.verified_credential_id)
  });
}

function assertClaimBinding(row, values) {
  if (row.recoverySessionId !== values.recoverySessionId || row.requestId !== values.requestId || row.memberId !== values.memberId || row.ceremony !== values.ceremony || row.operation !== values.operation || row.rpId !== values.rpId || row.origin !== values.origin) throw denied("recovery challenge binding did not match");
}

function expectedSessionStage(ceremony) { return ceremony === "registration" ? "session_issued" : "credential_enrolled"; }
function expectedRequestState(ceremony) { return ceremony === "registration" ? "session_issued" : "credential_enrolled"; }
function rowCount(result) { return Number.isSafeInteger(result?.rowCount) ? result.rowCount : Array.isArray(result?.rows) ? result.rows.length : 0; }
function clock(now) { const value = now(); if (!Number.isSafeInteger(value) || value < 0) throw inputError("clock is invalid"); return value; }
function iso(value) { return new Date(value).toISOString(); }
function isoMillis(value) { const number = Date.parse(value instanceof Date ? value.toISOString() : String(value)); if (!Number.isSafeInteger(number)) throw malformed("timestamp is malformed"); return number; }
function isoMillisString(value) { return iso(isoMillis(value)); }
function sha256(value) { return crypto.createHash("sha256").update(value).digest(); }
function constantEqual(left, right) { return Buffer.isBuffer(left) && Buffer.isBuffer(right) && left.length === right.length && crypto.timingSafeEqual(left, right); }
function uuid(value, label) { if (typeof value !== "string" || !UUID.test(value)) throw inputError(`${label} is invalid`); return value.toLowerCase(); }
function rpId(value) { if (typeof value !== "string" || !RP_ID.test(value) || value.length > 253) throw inputError("rp_id is invalid"); return value.toLowerCase(); }
function origin(value) { let parsed; try { parsed = new URL(value); } catch { throw inputError("origin is invalid"); } if (parsed.protocol !== "https:" || parsed.origin !== value || parsed.username || parsed.password || parsed.pathname !== "/") throw inputError("origin is invalid"); return value; }
function enumValue(value, allowed, label) { if (typeof value !== "string" || !allowed.has(value)) throw inputError(`${label} is invalid`); return value; }
function timestamp(value, label) { const number = Date.parse(value); if (!Number.isSafeInteger(number)) throw inputError(`${label} is invalid`); return number; }
function base64url(value, min, max, label) { if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/u.test(value)) throw inputError(`${label} is invalid`); const decoded = Buffer.from(value, "base64url"); if (decoded.length < min || decoded.length > max || decoded.toString("base64url") !== value) throw inputError(`${label} is invalid`); return value; }
function bytes(value, min, max, label) { const result = Buffer.isBuffer(value) ? Buffer.from(value) : value instanceof Uint8Array ? Buffer.from(value) : null; if (!result || result.length < min || result.length > max) throw malformed(`${label} is malformed`); return result; }
function optionalBytes(value) { if (value == null) return undefined; return bytes(value, 16, 1024, "credential_id"); }
function credential(value) { return Buffer.from(base64url(value, 16, 1024, "credential_id"), "base64url"); }
function optionalCredential(value) { return value === undefined ? undefined : credential(value); }
function inputError(message) { return new OwnerRecoveryWebAuthnRepositoryError("owner_recovery_webauthn_invalid_input", message); }
function unavailable(message) { return new OwnerRecoveryWebAuthnRepositoryError("owner_recovery_webauthn_unavailable", message); }
function malformed(message) { return new OwnerRecoveryWebAuthnRepositoryError("owner_recovery_webauthn_storage_invalid", message); }
function denied(message) { return new OwnerRecoveryWebAuthnRepositoryError("owner_recovery_webauthn_denied", message); }
function notFound() { return new OwnerRecoveryWebAuthnRepositoryError("owner_recovery_webauthn_not_found", "recovery challenge was not found"); }
function replay() { return new OwnerRecoveryWebAuthnRepositoryError("owner_recovery_webauthn_replayed", "recovery challenge cannot be reused"); }
function busy() { return new OwnerRecoveryWebAuthnRepositoryError("owner_recovery_webauthn_busy", "recovery challenge is already being verified"); }
function expired() { return new OwnerRecoveryWebAuthnRepositoryError("owner_recovery_webauthn_expired", "recovery challenge expired"); }

export const OWNER_RECOVERY_WEBAUTHN_OPERATIONS = OPERATIONS;
