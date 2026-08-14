import crypto from "node:crypto";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
const TOKEN = /^[A-Za-z0-9_-]{43}$/u;
const ERROR_CODE = /^[a-z][a-z0-9_]{0,127}$/u;
const EVENT_TYPE = /^recovery\.[a-z]+(?:\.[a-z]+)*$/u;
const DEFAULT_LEASE_MS = 30_000;
const MAX_LEASE_MS = 5 * 60_000;
const MAX_BATCH = 100;
const MAX_ATTEMPTS = 100;
const MAX_RETRY_MS = 24 * 60 * 60 * 1000;

export const OWNER_RECOVERY_OUTBOX_ERROR_CODES = Object.freeze({
  INVALID_REQUEST: "owner_recovery_outbox_invalid_request",
  CLAIM_LOST: "owner_recovery_outbox_claim_lost",
  UNAVAILABLE: "owner_recovery_outbox_unavailable"
});

const MESSAGES = Object.freeze({
  [OWNER_RECOVERY_OUTBOX_ERROR_CODES.INVALID_REQUEST]: "Owner recovery outbox request is invalid",
  [OWNER_RECOVERY_OUTBOX_ERROR_CODES.CLAIM_LOST]: "Owner recovery outbox claim is no longer valid",
  [OWNER_RECOVERY_OUTBOX_ERROR_CODES.UNAVAILABLE]: "Owner recovery outbox storage is unavailable"
});

export class OwnerRecoveryOutboxRepositoryError extends Error {
  constructor(code) {
    super(MESSAGES[code] ?? MESSAGES[OWNER_RECOVERY_OUTBOX_ERROR_CODES.UNAVAILABLE]);
    this.name = "OwnerRecoveryOutboxRepositoryError";
    this.code = MESSAGES[code] === undefined ? OWNER_RECOVERY_OUTBOX_ERROR_CODES.UNAVAILABLE : code;
  }
}

export function createPostgresOwnerRecoveryOutboxRepository({ client, randomBytes = crypto.randomBytes, now = () => Date.now() } = {}) {
  assertClient(client);
  if (typeof randomBytes !== "function" || typeof now !== "function") throw new TypeError("outbox clock and randomness sources are invalid");

  async function claimBatch({ limit = 10, lease_ms = DEFAULT_LEASE_MS } = {}) {
    const boundedLimit = integer(limit, 1, MAX_BATCH);
    const leaseMs = integer(lease_ms, 1_000, MAX_LEASE_MS);
    const claimToken = token(randomBytes);
    const claimDigest = sha256(claimToken);
    try {
      const result = await client.query(`WITH candidates AS (
          SELECT organization_id,event_id
          FROM owner_recovery_outbox
          WHERE status='pending' AND attempts<=$1
            AND available_at<=clock_timestamp()
            AND (claim_expires_at IS NULL OR claim_expires_at<=clock_timestamp())
          ORDER BY available_at ASC,created_at ASC,organization_id ASC,event_id ASC
          FOR UPDATE SKIP LOCKED
          LIMIT $2
        )
        UPDATE owner_recovery_outbox outbox
        SET attempts=LEAST(outbox.attempts+1,$1),
            claim_token_digest=$3,
            claim_expires_at=clock_timestamp()+($4 * interval '1 millisecond'),
            available_at=clock_timestamp()+($4 * interval '1 millisecond'),
            updated_at=clock_timestamp()
        FROM candidates
        WHERE outbox.organization_id=candidates.organization_id
          AND outbox.event_id=candidates.event_id
        RETURNING outbox.organization_id,outbox.event_id,outbox.request_id,
          outbox.subject_member_id,outbox.event_type,outbox.attempts,
          outbox.claim_expires_at,outbox.created_at`, [MAX_ATTEMPTS, boundedLimit, claimDigest, leaseMs]);
      const events = Object.freeze((result?.rows ?? []).map(publicClaim));
      return Object.freeze({ claim_token: claimToken, events });
    } catch (error) {
      if (error instanceof OwnerRecoveryOutboxRepositoryError) throw error;
      throw unavailable();
    }
  }

  async function markPublished(input = {}) {
    const value = normalizeClaimMutation(input);
    try {
      const result = await client.query(`UPDATE owner_recovery_outbox
        SET status='published',published_at=clock_timestamp(),updated_at=clock_timestamp(),
            claim_token_digest=NULL,claim_expires_at=NULL,last_error_code=NULL
        WHERE organization_id=$1 AND event_id=$2 AND status='pending'
          AND attempts=$3 AND claim_token_digest=$4
        RETURNING published_at`, [value.organizationId, value.eventId, value.attempt, value.claimDigest]);
      if (rowCount(result) !== 1) throw claimLost();
      return Object.freeze({ published: true, published_at: timestamp(result.rows[0].published_at) });
    } catch (error) {
      if (error instanceof OwnerRecoveryOutboxRepositoryError) throw error;
      throw unavailable();
    }
  }

  async function markFailed(input = {}) {
    const value = normalizeClaimMutation(input);
    const errorCode = stableErrorCode(input.error_code);
    const retryAt = value.attempt >= MAX_ATTEMPTS ? null : retryTimestamp(input.retry_at, now);
    try {
      const result = await client.query(`UPDATE owner_recovery_outbox
        SET status=CASE WHEN attempts=$5 THEN 'dead_letter' ELSE 'pending' END,
            available_at=CASE WHEN attempts=$5 THEN clock_timestamp() ELSE $6::timestamptz END,
            updated_at=clock_timestamp(),claim_token_digest=NULL,claim_expires_at=NULL,
            last_error_code=$7
        WHERE organization_id=$1 AND event_id=$2 AND status='pending'
          AND attempts=$3 AND claim_token_digest=$4
        RETURNING status,available_at`, [value.organizationId, value.eventId, value.attempt, value.claimDigest, MAX_ATTEMPTS, retryAt, errorCode]);
      if (rowCount(result) !== 1) throw claimLost();
      const status = result.rows[0].status;
      if (status !== "pending" && status !== "dead_letter") throw unavailable();
      return Object.freeze({ dead_letter: status === "dead_letter", retry_at: status === "pending" ? timestamp(result.rows[0].available_at) : null });
    } catch (error) {
      if (error instanceof OwnerRecoveryOutboxRepositoryError) throw error;
      throw unavailable();
    }
  }

  async function health() {
    try {
      const result = await client.query(`SELECT
          count(*) FILTER (WHERE status='pending')::text AS pending,
          count(*) FILTER (WHERE status='dead_letter')::text AS dead_letter,
          min(created_at) FILTER (WHERE status='pending') AS oldest_pending_at
        FROM owner_recovery_outbox`, []);
      if (rowCount(result) !== 1) throw unavailable();
      return Object.freeze({
        pending: count(result.rows[0].pending),
        dead_letter: count(result.rows[0].dead_letter),
        oldest_pending_at: result.rows[0].oldest_pending_at == null ? null : timestamp(result.rows[0].oldest_pending_at)
      });
    } catch (error) {
      if (error instanceof OwnerRecoveryOutboxRepositoryError) throw error;
      throw unavailable();
    }
  }

  return Object.freeze({ claimBatch, markPublished, markFailed, health });
}

function normalizeClaimMutation(input) {
  if (!input || typeof input !== "object" || Array.isArray(input) || Object.getPrototypeOf(input) !== Object.prototype) throw invalid();
  const allowed = new Set(["organization_id", "event_id", "attempt", "claim_token", "error_code", "retry_at"]);
  if (Object.keys(input).some((key) => !allowed.has(key))) throw invalid();
  return Object.freeze({
    organizationId: uuid(input.organization_id),
    eventId: uuid(input.event_id),
    attempt: integer(input.attempt, 1, MAX_ATTEMPTS),
    claimDigest: claimTokenDigest(input.claim_token)
  });
}

function publicClaim(row) {
  const eventType = String(row?.event_type ?? "");
  if (!EVENT_TYPE.test(eventType)) throw unavailable();
  return Object.freeze({
    organization_id: uuid(row.organization_id),
    event_id: uuid(row.event_id),
    request_id: uuid(row.request_id),
    subject_member_id: uuid(row.subject_member_id),
    event_type: eventType,
    attempt: integer(Number(row.attempts), 1, MAX_ATTEMPTS),
    claim_expires_at: timestamp(row.claim_expires_at),
    created_at: timestamp(row.created_at)
  });
}

function token(randomBytes) {
  let bytes;
  try { bytes = randomBytes(32); } catch { throw unavailable(); }
  if (!(Buffer.isBuffer(bytes) || bytes instanceof Uint8Array) || bytes.length !== 32) throw unavailable();
  return Buffer.from(bytes).toString("base64url");
}
function claimTokenDigest(value) { if (typeof value !== "string" || !TOKEN.test(value)) throw invalid(); return sha256(value); }
function sha256(value) { return crypto.createHash("sha256").update(value, "utf8").digest(); }
function stableErrorCode(value) { if (typeof value !== "string" || !ERROR_CODE.test(value)) throw invalid(); return value; }
function retryTimestamp(value, now) { const date = new Date(value); const current = Number(now()); if (!Number.isFinite(date.getTime()) || !Number.isSafeInteger(current) || current < 0 || date.getTime() <= current || date.getTime() > current + MAX_RETRY_MS) throw invalid(); return date.toISOString(); }
function timestamp(value) { const date = value instanceof Date ? value : new Date(value); if (!Number.isFinite(date.getTime())) throw unavailable(); return date.toISOString(); }
function uuid(value) { if (typeof value !== "string" || !UUID.test(value)) throw invalid(); return value.toLowerCase(); }
function integer(value, min, max) { if (!Number.isSafeInteger(value) || value < min || value > max) throw invalid(); return value; }
function count(value) { const number = Number(value); if (!Number.isSafeInteger(number) || number < 0) throw unavailable(); return number; }
function rowCount(result) { return Number(result?.rowCount ?? result?.rows?.length ?? 0); }
function invalid() { return new OwnerRecoveryOutboxRepositoryError(OWNER_RECOVERY_OUTBOX_ERROR_CODES.INVALID_REQUEST); }
function claimLost() { return new OwnerRecoveryOutboxRepositoryError(OWNER_RECOVERY_OUTBOX_ERROR_CODES.CLAIM_LOST); }
function unavailable() { return new OwnerRecoveryOutboxRepositoryError(OWNER_RECOVERY_OUTBOX_ERROR_CODES.UNAVAILABLE); }
function assertClient(client) { if (!client || typeof client.query !== "function") throw new TypeError("database client must provide query(text, params)"); }

export default createPostgresOwnerRecoveryOutboxRepository;
