import crypto from "node:crypto";

import { canonicalJson, normalizeScope } from "../../../../packages/protocol/src/index.mjs";
import {
  AGENT_SIGNING_CAPABILITY_ALGORITHM,
  AGENT_SIGNING_CAPABILITY_ISSUER,
  AGENT_SIGNING_CAPABILITY_MAX_SIGNATURES,
  AGENT_SIGNING_CAPABILITY_OPERATION,
  AGENT_SIGNING_CAPABILITY_TYPE,
  AGENT_SIGNING_CAPABILITY_VERSION,
  agentSigningCapabilityStatementHash,
  normalizeAgentSigningCapabilityStatement
} from "../agent-signing-capability.mjs";
import { withTransaction } from "./repository.mjs";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
const CLAIM_TOKEN = /^[A-Za-z0-9_-]{43}$/u;
const SIGNATURE = /^[A-Za-z0-9_-]{86}$/u;
const DIGEST_HEX = /^[0-9a-f]{64}$/u;
const TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u;
const RESERVE_REQUEST_KEYS = Object.freeze(["request_id", "operation", "key_purpose", "one_use", "max_signatures", "ttl_ms"]);
const COMMIT_REQUEST_KEYS = Object.freeze(["request_id", "claim_token", "capability", "capability_hash", "remaining_session_signatures"]);
const UNCERTAIN_REQUEST_KEYS = Object.freeze(["request_id", "claim_token", "reason"]);
const REQUEST_KEYS = Object.freeze(["request_id"]);
const UNCERTAINTY_REASONS = new Set(["signer_failure", "signer_output_invalid", "commit_failure", "commit_response_lost"]);
const MAX_TTL_MS = 15 * 60 * 1000;

/**
 * F2b SQL boundary.
 *
 * These four functions are the only database mutation/read boundary used by
 * this adapter. They are SECURITY DEFINER functions owned by the migration
 * layer; the application role has EXECUTE but no table DML. Every function
 * receives the complete pre-bound tenant/session audience, so a request body
 * can never select another organization's row.
 *
 * Function result is one jsonb value in column `result`:
 *
 * reserve({state:"reserved", claim_issued:true, ...reservation})
 *   | {state:"committed", capability, remaining_session_signatures}
 *   | {state:"outcome_unknown"|"in_progress"|"conflict"|"absent"}
 * commit({state:"completed", capability, remaining_session_signatures})
 *   | {state:"outcome_unknown"|"in_progress"|"conflict"|"absent"}
 * replay({state:"completed", capability, remaining_session_signatures})
 *   | {state:"reserved"|"outcome_unknown"|"absent"}
 * uncertain({state:"outcome_unknown"})
 *   | {state:"completed", capability, remaining_session_signatures}
 *
 * `reserve` derives the active purpose-separated signer key and all statement
 * authority from locked Session/Grant/Device/Agent rows. The request digest is
 * only the canonical external `{request_id}` identity; server policy changes
 * cannot turn an exact retry into a different request.
 *
 * Reserve fixes the exact statement hash, signing bytes, Managed Signer
 * canonical request digest, byte length, and deterministic provider operation
 * ID before the signer runs. Commit accepts only durable request/claim digests;
 * PostgreSQL loads the fixed provider operation and constructs the public
 * Capability itself. The ledger stores the short-lived public envelope only so
 * replay is byte-identical, and scrubs it at expiry.
 */
export const AGENT_SESSION_SIGNING_CAPABILITY_RESERVATION_SQL = Object.freeze({
  reserve: `SELECT public.agentpass_agent_signing_capability_reserve(
    $1::uuid,$2::uuid,$3::uuid,$4::uuid,$5::bytea,$6::uuid,$7::uuid,
    $8::bytea,$9::text,$10::text,$11::boolean,$12::integer,$13::bigint
  ) AS result`,
  commit: `SELECT public.agentpass_agent_signing_capability_commit(
    $1::uuid,$2::uuid,$3::uuid,$4::uuid,$5::bytea,$6::bytea
  ) AS result`,
  replay: `SELECT public.agentpass_agent_signing_capability_replay(
    $1::uuid,$2::uuid,$3::uuid,$4::uuid,$5::bytea
  ) AS result`,
  uncertain: `SELECT public.agentpass_agent_signing_capability_uncertain(
    $1::uuid,$2::uuid,$3::uuid,$4::uuid,$5::bytea,$6::bytea,$7::text
  ) AS result`
});

export const AGENT_SESSION_SIGNING_CAPABILITY_MAINTENANCE_SQL = Object.freeze({
  recoverExpired: `SELECT public.agentpass_agent_signing_capability_recover_expired(
    $1::integer
  ) AS result`
});

export const AGENT_SESSION_SIGNING_CAPABILITY_RESERVATION_FUNCTIONS = Object.freeze({
  reserve: "public.agentpass_agent_signing_capability_reserve",
  commit: "public.agentpass_agent_signing_capability_commit",
  replay: "public.agentpass_agent_signing_capability_replay",
  uncertain: "public.agentpass_agent_signing_capability_uncertain"
});

export const AGENT_SESSION_SIGNING_CAPABILITY_MAINTENANCE_FUNCTIONS = Object.freeze({
  recoverExpired: "public.agentpass_agent_signing_capability_recover_expired"
});

export const AGENT_SESSION_SIGNING_CAPABILITY_BIND_SQL = `SELECT
  s.organization_id,s.session_id,s.grant_id,s.device_id,s.agent_id,s.status,
  s.max_signatures,s.used_signatures,s.reserved_signatures,s.not_before,s.expires_at,
  s.control_sequence,s.authority_generation
FROM public.agent_sessions AS s
JOIN public.devices AS d ON d.organization_id=s.organization_id AND d.id=s.device_id
JOIN public.agents AS a ON a.organization_id=s.organization_id AND a.id=s.agent_id
JOIN public.control_plane_authority_generations AS g
  ON g.organization_id=s.organization_id AND g.generation=s.authority_generation
  AND g.superseded_at IS NULL
WHERE s.organization_id=$1::uuid AND s.device_id=$2::uuid AND s.session_id=$3::uuid
  AND s.status IN ('active','signed','request_reserved','signing_intent')
  AND s.max_signatures=2 AND s.used_signatures+s.reserved_signatures<=s.max_signatures
  AND s.not_before<=$4::timestamptz AND s.expires_at>$4::timestamptz
  AND d.status='active' AND a.status='active'
  AND NOT EXISTS (
    SELECT 1 FROM public.revocations AS r
    WHERE r.organization_id=s.organization_id AND r.status='active'
      AND (r.target_type='organization'
        OR (r.target_type='device' AND r.target_id=s.device_id)
        OR (r.target_type='agent' AND r.target_id=s.agent_id))
  )
FOR SHARE OF s,d,a,g`;

export const AGENT_SESSION_SIGNING_CAPABILITY_RESERVATION_ERROR_CODES = Object.freeze({
  CONFIG: "ERR_AGENT_SESSION_SIGNING_CAPABILITY_RESERVATION_CONFIG",
  INPUT: "ERR_AGENT_SESSION_SIGNING_CAPABILITY_RESERVATION_INPUT",
  DATABASE: "ERR_AGENT_SESSION_SIGNING_CAPABILITY_RESERVATION_DATABASE",
  RESULT: "ERR_AGENT_SESSION_SIGNING_CAPABILITY_RESERVATION_RESULT",
  CONFLICT: "ERR_AGENT_SESSION_SIGNING_CAPABILITY_RESERVATION_CONFLICT",
  IN_PROGRESS: "ERR_AGENT_SESSION_SIGNING_CAPABILITY_RESERVATION_IN_PROGRESS",
  CLAIM: "ERR_AGENT_SESSION_SIGNING_CAPABILITY_RESERVATION_CLAIM",
  UNCERTAIN: "ERR_AGENT_SESSION_SIGNING_CAPABILITY_RESERVATION_UNCERTAIN"
});

const MESSAGES = Object.freeze({
  [AGENT_SESSION_SIGNING_CAPABILITY_RESERVATION_ERROR_CODES.CONFIG]: "Agent Session signing capability repository configuration is invalid",
  [AGENT_SESSION_SIGNING_CAPABILITY_RESERVATION_ERROR_CODES.INPUT]: "Agent Session signing capability repository input is invalid",
  [AGENT_SESSION_SIGNING_CAPABILITY_RESERVATION_ERROR_CODES.DATABASE]: "Agent Session signing capability storage is unavailable",
  [AGENT_SESSION_SIGNING_CAPABILITY_RESERVATION_ERROR_CODES.RESULT]: "Agent Session signing capability storage returned an invalid result",
  [AGENT_SESSION_SIGNING_CAPABILITY_RESERVATION_ERROR_CODES.CONFLICT]: "Agent Session signing capability request conflicts with durable state",
  [AGENT_SESSION_SIGNING_CAPABILITY_RESERVATION_ERROR_CODES.IN_PROGRESS]: "Agent Session signing capability request is already in progress",
  [AGENT_SESSION_SIGNING_CAPABILITY_RESERVATION_ERROR_CODES.CLAIM]: "Agent Session signing capability claim is invalid",
  [AGENT_SESSION_SIGNING_CAPABILITY_RESERVATION_ERROR_CODES.UNCERTAIN]: "Agent Session signing capability outcome is uncertain"
});

export class AgentSessionSigningCapabilityReservationRepositoryError extends Error {
  constructor(code) {
    super(MESSAGES[code] ?? MESSAGES[AGENT_SESSION_SIGNING_CAPABILITY_RESERVATION_ERROR_CODES.DATABASE]);
    this.name = "AgentSessionSigningCapabilityReservationRepositoryError";
    this.code = Object.hasOwn(MESSAGES, code) ? code : AGENT_SESSION_SIGNING_CAPABILITY_RESERVATION_ERROR_CODES.DATABASE;
  }
}

/**
 * Create a tenant/session-bound repository for the F2a issuance service.
 * `context` is trusted only after the Device API's session binder has checked
 * it. The public service still receives only `{ request_id }`.
 */
export function createPostgresAgentSessionSigningCapabilityReservationRepository({
  client,
  organizationId,
  organization_id,
  sessionId,
  session_id,
  grantId,
  grant_id,
  deviceId,
  device_id,
  agentId,
  agent_id,
  context = undefined,
  randomBytes = crypto.randomBytes,
  randomUUID = crypto.randomUUID,
  maxTtlMs = MAX_TTL_MS,
  sql = AGENT_SESSION_SIGNING_CAPABILITY_RESERVATION_SQL
} = {}) {
  const boundContext = normalizeContext(context ?? { organizationId: organizationId ?? organization_id, sessionId: sessionId ?? session_id,
    grantId: grantId ?? grant_id, deviceId: deviceId ?? device_id, agentId: agentId ?? agent_id });
  if (!client || typeof client.query !== "function" || typeof randomBytes !== "function" || typeof randomUUID !== "function"
    || !Number.isSafeInteger(maxTtlMs) || maxTtlMs < 1_000 || maxTtlMs > MAX_TTL_MS
    || !sql || typeof sql.reserve !== "string" || typeof sql.commit !== "string"
    || typeof sql.replay !== "string" || typeof sql.uncertain !== "string") {
    throw repoError("CONFIG");
  }

  async function reserveCapability(input = {}) {
    const values = normalizeReserveInput(input, maxTtlMs);
    const claimToken = makeClaimToken(randomBytes);
    const requestDigest = requestDigestForRequest(values.request_id);
    const reservationId = makeUuid(randomUUID);
    const capabilityId = makeUuid(randomUUID);
    if (reservationId === capabilityId || reservationId === values.request_id || capabilityId === values.request_id) throw repoError("CONFIG");
    try {
      const raw = await withTenantTransaction(client, boundContext.organization_id, async (tx) => callFunction(tx, sql.reserve, [
        boundContext.organization_id, boundContext.device_id, boundContext.session_id, values.request_id,
        requestDigest, reservationId, capabilityId, digestText(claimToken), values.operation,
        values.key_purpose, values.one_use, values.max_signatures, values.ttl_ms
      ]));
      return normalizeReserveOutcome(raw, boundContext, claimToken, maxTtlMs);
    } catch (error) {
      throw publicError(error);
    }
  }

  async function commitCapability(input = {}) {
    const values = normalizeCommitInput(input, boundContext, maxTtlMs);
    try {
      const raw = await withTenantTransaction(client, boundContext.organization_id, async (tx) => callFunction(tx, sql.commit, [
        boundContext.organization_id, boundContext.device_id, boundContext.session_id, values.request_id,
        requestDigestForRequest(values.request_id), digestText(values.claim_token)
      ]));
      return normalizeCommittedOrTerminal(raw, boundContext, maxTtlMs);
    } catch (error) {
      throw publicError(error);
    }
  }

  async function replayCapability(input = {}) {
    const requestId = normalizeExactRequest(input);
    try {
      const raw = await withTenantTransaction(client, boundContext.organization_id, async (tx) => callFunction(tx, sql.replay, [
        boundContext.organization_id, boundContext.device_id, boundContext.session_id, requestId,
        requestDigestForRequest(requestId)
      ]));
      return normalizeReplayOutcome(raw, boundContext, maxTtlMs);
    } catch (error) {
      throw publicError(error);
    }
  }

  async function markCapabilityUncertain(input = {}) {
    const values = normalizeUncertainInput(input);
    try {
      const raw = await withTenantTransaction(client, boundContext.organization_id, async (tx) => callFunction(tx, sql.uncertain, [
        boundContext.organization_id, boundContext.device_id, boundContext.session_id, values.request_id,
        requestDigestForRequest(values.request_id), digestText(values.claim_token), values.reason
      ]));
      const outcome = normalizeReplayOutcome(raw, boundContext, maxTtlMs);
      if (outcome.state === "absent" || outcome.state === "in_progress") throw repoError("RESULT");
      return outcome.state === "reserved" ? { state: "uncertain" } : outcome;
    } catch (error) {
      throw publicError(error);
    }
  }

  return Object.freeze({ reserveCapability, commitCapability, replayCapability, markCapabilityUncertain });
}

/**
 * Create the deployment-wide expiry repository on the dedicated maintenance
 * connection. This adapter deliberately has no tenant context and exposes no
 * reserve/commit/replay methods. The SQL function applies its bounded batch
 * across all tenants under the migration-owned SECURITY DEFINER boundary.
 */
export function createPostgresAgentSessionSigningCapabilityMaintenanceRepository({
  client,
  sql = AGENT_SESSION_SIGNING_CAPABILITY_MAINTENANCE_SQL
} = {}) {
  if (!client || typeof client.query !== "function"
    || !sql || typeof sql.recoverExpired !== "string") throw repoError("CONFIG");

  async function recoverExpiredReservations({ limit = 64 } = {}) {
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 256) throw repoError("INPUT");
    try {
      const raw = await withTransaction(client, async (tx) => callFunction(tx, sql.recoverExpired, [limit]));
      if (!raw || typeof raw !== "object" || Array.isArray(raw) || raw.status !== "ok"
        || !Number.isSafeInteger(raw.expired) || raw.expired < 0 || raw.expired > limit
        || !Number.isSafeInteger(raw.uncertain) || raw.uncertain < 0
        || raw.expired + raw.uncertain > limit) throw repoError("RESULT");
      return Object.freeze({ expired: raw.expired, uncertain: raw.uncertain });
    } catch (error) {
      throw publicError(error);
    }
  }

  return Object.freeze({ recoverExpiredReservations });
}

export const createAgentSessionSigningCapabilityReservationRepository = createPostgresAgentSessionSigningCapabilityReservationRepository;
export default createPostgresAgentSessionSigningCapabilityReservationRepository;

export function createPostgresAgentSessionSigningCapabilitySessionBinder({ client } = {}) {
  if (!client || typeof client.query !== "function") throw repoError("CONFIG");
  return Object.freeze({
    async bindAgentSession(input = {}) {
      let organizationId;
      let deviceId;
      let sessionId;
      let observedAt;
      try {
        organizationId = uuid(input.organization_id ?? input.organizationId, "organization_id");
        deviceId = uuid(input.device_id ?? input.deviceId, "device_id");
        sessionId = uuid(input.session_id ?? input.sessionId, "session_id");
        const nowValue = input.now instanceof Date ? input.now.getTime() : input.now;
        if (!Number.isSafeInteger(nowValue) || nowValue <= 0) throw new Error("now");
        observedAt = new Date(nowValue).toISOString();
      } catch { throw repoError("INPUT"); }
      try {
        return await withTransaction(client, async (tx) => {
          const configured = await tx.query("SELECT set_config('agentpass.organization_id',$1,true) AS organization_id", [organizationId]);
          if (Number(configured?.rowCount ?? configured?.rows?.length ?? 0) !== 1
            || configured.rows?.[0]?.organization_id !== organizationId) throw repoError("DATABASE");
          const result = await tx.query(AGENT_SESSION_SIGNING_CAPABILITY_BIND_SQL, [organizationId, deviceId, sessionId, observedAt]);
          if (Number(result?.rowCount ?? result?.rows?.length ?? 0) !== 1) throw repoError("CONFLICT");
          const row = result.rows[0];
          return deepFreeze({
            authorized: true,
            organization_id: uuid(row.organization_id, "organization_id"),
            session_id: uuid(row.session_id, "session_id"),
            grant_id: uuid(row.grant_id, "grant_id"),
            device_id: uuid(row.device_id, "device_id"),
            agent_id: uuid(row.agent_id, "agent_id")
          });
        });
      } catch (error) {
        throw publicError(error);
      }
    }
  });
}

function normalizeContext(value) {
  try {
    return Object.freeze({
      organization_id: uuid(value.organizationId, "organization_id"),
      session_id: uuid(value.sessionId, "session_id"),
      grant_id: uuid(value.grantId, "grant_id"),
      device_id: uuid(value.deviceId, "device_id"),
      agent_id: uuid(value.agentId, "agent_id")
    });
  } catch {
    throw repoError("CONFIG");
  }
}

function normalizeReserveInput(input, maxTtlMs) {
  try {
    exactObject(input, RESERVE_REQUEST_KEYS);
    if (input.operation !== AGENT_SIGNING_CAPABILITY_OPERATION
      || input.key_purpose !== AGENT_SIGNING_CAPABILITY_OPERATION
      || input.one_use !== true || input.max_signatures !== AGENT_SIGNING_CAPABILITY_MAX_SIGNATURES) throw new Error("scope");
    if (!Number.isSafeInteger(input.ttl_ms) || input.ttl_ms < 1_000 || input.ttl_ms > maxTtlMs) throw new Error("ttl");
    return Object.freeze({ request_id: uuid(input.request_id, "request_id"), operation: input.operation,
      key_purpose: input.key_purpose, one_use: true, max_signatures: 1, ttl_ms: input.ttl_ms });
  } catch {
    throw repoError("INPUT");
  }
}

function normalizeCommitInput(input, context, maxTtlMs) {
  try {
    exactObject(input, COMMIT_REQUEST_KEYS);
    const requestId = uuid(input.request_id, "request_id");
    if (!CLAIM_TOKEN.test(input.claim_token)) throw new Error("claim");
    if (typeof input.capability_hash !== "string" || !DIGEST_HEX.test(input.capability_hash)) throw new Error("hash");
    if (!Number.isSafeInteger(input.remaining_session_signatures) || input.remaining_session_signatures < 0 || input.remaining_session_signatures > 1) throw new Error("remaining");
    const capability = normalizeCapability(input.capability, context, maxTtlMs);
    if (capability.statement_hash !== input.capability_hash) throw new Error("hash binding");
    return Object.freeze({ request_id: requestId, claim_token: input.claim_token, capability,
      capability_hash: input.capability_hash, remaining_session_signatures: input.remaining_session_signatures });
  } catch (error) {
    if (error instanceof AgentSessionSigningCapabilityReservationRepositoryError) throw error;
    throw repoError("INPUT");
  }
}

function normalizeUncertainInput(input) {
  try {
    exactObject(input, UNCERTAIN_REQUEST_KEYS);
    if (!CLAIM_TOKEN.test(input.claim_token) || typeof input.reason !== "string" || !UNCERTAINTY_REASONS.has(input.reason)) throw new Error("uncertain");
    return Object.freeze({ request_id: uuid(input.request_id, "request_id"), claim_token: input.claim_token, reason: input.reason });
  } catch {
    throw repoError("INPUT");
  }
}

function normalizeExactRequest(input) {
  try {
    exactObject(input, REQUEST_KEYS);
    return uuid(input.request_id, "request_id");
  } catch {
    throw repoError("INPUT");
  }
}

function normalizeReserveOutcome(value, context, claimToken, maxTtlMs) {
  const outcome = parseOutcome(value);
  if (["conflict", "in_progress", "absent", "uncertain"].includes(outcome.state)) return { state: outcome.state };
  if (outcome.state === "outcome_unknown") return { state: "uncertain" };
  if (outcome.state === "completed" || outcome.state === "committed") return normalizeCommittedOrTerminal(outcome, context, maxTtlMs);
  if (outcome.state !== "reserved") throw repoError("RESULT");
  if (outcome.claim_issued !== true) return { state: "in_progress" };
  const reservation = normalizeReservation(outcome, context, maxTtlMs);
  return deepFreeze({ ...reservation, claim_token: claimToken });
}

function normalizeReplayOutcome(value, context, maxTtlMs) {
  const outcome = parseOutcome(value);
  if (outcome.state === "absent") return { state: "absent" };
  if (outcome.state === "uncertain" || outcome.state === "outcome_unknown") return { state: "uncertain" };
  if (outcome.state === "expired" || outcome.state === "revoked") return { state: "absent" };
  if (outcome.state === "in_progress" || outcome.state === "reserved") return { state: "in_progress" };
  if (outcome.state === "conflict") return { state: "conflict" };
  if (outcome.state === "completed" || outcome.state === "committed") return normalizeCommitted(outcome, context, maxTtlMs);
  throw repoError("RESULT");
}

function normalizeCommittedOrTerminal(value, context, maxTtlMs) {
  const outcome = parseOutcome(value);
  if (outcome.state === "uncertain" || outcome.state === "outcome_unknown") return { state: "uncertain" };
  if (outcome.state === "expired" || outcome.state === "revoked") return { state: "absent" };
  if (outcome.state === "in_progress") return { state: "in_progress" };
  if (outcome.state === "conflict") return { state: "conflict" };
  if (outcome.state === "absent") return { state: "absent" };
  if (outcome.state === "completed" || outcome.state === "committed") return normalizeCommitted(outcome, context, maxTtlMs);
  throw repoError("RESULT");
}

function normalizeCommitted(value, context, maxTtlMs) {
  try {
    exactObject(value, ["state", "capability", "remaining_session_signatures"]);
    if (!Number.isSafeInteger(value.remaining_session_signatures) || value.remaining_session_signatures < 0 || value.remaining_session_signatures > 1) throw new Error("remaining");
    return deepFreeze({ state: "committed", capability: normalizeCapability(value.capability, context, maxTtlMs), remaining_session_signatures: value.remaining_session_signatures });
  } catch (error) {
    if (error instanceof AgentSessionSigningCapabilityReservationRepositoryError) throw error;
    throw repoError("RESULT");
  }
}

function normalizeReservation(value, context, maxTtlMs = MAX_TTL_MS) {
  try {
    exactObject(value, ["state", "capability_id", "organization_id", "session_id", "device_id", "agent_id", "scope", "sequence", "control_sequence", "authority_generation", "issued_at", "not_before", "expires_at", "remaining_session_signatures", "claim_issued"]);
    if (value.state !== "reserved" || value.organization_id !== context.organization_id || value.session_id !== context.session_id
      || value.device_id !== context.device_id || value.agent_id !== context.agent_id) throw new Error("binding");
    const reservation = {
      state: "reserved", capability_id: uuid(value.capability_id, "capability_id"), organization_id: context.organization_id,
      session_id: context.session_id, device_id: context.device_id, agent_id: context.agent_id, scope: normalizeScope(value.scope),
      sequence: positiveInteger(value.sequence), control_sequence: positiveInteger(value.control_sequence),
      authority_generation: positiveInteger(value.authority_generation), issued_at: timestamp(value.issued_at),
      not_before: timestamp(value.not_before), expires_at: timestamp(value.expires_at),
      remaining_session_signatures: boundedRemaining(value.remaining_session_signatures)
    };
    if (Date.parse(reservation.issued_at) > Date.parse(reservation.not_before)
      || Date.parse(reservation.not_before) >= Date.parse(reservation.expires_at)
      || Date.parse(reservation.expires_at) - Date.parse(reservation.issued_at) > maxTtlMs) throw new Error("window");
    return reservation;
  } catch (error) {
    if (error instanceof AgentSessionSigningCapabilityReservationRepositoryError) throw error;
    throw repoError("RESULT");
  }
}

function normalizeCapability(value, context, maxTtlMs) {
  try {
    exactObject(value, ["version", "type", "statement", "statement_hash", "signature"]);
    if (value.version !== AGENT_SIGNING_CAPABILITY_VERSION || value.type !== AGENT_SIGNING_CAPABILITY_TYPE
      || typeof value.statement_hash !== "string" || !DIGEST_HEX.test(value.statement_hash) || !SIGNATURE.test(value.signature)) throw new Error("shape");
    const statement = normalizeAgentSigningCapabilityStatement(value.statement, { maxTtlMs });
    for (const [key, expected] of Object.entries({
      organization_id: context.organization_id, session_id: context.session_id, device_id: context.device_id, agent_id: context.agent_id,
      operation: AGENT_SIGNING_CAPABILITY_OPERATION, key_purpose: AGENT_SIGNING_CAPABILITY_OPERATION, issuer: AGENT_SIGNING_CAPABILITY_ISSUER,
      algorithm: AGENT_SIGNING_CAPABILITY_ALGORITHM, max_signatures: AGENT_SIGNING_CAPABILITY_MAX_SIGNATURES, one_use: true
    })) if (statement[key] !== expected) throw new Error("authority");
    if (agentSigningCapabilityStatementHash(statement) !== value.statement_hash) throw new Error("statement hash");
    return deepFreeze({ version: value.version, type: value.type, statement, statement_hash: value.statement_hash, signature: value.signature });
  } catch (error) {
    if (error instanceof AgentSessionSigningCapabilityReservationRepositoryError) throw error;
    throw repoError("RESULT");
  }
}

function parseOutcome(value) {
  try {
    const result = typeof value === "string" ? JSON.parse(value) : value;
    if (!result || typeof result !== "object" || Array.isArray(result) || typeof result.state !== "string") throw new Error("outcome");
    return result;
  } catch {
    throw repoError("RESULT");
  }
}

async function callFunction(tx, text, params) {
  const result = await tx.query(text, params);
  if (Number(result?.rowCount ?? result?.rows?.length ?? 0) !== 1 || !Object.hasOwn(result.rows?.[0] ?? {}, "result")) throw repoError("DATABASE");
  return result.rows[0].result;
}

async function withTenantTransaction(client, organizationId, operation) {
  return withTransaction(client, async (tx) => {
    const configured = await tx.query("SELECT set_config('agentpass.organization_id',$1,true) AS organization_id", [organizationId]);
    if (Number(configured?.rowCount ?? configured?.rows?.length ?? 0) !== 1
      || configured.rows?.[0]?.organization_id !== organizationId) throw repoError("DATABASE");
    return operation(tx);
  });
}

function publicError(error) {
  if (error instanceof AgentSessionSigningCapabilityReservationRepositoryError) return error;
  const code = error?.code;
  if (code === "23505" || code === "23P01") return repoError("CONFLICT");
  if (code === "40001" || code === "55P03") return repoError("IN_PROGRESS");
  return repoError("DATABASE");
}

function makeClaimToken(randomBytes) {
  try {
    const bytes = randomBytes(32);
    if (!Buffer.isBuffer(bytes) || bytes.length !== 32) throw new Error("claim");
    const token = bytes.toString("base64url");
    if (!CLAIM_TOKEN.test(token)) throw new Error("claim");
    return token;
  } catch {
    throw repoError("CONFIG");
  }
}

function makeUuid(randomUUID) {
  try { return uuid(randomUUID(), "generated_uuid"); }
  catch { throw repoError("CONFIG"); }
}

function requestDigestForRequest(requestId) {
  return digestText(canonicalJson({ request_id: requestId }));
}

function digestText(value) { return crypto.createHash("sha256").update(value, "utf8").digest(); }
function uuid(value, field) { if (typeof value !== "string" || !UUID.test(value)) throw new Error(field); return value.toLowerCase(); }
function positiveInteger(value) { const number = typeof value === "string" ? Number(value) : value; if (!Number.isSafeInteger(number) || number < 1) throw new Error("integer"); return number; }
function boundedRemaining(value) { if (!Number.isSafeInteger(value) || value < 0 || value > 1) throw new Error("remaining"); return value; }
function timestamp(value) { const date = new Date(value); if (!(date instanceof Date) || !Number.isFinite(date.getTime()) || date.toISOString() !== value || !TIMESTAMP.test(value)) throw new Error("timestamp"); return value; }
function exactObject(value, keys) {
  if (!value || typeof value !== "object" || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype
    || Reflect.ownKeys(value).some((key) => typeof key !== "string") || Object.keys(value).length !== keys.length
    || Object.keys(value).some((key) => !keys.includes(key))) throw new Error("object");
}
function deepFreeze(value) { if (value && typeof value === "object" && !Object.isFrozen(value)) { Object.freeze(value); for (const nested of Object.values(value)) deepFreeze(nested); } return value; }
function repoError(code) { return new AgentSessionSigningCapabilityReservationRepositoryError(AGENT_SESSION_SIGNING_CAPABILITY_RESERVATION_ERROR_CODES[code]); }
