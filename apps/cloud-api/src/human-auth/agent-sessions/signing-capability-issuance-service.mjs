import { canonicalJson, normalizeScope } from "../../../../../packages/protocol/src/index.mjs";
import {
  AGENT_SIGNING_CAPABILITY_ALGORITHM,
  AGENT_SIGNING_CAPABILITY_ISSUER,
  AGENT_SIGNING_CAPABILITY_MAX_SIGNATURES,
  AGENT_SIGNING_CAPABILITY_OPERATION,
  AGENT_SIGNING_CAPABILITY_SIGNATURE_DOMAIN,
  AGENT_SIGNING_CAPABILITY_TYPE,
  AGENT_SIGNING_CAPABILITY_VERSION,
  agentSigningCapabilityStatementHash,
  normalizeAgentSigningCapabilityStatement
} from "../../agent-signing-capability.mjs";

export const AGENT_SIGNING_CAPABILITY_KEY_PURPOSE = "git.commit.sign";
export {
  AGENT_SIGNING_CAPABILITY_ALGORITHM,
  AGENT_SIGNING_CAPABILITY_ISSUER,
  AGENT_SIGNING_CAPABILITY_OPERATION,
  AGENT_SIGNING_CAPABILITY_SIGNATURE_DOMAIN
};
export const AGENT_SESSION_SIGNATURE_BUDGET = 2;
export const AGENT_SIGNING_CAPABILITY_DEFAULT_TTL_MS = 5 * 60 * 1000;
export const AGENT_SIGNING_CAPABILITY_MAX_TTL_MS = 15 * 60 * 1000;

export const AGENT_SIGNING_CAPABILITY_ISSUANCE_ERROR_CODES = Object.freeze({
  CONFIG: "ERR_AGENT_SIGNING_CAPABILITY_ISSUANCE_CONFIG",
  INPUT: "ERR_AGENT_SIGNING_CAPABILITY_ISSUANCE_INPUT",
  REPOSITORY: "ERR_AGENT_SIGNING_CAPABILITY_ISSUANCE_REPOSITORY",
  CONFLICT: "ERR_AGENT_SIGNING_CAPABILITY_ISSUANCE_CONFLICT",
  IN_PROGRESS: "ERR_AGENT_SIGNING_CAPABILITY_ISSUANCE_IN_PROGRESS",
  OUTCOME_UNKNOWN: "ERR_AGENT_SIGNING_CAPABILITY_ISSUANCE_OUTCOME_UNKNOWN",
  SIGNER_OUTPUT: "ERR_AGENT_SIGNING_CAPABILITY_ISSUANCE_SIGNER_OUTPUT",
  COMMIT: "ERR_AGENT_SIGNING_CAPABILITY_ISSUANCE_COMMIT",
  OUTPUT: "ERR_AGENT_SIGNING_CAPABILITY_ISSUANCE_OUTPUT"
});

export const AGENT_SIGNING_CAPABILITY_RESERVATION_STATES = Object.freeze([
  "reserved",
  "committed",
  "uncertain",
  "in_progress",
  "conflict",
  "absent"
]);

const ERROR_MESSAGES = Object.freeze({
  [AGENT_SIGNING_CAPABILITY_ISSUANCE_ERROR_CODES.CONFIG]: "Agent signing capability issuance is misconfigured",
  [AGENT_SIGNING_CAPABILITY_ISSUANCE_ERROR_CODES.INPUT]: "Agent signing capability issuance input is invalid",
  [AGENT_SIGNING_CAPABILITY_ISSUANCE_ERROR_CODES.REPOSITORY]: "Agent signing capability issuance storage is unavailable",
  [AGENT_SIGNING_CAPABILITY_ISSUANCE_ERROR_CODES.CONFLICT]: "Agent signing capability issuance conflicts with a committed request",
  [AGENT_SIGNING_CAPABILITY_ISSUANCE_ERROR_CODES.IN_PROGRESS]: "Agent signing capability issuance is already in progress",
  [AGENT_SIGNING_CAPABILITY_ISSUANCE_ERROR_CODES.OUTCOME_UNKNOWN]: "The signing capability issuance outcome is unknown",
  [AGENT_SIGNING_CAPABILITY_ISSUANCE_ERROR_CODES.SIGNER_OUTPUT]: "The signing capability signer returned invalid output",
  [AGENT_SIGNING_CAPABILITY_ISSUANCE_ERROR_CODES.COMMIT]: "The signing capability could not be committed",
  [AGENT_SIGNING_CAPABILITY_ISSUANCE_ERROR_CODES.OUTPUT]: "The signing capability response is invalid"
});

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const SAFE_IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$/u;
const SIGNATURE_BASE64URL = /^[A-Za-z0-9_-]{86}$/u;
const CANONICAL_TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u;
const REQUEST_KEYS = Object.freeze(["request_id"]);
const RESERVATION_KEYS = Object.freeze([
  "state",
  "capability_id",
  "organization_id",
  "session_id",
  "device_id",
  "agent_id",
  "scope",
  "sequence",
  "control_sequence",
  "authority_generation",
  "issued_at",
  "not_before",
  "expires_at",
  "remaining_session_signatures",
  "claim_token"
]);
const COMMITTED_KEYS = Object.freeze(["state", "capability", "remaining_session_signatures"]);
const STATE_ONLY_KEYS = Object.freeze(["state"]);

export class AgentSigningCapabilityIssuanceError extends Error {
  constructor(code) {
    super(ERROR_MESSAGES[code] ?? ERROR_MESSAGES[AGENT_SIGNING_CAPABILITY_ISSUANCE_ERROR_CODES.OUTPUT]);
    this.name = "AgentSigningCapabilityIssuanceError";
    this.code = Object.hasOwn(ERROR_MESSAGES, code)
      ? code
      : AGENT_SIGNING_CAPABILITY_ISSUANCE_ERROR_CODES.OUTPUT;
  }
}

/**
 * Create the pure F2a Cloud issuance coordinator.
 *
 * The request boundary deliberately accepts only `{ request_id }`. The
 * reservation repository is a trusted, already-authenticated server seam
 * scoped to the Device/Agent Session and must derive all audience, tenant,
 * policy, scope, sequence, and generation values. This service adds the
 * immutable protocol constants and time window, then coordinates exactly one
 * signer call and one durable commit.
 *
 * Repository contract:
 *
 *   reserveCapability({ request_id, operation, key_purpose, one_use,
 *     max_signatures, issued_at, not_before, expires_at, ttl_ms })
 *     -> { state: "reserved", ...authoritative reservation }
 *        | { state: "committed", capability, remaining_session_signatures }
 *        | { state: "uncertain" | "in_progress" | "conflict" | "absent" }
 *   commitCapability({ request_id, claim_token, capability,
 *     capability_hash, remaining_session_signatures }) -> committed outcome
 *   replayCapability({ request_id }) -> committed or terminal state
 *   markCapabilityUncertain({ request_id, claim_token, reason }) -> terminal state
 *
 * The repository owns the transaction, idempotency record, lease/generation
 * checks, budget reservation, and durable uncertainty state. It must never
 * persist the returned signature as reusable authority outside its immutable
 * committed response.
 *
 * Signer contract: `signAgentSigningCapability(statement)` is preferred and
 * may return the complete capability envelope. The compatible
 * `signCapability(statement)` method may instead return an unpadded base64url
 * Ed25519 signature or `{ signature }` / `{ ...statement, signature }`. The
 * signer owns the managed-key/provider boundary and must sign
 * `SIGNATURE_DOMAIN + canonicalJson(statement)` exactly once.
 */
export function createAgentSessionSigningCapabilityIssuanceService({
  repository,
  reservationRepository = repository,
  signer,
  signerKeyId = undefined,
  keyId = undefined,
  now = () => Date.now(),
  maxTtlMs = AGENT_SIGNING_CAPABILITY_DEFAULT_TTL_MS
} = {}) {
  const configuredKeyId = signerKeyId ?? keyId;
  const signCapability = validateConfiguration(reservationRepository, signer, configuredKeyId, now, maxTtlMs);
  const resolvedSignerKeyId = signer?.key_id ?? signer?.keyId ?? configuredKeyId;

  async function issue(input = {}) {
    const requestId = normalizeRequest(input);
    currentNow(now);
    const reservationInput = Object.freeze({
      request_id: requestId,
      operation: AGENT_SIGNING_CAPABILITY_OPERATION,
      key_purpose: AGENT_SIGNING_CAPABILITY_KEY_PURPOSE,
      one_use: true,
      max_signatures: AGENT_SIGNING_CAPABILITY_MAX_SIGNATURES,
      ttl_ms: maxTtlMs
    });

    let rawReservation;
    try {
      rawReservation = await reservationRepository.reserveCapability(reservationInput);
    } catch {
      throw issuanceError(AGENT_SIGNING_CAPABILITY_ISSUANCE_ERROR_CODES.REPOSITORY);
    }

    const reservation = normalizeReservationOutcome(rawReservation, requestId, undefined, maxTtlMs, "reserve");
    if (reservation.state === "committed") return materializeCommitted(reservation, requestId, true);
    if (reservation.state === "uncertain") throw issuanceError(AGENT_SIGNING_CAPABILITY_ISSUANCE_ERROR_CODES.OUTCOME_UNKNOWN);
    if (reservation.state === "in_progress") throw issuanceError(AGENT_SIGNING_CAPABILITY_ISSUANCE_ERROR_CODES.IN_PROGRESS);
    if (reservation.state === "conflict") throw issuanceError(AGENT_SIGNING_CAPABILITY_ISSUANCE_ERROR_CODES.CONFLICT);
    if (reservation.state !== "reserved") throw issuanceError(AGENT_SIGNING_CAPABILITY_ISSUANCE_ERROR_CODES.REPOSITORY);

    let statement;
    try {
      statement = buildStatement(reservation, resolvedSignerKeyId);
    } catch {
      await markUncertainBestEffort(requestId, reservation, "commit_failure");
      throw issuanceError(AGENT_SIGNING_CAPABILITY_ISSUANCE_ERROR_CODES.OUTPUT);
    }

    let signed;
    try {
      signed = await signCapability(statement);
    } catch {
      await markUncertainBestEffort(requestId, reservation, "signer_failure");
      throw issuanceError(AGENT_SIGNING_CAPABILITY_ISSUANCE_ERROR_CODES.OUTCOME_UNKNOWN);
    }

    let capability;
    try {
      capability = normalizeSignedCapability(signed, statement);
    } catch {
      await markUncertainBestEffort(requestId, reservation, "signer_output_invalid");
      throw issuanceError(AGENT_SIGNING_CAPABILITY_ISSUANCE_ERROR_CODES.SIGNER_OUTPUT);
    }

    const commitInput = Object.freeze({
      request_id: requestId,
      claim_token: reservation.claim_token,
      capability,
      capability_hash: capability.statement_hash,
      remaining_session_signatures: reservation.remaining_session_signatures
    });
    let rawCommitted;
    try {
      rawCommitted = await reservationRepository.commitCapability(commitInput);
    } catch {
      return reconcileCommitLoss(requestId, reservation, capability);
    }

    let committed;
    try {
      committed = normalizeReservationOutcome(rawCommitted, requestId, undefined, maxTtlMs, "commit");
    } catch {
      return reconcileCommitLoss(requestId, reservation, capability);
    }
    if (committed.state !== "committed") return reconcileCommitLoss(requestId, reservation, capability);
    if (!sameCapability(committed.capability, capability)) return reconcileCommitLoss(requestId, reservation, capability);
    if (committed.remaining_session_signatures !== reservation.remaining_session_signatures) {
      return reconcileCommitLoss(requestId, reservation, capability);
    }
    return publicResponse(requestId, capability, committed.remaining_session_signatures, false);
  }

  async function reconcileCommitLoss(requestId, reservation, capability) {
    let rawReplay;
    try {
      rawReplay = await reservationRepository.replayCapability({ request_id: requestId });
    } catch {
      await markUncertainBestEffort(requestId, reservation, "commit_response_lost");
      throw issuanceError(AGENT_SIGNING_CAPABILITY_ISSUANCE_ERROR_CODES.OUTCOME_UNKNOWN);
    }
    let replay;
    try {
      replay = normalizeReservationOutcome(rawReplay, requestId, undefined, maxTtlMs, "replay");
    } catch {
      await markUncertainBestEffort(requestId, reservation, "commit_failure");
      throw issuanceError(AGENT_SIGNING_CAPABILITY_ISSUANCE_ERROR_CODES.OUTCOME_UNKNOWN);
    }
    if (replay.state === "committed" && sameCapability(replay.capability, capability)) {
      if (replay.remaining_session_signatures !== reservation.remaining_session_signatures) {
        await markUncertainBestEffort(requestId, reservation, "commit_failure");
        throw issuanceError(AGENT_SIGNING_CAPABILITY_ISSUANCE_ERROR_CODES.OUTCOME_UNKNOWN);
      }
      return publicResponse(requestId, replay.capability, replay.remaining_session_signatures, true);
    }
    if (replay.state === "uncertain") throw issuanceError(AGENT_SIGNING_CAPABILITY_ISSUANCE_ERROR_CODES.OUTCOME_UNKNOWN);
    if (replay.state === "in_progress") throw issuanceError(AGENT_SIGNING_CAPABILITY_ISSUANCE_ERROR_CODES.IN_PROGRESS);
    await markUncertainBestEffort(requestId, reservation, "commit_failure");
    throw issuanceError(AGENT_SIGNING_CAPABILITY_ISSUANCE_ERROR_CODES.OUTCOME_UNKNOWN);
  }

  async function materializeCommitted(outcome, requestId, replayed) {
    try {
      const capability = normalizeCapability(outcome.capability, { maxTtlMs });
      return publicResponse(requestId, capability, outcome.remaining_session_signatures, replayed);
    } catch {
      throw issuanceError(AGENT_SIGNING_CAPABILITY_ISSUANCE_ERROR_CODES.OUTPUT);
    }
  }

  async function markUncertainBestEffort(requestId, reservation, reason) {
    if (typeof reservation?.claim_token !== "string") return;
    try {
      await reservationRepository.markCapabilityUncertain({
        request_id: requestId,
        claim_token: reservation.claim_token,
        reason
      });
    } catch {
      // The provider boundary is already ambiguous. Never replace the safe
      // public outcome with a repository or provider diagnostic.
    }
  }

  const service = {
    issueAgentSessionSigningCapability: issue,
    issue
  };
  return Object.freeze(service);
}

export const createAgentSigningCapabilityIssuanceService = createAgentSessionSigningCapabilityIssuanceService;

function validateConfiguration(repository, signer, configuredKeyId, now, maxTtlMs) {
  const signerMethod = typeof signer?.signAgentSigningCapability === "function"
    ? signer.signAgentSigningCapability
    : signer?.signCapability;
  const signerKeyId = signer?.key_id ?? signer?.keyId ?? configuredKeyId;
  if (!isObject(repository)
    || typeof repository.reserveCapability !== "function"
    || typeof repository.commitCapability !== "function"
    || typeof repository.replayCapability !== "function"
    || typeof repository.markCapabilityUncertain !== "function") {
    throw issuanceError(AGENT_SIGNING_CAPABILITY_ISSUANCE_ERROR_CODES.CONFIG);
  }
  if (!isObject(signer)
    || typeof signerMethod !== "function"
    || typeof signerKeyId !== "string"
    || !SAFE_IDENTIFIER.test(signerKeyId)
    || (signer.algorithm !== undefined && signer.algorithm !== AGENT_SIGNING_CAPABILITY_ALGORITHM)
    || (signer.purpose !== undefined && signer.purpose !== AGENT_SIGNING_CAPABILITY_KEY_PURPOSE)
    || ["privateKey", "private_key", "secret", "private_key_pem"].some((key) => Object.hasOwn(signer, key))) {
    throw issuanceError(AGENT_SIGNING_CAPABILITY_ISSUANCE_ERROR_CODES.CONFIG);
  }
  if (typeof now !== "function"
    || !Number.isSafeInteger(maxTtlMs)
    || maxTtlMs < 1_000
    || maxTtlMs > AGENT_SIGNING_CAPABILITY_MAX_TTL_MS) {
    throw issuanceError(AGENT_SIGNING_CAPABILITY_ISSUANCE_ERROR_CODES.CONFIG);
  }
  return signerMethod.bind(signer);
}

function normalizeRequest(input) {
  try {
    assertPlainObject(input);
    assertExactKeys(input, REQUEST_KEYS);
    return uuid(input.request_id, "request_id");
  } catch {
    throw issuanceError(AGENT_SIGNING_CAPABILITY_ISSUANCE_ERROR_CODES.INPUT);
  }
}

function buildStatement(reservation, keyId) {
  return normalizeAgentSigningCapabilityStatement({
    version: AGENT_SIGNING_CAPABILITY_VERSION,
    type: AGENT_SIGNING_CAPABILITY_TYPE,
    capability_id: reservation.capability_id,
    organization_id: reservation.organization_id,
    session_id: reservation.session_id,
    device_id: reservation.device_id,
    agent_id: reservation.agent_id,
    one_use: true,
    operation: AGENT_SIGNING_CAPABILITY_OPERATION,
    scope: reservation.scope,
    key_purpose: AGENT_SIGNING_CAPABILITY_KEY_PURPOSE,
    key_id: keyId,
    algorithm: AGENT_SIGNING_CAPABILITY_ALGORITHM,
    max_signatures: AGENT_SIGNING_CAPABILITY_MAX_SIGNATURES,
    issued_at: reservation.issued_at,
    not_before: reservation.not_before,
    expires_at: reservation.expires_at,
    sequence: reservation.sequence,
    control_sequence: reservation.control_sequence,
    authority_generation: reservation.authority_generation,
    issuer: AGENT_SIGNING_CAPABILITY_ISSUER
  }, { maxTtlMs: AGENT_SIGNING_CAPABILITY_MAX_TTL_MS });
}

function normalizeReservationOutcome(value, requestId, timing, maxTtlMs, phase) {
  try {
    assertPlainObject(value);
    if (typeof value.state !== "string" || !AGENT_SIGNING_CAPABILITY_RESERVATION_STATES.includes(value.state)) throw new Error("state");
    if (value.state === "absent" || value.state === "uncertain" || value.state === "in_progress" || value.state === "conflict") {
      assertExactKeys(value, STATE_ONLY_KEYS);
      return Object.freeze({ state: value.state });
    }
    if (value.state === "committed") {
      assertExactKeys(value, COMMITTED_KEYS);
      const capability = normalizeCapability(value.capability, { maxTtlMs });
      const remaining = remainingSignatures(value.remaining_session_signatures);
      if (capability.statement.sequence < 1) throw new Error("sequence");
      return Object.freeze({ state: "committed", capability, remaining_session_signatures: remaining });
    }
    assertExactKeys(value, RESERVATION_KEYS);
    const reservation = Object.freeze({
      state: "reserved",
      capability_id: uuid(value.capability_id, "capability_id"),
      organization_id: uuid(value.organization_id, "organization_id"),
      session_id: uuid(value.session_id, "session_id"),
      device_id: uuid(value.device_id, "device_id"),
      agent_id: uuid(value.agent_id, "agent_id"),
      scope: normalizeScope(value.scope),
      sequence: positiveInteger(value.sequence, "sequence"),
      control_sequence: positiveInteger(value.control_sequence, "control_sequence"),
      authority_generation: positiveInteger(value.authority_generation, "authority_generation"),
      issued_at: timestamp(value.issued_at, "issued_at"),
      not_before: timestamp(value.not_before, "not_before"),
      expires_at: timestamp(value.expires_at, "expires_at"),
      remaining_session_signatures: remainingSignatures(value.remaining_session_signatures),
      claim_token: claimToken(value.claim_token)
    });
    if (timing !== undefined && (reservation.issued_at !== timing.issued_at
      || reservation.not_before !== timing.not_before
      || reservation.expires_at !== timing.expires_at)) throw new Error("time binding");
    if (Date.parse(reservation.issued_at) > Date.parse(reservation.not_before)
      || Date.parse(reservation.expires_at) <= Date.parse(reservation.not_before)
      || Date.parse(reservation.expires_at) - Date.parse(reservation.not_before) > maxTtlMs) throw new Error("time window");
    if (requestId.length === 0) throw new Error("request");
    return reservation;
  } catch (error) {
    if (error instanceof AgentSigningCapabilityIssuanceError) throw error;
    throw issuanceError(phase === "commit" || phase === "replay"
      ? AGENT_SIGNING_CAPABILITY_ISSUANCE_ERROR_CODES.OUTPUT
      : AGENT_SIGNING_CAPABILITY_ISSUANCE_ERROR_CODES.REPOSITORY);
  }
}

function normalizeSignedCapability(value, statement) {
  try {
    let signature = value;
    if (isObject(value)) {
      const keys = Reflect.ownKeys(value);
      const expected = [...Object.keys(statement), "signature"].sort();
      if (keys.some((key) => typeof key !== "string")) throw new Error("signed symbols");
      const actual = keys.sort().join("\0");
      const envelopeKeys = ["signature", "statement", "statement_hash", "type", "version"].sort().join("\0");
      if (actual === envelopeKeys) {
        const envelope = normalizeCapability(value, { maxTtlMs: AGENT_SIGNING_CAPABILITY_MAX_TTL_MS });
        if (canonicalJson(envelope.statement) !== canonicalJson(statement)) throw new Error("envelope statement substitution");
        return envelope;
      }
      if (actual === "signature") {
        signature = value.signature;
      } else {
        if (actual !== expected.join("\0")) throw new Error("signed shape");
        const { signature: candidate, ...returnedStatement } = value;
        if (canonicalJson(returnedStatement) !== canonicalJson(statement)) throw new Error("statement substitution");
        signature = candidate;
      }
    }
    const normalizedSignature = signatureValue(signature);
    const statementHash = agentSigningCapabilityStatementHash(statement);
    return Object.freeze({
      version: AGENT_SIGNING_CAPABILITY_VERSION,
      type: AGENT_SIGNING_CAPABILITY_TYPE,
      statement,
      statement_hash: statementHash,
      signature: normalizedSignature
    });
  } catch (error) {
    if (error instanceof AgentSigningCapabilityIssuanceError) throw error;
    throw issuanceError(AGENT_SIGNING_CAPABILITY_ISSUANCE_ERROR_CODES.SIGNER_OUTPUT);
  }
}

function normalizeCapability(value, { maxTtlMs }) {
  try {
    assertPlainObject(value);
    assertExactKeys(value, ["version", "type", "statement", "statement_hash", "signature"]);
    if (value.version !== AGENT_SIGNING_CAPABILITY_VERSION || value.type !== AGENT_SIGNING_CAPABILITY_TYPE) throw new Error("envelope");
    assertPlainObject(value.statement);
    assertExactKeys(value.statement, [
      "version", "type", "capability_id", "organization_id", "session_id", "device_id", "agent_id", "one_use",
      "operation", "scope", "key_purpose", "key_id", "algorithm", "max_signatures", "issued_at", "not_before",
      "expires_at", "sequence", "control_sequence", "authority_generation", "issuer"
    ]);
    const statement = normalizeAgentSigningCapabilityStatement(value.statement, { maxTtlMs });
    const signature = signatureValue(value.signature);
    if (value.statement_hash !== agentSigningCapabilityStatementHash(statement)) throw new Error("statement hash");
    return Object.freeze({
      version: 1,
      type: AGENT_SIGNING_CAPABILITY_TYPE,
      statement,
      statement_hash: value.statement_hash,
      signature
    });
  } catch {
    throw issuanceError(AGENT_SIGNING_CAPABILITY_ISSUANCE_ERROR_CODES.OUTPUT);
  }
}

function publicResponse(requestId, capability, remaining, replayed) {
  const response = {
    capability,
    metadata: {
      operation: AGENT_SIGNING_CAPABILITY_OPERATION,
      key_purpose: AGENT_SIGNING_CAPABILITY_KEY_PURPOSE,
      issued_at: capability.statement.issued_at,
      expires_at: capability.statement.expires_at,
      sequence: capability.statement.sequence,
      remaining_session_signatures: remainingSignatures(remaining),
      replayed: replayed === true
    },
    request_id: requestId
  };
  return deepFreeze(response);
}

function sameCapability(left, right) {
  try { return canonicalJson(left) === canonicalJson(right); } catch { return false; }
}

function currentNow(clock) {
  let value;
  try { value = clock(); } catch { throw issuanceError(AGENT_SIGNING_CAPABILITY_ISSUANCE_ERROR_CODES.CONFIG); }
  const result = value instanceof Date ? value.getTime() : value;
  if (!Number.isSafeInteger(result) || result <= 0) throw issuanceError(AGENT_SIGNING_CAPABILITY_ISSUANCE_ERROR_CODES.CONFIG);
  return result;
}

function signatureValue(value) {
  if (typeof value !== "string" || !SIGNATURE_BASE64URL.test(value)) throw new Error("signature");
  const bytes = Buffer.from(value, "base64url");
  if (bytes.length !== 64 || bytes.toString("base64url") !== value) throw new Error("signature");
  return value;
}

function uuid(value, field) { if (typeof value !== "string" || value !== value.toLowerCase() || !UUID.test(value)) throw new Error(field); return value; }
function positiveInteger(value, field) { if (!Number.isSafeInteger(value) || value < 1) throw new Error(field); return value; }
function remainingSignatures(value) { if (!Number.isSafeInteger(value) || value < 0 || value > 1) throw new Error("remaining_session_signatures"); return value; }
function claimToken(value) { if (typeof value !== "string" || value.length < 16 || value.length > 512 || /[\u0000-\u001f\u007f]/u.test(value)) throw new Error("claim_token"); return value; }
function timestamp(value, field) { if (typeof value !== "string" || !CANONICAL_TIMESTAMP.test(value) || new Date(value).toISOString() !== value) throw new Error(field); return value; }
function assertPlainObject(value) { if (!isObject(value)) throw new Error("object"); }
function isObject(value) { if (!value || typeof value !== "object" || Array.isArray(value)) return false; const prototype = Object.getPrototypeOf(value); return prototype === Object.prototype || prototype === null; }
function assertExactKeys(value, allowed) { const actual = Reflect.ownKeys(value); if (actual.some((key) => typeof key !== "string") || actual.length !== allowed.length || actual.some((key) => !allowed.includes(key))) throw new Error("unknown field"); }
function deepFreeze(value) { if (value && typeof value === "object" && !Object.isFrozen(value)) { for (const child of Object.values(value)) deepFreeze(child); Object.freeze(value); } return value; }
function issuanceError(code) { return new AgentSigningCapabilityIssuanceError(code); }
