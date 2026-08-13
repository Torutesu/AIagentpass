import crypto from "node:crypto";

import {
  AGENT_SESSION_GRANT_ISSUER,
  AGENT_SESSION_GRANT_TYPE,
  agentSessionGrantSigningData,
  agentSessionGrantStatementHash,
  normalizeAgentSessionGrantStatement
} from "../../agent-session-grant.mjs";
import { canonicalJson, normalizeScope as normalizeScopePrimitive } from "../../../../../packages/protocol/src/index.mjs";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
const SHA256_HEX = /^[0-9a-f]{64}$/u;
const SAFE_IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$/u;
const SEMVER = /^(?:0|[1-9][0-9]{0,8})\.(?:0|[1-9][0-9]{0,8})\.(?:0|[1-9][0-9]{0,8})(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/u;
const CANONICAL_TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u;
const SIGNATURE_BASE64URL = /^[A-Za-z0-9_-]{86}$/u;
const IDEMPOTENCY_KEY = /^[A-Za-z0-9._~-]{8,255}$/u;
const AGENT_KINDS = new Set(["claude-code", "cursor"]);
const ADMIN_ROLES = new Set(["owner", "admin"]);
const MAX_SCOPE_ITEMS = 64;
const MAX_TTL_SECONDS = 3_600;
const MIN_TTL_SECONDS = 60;

export const AGENT_SESSION_GRANT_REPOSITORY_METHODS = Object.freeze([
  "issueAgentSessionGrant"
]);

export const AGENT_SESSION_GRANT_SIGNER_METHODS = Object.freeze(["signAgentSessionGrant"]);

export const AGENT_SESSION_GRANT_ISSUANCE_ERROR_CODES = Object.freeze({
  INVALID_REQUEST: "agent_session_grant_invalid_request",
  FORBIDDEN: "agent_session_grant_forbidden",
  NOT_FOUND: "agent_session_grant_not_found",
  IDEMPOTENCY_CONFLICT: "agent_session_grant_idempotency_conflict",
  UNAVAILABLE: "agent_session_grant_unavailable",
  SIGNER_UNAVAILABLE: "agent_session_grant_signer_unavailable",
  INTERNAL_ERROR: "agent_session_grant_internal_error"
});

const ERROR_MESSAGES = Object.freeze({
  [AGENT_SESSION_GRANT_ISSUANCE_ERROR_CODES.INVALID_REQUEST]: "The agent session grant request is invalid",
  [AGENT_SESSION_GRANT_ISSUANCE_ERROR_CODES.FORBIDDEN]: "The authenticated human is not allowed to issue this grant",
  [AGENT_SESSION_GRANT_ISSUANCE_ERROR_CODES.NOT_FOUND]: "The requested agent session resource was not found",
  [AGENT_SESSION_GRANT_ISSUANCE_ERROR_CODES.IDEMPOTENCY_CONFLICT]: "The idempotency key conflicts with another request",
  [AGENT_SESSION_GRANT_ISSUANCE_ERROR_CODES.UNAVAILABLE]: "The agent session grant service is unavailable",
  [AGENT_SESSION_GRANT_ISSUANCE_ERROR_CODES.SIGNER_UNAVAILABLE]: "The agent session grant signer is unavailable",
  [AGENT_SESSION_GRANT_ISSUANCE_ERROR_CODES.INTERNAL_ERROR]: "The request could not be completed"
});

export class AgentSessionGrantIssuanceError extends Error {
  constructor(code, { cause = undefined } = {}) {
    super(ERROR_MESSAGES[code] ?? ERROR_MESSAGES[AGENT_SESSION_GRANT_ISSUANCE_ERROR_CODES.INTERNAL_ERROR], { cause });
    this.name = "AgentSessionGrantIssuanceError";
    this.code = code;
  }
}

/**
 * Create the M2-A grant issuance service.
 *
 * Repository contract (the adapter owns the database transaction):
 *
 *   issueAgentSessionGrant({
 *     actor, organization_id, agent_id, device_id, intent,
 *     idempotency_key, request_fingerprint, request_id, grant_id,
 *     issued_at, not_before, expires_at, buildGrant, recent_auth
 *   }) -> Promise<{ grant, request_id, replayed? }>
 *
 * The adapter must verify the actor and the organization/device/agent
 * composite identity again, set the PostgreSQL tenant context, lock the
 * authority row, allocate a positive control_sequence, and call buildGrant
 * only for a new idempotency record. It must atomically persist the signed
 * grant, idempotency result, immutable admin audit event, and publication
 * intent. A retry with the same canonical request returns the committed
 * result; a different request raises idempotency_key_reused. No database
 * implementation is embedded in this service.
 *
 * Signer contract:
 *   signer.key_id (or signer.keyId) -> safe identifier
 *   signer.signAgentSessionGrant(statement) -> a complete signed grant
 *
 * A narrow test adapter may expose signer.sign({ algorithm: "ed25519",
 * key_id, statement_hash, statement, message }) instead; production callers
 * should use the shared signer primitive above.
 *
 * `message` is the domain-separated canonical statement bytes. It never
 * contains private key material, and the signer adapter must keep its private
 * key outside this service boundary.
 */
export function createAgentSessionGrantIssuanceService({
  repository,
  signer,
  signerKeyId = undefined,
  keyId = undefined,
  clock = { now: () => Date.now() },
  now = undefined,
  uuid = crypto.randomUUID
} = {}) {
  assertRepository(repository);
  const configuredSignerKeyId = signerKeyId ?? keyId;
  assertSigner(signer, configuredSignerKeyId);
  const readClock = normalizeClock(clock, now);
  if (typeof uuid !== "function") throw new TypeError("uuid must be a function");

  async function issue(input = {}) {
    const actor = normalizeActor(input.actor);
    const organizationId = requiredUuid(input.organization_id, "organization_id");
    const agentId = requiredUuid(input.agent_id, "agent_id");
    if (actor.organization_id !== organizationId) throw issuanceError(AGENT_SESSION_GRANT_ISSUANCE_ERROR_CODES.NOT_FOUND);
    if (!ADMIN_ROLES.has(actor.role)) throw issuanceError(AGENT_SESSION_GRANT_ISSUANCE_ERROR_CODES.FORBIDDEN);

    const intent = normalizeIntent(input.intent ?? input.request);
    const idempotencyKey = requiredIdempotencyKey(input.idempotency_key);
    const issuedAtMs = readNow(readClock);
    const issuedAt = canonicalTimestamp(issuedAtMs);
    const ttlMs = intent.ttl_seconds * 1_000;
    if (issuedAtMs > Number.MAX_SAFE_INTEGER - ttlMs) throw issuanceError(AGENT_SESSION_GRANT_ISSUANCE_ERROR_CODES.UNAVAILABLE);
    const expiresAt = canonicalTimestamp(issuedAtMs + ttlMs);
    const recentAuth = normalizeRecentAuthorization(input.recent_authorization ?? input.recent_auth, actor, organizationId, issuedAtMs);
    const requestFingerprint = sha256(canonicalJson({
      organization_id: organizationId,
      agent_id: agentId,
      ...intent
    }));
    const grantId = createUuid(uuid, "grant_id");
    const requestId = createUuid(uuid, "request_id");

    let result;
    try {
      result = await repository.issueAgentSessionGrant({
        actor,
        organization_id: organizationId,
        agent_id: agentId,
        device_id: intent.device_id,
        intent,
        idempotency_key: idempotencyKey,
        request_fingerprint: requestFingerprint,
        request_id: requestId,
        grant_id: grantId,
        issued_at: issuedAt,
        not_before: issuedAt,
        expires_at: expiresAt,
        recent_auth: recentAuth,
        buildGrant: async ({ control_sequence } = {}) => buildSignedGrant({
          grantId,
          organizationId,
          agentId,
          intent,
          issuedAt,
          expiresAt,
          controlSequence: control_sequence
        })
      });
    } catch (error) {
      throw mapRepositoryError(error);
    }

    return normalizeRepositoryResult(result, requestId, { organizationId, agentId, intent });
  }

  async function buildSignedGrant({ grantId, organizationId, agentId, intent, issuedAt, expiresAt, controlSequence } = {}) {
    if (!Number.isSafeInteger(controlSequence) || controlSequence < 1) {
      throw issuanceError(AGENT_SESSION_GRANT_ISSUANCE_ERROR_CODES.UNAVAILABLE);
    }
    const keyId = resolvedSignerKeyId(signer, configuredSignerKeyId);
    const statementInput = {
      version: 1,
      grant_id: grantId,
      organization_id: organizationId,
      device_id: intent.device_id,
      agent_id: agentId,
      agent_kind: intent.agent_kind,
      adapter_id: intent.adapter_id,
      adapter_version: intent.adapter_version,
      worktree_binding_sha256: intent.worktree_binding_sha256,
      process_binding_policy_id: intent.process_binding_policy_id,
      scope: intent.scope,
      max_signatures: intent.max_signatures,
      not_before: issuedAt,
      expires_at: expiresAt,
      control_sequence: controlSequence,
      issuer: AGENT_SESSION_GRANT_ISSUER,
      key_id: keyId
    };
    let statement;
    try {
      statement = normalizeAgentSessionGrantStatement(statementInput, {
        now: Date.parse(issuedAt),
        allowExpired: false,
        allowFuture: false,
        maxTtlMs: MAX_TTL_SECONDS * 1_000
      });
    } catch (error) {
      throw issuanceError(AGENT_SESSION_GRANT_ISSUANCE_ERROR_CODES.UNAVAILABLE, { cause: error });
    }
    const statementBytes = agentSessionGrantSigningData(statement);
    const statementHash = agentSessionGrantStatementHash(statement);
    let signed;
    try {
      if (typeof signer.signAgentSessionGrant === "function") {
        signed = await signer.signAgentSessionGrant(statement);
      } else {
        const output = await signer.sign(Object.freeze({
          algorithm: "ed25519",
          key_id: keyId,
          statement_hash: statementHash,
          statement,
          message: Buffer.from(statementBytes)
        }));
        signed = { version: 1, type: AGENT_SESSION_GRANT_TYPE, statement, statement_hash: statementHash, signature: output?.signature ?? output };
      }
    } catch (error) {
      throw issuanceError(AGENT_SESSION_GRANT_ISSUANCE_ERROR_CODES.SIGNER_UNAVAILABLE, { cause: error });
    }
    let grant;
    try {
      grant = normalizeSignedGrant(signed, statement, statementHash);
    } catch (error) {
      throw issuanceError(AGENT_SESSION_GRANT_ISSUANCE_ERROR_CODES.SIGNER_UNAVAILABLE, { cause: error });
    }
    return Object.freeze({
      grant,
      grant_hash: sha256(canonicalJson(grant)),
      statement_hash: statementHash,
      control_sequence: controlSequence
    });
  }

  return Object.freeze({
    issue,
    issueGrant: issue,
    issueAgentSessionGrant: issue,
    buildSignedGrant
  });
}

export const createHumanAgentSessionGrantIssuanceService = createAgentSessionGrantIssuanceService;

export function normalizeAgentSessionGrantIssueIntent(value) {
  return normalizeIntent(value);
}

function assertRepository(value) {
  if (!value || typeof value !== "object") throw new TypeError("agent session grant repository is required");
  for (const method of AGENT_SESSION_GRANT_REPOSITORY_METHODS) {
    if (typeof value[method] !== "function") throw new TypeError(`agent session grant repository is missing ${method}()`);
  }
}

function assertSigner(value, configuredKeyId) {
  if (!value || typeof value !== "object" || (typeof value.sign !== "function" && typeof value.signAgentSessionGrant !== "function")) throw new TypeError("agent session grant signer must expose sign() or signAgentSessionGrant()");
  const keyId = configuredKeyId ?? value.key_id ?? value.keyId;
  if (!isSafeIdentifier(keyId)) throw new TypeError("agent session grant signer key_id is invalid");
  if (value.algorithm !== undefined && value.algorithm !== "ed25519") throw new TypeError("agent session grant signer must use Ed25519");
}

function resolvedSignerKeyId(signer, configuredKeyId) {
  const keyId = configuredKeyId ?? signer.key_id ?? signer.keyId;
  if (!isSafeIdentifier(keyId)) throw issuanceError(AGENT_SESSION_GRANT_ISSUANCE_ERROR_CODES.SIGNER_UNAVAILABLE);
  return keyId;
}

function normalizeClock(clock, now) {
  const candidate = now ?? (typeof clock === "function" ? clock : clock?.now);
  if (typeof candidate !== "function") throw new TypeError("clock must expose now()");
  return candidate;
}

function readNow(clock) {
  let value;
  try { value = clock(); } catch (error) { throw issuanceError(AGENT_SESSION_GRANT_ISSUANCE_ERROR_CODES.UNAVAILABLE, { cause: error }); }
  if (!Number.isSafeInteger(value) || value < 0) throw issuanceError(AGENT_SESSION_GRANT_ISSUANCE_ERROR_CODES.UNAVAILABLE);
  return value;
}

function createUuid(uuid, label) {
  let value;
  try { value = uuid(); } catch (error) { throw issuanceError(AGENT_SESSION_GRANT_ISSUANCE_ERROR_CODES.UNAVAILABLE, { cause: error }); }
  if (!isUuid(value)) throw issuanceError(AGENT_SESSION_GRANT_ISSUANCE_ERROR_CODES.UNAVAILABLE);
  return value.toLowerCase();
}

function normalizeActor(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw issuanceError(AGENT_SESSION_GRANT_ISSUANCE_ERROR_CODES.FORBIDDEN);
  const actor = {
    session_id: requiredUuid(value.session_id, "session_id"),
    member_id: requiredUuid(value.member_id, "member_id"),
    organization_id: requiredUuid(value.organization_id, "organization_id"),
    role: value.role
  };
  if (!ADMIN_ROLES.has(actor.role)) throw issuanceError(AGENT_SESSION_GRANT_ISSUANCE_ERROR_CODES.FORBIDDEN);
  return Object.freeze(actor);
}

function normalizeIntent(value) {
  if (!isPlainObject(value)) throw issuanceError(AGENT_SESSION_GRANT_ISSUANCE_ERROR_CODES.INVALID_REQUEST);
  const expected = ["adapter_id", "adapter_version", "agent_kind", "device_id", "max_signatures", "process_binding_policy_id", "scope", "ttl_seconds", "worktree_binding_sha256"];
  exactKeys(value, expected);
  const intent = {
    device_id: requiredUuid(value.device_id, "device_id"),
    agent_kind: value.agent_kind,
    adapter_id: requiredUuid(value.adapter_id, "adapter_id"),
    adapter_version: value.adapter_version,
    worktree_binding_sha256: value.worktree_binding_sha256,
    process_binding_policy_id: value.process_binding_policy_id,
    scope: normalizeScope(value.scope),
    max_signatures: value.max_signatures,
    ttl_seconds: value.ttl_seconds
  };
  if (!AGENT_KINDS.has(intent.agent_kind)) invalid();
  if (typeof intent.adapter_version !== "string" || !SEMVER.test(intent.adapter_version)) invalid();
  if (!isSha256(intent.worktree_binding_sha256)) invalid();
  if (!isSafeIdentifier(intent.process_binding_policy_id)) invalid();
  if (!Number.isSafeInteger(intent.max_signatures) || intent.max_signatures < 1 || intent.max_signatures > 64) invalid();
  if (!Number.isSafeInteger(intent.ttl_seconds) || intent.ttl_seconds < MIN_TTL_SECONDS || intent.ttl_seconds > MAX_TTL_SECONDS) invalid();
  return Object.freeze(intent);
}

function normalizeScope(value) {
  if (!isPlainObject(value)) invalid();
  try {
    const normalized = normalizeScopePrimitive(value);
    for (const list of [normalized.operations, normalized.repositories, normalized.branches.allow, normalized.branches.deny, normalized.remotes.allow, normalized.remotes.deny, normalized.tags?.allow ?? [], normalized.tags?.deny ?? []]) {
      if (list.length > MAX_SCOPE_ITEMS || new Set(list).size !== list.length) invalid();
    }
    return normalized;
  } catch (error) {
    if (error instanceof AgentSessionGrantIssuanceError) throw error;
    invalid();
  }
}

function normalizeRecentAuthorization(value, actor, organizationId, nowMs) {
  if (!isPlainObject(value)) throw issuanceError(AGENT_SESSION_GRANT_ISSUANCE_ERROR_CODES.INVALID_REQUEST);
  const authorizationId = value.authorization_id ?? value.challenge_id;
  if (!isUuid(authorizationId) || value.organization_id !== undefined && value.organization_id !== organizationId || value.member_id !== undefined && value.member_id !== actor.member_id || value.operation !== undefined && value.operation !== "agent.session_grant.issue" || value.verified !== undefined && value.verified !== true || value.consumed !== undefined && value.consumed !== true) {
    throw issuanceError(AGENT_SESSION_GRANT_ISSUANCE_ERROR_CODES.FORBIDDEN);
  }
  const authenticatedAt = value.authenticated_at;
  if (!Number.isSafeInteger(authenticatedAt) || authenticatedAt < 0 || authenticatedAt > nowMs + 30_000 || nowMs - authenticatedAt > 5 * 60_000) {
    throw issuanceError(AGENT_SESSION_GRANT_ISSUANCE_ERROR_CODES.FORBIDDEN);
  }
  return Object.freeze({ authorization_id: authorizationId.toLowerCase(), authenticated_at: authenticatedAt });
}

function normalizeRepositoryResult(result, fallbackRequestId, { organizationId, agentId, intent }) {
  if (!isPlainObject(result)) throw issuanceError(AGENT_SESSION_GRANT_ISSUANCE_ERROR_CODES.UNAVAILABLE);
  const grant = result.grant ?? result;
  const requestId = result.request_id ?? fallbackRequestId;
  if (!isUuid(requestId)) throw issuanceError(AGENT_SESSION_GRANT_ISSUANCE_ERROR_CODES.UNAVAILABLE);
  normalizeGrant(grant, { organizationId, agentId, intent });
  return Object.freeze({ grant: deepFreeze(cloneJson(grant)), request_id: requestId.toLowerCase(), ...(result.replayed === true ? { replayed: true } : {}) });
}

function normalizeGrant(value, expected = undefined) {
  if (!isPlainObject(value)) throw issuanceError(AGENT_SESSION_GRANT_ISSUANCE_ERROR_CODES.UNAVAILABLE);
  exactKeys(value, ["signature", "statement", "statement_hash", "type", "version"]);
  if (value.version !== 1 || value.type !== AGENT_SESSION_GRANT_TYPE || !isSha256(value.statement_hash) || !SIGNATURE_BASE64URL.test(value.signature)) throw issuanceError(AGENT_SESSION_GRANT_ISSUANCE_ERROR_CODES.UNAVAILABLE);
  if (Buffer.from(value.signature, "base64url").length !== 64) throw issuanceError(AGENT_SESSION_GRANT_ISSUANCE_ERROR_CODES.UNAVAILABLE);
  let normalizedStatement;
  try { normalizedStatement = normalizeAgentSessionGrantStatement(value.statement); } catch (error) { throw issuanceError(AGENT_SESSION_GRANT_ISSUANCE_ERROR_CODES.UNAVAILABLE, { cause: error }); }
  const expectedHash = agentSessionGrantStatementHash(normalizedStatement);
  if (value.statement_hash !== expectedHash) throw issuanceError(AGENT_SESSION_GRANT_ISSUANCE_ERROR_CODES.UNAVAILABLE);
  if (expected !== undefined) assertGrantBinding(normalizedStatement, expected);
  return normalizedStatement;
}

function assertGrantBinding(statement, { organizationId, agentId, intent }) {
  if (statement.organization_id !== organizationId
    || statement.agent_id !== agentId
    || statement.device_id !== intent.device_id
    || statement.agent_kind !== intent.agent_kind
    || statement.adapter_id !== intent.adapter_id
    || statement.adapter_version !== intent.adapter_version
    || statement.worktree_binding_sha256 !== intent.worktree_binding_sha256
    || statement.process_binding_policy_id !== intent.process_binding_policy_id
    || statement.max_signatures !== intent.max_signatures
    || canonicalJson(statement.scope) !== canonicalJson(intent.scope)
    || statement.issuer !== AGENT_SESSION_GRANT_ISSUER) {
    throw issuanceError(AGENT_SESSION_GRANT_ISSUANCE_ERROR_CODES.UNAVAILABLE);
  }
}

function normalizeSignedGrant(value, statement, statementHash) {
  const candidate = value && typeof value === "object" && !Buffer.isBuffer(value) && !(value instanceof Uint8Array) ? value.signature : value;
  if (value && typeof value === "object" && !Buffer.isBuffer(value) && !(value instanceof Uint8Array)) {
    if (value.version !== 1 || value.type !== AGENT_SESSION_GRANT_TYPE || value.statement_hash !== statementHash || canonicalJson(value.statement) !== canonicalJson(statement)) throw new Error("signer returned a mismatched grant");
  }
  if (Buffer.isBuffer(candidate) || candidate instanceof Uint8Array) {
    if (candidate.length !== 64) throw issuanceError(AGENT_SESSION_GRANT_ISSUANCE_ERROR_CODES.SIGNER_UNAVAILABLE);
    return Object.freeze({ version: 1, type: AGENT_SESSION_GRANT_TYPE, statement, statement_hash: statementHash, signature: Buffer.from(candidate).toString("base64url") });
  }
  if (typeof candidate !== "string" || !SIGNATURE_BASE64URL.test(candidate) || Buffer.from(candidate, "base64url").length !== 64 || Buffer.from(candidate, "base64url").toString("base64url") !== candidate) throw issuanceError(AGENT_SESSION_GRANT_ISSUANCE_ERROR_CODES.SIGNER_UNAVAILABLE);
  return Object.freeze({ version: 1, type: AGENT_SESSION_GRANT_TYPE, statement, statement_hash: statementHash, signature: candidate });
}

function mapRepositoryError(error) {
  if (error instanceof AgentSessionGrantIssuanceError) return error;
  const code = String(error?.code ?? error?.name ?? "").toLowerCase();
  if (["not_found", "resource_not_found", "tenant_not_found", "organization_not_found", "agent_not_found", "device_not_found"].includes(code)) return issuanceError(AGENT_SESSION_GRANT_ISSUANCE_ERROR_CODES.NOT_FOUND, { cause: error });
  if (["forbidden", "not_authorized", "role_forbidden", "tenant_scope_error"].includes(code)) return issuanceError(AGENT_SESSION_GRANT_ISSUANCE_ERROR_CODES.FORBIDDEN, { cause: error });
  if (["idempotency_conflict", "idempotency_key_reused", "err_idempotency_conflict"].includes(code)) return issuanceError(AGENT_SESSION_GRANT_ISSUANCE_ERROR_CODES.IDEMPOTENCY_CONFLICT, { cause: error });
  if (["invalid_input", "invalid_scope", "validation_error"].includes(code)) return issuanceError(AGENT_SESSION_GRANT_ISSUANCE_ERROR_CODES.INVALID_REQUEST, { cause: error });
  return issuanceError(AGENT_SESSION_GRANT_ISSUANCE_ERROR_CODES.UNAVAILABLE, { cause: error });
}

function issuanceError(code, options = {}) { return new AgentSessionGrantIssuanceError(code, options); }

function requiredIdempotencyKey(value) {
  if (typeof value !== "string" || !IDEMPOTENCY_KEY.test(value)) invalid();
  return value;
}

function requiredUuid(value) {
  if (!isUuid(value)) invalid();
  return value.toLowerCase();
}

function canonicalTimestamp(value) {
  const date = new Date(value);
  const output = date.toISOString();
  if (!CANONICAL_TIMESTAMP.test(output)) throw issuanceError(AGENT_SESSION_GRANT_ISSUANCE_ERROR_CODES.UNAVAILABLE);
  return output;
}

function exactKeys(value, expected) {
  if (Reflect.ownKeys(value).some((key) => typeof key !== "string")) invalid();
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) invalid();
}

function invalid() { throw issuanceError(AGENT_SESSION_GRANT_ISSUANCE_ERROR_CODES.INVALID_REQUEST); }
function isUuid(value) { return typeof value === "string" && UUID.test(value); }
function isSha256(value) { return typeof value === "string" && SHA256_HEX.test(value); }
function isSafeIdentifier(value) { return typeof value === "string" && SAFE_IDENTIFIER.test(value); }
function isPlainObject(value) { return value !== null && typeof value === "object" && !Array.isArray(value) && (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null); }
function sha256(value) { return crypto.createHash("sha256").update(value).digest("hex"); }

function cloneJson(value) {
  if (Array.isArray(value)) return value.map(cloneJson);
  if (value && typeof value === "object") return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, cloneJson(item)]));
  return value;
}

function deepFreeze(value) {
  if (!value || typeof value !== "object" || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}
