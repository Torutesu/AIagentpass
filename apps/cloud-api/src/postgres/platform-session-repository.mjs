import { hashPlatformSessionToken, isPlatformSessionToken } from "../platform-session-transport.mjs";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
const RFC3339 = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$/u;
const OPERATION = /^[a-z][a-z0-9]*(?:[._:-][a-z0-9]+){0,15}$/u;
const CAPABILITIES = new Set([
  "platform.assignment.manage",
  "platform.promotion.issue",
  "platform.promotion.replay",
  "platform.promotion.verify",
  "platform.promotion.reconcile"
]);
const SESSION_STATUSES = new Set(["active", "expired", "revoked"]);
const MAX_OPERATION_LENGTH = 128;

const SESSION_KEYS = Object.freeze([
  "assignment_id", "assignment_version", "authenticated_at", "capability", "created_at",
  "credential_id", "credential_version", "expired_at", "expires_at", "idle_expires_at",
  "last_seen_at", "member_id", "operation", "organization_id", "principal_authority_generation",
  "principal_id", "revoke_reason", "revoked_at", "session_id", "status", "version"
]);

const FIND_INPUT_KEYS = Object.freeze(["capability", "operation", "organization_id", "session_material"]);
const TOUCH_INPUT_KEYS = Object.freeze([...FIND_INPUT_KEYS, "csrf_token"]);
const REVOKE_INPUT_KEYS = Object.freeze(["csrf_token", "session_material_hash"]);
const SHA256_HEX = /^[0-9a-f]{64}$/u;

// The PostgreSQL function is the authority boundary.  The raw bearer never
// appears in these parameters: normalizeSessionMaterial returns only a digest.
export const PLATFORM_SESSION_FIND_ACTIVE_SQL =
  "SELECT agentpass_platform_session_find_active($1::bytea,$2::uuid,$3::text,$4::text) AS session";
export const PLATFORM_SESSION_TOUCH_SQL =
  "SELECT agentpass_platform_session_touch($1::bytea,$2::bytea,$3::uuid,$4::text,$5::text) AS session";
export const PLATFORM_SESSION_REVOKE_SELF_SQL =
  "SELECT agentpass_platform_session_revoke($1::bytea,$2::bytea,$3::text) AS result";

export const PLATFORM_SESSION_REPOSITORY_ERROR_CODES = Object.freeze({
  CONFIG: "ERR_PLATFORM_SESSION_REPOSITORY_CONFIG",
  INPUT: "ERR_PLATFORM_SESSION_REPOSITORY_INPUT",
  RESULT: "ERR_PLATFORM_SESSION_REPOSITORY_RESULT",
  DATABASE: "ERR_PLATFORM_SESSION_REPOSITORY_DATABASE"
});

const MESSAGES = Object.freeze({
  [PLATFORM_SESSION_REPOSITORY_ERROR_CODES.CONFIG]: "platform session repository configuration is invalid",
  [PLATFORM_SESSION_REPOSITORY_ERROR_CODES.INPUT]: "platform session request is invalid",
  [PLATFORM_SESSION_REPOSITORY_ERROR_CODES.RESULT]: "platform session returned an invalid database result",
  [PLATFORM_SESSION_REPOSITORY_ERROR_CODES.DATABASE]: "platform session storage is unavailable"
});

export class PlatformSessionRepositoryError extends Error {
  constructor(code) {
    super(MESSAGES[code] ?? MESSAGES[PLATFORM_SESSION_REPOSITORY_ERROR_CODES.DATABASE]);
    this.name = "PlatformSessionRepositoryError";
    this.code = Object.hasOwn(MESSAGES, code)
      ? code
      : PLATFORM_SESSION_REPOSITORY_ERROR_CODES.DATABASE;
  }
}

/**
 * PostgreSQL adapter for the public platform-session lifecycle boundary.
 *
 * This adapter intentionally exposes only lookup and idle refresh.
 * Credential provisioning, WebAuthn counter advancement, and session issue
 * are administrative/verified-ceremony operations and are not reachable from
 * this public repository interface. Revocation is withheld until a runtime
 * procedure binds the target to the presented bearer hash; the current
 * migrator-only session-id procedure is not a safe public seam.
 */
export function createPostgresPlatformSessionRepository({ client } = {}) {
  if (!client || typeof client.query !== "function") {
    throw repositoryError(PLATFORM_SESSION_REPOSITORY_ERROR_CODES.CONFIG);
  }

  async function findActivePlatformSession(...args) {
    if (args.length !== 1) throw repositoryError(PLATFORM_SESSION_REPOSITORY_ERROR_CODES.INPUT);
    const values = normalizeLookupInputSafely(args[0]);
    return callFunction(
      PLATFORM_SESSION_FIND_ACTIVE_SQL,
      [values.session_material_hash, values.organization_id, values.operation, values.capability],
      (result) => normalizeSessionLookupResult(result, values, true)
    );
  }

  async function touchPlatformSession(...args) {
    if (args.length !== 1) throw repositoryError(PLATFORM_SESSION_REPOSITORY_ERROR_CODES.INPUT);
    const values = normalizeTouchInputSafely(args[0]);
    return callFunction(
      PLATFORM_SESSION_TOUCH_SQL,
      [values.session_material_hash, values.csrf_token_hash, values.organization_id, values.operation, values.capability],
      (result) => normalizeSessionLookupResult(result, values, false)
    );
  }

  async function revokeSelf(...args) {
    if (args.length !== 1) throw repositoryError(PLATFORM_SESSION_REPOSITORY_ERROR_CODES.INPUT);
    const values = normalizeRevokeInputSafely(args[0]);
    return callFunction(
      PLATFORM_SESSION_REVOKE_SELF_SQL,
      [values.session_material_hash, values.csrf_token_hash, "self_revoke"],
      normalizeRevokeResult
    );
  }

  return Object.freeze({
    bearerBound: true,
    acceptsSessionMaterialHash: true,
    findActivePlatformSession,
    touchPlatformSession,
    revokeSelf
  });

  async function callFunction(sql, params, normalizeResult) {
    let result;
    try {
      result = await client.query(sql, params);
    } catch {
      throw repositoryError(PLATFORM_SESSION_REPOSITORY_ERROR_CODES.DATABASE);
    }
    try {
      return normalizeResult(result);
    } catch (error) {
      if (error instanceof PlatformSessionRepositoryError) throw error;
      throw repositoryError(PLATFORM_SESSION_REPOSITORY_ERROR_CODES.RESULT);
    }
  }
}

function normalizeLookupInputSafely(value) {
  try {
    return normalizeLookupInput(value);
  } catch (error) {
    if (error instanceof PlatformSessionRepositoryError) throw error;
    throw repositoryError(PLATFORM_SESSION_REPOSITORY_ERROR_CODES.INPUT);
  }
}

function normalizeTouchInputSafely(value) {
  try {
    if (!isPlainObject(value) || !exactKeys(value, TOUCH_INPUT_KEYS)) throw repositoryError(PLATFORM_SESSION_REPOSITORY_ERROR_CODES.INPUT);
    const lookup = normalizeLookupInput(Object.fromEntries(FIND_INPUT_KEYS.map((key) => [key, value[key]])));
    return Object.freeze({ ...lookup, csrf_token_hash: hashSessionMaterial(value.csrf_token) });
  } catch (error) {
    if (error instanceof PlatformSessionRepositoryError) throw error;
    throw repositoryError(PLATFORM_SESSION_REPOSITORY_ERROR_CODES.INPUT);
  }
}

function normalizeRevokeInputSafely(value) {
  try {
    if (!isPlainObject(value) || !exactKeys(value, REVOKE_INPUT_KEYS)
      || typeof value.session_material_hash !== "string" || !SHA256_HEX.test(value.session_material_hash)) {
      throw repositoryError(PLATFORM_SESSION_REPOSITORY_ERROR_CODES.INPUT);
    }
    return Object.freeze({
      session_material_hash: Buffer.from(value.session_material_hash, "hex"),
      csrf_token_hash: hashSessionMaterial(value.csrf_token)
    });
  } catch (error) {
    if (error instanceof PlatformSessionRepositoryError) throw error;
    throw repositoryError(PLATFORM_SESSION_REPOSITORY_ERROR_CODES.INPUT);
  }
}

function normalizeRevokeResult(result) {
  const row = singleRow(result, "result");
  if (!isPlainObject(row.result) || !["revoked", "already-terminal", "absent"].includes(row.result.outcome)) {
    throw repositoryError(PLATFORM_SESSION_REPOSITORY_ERROR_CODES.RESULT);
  }
  if (row.result.outcome === "absent") return Object.freeze({ revoked: false });
  const session = normalizeSession(row.result.session);
  if (session.status !== "revoked" && row.result.outcome === "revoked") throw repositoryError(PLATFORM_SESSION_REPOSITORY_ERROR_CODES.RESULT);
  return Object.freeze({ revoked: true, session });
}

function normalizeLookupInput(value) {
  if (!isPlainObject(value) || !exactKeys(value, FIND_INPUT_KEYS)) throw repositoryError(PLATFORM_SESSION_REPOSITORY_ERROR_CODES.INPUT);
  const capability = capabilityValue(value.capability);
  const operation = operationValue(value.operation);
  if (operation !== capability) throw repositoryError(PLATFORM_SESSION_REPOSITORY_ERROR_CODES.INPUT);
  return Object.freeze({
    capability,
    operation,
    organization_id: uuidValue(value.organization_id),
    session_material_hash: hashSessionMaterial(value.session_material)
  });
}

function normalizeSessionLookupResult(result, input, findOnly) {
  const row = singleRow(result, "session");
  if (row.session === null) return null;
  const session = normalizeSession(row.session);
  if (session.organization_id !== input.organization_id
    || session.operation !== input.operation
    || session.capability !== input.capability) {
    throw repositoryError(PLATFORM_SESSION_REPOSITORY_ERROR_CODES.RESULT);
  }
  if (findOnly && session.status !== "active") {
    throw repositoryError(PLATFORM_SESSION_REPOSITORY_ERROR_CODES.RESULT);
  }
  return session;
}

function singleRow(result, key) {
  if (!result || result.rowCount !== 1 || !Array.isArray(result.rows) || result.rows.length !== 1
    || !isPlainObject(result.rows[0]) || !exactKeys(result.rows[0], [key])) {
    throw repositoryError(PLATFORM_SESSION_REPOSITORY_ERROR_CODES.RESULT);
  }
  return result.rows[0];
}

function normalizeSession(value) {
  if (!isPlainObject(value) || !exactKeys(value, SESSION_KEYS)) {
    throw repositoryError(PLATFORM_SESSION_REPOSITORY_ERROR_CODES.RESULT);
  }

  const session = {
    assignment_id: uuidValue(value.assignment_id, PLATFORM_SESSION_REPOSITORY_ERROR_CODES.RESULT),
    assignment_version: positiveInteger(value.assignment_version),
    authenticated_at: timestampValue(value.authenticated_at),
    capability: capabilityValue(value.capability, PLATFORM_SESSION_REPOSITORY_ERROR_CODES.RESULT),
    created_at: timestampValue(value.created_at),
    credential_id: uuidValue(value.credential_id, PLATFORM_SESSION_REPOSITORY_ERROR_CODES.RESULT),
    credential_version: positiveInteger(value.credential_version),
    expired_at: nullableTimestamp(value.expired_at),
    expires_at: timestampValue(value.expires_at),
    idle_expires_at: timestampValue(value.idle_expires_at),
    last_seen_at: timestampValue(value.last_seen_at),
    member_id: uuidValue(value.member_id, PLATFORM_SESSION_REPOSITORY_ERROR_CODES.RESULT),
    operation: operationValue(value.operation, PLATFORM_SESSION_REPOSITORY_ERROR_CODES.RESULT),
    organization_id: uuidValue(value.organization_id, PLATFORM_SESSION_REPOSITORY_ERROR_CODES.RESULT),
    principal_authority_generation: positiveInteger(value.principal_authority_generation),
    principal_id: uuidValue(value.principal_id, PLATFORM_SESSION_REPOSITORY_ERROR_CODES.RESULT),
    revoke_reason: nullableReason(value.revoke_reason),
    revoked_at: nullableTimestamp(value.revoked_at),
    session_id: uuidValue(value.session_id, PLATFORM_SESSION_REPOSITORY_ERROR_CODES.RESULT),
    status: statusValue(value.status),
    version: positiveInteger(value.version)
  };

  if (session.operation !== session.capability) throw repositoryError(PLATFORM_SESSION_REPOSITORY_ERROR_CODES.RESULT);
  assertSessionInvariants(session);
  return Object.freeze(session);
}

function assertSessionInvariants(session) {
  const created = Date.parse(session.created_at);
  const authenticated = Date.parse(session.authenticated_at);
  const lastSeen = Date.parse(session.last_seen_at);
  const expires = Date.parse(session.expires_at);
  const idleExpires = Date.parse(session.idle_expires_at);
  if (!(created <= authenticated
    && authenticated <= lastSeen
    && lastSeen <= expires
    && authenticated < expires
    && authenticated < idleExpires
    && idleExpires <= expires)) {
    throw repositoryError(PLATFORM_SESSION_REPOSITORY_ERROR_CODES.RESULT);
  }
  if (session.status === "active" && (session.expired_at !== null || session.revoked_at !== null)) {
    throw repositoryError(PLATFORM_SESSION_REPOSITORY_ERROR_CODES.RESULT);
  }
  if (session.status === "expired" && (session.expired_at === null || session.revoked_at !== null)) {
    throw repositoryError(PLATFORM_SESSION_REPOSITORY_ERROR_CODES.RESULT);
  }
  if (session.status === "revoked" && (session.revoked_at === null || session.expired_at !== null)) {
    throw repositoryError(PLATFORM_SESSION_REPOSITORY_ERROR_CODES.RESULT);
  }
  if (session.expired_at !== null && Date.parse(session.expired_at) < created) {
    throw repositoryError(PLATFORM_SESSION_REPOSITORY_ERROR_CODES.RESULT);
  }
  if (session.revoked_at !== null && Date.parse(session.revoked_at) < created) {
    throw repositoryError(PLATFORM_SESSION_REPOSITORY_ERROR_CODES.RESULT);
  }
}

function hashSessionMaterial(value) {
  if (!isPlatformSessionToken(value)) throw repositoryError(PLATFORM_SESSION_REPOSITORY_ERROR_CODES.INPUT);
  return Buffer.from(hashPlatformSessionToken(value), "hex");
}

function uuidValue(value, code = PLATFORM_SESSION_REPOSITORY_ERROR_CODES.INPUT) {
  if (typeof value !== "string" || !UUID.test(value)) throw repositoryError(code);
  return value.toLowerCase();
}

function operationValue(value, code = PLATFORM_SESSION_REPOSITORY_ERROR_CODES.INPUT) {
  if (typeof value !== "string" || value.length < 1 || value.length > MAX_OPERATION_LENGTH || !OPERATION.test(value)) {
    throw repositoryError(code);
  }
  return value;
}

function capabilityValue(value, code = PLATFORM_SESSION_REPOSITORY_ERROR_CODES.INPUT) {
  if (typeof value !== "string" || !CAPABILITIES.has(value)) throw repositoryError(code);
  return value;
}

function nullableReason(value) {
  if (value === null) return null;
  if (typeof value !== "string" || value.length < 1 || value.length > 256 || /[\u0000-\u001f\u007f]/u.test(value)) {
    throw repositoryError(PLATFORM_SESSION_REPOSITORY_ERROR_CODES.RESULT);
  }
  return value;
}

function statusValue(value) {
  if (typeof value !== "string" || !SESSION_STATUSES.has(value)) throw repositoryError(PLATFORM_SESSION_REPOSITORY_ERROR_CODES.RESULT);
  return value;
}

function positiveInteger(value) {
  if (!Number.isSafeInteger(value) || value < 1) throw repositoryError(PLATFORM_SESSION_REPOSITORY_ERROR_CODES.RESULT);
  return value;
}

function timestampValue(value) {
  if (typeof value !== "string" || !RFC3339.test(value)) throw repositoryError(PLATFORM_SESSION_REPOSITORY_ERROR_CODES.RESULT);
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)) throw repositoryError(PLATFORM_SESSION_REPOSITORY_ERROR_CODES.RESULT);
  return new Date(parsed).toISOString();
}

function nullableTimestamp(value) {
  return value === null ? null : timestampValue(value);
}

function exactKeys(value, expected) {
  const keys = Reflect.ownKeys(value);
  return keys.length === expected.length && keys.every((key) => typeof key === "string"
    && expected.includes(key) && Object.getOwnPropertyDescriptor(value, key)?.enumerable === true);
}

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    && (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null);
}

function repositoryError(code) {
  return new PlatformSessionRepositoryError(code);
}

export default createPostgresPlatformSessionRepository;
