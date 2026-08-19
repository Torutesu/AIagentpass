import { withTransaction } from "./repository.mjs";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
const CANONICAL_TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u;
const MAX_BATCH = 500;
const REVOCABLE_SESSION_STATUSES = Object.freeze([
  "challenge_pending", "active", "request_reserved", "signed"
]);

const PUBLIC_MESSAGES = Object.freeze({
  ERR_INPUT: "Agent session lifecycle input is invalid",
  ERR_TENANT_SCOPE: "Agent session lifecycle tenant scope is invalid",
  ERR_DATABASE: "Agent session lifecycle storage is unavailable"
});

export const AGENT_SESSION_LIFECYCLE_ERROR_CODES = Object.freeze(Object.keys(PUBLIC_MESSAGES));

export class AgentSessionLifecycleRepositoryError extends Error {
  constructor(code) {
    super(PUBLIC_MESSAGES[code] ?? PUBLIC_MESSAGES.ERR_DATABASE);
    this.name = "AgentSessionLifecycleRepositoryError";
    this.code = PUBLIC_MESSAGES[code] === undefined ? "ERR_DATABASE" : code;
  }
}

/**
 * Advances the durable grant/session lifecycle without exposing authority
 * rows. Each returned tuple is [grant_count, session_count].
 */
export function createPostgresAgentSessionLifecycleRepository({ client, metrics } = {}) {
  assertClient(client);
  assertMetrics(metrics);

  async function expireDue(input = {}) {
    const values = normalizeExpireInput(input);
    try {
      const result = await withTransaction(client, (tx) => expireDueInTransaction(tx, values));
      if (result.expired > 0) recordMetric("recordAgentSessionLifecycleExpired", result.expired);
      return result.counts;
    } catch (error) {
      throw mapError(error);
    }
  }

  async function revokeAuthority(input = {}) {
    const values = normalizeRevokeInput(input);
    for (let attempt = 0; attempt < 2; attempt += 1) {
      try {
        const result = await withTransaction(client, (tx) => advanceRevocationInTransaction(tx, values));
        if (result.expired > 0) recordMetric("recordAgentSessionLifecycleExpired", result.expired);
        if (result.revoked > 0) recordMetric("recordAgentSessionLifecycleRevoked", result.revoked);
        return result.counts;
      } catch (error) {
        if (attempt === 0 && isExpiryBoundaryRace(error)) continue;
        throw mapError(error);
      }
    }
  }

  async function revokeAuthorityInTransaction(input = {}) {
    if (!isObject(input) || !input.tx || typeof input.tx.query !== "function") throw failure("ERR_INPUT");
    const values = normalizeRevokeInput(input);
    const result = await advanceRevocationInTransaction(input.tx, values);
    return result.counts;
  }

  function recordMetric(method, amount) {
    try { metrics?.[method](amount); } catch { /* Metrics never alter lifecycle outcomes. */ }
  }

  return Object.freeze({ expireDue, revokeAuthority, revokeAuthorityInTransaction });
}

async function expireDueInTransaction(tx, values) {
  await setTenantContext(tx, values.organizationId);
  const result = await tx.query(
    "SELECT public.agentpass_agent_session_lifecycle_expire_due($1::uuid,$2::integer,$3::timestamptz) AS result",
    [values.organizationId, values.limit, values.expiredAt]
  );
  return lifecycleJsonResult(result);
}

async function advanceRevocationInTransaction(tx, values) {
  await setTenantContext(tx, values.organizationId);
  const result = await tx.query(
    "SELECT public.agentpass_agent_session_lifecycle_revoke($1::uuid,$2::uuid,$3::uuid,$4::uuid,$5::uuid,$6::boolean,$7::timestamptz) AS result",
    [values.organizationId, values.deviceId, values.agentId, values.grantId, values.sessionId, values.organizationWide, values.revokedAt]
  );
  return lifecycleJsonResult(result);
}

function lifecycleJsonResult(result) {
  if (rowCount(result) !== 1 || !isObject(result.rows[0]?.result)) throw failure("ERR_DATABASE");
  const value = result.rows[0].result;
  if (!Array.isArray(value.counts) || value.counts.length !== 2
    || !Number.isInteger(value.counts[0]) || !Number.isInteger(value.counts[1])
    || !Number.isInteger(value.expired) || !Number.isInteger(value.revoked)) throw failure("ERR_DATABASE");
  return Object.freeze({ counts: Object.freeze(value.counts), expired: value.expired, revoked: value.revoked });
}

function selectorClauses(values, alias, { sessionColumn }) {
  const clauses = [];
  const params = [];
  for (const [field, column] of [
    ["deviceId", "device_id"],
    ["agentId", "agent_id"],
    ["grantId", "grant_id"],
    ["sessionId", sessionColumn]
  ]) {
    if (values[field] === undefined) continue;
    params.push(values[field]);
    clauses.push(`${alias}.${column}=$${params.length + 1}`);
  }
  return Object.freeze({ text: clauses.length === 0 && values.organizationWide ? "TRUE" : clauses.join(" AND "), params: Object.freeze(params) });
}

async function setTenantContext(tx, organizationId) {
  const configured = await tx.query("SELECT set_config('agentpass.organization_id',$1,true) AS organization_id", [organizationId]);
  if (rowCount(configured) !== 1 || configured.rows[0]?.organization_id !== organizationId) throw new AgentSessionLifecycleRepositoryError("ERR_TENANT_SCOPE");
  const verified = await tx.query("SELECT current_setting('agentpass.organization_id',true) AS organization_id", []);
  if (rowCount(verified) !== 1 || verified.rows[0]?.organization_id !== organizationId) throw new AgentSessionLifecycleRepositoryError("ERR_TENANT_SCOPE");
}

function normalizeExpireInput(input) {
  if (!isObject(input)) throw failure("ERR_INPUT");
  return Object.freeze({
    organizationId: organization(input.organization_id ?? input.organizationId),
    limit: limitValue(input.limit),
    expiredAt: optionalTimestamp(input.expired_at ?? input.expiredAt)
  });
}

function normalizeRevokeInput(input) {
  if (!isObject(input)) throw failure("ERR_INPUT");
  const values = {
    organizationId: organization(input.organization_id ?? input.organizationId),
    deviceId: optionalUuid(input.device_id ?? input.deviceId),
    agentId: optionalUuid(input.agent_id ?? input.agentId),
    grantId: optionalUuid(input.grant_id ?? input.grantId),
    sessionId: optionalUuid(input.session_id ?? input.sessionId),
    organizationWide: input.organization_wide === true || input.organizationWide === true,
    revokedAt: optionalTimestamp(input.revoked_at ?? input.revokedAt)
  };
  if ([values.deviceId, values.agentId, values.grantId, values.sessionId].every((value) => value === undefined) && !values.organizationWide) throw failure("ERR_INPUT");
  if ((input.organization_wide !== undefined || input.organizationWide !== undefined) && !values.organizationWide) throw failure("ERR_INPUT");
  return Object.freeze(values);
}

function lifecycleResult(grants, sessions) {
  const counts = Object.freeze([requiredRowCount(grants), requiredRowCount(sessions)]);
  const rows = [...(grants.rows ?? []), ...(sessions.rows ?? [])];
  const expired = rows.filter((row) => row?.status === "expired").length;
  const revoked = rows.filter((row) => row?.status === "revoked").length;
  if (expired + revoked !== counts[0] + counts[1]) throw failure("ERR_DATABASE");
  return Object.freeze({ counts, expired, revoked });
}

function rowCount(result) {
  return Number.isSafeInteger(result?.rowCount) && result.rowCount >= 0 ? result.rowCount : 0;
}

function requiredRowCount(result) {
  if (!Number.isSafeInteger(result?.rowCount) || result.rowCount < 0) throw failure("ERR_DATABASE");
  return result.rowCount;
}

function mapError(error) {
  if (error instanceof AgentSessionLifecycleRepositoryError) return error;
  if (error?.constraint === "agent_session_authority_tenant") return failure("ERR_TENANT_SCOPE");
  if (error?.constraint === "agent_session_authority_lifecycle_limit"
    || error?.constraint === "agent_session_authority_lifecycle_selector") return failure("ERR_INPUT");
  return failure("ERR_DATABASE");
}

function isExpiryBoundaryRace(error) {
  return error?.code === "23514" && new Set([
    "agent_session_grants_expiry_forward_only",
    "agent_sessions_expiry_forward_only"
  ]).has(error?.constraint);
}

function failure(code) {
  return new AgentSessionLifecycleRepositoryError(code);
}

function assertClient(client) {
  if (!client || typeof client.query !== "function") throw failure("ERR_DATABASE");
}

function assertMetrics(metrics) {
  if (metrics === undefined) return;
  for (const method of ["recordAgentSessionLifecycleExpired", "recordAgentSessionLifecycleRevoked"]) {
    if (typeof metrics?.[method] !== "function") throw new TypeError(`${method}() is required`);
  }
}

function assertUuid(value) {
  if (typeof value !== "string" || !UUID.test(value)) throw failure("ERR_INPUT");
  return value.toLowerCase();
}

function organization(value) {
  try { return assertUuid(value); }
  catch { throw failure("ERR_TENANT_SCOPE"); }
}

function optionalUuid(value) {
  return value === undefined ? undefined : assertUuid(value);
}

function limitValue(value) {
  const candidate = value === undefined ? MAX_BATCH : typeof value === "string" && /^[0-9]+$/u.test(value) ? Number(value) : value;
  if (!Number.isSafeInteger(candidate) || candidate < 1 || candidate > MAX_BATCH) throw failure("ERR_INPUT");
  return candidate;
}

function optionalTimestamp(value) {
  if (value === undefined) return null;
  const date = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(date.getTime())) throw failure("ERR_INPUT");
  const result = date.toISOString();
  if (!CANONICAL_TIMESTAMP.test(result)) throw failure("ERR_INPUT");
  return result;
}

function isObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
