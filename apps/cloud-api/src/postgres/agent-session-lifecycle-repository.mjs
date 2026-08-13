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
  const grants = await tx.query(`WITH db_clock AS MATERIALIZED (
      SELECT clock_timestamp() AS now
    ), candidates AS (
      SELECT grant_record.organization_id,grant_record.grant_id
      FROM agent_session_grants AS grant_record
      CROSS JOIN db_clock
      WHERE grant_record.organization_id=$1
        AND grant_record.status='issued'
        AND grant_record.expires_at <= db_clock.now
      ORDER BY grant_record.expires_at ASC,grant_record.grant_id ASC
      LIMIT $2
      FOR UPDATE OF grant_record SKIP LOCKED
    )
    UPDATE agent_session_grants AS grant_record
    SET status='expired',
        expired_at=GREATEST(
          db_clock.now,
          COALESCE($3::timestamptz,db_clock.now),
          grant_record.expires_at
        )
    FROM candidates
    CROSS JOIN db_clock
    WHERE grant_record.organization_id=candidates.organization_id
      AND grant_record.grant_id=candidates.grant_id
      AND grant_record.status='issued'
    RETURNING grant_record.status`, [values.organizationId, values.limit, values.expiredAt]);

  const sessions = await tx.query(`WITH db_clock AS MATERIALIZED (
      SELECT clock_timestamp() AS now
    ), candidates AS (
      SELECT session_record.organization_id,session_record.session_id
      FROM agent_sessions AS session_record
      CROSS JOIN db_clock
      WHERE session_record.organization_id=$1
        AND session_record.status IN (${REVOCABLE_SESSION_STATUSES.map((_, index) => `'${REVOCABLE_SESSION_STATUSES[index]}'`).join(",")})
        AND session_record.expires_at <= db_clock.now
      ORDER BY session_record.expires_at ASC,session_record.session_id ASC
      LIMIT $2
      FOR UPDATE OF session_record SKIP LOCKED
    )
    UPDATE agent_sessions AS session_record
    SET status='expired',
        last_request_id=COALESCE(session_record.last_request_id,session_record.active_request_id),
        active_request_id=NULL,
        expired_at=GREATEST(
          db_clock.now,
          COALESCE($3::timestamptz,db_clock.now),
          session_record.expires_at
        )
    FROM candidates
    CROSS JOIN db_clock
    WHERE session_record.organization_id=candidates.organization_id
      AND session_record.session_id=candidates.session_id
      AND session_record.status IN (${REVOCABLE_SESSION_STATUSES.map((_, index) => `'${REVOCABLE_SESSION_STATUSES[index]}'`).join(",")})
    RETURNING session_record.status`, [values.organizationId, values.limit, values.expiredAt]);

  return lifecycleResult(grants, sessions);
}

async function advanceRevocationInTransaction(tx, values) {
  await setTenantContext(tx, values.organizationId);
  const selectors = selectorClauses(values, "grant_record", { sessionColumn: "consumed_session_id" });
  const revokedAtParameter = 2 + selectors.params.length;
  const grants = await tx.query(`WITH db_clock AS MATERIALIZED (
      SELECT clock_timestamp() AS now
    ), candidates AS (
      SELECT grant_record.organization_id,grant_record.grant_id
      FROM agent_session_grants AS grant_record
      CROSS JOIN db_clock
      WHERE grant_record.organization_id=$1
        AND grant_record.status='issued'
        AND ${selectors.text}
      ORDER BY grant_record.expires_at ASC,grant_record.grant_id ASC
      LIMIT ${MAX_BATCH}
      FOR UPDATE OF grant_record
    )
    UPDATE agent_session_grants AS grant_record
    SET status=CASE WHEN grant_record.expires_at <= db_clock.now THEN 'expired' ELSE 'revoked' END,
        expired_at=CASE WHEN grant_record.expires_at <= db_clock.now
          THEN GREATEST(db_clock.now,COALESCE($${revokedAtParameter}::timestamptz,db_clock.now),grant_record.expires_at)
          ELSE NULL END,
        revoked_at=CASE WHEN grant_record.expires_at <= db_clock.now THEN NULL
          ELSE GREATEST(db_clock.now,COALESCE($${revokedAtParameter}::timestamptz,db_clock.now),grant_record.issued_at) END
    FROM candidates
    CROSS JOIN db_clock
    WHERE grant_record.organization_id=candidates.organization_id
      AND grant_record.grant_id=candidates.grant_id
      AND grant_record.status='issued'
    RETURNING grant_record.status`, [values.organizationId, ...selectors.params, values.revokedAt]);

  const sessionSelectors = selectorClauses(values, "session_record", { sessionColumn: "session_id" });
  const sessions = await tx.query(`WITH db_clock AS MATERIALIZED (
      SELECT clock_timestamp() AS now
    ), candidates AS (
      SELECT session_record.organization_id,session_record.session_id
      FROM agent_sessions AS session_record
      CROSS JOIN db_clock
      WHERE session_record.organization_id=$1
        AND session_record.status IN (${REVOCABLE_SESSION_STATUSES.map((_, index) => `'${REVOCABLE_SESSION_STATUSES[index]}'`).join(",")})
        AND ${sessionSelectors.text}
      ORDER BY session_record.expires_at ASC,session_record.session_id ASC
      LIMIT ${MAX_BATCH}
      FOR UPDATE OF session_record
    )
    UPDATE agent_sessions AS session_record
    SET status=CASE WHEN session_record.expires_at <= db_clock.now THEN 'expired' ELSE 'revoked' END,
        last_request_id=COALESCE(session_record.last_request_id,session_record.active_request_id),
        active_request_id=NULL,
        expired_at=CASE WHEN session_record.expires_at <= db_clock.now
          THEN GREATEST(db_clock.now,COALESCE($${revokedAtParameter}::timestamptz,db_clock.now),session_record.expires_at)
          ELSE NULL END,
        revoked_at=CASE WHEN session_record.expires_at <= db_clock.now THEN NULL
          ELSE GREATEST(db_clock.now,COALESCE($${revokedAtParameter}::timestamptz,db_clock.now),session_record.created_at) END
    FROM candidates
    CROSS JOIN db_clock
    WHERE session_record.organization_id=candidates.organization_id
      AND session_record.session_id=candidates.session_id
      AND session_record.status IN (${REVOCABLE_SESSION_STATUSES.map((_, index) => `'${REVOCABLE_SESSION_STATUSES[index]}'`).join(",")})
    RETURNING session_record.status`, [values.organizationId, ...sessionSelectors.params, values.revokedAt]);

  return lifecycleResult(grants, sessions);
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
