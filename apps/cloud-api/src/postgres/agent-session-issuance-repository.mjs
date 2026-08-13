import crypto from "node:crypto";

import { intersectScopes } from "../../../../packages/capability/src/index.mjs";
import { canonicalJson, normalizeScope } from "../../../../packages/protocol/src/index.mjs";
import { createPostgresAdminAuditRepository } from "./admin-audit-repository.mjs";
import { createAgentSessionAuthorityRepository } from "./agent-session-authority-repository.mjs";
import { createSharedControlRepository } from "./shared-control-repository.mjs";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
const SHA256 = /^[0-9a-f]{64}$/u;
const IDEMPOTENCY_KEY = /^[A-Za-z0-9._~-]{8,255}$/u;
const SAFE_IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$/u;
const ADMIN_ROLES = new Set(["owner", "admin"]);
const AGENT_KINDS = new Set(["claude-code", "cursor"]);
const RECENT_AUTH_OPERATION = "agent.session_grant.issue";
const IDEMPOTENCY_TTL_MS = 24 * 60 * 60 * 1000;
const ISSUE_METRIC_METHODS = Object.freeze([
  "recordAgentSessionIssueSuccess",
  "recordAgentSessionIssueReplay",
  "recordAgentSessionIssueConflict",
  "recordAgentSessionIssueFailure",
  "recordAgentSessionIssueRollback",
  "recordAgentSessionSignerSuccess",
  "recordAgentSessionSignerFailure",
  "recordAgentSessionSignerLatency"
]);

export const AGENT_SESSION_ISSUANCE_REPOSITORY_ERROR_CODES = Object.freeze({
  INVALID_INPUT: "invalid_input",
  INVALID_SCOPE: "invalid_scope",
  FORBIDDEN: "forbidden",
  NOT_FOUND: "not_found",
  IDEMPOTENCY_CONFLICT: "idempotency_conflict",
  UNAVAILABLE: "unavailable"
});

const PUBLIC_MESSAGES = Object.freeze({
  invalid_input: "Agent session grant issuance input is invalid",
  invalid_scope: "Agent session grant scope exceeds current policy",
  forbidden: "Agent session grant issuance is forbidden",
  not_found: "Agent session grant authority was not found",
  idempotency_conflict: "Agent session grant idempotency key conflicts",
  unavailable: "Agent session grant issuance is unavailable"
});

export class AgentSessionIssuanceRepositoryError extends Error {
  constructor(code) {
    super(PUBLIC_MESSAGES[code] ?? PUBLIC_MESSAGES.unavailable);
    this.name = "AgentSessionIssuanceRepositoryError";
    this.code = PUBLIC_MESSAGES[code] === undefined ? "unavailable" : code;
  }
}

/**
 * High-level PostgreSQL transaction boundary required by the Human issuance
 * service.  The signer callback executes while the transaction owns the
 * idempotency, organization, membership, agent, device, policy, bundle, and
 * audit locks.  A completed retry reads the immutable Grant row and never
 * calls the signer again.
 *
 * `resolveProcessBindingPolicy` is deliberately required. Process identity
 * policies are native-release authority, not user-supplied identifiers. The
 * resolver receives only public identifiers and must return true (or an
 * object with `allowed: true`) for an enabled, agent-kind-compatible policy.
 */
export function createPostgresAgentSessionIssuanceRepository({
  client,
  authorityRepository = undefined,
  sharedControls = undefined,
  auditRepository = undefined,
  resolveProcessBindingPolicy,
  metrics = undefined,
  clock = undefined
} = {}) {
  assertClient(client);
  if (typeof resolveProcessBindingPolicy !== "function") throw new TypeError("resolveProcessBindingPolicy must be a function");
  const metricRecorder = validateMetrics(metrics);
  const readClock = normalizeClock(clock);
  const authority = authorityRepository ?? createAgentSessionAuthorityRepository({ client });
  const controls = sharedControls ?? createSharedControlRepository({ client });
  const audit = auditRepository ?? createPostgresAdminAuditRepository({ client });
  assertMethod(authority, "issueAgentSessionGrantInTransaction");
  assertMethod(authority, "getAgentSessionGrantInTransaction");
  assertMethod(controls, "withTransaction");
  assertMethod(controls, "acquireIdempotency");
  assertMethod(controls, "completeIdempotency");
  assertMethod(controls, "abandonIdempotency");
  assertMethod(audit, "appendAdminAuditEventInTransaction");

  async function replayAgentSessionGrant(input = {}) {
    let values;
    try {
      values = normalizeReplayInput(input);
    } catch (error) {
      recordMetric("recordAgentSessionIssueFailure");
      throw error;
    }
    const result = await transaction(async (tx) => {
      await prepareTenantAndOrganization(tx, values.organizationId);
      await authorizeHumanSession(tx, values, { requireRecentAuth: false });
      const acquired = await acquire(tx, values);
      if (acquired.state === "conflict") throw failure("idempotency_conflict");
      if (acquired.state === "new") {
        await controls.abandonIdempotency({
          tx,
          organizationId: values.organizationId,
          principalId: idempotencyPrincipal(values.actor.memberId),
          idempotencyKey: values.idempotencyKey,
          requestHash: values.requestFingerprint
        });
        return null;
      }
      if (acquired.state === "in_progress") throw failure("unavailable");
      return replayResult(tx, values, acquired);
    });
    if (result?.replayed === true) recordMetric("recordAgentSessionIssueReplay");
    return result;
  }

  async function issueAgentSessionGrant(input = {}) {
    let values;
    try {
      values = normalizeIssueInput(input);
    } catch (error) {
      recordMetric("recordAgentSessionIssueFailure");
      throw error;
    }
    const result = await transaction(async (tx) => {
      await prepareTenantAndOrganization(tx, values.organizationId);
      await authorizeHumanSession(tx, values, { requireRecentAuth: true });
      const acquired = await acquire(tx, values);
      if (acquired.state === "conflict") throw failure("idempotency_conflict");
      if (acquired.state === "in_progress") throw failure("unavailable");
      if (acquired.state === "replay") return replayResult(tx, values, acquired);

      const authorityState = await resolveIssuanceAuthority(tx, values);
      await authorizeProcessBindingPolicy(tx, values, authorityState);
      const stableIdentity = Object.freeze({
        organization_id: values.organizationId,
        member_id: values.actor.memberId,
        idempotency_key: values.idempotencyKey,
        request_fingerprint: values.requestFingerprint
      });
      const grantId = deterministicAgentSessionIssuanceUuid("grant", stableIdentity);
      const requestId = deterministicAgentSessionIssuanceUuid("request", stableIdentity);
      let built;
      const signerStartedAt = metricRecorder ? readClockSafely(readClock) : undefined;
      try {
        built = await values.buildGrant({
          grant_id: grantId,
          request_id: requestId,
          control_sequence: authorityState.controlSequence,
          policy_id: authorityState.policyId,
          policy_sequence: authorityState.policySequence,
          authority_generation: authorityState.authorityGeneration
        });
        recordMetric("recordAgentSessionSignerSuccess");
      } catch (error) {
        recordMetric("recordAgentSessionSignerFailure");
        // Signer errors are intentionally collapsed. The surrounding
        // transaction rolls the provisional idempotency row back.
        throw failure(error?.code === "agent_session_grant_signer_unavailable" ? "unavailable" : "unavailable");
      } finally {
        if (metricRecorder) recordMetric("recordAgentSessionSignerLatency", signerLatencyMs(signerStartedAt, readClockSafely(readClock)));
      }
      const grant = normalizeBuiltGrant(built, values, authorityState, grantId);
      const persisted = await authority.issueAgentSessionGrantInTransaction({
        tx,
        organization_id: values.organizationId,
        grant: grant.grant,
        grant_hash: grant.grantHash,
        created_by: values.actor.memberId,
        issued_at: values.issuedAt
      });
      if (persisted?.replayed === true || canonicalJson(persisted?.grant) !== canonicalJson(grant.grant)) throw failure("unavailable");

      const auditEvent = await audit.appendAdminAuditEventInTransaction({
        tx,
        organization_id: values.organizationId,
        actor_id: values.actor.memberId,
        idempotency_key: `${values.idempotencyKey}:grant-audit`,
        event_type: "agent_session_grant.issued",
        target_type: "agent_session_grant",
        target_id: grant.grant.statement.grant_id,
        details: {
          agent_id: values.agentId,
          device_id: values.intent.device_id,
          request_id: requestId,
          policy_id: authorityState.policyId,
          policy_sequence: authorityState.policySequence,
          authority_generation: authorityState.authorityGeneration,
          control_sequence: authorityState.controlSequence,
          statement_hash: grant.grant.statement_hash,
          grant_hash: grant.grantHash,
          expires_at: grant.grant.statement.expires_at
        }
      });

      const outboxId = deterministicAgentSessionIssuanceUuid("outbox", stableIdentity);
      const outboxPayload = Object.freeze({
        version: 1,
        grant_id: grant.grant.statement.grant_id,
        request_id: requestId,
        agent_id: values.agentId,
        device_id: values.intent.device_id,
        statement_hash: grant.grant.statement_hash,
        grant_hash: grant.grantHash,
        control_sequence: authorityState.controlSequence,
        authority_generation: authorityState.authorityGeneration,
        audit_event_id: requiredUuid(auditEvent?.audit_event_id)
      });
      const outbox = await tx.query(`INSERT INTO outbox_events
        (organization_id,id,aggregate,action,payload,status)
        VALUES ($1,$2,'agent-session-grant','agent_session_grant.issued',$3::jsonb,'pending')
        RETURNING id`, [values.organizationId, outboxId, JSON.stringify(outboxPayload)]);
      if (rowCount(outbox) !== 1 || requiredUuid(outbox.rows[0]?.id) !== outboxId) throw failure("unavailable");

      const replayPointer = Object.freeze({ grant_id: grant.grant.statement.grant_id, request_id: requestId });
      await controls.completeIdempotency({
        tx,
        organizationId: values.organizationId,
        principalId: idempotencyPrincipal(values.actor.memberId),
        idempotencyKey: values.idempotencyKey,
        requestHash: values.requestFingerprint,
        responseStatus: 201,
        response: replayPointer
      });
      return Object.freeze({ grant: persisted.grant, request_id: requestId, replayed: false });
    });
    recordMetric(result?.replayed === true ? "recordAgentSessionIssueReplay" : "recordAgentSessionIssueSuccess");
    return result;
  }

  return Object.freeze({ issueAgentSessionGrant, replayAgentSessionGrant });

  async function transaction(operation) {
    try {
      return await controls.withTransaction(operation);
    } catch (error) {
      recordMetric("recordAgentSessionIssueRollback");
      if (error instanceof AgentSessionIssuanceRepositoryError) {
        recordMetric(error.code === "idempotency_conflict" ? "recordAgentSessionIssueConflict" : "recordAgentSessionIssueFailure");
        throw error;
      }
      if (error?.code === "idempotency_conflict" || error?.code === "ERR_IDEMPOTENCY_CONFLICT") {
        recordMetric("recordAgentSessionIssueConflict");
        throw failure("idempotency_conflict");
      }
      recordMetric("recordAgentSessionIssueFailure");
      throw failure("unavailable");
    }
  }

  function recordMetric(method, amount = undefined) {
    if (!metricRecorder) return;
    try {
      if (amount === undefined) metricRecorder[method]();
      else metricRecorder[method](amount);
    } catch { /* Metrics never alter issuance correctness. */ }
  }

  async function acquire(tx, values) {
    return controls.acquireIdempotency({
      tx,
      organizationId: values.organizationId,
      principalId: idempotencyPrincipal(values.actor.memberId),
      idempotencyKey: values.idempotencyKey,
      requestHash: values.requestFingerprint,
      ttlMs: IDEMPOTENCY_TTL_MS
    });
  }

  async function replayResult(tx, values, acquired) {
    const pointer = normalizeReplayPointer(acquired.response);
    const stored = await authority.getAgentSessionGrantInTransaction({ tx, organization_id: values.organizationId, grant_id: pointer.grant_id });
    const statement = stored?.grant?.statement;
    if (!statement || statement.organization_id !== values.organizationId || statement.agent_id !== values.agentId
      || statement.device_id !== values.intent.device_id || statement.agent_kind !== values.intent.agent_kind
      || statement.adapter_id !== values.intent.adapter_id || statement.adapter_version !== values.intent.adapter_version
      || statement.worktree_binding_sha256 !== values.intent.worktree_binding_sha256
      || statement.process_binding_policy_id !== values.intent.process_binding_policy_id
      || statement.max_signatures !== values.intent.max_signatures
      || canonicalJson(statement.scope) !== canonicalJson(values.intent.scope)) throw failure("unavailable");
    return Object.freeze({ grant: stored.grant, request_id: pointer.request_id, replayed: true });
  }

  async function authorizeProcessBindingPolicy(tx, values, authorityState) {
    let decision;
    try {
      decision = await resolveProcessBindingPolicy(Object.freeze({
        tx,
        organization_id: values.organizationId,
        device_id: values.intent.device_id,
        agent_id: values.agentId,
        agent_kind: values.intent.agent_kind,
        adapter_id: values.intent.adapter_id,
        adapter_version: values.intent.adapter_version,
        process_binding_policy_id: values.intent.process_binding_policy_id,
        control_sequence: authorityState.controlSequence
      }));
    } catch { throw failure("unavailable"); }
    if (decision !== true && decision?.allowed !== true) throw failure("invalid_input");
  }
}

async function prepareTenantAndOrganization(tx, organizationId) {
  const configured = await tx.query("SELECT set_config('agentpass.organization_id',$1,true) AS organization_id", [organizationId]);
  if (rowCount(configured) !== 1 || configured.rows[0]?.organization_id !== organizationId) throw failure("unavailable");
  const verified = await tx.query("SELECT current_setting('agentpass.organization_id',true) AS organization_id", []);
  if (rowCount(verified) !== 1 || verified.rows[0]?.organization_id !== organizationId) throw failure("unavailable");
  await tx.query("SELECT pg_advisory_xact_lock(hashtextextended($1,0)) AS locked", [`agentpass:organization:${organizationId}`]);
  const organization = await tx.query("SELECT 1 FROM organizations WHERE id=$1 FOR SHARE", [organizationId]);
  if (rowCount(organization) !== 1) throw failure("not_found");
}

async function authorizeHumanSession(tx, values, { requireRecentAuth }) {
  const params = [values.actor.sessionId, values.actor.memberId, values.organizationId];
  const recentClause = requireRecentAuth
    ? `AND s.recent_auth_challenge_id=$4 AND s.recent_auth_organization_id=$3
       AND s.recent_auth_operation=$5 AND s.recent_auth_consumed_at IS NOT NULL
       AND s.recent_auth_at=$6::timestamptz AND s.recent_auth_at>clock_timestamp()-interval '5 minutes'`
    : "";
  if (requireRecentAuth) params.push(values.recentAuth.authorizationId, RECENT_AUTH_OPERATION, values.recentAuth.authenticatedAt);
  const result = await tx.query(`SELECT m.role
    FROM human_sessions s
    JOIN memberships m ON m.organization_id=s.organization_id AND m.id=s.membership_id AND m.member_id=s.member_id
    WHERE s.id=$1 AND s.member_id=$2 AND s.organization_id=$3
      AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp()
      AND (s.idle_expires_at IS NULL OR s.idle_expires_at>clock_timestamp())
      AND m.status='active' AND m.role=s.role
      ${recentClause}
    FOR SHARE OF s,m`, params);
  if (rowCount(result) !== 1 || !ADMIN_ROLES.has(result.rows[0]?.role) || result.rows[0]?.role !== values.actor.role) throw failure("forbidden");
}

async function resolveIssuanceAuthority(tx, values) {
  const audience = await tx.query(`SELECT a.kind AS agent_kind,a.status AS agent_status,d.status AS device_status
    FROM agents a JOIN devices d ON d.organization_id=a.organization_id AND d.id=a.device_id
    WHERE a.organization_id=$1 AND a.id=$2 AND a.device_id=$3
    FOR SHARE OF a,d`, [values.organizationId, values.agentId, values.intent.device_id]);
  if (rowCount(audience) !== 1) throw failure("not_found");
  const row = audience.rows[0];
  if (row.agent_status !== "active" || row.device_status !== "active") throw failure("not_found");
  if (row.agent_kind !== values.intent.agent_kind) throw failure("invalid_input");

  const revoked = await tx.query(`SELECT 1 FROM revocations
    WHERE organization_id=$1 AND status='active' AND (
      target_type='organization'
      OR (target_type='device' AND target_id=$2)
      OR (target_type='agent' AND target_id=$3))
    LIMIT 1 FOR SHARE`, [values.organizationId, values.intent.device_id, values.agentId]);
  if (rowCount(revoked) !== 0) throw failure("forbidden");

  const policy = await tx.query(`SELECT id,sequence,scope_json,created_at,updated_at
    FROM policies WHERE organization_id=$1 AND status='active'
    ORDER BY sequence DESC,id ASC LIMIT 1 FOR SHARE`, [values.organizationId]);
  if (rowCount(policy) !== 1) throw failure("not_found");
  const policyRow = policy.rows[0];
  const policyScope = normalizeStoredScope(policyRow.scope_json);
  let narrowed;
  try { narrowed = intersectScopes(policyScope, values.intent.scope); }
  catch { throw failure("invalid_scope"); }
  if (canonicalJson(narrowed) !== canonicalJson(values.intent.scope)) throw failure("invalid_scope");

  const control = await tx.query(`SELECT h.sequence,s.authority_generation
    FROM bundle_heads h
    JOIN control_bundle_statements s ON s.organization_id=h.organization_id AND s.device_id=h.device_id
      AND s.format_epoch=h.format_epoch AND s.sequence=h.sequence AND s.statement_hash=h.statement_hash
    JOIN control_plane_authority_generations g ON g.organization_id=s.organization_id
      AND g.generation=s.authority_generation AND g.superseded_at IS NULL
    JOIN device_control_plane_state state ON state.organization_id=h.organization_id AND state.device_id=h.device_id
      AND state.desired_generation=g.generation AND state.observed_generation=g.generation
      AND state.refresh_state='applied'
    JOIN bundle_acknowledgements ack ON ack.organization_id=h.organization_id AND ack.device_id=h.device_id
      AND ack.format_epoch=h.format_epoch AND ack.sequence=h.sequence AND ack.statement_hash=h.statement_hash
      AND ack.status='applied'
    WHERE h.organization_id=$1 AND h.device_id=$2 AND h.expires_at>clock_timestamp()
      AND h.format_epoch=2
      AND h.issued_at>=GREATEST($3::timestamptz,$4::timestamptz) AND h.sequence>=$5
    FOR SHARE OF h,s,g,state,ack`, [values.organizationId, values.intent.device_id, policyRow.created_at, policyRow.updated_at, policyRow.sequence]);
  if (rowCount(control) !== 1) throw failure("unavailable");
  return Object.freeze({
    policyId: requiredUuid(policyRow.id),
    policySequence: positiveInteger(policyRow.sequence),
    controlSequence: positiveInteger(control.rows[0].sequence),
    authorityGeneration: positiveInteger(control.rows[0].authority_generation)
  });
}

function normalizeReplayInput(input) {
  const actor = normalizeActor(input.actor);
  const organizationId = requiredUuid(input.organization_id);
  if (actor.organizationId !== organizationId) throw failure("not_found");
  const agentId = requiredUuid(input.agent_id);
  const intent = normalizeIntent(input.intent);
  const requestFingerprint = requiredHash(input.request_fingerprint);
  const expectedFingerprint = sha256(canonicalJson({ organization_id: organizationId, agent_id: agentId, ...intent }));
  if (requestFingerprint !== expectedFingerprint) throw failure("invalid_input");
  return Object.freeze({
    actor,
    organizationId,
    agentId,
    intent,
    idempotencyKey: requiredIdempotency(input.idempotency_key),
    requestFingerprint
  });
}

function normalizeIssueInput(input) {
  const replay = normalizeReplayInput(input);
  if (typeof input.buildGrant !== "function") throw failure("invalid_input");
  const requestId = requiredUuid(input.request_id);
  const issuedAt = timestamp(input.issued_at);
  const issuedAtMs = Date.parse(issuedAt);
  const ttlMs = replay.intent.ttl_seconds * 1_000;
  if (issuedAtMs > Number.MAX_SAFE_INTEGER - ttlMs) throw failure("invalid_input");
  const expiresAt = new Date(issuedAtMs + ttlMs).toISOString();
  const recentAuth = normalizeRecentAuth(input.recent_auth);
  return Object.freeze({ ...replay, requestId, issuedAt, expiresAt, recentAuth, buildGrant: input.buildGrant });
}

function normalizeActor(value) {
  if (!isObject(value)) throw failure("forbidden");
  const role = value.role;
  if (!ADMIN_ROLES.has(role)) throw failure("forbidden");
  return Object.freeze({
    sessionId: requiredUuid(value.session_id),
    memberId: requiredUuid(value.member_id),
    organizationId: requiredUuid(value.organization_id),
    role
  });
}

function normalizeIntent(value) {
  if (!isObject(value)) throw failure("invalid_input");
  let scope;
  try { scope = normalizeScope(value.scope); } catch { throw failure("invalid_scope"); }
  if (!AGENT_KINDS.has(value.agent_kind) || !SAFE_IDENTIFIER.test(value.process_binding_policy_id ?? "")) throw failure("invalid_input");
  return Object.freeze({
    device_id: requiredUuid(value.device_id),
    agent_kind: value.agent_kind,
    adapter_id: requiredUuid(value.adapter_id),
    adapter_version: value.adapter_version,
    worktree_binding_sha256: requiredHash(value.worktree_binding_sha256),
    process_binding_policy_id: value.process_binding_policy_id,
    scope,
    max_signatures: boundedInteger(value.max_signatures, 1, 64),
    ttl_seconds: boundedInteger(value.ttl_seconds, 60, 3600)
  });
}

function normalizeRecentAuth(value) {
  if (!isObject(value)) throw failure("forbidden");
  return Object.freeze({ authorizationId: requiredUuid(value.authorization_id), authenticatedAt: timestamp(value.authenticated_at) });
}

function normalizeBuiltGrant(value, expected, authorityState, expectedGrantId) {
  if (!isObject(value) || !isObject(value.grant) || !isObject(value.grant.statement)) throw failure("unavailable");
  const statement = value.grant.statement;
  if (statement.grant_id !== expectedGrantId || statement.organization_id !== expected.organizationId || statement.agent_id !== expected.agentId
      || statement.device_id !== expected.intent.device_id || statement.agent_kind !== expected.intent.agent_kind
      || statement.adapter_id !== expected.intent.adapter_id || statement.adapter_version !== expected.intent.adapter_version
      || statement.worktree_binding_sha256 !== expected.intent.worktree_binding_sha256
      || statement.process_binding_policy_id !== expected.intent.process_binding_policy_id
      || statement.max_signatures !== expected.intent.max_signatures
      || statement.control_sequence !== authorityState.controlSequence || statement.not_before !== expected.issuedAt
      || statement.expires_at !== expected.expiresAt
    || statement.authority_generation !== authorityState.authorityGeneration
    || canonicalJson(statement.scope) !== canonicalJson(expected.intent.scope)
    || value.statement_hash !== value.grant.statement_hash || value.control_sequence !== authorityState.controlSequence
    || value.authority_generation !== authorityState.authorityGeneration
    || !SHA256.test(value.grant_hash ?? "")) throw failure("unavailable");
  return Object.freeze({ grant: value.grant, grantHash: value.grant_hash });
}

function normalizeReplayPointer(value) {
  if (!isObject(value) || Object.keys(value).sort().join(",") !== "grant_id,request_id") throw failure("unavailable");
  return Object.freeze({ grant_id: requiredUuid(value.grant_id), request_id: requiredUuid(value.request_id) });
}

function normalizeStoredScope(value) { try { return normalizeScope(value); } catch { throw failure("unavailable"); } }
function idempotencyPrincipal(memberId) { return `agent-session-grant:${memberId}`; }
function requiredUuid(value) { if (typeof value !== "string" || !UUID.test(value)) throw failure("invalid_input"); return value.toLowerCase(); }
function requiredHash(value) { if (typeof value !== "string" || !SHA256.test(value)) throw failure("invalid_input"); return value; }
function requiredIdempotency(value) { if (typeof value !== "string" || !IDEMPOTENCY_KEY.test(value)) throw failure("invalid_input"); return value; }
function positiveInteger(value) { const number = typeof value === "string" ? Number(value) : value; if (!Number.isSafeInteger(number) || number < 1) throw failure("unavailable"); return number; }
function boundedInteger(value, min, max) { if (!Number.isSafeInteger(value) || value < min || value > max) throw failure("invalid_input"); return value; }
function timestamp(value) { const date = value instanceof Date ? value : new Date(value); if (Number.isNaN(date.getTime())) throw failure("invalid_input"); return date.toISOString(); }
function rowCount(result) { return Number(result?.rowCount ?? result?.rows?.length ?? 0); }
function isObject(value) { return value !== null && typeof value === "object" && !Array.isArray(value); }
function assertClient(value) { if (!value || typeof value.query !== "function") throw new TypeError("client must expose query()"); }
function assertMethod(value, method) { if (!value || typeof value[method] !== "function") throw new TypeError(`${method} is required`); }
function failure(code) { return new AgentSessionIssuanceRepositoryError(code); }
function sha256(value) { return crypto.createHash("sha256").update(value).digest("hex"); }

function validateMetrics(value) {
  if (value === undefined) return undefined;
  if (!isObject(value) || ISSUE_METRIC_METHODS.some((method) => typeof value[method] !== "function")) {
    throw new TypeError("metrics must expose the agent session issuance recorder methods");
  }
  return value;
}

function normalizeClock(value) {
  if (value === undefined) return () => globalThis.performance?.now?.() ?? Date.now();
  if (typeof value === "function") return value;
  if (isObject(value) && typeof value.now === "function") return () => value.now();
  throw new TypeError("clock must be a function");
}

function readClockSafely(clock) {
  try {
    const value = clock();
    return typeof value === "number" && Number.isFinite(value) ? value : undefined;
  } catch { return undefined; }
}

function signerLatencyMs(startedAt, finishedAt) {
  if (startedAt === undefined || finishedAt === undefined) return 0;
  const elapsed = finishedAt - startedAt;
  if (!Number.isFinite(elapsed) || elapsed <= 0) return 0;
  return Math.min(Number.MAX_SAFE_INTEGER, Math.round(elapsed));
}

export function deterministicAgentSessionIssuanceUuid(kind, identity) {
  if (typeof kind !== "string" || kind.length < 1 || kind.length > 64 || !isObject(identity)) throw failure("invalid_input");
  const bytes = crypto.createHash("sha256").update("AgentPass-Agent-Session-Issuance-Id-v1\0").update(kind).update("\0").update(canonicalJson(identity)).digest().subarray(0, 16);
  bytes[6] = (bytes[6] & 0x0f) | 0x50;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = bytes.toString("hex");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}
