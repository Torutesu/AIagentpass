import crypto from "node:crypto";

import { canonicalJson } from "../../../../packages/protocol/src/index.mjs";
import { normalizeAgentSessionGrantStatement } from "../agent-session-grant.mjs";
import { assertTenantId, withTransaction } from "./repository.mjs";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
const SHA256 = /^[0-9a-f]{64}$/u;
const SIGNATURE = /^[A-Za-z0-9_-]{86}$/u;
const SAFE_IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$/u;
const ADAPTER_VERSION = /^(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/u;
const CANONICAL_TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u;
const SENSITIVE_SCOPE_KEY = /(?:access|api|authorization|bearer|cookie|credential|password|private|refresh|secret|token|key_material|pem)/iu;
const PRIVATE_MATERIAL = /(?:BEGIN[\s\S]*PRIVATE[\s\S]*KEY|-----BEGIN|private\s*key)/iu;
const MAX_SCOPE_BYTES = 16 * 1024;
const MAX_SCOPE_DEPTH = 8;
const MAX_SCOPE_ITEMS = 64;
const MAX_SCOPE_STRING_BYTES = 4096;
const GRANT_TYPE = "agentpass.agent-session-grant";
const GRANT_ISSUER = "agentpass-cloud";
const ACTIVE_SESSION_STATUSES = new Set(["challenge_pending", "active", "request_reserved", "signing_intent", "signed"]);

const PUBLIC_MESSAGES = Object.freeze({
  ERR_INPUT: "Agent session authority input is invalid",
  ERR_CLOCK: "Agent session authority clock is unavailable",
  ERR_UUID: "Agent session authority identifier is invalid",
  ERR_HASH: "Agent session authority hash is invalid",
  ERR_HASH_MISMATCH: "Agent session authority hash does not match canonical content",
  ERR_TENANT_SCOPE: "Agent session authority tenant scope is invalid",
  ERR_TENANT_DRIFT: "Agent session authority tenant context changed",
  ERR_GRANT_CONFLICT: "Agent session grant conflicts with committed authority",
  ERR_GRANT_NOT_FOUND: "Agent session grant is not available",
  ERR_GRANT_UNAVAILABLE: "Agent session grant is not available",
  ERR_GRANT_NOT_YET_VALID: "Agent session grant is not yet valid",
  ERR_GRANT_EXPIRED: "Agent session grant is expired",
  ERR_BINDING_CONFLICT: "Agent session binding conflicts with committed authority",
  ERR_SESSION_CONFLICT: "Agent session conflicts with committed authority",
  ERR_DB_RESULT: "Agent session authority returned an invalid database result",
  ERR_DATABASE: "Agent session authority storage is unavailable"
});

const IMMUTABLE_GRANT_COLUMNS = [
  "organization_id", "grant_id", "device_id", "agent_id", "agent_kind", "adapter_id",
  "adapter_version", "worktree_binding_sha256", "process_binding_policy_id", "scope_json",
  "max_signatures", "not_before", "expires_at", "control_sequence", "issuer", "signer_key_id",
  "statement_hash", "grant_hash", "signature_base64url", "status", "issued_at", "created_by"
];

const GRANT_RETURNING = `organization_id,grant_id,device_id,agent_id,agent_kind,adapter_id,
      adapter_version,worktree_binding_sha256,process_binding_policy_id,scope_json,max_signatures,
      not_before,expires_at,control_sequence,issuer,signer_key_id,statement_hash,grant_hash,
      signature_base64url,status,issued_at,consumed_at,consumed_session_id,
      consumed_process_binding_sha256,created_by`;

const SESSION_RETURNING = `organization_id,session_id,grant_id,device_id,agent_id,agent_kind,adapter_id,
      adapter_version,process_binding_policy_id,grant_hash,process_binding_sha256,
      ancestry_binding_sha256,worktree_binding_sha256,control_sequence,max_signatures,
      used_signatures,reserved_signatures,status,created_at,not_before,expires_at`;

export const AGENT_SESSION_AUTHORITY_ERROR_CODES = Object.freeze(Object.keys(PUBLIC_MESSAGES));

export class AgentSessionAuthorityRepositoryError extends Error {
  constructor(code) {
    // Deliberately do not attach the database/provider cause.  Route handlers
    // and structured loggers must never be able to serialize SQL text, row
    // values, or lower-level error messages through this public error.
    super(PUBLIC_MESSAGES[code] ?? PUBLIC_MESSAGES.ERR_DATABASE);
    this.name = "AgentSessionAuthorityRepositoryError";
    this.code = PUBLIC_MESSAGES[code] === undefined ? "ERR_DATABASE" : code;
  }
}

/**
 * Durable Cloud-side authority for Agent Session Grants and process-bound
 * Session Leases.  `statement_hash` is the hash of the canonical public
 * statement (the issuance intent); `grant_hash` is the hash of the complete
 * signed public envelope.  Neither value is caller-trusted: both are derived
 * and checked before persistence and are immutable after insertion.
 */
export function createAgentSessionAuthorityRepository({ client, now, clock, uuid, uuidFactory } = {}) {
  assertClient(client);
  const currentClock = clock ?? now ?? (() => new Date().toISOString());
  const makeUuid = uuidFactory ?? uuid ?? (() => crypto.randomUUID());
  if (typeof currentClock !== "function") throw new AgentSessionAuthorityRepositoryError("ERR_CLOCK");
  if (typeof makeUuid !== "function") throw new AgentSessionAuthorityRepositoryError("ERR_UUID");

  async function issueAgentSessionGrant(input = {}) {
    const values = normalizeIssueInput(input, currentClock);
    try {
      return await withTransaction(client, (tx) => issueAgentSessionGrantInTransaction({ tx, values }));
    } catch (error) {
      throw mapError(error);
    }
  }

  async function issueAgentSessionGrantInTransaction(input = {}) {
    const tx = input.tx;
    assertTransactionClient(tx);
    const values = input.values ?? normalizeIssueInput(input, currentClock);
    try {
      await setTenantContext(tx, values.organizationId);
      await lockGrant(tx, values.organizationId, values.grantId);

      const inserted = await tx.query(`INSERT INTO agent_session_grants
        (${IMMUTABLE_GRANT_COLUMNS.join(",")})
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb,$11,$12::timestamptz,$13::timestamptz,
          $14,$15,$16,$17,$18,$19,$20,$21::timestamptz,$22)
        ON CONFLICT (organization_id,grant_id) DO NOTHING
        RETURNING ${GRANT_RETURNING}`, issueGrantParameters(values));

      if (rowCount(inserted) === 1) {
        const row = validateGrantRow(inserted.rows[0], values.organizationId);
        if (!sameImmutableGrant(row, values)) throw new AgentSessionAuthorityRepositoryError("ERR_DB_RESULT");
        return publicGrantResult(publicGrant(row), false);
      }

      const existing = await tx.query(`SELECT ${GRANT_RETURNING}
        FROM agent_session_grants
        WHERE organization_id=$1 AND grant_id=$2
        FOR UPDATE`, [values.organizationId, values.grantId]);
      if (rowCount(existing) !== 1) throw new AgentSessionAuthorityRepositoryError("ERR_GRANT_CONFLICT");
      const row = validateGrantRow(existing.rows[0], values.organizationId);
      if (!sameImmutableGrant(row, values)) throw new AgentSessionAuthorityRepositoryError("ERR_GRANT_CONFLICT");
      return publicGrantResult(publicGrant(row), true);
    } catch (error) {
      throw mapError(error);
    }
  }

  async function consumeAgentSessionGrant(input = {}) {
    const values = normalizeConsumeInput(input, currentClock);
    try {
      return await withTransaction(client, (tx) => consumeAgentSessionGrantInTransaction({ tx, values }));
    } catch (error) {
      throw mapError(error);
    }
  }

  async function consumeAgentSessionGrantInTransaction(input = {}) {
    const tx = input.tx;
    assertTransactionClient(tx);
    const values = input.values ?? normalizeConsumeInput(input, currentClock);
    try {
      await setTenantContext(tx, values.organizationId);
      await lockGrant(tx, values.organizationId, values.grantId);

      const grantResult = await tx.query(`SELECT ${GRANT_RETURNING}
        FROM agent_session_grants
        WHERE organization_id=$1 AND grant_id=$2 AND device_id=$3
        FOR UPDATE`, [values.organizationId, values.grantId, values.deviceId]);
      if (rowCount(grantResult) !== 1) throw new AgentSessionAuthorityRepositoryError("ERR_GRANT_NOT_FOUND");
      const grant = validateGrantRow(grantResult.rows[0], values.organizationId);
      if (grant.device_id !== values.deviceId) throw new AgentSessionAuthorityRepositoryError("ERR_TENANT_DRIFT");
      if (!sameGrantEnvelope(grant, values)) throw new AgentSessionAuthorityRepositoryError("ERR_GRANT_CONFLICT");

      if (grant.status === "consumed") {
        return consumeExistingSession(tx, grant, values);
      }
      if (grant.status !== "issued") throw grantAvailabilityError(grant.status);
      if (values.nowMs < Date.parse(grant.not_before)) throw new AgentSessionAuthorityRepositoryError("ERR_GRANT_NOT_YET_VALID");
      if (values.nowMs >= Date.parse(grant.expires_at)) throw new AgentSessionAuthorityRepositoryError("ERR_GRANT_EXPIRED");

      const sessionId = values.sessionId ?? generatedUuid(makeUuid);
      const inserted = await tx.query(`INSERT INTO agent_sessions
        (organization_id,session_id,grant_id,device_id,agent_id,agent_kind,adapter_id,adapter_version,
         process_binding_policy_id,grant_hash,process_binding_sha256,ancestry_binding_sha256,
         worktree_binding_sha256,control_sequence,max_signatures,used_signatures,reserved_signatures,
         status,created_at,not_before,expires_at)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,0,0,'challenge_pending',$16::timestamptz,$17::timestamptz,$18::timestamptz)
        RETURNING ${SESSION_RETURNING}`, [
        values.organizationId, sessionId, grant.grant_id, grant.device_id, grant.agent_id, grant.agent_kind,
        grant.adapter_id, grant.adapter_version, grant.process_binding_policy_id, grant.grant_hash,
        values.processBindingSha256, values.ancestryBindingSha256, grant.worktree_binding_sha256,
        grant.control_sequence, grant.max_signatures, values.now, grant.not_before, grant.expires_at
      ]);
      if (rowCount(inserted) !== 1) throw new AgentSessionAuthorityRepositoryError("ERR_DB_RESULT");
      const session = validateSessionRow(inserted.rows[0], values.organizationId);
      if (!sameNewSession(session, grant, values)) throw new AgentSessionAuthorityRepositoryError("ERR_DB_RESULT");
      return publicLeaseResult(publicLease(session), false);
    } catch (error) {
      throw mapError(error);
    }
  }

  async function consumeExistingSession(tx, grant, values) {
    const consumedSessionId = uuidValue(grant.consumed_session_id, "consumed_session_id");
    const sessionResult = await tx.query(`SELECT ${SESSION_RETURNING}
      FROM agent_sessions
      WHERE organization_id=$1 AND session_id=$2 AND grant_id=$3
      FOR SHARE`, [values.organizationId, consumedSessionId, grant.grant_id]);
    if (rowCount(sessionResult) !== 1) throw new AgentSessionAuthorityRepositoryError("ERR_DB_RESULT");
    const session = validateSessionRow(sessionResult.rows[0], values.organizationId);
    if (session.process_binding_sha256 !== values.processBindingSha256
      || session.ancestry_binding_sha256 !== values.ancestryBindingSha256) {
      throw new AgentSessionAuthorityRepositoryError("ERR_BINDING_CONFLICT");
    }
    if (values.sessionId !== undefined && values.sessionId !== session.session_id) {
      throw new AgentSessionAuthorityRepositoryError("ERR_SESSION_CONFLICT");
    }
    return publicLeaseResult(publicLease(session), true);
  }

  return Object.freeze({
    issueAgentSessionGrant,
    issueAgentSessionGrantInTransaction,
    consumeAgentSessionGrant,
    consumeAgentSessionGrantInTransaction,
    issueGrant: issueAgentSessionGrant,
    consumeGrant: consumeAgentSessionGrant,
    issueGrantInTransaction: issueAgentSessionGrantInTransaction,
    consumeGrantInTransaction: consumeAgentSessionGrantInTransaction
  });
}

function normalizeIssueInput(input, now) {
  if (!isObject(input)) throw new AgentSessionAuthorityRepositoryError("ERR_INPUT");
  const suppliedEnvelope = input.grant ?? input.envelope;
  const suppliedStatement = isObject(suppliedEnvelope?.statement) ? suppliedEnvelope.statement : input.statement;
  const source = isObject(suppliedStatement) ? suppliedStatement : input;
  if (suppliedEnvelope !== undefined && (!isObject(suppliedEnvelope) || suppliedEnvelope.version !== 1 || suppliedEnvelope.type !== GRANT_TYPE)) {
    throw new AgentSessionAuthorityRepositoryError("ERR_INPUT");
  }
  const organizationId = tenant(input.organization_id ?? input.organizationId ?? source.organization_id);
  const grantId = uuidValue(input.grant_id ?? input.grantId ?? source.grant_id, "grant_id");
  const deviceId = uuidValue(input.device_id ?? input.deviceId ?? source.device_id, "device_id");
  const agentId = uuidValue(input.agent_id ?? input.agentId ?? source.agent_id, "agent_id");
  const agentKind = enumValue(input.agent_kind ?? input.agentKind ?? source.agent_kind, ["claude-code", "cursor"]);
  const adapterId = uuidValue(input.adapter_id ?? input.adapterId ?? source.adapter_id, "adapter_id");
  const adapterVersion = stringPattern(input.adapter_version ?? input.adapterVersion ?? source.adapter_version, ADAPTER_VERSION, "adapter_version");
  const worktreeBindingSha256 = hashValue(input.worktree_binding_sha256 ?? input.worktreeBindingSha256 ?? source.worktree_binding_sha256, "worktree_binding_sha256");
  const processBindingPolicyId = stringPattern(input.process_binding_policy_id ?? input.processBindingPolicyId ?? source.process_binding_policy_id, SAFE_IDENTIFIER, "process_binding_policy_id");
  const scope = publicScope(input.scope ?? input.scope_json ?? input.scopeJson ?? source.scope);
  const maxSignatures = boundedInteger(input.max_signatures ?? input.maxSignatures ?? source.max_signatures, 1, 64, "max_signatures");
  const issuedAt = timestamp(input.issued_at ?? input.issuedAt ?? callClock(now), "issued_at");
  const notBefore = timestamp(input.not_before ?? input.notBefore ?? source.not_before, "not_before");
  const expiresAt = timestamp(input.expires_at ?? input.expiresAt ?? source.expires_at, "expires_at");
  if (Date.parse(expiresAt) <= Date.parse(notBefore) || Date.parse(expiresAt) <= Date.parse(issuedAt)) {
    throw new AgentSessionAuthorityRepositoryError("ERR_INPUT");
  }
  const controlSequence = boundedInteger(input.control_sequence ?? input.controlSequence ?? source.control_sequence, 1, Number.MAX_SAFE_INTEGER, "control_sequence");
  const issuer = input.issuer ?? source.issuer ?? GRANT_ISSUER;
  const keyId = stringPattern(input.key_id ?? input.keyId ?? input.signer_key_id ?? input.signerKeyId ?? source.key_id, SAFE_IDENTIFIER, "key_id");
  const signature = stringPattern(input.signature ?? input.signature_base64url ?? input.signatureBase64url ?? suppliedEnvelope?.signature, SIGNATURE, "signature");
  const createdBy = uuidValue(input.created_by ?? input.createdBy, "created_by");
  let statement;
  try {
    statement = normalizeAgentSessionGrantStatement({
      version: 1,
      grant_id: grantId,
      organization_id: organizationId,
      device_id: deviceId,
      agent_id: agentId,
      agent_kind: agentKind,
      adapter_id: adapterId,
      adapter_version: adapterVersion,
      worktree_binding_sha256: worktreeBindingSha256,
      process_binding_policy_id: processBindingPolicyId,
      scope,
      max_signatures: maxSignatures,
      not_before: notBefore,
      expires_at: expiresAt,
      control_sequence: controlSequence,
      issuer: GRANT_ISSUER,
      key_id: keyId
    });
  } catch { throw new AgentSessionAuthorityRepositoryError("ERR_INPUT"); }
  const envelope = Object.freeze({ version: 1, type: GRANT_TYPE, statement, statement_hash: digest(statement), signature });
  const statementHash = digest(statement);
  const grantHash = digest(envelope);
  const suppliedStatementHash = input.statement_hash ?? suppliedEnvelope?.statement_hash;
  if (suppliedStatementHash !== undefined && hashValue(suppliedStatementHash, "statement_hash") !== statementHash) throw new AgentSessionAuthorityRepositoryError("ERR_HASH_MISMATCH");
  if (input.grant_hash !== undefined && hashValue(input.grant_hash, "grant_hash") !== grantHash) throw new AgentSessionAuthorityRepositoryError("ERR_HASH_MISMATCH");
  if (issuer !== GRANT_ISSUER) throw new AgentSessionAuthorityRepositoryError("ERR_INPUT");
  return Object.freeze({
    organizationId, grantId, deviceId, agentId, agentKind, adapterId, adapterVersion,
    worktreeBindingSha256, processBindingPolicyId, scope, maxSignatures, issuedAt, notBefore,
    expiresAt, controlSequence, issuer: GRANT_ISSUER, keyId, signature, createdBy,
    statement, envelope, statementHash, grantHash
  });
}

function normalizeConsumeInput(input, now) {
  if (!isObject(input)) throw new AgentSessionAuthorityRepositoryError("ERR_INPUT");
  const envelope = input.grant ?? input.envelope;
  if (!isObject(envelope) || envelope.version !== 1 || envelope.type !== GRANT_TYPE || !isObject(envelope.statement)) {
    throw new AgentSessionAuthorityRepositoryError("ERR_INPUT");
  }
  let statement;
  try { statement = normalizeAgentSessionGrantStatement(envelope.statement); }
  catch { throw new AgentSessionAuthorityRepositoryError("ERR_INPUT"); }
  const organizationId = tenant(input.organization_id ?? input.organizationId ?? statement.organization_id);
  const deviceId = uuidValue(input.device_id ?? input.deviceId ?? statement.device_id, "device_id");
  const grantId = uuidValue(input.grant_id ?? input.grantId ?? statement.grant_id, "grant_id");
  if (statement.organization_id !== organizationId || statement.device_id !== deviceId || statement.grant_id !== grantId) {
    throw new AgentSessionAuthorityRepositoryError("ERR_GRANT_CONFLICT");
  }
  const statementHash = hashValue(envelope.statement_hash, "statement_hash");
  const signature = stringPattern(envelope.signature, SIGNATURE, "signature");
  const calculatedStatementHash = digest(statement);
  const calculatedGrantHash = digest({ version: 1, type: GRANT_TYPE, statement, statement_hash: statementHash, signature });
  if (statementHash !== calculatedStatementHash) throw new AgentSessionAuthorityRepositoryError("ERR_HASH_MISMATCH");
  const processBindingSha256 = hashValue(input.process_binding_sha256 ?? input.processBindingSha256, "process_binding_sha256");
  const ancestryBindingSha256 = hashValue(input.ancestry_binding_sha256 ?? input.ancestryBindingSha256, "ancestry_binding_sha256");
  const sessionId = input.session_id === undefined && input.sessionId === undefined
    ? undefined
    : uuidValue(input.session_id ?? input.sessionId, "session_id");
  const current = timestamp(callClock(now), "now");
  return Object.freeze({
    organizationId, deviceId, grantId, envelope, statementHash, grantHash: calculatedGrantHash,
    processBindingSha256, ancestryBindingSha256, sessionId, now: current, nowMs: Date.parse(current)
  });
}

function issueGrantParameters(values) {
  return [
    values.organizationId, values.grantId, values.deviceId, values.agentId, values.agentKind, values.adapterId,
    values.adapterVersion, values.worktreeBindingSha256, values.processBindingPolicyId, JSON.stringify(values.scope),
    values.maxSignatures, values.notBefore, values.expiresAt, values.controlSequence, values.issuer, values.keyId,
    values.statementHash, values.grantHash, values.signature, "issued", values.issuedAt, values.createdBy
  ];
}

function publicGrantResult(grant, replayed) {
  return Object.freeze({ grant, replayed });
}

function publicLeaseResult(lease, replayed) {
  return Object.freeze({ lease, replayed });
}

function publicGrant(row) {
  const statement = Object.freeze({
    version: 1,
    grant_id: row.grant_id,
    organization_id: row.organization_id,
    device_id: row.device_id,
    agent_id: row.agent_id,
    agent_kind: row.agent_kind,
    adapter_id: row.adapter_id,
    adapter_version: row.adapter_version,
    worktree_binding_sha256: row.worktree_binding_sha256,
    process_binding_policy_id: row.process_binding_policy_id,
    scope: row.scope_json,
    max_signatures: row.max_signatures,
    not_before: row.not_before,
    expires_at: row.expires_at,
    control_sequence: row.control_sequence,
    issuer: row.issuer,
    key_id: row.signer_key_id
  });
  return Object.freeze({
    version: 1,
    type: GRANT_TYPE,
    statement,
    statement_hash: row.statement_hash,
    signature: row.signature_base64url
  });
}

function publicLease(row) {
  return Object.freeze({
    version: 1,
    type: "agentpass.agent-session-lease",
    session_id: row.session_id,
    grant_id: row.grant_id,
    organization_id: row.organization_id,
    device_id: row.device_id,
    agent_id: row.agent_id,
    agent_kind: row.agent_kind,
    adapter_id: row.adapter_id,
    adapter_version: row.adapter_version,
    process_binding_sha256: row.process_binding_sha256,
    ancestry_binding_sha256: row.ancestry_binding_sha256,
    worktree_binding_sha256: row.worktree_binding_sha256,
    max_signatures: row.max_signatures,
    used_signatures: row.used_signatures,
    not_before: row.not_before,
    expires_at: row.expires_at,
    control_sequence: row.control_sequence
  });
}

function validateGrantRow(row, organizationId) {
  try {
    return validateGrantRowUnchecked(row, organizationId);
  } catch (error) {
    if (error instanceof AgentSessionAuthorityRepositoryError && error.code === "ERR_TENANT_DRIFT") throw error;
    throw new AgentSessionAuthorityRepositoryError("ERR_DB_RESULT");
  }
}

function validateGrantRowUnchecked(row, organizationId) {
  if (!isObject(row)) throw new AgentSessionAuthorityRepositoryError("ERR_DB_RESULT");
  const normalized = {
    organization_id: uuidValue(row.organization_id, "organization_id"),
    grant_id: uuidValue(row.grant_id, "grant_id"),
    device_id: uuidValue(row.device_id, "device_id"),
    agent_id: uuidValue(row.agent_id, "agent_id"),
    agent_kind: enumValue(row.agent_kind, ["claude-code", "cursor"]),
    adapter_id: uuidValue(row.adapter_id, "adapter_id"),
    adapter_version: stringPattern(row.adapter_version, ADAPTER_VERSION, "adapter_version"),
    worktree_binding_sha256: hashValue(row.worktree_binding_sha256, "worktree_binding_sha256"),
    process_binding_policy_id: stringPattern(row.process_binding_policy_id, SAFE_IDENTIFIER, "process_binding_policy_id"),
    scope_json: publicScope(row.scope_json),
    max_signatures: boundedInteger(row.max_signatures, 1, 64, "max_signatures"),
    not_before: timestamp(row.not_before, "not_before"),
    expires_at: timestamp(row.expires_at, "expires_at"),
    control_sequence: boundedInteger(row.control_sequence, 1, Number.MAX_SAFE_INTEGER, "control_sequence"),
    issuer: row.issuer,
    signer_key_id: stringPattern(row.signer_key_id, SAFE_IDENTIFIER, "signer_key_id"),
    statement_hash: hashValue(row.statement_hash, "statement_hash"),
    grant_hash: hashValue(row.grant_hash, "grant_hash"),
    signature_base64url: stringPattern(row.signature_base64url, SIGNATURE, "signature_base64url"),
    status: row.status,
    issued_at: timestamp(row.issued_at, "issued_at"),
    consumed_at: row.consumed_at === null || row.consumed_at === undefined ? null : timestamp(row.consumed_at, "consumed_at"),
    consumed_session_id: row.consumed_session_id === null || row.consumed_session_id === undefined ? null : uuidValue(row.consumed_session_id, "consumed_session_id"),
    consumed_process_binding_sha256: row.consumed_process_binding_sha256 === null || row.consumed_process_binding_sha256 === undefined ? null : hashValue(row.consumed_process_binding_sha256, "consumed_process_binding_sha256"),
    created_by: uuidValue(row.created_by, "created_by")
  };
  if (normalized.organization_id !== organizationId) throw new AgentSessionAuthorityRepositoryError("ERR_TENANT_DRIFT");
  if (normalized.issuer !== GRANT_ISSUER
    || normalized.expires_at <= normalized.not_before || normalized.expires_at <= normalized.issued_at
    || !["issued", "consumed", "expired", "revoked"].includes(normalized.status)) {
    throw new AgentSessionAuthorityRepositoryError("ERR_DB_RESULT");
  }
  if (normalized.status === "consumed"
    && (normalized.consumed_at === null || normalized.consumed_session_id === null || normalized.consumed_process_binding_sha256 === null)) {
    throw new AgentSessionAuthorityRepositoryError("ERR_DB_RESULT");
  }
  if (normalized.status !== "consumed"
    && (normalized.consumed_at !== null || normalized.consumed_session_id !== null || normalized.consumed_process_binding_sha256 !== null)) {
    throw new AgentSessionAuthorityRepositoryError("ERR_DB_RESULT");
  }
  const expectedStatement = statementFromGrantRow(normalized);
  const expectedEnvelope = { version: 1, type: GRANT_TYPE, statement: expectedStatement, statement_hash: digest(expectedStatement), signature: normalized.signature_base64url };
  if (normalized.statement_hash !== digest(expectedStatement) || normalized.grant_hash !== digest(expectedEnvelope)) {
    throw new AgentSessionAuthorityRepositoryError("ERR_DB_RESULT");
  }
  return Object.freeze(normalized);
}

function validateSessionRow(row, organizationId) {
  try {
    return validateSessionRowUnchecked(row, organizationId);
  } catch {
    throw new AgentSessionAuthorityRepositoryError("ERR_DB_RESULT");
  }
}

function validateSessionRowUnchecked(row, organizationId) {
  if (!isObject(row)) throw new AgentSessionAuthorityRepositoryError("ERR_DB_RESULT");
  const normalized = {
    organization_id: uuidValue(row.organization_id, "organization_id"),
    session_id: uuidValue(row.session_id, "session_id"),
    grant_id: uuidValue(row.grant_id, "grant_id"),
    device_id: uuidValue(row.device_id, "device_id"),
    agent_id: uuidValue(row.agent_id, "agent_id"),
    agent_kind: enumValue(row.agent_kind, ["claude-code", "cursor"]),
    adapter_id: uuidValue(row.adapter_id, "adapter_id"),
    adapter_version: stringPattern(row.adapter_version, ADAPTER_VERSION, "adapter_version"),
    process_binding_policy_id: stringPattern(row.process_binding_policy_id, SAFE_IDENTIFIER, "process_binding_policy_id"),
    grant_hash: hashValue(row.grant_hash, "grant_hash"),
    process_binding_sha256: hashValue(row.process_binding_sha256, "process_binding_sha256"),
    ancestry_binding_sha256: hashValue(row.ancestry_binding_sha256, "ancestry_binding_sha256"),
    worktree_binding_sha256: hashValue(row.worktree_binding_sha256, "worktree_binding_sha256"),
    control_sequence: boundedInteger(row.control_sequence, 1, Number.MAX_SAFE_INTEGER, "control_sequence"),
    max_signatures: boundedInteger(row.max_signatures, 1, 64, "max_signatures"),
    used_signatures: boundedInteger(row.used_signatures, 0, 64, "used_signatures"),
    reserved_signatures: boundedInteger(row.reserved_signatures, 0, 64, "reserved_signatures"),
    status: row.status,
    created_at: timestamp(row.created_at, "created_at"),
    not_before: timestamp(row.not_before, "not_before"),
    expires_at: timestamp(row.expires_at, "expires_at")
  };
  if (normalized.organization_id !== organizationId || normalized.used_signatures + normalized.reserved_signatures > normalized.max_signatures
    || normalized.expires_at <= normalized.not_before || normalized.created_at < normalized.not_before
    || !ACTIVE_SESSION_STATUSES.has(normalized.status)) throw new AgentSessionAuthorityRepositoryError("ERR_DB_RESULT");
  return Object.freeze(normalized);
}

function statementFromGrantRow(row) {
  return normalizeAgentSessionGrantStatement({
    version: 1,
    grant_id: row.grant_id,
    organization_id: row.organization_id,
    device_id: row.device_id,
    agent_id: row.agent_id,
    agent_kind: row.agent_kind,
    adapter_id: row.adapter_id,
    adapter_version: row.adapter_version,
    worktree_binding_sha256: row.worktree_binding_sha256,
    process_binding_policy_id: row.process_binding_policy_id,
    scope: row.scope_json,
    max_signatures: row.max_signatures,
    not_before: row.not_before,
    expires_at: row.expires_at,
    control_sequence: row.control_sequence,
    issuer: row.issuer,
    key_id: row.signer_key_id
  });
}

function sameImmutableGrant(row, values) {
  return row.organization_id === values.organizationId
    && row.grant_id === values.grantId
    && row.device_id === values.deviceId
    && row.agent_id === values.agentId
    && row.agent_kind === values.agentKind
    && row.adapter_id === values.adapterId
    && row.adapter_version === values.adapterVersion
    && row.worktree_binding_sha256 === values.worktreeBindingSha256
    && row.process_binding_policy_id === values.processBindingPolicyId
    && stableJson(row.scope_json) === stableJson(values.scope)
    && row.max_signatures === values.maxSignatures
    && row.not_before === values.notBefore
    && row.expires_at === values.expiresAt
    && row.control_sequence === values.controlSequence
    && row.issuer === values.issuer
    && row.signer_key_id === values.keyId
    && row.statement_hash === values.statementHash
    && row.grant_hash === values.grantHash
    && row.signature_base64url === values.signature
    && row.issued_at === values.issuedAt
    && row.created_by === values.createdBy;
}

function sameGrantEnvelope(row, values) {
  return row.grant_id === values.grantId
    && row.organization_id === values.organizationId
    && row.device_id === values.deviceId
    && row.statement_hash === values.statementHash
    && row.grant_hash === values.grantHash
    && row.signature_base64url === values.envelope.signature;
}

function sameNewSession(session, grant, values) {
  return session.organization_id === grant.organization_id
    && session.grant_id === grant.grant_id
    && session.device_id === grant.device_id
    && session.agent_id === grant.agent_id
    && session.agent_kind === grant.agent_kind
    && session.adapter_id === grant.adapter_id
    && session.adapter_version === grant.adapter_version
    && session.process_binding_policy_id === grant.process_binding_policy_id
    && session.grant_hash === grant.grant_hash
    && session.process_binding_sha256 === values.processBindingSha256
    && session.ancestry_binding_sha256 === values.ancestryBindingSha256
    && session.worktree_binding_sha256 === grant.worktree_binding_sha256
    && session.control_sequence === grant.control_sequence
    && session.max_signatures === grant.max_signatures
    && session.not_before === grant.not_before
    && session.expires_at === grant.expires_at
    && session.status === "challenge_pending"
    && session.used_signatures === 0;
}

function grantAvailabilityError(status) {
  return new AgentSessionAuthorityRepositoryError(status === "expired" ? "ERR_GRANT_EXPIRED" : "ERR_GRANT_UNAVAILABLE");
}

async function setTenantContext(tx, organizationId) {
  const configured = await tx.query("SELECT set_config('agentpass.organization_id',$1,true) AS organization_id", [organizationId]);
  if (rowCount(configured) !== 1 || configured.rows[0]?.organization_id !== organizationId) throw new AgentSessionAuthorityRepositoryError("ERR_TENANT_DRIFT");
  const verified = await tx.query("SELECT current_setting('agentpass.organization_id',true) AS organization_id", []);
  if (rowCount(verified) !== 1 || verified.rows[0]?.organization_id !== organizationId) throw new AgentSessionAuthorityRepositoryError("ERR_TENANT_DRIFT");
}

async function lockGrant(tx, organizationId, grantId) {
  await tx.query("SELECT pg_advisory_xact_lock(hashtextextended($1,0)) AS locked", [`agentpass:agent-session-grant:${organizationId}:${grantId}`]);
}

function mapError(error) {
  if (error instanceof AgentSessionAuthorityRepositoryError) return error;
  return new AgentSessionAuthorityRepositoryError("ERR_DATABASE", error);
}

function assertClient(client) {
  if (!client || typeof client.query !== "function") throw new AgentSessionAuthorityRepositoryError("ERR_DATABASE");
}

function assertTransactionClient(client) {
  if (!client || typeof client.query !== "function") throw new AgentSessionAuthorityRepositoryError("ERR_DATABASE");
}

function isObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function tenant(value) {
  try { return assertTenantId(value).toLowerCase(); }
  catch { throw new AgentSessionAuthorityRepositoryError("ERR_TENANT_SCOPE"); }
}

function uuidValue(value, field) {
  if (typeof value !== "string" || !UUID.test(value)) throw new AgentSessionAuthorityRepositoryError(field === "organization_id" ? "ERR_TENANT_SCOPE" : "ERR_UUID");
  return value.toLowerCase();
}

function hashValue(value) {
  if (typeof value !== "string" || !SHA256.test(value)) throw new AgentSessionAuthorityRepositoryError("ERR_HASH");
  return value;
}

function stringPattern(value, pattern) {
  if (typeof value !== "string" || !pattern.test(value)) throw new AgentSessionAuthorityRepositoryError("ERR_INPUT");
  return value;
}

function enumValue(value, allowed) {
  if (typeof value !== "string" || !allowed.includes(value)) throw new AgentSessionAuthorityRepositoryError("ERR_INPUT");
  return value;
}

function boundedInteger(value, min, max) {
  const number = typeof value === "string" && /^[0-9]+$/u.test(value) ? Number(value) : value;
  if (!Number.isSafeInteger(number) || number < min || number > max) throw new AgentSessionAuthorityRepositoryError("ERR_INPUT");
  return number;
}

function timestamp(value) {
  const date = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(date.getTime())) throw new AgentSessionAuthorityRepositoryError("ERR_INPUT");
  const result = date.toISOString();
  if (!CANONICAL_TIMESTAMP.test(result)) throw new AgentSessionAuthorityRepositoryError("ERR_INPUT");
  return result;
}

function callClock(now) {
  try { return now(); }
  catch (error) { throw new AgentSessionAuthorityRepositoryError("ERR_CLOCK", error); }
}

function generatedUuid(uuid) {
  let value;
  try { value = uuid(); }
  catch (error) { throw new AgentSessionAuthorityRepositoryError("ERR_UUID", error); }
  return uuidValue(value, "session_id");
}

function publicScope(value) {
  let parsed = value;
  if (typeof parsed === "string") {
    try { parsed = JSON.parse(parsed); } catch { throw new AgentSessionAuthorityRepositoryError("ERR_INPUT"); }
  }
  if (!isObject(parsed)) throw new AgentSessionAuthorityRepositoryError("ERR_INPUT");
  const seen = new Set();
  const normalized = normalizeScopeValue(parsed, 0, seen);
  let serialized;
  try { serialized = canonicalJson(normalized); } catch { throw new AgentSessionAuthorityRepositoryError("ERR_INPUT"); }
  if (Buffer.byteLength(serialized, "utf8") > MAX_SCOPE_BYTES || PRIVATE_MATERIAL.test(serialized)) throw new AgentSessionAuthorityRepositoryError("ERR_INPUT");
  return Object.freeze(normalized);
}

function normalizeScopeValue(value, depth, seen) {
  if (depth > MAX_SCOPE_DEPTH) throw new AgentSessionAuthorityRepositoryError("ERR_INPUT");
  if (value === null || typeof value === "string" || typeof value === "boolean") {
    if (typeof value === "string" && Buffer.byteLength(value, "utf8") > MAX_SCOPE_STRING_BYTES) throw new AgentSessionAuthorityRepositoryError("ERR_INPUT");
    if (typeof value === "string" && PRIVATE_MATERIAL.test(value)) throw new AgentSessionAuthorityRepositoryError("ERR_INPUT");
    return value;
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new AgentSessionAuthorityRepositoryError("ERR_INPUT");
    return value;
  }
  if (typeof value !== "object") throw new AgentSessionAuthorityRepositoryError("ERR_INPUT");
  if (seen.has(value)) throw new AgentSessionAuthorityRepositoryError("ERR_INPUT");
  seen.add(value);
  let result;
  if (Array.isArray(value)) {
    if (value.length > MAX_SCOPE_ITEMS) throw new AgentSessionAuthorityRepositoryError("ERR_INPUT");
    result = value.map((entry) => normalizeScopeValue(entry, depth + 1, seen));
  } else {
    const entries = Object.entries(value);
    if (entries.length > MAX_SCOPE_ITEMS) throw new AgentSessionAuthorityRepositoryError("ERR_INPUT");
    result = {};
    for (const [key, entry] of entries.sort(([left], [right]) => left.localeCompare(right))) {
      if (key === "__proto__" || key === "constructor" || key === "prototype" || SENSITIVE_SCOPE_KEY.test(key)) throw new AgentSessionAuthorityRepositoryError("ERR_INPUT");
      result[key] = normalizeScopeValue(entry, depth + 1, seen);
    }
  }
  seen.delete(value);
  return result;
}

function stableJson(value) {
  try { return canonicalJson(value); } catch { return ""; }
}

function digest(value) {
  try { return crypto.createHash("sha256").update(canonicalJson(value), "utf8").digest("hex"); }
  catch { throw new AgentSessionAuthorityRepositoryError("ERR_HASH_MISMATCH"); }
}

function rowCount(result) {
  return Number(result?.rowCount ?? result?.rows?.length ?? 0);
}
