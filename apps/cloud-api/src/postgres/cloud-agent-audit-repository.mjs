import crypto from "node:crypto";

import { canonicalJson } from "../../../../packages/protocol/src/index.mjs";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
const SHA256 = /^[0-9a-f]{64}$/u;
const SAFE_KEY_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$/u;
const CANONICAL_TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u;
const ZERO_HASH = "0".repeat(64);
const EVENT_TYPE = "agent_session_grant.consumed";
const EVENT_COLUMNS = Object.freeze([
  "organization_id", "sequence", "event_id", "event_type", "grant_id", "session_id", "device_id", "agent_id",
  "grant_hash", "statement_hash", "signer_key_id", "process_binding_sha256", "ancestry_binding_sha256",
  "worktree_binding_sha256", "control_sequence", "authority_generation", "consumed_at", "recorded_at",
  "previous_hash", "event_hash"
]);
const PUBLIC_MESSAGES = Object.freeze({
  ERR_INPUT: "Cloud agent audit input is invalid",
  ERR_TENANT_MISMATCH: "Cloud agent audit tenant identity is inconsistent",
  ERR_BINDING_MISMATCH: "Cloud agent audit binding identity is inconsistent",
  ERR_EVENT_CONFLICT: "Cloud agent audit event conflicts with committed state",
  ERR_HEAD: "Cloud agent audit head is unavailable",
  ERR_DB_RESULT: "Cloud agent audit returned an invalid database result",
  ERR_DATABASE: "Cloud agent audit storage is unavailable"
});

export class CloudAgentAuditRepositoryError extends Error {
  constructor(code) {
    super(PUBLIC_MESSAGES[code] ?? PUBLIC_MESSAGES.ERR_DATABASE);
    this.name = "CloudAgentAuditRepositoryError";
    this.code = PUBLIC_MESSAGES[code] === undefined ? "ERR_DATABASE" : code;
  }
}

/**
 * Transaction-bound writer for the Cloud agent-session audit chain.
 *
 * The caller owns the transaction and must pass the same checked-out client
 * that performed the grant/session mutation. This module never begins,
 * commits, rolls back, or opens a connection.
 */
export function createPostgresCloudAgentAuditRepository({ client = undefined, now = () => new Date().toISOString() } = {}) {
  if (client !== undefined) assertClient(client);
  if (typeof now !== "function") throw new TypeError("now must be a function");

  async function appendAgentSessionGrantConsumedInTransaction(input = {}) {
    const values = normalizeInput(input, now);
    const tx = input.tx;
    assertClient(tx);

    try {
      const authority = await readAuthority(tx, values);
      const eventId = values.eventId ?? deterministicUuid(values.stableIdentity);
      const existing = await readEvent(tx, values.organizationId, eventId);
      if (existing !== undefined) {
        const verified = validateStoredEvent(existing);
        if (!sameCommittedEvent(verified, values, authority, eventId)) throw new CloudAgentAuditRepositoryError("ERR_EVENT_CONFLICT");
        return publicEvent(verified);
      }

      const head = await readHead(tx, values.organizationId);
      const expected = buildExpectedEvent({ ...values, eventId }, authority, head);
      const inserted = await tx.query(`INSERT INTO cloud_agent_audit_events
        (${EVENT_COLUMNS.join(",")})
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17::timestamptz,$18::timestamptz,$19,$20)
        RETURNING ${EVENT_COLUMNS.join(",")}`, eventParameters(expected));
      if (rowCount(inserted) !== 1) throw new CloudAgentAuditRepositoryError("ERR_DB_RESULT");
      const stored = validateStoredEvent(inserted.rows[0]);
      if (!sameRetryEvent(stored, expected) || stored.event_hash !== expected.event_hash || stored.sequence !== expected.sequence) {
        throw new CloudAgentAuditRepositoryError("ERR_DB_RESULT");
      }

      return publicEvent(stored);
    } catch (error) {
      if (error instanceof CloudAgentAuditRepositoryError) throw error;
      throw new CloudAgentAuditRepositoryError("ERR_DATABASE");
    }
  }

  return Object.freeze({
    appendAgentSessionGrantConsumedInTransaction,
    appendConsumedEventInTransaction: appendAgentSessionGrantConsumedInTransaction,
    recordAgentSessionGrantConsumedInTransaction: appendAgentSessionGrantConsumedInTransaction
  });
}

function normalizeInput(input, now) {
  if (!isObject(input)) throw new CloudAgentAuditRepositoryError("ERR_INPUT");
  rejectSecretKeys(input);

  const organizationId = uuid(input.organization_id ?? input.organizationId, "organization_id");
  const grantId = uuid(input.grant_id ?? input.grantId, "grant_id");
  const sessionId = uuid(input.session_id ?? input.sessionId, "session_id");
  const deviceId = uuid(input.device_id ?? input.deviceId, "device_id");
  const agentId = uuid(input.agent_id ?? input.agentId, "agent_id");
  const eventId = optionalUuid(input.event_id ?? input.eventId, "event_id");
  const grantHash = digest(input.grant_hash ?? input.grantHash);
  const statementHash = digest(input.statement_hash ?? input.statementHash);
  const processBindingSha256 = digest(input.process_binding_sha256 ?? input.processBindingSha256);
  const ancestryBindingSha256 = digest(input.ancestry_binding_sha256 ?? input.ancestryBindingSha256);
  const worktreeBindingSha256 = digest(input.worktree_binding_sha256 ?? input.worktreeBindingSha256);
  const signerKeyId = keyId(input.signer_key_id ?? input.signerKeyId ?? input.key_id ?? input.keyId);
  const controlSequence = positiveInteger(input.control_sequence ?? input.controlSequence);
  const authorityGeneration = positiveInteger(input.authority_generation ?? input.authorityGeneration);
  const consumedAt = input.consumed_at === undefined && input.consumedAt === undefined
    ? undefined
    : timestamp(input.consumed_at ?? input.consumedAt);
  const recordedAt = input.recorded_at === undefined && input.recordedAt === undefined
    ? timestamp(callNow(now))
    : timestamp(input.recorded_at ?? input.recordedAt);

  const stableIdentity = {
    version: 1,
    organization_id: organizationId,
    grant_id: grantId,
    session_id: sessionId,
    device_id: deviceId,
    agent_id: agentId,
    grant_hash: grantHash,
    statement_hash: statementHash,
    signer_key_id: signerKeyId,
    process_binding_sha256: processBindingSha256,
    ancestry_binding_sha256: ancestryBindingSha256,
    worktree_binding_sha256: worktreeBindingSha256,
    control_sequence: controlSequence,
    authority_generation: authorityGeneration
  };

  return Object.freeze({
    organizationId, grantId, sessionId, deviceId, agentId, eventId,
    grantHash, statementHash, signerKeyId, processBindingSha256, ancestryBindingSha256,
    worktreeBindingSha256, controlSequence, authorityGeneration, consumedAt, recordedAt,
    stableIdentity
  });
}

async function readHead(tx, organizationId) {
  await tx.query(`INSERT INTO cloud_agent_audit_heads (organization_id)
    VALUES ($1) ON CONFLICT (organization_id) DO NOTHING`, [organizationId]);
  const result = await tx.query(`SELECT sequence,last_event_hash
    FROM cloud_agent_audit_heads
    WHERE organization_id=$1
    FOR UPDATE`, [organizationId]);
  if (rowCount(result) !== 1) throw new CloudAgentAuditRepositoryError("ERR_HEAD");
  const row = result.rows[0];
  let sequence;
  let eventHash;
  try {
    sequence = nonNegativeInteger(row?.sequence);
    eventHash = digestOrZero(row?.last_event_hash);
  } catch {
    throw new CloudAgentAuditRepositoryError("ERR_DB_RESULT");
  }
  return Object.freeze({ sequence, event_hash: eventHash });
}

async function readAuthority(tx, values) {
  const result = await tx.query(`SELECT
      g.organization_id AS grant_organization_id,
      g.grant_id,
      g.device_id AS grant_device_id,
      g.agent_id AS grant_agent_id,
      g.grant_hash,
      g.statement_hash,
      g.signer_key_id,
      g.control_sequence AS grant_control_sequence,
      g.authority_generation AS grant_authority_generation,
      g.consumed_at,
      g.consumed_session_id,
      s.organization_id AS session_organization_id,
      s.session_id,
      s.device_id AS session_device_id,
      s.agent_id AS session_agent_id,
      s.grant_hash AS session_grant_hash,
      s.process_binding_sha256,
      s.ancestry_binding_sha256,
      s.worktree_binding_sha256,
      s.control_sequence AS session_control_sequence,
      s.authority_generation AS session_authority_generation
    FROM agent_session_grants g
    JOIN agent_sessions s
      ON s.organization_id=g.organization_id
     AND s.session_id=g.consumed_session_id
     AND s.grant_id=g.grant_id
    WHERE g.organization_id=$1 AND g.grant_id=$2 AND s.session_id=$3
    FOR SHARE`, [values.organizationId, values.grantId, values.sessionId]);
  if (rowCount(result) !== 1) throw new CloudAgentAuditRepositoryError("ERR_TENANT_MISMATCH");

  const row = result.rows[0];
  const authority = normalizeAuthorityRow(row);
  if (authority.grant_organization_id !== values.organizationId || authority.session_organization_id !== values.organizationId) {
    throw new CloudAgentAuditRepositoryError("ERR_TENANT_MISMATCH");
  }
  if (authority.grant_id !== values.grantId || authority.session_id !== values.sessionId
    || authority.grant_device_id !== values.deviceId || authority.session_device_id !== values.deviceId
    || authority.grant_agent_id !== values.agentId || authority.session_agent_id !== values.agentId) {
    throw new CloudAgentAuditRepositoryError("ERR_BINDING_MISMATCH");
  }
  if (authority.grant_hash !== values.grantHash || authority.session_grant_hash !== values.grantHash
    || authority.statement_hash !== values.statementHash || authority.signer_key_id !== values.signerKeyId
    || authority.process_binding_sha256 !== values.processBindingSha256
    || authority.ancestry_binding_sha256 !== values.ancestryBindingSha256
    || authority.worktree_binding_sha256 !== values.worktreeBindingSha256
    || authority.grant_control_sequence !== values.controlSequence
    || authority.session_control_sequence !== values.controlSequence
    || authority.grant_authority_generation !== values.authorityGeneration
    || authority.session_authority_generation !== values.authorityGeneration
    || authority.consumed_session_id !== values.sessionId) {
    throw new CloudAgentAuditRepositoryError("ERR_BINDING_MISMATCH");
  }
  if (authority.consumed_at === null) throw new CloudAgentAuditRepositoryError("ERR_DB_RESULT");
  if (values.consumedAt !== undefined && values.consumedAt !== authority.consumed_at) {
    throw new CloudAgentAuditRepositoryError("ERR_BINDING_MISMATCH");
  }
  return authority;
}

function normalizeAuthorityRow(row) {
  if (!isObject(row)) throw new CloudAgentAuditRepositoryError("ERR_DB_RESULT");
  return Object.freeze({
    grant_organization_id: uuid(row.grant_organization_id, "grant_organization_id"),
    grant_id: uuid(row.grant_id, "grant_id"),
    grant_device_id: uuid(row.grant_device_id, "grant_device_id"),
    grant_agent_id: uuid(row.grant_agent_id, "grant_agent_id"),
    grant_hash: digest(row.grant_hash),
    statement_hash: digest(row.statement_hash),
    signer_key_id: keyId(row.signer_key_id),
    grant_control_sequence: positiveInteger(row.grant_control_sequence),
    grant_authority_generation: positiveInteger(row.grant_authority_generation),
    consumed_at: timestamp(row.consumed_at),
    consumed_session_id: uuid(row.consumed_session_id, "consumed_session_id"),
    session_organization_id: uuid(row.session_organization_id, "session_organization_id"),
    session_id: uuid(row.session_id, "session_id"),
    session_device_id: uuid(row.session_device_id, "session_device_id"),
    session_agent_id: uuid(row.session_agent_id, "session_agent_id"),
    session_grant_hash: digest(row.session_grant_hash),
    process_binding_sha256: digest(row.process_binding_sha256),
    ancestry_binding_sha256: digest(row.ancestry_binding_sha256),
    worktree_binding_sha256: digest(row.worktree_binding_sha256),
    session_control_sequence: positiveInteger(row.session_control_sequence),
    session_authority_generation: positiveInteger(row.session_authority_generation)
  });
}

function buildExpectedEvent(values, authority, head) {
  const consumedAt = authority.consumed_at;
  const eventId = values.eventId;
  const sequence = head.sequence + 1;
  if (!Number.isSafeInteger(sequence)) throw new CloudAgentAuditRepositoryError("ERR_HEAD");
  const preimage = {
    organization_id: values.organizationId,
    sequence,
    event_id: eventId,
    event_type: EVENT_TYPE,
    grant_id: values.grantId,
    session_id: values.sessionId,
    device_id: values.deviceId,
    agent_id: values.agentId,
    grant_hash: values.grantHash,
    statement_hash: values.statementHash,
    signer_key_id: values.signerKeyId,
    process_binding_sha256: values.processBindingSha256,
    ancestry_binding_sha256: values.ancestryBindingSha256,
    worktree_binding_sha256: values.worktreeBindingSha256,
    control_sequence: values.controlSequence,
    authority_generation: values.authorityGeneration,
    consumed_at: consumedAt,
    recorded_at: values.recordedAt,
    previous_hash: head.event_hash
  };
  return Object.freeze({ ...preimage, event_hash: sha256(preimage) });
}

async function readEvent(tx, organizationId, eventId) {
  const result = await tx.query(`SELECT ${EVENT_COLUMNS.join(",")}
    FROM cloud_agent_audit_events
    WHERE organization_id=$1 AND event_id=$2
    FOR SHARE`, [organizationId, eventId]);
  if (rowCount(result) > 1) throw new CloudAgentAuditRepositoryError("ERR_DB_RESULT");
  return rowCount(result) === 0 ? undefined : result.rows[0];
}

function validateStoredEvent(row) {
  if (!isObject(row)) throw new CloudAgentAuditRepositoryError("ERR_DB_RESULT");
  const event = {
    organization_id: uuid(row.organization_id, "organization_id"),
    sequence: positiveInteger(row.sequence),
    event_id: uuid(row.event_id, "event_id"),
    event_type: row.event_type,
    grant_id: uuid(row.grant_id, "grant_id"),
    session_id: uuid(row.session_id, "session_id"),
    device_id: uuid(row.device_id, "device_id"),
    agent_id: uuid(row.agent_id, "agent_id"),
    grant_hash: digest(row.grant_hash),
    statement_hash: digest(row.statement_hash),
    signer_key_id: keyId(row.signer_key_id),
    process_binding_sha256: digest(row.process_binding_sha256),
    ancestry_binding_sha256: digest(row.ancestry_binding_sha256),
    worktree_binding_sha256: digest(row.worktree_binding_sha256),
    control_sequence: positiveInteger(row.control_sequence),
    authority_generation: positiveInteger(row.authority_generation),
    consumed_at: timestamp(row.consumed_at),
    recorded_at: timestamp(row.recorded_at),
    previous_hash: digest(row.previous_hash),
    event_hash: digest(row.event_hash)
  };
  if (event.event_type !== EVENT_TYPE || event.event_hash !== sha256(withoutEventHash(event))) {
    throw new CloudAgentAuditRepositoryError("ERR_DB_RESULT");
  }
  return Object.freeze(event);
}

function sameRetryEvent(stored, expected) {
  return EVENT_COLUMNS.every((column) => stored[column] === expected[column]);
}

function sameCommittedEvent(stored, values, authority, eventId) {
  return stored.event_id === eventId
    && stored.event_type === EVENT_TYPE
    && stored.organization_id === values.organizationId
    && stored.grant_id === values.grantId
    && stored.session_id === values.sessionId
    && stored.device_id === values.deviceId
    && stored.agent_id === values.agentId
    && stored.grant_hash === values.grantHash
    && stored.statement_hash === values.statementHash
    && stored.signer_key_id === values.signerKeyId
    && stored.process_binding_sha256 === values.processBindingSha256
    && stored.ancestry_binding_sha256 === values.ancestryBindingSha256
    && stored.worktree_binding_sha256 === values.worktreeBindingSha256
    && stored.control_sequence === values.controlSequence
    && stored.authority_generation === values.authorityGeneration
    && stored.consumed_at === authority.consumed_at;
}

function publicEvent(event) {
  const output = {};
  for (const column of EVENT_COLUMNS) output[column] = event[column];
  return Object.freeze(output);
}

function eventParameters(event) {
  return EVENT_COLUMNS.map((column) => event[column]);
}

function withoutEventHash(event) {
  const output = {};
  for (const column of EVENT_COLUMNS) if (column !== "event_hash") output[column] = event[column];
  return output;
}

function deterministicUuid(identity) {
  const bytes = crypto.createHash("sha256").update("AgentPass-Cloud-Agent-Audit-Event-v1\0").update(canonicalJson(identity), "utf8").digest().subarray(0, 16);
  bytes[6] = (bytes[6] & 0x0f) | 0x50;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = bytes.toString("hex");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

function rejectSecretKeys(input) {
  const secret = /(?:^|_)(?:authorization|bearer|cookie|credential|environment|password|private|raw|secret|signature|token)(?:_|$)/iu;
  if (Object.keys(input).some((key) => secret.test(key))) throw new CloudAgentAuditRepositoryError("ERR_INPUT");
}

function sha256(value) {
  return crypto.createHash("sha256").update(canonicalJson(value), "utf8").digest("hex");
}

function uuid(value, field) {
  const result = optionalUuid(value, field);
  if (result === undefined) throw new CloudAgentAuditRepositoryError("ERR_INPUT");
  return result;
}

function optionalUuid(value) {
  if (value === undefined) return undefined;
  if (typeof value !== "string" || !UUID.test(value)) throw new CloudAgentAuditRepositoryError("ERR_INPUT");
  return value.toLowerCase();
}

function digest(value) {
  if (typeof value !== "string" || !SHA256.test(value)) throw new CloudAgentAuditRepositoryError("ERR_INPUT");
  return value.toLowerCase();
}

function digestOrZero(value) {
  if (value === undefined || value === null) return ZERO_HASH;
  return digest(value);
}

function keyId(value) {
  if (typeof value !== "string" || !SAFE_KEY_ID.test(value)) throw new CloudAgentAuditRepositoryError("ERR_INPUT");
  return value;
}

function timestamp(value) {
  const date = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(date.getTime())) throw new CloudAgentAuditRepositoryError("ERR_INPUT");
  const result = date.toISOString();
  if (!CANONICAL_TIMESTAMP.test(result)) throw new CloudAgentAuditRepositoryError("ERR_INPUT");
  return result;
}

function callNow(now) {
  try { return now(); } catch { throw new CloudAgentAuditRepositoryError("ERR_INPUT"); }
}

function positiveInteger(value) {
  const result = typeof value === "string" && /^[0-9]+$/u.test(value) ? Number(value) : value;
  if (!Number.isSafeInteger(result) || result < 1) throw new CloudAgentAuditRepositoryError("ERR_DB_RESULT");
  return result;
}

function nonNegativeInteger(value) {
  const result = typeof value === "string" && /^[0-9]+$/u.test(value) ? Number(value) : value;
  if (!Number.isSafeInteger(result) || result < 0) throw new CloudAgentAuditRepositoryError("ERR_DB_RESULT");
  return result;
}

function rowCount(result) {
  return Number(result?.rowCount ?? result?.rows?.length ?? 0);
}

function isObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function assertClient(client) {
  if (!client || typeof client.query !== "function") throw new TypeError("database client must provide query(text, params)");
}

export default createPostgresCloudAgentAuditRepository;
