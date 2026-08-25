import crypto from "node:crypto";

import { canonicalJson, normalizeAuditEvent } from "../../../../packages/protocol/src/index.mjs";
import { AUDIT_ANCHOR_PURPOSE, AUDIT_ANCHOR_ZERO_DIGEST } from "../audit-anchor-statement.mjs";

export const AUDIT_EXPORT_ROOT_VERSION = 1;
export const AUDIT_EXPORT_ROOT_DOMAIN = "AgentPass-Audit-Export-Root-v1";
export const AUDIT_EXPORT_SNAPSHOT_VERSION = 1;
export const AUDIT_EXPORT_SNAPSHOT_TYPE = "agentpass.audit-export";

export const AUDIT_EXPORT_MAX_ROWS = 100;
export const AUDIT_EXPORT_MAX_PAYLOAD_BYTES = 192 * 1024;
export const AUDIT_EXPORT_MAX_ENTRY_BYTES = 32 * 1024;

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
const DIGEST = /^[0-9a-f]{64}$/u;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$/u;
const CLOUD_KEY_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$/u;
const TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u;
const ENVIRONMENTS = new Set(["staging", "production"]);
const CHAINS = new Set(["admin", "cloud_agent", "device"]);
const ZERO = AUDIT_ANCHOR_ZERO_DIGEST;
const MAX_TREE_DEPTH = 16;
const MAX_TREE_ITEMS = 4096;
const MAX_STRING_BYTES = 16 * 1024;
const PRIVATE_FIELD = /(?:private(?:[_ -]?key|[_ -]?material)?|secret|password|credential|authorization|bearer|cookie|claim[_ -]?token|raw[_ -]?signature|provider[_ -]?diagnostic)/iu;

const ADMIN_EVENT_KEYS = Object.freeze([
  "version", "audit_event_id", "organization_id", "actor_id", "action", "target_type", "target_id",
  "details", "previous_hash", "sequence"
]);
const CLOUD_EVENT_KEYS = Object.freeze([
  "organization_id", "sequence", "event_id", "event_type", "grant_id", "session_id", "device_id", "agent_id",
  "grant_hash", "statement_hash", "signer_key_id", "process_binding_sha256", "ancestry_binding_sha256",
  "worktree_binding_sha256", "control_sequence", "authority_generation", "consumed_at", "recorded_at",
  "previous_hash", "event_hash"
]);
const DEVICE_ENTRY_KEYS = Object.freeze([
  "version", "organization_id", "environment", "chain", "export_position", "source_id", "source_device_id",
  "source_previous_hash", "source_hash", "source_gap", "event"
]);
const DEFAULT_LIMITS = Object.freeze({
  maxRecords: AUDIT_EXPORT_MAX_ROWS,
  maxPayloadBytes: AUDIT_EXPORT_MAX_PAYLOAD_BYTES
});

export class AuditExportSnapshotReaderError extends Error {
  constructor(code = "ERR_AUDIT_EXPORT_SNAPSHOT") {
    super("audit export snapshot is unavailable");
    this.name = "AuditExportSnapshotReaderError";
    this.code = code;
  }
}

/**
 * Create the production source reader consumed by the audit-export issuance
 * repository. The returned function is intentionally argument-free beyond
 * the transaction, identity, and previously committed boundary: callers
 * cannot choose a range, payload, or signing key.
 */
export function createPostgresAuditExportSnapshotReader(options = {}) {
  const limits = normalizeLimits(options);
  return (tx, identity, previousBoundary) => readAuditExportSnapshotWithLimits(tx, identity, previousBoundary, limits);
}

export const createAuditExportSnapshotReader = createPostgresAuditExportSnapshotReader;

export async function readAuditExportSnapshot(tx, identity, previousBoundary) {
  return readAuditExportSnapshotWithLimits(tx, identity, previousBoundary, DEFAULT_LIMITS);
}

async function readAuditExportSnapshotWithLimits(tx, identity, previousBoundary, limits) {
  assertClient(tx);
  const values = normalizeIdentity(identity);
  const boundary = normalizeBoundary(previousBoundary);

  try {
    const source = await readSourceEntries(tx, values, boundary, limits);
    const { range, payload } = materializeBoundedPayload(values, boundary, source.entries, limits.maxPayloadBytes);

    const key = await readActiveAuditAnchorKey(tx);
    return deepFreeze({
      range,
      payload,
      key_id: key.key_id,
      key_version: key.key_version,
      lifecycle_version: key.lifecycle_version
    });
  } catch (error) {
    if (error instanceof AuditExportSnapshotReaderError) throw error;
    throw new AuditExportSnapshotReaderError();
  }
}

function materializeBoundedPayload(identity, boundary, entries, maxPayloadBytes) {
  const selected = [];
  let root = boundary.root_digest;
  let range;
  let payload;
  for (const entry of entries) {
    const nextRoot = foldAuditExportRoot(root, entry);
    const nextEntries = Object.freeze([...selected, entry]);
    const nextRange = Object.freeze({
      from_audit_position: boundary.to_audit_position + 1,
      to_audit_position: boundary.to_audit_position + nextEntries.length,
      previous_root_digest: boundary.root_digest,
      root_digest: nextRoot,
      record_count: nextEntries.length
    });
    const nextPayload = {
      version: AUDIT_EXPORT_SNAPSHOT_VERSION,
      type: AUDIT_EXPORT_SNAPSHOT_TYPE,
      organization_id: identity.organization_id,
      environment: identity.environment,
      chain: identity.chain,
      range: nextRange,
      entries: nextEntries
    };
    if (Buffer.byteLength(canonicalJson(nextPayload), "utf8") > maxPayloadBytes) {
      if (selected.length === 0) fail("ERR_AUDIT_EXPORT_SNAPSHOT_TOO_LARGE");
      break;
    }
    selected.push(entry);
    root = nextRoot;
    range = nextRange;
    payload = nextPayload;
  }
  if (selected.length === 0 || range === undefined || payload === undefined) fail("ERR_AUDIT_EXPORT_SNAPSHOT_EMPTY");
  return Object.freeze({ range, payload: deepFreeze(payload) });
}

export default createPostgresAuditExportSnapshotReader;

async function readSourceEntries(tx, identity, boundary, limits) {
  if (identity.chain === "admin") return readAdminEntries(tx, identity, boundary, limits);
  if (identity.chain === "cloud_agent") return readCloudEntries(tx, identity, boundary, limits);
  return readDeviceEntries(tx, identity, boundary, limits);
}

async function readAdminEntries(tx, identity, boundary, limits) {
  const result = await tx.query(`SELECT e.organization_id,e.sequence,e.id,e.actor_id,e.action,e.target_type,e.target_id,
      e.previous_hash,e.event_hash,e.event_json,e.created_at
    FROM admin_audit_events e
    WHERE e.organization_id=$1 AND e.sequence>$2
    ORDER BY e.sequence ASC,e.id ASC
    LIMIT $3
    FOR SHARE OF e`, [identity.organization_id, boundary.to_audit_position, limits.maxRecords]);
  const rows = checkedRows(result);
  if (rows.length === 0) fail("ERR_AUDIT_EXPORT_SNAPSHOT_EMPTY");
  if (rows.length > limits.maxRecords) fail("ERR_AUDIT_EXPORT_SNAPSHOT_TOO_LARGE");
  await validateGlobalPredecessor(tx, "admin_audit_events", identity.organization_id, boundary.to_audit_position, rows[0].previous_hash);

  const entries = [];
  let expectedPosition = boundary.to_audit_position + 1;
  let previousSourceHash = boundary.to_audit_position === 0 ? ZERO : rows[0].previous_hash;
  for (const row of rows) {
    const event = normalizeAdminRow(row, identity, expectedPosition);
    if (event.previous_hash !== previousSourceHash) fail("ERR_AUDIT_EXPORT_SNAPSHOT_CHAIN");
    entries.push(makeEntry(identity, expectedPosition, event.audit_event_id, null, event.previous_hash, event.event_hash, null, event.public_event, limits));
    previousSourceHash = event.event_hash;
    expectedPosition += 1;
  }
  return Object.freeze({ entries: Object.freeze(entries), lastPosition: expectedPosition - 1 });
}

async function readCloudEntries(tx, identity, boundary, limits) {
  const result = await tx.query(`SELECT e.organization_id,e.sequence,e.event_id,e.event_type,e.grant_id,e.session_id,
      e.device_id,e.agent_id,e.grant_hash,e.statement_hash,e.signer_key_id,e.process_binding_sha256,
      e.ancestry_binding_sha256,e.worktree_binding_sha256,e.control_sequence,e.authority_generation,
      e.consumed_at,e.recorded_at,e.previous_hash,e.event_hash
    FROM cloud_agent_audit_events e
    WHERE e.organization_id=$1 AND e.sequence>$2
    ORDER BY e.sequence ASC,e.event_id ASC
    LIMIT $3
    FOR SHARE OF e`, [identity.organization_id, boundary.to_audit_position, limits.maxRecords]);
  const rows = checkedRows(result);
  if (rows.length === 0) fail("ERR_AUDIT_EXPORT_SNAPSHOT_EMPTY");
  if (rows.length > limits.maxRecords) fail("ERR_AUDIT_EXPORT_SNAPSHOT_TOO_LARGE");
  await validateGlobalPredecessor(tx, "cloud_agent_audit_events", identity.organization_id, boundary.to_audit_position, rows[0].previous_hash);

  const entries = [];
  let expectedPosition = boundary.to_audit_position + 1;
  let previousSourceHash = boundary.to_audit_position === 0 ? ZERO : rows[0].previous_hash;
  for (const row of rows) {
    const event = normalizeCloudRow(row, identity, expectedPosition);
    if (event.previous_hash !== previousSourceHash) fail("ERR_AUDIT_EXPORT_SNAPSHOT_CHAIN");
    entries.push(makeEntry(identity, expectedPosition, event.event_id, null, event.previous_hash, event.event_hash, null, event.public_event, limits));
    previousSourceHash = event.event_hash;
    expectedPosition += 1;
  }
  return Object.freeze({ entries: Object.freeze(entries), lastPosition: expectedPosition - 1 });
}

async function readDeviceEntries(tx, identity, boundary, limits) {
  const result = await tx.query(`SELECT x.organization_id,x.sequence,x.device_id,x.event_id,
      x.event_hash AS entry_event_hash,e.previous_hash,e.event_hash,e.redacted_json,e.received_at
    FROM device_audit_export_entries x
    JOIN device_audit_events e
      ON e.organization_id=x.organization_id AND e.device_id=x.device_id
     AND e.event_id=x.event_id AND e.event_hash=x.event_hash
    WHERE x.organization_id=$1 AND x.sequence>$2
    ORDER BY x.sequence ASC,x.device_id ASC,x.event_id ASC
    LIMIT $3
    FOR SHARE OF x,e`, [identity.organization_id, boundary.to_audit_position, limits.maxRecords]);
  const rows = checkedRows(result);
  if (rows.length === 0) fail("ERR_AUDIT_EXPORT_SNAPSHOT_EMPTY");
  if (rows.length > limits.maxRecords) fail("ERR_AUDIT_EXPORT_SNAPSHOT_TOO_LARGE");

  const gapBySource = await readDeviceGapEvidence(tx, identity.organization_id, rows);

  const predecessorHashes = [];
  const seenDevices = new Set();
  for (const row of rows) {
    const deviceId = uuid(row.device_id);
    const previousHash = digest(row.previous_hash, true);
    if (!seenDevices.has(deviceId)) {
      seenDevices.add(deviceId);
      if (previousHash !== ZERO) predecessorHashes.push({ device_id: deviceId, hash: previousHash });
    }
  }
  const predecessorByKey = await readDevicePredecessors(tx, identity.organization_id, predecessorHashes);

  const entries = [];
  let expectedPosition = boundary.to_audit_position + 1;
  const lastByDevice = new Map();
  const seenSourceIds = new Set();
  for (const row of rows) {
    const event = normalizeDeviceRow(row, identity, expectedPosition);
    const sourceKey = `${event.device_id}:${event.event_id}`;
    if (seenSourceIds.has(sourceKey)) fail("ERR_AUDIT_EXPORT_SNAPSHOT_CHAIN");
    seenSourceIds.add(sourceKey);
    const prior = lastByDevice.get(event.device_id);
    const gap = gapBySource.get(sourceKey) ?? null;
    if (prior !== undefined) {
      if (event.previous_hash !== prior
        && (gap === null || gap.expected_previous_hash !== prior || gap.received_previous_hash !== event.previous_hash)) {
        fail("ERR_AUDIT_EXPORT_SNAPSHOT_CHAIN");
      }
    } else if (event.previous_hash !== ZERO && !predecessorByKey.has(`${event.device_id}:${event.previous_hash}`)) {
      if (gap === null || gap.received_previous_hash !== event.previous_hash) fail("ERR_AUDIT_EXPORT_SNAPSHOT_CHAIN");
    }
    lastByDevice.set(event.device_id, event.event_hash);
    entries.push(makeEntry(identity, expectedPosition, event.event_id, event.device_id, event.previous_hash, event.event_hash, gap, event.public_event, limits));
    expectedPosition += 1;
  }
  return Object.freeze({ entries: Object.freeze(entries), lastPosition: expectedPosition - 1 });
}

async function readDeviceGapEvidence(tx, organizationId, rows) {
  const eventIds = [...new Set(rows.map((row) => uuid(row.event_id)))];
  const result = await tx.query(`SELECT device_id,event_id,expected_previous_hash,received_previous_hash,
      recorded_at,resolved_at
    FROM device_audit_gaps
    WHERE organization_id=$1 AND event_id=ANY($2::uuid[])
    FOR SHARE`, [organizationId, eventIds]);
  const gaps = new Map();
  for (const row of checkedRows(result)) {
    assertRow(row, ["device_id", "event_id", "expected_previous_hash", "received_previous_hash", "recorded_at", "resolved_at"]);
    const key = `${uuid(row.device_id)}:${uuid(row.event_id)}`;
    if (gaps.has(key)) fail("ERR_AUDIT_EXPORT_SNAPSHOT_DATABASE");
    const gap = deepFreeze({
      expected_previous_hash: digest(row.expected_previous_hash, true),
      received_previous_hash: digest(row.received_previous_hash, true),
      recorded_at: timestamp(row.recorded_at),
      resolved_at: row.resolved_at === null || row.resolved_at === undefined ? null : timestamp(row.resolved_at)
    });
    if (gap.expected_previous_hash === gap.received_previous_hash) fail("ERR_AUDIT_EXPORT_SNAPSHOT_CHAIN");
    gaps.set(key, gap);
  }
  return gaps;
}

async function readDevicePredecessors(tx, organizationId, predecessors) {
  if (predecessors.length === 0) return new Map();
  const devices = [...new Set(predecessors.map((item) => item.device_id))];
  const hashes = [...new Set(predecessors.map((item) => item.hash))];
  const result = await tx.query(`SELECT device_id,event_id,event_hash,previous_hash
    FROM device_audit_events
    WHERE organization_id=$1 AND device_id=ANY($2::uuid[]) AND event_hash=ANY($3::text[])
    FOR SHARE`, [organizationId, devices, hashes]);
  const map = new Map();
  for (const row of checkedRows(result)) {
    const deviceId = uuid(row.device_id);
    const eventHash = digest(row.event_hash, false);
    if (!map.has(`${deviceId}:${eventHash}`)) map.set(`${deviceId}:${eventHash}`, row.event_id);
  }
  return map;
}

async function validateGlobalPredecessor(tx, table, organizationId, previousPosition, firstPreviousHash) {
  const expected = digest(firstPreviousHash, true);
  if (previousPosition === 0) {
    if (expected !== ZERO) fail("ERR_AUDIT_EXPORT_SNAPSHOT_CHAIN");
    return;
  }
  const result = await tx.query(`SELECT sequence,event_hash
    FROM ${table}
    WHERE organization_id=$1 AND sequence=$2
    FOR SHARE`, [organizationId, previousPosition]);
  const rows = checkedRows(result);
  if (rows.length !== 1 || digest(rows[0].event_hash, false) !== expected) fail("ERR_AUDIT_EXPORT_SNAPSHOT_CHAIN");
}

async function readActiveAuditAnchorKey(tx) {
  const result = await tx.query(`SELECT l.version AS lifecycle_version,k.key_id,k.key_version,
      k.state,k.state_version,k.verification_until
    FROM managed_signer_key_lifecycles l
    JOIN managed_signer_keys k ON k.purpose=l.purpose
    WHERE l.purpose=$1 AND l.algorithm='ed25519' AND k.algorithm='ed25519'
      AND k.state='active' AND k.state_version=l.version
      AND k.verification_until IS NULL
    FOR SHARE OF l,k`, [AUDIT_ANCHOR_PURPOSE]);
  const rows = checkedRows(result);
  if (rows.length !== 1) fail("ERR_AUDIT_EXPORT_SNAPSHOT_LIFECYCLE");
  const row = rows[0];
  if (row.state !== "active" || row.verification_until !== null && row.verification_until !== undefined) fail("ERR_AUDIT_EXPORT_SNAPSHOT_LIFECYCLE");
  const lifecycleVersion = positiveInteger(row.lifecycle_version);
  if (positiveInteger(row.state_version) !== lifecycleVersion) fail("ERR_AUDIT_EXPORT_SNAPSHOT_LIFECYCLE");
  const keyId = identifier(row.key_id);
  const keyVersion = positiveInteger(row.key_version);
  return Object.freeze({ key_id: keyId, key_version: keyVersion, lifecycle_version: lifecycleVersion });
}

function normalizeAdminRow(row, identity, expectedPosition) {
  assertRow(row, ["organization_id", "sequence", "id", "actor_id", "action", "target_type", "target_id", "previous_hash", "event_hash", "event_json", "created_at"]);
  const organizationId = uuid(row.organization_id);
  const sequence = positiveInteger(row.sequence);
  const auditEventId = uuid(row.id);
  const actorId = uuid(row.actor_id);
  const action = publicText(row.action, 128);
  const targetType = publicText(row.target_type, 64);
  const targetId = row.target_id === null || row.target_id === undefined ? null : uuid(row.target_id);
  const previousHash = digest(row.previous_hash, true);
  const eventHash = digest(row.event_hash, false);
  const eventJson = normalizeAdminEvent(row.event_json);
  if (organizationId !== identity.organization_id || sequence !== expectedPosition
    || eventJson.organization_id !== organizationId || eventJson.audit_event_id !== auditEventId
    || eventJson.actor_id !== actorId || eventJson.action !== action || eventJson.target_type !== targetType
    || eventJson.target_id !== targetId || eventJson.previous_hash !== previousHash || eventJson.sequence !== sequence) {
    fail("ERR_AUDIT_EXPORT_SNAPSHOT_ROW");
  }
  // Admin v1 was hashed before JSONB persistence with JSON.stringify. JSONB
  // does not preserve nested object key order, so v1 remains linkage-only.
  // Version 2 hashes the normalized event canonically, making recomputation
  // independent of JSONB object key order.
  if (eventJson.version === 2 && eventHash !== sha256Text(canonicalJson(eventJson))) fail("ERR_AUDIT_EXPORT_SNAPSHOT_HASH");
  const recordedAt = timestamp(row.created_at);
  const publicEvent = { ...eventJson, event_hash: eventHash, recorded_at: recordedAt };
  assertPublicTree(publicEvent);
  return Object.freeze({
    audit_event_id: auditEventId, event_hash: eventHash, previous_hash: previousHash,
    public_event: deepFreeze(publicEvent)
  });
}

function normalizeAdminEvent(value) {
  assertPlainObject(value);
  assertExactKeys(value, ADMIN_EVENT_KEYS);
  if (value.version !== 1 && value.version !== 2) fail("ERR_AUDIT_EXPORT_SNAPSHOT_ROW");
  const event = {
    version: value.version,
    audit_event_id: uuid(value.audit_event_id),
    organization_id: uuid(value.organization_id),
    actor_id: uuid(value.actor_id),
    action: publicText(value.action, 128),
    target_type: publicText(value.target_type, 64),
    target_id: value.target_id === null ? null : uuid(value.target_id),
    details: normalizePublicObject(value.details),
    previous_hash: digest(value.previous_hash, true),
    sequence: positiveInteger(value.sequence)
  };
  assertPublicTree(event);
  return event;
}

function normalizeCloudRow(row, identity, expectedPosition) {
  assertRow(row, CLOUD_EVENT_KEYS);
  const event = {
    organization_id: uuid(row.organization_id),
    sequence: positiveInteger(row.sequence),
    event_id: uuid(row.event_id),
    event_type: row.event_type,
    grant_id: uuid(row.grant_id),
    session_id: uuid(row.session_id),
    device_id: uuid(row.device_id),
    agent_id: uuid(row.agent_id),
    grant_hash: digest(row.grant_hash, false),
    statement_hash: digest(row.statement_hash, false),
    signer_key_id: cloudKeyId(row.signer_key_id),
    process_binding_sha256: digest(row.process_binding_sha256, false),
    ancestry_binding_sha256: digest(row.ancestry_binding_sha256, false),
    worktree_binding_sha256: digest(row.worktree_binding_sha256, false),
    control_sequence: positiveInteger(row.control_sequence),
    authority_generation: positiveInteger(row.authority_generation),
    consumed_at: timestamp(row.consumed_at),
    recorded_at: timestamp(row.recorded_at),
    previous_hash: digest(row.previous_hash, true),
    event_hash: digest(row.event_hash, false)
  };
  if (event.organization_id !== identity.organization_id || event.sequence !== expectedPosition || event.event_type !== "agent_session_grant.consumed") {
    fail("ERR_AUDIT_EXPORT_SNAPSHOT_ROW");
  }
  assertPublicTree(event);
  const { event_hash: _eventHash, ...preimage } = event;
  if (event.event_hash !== sha256Text(canonicalJson(preimage))) fail("ERR_AUDIT_EXPORT_SNAPSHOT_HASH");
  return Object.freeze({ event_id: event.event_id, event_hash: event.event_hash, previous_hash: event.previous_hash, public_event: deepFreeze(event) });
}

function normalizeDeviceRow(row, identity, expectedPosition) {
  assertRow(row, ["organization_id", "sequence", "device_id", "event_id", "entry_event_hash", "previous_hash", "event_hash", "redacted_json", "received_at"]);
  const organizationId = uuid(row.organization_id);
  const sequence = positiveInteger(row.sequence);
  const deviceId = uuid(row.device_id);
  const eventId = uuid(row.event_id);
  const entryHash = digest(row.entry_event_hash, false);
  const previousHash = digest(row.previous_hash, true);
  const eventHash = digest(row.event_hash, false);
  if (organizationId !== identity.organization_id || sequence !== expectedPosition || entryHash !== eventHash) fail("ERR_AUDIT_EXPORT_SNAPSHOT_ROW");
  let event;
  try { event = normalizeAuditEvent(row.redacted_json); } catch { fail("ERR_AUDIT_EXPORT_SNAPSHOT_ROW"); }
  assertPublicTree(event);
  if (event.event_id !== eventId || event.previous_hash !== previousHash || event.event_hash !== eventHash) fail("ERR_AUDIT_EXPORT_SNAPSHOT_ROW");
  const { event_hash: _eventHash, ...preimage } = event;
  if (eventHash !== sha256Text(canonicalJson(preimage))) fail("ERR_AUDIT_EXPORT_SNAPSHOT_HASH");
  const publicEvent = deepFreeze({ ...event, received_at: timestamp(row.received_at) });
  assertPublicTree(publicEvent);
  return Object.freeze({ device_id: deviceId, event_id: eventId, event_hash: eventHash, previous_hash: previousHash, public_event: publicEvent });
}

function makeEntry(identity, position, sourceId, sourceDeviceId, previousHash, sourceHash, sourceGap, event, limits) {
  const entry = {
    version: AUDIT_EXPORT_ROOT_VERSION,
    organization_id: identity.organization_id,
    environment: identity.environment,
    chain: identity.chain,
    export_position: position,
    source_id: sourceId,
    source_device_id: sourceDeviceId,
    source_previous_hash: previousHash,
    source_hash: sourceHash,
    source_gap: sourceGap,
    event
  };
  assertExactKeys(entry, DEVICE_ENTRY_KEYS);
  assertPublicTree(entry);
  const encoded = canonicalJson(entry);
  const bytes = Buffer.byteLength(encoded, "utf8");
  if (bytes > Math.min(AUDIT_EXPORT_MAX_ENTRY_BYTES, limits.maxPayloadBytes)) fail("ERR_AUDIT_EXPORT_SNAPSHOT_TOO_LARGE");
  return deepFreeze(entry);
}

export function canonicalAuditExportEntry(value) {
  assertPlainObject(value);
  assertExactKeys(value, DEVICE_ENTRY_KEYS);
  assertPublicTree(value);
  return deepFreeze(structuredClone(value));
}

export function foldAuditExportRoot(previousRoot, entry) {
  const root = digest(previousRoot, true);
  const normalized = canonicalAuditExportEntry(entry);
  const input = Buffer.concat([
    Buffer.from(AUDIT_EXPORT_ROOT_DOMAIN, "utf8"), Buffer.from([0]),
    Buffer.from(root, "hex"), Buffer.from([0]), Buffer.from(canonicalJson(normalized), "utf8")
  ]);
  return crypto.createHash("sha256").update(input).digest("hex");
}

function normalizeIdentity(value) {
  assertPlainObject(value);
  assertExactKeys(value, ["organization_id", "export_id", "environment", "chain", "idempotency_key"]);
  return Object.freeze({
    organization_id: uuid(value.organization_id),
    export_id: uuid(value.export_id),
    environment: enumeration(value.environment, ENVIRONMENTS),
    chain: enumeration(value.chain, CHAINS),
    idempotency_key: publicText(value.idempotency_key, 255)
  });
}

function normalizeLimits(value) {
  assertPlainObject(value);
  assertExactKeys(value, ["maxRecords", "maxPayloadBytes"], true);
  const maxRecords = value.maxRecords === undefined ? DEFAULT_LIMITS.maxRecords : value.maxRecords;
  const maxPayloadBytes = value.maxPayloadBytes === undefined ? DEFAULT_LIMITS.maxPayloadBytes : value.maxPayloadBytes;
  if (!Number.isSafeInteger(maxRecords) || maxRecords < 1 || maxRecords > AUDIT_EXPORT_MAX_ROWS
    || !Number.isSafeInteger(maxPayloadBytes) || maxPayloadBytes < 1 || maxPayloadBytes > AUDIT_EXPORT_MAX_PAYLOAD_BYTES) {
    fail("ERR_AUDIT_EXPORT_SNAPSHOT_CONFIG");
  }
  return Object.freeze({ maxRecords, maxPayloadBytes });
}

function normalizeBoundary(value) {
  assertPlainObject(value);
  const keys = Reflect.ownKeys(value);
  if (!keys.every((key) => key === "from_audit_position" || key === "to_audit_position" || key === "root_digest")
    || !keys.includes("to_audit_position") || !keys.includes("root_digest") || keys.length > 3) fail("ERR_AUDIT_EXPORT_SNAPSHOT_BOUNDARY");
  const to = nonNegativeInteger(value.to_audit_position);
  const root = digest(value.root_digest, true);
  if ((to === 0 && root !== ZERO) || (to > 0 && root === ZERO)) fail("ERR_AUDIT_EXPORT_SNAPSHOT_BOUNDARY");
  if (value.from_audit_position !== undefined && nonNegativeInteger(value.from_audit_position) > to) fail("ERR_AUDIT_EXPORT_SNAPSHOT_BOUNDARY");
  return Object.freeze({ to_audit_position: to, root_digest: root });
}

function assertRow(row, keys) {
  assertPlainObject(row);
  assertExactKeys(row, keys);
}

function assertExactKeys(value, keys, allowUndefined = false) {
  const actual = Reflect.ownKeys(value);
  if (actual.some((key) => typeof key !== "string" || !keys.includes(key))) fail("ERR_AUDIT_EXPORT_SNAPSHOT_ROW");
  if ((!allowUndefined && actual.length !== keys.length) || (allowUndefined && actual.length > keys.length)) fail("ERR_AUDIT_EXPORT_SNAPSHOT_ROW");
  for (const key of (allowUndefined ? actual : keys)) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !descriptor.enumerable || !("value" in descriptor)) fail("ERR_AUDIT_EXPORT_SNAPSHOT_ROW");
  }
}

function assertPlainObject(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) fail("ERR_AUDIT_EXPORT_SNAPSHOT_ROW");
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) fail("ERR_AUDIT_EXPORT_SNAPSHOT_ROW");
}

function assertPublicTree(value, seen = new Set(), depth = 0) {
  if (value === null || typeof value !== "object") {
    if (typeof value === "string" && (Buffer.byteLength(value, "utf8") > MAX_STRING_BYTES || /-----BEGIN [^-]*PRIVATE KEY-----/iu.test(value))) fail("ERR_AUDIT_EXPORT_SNAPSHOT_ROW");
    return;
  }
  if (depth > MAX_TREE_DEPTH || seen.has(value) || (!Array.isArray(value) && (Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null))) fail("ERR_AUDIT_EXPORT_SNAPSHOT_ROW");
  seen.add(value);
  const keys = Reflect.ownKeys(value);
  if (keys.length > MAX_TREE_ITEMS) fail("ERR_AUDIT_EXPORT_SNAPSHOT_ROW");
  for (const key of keys) {
    if (typeof key !== "string" || key === "__proto__" || key === "constructor" || key === "prototype" || PRIVATE_FIELD.test(key)) fail("ERR_AUDIT_EXPORT_SNAPSHOT_ROW");
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !descriptor.enumerable || !("value" in descriptor)) fail("ERR_AUDIT_EXPORT_SNAPSHOT_ROW");
    assertPublicTree(descriptor.value, seen, depth + 1);
  }
  seen.delete(value);
}

function normalizePublicObject(value) {
  assertPlainObject(value);
  assertPublicTree(value);
  return structuredClone(value);
}

function checkedRows(result) {
  if (!result || !Array.isArray(result.rows)) fail("ERR_AUDIT_EXPORT_SNAPSHOT_DATABASE");
  const count = Number(result.rowCount ?? result.rows.length);
  if (!Number.isSafeInteger(count) || count !== result.rows.length) fail("ERR_AUDIT_EXPORT_SNAPSHOT_DATABASE");
  return result.rows;
}

function digest(value, allowZero) {
  const normalized = Buffer.isBuffer(value) || value instanceof Uint8Array ? Buffer.from(value).toString("hex") : value;
  if (typeof normalized !== "string" || !DIGEST.test(normalized) || (!allowZero && normalized === ZERO)) fail("ERR_AUDIT_EXPORT_SNAPSHOT_ROW");
  return normalized;
}

function uuid(value) {
  if (typeof value !== "string" || !UUID.test(value)) fail("ERR_AUDIT_EXPORT_SNAPSHOT_ROW");
  return value.toLowerCase();
}

function identifier(value) {
  if (typeof value !== "string" || !IDENTIFIER.test(value)) fail("ERR_AUDIT_EXPORT_SNAPSHOT_LIFECYCLE");
  return value;
}

function cloudKeyId(value) {
  if (typeof value !== "string" || !CLOUD_KEY_ID.test(value)) fail("ERR_AUDIT_EXPORT_SNAPSHOT_ROW");
  return value;
}

function publicText(value, maxBytes) {
  if (typeof value !== "string" || value.length < 1 || Buffer.byteLength(value, "utf8") > maxBytes || /[\u0000-\u001f\u007f]/u.test(value)) fail("ERR_AUDIT_EXPORT_SNAPSHOT_ROW");
  return value;
}

function timestamp(value) {
  const date = value instanceof Date ? value : new Date(value);
  const output = date.toISOString();
  if (!TIMESTAMP.test(output)) fail("ERR_AUDIT_EXPORT_SNAPSHOT_ROW");
  return output;
}

function positiveInteger(value, allowZero = false) {
  const number = typeof value === "string" && /^\d+$/u.test(value) ? Number(value) : value;
  if (!Number.isSafeInteger(number) || number < (allowZero ? 0 : 1)) fail("ERR_AUDIT_EXPORT_SNAPSHOT_ROW");
  return number;
}

function nonNegativeInteger(value) { return positiveInteger(value, true); }
function enumeration(value, allowed) { if (typeof value !== "string" || !allowed.has(value)) fail("ERR_AUDIT_EXPORT_SNAPSHOT_BOUNDARY"); return value; }
function sha256Text(value) { return crypto.createHash("sha256").update(value, "utf8").digest("hex"); }
function fail(code) { throw new AuditExportSnapshotReaderError(code); }
function assertClient(client) { if (!client || typeof client.query !== "function") throw new TypeError("database transaction client is invalid"); }

function deepFreeze(value, seen = new Set()) {
  if (!value || typeof value !== "object" || seen.has(value)) return value;
  seen.add(value);
  Object.freeze(value);
  for (const child of Object.values(value)) deepFreeze(child, seen);
  return value;
}
