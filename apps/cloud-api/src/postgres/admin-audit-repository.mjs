import crypto from "node:crypto";

import { canonicalJson } from "../../../../packages/protocol/src/index.mjs";
import { createSharedControlRepository } from "./shared-control-repository.mjs";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
const CONTROL = /[\u0000-\u001f\u007f]/u;
const IDEMPOTENCY_KEY = /^[A-Za-z0-9._~-]{8,255}$/u;
const DERIVED_IDEMPOTENCY_KEY = /^[A-Za-z0-9._~:-]{8,255}$/u;
const ZERO_HASH = "0".repeat(64);
const SENSITIVE_KEY = /(?:^|_)(?:authorization|bearer|cookie|credential|csrf|nonce|password|private|recovery|refresh|secret|session|signature|token)(?:_|$)/iu;
const DEFAULT_LIMIT = 100;
const MAX_LIMIT = 500;

export class AdminAuditRepositoryError extends Error {
  constructor(code, message, cause = undefined) {
    super(message, cause === undefined ? undefined : { cause });
    this.name = "AdminAuditRepositoryError";
    this.code = code;
  }
}

/**
 * Append-only PostgreSQL authority for operator audit records. The shared
 * idempotency record, chain-head lock, event insert, and head advance commit
 * on one checked-out connection. Only canonical, secret-free event metadata
 * is persisted and returned.
 */
export function createPostgresAdminAuditRepository({ client, now = () => new Date().toISOString() } = {}) {
  assertClient(client);
  if (typeof now !== "function") throw new TypeError("now must be a function");
  const controls = createSharedControlRepository({ client });

  async function appendAdminAuditEvent(input = {}) {
    const values = normalizeAppendInput(input);

    try {
      const outcome = await controls.runIdempotent({
        organizationId: values.organizationId,
        principalId: values.actorId,
        idempotencyKey: values.idempotencyKey,
        requestHash: values.requestHash,
        operation: (tx) => appendEvent(tx, values)
      });
      if (outcome.state === "committed" || outcome.state === "replay") return outcome.response;
      if (outcome.state === "conflict") throw new AdminAuditRepositoryError("ERR_IDEMPOTENCY_CONFLICT", "idempotency key conflicts with another audit mutation");
      throw new AdminAuditRepositoryError("ERR_IDEMPOTENCY_IN_PROGRESS", "audit mutation is already in progress");
    } catch (error) {
      if (error instanceof AdminAuditRepositoryError) throw error;
      throw new AdminAuditRepositoryError("ERR_DATABASE", "admin audit storage is unavailable", error);
    }
  }

  /**
   * Append an audit event to a transaction owned by the caller. No BEGIN,
   * COMMIT, or connection checkout is performed here. The caller must keep
   * the supplied client inside an active PostgreSQL transaction and must
   * rollback it if either the privileged mutation or this method fails.
   */
  async function appendAdminAuditEventInTransaction(input = {}) {
    const tx = input.tx;
    assertTransactionClient(tx);
    const values = normalizeAppendInput(input);
    try {
      const acquired = await controls.acquireIdempotency({
        tx,
        organizationId: values.organizationId,
        principalId: values.actorId,
        idempotencyKey: values.idempotencyKey,
        requestHash: values.requestHash
      });
      if (acquired.state === "replay") return acquired.response;
      if (acquired.state === "conflict") throw new AdminAuditRepositoryError("ERR_IDEMPOTENCY_CONFLICT", "idempotency key conflicts with another audit mutation");
      if (acquired.state === "in_progress") throw new AdminAuditRepositoryError("ERR_IDEMPOTENCY_IN_PROGRESS", "audit mutation is already in progress");
      const result = await appendEvent(tx, values);
      await controls.completeIdempotency({
        tx,
        organizationId: values.organizationId,
        principalId: values.actorId,
        idempotencyKey: values.idempotencyKey,
        requestHash: values.requestHash,
        responseStatus: 201,
        response: result.response
      });
      return result.response;
    } catch (error) {
      if (error instanceof AdminAuditRepositoryError) throw error;
      throw new AdminAuditRepositoryError("ERR_DATABASE", "admin audit storage is unavailable", error);
    }
  }

  async function listAdminAuditEvents(input = {}) {
    const organizationId = uuid(input.organizationId ?? input.organization_id, "organization_id");
    const limit = boundedLimit(input.limit);
    try {
      const result = await client.query(`SELECT id,organization_id,actor_id,action,target_type,target_id,sequence,event_hash,event_json,created_at
        FROM admin_audit_events WHERE organization_id=$1
        ORDER BY sequence DESC,id DESC LIMIT $2`, [organizationId, limit]);
      return Object.freeze((result.rows ?? []).reverse().map(publicStoredEvent));
    } catch (error) {
      if (error instanceof AdminAuditRepositoryError) throw error;
      throw new AdminAuditRepositoryError("ERR_DATABASE", "admin audit storage is unavailable", error);
    }
  }

  return Object.freeze({ appendAdminAuditEvent, appendAdminAuditEventInTransaction, listAdminAuditEvents });

  async function appendEvent(tx, values) {
    await tx.query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))", [`agentpass:admin-audit:${values.organizationId}`]);
    const actor = await tx.query(`SELECT 1 FROM memberships
      WHERE organization_id=$1 AND member_id=$2 AND status='active' FOR SHARE`, [values.organizationId, values.actorId]);
    if (rowCount(actor) !== 1) throw new AdminAuditRepositoryError("ERR_ACTOR", "audit actor is not an active organization member");
    const headResult = await tx.query(`SELECT sequence,event_hash FROM admin_audit_heads
      WHERE organization_id=$1 FOR UPDATE`, [values.organizationId]);
    if (rowCount(headResult) !== 1) throw new AdminAuditRepositoryError("ERR_AUDIT_HEAD", "admin audit head is unavailable");
    const sequence = positiveInteger(headResult.rows[0].sequence, true) + 1;
    const previousHash = digest(headResult.rows[0].event_hash ?? ZERO_HASH);
    const event = canonicalAdminEvent({
      version: 2,
      audit_event_id: values.auditEventId,
      organization_id: values.organizationId,
      actor_id: values.actorId,
      action: values.eventType,
      target_type: values.targetType,
      target_id: values.targetId,
      details: values.details,
      previous_hash: previousHash,
      sequence
    });
    const eventHash = crypto.createHash("sha256").update(canonicalJson(event), "utf8").digest("hex");
    const recordedAt = timestamp(now(), "recorded_at");
    const inserted = await tx.query(`INSERT INTO admin_audit_events
      (organization_id,id,actor_id,action,target_type,target_id,previous_hash,event_hash,sequence,event_json,created_at)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb,$11::timestamptz)
      RETURNING created_at`, [values.organizationId, values.auditEventId, values.actorId, values.eventType, values.targetType, values.targetId, previousHash, eventHash, sequence, JSON.stringify(event), recordedAt]);
    if (rowCount(inserted) !== 1) throw new AdminAuditRepositoryError("ERR_DATABASE", "admin audit event was not appended");
    const advanced = await tx.query(`UPDATE admin_audit_heads SET sequence=$2,event_hash=$3,updated_at=$4::timestamptz
      WHERE organization_id=$1 AND sequence=$5 AND event_hash=$6`, [values.organizationId, sequence, eventHash, recordedAt, sequence - 1, previousHash]);
    if (rowCount(advanced) !== 1) throw new AdminAuditRepositoryError("ERR_AUDIT_HEAD", "admin audit head changed unexpectedly");
    return { responseStatus: 201, response: publicEvent({ event, eventHash, recordedAt }) };
  }
}

function publicEvent({ event, eventHash, recordedAt }) {
  return Object.freeze({
    audit_event_id: event.audit_event_id,
    organization_id: event.organization_id,
    event_type: event.action,
    actor_id: event.actor_id,
    target_type: event.target_type,
    ...(event.target_id === null ? {} : { target_id: event.target_id }),
    details: structuredClone(event.details),
    event_hash: eventHash,
    recorded_at: recordedAt
  });
}

function publicStoredEvent(row) {
  if (!row || typeof row !== "object" || !row.event_json || typeof row.event_json !== "object" || Array.isArray(row.event_json)) {
    throw new AdminAuditRepositoryError("ERR_DATABASE", "stored admin audit event is invalid");
  }
  return publicEvent({
    event: storedAdminEvent(row),
    eventHash: digest(row.event_hash),
    recordedAt: timestamp(row.created_at, "recorded_at")
  });
}

function storedAdminEvent(row) {
  if (row.event_json.version === 0) return legacyAdminEvent(row.event_json, row.sequence);
  return canonicalAdminEvent(row.event_json);
}

function normalizeAppendInput(input) {
  const organizationId = uuid(input.organizationId ?? input.organization_id, "organization_id");
  const actorId = uuid(input.actorId ?? input.actor_id, "actor_id");
  const idempotencyKey = idempotency(input.idempotencyKey ?? input.idempotency_key);
  const auditEventId = optionalUuid(input.auditEventId ?? input.audit_event_id ?? input.eventId ?? input.event_id, "audit_event_id")
    ?? deterministicUuid(canonicalJson({ version: 1, organization_id: organizationId, actor_id: actorId, idempotency_key: idempotencyKey }));
  const eventType = text(input.eventType ?? input.event_type, "event_type", 128);
  const targetType = text(input.targetType ?? input.target_type ?? "organization", "target_type", 64);
  const targetId = input.targetId === undefined && input.target_id === undefined
    ? null
    : uuid(input.targetId ?? input.target_id, "target_id");
  const details = safeDetails(input.details ?? {});
  const requestHash = crypto.createHash("sha256").update(canonicalJson({
    organization_id: organizationId,
    audit_event_id: auditEventId,
    actor_id: actorId,
    event_type: eventType,
    target_type: targetType,
    target_id: targetId,
    details
  })).digest("hex");
  return Object.freeze({ organizationId, actorId, idempotencyKey, auditEventId, eventType, targetType, targetId, details, requestHash });
}

function canonicalAdminEvent(input) {
  if (!input || typeof input !== "object" || Array.isArray(input)) throw new AdminAuditRepositoryError("ERR_DATABASE", "stored admin audit event is invalid");
  if (input.version !== 1 && input.version !== 2) throw new AdminAuditRepositoryError("ERR_DATABASE", "stored admin audit event is invalid");
  const sequence = positiveInteger(input.sequence);
  return Object.freeze({
    version: input.version,
    audit_event_id: uuid(input.audit_event_id, "audit_event_id"),
    organization_id: uuid(input.organization_id, "organization_id"),
    actor_id: uuid(input.actor_id, "actor_id"),
    action: text(input.action, "action", 128),
    target_type: text(input.target_type, "target_type", 64),
    target_id: input.target_id === null ? null : uuid(input.target_id, "target_id"),
    details: safeDetails(input.details),
    previous_hash: digest(input.previous_hash),
    sequence
  });
}

function legacyAdminEvent(input, storedSequence) {
  if (!input || input.version !== 0 || input.legacy !== true) throw new AdminAuditRepositoryError("ERR_DATABASE", "stored admin audit event is invalid");
  return Object.freeze({
    version: 0,
    audit_event_id: uuid(input.audit_event_id, "audit_event_id"),
    organization_id: uuid(input.organization_id, "organization_id"),
    actor_id: uuid(input.actor_id, "actor_id"),
    action: text(input.action, "action", 128),
    target_type: text(input.target_type, "target_type", 64),
    target_id: input.target_id === null ? null : uuid(input.target_id, "target_id"),
    details: {},
    previous_hash: digest(input.previous_hash),
    sequence: positiveInteger(storedSequence)
  });
}

function safeDetails(value, depth = 0) {
  if (!value || typeof value !== "object" || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) throw new AdminAuditRepositoryError("ERR_INPUT", "audit details must be a plain object");
  if (depth > 8) throw new AdminAuditRepositoryError("ERR_INPUT", "audit details are too deeply nested");
  const output = {};
  for (const [key, item] of Object.entries(value)) {
    if (SENSITIVE_KEY.test(key)) throw new AdminAuditRepositoryError("ERR_SECRET_MATERIAL", "audit details contain a prohibited field");
    if (item && typeof item === "object") {
      if (Array.isArray(item)) output[key] = item.map((entry) => entry && typeof entry === "object" ? safeDetails(entry, depth + 1) : scalar(entry));
      else output[key] = safeDetails(item, depth + 1);
    } else output[key] = scalar(item);
  }
  if (Buffer.byteLength(JSON.stringify(output), "utf8") > 16 * 1024) throw new AdminAuditRepositoryError("ERR_INPUT", "audit details are too large");
  return output;
}

function scalar(value) {
  if (value === null || typeof value === "boolean" || (typeof value === "number" && Number.isFinite(value))) return value;
  if (typeof value === "string" && !CONTROL.test(value) && Buffer.byteLength(value, "utf8") <= 4096) return value;
  throw new AdminAuditRepositoryError("ERR_INPUT", "audit details contain an unsupported value");
}

function boundedLimit(value) { if (value === undefined) return DEFAULT_LIMIT; if (!Number.isSafeInteger(value) || value < 1 || value > MAX_LIMIT) throw new AdminAuditRepositoryError("ERR_INPUT", "audit limit is invalid"); return value; }
function idempotency(value) {
  if (typeof value !== "string" || value.length < 8 || value.length > 255 || !DERIVED_IDEMPOTENCY_KEY.test(value)) {
    throw new AdminAuditRepositoryError("ERR_INPUT", "audit idempotency key is invalid");
  }
  if (IDEMPOTENCY_KEY.test(value)) return value;
  // server.mjs derives audit keys as `${mutationKey}:audit`. Keep that
  // accepted request shape while storing only the shared-control alphabet.
  return `audit-${crypto.createHash("sha256").update("AgentPass-Admin-Audit-Key-v1\0").update(value).digest("hex")}`;
}
function text(value, label, max) { if (typeof value !== "string" || value.length < 1 || CONTROL.test(value) || Buffer.byteLength(value, "utf8") > max) throw new AdminAuditRepositoryError("ERR_INPUT", `${label} is invalid`); return value; }
function uuid(value, label) { const result = optionalUuid(value, label); if (result === undefined) throw new AdminAuditRepositoryError("ERR_INPUT", `${label} is invalid`); return result; }
function optionalUuid(value, label) { if (value === undefined || value === null) return undefined; if (typeof value !== "string" || !UUID.test(value)) throw new AdminAuditRepositoryError("ERR_INPUT", `${label} is invalid`); return value.toLowerCase(); }
function digest(value) { if (typeof value !== "string" || !/^[0-9a-f]{64}$/u.test(value)) throw new AdminAuditRepositoryError("ERR_DATABASE", "stored admin audit digest is invalid"); return value; }
function timestamp(value, label) { const date = value instanceof Date ? value : new Date(value); if (Number.isNaN(date.getTime())) throw new AdminAuditRepositoryError("ERR_INPUT", `${label} is invalid`); return date.toISOString(); }
function positiveInteger(value, allowZero = false) { const result = typeof value === "string" ? Number(value) : value; if (!Number.isSafeInteger(result) || result < (allowZero ? 0 : 1)) throw new AdminAuditRepositoryError("ERR_DATABASE", "stored admin audit sequence is invalid"); return result; }
function rowCount(result) { return Number(result?.rowCount ?? result?.rows?.length ?? 0); }
function deterministicUuid(identity) { const bytes=crypto.createHash("sha256").update("AgentPass-Admin-Audit-Id-v1\0").update(identity).digest().subarray(0,16); bytes[6]=(bytes[6]&0x0f)|0x50; bytes[8]=(bytes[8]&0x3f)|0x80; const hex=bytes.toString("hex"); return `${hex.slice(0,8)}-${hex.slice(8,12)}-${hex.slice(12,16)}-${hex.slice(16,20)}-${hex.slice(20)}`; }
function assertClient(client) { if (!client || typeof client.query !== "function") throw new TypeError("database client must provide query(text, params)"); }
function assertTransactionClient(client) { assertClient(client); }

export default createPostgresAdminAuditRepository;
