import crypto from "node:crypto";

import { canonicalJson } from "../../../../packages/protocol/src/index.mjs";
import { createHumanCursorCodec } from "../human-auth/pagination/cursor-codec.mjs";
import { createPostgresAdminAuditRepository } from "./admin-audit-repository.mjs";
import { createSharedControlRepository, SharedControlRepositoryError } from "./shared-control-repository.mjs";

const RESOURCE = "owner_recovery_dead_letters";
const DIRECTION = "asc";
const DEFAULT_LIMIT = 25;
const MAX_LIMIT = 100;
const MAX_REASON_BYTES = 128;
const MAX_CURSOR_LENGTH = 512;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
const BASE64URL = /^[A-Za-z0-9_-]+$/u;
const IDEMPOTENCY_KEY = /^[A-Za-z0-9][A-Za-z0-9._:~-]{7,254}$/u;
const EVENT_TYPE = /^recovery\.[a-z]+(?:\.[a-z]+)*$/u;
const CONTROL = /[\u0000-\u001f\u007f]/u;
const MANAGEMENT_ROLES = new Set(["owner", "admin"]);

export const OWNER_RECOVERY_OUTBOX_MANAGEMENT_OPERATIONS = Object.freeze({
  redrive: "human.recovery.outbox.redrive",
  suppress: "human.recovery.outbox.suppress"
});

export const OWNER_RECOVERY_OUTBOX_MANAGEMENT_ERROR_CODES = Object.freeze({
  INVALID_INPUT: "owner_recovery_outbox_management_invalid_input",
  FORBIDDEN: "owner_recovery_outbox_management_forbidden",
  INVALID_CURSOR: "owner_recovery_outbox_management_invalid_cursor",
  VERSION_CONFLICT: "owner_recovery_outbox_management_version_conflict",
  IDEMPOTENCY_CONFLICT: "owner_recovery_outbox_management_idempotency_conflict",
  IDEMPOTENCY_IN_PROGRESS: "owner_recovery_outbox_management_idempotency_in_progress",
  DATABASE: "owner_recovery_outbox_management_unavailable",
  AUDIT: "owner_recovery_outbox_management_audit_unavailable"
});

const MESSAGES = Object.freeze({
  [OWNER_RECOVERY_OUTBOX_MANAGEMENT_ERROR_CODES.INVALID_INPUT]: "Owner recovery outbox management input is invalid",
  [OWNER_RECOVERY_OUTBOX_MANAGEMENT_ERROR_CODES.FORBIDDEN]: "Owner recovery outbox management authorization is invalid",
  [OWNER_RECOVERY_OUTBOX_MANAGEMENT_ERROR_CODES.INVALID_CURSOR]: "Owner recovery outbox management cursor is invalid",
  [OWNER_RECOVERY_OUTBOX_MANAGEMENT_ERROR_CODES.VERSION_CONFLICT]: "Owner recovery outbox management version is stale",
  [OWNER_RECOVERY_OUTBOX_MANAGEMENT_ERROR_CODES.IDEMPOTENCY_CONFLICT]: "Owner recovery outbox management idempotency key conflicts",
  [OWNER_RECOVERY_OUTBOX_MANAGEMENT_ERROR_CODES.IDEMPOTENCY_IN_PROGRESS]: "Owner recovery outbox management mutation is already in progress",
  [OWNER_RECOVERY_OUTBOX_MANAGEMENT_ERROR_CODES.DATABASE]: "Owner recovery outbox management storage is unavailable",
  [OWNER_RECOVERY_OUTBOX_MANAGEMENT_ERROR_CODES.AUDIT]: "Owner recovery outbox management audit is unavailable"
});

export class OwnerRecoveryOutboxManagementRepositoryError extends Error {
  constructor(code) {
    super(MESSAGES[code] ?? MESSAGES[OWNER_RECOVERY_OUTBOX_MANAGEMENT_ERROR_CODES.DATABASE]);
    this.name = "OwnerRecoveryOutboxManagementRepositoryError";
    this.code = MESSAGES[code] === undefined ? OWNER_RECOVERY_OUTBOX_MANAGEMENT_ERROR_CODES.DATABASE : code;
  }
}

/**
 * PostgreSQL authority for operator management of owner-recovery dead letters.
 *
 * The caller must pass an actor produced by the authenticated server session
 * boundary. This repository deliberately does not accept a member, role, or
 * session separately from that scope. Redrive and suppress use shared-control
 * idempotency and append the admin audit event before the same transaction is
 * committed.
 *
 * The SQL targets the expected 0030 contract. It does not require the
 * migration to be present while unit tests exercise the repository boundary.
 */
export function createPostgresOwnerRecoveryOutboxManagementRepository({
  client,
  cursorCodec,
  cursorSecret,
  auditRepository,
  now = () => new Date().toISOString()
} = {}) {
  assertClient(client);
  if (typeof now !== "function") throw new TypeError("now must be a function");
  const codec = cursorCodec ?? (cursorSecret === undefined ? undefined : createHumanCursorCodec({ secret: cursorSecret }));
  if (!codec || typeof codec.encode !== "function" || typeof codec.decode !== "function") throw new TypeError("cursorCodec or cursorSecret is required");
  const audit = auditRepository ?? createPostgresAdminAuditRepository({ client, now });
  if (!audit || typeof audit.appendAdminAuditEventInTransaction !== "function") throw new TypeError("auditRepository must expose appendAdminAuditEventInTransaction");
  const controls = createSharedControlRepository({ client });

  async function listDeadLetters(input = {}) {
    if (!isObject(input)) throw invalidInput();
    const actor = normalizeActor(input.actor);
    const limit = boundedLimit(input.limit);
    const position = decodeCursor(input.cursor, actor, codec);
    const params = [actor.organizationId, actor.sessionId, actor.memberId, actor.role];
    const clauses = ["organization_id=$1", "status='dead_letter'", `EXISTS (
      SELECT 1 FROM human_sessions s
      JOIN memberships m ON m.organization_id=s.organization_id AND m.id=s.membership_id AND m.member_id=s.member_id
      JOIN organizations o ON o.id=s.organization_id
      WHERE s.id=$2 AND s.member_id=$3 AND s.organization_id=$1 AND s.role=$4
        AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp()
        AND (s.idle_expires_at IS NULL OR s.idle_expires_at>clock_timestamp())
        AND m.status='active' AND m.role=s.role AND m.role IN ('owner','admin')
        AND s.organization_authority_epoch=o.authority_epoch
        AND s.membership_session_epoch=m.session_epoch
    )`];
    if (position !== undefined) {
      params.push(position.created_at, position.id);
      clauses.push(`(created_at,event_id) > ($${params.length - 1}::timestamptz,$${params.length}::uuid)`);
    }
    params.push(limit + 1);
    try {
      const result = await client.query(`SELECT organization_id,event_id,request_id,subject_member_id,event_type,status,
          attempts,total_attempts,management_version,redrive_count,last_error_code,
          suppressed_at,suppression_reason,created_at,updated_at
        FROM owner_recovery_outbox
        WHERE ${clauses.join(" AND ")}
        ORDER BY created_at ASC,event_id ASC
        LIMIT $${params.length}`, params);
      const rows = (result.rows ?? []).map(publicDeadLetter);
      const hasNext = rows.length > limit;
      const items = rows.slice(0, limit);
      const last = items.at(-1);
      const next_cursor = hasNext ? encodeCursor(actor, last, codec) : null;
      return Object.freeze({ items: Object.freeze(items), next_cursor });
    } catch (error) {
      if (error instanceof OwnerRecoveryOutboxManagementRepositoryError) throw error;
      throw database(error);
    }
  }

  async function redriveDeadLetter(input = {}) {
    const values = normalizeMutation(input, { reasonRequired: false });
    return mutate(values, {
      operation: "redrive",
      eventType: "owner_recovery.outbox.redriven",
      reason: values.reason,
      sql: `UPDATE owner_recovery_outbox
        SET status='pending',attempts=0,
            redrive_count=redrive_count+1,management_version=management_version+1,
            available_at=clock_timestamp(),updated_at=clock_timestamp(),
            claim_token_digest=NULL,claim_expires_at=NULL,last_error_code=NULL,
            suppressed_at=NULL,suppression_reason=NULL
        WHERE organization_id=$1 AND event_id=$2 AND status='dead_letter'
          AND management_version=$3 AND redrive_count<3
        RETURNING organization_id,event_id,status,attempts,total_attempts,
          management_version,redrive_count,suppressed_at,suppression_reason`
    });
  }

  async function suppressDeadLetter(input = {}) {
    const values = normalizeMutation(input, { reasonRequired: true });
    return mutate(values, {
      operation: "suppress",
      eventType: "owner_recovery.outbox.suppressed",
      reason: values.reason,
      sql: `UPDATE owner_recovery_outbox
        SET status='suppressed',suppressed_at=clock_timestamp(),suppression_reason=$4,
            management_version=management_version+1,updated_at=clock_timestamp(),
            claim_token_digest=NULL,claim_expires_at=NULL
        WHERE organization_id=$1 AND event_id=$2 AND status='dead_letter'
          AND management_version=$3
        RETURNING organization_id,event_id,status,attempts,total_attempts,
          management_version,redrive_count,suppressed_at,suppression_reason`
    });
  }

  return Object.freeze({ listDeadLetters, redriveDeadLetter, suppressDeadLetter });

  async function mutate(values, { operation, eventType, reason, sql }) {
    const expectedOperation = OWNER_RECOVERY_OUTBOX_MANAGEMENT_OPERATIONS[operation];
    const requestHash = crypto.createHash("sha256").update(canonicalJson({
      version: 1,
      operation,
      organization_id: values.actor.organizationId,
      actor_member_id: values.actor.memberId,
      actor_session_id: values.actor.sessionId,
      authorization_id: values.authorization.challengeId,
      event_id: values.eventId,
      expected_management_version: values.expectedManagementVersion,
      ...(reason === undefined ? {} : { reason })
    })).digest("hex");
    try {
      const outcome = await controls.withTransaction(async (tx) => {
          await tx.query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))", [`agentpass:organization:${values.actor.organizationId}`]);
          await requireCurrentAuthorization(tx, values, expectedOperation);
          const acquired = await controls.acquireIdempotency({
            tx,
            organizationId: values.actor.organizationId,
            principalId: values.actor.memberId,
            idempotencyKey: values.idempotencyKey,
            requestHash
          });
          if (acquired.state === "replay") return acquired;
          if (acquired.state === "conflict" || acquired.state === "in_progress") return { state: acquired.state };
          const params = operation === "suppress"
            ? [values.actor.organizationId, values.eventId, values.expectedManagementVersion, reason]
            : [values.actor.organizationId, values.eventId, values.expectedManagementVersion];
          const changed = await tx.query(sql, params);
          if (rowCount(changed) !== 1) throw versionConflict();
          const row = publicMutation(changed.rows[0]);
          try {
            await audit.appendAdminAuditEventInTransaction({
              tx,
              organizationId: values.actor.organizationId,
              actorId: values.actor.memberId,
              eventType,
              targetType: "owner_recovery_outbox",
              targetId: values.eventId,
              details: {
                operation,
                expected_management_version: values.expectedManagementVersion,
                management_version: row.management_version,
                redrive_count: row.redrive_count,
                total_attempts: row.total_attempts,
                ...(reason === undefined ? {} : { reason })
              },
              idempotencyKey: auditIdempotencyKey({ values, operation })
            });
          } catch (error) {
            throw auditUnavailable(error);
          }
          await controls.completeIdempotency({
            tx,
            organizationId: values.actor.organizationId,
            principalId: values.actor.memberId,
            idempotencyKey: values.idempotencyKey,
            requestHash,
            responseStatus: 200,
            response: row
          });
          return { state: "committed", responseStatus: 200, response: row };
      });
      if (outcome.state === "committed" || outcome.state === "replay") return outcome.response;
      if (outcome.state === "conflict") throw new OwnerRecoveryOutboxManagementRepositoryError(OWNER_RECOVERY_OUTBOX_MANAGEMENT_ERROR_CODES.IDEMPOTENCY_CONFLICT);
      if (outcome.state === "in_progress") throw new OwnerRecoveryOutboxManagementRepositoryError(OWNER_RECOVERY_OUTBOX_MANAGEMENT_ERROR_CODES.IDEMPOTENCY_IN_PROGRESS);
      throw database();
    } catch (error) {
      if (error instanceof OwnerRecoveryOutboxManagementRepositoryError) throw error;
      if (error instanceof SharedControlRepositoryError) {
        if (error.code === "idempotency_conflict") throw new OwnerRecoveryOutboxManagementRepositoryError(OWNER_RECOVERY_OUTBOX_MANAGEMENT_ERROR_CODES.IDEMPOTENCY_CONFLICT);
        throw database(error);
      }
      throw database(error);
    }
  }
}

function normalizeActor(value) {
  if (!isObject(value)) throw invalidInput();
  const keys = Object.keys(value);
  if (keys.length !== 4 || keys.some((key) => !["organization_id", "member_id", "session_id", "role"].includes(key))) throw invalidInput();
  const role = typeof value.role === "string" ? value.role : "";
  if (!MANAGEMENT_ROLES.has(role)) throw forbidden();
  return Object.freeze({
    organizationId: uuid(value.organization_id),
    memberId: uuid(value.member_id),
    sessionId: uuid(value.session_id),
    role
  });
}

function normalizeMutation(input, { reasonRequired }) {
  if (!isObject(input)) throw invalidInput();
  const allowed = new Set(["actor", "event_id", "expected_management_version", "idempotency_key", "reason", "recent_authorization"]);
  if (Object.keys(input).some((key) => !allowed.has(key))) throw invalidInput();
  const actor = normalizeActor(input.actor);
  const reasonValue = input.reason;
  if (reasonRequired && reasonValue === undefined) throw invalidInput();
  const reason = reasonValue === undefined ? undefined : safeReason(reasonValue);
  return Object.freeze({
    actor,
    eventId: uuid(input.event_id),
    expectedManagementVersion: positiveInteger(input.expected_management_version),
    idempotencyKey: idempotency(input.idempotency_key),
    authorization: normalizeAuthorization(input.recent_authorization, actor),
    ...(reason === undefined ? {} : { reason })
  });
}

function normalizeAuthorization(value, actor) {
  if (!isObject(value) || Object.keys(value).sort().join(",") !== "authenticated_at,challenge_id,operation,session_id"
    || uuid(value.session_id) !== actor.sessionId || !Number.isSafeInteger(value.authenticated_at) || value.authenticated_at < 0
    || typeof value.operation !== "string" || !Object.values(OWNER_RECOVERY_OUTBOX_MANAGEMENT_OPERATIONS).includes(value.operation)) throw forbidden();
  return Object.freeze({
    sessionId: actor.sessionId,
    challengeId: uuid(value.challenge_id),
    operation: value.operation,
    authenticatedAt: value.authenticated_at
  });
}

async function requireCurrentAuthorization(tx, values, expectedOperation) {
  if (values.authorization.operation !== expectedOperation) throw forbidden();
  const authenticatedAt = new Date(values.authorization.authenticatedAt);
  if (!Number.isFinite(authenticatedAt.getTime())) throw forbidden();
  const result = await tx.query(`SELECT s.id
    FROM human_sessions s
    JOIN memberships m ON m.organization_id=s.organization_id AND m.id=s.membership_id AND m.member_id=s.member_id
    JOIN organizations o ON o.id=s.organization_id
    WHERE s.id=$1 AND s.member_id=$2 AND s.organization_id=$3 AND s.role=$4
      AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp()
      AND (s.idle_expires_at IS NULL OR s.idle_expires_at>clock_timestamp())
      AND m.status='active' AND m.role=s.role AND m.role IN ('owner','admin')
      AND s.organization_authority_epoch=o.authority_epoch
      AND s.membership_session_epoch=m.session_epoch
      AND s.recent_auth_challenge_id=$5 AND s.recent_auth_organization_id=$3
      AND s.recent_auth_operation=$6 AND s.recent_auth_consumed_at IS NOT NULL
      AND s.recent_auth_at=$7::timestamptz
      AND s.recent_auth_at>clock_timestamp()-INTERVAL '5 minutes'
    FOR UPDATE OF s,m,o`, [values.actor.sessionId, values.actor.memberId, values.actor.organizationId, values.actor.role, values.authorization.challengeId, expectedOperation, authenticatedAt.toISOString()]);
  if (rowCount(result) !== 1) throw forbidden();
}

function decodeCursor(value, actor, codec) {
  if (value === undefined) return undefined;
  if (typeof value !== "string" || value.length < 1 || value.length > MAX_CURSOR_LENGTH || !BASE64URL.test(value)) throw invalidCursor();
  try {
    const decoded = codec.decode(value, { resource: RESOURCE, tenant_id: actor.organizationId, member_id: actor.memberId, direction: DIRECTION });
    if (!decoded || decoded.resource !== RESOURCE || decoded.direction !== DIRECTION) throw invalidCursor();
    return Object.freeze({ created_at: timestamp(decoded.created_at), id: uuid(decoded.id) });
  } catch (error) {
    if (error instanceof OwnerRecoveryOutboxManagementRepositoryError) throw error;
    throw invalidCursor();
  }
}

function encodeCursor(actor, row, codec) {
  try {
    const cursor = codec.encode({
      resource: RESOURCE,
      tenant_id: actor.organizationId,
      member_id: actor.memberId,
      created_at: row.created_at,
      id: row.event_id,
      direction: DIRECTION
    });
    if (typeof cursor !== "string" || cursor.length < 1 || cursor.length > MAX_CURSOR_LENGTH || !BASE64URL.test(cursor)) throw invalidCursor();
    return cursor;
  } catch (error) {
    if (error instanceof OwnerRecoveryOutboxManagementRepositoryError) throw error;
    throw invalidCursor();
  }
}

function publicDeadLetter(row = {}) {
  if (!row || typeof row !== "object" || Array.isArray(row)) throw database();
  if (row.status !== "dead_letter") throw database();
  return Object.freeze({
    organization_id: uuid(row.organization_id),
    event_id: uuid(row.event_id),
    request_id: uuid(row.request_id),
    subject_member_id: uuid(row.subject_member_id),
    event_type: eventType(row.event_type),
    status: "dead_letter",
    attempts: positiveInteger(row.attempts),
    total_attempts: nonNegativeInteger(row.total_attempts),
    management_version: positiveInteger(row.management_version),
    redrive_count: nonNegativeInteger(row.redrive_count),
    last_error_code: errorCode(row.last_error_code),
    created_at: timestamp(row.created_at),
    updated_at: timestamp(row.updated_at),
    suppressed_at: nullableTimestamp(row.suppressed_at),
    suppression_reason: nullableReason(row.suppression_reason)
  });
}

function publicMutation(row = {}) {
  if (!row || typeof row !== "object" || Array.isArray(row)) throw database();
  const status = row.status;
  if (status !== "pending" && status !== "suppressed") throw database();
  return Object.freeze({
    organization_id: uuid(row.organization_id),
    event_id: uuid(row.event_id),
    status,
    attempts: nonNegativeInteger(row.attempts),
    total_attempts: nonNegativeInteger(row.total_attempts),
    management_version: positiveInteger(row.management_version),
    redrive_count: nonNegativeInteger(row.redrive_count),
    suppressed_at: nullableTimestamp(row.suppressed_at),
    suppression_reason: nullableReason(row.suppression_reason)
  });
}

function auditIdempotencyKey({ values, operation }) {
  const digest = crypto.createHash("sha256").update(canonicalJson({
    version: 1,
    organization_id: values.actor.organizationId,
    event_id: values.eventId,
    actor_member_id: values.actor.memberId,
    idempotency_key: values.idempotencyKey,
    operation
  })).digest("hex");
  return `outbox-management-${digest}`;
}

function boundedLimit(value) { if (value === undefined) return DEFAULT_LIMIT; if (!Number.isSafeInteger(value) || value < 1 || value > MAX_LIMIT) throw invalidInput(); return value; }
function idempotency(value) { if (typeof value !== "string" || !IDEMPOTENCY_KEY.test(value)) throw invalidInput(); return value; }
function safeReason(value) { if (typeof value !== "string" || value.length < 1 || CONTROL.test(value) || Buffer.byteLength(value, "utf8") > MAX_REASON_BYTES) throw invalidInput(); return value; }
function nullableReason(value) { return value === null || value === undefined ? null : safeReason(value); }
function errorCode(value) { if (typeof value !== "string" || !/^[a-z][a-z0-9_]{0,127}$/u.test(value)) throw database(); return value; }
function eventType(value) { if (typeof value !== "string" || !EVENT_TYPE.test(value)) throw database(); return value; }
function timestamp(value) { const date = value instanceof Date ? value : new Date(value); if (!Number.isFinite(date.getTime())) throw database(); return date.toISOString(); }
function nullableTimestamp(value) { return value === null || value === undefined ? null : timestamp(value); }
function uuid(value) { if (typeof value !== "string" || !UUID.test(value)) throw invalidInput(); return value.toLowerCase(); }
function positiveInteger(value) { const result = typeof value === "string" ? Number(value) : value; if (!Number.isSafeInteger(result) || result < 1) throw invalidInput(); return result; }
function nonNegativeInteger(value) { const result = typeof value === "string" ? Number(value) : value; if (!Number.isSafeInteger(result) || result < 0) throw database(); return result; }
function rowCount(result) { return Number(result?.rowCount ?? result?.rows?.length ?? 0); }
function isObject(value) { return value !== null && typeof value === "object" && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype; }
function invalidInput() { return new OwnerRecoveryOutboxManagementRepositoryError(OWNER_RECOVERY_OUTBOX_MANAGEMENT_ERROR_CODES.INVALID_INPUT); }
function forbidden() { return new OwnerRecoveryOutboxManagementRepositoryError(OWNER_RECOVERY_OUTBOX_MANAGEMENT_ERROR_CODES.FORBIDDEN); }
function invalidCursor() { return new OwnerRecoveryOutboxManagementRepositoryError(OWNER_RECOVERY_OUTBOX_MANAGEMENT_ERROR_CODES.INVALID_CURSOR); }
function versionConflict() { return new OwnerRecoveryOutboxManagementRepositoryError(OWNER_RECOVERY_OUTBOX_MANAGEMENT_ERROR_CODES.VERSION_CONFLICT); }
function auditUnavailable() { return new OwnerRecoveryOutboxManagementRepositoryError(OWNER_RECOVERY_OUTBOX_MANAGEMENT_ERROR_CODES.AUDIT); }
function database() { return new OwnerRecoveryOutboxManagementRepositoryError(OWNER_RECOVERY_OUTBOX_MANAGEMENT_ERROR_CODES.DATABASE); }
function assertClient(client) { if (!client || typeof client.query !== "function") throw new TypeError("database client must provide query(text, params)"); }

export default createPostgresOwnerRecoveryOutboxManagementRepository;
