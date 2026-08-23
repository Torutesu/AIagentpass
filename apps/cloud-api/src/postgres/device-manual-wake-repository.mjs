import crypto from "node:crypto";

import { canonicalJson } from "../../../../packages/protocol/src/index.mjs";
import { withTransaction } from "./repository.mjs";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
const IDEMPOTENCY_KEY = /^[A-Za-z0-9._~-]{8,255}$/u;
const EMPTY_BODY = Object.freeze({});
const RESULTS = new Set(["accepted", "coalesced", "no_pending_refresh"]);
const ROLES = new Set(["owner", "admin"]);
const DEFAULT_MAX_WAKE_COUNT = 1000;

export const DEVICE_MANUAL_WAKE_CHANNEL = "agentpass_refresh_hint_v1";
export const DEVICE_MANUAL_WAKE_RESULTS = Object.freeze(["accepted", "coalesced", "no_pending_refresh"]);

export class DeviceManualWakeRepositoryError extends Error {
  constructor(code, message, cause = undefined) {
    super(message, cause === undefined ? undefined : { cause });
    this.name = "DeviceManualWakeRepositoryError";
    this.code = code;
  }
}

/**
 * PostgreSQL authority-neutral device wake repository.
 *
 * The public method owns a transaction.  The InTransaction variant performs
 * no BEGIN/COMMIT/connection checkout and is intended for a caller-owned
 * transaction that must include the wake ledger in a larger mutation.
 */
export function createPostgresDeviceManualWakeRepository({
  client,
  now = () => new Date().toISOString(),
  maxWakeCount = DEFAULT_MAX_WAKE_COUNT
} = {}) {
  assertClient(client);
  if (typeof now !== "function") throw new TypeError("now must be a function");
  if (!Number.isSafeInteger(maxWakeCount) || maxWakeCount < 1 || maxWakeCount > 1_000_000) {
    throw new TypeError("maxWakeCount must be a safe integer between 1 and 1000000");
  }

  async function requestDeviceManualWake(input = {}) {
    const values = normalizeInput(input, now);
    if (input?.tx !== undefined) return requestDeviceManualWakeInTransaction({ ...input, ...values });
    try {
      return await inTransaction((tx) => requestDeviceManualWakeInTransaction({ ...input, ...values, tx }));
    } catch (error) {
      throw mapError(error);
    }
  }

  async function requestDeviceManualWakeInTransaction(input = {}) {
    const tx = input?.tx;
    assertTransactionClient(tx);
    const values = input.organization_id && input.device_id && input.actor_id && input.idempotency_key && input.body_digest
      ? normalizeNormalizedInput(input)
      : normalizeInput(input, now);
    try {
      await storageQuery(tx, "idempotency_lock",
        "SELECT pg_advisory_xact_lock(hashtextextended($1, 0)) AS locked",
        [`agentpass:device-manual-wake:idempotency:${values.organizationId}:${values.actorId}:${values.idempotencyKey}`]
      );

      const state = await storageQuery(tx, "device_state", `SELECT d.id AS device_id,d.status AS device_status,
          state.desired_generation,state.observed_generation,state.refresh_state,
          active.outbox_id AS active_outbox_id
        FROM devices AS d
        JOIN device_control_plane_state AS state
          ON state.organization_id=d.organization_id AND state.device_id=d.id
        LEFT JOIN LATERAL (
          SELECT outbox.outbox_id
          FROM device_refresh_outbox AS outbox
          WHERE outbox.organization_id=d.organization_id
            AND outbox.device_id=d.id
            AND outbox.desired_generation=state.desired_generation
            AND outbox.status IN ('pending','delivered')
          ORDER BY outbox.created_at ASC,outbox.outbox_id ASC
          LIMIT 1
        ) AS active ON TRUE
        WHERE d.organization_id=$1 AND d.id=$2
        FOR UPDATE OF d,state`, [values.organizationId, values.deviceId]);
      if (rowCount(state) !== 1 || state.rows[0].device_status !== "active" || state.rows[0].refresh_state === "revoked") {
        throw new DeviceManualWakeRepositoryError("ERR_DEVICE_UNAVAILABLE", "device is unavailable for manual wake");
      }

      const actor = await storageQuery(tx, "actor_membership", `SELECT role
        FROM memberships
        WHERE organization_id=$1 AND member_id=$2 AND status='active'
        FOR SHARE`, [values.organizationId, values.actorId]);
      if (rowCount(actor) !== 1 || !ROLES.has(actor.rows[0].role)) {
        throw new DeviceManualWakeRepositoryError("ERR_ACTOR_UNAVAILABLE", "manual wake actor is unavailable");
      }

      const existing = await storageQuery(tx, "replay_ledger", `SELECT request_id,organization_id,device_id,actor_id,idempotency_key,
          body_digest,desired_generation,active_outbox_id,result,requested_at,response_json
        FROM device_manual_wake_requests
        WHERE organization_id=$1 AND actor_id=$2 AND idempotency_key=$3
        FOR UPDATE`, [values.organizationId, values.actorId, values.idempotencyKey]);
      if (rowCount(existing) === 1) {
        const row = existing.rows[0];
        if (row.device_id !== values.deviceId || !sameDigest(row.body_digest, values.bodyDigest)) {
          throw new DeviceManualWakeRepositoryError("ERR_IDEMPOTENCY_CONFLICT", "idempotency key conflicts with another manual wake request");
        }
        return publicStoredResponse(row.response_json);
      }

      const desiredGeneration = generationNumber(state.rows[0].desired_generation);
      const observedGeneration = state.rows[0].observed_generation === null || state.rows[0].observed_generation === undefined
        ? null
        : generationNumber(state.rows[0].observed_generation);
      const generationNeedsRefresh = observedGeneration === null || observedGeneration < desiredGeneration;
      let activeOutboxId = null;
      if (generationNeedsRefresh) {
        const selectedOutbox = await storageQuery(tx, "refresh_outbox", `SELECT outbox_id
          FROM device_refresh_outbox
          WHERE organization_id=$1 AND device_id=$2 AND desired_generation=$3
            AND status IN ('pending','delivered')
          ORDER BY created_at ASC,outbox_id ASC
          LIMIT 1
          FOR UPDATE`, [values.organizationId, values.deviceId, desiredGeneration]);
        activeOutboxId = rowCount(selectedOutbox) === 1 ? uuid(selectedOutbox.rows[0].outbox_id, "active_outbox_id") : null;
      }
      const result = activeOutboxId === null ? "no_pending_refresh" : await upsertWakeEvent(tx, {
        organizationId: values.organizationId,
        deviceId: values.deviceId,
        desiredGeneration,
        activeOutboxId,
        actorId: values.actorId,
        requestedAt: values.requestedAt,
        maxWakeCount
      });
      const response = publicResponse({
        request_id: values.requestId,
        device_id: values.deviceId,
        desired_generation: desiredGeneration,
        result,
        requested_at: values.requestedAt
      });
      const inserted = await storageQuery(tx, "request_ledger", `INSERT INTO device_manual_wake_requests
          (organization_id,device_id,actor_id,idempotency_key,request_id,body_digest,
           desired_generation,active_outbox_id,result,requested_at,response_json)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::timestamptz,$11::jsonb)
        RETURNING request_id`, [
        values.organizationId, values.deviceId, values.actorId, values.idempotencyKey,
        values.requestId, values.bodyDigest, desiredGeneration, activeOutboxId, result,
        values.requestedAt, JSON.stringify(response)
      ]);
      if (rowCount(inserted) !== 1) throw new DeviceManualWakeRepositoryError("ERR_DATABASE", "manual wake replay evidence could not be recorded");
      return response;
    } catch (error) {
      if (error instanceof DeviceManualWakeRepositoryError) throw error;
      throw new DeviceManualWakeRepositoryError("ERR_DATABASE", "manual wake storage is unavailable", error);
    }
  }

  async function inTransaction(operation) {
    const tx = typeof client.connect === "function" ? await client.connect() : client;
    try {
      return await withTransaction(tx, operation);
    } finally {
      if (tx !== client) tx.release?.();
    }
  }

  return Object.freeze({
    requestDeviceManualWake,
    requestManualWake: requestDeviceManualWake,
    requestDeviceWake: requestDeviceManualWake,
    requestDeviceManualWakeInTransaction
  });
}

async function upsertWakeEvent(tx, values) {
  const inserted = await storageQuery(tx, "wake_event_insert", `INSERT INTO device_manual_wake_events
      (organization_id,device_id,desired_generation,active_outbox_id,wake_count,
       first_requested_at,last_requested_at,last_actor_id)
    VALUES ($1,$2,$3,$4,1,$5::timestamptz,$5::timestamptz,$6)
    ON CONFLICT (organization_id,device_id,desired_generation) DO NOTHING
    RETURNING desired_generation`, [
    values.organizationId, values.deviceId, values.desiredGeneration,
    values.activeOutboxId, values.requestedAt, values.actorId
  ]);
  if (rowCount(inserted) === 1) return "accepted";

  const updated = await storageQuery(tx, "wake_event_update", `UPDATE device_manual_wake_events
    SET active_outbox_id=$4,
        wake_count=LEAST(wake_count+1,$5),
        last_requested_at=$6::timestamptz,
        last_actor_id=$7
    WHERE organization_id=$1 AND device_id=$2 AND desired_generation=$3
    RETURNING desired_generation`, [
    values.organizationId, values.deviceId, values.desiredGeneration,
    values.activeOutboxId, values.maxWakeCount, values.requestedAt, values.actorId
  ]);
  if (rowCount(updated) !== 1) throw new DeviceManualWakeRepositoryError("ERR_DATABASE", "manual wake event disappeared during coalescing");
  return "coalesced";
}

function normalizeInput(input, now) {
  if (!input || typeof input !== "object" || Array.isArray(input)) throw inputError("input must be an object");
  const organizationId = uuid(input.organization_id ?? input.organizationId, "organization_id");
  const deviceId = uuid(input.device_id ?? input.deviceId, "device_id");
  const actorId = uuid(input.actor_id ?? input.actorId ?? input.principal_id ?? input.principalId, "actor_id");
  const idempotencyKey = idempotency(input.idempotency_key ?? input.idempotencyKey);
  const body = normalizeBody(input.body);
  const requestedAt = timestamp(input.requested_at ?? input.requestedAt ?? now(), "requested_at");
  const bodyDigest = sha256Buffer(canonicalJson(body));
  const requestId = deterministicUuid({ version: 1, organization_id: organizationId, device_id: deviceId, actor_id: actorId, idempotency_key: idempotencyKey, body_digest: bodyDigest.toString("hex") });
  return Object.freeze({ organizationId, deviceId, actorId, idempotencyKey, bodyDigest, requestedAt, requestId });
}

function normalizeNormalizedInput(input) {
  return Object.freeze({
    organizationId: uuid(input.organization_id, "organization_id"),
    deviceId: uuid(input.device_id, "device_id"),
    actorId: uuid(input.actor_id, "actor_id"),
    idempotencyKey: idempotency(input.idempotency_key),
    bodyDigest: digestBuffer(input.body_digest),
    requestedAt: timestamp(input.requested_at, "requested_at"),
    requestId: uuid(input.request_id, "request_id")
  });
}

function normalizeBody(value) {
  if (value === undefined) return EMPTY_BODY;
  if (!value || typeof value !== "object" || Array.isArray(value) || Object.keys(value).length !== 0) {
    throw inputError("body must be exactly an empty JSON object");
  }
  return EMPTY_BODY;
}

function publicResponse(value) {
  return Object.freeze({
    version: 1,
    request_id: uuid(value.request_id, "request_id"),
    device_id: uuid(value.device_id, "device_id"),
    desired_generation: generationNumber(value.desired_generation),
    status: result(value.result ?? value.status),
    requested_at: timestamp(value.requested_at, "requested_at")
  });
}

function publicStoredResponse(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new DeviceManualWakeRepositoryError("ERR_DATABASE", "stored manual wake response is invalid");
  const response = publicResponse(value);
  if (Object.keys(value).sort().join(",") !== ["desired_generation", "device_id", "request_id", "requested_at", "status", "version"].join(",")) {
    throw new DeviceManualWakeRepositoryError("ERR_DATABASE", "stored manual wake response contains unexpected fields");
  }
  return response;
}

function mapError(error) {
  if (error instanceof DeviceManualWakeRepositoryError) return error;
  if (error?.code === "23505") return new DeviceManualWakeRepositoryError("ERR_IDEMPOTENCY_CONFLICT", "manual wake identity conflicts with an existing request", error);
  if (error?.code === "23503") return new DeviceManualWakeRepositoryError("ERR_DEVICE_UNAVAILABLE", "device is unavailable for manual wake", error);
  return new DeviceManualWakeRepositoryError("ERR_DATABASE", "manual wake storage is unavailable", error);
}

async function storageQuery(tx, phase, text, params) {
  try {
    return await tx.query(text, params);
  } catch (error) {
    const wrapped = new DeviceManualWakeRepositoryError("ERR_DATABASE", "manual wake storage is unavailable", error);
    Object.defineProperty(wrapped, "storagePhase", { value: phase, enumerable: false });
    throw wrapped;
  }
}

function assertClient(client) { if (!client || typeof client.query !== "function") throw new TypeError("client must provide query(text, params)"); }
function assertTransactionClient(tx) { if (!tx || typeof tx.query !== "function") throw inputError("tx must provide query(text, params)"); }
function rowCount(result) { return Number(result?.rowCount ?? result?.rows?.length ?? 0); }
function inputError(message) { return new DeviceManualWakeRepositoryError("ERR_INPUT", message); }
function uuid(value, field) { if (typeof value !== "string" || !UUID.test(value)) throw inputError(`${field} must be a UUID`); return value.toLowerCase(); }
function idempotency(value) { if (typeof value !== "string" || !IDEMPOTENCY_KEY.test(value)) throw inputError("idempotency_key is invalid"); return value; }
function result(value) { if (typeof value !== "string" || !RESULTS.has(value)) throw new DeviceManualWakeRepositoryError("ERR_DATABASE", "stored manual wake result is invalid"); return value; }
function generationNumber(value) {
  try {
    const parsed = typeof value === "bigint" ? value : BigInt(String(value));
    if (parsed < 1n || parsed > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error();
    return Number(parsed);
  } catch { throw new DeviceManualWakeRepositoryError("ERR_DATABASE", "manual wake desired generation is invalid"); }
}
function timestamp(value, field) {
  if (typeof value !== "string" && !(value instanceof Date)) throw inputError(`${field} must be a timestamp`);
  const date = value instanceof Date ? value : new Date(value);
  if (!Number.isFinite(date.getTime())) throw inputError(`${field} must be a valid timestamp`);
  return date.toISOString();
}
function digestBuffer(value) {
  if (Buffer.isBuffer(value) && value.length === 32) return Buffer.from(value);
  if (value instanceof Uint8Array && value.length === 32) return Buffer.from(value);
  throw new DeviceManualWakeRepositoryError("ERR_DATABASE", "stored body digest is invalid");
}
function sameDigest(left, right) { try { return crypto.timingSafeEqual(digestBuffer(left), digestBuffer(right)); } catch { return false; } }
function sha256Buffer(value) { return crypto.createHash("sha256").update(value, "utf8").digest(); }
function deterministicUuid(value) {
  const bytes = sha256Buffer(canonicalJson(value));
  bytes[6] = (bytes[6] & 0x0f) | 0x50;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = bytes.toString("hex");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20, 32)}`;
}
