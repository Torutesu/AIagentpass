import crypto from "node:crypto";

import { canonicalJson } from "../../../../packages/protocol/src/index.mjs";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
const EVENT_TYPE = /^platform\.promotion\.[a-z_]+\.[a-z_]+$/u;
const IDEMPOTENCY = /^[A-Za-z0-9][A-Za-z0-9._~:-]{7,254}$/u;
const ROLE = new Set(["platform_admin", "platform_operator", "platform_auditor"]);
const SENSITIVE = /(?:^|_)(?:authorization|bearer|cookie|credential|csrf|nonce|password|private|secret|session|signature|token)(?:_|$)/iu;
const CONTROL = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/u;
const MAX_DETAILS_BYTES = 128 * 1024;

export class PlatformPromotionAuditRepositoryError extends Error {
  constructor(code) {
    super(code === "ERR_CONFLICT" ? "platform audit idempotency conflict" : "platform audit storage is unavailable");
    this.name = "PlatformPromotionAuditRepositoryError";
    this.code = `ERR_PLATFORM_AUDIT_${code.slice(4)}`;
  }
}

export function createPostgresPlatformPromotionAuditRepository({ client, now = () => new Date() } = {}) {
  if (!client || typeof client.query !== "function" || typeof now !== "function") throw auditError("ERR_CONFIG");

  async function appendPlatformAuditEvent(input = {}) {
    const event = normalizeEvent(input, now);
    const transactionClient = input.tx ?? client;
    if (!transactionClient || typeof transactionClient.query !== "function") throw auditError("ERR_CONFIG");
    // Idempotency is about the logical event, not transport-generated event
    // ids or insertion time. Excluding those two values makes a retry with
    // the same key converge to the original immutable row.
    const eventHash = crypto.createHash("sha256").update(canonicalJson({
      kind: "agentpass.platform-promotion-audit.v1",
      request_id: event.request_id,
      event_type: event.event_type,
      actor_id: event.actor_id,
      platform_role: event.platform_role,
      target_type: event.target_type,
      target_id: event.target_id,
      idempotency_key: event.idempotency_key,
      details: event.details
    })).digest();
    try {
      const inserted = await transactionClient.query(`INSERT INTO platform_promotion_audit_events
        (event_id,request_id,event_type,actor_id,platform_role,target_type,target_id,idempotency_key,details,event_hash,recorded_at)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10,$11)
        ON CONFLICT (idempotency_key) DO NOTHING
        RETURNING event_id,recorded_at`, [
        event.event_id, event.request_id, event.event_type, event.actor_id, event.platform_role,
        event.target_type, event.target_id, event.idempotency_key, JSON.stringify(event.details), eventHash,
        event.recorded_at
      ]);
      if (inserted.rowCount === 1) return Object.freeze({ event_id: inserted.rows[0].event_id, recorded_at: inserted.rows[0].recorded_at });
      const existing = await transactionClient.query("SELECT event_id,encode(event_hash,'hex') AS event_hash FROM platform_promotion_audit_events WHERE idempotency_key=$1", [event.idempotency_key]);
      if (existing.rowCount !== 1 || existing.rows[0].event_hash !== eventHash.toString("hex")) throw auditError("ERR_CONFLICT");
      return Object.freeze({ idempotent: true, event_id: existing.rows[0].event_id });
    } catch (error) {
      if (error instanceof PlatformPromotionAuditRepositoryError) throw error;
      throw auditError("ERR_DATABASE");
    }
  }

  return Object.freeze({ appendPlatformAuditEvent });
}

function normalizeEvent(input, now) {
  if (!input || typeof input !== "object" || Array.isArray(input)) throw auditError("ERR_INPUT");
  const event_id = input.event_id ?? crypto.randomUUID();
  const request_id = input.request_id;
  const event_type = input.event_type;
  const actor_id = input.actor_id;
  const platform_role = input.platform_role;
  const target_type = input.target_type;
  const target_id = input.target_id;
  const idempotency_key = input.idempotency_key;
  const details = input.details;
  if (![event_id, request_id, target_id].every((value) => typeof value === "string" && UUID.test(value))) throw auditError("ERR_INPUT");
  if (typeof event_type !== "string" || !EVENT_TYPE.test(event_type) || typeof actor_id !== "string" || actor_id.length === 0 || actor_id.length > 255 || CONTROL.test(actor_id)) throw auditError("ERR_INPUT");
  if (typeof platform_role !== "string" || !ROLE.has(platform_role) || target_type !== "platform_promotion") throw auditError("ERR_INPUT");
  if (typeof idempotency_key !== "string" || !IDEMPOTENCY.test(idempotency_key)) throw auditError("ERR_INPUT");
  if (!details || typeof details !== "object" || Array.isArray(details)) throw auditError("ERR_INPUT");
  const safeDetails = rejectSensitiveValues(details);
  if (Buffer.byteLength(JSON.stringify(safeDetails), "utf8") > MAX_DETAILS_BYTES) throw auditError("ERR_INPUT");
  const recorded_at = now();
  if (!(recorded_at instanceof Date) || !Number.isFinite(recorded_at.getTime())) throw auditError("ERR_INPUT");
  return { event_id, request_id, event_type, actor_id, platform_role, target_type, target_id, idempotency_key, details: safeDetails, recorded_at: recorded_at.toISOString() };
}

function rejectSensitiveValues(value, path = "details") {
  if (typeof value === "string") {
    if (CONTROL.test(value)) throw auditError("ERR_INPUT");
    return value;
  }
  if (Array.isArray(value)) return value.map((entry, index) => rejectSensitiveValues(entry, `${path}[${index}]`));
  if (!value || typeof value !== "object") return value;
  const output = {};
  for (const [key, entry] of Object.entries(value)) {
    if (SENSITIVE.test(key) || CONTROL.test(key)) throw auditError("ERR_INPUT");
    output[key] = rejectSensitiveValues(entry, `${path}.${key}`);
  }
  return output;
}

function auditError(code) {
  return new PlatformPromotionAuditRepositoryError(code);
}
