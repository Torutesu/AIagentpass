import { auditCursorBinding, createAuditCursorCodec, normalizeAuditPageInput } from "../audit-pagination.mjs";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;

export class PostgresAuditRepositoryError extends Error {
  constructor(code, message, cause = undefined) {
    super(message, cause === undefined ? undefined : { cause });
    this.name = "PostgresAuditRepositoryError";
    this.code = code;
    if (cause !== undefined) this.cause = cause;
  }
}

/**
 * Read-only PostgreSQL source for the Cloud device-audit activity stream.
 * G3 deliberately keeps ingestion and the rest of the control plane outside
 * this repository; callers can adopt this source independently.
 */
export function createPostgresAuditRepository({ client, cursorCodec, cursorSecret, now = () => Date.now() } = {}) {
  assertClient(client);
  if (typeof now !== "function") throw new TypeError("now must be a function");
  const codec = cursorCodec ?? createAuditCursorCodec({ secret: cursorSecret, now });
  if (!codec || typeof codec.decode !== "function" || typeof codec.encode !== "function") throw new TypeError("cursorCodec must expose encode() and decode()");

  async function listDeviceAuditEvents(input = {}) {
    const organizationId = requiredUuid(input.organization_id ?? input.organizationId);
    const page = normalizeAuditPageInput(input);
    const position = page.cursor === undefined ? null : codec.decode(page.cursor, auditCursorBinding(organizationId, page.device_id));
    const params = [organizationId];
    const clauses = ["organization_id = $1"];
    if (page.device_id !== null) {
      params.push(page.device_id);
      clauses.push(`device_id = $${params.length}`);
    }
    if (position !== null) {
      const timestampParameter = params.length + 1;
      params.push(position.device_timestamp, position.device_id, position.event_id);
      clauses.push(`((redacted_json ->> 'device_timestamp'), device_id, event_id) < ($${timestampParameter}, $${timestampParameter + 1}::uuid, $${timestampParameter + 2}::uuid)`);
    }
    params.push(page.limit + 1);
    const result = await client.query(`SELECT organization_id,device_id,event_id,redacted_json,received_at
      FROM device_audit_events
      WHERE ${clauses.join(" AND ")}
      ORDER BY (redacted_json ->> 'device_timestamp') DESC,device_id DESC,event_id DESC
      LIMIT $${params.length}`, params);
    const records = (result.rows ?? []).map(safeAuditRow);
    const hasNext = records.length > page.limit;
    const events = records.slice(0, page.limit);
    const last = events.at(-1);
    const next_cursor = hasNext
      ? codec.encode({ organization_id: organizationId, device_id: page.device_id, device_timestamp: last.event.device_timestamp, event_id: last.event_id })
      : null;
    return Object.freeze({ events: Object.freeze(events), next_cursor });
  }

  return Object.freeze({ listDeviceAuditEvents });
}

function safeAuditRow(row = {}) {
  const organizationId = requiredUuid(String(row.organization_id));
  const deviceId = requiredUuid(String(row.device_id));
  const eventId = requiredUuid(String(row.event_id));
  if (!row.redacted_json || typeof row.redacted_json !== "object" || Array.isArray(row.redacted_json)) throw new PostgresAuditRepositoryError("ERR_AUDIT_ROW", "stored audit event is invalid");
  const event = structuredClone(row.redacted_json);
  const deviceTimestamp = returnedTimestamp(event.device_timestamp);
  if (event.event_id !== eventId || event.device_timestamp !== deviceTimestamp) throw new PostgresAuditRepositoryError("ERR_AUDIT_ROW", "stored audit event key is inconsistent");
  const receivedAt = returnedTimestamp(row.received_at);
  return Object.freeze({
    organization_id: organizationId,
    device_id: deviceId,
    event_id: eventId,
    event,
    received_at: receivedAt
  });
}

function requiredUuid(value) { if (typeof value !== "string" || !UUID.test(value)) throw new PostgresAuditRepositoryError("ERR_INVALID_INPUT", "audit identifier is invalid"); return value.toLowerCase(); }
function returnedTimestamp(value) {
  const date = value instanceof Date ? value : new Date(value);
  if (!Number.isFinite(date.getTime())) throw new PostgresAuditRepositoryError("ERR_AUDIT_ROW", "stored audit timestamp is invalid");
  return date.toISOString();
}
function assertClient(client) { if (!client || typeof client.query !== "function") throw new TypeError("database client is invalid"); }

export default createPostgresAuditRepository;
