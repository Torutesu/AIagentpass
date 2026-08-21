import crypto from "node:crypto";
import { canonicalJson, normalizeAuditEvent } from "../../../packages/protocol/src/index.mjs";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
const BATCH_ID = /^audit-[0-9a-f]{64}$/u;

export class DeviceAuditIngestionError extends Error {
  constructor(code, message, details = undefined) { super(message); this.name = "DeviceAuditIngestionError"; this.code = code; if (details !== undefined) this.details = details; }
}

export function normalizeDeviceAuditUpload({ organizationId, deviceId, batchId, events } = {}) {
  if (!UUID.test(String(organizationId ?? "")) || !UUID.test(String(deviceId ?? ""))) throw new DeviceAuditIngestionError("ERR_AUDIT_INPUT", "audit upload scope is invalid");
  if (!BATCH_ID.test(String(batchId ?? ""))) throw new DeviceAuditIngestionError("ERR_AUDIT_BATCH_ID", "batch_id is invalid");
  if (!Array.isArray(events) || events.length < 1 || events.length > 64) throw new DeviceAuditIngestionError("ERR_AUDIT_INPUT", "events must contain 1-64 items");
  let normalized;
  try { normalized = events.map((event) => normalizeAuditEvent(event)); } catch (error) { throw new DeviceAuditIngestionError("ERR_AUDIT_EVENT_INVALID", "audit event is invalid", error); }
  assertDeviceAuditChainOrdered(normalized);
  const expectedBatchId = deterministicDeviceAuditBatchId(organizationId, deviceId, normalized);
  if (batchId !== expectedBatchId) throw new DeviceAuditIngestionError("ERR_AUDIT_BATCH_ID", "batch_id does not match the canonical audit batch content", { expected_batch_id: expectedBatchId });
  return Object.freeze({ organization_id: organizationId, device_id: deviceId, batch_id: batchId, events: Object.freeze(normalized) });
}

export function deterministicDeviceAuditBatchId(organizationId, deviceId, events) {
  // The organization/device are authenticated transport bindings and are not
  // part of the body identity. This must remain byte-compatible with the
  // NativeDeviceAuditBatch implementation, which only has the ordered events
  // when it constructs the retry identity.
  void organizationId;
  void deviceId;
  return `audit-${crypto.createHash("sha256").update(canonicalJson({ events }), "utf8").digest("hex")}`;
}

export function assertDeviceAuditChainOrdered(events) {
  const seen = new Set();
  for (let index = 0; index < events.length; index += 1) {
    const event = events[index];
    if (seen.has(event.event_id)) throw new DeviceAuditIngestionError("ERR_AUDIT_CHAIN_ORDER", "event_id values must be unique within a batch");
    seen.add(event.event_id);
    if (index > 0 && event.previous_hash !== events[index - 1].event_hash) throw new DeviceAuditIngestionError("ERR_AUDIT_CHAIN_ORDER", "events must be hash-chain ordered");
  }
}
