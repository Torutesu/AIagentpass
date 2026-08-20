import crypto from "node:crypto";

import { canonicalJson } from "../../../packages/protocol/src/index.mjs";
import { normalizeDeviceAuditUpload } from "./device-audit-ingestion.mjs";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
const BATCH_ID = /^audit-[0-9a-f]{64}$/u;
const DIGEST = /^[0-9a-f]{64}$/u;
const STATES = new Set(["pending", "processing", "accepted", "uncertain", "dead_letter"]);
const OUTCOMES = new Set(["accepted", "retryable_failure", "uncertain"]);
const MAX_ATTEMPTS = 100;

export const DEVICE_AUDIT_INBOX_STATES = Object.freeze([...STATES]);
export const DEVICE_AUDIT_INBOX_MAX_ATTEMPTS = MAX_ATTEMPTS;

export class DeviceAuditInboxContractError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "DeviceAuditInboxContractError";
    this.code = code;
  }
}

export function normalizeDeviceAuditInboxEntry(input = {}, now = () => new Date().toISOString()) {
  if (!isObject(input) || typeof now !== "function") throw invalid("input");
  const upload = normalizeDeviceAuditUpload({
    organizationId: input.organization_id ?? input.organizationId,
    deviceId: input.device_id ?? input.deviceId,
    batchId: input.batch_id ?? input.batchId,
    events: input.events,
  });
  const organizationId = upload.organization_id;
  const deviceId = upload.device_id;
  const batchId = upload.batch_id;
  const payload = canonicalJson({ events: upload.events });
  const payloadDigest = sha256(payload);
  const createdAt = timestamp(now());
  return Object.freeze({
    organization_id: organizationId,
    device_id: deviceId,
    batch_id: batchId,
    payload_sha256: payloadDigest,
    events: upload.events,
    state: "pending",
    attempt: 0,
    claim_token_digest: null,
    claim_expires_at: null,
    created_at: createdAt,
    updated_at: createdAt,
  });
}

export function claimDeviceAuditInboxEntry(entry, { claimToken, now = () => new Date().toISOString(), leaseMs = 30_000 } = {}) {
  const current = normalizeStoredEntry(entry);
  if (current.state !== "pending") throw invalid("claim_state");
  if (typeof claimToken !== "string" || claimToken.length < 16 || claimToken.length > 512) throw invalid("claim_token");
  if (!Number.isSafeInteger(leaseMs) || leaseMs < 1_000 || leaseMs > 300_000) throw invalid("lease");
  if (current.attempt >= MAX_ATTEMPTS) throw invalid("attempt_limit");
  const start = Date.parse(timestamp(now()));
  const expires = new Date(start + leaseMs).toISOString();
  return Object.freeze({ ...current, state: "processing", attempt: current.attempt + 1, claim_token_digest: sha256(claimToken), claim_expires_at: expires, updated_at: new Date(start).toISOString() });
}

export function settleDeviceAuditInboxEntry(entry, { claimToken, outcome, now = () => new Date().toISOString() } = {}) {
  const current = normalizeStoredEntry(entry);
  if (current.state !== "processing" || typeof claimToken !== "string" || sha256(claimToken) !== current.claim_token_digest) throw invalid("claim");
  if (!OUTCOMES.has(outcome)) throw invalid("outcome");
  const currentTime = timestamp(now());
  if (current.claim_expires_at !== null && Date.parse(current.claim_expires_at) <= Date.parse(currentTime)) throw invalid("expired_claim");
  const nextState = outcome === "accepted" ? "accepted" : outcome === "uncertain" || current.attempt >= MAX_ATTEMPTS ? outcome === "uncertain" ? "uncertain" : "dead_letter" : "pending";
  return Object.freeze({ ...current, state: nextState, claim_token_digest: null, claim_expires_at: null, updated_at: currentTime });
}

export function normalizeStoredDeviceAuditInboxEntry(entry) {
  return normalizeStoredEntry(entry);
}

function normalizeStoredEntry(value) {
  if (!isObject(value) || !UUID.test(String(value.organization_id ?? "")) || !UUID.test(String(value.device_id ?? ""))
    || !BATCH_ID.test(String(value.batch_id ?? "")) || !DIGEST.test(String(value.payload_sha256 ?? ""))
    || !STATES.has(value.state) || !Number.isSafeInteger(value.attempt) || value.attempt < 0 || value.attempt > MAX_ATTEMPTS
    || (value.claim_token_digest !== null && !DIGEST.test(String(value.claim_token_digest)))
    || (value.claim_expires_at !== null && !timestamp(value.claim_expires_at)) || !timestamp(value.created_at) || !timestamp(value.updated_at)
    || !Array.isArray(value.events) || value.events.length < 1 || value.events.length > 64) throw invalid("stored_entry");
  const payload = canonicalJson({ events: value.events });
  if (sha256(payload) !== value.payload_sha256) throw invalid("payload_digest");
  return Object.freeze({
    organization_id: value.organization_id,
    device_id: value.device_id,
    batch_id: value.batch_id,
    payload_sha256: value.payload_sha256,
    events: Object.freeze(value.events),
    state: value.state,
    attempt: value.attempt,
    claim_token_digest: value.claim_token_digest,
    claim_expires_at: value.claim_expires_at,
    created_at: value.created_at,
    updated_at: value.updated_at,
  });
}

function timestamp(value) {
  if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(value) || !Number.isFinite(Date.parse(value))) throw invalid("timestamp");
  return value;
}
function sha256(value) { return crypto.createHash("sha256").update(value, "utf8").digest("hex"); }
function isObject(value) { return value !== null && typeof value === "object" && !Array.isArray(value); }
function invalid(field) { return new DeviceAuditInboxContractError(`ERR_DEVICE_AUDIT_INBOX_${field}`.toUpperCase(), `device audit inbox ${field} is invalid`); }
