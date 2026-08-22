import crypto from "node:crypto";

import {
  normalizeDeviceAuditInboxEntry,
  normalizeStoredDeviceAuditInboxEntry,
} from "../device-audit-inbox-contract.mjs";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
const BATCH_ID = /^audit-[0-9a-f]{64}$/u;
const DIGEST = /^[0-9a-f]{64}$/u;

export class DeviceAuditInboxRepositoryError extends Error {
  constructor(code, message = "Device audit inbox storage is unavailable") {
    super(message);
    this.name = "DeviceAuditInboxRepositoryError";
    this.code = code;
  }
}

export function createPostgresDeviceAuditInboxRepository({ client, randomBytes = crypto.randomBytes, now = () => new Date().toISOString() } = {}) {
  if (!client || typeof client.query !== "function" || typeof randomBytes !== "function" || typeof now !== "function") throw new DeviceAuditInboxRepositoryError("ERR_DEVICE_AUDIT_INBOX_CONFIG", "Device audit inbox repository configuration is invalid");

  async function enqueue(input = {}) {
    const entry = normalizeDeviceAuditInboxEntry(input, now);
    const inboxId = input.inbox_id ?? input.inboxId;
    if (!UUID.test(String(inboxId ?? ""))) throw invalid();
    try {
      const result = await client.query(`SELECT * FROM public.agentpass_device_audit_inbox_enqueue($1::uuid,$2::uuid,$3::uuid,$4::text,$5::text,$6::jsonb)`, [
        entry.organization_id, inboxId, entry.device_id, entry.batch_id, entry.payload_sha256, JSON.stringify({ events: entry.events })
      ]);
      if (!result || result.rows?.length !== 1) throw unavailable();
      return normalizeStoredDeviceAuditInboxEntry(rowToEntry(result.rows[0], entry));
    } catch (error) {
      if (error instanceof DeviceAuditInboxRepositoryError) throw error;
      throw unavailable();
    }
  }

  async function claimBatch({ limit = 10, lease_ms = 30_000 } = {}) {
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 100 || !Number.isSafeInteger(lease_ms) || lease_ms < 1_000 || lease_ms > 300_000) throw invalid();
    const claimToken = Buffer.from(randomBytes(32));
    if (claimToken.length !== 32) throw invalid();
    const claimTokenDigest = crypto.createHash("sha256").update(claimToken).digest();
    try {
      const result = await client.query(`SELECT * FROM public.agentpass_device_audit_inbox_claim($1::bytea,$2::integer,$3::integer)`, [claimTokenDigest, limit, lease_ms]);
      const events = Object.freeze((result.rows ?? []).map((row) => rowToClaim(row, claimTokenDigest, now)));
      return Object.freeze({ claim_token: claimToken.toString("base64url"), events });
    } catch (error) {
      if (error instanceof DeviceAuditInboxRepositoryError) throw error;
      throw unavailable();
    }
  }

  async function settle(input = {}) {
    const state = normalizeSettleInput(input);
    const digest = Buffer.from(state.claim_token_digest, "hex");
    try {
      const result = await client.query(`SELECT * FROM public.agentpass_device_audit_inbox_settle($1::uuid,$2::uuid,$3::integer,$4::bytea,$5::text,$6::text)`, [
        state.organization_id, state.inbox_id, state.attempt, digest, state.outcome, state.error_code
      ]);
      if (result.rows?.length !== 1) throw new DeviceAuditInboxRepositoryError("ERR_DEVICE_AUDIT_INBOX_CLAIM_LOST", "Device audit inbox claim is no longer valid");
      return Object.freeze({ state: result.rows[0].state, attempt: Number(result.rows[0].attempt), accepted_at: result.rows[0].accepted_at ?? null, uncertain_at: result.rows[0].uncertain_at ?? null });
    } catch (error) {
      if (error instanceof DeviceAuditInboxRepositoryError) throw error;
      throw unavailable();
    }
  }

  async function health() {
    try {
      const result = await client.query(`SELECT state,row_count AS count,oldest_at,expired_processing FROM public.agentpass_device_audit_inbox_health()`, []);
      const counts = { pending: 0, processing: 0, accepted: 0, uncertain: 0, dead_letter: 0 };
      let oldestPendingAt = null;
      let oldestUncertainAt = null;
      let oldestProcessingAt = null;
      let expiredProcessing = 0;
      for (const row of result.rows ?? []) {
        if (!Object.hasOwn(counts, row.state)) throw unavailable();
        counts[row.state] = Number(row.count);
        if (row.state === "pending" && row.oldest_at !== null) oldestPendingAt = new Date(row.oldest_at).toISOString();
        if (row.state === "uncertain" && row.oldest_at !== null) oldestUncertainAt = new Date(row.oldest_at).toISOString();
        if (row.state === "processing" && row.oldest_at !== null) oldestProcessingAt = new Date(row.oldest_at).toISOString();
        if (row.state === "processing") expiredProcessing = Number(row.expired_processing);
      }
      if (Object.values(counts).some((count) => !Number.isSafeInteger(count) || count < 0)
        || !Number.isSafeInteger(expiredProcessing) || expiredProcessing < 0) throw unavailable();
      return Object.freeze({ ...counts, oldest_pending_at: oldestPendingAt, oldest_processing_at: oldestProcessingAt, oldest_uncertain_at: oldestUncertainAt, expired_processing: expiredProcessing });
    } catch (error) {
      if (error instanceof DeviceAuditInboxRepositoryError) throw error;
      throw unavailable();
    }
  }

  return Object.freeze({ enqueue, claimBatch, settle, health });
}

function rowToEntry(row, fallback) {
  const payload = parsePayload(row.payload);
  return { ...fallback, organization_id: String(row.organization_id), inbox_id: String(row.inbox_id), device_id: String(row.device_id), batch_id: String(row.batch_id), payload_sha256: String(row.payload_sha256), events: payload.events, state: String(row.state), attempt: Number(row.attempt), claim_token_digest: row.claim_token_digest === null ? null : Buffer.from(row.claim_token_digest).toString("hex"), claim_expires_at: row.claim_expires_at === null ? null : new Date(row.claim_expires_at).toISOString(), created_at: new Date(row.created_at ?? fallback.created_at).toISOString(), updated_at: new Date(row.updated_at ?? fallback.updated_at).toISOString() };
}

function rowToClaim(row, claimToken, now) {
  const payload = parsePayload(row.payload);
  const claimed = {
    organization_id: String(row.organization_id), inbox_id: String(row.inbox_id), device_id: String(row.device_id), batch_id: String(row.batch_id), payload_sha256: String(row.payload_sha256), events: payload.events,
    state: "processing", attempt: Number(row.attempt), claim_token_digest: claimToken.toString("hex"), claim_expires_at: new Date(row.claim_expires_at).toISOString(), created_at: new Date().toISOString(), updated_at: new Date().toISOString()
  };
  return normalizeStoredDeviceAuditInboxEntry(claimed);
}

function normalizeSettleInput(value) {
  if (!value || typeof value !== "object" || Array.isArray(value) || !UUID.test(String(value.organization_id ?? "")) || !UUID.test(String(value.inbox_id ?? "")) || !Number.isSafeInteger(value.attempt) || value.attempt < 1 || value.attempt > 100 || typeof value.claim_token_digest !== "string" || !DIGEST.test(value.claim_token_digest) || !["accepted", "retryable_failure", "uncertain"].includes(value.outcome) || (value.error_code !== null && value.error_code !== undefined && !/^[a-z][a-z0-9_]{0,127}$/u.test(value.error_code))) throw invalid();
  return Object.freeze({ organization_id: value.organization_id, inbox_id: value.inbox_id, attempt: value.attempt, claim_token_digest: value.claim_token_digest, outcome: value.outcome, error_code: value.error_code ?? null });
}
function parsePayload(payload) { if (!payload || typeof payload !== "object" || Array.isArray(payload) || !Array.isArray(payload.events)) throw unavailable(); return payload; }
function invalid() { return new DeviceAuditInboxRepositoryError("ERR_DEVICE_AUDIT_INBOX_INPUT", "Device audit inbox input is invalid"); }
function unavailable() { return new DeviceAuditInboxRepositoryError("ERR_DEVICE_AUDIT_INBOX_UNAVAILABLE"); }
