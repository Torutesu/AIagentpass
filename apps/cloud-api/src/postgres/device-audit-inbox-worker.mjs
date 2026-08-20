import crypto from "node:crypto";

const OUTCOMES = new Set(["accepted", "retryable_failure", "uncertain"]);

export const DEVICE_AUDIT_INBOX_WORKER_STATES = Object.freeze(["idle", "running", "draining", "closed"]);

export class DeviceAuditInboxWorkerError extends Error {
  constructor(code, message) { super(message); this.name = "DeviceAuditInboxWorkerError"; this.code = code; }
}

export function createDeviceAuditInboxWorker({ repository, processor, batchSize = 10, leaseMs = 30_000 } = {}) {
  if (!repository || typeof repository.claimBatch !== "function" || typeof repository.settle !== "function" || !processor || typeof processor.process !== "function" || !Number.isSafeInteger(batchSize) || batchSize < 1 || batchSize > 100 || !Number.isSafeInteger(leaseMs) || leaseMs < 1_000 || leaseMs > 300_000) throw invalid();
  let state = "idle";
  let cycles = 0;

  async function runOnce() {
    if (state === "closed" || state === "draining") throw new DeviceAuditInboxWorkerError("ERR_DEVICE_AUDIT_INBOX_WORKER_CLOSED", "Device audit inbox worker is closed");
    state = "running";
    try {
      const batch = await repository.claimBatch({ limit: batchSize, lease_ms: leaseMs });
      if (!batch || typeof batch.claim_token !== "string" || !Array.isArray(batch.events)) throw unavailable();
      const settled = await Promise.all(batch.events.map((entry) => processOne(entry, batch.claim_token)));
      cycles += 1;
      state = "idle";
      return Object.freeze({ claimed: batch.events.length, accepted: settled.filter((value) => value === "accepted").length, retryable_failure: settled.filter((value) => value === "retryable_failure").length, uncertain: settled.filter((value) => value === "uncertain").length });
    } catch (error) {
      state = "idle";
      if (error instanceof DeviceAuditInboxWorkerError) throw error;
      throw unavailable();
    }
  }

  async function processOne(entry, claimToken) {
    let outcome = "uncertain";
    let errorCode = "processor_failure";
    try {
      const result = await processor.process(Object.freeze({ organization_id: entry.organization_id, device_id: entry.device_id, batch_id: entry.batch_id, events: entry.events }));
      if (!result || !OUTCOMES.has(result.outcome)) throw new Error("invalid processor outcome");
      outcome = result.outcome;
      errorCode = result.error_code ?? null;
    } catch {
      // A thrown processor error may follow a committed database transaction;
      // it is therefore never treated as immediately retryable.
      outcome = "uncertain";
    }
    const settled = await repository.settle({ organization_id: entry.organization_id, inbox_id: entry.inbox_id, attempt: entry.attempt, claim_token_digest: digestToken(claimToken), outcome, error_code: errorCode });
    if (!settled || !OUTCOMES.has(outcome)) throw unavailable();
    return outcome;
  }

  async function close() { if (state === "closed") return; state = "draining"; state = "closed"; }
  function snapshot() { return Object.freeze({ state, cycles }); }
  return Object.freeze({ runOnce, close, snapshot });
}

function digestToken(token) {
  if (typeof token !== "string" || token.length < 16) throw invalid();
  // The repository returns base64url for the opaque claim token; the SQL
  // settlement function receives the SHA-256 digest, never the token itself.
  return Buffer.from(sha256(Buffer.from(token, "base64url")), "hex").toString("hex");
}
function sha256(value) { return crypto.createHash("sha256").update(value).digest("hex"); }
function invalid() { return new DeviceAuditInboxWorkerError("ERR_DEVICE_AUDIT_INBOX_WORKER_CONFIG", "Device audit inbox worker configuration is invalid"); }
function unavailable() { return new DeviceAuditInboxWorkerError("ERR_DEVICE_AUDIT_INBOX_WORKER_UNAVAILABLE", "Device audit inbox worker is unavailable"); }
