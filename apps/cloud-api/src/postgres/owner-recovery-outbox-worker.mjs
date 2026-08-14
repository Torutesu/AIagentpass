const DEFAULTS = Object.freeze({
  batchSize: 10,
  leaseMs: 30_000,
  pollIntervalMs: 1_000,
  publishTimeoutMs: 10_000,
  baseRetryMs: 1_000,
  maxRetryMs: 15 * 60_000,
  drainTimeoutMs: 30_000
});
const MAX_ATTEMPTS = 100;

export const OWNER_RECOVERY_OUTBOX_WORKER_ERROR_CODES = Object.freeze({
  INVALID_CONFIGURATION: "owner_recovery_outbox_worker_invalid_configuration",
  CLOSED: "owner_recovery_outbox_worker_closed",
  STORAGE_UNAVAILABLE: "owner_recovery_outbox_worker_storage_unavailable"
});

export class OwnerRecoveryOutboxWorkerError extends Error {
  constructor(code) {
    super(code === OWNER_RECOVERY_OUTBOX_WORKER_ERROR_CODES.CLOSED
      ? "Owner recovery outbox worker is closed"
      : code === OWNER_RECOVERY_OUTBOX_WORKER_ERROR_CODES.STORAGE_UNAVAILABLE
        ? "Owner recovery outbox storage is unavailable"
        : "Owner recovery outbox worker configuration is invalid");
    this.name = "OwnerRecoveryOutboxWorkerError";
    this.code = code;
  }
}

export function createOwnerRecoveryOutboxWorker({
  repository,
  publisher,
  metrics,
  now = () => Date.now(),
  random = Math.random,
  setTimeoutFn = setTimeout,
  clearTimeoutFn = clearTimeout,
  batchSize = DEFAULTS.batchSize,
  leaseMs = DEFAULTS.leaseMs,
  pollIntervalMs = DEFAULTS.pollIntervalMs,
  publishTimeoutMs = DEFAULTS.publishTimeoutMs,
  baseRetryMs = DEFAULTS.baseRetryMs,
  maxRetryMs = DEFAULTS.maxRetryMs,
  drainTimeoutMs = DEFAULTS.drainTimeoutMs
} = {}) {
  if (!repository || typeof repository.claimBatch !== "function" || typeof repository.markPublished !== "function" || typeof repository.markFailed !== "function") throw invalid();
  if (!publisher || typeof publisher.publish !== "function" || typeof now !== "function" || typeof random !== "function" || typeof setTimeoutFn !== "function" || typeof clearTimeoutFn !== "function") throw invalid();
  const config = Object.freeze({
    batchSize: integer(batchSize, 1, 100),
    leaseMs: integer(leaseMs, 1_000, 5 * 60_000),
    pollIntervalMs: integer(pollIntervalMs, 10, 60_000),
    publishTimeoutMs: integer(publishTimeoutMs, 100, 60_000),
    baseRetryMs: integer(baseRetryMs, 100, 60_000),
    maxRetryMs: integer(maxRetryMs, 1_000, 24 * 60 * 60_000),
    drainTimeoutMs: integer(drainTimeoutMs, 0, 60_000)
  });
  if (config.baseRetryMs > config.maxRetryMs || config.publishTimeoutMs >= config.leaseMs) throw invalid();

  let state = "idle";
  let timer;
  let cyclePromise;
  const active = new Set();

  async function runOnce() {
    if (state === "draining" || state === "closed") throw new OwnerRecoveryOutboxWorkerError(OWNER_RECOVERY_OUTBOX_WORKER_ERROR_CODES.CLOSED);
    let batch;
    try {
      batch = await repository.claimBatch({ limit: config.batchSize, lease_ms: config.leaseMs });
    } catch {
      metric(metrics, "recordOwnerRecoveryOutboxFailure");
      throw new OwnerRecoveryOutboxWorkerError(OWNER_RECOVERY_OUTBOX_WORKER_ERROR_CODES.STORAGE_UNAVAILABLE);
    }
    if (!batch || typeof batch.claim_token !== "string" || !Array.isArray(batch.events)) {
      metric(metrics, "recordOwnerRecoveryOutboxFailure");
      throw new OwnerRecoveryOutboxWorkerError(OWNER_RECOVERY_OUTBOX_WORKER_ERROR_CODES.STORAGE_UNAVAILABLE);
    }
    const result = { claimed: batch.events.length, published: 0, retried: 0, dead_lettered: 0, claim_lost: 0 };
    if (batch.events.length > 0) metric(metrics, "recordOwnerRecoveryOutboxClaim", batch.events.length);
    for (const event of batch.events) {
      observeLag(metrics, event.created_at, now);
      const delivery = deliver(event, batch.claim_token);
      active.add(delivery);
      try {
        const outcome = await delivery;
        result[outcome] += 1;
      } finally {
        active.delete(delivery);
      }
    }
    return Object.freeze(result);
  }

  async function deliver(event, claimToken) {
    try {
      const response = await withTimeout(
        (signal) => publisher.publish(Object.freeze({
          idempotency_key: event.event_id,
          event: publicEvent(event),
          signal
        })),
        config.publishTimeoutMs,
        setTimeoutFn,
        clearTimeoutFn
      );
      if (!response || response.accepted !== true) throw Object.assign(new Error("publisher rejected event"), { deliveryCode: "publisher_rejected" });
      try {
        await repository.markPublished({ organization_id: event.organization_id, event_id: event.event_id, attempt: event.attempt, claim_token: claimToken });
      } catch (error) {
        if (isClaimLost(error)) { metric(metrics, "recordOwnerRecoveryOutboxClaimLost"); return "claim_lost"; }
        throw Object.assign(new Error("publish acknowledgement storage failed"), { deliveryCode: "storage_unavailable" });
      }
      metric(metrics, "recordOwnerRecoveryOutboxPublish");
      return "published";
    } catch (error) {
      const code = deliveryCode(error);
      const retryAt = new Date(clock(now) + retryDelay(event.attempt, config, random)).toISOString();
      try {
        const failed = await repository.markFailed({ organization_id: event.organization_id, event_id: event.event_id, attempt: event.attempt, claim_token: claimToken, error_code: code, retry_at: retryAt });
        if (failed.dead_letter) { metric(metrics, "recordOwnerRecoveryOutboxDeadLetter"); return "dead_lettered"; }
        metric(metrics, "recordOwnerRecoveryOutboxRetry");
        return "retried";
      } catch (markError) {
        if (isClaimLost(markError)) { metric(metrics, "recordOwnerRecoveryOutboxClaimLost"); return "claim_lost"; }
        metric(metrics, "recordOwnerRecoveryOutboxFailure");
        return "claim_lost";
      }
    }
  }

  function start() {
    if (state === "draining" || state === "closed") throw new OwnerRecoveryOutboxWorkerError(OWNER_RECOVERY_OUTBOX_WORKER_ERROR_CODES.CLOSED);
    if (state === "running") return snapshot();
    state = "running";
    schedule(0);
    return snapshot();
  }

  function schedule(delay) {
    if (state !== "running" || timer !== undefined) return;
    timer = setTimeoutFn(() => {
      timer = undefined;
      cyclePromise = runOnce()
        .catch(() => Object.freeze({ claimed: 0 }))
        .then((result) => schedule(result.claimed >= config.batchSize ? 0 : config.pollIntervalMs))
        .finally(() => { cyclePromise = undefined; });
    }, delay);
    timer?.unref?.();
  }

  async function drain({ timeout_ms = config.drainTimeoutMs } = {}) {
    const timeoutMs = integer(timeout_ms, 0, 60_000);
    if (state === "closed") return snapshot();
    state = "draining";
    if (timer !== undefined) { clearTimeoutFn(timer); timer = undefined; }
    const pending = [...active];
    if (cyclePromise) pending.push(cyclePromise);
    const drained = pending.length === 0 ? true : await waitBounded(Promise.allSettled(pending), timeoutMs, setTimeoutFn, clearTimeoutFn);
    state = drained ? "closed" : "draining";
    return Object.freeze({ ...snapshot(), drained });
  }

  function snapshot() { return Object.freeze({ state, active: active.size, scheduled: timer !== undefined, config }); }

  return Object.freeze({ start, runOnce, drain, close: drain, snapshot });
}

function publicEvent(value) {
  return Object.freeze({
    schema_version: 1,
    kind: "owner-recovery-notification",
    event_id: value.event_id,
    organization_id: value.organization_id,
    request_id: value.request_id,
    subject_member_id: value.subject_member_id,
    event_type: value.event_type,
    created_at: value.created_at
  });
}
function retryDelay(attempt, config, random) {
  const exponent = Math.min(20, Math.max(0, integer(attempt, 1, MAX_ATTEMPTS) - 1));
  const base = Math.min(config.maxRetryMs, config.baseRetryMs * (2 ** exponent));
  const sample = Number(random());
  if (!Number.isFinite(sample) || sample < 0 || sample >= 1) throw invalid();
  return Math.min(config.maxRetryMs, Math.ceil(base + base * 0.2 * sample));
}
function deliveryCode(error) {
  if (error?.deliveryCode === "publish_timeout") return "publish_timeout";
  if (error?.deliveryCode === "publisher_rejected") return "publisher_rejected";
  if (error?.deliveryCode === "storage_unavailable") return "storage_unavailable";
  return "publisher_unavailable";
}
function isClaimLost(error) { return String(error?.code ?? "").includes("claim_lost"); }
function observeLag(metrics, createdAt, now) {
  const created = Date.parse(String(createdAt));
  const current = clock(now);
  if (!Number.isFinite(created) || created > current) return;
  metric(metrics, "recordOwnerRecoveryOutboxLag", Math.min(Number.MAX_SAFE_INTEGER, current - created));
}
function metric(metrics, method, amount = 1) { try { metrics?.[method]?.(amount); } catch { /* Metrics cannot affect delivery. */ } }
function clock(now) { const value = Number(now()); if (!Number.isSafeInteger(value) || value < 0) throw invalid(); return value; }
function integer(value, min, max) { if (!Number.isSafeInteger(value) || value < min || value > max) throw invalid(); return value; }
function invalid() { return new OwnerRecoveryOutboxWorkerError(OWNER_RECOVERY_OUTBOX_WORKER_ERROR_CODES.INVALID_CONFIGURATION); }

async function withTimeout(operation, timeoutMs, setTimeoutFn, clearTimeoutFn) {
  const controller = new AbortController();
  let timer;
  try {
    return await Promise.race([
      Promise.resolve().then(() => operation(controller.signal)),
      new Promise((_, reject) => {
        timer = setTimeoutFn(() => {
          controller.abort();
          reject(Object.assign(new Error("publish timeout"), { deliveryCode: "publish_timeout" }));
        }, timeoutMs);
      })
    ]);
  } finally { if (timer !== undefined) clearTimeoutFn(timer); }
}

async function waitBounded(promise, timeoutMs, setTimeoutFn, clearTimeoutFn) {
  if (timeoutMs === 0) return false;
  let timer;
  try {
    return await Promise.race([
      promise.then(() => true),
      new Promise((resolve) => { timer = setTimeoutFn(() => resolve(false), timeoutMs); })
    ]);
  } finally { if (timer !== undefined) clearTimeoutFn(timer); }
}

export default createOwnerRecoveryOutboxWorker;
