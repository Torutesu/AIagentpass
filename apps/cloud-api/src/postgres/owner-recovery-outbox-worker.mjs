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
  let drainPromise;
  const cycles = new Set();
  const active = new Set();

  async function runOnce() {
    if (state === "draining" || state === "closed") throw new OwnerRecoveryOutboxWorkerError(OWNER_RECOVERY_OUTBOX_WORKER_ERROR_CODES.CLOSED);
    const cycle = executeCycle();
    cycles.add(cycle);
    cycle.then(() => cycles.delete(cycle), () => cycles.delete(cycle));
    return cycle;
  }

  async function executeCycle() {
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
    const result = { claimed: batch.events.length, published: 0, retried: 0, dead_lettered: 0, claim_lost: 0, uncertain: 0 };
    if (batch.events.length > 0) metric(metrics, "recordOwnerRecoveryOutboxClaim", batch.events.length);
    const deliveries = batch.events.map(async (event) => {
      observeLag(metrics, event.created_at, now);
      const delivery = deliver(event, batch.claim_token);
      active.add(delivery);
      try {
        return await delivery;
      } finally {
        active.delete(delivery);
      }
    });
    for (const outcome of await Promise.all(deliveries)) result[outcome] += 1;
    return Object.freeze(result);
  }

  async function deliver(event, claimToken) {
    let response;
    try {
      response = await withTimeout(
        (signal) => publisher.publish(Object.freeze({
          idempotency_key: event.event_id,
          event: publicEvent(event),
          signal
        })),
        config.publishTimeoutMs,
        setTimeoutFn,
        clearTimeoutFn
      );
    } catch {
      // Timeout and transport exceptions are an unknown delivery outcome: the
      // provider may have accepted the idempotency key before the response was
      // lost. Keep the lease instead of making the row immediately retryable.
      metric(metrics, "recordOwnerRecoveryOutboxUncertain");
      return "uncertain";
    }
    if (!response || typeof response.duplicate !== "boolean" || response.accepted !== true) {
      if (response?.accepted !== false || response?.duplicate !== false) {
        metric(metrics, "recordOwnerRecoveryOutboxUncertain");
        return "uncertain";
      }
      const retryAt = new Date(clock(now) + retryDelay(event.attempt, config, random)).toISOString();
      try {
        const failed = await repository.markFailed({ organization_id: event.organization_id, event_id: event.event_id, attempt: event.attempt, claim_token: claimToken, error_code: "publisher_rejected", retry_at: retryAt });
        if (failed.dead_letter) { metric(metrics, "recordOwnerRecoveryOutboxDeadLetter"); return "dead_lettered"; }
        metric(metrics, "recordOwnerRecoveryOutboxRetry");
        return "retried";
      } catch (markError) {
        if (isClaimLost(markError)) { metric(metrics, "recordOwnerRecoveryOutboxClaimLost"); return "claim_lost"; }
        metric(metrics, "recordOwnerRecoveryOutboxUncertain");
        return "uncertain";
      }
    }
    try {
      await repository.markPublished({ organization_id: event.organization_id, event_id: event.event_id, attempt: event.attempt, claim_token: claimToken });
    } catch (error) {
      if (isClaimLost(error)) { metric(metrics, "recordOwnerRecoveryOutboxClaimLost"); return "claim_lost"; }
      metric(metrics, "recordOwnerRecoveryOutboxUncertain");
      return "uncertain";
    }
    metric(metrics, "recordOwnerRecoveryOutboxPublish");
    return "published";
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
      runOnce()
        .catch(() => Object.freeze({ claimed: 0 }))
        .then((result) => schedule(result.claimed >= config.batchSize ? 0 : config.pollIntervalMs));
    }, delay);
    timer?.unref?.();
  }

  async function drain({ timeout_ms = config.drainTimeoutMs } = {}) {
    const timeoutMs = integer(timeout_ms, 0, 60_000);
    if (state === "closed") return snapshot();
    if (drainPromise) return drainPromise;
    state = "draining";
    if (timer !== undefined) { clearTimeoutFn(timer); timer = undefined; }
    const pending = [...cycles];
    const current = (async () => {
      const drained = pending.length === 0 ? true : await waitBounded(Promise.allSettled(pending), timeoutMs, setTimeoutFn, clearTimeoutFn);
      state = drained ? "closed" : "draining";
      return Object.freeze({ ...snapshot(), drained });
    })();
    drainPromise = current;
    try { return await current; }
    finally { if (drainPromise === current) drainPromise = undefined; }
  }

  function snapshot() { return Object.freeze({ state, active: active.size, cycles: cycles.size, scheduled: timer !== undefined, config }); }

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
