import crypto from "node:crypto";

const DEFAULTS = Object.freeze({
  batchSize: 10,
  leaseMs: 30_000,
  pollIntervalMs: 1_000,
  closeTimeoutMs: 10_000
});

const LIMITS = Object.freeze({
  batchSize: Object.freeze({ min: 1, max: 100 }),
  leaseMs: Object.freeze({ min: 1_000, max: 300_000 }),
  pollIntervalMs: Object.freeze({ min: 10, max: 60_000 }),
  closeTimeoutMs: Object.freeze({ min: 0, max: 60_000 })
});

const OUTCOMES = new Set(["accepted", "retryable_failure", "uncertain"]);

export const DEVICE_AUDIT_INBOX_WORKER_STATES = Object.freeze(["idle", "running", "draining", "closed"]);

export const DEVICE_AUDIT_INBOX_WORKER_ERROR_CODES = Object.freeze({
  INVALID_CONFIGURATION: "ERR_DEVICE_AUDIT_INBOX_WORKER_CONFIG",
  CLOSED: "ERR_DEVICE_AUDIT_INBOX_WORKER_CLOSED",
  UNAVAILABLE: "ERR_DEVICE_AUDIT_INBOX_WORKER_UNAVAILABLE"
});

export class DeviceAuditInboxWorkerError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "DeviceAuditInboxWorkerError";
    this.code = code;
  }
}

/**
 * Runs the durable audit inbox as a single bounded poller per process.
 * PostgreSQL owns the lease and retry state; the worker never stores payloads
 * or claim tokens outside the current bounded operation.
 */
export function createDeviceAuditInboxWorker({
  repository,
  processor,
  metrics,
  batchSize = DEFAULTS.batchSize,
  leaseMs = DEFAULTS.leaseMs,
  pollIntervalMs = DEFAULTS.pollIntervalMs,
  closeTimeoutMs = DEFAULTS.closeTimeoutMs,
  setTimeoutFn = setTimeout,
  clearTimeoutFn = clearTimeout,
  now = () => Date.now()
} = {}) {
  if (!repository || typeof repository.claimBatch !== "function" || typeof repository.settle !== "function"
    || !processor || typeof processor.process !== "function"
    || typeof setTimeoutFn !== "function" || typeof clearTimeoutFn !== "function" || typeof now !== "function") throw invalid();
  const config = Object.freeze({
    batchSize: integer(batchSize, LIMITS.batchSize),
    leaseMs: integer(leaseMs, LIMITS.leaseMs),
    pollIntervalMs: integer(pollIntervalMs, LIMITS.pollIntervalMs),
    closeTimeoutMs: integer(closeTimeoutMs, LIMITS.closeTimeoutMs)
  });

  let state = "idle";
  let timer;
  let activeCycle;
  let closePromise;
  let closeResult;
  let cycles = 0;
  let consecutiveFailures = 0;
  let lastCycleAt = null;
  let lastSuccessAt = null;

  function snapshot() {
    return Object.freeze({
      state,
      active: activeCycle === undefined ? 0 : 1,
      cycles,
      scheduled: timer !== undefined,
      consecutive_failures: consecutiveFailures,
      last_cycle_at: lastCycleAt,
      last_success_at: lastSuccessAt,
      config
    });
  }

  function runOnce() {
    if (state === "closed" || state === "draining") throw closed();
    if (activeCycle !== undefined) return activeCycle;
    const cycle = executeCycle();
    activeCycle = cycle;
    cycle.then(
      () => { if (activeCycle === cycle) activeCycle = undefined; },
      () => { if (activeCycle === cycle) activeCycle = undefined; }
    );
    return cycle;
  }

  async function executeCycle() {
    metric(metrics, "recordDeviceAuditInboxCycle");
    let batch;
    try {
      batch = await repository.claimBatch({ limit: config.batchSize, lease_ms: config.leaseMs });
    } catch {
      metric(metrics, "recordDeviceAuditInboxFailure");
      cycles = incrementBounded(cycles);
      consecutiveFailures = incrementBounded(consecutiveFailures);
      lastCycleAt = safeNow(now);
      throw unavailable();
    }
    if (!batch || typeof batch.claim_token !== "string" || !Array.isArray(batch.events)) {
      metric(metrics, "recordDeviceAuditInboxFailure");
      cycles = incrementBounded(cycles);
      consecutiveFailures = incrementBounded(consecutiveFailures);
      lastCycleAt = safeNow(now);
      throw unavailable();
    }

    const result = { claimed: batch.events.length, accepted: 0, retryable_failure: 0, uncertain: 0 };
    if (batch.events.length > 0) metric(metrics, "recordDeviceAuditInboxClaim", batch.events.length);
    const deliveries = batch.events.map((entry) => processOne(entry, batch.claim_token));
    for (const settled of await Promise.allSettled(deliveries)) {
      const outcome = settled.status === "fulfilled" && OUTCOMES.has(settled.value) ? settled.value : "uncertain";
      result[outcome] += 1;
    }
    cycles = incrementBounded(cycles);
    consecutiveFailures = 0;
    lastCycleAt = safeNow(now);
    lastSuccessAt = lastCycleAt;
    metric(metrics, "recordDeviceAuditInboxSuccess");
    metric(metrics, "recordDeviceAuditInboxAccepted", result.accepted);
    metric(metrics, "recordDeviceAuditInboxRetry", result.retryable_failure);
    metric(metrics, "recordDeviceAuditInboxUncertain", result.uncertain);
    return Object.freeze(result);
  }

  async function processOne(entry, claimToken) {
    let outcome = "uncertain";
    let errorCode = "processor_failure";
    try {
      const result = await processor.process(Object.freeze({
        organization_id: entry.organization_id,
        device_id: entry.device_id,
        batch_id: entry.batch_id,
        events: entry.events
      }));
      if (!result || !OUTCOMES.has(result.outcome)) throw new Error("invalid processor outcome");
      outcome = result.outcome;
      errorCode = result.error_code ?? null;
    } catch {
      // A processor exception may follow a committed audit transaction. It is
      // therefore quarantined instead of blindly replayed in this cycle.
      outcome = "uncertain";
    }

    try {
      const settled = await repository.settle({
        organization_id: entry.organization_id,
        inbox_id: entry.inbox_id,
        attempt: entry.attempt,
        claim_token_digest: digestToken(claimToken),
        outcome,
        error_code: errorCode
      });
      if (!settled || typeof settled.state !== "string") throw unavailable();
      return outcome;
    } catch {
      // A lost claim is not an API failure and must not reject the whole batch.
      // An expired lease is recovered by the database claim function after a
      // process crash; a response-loss outcome is intentionally not retried.
      return "uncertain";
    }
  }

  function start() {
    if (state === "closed" || state === "draining") throw closed();
    if (state === "running") return snapshot();
    state = "running";
    schedule(0);
    return snapshot();
  }

  function schedule(delayMs) {
    if (state !== "running" || timer !== undefined) return;
    timer = setTimeoutFn(() => {
      timer = undefined;
      let cycle;
      try { cycle = runOnce(); }
      catch { cycle = Promise.resolve({ claimed: 0 }); }
      cycle.then(
        (result) => { if (state === "running") schedule(result?.claimed >= config.batchSize ? 0 : config.pollIntervalMs); },
        () => { if (state === "running") schedule(config.pollIntervalMs); }
      );
    }, delayMs);
    timer?.unref?.();
  }

  function close(options = {}) {
    const timeoutMs = options.timeoutMs ?? options.timeout_ms ?? config.closeTimeoutMs;
    const boundedTimeoutMs = integer(timeoutMs, LIMITS.closeTimeoutMs);
    if (closePromise !== undefined) return closePromise;
    if (state === "closed") return closeResult ?? Promise.resolve(snapshot());
    state = "draining";
    if (timer !== undefined) {
      clearTimeoutFn(timer);
      timer = undefined;
    }
    const pending = activeCycle;
    if (pending === undefined) {
      state = "closed";
      closeResult = Object.freeze({ ...snapshot(), drained: true });
      closePromise = Promise.resolve(closeResult);
      return closePromise;
    }
    closePromise = waitBounded(pending, boundedTimeoutMs, setTimeoutFn, clearTimeoutFn).then((drained) => {
      if (drained) state = "closed";
      else pending.then(() => { if (state === "draining") state = "closed"; }, () => { if (state === "draining") state = "closed"; });
      closeResult = Object.freeze({ ...snapshot(), drained });
      return closeResult;
    });
    return closePromise;
  }

  return Object.freeze({ start, runOnce, close, drain: close, snapshot });
}

function digestToken(token) {
  if (typeof token !== "string" || token.length < 16) throw invalid();
  return crypto.createHash("sha256").update(Buffer.from(token, "base64url")).digest("hex");
}

function metric(metrics, method, amount = 1) {
  if (amount <= 0) return;
  try { metrics?.[method]?.(amount); } catch { /* metrics cannot affect delivery */ }
}

function integer(value, bounds) {
  if (!Number.isSafeInteger(value) || value < bounds.min || value > bounds.max) throw invalid();
  return value;
}

function incrementBounded(value) { return value >= Number.MAX_SAFE_INTEGER ? Number.MAX_SAFE_INTEGER : value + 1; }
function safeNow(now) { try { const value = Number(now()); return Number.isSafeInteger(value) && value >= 0 ? value : null; } catch { return null; } }
function invalid() { return new DeviceAuditInboxWorkerError(DEVICE_AUDIT_INBOX_WORKER_ERROR_CODES.INVALID_CONFIGURATION, "Device audit inbox worker configuration is invalid"); }
function closed() { return new DeviceAuditInboxWorkerError(DEVICE_AUDIT_INBOX_WORKER_ERROR_CODES.CLOSED, "Device audit inbox worker is closed"); }
function unavailable() { return new DeviceAuditInboxWorkerError(DEVICE_AUDIT_INBOX_WORKER_ERROR_CODES.UNAVAILABLE, "Device audit inbox worker is unavailable"); }

async function waitBounded(promise, timeoutMs, setTimeoutFn, clearTimeoutFn) {
  if (timeoutMs === 0) return false;
  let timer;
  try {
    return await Promise.race([
      promise.then(() => true, () => true),
      new Promise((resolve) => { timer = setTimeoutFn(() => resolve(false), timeoutMs); })
    ]);
  } finally {
    if (timer !== undefined) clearTimeoutFn(timer);
  }
}

export default createDeviceAuditInboxWorker;
