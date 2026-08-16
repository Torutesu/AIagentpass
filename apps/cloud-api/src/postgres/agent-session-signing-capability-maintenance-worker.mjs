const DEFAULTS = Object.freeze({
  firstCycleDelayMs: 0,
  intervalMs: 60 * 60_000,
  limit: 256,
  closeTimeoutMs: 10_000
});

const LIMITS = Object.freeze({
  firstCycleDelayMs: Object.freeze({ min: 0, max: 60_000 }),
  intervalMs: Object.freeze({ min: 10, max: 24 * 60 * 60_000 }),
  limit: Object.freeze({ min: 1, max: 256 }),
  closeTimeoutMs: Object.freeze({ min: 0, max: 60_000 })
});

const RESULT_FIELDS = Object.freeze(["expired", "uncertain"]);

export const AGENT_SESSION_SIGNING_CAPABILITY_MAINTENANCE_METHOD = "recoverExpiredReservations";

/**
 * Metric method names are a closed, deployment-wide contract. The worker
 * supplies only aggregate numeric values; it never supplies tenant IDs,
 * reservation IDs, database errors, or repository result objects.
 */
export const AGENT_SESSION_SIGNING_CAPABILITY_MAINTENANCE_METRIC_HOOKS = Object.freeze({
  cycle: "recordAgentSessionSigningCapabilityMaintenanceCycle",
  success: "recordAgentSessionSigningCapabilityMaintenanceSuccess",
  failure: "recordAgentSessionSigningCapabilityMaintenanceFailure",
  expired: "recordAgentSessionSigningCapabilityMaintenanceExpired",
  uncertain: "recordAgentSessionSigningCapabilityMaintenanceUncertain"
});

export const AGENT_SESSION_SIGNING_CAPABILITY_MAINTENANCE_WORKER_STATES = Object.freeze([
  "idle",
  "running",
  "closing",
  "closed"
]);

/**
 * Run deployment-wide signing-capability expiry recovery on one bounded
 * schedule. The repository owns row selection and transaction boundaries;
 * this worker only supplies a global batch limit and consumes aggregate
 * counts.
 */
export function createAgentSessionSigningCapabilityMaintenanceWorker({
  repository,
  metrics,
  firstCycleDelayMs = DEFAULTS.firstCycleDelayMs,
  intervalMs = DEFAULTS.intervalMs,
  limit = DEFAULTS.limit,
  closeTimeoutMs = DEFAULTS.closeTimeoutMs,
  setTimeoutFn = setTimeout,
  clearTimeoutFn = clearTimeout
} = {}) {
  if (!repository || typeof repository[AGENT_SESSION_SIGNING_CAPABILITY_MAINTENANCE_METHOD] !== "function") throw invalidConfiguration();
  if (typeof setTimeoutFn !== "function" || typeof clearTimeoutFn !== "function") throw invalidConfiguration();
  const config = Object.freeze({
    firstCycleDelayMs: boundedInteger(firstCycleDelayMs, LIMITS.firstCycleDelayMs),
    intervalMs: boundedInteger(intervalMs, LIMITS.intervalMs),
    limit: boundedInteger(limit, LIMITS.limit),
    closeTimeoutMs: boundedInteger(closeTimeoutMs, LIMITS.closeTimeoutMs)
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
      scheduled: timer !== undefined,
      cycles,
      consecutive_failures: consecutiveFailures,
      last_cycle_at: lastCycleAt,
      last_success_at: lastSuccessAt,
      config
    });
  }

  /**
   * Concurrent callers share one promise. A timer tick therefore cannot
   * overlap a manually requested recovery cycle.
   */
  function runOnce() {
    if (state === "closed" || state === "closing") return activeCycle ?? Promise.resolve(finishedResult(false));
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
    emit(metrics, AGENT_SESSION_SIGNING_CAPABILITY_MAINTENANCE_METRIC_HOOKS.cycle, 1);
    try {
      const result = normalizeRecoveryResult(
        await repository.recoverExpiredReservations({ limit: config.limit }),
        config.limit
      );
      emit(metrics, AGENT_SESSION_SIGNING_CAPABILITY_MAINTENANCE_METRIC_HOOKS.success, 1);
      emitCount(metrics, AGENT_SESSION_SIGNING_CAPABILITY_MAINTENANCE_METRIC_HOOKS.expired, result.expired);
      emitCount(metrics, AGENT_SESSION_SIGNING_CAPABILITY_MAINTENANCE_METRIC_HOOKS.uncertain, result.uncertain);
      cycles = incrementBounded(cycles);
      consecutiveFailures = 0;
      lastCycleAt = Date.now();
      lastSuccessAt = lastCycleAt;
      return Object.freeze({ ok: true, ...result });
    } catch {
      // Recovery is auxiliary work. Database failures and malformed adapter
      // output are reduced to one aggregate failure counter and never escape
      // into the hosted request process or metric payload.
      emit(metrics, AGENT_SESSION_SIGNING_CAPABILITY_MAINTENANCE_METRIC_HOOKS.failure, 1);
      cycles = incrementBounded(cycles);
      consecutiveFailures = incrementBounded(consecutiveFailures);
      lastCycleAt = Date.now();
      return finishedResult(true);
    }
  }

  function start() {
    if (state === "idle") {
      state = "running";
      schedule(config.firstCycleDelayMs);
    }
    return snapshot();
  }

  function schedule(delayMs) {
    if (state !== "running" || timer !== undefined) return;
    timer = setTimeoutFn(() => {
      timer = undefined;
      runOnce().then(() => {
        if (state === "running") schedule(config.intervalMs);
      }, () => {
        // executeCycle is fail-closed, but retain this boundary if that
        // implementation detail changes in a future version.
        if (state === "running") schedule(config.intervalMs);
      });
    }, delayMs);
    timer?.unref?.();
  }

  /**
   * Stop future cycles and wait for the active repository call for a bounded
   * period. Repeated calls return the same promise and have no extra effect.
   */
  function close({ timeoutMs = config.closeTimeoutMs } = {}) {
    const boundedTimeoutMs = boundedInteger(timeoutMs, LIMITS.closeTimeoutMs);
    if (closePromise !== undefined) return closePromise;
    if (state === "closed") return closeResult ?? Promise.resolve(snapshot());
    state = "closing";
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
      else pending.then(() => { if (state === "closing") state = "closed"; }, () => { if (state === "closing") state = "closed"; });
      closeResult = Object.freeze({ ...snapshot(), drained });
      return closeResult;
    });
    return closePromise;
  }

  return Object.freeze({ start, runOnce, close, snapshot });
}

function normalizeRecoveryResult(result, limit) {
  if (!result || typeof result !== "object" || Array.isArray(result)) throw invalidResult();
  const keys = Object.keys(result);
  if (keys.length !== RESULT_FIELDS.length || RESULT_FIELDS.some((field) => !Object.hasOwn(result, field))) throw invalidResult();
  const expired = count(result.expired, limit);
  const uncertain = count(result.uncertain, limit - expired);
  if (expired + uncertain > limit) throw invalidResult();
  return Object.freeze({ expired, uncertain });
}

function count(value, max) {
  if (!Number.isSafeInteger(value) || value < 0 || value > max) throw invalidResult();
  return value;
}

function finishedResult(failed) {
  return Object.freeze({ ok: false, failed, expired: 0, uncertain: 0 });
}

function emitCount(metrics, method, amount) {
  if (amount > 0) emit(metrics, method, amount);
}

function emit(metrics, method, amount) {
  try { metrics?.[method]?.(amount); } catch { /* Metric sinks cannot affect recovery. */ }
}

function boundedInteger(value, bounds) {
  if (!Number.isSafeInteger(value) || value < bounds.min || value > bounds.max) throw invalidConfiguration();
  return value;
}

function invalidConfiguration() {
  return new TypeError("Agent Session signing capability maintenance worker configuration is invalid");
}

function invalidResult() {
  return new TypeError("Agent Session signing capability maintenance result is invalid");
}

function incrementBounded(value) {
  return value >= Number.MAX_SAFE_INTEGER ? Number.MAX_SAFE_INTEGER : value + 1;
}

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

export default createAgentSessionSigningCapabilityMaintenanceWorker;
