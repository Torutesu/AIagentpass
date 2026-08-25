const DEFAULTS = Object.freeze({
  firstCycleDelayMs: 0,
  intervalMs: 60 * 60_000,
  maintenanceLimit: 1_000,
  closeTimeoutMs: 10_000
});

const LIMITS = Object.freeze({
  firstCycleDelayMs: Object.freeze({ min: 0, max: 60_000 }),
  intervalMs: Object.freeze({ min: 10, max: 24 * 60 * 60_000 }),
  maintenanceLimit: Object.freeze({ min: 1, max: 1_000 }),
  closeTimeoutMs: Object.freeze({ min: 0, max: 60_000 })
});

const RESULT_FIELDS = Object.freeze([
  "quarantined",
  "reconciled",
  "pruned",
  "total"
]);

// Deployment-wide by contract: callers do not provide a tenant, purpose, key,
// or operation selector to the maintenance worker.
export const MANAGED_SIGNER_PROVIDER_OPERATION_MAINTENANCE_METHOD = "maintainProviderOperations";

/**
 * These hooks are intentionally fixed and aggregate-only.  The worker never
 * forwards a provider operation id, receipt, request bytes, or provider
 * diagnostic to a metric sink.
 */
export const MANAGED_SIGNER_PROVIDER_OPERATION_MAINTENANCE_METRIC_HOOKS = Object.freeze({
  cycle: "recordManagedSignerProviderOperationMaintenanceCycle",
  success: "recordManagedSignerProviderOperationMaintenanceSuccess",
  failure: "recordManagedSignerProviderOperationMaintenanceFailure",
  quarantined: "recordManagedSignerProviderOperationMaintenanceQuarantined",
  reconciled: "recordManagedSignerProviderOperationMaintenanceReconciled",
  pruned: "recordManagedSignerProviderOperationMaintenancePruned"
});

export const MANAGED_SIGNER_PROVIDER_OPERATION_MAINTENANCE_WORKER_STATES = Object.freeze([
  "idle",
  "running",
  "closing",
  "closed"
]);

/**
 * Run deployment-wide provider-operation maintenance on a single bounded
 * schedule.  The repository owns all operation selection and persistence;
 * this worker only supplies a global row budget and consumes aggregate counts.
 */
export function createManagedSignerProviderOperationMaintenanceWorker({
  repository,
  metrics,
  firstCycleDelayMs = DEFAULTS.firstCycleDelayMs,
  intervalMs = DEFAULTS.intervalMs,
  maintenanceLimit = DEFAULTS.maintenanceLimit,
  closeTimeoutMs = DEFAULTS.closeTimeoutMs,
  setTimeoutFn = setTimeout,
  clearTimeoutFn = clearTimeout,
  now = () => Date.now()
} = {}) {
  if (!repository || typeof repository[MANAGED_SIGNER_PROVIDER_OPERATION_MAINTENANCE_METHOD] !== "function") throw invalidConfiguration();
  if (typeof setTimeoutFn !== "function" || typeof clearTimeoutFn !== "function" || typeof now !== "function") throw invalidConfiguration();
  const config = Object.freeze({
    firstCycleDelayMs: boundedInteger(firstCycleDelayMs, LIMITS.firstCycleDelayMs),
    intervalMs: boundedInteger(intervalMs, LIMITS.intervalMs),
    maintenanceLimit: boundedInteger(maintenanceLimit, LIMITS.maintenanceLimit),
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
   * Concurrent callers share the current cycle.  This is also what prevents
   * a timer tick from overlapping a manually-triggered maintenance run.
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
    emit(metrics, MANAGED_SIGNER_PROVIDER_OPERATION_MAINTENANCE_METRIC_HOOKS.cycle, 1);
    try {
      const result = normalizeMaintenanceResult(
        await repository[MANAGED_SIGNER_PROVIDER_OPERATION_MAINTENANCE_METHOD]({ limit: config.maintenanceLimit }),
        config.maintenanceLimit
      );
      emit(metrics, MANAGED_SIGNER_PROVIDER_OPERATION_MAINTENANCE_METRIC_HOOKS.success, 1);
      emitCount(metrics, MANAGED_SIGNER_PROVIDER_OPERATION_MAINTENANCE_METRIC_HOOKS.quarantined, result.quarantined);
      emitCount(metrics, MANAGED_SIGNER_PROVIDER_OPERATION_MAINTENANCE_METRIC_HOOKS.reconciled, result.reconciled);
      emitCount(metrics, MANAGED_SIGNER_PROVIDER_OPERATION_MAINTENANCE_METRIC_HOOKS.pruned, result.pruned);
      cycles = incrementBounded(cycles);
      consecutiveFailures = 0;
      lastCycleAt = safeNow(now);
      lastSuccessAt = lastCycleAt;
      return Object.freeze({ ok: true, ...result });
    } catch {
      // Maintenance is auxiliary work.  Database errors and malformed adapter
      // results are observable through the fixed failure counter only.
      emit(metrics, MANAGED_SIGNER_PROVIDER_OPERATION_MAINTENANCE_METRIC_HOOKS.failure, 1);
      cycles = incrementBounded(cycles);
      consecutiveFailures = incrementBounded(consecutiveFailures);
      lastCycleAt = safeNow(now);
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
   * period.  A timeout reports an undrained close while allowing the call to
   * settle later; it never starts another maintenance cycle.
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

function normalizeMaintenanceResult(result, limit) {
  if (!result || typeof result !== "object" || Array.isArray(result)) throw invalidResult();
  const keys = Object.keys(result);
  if (keys.length !== RESULT_FIELDS.length || RESULT_FIELDS.some((field) => !Object.hasOwn(result, field))) throw invalidResult();
  const quarantined = count(result.quarantined, limit);
  const reconciled = count(result.reconciled, limit);
  const pruned = count(result.pruned, limit);
  const total = count(result.total, limit);
  if (total !== quarantined + reconciled + pruned) throw invalidResult();
  return Object.freeze({ quarantined, reconciled, pruned, total });
}

function count(value, limit) {
  if (!Number.isSafeInteger(value) || value < 0 || value > limit) throw invalidResult();
  return value;
}

function finishedResult(failed) {
  return Object.freeze({
    ok: false,
    failed,
    quarantined: 0,
    reconciled: 0,
    pruned: 0,
    total: 0
  });
}

function emitCount(metrics, method, amount) {
  if (amount > 0) emit(metrics, method, amount);
}

function emit(metrics, method, amount) {
  try { metrics?.[method]?.(amount); } catch { /* Metric sinks cannot affect maintenance. */ }
}

function boundedInteger(value, bounds) {
  if (!Number.isSafeInteger(value) || value < bounds.min || value > bounds.max) throw invalidConfiguration();
  return value;
}

function invalidConfiguration() {
  return new TypeError("managed signer provider operation maintenance worker configuration is invalid");
}

function invalidResult() {
  return new TypeError("managed signer provider operation maintenance result is invalid");
}

function incrementBounded(value) {
  return value >= Number.MAX_SAFE_INTEGER ? Number.MAX_SAFE_INTEGER : value + 1;
}

function safeNow(now) {
  try {
    const value = Number(now());
    return Number.isSafeInteger(value) && value >= 0 ? value : null;
  } catch {
    return null;
  }
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

export default createManagedSignerProviderOperationMaintenanceWorker;
