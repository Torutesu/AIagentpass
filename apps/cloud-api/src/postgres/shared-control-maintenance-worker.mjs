const DEFAULTS = Object.freeze({
  firstCycleDelayMs: 0,
  intervalMs: 60 * 60_000,
  pruneLimit: 1_000,
  closeTimeoutMs: 10_000
});

const LIMITS = Object.freeze({
  firstCycleDelayMs: Object.freeze({ min: 0, max: 60_000 }),
  intervalMs: Object.freeze({ min: 10, max: 24 * 60 * 60_000 }),
  pruneLimit: Object.freeze({ min: 1, max: 10_000 }),
  closeTimeoutMs: Object.freeze({ min: 0, max: 60_000 })
});

/**
 * These are deliberately fixed method names.  A metric adapter may implement
 * any or all of them, but the worker never forwards operation names, tenant
 * identifiers, SQL errors, or other caller-controlled labels.
 */
export const SHARED_CONTROL_MAINTENANCE_METRIC_HOOKS = Object.freeze({
  cycle: "recordSharedControlMaintenanceCycle",
  success: "recordSharedControlMaintenanceSuccess",
  failure: "recordSharedControlMaintenanceFailure",
  removed: "recordSharedControlMaintenanceRemoved"
});

export const SHARED_CONTROL_MAINTENANCE_WORKER_STATES = Object.freeze([
  "idle",
  "running",
  "closing",
  "closed"
]);

export function createSharedControlMaintenanceWorker({
  repository,
  metrics,
  firstCycleDelayMs = DEFAULTS.firstCycleDelayMs,
  intervalMs = DEFAULTS.intervalMs,
  pruneLimit = DEFAULTS.pruneLimit,
  closeTimeoutMs = DEFAULTS.closeTimeoutMs,
  setTimeoutFn = setTimeout,
  clearTimeoutFn = clearTimeout
} = {}) {
  if (!repository || typeof repository.pruneSharedControlMaintenance !== "function") throw invalidConfiguration();
  if (typeof setTimeoutFn !== "function" || typeof clearTimeoutFn !== "function") throw invalidConfiguration();
  const config = Object.freeze({
    firstCycleDelayMs: boundedInteger(firstCycleDelayMs, LIMITS.firstCycleDelayMs),
    intervalMs: boundedInteger(intervalMs, LIMITS.intervalMs),
    pruneLimit: boundedInteger(pruneLimit, LIMITS.pruneLimit),
    closeTimeoutMs: boundedInteger(closeTimeoutMs, LIMITS.closeTimeoutMs)
  });

  let state = "idle";
  let timer;
  let activeCycle;
  let closePromise;
  let closeResult;

  function snapshot() {
    return Object.freeze({
      state,
      active: activeCycle === undefined ? 0 : 1,
      scheduled: timer !== undefined,
      config
    });
  }

  /**
   * Execute at most one database prune at a time.  Returning the active
   * promise to concurrent callers makes the no-overlap property explicit and
   * avoids making a second database request merely because a timer fired.
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
    emit(metrics, SHARED_CONTROL_MAINTENANCE_METRIC_HOOKS.cycle, 1);
    try {
      const result = normalizePruneResult(await repository.pruneSharedControlMaintenance({ limit: config.pruneLimit }), config.pruneLimit);
      emit(metrics, SHARED_CONTROL_MAINTENANCE_METRIC_HOOKS.success, 1);
      if (result.removed > 0) emit(metrics, SHARED_CONTROL_MAINTENANCE_METRIC_HOOKS.removed, result.removed);
      return Object.freeze({ ok: true, ...result });
    } catch {
      // Maintenance is auxiliary work.  A database outage or malformed
      // adapter result is observable through the aggregate hook, but never
      // becomes an unhandled rejection in the hosted API process.
      emit(metrics, SHARED_CONTROL_MAINTENANCE_METRIC_HOOKS.failure, 1);
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
        // executeCycle is fail-closed and resolves, but retain the guard if a
        // future implementation changes that internal promise boundary.
        if (state === "running") schedule(config.intervalMs);
      });
    }, delayMs);
    timer?.unref?.();
  }

  /**
   * Stop scheduling and wait for the current bounded prune.  Repeated calls
   * return the same promise/result and therefore have no additional effects.
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

function normalizePruneResult(result, limit) {
  if (!result || typeof result !== "object" || Array.isArray(result)) throw invalidConfiguration();
  const sharedRemoved = count(result.sharedRemoved, limit);
  const anonymousRemoved = count(result.anonymousRemoved, limit - sharedRemoved);
  const replayRemoved = count(result.replayRemoved, limit - sharedRemoved - anonymousRemoved);
  const removed = count(result.removed, limit);
  if (removed !== sharedRemoved + anonymousRemoved + replayRemoved) throw invalidConfiguration();
  return Object.freeze({ removed, sharedRemoved, anonymousRemoved, replayRemoved });
}

function count(value, max) {
  if (!Number.isSafeInteger(value) || value < 0 || value > max) throw invalidConfiguration();
  return value;
}

function finishedResult(failed) {
  return Object.freeze({
    ok: false,
    failed,
    removed: 0,
    sharedRemoved: 0,
    anonymousRemoved: 0,
    replayRemoved: 0
  });
}

function emit(metrics, method, amount) {
  try { metrics?.[method]?.(amount); } catch { /* Metric sinks cannot affect maintenance. */ }
}

function boundedInteger(value, bounds) {
  if (!Number.isSafeInteger(value) || value < bounds.min || value > bounds.max) throw invalidConfiguration();
  return value;
}

function invalidConfiguration() {
  return new TypeError("shared-control maintenance worker configuration is invalid");
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

export default createSharedControlMaintenanceWorker;
