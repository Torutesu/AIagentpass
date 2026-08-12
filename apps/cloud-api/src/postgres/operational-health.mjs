export const OPERATIONAL_HEALTH_VERSION = 1;
export const EXPECTED_POSTGRES_SCHEMA_VERSION = 11;

export const OPERATIONAL_METRIC_KEYS = Object.freeze([
  "lock_timeout_total",
  "lock_wait_total",
  "replay_denial_total",
  "rate_limit_denial_total",
  "stale_ack_total",
  "audit_gap_total"
]);

const METRIC_KEY_SET = new Set(OPERATIONAL_METRIC_KEYS);
const MAX_COUNTER = Number.MAX_SAFE_INTEGER;
const DEFAULT_DRAIN_TIMEOUT_MS = 10_000;
const MAX_DRAIN_TIMEOUT_MS = 60_000;

export class OperationalHealthError extends Error {
  constructor(code) {
    super(publicMessage(code));
    this.name = "OperationalHealthError";
    this.code = code;
  }
}

export class DrainRejectedError extends OperationalHealthError {
  constructor() {
    super("draining");
    this.name = "DrainRejectedError";
  }
}

/**
 * Process-local, intentionally label-free counters.  The API only accepts
 * fixed metric names and positive integer amounts; no caller-supplied value
 * is retained or returned.  Integrations can export the snapshot to their
 * metrics backend without ever attaching tenant, request, SQL, or secret
 * labels.
 */
export function createOperationalMetrics({ initial = {} } = {}) {
  const counters = Object.fromEntries(OPERATIONAL_METRIC_KEYS.map((key) => [key, 0]));
  if (initial !== null && (typeof initial !== "object" || Array.isArray(initial))) throw invalidOperationalInput();
  for (const key of OPERATIONAL_METRIC_KEYS) {
    if (initial?.[key] !== undefined) counters[key] = boundedCounter(initial[key]);
  }

  function increment(key, amount = 1) {
    if (!METRIC_KEY_SET.has(key)) throw invalidOperationalInput();
    const value = boundedCounter(amount);
    if (value < 1) throw invalidOperationalInput();
    counters[key] = Math.min(MAX_COUNTER, counters[key] + value);
    return counters[key];
  }

  function snapshot() {
    const output = {};
    for (const key of OPERATIONAL_METRIC_KEYS) output[key] = counters[key];
    return Object.freeze({
      version: OPERATIONAL_HEALTH_VERSION,
      counters: Object.freeze(output),
      valid: true
    });
  }

  return Object.freeze({
    increment,
    recordLockTimeout: (amount = 1) => increment("lock_timeout_total", amount),
    recordLockWait: (amount = 1) => increment("lock_wait_total", amount),
    recordReplayDenial: (amount = 1) => increment("replay_denial_total", amount),
    recordRateLimitDenial: (amount = 1) => increment("rate_limit_denial_total", amount),
    recordStaleAck: (amount = 1) => increment("stale_ack_total", amount),
    recordAuditGap: (amount = 1) => increment("audit_gap_total", amount),
    snapshot
  });
}

/**
 * Tracks only an aggregate in-flight count.  It intentionally has no work
 * identifiers, request objects, or error payloads.  Once draining starts,
 * new work is rejected and readiness can fail immediately.  `drain()` waits
 * at most the bounded timeout. The close callback is invoked only after all
 * tracked work has finished, and it shares the same end-to-end deadline.
 */
export function createDrainController({
  defaultTimeoutMs = DEFAULT_DRAIN_TIMEOUT_MS,
  maxTimeoutMs = MAX_DRAIN_TIMEOUT_MS,
  clock = () => Date.now()
} = {}) {
  const defaultTimeout = boundedTimeout(defaultTimeoutMs, maxTimeoutMs);
  if (!Number.isSafeInteger(maxTimeoutMs) || maxTimeoutMs < 0 || maxTimeoutMs > 10 * 60_000) throw invalidOperationalInput();
  if (typeof clock !== "function") throw invalidOperationalInput();

  let state = "running";
  let inFlight = 0;
  let drainPromise;
  let closePromise;
  let wakeDrain;

  function snapshot() {
    return Object.freeze({
      state,
      accepting: state === "running",
      in_flight: inFlight
    });
  }

  function acquire() {
    if (state !== "running") throw new DrainRejectedError();
    inFlight += 1;
    let released = false;
    return () => {
      if (released) return;
      released = true;
      inFlight = Math.max(0, inFlight - 1);
      if (inFlight === 0) wakeDrain?.();
    };
  }

  async function track(operation) {
    if (typeof operation !== "function") throw invalidOperationalInput();
    const release = acquire();
    try {
      return await operation();
    } finally {
      release();
    }
  }

  function beginDrain() {
    if (state === "running") state = "draining";
    return snapshot();
  }

  async function waitForInFlight(timeoutMs) {
    if (inFlight === 0) return true;
    const startedAt = safeClock(clock);
    const deadline = startedAt + timeoutMs;
    let timer;
    try {
      return await new Promise((resolve) => {
        let settled = false;
        const settle = (drained) => {
          if (settled) return;
          settled = true;
          if (timer !== undefined) clearTimeout(timer);
          if (wakeDrain === notify) wakeDrain = undefined;
          resolve(drained);
        };
        const notify = () => settle(inFlight === 0);
        wakeDrain = notify;
        const remaining = Math.max(0, deadline - safeClock(clock));
        timer = setTimeout(() => settle(inFlight === 0), remaining);
        if (inFlight === 0) settle(true);
      });
    } finally {
      wakeDrain = undefined;
    }
  }

  async function close(closeCallback, timeoutMs = defaultTimeout) {
    if (typeof closeCallback !== "function") throw invalidOperationalInput();
    if (closePromise) return closePromise;
    closePromise = withTimeout(Promise.resolve().then(closeCallback), timeoutMs);
    try {
      await closePromise;
      state = "closed";
      return Object.freeze({ state: "closed", drained: inFlight === 0, in_flight: inFlight, timeout_ms: timeoutMs });
    } catch (error) {
      closePromise = undefined;
      state = "draining";
      throw error;
    }
  }

  async function drain({ timeoutMs = defaultTimeout, close: closeCallback } = {}) {
    if (typeof closeCallback !== "function") throw invalidOperationalInput();
    if (drainPromise) return drainPromise;
    if (state === "closed") return { state: "closed", drained: inFlight === 0, in_flight: inFlight };
    beginDrain();
    const bounded = boundedTimeout(timeoutMs, maxTimeoutMs);
    drainPromise = (async () => {
      const startedAt = safeClock(clock);
      const drained = await waitForInFlight(bounded);
      if (!drained) {
        drainPromise = undefined;
        return Object.freeze({ state: "draining", drained: false, in_flight: inFlight, timeout_ms: bounded });
      }
      const remaining = Math.max(0, bounded - Math.max(0, safeClock(clock) - startedAt));
      await close(closeCallback, remaining);
      return Object.freeze({ state: "closed", drained: true, in_flight: inFlight, timeout_ms: bounded });
    })();
    return drainPromise;
  }

  async function closeImmediately(closeCallback) {
    if (drainPromise) return drainPromise;
    return close(closeCallback, defaultTimeout);
  }

  return Object.freeze({
    acquire,
    track,
    beginDrain,
    drain,
    close: closeImmediately,
    snapshot
  });
}

/**
 * Build the stable readiness/operational-health JSON contract.  All source
 * failures are converted to fixed status values.  The returned object never
 * includes an exception, SQL text, connection string, tenant identifier, or
 * caller-provided label.
 */
export function createOperationalHealth({
  pool,
  migrationStatus,
  expectedSchemaVersion = EXPECTED_POSTGRES_SCHEMA_VERSION,
  maxConnections,
  metrics = createOperationalMetrics(),
  drainController,
  probe = defaultProbe
} = {}) {
  if (!pool || typeof pool !== "object") throw invalidOperationalInput();
  if (typeof migrationStatus !== "function" || typeof probe !== "function") throw invalidOperationalInput();
  if (!Number.isSafeInteger(expectedSchemaVersion) || expectedSchemaVersion < 1) throw invalidOperationalInput();
  if (!metrics || typeof metrics.snapshot !== "function") throw invalidOperationalInput();
  if (!drainController || typeof drainController.snapshot !== "function") throw invalidOperationalInput();
  const configuredMax = positiveInteger(maxConnections ?? pool.options?.max);

  async function readiness() {
    const drain = safeDrainSnapshot(drainController.snapshot);
    const poolCheck = readPool(pool, configuredMax);
    const metricSnapshot = safeMetricSnapshot(metrics);
    if (drain.state !== "running") {
      return contract({
        ready: false,
        status: drain.state,
        code: drain.state === "draining" ? "draining" : "closed",
        database: { ok: false, probe: "skipped" },
        schema: skippedSchema(expectedSchemaVersion),
        pool: poolCheck,
        drain,
        metrics: metricSnapshot
      });
    }

    const [databaseResult, migrationResult] = await Promise.allSettled([
      Promise.resolve().then(() => probe(pool)),
      Promise.resolve().then(() => migrationStatus())
    ]);
    recordObservedLockWaits(metrics, databaseResult);
    const database = normalizeProbeResult(databaseResult);
    const schema = normalizeSchemaResult(migrationResult, expectedSchemaVersion);
    const poolReady = poolCheck.ok;
    const metricsReady = metricSnapshot.valid !== false;
    const ready = database.ok && schema.ok && poolReady && metricsReady;
    const code = ready ? "ready" : firstFailureCode({ database, schema, pool: poolCheck, metricsReady });
    return contract({
      ready,
      status: ready ? "ready" : "not_ready",
      code,
      database,
      schema,
      pool: poolCheck,
      drain,
      metrics: metricSnapshot
    });
  }

  return Object.freeze({ readiness, health: readiness });
}

function contract({ ready, status, code, database, schema, pool, drain, metrics }) {
  return Object.freeze({
    version: OPERATIONAL_HEALTH_VERSION,
    ready: Boolean(ready),
    status,
    code,
    checks: Object.freeze({ database, schema, pool, drain }),
    metrics
  });
}

async function defaultProbe(pool) {
  const result = await pool.query("SELECT 1::integer AS ready", []);
  if (result?.rows?.[0]?.ready !== 1) return false;
  try {
    const waits = await pool.query("SELECT count(*)::integer AS lock_waits FROM pg_stat_activity WHERE wait_event_type = 'Lock' AND state = 'active'", []);
    const lockWaits = Number(waits?.rows?.[0]?.lock_waits);
    return { ok: true, lockWaits: Number.isSafeInteger(lockWaits) && lockWaits >= 0 ? lockWaits : null };
  } catch {
    return { ok: true, lockWaits: null };
  }
}

function recordObservedLockWaits(metrics, result) {
  const amount = result.status === "fulfilled" ? result.value?.lockWaits : null;
  if (!Number.isSafeInteger(amount) || amount < 1) return;
  try { metrics.recordLockWait(amount); } catch { /* Metrics cannot affect readiness. */ }
}

function withTimeout(promise, timeoutMs) {
  if (timeoutMs <= 0) return Promise.reject(new OperationalHealthError("drain_timeout"));
  let timer;
  return Promise.race([
    promise,
    new Promise((_, reject) => { timer = setTimeout(() => reject(new OperationalHealthError("drain_timeout")), timeoutMs); })
  ]).finally(() => clearTimeout(timer));
}

function normalizeProbeResult(result) {
  if (result.status !== "fulfilled") return Object.freeze({ ok: false, probe: "failed" });
  return Object.freeze({ ok: result.value === true || result.value?.ok === true, probe: result.value === true || result.value?.ok === true ? "ok" : "failed" });
}

function normalizeSchemaResult(result, expectedVersion) {
  if (result.status !== "fulfilled" || !result.value || typeof result.value !== "object") return skippedSchema(expectedVersion, "unknown");
  const value = result.value;
  const applied = Array.isArray(value.applied) ? value.applied : null;
  const appliedVersion = applied?.length ? safeVersion(applied.at(-1)?.version) : null;
  const migrationCount = applied?.length ?? null;
  const pendingCount = Array.isArray(value.pending) ? value.pending.length : null;
  const modifiedCount = Array.isArray(value.modified) ? value.modified.length : null;
  const dirty = value.dirty === true;
  const exactVersion = appliedVersion === expectedVersion && migrationCount === expectedVersion;
  const exact = exactVersion && pendingCount === 0 && modifiedCount === 0 && dirty === false;
  const checksumStatus = result.value.dirty === true
    ? "dirty"
    : modifiedCount > 0
      ? "drift"
      : pendingCount > 0
        ? "pending"
        : modifiedCount === 0 && pendingCount === 0
          ? "verified"
          : "unknown";
  return Object.freeze({
    ok: exact,
    expected_version: expectedVersion,
    schema_version_status: exactVersion ? "exact" : "mismatch",
    applied_version: appliedVersion,
    migration_count: migrationCount,
    pending_count: pendingCount,
    checksum_status: checksumStatus,
    drift: modifiedCount === null ? null : modifiedCount > 0
  });
}

function skippedSchema(expectedVersion, status = "skipped") {
  return Object.freeze({
    ok: false,
    expected_version: expectedVersion,
    schema_version_status: status === "unknown" ? "unknown" : "skipped",
    applied_version: null,
    migration_count: null,
    pending_count: null,
    checksum_status: status,
    drift: null
  });
}

function readPool(pool, configuredMax) {
  try {
    const max = positiveInteger(configuredMax ?? pool.options?.max);
    const total = nonNegativeInteger(pool.totalCount);
    const idle = nonNegativeInteger(pool.idleCount);
    const waiting = nonNegativeInteger(pool.waitingCount);
    const valid = max !== null && total !== null && idle !== null && waiting !== null && idle <= total && total <= max;
    const utilization = valid ? Math.min(100, Math.round((total / max) * 100)) : null;
    return Object.freeze({
      ok: valid && waiting === 0,
      max_connections: max,
      total_connections: total,
      idle_connections: idle,
      waiting_connections: waiting,
      utilization_percent: utilization,
      saturated: valid ? total >= max : null
    });
  } catch {
    return unavailablePool();
  }
}

function unavailablePool() {
  return Object.freeze({
    ok: false,
    max_connections: null,
    total_connections: null,
    idle_connections: null,
    waiting_connections: null,
    utilization_percent: null,
    saturated: null
  });
}

function safeDrainSnapshot(read) {
  try {
    const value = read();
    const state = value?.state;
    const inFlight = nonNegativeInteger(value?.in_flight);
    if (!["running", "draining", "closed"].includes(state) || inFlight === null) throw new Error();
    return Object.freeze({ state, accepting: state === "running", in_flight: inFlight });
  } catch {
    return Object.freeze({ state: "closed", accepting: false, in_flight: 0 });
  }
}

function safeMetricSnapshot(metrics) {
  try {
    const value = metrics.snapshot();
    const counters = value?.counters;
    if (!counters || typeof counters !== "object") throw new Error();
    const output = {};
    for (const key of OPERATIONAL_METRIC_KEYS) output[key] = boundedCounter(counters[key]);
    return Object.freeze({ version: OPERATIONAL_HEALTH_VERSION, counters: Object.freeze(output), valid: value.valid !== false });
  } catch {
    const counters = Object.fromEntries(OPERATIONAL_METRIC_KEYS.map((key) => [key, 0]));
    return Object.freeze({ version: OPERATIONAL_HEALTH_VERSION, counters: Object.freeze(counters), valid: false });
  }
}

function firstFailureCode({ database, schema, pool, metricsReady }) {
  if (!database.ok) return "database_unavailable";
  if (!schema.ok) {
    if (schema.checksum_status === "drift") return "migration_drift";
    if (schema.schema_version_status === "mismatch" || schema.checksum_status === "pending") return "schema_version_mismatch";
    return "schema_unverified";
  }
  if (!pool.ok) return "pool_saturated";
  if (!metricsReady) return "metrics_unavailable";
  return "health_check_failed";
}

function safeClock(clock) {
  const value = Number(clock());
  return Number.isFinite(value) ? value : Date.now();
}

function boundedTimeout(value, max) {
  if (!Number.isSafeInteger(max) || max < 0 || max > 10 * 60_000) throw invalidOperationalInput();
  if (!Number.isSafeInteger(value) || value < 0 || value > max) throw invalidOperationalInput();
  return value;
}

function boundedCounter(value) {
  if (!Number.isSafeInteger(value) || value < 0 || value > MAX_COUNTER) throw invalidOperationalInput();
  return value;
}

function positiveInteger(value) {
  return Number.isSafeInteger(value) && value > 0 ? value : null;
}

function nonNegativeInteger(value) {
  return Number.isSafeInteger(value) && value >= 0 ? value : null;
}

function safeVersion(value) {
  const normalized = Number(value);
  return Number.isSafeInteger(normalized) && normalized >= 1 ? normalized : null;
}

function invalidOperationalInput() {
  return new OperationalHealthError("invalid_input");
}

function publicMessage(code) {
  if (code === "draining") return "PostgreSQL runtime is draining";
  if (code === "drain_timeout") return "PostgreSQL runtime drain timed out";
  return "Operational health input is invalid";
}
