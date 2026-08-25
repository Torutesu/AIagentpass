/**
 * Deterministic, aggregate-only G4.1 propagation qualification evidence.
 *
 * This module is deliberately not imported by the service, runtime, or
 * notifier. A real PostgreSQL qualification harness feeds it completed
 * attempts and fixed resource snapshots after each test operation.
 */

export const G41_PROPAGATION_QUALIFICATION_SCHEMA_VERSION = 1;
export const G41_PROPAGATION_QUALIFICATION_NAME = "g4.1-propagation-latency";

export const G41_PROPAGATION_PHASES = Object.freeze([
  "commit_to_observation",
  "commit_to_applied_ack"
]);

export const G41_PROPAGATION_RESOURCE_KEYS = Object.freeze([
  "pool_connections",
  "pool_waiters",
  "in_flight_operations",
  "notification_reconnects"
]);

export const G41_DEFAULT_SLO_THRESHOLDS = Object.freeze({
  min_count: 100,
  max_timeout_rate: 0.01,
  commit_to_observation: Object.freeze({
    p50_ms: 100,
    p95_ms: 250,
    p99_ms: 500,
    max_ms: 2_000
  }),
  commit_to_applied_ack: Object.freeze({
    p50_ms: 250,
    p95_ms: 1_000,
    p99_ms: 2_000,
    max_ms: 5_000
  }),
  resources: Object.freeze({
    pool_connections: 16,
    pool_waiters: 0,
    in_flight_operations: 100,
    notification_reconnects: 3
  })
});

export const G41_PROPAGATION_LIMITS = Object.freeze({
  max_samples: 100_000,
  max_latency_ms: 86_400_000,
  max_timestamp_ms: Number.MAX_SAFE_INTEGER,
  max_timeout_rate: 1,
  max_report_failures: 32
});

const PHASE_SET = new Set(G41_PROPAGATION_PHASES);
const LATENCY_KEYS = Object.freeze(["p50_ms", "p95_ms", "p99_ms", "max_ms"]);
const PHASE_REPORT_KEYS = Object.freeze([
  "count",
  "latency_count",
  "timeout_count",
  "timeout_rate",
  "p50_ms",
  "p95_ms",
  "p99_ms",
  "max_ms"
]);
const FAILURE_CODES = new Set([
  "sample_count_below_minimum",
  "latency_samples_missing",
  "timeout_rate_exceeded",
  "latency_p50_exceeded",
  "latency_p95_exceeded",
  "latency_p99_exceeded",
  "latency_max_exceeded",
  "resource_data_missing",
  "resource_bound_exceeded",
  "sample_capacity_exceeded"
]);
const FAILURE_PHASES = new Set([...G41_PROPAGATION_PHASES, "run", "resources"]);
const FAILURE_METRICS = new Set([
  "accepted_samples",
  "count",
  "latency_count",
  "timeout_rate",
  ...LATENCY_KEYS,
  ...G41_PROPAGATION_RESOURCE_KEYS,
  "resource_samples"
]);
const MAX_SAFE = Number.MAX_SAFE_INTEGER;

export class G41PropagationQualificationError extends Error {
  constructor(code) {
    super(publicMessage(code));
    this.name = "G41PropagationQualificationError";
    this.code = code;
  }
}

/**
 * Create a bounded recorder. The recorder keeps only latency numbers, fixed
 * aggregate counters, and resource maxima. It never stores an input object,
 * timestamp, tenant, request, UUID, SQL value, or error message.
 */
export function createG41PropagationLatencyRecorder({
  thresholds = G41_DEFAULT_SLO_THRESHOLDS,
  maxSamples = G41_PROPAGATION_LIMITS.max_samples,
  maxLatencyMs = G41_PROPAGATION_LIMITS.max_latency_ms
} = {}) {
  const normalizedThresholds = normalizeThresholds(thresholds);
  const boundedMaxSamples = boundedInteger(maxSamples, 1, G41_PROPAGATION_LIMITS.max_samples);
  if (normalizedThresholds.min_count * G41_PROPAGATION_PHASES.length > boundedMaxSamples) throw invalidInput();
  const boundedMaxLatencyMs = boundedFinite(maxLatencyMs, 0, G41_PROPAGATION_LIMITS.max_latency_ms);
  const latencies = Object.fromEntries(G41_PROPAGATION_PHASES.map((phase) => [phase, []]));
  const counts = Object.fromEntries(G41_PROPAGATION_PHASES.map((phase) => [phase, { count: 0, timeout_count: 0 }]));
  const resourceMaxima = Object.fromEntries(G41_PROPAGATION_RESOURCE_KEYS.map((key) => [key, 0]));
  let acceptedSamples = 0;
  let resourceSamples = 0;
  let resourceDataMissing = false;
  let capacityExceeded = false;

  function recordPhase(phase, input = {}) {
    if (!PHASE_SET.has(phase)) throw invalidInput();
    if (capacityExceeded || acceptedSamples >= boundedMaxSamples) {
      capacityExceeded = true;
      throw new G41PropagationQualificationError("sample_capacity_exceeded");
    }
    const sample = normalizeSample(phase, input, boundedMaxLatencyMs);
    const state = counts[phase];
    state.count += 1;
    acceptedSamples += 1;
    if (sample.timedOut) {
      state.timeout_count += 1;
    } else {
      latencies[phase].push(sample.latencyMs);
    }
    if (sample.resourceSnapshot === null) {
      resourceDataMissing = true;
    } else {
      resourceSamples += 1;
      for (const key of G41_PROPAGATION_RESOURCE_KEYS) {
        resourceMaxima[key] = Math.max(resourceMaxima[key], sample.resourceSnapshot[key]);
      }
    }
    return Object.freeze({ phase, count: state.count, accepted_samples: acceptedSamples });
  }

  function recordCommitToObservation(input) {
    return recordPhase("commit_to_observation", input);
  }

  function recordCommitToAppliedAck(input) {
    return recordPhase("commit_to_applied_ack", input);
  }

  function report() {
    const phases = {};
    for (const phase of G41_PROPAGATION_PHASES) phases[phase] = phaseReport(counts[phase], latencies[phase]);
    const failures = evaluateFailures({
      phases,
      thresholds: normalizedThresholds,
      resourceMaxima,
      resourceDataMissing,
      capacityExceeded,
      resourceSamples
    });
    return freezeDeep({
      schema_version: G41_PROPAGATION_QUALIFICATION_SCHEMA_VERSION,
      qualification: G41_PROPAGATION_QUALIFICATION_NAME,
      qualified: failures.length === 0,
      thresholds: normalizedThresholds,
      limits: {
        max_samples: boundedMaxSamples,
        max_latency_ms: boundedMaxLatencyMs
      },
      phases,
      resource_maxima: { ...resourceMaxima },
      resource_samples: resourceSamples,
      accepted_samples: acceptedSamples,
      capacity_exceeded: capacityExceeded,
      failures
    });
  }

  return Object.freeze({
    recordCommitToObservation,
    recordCommitToAppliedAck,
    recordObservation: recordCommitToObservation,
    recordAppliedAck: recordCommitToAppliedAck,
    recordPhase,
    report
  });
}

export function buildG41PropagationReport(options) {
  const recorder = createG41PropagationLatencyRecorder(options);
  for (const sample of options?.samples ?? []) {
    if (!sample || typeof sample !== "object" || Array.isArray(sample)) throw invalidInput();
    const { phase, ...input } = sample;
    recorder.recordPhase(phase, input);
  }
  return recorder.report();
}

/**
 * Validate both the fixed JSON shape and the derived qualification decision.
 * This intentionally rejects unknown fields so a caller cannot smuggle labels
 * or secret-bearing evidence into a report.
 */
export function validateG41PropagationReport(value) {
  exactKeys(value, [
    "schema_version",
    "qualification",
    "qualified",
    "thresholds",
    "limits",
    "phases",
    "resource_maxima",
    "resource_samples",
    "accepted_samples",
    "capacity_exceeded",
    "failures"
  ], "G4.1 propagation report");
  if (value.schema_version !== G41_PROPAGATION_QUALIFICATION_SCHEMA_VERSION
    || value.qualification !== G41_PROPAGATION_QUALIFICATION_NAME
    || typeof value.qualified !== "boolean") throw invalidInput();
  validateThresholds(value.thresholds);
  exactKeys(value.limits, ["max_samples", "max_latency_ms"], "G4.1 report limits");
  boundedInteger(value.limits.max_samples, 1, G41_PROPAGATION_LIMITS.max_samples);
  boundedFinite(value.limits.max_latency_ms, 0, G41_PROPAGATION_LIMITS.max_latency_ms);
  if (value.thresholds.min_count * G41_PROPAGATION_PHASES.length > value.limits.max_samples) throw invalidInput();
  exactKeys(value.phases, G41_PROPAGATION_PHASES, "G4.1 report phases");
  for (const phase of G41_PROPAGATION_PHASES) validatePhaseReport(value.phases[phase], value.limits.max_latency_ms);
  exactKeys(value.resource_maxima, G41_PROPAGATION_RESOURCE_KEYS, "G4.1 resource maxima");
  for (const key of G41_PROPAGATION_RESOURCE_KEYS) boundedInteger(value.resource_maxima[key], 0, MAX_SAFE);
  boundedInteger(value.resource_samples, 0, MAX_SAFE);
  boundedInteger(value.accepted_samples, 0, G41_PROPAGATION_LIMITS.max_samples);
  if (value.accepted_samples > value.limits.max_samples) throw invalidInput();
  if (value.resource_samples > value.limits.max_samples) throw invalidInput();
  if (typeof value.capacity_exceeded !== "boolean") throw invalidInput();
  if (!Array.isArray(value.failures) || value.failures.length > G41_PROPAGATION_LIMITS.max_report_failures) throw invalidInput();
  for (const failure of value.failures) validateFailure(failure);
  const expectedFailures = evaluateFailures({
    phases: value.phases,
    thresholds: value.thresholds,
    resourceMaxima: value.resource_maxima,
    resourceDataMissing: value.resource_samples < value.accepted_samples,
    capacityExceeded: value.capacity_exceeded,
    resourceSamples: value.resource_samples
  });
  if (JSON.stringify(value.failures) !== JSON.stringify(expectedFailures)
    || value.qualified !== (expectedFailures.length === 0)
    || value.capacity_exceeded !== value.failures.some((failure) => failure.code === "sample_capacity_exceeded")) {
    throw invalidInput();
  }
  const totalCount = G41_PROPAGATION_PHASES.reduce((sum, phase) => sum + value.phases[phase].count, 0);
  if (value.accepted_samples !== totalCount || value.resource_samples > value.accepted_samples) throw invalidInput();
  return value;
}

export function serializeG41PropagationReport(value) {
  validateG41PropagationReport(value);
  return `${JSON.stringify(value, null, 2)}\n`;
}

export function parseAndValidateG41PropagationReport(json) {
  if (typeof json !== "string" || Buffer.byteLength(json, "utf8") > 1_048_576) throw invalidInput();
  let value;
  try { value = JSON.parse(json); } catch { throw new G41PropagationQualificationError("invalid_json"); }
  validateG41PropagationReport(value);
  if (serializeG41PropagationReport(value) !== json) throw new G41PropagationQualificationError("noncanonical_json");
  return value;
}

function normalizeSample(phase, input, maxLatencyMs) {
  if (!input || typeof input !== "object" || Array.isArray(input)) throw invalidInput();
  const allowed = new Set(["committed_at_ms", "observed_at_ms", "applied_ack_at_ms", "latency_ms", "timed_out", "resource_snapshot"]);
  for (const key of Object.keys(input)) if (!allowed.has(key)) throw invalidInput();
  if (input.timed_out !== undefined && typeof input.timed_out !== "boolean") throw invalidInput();
  const timedOut = input.timed_out === true;
  const endKey = phase === "commit_to_observation" ? "observed_at_ms" : "applied_ack_at_ms";
  const hasLatency = input.latency_ms !== undefined;
  const hasStart = input.committed_at_ms !== undefined;
  const hasEnd = input[endKey] !== undefined;
  if (timedOut) {
    if (hasLatency || hasEnd) throw invalidInput();
  } else if (hasLatency === (hasStart || hasEnd)) {
    throw invalidInput();
  }
  let latencyMs = null;
  if (!timedOut) {
    if (hasLatency) {
      latencyMs = boundedFinite(input.latency_ms, 0, maxLatencyMs);
    } else {
      if (!hasStart || !hasEnd) throw invalidInput();
      const committedAt = boundedFinite(input.committed_at_ms, 0, G41_PROPAGATION_LIMITS.max_timestamp_ms);
      const completedAt = boundedFinite(input[endKey], 0, G41_PROPAGATION_LIMITS.max_timestamp_ms);
      if (completedAt < committedAt) throw invalidInput();
      latencyMs = boundedFinite(completedAt - committedAt, 0, maxLatencyMs);
    }
  }
  const resourceSnapshot = input.resource_snapshot === undefined ? null : normalizeResourceSnapshot(input.resource_snapshot);
  return { timedOut, latencyMs, resourceSnapshot };
}

function normalizeResourceSnapshot(value) {
  exactKeys(value, G41_PROPAGATION_RESOURCE_KEYS, "G4.1 resource snapshot");
  const output = {};
  for (const key of G41_PROPAGATION_RESOURCE_KEYS) output[key] = boundedInteger(value[key], 0, MAX_SAFE);
  return output;
}

function phaseReport(state, samples) {
  const sorted = [...samples].sort((left, right) => left - right);
  return {
    count: state.count,
    latency_count: sorted.length,
    timeout_count: state.timeout_count,
    timeout_rate: state.count === 0 ? 0 : state.timeout_count / state.count,
    p50_ms: quantile(sorted, 0.50),
    p95_ms: quantile(sorted, 0.95),
    p99_ms: quantile(sorted, 0.99),
    max_ms: sorted.length === 0 ? null : sorted[sorted.length - 1]
  };
}

function quantile(sorted, percentile) {
  if (sorted.length === 0) return null;
  return sorted[Math.max(0, Math.ceil(sorted.length * percentile) - 1)];
}

function evaluateFailures({ phases, thresholds, resourceMaxima, resourceDataMissing, capacityExceeded, resourceSamples }) {
  const failures = [];
  if (capacityExceeded) failures.push(failure("sample_capacity_exceeded", "run", "accepted_samples", null, null));
  for (const phase of G41_PROPAGATION_PHASES) {
    const result = phases[phase];
    if (result.count < thresholds.min_count) failures.push(failure("sample_count_below_minimum", phase, "count", result.count, thresholds.min_count));
    if (result.latency_count === 0) failures.push(failure("latency_samples_missing", phase, "latency_count", result.latency_count, 1));
    if (result.timeout_rate > thresholds.max_timeout_rate) failures.push(failure("timeout_rate_exceeded", phase, "timeout_rate", result.timeout_rate, thresholds.max_timeout_rate));
    for (const metric of LATENCY_KEYS) {
      const observed = result[metric];
      const threshold = thresholds[phase][metric];
      if (observed !== null && observed > threshold) failures.push(failure(`latency_${metric.replace("_ms", "")}_exceeded`, phase, metric, observed, threshold));
    }
  }
  if (resourceDataMissing || resourceSamples === 0) failures.push(failure("resource_data_missing", "resources", "resource_samples", resourceSamples, 1));
  for (const key of G41_PROPAGATION_RESOURCE_KEYS) {
    if (resourceMaxima[key] > thresholds.resources[key]) failures.push(failure("resource_bound_exceeded", "resources", key, resourceMaxima[key], thresholds.resources[key]));
  }
  return failures;
}

function failure(code, phase, metric, observed, threshold) {
  return { code, phase, metric, observed, threshold };
}

function normalizeThresholds(value) {
  validateThresholds(value);
  return {
    min_count: value.min_count,
    max_timeout_rate: value.max_timeout_rate,
    commit_to_observation: { ...value.commit_to_observation },
    commit_to_applied_ack: { ...value.commit_to_applied_ack },
    resources: { ...value.resources }
  };
}

function validateThresholds(value) {
  exactKeys(value, ["min_count", "max_timeout_rate", ...G41_PROPAGATION_PHASES, "resources"], "G4.1 SLO thresholds");
  boundedInteger(value.min_count, 1, G41_PROPAGATION_LIMITS.max_samples);
  boundedFinite(value.max_timeout_rate, 0, G41_PROPAGATION_LIMITS.max_timeout_rate);
  for (const phase of G41_PROPAGATION_PHASES) {
    exactKeys(value[phase], LATENCY_KEYS, `G4.1 ${phase} thresholds`);
    for (const key of LATENCY_KEYS) boundedFinite(value[phase][key], 0, G41_PROPAGATION_LIMITS.max_latency_ms);
    if (value[phase].p50_ms > value[phase].p95_ms || value[phase].p95_ms > value[phase].p99_ms || value[phase].p99_ms > value[phase].max_ms) throw invalidInput();
  }
  exactKeys(value.resources, G41_PROPAGATION_RESOURCE_KEYS, "G4.1 resource thresholds");
  for (const key of G41_PROPAGATION_RESOURCE_KEYS) boundedInteger(value.resources[key], 0, MAX_SAFE);
}

function validatePhaseReport(value, maxLatencyMs = G41_PROPAGATION_LIMITS.max_latency_ms) {
  exactKeys(value, PHASE_REPORT_KEYS, "G4.1 phase report");
  boundedInteger(value.count, 0, G41_PROPAGATION_LIMITS.max_samples);
  boundedInteger(value.latency_count, 0, G41_PROPAGATION_LIMITS.max_samples);
  boundedInteger(value.timeout_count, 0, G41_PROPAGATION_LIMITS.max_samples);
  if (value.latency_count + value.timeout_count !== value.count) throw invalidInput();
  boundedFinite(value.timeout_rate, 0, 1);
  if (value.timeout_rate !== (value.count === 0 ? 0 : value.timeout_count / value.count)) throw invalidInput();
  for (const key of ["p50_ms", "p95_ms", "p99_ms", "max_ms"]) {
    if (value[key] !== null) boundedFinite(value[key], 0, maxLatencyMs);
  }
  if (value.latency_count === 0) {
    if (value.p50_ms !== null || value.p95_ms !== null || value.p99_ms !== null || value.max_ms !== null) throw invalidInput();
  } else if ([value.p50_ms, value.p95_ms, value.p99_ms, value.max_ms].some((metric) => metric === null)) {
    throw invalidInput();
  } else if (value.p50_ms > value.p95_ms || value.p95_ms > value.p99_ms || value.p99_ms > value.max_ms) {
    throw invalidInput();
  }
}

function validateFailure(value) {
  exactKeys(value, ["code", "phase", "metric", "observed", "threshold"], "G4.1 qualification failure");
  if (!FAILURE_CODES.has(value.code) || !FAILURE_PHASES.has(value.phase) || !FAILURE_METRICS.has(value.metric)) throw invalidInput();
  if (value.observed !== null) boundedFinite(value.observed, 0, MAX_SAFE);
  if (value.threshold !== null) boundedFinite(value.threshold, 0, MAX_SAFE);
}

function exactKeys(value, keys, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new G41PropagationQualificationError("invalid_input");
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) throw new G41PropagationQualificationError("unknown_field");
  return value;
}

function boundedInteger(value, minimum, maximum) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) throw invalidInput();
  return value;
}

function boundedFinite(value, minimum, maximum) {
  if (typeof value !== "number" || !Number.isFinite(value) || value < minimum || value > maximum) throw invalidInput();
  return value;
}

function invalidInput() {
  return new G41PropagationQualificationError("invalid_input");
}

function publicMessage(code) {
  if (code === "sample_capacity_exceeded") return "G4.1 propagation sample capacity was exceeded";
  if (code === "invalid_json") return "G4.1 propagation report is not valid JSON";
  if (code === "noncanonical_json") return "G4.1 propagation report is not canonical JSON";
  if (code === "unknown_field") return "G4.1 propagation evidence contains an unknown field";
  return "G4.1 propagation qualification input is invalid";
}

function freezeDeep(value) {
  if (!value || typeof value !== "object" || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) freezeDeep(child);
  return Object.freeze(value);
}
