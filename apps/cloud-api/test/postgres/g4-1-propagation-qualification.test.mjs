import assert from "node:assert/strict";
import test from "node:test";

import {
  G41_DEFAULT_SLO_THRESHOLDS,
  G41_PROPAGATION_RESOURCE_KEYS,
  G41PropagationQualificationError,
  buildG41PropagationReport,
  createG41PropagationLatencyRecorder,
  parseAndValidateG41PropagationReport,
  serializeG41PropagationReport,
  validateG41PropagationReport
} from "../../src/postgres/g4-1-propagation-qualification.mjs";

const RESOURCES = Object.freeze({
  pool_connections: 2,
  pool_waiters: 0,
  in_flight_operations: 1,
  notification_reconnects: 0
});

function thresholds(overrides = {}) {
  return {
    min_count: 1,
    max_timeout_rate: 0.1,
    commit_to_observation: { ...G41_DEFAULT_SLO_THRESHOLDS.commit_to_observation },
    commit_to_applied_ack: { ...G41_DEFAULT_SLO_THRESHOLDS.commit_to_applied_ack },
    resources: { ...G41_DEFAULT_SLO_THRESHOLDS.resources },
    ...overrides
  };
}

test("records commit-to-observation and applied-ACK latency independently with deterministic nearest-rank percentiles", () => {
  const recorder = createG41PropagationLatencyRecorder({
    thresholds: thresholds({ min_count: 1 }),
    maxSamples: 32
  });
  const input = { committed_at_ms: 1_000, observed_at_ms: 1_001, resource_snapshot: { ...RESOURCES } };
  recorder.recordCommitToObservation(input);
  input.observed_at_ms = 99_999;
  for (let latency = 1; latency <= 10; latency += 1) {
    recorder.recordCommitToAppliedAck({ latency_ms: latency, resource_snapshot: { ...RESOURCES, pool_connections: latency } });
  }
  recorder.recordCommitToAppliedAck({ timed_out: true, resource_snapshot: RESOURCES });
  const report = recorder.report();

  assert.equal(report.qualified, true);
  assert.deepEqual(report.phases.commit_to_observation, {
    count: 1,
    latency_count: 1,
    timeout_count: 0,
    timeout_rate: 0,
    p50_ms: 1,
    p95_ms: 1,
    p99_ms: 1,
    max_ms: 1
  });
  assert.deepEqual(report.phases.commit_to_applied_ack, {
    count: 11,
    latency_count: 10,
    timeout_count: 1,
    timeout_rate: 1 / 11,
    p50_ms: 5,
    p95_ms: 10,
    p99_ms: 10,
    max_ms: 10
  });
  assert.deepEqual(report.resource_maxima, {
    pool_connections: 10,
    pool_waiters: 0,
    in_flight_operations: 1,
    notification_reconnects: 0
  });
  assert.deepEqual(validateG41PropagationReport(report), report);
  assert.equal(JSON.stringify(report).includes("tenant"), false);
  assert.equal(JSON.stringify(report).includes("request"), false);
});

test("fails qualification when latency, timeout, or resource SLOs are exceeded", () => {
  const recorder = createG41PropagationLatencyRecorder({
    thresholds: thresholds({
      max_timeout_rate: 0,
      commit_to_observation: { p50_ms: 10, p95_ms: 10, p99_ms: 10, max_ms: 10 },
      commit_to_applied_ack: { p50_ms: 10, p95_ms: 10, p99_ms: 10, max_ms: 10 },
      resources: { ...RESOURCES, pool_connections: 2, pool_waiters: 0, in_flight_operations: 1, notification_reconnects: 0 }
    })
  });
  const overLimit = { pool_connections: 3, pool_waiters: 1, in_flight_operations: 2, notification_reconnects: 1 };
  recorder.recordCommitToObservation({ latency_ms: 20, resource_snapshot: overLimit });
  recorder.recordCommitToObservation({ timed_out: true, resource_snapshot: overLimit });
  recorder.recordCommitToAppliedAck({ latency_ms: 20, resource_snapshot: overLimit });
  const report = recorder.report();

  assert.equal(report.qualified, false);
  const codes = report.failures.map(({ code, phase, metric }) => `${code}:${phase}:${metric}`);
  assert.ok(codes.includes("timeout_rate_exceeded:commit_to_observation:timeout_rate"));
  assert.ok(codes.includes("latency_p50_exceeded:commit_to_observation:p50_ms"));
  assert.ok(codes.includes("latency_max_exceeded:commit_to_applied_ack:max_ms"));
  assert.ok(codes.includes("resource_bound_exceeded:resources:pool_waiters"));
  assert.ok(codes.includes("resource_bound_exceeded:resources:in_flight_operations"));
  assert.ok(codes.includes("resource_bound_exceeded:resources:pool_connections"));
});

test("counts timeouts in the denominator and fails incomplete latency/resource evidence", () => {
  const recorder = createG41PropagationLatencyRecorder({ thresholds: thresholds({ max_timeout_rate: 0.5 }) });
  recorder.recordCommitToObservation({ timed_out: true });
  recorder.recordCommitToAppliedAck({ timed_out: true });
  const report = recorder.report();

  assert.equal(report.phases.commit_to_observation.count, 1);
  assert.equal(report.phases.commit_to_observation.latency_count, 0);
  assert.equal(report.phases.commit_to_observation.timeout_count, 1);
  assert.equal(report.phases.commit_to_observation.timeout_rate, 1);
  assert.equal(report.phases.commit_to_observation.p99_ms, null);
  assert.ok(report.failures.some(({ code }) => code === "latency_samples_missing"));
  assert.ok(report.failures.some(({ code }) => code === "resource_data_missing"));
  assert.ok(report.failures.some(({ code }) => code === "timeout_rate_exceeded"));
});

test("rejects unsafe, non-finite, reversed, ambiguous, and labeled samples", () => {
  const recorder = createG41PropagationLatencyRecorder({ thresholds: thresholds() });
  const invalidSamples = [
    { latency_ms: Number.NaN, resource_snapshot: RESOURCES },
    { latency_ms: Number.POSITIVE_INFINITY, resource_snapshot: RESOURCES },
    { latency_ms: Number.MAX_SAFE_INTEGER + 1, resource_snapshot: RESOURCES },
    { committed_at_ms: 5, observed_at_ms: 4, resource_snapshot: RESOURCES },
    { latency_ms: 1, committed_at_ms: 1, observed_at_ms: 2, resource_snapshot: RESOURCES },
    { latency_ms: 1, tenant_id: "tenant-secret", resource_snapshot: RESOURCES },
    { latency_ms: 1, resource_snapshot: { ...RESOURCES, pool_waiters: -1 } },
    { latency_ms: 1, resource_snapshot: { ...RESOURCES, request_id: "request-secret" } }
  ];
  for (const sample of invalidSamples) {
    assert.throws(() => recorder.recordCommitToObservation(sample), G41PropagationQualificationError);
  }
  assert.deepEqual(G41_PROPAGATION_RESOURCE_KEYS, ["pool_connections", "pool_waiters", "in_flight_operations", "notification_reconnects"]);
});

test("bounds retained samples and records capacity failure without growing unbounded state", () => {
  const recorder = createG41PropagationLatencyRecorder({ thresholds: thresholds(), maxSamples: 2 });
  recorder.recordCommitToObservation({ latency_ms: 1, resource_snapshot: RESOURCES });
  recorder.recordCommitToAppliedAck({ latency_ms: 1, resource_snapshot: RESOURCES });
  assert.throws(() => recorder.recordCommitToObservation({ latency_ms: 1, resource_snapshot: RESOURCES }), { code: "sample_capacity_exceeded" });
  const report = recorder.report();
  assert.equal(report.accepted_samples, 2);
  assert.equal(report.capacity_exceeded, true);
  assert.equal(report.qualified, false);
  assert.ok(report.failures.some(({ code }) => code === "sample_capacity_exceeded"));
  assert.doesNotThrow(() => validateG41PropagationReport(report));
});

test("rejects an impossible qualification capacity and non-monotonic percentile evidence", () => {
  assert.throws(
    () => createG41PropagationLatencyRecorder({ thresholds: thresholds({ min_count: 2 }), maxSamples: 3 }),
    { code: "invalid_input" }
  );
  const report = buildG41PropagationReport({
    thresholds: thresholds(),
    samples: [
      { phase: "commit_to_observation", latency_ms: 1, resource_snapshot: RESOURCES },
      { phase: "commit_to_applied_ack", latency_ms: 2, resource_snapshot: RESOURCES }
    ]
  });
  const forged = structuredClone(report);
  forged.phases.commit_to_observation.p50_ms = 2;
  forged.phases.commit_to_observation.p95_ms = 1;
  assert.throws(() => validateG41PropagationReport(forged), { code: "invalid_input" });
});

test("validates canonical JSON and rejects forged or label-bearing reports", () => {
  const report = buildG41PropagationReport({
    thresholds: thresholds(),
    samples: [
      { phase: "commit_to_observation", latency_ms: 1, resource_snapshot: RESOURCES },
      { phase: "commit_to_applied_ack", latency_ms: 2, resource_snapshot: RESOURCES }
    ]
  });
  const json = serializeG41PropagationReport(report);
  assert.deepEqual(parseAndValidateG41PropagationReport(json), report);
  assert.throws(() => parseAndValidateG41PropagationReport(JSON.stringify(report)), { code: "noncanonical_json" });

  const forged = structuredClone(report);
  forged.qualified = false;
  assert.throws(() => validateG41PropagationReport(forged), { code: "invalid_input" });

  const labeled = structuredClone(report);
  labeled.request_labels = [];
  assert.throws(() => validateG41PropagationReport(labeled), { code: "unknown_field" });

  const inconsistentLimit = structuredClone(report);
  inconsistentLimit.limits.max_samples = 1;
  assert.throws(() => validateG41PropagationReport(inconsistentLimit), { code: "invalid_input" });
});
