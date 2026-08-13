import assert from "node:assert/strict";
import test from "node:test";

import {
  EXPECTED_POSTGRES_SCHEMA_VERSION,
  OPERATIONAL_METRIC_KEYS,
  createDrainController,
  createOperationalHealth,
  createOperationalMetrics
} from "../../src/postgres/operational-health.mjs";

const APPLIED = Object.freeze({
  applied: Array.from({ length: EXPECTED_POSTGRES_SCHEMA_VERSION }, (_, index) => ({ version: index + 1, checksum: "a".repeat(64) })),
  pending: [],
  modified: [],
  dirty: false
});

function pool(overrides = {}) {
  return { options: { max: 4 }, totalCount: 2, idleCount: 1, waitingCount: 0, async query() { return { rows: [{ ready: 1 }] }; }, ...overrides };
}

test("metrics are fixed-key, monotonic, and free of caller labels", () => {
  const metrics = createOperationalMetrics();
  metrics.recordLockWait();
  metrics.recordLockTimeout(2);
  metrics.recordReplayDenial();
  metrics.recordRateLimitDenial();
  metrics.recordStaleAck(3);
  metrics.recordAuditGap();
  metrics.recordRefreshWaiterRejection(2);
  metrics.recordRefreshWaiterCapacity();
  metrics.recordRefreshDeliveryFailure(3);
  metrics.recordRefreshNotificationReconnect();
  metrics.recordRefreshNotificationWakeFailure(2);
  metrics.recordRefreshPropagationObservation(4);
  metrics.recordRefreshPropagationTimeout();
  metrics.recordAgentSessionIssueSuccess();
  metrics.recordAgentSessionIssueReplay(2);
  metrics.recordAgentSessionIssueConflict();
  metrics.recordAgentSessionIssueFailure(3);
  metrics.recordAgentSessionIssueRollback();
  metrics.recordAgentSessionConsumeSuccess(2);
  metrics.recordAgentSessionConsumeReplay();
  metrics.recordAgentSessionConsumeConflict(3);
  metrics.recordAgentSessionConsumeStale();
  metrics.recordAgentSessionConsumeFailure(2);
  metrics.recordAgentSessionConsumeRollback();
  metrics.recordAgentSessionSignerSuccess(2);
  metrics.recordAgentSessionSignerFailure();
  metrics.recordAgentSessionSignerLatency(17);
  metrics.recordAgentSessionLifecycleExpired(3);
  metrics.recordAgentSessionLifecycleRevoked();
  metrics.recordCloudAuditAppend(2);
  metrics.recordCloudAuditFailure();
  const snapshot = metrics.snapshot();
  assert.deepEqual(Object.keys(snapshot), ["version", "counters", "valid"]);
  assert.deepEqual(Object.keys(snapshot.counters), OPERATIONAL_METRIC_KEYS);
  assert.equal(Object.isFrozen(snapshot), true);
  assert.equal(Object.isFrozen(snapshot.counters), true);
  assert.deepEqual(snapshot.counters, {
    lock_timeout_total: 2,
    lock_wait_total: 1,
    replay_denial_total: 1,
    rate_limit_denial_total: 1,
    stale_ack_total: 3,
    audit_gap_total: 1,
    refresh_waiter_rejection_total: 2,
    refresh_waiter_capacity_total: 1,
    refresh_delivery_failure_total: 3,
    refresh_notification_reconnect_total: 1,
    refresh_notification_wake_failure_total: 2,
    refresh_propagation_observation_total: 4,
    refresh_propagation_timeout_total: 1,
    agent_session_issue_success_total: 1,
    agent_session_issue_replay_total: 2,
    agent_session_issue_conflict_total: 1,
    agent_session_issue_failure_total: 3,
    agent_session_issue_rollback_total: 1,
    agent_session_consume_success_total: 2,
    agent_session_consume_replay_total: 1,
    agent_session_consume_conflict_total: 3,
    agent_session_consume_stale_total: 1,
    agent_session_consume_failure_total: 2,
    agent_session_consume_rollback_total: 1,
    agent_session_signer_success_total: 2,
    agent_session_signer_failure_total: 1,
    agent_session_signer_latency_count: 1,
    agent_session_signer_latency_total_ms: 17,
    agent_session_lifecycle_expired_total: 3,
    agent_session_lifecycle_revoked_total: 1,
    cloud_audit_append_total: 2,
    cloud_audit_failure_total: 1
  });
  assert.equal(JSON.stringify(snapshot).includes("tenant"), false);
  assert.throws(() => metrics.increment("tenant_id", 1), { code: "invalid_input" });
  assert.throws(() => metrics.recordAuditGap(-1), { code: "invalid_input" });
  assert.throws(() => metrics.recordAgentSessionIssueSuccess({ tenant_id: "tenant-a" }), { code: "invalid_input" });
  assert.throws(() => metrics.recordAgentSessionSignerLatency(1, { request_id: "request-a" }), { code: "invalid_input" });
});

test("refresh metrics are bounded fixed-key counters and never retain labels", () => {
  const metrics = createOperationalMetrics({
    initial: {
      refresh_delivery_failure_total: Number.MAX_SAFE_INTEGER - 1
    }
  });
  assert.equal(metrics.recordRefreshDeliveryFailure(10), Number.MAX_SAFE_INTEGER);
  assert.equal(metrics.recordRefreshDeliveryFailure(), Number.MAX_SAFE_INTEGER);
  assert.throws(() => metrics.recordRefreshWaiterRejection("tenant-a"), { code: "invalid_input" });
  assert.throws(() => createOperationalMetrics({ initial: { refresh_waiter_capacity_total: -1 } }), { code: "invalid_input" });
  const serialized = JSON.stringify(metrics.snapshot());
  assert.equal(serialized.includes("tenant-a"), false);
  assert.equal(serialized.includes("label"), false);
  assert.deepEqual(Object.keys(metrics.snapshot().counters), OPERATIONAL_METRIC_KEYS);
});

test("M2 signer latency is a bounded count and total without caller labels", () => {
  const metrics = createOperationalMetrics({
    initial: {
      agent_session_signer_latency_count: Number.MAX_SAFE_INTEGER - 1,
      agent_session_signer_latency_total_ms: Number.MAX_SAFE_INTEGER - 2,
      cloud_audit_append_total: Number.MAX_SAFE_INTEGER - 1
    }
  });
  assert.equal(metrics.recordAgentSessionSignerLatency(Number.MAX_SAFE_INTEGER), Number.MAX_SAFE_INTEGER);
  assert.equal(metrics.snapshot().counters.agent_session_signer_latency_count, Number.MAX_SAFE_INTEGER);
  assert.equal(metrics.snapshot().counters.agent_session_signer_latency_total_ms, Number.MAX_SAFE_INTEGER);
  assert.equal(metrics.recordCloudAuditAppend(10), Number.MAX_SAFE_INTEGER);
  for (const latency of [undefined, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY, "5", { milliseconds: 5 }]) {
    assert.throws(() => metrics.recordAgentSessionSignerLatency(latency), { code: "invalid_input" });
  }
  assert.deepEqual(Object.keys(metrics.snapshot().counters), OPERATIONAL_METRIC_KEYS);
  assert.equal(JSON.stringify(metrics.snapshot()).includes("request_id"), false);
});

test("readiness requires the exact schema version, verified checksums, a DB probe, and a non-waiting pool", async () => {
  const metrics = createOperationalMetrics();
  const drain = createDrainController();
  let probeCalls = 0;
  const health = createOperationalHealth({
    pool: pool(),
    metrics,
    drainController: drain,
    migrationStatus: async () => APPLIED,
    probe: async () => { probeCalls += 1; return true; }
  });
  const result = await health.readiness();
  assert.equal(result.version, 1);
  assert.equal(result.ready, true);
  assert.equal(result.status, "ready");
  assert.equal(result.code, "ready");
  assert.equal(result.checks.schema.applied_version, EXPECTED_POSTGRES_SCHEMA_VERSION);
  assert.equal(result.checks.schema.schema_version_status, "exact");
  assert.equal(result.checks.schema.checksum_status, "verified");
  assert.equal(result.checks.schema.drift, false);
  assert.deepEqual(result.checks.pool, {
    ok: true,
    max_connections: 4,
    total_connections: 2,
    idle_connections: 1,
    waiting_connections: 0,
    utilization_percent: 50,
    saturated: false
  });
  assert.equal(probeCalls, 1);

  const waiting = createOperationalHealth({
    pool: pool({ waitingCount: 1, totalCount: 4, idleCount: 0 }),
    drainController: createDrainController(),
    migrationStatus: async () => APPLIED,
    probe: async () => true
  });
  const waitingResult = await waiting.readiness();
  assert.equal(waitingResult.ready, false);
  assert.equal(waitingResult.code, "pool_saturated");
  assert.equal(waitingResult.checks.pool.waiting_connections, 1);
});

test("schema drift, DB failure, and malformed pool state fail closed without error details", async () => {
  const secretError = new Error("password=super-secret SELECT tenant_id");
  const health = createOperationalHealth({
    pool: pool({ totalCount: 5 }),
    drainController: createDrainController(),
    migrationStatus: async () => ({ ...APPLIED, modified: [4] }),
    probe: async () => { throw secretError; }
  });
  const result = await health.readiness();
  assert.equal(result.ready, false);
  assert.equal(result.code, "database_unavailable");
  assert.equal(result.checks.schema.checksum_status, "drift");
  assert.equal(JSON.stringify(result).includes("super-secret"), false);
  assert.equal(JSON.stringify(result).includes("tenant_id"), false);
  assert.equal(JSON.stringify(result).includes("SELECT"), false);

  const malformedSchema = createOperationalHealth({
    pool: pool(),
    drainController: createDrainController(),
    migrationStatus: async () => ({ ...APPLIED, applied: APPLIED.applied.slice(0, 11), pending: [12] }),
    probe: async () => true
  });
  const schemaResult = await malformedSchema.readiness();
  assert.equal(schemaResult.ready, false);
  assert.equal(schemaResult.code, "schema_version_mismatch");
  assert.equal(schemaResult.checks.schema.schema_version_status, "mismatch");
  assert.equal(schemaResult.checks.schema.applied_version, 11);

  const invalidPool = createOperationalHealth({
    pool: pool({ idleCount: 9 }),
    drainController: createDrainController(),
    migrationStatus: async () => APPLIED,
    probe: async () => true
  });
  const poolResult = await invalidPool.readiness();
  assert.equal(poolResult.ready, false);
  assert.equal(poolResult.code, "pool_saturated");
  assert.equal(poolResult.checks.pool.ok, false);

  const throwingPool = pool();
  Object.defineProperty(throwingPool, "waitingCount", { get() { throw new Error("secret sql state"); } });
  const throwing = createOperationalHealth({
    pool: throwingPool,
    drainController: createDrainController(),
    migrationStatus: () => { throw new Error("tenant=private"); },
    probe: () => { throw new Error("password=private"); }
  });
  const throwingResult = await throwing.readiness();
  assert.equal(throwingResult.ready, false);
  assert.equal(throwingResult.code, "database_unavailable");
  assert.equal(throwingResult.checks.schema.schema_version_status, "unknown");
  assert.equal(JSON.stringify(throwingResult).includes("private"), false);
});

test("drain rejects readiness immediately and waits for tracked work within the bound", async () => {
  const drain = createDrainController({ defaultTimeoutMs: 100, maxTimeoutMs: 200 });
  const release = drain.acquire();
  let probeCalls = 0;
  let migrationCalls = 0;
  let closed = false;
  const health = createOperationalHealth({
    pool: pool(),
    drainController: drain,
    migrationStatus: async () => { migrationCalls += 1; return APPLIED; },
    probe: async () => { probeCalls += 1; return true; }
  });

  drain.beginDrain();
  const immediate = await health.readiness();
  assert.equal(immediate.ready, false);
  assert.equal(immediate.status, "draining");
  assert.equal(immediate.code, "draining");
  assert.equal(immediate.checks.drain.in_flight, 1);
  assert.equal(probeCalls, 0);
  assert.equal(migrationCalls, 0);

  const draining = drain.drain({ timeoutMs: 100, close: async () => { closed = true; } });
  setTimeout(release, 5);
  const result = await draining;
  assert.deepEqual(result, { state: "closed", drained: true, in_flight: 0, timeout_ms: 100 });
  assert.equal(closed, true);
  assert.equal((await health.readiness()).code, "closed");
  assert.throws(() => drain.acquire(), { code: "draining" });
});

test("drain does not close storage when tracked work exceeds the bounded timeout", async () => {
  const drain = createDrainController({ defaultTimeoutMs: 5, maxTimeoutMs: 20 });
  const release = drain.acquire();
  let closed = false;
  const started = Date.now();
  const result = await drain.drain({ timeoutMs: 5, close: async () => { closed = true; } });
  assert.equal(result.state, "draining");
  assert.equal(result.drained, false);
  assert.equal(result.in_flight, 1);
  assert.equal(closed, false);
  assert.ok(Date.now() - started < 250);
  release();
});
