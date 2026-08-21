import assert from "node:assert/strict";
import test from "node:test";

import {
  EXPECTED_POSTGRES_SCHEMA_VERSION,
  OPERATIONAL_GAUGE_KEYS,
  OPERATIONAL_METRIC_KEYS,
  createDrainController,
  createOperationalHealth,
  createOperationalMetrics,
  HUMAN_RECOVERY_METRIC_KEYS,
  HUMAN_RECOVERY_OPERATIONS
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
  metrics.recordHumanAuthRateLimitDenial(2);
  metrics.recordHumanAuthRateLimitUnavailable();
  metrics.recordHumanAuthTenantDenial(3);
  metrics.recordHumanAuthReplayDenial(4);
  metrics.recordHumanAuthVerifierTimeout();
  metrics.recordHumanAuthStaleClaimRecovery(5);
  metrics.recordSharedControlMaintenanceCycle(2);
  metrics.recordSharedControlMaintenanceSuccess();
  metrics.recordSharedControlMaintenanceFailure(3);
  metrics.recordSharedControlMaintenanceRemoved(7);
  metrics.recordManagedSignerProviderOperationMaintenanceCycle(2);
  metrics.recordManagedSignerProviderOperationMaintenanceSuccess();
  metrics.recordManagedSignerProviderOperationMaintenanceFailure(3);
  metrics.recordManagedSignerProviderOperationMaintenanceQuarantined(5);
  metrics.recordManagedSignerProviderOperationMaintenanceReconciled(4);
  metrics.recordManagedSignerProviderOperationMaintenancePruned(6);
  metrics.recordAgentSessionSigningCapabilityMaintenanceCycle(2);
  metrics.recordAgentSessionSigningCapabilityMaintenanceSuccess();
  metrics.recordAgentSessionSigningCapabilityMaintenanceFailure(3);
  metrics.recordAgentSessionSigningCapabilityMaintenanceExpired(5);
  metrics.recordAgentSessionSigningCapabilityMaintenanceUncertain(4);
  for (const operation of Object.values(HUMAN_RECOVERY_OPERATIONS)) metrics.recordHumanRecoveryOperation(operation);
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
    cloud_audit_failure_total: 1,
    human_auth_rate_limit_denial_total: 2,
    human_auth_rate_limit_unavailable_total: 1,
    human_auth_tenant_denial_total: 3,
    human_auth_replay_denial_total: 4,
    human_auth_verifier_timeout_total: 1,
    human_auth_stale_claim_recovery_total: 5,
    shared_control_maintenance_cycle_total: 2,
    shared_control_maintenance_success_total: 1,
    shared_control_maintenance_failure_total: 3,
    shared_control_maintenance_removed_total: 7,
    managed_signer_provider_operation_maintenance_cycle_total: 2,
    managed_signer_provider_operation_maintenance_success_total: 1,
    managed_signer_provider_operation_maintenance_failure_total: 3,
    managed_signer_provider_operation_maintenance_quarantined_total: 5,
    managed_signer_provider_operation_maintenance_reconciled_total: 4,
    managed_signer_provider_operation_maintenance_pruned_total: 6,
    agent_session_signing_capability_maintenance_cycle_total: 2,
    agent_session_signing_capability_maintenance_success_total: 1,
    agent_session_signing_capability_maintenance_failure_total: 3,
    agent_session_signing_capability_maintenance_expired_total: 5,
    agent_session_signing_capability_maintenance_uncertain_total: 4,
    owner_recovery_outbox_claim_total: 0,
    owner_recovery_outbox_publish_total: 0,
    owner_recovery_outbox_retry_total: 0,
    owner_recovery_outbox_dead_letter_total: 0,
    owner_recovery_outbox_claim_lost_total: 0,
    owner_recovery_outbox_uncertain_total: 0,
    owner_recovery_outbox_failure_total: 0,
    owner_recovery_outbox_lag_count: 0,
    owner_recovery_outbox_lag_total_ms: 0,
    owner_recovery_outbox_suppression_total: 0,
    owner_recovery_outbox_redrive_success_total: 0,
    owner_recovery_outbox_redrive_failure_total: 0,
    owner_recovery_outbox_prune_total: 0,
    owner_recovery_outbox_prune_failure_total: 0,
    owner_recovery_outbox_confirmation_lookup_total: 0,
    owner_recovery_outbox_confirmation_success_total: 0,
    owner_recovery_outbox_confirmation_miss_total: 0,
    owner_recovery_outbox_confirmation_failure_total: 0,
    owner_recovery_state_latency_count: 0,
    owner_recovery_state_latency_total_ms: 0,
    human_recovery_create_total: 1,
    human_recovery_status_total: 1,
    human_recovery_approve_total: 1,
    human_recovery_cancel_total: 1,
    human_recovery_exchange_total: 1,
    human_recovery_registration_options_total: 1,
    human_recovery_registration_verify_total: 1,
    human_recovery_activate_total: 1
  });
  assert.doesNotMatch(JSON.stringify(snapshot), /tenant_id|organization_id|member_id|session_id|request_id/);
  assert.throws(() => metrics.increment("tenant_id", 1), { code: "invalid_input" });
  assert.throws(() => metrics.recordAuditGap(-1), { code: "invalid_input" });
  assert.throws(() => metrics.recordAgentSessionIssueSuccess({ tenant_id: "tenant-a" }), { code: "invalid_input" });
  assert.throws(() => metrics.recordAgentSessionSignerLatency(1, { request_id: "request-a" }), { code: "invalid_input" });
  assert.throws(() => metrics.recordManagedSignerProviderOperationMaintenanceQuarantined({ operation_id: "operation-a" }), { code: "invalid_input" });
  assert.throws(() => metrics.recordHumanRecoveryOperation("human.recovery.unknown"), { code: "invalid_input" });
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

test("W1 recovery operations are fixed-key counters and state latency is an aggregate", () => {
  const zeroLatency = createOperationalMetrics();
  assert.equal(zeroLatency.recordOwnerRecoveryStateLatency(0), 0);
  assert.equal(zeroLatency.snapshot().counters.owner_recovery_state_latency_count, 1);
  assert.equal(zeroLatency.snapshot().counters.owner_recovery_state_latency_total_ms, 0);

  const metrics = createOperationalMetrics({
    initial: {
      owner_recovery_outbox_suppression_total: Number.MAX_SAFE_INTEGER - 1,
      owner_recovery_outbox_redrive_success_total: Number.MAX_SAFE_INTEGER - 2,
      owner_recovery_outbox_redrive_failure_total: Number.MAX_SAFE_INTEGER - 3,
      owner_recovery_outbox_prune_total: Number.MAX_SAFE_INTEGER - 4,
      owner_recovery_outbox_prune_failure_total: Number.MAX_SAFE_INTEGER - 5,
      owner_recovery_state_latency_count: Number.MAX_SAFE_INTEGER - 1,
      owner_recovery_state_latency_total_ms: Number.MAX_SAFE_INTEGER - 2
    }
  });

  assert.equal(metrics.recordOwnerRecoveryOutboxSuppression(10), Number.MAX_SAFE_INTEGER);
  assert.equal(metrics.recordOwnerRecoveryOutboxRedriveSuccess(10), Number.MAX_SAFE_INTEGER);
  assert.equal(metrics.recordOwnerRecoveryOutboxRedriveFailure(10), Number.MAX_SAFE_INTEGER);
  assert.equal(metrics.recordOwnerRecoveryOutboxPrune(10), Number.MAX_SAFE_INTEGER);
  assert.equal(metrics.recordOwnerRecoveryOutboxPruneFailure(10), Number.MAX_SAFE_INTEGER);
  assert.equal(metrics.recordOwnerRecoveryStateLatency(Number.MAX_SAFE_INTEGER), Number.MAX_SAFE_INTEGER);
  assert.equal(metrics.snapshot().counters.owner_recovery_state_latency_count, Number.MAX_SAFE_INTEGER);
  assert.equal(metrics.snapshot().counters.owner_recovery_state_latency_total_ms, Number.MAX_SAFE_INTEGER);

  for (const latency of [undefined, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY, "5", { milliseconds: 5 }]) {
    assert.throws(() => metrics.recordOwnerRecoveryStateLatency(latency), { code: "invalid_input" });
  }
  for (const value of [0, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY, "1", { tenant_id: "tenant-a" }]) {
    assert.throws(() => metrics.recordOwnerRecoveryOutboxPrune(value), { code: "invalid_input" });
  }
  assert.equal(metrics.increment("owner_recovery_state_latency_total_ms", 1), Number.MAX_SAFE_INTEGER);
  assert.throws(() => metrics.increment("caller_defined_label_total", 1), { code: "invalid_input" });
  assert.doesNotMatch(JSON.stringify(metrics.snapshot()), /tenant_id|organization_id|member_id|request_id/);
  assert.deepEqual(Object.keys(metrics.snapshot().counters), OPERATIONAL_METRIC_KEYS);
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

test("owner recovery outbox readiness is aggregate-only and fails closed on dead letters, hard lag, or a stopped worker", async () => {
  const now = Date.parse("2026-08-14T00:15:00.000Z");
  let outbox = { pending: 0, uncertain: 0, dead_letter: 0, oldest_pending_at: null, oldest_uncertain_at: null, worker_state: "running" };
  const health = createOperationalHealth({
    pool: pool(),
    maxConnections: 4,
    migrationStatus: async () => APPLIED,
    metrics: createOperationalMetrics(),
    drainController: createDrainController(),
    probe: async () => true,
    outboxStatus: async () => outbox,
    outboxMaxPending: 10,
    outboxMaxLagMs: 60_000,
    now: () => now
  });
  let report = await health.readiness();
  assert.equal(report.ready, true);
  assert.deepEqual(report.checks.owner_recovery_outbox, { ok: true, code: "ok", worker_state: "running", pending_count: 0, uncertain_count: 0, dead_letter_count: 0, oldest_pending_age_ms: null, oldest_uncertain_age_ms: null });
  let operational = await health.operationalSnapshot();
  assert.equal(operational.valid, true);
  assert.deepEqual(Object.keys(operational.gauges), OPERATIONAL_GAUGE_KEYS);
  assert.deepEqual(operational.gauges, {
    owner_recovery_outbox_pending_count: 0,
    owner_recovery_outbox_uncertain_count: 0,
    owner_recovery_outbox_dead_letter_count: 0,
    owner_recovery_outbox_oldest_pending_age_ms: 0,
    owner_recovery_outbox_oldest_uncertain_age_ms: 0
  });

  outbox = { pending: 1, uncertain: 0, dead_letter: 1, oldest_pending_at: new Date(now - 1_000).toISOString(), oldest_uncertain_at: null, worker_state: "running", organization_id: "must-not-leak" };
  report = await health.readiness();
  assert.equal(report.code, "owner_recovery_outbox_dead_letter_present");
  assert.equal(JSON.stringify(report).includes("must-not-leak"), false);
  operational = await health.operationalSnapshot();
  assert.deepEqual(operational.gauges, {
    owner_recovery_outbox_pending_count: 1,
    owner_recovery_outbox_uncertain_count: 0,
    owner_recovery_outbox_dead_letter_count: 1,
    owner_recovery_outbox_oldest_pending_age_ms: 1_000,
    owner_recovery_outbox_oldest_uncertain_age_ms: 0
  });

  outbox = { pending: 0, uncertain: 1, dead_letter: 0, oldest_pending_at: null, oldest_uncertain_at: new Date(now - 5_000).toISOString(), worker_state: "running" };
  report = await health.readiness();
  assert.equal(report.ready, false);
  assert.equal(report.code, "owner_recovery_outbox_uncertain_delivery_present");
  assert.equal(report.checks.owner_recovery_outbox.uncertain_count, 1);
  assert.equal(report.checks.owner_recovery_outbox.oldest_uncertain_age_ms, 5_000);

  outbox = { pending: 1, uncertain: 0, dead_letter: 0, oldest_pending_at: new Date(now - 60_001).toISOString(), oldest_uncertain_at: null, worker_state: "running" };
  assert.equal((await health.readiness()).code, "owner_recovery_outbox_lag_exceeded");
  outbox = { pending: 0, uncertain: 0, dead_letter: 0, oldest_pending_at: null, oldest_uncertain_at: null, worker_state: "idle" };
  assert.equal((await health.readiness()).code, "owner_recovery_outbox_worker_unavailable");
  outbox = null;
  assert.equal((await health.readiness()).code, "owner_recovery_outbox_unavailable");
  assert.equal((await health.operationalSnapshot()).valid, false);
});

test("managed signer provider-operation readiness is deployment-wide, aggregate-only, and fail-closed", async () => {
  const current = Date.parse("2026-08-15T00:10:00.000Z");
  const base = {
    version: 1,
    states: { pending: 0, started: 0, accepted: 0, uncertain: 0, committed: 7, rejected: 0, failed: 0 },
    stale_started: 0,
    oldest_nonterminal_at: null,
    worker_state: "running",
    worker_cycles: 2,
    consecutive_failures: 0,
    last_success_at: current - 1_000
  };
  let status = base;
  const health = createOperationalHealth({
    pool: pool(),
    drainController: createDrainController(),
    migrationStatus: async () => APPLIED,
    probe: async () => true,
    providerOperationStatus: async () => status,
    now: () => current
  });

  let report = await health.readiness();
  assert.equal(report.ready, true);
  assert.deepEqual(report.checks.managed_signer_provider_operations, {
    ok: true,
    code: "ok",
    worker_state: "running",
    pending_count: 0,
    started_count: 0,
    accepted_count: 0,
    uncertain_count: 0,
    stale_started_count: 0,
    oldest_nonterminal_age_ms: null,
    last_success_age_ms: 1_000
  });

  status = { ...base, states: { ...base.states, uncertain: 1 }, oldest_nonterminal_at: new Date(current - 5_000).toISOString() };
  assert.equal((await health.readiness()).code, "managed_signer_provider_operations_uncertain_present");
  status = { ...base, states: { ...base.states, started: 1 }, stale_started: 1, oldest_nonterminal_at: new Date(current - 5_000).toISOString() };
  assert.equal((await health.readiness()).code, "managed_signer_provider_operations_stale_started");
  status = { ...base, states: { ...base.states, pending: 10_001 }, oldest_nonterminal_at: new Date(current - 5_000).toISOString() };
  assert.equal((await health.readiness()).code, "managed_signer_provider_operations_backlog_exceeded");
  status = { ...base, states: { ...base.states, pending: 1 }, oldest_nonterminal_at: new Date(current - 15 * 60_000 - 1).toISOString() };
  assert.equal((await health.readiness()).code, "managed_signer_provider_operations_lag_exceeded");
  status = { ...base, consecutive_failures: 1, last_success_at: null };
  assert.equal((await health.readiness()).code, "managed_signer_provider_operations_maintenance_failed");
  status = { ...base, last_success_at: current - 2 * 60_000 - 1 };
  assert.equal((await health.readiness()).code, "managed_signer_provider_operations_maintenance_stale");
  status = { ...base, worker_state: "idle", worker_cycles: 0, last_success_at: null };
  assert.equal((await health.readiness()).code, "managed_signer_provider_operations_worker_unavailable");
  status = { ...base, operation_id: "must-not-escape" };
  report = await health.readiness();
  assert.equal(report.code, "managed_signer_provider_operations_unavailable");
  assert.doesNotMatch(JSON.stringify(report), /must-not-escape|receipt|request_bytes|provider_diagnostic/u);
});

test("readiness returns a fixed failure within its application deadline when a provider never settles", async () => {
  const drain = createDrainController();
  const health = createOperationalHealth({
    pool: pool(),
    maxConnections: 10,
    migrationStatus: () => new Promise(() => {}),
    probe: () => new Promise(() => {}),
    metrics: createOperationalMetrics(),
    drainController: drain,
    readinessTimeoutMs: 10
  });
  const started = Date.now();
  const report = await health.readiness();
  assert.ok(Date.now() - started < 250);
  assert.equal(report.ready, false);
  assert.equal(report.code, "database_unavailable");
  assert.deepEqual(report.checks.database, { ok: false, probe: "failed" });
  assert.equal(report.checks.schema.checksum_status, "unknown");
  assert.doesNotMatch(JSON.stringify(report), /drain_timeout|Promise|stack|SELECT/u);
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
  assert.throws(() => drain.assertAccepting(), { code: "draining" });
});

test("drain close is shared and idempotent across concurrent and repeated callers", async () => {
  const drain = createDrainController({ defaultTimeoutMs: 100, maxTimeoutMs: 200 });
  const release = drain.acquire();
  let closeCalls = 0;
  const close = drain.drain({ timeoutMs: 100, close: async () => { closeCalls += 1; } });
  const concurrent = drain.drain({ timeoutMs: 100, close: async () => { closeCalls += 100; } });
  setTimeout(release, 5);
  const first = await close;
  assert.deepEqual(await concurrent, first);
  const second = await drain.drain({ timeoutMs: 100, close: async () => { closeCalls += 1000; } });
  assert.deepEqual(second, first);
  assert.equal(closeCalls, 1);
  assert.throws(() => drain.assertAccepting(), { code: "draining" });
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
