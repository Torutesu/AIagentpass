import { POSTGRES_SCHEMA_HEAD, POSTGRES_SCHEMA_HEAD_SOURCE_VERSION } from "./schema-head.mjs";

export const OPERATIONAL_HEALTH_VERSION = 1;
// Backwards-compatible export for adapters; the value is derived from the
// catalog/files source at module load and is never maintained independently.
export const EXPECTED_POSTGRES_SCHEMA_VERSION = POSTGRES_SCHEMA_HEAD.version;

// Recovery operations are deliberately a closed set.  These names are also
// the admission-control names used by human-auth/rate-limit.mjs; keeping the
// vocabulary here makes the exported metrics contract independently useful to
// health reporters and metric adapters.
export const HUMAN_RECOVERY_OPERATIONS = Object.freeze({
  create: "human.recovery.create",
  status: "human.recovery.status",
  approve: "human.recovery.approve",
  cancel: "human.recovery.cancel",
  exchange: "human.recovery.exchange",
  registrationOptions: "human.recovery.registration.options",
  registrationVerify: "human.recovery.registration.verify",
  activate: "human.recovery.activate"
});

export const HUMAN_RECOVERY_METRIC_KEYS = Object.freeze({
  [HUMAN_RECOVERY_OPERATIONS.create]: "human_recovery_create_total",
  [HUMAN_RECOVERY_OPERATIONS.status]: "human_recovery_status_total",
  [HUMAN_RECOVERY_OPERATIONS.approve]: "human_recovery_approve_total",
  [HUMAN_RECOVERY_OPERATIONS.cancel]: "human_recovery_cancel_total",
  [HUMAN_RECOVERY_OPERATIONS.exchange]: "human_recovery_exchange_total",
  [HUMAN_RECOVERY_OPERATIONS.registrationOptions]: "human_recovery_registration_options_total",
  [HUMAN_RECOVERY_OPERATIONS.registrationVerify]: "human_recovery_registration_verify_total",
  [HUMAN_RECOVERY_OPERATIONS.activate]: "human_recovery_activate_total"
});

export const OPERATIONAL_METRIC_KEYS = Object.freeze([
  "lock_timeout_total",
  "lock_wait_total",
  "replay_denial_total",
  "rate_limit_denial_total",
  "stale_ack_total",
  "audit_gap_total",
  "refresh_waiter_rejection_total",
  "refresh_waiter_capacity_total",
  "refresh_delivery_failure_total",
  "refresh_notification_reconnect_total",
  "refresh_notification_wake_failure_total",
  "refresh_propagation_observation_total",
  "refresh_propagation_timeout_total",
  "agent_session_issue_success_total",
  "agent_session_issue_replay_total",
  "agent_session_issue_conflict_total",
  "agent_session_issue_failure_total",
  "agent_session_issue_rollback_total",
  "agent_session_consume_success_total",
  "agent_session_consume_replay_total",
  "agent_session_consume_conflict_total",
  "agent_session_consume_stale_total",
  "agent_session_consume_failure_total",
  "agent_session_consume_rollback_total",
  "agent_session_signer_success_total",
  "agent_session_signer_failure_total",
  "agent_session_signer_latency_count",
  "agent_session_signer_latency_total_ms",
  "agent_session_lifecycle_expired_total",
  "agent_session_lifecycle_revoked_total",
  "cloud_audit_append_total",
  "cloud_audit_failure_total",
  "human_auth_rate_limit_denial_total",
  "human_auth_rate_limit_unavailable_total",
  "human_auth_tenant_denial_total",
  "human_auth_replay_denial_total",
  "human_auth_verifier_timeout_total",
  "human_auth_stale_claim_recovery_total",
  "shared_control_maintenance_cycle_total",
  "shared_control_maintenance_success_total",
  "shared_control_maintenance_failure_total",
  "shared_control_maintenance_removed_total",
  "managed_signer_provider_operation_maintenance_cycle_total",
  "managed_signer_provider_operation_maintenance_success_total",
  "managed_signer_provider_operation_maintenance_failure_total",
  "managed_signer_provider_operation_maintenance_quarantined_total",
  "managed_signer_provider_operation_maintenance_reconciled_total",
  "managed_signer_provider_operation_maintenance_pruned_total",
  "owner_recovery_outbox_claim_total",
  "owner_recovery_outbox_publish_total",
  "owner_recovery_outbox_retry_total",
  "owner_recovery_outbox_dead_letter_total",
  "owner_recovery_outbox_claim_lost_total",
  "owner_recovery_outbox_uncertain_total",
  "owner_recovery_outbox_failure_total",
  "owner_recovery_outbox_lag_count",
  "owner_recovery_outbox_lag_total_ms",
  "owner_recovery_outbox_suppression_total",
  "owner_recovery_outbox_redrive_success_total",
  "owner_recovery_outbox_redrive_failure_total",
  "owner_recovery_outbox_prune_total",
  "owner_recovery_outbox_prune_failure_total",
  "owner_recovery_outbox_confirmation_lookup_total",
  "owner_recovery_outbox_confirmation_success_total",
  "owner_recovery_outbox_confirmation_miss_total",
  "owner_recovery_outbox_confirmation_failure_total",
  "owner_recovery_state_latency_count",
  "owner_recovery_state_latency_total_ms",
  ...Object.values(HUMAN_RECOVERY_METRIC_KEYS)
]);

export const OPERATIONAL_GAUGE_KEYS = Object.freeze([
  "owner_recovery_outbox_pending_count",
  "owner_recovery_outbox_uncertain_count",
  "owner_recovery_outbox_dead_letter_count",
  "owner_recovery_outbox_oldest_pending_age_ms",
  "owner_recovery_outbox_oldest_uncertain_age_ms"
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
    counters[key] = boundedAdd(counters[key], value);
    return counters[key];
  }

  function recordSignerLatency(milliseconds) {
    if (arguments.length !== 1 || !Number.isSafeInteger(milliseconds) || milliseconds < 0) throw invalidOperationalInput();
    counters.agent_session_signer_latency_count = boundedAdd(counters.agent_session_signer_latency_count, 1);
    counters.agent_session_signer_latency_total_ms = boundedAdd(counters.agent_session_signer_latency_total_ms, milliseconds);
    return counters.agent_session_signer_latency_total_ms;
  }

  function recordOwnerRecoveryOutboxLag(milliseconds) {
    if (arguments.length !== 1 || !Number.isSafeInteger(milliseconds) || milliseconds < 0) throw invalidOperationalInput();
    counters.owner_recovery_outbox_lag_count = boundedAdd(counters.owner_recovery_outbox_lag_count, 1);
    counters.owner_recovery_outbox_lag_total_ms = boundedAdd(counters.owner_recovery_outbox_lag_total_ms, milliseconds);
    return counters.owner_recovery_outbox_lag_total_ms;
  }

  function recordOwnerRecoveryStateLatency(milliseconds) {
    if (arguments.length !== 1 || !Number.isSafeInteger(milliseconds) || milliseconds < 0) throw invalidOperationalInput();
    counters.owner_recovery_state_latency_count = boundedAdd(counters.owner_recovery_state_latency_count, 1);
    counters.owner_recovery_state_latency_total_ms = boundedAdd(counters.owner_recovery_state_latency_total_ms, milliseconds);
    return counters.owner_recovery_state_latency_total_ms;
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
    recordRefreshWaiterRejection: (amount = 1) => increment("refresh_waiter_rejection_total", amount),
    recordRefreshWaiterCapacity: (amount = 1) => increment("refresh_waiter_capacity_total", amount),
    recordRefreshDeliveryFailure: (amount = 1) => increment("refresh_delivery_failure_total", amount),
    recordRefreshNotificationReconnect: (amount = 1) => increment("refresh_notification_reconnect_total", amount),
    recordRefreshNotificationWakeFailure: (amount = 1) => increment("refresh_notification_wake_failure_total", amount),
    recordRefreshPropagationObservation: (amount = 1) => increment("refresh_propagation_observation_total", amount),
    recordRefreshPropagationTimeout: (amount = 1) => increment("refresh_propagation_timeout_total", amount),
    recordAgentSessionIssueSuccess: (amount = 1) => increment("agent_session_issue_success_total", amount),
    recordAgentSessionIssueReplay: (amount = 1) => increment("agent_session_issue_replay_total", amount),
    recordAgentSessionIssueConflict: (amount = 1) => increment("agent_session_issue_conflict_total", amount),
    recordAgentSessionIssueFailure: (amount = 1) => increment("agent_session_issue_failure_total", amount),
    recordAgentSessionIssueRollback: (amount = 1) => increment("agent_session_issue_rollback_total", amount),
    recordAgentSessionConsumeSuccess: (amount = 1) => increment("agent_session_consume_success_total", amount),
    recordAgentSessionConsumeReplay: (amount = 1) => increment("agent_session_consume_replay_total", amount),
    recordAgentSessionConsumeConflict: (amount = 1) => increment("agent_session_consume_conflict_total", amount),
    recordAgentSessionConsumeStale: (amount = 1) => increment("agent_session_consume_stale_total", amount),
    recordAgentSessionConsumeFailure: (amount = 1) => increment("agent_session_consume_failure_total", amount),
    recordAgentSessionConsumeRollback: (amount = 1) => increment("agent_session_consume_rollback_total", amount),
    recordAgentSessionSignerSuccess: (amount = 1) => increment("agent_session_signer_success_total", amount),
    recordAgentSessionSignerFailure: (amount = 1) => increment("agent_session_signer_failure_total", amount),
    recordAgentSessionSignerLatency: recordSignerLatency,
    recordAgentSessionLifecycleExpired: (amount = 1) => increment("agent_session_lifecycle_expired_total", amount),
    recordAgentSessionLifecycleRevoked: (amount = 1) => increment("agent_session_lifecycle_revoked_total", amount),
    recordCloudAuditAppend: (amount = 1) => increment("cloud_audit_append_total", amount),
    recordCloudAuditFailure: (amount = 1) => increment("cloud_audit_failure_total", amount),
    recordHumanAuthRateLimitDenial: (amount = 1) => increment("human_auth_rate_limit_denial_total", amount),
    recordHumanAuthRateLimitUnavailable: (amount = 1) => increment("human_auth_rate_limit_unavailable_total", amount),
    recordHumanAuthTenantDenial: (amount = 1) => increment("human_auth_tenant_denial_total", amount),
    recordHumanAuthReplayDenial: (amount = 1) => increment("human_auth_replay_denial_total", amount),
    recordHumanAuthVerifierTimeout: (amount = 1) => increment("human_auth_verifier_timeout_total", amount),
    recordHumanAuthStaleClaimRecovery: (amount = 1) => increment("human_auth_stale_claim_recovery_total", amount),
    recordSharedControlMaintenanceCycle: (amount = 1) => increment("shared_control_maintenance_cycle_total", amount),
    recordSharedControlMaintenanceSuccess: (amount = 1) => increment("shared_control_maintenance_success_total", amount),
    recordSharedControlMaintenanceFailure: (amount = 1) => increment("shared_control_maintenance_failure_total", amount),
    recordSharedControlMaintenanceRemoved: (amount = 1) => increment("shared_control_maintenance_removed_total", amount),
    recordManagedSignerProviderOperationMaintenanceCycle: (amount = 1) => increment("managed_signer_provider_operation_maintenance_cycle_total", amount),
    recordManagedSignerProviderOperationMaintenanceSuccess: (amount = 1) => increment("managed_signer_provider_operation_maintenance_success_total", amount),
    recordManagedSignerProviderOperationMaintenanceFailure: (amount = 1) => increment("managed_signer_provider_operation_maintenance_failure_total", amount),
    recordManagedSignerProviderOperationMaintenanceQuarantined: (amount = 1) => increment("managed_signer_provider_operation_maintenance_quarantined_total", amount),
    recordManagedSignerProviderOperationMaintenanceReconciled: (amount = 1) => increment("managed_signer_provider_operation_maintenance_reconciled_total", amount),
    recordManagedSignerProviderOperationMaintenancePruned: (amount = 1) => increment("managed_signer_provider_operation_maintenance_pruned_total", amount),
    recordOwnerRecoveryOutboxClaim: (amount = 1) => increment("owner_recovery_outbox_claim_total", amount),
    recordOwnerRecoveryOutboxPublish: (amount = 1) => increment("owner_recovery_outbox_publish_total", amount),
    recordOwnerRecoveryOutboxRetry: (amount = 1) => increment("owner_recovery_outbox_retry_total", amount),
    recordOwnerRecoveryOutboxDeadLetter: (amount = 1) => increment("owner_recovery_outbox_dead_letter_total", amount),
    recordOwnerRecoveryOutboxClaimLost: (amount = 1) => increment("owner_recovery_outbox_claim_lost_total", amount),
    recordOwnerRecoveryOutboxUncertain: (amount = 1) => increment("owner_recovery_outbox_uncertain_total", amount),
    recordOwnerRecoveryOutboxFailure: (amount = 1) => increment("owner_recovery_outbox_failure_total", amount),
    recordOwnerRecoveryOutboxLag,
    recordOwnerRecoveryOutboxSuppression: (amount = 1) => increment("owner_recovery_outbox_suppression_total", amount),
    recordOwnerRecoveryOutboxRedriveSuccess: (amount = 1) => increment("owner_recovery_outbox_redrive_success_total", amount),
    recordOwnerRecoveryOutboxRedriveFailure: (amount = 1) => increment("owner_recovery_outbox_redrive_failure_total", amount),
    recordOwnerRecoveryOutboxPrune: (amount = 1) => increment("owner_recovery_outbox_prune_total", amount),
    recordOwnerRecoveryOutboxPruneFailure: (amount = 1) => increment("owner_recovery_outbox_prune_failure_total", amount),
    recordOwnerRecoveryOutboxConfirmationLookup: (amount = 1) => increment("owner_recovery_outbox_confirmation_lookup_total", amount),
    recordOwnerRecoveryOutboxConfirmationSuccess: (amount = 1) => increment("owner_recovery_outbox_confirmation_success_total", amount),
    recordOwnerRecoveryOutboxConfirmationMiss: (amount = 1) => increment("owner_recovery_outbox_confirmation_miss_total", amount),
    recordOwnerRecoveryOutboxConfirmationFailure: (amount = 1) => increment("owner_recovery_outbox_confirmation_failure_total", amount),
    recordOwnerRecoveryStateLatency,
    recordHumanRecoveryOperation: (operation, amount = 1) => {
      const key = HUMAN_RECOVERY_METRIC_KEYS[operation];
      if (!key) throw invalidOperationalInput();
      return increment(key, amount);
    },
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

  // Signing boundaries use the same deployment-wide admission state as HTTP
  // work.  A checkpoint is intentionally synchronous so a caller can place it
  // immediately before a durable reservation or an external provider call.
  // The state can change while an awaited database operation is in flight;
  // callers must checkpoint again after every such boundary.
  function assertAccepting() {
    if (state !== "running") throw new DrainRejectedError();
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
    assertAccepting,
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
  schemaHead = POSTGRES_SCHEMA_HEAD,
  expectedSchemaVersion = schemaHead?.version,
  maxConnections,
  metrics = createOperationalMetrics(),
  drainController,
  probe = defaultProbe,
  outboxStatus,
  outboxMaxPending = 10_000,
  outboxMaxLagMs = 15 * 60_000,
  providerOperationStatus,
  providerOperationMaxBacklog = 10_000,
  providerOperationMaxLagMs = 15 * 60_000,
  providerOperationMaxMaintenanceAgeMs = 2 * 60_000,
  readinessTimeoutMs = 5_000,
  now = () => Date.now()
} = {}) {
  if (!pool || typeof pool !== "object") throw invalidOperationalInput();
  if (typeof migrationStatus !== "function" || typeof probe !== "function") throw invalidOperationalInput();
  if (!schemaHead || typeof schemaHead !== "object" || Array.isArray(schemaHead)
    || schemaHead.schema_version !== POSTGRES_SCHEMA_HEAD_SOURCE_VERSION
    || !Number.isSafeInteger(schemaHead.version) || schemaHead.version < 1
    || !Number.isSafeInteger(schemaHead.migration_count) || schemaHead.migration_count !== schemaHead.version
    || !Number.isSafeInteger(expectedSchemaVersion) || expectedSchemaVersion !== schemaHead.version) throw invalidOperationalInput();
  if (!metrics || typeof metrics.snapshot !== "function") throw invalidOperationalInput();
  if (!drainController || typeof drainController.snapshot !== "function") throw invalidOperationalInput();
  if (outboxStatus !== undefined && typeof outboxStatus !== "function") throw invalidOperationalInput();
  if (providerOperationStatus !== undefined && typeof providerOperationStatus !== "function") throw invalidOperationalInput();
  if (!Number.isSafeInteger(outboxMaxPending) || outboxMaxPending < 0 || outboxMaxPending > 1_000_000 || !Number.isSafeInteger(outboxMaxLagMs) || outboxMaxLagMs < 1_000 || outboxMaxLagMs > 24 * 60 * 60_000 || !Number.isSafeInteger(providerOperationMaxBacklog) || providerOperationMaxBacklog < 0 || providerOperationMaxBacklog > 1_000_000 || !Number.isSafeInteger(providerOperationMaxLagMs) || providerOperationMaxLagMs < 1_000 || providerOperationMaxLagMs > 24 * 60 * 60_000 || !Number.isSafeInteger(providerOperationMaxMaintenanceAgeMs) || providerOperationMaxMaintenanceAgeMs < 1_000 || providerOperationMaxMaintenanceAgeMs > 24 * 60 * 60_000 || !Number.isSafeInteger(readinessTimeoutMs) || readinessTimeoutMs < 10 || readinessTimeoutMs > 30_000 || typeof now !== "function") throw invalidOperationalInput();
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
        ...(outboxStatus === undefined ? {} : { outbox: skippedOutbox("draining") }),
        ...(providerOperationStatus === undefined ? {} : { providerOperations: skippedProviderOperations("draining") }),
        metrics: metricSnapshot
      });
    }

    const [databaseResult, migrationResult, outboxResult, providerOperationResult] = await Promise.allSettled([
      withTimeout(Promise.resolve().then(() => probe(pool)), readinessTimeoutMs),
      withTimeout(Promise.resolve().then(() => migrationStatus()), readinessTimeoutMs),
      outboxStatus === undefined ? Promise.resolve(undefined) : withTimeout(Promise.resolve().then(() => outboxStatus()), readinessTimeoutMs),
      providerOperationStatus === undefined ? Promise.resolve(undefined) : withTimeout(Promise.resolve().then(() => providerOperationStatus()), readinessTimeoutMs)
    ]);
    recordObservedLockWaits(metrics, databaseResult);
    const database = normalizeProbeResult(databaseResult);
    const schema = normalizeSchemaResult(migrationResult, expectedSchemaVersion);
    const outbox = outboxStatus === undefined ? undefined : normalizeOutboxResult(outboxResult, { outboxMaxPending, outboxMaxLagMs, now });
    const providerOperations = providerOperationStatus === undefined ? undefined : normalizeProviderOperationResult(providerOperationResult, { providerOperationMaxBacklog, providerOperationMaxLagMs, providerOperationMaxMaintenanceAgeMs, now });
    const poolReady = poolCheck.ok;
    const metricsReady = metricSnapshot.valid !== false;
    const ready = database.ok && schema.ok && poolReady && metricsReady && (outbox === undefined || outbox.ok) && (providerOperations === undefined || providerOperations.ok);
    const code = ready ? "ready" : firstFailureCode({ database, schema, pool: poolCheck, metricsReady, outbox, providerOperations });
    return contract({
      ready,
      status: ready ? "ready" : "not_ready",
      code,
      database,
      schema,
      pool: poolCheck,
      drain,
      ...(outbox === undefined ? {} : { outbox }),
      ...(providerOperations === undefined ? {} : { providerOperations }),
      metrics: metricSnapshot
    });
  }

  async function operationalSnapshot() {
    const counterSnapshot = safeMetricSnapshot(metrics);
    if (outboxStatus === undefined) return counterSnapshot;
    const result = await Promise.allSettled([
      withTimeout(Promise.resolve().then(() => outboxStatus()), readinessTimeoutMs)
    ]);
    const outbox = normalizeOutboxResult(result[0], { outboxMaxPending, outboxMaxLagMs, now });
    const gauges = outboxGauges(outbox);
    if (gauges === null) return Object.freeze({ ...counterSnapshot, valid: false });
    return Object.freeze({ ...counterSnapshot, gauges });
  }

  return Object.freeze({ readiness, health: readiness, operationalSnapshot });
}

function contract({ ready, status, code, database, schema, pool, drain, outbox, providerOperations, metrics }) {
  return Object.freeze({
    version: OPERATIONAL_HEALTH_VERSION,
    ready: Boolean(ready),
    status,
    code,
    checks: Object.freeze({ database, schema, pool, drain, ...(outbox === undefined ? {} : { owner_recovery_outbox: outbox }), ...(providerOperations === undefined ? {} : { managed_signer_provider_operations: providerOperations }) }),
    metrics
  });
}

function normalizeOutboxResult(result, { outboxMaxPending, outboxMaxLagMs, now }) {
  if (result.status !== "fulfilled" || !result.value || typeof result.value !== "object" || Array.isArray(result.value)) return skippedOutbox("unavailable");
  const value = result.value;
  const pending = Number(value.pending);
  const uncertain = Number(value.uncertain);
  const deadLetter = Number(value.dead_letter);
  const workerState = value.worker_state;
  let current;
  try { current = Number(now()); } catch { return skippedOutbox("unavailable"); }
  if (!Number.isSafeInteger(pending) || pending < 0 || !Number.isSafeInteger(uncertain) || uncertain < 0 || !Number.isSafeInteger(deadLetter) || deadLetter < 0 || !["running", "idle", "draining", "closed"].includes(workerState) || !Number.isSafeInteger(current) || current < 0) return skippedOutbox("unavailable");
  let oldestPendingAgeMs = null;
  if (value.oldest_pending_at !== null) {
    const oldest = Date.parse(String(value.oldest_pending_at));
    if (!Number.isFinite(oldest) || oldest > current) return skippedOutbox("unavailable");
    oldestPendingAgeMs = Math.min(Number.MAX_SAFE_INTEGER, current - oldest);
  } else if (pending !== 0) return skippedOutbox("unavailable");
  let oldestUncertainAgeMs = null;
  if (value.oldest_uncertain_at !== null) {
    const oldest = Date.parse(String(value.oldest_uncertain_at));
    if (!Number.isFinite(oldest) || oldest > current) return skippedOutbox("unavailable");
    oldestUncertainAgeMs = Math.min(Number.MAX_SAFE_INTEGER, current - oldest);
  } else if (uncertain !== 0) return skippedOutbox("unavailable");
  const code = workerState !== "running"
    ? "worker_unavailable"
    : uncertain > 0
      ? "uncertain_delivery_present"
      : deadLetter > 0
      ? "dead_letter_present"
      : pending > outboxMaxPending
        ? "backlog_exceeded"
        : oldestPendingAgeMs !== null && oldestPendingAgeMs > outboxMaxLagMs
          ? "lag_exceeded"
          : "ok";
  return Object.freeze({ ok: code === "ok", code, worker_state: workerState, pending_count: pending, uncertain_count: uncertain, dead_letter_count: deadLetter, oldest_pending_age_ms: oldestPendingAgeMs, oldest_uncertain_age_ms: oldestUncertainAgeMs });
}

function skippedOutbox(code) {
  return Object.freeze({ ok: false, code, worker_state: code === "draining" ? "draining" : "unavailable", pending_count: null, uncertain_count: null, dead_letter_count: null, oldest_pending_age_ms: null, oldest_uncertain_age_ms: null });
}

function outboxGauges(outbox) {
  if (!outbox || !Number.isSafeInteger(outbox.pending_count) || outbox.pending_count < 0
    || !Number.isSafeInteger(outbox.uncertain_count) || outbox.uncertain_count < 0
    || !Number.isSafeInteger(outbox.dead_letter_count) || outbox.dead_letter_count < 0) return null;
  const pendingAge = outbox.oldest_pending_age_ms === null && outbox.pending_count === 0 ? 0 : outbox.oldest_pending_age_ms;
  const uncertainAge = outbox.oldest_uncertain_age_ms === null && outbox.uncertain_count === 0 ? 0 : outbox.oldest_uncertain_age_ms;
  if (!Number.isSafeInteger(pendingAge) || pendingAge < 0 || !Number.isSafeInteger(uncertainAge) || uncertainAge < 0) return null;
  return Object.freeze({
    owner_recovery_outbox_pending_count: outbox.pending_count,
    owner_recovery_outbox_uncertain_count: outbox.uncertain_count,
    owner_recovery_outbox_dead_letter_count: outbox.dead_letter_count,
    owner_recovery_outbox_oldest_pending_age_ms: pendingAge,
    owner_recovery_outbox_oldest_uncertain_age_ms: uncertainAge
  });
}

function normalizeProviderOperationResult(result, { providerOperationMaxBacklog, providerOperationMaxLagMs, providerOperationMaxMaintenanceAgeMs, now }) {
  if (result.status !== "fulfilled" || !plainHealthObject(result.value)) return skippedProviderOperations("unavailable");
  const value = result.value;
  const states = value.states;
  const stateNames = ["pending", "started", "accepted", "uncertain", "committed", "rejected", "failed"];
  const rootNames = ["version", "states", "stale_started", "oldest_nonterminal_at", "worker_state", "worker_cycles", "consecutive_failures", "last_success_at"];
  if (Reflect.ownKeys(value).length !== rootNames.length || !rootNames.every((field) => Object.hasOwn(value, field))
    || value.version !== 1 || !plainHealthObject(states) || Reflect.ownKeys(states).length !== stateNames.length
    || !stateNames.every((state) => Object.hasOwn(states, state) && Number.isSafeInteger(states[state]) && states[state] >= 0)
    || !Number.isSafeInteger(value.stale_started) || value.stale_started < 0
    || !["running", "idle", "closing", "closed"].includes(value.worker_state)
    || !Number.isSafeInteger(value.worker_cycles) || value.worker_cycles < 0
    || !Number.isSafeInteger(value.consecutive_failures) || value.consecutive_failures < 0) return skippedProviderOperations("unavailable");
  let current;
  try { current = Number(now()); } catch { return skippedProviderOperations("unavailable"); }
  if (!Number.isSafeInteger(current) || current < 0) return skippedProviderOperations("unavailable");
  const nonterminal = states.pending + states.started + states.accepted + states.uncertain;
  if (!Number.isSafeInteger(nonterminal)) return skippedProviderOperations("unavailable");
  const oldestNonterminalAgeMs = ageFromTimestamp(value.oldest_nonterminal_at, nonterminal, current);
  const lastSuccessAgeMs = ageFromEpoch(value.last_success_at, current);
  if (oldestNonterminalAgeMs === undefined || lastSuccessAgeMs === undefined) return skippedProviderOperations("unavailable");
  const code = value.worker_state !== "running"
    ? "worker_unavailable"
    : value.consecutive_failures > 0
      ? "maintenance_failed"
      : states.uncertain > 0
        ? "uncertain_present"
        : value.stale_started > 0
          ? "stale_started"
          : nonterminal > providerOperationMaxBacklog
            ? "backlog_exceeded"
            : oldestNonterminalAgeMs !== null && oldestNonterminalAgeMs > providerOperationMaxLagMs
              ? "lag_exceeded"
              : lastSuccessAgeMs === null || lastSuccessAgeMs > providerOperationMaxMaintenanceAgeMs
                ? "maintenance_stale"
                : "ok";
  return Object.freeze({
    ok: code === "ok",
    code,
    worker_state: value.worker_state,
    pending_count: states.pending,
    started_count: states.started,
    accepted_count: states.accepted,
    uncertain_count: states.uncertain,
    stale_started_count: value.stale_started,
    oldest_nonterminal_age_ms: oldestNonterminalAgeMs,
    last_success_age_ms: lastSuccessAgeMs
  });
}

function skippedProviderOperations(code) {
  return Object.freeze({
    ok: false,
    code,
    worker_state: code === "draining" ? "closing" : "unavailable",
    pending_count: null,
    started_count: null,
    accepted_count: null,
    uncertain_count: null,
    stale_started_count: null,
    oldest_nonterminal_age_ms: null,
    last_success_age_ms: null
  });
}

function ageFromTimestamp(value, count, current) {
  if (value === null) return count === 0 ? null : undefined;
  const timestamp = Date.parse(String(value));
  if (!Number.isFinite(timestamp) || timestamp > current) return undefined;
  return Math.min(Number.MAX_SAFE_INTEGER, current - timestamp);
}

function ageFromEpoch(value, current) {
  if (value === null) return null;
  if (!Number.isSafeInteger(value) || value < 0 || value > current) return undefined;
  return current - value;
}

function plainHealthObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
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

function firstFailureCode({ database, schema, pool, metricsReady, outbox, providerOperations }) {
  if (!database.ok) return "database_unavailable";
  if (!schema.ok) {
    if (schema.checksum_status === "drift") return "migration_drift";
    if (schema.schema_version_status === "mismatch" || schema.checksum_status === "pending") return "schema_version_mismatch";
    return "schema_unverified";
  }
  if (!pool.ok) return "pool_saturated";
  if (!metricsReady) return "metrics_unavailable";
  if (outbox && !outbox.ok) return `owner_recovery_outbox_${outbox.code}`;
  if (providerOperations && !providerOperations.ok) return `managed_signer_provider_operations_${providerOperations.code}`;
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

function boundedAdd(current, amount) {
  return current >= MAX_COUNTER - amount ? MAX_COUNTER : current + amount;
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
