/**
 * Zero-dependency operational alert evaluator for AgentPass Cloud API.
 *
 * Evaluates fixed alert rules against the existing metrics snapshot.
 * Every alert name, severity, and message is from a closed frozen set.
 * No caller-supplied value, identifier, or diagnostic is interpolated.
 *
 * Alert evaluation is non-authoritative: failures produce a degraded
 * response but never alter authorization or API behavior.
 */

/**
 * Fixed alert definitions.  Each alert has a deterministic name, severity,
 * fixed human-readable message, and an evaluation function that receives
 * the metrics snapshot.  The evaluation function returns true when the
 * alert should fire.
 */
const ALERT_DEFINITIONS = Object.freeze([
  {
    name: "replay_denial_detected",
    severity: "critical",
    code: "replay_denial_detected",
    message: "Authentication replay denial detected",
    evaluate: (counters) => safeCounter(counters.replay_denial_total) > 0
  },
  {
    name: "lock_timeout_detected",
    severity: "warning",
    code: "lock_timeout_detected",
    message: "Database lock timeout detected",
    evaluate: (counters) => safeCounter(counters.lock_timeout_total) > 0
  },
  {
    name: "signer_failure_detected",
    severity: "critical",
    code: "signer_failure_detected",
    message: "Agent session signer failure detected",
    evaluate: (counters) => safeCounter(counters.agent_session_signer_failure_total) > 0
  },
  {
    name: "audit_gap_detected",
    severity: "critical",
    code: "audit_gap_detected",
    message: "Audit record gap detected",
    evaluate: (counters) => safeCounter(counters.audit_gap_total) > 0
  },
  {
    name: "cloud_audit_failure_detected",
    severity: "warning",
    code: "cloud_audit_failure_detected",
    message: "Cloud audit append failure detected",
    evaluate: (counters) => safeCounter(counters.cloud_audit_failure_total) > 0
  },
  {
    name: "outbox_dead_letter_present",
    severity: "critical",
    code: "outbox_dead_letter_present",
    message: "Owner recovery outbox contains dead-letter entries",
    evaluate: (counters, gauges) => safeCounter(gauges?.owner_recovery_outbox_dead_letter_count) > 0
  },
  {
    name: "outbox_uncertain_present",
    severity: "warning",
    code: "outbox_uncertain_present",
    message: "Owner recovery outbox contains uncertain entries",
    evaluate: (counters, gauges) => safeCounter(gauges?.owner_recovery_outbox_uncertain_count) > 0
  }
]);

export const OPERATIONAL_ALERT_NAMES = Object.freeze(ALERT_DEFINITIONS.map((alert) => alert.name));

/**
 * Create an operational alert evaluator.
 *
 * @param {object} [options]
 * @param {object} [options.thresholds] - optional per-alert threshold overrides
 *   (reserved for future use; current alerts use >0 thresholds)
 * @returns {object} frozen evaluator with evaluate()
 */
export function createOperationalAlerts({ thresholds } = {}) {
  if (thresholds !== undefined && (thresholds === null || typeof thresholds !== "object" || Array.isArray(thresholds))) {
    throw new TypeError("thresholds must be a plain object");
  }

  /**
   * Evaluate all alert rules against a metrics snapshot.
   *
   * @param {object} metricsSnapshot - from publicMetricsReport() or
   *   operationalMetrics.snapshot()
   * @returns {object} frozen { version, ok, alerts: [...firing] }
   */
  function evaluate(metricsSnapshot) {
    if (!metricsSnapshot || typeof metricsSnapshot !== "object" || Array.isArray(metricsSnapshot)) {
      return unavailable();
    }
    const counters = metricsSnapshot.counters;
    const gauges = metricsSnapshot.gauges;
    if (!counters || typeof counters !== "object" || Array.isArray(counters)) {
      return unavailable();
    }

    const firing = [];
    for (const definition of ALERT_DEFINITIONS) {
      try {
        if (definition.evaluate(counters, gauges)) {
          firing.push(Object.freeze({
            name: definition.name,
            severity: definition.severity,
            code: definition.code,
            message: definition.message
          }));
        }
      } catch {
        // Individual alert evaluation failure is non-fatal.  The alert
        // is silently skipped rather than blocking other evaluations.
      }
    }

    return Object.freeze({
      version: 1,
      ok: firing.length === 0,
      alerts: Object.freeze(firing)
    });
  }

  return Object.freeze({ evaluate });
}

function unavailable() {
  return Object.freeze({
    version: 1,
    ok: false,
    alerts: Object.freeze([Object.freeze({
      name: "metrics_unavailable",
      severity: "critical",
      code: "metrics_unavailable",
      message: "Metrics snapshot is unavailable for alert evaluation"
    })])
  });
}

function safeCounter(value) {
  return Number.isSafeInteger(value) && value >= 0 ? value : 0;
}
