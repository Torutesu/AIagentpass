/**
 * Zero-dependency structured operational logger for AgentPass Cloud API.
 *
 * Design constraints (from THREAT_MODEL.md and IMPLEMENTATION_ROADMAP.md OP-01):
 *
 * 1. Closed fixed vocabulary — every event name and field key is from a
 *    predetermined frozen set.  No caller-supplied string is interpolated.
 * 2. Aggregate-only — no organization, member, principal, request body,
 *    destination, URL, DSN, token, credential, notification content, or
 *    provider diagnostics.
 * 3. Non-authoritative — logging failures never alter authorization or API
 *    behavior.  Every public method swallows exceptions.
 * 4. Zero dependencies — uses only node:perf_hooks for monotonic timing.
 *
 * The only identifiers emitted are:
 * - request_id: a server-generated crypto.randomUUID(), never caller-supplied
 * - decision_code: from the fixed set below, never from error.message
 * - route: from the fixed set below, never from the URL path
 * - status: HTTP status code (integer)
 * - duration_ms: monotonic elapsed time (integer)
 */

import { performance } from "node:perf_hooks";

/**
 * Fixed event names.  Any event not in this set is silently dropped.
 */
export const OPERATIONAL_LOG_EVENTS = Object.freeze([
  "request.start",
  "request.complete",
  "request.error",
  "admission.denied",
  "auth.failed",
  "auth.replay_detected",
  "rate_limit.denied",
  "drain.rejected",
  "signer.failure",
  "signer.timeout",
  "lock.timeout",
  "audit.gap_detected",
  "alert.fired"
]);

/**
 * Fixed route labels.  Derived from the server.mjs route table, not from
 * the request URL.  A request that does not match any known route is
 * labelled "unknown".
 */
export const OPERATIONAL_LOG_ROUTES = Object.freeze([
  "health.ready",
  "health.metrics",
  "health.alerts",
  "device.enrollment",
  "device.bundle",
  "device.ack",
  "device.refresh",
  "device.audit",
  "device.wake",
  "agent_session.consume",
  "agent_session.signing_capability",
  "agent_session.launch_handoff",
  "qualification.claim",
  "human.auth",
  "human.session",
  "human.management",
  "human.organization",
  "human.audit_export",
  "platform.session",
  "platform.promotion",
  "hosted.bootstrap",
  "unknown"
]);

/**
 * Fixed decision codes.  These are the only values permitted in the
 * decision_code field.  They map to error codes already used by mapError()
 * and apiError() in server.mjs but are a closed re-export rather than a
 * pass-through of arbitrary error.code values.
 */
export const OPERATIONAL_LOG_DECISION_CODES = Object.freeze([
  "allowed",
  "denied",
  "rate_limited",
  "auth_failed",
  "auth_replay_detected",
  "draining",
  "not_found",
  "internal_error",
  "service_not_ready",
  "signer_failure",
  "signer_timeout",
  "lock_timeout",
  "version_conflict",
  "enrollment_conflict",
  "idempotency_conflict",
  "input_rejected",
  "unavailable"
]);

const EVENT_SET = new Set(OPERATIONAL_LOG_EVENTS);
const ROUTE_SET = new Set(OPERATIONAL_LOG_ROUTES);
const DECISION_SET = new Set(OPERATIONAL_LOG_DECISION_CODES);

const DEFAULT_SINK = (entry) => {
  try { process.stderr.write(JSON.stringify(entry) + "\n"); } catch { /* stderr failure is non-fatal */ }
};

/**
 * Create a structured operational logger.
 *
 * @param {object} options
 * @param {function} [options.sink] - receives a frozen log entry object
 * @param {function} [options.clock] - returns epoch milliseconds (for timestamps)
 * @returns {object} frozen logger with fixed public methods
 */
export function createOperationalLog({ sink = DEFAULT_SINK, clock = () => Date.now() } = {}) {
  if (typeof sink !== "function") throw new TypeError("sink must be a function");
  if (typeof clock !== "function") throw new TypeError("clock must be a function");

  function emit(event, fields) {
    try {
      if (!EVENT_SET.has(event)) return;
      const entry = Object.freeze({
        timestamp: safeClock(clock),
        event,
        ...(fields.request_id !== undefined ? { request_id: safeString(fields.request_id) } : {}),
        ...(fields.decision_code !== undefined && DECISION_SET.has(fields.decision_code) ? { decision_code: fields.decision_code } : {}),
        ...(fields.route !== undefined && ROUTE_SET.has(fields.route) ? { route: fields.route } : {}),
        ...(fields.status !== undefined && Number.isSafeInteger(fields.status) && fields.status >= 100 && fields.status <= 599 ? { status: fields.status } : {}),
        ...(fields.duration_ms !== undefined && Number.isSafeInteger(fields.duration_ms) && fields.duration_ms >= 0 ? { duration_ms: fields.duration_ms } : {})
      });
      sink(entry);
    } catch { /* Observability must never alter authorization or API behavior. */ }
  }

  /**
   * Record the start of a request.  Returns a monotonic start mark for
   * duration calculation.
   */
  function requestStart({ requestId, route } = {}) {
    const mark = performance.now();
    emit("request.start", { request_id: requestId, route: safeRoute(route) });
    return mark;
  }

  function requestComplete({ requestId, route, status, decisionCode, startMark } = {}) {
    const durationMs = safeDuration(startMark);
    emit("request.complete", { request_id: requestId, route: safeRoute(route), status, decision_code: safeDecision(decisionCode), duration_ms: durationMs });
  }

  function requestError({ requestId, route, status, decisionCode, startMark } = {}) {
    const durationMs = safeDuration(startMark);
    emit("request.error", { request_id: requestId, route: safeRoute(route), status, decision_code: safeDecision(decisionCode), duration_ms: durationMs });
  }

  function admissionDenied({ requestId, route } = {}) {
    emit("admission.denied", { request_id: requestId, route: safeRoute(route), decision_code: "rate_limited" });
  }

  function authFailed({ requestId, route, decisionCode } = {}) {
    emit("auth.failed", { request_id: requestId, route: safeRoute(route), decision_code: safeDecision(decisionCode) });
  }

  function authReplayDetected({ requestId, route } = {}) {
    emit("auth.replay_detected", { request_id: requestId, route: safeRoute(route), decision_code: "auth_replay_detected" });
  }

  function rateLimitDenied({ requestId, route } = {}) {
    emit("rate_limit.denied", { request_id: requestId, route: safeRoute(route), decision_code: "rate_limited" });
  }

  function drainRejected({ requestId } = {}) {
    emit("drain.rejected", { request_id: requestId, decision_code: "draining" });
  }

  function signerFailure({ requestId } = {}) {
    emit("signer.failure", { request_id: requestId, decision_code: "signer_failure" });
  }

  function signerTimeout({ requestId } = {}) {
    emit("signer.timeout", { request_id: requestId, decision_code: "signer_timeout" });
  }

  function lockTimeout({ requestId } = {}) {
    emit("lock.timeout", { request_id: requestId, decision_code: "lock_timeout" });
  }

  function auditGapDetected({ requestId } = {}) {
    emit("audit.gap_detected", { request_id: requestId, decision_code: "denied" });
  }

  function alertFired({ alertName } = {}) {
    emit("alert.fired", { decision_code: safeDecision(alertName) });
  }

  return Object.freeze({
    requestStart,
    requestComplete,
    requestError,
    admissionDenied,
    authFailed,
    authReplayDetected,
    rateLimitDenied,
    drainRejected,
    signerFailure,
    signerTimeout,
    lockTimeout,
    auditGapDetected,
    alertFired
  });
}

function safeClock(clock) {
  try {
    const value = clock();
    return Number.isSafeInteger(value) && value >= 0 ? value : Date.now();
  } catch { return Date.now(); }
}

function safeDuration(startMark) {
  if (startMark === undefined) return undefined;
  const elapsed = Math.round(performance.now() - startMark);
  return Number.isSafeInteger(elapsed) && elapsed >= 0 ? elapsed : undefined;
}

function safeString(value) {
  return typeof value === "string" && value.length > 0 && value.length <= 128 ? value : undefined;
}

function safeRoute(value) {
  return ROUTE_SET.has(value) ? value : "unknown";
}

function safeDecision(value) {
  return DECISION_SET.has(value) ? value : undefined;
}
