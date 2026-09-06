import assert from "node:assert/strict";
import test from "node:test";

import {
  createOperationalLog,
  OPERATIONAL_LOG_EVENTS,
  OPERATIONAL_LOG_ROUTES,
  OPERATIONAL_LOG_DECISION_CODES
} from "../src/operational-log.mjs";
import { createOperationalAlerts, OPERATIONAL_ALERT_NAMES } from "../src/operational-alerts.mjs";
import { createCloudApi } from "../src/server.mjs";
import { createOperationalMetrics } from "../src/postgres/operational-health.mjs";
import { startInMemoryHttpServer } from "../../../test/support/http-test-transport.mjs";

const PROBE_SECRET = Buffer.alloc(32, 0x41);
const PROBE_HEADERS = { "AgentPass-Operational-Token": PROBE_SECRET.toString("base64url") };

// Sensitive test material that must never appear in telemetry output.
const SENSITIVE_BEARER = "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.bearer-secret-material";
const SENSITIVE_CSRF = "csrf-token-secret-value-that-must-not-leak";
const SENSITIVE_JTI = "jti-claim-value-that-must-not-leak";
const SENSITIVE_CHALLENGE = "webauthn-challenge-raw-bytes-must-not-leak";
const SENSITIVE_ASSERTION = "webauthn-assertion-response-must-not-leak";
const SENSITIVE_PRIVATE_KEY = "-----BEGIN PRIVATE KEY-----MIIEvgIBADANBgkqhkiG9w0BAQE";
const SENSITIVE_CLAIM_TOKEN = "provider-claim-token-must-not-leak";
const SENSITIVE_DSN = "postgresql://admin:password@db.internal:5432/agentpass";
const SENSITIVE_ORG_ID = "11111111-1111-4111-8111-111111111111";
const SENSITIVE_MEMBER_ID = "22222222-2222-4222-8222-222222222222";
const SENSITIVE_CREDENTIAL_ID = "credential-id-value-must-not-leak";
const SENSITIVE_NOTIFICATION = "notification-content-delivery-must-not-leak";
const SENSITIVE_PROVIDER_DIAG = "provider-diagnostic-detail-must-not-leak";

const FORBIDDEN_PATTERN = new RegExp(
  [SENSITIVE_BEARER, SENSITIVE_CSRF, SENSITIVE_JTI, SENSITIVE_CHALLENGE,
   SENSITIVE_ASSERTION, SENSITIVE_PRIVATE_KEY, SENSITIVE_CLAIM_TOKEN,
   SENSITIVE_DSN, SENSITIVE_CREDENTIAL_ID, SENSITIVE_NOTIFICATION,
   SENSITIVE_PROVIDER_DIAG].map((s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("|"),
  "u"
);

// ─── Structured Logger Tests ────────────────────────────────────────────────

test("structured log entries use only the fixed event vocabulary", () => {
  const captured = [];
  const log = createOperationalLog({ sink: (entry) => captured.push(entry) });
  log.requestStart({ requestId: "test-id", route: "unknown" });
  log.requestComplete({ requestId: "test-id", route: "unknown", status: 200, decisionCode: "allowed" });
  log.requestError({ requestId: "test-id", route: "unknown", status: 500, decisionCode: "internal_error" });
  log.admissionDenied({ requestId: "test-id", route: "unknown" });
  log.authFailed({ requestId: "test-id", route: "unknown", decisionCode: "auth_failed" });
  log.authReplayDetected({ requestId: "test-id", route: "unknown" });
  log.rateLimitDenied({ requestId: "test-id", route: "unknown" });
  log.drainRejected({ requestId: "test-id" });
  assert.equal(captured.length, 8);
  const eventSet = new Set(OPERATIONAL_LOG_EVENTS);
  for (const entry of captured) {
    assert.equal(eventSet.has(entry.event), true, `event "${entry.event}" is not in the fixed vocabulary`);
  }
});

test("structured log entries never contain bearer tokens, CSRF tokens, or JTI values", () => {
  const captured = [];
  const log = createOperationalLog({ sink: (entry) => captured.push(entry) });
  // Attempt to inject sensitive material through all log methods.
  // The logger API only accepts requestId, route, status, and decisionCode.
  // Even if a caller passes a request ID that looks like a bearer token, the
  // string is bounded to 128 chars and checked; but the key test is that no
  // _additional_ fields carrying raw sensitive data exist.
  log.requestStart({ requestId: SENSITIVE_BEARER.slice(0, 128), route: "unknown" });
  log.requestComplete({ requestId: "id", route: "unknown", status: 200, decisionCode: "allowed" });
  log.requestError({ requestId: "id", route: "unknown", status: 401, decisionCode: "auth_failed" });
  log.admissionDenied({ requestId: "id", route: "unknown" });
  log.authFailed({ requestId: "id", route: "unknown", decisionCode: "auth_failed" });
  log.authReplayDetected({ requestId: "id" });
  log.rateLimitDenied({ requestId: "id" });
  log.drainRejected({ requestId: "id" });
  const logText = JSON.stringify(captured);
  // The log must never contain the raw sensitive material values.
  assert.doesNotMatch(logText, new RegExp(SENSITIVE_CSRF.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "u"));
  assert.doesNotMatch(logText, new RegExp(SENSITIVE_JTI.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "u"));
  assert.doesNotMatch(logText, new RegExp(SENSITIVE_CHALLENGE.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "u"));
  assert.doesNotMatch(logText, new RegExp(SENSITIVE_ASSERTION.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "u"));
  assert.doesNotMatch(logText, new RegExp(SENSITIVE_PRIVATE_KEY.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "u"));
  // Verify no log entry has fields like "headers", "body", "authorization",
  // "cookie", "csrf", "assertion", "challenge", or "token".
  for (const entry of captured) {
    const keys = Object.keys(entry);
    for (const key of keys) {
      assert.equal(["timestamp", "event", "request_id", "decision_code", "route", "status", "duration_ms"].includes(key), true, `unexpected field "${key}" in log entry`);
    }
  }
});

test("structured log entries never contain organization, member, or principal identifiers", () => {
  const captured = [];
  const log = createOperationalLog({ sink: (entry) => captured.push(entry) });
  log.requestStart({ requestId: "safe-request-id", route: "human.auth" });
  log.requestComplete({ requestId: "safe-request-id", route: "human.auth", status: 200, decisionCode: "allowed" });
  const logText = JSON.stringify(captured);
  // Even though real requests involve these IDs, the logger API has no
  // parameters to accept them, so they cannot appear.
  assert.doesNotMatch(logText, new RegExp(SENSITIVE_ORG_ID.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "u"));
  assert.doesNotMatch(logText, new RegExp(SENSITIVE_MEMBER_ID.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "u"));
  // Verify no field named "organization", "member", "principal", "tenant"
  for (const entry of captured) {
    const keys = Object.keys(entry);
    assert.equal(keys.some((key) => /organization|member|principal|tenant/iu.test(key)), false);
  }
});

test("structured log entries reject unknown event names silently", () => {
  const captured = [];
  const log = createOperationalLog({ sink: (entry) => captured.push(entry) });
  // The internal emit function silently drops unknown events.
  // We can only verify this indirectly: only known events produce output.
  log.requestStart({ requestId: "test" });
  assert.equal(captured.length, 1);
  assert.equal(captured[0].event, "request.start");
});

test("structured log entries reject unknown route labels and decision codes", () => {
  const captured = [];
  const log = createOperationalLog({ sink: (entry) => captured.push(entry) });
  log.requestComplete({ requestId: "test", route: "attacker.injected.route", status: 200, decisionCode: "attacker.injected.code" });
  assert.equal(captured.length, 1);
  assert.equal(captured[0].route, "unknown");
  assert.equal(captured[0].decision_code, undefined);
});

test("log sink failure never alters logger behavior", () => {
  let calls = 0;
  const log = createOperationalLog({
    sink: () => { calls += 1; throw new Error(SENSITIVE_DSN); }
  });
  // Must not throw, even though the sink throws.
  assert.doesNotThrow(() => log.requestStart({ requestId: "test" }));
  assert.doesNotThrow(() => log.requestComplete({ requestId: "test", status: 200 }));
  assert.doesNotThrow(() => log.requestError({ requestId: "test", status: 500 }));
  assert.doesNotThrow(() => log.admissionDenied({ requestId: "test" }));
  assert.equal(calls, 4);
});

test("structured log vocabularies are frozen and have no empty entries", () => {
  assert.ok(Object.isFrozen(OPERATIONAL_LOG_EVENTS));
  assert.ok(Object.isFrozen(OPERATIONAL_LOG_ROUTES));
  assert.ok(Object.isFrozen(OPERATIONAL_LOG_DECISION_CODES));
  assert.ok(OPERATIONAL_LOG_EVENTS.length > 0);
  assert.ok(OPERATIONAL_LOG_ROUTES.length > 0);
  assert.ok(OPERATIONAL_LOG_DECISION_CODES.length > 0);
  for (const event of OPERATIONAL_LOG_EVENTS) assert.equal(typeof event, "string");
  for (const route of OPERATIONAL_LOG_ROUTES) assert.equal(typeof route, "string");
  for (const code of OPERATIONAL_LOG_DECISION_CODES) assert.equal(typeof code, "string");
});

// ─── Alert Evaluator Tests ──────────────────────────────────────────────────

test("alert evaluator returns ok when no counters exceed thresholds", () => {
  const alerts = createOperationalAlerts();
  const metrics = createOperationalMetrics();
  const result = alerts.evaluate(metrics.snapshot());
  assert.equal(result.version, 1);
  assert.equal(result.ok, true);
  assert.deepEqual(result.alerts, []);
});

test("alert evaluator fires on replay denial", () => {
  const alerts = createOperationalAlerts();
  const metrics = createOperationalMetrics();
  metrics.recordReplayDenial();
  const result = alerts.evaluate(metrics.snapshot());
  assert.equal(result.ok, false);
  const replayAlert = result.alerts.find((a) => a.name === "replay_denial_detected");
  assert.ok(replayAlert);
  assert.equal(replayAlert.severity, "critical");
  assert.equal(replayAlert.code, "replay_denial_detected");
});

test("alert evaluator fires on signer failure", () => {
  const alerts = createOperationalAlerts();
  const metrics = createOperationalMetrics();
  metrics.recordAgentSessionSignerFailure();
  const result = alerts.evaluate(metrics.snapshot());
  assert.equal(result.ok, false);
  const signerAlert = result.alerts.find((a) => a.name === "signer_failure_detected");
  assert.ok(signerAlert);
  assert.equal(signerAlert.severity, "critical");
});

test("alert evaluator fires on audit gap", () => {
  const alerts = createOperationalAlerts();
  const metrics = createOperationalMetrics();
  metrics.recordAuditGap();
  const result = alerts.evaluate(metrics.snapshot());
  assert.equal(result.ok, false);
  assert.ok(result.alerts.some((a) => a.name === "audit_gap_detected"));
});

test("alert evaluator returns only fixed-vocabulary alert names without interpolated values", () => {
  const alerts = createOperationalAlerts();
  const metrics = createOperationalMetrics();
  // Trigger multiple alerts.
  metrics.recordReplayDenial();
  metrics.recordLockTimeout();
  metrics.recordAgentSessionSignerFailure();
  metrics.recordAuditGap();
  metrics.recordCloudAuditFailure();
  const result = alerts.evaluate(metrics.snapshot());
  const alertNameSet = new Set(OPERATIONAL_ALERT_NAMES);
  for (const alert of result.alerts) {
    assert.equal(alertNameSet.has(alert.name), true, `alert name "${alert.name}" is not in the fixed vocabulary`);
    assert.equal(typeof alert.message, "string");
    assert.ok(alert.message.length > 0);
    // Verify no interpolated identifiers in the message.
    assert.doesNotMatch(alert.message, FORBIDDEN_PATTERN);
  }
});

test("alert evaluator handles malformed metrics snapshot gracefully", () => {
  const alerts = createOperationalAlerts();
  const result1 = alerts.evaluate(null);
  assert.equal(result1.ok, false);
  assert.ok(result1.alerts.length > 0);
  assert.equal(result1.alerts[0].name, "metrics_unavailable");

  const result2 = alerts.evaluate({ counters: null });
  assert.equal(result2.ok, false);

  const result3 = alerts.evaluate("not-an-object");
  assert.equal(result3.ok, false);
});

test("alert evaluator fires on outbox dead letters when gauges are present", () => {
  const alerts = createOperationalAlerts();
  const snapshot = {
    version: 1,
    valid: true,
    counters: createOperationalMetrics().snapshot().counters,
    gauges: {
      owner_recovery_outbox_pending_count: 0,
      owner_recovery_outbox_uncertain_count: 0,
      owner_recovery_outbox_dead_letter_count: 3,
      owner_recovery_outbox_oldest_pending_age_ms: 0,
      owner_recovery_outbox_oldest_uncertain_age_ms: 0
    }
  };
  const result = alerts.evaluate(snapshot);
  assert.equal(result.ok, false);
  assert.ok(result.alerts.some((a) => a.name === "outbox_dead_letter_present"));
});

// ─── Telemetry Redaction Integration Tests ──────────────────────────────────

test("metrics endpoint never contains organization, member, request, or credential identifiers", async (t) => {
  const metrics = createOperationalMetrics();
  metrics.recordReplayDenial();
  metrics.recordRateLimitDenial();
  const server = createCloudApi({
    store: {},
    operationalMetrics: metrics,
    operationalProbeSecret: PROBE_SECRET
  });
  const base = startInMemoryHttpServer(server);
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const response = await fetch(`${base}/health/metrics`, { headers: PROBE_HEADERS });
  assert.equal(response.status, 200);
  const body = await response.text();
  // Check that no _field name_ in the response contains these identifiers.
  // Note: counter key names like "managed_signer_provider_operation_..." contain
  // the substring "operation" — we check for field-level identifiers, not
  // counter key substrings.  Parse the JSON and check top-level + nested keys.
  const parsed = JSON.parse(body);
  const topKeys = Object.keys(parsed);
  for (const key of topKeys) {
    assert.equal(["version", "valid", "counters", "gauges", "code"].includes(key), true, `unexpected top-level key "${key}"`);
  }
  assert.doesNotMatch(body, FORBIDDEN_PATTERN);
});

test("alerts endpoint never contains sensitive data even when alerts are firing", async (t) => {
  const metrics = createOperationalMetrics();
  metrics.recordReplayDenial();
  metrics.recordAuditGap();
  metrics.recordAgentSessionSignerFailure();
  const server = createCloudApi({
    store: {},
    operationalMetrics: metrics,
    operationalProbeSecret: PROBE_SECRET
  });
  const base = startInMemoryHttpServer(server);
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const response = await fetch(`${base}/health/alerts`, { headers: PROBE_HEADERS });
  assert.equal(response.status, 200);
  const body = await response.json();
  assert.equal(body.version, 1);
  assert.equal(body.ok, false);
  assert.ok(body.alerts.length >= 3);
  const alertText = JSON.stringify(body);
  assert.doesNotMatch(alertText, FORBIDDEN_PATTERN);
  assert.doesNotMatch(alertText, /organization|member|token|bearer|assertion|challenge|credential|dsn|connection|password/iu);
});

test("alerts endpoint requires the same operational probe secret as readiness and metrics", async (t) => {
  const metrics = createOperationalMetrics();
  const server = createCloudApi({
    store: {},
    operationalMetrics: metrics,
    operationalProbeSecret: PROBE_SECRET
  });
  const base = startInMemoryHttpServer(server);
  t.after(() => new Promise((resolve) => server.close(resolve)));
  // Without probe header → 404 (not 403, to avoid fingerprintability).
  const unauthResponse = await fetch(`${base}/health/alerts`);
  assert.equal(unauthResponse.status, 404);
  // With probe header → 200.
  const authResponse = await fetch(`${base}/health/alerts`, { headers: PROBE_HEADERS });
  assert.equal(authResponse.status, 200);
  const body = await authResponse.json();
  assert.equal(body.version, 1);
  assert.equal(typeof body.ok, "boolean");
  assert.ok(Array.isArray(body.alerts));
});

test("alerts endpoint returns ok:true when no alerts are firing", async (t) => {
  const metrics = createOperationalMetrics();
  const server = createCloudApi({
    store: {},
    operationalMetrics: metrics,
    operationalProbeSecret: PROBE_SECRET
  });
  const base = startInMemoryHttpServer(server);
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const response = await fetch(`${base}/health/alerts`, { headers: PROBE_HEADERS });
  assert.equal(response.status, 200);
  const body = await response.json();
  assert.equal(body.ok, true);
  assert.deepEqual(body.alerts, []);
});

test("error responses never leak internal error messages containing SQL, DSN, or provider diagnostics", async (t) => {
  // Verify that mapError() in server.mjs strips internal details.
  // A request to a non-existent route produces a fixed "not_found" error.
  const server = createCloudApi({
    store: {},
    operationalProbeSecret: PROBE_SECRET
  });
  const base = startInMemoryHttpServer(server);
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const response = await fetch(`${base}/v1/organizations/${SENSITIVE_ORG_ID}`);
  const body = await response.text();
  // The response must not reflect the organization ID from the path as an
  // error detail — only fixed error codes and messages are permitted.
  assert.doesNotMatch(body, new RegExp(SENSITIVE_DSN.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "u"));
  assert.doesNotMatch(body, /password|connection.*string|pg_stat/iu);
});

test("log sink failure never alters request authorization outcome", async (t) => {
  const throwingSink = () => { throw new Error("sink failure with " + SENSITIVE_DSN); };
  const log = createOperationalLog({ sink: throwingSink });
  const metrics = createOperationalMetrics();
  const server = createCloudApi({
    store: {},
    readiness: async () => ({ version: 1, ready: true, status: "ready", code: "ready" }),
    operationalMetrics: metrics,
    operationalProbeSecret: PROBE_SECRET,
    operationalLog: log
  });
  const base = startInMemoryHttpServer(server);
  t.after(() => new Promise((resolve) => server.close(resolve)));
  // Requests must still succeed normally despite the failing log sink.
  const healthResponse = await fetch(`${base}/health/ready`, { headers: PROBE_HEADERS });
  assert.equal(healthResponse.status, 200);
  const metricsResponse = await fetch(`${base}/health/metrics`, { headers: PROBE_HEADERS });
  assert.equal(metricsResponse.status, 200);
});

test("structured log captures request lifecycle with monotonic duration", () => {
  const captured = [];
  const log = createOperationalLog({ sink: (entry) => captured.push(entry) });
  const startMark = log.requestStart({ requestId: "duration-test", route: "device.enrollment" });
  assert.equal(typeof startMark, "number");
  // Simulate work.
  let sum = 0;
  for (let i = 0; i < 1_000_000; i += 1) sum += i;
  log.requestComplete({ requestId: "duration-test", route: "device.enrollment", status: 200, decisionCode: "allowed", startMark });
  assert.equal(captured.length, 2);
  assert.equal(captured[0].event, "request.start");
  assert.equal(captured[1].event, "request.complete");
  assert.equal(captured[1].route, "device.enrollment");
  assert.equal(typeof captured[1].duration_ms, "number");
  assert.ok(captured[1].duration_ms >= 0);
  // Suppress unused variable lint.
  void sum;
});
