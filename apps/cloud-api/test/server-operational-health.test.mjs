import assert from "node:assert/strict";
import test from "node:test";

import { createCloudApi } from "../src/server.mjs";
import { createDrainController, createOperationalMetrics } from "../src/postgres/operational-health.mjs";

const PROBE_SECRET = Buffer.alloc(32, 0x41);
const PROBE_HEADERS = { "AgentPass-Operational-Token": PROBE_SECRET.toString("base64url") };

test("exposes secret-free readiness and metrics while drain rejects new application work", async (t) => {
  const drain = createDrainController({ defaultTimeoutMs: 100 });
  const metrics = createOperationalMetrics();
  metrics.recordReplayDenial();
  const server = createCloudApi({
    store: {},
    readiness: async () => Object.freeze({ version: 1, ready: drain.snapshot().state === "running", status: drain.snapshot().state, code: drain.snapshot().state === "running" ? "ready" : "draining" }),
    operationalMetrics: metrics,
    operationalProbeSecret: PROBE_SECRET,
    trackInFlight: drain.track
  });
  await new Promise((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", resolve); });
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const base = `http://127.0.0.1:${server.address().port}`;

  assert.equal((await fetch(`${base}/health/ready`)).status, 404);
  const ready = await fetch(`${base}/health/ready`, { headers: PROBE_HEADERS });
  assert.equal(ready.status, 200);
  assert.equal((await ready.json()).code, "ready");
  const metricResponse = await fetch(`${base}/health/metrics`, { headers: PROBE_HEADERS });
  assert.equal(metricResponse.status, 200);
  const metricBody = await metricResponse.json();
  assert.equal(metricBody.counters.replay_denial_total, 1);
  assert.equal(JSON.stringify(metricBody).includes("organization"), false);

  drain.beginDrain();
  const drainingHealth = await fetch(`${base}/health/ready`, { headers: PROBE_HEADERS });
  assert.equal(drainingHealth.status, 503);
  assert.equal((await drainingHealth.json()).error.code, "draining");
  const rejected = await fetch(`${base}/not-an-application-route`);
  assert.equal(rejected.status, 503);
  assert.equal((await rejected.json()).error.code, "draining");
});

test("malformed operational providers fail closed without reflecting their values", async (t) => {
  const server = createCloudApi({
    store: {},
    readiness: async () => ({ version: 1, ready: true, status: "ready", code: "ready", checks: { password: "must-not-leak" } }),
    operationalMetrics: { snapshot: () => ({ version: 1, valid: true, counters: { token: 1 } }) },
    operationalProbeSecret: PROBE_SECRET
  });
  await new Promise((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", resolve); });
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const base = `http://127.0.0.1:${server.address().port}`;
  const ready = await fetch(`${base}/health/ready`, { headers: PROBE_HEADERS });
  assert.equal(ready.status, 503);
  assert.doesNotMatch(await ready.text(), /must-not-leak|password/u);
  const metrics = await fetch(`${base}/health/metrics`, { headers: PROBE_HEADERS });
  assert.equal(metrics.status, 503);
  assert.doesNotMatch(await metrics.text(), /token/u);
});

test("readiness exposes only aggregate owner recovery outbox state", async (t) => {
  const report = {
    version: 1,
    ready: false,
    status: "not_ready",
    code: "owner_recovery_outbox_dead_letter_present",
    checks: {
      database: { ok: true, probe: "ok" },
      schema: { ok: true, expected_version: 30, applied_version: 30, migration_count: 30, pending_count: 0, checksum_status: "verified", drift: false },
      pool: { ok: true, max_connections: 10, total_connections: 1, idle_connections: 1, waiting_connections: 0, utilization_percent: 10, saturated: false },
      drain: { state: "running", accepting: true, in_flight: 0 },
      owner_recovery_outbox: { ok: false, code: "dead_letter_present", worker_state: "running", pending_count: 2, uncertain_count: 0, dead_letter_count: 1, oldest_pending_age_ms: 500, oldest_uncertain_age_ms: null, organization_id: "must-not-leak" }
    }
  };
  const server = createCloudApi({ store: {}, readiness: async () => report, operationalMetrics: createOperationalMetrics(), operationalProbeSecret: PROBE_SECRET });
  await new Promise((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", resolve); });
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const response = await fetch(`http://127.0.0.1:${server.address().port}/health/ready`, { headers: PROBE_HEADERS });
  assert.equal(response.status, 503);
  const body = await response.json();
  assert.deepEqual(body.checks.owner_recovery_outbox, { ok: false, code: "dead_letter_present", worker_state: "running", pending_count: 2, uncertain_count: 0, dead_letter_count: 1, oldest_pending_age_ms: 500, oldest_uncertain_age_ms: null });
  assert.equal(JSON.stringify(body).includes("must-not-leak"), false);
});

test("readiness exposes only fixed aggregate managed signer provider-operation state", async (t) => {
  const report = {
    version: 1,
    ready: false,
    status: "not_ready",
    code: "managed_signer_provider_operations_uncertain_present",
    checks: {
      database: { ok: true, probe: "ok" },
      schema: { ok: true, expected_version: 46, applied_version: 46, migration_count: 46, pending_count: 0, checksum_status: "verified", drift: false },
      pool: { ok: true, max_connections: 10, total_connections: 1, idle_connections: 1, waiting_connections: 0, utilization_percent: 10, saturated: false },
      drain: { state: "running", accepting: true, in_flight: 0 },
      managed_signer_provider_operations: { ok: false, code: "uncertain_present", worker_state: "running", pending_count: 0, started_count: 0, accepted_count: 0, uncertain_count: 1, stale_started_count: 0, oldest_nonterminal_age_ms: 500, last_success_age_ms: 100, operation_id: "must-not-leak", receipt_id: "must-not-leak" }
    }
  };
  const server = createCloudApi({ store: {}, readiness: async () => report, operationalMetrics: createOperationalMetrics(), operationalProbeSecret: PROBE_SECRET });
  await new Promise((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", resolve); });
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const response = await fetch(`http://127.0.0.1:${server.address().port}/health/ready`, { headers: PROBE_HEADERS });
  assert.equal(response.status, 503);
  const body = await response.json();
  assert.deepEqual(body.checks.managed_signer_provider_operations, { ok: false, code: "uncertain_present", worker_state: "running", pending_count: 0, started_count: 0, accepted_count: 0, uncertain_count: 1, stale_started_count: 0, oldest_nonterminal_age_ms: 500, last_success_age_ms: 100 });
  assert.doesNotMatch(JSON.stringify(body), /must-not-leak|operation_id|receipt_id/u);
});

test("metrics exposes the fixed owner recovery gauges required by the alert policy", async (t) => {
  const counters = createOperationalMetrics().snapshot().counters;
  const gauges = {
    owner_recovery_outbox_pending_count: 2,
    owner_recovery_outbox_uncertain_count: 1,
    owner_recovery_outbox_dead_letter_count: 0,
    owner_recovery_outbox_oldest_pending_age_ms: 500,
    owner_recovery_outbox_oldest_uncertain_age_ms: 250
  };
  const server = createCloudApi({
    store: {},
    operationalMetrics: { async snapshot() { return { version: 1, valid: true, counters, gauges }; } },
    operationalProbeSecret: PROBE_SECRET
  });
  await new Promise((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", resolve); });
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const response = await fetch(`http://127.0.0.1:${server.address().port}/health/metrics`, { headers: PROBE_HEADERS });
  assert.equal(response.status, 200);
  assert.deepEqual((await response.json()).gauges, gauges);
});
