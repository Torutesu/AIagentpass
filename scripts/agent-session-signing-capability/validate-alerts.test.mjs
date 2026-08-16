import assert from "node:assert/strict";
import { chmod, link, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

import { OPERATIONAL_METRIC_KEYS } from "../../apps/cloud-api/src/postgres/operational-health.mjs";
import {
  AGENT_SESSION_SIGNING_CAPABILITY_ALERT_NAMES,
  inspectAgentSessionSigningCapabilityAlertsFile,
  parseStrictAgentSessionSigningCapabilityAlertsJson,
  validateAgentSessionSigningCapabilityAlertPolicy,
  validateAgentSessionSigningCapabilityAlertsFile
} from "./validate-alerts.mjs";

const SCRIPT = fileURLToPath(new URL("./validate-alerts.mjs", import.meta.url));
const POLICY_PATH = fileURLToPath(new URL("../../ops/observability/agent-session-signing-capability-maintenance-alerts.v1.json", import.meta.url));
const RUNBOOK_PATH = fileURLToPath(new URL("../../ops/observability/agent-session-signing-capability-maintenance.runbook.md", import.meta.url));

async function loadPolicy() {
  return parseStrictAgentSessionSigningCapabilityAlertsJson(await readFile(POLICY_PATH, "utf8"));
}

async function withTempPolicy(t, value, name = "policy.json") {
  const directory = await mkdtemp(path.join(os.tmpdir(), "agentpass-agent-signing-alerts-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const file = path.join(directory, name);
  await writeFile(file, typeof value === "string" ? value : `${JSON.stringify(value)}\n`, { mode: 0o600 });
  return file;
}

test("accepts the closed fixed-name policy and validates the repository artifact", async () => {
  const policy = await loadPolicy();
  assert.deepEqual(policy.alerts.map((alert) => alert.name), AGENT_SESSION_SIGNING_CAPABILITY_ALERT_NAMES);
  assert.deepEqual(policy.label_policy, { mode: "none", labels: [] });
  assert.equal(policy.alerts.length, 3);
  const exported = new Set(OPERATIONAL_METRIC_KEYS);
  for (const alert of policy.alerts) {
    assert.equal(exported.has(alert.metric), true);
    assert.equal(alert.sample_count_metric, null);
    assert.deepEqual(alert.thresholds.map((threshold) => threshold.severity), ["warning", "critical"]);
    assert.ok(alert.thresholds.every((threshold) => threshold.window_seconds >= 60));
  }
  assert.deepEqual(validateAgentSessionSigningCapabilityAlertPolicy(policy), policy);
  assert.deepEqual(await validateAgentSessionSigningCapabilityAlertsFile(POLICY_PATH), policy);
  assert.match((await inspectAgentSessionSigningCapabilityAlertsFile(POLICY_PATH)).policy_digest, /^sha256:[0-9a-f]{64}$/u);
});

test("keeps the policy aggregate-only and documents the same fixed signals", async () => {
  const policy = await loadPolicy();
  const runbook = await readFile(RUNBOOK_PATH, "utf8");
  for (const alert of policy.alerts) {
    assert.match(runbook, new RegExp(alert.name, "u"));
    assert.match(runbook, new RegExp(alert.metric, "u"));
    assert.equal(alert.metric.includes("tenant"), false);
  }
  assert.deepEqual(policy.label_policy, { mode: "none", labels: [] });
  const serialized = JSON.stringify(policy);
  assert.doesNotMatch(serialized, /https?:\/\/|postgres(?:ql)?:\/\/|-----BEGIN|(?:secret|credential|password|token|dsn)\s*[:=]/iu);
  assert.doesNotMatch(serialized, /"(?:tenant|organization|member|event|request|user|url|credential|secret|token|password|private|authorization|cookie|email|ip|repository|destination|webhook)"\s*:/iu);
});

test("CLI returns only a digest for valid input and a generic error for invalid input", async (t) => {
  const policy = await loadPolicy();
  const valid = await withTempPolicy(t, policy);
  const accepted = spawnSync(process.execPath, [SCRIPT, valid], { encoding: "utf8" });
  assert.equal(accepted.status, 0);
  assert.match(accepted.stdout, /^sha256:[0-9a-f]{64}\n$/u);
  assert.equal(accepted.stderr, "");

  const invalid = await withTempPolicy(t, { ...policy, unexpected: "ignored" }, "contains-credential-secret.json");
  const rejected = spawnSync(process.execPath, [SCRIPT, invalid], { encoding: "utf8" });
  assert.notEqual(rejected.status, 0);
  assert.equal(rejected.stderr, "agent-session-signing-capability-alerts: invalid_policy\n");
  assert.doesNotMatch(rejected.stderr, /credential|secret|contains-credential-secret|agentpass-agent-signing-alerts/iu);
});

test("rejects unknown fields, labels, and secret-bearing material", async () => {
  const policy = await loadPolicy();
  for (const mutation of [
    { ...policy, metadata: {} },
    { ...policy, label_policy: { ...policy.label_policy, labels: ["tenant_id"] } },
    { ...policy, alerts: [{ ...policy.alerts[0], labels: [] }, ...policy.alerts.slice(1)] },
    { ...policy, alerts: [{ ...policy.alerts[0], secret: "do-not-accept" }, ...policy.alerts.slice(1)] },
    { ...policy, alerts: [{ ...policy.alerts[0], metric: "https://example.invalid/secret" }, ...policy.alerts.slice(1)] }
  ]) {
    assert.throws(() => validateAgentSessionSigningCapabilityAlertPolicy(mutation), { code: "invalid_policy" });
  }
});

test("rejects duplicate keys and threshold drift", async () => {
  assert.throws(() => parseStrictAgentSessionSigningCapabilityAlertsJson('{"schema_version":1,"schema_version":1}'), { code: "invalid_policy" });
  const policy = await loadPolicy();
  const inverted = structuredClone(policy);
  inverted.alerts[1].thresholds[0].value = 4;
  assert.throws(() => validateAgentSessionSigningCapabilityAlertPolicy(inverted), { code: "invalid_policy" });
  const window = structuredClone(policy);
  window.alerts[0].thresholds[1].window_seconds = 60;
  assert.throws(() => validateAgentSessionSigningCapabilityAlertPolicy(window), { code: "invalid_policy" });
  const comparison = structuredClone(policy);
  comparison.alerts[0].thresholds[0].comparison = ">=";
  assert.throws(() => validateAgentSessionSigningCapabilityAlertPolicy(comparison), { code: "invalid_policy" });
});

test("rejects hard-linked and writable policy artifacts", async (t) => {
  const policy = await loadPolicy();
  const file = await withTempPolicy(t, policy);
  const hardlink = path.join(path.dirname(file), "policy-hardlink.json");
  await link(file, hardlink);
  await assert.rejects(validateAgentSessionSigningCapabilityAlertsFile(file), { code: "invalid_file" });
  await rm(hardlink);
  await chmod(file, 0o622);
  await assert.rejects(validateAgentSessionSigningCapabilityAlertsFile(file), { code: "invalid_file" });
});
