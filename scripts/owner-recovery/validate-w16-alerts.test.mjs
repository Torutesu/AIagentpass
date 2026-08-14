import assert from "node:assert/strict";
import { chmod, link, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

import { OPERATIONAL_GAUGE_KEYS, OPERATIONAL_METRIC_KEYS } from "../../apps/cloud-api/src/postgres/operational-health.mjs";

import {
  parseStrictW16AlertsJson,
  inspectW16AlertsFile,
  validateW16AlertPolicy,
  validateW16AlertsFile,
  W16_ALERT_NAMES,
  W16_ALERT_POLICY_MAX_BYTES
} from "./validate-w16-alerts.mjs";

const SCRIPT = fileURLToPath(new URL("./validate-w16-alerts.mjs", import.meta.url));
const POLICY_PATH = fileURLToPath(new URL("../../ops/observability/owner-recovery-alerts.v1.json", import.meta.url));

async function loadPolicy() {
  return parseStrictW16AlertsJson(await readFile(POLICY_PATH, "utf8"));
}

async function withTempPolicy(t, value, name = "policy.json") {
  const directory = await mkdtemp(path.join(os.tmpdir(), "agentpass-w16-alerts-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const file = path.join(directory, name);
  await writeFile(file, typeof value === "string" ? value : `${JSON.stringify(value)}\n`, { mode: 0o600 });
  return file;
}

test("accepts the closed fixed-name W1.6 policy and validates the repository artifact", async () => {
  const policy = await loadPolicy();
  assert.deepEqual(policy.alerts.map((alert) => alert.name), W16_ALERT_NAMES);
  assert.deepEqual(policy.label_policy, { mode: "none", labels: [] });
  assert.equal(policy.alerts.length, 10);
  for (const alert of policy.alerts) {
    assert.deepEqual(alert.thresholds.map((threshold) => threshold.severity), ["warning", "critical"]);
    assert.ok(alert.thresholds.every((threshold) => threshold.window_seconds >= 60));
    assert.ok(alert.thresholds.every((threshold) => threshold.comparison === ">="));
  }
  assert.deepEqual(validateW16AlertPolicy(policy), policy);
  assert.deepEqual(await validateW16AlertsFile(POLICY_PATH), policy);
  assert.match((await inspectW16AlertsFile(POLICY_PATH)).policy_digest, /^sha256:[0-9a-f]{64}$/u);
});

test("every alert input is exported by the operational metrics contract", async () => {
  const policy = await loadPolicy();
  const exported = new Set([...OPERATIONAL_METRIC_KEYS, ...OPERATIONAL_GAUGE_KEYS]);
  for (const alert of policy.alerts) {
    assert.equal(exported.has(alert.metric), true, `missing operational signal ${alert.metric}`);
    if (alert.sample_count_metric !== null) assert.equal(exported.has(alert.sample_count_metric), true, `missing sample counter ${alert.sample_count_metric}`);
  }
});

test("CLI returns success for the policy and a generic nonzero failure for invalid input", async (t) => {
  const policy = await loadPolicy();
  const valid = await withTempPolicy(t, policy);
  const accepted = spawnSync(process.execPath, [SCRIPT, valid], { encoding: "utf8" });
  assert.equal(accepted.status, 0);
  assert.match(accepted.stdout, /^sha256:[0-9a-f]{64}\n$/u);
  assert.equal(accepted.stderr, "");

  const invalid = await withTempPolicy(t, { ...policy, unexpected: "ignored" }, "contains-credential-secret.json");
  const rejected = spawnSync(process.execPath, [SCRIPT, invalid], { encoding: "utf8" });
  assert.notEqual(rejected.status, 0);
  assert.equal(rejected.stderr, "w16-alerts: invalid_policy\n");
  assert.doesNotMatch(rejected.stderr, /credential|secret|contains-credential-secret|agentpass-w16-alerts/iu);
});

test("rejects unknown fields at every contract level", async () => {
  const policy = await loadPolicy();
  for (const mutation of [
    { ...policy, metadata: {} },
    { ...policy, label_policy: { ...policy.label_policy, labels: ["tenant_id"] } },
    { ...policy, alerts: [{ ...policy.alerts[0], labels: [] }, ...policy.alerts.slice(1)] },
    { ...policy, alerts: [{ ...policy.alerts[0], thresholds: [{ ...policy.alerts[0].thresholds[0], for_seconds: 60 }, policy.alerts[0].thresholds[1]] }, ...policy.alerts.slice(1)] }
  ]) {
    assert.throws(() => validateW16AlertPolicy(mutation), { code: "invalid_policy" });
  }
});

test("rejects duplicate JSON keys before JSON.parse can collapse them", async (t) => {
  const duplicate = '{"schema_version":1,"schema_version":1}';
  assert.throws(() => parseStrictW16AlertsJson(duplicate), { code: "invalid_policy" });
  const file = await withTempPolicy(t, duplicate, "duplicate.json");
  await assert.rejects(validateW16AlertsFile(file), { code: "invalid_policy" });
});

test("rejects unbounded thresholds and windows", async () => {
  const policy = await loadPolicy();
  const oversizedValue = structuredClone(policy);
  oversizedValue.alerts[0].thresholds[1].value = Number.MAX_SAFE_INTEGER;
  assert.throws(() => validateW16AlertPolicy(oversizedValue), { code: "invalid_policy" });

  const oversizedWindow = structuredClone(policy);
  oversizedWindow.alerts[0].thresholds[0].window_seconds = W16_ALERT_POLICY_MAX_BYTES;
  assert.throws(() => validateW16AlertPolicy(oversizedWindow), { code: "invalid_policy" });
});

test("rejects comparison or evaluation-window drift from the closed alert contract", async () => {
  const policy = await loadPolicy();
  const comparison = structuredClone(policy);
  comparison.alerts[0].thresholds[0].comparison = ">";
  comparison.alerts[0].thresholds[1].comparison = ">";
  assert.throws(() => validateW16AlertPolicy(comparison), { code: "invalid_policy" });

  const window = structuredClone(policy);
  window.alerts[0].thresholds[0].window_seconds = 600;
  window.alerts[0].thresholds[1].window_seconds = 600;
  assert.throws(() => validateW16AlertPolicy(window), { code: "invalid_policy" });
});

test("rejects forbidden labels, templated values, URLs, and secret-bearing fields", async () => {
  const policy = await loadPolicy();
  const label = structuredClone(policy);
  label.label_policy.labels = ["{{tenant_id}}"];
  assert.throws(() => validateW16AlertPolicy(label), { code: "invalid_policy" });

  const url = structuredClone(policy);
  url.alerts[0].metric = "https://example.invalid/credential-secret";
  assert.throws(() => validateW16AlertPolicy(url), { code: "invalid_policy" });

  const secretField = structuredClone(policy);
  secretField.alerts[0].credential = "do-not-accept";
  assert.throws(() => validateW16AlertPolicy(secretField), { code: "invalid_policy" });
});

test("rejects inverted warning and critical thresholds", async () => {
  const policy = await loadPolicy();
  const inverted = structuredClone(policy);
  inverted.alerts[0].thresholds[0].value = 2_000_000;
  assert.throws(() => validateW16AlertPolicy(inverted), { code: "invalid_policy" });

  const invertedWindow = structuredClone(policy);
  invertedWindow.alerts[0].thresholds[0].window_seconds = 900;
  invertedWindow.alerts[0].thresholds[1].window_seconds = 300;
  assert.throws(() => validateW16AlertPolicy(invertedWindow), { code: "invalid_policy" });
});

test("rejects hard-linked or writable policy artifacts", async (t) => {
  const policy = await loadPolicy();
  const file = await withTempPolicy(t, policy);
  const hardlink = path.join(path.dirname(file), "policy-hardlink.json");
  await link(file, hardlink);
  await assert.rejects(validateW16AlertsFile(file), { code: "invalid_file" });
  await rm(hardlink);
  await chmod(file, 0o622);
  await assert.rejects(validateW16AlertsFile(file), { code: "invalid_file" });
});
