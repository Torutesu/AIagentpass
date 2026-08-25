import assert from "node:assert/strict";
import crypto from "node:crypto";
import { chmod, link, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";

import {
  W16_DRILL_MAX_BYTES,
  W16_DRILL_MAX_DURATION_MS,
  W16_DRILL_SCENARIOS,
  W16_DRILL_SCHEMA_VERSION,
  verifyW16DrillEvidence
} from "./verify-w16-drill-evidence.mjs";

const COMMIT = "0123456789abcdef0123456789abcdef01234567";
const IMAGE = `sha256:${"a".repeat(64)}`;
const ALERT_POLICY = `sha256:${"b".repeat(64)}`;
const VALID = Object.freeze({
  schema_version: W16_DRILL_SCHEMA_VERSION,
  source_commit: COMMIT,
  image_digest: IMAGE,
  alert_policy_digest: ALERT_POLICY,
  started_at: "2026-08-14T00:00:00.000Z",
  completed_at: "2026-08-14T00:01:00.000Z",
  duration_ms: 60_000,
  outcome: "passed",
  scenarios: W16_DRILL_SCENARIOS.map((name) => ({ name, outcome: "passed" })),
  aggregate_observations: {
    scenario_count: 6,
    passed_count: 6,
    failed_count: 0,
    alert_policy_rule_count: 10,
    warning_alerts_observed: 10,
    critical_alerts_observed: 10,
    unauthorized_mutations: 0,
    duplicate_provider_acceptances: 0,
    forbidden_material_findings: 0,
    active_claims: 0,
    active_leases: 0
  }
});

async function fixture(t, value = VALID) {
  const directory = await mkdtemp(path.join(os.tmpdir(), "agentpass-w16-drill-evidence-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const file = path.join(directory, "evidence.json");
  await writeFile(file, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
  return { directory, file };
}

test("accepts only the closed, source-bound W1.6 evidence contract", async (t) => {
  const value = await fixture(t);
  const result = await verifyW16DrillEvidence(value.file, {
    expectedCommitSha: COMMIT,
    expectedImageDigest: IMAGE,
    expectedAlertPolicyDigest: ALERT_POLICY
  });
  assert.equal(result.ok, true);
  assert.equal(result.schema_version, 36);
  assert.equal(result.duration_ms, 60_000);
  assert.equal(result.scenario_count, 6);
  assert.equal(result.alert_policy_rule_count, 10);
  assert.equal(result.warning_alerts_observed, 10);
  assert.equal(result.critical_alerts_observed, 10);
  assert.equal(result.active_claims, 0);
  assert.equal(result.active_leases, 0);
  assert.match(result.evidence_sha256, /^[0-9a-f]{64}$/u);
  assert.equal(Object.hasOwn(result, "scenarios"), false);
});

test("publishes a strict JSON schema with canonical scenario order and nonzero bindings", async () => {
  const schemaPath = path.join(path.dirname(new URL(import.meta.url).pathname), "w16-drill-evidence.schema.json");
  const schema = JSON.parse(await readFile(schemaPath, "utf8"));
  assert.equal(schema.additionalProperties, false);
  assert.equal(schema.properties.schema_version.const, W16_DRILL_SCHEMA_VERSION);
  assert.deepEqual(schema.properties.scenarios.prefixItems.map((item) => item.$ref.split("/").at(-1)), W16_DRILL_SCENARIOS);
  assert.equal(schema.properties.scenarios.items, false);
  assert.equal(schema.properties.source_commit.pattern.includes("(?!"), true);
  assert.equal(schema.properties.image_digest.pattern.includes("(?!"), true);
  assert.equal(schema.properties.started_at.format, "date-time");
  assert.equal(schema.$defs.scenario_base.additionalProperties, false);
  for (const name of W16_DRILL_SCENARIOS) assert.equal(schema.$defs[name].allOf[1].type, "object");
  assert.equal(schema.properties.aggregate_observations.additionalProperties, false);
  assert.equal(schema.properties.duration_ms.maximum, W16_DRILL_MAX_DURATION_MS);
});

test("requires exact source bindings and rejects secret, identity, URL, notification, and unknown material", async (t) => {
  const value = await fixture(t);
  await assert.rejects(verifyW16DrillEvidence(value.file, { expectedCommitSha: "f".repeat(40) }), { code: "source_mismatch" });
  await assert.rejects(verifyW16DrillEvidence(value.file, { expectedCommitSha: "f".repeat(41) }), { code: "invalid_arguments" });
  await assert.rejects(verifyW16DrillEvidence(value.file, { commit_sha: COMMIT }), { code: "invalid_arguments" });
  for (const mutation of [
    { organization_id: "11111111-1111-4111-8111-111111111111" },
    { member_id: "22222222-2222-4222-8222-222222222222" },
    { event_id: "33333333-3333-4333-8333-333333333333" },
    { dsn: "postgresql://user:password@example.invalid/db" },
    { notification: "page the operator with this content" },
    { token: "Bearer do-not-record" }
  ]) {
    await writeFile(value.file, `${JSON.stringify({ ...VALID, ...mutation })}\n`, { mode: 0o600 });
    await assert.rejects(verifyW16DrillEvidence(value.file), (error) => error.code === "invalid_evidence" && !error.message.includes("example.invalid"));
  }
  await writeFile(value.file, `${JSON.stringify({ ...VALID, scenarios: VALID.scenarios.map((item, index) => index === 0 ? { ...item, notification_content: "never" } : item) })}\n`, { mode: 0o600 });
  await assert.rejects(verifyW16DrillEvidence(value.file), { code: "invalid_evidence" });
});

test("rejects duplicate JSON fields instead of accepting an ambiguous last value", async (t) => {
  const value = await fixture(t);
  const duplicateOutcome = JSON.stringify(VALID).replace('"outcome":"passed"', '"outcome":"passed","outcome":"passed"');
  await writeFile(value.file, `${duplicateOutcome}\n`, { mode: 0o600 });
  await assert.rejects(verifyW16DrillEvidence(value.file), { code: "invalid_evidence" });
});

test("requires all six scenarios exactly once, all passed, and fixed drained observations", async (t) => {
  const value = await fixture(t);
  const mutations = [
    { scenarios: [...VALID.scenarios].reverse() },
    { scenarios: VALID.scenarios.slice(0, 5).map((name) => ({ name, outcome: "passed" })) },
    { scenarios: VALID.scenarios.map((item, index) => index === 0 ? { ...item, outcome: "failed" } : item) },
    { aggregate_observations: { ...VALID.aggregate_observations, active_claims: 1 } },
    { aggregate_observations: { ...VALID.aggregate_observations, active_leases: 1 } },
    { aggregate_observations: { ...VALID.aggregate_observations, warning_alerts_observed: 9 } },
    { aggregate_observations: { ...VALID.aggregate_observations, critical_alerts_observed: 9 } },
    { aggregate_observations: { ...VALID.aggregate_observations, unauthorized_mutations: 1 } },
    { aggregate_observations: { ...VALID.aggregate_observations, duplicate_provider_acceptances: 1 } },
    { aggregate_observations: { ...VALID.aggregate_observations, forbidden_material_findings: 1 } },
    { aggregate_observations: { ...VALID.aggregate_observations, failed_count: 1 } }
  ];
  for (const mutation of mutations) {
    await writeFile(value.file, `${JSON.stringify({ ...VALID, ...mutation })}\n`, { mode: 0o600 });
    await assert.rejects(verifyW16DrillEvidence(value.file), { code: "invalid_evidence" });
  }
});

test("derives and bounds duration from canonical UTC timestamps", async (t) => {
  const value = await fixture(t);
  await writeFile(value.file, `${JSON.stringify({ ...VALID, duration_ms: 1 })}\n`, { mode: 0o600 });
  await assert.rejects(verifyW16DrillEvidence(value.file), { code: "invalid_evidence" });
  await writeFile(value.file, `${JSON.stringify({ ...VALID, completed_at: "2026-08-14T00:31:00.000Z", duration_ms: 1_860_000 })}\n`, { mode: 0o600 });
  await assert.rejects(verifyW16DrillEvidence(value.file), { code: "invalid_evidence" });
  await writeFile(value.file, `${JSON.stringify({ ...VALID, started_at: "2026-08-14T00:00:00+09:00" })}\n`, { mode: 0o600 });
  await assert.rejects(verifyW16DrillEvidence(value.file), { code: "invalid_evidence" });
  assert.equal(W16_DRILL_MAX_DURATION_MS, 1_800_000);
});

test("rejects symlink, hardlink, permissive, and oversized evidence", async (t) => {
  const value = await fixture(t);
  const symlinkFile = path.join(value.directory, "evidence-symlink.json");
  const hardlinkFile = path.join(value.directory, "evidence-hardlink.json");
  await symlink(value.file, symlinkFile);
  await assert.rejects(verifyW16DrillEvidence(symlinkFile), { code: "invalid_file" });
  await link(value.file, hardlinkFile);
  await assert.rejects(verifyW16DrillEvidence(value.file), { code: "invalid_file" });
  await rm(hardlinkFile);
  await chmod(value.file, 0o644);
  await assert.rejects(verifyW16DrillEvidence(value.file), { code: "invalid_file" });
  await chmod(value.file, 0o600);
  await writeFile(value.file, "x".repeat(W16_DRILL_MAX_BYTES + 1), { mode: 0o600 });
  await assert.rejects(verifyW16DrillEvidence(value.file), { code: "invalid_file" });
});

test("CLI emits only the evidence digest and never evidence content", async (t) => {
  const value = await fixture(t);
  const script = path.join(path.dirname(new URL(import.meta.url).pathname), "verify-w16-drill-evidence.mjs");
  const expected = crypto.createHash("sha256").update(await readFile(value.file)).digest("hex");
  const result = spawnSync(process.execPath, [script, value.file, "--commit-sha", COMMIT, "--image-digest", IMAGE, "--alert-policy-digest", ALERT_POLICY], { encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout, `${expected}\n`);
  assert.equal(result.stdout.includes("postgresql"), false);
  assert.equal(result.stderr, "");
});
