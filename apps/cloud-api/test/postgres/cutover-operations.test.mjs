import crypto from "node:crypto";
import fs from "node:fs/promises";
import assert from "node:assert/strict";
import test from "node:test";

import {
  CUTOVER_DIAGNOSTICS,
  CUTOVER_SCHEMA,
  createCutoverOperations,
  evaluateDrainGate,
  evaluateReadiness,
  executeCutoverCommand,
  executeTrafficRollback,
  fetchReadiness,
  normalizeMigrationStatus,
  parseCutoverArguments,
  readDrainFile,
  runCli,
  validateCutoverEnvironment
} from "../../../../scripts/postgres/cutover.mjs";
import { runControlPlaneCutoverPreflight } from "../../../../scripts/postgres/preflight-0011.mjs";

const NOW = new Date("2026-08-13T12:00:00.000Z");
const DATABASE_URL = "postgresql://operator:database-secret@db.example/agentpass?sslmode=verify-full";
const OPERATIONAL_SECRET = Buffer.alloc(32, 0x11).toString("base64url");
const DRAIN_SECRET = Buffer.alloc(32, 0x22).toString("base64url");
const TEST_MIGRATION = Object.freeze({ name: "0001_example.sql", sql: "BEGIN; SELECT 1; COMMIT;" });
const TEST_MIGRATION_CHECKSUM = crypto.createHash("sha256").update(TEST_MIGRATION.sql).digest("hex");
const MIGRATION_TARGET_MANIFEST = Object.freeze({
  schema: "agentpass.cutover.target.v1",
  target: { id: "prod-postgres-primary", database_url_sha256: crypto.createHash("sha256").update(DATABASE_URL).digest("hex"), migrations: [{ version: 1, checksum: TEST_MIGRATION_CHECKSUM }] },
  deployment: { id: "deploy-2026-08-13", revision: "release-2026-08-13", traffic_generation: "42", application_version: "cutover-operations" }
});
const DATABASE_ENV = Object.freeze({
  AGENTPASS_CLOUD_PROFILE: "hosted",
  AGENTPASS_DATABASE_URL: DATABASE_URL,
  AGENTPASS_OPERATIONAL_PROBE_SECRET: OPERATIONAL_SECRET,
  AGENTPASS_CUTOVER_TARGET_MANIFEST: JSON.stringify(MIGRATION_TARGET_MANIFEST),
  AGENTPASS_CUTOVER_APPLICATION_VERSION: "cutover-operations",
  AGENTPASS_CUTOVER_DRAIN_SECRET: DRAIN_SECRET
});
const CLEAN_PREFLIGHT = Object.freeze({ ok: true, validated: false, violations: [] });
const CLEAN_STATUS = Object.freeze({
  currentVersion: 11,
  applied: [{ version: 11, checksum: "a".repeat(64) }],
  pending: [],
  modified: [],
  dirty: false,
  dirtyRows: []
});

class QueryRecorder {
  constructor() { this.calls = []; }
  async query(text, params = []) {
    this.calls.push({ text, params });
    if (text.startsWith("SELECT 1")) return { rows: [{ ready: 1 }] };
    if (text.includes("pg_stat_activity")) return { rows: [{ lock_waits: 0 }] };
    return { rows: [] };
  }
}

function operations(overrides = {}) {
  const client = overrides.client ?? new QueryRecorder();
  return createCutoverOperations({
    client,
    migrations: [TEST_MIGRATION],
    applicationVersion: "cutover-operations",
    migrationTargetManifest: overrides.migrationTargetManifest ?? MIGRATION_TARGET_MANIFEST,
    drainSecret: Buffer.from(DRAIN_SECRET, "base64url"),
    preflightRunner: overrides.preflightRunner ?? (async () => CLEAN_PREFLIGHT),
    statusReader: overrides.statusReader ?? (async () => CLEAN_STATUS),
    databaseHealth: overrides.databaseHealth,
    metricsReader: overrides.metricsReader,
    applicationReadiness: overrides.applicationReadiness,
    trafficController: overrides.trafficController,
    migrationRunnerFactory: overrides.migrationRunnerFactory,
    now: () => NOW
  });
}

function canonicalDrainEvidence(input) {
  return JSON.stringify({
    schema: input.schema,
    deployment_id: input.deployment_id,
    revision: input.revision,
    traffic_generation: input.traffic_generation,
    nonce: input.nonce,
    drained: input.drained,
    active_requests: input.active_requests,
    oldest_request_age_ms: input.oldest_request_age_ms,
    observed_at: input.observed_at
  });
}

function signedDrain(overrides = {}) {
  const evidence = {
    schema: "agentpass.drain.v2",
    deployment_id: "deploy-2026-08-13",
    revision: "release-2026-08-13",
    traffic_generation: "42",
    nonce: "nonce-0123456789abcdef",
    drained: true,
    active_requests: 0,
    oldest_request_age_ms: 0,
    observed_at: "2026-08-13T11:59:45.000Z",
    ...overrides
  };
  return { ...evidence, signature: crypto.createHmac("sha256", Buffer.from(DRAIN_SECRET, "base64url")).update(canonicalDrainEvidence(evidence)).digest("base64url") };
}

test("CLI grammar is explicit and rejects unknown or secret-bearing arguments", () => {
  assert.deepEqual(parseCutoverArguments(["preflight"]), { command: "preflight" });
  assert.deepEqual(parseCutoverArguments(["migrate", "--apply"]), { command: "migrate", apply: true });
  assert.deepEqual(parseCutoverArguments(["rollback", "--confirm"]), { command: "rollback", confirm: true });
  assert.throws(() => parseCutoverArguments(["status", "--force"]), (error) => error.code === CUTOVER_DIAGNOSTICS.INVALID_ARGUMENT);
  assert.throws(() => parseCutoverArguments(["status", "--database-url=postgresql://operator:secret@db.example/db"]), (error) => error.code === CUTOVER_DIAGNOSTICS.INVALID_ARGUMENT);
  assert.throws(() => parseCutoverArguments(["migrate"]), (error) => error.code === CUTOVER_DIAGNOSTICS.INVALID_ARGUMENT);
});

test("environment validation is hosted-only, allow-listed, secret-complete, and pins the exact target manifest", () => {
  assert.equal(validateCutoverEnvironment(DATABASE_ENV, { requireMigrationManifest: true }).migrationTargetManifest.target.id, "prod-postgres-primary");
  assert.throws(() => validateCutoverEnvironment({ ...DATABASE_ENV, AGENTPASS_CUTOVER_UNKNOWN: "x" }), (error) => error.code === CUTOVER_DIAGNOSTICS.INVALID_ENVIRONMENT);
  assert.throws(() => validateCutoverEnvironment({ ...DATABASE_ENV, AGENTPASS_CLOUD_PROFILE: "evaluation" }), (error) => error.code === CUTOVER_DIAGNOSTICS.INVALID_ENVIRONMENT);
  assert.throws(() => validateCutoverEnvironment({ ...DATABASE_ENV, AGENTPASS_DATABASE_URL: `${DATABASE_URL}&application_name=cutover` }), (error) => error.code === CUTOVER_DIAGNOSTICS.INVALID_ENVIRONMENT);
  assert.throws(() => validateCutoverEnvironment({ ...DATABASE_ENV, AGENTPASS_DATABASE_URL: `${DATABASE_URL}&sslmode=verify-full` }), (error) => error.code === CUTOVER_DIAGNOSTICS.INVALID_ENVIRONMENT);
  assert.throws(() => validateCutoverEnvironment({ ...DATABASE_ENV, AGENTPASS_OPERATIONAL_PROBE_SECRET: "short" }), (error) => error.code === CUTOVER_DIAGNOSTICS.INVALID_ENVIRONMENT);
  assert.throws(() => validateCutoverEnvironment({ ...DATABASE_ENV, AGENTPASS_CUTOVER_TARGET_MANIFEST: JSON.stringify({ ...MIGRATION_TARGET_MANIFEST, target: { ...MIGRATION_TARGET_MANIFEST.target, database_url_sha256: "0".repeat(64) } }) }, { requireMigrationManifest: true }), (error) => error.code === CUTOVER_DIAGNOSTICS.INVALID_ENVIRONMENT);
  assert.throws(() => validateCutoverEnvironment({ ...DATABASE_ENV, AGENTPASS_CUTOVER_READINESS_URL: "https://169.254.169.254/health/ready", AGENTPASS_CUTOVER_READINESS_ALLOWED_ORIGIN: "https://health.example" }), (error) => error.code === CUTOVER_DIAGNOSTICS.INVALID_ENVIRONMENT);
});

test("preflight operation is read-only and never invokes validation", async () => {
  const calls = [];
  const control = operations({ preflightRunner: async ({ validate }) => { calls.push(validate); return CLEAN_PREFLIGHT; } });
  const result = await executeCutoverCommand({ command: "preflight", operations: control });
  assert.deepEqual(calls, [false]);
  assert.deepEqual(result, { schema: CUTOVER_SCHEMA, ok: true, command: "preflight", phase: "preflight", code: "OK", result: { ok: true, validated: false, violation_count: 0 } });
});

test("the real preflight dependency is SELECT-only when the cutover wrapper calls it", async () => {
  const client = new QueryRecorder();
  const control = createCutoverOperations({ client, migrations: [{ name: "0001_example.sql", sql: "BEGIN; SELECT 1; COMMIT;" }], preflightRunner: runControlPlaneCutoverPreflight });
  const result = await control.preflight();
  assert.deepEqual(result, { ok: true, validated: false, violation_count: 0 });
  assert.equal(client.calls.some(({ text }) => /\b(?:BEGIN|COMMIT|ROLLBACK|INSERT|UPDATE|DELETE|ALTER|CREATE|DROP)\b/iu.test(text)), false);
});

test("migrate fails closed unless the exact pinned migration set matches", async () => {
  const calls = [];
  const control = operations({ migrationRunnerFactory: ({ applicationVersion, migrations }) => ({ async run() { calls.push({ applicationVersion, migrations }); return { applied: [{ version: 1, checksum: TEST_MIGRATION_CHECKSUM }], currentVersion: 1 }; } }) });
  const result = await executeCutoverCommand({ command: "migrate", options: { apply: true }, operations: control });
  assert.equal(calls[0].migrations[0].checksum, TEST_MIGRATION_CHECKSUM);
  assert.equal(calls[0].applicationVersion, "cutover-operations");
  assert.deepEqual(result.result.migration, { applied_versions: [1], current_version: 1 });
  assert.doesNotMatch(JSON.stringify(result), /database-secret|down.?migration|rollback/i);
  await assert.rejects(() => createCutoverOperations({ client: new QueryRecorder(), migrations: [], applicationVersion: "cutover-operations" }).migrate(), (error) => error.code === CUTOVER_DIAGNOSTICS.INVALID_ENVIRONMENT);
  await assert.rejects(() => operations({ migrationTargetManifest: { ...MIGRATION_TARGET_MANIFEST, target: { ...MIGRATION_TARGET_MANIFEST.target, migrations: [{ version: 1, checksum: "f".repeat(64) }] } } }).migrate(), (error) => error.code === CUTOVER_DIAGNOSTICS.INVALID_ENVIRONMENT);
  assert.deepEqual(normalizeMigrationStatus(CLEAN_STATUS), { expected_version: 11, database_version: 11, applied_versions: [11], pending_versions: [], modified_versions: [], dirty: false, dirty_versions: [] });
});

test("readiness requires available metrics and configured application readiness", async () => {
  const ready = await evaluateReadiness({
    status: async () => ({ expected_version: 11, database_version: 11, applied_versions: [11], pending_versions: [], modified_versions: [], dirty: false, dirty_versions: [] }),
    preflight: async () => CLEAN_PREFLIGHT,
    databaseHealth: async () => ({ ready: true, code: "ready" }),
    metrics: async () => ({ available: true, lock_waits: 0, pool: { total: 2, idle: 2, waiting: 0 } }),
    applicationReadiness: async () => ({ configured: true, ready: true }), now: () => NOW
  });
  assert.equal(ready.ready, true);
  for (const [metrics, application] of [[{ available: false, lock_waits: null, pool: null }, { configured: true, ready: true }], [{ available: true, lock_waits: 0, pool: null }, { configured: false, ready: true }]]) {
    const blocked = await evaluateReadiness({ status: async () => CLEAN_STATUS, preflight: async () => CLEAN_PREFLIGHT, databaseHealth: async () => ({ ready: true }), metrics: async () => metrics, applicationReadiness: async () => application, now: () => NOW });
    assert.equal(blocked.ready, false);
  }
});

test("drain evidence is authenticated and bound to deployment, revision, traffic generation, and nonce", () => {
  const fresh = signedDrain();
  const expectedBinding = MIGRATION_TARGET_MANIFEST.deployment;
  assert.deepEqual(evaluateDrainGate({ input: fresh, secret: Buffer.from(DRAIN_SECRET, "base64url"), expectedBinding, now: () => NOW, maxAgeMs: 30_000 }), { ready: true, observed_at: fresh.observed_at, age_ms: 15_000, active_requests: 0 });
  for (const change of [{ signature: "A".repeat(43) }, { revision: "other" }, { traffic_generation: "43" }, { deployment_id: "other" }, { nonce: "nonce-other-0123456789" }]) {
    assert.equal(evaluateDrainGate({ input: { ...fresh, ...change }, secret: DRAIN_SECRET, expectedBinding, now: () => NOW }).ready, false);
  }
  assert.equal(evaluateDrainGate({ input: { ...fresh, active_requests: 1 }, secret: DRAIN_SECRET, expectedBinding, now: () => NOW }).code, CUTOVER_DIAGNOSTICS.DRAIN_REQUIRED);
  assert.equal(evaluateDrainGate({ input: { ...fresh, extra: "secret" }, secret: DRAIN_SECRET, expectedBinding, now: () => NOW }).code, CUTOVER_DIAGNOSTICS.DRAIN_INPUT_INVALID);
  assert.equal(evaluateDrainGate({ input: fresh, expectedBinding, now: () => NOW }).code, CUTOVER_DIAGNOSTICS.DRAIN_INPUT_INVALID);
  assert.equal(evaluateDrainGate({ input: signedDrain({ observed_at: "2026-08-13T11:58:00.000Z" }), secret: DRAIN_SECRET, expectedBinding, now: () => NOW, maxAgeMs: 30_000 }).code, CUTOVER_DIAGNOSTICS.DRAIN_REQUIRED);
});

test("readiness sends the required operational token only to the explicitly allowed origin and streams a hard 64KiB cap", async () => {
  let request;
  const response = { ok: true, body: { getReader() { let done = false; return { async read() { if (done) return { done: true }; done = true; return { done: false, value: new TextEncoder().encode('{"ready":true}') }; }, releaseLock() {} }; } } };
  const result = await fetchReadiness("https://health.example/health/ready", 5_000, async (url, options) => { request = { url, options }; return response; }, OPERATIONAL_SECRET, "https://health.example");
  assert.deepEqual(result, { configured: true, ready: true });
  assert.equal(request.options.headers["AgentPass-Operational-Token"], OPERATIONAL_SECRET);
  assert.equal(JSON.stringify(result).includes(OPERATIONAL_SECRET), false);
  assert.deepEqual(await fetchReadiness("https://health.example/health/ready", 5_000, async () => ({ ok: true, body: { getReader() { return { async read() { return { done: false, value: new Uint8Array(64 * 1024 + 1) }; }, async cancel() {}, releaseLock() {} }; } } }), OPERATIONAL_SECRET, "https://health.example"), { configured: true, ready: false });
  await assert.rejects(() => fetchReadiness("https://169.254.169.254/health/ready", 5_000, async () => response, OPERATIONAL_SECRET, "https://health.example"));
});

test("cutover gate keeps current traffic when either readiness or drain fails", async () => {
  const result = await executeCutoverCommand({ command: "cutover", operations: { async readiness() { return { ready: false, schema: null }; }, async drain() { return { ready: true, active_requests: 0 }; } }, drainInput: {} });
  assert.equal(result.ok, false);
  assert.equal(result.code, CUTOVER_DIAGNOSTICS.NOT_READY);
  assert.equal(result.result.ready, false);
});

test("rollback only calls the injected application traffic controller and never exposes a schema rollback", async () => {
  const calls = [];
  const result = await executeTrafficRollback({ trafficController: { async rollbackApplicationTraffic(input) { calls.push(input); } }, reason: "test rollback" });
  assert.deepEqual(calls, [{ reason: "test rollback" }]);
  assert.deepEqual(result, { action: "rollback_application_traffic", executed: true, schema_action: "none", down_migration: "forbidden" });
  assert.deepEqual(await executeTrafficRollback(), { action: "rollback_application_traffic", executed: false, requires_external_traffic_controller: true, schema_action: "none", down_migration: "forbidden", reason: "operator-requested cutover rollback" });
  const noController = await executeCutoverCommand({ command: "rollback", options: { confirm: true }, operations: { async rollback() { return executeTrafficRollback(); } } });
  assert.equal(noController.ok, false);
  assert.equal(noController.code, CUTOVER_DIAGNOSTICS.ROLLBACK_ACTION_REQUIRED);
});

test("CLI errors are stable and do not echo secret-bearing argv or environment", async () => {
  const unknownArg = await runCli(["status", "--token=database-secret"], DATABASE_ENV, { operations: {} });
  assert.equal(unknownArg.ok, false);
  assert.equal(unknownArg.code, CUTOVER_DIAGNOSTICS.INVALID_ARGUMENT);
  assert.doesNotMatch(JSON.stringify(unknownArg), /database-secret|token/iu);
  const unknownEnv = await runCli(["status"], { ...DATABASE_ENV, AGENTPASS_CUTOVER_SECRET: "database-secret" }, { operations: {} });
  assert.equal(unknownEnv.ok, false);
  assert.equal(unknownEnv.code, CUTOVER_DIAGNOSTICS.INVALID_ENVIRONMENT);
  assert.doesNotMatch(JSON.stringify(unknownEnv), /database-secret|AGENTPASS_CUTOVER_SECRET/iu);
});

test("drain input is bounded and must be a regular file; path/content/secret are not emitted", async () => {
  const file = "/tmp/agentpass-cutover-drain-operations-test.json";
  const link = "/tmp/agentpass-cutover-drain-operations-test-link.json";
  await fs.writeFile(file, JSON.stringify(signedDrain()), { mode: 0o600 });
  try {
    const result = await runCli(["drain", "--drain-file", file], DATABASE_ENV, { now: () => NOW, operations: { async drain(input) { return evaluateDrainGate({ input, now: () => NOW, secret: DRAIN_SECRET, expectedBinding: MIGRATION_TARGET_MANIFEST.deployment }); } } });
    assert.equal(result.ok, true);
    assert.doesNotMatch(JSON.stringify(result), /agentpass-cutover-drain-operations-test|database-secret|AgentPass-Operational-Token/);
    await assert.rejects(() => readDrainFile("/tmp"), (error) => error.code === CUTOVER_DIAGNOSTICS.DRAIN_INPUT_INVALID);
    await fs.symlink(file, link);
    await assert.rejects(() => readDrainFile(link), (error) => error.code === CUTOVER_DIAGNOSTICS.DRAIN_INPUT_INVALID);
    await fs.writeFile(file, "x".repeat(64 * 1024 + 1));
    await assert.rejects(() => readDrainFile(file), (error) => error.code === CUTOVER_DIAGNOSTICS.DRAIN_INPUT_INVALID);
  } finally {
    await fs.unlink(file).catch(() => {});
    await fs.unlink(link).catch(() => {});
  }
});
