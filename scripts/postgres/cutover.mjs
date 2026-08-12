#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs/promises";
import { constants as FS_CONSTANTS } from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";

import { Pool } from "pg";

import {
  ControlPlaneCutoverPreflightError,
  runControlPlaneCutoverPreflight
} from "./preflight-0011.mjs";
import {
  createMigrationRunner,
  defaultContractDirectory,
  loadSqlMigrations,
  migrationStatus,
  normalizeMigrations
} from "../../apps/cloud-api/src/postgres/migration-runner.mjs";

export const CUTOVER_SCHEMA = "agentpass.cutover.v1";
export const CUTOVER_COMMANDS = Object.freeze([
  "preflight",
  "status",
  "migrate",
  "validate",
  "readiness",
  "drain",
  "cutover",
  "rollback"
]);

export const CUTOVER_DIAGNOSTICS = Object.freeze({
  INVALID_ARGUMENT: "AGENTPASS_CUTOVER_INVALID_ARGUMENT",
  INVALID_ENVIRONMENT: "AGENTPASS_CUTOVER_INVALID_ENVIRONMENT",
  DATABASE_UNAVAILABLE: "AGENTPASS_CUTOVER_DATABASE_UNAVAILABLE",
  PREFLIGHT_BLOCKED: "AGENTPASS_CUTOVER_PREFLIGHT_BLOCKED",
  MIGRATION_BLOCKED: "AGENTPASS_CUTOVER_MIGRATION_BLOCKED",
  VALIDATION_BLOCKED: "AGENTPASS_CUTOVER_VALIDATION_BLOCKED",
  NOT_READY: "AGENTPASS_CUTOVER_NOT_READY",
  DRAIN_REQUIRED: "AGENTPASS_CUTOVER_DRAIN_REQUIRED",
  DRAIN_INPUT_INVALID: "AGENTPASS_CUTOVER_DRAIN_INPUT_INVALID",
  ROLLBACK_ACTION_REQUIRED: "AGENTPASS_CUTOVER_ROLLBACK_ACTION_REQUIRED",
  ROLLBACK_FAILED: "AGENTPASS_CUTOVER_ROLLBACK_FAILED"
});

const ALLOWED_ENVIRONMENT_KEYS = new Set([
  "AGENTPASS_CLOUD_PROFILE",
  "AGENTPASS_DATABASE_URL",
  "AGENTPASS_OPERATIONAL_PROBE_SECRET",
  "AGENTPASS_CUTOVER_APPLICATION_VERSION",
  "AGENTPASS_CUTOVER_TARGET_MANIFEST",
  "AGENTPASS_CUTOVER_READINESS_URL",
  "AGENTPASS_CUTOVER_READINESS_ALLOWED_ORIGIN",
  "AGENTPASS_CUTOVER_READINESS_TIMEOUT_MS",
  "AGENTPASS_CUTOVER_DRAIN_MAX_AGE_MS",
  "AGENTPASS_CUTOVER_DRAIN_SECRET"
]);
const INTEGER_ENVIRONMENT_KEYS = new Set([
  "AGENTPASS_CUTOVER_READINESS_TIMEOUT_MS",
  "AGENTPASS_CUTOVER_DRAIN_MAX_AGE_MS"
]);
const DEFAULT_READINESS_TIMEOUT_MS = 5_000;
const DEFAULT_DRAIN_MAX_AGE_MS = 30_000;
const MAX_READINESS_TIMEOUT_MS = 30_000;
const MAX_DRAIN_MAX_AGE_MS = 300_000;
const MAX_DRAIN_INPUT_BYTES = 64 * 1024;
const DRAIN_SCHEMA = "agentpass.drain.v2";
const TARGET_MANIFEST_SCHEMA = "agentpass.cutover.target.v1";
const SECRET_BYTES = 32;
const SENSITIVE_ARGUMENT = /(?:password|passwd|secret|token|bearer|credential|private[_-]?key|database[_-]?url|connection[_-]?string)/iu;

export class CutoverOperationsError extends Error {
  constructor(code, message, remediation, cause = undefined) {
    super(message, cause === undefined ? undefined : { cause });
    this.name = "CutoverOperationsError";
    this.code = code;
    this.remediation = remediation;
    if (cause !== undefined) this.cause = cause;
  }
}

export function parseCutoverArguments(argv = []) {
  if (!Array.isArray(argv) || argv.length === 0) {
    throw invalidArgument("a command is required");
  }
  const [command, ...rest] = argv;
  if (!CUTOVER_COMMANDS.includes(command)) throw invalidArgument("unknown command");

  const options = { command };
  const allowed = commandOptions(command);
  for (let index = 0; index < rest.length; index += 1) {
    const argument = rest[index];
    if (typeof argument !== "string" || SENSITIVE_ARGUMENT.test(argument)) {
      throw invalidArgument("unsupported or secret-bearing argument");
    }
    if (!allowed.has(argument) && !(argument.startsWith("--drain-file=") && ["drain", "cutover"].includes(command))) {
      throw invalidArgument("unknown argument");
    }
    if (argument === "--apply") {
      if (options.apply) throw invalidArgument("duplicate flag");
      options.apply = true;
      continue;
    }
    if (argument === "--confirm") {
      if (options.confirm) throw invalidArgument("duplicate flag");
      options.confirm = true;
      continue;
    }
    if (argument === "--drain-file") {
      if (options.drainFile !== undefined || index + 1 >= rest.length) throw invalidArgument("drain file is missing");
      options.drainFile = assertSafePathArgument(rest[++index]);
      continue;
    }
    if (argument.startsWith("--drain-file=")) {
      if (options.drainFile !== undefined) throw invalidArgument("duplicate drain file");
      options.drainFile = assertSafePathArgument(argument.slice("--drain-file=".length));
    }
  }

  if (["migrate", "validate"].includes(command) && options.apply !== true) {
    throw invalidArgument(`${command} requires --apply`);
  }
  if (command === "rollback" && options.confirm !== true) {
    throw invalidArgument("rollback requires --confirm");
  }
  if (["drain", "cutover"].includes(command) && options.drainFile === undefined) {
    throw invalidArgument(`${command} requires --drain-file`);
  }
  return Object.freeze(options);
}

export function validateCutoverEnvironment(env = {}, { requireMigrationManifest = false, requireDrainEvidence = false } = {}) {
  if (!env || typeof env !== "object" || Array.isArray(env)) {
    throw invalidEnvironment();
  }
  for (const key of Object.keys(env)) {
    if (key.startsWith("AGENTPASS_CUTOVER_") && !ALLOWED_ENVIRONMENT_KEYS.has(key)) {
      throw invalidEnvironment();
    }
  }
  if (env.AGENTPASS_CLOUD_PROFILE !== "hosted") throw invalidEnvironment();
  if (typeof env.AGENTPASS_DATABASE_URL !== "string") throw invalidEnvironment();
  assertDatabaseUrl(env.AGENTPASS_DATABASE_URL);
  decodeExactBase64UrlSecret(env.AGENTPASS_OPERATIONAL_PROBE_SECRET, "operational probe secret");
  for (const key of INTEGER_ENVIRONMENT_KEYS) {
    if (env[key] !== undefined) parseBoundedInteger(env[key], key, key === "AGENTPASS_CUTOVER_READINESS_TIMEOUT_MS" ? 250 : 1_000, key === "AGENTPASS_CUTOVER_READINESS_TIMEOUT_MS" ? MAX_READINESS_TIMEOUT_MS : MAX_DRAIN_MAX_AGE_MS);
  }
  const readinessUrl = env.AGENTPASS_CUTOVER_READINESS_URL;
  const readinessOrigin = env.AGENTPASS_CUTOVER_READINESS_ALLOWED_ORIGIN;
  if (readinessUrl !== undefined) assertReadinessUrl(readinessUrl, readinessOrigin);
  else if (readinessOrigin !== undefined) throw invalidEnvironment();
  const applicationVersion = validateApplicationVersion(env.AGENTPASS_CUTOVER_APPLICATION_VERSION ?? "cutover-operations");
  const migrationTargetManifest = env.AGENTPASS_CUTOVER_TARGET_MANIFEST === undefined
    ? undefined
    : parseMigrationTargetManifest(env.AGENTPASS_CUTOVER_TARGET_MANIFEST, env.AGENTPASS_DATABASE_URL, applicationVersion);
  if (requireMigrationManifest && migrationTargetManifest === undefined) throw invalidEnvironment();
  if (requireDrainEvidence) decodeExactBase64UrlSecret(env.AGENTPASS_CUTOVER_DRAIN_SECRET, "drain evidence secret");
  return Object.freeze({
    applicationVersion,
    migrationTargetManifest,
    readinessUrl: readinessUrl === undefined ? undefined : readinessUrl,
    readinessAllowedOrigin: readinessOrigin === undefined ? undefined : readinessOrigin,
    readinessTimeoutMs: env.AGENTPASS_CUTOVER_READINESS_TIMEOUT_MS === undefined ? DEFAULT_READINESS_TIMEOUT_MS : Number(env.AGENTPASS_CUTOVER_READINESS_TIMEOUT_MS),
    drainMaxAgeMs: env.AGENTPASS_CUTOVER_DRAIN_MAX_AGE_MS === undefined ? DEFAULT_DRAIN_MAX_AGE_MS : Number(env.AGENTPASS_CUTOVER_DRAIN_MAX_AGE_MS)
  });
}

export function createCutoverOperations({
  client,
  pool = undefined,
  migrations = undefined,
  migrationDirectory = defaultContractDirectory(),
  applicationVersion = "cutover-operations",
  migrationTargetManifest = undefined,
  drainSecret = undefined,
  preflightRunner = runControlPlaneCutoverPreflight,
  statusReader = migrationStatus,
  migrationRunnerFactory = createMigrationRunner,
  databaseHealth = defaultDatabaseHealth,
  metricsReader = defaultMetrics,
  applicationReadiness = async () => ({ configured: false, ready: false }),
  trafficController = undefined,
  now = () => new Date()
} = {}) {
  if (!client || typeof client.query !== "function") throw new TypeError("cutover client must provide query(text, params)");
  if (typeof applicationVersion !== "string" || applicationVersion.length < 1 || applicationVersion.length > 64 || /[\u0000-\u001f\u007f]/u.test(applicationVersion)) throw new TypeError("cutover application version is invalid");
  if (migrationTargetManifest !== undefined) assertMigrationTargetManifest(migrationTargetManifest, applicationVersion);
  let migrationPromise;
  const resolveMigrations = async () => {
    if (migrations !== undefined) return normalizeMigrations(migrations);
    if (!migrationPromise) migrationPromise = loadSqlMigrations(migrationDirectory);
    return migrationPromise;
  };

  const readStatus = async () => {
    const status = await statusReader({ client, migrations: resolveMigrations() });
    return normalizeMigrationStatus(status);
  };
  const readPreflight = async () => preflightRunner({ client, validate: false });

  return Object.freeze({
    async preflight() {
      return normalizePreflight(await readPreflight());
    },
    async status() {
      return readStatus();
    },
    async migrate() {
      assertMigrationTargetManifest(migrationTargetManifest, applicationVersion);
      const preflight = await readPreflight();
      const resolved = await resolveMigrations();
      assertPinnedMigrations(resolved, migrationTargetManifest.target.migrations);
      const runner = migrationRunnerFactory({ client, migrations: resolved, applicationVersion });
      const result = await runner.run();
      return Object.freeze({ preflight: normalizePreflight(preflight), migration: normalizeMigrationRun(result), status: await readStatus() });
    },
    async validate() {
      return normalizePreflight(await preflightRunner({ client, validate: true }), true);
    },
    async readiness() {
      return evaluateReadiness({
        status: readStatus,
        preflight: readPreflight,
        databaseHealth: () => databaseHealth({ client }),
        metrics: () => metricsReader({ client, pool }),
        applicationReadiness,
        now
      });
    },
    async drain(input, { maxAgeMs = DEFAULT_DRAIN_MAX_AGE_MS } = {}) {
      return evaluateDrainGate({ input, now, maxAgeMs, secret: drainSecret, expectedBinding: migrationTargetManifest?.deployment });
    },
    async rollback({ reason = "cutover rollback requested" } = {}) {
      return executeTrafficRollback({ trafficController, reason });
    }
  });
}

export async function executeCutoverCommand({ command, options = {}, operations, drainInput = undefined } = {}) {
  if (!operations || typeof operations !== "object") throw new TypeError("cutover operations are required");
  if (["migrate", "validate"].includes(command) && options.apply !== true) throw invalidArgument(`${command} requires --apply`);
  if (command === "rollback" && options.confirm !== true) throw invalidArgument("rollback requires --confirm");
  switch (command) {
    case "preflight":
      return success(command, "preflight", await operations.preflight());
    case "status":
      return success(command, "status", await operations.status());
    case "migrate":
      return success(command, "migrate", await operations.migrate());
    case "validate":
      return success(command, "validate", await operations.validate());
    case "readiness": {
      const result = await operations.readiness();
      return result.ready ? success(command, "readiness", result) : failure(command, "readiness", CUTOVER_DIAGNOSTICS.NOT_READY, "cutover readiness checks did not pass", "Resolve every failing readiness check and rerun this command.", result);
    }
    case "drain": {
      const result = await operations.drain(drainInput);
      return result.ready ? success(command, "drain", result) : failure(command, "drain", CUTOVER_DIAGNOSTICS.DRAIN_REQUIRED, "application traffic is not drained", "Stop new application traffic, wait for active requests to reach zero, and submit a fresh drain gate input.", result);
    }
    case "cutover": {
      const readiness = await operations.readiness();
      const drain = await operations.drain(drainInput);
      const result = Object.freeze({ readiness, drain, ready: readiness.ready && drain.ready });
      return result.ready ? success(command, "cutover", result) : failure(command, "cutover", readiness.ready ? CUTOVER_DIAGNOSTICS.DRAIN_REQUIRED : CUTOVER_DIAGNOSTICS.NOT_READY, "cutover gates did not pass", "Keep the current application traffic path, resolve the failing gate, and rerun the cutover command.", result);
    }
    case "rollback": {
      const result = await operations.rollback({ reason: "operator-requested cutover rollback" });
      return result.executed === true
        ? success(command, "rollback", result)
        : failure(command, "rollback", CUTOVER_DIAGNOSTICS.ROLLBACK_ACTION_REQUIRED, "application traffic rollback was not executed", "Invoke the reviewed deployment traffic controller, then verify readiness; never down-migrate the committed database schema.", result);
    }
    default:
      throw invalidArgument("unknown command");
  }
}

export async function evaluateReadiness({ status, preflight, databaseHealth, metrics, applicationReadiness, now = () => new Date() } = {}) {
  if (typeof status !== "function" || typeof preflight !== "function" || typeof databaseHealth !== "function" || typeof metrics !== "function" || typeof applicationReadiness !== "function") throw new TypeError("readiness probes are incomplete");
  const checks = {};
  try { checks.status = await status(); } catch { checks.status = null; }
  try { checks.preflight = normalizePreflight(await preflight()); } catch (error) { checks.preflight = { ok: false, code: stablePreflightCode(error) }; }
  try { checks.database = normalizeDatabaseHealth(await databaseHealth()); } catch { checks.database = { ready: false, code: "database_unavailable" }; }
  try { checks.metrics = normalizeMetrics(await metrics()); } catch { checks.metrics = { available: false, lock_waits: null, pool: null }; }
  try { checks.application = normalizeApplicationReadiness(await applicationReadiness()); } catch { checks.application = { configured: true, ready: false }; }
  const statusReady = checks.status !== null
    && Array.isArray(checks.status.pending_versions)
    && Array.isArray(checks.status.modified_versions)
    && checks.status.pending_versions.length === 0
    && checks.status.modified_versions.length === 0
    && checks.status.dirty === false;
  const ready = statusReady
    && checks.preflight.ok === true
    && checks.database.ready === true
    && checks.metrics.available === true
    && checks.application.configured === true
    && checks.application.ready === true;
  return Object.freeze({
    ready,
    observed_at: validIsoTimestamp(now),
    schema: checks.status,
    preflight: checks.preflight,
    database: checks.database,
    application: checks.application,
    metrics: checks.metrics
  });
}

export function evaluateDrainGate({ input, now = () => new Date(), maxAgeMs = DEFAULT_DRAIN_MAX_AGE_MS, secret = undefined, expectedBinding = undefined } = {}) {
  if (!Number.isSafeInteger(maxAgeMs) || maxAgeMs < 1_000 || maxAgeMs > MAX_DRAIN_MAX_AGE_MS) throw new TypeError("drain max age is invalid");
  if (!input || typeof input !== "object" || Array.isArray(input)) return Object.freeze({ ready: false, code: CUTOVER_DIAGNOSTICS.DRAIN_INPUT_INVALID });
  const allowedKeys = new Set(["schema", "deployment_id", "revision", "traffic_generation", "nonce", "drained", "active_requests", "oldest_request_age_ms", "observed_at", "signature"]);
  if (Object.keys(input).some((key) => !allowedKeys.has(key))) return Object.freeze({ ready: false, code: CUTOVER_DIAGNOSTICS.DRAIN_INPUT_INVALID });
  if (input.schema !== DRAIN_SCHEMA || input.drained !== true || input.active_requests !== 0 || input.oldest_request_age_ms !== 0) return Object.freeze({ ready: false, code: CUTOVER_DIAGNOSTICS.DRAIN_REQUIRED });
  if (!isSafeBindingValue(input.deployment_id) || !isSafeBindingValue(input.revision) || !isSafeBindingValue(input.traffic_generation) || !isSafeNonce(input.nonce) || !isBase64UrlSignature(input.signature)) return Object.freeze({ ready: false, code: CUTOVER_DIAGNOSTICS.DRAIN_INPUT_INVALID });
  if (!expectedBindingMatches(input, expectedBinding)) return Object.freeze({ ready: false, code: CUTOVER_DIAGNOSTICS.DRAIN_REQUIRED });
  if (!verifyDrainEvidence(input, secret)) return Object.freeze({ ready: false, code: CUTOVER_DIAGNOSTICS.DRAIN_INPUT_INVALID });
  const observed = parseTimestamp(input.observed_at);
  if (!observed) return Object.freeze({ ready: false, code: CUTOVER_DIAGNOSTICS.DRAIN_INPUT_INVALID });
  const current = now instanceof Function ? now() : now;
  const currentMs = current instanceof Date ? current.getTime() : NaN;
  const ageMs = currentMs - observed.getTime();
  if (!Number.isFinite(currentMs) || ageMs < -5_000 || ageMs > maxAgeMs) return Object.freeze({ ready: false, code: CUTOVER_DIAGNOSTICS.DRAIN_REQUIRED });
  return Object.freeze({ ready: true, observed_at: observed.toISOString(), age_ms: Math.max(0, Math.floor(ageMs)), active_requests: 0 });
}

export async function executeTrafficRollback({ trafficController, reason } = {}) {
  if (trafficController === undefined) {
    return Object.freeze({
      action: "rollback_application_traffic",
      executed: false,
      requires_external_traffic_controller: true,
      schema_action: "none",
      down_migration: "forbidden",
      reason: "operator-requested cutover rollback"
    });
  }
  if (typeof trafficController.rollbackApplicationTraffic !== "function") throw new CutoverOperationsError(CUTOVER_DIAGNOSTICS.ROLLBACK_FAILED, "traffic rollback controller is invalid", "Configure a reviewed deployment traffic controller; never run a down-migration.");
  try {
    await trafficController.rollbackApplicationTraffic({ reason });
  } catch (error) {
    throw new CutoverOperationsError(CUTOVER_DIAGNOSTICS.ROLLBACK_FAILED, "application traffic rollback failed", "Keep the database schema at its committed version and resolve the deployment traffic controller failure.", error);
  }
  return Object.freeze({ action: "rollback_application_traffic", executed: true, schema_action: "none", down_migration: "forbidden" });
}

export function normalizeMigrationStatus(status) {
  if (!status || !Array.isArray(status.applied) || !Array.isArray(status.pending) || !Array.isArray(status.modified) || !Array.isArray(status.dirtyRows)) throw new Error("invalid migration status");
  return Object.freeze({
    expected_version: Number(status.currentVersion),
    database_version: status.applied.length === 0 ? 0 : Number(status.applied.at(-1).version),
    applied_versions: Object.freeze(status.applied.map((row) => Number(row.version))),
    pending_versions: Object.freeze(status.pending.map(Number)),
    modified_versions: Object.freeze(status.modified.map(Number)),
    dirty: status.dirty === true,
    dirty_versions: Object.freeze(status.dirtyRows.map((row) => Number(row.version)))
  });
}

export function normalizePreflight(result, allowValidated = false) {
  if (!result || result.ok !== true || (result.validated !== false && !(allowValidated && result.validated === true)) || !Array.isArray(result.violations)) throw new Error("invalid preflight result");
  return Object.freeze({ ok: true, validated: result.validated === true, violation_count: result.violations.reduce((sum, item) => sum + Number(item.count), 0) });
}

function normalizeMigrationRun(result) {
  if (!result || !Array.isArray(result.applied)) throw new Error("invalid migration result");
  return Object.freeze({ applied_versions: Object.freeze(result.applied.map((row) => Number(row.version))), current_version: Number(result.currentVersion) });
}

function normalizeDatabaseHealth(result) {
  return Object.freeze({ ready: result?.ready === true, code: result?.ready === true ? "ready" : "database_unavailable" });
}

function normalizeMetrics(result) {
  const lockWaits = result?.lock_waits;
  const pool = result?.pool;
  if (lockWaits !== null && (!Number.isSafeInteger(lockWaits) || lockWaits < 0)) throw new Error("invalid lock wait metric");
  if (pool !== null && (pool === undefined || !Number.isSafeInteger(pool.total) || !Number.isSafeInteger(pool.idle) || !Number.isSafeInteger(pool.waiting) || pool.total < 0 || pool.idle < 0 || pool.waiting < 0 || pool.idle > pool.total)) throw new Error("invalid pool metric");
  return Object.freeze({ available: result?.available === true, lock_waits: lockWaits ?? null, pool: pool ?? null });
}

function normalizeApplicationReadiness(result) {
  return Object.freeze({ configured: result?.configured === true, ready: result?.ready === true });
}

async function defaultDatabaseHealth({ client }) {
  const result = await client.query("SELECT 1 AS ready", []);
  return { ready: result?.rows?.[0]?.ready === 1, code: result?.rows?.[0]?.ready === 1 ? "ready" : "database_unavailable" };
}

async function defaultMetrics({ client, pool }) {
  const lockResult = await client.query("SELECT count(*)::int AS lock_waits FROM pg_stat_activity WHERE wait_event_type = 'Lock' AND state = 'active'", []);
  const row = lockResult?.rows?.[0];
  const lockWaits = Number(row?.lock_waits);
  if (!Number.isSafeInteger(lockWaits) || lockWaits < 0) throw new Error("invalid lock wait metric");
  const poolMetrics = pool && ["totalCount", "idleCount", "waitingCount"].every((key) => Number.isSafeInteger(pool[key]))
    ? { total: pool.totalCount, idle: pool.idleCount, waiting: pool.waitingCount }
    : null;
  return { available: true, lock_waits: lockWaits, pool: poolMetrics };
}

function commandOptions(command) {
  if (["migrate", "validate"].includes(command)) return new Set(["--apply"]);
  if (command === "rollback") return new Set(["--confirm"]);
  if (["drain", "cutover"].includes(command)) return new Set(["--drain-file"]);
  return new Set();
}

function assertSafePathArgument(value) {
  if (typeof value !== "string" || value.length < 1 || value.length > 1_024 || value.startsWith("-") || !path.isAbsolute(value)) throw invalidArgument("drain file path is invalid");
  return value;
}

function validateApplicationVersion(value) {
  if (typeof value !== "string" || value.length < 1 || value.length > 64 || /[^A-Za-z0-9._:-]/u.test(value)) throw invalidEnvironment();
  return value;
}

function parseBoundedInteger(value, name, min, max) {
  if (typeof value !== "string" || !/^\d+$/u.test(value)) throw invalidEnvironment();
  const number = Number(value);
  if (!Number.isSafeInteger(number) || number < min || number > max) throw invalidEnvironment();
  return number;
}

function assertReadinessUrl(value, allowedOrigin) {
  try {
    const url = new URL(value);
    const origin = new URL(allowedOrigin);
    if (url.protocol !== "https:" || url.username || url.password || url.hash || url.search || origin.protocol !== "https:" || origin.username || origin.password || origin.pathname !== "/" || origin.search || origin.hash || url.origin !== origin.origin) throw new Error("invalid readiness URL");
  } catch {
    throw invalidEnvironment();
  }
}

function assertDatabaseUrl(value) {
  try {
    const url = new URL(value);
    const sslmodes = url.searchParams.getAll("sslmode");
    if (url.protocol !== "postgresql:" || !url.hostname || !url.username || !url.password || url.hash || sslmodes.length !== 1 || sslmodes[0] !== "verify-full" || [...url.searchParams.keys()].some((key) => key !== "sslmode")) throw new Error("invalid database URL");
  } catch {
    throw invalidEnvironment();
  }
}

function decodeExactBase64UrlSecret(value, label) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]{43}$/u.test(value)) throw invalidEnvironment();
  let decoded;
  try { decoded = Buffer.from(value, "base64url"); }
  catch { throw invalidEnvironment(); }
  if (decoded.length !== SECRET_BYTES || decoded.toString("base64url") !== value) throw invalidEnvironment();
  return decoded;
}

function parseMigrationTargetManifest(value, databaseUrl, applicationVersion) {
  if (typeof value !== "string" || value.length < 1 || value.length > 8 * 1024) throw invalidEnvironment();
  let parsed;
  try { parsed = JSON.parse(value); }
  catch { throw invalidEnvironment(); }
  try {
    assertMigrationTargetManifest(parsed, applicationVersion);
    const targetHash = crypto.createHash("sha256").update(databaseUrl, "utf8").digest("hex");
    if (parsed.target.database_url_sha256 !== targetHash) throw new Error("target mismatch");
    return Object.freeze({
      schema: TARGET_MANIFEST_SCHEMA,
      target: Object.freeze({ id: parsed.target.id, database_url_sha256: parsed.target.database_url_sha256, migrations: Object.freeze(parsed.target.migrations.map((item) => Object.freeze({ version: item.version, checksum: item.checksum }))) }),
      deployment: Object.freeze({
        id: parsed.deployment.id,
        revision: parsed.deployment.revision,
        traffic_generation: parsed.deployment.traffic_generation,
        application_version: parsed.deployment.application_version
      })
    });
  } catch {
    throw invalidEnvironment();
  }
}

function assertMigrationTargetManifest(manifest, applicationVersion) {
  if (!manifest || typeof manifest !== "object" || Array.isArray(manifest) || manifest.schema !== TARGET_MANIFEST_SCHEMA || !exactKeys(manifest, ["schema", "target", "deployment"])) throw invalidEnvironment();
  const target = manifest.target;
  const deployment = manifest.deployment;
  if (!target || typeof target !== "object" || Array.isArray(target) || !exactKeys(target, ["id", "database_url_sha256", "migrations"]) || !isSafeBindingValue(target.id) || !/^[0-9a-f]{64}$/u.test(target.database_url_sha256) || !Array.isArray(target.migrations) || target.migrations.length < 1) throw invalidEnvironment();
  for (let index = 0; index < target.migrations.length; index += 1) {
    const migration = target.migrations[index];
    if (!migration || typeof migration !== "object" || Array.isArray(migration) || !exactKeys(migration, ["version", "checksum"]) || migration.version !== index + 1 || !/^[0-9a-f]{64}$/u.test(migration.checksum)) throw invalidEnvironment();
  }
  if (!deployment || typeof deployment !== "object" || Array.isArray(deployment) || !exactKeys(deployment, ["id", "revision", "traffic_generation", "application_version"]) || !isSafeBindingValue(deployment.id) || !isSafeBindingValue(deployment.revision) || !isSafeBindingValue(deployment.traffic_generation) || deployment.application_version !== applicationVersion) throw invalidEnvironment();
  return true;
}

function assertPinnedMigrations(migrations, pinned) {
  if (!Array.isArray(migrations) || !Array.isArray(pinned) || migrations.length !== pinned.length) throw invalidEnvironment();
  for (let index = 0; index < migrations.length; index += 1) {
    if (migrations[index]?.version !== pinned[index]?.version || migrations[index]?.checksum !== pinned[index]?.checksum) throw invalidEnvironment();
  }
}

function exactKeys(value, expected) {
  const keys = Object.keys(value).sort();
  return keys.length === expected.length && keys.every((key, index) => key === expected.slice().sort()[index]);
}

function isSafeBindingValue(value) {
  return typeof value === "string" && value.length >= 1 && value.length <= 256 && /^[A-Za-z0-9][A-Za-z0-9._:@/-]*$/u.test(value);
}

function isSafeNonce(value) {
  return typeof value === "string" && value.length >= 16 && value.length <= 128 && /^[A-Za-z0-9_-]+$/u.test(value);
}

function isBase64UrlSignature(value) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]{43}$/u.test(value)) return false;
  try { return Buffer.from(value, "base64url").length === 32 && Buffer.from(value, "base64url").toString("base64url") === value; }
  catch { return false; }
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

function expectedBindingMatches(input, expected) {
  return expected !== undefined
    && input.deployment_id === expected.id
    && input.revision === expected.revision
    && input.traffic_generation === expected.traffic_generation;
}

function verifyDrainEvidence(input, secret) {
  let key;
  try {
    key = Buffer.isBuffer(secret) ? secret : decodeExactBase64UrlSecret(secret, "drain evidence secret");
  } catch {
    return false;
  }
  const expected = crypto.createHmac("sha256", key).update(canonicalDrainEvidence(input), "utf8").digest();
  let actual;
  try { actual = Buffer.from(input.signature, "base64url"); }
  catch { return false; }
  return actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
}

function parseTimestamp(value) {
  if (typeof value !== "string" || value.length > 64 || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/u.test(value)) return null;
  const date = new Date(value);
  return Number.isFinite(date.getTime()) ? date : null;
}

function validIsoTimestamp(now) {
  const date = now instanceof Function ? now() : now;
  return date instanceof Date && Number.isFinite(date.getTime()) ? date.toISOString() : null;
}

function stablePreflightCode(error) {
  if (error instanceof ControlPlaneCutoverPreflightError && typeof error.code === "string" && /^AGENTPASS_0011_PREFLIGHT_[A-Z_]+$/u.test(error.code)) return error.code;
  return CUTOVER_DIAGNOSTICS.PREFLIGHT_BLOCKED;
}

function invalidArgument(reason) {
  return new CutoverOperationsError(CUTOVER_DIAGNOSTICS.INVALID_ARGUMENT, "cutover arguments are invalid", "Use only the documented command and flags; provide secrets through the environment or a secret manager.", reason);
}

function invalidEnvironment() {
  return new CutoverOperationsError(CUTOVER_DIAGNOSTICS.INVALID_ENVIRONMENT, "cutover environment is invalid", "Set the explicit hosted profile and approved non-secret settings; provide the database URL through the environment only.");
}

function success(command, phase, result) {
  return Object.freeze({ schema: CUTOVER_SCHEMA, ok: true, command, phase, code: "OK", result });
}

function failure(command, phase, code, message, remediation, result = undefined) {
  const output = { schema: CUTOVER_SCHEMA, ok: false, command, phase, code, message, remediation };
  if (result !== undefined) output.result = result;
  return Object.freeze(output);
}

function asFailure(command, error) {
  if (error instanceof CutoverOperationsError) return failure(command, "configuration", error.code, error.message, error.remediation);
  if (error instanceof ControlPlaneCutoverPreflightError) return failure(command, "preflight", stablePreflightCode(error), "cutover preflight did not pass", "Repair the reported database condition and rerun the read-only preflight before applying a migration.");
  return failure(command, command === "migrate" ? "migrate" : command === "validate" ? "validate" : "operation", command === "migrate" ? CUTOVER_DIAGNOSTICS.MIGRATION_BLOCKED : command === "validate" ? CUTOVER_DIAGNOSTICS.VALIDATION_BLOCKED : CUTOVER_DIAGNOSTICS.DATABASE_UNAVAILABLE, "cutover operation could not establish a trustworthy result", "Inspect the deployment platform and database health without exposing credentials, then rerun the operation.");
}

async function openDatabase({ env, PoolClass = Pool } = {}) {
  const config = validateCutoverEnvironment(env);
  const url = new URL(env.AGENTPASS_DATABASE_URL);
  const pool = new PoolClass({ connectionString: url.toString(), ssl: { rejectUnauthorized: true }, max: 1, connectionTimeoutMillis: 5_000, idleTimeoutMillis: 5_000, statement_timeout: 15_000, lock_timeout: 5_000, query_timeout: 20_000, allowExitOnIdle: false });
  let client;
  try { client = await pool.connect(); }
  catch (error) { await pool.end().catch(() => {}); throw new CutoverOperationsError(CUTOVER_DIAGNOSTICS.DATABASE_UNAVAILABLE, "database connection is unavailable", "Verify the private database connection and TLS configuration without putting credentials on the command line.", error); }
  return Object.freeze({ client, pool, config, async close() { client.release?.(); await pool.end(); } });
}

export async function readDrainFile(file) {
  let handle;
  try {
    const flags = FS_CONSTANTS.O_RDONLY | (FS_CONSTANTS.O_NOFOLLOW ?? 0);
    handle = await fs.open(file, flags);
    const stat = await handle.stat();
    if (!stat.isFile() || stat.size > MAX_DRAIN_INPUT_BYTES) throw new Error("drain input is not a bounded regular file");
    const buffer = Buffer.allocUnsafe(MAX_DRAIN_INPUT_BYTES + 1);
    let offset = 0;
    while (offset < buffer.length) {
      const { bytesRead } = await handle.read(buffer, offset, buffer.length - offset, offset);
      if (bytesRead === 0) break;
      offset += bytesRead;
    }
    if (offset > MAX_DRAIN_INPUT_BYTES) throw new Error("drain input too large");
    const text = new TextDecoder("utf-8", { fatal: true }).decode(buffer.subarray(0, offset));
    return JSON.parse(text);
  } catch {
    throw new CutoverOperationsError(CUTOVER_DIAGNOSTICS.DRAIN_INPUT_INVALID, "drain gate input is invalid", "Provide a bounded JSON drain gate document with no credentials or bearer material.");
  } finally {
    await handle?.close().catch(() => {});
  }
}

async function createCliOperations({ env, options, dependencies = {}, config = undefined } = {}) {
  if (dependencies.operations) return { operations: dependencies.operations, close: async () => {} };
  const resolvedConfig = config ?? validateCutoverEnvironment(env, { requireMigrationManifest: options.command === "migrate", requireDrainEvidence: ["drain", "cutover"].includes(options.command) });
  const database = await openDatabase({ env, PoolClass: dependencies.PoolClass });
  const applicationReadiness = resolvedConfig.readinessUrl === undefined
    ? async () => ({ configured: false, ready: false })
    : () => fetchReadiness(resolvedConfig.readinessUrl, resolvedConfig.readinessTimeoutMs, dependencies.fetch ?? globalThis.fetch, decodeExactBase64UrlSecret(env.AGENTPASS_OPERATIONAL_PROBE_SECRET, "operational probe secret"), resolvedConfig.readinessAllowedOrigin);
  const drainSecret = env.AGENTPASS_CUTOVER_DRAIN_SECRET === undefined ? undefined : decodeExactBase64UrlSecret(env.AGENTPASS_CUTOVER_DRAIN_SECRET, "drain evidence secret");
  return {
    operations: createCutoverOperations({ client: database.client, pool: database.pool, applicationVersion: resolvedConfig.applicationVersion, migrationTargetManifest: resolvedConfig.migrationTargetManifest, drainSecret, applicationReadiness, now: dependencies.now ?? (() => new Date()) }),
    close: database.close
  };
}

export async function fetchReadiness(url, timeoutMs, fetchImpl, operationalProbeSecret, allowedOrigin) {
  if (typeof fetchImpl !== "function") throw new Error("fetch is unavailable");
  assertReadinessUrl(url, allowedOrigin);
  const secret = Buffer.isBuffer(operationalProbeSecret) ? operationalProbeSecret : decodeExactBase64UrlSecret(operationalProbeSecret, "operational probe secret");
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetchImpl(url, { method: "GET", headers: { accept: "application/json", "AgentPass-Operational-Token": secret.toString("base64url") }, redirect: "error", signal: controller.signal });
    if (!response.ok) return { configured: true, ready: false };
    const body = await readResponseBodyBounded(response);
    const parsed = JSON.parse(body);
    return { configured: true, ready: parsed?.ready === true };
  } catch {
    return { configured: true, ready: false };
  } finally {
    clearTimeout(timeout);
  }
}

async function readResponseBodyBounded(response) {
  const reader = response?.body?.getReader?.();
  if (!reader) throw new Error("readiness response is not streamable");
  const chunks = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!(value instanceof Uint8Array) || value.byteLength === 0) continue;
      total += value.byteLength;
      if (total > MAX_DRAIN_INPUT_BYTES) {
        await reader.cancel().catch(() => {});
        throw new Error("readiness response too large");
      }
      chunks.push(Buffer.from(value));
    }
    return new TextDecoder("utf-8", { fatal: true }).decode(Buffer.concat(chunks, total));
  } finally {
    reader.releaseLock?.();
  }
}

export async function runCli(argv = process.argv.slice(2), env = process.env, dependencies = {}) {
  let command = "unknown";
  let close = async () => {};
  try {
    const options = parseCutoverArguments(argv);
    command = options.command;
    const config = validateCutoverEnvironment(env, { requireMigrationManifest: ["migrate", "drain", "cutover"].includes(command), requireDrainEvidence: ["drain", "cutover"].includes(command) });
    const { operations, close: closeDatabase } = await createCliOperations({ env, options, dependencies, config });
    close = closeDatabase;
    const drainInput = options.drainFile === undefined ? undefined : await readDrainFile(options.drainFile);
    return await executeCutoverCommand({ command, options, operations, drainInput });
  } catch (error) {
    return asFailure(command, error);
  } finally {
    await close().catch(() => {});
  }
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  const result = await runCli();
  process.stdout.write(`${JSON.stringify(result)}\n`);
  if (!result.ok) process.exitCode = 1;
}
