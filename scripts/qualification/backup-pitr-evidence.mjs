#!/usr/bin/env node

import crypto from "node:crypto";
import { spawn as nodeSpawn } from "node:child_process";
import { chmod, lstat, mkdtemp, open, readFile, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";

import { canonicalJson } from "../../packages/protocol/src/index.mjs";

export const BACKUP_PITR_EVIDENCE_SCHEMA_VERSION = 1;
export const BACKUP_PITR_EVIDENCE_KIND = "agentpass-backup-pitr-evidence";
export const BACKUP_PITR_EXECUTION_RESULT_KIND = "agentpass-backup-pitr-execution-result";

export const BACKUP_PITR_EVIDENCE_ERROR_CODES = Object.freeze({
  INPUT_FILE: "invalid_input_file",
  INPUT: "invalid_execution_result",
  OUTPUT_FILE: "invalid_output_file",
  SOURCE_BINDING: "invalid_source_binding",
  RUN_BINDING: "invalid_run_binding",
  ARTIFACT_BINDING: "invalid_artifact_binding",
  NOT_EXTERNAL: "execution_not_external",
  CHECK_FAILED: "backup_pitr_failed",
  NON_CANONICAL: "non_canonical_json",
  DATABASE_CONFIG: "invalid_database_config",
  COMMAND_FAILED: "backup_pitr_command_failed",
  RUNNER_CONFIG: "invalid_runner_config"
});

const SHA1 = /^[0-9a-f]{40}$/u;
const SHA256 = /^[0-9a-f]{64}$/u;
const POSITIVE_ID = /^[1-9][0-9]{0,19}$/u;
const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/u;
const TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u;
const CHECK_STATUSES = new Set(["passed", "failed", "not_run"]);
const DISALLOWED_RUNNER = /(?:^|[._:/ -])(local|static|unit|mock|fixture|fake|simulator|emulator|test|macos-latest)(?:$|[._:/ -])/iu;
const RUNNER_CONFIRMATION = "isolated-disposable";
const COMMAND_TIMEOUT_MS = 15 * 60 * 1000;
const MAX_COMMAND_RESULT_BYTES = 1024;
const MAX_BACKUP_BYTES = 64 * 1024 * 1024 * 1024;
const COMMANDS = Object.freeze({
  dump: "pg_dump",
  restore: "pg_restore",
  probe: "psql"
});

const INPUT_KEYS = Object.freeze([
  "artifact_sha256", "backup_restore", "ci_job_id", "ci_run_attempt", "ci_run_id", "completed_at",
  "execution", "kind", "pitr_recovery", "schema_version", "source_commit", "source_tree", "started_at"
]);
const EXECUTION_KEYS = Object.freeze(["environment", "real_execution", "runner_id"]);
const CHECK_INPUT_KEYS = Object.freeze(["expected", "observed", "status"]);
const EVIDENCE_KEYS = Object.freeze([
  "artifact_sha256", "backup_restore", "ci_job_id", "ci_run_attempt", "ci_run_id",
  "pitr_recovery", "redacted", "schema_version", "source_commit", "source_tree"
]);
const CHECK_KEYS = Object.freeze(["evidence_sha256", "expected", "id", "observed", "status"]);

export class BackupPitrEvidenceError extends TypeError {
  constructor(code) {
    super(code);
    this.name = "BackupPitrEvidenceError";
    this.code = code;
  }
}

function fail(code) {
  throw new BackupPitrEvidenceError(code);
}

function failRunner(code) {
  throw new BackupPitrEvidenceError(code);
}

function exactObject(value, keys, code = BACKUP_PITR_EVIDENCE_ERROR_CODES.INPUT) {
  if (value === null || typeof value !== "object" || Array.isArray(value)
    || (Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null)) fail(code);
  const actual = Reflect.ownKeys(value);
  if (actual.length !== keys.length || actual.some((key) => typeof key !== "string" || !keys.includes(key))) fail(code);
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || descriptor.enumerable !== true || !Object.hasOwn(descriptor, "value")) fail(code);
  }
  return value;
}

function string(value, pattern, code) {
  if (typeof value !== "string" || !pattern.test(value)) fail(code);
  return value;
}

function timestamp(value) {
  string(value, TIMESTAMP, BACKUP_PITR_EVIDENCE_ERROR_CODES.INPUT);
  if (!Number.isFinite(Date.parse(value))) fail(BACKUP_PITR_EVIDENCE_ERROR_CODES.INPUT);
  return value;
}

function bindingFrom(value) {
  return Object.freeze({
    sourceCommit: string(value.source_commit, SHA1, BACKUP_PITR_EVIDENCE_ERROR_CODES.SOURCE_BINDING),
    sourceTree: string(value.source_tree, SHA1, BACKUP_PITR_EVIDENCE_ERROR_CODES.SOURCE_BINDING),
    ciRunId: string(value.ci_run_id, POSITIVE_ID, BACKUP_PITR_EVIDENCE_ERROR_CODES.RUN_BINDING),
    ciRunAttempt: string(value.ci_run_attempt, POSITIVE_ID, BACKUP_PITR_EVIDENCE_ERROR_CODES.RUN_BINDING),
    ciJobId: string(value.ci_job_id, SAFE_ID, BACKUP_PITR_EVIDENCE_ERROR_CODES.RUN_BINDING),
    artifactSha256: string(value.artifact_sha256, SHA256, BACKUP_PITR_EVIDENCE_ERROR_CODES.ARTIFACT_BINDING)
  });
}

function assertExpectedBinding(actual, expected = {}) {
  const names = [
    ["sourceCommit", BACKUP_PITR_EVIDENCE_ERROR_CODES.SOURCE_BINDING],
    ["sourceTree", BACKUP_PITR_EVIDENCE_ERROR_CODES.SOURCE_BINDING],
    ["ciRunId", BACKUP_PITR_EVIDENCE_ERROR_CODES.RUN_BINDING],
    ["ciRunAttempt", BACKUP_PITR_EVIDENCE_ERROR_CODES.RUN_BINDING],
    ["ciJobId", BACKUP_PITR_EVIDENCE_ERROR_CODES.RUN_BINDING],
    ["artifactSha256", BACKUP_PITR_EVIDENCE_ERROR_CODES.ARTIFACT_BINDING]
  ];
  for (const [key, code] of names) {
    if (expected[key] !== undefined && String(expected[key]) !== actual[key]) fail(code);
  }
}

function normalizeExecution(value) {
  exactObject(value, EXECUTION_KEYS);
  if (value.real_execution !== true || typeof value.environment !== "string"
    || value.environment !== "postgresql" || typeof value.runner_id !== "string"
    || !SAFE_ID.test(value.runner_id) || DISALLOWED_RUNNER.test(value.runner_id)) {
    fail(BACKUP_PITR_EVIDENCE_ERROR_CODES.NOT_EXTERNAL);
  }
  return Object.freeze({ ...value });
}

function normalizeInputCheck(value, id) {
  exactObject(value, CHECK_INPUT_KEYS);
  if (!CHECK_STATUSES.has(value.expected) || value.expected !== "passed"
    || !CHECK_STATUSES.has(value.observed) || !CHECK_STATUSES.has(value.status)
    || value.status !== value.observed) fail(BACKUP_PITR_EVIDENCE_ERROR_CODES.INPUT);
  if (value.status !== "passed") fail(BACKUP_PITR_EVIDENCE_ERROR_CODES.CHECK_FAILED);
  return Object.freeze({ id, expected: value.expected, observed: value.observed, status: value.status });
}

function checkDigest(check) {
  return crypto.createHash("sha256").update(canonicalJson({
    check_id: check.id,
    expected: check.expected,
    observed: check.observed,
    status: check.status
  }), "utf8").digest("hex");
}

function toEvidenceCheck(check) {
  const result = {
    id: check.id,
    status: check.status,
    expected: { type: "status", value: check.expected },
    observed: { type: "status", value: check.observed },
    evidence_sha256: null
  };
  result.evidence_sha256 = checkDigest(result);
  return Object.freeze(result);
}

function normalizeEvidenceCheck(value, id) {
  exactObject(value, CHECK_KEYS, BACKUP_PITR_EVIDENCE_ERROR_CODES.INPUT);
  if (value.id !== id || value.status !== "passed"
    || value.expected?.type !== "status" || value.expected.value !== "passed"
    || value.observed?.type !== "status" || value.observed.value !== "passed"
    || typeof value.evidence_sha256 !== "string" || !SHA256.test(value.evidence_sha256)
    || value.evidence_sha256 !== checkDigest(value)) fail(BACKUP_PITR_EVIDENCE_ERROR_CODES.INPUT);
  exactObject(value.expected, ["type", "value"], BACKUP_PITR_EVIDENCE_ERROR_CODES.INPUT);
  exactObject(value.observed, ["type", "value"], BACKUP_PITR_EVIDENCE_ERROR_CODES.INPUT);
  return Object.freeze(value);
}

export function normalizeBackupPitrExecutionResult(value, expectedBinding = {}) {
  exactObject(value, INPUT_KEYS);
  if (value.schema_version !== BACKUP_PITR_EVIDENCE_SCHEMA_VERSION || value.kind !== BACKUP_PITR_EXECUTION_RESULT_KIND) {
    fail(BACKUP_PITR_EVIDENCE_ERROR_CODES.INPUT);
  }
  const binding = bindingFrom(value);
  assertExpectedBinding(binding, expectedBinding);
  timestamp(value.started_at);
  timestamp(value.completed_at);
  if (Date.parse(value.completed_at) < Date.parse(value.started_at)) fail(BACKUP_PITR_EVIDENCE_ERROR_CODES.INPUT);
  normalizeExecution(value.execution);
  const backupRestore = normalizeInputCheck(value.backup_restore, "backup_restore");
  const pitrRecovery = normalizeInputCheck(value.pitr_recovery, "pitr_recovery");
  return Object.freeze({ ...value, binding, backupRestore, pitrRecovery });
}

export function createBackupPitrEvidence(value, expectedBinding = {}) {
  const input = normalizeBackupPitrExecutionResult(value, expectedBinding);
  const evidence = {
    schema_version: BACKUP_PITR_EVIDENCE_SCHEMA_VERSION,
    redacted: true,
    source_commit: input.binding.sourceCommit,
    source_tree: input.binding.sourceTree,
    ci_run_id: input.binding.ciRunId,
    ci_run_attempt: input.binding.ciRunAttempt,
    ci_job_id: input.binding.ciJobId,
    artifact_sha256: input.binding.artifactSha256,
    backup_restore: toEvidenceCheck(input.backupRestore),
    pitr_recovery: toEvidenceCheck(input.pitrRecovery)
  };
  return normalizeBackupPitrEvidence(evidence, expectedBinding);
}

export function normalizeBackupPitrEvidence(value, expectedBinding = {}) {
  exactObject(value, EVIDENCE_KEYS, BACKUP_PITR_EVIDENCE_ERROR_CODES.INPUT);
  if (value.schema_version !== BACKUP_PITR_EVIDENCE_SCHEMA_VERSION || value.redacted !== true) fail(BACKUP_PITR_EVIDENCE_ERROR_CODES.INPUT);
  const binding = bindingFrom(value);
  assertExpectedBinding(binding, expectedBinding);
  normalizeEvidenceCheck(value.backup_restore, "backup_restore");
  normalizeEvidenceCheck(value.pitr_recovery, "pitr_recovery");
  const serialized = canonicalJson(value);
  if (serialized.includes("postgresql://") || /password|secret|private[\s_-]*key|credential|authorization|cookie|api[\s_-]*key|connection[\s_-]*(?:string|url)|token/iu.test(serialized)) {
    fail(BACKUP_PITR_EVIDENCE_ERROR_CODES.INPUT);
  }
  return Object.freeze(value);
}

export function canonicalBackupPitrEvidence(value, expectedBinding = {}) {
  return canonicalJson(normalizeBackupPitrEvidence(value, expectedBinding));
}

export function backupPitrEvidenceSHA256(value, expectedBinding = {}) {
  return crypto.createHash("sha256").update(canonicalBackupPitrEvidence(value, expectedBinding), "utf8").digest("hex");
}

function absolutePath(value, code) {
  if (typeof value !== "string" || !path.isAbsolute(value)) fail(code);
  return value;
}

async function protectedFile(pathname, code = BACKUP_PITR_EVIDENCE_ERROR_CODES.INPUT_FILE) {
  absolutePath(pathname, code);
  const metadata = await lstat(pathname).catch(() => null);
  if (!metadata || !metadata.isFile() || metadata.isSymbolicLink() || metadata.nlink !== 1
    || (metadata.mode & 0o077) !== 0 || metadata.size < 1 || metadata.size > 1024 * 1024) fail(code);
  return metadata;
}

async function protectedReadableFile(pathname) {
  absolutePath(pathname, BACKUP_PITR_EVIDENCE_ERROR_CODES.DATABASE_CONFIG);
  const metadata = await lstat(pathname).catch(() => null);
  if (!metadata || !metadata.isFile() || metadata.isSymbolicLink() || metadata.nlink !== 1
    || (metadata.mode & 0o022) !== 0 || metadata.size < 1 || metadata.size > 1024 * 1024) {
    failRunner(BACKUP_PITR_EVIDENCE_ERROR_CODES.DATABASE_CONFIG);
  }
  return pathname;
}

function parseDatabaseUrl(value, caFile) {
  if (typeof value !== "string" || value.length < 1 || value.length > 4096) {
    failRunner(BACKUP_PITR_EVIDENCE_ERROR_CODES.DATABASE_CONFIG);
  }
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    failRunner(BACKUP_PITR_EVIDENCE_ERROR_CODES.DATABASE_CONFIG);
  }
  const sslModes = parsed.searchParams.getAll("sslmode");
  const unknownParams = [...parsed.searchParams.keys()].filter((key) => key !== "sslmode");
  if (!["postgres:", "postgresql:"].includes(parsed.protocol) || !parsed.hostname
    || parsed.username.length === 0 || parsed.pathname.length < 2
    || sslModes.length !== 1 || sslModes[0] !== "verify-full" || unknownParams.length > 0
    || parsed.hash || parsed.searchParams.get("sslcert") || parsed.searchParams.get("sslkey")) {
    failRunner(BACKUP_PITR_EVIDENCE_ERROR_CODES.DATABASE_CONFIG);
  }
  try {
    return Object.freeze({
      host: parsed.hostname.replace(/^\[|\]$/gu, ""),
      port: parsed.port || "5432",
      user: decodeURIComponent(parsed.username),
      password: parsed.password === "" ? undefined : decodeURIComponent(parsed.password),
      database: decodeURIComponent(parsed.pathname.slice(1)),
      caFile
    });
  } catch {
    failRunner(BACKUP_PITR_EVIDENCE_ERROR_CODES.DATABASE_CONFIG);
  }
}

function connectionIdentity(connection) {
  return `${connection.host}\u0000${connection.port}\u0000${connection.database}`;
}

function commandEnvironment(connection, env) {
  const result = {
    PATH: env.PATH ?? "/usr/bin:/bin",
    LANG: "C",
    LC_ALL: "C",
    PGAPPNAME: "agentpass-backup-pitr",
    PGCONNECT_TIMEOUT: "10",
    PGSSLMODE: "verify-full",
    PGSSLROOTCERT: connection.caFile,
    PGHOST: connection.host,
    PGPORT: connection.port,
    PGUSER: connection.user,
    PGDATABASE: connection.database
  };
  if (connection.password !== undefined) result.PGPASSWORD = connection.password;
  return result;
}

function exactCommandResult(text) {
  if (typeof text !== "string" || text.length > MAX_COMMAND_RESULT_BYTES) {
    failRunner(BACKUP_PITR_EVIDENCE_ERROR_CODES.COMMAND_FAILED);
  }
  return text.replace(/\r\n/gu, "\n").trim();
}

function runFixedCommand(command, args, env, {
  spawnProcess = nodeSpawn,
  timeoutMs = COMMAND_TIMEOUT_MS,
  outputPath
} = {}) {
  return new Promise((resolve) => {
    let child;
    let settled = false;
    let timedOut = false;
    const finish = (result) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(result);
    };
    const timer = setTimeout(() => {
      timedOut = true;
      child?.kill("SIGTERM");
      finish({ ok: false, reason: "timeout" });
    }, timeoutMs);
    try {
      child = spawnProcess(command, args, {
        env,
        shell: false,
        stdio: outputPath ? ["ignore", "ignore", "ignore"] : "ignore"
      });
      child.once("error", () => finish({ ok: false, reason: "spawn" }));
      child.once("exit", (code, signal) => finish({
        ok: code === 0 && signal === null && !timedOut,
        reason: code === 0 && signal === null && !timedOut ? null : "exit"
      }));
    } catch {
      finish({ ok: false, reason: "spawn" });
    }
  });
}

async function readCommandResult(pathname) {
  let text;
  try {
    text = await readFile(pathname, "utf8");
  } catch {
    failRunner(BACKUP_PITR_EVIDENCE_ERROR_CODES.COMMAND_FAILED);
  }
  await rm(pathname, { force: true }).catch(() => {});
  return exactCommandResult(text);
}

async function runDatabaseCommand(command, args, connection, env, options = {}) {
  const result = await runFixedCommand(command, args, commandEnvironment(connection, env), options);
  if (!result.ok) failRunner(BACKUP_PITR_EVIDENCE_ERROR_CODES.COMMAND_FAILED);
  return result;
}

async function runBackupPitrCommands({ env = process.env, spawnProcess = nodeSpawn, tempDirectory }) {
  const caFile = await protectedReadableFile(env.AGENTPASS_BACKUP_PITR_CA_CERT_FILE);
  const source = parseDatabaseUrl(env.AGENTPASS_DATABASE_URL, caFile);
  const restore = parseDatabaseUrl(env.AGENTPASS_BACKUP_PITR_RESTORE_DATABASE_URL, caFile);
  const pitr = parseDatabaseUrl(env.AGENTPASS_BACKUP_PITR_PITR_DATABASE_URL, caFile);
  if ([source, restore, pitr].some((connection, index, all) => all.findIndex((other) => connectionIdentity(other) === connectionIdentity(connection)) !== index)
    || env.AGENTPASS_BACKUP_PITR_RESTORE_CONFIRMATION !== RUNNER_CONFIRMATION
    || env.AGENTPASS_BACKUP_PITR_PITR_CONFIRMATION !== RUNNER_CONFIRMATION) {
    failRunner(BACKUP_PITR_EVIDENCE_ERROR_CODES.RUNNER_CONFIG);
  }

  const directory = tempDirectory ?? await mkdtemp(path.join(os.tmpdir(), "agentpass-backup-pitr-"));
  const dumpPath = path.join(directory, "base.dump");
  const restoreProbePath = path.join(directory, "restore-probe.txt");
  const pitrProbePath = path.join(directory, "pitr-probe.txt");
  try {
    await chmod(directory, 0o700).catch(() => failRunner(BACKUP_PITR_EVIDENCE_ERROR_CODES.OUTPUT_FILE));
    await runDatabaseCommand(COMMANDS.dump, [
      "--format=custom", "--no-owner", "--no-acl", "--no-password", "--file", dumpPath
    ], source, env, { spawnProcess });
    const dumpMetadata = await lstat(dumpPath).catch(() => null);
    if (!dumpMetadata || !dumpMetadata.isFile() || dumpMetadata.isSymbolicLink() || dumpMetadata.nlink !== 1
      || (dumpMetadata.mode & 0o077) !== 0 || dumpMetadata.size < 1 || dumpMetadata.size > MAX_BACKUP_BYTES) {
      failRunner(BACKUP_PITR_EVIDENCE_ERROR_CODES.COMMAND_FAILED);
    }
    await runDatabaseCommand(COMMANDS.restore, [
      "--exit-on-error", "--single-transaction", "--no-owner", "--no-acl", "--no-password", "--dbname", restore.database, dumpPath
    ], restore, env, { spawnProcess });
    await runDatabaseCommand(COMMANDS.probe, [
      "--no-psqlrc", "--quiet", "--no-password", "--tuples-only", "--no-align", "--set=ON_ERROR_STOP=1",
      "--command", "SELECT 'restore-ok'", "--output", restoreProbePath
    ], restore, env, { spawnProcess, outputPath: restoreProbePath });
    if ((await readCommandResult(restoreProbePath)) !== "restore-ok") {
      failRunner(BACKUP_PITR_EVIDENCE_ERROR_CODES.COMMAND_FAILED);
    }
    await runDatabaseCommand(COMMANDS.probe, [
      "--no-psqlrc", "--quiet", "--no-password", "--tuples-only", "--no-align", "--set=ON_ERROR_STOP=1",
      "--command", "SELECT CASE WHEN pg_last_wal_replay_lsn() IS NULL THEN 'not-replayed' ELSE 'replayed' END || ':' || CASE WHEN pg_is_in_recovery() THEN 'recovery' ELSE 'ready' END",
      "--output", pitrProbePath
    ], pitr, env, { spawnProcess, outputPath: pitrProbePath });
    const pitrResult = await readCommandResult(pitrProbePath);
    if (!/^replayed:(?:recovery|ready)$/u.test(pitrResult)) {
      failRunner(BACKUP_PITR_EVIDENCE_ERROR_CODES.COMMAND_FAILED);
    }
    return Object.freeze({ backupRestore: "passed", pitrRecovery: "passed" });
  } finally {
    await rm(directory, { recursive: true, force: true }).catch(() => {});
  }
}

export async function runBackupPitrQualification({
  outputPath,
  expectedBinding = {},
  env = process.env,
  spawnProcess = nodeSpawn,
  clock = () => new Date()
} = {}) {
  absolutePath(outputPath, BACKUP_PITR_EVIDENCE_ERROR_CODES.OUTPUT_FILE);
  const binding = bindingFrom({
    source_commit: expectedBinding.sourceCommit,
    source_tree: expectedBinding.sourceTree,
    ci_run_id: expectedBinding.ciRunId,
    ci_run_attempt: expectedBinding.ciRunAttempt,
    ci_job_id: expectedBinding.ciJobId,
    artifact_sha256: expectedBinding.artifactSha256
  });
  const runnerId = env.AGENTPASS_BACKUP_PITR_RUNNER_ID;
  if (typeof runnerId !== "string" || !SAFE_ID.test(runnerId) || DISALLOWED_RUNNER.test(runnerId)) {
    failRunner(BACKUP_PITR_EVIDENCE_ERROR_CODES.NOT_EXTERNAL);
  }
  const startedAt = clock().toISOString();
  const checks = await runBackupPitrCommands({ env, spawnProcess });
  const completedAt = clock().toISOString();
  const executionResult = {
    schema_version: BACKUP_PITR_EVIDENCE_SCHEMA_VERSION,
    kind: BACKUP_PITR_EXECUTION_RESULT_KIND,
    source_commit: binding.sourceCommit,
    source_tree: binding.sourceTree,
    ci_run_id: binding.ciRunId,
    ci_run_attempt: binding.ciRunAttempt,
    ci_job_id: binding.ciJobId,
    artifact_sha256: binding.artifactSha256,
    started_at: startedAt,
    completed_at: completedAt,
    execution: { environment: "postgresql", real_execution: true, runner_id: runnerId },
    backup_restore: { expected: "passed", observed: checks.backupRestore, status: checks.backupRestore },
    pitr_recovery: { expected: "passed", observed: checks.pitrRecovery, status: checks.pitrRecovery }
  };
  const evidence = createBackupPitrEvidence(executionResult, expectedBinding);
  await writeBackupPitrEvidence(outputPath, evidence);
  process.stdout.write(`${canonicalJson(evidence)}\n`);
  return evidence;
}

async function readCanonicalJson(pathname) {
  await protectedFile(pathname);
  let bytes;
  try {
    bytes = await readFile(pathname);
    const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    if (!text.endsWith("\n")) fail(BACKUP_PITR_EVIDENCE_ERROR_CODES.NON_CANONICAL);
    const value = JSON.parse(text);
    if (`${canonicalJson(value)}\n` !== text) fail(BACKUP_PITR_EVIDENCE_ERROR_CODES.NON_CANONICAL);
    return value;
  } catch (error) {
    if (error instanceof BackupPitrEvidenceError) throw error;
    fail(BACKUP_PITR_EVIDENCE_ERROR_CODES.INPUT_FILE);
  }
}

export async function writeBackupPitrEvidence(outputPath, evidence) {
  absolutePath(outputPath, BACKUP_PITR_EVIDENCE_ERROR_CODES.OUTPUT_FILE);
  const text = `${canonicalBackupPitrEvidence(evidence)}\n`;
  let handle;
  try {
    handle = await open(outputPath, "wx", 0o600);
    await handle.writeFile(text, "utf8");
  } catch (error) {
    fail(BACKUP_PITR_EVIDENCE_ERROR_CODES.OUTPUT_FILE);
  } finally {
    await handle?.close().catch(() => {});
  }
  await chmod(outputPath, 0o600).catch(() => fail(BACKUP_PITR_EVIDENCE_ERROR_CODES.OUTPUT_FILE));
  await protectedFile(outputPath, BACKUP_PITR_EVIDENCE_ERROR_CODES.OUTPUT_FILE);
  return outputPath;
}

export async function readBackupPitrEvidence(inputPath, expectedBinding = {}) {
  const value = await readCanonicalJson(inputPath);
  return normalizeBackupPitrEvidence(value, expectedBinding);
}

function parseOptions(argv, env) {
  const options = Object.create(null);
  const allowed = new Set(["source-commit", "source-tree", "run-id", "run-attempt", "job-id", "artifact-sha256"]);
  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index];
    if (!token.startsWith("--")) fail(BACKUP_PITR_EVIDENCE_ERROR_CODES.INPUT);
    const [key, inline] = token.slice(2).split("=", 2);
    if (!allowed.has(key) || Object.hasOwn(options, key)) fail(BACKUP_PITR_EVIDENCE_ERROR_CODES.INPUT);
    const value = inline ?? argv[++index];
    if (typeof value !== "string" || value.startsWith("--")) fail(BACKUP_PITR_EVIDENCE_ERROR_CODES.INPUT);
    options[key] = value;
  }
  const result = {
    sourceCommit: options["source-commit"] ?? env.AGENTPASS_BACKUP_PITR_SOURCE_COMMIT,
    sourceTree: options["source-tree"] ?? env.AGENTPASS_BACKUP_PITR_SOURCE_TREE,
    ciRunId: options["run-id"] ?? env.AGENTPASS_BACKUP_PITR_CI_RUN_ID ?? env.GITHUB_RUN_ID,
    ciRunAttempt: options["run-attempt"] ?? env.AGENTPASS_BACKUP_PITR_CI_RUN_ATTEMPT ?? env.GITHUB_RUN_ATTEMPT,
    ciJobId: options["job-id"] ?? env.AGENTPASS_BACKUP_PITR_CI_JOB_ID ?? env.GITHUB_JOB,
    artifactSha256: options["artifact-sha256"] ?? env.AGENTPASS_BACKUP_PITR_ARTIFACT_SHA256
  };
  if (!result.sourceCommit || !result.sourceTree || !result.ciRunId || !result.ciRunAttempt || !result.ciJobId || !result.artifactSha256) {
    fail(BACKUP_PITR_EVIDENCE_ERROR_CODES.INPUT);
  }
  return result;
}

export async function runBackupPitrEvidenceCli(argv = process.argv.slice(2), env = process.env) {
  const command = ["build", "verify", "run"].includes(argv[0]) ? argv[0] : "build";
  const offset = ["build", "verify", "run"].includes(argv[0]) ? 1 : 0;
  const inputPath = command === "run"
    ? undefined
    : absolutePath(argv[offset], BACKUP_PITR_EVIDENCE_ERROR_CODES.INPUT_FILE);
  const outputPath = command === "build"
    ? absolutePath(argv[offset + 1], BACKUP_PITR_EVIDENCE_ERROR_CODES.OUTPUT_FILE)
    : command === "run" ? absolutePath(argv[offset], BACKUP_PITR_EVIDENCE_ERROR_CODES.OUTPUT_FILE) : undefined;
  const optionArgs = argv.slice(offset + (command === "build" ? 2 : 1));
  const expected = parseOptions(optionArgs, env);
  if (command === "verify") {
    const evidence = await readBackupPitrEvidence(inputPath, expected);
    const result = { status: "passed", qualified: true, evidence_sha256: backupPitrEvidenceSHA256(evidence, expected) };
    process.stdout.write(`${canonicalJson(result)}\n`);
    return result;
  }
  if (command === "run") {
    return runBackupPitrQualification({ outputPath, expectedBinding: expected, env });
  }
  const input = await readCanonicalJson(inputPath);
  const evidence = createBackupPitrEvidence(input, expected);
  await writeBackupPitrEvidence(outputPath, evidence);
  process.stdout.write(`${canonicalJson(evidence)}\n`);
  return evidence;
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  runBackupPitrEvidenceCli().catch((error) => {
    process.stderr.write(`backup PITR evidence failed: ${error?.code ?? "invalid_input"}\n`);
    process.exitCode = 1;
  });
}
