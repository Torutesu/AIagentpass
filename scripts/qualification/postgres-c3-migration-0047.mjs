#!/usr/bin/env node

import crypto from "node:crypto";
import { constants as fsConstants } from "node:fs";
import { lstat, readFile, writeFile } from "node:fs/promises";
import { open } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { Pool } from "pg";
import { canonicalJson } from "../../packages/protocol/src/index.mjs";

import {
  createMigrationRunner,
  loadSqlMigrations,
  migrationChecksum,
  migrationStatus
} from "../../apps/cloud-api/src/postgres/migration-runner.mjs";

export const QUALIFICATION_ID = "postgres-c3-migration-0047";
export const TARGET_VERSION = 47;
export const TARGET_NAME = "0047_platform_promotion_issuance.sql";
export const DEFAULT_QUALIFICATION_INPUT_ARTIFACT_PATH = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../contracts/postgres",
  TARGET_NAME
);
export const QUALIFICATION_DIAGNOSTICS = Object.freeze({
  DATABASE_URL_MISSING: "database_url_missing",
  DATABASE_URL_INVALID: "database_url_invalid",
  INVALID_SOURCE_BINDING: "invalid_source_binding",
  INVALID_RUN_BINDING: "invalid_run_binding",
  INVALID_EVIDENCE: "invalid_evidence",
  DATABASE_UNAVAILABLE: "database_unavailable",
  DATABASE_CLEANUP_FAILED: "database_cleanup_failed",
  MIGRATION_FAILED: "migration_failed",
  ROLE_FAILED: "role_failed",
  VERIFICATION_FAILED: "verification_failed",
  SERVER_VERSION_UNEXPECTED: "server_version_unexpected",
  TLS_REQUIRED: "tls_required",
  CA_CERT_INVALID: "ca_cert_invalid",
  REAL_DATABASE_REQUIRED: "real_database_required",
  INVALID_ARTIFACT_BINDING: "invalid_artifact_binding",
  DATABASE_TARGET_MISSING: "database_target_missing",
  BACKUP_PITR_NOT_RUN: "backup_pitr_not_run",
  BACKUP_PITR_FAILED: "backup_pitr_failed"
});
const SOURCE_COMMIT_PATTERN = /^[0-9a-f]{40}$/u;
const SOURCE_TREE_PATTERN = /^[0-9a-f]{40}$/u;
const CI_RUN_ID_PATTERN = /^[1-9][0-9]{0,19}$/u;
const CI_RUN_ATTEMPT_PATTERN = /^[1-9][0-9]{0,9}$/u;
const CI_JOB_ID_PATTERN = /^[A-Za-z0-9_-]{1,100}$/u;
const DATABASE_NAME_PATTERN = /^[A-Za-z0-9_][A-Za-z0-9_$-]{0,62}$/u;
const PORT_PATTERN = /^\d{1,5}$/u;
const SERVER_VERSION_PATTERN = /^\d+(?:\.\d+){1,3}$/u;
const POSTGRES_MAJOR_PATTERN = /^(?:16|17)$/u;
const ARTIFACT_SHA_PATTERN = /^(?!0{64}$)[0-9a-f]{64}$/u;
const MAX_QUALIFICATION_INPUT_ARTIFACT_BYTES = 64 * 1024 * 1024;
const TLS_VERSION_PATTERN = /^TLSv1\.[23]$/u;
const SAFE_REASONS = new Set(Object.values(QUALIFICATION_DIAGNOSTICS));
const QUALIFICATION_CHECK_IDS = Object.freeze([
  "tls_connection",
  "postgres_major",
  "migration_checksum",
  "schema_objects",
  "catalog_constraints_validated",
  "role_privileges_and_ownership",
  "rls_policy_catalog",
  "positive_insert_and_transition",
  "rls_cross_role_read_write",
  "negative_authority_mutation_rejected",
  "audit_event_append_only",
  "generation_contention_single_winner",
  "transaction_rollback",
  "cross_role_privilege_boundary",
  "backup_restore",
  "pitr_recovery"
]);
const QUALIFICATION_EVIDENCE_KEYS = Object.freeze([
  "artifact_sha256", "checks", "ci_job_id", "ci_run_attempt", "ci_run_id", "completed_at", "current_version",
  "migration_applied_this_run", "migration_checksum", "migration_name", "migration_version",
  "qualification", "qualified", "reason", "redacted", "schema_version", "server_version", "database_name", "server_port", "tls_version",
  "source_commit", "source_tree", "started_at", "status"
]);

const TYPED_VALUE_TYPES = new Set(["boolean", "integer", "status", "string"]);
const CHECK_STATUS = new Set(["passed", "failed", "not_run"]);
const CHECK_STATUS_VALUES = new Set(["passed", "failed", "not_run"]);
const BACKUP_PITR_EVIDENCE_KEYS = Object.freeze([
  "artifact_sha256", "backup_restore", "ci_job_id", "ci_run_attempt", "ci_run_id",
  "pitr_recovery", "redacted", "schema_version", "source_commit", "source_tree"
]);

export const ROLE_NAMES = Object.freeze({
  app: "agentpass_app",
  migrator: "agentpass_migrator",
  backup: "agentpass_backup"
});

const DATABASE_ENV_NAMES = Object.freeze([
  "AGENTPASS_TEST_DATABASE_URL",
  "AGENTPASS_TEST_POSTGRES_URL"
]);
const REQUIRED_RELATIONS = Object.freeze([
  "platform_promotion_issuances",
  "platform_deployment_state",
  "platform_promotion_audit_events"
]);
const REQUIRED_INDEXES = Object.freeze([
  "platform_promotion_approvals_issuance_binding",
  "platform_promotion_issuances_one_open",
  "platform_promotion_issuances_claims"
]);
const REQUIRED_TRIGGERS = Object.freeze([
  "platform_promotion_issuances_guard",
  "platform_deployment_generation_guard",
  "platform_promotion_audit_events_guard"
]);
const REQUIRED_FUNCTIONS = Object.freeze([
  "agentpass_promotion_digest_array_valid",
  "agentpass_guard_platform_promotion_issuance",
  "agentpass_guard_platform_deployment_generation",
  "agentpass_guard_platform_promotion_audit_event"
]);
const REQUIRED_POLICIES = Object.freeze([
  "platform_promotion_approvals_runtime_select",
  "platform_promotion_approvals_backup_select",
  "platform_promotion_approvals_migration_all",
  "platform_promotion_issuances_runtime_select",
  "platform_promotion_issuances_runtime_insert",
  "platform_promotion_issuances_runtime_update",
  "platform_promotion_issuances_backup_select",
  "platform_promotion_issuances_migration_all",
  "platform_deployment_state_runtime_select",
  "platform_deployment_state_runtime_insert",
  "platform_deployment_state_runtime_update",
  "platform_deployment_state_backup_select",
  "platform_deployment_state_migration_all",
  "platform_promotion_audit_events_runtime_select",
  "platform_promotion_audit_events_runtime_insert",
  "platform_promotion_audit_events_backup_select",
  "platform_promotion_audit_events_migration_all"
]);
const ROLE_SQL_PATH = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../postgres/roles.sql");
const EXPECTED_ISSUANCE_COLUMNS = Object.freeze([
  "deployment_id", "environment", "promotion_id", "idempotency_key", "candidate_id",
  "source_commit", "source_tree", "product_pkg_sha256", "release_manifest_sha256",
  "sbom_sha256", "image_digest", "qualification_report_digests", "approval_id",
  "approval_digest", "signer_key_id", "signer_key_version", "signer_lifecycle_version",
  "expected_deployment_generation", "state", "claim_token_digest", "claim_expires_at",
  "provider_operation_id", "provider_operation_purpose", "uncertain_reason", "evidence", "rejection_reason", "authority_digest",
  "created_at", "updated_at"
]);
const EXPECTED_AUDIT_COLUMNS = Object.freeze([
  "event_id", "request_id", "event_type", "actor_id", "platform_role", "target_type", "target_id",
  "idempotency_key", "details", "event_hash", "recorded_at"
]);

export function qualificationDatabaseUrl(env = process.env) {
  for (const name of DATABASE_ENV_NAMES) {
    if (typeof env?.[name] === "string" && env[name].length > 0) return env[name];
  }
  return undefined;
}

export function qualificationInputArtifactPath({ env = process.env, migrationDirectory } = {}) {
  if (typeof env?.AGENTPASS_C3_ARTIFACT_PATH === "string") return env.AGENTPASS_C3_ARTIFACT_PATH;
  if (migrationDirectory !== undefined) return path.resolve(migrationDirectory, TARGET_NAME);
  return DEFAULT_QUALIFICATION_INPUT_ARTIFACT_PATH;
}

function safeQualificationInputArtifactMetadata(metadata) {
  return metadata && metadata.isFile() && !metadata.isSymbolicLink()
    && metadata.nlink === 1 && (metadata.mode & 0o022) === 0
    && metadata.size > 0 && metadata.size <= MAX_QUALIFICATION_INPUT_ARTIFACT_BYTES;
}

function qualificationInputArtifactIdentity(metadata) {
  return [metadata.dev, metadata.ino, metadata.mode, metadata.nlink, metadata.size, metadata.mtimeMs].join(":");
}

export async function computeQualificationInputArtifactSha256(inputPath = DEFAULT_QUALIFICATION_INPUT_ARTIFACT_PATH) {
  if (typeof inputPath !== "string" || !path.isAbsolute(inputPath) || !Number.isInteger(fsConstants.O_NOFOLLOW)) {
    throw qualificationError(QUALIFICATION_DIAGNOSTICS.INVALID_ARTIFACT_BINDING);
  }
  const beforePath = await lstat(inputPath).catch(() => null);
  if (!safeQualificationInputArtifactMetadata(beforePath)) {
    throw qualificationError(QUALIFICATION_DIAGNOSTICS.INVALID_ARTIFACT_BINDING);
  }
  let handle;
  try {
    handle = await open(inputPath, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
    const before = await handle.stat();
    if (!safeQualificationInputArtifactMetadata(before)
      || qualificationInputArtifactIdentity(before) !== qualificationInputArtifactIdentity(beforePath)) {
      throw qualificationError(QUALIFICATION_DIAGNOSTICS.INVALID_ARTIFACT_BINDING);
    }
    const bytes = await handle.readFile();
    const after = await handle.stat();
    const afterPath = await lstat(inputPath).catch(() => null);
    if (bytes.length !== before.size || !safeQualificationInputArtifactMetadata(after)
      || !safeQualificationInputArtifactMetadata(afterPath)
      || qualificationInputArtifactIdentity(before) !== qualificationInputArtifactIdentity(after)
      || qualificationInputArtifactIdentity(after) !== qualificationInputArtifactIdentity(afterPath)) {
      throw qualificationError(QUALIFICATION_DIAGNOSTICS.INVALID_ARTIFACT_BINDING);
    }
    const digest = crypto.createHash("sha256").update(bytes).digest("hex");
    if (!ARTIFACT_SHA_PATTERN.test(digest)) {
      throw qualificationError(QUALIFICATION_DIAGNOSTICS.INVALID_ARTIFACT_BINDING);
    }
    return digest;
  } catch (error) {
    if (error?.qualificationReason === QUALIFICATION_DIAGNOSTICS.INVALID_ARTIFACT_BINDING) throw error;
    throw qualificationError(QUALIFICATION_DIAGNOSTICS.INVALID_ARTIFACT_BINDING);
  } finally {
    await handle?.close().catch(() => {});
  }
}

export function validateQualificationDatabaseUrl(raw, { requireTls = true } = {}) {
  if (typeof raw !== "string" || raw.length === 0 || raw.includes("\u0000")) {
    throw new TypeError("qualification database URL is missing");
  }
  const parsed = new URL(raw);
  if (parsed.protocol !== "postgresql:"
    || !parsed.hostname
    || !parsed.username
    || !parsed.password
    || !parsed.pathname
    || parsed.pathname === "/"
    || parsed.hash) {
    throw new TypeError("qualification database URL is invalid");
  }
  const sslModes = parsed.searchParams.getAll("sslmode");
  if (requireTls && (sslModes.length !== 1 || sslModes[0] !== "verify-full")) {
    throw new TypeError("qualification database URL must use sslmode=verify-full");
  }
  return parsed;
}

async function readQualificationCaCertificate(caCertPath) {
  if (typeof caCertPath !== "string" || !path.isAbsolute(caCertPath)) {
    throw qualificationError(QUALIFICATION_DIAGNOSTICS.CA_CERT_INVALID);
  }
  const metadata = await lstat(caCertPath).catch(() => null);
  if (!metadata || !metadata.isFile() || metadata.isSymbolicLink() || metadata.nlink !== 1
    || (metadata.mode & 0o022) !== 0 || metadata.size <= 0 || metadata.size > 1024 * 1024) {
    throw qualificationError(QUALIFICATION_DIAGNOSTICS.CA_CERT_INVALID);
  }
  const pem = await readFile(caCertPath, "utf8");
  if (!/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/u.test(pem)
    || /-----BEGIN [^-]*PRIVATE KEY-----/u.test(pem)
    || /-----BEGIN (?:RSA |EC )?PRIVATE KEY-----/u.test(pem)) {
    throw qualificationError(QUALIFICATION_DIAGNOSTICS.CA_CERT_INVALID);
  }
  return pem;
}

function requireExpectedPostgresMajor(value) {
  if (typeof value !== "string" || !POSTGRES_MAJOR_PATTERN.test(value)) {
    throw qualificationError(QUALIFICATION_DIAGNOSTICS.SERVER_VERSION_UNEXPECTED);
  }
  return value;
}

function checkEvidenceDigest(check) {
  return crypto.createHash("sha256").update(canonicalJson({
    check_id: check.id,
    expected: check.expected,
    observed: check.observed,
    status: check.status
  }), "utf8").digest("hex");
}

function typedValue(type, value) {
  if (!TYPED_VALUE_TYPES.has(type)) throw new TypeError(QUALIFICATION_DIAGNOSTICS.INVALID_EVIDENCE);
  if (type === "boolean" && typeof value !== "boolean") throw new TypeError(QUALIFICATION_DIAGNOSTICS.INVALID_EVIDENCE);
  if (type === "integer" && (!Number.isSafeInteger(value))) throw new TypeError(QUALIFICATION_DIAGNOSTICS.INVALID_EVIDENCE);
  if ((type === "status" || type === "string") && typeof value !== "string") throw new TypeError(QUALIFICATION_DIAGNOSTICS.INVALID_EVIDENCE);
  if (type === "status" && !CHECK_STATUS_VALUES.has(value)) throw new TypeError(QUALIFICATION_DIAGNOSTICS.INVALID_EVIDENCE);
  return Object.freeze({ type, value });
}

function makeCheck(id, expected, observed, status = observed === expected ? "passed" : "failed") {
  const check = {
    id,
    status,
    expected: typedValue(typeof expected === "number" ? "integer" : typeof expected === "boolean" ? "boolean" : CHECK_STATUS_VALUES.has(expected) ? "status" : "string", expected),
    observed: typedValue(typeof observed === "number" ? "integer" : typeof observed === "boolean" ? "boolean" : CHECK_STATUS_VALUES.has(observed) ? "status" : "string", observed),
    evidence_sha256: null
  };
  check.evidence_sha256 = checkEvidenceDigest(check);
  return Object.freeze(check);
}

function notRunChecks() {
  return Object.freeze(QUALIFICATION_CHECK_IDS.map((id) => makeCheck(id, "passed", "not_run", "not_run")));
}

function failedChecks(failedId) {
  return Object.freeze(QUALIFICATION_CHECK_IDS.map((id) => id === failedId
    ? makeCheck(id, true, false, "failed")
    : makeCheck(id, "passed", "not_run", "not_run")));
}

function normalizeBackupPitrEvidence(value, binding) {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || JSON.stringify(Object.keys(value).sort()) !== JSON.stringify([...BACKUP_PITR_EVIDENCE_KEYS].sort())
    || value.schema_version !== 1 || value.redacted !== true) {
    throw qualificationError(QUALIFICATION_DIAGNOSTICS.BACKUP_PITR_FAILED);
  }
  for (const [key, expected] of [["source_commit", binding.sourceCommit], ["source_tree", binding.sourceTree],
    ["ci_run_id", binding.ciRunId], ["ci_run_attempt", binding.ciRunAttempt], ["ci_job_id", binding.ciJobId],
    ["artifact_sha256", binding.artifactSha256]]) {
    if (value[key] !== expected) throw qualificationError(QUALIFICATION_DIAGNOSTICS.INVALID_ARTIFACT_BINDING);
  }
  const checks = [];
  for (const [id, check] of [["backup_restore", value.backup_restore], ["pitr_recovery", value.pitr_recovery]]) {
    assertTypedCheck(check, id);
    checks.push(check);
  }
  if (checks.some((check) => check.status !== "passed")) {
    throw qualificationError(QUALIFICATION_DIAGNOSTICS.BACKUP_PITR_FAILED);
  }
  return Object.freeze({ ...value, backup_restore: checks[0], pitr_recovery: checks[1] });
}

async function loadBackupPitrEvidence(inputPath, binding) {
  if (inputPath === undefined) throw qualificationError(QUALIFICATION_DIAGNOSTICS.BACKUP_PITR_NOT_RUN);
  if (typeof inputPath !== "string" || !path.isAbsolute(inputPath)) {
    throw qualificationError(QUALIFICATION_DIAGNOSTICS.BACKUP_PITR_FAILED);
  }
  const metadata = await lstat(inputPath).catch(() => null);
  if (!metadata || !metadata.isFile() || metadata.isSymbolicLink() || metadata.nlink !== 1
    || (metadata.mode & 0o022) !== 0 || metadata.size <= 0 || metadata.size > 1024 * 1024) {
    throw qualificationError(QUALIFICATION_DIAGNOSTICS.BACKUP_PITR_FAILED);
  }
  let value;
  let serialized;
  try {
    serialized = await readFile(inputPath, "utf8");
    if (!serialized.endsWith("\n")) throw new Error("non-canonical");
    value = JSON.parse(serialized);
  } catch {
    throw qualificationError(QUALIFICATION_DIAGNOSTICS.BACKUP_PITR_FAILED);
  }
  const normalized = normalizeBackupPitrEvidence(value, binding);
  if (`${canonicalJson(normalized)}\n` !== serialized) {
    throw qualificationError(QUALIFICATION_DIAGNOSTICS.BACKUP_PITR_FAILED);
  }
  return normalized;
}

function assertTypedCheck(check, expectedId) {
  if (!check || typeof check !== "object" || Array.isArray(check)
    || JSON.stringify(Object.keys(check).sort()) !== JSON.stringify(["evidence_sha256", "expected", "id", "observed", "status"])
    || check.id !== expectedId || check.status !== "passed"
    || !check.expected || JSON.stringify(Object.keys(check.expected).sort()) !== JSON.stringify(["type", "value"])
    || !check.observed || JSON.stringify(Object.keys(check.observed).sort()) !== JSON.stringify(["type", "value"])
    || check.expected?.type !== "status" || check.expected.value !== "passed"
    || check.observed?.type !== "status" || check.observed.value !== "passed"
    || typeof check.evidence_sha256 !== "string" || !ARTIFACT_SHA_PATTERN.test(check.evidence_sha256)
    || check.evidence_sha256 !== checkEvidenceDigest(check)) {
    throw qualificationError(QUALIFICATION_DIAGNOSTICS.BACKUP_PITR_FAILED);
  }
  return check;
}

async function requireTlsConnection(client) {
  const result = await client.query(`
    SELECT ssl, version
    FROM pg_catalog.pg_stat_ssl
    WHERE pid = pg_backend_pid()`);
  const row = result.rows?.[0];
  if (!row || row.ssl !== true || typeof row.version !== "string" || !TLS_VERSION_PATTERN.test(row.version)) {
    throw qualificationError(QUALIFICATION_DIAGNOSTICS.TLS_REQUIRED);
  }
  return Object.freeze({ version: row.version });
}

export async function runC3Migration0047Qualification({
  env = process.env,
  databaseUrl = qualificationDatabaseUrl(env),
  sourceCommit = env.AGENTPASS_C3_SOURCE_COMMIT ?? env.GITHUB_SHA,
  sourceTree = env.AGENTPASS_C3_SOURCE_TREE,
  ciRunId = env.AGENTPASS_C3_CI_RUN_ID ?? env.AGENTPASS_C3_RUN_ID ?? env.GITHUB_RUN_ID,
  ciRunAttempt = env.AGENTPASS_C3_CI_RUN_ATTEMPT ?? env.AGENTPASS_C3_RUN_ATTEMPT ?? env.GITHUB_RUN_ATTEMPT,
  ciJobId = env.AGENTPASS_C3_CI_JOB_ID ?? env.AGENTPASS_C3_JOB_ID ?? env.GITHUB_JOB,
  artifactSha256 = env.AGENTPASS_C3_ARTIFACT_SHA256 ?? env.AGENTPASS_QUALIFICATION_ARTIFACT_SHA256,
  artifactPath,
  expectedPostgresMajor = env.AGENTPASS_C3_EXPECTED_POSTGRES_MAJOR,
  expectedDatabaseName = env.AGENTPASS_C3_EXPECTED_DATABASE_NAME,
  expectedServerPort = env.AGENTPASS_C3_EXPECTED_SERVER_PORT,
  caCertPath = env.AGENTPASS_C3_CA_CERT_FILE,
  backupPitrEvidencePath = env.AGENTPASS_C3_BACKUP_PITR_EVIDENCE,
  PoolClass = Pool,
  migrationDirectory,
  roleSqlPath = ROLE_SQL_PATH,
  now = () => new Date()
} = {}) {
  const startedAt = now().toISOString();
  if (databaseUrl === undefined) {
    return notRunEvidence(startedAt, QUALIFICATION_DIAGNOSTICS.DATABASE_URL_MISSING,
      qualificationBinding({ sourceCommit, sourceTree, ciRunId, ciRunAttempt, ciJobId, artifactSha256 }));
  }

  const inputArtifactPath = artifactPath ?? qualificationInputArtifactPath({ env, migrationDirectory });
  let computedArtifactSha256;
  try {
    computedArtifactSha256 = await computeQualificationInputArtifactSha256(inputArtifactPath);
    if (artifactSha256 !== undefined && (!ARTIFACT_SHA_PATTERN.test(String(artifactSha256)) || artifactSha256 !== computedArtifactSha256)) {
      throw qualificationError(QUALIFICATION_DIAGNOSTICS.INVALID_ARTIFACT_BINDING);
    }
    artifactSha256 = computedArtifactSha256;
  } catch {
    return failedEvidence(startedAt, QUALIFICATION_DIAGNOSTICS.INVALID_ARTIFACT_BINDING,
      qualificationBinding({ sourceCommit, sourceTree, ciRunId, ciRunAttempt, ciJobId, artifactSha256: null }));
  }
  const binding = qualificationBinding({ sourceCommit, sourceTree, ciRunId, ciRunAttempt, ciJobId, artifactSha256: computedArtifactSha256 });

  if (typeof sourceCommit !== "string" || !SOURCE_COMMIT_PATTERN.test(sourceCommit)) {
    return failedEvidence(startedAt, QUALIFICATION_DIAGNOSTICS.INVALID_SOURCE_BINDING, binding);
  }
  if (typeof sourceTree !== "string" || !SOURCE_TREE_PATTERN.test(sourceTree)) {
    return failedEvidence(startedAt, QUALIFICATION_DIAGNOSTICS.INVALID_SOURCE_BINDING, binding);
  }
  if (typeof ciRunId !== "string" || !CI_RUN_ID_PATTERN.test(ciRunId)
    || typeof ciRunAttempt !== "string" || !CI_RUN_ATTEMPT_PATTERN.test(ciRunAttempt)
    || typeof ciJobId !== "string" || !CI_JOB_ID_PATTERN.test(ciJobId)) {
    return failedEvidence(startedAt, QUALIFICATION_DIAGNOSTICS.INVALID_RUN_BINDING, binding);
  }
  if (typeof artifactSha256 !== "string" || !ARTIFACT_SHA_PATTERN.test(artifactSha256)) {
    return failedEvidence(startedAt, QUALIFICATION_DIAGNOSTICS.INVALID_ARTIFACT_BINDING, binding);
  }
  let parsed;
  try {
    parsed = validateQualificationDatabaseUrl(databaseUrl);
  } catch {
    return failedEvidence(startedAt, QUALIFICATION_DIAGNOSTICS.DATABASE_URL_INVALID, binding);
  }
  if (PoolClass !== Pool && (env.AGENTPASS_C3_ALLOW_TEST_POOL !== "true"
    || env.AGENTPASS_C3_REQUIRE_REAL_DATABASE === "1")) {
    return failedEvidence(startedAt, QUALIFICATION_DIAGNOSTICS.REAL_DATABASE_REQUIRED, binding);
  }
  try {
    requireExpectedPostgresMajor(String(expectedPostgresMajor));
  } catch {
    return failedEvidence(startedAt, QUALIFICATION_DIAGNOSTICS.SERVER_VERSION_UNEXPECTED, binding);
  }
  if ((typeof env.GITHUB_SHA === "string" && env.GITHUB_SHA !== sourceCommit)
    || (typeof env.GITHUB_RUN_ID === "string" && env.GITHUB_RUN_ID !== ciRunId)
    || (typeof env.GITHUB_RUN_ATTEMPT === "string" && env.GITHUB_RUN_ATTEMPT !== ciRunAttempt)
    || (typeof env.GITHUB_JOB === "string" && env.GITHUB_JOB !== ciJobId)) {
    return failedEvidence(startedAt, QUALIFICATION_DIAGNOSTICS.INVALID_RUN_BINDING, binding);
  }
  if (expectedPostgresMajor !== undefined && !/^\d{1,2}$/u.test(String(expectedPostgresMajor))) {
    return failedEvidence(startedAt, QUALIFICATION_DIAGNOSTICS.SERVER_VERSION_UNEXPECTED, binding);
  }
  if (expectedDatabaseName !== undefined && !DATABASE_NAME_PATTERN.test(String(expectedDatabaseName))) {
    return failedEvidence(startedAt, QUALIFICATION_DIAGNOSTICS.INVALID_EVIDENCE, binding);
  }
  if (expectedServerPort !== undefined && (!PORT_PATTERN.test(String(expectedServerPort)) || Number(expectedServerPort) < 1 || Number(expectedServerPort) > 65535)) {
    return failedEvidence(startedAt, QUALIFICATION_DIAGNOSTICS.INVALID_EVIDENCE, binding);
  }
  if (ciJobId !== `postgres-authority-${expectedPostgresMajor}`) {
    return failedEvidence(startedAt, QUALIFICATION_DIAGNOSTICS.INVALID_RUN_BINDING, binding);
  }
  const testPool = PoolClass !== Pool && env.AGENTPASS_C3_ALLOW_TEST_POOL === "true";
  if (!testPool && (expectedDatabaseName === undefined || expectedServerPort === undefined)) {
    return failedEvidence(startedAt, QUALIFICATION_DIAGNOSTICS.DATABASE_TARGET_MISSING, binding);
  }

  let caPem;
  if (!testPool) {
    try {
      caPem = await readQualificationCaCertificate(caCertPath);
    } catch (error) {
      return failedEvidence(startedAt, error?.qualificationReason ?? QUALIFICATION_DIAGNOSTICS.CA_CERT_INVALID, binding);
    }
  }
  let backupPitr;
  if (!testPool) {
    try {
      backupPitr = await loadBackupPitrEvidence(backupPitrEvidencePath, binding);
    } catch (error) {
      return failedEvidence(startedAt, error?.qualificationReason ?? QUALIFICATION_DIAGNOSTICS.BACKUP_PITR_FAILED, binding);
    }
  }

  let migrations;
  let rolesSql;
  try {
    migrations = await loadSqlMigrations(migrationDirectory);
    rolesSql = await readFile(roleSqlPath, "utf8");
  } catch {
    return failedEvidence(startedAt, QUALIFICATION_DIAGNOSTICS.MIGRATION_FAILED, binding);
  }
  const target = migrations.find((migration) => migration.version === TARGET_VERSION);
  if (!target || target.name !== TARGET_NAME) return failedEvidence(startedAt, QUALIFICATION_DIAGNOSTICS.MIGRATION_FAILED, binding);

  const pool = new PoolClass({
    connectionString: parsed.toString(),
    ssl: { ca: caPem, rejectUnauthorized: true, servername: parsed.hostname, minVersion: "TLSv1.2" },
    max: 8,
    connectionTimeoutMillis: 5_000,
    idleTimeoutMillis: 2_000,
    statement_timeout: 15_000,
    lock_timeout: 5_000,
    query_timeout: 20_000,
    allowExitOnIdle: false
  });
  let client;
  let connected = false;
  let migration;
  let result;
  let cleanupError;
  try {
    client = await pool.connect();
    connected = true;
    await requireQualificationAdministrator(client);
    const tls = await requireTlsConnection(client);
    await applyRoleContract(client, rolesSql);
    client.release(true);
    client = undefined;
    client = await pool.connect();
    await setSessionAuthorization(client, ROLE_NAMES.migrator);
    migration = await createMigrationRunner({
      client,
      migrations,
      applicationVersion: QUALIFICATION_ID
    }).run();
    client.release(true);
    client = undefined;
    client = await pool.connect();
    await applyRoleContract(client, rolesSql);
    const server = await client.query("SELECT current_setting('server_version') AS server_version, current_database() AS database_name, inet_server_port() AS server_port");
    const status = await migrationStatus({ client, migrations: Promise.resolve(migrations) });
    if (status.currentVersion !== TARGET_VERSION || status.pending.length !== 0
      || status.modified.length !== 0 || status.dirty === true) {
      throw qualificationError(QUALIFICATION_DIAGNOSTICS.MIGRATION_FAILED);
    }
    const serverVersion = normalizeServerVersion(server.rows?.[0]?.server_version);
    const databaseName = server.rows?.[0]?.database_name;
    const serverPort = Number(server.rows?.[0]?.server_port);
    if (typeof databaseName !== "string" || !DATABASE_NAME_PATTERN.test(databaseName)
      || !Number.isSafeInteger(serverPort) || serverPort < 1 || serverPort > 65535
      || (expectedDatabaseName !== undefined && databaseName !== String(expectedDatabaseName))
      || (expectedServerPort !== undefined && serverPort !== Number(expectedServerPort))) {
      throw qualificationError(QUALIFICATION_DIAGNOSTICS.INVALID_EVIDENCE);
    }
    if (expectedPostgresMajor !== undefined && !serverVersion.startsWith(`${expectedPostgresMajor}.`)
      && serverVersion !== String(expectedPostgresMajor)) {
      throw qualificationError(QUALIFICATION_DIAGNOSTICS.SERVER_VERSION_UNEXPECTED);
    }
    const checks = await verifyMigration0047({ client, pool, target, tls, backupPitr });
    assertQualificationChecks(checks);
    const completedAt = now().toISOString();
    result = Object.freeze({
      schema_version: 1,
      qualification: QUALIFICATION_ID,
      status: "passed",
      qualified: true,
      reason: null,
      started_at: startedAt,
      completed_at: completedAt,
      migration_version: TARGET_VERSION,
      migration_name: TARGET_NAME,
      migration_checksum: target.checksum,
      migration_applied_this_run: migration.applied.some((item) => item.version === TARGET_VERSION),
      current_version: status.currentVersion,
      server_version: serverVersion,
      database_name: databaseName,
      server_port: serverPort,
      tls_version: tls.version,
      artifact_sha256: artifactSha256,
      source_commit: sourceCommit,
      source_tree: sourceTree,
      ci_run_id: ciRunId,
      ci_run_attempt: ciRunAttempt,
      ci_job_id: ciJobId,
      redacted: true,
      checks: Object.freeze(checks)
    });
  } catch (error) {
    const reason = !connected || error?.code === "ECONNREFUSED" || error?.code === "ENOTFOUND" || error?.code === "ETIMEDOUT"
      ? QUALIFICATION_DIAGNOSTICS.DATABASE_UNAVAILABLE
      : error?.code?.startsWith?.("ERR_MIGRATION_")
        ? QUALIFICATION_DIAGNOSTICS.MIGRATION_FAILED
        : [QUALIFICATION_DIAGNOSTICS.ROLE_FAILED, QUALIFICATION_DIAGNOSTICS.MIGRATION_FAILED,
          QUALIFICATION_DIAGNOSTICS.SERVER_VERSION_UNEXPECTED, QUALIFICATION_DIAGNOSTICS.TLS_REQUIRED,
          QUALIFICATION_DIAGNOSTICS.BACKUP_PITR_NOT_RUN, QUALIFICATION_DIAGNOSTICS.BACKUP_PITR_FAILED,
          QUALIFICATION_DIAGNOSTICS.INVALID_ARTIFACT_BINDING, QUALIFICATION_DIAGNOSTICS.INVALID_EVIDENCE,
          QUALIFICATION_DIAGNOSTICS.DATABASE_TARGET_MISSING].includes(error?.qualificationReason)
          ? error.qualificationReason
        : QUALIFICATION_DIAGNOSTICS.VERIFICATION_FAILED;
    result = failedEvidence(startedAt, reason, binding, reason === QUALIFICATION_DIAGNOSTICS.BACKUP_PITR_NOT_RUN
      ? backupPitr : undefined);
  } finally {
    client?.release?.(true);
    try {
      await pool.end();
    } catch (error) {
      cleanupError = error;
    }
  }
  return downgradeSuccessfulQualificationOnCleanupFailure(result, {
    cleanupError,
    startedAt,
    binding
  });
}

export function downgradeSuccessfulQualificationOnCleanupFailure(evidence, { cleanupError, startedAt, binding } = {}) {
  if (!cleanupError || evidence?.status !== "passed") return evidence;
  return failedEvidence(startedAt, QUALIFICATION_DIAGNOSTICS.DATABASE_CLEANUP_FAILED, binding);
}

function qualificationError(reason, message = reason) {
  const error = new Error(message);
  error.qualificationReason = reason;
  return error;
}

async function requireQualificationAdministrator(client) {
  const result = await client.query(`
    SELECT current_user AS role_name, session_user,
           COALESCE((SELECT rolsuper FROM pg_catalog.pg_roles WHERE rolname=current_user), false) AS is_superuser`);
  const row = result.rows?.[0];
  if (!row || row.session_user !== row.role_name || row.is_superuser !== true) {
    throw qualificationError(QUALIFICATION_DIAGNOSTICS.ROLE_FAILED);
  }
}

async function applyRoleContract(client, source) {
  const sql = source
    .split("\n")
    .filter((line) => !/^\s*\\[A-Za-z][^\r\n]*$/u.test(line))
    .join("\n");
  try {
    await client.query(sql);
  } catch (error) {
    throw qualificationError(QUALIFICATION_DIAGNOSTICS.ROLE_FAILED, error?.message ?? "role contract failed");
  }
}

async function setSessionAuthorization(client, roleName) {
  if (!Object.values(ROLE_NAMES).includes(roleName)) throw new TypeError("unsupported qualification role");
  await client.query(`SET SESSION AUTHORIZATION ${roleName}`);
  const result = await client.query("SELECT session_user, current_user");
  if (result.rows?.[0]?.session_user !== roleName || result.rows?.[0]?.current_user !== roleName) {
    throw qualificationError(QUALIFICATION_DIAGNOSTICS.ROLE_FAILED);
  }
}

async function verifyMigration0047({ client, pool, target, tls, backupPitr }) {
  if (!backupPitr) throw qualificationError(QUALIFICATION_DIAGNOSTICS.BACKUP_PITR_NOT_RUN);
  const migrationRow = await client.query(
    "SELECT version, checksum FROM schema_migrations WHERE version=$1",
    [TARGET_VERSION]
  );
  if (migrationRow.rowCount !== 1 || Number(migrationRow.rows[0].version) !== TARGET_VERSION
    || migrationRow.rows[0].checksum !== target.checksum
    || target.checksum !== migrationChecksum(target.sql)) throw new Error("migration checksum verification failed");

  const relations = await client.query(`
    SELECT c.relname
    FROM pg_catalog.pg_class c
    JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
    WHERE n.nspname='public' AND c.relkind='r' AND c.relname=ANY($1::text[])
    ORDER BY c.relname`, [REQUIRED_RELATIONS]);
  assertExactNames(relations.rows, REQUIRED_RELATIONS, "relations");

  const columns = await client.query(`
    SELECT a.attname AS name
    FROM pg_catalog.pg_attribute a
    JOIN pg_catalog.pg_class c ON c.oid=a.attrelid
    JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
    WHERE n.nspname='public' AND c.relname='platform_promotion_issuances'
      AND a.attnum > 0 AND NOT a.attisdropped
    ORDER BY a.attnum`);
  assertExactNames(columns.rows, EXPECTED_ISSUANCE_COLUMNS, "issuance columns");

  const auditColumns = await client.query(`
    SELECT a.attname AS name
    FROM pg_catalog.pg_attribute a
    JOIN pg_catalog.pg_class c ON c.oid=a.attrelid
    JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
    WHERE n.nspname='public' AND c.relname='platform_promotion_audit_events'
      AND a.attnum > 0 AND NOT a.attisdropped
    ORDER BY a.attnum`);
  assertExactNames(auditColumns.rows, EXPECTED_AUDIT_COLUMNS, "audit columns");

  const indexes = await client.query(`
    SELECT indexname AS name
    FROM pg_catalog.pg_indexes
    WHERE schemaname='public' AND indexname=ANY($1::text[])
    ORDER BY indexname`, [REQUIRED_INDEXES]);
  assertExactNames(indexes.rows, REQUIRED_INDEXES, "indexes");

  const triggers = await client.query(`
    SELECT t.tgname AS name
    FROM pg_catalog.pg_trigger t
    JOIN pg_catalog.pg_class c ON c.oid=t.tgrelid
    JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
    WHERE n.nspname='public' AND NOT t.tgisinternal AND t.tgname=ANY($1::text[])
    ORDER BY t.tgname`, [REQUIRED_TRIGGERS]);
  assertExactNames(triggers.rows, REQUIRED_TRIGGERS, "triggers");

  const functions = await client.query(`
    SELECT p.proname AS name
    FROM pg_catalog.pg_proc p
    JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
    WHERE n.nspname='public' AND p.proname=ANY($1::text[])
    GROUP BY p.proname
    ORDER BY p.proname`, [REQUIRED_FUNCTIONS]);
  assertExactNames(functions.rows, REQUIRED_FUNCTIONS, "functions");

  const policies = await client.query(`
    SELECT p.polname AS name
    FROM pg_catalog.pg_policy p
    JOIN pg_catalog.pg_class c ON c.oid=p.polrelid
    JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
    WHERE n.nspname='public' AND p.polname=ANY($1::text[])
    ORDER BY p.polname`, [REQUIRED_POLICIES]);
  assertExactNames(policies.rows, REQUIRED_POLICIES, "RLS policies");

  const rls = await client.query(`
    SELECT c.relname AS name, c.relrowsecurity AS enabled, c.relforcerowsecurity AS forced
    FROM pg_catalog.pg_class c
    JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
    WHERE n.nspname='public' AND c.relname=ANY($1::text[])
    ORDER BY c.relname`, [["platform_promotion_approvals", ...REQUIRED_RELATIONS]]);
  if (rls.rowCount !== 4 || rls.rows.some((row) => row.enabled !== true || row.forced !== true)) throw new Error("platform RLS is not enabled and forced");

  const constraints = await client.query(`
    SELECT c.conname AS name, r.relname AS relation, c.convalidated AS validated
    FROM pg_catalog.pg_constraint c
    JOIN pg_catalog.pg_class r ON r.oid=c.conrelid
    JOIN pg_catalog.pg_namespace n ON n.oid=r.relnamespace
    WHERE n.nspname='public' AND r.relname IN ('platform_promotion_issuances','platform_deployment_state','platform_promotion_audit_events')
    ORDER BY conname`);
  const constrainedRelations = new Set(constraints.rows.map((row) => row.relation));
  if (constraints.rowCount === 0
    || constraints.rows.some((row) => row.validated !== true)
    || !["platform_promotion_issuances", "platform_deployment_state", "platform_promotion_audit_events"].every((name) => constrainedRelations.has(name))) {
    throw new Error("migration constraints are not fully validated");
  }

  await verifyRoleAndRlsCatalog(client);
  const backupChecks = [
    assertTypedCheck(backupPitr.backup_restore, "backup_restore"),
    assertTypedCheck(backupPitr.pitr_recovery, "pitr_recovery")
  ];
  return Object.freeze([
    { id: "tls_connection", status: tls.version ? "passed" : "failed" },
    { id: "postgres_major", status: "passed" },
    { id: "migration_checksum", status: "passed" },
    { id: "schema_objects", status: "passed" },
    { id: "catalog_constraints_validated", status: "passed" },
    { id: "role_privileges_and_ownership", status: "passed" },
    { id: "rls_policy_catalog", status: "passed" },
    ...(await runBehaviorAndContentionProbes(client, pool)),
    { id: "cross_role_privilege_boundary", status: "passed" },
    { id: "backup_restore", status: backupChecks[0].status },
    { id: "pitr_recovery", status: backupChecks[1].status }
  ]);
}

async function verifyRoleAndRlsCatalog(client) {
  const roles = await client.query(`
    SELECT rolname AS name, rolcanlogin, rolinherit, rolsuper, rolcreaterole,
           rolcreatedb, rolreplication, rolbypassrls
    FROM pg_catalog.pg_roles
    WHERE rolname=ANY($1::text[])
    ORDER BY rolname`, [Object.values(ROLE_NAMES)]);
  assertExactNames(roles.rows, Object.values(ROLE_NAMES), "qualification roles");
  if (roles.rows.some((row) => row.rolcanlogin !== true || row.rolinherit !== false
    || row.rolsuper !== false || row.rolcreaterole !== false || row.rolcreatedb !== false
    || row.rolreplication !== false || row.rolbypassrls !== false)) {
    throw new Error("qualification role attributes are too broad");
  }

  const memberships = await client.query(`
    SELECT 1
    FROM pg_catalog.pg_auth_members m
    JOIN pg_catalog.pg_roles granted ON granted.oid=m.roleid
    JOIN pg_catalog.pg_roles member ON member.oid=m.member
    WHERE granted.rolname=ANY($1::text[]) OR member.rolname=ANY($1::text[])
    LIMIT 1`, [Object.values(ROLE_NAMES)]);
  if (memberships.rowCount !== 0) throw new Error("qualification roles have an unexpected membership");

  const protectedRelations = ["platform_promotion_approvals", ...REQUIRED_RELATIONS];
  const relationCatalog = await client.query(`
    SELECT c.relname AS name, pg_get_userbyid(c.relowner) AS owner,
           c.relrowsecurity, c.relforcerowsecurity
    FROM pg_catalog.pg_class c
    JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
    WHERE n.nspname='public' AND c.relname=ANY($1::text[])
    ORDER BY c.relname`, [protectedRelations]);
  assertExactNames(relationCatalog.rows, protectedRelations, "protected relations");
  if (relationCatalog.rows.some((row) => row.owner !== ROLE_NAMES.migrator
    || row.relrowsecurity !== true || row.relforcerowsecurity !== true)) {
    throw new Error("protected relation ownership or RLS is not qualified");
  }

  const privilegeRows = await client.query(`
    SELECT
      has_schema_privilege('agentpass_app','public','USAGE') AS app_schema_usage,
      has_schema_privilege('agentpass_app','public','CREATE') AS app_schema_create,
      has_schema_privilege('agentpass_backup','public','USAGE') AS backup_schema_usage,
      has_schema_privilege('agentpass_backup','public','CREATE') AS backup_schema_create,
      has_table_privilege('agentpass_app','public.platform_promotion_approvals','SELECT') AS app_approval_select,
      has_table_privilege('agentpass_app','public.platform_promotion_approvals','INSERT') AS app_approval_insert,
      has_table_privilege('agentpass_app','public.platform_promotion_approvals','UPDATE') AS app_approval_update,
      has_table_privilege('agentpass_app','public.platform_promotion_approvals','DELETE') AS app_approval_delete,
      has_table_privilege('agentpass_app','public.platform_promotion_issuances','INSERT') AS app_issuance_insert,
      has_table_privilege('agentpass_app','public.platform_promotion_issuances','UPDATE') AS app_issuance_update,
      has_table_privilege('agentpass_app','public.platform_promotion_issuances','DELETE') AS app_issuance_delete,
      has_table_privilege('agentpass_app','public.platform_deployment_state','INSERT') AS app_deployment_insert,
      has_table_privilege('agentpass_app','public.platform_deployment_state','UPDATE') AS app_deployment_update,
      has_table_privilege('agentpass_app','public.platform_deployment_state','DELETE') AS app_deployment_delete,
      has_table_privilege('agentpass_app','public.platform_promotion_audit_events','SELECT') AS app_audit_select,
      has_table_privilege('agentpass_app','public.platform_promotion_audit_events','INSERT') AS app_audit_insert,
      has_table_privilege('agentpass_app','public.platform_promotion_audit_events','UPDATE') AS app_audit_update,
      has_table_privilege('agentpass_app','public.platform_promotion_audit_events','DELETE') AS app_audit_delete,
      has_table_privilege('agentpass_backup','public.platform_promotion_issuances','SELECT') AS backup_issuance_select,
      has_table_privilege('agentpass_backup','public.platform_promotion_issuances','INSERT') AS backup_issuance_insert,
      has_table_privilege('agentpass_backup','public.platform_deployment_state','UPDATE') AS backup_deployment_update,
      has_table_privilege('agentpass_backup','public.platform_promotion_audit_events','SELECT') AS backup_audit_select,
      has_table_privilege('agentpass_backup','public.platform_promotion_audit_events','INSERT') AS backup_audit_insert,
      has_function_privilege('agentpass_app','public.agentpass_guard_platform_promotion_issuance()','EXECUTE') AS app_guard_execute`);
  const privilege = privilegeRows.rows?.[0];
  if (!privilege || privilege.app_schema_usage !== true || privilege.app_schema_create !== false
    || privilege.backup_schema_usage !== true || privilege.backup_schema_create !== false
    || privilege.app_approval_select !== true || privilege.app_approval_insert !== false
    || privilege.app_approval_update !== false || privilege.app_approval_delete !== false
    || privilege.app_issuance_insert !== true || privilege.app_issuance_update !== true
    || privilege.app_issuance_delete !== false || privilege.app_deployment_insert !== true
    || privilege.app_deployment_update !== true || privilege.app_deployment_delete !== false
    || privilege.app_audit_select !== true || privilege.app_audit_insert !== true
    || privilege.app_audit_update !== false || privilege.app_audit_delete !== false
    || privilege.backup_issuance_select !== true || privilege.backup_issuance_insert !== false
    || privilege.backup_deployment_update !== false || privilege.backup_audit_select !== true
    || privilege.backup_audit_insert !== false || privilege.app_guard_execute !== false) {
    throw new Error("qualification role privileges do not match the contract");
  }
}

async function runBehaviorProbes(client) {
  const approvalId = crypto.randomUUID();
  const promotionId = crypto.randomUUID();
  const deploymentId = `qualification-${crypto.randomUUID()}`;
  const providerOperationId = `qualification-provider-operation-${crypto.randomUUID()}`;
  const productDigest = "a".repeat(64);
  const approvalAt = new Date(Date.now() - 30_000).toISOString();
  const expiresAt = new Date(Date.now() + 30 * 60_000).toISOString();
  const values = [
    1, "agentpass.platform-promotion-approval", approvalId, deploymentId, "staging",
    `release-pkg-sha256-v1-${productDigest}`, "1".repeat(40), "2".repeat(40), productDigest,
    `sha256:${"b".repeat(64)}`, "c".repeat(64), ["1".repeat(64)], 4, "d".repeat(64),
    "qualification-policy", 1, 1, "approved", ["qualification-operator"], ["e".repeat(64)],
    approvalAt, expiresAt
  ];
  const rollbackTable = `qualification_rollback_${crypto.randomUUID().replaceAll("-", "")}`;
  await client.query("BEGIN");
  try {
    await client.query(`INSERT INTO platform_promotion_approvals
      (version,type,approval_id,deployment_id,environment,candidate_id,source_commit,source_tree,
       product_pkg_sha256,image_digest,sbom_sha256,qualification_report_digests,
       release_manifest_schema_version,release_manifest_sha256,policy_id,policy_version,
       approval_version,decision,platform_principal_ids,authorization_evidence_digests,
      approved_at,expires_at)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22)`, values);
    await client.query(`INSERT INTO managed_signer_provider_operations
      (purpose,operation_id,algorithm,bytes_length,request_digest,key_id,key_version,state,
       claim_token_digest,claim_expires_at,provider_started_at,uncertain_reason,signature,public_key_der,
       provider_receipt_provider,provider_receipt_id,expires_at)
      VALUES ('agentpass.promotion-evidence',$1,'ed25519',1,$2,'qualification-signer',1,'committed',
        NULL,NULL,clock_timestamp(),NULL,$3,$4,'qualification-provider','qualification-receipt',clock_timestamp()+interval '30 minutes')`, [
      providerOperationId, crypto.createHash("sha256").update(providerOperationId).digest(),
      Buffer.alloc(64, 0x44), Buffer.alloc(44, 0x55)
    ]);
    const idempotencyKey = `qualification-${crypto.randomUUID()}`;
    const approvalDigest = await client.query("SELECT record_digest FROM platform_promotion_approvals WHERE approval_id=$1", [approvalId]);
    const authorityDigest = await client.query(`SELECT agentpass_platform_promotion_authority_digest(
      $1::text,$2::text,$3::uuid,$4::text,$5::text,$6::text,$7::text,$8::text,$9::text,$10::text,$11::text,
      $12::text[],$13::uuid,$14::text,$15::text,$16::bigint,$17::bigint,$18::bigint) AS digest`, [
      deploymentId, "staging", promotionId, idempotencyKey, values[5], values[6], values[7], values[8],
      values[13], values[10], values[9], values[11], approvalId, approvalDigest.rows[0].record_digest,
      "qualification-signer", 1, 1, 0
    ]);
    await client.query(`INSERT INTO platform_promotion_issuances
      (deployment_id,environment,promotion_id,idempotency_key,candidate_id,source_commit,source_tree,
      product_pkg_sha256,release_manifest_sha256,sbom_sha256,image_digest,qualification_report_digests,
       approval_id,approval_digest,signer_key_id,signer_key_version,signer_lifecycle_version,
       expected_deployment_generation,state,claim_token_digest,claim_expires_at,provider_operation_id,authority_digest)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12::jsonb,$13,
        (SELECT record_digest FROM platform_promotion_approvals WHERE approval_id=$13),
        'qualification-signer',1,1,0,'reserved',$14,clock_timestamp()+interval '5 minutes',$15,$16)`, [
      deploymentId, "staging", promotionId, idempotencyKey,
      values[5], values[6], values[7], values[8], values[13], values[10], values[9], JSON.stringify(values[11]), approvalId,
      Buffer.alloc(32, 0x11), providerOperationId, authorityDigest.rows[0].digest
    ]);
    await client.query(`SET LOCAL ROLE ${ROLE_NAMES.app}`);
    const appVisible = await client.query(`SELECT state FROM platform_promotion_issuances
      WHERE deployment_id=$1 AND environment='staging' AND promotion_id=$2`, [deploymentId, promotionId]);
    if (appVisible.rowCount !== 1 || appVisible.rows[0].state !== "reserved") throw new Error("app RLS cannot read its C3 row");
    const evidence = {
      signature: "s".repeat(86),
      statement: {
        promotion_id: promotionId,
        deployment_id: deploymentId,
        environment: "staging",
        candidate_id: values[5],
        source_commit: values[6],
        source_tree: values[7],
        product_pkg_sha256: values[8],
        image_digest: values[9],
        sbom_sha256: values[10],
        qualification_report_digests: values[11],
        release_manifest_sha256: values[13],
        platform_approval_id: approvalId,
        platform_approval_digest: approvalDigest.rows[0].record_digest,
        key_id: "qualification-signer",
        key_version: "1",
        lifecycle_version: "1"
      }
    };
    await client.query(`UPDATE platform_promotion_issuances
      SET state='committed',claim_token_digest=NULL,claim_expires_at=NULL,
          evidence=$2::jsonb,updated_at=clock_timestamp()
      WHERE deployment_id=$1 AND environment='staging' AND promotion_id=$3`, [
      deploymentId, JSON.stringify(evidence), promotionId
    ]);
    const evidenceDigest = crypto.createHash("sha256").update(canonicalJson(evidence), "utf8").digest();
    await client.query(`INSERT INTO platform_deployment_state
      (deployment_id,environment,generation,state,promotion_id,evidence_digest)
      VALUES ($1,'staging',1,'promoted',$2,$3)`, [deploymentId, promotionId, evidenceDigest]);
    const eventDetails = { redacted: true };
    const requestId = crypto.randomUUID();
    const auditIdempotencyKey = `qualification-audit-${crypto.randomUUID()}`;
    const eventHash = await client.query(`SELECT agentpass_platform_promotion_audit_event_hash(
      $1::uuid,$2::text,$3::text,$4::text,$5::text,$6::uuid,$7::text,$8::jsonb) AS digest`, [
      requestId, "platform.promotion.issuance.committed", "qualification-operator", "platform_operator",
      "platform_promotion", promotionId, auditIdempotencyKey, JSON.stringify(eventDetails)
    ]);
    await client.query(`INSERT INTO platform_promotion_audit_events
      (event_id,request_id,event_type,actor_id,platform_role,target_type,target_id,idempotency_key,details,event_hash)
      VALUES ($1,$2,'platform.promotion.issuance.committed','qualification-operator','platform_operator',
        'platform_promotion',$3,$4,$5::jsonb,$6)`, [
      crypto.randomUUID(), requestId, promotionId, auditIdempotencyKey,
      JSON.stringify(eventDetails), eventHash.rows[0].digest
    ]);
    await expectRejected(client, "authority mutation", `UPDATE platform_promotion_issuances SET candidate_id=$2
      WHERE deployment_id=$1 AND environment='staging' AND promotion_id=$3`, [deploymentId, `release-pkg-sha256-v1-${"f".repeat(64)}`, promotionId]);
    await expectRejected(client, "app approval mutation", `UPDATE platform_promotion_approvals SET policy_id='qualification-denied'
      WHERE approval_id=$1`, [approvalId]);
    await expectRejected(client, "app issuance delete", `DELETE FROM platform_promotion_issuances
      WHERE deployment_id=$1 AND environment='staging' AND promotion_id=$2`, [deploymentId, promotionId]);
    await expectRejected(client, "app audit mutation", `UPDATE platform_promotion_audit_events SET actor_id='qualification-denied'
      WHERE target_id=$1`, [promotionId]);
    await expectRejected(client, "app audit truncate", "TRUNCATE TABLE platform_promotion_audit_events");

    await client.query("SET LOCAL ROLE NONE");
    await client.query(`SET LOCAL ROLE ${ROLE_NAMES.backup}`);
    const backupVisible = await client.query(`SELECT state FROM platform_promotion_issuances
      WHERE deployment_id=$1 AND environment='staging' AND promotion_id=$2`, [deploymentId, promotionId]);
    if (backupVisible.rowCount !== 1 || backupVisible.rows[0].state !== "committed") throw new Error("backup RLS cannot read its C3 row");
    const backupAudit = await client.query("SELECT count(*)::int AS count FROM platform_promotion_audit_events WHERE target_id=$1", [promotionId]);
    if (backupAudit.rows[0]?.count !== 1) throw new Error("backup RLS cannot read the C3 audit row");
    await expectRejected(client, "backup issuance mutation", `UPDATE platform_promotion_issuances SET state='rejected'
      WHERE deployment_id=$1 AND environment='staging' AND promotion_id=$2`, [deploymentId, promotionId]);
    await expectRejected(client, "backup deployment mutation", `UPDATE platform_deployment_state SET generation=0
      WHERE deployment_id=$1 AND environment='staging'`, [deploymentId]);
    await expectRejected(client, "backup audit truncate", "TRUNCATE TABLE platform_promotion_audit_events");

    await client.query("SET LOCAL ROLE NONE");
    await client.query(`SET LOCAL ROLE ${ROLE_NAMES.migrator}`);
    await expectRejected(client, "migrator audit truncate", "TRUNCATE TABLE platform_promotion_audit_events");
    await client.query(`CREATE TABLE public.${rollbackTable} (marker text NOT NULL)`);
    await client.query(`INSERT INTO public.${rollbackTable} (marker) VALUES ('redacted')`);
    await client.query("ROLLBACK");
    const rollbackState = await client.query("SELECT to_regclass($1) AS relation", [`public.${rollbackTable}`]);
    if (rollbackState.rows[0]?.relation !== null) throw new Error("qualification rollback left a relation behind");
  } catch (error) {
    await client.query("ROLLBACK").catch(() => {});
    throw error;
  }
}

async function runContentionProbe(pool) {
  let first;
  let second;
  const fixture = {
    approvalId: crypto.randomUUID(),
    deploymentId: `qualification-contention-${crypto.randomUUID()}`,
    environment: "staging",
    productDigest: "f".repeat(64),
    sourceCommit: "3".repeat(40),
    sourceTree: "4".repeat(40),
    releaseManifestDigest: "5".repeat(64),
    imageDigest: `sha256:${"6".repeat(64)}`,
    sbomDigest: "7".repeat(64),
    qualificationDigest: "8".repeat(64),
    providerOperationId: `qualification-provider-operation-${crypto.randomUUID()}`
  };
  fixture.candidateId = `release-pkg-sha256-v1-${fixture.productDigest}`;
  const competingFixture = {
    ...fixture,
    approvalId: crypto.randomUUID(),
    productDigest: "9".repeat(64),
    sourceCommit: "a".repeat(40),
    sourceTree: "b".repeat(40),
    releaseManifestDigest: "c".repeat(64),
    imageDigest: `sha256:${"d".repeat(64)}`,
    sbomDigest: "e".repeat(64),
    qualificationDigest: "f".repeat(64),
    providerOperationId: `qualification-provider-operation-${crypto.randomUUID()}`
  };
  competingFixture.candidateId = `release-pkg-sha256-v1-${competingFixture.productDigest}`;
  try {
    first = await pool.connect();
    second = await pool.connect();
    await Promise.all([first.query("BEGIN"), second.query("BEGIN")]);
    await insertFixtureAuthority(first, fixture);
    await insertFixtureAuthority(second, competingFixture);
    await first.query(`SET LOCAL ROLE ${ROLE_NAMES.app}`);
    await second.query(`SET LOCAL ROLE ${ROLE_NAMES.app}`);
    await insertReservedIssuance(first, fixture, crypto.randomUUID(), `qualification-contention-${crypto.randomUUID()}`);
    const competingInsert = insertReservedIssuance(second, competingFixture, crypto.randomUUID(), `qualification-contention-${crypto.randomUUID()}`);
    await first.query("COMMIT");
    let rejected = false;
    try {
      await competingInsert;
    } catch {
      rejected = true;
    }
    if (!rejected) throw new Error("contention probe accepted two unique winners");
    await second.query("ROLLBACK").catch(() => {});
  } catch (error) {
    await first?.query("ROLLBACK").catch(() => {});
    await second?.query("ROLLBACK").catch(() => {});
    throw error;
  } finally {
    first?.release(true);
    second?.release(true);
  }
}

async function assertQualificationTablesEmpty(pool) {
  const client = await pool.connect();
  try {
    await requireQualificationAdministrator(client);
    const result = await client.query(`
      SELECT
        (SELECT count(*) FROM public.platform_promotion_approvals) AS approvals,
        (SELECT count(*) FROM public.platform_promotion_issuances) AS issuances,
        (SELECT count(*) FROM public.platform_deployment_state) AS deployments,
        (SELECT count(*) FROM public.platform_promotion_audit_events) AS audit_events,
        (SELECT count(*) FROM public.managed_signer_provider_operations) AS provider_operations`);
    if (!result.rows[0] || Object.values(result.rows[0]).some((value) => Number(value) !== 0)) {
      throw qualificationError(QUALIFICATION_DIAGNOSTICS.VERIFICATION_FAILED);
    }
  } finally {
    client.release(true);
  }
}

async function insertFixtureAuthority(client, fixture) {
  await client.query(`INSERT INTO platform_promotion_approvals
    (version,type,approval_id,deployment_id,environment,candidate_id,source_commit,source_tree,
     product_pkg_sha256,image_digest,sbom_sha256,qualification_report_digests,
     release_manifest_schema_version,release_manifest_sha256,policy_id,policy_version,
     approval_version,decision,platform_principal_ids,authorization_evidence_digests,
     approved_at,expires_at)
    VALUES (1,'agentpass.platform-promotion-approval',$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,4,$11,
      'qualification-policy',1,1,'approved',ARRAY['qualification-operator'],ARRAY[$12],clock_timestamp(),clock_timestamp()+interval '30 minutes')`, [
    fixture.approvalId, fixture.deploymentId, fixture.environment, fixture.candidateId,
    fixture.sourceCommit, fixture.sourceTree, fixture.productDigest, fixture.imageDigest,
    fixture.sbomDigest, [fixture.qualificationDigest], fixture.releaseManifestDigest,
    "9".repeat(64)
  ]);
  await client.query(`INSERT INTO managed_signer_provider_operations
    (purpose,operation_id,algorithm,bytes_length,request_digest,key_id,key_version,state,
     claim_token_digest,claim_expires_at,provider_started_at,uncertain_reason,signature,public_key_der,
     provider_receipt_provider,provider_receipt_id,expires_at)
    VALUES ('agentpass.promotion-evidence',$1,'ed25519',1,$2,'qualification-signer',1,'committed',
      NULL,NULL,clock_timestamp(),NULL,$3,$4,'qualification-provider','qualification-receipt',clock_timestamp()+interval '30 minutes')`, [
    fixture.providerOperationId, crypto.createHash("sha256").update(fixture.providerOperationId).digest(),
    Buffer.alloc(64, 0x44), Buffer.alloc(44, 0x55)
  ]);
}

async function insertReservedIssuance(client, fixture, promotionId, idempotencyKey) {
  const approval = await client.query("SELECT record_digest FROM platform_promotion_approvals WHERE approval_id=$1", [fixture.approvalId]);
  const digest = await client.query(`SELECT agentpass_platform_promotion_authority_digest(
    $1::text,$2::text,$3::uuid,$4::text,$5::text,$6::text,$7::text,$8::text,$9::text,$10::text,$11::text,
    $12::text[],$13::uuid,$14::text,$15::text,$16::bigint,$17::bigint,$18::bigint) AS digest`, [
    fixture.deploymentId, fixture.environment, promotionId, idempotencyKey, fixture.candidateId,
    fixture.sourceCommit, fixture.sourceTree, fixture.productDigest, fixture.releaseManifestDigest,
    fixture.sbomDigest, fixture.imageDigest, [fixture.qualificationDigest], fixture.approvalId,
    approval.rows[0].record_digest, "qualification-signer", 1, 1, 0
  ]);
  await client.query(`INSERT INTO platform_promotion_issuances
    (deployment_id,environment,promotion_id,idempotency_key,candidate_id,source_commit,source_tree,
     product_pkg_sha256,release_manifest_sha256,sbom_sha256,image_digest,qualification_report_digests,
     approval_id,approval_digest,signer_key_id,signer_key_version,signer_lifecycle_version,
     expected_deployment_generation,state,claim_token_digest,claim_expires_at,provider_operation_id,authority_digest)
    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12::jsonb,$13,$14,
      'qualification-signer',1,1,0,'reserved',$15,clock_timestamp()+interval '5 minutes',$16,$17)`, [
    fixture.deploymentId, fixture.environment, promotionId, idempotencyKey, fixture.candidateId,
    fixture.sourceCommit, fixture.sourceTree, fixture.productDigest, fixture.releaseManifestDigest,
      fixture.sbomDigest, fixture.imageDigest, JSON.stringify([fixture.qualificationDigest]), fixture.approvalId,
      approval.rows[0].record_digest, Buffer.alloc(32, 0x11), fixture.providerOperationId, digest.rows[0].digest
  ]);
}

async function runBehaviorAndContentionProbes(client, pool) {
  await assertQualificationTablesEmpty(pool);
  await runBehaviorProbes(client);
  await runContentionProbe(pool);
  return Object.freeze([
    { id: "positive_insert_and_transition", status: "passed" },
    { id: "rls_cross_role_read_write", status: "passed" },
    { id: "negative_authority_mutation_rejected", status: "passed" },
    { id: "audit_event_append_only", status: "passed" },
    { id: "generation_contention_single_winner", status: "passed" },
    { id: "transaction_rollback", status: "passed" }
  ]);
}

async function expectRejected(client, label, sql, params) {
  await client.query("SAVEPOINT qualification_probe");
  try {
    await client.query(sql, params);
    throw new Error(`${label} was accepted`);
  } catch (error) {
    await client.query("ROLLBACK TO SAVEPOINT qualification_probe");
    await client.query("RELEASE SAVEPOINT qualification_probe");
    if (error.message === `${label} was accepted`) throw error;
  }
}

function assertExactNames(rows, expected, label) {
  const actual = rows.map((row) => row.name ?? row.relname).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((value, index) => value !== wanted[index])) throw new Error(`${label} do not match expected objects`);
}

function normalizeServerVersion(value) {
  const match = typeof value === "string" ? /^(\d+(?:\.\d+){1,3})/u.exec(value) : null;
  return match?.[1] ?? "unknown";
}

function assertQualificationChecks(checks) {
  if (!Array.isArray(checks) || checks.length !== QUALIFICATION_CHECK_IDS.length
    || checks.some((check, index) => check?.id !== QUALIFICATION_CHECK_IDS[index] || check.status !== "passed")) {
    throw qualificationError(QUALIFICATION_DIAGNOSTICS.VERIFICATION_FAILED);
  }
}

function qualificationBinding({ sourceCommit, sourceTree, ciRunId, ciRunAttempt, ciJobId, artifactSha256 }) {
  return Object.freeze({
    sourceCommit: typeof sourceCommit === "string" && SOURCE_COMMIT_PATTERN.test(sourceCommit) ? sourceCommit : null,
    sourceTree: typeof sourceTree === "string" && SOURCE_TREE_PATTERN.test(sourceTree) ? sourceTree : null,
    ciRunId: typeof ciRunId === "string" && CI_RUN_ID_PATTERN.test(ciRunId) ? ciRunId : null,
    ciRunAttempt: typeof ciRunAttempt === "string" && CI_RUN_ATTEMPT_PATTERN.test(ciRunAttempt) ? ciRunAttempt : null,
    ciJobId: typeof ciJobId === "string" && CI_JOB_ID_PATTERN.test(ciJobId) ? ciJobId : null,
    artifactSha256: typeof artifactSha256 === "string" && ARTIFACT_SHA_PATTERN.test(artifactSha256) ? artifactSha256 : null
  });
}

export function normalizeQualificationEvidence(evidence, {
  expectedSourceCommit,
  expectedSourceTree,
  expectedCiRunId,
  expectedCiRunAttempt,
  expectedCiJobId,
  expectedArtifactSha256,
  expectedPostgresMajor,
  expectedDatabaseName,
  expectedServerPort,
  requirePassed = false
} = {}) {
  if (!evidence || typeof evidence !== "object" || Array.isArray(evidence)
    || JSON.stringify(Object.keys(evidence).sort()) !== JSON.stringify([...QUALIFICATION_EVIDENCE_KEYS].sort())) {
    throw new TypeError(QUALIFICATION_DIAGNOSTICS.INVALID_EVIDENCE);
  }
    if (evidence.schema_version !== 1 || evidence.qualification !== QUALIFICATION_ID
    || !["not_run", "failed", "passed"].includes(evidence.status)
    || evidence.qualified !== (evidence.status === "passed")
    || (evidence.reason !== null && !SAFE_REASONS.has(evidence.reason))
    || evidence.redacted !== true || evidence.migration_version !== TARGET_VERSION
    || evidence.migration_name !== TARGET_NAME || typeof evidence.migration_applied_this_run !== "boolean"
    || !Array.isArray(evidence.checks)) {
    throw new TypeError(QUALIFICATION_DIAGNOSTICS.INVALID_EVIDENCE);
  }
  if (evidence.status === "passed") {
    if (evidence.reason !== null || typeof evidence.migration_checksum !== "string" || !/^[0-9a-f]{64}$/u.test(evidence.migration_checksum)
      || evidence.current_version !== TARGET_VERSION || !SERVER_VERSION_PATTERN.test(evidence.server_version ?? "")
      || typeof evidence.database_name !== "string" || !DATABASE_NAME_PATTERN.test(evidence.database_name)
      || !Number.isSafeInteger(evidence.server_port) || evidence.server_port < 1 || evidence.server_port > 65535
      || typeof evidence.tls_version !== "string" || !TLS_VERSION_PATTERN.test(evidence.tls_version)
      || typeof evidence.source_commit !== "string" || !SOURCE_COMMIT_PATTERN.test(evidence.source_commit)
      || typeof evidence.source_tree !== "string" || !SOURCE_TREE_PATTERN.test(evidence.source_tree)
      || typeof evidence.ci_run_id !== "string" || !CI_RUN_ID_PATTERN.test(evidence.ci_run_id)
      || typeof evidence.ci_run_attempt !== "string" || !CI_RUN_ATTEMPT_PATTERN.test(evidence.ci_run_attempt)
      || typeof evidence.ci_job_id !== "string" || !CI_JOB_ID_PATTERN.test(evidence.ci_job_id)
      || typeof evidence.artifact_sha256 !== "string" || !ARTIFACT_SHA_PATTERN.test(evidence.artifact_sha256)) {
      throw new TypeError(QUALIFICATION_DIAGNOSTICS.INVALID_EVIDENCE);
    }
    assertQualificationChecks(evidence.checks);
    if (expectedPostgresMajor !== undefined && (!POSTGRES_MAJOR_PATTERN.test(String(expectedPostgresMajor))
      || !evidence.server_version.startsWith(`${expectedPostgresMajor}.`)
      && evidence.server_version !== String(expectedPostgresMajor))) throw new TypeError(QUALIFICATION_DIAGNOSTICS.SERVER_VERSION_UNEXPECTED);
    if (expectedDatabaseName !== undefined && evidence.database_name !== String(expectedDatabaseName)) throw new TypeError(QUALIFICATION_DIAGNOSTICS.INVALID_EVIDENCE);
    if (expectedServerPort !== undefined && evidence.server_port !== Number(expectedServerPort)) throw new TypeError(QUALIFICATION_DIAGNOSTICS.INVALID_EVIDENCE);
  } else if (requirePassed || evidence.qualified !== false || evidence.migration_checksum !== null
    || evidence.migration_applied_this_run !== false || evidence.current_version !== null
    || evidence.server_version !== null || evidence.database_name !== null || evidence.server_port !== null
    || evidence.tls_version !== null || evidence.checks.length !== 0) {
    throw new TypeError(QUALIFICATION_DIAGNOSTICS.INVALID_EVIDENCE);
  }
  if (evidence.artifact_sha256 !== null && (typeof evidence.artifact_sha256 !== "string" || !ARTIFACT_SHA_PATTERN.test(evidence.artifact_sha256))) {
    throw new TypeError(QUALIFICATION_DIAGNOSTICS.INVALID_ARTIFACT_BINDING);
  }
  for (const [key, pattern] of [["source_commit", SOURCE_COMMIT_PATTERN], ["source_tree", SOURCE_TREE_PATTERN], ["ci_run_id", CI_RUN_ID_PATTERN], ["ci_run_attempt", CI_RUN_ATTEMPT_PATTERN], ["ci_job_id", CI_JOB_ID_PATTERN]]) {
    if (evidence[key] !== null && (typeof evidence[key] !== "string" || !pattern.test(evidence[key]))) throw new TypeError(QUALIFICATION_DIAGNOSTICS.INVALID_EVIDENCE);
  }
  if (expectedSourceCommit !== undefined && evidence.source_commit !== expectedSourceCommit) throw new TypeError(QUALIFICATION_DIAGNOSTICS.INVALID_SOURCE_BINDING);
  if (expectedSourceTree !== undefined && evidence.source_tree !== expectedSourceTree) throw new TypeError(QUALIFICATION_DIAGNOSTICS.INVALID_SOURCE_BINDING);
  if (expectedCiRunId !== undefined && evidence.ci_run_id !== String(expectedCiRunId)) throw new TypeError(QUALIFICATION_DIAGNOSTICS.INVALID_RUN_BINDING);
  if (expectedCiRunAttempt !== undefined && evidence.ci_run_attempt !== String(expectedCiRunAttempt)) throw new TypeError(QUALIFICATION_DIAGNOSTICS.INVALID_RUN_BINDING);
  if (expectedCiJobId !== undefined && evidence.ci_job_id !== String(expectedCiJobId)) throw new TypeError(QUALIFICATION_DIAGNOSTICS.INVALID_RUN_BINDING);
  if (expectedArtifactSha256 !== undefined && evidence.artifact_sha256 !== expectedArtifactSha256) throw new TypeError(QUALIFICATION_DIAGNOSTICS.INVALID_ARTIFACT_BINDING);
  if (typeof evidence.started_at !== "string" || typeof evidence.completed_at !== "string"
    || !Number.isFinite(Date.parse(evidence.started_at)) || !Number.isFinite(Date.parse(evidence.completed_at))
    || Date.parse(evidence.completed_at) < Date.parse(evidence.started_at)) throw new TypeError(QUALIFICATION_DIAGNOSTICS.INVALID_EVIDENCE);
  const serialized = JSON.stringify(evidence);
  if (/postgres(?:ql)?:\/\/|password|secret|private[\s_-]*key|(?:claim[\s_-]*)?token|credential|authorization|cookie|api[\s_-]*key|connection[\s_-]*(?:string|url)|error|stack|diagnostic/iu.test(serialized)) {
    throw new TypeError(QUALIFICATION_DIAGNOSTICS.INVALID_EVIDENCE);
  }
  return Object.freeze(evidence);
}

export function assertRedactedQualificationEvidence(evidence) {
  return normalizeQualificationEvidence(evidence);
}

export function verifyQualificationEvidence(input, options = {}) {
  let evidence;
  let serialized;
  try {
    if (typeof input === "string" || Buffer.isBuffer(input) || input instanceof Uint8Array) {
      serialized = Buffer.from(input).toString("utf8");
      if (!serialized.endsWith("\n")) throw new TypeError(QUALIFICATION_DIAGNOSTICS.INVALID_EVIDENCE);
      evidence = JSON.parse(serialized);
    } else evidence = input;
  } catch {
    throw new TypeError(QUALIFICATION_DIAGNOSTICS.INVALID_EVIDENCE);
  }
  const normalized = normalizeQualificationEvidence(evidence, { ...options, requirePassed: options.requirePassed ?? true });
  if (serialized !== undefined && `${canonicalJson(normalized)}\n` !== serialized) throw new TypeError(QUALIFICATION_DIAGNOSTICS.INVALID_EVIDENCE);
  return Object.freeze({
    status: normalized.status,
    qualified: normalized.qualified,
    source_commit: normalized.source_commit,
    source_tree: normalized.source_tree,
    ci_run_id: normalized.ci_run_id,
    ci_run_attempt: normalized.ci_run_attempt,
    ci_job_id: normalized.ci_job_id,
    artifact_sha256: normalized.artifact_sha256,
    server_version: normalized.server_version,
    database_name: normalized.database_name,
    server_port: normalized.server_port,
    evidence_sha256: crypto.createHash("sha256").update(canonicalJson(normalized), "utf8").digest("hex")
  });
}

export async function writeQualificationEvidence(outputPath, evidence) {
  if (typeof outputPath !== "string" || !path.isAbsolute(outputPath)) {
    throw new TypeError("qualification evidence output must be an absolute path");
  }
  normalizeQualificationEvidence(evidence, { requirePassed: true });
  await writeFile(outputPath, `${canonicalJson(evidence)}\n`, { encoding: "utf8", mode: 0o600 });
  return outputPath;
}

function baseEvidence(startedAt, status, reason, binding) {
  return {
    schema_version: 1,
    qualification: QUALIFICATION_ID,
    status,
    qualified: false,
    reason,
    started_at: startedAt,
    completed_at: new Date().toISOString(),
    migration_version: TARGET_VERSION,
    migration_name: TARGET_NAME,
    migration_checksum: null,
    migration_applied_this_run: false,
    current_version: null,
    server_version: null,
    database_name: null,
    server_port: null,
    tls_version: null,
    artifact_sha256: binding.artifactSha256,
    source_commit: binding.sourceCommit,
    source_tree: binding.sourceTree,
    ci_run_id: binding.ciRunId,
    ci_run_attempt: binding.ciRunAttempt,
    ci_job_id: binding.ciJobId,
    redacted: true,
    checks: []
  };
}

function notRunEvidence(startedAt, reason, binding) {
  return Object.freeze(baseEvidence(startedAt, "not_run", reason, binding));
}

function failedEvidence(startedAt, reason, binding) {
  return Object.freeze(baseEvidence(startedAt, "failed", reason, binding));
}

async function main(argv = process.argv.slice(2)) {
  if (argv[0] === "artifact-digest") {
    const inputPath = argv[1] ?? qualificationInputArtifactPath();
    if (argv.length > 2 || !path.isAbsolute(inputPath)) throw new TypeError(QUALIFICATION_DIAGNOSTICS.INVALID_ARTIFACT_BINDING);
    const artifactSha256 = await computeQualificationInputArtifactSha256(inputPath);
    process.stdout.write(`${canonicalJson({ artifact_sha256: artifactSha256 })}\n`);
    return;
  }
  if (argv[0] === "verify") {
    const [inputPath, expectedSourceCommit, expectedSourceTree, expectedCiRunId, expectedCiRunAttempt, expectedCiJobId, expectedPostgresMajor, expectedDatabaseName, expectedServerPort] = argv.slice(1);
    if (!path.isAbsolute(inputPath ?? "") || !SOURCE_COMMIT_PATTERN.test(expectedSourceCommit ?? "")
      || !SOURCE_TREE_PATTERN.test(expectedSourceTree ?? "") || !CI_RUN_ID_PATTERN.test(expectedCiRunId ?? "")
      || !CI_RUN_ATTEMPT_PATTERN.test(expectedCiRunAttempt ?? "") || !CI_JOB_ID_PATTERN.test(expectedCiJobId ?? "")
      || !/^\d{1,2}$/u.test(expectedPostgresMajor ?? "") || !DATABASE_NAME_PATTERN.test(expectedDatabaseName ?? "")
      || !PORT_PATTERN.test(expectedServerPort ?? "")) {
      throw new TypeError(QUALIFICATION_DIAGNOSTICS.INVALID_EVIDENCE);
    }
    const serialized = await readFile(inputPath, "utf8");
    const expectedArtifactSha256 = await computeQualificationInputArtifactSha256(qualificationInputArtifactPath());
    const result = verifyQualificationEvidence(serialized, {
      expectedSourceCommit,
      expectedSourceTree,
      expectedCiRunId,
      expectedCiRunAttempt,
      expectedCiJobId,
      expectedArtifactSha256,
      expectedPostgresMajor,
      expectedDatabaseName,
      expectedServerPort,
      requirePassed: true
    });
    process.stdout.write(`${canonicalJson(result)}\n`);
    return;
  }
  const evidence = await runC3Migration0047Qualification();
  process.stdout.write(`${canonicalJson(evidence)}\n`);
  if (evidence.status !== "passed" || evidence.qualified !== true) process.exitCode = 1;
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) main().catch(() => {
  process.stderr.write("postgres C3 qualification failed\n");
  process.exitCode = 1;
});
