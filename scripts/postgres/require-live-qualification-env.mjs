import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const URL_KEYS = Object.freeze([
  "AGENTPASS_TEST_DATABASE_URL",
  "AGENTPASS_TEST_POSTGRES_URL",
  "AGENTPASS_TEST_POSTGRES_ADMIN_URL",
  "AGENTPASS_TEST_APP_DATABASE_URL",
  "AGENTPASS_TEST_SIGNER_DATABASE_URL",
  "AGENTPASS_TEST_MIGRATION_DATABASE_URL",
  "AGENTPASS_TEST_BACKUP_DATABASE_URL",
  "AGENTPASS_TEST_MAINTENANCE_DATABASE_URL",
]);

const PROTECTED_URL_KEYS = Object.freeze([
  "AGENTPASS_DATABASE_URL",
  "AGENTPASS_BACKUP_PITR_RESTORE_DATABASE_URL",
  "AGENTPASS_BACKUP_PITR_PITR_DATABASE_URL",
]);

const BINDING_KEYS = Object.freeze([
  "AGENTPASS_BACKUP_PITR_SOURCE_COMMIT",
  "AGENTPASS_BACKUP_PITR_SOURCE_TREE",
  "AGENTPASS_BACKUP_PITR_CI_RUN_ID",
  "AGENTPASS_BACKUP_PITR_CI_RUN_ATTEMPT",
  "AGENTPASS_BACKUP_PITR_CI_JOB_ID",
  "AGENTPASS_BACKUP_PITR_ARTIFACT_SHA256",
]);

const COMMIT = /^[0-9a-f]{40}$/u;
const SHA256 = /^[0-9a-f]{64}$/u;
const POSITIVE_ID = /^[1-9][0-9]{0,19}$/u;
const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/u;
const PROTECTED_RUNNER = /^protected-postgresql\/[A-Za-z0-9][A-Za-z0-9._:/-]{0,95}$/u;
const DISALLOWED_IDENTITY = /(?:^|[._:/ -])(local|static|unit|mock|fixture|fake|simulator|emulator|test|unknown|placeholder)(?:$|[._:/ -])/iu;
const LOOPBACK_HOST = /^(?:localhost|127(?:\.\d{1,3}){3}|0\.0\.0\.0|::1|\[::1\])$/iu;
const REQUIRED_CONFIRMATION = "isolated-disposable";
const CA_MAX_BYTES = 1024 * 1024;

export class LivePostgresQualificationEnvironmentError extends Error {
  constructor(code) {
    super(code);
    this.name = "LivePostgresQualificationEnvironmentError";
    this.code = code;
  }
}

function fail(code) {
  throw new LivePostgresQualificationEnvironmentError(code);
}

function requiredString(env, key) {
  if (typeof env[key] !== "string" || env[key].trim() === "") fail(`missing_${key.toLowerCase()}`);
  return env[key];
}

function validatePostgresUrl(env, key, label) {
  const value = requiredString(env, key);
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    fail(`invalid_${label}_url`);
  }

  const queryKeys = [...parsed.searchParams.keys()];
  if ((parsed.protocol !== "postgres:" && parsed.protocol !== "postgresql:")
    || parsed.hostname === ""
    || LOOPBACK_HOST.test(parsed.hostname)
    || parsed.pathname === "" || parsed.pathname === "/"
    || parsed.username === "" || parsed.password === ""
    || parsed.hash !== ""
    || queryKeys.length !== 1
    || queryKeys[0] !== "sslmode"
    || parsed.searchParams.get("sslmode") !== "verify-full") {
    fail(`invalid_${label}_url`);
  }

  // The identity intentionally excludes username, password, query parameters,
  // and any other credential-bearing component. It is used only for endpoint
  // separation; it is never returned or logged.
  const port = parsed.port || "5432";
  return `${parsed.hostname.toLowerCase()}:${port}${parsed.pathname}`;
}

function validateCaPath(env) {
  const value = requiredString(env, "AGENTPASS_BACKUP_PITR_CA_CERT_FILE");
  if (!path.isAbsolute(value)) fail("invalid_ca_path");

  let stat;
  try {
    stat = fs.lstatSync(value);
    if (!stat.isFile() || stat.nlink !== 1 || stat.size < 1 || stat.size > CA_MAX_BYTES
      || (stat.mode & 0o077) !== 0) fail("invalid_ca_path");
    fs.accessSync(value, fs.constants.R_OK);
  } catch (error) {
    if (error instanceof LivePostgresQualificationEnvironmentError) throw error;
    fail("invalid_ca_path");
  }
}

function validateRunner(env) {
  const value = requiredString(env, "AGENTPASS_BACKUP_PITR_RUNNER_ID");
  if (!SAFE_ID.test(value) || !PROTECTED_RUNNER.test(value) || DISALLOWED_IDENTITY.test(value)) {
    fail("invalid_runner_identity");
  }
}

function validateBinding(env, key, pattern, code) {
  const value = requiredString(env, key);
  if (!pattern.test(value) || DISALLOWED_IDENTITY.test(value)) fail(code);
}

function validateProtectedBinding(env) {
  validateBinding(env, "AGENTPASS_BACKUP_PITR_SOURCE_COMMIT", COMMIT, "invalid_source_commit");
  validateBinding(env, "AGENTPASS_BACKUP_PITR_SOURCE_TREE", COMMIT, "invalid_source_tree");
  validateBinding(env, "AGENTPASS_BACKUP_PITR_CI_RUN_ID", POSITIVE_ID, "invalid_run_id");
  validateBinding(env, "AGENTPASS_BACKUP_PITR_CI_RUN_ATTEMPT", POSITIVE_ID, "invalid_run_attempt");
  validateBinding(env, "AGENTPASS_BACKUP_PITR_CI_JOB_ID", SAFE_ID, "invalid_job_id");
  validateBinding(env, "AGENTPASS_BACKUP_PITR_ARTIFACT_SHA256", SHA256, "invalid_artifact_sha256");
}

function validateIsolationAcknowledgements(env) {
  if (env.AGENTPASS_BACKUP_PITR_RESTORE_CONFIRMATION !== REQUIRED_CONFIRMATION
    || env.AGENTPASS_BACKUP_PITR_PITR_CONFIRMATION !== REQUIRED_CONFIRMATION) {
    fail("isolated_disposable_confirmation_required");
  }
}

function validateLegacyRoleUrls(env) {
  // These role-specific URLs are retained as part of the existing live-role
  // qualification contract. The protected backup/PITR profile below is still
  // independently required and never falls back to these values.
  const databaseKey = env.AGENTPASS_TEST_DATABASE_URL !== undefined
    ? "AGENTPASS_TEST_DATABASE_URL"
    : "AGENTPASS_TEST_POSTGRES_URL";
  const databaseUrl = env[databaseKey];
  const missing = [];
  if (databaseUrl === undefined) missing.push("AGENTPASS_TEST_DATABASE_URL or AGENTPASS_TEST_POSTGRES_URL");
  for (const key of [
    "AGENTPASS_TEST_POSTGRES_ADMIN_URL",
    "AGENTPASS_TEST_APP_DATABASE_URL",
    "AGENTPASS_TEST_SIGNER_DATABASE_URL",
    "AGENTPASS_TEST_MIGRATION_DATABASE_URL",
    "AGENTPASS_TEST_BACKUP_DATABASE_URL",
    "AGENTPASS_TEST_MAINTENANCE_DATABASE_URL",
  ]) if (env[key] === undefined) missing.push(key);
  if (missing.length > 0) fail("missing_legacy_role_urls");

  for (const [key, label] of [
    [databaseKey, "database"],
    ["AGENTPASS_TEST_POSTGRES_ADMIN_URL", "admin"],
    ["AGENTPASS_TEST_APP_DATABASE_URL", "app"],
    ["AGENTPASS_TEST_SIGNER_DATABASE_URL", "signer"],
    ["AGENTPASS_TEST_MIGRATION_DATABASE_URL", "migration"],
    ["AGENTPASS_TEST_BACKUP_DATABASE_URL", "backup"],
    ["AGENTPASS_TEST_MAINTENANCE_DATABASE_URL", "maintenance"],
  ]) {
    validatePostgresUrl(env, key, label);
  }
}

/**
 * Validate a protected-runner environment before any PostgreSQL utility is
 * started. This function performs configuration checks only. It does not load
 * a PostgreSQL client, open a socket, run psql, or claim that a DB was reached.
 */
export function validateLivePostgresQualificationEnvironment(env = process.env) {
  if (env === null || typeof env !== "object" || Array.isArray(env)) fail("invalid_environment");

  // A caller that supplies the legacy role-profile variables opts into that
  // contract and must supply the complete set. The protected backup/PITR
  // profile itself does not fall back to a test DSN and can run without them.
  if (URL_KEYS.some((key) => env[key] !== undefined)) validateLegacyRoleUrls(env);
  const source = validatePostgresUrl(env, "AGENTPASS_DATABASE_URL", "source");
  const restore = validatePostgresUrl(env, "AGENTPASS_BACKUP_PITR_RESTORE_DATABASE_URL", "restore");
  const pitr = validatePostgresUrl(env, "AGENTPASS_BACKUP_PITR_PITR_DATABASE_URL", "pitr");
  if (new Set([source, restore, pitr]).size !== 3) fail("postgres_endpoint_not_separate");
  validateCaPath(env);
  validateIsolationAcknowledgements(env);
  validateRunner(env);
  validateProtectedBinding(env);

  return Object.freeze({
    status: "preflight_validated",
    connection_attempted: false,
    tls_mode: "verify-full",
    ca_path_validated: true,
    endpoint_separation: "source_restore_pitr_distinct",
    isolation_acknowledged: true,
    runner_identity_validated: true,
    binding_validated: Object.freeze({
      source_commit: true,
      source_tree: true,
      ci_run_id: true,
      ci_run_attempt: true,
      ci_job_id: true,
      artifact_sha256: true,
    }),
    validated_keys: Object.freeze([
      ...URL_KEYS.filter((key) => typeof env[key] === "string"),
      ...PROTECTED_URL_KEYS,
      ...BINDING_KEYS,
    ]),
  });
}

export const validateProtectedPostgresQualificationEnvironment = validateLivePostgresQualificationEnvironment;

function main() {
  try {
    process.stdout.write(`${JSON.stringify(validateLivePostgresQualificationEnvironment())}\n`);
  } catch (error) {
    // Deliberately emit only a stable code. In particular, never echo an URL,
    // password, CA path, filesystem error, or provider message.
    process.stdout.write(`${JSON.stringify({
      status: "not_proven",
      reason: error instanceof LivePostgresQualificationEnvironmentError ? error.code : "invalid_environment",
    })}\n`);
    process.exitCode = 2;
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(fileURLToPath(import.meta.url))) main();
