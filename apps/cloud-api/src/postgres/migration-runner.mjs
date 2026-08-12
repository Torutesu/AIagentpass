import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const MIGRATION_FILE = /^(\d{4})_([a-z0-9_]+)\.sql$/;
const SHA256 = /^[0-9a-f]{64}$/;
const RELATION_MISSING = "42P01";
const DEFAULT_LOCK_NAMESPACE = "agentpass:postgres:migrations:v1";

export class MigrationRunnerError extends Error {
  constructor(code, message, details = undefined, cause = undefined) {
    super(message, cause === undefined ? undefined : { cause });
    this.name = "MigrationRunnerError";
    this.code = code;
    if (details !== undefined) this.details = details;
    if (cause !== undefined) this.cause = cause;
  }
}

export class MigrationChecksumError extends MigrationRunnerError {
  constructor(version, expected, actual) {
    super("ERR_MIGRATION_CHECKSUM", `migration ${version} checksum does not match the applied checksum`, { version, expected, actual });
    this.name = "MigrationChecksumError";
  }
}

export class MigrationDirtyError extends MigrationRunnerError {
  constructor(rows) {
    super("ERR_MIGRATION_DIRTY", "database contains an unfinished or failed migration attempt", { rows });
    this.name = "MigrationDirtyError";
  }
}

/**
 * Load SQL files using the same four-digit ordering as contracts/postgres.
 * The returned SQL is kept byte-for-byte so its checksum represents the file
 * that was reviewed and deployed.
 */
export async function loadSqlMigrations(directory = defaultContractDirectory()) {
  if (typeof directory !== "string" || !path.isAbsolute(directory)) throw new MigrationRunnerError("ERR_MIGRATION_DIRECTORY", "migration directory must be an absolute path");
  let names;
  try { names = await fs.readdir(directory); }
  catch (error) { throw new MigrationRunnerError("ERR_MIGRATION_DIRECTORY", `cannot read migration directory: ${directory}`, undefined, error); }
  const selected = names.filter((name) => MIGRATION_FILE.test(name)).sort();
  if (selected.length === 0) throw new MigrationRunnerError("ERR_MIGRATION_EMPTY", "migration directory contains no ordered SQL migrations");
  return normalizeMigrations(await Promise.all(selected.map(async (name) => ({ name, sql: await fs.readFile(path.join(directory, name), "utf8") }))));
}

export function defaultContractDirectory() {
  return path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../../../contracts/postgres");
}

export function migrationChecksum(sql) {
  if (typeof sql !== "string" || sql.length === 0) throw new MigrationRunnerError("ERR_MIGRATION_SQL", "migration SQL must be a non-empty string");
  return crypto.createHash("sha256").update(sql, "utf8").digest("hex");
}

export function normalizeMigrations(migrations) {
  if (!Array.isArray(migrations) || migrations.length === 0) throw new MigrationRunnerError("ERR_MIGRATION_EMPTY", "at least one migration is required");
  const normalized = migrations.map((migration, index) => normalizeMigration(migration, index));
  for (let index = 0; index < normalized.length; index += 1) {
    const expected = index + 1;
    if (normalized[index].version !== expected) throw new MigrationRunnerError("ERR_MIGRATION_ORDER", `migration order must be contiguous from 1; expected ${expected}`, { index, version: normalized[index].version });
    if (index > 0 && normalized[index - 1].name >= normalized[index].name) throw new MigrationRunnerError("ERR_MIGRATION_ORDER", "migration names must be strictly ordered");
  }
  return Object.freeze(normalized);
}

function normalizeMigration(migration, index) {
  if (!migration || typeof migration !== "object" || Array.isArray(migration)) throw new MigrationRunnerError("ERR_MIGRATION_DESCRIPTOR", `migration ${index} must be an object`);
  const name = migration.name;
  const match = typeof name === "string" ? MIGRATION_FILE.exec(name) : null;
  if (!match) throw new MigrationRunnerError("ERR_MIGRATION_NAME", `migration ${index} has an invalid filename`);
  const version = Number(migration.version ?? match[1]);
  if (!Number.isSafeInteger(version) || version < 1 || Number(match[1]) !== version) throw new MigrationRunnerError("ERR_MIGRATION_VERSION", `migration ${name} has an invalid version`);
  if (typeof migration.sql !== "string" || migration.sql.trim().length === 0) throw new MigrationRunnerError("ERR_MIGRATION_SQL", `migration ${name} must contain SQL`);
  const checksum = migration.checksum ?? migrationChecksum(migration.sql);
  if (typeof checksum !== "string" || !SHA256.test(checksum)) throw new MigrationRunnerError("ERR_MIGRATION_CHECKSUM", `migration ${name} checksum is invalid`);
  if (checksum !== migrationChecksum(migration.sql)) throw new MigrationRunnerError("ERR_MIGRATION_CHECKSUM", `migration ${name} supplied checksum does not match SQL`);
  return Object.freeze({ version, name, sql: migration.sql, checksum });
}

export function advisoryLockKey(namespace = DEFAULT_LOCK_NAMESPACE) {
  if (typeof namespace !== "string" || namespace.length < 1 || namespace.length > 256) throw new MigrationRunnerError("ERR_MIGRATION_LOCK", "advisory lock namespace is invalid");
  const bytes = crypto.createHash("sha256").update(namespace, "utf8").digest().readBigInt64BE(0);
  return bytes.toString(10);
}

/**
 * Run forward-only immutable migrations. `client` intentionally only needs a
 * query(text, params) method; connection pooling and lifecycle stay outside
 * this package. The transaction lock is held until COMMIT/ROLLBACK.
 */
export function createMigrationRunner({ client, migrations, migrationDirectory, lockNamespace = DEFAULT_LOCK_NAMESPACE, applicationVersion = "unknown" } = {}) {
  assertClient(client);
  if (migrations !== undefined && migrationDirectory !== undefined) throw new MigrationRunnerError("ERR_MIGRATION_CONFIG", "provide migrations or migrationDirectory, not both");
  let migrationPromise;
  const resolveMigrations = async () => migrations === undefined ? loadSqlMigrations(migrationDirectory ?? defaultContractDirectory()) : normalizeMigrations(migrations);

  const run = async () => {
    if (migrationPromise) return migrationPromise;
    const current = (async () => runMigrations({ client, migrations: await resolveMigrations(), lockNamespace, applicationVersion }))();
    migrationPromise = current;
    current.then(() => { if (migrationPromise === current) migrationPromise = undefined; }, () => { if (migrationPromise === current) migrationPromise = undefined; });
    return current;
  };
  return Object.freeze({ run, migrate: run, status: () => migrationStatus({ client, migrations: resolveMigrations() }) });
}

export async function runMigrations({ client, migrations, lockNamespace = DEFAULT_LOCK_NAMESPACE, applicationVersion = "unknown" } = {}) {
  assertClient(client);
  if (typeof applicationVersion !== "string" || applicationVersion.length < 1 || applicationVersion.length > 64 || /[\u0000-\u001f\u007f]/.test(applicationVersion)) throw new MigrationRunnerError("ERR_APPLICATION_VERSION", "application version is invalid");
  const normalized = normalizeMigrations(migrations);
  const lockKey = advisoryLockKey(lockNamespace);
  const applied = [];
  let began = false;
  try {
    await query(client, "BEGIN", []);
    began = true;
    await query(client, "SELECT pg_advisory_xact_lock($1::bigint) AS locked", [lockKey]);
    const appliedRows = await readAppliedMigrations(client);
    const dirtyRows = await readDirtyMigrations(client);
    if (dirtyRows.length > 0) throw new MigrationDirtyError(dirtyRows);
    validateAppliedHistory(appliedRows, normalized);
    const appliedByVersion = new Map(appliedRows.map((row) => [row.version, row]));
    for (const migration of normalized) {
      const previous = appliedByVersion.get(migration.version);
      if (previous) {
        if (previous.checksum !== migration.checksum) throw new MigrationChecksumError(migration.version, previous.checksum, migration.checksum);
        continue;
      }
      await query(client, stripTransactionEnvelope(migration.sql), []);
      if (migration.version === 1) await query(client, "INSERT INTO schema_migrations (version, checksum, applied_at) VALUES ($1, $2, clock_timestamp())", [migration.version, migration.checksum]);
      else await query(client, "INSERT INTO schema_migrations (version, checksum, application_version, applied_at) VALUES ($1, $2, $3, clock_timestamp())", [migration.version, migration.checksum, applicationVersion]);
      applied.push({ version: migration.version, name: migration.name, checksum: migration.checksum });
    }
    await query(client, "COMMIT", []);
    began = false;
    return Object.freeze({ applied: Object.freeze(applied), currentVersion: normalized.at(-1).version, applicationVersion });
  } catch (error) {
    if (began) {
      try { await query(client, "ROLLBACK", []); }
      catch (rollbackError) { throw new MigrationRunnerError("ERR_MIGRATION_ROLLBACK", "migration failed and rollback failed", { rollbackError: rollbackError.message }, error); }
    }
    if (error instanceof MigrationRunnerError) throw error;
    throw new MigrationRunnerError("ERR_MIGRATION_FAILED", "migration transaction failed", undefined, error);
  }
}

export async function migrationStatus({ client, migrations }) {
  assertClient(client);
  const normalized = normalizeMigrations(await migrations);
  const appliedRows = await readAppliedMigrations(client);
  const dirtyRows = await readDirtyMigrations(client);
  validateAppliedHistory(appliedRows, normalized);
  const appliedByVersion = new Map(appliedRows.map((row) => [row.version, row]));
  const pending = normalized.filter((migration) => !appliedByVersion.has(migration.version)).map((migration) => migration.version);
  const modified = normalized.filter((migration) => appliedByVersion.get(migration.version)?.checksum !== undefined && appliedByVersion.get(migration.version).checksum !== migration.checksum).map((migration) => migration.version);
  return Object.freeze({ currentVersion: normalized.at(-1).version, applied: Object.freeze(appliedRows), pending: Object.freeze(pending), modified: Object.freeze(modified), dirty: dirtyRows.length > 0, dirtyRows: Object.freeze(dirtyRows) });
}

function assertClient(client) {
  if (!client || typeof client.query !== "function") throw new MigrationRunnerError("ERR_DB_CLIENT", "database client must provide query(text, params)");
}

async function query(client, text, params) {
  const result = await client.query(text, params);
  if (!result || !Array.isArray(result.rows)) return { rows: [] };
  return result;
}

async function readAppliedMigrations(client) {
  try {
    const result = await query(client, "SELECT version, checksum FROM schema_migrations ORDER BY version ASC", []);
    return result.rows.map(normalizeAppliedRow);
  } catch (error) {
    if (isMissingRelation(error, "schema_migrations")) return [];
    throw error;
  }
}

async function readDirtyMigrations(client) {
  try {
    const result = await query(client, "SELECT version, checksum, status, finished_at FROM schema_migration_attempts WHERE status IN ('running', 'failed') ORDER BY version ASC", []);
    return result.rows.map((row) => ({ version: Number(row.version), checksum: row.checksum, status: row.status, finished_at: row.finished_at ?? null }));
  } catch (error) {
    if (isMissingRelation(error, "schema_migration_attempts")) return [];
    throw error;
  }
}

function normalizeAppliedRow(row) {
  const version = Number(row.version);
  if (!Number.isSafeInteger(version) || version < 1 || typeof row.checksum !== "string" || !SHA256.test(row.checksum)) throw new MigrationRunnerError("ERR_MIGRATION_HISTORY", "schema_migrations contains an invalid row", { row });
  return Object.freeze({ version, checksum: row.checksum, applied_at: row.applied_at ?? null });
}

function validateAppliedHistory(rows, migrations) {
  const known = new Set(migrations.map((migration) => migration.version));
  let previous = 0;
  for (const row of rows) {
    if (row.version !== previous + 1 || !known.has(row.version)) throw new MigrationRunnerError("ERR_MIGRATION_HISTORY", "database migration history is out of order or newer than this application", { row, expected: previous + 1 });
    previous = row.version;
  }
}

function isMissingRelation(error, relation) {
  return error?.code === RELATION_MISSING || (typeof error?.message === "string" && new RegExp(`relation [^\\n]*${relation}[^\\n]* does not exist`, "i").test(error.message));
}

export function stripTransactionEnvelope(sql) {
  const match = /^\s*BEGIN\s*;([\s\S]*?)COMMIT\s*;\s*$/i.exec(sql);
  const body = match ? match[1] : sql;
  if (/\b(?:BEGIN|COMMIT|ROLLBACK)\b/i.test(body)) throw new MigrationRunnerError("ERR_MIGRATION_TRANSACTION", "migration contains nested transaction control statements");
  return body.trim();
}
