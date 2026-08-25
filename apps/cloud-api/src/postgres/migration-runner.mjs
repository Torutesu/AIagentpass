import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const MIGRATION_FILE = /^(\d{4})_([a-z0-9_]+)\.sql$/;
const SHA256 = /^[0-9a-f]{64}$/;
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
  let migrationAttempts = [];
  let began = false;
  let migrationCommitted = false;
  try {
    await query(client, "BEGIN", []);
    began = true;
    await query(client, "SELECT pg_advisory_xact_lock($1::bigint) AS locked", [lockKey]);
    const appliedRows = await readAppliedMigrations(client);
    const attemptsRelationExists = await relationExists(client, "schema_migration_attempts");
    const dirtyRows = await readDirtyMigrations(client, { relationExists: attemptsRelationExists });
    if (dirtyRows.length > 0) throw new MigrationDirtyError(dirtyRows);
    validateAppliedHistory(appliedRows, normalized);
    const appliedByVersion = new Map(appliedRows.map((row) => [row.version, row]));
    const pending = normalized.filter((migration) => !appliedByVersion.has(migration.version));

    // The attempt row must be committed before any migration SQL begins. The
    // first transaction is therefore only the coordination/ledger transaction;
    // after it commits, the migration transaction starts from a clean boundary.
    // Bootstrap migrations cannot use this ledger until migration 0002 creates
    // the table; all subsequent migrations are covered fail-closed.
    if (attemptsRelationExists && pending.length > 0) {
      migrationAttempts = await insertMigrationAttempts(client, pending, applicationVersion);
      await query(client, "COMMIT", []);
      began = false;
      await query(client, "BEGIN", []);
      began = true;
      await query(client, "SELECT pg_advisory_xact_lock($1::bigint) AS locked", [lockKey]);
    }

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
    migrationCommitted = true;
    await completeMigrationAttempts(client, migrationAttempts);
    return Object.freeze({ applied: Object.freeze(applied), currentVersion: normalized.at(-1).version, applicationVersion });
  } catch (error) {
    if (began) {
      try { await query(client, "ROLLBACK", []); }
      catch (rollbackError) { throw new MigrationRunnerError("ERR_MIGRATION_ROLLBACK", "migration failed and rollback failed", { rollbackError: rollbackError.message }, error); }
    }
    if (!migrationCommitted && migrationAttempts.length > 0) {
      try { await failMigrationAttempts(client, migrationAttempts, error); }
      catch (attemptError) {
        throw new MigrationRunnerError("ERR_MIGRATION_ATTEMPT_RECORD", "migration failed and its attempt could not be durably recorded", undefined, attemptError);
      }
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
  if (!(await relationExists(client, "schema_migrations"))) return [];
  const result = await query(client, "SELECT version, checksum FROM schema_migrations ORDER BY version ASC", []);
  return result.rows.map(normalizeAppliedRow);
}

async function readDirtyMigrations(client) {
  const hasKnownRelation = arguments.length > 1;
  const relationAlreadyExists = hasKnownRelation ? arguments[1]?.relationExists === true : await relationExists(client, "schema_migration_attempts");
  if (!relationAlreadyExists) return [];
  const result = await query(client, "SELECT version, checksum, status, finished_at FROM schema_migration_attempts WHERE status IN ('running', 'failed') ORDER BY version ASC", []);
  return result.rows.map((row) => ({ version: Number(row.version), checksum: row.checksum, status: row.status, finished_at: row.finished_at ?? null }));
}

async function insertMigrationAttempts(client, migrations, applicationVersion) {
  const attempts = [];
  for (const migration of migrations) {
    const id = crypto.randomUUID();
    await query(client, `INSERT INTO schema_migration_attempts
        (id,version,checksum,application_version,status,started_at,finished_at,error_code)
        VALUES ($1,$2,$3,$4,'running',clock_timestamp(),NULL,NULL)`, [
      id, migration.version, migration.checksum, applicationVersion
    ]);
    attempts.push(Object.freeze({ id, version: migration.version, checksum: migration.checksum }));
  }
  return Object.freeze(attempts);
}

async function completeMigrationAttempts(client, attempts) {
  for (const attempt of attempts) {
    const result = await query(client, `UPDATE schema_migration_attempts
        SET status='applied',finished_at=clock_timestamp(),error_code=NULL
        WHERE id=$1 AND status='running'`, [attempt.id]);
    if (result.rowCount !== 1) throw new MigrationRunnerError("ERR_MIGRATION_ATTEMPT_RECORD", "migration attempt completion was not durable", { version: attempt.version });
  }
}

async function failMigrationAttempts(client, attempts, error) {
  const errorCode = migrationAttemptErrorCode(error);
  for (const attempt of attempts) {
    const result = await query(client, `UPDATE schema_migration_attempts
        SET status='failed',finished_at=clock_timestamp(),error_code=$2
        WHERE id=$1 AND status='running'`, [attempt.id, errorCode]);
    if (result.rowCount !== 1) throw new MigrationRunnerError("ERR_MIGRATION_ATTEMPT_RECORD", "migration failure attempt was not durable", { version: attempt.version });
  }
}

function migrationAttemptErrorCode(error) {
  const code = error?.code;
  return error instanceof MigrationRunnerError && typeof code === "string" && /^[A-Za-z0-9_.:-]{1,64}$/u.test(code)
    ? code
    : "ERR_MIGRATION_FAILED";
}

async function relationExists(client, relation) {
  const result = await query(client, "SELECT to_regclass($1) AS relation", [relation]);
  const value = result.rows?.[0]?.relation;
  return typeof value === "string" && value.length > 0;
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

export function stripTransactionEnvelope(sql) {
  const match = /^\s*BEGIN\s*;([\s\S]*?)COMMIT\s*;\s*$/i.exec(sql);
  const body = match ? match[1] : sql;
  if (hasTopLevelTransactionControl(body)) throw new MigrationRunnerError("ERR_MIGRATION_TRANSACTION", "migration contains nested transaction control statements");
  return body.trim();
}

function hasTopLevelTransactionControl(sql) {
  for (let index = 0; index < sql.length;) {
    const character = sql[index];
    const next = sql[index + 1];
    if (character === "'") { index = skipQuoted(sql, index, "'"); continue; }
    if (character === '"') { index = skipQuoted(sql, index, '"'); continue; }
    if (character === "-" && next === "-") { index = skipLineComment(sql, index + 2); continue; }
    if (character === "/" && next === "*") { index = skipBlockComment(sql, index + 2); continue; }
    if (character === "$") {
      const delimiter = /^\$(?:[A-Za-z_][A-Za-z0-9_]*)?\$/u.exec(sql.slice(index))?.[0];
      if (delimiter) { index = skipDollarQuote(sql, index, delimiter); continue; }
    }
    if (/[A-Za-z_]/u.test(character)) {
      let end = index + 1;
      while (end < sql.length && /[A-Za-z0-9_$]/u.test(sql[end])) end += 1;
      if (["BEGIN", "COMMIT", "ROLLBACK"].includes(sql.slice(index, end).toUpperCase())) return true;
      index = end;
      continue;
    }
    index += 1;
  }
  return false;
}

function skipQuoted(sql, start, quote) {
  let index = start + 1;
  while (index < sql.length) {
    if (sql[index] !== quote) { index += 1; continue; }
    if (sql[index + 1] === quote) { index += 2; continue; }
    return index + 1;
  }
  throw new MigrationRunnerError("ERR_MIGRATION_SQL", "migration contains an unterminated quoted value");
}

function skipLineComment(sql, start) {
  const end = sql.indexOf("\n", start);
  return end === -1 ? sql.length : end + 1;
}

function skipBlockComment(sql, start) {
  let depth = 1;
  let index = start;
  while (index < sql.length && depth > 0) {
    if (sql[index] === "/" && sql[index + 1] === "*") { depth += 1; index += 2; continue; }
    if (sql[index] === "*" && sql[index + 1] === "/") { depth -= 1; index += 2; continue; }
    index += 1;
  }
  if (depth !== 0) throw new MigrationRunnerError("ERR_MIGRATION_SQL", "migration contains an unterminated block comment");
  return index;
}

function skipDollarQuote(sql, start, delimiter) {
  const end = sql.indexOf(delimiter, start + delimiter.length);
  if (end === -1) throw new MigrationRunnerError("ERR_MIGRATION_SQL", "migration contains an unterminated dollar-quoted value");
  return end + delimiter.length;
}
