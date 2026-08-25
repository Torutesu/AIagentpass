import crypto from "node:crypto";
import fs from "node:fs";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const MIGRATION_FILE = /^(\d{4})_([a-z0-9_]+)\.sql$/u;
const SHA256 = /^[0-9a-f]{64}$/u;
const MAX_MIGRATIONS = 256;
const MAX_CATALOG_BYTES = 2 * 1024 * 1024;
const MAX_MANIFEST_BYTES = 16 * 1024 * 1024;

export const POSTGRES_SCHEMA_HEAD_SOURCE_VERSION = 1;

export class PostgresSchemaHeadError extends Error {
  constructor(code, message, details = undefined) {
    super(message);
    this.name = "PostgresSchemaHeadError";
    this.code = code;
    if (details !== undefined) this.details = details;
  }
}

export function defaultPostgresCatalogFile() {
  return path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../../../contracts/catalog-v1.json");
}

export function defaultPostgresMigrationDirectory() {
  return path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../../../contracts/postgres");
}

/**
 * Derive the only supported PostgreSQL schema head from independently
 * reviewable inputs. Callers may pass a release migration manifest as a
 * third source; when present, its names and checksums must also agree.
 */
export function derivePostgresSchemaHead({ catalog, migrations, migrationManifest, catalogBytes, manifestBytes } = {}) {
  const catalogMigrations = normalizeCatalogMigrations(catalog);
  const fileMigrations = normalizeMigrations(migrations);
  assertSameMigrationSet(catalogMigrations, fileMigrations, "catalog and migration files disagree", true);

  const manifestMigrations = migrationManifest === undefined ? undefined : normalizeManifestMigrations(migrationManifest);
  if (manifestMigrations !== undefined) assertSameMigrationSet(fileMigrations, manifestMigrations, "migration manifest and migration files disagree", true);

  const head = fileMigrations.at(-1);
  if (!head) throw schemaError("empty", "PostgreSQL migration set is empty");
  return deepFreeze({
    schema_version: POSTGRES_SCHEMA_HEAD_SOURCE_VERSION,
    version: head.version,
    name: head.name,
    checksum: head.checksum,
    migration_count: fileMigrations.length,
    migrations: fileMigrations.map(({ version, name, checksum, bytes }) => ({ version, name, checksum, ...(bytes === undefined ? {} : { bytes }) })),
    catalog_entries: Array.isArray(catalog?.entries) ? catalog.entries.length : null,
    catalog_sha256: digestIfBytes(catalogBytes),
    manifest_sha256: digestIfBytes(manifestBytes)
  });
}

export async function readPostgresSchemaHead({
  catalogFile = defaultPostgresCatalogFile(),
  migrationDirectory = defaultPostgresMigrationDirectory(),
  migrationManifestFile
} = {}) {
  const [catalogBytes, migrations, manifestBytes] = await Promise.all([
    readBoundedFile(catalogFile, MAX_CATALOG_BYTES),
    readMigrationFiles(migrationDirectory),
    migrationManifestFile === undefined ? undefined : readBoundedFile(migrationManifestFile, MAX_MANIFEST_BYTES)
  ]);
  const catalog = parseJson(catalogBytes, "catalog");
  const migrationManifest = manifestBytes === undefined ? undefined : parseJson(manifestBytes, "migration manifest");
  return derivePostgresSchemaHead({ catalog, migrations, migrationManifest, catalogBytes, manifestBytes });
}

export function readPostgresSchemaHeadSync({
  catalogFile = defaultPostgresCatalogFile(),
  migrationDirectory = defaultPostgresMigrationDirectory(),
  migrationManifestFile
} = {}) {
  const catalogBytes = readBoundedFileSync(catalogFile, MAX_CATALOG_BYTES);
  const migrations = readMigrationFilesSync(migrationDirectory);
  const manifestBytes = migrationManifestFile === undefined ? undefined : readBoundedFileSync(migrationManifestFile, MAX_MANIFEST_BYTES);
  const catalog = parseJson(catalogBytes, "catalog");
  const migrationManifest = manifestBytes === undefined ? undefined : parseJson(manifestBytes, "migration manifest");
  return derivePostgresSchemaHead({ catalog, migrations, migrationManifest, catalogBytes, manifestBytes });
}

// This is intentionally evaluated from the catalog and SQL files at process
// start. It is frozen and has no setter, so a new catalog/file head becomes
// the expected head on the next process start without a second version knob.
export const POSTGRES_SCHEMA_HEAD = readPostgresSchemaHeadSync();

function normalizeCatalogMigrations(catalog) {
  if (!plainObject(catalog) || !Array.isArray(catalog.entries)) throw schemaError("catalog", "migration catalog is invalid");
  const entries = catalog.entries.filter((entry) => plainObject(entry) && entry.kind === "postgres-migration");
  if (entries.length === 0 || entries.length > MAX_MIGRATIONS) throw schemaError("catalog", "migration catalog contains no supported migrations");
  const migrations = entries.map((entry) => {
    const source = typeof entry.source === "string" ? entry.source : "";
    const match = /^postgres\/(\d{4})_([a-z0-9_]+)\.sql$/u.exec(source);
    const version = Number(entry.version);
    const checksum = entry.sha256;
    if (!match || !Number.isSafeInteger(version) || version < 1 || Number(match[1]) !== version) throw schemaError("catalog", "migration catalog entry has an invalid source or version");
    if (typeof checksum !== "string" || !SHA256.test(checksum)) throw schemaError("catalog", "migration catalog entry has an invalid checksum");
    return { version, name: `${match[1]}_${match[2]}.sql`, checksum };
  }).sort((left, right) => left.version - right.version || left.name.localeCompare(right.name));
  assertContiguous(migrations, "migration catalog");
  return migrations;
}

function normalizeMigrations(migrations) {
  if (!Array.isArray(migrations) || migrations.length === 0 || migrations.length > MAX_MIGRATIONS) throw schemaError("files", "migration files are invalid");
  const normalized = migrations.map((migration) => {
    if (!plainObject(migration) || typeof migration.name !== "string") throw schemaError("files", "migration descriptor is invalid");
    const match = MIGRATION_FILE.exec(migration.name);
    const version = Number(migration.version ?? match?.[1]);
    if (!match || !Number.isSafeInteger(version) || version < 1 || Number(match[1]) !== version) throw schemaError("files", "migration filename or version is invalid");
    const checksum = migration.checksum ?? (typeof migration.sql === "string" ? sha256(Buffer.from(migration.sql, "utf8")) : undefined);
    if (typeof checksum !== "string" || !SHA256.test(checksum)) throw schemaError("files", "migration checksum is invalid");
    const bytes = migration.bytes ?? (typeof migration.sql === "string" ? Buffer.byteLength(migration.sql, "utf8") : undefined);
    if (bytes !== undefined && (!Number.isSafeInteger(bytes) || bytes < 1)) throw schemaError("files", "migration byte count is invalid");
    return { version, name: migration.name, checksum, ...(bytes === undefined ? {} : { bytes }) };
  }).sort((left, right) => left.version - right.version || left.name.localeCompare(right.name));
  assertContiguous(normalized, "migration files");
  return normalized;
}

function normalizeManifestMigrations(manifest) {
  if (!plainObject(manifest) || !Array.isArray(manifest.migrations)) throw schemaError("manifest", "migration manifest is invalid");
  return normalizeMigrations(manifest.migrations.map((entry) => ({
    name: entry?.name,
    checksum: entry?.sha256,
    bytes: entry?.bytes
  })));
}

function assertSameMigrationSet(left, right, message, compareChecksums = false) {
  if (left.length !== right.length || left.some((migration, index) => migration.version !== right[index].version || migration.name !== right[index].name
    || compareChecksums && migration.checksum !== right[index].checksum)) {
    throw schemaError("mismatch", message);
  }
}

function assertContiguous(migrations, label) {
  for (let index = 0; index < migrations.length; index += 1) {
    if (migrations[index].version !== index + 1) throw schemaError("order", `${label} must be contiguous from version 1`);
    if (index > 0 && migrations[index - 1].name >= migrations[index].name) throw schemaError("order", `${label} names must be strictly ordered`);
  }
}

async function readMigrationFiles(directory) {
  if (typeof directory !== "string" || !path.isAbsolute(directory)) throw schemaError("files", "migration directory must be absolute");
  let names;
  try { names = await fs.promises.readdir(directory); } catch { throw schemaError("files", "migration directory cannot be read"); }
  return Promise.all(names.filter((name) => MIGRATION_FILE.test(name)).sort().map(async (name) => {
    let bytes;
    try { bytes = await fs.promises.readFile(path.join(directory, name)); } catch { throw schemaError("files", "migration file cannot be read"); }
    return { name, sql: bytes.toString("utf8"), bytes: bytes.length, checksum: sha256(bytes) };
  }));
}

function readMigrationFilesSync(directory) {
  if (typeof directory !== "string" || !path.isAbsolute(directory)) throw schemaError("files", "migration directory must be absolute");
  let names;
  try { names = fs.readdirSync(directory); } catch { throw schemaError("files", "migration directory cannot be read"); }
  return names.filter((name) => MIGRATION_FILE.test(name)).sort().map((name) => {
    let bytes;
    try { bytes = fs.readFileSync(path.join(directory, name)); } catch { throw schemaError("files", "migration file cannot be read"); }
    return { name, sql: bytes.toString("utf8"), bytes: bytes.length, checksum: sha256(bytes) };
  });
}

async function readBoundedFile(file, maximum) {
  if (typeof file !== "string" || !path.isAbsolute(file)) throw schemaError("file", "input file must be absolute");
  let bytes;
  try { bytes = await readFile(file); } catch { throw schemaError("file", "input file cannot be read"); }
  if (bytes.length < 1 || bytes.length > maximum) throw schemaError("file", "input file is too large");
  return bytes;
}

function readBoundedFileSync(file, maximum) {
  if (typeof file !== "string" || !path.isAbsolute(file)) throw schemaError("file", "input file must be absolute");
  let bytes;
  try { bytes = fs.readFileSync(file); } catch { throw schemaError("file", "input file cannot be read"); }
  if (bytes.length < 1 || bytes.length > maximum) throw schemaError("file", "input file is too large");
  return bytes;
}

function parseJson(bytes, label) {
  try { return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)); }
  catch { throw schemaError("json", `${label} is not valid JSON`); }
}

function digestIfBytes(bytes) { return bytes === undefined ? null : sha256(bytes); }
function sha256(value) { return crypto.createHash("sha256").update(value).digest("hex"); }
function plainObject(value) { return value !== null && typeof value === "object" && !Array.isArray(value); }
function deepFreeze(value) {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const child of Object.values(value)) deepFreeze(child);
  }
  return value;
}
function schemaError(code, message, details) { return new PostgresSchemaHeadError(`ERR_SCHEMA_HEAD_${code.toUpperCase()}`, message, details); }
