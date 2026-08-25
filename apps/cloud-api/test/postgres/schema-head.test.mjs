import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs/promises";
import test from "node:test";

import { REQUIRED_MIGRATION_VERSION } from "../../../../scripts/postgres/authority-manifest.mjs";
import { createOperationalHealth, createDrainController } from "../../src/postgres/operational-health.mjs";
import {
  derivePostgresSchemaHead,
  POSTGRES_SCHEMA_HEAD,
  POSTGRES_SCHEMA_HEAD_SOURCE_VERSION
} from "../../src/postgres/schema-head.mjs";
import { loadSqlMigrations } from "../../src/postgres/migration-runner.mjs";

const CATALOG_FILE = new URL("../../../../contracts/catalog-v1.json", import.meta.url);

function digest(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function pool() {
  return { options: { max: 4 }, totalCount: 1, idleCount: 1, waitingCount: 0 };
}

function catalogWithSyntheticMigration(catalog, version, name, checksum) {
  return {
    ...catalog,
    entries: [...catalog.entries, { kind: "postgres-migration", source: `postgres/${name}`, version, sha256: checksum }]
  };
}

function syntheticMigrationName(version) {
  return `${String(version).padStart(4, "0")}_synthetic_s3.sql`;
}

function appliedThrough(version) {
  return Array.from({ length: version }, (_, index) => ({ version: index + 1, checksum: "a".repeat(64) }));
}

test("the current catalog, migration files, and authority manifest head are one frozen source", async () => {
  const catalogBytes = await fs.readFile(CATALOG_FILE);
  const catalog = JSON.parse(catalogBytes.toString("utf8"));
  const migrations = await loadSqlMigrations();
  const head = derivePostgresSchemaHead({ catalog, migrations, catalogBytes });
  assert.deepEqual(head, POSTGRES_SCHEMA_HEAD);
  assert.equal(REQUIRED_MIGRATION_VERSION, String(head.version));
  assert.equal(head.schema_version, POSTGRES_SCHEMA_HEAD_SOURCE_VERSION);
  assert.equal(Object.isFrozen(head), true);
  assert.equal(Object.isFrozen(head.migrations), true);
  assert.equal(Object.isFrozen(head.migrations.at(-1)), true);
  assert.throws(() => { head.version = 1; }, TypeError);
});

test("a coordinated synthetic 0056 automatically becomes the head", async () => {
  const catalog = JSON.parse(await fs.readFile(CATALOG_FILE, "utf8"));
  const sql = "BEGIN;\nCREATE TABLE synthetic_s3 (id integer PRIMARY KEY);\nCOMMIT;\n";
  const migration = {
    version: POSTGRES_SCHEMA_HEAD.version + 1,
    name: syntheticMigrationName(POSTGRES_SCHEMA_HEAD.version + 1),
    sql,
    bytes: Buffer.byteLength(sql),
    checksum: digest(sql)
  };
  const migrations = [...POSTGRES_SCHEMA_HEAD.migrations, migration];
  const manifest = { schema_version: 1, migrations: migrations.map(({ name, bytes, checksum }) => ({ name, bytes, sha256: checksum })) };
  const head = derivePostgresSchemaHead({
    catalog: catalogWithSyntheticMigration(catalog, migration.version, migration.name, migration.checksum),
    migrations,
    migrationManifest: manifest
  });
  assert.equal(head.version, POSTGRES_SCHEMA_HEAD.version + 1);
  assert.equal(head.migration_count, POSTGRES_SCHEMA_HEAD.migration_count + 1);
  assert.equal(head.name, migration.name);
  assert.equal(head.checksum, migration.checksum);
});

test("a file, catalog, manifest, or checksum update without the other sources fails closed", async () => {
  const catalog = JSON.parse(await fs.readFile(CATALOG_FILE, "utf8"));
  const sql = "BEGIN;\nCREATE TABLE synthetic_s3 (id integer PRIMARY KEY);\nCOMMIT;\n";
  const migration = {
    version: POSTGRES_SCHEMA_HEAD.version + 1,
    name: syntheticMigrationName(POSTGRES_SCHEMA_HEAD.version + 1),
    sql,
    bytes: Buffer.byteLength(sql),
    checksum: digest(sql)
  };
  const futureCatalog = catalogWithSyntheticMigration(catalog, migration.version, migration.name, migration.checksum);
  const futureMigrations = [...POSTGRES_SCHEMA_HEAD.migrations, migration];
  const futureManifest = { migrations: futureMigrations.map(({ name, bytes, checksum }) => ({ name, bytes, sha256: checksum })) };
  assert.throws(() => derivePostgresSchemaHead({ catalog, migrations: futureMigrations }), { code: "ERR_SCHEMA_HEAD_MISMATCH" });
  assert.throws(() => derivePostgresSchemaHead({ catalog: futureCatalog, migrations: POSTGRES_SCHEMA_HEAD.migrations }), { code: "ERR_SCHEMA_HEAD_MISMATCH" });
  assert.throws(() => derivePostgresSchemaHead({ catalog, migrations: POSTGRES_SCHEMA_HEAD.migrations, migrationManifest: futureManifest }), { code: "ERR_SCHEMA_HEAD_MISMATCH" });
  assert.throws(() => derivePostgresSchemaHead({ catalog: futureCatalog, migrations: futureMigrations, migrationManifest: { migrations: futureManifest.migrations.map((entry, index) => index === futureManifest.migrations.length - 1 ? { ...entry, sha256: "0".repeat(64) } : entry) } }), { code: "ERR_SCHEMA_HEAD_MISMATCH" });
  const staleCatalog = { ...catalog, entries: catalog.entries.map((entry) => entry.id === "migration.0084_device_audit_inbox_worker_authority" ? { ...entry, sha256: "0".repeat(64) } : entry) };
  assert.throws(() => derivePostgresSchemaHead({ catalog: staleCatalog, migrations: POSTGRES_SCHEMA_HEAD.migrations }), { code: "ERR_SCHEMA_HEAD_MISMATCH" });
});

test("readiness consumes the same derived head and rejects a stale database", async () => {
  const futureHead = { ...POSTGRES_SCHEMA_HEAD, version: POSTGRES_SCHEMA_HEAD.version + 1, migration_count: POSTGRES_SCHEMA_HEAD.migration_count + 1 };
  const ready = createOperationalHealth({
    pool: pool(),
    schemaHead: futureHead,
    migrationStatus: async () => ({ applied: appliedThrough(futureHead.version), pending: [], modified: [], dirty: false }),
    drainController: createDrainController(),
    probe: async () => true
  });
  const readyResult = await ready.readiness();
  assert.equal(readyResult.ready, true);
  assert.equal(readyResult.checks.schema.expected_version, futureHead.version);

  const stale = createOperationalHealth({
    pool: pool(),
    schemaHead: futureHead,
    migrationStatus: async () => ({ applied: appliedThrough(POSTGRES_SCHEMA_HEAD.version), pending: [futureHead.version], modified: [], dirty: false }),
    drainController: createDrainController(),
    probe: async () => true
  });
  const staleResult = await stale.readiness();
  assert.equal(staleResult.ready, false);
  assert.equal(staleResult.checks.schema.expected_version, futureHead.version);
});
