import assert from "node:assert/strict";
import test from "node:test";

import {
  N1_APPLICATION_VERSION,
  N1_UPGRADE_START_VERSIONS,
  assertAuthorityRowsPreserved,
  assertN1MigrationHistory
} from "../../../../scripts/postgres/n1-upgrade-qualification.mjs";
import { loadSqlMigrations } from "../../src/postgres/migration-runner.mjs";

test("N1 history validator proves contiguous checksums, head, status, and exact upgrade set", async () => {
  const migrations = await loadSqlMigrations();
  for (const startVersion of N1_UPGRADE_START_VERSIONS) {
    const rows = migrations.slice(0, 51).map(({ version, checksum }) => ({ version, checksum, application_version: N1_APPLICATION_VERSION }));
    const upgrade = { applied: migrations.slice(startVersion, 51).map(({ version, checksum }) => ({ version, checksum })) };
    const status = {
      currentVersion: 51,
      pending: [],
      modified: [],
      dirty: false,
      dirtyRows: [],
      applied: rows
    };
    const report = assertN1MigrationHistory({ rows, migrations, startVersion, upgrade, status });
    assert.deepEqual(report.appliedUpgradeVersions, migrations.slice(startVersion, 51).map(({ version }) => version));
  }
});

test("N1 history validator rejects checksum drift, missing history, a wrong head, and an incomplete upgrade", async () => {
  const migrations = await loadSqlMigrations();
  const rows = migrations.slice(0, 51).map(({ version, checksum }) => ({ version, checksum, application_version: N1_APPLICATION_VERSION }));
  const base = {
    rows,
    migrations,
    startVersion: 47,
    upgrade: { applied: migrations.slice(47, 51).map(({ version, checksum }) => ({ version, checksum })) },
    status: { currentVersion: 51, pending: [], modified: [], dirty: false, dirtyRows: [], applied: rows }
  };
  for (const mutate of [
    (value) => { value.rows[50].checksum = "0".repeat(64); },
    (value) => { value.rows.splice(20, 1); },
    (value) => { value.rows[50].version = 52; },
    (value) => { value.upgrade.applied.pop(); },
    (value) => { value.status.pending = [51]; }
  ]) {
    const candidate = structuredClone(base);
    mutate(candidate);
    assert.throws(() => assertN1MigrationHistory(candidate), assert.AssertionError);
  }
});

test("N1 authority snapshot comparison is strict, including binary values", () => {
  const before = new Map([["managed_signer_keys", [{ key_id: "seed", fingerprint: Buffer.from([1, 2, 3]) }]]]);
  const after = new Map([["managed_signer_keys", [{ key_id: "seed", fingerprint: Buffer.from([1, 2, 3]) }]]]);
  assert.equal(assertAuthorityRowsPreserved(before, after), true);
  const changed = new Map([["managed_signer_keys", [{ key_id: "seed", fingerprint: Buffer.from([1, 2, 4]) }]]]);
  assert.throws(() => assertAuthorityRowsPreserved(before, changed), /authority rows changed/u);
});
