import assert from "node:assert/strict";
import test from "node:test";

import {
  N5_MIGRATION_NAME,
  N5_SOURCE_VERSION,
  N5_TARGET_VERSION,
  runN5UpgradeQualification
} from "../../../../scripts/postgres/n5-upgrade-qualification.mjs";

const ADMIN_DATABASE_URL = process.env.AGENTPASS_N5_POSTGRES_ADMIN_URL ?? process.env.AGENTPASS_TEST_POSTGRES_ADMIN_URL;
const MIGRATION_DATABASE_URL = process.env.AGENTPASS_N5_POSTGRES_MIGRATION_URL ?? process.env.AGENTPASS_TEST_MIGRATION_DATABASE_URL;

test("N5 qualifies fresh 1→55 and exact 54→55 upgrade paths with clean history", {
  skip: ADMIN_DATABASE_URL && MIGRATION_DATABASE_URL ? false : "set N5 admin and agentpass_migrator PostgreSQL URLs to run the disposable qualification",
  timeout: 180_000
}, async () => {
  const report = await runN5UpgradeQualification({ adminUrl: ADMIN_DATABASE_URL, migrationUrl: MIGRATION_DATABASE_URL });
  assert.equal(report.qualification, "postgres-upgrade");
  assert.equal(report.report_schema_version, 1);
  assert.equal(report.name, "N5");
  assert.equal(report.source_version, N5_SOURCE_VERSION);
  assert.equal(report.target_version, N5_TARGET_VERSION);
  assert.equal(report.migration_name, N5_MIGRATION_NAME);
  assert.match(report.migration_checksum, /^[0-9a-f]{64}$/u);
  assert.equal(report.migration_role, "agentpass_migrator");
  assert.deepEqual(report.scenarios.map(({ from_version, to_version }) => ({ from_version, to_version })), [
    { from_version: 0, to_version: 55 },
    { from_version: 54, to_version: 55 }
  ]);
  for (const scenario of report.scenarios) {
    assert.equal(scenario.history.status, "clean");
    assert.equal(scenario.history.historyRows, 55);
    assert.deepEqual(scenario.history.appliedUpgradeVersions, [55]);
    assert.deepEqual(scenario.history.migrationIdentity, { session_user: "agentpass_migrator", current_user: "agentpass_migrator" });
    assert.equal(scenario.history.migrationName, N5_MIGRATION_NAME);
  }
});
