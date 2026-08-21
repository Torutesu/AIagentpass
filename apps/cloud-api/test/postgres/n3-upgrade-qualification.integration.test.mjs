import assert from "node:assert/strict";
import test from "node:test";

import { runN3UpgradeQualification, N3_SOURCE_VERSION, N3_TARGET_VERSION } from "../../../../scripts/postgres/n3-upgrade-qualification.mjs";

const ADMIN_DATABASE_URL = process.env.AGENTPASS_N3_POSTGRES_ADMIN_URL ?? process.env.AGENTPASS_TEST_POSTGRES_ADMIN_URL;
const MIGRATION_DATABASE_URL = process.env.AGENTPASS_N3_POSTGRES_MIGRATION_URL ?? process.env.AGENTPASS_TEST_MIGRATION_DATABASE_URL;

test("N3 qualifies the exact 52→53 upgrade with real migrator identity, preserved 0052 authority, preserved legacy rows, and no implicit sessions", {
  skip: ADMIN_DATABASE_URL && MIGRATION_DATABASE_URL ? false : "set N3 admin and agentpass_migrator PostgreSQL URLs to run the disposable qualification",
  timeout: 120_000
}, async () => {
  const report = await runN3UpgradeQualification({ adminUrl: ADMIN_DATABASE_URL, migrationUrl: MIGRATION_DATABASE_URL });
  assert.equal(report.qualification, "postgres-upgrade");
  assert.equal(report.report_schema_version, 1);
  assert.equal(report.name, "N3");
  assert.equal(report.source_version, N3_SOURCE_VERSION);
  assert.equal(report.target_version, N3_TARGET_VERSION);
  assert.equal(report.migration_role, "agentpass_migrator");
  assert.deepEqual(report.scenarios.map(({ from_version, to_version }) => ({ from_version, to_version })), [{ from_version: 52, to_version: 53 }]);
  const scenario = report.scenarios[0];
  assert.equal(scenario.seeded_legacy_row_count, 5);
  assert.equal(scenario.seeded_platform_authority_row_count, 4);
  assert.equal(scenario.legacy_preservation.exact, true);
  assert.equal(scenario.platform_authority_preservation.exact, true);
  assert.equal(scenario.history.startVersion, 52);
  assert.equal(scenario.history.targetVersion, 53);
  assert.equal(scenario.history.historyRows, 53);
  assert.deepEqual(scenario.history.appliedUpgradeVersions, [53]);
  assert.equal(scenario.history.status, "clean");
  assert.equal(scenario.history.seeded_legacy_row_count, 5);
  assert.equal(scenario.history.legacy_preservation.exact, true);
  assert.equal(scenario.history.platform_authority_preservation.exact, true);
  assert.match(scenario.history.legacy_preservation.snapshot_sha256, /^[0-9a-f]{64}$/u);
  assert.match(scenario.history.platform_authority_preservation.snapshot_sha256, /^[0-9a-f]{64}$/u);
  assert.deepEqual(scenario.history.migration_identity, { session_user: "agentpass_migrator", current_user: "agentpass_migrator" });
  assert.deepEqual(scenario.platform_session_seeds.before, [
    { name: "platform_credentials", exists: false, row_count: 0 },
    { name: "platform_sessions", exists: false, row_count: 0 }
  ]);
  assert.deepEqual(scenario.platform_session_seeds.after, [
    { name: "platform_credentials", exists: true, row_count: 0 },
    { name: "platform_sessions", exists: true, row_count: 0 }
  ]);
});
