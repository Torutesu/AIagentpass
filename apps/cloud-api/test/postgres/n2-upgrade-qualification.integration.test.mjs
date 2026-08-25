import assert from "node:assert/strict";
import test from "node:test";

import { runN2UpgradeQualification, N2_SOURCE_VERSION, N2_TARGET_VERSION } from "../../../../scripts/postgres/n2-upgrade-qualification.mjs";

const ADMIN_DATABASE_URL = process.env.AGENTPASS_N2_POSTGRES_ADMIN_URL ?? process.env.AGENTPASS_TEST_POSTGRES_ADMIN_URL;
const MIGRATION_DATABASE_URL = process.env.AGENTPASS_N2_POSTGRES_MIGRATION_URL ?? process.env.AGENTPASS_TEST_MIGRATION_DATABASE_URL;

test("N2 qualifies the exact 51→52 upgrade with real migrator identity, clean status, exact history, and no implicit authority seeds", {
  skip: ADMIN_DATABASE_URL && MIGRATION_DATABASE_URL ? false : "set N2 admin and agentpass_migrator PostgreSQL URLs to run the disposable qualification",
  timeout: 120_000
}, async () => {
  const report = await runN2UpgradeQualification({ adminUrl: ADMIN_DATABASE_URL, migrationUrl: MIGRATION_DATABASE_URL });
  assert.equal(report.qualification, "postgres-upgrade");
  assert.equal(report.report_schema_version, 1);
  assert.equal(report.name, "N2");
  assert.equal(report.source_version, N2_SOURCE_VERSION);
  assert.equal(report.target_version, N2_TARGET_VERSION);
  assert.equal(report.migration_role, "agentpass_migrator");
  assert.deepEqual(report.scenarios.map(({ from_version, to_version }) => ({ from_version, to_version })), [{ from_version: 51, to_version: 52 }]);
  const scenario = report.scenarios[0];
  assert.equal(scenario.seeded_legacy_row_count, 4);
  assert.equal(scenario.legacy_preservation.exact, true);
  assert.equal(scenario.history.startVersion, 51);
  assert.equal(scenario.history.targetVersion, 52);
  assert.equal(scenario.history.historyRows, 52);
  assert.deepEqual(scenario.history.appliedUpgradeVersions, [52]);
  assert.equal(scenario.history.status, "clean");
  assert.equal(scenario.history.seeded_legacy_row_count, 4);
  assert.equal(scenario.history.legacy_preservation.exact, true);
  assert.match(scenario.history.legacy_preservation.snapshot_sha256, /^[0-9a-f]{64}$/u);
  assert.deepEqual(scenario.history.legacy_preservation.tables, [
    { name: "organizations", row_count: 1 },
    { name: "members", row_count: 1 },
    { name: "memberships", row_count: 1 },
    { name: "human_sessions", row_count: 1 }
  ]);
  assert.deepEqual(scenario.history.migration_identity, { session_user: "agentpass_migrator", current_user: "agentpass_migrator" });
  for (const point of [scenario.history.platform_authority_seeds.before, scenario.history.platform_authority_seeds.after]) {
    assert.ok(point.every(({ row_count }) => row_count === 0));
  }
});
