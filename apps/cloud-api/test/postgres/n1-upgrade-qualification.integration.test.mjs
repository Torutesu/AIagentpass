import assert from "node:assert/strict";
import test from "node:test";

import { runN1UpgradeQualification, N1_TARGET_VERSION } from "../../../../scripts/postgres/n1-upgrade-qualification.mjs";

const ADMIN_DATABASE_URL = process.env.AGENTPASS_N1_POSTGRES_ADMIN_URL ?? process.env.AGENTPASS_TEST_POSTGRES_ADMIN_URL;
const MIGRATION_DATABASE_URL = process.env.AGENTPASS_N1_POSTGRES_MIGRATION_URL ?? process.env.AGENTPASS_TEST_MIGRATION_DATABASE_URL;

test("N1 qualifies seeded 47→51 and 48→51 upgrades with exact history and authority preservation", {
  skip: ADMIN_DATABASE_URL && MIGRATION_DATABASE_URL ? false : "set N1 admin and migrator PostgreSQL URLs to run the disposable qualification",
  timeout: 120_000
}, async () => {
  const report = await runN1UpgradeQualification({ adminUrl: ADMIN_DATABASE_URL, migrationUrl: MIGRATION_DATABASE_URL });
  assert.equal(report.qualification, "postgres-upgrade");
  assert.equal(report.name, "N1");
  assert.equal(report.target_version, N1_TARGET_VERSION);
  assert.equal(report.migration_role, "agentpass_migrator");
  assert.deepEqual(report.scenarios.map(({ from_version, to_version }) => ({ from_version, to_version })), [
    { from_version: 47, to_version: 51 },
    { from_version: 48, to_version: 51 }
  ]);
  for (const scenario of report.scenarios) {
    assert.equal(scenario.history.targetVersion, 51);
    assert.deepEqual(scenario.history.appliedUpgradeVersions, scenario.from_version === 47 ? [48, 49, 50, 51] : [49, 50, 51]);
    assert.equal(scenario.seeded_authority_row_count, 9);
  }
});
