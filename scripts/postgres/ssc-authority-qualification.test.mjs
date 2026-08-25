import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { crossTenantNegativeMatrix, loadAuthorityManifest, migrationHeadFixture, notProvenReport, scenarioDriver } from "./ssc-authority-qualification.mjs";

test("DB-101 manifest is closed, role-separated, and secret-free", () => {
  const manifest = loadAuthorityManifest();
  assert.deepEqual(Object.keys(manifest.domains).sort(), ["maintenance", "small_software"]);
  assert.equal(manifest.invariants.app_direct_dml, false);
  assert.equal(JSON.stringify(manifest).includes("password"), false);
});

test("DB-102 cross-tenant matrix is deny-only", () => {
  const matrix = crossTenantNegativeMatrix();
  assert.ok(matrix.length >= 5);
  assert.ok(matrix.every((probe) => probe.expected === "deny" && probe.subject.includes("tenant")));
});

test("DB-103 rejects split migration/catalog heads", () => {
  assert.equal(migrationHeadFixture({ version: 12, migration_count: 12, catalog_head: 12, catalog_checksum: "a".repeat(64) }).status, "passed");
  assert.equal(migrationHeadFixture({ version: 12, migration_count: 11, catalog_head: 12, catalog_checksum: "a".repeat(64) }).status, "failed");
});

test("DB-104/105 driver has deterministic lock order and one response-loss outcome", () => {
  const result = scenarioDriver({ responseLost: true });
  assert.deepEqual(result.lock_order, ["tenant_authority", "operation_ledger"]);
  assert.equal(result.deadlock_detected, false);
  assert.equal(result.terminal_outcomes, 1);
});

test("DB-106 missing live PostgreSQL is typed not_proven", () => {
  assert.deepEqual(notProvenReport(), { status: "not_proven", qualified: false, check_id: "DB-106", reason: "live_postgresql_unavailable", external_evidence: "not_proven" });
  const child = spawnSync(process.execPath, [fileURLToPath(new URL("./ssc-authority-qualification.mjs", import.meta.url))], { encoding: "utf8", env: { PATH: process.env.PATH } });
  assert.equal(child.status, 2);
  assert.match(child.stdout, /"status":"not_proven"/u);
});
