import assert from "node:assert/strict";
import crypto from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { readFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

import {
  N4_APPLICATION_VERSION,
  N4_AUTHORITY_TEST_FILES,
  N4_LEGACY_TABLE_SPECS,
  N4_MIGRATION_NAME,
  N4_SOURCE_VERSION,
  N4_TARGET_VERSION,
  assertLegacyRowsPreserved,
  assertN4MigrationHistory,
  assertPlatformAuthorityRowsPreserved,
  assertPlatformCredentialsPreserved,
  assertPlatformSessionUpgrade,
  assertReviewedN4MigrationSet,
  buildN4UpgradePlan,
  parseN4AuthorityTapEvidence,
  runN4UpgradeQualification
} from "../../../../scripts/postgres/n4-upgrade-qualification.mjs";
import { loadSqlMigrations, migrationChecksum } from "../../src/postgres/migration-runner.mjs";

const SCRIPT_PATH = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../../../scripts/postgres/n4-upgrade-qualification.mjs");
const CI_PATH = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../../../.github/workflows/ci.yml");

function cleanAuthority() {
  return {
    platform_principals: [{ principal_id: "principal" }, { principal_id: "approver" }, { principal_id: "second-approver" }],
    platform_operator_assignments: [{ assignment_id: "assignment" }],
    platform_operator_assignment_approvals: [{ approval_id: "approval" }, { approval_id: "second-approval" }]
  };
}

function cleanLegacy() {
  return Object.fromEntries(N4_LEGACY_TABLE_SPECS.map(({ name }, index) => [
    name,
    Array.from({ length: name === "members" ? 3 : 1 }, (_, row) => ({ id: `${name}-${index}-${row}` }))
  ]));
}

function cleanCredentials() {
  return [{ credential_id: "credential", status: "active", version: 1 }];
}

function cleanSessions() {
  return [{
    session_id: "00000000-0000-4000-8000-000000000416",
    session_material_hash: "62".repeat(32),
    principal_id: "principal",
    member_id: "member",
    organization_id: "organization",
    assignment_id: "assignment",
    credential_id: "credential",
    operation: "platform.promotion.issue",
    capability: "platform.promotion.issue",
    principal_authority_generation: 1,
    assignment_version: 1,
    credential_version: 1,
    idle_timeout_seconds: 300,
    status: "active",
    version: 1,
    created_at: "2099-01-01T00:00:00.000Z",
    authenticated_at: "2099-01-01T00:00:00.000Z",
    last_seen_at: "2099-01-01T00:00:00.000Z",
    expires_at: "2099-01-01T00:15:00.000Z",
    revoked_at: null,
    revoke_reason: null
  }];
}

function upgradedSessions() {
  const session = cleanSessions()[0];
  return [{
    ...session,
    csrf_token_hash: crypto.createHash("sha256").update("agentpass:0054:csrf:00000000-0000-4000-8000-000000000416", "utf8").digest("hex"),
    request_digest_sha256: crypto.createHash("sha256").update("agentpass:0054:request:00000000-0000-4000-8000-000000000416", "utf8").digest("hex"),
    allowed_credential_ids: [Buffer.alloc(32, 0x61).toString("base64url")],
    status: "revoked",
    version: 2,
    revoked_at: "2099-01-01T00:00:02.000Z",
    revoke_reason: "request_binding_migration"
  }];
}

test("N4 authority TAP evidence is required, complete, and byte-digest bound", () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "agentpass-n4-tap-"));
  try {
    const writeTap = (bytes) => {
      const filePath = path.join(directory, "authority.tap");
      writeFileSync(filePath, bytes);
      return filePath;
    };
    const validTap = Buffer.from("TAP version 13\r\n1..2\r\nok 1 - migration\r\nok 2 - integration\r\n", "utf8");
    const evidence = parseN4AuthorityTapEvidence(writeTap(validTap));
    assert.equal(evidence.required, true);
    assert.equal(evidence.present, true);
    assert.equal(evidence.tests, 2);
    assert.equal(evidence.tap_sha256, crypto.createHash("sha256").update(validTap).digest("hex"));
    assert.notEqual(evidence.present, false);

    for (const invalidTap of [
      "TAP version 13\n1..1\nnot ok 1 - failed\n",
      "TAP version 13\n1..1\nok 1 - skipped # skip unavailable\n",
      "TAP version 13\n1..1\nok 1 - todo # todo later\n",
      "TAP version 13\n1..1\nok missing-number\n",
      "TAP version 13\n1..1\nok1 - missing separator\n",
      "TAP version 13\n1..1\nok 01 - malformed number\n",
      "TAP version 13\n1..2\nok 1 - first\nok 1 - duplicate\n",
      "TAP version 13\n1..2\nok 1 - first\nok 3 - wrong number\n",
      "TAP version 13\n1..2\nok 1 - only one\n"
    ]) {
      assert.throws(() => parseN4AuthorityTapEvidence(writeTap(Buffer.from(invalidTap, "utf8"))));
    }

    assert.throws(() => parseN4AuthorityTapEvidence(), /evidence is required/u);
    assert.throws(() => parseN4AuthorityTapEvidence(path.join(directory, "missing.tap")));
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("N4 qualification rejects missing authority TAP before opening a database", async () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "agentpass-n4-missing-tap-"));
  try {
    let factoryCalled = false;
    await assert.rejects(
      () => runN4UpgradeQualification({
        adminUrl: "postgresql://postgres:secret@db.example.test/agentpass?sslmode=verify-full",
        migrationUrl: "postgresql://agentpass_migrator:secret@db.example.test/agentpass?sslmode=verify-full",
        authorityTapPath: path.join(directory, "missing.tap"),
        databaseFactory: async () => {
          factoryCalled = true;
          throw new Error("database factory must not be reached");
        }
      }),
      /ENOENT/u
    );
    assert.equal(factoryCalled, false);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("N4 plan is exactly 53→54 and names the reviewed migration head", async () => {
  const migrations = await loadSqlMigrations();
  const plan = buildN4UpgradePlan(migrations);
  assert.equal(N4_SOURCE_VERSION, 53);
  assert.equal(N4_TARGET_VERSION, 54);
  assert.equal(N4_APPLICATION_VERSION, "n4-postgres-upgrade-qualification");
  assert.deepEqual(plan.map(({ startVersion, targetVersion }) => ({ startVersion, targetVersion })), [{ startVersion: 53, targetVersion: 54 }]);
  assert.equal(plan[0].bootstrap.at(-1).name, "0053_platform_sessions.sql");
  assert.equal(plan[0].upgrade.at(-1).name, N4_MIGRATION_NAME);
  assert.equal(plan[0].bootstrap.length, 53);
  assert.equal(plan[0].upgrade.length, 54);
  assert.ok(migrations.slice(0, 54).every(({ sql, checksum }) => migrationChecksum(sql) === checksum));
});

test("N4 reviewed migration set rejects missing, reordered, drifted, and wrong-headed history", async () => {
  const migrations = await loadSqlMigrations();
  assert.equal(assertReviewedN4MigrationSet(migrations), true);
  for (const mutate of [
    (value) => { value.splice(53, 1); },
    (value) => { value[52].version = 54; },
    (value) => { value[53].checksum = "0".repeat(64); },
    (value) => { value[53].name = "0054_unreviewed.sql"; }
  ]) {
    const candidate = structuredClone(migrations);
    mutate(candidate);
    assert.throws(() => assertReviewedN4MigrationSet(candidate));
  }
});

test("N4 history validator proves exact upgrade, legacy preservation, credential preservation, and session invalidation", async () => {
  const migrations = await loadSqlMigrations();
  const rows = migrations.slice(0, 54).map(({ version, checksum }) => ({ version, checksum }));
  const authority = cleanAuthority();
  const legacy = cleanLegacy();
  const credentials = cleanCredentials();
  const sessions = cleanSessions();
  const result = assertN4MigrationHistory({
    rows,
    migrations,
    upgrade: { applied: [migrations[53]] },
    status: { currentVersion: 54, pending: [], modified: [], dirty: false, dirtyRows: [], applied: rows },
    identity: { session_user: "agentpass_migrator", current_user: "agentpass_migrator" },
    authorityBefore: authority,
    authorityAfter: structuredClone(authority),
    credentialsBefore: credentials,
    credentialsAfter: structuredClone(credentials),
    sessionsBefore: sessions,
    sessionsAfter: upgradedSessions(),
    legacyBefore: legacy,
    legacyAfter: structuredClone(legacy)
  });
  assert.equal(result.status, "clean");
  assert.deepEqual(result.appliedUpgradeVersions, [54]);
  assert.equal(result.history.length, 54);
  assert.equal(result.seeded_legacy_row_count, 6);
  assert.equal(result.seeded_platform_credential_row_count, 1);
  assert.equal(result.seeded_platform_session_row_count, 1);
  assert.equal(result.platform_authority_preservation.exact, true);
  assert.equal(result.platform_credential_preservation.exact, true);
  assert.equal(result.platform_session_upgrade.immutable_binding_exact, true);
  assert.equal(result.platform_session_upgrade.invalidated_for_request_binding, true);
  assert.equal(result.legacy_preservation.exact, true);
});

test("N4 validators reject history, identity, preservation, and invalid session transitions", async () => {
  const migrations = await loadSqlMigrations();
  const rows = migrations.slice(0, 54).map(({ version, checksum }) => ({ version, checksum }));
  const authority = cleanAuthority();
  const legacy = cleanLegacy();
  const credentials = cleanCredentials();
  const sessions = cleanSessions();
  const base = {
    rows,
    migrations,
    upgrade: { applied: [migrations[53]] },
    status: { currentVersion: 54, pending: [], modified: [], dirty: false, dirtyRows: [], applied: rows },
    identity: { session_user: "agentpass_migrator", current_user: "agentpass_migrator" },
    authorityBefore: authority,
    authorityAfter: structuredClone(authority),
    credentialsBefore: credentials,
    credentialsAfter: structuredClone(credentials),
    sessionsBefore: sessions,
    sessionsAfter: upgradedSessions(),
    legacyBefore: legacy,
    legacyAfter: structuredClone(legacy)
  };
  for (const mutate of [
    (value) => { value.startVersion = 52; },
    (value) => { value.targetVersion = 53; },
    (value) => { value.rows[53].checksum = "0".repeat(64); },
    (value) => { value.upgrade.applied = []; },
    (value) => { value.status.pending = [54]; },
    (value) => { value.identity.current_user = "postgres"; },
    (value) => { value.authorityAfter.platform_principals[0].principal_id = "changed"; },
    (value) => { value.credentialsAfter[0].status = "revoked"; },
    (value) => { value.sessionsAfter[0].status = "active"; },
    (value) => { value.legacyAfter.members[0].id = "changed"; }
  ]) {
    const candidate = structuredClone(base);
    mutate(candidate);
    assert.throws(() => assertN4MigrationHistory(candidate));
  }
  assert.throws(() => assertLegacyRowsPreserved(legacy, { ...legacy, members: [{ id: "changed" }] }));
  assert.throws(() => assertPlatformAuthorityRowsPreserved(authority, { ...authority, platform_principals: [] }));
  assert.throws(() => assertPlatformCredentialsPreserved(credentials, [{ status: "revoked" }]));
  assert.throws(() => assertPlatformSessionUpgrade(sessions, [{ ...upgradedSessions()[0], allowed_credential_ids: [] }]));
});

test("N4 qualification owns its seed set, authority evidence, and direct CI aggregation contract", async () => {
  const source = await readFile(SCRIPT_PATH, "utf8");
  assert.match(source, /createMigrationRunner/u);
  assert.match(source, /loadSqlMigrations/u);
  assert.match(source, /createDisposablePostgres/u);
  assert.match(source, /agentpass_migrator/u);
  assert.match(source, /0053_platform_sessions\.sql/u);
  assert.match(source, /0054_platform_authorization\.sql/u);
  assert.match(source, /platform_credential_provision/u);
  assert.match(source, /platform_principal_provision/u);
  assert.match(source, /platform_operator_assignment_request/u);
  assert.match(source, /INSERT INTO platform_sessions/u);
  assert.match(source, /WITH db_now AS MATERIALIZED/u);
  assert.match(source, /created_at, authenticated_at, last_seen_at/u);
  assert.match(source, /platform_sessions/u);
  assert.match(source, /platform_credentials/u);
  assert.match(source, /platform_authorization/u);
  assert.match(source, /parseN4AuthorityTapEvidence/u);
  assert.doesNotMatch(source, /\.github\/workflows/u);
  const ci = `${await readFile(CI_PATH, "utf8")}\n${await readFile(new URL("../../../../.github/actions/postgres-authority-qualification/action.yml", import.meta.url), "utf8")}`;
  assert.match(ci, /qualification-n4-upgrade\.json/u);
  assert.match(ci, /qualification-0054\.tap/u);
  assert.match(ci, /n4UpgradeReport/u);
  for (const file of N4_AUTHORITY_TEST_FILES) assert.match(ci, new RegExp(file.replaceAll("/", "\\/"), "u"));
});

test("N4 qualification rejects non-TLS, non-admin, or non-migrator DSNs before opening a database", async () => {
  const databaseFactory = async () => { throw new Error("database factory must not be reached"); };
  await assert.rejects(
    () => runN4UpgradeQualification({
      adminUrl: "postgresql://postgres:secret@db.example.test/agentpass",
      migrationUrl: "postgresql://agentpass_migrator:secret@db.example.test/agentpass?sslmode=verify-full",
      databaseFactory
    }),
    /authenticated PostgreSQL TLS/u
  );
  await assert.rejects(
    () => runN4UpgradeQualification({
      adminUrl: "postgresql://postgres:secret@db.example.test/agentpass?sslmode=verify-full",
      migrationUrl: "postgresql://agentpass_app:secret@db.example.test/agentpass?sslmode=verify-full",
      databaseFactory
    }),
    /must use agentpass_migrator/u
  );
  await assert.rejects(
    () => runN4UpgradeQualification({
      adminUrl: "postgresql://agentpass_migrator:secret@db.example.test/agentpass?sslmode=verify-full",
      migrationUrl: "postgresql://agentpass_migrator:secret@db.example.test/agentpass?sslmode=verify-full",
      databaseFactory
    }),
    /must not use agentpass_migrator/u
  );
});
