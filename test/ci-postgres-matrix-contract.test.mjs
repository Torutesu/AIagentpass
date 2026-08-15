import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";

const root = path.resolve(import.meta.dirname, "..");
const workflow = fs.readFileSync(path.join(root, ".github", "workflows", "ci.yml"), "utf8");

function job(name) {
  const start = workflow.indexOf(`  ${name}:`);
  assert.notEqual(start, -1, `missing CI job ${name}`);
  const rest = workflow.slice(start + 1);
  const next = rest.search(/^  [A-Za-z0-9_-]+:/m);
  return workflow.slice(start, next === -1 ? workflow.length : start + 1 + next);
}

test("authority qualification runs an isolated PostgreSQL 16/17 matrix with a fresh current-head database", () => {
  const section = job("postgres-authority-matrix");
  assert.match(section, /strategy:\n      fail-fast: false\n      matrix:\n        postgres-version: \["16", "17"\]/u);
  assert.match(section, /timeout-minutes: 30/u);
  assert.match(section, /docker run --detach --name "\$N1_CONTAINER_NAME"[\s\S]*?"postgres:\$\{POSTGRES_MAJOR\}"/u);
  assert.match(section, /assert\.equal\(preflight\.rows\[0\]\.schema_migrations, null, "N1 requires a fresh database"\)/u);
  assert.match(section, /assert\.equal\(result\.currentVersion, POSTGRES_SCHEMA_HEAD\.version\)/u);
  assert.match(section, /assert\.equal\(history\.rowCount, POSTGRES_SCHEMA_HEAD\.migration_count\)/u);
  assert.match(section, /Array\.from\(\{ length: POSTGRES_SCHEMA_HEAD\.migration_count \}/u);
  assert.match(section, /FROM pg_stat_ssl WHERE pid = pg_backend_pid\(\)/u);
  assert.match(section, /assert\.equal\(server\.rows\[0\]\.ssl, true/u);
  assert.match(section, /migration-history\.json/u);
  assert.match(section, /postgres-server\.json/u);
  assert.match(section, /docker inspect --format '\{\{\.Image\}\}'/u);
  assert.match(section, /postgres_image_id: process\.env\.N1_POSTGRES_IMAGE_ID/u);
});

test("N1 bootstraps roles, migrates as the actual migrator login, then reconciles and checks privileges", () => {
  const section = job("postgres-authority-matrix");
  const bootstrap = section.indexOf("Bootstrap database roles before migrations");
  const authentication = section.indexOf("Provision ephemeral CI role authentication");
  const migration = section.indexOf("Run fresh migrations through current head");
  const roles = section.indexOf("Reconcile database roles after migrations");
  const checker = section.indexOf("Run PostgreSQL privilege checker");
  const logins = section.indexOf("Verify actual service-role login boundaries");
  assert.ok(bootstrap >= 0 && authentication > bootstrap && migration > authentication && roles > migration && checker > roles && logins > checker);
  assert.match(section, /--file scripts\/postgres\/roles\.sql/u);
  assert.match(section, /N1_DATABASE_URL="\$N1_MIGRATION_DATABASE_URL"/u);
  assert.match(section, /scripts\/postgres\/role-privilege-check\.mjs/u);
  assert.match(section, /AGENTPASS_PRIVILEGE_EVIDENCE_OUTPUT="\$N1_EVIDENCE_DIR\/privilege-matrix\.json"/u);
  assert.match(section, /N1_PRIVILEGE_DATABASE_URL=.*sslmode=verify-full/u);
  assert.match(section, /PGSSLROOTCERT="\$N1_PGSSLROOTCERT"/u);
  assert.match(section, /N1_DATABASE_URL=.*sslmode=verify-full/u);
  assert.match(section, /N1_ADMIN_DATABASE_URL=.*sslmode=verify-full/u);
  assert.match(section, /N1_APP_DATABASE_URL=.*agentpass_app.*sslmode=verify-full/u);
  assert.match(section, /N1_SIGNER_DATABASE_URL=.*agentpass_signer.*sslmode=verify-full/u);
  assert.match(section, /N1_MIGRATION_DATABASE_URL=.*agentpass_migrator.*sslmode=verify-full/u);
  assert.match(section, /N1_BACKUP_DATABASE_URL=.*agentpass_backup.*sslmode=verify-full/u);
  assert.match(section, /NODE_EXTRA_CA_CERTS=.*server\.crt/u);
  assert.match(section, /role-login-boundaries\.json/u);
  assert.match(section, /assert\.equal\(principal\.rows\[0\]\.session_user, expected\)/u);
  assert.match(section, /role_logins: \{ ok: true, evidence_sha256: sha256\(roleLoginOutput\) \}/u);
});

test("N1 runs both seeded upgrade paths on every PostgreSQL matrix member", () => {
  const section = job("postgres-authority-matrix");
  assert.match(section, /scripts\/postgres\/n1-upgrade-qualification\.mjs/u);
  assert.match(section, /AGENTPASS_N1_POSTGRES_ADMIN_URL="\$N1_ADMIN_DATABASE_URL"/u);
  assert.match(section, /AGENTPASS_N1_POSTGRES_MIGRATION_URL="\$N1_MIGRATION_DATABASE_URL"/u);
  assert.match(section, /\[\[47, 51\], \[48, 51\]\]/u);
  assert.match(section, /qualification-upgrades\.json/u);
});

test("N2 runs a seeded 51-to-52 upgrade with exact legacy-row preservation", () => {
  const section = job("postgres-authority-matrix");
  assert.match(section, /scripts\/postgres\/n2-upgrade-qualification\.mjs/u);
  assert.match(section, /AGENTPASS_N2_POSTGRES_ADMIN_URL="\$N1_ADMIN_DATABASE_URL"/u);
  assert.match(section, /AGENTPASS_N2_POSTGRES_MIGRATION_URL="\$N1_MIGRATION_DATABASE_URL"/u);
  assert.match(section, /seeded_legacy_row_count, 4/u);
  assert.match(section, /legacy_preservation\.exact, true/u);
  assert.match(section, /\[\[51, 52\]\]/u);
  assert.match(section, /qualification-n2-upgrade\.json/u);
});

test("N3 runs a seeded 52-to-53 upgrade preserving authority without implicit sessions", () => {
  const section = job("postgres-authority-matrix");
  assert.match(section, /scripts\/postgres\/n3-upgrade-qualification\.mjs/u);
  assert.match(section, /AGENTPASS_N3_POSTGRES_ADMIN_URL="\$N1_ADMIN_DATABASE_URL"/u);
  assert.match(section, /AGENTPASS_N3_POSTGRES_MIGRATION_URL="\$N1_MIGRATION_DATABASE_URL"/u);
  assert.match(section, /seeded_platform_authority_row_count, 4/u);
  assert.match(section, /platform_authority_preservation\.exact, true/u);
  assert.match(section, /\[\[52, 53\]\]/u);
  assert.match(section, /qualification-n3-upgrade\.json/u);
});

test("authority matrix executes the 0048-0055 qualification set and rejects unexpected skips", () => {
  const section = job("postgres-authority-matrix");
  for (const required of [
    "platform-promotion-authority-boundary-migration.test.mjs",
    "platform-promotion-authority-qualification.integration.test.mjs",
    "provider-operation-repository.test.mjs",
    "provider-operation-repository.integration.test.mjs",
    "provider-operation-query-indexes.integration.test.mjs",
    "provider-operation-maintenance-repository.test.mjs",
    "managed-signer-authority-boundary-migration.test.mjs",
    "managed-signer-lifecycle-signing-authority-migration.test.mjs",
    "least-privilege-role.integration.test.mjs",
    "managed-signer-key-lifecycle-repository.integration.test.mjs",
    "managed-signer-lifecycle-signing-authority.integration.test.mjs",
    "platform-operator-authority-migration.test.mjs",
    "platform-operator-authority.integration.test.mjs",
    "platform-operator-assignment-repository.test.mjs",
    "platform-operator-authorizer.test.mjs",
    "platform-session-authority-migration.test.mjs",
    "platform-session-contract.test.mjs",
    "platform-authorization-migration.test.mjs",
    "platform-authorization.integration.test.mjs",
    "platform-session-bootstrap-migration.test.mjs",
    "platform-session-bootstrap-repository.test.mjs",
    "platform-session-bootstrap.integration.test.mjs",
  ]) assert.match(section, new RegExp(required.replaceAll(".", "\\."), "u"));
  assert.match(section, /node --test --test-concurrency=1 --test-reporter=tap/u);
  assert.match(section, /AGENTPASS_TEST_POSTGRES_CA_FILE="\$N1_PGSSLROOTCERT"/u);
  assert.match(section, /run_qualification 0053/u);
  assert.match(section, /run_qualification 0054/u);
  assert.match(section, /run_qualification 0055/u);
  assert.match(section, /# \(SKIP\|TODO\)/u);
  assert.match(section, /\^Bail out!/u);
  assert.match(section, /unexpected incomplete qualification/u);
  assert.match(section, /if \[\[ "\$N1_POSTGRES_MAJOR" == "17" \]\]/u);
  assert.match(section, /grep -Eq '\^1\\\.\[1-9\]\[0-9\]\*\$'/u);
});

test("N1 evidence is source-SHA-bound and uploaded with a fail-closed artifact contract", () => {
  const section = job("postgres-authority-matrix");
  assert.match(section, /source_commit: sourceCommit/u);
  assert.match(section, /migration_head: POSTGRES_SCHEMA_HEAD\.version/u);
  assert.match(section, /--argjson migration_head/u);
  assert.match(section, /\.migration_head == \$migration_head/u);
  assert.match(section, /roles_applied_after_migrations: true/u);
  assert.match(section, /unexpected_skips: 0/u);
  assert.match(section, /seeded_upgrades:/u);
  assert.match(section, /n1_report_sha256: sha256\(upgradeOutput\)/u);
  assert.match(section, /n2_report_sha256: sha256\(n2UpgradeOutput\)/u);
  assert.match(section, /n3_report_sha256: sha256\(n3UpgradeOutput\)/u);
  assert.match(section, /n4_report_sha256: sha256\(n4UpgradeOutput\)/u);
  assert.match(section, /n5_report_sha256: sha256\(n5UpgradeOutput\)/u);
  assert.match(section, /\[\[47, 51\], \[48, 51\], \[51, 52\], \[52, 53\], \[53, 54\], \[54, 55\]\]/u);
  assert.match(section, /migration_history_sha256: sha256\(migrationHistoryOutput\)/u);
  assert.match(section, /postgres_server:/u);
  assert.match(section, /Independently verify source-SHA-bound N1 evidence/u);
  assert.match(section, /jq -e[\s\\\S]*\.source_commit == \$source/u);
  assert.match(section, /name: postgres-n1-\$\{\{ matrix\.postgres-version \}\}-\$\{\{ github\.sha \}\}/u);
  assert.match(section, /if-no-files-found: error/u);
  assert.match(section, /agentpass-n1-evidence-\$\{\{ github\.run_id \}\}[^\n]+\/\n/u);
  assert.match(section, /uses: actions\/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02/u);
  assert.doesNotMatch(section, /continue-on-error:\s*true/u);
});
