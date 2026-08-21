import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { parse } from "yaml";

const root = path.resolve(import.meta.dirname, "..");
const workflow = fs.readFileSync(path.join(root, ".github", "workflows", "ci.yml"), "utf8");
const packageManifest = JSON.parse(fs.readFileSync(path.join(root, "package.json"), "utf8"));
const parsedWorkflow = parse(workflow, { uniqueKeys: true });

function job(name) {
  const start = workflow.indexOf(`  ${name}:`);
  assert.notEqual(start, -1, `missing CI job ${name}`);
  const rest = workflow.slice(start + 1);
  const next = rest.search(/^  [A-Za-z0-9_-]+:/m);
  return workflow.slice(start, next === -1 ? workflow.length : start + 1 + next);
}

test("published package retains the W1.6 operational policy and evidence gates", () => {
  assert.ok(packageManifest.files.includes("ops"));
  assert.ok(packageManifest.files.includes("scripts/owner-recovery"));
});

test("main CI validates the machine-readable contract inventory before product tests", () => {
  const section = job("test");
  const install = section.indexOf("- run: npm ci");
  const consoleInstall = section.indexOf("- run: npm ci --prefix apps/web-console");
  const contracts = section.indexOf("- run: npm run contracts:validate");
  const platformContracts = section.indexOf("- run: npm run contracts:validate:platform");
  const identityBootstrapContracts = section.indexOf("- run: npm run contracts:validate:hosted-identity-bootstrap");
  const w16 = section.indexOf("- run: npm run test:w16");
  const nodeTests = section.indexOf("- run: npm test");
  assert.ok(install >= 0 && consoleInstall > install && contracts > consoleInstall && platformContracts > contracts && identityBootstrapContracts > platformContracts && w16 > identityBootstrapContracts && nodeTests > w16);
  assert.equal(section.match(/^\s*- run: npm run contracts:validate$/gmu)?.length, 1);
  assert.equal(section.match(/^\s*- run: npm run contracts:validate:platform$/gmu)?.length, 1);
  assert.equal(section.match(/^\s*- run: npm run contracts:validate:hosted-identity-bootstrap$/gmu)?.length, 1);
  assert.equal(section.match(/npm run test:w16/g)?.length, 1);
});

test("the standard test command includes qualification evidence contracts", () => {
  assert.match(packageManifest.scripts.test, /scripts\/qualification\/\*\.test\.mjs/u);
});

test("native qualification is serialized at the top level", () => {
  const section = job("test");
  assert.equal(
    packageManifest.scripts["test:native"],
    "node scripts/ci/run-native-test-shards.mjs",
  );
  assert.match(section, /runs-on: macos-latest\n    timeout-minutes: 60/u);
  for (const [name, minutes, command] of [
    ["Run bounded native unit tests", 30, "npm run test:native"],
    ["Run bounded native app bundle tests", 10, "npm run test:native-app"],
    ["Run bounded installer preservation tests", 5, "npm run test:native-installer-preservation"],
    ["Run bounded native durability model", 10, "npm run test:native-durability-model"],
  ]) {
    assert.match(section, new RegExp(`- name: ${name}\\n        timeout-minutes: ${minutes}\\n[\\s\\S]*?run: ${command}(?:\\n|$)`, "u"));
  }
  assert.match(section, /NATIVE_TEST_TIMEOUT_MS: 1500000/u);
});

test("canonical PostgreSQL integration keeps its independent integration and role lanes", () => {
  const section = job("postgres-integration");
  assert.match(section, /createdb --host=127\.0\.0\.1 --port=5433 --username=postgres agentpass_roles/u);
  assert.match(section, /least-privilege-role\.integration\.test\.mjs/u);
  assert.doesNotMatch(section, /c3-migration-0047-(?:qualification|adversarial)\.test\.mjs/u);
});

test("PostgreSQL 16 and 17 authority lanes each own exactly one isolated C3 qualification", () => {
  for (const major of [16, 17]) {
    const section = job(`postgres-authority-${major}`);
    assert.match(section, new RegExp(`image: postgres:${major}\\n`, "u"));
    assert.match(section, new RegExp(`Configure PostgreSQL ${major} TLS and reject plaintext connections`, "u"));
    assert.match(section, /openssl req -x509 -newkey rsa:3072/u);
    assert.match(section, /subjectAltName = IP:127\.0\.0\.1,DNS:localhost/u);
    assert.match(section, /docker cp .*server\.crt/u);
    assert.match(section, /ALTER SYSTEM SET ssl = 'on'/u);
    assert.match(section, /hostnossl all all all reject/u);
    assert.match(section, /docker restart/u);
    assert.match(section, new RegExp(`createdb --host=127\\.0\\.0\\.1 --port=5432 --username=postgres agentpass_c3_${major}`, "u"));
    assert.match(section, new RegExp(`PGSSLMODE: verify-full[\\s\\S]*PGSSLROOTCERT: .*agentpass-postgres-tls-${major}/ca\\.crt`, "u"));
    assert.match(section, new RegExp(`AGENTPASS_TEST_DATABASE_URL: postgresql://postgres:.*@127\\.0\\.0\\.1:5432/agentpass_c3_${major}\\?sslmode=verify-full`, "u"));
    assert.match(section, new RegExp(`AGENTPASS_C3_CA_CERT_FILE: .*agentpass-postgres-tls-${major}/ca\\.crt`, "u"));
    assert.equal((section.match(/c3-migration-0047-qualification\.test\.mjs/gu) ?? []).length, 1);
    assert.equal((section.match(/c3-migration-0047-adversarial\.test\.mjs/gu) ?? []).length, 1);
    assert.match(section, new RegExp(`AGENTPASS_C3_EXPECTED_POSTGRES_MAJOR: "${major}"`, "u"));
    assert.match(section, /AGENTPASS_C3_CI_JOB_ID: \$\{\{ github\.job \}\}/u);
    assert.match(section, /git rev-parse "\$\{GITHUB_SHA\}\^\{tree\}"/u);
    assert.match(section, /GITHUB_RUN_ID/iu);
    assert.match(section, /GITHUB_RUN_ATTEMPT/iu);
    assert.match(section, new RegExp(`--dbname=agentpass_c3_${major}[\\s\\S]*SHOW server_version_major[\\s\\S]*= ${major}`, "u"));
    assert.match(section, /PGSSLMODE=verify-full PGSSLROOTCERT=.*psql/u);
    assert.match(section, /PGSSLMODE=disable psql/u);
    assert.match(section, /set -euo pipefail[\s\S]*pg_dump[\s\S]*pg_restore[\s\S]*pg_basebackup/u);
    assert.match(section, /archive_mode = 'on'[\s\S]*archive_command/u);
    assert.match(section, /recovery\.signal/u);
    assert.match(section, /restore_command=cp/u);
    assert.match(section, /docker run --detach[\s\S]*recovery_target_time/u);
    assert.match(section, /kind: "agentpass-backup-pitr-execution-result"[\s\S]*real_execution: true/u);
    assert.match(section, /backup-pitr-evidence\.mjs build[\s\S]*backup-pitr-evidence\.mjs verify/u);
    assert.ok(section.includes("AGENTPASS_C3_BACKUP_PITR_EVIDENCE: ${{ github.workspace }}/backup-pitr-evidence/postgres-" + major + ".json"));
    assert.match(section, new RegExp(`\\$GITHUB_JOB" "${major}`, "u"));
    assert.match(section, new RegExp(`path: c3-migration-0047-evidence/postgres-${major}\\.json`, "u"));
    assert.match(section, new RegExp(`NODE_EXTRA_CA_CERTS: .*agentpass-postgres-tls-${major}/ca\\.crt`, "u"));
    assert.match(section, /if-no-files-found: error/u);
  }
  assert.equal((workflow.match(/c3-migration-0047-qualification\.test\.mjs/gu) ?? []).length, 2);
  assert.equal((workflow.match(/actions\/upload-artifact@[0-9a-f]{40}[\s\S]*?path: c3-migration-0047-evidence\/postgres-(?:16|17)\.json/gu) ?? []).length, 2);
});

test("authority lanes scan every generated evidence input and clean disposable state on every exit", () => {
  for (const major of [16, 17]) {
    const authority = parsedWorkflow.jobs[`postgres-authority-${major}`];
    const steps = authority.steps;
    const indexOf = (name) => {
      const index = steps.findIndex((step) => step.name === name);
      assert.notEqual(index, -1, `missing ${name} in PostgreSQL ${major} authority lane`);
      return index;
    };
    const backup = indexOf(`Run real PostgreSQL ${major} backup restore and PITR qualification`);
    const backupScan = indexOf(`Scan PostgreSQL ${major} backup and PITR evidence for secrets and unsafe entries`);
    const qualification = indexOf(`Run real PostgreSQL ${major} C3 platform promotion qualification`);
    const c3Verify = indexOf(`Independently verify PostgreSQL ${major} C3 evidence binding`);
    const c3Scan = indexOf(`Scan PostgreSQL ${major} C3 evidence for secrets and unsafe entries`);
    const upload = indexOf(`Retain verified redacted PostgreSQL ${major} C3 evidence`);
    const cleanup = indexOf(`Cleanup PostgreSQL ${major} authority state and secret material`);

    assert.ok(backup < backupScan && backupScan < qualification, "PITR evidence must be scanned before C3 consumes it");
    assert.ok(qualification < c3Verify && c3Verify < c3Scan && c3Scan < upload && upload < cleanup, "C3 evidence must be verified and scanned before upload, then cleaned");
    assert.match(steps[backupScan].run, /archive-secret-scan\.mjs[\s\S]*backup-pitr-evidence/u);
    assert.equal(steps[upload].if, "success()", "evidence upload must be success-only");
    assert.equal(steps[cleanup].if, "always()", "cleanup must run after failed or cancelled qualification");
    assert.match(steps[cleanup].run, /docker rm --force[\s\S]*AGENTPASS_PITR_CONTAINER/u);
    assert.match(steps[cleanup].run, /DROP DATABASE IF EXISTS[\s\S]*WITH \(FORCE\)/u);
    assert.match(steps[cleanup].run, /rm -rf --[\s\S]*AGENTPASS_C3_TLS_DIR[\s\S]*AGENTPASS_BACKUP_PITR_DIRECTORY[\s\S]*backup-pitr-evidence[\s\S]*c3-migration-0047-evidence/u);
    assert.match(steps[cleanup].env.AGENTPASS_PITR_CONTAINER, new RegExp(`^agentpass-pitr-${major}-\\$\\{\\{ github\\.run_id \\}\\}-\\$\\{\\{ github\\.run_attempt \\}\\}$`, "u"));
    assert.match(steps[cleanup].env.AGENTPASS_C3_TLS_DIR, new RegExp(`agentpass-postgres-tls-${major}$`, "u"));
  }
});
