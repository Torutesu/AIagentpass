import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { parse } from "yaml";

const root = path.resolve(import.meta.dirname, "..");
const ciPath = path.join(root, ".github/workflows/ci.yml");
const releasePath = path.join(root, ".github/workflows/release-candidate.yml");
const ciSource = fs.readFileSync(ciPath, "utf8");
const releaseSource = fs.readFileSync(releasePath, "utf8");
const lanes = ["postgres-authority-16", "postgres-authority-17", "postgres-integration", "browser-e2e", "p0b-live-process", "test"];

function parseUnique(source) {
  return parse(source, { uniqueKeys: true });
}

function assertSixLaneContract(source, label) {
  const workflow = parseUnique(source);
  assert.ok(workflow?.jobs, `${label} jobs are required`);
  assert.deepEqual(Object.keys(workflow.jobs).filter((name) => lanes.includes(name)).sort(), [...lanes].sort(), `${label} must expose exactly the canonical six lanes`);
  for (const lane of lanes) {
    const job = workflow.jobs[lane];
    assert.ok(Array.isArray(job.steps) && job.steps.length > 0, `${lane} must have steps`);
    assert.ok(job.steps.some((step) => typeof step.uses === "string" && /^actions\/checkout@[0-9a-f]{40}$/u.test(step.uses)), `${lane} must checkout an immutable SHA`);
  }
}

test("canonical CI exposes exactly six source-bound qualification lanes", () => {
  assertSixLaneContract(ciSource, "CI");
  assert.match(ciSource, /github\.sha/u);
  assert.match(ciSource, /git rev-parse "\$\{GITHUB_SHA\}\^\{tree\}"/u);
  assert.match(ciSource, /upload-artifact/u);
  const ciWorkflow = parseUnique(ciSource);
  for (const major of [16, 17]) {
    const authority = ciWorkflow.jobs[`postgres-authority-${major}`];
    assert.equal(authority.services?.postgres?.image, `postgres:${major}`);
    const commands = JSON.stringify(authority);
    assert.match(commands, /openssl req -x509 -newkey rsa:3072/u);
    assert.match(commands, /docker cp .*server\.crt/u);
    assert.match(commands, /hostnossl all all all reject/u);
    assert.match(commands, /PGSSLMODE=verify-full/u);
    assert.match(commands, /PGSSLMODE=disable/u);
    assert.match(commands, /sslmode=verify-full/u);
    assert.match(commands, /set -euo pipefail[\s\S]*pg_dump[\s\S]*pg_restore[\s\S]*pg_basebackup/u);
    assert.match(commands, /archive_mode = 'on'[\s\S]*archive_command/u);
    assert.match(commands, /recovery\.signal/u);
    assert.match(commands, /restore_command=cp/u);
    assert.match(commands, /docker run --detach[\s\S]*recovery_target_time/u);
    assert.match(commands, /agentpass-backup-pitr-execution-result[\s\S]*real_execution: true/u);
    assert.match(commands, /backup-pitr-evidence\.mjs build[\s\S]*backup-pitr-evidence\.mjs verify/u);
    assert.ok(commands.includes('"AGENTPASS_C3_BACKUP_PITR_EVIDENCE":"${{ github.workspace }}/backup-pitr-evidence/postgres-' + major + '.json"'));
  }
  const browserJob = parseUnique(ciSource).jobs["browser-e2e"];
  assert.ok(browserJob.steps.some((step) => typeof step.run === "string" && /ci-preflight\.mjs browser-e2e/u.test(step.run)), "browser E2E evidence must be source/run bound before upload");
  assert.equal(browserJob.steps.find((step) => typeof step.uses === "string" && step.uses.startsWith("actions/upload-artifact@"))?.if, "success()", "browser E2E artifacts must upload only after evidence verification");
});

test("release candidate binds exact CI run, source tree, terminal results, and artifact inventory", () => {
  parseUnique(releaseSource);
  assert.match(releaseSource, /Verify exact six-lane CI run before protected signing/u);
  assert.match(releaseSource, /ci-preflight\.mjs github/u);
  assert.match(releaseSource, /AGENTPASS_VERIFIED_COMMIT/u);
  assert.match(releaseSource, /git rev-parse.*\^\{tree\}/u);
  assert.match(releaseSource, /ci-preflight\.mjs github[\s\\]*/u);
  assert.match(releaseSource, /source-binding|github-commit/u);
  assert.match(releaseSource, /artifact-scan/u);
  assert.doesNotMatch(releaseSource, /not_proven/u);
  const uses = [...releaseSource.matchAll(/uses:\s*([^\s]+)/gu)].map(([, value]) => value);
  assert.ok(uses.length > 0);
  for (const use of uses) assert.match(use, /^actions\/(?:checkout|setup-node|upload-artifact|download-artifact)@[0-9a-f]{40}$/u);
});

test("lane deletion is detected by the contract test", () => {
  const withoutLane = ciSource.replace(/\n  postgres-authority-17:\n[\s\S]*?(?=\n  postgres-integration:)/u, "\n");
  assert.throws(() => assertSixLaneContract(withoutLane, "mutated CI"), /canonical six lanes/u);
});

test("lane substitution is detected by the contract test", () => {
  const substituted = ciSource.replace("  p0b-live-process:\n", "  p0b-live-process-renamed:\n");
  assert.throws(() => assertSixLaneContract(substituted, "mutated CI"), /canonical six lanes/u);
});

test("authority lanes keep TLS, PITR, evidence, and cleanup boundaries intact", () => {
  const ciWorkflow = parseUnique(ciSource);
  for (const major of [16, 17]) {
    const job = ciWorkflow.jobs[`postgres-authority-${major}`];
    const steps = job.steps;
    const names = steps.map((step) => step.name ?? "");
    const indexOf = (name) => {
      const index = names.indexOf(name);
      assert.notEqual(index, -1, `missing ${name}`);
      return index;
    };
    const configure = indexOf(`Configure PostgreSQL ${major} TLS and reject plaintext connections`);
    const assertDatabase = indexOf(`Assert PostgreSQL ${major} C3 database is connected to major ${major}`);
    const backup = indexOf(`Run real PostgreSQL ${major} backup restore and PITR qualification`);
    const backupScan = indexOf(`Scan PostgreSQL ${major} backup and PITR evidence for secrets and unsafe entries`);
    const c3 = indexOf(`Run real PostgreSQL ${major} C3 platform promotion qualification`);
    const c3Scan = indexOf(`Scan PostgreSQL ${major} C3 evidence for secrets and unsafe entries`);
    const upload = indexOf(`Retain verified redacted PostgreSQL ${major} C3 evidence`);
    const cleanup = indexOf(`Cleanup PostgreSQL ${major} authority state and secret material`);
    assert.ok(configure < assertDatabase && assertDatabase < backup && backup < backupScan && backupScan < c3 && c3 < c3Scan && c3Scan < upload && upload < cleanup);
    assert.match(JSON.stringify(steps[configure]), /ssl_min_protocol_version[\s\S]*TLSv1\.2/u);
    assert.match(JSON.stringify(steps[configure]), /hostnossl all all all reject/u);
    assert.match(JSON.stringify(steps[assertDatabase]), /PGSSLMODE=disable/u);
    assert.match(JSON.stringify(steps[backup]), /recovery\.signal[\s\S]*restore_command=cp[\s\S]*recovery_target_time/u);
    assert.match(steps[backupScan].run, /archive-secret-scan\.mjs[\s\S]*backup-pitr-evidence/u);
    assert.equal(steps[upload].if, "success()");
    assert.equal(steps[cleanup].if, "always()");
    assert.match(steps[cleanup].run, /docker rm --force[\s\S]*DROP DATABASE IF EXISTS[\s\S]*rm -rf --/u);
  }
});
