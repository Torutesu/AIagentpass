import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { parse } from "yaml";

const root = path.resolve(import.meta.dirname, "..");
const workflowText = fs.readFileSync(path.join(root, ".github", "workflows", "ci.yml"), "utf8");
const authorityActionText = fs.readFileSync(path.join(root, ".github", "actions", "postgres-authority-qualification", "action.yml"), "utf8");
const workflow = parse(workflowText, { uniqueKeys: true });
const packageManifest = JSON.parse(fs.readFileSync(path.join(root, "package.json"), "utf8"));

function job(name) {
  const value = workflow.jobs[name];
  assert.ok(value, `missing CI job ${name}`);
  return value["<<"] ? { ...value["<<"], ...value, steps: value.steps ?? value["<<"].steps } : value;
}

test("published package retains the W1.6 operational policy and evidence gates", () => {
  assert.ok(packageManifest.files.includes("ops"));
  assert.ok(packageManifest.files.includes("scripts/owner-recovery"));
});

test("main CI validates contracts before the standard test command", () => {
  const source = workflowText;
  assert.ok(source.indexOf("npm run contracts:validate") < source.indexOf("npm test"));
  assert.equal((source.match(/npm run contracts:validate/g) ?? []).length >= 1, true);
  assert.match(packageManifest.scripts.test, /scripts\/qualification\/\*\.test\.mjs/u);
});

test("native qualification remains serialized with bounded commands", () => {
  const value = job("test");
  assert.equal(packageManifest.scripts["test:native"], "node scripts/ci/run-native-test-shards.mjs");
  assert.match(JSON.stringify(value), /test:native|test-native|NATIVE_TEST_TIMEOUT_MS/u);
});

test("PostgreSQL authority jobs are independent, TLS-bound, and cleaned up", () => {
  for (const major of ["16", "17"]) {
    const value = job(`postgres-authority-${major}`);
    assert.deepEqual(value.strategy?.matrix?.["postgres-version"], [major]);
    assert.ok(Array.isArray(value.steps) && value.steps.length > 0);
    const source = `${JSON.stringify(value)}\n${authorityActionText}`;
    assert.match(source, /postgres:\$\{POSTGRES_MAJOR\}/u);
    assert.match(source, /openssl req -x509/u);
    assert.match(source, /FROM pg_stat_ssl WHERE pid = pg_backend_pid\(\)/u);
    assert.match(source, /ssl = 'on'/u);
    assert.match(source, /scripts\/postgres\/role-privilege-check\.mjs/u);
    assert.match(source, /run_qualification 0048/u);
    assert.match(source, /source_commit/u);
    assert.match(source, /docker rm --force/u);
  }
});

test("canonical PostgreSQL integration remains separate from authority qualification", () => {
  const source = JSON.stringify(job("postgres-integration"));
  assert.match(source, /least-privilege-role\.integration\.test\.mjs/u);
  assert.doesNotMatch(source, /c3-migration-0047-(?:qualification|adversarial)\.test\.mjs/u);
});
