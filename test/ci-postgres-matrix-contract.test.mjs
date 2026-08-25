import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { parse } from "yaml";

const root = path.resolve(import.meta.dirname, "..");
const workflowText = fs.readFileSync(path.join(root, ".github", "workflows", "ci.yml"), "utf8");
const authorityActionText = fs.readFileSync(path.join(root, ".github", "actions", "postgres-authority-qualification", "action.yml"), "utf8");
const workflow = parse(workflowText, { uniqueKeys: true });

function job(name) {
  const value = workflow.jobs[name];
  assert.ok(value, `missing CI job ${name}`);
  return value["<<"] ? { ...value["<<"], ...value, steps: value.steps ?? value["<<"].steps } : value;
}

test("authority qualification exposes two independent source-bound PostgreSQL jobs", () => {
  for (const major of ["16", "17"]) {
    const value = job(`postgres-authority-${major}`);
    assert.deepEqual(value.strategy?.matrix?.["postgres-version"], [major]);
    assert.ok(Array.isArray(value.steps) && value.steps.length > 0);
    assert.ok(value.steps.some((step) => step.uses?.startsWith("actions/checkout@")));
    const source = `${JSON.stringify(value)}\n${authorityActionText}`;
    assert.match(source, /github\.sha/u);
    assert.match(source, /postgres:\$\{POSTGRES_MAJOR\}/u);
    assert.match(source, /ssl = 'on'/u);
    assert.match(source, /docker restart/u);
    assert.match(source, /scripts\/postgres\/roles\.sql/u);
    assert.match(source, /scripts\/postgres\/role-privilege-check\.mjs/u);
    assert.match(source, /scripts\/postgres\/n1-upgrade-qualification\.mjs/u);
    assert.match(source, /scripts\/postgres\/n2-upgrade-qualification\.mjs/u);
    assert.match(source, /scripts\/postgres\/n3-upgrade-qualification\.mjs/u);
    assert.match(source, /run_qualification 0048/u);
    assert.match(source, /run_qualification 0055/u);
    assert.match(source, /if-no-files-found/u);
  }
});

test("authority jobs retain fresh-database, TLS, evidence, and cleanup boundaries", () => {
  for (const major of ["16", "17"]) {
    const source = `${JSON.stringify(job(`postgres-authority-${major}`))}\n${authorityActionText}`;
    assert.match(source, /N1 requires a fresh database/u);
    assert.match(source, /FROM pg_stat_ssl WHERE pid = pg_backend_pid\(\)/u);
    assert.match(source, /postgres_image_id/u);
    assert.match(source, /source_commit/u);
    assert.match(source, /migration_head/u);
    assert.match(source, /unexpected_skips/u);
    assert.match(source, /docker rm --force/u);
    assert.match(source, /N1_EVIDENCE_DIR/u);
  }
});
