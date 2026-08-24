import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { parse } from "yaml";

const root = path.resolve(import.meta.dirname, "..");
const ciPath = path.join(root, ".github/workflows/ci.yml");
const postgresActionPath = path.join(root, ".github/actions/postgres-authority-qualification/action.yml");
const releasePath = path.join(root, ".github/workflows/release-candidate.yml");
const ciSource = fs.readFileSync(ciPath, "utf8");
const postgresActionSource = fs.readFileSync(postgresActionPath, "utf8");
const releaseSource = fs.readFileSync(releasePath, "utf8");
const lanes = ["postgres-authority-16", "postgres-authority-17", "postgres-integration", "browser-e2e", "p0b-live-process", "test"];

function workflow(source) { return parse(source, { uniqueKeys: true }); }
function job(value, name) {
  const raw = value.jobs[name];
  assert.ok(raw, `${name} job is required`);
  return raw["<<"] ? { ...raw["<<"], ...raw, steps: raw.steps ?? raw["<<"].steps } : raw;
}
function assertSixLanes(source) {
  const value = workflow(source);
  assert.deepEqual(Object.keys(value.jobs).filter((name) => lanes.includes(name)).sort(), [...lanes].sort());
  for (const lane of lanes) {
    const current = job(value, lane);
    assert.ok(current.steps.some((step) => /^actions\/checkout@[0-9a-f]{40}$/u.test(step.uses ?? "")), `${lane} must checkout an immutable SHA`);
  }
}

test("canonical CI exposes exactly six source-bound qualification lanes", () => {
  assertSixLanes(ciSource);
  const ci = workflow(ciSource);
  assert.equal(ci.concurrency?.["cancel-in-progress"], true);
  assert.equal(ci.concurrency?.group, "agentpass-ci-${{ github.event.pull_request.number || github.ref }}");
  assert.doesNotMatch(ciSource, /(?:^|\n)\s*(?:steps:\s*[&*]|[&*]postgres-authority-qualification)/u);
  assert.match(postgresActionSource, /using: composite/u);
  assert.match(postgresActionSource, /inputs:\n\s+postgres-version:/u);
  assert.doesNotMatch(postgresActionSource, /matrix\.postgres-version/u);
  assert.match(ciSource, /github\.sha/u);
  assert.match(ciSource, /git rev-parse "\$\{GITHUB_SHA\}\^\{tree\}"/u);
  assert.match(ciSource, /upload-artifact/u);
  for (const major of ["16", "17"]) {
    const source = JSON.stringify(job(workflow(ciSource), `postgres-authority-${major}`));
    const qualification = postgresActionSource;
    assert.match(source, new RegExp(`postgres-version.*${major}`, "u"));
    assert.match(qualification, /ssl = 'on'/u);
    assert.match(qualification, /FROM pg_stat_ssl WHERE pid = pg_backend_pid\(\)/u);
    assert.match(qualification, /run_qualification 0048/u);
    assert.match(qualification, /source_commit/u);
    assert.match(qualification, /docker rm --force/u);
  }
});

test("release candidate binds the exact CI run, source tree, and artifact inventory", () => {
  workflow(releaseSource);
  assert.match(releaseSource, /Re-validate exact-SHA CI lanes before protected credentials/u);
  assert.match(releaseSource, /ci-preflight\.mjs github/u);
  assert.match(releaseSource, /AGENTPASS_VERIFIED_COMMIT|AGENTPASS_RELEASE_COMMIT/u);
  assert.match(releaseSource, /git rev-parse.*\^\{tree\}/u);
  assert.match(releaseSource, /git\/commits\/\$commit/u);
  assert.match(releaseSource, /git\/commits\/\$EXPECTED_COMMIT/u);
  assert.match(releaseSource, /assertGithubCommit/u);
  assert.match(releaseSource, /jobsEnvelope\.total_count/u);
  assert.doesNotMatch(releaseSource, /assertGithubCiRun\(\{\s*run:/u,
    "protected-credential boundary must use the complete GitHub API envelope");
  assert.match(releaseSource, /artifact-scan/u);
  assert.doesNotMatch(releaseSource, /not_proven/u);
  for (const [, value] of releaseSource.matchAll(/uses:\s*([^\s]+)/gu)) assert.match(value, /^actions\/(?:checkout|setup-node|upload-artifact|download-artifact)@[0-9a-f]{40}$/u);
});

test("lane deletion and substitution are detected", () => {
  assert.throws(() => assertSixLanes(ciSource.replace(/\n  postgres-authority-17:[\s\S]*?(?=\n  postgres-integration:)/u, "\n")), /deep|lane|undefined|job/u);
  assert.throws(() => assertSixLanes(ciSource.replace("  p0b-live-process:\n", "  p0b-live-process-renamed:\n")), /deep|lane|undefined|job/u);
});
