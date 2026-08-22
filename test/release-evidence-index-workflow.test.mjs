import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';
import { parse } from 'yaml';

const read = (file) => fs.readFileSync(new URL(`../${file}`, import.meta.url), 'utf8');
const candidate = read('.github/workflows/release-candidate.yml');
const preflight = read('.github/workflows/release-preflight.yml');
const evidenceIndexDoc = read('docs/release/RELEASE_EVIDENCE_INDEX.md');

test('release-candidate derives the expected evidence candidate from the exact signed manifest and PKG', () => {
  assert.match(candidate, /name: Derive immutable release evidence candidate binding/u);
  assert.match(candidate, /createHash\('sha256'\)\.update\(packageBytes\)/u);
  assert.match(candidate, /product\[0\]\.sha256 !== artifactSha256/u);
  assert.match(candidate, /manifest\.source\?\.commit !== expectedCommit/u);
  assert.match(candidate, /manifest\.source\?\.tree !== expectedTree/u);
  assert.match(candidate, /release-pkg-sha256-v1-\$\{artifactSha256\}/u);
  assert.match(candidate, /O_EXCL \| fs\.constants\.O_NOFOLLOW/u);
  assert.match(candidate, /release-evidence-expected-candidate\.json/u);
});

test('release-candidate uploads the candidate binding into the integrity artifact', () => {
  assert.match(candidate, /name: release-integrity-evidence[\s\S]*?release-evidence-expected-candidate\.json/u);
  assert.match(candidate, /name: notarized-release-candidate/u);
  assert.match(candidate, /name: release-integrity-evidence/u);
});

test('release-preflight requires actions read and an exact candidate run', () => {
  assert.match(preflight, /permissions:\n  contents: read\n  actions: read/u);
  assert.match(preflight, /candidate_run_id:/u);
  assert.match(preflight, /exactly one successful source-bound Release candidate run is required/u);
  assert.match(preflight, /run\.path !== '\.github\/workflows\/release-candidate\.yml'/u);
  assert.match(preflight, /run\.head_sha !== expectedSha/u);
  assert.match(preflight, /run\.repository\?\.full_name !== expectedRepository/u);
  assert.match(preflight, /run\.run_attempt/u);
});

test('release-preflight verifies both candidate artifacts are live and bound to the selected run', () => {
  assert.match(preflight, /release-integrity-evidence/u);
  assert.match(preflight, /item\.expired === false/u);
  assert.match(preflight, /String\(item\.workflow_run\?\.id\) === expectedRunId/u);
  assert.match(preflight, /gh run download "\$candidate_run_id"/u);
  assert.match(preflight, /notarized-release-candidate/u);
});

test('release-preflight independently derives source/tree/artifact/manifest binding', () => {
  assert.match(preflight, /signed release manifest product name is not bound to the exact PKG/u);
  assert.match(preflight, /manifest\.source\?\.commit !== expectedCommit/u);
  assert.match(preflight, /manifest\.source\?\.tag !== expectedTag/u);
  assert.match(preflight, /manifest\.source\.tree/u);
  assert.match(preflight, /createHash\('sha256'\)\.update\(fs\.readFileSync\(packagePath\)\)/u);
  assert.match(preflight, /release manifest product digest differs from the exact PKG/u);
  assert.match(preflight, /candidate binding artifact differs from the independently derived candidate/u);
});

test('release-preflight requires the protected canonical evidence index and the new fail-closed verifier', () => {
  assert.match(preflight, /RELEASE_EVIDENCE_INDEX_JSON: \$\{\{ vars\.AGENTPASS_RELEASE_EVIDENCE_INDEX_JSON \}\}/u);
  assert.match(preflight, /: "\$\{RELEASE_EVIDENCE_INDEX_JSON:\?AGENTPASS_RELEASE_EVIDENCE_INDEX_JSON/u);
  assert.match(preflight, /release evidence index must be canonical JSON without a trailing newline/u);
  assert.match(preflight, /node scripts\/release\/release-evidence-index\.mjs verify/u);
  assert.match(preflight, /release evidence index candidate binding is not exact/u);
  assert.match(preflight, /release evidence index candidate slot is not bound to the exact Release candidate run/u);
});

test('workflow YAML parses with unique keys and keeps existing protected action pins', () => {
  const parsedCandidate = parse(candidate, { uniqueKeys: true });
  const parsedPreflight = parse(preflight, { uniqueKeys: true });
  assert.equal(parsedCandidate.jobs['signed-candidate'].permissions, undefined);
  assert.equal(parsedPreflight.permissions.actions, 'read');
  for (const workflow of [candidate, preflight]) {
    for (const match of workflow.matchAll(/^\s*- uses:\s*([^\s@]+)@([^\s#]+)(?:\s+#.*)?$/gmu)) {
      assert.match(match[2], /^[0-9a-f]{40}$/u, `${match[1]} must remain immutable-pinned`);
    }
  }
});

test('release evidence documentation records the candidate artifact and protected preflight boundary', () => {
  assert.match(evidenceIndexDoc, /release-evidence-expected-candidate\.json/u);
  assert.match(evidenceIndexDoc, /release-candidate\.yml/u);
  assert.match(evidenceIndexDoc, /release-preflight\.yml/u);
  assert.match(evidenceIndexDoc, /source commit\/tree/u);
  assert.match(evidenceIndexDoc, /artifact digest/u);
  assert.match(evidenceIndexDoc, /run tuple/u);
});
