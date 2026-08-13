import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import test from 'node:test';

const root = resolve(import.meta.dirname, '..');
const workflow = readFileSync(resolve(root, '.github/workflows/promote-qualified-release.yml'), 'utf8');

const job = (name) => {
  const start = workflow.indexOf(`  ${name}:`);
  assert.notEqual(start, -1, `missing job: ${name}`);
  const next = workflow.slice(start + 1).search(/^  [A-Za-z0-9_-]+:/m);
  return workflow.slice(start, next === -1 ? workflow.length : start + 1 + next);
};

const promote = job('promote');
const step = (name) => {
  const nameOffset = promote.indexOf(`name: ${name}`);
  assert.notEqual(nameOffset, -1, `missing step: ${name}`);
  const start = promote.lastIndexOf('      - ', nameOffset);
  assert.notEqual(start, -1, `missing step heading: ${name}`);
  const after = promote.slice(start);
  const next = after.slice(1).search(/^      - /m);
  return after.slice(0, next === -1 ? after.length : next + 1);
};

test('promotion is manual-dispatch only, canonical-main only, and protected with no secret inputs', () => {
  assert.match(workflow, /^on:\n  workflow_dispatch:/m);
  for (const event of ['push', 'pull_request', 'pull_request_target', 'repository_dispatch', 'workflow_call', 'schedule', 'workflow_run']) {
    assert.doesNotMatch(workflow, new RegExp(`^\\s{2}${event}:`, 'm'), `unexpected trigger: ${event}`);
  }
  assert.match(promote, /if: \$\{\{ github\.event_name == 'workflow_dispatch' && github\.repository == 'Torutesu\/AIagentpass' && github\.ref == 'refs\/heads\/main' \}\}/);
  assert.match(promote, /runs-on: macos-15/);
  assert.match(promote, /environment: production-release/);
  assert.match(promote, /permissions:\n      contents: write\n      actions: read/);
  assert.doesNotMatch(workflow, /secrets\./, 'promotion must not consume signing, notary, or operator private secrets');
  assert.doesNotMatch(workflow, /pull_request(?:_target)?:/);
});

test('all actions are immutable SHAs and only trusted built-in actions are used', () => {
  const uses = [...workflow.matchAll(/uses:\s*([^\s]+)/g)].map(([, value]) => value);
  assert.equal(uses.length, 6, 'expected checkout, setup-node, and four exact artifact downloads');
  for (const use of uses) {
    assert.match(use, /^actions\/(?:checkout|setup-node|download-artifact)@[0-9a-f]{40}$/);
  }
  assert.doesNotMatch(workflow, /@[vV][0-9]/);
  assert.doesNotMatch(workflow, /^\s*-\s+uses:\s+(?!actions\/)/m);
});

test('inputs identify exact runs and preflight validates both runs and every artifact through the API', () => {
  assert.match(workflow, /release_run_id:\n\s+description: Successful Release candidate workflow run ID/);
  assert.match(workflow, /qualification_run_id:\n\s+description: Successful P0-C hardware qualification workflow run ID/);
  const preflight = step('Validate exact successful source and qualification runs through the GitHub API');
  assert.match(preflight, /RELEASE_RUN_ID" =~ \^\[1-9\]\[0-9\]\{0,18\}\$/);
  assert.match(preflight, /QUALIFICATION_RUN_ID" =~ \^\[1-9\]\[0-9\]\{0,18\}\$/);
  assert.match(preflight, /actions\/runs\/\$RELEASE_RUN_ID/);
  assert.match(preflight, /actions\/runs\/\$QUALIFICATION_RUN_ID/);
  assert.match(preflight, /actions\/runs\/\$RELEASE_RUN_ID\/artifacts/);
  assert.match(preflight, /actions\/runs\/\$QUALIFICATION_RUN_ID\/artifacts/);
  for (const expected of [
    '.name == "Release candidate"',
    '.path == ".github/workflows/release-candidate.yml"',
    '.name == "P0-C hardware qualification"',
    '.path == ".github/workflows/p0c-hardware-qualification.yml"',
    '.event == "workflow_dispatch"',
    '.status == "completed"',
    '.conclusion == "success"',
    '.head_branch == "main"',
    '.head_repository.full_name == $repo'
  ]) assert.match(preflight, new RegExp(expected.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
  assert.match(preflight, /aggregate job therefore emits a canonical\n\s+# dispatch binding/);
  assert.match(preflight, /both signed\n\s+# reports' exact artifact\/manifest bindings/);
  for (const artifact of ['EXPECTED_CANDIDATE_ARTIFACT', 'EXPECTED_APPLE_ARTIFACT', 'EXPECTED_INTEL_ARTIFACT', 'EXPECTED_SUMMARY_ARTIFACT']) assert.match(preflight, new RegExp(`\\$${artifact}`));
});

test('downloads candidate from release run and all three P0-C artifacts from qualification run', () => {
  const downloads = [...promote.matchAll(/uses: actions\/download-artifact@[0-9a-f]{40}[\s\S]*?(?=\n\n      - uses:|\n\n      - id:|\n\n      - name:|$)/g)].map((match) => match[0]);
  assert.equal(downloads.length, 4);
  assert.match(downloads[0], /name: notarized-release-candidate/);
  assert.match(downloads[0], /run-id: \$\{\{ steps\.preflight\.outputs\.release_run_id \}\}/);
  for (const [name, output] of [['p0c-hardware-apple-silicon', 'qualification_run_id'], ['p0c-hardware-intel-t2', 'qualification_run_id'], ['p0c-hardware-qualification-summary', 'qualification_run_id']]) {
    const found = downloads.find((value) => value.includes(`name: ${name}`));
    assert.ok(found, `missing download for ${name}`);
    assert.match(found, new RegExp(`run-id: \\$\\{\\{ steps\\.preflight\\.outputs\\.${output} \\}\\}`));
    assert.match(found, /repository: Torutesu\/AIagentpass/);
  }
  const catalog = step('Catalog only the exact downloaded candidate and qualification evidence');
  for (const name of ['release-manifest.json', 'release-manifest.sig', 'release-manifest.public.pem', 'report.json', 'report.sig', 'operator-public.pem', 'qualification-summary.json', 'qualification-dispatch-binding.json']) assert.match(catalog, new RegExp(name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
  assert.match(catalog, /candidate artifact contains unexpected or missing files/);
  assert.match(catalog, /qualification artifact has unexpected files/);
});

test('re-runs signed macOS and cross-hardware qualification verification, including byte comparison', () => {
  const release = step('Verify signed release candidate and derive its tag');
  assert.match(release, /verify-release\.mjs/);
  assert.match(release, /verify-macos-release\.sh/);
  assert.match(release, /RELEASE_RUN_HEAD_SHA/);
  const source = step('Verify annotated tag and source identity before promotion');
  for (const check of [/git cat-file -t/, /git.*verify-tag/, /git rev-parse/, /git merge-base --is-ancestor/, /refs\/tags\/\$RELEASE_TAG/]) assert.match(source, check);
  const qualification = step('Re-run hardware qualification verification against the exact candidate');
  assert.match(qualification, /verify-hardware-qualification-set\.mjs/);
  assert.match(promote, /APPROVED_OPERATOR_POLICY_JSON: \$\{\{ vars\.AGENTPASS_P0C_APPROVED_OPERATOR_POLICY_JSON \}\}/);
  assert.match(qualification, /APPLE_OPERATOR_FINGERPRINT/);
  assert.match(qualification, /INTEL_OPERATOR_FINGERPRINT/);
  assert.match(qualification, /cmp -s "\$GENERATED_SUMMARY" "\$RETAINED_SUMMARY"/);
  assert.match(qualification, /summary\.release_manifest_sha256 !== expectedManifestDigest/);
  assert.match(qualification, /summary\.artifact_sha256 !== product\.sha256/);
  assert.match(qualification, /binding\.release_run_id !== process\.env\.RELEASE_RUN_ID/);
  assert.match(qualification, /binding\.qualification_run_id !== process\.env\.QUALIFICATION_RUN_ID/);
});

test('release creation is last, refuses existing tags, and uploads an explicit manifest-bound list', () => {
  const refuse = step('Refuse an existing release before creating the public release');
  assert.match(refuse, /releases\/tags\/\$RELEASE_TAG/);
  assert.match(refuse, /a GitHub Release already exists/);
  const create = step('Create draft release after every verification gate');
  assert.match(create, /gh release create "\$RELEASE_TAG" --repo "\$CANONICAL_REPOSITORY" --draft --verify-tag --target "\$RELEASE_COMMIT"/);
  const upload = step('Upload only the explicit signed-manifest-bound release list');
  assert.match(upload, /manifest\.artifacts\.map/);
  assert.match(upload, /manifest\.evidence\.notarization\.evidence\.map/);
  assert.match(upload, /manifest\.evidence\.checksums/);
  assert.match(upload, /spawnSync\('gh', \['release', 'upload', tag, '--repo', repository, \.\.\.files\]/);
  assert.match(upload, /shell: false/);
  const qualificationAssets = step('Upload the verified signed qualification evidence');
  for (const name of ['p0c-apple-silicon-report.json', 'p0c-intel-t2-report.json', 'p0c-hardware-qualification-summary.json', 'p0c-approved-operator-policy.json', 'P0C-SHA256SUMS']) assert.match(qualificationAssets, new RegExp(name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
  assert.match(qualificationAssets, /p0c-apple-silicon-evidence\.tar\.gz/);
  assert.match(qualificationAssets, /p0c-intel-t2-evidence\.tar\.gz/);
  const publish = step('Publish the fully uploaded public release');
  assert.match(publish, /gh release edit "\$RELEASE_TAG" --repo "\$CANONICAL_REPOSITORY" --draft=false/);
  assert.ok(promote.indexOf('verify-hardware-qualification-set.mjs') < promote.indexOf('gh release create'));
  assert.ok(promote.indexOf('gh release upload') < promote.indexOf('gh release edit'));
});

test('no untrusted downloaded content is executed and cleanup is unconditional', () => {
  assert.match(workflow, /actions\/checkout@[0-9a-f]{40}[\s\S]*?persist-credentials: false/);
  assert.doesNotMatch(workflow, /chmod \+x.*(?:candidate|apple|intel|summary)|bash .*candidate|sh .*candidate|open .*\.pkg/);
  assert.match(workflow, /if: \$\{\{ always\(\) \}\}/);
  assert.match(workflow, /rm -rf -- "\$PROMOTION_ROOT"/);
});
