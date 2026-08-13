import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import test from 'node:test';

const root = resolve(import.meta.dirname, '..');
const workflow = readFileSync(resolve(root, '.github/workflows/release-candidate.yml'), 'utf8');

const job = (name) => {
  const start = workflow.indexOf(`  ${name}:`);
  assert.notEqual(start, -1, `missing job: ${name}`);
  const next = workflow.slice(start + 1).search(/^  [A-Za-z0-9_-]+:/m);
  return workflow.slice(start, next === -1 ? workflow.length : start + 1 + next);
};

const signedCandidate = job('signed-candidate');
const runBlock = (value, name) => {
  const start = value.indexOf(`      - name: ${name}`);
  assert.notEqual(start, -1, `missing step: ${name}`);
  const after = value.slice(start);
  const next = after.slice(1).search(/^      - /m);
  return after.slice(0, next === -1 ? after.length : next + 1);
};

const stepContaining = (value, marker) => {
  const markerOffset = value.indexOf(marker);
  assert.notEqual(markerOffset, -1, `missing step content: ${marker}`);
  const start = value.lastIndexOf('      - ', markerOffset);
  const after = value.slice(start);
  const next = after.slice(1).search(/^      - /m);
  return after.slice(0, next === -1 ? after.length : next + 1);
};

test('P0-C1 creates migration manifest and attestation before the signed manifest', () => {
  const build = runBlock(signedCandidate, 'Build, notarize, staple, and bind installer candidate');
  const migration = signedCandidate.indexOf('generate-database-migration-manifest.mjs');
  const attestation = build.indexOf('generate-release-attestation.mjs');
  const manifest = build.indexOf('generate-manifest.mjs');
  const sign = build.indexOf('sign-manifest.mjs');
  assert.ok(migration >= 0);
  assert.ok(attestation >= 0 && manifest > attestation && sign > manifest);
  assert.match(build, /--dependency-lock "\$GITHUB_WORKSPACE\/package-lock\.json"/);
  assert.match(build, /--database-migration-manifest "\$RUNNER_TEMP\/candidate\/AgentPass-\$\{AGENTPASS_RELEASE_TAG\}\.database-migration-manifest\.json"/);
  assert.match(build, /--cloud-image-digest "\$AGENTPASS_CLOUD_IMAGE_DIGEST"/);
  assert.match(build, /--signer-key-versions "\$RUNNER_TEMP\/agentpass-attestation-inputs\/signer-key-versions\.json"/);
  assert.match(build, /AgentPass-\$\{AGENTPASS_RELEASE_TAG\}\.database-migration-manifest\.json/);
  assert.match(build, /candidate\/release-attestation\.json/);
});

test('P0-C1 propagates both attestation artifacts through the candidate upload', () => {
  const upload = stepContaining(signedCandidate, 'actions/upload-artifact@');
  assert.match(upload, /candidate\/\*\.database-migration-manifest\.json/);
  assert.match(upload, /candidate\/release-attestation\.json/);
  assert.doesNotMatch(workflow, /^  publish:|gh release (?:create|edit|upload)/m);
});

test('P0-C1 uses protected immutable inputs and fails closed without shell JSON interpolation', () => {
  const materialize = runBlock(signedCandidate, 'Materialize protected attestation inputs');
  assert.match(materialize, /AGENTPASS_CLOUD_IMAGE_DIGEST: \$\{\{ vars\.AGENTPASS_CLOUD_IMAGE_DIGEST \}\}/);
  assert.match(materialize, /AGENTPASS_SIGNER_KEY_VERSIONS_JSON: \$\{\{ secrets\.AGENTPASS_SIGNER_KEY_VERSIONS_JSON \}\}/);
  assert.match(materialize, /AGENTPASS_CLOUD_IMAGE_DIGEST:\?AGENTPASS_CLOUD_IMAGE_DIGEST is required/);
  assert.match(materialize, /AGENTPASS_SIGNER_KEY_VERSIONS_JSON:\?AGENTPASS_SIGNER_KEY_VERSIONS_JSON is required/);
  assert.match(materialize, /umask 077/);
  assert.match(materialize, /process\.env\.AGENTPASS_SIGNER_KEY_VERSIONS_JSON/);
  assert.match(materialize, /fs\.constants\.O_EXCL/);
  assert.match(materialize, /fs\.constants\.O_NOFOLLOW/);
  assert.match(materialize, /fs\.openSync\(output, flags, 0o600\)/);
  assert.match(materialize, /protected signer key versions must use canonical JSON/);
  assert.doesNotMatch(materialize, /printf[^\n]*AGENTPASS_SIGNER_KEY_VERSIONS_JSON/);
  assert.doesNotMatch(materialize, /echo[^\n]*AGENTPASS_SIGNER_KEY_VERSIONS_JSON/);
  assert.match(signedCandidate, /rm -rf "\$RUNNER_TEMP\/agentpass-attestation-inputs"/);
  assert.match(signedCandidate, /AGENTPASS_CLOUD_IMAGE_DIGEST: \$\{\{ vars\.AGENTPASS_CLOUD_IMAGE_DIGEST \}\}/);
});

test('P0-C1 has no untrusted pull request secret path and all actions are pinned', () => {
  assert.doesNotMatch(workflow, /pull_request(?:_target)?:/);
  for (const use of workflow.matchAll(/uses:\s*([^\s]+)/g)) assert.match(use[1], /^[^@]+@[0-9a-f]{40}$/);
  const verifySource = job('verify-source');
  assert.doesNotMatch(verifySource, /secrets\./);
  assert.match(verifySource, /vars\.AGENTPASS_RELEASE_ALLOWED_SIGNERS/);
  assert.match(signedCandidate, /environment: production-signing/);
});

test('P0-C1 preserves exact v-tagged universal package naming', () => {
  assert.match(workflow, /package="\$RUNNER_TEMP\/candidate\/AgentPass-\$\{AGENTPASS_RELEASE_TAG\}-macos-universal\.pkg"/);
  assert.doesNotMatch(workflow, /AgentPass-\$\{AGENTPASS_RELEASE_TAG\}-macos-universal\.pkg[^\n]*\$\{AGENTPASS_RELEASE_TAG\}/);
  assert.doesNotMatch(workflow, /AgentPass-\$\{AGENTPASS_RELEASE_TAG\}-macos-universal\.pkg[^"]*\b(?:no-v|pkg-)\b/);
});
