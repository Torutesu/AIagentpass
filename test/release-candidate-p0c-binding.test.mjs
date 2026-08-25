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

test('P0-C1 requires and materializes the dedicated controller profile', () => {
  assert.match(signedCandidate, /AGENTPASS_CONTROLLER_PROFILE_BASE64: \$\{\{ secrets\.AGENTPASS_CONTROLLER_PROFILE_BASE64 \}\}/);
  const requireControllerProfile = runBlock(signedCandidate, 'Require dedicated controller profile');
  assert.match(requireControllerProfile, /AGENTPASS_CONTROLLER_PROFILE_BASE64:\?AGENTPASS_CONTROLLER_PROFILE_BASE64 is required/);
  const importMaterial = runBlock(signedCandidate, 'Import ephemeral signing material');
  assert.match(importMaterial, /printf '%s' "\$AGENTPASS_CONTROLLER_PROFILE_BASE64" \| base64 --decode > "\$RUNNER_TEMP\/agentpass-signing\/controller\.provisionprofile"/);
  assert.match(signedCandidate, /rm -rf "\$RUNNER_TEMP\/agentpass-signing"/);
});

test('P0-C1 builds the external controller as a universal artifact outside the product', () => {
  const controllerBuild = runBlock(signedCandidate, 'Build, independently notarize, staple, and archive external qualification controller');
  assert.match(controllerBuild, /swift build -c release --package-path native\/macos --arch "\$architecture"/);
  assert.match(controllerBuild, /for architecture in arm64 x86_64/);
  assert.match(controllerBuild, /xcrun lipo -create/);
  assert.match(controllerBuild, /--source-binary "\$controller_binary"/);
  assert.match(controllerBuild, /--output "\$controller_app"/);
  assert.match(controllerBuild, /--profile "\$RUNNER_TEMP\/agentpass-signing\/controller\.provisionprofile"/);
  assert.match(controllerBuild, /controller_dir="\$RUNNER_TEMP\/controller"/);
  assert.doesNotMatch(controllerBuild, /candidate\/AgentPass\.app|candidate\/.*\.pkg/);
  assert.match(controllerBuild, /scripts\/release\/notarize-controller\.sh "\$controller_app" "\$controller_notarytool" "\$controller_stapler"/);
  assert.match(controllerBuild, /controller-notarytool-result\.json/);
  assert.match(controllerBuild, /archive-controller\.mjs "\$controller_app" "\$controller_archive" "\$release_version"/);
  assert.match(controllerBuild, /release_version="\$\{AGENTPASS_RELEASE_TAG#v\}"/);
  assert.match(controllerBuild, /AgentPassQualificationController-\$\{release_version\}-macos-universal\.tar/);
});

test('P0-C1 uses the fixed controller identity CLI without a second collector path', () => {
  const collect = runBlock(signedCandidate, 'Collect external qualification controller identity');
  assert.match(collect, /controller-identity\.json/);
  assert.match(collect, /controller-identity-contract\.mjs/);
  assert.doesNotMatch(collect, /Controller identity CLI is not available|--input-type=module/);
  assert.match(collect, /node "\$controller_identity_cli" collect \\\n+\s+"\$controller_dir\/AgentPassQualificationController-\$\{AGENTPASS_RELEASE_TAG#v\}-macos-universal\.tar" \\\n+\s+"\$controller_dir\/AgentPassQualificationController\.app" "\$AGENTPASS_TEAM_ID" "\$controller_identity"/);
  assert.doesNotMatch(collect, /collectExternalQualificationControllerIdentity|canonicalJSON/);
});

test('P0-C1 binds the exact controller manifest contract', () => {
  const build = runBlock(signedCandidate, 'Build, notarize, staple, and bind installer candidate');
  const manifest = build.indexOf('generate-manifest.mjs');
  assert.ok(manifest >= 0);
  const manifestCommand = build.slice(manifest);
  for (const option of [
    '--controller-identity="$RUNNER_TEMP/candidate/controller-identity.json"',
    '--controller-notarization-status=accepted_stapled',
    '--controller-notary-submission="$controller_submission_id"',
    '--controller-notarytool-evidence="$RUNNER_TEMP/candidate/controller-notarytool-result.json"',
    '--controller-stapler-evidence="$RUNNER_TEMP/candidate/controller-stapler-result.txt"'
  ]) assert.ok(manifestCommand.indexOf(option) >= 0, `missing exact controller manifest option: ${option}`);
  assert.ok(manifestCommand.indexOf('--controller-identity=') < manifestCommand.indexOf('--controller-notarization-status='));
  assert.ok(manifestCommand.indexOf('--controller-notarization-status=') < manifestCommand.indexOf('--controller-notary-submission='));
  assert.ok(manifestCommand.indexOf('--controller-notary-submission=') < manifestCommand.indexOf('--controller-notarytool-evidence='));
  assert.ok(manifestCommand.indexOf('--controller-notarytool-evidence=') < manifestCommand.indexOf('--controller-stapler-evidence='));
  assert.match(manifestCommand, /AgentPassQualificationController-\$\{AGENTPASS_RELEASE_TAG#v\}-macos-universal\.tar/);
});

test('P0-C1 uploads every external controller artifact and evidence file', () => {
  const upload = stepContaining(signedCandidate, 'actions/upload-artifact@');
  for (const path of [
    'candidate/AgentPassQualificationController-*-macos-universal.tar',
    'candidate/controller-identity.json',
    'candidate/controller-notarytool-result.json',
    'candidate/controller-stapler-result.txt'
  ]) assert.ok(upload.includes(`\${{ runner.temp }}/${path}`), `missing controller upload path: ${path}`);
  assert.match(signedCandidate, /rm -rf "\$RUNNER_TEMP\/controller"/);
});
