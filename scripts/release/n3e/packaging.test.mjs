import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';

const ROOT = path.resolve(import.meta.dirname, '../../..');
const ENTRYPOINT = 'run-fixed-protected-qualification.mjs';
const INSTALLED_ENTRYPOINT = `n3e/${ENTRYPOINT}`;
const SOURCE_ENTRYPOINT = `scripts/release/n3e/${ENTRYPOINT}`;
const packageJSON = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));
const workflow = fs.readFileSync(path.join(ROOT, '.github/workflows/p0c-hardware-qualification.yml'), 'utf8');
const releaseWorkflow = fs.readFileSync(path.join(ROOT, '.github/workflows/release-candidate.yml'), 'utf8');
const appBuilder = fs.readFileSync(path.join(ROOT, 'native/macos/scripts/build-app.sh'), 'utf8');
const installedQualificationVerifier = fs.readFileSync(path.join(ROOT, 'native/macos/scripts/verify-installed-qualification-client.sh'), 'utf8');
const qualificationEntitlements = fs.readFileSync(path.join(ROOT, 'native/macos/scripts/qualification-grant-client.entitlements'), 'utf8');
const qualificationLauncher = fs.readFileSync(path.join(ROOT, 'native/macos/scripts/qualification-grant-client-launcher.sh'), 'utf8');

const expectedPair = `['${INSTALLED_ENTRYPOINT}', '${SOURCE_ENTRYPOINT}']`;
const unarmedPair = "['n3e/qualification-unarmed-control.mjs', 'scripts/release/n3e/qualification-unarmed-control.mjs']";
const releaseTrustPair = "['n3e/qualification-release-trust.mjs', 'scripts/release/n3e/qualification-release-trust.mjs']";
const checkpointPair = "['p0c/lib/candidate-checkpoint.mjs', 'scripts/release/p0c/lib/candidate-checkpoint.mjs']";
const addedPairs = Object.freeze([
  "['n3e/qualification-canonical-json.mjs', 'scripts/release/n3e/qualification-canonical-json.mjs']",
  "['n3e/qualification-device-relay.mjs', 'scripts/release/n3e/qualification-device-relay.mjs']",
  "['n3e/qualification-input-materializer.mjs', 'scripts/release/n3e/qualification-input-materializer.mjs']",
  "['n3e/qualification-release-materializer.mjs', 'scripts/release/n3e/qualification-release-materializer.mjs']",
  "['n3e/qualification-run-binding.mjs', 'scripts/release/n3e/qualification-run-binding.mjs']",
  "['n3e/qualification-suite-evidence.mjs', 'scripts/release/n3e/qualification-suite-evidence.mjs']",
  "['n3e/qualification-suite-input.mjs', 'scripts/release/n3e/qualification-suite-input.mjs']",
  "['n3e/qualification-suite-orchestrator.mjs', 'scripts/release/n3e/qualification-suite-orchestrator.mjs']"
]);

test('the fixed protected qualification entrypoint is present in the source tree', () => {
  assert.equal(fs.existsSync(path.join(ROOT, SOURCE_ENTRYPOINT)), true, `missing ${SOURCE_ENTRYPOINT}`);
});

test('the N3-E packaging test is included in the package test surface', () => {
  assert.match(packageJSON.scripts.test, /scripts\/release\/n3e\/\*\.test\.mjs/u);
  assert.equal(packageJSON.scripts['test:n3e:packaging'], 'node --test scripts/release/n3e/packaging.test.mjs');
  assert.match(packageJSON.scripts.lint, /scripts\/release\/n3e\/\*\.mjs/u);
});

test('qualification client distribution carries the launcher and its profile-bound helper app together', () => {
  assert.match(appBuilder, /QUALIFICATION_CLIENT_APP=.*agentpass-qualification-grant-client\.app/u);
  assert.match(appBuilder, /--qualification-client-profile/u);
  assert.match(appBuilder, /embedded\.provisionprofile/u);
  assert.match(appBuilder, /qualification-grant-client\.entitlements/u);
  assert.match(qualificationLauncher, /\/opt\/agentpass\/p0c\/qualification-client\/agentpass-qualification-grant-client\.app\/Contents\/MacOS\/agentpass-qualification-grant-client/u);
  assert.match(releaseWorkflow, /AGENTPASS_QUALIFICATION_CLIENT_PROFILE_BASE64/u);
  assert.match(releaseWorkflow, /--qualification-client-profile/u);
  assert.doesNotMatch(releaseWorkflow, /qualification_client_source|qualification_client_artifact|agentpass-qualification-grant-client-\$\{[^}]+\}-macos-universal/u);
  assert.match(workflow, /qualification_client: '\/Applications\/AgentPass\.app\/Contents\/Library\/HelperTools\/agentpass-qualification-grant-client'/u);
  assert.doesNotMatch(workflow, /QUALIFICATION_CLIENT_ARTIFACT/u);
});

test('qualification helper verification checks the app and inner executable independently', () => {
  assert.doesNotMatch(installedQualificationVerifier, /--deep/u, 'qualification verification must not rely on --deep');
  for (const label of ['SOURCE_APP', 'SOURCE_BINARY', 'FIXED_APP', 'FIXED_BINARY']) assert.ok(installedQualificationVerifier.includes(`verify_signed_item \"$${label}\"`), `missing independent verification for ${label}`);
  assert.match(installedQualificationVerifier, /source-profile/u);
  assert.match(installedQualificationVerifier, /installed-profile/u);
  assert.match(installedQualificationVerifier, /codesign -d --entitlements :-/u);
  assert.match(installedQualificationVerifier, /keychain-access-groups:1/u);
  assert.match(installedQualificationVerifier, /shasum -a 256.*embedded\.provisionprofile/u);
  assert.match(qualificationEntitlements, /application-identifier/u);
  assert.match(qualificationEntitlements, /com\.apple\.developer\.team-identifier/u);
  assert.match(qualificationEntitlements, /keychain-access-groups/u);
  assert.doesNotMatch(qualificationEntitlements, /get-task-allow|disable-library-validation|allow-dyld-environment-variables/u);
});

test('both hardware-lane preflights pin the fixed protected entrypoint source and installed names', () => {
  assert.equal(workflow.split(expectedPair).length - 1, 2, `expected the fixed pair in both hardware-lane preflights: ${expectedPair}`);
  assert.equal(workflow.split(unarmedPair).length - 1, 2, 'expected the unarmed control in both hardware-lane preflights');
  assert.equal(workflow.split(releaseTrustPair).length - 1, 2, 'expected the release trust resolver in both hardware-lane preflights');
  assert.equal(workflow.split(checkpointPair).length - 1, 2, 'expected the candidate checkpoint verifier in both hardware-lane preflights');
  for (const pair of addedPairs) assert.equal(workflow.split(pair).length - 1, 2, `expected ${pair} in both hardware-lane preflights`);
  assert.equal(workflow.split(`qualification tool manifest is invalid`).length - 1, 2, 'expected duplicated immutable manifest checks for both hardware lanes');
});

test('the protected relay and evidence modules are source-pinned with their local canonical dependency', () => {
  const relay = fs.readFileSync(path.join(ROOT, 'scripts/release/n3e/qualification-device-relay.mjs'), 'utf8');
  assert.match(relay, /from ['"]\.\/qualification-canonical-json\.mjs['"]/u);
  assert.doesNotMatch(relay, /packages\/protocol/u);
  for (const file of ['qualification-canonical-json.mjs', 'qualification-device-relay.mjs', 'qualification-suite-evidence.mjs']) {
    assert.equal(fs.existsSync(path.join(ROOT, 'scripts/release/n3e', file)), true, `missing protected module ${file}`);
  }
});
