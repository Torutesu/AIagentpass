import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';

const ROOT = path.resolve(import.meta.dirname, '../../..');
const read = (relative) => fs.readFileSync(path.join(ROOT, relative), 'utf8');
const buildApp = read('native/macos/scripts/build-app.sh');
const testApp = read('native/macos/scripts/test-app-bundle.sh');
const verifyInstaller = read('native/macos/scripts/verify-installer-package.sh');
const verifyRelease = read('scripts/release/verify-macos-release.sh');
const packageSwift = read('native/macos/Package.swift');
const releaseWorkflow = read('.github/workflows/release-candidate.yml');
const releaseDocs = read('docs/RELEASE.md');
const distributionDocs = read('docs/release/MACOS_DISTRIBUTION.md');
const forwardPlan = read('docs/FORWARD_IMPLEMENTATION_PLAN_2026-08-16.md');

const helpers = Object.freeze([
  ['agentpass-git-sign', 'dev.agentpass.git-sign', 'AgentPassGitSigningHelper', 'GIT_SIGNING_HELPER'],
  ['agentpass-git-session-sign', 'dev.agentpass.git-session-sign', 'AgentPassGitSessionSigningHelper', 'GIT_SESSION_SIGNING_HELPER'],
  ['agentpass-git-sign-xpc', 'dev.agentpass.git-sign-xpc', 'AgentPassGitSigningXPCHelper', 'GIT_SIGNING_XPC_HELPER']
]);

test('Package.swift exposes exactly the three reviewed Git helper products and targets', () => {
  for (const [name, , target] of helpers) {
    assert.equal(packageSwift.split(`.executable(name: "${name}",`).length - 1, 1, `${name} product must be declared once`);
    assert.equal(packageSwift.split(`name: "${target}"`).length - 1, 1, `${target} target must be declared once`);
  }
  assert.match(packageSwift, /name: "AgentPassGitSigningHelper"[\s\S]*dependencies: \["AgentPassNativeCore"\]/u);
  assert.match(packageSwift, /name: "AgentPassGitSessionSigningHelper"[\s\S]*dependencies: \["AgentPassNativeCore"\]/u);
  assert.match(packageSwift, /name: "AgentPassGitSigningXPCHelper"[\s\S]*dependencies: \["AgentPassNativeCore"\]/u);
});

test('build-app.sh assembles, signs, and validates all three helpers at the frozen resource path', () => {
  assert.match(buildApp, /RESOURCE_BIN_DIR="\$APP\/Contents\/Resources\/bin"/u);
  for (const [name, identifier, , variable] of helpers) {
    assert.ok(buildApp.includes(`install_product ${name} "$${variable}"`), `${name} must be installed at the resource path`);
    assert.ok(buildApp.includes(`--identifier "${identifier}"`), `${name} must be signed with its fixed identifier`);
    assert.ok(buildApp.includes(`verify_identifier "$${variable}" "${identifier}"`), `${name} identifier must be verified`);
  }
  assert.match(buildApp, /ARCHITECTURES=\(arm64 x86_64\)/u);
  assert.match(buildApp, /Universal executable must contain arm64 and x86_64 slices/u);
  assert.match(buildApp, /Production app identity must be a Developer ID Application identity/u);
  assert.match(buildApp, /--options runtime --timestamp/u);
  assert.match(buildApp, /notarize after assembly/u);
});

test('bundle test exercises universal slices and an exact, duplicate-free helper inventory', () => {
  assert.match(testApp, /build-app\.sh --adhoc --universal/u);
  assert.match(testApp, /RESOURCE_BIN.*exactly three files/u);
  assert.match(testApp, /agentpass-git-session-sign agentpass-git-sign agentpass-git-sign-xpc/u);
  assert.match(testApp, /must appear exactly once/u);
  assert.match(testApp, /Executable must contain exactly arm64 and x86_64 slices/u);
  for (const [name, identifier] of helpers) {
    assert.ok(testApp.includes(name), `${name} must be checked`);
    assert.ok(testApp.includes(identifier), `${identifier} must be checked`);
  }
});

test('installer and offline macOS release verification retain the helper contract', () => {
  for (const [name, identifier] of helpers) {
    assert.ok(verifyInstaller.includes(`Contents/Resources/bin/${name}`), `${name} must be checked in the installer verifier`);
    assert.ok(verifyInstaller.includes(identifier), `${identifier} must be checked in the installer verifier`);
    assert.ok(verifyRelease.includes(`Contents/Resources/bin/${name}`), `${name} must be checked in the release verifier`);
    assert.ok(verifyRelease.includes(identifier), `${identifier} must be checked in the release verifier`);
  }
  assert.match(verifyInstaller, /exactly three files/u);
  assert.match(verifyInstaller, /must contain exactly arm64 and x86_64 slices/u);
  assert.match(verifyRelease, /Universal slices missing from Git helper/u);
});

test('release workflow and operator docs bind universal build to Developer ID, notarization, staple, and post-staple verification', () => {
  assert.match(releaseWorkflow, /build-app\.sh --universal/u);
  for (const option of ['--service-profile', '--client-profile', '--agent-profile', '--qualification-client-profile']) assert.ok(releaseWorkflow.includes(option), `${option} must be supplied by the release workflow`);
  assert.match(releaseWorkflow, /build-installer\.sh/u);
  assert.match(releaseWorkflow, /verify-installer-package\.sh/u);
  assert.match(releaseWorkflow, /notarize-installer\.sh/u);
  assert.match(releaseWorkflow, /verify-macos-release\.sh/u);
  assert.match(releaseWorkflow, /macos-universal\.pkg/u);
  for (const document of [releaseDocs, distributionDocs, forwardPlan]) {
    assert.match(document, /Developer ID/u);
    assert.match(document, /notariz/u);
    assert.match(document, /arm64/u);
    assert.match(document, /x86_64/u);
  }
  assert.match(releaseDocs, /--agent-profile/u);
  assert.match(releaseDocs, /--qualification-client-profile/u);
  assert.match(distributionDocs, /Production onboarding must not continue/u);
});
