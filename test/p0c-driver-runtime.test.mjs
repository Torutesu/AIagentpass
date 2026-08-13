import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { executeGateDriver, validateDriverConfig, validateReleaseBindings } from '../scripts/release/p0c/lib/driver-runtime.mjs';

const digest = (bytes) => crypto.createHash('sha256').update(bytes).digest('hex');
const canonical = (value) => Buffer.from(`${JSON.stringify(value, null, 2)}\n`);
const teamId = 'A1B2C3D4E5';
const codeIdentities = [
  ['AgentPass.app', 'dev.agentpass'],
  ['AgentPass.app/Contents/Library/HelperTools/AgentPassNativeClient.app', 'dev.agentpass.native-client'],
  ['AgentPass.app/Contents/Library/HelperTools/AgentPassNativeService.app', 'dev.agentpass.native-service'],
  ['AgentPass.app/Contents/Library/HelperTools/agentpass-atomic-rename', 'dev.agentpass.atomic-rename'],
  ['AgentPass.app/Contents/MacOS/agentpass-native-manager', 'dev.agentpass.native-manager'],
  ['AgentPass.app/Contents/MacOS/agentpass-onboarding', 'dev.agentpass']
].map(([identityPath, bundleId], index) => ({ path: identityPath, bundle_id: bundleId, team_id: teamId, code_directory_hash: String(index + 1).repeat(40) }));
const gateNames = [
  'audit-upload-observation', 'claude-code-unattended-sign', 'clean-install-launchd-xpc',
  'cloud-possession-verification', 'crash-restart-recovery', 'current-user-purge',
  'cursor-code-unattended-sign', 'gatekeeper-notarization', 'negative-identity-and-entitlement-cases',
  'offline-expiry', 'policy-reduction-refresh-ack', 'revoke-emergency-stop',
  'secure-enclave-enrollment', 'sleep-wake-network-clock', 'uninstall-reinstall-recovery',
  'upgrade-preserves-state'
];

const fixture = () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpass-driver-runtime-'));
  const artifact = path.join(directory, 'AgentPass.pkg'); const artifactBytes = Buffer.from('bound candidate'); fs.writeFileSync(artifact, artifactBytes, { mode: 0o600 });
  const scenarioDirectory = path.join(directory, 'scenarios'); fs.mkdirSync(scenarioDirectory, { mode: 0o755 });
  const scenarios = gateNames.map((gate) => {
    const executable = gate; const bytes = Buffer.from('#!/bin/sh\nexit 1\n'); const file = path.join(scenarioDirectory, executable); fs.writeFileSync(file, bytes, { mode: 0o755 }); fs.chmodSync(file, 0o755);
    return { gate, executable, sha256: digest(bytes) };
  });
  const env = { AGENTPASS_P0C_ARTIFACT_PATH: artifact, AGENTPASS_P0C_ARTIFACT_SHA256: digest(artifactBytes), AGENTPASS_P0C_SOURCE_COMMIT: 'a'.repeat(40), AGENTPASS_P0C_TEAM_ID: teamId, AGENTPASS_P0C_CODE_IDENTITIES_JSON: JSON.stringify(codeIdentities) };
  return { directory, artifact, env, config: validateDriverConfig({ schema_version: 1, scenario_directory: scenarioDirectory, scenarios }, { production: false }) };
};

test('driver accepts only an exact release-bound scenario protocol and emits the runner protocol', async () => {
  const value = fixture();
  const result = await executeGateDriver({
    gate: 'gatekeeper-notarization', tests: ['exact-pkg-install'], scenario: 'gatekeeper-notarization', config: value.config, env: value.env, production: false,
    run: async (_command, scenarioEnv) => ({ exitCode: 0, signal: null, spawnError: false, timedOut: false, outputLimit: false, stdout: canonical({ schema_version: 1, gate: scenarioEnv.AGENTPASS_P0C_GATE, status: 'passed', tests: [{ name: 'exact-pkg-install', status: 'passed' }], bindings: { artifact_sha256: value.env.AGENTPASS_P0C_ARTIFACT_SHA256, source_commit: value.env.AGENTPASS_P0C_SOURCE_COMMIT, team_id: value.env.AGENTPASS_P0C_TEAM_ID, code_identities_sha256: digest(Buffer.from(value.env.AGENTPASS_P0C_CODE_IDENTITIES_JSON)) } }) })
  });
  assert.deepEqual(result, { schema_version: 1, gate: 'gatekeeper-notarization', status: 'passed', tests: [{ name: 'exact-pkg-install', status: 'passed' }] });
});

test('driver refuses substituted release bindings, static results, and changed executables', async () => {
  const value = fixture(); const declaration = { gate: 'gatekeeper-notarization', tests: ['exact-pkg-install'], scenario: 'gatekeeper-notarization', config: value.config, env: value.env, production: false };
  await assert.rejects(() => executeGateDriver({ ...declaration, run: async () => ({ exitCode: 0, stdout: canonical({ schema_version: 1, gate: declaration.gate, status: 'passed', tests: [{ name: 'exact-pkg-install', status: 'passed' }], bindings: { artifact_sha256: 'b'.repeat(64), source_commit: 'a'.repeat(40), team_id: teamId, code_identities_sha256: digest(Buffer.from(value.env.AGENTPASS_P0C_CODE_IDENTITIES_JSON)) } }) }) }), /bound to this release/);
  await assert.rejects(() => executeGateDriver({ ...declaration, run: async () => ({ exitCode: 0, stdout: canonical({ schema_version: 1, gate: declaration.gate, status: 'passed', tests: [{ name: 'exact-pkg-install', status: 'passed' }] }) }) }), /missing or unknown fields/);
  await assert.rejects(() => executeGateDriver({ ...declaration, run: async (command) => { fs.appendFileSync(command, '# mutation'); return { exitCode: 0, stdout: Buffer.alloc(0) }; } }), /digest mismatch/);
});

test('release bindings recompute the exact artifact digest and reject path substitution', () => {
  const value = fixture(); assert.equal(validateReleaseBindings(value.env).artifactSha256, value.env.AGENTPASS_P0C_ARTIFACT_SHA256);
  fs.appendFileSync(value.artifact, 'tampered'); assert.throws(() => validateReleaseBindings(value.env), /digest mismatch/);
  assert.throws(() => validateReleaseBindings({ ...value.env, AGENTPASS_P0C_ARTIFACT_PATH: 'relative.pkg' }), /missing or invalid/);
});
