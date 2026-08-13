import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { canonicalJSON, executePhysicalScenario, releaseBindings, runFixedCommand, runPinnedExecutable, validateScenarioConfig } from '../scripts/release/p0c/lib/scenario-runtime.mjs';

const digest = (bytes) => crypto.createHash('sha256').update(bytes).digest('hex');
const teamId = 'A1B2C3D4E5';
const codeIdentities = [
  ['AgentPass.app', 'dev.agentpass'],
  ['AgentPass.app/Contents/Library/HelperTools/AgentPassNativeClient.app', 'dev.agentpass.native-client'],
  ['AgentPass.app/Contents/Library/HelperTools/AgentPassNativeService.app', 'dev.agentpass.native-service'],
  ['AgentPass.app/Contents/Library/HelperTools/agentpass-atomic-rename', 'dev.agentpass.atomic-rename'],
  ['AgentPass.app/Contents/MacOS/agentpass-native-manager', 'dev.agentpass.native-manager'],
  ['AgentPass.app/Contents/MacOS/agentpass-onboarding', 'dev.agentpass']
].map(([identityPath, bundleId], index) => ({ path: identityPath, bundle_id: bundleId, team_id: teamId, code_directory_hash: String(index + 1).repeat(40) }));
const fixture = () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpass-scenario-')); const artifact = path.join(root, 'AgentPass.pkg'); const bytes = Buffer.from('candidate'); fs.writeFileSync(artifact, bytes, { mode: 0o600 });
  const executable = path.join(root, 'tool'); const tool = Buffer.from('#!/bin/sh\nexit 1\n'); fs.writeFileSync(executable, tool, { mode: 0o755 }); fs.chmodSync(executable, 0o755);
  const entry = { path: executable, sha256: digest(tool) };
  const rawConfig = { schema_version: 1, application_path: '/Applications/AgentPass.app', service_label: 'dev.agentpass.native-service', service_config_path: '/Library/Application Support/AgentPass/native-service.json', test_repository: root, cloud_probe_url: 'https://qualification.invalid/v1/probe', checkpoint_directory: path.join(root, 'checkpoints'), executables: { native_client: entry, native_manager: entry, native_service: entry, claude_code: entry, cursor: entry } };
  const env = { AGENTPASS_P0C_ARTIFACT_PATH: artifact, AGENTPASS_P0C_ARTIFACT_SHA256: digest(bytes), AGENTPASS_P0C_SOURCE_COMMIT: 'a'.repeat(40), AGENTPASS_P0C_TEAM_ID: teamId, AGENTPASS_P0C_CODE_IDENTITIES_JSON: JSON.stringify(codeIdentities), AGENTPASS_P0C_GATE: 'gatekeeper-notarization', AGENTPASS_P0C_TESTS_JSON: '["exact-pkg-install"]' };
  return { root, artifact, executable, entry, config: validateScenarioConfig(rawConfig), bindings: releaseBindings(env) };
};

test('scenario success requires exact declaration, release binding, and explicit proof list', async () => {
  const value = fixture();
  const result = await executePhysicalScenario({ gate: 'gatekeeper-notarization', tests: ['exact-pkg-install'], config: value.config, bindings: value.bindings, production: false, execute: async () => ['exact-pkg-install'] });
  assert.deepEqual(result, { schema_version: 1, gate: 'gatekeeper-notarization', status: 'passed', tests: [{ name: 'exact-pkg-install', status: 'passed' }], bindings: { artifact_sha256: value.bindings.artifactSha256, source_commit: 'a'.repeat(40), team_id: teamId, code_identities_sha256: digest(Buffer.from(JSON.stringify(codeIdentities))) } });
  assert.ok(canonicalJSON(result).equals(Buffer.from(`${JSON.stringify(result, null, 2)}\n`)));
  await assert.rejects(() => executePhysicalScenario({ gate: 'gatekeeper-notarization', tests: ['exact-pkg-install'], config: value.config, bindings: value.bindings, production: false, execute: async () => [] }), /prove every/);
  await assert.rejects(() => executePhysicalScenario({ gate: 'offline-expiry', tests: ['exact-pkg-install'], config: value.config, bindings: value.bindings, production: false, execute: async () => ['exact-pkg-install'] }), /does not match/);
});

test('fixed commands have bounded output, no shell, closed stdin, and fixed environment', async () => {
  // The full suite launches many child-process tests concurrently on CI. Keep
  // this deadline bounded without making scheduler contention a false failure.
  const successful = await runFixedCommand(process.execPath, ['-e', 'process.stdout.write(JSON.stringify({home:process.env.HOME,extra:process.env.EXTRA||null}))'], { timeoutMs: 5000 });
  assert.equal(successful.ok, true); assert.deepEqual(JSON.parse(successful.stdout), { home: '/var/empty', extra: null });
  const limited = await runFixedCommand(process.execPath, ['-e', 'process.stdout.write("x".repeat(1024))'], { timeoutMs: 5000, maxOutputBytes: 32 }); assert.equal(limited.ok, false); assert.equal(limited.outputLimit, true); assert.equal(limited.stdout.length, 32);
  await assert.rejects(() => runFixedCommand('relative', []), /invalid/);
  await assert.rejects(() => runFixedCommand(process.execPath, [], { env: { PATH: '/tmp' } }), /invalid/);
});

test('pinned executable replacement and artifact substitution fail closed', async () => {
  const value = fixture();
  await assert.rejects(() => runPinnedExecutable(value.entry, [], { production: false, executionStagingRoot: value.root, runCommand: async (command) => { fs.chmodSync(command, 0o700); fs.appendFileSync(command, 'mutation'); return { ok: true, stdout: Buffer.alloc(0) }; } }), /digest mismatch|unsafe/);
  fs.appendFileSync(value.artifact, 'tamper'); assert.throws(() => releaseBindings({ AGENTPASS_P0C_ARTIFACT_PATH: value.artifact, AGENTPASS_P0C_ARTIFACT_SHA256: value.bindings.artifactSha256, AGENTPASS_P0C_SOURCE_COMMIT: 'a'.repeat(40), AGENTPASS_P0C_TEAM_ID: teamId, AGENTPASS_P0C_CODE_IDENTITIES_JSON: JSON.stringify(codeIdentities), AGENTPASS_P0C_GATE: 'gatekeeper-notarization', AGENTPASS_P0C_TESTS_JSON: '["exact-pkg-install"]' }), /digest mismatch/);
});

test('pinned execution uses a private verified copy and cleans it after original-path substitution', async () => {
  const value = fixture();
  const original = fs.readFileSync(value.executable);
  let executedPath;
  await assert.rejects(() => runPinnedExecutable(value.entry, ['probe'], {
    production: false,
    executionStagingRoot: value.root,
    runCommand: async (command) => {
      executedPath = command;
      assert.notEqual(command, value.executable);
      assert.deepEqual(fs.readFileSync(command), original);
      fs.renameSync(value.executable, `${value.executable}.old`);
      fs.writeFileSync(value.executable, '#!/bin/sh\nexit 99\n', { mode: 0o755 });
      return { ok: true, stdout: Buffer.from('verified') };
    }
  }), /digest mismatch|changed during scenario/);
  assert.equal(fs.existsSync(executedPath), false);
  assert.equal(fs.existsSync(path.dirname(executedPath)), false);
  assert.notDeepEqual(fs.readFileSync(value.executable), original);
});

test('pinned execution rejects an unsafe staging root before running', async () => {
  const value = fixture();
  const unsafe = path.join(value.root, 'unsafe-stage');
  fs.mkdirSync(unsafe, { mode: 0o777 });
  fs.chmodSync(unsafe, 0o777);
  let invoked = false;
  await assert.rejects(() => runPinnedExecutable(value.entry, [], { production: false, executionStagingRoot: unsafe, runCommand: async () => { invoked = true; } }), /staging root is unsafe/);
  assert.equal(invoked, false);
});
