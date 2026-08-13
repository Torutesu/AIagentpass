import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { REQUIRED_GATES, inspectProvisioningSources, provisionRunner } from '../scripts/release/p0c/provision-runner.mjs';
import { canonicalJSON } from '../scripts/release/p0c/lib/scenario-runtime.mjs';
import crypto from 'node:crypto';

const repository = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const sourceRoot = path.join(repository, 'scripts/release/p0c');

const makeFixture = () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpass-p0c-provision-'));
  const parent = path.join(root, 'install'); fs.mkdirSync(parent, { mode: 0o700 });
  const scenarios = path.join(root, 'scenarios'); fs.mkdirSync(scenarios, { mode: 0o755 });
  for (const gate of REQUIRED_GATES) { const file = path.join(scenarios, gate); fs.writeFileSync(file, `#!/bin/sh\n# physical fixture ${gate}\nexit 1\n`, { mode: 0o755 }); fs.chmodSync(file, 0o755); }
  const tool = path.join(root, 'tool'); const toolBytes = Buffer.from('#!/bin/sh\nexit 1\n'); fs.writeFileSync(tool, toolBytes, { mode: 0o755 }); fs.chmodSync(tool, 0o755); const entry = { path: tool, sha256: crypto.createHash('sha256').update(toolBytes).digest('hex') };
  const machineConfig = path.join(root, 'machine-config.json'); fs.writeFileSync(machineConfig, canonicalJSON({ schema_version: 1, application_path: '/Applications/AgentPass.app', service_label: 'dev.agentpass.native-service', service_config_path: '/Library/Application Support/AgentPass/native-service.json', test_repository: root, cloud_probe_url: 'https://qualification.invalid/v1/probe', checkpoint_directory: path.join(root, 'checkpoints'), executables: { native_client: entry, native_manager: entry, native_service: entry, claude_code: entry, cursor: entry } }), { mode: 0o644 });
  return { root, parent, scenarios, machineConfig, destination: path.join(parent, 'p0c') };
};

test('non-production provisioning atomically installs the exact protected inventory', () => {
  const fixture = makeFixture(); const result = provisionRunner({ sourceRoot, scenarioDirectory: fixture.scenarios, machineConfigPath: fixture.machineConfig, destinationRoot: fixture.destination, production: false, uid: process.geteuid(), gid: process.getegid() });
  assert.deepEqual({ production: result.production, driver_count: result.driver_count, scenario_count: result.scenario_count }, { production: false, driver_count: 16, scenario_count: 16 });
  assert.deepEqual(fs.readdirSync(path.join(fixture.destination, 'gates')).sort(), [...REQUIRED_GATES]);
  assert.deepEqual(fs.readdirSync(path.join(fixture.destination, 'scenarios')).sort(), [...REQUIRED_GATES]);
  const config = JSON.parse(fs.readFileSync(path.join(fixture.destination, 'driver-config.json'), 'utf8'));
  assert.equal(config.scenario_directory, path.join(fixture.destination, 'scenarios')); assert.deepEqual(config.scenarios.map((item) => item.gate), [...REQUIRED_GATES]);
  assert.equal(fs.existsSync(path.join(fixture.destination, 'scenario-config.json')), true); assert.deepEqual(fs.readdirSync(path.join(fixture.destination, 'lib')).sort(), ['driver-runtime.mjs', 'scenario-runtime.mjs']);
  assert.equal(fs.readdirSync(fixture.parent).some((name) => name.startsWith('.p0c-stage-')), false);
});

test('provisioning refuses replacement, incomplete scenarios, and unsafe source links', () => {
  const existing = makeFixture(); fs.mkdirSync(existing.destination); assert.throws(() => provisionRunner({ sourceRoot, scenarioDirectory: existing.scenarios, machineConfigPath: existing.machineConfig, destinationRoot: existing.destination, production: false, uid: process.geteuid(), gid: process.getegid() }), /already exists/);
  const incomplete = makeFixture(); fs.unlinkSync(path.join(incomplete.scenarios, REQUIRED_GATES[0])); assert.throws(() => inspectProvisioningSources({ sourceRoot, scenarioDirectory: incomplete.scenarios, machineConfigPath: incomplete.machineConfig, production: false }), /exact inventory/);
  const linked = makeFixture(); const target = path.join(linked.scenarios, REQUIRED_GATES[1]); fs.unlinkSync(target); fs.symlinkSync('/bin/false', target); assert.throws(() => inspectProvisioningSources({ sourceRoot, scenarioDirectory: linked.scenarios, machineConfigPath: linked.machineConfig, production: false }), /exact inventory/);
});

test('production mode is fixed to root, macOS, and /opt destination', () => {
  const fixture = makeFixture();
  assert.throws(() => provisionRunner({ sourceRoot, scenarioDirectory: fixture.scenarios, machineConfigPath: fixture.machineConfig, destinationRoot: fixture.destination, production: true, platform: 'linux', uid: 0 }), /requires root on macOS/);
  assert.throws(() => provisionRunner({ sourceRoot, scenarioDirectory: fixture.scenarios, machineConfigPath: fixture.machineConfig, destinationRoot: fixture.destination, production: true, platform: 'darwin', uid: 501 }), /requires root on macOS/);
  assert.throws(() => provisionRunner({ sourceRoot, scenarioDirectory: fixture.scenarios, machineConfigPath: fixture.machineConfig, destinationRoot: fixture.destination, production: true, platform: 'darwin', uid: 0 }), /fixed destination/);
});
