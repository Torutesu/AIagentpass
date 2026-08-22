import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { QUALIFICATION_TOOL_FILES, REQUIRED_GATES, inspectProvisioningSources, provisionRunner, verifyInstalledTree } from '../scripts/release/p0c/provision-runner.mjs';
import { canonicalJSON } from '../scripts/release/p0c/lib/scenario-runtime.mjs';
import crypto from 'node:crypto';

const repository = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const sourceRoot = path.join(repository, 'scripts/release/p0c');
const EXPECTED_QUALIFICATION_TOOL_FILES = Object.freeze([
  'p0c/verify-runner-attestation.mjs',
  'generate-release-attestation.mjs',
  'release-candidate-identity.mjs',
  'n3e/controller-candidate-contract.mjs',
  'n3e/controller-identity-contract.mjs',
  'n3e/materialize-controller-candidate.mjs',
  'n3e/materialize-qualification-activation.mjs',
  'n3e/provision-qualification-config.mjs',
  'n3e/qualification-activation-contract.mjs',
  'n3e/qualification-canonical-json.mjs',
  'n3e/qualification-device-relay.mjs',
  'n3e/qualification-input-materializer.mjs',
  'n3e/qualification-release-materializer.mjs',
  'n3e/qualification-release-trust.mjs',
  'n3e/qualification-run-binding.mjs',
  'n3e/qualification-scenario-driver.mjs',
  'n3e/qualification-suite-evidence.mjs',
  'n3e/qualification-suite-input.mjs',
  'n3e/qualification-suite-orchestrator.mjs',
  'n3e/qualification-unarmed-control.mjs',
  'n3e/run-fixed-protected-qualification.mjs',
  'n3e/run-protected-qualification.mjs',
  'p0c/lib/candidate-checkpoint.mjs'
]);

const cloneSourceRoot = () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpass-p0c-source-'));
  const release = path.join(root, 'release');
  fs.mkdirSync(release, { mode: 0o755 });
  fs.cpSync(sourceRoot, path.join(release, 'p0c'), { recursive: true });
  fs.cpSync(path.join(repository, 'scripts/release/n3e'), path.join(release, 'n3e'), { recursive: true });
  fs.copyFileSync(path.join(repository, 'scripts/release/generate-release-attestation.mjs'), path.join(release, 'generate-release-attestation.mjs'));
  return path.join(release, 'p0c');
};

const makeFixture = () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpass-p0c-provision-'));
  const parent = path.join(root, 'install'); fs.mkdirSync(parent, { mode: 0o700 });
  const scenarios = path.join(root, 'scenarios'); fs.mkdirSync(scenarios, { mode: 0o755 });
  for (const gate of REQUIRED_GATES) { const file = path.join(scenarios, gate); fs.writeFileSync(file, `#!/bin/sh\n# physical fixture ${gate}\nexit 1\n`, { mode: 0o755 }); fs.chmodSync(file, 0o755); }
  const tool = path.join(root, 'tool'); const toolBytes = Buffer.from('#!/bin/sh\nexit 1\n'); fs.writeFileSync(tool, toolBytes, { mode: 0o755 }); fs.chmodSync(tool, 0o755); const entry = { path: tool, sha256: crypto.createHash('sha256').update(toolBytes).digest('hex') };
  const qualificationClient = path.join(root, 'agentpass-qualification-grant-client'); const qualificationClientBytes = Buffer.from('#!/bin/sh\nexec /opt/agentpass/p0c/qualification-client/agentpass-qualification-grant-client.app/Contents/MacOS/agentpass-qualification-grant-client "$@"\n'); fs.writeFileSync(qualificationClient, qualificationClientBytes, { mode: 0o755 }); fs.chmodSync(qualificationClient, 0o755);
  const qualificationClientApp = `${qualificationClient}.app`; fs.mkdirSync(path.join(qualificationClientApp, 'Contents', 'MacOS'), { recursive: true, mode: 0o755 }); fs.writeFileSync(path.join(qualificationClientApp, 'Contents', 'Info.plist'), '<plist/>\n', { mode: 0o644 }); fs.writeFileSync(path.join(qualificationClientApp, 'Contents', 'embedded.provisionprofile'), 'profile\n', { mode: 0o644 }); fs.writeFileSync(path.join(qualificationClientApp, 'Contents', 'MacOS', 'agentpass-qualification-grant-client'), '#!/bin/sh\nexit 0\n', { mode: 0o755 });
  const machineConfig = path.join(root, 'machine-config.json'); fs.writeFileSync(machineConfig, canonicalJSON({ schema_version: 1, application_path: '/Applications/AgentPass.app', service_label: 'dev.agentpass.native-service', service_config_path: '/Library/Application Support/AgentPass/native-service.json', test_repository: root, cloud_probe_url: 'https://qualification.invalid/v1/probe', checkpoint_directory: path.join(root, 'checkpoints'), executables: { native_client: entry, native_manager: entry, native_service: entry, claude_code: entry, cursor: entry, qualification_grant_client: { path: '/opt/agentpass/p0c/qualification-client/agentpass-qualification-grant-client', sha256: crypto.createHash('sha256').update(qualificationClientBytes).digest('hex') } } }), { mode: 0o644 });
  return { root, parent, scenarios, machineConfig, qualificationClient, qualificationClientApp, destination: path.join(parent, 'p0c') };
};

test('non-production provisioning atomically installs the exact protected inventory', () => {
  assert.deepEqual(QUALIFICATION_TOOL_FILES.map(({ installed }) => installed), EXPECTED_QUALIFICATION_TOOL_FILES);
  const fixture = makeFixture(); const result = provisionRunner({ sourceRoot, scenarioDirectory: fixture.scenarios, machineConfigPath: fixture.machineConfig, qualificationClientPath: fixture.qualificationClient, destinationRoot: fixture.destination, production: false, uid: process.geteuid(), gid: process.getegid() });
  assert.deepEqual({ production: result.production, driver_count: result.driver_count, scenario_count: result.scenario_count }, { production: false, driver_count: 16, scenario_count: 16 });
  assert.deepEqual(fs.readdirSync(path.join(fixture.destination, 'gates')).sort(), [...REQUIRED_GATES]);
  assert.deepEqual(fs.readdirSync(path.join(fixture.destination, 'scenarios')).sort(), [...REQUIRED_GATES]);
  const config = JSON.parse(fs.readFileSync(path.join(fixture.destination, 'driver-config.json'), 'utf8'));
  assert.equal(config.scenario_directory, path.join(fixture.destination, 'scenarios')); assert.deepEqual(config.scenarios.map((item) => item.gate), [...REQUIRED_GATES]);
  assert.equal(fs.existsSync(path.join(fixture.destination, 'scenario-config.json')), true); assert.deepEqual(fs.readdirSync(path.join(fixture.destination, 'lib')).sort(), ['candidate-checkpoint.mjs', 'driver-runtime.mjs', 'scenario-runtime.mjs']);
  assert.equal(result.qualification_tool_path, path.join(fixture.destination, 'qualification-tool/n3e/provision-qualification-config.mjs'));
  assert.equal(result.qualification_orchestrator_path, path.join(fixture.destination, 'qualification-tool/n3e/run-protected-qualification.mjs'));
  assert.equal(result.fixed_qualification_entrypoint_path, path.join(fixture.destination, 'qualification-tool/n3e/run-fixed-protected-qualification.mjs'));
  assert.equal(result.qualification_scenario_driver_path, path.join(fixture.destination, 'qualification-tool/n3e/qualification-scenario-driver.mjs'));
  assert.equal(result.qualification_client_path, path.join(fixture.destination, 'qualification-client/agentpass-qualification-grant-client'));
  assert.equal(result.qualification_client_app_path, path.join(fixture.destination, 'qualification-client/agentpass-qualification-grant-client.app'));
  assert.equal(fs.statSync(path.join(fixture.destination, 'qualification-client')).mode & 0o777, 0o700);
  assert.equal(fs.statSync(result.qualification_client_path).mode & 0o777, 0o755);
  assert.equal(fs.statSync(result.qualification_client_path).nlink, 1);
  assert.match(fs.readFileSync(result.qualification_client_path, 'utf8'), /agentpass-qualification-grant-client\.app\/Contents\/MacOS\/agentpass-qualification-grant-client/u);
  assert.equal(fs.existsSync(path.join(result.qualification_client_app_path, 'Contents/embedded.provisionprofile')), true);
  assert.deepEqual(fs.readdirSync(path.join(fixture.destination, 'qualification-tool')).sort(), ['generate-release-attestation.mjs', 'manifest.json', 'n3e', 'p0c', 'release-candidate-identity.mjs']);
  assert.deepEqual(fs.readdirSync(path.join(fixture.destination, 'qualification-tool/p0c/lib')).sort(), ['candidate-checkpoint.mjs']);
  assert.deepEqual(fs.readdirSync(path.join(fixture.destination, 'qualification-tool/n3e')).sort(), QUALIFICATION_TOOL_FILES.filter(({ installed }) => installed.startsWith('n3e/')).map(({ installed }) => installed.slice('n3e/'.length)));
  const toolManifest = JSON.parse(fs.readFileSync(path.join(fixture.destination, 'qualification-tool/manifest.json'), 'utf8'));
  assert.equal(toolManifest.schema_version, 1); assert.deepEqual(toolManifest.files.map((item) => item.path), QUALIFICATION_TOOL_FILES.map(({ installed }) => installed));
  for (const item of toolManifest.files) assert.equal(item.sha256, crypto.createHash('sha256').update(fs.readFileSync(path.join(fixture.destination, 'qualification-tool', item.path))).digest('hex'));
  assert.equal(result.qualification_tool_manifest_sha256, crypto.createHash('sha256').update(fs.readFileSync(path.join(fixture.destination, 'qualification-tool/manifest.json'))).digest('hex'));
  assert.equal(fs.readdirSync(fixture.parent).some((name) => name.startsWith('.p0c-stage-')), false);
});

test('installed fixed entrypoints resolve every packaged production dependency', async () => {
  const fixture = makeFixture();
  provisionRunner({ sourceRoot, scenarioDirectory: fixture.scenarios, machineConfigPath: fixture.machineConfig, qualificationClientPath: fixture.qualificationClient, destinationRoot: fixture.destination, production: false, uid: process.geteuid(), gid: process.getegid() });
  for (const name of ['qualification-canonical-json.mjs', 'qualification-device-relay.mjs', 'qualification-suite-evidence.mjs', 'qualification-input-materializer.mjs', 'qualification-release-materializer.mjs', 'qualification-suite-orchestrator.mjs', 'run-fixed-protected-qualification.mjs']) {
    const module = await import(`${pathToFileURL(path.join(fixture.destination, 'qualification-tool/n3e', name)).href}?fixture=${encodeURIComponent(fixture.root)}`);
    assert.equal(typeof module, 'object');
  }
});

test('qualification driver, fixed entrypoint, unarmed control, and activation dependency omission and source substitution are rejected before installation', () => {
  const fixture = makeFixture();
  for (const file of ['qualification-input-materializer.mjs', 'qualification-release-materializer.mjs', 'qualification-release-trust.mjs', 'qualification-run-binding.mjs', 'qualification-scenario-driver.mjs', 'qualification-suite-input.mjs', 'qualification-suite-orchestrator.mjs', 'qualification-unarmed-control.mjs', 'run-fixed-protected-qualification.mjs', 'qualification-activation-contract.mjs', 'materialize-qualification-activation.mjs']) {
    const omittedRoot = cloneSourceRoot();
    fs.unlinkSync(path.join(path.dirname(omittedRoot), 'n3e', file));
    assert.throws(() => inspectProvisioningSources({ sourceRoot: omittedRoot, scenarioDirectory: fixture.scenarios, machineConfigPath: fixture.machineConfig, qualificationClientPath: fixture.qualificationClient, production: false }), /provisioning source is unavailable/);

    const substitutedRoot = cloneSourceRoot();
    const substituted = path.join(path.dirname(substitutedRoot), 'n3e', file);
    fs.unlinkSync(substituted);
    fs.symlinkSync(path.join(path.dirname(substitutedRoot), 'n3e/provision-qualification-config.mjs'), substituted);
    assert.throws(() => inspectProvisioningSources({ sourceRoot: substitutedRoot, scenarioDirectory: fixture.scenarios, machineConfigPath: fixture.machineConfig, qualificationClientPath: fixture.qualificationClient, production: false }), /provisioning source is unavailable/);
  }
});

test('installed qualification driver, fixed entrypoint, unarmed control, and activation dependencies fail closed on omission and substitution', () => {
  for (const file of ['qualification-input-materializer.mjs', 'qualification-release-materializer.mjs', 'qualification-release-trust.mjs', 'qualification-run-binding.mjs', 'qualification-scenario-driver.mjs', 'qualification-suite-input.mjs', 'qualification-suite-orchestrator.mjs', 'qualification-unarmed-control.mjs', 'run-fixed-protected-qualification.mjs', 'qualification-activation-contract.mjs', 'materialize-qualification-activation.mjs']) {
    const fixture = makeFixture();
    provisionRunner({ sourceRoot, scenarioDirectory: fixture.scenarios, machineConfigPath: fixture.machineConfig, qualificationClientPath: fixture.qualificationClient, destinationRoot: fixture.destination, production: false, uid: process.geteuid(), gid: process.getegid() });
    const inspected = inspectProvisioningSources({ sourceRoot, scenarioDirectory: fixture.scenarios, machineConfigPath: fixture.machineConfig, qualificationClientPath: fixture.qualificationClient, production: false });
    const installed = path.join(fixture.destination, 'qualification-tool/n3e', file);
    fs.unlinkSync(installed);
    assert.throws(() => verifyInstalledTree(fixture.destination, inspected, process.geteuid()), /exact inventory/);

    fs.writeFileSync(installed, Buffer.from(`substituted ${file}\n`), { mode: 0o644 });
    assert.throws(() => verifyInstalledTree(fixture.destination, inspected, process.geteuid()), /digest mismatch|not root-owned 0755/u);
  }
});

test('provisioning refuses replacement, incomplete scenarios, and unsafe source links', () => {
  const existing = makeFixture(); fs.mkdirSync(existing.destination); assert.throws(() => provisionRunner({ sourceRoot, scenarioDirectory: existing.scenarios, machineConfigPath: existing.machineConfig, qualificationClientPath: existing.qualificationClient, destinationRoot: existing.destination, production: false, uid: process.geteuid(), gid: process.getegid() }), /already exists/);
  const incomplete = makeFixture(); fs.unlinkSync(path.join(incomplete.scenarios, REQUIRED_GATES[0])); assert.throws(() => inspectProvisioningSources({ sourceRoot, scenarioDirectory: incomplete.scenarios, machineConfigPath: incomplete.machineConfig, qualificationClientPath: incomplete.qualificationClient, production: false }), /exact inventory/);
  const linked = makeFixture(); const target = path.join(linked.scenarios, REQUIRED_GATES[1]); fs.unlinkSync(target); fs.symlinkSync('/bin/false', target); assert.throws(() => inspectProvisioningSources({ sourceRoot, scenarioDirectory: linked.scenarios, machineConfigPath: linked.machineConfig, qualificationClientPath: linked.qualificationClient, production: false }), /exact inventory/);
});

test('production mode is fixed to root, macOS, and /opt destination', () => {
  const fixture = makeFixture();
  assert.throws(() => provisionRunner({ sourceRoot, scenarioDirectory: fixture.scenarios, machineConfigPath: fixture.machineConfig, qualificationClientPath: fixture.qualificationClient, destinationRoot: fixture.destination, production: true, platform: 'linux', uid: 0 }), /requires root on macOS/);
  assert.throws(() => provisionRunner({ sourceRoot, scenarioDirectory: fixture.scenarios, machineConfigPath: fixture.machineConfig, qualificationClientPath: fixture.qualificationClient, destinationRoot: fixture.destination, production: true, platform: 'darwin', uid: 501 }), /requires root on macOS/);
  assert.throws(() => provisionRunner({ sourceRoot, scenarioDirectory: fixture.scenarios, machineConfigPath: fixture.machineConfig, qualificationClientPath: fixture.qualificationClient, destinationRoot: fixture.destination, production: true, platform: 'darwin', uid: 0 }), /fixed destination/);
});
