import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import { chmodSync, copyFileSync, linkSync, mkdirSync, mkdtempSync, readFileSync, symlinkSync, unlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import test from 'node:test';

import { REQUIRED_CODE_IDENTITIES, buildReleaseAttestation, canonicalJSON as canonicalAttestation } from '../generate-release-attestation.mjs';
import { canonicalJSON as canonicalControllerIdentity, designatedRequirementForTeam } from './controller-identity-contract.mjs';
import {
  QUALIFICATION_FIELDS,
  SCENARIO_PHASE,
  provisionQualificationConfig,
  restoreQualificationConfig
} from './provision-qualification-config.mjs';

const root = resolve(import.meta.dirname, '../../..');
const expectedUid = process.getuid();
if (typeof expectedUid !== 'number') throw new Error('this test requires a POSIX process owner');

const packageVersion = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')).version;
const controllerTeamId = 'ABCDE12345';
const controllerArchiveName = `AgentPassQualificationController-${packageVersion}-macos-universal.tar`;
const controllerSubmission = 'fedcba98-7654-3210-fedc-ba9876543210';
const controllerHashes = Object.freeze({ arm64: 'a'.repeat(40), x86_64: 'b'.repeat(40) });
const runId = '987654321';
const runIdBytes = Buffer.from(runId, 'utf8');
const canonical = (value) => Buffer.from(`${JSON.stringify(value, null, 2)}\n`, 'utf8');
const digest = (value) => crypto.createHash('sha256').update(value).digest('hex');
const actualFingerprint = (publicKey) => `SHA256:${crypto.createHash('sha256').update(publicKey.export({ type: 'spki', format: 'der' })).digest('base64url')}`;
const runReleaseScript = (name, args) => execFileSync(process.execPath, [join(root, 'scripts/release', name), ...args], { cwd: root, encoding: 'utf8' });

const writeDetachedSignature = (path, bytes, privateKey) => {
  writeFileSync(path, `${crypto.sign(null, bytes, privateKey).toString('base64')}\n`, { mode: 0o644 });
  chmodSync(path, 0o644);
};

const baseServiceConfig = Object.freeze({
  mach_service_name: 'dev.agentpass.native-service',
  agent_mach_service_name: 'dev.agentpass.agent-session',
  key_tag: 'dev.agentpass.signing-key',
  policy_path: '/Library/Application Support/AgentPass/policy.json',
  audit_log_path: '/Library/Application Support/AgentPass/audit.log',
  client_code_signing_requirement: 'anchor apple generic and identifier "dev.agentpass.native-client"',
  agent_client_code_signing_requirement: 'anchor apple generic and identifier "dev.agentpass.agent"',
  keychain_access_group: 'ABCDE12345.dev.agentpass'
});

const controllerIdentityFor = (archiveBytes) => {
  const entitlements = Buffer.from('<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict><key>dev.agentpass.qualification-control</key><true/></dict></plist>', 'utf8');
  return {
    schema_version: 1,
    kind: 'agentpass-n3e-external-qualification-controller-identity',
    archive_name: controllerArchiveName,
    archive_sha256: digest(archiveBytes),
    archive_bytes: archiveBytes.length,
    bundle_id: 'dev.agentpass.qualification-controller',
    team_id: controllerTeamId,
    entitlements_sha256: digest(entitlements),
    code_directory_hashes: ['arm64', 'x86_64'].map((architecture) => ({ architecture, hash: controllerHashes[architecture] })),
    designated_requirements: ['arm64', 'x86_64'].map((architecture) => ({
      architecture,
      requirement: `identifier "dev.agentpass.qualification-controller" and anchor apple generic ${architecture}`
    })),
    authorization_requirements: ['arm64', 'x86_64'].map((architecture) => ({
      architecture,
      requirement: designatedRequirementForTeam(controllerTeamId, controllerHashes[architecture])
    }))
  };
};

const attestationFor = () => buildReleaseAttestation({
  teamId: controllerTeamId,
  cloudImageDigest: `sha256:${'1'.repeat(64)}`,
  dependencyLockSha256: '2'.repeat(64),
  databaseMigrationManifestSha256: '3'.repeat(64),
  nestedCodeIdentities: REQUIRED_CODE_IDENTITIES.map((identity, index) => ({
    path: identity.path,
    bundle_id: identity.bundle_id,
    team_id: controllerTeamId,
    code_directory_hash: (index.toString(16) + '4').repeat(20).slice(0, 40)
  })),
  signerKeyVersions: [
    { name: 'audit', version: 'v1' },
    { name: 'release', version: 'v2' }
  ]
});

const createSignedReleaseV3 = () => {
  const directory = mkdtempSync(join(tmpdir(), 'agentpass-provision-release-'));
  const productName = `AgentPass-v${packageVersion}-macos-universal.pkg`;
  const productPath = join(directory, productName);
  const controllerArchivePath = join(directory, controllerArchiveName);
  const controllerIdentityPath = join(directory, 'AgentPassQualificationController.identity.json');
  const attestationPath = join(directory, 'release-attestation.json');
  const sbomPath = join(directory, `AgentPass-${packageVersion}.spdx.json`);
  const manifestPath = join(directory, `AgentPass-${packageVersion}.release-manifest.json`);
  const sumsPath = join(directory, 'SHA256SUMS');
  const signaturePath = join(directory, `AgentPass-${packageVersion}.release-manifest.sig`);
  const publicKeyPath = join(directory, 'release.public.pem');
  const privateKeyPath = join(directory, 'release.private.pem');
  const controllerNotarytoolPath = join(directory, 'controller-notarytool-result.json');
  const controllerStaplerPath = join(directory, 'controller-stapler-result.txt');
  const keys = crypto.generateKeyPairSync('ed25519');
  const controllerArchive = Buffer.from('Mach-O universal qualification controller archive fixture\n', 'utf8');

  writeFileSync(productPath, Buffer.from('signed Apple installer package fixture\n'), { mode: 0o644 });
  writeFileSync(controllerArchivePath, controllerArchive, { mode: 0o644 });
  writeFileSync(controllerIdentityPath, canonicalControllerIdentity(controllerIdentityFor(controllerArchive)), { mode: 0o644 });
  writeFileSync(attestationPath, canonicalAttestation(attestationFor()), { mode: 0o644 });
  writeFileSync(controllerNotarytoolPath, JSON.stringify({ id: controllerSubmission, status: 'Accepted', message: 'Controller Approved' }), { mode: 0o644 });
  writeFileSync(controllerStaplerPath, 'Processing: AgentPassQualificationController.app\nThe validate action worked!\n', { mode: 0o644 });
  writeFileSync(privateKeyPath, keys.privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
  chmodSync(privateKeyPath, 0o600);
  writeFileSync(publicKeyPath, keys.publicKey.export({ type: 'spki', format: 'pem' }), { mode: 0o644 });

  runReleaseScript('generate-sbom.mjs', [sbomPath]);
  runReleaseScript('generate-manifest.mjs', [
    manifestPath,
    sumsPath,
    `--controller-identity=${controllerIdentityPath}`,
    '--controller-notarization-status=accepted_stapled',
    `--controller-notary-submission=${controllerSubmission}`,
    `--controller-notarytool-evidence=${controllerNotarytoolPath}`,
    `--controller-stapler-evidence=${controllerStaplerPath}`,
    productPath,
    controllerArchivePath,
    sbomPath,
    attestationPath
  ]);
  const manifestBytes = readFileSync(manifestPath);
  writeDetachedSignature(signaturePath, manifestBytes, keys.privateKey);

  return Object.freeze({
    directory,
    productName,
    productPath,
    controllerArchivePath,
    controllerIdentityPath,
    attestationPath,
    sbomPath,
    manifestPath,
    sumsPath,
    signaturePath,
    publicKeyPath,
    privateKeyPath,
    controllerNotarytoolPath,
    controllerStaplerPath,
    fingerprint: actualFingerprint(keys.publicKey),
    keys
  });
};

const release = createSignedReleaseV3();
const releaseFiles = [
  'productPath', 'controllerArchivePath', 'controllerIdentityPath', 'attestationPath',
  'sbomPath', 'manifestPath', 'sumsPath', 'signaturePath', 'publicKeyPath',
  'controllerNotarytoolPath', 'controllerStaplerPath'
];

const copyRelease = (directory) => {
  const releaseDirectory = join(directory, 'release');
  mkdirSync(releaseDirectory, 0o700);
  const copied = {};
  for (const key of releaseFiles) {
    const source = release[key];
    const destination = join(releaseDirectory, source.slice(source.lastIndexOf('/') + 1));
    copyFileSync(source, destination);
    copied[key] = destination;
  }
  return copied;
};

const protectedFile = (path, bytes, mode = 0o600) => {
  writeFileSync(path, bytes, { mode });
  chmodSync(path, mode);
  return path;
};

const makeCase = ({ serviceValue = baseServiceConfig, run = runId } = {}) => {
  const directory = mkdtempSync(join(tmpdir(), 'agentpass-provision-case-'));
  const protectedDirectory = join(directory, 'protected');
  mkdirSync(protectedDirectory, 0o700);
  const copiedRelease = copyRelease(directory);
  const serviceConfigPath = join(protectedDirectory, 'native-service.json');
  const statePath = join(protectedDirectory, 'n3e-qualification-provision.json');
  const runBindingPath = join(protectedDirectory, 'run-binding');
  const originalBytes = canonical(serviceValue);
  protectedFile(serviceConfigPath, originalBytes);
  protectedFile(runBindingPath, Buffer.from(run, 'utf8'));
  return {
    directory,
    protectedDirectory,
    serviceConfigPath,
    statePath,
    runBindingPath,
    originalBytes,
    releaseDirectory: join(directory, 'release'),
    ...copiedRelease
  };
};

const provision = (fixture, options = {}) => provisionQualificationConfig({
  manifestPath: fixture.manifestPath,
  signaturePath: fixture.signaturePath,
  publicKeyPath: fixture.publicKeyPath,
  expectedFingerprint: release.fingerprint,
  productPath: fixture.productPath,
  runBindingPath: fixture.runBindingPath,
  scenario: 'pre-cloud-kill',
  expiresAtEpochSeconds: 1_700_000_120,
  serviceConfigPath: fixture.serviceConfigPath,
  statePath: fixture.statePath,
  expectedUid,
  nowEpochSeconds: 1_700_000_000,
  architecture: 'arm64',
  ...options
});

const expectFailure = (fixture, action, pattern = /qualification|release|manifest|controller|unsafe|invalid|mismatch|signature|identity|attestation/iu) => {
  assert.throws(action, pattern);
  assert.deepEqual(readFileSync(fixture.serviceConfigPath), fixture.originalBytes);
  assert.equal(fs.existsSync(fixture.statePath), false);
};

test('provisions signed release-v3 data, selects arm64 CDHash, and restores exact original bytes', () => {
  const fixture = makeCase();
  const result = provision(fixture);
  const manifest = JSON.parse(readFileSync(fixture.manifestPath));
  const attestation = JSON.parse(readFileSync(fixture.attestationPath));
  const qualifiedBytes = readFileSync(fixture.serviceConfigPath);
  const stateBytes = readFileSync(fixture.statePath);
  const state = JSON.parse(stateBytes);

  assert.deepEqual(result, {
    ok: true,
    action: 'provisioned',
    architecture: 'arm64',
    candidate_sha256: manifest.artifacts.find((item) => item.role === 'product').sha256,
    controller_cdhash: controllerHashes.arm64,
    run_id_sha256: digest(runIdBytes),
    config_sha256: digest(qualifiedBytes),
    expires_at_epoch_seconds: 1_700_000_120,
    scenario: 'pre-cloud-kill',
    phase: 'pre-cloud'
  });
  assert.equal(JSON.parse(qualifiedBytes).qualification_controller_cdhash, controllerHashes.arm64);
  assert.equal(JSON.parse(qualifiedBytes).qualification_run_id_sha256, digest(runIdBytes));
  assert.equal(state.original_config_base64, fixture.originalBytes.toString('base64'));
  assert.equal(state.qualified_config_sha256, digest(qualifiedBytes));
  assert.equal(state.architecture, 'arm64');
  assert.equal(state.phase, 'pre-cloud');
  assert.equal(state.source_commit_sha256, digest(Buffer.from(manifest.source.commit, 'utf8')));
  assert.equal(state.code_identities_sha256, digest(Buffer.from(JSON.stringify(attestation.nested_code_identities), 'utf8')));
  assert.ok(!Buffer.concat([qualifiedBytes, stateBytes, Buffer.from(JSON.stringify(result))]).includes(runIdBytes));
  assert.equal((fs.statSync(fixture.serviceConfigPath).mode & 0o7777), 0o600);
  assert.equal((fs.statSync(fixture.statePath).mode & 0o7777), 0o600);

  const restored = restoreQualificationConfig({ serviceConfigPath: fixture.serviceConfigPath, statePath: fixture.statePath, expectedUid });
  assert.deepEqual(restored, { ok: true, action: 'restored', original_config_sha256: digest(fixture.originalBytes) });
  assert.deepEqual(readFileSync(fixture.serviceConfigPath), fixture.originalBytes);
  assert.equal(fs.existsSync(fixture.statePath), false);
});

test('selects the x86_64 CDHash independently of the arm64 slice', () => {
  const fixture = makeCase();
  const result = provision(fixture, { architecture: 'x86_64' });
  assert.equal(result.controller_cdhash, controllerHashes.x86_64);
  assert.equal(JSON.parse(readFileSync(fixture.serviceConfigPath)).qualification_controller_cdhash, controllerHashes.x86_64);
  restoreQualificationConfig({ serviceConfigPath: fixture.serviceConfigPath, statePath: fixture.statePath, expectedUid });
});

test('accepts exactly all six closed scenario/phase pairs and restores each run', () => {
  for (const [scenario, phase] of Object.entries(SCENARIO_PHASE)) {
    const fixture = makeCase();
    const result = provision(fixture, { scenario, expiresAtEpochSeconds: 1_700_000_121 });
    assert.equal(result.scenario, scenario);
    assert.equal(result.phase, phase);
    assert.equal(JSON.parse(readFileSync(fixture.serviceConfigPath)).qualification_phase, phase);
    restoreQualificationConfig({ serviceConfigPath: fixture.serviceConfigPath, statePath: fixture.statePath, expectedUid });
    assert.deepEqual(readFileSync(fixture.serviceConfigPath), fixture.originalBytes);
  }
});

test('rejects stale and overlong expiries without creating state or changing config', () => {
  for (const expiresAtEpochSeconds of [1_700_000_000, 1_699_999_999, 1_700_000_901]) {
    const fixture = makeCase();
    expectFailure(fixture, () => provision(fixture, { expiresAtEpochSeconds }), /expiry is invalid/iu);
  }
});

test('rejects partial and complete pre-existing qualification authority fields', () => {
  const partial = makeCase({ serviceValue: { ...baseServiceConfig, qualification_mode: 'n3e-qualification' } });
  expectFailure(partial, () => provision(partial), /already contains qualification authority/iu);

  const completeValues = {
    qualification_mode: 'n3e-qualification',
    qualification_mach_service_name: 'dev.agentpass.n3e-qualification',
    qualification_candidate_sha256: '1'.repeat(64),
    qualification_source_commit_sha256: '2'.repeat(64),
    qualification_code_identities_sha256: '3'.repeat(64),
    qualification_controller_cdhash: '4'.repeat(40),
    qualification_run_id_sha256: '5'.repeat(64),
    qualification_expires_at_epoch_seconds: 1_700_000_120,
    qualification_scenario: 'pre-cloud-kill',
    qualification_phase: 'pre-cloud'
  };
  const complete = makeCase({ serviceValue: { ...baseServiceConfig, ...completeValues } });
  expectFailure(complete, () => provision(complete), /already contains qualification authority/iu);
});

test('rejects invalid signature, fingerprint, product, attestation, and identity bindings', () => {
  const cases = [
    ['signature', (fixture) => writeFileSync(fixture.signaturePath, 'not-a-signature\n'), /signature (?:encoding is|is) invalid/iu],
    ['fingerprint', () => {}, /fingerprint mismatch/iu],
    ['product', (fixture) => writeFileSync(fixture.productPath, 'substituted product\n'), /product does not match/iu],
    ['attestation', (fixture) => writeFileSync(fixture.attestationPath, `${readFileSync(fixture.attestationPath, 'utf8')}\n`), /attestation digest mismatch/iu],
    ['identity', (fixture) => writeFileSync(fixture.controllerIdentityPath, '{}\n'), /identity document digest mismatch/iu]
  ];
  for (const [kind, mutate, pattern] of cases) {
    const fixture = makeCase();
    mutate(fixture);
    const action = () => provision(fixture, kind === 'fingerprint' ? { expectedFingerprint: `SHA256:${'A'.repeat(43)}` } : {});
    expectFailure(fixture, action, pattern);
  }
});

test('rejects unsafe modes, symlinks, hardlinks, and writable protected parents', () => {
  const configMode = makeCase();
  chmodSync(configMode.serviceConfigPath, 0o644);
  expectFailure(configMode, () => provision(configMode), /service configuration has an unsafe mode/iu);

  const runMode = makeCase();
  chmodSync(runMode.runBindingPath, 0o644);
  expectFailure(runMode, () => provision(runMode), /qualification run binding has an unsafe mode/iu);

  const configSymlink = makeCase();
  const configTarget = join(configSymlink.protectedDirectory, 'config-target');
  copyFileSync(configSymlink.serviceConfigPath, configTarget);
  unlinkSync(configSymlink.serviceConfigPath);
  symlinkSync(configTarget, configSymlink.serviceConfigPath);
  expectFailure(configSymlink, () => provision(configSymlink), /service configuration is unavailable/iu);

  const configHardlink = makeCase();
  const configHardlinkTarget = join(configHardlink.protectedDirectory, 'config-hardlink-target');
  linkSync(configHardlink.serviceConfigPath, configHardlinkTarget);
  expectFailure(configHardlink, () => provision(configHardlink), /service configuration is unsafe/iu);

  const runSymlink = makeCase();
  const runTarget = join(runSymlink.protectedDirectory, 'run-target');
  copyFileSync(runSymlink.runBindingPath, runTarget);
  unlinkSync(runSymlink.runBindingPath);
  symlinkSync(runTarget, runSymlink.runBindingPath);
  expectFailure(runSymlink, () => provision(runSymlink), /qualification run binding is unavailable/iu);

  const runHardlink = makeCase();
  linkSync(runHardlink.runBindingPath, join(runHardlink.protectedDirectory, 'run-hardlink-target'));
  expectFailure(runHardlink, () => provision(runHardlink), /qualification run binding is unsafe/iu);

  const stateSymlink = makeCase();
  const stateTarget = join(stateSymlink.protectedDirectory, 'state-target');
  protectedFile(stateTarget, Buffer.from('{}\n'));
  symlinkSync(stateTarget, stateSymlink.statePath);
  assert.throws(() => provision(stateSymlink), /state already exists/iu);
  assert.deepEqual(readFileSync(stateSymlink.serviceConfigPath), stateSymlink.originalBytes);
  assert.equal(fs.existsSync(stateSymlink.statePath), true);

  const stateHardlink = makeCase();
  const stateHardlinkTarget = join(stateHardlink.protectedDirectory, 'state-hardlink-target');
  protectedFile(stateHardlinkTarget, Buffer.from('{}\n'));
  linkSync(stateHardlinkTarget, stateHardlink.statePath);
  assert.throws(() => provision(stateHardlink), /state already exists/iu);
  assert.deepEqual(readFileSync(stateHardlink.serviceConfigPath), stateHardlink.originalBytes);
  assert.equal(fs.existsSync(stateHardlink.statePath), true);

  const parentMode = makeCase();
  chmodSync(parentMode.protectedDirectory, 0o775);
  expectFailure(parentMode, () => provision(parentMode), /service configuration parent is unsafe/iu);
});

test('refuses state and config substitution during restore', () => {
  const stateSubstitution = makeCase();
  provision(stateSubstitution);
  const otherState = makeCase();
  provision(otherState, { architecture: 'x86_64' });
  writeFileSync(stateSubstitution.statePath, readFileSync(otherState.statePath), { mode: 0o600 });
  assert.throws(() => restoreQualificationConfig({ serviceConfigPath: stateSubstitution.serviceConfigPath, statePath: stateSubstitution.statePath, expectedUid }), /state identity|config_path|changed after qualification/iu);
  assert.notDeepEqual(readFileSync(stateSubstitution.serviceConfigPath), stateSubstitution.originalBytes);
  assert.equal(fs.existsSync(stateSubstitution.statePath), true);

  const configSubstitution = makeCase();
  provision(configSubstitution);
  writeFileSync(configSubstitution.serviceConfigPath, canonical({ ...baseServiceConfig, substituted: true }), { mode: 0o600 });
  assert.throws(() => restoreQualificationConfig({ serviceConfigPath: configSubstitution.serviceConfigPath, statePath: configSubstitution.statePath, expectedUid }), /changed after qualification provisioning/iu);
  assert.equal(fs.existsSync(configSubstitution.statePath), true);
});

test('recovers idempotently when state was durable but config replacement had not happened', () => {
  const fixture = makeCase();
  provision(fixture);
  const qualifiedState = readFileSync(fixture.statePath);
  writeFileSync(fixture.serviceConfigPath, fixture.originalBytes, { mode: 0o600 });
  const restored = restoreQualificationConfig({ serviceConfigPath: fixture.serviceConfigPath, statePath: fixture.statePath, expectedUid });
  assert.deepEqual(restored, { ok: true, action: 'restored', original_config_sha256: digest(fixture.originalBytes) });
  assert.deepEqual(readFileSync(fixture.serviceConfigPath), fixture.originalBytes);
  assert.equal(fs.existsSync(fixture.statePath), false);
  assert.ok(qualifiedState.length > 0);
});

test('detects architecture only from the injected macOS command boundary', async () => {
  const { detectControllerArchitecture } = await import('./provision-qualification-config.mjs');
  assert.equal(detectControllerArchitecture({
    platform: 'darwin',
    runCommand: (command) => command === '/usr/sbin/sysctl' ? { status: 0, signal: null, stdout: '0\n' } : { status: 0, signal: null, stdout: 'x86_64\n' }
  }), 'x86_64');
  assert.throws(() => detectControllerArchitecture({ platform: 'linux', runCommand: () => ({ status: 0, signal: null, stdout: '1\n' }) }), /requires macOS/iu);
});
