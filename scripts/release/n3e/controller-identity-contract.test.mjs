import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import {
  CONTROLLER_ARCHIVE_NAME,
  CONTROLLER_BUNDLE_ID,
  CONTROLLER_EXECUTABLE_RELATIVE_PATH,
  CONTRACT_FIELDS,
  CONTRACT_KIND,
  SCHEMA_VERSION,
  canonicalJSON,
  collectExternalQualificationControllerIdentity,
  parseCanonicalExternalQualificationControllerIdentity,
  parseCodesignIdentity,
  parseLipoArchitectures,
  validateExternalQualificationControllerIdentity
} from './controller-identity-contract.mjs';

const TEAM_ID = 'ABCDE12345';
const ARCHITECTURES = ['arm64', 'x86_64'];
const ARCH_HASHES = {
  arm64: 'a'.repeat(40),
  x86_64: 'b'.repeat(40)
};
const ENTITLEMENTS = Buffer.from([
  '<?xml version="1.0" encoding="UTF-8"?>',
  '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">',
  '<plist version="1.0"><dict><key>dev.agentpass.qualification-control</key><true/></dict></plist>'
].join(''), 'utf8');
const ENTITLEMENTS_SHA256 = crypto.createHash('sha256').update(ENTITLEMENTS).digest('hex');
const designatedRequirement = (architecture) => `anchor apple generic and identifier "dev.agentpass.qualification-controller" and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate leaf[subject.OU] = "${TEAM_ID}" and entitlement["dev.agentpass.qualification-control"] exists and cdhash H"${ARCH_HASHES[architecture]}"`;

assert.doesNotMatch(designatedRequirement('arm64'), /entitlement\[[^\]]+\]\s*=\s*true/u);
assert.match(designatedRequirement('arm64'), /entitlement\["dev\.agentpass\.qualification-control"\] exists/u);

const temporaryDirectories = [];
const fixture = () => {
  const root = fs.mkdtempSync(join(fs.realpathSync.native(os.tmpdir()), 'agentpass-n3e-controller-identity-'));
  temporaryDirectories.push(root);
  const archivePath = join(root, CONTROLLER_ARCHIVE_NAME);
  fs.writeFileSync(archivePath, Buffer.from('controller archive fixture\n'), { mode: 0o600 });
  fs.chmodSync(archivePath, 0o600);
  const bundlePath = join(root, 'AgentPassQualificationController.app');
  const executablePath = join(bundlePath, CONTROLLER_EXECUTABLE_RELATIVE_PATH);
  fs.mkdirSync(join(executablePath, '..'), { recursive: true, mode: 0o755 });
  fs.chmodSync(bundlePath, 0o755);
  fs.chmodSync(join(bundlePath, 'Contents'), 0o755);
  fs.chmodSync(join(bundlePath, 'Contents', 'MacOS'), 0o755);
  fs.writeFileSync(executablePath, 'mach-o fixture\n', { mode: 0o755 });
  fs.chmodSync(executablePath, 0o755);
  return { root, archivePath, bundlePath, executablePath };
};

const codesignOutput = (architecture = 'arm64', entitlements = ENTITLEMENTS) => ({
  status: 0,
  signal: null,
  stdout: entitlements,
  stderr: [
    `Identifier=${CONTROLLER_BUNDLE_ID}`,
    `TeamIdentifier=${TEAM_ID}`,
    `CDHash=${ARCH_HASHES[architecture]}`,
    `designated => ${designatedRequirement(architecture)}`
  ].join('\n')
});

test.afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) fs.rmSync(directory, { recursive: true, force: true });
});

test('collects a closed canonical identity through injected codesign and lipo runners', () => {
  const value = fixture();
  const calls = [];
  const identity = collectExternalQualificationControllerIdentity({
    archivePath: value.archivePath,
    bundlePath: value.bundlePath,
    expectedTeamId: TEAM_ID,
    platform: 'darwin',
    runCodesign: (command, args, options) => {
      calls.push({ runner: 'codesign', command, args, options });
      const architecture = args[args.indexOf('--arch') + 1];
      return codesignOutput(architecture);
    },
    runLipo: (command, args, options) => {
      calls.push({ runner: 'lipo', command, args, options });
      return { status: 0, signal: null, stdout: 'arm64 x86_64\n', stderr: '' };
    }
  });
  assert.deepEqual(Object.keys(identity), CONTRACT_FIELDS);
  assert.deepEqual(identity, {
    schema_version: SCHEMA_VERSION,
    kind: CONTRACT_KIND,
    archive_name: CONTROLLER_ARCHIVE_NAME,
    archive_sha256: crypto.createHash('sha256').update('controller archive fixture\n').digest('hex'),
    archive_bytes: Buffer.byteLength('controller archive fixture\n'),
    bundle_id: CONTROLLER_BUNDLE_ID,
    team_id: TEAM_ID,
    entitlements_sha256: ENTITLEMENTS_SHA256,
    code_directory_hashes: ARCHITECTURES.map((architecture) => ({ architecture, hash: ARCH_HASHES[architecture] })),
    designated_requirements: ARCHITECTURES.map((architecture) => ({ architecture, requirement: designatedRequirement(architecture) }))
  });
  assert.equal(calls.length, 3);
  assert.deepEqual(calls[0].args, ['-archs', value.executablePath]);
  assert.deepEqual(calls[1].args, ['--display', '--verbose=4', '--arch', 'arm64', '--requirements', '-', '--entitlements', ':-', value.bundlePath]);
  assert.deepEqual(calls[2].args, ['--display', '--verbose=4', '--arch', 'x86_64', '--requirements', '-', '--entitlements', ':-', value.bundlePath]);
  assert.equal(calls[0].command, '/usr/bin/lipo');
  assert.equal(calls[1].command, '/usr/bin/codesign');
  assert.equal(calls[2].command, '/usr/bin/codesign');
  assert.equal(calls[0].options.shell, false);
  assert.equal(calls[1].options.shell, false);
  assert.equal(calls[2].options.shell, false);
});

test('canonical bytes are fixed and unknown, missing, or non-canonical fields are rejected', () => {
  const value = {
    schema_version: SCHEMA_VERSION,
    kind: CONTRACT_KIND,
    archive_name: CONTROLLER_ARCHIVE_NAME,
    archive_sha256: 'b'.repeat(64),
    archive_bytes: 42,
    bundle_id: CONTROLLER_BUNDLE_ID,
    team_id: TEAM_ID,
    entitlements_sha256: ENTITLEMENTS_SHA256,
    code_directory_hashes: ARCHITECTURES.map((architecture) => ({ architecture, hash: ARCH_HASHES[architecture] })),
    designated_requirements: ARCHITECTURES.map((architecture) => ({ architecture, requirement: designatedRequirement(architecture) }))
  };
  const bytes = canonicalJSON(value);
  assert.deepEqual(parseCanonicalExternalQualificationControllerIdentity(bytes), value);
  assert.equal(bytes.toString('utf8'), JSON.stringify(value));
  const reordered = JSON.stringify({ kind: value.kind, schema_version: value.schema_version, ...Object.fromEntries(Object.entries(value).filter(([key]) => key !== 'kind' && key !== 'schema_version')) });
  assert.throws(() => parseCanonicalExternalQualificationControllerIdentity(Buffer.from(reordered)), /canonical JSON/iu);
  assert.throws(() => validateExternalQualificationControllerIdentity({ ...value, unexpected: true }), /missing or unknown/iu);
  const missing = { ...value };
  delete missing.entitlements_sha256;
  assert.throws(() => validateExternalQualificationControllerIdentity(missing), /missing or unknown/iu);
  assert.throws(() => parseCanonicalExternalQualificationControllerIdentity(Buffer.from(`${JSON.stringify(value)}\n`)), /canonical JSON/iu);
  const duplicate = JSON.stringify(value).replace('"schema_version":1,', '"schema_version":1,"schema_version":1,');
  assert.throws(() => parseCanonicalExternalQualificationControllerIdentity(Buffer.from(duplicate)), /duplicate key/iu);
  assert.throws(() => validateExternalQualificationControllerIdentity({ ...value, code_directory_hashes: [...value.code_directory_hashes].reverse() }), /sorted|substituted/iu);
  assert.throws(() => validateExternalQualificationControllerIdentity({ ...value, designated_requirements: [{ ...value.designated_requirements[0], requirement: designatedRequirement('x86_64') }, value.designated_requirements[1]] }), /exact|bind|match/iu);
  const invalidFields = [
    ['archive_name', 'controller.tar', /archive name/iu],
    ['archive_sha256', 'not-a-digest', /archive_sha256/iu],
    ['archive_bytes', 0, /archive_bytes/iu],
    ['bundle_id', 'dev.agentpass.native-client', /bundle_id/iu],
    ['team_id', 'wrong-team', /team_id/iu],
    ['entitlements_sha256', 'not-a-digest', /entitlements_sha256/iu],
    ['code_directory_hashes', [{ architecture: 'arm64', hash: 'not-a-cdhash' }], /code_directory_hashes/iu],
    ['designated_requirements', [{ architecture: 'arm64', requirement: 'anchor apple generic' }], /designated_requirements/iu]
  ];
  for (const [field, replacement, error] of invalidFields) assert.throws(() => validateExternalQualificationControllerIdentity({ ...value, [field]: replacement }), error);
});

test('identity parsers bind exact signed metadata and entitlement bytes', () => {
  const parsed = parseCodesignIdentity(codesignOutput('arm64'));
  assert.deepEqual(parsed, {
    bundle_id: CONTROLLER_BUNDLE_ID,
    team_id: TEAM_ID,
    designated_requirement: designatedRequirement('arm64'),
    hash: ARCH_HASHES.arm64,
    entitlements_sha256: ENTITLEMENTS_SHA256
  });
  assert.deepEqual(parseLipoArchitectures('arm64 x86_64\n'), ARCHITECTURES);
  for (const mutation of [
    () => parseCodesignIdentity({ ...codesignOutput(), stderr: codesignOutput().stderr.replace(`TeamIdentifier=${TEAM_ID}`, 'TeamIdentifier=WRONG12345') }),
    () => parseCodesignIdentity({ ...codesignOutput('arm64'), stderr: codesignOutput('arm64').stderr.replace(`TeamIdentifier=${TEAM_ID}`, 'TeamIdentifier=WRONG12345') }),
    () => parseCodesignIdentity({ ...codesignOutput('arm64'), stderr: codesignOutput('arm64').stderr.replace(`CDHash=${ARCH_HASHES.arm64}`, 'CDHash=not-a-hash') }),
    () => parseCodesignIdentity({ ...codesignOutput('arm64'), stderr: codesignOutput('arm64').stderr.replace(`cdhash H"${ARCH_HASHES.arm64}"`, `cdhash H"${'b'.repeat(40)}"`) }),
    () => parseCodesignIdentity({ ...codesignOutput('arm64'), stderr: codesignOutput('arm64').stderr.replace(`CDHash=${ARCH_HASHES.arm64}`, `CDHash=${'A'.repeat(40)}`) }),
    () => parseCodesignIdentity({ ...codesignOutput('arm64'), stdout: Buffer.from('not a plist') }),
    () => parseLipoArchitectures('x86_64 arm64\n'),
    () => parseLipoArchitectures('arm64 arm64\n')
  ]) assert.throws(mutation, /invalid|missing|sorted|unique|exact|plist/iu);
});

test('collector fails closed on archive substitution, tool failure, and platform mismatch', () => {
  const value = fixture();
  assert.throws(() => collectExternalQualificationControllerIdentity({
    archivePath: value.archivePath,
    bundlePath: value.bundlePath,
    platform: 'linux',
    runCodesign: () => codesignOutput(),
    runLipo: () => ({ status: 0, stdout: 'arm64 x86_64' })
  }), /requires macOS/iu);
  const wrongName = join(value.root, 'wrong.zip');
  fs.copyFileSync(value.archivePath, wrongName);
  assert.throws(() => collectExternalQualificationControllerIdentity({
    archivePath: wrongName,
    bundlePath: value.bundlePath,
    platform: 'darwin',
    runCodesign: () => codesignOutput(),
    runLipo: () => ({ status: 0, stdout: 'arm64 x86_64' })
  }), /archive name/iu);
  assert.throws(() => collectExternalQualificationControllerIdentity({
    archivePath: value.archivePath,
    bundlePath: value.bundlePath,
    platform: 'darwin',
    runCodesign: () => ({ status: 1, signal: null, stdout: '', stderr: 'denied' }),
    runLipo: () => ({ status: 0, stdout: 'arm64 x86_64' })
  }), /codesign inspection failed/iu);
});

test('collector rejects symlink, hard-link, and writable bundle boundaries', () => {
  const symlink = fixture();
  const outside = join(symlink.root, 'outside-controller');
  fs.renameSync(symlink.executablePath, outside);
  fs.symlinkSync(outside, symlink.executablePath);
  assert.throws(() => collectExternalQualificationControllerIdentity({
    archivePath: symlink.archivePath,
    bundlePath: symlink.bundlePath,
    expectedTeamId: TEAM_ID,
    platform: 'darwin',
    runCodesign: () => codesignOutput(),
    runLipo: () => ({ status: 0, signal: null, stdout: 'arm64 x86_64' })
  }), /symlink|unsafe/iu);

  const hardLink = fixture();
  fs.linkSync(hardLink.executablePath, join(hardLink.root, 'executable-copy'));
  assert.throws(() => collectExternalQualificationControllerIdentity({
    archivePath: hardLink.archivePath,
    bundlePath: hardLink.bundlePath,
    expectedTeamId: TEAM_ID,
    platform: 'darwin',
    runCodesign: () => codesignOutput(),
    runLipo: () => ({ status: 0, signal: null, stdout: 'arm64 x86_64' })
  }), /unsafe/iu);

  const writable = fixture();
  fs.chmodSync(join(writable.bundlePath, 'Contents'), 0o775);
  assert.throws(() => collectExternalQualificationControllerIdentity({
    archivePath: writable.archivePath,
    bundlePath: writable.bundlePath,
    expectedTeamId: TEAM_ID,
    platform: 'darwin',
    runCodesign: () => codesignOutput(),
    runLipo: () => ({ status: 0, signal: null, stdout: 'arm64 x86_64' })
  }), /writable|unsafe/iu);
});
