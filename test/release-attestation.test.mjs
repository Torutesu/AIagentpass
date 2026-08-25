import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import { join } from 'node:path';
import { afterEach, test } from 'node:test';

import {
  REQUIRED_CODE_IDENTITIES,
  buildReleaseAttestation,
  canonicalJSON,
  collectCodeIdentities,
  generateReleaseAttestation,
  writeCanonicalAtomically
} from '../scripts/release/generate-release-attestation.mjs';

const TEAM_ID = 'ABCDE12345';
const CLOUD_DIGEST = `sha256:${'a'.repeat(64)}`;
const HASHES = ['1', '2', '3', '4', '5', '6'].map((value) => value.repeat(40));
const SIGNER_KEY_VERSIONS = [
  { name: 'cloud', version: 'v3' },
  { name: 'device', version: '2026.08.1' }
];

const temporaryDirectories = [];
afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) fs.rmSync(directory, { recursive: true, force: true });
});

const makeFixture = () => {
  const directory = fs.mkdtempSync(join(os.tmpdir(), 'agentpass-release-attestation-'));
  temporaryDirectories.push(directory);
  const appPath = join(directory, 'AgentPass.app');
  for (const identity of REQUIRED_CODE_IDENTITIES) {
    const suffix = identity.path === 'AgentPass.app' ? '' : identity.path.slice('AgentPass.app/'.length);
    const target = suffix ? join(appPath, suffix) : appPath;
    if (target.endsWith('.app')) fs.mkdirSync(target, { recursive: true });
    else {
      fs.mkdirSync(join(target, '..'), { recursive: true });
      fs.writeFileSync(target, 'signed executable\n', { mode: 0o755 });
    }
  }
  const lockPath = join(directory, 'package-lock.json');
  const migrationsPath = join(directory, 'migrations.sha256');
  const signerPath = join(directory, 'signer-key-versions.json');
  fs.writeFileSync(lockPath, '{"lockfileVersion":3}\n');
  fs.writeFileSync(migrationsPath, '001 init 0000000000000000000000000000000000000000000000000000000000000000\n');
  fs.writeFileSync(signerPath, `${JSON.stringify(SIGNER_KEY_VERSIONS)}\n`);
  return { directory, appPath, lockPath, migrationsPath, signerPath };
};

const fixtureRunner = (calls, { omitHashAt = -1, substituteIdentifierAt = -1 } = {}) => (command, args) => {
  calls.push({ command, args: [...args] });
  if (args[0] === '--verify') return { status: 0, stdout: '', stderr: '' };
  const index = calls.length - 2;
  const identity = REQUIRED_CODE_IDENTITIES[index];
  const identifier = index === substituteIdentifierAt ? 'dev.attacker.substituted' : identity.bundle_id;
  const hash = index === omitHashAt ? undefined : HASHES[index];
  return { status: 0, stdout: '', stderr: [`Identifier=${identifier}`, `TeamIdentifier=${TEAM_ID}`, hash ? `CDHash=${hash}` : ''].filter(Boolean).join('\n') };
};

const validIdentities = () => REQUIRED_CODE_IDENTITIES.map((identity, index) => ({
  path: identity.path,
  bundle_id: identity.bundle_id,
  team_id: TEAM_ID,
  code_directory_hash: HASHES[index]
}));

test('generates deterministic canonical attestation from explicit inputs and fixed codesign calls', () => {
  const fixture = makeFixture();
  const calls = [];
  const attestation = generateReleaseAttestation({
    appPath: fixture.appPath,
    teamId: TEAM_ID,
    dependencyLockPath: fixture.lockPath,
    databaseMigrationManifestPath: fixture.migrationsPath,
    cloudImageDigest: CLOUD_DIGEST,
    signerKeyVersionsPath: fixture.signerPath,
    runCommand: fixtureRunner(calls),
    platform: 'darwin'
  });
  const expected = {
    schema_version: 1,
    team_id: TEAM_ID,
    nested_code_identities: validIdentities(),
    cloud_image_digest: CLOUD_DIGEST,
    dependency_lock_sha256: createHash('sha256').update(fs.readFileSync(fixture.lockPath)).digest('hex'),
    database_migration_manifest_sha256: createHash('sha256').update(fs.readFileSync(fixture.migrationsPath)).digest('hex'),
    signer_key_versions: SIGNER_KEY_VERSIONS
  };
  assert.deepEqual(attestation, expected);
  assert.deepEqual(canonicalJSON(attestation), Buffer.from(`${JSON.stringify(expected, null, 2)}\n`));
  assert.equal(calls.length, 7);
  assert.deepEqual(calls[0].args, ['--verify', '--deep', '--strict', '--verbose=2', fixture.appPath]);
  for (let index = 1; index < calls.length; index += 1) assert.deepEqual(calls[index].args.slice(0, 3), ['--display', '--verbose=4', calls[index].args[2]]);
});

test('collects all six identities and rejects omission or substitution', () => {
  const fixture = makeFixture();
  assert.throws(() => collectCodeIdentities({ appPath: fixture.appPath, expectedTeamId: TEAM_ID, runCommand: fixtureRunner([], { omitHashAt: 4 }), platform: 'darwin' }), /CodeDirectory hash missing/);
  assert.throws(() => collectCodeIdentities({ appPath: fixture.appPath, expectedTeamId: TEAM_ID, runCommand: fixtureRunner([], { substituteIdentifierAt: 2 }), platform: 'darwin' }), /identifier mismatch/);
  assert.throws(() => buildReleaseAttestation({ teamId: TEAM_ID, cloudImageDigest: CLOUD_DIGEST, dependencyLockSha256: 'b'.repeat(64), databaseMigrationManifestSha256: 'c'.repeat(64), nestedCodeIdentities: validIdentities().slice(0, 5), signerKeyVersions: SIGNER_KEY_VERSIONS }), /all six/);
  const substituted = validIdentities();
  substituted[1] = { ...substituted[1], bundle_id: 'dev.attacker' };
  assert.throws(() => buildReleaseAttestation({ teamId: TEAM_ID, cloudImageDigest: CLOUD_DIGEST, dependencyLockSha256: 'b'.repeat(64), databaseMigrationManifestSha256: 'c'.repeat(64), nestedCodeIdentities: substituted, signerKeyVersions: SIGNER_KEY_VERSIONS }), /omission or substitution/);
});

test('rejects non-macOS production generation and mutable cloud tags', () => {
  const fixture = makeFixture();
  assert.throws(() => generateReleaseAttestation({
    appPath: fixture.appPath,
    teamId: TEAM_ID,
    dependencyLockPath: fixture.lockPath,
    databaseMigrationManifestPath: fixture.migrationsPath,
    cloudImageDigest: CLOUD_DIGEST,
    signerKeyVersionsPath: fixture.signerPath,
    platform: 'linux'
  }), /requires macOS/);
  assert.throws(() => buildReleaseAttestation({ teamId: TEAM_ID, cloudImageDigest: 'latest', dependencyLockSha256: 'b'.repeat(64), databaseMigrationManifestSha256: 'c'.repeat(64), nestedCodeIdentities: validIdentities(), signerKeyVersions: SIGNER_KEY_VERSIONS }), /immutable sha256 digest/);
  assert.throws(() => buildReleaseAttestation({ teamId: 'lowercase01', cloudImageDigest: CLOUD_DIGEST, dependencyLockSha256: 'b'.repeat(64), databaseMigrationManifestSha256: 'c'.repeat(64), nestedCodeIdentities: validIdentities(), signerKeyVersions: SIGNER_KEY_VERSIONS }), /Team ID/);
});

test('validates strict signer key version schema and ordering', () => {
  const base = { teamId: TEAM_ID, cloudImageDigest: CLOUD_DIGEST, dependencyLockSha256: 'b'.repeat(64), databaseMigrationManifestSha256: 'c'.repeat(64), nestedCodeIdentities: validIdentities() };
  assert.throws(() => buildReleaseAttestation({ ...base, signerKeyVersions: [{ name: 'device', version: 'v1' }, { name: 'cloud', version: 'v2' }] }), /unique and sorted/);
  assert.throws(() => buildReleaseAttestation({ ...base, signerKeyVersions: [{ name: 'device', version: 'v1', secret: 'must-not-be-here' }] }), /unknown fields/);
  assert.throws(() => buildReleaseAttestation({ ...base, signerKeyVersions: [{ name: 'device', version: 'not a version' }] }), /unique and sorted|invalid/);
});

test('rejects symlink and hard-link inputs and unsafe app bundle paths', () => {
  const fixture = makeFixture();
  const lockLink = join(fixture.directory, 'lock-link');
  fs.symlinkSync(fixture.lockPath, lockLink);
  assert.throws(() => generateReleaseAttestation({ appPath: fixture.appPath, teamId: TEAM_ID, dependencyLockPath: lockLink, databaseMigrationManifestPath: fixture.migrationsPath, cloudImageDigest: CLOUD_DIGEST, signerKeyVersionsPath: fixture.signerPath, runCommand: fixtureRunner([]), platform: 'darwin' }), /cannot open dependency lock file/);

  const hardLink = join(fixture.directory, 'lock-hard-link');
  fs.linkSync(fixture.lockPath, hardLink);
  assert.throws(() => generateReleaseAttestation({ appPath: fixture.appPath, teamId: TEAM_ID, dependencyLockPath: hardLink, databaseMigrationManifestPath: fixture.migrationsPath, cloudImageDigest: CLOUD_DIGEST, signerKeyVersionsPath: fixture.signerPath, runCommand: fixtureRunner([]), platform: 'darwin' }), /unsafe dependency lock file/);

  const appLink = join(fixture.directory, 'AgentPass-link.app');
  fs.symlinkSync(fixture.appPath, appLink);
  assert.throws(() => collectCodeIdentities({ appPath: appLink, expectedTeamId: TEAM_ID, runCommand: fixtureRunner([]), platform: 'darwin' }), /must end in AgentPass.app/);
});

test('creates canonical output atomically, refuses replacement, and rejects output symlinks', () => {
  const fixture = makeFixture();
  const output = join(fixture.directory, 'release-attestation.json');
  const attestation = buildReleaseAttestation({ teamId: TEAM_ID, cloudImageDigest: CLOUD_DIGEST, dependencyLockSha256: 'b'.repeat(64), databaseMigrationManifestSha256: 'c'.repeat(64), nestedCodeIdentities: validIdentities(), signerKeyVersions: SIGNER_KEY_VERSIONS });
  const result = writeCanonicalAtomically(output, attestation);
  assert.equal(result.bytes, fs.statSync(output).size);
  assert.equal(fs.readFileSync(output, 'utf8'), canonicalJSON(attestation).toString('utf8'));
  assert.throws(() => writeCanonicalAtomically(output, attestation), /already exists/);
  const symlink = join(fixture.directory, 'attestation-link.json');
  fs.symlinkSync(output, symlink);
  assert.throws(() => writeCanonicalAtomically(symlink, attestation), /output path is unsafe/);
});
