import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';

import {
  REQUIRED_CODE_IDENTITIES,
  buildReleaseAttestation,
  canonicalJSON as canonicalAttestationJSON
} from '../generate-release-attestation.mjs';
import { mintCandidateCheckpoint } from '../p0c/lib/candidate-checkpoint.mjs';
import { deriveReleaseCandidateId } from '../../../lib/release-candidate-identity.mjs';
import {
  FIXED_QUALIFICATION_RELEASE_DIRECTORY,
  FIXED_QUALIFICATION_RELEASE_TRUST_PATH,
  materializeQualificationRelease,
  parseQualificationReleaseMaterializerCLI,
  recoverQualificationRelease
} from './qualification-release-materializer.mjs';
import {
  parseQualificationReleaseTrust,
  resolveQualificationReleaseTrust
} from './qualification-release-trust.mjs';

const UID = process.getuid?.() ?? 0;
const TEAM_ID = 'ABCDE12345';
const COMMIT = 'c'.repeat(40);
const TREE = 'd'.repeat(40);
const REQUESTED_FINGERPRINT = (publicKey) => `SHA256:${crypto.createHash('sha256').update(publicKey.export({ type: 'spki', format: 'der' })).digest('base64url')}`;
const json = (value) => Buffer.from(`${JSON.stringify(value, null, 2)}\n`, 'utf8');
const digest = (bytes) => crypto.createHash('sha256').update(bytes).digest('hex');

const write = (file, bytes, mode = 0o600) => {
  fs.writeFileSync(file, bytes, { mode });
  fs.chmodSync(file, mode);
};

const fileEntry = (name, role, mediaType, bytes) => ({ name, role, media_type: mediaType, bytes: bytes.length, sha256: digest(bytes) });

const fixture = () => {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(process.cwd(), '.n3e-release-materializer-')));
  fs.chmodSync(root, 0o700);
  const sourceDirectory = path.join(root, 'source-release');
  fs.mkdirSync(sourceDirectory, { mode: 0o700 });
  fs.chmodSync(sourceDirectory, 0o700);
  const destination = path.join(root, 'release');
  const trustPath = path.join(root, 'release-trust.json');
  const checkpointPath = path.join(root, 'candidate-checkpoint.json');

  const productBytes = Buffer.from('signed installer product\n');
  const controllerBytes = Buffer.from('controller archive bytes\n');
  const sbomBytes = Buffer.from('{"spdxVersion":"SPDX-2.3"}\n');
  const attestation = buildReleaseAttestation({
    teamId: TEAM_ID,
    cloudImageDigest: `sha256:${'e'.repeat(64)}`,
    dependencyLockSha256: '1'.repeat(64),
    databaseMigrationManifestSha256: '2'.repeat(64),
    nestedCodeIdentities: REQUIRED_CODE_IDENTITIES.map((item, index) => ({
      path: item.path,
      bundle_id: item.bundle_id,
      team_id: TEAM_ID,
      code_directory_hash: `${String(index + 1).padStart(2, '0')}${'a'.repeat(38)}`
    })),
    signerKeyVersions: [{ name: 'capability', version: 'v1' }]
  });
  const attestationBytes = canonicalAttestationJSON(attestation);
  const auxiliary = new Map([
    ['controller-identity.json', Buffer.from('{"controller":"qualification"}\n')],
    ['controller-notary.json', Buffer.from('{"status":"Accepted"}\n')],
    ['controller-stapler.txt', Buffer.from('The validate action worked!\n')],
    ['SHA256SUMS', Buffer.from('checksums\n')],
    ['release-notary.json', Buffer.from('{"status":"Accepted"}\n')],
    ['release-stapler.txt', Buffer.from('The validate action worked!\n')]
  ]);
  const entries = [
    fileEntry('AgentPass-v0.18.0-macos-universal.pkg', 'product', 'application/vnd.apple.installer+xml', productBytes),
    fileEntry('AgentPassQualificationController-0.18.0-macos-universal.tar', 'external_qualification_controller', 'application/octet-stream', controllerBytes),
    fileEntry('release-attestation.json', 'auxiliary', 'application/json', attestationBytes),
    fileEntry('sbom.spdx.json', 'auxiliary', 'application/json', sbomBytes)
  ].sort((left, right) => left.name < right.name ? -1 : 1);
  const externalIdentity = {
    identity_document: { name: 'controller-identity.json', bytes: auxiliary.get('controller-identity.json').length, sha256: digest(auxiliary.get('controller-identity.json')) },
    identity: { archive_name: 'AgentPassQualificationController-0.18.0-macos-universal.tar' },
    notarization: { status: 'accepted_stapled', evidence: [
      { kind: 'notarytool_result', name: 'controller-notary.json', bytes: auxiliary.get('controller-notary.json').length, sha256: digest(auxiliary.get('controller-notary.json')) },
      { kind: 'stapler_result', name: 'controller-stapler.txt', bytes: auxiliary.get('controller-stapler.txt').length, sha256: digest(auxiliary.get('controller-stapler.txt')) }
    ] }
  };
  const manifest = {
    schema_version: 4,
    product: 'AgentPass',
    version: '0.18.0',
    source: { commit: COMMIT, tree: TREE, tag: 'v0.18.0' },
    generated_at: '2026-08-14T00:00:00.000Z',
    candidate_id: deriveReleaseCandidateId(digest(productBytes)),
    artifacts: entries,
    external_qualification_controller: externalIdentity,
    evidence: {
      checksums: { name: 'SHA256SUMS', bytes: auxiliary.get('SHA256SUMS').length, sha256: digest(auxiliary.get('SHA256SUMS')), entry_count: entries.length },
      sbom: { artifact_name: 'sbom.spdx.json', sha256: digest(sbomBytes), spdx_version: 'SPDX-2.3' },
      notarization: { status: 'accepted_stapled', evidence: [
        { kind: 'notarytool_result', name: 'release-notary.json', bytes: auxiliary.get('release-notary.json').length, sha256: digest(auxiliary.get('release-notary.json')) },
        { kind: 'stapler_result', name: 'release-stapler.txt', bytes: auxiliary.get('release-stapler.txt').length, sha256: digest(auxiliary.get('release-stapler.txt')) }
      ] }
    }
  };
  const manifestBytes = json(manifest);
  const keys = crypto.generateKeyPairSync('ed25519');
  const signatureBytes = Buffer.from(`${crypto.sign(null, manifestBytes, keys.privateKey).toString('base64')}\n`, 'utf8');
  const publicKeyBytes = Buffer.from(keys.publicKey.export({ type: 'spki', format: 'pem' }));
  const sourceFiles = new Map([
    ['release-manifest.json', manifestBytes],
    ['release-manifest.sig', signatureBytes],
    ['release-public.pem', publicKeyBytes],
    ['AgentPass-v0.18.0-macos-universal.pkg', productBytes],
    ['AgentPassQualificationController-0.18.0-macos-universal.tar', controllerBytes],
    ['release-attestation.json', attestationBytes],
    ['sbom.spdx.json', sbomBytes],
    ...auxiliary
  ]);
  for (const [name, bytes] of sourceFiles) write(path.join(sourceDirectory, name), bytes);

  const application = path.join(root, 'AgentPass.app');
  fs.mkdirSync(path.join(application, 'Contents', 'MacOS'), { recursive: true, mode: 0o700 });
  fs.chmodSync(application, 0o700);
  write(path.join(application, 'Contents', 'MacOS', 'agentpass'), Buffer.from('signed app\n'), 0o700);
  const identityReader = () => ({ bundle_id: 'dev.agentpass', team_id: TEAM_ID, code_directory_hash: 'a'.repeat(40), designated_requirement: 'anchor apple generic' });
  mintCandidateCheckpoint({
    checkpoint_path: checkpointPath,
    artifact_sha256: digest(productBytes),
    source_commit: COMMIT,
    team_id: TEAM_ID,
    application_path: application,
    code_objects: [{ path: application, role: 'application', bundle_id: 'dev.agentpass', team_id: TEAM_ID, code_directory_hash: 'a'.repeat(40), designated_requirement: 'anchor apple generic' }]
  }, { production: false, identityReader });
  return {
    root,
    sourceDirectory,
    destination,
    trustPath,
    checkpointPath,
    manifestPath: path.join(sourceDirectory, 'release-manifest.json'),
    signaturePath: path.join(sourceDirectory, 'release-manifest.sig'),
    publicKeyPath: path.join(sourceDirectory, 'release-public.pem'),
    productPath: path.join(sourceDirectory, 'AgentPass-v0.18.0-macos-universal.pkg'),
    expectedFingerprint: REQUESTED_FINGERPRINT(keys.publicKey),
    identityReader,
    source: {
      releaseDirectory: sourceDirectory,
      manifestPath: path.join(sourceDirectory, 'release-manifest.json'),
      signaturePath: path.join(sourceDirectory, 'release-manifest.sig'),
      publicKeyPath: path.join(sourceDirectory, 'release-public.pem'),
      productPath: path.join(sourceDirectory, 'AgentPass-v0.18.0-macos-universal.pkg')
    }
  };
};

const materialize = (value, overrides = {}) => materializeQualificationRelease({
  source: value.source,
  expectedFingerprint: value.expectedFingerprint,
  destination: value.destination,
  trustPath: value.trustPath,
  checkpointPath: value.checkpointPath,
  expectedUid: UID,
  uid: UID,
  production: false,
  identityReader: value.identityReader,
  ...overrides
});

const recover = (value, overrides = {}) => recoverQualificationRelease({
  destination: value.destination,
  trustPath: value.trustPath,
  checkpointPath: value.checkpointPath,
  expectedUid: UID,
  uid: UID,
  production: false,
  platform: process.platform,
  identityReader: value.identityReader,
  proveNoActiveQualificationProcesses: () => true,
  ...overrides
});

const cleanup = (value) => fs.rmSync(value.root, { recursive: true, force: true });

test('materializes the exact manifest-relative inventory and writes trust last', () => {
  const value = fixture();
  try {
    const result = materialize(value);
    assert.equal(result.ok, true);
    assert.equal(result.files, 13);
    assert.deepEqual(fs.readdirSync(value.destination).sort(), [
      'AgentPass-v0.18.0-macos-universal.pkg',
      'AgentPassQualificationController-0.18.0-macos-universal.tar',
      'SHA256SUMS',
      'controller-identity.json',
      'controller-notary.json',
      'controller-stapler.txt',
      'release-attestation.json',
      'release-manifest.json',
      'release-manifest.sig',
      'release-notary.json',
      'release-public.pem',
      'release-stapler.txt',
      'sbom.spdx.json'
    ].sort());
    assert.equal(fs.readdirSync(value.destination).length, result.files);
    assert.equal(fs.statSync(value.destination).mode & 0o7777, 0o700);
    for (const name of fs.readdirSync(value.destination)) {
      const stat = fs.lstatSync(path.join(value.destination, name));
      assert.equal(stat.isSymbolicLink(), false);
      assert.equal(stat.nlink, 1);
      assert.equal(stat.mode & 0o7777, 0o600);
    }
    const trust = parseQualificationReleaseTrust(fs.readFileSync(value.trustPath));
    assert.equal(trust.expected_fingerprint, value.expectedFingerprint);
    assert.equal(trust.run_binding_name, 'run-binding');
    assert.equal(trust.candidate_checkpoint_sha256, result.candidate_checkpoint_sha256);
    assert.equal(JSON.stringify(trust).includes(value.sourceDirectory), false);
    assert.equal(fs.existsSync(path.join(value.destination, 'run-binding')), false);
    assert.deepEqual(resolveQualificationReleaseTrust({ checkpoint: {
      checkpoint_sha256: trust.candidate_checkpoint_sha256,
      artifact_sha256: trust.artifact_sha256,
      source_commit: trust.source_commit,
      team_id: trust.team_id
    }, trustPath: value.trustPath, releaseDirectory: value.destination, expectedUid: UID, uid: UID, production: false }).trust, trust);
    assert.equal(fs.readdirSync(value.root).some((name) => name.endsWith('.staging')), false);
  } finally { cleanup(value); }
});

test('refuses overwrite of either the release directory or trust document', () => {
  const value = fixture();
  try {
    materialize(value);
    assert.throws(() => materialize(value), /already exists|overwrite/u);
  } finally { cleanup(value); }
});

test('rejects source symlinks and hardlinks before publication', () => {
  const symlinked = fixture();
  try {
    const moved = `${symlinked.manifestPath}.real`;
    fs.renameSync(symlinked.manifestPath, moved);
    fs.symlinkSync(moved, symlinked.manifestPath);
    assert.throws(() => materialize(symlinked), /unavailable|unsafe|symlink/u);
    assert.equal(fs.existsSync(symlinked.destination), false);
  } finally { cleanup(symlinked); }

  const hardlinked = fixture();
  try {
    const duplicate = path.join(hardlinked.sourceDirectory, 'product-copy');
    fs.linkSync(hardlinked.productPath, duplicate);
    assert.throws(() => materialize(hardlinked), /unsafe/u);
    assert.equal(fs.existsSync(hardlinked.destination), false);
  } finally { cleanup(hardlinked); }
});

test('rejects manifest path escape, missing binding, and checkpoint mismatch', () => {
  const escaped = fixture();
  try {
    const bytes = fs.readFileSync(escaped.manifestPath, 'utf8').replace('"controller-identity.json"', '"../controller-identity.json"');
    write(escaped.manifestPath, Buffer.from(bytes));
    assert.throws(() => materialize(escaped), /unsafe|signature/u);
  } finally { cleanup(escaped); }

  const mismatch = fixture();
  try {
    mismatch.expectedFingerprint = `SHA256:${'A'.repeat(43)}`;
    assert.throws(() => materialize(mismatch), /fingerprint/u);
  } finally { cleanup(mismatch); }
});

test('recovers only an exact verified release and removes trust before the release inventory', () => {
  const value = fixture();
  try {
    materialize(value);
    let proofCalls = 0;
    const result = recover(value, { proveNoActiveQualificationProcesses: () => { proofCalls += 1; return true; } });
    assert.equal(result.ok, true);
    assert.equal(result.action, 'recovered');
    assert.equal(result.files, 13);
    assert.equal(proofCalls, 2);
    assert.equal(fs.existsSync(value.trustPath), false);
    assert.equal(fs.existsSync(value.destination), false);
  } finally { cleanup(value); }
});

test('is idempotent only when both release trust and release directory are absent', () => {
  const value = fixture();
  try {
    let proofCalls = 0;
    const result = recover(value, { proveNoActiveQualificationProcesses: () => { proofCalls += 1; return true; } });
    assert.equal(result.action, 'already-recovered');
    assert.equal(proofCalls, 1);
    assert.throws(() => recover(value, { proveNoActiveQualificationProcesses: () => false }), /process remained active/u);

    materialize(value);
    fs.unlinkSync(value.trustPath);
    assert.throws(() => recover(value), /partial release state/u);
    assert.equal(fs.existsSync(value.destination), true);
  } finally { cleanup(value); }

  const second = fixture();
  try {
    materialize(second);
    fs.rmSync(second.destination, { recursive: true });
    assert.throws(() => recover(second), /partial release state/u);
    assert.equal(fs.existsSync(second.trustPath), true);
  } finally { cleanup(second); }
});

test('refuses active processes, trust/checkpoint mismatch, extra run-binding, symlink, or unsafe release files', () => {
  const active = fixture();
  try {
    materialize(active);
    assert.throws(() => recover(active, { proveNoActiveQualificationProcesses: () => false }), /process remained active/u);
    assert.equal(fs.existsSync(active.trustPath), true);
    assert.equal(fs.existsSync(active.destination), true);
  } finally { cleanup(active); }

  const mismatch = fixture();
  try {
    materialize(mismatch);
    const trust = parseQualificationReleaseTrust(fs.readFileSync(mismatch.trustPath));
    write(mismatch.trustPath, json({ ...trust, candidate_checkpoint_sha256: 'f'.repeat(64) }));
    assert.throws(() => recover(mismatch), /does not match the candidate checkpoint/u);
    assert.equal(fs.existsSync(mismatch.trustPath), true);
    assert.equal(fs.existsSync(mismatch.destination), true);
  } finally { cleanup(mismatch); }

  const extra = fixture();
  try {
    materialize(extra);
    write(path.join(extra.destination, 'run-binding'), Buffer.from('unexpected\n'));
    assert.throws(() => recover(extra), /inventory/u);
  } finally { cleanup(extra); }

  const symlink = fixture();
  try {
    materialize(symlink);
    const product = path.join(symlink.destination, 'AgentPass-v0.18.0-macos-universal.pkg');
    fs.unlinkSync(product);
    fs.symlinkSync(symlink.productPath, product);
    assert.throws(() => recover(symlink), /unsafe|unavailable|inventory/u);
  } finally { cleanup(symlink); }

  const mode = fixture();
  try {
    materialize(mode);
    fs.chmodSync(path.join(mode.destination, 'release-public.pem'), 0o644);
    assert.throws(() => recover(mode), /unsafe|inventory/u);
  } finally { cleanup(mode); }
});

test('refuses a release file substituted after the final no-active proof', () => {
  const value = fixture();
  try {
    materialize(value);
    let proofCalls = 0;
    const product = path.join(value.destination, 'AgentPass-v0.18.0-macos-universal.pkg');
    assert.throws(() => recover(value, {
      proveNoActiveQualificationProcesses: () => {
        proofCalls += 1;
        if (proofCalls === 2) write(product, Buffer.from('substituted after proof\n'));
        return true;
      }
    }), /changed before removal/u);
    assert.equal(proofCalls, 2);
    assert.equal(fs.existsSync(value.trustPath), false);
    assert.equal(fs.existsSync(value.destination), true);
  } finally { cleanup(value); }
});

test('refuses a release file that disappears after the final no-active proof', () => {
  const value = fixture();
  try {
    materialize(value);
    let proofCalls = 0;
    const product = path.join(value.destination, 'AgentPass-v0.18.0-macos-universal.pkg');
    assert.throws(() => recover(value, {
      proveNoActiveQualificationProcesses: () => {
        proofCalls += 1;
        if (proofCalls === 2) fs.unlinkSync(product);
        return true;
      }
    }), /removal was refused|changed before removal/u);
    assert.equal(proofCalls, 2);
    assert.equal(fs.existsSync(value.trustPath), false);
    assert.equal(fs.existsSync(value.destination), true);
  } finally { cleanup(value); }
});

test('accepts a runner-owned source release when the destination and checkpoint remain owner-bound', { skip: UID !== 0 }, () => {
  const value = fixture();
  try {
    for (const name of fs.readdirSync(value.sourceDirectory)) fs.chownSync(path.join(value.sourceDirectory, name), 1, -1);
    fs.chownSync(value.sourceDirectory, 1, -1);
    const result = materializeQualificationRelease({
      source: value.source,
      expectedFingerprint: value.expectedFingerprint,
      destination: value.destination,
      trustPath: value.trustPath,
      checkpointPath: value.checkpointPath,
      expectedUid: 0,
      uid: 0,
      production: false,
      identityReader: value.identityReader
    });
    assert.equal(result.ok, true);
    assert.equal(fs.statSync(value.destination).uid, 0);
  } finally { cleanup(value); }
});

test('production guard fixes destinations and CLI exposes only the release staging boundary', () => {
  assert.equal(FIXED_QUALIFICATION_RELEASE_DIRECTORY, '/private/var/db/agentpass-qualification/release');
  assert.equal(FIXED_QUALIFICATION_RELEASE_TRUST_PATH, '/private/var/db/agentpass-qualification/release-trust.json');
  assert.deepEqual(parseQualificationReleaseMaterializerCLI(['materialize', '/release', '/release/manifest.json', '/release/manifest.sig', '/release/public.pem', `SHA256:${'A'.repeat(43)}`, '/release/AgentPass.pkg']), {
    operation: 'materialize',
    source: { releaseDirectory: '/release', manifestPath: '/release/manifest.json', signaturePath: '/release/manifest.sig', publicKeyPath: '/release/public.pem', productPath: '/release/AgentPass.pkg' },
    expectedFingerprint: `SHA256:${'A'.repeat(43)}`
  });
  assert.deepEqual(parseQualificationReleaseMaterializerCLI(['recover']), { operation: 'recover' });
  assert.throws(() => parseQualificationReleaseMaterializerCLI([]), /usage/u);
  assert.throws(() => parseQualificationReleaseMaterializerCLI(['recover', 'unexpected']), /usage/u);
  assert.throws(() => parseQualificationReleaseMaterializerCLI(['materialize', '/tmp/release']), /usage/u);
  const value = fixture();
  try {
    assert.throws(() => materializeQualificationRelease({ source: value.source, expectedFingerprint: value.expectedFingerprint, destination: value.destination, trustPath: value.trustPath, checkpointPath: value.checkpointPath, expectedUid: UID, uid: UID, platform: 'darwin', production: true, identityReader: value.identityReader }), /root on macOS|fixed/u);
  } finally { cleanup(value); }
});
