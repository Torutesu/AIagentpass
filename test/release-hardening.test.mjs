import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { execFileSync, spawnSync } from 'node:child_process';
import { chmodSync, linkSync, mkdirSync, mkdtempSync, readFileSync, statSync, symlinkSync, unlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import test from 'node:test';
import { deriveReleaseCandidateId, parseReleaseCandidateId } from '../lib/release-candidate-identity.mjs';

const root = resolve(import.meta.dirname, '..');
const scriptPath = (script) => resolve(root, 'scripts/release', script);
const run = (script, args = [], options = {}) => execFileSync(process.execPath, [scriptPath(script), ...args], { cwd: root, encoding: 'utf8', ...options });
const spawn = (script, args = [], options = {}) => spawnSync(process.execPath, [scriptPath(script), ...args], { cwd: root, encoding: 'utf8', ...options });
const canonical = (value) => `${JSON.stringify(value, null, 2)}\n`;
const fingerprint = (publicKey) => `SHA256:${crypto.createHash('sha256').update(publicKey.export({ type: 'spki', format: 'der' })).digest('base64url')}`;
const writeDetachedSignature = (path, bytes, privateKey) => writeFileSync(path, `${crypto.sign(null, bytes, privateKey).toString('base64')}\n`, { mode: 0o644 });

const CONTROLLER_TEAM_ID = 'ABCDE12345';
const CONTROLLER_WRONG_TEAM_ID = 'ZZZZZ99999';
const CONTROLLER_BUNDLE_ID = 'dev.agentpass.qualification-controller';
const CONTROLLER_KIND = 'agentpass-n3e-external-qualification-controller-identity';
const CONTROLLER_ARCHIVE_NAME = 'AgentPassQualificationController-0.18.0-macos-universal.tar';
const CONTROLLER_ARCHITECTURES = ['arm64', 'x86_64'];
const CONTROLLER_HASHES = { arm64: 'a'.repeat(40), x86_64: 'b'.repeat(40) };
const CONTROLLER_ENTITLEMENTS = Buffer.from('<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict><key>dev.agentpass.qualification-control</key><true/></dict></plist>');
const controllerRequirement = (teamId, architecture) => `anchor apple generic and identifier "${CONTROLLER_BUNDLE_ID}" and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate leaf[subject.OU] = "${teamId}" and entitlement["dev.agentpass.qualification-control"] exists and cdhash H"${CONTROLLER_HASHES[architecture]}"`;
const controllerIdentityFor = (archiveBytes, { teamId = CONTROLLER_TEAM_ID } = {}) => ({
  schema_version: 1,
  kind: CONTROLLER_KIND,
  archive_name: CONTROLLER_ARCHIVE_NAME,
  archive_sha256: crypto.createHash('sha256').update(archiveBytes).digest('hex'),
  archive_bytes: archiveBytes.length,
  bundle_id: CONTROLLER_BUNDLE_ID,
  team_id: teamId,
  entitlements_sha256: crypto.createHash('sha256').update(CONTROLLER_ENTITLEMENTS).digest('hex'),
  code_directory_hashes: CONTROLLER_ARCHITECTURES.map((architecture) => ({ architecture, hash: CONTROLLER_HASHES[architecture] })),
  designated_requirements: CONTROLLER_ARCHITECTURES.map((architecture) => ({ architecture, requirement: `identifier "${CONTROLLER_BUNDLE_ID}" and anchor apple generic` })),
  authorization_requirements: CONTROLLER_ARCHITECTURES.map((architecture) => ({ architecture, requirement: controllerRequirement(teamId, architecture) }))
});

const controllerManifestArgs = (release, manifest, sums, options = {}) => {
  const { identity = release.controllerIdentity, controllerNotarytool = release.controllerNotarytool, controllerStapler = release.controllerStapler, controllerSubmission = release.controllerSubmission, product = release.artifact, controllerArchive = release.controllerArchive, sbom = release.sbom, includeControllerStapler = true } = options;
  return [
    manifest,
    sums,
    `--controller-identity=${identity}`,
    '--controller-notarization-status=accepted_stapled',
    `--controller-notary-submission=${controllerSubmission}`,
    `--controller-notarytool-evidence=${controllerNotarytool}`,
    ...(includeControllerStapler ? [`--controller-stapler-evidence=${controllerStapler}`] : []),
    product,
    controllerArchive,
    sbom
  ];
};

const resignManifest = (release, mutate) => {
  const value = JSON.parse(readFileSync(release.manifest));
  mutate(value);
  const bytes = Buffer.from(canonical(value));
  writeFileSync(release.manifest, bytes);
  writeDetachedSignature(release.signature, bytes, release.keys.privateKey);
};

const makeRelease = (prefix = 'agentpass-release-', options = {}) => {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  const artifact = join(dir, 'AgentPass-v0.17.0-macos-universal.pkg');
  const controllerArchive = join(dir, CONTROLLER_ARCHIVE_NAME);
  const controllerIdentity = join(dir, 'AgentPassQualificationController.identity.json');
  const sbom = join(dir, 'AgentPass-v0.17.0.spdx.json');
  const manifest = join(dir, 'AgentPass-v0.17.0.release-manifest.json');
  const sums = join(dir, 'SHA256SUMS');
  const signature = join(dir, 'AgentPass-v0.17.0.release-manifest.sig');
  const privateKeyFile = join(dir, 'release.private.pem');
  const publicKeyFile = join(dir, 'release.public.pem');
  const controllerSubmission = 'fedcba98-7654-3210-fedc-ba9876543210';
  const controllerNotarytool = join(dir, 'controller-notarytool-result.json');
  const controllerStapler = join(dir, 'controller-stapler-result.txt');
  const keys = crypto.generateKeyPairSync('ed25519');
  writeFileSync(privateKeyFile, keys.privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
  chmodSync(privateKeyFile, 0o600);
  writeFileSync(publicKeyFile, keys.publicKey.export({ type: 'spki', format: 'pem' }), { mode: 0o644 });
  writeFileSync(artifact, 'signed application artifact');
  const controllerBytes = Buffer.from('signed external qualification controller archive');
  writeFileSync(controllerArchive, controllerBytes);
  writeFileSync(controllerIdentity, JSON.stringify(controllerIdentityFor(controllerBytes)));
  writeFileSync(controllerNotarytool, JSON.stringify({ id: controllerSubmission, status: 'Accepted', message: 'Controller Approved' }));
  writeFileSync(controllerStapler, 'Processing: AgentPassQualificationController.app\nThe validate action worked!\n');
  run('generate-sbom.mjs', [sbom]);
  const args = controllerManifestArgs({ artifact, controllerArchive, controllerIdentity, sbom, controllerNotarytool, controllerStapler, controllerSubmission }, manifest, sums);
  if (options.acceptedNotarization) {
    const id = '01234567-89ab-cdef-0123-456789abcdef';
    const notarytool = join(dir, 'notarytool-result.json');
    const stapler = join(dir, 'stapler-result.txt');
    writeFileSync(notarytool, JSON.stringify({ id, status: 'Accepted', message: 'Package Approved' }));
    writeFileSync(stapler, 'Processing: AgentPass.app\nThe validate action worked!\n');
    args.push('--notarization-status=accepted_stapled', `--notary-submission=${id}`, `--notarytool-evidence=${notarytool}`, `--stapler-evidence=${stapler}`);
  }
  run('generate-manifest.mjs', args);
  run('sign-manifest.mjs', [manifest, privateKeyFile, signature]);
  return { dir, artifact, controllerArchive, controllerIdentity, sbom, manifest, sums, signature, privateKeyFile, publicKeyFile, controllerNotarytool, controllerStapler, controllerSubmission, keys, fingerprint: fingerprint(keys.publicKey) };
};

test('release versions agree across package and all app bundles', () => {
  const result = JSON.parse(run('validate-version.mjs'));
  assert.equal(result.ok, true);
});

test('SPDX SBOM binds Git source, Swift inputs, compiler metadata, and documentDescribes', () => {
  const dir = mkdtempSync(join(tmpdir(), 'agentpass-sbom-'));
  const output = join(dir, 'AgentPass.spdx.json');
  run('generate-sbom.mjs', [output]);
  const sbom = JSON.parse(readFileSync(output));
  const commit = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: root, encoding: 'utf8' }).trim();
  const tree = execFileSync('git', ['rev-parse', 'HEAD^{tree}'], { cwd: root, encoding: 'utf8' }).trim();
  assert.equal(sbom.spdxVersion, 'SPDX-2.3');
  assert.deepEqual(sbom.documentDescribes, ['SPDXRef-AgentPass']);
  assert.match(sbom.packages.find((item) => item.SPDXID === 'SPDXRef-AgentPass').sourceInfo, new RegExp(`${commit}.*${tree}`));
  assert.ok(sbom.files.some((item) => item.fileName === 'native/macos/Package.swift'));
  assert.ok(sbom.files.some((item) => item.fileName.endsWith('.swift')));
  for (const id of ['SPDXRef-BuildTool-Node', 'SPDXRef-BuildTool-Swift', 'SPDXRef-BuildTool-macOSSDK']) assert.ok(sbom.packages.some((item) => item.SPDXID === id));
  assert.deepEqual(JSON.parse(sbom.creationInfo.comment).source_commit, commit);
  assert.deepEqual(JSON.parse(sbom.creationInfo.comment).source_tree, tree);
});

test('signed manifest strictly binds artifacts, SHA256SUMS, SPDX SBOM, and source identity', () => {
  const release = makeRelease();
  const manifest = JSON.parse(readFileSync(release.manifest));
  assert.equal(manifest.schema_version, 4);
  assert.equal(manifest.candidate_id, deriveReleaseCandidateId(crypto.createHash('sha256').update(readFileSync(release.artifact)).digest('hex')));
  assert.deepEqual(parseReleaseCandidateId(manifest.candidate_id), {
    candidate_id: manifest.candidate_id,
    version: 1,
    product: 'pkg',
    sha256: manifest.candidate_id.slice('release-pkg-sha256-v1-'.length)
  });
  assert.equal(manifest.artifacts.filter((item) => item.role === 'external_qualification_controller').length, 1);
  assert.equal(manifest.external_qualification_controller.identity_document.name, 'AgentPassQualificationController.identity.json');
  assert.equal(manifest.external_qualification_controller.notarization.status, 'accepted_stapled');
  assert.equal(manifest.evidence.checksums.name, 'SHA256SUMS');
  assert.equal(manifest.evidence.sbom.spdx_version, 'SPDX-2.3');
  const verified = JSON.parse(run('verify-release.mjs', [release.manifest, release.signature, release.publicKeyFile, release.fingerprint]));
  assert.equal(verified.artifacts, 3);
  assert.equal(verified.checksums_bound, true);
  assert.equal(verified.sbom_bound, true);
  assert.equal(verified.notarization, 'not_verified');
  assert.equal(verified.apple_ticket_verified, false);

  writeFileSync(release.artifact, 'tampered');
  const failed = spawn('verify-release.mjs', [release.manifest, release.signature, release.publicKeyFile, release.fingerprint]);
  assert.notEqual(failed.status, 0);
  assert.match(failed.stderr, /mismatch/);
});

test('signed manifest recognizes the production installer as the product artifact', () => {
  const release = makeRelease('agentpass-pkg-manifest-', { packageArtifact: true, acceptedNotarization: true });
  const manifest = JSON.parse(readFileSync(release.manifest));
  const product = manifest.artifacts.find((item) => item.role === 'product');
  assert.equal(product.name, 'AgentPass-v0.17.0-macos-universal.pkg');
  assert.equal(product.media_type, 'application/vnd.apple.installer+xml');
  assert.equal(JSON.parse(run('verify-release.mjs', [release.manifest, release.signature, release.publicKeyFile, release.fingerprint])).notarization, 'accepted_stapled');
});

test('release candidate identity is required and must match the exact product PKG digest', () => {
  const missing = makeRelease('agentpass-candidate-missing-');
  resignManifest(missing, (value) => { delete value.candidate_id; });
  const missingFailure = spawn('verify-release.mjs', [missing.manifest, missing.signature, missing.publicKeyFile, missing.fingerprint]);
  assert.notEqual(missingFailure.status, 0);
  assert.match(missingFailure.stderr, /missing or unknown fields|candidate_id/iu);

  const substituted = makeRelease('agentpass-candidate-substituted-');
  resignManifest(substituted, (value) => { value.candidate_id = deriveReleaseCandidateId('f'.repeat(64)); });
  const substitutedFailure = spawn('verify-release.mjs', [substituted.manifest, substituted.signature, substituted.publicKeyFile, substituted.fingerprint]);
  assert.notEqual(substitutedFailure.status, 0);
  assert.match(substitutedFailure.stderr, /candidate|PKG|SHA-256|match/iu);

  const arbitrary = makeRelease('agentpass-candidate-arbitrary-');
  resignManifest(arbitrary, (value) => { value.candidate_id = 'release-2026-08-13-01'; });
  const arbitraryFailure = spawn('verify-release.mjs', [arbitrary.manifest, arbitrary.signature, arbitrary.publicKeyFile, arbitrary.fingerprint]);
  assert.notEqual(arbitraryFailure.status, 0);
  assert.match(arbitraryFailure.stderr, /candidate|identity/iu);
});

test('manifest generation requires one and only one product PKG', () => {
  const release = makeRelease('agentpass-candidate-product-shape-');
  const extraZip = join(release.dir, 'AgentPass-extra.zip');
  writeFileSync(extraZip, 'alternate product archive');
  const multipleProducts = spawn('generate-manifest.mjs', [
    ...controllerManifestArgs(release, join(release.dir, 'multiple.manifest.json'), join(release.dir, 'multiple.SHA256SUMS')),
    extraZip
  ]);
  assert.notEqual(multipleProducts.status, 0);
  assert.match(multipleProducts.stderr, /exactly one product PKG/iu);

  const zipOnly = join(release.dir, 'AgentPass-v0.17.0-macos-universal.zip');
  writeFileSync(zipOnly, 'zip product only');
  const noPkg = spawn('generate-manifest.mjs', controllerManifestArgs(release, join(release.dir, 'no-pkg.manifest.json'), join(release.dir, 'no-pkg.SHA256SUMS'), { product: zipOnly }));
  assert.notEqual(noPkg.status, 0);
  assert.match(noPkg.stderr, /exactly one product PKG/iu);
});

test('manifest v4 rejects unknown and missing external controller fields under a valid signature', () => {
  const unknown = makeRelease('agentpass-controller-schema-unknown-');
  resignManifest(unknown, (value) => { value.external_qualification_controller.untrusted = true; });
  const unknownSigner = spawn('sign-manifest.mjs', [unknown.manifest, unknown.privateKeyFile, join(unknown.dir, 'unknown-controller.sig')]);
  assert.notEqual(unknownSigner.status, 0);
  assert.match(unknownSigner.stderr, /missing or unknown fields/);
  const unknownFailure = spawn('verify-release.mjs', [unknown.manifest, unknown.signature, unknown.publicKeyFile, unknown.fingerprint]);
  assert.notEqual(unknownFailure.status, 0);
  assert.match(unknownFailure.stderr, /missing or unknown fields/);

  const missing = makeRelease('agentpass-controller-schema-missing-');
  resignManifest(missing, (value) => { delete value.external_qualification_controller.identity; });
  const missingSigner = spawn('sign-manifest.mjs', [missing.manifest, missing.privateKeyFile, join(missing.dir, 'missing-controller.sig')]);
  assert.notEqual(missingSigner.status, 0);
  assert.match(missingSigner.stderr, /missing or unknown fields/);
  const missingFailure = spawn('verify-release.mjs', [missing.manifest, missing.signature, missing.publicKeyFile, missing.fingerprint]);
  assert.notEqual(missingFailure.status, 0);
  assert.match(missingFailure.stderr, /missing or unknown fields|identity/);
});

test('controller archive and identity mutations fail closed after manifest signing', () => {
  const archive = makeRelease('agentpass-controller-archive-mutation-');
  writeFileSync(archive.controllerArchive, 'mutated external controller archive');
  const archiveFailure = spawn('verify-release.mjs', [archive.manifest, archive.signature, archive.publicKeyFile, archive.fingerprint]);
  assert.notEqual(archiveFailure.status, 0);
  assert.match(archiveFailure.stderr, /external|archive|mismatch|digest/iu);

  const identity = makeRelease('agentpass-controller-identity-mutation-');
  writeFileSync(identity.controllerIdentity, `${readFileSync(identity.controllerIdentity, 'utf8')} `);
  const identityFailure = spawn('verify-release.mjs', [identity.manifest, identity.signature, identity.publicKeyFile, identity.fingerprint]);
  assert.notEqual(identityFailure.status, 0);
  assert.match(identityFailure.stderr, /identity|digest|canonical|mismatch/iu);
});

test('generator binds the controller identity document to the exact archive digest and bytes', () => {
  const release = makeRelease('agentpass-controller-archive-binding-');
  const value = JSON.parse(readFileSync(release.controllerIdentity));
  value.archive_sha256 = 'f'.repeat(64);
  const identity = join(release.dir, 'archive-mismatch.identity.json');
  writeFileSync(identity, JSON.stringify(value));
  const failed = spawn('generate-manifest.mjs', controllerManifestArgs(release, join(release.dir, 'archive-mismatch.manifest.json'), join(release.dir, 'archive-mismatch.SHA256SUMS'), { identity }));
  assert.notEqual(failed.status, 0);
  assert.match(failed.stderr, /controller identity.*bind|archive.*digest|archive.*bytes/iu);
});

test('controller identity rejects invalid or substituted Team IDs, architecture inventory, requirements, and entitlement digest', () => {
  const cases = [
    ['invalid-team', (value) => { value.team_id = 'not-a-team'; }, /team_id/iu],
    ['substituted-team', (value) => { value.team_id = CONTROLLER_WRONG_TEAM_ID; }, /designated|team_id|identity/iu],
    ['missing-architecture', (value) => { value.code_directory_hashes.pop(); value.designated_requirements.pop(); value.authorization_requirements.pop(); }, /architecture|exact|designated|authorization/iu],
    ['duplicate-architecture', (value) => { value.code_directory_hashes[1].architecture = 'arm64'; value.designated_requirements[1].architecture = 'arm64'; value.authorization_requirements[1].architecture = 'arm64'; }, /architecture|duplicate|sorted/iu],
    ['swapped-architecture', (value) => { value.code_directory_hashes.reverse(); value.designated_requirements.reverse(); value.authorization_requirements.reverse(); }, /architecture|sorted|exact/iu],
    ['cdhash-mismatch', (value) => { value.code_directory_hashes[0].hash = 'c'.repeat(40); }, /designated|cdhash|hash/iu],
    ['requirement-mismatch', (value) => { value.authorization_requirements[0].requirement = controllerRequirement(CONTROLLER_TEAM_ID, 'x86_64'); }, /authorization|cdhash|bind/iu],
    ['invalid-entitlement-digest', (value) => { value.entitlements_sha256 = 'not-a-digest'; }, /entitlement|digest/iu]
  ];
  for (const [label, mutate, error] of cases) {
    const release = makeRelease(`agentpass-controller-identity-${label}-`);
    const value = JSON.parse(readFileSync(release.controllerIdentity));
    mutate(value);
    const identity = join(release.dir, `${label}.identity.json`);
    writeFileSync(identity, JSON.stringify(value));
    const failed = spawn('generate-manifest.mjs', controllerManifestArgs(release, join(release.dir, `${label}.manifest.json`), join(release.dir, `${label}.SHA256SUMS`), { identity }));
    assert.notEqual(failed.status, 0, label);
    assert.match(failed.stderr, error, label);
  }
});

test('controller notarization is complete, accepted, and bound to its declared submission', () => {
  const incomplete = makeRelease('agentpass-controller-notary-incomplete-');
  const missingStapler = spawn('generate-manifest.mjs', controllerManifestArgs(incomplete, join(incomplete.dir, 'incomplete.manifest.json'), join(incomplete.dir, 'incomplete.SHA256SUMS'), { includeControllerStapler: false }));
  assert.notEqual(missingStapler.status, 0);
  assert.match(missingStapler.stderr, /controller.*stapler|one notarytool.*stapler/iu);

  const substituted = makeRelease('agentpass-controller-notary-substituted-');
  writeFileSync(substituted.controllerNotarytool, JSON.stringify({ id: '11111111-2222-3333-4444-555555555555', status: 'Accepted' }));
  const substitutedFailure = spawn('generate-manifest.mjs', controllerManifestArgs(substituted, join(substituted.dir, 'substituted.manifest.json'), join(substituted.dir, 'substituted.SHA256SUMS')));
  assert.notEqual(substitutedFailure.status, 0);
  assert.match(substitutedFailure.stderr, /controller.*notarytool|accepted.*declared submission/iu);

  const invalidStatus = makeRelease('agentpass-controller-notary-invalid-');
  writeFileSync(invalidStatus.controllerNotarytool, JSON.stringify({ id: invalidStatus.controllerSubmission, status: 'Invalid' }));
  const invalidFailure = spawn('generate-manifest.mjs', controllerManifestArgs(invalidStatus, join(invalidStatus.dir, 'invalid.manifest.json'), join(invalidStatus.dir, 'invalid.SHA256SUMS')));
  assert.notEqual(invalidFailure.status, 0);
  assert.match(invalidFailure.stderr, /controller.*notarytool|accepted/iu);
});

test('SHA256SUMS and notarization evidence are signed-manifest-bound and fail closed', () => {
  const release = makeRelease('agentpass-notary-', { acceptedNotarization: true });
  const verified = JSON.parse(run('verify-release.mjs', [release.manifest, release.signature, release.publicKeyFile, release.fingerprint]));
  assert.equal(verified.notarization, 'accepted_stapled');
  assert.equal(verified.notarization_evidence_bound, true);
  assert.equal(verified.apple_ticket_verified, false);

  const originalSums = readFileSync(release.sums);
  writeFileSync(release.sums, Buffer.concat([originalSums, Buffer.from('0')]));
  const sumsFailure = spawn('verify-release.mjs', [release.manifest, release.signature, release.publicKeyFile, release.fingerprint]);
  assert.notEqual(sumsFailure.status, 0);
  assert.match(sumsFailure.stderr, /SHA256SUMS|size mismatch|digest mismatch/);
  writeFileSync(release.sums, originalSums);
  writeFileSync(join(release.dir, 'notarytool-result.json'), JSON.stringify({ id: '01234567-89ab-cdef-0123-456789abcdef', status: 'Invalid' }));
  const notaryFailure = spawn('verify-release.mjs', [release.manifest, release.signature, release.publicKeyFile, release.fingerprint]);
  assert.notEqual(notaryFailure.status, 0);
  assert.match(notaryFailure.stderr, /notarytool-result\.json.*mismatch/);

  const seed = makeRelease('agentpass-notary-missing-');
  const missing = spawn('generate-manifest.mjs', [
    ...controllerManifestArgs(seed, join(seed.dir, 'missing.manifest.json'), join(seed.dir, 'missing.SHA256SUMS')),
    '--notarization-status=accepted_stapled',
    '--notary-submission=01234567-89ab-cdef-0123-456789abcdef'
  ]);
  assert.notEqual(missing.status, 0);
  assert.match(missing.stderr, /requires.*notarytool.*stapler/i);
});

test('release file inputs reject symlinks and hard links', () => {
  const release = makeRelease('agentpass-release-links-');
  const dir = release.dir;
  const target = join(dir, 'target.pkg'); const symlink = join(dir, 'symlink.pkg'); const hardlink = join(dir, 'hardlink.pkg');
  writeFileSync(target, 'x'); symlinkSync(target, symlink); linkSync(target, hardlink);
  for (const candidate of [symlink, hardlink]) {
    const failed = spawn('generate-manifest.mjs', controllerManifestArgs(release, join(dir, `${candidate.endsWith('symlink.pkg') ? 's' : 'h'}.json`), join(dir, `${candidate.endsWith('symlink.pkg') ? 's' : 'h'}.sums`), { product: candidate }));
    assert.notEqual(failed.status, 0);
    assert.match(failed.stderr, /ELOOP|single-link|regular file/);
  }
});

test('manifest verifier rejects unknown fields even under a valid release signature', () => {
  const release = makeRelease('agentpass-manifest-schema-');
  const value = JSON.parse(readFileSync(release.manifest));
  value.evidence.checksums.untrusted = true;
  const bytes = Buffer.from(canonical(value));
  writeFileSync(release.manifest, bytes);
  const alternateSignature = join(release.dir, 'alternate.sig');
  writeDetachedSignature(alternateSignature, bytes, release.keys.privateKey);
  const failed = spawn('verify-release.mjs', [release.manifest, alternateSignature, release.publicKeyFile, release.fingerprint]);
  assert.notEqual(failed.status, 0);
  assert.match(failed.stderr, /missing or unknown fields/);
});

test('manifest signature trust root is pinned and private signing inputs reject hard links', () => {
  const release = makeRelease('agentpass-release-trust-');
  const other = crypto.generateKeyPairSync('ed25519');
  const mismatch = spawn('verify-release.mjs', [release.manifest, release.signature, release.publicKeyFile, fingerprint(other.publicKey)]);
  assert.notEqual(mismatch.status, 0);
  assert.match(mismatch.stderr, /fingerprint mismatch/);

  const hardlink = join(release.dir, 'release-private-hardlink.pem');
  linkSync(release.privateKeyFile, hardlink);
  const rejected = spawn('sign-manifest.mjs', [release.manifest, hardlink, join(release.dir, 'hardlink.sig')]);
  assert.notEqual(rejected.status, 0);
  assert.match(rejected.stderr, /unsafe release input/);

  const artifactHardlink = join(release.dir, 'artifact-hardlink.zip');
  linkSync(release.artifact, artifactHardlink);
  const linkedArtifact = spawn('verify-release.mjs', [release.manifest, release.signature, release.publicKeyFile, release.fingerprint]);
  assert.notEqual(linkedArtifact.status, 0);
  assert.match(linkedArtifact.stderr, /unsafe release input/);
});

test('manifest trust-root artifact is bound to the public key used for signature verification', () => {
  const release = makeRelease('agentpass-release-trust-root-binding-');
  const manifest = join(release.dir, 'bound.release-manifest.json');
  const sums = join(release.dir, 'bound.SHA256SUMS');
  run('generate-manifest.mjs', [...controllerManifestArgs(release, manifest, sums), release.publicKeyFile]);
  const signature = join(release.dir, 'bound.release-manifest.sig');
  run('sign-manifest.mjs', [manifest, release.privateKeyFile, signature]);

  const other = crypto.generateKeyPairSync('ed25519');
  const otherPublicKey = join(release.dir, 'other.public.pem');
  const otherSignature = join(release.dir, 'other.release-manifest.sig');
  writeFileSync(otherPublicKey, other.publicKey.export({ type: 'spki', format: 'pem' }), { mode: 0o644 });
  writeDetachedSignature(otherSignature, readFileSync(manifest), other.privateKey);
  const failed = spawn('verify-release.mjs', [manifest, otherSignature, otherPublicKey, fingerprint(other.publicKey)]);
  assert.notEqual(failed.status, 0);
  assert.match(failed.stderr, /trust root.*verification public key/iu);
});

test('private staging freezes every manifest-declared byte before verification', () => {
  const release = makeRelease('agentpass-release-stage-');
  const staging = join(release.dir, 'private-stage');
  mkdirSync(staging, { mode: 0o700 });
  const result = JSON.parse(run('stage-release.mjs', [staging, release.manifest, release.signature, release.publicKeyFile]));
  assert.equal(statSync(staging).mode & 0o777, 0o500);
  assert.equal(statSync(result.manifest).mode & 0o777, 0o400);
  assert.equal(result.declared_files, 7);
  for (const name of [
    'AgentPass-v0.17.0-macos-universal.pkg',
    'AgentPassQualificationController-0.18.0-macos-universal.tar',
    'AgentPass-v0.17.0.spdx.json',
    'AgentPassQualificationController.identity.json',
    'controller-notarytool-result.json',
    'controller-stapler-result.txt',
    'SHA256SUMS'
  ]) assert.ok(statSync(join(staging, name)).isFile(), `staging omitted ${name}`);

  writeFileSync(release.artifact, 'source path changed after staging');
  const verified = JSON.parse(run('verify-release.mjs', [result.manifest, result.signature, result.public_key, release.fingerprint]));
  assert.equal(verified.artifacts, 3);

  const linkedRelease = makeRelease('agentpass-release-stage-link-');
  const hardlink = join(linkedRelease.dir, 'artifact-hardlink.zip');
  linkSync(linkedRelease.artifact, hardlink);
  const linkedStaging = join(linkedRelease.dir, 'private-stage');
  mkdirSync(linkedStaging, { mode: 0o700 });
  const rejected = spawn('stage-release.mjs', [linkedStaging, linkedRelease.manifest, linkedRelease.signature, linkedRelease.publicKeyFile]);
  assert.notEqual(rejected.status, 0);
  assert.match(rejected.stderr, /unsafe release staging input/);
});

test('macOS verifier uses staged payloads and enforces production signing policy', () => {
  const verifier = readFileSync(scriptPath('verify-macos-release.sh'), 'utf8');
  const entitlementVerifier = readFileSync(scriptPath('verify-macos-entitlements.mjs'), 'utf8');
  const stageOffset = verifier.indexOf('stage-release.mjs');
  const verifyOffset = verifier.indexOf('verify-release.mjs');
  const extractOffset = verifier.indexOf('pkgutil --expand-full');
  assert.ok(stageOffset > 0 && verifyOffset > stageOffset && extractOffset > verifyOffset);
  assert.match(verifier, /ARTIFACT_DIR="\$\(dirname "\$MANIFEST"\)"/);
  assert.match(verifier, /verify-installer-package\.sh/);
  assert.match(verifier, /stapler validate "\$PACKAGE"/);
  assert.match(verifier, /verify-controller-archive\.mjs/);
  assert.match(verifier, /controller-identity-contract\.mjs" collect/);
  assert.match(verifier, /recollected-identity\.json/);
  assert.match(verifier, /stapler validate "\$CONTROLLER_APP"/);
  assert.match(verifier, /spctl --assess --type execute --verbose=4 "\$CONTROLLER_APP"/);
  assert.match(verifier, /spctl --assess --type install/);
  assert.match(verifier, /for item in "\$SERVICE" "\$CLIENT" "\$MANAGER_BINARY" "\$ONBOARDING_BINARY" "\$APP"/);
  assert.match(verifier, /--test-requirement "=identifier/);
  assert.doesNotMatch(verifier, /=designated =>/);
  assert.match(verifier, /certificate leaf\[subject\.OU\]/);
  assert.match(verifier, /verify-macos-entitlements\.mjs/);
  assert.match(entitlementVerifier, /groups\.length !== 1/);
  assert.match(entitlementVerifier, /keys\.length !== 1/);
  assert.match(entitlementVerifier, /com\.apple\.security\.get-task-allow/);
  assert.match(entitlementVerifier, /com\.apple\.security\.cs\.disable-library-validation/);
  assert.match(verifier, /verify_no_dangerous_entitlements "\$MANAGER_BINARY" manager/);
  assert.match(verifier, /verify_no_dangerous_entitlements "\$ONBOARDING_BINARY" onboarding/);
  assert.match(verifier, /verify_no_dangerous_entitlements "\$APP" outer/);
  const notarizeInstaller = readFileSync(scriptPath('notarize-installer.sh'), 'utf8');
  const notarizeController = readFileSync(scriptPath('notarize-controller.sh'), 'utf8');
  assert.match(notarizeInstaller, /AGENTPASS_TEAM_ID/);
  assert.match(notarizeInstaller, /pkgutil --check-signature/);
  assert.match(notarizeInstaller, /Developer ID Installer/);
  assert.match(notarizeController, /AGENTPASS_TEAM_ID/);
  assert.match(notarizeController, /Developer ID Application/);
  assert.match(notarizeController, /TeamIdentifier=/);
});

test('component installer excludes protected state and ships fail-closed preservation checks', () => {
  const nativeScripts = resolve(root, 'native/macos/scripts');
  const build = readFileSync(join(nativeScripts, 'build-installer.sh'), 'utf8');
  const verify = readFileSync(join(nativeScripts, 'verify-installer-package.sh'), 'utf8');
  const preinstall = readFileSync(join(nativeScripts, 'installer-preinstall.sh'), 'utf8');
  const postinstall = readFileSync(join(nativeScripts, 'installer-postinstall.sh'), 'utf8');
  const preservation = readFileSync(join(nativeScripts, 'validate-preserved-state.sh'), 'utf8');

  assert.match(build, /pkgbuild --root/);
  assert.match(build, /--install-location \/Applications/);
  assert.match(build, /--component-plist/);
  assert.match(build, /Clear array/);
  assert.match(build, /BundleIsRelocatable bool false/);
  assert.match(build, /BundleOverwriteAction string upgrade/);
  assert.match(build, /--sign "\$IDENTITY"/);
  assert.doesNotMatch(build, /Library\/Application Support\/AgentPass/);
  assert.match(verify, /payload-files/);
  assert.match(verify, /Installer payload or package scripts contain secret material/);
  assert.match(verify, /-----BEGIN \(RSA \|EC \|OPENSSH \|ED25519 \)\?PRIVATE KEY-----/);
  assert.match(verify, /Installer payload escapes AgentPass\.app/);
  assert.match(verify, /Installer payload contains protected AgentPass state/);
  assert.match(verify, /install-location.*\/Applications/);
  assert.match(verify, /dev\.agentpass\.installer/);
  assert.match(verify, /strict-identifier/);
  assert.match(verify, /upgrade-bundle/);
  assert.match(verify, /cmp -s/);
  for (const entrypoint of [preinstall, postinstall]) {
    assert.match(entrypoint, /validate-preserved-state\.sh" "\$TARGET_VOLUME" 0/);
    assert.doesNotMatch(entrypoint, /rm\s+-[A-Za-z]*r/);
  }
  assert.match(postinstall, /mkdir -m 0700/);
  assert.match(postinstall, /codesign --verify --deep --strict/);
  assert.match(preservation, /find -P "\$STATE_ROOT" -xdev -print0/);
  assert.match(preservation, /Symbolic Link/);
  assert.match(preservation, /hard-linked file/);
  assert.match(preservation, /grants group\/world permissions/);
  assert.match(preservation, /crosses a filesystem boundary/);
});

test('preservation validator accepts secure state and rejects link and mode substitution', { skip: process.platform !== 'darwin' }, () => {
  const validator = resolve(root, 'native/macos/scripts/validate-preserved-state.sh');
  const volume = mkdtempSync(join(tmpdir(), 'agentpass-installer-state-'));
  const state = join(volume, 'Library/Application Support/AgentPass');
  const lifecycle = join(state, 'key-lifecycle');
  mkdirSync(lifecycle, { recursive: true, mode: 0o700 });
  chmodSync(join(volume, 'Library'), 0o755);
  chmodSync(join(volume, 'Library/Application Support'), 0o755);
  chmodSync(state, 0o700);
  chmodSync(lifecycle, 0o700);
  const audit = join(state, 'audit.jsonl');
  writeFileSync(audit, 'preserved-audit-bytes\n', { mode: 0o600 });
  const uid = String(process.getuid());
  const validate = () => spawnSync('/bin/bash', [validator, volume, uid], { cwd: root, encoding: 'utf8' });
  assert.equal(validate().status, 0);
  assert.equal(readFileSync(audit, 'utf8'), 'preserved-audit-bytes\n');
  const wrongOwnerExpectation = spawnSync('/bin/bash', [validator, volume, String(Number(uid) + 1)], { cwd: root, encoding: 'utf8' });
  assert.notEqual(wrongOwnerExpectation.status, 0);
  assert.match(wrongOwnerExpectation.stderr, /owner|ownership/i);

  const hardlink = join(state, 'audit-hardlink.jsonl');
  linkSync(audit, hardlink);
  const linkedFile = validate();
  assert.notEqual(linkedFile.status, 0);
  assert.match(linkedFile.stderr, /hard-linked/i);
  unlinkSync(hardlink);

  const link = join(lifecycle, 'substitution');
  symlinkSync('/tmp', link);
  const linked = validate();
  assert.notEqual(linked.status, 0);
  assert.match(linked.stderr, /symlink/i);
  unlinkSync(link);

  chmodSync(lifecycle, 0o770);
  const writable = validate();
  assert.notEqual(writable.status, 0);
  assert.match(writable.stderr, /group\/world permissions/i);

  const substitutedVolume = mkdtempSync(join(tmpdir(), 'agentpass-installer-ancestor-'));
  const externalLibrary = mkdtempSync(join(tmpdir(), 'agentpass-external-library-'));
  symlinkSync(externalLibrary, join(substitutedVolume, 'Library'));
  const substituted = spawnSync('/bin/bash', [validator, substitutedVolume, uid], { cwd: root, encoding: 'utf8' });
  assert.notEqual(substituted.status, 0);
  assert.match(substituted.stderr, /ancestry.*symlink/i);
});

test('signed entitlement policy rejects privilege expansion without production certificates', () => {
  const group = 'APPLETEAM1.dev.agentpass.service-keys';
  const check = (role, value, ...expected) => spawn('verify-macos-entitlements.mjs', [role, ...expected], { input: JSON.stringify(value) });
  assert.equal(check('service', { 'keychain-access-groups': [group] }, group).status, 0);
  assert.equal(check('manager', {}).status, 0);
  const controller = {
    'application-identifier': 'APPLETEAM1.dev.agentpass.qualification-controller',
    'com.apple.developer.team-identifier': 'APPLETEAM1',
    'dev.agentpass.qualification-control': true
  };
  assert.equal(check('controller', controller, 'APPLETEAM1', 'APPLETEAM1').status, 0);
  assert.notEqual(check('controller', { ...controller, 'keychain-access-groups': [group] }, 'APPLETEAM1', 'APPLETEAM1').status, 0);

  for (const value of [
    { 'keychain-access-groups': [group, 'APPLETEAM1.dev.agentpass.approval-keys'] },
    { 'keychain-access-groups': [group], 'com.apple.security.get-task-allow': true },
    { 'keychain-access-groups': [group], 'com.apple.security.cs.disable-library-validation': true }
  ]) {
    const rejected = check('service', value, group);
    assert.notEqual(rejected.status, 0);
  }
  assert.notEqual(check('manager', { 'keychain-access-groups': [group] }).status, 0);
  assert.notEqual(check('outer', { 'com.apple.security.cs.disable-library-validation': true }).status, 0);
});

test('legacy hardware qualification cannot assert production qualification', () => {
  const template = resolve(root, 'scripts/release/hardware-qualification.template.json');
  assert.equal(JSON.parse(run('validate-hardware-qualification.mjs', [template])).qualified, false);

  const dir = mkdtempSync(join(tmpdir(), 'agentpass-hardware-'));
  const artifact = join(dir, 'AgentPass.zip'); writeFileSync(artifact, 'qualified candidate');
  const artifactDigest = crypto.createHash('sha256').update(readFileSync(artifact)).digest('hex');
  const required = [
    'install-and-register', 'secure-enclave-key-creation', 'secure-enclave-nonexportability',
    'unattended-sign', 'session-expiry-revocation', 'all-key-rotations', 'key-deletion-absence',
    'lifecycle-rollback-fail-stop', 'checkpoint-anchor-transition', 'recovery-threshold',
    'audit-evidence-rotation', 'audit-segment-corruption', 'sleep-wake', 'reboot',
    'upgrade-preserves-state', 'uninstall-preserves-state', 'tampered-client-denied',
    'apple-silicon-secure-enclave'
  ];
  const reportValue = {
    schema_version: 1,
    artifact_sha256: artifactDigest,
    architecture: 'arm64',
    hardware_class: 'apple_silicon',
    model_identifier: 'Mac15,7',
    macos_version: '15.6',
    macos_build: '24G84',
    secure_enclave: true,
    started_at: '2026-08-11T00:00:00.000Z',
    completed_at: '2026-08-11T00:30:00.000Z',
    operator: 'release-operator@example.com',
    qualified: true,
    tests: required.map((name) => ({ name, status: 'passed', evidence: `sha256:${crypto.createHash('sha256').update(name).digest('hex')}` }))
  };
  const report = join(dir, 'qualification.json'); const signature = join(dir, 'qualification.sig');
  const publicKeyFile = join(dir, 'operator.public.pem'); const keys = crypto.generateKeyPairSync('ed25519');
  const reportBytes = Buffer.from(canonical(reportValue)); writeFileSync(report, reportBytes);
  writeDetachedSignature(signature, reportBytes, keys.privateKey);
  writeFileSync(publicKeyFile, keys.publicKey.export({ type: 'spki', format: 'pem' }));

  const rejected = spawn('validate-hardware-qualification.mjs', [report]);
  assert.notEqual(rejected.status, 0);
  assert.match(rejected.stderr, /v1 hardware qualification is accepted only as unqualified\/non-production/);
});

test('hardware reports reject unknown fields and self-asserted qualification', () => {
  const template = JSON.parse(readFileSync(resolve(root, 'scripts/release/hardware-qualification.template.json')));
  const dir = mkdtempSync(join(tmpdir(), 'agentpass-hardware-invalid-'));
  template.untrusted = true;
  const unknown = join(dir, 'unknown.json'); writeFileSync(unknown, canonical(template));
  const unknownFailure = spawn('validate-hardware-qualification.mjs', [unknown]);
  assert.notEqual(unknownFailure.status, 0);
  assert.match(unknownFailure.stderr, /missing or unknown fields/);

  delete template.untrusted; template.qualified = true;
  const selfAsserted = join(dir, 'self-asserted.json'); writeFileSync(selfAsserted, canonical(template));
  const selfFailure = spawn('validate-hardware-qualification.mjs', [selfAsserted]);
  assert.notEqual(selfFailure.status, 0);
  assert.match(selfFailure.stderr, /signed release manifest|detached operator signature|self-asserted/);
});

test('release candidate verifies signed source before the secret-bearing job and cannot publish', () => {
  const workflow = readFileSync(resolve(root, '.github/workflows/release-candidate.yml'), 'utf8');
  assert.doesNotMatch(workflow, /pull_request(?:_target)?:/);
  assert.doesNotMatch(workflow, /push:\s*\n\s*tags:/);
  for (const use of workflow.matchAll(/uses:\s*([^\s]+)/g)) assert.match(use[1], /^[^@]+@[0-9a-f]{40}$/);
  assert.match(workflow, /environment: production-signing/);
  assert.match(workflow, /verify-source:/);
  assert.match(workflow, /needs: verify-source/);
  assert.match(workflow, /AGENTPASS_RELEASE_ALLOWED_SIGNERS/);
  assert.match(workflow, /verify-tag/);
  assert.match(workflow, /persist-credentials: false/g);
  assert.match(workflow, /AGENTPASS_INSTALLER_SIGNING_IDENTITY/);
  assert.match(workflow, /AGENTPASS_NOTARY_PRIVATE_KEY_BASE64/);
  assert.match(workflow, /notarize-installer\.sh/);
  assert.match(workflow, /notarize-controller\.sh/);
  assert.match(workflow, /--notarization-status=accepted_stapled/);
  assert.match(workflow, /verify-macos-release\.sh/);
  const candidateScanStart = workflow.indexOf('install -m 0600 "$RUNNER_TEMP/candidate/ci-preflight.json" "$ci_preflight_scan_root/ci-preflight.json"');
  const preflightScan = workflow.indexOf('node scripts/release/ci-preflight.mjs artifact-scan', candidateScanStart);
  const preflightCopy = workflow.indexOf('install -m 0644 "$RUNNER_TEMP/candidate/ci-preflight.json" "$integrity_dir/ci-preflight.json"', preflightScan);
  const candidateRemoval = workflow.indexOf('rm -f "$RUNNER_TEMP/candidate/ci-preflight.json"', preflightCopy);
  const productScan = workflow.indexOf('node scripts/release/ci-preflight.mjs artifact-scan', candidateRemoval);
  assert.ok(candidateScanStart >= 0 && preflightScan > candidateScanStart && preflightCopy > preflightScan && candidateRemoval > preflightCopy && productScan > candidateRemoval, "preflight must be scanned separately before the candidate scan");
  assert.match(workflow, /Archive-scan the final raw evidence upload inventory[\s\S]*?archive-secret-scan\.mjs "\$RUNNER_TEMP\/integrity-evidence"/);
  assert.match(workflow, /Require source-bound external qualification evidence inputs[\s\S]*?AGENTPASS_KMS_QUALIFICATION_EVIDENCE_JSON/);
  assert.match(workflow, /AGENTPASS_PLATFORM_AUTH_QUALIFICATION_EVIDENCE_JSON[\s\S]*?canonical JSON[\s\S]*?kms-qualification/);
  assert.match(workflow, /ci-preflight\.mjs kms-qualification[\s\S]*?ci-preflight\.mjs platform-auth-qualification/);
  assert.match(workflow, /AGENTPASS_PLATFORM_AUTH_QUALIFICATION_PRIMARY_DEPLOYMENT_DIGEST/);
  assert.match(workflow, /AGENTPASS_PLATFORM_AUTH_QUALIFICATION_SECONDARY_DEPLOYMENT_DIGEST/);
  assert.match(workflow, /platform-auth-qualification[^\n]*\$AGENTPASS_PLATFORM_AUTH_QUALIFICATION_PRIMARY_DEPLOYMENT_DIGEST[^\n]*\$AGENTPASS_PLATFORM_AUTH_QUALIFICATION_SECONDARY_DEPLOYMENT_DIGEST/);
  assert.match(workflow, /release-integrity-evidence[\s\S]*?kms-qualification\.json[\s\S]*?platform-auth-qualification\.json/);
  assert.match(workflow, /Validate frozen protocol and schema catalog before signing[\s\S]*?npm run contracts:validate[\s\S]*?node --test test\/contract-catalog\.test\.mjs/);
  assert.doesNotMatch(workflow, /gh release (?:create|upload|edit)|^  publish:/m);
  assert.doesNotMatch(workflow, /NOT_NOTARIZED/);
  const controllerNotary = readFileSync(scriptPath('notarize-controller.sh'), 'utf8');
  assert.match(controllerNotary, /notarytool submit "\$SUBMISSION" --wait --output-format json/);
  assert.match(controllerNotary, /stapler staple "\$CONTROLLER"/);
  assert.match(controllerNotary, /stapler validate "\$CONTROLLER"/);
  assert.match(controllerNotary, /spctl --assess --type execute/);
  assert.match(controllerNotary, /codesign --verify --strict/);
  const verifySource = workflow.slice(workflow.indexOf('  verify-source:'), workflow.indexOf('  signed-candidate:'));
  assert.doesNotMatch(verifySource, /secrets\./);
});
