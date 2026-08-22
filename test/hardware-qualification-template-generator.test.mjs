import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import { spawnSync } from 'node:child_process';
import { join } from 'node:path';
import { afterEach, test } from 'node:test';

import {
  REPORT_KEYS,
  REQUIRED_CODE_IDENTITIES,
  canonicalJSON,
  generateHardwareQualificationTemplate,
  parseArguments,
  readPinnedBrowserVersions,
  writeCanonicalExclusive
} from '../scripts/release/generate-hardware-qualification-template.mjs';
import {
  CONTRACT_KIND,
  designatedRequirementForTeam,
  canonicalJSON as canonicalControllerIdentityJSON
} from '../scripts/release/n3e/controller-identity-contract.mjs';
import { deriveReleaseCandidateId } from '../lib/release-candidate-identity.mjs';

const ROOT = new URL('..', import.meta.url).pathname.replace(/\/$/u, '');
const GENERATOR = join(ROOT, 'scripts/release/generate-hardware-qualification-template.mjs');
const VALID_RELEASE_KEY_FINGERPRINT = (key) => `SHA256:${crypto.createHash('sha256').update(key.export({ type: 'spki', format: 'der' })).digest('base64url')}`;
const digest = (value) => crypto.createHash('sha256').update(value).digest('hex');
const canonical = (value) => canonicalJSON(value);
const cleanupDirectories = [];

afterEach(() => {
  for (const directory of cleanupDirectories.splice(0)) fs.rmSync(directory, { recursive: true, force: true });
});

const writeSignature = (path, bytes, privateKey) => fs.writeFileSync(path, `${crypto.sign(null, bytes, privateKey).toString('base64')}\n`, { mode: 0o644 });

const makeFixture = () => {
  const directory = fs.mkdtempSync(join(os.tmpdir(), 'agentpass-template-generator-'));
  cleanupDirectories.push(directory);
  const releaseDirectory = join(directory, 'release');
  fs.mkdirSync(releaseDirectory, { mode: 0o755 });
  const releaseKeys = crypto.generateKeyPairSync('ed25519');
  const teamID = 'ABCDE12345';
  const sourceCommit = 'a'.repeat(40);
  const sourceTree = 'b'.repeat(40);
  const productName = 'AgentPass-v0.18.0-macos-universal.pkg';
  const productBytes = Buffer.from('signed and notarized AgentPass product fixture\n');
  const controllerName = 'AgentPassQualificationController-0.18.0-macos-universal.tar';
  const controllerBytes = Buffer.from('external qualification controller fixture\n');
  const nestedCodeIdentities = REQUIRED_CODE_IDENTITIES.map((item, index) => ({
    path: item.path,
    bundle_id: item.bundle_id,
    team_id: teamID,
    code_directory_hash: String(index + 1).repeat(40)
  }));
  const signerKeyVersions = [
    { name: 'cloud', version: 'cloud-2026.08' },
    { name: 'device', version: 'device-2026.08' }
  ];
  const lockBytes = Buffer.from('{"lockfileVersion":3}\n');
  const migrationBytes = Buffer.from('{"schema_version":1,"migration":"0011"}\n');
  const cloudImageDigest = `sha256:${'c'.repeat(64)}`;
  const attestation = {
    schema_version: 1,
    team_id: teamID,
    nested_code_identities: nestedCodeIdentities,
    cloud_image_digest: cloudImageDigest,
    dependency_lock_sha256: digest(lockBytes),
    database_migration_manifest_sha256: digest(migrationBytes),
    signer_key_versions: signerKeyVersions
  };
  const controllerIdentity = {
    schema_version: 1,
    kind: CONTRACT_KIND,
    archive_name: controllerName,
    archive_sha256: digest(controllerBytes),
    archive_bytes: controllerBytes.length,
    bundle_id: 'dev.agentpass.qualification-controller',
    team_id: teamID,
    entitlements_sha256: digest(Buffer.from('qualification-control.entitlements\n')),
    code_directory_hashes: [
      { architecture: 'arm64', hash: 'd'.repeat(40) },
      { architecture: 'x86_64', hash: 'e'.repeat(40) }
    ],
    designated_requirements: [
      { architecture: 'arm64', requirement: designatedRequirementForTeam(teamID, 'd'.repeat(40)) },
      { architecture: 'x86_64', requirement: designatedRequirementForTeam(teamID, 'e'.repeat(40)) }
    ],
    authorization_requirements: [
      { architecture: 'arm64', requirement: designatedRequirementForTeam(teamID, 'd'.repeat(40)) },
      { architecture: 'x86_64', requirement: designatedRequirementForTeam(teamID, 'e'.repeat(40)) }
    ]
  };
  const identityBytes = canonicalControllerIdentityJSON(controllerIdentity);
  const sbom = {
    spdxVersion: 'SPDX-2.3',
    SPDXID: 'SPDXRef-DOCUMENT',
    documentNamespace: 'https://github.com/Torutesu/Agentpass/sbom/fixture',
    documentDescribes: ['SPDXRef-AgentPass'],
    creationInfo: {
      comment: JSON.stringify({ source_commit: sourceCommit, source_tree: sourceTree, swift_input_count: 4, swift: '6.1', macos_sdk: '26.0' })
    },
    packages: [{
      SPDXID: 'SPDXRef-AgentPass',
      versionInfo: '0.18.0',
      sourceInfo: `source commit ${sourceCommit}; source tree ${sourceTree}`
    }]
  };
  const files = new Map([
    [productName, productBytes],
    [controllerName, controllerBytes],
    ['AgentPass-0.18.0.spdx.json', canonical(sbom)],
    ['database-migration-manifest.json', migrationBytes],
    ['package-lock.json', lockBytes],
    ['release-attestation.json', canonical(attestation)]
  ]);
  for (const [name, bytes] of files) fs.writeFileSync(join(releaseDirectory, name), bytes, { mode: 0o644 });
  const identityName = 'AgentPassQualificationController.identity.json';
  fs.writeFileSync(join(releaseDirectory, identityName), identityBytes, { mode: 0o644 });
  const notaryID = '12345678-1234-1234-1234-123456789abc';
  const notaryBytes = canonical({ status: 'Accepted', id: notaryID });
  const staplerBytes = Buffer.from('The validate action worked!\n');
  const controllerNotaryID = 'abcdefab-cdef-cdef-cdef-abcdefabcdef';
  const controllerNotaryBytes = canonical({ status: 'Accepted', id: controllerNotaryID });
  const controllerStaplerBytes = Buffer.from('The validate action worked!\n');
  fs.writeFileSync(join(releaseDirectory, 'notarytool-result.json'), notaryBytes, { mode: 0o644 });
  fs.writeFileSync(join(releaseDirectory, 'stapler-result.txt'), staplerBytes, { mode: 0o644 });
  fs.writeFileSync(join(releaseDirectory, 'controller-notarytool-result.json'), controllerNotaryBytes, { mode: 0o644 });
  fs.writeFileSync(join(releaseDirectory, 'controller-stapler-result.txt'), controllerStaplerBytes, { mode: 0o644 });
  const artifacts = [...files.entries()].map(([name, bytes]) => ({
    name,
    role: name.endsWith('.spdx.json') ? 'sbom' : name === productName ? 'product' : name === controllerName ? 'external_qualification_controller' : 'auxiliary',
    media_type: name.endsWith('.spdx.json') ? 'application/spdx+json' : name.endsWith('.pkg') ? 'application/vnd.apple.installer+xml' : name === controllerName ? 'application/octet-stream' : 'application/json',
    bytes: bytes.length,
    sha256: digest(bytes)
  })).sort((left, right) => left.name.localeCompare(right.name));
  const notarizationEvidence = [
    { kind: 'notarytool_result', name: 'notarytool-result.json', bytes: notaryBytes.length, sha256: digest(notaryBytes) },
    { kind: 'stapler_result', name: 'stapler-result.txt', bytes: staplerBytes.length, sha256: digest(staplerBytes) }
  ];
  const controllerNotarizationEvidence = [
    { kind: 'notarytool_result', name: 'controller-notarytool-result.json', bytes: controllerNotaryBytes.length, sha256: digest(controllerNotaryBytes) },
    { kind: 'stapler_result', name: 'controller-stapler-result.txt', bytes: controllerStaplerBytes.length, sha256: digest(controllerStaplerBytes) }
  ];
  const identityDocument = { name: identityName, bytes: identityBytes.length, sha256: digest(identityBytes) };
  const checksumEntries = [...artifacts, ...notarizationEvidence, identityDocument, ...controllerNotarizationEvidence].sort((left, right) => left.name.localeCompare(right.name));
  const checksumsBytes = Buffer.from(`${checksumEntries.map((item) => `${item.sha256}  ${item.name}`).join('\n')}\n`, 'utf8');
  fs.writeFileSync(join(releaseDirectory, 'SHA256SUMS'), checksumsBytes, { mode: 0o644 });
  const manifest = {
    schema_version: 4,
    product: 'AgentPass',
    version: '0.18.0',
    source: { commit: sourceCommit, tree: sourceTree, tag: 'v0.18.0' },
    generated_at: '2026-08-13T00:00:00.000Z',
    candidate_id: deriveReleaseCandidateId(digest(productBytes)),
    artifacts,
    external_qualification_controller: {
      identity_document: identityDocument,
      identity: controllerIdentity,
      notarization: { status: 'accepted_stapled', submission_ids: [controllerNotaryID], evidence: controllerNotarizationEvidence }
    },
    evidence: {
      checksums: { name: 'SHA256SUMS', bytes: checksumsBytes.length, sha256: digest(checksumsBytes), entry_count: checksumEntries.length },
      sbom: {
        artifact_name: 'AgentPass-0.18.0.spdx.json',
        sha256: digest(files.get('AgentPass-0.18.0.spdx.json')),
        spdx_version: 'SPDX-2.3',
        document_namespace: sbom.documentNamespace,
        document_spdx_id: 'SPDXRef-DOCUMENT',
        document_describes: ['SPDXRef-AgentPass'],
        source_commit: sourceCommit,
        source_tree: sourceTree
      },
      notarization: { status: 'accepted_stapled', submission_ids: [notaryID], evidence: notarizationEvidence }
    }
  };
  const manifestBytes = canonical(manifest);
  const manifestPath = join(releaseDirectory, 'release-manifest.json');
  const signaturePath = join(releaseDirectory, 'release-manifest.sig');
  const publicKeyPath = join(releaseDirectory, 'release-manifest.public.pem');
  fs.writeFileSync(manifestPath, manifestBytes, { mode: 0o644 });
  writeSignature(signaturePath, manifestBytes, releaseKeys.privateKey);
  fs.writeFileSync(publicKeyPath, releaseKeys.publicKey.export({ type: 'spki', format: 'pem' }), { mode: 0o644 });
  const browserVersions = [
    { name: 'chromium', version: '151.0.7922.34' },
    { name: 'webkit', version: '26.0' }
  ];
  const browserPath = join(directory, 'browser-versions.json');
  fs.writeFileSync(browserPath, canonical(browserVersions), { mode: 0o644 });
  const operatorKeys = crypto.generateKeyPairSync('ed25519');
  return {
    directory,
    releaseDirectory,
    manifestPath,
    signaturePath,
    publicKeyPath,
    releaseFingerprint: VALID_RELEASE_KEY_FINGERPRINT(releaseKeys.publicKey),
    artifactPath: join(releaseDirectory, productName),
    browserPath,
    browserVersions,
    operator: 'operator@example.com',
    operatorFingerprint: VALID_RELEASE_KEY_FINGERPRINT(operatorKeys.publicKey),
    manifest,
    attestation,
    controllerIdentity,
    identityBytes,
    identityDocument,
    controllerNotarizationEvidence,
    productName,
    releaseKeys,
    operatorKeys
  };
};

const generateArgs = (fixture, outputPath) => ({
  releaseManifestPath: fixture.manifestPath,
  releaseSignaturePath: fixture.signaturePath,
  releasePublicKeyPath: fixture.publicKeyPath,
  releaseFingerprint: fixture.releaseFingerprint,
  artifactPath: fixture.artifactPath,
  operator: fixture.operator,
  operatorKeyFingerprint: fixture.operatorFingerprint,
  browserVersions: fixture.browserVersions,
  outputPath
});

const rewriteSignedManifest = (fixture, mutate) => {
  const manifest = JSON.parse(fs.readFileSync(fixture.manifestPath));
  mutate(manifest);
  const bytes = canonical(manifest);
  fs.writeFileSync(fixture.manifestPath, bytes);
  writeSignature(fixture.signaturePath, bytes, fixture.releaseKeys.privateKey);
  return manifest;
};

const rewriteIdentityBinding = (fixture, identity, { canonicalBytes = canonicalControllerIdentityJSON(identity) } = {}) => {
  const identityPath = join(fixture.releaseDirectory, fixture.identityDocument.name);
  fs.writeFileSync(identityPath, canonicalBytes);
  const checksumPath = join(fixture.releaseDirectory, fixture.manifest.evidence.checksums.name);
  const manifest = JSON.parse(fs.readFileSync(fixture.manifestPath));
  const binding = manifest.external_qualification_controller.identity_document;
  binding.bytes = canonicalBytes.length;
  binding.sha256 = digest(canonicalBytes);
  manifest.external_qualification_controller.identity = identity;
  const checksums = fs.readFileSync(checksumPath, 'utf8').split('\n');
  const identityIndex = checksums.findIndex((line) => line.endsWith(`  ${binding.name}`));
  checksums[identityIndex] = `${binding.sha256}  ${binding.name}`;
  const checksumBytes = Buffer.from(checksums.join('\n'), 'utf8');
  fs.writeFileSync(checksumPath, checksumBytes);
  manifest.evidence.checksums.bytes = checksumBytes.length;
  manifest.evidence.checksums.sha256 = digest(checksumBytes);
  const manifestBytes = canonical(manifest);
  fs.writeFileSync(fixture.manifestPath, manifestBytes);
  writeSignature(fixture.signaturePath, manifestBytes, fixture.releaseKeys.privateKey);
};

test('creates a canonical, unqualified v2 template bound to the signed v4 release', () => {
  const fixture = makeFixture();
  const output = join(fixture.directory, 'hardware-qualification-template.json');
  const template = generateHardwareQualificationTemplate(generateArgs(fixture, output));
  assert.deepEqual(Object.keys(template).sort(), [...REPORT_KEYS].sort());
  assert.equal(template.schema_version, 2);
  assert.equal(template.source_commit, fixture.manifest.source.commit);
  assert.equal(template.source_tree, fixture.manifest.source.tree);
  assert.equal(template.release_manifest_sha256, digest(fs.readFileSync(fixture.manifestPath)));
  assert.equal(template.artifact_name, fixture.productName);
  assert.equal(template.artifact_sha256, digest(fs.readFileSync(fixture.artifactPath)));
  assert.deepEqual(template.nested_code_identities, fixture.attestation.nested_code_identities);
  assert.deepEqual(template.notarization, fixture.manifest.evidence.notarization);
  assert.equal(template.dependency_lock_sha256, fixture.attestation.dependency_lock_sha256);
  assert.equal(template.database_migration_manifest_sha256, fixture.attestation.database_migration_manifest_sha256);
  assert.deepEqual(template.signer_key_versions, fixture.attestation.signer_key_versions);
  assert.deepEqual(template.browser_versions, fixture.browserVersions);
  assert.equal(template.operator, fixture.operator);
  assert.equal(template.operator_key_fingerprint, fixture.operatorFingerprint);
  assert.equal(Object.keys(template).some((key) => key.includes('controller')), false);
  assert.equal(fixture.manifest.schema_version, 4);
  assert.equal(fixture.manifest.artifacts.filter((item) => item.role === 'external_qualification_controller').length, 1);
  assert.equal(fixture.manifest.artifacts.filter((item) => item.role === 'product').length, 1);
  assert.equal(fixture.manifest.external_qualification_controller.identity_document.bytes, fixture.identityBytes.length);
  assert.equal(fixture.manifest.external_qualification_controller.identity_document.sha256, digest(fixture.identityBytes));
  assert.equal(fixture.manifest.evidence.checksums.entry_count,
    fixture.manifest.artifacts.length + fixture.manifest.evidence.notarization.evidence.length + 1
      + fixture.manifest.external_qualification_controller.notarization.evidence.length);
  const checksumText = fs.readFileSync(join(fixture.releaseDirectory, 'SHA256SUMS'), 'utf8');
  for (const name of [fixture.identityDocument.name, ...fixture.controllerNotarizationEvidence.map((item) => item.name)]) {
    assert.match(checksumText, new RegExp(`  ${name.replace(/[.*+?^${}()|[\]\\]/gu, '\\$&')}\\n`, 'u'));
  }
  assert.equal(template.qualified, false);
  assert.equal(template.tests[0].status, 'skipped');
  assert.equal(template.gates[0].status, 'skipped');
  assert.equal(canonical(template).toString('utf8').includes('REPLACE_WITH'), false);
  const written = writeCanonicalExclusive(output, template);
  assert.equal(fs.readFileSync(output).toString('utf8'), canonical(template).toString('utf8'));
  assert.equal(written.sha256, digest(fs.readFileSync(output)));
  const validator = spawnSync(process.execPath, [join(ROOT, 'scripts/release/validate-hardware-qualification.mjs'), output], { encoding: 'utf8' });
  assert.equal(validator.status, 0, validator.stderr);
  assert.equal(JSON.parse(validator.stdout).production, false);
  assert.throws(() => writeCanonicalExclusive(output, template), /already exists|refusing overwrite/u);
});

test('accepts only canonical, sorted external browser pins and rejects unknown fields', () => {
  const fixture = makeFixture();
  assert.deepEqual(readPinnedBrowserVersions(fixture.browserPath), fixture.browserVersions);
  const noncanonical = join(fixture.directory, 'browser-noncanonical.json');
  fs.writeFileSync(noncanonical, JSON.stringify(fixture.browserVersions));
  assert.throws(() => readPinnedBrowserVersions(noncanonical), /canonical JSON/u);
  const unknown = join(fixture.directory, 'browser-unknown.json');
  fs.writeFileSync(unknown, canonical([{ name: 'chromium', version: '1', extra: 'reject' }]));
  assert.throws(() => readPinnedBrowserVersions(unknown), /unknown fields/u);
  const unsorted = join(fixture.directory, 'browser-unsorted.json');
  fs.writeFileSync(unsorted, canonical([...fixture.browserVersions].reverse()));
  assert.throws(() => readPinnedBrowserVersions(unsorted), /unsorted/u);
});

test('attacks v4 controller bindings and release-manifest boundaries', () => {
  const missingController = makeFixture();
  rewriteSignedManifest(missingController, (manifest) => { delete manifest.external_qualification_controller; });
  assert.throws(() => generateHardwareQualificationTemplate(generateArgs(missingController, join(missingController.directory, 'missing.json'))), /release manifest has missing or unknown fields/u);

  const wrongRole = makeFixture();
  rewriteSignedManifest(wrongRole, (manifest) => {
    manifest.artifacts.find((item) => item.name === wrongRole.controllerIdentity.archive_name).role = 'product';
  });
  assert.throws(() => generateHardwareQualificationTemplate(generateArgs(wrongRole, join(wrongRole.directory, 'wrong-role.json'))), /exactly one canonical macOS product|external qualification controller/u);

  for (const [label, mutate] of [
    ['digest', (identity) => { identity.archive_sha256 = 'f'.repeat(64); }],
    ['bytes', (identity) => { identity.archive_bytes += 1; }],
    ['versioned name', (identity) => { identity.archive_name = 'AgentPassQualificationController-0.18.1-macos-universal.tar'; }]
  ]) {
    const archiveBinding = makeFixture();
    const substitutedIdentity = structuredClone(archiveBinding.controllerIdentity);
    mutate(substitutedIdentity);
    rewriteIdentityBinding(archiveBinding, substitutedIdentity);
    assert.throws(() => generateHardwareQualificationTemplate(generateArgs(archiveBinding, join(archiveBinding.directory, `${label}.json`))), /controller identity does not bind the exact external archive/u);
  }

  const noncanonicalIdentity = makeFixture();
  const prettyIdentity = Buffer.from(`${JSON.stringify(noncanonicalIdentity.controllerIdentity, null, 2)}\n`, 'utf8');
  rewriteIdentityBinding(noncanonicalIdentity, noncanonicalIdentity.controllerIdentity, { canonicalBytes: prettyIdentity });
  assert.throws(() => generateHardwareQualificationTemplate(generateArgs(noncanonicalIdentity, join(noncanonicalIdentity.directory, 'noncanonical.json'))), /controller identity document.*canonical JSON/u);

  const wrongTeam = makeFixture();
  const substitutedIdentity = structuredClone(wrongTeam.controllerIdentity);
  substitutedIdentity.team_id = 'ZZZZZZ9999';
  substitutedIdentity.designated_requirements = substitutedIdentity.designated_requirements.map((item) => ({
    ...item,
    requirement: designatedRequirementForTeam(substitutedIdentity.team_id, substitutedIdentity.code_directory_hashes.find((hash) => hash.architecture === item.architecture).hash)
  }));
  substitutedIdentity.authorization_requirements = substitutedIdentity.authorization_requirements.map((item) => ({
    ...item,
    requirement: designatedRequirementForTeam(substitutedIdentity.team_id, substitutedIdentity.code_directory_hashes.find((hash) => hash.architecture === item.architecture).hash)
  }));
  rewriteIdentityBinding(wrongTeam, substitutedIdentity);
  assert.throws(() => generateHardwareQualificationTemplate(generateArgs(wrongTeam, join(wrongTeam.directory, 'wrong-team.json'))), /Team ID does not match/u);

  const incompleteControllerNotarization = makeFixture();
  rewriteSignedManifest(incompleteControllerNotarization, (manifest) => {
    manifest.external_qualification_controller.notarization.evidence.pop();
  });
  assert.throws(() => generateHardwareQualificationTemplate(generateArgs(incompleteControllerNotarization, join(incompleteControllerNotarization.directory, 'incomplete-notarization.json'))), /controller notarization evidence is incomplete/u);

  const omittedControllerChecksum = makeFixture();
  rewriteSignedManifest(omittedControllerChecksum, (manifest) => {
    manifest.evidence.checksums.entry_count -= 1;
  });
  assert.throws(() => generateHardwareQualificationTemplate(generateArgs(omittedControllerChecksum, join(omittedControllerChecksum.directory, 'omitted-checksum.json'))), /checksums evidence is invalid/u);
});

test('rejects signature, manifest, attestation, notarization, and artifact substitutions', () => {
  const fixture = makeFixture();
  const base = generateArgs(fixture, join(fixture.directory, 'out.json'));
  const originalManifest = fs.readFileSync(fixture.manifestPath);
  fs.writeFileSync(fixture.manifestPath, Buffer.from(originalManifest.toString('utf8').replace('0.18.0', '0.18.1')));
  assert.throws(() => generateHardwareQualificationTemplate(base), /canonical JSON|signature is invalid/u);
  fs.writeFileSync(fixture.manifestPath, originalManifest);
  assert.throws(() => generateHardwareQualificationTemplate({ ...base, releaseFingerprint: fixture.operatorFingerprint }), /fingerprint mismatch/u);

  const otherArtifact = join(fixture.directory, fixture.productName);
  fs.writeFileSync(otherArtifact, 'substituted product\n');
  assert.throws(() => generateHardwareQualificationTemplate({ ...base, artifactPath: otherArtifact }), /does not match/u);

  const attestationPath = join(fixture.releaseDirectory, 'release-attestation.json');
  const attestation = JSON.parse(fs.readFileSync(attestationPath));
  attestation.team_id = 'ZZZZZZ9999';
  fs.writeFileSync(attestationPath, canonical(attestation));
  assert.throws(() => generateHardwareQualificationTemplate(base), /artifact digest mismatch|attestation/u);
});

test('requires the signed migration artifact to match the attested migration digest', () => {
  const fixture = makeFixture();
  const manifest = JSON.parse(fs.readFileSync(fixture.manifestPath));
  const migration = manifest.artifacts.find((item) => item.name === 'database-migration-manifest.json');
  migration.sha256 = 'f'.repeat(64);
  const bytes = canonical(manifest);
  fs.writeFileSync(fixture.manifestPath, bytes);
  writeSignature(fixture.signaturePath, bytes, fixture.releaseKeys.privateKey);
  assert.throws(() => generateHardwareQualificationTemplate(generateArgs(fixture, join(fixture.directory, 'out.json'))), /migration manifest|artifact digest/u);
});

test('rejects a signed release whose source tree disagrees with its signed SBOM bindings', () => {
  const fixture = makeFixture();
  rewriteSignedManifest(fixture, (manifest) => { manifest.source.tree = 'c'.repeat(40); });
  assert.throws(() => generateHardwareQualificationTemplate(generateArgs(fixture, join(fixture.directory, 'source-tree-mismatch.json'))), /SBOM source identity|SBOM binding/u);
});

test('rejects unsafe symlink and hard-link inputs before trusting their bytes', () => {
  const fixture = makeFixture();
  const base = generateArgs(fixture, join(fixture.directory, 'out.json'));
  const manifestLink = join(fixture.directory, 'manifest-link.json');
  fs.symlinkSync(fixture.manifestPath, manifestLink);
  assert.throws(() => generateHardwareQualificationTemplate({ ...base, releaseManifestPath: manifestLink }), /symlink|cannot open/u);
  const browserLink = join(fixture.directory, 'browser-link.json');
  fs.symlinkSync(fixture.browserPath, browserLink);
  assert.throws(() => readPinnedBrowserVersions(browserLink), /symlink|cannot open/u);
  const browserHardLink = join(fixture.directory, 'browser-hardlink.json');
  fs.linkSync(fixture.browserPath, browserHardLink);
  assert.throws(() => readPinnedBrowserVersions(browserHardLink), /unsafe|single-link|cannot open/u);
  const keyLink = join(fixture.directory, 'key-link.pem');
  fs.symlinkSync(fixture.publicKeyPath, keyLink);
  assert.throws(() => generateHardwareQualificationTemplate({ ...base, releasePublicKeyPath: keyLink }), /symlink|cannot open/u);
  const outputLink = join(fixture.directory, 'output-link.json');
  fs.symlinkSync(fixture.manifestPath, outputLink);
  assert.throws(() => writeCanonicalExclusive(outputLink, { safe: true }), /symlink|output/u);
});

test('never self-qualifies and refuses output replacement atomically', () => {
  const fixture = makeFixture();
  const output = join(fixture.directory, 'template.json');
  const template = generateHardwareQualificationTemplate(generateArgs(fixture, output));
  assert.equal(template.qualified, false);
  assert.notEqual(template.tests[0].status, 'passed');
  assert.notEqual(template.gates[0].status, 'passed');
  fs.writeFileSync(output, 'sentinel\n', { mode: 0o644 });
  assert.throws(() => writeCanonicalExclusive(output, template), /already exists|refusing overwrite/u);
  assert.equal(fs.readFileSync(output, 'utf8'), 'sentinel\n');
});

test('CLI is strict, requires all externally pinned inputs, and emits only a false qualification result', () => {
  const fixture = makeFixture();
  const output = join(fixture.directory, 'cli-template.json');
  const args = [
    '--release-manifest', fixture.manifestPath,
    '--release-signature', fixture.signaturePath,
    '--release-public-key', fixture.publicKeyPath,
    '--release-fingerprint', fixture.releaseFingerprint,
    '--artifact', fixture.artifactPath,
    '--operator', fixture.operator,
    '--operator-key-fingerprint', fixture.operatorFingerprint,
    '--browser-versions', fixture.browserPath,
    '--output', output
  ];
  const result = spawnSync(process.execPath, [GENERATOR, ...args], { encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(JSON.parse(result.stdout).qualified, false);
  assert.equal(JSON.parse(fs.readFileSync(output)).qualified, false);
  const unknown = spawnSync(process.execPath, [GENERATOR, ...args, '--unexpected', 'x'], { encoding: 'utf8' });
  assert.notEqual(unknown.status, 0);
  assert.match(unknown.stderr, /Usage|refused/u);
  const duplicate = spawnSync(process.execPath, [GENERATOR, ...args.slice(0, -2), '--operator', fixture.operator, '--output', join(fixture.directory, 'duplicate.json')], { encoding: 'utf8' });
  assert.notEqual(duplicate.status, 0);
  assert.match(duplicate.stderr, /Usage|refused/u);
  assert.throws(() => parseArguments(args.slice(0, -2)), /Usage/u);
});
