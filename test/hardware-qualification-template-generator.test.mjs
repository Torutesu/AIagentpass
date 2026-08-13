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
    ['AgentPass-0.18.0.spdx.json', canonical(sbom)],
    ['database-migration-manifest.json', migrationBytes],
    ['package-lock.json', lockBytes],
    ['release-attestation.json', canonical(attestation)]
  ]);
  for (const [name, bytes] of files) fs.writeFileSync(join(releaseDirectory, name), bytes, { mode: 0o644 });
  const notaryID = '12345678-1234-1234-1234-123456789abc';
  const notaryBytes = canonical({ status: 'Accepted', id: notaryID });
  const staplerBytes = Buffer.from('The validate action worked!\n');
  fs.writeFileSync(join(releaseDirectory, 'notarytool-result.json'), notaryBytes, { mode: 0o644 });
  fs.writeFileSync(join(releaseDirectory, 'stapler-result.txt'), staplerBytes, { mode: 0o644 });
  const artifacts = [...files.entries()].map(([name, bytes]) => ({
    name,
    role: name.endsWith('.spdx.json') ? 'sbom' : name === productName ? 'product' : 'auxiliary',
    media_type: name.endsWith('.spdx.json') ? 'application/spdx+json' : name.endsWith('.pkg') ? 'application/vnd.apple.installer+xml' : 'application/json',
    bytes: bytes.length,
    sha256: digest(bytes)
  })).sort((left, right) => left.name.localeCompare(right.name));
  const notarizationEvidence = [
    { kind: 'notarytool_result', name: 'notarytool-result.json', bytes: notaryBytes.length, sha256: digest(notaryBytes) },
    { kind: 'stapler_result', name: 'stapler-result.txt', bytes: staplerBytes.length, sha256: digest(staplerBytes) }
  ];
  const checksumEntries = [...artifacts, ...notarizationEvidence].sort((left, right) => left.name.localeCompare(right.name));
  const checksumsBytes = Buffer.from(`${checksumEntries.map((item) => `${item.sha256}  ${item.name}`).join('\n')}\n`, 'utf8');
  fs.writeFileSync(join(releaseDirectory, 'SHA256SUMS'), checksumsBytes, { mode: 0o644 });
  const manifest = {
    schema_version: 2,
    product: 'AgentPass',
    version: '0.18.0',
    source: { commit: sourceCommit, tree: sourceTree, tag: 'v0.18.0' },
    generated_at: '2026-08-13T00:00:00.000Z',
    artifacts,
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

test('creates a canonical, unqualified v2 template bound to the signed release', () => {
  const fixture = makeFixture();
  const output = join(fixture.directory, 'hardware-qualification-template.json');
  const template = generateHardwareQualificationTemplate(generateArgs(fixture, output));
  assert.deepEqual(Object.keys(template).sort(), [...REPORT_KEYS].sort());
  assert.equal(template.schema_version, 2);
  assert.equal(template.source_commit, fixture.manifest.source.commit);
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
