#!/usr/bin/env node
import { createHash, createPublicKey, verify } from 'node:crypto';
import fs from 'node:fs';
import { basename, dirname, resolve } from 'node:path';
import { assertReleaseCandidateIdMatchesProduct, parseReleaseCandidateId, RELEASE_MANIFEST_SCHEMA_VERSION } from '../../lib/release-candidate-identity.mjs';
import { parseCanonicalExternalQualificationControllerIdentity, validateExternalQualificationControllerIdentity } from './n3e/controller-identity-contract.mjs';

const [manifestPath, signaturePath, publicKeyPath, expectedFingerprint] = process.argv.slice(2);
if (!manifestPath || !signaturePath || !publicKeyPath || !expectedFingerprint || process.argv.slice(2).length !== 4) throw new Error('Usage: verify-release.mjs RELEASE-MANIFEST.json SIGNATURE PUBLIC-KEY EXPECTED-FINGERPRINT');
if (!/^SHA256:[A-Za-z0-9_-]{43}$/.test(expectedFingerprint)) throw new Error('invalid expected release key fingerprint');
if (!Number.isInteger(fs.constants.O_NOFOLLOW)) throw new Error('O_NOFOLLOW is unavailable on this platform');

const statIdentity = (stat) => [stat.dev, stat.ino, stat.mode, stat.nlink, stat.size, stat.mtimeNs, stat.ctimeNs].join(':');
const snapshotFile = (input, { maximum, capture = false, expectedBytes = null, expectedSHA256 = null } = {}) => {
  const path = resolve(input);
  const descriptor = fs.openSync(path, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  try {
    const before = fs.fstatSync(descriptor, { bigint: true });
    if (!before.isFile() || before.nlink !== 1n || before.size <= 0n || before.size > BigInt(maximum) || before.size > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error(`unsafe release input: ${input}`);
    const size = Number(before.size);
    if (expectedBytes !== null && size !== expectedBytes) throw new Error(`${basename(path)} size mismatch`);
    const hash = createHash('sha256');
    const chunks = capture ? [] : null;
    const buffer = Buffer.allocUnsafe(Math.min(1024 * 1024, size));
    let offset = 0;
    while (offset < size) {
      const wanted = Math.min(buffer.length, size - offset);
      const count = fs.readSync(descriptor, buffer, 0, wanted, offset);
      if (count === 0) throw new Error(`release input changed while reading: ${input}`);
      const chunk = buffer.subarray(0, count);
      hash.update(chunk);
      if (chunks) chunks.push(Buffer.from(chunk));
      offset += count;
    }
    const after = fs.fstatSync(descriptor, { bigint: true });
    if (statIdentity(before) !== statIdentity(after)) throw new Error(`release input changed while reading: ${input}`);
    const digest = hash.digest('hex');
    if (expectedSHA256 !== null && digest !== expectedSHA256) throw new Error(`${basename(path)} digest mismatch`);
    return { path, name: basename(path), bytes: size, sha256: digest, content: chunks ? Buffer.concat(chunks, size) : undefined };
  } finally {
    fs.closeSync(descriptor);
  }
};

const exactKeys = (value, keys, label) => {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) throw new Error(`${label} must be an object`);
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) throw new Error(`${label} has missing or unknown fields`);
};
const safeName = (name) => typeof name === 'string' && /^[0-9A-Za-z][0-9A-Za-z._-]*$/.test(name) && name === basename(name);
const lexicalCompare = (left, right) => left < right ? -1 : left > right ? 1 : 0;
const validDigest = (value) => typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
const canonicalDate = (value) => typeof value === 'string' && Number.isFinite(Date.parse(value)) && new Date(value).toISOString() === value;

const manifestSnapshot = snapshotFile(manifestPath, { maximum: 16 * 1024 * 1024, capture: true });
const manifestBytes = manifestSnapshot.content;
let manifest;
try { manifest = JSON.parse(manifestBytes.toString('utf8')); } catch { throw new Error('release manifest is not valid UTF-8 JSON'); }
if (!manifestBytes.equals(Buffer.from(`${JSON.stringify(manifest, null, 2)}\n`, 'utf8'))) throw new Error('release manifest is not canonical JSON');

const publicKeyBytes = snapshotFile(publicKeyPath, { maximum: 16 * 1024, capture: true }).content;
const publicKey = createPublicKey(publicKeyBytes);
if (publicKey.asymmetricKeyType !== 'ed25519') throw new Error('release public key must be Ed25519');
const fingerprint = `SHA256:${createHash('sha256').update(publicKey.export({ type: 'spki', format: 'der' })).digest('base64url')}`;
if (fingerprint !== expectedFingerprint) throw new Error('release public key fingerprint mismatch');

const signatureBytes = snapshotFile(signaturePath, { maximum: 1024, capture: true }).content;
const encodedSignature = signatureBytes.toString('utf8');
if (!/^(?:[A-Za-z0-9+/]{4}){21}[A-Za-z0-9+/]{2}==\n$/.test(encodedSignature)) throw new Error('invalid release manifest signature encoding');
const signature = Buffer.from(encodedSignature.trim(), 'base64');
if (signature.length !== 64 || !verify(null, manifestBytes, publicKey, signature)) throw new Error('release manifest signature is invalid');

exactKeys(manifest, ['schema_version', 'product', 'version', 'source', 'generated_at', 'candidate_id', 'artifacts', 'external_qualification_controller', 'evidence'], 'release manifest');
if (manifest.schema_version !== RELEASE_MANIFEST_SCHEMA_VERSION || manifest.product !== 'AgentPass') throw new Error('unsupported release manifest identity');
if (typeof manifest.version !== 'string' || !/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(manifest.version) || !canonicalDate(manifest.generated_at)) throw new Error('invalid release metadata');
parseReleaseCandidateId(manifest.candidate_id);
exactKeys(manifest.source, ['commit', 'tree', 'tag'], 'source');
if (!/^[0-9a-f]{40}$/.test(manifest.source.commit) || !/^[0-9a-f]{40}$/.test(manifest.source.tree)) throw new Error('invalid source identity');
if (manifest.source.tag !== null && manifest.source.tag !== `v${manifest.version}`) throw new Error('source tag and release version disagree');
if (!Array.isArray(manifest.artifacts) || manifest.artifacts.length === 0) throw new Error('release manifest has no artifacts');
exactKeys(manifest.evidence, ['checksums', 'sbom', 'notarization'], 'evidence');

const manifestDirectory = dirname(manifestSnapshot.path);
const names = new Set();
const artifactContent = new Map();
const roles = new Set(['product', 'sbom', 'release_notice', 'trust_root', 'auxiliary', 'external_qualification_controller']);
const mediaTypes = new Set(['application/spdx+json', 'application/zip', 'application/vnd.apple.installer+xml', 'application/gzip', 'application/x-pem-file', 'application/json', 'text/plain', 'application/octet-stream']);
let previousName = '';
for (const artifact of manifest.artifacts) {
  exactKeys(artifact, ['name', 'role', 'media_type', 'bytes', 'sha256'], 'artifact');
  if (!safeName(artifact.name) || names.has(artifact.name) || lexicalCompare(artifact.name, previousName) <= 0) throw new Error('unsafe, duplicate, or unsorted artifact name');
  if (!roles.has(artifact.role) || !mediaTypes.has(artifact.media_type) || !Number.isSafeInteger(artifact.bytes) || artifact.bytes <= 0 || !validDigest(artifact.sha256)) throw new Error(`invalid metadata for ${artifact.name}`);
  if ((artifact.role === 'sbom') !== (artifact.media_type === 'application/spdx+json')) throw new Error(`SBOM role/media type mismatch for ${artifact.name}`);
  names.add(artifact.name);
  previousName = artifact.name;
  const capture = artifact.role === 'sbom';
  const snapshot = snapshotFile(resolve(manifestDirectory, artifact.name), { maximum: artifact.role === 'sbom' ? 32 * 1024 * 1024 : 16 * 1024 * 1024 * 1024, capture, expectedBytes: artifact.bytes, expectedSHA256: artifact.sha256 });
  if (capture) artifactContent.set(artifact.name, snapshot.content);
}
const productArtifacts = manifest.artifacts.filter((artifact) => artifact.role === 'product');
if (productArtifacts.length !== 1 || !productArtifacts[0].name.endsWith('.pkg')) throw new Error('release manifest requires exactly one product PKG artifact');
const productArtifact = productArtifacts[0];
assertReleaseCandidateIdMatchesProduct(manifest.candidate_id, productArtifact.sha256);
const trustRootArtifacts = manifest.artifacts.filter((artifact) => artifact.role === 'trust_root');
if (trustRootArtifacts.length > 1) throw new Error('release manifest contains multiple trust root artifacts');
if (trustRootArtifacts.length === 1) {
  const trustRoot = trustRootArtifacts[0];
  const publicKeyDigest = createHash('sha256').update(publicKeyBytes).digest('hex');
  if (trustRoot.bytes !== publicKeyBytes.length || trustRoot.sha256 !== publicKeyDigest) throw new Error('release trust root artifact does not match verification public key');
}
const controllerArtifacts = manifest.artifacts.filter((artifact) => artifact.role === 'external_qualification_controller');
if (controllerArtifacts.length !== 1 || controllerArtifacts[0].media_type !== 'application/octet-stream' || !/^AgentPassQualificationController-(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-(?:0|[1-9A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9A-Za-z-][0-9A-Za-z-]*))*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?-macos-universal\.tar$/u.test(controllerArtifacts[0].name)) throw new Error('release manifest requires one exact external controller archive');
if (controllerArtifacts[0].name !== `AgentPassQualificationController-${manifest.version}-macos-universal.tar`) throw new Error('controller archive version does not match the release');

const externalController = manifest.external_qualification_controller;
exactKeys(externalController, ['identity_document', 'identity', 'notarization'], 'external qualification controller');
exactKeys(externalController.identity_document, ['name', 'bytes', 'sha256'], 'controller identity document');
const identityDocument = externalController.identity_document;
if (!safeName(identityDocument.name) || names.has(identityDocument.name) || !Number.isSafeInteger(identityDocument.bytes) || identityDocument.bytes <= 0 || identityDocument.bytes > 1024 * 1024 || !validDigest(identityDocument.sha256)) throw new Error('invalid controller identity document binding');
names.add(identityDocument.name);
const identitySnapshot = snapshotFile(resolve(manifestDirectory, identityDocument.name), { maximum: 1024 * 1024, capture: true, expectedBytes: identityDocument.bytes, expectedSHA256: identityDocument.sha256 });
let parsedControllerIdentity;
try { parsedControllerIdentity = parseCanonicalExternalQualificationControllerIdentity(identitySnapshot.content); }
catch (error) { throw new Error(`controller identity document is invalid: ${error.message}`); }
let embeddedControllerIdentity;
try { embeddedControllerIdentity = validateExternalQualificationControllerIdentity(externalController.identity); }
catch (error) { throw new Error(`embedded controller identity is invalid: ${error.message}`); }
if (JSON.stringify(parsedControllerIdentity) !== JSON.stringify(embeddedControllerIdentity)) throw new Error('embedded controller identity differs from its bound document');
const controllerArtifact = controllerArtifacts[0];
if (parsedControllerIdentity.archive_name !== controllerArtifact.name || parsedControllerIdentity.archive_sha256 !== controllerArtifact.sha256 || parsedControllerIdentity.archive_bytes !== controllerArtifact.bytes) throw new Error('controller identity does not bind the exact external archive');

const controllerNotarization = externalController.notarization;
exactKeys(controllerNotarization, ['status', 'submission_ids', 'evidence'], 'controller notarization');
if (controllerNotarization.status !== 'accepted_stapled' || !Array.isArray(controllerNotarization.submission_ids) || !Array.isArray(controllerNotarization.evidence)) throw new Error('external controller must carry accepted stapled notarization evidence');
const controllerSubmissionIDs = new Set();
let previousControllerSubmission = '';
for (const id of controllerNotarization.submission_ids) {
  if (typeof id !== 'string' || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(id) || controllerSubmissionIDs.has(id) || lexicalCompare(id, previousControllerSubmission) <= 0) throw new Error('invalid, duplicate, or unsorted controller notary submission ID');
  controllerSubmissionIDs.add(id); previousControllerSubmission = id;
}
const controllerNotaryContent = new Map();
const controllerEvidenceKinds = new Set();
let previousControllerEvidenceName = '';
for (const evidence of controllerNotarization.evidence) {
  exactKeys(evidence, ['kind', 'name', 'bytes', 'sha256'], 'controller notarization evidence item');
  if (!['notarytool_result', 'stapler_result'].includes(evidence.kind) || controllerEvidenceKinds.has(evidence.kind)) throw new Error('invalid or duplicate controller notarization evidence kind');
  if (!safeName(evidence.name) || names.has(evidence.name) || lexicalCompare(evidence.name, previousControllerEvidenceName) <= 0 || !Number.isSafeInteger(evidence.bytes) || evidence.bytes <= 0 || !validDigest(evidence.sha256)) throw new Error('invalid, duplicate, or unsorted controller notarization evidence');
  controllerEvidenceKinds.add(evidence.kind); names.add(evidence.name); previousControllerEvidenceName = evidence.name;
  const snapshot = snapshotFile(resolve(manifestDirectory, evidence.name), { maximum: 4 * 1024 * 1024, capture: true, expectedBytes: evidence.bytes, expectedSHA256: evidence.sha256 });
  controllerNotaryContent.set(evidence.kind, snapshot.content);
}
if (controllerSubmissionIDs.size === 0 || controllerEvidenceKinds.size !== 2 || !controllerEvidenceKinds.has('notarytool_result') || !controllerEvidenceKinds.has('stapler_result')) throw new Error('external controller lacks complete notarization evidence');
let controllerNotaryResult;
try { controllerNotaryResult = JSON.parse(controllerNotaryContent.get('notarytool_result').toString('utf8')); } catch { throw new Error('controller notarytool evidence is not valid JSON'); }
if (typeof controllerNotaryResult !== 'object' || controllerNotaryResult === null || controllerNotaryResult.status !== 'Accepted' || typeof controllerNotaryResult.id !== 'string' || !controllerSubmissionIDs.has(controllerNotaryResult.id.toLowerCase())) throw new Error('controller notarytool evidence does not match an accepted submission');
if (!/The validate action worked!/i.test(controllerNotaryContent.get('stapler_result').toString('utf8'))) throw new Error('controller stapler evidence does not record successful validation');

const notarization = manifest.evidence.notarization;
exactKeys(notarization, ['status', 'submission_ids', 'evidence'], 'notarization');
if (!['not_verified', 'accepted_stapled'].includes(notarization.status) || !Array.isArray(notarization.submission_ids) || !Array.isArray(notarization.evidence)) throw new Error('invalid notarization evidence');
const submissionIDs = new Set();
let previousSubmission = '';
for (const id of notarization.submission_ids) {
  if (typeof id !== 'string' || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(id) || submissionIDs.has(id) || lexicalCompare(id, previousSubmission) <= 0) throw new Error('invalid, duplicate, or unsorted notarization submission ID');
  submissionIDs.add(id); previousSubmission = id;
}
const notaryContent = new Map();
const evidenceKinds = new Set();
let previousEvidenceName = '';
for (const evidence of notarization.evidence) {
  exactKeys(evidence, ['kind', 'name', 'bytes', 'sha256'], 'notarization evidence item');
  if (!['notarytool_result', 'stapler_result'].includes(evidence.kind) || evidenceKinds.has(evidence.kind)) throw new Error('invalid or duplicate notarization evidence kind');
  if (!safeName(evidence.name) || names.has(evidence.name) || lexicalCompare(evidence.name, previousEvidenceName) <= 0 || !Number.isSafeInteger(evidence.bytes) || evidence.bytes <= 0 || !validDigest(evidence.sha256)) throw new Error('invalid, duplicate, or unsorted notarization evidence');
  evidenceKinds.add(evidence.kind); names.add(evidence.name); previousEvidenceName = evidence.name;
  const snapshot = snapshotFile(resolve(manifestDirectory, evidence.name), { maximum: 4 * 1024 * 1024, capture: true, expectedBytes: evidence.bytes, expectedSHA256: evidence.sha256 });
  notaryContent.set(evidence.kind, snapshot.content);
}
if (notarization.status === 'not_verified' && (submissionIDs.size || notarization.evidence.length)) throw new Error('not_verified release contains notarization claims');
if (notarization.status === 'accepted_stapled') {
  if (submissionIDs.size === 0 || evidenceKinds.size !== 2 || !evidenceKinds.has('notarytool_result') || !evidenceKinds.has('stapler_result')) throw new Error('accepted_stapled release lacks complete evidence');
  let result;
  try { result = JSON.parse(notaryContent.get('notarytool_result').toString('utf8')); } catch { throw new Error('notarytool evidence is not valid JSON'); }
  if (typeof result !== 'object' || result === null || result.status !== 'Accepted' || typeof result.id !== 'string' || !submissionIDs.has(result.id.toLowerCase())) throw new Error('notarytool evidence does not match an accepted submission');
  if (!/The validate action worked!/i.test(notaryContent.get('stapler_result').toString('utf8'))) throw new Error('stapler evidence does not record successful validation');
}

const checksums = manifest.evidence.checksums;
exactKeys(checksums, ['name', 'bytes', 'sha256', 'entry_count'], 'checksums evidence');
if (!safeName(checksums.name) || names.has(checksums.name) || !Number.isSafeInteger(checksums.bytes) || checksums.bytes <= 0 || !validDigest(checksums.sha256) || !Number.isSafeInteger(checksums.entry_count) || checksums.entry_count !== manifest.artifacts.length + notarization.evidence.length + 1 + controllerNotarization.evidence.length) throw new Error('invalid checksums evidence');
const checksumEntries = [...manifest.artifacts, ...notarization.evidence, identityDocument, ...controllerNotarization.evidence].sort((a, b) => lexicalCompare(a.name, b.name));
const expectedChecksums = Buffer.from(`${checksumEntries.map((item) => `${item.sha256}  ${item.name}`).join('\n')}\n`, 'utf8');
const checksumsSnapshot = snapshotFile(resolve(manifestDirectory, checksums.name), { maximum: 16 * 1024 * 1024, capture: true, expectedBytes: checksums.bytes, expectedSHA256: checksums.sha256 });
if (!checksumsSnapshot.content.equals(expectedChecksums)) throw new Error('SHA256SUMS content mismatch');

const sbomBinding = manifest.evidence.sbom;
exactKeys(sbomBinding, ['artifact_name', 'sha256', 'spdx_version', 'document_namespace', 'document_spdx_id', 'document_describes', 'source_commit', 'source_tree'], 'SBOM evidence');
const sbomArtifacts = manifest.artifacts.filter((artifact) => artifact.role === 'sbom');
if (sbomArtifacts.length !== 1 || sbomBinding.artifact_name !== sbomArtifacts[0].name || sbomBinding.sha256 !== sbomArtifacts[0].sha256 || sbomBinding.spdx_version !== 'SPDX-2.3' || sbomBinding.document_spdx_id !== 'SPDXRef-DOCUMENT' || sbomBinding.source_commit !== manifest.source.commit || sbomBinding.source_tree !== manifest.source.tree || !Array.isArray(sbomBinding.document_describes) || sbomBinding.document_describes.length !== 1 || sbomBinding.document_describes[0] !== 'SPDXRef-AgentPass') throw new Error('invalid SBOM binding');
let sbom;
try { sbom = JSON.parse(artifactContent.get(sbomBinding.artifact_name).toString('utf8')); } catch { throw new Error('bound SBOM is not valid JSON'); }
if (sbom.spdxVersion !== sbomBinding.spdx_version || sbom.SPDXID !== sbomBinding.document_spdx_id || sbom.documentNamespace !== sbomBinding.document_namespace || JSON.stringify(sbom.documentDescribes) !== JSON.stringify(sbomBinding.document_describes)) throw new Error('SBOM document identity mismatch');
const describedPackage = Array.isArray(sbom.packages) ? sbom.packages.find((item) => item?.SPDXID === 'SPDXRef-AgentPass') : undefined;
if (!describedPackage || describedPackage.versionInfo !== manifest.version || typeof describedPackage.sourceInfo !== 'string' || !describedPackage.sourceInfo.includes(manifest.source.commit) || !describedPackage.sourceInfo.includes(manifest.source.tree)) throw new Error('SBOM source package mismatch');
let creationMetadata;
try { creationMetadata = JSON.parse(sbom.creationInfo?.comment); } catch { throw new Error('SBOM creation metadata is invalid'); }
if (creationMetadata.source_commit !== manifest.source.commit || creationMetadata.source_tree !== manifest.source.tree || !Number.isSafeInteger(creationMetadata.swift_input_count) || creationMetadata.swift_input_count < 1 || typeof creationMetadata.swift !== 'string' || typeof creationMetadata.macos_sdk !== 'string') throw new Error('SBOM source/build metadata mismatch');
if (!Array.isArray(sbom.files) || !sbom.files.some((file) => file?.fileName === 'native/macos/Package.swift') || !sbom.files.some((file) => typeof file?.fileName === 'string' && file.fileName.endsWith('.swift'))) throw new Error('SBOM is missing Swift inputs');
for (const toolID of ['SPDXRef-BuildTool-Node', 'SPDXRef-BuildTool-Swift', 'SPDXRef-BuildTool-macOSSDK']) if (!sbom.packages.some((item) => item?.SPDXID === toolID && typeof item.versionInfo === 'string' && item.versionInfo.length > 0)) throw new Error(`SBOM is missing compiler metadata: ${toolID}`);

console.log(JSON.stringify({
  ok: true,
  artifacts: manifest.artifacts.length,
  candidate_id: manifest.candidate_id,
  product_pkg_sha256: productArtifact.sha256,
  checksums_bound: true,
  sbom_bound: true,
  notarization: notarization.status,
  notarization_evidence_bound: notarization.status === 'accepted_stapled',
  controller_archive: controllerArtifact.name,
  controller_archive_sha256: controllerArtifact.sha256,
  controller_identity_sha256: identityDocument.sha256,
  controller_notarization: controllerNotarization.status,
  controller_notarization_evidence_bound: true,
  apple_ticket_verified: false,
  signer_fingerprint: fingerprint,
  source_commit: manifest.source.commit,
  source_tree: manifest.source.tree
}));
