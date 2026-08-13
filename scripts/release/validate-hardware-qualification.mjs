#!/usr/bin/env node
import { createHash, createPublicKey, verify } from 'node:crypto';
import fs from 'node:fs';
import { basename, dirname, resolve } from 'node:path';

const args = process.argv.slice(2);
const [input, artifactInput, manifestInput, manifestSignatureInput, manifestPublicKeyInput,
  manifestFingerprint, operatorSignatureInput, operatorPublicKeyInput, operatorFingerprint,
  evidenceDirectoryInput] = args;
const V2_ARGUMENTS = 10;
if (!input || ![1, V2_ARGUMENTS].includes(args.length)) {
  throw new Error('Usage: validate-hardware-qualification.mjs RESULT.json [ARTIFACT RELEASE-MANIFEST RELEASE-SIGNATURE RELEASE-PUBLIC-KEY RELEASE-FINGERPRINT OPERATOR-SIGNATURE OPERATOR-PUBLIC-KEY OPERATOR-FINGERPRINT EVIDENCE-DIR]');
}
if (!Number.isInteger(fs.constants.O_NOFOLLOW)) throw new Error('O_NOFOLLOW is unavailable on this platform');

const statIdentity = (stat) => [stat.dev, stat.ino, stat.mode, stat.nlink, stat.size, stat.mtimeNs, stat.ctimeNs].join(':');
const validDigest = (value) => typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
const validCloudDigest = (value) => typeof value === 'string' && /^sha256:[0-9a-f]{64}$/.test(value);
const safeName = (value) => typeof value === 'string' && /^[0-9A-Za-z][0-9A-Za-z._-]*$/.test(value) && value === basename(value);
const lexicalCompare = (left, right) => left < right ? -1 : left > right ? 1 : 0;
const utcTimestamp = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/;
const canonicalDate = (value) => typeof value === 'string' && Number.isFinite(Date.parse(value)) && new Date(value).toISOString() === value;
const exactKeys = (value, keys, label) => {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) throw new Error(`${label} must be an object`);
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) throw new Error(`${label} has missing or unknown fields`);
};

const snapshotFile = (pathInput, { maximum, capture = false, expectedBytes = null, expectedSHA256 = null, label = 'hardware qualification input' } = {}) => {
  const path = resolve(pathInput);
  const descriptor = fs.openSync(path, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  try {
    const before = fs.fstatSync(descriptor, { bigint: true });
    if (!before.isFile() || before.nlink !== 1n || before.size <= 0n || before.size > BigInt(maximum) || before.size > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error(`unsafe ${label}: ${pathInput}`);
    const size = Number(before.size);
    if (expectedBytes !== null && size !== expectedBytes) throw new Error(`${basename(path)} size mismatch`);
    const hash = createHash('sha256');
    const chunks = capture ? [] : null;
    const buffer = Buffer.allocUnsafe(Math.min(1024 * 1024, size));
    let offset = 0;
    while (offset < size) {
      const wanted = Math.min(buffer.length, size - offset);
      const count = fs.readSync(descriptor, buffer, 0, wanted, offset);
      if (count === 0) throw new Error(`${label} changed while reading: ${pathInput}`);
      const chunk = buffer.subarray(0, count);
      hash.update(chunk);
      if (chunks) chunks.push(Buffer.from(chunk));
      offset += count;
    }
    const after = fs.fstatSync(descriptor, { bigint: true });
    if (statIdentity(before) !== statIdentity(after)) throw new Error(`${label} changed while reading: ${pathInput}`);
    const sha256 = hash.digest('hex');
    if (expectedSHA256 !== null && sha256 !== expectedSHA256) throw new Error(`${basename(path)} digest mismatch`);
    return { path, name: basename(path), bytes: size, sha256, content: chunks ? Buffer.concat(chunks, size) : undefined };
  } finally {
    fs.closeSync(descriptor);
  }
};

const readJSON = (snapshot, label) => {
  try { return JSON.parse(snapshot.content.toString('utf8')); } catch { throw new Error(`${label} is not valid UTF-8 JSON`); }
};
const canonicalJSON = (value) => Buffer.from(`${JSON.stringify(value, null, 2)}\n`, 'utf8');
const fingerprintFor = (publicKey) => `SHA256:${createHash('sha256').update(publicKey.export({ type: 'spki', format: 'der' })).digest('base64url')}`;
const verifyDetached = (payload, signaturePath, publicKeyPath, expected, label) => {
  if (!/^SHA256:[A-Za-z0-9_-]{43}$/.test(expected)) throw new Error(`invalid expected ${label} key fingerprint`);
  const publicKeyBytes = snapshotFile(publicKeyPath, { maximum: 16 * 1024, capture: true, label: `${label} public key` }).content;
  let publicKey;
  try { publicKey = createPublicKey(publicKeyBytes); } catch { throw new Error(`${label} public key is invalid`); }
  if (publicKey.asymmetricKeyType !== 'ed25519') throw new Error(`${label} public key must be Ed25519`);
  const actualFingerprint = fingerprintFor(publicKey);
  if (actualFingerprint !== expected) throw new Error(`${label} public key fingerprint mismatch`);
  const encoded = snapshotFile(signaturePath, { maximum: 1024, capture: true, label: `${label} signature` }).content.toString('utf8');
  if (!/^(?:[A-Za-z0-9+/]{4}){21}[A-Za-z0-9+/]{2}==\n$/.test(encoded)) throw new Error(`invalid ${label} signature encoding`);
  const signature = Buffer.from(encoded.trim(), 'base64');
  if (signature.length !== 64 || !verify(null, payload, publicKey, signature)) throw new Error(`${label} signature is invalid`);
  return { publicKey, fingerprint: actualFingerprint };
};

const validateManifest = (manifestSnapshot, manifestSignaturePath, manifestPublicKeyPath, expectedFingerprint) => {
  const manifestBytes = manifestSnapshot.content;
  if (!manifestBytes.equals(canonicalJSON(readJSON(manifestSnapshot, 'release manifest')))) throw new Error('release manifest is not canonical JSON');
  const signed = verifyDetached(manifestBytes, manifestSignaturePath, manifestPublicKeyPath, expectedFingerprint, 'release manifest');
  const manifest = readJSON(manifestSnapshot, 'release manifest');
  exactKeys(manifest, ['schema_version', 'product', 'version', 'source', 'generated_at', 'artifacts', 'evidence'], 'release manifest');
  if (manifest.schema_version !== 2 || manifest.product !== 'AgentPass') throw new Error('unsupported release manifest identity');
  if (typeof manifest.version !== 'string' || !/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(manifest.version) || !canonicalDate(manifest.generated_at)) throw new Error('invalid release metadata');
  exactKeys(manifest.source, ['commit', 'tree', 'tag'], 'release manifest source');
  if (!/^[0-9a-f]{40}$/.test(manifest.source.commit) || !/^[0-9a-f]{40}$/.test(manifest.source.tree)) throw new Error('release manifest source identity is invalid');
  if (manifest.source.tag !== null && (typeof manifest.source.tag !== 'string' || !/^v\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(manifest.source.tag))) throw new Error('release manifest source tag is invalid');
  if (!Array.isArray(manifest.artifacts) || manifest.artifacts.length === 0) throw new Error('release manifest has no artifacts');
  const manifestDirectory = dirname(manifestSnapshot.path);
  const artifacts = [];
  const names = new Set();
  const roles = new Set(['product', 'sbom', 'release_notice', 'trust_root', 'auxiliary']);
  const mediaTypes = new Set(['application/spdx+json', 'application/zip', 'application/vnd.apple.installer+xml', 'application/gzip', 'application/x-pem-file', 'application/json', 'text/plain', 'application/octet-stream']);
  let previousName = '';
  for (const artifact of manifest.artifacts) {
    exactKeys(artifact, ['name', 'role', 'media_type', 'bytes', 'sha256'], 'release artifact');
    if (!safeName(artifact.name) || names.has(artifact.name) || lexicalCompare(artifact.name, previousName) <= 0 || !roles.has(artifact.role) || !mediaTypes.has(artifact.media_type) || !Number.isSafeInteger(artifact.bytes) || artifact.bytes <= 0 || !validDigest(artifact.sha256) || ((artifact.role === 'sbom') !== (artifact.media_type === 'application/spdx+json'))) throw new Error('release manifest artifact metadata is invalid');
    snapshotFile(resolve(manifestDirectory, artifact.name), { maximum: 16 * 1024 * 1024 * 1024, expectedBytes: artifact.bytes, expectedSHA256: artifact.sha256, label: 'release artifact' });
    names.add(artifact.name); previousName = artifact.name; artifacts.push(artifact);
  }
  const products = artifacts.filter((item) => item.role === 'product');
  if (products.length !== 1 || products[0].name !== `AgentPass-${manifest.version}-macos-universal.pkg` || products[0].media_type !== 'application/vnd.apple.installer+xml') throw new Error('release manifest must contain exactly one canonical macOS product artifact');
  exactKeys(manifest.evidence, ['checksums', 'sbom', 'notarization'], 'release manifest evidence');
  const notarization = manifest.evidence.notarization;
  exactKeys(notarization, ['status', 'submission_ids', 'evidence'], 'release notarization');
  if (!['not_verified', 'accepted_stapled'].includes(notarization.status) || !Array.isArray(notarization.submission_ids) || !Array.isArray(notarization.evidence)) throw new Error('release notarization metadata is invalid');
  const submissionIDs = new Set();
  let previousSubmission = '';
  for (const id of notarization.submission_ids) {
    if (typeof id !== 'string' || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(id) || submissionIDs.has(id) || lexicalCompare(id, previousSubmission) <= 0) throw new Error('release notarization submission ID is invalid');
    submissionIDs.add(id); previousSubmission = id;
  }
  const evidence = [];
  const evidenceKinds = new Set();
  const evidenceContent = new Map();
  let previousEvidenceName = '';
  for (const item of notarization.evidence) {
    exactKeys(item, ['kind', 'name', 'bytes', 'sha256'], 'release notarization evidence');
    if (!['notarytool_result', 'stapler_result'].includes(item.kind) || evidenceKinds.has(item.kind) || !safeName(item.name) || names.has(item.name) || lexicalCompare(item.name, previousEvidenceName) <= 0 || !Number.isSafeInteger(item.bytes) || item.bytes <= 0 || !validDigest(item.sha256)) throw new Error('release notarization evidence metadata is invalid');
    const snapshot = snapshotFile(resolve(manifestDirectory, item.name), { maximum: 4 * 1024 * 1024, capture: true, expectedBytes: item.bytes, expectedSHA256: item.sha256, label: 'release notarization evidence' });
    names.add(item.name); evidenceKinds.add(item.kind); evidenceContent.set(item.kind, snapshot.content); previousEvidenceName = item.name; evidence.push(item);
  }
  if (notarization.status === 'not_verified' && (submissionIDs.size !== 0 || evidence.length !== 0)) throw new Error('not_verified release contains notarization claims');
  if (notarization.status === 'accepted_stapled') {
    if (submissionIDs.size === 0 || evidenceKinds.size !== 2 || !evidenceKinds.has('notarytool_result') || !evidenceKinds.has('stapler_result')) throw new Error('accepted_stapled release lacks complete notarization evidence');
    let result;
    try { result = JSON.parse(evidenceContent.get('notarytool_result').toString('utf8')); } catch { throw new Error('notarytool evidence is not valid JSON'); }
    if (typeof result !== 'object' || result === null || result.status !== 'Accepted' || typeof result.id !== 'string' || !submissionIDs.has(result.id.toLowerCase())) throw new Error('notarytool evidence does not match an accepted submission');
    if (!/The validate action worked!/i.test(evidenceContent.get('stapler_result').toString('utf8'))) throw new Error('stapler evidence does not record successful validation');
  }
  const checksums = manifest.evidence.checksums;
  exactKeys(checksums, ['name', 'bytes', 'sha256', 'entry_count'], 'release checksums evidence');
  if (!safeName(checksums.name) || names.has(checksums.name) || !Number.isSafeInteger(checksums.bytes) || checksums.bytes <= 0 || !validDigest(checksums.sha256) || checksums.entry_count !== artifacts.length + evidence.length) throw new Error('release checksums evidence metadata is invalid');
  const checksumEntries = [...artifacts, ...evidence].sort((left, right) => lexicalCompare(left.name, right.name));
  const expectedChecksums = Buffer.from(`${checksumEntries.map((item) => `${item.sha256}  ${item.name}`).join('\n')}\n`, 'utf8');
  const checksumSnapshot = snapshotFile(resolve(manifestDirectory, checksums.name), { maximum: 16 * 1024 * 1024, capture: true, expectedBytes: checksums.bytes, expectedSHA256: checksums.sha256, label: 'release checksums' });
  if (!checksumSnapshot.content.equals(expectedChecksums)) throw new Error('release checksums content mismatch');
  const sbomBinding = manifest.evidence.sbom;
  exactKeys(sbomBinding, ['artifact_name', 'sha256', 'spdx_version', 'document_namespace', 'document_spdx_id', 'document_describes', 'source_commit', 'source_tree'], 'release SBOM evidence');
  const sbomArtifact = artifacts.filter((item) => item.role === 'sbom');
  if (sbomArtifact.length !== 1 || sbomBinding.artifact_name !== sbomArtifact[0].name || sbomBinding.sha256 !== sbomArtifact[0].sha256 || sbomBinding.spdx_version !== 'SPDX-2.3' || sbomBinding.document_spdx_id !== 'SPDXRef-DOCUMENT' || sbomBinding.source_commit !== manifest.source.commit || sbomBinding.source_tree !== manifest.source.tree || !Array.isArray(sbomBinding.document_describes) || sbomBinding.document_describes.length !== 1 || sbomBinding.document_describes[0] !== 'SPDXRef-AgentPass') throw new Error('release SBOM binding is invalid');
  const sbom = readJSON(snapshotFile(resolve(manifestDirectory, sbomArtifact[0].name), { maximum: 32 * 1024 * 1024, capture: true, expectedBytes: sbomArtifact[0].bytes, expectedSHA256: sbomArtifact[0].sha256, label: 'release SBOM' }), 'release SBOM');
  if (sbom.spdxVersion !== 'SPDX-2.3' || sbom.SPDXID !== 'SPDXRef-DOCUMENT' || sbom.documentNamespace !== sbomBinding.document_namespace || JSON.stringify(sbom.documentDescribes) !== JSON.stringify(sbomBinding.document_describes)) throw new Error('release SBOM document identity mismatch');
  return { manifest, manifestBytes, manifestDirectory, artifacts, notarization, ...signed };
};

const requiredGates = [
  'gatekeeper-notarization', 'clean-install-launchd-xpc', 'secure-enclave-enrollment',
  'cloud-possession-verification', 'claude-code-unattended-sign', 'cursor-unattended-sign',
  'audit-upload-observation', 'policy-reduction-refresh-ack', 'offline-expiry',
  'revoke-emergency-stop', 'crash-restart-recovery', 'sleep-wake-network-clock',
  'upgrade-preserves-state', 'uninstall-reinstall-recovery', 'current-user-purge',
  'negative-identity-and-entitlement-cases'
];
const requiredTests = [
  'exact-pkg-install', 'launchd-xpc-approval', 'secure-enclave-key-creation',
  'secure-enclave-nonexportability', 'cloud-possession-proof',
  'claude-code-unattended-sign', 'cursor-unattended-sign', 'unrelated-process-denied',
  'audit-console-observation', 'policy-reduction-denied', 'offline-expiry-denied',
  'revoke-denied', 'emergency-stop-denied', 'service-crash-recovery', 'os-reboot-recovery',
  'sleep-wake-recovery', 'network-clock-failure', 'upgrade-preserves-state',
  'uninstall-reinstall-recovery', 'current-user-purge'
];
const requiredCodeIdentities = new Map([
  ['AgentPass.app', 'dev.agentpass'],
  ['AgentPass.app/Contents/Library/HelperTools/AgentPassNativeClient.app', 'dev.agentpass.native-client'],
  ['AgentPass.app/Contents/Library/HelperTools/AgentPassNativeService.app', 'dev.agentpass.native-service'],
  ['AgentPass.app/Contents/Library/HelperTools/agentpass-atomic-rename', 'dev.agentpass.atomic-rename'],
  ['AgentPass.app/Contents/MacOS/agentpass-native-manager', 'dev.agentpass.native-manager'],
  ['AgentPass.app/Contents/MacOS/agentpass-onboarding', 'dev.agentpass']
]);
const validateEvidenceList = (items, label, evidenceDirectory, seenEvidence) => {
  if (!Array.isArray(items) || items.length === 0 || items.length > 256) throw new Error(`invalid ${label} count`);
  const names = new Set();
  for (const item of items) {
    exactKeys(item, ['name', 'status', 'evidence', ...(item?.status === 'passed' ? [] : ['reason'])], label);
    if (typeof item.name !== 'string' || !/^[a-z0-9][a-z0-9-]{1,127}$/.test(item.name) || names.has(item.name)) throw new Error(`invalid or duplicate ${label} name`);
    if (!['passed', 'failed', 'skipped'].includes(item.status)) throw new Error(`invalid ${label} status`);
    names.add(item.name);
    if (!Array.isArray(item.evidence) || item.evidence.length > 16) throw new Error(`${label} evidence must be an array`);
    if (item.status === 'passed' && item.evidence.length === 0) throw new Error(`passed ${label} requires evidence`);
    if (item.status !== 'passed' && (typeof item.reason !== 'string' || item.reason.length < 3 || item.reason.length > 1024)) throw new Error(`non-passing ${label} requires a bounded reason`);
    const evidenceNames = new Set();
    for (const evidence of item.evidence) {
      exactKeys(evidence, ['name', 'bytes', 'sha256'], `${label} evidence item`);
      if (!safeName(evidence.name) || evidenceNames.has(evidence.name) || seenEvidence.has(evidence.name) || !Number.isSafeInteger(evidence.bytes) || evidence.bytes <= 0 || !validDigest(evidence.sha256)) throw new Error(`invalid, duplicate, or unbound ${label} evidence`);
      if (!evidenceDirectory) throw new Error('qualified hardware report requires an evidence directory');
      snapshotFile(resolve(evidenceDirectory, evidence.name), { maximum: 16 * 1024 * 1024, expectedBytes: evidence.bytes, expectedSHA256: evidence.sha256, label: `${label} evidence` });
      evidenceNames.add(evidence.name); seenEvidence.add(evidence.name);
    }
  }
  return new Set(names);
};

const validateV1 = (value) => {
  exactKeys(value, ['schema_version', 'artifact_sha256', 'architecture', 'hardware_class', 'model_identifier', 'macos_version', 'macos_build', 'secure_enclave', 'started_at', 'completed_at', 'operator', 'qualified', 'tests'], 'hardware qualification report');
  if (value.schema_version !== 1 || value.qualified !== false) throw new Error('v1 hardware qualification is accepted only as unqualified/non-production');
  console.log(JSON.stringify({ ok: true, schema_version: 1, qualified: false, production: false, backwards_compatible: true }));
};

const reportSnapshot = snapshotFile(input, { maximum: 4 * 1024 * 1024, capture: true, label: 'hardware qualification report' });
const reportValue = readJSON(reportSnapshot, 'hardware qualification report');
if (reportValue.schema_version === 1) { validateV1(reportValue); process.exit(0); }
if (reportValue.schema_version !== 2) throw new Error('unsupported hardware qualification schema version');
if (!reportSnapshot.content.equals(canonicalJSON(reportValue))) throw new Error('hardware qualification report is not canonical JSON');
exactKeys(reportValue, [
  'schema_version', 'source_commit', 'dependency_lock_sha256', 'release_manifest_sha256', 'artifact_name', 'artifact_sha256',
  'architecture', 'hardware_class', 'model_identifier', 'macos_version', 'macos_build', 'secure_enclave', 'team_id',
  'nested_code_identities', 'notarization', 'cloud_image_digest', 'database_migration_manifest_sha256', 'signer_key_versions',
  'browser_versions', 'started_at', 'completed_at', 'operator', 'operator_key_fingerprint', 'qualified', 'tests', 'gates'
], 'hardware qualification report');
for (const field of ['source_commit']) if (typeof reportValue[field] !== 'string' || !/^[0-9a-f]{40}$/.test(reportValue[field])) throw new Error(`invalid ${field}`);
for (const field of ['dependency_lock_sha256', 'release_manifest_sha256', 'artifact_sha256', 'database_migration_manifest_sha256']) if (!validDigest(reportValue[field])) throw new Error(`invalid ${field}`);
if (!safeName(reportValue.artifact_name) || !['arm64', 'x86_64'].includes(reportValue.architecture) || !['apple_silicon', 'intel_t2', 'intel_without_t2'].includes(reportValue.hardware_class)) throw new Error('invalid artifact or hardware identity');
if ((reportValue.hardware_class === 'apple_silicon') !== (reportValue.architecture === 'arm64') || (reportValue.hardware_class === 'intel_without_t2' && reportValue.secure_enclave === true)) throw new Error('hardware class and architecture disagree');
if (typeof reportValue.model_identifier !== 'string' || !/^[A-Za-z0-9,._-]{3,80}$/.test(reportValue.model_identifier) || typeof reportValue.macos_version !== 'string' || !/^\d+\.\d+(?:\.\d+)?$/.test(reportValue.macos_version) || typeof reportValue.macos_build !== 'string' || !/^[A-Za-z0-9]{3,32}$/.test(reportValue.macos_build) || typeof reportValue.secure_enclave !== 'boolean') throw new Error('physical hardware identity is invalid');
if (typeof reportValue.team_id !== 'string' || !/^[A-Z0-9]{10}$/.test(reportValue.team_id)) throw new Error('invalid Team ID');
if (!Array.isArray(reportValue.nested_code_identities) || reportValue.nested_code_identities.length === 0 || reportValue.nested_code_identities.length > 64) throw new Error('nested code identities are invalid');
let previousIdentity = '';
for (const identity of reportValue.nested_code_identities) {
  exactKeys(identity, ['path', 'bundle_id', 'team_id', 'code_directory_hash'], 'nested code identity');
  if (typeof identity.path !== 'string' || !/^[A-Za-z0-9._/-]+$/.test(identity.path) || !safeName(basename(identity.path)) || identity.path.split('/').includes('..') || identity.path.startsWith('/') || typeof identity.bundle_id !== 'string' || !/^[A-Za-z0-9.-]+$/.test(identity.bundle_id) || identity.team_id !== reportValue.team_id || !/^[0-9a-f]{40,64}$/.test(identity.code_directory_hash) || lexicalCompare(identity.path, previousIdentity) <= 0) throw new Error('nested code identity is invalid, unsorted, or substituted');
  previousIdentity = identity.path;
}
if (reportValue.qualified) {
  const identities = new Map(reportValue.nested_code_identities.map((item) => [item.path, item.bundle_id]));
  if ([...requiredCodeIdentities].some(([path, id]) => identities.get(path) !== id)) throw new Error('qualified report is missing a required code identity');
}
if (!validCloudDigest(reportValue.cloud_image_digest)) throw new Error('invalid Cloud image digest');
exactKeys(reportValue.notarization, ['status', 'submission_ids', 'evidence'], 'hardware notarization binding');
if (!['not_verified', 'accepted_stapled'].includes(reportValue.notarization.status) || !Array.isArray(reportValue.notarization.submission_ids) || !Array.isArray(reportValue.notarization.evidence)) throw new Error('invalid hardware notarization binding');
for (const id of reportValue.notarization.submission_ids) if (typeof id !== 'string' || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(id)) throw new Error('invalid hardware notarization submission ID');
for (const item of reportValue.notarization.evidence) { exactKeys(item, ['kind', 'name', 'bytes', 'sha256'], 'hardware notarization evidence'); if (!safeName(item.name) || !['notarytool_result', 'stapler_result'].includes(item.kind) || !Number.isSafeInteger(item.bytes) || !validDigest(item.sha256)) throw new Error('invalid hardware notarization evidence'); }
const validateVersionList = (items, label) => {
  if (!Array.isArray(items) || items.length === 0 || items.length > 64) throw new Error(`${label} are invalid`);
  let previous = '';
  for (const item of items) {
    exactKeys(item, ['name', 'version'], label);
    if (typeof item.name !== 'string' || !/^[A-Za-z0-9._-]{1,80}$/.test(item.name) || typeof item.version !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._+~-]{0,127}$/.test(item.version) || lexicalCompare(item.name, previous) <= 0) throw new Error(`${label} are invalid or unsorted`);
    previous = item.name;
  }
};
validateVersionList(reportValue.signer_key_versions, 'signer key versions');
validateVersionList(reportValue.browser_versions, 'browser versions');
if (typeof reportValue.operator !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9@._-]{2,127}$/.test(reportValue.operator) || !/^SHA256:[A-Za-z0-9_-]{43}$/.test(reportValue.operator_key_fingerprint) || typeof reportValue.qualified !== 'boolean') throw new Error('invalid qualification conclusion');
const started = Date.parse(reportValue.started_at); const completed = Date.parse(reportValue.completed_at);
if (!Number.isFinite(started) || !Number.isFinite(completed) || !utcTimestamp.test(reportValue.started_at) || !utcTimestamp.test(reportValue.completed_at) || completed < started || completed - started > 24 * 60 * 60 * 1000) throw new Error('invalid hardware qualification time window');

const suppliedGate = args.length === V2_ARGUMENTS;
if (reportValue.qualified && !suppliedGate) throw new Error('qualified result requires signed release manifest, exact artifact, and detached operator signature inputs');
if (!suppliedGate) {
  if (reportValue.qualified) throw new Error('qualified result cannot be self-asserted');
  validateEvidenceList(reportValue.tests, 'hardware test', null, new Set());
  validateEvidenceList(reportValue.gates, 'hardware gate', null, new Set());
  console.log(JSON.stringify({ ok: true, schema_version: 2, qualified: false, production: false, operator_signature_verified: false }));
} else {
  const evidenceDirectory = resolve(evidenceDirectoryInput);
  const release = validateManifest(snapshotFile(manifestInput, { maximum: 16 * 1024 * 1024, capture: true, label: 'release manifest' }), manifestSignatureInput, manifestPublicKeyInput, manifestFingerprint);
  if (release.manifest.source.commit !== reportValue.source_commit) throw new Error('source commit mismatch between report and signed release manifest');
  if (createHash('sha256').update(release.manifestBytes).digest('hex') !== reportValue.release_manifest_sha256) throw new Error('release manifest digest mismatch');
  const product = release.artifacts.find((item) => item.role === 'product');
  const artifact = snapshotFile(artifactInput, { maximum: 16 * 1024 * 1024 * 1024, label: 'release artifact' });
  if (basename(artifactInput) !== reportValue.artifact_name || product.name !== reportValue.artifact_name || artifact.name !== product.name || artifact.sha256 !== reportValue.artifact_sha256 || product.sha256 !== reportValue.artifact_sha256 || artifact.bytes !== product.bytes) throw new Error('exact product artifact does not match signed release manifest');
  if (release.notarization.status !== reportValue.notarization.status || JSON.stringify(release.notarization.submission_ids) !== JSON.stringify(reportValue.notarization.submission_ids) || JSON.stringify(release.notarization.evidence) !== JSON.stringify(reportValue.notarization.evidence)) throw new Error('notarization binding mismatch between report and signed release manifest');
  const attestationArtifact = release.artifacts.find((item) => item.name === 'release-attestation.json');
  if (!attestationArtifact) throw new Error('signed release manifest is missing release-attestation.json');
  const attestationSnapshot = snapshotFile(resolve(release.manifestDirectory, attestationArtifact.name), { maximum: 2 * 1024 * 1024, capture: true, expectedBytes: attestationArtifact.bytes, expectedSHA256: attestationArtifact.sha256, label: 'release attestation' });
  const attestation = readJSON(attestationSnapshot, 'release attestation');
  if (!attestationSnapshot.content.equals(canonicalJSON(attestation))) throw new Error('release attestation is not canonical JSON');
  exactKeys(attestation, ['schema_version', 'team_id', 'nested_code_identities', 'cloud_image_digest', 'dependency_lock_sha256', 'database_migration_manifest_sha256', 'signer_key_versions'], 'release attestation');
  if (attestation.schema_version !== 1 || attestation.team_id !== reportValue.team_id || JSON.stringify(attestation.nested_code_identities) !== JSON.stringify(reportValue.nested_code_identities) || attestation.cloud_image_digest !== reportValue.cloud_image_digest || attestation.dependency_lock_sha256 !== reportValue.dependency_lock_sha256 || attestation.database_migration_manifest_sha256 !== reportValue.database_migration_manifest_sha256 || JSON.stringify(attestation.signer_key_versions) !== JSON.stringify(reportValue.signer_key_versions)) throw new Error('release attestation does not match hardware qualification report');
  if (reportValue.qualified && (reportValue.secure_enclave !== true || reportValue.hardware_class === 'intel_without_t2' || reportValue.notarization.status !== 'accepted_stapled')) throw new Error('hardware cannot qualify for production guarantees');
  const seenEvidence = new Set();
  const testNames = validateEvidenceList(reportValue.tests, 'hardware test', evidenceDirectory, seenEvidence);
  const gateNames = validateEvidenceList(reportValue.gates, 'hardware gate', evidenceDirectory, seenEvidence);
  if (reportValue.qualified && (reportValue.tests.some((item) => item.status !== 'passed') || reportValue.gates.some((item) => item.status !== 'passed') || requiredTests.some((name) => !testNames.has(name)) || requiredGates.some((name) => !gateNames.has(name)))) throw new Error('qualified result is missing required passing tests or gates');
  const operator = verifyDetached(reportSnapshot.content, operatorSignatureInput, operatorPublicKeyInput, operatorFingerprint, 'operator');
  if (operator.fingerprint !== reportValue.operator_key_fingerprint) throw new Error('report operator key fingerprint does not match detached operator signature');
  if (reportValue.qualified && seenEvidence.size === 0) throw new Error('qualified result requires real evidence files');
  console.log(JSON.stringify({ ok: true, schema_version: 2, qualified: reportValue.qualified, production: reportValue.qualified, tests: testNames.size, gates: gateNames.size, artifact_name: reportValue.artifact_name, artifact_sha256: reportValue.artifact_sha256, source_commit: reportValue.source_commit, release_manifest_sha256: reportValue.release_manifest_sha256, operator_key_fingerprint: operator.fingerprint, operator_signature_verified: true, release_manifest_signature_verified: true }));
}
