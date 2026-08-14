#!/usr/bin/env node
import { createHash, createPublicKey, verify } from 'node:crypto';
import fs from 'node:fs';
import { basename, dirname, resolve } from 'node:path';
import {
  CONTROLLER_ARCHIVE_NAME_PATTERN,
  canonicalExternalQualificationControllerIdentity,
  parseCanonicalExternalQualificationControllerIdentity
} from './n3e/controller-identity-contract.mjs';
import { assertReleaseCandidateIdMatchesProduct, RELEASE_MANIFEST_SCHEMA_VERSION } from '../../lib/release-candidate-identity.mjs';

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
const sortedJSON = (value) => {
  if (Array.isArray(value)) return value.map(sortedJSON);
  if (value && typeof value === 'object') return Object.fromEntries(Object.keys(value).sort().map((key) => [key, sortedJSON(value[key])]));
  return value;
};
const canonicalN3ESuiteRecord = (value) => Buffer.from(`${JSON.stringify(sortedJSON(value), null, 2)}\n`, 'utf8');
const N3E_SUITE_KIND = 'agentpass-n3e-qualification-suite-evidence';
const N3E_SUITE_STEPS = Object.freeze([
  Object.freeze({ kind: 'unarmed-control', scenario: null, phase: null }),
  Object.freeze({ kind: 'scenario', scenario: 'pre-cloud-kill', phase: 'pre-cloud' }),
  Object.freeze({ kind: 'scenario', scenario: 'post-cloud-pre-local-kill', phase: 'post-cloud-pre-local' }),
  Object.freeze({ kind: 'scenario', scenario: 'post-activation-pre-audit-kill', phase: 'post-activation-pre-audit' }),
  Object.freeze({ kind: 'scenario', scenario: 'post-audit-pre-reply-loss', phase: 'post-audit-pre-reply' }),
  Object.freeze({ kind: 'scenario', scenario: 'audit-fsync-failure', phase: 'audit-fsync' }),
  Object.freeze({ kind: 'scenario', scenario: 'transport-reply-loss', phase: 'transport-reply' })
]);
const N3E_RECORD_KEYS = Object.freeze([
  'artifact_sha256', 'candidate_checkpoint_sha256', 'completed_at', 'kind', 'lane_class',
  'release_trust_sha256', 'schema_version', 'source_commit', 'started_at', 'steps',
  'suite_input_sha256', 'team_id', 'teardown_proof_sha256'
]);
const N3E_STEP_KEYS = Object.freeze(['evidence_sha256', 'kind', 'phase', 'scenario', 'status']);
const N3E_SECRET_KEY = /(?:grant|run[_-]?binding|secret|token|password|private|credential|authorization|stdout|stderr|raw|signature|nonce|output)/iu;
const N3E_SECRET_VALUE = /(?:-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----|\bBearer\s+\S+|\b(?:sk|ghp|github_pat|xox[baprs])_[A-Za-z0-9_-]{8,}|\bprivate[-_ ]?(?:key|token|credential)\b)/iu;
const n3eNonzeroDigest = (value, label) => {
  if (!validDigest(value) || value === '0'.repeat(64)) throw new Error(`${label} is invalid`);
  return value;
};
const rejectN3ESecretMaterial = (value, path = '$') => {
  if (Array.isArray(value)) { value.forEach((item, index) => rejectN3ESecretMaterial(item, `${path}[${index}]`)); return; }
  if (value && typeof value === 'object') {
    for (const [key, child] of Object.entries(value)) {
      if (N3E_SECRET_KEY.test(key)) throw new Error(`${path}.${key} contains forbidden Grant, run binding, or secret material`);
      rejectN3ESecretMaterial(child, `${path}.${key}`);
    }
    return;
  }
  if (typeof value === 'string' && N3E_SECRET_VALUE.test(value)) throw new Error(`${path} contains secret material`);
};
const validateN3ESuiteReportEvidence = (value, report) => {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('N3-E report evidence binding is invalid');
  exactKeys(value, ['schema_version', 'record', 'record_sha256'], 'N3-E report evidence binding');
  if (value.schema_version !== 1 || !validDigest(value.record_sha256)) throw new Error('N3-E report evidence binding version or digest is invalid');
  const record = value.record;
  exactKeys(record, N3E_RECORD_KEYS, 'N3-E suite evidence record');
  if (record.schema_version !== 1 || record.kind !== N3E_SUITE_KIND) throw new Error('N3-E suite evidence identity is invalid');
  n3eNonzeroDigest(record.suite_input_sha256, 'N3-E suite input digest');
  n3eNonzeroDigest(record.release_trust_sha256, 'N3-E release trust digest');
  n3eNonzeroDigest(record.candidate_checkpoint_sha256, 'N3-E candidate checkpoint digest');
  n3eNonzeroDigest(record.artifact_sha256, 'N3-E artifact digest');
  n3eNonzeroDigest(record.teardown_proof_sha256, 'N3-E teardown proof digest');
  if (typeof record.source_commit !== 'string' || !/^[0-9a-f]{40}$/.test(record.source_commit) || record.source_commit === '0'.repeat(40)) throw new Error('N3-E source commit is invalid');
  if (typeof record.team_id !== 'string' || !/^[A-Z0-9]{10}$/.test(record.team_id)) throw new Error('N3-E Team ID is invalid');
  if (!['apple_silicon', 'intel_t2'].includes(record.lane_class)) throw new Error('N3-E lane class is invalid');
  if (record.source_commit !== report.source_commit || record.artifact_sha256 !== report.artifact_sha256 || record.team_id !== report.team_id || record.lane_class !== report.hardware_class) throw new Error('N3-E suite evidence does not bind the report source, artifact, Team ID, or lane');
  const parseN3ETimestamp = (timestamp, label) => {
    if (typeof timestamp !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(timestamp) || !Number.isFinite(Date.parse(timestamp)) || new Date(Date.parse(timestamp)).toISOString() !== timestamp) throw new Error(`${label} is invalid`);
    return Date.parse(timestamp);
  };
  const started = parseN3ETimestamp(record.started_at, 'N3-E suite started_at');
  const completed = parseN3ETimestamp(record.completed_at, 'N3-E suite completed_at');
  if (completed <= started || completed - started > 2 * 60 * 60 * 1000) throw new Error('N3-E suite timestamp window is invalid');
  const reportStarted = Date.parse(report.started_at); const reportCompleted = Date.parse(report.completed_at);
  if (started < reportStarted || completed > reportCompleted) throw new Error('N3-E suite timestamps fall outside the hardware report window');
  if (!Array.isArray(record.steps) || record.steps.length !== N3E_SUITE_STEPS.length) throw new Error('N3-E suite evidence must contain exactly seven steps');
  const stepDigests = new Set();
  record.steps.forEach((step, index) => {
    exactKeys(step, N3E_STEP_KEYS, `N3-E suite step ${index}`);
    const expected = N3E_SUITE_STEPS[index];
    if (step.kind !== expected.kind || step.scenario !== expected.scenario || step.phase !== expected.phase || step.status !== 'passed') throw new Error('N3-E suite steps are missing, duplicated, reordered, or substituted');
    n3eNonzeroDigest(step.evidence_sha256, `N3-E suite step ${index} evidence digest`);
    if (stepDigests.has(step.evidence_sha256)) throw new Error('N3-E suite step evidence digest is repeated');
    stepDigests.add(step.evidence_sha256);
  });
  rejectN3ESecretMaterial(value);
  const expectedRecordDigest = createHash('sha256').update(canonicalN3ESuiteRecord(record)).digest('hex');
  if (value.record_sha256 !== expectedRecordDigest) throw new Error('N3-E suite evidence record digest mismatch');
  return value.record_sha256;
};
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

const validateManifest = (manifestSnapshot, manifestSignaturePath, manifestPublicKeyPath, expectedFingerprint, expectedTeamId) => {
  const manifestBytes = manifestSnapshot.content;
  if (!manifestBytes.equals(canonicalJSON(readJSON(manifestSnapshot, 'release manifest')))) throw new Error('release manifest is not canonical JSON');
  const signed = verifyDetached(manifestBytes, manifestSignaturePath, manifestPublicKeyPath, expectedFingerprint, 'release manifest');
  const manifest = readJSON(manifestSnapshot, 'release manifest');
  if (manifest.schema_version !== RELEASE_MANIFEST_SCHEMA_VERSION || manifest.product !== 'AgentPass') throw new Error('unsupported release manifest identity');
  exactKeys(manifest, ['schema_version', 'product', 'version', 'source', 'generated_at', 'candidate_id', 'artifacts', 'external_qualification_controller', 'evidence'], 'release manifest');
  if (typeof manifest.version !== 'string' || !/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(manifest.version) || !canonicalDate(manifest.generated_at)) throw new Error('invalid release metadata');
  exactKeys(manifest.source, ['commit', 'tree', 'tag'], 'release manifest source');
  if (!/^[0-9a-f]{40}$/.test(manifest.source.commit) || !/^[0-9a-f]{40}$/.test(manifest.source.tree)) throw new Error('release manifest source identity is invalid');
  if (manifest.source.tag !== null && (typeof manifest.source.tag !== 'string' || !/^v\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(manifest.source.tag))) throw new Error('release manifest source tag is invalid');
  if (!Array.isArray(manifest.artifacts) || manifest.artifacts.length === 0) throw new Error('release manifest has no artifacts');
  const manifestDirectory = dirname(manifestSnapshot.path);
  const artifacts = [];
  const names = new Set();
  const roles = new Set(['product', 'sbom', 'release_notice', 'trust_root', 'auxiliary', 'external_qualification_controller']);
  const mediaTypes = new Set(['application/spdx+json', 'application/zip', 'application/vnd.apple.installer+xml', 'application/gzip', 'application/x-pem-file', 'application/json', 'text/plain', 'application/octet-stream']);
  let previousName = '';
  for (const artifact of manifest.artifacts) {
    exactKeys(artifact, ['name', 'role', 'media_type', 'bytes', 'sha256'], 'release artifact');
    const isControllerArchive = CONTROLLER_ARCHIVE_NAME_PATTERN.test(artifact.name);
    if (!safeName(artifact.name) || names.has(artifact.name) || lexicalCompare(artifact.name, previousName) <= 0 || !roles.has(artifact.role) || !mediaTypes.has(artifact.media_type) || !Number.isSafeInteger(artifact.bytes) || artifact.bytes <= 0 || !validDigest(artifact.sha256) || ((artifact.role === 'sbom') !== (artifact.media_type === 'application/spdx+json')) || (isControllerArchive !== (artifact.role === 'external_qualification_controller')) || (artifact.role === 'external_qualification_controller' && artifact.media_type !== 'application/octet-stream')) throw new Error('release manifest artifact metadata is invalid');
    snapshotFile(resolve(manifestDirectory, artifact.name), { maximum: 16 * 1024 * 1024 * 1024, expectedBytes: artifact.bytes, expectedSHA256: artifact.sha256, label: 'release artifact' });
    names.add(artifact.name); previousName = artifact.name; artifacts.push(artifact);
  }
  const products = artifacts.filter((item) => item.role === 'product');
  if (products.length !== 1 || products[0].name !== `AgentPass-v${manifest.version}-macos-universal.pkg` || products[0].media_type !== 'application/vnd.apple.installer+xml') throw new Error('release manifest must contain exactly one canonical macOS product artifact');
  assertReleaseCandidateIdMatchesProduct(manifest.candidate_id, products[0].sha256);
  const controllerArtifacts = artifacts.filter((item) => item.role === 'external_qualification_controller');
  if (controllerArtifacts.length !== 1) throw new Error('release manifest must contain exactly one external qualification controller archive for schema v4');
  if (controllerArtifacts[0].name !== `AgentPassQualificationController-${manifest.version}-macos-universal.tar`) throw new Error('external qualification controller archive version does not match the release');
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
  let controllerIdentityDocument;
  let controllerIdentity;
  let controllerNotarization;
  const controllerNotarizationEvidence = [];
  {
    exactKeys(manifest.external_qualification_controller, ['identity_document', 'identity', 'notarization'], 'external qualification controller');
    const identityDocument = manifest.external_qualification_controller.identity_document;
    exactKeys(identityDocument, ['name', 'bytes', 'sha256'], 'external qualification controller identity document');
    if (!safeName(identityDocument.name) || names.has(identityDocument.name) || !Number.isSafeInteger(identityDocument.bytes) || identityDocument.bytes <= 0 || !validDigest(identityDocument.sha256)) throw new Error('external qualification controller identity document metadata is invalid');
    const identitySnapshot = snapshotFile(resolve(manifestDirectory, identityDocument.name), { maximum: 1024 * 1024, capture: true, expectedBytes: identityDocument.bytes, expectedSHA256: identityDocument.sha256, label: 'external qualification controller identity document' });
    try { controllerIdentity = parseCanonicalExternalQualificationControllerIdentity(identitySnapshot.content); } catch (error) { throw new Error(`external qualification controller identity document is invalid: ${error.message}`); }
    let embeddedIdentity;
    try { embeddedIdentity = canonicalExternalQualificationControllerIdentity(manifest.external_qualification_controller.identity); } catch (error) { throw new Error(`external qualification controller embedded identity is invalid: ${error.message}`); }
    if (JSON.stringify(controllerIdentity) !== JSON.stringify(embeddedIdentity)) throw new Error('external qualification controller identity document and embedded identity disagree');
    const controllerArtifact = controllerArtifacts[0];
    if (controllerIdentity.archive_name !== controllerArtifact.name || controllerIdentity.archive_sha256 !== controllerArtifact.sha256 || controllerIdentity.archive_bytes !== controllerArtifact.bytes || controllerIdentity.team_id !== expectedTeamId) throw new Error('external qualification controller identity does not bind the exact archive or release Team ID');
    controllerIdentityDocument = identityDocument;
    names.add(identityDocument.name);

    controllerNotarization = manifest.external_qualification_controller.notarization;
    exactKeys(controllerNotarization, ['status', 'submission_ids', 'evidence'], 'external qualification controller notarization');
    if (controllerNotarization.status !== 'accepted_stapled' || !Array.isArray(controllerNotarization.submission_ids) || controllerNotarization.submission_ids.length === 0 || !Array.isArray(controllerNotarization.evidence) || controllerNotarization.evidence.length !== 2) throw new Error('external qualification controller notarization must be complete accepted_stapled evidence');
    let previousControllerSubmission = '';
    const controllerSubmissionIDs = new Set();
    for (const id of controllerNotarization.submission_ids) {
      if (typeof id !== 'string' || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(id) || controllerSubmissionIDs.has(id) || lexicalCompare(id, previousControllerSubmission) <= 0) throw new Error('external qualification controller notarization submission ID is invalid');
      controllerSubmissionIDs.add(id); previousControllerSubmission = id;
    }
    const controllerEvidenceKinds = new Set();
    let previousControllerEvidenceName = '';
    const controllerEvidenceContent = new Map();
    for (const item of controllerNotarization.evidence) {
      exactKeys(item, ['kind', 'name', 'bytes', 'sha256'], 'external qualification controller notarization evidence');
      if (!['notarytool_result', 'stapler_result'].includes(item.kind) || controllerEvidenceKinds.has(item.kind) || !safeName(item.name) || names.has(item.name) || lexicalCompare(item.name, previousControllerEvidenceName) <= 0 || !Number.isSafeInteger(item.bytes) || item.bytes <= 0 || !validDigest(item.sha256)) throw new Error('external qualification controller notarization evidence metadata is invalid');
      const snapshot = snapshotFile(resolve(manifestDirectory, item.name), { maximum: 4 * 1024 * 1024, capture: true, expectedBytes: item.bytes, expectedSHA256: item.sha256, label: 'external qualification controller notarization evidence' });
      names.add(item.name); controllerEvidenceKinds.add(item.kind); controllerEvidenceContent.set(item.kind, snapshot.content); previousControllerEvidenceName = item.name; controllerNotarizationEvidence.push(item);
    }
    if (controllerEvidenceKinds.size !== 2 || !controllerEvidenceKinds.has('notarytool_result') || !controllerEvidenceKinds.has('stapler_result')) throw new Error('external qualification controller notarization evidence is incomplete');
    let controllerNotaryResult;
    try { controllerNotaryResult = JSON.parse(controllerEvidenceContent.get('notarytool_result').toString('utf8')); } catch { throw new Error('external qualification controller notarytool evidence is not valid JSON'); }
    if (typeof controllerNotaryResult !== 'object' || controllerNotaryResult === null || controllerNotaryResult.status !== 'Accepted' || typeof controllerNotaryResult.id !== 'string' || !controllerSubmissionIDs.has(controllerNotaryResult.id.toLowerCase())) throw new Error('external qualification controller notarytool evidence does not match an accepted submission');
    if (!/The validate action worked!/i.test(controllerEvidenceContent.get('stapler_result').toString('utf8'))) throw new Error('external qualification controller stapler evidence does not record successful validation');
  }
  const checksums = manifest.evidence.checksums;
  exactKeys(checksums, ['name', 'bytes', 'sha256', 'entry_count'], 'release checksums evidence');
  const extraChecksumEntries = [controllerIdentityDocument, ...controllerNotarizationEvidence];
  if (!safeName(checksums.name) || names.has(checksums.name) || !Number.isSafeInteger(checksums.bytes) || checksums.bytes <= 0 || !validDigest(checksums.sha256) || checksums.entry_count !== artifacts.length + evidence.length + extraChecksumEntries.length) throw new Error('release checksums evidence metadata is invalid');
  const checksumEntries = [...artifacts, ...evidence, ...extraChecksumEntries].sort((left, right) => lexicalCompare(left.name, right.name));
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
  'cloud-possession-verification', 'claude-code-unattended-sign', 'cursor-code-unattended-sign',
  'audit-upload-observation', 'policy-reduction-refresh-ack', 'offline-expiry',
  'revoke-emergency-stop', 'crash-restart-recovery', 'sleep-wake-network-clock',
  'upgrade-preserves-state', 'uninstall-reinstall-recovery', 'current-user-purge',
  'negative-identity-and-entitlement-cases'
];
const requiredTests = [
  'exact-pkg-install', 'launchd-xpc-approval', 'secure-enclave-key-creation',
  'secure-enclave-nonexportability', 'cloud-possession-proof',
  'claude-code-unattended-sign', 'cursor-code-unattended-sign', 'unrelated-process-denied',
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
const reportKeys = [
  'schema_version', 'source_commit', 'dependency_lock_sha256', 'release_manifest_sha256', 'artifact_name', 'artifact_sha256',
  'architecture', 'hardware_class', 'model_identifier', 'macos_version', 'macos_build', 'secure_enclave', 'team_id',
  'nested_code_identities', 'notarization', 'cloud_image_digest', 'database_migration_manifest_sha256', 'signer_key_versions',
  'browser_versions', 'started_at', 'completed_at', 'operator', 'operator_key_fingerprint', 'qualified', 'tests', 'gates'
];
if (Object.hasOwn(reportValue, 'n3e_qualification_suite_evidence')) reportKeys.push('n3e_qualification_suite_evidence');
exactKeys(reportValue, reportKeys, 'hardware qualification report');
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
let n3eSuiteEvidenceSHA256 = null;
if (Object.hasOwn(reportValue, 'n3e_qualification_suite_evidence') && reportValue.n3e_qualification_suite_evidence !== null) {
  n3eSuiteEvidenceSHA256 = validateN3ESuiteReportEvidence(reportValue.n3e_qualification_suite_evidence, reportValue);
} else if (reportValue.qualified) {
  throw new Error('qualified result cannot be self-asserted and requires N3-E qualification suite evidence');
}

const suppliedGate = args.length === V2_ARGUMENTS;
if (reportValue.qualified && !suppliedGate) throw new Error('qualified result requires signed release manifest, exact artifact, and detached operator signature inputs');
if (!suppliedGate) {
  if (reportValue.qualified) throw new Error('qualified result cannot be self-asserted');
  validateEvidenceList(reportValue.tests, 'hardware test', null, new Set());
  validateEvidenceList(reportValue.gates, 'hardware gate', null, new Set());
  console.log(JSON.stringify({ ok: true, schema_version: 2, qualified: false, production: false, operator_signature_verified: false }));
} else {
  const evidenceDirectory = resolve(evidenceDirectoryInput);
  const release = validateManifest(snapshotFile(manifestInput, { maximum: 16 * 1024 * 1024, capture: true, label: 'release manifest' }), manifestSignatureInput, manifestPublicKeyInput, manifestFingerprint, reportValue.team_id);
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
  console.log(JSON.stringify({ ok: true, schema_version: 2, qualified: reportValue.qualified, production: reportValue.qualified, tests: testNames.size, gates: gateNames.size, artifact_name: reportValue.artifact_name, artifact_sha256: reportValue.artifact_sha256, source_commit: reportValue.source_commit, release_manifest_sha256: reportValue.release_manifest_sha256, operator_key_fingerprint: operator.fingerprint, operator_signature_verified: true, release_manifest_signature_verified: true, ...(n3eSuiteEvidenceSHA256 ? { n3e_suite_evidence_sha256: n3eSuiteEvidenceSHA256 } : {}) }));
}
