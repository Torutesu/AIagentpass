#!/usr/bin/env node
import { createHash, createPublicKey, randomBytes, verify } from 'node:crypto';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import {
  basename,
  dirname,
  isAbsolute,
  join,
  parse,
  relative,
  resolve,
  sep
} from 'node:path';
import { TextDecoder } from 'node:util';
import {
  CONTROLLER_ARCHIVE_NAME_PATTERN,
  parseCanonicalExternalQualificationControllerIdentity,
  validateExternalQualificationControllerIdentity
} from './n3e/controller-identity-contract.mjs';

const MAX_MANIFEST_BYTES = 16 * 1024 * 1024;
const MAX_ARTIFACT_BYTES = 16 * 1024 * 1024 * 1024;
const MAX_SBOM_BYTES = 32 * 1024 * 1024;
const MAX_ATTESTATION_BYTES = 2 * 1024 * 1024;
const MAX_EVIDENCE_BYTES = 4 * 1024 * 1024;
const MAX_KEY_BYTES = 16 * 1024;
const MAX_SIGNATURE_BYTES = 1024;
const MAX_BROWSER_INPUT_BYTES = 1024 * 1024;
const ZERO_40 = '0'.repeat(40);
const ZERO_64 = '0'.repeat(64);
const FINGERPRINT = /^SHA256:[A-Za-z0-9_-]{43}$/u;
const DIGEST = /^[0-9a-f]{64}$/u;
const CLOUD_DIGEST = /^sha256:[0-9a-f]{64}$/u;
const COMMIT = /^[0-9a-f]{40}$/u;
const TEAM_ID = /^[A-Z0-9]{10}$/u;
const SAFE_NAME = /^[0-9A-Za-z][0-9A-Za-z._-]*$/u;
const VERSION_NAME = /^[A-Za-z0-9._-]{1,80}$/u;
const VERSION = /^[A-Za-z0-9][A-Za-z0-9._+~-]{0,127}$/u;
const OPERATOR = /^[A-Za-z0-9][A-Za-z0-9@._-]{2,127}$/u;
const CODE_HASH = /^[0-9a-f]{40,64}$/u;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u;
const VERSION_STRING = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/u;
const CANONICAL_DATE = (value) => typeof value === 'string'
  && Number.isFinite(Date.parse(value))
  && new Date(value).toISOString() === value;

export const REPORT_KEYS = Object.freeze([
  'schema_version', 'source_commit', 'dependency_lock_sha256', 'release_manifest_sha256',
  'artifact_name', 'artifact_sha256', 'architecture', 'hardware_class', 'model_identifier',
  'macos_version', 'macos_build', 'secure_enclave', 'team_id', 'nested_code_identities',
  'notarization', 'cloud_image_digest', 'database_migration_manifest_sha256',
  'signer_key_versions', 'browser_versions', 'started_at', 'completed_at', 'operator',
  'operator_key_fingerprint', 'qualified', 'tests', 'gates'
]);

export const REQUIRED_CODE_IDENTITIES = Object.freeze([
  Object.freeze({ path: 'AgentPass.app', bundle_id: 'dev.agentpass' }),
  Object.freeze({ path: 'AgentPass.app/Contents/Library/HelperTools/AgentPassNativeClient.app', bundle_id: 'dev.agentpass.native-client' }),
  Object.freeze({ path: 'AgentPass.app/Contents/Library/HelperTools/AgentPassNativeService.app', bundle_id: 'dev.agentpass.native-service' }),
  Object.freeze({ path: 'AgentPass.app/Contents/Library/HelperTools/agentpass-atomic-rename', bundle_id: 'dev.agentpass.atomic-rename' }),
  Object.freeze({ path: 'AgentPass.app/Contents/MacOS/agentpass-native-manager', bundle_id: 'dev.agentpass.native-manager' }),
  Object.freeze({ path: 'AgentPass.app/Contents/MacOS/agentpass-onboarding', bundle_id: 'dev.agentpass' })
]);

const MEDIA_TYPES = new Set([
  'application/spdx+json', 'application/zip', 'application/vnd.apple.installer+xml',
  'application/gzip', 'application/x-pem-file', 'application/json', 'text/plain',
  'application/octet-stream'
]);
const ROLES = new Set(['product', 'sbom', 'release_notice', 'trust_root', 'auxiliary', 'external_qualification_controller']);

export const canonicalJSON = (value) => Buffer.from(`${JSON.stringify(value, null, 2)}\n`, 'utf8');
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
const lexicalCompare = (left, right) => left < right ? -1 : left > right ? 1 : 0;
const exactKeys = (value, expected, label) => {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new Error(`${label} must be an object`);
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) {
    throw new Error(`${label} has missing or unknown fields`);
  }
};

const assertNoFollowSupport = () => {
  if (!Number.isInteger(fs.constants.O_NOFOLLOW)) throw new Error('O_NOFOLLOW is unavailable on this platform');
};

const safeAbsolutePath = (input, label) => {
  if (typeof input !== 'string' || input.length === 0 || input.includes('\0') || !isAbsolute(input)) {
    throw new Error(`${label} must be an absolute path`);
  }
  const path = resolve(input);
  // The final component is the trust boundary. Parent paths may include the
  // platform's canonical /tmp alias (for example /tmp -> /private/tmp), but
  // the requested file itself is always opened with O_NOFOLLOW and checked
  // again by readStableFile.
  try {
    const stat = fs.lstatSync(path);
    if (stat.isSymbolicLink()) throw new Error(`${label} path contains a symlink`);
  } catch (error) {
    if (error?.code !== 'ENOENT') throw error;
  }
  return path;
};

const statIdentity = (stat) => [
  stat.dev, stat.ino, stat.mode, stat.nlink, stat.size, stat.mtimeNs, stat.ctimeNs
].join(':');

const readStableFile = (input, { maximum, label, capture = true } = {}) => {
  assertNoFollowSupport();
  const path = safeAbsolutePath(input, label);
  let descriptor;
  try {
    descriptor = fs.openSync(path, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  } catch {
    throw new Error(`cannot open ${label}`);
  }
  try {
    const before = fs.fstatSync(descriptor, { bigint: true });
    if (!before.isFile() || before.nlink !== 1n || before.size <= 0n
      || before.size > BigInt(maximum) || before.size > BigInt(Number.MAX_SAFE_INTEGER)) {
      throw new Error(`unsafe ${label}`);
    }
    const size = Number(before.size);
    const hash = createHash('sha256');
    const chunks = capture ? [] : null;
    const buffer = Buffer.allocUnsafe(Math.min(1024 * 1024, size));
    let offset = 0;
    while (offset < size) {
      const wanted = Math.min(buffer.length, size - offset);
      const count = fs.readSync(descriptor, buffer, 0, wanted, offset);
      if (count === 0) throw new Error(`${label} changed while reading`);
      const chunk = buffer.subarray(0, count);
      hash.update(chunk);
      if (chunks) chunks.push(Buffer.from(chunk));
      offset += count;
    }
    const after = fs.fstatSync(descriptor, { bigint: true });
    if (statIdentity(before) !== statIdentity(after)) throw new Error(`${label} changed while reading`);
    return {
      path,
      name: basename(path),
      bytes: size,
      sha256: hash.digest('hex'),
      content: chunks ? Buffer.concat(chunks, size) : undefined
    };
  } finally {
    fs.closeSync(descriptor);
  }
};

const decodeUTF8 = (bytes, label) => {
  try { return new TextDecoder('utf-8', { fatal: true }).decode(bytes); }
  catch { throw new Error(`${label} is not valid UTF-8`); }
};

const parseCanonicalJSON = (snapshot, label) => {
  let value;
  try { value = JSON.parse(decodeUTF8(snapshot.content, label)); }
  catch (error) {
    if (error instanceof SyntaxError) throw new Error(`${label} is not valid JSON`);
    throw error;
  }
  if (!snapshot.content.equals(canonicalJSON(value))) throw new Error(`${label} is not canonical JSON`);
  return value;
};

const validNonzeroDigest = (value, label) => {
  if (!DIGEST.test(value) || value === ZERO_64) throw new Error(`${label} is invalid or unbound`);
};

const validateVersionList = (value, label) => {
  if (!Array.isArray(value) || value.length === 0 || value.length > 64) throw new Error(`${label} are invalid`);
  const output = [];
  const names = new Set();
  let previous = '';
  for (const item of value) {
    exactKeys(item, ['name', 'version'], label);
    if (!VERSION_NAME.test(item.name) || !VERSION.test(item.version) || names.has(item.name)
      || lexicalCompare(item.name, previous) <= 0) throw new Error(`${label} are invalid or unsorted`);
    names.add(item.name);
    previous = item.name;
    output.push({ name: item.name, version: item.version });
  }
  return output;
};

const validateFingerprint = (value, label) => {
  if (typeof value !== 'string' || !FINGERPRINT.test(value)) throw new Error(`${label} is invalid`);
  return value;
};

const publicKeyFingerprint = (key) => `SHA256:${createHash('sha256')
  .update(key.export({ type: 'spki', format: 'der' })).digest('base64url')}`;

const verifyDetachedSignature = (payload, signatureInput, publicKeyInput, expectedFingerprint, label) => {
  validateFingerprint(expectedFingerprint, `${label} fingerprint`);
  const keySnapshot = readStableFile(publicKeyInput, { maximum: MAX_KEY_BYTES, label: `${label} public key` });
  let publicKey;
  try { publicKey = createPublicKey(keySnapshot.content); }
  catch { throw new Error(`${label} public key is invalid`); }
  if (publicKey.asymmetricKeyType !== 'ed25519') throw new Error(`${label} public key must be Ed25519`);
  if (publicKeyFingerprint(publicKey) !== expectedFingerprint) throw new Error(`${label} public key fingerprint mismatch`);
  const signatureSnapshot = readStableFile(signatureInput, { maximum: MAX_SIGNATURE_BYTES, label: `${label} signature` });
  const encoded = decodeUTF8(signatureSnapshot.content, `${label} signature`);
  if (!/^(?:[A-Za-z0-9+/]{4}){21}[A-Za-z0-9+/]{2}==\n$/u.test(encoded)) throw new Error(`${label} signature encoding is invalid`);
  const signature = Buffer.from(encoded.trim(), 'base64');
  if (signature.length !== 64 || !verify(null, payload, publicKey, signature)) throw new Error(`${label} signature is invalid`);
  return publicKey;
};

const validateCodeIdentities = (value, teamId) => {
  if (!Array.isArray(value) || value.length !== REQUIRED_CODE_IDENTITIES.length) throw new Error('release attestation code identities are incomplete');
  const result = [];
  for (const [index, item] of value.entries()) {
    exactKeys(item, ['path', 'bundle_id', 'team_id', 'code_directory_hash'], 'release attestation code identity');
    const expected = REQUIRED_CODE_IDENTITIES[index];
    if (item.path !== expected.path || item.bundle_id !== expected.bundle_id || item.team_id !== teamId || !CODE_HASH.test(item.code_directory_hash)) {
      throw new Error('release attestation code identities are substituted or out of order');
    }
    result.push({ ...item });
  }
  return result;
};

const validateReleaseAttestation = (value) => {
  exactKeys(value, [
    'schema_version', 'team_id', 'nested_code_identities', 'cloud_image_digest',
    'dependency_lock_sha256', 'database_migration_manifest_sha256', 'signer_key_versions'
  ], 'release attestation');
  if (value.schema_version !== 1 || !TEAM_ID.test(value.team_id)) throw new Error('release attestation identity is invalid');
  if (!CLOUD_DIGEST.test(value.cloud_image_digest) || value.cloud_image_digest === `sha256:${ZERO_64}`) throw new Error('release attestation Cloud image digest is invalid');
  validNonzeroDigest(value.dependency_lock_sha256, 'release attestation dependency lock digest');
  validNonzeroDigest(value.database_migration_manifest_sha256, 'release attestation migration digest');
  return {
    schema_version: 1,
    team_id: value.team_id,
    nested_code_identities: validateCodeIdentities(value.nested_code_identities, value.team_id),
    cloud_image_digest: value.cloud_image_digest,
    dependency_lock_sha256: value.dependency_lock_sha256,
    database_migration_manifest_sha256: value.database_migration_manifest_sha256,
    signer_key_versions: validateVersionList(value.signer_key_versions, 'release attestation signer key versions')
  };
};

const validateNotarization = (value, manifestDirectory, occupiedNames, label = 'release') => {
  exactKeys(value, ['status', 'submission_ids', 'evidence'], `${label} notarization`);
  if (value.status !== 'accepted_stapled' || !Array.isArray(value.submission_ids) || value.submission_ids.length === 0) {
    throw new Error(`${label} must have accepted stapled notarization`);
  }
  const submissionIDs = [];
  let previousSubmission = '';
  for (const id of value.submission_ids) {
    if (!UUID.test(id) || lexicalCompare(id, previousSubmission) <= 0) throw new Error(`${label} notarization submission IDs are invalid or unsorted`);
    submissionIDs.push(id);
    previousSubmission = id;
  }
  if (!Array.isArray(value.evidence) || value.evidence.length !== 2) throw new Error(`${label} notarization evidence is incomplete`);
  const evidence = [];
  const kinds = new Set();
  let previousName = '';
  const contentByKind = new Map();
  for (const item of value.evidence) {
    exactKeys(item, ['kind', 'name', 'bytes', 'sha256'], `${label} notarization evidence`);
    if (!['notarytool_result', 'stapler_result'].includes(item.kind) || kinds.has(item.kind)
      || !SAFE_NAME.test(item.name) || occupiedNames.has(item.name) || lexicalCompare(item.name, previousName) <= 0
      || !Number.isSafeInteger(item.bytes) || item.bytes <= 0 || !DIGEST.test(item.sha256)) {
      throw new Error(`${label} notarization evidence metadata is invalid`);
    }
    const snapshot = readStableFile(join(manifestDirectory, item.name), { maximum: MAX_EVIDENCE_BYTES, label: `${label} notarization evidence` });
    if (snapshot.bytes !== item.bytes || snapshot.sha256 !== item.sha256) throw new Error(`${label} notarization evidence digest mismatch`);
    occupiedNames.add(item.name);
    kinds.add(item.kind);
    previousName = item.name;
    contentByKind.set(item.kind, snapshot.content);
    evidence.push({ kind: item.kind, name: item.name, bytes: item.bytes, sha256: item.sha256 });
  }
  if (!kinds.has('notarytool_result') || !kinds.has('stapler_result')) throw new Error(`${label} notarization evidence kinds are incomplete`);
  let notaryResult;
  try { notaryResult = JSON.parse(decodeUTF8(contentByKind.get('notarytool_result'), 'notarytool evidence')); }
  catch (error) {
    if (error instanceof SyntaxError) throw new Error(`${label} notarytool evidence is not valid JSON`);
    throw error;
  }
  if (notaryResult?.status !== 'Accepted' || typeof notaryResult.id !== 'string' || !submissionIDs.includes(notaryResult.id.toLowerCase())) {
    throw new Error(`${label} notarytool evidence does not match an accepted submission`);
  }
  if (!/The validate action worked!/iu.test(decodeUTF8(contentByKind.get('stapler_result'), 'stapler evidence'))) {
    throw new Error(`${label} stapler evidence does not prove successful validation`);
  }
  return { status: 'accepted_stapled', submission_ids: submissionIDs, evidence };
};

const validateSBOM = (value, manifest, sbomBytes) => {
  exactKeys(value, [
    'artifact_name', 'sha256', 'spdx_version', 'document_namespace', 'document_spdx_id',
    'document_describes', 'source_commit', 'source_tree'
  ], 'release SBOM binding');
  const sbomArtifacts = manifest.artifacts.filter((item) => item.role === 'sbom');
  if (sbomArtifacts.length !== 1 || value.artifact_name !== sbomArtifacts[0].name || value.sha256 !== sbomArtifacts[0].sha256
    || value.spdx_version !== 'SPDX-2.3' || value.document_spdx_id !== 'SPDXRef-DOCUMENT'
    || value.source_commit !== manifest.source.commit || value.source_tree !== manifest.source.tree
    || !Array.isArray(value.document_describes) || value.document_describes.length !== 1 || value.document_describes[0] !== 'SPDXRef-AgentPass') {
    throw new Error('release SBOM binding is invalid');
  }
  let sbom;
  try { sbom = JSON.parse(decodeUTF8(sbomBytes, 'release SBOM')); }
  catch (error) {
    if (error instanceof SyntaxError) throw new Error('release SBOM is not valid JSON');
    throw error;
  }
  if (sbom.spdxVersion !== value.spdx_version || sbom.SPDXID !== value.document_spdx_id
    || sbom.documentNamespace !== value.document_namespace || JSON.stringify(sbom.documentDescribes) !== JSON.stringify(value.document_describes)) {
    throw new Error('release SBOM document identity mismatch');
  }
  const pkg = Array.isArray(sbom.packages) ? sbom.packages.find((item) => item?.SPDXID === 'SPDXRef-AgentPass') : undefined;
  if (!pkg || pkg.versionInfo !== manifest.version || typeof pkg.sourceInfo !== 'string'
    || !pkg.sourceInfo.includes(manifest.source.commit) || !pkg.sourceInfo.includes(manifest.source.tree)) throw new Error('release SBOM source identity mismatch');
  let creation;
  try { creation = JSON.parse(sbom.creationInfo?.comment); } catch { throw new Error('release SBOM creation metadata is invalid'); }
  if (creation.source_commit !== manifest.source.commit || creation.source_tree !== manifest.source.tree
    || !Number.isSafeInteger(creation.swift_input_count) || creation.swift_input_count < 1
    || typeof creation.swift !== 'string' || typeof creation.macos_sdk !== 'string') throw new Error('release SBOM build metadata mismatch');
};

const validateManifestAndBindings = ({ manifestSnapshot, signaturePath, publicKeyPath, fingerprint, artifactPath }) => {
  const manifest = parseCanonicalJSON(manifestSnapshot, 'release manifest');
  verifyDetachedSignature(manifestSnapshot.content, signaturePath, publicKeyPath, fingerprint, 'release manifest');
  exactKeys(manifest, ['schema_version', 'product', 'version', 'source', 'generated_at', 'artifacts', 'external_qualification_controller', 'evidence'], 'release manifest');
  if (manifest.schema_version !== 3 || manifest.product !== 'AgentPass' || !VERSION_STRING.test(manifest.version) || !CANONICAL_DATE(manifest.generated_at)) throw new Error('release manifest identity is invalid');
  exactKeys(manifest.source, ['commit', 'tree', 'tag'], 'release manifest source');
  if (!COMMIT.test(manifest.source.commit) || manifest.source.commit === ZERO_40 || !COMMIT.test(manifest.source.tree) || manifest.source.tree === ZERO_40
    || (manifest.source.tag !== null && manifest.source.tag !== `v${manifest.version}`)) throw new Error('release manifest source identity is invalid');
  if (!Array.isArray(manifest.artifacts) || manifest.artifacts.length === 0) throw new Error('release manifest has no artifacts');
  const directory = dirname(manifestSnapshot.path);
  const names = new Set();
  const contents = new Map();
  const artifacts = [];
  let previousName = '';
  for (const item of manifest.artifacts) {
    exactKeys(item, ['name', 'role', 'media_type', 'bytes', 'sha256'], 'release artifact');
    if (!SAFE_NAME.test(item.name) || names.has(item.name) || lexicalCompare(item.name, previousName) <= 0
      || !ROLES.has(item.role) || !MEDIA_TYPES.has(item.media_type) || !Number.isSafeInteger(item.bytes) || item.bytes <= 0 || !DIGEST.test(item.sha256)
      || ((item.role === 'sbom') !== (item.media_type === 'application/spdx+json'))) throw new Error('release artifact metadata is invalid');
    const maximum = item.role === 'sbom' ? MAX_SBOM_BYTES : item.name === 'release-attestation.json' ? MAX_ATTESTATION_BYTES : MAX_ARTIFACT_BYTES;
    const snapshot = readStableFile(join(directory, item.name), { maximum, label: 'release artifact', capture: item.role === 'sbom' || item.name === 'release-attestation.json' });
    if (snapshot.bytes !== item.bytes || snapshot.sha256 !== item.sha256) throw new Error('release artifact digest mismatch');
    names.add(item.name);
    previousName = item.name;
    if (snapshot.content) contents.set(item.name, snapshot.content);
    artifacts.push({ name: item.name, role: item.role, media_type: item.media_type, bytes: item.bytes, sha256: item.sha256 });
  }
  const products = artifacts.filter((item) => item.role === 'product');
  const expectedProductName = `AgentPass-v${manifest.version}-macos-universal.pkg`;
  if (products.length !== 1 || products[0].name !== expectedProductName || products[0].media_type !== 'application/vnd.apple.installer+xml') throw new Error('release manifest must contain exactly one canonical macOS product artifact');
  const product = products[0];
  const artifact = readStableFile(artifactPath, { maximum: MAX_ARTIFACT_BYTES, label: 'product artifact', capture: false });
  if (artifact.name !== product.name || artifact.bytes !== product.bytes || artifact.sha256 !== product.sha256) throw new Error('product artifact does not match the signed release manifest');
  const attestationArtifact = artifacts.filter((item) => item.name === 'release-attestation.json' && item.role === 'auxiliary' && item.media_type === 'application/json');
  if (attestationArtifact.length !== 1 || !contents.has('release-attestation.json')) throw new Error('signed release manifest is missing release-attestation.json');
  const attestation = validateReleaseAttestation(parseCanonicalJSON({ content: contents.get('release-attestation.json') }, 'release attestation'));
  const migrationArtifacts = artifacts.filter((item) => item.name.endsWith('.database-migration-manifest.json') || item.name === 'database-migration-manifest.json');
  if (migrationArtifacts.length !== 1 || migrationArtifacts[0].role !== 'auxiliary' || migrationArtifacts[0].media_type !== 'application/json'
    || migrationArtifacts[0].sha256 !== attestation.database_migration_manifest_sha256) {
    throw new Error('signed migration manifest does not match the release attestation');
  }
  const controllerArtifacts = artifacts.filter((item) => item.role === 'external_qualification_controller');
  if (controllerArtifacts.length !== 1 || controllerArtifacts[0].media_type !== 'application/octet-stream'
    || !CONTROLLER_ARCHIVE_NAME_PATTERN.test(controllerArtifacts[0].name)
    || controllerArtifacts[0].name !== `AgentPassQualificationController-${manifest.version}-macos-universal.tar`) {
    throw new Error('release manifest must contain exactly one version-bound external qualification controller archive');
  }
  const controllerArtifact = controllerArtifacts[0];
  exactKeys(manifest.external_qualification_controller, ['identity_document', 'identity', 'notarization'], 'external qualification controller');
  const controllerBinding = manifest.external_qualification_controller.identity_document;
  exactKeys(controllerBinding, ['name', 'bytes', 'sha256'], 'controller identity document');
  if (!SAFE_NAME.test(controllerBinding.name) || names.has(controllerBinding.name)
    || !Number.isSafeInteger(controllerBinding.bytes) || controllerBinding.bytes <= 0 || controllerBinding.bytes > 1024 * 1024
    || !DIGEST.test(controllerBinding.sha256)) throw new Error('controller identity document binding is invalid');
  const identitySnapshot = readStableFile(join(directory, controllerBinding.name), {
    maximum: 1024 * 1024,
    label: 'controller identity document'
  });
  if (identitySnapshot.bytes !== controllerBinding.bytes || identitySnapshot.sha256 !== controllerBinding.sha256) throw new Error('controller identity document digest mismatch');
  let documentIdentity;
  try { documentIdentity = parseCanonicalExternalQualificationControllerIdentity(identitySnapshot.content); }
  catch (error) { throw new Error(`controller identity document is invalid: ${error.message}`); }
  let embeddedIdentity;
  try { embeddedIdentity = validateExternalQualificationControllerIdentity(manifest.external_qualification_controller.identity); }
  catch (error) { throw new Error(`embedded controller identity is invalid: ${error.message}`); }
  if (JSON.stringify(documentIdentity) !== JSON.stringify(embeddedIdentity)) throw new Error('embedded controller identity differs from its bound document');
  if (documentIdentity.archive_name !== controllerArtifact.name
    || documentIdentity.archive_sha256 !== controllerArtifact.sha256
    || documentIdentity.archive_bytes !== controllerArtifact.bytes) throw new Error('controller identity does not bind the exact external archive');
  if (documentIdentity.team_id !== attestation.team_id) throw new Error('controller identity Team ID does not match the release attestation');
  names.add(controllerBinding.name);
  const controllerNotarization = validateNotarization(manifest.external_qualification_controller.notarization, directory, names, 'controller');
  exactKeys(manifest.evidence, ['checksums', 'sbom', 'notarization'], 'release manifest evidence');
  const notarization = validateNotarization(manifest.evidence.notarization, directory, names);
  const checksums = manifest.evidence.checksums;
  exactKeys(checksums, ['name', 'bytes', 'sha256', 'entry_count'], 'release checksums evidence');
  if (!SAFE_NAME.test(checksums.name) || names.has(checksums.name) || !Number.isSafeInteger(checksums.bytes) || checksums.bytes <= 0
    || !DIGEST.test(checksums.sha256) || checksums.entry_count !== artifacts.length + notarization.evidence.length + 1 + controllerNotarization.evidence.length) throw new Error('release checksums evidence is invalid');
  const checksumSnapshot = readStableFile(join(directory, checksums.name), { maximum: 16 * 1024 * 1024, label: 'release checksums' });
  const checksumEntries = [
    ...artifacts,
    ...notarization.evidence,
    { name: controllerBinding.name, bytes: controllerBinding.bytes, sha256: controllerBinding.sha256 },
    ...controllerNotarization.evidence
  ].sort((left, right) => lexicalCompare(left.name, right.name));
  const expectedChecksums = Buffer.from(`${checksumEntries.map((item) => `${item.sha256}  ${item.name}`).join('\n')}\n`, 'utf8');
  if (checksumSnapshot.bytes !== checksums.bytes || checksumSnapshot.sha256 !== checksums.sha256 || !checksumSnapshot.content.equals(expectedChecksums)) throw new Error('release checksums content mismatch');
  const sbomArtifact = artifacts.find((item) => item.role === 'sbom');
  if (!sbomArtifact || !contents.has(sbomArtifact.name)) throw new Error('release manifest must contain an SPDX SBOM');
  validateSBOM(manifest.evidence.sbom, manifest, contents.get(sbomArtifact.name));
  return { manifest, manifestDirectory: directory, manifestSha256: manifestSnapshot.sha256, product, attestation, notarization };
};

const validateInputs = ({ operator, operatorKeyFingerprint, browserVersions }) => {
  if (!OPERATOR.test(operator)) throw new Error('operator is invalid');
  validateFingerprint(operatorKeyFingerprint, 'operator key fingerprint');
  return { operator, operator_key_fingerprint: operatorKeyFingerprint, browser_versions: validateVersionList(browserVersions, 'browser versions') };
};

const buildTemplate = ({ release, operator, operatorKeyFingerprint, browserVersions }) => {
  const external = validateInputs({ operator, operatorKeyFingerprint, browserVersions });
  const template = {
    schema_version: 2,
    source_commit: release.manifest.source.commit,
    dependency_lock_sha256: release.attestation.dependency_lock_sha256,
    release_manifest_sha256: release.manifestSha256,
    artifact_name: release.product.name,
    artifact_sha256: release.product.sha256,
    architecture: 'arm64',
    hardware_class: 'apple_silicon',
    model_identifier: 'Template',
    macos_version: '0.0',
    macos_build: 'TEMPLATE',
    secure_enclave: true,
    team_id: release.attestation.team_id,
    nested_code_identities: release.attestation.nested_code_identities,
    notarization: release.notarization,
    cloud_image_digest: release.attestation.cloud_image_digest,
    database_migration_manifest_sha256: release.attestation.database_migration_manifest_sha256,
    signer_key_versions: release.attestation.signer_key_versions,
    browser_versions: external.browser_versions,
    started_at: '1970-01-01T00:00:00.000Z',
    completed_at: '1970-01-01T00:00:00.000Z',
    operator: external.operator,
    operator_key_fingerprint: external.operator_key_fingerprint,
    qualified: false,
    tests: [{ name: 'template', status: 'skipped', reason: 'template only; physical qualification is required', evidence: [] }],
    gates: [{ name: 'template', status: 'skipped', reason: 'template only; physical qualification is required', evidence: [] }]
  };
  exactKeys(template, REPORT_KEYS, 'hardware qualification template');
  if (template.qualified !== false || template.tests.some((item) => item.status === 'passed') || template.gates.some((item) => item.status === 'passed')) throw new Error('generator cannot self-qualify');
  return template;
};

export const generateHardwareQualificationTemplate = ({
  releaseManifestPath,
  releaseSignaturePath,
  releasePublicKeyPath,
  releaseFingerprint,
  artifactPath,
  operator,
  operatorKeyFingerprint,
  browserVersions
} = {}) => {
  const manifestSnapshot = readStableFile(releaseManifestPath, { maximum: MAX_MANIFEST_BYTES, label: 'release manifest' });
  const release = validateManifestAndBindings({ manifestSnapshot, signaturePath: releaseSignaturePath, publicKeyPath: releasePublicKeyPath, fingerprint: releaseFingerprint, artifactPath });
  return buildTemplate({ release, operator, operatorKeyFingerprint, browserVersions });
};

export const readPinnedBrowserVersions = (browserVersionsPath) => {
  const snapshot = readStableFile(browserVersionsPath, { maximum: MAX_BROWSER_INPUT_BYTES, label: 'browser versions input' });
  return validateVersionList(parseCanonicalJSON(snapshot, 'browser versions input'), 'browser versions');
};

const fsyncDirectory = (directory) => {
  const descriptor = fs.openSync(directory, fs.constants.O_RDONLY | (fs.constants.O_DIRECTORY || 0) | fs.constants.O_NOFOLLOW);
  try { fs.fsyncSync(descriptor); } finally { fs.closeSync(descriptor); }
};

export const writeCanonicalExclusive = (outputPath, value) => {
  assertNoFollowSupport();
  const requestedDestination = safeAbsolutePath(outputPath, 'output');
  const requestedDirectory = dirname(requestedDestination);
  let directory;
  try {
    directory = fs.realpathSync.native(requestedDirectory);
    const directoryStat = fs.lstatSync(directory);
    if (!directoryStat.isDirectory()) throw new Error('output directory is not a directory');
  } catch (error) {
    if (error?.message === 'output directory is not a directory') throw error;
    throw new Error('output directory is unavailable');
  }
  const destination = join(directory, basename(requestedDestination));
  const name = basename(destination);
  if (!SAFE_NAME.test(name)) throw new Error('output filename is unsafe');
  let existing;
  try { existing = fs.lstatSync(destination); } catch (error) { if (error?.code !== 'ENOENT') throw new Error('output path is unavailable'); }
  if (existing) throw new Error('output already exists; refusing overwrite');
  const bytes = canonicalJSON(value);
  let temporary;
  let descriptor;
  try {
    for (let attempt = 0; attempt < 8; attempt += 1) {
      temporary = join(directory, `.${name}.${process.pid}.${randomBytes(12).toString('hex')}.tmp`);
      try {
        descriptor = fs.openSync(temporary, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o644);
        break;
      } catch (error) {
        if (error?.code !== 'EEXIST' || attempt === 7) throw error;
      }
    }
    let offset = 0;
    while (offset < bytes.length) offset += fs.writeSync(descriptor, bytes, offset, bytes.length - offset);
    fs.fsyncSync(descriptor);
    fs.closeSync(descriptor);
    descriptor = undefined;
    fs.linkSync(temporary, destination);
    fs.unlinkSync(temporary);
    temporary = undefined;
    fsyncDirectory(directory);
  } catch (error) {
    if (descriptor !== undefined) { try { fs.closeSync(descriptor); } catch {} }
    if (temporary) { try { fs.unlinkSync(temporary); } catch {} }
    throw error;
  }
  return { path: destination, bytes: bytes.length, sha256: sha256(bytes) };
};

const usage = 'Usage: generate-hardware-qualification-template.mjs --release-manifest FILE --release-signature FILE --release-public-key FILE --release-fingerprint SHA256:... --artifact PKG --operator ID --operator-key-fingerprint SHA256:... --browser-versions FILE --output FILE';

export const parseArguments = (args) => {
  const allowed = new Set([
    '--release-manifest', '--release-signature', '--release-public-key', '--release-fingerprint',
    '--artifact', '--operator', '--operator-key-fingerprint', '--browser-versions', '--output'
  ]);
  if (args.length % 2 !== 0) throw new Error(usage);
  const values = new Map();
  for (let index = 0; index < args.length; index += 2) {
    const key = args[index];
    const value = args[index + 1];
    if (!allowed.has(key) || typeof value !== 'string' || value.length === 0 || value.startsWith('--') || values.has(key)) throw new Error(usage);
    values.set(key, value);
  }
  if (values.size !== allowed.size) throw new Error(usage);
  return values;
};

if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
  try {
    const values = parseArguments(process.argv.slice(2));
    const template = generateHardwareQualificationTemplate({
      releaseManifestPath: values.get('--release-manifest'),
      releaseSignaturePath: values.get('--release-signature'),
      releasePublicKeyPath: values.get('--release-public-key'),
      releaseFingerprint: values.get('--release-fingerprint'),
      artifactPath: values.get('--artifact'),
      operator: values.get('--operator'),
      operatorKeyFingerprint: values.get('--operator-key-fingerprint'),
      browserVersions: readPinnedBrowserVersions(values.get('--browser-versions'))
    });
    const result = writeCanonicalExclusive(values.get('--output'), template);
    process.stdout.write(`${JSON.stringify({ ok: true, qualified: false, output: result.path, bytes: result.bytes, sha256: result.sha256 })}\n`);
  } catch (error) {
    process.stderr.write(`hardware qualification template refused: ${error instanceof Error ? error.message : 'invalid input'}\n`);
    process.exitCode = 1;
  }
}
