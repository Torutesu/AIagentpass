#!/usr/bin/env node
import crypto from 'node:crypto';
import fs from 'node:fs';
import { spawnSync } from 'node:child_process';
import { basename, dirname, isAbsolute, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildReleaseAttestation, canonicalJSON as canonicalReleaseAttestation } from '../generate-release-attestation.mjs';
import {
  parseCanonicalExternalQualificationControllerIdentity,
  validateExternalQualificationControllerIdentity
} from './controller-identity-contract.mjs';

export const SERVICE_CONFIG_PATH = '/Library/Application Support/AgentPass/native-service.json';
export const PROVISION_STATE_PATH = '/Library/Application Support/AgentPass/n3e-qualification-provision.json';
export const QUALIFICATION_MODE = 'n3e-qualification';
export const QUALIFICATION_MACH_SERVICE = 'dev.agentpass.n3e-qualification';
export const MAX_LIFETIME_SECONDS = 15 * 60;

export const QUALIFICATION_FIELDS = Object.freeze([
  'qualification_mode',
  'qualification_mach_service_name',
  'qualification_candidate_sha256',
  'qualification_source_commit_sha256',
  'qualification_code_identities_sha256',
  'qualification_controller_cdhash',
  'qualification_run_id_sha256',
  'qualification_expires_at_epoch_seconds',
  'qualification_scenario',
  'qualification_phase'
]);

export const SCENARIO_PHASE = Object.freeze({
  'pre-cloud-kill': 'pre-cloud',
  'post-cloud-pre-local-kill': 'post-cloud-pre-local',
  'post-activation-pre-audit-kill': 'post-activation-pre-audit',
  'post-audit-pre-reply-loss': 'post-audit-pre-reply',
  'audit-fsync-failure': 'audit-fsync',
  'transport-reply-loss': 'transport-reply'
});

const MAX_CONFIG_BYTES = 1024 * 1024;
const MAX_MANIFEST_BYTES = 16 * 1024 * 1024;
const MAX_ATTESTATION_BYTES = 4 * 1024 * 1024;
const MAX_IDENTITY_BYTES = 1024 * 1024;
const MAX_ARTIFACT_BYTES = 16 * 1024 * 1024 * 1024;
const MAX_STATE_BYTES = 2 * 1024 * 1024;
const DIGEST = /^[0-9a-f]{64}$/u;
const COMMIT = /^[0-9a-f]{40}$/u;
const CDHASH = /^[0-9a-f]{40}$/u;
const FINGERPRINT = /^SHA256:[A-Za-z0-9_-]{43}$/u;
const RUN_BINDING = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;
const SAFE_NAME = /^[0-9A-Za-z][0-9A-Za-z._-]*$/u;
const VERSION = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/u;
const ZERO_64 = '0'.repeat(64);
const ZERO_40 = '0'.repeat(40);
const NOFOLLOW = fs.constants.O_NOFOLLOW;
const O_DIRECTORY = fs.constants.O_DIRECTORY ?? 0;
const STATE_KEYS = Object.freeze([
  'schema_version', 'kind', 'config_path', 'architecture', 'original_config_base64',
  'original_config_sha256', 'qualified_config_sha256', 'release_manifest_sha256',
  'candidate_sha256', 'source_commit_sha256', 'code_identities_sha256',
  'controller_cdhash', 'run_id_sha256', 'expires_at_epoch_seconds', 'scenario', 'phase'
]);

const fail = (message) => { throw new Error(message); };
const sha256 = (bytes) => crypto.createHash('sha256').update(bytes).digest('hex');
const exactKeys = (value, keys, label) => {
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail(`${label} must be an object`);
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) fail(`${label} has missing or unknown fields`);
};
const validDigest = (value) => typeof value === 'string' && DIGEST.test(value) && value !== ZERO_64;
const validCDHash = (value) => typeof value === 'string' && CDHASH.test(value) && value !== ZERO_40;
const identityOf = (stat) => [stat.dev, stat.ino, stat.mode, stat.nlink, stat.size, stat.mtimeNs, stat.ctimeNs, stat.uid, stat.gid].map(String).join(':');

const strictJSON = (bytes, label, maximumDepth = 24) => {
  let source;
  try { source = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes); }
  catch { fail(`${label} is not valid UTF-8 JSON`); }
  if (source.startsWith('\uFEFF')) fail(`${label} contains a UTF-8 BOM`);
  const cursor = { index: 0 };
  const whitespace = () => { while (cursor.index < source.length && /[\x20\x09\x0a\x0d]/u.test(source[cursor.index])) cursor.index += 1; };
  const string = () => {
    const start = cursor.index;
    if (source[cursor.index] !== '"') fail(`${label} contains malformed JSON`);
    cursor.index += 1;
    while (cursor.index < source.length) {
      const code = source.charCodeAt(cursor.index);
      if (code < 0x20) fail(`${label} contains malformed JSON`);
      if (source[cursor.index] === '\\') { cursor.index += 2; continue; }
      if (source[cursor.index] === '"') {
        cursor.index += 1;
        try { return JSON.parse(source.slice(start, cursor.index)); } catch { fail(`${label} contains malformed JSON`); }
      }
      cursor.index += 1;
    }
    fail(`${label} contains malformed JSON`);
  };
  const value = (depth) => {
    if (depth > maximumDepth) fail(`${label} nesting is too deep`);
    whitespace();
    const character = source[cursor.index];
    if (character === '"') return string();
    if (character === '{') {
      cursor.index += 1;
      const output = Object.create(null);
      const keys = new Set();
      whitespace();
      if (source[cursor.index] === '}') { cursor.index += 1; return output; }
      while (true) {
        whitespace();
        const key = string();
        if (keys.has(key)) fail(`${label} contains duplicate JSON fields`);
        keys.add(key);
        whitespace();
        if (source[cursor.index] !== ':') fail(`${label} contains malformed JSON`);
        cursor.index += 1;
        output[key] = value(depth + 1);
        whitespace();
        if (source[cursor.index] === '}') { cursor.index += 1; return output; }
        if (source[cursor.index] !== ',') fail(`${label} contains malformed JSON`);
        cursor.index += 1;
      }
    }
    if (character === '[') {
      cursor.index += 1;
      const output = [];
      whitespace();
      if (source[cursor.index] === ']') { cursor.index += 1; return output; }
      while (true) {
        output.push(value(depth + 1));
        whitespace();
        if (source[cursor.index] === ']') { cursor.index += 1; return output; }
        if (source[cursor.index] !== ',') fail(`${label} contains malformed JSON`);
        cursor.index += 1;
      }
    }
    const start = cursor.index;
    while (cursor.index < source.length && !/[\x20\x09\x0a\x0d,\]}]/u.test(source[cursor.index])) cursor.index += 1;
    if (cursor.index === start) fail(`${label} contains malformed JSON`);
    try { return JSON.parse(source.slice(start, cursor.index)); } catch { fail(`${label} contains malformed JSON`); }
  };
  const parsed = value(0);
  whitespace();
  if (cursor.index !== source.length || !parsed || typeof parsed !== 'object' || Array.isArray(parsed)) fail(`${label} must be one JSON object`);
  return parsed;
};

const canonicalObject = (value) => {
  const normalize = (item) => {
    if (Array.isArray(item)) return item.map(normalize);
    if (item && typeof item === 'object') return Object.fromEntries(Object.keys(item).sort().map((key) => [key, normalize(item[key])]));
    return item;
  };
  return Buffer.from(`${JSON.stringify(normalize(value), null, 2)}\n`, 'utf8');
};

const absolutePath = (value, label) => {
  if (typeof value !== 'string' || value.includes('\0') || !isAbsolute(value) || resolve(value) !== value) fail(`${label} path must be absolute and normalized`);
  return value;
};

const verifyProtectedParent = (file, expectedUid) => {
  const parent = dirname(file);
  const stat = fs.lstatSync(parent, { bigint: true });
  if (!stat.isDirectory() || stat.isSymbolicLink() || (stat.mode & 0o022n) !== 0n || stat.uid !== BigInt(expectedUid)) fail('service configuration parent is unsafe');
};

const readStable = (input, { label, maximum, expectedUid = null, exactMode = null, writableDenied = true, capture = true } = {}) => {
  if (!Number.isInteger(NOFOLLOW)) fail('O_NOFOLLOW is unavailable');
  const file = absolutePath(input, label);
  let descriptor;
  try { descriptor = fs.openSync(file, fs.constants.O_RDONLY | NOFOLLOW); }
  catch { fail(`${label} is unavailable`); }
  try {
    const before = fs.fstatSync(descriptor, { bigint: true });
    if (!before.isFile() || before.nlink !== 1n || before.size <= 0n || before.size > BigInt(maximum) || before.size > BigInt(Number.MAX_SAFE_INTEGER)) fail(`${label} is unsafe`);
    if (expectedUid !== null && before.uid !== BigInt(expectedUid)) fail(`${label} has an unsafe owner`);
    if (exactMode !== null && (before.mode & 0o7777n) !== BigInt(exactMode)) fail(`${label} has an unsafe mode`);
    if (writableDenied && (before.mode & 0o022n) !== 0n) fail(`${label} is group or world writable`);
    const size = Number(before.size);
    const chunks = capture ? [] : null;
    const hash = crypto.createHash('sha256');
    const buffer = Buffer.allocUnsafe(Math.min(1024 * 1024, size));
    let offset = 0;
    while (offset < size) {
      const count = fs.readSync(descriptor, buffer, 0, Math.min(buffer.length, size - offset), offset);
      if (count <= 0) fail(`${label} changed while reading`);
      const chunk = buffer.subarray(0, count);
      hash.update(chunk);
      if (chunks) chunks.push(Buffer.from(chunk));
      offset += count;
    }
    const after = fs.fstatSync(descriptor, { bigint: true });
    let pathStat;
    try { pathStat = fs.lstatSync(file, { bigint: true }); } catch { fail(`${label} changed while reading`); }
    if (identityOf(before) !== identityOf(after) || identityOf(after) !== identityOf(pathStat)) fail(`${label} changed while reading`);
    return Object.freeze({ path: file, bytes: chunks ? Buffer.concat(chunks, size) : undefined, size, sha256: hash.digest('hex'), stat: after });
  } finally { fs.closeSync(descriptor); }
};

const fsyncDirectory = (directory) => {
  const descriptor = fs.openSync(directory, fs.constants.O_RDONLY | O_DIRECTORY | NOFOLLOW);
  try { fs.fsyncSync(descriptor); } finally { fs.closeSync(descriptor); }
};

const writeExclusive = (destination, bytes, expectedUid) => {
  verifyProtectedParent(destination, expectedUid);
  let temporary;
  let descriptor;
  try {
    for (let attempt = 0; attempt < 8; attempt += 1) {
      temporary = join(dirname(destination), `.${basename(destination)}.${process.pid}.${crypto.randomBytes(12).toString('hex')}.tmp`);
      try { descriptor = fs.openSync(temporary, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | NOFOLLOW, 0o600); break; }
      catch (error) { if (error?.code !== 'EEXIST' || attempt === 7) throw error; }
    }
    fs.writeFileSync(descriptor, bytes);
    fs.fsyncSync(descriptor);
    const stat = fs.fstatSync(descriptor, { bigint: true });
    if (!stat.isFile() || stat.nlink !== 1n || stat.uid !== BigInt(expectedUid) || (stat.mode & 0o7777n) !== 0o600n || stat.size !== BigInt(bytes.length)) fail('staged qualification state is unsafe');
    fs.closeSync(descriptor); descriptor = undefined;
    fs.linkSync(temporary, destination);
    fs.unlinkSync(temporary); temporary = undefined;
    fsyncDirectory(dirname(destination));
  } finally {
    if (descriptor !== undefined) { try { fs.closeSync(descriptor); } catch {} }
    if (temporary) { try { fs.unlinkSync(temporary); } catch {} }
  }
};

const replaceAtomic = (destination, bytes, expectedIdentity, expectedUid) => {
  verifyProtectedParent(destination, expectedUid);
  let temporary;
  let descriptor;
  try {
    temporary = join(dirname(destination), `.${basename(destination)}.${process.pid}.${crypto.randomBytes(12).toString('hex')}.replace`);
    descriptor = fs.openSync(temporary, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | NOFOLLOW, 0o600);
    fs.writeFileSync(descriptor, bytes);
    fs.fsyncSync(descriptor);
    const staged = fs.fstatSync(descriptor, { bigint: true });
    if (!staged.isFile() || staged.nlink !== 1n || staged.uid !== BigInt(expectedUid) || (staged.mode & 0o7777n) !== 0o600n || staged.size !== BigInt(bytes.length)) fail('staged service configuration is unsafe');
    fs.closeSync(descriptor); descriptor = undefined;
    const current = fs.lstatSync(destination, { bigint: true });
    if (identityOf(current) !== expectedIdentity) fail('service configuration changed before publication');
    fs.renameSync(temporary, destination); temporary = undefined;
    fsyncDirectory(dirname(destination));
    const installed = readStable(destination, { label: 'installed service configuration', maximum: MAX_CONFIG_BYTES, expectedUid, exactMode: 0o600 });
    if (!installed.bytes.equals(bytes)) fail('installed service configuration verification failed');
    return installed;
  } finally {
    if (descriptor !== undefined) { try { fs.closeSync(descriptor); } catch {} }
    if (temporary) { try { fs.unlinkSync(temporary); } catch {} }
  }
};

const verifyReleaseSignature = (manifest, signaturePath, publicKeyPath, expectedFingerprint) => {
  if (!FINGERPRINT.test(expectedFingerprint)) fail('release key fingerprint is invalid');
  const publicKeySnapshot = readStable(publicKeyPath, { label: 'release public key', maximum: 16 * 1024 });
  let publicKey;
  try { publicKey = crypto.createPublicKey(publicKeySnapshot.bytes); } catch { fail('release public key is invalid'); }
  if (publicKey.asymmetricKeyType !== 'ed25519') fail('release public key must be Ed25519');
  const actualFingerprint = `SHA256:${crypto.createHash('sha256').update(publicKey.export({ type: 'spki', format: 'der' })).digest('base64url')}`;
  if (actualFingerprint !== expectedFingerprint) fail('release public key fingerprint mismatch');
  const signatureSnapshot = readStable(signaturePath, { label: 'release manifest signature', maximum: 1024 });
  const encoded = signatureSnapshot.bytes.toString('utf8');
  if (!/^(?:[A-Za-z0-9+/]{4}){21}[A-Za-z0-9+/]{2}==\n$/u.test(encoded)) fail('release manifest signature encoding is invalid');
  const signature = Buffer.from(encoded.trim(), 'base64');
  if (signature.length !== 64 || !crypto.verify(null, manifest.bytes, publicKey, signature)) fail('release manifest signature is invalid');
};

const validateRelease = ({ manifestPath, signaturePath, publicKeyPath, expectedFingerprint, productPath }) => {
  const manifestSnapshot = readStable(manifestPath, { label: 'release manifest', maximum: MAX_MANIFEST_BYTES });
  const manifest = strictJSON(manifestSnapshot.bytes, 'release manifest');
  if (!manifestSnapshot.bytes.equals(Buffer.from(`${JSON.stringify(manifest, null, 2)}\n`, 'utf8'))) fail('release manifest is not canonical JSON');
  verifyReleaseSignature(manifestSnapshot, signaturePath, publicKeyPath, expectedFingerprint);
  exactKeys(manifest, ['schema_version', 'product', 'version', 'source', 'generated_at', 'artifacts', 'external_qualification_controller', 'evidence'], 'release manifest');
  if (manifest.schema_version !== 3 || manifest.product !== 'AgentPass' || !VERSION.test(manifest.version)) fail('release manifest identity is invalid');
  exactKeys(manifest.source, ['commit', 'tree', 'tag'], 'release source');
  if (!COMMIT.test(manifest.source.commit) || manifest.source.commit === ZERO_40 || !COMMIT.test(manifest.source.tree) || manifest.source.tree === ZERO_40) fail('release source identity is invalid');
  if (manifest.source.tag !== null && manifest.source.tag !== `v${manifest.version}`) fail('release source tag is invalid');
  if (!Array.isArray(manifest.artifacts)) fail('release artifacts are invalid');
  const artifactNames = new Set();
  let previousArtifactName = '';
  for (const artifact of manifest.artifacts) {
    exactKeys(artifact, ['name', 'role', 'media_type', 'bytes', 'sha256'], 'release artifact');
    if (!SAFE_NAME.test(artifact.name) || basename(artifact.name) !== artifact.name || artifactNames.has(artifact.name) || artifact.name <= previousArtifactName || !Number.isSafeInteger(artifact.bytes) || artifact.bytes <= 0 || !validDigest(artifact.sha256)) fail('release artifact binding is invalid');
    artifactNames.add(artifact.name); previousArtifactName = artifact.name;
  }
  const products = manifest.artifacts.filter((item) => item?.role === 'product');
  if (products.length !== 1) fail('release manifest must bind one product');
  const product = products[0];
  exactKeys(product, ['name', 'role', 'media_type', 'bytes', 'sha256'], 'release product');
  if (product.media_type !== 'application/vnd.apple.installer+xml' || product.name !== `AgentPass-v${manifest.version}-macos-universal.pkg`) fail('release product binding is invalid');
  const productSnapshot = readStable(productPath, { label: 'release product', maximum: MAX_ARTIFACT_BYTES, capture: false });
  if (productSnapshot.path !== resolve(dirname(manifestSnapshot.path), product.name) || productSnapshot.size !== product.bytes || productSnapshot.sha256 !== product.sha256) fail('release product does not match the signed manifest');
  const attestations = manifest.artifacts.filter((item) => item?.name === 'release-attestation.json' && item?.role === 'auxiliary' && item?.media_type === 'application/json');
  if (attestations.length !== 1) fail('release attestation binding is missing');
  const attestationBinding = attestations[0];
  const attestationSnapshot = readStable(resolve(dirname(manifestSnapshot.path), attestationBinding.name), { label: 'release attestation', maximum: MAX_ATTESTATION_BYTES });
  if (attestationSnapshot.bytes.length !== attestationBinding.bytes || attestationSnapshot.sha256 !== attestationBinding.sha256) fail('release attestation digest mismatch');
  const attestationValue = strictJSON(attestationSnapshot.bytes, 'release attestation');
  const attestation = buildReleaseAttestation({
    teamId: attestationValue.team_id,
    cloudImageDigest: attestationValue.cloud_image_digest,
    dependencyLockSha256: attestationValue.dependency_lock_sha256,
    databaseMigrationManifestSha256: attestationValue.database_migration_manifest_sha256,
    nestedCodeIdentities: attestationValue.nested_code_identities,
    signerKeyVersions: attestationValue.signer_key_versions
  });
  if (!attestationSnapshot.bytes.equals(canonicalReleaseAttestation(attestation))) fail('release attestation is not canonical or exact');
  exactKeys(manifest.external_qualification_controller, ['identity_document', 'identity', 'notarization'], 'external qualification controller');
  const identityBinding = manifest.external_qualification_controller.identity_document;
  exactKeys(identityBinding, ['name', 'bytes', 'sha256'], 'controller identity document');
  if (!SAFE_NAME.test(identityBinding.name) || basename(identityBinding.name) !== identityBinding.name || artifactNames.has(identityBinding.name) || !Number.isSafeInteger(identityBinding.bytes) || identityBinding.bytes <= 0 || !validDigest(identityBinding.sha256)) fail('controller identity document binding is invalid');
  const identitySnapshot = readStable(resolve(dirname(manifestSnapshot.path), identityBinding.name), { label: 'controller identity document', maximum: MAX_IDENTITY_BYTES });
  if (identitySnapshot.bytes.length !== identityBinding.bytes || identitySnapshot.sha256 !== identityBinding.sha256) fail('controller identity document digest mismatch');
  const identity = parseCanonicalExternalQualificationControllerIdentity(identitySnapshot.bytes);
  const embedded = validateExternalQualificationControllerIdentity(manifest.external_qualification_controller.identity, { expectedTeamId: attestation.team_id });
  if (JSON.stringify(identity) !== JSON.stringify(embedded)) fail('controller identity document does not match the manifest');
  const controllerArtifacts = manifest.artifacts.filter((item) => item?.role === 'external_qualification_controller');
  if (controllerArtifacts.length !== 1 || controllerArtifacts[0].media_type !== 'application/octet-stream' || controllerArtifacts[0].name !== identity.archive_name || controllerArtifacts[0].sha256 !== identity.archive_sha256 || controllerArtifacts[0].bytes !== identity.archive_bytes) fail('controller archive binding is invalid');
  const controllerArchive = readStable(resolve(dirname(manifestSnapshot.path), controllerArtifacts[0].name), { label: 'controller archive', maximum: MAX_ARTIFACT_BYTES, capture: false });
  if (controllerArchive.size !== controllerArtifacts[0].bytes || controllerArchive.sha256 !== controllerArtifacts[0].sha256) fail('controller archive digest mismatch');
  const notarization = manifest.external_qualification_controller.notarization;
  exactKeys(notarization, ['status', 'submission_ids', 'evidence'], 'controller notarization');
  if (notarization.status !== 'accepted_stapled' || !Array.isArray(notarization.submission_ids) || notarization.submission_ids.length === 0 || !Array.isArray(notarization.evidence) || notarization.evidence.length !== 2) fail('controller notarization is incomplete');
  const submissionIDs = new Set();
  for (const id of notarization.submission_ids) {
    if (typeof id !== 'string' || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u.test(id) || submissionIDs.has(id)) fail('controller notarization submission ID is invalid');
    submissionIDs.add(id);
  }
  const evidenceKinds = new Set();
  const evidenceNames = new Set();
  const evidenceContent = new Map();
  for (const evidence of notarization.evidence) {
    exactKeys(evidence, ['kind', 'name', 'bytes', 'sha256'], 'controller notarization evidence');
    if (!['notarytool_result', 'stapler_result'].includes(evidence.kind) || evidenceKinds.has(evidence.kind) || evidenceNames.has(evidence.name) || !SAFE_NAME.test(evidence.name) || artifactNames.has(evidence.name) || evidence.name === identityBinding.name || !Number.isSafeInteger(evidence.bytes) || evidence.bytes <= 0 || !validDigest(evidence.sha256)) fail('controller notarization evidence is invalid');
    evidenceKinds.add(evidence.kind); evidenceNames.add(evidence.name);
    const snapshot = readStable(resolve(dirname(manifestSnapshot.path), evidence.name), { label: 'controller notarization evidence', maximum: 4 * 1024 * 1024 });
    if (snapshot.size !== evidence.bytes || snapshot.sha256 !== evidence.sha256) fail('controller notarization evidence digest mismatch');
    evidenceContent.set(evidence.kind, snapshot.bytes);
  }
  if (!evidenceKinds.has('notarytool_result') || !evidenceKinds.has('stapler_result')) fail('controller notarization evidence is incomplete');
  let notaryResult;
  try { notaryResult = strictJSON(evidenceContent.get('notarytool_result'), 'controller notarytool evidence'); } catch { fail('controller notarytool evidence is invalid'); }
  if (notaryResult.status !== 'Accepted' || typeof notaryResult.id !== 'string' || !submissionIDs.has(notaryResult.id.toLowerCase())) fail('controller notarytool evidence does not prove the signed submission');
  if (!/The validate action worked!/iu.test(evidenceContent.get('stapler_result').toString('utf8'))) fail('controller stapler evidence does not prove validation');
  return Object.freeze({ manifestSnapshot, manifest, product, attestation, identity });
};

export const detectControllerArchitecture = ({ platform = process.platform, runCommand = spawnSync } = {}) => {
  if (platform !== 'darwin') fail('qualification provisioning requires macOS');
  const result = runCommand('/usr/sbin/sysctl', ['-n', 'hw.optional.arm64'], { encoding: 'utf8', shell: false, stdio: ['ignore', 'pipe', 'pipe'], env: { PATH: '/usr/bin:/bin:/usr/sbin:/sbin', LANG: 'C', LC_ALL: 'C' } });
  if (result?.status === 0 && result.signal == null && result.stdout.trim() === '1') return 'arm64';
  const machine = runCommand('/usr/bin/uname', ['-m'], { encoding: 'utf8', shell: false, stdio: ['ignore', 'pipe', 'pipe'], env: { PATH: '/usr/bin:/bin:/usr/sbin:/sbin', LANG: 'C', LC_ALL: 'C' } });
  if (machine?.status === 0 && machine.signal == null && machine.stdout.trim() === 'x86_64') return 'x86_64';
  fail('supported controller architecture cannot be derived from the host');
};

const validateState = (value, serviceConfigPath) => {
  exactKeys(value, STATE_KEYS, 'qualification provision state');
  if (value.schema_version !== 1 || value.kind !== 'agentpass-n3e-qualification-provision' || value.config_path !== serviceConfigPath || !['arm64', 'x86_64'].includes(value.architecture)) fail('qualification provision state identity is invalid');
  for (const key of ['original_config_sha256', 'qualified_config_sha256', 'release_manifest_sha256', 'candidate_sha256', 'source_commit_sha256', 'code_identities_sha256', 'run_id_sha256']) if (!validDigest(value[key])) fail('qualification provision state digest is invalid');
  if (!validCDHash(value.controller_cdhash) || !Number.isSafeInteger(value.expires_at_epoch_seconds) || SCENARIO_PHASE[value.scenario] !== value.phase || typeof value.original_config_base64 !== 'string' || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u.test(value.original_config_base64)) fail('qualification provision state binding is invalid');
  const original = Buffer.from(value.original_config_base64, 'base64');
  if (original.length === 0 || original.length > MAX_CONFIG_BYTES || sha256(original) !== value.original_config_sha256) fail('qualification provision backup is invalid');
  return Object.freeze({ value, original });
};

export const provisionQualificationConfig = ({
  manifestPath, signaturePath, publicKeyPath, expectedFingerprint, productPath, runBindingPath,
  scenario, expiresAtEpochSeconds, serviceConfigPath = SERVICE_CONFIG_PATH,
  statePath = PROVISION_STATE_PATH, expectedUid = 0, nowEpochSeconds = Math.floor(Date.now() / 1000),
  architecture = detectControllerArchitecture()
} = {}) => {
  if (typeof process.getuid === 'function' && process.getuid() !== expectedUid) fail('qualification provisioning requires the expected root authority');
  absolutePath(serviceConfigPath, 'service configuration'); absolutePath(statePath, 'provision state');
  if (dirname(serviceConfigPath) !== dirname(statePath)) fail('qualification state must share the protected service configuration directory');
  verifyProtectedParent(serviceConfigPath, expectedUid);
  try { fs.lstatSync(statePath); fail('qualification provision state already exists; restore is required'); } catch (error) { if (error?.code !== 'ENOENT') throw error; }
  if (!Number.isSafeInteger(expiresAtEpochSeconds) || expiresAtEpochSeconds <= nowEpochSeconds || expiresAtEpochSeconds - nowEpochSeconds > MAX_LIFETIME_SECONDS) fail('qualification expiry is invalid');
  const phase = SCENARIO_PHASE[scenario];
  if (!phase) fail('qualification scenario is invalid');
  if (!['arm64', 'x86_64'].includes(architecture)) fail('qualification architecture is invalid');
  const release = validateRelease({ manifestPath, signaturePath, publicKeyPath, expectedFingerprint, productPath });
  const hashes = release.identity.code_directory_hashes.filter((item) => item.architecture === architecture);
  if (hashes.length !== 1 || !validCDHash(hashes[0].hash)) fail('signed controller identity lacks the host architecture CDHash');
  const runSnapshot = readStable(runBindingPath, { label: 'qualification run binding', maximum: 128, expectedUid, exactMode: 0o600 });
  const rawRunBinding = runSnapshot.bytes.toString('utf8');
  if (!RUN_BINDING.test(rawRunBinding)) fail('qualification run binding format is invalid');
  const service = readStable(serviceConfigPath, { label: 'service configuration', maximum: MAX_CONFIG_BYTES, expectedUid, exactMode: 0o600 });
  const serviceValue = strictJSON(service.bytes, 'service configuration');
  if (QUALIFICATION_FIELDS.some((field) => Object.hasOwn(serviceValue, field))) fail('service configuration already contains qualification authority');
  const sourceCommitSHA256 = sha256(Buffer.from(release.manifest.source.commit, 'utf8'));
  const codeIdentitiesSHA256 = sha256(Buffer.from(JSON.stringify(release.attestation.nested_code_identities), 'utf8'));
  const runIDSHA256 = sha256(runSnapshot.bytes);
  const qualification = {
    qualification_mode: QUALIFICATION_MODE,
    qualification_mach_service_name: QUALIFICATION_MACH_SERVICE,
    qualification_candidate_sha256: release.product.sha256,
    qualification_source_commit_sha256: sourceCommitSHA256,
    qualification_code_identities_sha256: codeIdentitiesSHA256,
    qualification_controller_cdhash: hashes[0].hash,
    qualification_run_id_sha256: runIDSHA256,
    qualification_expires_at_epoch_seconds: expiresAtEpochSeconds,
    qualification_scenario: scenario,
    qualification_phase: phase
  };
  const qualifiedBytes = canonicalObject({ ...serviceValue, ...qualification });
  const state = {
    schema_version: 1,
    kind: 'agentpass-n3e-qualification-provision',
    config_path: serviceConfigPath,
    architecture,
    original_config_base64: service.bytes.toString('base64'),
    original_config_sha256: service.sha256,
    qualified_config_sha256: sha256(qualifiedBytes),
    release_manifest_sha256: release.manifestSnapshot.sha256,
    candidate_sha256: release.product.sha256,
    source_commit_sha256: sourceCommitSHA256,
    code_identities_sha256: codeIdentitiesSHA256,
    controller_cdhash: hashes[0].hash,
    run_id_sha256: runIDSHA256,
    expires_at_epoch_seconds: expiresAtEpochSeconds,
    scenario,
    phase
  };
  writeExclusive(statePath, canonicalObject(state), expectedUid);
  replaceAtomic(serviceConfigPath, qualifiedBytes, identityOf(service.stat), expectedUid);
  return Object.freeze({ ok: true, action: 'provisioned', architecture, candidate_sha256: release.product.sha256, controller_cdhash: hashes[0].hash, run_id_sha256: runIDSHA256, config_sha256: state.qualified_config_sha256, expires_at_epoch_seconds: expiresAtEpochSeconds, scenario, phase });
};

export const restoreQualificationConfig = ({ serviceConfigPath = SERVICE_CONFIG_PATH, statePath = PROVISION_STATE_PATH, expectedUid = 0 } = {}) => {
  if (typeof process.getuid === 'function' && process.getuid() !== expectedUid) fail('qualification restore requires the expected root authority');
  absolutePath(serviceConfigPath, 'service configuration'); absolutePath(statePath, 'provision state');
  if (dirname(serviceConfigPath) !== dirname(statePath)) fail('qualification state must share the protected service configuration directory');
  verifyProtectedParent(serviceConfigPath, expectedUid);
  const stateSnapshot = readStable(statePath, { label: 'qualification provision state', maximum: MAX_STATE_BYTES, expectedUid, exactMode: 0o600 });
  const parsed = strictJSON(stateSnapshot.bytes, 'qualification provision state');
  if (!stateSnapshot.bytes.equals(canonicalObject(parsed))) fail('qualification provision state is not canonical');
  const state = validateState(parsed, serviceConfigPath);
  const current = readStable(serviceConfigPath, { label: 'service configuration', maximum: MAX_CONFIG_BYTES, expectedUid, exactMode: 0o600 });
  if (current.sha256 === state.value.qualified_config_sha256) {
    replaceAtomic(serviceConfigPath, state.original, identityOf(current.stat), expectedUid);
  } else if (current.sha256 !== state.value.original_config_sha256) {
    fail('service configuration changed after qualification provisioning; refusing restore');
  }
  const restored = readStable(serviceConfigPath, { label: 'restored service configuration', maximum: MAX_CONFIG_BYTES, expectedUid, exactMode: 0o600 });
  if (restored.sha256 !== state.value.original_config_sha256 || !restored.bytes.equals(state.original)) fail('service configuration restore verification failed');
  const beforeUnlink = fs.lstatSync(statePath, { bigint: true });
  if (identityOf(beforeUnlink) !== identityOf(stateSnapshot.stat)) fail('qualification provision state changed before cleanup');
  fs.unlinkSync(statePath);
  fsyncDirectory(dirname(statePath));
  return Object.freeze({ ok: true, action: 'restored', original_config_sha256: state.value.original_config_sha256 });
};

const parseCLI = (args) => {
  const command = args[0];
  if (command === 'restore' && args.length === 1) return { command };
  if (command !== 'provision') fail('Usage: provision-qualification-config.mjs provision MANIFEST SIGNATURE PUBLIC_KEY FINGERPRINT PRODUCT_PKG RUN_BINDING_FILE SCENARIO EXPIRES_AT_EPOCH_SECONDS | restore');
  if (args.length !== 9) fail('Usage: provision-qualification-config.mjs provision MANIFEST SIGNATURE PUBLIC_KEY FINGERPRINT PRODUCT_PKG RUN_BINDING_FILE SCENARIO EXPIRES_AT_EPOCH_SECONDS | restore');
  const expiry = Number(args[8]);
  if (!Number.isSafeInteger(expiry)) fail('qualification expiry is invalid');
  return { command, manifestPath: args[1], signaturePath: args[2], publicKeyPath: args[3], expectedFingerprint: args[4], productPath: args[5], runBindingPath: args[6], scenario: args[7], expiresAtEpochSeconds: expiry };
};

if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
  if (process.platform !== 'darwin' || typeof process.getuid !== 'function' || process.getuid() !== 0) fail('qualification provisioning CLI requires root on macOS');
  const options = parseCLI(process.argv.slice(2));
  const result = options.command === 'restore' ? restoreQualificationConfig() : provisionQualificationConfig(options);
  process.stdout.write(`${JSON.stringify(result)}\n`);
}
