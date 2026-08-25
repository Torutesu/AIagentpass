#!/usr/bin/env node
import crypto from 'node:crypto';
import fs from 'node:fs';
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  FIXED_CANDIDATE_CHECKPOINT_PATH,
  FIXED_QUALIFICATION_RELEASE_DIRECTORY,
  FIXED_QUALIFICATION_RELEASE_TRUST_PATH,
  normalizeQualificationReleaseTrust,
  parseQualificationReleaseTrust,
  resolveQualificationReleaseTrust
} from './qualification-release-trust.mjs';
import {
  readCandidateCheckpoint,
  verifyCandidateCheckpoint
} from '../p0c/lib/candidate-checkpoint.mjs';
import { buildReleaseAttestation, canonicalJSON as canonicalAttestationJSON } from '../generate-release-attestation.mjs';
import { proveNoQualificationProcesses } from './qualification-scenario-driver.mjs';
import { assertReleaseCandidateIdMatchesProduct, RELEASE_MANIFEST_SCHEMA_VERSION } from '../release-candidate-identity.mjs';

export {
  FIXED_CANDIDATE_CHECKPOINT_PATH,
  FIXED_QUALIFICATION_RELEASE_DIRECTORY,
  FIXED_QUALIFICATION_RELEASE_TRUST_PATH
};

export const QUALIFICATION_RELEASE_MATERIALIZER_SCHEMA_VERSION = 1;
export const QUALIFICATION_RELEASE_MATERIALIZER_KIND = 'agentpass-n3e-qualification-release-materializer';
export const QUALIFICATION_RELEASE_MAX_MANIFEST_BYTES = 16 * 1024 * 1024;
export const QUALIFICATION_RELEASE_MAX_FILE_BYTES = 16 * 1024 * 1024 * 1024;
export const QUALIFICATION_RELEASE_MAX_SMALL_FILE_BYTES = 16 * 1024 * 1024;

const NOFOLLOW = fs.constants.O_NOFOLLOW;
const O_DIRECTORY = fs.constants.O_DIRECTORY ?? 0;
const DIRECTORY_MODE = 0o700;
const FILE_MODE = 0o600;
const DIGEST = /^[0-9a-f]{64}$/u;
const COMMIT = /^[0-9a-f]{40}$/u;
const TEAM_ID = /^[A-Z0-9]{10}$/u;
const FINGERPRINT = /^SHA256:[A-Za-z0-9_-]{43}$/u;
const SAFE_NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,255}$/u;
const SAFE_STAGING_NAME = /^\.[A-Za-z0-9][A-Za-z0-9._-]{0,255}$/u;
const REFERENCE_KEYS = new Set(['name', 'archive_name', 'artifact_name']);
const TRUST_FILE_NAME = basename(FIXED_QUALIFICATION_RELEASE_TRUST_PATH);
const CLI_USAGE = 'usage: qualification-release-materializer.mjs materialize RELEASE_DIRECTORY MANIFEST SIGNATURE PUBLIC_KEY FINGERPRINT PRODUCT | recover';

const fail = (message) => { throw new Error(message); };
const sha256 = (bytes) => crypto.createHash('sha256').update(bytes).digest('hex');

const exactKeys = (value, expected, label) => {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) fail(`${label} is invalid`);
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) fail(`${label} is not closed`);
};

const canonicalJSON = (value) => Buffer.from(`${JSON.stringify(value, null, 2)}\n`, 'utf8');

const absolutePath = (value, label) => {
  if (typeof value !== 'string' || value.length === 0 || value.includes('\0') || !isAbsolute(value) || resolve(value) !== value) fail(`${label} is invalid`);
  return value;
};

const statIdentity = (stat) => Object.freeze({
  dev: String(stat.dev),
  ino: String(stat.ino),
  mode: String(stat.mode),
  nlink: String(stat.nlink),
  size: String(stat.size),
  mtime_ns: String(stat.mtimeNs),
  ctime_ns: String(stat.ctimeNs),
  uid: String(stat.uid),
  gid: String(stat.gid)
});

const sameIdentity = (left, right) => Object.keys(left).every((key) => left[key] === right[key]);
const sameFileIdentity = (left, right) => Object.keys(left).filter((key) => key !== 'nlink' && key !== 'ctime_ns').every((key) => left[key] === right[key]);
const sameDirectoryIdentity = (left, right) => ['dev', 'ino', 'mode', 'uid', 'gid'].every((key) => left[key] === right[key]);
const isMissing = (error) => error?.code === 'ENOENT';

const validateOwner = (stat, expectedUid, label) => {
  if (stat.uid !== BigInt(expectedUid)) fail(`${label} owner is unsafe`);
};

const readLstat = (path, label, fileSystem) => {
  try { return fileSystem.lstatSync(path, { bigint: true }); }
  catch { fail(`${label} is unavailable`); }
};

const validateProtectedAncestry = (input, { fileSystem, expectedUid, production, exactLeafMode = null, requireOwner = production, requireLeafOwner = true, label }) => {
  const path = absolutePath(input, label);
  const parts = relative(sep, path).split(sep).filter(Boolean);
  let current = sep;
  for (let index = 0; index < parts.length; index += 1) {
    current = join(current, parts[index]);
    const stat = readLstat(current, label, fileSystem);
    if (!stat.isDirectory() || stat.isSymbolicLink() || (production && (stat.mode & 0o022n) !== 0n)) fail(`${label} ancestry is unsafe`);
    if (requireOwner || (index === parts.length - 1 && requireLeafOwner)) validateOwner(stat, expectedUid, label);
    if (index === parts.length - 1 && exactLeafMode !== null && (stat.mode & 0o7777n) !== BigInt(exactLeafMode)) fail(`${label} mode is unsafe`);
    if (production && current === '/' && stat.uid !== 0n) fail(`${label} root ancestry is unsafe`);
  }
  let real;
  try { real = resolve(fileSystem.realpathSync(path)); } catch { fail(`${label} is unavailable`); }
  if (real !== path) fail(`${label} contains a symlink`);
  return path;
};

const validateDirectory = (input, { fileSystem, expectedUid, production, exactMode, requireOwner = production, requireLeafOwner = true, label }) => {
  const path = validateProtectedAncestry(input, { fileSystem, expectedUid, production, exactLeafMode: exactMode, requireOwner, requireLeafOwner, label });
  const stat = readLstat(path, label, fileSystem);
  if (!stat.isDirectory() || stat.isSymbolicLink()) fail(`${label} is unsafe`);
  return Object.freeze({ path, identity: statIdentity(stat), ownerUid: Number(stat.uid) });
};

const ensureAbsent = (path, fileSystem, label) => {
  try {
    fileSystem.lstatSync(path, { bigint: true });
    fail(`${label} already exists; overwrite is refused`);
  } catch (error) {
    if (!isMissing(error)) throw error;
  }
};

const fsyncDirectory = (directory, fileSystem) => {
  if (!Number.isInteger(NOFOLLOW)) fail('release materialization requires O_NOFOLLOW');
  let descriptor;
  try {
    descriptor = fileSystem.openSync(directory, fileSystem.constants.O_RDONLY | O_DIRECTORY | NOFOLLOW);
    fileSystem.fsyncSync(descriptor);
  } catch { fail('release directory sync failed'); }
  finally {
    if (descriptor !== undefined) {
      try { fileSystem.closeSync(descriptor); } catch { fail('release directory sync failed'); }
    }
  }
};

const scanJSONString = (text, start, label) => {
  if (text[start] !== '"') fail(`${label} contains malformed JSON`);
  let index = start + 1;
  while (index < text.length) {
    const code = text.charCodeAt(index);
    if (code < 0x20) fail(`${label} contains malformed JSON`);
    if (text[index] === '\\') {
      index += 2;
      continue;
    }
    if (text[index] === '"') {
      try { return { value: JSON.parse(text.slice(start, index + 1)), end: index + 1 }; }
      catch { fail(`${label} contains malformed JSON`); }
    }
    index += 1;
  }
  fail(`${label} contains an unterminated string`);
};

const strictJSON = (bytes, label) => {
  let text;
  try { text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes); }
  catch { fail(`${label} is not valid UTF-8 JSON`); }
  if (text.startsWith('\uFEFF')) fail(`${label} contains a BOM`);
  const cursor = { index: 0 };
  const whitespace = () => { while (cursor.index < text.length && /[\x20\x09\x0a\x0d]/u.test(text[cursor.index])) cursor.index += 1; };
  const parse = (depth) => {
    if (depth > 32) fail(`${label} is too deeply nested`);
    whitespace();
    const character = text[cursor.index];
    if (character === '"') {
      const result = scanJSONString(text, cursor.index, label);
      cursor.index = result.end;
      return result.value;
    }
    if (character === '{') {
      cursor.index += 1;
      const output = {};
      const keys = new Set();
      whitespace();
      if (text[cursor.index] === '}') { cursor.index += 1; return output; }
      for (;;) {
        whitespace();
        const key = scanJSONString(text, cursor.index, label);
        cursor.index = key.end;
        if (keys.has(key.value)) fail(`${label} contains duplicate JSON fields`);
        keys.add(key.value);
        whitespace();
        if (text[cursor.index] !== ':') fail(`${label} contains malformed JSON`);
        cursor.index += 1;
        output[key.value] = parse(depth + 1);
        whitespace();
        if (text[cursor.index] === '}') { cursor.index += 1; return output; }
        if (text[cursor.index] !== ',') fail(`${label} contains malformed JSON`);
        cursor.index += 1;
      }
    }
    if (character === '[') {
      cursor.index += 1;
      const output = [];
      whitespace();
      if (text[cursor.index] === ']') { cursor.index += 1; return output; }
      for (;;) {
        output.push(parse(depth + 1));
        whitespace();
        if (text[cursor.index] === ']') { cursor.index += 1; return output; }
        if (text[cursor.index] !== ',') fail(`${label} contains malformed JSON`);
        cursor.index += 1;
      }
    }
    const start = cursor.index;
    while (cursor.index < text.length && !/[\x20\x09\x0a\x0d,\]}]/u.test(text[cursor.index])) cursor.index += 1;
    if (start === cursor.index) fail(`${label} contains malformed JSON`);
    const token = text.slice(start, cursor.index);
    if (!['true', 'false', 'null'].includes(token) && !/^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?$/u.test(token)) fail(`${label} contains malformed JSON`);
    try { return JSON.parse(token); } catch { fail(`${label} contains malformed JSON`); }
  };
  const value = parse(0);
  whitespace();
  if (cursor.index !== text.length) fail(`${label} contains trailing data`);
  return value;
};

const validateName = (value, label) => {
  if (typeof value !== 'string' || !SAFE_NAME.test(value) || basename(value) !== value || value === '.' || value === '..') fail(`${label} is unsafe`);
  return value;
};

const readStableFile = (input, { fileSystem, expectedUid, production, maximum, label, capture = true, exactMode = null, requireParentOwner = production, requireParentLeafOwner = true }) => {
  const path = absolutePath(input, label);
  validateProtectedAncestry(dirname(path), { fileSystem, expectedUid, production, requireOwner: requireParentOwner, requireLeafOwner: requireParentLeafOwner, label: `${label} parent` });
  let descriptor;
  try { descriptor = fileSystem.openSync(path, fileSystem.constants.O_RDONLY | NOFOLLOW); }
  catch { fail(`${label} is unavailable`); }
  try {
    const before = fileSystem.fstatSync(descriptor, { bigint: true });
    if (!before.isFile() || before.isSymbolicLink?.() || before.nlink !== 1n || before.uid !== BigInt(expectedUid) || (before.mode & 0o022n) !== 0n || (exactMode !== null && (before.mode & 0o7777n) !== BigInt(exactMode)) || before.size <= 0n || before.size > BigInt(maximum) || before.size > BigInt(Number.MAX_SAFE_INTEGER)) fail(`${label} is unsafe`);
    const bytes = Buffer.alloc(Number(before.size));
    let offset = 0;
    while (offset < bytes.length) {
      const count = fileSystem.readSync(descriptor, bytes, offset, bytes.length - offset, offset);
      if (!Number.isInteger(count) || count <= 0) fail(`${label} changed while reading`);
      offset += count;
    }
    const after = fileSystem.fstatSync(descriptor, { bigint: true });
    const current = readLstat(path, label, fileSystem);
    if (!sameIdentity(statIdentity(before), statIdentity(after)) || !sameIdentity(statIdentity(after), statIdentity(current))) fail(`${label} changed while reading`);
    return Object.freeze({ path, bytes: capture ? bytes : undefined, size: bytes.length, sha256: sha256(bytes), identity: statIdentity(after) });
  } finally { fileSystem.closeSync(descriptor); }
};

const copyStableFile = (sourcePath, destinationPath, { fileSystem, expectedUid, sourceUid = expectedUid, production, sourceRequireParentOwner = production, maximum, expected, label }) => {
  const source = absolutePath(sourcePath, `${label} source`);
  const destination = absolutePath(destinationPath, `${label} destination`);
  validateProtectedAncestry(dirname(source), { fileSystem, expectedUid: sourceUid, production, requireOwner: sourceRequireParentOwner, requireLeafOwner: sourceRequireParentOwner, label: `${label} source parent` });
  validateDirectory(dirname(destination), { fileSystem, expectedUid, production, exactMode: DIRECTORY_MODE, label: `${label} destination parent` });
  let sourceDescriptor;
  let destinationDescriptor;
  try {
    sourceDescriptor = fileSystem.openSync(source, fileSystem.constants.O_RDONLY | NOFOLLOW);
    const before = fileSystem.fstatSync(sourceDescriptor, { bigint: true });
    if (!before.isFile() || before.nlink !== 1n || before.uid !== BigInt(sourceUid) || (before.mode & 0o022n) !== 0n || before.size <= 0n || before.size > BigInt(maximum) || before.size > BigInt(Number.MAX_SAFE_INTEGER)) fail(`${label} source is unsafe`);
    destinationDescriptor = fileSystem.openSync(destination, fileSystem.constants.O_WRONLY | fileSystem.constants.O_CREAT | fileSystem.constants.O_EXCL | NOFOLLOW, FILE_MODE);
    const hash = crypto.createHash('sha256');
    const buffer = Buffer.allocUnsafe(1024 * 1024);
    let remaining = Number(before.size);
    let offset = 0;
    while (remaining > 0) {
      const requested = Math.min(buffer.length, remaining);
      const count = fileSystem.readSync(sourceDescriptor, buffer, 0, requested, offset);
      if (!Number.isInteger(count) || count <= 0) fail(`${label} source changed while reading`);
      let written = 0;
      while (written < count) {
        const result = fileSystem.writeSync(destinationDescriptor, buffer, written, count - written, offset + written);
        if (!Number.isInteger(result) || result <= 0) fail(`${label} staging write failed`);
        written += result;
      }
      hash.update(buffer.subarray(0, count));
      remaining -= count;
      offset += count;
    }
    fileSystem.fchmodSync(destinationDescriptor, FILE_MODE);
    fileSystem.fsyncSync(destinationDescriptor);
    const after = fileSystem.fstatSync(sourceDescriptor, { bigint: true });
    const current = readLstat(source, label, fileSystem);
    const digest = hash.digest('hex');
    if (!sameIdentity(statIdentity(before), statIdentity(after)) || !sameIdentity(statIdentity(after), statIdentity(current))) fail(`${label} source changed while copying`);
    if (expected && (digest !== expected.sha256 || Number(before.size) !== expected.bytes)) fail(`${label} does not match the signed manifest`);
    const staged = fileSystem.fstatSync(destinationDescriptor, { bigint: true });
    if (!staged.isFile() || staged.nlink !== 1n || staged.uid !== BigInt(expectedUid) || (staged.mode & 0o7777n) !== BigInt(FILE_MODE) || staged.size !== before.size) fail(`${label} staged file is unsafe`);
    const installed = readLstat(destination, label, fileSystem);
    if (!sameIdentity(statIdentity(staged), statIdentity(installed))) fail(`${label} staging path changed`);
    return Object.freeze({ name: basename(destination), bytes: Number(before.size), sha256: digest, identity: statIdentity(staged) });
  } finally {
    if (destinationDescriptor !== undefined) fileSystem.closeSync(destinationDescriptor);
    if (sourceDescriptor !== undefined) fileSystem.closeSync(sourceDescriptor);
  }
};

const assertSourceChild = (sourceRoot, input, label) => {
  const path = absolutePath(input, label);
  if (dirname(path) !== sourceRoot) fail(`${label} must be a direct child of the source release directory`);
  return path;
};

const addBinding = (bindings, name, bytes, digest, label) => {
  const safeName = validateName(name, `${label} name`);
  if (!Number.isSafeInteger(bytes) || bytes <= 0 || !DIGEST.test(digest)) fail(`${label} binding is invalid`);
  const previous = bindings.get(safeName);
  if (previous && (previous.bytes !== bytes || previous.sha256 !== digest)) fail(`${label} binding collides with another file`);
  bindings.set(safeName, Object.freeze({ bytes, sha256: digest }));
  return safeName;
};

const collectManifestFiles = (manifest) => {
  const bindings = new Map();
  const references = new Set();
  const visit = (value) => {
    if (Array.isArray(value)) { value.forEach(visit); return; }
    if (!value || typeof value !== 'object') return;
    for (const [key, child] of Object.entries(value)) {
      if (REFERENCE_KEYS.has(key)) {
        if (typeof child !== 'string') fail(`release manifest ${key} is invalid`);
        const name = validateName(child, `release manifest ${key}`);
        references.add(name);
        if (Number.isSafeInteger(value.bytes) && typeof value.sha256 === 'string') addBinding(bindings, name, value.bytes, value.sha256, `release manifest ${key}`);
      }
      visit(child);
    }
  };
  visit(manifest);
  if (!Array.isArray(manifest.artifacts)) fail('release manifest artifacts are invalid');
  for (const artifact of manifest.artifacts) {
    exactKeys(artifact, ['name', 'role', 'media_type', 'bytes', 'sha256'], 'release artifact');
    addBinding(bindings, artifact.name, artifact.bytes, artifact.sha256, 'release artifact');
  }
  return Object.freeze({ bindings, references: Object.freeze([...references].sort()) });
};

const validateManifest = (snapshot) => {
  const manifest = strictJSON(snapshot.bytes, 'release manifest');
  if (!snapshot.bytes.equals(canonicalJSON(manifest))) fail('release manifest is not canonical JSON');
  exactKeys(manifest, ['schema_version', 'product', 'version', 'source', 'generated_at', 'candidate_id', 'artifacts', 'external_qualification_controller', 'evidence'], 'release manifest');
  if (manifest.schema_version !== RELEASE_MANIFEST_SCHEMA_VERSION || manifest.product !== 'AgentPass' || !manifest.source || !COMMIT.test(manifest.source.commit)) fail('release manifest identity is invalid');
  const files = collectManifestFiles(manifest);
  const products = manifest.artifacts.filter((item) => item.role === 'product');
  if (products.length !== 1 || !products[0].name.endsWith('.pkg')) fail('release manifest must bind exactly one product PKG');
  const product = products[0];
  try { assertReleaseCandidateIdMatchesProduct(manifest.candidate_id, product.sha256); } catch (error) { fail(error.message); }
  const attestation = manifest.artifacts.find((item) => item.name === 'release-attestation.json' && item.role === 'auxiliary');
  if (!attestation) fail('release manifest attestation binding is missing');
  const attestationName = validateName(attestation.name, 'release attestation name');
  return Object.freeze({ manifest, files, product: Object.freeze({ ...product, name: validateName(product.name, 'release product name') }), attestationName });
};

const verifySignature = ({ manifest, signature, publicKey, expectedFingerprint }) => {
  if (!FINGERPRINT.test(expectedFingerprint)) fail('release key fingerprint is invalid');
  let key;
  try { key = crypto.createPublicKey(publicKey.bytes); } catch { fail('release public key is invalid'); }
  if (key.asymmetricKeyType !== 'ed25519') fail('release public key must be Ed25519');
  const actual = `SHA256:${crypto.createHash('sha256').update(key.export({ type: 'spki', format: 'der' })).digest('base64url')}`;
  if (actual !== expectedFingerprint) fail('release public key fingerprint mismatch');
  const encoded = signature.bytes.toString('utf8');
  if (!/^(?:[A-Za-z0-9+/]{4}){21}[A-Za-z0-9+/]{2}==\n$/u.test(encoded)) fail('release manifest signature encoding is invalid');
  const value = Buffer.from(encoded.trim(), 'base64');
  if (value.length !== 64 || !crypto.verify(null, manifest.bytes, key, value)) fail('release manifest signature is invalid');
};

const validateAttestationBinding = (bytes, expectedTeamId) => {
  const value = strictJSON(bytes, 'release attestation');
  if (!bytes.equals(canonicalAttestationJSON(value))) fail('release attestation is not canonical JSON');
  if (value.team_id !== expectedTeamId) fail('release attestation Team ID does not match the candidate checkpoint');
  let normalized;
  try {
    normalized = buildReleaseAttestation({
      teamId: value.team_id,
      cloudImageDigest: value.cloud_image_digest,
      dependencyLockSha256: value.dependency_lock_sha256,
      databaseMigrationManifestSha256: value.database_migration_manifest_sha256,
      nestedCodeIdentities: value.nested_code_identities,
      signerKeyVersions: value.signer_key_versions
    });
  } catch { fail('release attestation is invalid'); }
  if (!bytes.equals(canonicalAttestationJSON(normalized))) fail('release attestation is not a closed canonical document');
};

const validateSource = (source, { fileSystem, expectedUid, production }) => {
  exactKeys(source, ['releaseDirectory', 'manifestPath', 'signaturePath', 'publicKeyPath', 'productPath'], 'release source');
  const rootState = validateDirectory(source.releaseDirectory, { fileSystem, expectedUid, production, exactMode: DIRECTORY_MODE, requireOwner: false, requireLeafOwner: false, label: 'source release directory' });
  const sourceUid = rootState.ownerUid;
  if (!Number.isSafeInteger(sourceUid) || sourceUid < 0) fail('source release directory owner is invalid');
  const root = rootState.path;
  const paths = Object.freeze({
    root,
    manifest: assertSourceChild(root, source.manifestPath, 'release manifest'),
    signature: assertSourceChild(root, source.signaturePath, 'release signature'),
    publicKey: assertSourceChild(root, source.publicKeyPath, 'release public key'),
    product: assertSourceChild(root, source.productPath, 'release product')
  });
  const names = [paths.manifest, paths.signature, paths.publicKey, paths.product].map((value) => basename(value));
  names.forEach((name, index) => validateName(name, ['manifest', 'signature', 'public key', 'product'][index]));
  if (new Set(names).size !== names.length) fail('release source file names are not unique');
  return Object.freeze({ ...paths, ownerUid: sourceUid });
};

const validateCheckpoint = (checkpointPath, { fileSystem, expectedUid, production, identityReader, expected }) => {
  const initial = readCandidateCheckpoint(checkpointPath, { production, fsImpl: fileSystem });
  const verified = verifyCandidateCheckpoint(checkpointPath, {
    expected,
    production,
    fsImpl: fileSystem,
    identityReader
  });
  if (JSON.stringify(initial) !== JSON.stringify(verified)) fail('candidate checkpoint changed during release materialization');
  if (!DIGEST.test(verified.artifact_sha256) || !DIGEST.test(verified.checkpoint_sha256) || !COMMIT.test(verified.source_commit) || !TEAM_ID.test(verified.team_id)) fail('candidate checkpoint binding is invalid');
  return verified;
};

const writeAll = (descriptor, bytes, fileSystem) => {
  let offset = 0;
  while (offset < bytes.length) {
    const count = fileSystem.writeSync(descriptor, bytes, offset, bytes.length - offset, offset);
    if (!Number.isInteger(count) || count <= 0) fail('release trust write failed');
    offset += count;
  }
};

const writeExclusive = (path, bytes, { fileSystem, expectedUid, label }) => {
  let descriptor;
  try { descriptor = fileSystem.openSync(path, fileSystem.constants.O_WRONLY | fileSystem.constants.O_CREAT | fileSystem.constants.O_EXCL | NOFOLLOW, FILE_MODE); }
  catch { fail(`${label} already exists or is unavailable`); }
  try {
    writeAll(descriptor, bytes, fileSystem);
    fileSystem.fchmodSync(descriptor, FILE_MODE);
    const stat = fileSystem.fstatSync(descriptor, { bigint: true });
    if (!stat.isFile() || stat.nlink !== 1n || stat.uid !== BigInt(expectedUid) || (stat.mode & 0o7777n) !== BigInt(FILE_MODE) || stat.size !== BigInt(bytes.length)) fail(`${label} is unsafe`);
    fileSystem.fsyncSync(descriptor);
    return statIdentity(stat);
  } finally { fileSystem.closeSync(descriptor); }
};

const safeRemoveOwnedFile = (path, expectedIdentity, { fileSystem, expectedUid }) => {
  let stat;
  try { stat = fileSystem.lstatSync(path, { bigint: true }); } catch { return true; }
  const actual = statIdentity(stat);
  const withoutLinks = (value) => Object.fromEntries(Object.entries(value).filter(([key]) => key !== 'nlink' && key !== 'ctime_ns'));
  if (!stat.isFile() || stat.isSymbolicLink() || stat.uid !== BigInt(expectedUid) || JSON.stringify(withoutLinks(actual)) !== JSON.stringify(withoutLinks(expectedIdentity)) || ![1n, 2n].includes(stat.nlink)) return false;
  try { fileSystem.unlinkSync(path); return true; } catch { return false; }
};

const removeExactOwnedFile = (path, expectedIdentity, { fileSystem, expectedUid, label }) => {
  let stat;
  try { stat = fileSystem.lstatSync(path, { bigint: true }); }
  catch { return false; }
  if (!stat.isFile() || stat.isSymbolicLink() || stat.uid !== BigInt(expectedUid) || stat.nlink !== 1n || (stat.mode & 0o7777n) !== BigInt(FILE_MODE) || !sameIdentity(statIdentity(stat), expectedIdentity)) fail(`${label} changed before removal`);
  try { fileSystem.unlinkSync(path); } catch { fail(`${label} removal failed`); }
  return true;
};

const safeRemoveOwnedDirectory = (path, expectedIdentity, ownedFiles, { fileSystem, expectedUid }) => {
  let stat;
  try { stat = fileSystem.lstatSync(path, { bigint: true }); } catch (error) { return isMissing(error); }
  if (!stat.isDirectory() || stat.isSymbolicLink() || stat.uid !== BigInt(expectedUid) || !sameDirectoryIdentity(statIdentity(stat), expectedIdentity)) return false;
  let ok = true;
  for (const [name, identity] of ownedFiles) ok = safeRemoveOwnedFile(join(path, name), identity, { fileSystem, expectedUid }) && ok;
  try {
    const entries = fileSystem.readdirSync(path);
    if (entries.length !== 0) return false;
    fileSystem.rmdirSync(path);
  } catch { return false; }
  return ok;
};

const productionGuard = ({ production, platform, uid, expectedUid, destination, trustPath, checkpointPath, fileSystem, randomBytes }) => {
  if (production && (platform !== 'darwin' || uid !== 0 || expectedUid !== 0 || destination !== FIXED_QUALIFICATION_RELEASE_DIRECTORY || trustPath !== FIXED_QUALIFICATION_RELEASE_TRUST_PATH || checkpointPath !== FIXED_CANDIDATE_CHECKPOINT_PATH || fileSystem !== fs || randomBytes !== crypto.randomBytes)) fail('release materialization requires root on macOS and fixed production destinations');
  if (!production && uid !== expectedUid) fail('release materialization requires the expected owner');
};

const materialize = ({
  source,
  expectedFingerprint,
  destination = FIXED_QUALIFICATION_RELEASE_DIRECTORY,
  trustPath = FIXED_QUALIFICATION_RELEASE_TRUST_PATH,
  checkpointPath = FIXED_CANDIDATE_CHECKPOINT_PATH,
  expectedUid = 0,
  production = true,
  platform = process.platform,
  uid = process.getuid?.(),
  fileSystem = fs,
  randomBytes = crypto.randomBytes,
  processId = process.pid,
  identityReader
} = {}) => {
  productionGuard({ production, platform, uid, expectedUid, destination, trustPath, checkpointPath, fileSystem, randomBytes });
  absolutePath(destination, 'release destination');
  absolutePath(trustPath, 'release trust');
  absolutePath(checkpointPath, 'candidate checkpoint');
  if (!Number.isInteger(expectedUid) || expectedUid < 0 || !Number.isInteger(processId) || processId < 0 || typeof randomBytes !== 'function') fail('release materialization options are invalid');
  if (!FINGERPRINT.test(expectedFingerprint)) fail('release key fingerprint is invalid');
  const destinationParent = validateDirectory(dirname(destination), { fileSystem, expectedUid, production, exactMode: DIRECTORY_MODE, label: 'release destination parent' });
  if (basename(trustPath) !== TRUST_FILE_NAME || dirname(trustPath) !== destinationParent.path) fail('release trust destination is not fixed under the qualification root');
  ensureAbsent(destination, fileSystem, 'release directory');
  ensureAbsent(trustPath, fileSystem, 'release trust');

  const sourcePaths = validateSource(source, { fileSystem, expectedUid, production });
  const checkpoint = validateCheckpoint(checkpointPath, { fileSystem, expectedUid, production, identityReader });
  const sourceReadOptions = { fileSystem, expectedUid: sourcePaths.ownerUid, production, requireParentOwner: false, requireParentLeafOwner: false };
  const manifestSnapshot = readStableFile(sourcePaths.manifest, { ...sourceReadOptions, maximum: QUALIFICATION_RELEASE_MAX_MANIFEST_BYTES, label: 'release manifest' });
  const release = validateManifest(manifestSnapshot);
  if (release.manifest.source.commit !== checkpoint.source_commit) fail('release source commit does not match the candidate checkpoint');
  if (release.product.sha256 !== checkpoint.artifact_sha256) fail('release product does not match the candidate checkpoint');
  if (basename(sourcePaths.product) !== release.product.name) fail('release product path does not match the signed manifest');
  const signature = readStableFile(sourcePaths.signature, { ...sourceReadOptions, maximum: 1024, label: 'release signature' });
  const publicKey = readStableFile(sourcePaths.publicKey, { ...sourceReadOptions, maximum: 16 * 1024, label: 'release public key' });
  verifySignature({ manifest: manifestSnapshot, signature, publicKey, expectedFingerprint });
  const attestation = readStableFile(join(sourcePaths.root, release.attestationName), { ...sourceReadOptions, maximum: QUALIFICATION_RELEASE_MAX_SMALL_FILE_BYTES, label: 'release attestation' });
  validateAttestationBinding(attestation.bytes, checkpoint.team_id);
  const names = new Set([...release.files.references, basename(sourcePaths.manifest), basename(sourcePaths.signature), basename(sourcePaths.publicKey), basename(sourcePaths.product)]);
  for (const name of [basename(sourcePaths.manifest), basename(sourcePaths.signature), basename(sourcePaths.publicKey)]) {
    if (release.files.references.includes(name)) fail('release materialization file inventory has collisions');
  }
  if (!release.files.references.includes(basename(sourcePaths.product)) || names.size !== release.files.references.length + 3) fail('release materialization file inventory has collisions');
  const bindings = new Map(release.files.bindings);
  bindings.set(basename(sourcePaths.manifest), Object.freeze({ bytes: manifestSnapshot.size, sha256: manifestSnapshot.sha256 }));
  bindings.set(basename(sourcePaths.signature), Object.freeze({ bytes: signature.size, sha256: signature.sha256 }));
  bindings.set(basename(sourcePaths.publicKey), Object.freeze({ bytes: publicKey.size, sha256: publicKey.sha256 }));
  bindings.set(basename(sourcePaths.product), Object.freeze({ bytes: release.product.bytes, sha256: release.product.sha256 }));
  let random;
  try { random = randomBytes(16); } catch { fail('release staging name generation failed'); }
  if (!(random instanceof Uint8Array) || random.length !== 16) fail('release staging name generation failed');
  const stagingName = `.release.${processId}.${Buffer.from(random).toString('hex')}.staging`;
  if (!SAFE_STAGING_NAME.test(stagingName)) fail('release staging name is invalid');
  const staging = join(destinationParent.path, stagingName);
  ensureAbsent(staging, fileSystem, 'release staging directory');
  let stagingIdentity;
  let finalIdentity;
  let trustIdentity;
  const stagedFiles = new Map();
  const finalFiles = new Map();
  try {
    fileSystem.mkdirSync(staging, { mode: DIRECTORY_MODE });
    const stagedDirectory = validateDirectory(staging, { fileSystem, expectedUid, production, exactMode: DIRECTORY_MODE, label: 'release staging directory' });
    stagingIdentity = stagedDirectory.identity;
    for (const name of [...names].sort()) {
      const sourcePath = name === basename(sourcePaths.manifest) ? sourcePaths.manifest
        : name === basename(sourcePaths.signature) ? sourcePaths.signature
            : name === basename(sourcePaths.publicKey) ? sourcePaths.publicKey
              : name === basename(sourcePaths.product) ? sourcePaths.product
                : join(sourcePaths.root, name);
      const expected = bindings.get(name);
      if (!expected) fail(`release manifest file binding is missing for ${name}`);
      const maximum = name === basename(sourcePaths.product) || name.endsWith('.tar') || name.endsWith('.pkg') ? QUALIFICATION_RELEASE_MAX_FILE_BYTES : QUALIFICATION_RELEASE_MAX_SMALL_FILE_BYTES;
      const copied = copyStableFile(sourcePath, join(staging, name), { fileSystem, expectedUid, sourceUid: sourcePaths.ownerUid, production, sourceRequireParentOwner: false, maximum, expected, label: `release file ${name}` });
      stagedFiles.set(name, copied.identity);
    }
    fsyncDirectory(staging, fileSystem);
    const stagedEntries = fileSystem.readdirSync(staging).sort();
    if (stagedEntries.length !== names.size || stagedEntries.some((name) => !names.has(name))) fail('release staging inventory is invalid');
    for (const name of stagedEntries) {
      const stat = readLstat(join(staging, name), `release staging file ${name}`, fileSystem);
      if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1n || stat.uid !== BigInt(expectedUid) || (stat.mode & 0o7777n) !== BigInt(FILE_MODE) || !sameIdentity(statIdentity(stat), stagedFiles.get(name))) fail('release staging file changed');
    }
    ensureAbsent(destination, fileSystem, 'release directory');
    fileSystem.mkdirSync(destination, { mode: DIRECTORY_MODE });
    const finalDirectory = validateDirectory(destination, { fileSystem, expectedUid, production, exactMode: DIRECTORY_MODE, label: 'release directory' });
    finalIdentity = finalDirectory.identity;
    for (const name of stagedEntries) {
      const sourcePath = join(staging, name);
      const targetPath = join(destination, name);
      fileSystem.linkSync(sourcePath, targetPath);
      const linked = readLstat(targetPath, `release file ${name}`, fileSystem);
      if (!linked.isFile() || linked.isSymbolicLink() || linked.nlink !== 2n || linked.uid !== BigInt(expectedUid) || (linked.mode & 0o7777n) !== BigInt(FILE_MODE) || !sameFileIdentity(statIdentity(linked), stagedFiles.get(name))) fail('release file publication changed');
      finalFiles.set(name, statIdentity(linked));
    }
    for (const name of stagedEntries) {
      if (!safeRemoveOwnedFile(join(staging, name), stagedFiles.get(name), { fileSystem, expectedUid })) fail('release staging file cleanup was refused');
    }
    if (!safeRemoveOwnedDirectory(staging, stagingIdentity, stagedFiles, { fileSystem, expectedUid })) fail('release staging directory cleanup was refused');
    stagingIdentity = undefined;
    fsyncDirectory(destinationParent.path, fileSystem);
    fsyncDirectory(destination, fileSystem);
    const finalEntries = fileSystem.readdirSync(destination).sort();
    if (finalEntries.length !== names.size || finalEntries.some((name) => !names.has(name))) fail('release inventory is invalid');
    for (const name of finalEntries) {
      const maximum = name === basename(sourcePaths.product) || name.endsWith('.tar') || name.endsWith('.pkg') ? QUALIFICATION_RELEASE_MAX_FILE_BYTES : QUALIFICATION_RELEASE_MAX_SMALL_FILE_BYTES;
      const verifiedFile = readStableFile(join(destination, name), { fileSystem, expectedUid, production, maximum, label: `release file ${name}` });
      const expected = bindings.get(name);
      if (!expected || verifiedFile.size !== expected.bytes || verifiedFile.sha256 !== expected.sha256) fail('release file verification failed');
      finalFiles.set(name, verifiedFile.identity);
    }
    const finalCheckpoint = validateCheckpoint(checkpointPath, { fileSystem, expectedUid, production, identityReader, expected: { artifactSha256: checkpoint.artifact_sha256, sourceCommit: checkpoint.source_commit, teamId: checkpoint.team_id } });
    if (JSON.stringify(finalCheckpoint) !== JSON.stringify(checkpoint)) fail('candidate checkpoint changed before trust publication');
    const trust = normalizeQualificationReleaseTrust({
      schema_version: QUALIFICATION_RELEASE_MATERIALIZER_SCHEMA_VERSION,
      artifact_sha256: checkpoint.artifact_sha256,
      candidate_checkpoint_sha256: checkpoint.checkpoint_sha256,
      expected_fingerprint: expectedFingerprint,
      kind: 'agentpass-n3e-qualification-release-trust',
      manifest_name: basename(sourcePaths.manifest),
      product_name: basename(sourcePaths.product),
      public_key_name: basename(sourcePaths.publicKey),
      run_binding_name: 'run-binding',
      signature_name: basename(sourcePaths.signature),
      source_commit: checkpoint.source_commit,
      team_id: checkpoint.team_id
    });
    const trustBytes = canonicalJSON(trust);
    parseQualificationReleaseTrust(trustBytes);
    trustIdentity = writeExclusive(trustPath, trustBytes, { fileSystem, expectedUid, label: 'release trust' });
    fsyncDirectory(destinationParent.path, fileSystem);
    const installedTrust = readStableFile(trustPath, { fileSystem, expectedUid, production, maximum: 32 * 1024, label: 'installed release trust' });
    if (!installedTrust.bytes.equals(trustBytes)) fail('release trust verification failed');
    resolveQualificationReleaseTrust({ checkpoint, fileSystem, trustPath, releaseDirectory: destination, expectedUid, platform, uid, production });
    return Object.freeze({ ok: true, action: 'materialized', release_directory: destination, trust_path: trustPath, files: names.size, artifact_sha256: checkpoint.artifact_sha256, candidate_checkpoint_sha256: checkpoint.checkpoint_sha256, source_commit: checkpoint.source_commit, team_id: checkpoint.team_id, expected_fingerprint: expectedFingerprint });
  } catch (error) {
    if (trustIdentity) safeRemoveOwnedFile(trustPath, trustIdentity, { fileSystem, expectedUid });
    if (finalIdentity) safeRemoveOwnedDirectory(destination, finalIdentity, finalFiles, { fileSystem, expectedUid });
    if (stagingIdentity) safeRemoveOwnedDirectory(staging, stagingIdentity, stagedFiles, { fileSystem, expectedUid });
    throw error?.message ? error : new Error('release materialization failed');
  }
};

export const materializeQualificationRelease = (options = {}) => materialize(options);
export const materializeFixedQualificationRelease = materializeQualificationRelease;

const releaseInventory = ({ checkpoint, trust, fileSystem, expectedUid, production, platform, uid, identityReader, destination, trustPath }) => {
  const destinationState = validateDirectory(destination, { fileSystem, expectedUid, production, exactMode: DIRECTORY_MODE, label: 'release directory' });
  const resolvedTrust = resolveQualificationReleaseTrust({ checkpoint, fileSystem, trustPath, releaseDirectory: destination, expectedUid, platform, uid, production });
  if (JSON.stringify(resolvedTrust.trust) !== JSON.stringify(trust)) fail('release trust changed while verifying the release');
  if (resolvedTrust.runBindingPath !== join(destination, 'run-binding')) fail('qualification run binding path is not fixed');

  const manifestSnapshot = readStableFile(resolvedTrust.manifestPath, { fileSystem, expectedUid, production, maximum: QUALIFICATION_RELEASE_MAX_MANIFEST_BYTES, exactMode: FILE_MODE, label: 'installed release manifest' });
  const release = validateManifest(manifestSnapshot);
  if (release.manifest.source.commit !== checkpoint.source_commit || release.product.sha256 !== checkpoint.artifact_sha256 || release.product.name !== trust.product_name || release.attestationName === trust.run_binding_name) fail('installed release manifest does not match the release trust');
  if (basename(resolvedTrust.manifestPath) !== trust.manifest_name || basename(resolvedTrust.signaturePath) !== trust.signature_name || basename(resolvedTrust.publicKeyPath) !== trust.public_key_name || basename(resolvedTrust.productPath) !== trust.product_name) fail('release trust names do not match the installed release');

  const signature = readStableFile(resolvedTrust.signaturePath, { fileSystem, expectedUid, production, maximum: 1024, exactMode: FILE_MODE, label: 'installed release signature' });
  const publicKey = readStableFile(resolvedTrust.publicKeyPath, { fileSystem, expectedUid, production, maximum: 16 * 1024, exactMode: FILE_MODE, label: 'installed release public key' });
  verifySignature({ manifest: manifestSnapshot, signature, publicKey, expectedFingerprint: trust.expected_fingerprint });
  const attestation = readStableFile(join(destination, release.attestationName), { fileSystem, expectedUid, production, maximum: QUALIFICATION_RELEASE_MAX_SMALL_FILE_BYTES, exactMode: FILE_MODE, label: 'installed release attestation' });
  validateAttestationBinding(attestation.bytes, checkpoint.team_id);

  const names = new Set([...release.files.references, trust.manifest_name, trust.signature_name, trust.public_key_name, trust.product_name]);
  for (const name of [trust.manifest_name, trust.signature_name, trust.public_key_name]) {
    if (release.files.references.includes(name)) fail('installed release inventory has a reserved-name collision');
  }
  if (!release.files.references.includes(trust.product_name) || names.size !== release.files.references.length + 3 || names.has(trust.run_binding_name)) fail('installed release inventory is invalid');
  const bindings = new Map(release.files.bindings);
  bindings.set(trust.manifest_name, Object.freeze({ bytes: manifestSnapshot.size, sha256: manifestSnapshot.sha256 }));
  bindings.set(trust.signature_name, Object.freeze({ bytes: signature.size, sha256: signature.sha256 }));
  bindings.set(trust.public_key_name, Object.freeze({ bytes: publicKey.size, sha256: publicKey.sha256 }));
  bindings.set(trust.product_name, Object.freeze({ bytes: release.product.bytes, sha256: release.product.sha256 }));
  const entries = fileSystem.readdirSync(destination).sort();
  if (entries.length !== names.size || entries.some((name) => !names.has(name)) || entries.includes(trust.run_binding_name)) fail('installed release inventory is not exact');
  const files = new Map();
  for (const name of entries) {
    const maximum = name === trust.product_name || name.endsWith('.tar') || name.endsWith('.pkg') ? QUALIFICATION_RELEASE_MAX_FILE_BYTES : QUALIFICATION_RELEASE_MAX_SMALL_FILE_BYTES;
    const snapshot = readStableFile(join(destination, name), { fileSystem, expectedUid, production, maximum, exactMode: FILE_MODE, label: `installed release file ${name}` });
    const expected = bindings.get(name);
    if (!expected || snapshot.size !== expected.bytes || snapshot.sha256 !== expected.sha256) fail(`installed release file ${name} does not match the signed inventory`);
    files.set(name, snapshot.identity);
  }
  return Object.freeze({ destinationIdentity: destinationState.identity, files });
};

const recover = ({
  destination = FIXED_QUALIFICATION_RELEASE_DIRECTORY,
  trustPath = FIXED_QUALIFICATION_RELEASE_TRUST_PATH,
  checkpointPath = FIXED_CANDIDATE_CHECKPOINT_PATH,
  expectedUid = 0,
  production = true,
  platform = process.platform,
  uid = process.getuid?.(),
  fileSystem = fs,
  identityReader,
  proveNoActiveQualificationProcesses = proveNoQualificationProcesses
} = {}) => {
  productionGuard({ production, platform, uid, expectedUid, destination, trustPath, checkpointPath, fileSystem, randomBytes: crypto.randomBytes });
  if (production && proveNoActiveQualificationProcesses !== proveNoQualificationProcesses) fail('qualification release recovery requires the fixed qualification process proof');
  if (typeof proveNoActiveQualificationProcesses !== 'function') fail('qualification release recovery requires a qualification process proof');
  absolutePath(destination, 'release destination');
  absolutePath(trustPath, 'release trust');
  absolutePath(checkpointPath, 'candidate checkpoint');
  if (!Number.isInteger(expectedUid) || expectedUid < 0) fail('qualification release recovery options are invalid');
  const destinationParent = validateDirectory(dirname(destination), { fileSystem, expectedUid, production, exactMode: DIRECTORY_MODE, label: 'release destination parent' });
  if (basename(trustPath) !== TRUST_FILE_NAME || dirname(trustPath) !== destinationParent.path) fail('release trust destination is not fixed under the qualification root');
  const prove = () => { if (proveNoActiveQualificationProcesses() !== true) fail('qualification process remained active'); };
  prove();

  let trustState;
  let destinationState;
  try { trustState = fileSystem.lstatSync(trustPath, { bigint: true }); } catch (error) { if (!isMissing(error)) fail('release trust state is unavailable'); }
  try { destinationState = fileSystem.lstatSync(destination, { bigint: true }); } catch (error) { if (!isMissing(error)) fail('release directory state is unavailable'); }
  const trustMissing = trustState === undefined;
  const destinationMissing = destinationState === undefined;
  if (trustMissing && destinationMissing) return Object.freeze({ ok: true, action: 'already-recovered', release_directory: destination, trust_path: trustPath });
  if (trustMissing !== destinationMissing) fail('release recovery refused a partial release state');

  const checkpoint = validateCheckpoint(checkpointPath, { fileSystem, expectedUid, production, identityReader });
  const trustSnapshot = readStableFile(trustPath, { fileSystem, expectedUid, production, maximum: 32 * 1024, exactMode: FILE_MODE, label: 'release trust' });
  const trust = parseQualificationReleaseTrust(trustSnapshot.bytes);
  const inventory = releaseInventory({ checkpoint, trust, fileSystem, expectedUid, production, platform, uid, identityReader, destination, trustPath });
  prove();

  if (!removeExactOwnedFile(trustPath, trustSnapshot.identity, { fileSystem, expectedUid, label: 'release trust' })) fail('release trust removal was refused');
  fsyncDirectory(destinationParent.path, fileSystem);
  for (const [name, identity] of [...inventory.files.entries()].sort(([left], [right]) => left.localeCompare(right))) {
    if (!removeExactOwnedFile(join(destination, name), identity, { fileSystem, expectedUid, label: `release file ${name}` })) fail(`release file ${name} removal was refused`);
  }
  fsyncDirectory(destination, fileSystem);
  let currentDirectory;
  try { currentDirectory = fileSystem.lstatSync(destination, { bigint: true }); } catch { fail('release directory changed before removal'); }
  if (!currentDirectory.isDirectory() || currentDirectory.isSymbolicLink() || currentDirectory.uid !== BigInt(expectedUid) || (currentDirectory.mode & 0o7777n) !== BigInt(DIRECTORY_MODE) || !sameDirectoryIdentity(statIdentity(currentDirectory), inventory.destinationIdentity) || fileSystem.readdirSync(destination).length !== 0) fail('release directory removal was refused');
  try { fileSystem.rmdirSync(destination); } catch { fail('release directory removal failed'); }
  fsyncDirectory(destinationParent.path, fileSystem);
  return Object.freeze({ ok: true, action: 'recovered', release_directory: destination, trust_path: trustPath, files: inventory.files.size, candidate_checkpoint_sha256: checkpoint.checkpoint_sha256 });
};

export const recoverQualificationRelease = (options = {}) => recover(options);
export const recoverFixedQualificationRelease = recoverQualificationRelease;

export const parseQualificationReleaseMaterializerCLI = (args) => {
  if (Array.isArray(args) && args.length === 1 && args[0] === 'recover') return Object.freeze({ operation: 'recover' });
  if (!Array.isArray(args) || args.length !== 7 || args[0] !== 'materialize') fail(CLI_USAGE);
  return Object.freeze({
    operation: 'materialize',
    source: Object.freeze({ releaseDirectory: args[1], manifestPath: args[2], signaturePath: args[3], publicKeyPath: args[4], productPath: args[6] }),
    expectedFingerprint: args[5]
  });
};

if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
  try {
    const options = parseQualificationReleaseMaterializerCLI(process.argv.slice(2));
    const result = options.operation === 'recover'
      ? recoverFixedQualificationRelease()
      : materializeQualificationRelease({ source: options.source, expectedFingerprint: options.expectedFingerprint });
    process.stdout.write(`${JSON.stringify(result)}\n`);
  } catch (error) {
    process.stderr.write(`${error?.message === CLI_USAGE ? CLI_USAGE : 'qualification release materialization refused'}\n`);
    process.exitCode = 2;
  }
}
