#!/usr/bin/env node
import crypto from 'node:crypto';
import fs from 'node:fs';
import { spawnSync } from 'node:child_process';
import { dirname, isAbsolute, relative, resolve, sep } from 'node:path';

const SCHEMA_VERSION = 1;
const MAX_CHECKPOINT_BYTES = 1024 * 1024;
const MAX_CODE_OBJECTS = 128;
const MAX_CODE_OBJECT_BYTES = 512 * 1024 * 1024;
const MAX_TREE_ENTRIES = 100_000;
const MAX_DESIGNATED_REQUIREMENT_BYTES = 16 * 1024;
const DIGEST = /^[0-9a-f]{64}$/u;
const COMMIT = /^[0-9a-f]{40}$/u;
const TEAM_ID = /^[A-Z0-9]{10}$/u;
const CODE_HASH = /^[0-9a-f]{40}(?:[0-9a-f]{24})?$/u;
const ROLE = /^[a-z][a-z0-9-]{0,63}$/u;
const BUNDLE_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,255}$/u;
const DECIMAL = /^(?:0|[1-9][0-9]*)$/u;
const FIXED_ENV = Object.freeze({ HOME: '/var/empty', LANG: 'C', LC_ALL: 'C', PATH: '/usr/bin:/bin:/usr/sbin:/sbin' });
const O_DIRECTORY = fs.constants.O_DIRECTORY ?? 0;

const exactKeys = (value, keys, label) => {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new Error(`${label} must be an object`);
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) throw new Error(`${label} has missing or unknown fields`);
};

const sha256 = (bytes) => crypto.createHash('sha256').update(bytes).digest('hex');
const canonicalJSON = (value) => Buffer.from(`${JSON.stringify(value, null, 2)}\n`, 'utf8');

const identityFields = Object.freeze(['dev', 'ino', 'mode', 'nlink', 'size', 'mtime_ns', 'ctime_ns', 'uid', 'gid']);

const statIdentity = (stat) => Object.freeze({
  dev: stat.dev.toString(),
  ino: stat.ino.toString(),
  mode: stat.mode.toString(),
  nlink: stat.nlink.toString(),
  size: stat.size.toString(),
  mtime_ns: stat.mtimeNs.toString(),
  ctime_ns: stat.ctimeNs.toString(),
  uid: stat.uid.toString(),
  gid: stat.gid.toString()
});

const identityEqual = (left, right) => identityFields.every((key) => left[key] === right[key]);

const validateIdentity = (value, label) => {
  exactKeys(value, identityFields, label);
  for (const key of identityFields) if (!DECIMAL.test(value[key])) throw new Error(`${label}.${key} is invalid`);
  const mode = BigInt(value.mode);
  const fileType = mode & 0o170000n;
  if (fileType === 0o40000n) {
    if (BigInt(value.nlink) < 2n || (mode & 0o022n) !== 0n) throw new Error(`${label} directory identity is unsafe`);
  } else if (fileType === 0o100000n) {
    if (BigInt(value.nlink) !== 1n || (mode & 0o111n) === 0n || (mode & 0o022n) !== 0n) throw new Error(`${label} file identity is unsafe`);
  } else throw new Error(`${label} has an unsupported file type`);
  return Object.freeze(Object.fromEntries(identityFields.map((key) => [key, value[key]])));
};

const validateAbsolutePath = (value, label) => {
  if (typeof value !== 'string' || !isAbsolute(value) || resolve(value) !== value || value.includes('\0')) throw new Error(`${label} is invalid`);
  return value;
};

const validateMetadata = (value, label) => {
  exactKeys(value, ['bundle_id', 'team_id', 'code_directory_hash', 'designated_requirement'], label);
  if (!BUNDLE_ID.test(value.bundle_id) || !TEAM_ID.test(value.team_id) || !CODE_HASH.test(value.code_directory_hash) || typeof value.designated_requirement !== 'string' || value.designated_requirement.length === 0 || Buffer.byteLength(value.designated_requirement, 'utf8') > MAX_DESIGNATED_REQUIREMENT_BYTES || /[\u0000\r\n]/u.test(value.designated_requirement)) throw new Error(`${label} is invalid`);
  return Object.freeze({ bundle_id: value.bundle_id, team_id: value.team_id, code_directory_hash: value.code_directory_hash, designated_requirement: value.designated_requirement });
};

const validateCodeObject = (value, label = 'code object') => {
  exactKeys(value, ['path', 'role', 'bundle_id', 'team_id', 'code_directory_hash', 'designated_requirement', 'sha256', 'file_identity'], label);
  const path = validateAbsolutePath(value.path, `${label}.path`);
  if (!ROLE.test(value.role) || !DIGEST.test(value.sha256)) throw new Error(`${label} is invalid`);
  return Object.freeze({ path, role: value.role, ...validateMetadata({ bundle_id: value.bundle_id, team_id: value.team_id, code_directory_hash: value.code_directory_hash, designated_requirement: value.designated_requirement }, label), sha256: value.sha256, file_identity: validateIdentity(value.file_identity, `${label}.file_identity`) });
};

const validateDescriptor = (value, label = 'code object descriptor') => {
  exactKeys(value, ['path', 'role', 'bundle_id', 'team_id', 'code_directory_hash', 'designated_requirement'], label);
  if (!ROLE.test(value.role)) throw new Error(`${label}.role is invalid`);
  return Object.freeze({ path: validateAbsolutePath(value.path, `${label}.path`), role: value.role, ...validateMetadata({ bundle_id: value.bundle_id, team_id: value.team_id, code_directory_hash: value.code_directory_hash, designated_requirement: value.designated_requirement }, label) });
};

const checkpointBody = (value) => {
  const { checkpoint_sha256: ignored, ...body } = value;
  return body;
};

export const candidateCheckpointHash = (value) => sha256(canonicalJSON(checkpointBody(value)));

export const validateCandidateCheckpoint = (value) => {
  exactKeys(value, ['schema_version', 'artifact_sha256', 'source_commit', 'team_id', 'application_path', 'code_objects', 'checkpoint_sha256'], 'candidate checkpoint');
  if (value.schema_version !== SCHEMA_VERSION || !DIGEST.test(value.artifact_sha256) || !COMMIT.test(value.source_commit) || !TEAM_ID.test(value.team_id) || !DIGEST.test(value.checkpoint_sha256)) throw new Error('candidate checkpoint binding is invalid');
  const applicationPath = validateAbsolutePath(value.application_path, 'candidate checkpoint.application_path');
  if (!Array.isArray(value.code_objects) || value.code_objects.length === 0 || value.code_objects.length > MAX_CODE_OBJECTS) throw new Error('candidate checkpoint code object inventory is invalid');
  const codeObjects = value.code_objects.map((item, index) => validateCodeObject(item, `candidate checkpoint.code_objects[${index}]`));
  const sorted = [...codeObjects].sort((left, right) => left.path.localeCompare(right.path));
  if (sorted.some((item, index) => item.path !== codeObjects[index].path) || new Set(codeObjects.map((item) => item.path)).size !== codeObjects.length) throw new Error('candidate checkpoint code objects are not strictly sorted');
  const applicationObject = codeObjects.find((item) => item.role === 'application');
  if (!applicationObject || applicationObject.path !== applicationPath || codeObjects.filter((item) => item.role === 'application').length !== 1 || new Set(codeObjects.map((item) => item.role)).size !== codeObjects.length) throw new Error('candidate checkpoint code object roles are invalid');
  for (const item of codeObjects) {
    const childPath = relative(applicationPath, item.path);
    if (childPath.startsWith(`..${sep}`) || childPath === '..' || isAbsolute(childPath)) throw new Error('candidate checkpoint code object escapes application');
    if (item.team_id !== value.team_id) throw new Error('candidate checkpoint code object Team ID mismatch');
  }
  const normalized = Object.freeze({ schema_version: SCHEMA_VERSION, artifact_sha256: value.artifact_sha256, source_commit: value.source_commit, team_id: value.team_id, application_path: applicationPath, code_objects: Object.freeze(codeObjects), checkpoint_sha256: value.checkpoint_sha256 });
  if (candidateCheckpointHash(normalized) !== normalized.checkpoint_sha256) throw new Error('candidate checkpoint digest mismatch');
  return normalized;
};

const validateDirectory = (input, { production, fsImpl }) => {
  const path = resolve(input);
  let finalStat;
  try { finalStat = fsImpl.lstatSync(path, { bigint: true }); } catch { throw new Error('candidate checkpoint directory is unavailable'); }
  if (!finalStat.isDirectory() || finalStat.isSymbolicLink()) throw new Error('candidate checkpoint directory is unsafe');
  let realPath;
  try { realPath = resolve(fsImpl.realpathSync(path)); } catch { throw new Error('candidate checkpoint directory is unavailable'); }
  let current = realPath;
  while (true) {
    let stat;
    try { stat = fsImpl.lstatSync(current, { bigint: true }); } catch { throw new Error('candidate checkpoint directory is unavailable'); }
    if (!stat.isDirectory() || stat.isSymbolicLink() || (stat.mode & 0o022n) !== 0n || (production && stat.uid !== 0n)) throw new Error('candidate checkpoint directory is unsafe');
    if (current === '/') break;
    current = dirname(current);
  }
  return path;
};

const validateProtectedFile = (input, { production, fsImpl, maximum = MAX_CHECKPOINT_BYTES } = {}) => {
  const path = validateAbsolutePath(input, 'candidate checkpoint path');
  validateDirectory(dirname(path), { production, fsImpl });
  let descriptor;
  try { descriptor = fsImpl.openSync(path, fsImpl.constants.O_RDONLY | fsImpl.constants.O_NOFOLLOW); } catch { throw new Error('candidate checkpoint is unavailable'); }
  try {
    const before = fsImpl.fstatSync(descriptor, { bigint: true });
    if (!before.isFile() || before.nlink !== 1n || before.size <= 0n || before.size > BigInt(maximum) || (before.mode & 0o7777n) !== 0o600n || (production && before.uid !== 0n)) throw new Error('candidate checkpoint file is unsafe');
    const bytes = Buffer.alloc(Number(before.size));
    let offset = 0;
    while (offset < bytes.length) {
      const count = fsImpl.readSync(descriptor, bytes, offset, bytes.length - offset, offset);
      if (count === 0) throw new Error('candidate checkpoint changed while reading');
      offset += count;
    }
    const after = fsImpl.fstatSync(descriptor, { bigint: true });
    const beforeIdentity = statIdentity(before);
    const afterIdentity = statIdentity(after);
    if (!identityEqual(beforeIdentity, afterIdentity)) throw new Error('candidate checkpoint changed while reading');
    return Object.freeze({ path, bytes, identity: afterIdentity });
  } finally { fsImpl.closeSync(descriptor); }
};

const safePathStat = (path, { production, fsImpl }) => {
  validateDirectory(dirname(path), { production, fsImpl });
  let descriptor;
  try { descriptor = fsImpl.openSync(path, fsImpl.constants.O_RDONLY | fsImpl.constants.O_NOFOLLOW); } catch { throw new Error('installed code object is unavailable'); }
  try {
    const before = fsImpl.fstatSync(descriptor, { bigint: true });
    const directory = before.isDirectory();
    if ((!before.isFile() && !directory) || (before.mode & 0o022n) !== 0n || (production && before.uid !== 0n) || (!directory && (before.nlink !== 1n || (before.mode & 0o111n) === 0n)) || before.size > BigInt(MAX_CODE_OBJECT_BYTES)) throw new Error('installed code object is unsafe');
    return { descriptor, before, directory };
  } catch (error) { fsImpl.closeSync(descriptor); throw error; }
};

const digestFile = (path, descriptor, before, { fsImpl }) => {
  const bytes = Buffer.alloc(Number(before.size));
  let offset = 0;
  while (offset < bytes.length) {
    const count = fsImpl.readSync(descriptor, bytes, offset, bytes.length - offset, offset);
    if (count === 0) throw new Error('installed code object changed while reading');
    offset += count;
  }
  const after = fsImpl.fstatSync(descriptor, { bigint: true });
  if (!identityEqual(statIdentity(before), statIdentity(after))) throw new Error('installed code object changed while reading');
  return { sha256: sha256(bytes), identity: statIdentity(after) };
};

const digestDirectory = (path, descriptor, before, { production, fsImpl }) => {
  fsImpl.closeSync(descriptor);
  let entries = 0;
  let totalBytes = 0n;
  const hash = crypto.createHash('sha256');
  const visit = (directory, relativePath, expectedIdentity) => {
    const directoryHandle = safePathStat(directory, { production, fsImpl });
    if (!directoryHandle.directory) { fsImpl.closeSync(directoryHandle.descriptor); throw new Error('installed code object tree is unsafe'); }
    const directoryBefore = statIdentity(directoryHandle.before);
    if (expectedIdentity && !identityEqual(directoryBefore, expectedIdentity)) { fsImpl.closeSync(directoryHandle.descriptor); throw new Error('installed code object changed while reading'); }
    fsImpl.closeSync(directoryHandle.descriptor);
    const names = fsImpl.readdirSync(directory, { encoding: 'utf8' }).sort();
    const directoryAfterHandle = safePathStat(directory, { production, fsImpl });
    try {
      if (!directoryAfterHandle.directory || !identityEqual(directoryBefore, statIdentity(directoryAfterHandle.before))) throw new Error('installed code object changed while reading');
    } finally { fsImpl.closeSync(directoryAfterHandle.descriptor); }
    for (const name of names) {
      if (name === '.' || name === '..' || name.includes('\0') || name.includes('/')) throw new Error('installed code object contains an invalid entry');
      entries += 1;
      if (entries > MAX_TREE_ENTRIES) throw new Error('installed code object tree is too large');
      const child = resolve(directory, name);
      const childStat = fsImpl.lstatSync(child, { bigint: true });
      if (childStat.isSymbolicLink() || (childStat.mode & 0o022n) !== 0n || (production && childStat.uid !== 0n)) throw new Error('installed code object tree is unsafe');
      const childRelative = `${relativePath}/${name}`;
      if (childStat.isDirectory()) {
        hash.update(`D\0${childRelative}\0${childStat.mode.toString()}\0`);
        visit(child, childRelative, statIdentity(childStat));
      } else if (childStat.isFile()) {
        if (childStat.nlink !== 1n || childStat.size > BigInt(MAX_CODE_OBJECT_BYTES) || totalBytes + childStat.size > BigInt(MAX_CODE_OBJECT_BYTES)) throw new Error('installed code object tree is unsafe');
        const childHandle = safePathStat(child, { production, fsImpl });
        try {
          const content = digestFile(child, childHandle.descriptor, childHandle.before, { fsImpl });
          totalBytes += childHandle.before.size;
          hash.update(`F\0${childRelative}\0${childHandle.before.mode.toString()}\0${content.sha256}\0`);
        } finally { fsImpl.closeSync(childHandle.descriptor); }
      } else throw new Error('installed code object tree contains unsupported entry');
    }
  };
  visit(path, '', statIdentity(before));
  let after;
  const reopen = safePathStat(path, { production, fsImpl });
  try { after = reopen.before; } finally { fsImpl.closeSync(reopen.descriptor); }
  if (!identityEqual(statIdentity(before), statIdentity(after))) throw new Error('installed code object changed while reading');
  return { sha256: hash.digest('hex'), identity: statIdentity(after), directory: true };
};

export const observeInstalledFileIdentity = (input, { production = process.platform === 'darwin', fsImpl = fs } = {}) => {
  const path = validateAbsolutePath(input, 'installed code object path');
  const handle = safePathStat(path, { production, fsImpl });
  if (handle.directory) return digestDirectory(path, handle.descriptor, handle.before, { production, fsImpl });
  try { return { ...digestFile(path, handle.descriptor, handle.before, { fsImpl }), directory: false }; } finally { fsImpl.closeSync(handle.descriptor); }
};

const parseCodesign = (path, { runner = spawnSync } = {}) => {
  if (process.platform !== 'darwin' && runner === spawnSync) throw new Error('codesign identity inspection requires macOS');
  const result = runner('/usr/bin/codesign', ['--display', '--verbose=4', '--strict', path], { cwd: '/', env: FIXED_ENV, shell: false, encoding: 'utf8', maxBuffer: 128 * 1024 });
  if (!result || result.error || result.status !== 0 || result.signal) throw new Error('installed code signature inspection failed');
  const output = `${result.stderr ?? ''}\n${result.stdout ?? ''}`;
  const value = {
    bundle_id: /^Identifier=(.+)$/mu.exec(output)?.[1]?.trim(),
    team_id: /^TeamIdentifier=(.+)$/mu.exec(output)?.[1]?.trim(),
    code_directory_hash: /^CDHash=(.+)$/mu.exec(output)?.[1]?.trim()?.toLowerCase(),
    designated_requirement: /^designated => (.+)$/mu.exec(output)?.[1]?.trim()
  };
  return validateMetadata(value, 'codesign identity');
};

const defaultIdentityReader = (path, options) => parseCodesign(path, options);

export const readInstalledCodeSignatureIdentity = (path, options = {}) => parseCodesign(path, options);

const observeCodeObject = (descriptor, { production, fsImpl, identityReader, identityReaderOptions } = {}) => {
  const file = observeInstalledFileIdentity(descriptor.path, { production, fsImpl });
  if (descriptor.role === 'application' && !file.directory) throw new Error('candidate application is not a directory');
  if (descriptor.sha256 !== undefined && file.sha256 !== descriptor.sha256) throw new Error('installed code object digest mismatch');
  if (descriptor.file_identity !== undefined && !identityEqual(file.identity, descriptor.file_identity)) throw new Error('installed code object identity mismatch');
  const metadata = validateMetadata(identityReader(descriptor.path, { production, fsImpl, ...identityReaderOptions }), 'observed code identity');
  if (metadata.bundle_id !== descriptor.bundle_id || metadata.team_id !== descriptor.team_id || metadata.code_directory_hash !== descriptor.code_directory_hash || metadata.designated_requirement !== descriptor.designated_requirement) throw new Error('installed code signature identity mismatch');
  return Object.freeze({ ...descriptor, sha256: file.sha256, file_identity: file.identity });
};

const descriptorFromObject = (value) => {
  if (Object.prototype.hasOwnProperty.call(value, 'sha256') || Object.prototype.hasOwnProperty.call(value, 'file_identity')) return validateCodeObject(value);
  return validateDescriptor({ path: value.path, role: value.role, bundle_id: value.bundle_id, team_id: value.team_id, code_directory_hash: value.code_directory_hash, designated_requirement: value.designated_requirement });
};

const validateCreateInput = (input) => {
  exactKeys(input, ['checkpoint_path', 'artifact_sha256', 'source_commit', 'team_id', 'application_path', 'code_objects'], 'candidate checkpoint creation request');
  if (!DIGEST.test(input.artifact_sha256) || !COMMIT.test(input.source_commit) || !TEAM_ID.test(input.team_id)) throw new Error('candidate checkpoint creation binding is invalid');
  const applicationPath = validateAbsolutePath(input.application_path, 'candidate checkpoint.application_path');
  if (!Array.isArray(input.code_objects) || input.code_objects.length === 0 || input.code_objects.length > MAX_CODE_OBJECTS) throw new Error('candidate checkpoint creation inventory is invalid');
  const descriptors = input.code_objects.map((item, index) => descriptorFromObject(item, `candidate checkpoint descriptor[${index}]`));
  const sorted = [...descriptors].sort((left, right) => left.path.localeCompare(right.path));
  if (sorted.some((item, index) => item.path !== descriptors[index].path) || new Set(descriptors.map((item) => item.path)).size !== descriptors.length) throw new Error('candidate checkpoint descriptors are not strictly sorted');
  if (!descriptors.some((item) => item.role === 'application' && item.path === applicationPath) || descriptors.filter((item) => item.role === 'application').length !== 1 || new Set(descriptors.map((item) => item.role)).size !== descriptors.length) throw new Error('candidate checkpoint descriptor roles are invalid');
  for (const item of descriptors) {
    const childPath = relative(applicationPath, item.path);
    if (childPath.startsWith(`..${sep}`) || childPath === '..' || isAbsolute(childPath) || item.team_id !== input.team_id) throw new Error('candidate checkpoint descriptor is outside the candidate');
  }
  return Object.freeze({ checkpointPath: validateAbsolutePath(input.checkpoint_path, 'candidate checkpoint path'), artifactSha256: input.artifact_sha256, sourceCommit: input.source_commit, teamId: input.team_id, applicationPath, descriptors: Object.freeze(descriptors) });
};

const publishExclusive = (path, bytes, { production, fsImpl, randomBytes = crypto.randomBytes }) => {
  const parent = validateDirectory(dirname(path), { production, fsImpl });
  if (typeof randomBytes !== 'function') throw new Error('candidate checkpoint random source is invalid');
  const suffix = randomBytes(16).toString('hex');
  const temporary = resolve(parent, `.${path.split('/').pop()}.${suffix}.tmp`);
  let tempDescriptor;
  try {
    tempDescriptor = fsImpl.openSync(temporary, fsImpl.constants.O_WRONLY | fsImpl.constants.O_CREAT | fsImpl.constants.O_EXCL | fsImpl.constants.O_NOFOLLOW, 0o600);
    let offset = 0;
    while (offset < bytes.length) {
      const written = fsImpl.writeSync(tempDescriptor, bytes, offset, bytes.length - offset);
      if (written <= 0) throw new Error('candidate checkpoint staging write failed');
      offset += written;
    }
    const staged = fsImpl.fstatSync(tempDescriptor, { bigint: true });
    if (!staged.isFile() || staged.nlink !== 1n || staged.size !== BigInt(bytes.length) || (staged.mode & 0o7777n) !== 0o600n || (production && staged.uid !== 0n)) throw new Error('candidate checkpoint staging file is unsafe');
    fsImpl.fsyncSync(tempDescriptor);
    fsImpl.closeSync(tempDescriptor);
    tempDescriptor = undefined;
    fsImpl.linkSync(temporary, path);
    fsImpl.unlinkSync(temporary);
    const directoryDescriptor = fsImpl.openSync(parent, fsImpl.constants.O_RDONLY | O_DIRECTORY | fsImpl.constants.O_NOFOLLOW);
    try { fsImpl.fsyncSync(directoryDescriptor); } finally { fsImpl.closeSync(directoryDescriptor); }
  } finally {
    if (tempDescriptor !== undefined) fsImpl.closeSync(tempDescriptor);
    try { fsImpl.unlinkSync(temporary); } catch { /* already linked and removed, or publication failed before creation */ }
  }
  return path;
};

export const writeCandidateCheckpoint = ({ checkpointPath, checkpoint }, { production = process.platform === 'darwin', fsImpl = fs, randomBytes = crypto.randomBytes } = {}) => {
  const path = validateAbsolutePath(checkpointPath, 'candidate checkpoint path');
  const normalized = validateCandidateCheckpoint(checkpoint);
  const bytes = canonicalJSON(normalized);
  if (bytes.length > MAX_CHECKPOINT_BYTES) throw new Error('candidate checkpoint is too large');
  publishExclusive(path, bytes, { production, fsImpl, randomBytes });
  const stored = readCandidateCheckpoint(path, { production, fsImpl });
  if (JSON.stringify(stored) !== JSON.stringify(normalized)) throw new Error('candidate checkpoint publication verification failed');
  return stored;
};

export const mintCandidateCheckpoint = (input, { production = process.platform === 'darwin', fsImpl = fs, identityReader = defaultIdentityReader, identityReaderOptions, randomBytes = crypto.randomBytes } = {}) => {
  const request = validateCreateInput(input);
  if (typeof identityReader !== 'function') throw new Error('candidate identity reader is invalid');
  const codeObjects = request.descriptors.map((descriptor) => observeCodeObject(descriptor, { production, fsImpl, identityReader, identityReaderOptions }));
  const body = { schema_version: SCHEMA_VERSION, artifact_sha256: request.artifactSha256, source_commit: request.sourceCommit, team_id: request.teamId, application_path: request.applicationPath, code_objects: codeObjects };
  const checkpoint = { ...body, checkpoint_sha256: candidateCheckpointHash(body) };
  return writeCandidateCheckpoint({ checkpointPath: request.checkpointPath, checkpoint }, { production, fsImpl, randomBytes });
};

const readSnapshot = (checkpointPath, options) => {
  const snapshot = validateProtectedFile(checkpointPath, options);
  let value;
  try { value = JSON.parse(snapshot.bytes.toString('utf8')); } catch { throw new Error('candidate checkpoint is invalid JSON'); }
  if (!snapshot.bytes.equals(canonicalJSON(value))) throw new Error('candidate checkpoint is not canonical JSON');
  return Object.freeze({ checkpoint: validateCandidateCheckpoint(value), identity: snapshot.identity });
};

export const readCandidateCheckpoint = (checkpointPath, { production = process.platform === 'darwin', fsImpl = fs } = {}) => readSnapshot(checkpointPath, { production, fsImpl }).checkpoint;

const compareBindings = (checkpoint, expected = {}) => {
  if (expected.artifactSha256 !== undefined && checkpoint.artifact_sha256 !== expected.artifactSha256) throw new Error('candidate checkpoint artifact binding mismatch');
  if (expected.sourceCommit !== undefined && checkpoint.source_commit !== expected.sourceCommit) throw new Error('candidate checkpoint source binding mismatch');
  if (expected.teamId !== undefined && checkpoint.team_id !== expected.teamId) throw new Error('candidate checkpoint Team ID binding mismatch');
  if (expected.applicationPath !== undefined && checkpoint.application_path !== expected.applicationPath) throw new Error('candidate checkpoint application binding mismatch');
};

export const verifyCandidateCheckpoint = (checkpointPath, { expected = {}, production = process.platform === 'darwin', fsImpl = fs, identityReader = defaultIdentityReader, identityReaderOptions } = {}) => {
  if (typeof identityReader !== 'function') throw new Error('candidate identity reader is invalid');
  const before = readSnapshot(checkpointPath, { production, fsImpl });
  compareBindings(before.checkpoint, expected);
  for (const object of before.checkpoint.code_objects) {
    const observed = observeCodeObject(descriptorFromObject(object), { production, fsImpl, identityReader, identityReaderOptions });
    if (observed.sha256 !== object.sha256 || !identityEqual(observed.file_identity, object.file_identity)) throw new Error('installed code object checkpoint identity mismatch');
  }
  const after = readSnapshot(checkpointPath, { production, fsImpl });
  if (!identityEqual(before.identity, after.identity) || JSON.stringify(before.checkpoint) !== JSON.stringify(after.checkpoint)) throw new Error('candidate checkpoint changed during verification');
  return after.checkpoint;
};

export const withVerifiedCandidateCheckpoint = async (checkpointPath, operation, options = {}) => {
  if (typeof operation !== 'function') throw new Error('candidate checkpoint operation is invalid');
  const before = verifyCandidateCheckpoint(checkpointPath, options);
  const result = await operation(before);
  verifyCandidateCheckpoint(checkpointPath, options);
  return result;
};
