#!/usr/bin/env node
import crypto from 'node:crypto';
import fs from 'node:fs';
import nodePath from 'node:path';
import { fileURLToPath } from 'node:url';

export const QUALIFICATION_RUN_BINDING_DIRECTORY = '/private/var/db/agentpass-qualification/release';
export const QUALIFICATION_RUN_BINDING_PATH = `${QUALIFICATION_RUN_BINDING_DIRECTORY}/run-binding`;
export const FIXED_QUALIFICATION_RUN_BINDING_PATH = QUALIFICATION_RUN_BINDING_PATH;
export const QUALIFICATION_RUN_BINDING_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;
export const QUALIFICATION_RUN_BINDING_MAX_BYTES = 128;

const NOFOLLOW = fs.constants.O_NOFOLLOW;
const O_DIRECTORY = fs.constants.O_DIRECTORY ?? 0;
const DIRECTORY_MODE = 0o700;
const FILE_MODE = 0o600;
const fail = (message) => { throw new Error(message); };

const getFileSystem = (options) => options.fileSystem ?? options.fsImpl ?? options.fs ?? fs;

const getPathModule = (options) => {
  if (options.pathImpl && typeof options.pathImpl === 'object') return options.pathImpl;
  if (options.path && typeof options.path === 'object') return options.path;
  return nodePath;
};

const getDestination = (options, pathModule) => {
  if (typeof options.destination === 'string') return options.destination;
  if (typeof options.runBindingPath === 'string') return options.runBindingPath;
  if (typeof options.path === 'string') return options.path;
  return QUALIFICATION_RUN_BINDING_PATH;
};

const getUid = (options) => options.uid ?? process.getuid?.();
const getPlatform = (options) => options.platform ?? process.platform;
const getExpectedUid = (options) => options.expectedUid ?? 0;

const absolutePath = (value, label, pathModule) => {
  if (typeof value !== 'string' || value.length === 0 || value.includes('\0') || !pathModule.isAbsolute(value) || pathModule.resolve(value) !== value) fail(`${label} path is invalid`);
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

const identityString = (identity) => [
  identity.dev, identity.ino, identity.mode, identity.nlink, identity.size,
  identity.mtime_ns, identity.ctime_ns, identity.uid, identity.gid
].join(':');

const sameIdentity = (left, right) => identityString(left) === identityString(right);

const validateIdentity = (value, label) => {
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail(`${label} is invalid`);
  const keys = ['dev', 'ino', 'mode', 'nlink', 'size', 'mtime_ns', 'ctime_ns', 'uid', 'gid'];
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) fail(`${label} is invalid`);
  for (const key of keys) if (typeof value[key] !== 'string' || !/^[0-9]+$/u.test(value[key])) fail(`${label} is invalid`);
  if ((BigInt(value.mode) & 0o170000n) !== 0o100000n || BigInt(value.nlink) !== 1n || (BigInt(value.mode) & 0o7777n) !== BigInt(FILE_MODE)) fail(`${label} is unsafe`);
  return Object.freeze(Object.fromEntries(keys.map((key) => [key, value[key]])));
};

const validateRunBinding = (value) => {
  if (typeof value !== 'string' || value.length === 0 || value.length > 128 || value.includes('\n') || value.includes('\r') || !QUALIFICATION_RUN_BINDING_PATTERN.test(value)) fail('qualification run binding is invalid');
  if (Buffer.byteLength(value, 'utf8') > QUALIFICATION_RUN_BINDING_MAX_BYTES) fail('qualification run binding is too large');
  return value;
};

export { validateRunBinding as validateQualificationRunBinding };

const productionGuard = ({ production, platform, uid, expectedUid, destination, fileSystem }) => {
  if (production && (platform !== 'darwin' || uid !== 0 || expectedUid !== 0 || destination !== QUALIFICATION_RUN_BINDING_PATH || fileSystem !== fs)) fail('qualification run binding requires root on macOS and the fixed path');
  if (!production && uid !== expectedUid) fail('qualification run binding requires the expected owner');
};

const protectedDirectory = (directory, { fileSystem, expectedUid, production, pathModule }) => {
  let current = directory;
  for (;;) {
    let stat;
    try { stat = fileSystem.lstatSync(current, { bigint: true }); } catch { fail('qualification run binding directory is unavailable'); }
    if (!stat.isDirectory() || stat.isSymbolicLink() || stat.uid !== BigInt(expectedUid) || (stat.mode & 0o022n) !== 0n) fail('qualification run binding directory is unsafe');
    if (current === directory && (stat.mode & 0o7777n) !== BigInt(DIRECTORY_MODE)) fail('qualification run binding directory mode is unsafe');
    if (!production || current === '/') break;
    const parent = pathModule.dirname(current);
    if (parent === current) break;
    current = parent;
  }
};

const fsyncDirectory = (directory, fileSystem) => {
  if (!Number.isInteger(NOFOLLOW)) fail('qualification run binding requires O_NOFOLLOW');
  let descriptor;
  try { descriptor = fileSystem.openSync(directory, fileSystem.constants.O_RDONLY | O_DIRECTORY | NOFOLLOW); }
  catch { fail('qualification run binding directory sync failed'); }
  try { fileSystem.fsyncSync(descriptor); }
  catch { fail('qualification run binding directory sync failed'); }
  finally {
    try { fileSystem.closeSync(descriptor); }
    catch { fail('qualification run binding directory sync failed'); }
  }
};

const assertAbsent = (destination, fileSystem) => {
  try { fileSystem.lstatSync(destination, { bigint: true }); fail('qualification run binding already exists; cleanup or recovery is required'); }
  catch (error) { if (error?.message?.includes('already exists')) throw error; if (error?.code !== 'ENOENT') throw error; }
};

const assertFile = (stat, expectedUid, expectedSize = null, expectedLinks = 1n) => {
  if (!stat.isFile() || stat.isSymbolicLink() || stat.uid !== BigInt(expectedUid) || stat.nlink !== expectedLinks || (stat.mode & 0o7777n) !== BigInt(FILE_MODE) || (expectedSize !== null && stat.size !== BigInt(expectedSize))) fail('qualification run binding file is unsafe');
};

const writeAll = (descriptor, bytes, fileSystem) => {
  let offset = 0;
  while (offset < bytes.length) {
    const count = fileSystem.writeSync(descriptor, bytes, offset, bytes.length - offset, offset);
    if (!Number.isInteger(count) || count <= 0) fail('qualification run binding write failed');
    offset += count;
  }
};

const readAll = (descriptor, size, fileSystem) => {
  const bytes = Buffer.alloc(size);
  let offset = 0;
  while (offset < bytes.length) {
    const count = fileSystem.readSync(descriptor, bytes, offset, bytes.length - offset, offset);
    if (!Number.isInteger(count) || count <= 0) fail('qualification run binding changed while reading');
    offset += count;
  }
  return bytes;
};

const readStable = (destination, { fileSystem, expectedUid, expectedLinks = 1n, pathModule }) => {
  let descriptor;
  try { descriptor = fileSystem.openSync(destination, fileSystem.constants.O_RDONLY | NOFOLLOW); }
  catch { fail('qualification run binding is unavailable'); }
  try {
    const before = fileSystem.fstatSync(descriptor, { bigint: true });
    assertFile(before, expectedUid, null, expectedLinks);
    if (before.size <= 0n || before.size > BigInt(QUALIFICATION_RUN_BINDING_MAX_BYTES)) fail('qualification run binding size is invalid');
    const bytes = readAll(descriptor, Number(before.size), fileSystem);
    const after = fileSystem.fstatSync(descriptor, { bigint: true });
    let current;
    try { current = fileSystem.lstatSync(destination, { bigint: true }); } catch { fail('qualification run binding changed while reading'); }
    assertFile(after, expectedUid, Number(before.size), expectedLinks);
    assertFile(current, expectedUid, Number(before.size), expectedLinks);
    const beforeIdentity = statIdentity(before);
    if (!sameIdentity(beforeIdentity, statIdentity(after)) || !sameIdentity(beforeIdentity, statIdentity(current))) fail('qualification run binding changed while reading');
    const value = bytes.toString('utf8');
    validateRunBinding(value);
    return Object.freeze({ value, bytes, identity: statIdentity(current), path: pathModule.resolve(destination) });
  } finally { fileSystem.closeSync(descriptor); }
};

const expectedCleanup = (expected) => {
  if (!expected || typeof expected !== 'object' || Array.isArray(expected)) fail('qualification run binding cleanup binding is required');
  const value = expected.value ?? expected.run_binding ?? expected.binding;
  validateRunBinding(value);
  const identity = validateIdentity(expected.identity ?? expected.file_identity, 'qualification run binding cleanup identity');
  return Object.freeze({ value, identity });
};

const resolveOptions = (options = {}) => {
  const pathModule = getPathModule(options);
  const fileSystem = getFileSystem(options);
  const destination = absolutePath(getDestination(options, pathModule), 'qualification run binding', pathModule);
  const expectedUid = getExpectedUid(options);
  const uid = getUid(options);
  if (!Number.isInteger(expectedUid) || expectedUid < 0 || !Number.isInteger(uid) || uid < 0) fail('qualification run binding owner is invalid');
  return { ...options, pathModule, fileSystem, destination, expectedUid, uid, platform: getPlatform(options), production: options.production ?? true };
};

export const readQualificationRunBinding = (options = {}) => {
  const resolved = resolveOptions(options);
  productionGuard(resolved);
  if (resolved.production && resolved.destination !== QUALIFICATION_RUN_BINDING_PATH) fail('qualification run binding path is not fixed');
  protectedDirectory(resolved.pathModule.dirname(resolved.destination), resolved);
  return readStable(resolved.destination, resolved);
};

export const materializeQualificationRunBinding = (options = {}) => {
  const resolved = resolveOptions(options);
  productionGuard(resolved);
  if (resolved.production && resolved.destination !== QUALIFICATION_RUN_BINDING_PATH) fail('qualification run binding path is not fixed');
  const value = options.value ?? options.runBinding ?? options.binding;
  validateRunBinding(value);
  const bytes = Buffer.from(value, 'utf8');
  const parent = resolved.pathModule.dirname(resolved.destination);
  protectedDirectory(parent, resolved);
  assertAbsent(resolved.destination, resolved.fileSystem);
  if (!Number.isInteger(NOFOLLOW)) fail('qualification run binding requires O_NOFOLLOW');

  const randomBytes = options.randomBytes ?? crypto.randomBytes;
  if (typeof randomBytes !== 'function') fail('qualification run binding random source is invalid');
  let random;
  try { random = randomBytes(16); } catch { fail('qualification run binding staging name generation failed'); }
  if (!(random instanceof Uint8Array) || random.length !== 16) fail('qualification run binding staging name generation failed');
  const processId = options.processId ?? process.pid;
  if (!Number.isInteger(processId) || processId < 0) fail('qualification run binding process identity is invalid');
  const staging = resolved.pathModule.join(parent, `.run-binding.${processId}.${Buffer.from(random).toString('hex')}.tmp`);
  let descriptor;
  let linked = false;
  try {
    descriptor = resolved.fileSystem.openSync(staging, resolved.fileSystem.constants.O_WRONLY | resolved.fileSystem.constants.O_CREAT | resolved.fileSystem.constants.O_EXCL | NOFOLLOW, FILE_MODE);
    const opened = resolved.fileSystem.fstatSync(descriptor, { bigint: true });
    assertFile(opened, resolved.expectedUid, 0, 1n);
    writeAll(descriptor, bytes, resolved.fileSystem);
    resolved.fileSystem.fchmodSync(descriptor, FILE_MODE);
    const staged = resolved.fileSystem.fstatSync(descriptor, { bigint: true });
    assertFile(staged, resolved.expectedUid, bytes.length, 1n);
    resolved.fileSystem.fsyncSync(descriptor);
    resolved.fileSystem.closeSync(descriptor);
    descriptor = undefined;

    protectedDirectory(parent, resolved);
    const beforeLink = resolved.fileSystem.lstatSync(staging, { bigint: true });
    assertFile(beforeLink, resolved.expectedUid, bytes.length, 1n);
    resolved.fileSystem.linkSync(staging, resolved.destination);
    linked = true;
    const published = readStable(resolved.destination, { ...resolved, expectedLinks: 2n });
    if (published.value !== value) fail('qualification run binding published value changed');
    resolved.fileSystem.unlinkSync(staging);
    const installed = readStable(resolved.destination, resolved);
    if (installed.value !== value) fail('qualification run binding published value changed');
    fsyncDirectory(parent, resolved.fileSystem);
    return Object.freeze({ ok: true, action: 'materialized', value, run_binding: value, path: installed.path, identity: installed.identity, bytes: bytes.length, sha256: crypto.createHash('sha256').update(bytes).digest('hex') });
  } catch {
    if (descriptor !== undefined) { try { resolved.fileSystem.closeSync(descriptor); } catch {} }
    try {
      const current = resolved.fileSystem.lstatSync(staging, { bigint: true });
      const expectedLinks = linked ? 2n : 1n;
      if (current.isFile() && !current.isSymbolicLink() && current.uid === BigInt(resolved.expectedUid) && current.nlink === expectedLinks && (current.mode & 0o7777n) === BigInt(FILE_MODE)) resolved.fileSystem.unlinkSync(staging);
    } catch {}
    fail('qualification run binding materialization failed');
  }
};

const removeInternal = (options = {}) => {
  const resolved = resolveOptions(options);
  productionGuard(resolved);
  if (resolved.production && resolved.destination !== QUALIFICATION_RUN_BINDING_PATH) fail('qualification run binding path is not fixed');
  const recovery = options.recovery === true;
  if (recovery && (typeof options.proveNoActiveRun !== 'function' || options.proveNoActiveRun() !== true)) fail('qualification run binding recovery refused an active run');
  const parent = resolved.pathModule.dirname(resolved.destination);
  protectedDirectory(parent, resolved);
  let exists;
  try { resolved.fileSystem.lstatSync(resolved.destination, { bigint: true }); exists = true; }
  catch (error) { if (error?.code === 'ENOENT' && recovery) return Object.freeze({ ok: true, action: 'absent', path: resolved.destination }); throw error; }
  if (!exists) fail('qualification run binding is unavailable');
  const current = readStable(resolved.destination, resolved);
  if (!recovery) {
    const expected = expectedCleanup(options.expected);
    if (current.value !== expected.value || !sameIdentity(current.identity, expected.identity)) fail('qualification run binding changed before cleanup');
  }
  const beforeRemove = resolved.fileSystem.lstatSync(resolved.destination, { bigint: true });
  if (!sameIdentity(current.identity, statIdentity(beforeRemove))) fail('qualification run binding changed before cleanup');
  resolved.fileSystem.unlinkSync(resolved.destination);
  fsyncDirectory(parent, resolved.fileSystem);
  return Object.freeze({ ok: true, action: 'removed', value: current.value, run_binding: current.value, path: resolved.destination, identity: current.identity, bytes: current.bytes.length });
};

export const removeQualificationRunBinding = (options = {}) => removeInternal(options);
export const recoverQualificationRunBinding = (options = {}) => removeInternal({ ...options, recovery: true });
export const materializeRunBinding = materializeQualificationRunBinding;
export const removeRunBinding = removeQualificationRunBinding;
export const recoverRunBinding = recoverQualificationRunBinding;
export const readRunBinding = readQualificationRunBinding;
export const materializeQualificationRunBindingForTest = (options = {}) => materializeQualificationRunBinding({ ...options, production: false });

if (process.argv[1] && fileURLToPath(import.meta.url) === nodePath.resolve(process.argv[1])) {
  process.stderr.write('qualification run binding materialization refused: fixed root orchestration required\n');
  process.exitCode = 2;
}
