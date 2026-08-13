#!/usr/bin/env node
import crypto from 'node:crypto';
import fs from 'node:fs';
import { dirname, isAbsolute, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  OUTPUT_FILES,
  canonicalJSON,
  makeControllerCandidate,
  readQualification
} from './controller-candidate-contract.mjs';

export const SERVICE_CONFIG_PATH = '/Library/Application Support/AgentPass/native-service.json';
export const CONTROLLER_CANDIDATE_DIRECTORY = '/private/var/db/agentpass-qualification/controller';

const MAX_CONFIG_BYTES = 1024 * 1024;
const MAX_CANDIDATE_BYTES = 1024 * 1024;
const NOFOLLOW = fs.constants.O_NOFOLLOW;
const O_DIRECTORY = fs.constants.O_DIRECTORY ?? 0;
const DIGEST = /^[0-9a-f]{64}$/u;

const fail = (message) => { throw new Error(message); };
const sha256 = (bytes) => crypto.createHash('sha256').update(bytes).digest('hex');
const identity = (stat) => [stat.dev, stat.ino, stat.mode, stat.nlink, stat.size, stat.mtimeNs, stat.ctimeNs, stat.uid, stat.gid].map(String).join(':');

const absolute = (value, label) => {
  if (typeof value !== 'string' || !isAbsolute(value) || resolve(value) !== value || value.includes('\0')) fail(`${label} path is invalid`);
  return value;
};

const protectedDirectory = (path, expectedUid) => {
  let stat;
  try { stat = fs.lstatSync(path, { bigint: true }); } catch { fail('controller candidate parent is unavailable'); }
  if (!stat.isDirectory() || stat.isSymbolicLink() || stat.uid !== BigInt(expectedUid) || (stat.mode & 0o022n) !== 0n) fail('controller candidate parent is unsafe');
};

const readStable = (path, label, maximum, expectedUid, exactMode) => {
  let descriptor;
  try { descriptor = fs.openSync(absolute(path, label), fs.constants.O_RDONLY | NOFOLLOW); }
  catch { fail(`${label} is unavailable`); }
  try {
    const before = fs.fstatSync(descriptor, { bigint: true });
    if (!before.isFile() || before.nlink !== 1n || before.uid !== BigInt(expectedUid) || (before.mode & 0o7777n) !== BigInt(exactMode) || before.size <= 0n || before.size > BigInt(maximum)) fail(`${label} is unsafe`);
    const bytes = Buffer.alloc(Number(before.size));
    let offset = 0;
    while (offset < bytes.length) {
      const count = fs.readSync(descriptor, bytes, offset, bytes.length - offset, offset);
      if (count <= 0) fail(`${label} changed while reading`);
      offset += count;
    }
    const after = fs.fstatSync(descriptor, { bigint: true });
    let current;
    try { current = fs.lstatSync(path, { bigint: true }); } catch { fail(`${label} changed while reading`); }
    if (identity(before) !== identity(after) || identity(after) !== identity(current)) fail(`${label} changed while reading`);
    return Object.freeze({ bytes, identity: identity(after) });
  } finally { fs.closeSync(descriptor); }
};

const fsyncDirectory = (path) => {
  const descriptor = fs.openSync(path, fs.constants.O_RDONLY | O_DIRECTORY | NOFOLLOW);
  try { fs.fsyncSync(descriptor); } finally { fs.closeSync(descriptor); }
};

const writeDurable = (directory, name, bytes, expectedUid) => {
  const path = join(directory, name);
  let descriptor;
  try {
    descriptor = fs.openSync(path, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | NOFOLLOW, 0o600);
    let offset = 0;
    while (offset < bytes.length) offset += fs.writeSync(descriptor, bytes, offset, bytes.length - offset, offset);
    fs.fchmodSync(descriptor, 0o600);
    const stat = fs.fstatSync(descriptor, { bigint: true });
    if (!stat.isFile() || stat.nlink !== 1n || stat.uid !== BigInt(expectedUid) || (stat.mode & 0o7777n) !== 0o600n || stat.size !== BigInt(bytes.length)) fail('staged controller candidate file is unsafe');
    fs.fsyncSync(descriptor);
  } finally { if (descriptor !== undefined) fs.closeSync(descriptor); }
};

const verifyCandidate = (directory, expectedUid, expected = null) => {
  const stat = fs.lstatSync(directory, { bigint: true });
  if (!stat.isDirectory() || stat.isSymbolicLink() || stat.uid !== BigInt(expectedUid) || (stat.mode & 0o7777n) !== 0o700n) fail('controller candidate directory is unsafe');
  const entries = fs.readdirSync(directory, { withFileTypes: true }).sort((left, right) => left.name.localeCompare(right.name));
  if (entries.length !== OUTPUT_FILES.length || entries.some((entry, index) => entry.name !== [...OUTPUT_FILES].sort()[index] || !entry.isFile() || entry.isSymbolicLink())) fail('controller candidate inventory is invalid');
  const manifest = readStable(join(directory, 'controller-candidate.json'), 'controller candidate manifest', MAX_CANDIDATE_BYTES, expectedUid, 0o600);
  const signature = readStable(join(directory, 'controller-candidate.sig'), 'controller candidate signature', 1024, expectedUid, 0o600);
  const publicKey = readStable(join(directory, 'release-public.pem'), 'controller candidate public key', 16 * 1024, expectedUid, 0o600);
  let key;
  try { key = crypto.createPublicKey(publicKey.bytes); } catch { fail('controller candidate public key is invalid'); }
  if (key.asymmetricKeyType !== 'ed25519') fail('controller candidate public key is invalid');
  const encoded = signature.bytes.toString('utf8');
  if (!/^(?:[A-Za-z0-9+/]{4}){21}[A-Za-z0-9+/]{2}==\n$/u.test(encoded)) fail('controller candidate signature encoding is invalid');
  const signatureBytes = Buffer.from(encoded.trim(), 'base64');
  if (signatureBytes.length !== 64 || !crypto.verify(null, manifest.bytes, key, signatureBytes)) fail('controller candidate signature is invalid');
  const digests = Object.freeze({
    manifest_sha256: sha256(manifest.bytes),
    signature_sha256: sha256(signature.bytes),
    public_key_sha256: sha256(publicKey.bytes)
  });
  if (expected && Object.keys(digests).some((name) => !DIGEST.test(expected[name]) || expected[name] !== digests[name])) fail('controller candidate changed before cleanup');
  return Object.freeze({ digests, identities: Object.freeze({ manifest: manifest.identity, signature: signature.identity, publicKey: publicKey.identity }) });
};

export const materializeControllerCandidate = ({
  serviceConfigPath = SERVICE_CONFIG_PATH,
  destination = CONTROLLER_CANDIDATE_DIRECTORY,
  expectedUid = 0,
  production = true,
  platform = process.platform,
  uid = process.getuid?.(),
  nowEpochSeconds = Date.now() / 1000,
  generateKeyPair = () => crypto.generateKeyPairSync('ed25519')
} = {}) => {
  if (production && (platform !== 'darwin' || uid !== 0 || expectedUid !== 0)) fail('controller candidate materialization requires root on macOS');
  if (!production && uid !== expectedUid) fail('controller candidate materialization requires the expected owner');
  absolute(serviceConfigPath, 'service configuration'); absolute(destination, 'controller candidate');
  if (production && destination !== CONTROLLER_CANDIDATE_DIRECTORY) fail('production controller candidate destination is not fixed');
  const parent = dirname(destination); protectedDirectory(parent, expectedUid);
  try { fs.lstatSync(destination); fail('controller candidate already exists; cleanup or recovery is required'); } catch (error) { if (error?.code !== 'ENOENT') throw error; }
  const service = readStable(serviceConfigPath, 'service configuration', MAX_CONFIG_BYTES, expectedUid, 0o600);
  const manifest = canonicalJSON(makeControllerCandidate(readQualification(service.bytes, nowEpochSeconds)));
  let keys;
  try { keys = generateKeyPair(); } catch { fail('ephemeral controller candidate key generation failed'); }
  if (!keys?.privateKey || !keys?.publicKey || keys.privateKey.asymmetricKeyType !== 'ed25519' || keys.publicKey.asymmetricKeyType !== 'ed25519') fail('ephemeral controller candidate key is invalid');
  const signature = Buffer.from(`${crypto.sign(null, manifest, keys.privateKey).toString('base64')}\n`, 'utf8');
  const publicKey = Buffer.from(keys.publicKey.export({ type: 'spki', format: 'pem' }), 'utf8');
  const staging = join(parent, `.controller.${process.pid}.${crypto.randomBytes(12).toString('hex')}.tmp`);
  let stagingCreated = false;
  try {
    fs.mkdirSync(staging, { mode: 0o700 });
    stagingCreated = true;
    writeDurable(staging, 'controller-candidate.json', manifest, expectedUid);
    writeDurable(staging, 'controller-candidate.sig', signature, expectedUid);
    writeDurable(staging, 'release-public.pem', publicKey, expectedUid);
    fsyncDirectory(staging);
    verifyCandidate(staging, expectedUid);
    fs.renameSync(staging, destination);
    fsyncDirectory(parent);
    const verified = verifyCandidate(destination, expectedUid);
    return Object.freeze({ ok: true, action: 'materialized', files: OUTPUT_FILES.length, ...verified.digests });
  } catch {
    if (stagingCreated) { try { fs.rmSync(staging, { recursive: true, force: true }); } catch {} }
    fail('controller candidate materialization failed');
  }
};

export const removeControllerCandidate = ({
  destination = CONTROLLER_CANDIDATE_DIRECTORY,
  expected,
  recovery = false,
  proveNoActiveController,
  expectedUid = 0,
  production = true,
  platform = process.platform,
  uid = process.getuid?.()
} = {}) => {
  if (production && (platform !== 'darwin' || uid !== 0 || expectedUid !== 0)) fail('controller candidate cleanup requires root on macOS');
  if (!production && uid !== expectedUid) fail('controller candidate cleanup requires the expected owner');
  if (production && destination !== CONTROLLER_CANDIDATE_DIRECTORY) fail('controller candidate cleanup destination is not fixed');
  if (recovery !== true && (!expected || typeof expected !== 'object')) fail('controller candidate cleanup binding is required');
  if (recovery === true && (typeof proveNoActiveController !== 'function' || proveNoActiveController() !== true)) fail('controller candidate recovery refused an active controller');
  try {
    protectedDirectory(dirname(destination), expectedUid);
    if (recovery) {
      try { fs.lstatSync(destination); } catch (error) {
        if (error?.code === 'ENOENT') return Object.freeze({ ok: true, action: 'absent' });
        throw error;
      }
    }
    const verified = verifyCandidate(destination, expectedUid, recovery ? null : expected);
    for (const [name, identityKey] of [['controller-candidate.json', 'manifest'], ['controller-candidate.sig', 'signature'], ['release-public.pem', 'publicKey']]) {
      const current = fs.lstatSync(join(destination, name), { bigint: true });
      if (identity(current) !== verified.identities[identityKey]) fail('controller candidate changed before cleanup');
      fs.unlinkSync(join(destination, name));
    }
    fs.rmdirSync(destination);
    fsyncDirectory(dirname(destination));
    return Object.freeze({ ok: true, action: 'removed', manifest_sha256: verified.digests.manifest_sha256 });
  } catch { fail('controller candidate cleanup failed'); }
};

if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
  process.stderr.write('controller candidate materialization refused: fixed root orchestration required\n');
  process.exitCode = 2;
}
