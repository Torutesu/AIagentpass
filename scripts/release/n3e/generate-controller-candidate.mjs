#!/usr/bin/env node
import crypto from 'node:crypto';
import fs from 'node:fs';
import { dirname, isAbsolute, join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

export const SCHEMA_VERSION = 1;
export const MANIFEST_KIND = 'agentpass-n3e-controller-candidate';
export const QUALIFICATION_MODE = 'n3e-qualification';
export const QUALIFICATION_MACH_SERVICE = 'dev.agentpass.n3e-qualification';
export const MAX_SERVICE_CONFIG_BYTES = 1024 * 1024;
export const MAX_KEY_BYTES = 16 * 1024;
export const OUTPUT_FILES = Object.freeze([
  'controller-candidate.json',
  'controller-candidate.sig',
  'release-public.pem'
]);

const NOFOLLOW = fs.constants.O_NOFOLLOW;
const O_DIRECTORY = fs.constants.O_DIRECTORY ?? 0;
const DIGEST = /^[0-9a-f]{64}$/u;
const MAX_LIFETIME_SECONDS = 15 * 60;
const QUALIFICATION_FIELDS = Object.freeze([
  'qualification_mode',
  'qualification_mach_service_name',
  'qualification_candidate_sha256',
  'qualification_source_commit_sha256',
  'qualification_code_identities_sha256',
  'qualification_run_id_sha256',
  'qualification_expires_at_epoch_seconds',
  'qualification_scenario',
  'qualification_phase'
]);
const SCENARIO_PHASE = new Map([
  ['pre-cloud-kill', 'pre-cloud'],
  ['post-cloud-pre-local-kill', 'post-cloud-pre-local'],
  ['post-activation-pre-audit-kill', 'post-activation-pre-audit'],
  ['post-audit-pre-reply-loss', 'post-audit-pre-reply'],
  ['audit-fsync-failure', 'audit-fsync'],
  ['transport-reply-loss', 'transport-reply']
]);

const usage = 'Usage: generate-controller-candidate.mjs --service-config FILE --private-key FILE --public-key FILE --output DIRECTORY';

const fail = (message) => { throw new Error(message); };

const assertNoFollow = () => {
  if (!Number.isInteger(NOFOLLOW)) fail('O_NOFOLLOW is unavailable');
};

const absolutePath = (value, label) => {
  if (typeof value !== 'string' || value.length === 0 || value.includes('\0') || !isAbsolute(value) || resolve(value) !== value) {
    fail(`${label} path is invalid`);
  }
  return value;
};

const statIdentity = (stat) => [
  stat.dev, stat.ino, stat.mode, stat.nlink, stat.size,
  stat.mtimeNs, stat.ctimeNs, stat.uid, stat.gid
].map((value) => value.toString()).join(':');

const readStableFile = (input, { label, maximum, protectedMode = false, ownerOnly = false } = {}) => {
  assertNoFollow();
  const file = absolutePath(input, label ?? 'input');
  let descriptor;
  try {
    descriptor = fs.openSync(file, fs.constants.O_RDONLY | NOFOLLOW);
  } catch {
    fail(`${label ?? 'input'} is unavailable`);
  }
  try {
    const before = fs.fstatSync(descriptor, { bigint: true });
    if (!before.isFile() || before.nlink !== 1n || before.size <= 0n || before.size > BigInt(maximum) || before.size > BigInt(Number.MAX_SAFE_INTEGER)) {
      fail(`${label ?? 'input'} is unsafe`);
    }
    if (protectedMode && (before.mode & 0o7777n) !== 0o600n) fail(`${label ?? 'input'} is not protected`);
    if (ownerOnly && typeof process.getuid === 'function' && before.uid !== BigInt(process.getuid())) {
      fail(`${label ?? 'input'} is not owned by the current user`);
    }
    const bytes = Buffer.alloc(Number(before.size));
    let offset = 0;
    while (offset < bytes.length) {
      const count = fs.readSync(descriptor, bytes, offset, bytes.length - offset, offset);
      if (count <= 0) fail(`${label ?? 'input'} was truncated`);
      offset += count;
    }
    const after = fs.fstatSync(descriptor, { bigint: true });
    let pathStat;
    try { pathStat = fs.lstatSync(file, { bigint: true }); } catch { fail(`${label ?? 'input'} changed while reading`); }
    if (statIdentity(before) !== statIdentity(after) || statIdentity(after) !== statIdentity(pathStat)) {
      fail(`${label ?? 'input'} changed while reading`);
    }
    return bytes;
  } finally {
    fs.closeSync(descriptor);
  }
};

const parseJSON = (bytes, label) => {
  let value;
  try { value = JSON.parse(bytes.toString('utf8')); } catch { fail(`${label} is not valid JSON`); }
  if (value === null || typeof value !== 'object' || Array.isArray(value)) fail(`${label} must be an object`);
  return value;
};

const digest = (value, field) => {
  if (typeof value !== 'string' || !DIGEST.test(value) || /^0+$/u.test(value)) fail(`${field} is invalid`);
  return value;
};

const integer = (value, field) => {
  if (!Number.isSafeInteger(value) || value < 0) fail(`${field} is invalid`);
  return value;
};

const readQualification = (serviceBytes) => {
  const service = parseJSON(serviceBytes, 'service config');
  const values = Object.create(null);
  for (const field of QUALIFICATION_FIELDS) {
    if (!Object.prototype.hasOwnProperty.call(service, field)) fail(`service config is missing ${field}`);
    values[field] = service[field];
  }
  if (values.qualification_mode !== QUALIFICATION_MODE) fail('service config mode is invalid');
  if (values.qualification_mach_service_name !== QUALIFICATION_MACH_SERVICE) fail('service config service is invalid');
  const candidate = digest(values.qualification_candidate_sha256, 'candidate_sha256');
  const source = digest(values.qualification_source_commit_sha256, 'source_commit_sha256');
  const identities = digest(values.qualification_code_identities_sha256, 'code_identities_sha256');
  const run = digest(values.qualification_run_id_sha256, 'run_id_sha256');
  const expiry = integer(values.qualification_expires_at_epoch_seconds, 'expires_at_epoch_seconds');
  const now = Date.now() / 1000;
  if (!(expiry > now) || expiry - now > MAX_LIFETIME_SECONDS) fail('service config expiry is invalid');
  const scenario = values.qualification_scenario;
  const phase = values.qualification_phase;
  if (typeof scenario !== 'string' || SCENARIO_PHASE.get(scenario) !== phase) fail('service config scenario/phase pair is invalid');
  return Object.freeze({ candidate, source, identities, run, expiry, scenario, phase });
};

const sortedValue = (value) => {
  if (Array.isArray(value)) return value.map(sortedValue);
  if (value !== null && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, sortedValue(value[key])]));
  }
  return value;
};

export const canonicalJSON = (value) => Buffer.from(JSON.stringify(sortedValue(value)), 'utf8');

const publicKeyPEM = (key) => key.export({ type: 'spki', format: 'pem' });

const loadMatchingKeys = (privateBytes, publicBytes) => {
  let privateKey;
  let publicKey;
  try {
    try {
      privateKey = crypto.createPrivateKey(privateBytes);
      publicKey = crypto.createPublicKey(publicBytes);
    } catch { fail('Ed25519 key input is invalid'); }
  } finally {
    privateBytes.fill(0);
  }
  if (privateKey.asymmetricKeyType !== 'ed25519' || publicKey.asymmetricKeyType !== 'ed25519') fail('key input is not Ed25519');
  const privatePublic = crypto.createPublicKey(privateKey).export({ type: 'spki', format: 'der' });
  const suppliedPublic = publicKey.export({ type: 'spki', format: 'der' });
  if (!privatePublic.equals(suppliedPublic)) fail('Ed25519 public key does not match private key');
  return { privateKey, publicKey, publicPEM: publicKeyPEM(publicKey) };
};

export const makeControllerCandidate = (qualification) => ({
  schema_version: SCHEMA_VERSION,
  kind: MANIFEST_KIND,
  candidate_sha256: qualification.candidate,
  source_commit_sha256: qualification.source,
  code_identities_sha256: qualification.identities,
  run_id_sha256: qualification.run,
  expires_at_epoch_seconds: qualification.expiry,
  scenario: qualification.scenario,
  phase: qualification.phase
});

const writeFileDurably = (directory, name, bytes) => {
  const target = join(directory, name);
  let descriptor;
  try {
    descriptor = fs.openSync(target, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | NOFOLLOW, 0o600);
    let offset = 0;
    while (offset < bytes.length) offset += fs.writeSync(descriptor, bytes, offset, bytes.length - offset);
    fs.fchmodSync(descriptor, 0o600);
    fs.fsyncSync(descriptor);
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }
};

const fsyncDirectory = (directory) => {
  const descriptor = fs.openSync(directory, fs.constants.O_RDONLY | O_DIRECTORY | NOFOLLOW);
  try { fs.fsyncSync(descriptor); } finally { fs.closeSync(descriptor); }
};

const randomStagingPath = (parent) => join(parent, `.controller-candidate.${process.pid}.${crypto.randomBytes(12).toString('hex')}.tmp`);

const verifyOutputAncestry = (parent) => {
  const currentUID = typeof process.getuid === 'function' ? BigInt(process.getuid()) : null;
  let current = parent;
  while (true) {
    let state;
    try { state = fs.lstatSync(current, { bigint: true }); } catch { fail('output ancestry is unavailable'); }
    if (!state.isDirectory() || state.isSymbolicLink()) fail('output ancestry is unsafe');
    const writableByOther = (state.mode & 0o022n) !== 0n;
    const trustedStickyTemp = (state.mode & 0o1000n) !== 0n && state.uid === 0n;
    if (writableByOther && !trustedStickyTemp) fail('output ancestry is writable by another user');
    if (currentUID !== null && current === parent && state.uid !== currentUID) fail('output parent is not owned by the current user');
    const next = dirname(current);
    if (next === current) break;
    current = next;
  }
};

export const emitControllerCandidate = ({ serviceConfigPath, privateKeyPath, publicKeyPath, outputDirectory } = {}) => {
  const serviceBytes = readStableFile(serviceConfigPath, { label: 'service config', maximum: MAX_SERVICE_CONFIG_BYTES, protectedMode: true, ownerOnly: true });
  const qualification = readQualification(serviceBytes);
  let privateBytes;
  try {
    privateBytes = readStableFile(privateKeyPath, { label: 'private key', maximum: MAX_KEY_BYTES, protectedMode: true, ownerOnly: true });
    const publicBytes = readStableFile(publicKeyPath, { label: 'public key', maximum: MAX_KEY_BYTES, protectedMode: true, ownerOnly: true });
    const manifest = canonicalJSON(makeControllerCandidate(qualification));
    const keys = loadMatchingKeys(privateBytes, publicBytes);
    const signature = Buffer.concat([Buffer.from(crypto.sign(null, manifest, keys.privateKey).toString('base64'), 'utf8'), Buffer.from('\n')]);
    const publicPEM = Buffer.from(keys.publicPEM, 'utf8');

    assertNoFollow();
    const output = absolutePath(outputDirectory, 'output');
    const parent = dirname(output);
    let parentStat;
    try { parentStat = fs.lstatSync(parent, { bigint: true }); } catch { fail('output parent is unavailable'); }
    if (!parentStat.isDirectory() || parentStat.isSymbolicLink()) fail('output parent is unsafe');
    verifyOutputAncestry(parent);
    try { fs.lstatSync(output, { bigint: true }); fail('output directory already exists'); } catch (error) { if (error?.code !== 'ENOENT') throw error; }

    const staging = randomStagingPath(parent);
    try {
      fs.mkdirSync(staging, { mode: 0o700 });
      writeFileDurably(staging, 'controller-candidate.json', manifest);
      writeFileDurably(staging, 'controller-candidate.sig', signature);
      writeFileDurably(staging, 'release-public.pem', publicPEM);
      fsyncDirectory(staging);
      fs.renameSync(staging, output);
      fsyncDirectory(parent);
    } catch (error) {
      try { fs.rmSync(staging, { recursive: true, force: true }); } catch {}
      if (error instanceof Error && error.message === 'output directory already exists') throw error;
      fail('unable to atomically publish candidate');
    }
    return Object.freeze({ manifestBytes: manifest.length, signatureBytes: signature.length, files: OUTPUT_FILES.length });
  } finally {
    if (privateBytes) privateBytes.fill(0);
  }
};

export const parseArguments = (args) => {
  const allowed = new Set(['--service-config', '--private-key', '--public-key', '--output']);
  if (!Array.isArray(args) || args.length !== allowed.size * 2) fail(usage);
  const values = new Map();
  for (let index = 0; index < args.length; index += 2) {
    const option = args[index];
    const value = args[index + 1];
    if (!allowed.has(option) || typeof value !== 'string' || value.length === 0 || value.startsWith('--') || values.has(option)) fail(usage);
    values.set(option, value);
  }
  if (values.size !== allowed.size) fail(usage);
  return Object.freeze({
    serviceConfigPath: absolutePath(values.get('--service-config'), 'service config'),
    privateKeyPath: absolutePath(values.get('--private-key'), 'private key'),
    publicKeyPath: absolutePath(values.get('--public-key'), 'public key'),
    outputDirectory: absolutePath(values.get('--output'), 'output')
  });
};

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    emitControllerCandidate(parseArguments(process.argv.slice(2)));
    process.stdout.write('{"ok":true,"files":3}\n');
  } catch (error) {
    process.stderr.write(`controller candidate refused: ${error instanceof Error ? error.message : 'invalid input'}\n`);
    process.exitCode = 1;
  }
}
