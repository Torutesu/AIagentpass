#!/usr/bin/env node
import crypto from 'node:crypto';
import fs from 'node:fs';
import { dirname, isAbsolute, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  QUALIFICATION_ACTIVATION_MAX_BYTES,
  canonicalQualificationActivation,
  parseQualificationActivation,
  qualificationActivationPublicMetadata
} from './qualification-activation-contract.mjs';

export const QUALIFICATION_ACTIVATION_DIRECTORY = '/private/var/db/agentpass-qualification/activation';
export const QUALIFICATION_ACTIVATION_PATH = `${QUALIFICATION_ACTIVATION_DIRECTORY}/activation.json`;

const NOFOLLOW = fs.constants.O_NOFOLLOW;
const O_DIRECTORY = fs.constants.O_DIRECTORY ?? 0;
const fail = (message) => { throw new Error(message); };
const sha256 = (bytes) => crypto.createHash('sha256').update(bytes).digest('hex');
const identity = (value) => [value.dev, value.ino, value.mode, value.nlink, value.size, value.mtimeNs, value.ctimeNs, value.uid, value.gid].map(String).join(':');

const absolute = (value, label) => {
  if (typeof value !== 'string' || !isAbsolute(value) || resolve(value) !== value || value.includes('\0')) fail(`${label} path is invalid`);
  return value;
};

const protectedDirectory = (path, expectedUid, exactMode) => {
  let state;
  try { state = fs.lstatSync(path, { bigint: true }); } catch { fail('qualification activation parent is unavailable'); }
  if (!state.isDirectory() || state.isSymbolicLink() || state.uid !== BigInt(expectedUid) || (state.mode & 0o7777n) !== BigInt(exactMode)) fail('qualification activation parent is unsafe');
};

const fsyncDirectory = (path) => {
  const descriptor = fs.openSync(path, fs.constants.O_RDONLY | O_DIRECTORY | NOFOLLOW);
  try { fs.fsyncSync(descriptor); } finally { fs.closeSync(descriptor); }
};

const readActivation = (path, expectedUid) => {
  let descriptor;
  try { descriptor = fs.openSync(path, fs.constants.O_RDONLY | NOFOLLOW); }
  catch { fail('qualification activation document is unavailable'); }
  try {
    const before = fs.fstatSync(descriptor, { bigint: true });
    if (!before.isFile() || before.nlink !== 1n || before.uid !== BigInt(expectedUid) || (before.mode & 0o7777n) !== 0o600n || before.size <= 0n || before.size > BigInt(QUALIFICATION_ACTIVATION_MAX_BYTES)) fail('qualification activation document is unsafe');
    const bytes = Buffer.alloc(Number(before.size)); let offset = 0;
    while (offset < bytes.length) {
      const count = fs.readSync(descriptor, bytes, offset, bytes.length - offset, offset);
      if (count <= 0) fail('qualification activation document changed');
      offset += count;
    }
    const after = fs.fstatSync(descriptor, { bigint: true });
    const current = fs.lstatSync(path, { bigint: true });
    if (identity(before) !== identity(after) || identity(after) !== identity(current)) fail('qualification activation document changed');
    const value = parseQualificationActivation(bytes);
    return Object.freeze({ bytes, value, identity: identity(after), sha256: sha256(bytes) });
  } finally { fs.closeSync(descriptor); }
};

const productionGuard = ({ production, platform, uid, expectedUid, destination }) => {
  if (production && (platform !== 'darwin' || uid !== 0 || expectedUid !== 0 || destination !== QUALIFICATION_ACTIVATION_DIRECTORY)) fail('qualification activation materialization requires root on macOS and the fixed destination');
  if (!production && uid !== expectedUid) fail('qualification activation materialization requires the expected owner');
};

export const materializeQualificationActivation = ({
  activation,
  destination = QUALIFICATION_ACTIVATION_DIRECTORY,
  expectedUid = 0,
  production = true,
  platform = process.platform,
  uid = process.getuid?.()
} = {}) => {
  productionGuard({ production, platform, uid, expectedUid, destination });
  absolute(destination, 'qualification activation');
  const parent = dirname(destination); protectedDirectory(parent, expectedUid, 0o700);
  try { fs.lstatSync(destination); fail('qualification activation already exists; cleanup or recovery is required'); }
  catch (error) { if (error?.code !== 'ENOENT') throw error; }
  let bytes;
  try { bytes = canonicalQualificationActivation(activation); }
  catch { fail('qualification activation input is invalid'); }
  const staging = join(parent, `.activation.${process.pid}.${crypto.randomBytes(12).toString('hex')}.tmp`);
  let created = false;
  try {
    fs.mkdirSync(staging, { mode: 0o700 }); created = true;
    const path = join(staging, 'activation.json');
    const descriptor = fs.openSync(path, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | NOFOLLOW, 0o600);
    try {
      let offset = 0;
      while (offset < bytes.length) offset += fs.writeSync(descriptor, bytes, offset, bytes.length - offset, offset);
      fs.fchmodSync(descriptor, 0o600); fs.fsyncSync(descriptor);
    } finally { fs.closeSync(descriptor); }
    fsyncDirectory(staging);
    const staged = readActivation(path, expectedUid);
    if (!staged.bytes.equals(bytes)) fail('qualification activation staged bytes changed');
    fs.renameSync(staging, destination); fsyncDirectory(parent);
    const installed = readActivation(join(destination, 'activation.json'), expectedUid);
    const metadata = qualificationActivationPublicMetadata(installed.value);
    return Object.freeze({ ok: true, action: 'materialized', document_sha256: installed.sha256, proof_sha256: metadata.proof_sha256, proof_bytes: metadata.proof_bytes });
  } catch {
    if (created) { try { fs.rmSync(staging, { recursive: true, force: true }); } catch {} }
    fail('qualification activation materialization failed');
  }
};

export const removeQualificationActivation = ({
  destination = QUALIFICATION_ACTIVATION_DIRECTORY,
  expected,
  recovery = false,
  proveNoActiveAgent,
  expectedUid = 0,
  production = true,
  platform = process.platform,
  uid = process.getuid?.()
} = {}) => {
  productionGuard({ production, platform, uid, expectedUid, destination });
  if (!recovery && (!expected || !/^[0-9a-f]{64}$/u.test(expected.document_sha256 ?? ''))) fail('qualification activation cleanup binding is required');
  if (recovery && (typeof proveNoActiveAgent !== 'function' || proveNoActiveAgent() !== true)) fail('qualification activation recovery refused an active Agent');
  try {
    protectedDirectory(dirname(destination), expectedUid, 0o700);
    try { protectedDirectory(destination, expectedUid, 0o700); }
    catch (error) {
      if (recovery) {
        try { fs.lstatSync(destination); } catch (missing) { if (missing?.code === 'ENOENT') return Object.freeze({ ok: true, action: 'absent' }); }
      }
      throw error;
    }
    const entries = fs.readdirSync(destination, { withFileTypes: true });
    if (entries.length !== 1 || entries[0].name !== 'activation.json' || !entries[0].isFile() || entries[0].isSymbolicLink()) fail('qualification activation inventory is invalid');
    const path = join(destination, 'activation.json');
    const current = readActivation(path, expectedUid);
    if (!recovery && current.sha256 !== expected.document_sha256) fail('qualification activation changed before cleanup');
    const before = fs.lstatSync(path, { bigint: true });
    if (identity(before) !== current.identity) fail('qualification activation changed before cleanup');
    fs.unlinkSync(path); fs.rmdirSync(destination); fsyncDirectory(dirname(destination));
    return Object.freeze({ ok: true, action: 'removed', document_sha256: current.sha256 });
  } catch { fail('qualification activation cleanup failed'); }
};

if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
  process.stderr.write('qualification activation materialization refused: fixed root orchestration required\n');
  process.exitCode = 2;
}
