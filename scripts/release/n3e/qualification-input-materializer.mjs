#!/usr/bin/env node
import crypto from 'node:crypto';
import fs from 'node:fs';
import { dirname, isAbsolute, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  FIXED_INPUT_KIND,
  FIXED_INPUT_SCHEMA_VERSION,
  FIXED_QUALIFICATION_INPUT_PATH,
  FIXED_INPUT_MAX_BYTES,
  parseFixedQualificationInput
} from './run-fixed-protected-qualification.mjs';
import { normalizeQualificationActivation } from './qualification-activation-contract.mjs';
import {
  QUALIFICATION_SUITE_INPUT_KIND,
  canonicalQualificationSuiteInput,
  consumeFixedQualificationSuiteInbox
} from './qualification-suite-input.mjs';

export {
  FIXED_INPUT_KIND,
  FIXED_INPUT_SCHEMA_VERSION,
  FIXED_QUALIFICATION_INPUT_PATH,
  FIXED_INPUT_MAX_BYTES
};

export const QUALIFICATION_INPUT_DIRECTORY = dirname(FIXED_QUALIFICATION_INPUT_PATH);

const NOFOLLOW = fs.constants.O_NOFOLLOW;
const O_DIRECTORY = fs.constants.O_DIRECTORY ?? 0;
const DIRECTORY_MODE = 0o700;
const FILE_MODE = 0o600;
const PROVISION_KEYS = Object.freeze([
  'scenario',
  'expires_at_epoch_seconds',
  'run_binding'
]);
const INPUT_KEYS = Object.freeze(['schema_version', 'kind', 'provision', 'activation']);

const fail = (message) => { throw new Error(message); };

const exactDataObject = (value, expected, label) => {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) fail(`${label} is invalid`);
  const ownKeys = Reflect.ownKeys(value);
  if (ownKeys.some((key) => typeof key !== 'string')) fail(`${label} is not closed`);
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) fail(`${label} is not closed`);
  for (const key of expected) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !('value' in descriptor) || descriptor.enumerable !== true) fail(`${label} contains an accessor`);
  }
  return value;
};

const sortedJSONValue = (value) => {
  if (Array.isArray(value)) return value.map(sortedJSONValue);
  if (value && typeof value === 'object') return Object.fromEntries(Object.keys(value).sort().map((key) => [key, sortedJSONValue(value[key])]));
  return value;
};

const canonicalJSON = (value) => {
  let encoded;
  try { encoded = Buffer.from(`${JSON.stringify(sortedJSONValue(value), null, 2)}\n`, 'utf8'); }
  catch { fail('qualification input cannot be encoded'); }
  if (encoded.length === 0 || encoded.length > FIXED_INPUT_MAX_BYTES) fail('qualification input exceeds its size limit');
  return encoded;
};

const absolutePath = (value, label) => {
  if (typeof value !== 'string' || value.length === 0 || value.includes('\0') || !isAbsolute(value) || resolve(value) !== value) fail(`${label} is invalid`);
  return value;
};

const statBinding = (stat) => [stat.dev, stat.ino, stat.uid].map(String).join(':');

const isMissing = (error) => error?.code === 'ENOENT';

const verifyDirectory = (directory, { fileSystem, expectedUid, production }) => {
  let current = directory;
  for (;;) {
    let stat;
    try { stat = fileSystem.lstatSync(current, { bigint: true }); }
    catch { fail('qualification input directory is unavailable'); }
    if (!stat.isDirectory() || stat.isSymbolicLink() || stat.uid !== BigInt(expectedUid) || (stat.mode & 0o022n) !== 0n) fail('qualification input directory is unsafe');
    if (current === directory && (stat.mode & 0o7777n) !== BigInt(DIRECTORY_MODE)) fail('qualification input directory mode is unsafe');
    if (!production || current === '/') break;
    current = resolve(current, '..');
  }
};

const syncDirectory = (directory, fileSystem) => {
  if (!Number.isInteger(NOFOLLOW)) fail('qualification input requires O_NOFOLLOW');
  let descriptor;
  try {
    descriptor = fileSystem.openSync(directory, fileSystem.constants.O_RDONLY | O_DIRECTORY | NOFOLLOW);
    fileSystem.fsyncSync(descriptor);
  } catch { fail('qualification input directory sync failed'); }
  finally {
    if (descriptor !== undefined) {
      try { fileSystem.closeSync(descriptor); } catch { fail('qualification input directory sync failed'); }
    }
  }
};

const assertDestinationAbsent = (destination, fileSystem) => {
  try {
    fileSystem.lstatSync(destination, { bigint: true });
    fail('qualification input already exists; cleanup or recovery is required');
  } catch (error) {
    if (!isMissing(error)) throw error;
  }
};

const assertRegularFile = (stat, expectedUid, expectedSize = null, expectedLinks = 1n) => {
  if (!stat.isFile() || stat.isSymbolicLink() || stat.uid !== BigInt(expectedUid) || stat.nlink !== expectedLinks || (stat.mode & 0o7777n) !== BigInt(FILE_MODE) || (expectedSize !== null && stat.size !== BigInt(expectedSize))) fail('qualification input staging file is unsafe');
};

const writeAll = (descriptor, bytes, fileSystem) => {
  let offset = 0;
  while (offset < bytes.length) {
    const count = fileSystem.writeSync(descriptor, bytes, offset, bytes.length - offset, offset);
    if (!Number.isInteger(count) || count <= 0) fail('qualification input staging write failed');
    offset += count;
  }
};

const readAll = (descriptor, size, fileSystem) => {
  const bytes = Buffer.alloc(size);
  let offset = 0;
  while (offset < bytes.length) {
    const count = fileSystem.readSync(descriptor, bytes, offset, bytes.length - offset, offset);
    if (!Number.isInteger(count) || count <= 0) fail('qualification input staging read failed');
    offset += count;
  }
  return bytes;
};

const readStableFile = (file, { fileSystem, expectedUid, expectedLinks, binding, expectedSize }) => {
  let descriptor;
  try { descriptor = fileSystem.openSync(file, fileSystem.constants.O_RDONLY | NOFOLLOW); }
  catch { fail('qualification input staging file is unavailable'); }
  try {
    const before = fileSystem.fstatSync(descriptor, { bigint: true });
    assertRegularFile(before, expectedUid, expectedSize, expectedLinks);
    if (binding && statBinding(before) !== binding) fail('qualification input staging file changed');
    const bytes = readAll(descriptor, Number(before.size), fileSystem);
    const after = fileSystem.fstatSync(descriptor, { bigint: true });
    const current = fileSystem.lstatSync(file, { bigint: true });
    assertRegularFile(after, expectedUid, expectedSize, expectedLinks);
    assertRegularFile(current, expectedUid, expectedSize, expectedLinks);
    if (statBinding(before) !== statBinding(after) || statBinding(after) !== statBinding(current) || before.size !== after.size || before.nlink !== current.nlink) fail('qualification input staging file changed');
    return bytes;
  } finally { fileSystem.closeSync(descriptor); }
};

const removeBoundStaging = ({ staging, binding, published, fileSystem, expectedUid }) => {
  if (!staging || !binding) return;
  let stat;
  try { stat = fileSystem.lstatSync(staging, { bigint: true }); }
  catch { return; }
  if (!stat.isFile() || stat.isSymbolicLink() || statBinding(stat) !== binding || stat.uid !== BigInt(expectedUid)) return;
  const expectedLinks = published ? 2n : 1n;
  if (stat.nlink !== expectedLinks) return;
  try { fileSystem.unlinkSync(staging); } catch {}
};

const materialize = ({
  input,
  provision,
  activation,
  destination,
  expectedUid,
  production,
  platform,
  uid,
  fileSystem,
  randomBytes,
  processId
}) => {
  if (input !== undefined && (provision !== undefined || activation !== undefined)) fail('qualification input cannot combine document and fields');
  const selectedInput = input ?? {
    schema_version: FIXED_INPUT_SCHEMA_VERSION,
    kind: FIXED_INPUT_KIND,
    provision,
    activation
  };
  let bytes;
  if (selectedInput?.kind === QUALIFICATION_SUITE_INPUT_KIND) {
    try { bytes = canonicalQualificationSuiteInput(selectedInput); }
    catch { fail('qualification input does not satisfy the fixed suite schema'); }
  } else {
    exactDataObject(selectedInput, INPUT_KEYS, 'qualification input');
    if (selectedInput.schema_version !== FIXED_INPUT_SCHEMA_VERSION || selectedInput.kind !== FIXED_INPUT_KIND) fail('qualification input identity is invalid');
    exactDataObject(selectedInput.provision, PROVISION_KEYS, 'qualification provision input');
    bytes = canonicalJSON(normalizeInputDocument(selectedInput));
    try { parseFixedQualificationInput(bytes); }
    catch { fail('qualification input does not satisfy the fixed schema'); }
  }

  if (production) {
    if (destination !== FIXED_QUALIFICATION_INPUT_PATH) fail('qualification input materialization requires the fixed path');
    if (process.platform !== 'darwin' || typeof process.getuid !== 'function' || process.getuid() !== 0 || expectedUid !== 0 || fileSystem !== fs || randomBytes !== crypto.randomBytes || processId !== process.pid) fail('qualification input materialization requires root on macOS and the fixed path');
  } else if (uid !== expectedUid) {
    fail('qualification input materialization requires the expected owner');
  }
  if (!Number.isInteger(expectedUid) || expectedUid < 0) fail('qualification input owner is invalid');
  if (!Number.isInteger(processId) || processId < 0) fail('qualification input process identity is invalid');
  absolutePath(destination, 'qualification input');
  if (!Number.isInteger(NOFOLLOW)) fail('qualification input requires O_NOFOLLOW');

  const parent = dirname(destination);
  verifyDirectory(parent, { fileSystem, expectedUid, production });
  assertDestinationAbsent(destination, fileSystem);

  let staging;
  let descriptor;
  let binding;
  let published = false;
  try {
    let random;
    try { random = randomBytes(16); } catch { fail('qualification input staging name generation failed'); }
    if (!(random instanceof Uint8Array) || random.length !== 16) fail('qualification input staging name generation failed');
    staging = join(parent, `.input.json.${processId}.${Buffer.from(random).toString('hex')}.tmp`);
    descriptor = fileSystem.openSync(staging, fileSystem.constants.O_WRONLY | fileSystem.constants.O_CREAT | fileSystem.constants.O_EXCL | NOFOLLOW, FILE_MODE);
    const opened = fileSystem.fstatSync(descriptor, { bigint: true });
    binding = statBinding(opened);
    assertRegularFile(opened, expectedUid, 0, 1n);
    writeAll(descriptor, bytes, fileSystem);
    fileSystem.fchmodSync(descriptor, FILE_MODE);
    const staged = fileSystem.fstatSync(descriptor, { bigint: true });
    assertRegularFile(staged, expectedUid, bytes.length, 1n);
    fileSystem.fsyncSync(descriptor);
    fileSystem.closeSync(descriptor);
    descriptor = undefined;

    verifyDirectory(parent, { fileSystem, expectedUid, production });
    const beforeLink = fileSystem.lstatSync(staging, { bigint: true });
    if (!beforeLink.isFile() || beforeLink.isSymbolicLink() || statBinding(beforeLink) !== binding || beforeLink.nlink !== 1n) fail('qualification input staging file changed');
    fileSystem.linkSync(staging, destination);
    published = true;
    const installed = fileSystem.lstatSync(destination, { bigint: true });
    assertRegularFile(installed, expectedUid, bytes.length, 2n);
    const installedBytes = readStableFile(destination, { fileSystem, expectedUid, expectedLinks: 2n, expectedSize: bytes.length, binding });
    if (!installedBytes.equals(bytes)) fail('qualification input installed bytes changed');
    fileSystem.unlinkSync(staging);
    staging = undefined;
    const final = fileSystem.lstatSync(destination, { bigint: true });
    assertRegularFile(final, expectedUid, bytes.length, 1n);
    const finalBytes = readStableFile(destination, { fileSystem, expectedUid, expectedLinks: 1n, expectedSize: bytes.length, binding });
    if (!finalBytes.equals(bytes)) fail('qualification input installed bytes changed');
    syncDirectory(parent, fileSystem);
    return Object.freeze({
      ok: true,
      action: 'materialized',
      document_sha256: crypto.createHash('sha256').update(bytes).digest('hex'),
      document_bytes: bytes.length
    });
  } catch {
    removeBoundStaging({ staging, binding, published, fileSystem, expectedUid });
    fail('qualification input materialization failed');
  } finally {
    if (descriptor !== undefined) {
      try { fileSystem.closeSync(descriptor); } catch {}
    }
  }
};

const normalizeInputDocument = (input) => {
  exactDataObject(input, INPUT_KEYS, 'qualification input');
  if (input.schema_version !== FIXED_INPUT_SCHEMA_VERSION || input.kind !== FIXED_INPUT_KIND) fail('qualification input identity is invalid');
  exactDataObject(input.provision, PROVISION_KEYS, 'qualification provision input');
  return {
    schema_version: FIXED_INPUT_SCHEMA_VERSION,
    kind: FIXED_INPUT_KIND,
    provision: Object.fromEntries(PROVISION_KEYS.map((key) => [key, input.provision[key]])),
    activation: normalizeQualificationActivation(input.activation)
  };
};

export const canonicalFixedQualificationInput = (input) => {
  const bytes = canonicalJSON(normalizeInputDocument(input));
  try { parseFixedQualificationInput(bytes); }
  catch { fail('qualification input does not satisfy the fixed schema'); }
  return bytes;
};

export const materializeFixedQualificationInput = ({
  input,
  provision,
  activation,
  destination = FIXED_QUALIFICATION_INPUT_PATH,
  expectedUid = 0,
  production = true,
  platform = process.platform,
  uid = process.getuid?.(),
  fileSystem = fs,
  randomBytes = crypto.randomBytes,
  processId = process.pid
} = {}) => materialize({ input, provision, activation, destination, expectedUid, production, platform, uid, fileSystem, randomBytes, processId });

export const materializeFixedQualificationInputForTest = (options = {}) => materializeFixedQualificationInput({ ...options, production: false });
export const materializeFixedQualificationSuiteInput = ({ input, ...options } = {}) => {
  if (input?.kind !== QUALIFICATION_SUITE_INPUT_KIND) fail('qualification suite input identity is invalid');
  return materializeFixedQualificationInput({ input, ...options });
};
export const materializeQualificationInput = materializeFixedQualificationInput;

export const parseQualificationInputMaterializerCLI = (args) => {
  if (!Array.isArray(args) || args.length !== 1 || args[0] !== 'materialize') fail('usage: qualification-input-materializer.mjs materialize');
  return Object.freeze({ operation: 'materialize' });
};

if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
  try {
    parseQualificationInputMaterializerCLI(process.argv.slice(2));
    const input = consumeFixedQualificationSuiteInbox();
    const result = materializeFixedQualificationSuiteInput({ input });
    process.stdout.write(`${JSON.stringify(result)}\n`);
  } catch (error) {
    const message = error?.message === 'usage: qualification-input-materializer.mjs materialize' ? error.message : 'qualification input materialization was refused';
    process.stderr.write(`${message}\n`);
    process.exitCode = 2;
  }
}
