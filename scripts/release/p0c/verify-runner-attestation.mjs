#!/usr/bin/env node
import crypto from 'node:crypto';
import fs from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

const FINGERPRINT = /^SHA256:[A-Za-z0-9_-]{43}$/u;
const RUNNER_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$/u;
const MODEL = /^[A-Za-z0-9,._-]{3,80}$/u;
const TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u;
const ARCHITECTURES = new Set(['arm64', 'x86_64']);
const HARDWARE_CLASSES = new Set(['apple_silicon', 'intel_t2']);
const MAX_JSON_BYTES = 64 * 1024;

export const canonicalJSON = (value) => Buffer.from(`${JSON.stringify(value, null, 2)}\n`, 'utf8');

const exactKeys = (value, keys, label) => {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error(`${label} must be an object`);
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) throw new Error(`${label} has missing or unknown fields`);
};

const sha256 = (bytes) => crypto.createHash('sha256').update(bytes).digest('hex');
const publicKeyFingerprint = (key) => `SHA256:${crypto.createHash('sha256').update(key.export({ type: 'spki', format: 'der' })).digest('base64url')}`;

function snapshot(pathInput, label, maximum) {
  const path = resolve(pathInput);
  let fd;
  try { fd = fs.openSync(path, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW); } catch { throw new Error(`${label} cannot be opened`); }
  try {
    const before = fs.fstatSync(fd, { bigint: true });
    if (!before.isFile() || before.nlink !== 1n || before.size <= 0n || before.size > BigInt(maximum) || (before.mode & 0o022n) !== 0n) throw new Error(`${label} is not protected`);
    const bytes = Buffer.alloc(Number(before.size));
    let offset = 0;
    while (offset < bytes.length) {
      const count = fs.readSync(fd, bytes, offset, bytes.length - offset, offset);
      if (count === 0) throw new Error(`${label} changed while reading`);
      offset += count;
    }
    const after = fs.fstatSync(fd, { bigint: true });
    const identity = (value) => [value.dev, value.ino, value.mode, value.nlink, value.size, value.mtimeNs, value.ctimeNs].join(':');
    if (identity(before) !== identity(after)) throw new Error(`${label} changed while reading`);
    return { path, bytes, sha256: sha256(bytes), uid: Number(after.uid), mode: Number(after.mode & 0o777n) };
  } finally { fs.closeSync(fd); }
}

function parseCanonical(snapshotValue, label) {
  let value;
  try { value = JSON.parse(snapshotValue.bytes.toString('utf8')); } catch { throw new Error(`${label} is not valid JSON`); }
  if (!snapshotValue.bytes.equals(canonicalJSON(value))) throw new Error(`${label} is not canonical JSON`);
  return value;
}

export function validateRunnerAttestation(value, { expectedArchitecture, expectedHardwareClass, expectedRunnerId } = {}) {
  exactKeys(value, ['schema_version', 'kind', 'runner_id', 'architecture', 'hardware_class', 'model_identifier', 'native_execution', 'vm_detected', 'rosetta_detected', 'attested_at'], 'runner attestation');
  if (value.schema_version !== 1 || value.kind !== 'agentpass.macos.protected-runner-attestation' || !RUNNER_ID.test(value.runner_id) || !ARCHITECTURES.has(value.architecture) || !HARDWARE_CLASSES.has(value.hardware_class) || !MODEL.test(value.model_identifier) || value.native_execution !== true || value.vm_detected !== false || value.rosetta_detected !== false || !TIMESTAMP.test(value.attested_at) || new Date(value.attested_at).toISOString() !== value.attested_at) throw new Error('runner attestation facts are invalid');
  if ((value.architecture === 'arm64' && value.hardware_class !== 'apple_silicon') || (value.architecture === 'x86_64' && value.hardware_class !== 'intel_t2')) throw new Error('runner attestation architecture and hardware class disagree');
  if (expectedArchitecture !== undefined && value.architecture !== expectedArchitecture) throw new Error('runner attestation architecture does not match the qualification lane');
  if (expectedHardwareClass !== undefined && value.hardware_class !== expectedHardwareClass) throw new Error('runner attestation hardware class does not match the qualification lane');
  if (expectedRunnerId !== undefined && value.runner_id !== expectedRunnerId) throw new Error('runner attestation runner identity does not match the protected runner binding');
  return value;
}

export function verifyRunnerAttestation({ attestation, signature, publicKey, fingerprint, expectedArchitecture, expectedHardwareClass, expectedRunnerId, production = false } = {}) {
  if (!attestation || !signature || !publicKey || !FINGERPRINT.test(fingerprint ?? '')) throw new Error('runner attestation signature binding is required');
  const payload = snapshot(attestation, 'runner attestation', MAX_JSON_BYTES);
  const signatureFile = snapshot(signature, 'runner attestation signature', 1024);
  const publicKeyFile = snapshot(publicKey, 'runner attestation public key', 16 * 1024);
  if (production && (payload.uid !== 0 || signatureFile.uid !== 0 || publicKeyFile.uid !== 0)) throw new Error('production runner attestation files must be root-owned');
  const value = parseCanonical(payload, 'runner attestation');
  validateRunnerAttestation(value, { expectedArchitecture, expectedHardwareClass, expectedRunnerId });
  let key;
  try { key = crypto.createPublicKey(publicKeyFile.bytes); } catch { throw new Error('runner attestation public key is invalid'); }
  if (key.asymmetricKeyType !== 'ed25519' || publicKeyFingerprint(key) !== fingerprint) throw new Error('runner attestation public key fingerprint mismatch');
  const encoded = signatureFile.bytes.toString('ascii');
  if (!/^(?:[A-Za-z0-9+/]{4}){21}[A-Za-z0-9+/]{2}==\n$/u.test(encoded)) throw new Error('runner attestation signature encoding is invalid');
  const signatureBytes = Buffer.from(encoded.trim(), 'base64');
  if (signatureBytes.length !== 64 || !crypto.verify(null, payload.bytes, key, signatureBytes)) throw new Error('runner attestation signature is invalid');
  return Object.freeze({ schema_version: 1, attestation_sha256: payload.sha256, signature_sha256: signatureFile.sha256, public_key_fingerprint: fingerprint, runner_id: value.runner_id, architecture: value.architecture, hardware_class: value.hardware_class, model_identifier: value.model_identifier, native_execution: true, vm_detected: false, rosetta_detected: false, attested_at: value.attested_at, signed: true, owner_uid: payload.uid, mode: payload.mode });
}

function parseCLI(argv) {
  if (argv.length !== 7 && argv.length !== 8) throw new Error('Usage: verify-runner-attestation.mjs ATTESTATION.json SIGNATURE PUBLIC-KEY FINGERPRINT ARCHITECTURE HARDWARE-CLASS RUNNER-ID [artifact]');
  if (argv.length === 8 && argv[7] !== 'artifact') throw new Error('runner attestation verification mode is invalid');
  return { attestation: argv[0], signature: argv[1], publicKey: argv[2], fingerprint: argv[3], expectedArchitecture: argv[4], expectedHardwareClass: argv[5], expectedRunnerId: argv[6] === '-' ? undefined : argv[6], production: argv.length === 7 };
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try { process.stdout.write(`${JSON.stringify(verifyRunnerAttestation(parseCLI(process.argv.slice(2)), { production: true }), null, 2)}\n`); }
  catch (error) { process.stderr.write(`${error instanceof Error ? error.message : 'runner attestation verification failed'}\n`); process.exitCode = 1; }
}
