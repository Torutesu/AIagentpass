#!/usr/bin/env node
import { createHash, createPublicKey, verify } from 'node:crypto';
import fs from 'node:fs';
import { basename, resolve } from 'node:path';

const [input, artifactInput, signatureInput, publicKeyInput, expectedFingerprint] = process.argv.slice(2);
if (!input || ![1, 5].includes(process.argv.slice(2).length)) throw new Error('Usage: validate-hardware-qualification.mjs RESULT.json [ARTIFACT SIGNATURE OPERATOR-PUBLIC-KEY EXPECTED-FINGERPRINT]');
if (!Number.isInteger(fs.constants.O_NOFOLLOW)) throw new Error('O_NOFOLLOW is unavailable on this platform');

const statIdentity = (stat) => [stat.dev, stat.ino, stat.mode, stat.nlink, stat.size, stat.mtimeNs, stat.ctimeNs].join(':');
const snapshotFile = (pathInput, { maximum, capture = false } = {}) => {
  const path = resolve(pathInput);
  const descriptor = fs.openSync(path, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  try {
    const before = fs.fstatSync(descriptor, { bigint: true });
    if (!before.isFile() || before.nlink !== 1n || before.size <= 0n || before.size > BigInt(maximum) || before.size > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error(`unsafe hardware qualification input: ${pathInput}`);
    const size = Number(before.size);
    const hash = createHash('sha256');
    const chunks = capture ? [] : null;
    const buffer = Buffer.allocUnsafe(Math.min(1024 * 1024, size));
    let offset = 0;
    while (offset < size) {
      const wanted = Math.min(buffer.length, size - offset);
      const count = fs.readSync(descriptor, buffer, 0, wanted, offset);
      if (count === 0) throw new Error(`hardware qualification input changed while reading: ${pathInput}`);
      const chunk = buffer.subarray(0, count); hash.update(chunk); if (chunks) chunks.push(Buffer.from(chunk)); offset += count;
    }
    const after = fs.fstatSync(descriptor, { bigint: true });
    if (statIdentity(before) !== statIdentity(after)) throw new Error(`hardware qualification input changed while reading: ${pathInput}`);
    return { name: basename(path), bytes: size, sha256: hash.digest('hex'), content: chunks ? Buffer.concat(chunks, size) : undefined };
  } finally { fs.closeSync(descriptor); }
};
const exactKeys = (value, keys, label) => {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) throw new Error(`${label} must be an object`);
  const actual = Object.keys(value).sort(); const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) throw new Error(`${label} has missing or unknown fields`);
};

const report = snapshotFile(input, { maximum: 1024 * 1024, capture: true });
let value;
try { value = JSON.parse(report.content.toString('utf8')); } catch { throw new Error('hardware qualification report is not valid UTF-8 JSON'); }
exactKeys(value, ['schema_version', 'artifact_sha256', 'architecture', 'hardware_class', 'model_identifier', 'macos_version', 'macos_build', 'secure_enclave', 'started_at', 'completed_at', 'operator', 'qualified', 'tests'], 'hardware qualification report');

const allowedArchitectures = new Set(['arm64', 'x86_64']);
const allowedHardware = new Set(['apple_silicon', 'intel_t2', 'intel_without_t2']);
if (value.schema_version !== 1 || typeof value.artifact_sha256 !== 'string' || !/^[0-9a-f]{64}$/.test(value.artifact_sha256)) throw new Error('invalid artifact identity');
if (!allowedArchitectures.has(value.architecture) || !allowedHardware.has(value.hardware_class)) throw new Error('invalid hardware identity');
if ((value.hardware_class === 'apple_silicon' && value.architecture !== 'arm64') || (value.hardware_class !== 'apple_silicon' && value.architecture !== 'x86_64')) throw new Error('hardware class and architecture disagree');
if (typeof value.macos_version !== 'string' || !/^\d+\.\d+(?:\.\d+)?$/.test(value.macos_version)) throw new Error('invalid macOS version');
if (typeof value.model_identifier !== 'string' || !/^[A-Za-z0-9,._-]{3,80}$/.test(value.model_identifier) || typeof value.macos_build !== 'string' || !/^[A-Za-z0-9]{3,32}$/.test(value.macos_build) || typeof value.secure_enclave !== 'boolean') throw new Error('hardware attestation fields are invalid');
if (typeof value.operator !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9@._-]{2,127}$/.test(value.operator) || typeof value.qualified !== 'boolean') throw new Error('invalid qualification conclusion');
const started = Date.parse(value.started_at); const completed = Date.parse(value.completed_at);
const utcTimestamp = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/;
if (!Number.isFinite(started) || !Number.isFinite(completed) || !utcTimestamp.test(value.started_at) || !utcTimestamp.test(value.completed_at) || completed < started || completed - started > 24 * 60 * 60 * 1000) throw new Error('invalid hardware qualification time window');
if (!Array.isArray(value.tests) || value.tests.length === 0 || value.tests.length > 128) throw new Error('invalid hardware test count');

const names = new Set();
const requiredTests = new Set([
  'install-and-register', 'secure-enclave-key-creation', 'secure-enclave-nonexportability',
  'unattended-sign', 'session-expiry-revocation', 'all-key-rotations', 'key-deletion-absence',
  'lifecycle-rollback-fail-stop', 'checkpoint-anchor-transition', 'recovery-threshold',
  'audit-evidence-rotation', 'audit-segment-corruption', 'sleep-wake', 'reboot',
  'upgrade-preserves-state', 'uninstall-preserves-state', 'tampered-client-denied',
  value.architecture === 'arm64' ? 'apple-silicon-secure-enclave' : 'intel-t2-secure-enclave'
]);
for (const test of value.tests) {
  if (!['passed', 'failed', 'skipped'].includes(test?.status)) throw new Error('invalid hardware test status');
  exactKeys(test, test.status === 'passed' ? ['name', 'status', 'evidence'] : ['name', 'status', 'reason'], 'hardware test');
  if (typeof test.name !== 'string' || !/^[a-z0-9][a-z0-9-]{1,79}$/.test(test.name) || names.has(test.name)) throw new Error('invalid or duplicate hardware test');
  names.add(test.name);
  if (test.status === 'passed' && (typeof test.evidence !== 'string' || !/^sha256:[0-9a-f]{64}$/.test(test.evidence))) throw new Error('passed hardware tests require a SHA-256 evidence binding');
  if (test.status !== 'passed' && (typeof test.reason !== 'string' || test.reason.length < 3 || test.reason.length > 1024)) throw new Error('non-passing hardware tests require a bounded reason');
}

if (value.qualified === true && (value.secure_enclave !== true || value.hardware_class === 'intel_without_t2')) throw new Error('hardware cannot qualify for Secure Enclave guarantees');
if (value.qualified === true && (value.tests.some((test) => test.status !== 'passed') || [...requiredTests].some((name) => !names.has(name)))) throw new Error('qualified result is missing required passing tests');
if (value.qualified === true && !report.content.equals(Buffer.from(`${JSON.stringify(value, null, 2)}\n`, 'utf8'))) throw new Error('qualified hardware report is not canonical JSON');

const suppliedGate = [artifactInput, signatureInput, publicKeyInput, expectedFingerprint].filter((item) => item !== undefined).length;
if (suppliedGate !== 0 && suppliedGate !== 4) throw new Error('hardware qualification verification inputs must be supplied as a complete set');
if (value.qualified === true && suppliedGate !== 4) throw new Error('qualified result requires exact artifact and detached operator signature verification');

let operatorFingerprint = null;
if (suppliedGate === 4) {
  if (!/^SHA256:[A-Za-z0-9_-]{43}$/.test(expectedFingerprint)) throw new Error('invalid expected operator key fingerprint');
  const artifact = snapshotFile(artifactInput, { maximum: 16 * 1024 * 1024 * 1024, capture: false });
  if (artifact.sha256 !== value.artifact_sha256) throw new Error('qualification artifact hash mismatch');
  const publicKeyBytes = snapshotFile(publicKeyInput, { maximum: 16 * 1024, capture: true }).content;
  const publicKey = createPublicKey(publicKeyBytes);
  if (publicKey.asymmetricKeyType !== 'ed25519') throw new Error('hardware qualification operator key must be Ed25519');
  operatorFingerprint = `SHA256:${createHash('sha256').update(publicKey.export({ type: 'spki', format: 'der' })).digest('base64url')}`;
  if (operatorFingerprint !== expectedFingerprint) throw new Error('hardware qualification operator key fingerprint mismatch');
  const encodedSignature = snapshotFile(signatureInput, { maximum: 1024, capture: true }).content.toString('utf8');
  if (!/^(?:[A-Za-z0-9+/]{4}){21}[A-Za-z0-9+/]{2}==\n$/.test(encodedSignature)) throw new Error('invalid hardware qualification signature encoding');
  const signature = Buffer.from(encodedSignature.trim(), 'base64');
  if (signature.length !== 64 || !verify(null, report.content, publicKey, signature)) throw new Error('hardware qualification operator signature is invalid');
}

console.log(JSON.stringify({ ok: true, qualified: value.qualified, tests: value.tests.length, artifact_sha256: value.artifact_sha256, architecture: value.architecture, hardware_class: value.hardware_class, operator: value.operator, operator_key_fingerprint: operatorFingerprint, operator_signature_verified: suppliedGate === 4 }));
