import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { canonicalJSON, verifyRunnerAttestation } from '../scripts/release/p0c/verify-runner-attestation.mjs';

const fixture = () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpass-runner-attestation-'));
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const value = { schema_version: 1, kind: 'agentpass.macos.protected-runner-attestation', runner_id: 'p0c-apple-01', architecture: 'arm64', hardware_class: 'apple_silicon', model_identifier: 'Mac14,2', native_execution: true, vm_detected: false, rosetta_detected: false, attested_at: '2026-08-21T12:00:00.000Z' };
  const payload = canonicalJSON(value); const signature = Buffer.from(`${crypto.sign(null, payload, privateKey).toString('base64')}\n`); const pem = publicKey.export({ type: 'spki', format: 'pem' });
  const write = (name, bytes) => { const file = path.join(root, name); fs.writeFileSync(file, bytes, { mode: 0o600 }); return file; };
  const publicKeyBytes = Buffer.from(pem); const key = crypto.createPublicKey(publicKeyBytes); const fingerprint = `SHA256:${crypto.createHash('sha256').update(key.export({ type: 'spki', format: 'der' })).digest('base64url')}`;
  return { root, value, attestation: write('attestation.json', payload), signature: write('attestation.sig', signature), publicKey: write('attestation.pem', publicKeyBytes), fingerprint };
};

test('runner attestation verifies signature and lane binding', () => {
  const value = fixture();
  const result = verifyRunnerAttestation({ ...value, expectedArchitecture: 'arm64', expectedHardwareClass: 'apple_silicon', expectedRunnerId: 'p0c-apple-01' });
  assert.equal(result.signed, true); assert.equal(result.hardware_class, 'apple_silicon'); assert.match(result.attestation_sha256, /^[0-9a-f]{64}$/u);
});

test('runner attestation rejects wrong key, lane, VM, and symlink inputs', () => {
  const value = fixture();
  assert.throws(() => verifyRunnerAttestation({ ...value, expectedHardwareClass: 'intel_t2' }), /hardware class/);
  const other = crypto.generateKeyPairSync('ed25519').publicKey.export({ type: 'spki', format: 'pem' }); fs.writeFileSync(value.publicKey, other);
  assert.throws(() => verifyRunnerAttestation(value), /fingerprint mismatch/);
  const vm = fixture(); vm.value.vm_detected = true; fs.writeFileSync(vm.attestation, canonicalJSON(vm.value));
  assert.throws(() => verifyRunnerAttestation(vm), /facts are invalid/);
  const linked = fixture(); const target = path.join(linked.root, 'real.json'); fs.renameSync(linked.attestation, target); fs.symlinkSync(target, linked.attestation);
  assert.throws(() => verifyRunnerAttestation(linked), /cannot be opened/);
});
