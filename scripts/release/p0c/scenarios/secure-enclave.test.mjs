import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { performSecureEnclaveEnrollment } from './secure-enclave-enrollment';

const privateKey = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).privateKey;
const publicKey = crypto.createPublicKey(privateKey).export({ type: 'spki', format: 'pem' });
const fingerprint = `SHA256:${'A'.repeat(43)}`;
const release = { artifactSha256: 'a'.repeat(64), sourceCommit: 'b'.repeat(40), teamId: 'ABCDE12345' };
const machine = { serviceConfigPath: '/Library/Application Support/AgentPass/native-service.json', serviceLabel: 'dev.agentpass.native-service', checkpointDirectory: '/private/var/db/agentpass-qualification', executables: { native_service: { path: '/service', sha256: 'c'.repeat(64) }, native_client: { path: '/client', sha256: 'd'.repeat(64) } } };
const verifiedCheckpoint = async (_path, operation) => operation();
const success = (value) => ({ ok: true, exitCode: 0, signal: null, stdout: Buffer.from(`${JSON.stringify(value)}\n`), stderr: Buffer.alloc(0) });
const envelope = (value) => success({ ok: true, stdout_base64: Buffer.from(`${JSON.stringify(value)}\n`).toString('base64') });
const snapshot = (overrides = {}) => ({ access_group: 'ABCDE12345.dev.agentpass.service-keys', application_tag: 'dev.agentpass.device-auth.v1', key_class: 'private', key_size_bits: 256, keychain_match_count: 1, private_exportable: false, public_key_fingerprint: fingerprint, secure_enclave: true, sign_supported: true, status: 'passed', token_id: 'SecureEnclave', version: 1, ...overrides });
const control = (overrides = {}) => ({ control_configured: true, control_format_epoch: 2, control_operational: true, control_device_auth_public_key: publicKey, ...overrides });

const runner = ({ snapshotValue = snapshot(), controlValue = control(), corruptSignature = false } = {}) => async (_entry, args, options = {}) => {
  const action = args.includes('--device-auth') ? args[1] : args.at(-1);
  if (action === 'qualify') return success(snapshotValue);
  if (action === 'key') return success({ fingerprint, public_key_pem: publicKey });
  if (action === 'sign') { const signature = crypto.sign('sha256', options.input, { key: privateKey, dsaEncoding: 'ieee-p1363' }); if (corruptSignature) signature[0] ^= 0xff; return success({ signature_base64: signature.toString('base64') }); }
  if (action === 'control-status') return envelope(controlValue);
  throw new Error('unexpected command');
};

test('secure enclave scenario proves live nonexportable key, possession, and control-key continuity', async () => {
  assert.deepEqual(await performSecureEnclaveEnrollment({ release, machine, production: false, getUid: () => 0, runPinned: runner(), withCheckpoint: verifiedCheckpoint }), ['secure-enclave-key-creation', 'secure-enclave-nonexportability']);
});

test('secure enclave scenario rejects exportability, bad signatures, key substitution, and non-root execution', async () => {
  await assert.rejects(() => performSecureEnclaveEnrollment({ release, machine, production: false, getUid: () => 0, runPinned: runner({ snapshotValue: snapshot({ private_exportable: true }) }), withCheckpoint: verifiedCheckpoint }), /did not prove/);
  await assert.rejects(() => performSecureEnclaveEnrollment({ release, machine, production: false, getUid: () => 0, runPinned: runner({ corruptSignature: true }), withCheckpoint: verifiedCheckpoint }), /signature is invalid/);
  await assert.rejects(() => performSecureEnclaveEnrollment({ release, machine, production: false, getUid: () => 0, runPinned: runner({ controlValue: control({ control_device_auth_public_key: 'substituted' }) }), withCheckpoint: verifiedCheckpoint }), /not bound/);
  await assert.rejects(() => performSecureEnclaveEnrollment({ release, machine, production: false, getUid: () => 501, runPinned: runner(), withCheckpoint: verifiedCheckpoint }), /requires root/);
});
