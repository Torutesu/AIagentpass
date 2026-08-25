import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import test from 'node:test';

import { performCloudPossessionVerification } from './cloud-possession-verification';

const ids = { organization: '11111111-1111-4111-8111-111111111111', candidate: 'release-2026-08-13-01', enrollment: '22222222-2222-4222-8222-222222222222', device: '33333333-3333-4333-8333-333333333333' };
const keyPair = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
const publicKey = keyPair.publicKey.export({ type: 'spki', format: 'pem' }).toString();
const fingerprint = `SHA256:${crypto.createHash('sha256').update(keyPair.publicKey.export({ type: 'spki', format: 'der' })).digest('base64url')}`;
const receiptKeys = crypto.generateKeyPairSync('ed25519');
const receiptPublic = receiptKeys.publicKey.export({ type: 'spki', format: 'pem' }).toString();
const release = { gate: 'cloud-possession-verification', artifactSha256: 'a'.repeat(64), sourceCommit: 'b'.repeat(40), teamId: 'ABCDE12345' };
const machine = { cloudProbeURL: `https://api.example.test/v1/organizations/${ids.organization}/device-enrollments`, serviceConfigPath: '/Library/Application Support/AgentPass/native-service.json', checkpointDirectory: '/private/var/db/agentpass-qualification', executables: { native_service: { path: '/service', sha256: 'c'.repeat(64) } } };
const cloudConfig = { schema_version: 1, issue_url: machine.cloudProbeURL, organization_id: ids.organization, candidate_id: ids.candidate, label: 'P0-C qualification Mac', ttl_ms: 600000, receipt_signer_public_key: receiptPublic };
const checkpoint = async (_path, operation) => operation();
const response = (value, status = 201) => ({ status, headers: { get: () => null }, arrayBuffer: async () => Buffer.from(JSON.stringify(value)) });
const bodyValue = (options) => JSON.parse(Buffer.from(options.body).toString('utf8'));
const binding = (expires = '2099-08-13T00:00:00.000Z') => ({ version: 1, enrollment_id: ids.enrollment, organization_id: ids.organization, device_id: ids.device, candidate_id: ids.candidate, artifact_sha256: release.artifactSha256, source_commit: release.sourceCommit, team_id: release.teamId, device_key_fingerprint: fingerprint, expires_at: expires });
const receipt = (epoch, nonce) => {
  const statement = { version: 1, enrollment_id: ids.enrollment, organization_id: ids.organization, device_id: ids.device, candidate_id: ids.candidate, artifact_sha256: release.artifactSha256, source_commit: release.sourceCommit, team_id: release.teamId, device_key_fingerprint: fingerprint, device_key_epoch: epoch, challenge_nonce_digest: crypto.createHash('sha256').update(nonce).digest('hex'), issued_at: '2026-08-13T00:00:00.000Z' };
  const canonical = (value) => value === null || typeof value !== 'object' ? JSON.stringify(value) : Array.isArray(value) ? `[${value.map(canonical).join(',')}]` : `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
  const bytes = Buffer.from(canonical(statement));
  const signed = Buffer.from(`AgentPass-Cloud-Possession-Receipt-v1\0${canonical(statement)}`);
  return { version: 1, purpose: 'device-enrollment-possession-receipt', key_id: 'possession-receipt-v1', algorithm: 'ed25519', statement, statement_hash: crypto.createHash('sha256').update(bytes).digest('hex'), signature: crypto.sign(null, signed, receiptKeys.privateKey).toString('base64url') };
};
const nativeRunner = async (_entry, args, options = {}) => {
  if (args[1] === 'key') return { ok: true, exitCode: 0, stdout: Buffer.from(JSON.stringify({ fingerprint, public_key_pem: publicKey })), stderr: Buffer.alloc(0) };
  const signature = crypto.sign('sha256', options.input, { key: keyPair.privateKey, dsaEncoding: 'ieee-p1363' });
  return { ok: true, exitCode: 0, stdout: Buffer.from(JSON.stringify({ signature_base64: signature.toString('base64') })), stderr: Buffer.alloc(0) };
};

function fetchFixture({ receiptOverride, completionOverride, issueCandidateOverride } = {}) {
  const calls = [];
  const fetchImpl = async (url, options) => {
    calls.push({ url, options });
    const parsed = new URL(url);
    if (parsed.pathname.endsWith('/device-enrollments')) {
      const candidateBinding = binding();
      if (issueCandidateOverride) candidateBinding.candidate_id = issueCandidateOverride;
      return response({ request_id: '44444444-4444-4444-8444-444444444444', enrollment: { version: 2, proof_version: 2, enrollment_id: ids.enrollment, organization_id: ids.organization, device_id: ids.device, label: cloudConfig.label, platform: 'macos', candidate_binding: candidateBinding, challenge_id: ids.enrollment, nonce: 'N'.repeat(43), expires_at: candidateBinding.expires_at, challenge: { challenge_id: ids.enrollment, nonce: 'N'.repeat(43), expires_at: candidateBinding.expires_at, candidate_id: ids.candidate, device_key_fingerprint: fingerprint }, credential: 'C'.repeat(43), endpoint: `/v1/enrollments/${ids.enrollment}` } });
    }
    if (parsed.pathname === `/v1/enrollments/${ids.enrollment}`) {
      return response(completionOverride ?? { request_id: '55555555-5555-4555-8555-555555555555', enrollment: { version: 1, enrollment_id: ids.enrollment, organization_id: ids.organization, device_id: ids.device, status: 'active', key_algorithm: 'p256-sha256', device_key_epoch: 1, control: { format_epoch: 2, issuer: 'cloud', key_id: 'control-v1', public_key: publicKey, bundle_path: '/v1/bundle', refresh_hint: { key_id: 'refresh-v1', algorithm: 'ed25519', public_key: receiptPublic } } } });
    }
    if (parsed.pathname.endsWith('/enrollment-receipt')) return response(receiptOverride ?? { request_id: '66666666-6666-4666-8666-666666666666', receipt: receipt(1, 'N'.repeat(43)) }, 200);
    throw new Error(`unexpected URL ${url}`);
  };
  return { fetchImpl, calls };
}

const run = (overrides = {}) => {
  const fixture = fetchFixture(overrides);
  return performCloudPossessionVerification({ release, machine, cloudConfig, production: false, getUid: () => 0, runPinned: nativeRunner, fetchImpl: fixture.fetchImpl, withCheckpoint: checkpoint }).then((result) => ({ result, calls: fixture.calls }));
};

test('cloud possession scenario completes issue, native proof, authenticated receipt read, and binding verification', async () => {
  const value = await run();
  assert.deepEqual(value.result, ['cloud-possession-proof']);
  assert.equal(value.calls.length, 3);
  assert.equal(value.calls[1].options.headers['AgentPass-Enrollment-Candidate-Binding'].includes(release.artifactSha256), true);
  assert.equal(value.calls[2].options.headers['AgentPass-Device'], ids.device);
});

test('cloud possession scenario rejects missing production config before network or signing', async () => {
  let touched = false;
  await assert.rejects(() => performCloudPossessionVerification({ release, machine, production: false, getUid: () => 0, readConfig: () => { throw new Error('missing'); }, fetchImpl: async () => { touched = true; }, runPinned: async () => { touched = true; }, withCheckpoint: checkpoint }), /missing/);
  assert.equal(touched, false);
});

test('cloud possession scenario rejects candidate, receipt, and key substitution', async () => {
  await assert.rejects(() => run({ issueCandidateOverride: 'other-release' }), /candidate binding|release/);
  const tamperedReceipt = receipt(1, 'N'.repeat(43));
  tamperedReceipt.statement.candidate_id = 'other-release';
  await assert.rejects(() => run({ receiptOverride: { request_id: '66666666-6666-4666-8666-666666666666', receipt: tamperedReceipt } }), /invalid|binding|signature/);
  await assert.rejects(() => run({ completionOverride: { request_id: '55555555-5555-4555-8555-555555555555', enrollment: { version: 1, enrollment_id: ids.enrollment, organization_id: ids.organization, device_id: ids.device, status: 'active', key_algorithm: 'p256-sha256', device_key_epoch: 2, control: {} } } }), /completion|receipt|binding/);
  const badConfig = { ...cloudConfig, receipt_signer_public_key: publicKey };
  await assert.rejects(() => performCloudPossessionVerification({ release, machine, cloudConfig: badConfig, production: false, getUid: () => 0, runPinned: nativeRunner, fetchImpl: fetchFixture().fetchImpl, withCheckpoint: checkpoint }), /receipt signer|signature/);
});

test('scenario source never accepts or exports a JS private key', async () => {
  const source = await (await import('node:fs/promises')).readFile(new URL('./cloud-possession-verification', import.meta.url), 'utf8');
  assert.doesNotMatch(source, /createPrivateKey|privateKey|private_key|\bAuthorization\b/iu);
});
