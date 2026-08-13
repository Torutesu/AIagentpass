import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import {
  CONTROLLER_CANDIDATE_DIRECTORY,
  materializeControllerCandidate,
  removeControllerCandidate
} from './materialize-controller-candidate.mjs';

const now = 1_700_000_000;
const service = Object.freeze({
  qualification_mode: 'n3e-qualification',
  qualification_mach_service_name: 'dev.agentpass.n3e-qualification',
  qualification_candidate_sha256: 'a'.repeat(64),
  qualification_source_commit_sha256: 'b'.repeat(64),
  qualification_code_identities_sha256: 'c'.repeat(64),
  qualification_controller_cdhash: 'd'.repeat(40),
  qualification_run_id_sha256: 'e'.repeat(64),
  qualification_expires_at_epoch_seconds: now + 300,
  qualification_scenario: 'pre-cloud-kill',
  qualification_phase: 'pre-cloud'
});

const fixture = () => {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'agentpass-controller-materialize-')));
  fs.chmodSync(root, 0o700);
  const serviceConfigPath = path.join(root, 'native-service.json');
  const destination = path.join(root, 'controller');
  fs.writeFileSync(serviceConfigPath, JSON.stringify(service), { mode: 0o600 });
  return { root, serviceConfigPath, destination, uid: process.getuid() };
};

const materialize = (value, overrides = {}) => materializeControllerCandidate({
  serviceConfigPath: value.serviceConfigPath,
  destination: value.destination,
  expectedUid: value.uid,
  uid: value.uid,
  platform: process.platform,
  production: false,
  nowEpochSeconds: now,
  ...overrides
});

const remove = (value, result, overrides = {}) => removeControllerCandidate({
  destination: value.destination,
  expected: {
    manifest_sha256: result.manifest_sha256,
    signature_sha256: result.signature_sha256,
    public_key_sha256: result.public_key_sha256
  },
  expectedUid: value.uid,
  uid: value.uid,
  platform: process.platform,
  production: false,
  ...overrides
});

test('uses the fixed production destination and never accepts a non-root production caller', () => {
  assert.equal(CONTROLLER_CANDIDATE_DIRECTORY, '/private/var/db/agentpass-qualification/controller');
  assert.throws(() => materializeControllerCandidate({ platform: 'linux', uid: 0 }), /root on macOS/u);
  assert.throws(() => materializeControllerCandidate({ platform: 'darwin', uid: 501 }), /root on macOS/u);
});

test('derives an exact candidate, signs with one ephemeral key, and writes no private key', () => {
  const value = fixture();
  let calls = 0;
  const result = materialize(value, { generateKeyPair() { calls += 1; return crypto.generateKeyPairSync('ed25519'); } });
  try {
    assert.equal(calls, 1);
    assert.equal(result.ok, true);
    assert.equal(result.action, 'materialized');
    assert.equal(result.files, 3);
    const manifestBytes = fs.readFileSync(path.join(value.destination, 'controller-candidate.json'));
    assert.deepEqual(JSON.parse(manifestBytes), {
      schema_version: 2,
      kind: 'agentpass-n3e-controller-candidate',
      candidate_sha256: service.qualification_candidate_sha256,
      source_commit_sha256: service.qualification_source_commit_sha256,
      code_identities_sha256: service.qualification_code_identities_sha256,
      controller_cdhash: service.qualification_controller_cdhash,
      run_id_sha256: service.qualification_run_id_sha256,
      expires_at_epoch_seconds: service.qualification_expires_at_epoch_seconds,
      scenario: service.qualification_scenario,
      phase: service.qualification_phase
    });
    const publicKey = crypto.createPublicKey(fs.readFileSync(path.join(value.destination, 'release-public.pem')));
    const signature = Buffer.from(fs.readFileSync(path.join(value.destination, 'controller-candidate.sig'), 'utf8').trim(), 'base64');
    assert.equal(crypto.verify(null, manifestBytes, publicKey, signature), true);
    assert.equal(fs.statSync(value.destination).mode & 0o777, 0o700);
    for (const name of ['controller-candidate.json', 'controller-candidate.sig', 'release-public.pem']) assert.equal(fs.statSync(path.join(value.destination, name)).mode & 0o777, 0o600);
    assert.equal(fs.readdirSync(value.destination).some((name) => /private|secret|key\.pem/iu.test(name) && name !== 'release-public.pem'), false);
  } finally {
    remove(value, result);
    fs.rmSync(value.root, { recursive: true, force: true });
  }
});

test('refuses stale output and identity-bound cleanup refuses substitution', () => {
  const stale = fixture();
  fs.mkdirSync(stale.destination, { mode: 0o700 });
  fs.writeFileSync(path.join(stale.destination, 'sentinel'), 'keep', { mode: 0o600 });
  assert.throws(() => materialize(stale), /already exists/u);
  assert.equal(fs.readFileSync(path.join(stale.destination, 'sentinel'), 'utf8'), 'keep');
  fs.rmSync(stale.root, { recursive: true, force: true });

  const value = fixture();
  const result = materialize(value);
  const replacement = `${value.destination}.original`;
  fs.renameSync(value.destination, replacement);
  fs.mkdirSync(value.destination, { mode: 0o700 });
  for (const name of ['controller-candidate.json', 'controller-candidate.sig', 'release-public.pem']) fs.writeFileSync(path.join(value.destination, name), 'substituted', { mode: 0o600 });
  assert.throws(() => remove(value, result), /cleanup failed/u);
  assert.equal(fs.existsSync(replacement), true);
  fs.rmSync(value.destination, { recursive: true, force: true });
  fs.renameSync(replacement, value.destination);
  remove(value, result);
  fs.rmSync(value.root, { recursive: true, force: true });
});

test('recovery cleanup requires an explicit no-active-controller proof and errors stay secret-free', () => {
  const value = fixture();
  const secret = `secret-${crypto.randomBytes(12).toString('hex')}`;
  fs.writeFileSync(value.serviceConfigPath, JSON.stringify({ ...service, unrelated_secret: secret }), { mode: 0o600 });
  const result = materialize(value);
  assert.throws(() => remove(value, result, { expected: undefined, recovery: true, proveNoActiveController: () => false }), /active controller/u);
  const removed = remove(value, result, { expected: undefined, recovery: true, proveNoActiveController: () => true });
  assert.equal(removed.ok, true);
  assert.equal(fs.existsSync(value.destination), false);
  assert.doesNotMatch(JSON.stringify(result), new RegExp(secret, 'u'));
  fs.rmSync(value.root, { recursive: true, force: true });
});
