import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import {
  QUALIFICATION_ACTIVATION_DIRECTORY,
  materializeQualificationActivation,
  removeQualificationActivation
} from './materialize-qualification-activation.mjs';

const activation = Object.freeze({
  schema_version: 1,
  agent_id: '12345678-1234-4123-8123-123456789abc',
  agent_kind: 'claude_code',
  requested_ttl_seconds: 60,
  proof: '{"grant":"xxxxxxxxxxxxxxxx"}'
});

const fixture = () => {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'agentpass-activation-materialize-')));
  fs.chmodSync(root, 0o700);
  return { root, destination: path.join(root, 'activation'), uid: process.getuid() };
};

const materialize = (value, overrides = {}) => materializeQualificationActivation({ activation, destination: value.destination, expectedUid: value.uid, uid: value.uid, production: false, ...overrides });
const remove = (value, result, overrides = {}) => removeQualificationActivation({ destination: value.destination, expected: result, expectedUid: value.uid, uid: value.uid, production: false, ...overrides });

test('production materialization is fixed to the root-owned macOS destination', () => {
  assert.equal(QUALIFICATION_ACTIVATION_DIRECTORY, '/private/var/db/agentpass-qualification/activation');
  assert.throws(() => materializeQualificationActivation({ activation, platform: 'linux', uid: 0 }), /root on macOS/u);
  assert.throws(() => materializeQualificationActivation({ activation, platform: 'darwin', uid: 501 }), /root on macOS/u);
});

test('materializes one 0600 canonical document and returns only digest metadata', () => {
  const value = fixture();
  const result = materialize(value);
  try {
    assert.deepEqual(Object.keys(result).sort(), ['action', 'document_sha256', 'ok', 'proof_bytes', 'proof_sha256']);
    assert.equal(result.ok, true);
    assert.equal(fs.statSync(value.destination).mode & 0o777, 0o700);
    assert.equal(fs.statSync(path.join(value.destination, 'activation.json')).mode & 0o777, 0o600);
    assert.doesNotMatch(JSON.stringify(result), /xxxxxxxx/u);
    assert.deepEqual(JSON.parse(fs.readFileSync(path.join(value.destination, 'activation.json'))), activation);
  } finally {
    remove(value, result);
    fs.rmSync(value.root, { recursive: true, force: true });
  }
});

test('refuses stale output and identity-bound cleanup refuses substitution', () => {
  const stale = fixture();
  fs.mkdirSync(stale.destination, { mode: 0o700 });
  assert.throws(() => materialize(stale), /already exists/u);
  fs.rmSync(stale.root, { recursive: true, force: true });

  const value = fixture(); const result = materialize(value);
  fs.writeFileSync(path.join(value.destination, 'activation.json'), Buffer.from(JSON.stringify({ ...activation, proof: '{"grant":"yyyyyyyyyyyyyyyy"}' })), { mode: 0o600 });
  assert.throws(() => remove(value, result), /cleanup failed/u);
  fs.rmSync(value.root, { recursive: true, force: true });
});

test('recovery requires no-active-Agent proof and handles absence idempotently', () => {
  const value = fixture(); const result = materialize(value);
  assert.throws(() => remove(value, result, { expected: undefined, recovery: true, proveNoActiveAgent: () => false }), /active Agent/u);
  assert.equal(remove(value, result, { expected: undefined, recovery: true, proveNoActiveAgent: () => true }).action, 'removed');
  assert.equal(remove(value, result, { expected: undefined, recovery: true, proveNoActiveAgent: () => true }).action, 'absent');
  fs.rmSync(value.root, { recursive: true, force: true });
});
