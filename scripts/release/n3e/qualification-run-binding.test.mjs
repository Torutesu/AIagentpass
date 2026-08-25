import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import {
  FIXED_QUALIFICATION_RUN_BINDING_PATH,
  QUALIFICATION_RUN_BINDING_DIRECTORY,
  QUALIFICATION_RUN_BINDING_PATTERN,
  materializeQualificationRunBinding,
  materializeQualificationRunBindingForTest,
  readQualificationRunBinding,
  recoverQualificationRunBinding,
  removeQualificationRunBinding,
  validateQualificationRunBinding
} from './qualification-run-binding.mjs';

const uid = typeof process.getuid === 'function' ? process.getuid() : 0;
const randomBytes = () => Buffer.alloc(16, 7);

const withBindingDirectory = (callback) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpass-run-binding-'));
  const directory = path.join(root, 'release');
  fs.mkdirSync(directory, { mode: 0o700 });
  fs.chmodSync(directory, 0o700);
  try { return callback({ root, directory, destination: path.join(directory, 'run-binding') }); }
  finally { fs.rmSync(root, { recursive: true, force: true }); }
};

const options = (destination, extra = {}) => ({
  destination,
  expectedUid: uid,
  uid,
  production: false,
  platform: process.platform,
  fs,
  path,
  randomBytes,
  processId: 1234,
  ...extra
});

test('exports the fixed production location and exact value contract', () => {
  assert.equal(QUALIFICATION_RUN_BINDING_DIRECTORY, '/private/var/db/agentpass-qualification/release');
  assert.equal(FIXED_QUALIFICATION_RUN_BINDING_PATH, `${QUALIFICATION_RUN_BINDING_DIRECTORY}/run-binding`);
  assert.equal(QUALIFICATION_RUN_BINDING_PATTERN.test('run:2026-08-14_01'), true);
  for (const value of ['', '.bad', 'a\n', 'a\r', 'a/b', 'a\\b', 'a'.repeat(129)]) assert.throws(() => validateQualificationRunBinding(value), /invalid|too large/u);
  assert.equal(validateQualificationRunBinding('A0._:-z'), 'A0._:-z');
});

test('materializes one binding atomically with protected modes and returns identity', () => withBindingDirectory(({ destination, directory }) => {
  const result = materializeQualificationRunBindingForTest({ ...options(destination), value: 'run:2026-08-14_01' });
  assert.equal(result.action, 'materialized');
  assert.equal(result.value, 'run:2026-08-14_01');
  assert.equal(result.identity.nlink, '1');
  assert.equal(fs.statSync(directory).mode & 0o7777, 0o700);
  assert.equal(fs.statSync(destination).mode & 0o7777, 0o600);
  assert.equal(fs.readFileSync(destination, 'utf8'), 'run:2026-08-14_01');
  assert.deepEqual(readQualificationRunBinding(options(destination)), { value: result.value, bytes: Buffer.from(result.value), identity: result.identity, path: path.resolve(destination) });
}));

test('never overwrites an existing binding and rejects invalid values', () => withBindingDirectory(({ destination }) => {
  materializeQualificationRunBindingForTest({ ...options(destination), value: 'first' });
  assert.throws(() => materializeQualificationRunBindingForTest({ ...options(destination), value: 'second' }), /already exists|materialization failed/u);
  assert.equal(fs.readFileSync(destination, 'utf8'), 'first');
  for (const value of ['bad\nvalue', 'bad\rvalue', 'a/b', 'a'.repeat(129)]) assert.throws(() => materializeQualificationRunBindingForTest({ ...options(path.join(path.dirname(destination), `binding-${Math.random()}`)), value }), /invalid|too large/u);
}));

test('production mode rejects path, filesystem, and non-root overrides', () => withBindingDirectory(({ destination }) => {
  assert.throws(() => materializeQualificationRunBinding({ destination, value: 'run', expectedUid: uid, uid, platform: 'darwin', production: true }), /fixed path|root/u);
  assert.throws(() => materializeQualificationRunBinding({ destination: FIXED_QUALIFICATION_RUN_BINDING_PATH, value: 'run', expectedUid: 1, uid: 1, platform: 'darwin', production: true }), /root/u);
  assert.throws(() => materializeQualificationRunBinding({ destination, value: 'run', expectedUid: uid, uid, platform: process.platform, production: true, fs }), /root|fixed path/u);
}));

test('normal cleanup requires both value and exact file identity', () => withBindingDirectory(({ destination }) => {
  const materialized = materializeQualificationRunBindingForTest({ ...options(destination), value: 'run-cleanup' });
  assert.throws(() => removeQualificationRunBinding({ ...options(destination), expected: { value: 'run-cleanup' } }), /identity|required/u);
  assert.throws(() => removeQualificationRunBinding({ ...options(destination), expected: { value: 'other', identity: materialized.identity } }), /changed/u);
  const changed = { ...materialized.identity, ctime_ns: '0' };
  assert.throws(() => removeQualificationRunBinding({ ...options(destination), expected: { value: 'run-cleanup', identity: changed } }), /changed/u);
  assert.equal(fs.existsSync(destination), true);
  const removed = removeQualificationRunBinding({ ...options(destination), expected: materialized });
  assert.equal(removed.action, 'removed');
  assert.equal(fs.existsSync(destination), false);
}));

test('recovery requires a no-active-run proof and is idempotent when absent', () => withBindingDirectory(({ destination }) => {
  const materialized = materializeQualificationRunBindingForTest({ ...options(destination), value: 'run-recovery' });
  assert.throws(() => recoverQualificationRunBinding({ ...options(destination) }), /no-active-run|active run/u);
  assert.throws(() => recoverQualificationRunBinding({ ...options(destination), proveNoActiveRun: () => false }), /no-active-run|active run/u);
  let proofCalls = 0;
  const recovered = recoverQualificationRunBinding({ ...options(destination), proveNoActiveRun: () => { proofCalls += 1; return true; } });
  assert.equal(recovered.action, 'removed');
  assert.equal(recovered.identity.ino, materialized.identity.ino);
  assert.equal(proofCalls, 1);
  const absent = recoverQualificationRunBinding({ ...options(destination), proveNoActiveRun: () => true });
  assert.equal(absent.action, 'absent');
}));

test('recovery refuses symlink and unsafe parent instead of deleting through it', () => withBindingDirectory(({ root, directory, destination }) => {
  const target = path.join(root, 'outside');
  fs.writeFileSync(target, 'outside', { mode: 0o600 });
  fs.symlinkSync(target, destination);
  assert.throws(() => recoverQualificationRunBinding({ ...options(destination), proveNoActiveRun: () => true }), /unsafe|failed|unavailable/u);
  assert.equal(fs.readFileSync(target, 'utf8'), 'outside');
  fs.unlinkSync(destination);
  fs.chmodSync(directory, 0o755);
  assert.throws(() => materializeQualificationRunBindingForTest({ ...options(destination), value: 'run' }), /mode|unsafe/u);
}));
