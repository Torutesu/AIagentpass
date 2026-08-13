import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import {
  FIXED_INPUT_KIND,
  FIXED_INPUT_MAX_BYTES,
  FIXED_INPUT_SCHEMA_VERSION,
  FIXED_QUALIFICATION_INPUT_PATH,
  canonicalFixedQualificationInput,
  materializeFixedQualificationInput,
  materializeFixedQualificationInputForTest,
  parseQualificationInputMaterializerCLI
} from './qualification-input-materializer.mjs';
import { parseFixedQualificationInput } from './run-fixed-protected-qualification.mjs';

const UID = process.getuid?.();
if (typeof UID !== 'number') throw new Error('these tests require a POSIX process owner');

const input = () => ({
  schema_version: FIXED_INPUT_SCHEMA_VERSION,
  kind: FIXED_INPUT_KIND,
  provision: {
    scenario: 'pre-cloud-kill',
    expires_at_epoch_seconds: 1_800_000_000,
    run_binding: 'run-0'
  },
  activation: {
    schema_version: 1,
    agent_id: '12345678-1234-4123-8123-123456789abc',
    agent_kind: 'claude_code',
    requested_ttl_seconds: 60,
    proof: '{"grant":"opaque"}'
  }
});

const digest = (bytes) => crypto.createHash('sha256').update(bytes).digest('hex');
const stagingFiles = (directory) => fs.readdirSync(directory).filter((name) => /^\.input\.json\..+\.tmp$/u.test(name));

const fixture = () => {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'agentpass-input-materializer-')));
  const directory = path.join(root, 'qualification');
  fs.mkdirSync(directory, { mode: 0o700 });
  fs.chmodSync(directory, 0o700);
  return { root, directory, destination: path.join(directory, 'input.json') };
};

const options = (value, overrides = {}) => ({
  input: input(),
  destination: value.destination,
  expectedUid: UID,
  uid: UID,
  production: false,
  processId: 4242,
  randomBytes: () => Buffer.alloc(16, 0x42),
  ...overrides
});

test('exports the runner schema and fixed production destination', () => {
  assert.equal(FIXED_QUALIFICATION_INPUT_PATH, '/private/var/db/agentpass-qualification/input.json');
  assert.equal(FIXED_INPUT_SCHEMA_VERSION, 1);
  assert.equal(FIXED_INPUT_KIND, 'agentpass-n3e-fixed-protected-qualification-input');
  assert.equal(FIXED_INPUT_MAX_BYTES, 64 * 1024);
});

test('CLI is closed to fixed inbox materialization and does not echo caller values', () => {
  assert.deepEqual(parseQualificationInputMaterializerCLI(['materialize']), { operation: 'materialize' });
  for (const args of [[], ['materialize', '/tmp/input'], ['--input', '/tmp/input']]) assert.throws(() => parseQualificationInputMaterializerCLI(args), /usage/u);
  const modulePath = path.resolve(new URL('./qualification-input-materializer.mjs', import.meta.url).pathname);
  const result = spawnSync(process.execPath, [modulePath, 'materialize', 'do-not-read'], { encoding: 'utf8' });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /usage/u);
  assert.doesNotMatch(result.stderr + result.stdout, /do-not-read/u);
});

test('production mode cannot select a path or bypass the macOS root guard', () => {
  const value = fixture();
  try {
    assert.throws(
      () => materializeFixedQualificationInput({ ...options(value), production: true, platform: 'darwin', uid: 0, expectedUid: 0 }),
      /fixed path/u
    );
    assert.throws(
      () => materializeFixedQualificationInput({ input: input(), destination: FIXED_QUALIFICATION_INPUT_PATH, production: true, platform: 'linux', uid: 0, expectedUid: 0 }),
      /root on macOS/u
    );
  } finally {
    fs.rmSync(value.root, { recursive: true, force: true });
  }
});

test('canonicalFixedQualificationInput emits the existing closed schema and bounded bytes', () => {
  const bytes = canonicalFixedQualificationInput(input());
  assert.ok(Buffer.isBuffer(bytes));
  assert.ok(bytes.length > 0 && bytes.length <= FIXED_INPUT_MAX_BYTES);
  assert.equal(bytes.toString('utf8'), `${bytes.toString('utf8').trimEnd()}\n`);
  const parsed = parseFixedQualificationInput(bytes);
  assert.equal(parsed.provisionRequest.scenario, 'pre-cloud-kill');
  assert.equal(parsed.activation.agent_kind, 'claude_code');

  const extra = input();
  extra.provision.extra = 'reject-me';
  assert.throws(() => canonicalFixedQualificationInput(extra), /not closed/u);

  const accessor = input();
  Object.defineProperty(accessor.provision, 'manifest_path', { get: () => '/tmp/attacker', enumerable: true });
  assert.throws(() => canonicalFixedQualificationInput(accessor), /closed|accessor/u);
});

test('materializes one canonical 0600 document in an exact 0700 directory', () => {
  const value = fixture();
  const expected = canonicalFixedQualificationInput(input());
  try {
    const result = materializeFixedQualificationInputForTest(options(value));
    assert.deepEqual(Object.keys(result).sort(), ['action', 'document_bytes', 'document_sha256', 'ok']);
    assert.deepEqual(result, {
      ok: true,
      action: 'materialized',
      document_sha256: digest(expected),
      document_bytes: expected.length
    });
    assert.equal(fs.statSync(value.directory).mode & 0o7777, 0o700);
    const installed = fs.lstatSync(value.destination);
    assert.equal(installed.mode & 0o7777, 0o600);
    assert.equal(installed.nlink, 1);
    assert.deepEqual(fs.readFileSync(value.destination), expected);
    assert.deepEqual(stagingFiles(value.directory), []);
  } finally {
    fs.rmSync(value.root, { recursive: true, force: true });
  }
});

test('refuses an existing destination and never overwrites it', () => {
  const value = fixture();
  const original = Buffer.from('existing one-shot input\n', 'utf8');
  fs.writeFileSync(value.destination, original, { mode: 0o600 });
  fs.chmodSync(value.destination, 0o600);
  try {
    assert.throws(() => materializeFixedQualificationInputForTest(options(value)), /already exists|failed/u);
    assert.deepEqual(fs.readFileSync(value.destination), original);
    assert.deepEqual(stagingFiles(value.directory), []);
  } finally {
    fs.rmSync(value.root, { recursive: true, force: true });
  }
});

test('rejects a destination symlink and an unsafe or symlinked parent', () => {
  const linked = fixture();
  const target = path.join(linked.root, 'target.json');
  fs.writeFileSync(target, Buffer.from('do not follow\n'), { mode: 0o600 });
  fs.symlinkSync(target, linked.destination);
  try {
    assert.throws(() => materializeFixedQualificationInputForTest(options(linked)), /already exists|failed/u);
  } finally {
    fs.rmSync(linked.root, { recursive: true, force: true });
  }

  const unsafe = fixture();
  fs.chmodSync(unsafe.directory, 0o755);
  try {
    assert.throws(() => materializeFixedQualificationInputForTest(options(unsafe)), /unsafe|failed/u);
  } finally {
    fs.rmSync(unsafe.root, { recursive: true, force: true });
  }

  const symlinkParent = fixture();
  const realDirectory = path.join(symlinkParent.root, 'real');
  fs.mkdirSync(realDirectory, { mode: 0o700 });
  fs.chmodSync(realDirectory, 0o700);
  const alias = path.join(symlinkParent.root, 'alias');
  fs.symlinkSync(realDirectory, alias);
  try {
    assert.throws(() => materializeFixedQualificationInputForTest({ ...options(symlinkParent), destination: path.join(alias, 'input.json') }), /unsafe|failed/u);
  } finally {
    fs.rmSync(symlinkParent.root, { recursive: true, force: true });
  }
});

test('rejects an over-limit canonical document before creating staging', () => {
  const value = fixture();
  const oversized = input();
  oversized.provision.scenario = `pre-cloud-kill-${'x'.repeat(FIXED_INPUT_MAX_BYTES)}`;
  try {
    assert.throws(() => materializeFixedQualificationInputForTest({ ...options(value), input: oversized }), /size limit|failed/u);
    assert.equal(fs.existsSync(value.destination), false);
    assert.deepEqual(stagingFiles(value.directory), []);
  } finally {
    fs.rmSync(value.root, { recursive: true, force: true });
  }
});

test('fsync failure rolls back only the identity-bound staging file', () => {
  const value = fixture();
  let fsyncCalls = 0;
  const injectedFileSystem = {
    ...fs,
    fsyncSync(descriptor) {
      fsyncCalls += 1;
      if (fsyncCalls === 1) throw new Error('simulated fsync failure');
      return fs.fsyncSync(descriptor);
    }
  };
  try {
    assert.throws(() => materializeFixedQualificationInputForTest(options(value, { fileSystem: injectedFileSystem })), /failed/u);
    assert.equal(fsyncCalls, 1);
    assert.equal(fs.existsSync(value.destination), false);
    assert.deepEqual(stagingFiles(value.directory), []);
  } finally {
    fs.rmSync(value.root, { recursive: true, force: true });
  }
});

test('rollback refuses to unlink a substituted staging path', () => {
  const value = fixture();
  let staging;
  let fsyncCalls = 0;
  const injectedFileSystem = {
    ...fs,
    openSync(file, ...args) {
      if (file.endsWith('.tmp')) staging = file;
      return fs.openSync(file, ...args);
    },
    fsyncSync(descriptor) {
      fsyncCalls += 1;
      if (fsyncCalls === 1) throw new Error('simulated fsync failure');
      return fs.fsyncSync(descriptor);
    },
    lstatSync(file, options) {
      const stat = fs.lstatSync(file, options);
      if (file === staging) {
        stat.ino += 1n;
        return stat;
      }
      return stat;
    }
  };
  try {
    assert.throws(() => materializeFixedQualificationInputForTest(options(value, { fileSystem: injectedFileSystem })), /failed/u);
    assert.equal(fs.existsSync(value.destination), false);
    assert.equal(stagingFiles(value.directory).length, 1);
  } finally {
    for (const name of stagingFiles(value.directory)) fs.unlinkSync(path.join(value.directory, name));
    fs.rmSync(value.root, { recursive: true, force: true });
  }
});
