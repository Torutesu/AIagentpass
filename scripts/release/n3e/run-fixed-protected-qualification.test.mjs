import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import {
  FIXED_DEPENDENCY_KEYS,
  FIXED_INPUT_KIND,
  FIXED_INPUT_SCHEMA_VERSION,
  FIXED_QUALIFICATION_APPLICATION_PATH,
  FIXED_QUALIFICATION_INPUT_PATH,
  consumeFixedQualificationInput,
  parseFixedQualificationCLI,
  parseFixedQualificationInput,
  recoverFixedQualificationInput,
  recoverFixedProtectedQualification,
  runFixedProtectedQualification
} from './run-fixed-protected-qualification.mjs';

const MODULE_PATH = path.resolve(new URL('./run-fixed-protected-qualification.mjs', import.meta.url).pathname);
const UID = process.getuid?.();

const sortedValue = (value) => {
  if (Array.isArray(value)) return value.map(sortedValue);
  if (value && typeof value === 'object') return Object.fromEntries(Object.keys(value).sort().map((key) => [key, sortedValue(value[key])]));
  return value;
};
const canonical = (value) => Buffer.from(`${JSON.stringify(sortedValue(value), null, 2)}\n`, 'utf8');

const validInput = () => ({
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

const inputFixture = () => {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'agentpass-fixed-n3e-')));
  fs.chmodSync(root, 0o700);
  const inputPath = path.join(root, 'input.json');
  fs.writeFileSync(inputPath, canonical(validInput()), { mode: 0o600 });
  return { root, inputPath };
};

test('exports the fixed dependency inventory and fixed production input path', () => {
  assert.equal(FIXED_QUALIFICATION_INPUT_PATH, '/private/var/db/agentpass-qualification/input.json');
  assert.equal(FIXED_QUALIFICATION_APPLICATION_PATH, '/Applications/AgentPass.app');
  assert.deepEqual([...FIXED_DEPENDENCY_KEYS], [
    'disarmQualification',
    'executeQualification',
    'materializeControllerCandidate',
    'materializeQualificationActivation',
    'materializeQualificationRunBinding',
    'proveNoQualificationProcesses',
    'proveQualificationListenerUnavailable',
    'provisionQualificationConfig',
    'recoverProtectedQualification',
    'recoverQualificationRunBinding',
    'resolveQualificationReleaseTrust',
    'removeControllerCandidate',
    'removeQualificationActivation',
    'removeQualificationRunBinding',
    'restartNativeService',
    'restoreQualificationConfig',
    'runProtectedQualification',
    'withVerifiedCandidateCheckpoint'
  ]);
});

test('source contract separates no-active-process proof from post-restore listener proof and fixes the parent mode', () => {
  const source = fs.readFileSync(MODULE_PATH, 'utf8');
  assert.match(source, /qualificationScenarioDriver\.proveNoQualificationProcesses\(\)/u);
  assert.match(source, /fixedListenerUnavailable/iu);
  assert.match(source, /current === dirname\(inputPath\).*0o700n/u);
  assert.match(source, /proveNoActiveRun: fixedNoActiveProof/u);
  assert.match(source, /proveNoActiveAgent: fixedNoActiveProof/u);
  assert.match(source, /proveNoActiveController: fixedNoActiveProof/u);
  assert.match(source, /proveListenerUnavailable: fixedListenerUnavailable/u);
  assert.doesNotMatch(source, /const fixedNoActiveProof = \(\) => \{[\s\S]*?fixedListenerUnavailable\(\)/u);
});

test('input document is closed, canonical, and keeps activation proof out of the CLI contract', () => {
  const parsed = parseFixedQualificationInput(canonical(validInput()));
  assert.equal(parsed.provisionRequest.scenario, 'pre-cloud-kill');
  assert.equal(parsed.activation.agent_kind, 'claude_code');
  assert.equal(JSON.stringify(validInput()).includes('fingerprint'), false);
  assert.equal(JSON.stringify(validInput()).includes('_path'), false);

  const missing = validInput();
  delete missing.activation;
  assert.throws(() => parseFixedQualificationInput(canonical(missing)), /not closed|invalid/u);

  const substituted = validInput();
  substituted.endpoint = 'https://attacker.invalid';
  assert.throws(() => parseFixedQualificationInput(canonical(substituted)), /not closed/u);

  const nonCanonical = Buffer.from(JSON.stringify(validInput()), 'utf8');
  assert.throws(() => parseFixedQualificationInput(nonCanonical), /canonical/u);
});

test('fixed input consumption requires a private single-link document', () => {
  const unsafe = inputFixture();
  try {
    fs.chmodSync(unsafe.inputPath, 0o644);
    assert.throws(() => consumeFixedQualificationInput({ inputPath: unsafe.inputPath, expectedUid: UID, uid: UID, production: false }), /unavailable|unsafe/u);
  } finally {
    fs.rmSync(unsafe.root, { recursive: true, force: true });
  }

  const linked = inputFixture();
  try {
    const link = path.join(linked.root, 'input-link.json');
    fs.symlinkSync(linked.inputPath, link);
    assert.throws(() => consumeFixedQualificationInput({ inputPath: link, expectedUid: UID, uid: UID, production: false }), /unavailable|unsafe/u);
  } finally {
    fs.rmSync(linked.root, { recursive: true, force: true });
  }
});

test('fixed input consumption is identity-bound, one-time, and leaves no Grant proof bytes behind', () => {
  const fixture = inputFixture();
  try {
    const parsed = consumeFixedQualificationInput({ inputPath: fixture.inputPath, expectedUid: UID, uid: UID, production: false });
    assert.equal(parsed.activation.proof, '{"grant":"opaque"}');
    assert.equal(fs.existsSync(fixture.inputPath), false);
    assert.throws(() => fs.readFileSync(fixture.inputPath), { code: 'ENOENT' });

    assert.throws(
      () => consumeFixedQualificationInput({ inputPath: fixture.inputPath, expectedUid: UID, uid: UID, production: false }),
      /unavailable/u
    );
  } finally {
    fs.rmSync(fixture.root, { recursive: true, force: true });
  }

  const substituted = inputFixture();
  try {
    let inputLstatCalls = 0;
    const fileSystem = {
      ...fs,
      lstatSync(inputPath, options) {
        const stat = fs.lstatSync(inputPath, options);
        if (inputPath === substituted.inputPath) {
          inputLstatCalls += 1;
          if (inputLstatCalls === 2) return { ...stat, ino: stat.ino + 1n };
        }
        return stat;
      }
    };
    assert.throws(
      () => consumeFixedQualificationInput({ fileSystem, inputPath: substituted.inputPath, expectedUid: UID, uid: UID, production: false }),
      /changed before consumption/u
    );
    assert.equal(fs.existsSync(substituted.inputPath), true);
    assert.match(fs.readFileSync(substituted.inputPath, 'utf8'), /opaque/u);
  } finally {
    fs.rmSync(substituted.root, { recursive: true, force: true });
  }
});

test('fixed-input recovery proves no active run before cleanup and is idempotent when absent', () => {
  const fixture = inputFixture();
  let proofCalls = 0;
  try {
    assert.throws(
      () => recoverFixedQualificationInput({ inputPath: fixture.inputPath, expectedUid: UID, uid: UID, production: false, proveNoActiveRun: () => false }),
      /active run/u
    );
    assert.equal(fs.existsSync(fixture.inputPath), true);

    const removed = recoverFixedQualificationInput({ inputPath: fixture.inputPath, expectedUid: UID, uid: UID, production: false, proveNoActiveRun: () => { proofCalls += 1; return true; } });
    assert.deepEqual(removed, { ok: true, action: 'removed' });
    assert.equal(fs.existsSync(fixture.inputPath), false);
    assert.deepEqual(recoverFixedQualificationInput({ inputPath: fixture.inputPath, expectedUid: UID, uid: UID, production: false, proveNoActiveRun: () => { proofCalls += 1; return true; } }), { ok: true, action: 'absent' });
    assert.equal(proofCalls, 2);
  } finally {
    fs.rmSync(fixture.root, { recursive: true, force: true });
  }
});

test('CLI is a strict closed mechanism and refuses dynamic paths or value-bearing arguments', () => {
  assert.deepEqual(parseFixedQualificationCLI(['run']), { operation: 'run' });
  assert.deepEqual(parseFixedQualificationCLI(['recover']), { operation: 'recover' });
  for (const args of [[], ['run', '--input', '/tmp/grant-proof.json'], ['--input', FIXED_QUALIFICATION_INPUT_PATH], ['run', '/tmp/proof.json'], ['run', '--endpoint', 'https://attacker.invalid']]) {
    assert.throws(() => parseFixedQualificationCLI(args), /usage/u);
  }

  const result = spawnSync(process.execPath, [MODULE_PATH, 'run', '--input', '/tmp/grant-proof.json'], {
    encoding: 'utf8',
    env: { PATH: process.env.PATH ?? '/usr/bin:/bin', AGENTPASS_N3E_GRANT_PROOF: 'do-not-read' }
  });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /usage/u);
  assert.doesNotMatch(result.stderr, /grant-proof|do-not-read/u);
});

test('production entry points refuse omitted or substituted caller dependencies', async () => {
  await assert.rejects(
    () => runFixedProtectedQualification({ executeQualification: () => ({}) }),
    /caller-provided dependencies/u
  );
  assert.throws(
    () => recoverFixedProtectedQualification({ proveNoActiveRun: () => true }),
    /caller-provided dependencies/u
  );
});

test('production input path and identity guards fail closed before any lifecycle dependency runs', async () => {
  assert.throws(() => consumeFixedQualificationInput({ inputPath: '/tmp/operator-input.json', platform: 'darwin', uid: 0, expectedUid: 0 }), /fixed path/u);
  await assert.rejects(() => runFixedProtectedQualification(), /root on macOS/u);
});
