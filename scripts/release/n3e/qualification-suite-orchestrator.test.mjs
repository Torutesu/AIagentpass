import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import crypto from 'node:crypto';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import {
  QUALIFICATION_SUITE_ABORT_TIMEOUT_MILLISECONDS,
  QUALIFICATION_SUITE_KIND,
  QUALIFICATION_SUITE_SCENARIOS,
  QUALIFICATION_SUITE_STEPS,
  QUALIFICATION_SUITE_SCHEMA_VERSION,
  aggregateQualificationSuiteEvidence,
  buildQualificationSuiteEvidence,
  canonicalQualificationSuiteJSON,
  executeQualificationSuiteForTest,
  parseQualificationSuiteCLI,
  qualificationSuiteEvidenceSHA256,
  validateQualificationSuiteEvidence
} from './qualification-suite-orchestrator.mjs';

const MODULE_PATH = fileURLToPath(new URL('./qualification-suite-orchestrator.mjs', import.meta.url));
const CANDIDATE = 'a'.repeat(64);
const RUN = 'b'.repeat(64);
const digest = (value) => crypto.createHash('sha256').update(value).digest('hex');

const execution = (value) => ({ ok: true, status: 'passed', evidence_sha256: digest(value) });

const recordFor = (step, index) => ({
  candidate_sha256: CANDIDATE,
  evidence_sha256: digest(`evidence-${index}`),
  kind: step.kind,
  phase: step.phase,
  run_id_sha256: RUN,
  scenario: step.scenario,
  status: 'passed'
});

const validEvidence = () => buildQualificationSuiteEvidence({
  records: QUALIFICATION_SUITE_STEPS.map(recordFor)
});

const handle = (value, signals = []) => ({
  completion: Promise.resolve(value),
  terminate(reason) { signals.push(reason); }
});

test('the suite inventory is a closed deterministic control-plus-six sequence', () => {
  assert.deepEqual(QUALIFICATION_SUITE_SCENARIOS, [
    { scenario: 'pre-cloud-kill', phase: 'pre-cloud' },
    { scenario: 'post-cloud-pre-local-kill', phase: 'post-cloud-pre-local' },
    { scenario: 'post-activation-pre-audit-kill', phase: 'post-activation-pre-audit' },
    { scenario: 'post-audit-pre-reply-loss', phase: 'post-audit-pre-reply' },
    { scenario: 'audit-fsync-failure', phase: 'audit-fsync' },
    { scenario: 'transport-reply-loss', phase: 'transport-reply' }
  ]);
  assert.equal(QUALIFICATION_SUITE_STEPS.length, 7);
  assert.deepEqual(QUALIFICATION_SUITE_STEPS[0], { kind: 'unarmed-control', scenario: null, phase: null });
  assert.deepEqual(QUALIFICATION_SUITE_STEPS.slice(1), QUALIFICATION_SUITE_SCENARIOS.map(({ scenario, phase }) => ({ kind: 'scenario', scenario, phase })));
});

test('injected execution runs exactly in order and returns only the public suite digest', async () => {
  const controller = new AbortController();
  const calls = [];
  const result = await executeQualificationSuiteForTest({
    candidateSHA256: CANDIDATE,
    runIDSHA256: RUN,
    signal: controller.signal,
    stepTimeoutMilliseconds: 100,
    abortTimeoutMilliseconds: 100,
    executeUnarmedControl(input) {
      calls.push({ kind: input.kind, scenario: input.scenario, phase: input.phase, candidate: input.candidateSHA256, run: input.runIDSHA256 });
      return handle(execution('unarmed'));
    },
    executeScenario(input) {
      calls.push({ kind: input.kind, scenario: input.scenario, phase: input.phase, candidate: input.candidateSHA256, run: input.runIDSHA256 });
      return handle(execution(input.scenario));
    }
  });

  assert.deepEqual(calls, QUALIFICATION_SUITE_STEPS.map((step) => ({
    kind: step.kind,
    scenario: step.scenario,
    phase: step.phase,
    candidate: CANDIDATE,
    run: RUN
  })));
  assert.deepEqual(Object.keys(result).sort(), ['evidence_sha256', 'ok', 'status']);
  assert.equal(result.ok, true);
  assert.equal(result.status, 'passed');
  assert.match(result.evidence_sha256, /^[0-9a-f]{64}$/u);
  assert.doesNotMatch(JSON.stringify(result), /stdout|stderr|secret|proof|grant/iu);
});

test('public evidence is canonical, identity-bound, and deterministic', () => {
  const first = validEvidence();
  const second = validEvidence();
  assert.deepEqual(first, second);
  assert.equal(qualificationSuiteEvidenceSHA256(first), qualificationSuiteEvidenceSHA256(second));
  assert.equal(aggregateQualificationSuiteEvidence({ records: first.steps }), qualificationSuiteEvidenceSHA256(first));
  assert.deepEqual(JSON.parse(canonicalQualificationSuiteJSON(first)), first);
  assert.notEqual(
    qualificationSuiteEvidenceSHA256(first),
    qualificationSuiteEvidenceSHA256(buildQualificationSuiteEvidence({
      records: first.steps.map((step, index) => index === 0 ? { ...step, run_id_sha256: 'c'.repeat(64) } : step)
    }))
  );
});

test('evidence rejects missing, duplicate, reordered, substituted, and non-public records', () => {
  const original = validEvidence();
  const accessor = { ...original, steps: original.steps.map((step) => ({ ...step })) };
  Object.defineProperty(accessor.steps[0], 'status', { enumerable: true, get: () => 'passed' });
  const symbolKey = { ...original, steps: original.steps.map((step) => ({ ...step })) };
  symbolKey.steps[0][Symbol('unexpected')] = 'value';
  const cases = [
    () => ({ ...original, steps: original.steps.slice(0, -1) }),
    () => ({ ...original, steps: [original.steps[0], original.steps[1], original.steps[1], ...original.steps.slice(2, -1)] }),
    () => ({ ...original, steps: [...original.steps].reverse() }),
    () => ({ ...original, steps: original.steps.map((step, index) => index === 2 ? { ...step, scenario: 'transport-reply-loss', phase: 'transport-reply' } : step) }),
    () => ({ ...original, steps: original.steps.map((step, index) => index === 1 ? { ...step, stdout: 'secret output' } : step) }),
    () => ({ ...original, steps: original.steps.map((step, index) => index === 4 ? { ...step, evidence_sha256: '0'.repeat(64) } : step) }),
    () => accessor,
    () => symbolKey
  ];
  for (const makeCase of cases) assert.throws(() => validateQualificationSuiteEvidence(makeCase()), /invalid|closed|missing|duplicated|reordered|public|accessor/iu);
});

test('step and aggregate results reject raw material and non-closed shapes', async () => {
  const controller = new AbortController();
  const failures = [
    { ok: true, status: 'passed', evidence_sha256: digest('x'), stdout: 'secret' },
    { ok: true, status: 'passed', evidence_sha256: 'not-a-digest' },
    { ok: true, status: 'failed', evidence_sha256: digest('x') }
  ];
  for (const bad of failures) {
    await assert.rejects(
      executeQualificationSuiteForTest({
        candidateSHA256: CANDIDATE,
        runIDSHA256: RUN,
        signal: controller.signal,
        stepTimeoutMilliseconds: 100,
        abortTimeoutMilliseconds: 100,
        executeUnarmedControl: () => handle(bad),
        executeScenario: () => handle(execution('never'))
      }),
      /execution failed/iu
    );
  }
});

test('abort terminates the active step within a bounded deadline and does not start later steps', async () => {
  const controller = new AbortController();
  const signals = [];
  const calls = [];
  const started = Date.now();
  const pending = new Promise(() => {});
  const promise = executeQualificationSuiteForTest({
    candidateSHA256: CANDIDATE,
    runIDSHA256: RUN,
    signal: controller.signal,
    stepTimeoutMilliseconds: 10_000,
    abortTimeoutMilliseconds: 20,
    executeUnarmedControl() {
      calls.push('unarmed-control');
      return { completion: pending, terminate: (reason) => signals.push(reason) };
    },
    executeScenario() {
      calls.push('scenario');
      return handle(execution('unexpected'));
    }
  });
  setTimeout(() => controller.abort(), 5);
  await assert.rejects(promise, /execution failed/iu);
  assert.deepEqual(calls, ['unarmed-control']);
  assert.deepEqual(signals, ['abort']);
  assert.ok(Date.now() - started < 500, 'abort exceeded its bounded test deadline');
});

test('a hanging termination dependency is still bounded and its secret error is not exposed', async () => {
  const controller = new AbortController();
  const secret = '-----BEGIN PRIVATE KEY----- secret';
  const promise = executeQualificationSuiteForTest({
    candidateSHA256: CANDIDATE,
    runIDSHA256: RUN,
    signal: controller.signal,
    stepTimeoutMilliseconds: 10,
    abortTimeoutMilliseconds: 10,
    executeUnarmedControl() {
      return { completion: new Promise(() => {}), terminate: () => new Promise(() => {}) };
    },
    executeScenario() {
      throw new Error(secret);
    }
  });
  await assert.rejects(promise, (error) => {
    assert.match(error.message, /execution failed/iu);
    assert.doesNotMatch(error.message, /PRIVATE KEY|secret/iu);
    return true;
  });
});

test('CLI accepts only the fixed run/recover operations', () => {
  assert.deepEqual(parseQualificationSuiteCLI(['run']), { operation: 'run' });
  assert.deepEqual(parseQualificationSuiteCLI(['recover']), { operation: 'recover' });
  for (const args of [[], ['run', '--input', '/tmp/secrets'], ['--candidate', CANDIDATE], ['recover', 'anything']]) {
    assert.throws(() => parseQualificationSuiteCLI(args), /usage/iu);
  }
});

test('production CLI refuses arbitrary arguments without reading their values', () => {
  const secret = 'do-not-read-private-key';
  const result = spawnSync(process.execPath, [MODULE_PATH, 'run', '--secret', secret], {
    encoding: 'utf8',
    env: { PATH: process.env.PATH ?? '/usr/bin:/bin' }
  });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /usage/iu);
  assert.doesNotMatch(result.stderr, /do-not-read-private-key/iu);
  assert.doesNotMatch(result.stdout, /do-not-read-private-key/iu);
});

test('production execution refuses caller-provided dependencies and arbitrary identity arguments', async () => {
  const module = await import('./qualification-suite-orchestrator.mjs');
  await assert.rejects(() => module.executeQualificationSuite({ candidateSHA256: CANDIDATE }), /caller-provided arguments|root on macOS|fixed protected/iu);
  await assert.rejects(() => module.runFixedProtectedQualificationSuite({}), /caller-provided arguments/iu);
  assert.equal(QUALIFICATION_SUITE_KIND, 'agentpass-n3e-qualification-suite-evidence');
  assert.equal(QUALIFICATION_SUITE_SCHEMA_VERSION, 1);
  assert.equal(QUALIFICATION_SUITE_ABORT_TIMEOUT_MILLISECONDS, 30_000);
});
