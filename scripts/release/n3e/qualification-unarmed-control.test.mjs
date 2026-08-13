import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';

import {
  AGENT_ACTIVATION_ARGUMENTS,
  AGENT_HOST_EXECUTABLE_PATH,
  CONTROLLER_EXECUTABLE_PATH
} from './qualification-scenario-driver.mjs';
import {
  UNARMED_CONTROL_AGENT_STATUSES,
  UNARMED_CONTROL_CONTROLLER_STATUS,
  UNARMED_CONTROL_KIND,
  executeQualificationUnarmedControlForTest,
  parseUnarmedControllerStatus,
  unarmedControlEvidenceSHA256
} from './qualification-unarmed-control.mjs';

const CANDIDATE = 'a'.repeat(64);
const RUN = 'b'.repeat(64);
const RECEIPT = 'c'.repeat(64);

const statusBytes = (status = UNARMED_CONTROL_CONTROLLER_STATUS, overrides = {}) => Buffer.from(`${JSON.stringify({
  schema_version: 1,
  command: 'status',
  ok: true,
  status,
  candidate_sha256: CANDIDATE,
  run_id_sha256: RUN,
  receipt_sha256: RECEIPT,
  error: null,
  ...overrides
})}\n`, 'utf8');

const commandResult = (stdout, overrides = {}) => ({
  status: 0,
  signal: null,
  stdout,
  stderr: Buffer.alloc(0),
  ...overrides
});

const activation = ({ completion = Promise.resolve({ exited: true }) } = {}) => {
  const signals = [];
  return {
    signals,
    handle: {
      completion,
      terminate(signal) { signals.push(signal); }
    }
  };
};

const execute = ({ statuses = [statusBytes(), statusBytes()], host, ...overrides } = {}) => {
  const calls = [];
  let statusIndex = 0;
  const chosenHost = host ?? activation();
  const handle = executeQualificationUnarmedControlForTest({
    candidateSHA256: CANDIDATE,
    runIDSHA256: RUN,
    signal: new AbortController().signal,
    runCommand(command, args, options) {
      calls.push({ command, args, options });
      return commandResult(statuses[statusIndex++]);
    },
    startAgentActivation(input) {
      calls.push({ activation: input });
      return chosenHost.handle;
    },
    ...overrides
  });
  return { handle, calls, host: chosenHost };
};

test('the unarmed contract binds fixed executables and the active-to-closed host result', () => {
  assert.equal(CONTROLLER_EXECUTABLE_PATH, '/Library/Application Support/AgentPass/Qualification/AgentPassQualificationController.app/Contents/MacOS/agentpass-qualification-controller');
  assert.equal(AGENT_HOST_EXECUTABLE_PATH, '/Applications/AgentPass.app/Contents/Library/HelperTools/AgentPassNativeAgentHost.app/Contents/MacOS/agentpass-native-agent-host');
  assert.deepEqual([...AGENT_ACTIVATION_ARGUMENTS], ['qualification-activate']);
  assert.deepEqual([...UNARMED_CONTROL_AGENT_STATUSES], ['active', 'closed']);
  assert.equal(UNARMED_CONTROL_KIND, 'agentpass-n3e-qualification-unarmed-control');

  const source = fs.readFileSync(path.resolve(new URL('./qualification-unarmed-control.mjs', import.meta.url).pathname), 'utf8');
  assert.doesNotMatch(source, /CONTROLLER_EXECUTABLE_PATH,\s*\[['"]arm['"]\]/u);
  assert.doesNotMatch(source, /process\.env|https?:\/\//u);
});

test('successful unarmed execution observes disarmed before and after active-to-closed activation', async () => {
  const value = execute();
  const result = await value.handle.completion;

  assert.deepEqual(Object.keys(result).sort(), ['evidence_sha256', 'ok', 'status']);
  assert.deepEqual(result, {
    ok: true,
    status: 'passed',
    evidence_sha256: unarmedControlEvidenceSHA256({
      candidateSHA256: CANDIDATE,
      runIDSHA256: RUN,
      before: JSON.parse(statusBytes().toString('utf8')),
      after: JSON.parse(statusBytes().toString('utf8'))
    })
  });
  assert.deepEqual(value.calls.map((call) => [call.command, call.args]), [
    [CONTROLLER_EXECUTABLE_PATH, ['status']],
    [undefined, undefined],
    [CONTROLLER_EXECUTABLE_PATH, ['status']]
  ]);
  assert.deepEqual(value.calls[0].options, {
    cwd: '/',
    env: { HOME: '/var/empty', LANG: 'C', LC_ALL: 'C', PATH: '/usr/bin:/bin:/usr/sbin:/sbin' },
    encoding: null,
    shell: false,
    stdio: ['ignore', 'pipe', 'pipe'],
    timeout: 30 * 1000,
    maxBuffer: 64 * 1024
  });
  assert.deepEqual(value.calls[1].activation, { signal: value.calls[1].activation.signal });
  assert.deepEqual(value.host.signals, []);
});

test('armed or fired Controller status is rejected before or after activation', async () => {
  for (const firstStatus of ['armed', 'fired']) {
    const value = execute({ statuses: [statusBytes(firstStatus)] });
    await assert.rejects(value.handle.completion, /disarmed state/u);
    assert.equal(value.calls.some((call) => call.activation), false);
  }

  for (const finalStatus of ['armed', 'fired']) {
    const value = execute({ statuses: [statusBytes(), statusBytes(finalStatus)] });
    await assert.rejects(value.handle.completion, /disarmed state/u);
    assert.deepEqual(value.host.signals, []);
  }
});

test('Agent Host failure is rejected and bounded termination is attempted', async () => {
  const value = execute({ host: activation({ completion: Promise.reject(new Error('host failure secret')) }) });
  await assert.rejects(value.handle.completion, /Agent Host failed/u);
  assert.deepEqual(value.host.signals, ['SIGTERM']);
});

test('Agent Host timeout escalates from SIGTERM to SIGKILL', async () => {
  const value = execute({
    host: activation({ completion: new Promise(() => {}) }),
    timeoutMilliseconds: 20,
    terminationGraceMilliseconds: 1
  });
  await assert.rejects(value.handle.completion, /timed out/u);
  assert.deepEqual(value.host.signals, ['SIGTERM', 'SIGKILL']);
});

test('Controller output substitution is rejected, including identity substitution and unknown fields', async () => {
  const identitySubstitution = execute({ statuses: [statusBytes('disarmed', { run_id_sha256: 'd'.repeat(64) })] });
  await assert.rejects(identitySubstitution.handle.completion, /bound disarmed state/u);

  const extraField = JSON.parse(statusBytes().toString('utf8'));
  extraField.endpoint = 'https://attacker.invalid';
  const outputSubstitution = execute({ statuses: [Buffer.from(`${JSON.stringify(extraField)}\n`, 'utf8')] });
  await assert.rejects(outputSubstitution.handle.completion, /not closed/u);

  assert.throws(() => parseUnarmedControllerStatus(statusBytes('fired'), { candidateSHA256: CANDIDATE, runIDSHA256: RUN }), /bound disarmed state/u);
  assert.throws(() => parseUnarmedControllerStatus(Buffer.alloc(64 * 1024 + 1), { candidateSHA256: CANDIDATE, runIDSHA256: RUN }), /invalid/u);
});

test('public evidence hashing is identity-bound and does not claim durable receipt absence', () => {
  const before = JSON.parse(statusBytes().toString('utf8'));
  const after = JSON.parse(statusBytes().toString('utf8'));
  const first = unarmedControlEvidenceSHA256({ candidateSHA256: CANDIDATE, runIDSHA256: RUN, before, after });
  const changedIdentity = unarmedControlEvidenceSHA256({ candidateSHA256: 'd'.repeat(64), runIDSHA256: RUN, before: { ...before, candidate_sha256: 'd'.repeat(64) }, after: { ...after, candidate_sha256: 'd'.repeat(64) } });
  assert.match(first, /^[0-9a-f]{64}$/u);
  assert.notEqual(first, changedIdentity);
  assert.equal(Object.hasOwn(before, 'durable_fired_evidence'), false);
});
