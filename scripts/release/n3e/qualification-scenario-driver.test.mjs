import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import test from 'node:test';

import {
  AGENT_ACTIVATION_ARGUMENTS,
  AGENT_HOST_EXECUTABLE_PATH,
  APPROVED_LISTENER_PROBE_PATH,
  CONTROLLER_EXECUTABLE_PATH,
  LISTENER_PROBE_ARGUMENTS,
  SCENARIOS,
  disarmQualification,
  executeQualification,
  proveQualificationListenerUnavailable
} from './qualification-scenario-driver.mjs';

const DIGEST_A = 'a'.repeat(64);
const DIGEST_B = 'b'.repeat(64);
const RECEIPT = 'c'.repeat(64);
const EXPECTED_SCENARIOS = Object.freeze([
  'pre-cloud-kill',
  'post-cloud-pre-local-kill',
  'post-activation-pre-audit-kill',
  'post-audit-pre-reply-loss',
  'audit-fsync-failure',
  'transport-reply-loss'
]);

const protocolLine = (command, status, overrides = {}) => JSON.stringify({
  schema_version: 1,
  command,
  ok: true,
  status,
  candidate_sha256: DIGEST_A,
  run_id_sha256: DIGEST_B,
  receipt_sha256: RECEIPT,
  error: null,
  ...overrides
}) + '\n';

const fakeChild = ({ closeOnKill = true } = {}) => {
  const child = new EventEmitter();
  child.stdout = new EventEmitter();
  child.stderr = new EventEmitter();
  child.killCalls = [];
  child.kill = (signal) => {
    child.killCalls.push(signal);
    if (closeOnKill) queueMicrotask(() => child.emit('close', null, signal));
    return true;
  };
  return child;
};

const activationHandle = ({ complete = Promise.resolve() } = {}) => {
  const signals = [];
  return { handle: { completion: complete, terminate: (signal) => signals.push(signal) }, signals };
};

const emitSuccessfulControllerRun = (child) => {
  child.stdout.emit('data', protocolLine('arm', 'armed'));
  child.stdout.emit('data', protocolLine('arm', 'fired'));
  child.stdout.emit('data', protocolLine('arm', 'disarmed'));
  child.emit('close', 0, null);
};

test('the scenario inventory and executable bindings are closed constants', () => {
  assert.deepEqual([...SCENARIOS], EXPECTED_SCENARIOS);
  assert.equal(CONTROLLER_EXECUTABLE_PATH, '/Library/Application Support/AgentPass/Qualification/AgentPassQualificationController.app/Contents/MacOS/agentpass-qualification-controller');
  assert.equal(AGENT_HOST_EXECUTABLE_PATH, '/Applications/AgentPass.app/Contents/Library/HelperTools/AgentPassNativeAgentHost.app/Contents/MacOS/agentpass-native-agent-host');
  assert.equal(APPROVED_LISTENER_PROBE_PATH, '/opt/agentpass/p0c/probes/controller-approved/AgentPassNegativeXPCProbe.app/Contents/MacOS/agentpass-negative-xpc-probe');
  assert.deepEqual([...AGENT_ACTIVATION_ARGUMENTS], ['qualification-activate']);
  assert.deepEqual([...LISTENER_PROBE_ARGUMENTS], ['qualification-controller']);
});

test('the driver accepts exactly armed, fired, disarmed and waits for Agent Host exit', async () => {
  const child = fakeChild();
  let finishActivation;
  const activation = activationHandle({ complete: new Promise((resolve) => { finishActivation = resolve; }) });
  const calls = [];
  const controller = new AbortController();
  const handle = executeQualification({
    scenario: EXPECTED_SCENARIOS[0], phase: 'pre-cloud', candidateSHA256: DIGEST_A, runIDSHA256: DIGEST_B,
    signal: controller.signal,
    spawnProcess(command, args, options) { calls.push({ command, args, options }); return child; },
    startAgentActivation(input) { calls.push(input); return activation.handle; }
  });

  assert.deepEqual(Object.keys(handle).sort(), ['completion', 'terminate']);
  emitSuccessfulControllerRun(child);
  let completed = false;
  handle.completion.then(() => { completed = true; });
  await Promise.resolve();
  assert.equal(completed, false);
  finishActivation();
  const result = await handle.completion;
  assert.equal(result.ok, true);
  assert.equal(result.status, 'passed');
  assert.match(result.evidence_sha256, /^[0-9a-f]{64}$/u);
  assert.equal(calls.length, 2);
  assert.equal(calls[0].command, CONTROLLER_EXECUTABLE_PATH);
  assert.deepEqual(calls[0].args, ['arm']);
  assert.equal(calls[0].options.cwd, '/');
  assert.equal(calls[0].options.shell, false);
  assert.deepEqual(calls[0].options.stdio, ['ignore', 'pipe', 'pipe']);
  assert.deepEqual(calls[1], { signal: controller.signal, scenario: EXPECTED_SCENARIOS[0], phase: 'pre-cloud', candidateSHA256: DIGEST_A, runIDSHA256: DIGEST_B });
});

test('the driver rejects invalid order, digest binding, and early clean exit', async () => {
  for (const emit of [
    (child) => { child.stdout.emit('data', protocolLine('arm', 'fired')); },
    (child) => { child.stdout.emit('data', protocolLine('arm', 'armed', { candidate_sha256: DIGEST_B })); },
    (child) => { child.emit('close', 0, null); }
  ]) {
    const child = fakeChild();
    const handle = executeQualification({
      scenario: EXPECTED_SCENARIOS[1], phase: 'post-cloud-pre-local', candidateSHA256: DIGEST_A, runIDSHA256: DIGEST_B,
      signal: new AbortController().signal, spawnProcess: () => child,
      startAgentActivation: () => activationHandle().handle
    });
    emit(child);
    await assert.rejects(handle.completion, /scenario execution failed/u);
  }
});

test('termination is bounded and escalates both processes without embedding secrets', async () => {
  const child = fakeChild({ closeOnKill: false });
  const activation = activationHandle({ complete: new Promise(() => {}) });
  const handle = executeQualification({
    scenario: EXPECTED_SCENARIOS[5], phase: 'transport-reply', candidateSHA256: DIGEST_A, runIDSHA256: DIGEST_B,
    signal: new AbortController().signal, spawnProcess: () => child,
    startAgentActivation: () => activation.handle, wait: async () => undefined
  });
  child.stdout.emit('data', protocolLine('arm', 'armed'));
  await handle.terminate();
  assert.deepEqual(child.killCalls, ['SIGTERM', 'SIGKILL']);
  assert.deepEqual(activation.signals, ['SIGTERM', 'SIGKILL']);
  assert.doesNotMatch(JSON.stringify(handle), /[a-f0-9]{64}/u);
});

test('abort terminates the controller and oversized output fails closed', async () => {
  const child = fakeChild();
  const controller = new AbortController();
  const handle = executeQualification({
    scenario: EXPECTED_SCENARIOS[2], phase: 'post-activation-pre-audit', candidateSHA256: DIGEST_A, runIDSHA256: DIGEST_B,
    signal: controller.signal, spawnProcess: () => child,
    startAgentActivation: () => activationHandle().handle
  });
  controller.abort();
  await assert.rejects(handle.completion, /scenario execution failed/u);
  assert.deepEqual(child.killCalls, ['SIGTERM']);

  const noisy = fakeChild();
  const noisyHandle = executeQualification({
    scenario: EXPECTED_SCENARIOS[3], phase: 'post-audit-pre-reply', candidateSHA256: DIGEST_A, runIDSHA256: DIGEST_B,
    signal: new AbortController().signal, spawnProcess: () => noisy,
    startAgentActivation: () => activationHandle().handle
  });
  noisy.stderr.emit('data', Buffer.alloc(64 * 1024 + 1));
  await assert.rejects(noisyHandle.completion, /scenario execution failed/u);
  assert.deepEqual(noisy.killCalls, ['SIGKILL']);
});

test('an already-aborted signal still terminates the controller', async () => {
  const child = fakeChild();
  const controller = new AbortController();
  controller.abort();
  const handle = executeQualification({
    scenario: EXPECTED_SCENARIOS[4], phase: 'audit-fsync', candidateSHA256: DIGEST_A, runIDSHA256: DIGEST_B,
    signal: controller.signal, spawnProcess: () => child,
    startAgentActivation: () => activationHandle().handle
  });
  await assert.rejects(handle.completion, /scenario execution failed/u);
  assert.deepEqual(child.killCalls, ['SIGTERM']);
});

test('invalid caller-controlled bindings are rejected before spawning', () => {
  let spawned = false;
  assert.throws(() => executeQualification({
    scenario: 'pre-cloud-kill;touch /tmp/pwned', phase: 'pre-cloud', candidateSHA256: DIGEST_A, runIDSHA256: DIGEST_B,
    signal: new AbortController().signal, spawnProcess: () => { spawned = true; }
  }), /binding is invalid/u);
  assert.equal(spawned, false);
});

test('disarm uses the fixed controller and validates a closed bound receipt', () => {
  let call;
  const result = disarmQualification({ runCommand(command, args, options) {
    call = { command, args, options };
    return { status: 0, signal: null, stdout: Buffer.from(protocolLine('disarm', 'disarmed')), stderr: Buffer.alloc(0) };
  } });
  assert.equal(result, true);
  assert.equal(call.command, CONTROLLER_EXECUTABLE_PATH);
  assert.deepEqual(call.args, ['disarm']);
  assert.equal(call.options.shell, false);
});

test('listener proof accepts only denied-before-selector from the approved fixed probe', () => {
  let call;
  const runCommand = (command, args, options) => {
    call = { command, args, options };
    return { status: 0, signal: null, stdout: Buffer.from(JSON.stringify({ schema_version: 1, operation: 'qualification-controller-status', outcome: 'denied-before-selector', service_protocol_version: null })), stderr: Buffer.alloc(0) };
  };
  assert.equal(proveQualificationListenerUnavailable({ runCommand }), true);
  assert.equal(call.command, APPROVED_LISTENER_PROBE_PATH);
  assert.deepEqual(call.args, LISTENER_PROBE_ARGUMENTS);
  assert.equal(call.options.shell, false);

  assert.equal(proveQualificationListenerUnavailable({ runCommand: () => ({ status: 0, signal: null, stdout: Buffer.from(JSON.stringify({ schema_version: 1, operation: 'qualification-controller-status', outcome: 'selector-reached-binding-rejected', service_protocol_version: 1 })), stderr: Buffer.alloc(0) }) }), false);
});
