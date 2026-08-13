import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { canonicalQualificationActivation } from './qualification-activation-contract.mjs';
import {
  ACTIVATION_DOCUMENT_PATH,
  AGENT_ACTIVATION_ARGUMENTS,
  AGENT_HOST_EXECUTABLE_PATH,
  APPROVED_LISTENER_PROBE_PATH,
  CONTROLLER_EXECUTABLE_PATH,
  LAUNCHCTL_PATH,
  LISTENER_PROBE_ARGUMENTS,
  PS_ARGUMENTS,
  PS_MAX_OUTPUT_BYTES,
  PS_PATH,
  SERVICE_TARGET,
  SCENARIO_CONFIGURATION_PATH,
  SERVICE_CONFIGURATION_PATH,
  SCENARIOS,
  disarmQualification,
  executeQualification,
  proveQualificationListenerUnavailable,
  proveNoQualificationProcesses,
  recoverQualification,
  restartQualificationDaemon,
  startQualificationAgentActivation
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

const disarmLine = (receipt = RECEIPT) => protocolLine('disarm', 'disarmed', { receipt_sha256: receipt });

const launchctlResult = (stdout = Buffer.alloc(0), status = 0) => ({
  status, signal: null, stdout: Buffer.from(stdout), stderr: Buffer.alloc(0)
});

const processListing = (command = '/usr/bin/other-process') => `0 1 ${command}\n`;

test('the scenario inventory and executable bindings are closed constants', () => {
  assert.deepEqual([...SCENARIOS], EXPECTED_SCENARIOS);
  assert.equal(CONTROLLER_EXECUTABLE_PATH, '/Library/Application Support/AgentPass/Qualification/AgentPassQualificationController.app/Contents/MacOS/agentpass-qualification-controller');
  assert.equal(AGENT_HOST_EXECUTABLE_PATH, '/Applications/AgentPass.app/Contents/Library/HelperTools/AgentPassNativeAgentHost.app/Contents/MacOS/agentpass-native-agent-host');
  assert.equal(APPROVED_LISTENER_PROBE_PATH, '/opt/agentpass/p0c/probes/controller-approved/AgentPassNegativeXPCProbe.app/Contents/MacOS/agentpass-negative-xpc-probe');
  assert.equal(SERVICE_CONFIGURATION_PATH, '/Library/Application Support/AgentPass/native-service.json');
  assert.equal(SCENARIO_CONFIGURATION_PATH, '/opt/agentpass/p0c/scenario-config.json');
  assert.equal(ACTIVATION_DOCUMENT_PATH, '/private/var/db/agentpass-qualification/activation/activation.json');
  assert.deepEqual([...AGENT_ACTIVATION_ARGUMENTS], ['qualification-activate']);
  assert.deepEqual([...LISTENER_PROBE_ARGUMENTS], ['qualification-controller']);
});

test('the real activation launcher passes the protected document only through fd 3 as the repository owner', async () => {
  const directory = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'agentpass-activation-driver-')));
  try {
    const repository = path.join(directory, 'repository');
    const servicePath = path.join(directory, 'service.json');
    const scenarioPath = path.join(directory, 'scenario.json');
    const activationPath = path.join(directory, 'activation.json');
    fs.mkdirSync(repository, { mode: 0o700 });
    const owner = fs.lstatSync(repository);
    fs.writeFileSync(servicePath, `${JSON.stringify({ allowed_client_uid: owner.uid }, null, 2)}\n`, { mode: 0o600 });
    fs.writeFileSync(scenarioPath, `${JSON.stringify({ schema_version: 1, test_repository: repository }, null, 2)}\n`, { mode: 0o644 });
    const activationBytes = canonicalQualificationActivation({
      schema_version: 1,
      agent_id: '12345678-1234-4123-8123-123456789abc',
      agent_kind: 'claude_code',
      requested_ttl_seconds: 60,
      proof: '{"grant":"xxxxxxxxxxxxxxxx"}'
    });
    fs.writeFileSync(activationPath, activationBytes, { mode: 0o600 });
    fs.chmodSync(servicePath, 0o600); fs.chmodSync(scenarioPath, 0o644); fs.chmodSync(activationPath, 0o600);

    const child = fakeChild(); let invocation;
    const handle = startQualificationAgentActivation({
      production: false, platform: process.platform, effectiveUID: process.geteuid(),
      serviceConfigurationPath: servicePath, scenarioConfigurationPath: scenarioPath, activationDocumentPath: activationPath,
      spawnProcess(command, args, options) {
        invocation = { command, args, options, descriptorBytes: fs.readFileSync(options.stdio[3]) };
        queueMicrotask(() => {
          child.stdout.emit('data', Buffer.from('{"error":null,"ok":true,"operation":"qualification-activate","status":"active"}\n{"error":null,"ok":true,"operation":"qualification-activate","status":"closed"}\n'));
          child.emit('close', 0, null);
        });
        return child;
      }
    });
    await handle.completion;
    assert.equal(invocation.command, AGENT_HOST_EXECUTABLE_PATH);
    assert.deepEqual(invocation.args, ['qualification-activate']);
    assert.equal(invocation.options.cwd, repository);
    assert.equal(invocation.options.shell, false);
    assert.equal(invocation.options.uid, owner.uid);
    assert.equal(invocation.options.gid, owner.gid);
    assert.equal(invocation.options.env.AGENTPASS_SECRET, undefined);
    assert.deepEqual(invocation.options.stdio.slice(0, 3), ['ignore', 'pipe', 'pipe']);
    assert.ok(Number.isInteger(invocation.options.stdio[3]));
    assert.deepEqual(invocation.descriptorBytes, activationBytes);
    assert.throws(() => fs.fstatSync(invocation.options.stdio[3]), /bad file descriptor/iu);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
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
  assert.deepEqual(activation.signals, ['SIGTERM']);
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

test('Controller interruption recovers only the observed fired receipt before restarting the daemon', async () => {
  const child = fakeChild({ closeOnKill: false });
  const activation = activationHandle();
  const calls = [];
  const handle = executeQualification({
    scenario: EXPECTED_SCENARIOS[0], phase: 'pre-cloud', candidateSHA256: DIGEST_A, runIDSHA256: DIGEST_B,
    signal: new AbortController().signal, spawnProcess: () => child,
    startAgentActivation: () => activation.handle,
    runCommand(command, args) {
      calls.push([command, args]);
      if (command === PS_PATH) return launchctlResult(processListing());
      if (command === CONTROLLER_EXECUTABLE_PATH) return { status: 0, signal: null, stdout: Buffer.from(args[0] === 'status' ? protocolLine('status', 'fired') : disarmLine()), stderr: Buffer.alloc(0) };
      return command === LAUNCHCTL_PATH && args[0] === 'print'
        ? launchctlResult('pid = 8123\n')
        : launchctlResult();
    }
  });
  child.stdout.emit('data', protocolLine('arm', 'armed'));
  child.emit('close', null, 'SIGKILL');
  await assert.rejects(handle.completion, /scenario execution failed/u);
  assert.deepEqual(calls, [
    [PS_PATH, [...PS_ARGUMENTS]],
    [CONTROLLER_EXECUTABLE_PATH, ['status']],
    [CONTROLLER_EXECUTABLE_PATH, ['disarm']],
    [LAUNCHCTL_PATH, ['kickstart', '-k', SERVICE_TARGET]],
    [LAUNCHCTL_PATH, ['print', SERVICE_TARGET]],
    [PS_PATH, [...PS_ARGUMENTS]]
  ]);
  assert.deepEqual(activation.signals, ['SIGTERM']);
});

test('daemon-unavailable recovery retries once with fixed restart and rejects a failed restart', () => {
  const unavailable = { status: 1, signal: null, stdout: Buffer.alloc(0), stderr: Buffer.alloc(0) };
  const calls = [];
  let controllerCalls = 0;
  const runCommand = (command, args) => {
    calls.push([command, args]);
    if (command === PS_PATH) return launchctlResult(processListing());
    if (command === CONTROLLER_EXECUTABLE_PATH) {
      controllerCalls += 1;
      return controllerCalls <= 2 ? unavailable : { status: 0, signal: null, stdout: Buffer.from(disarmLine()), stderr: Buffer.alloc(0) };
    }
    return args[0] === 'print' ? launchctlResult('pid = 91\n') : launchctlResult();
  };
  assert.equal(recoverQualification({ expectedReceiptSHA256: RECEIPT, runCommand }), true);
  assert.equal(calls.length, 9);

  assert.throws(() => recoverQualification({
    expectedReceiptSHA256: RECEIPT,
    runCommand(command) {
      if (command === PS_PATH) return launchctlResult(processListing());
      if (command === CONTROLLER_EXECUTABLE_PATH) return { status: 0, signal: null, stdout: Buffer.from(disarmLine()), stderr: Buffer.alloc(0) };
      return { status: 1, signal: null, stdout: Buffer.alloc(0), stderr: Buffer.alloc(0) };
    }
  }), /daemon restart failed/u);
});

test('recovery refuses a missing or substituted durable receipt after daemon restart', () => {
  let controllerCalls = 0;
  assert.throws(() => recoverQualification({
    expectedReceiptSHA256: RECEIPT,
    runCommand(command, args) {
      if (command === PS_PATH) return launchctlResult(processListing());
      if (command === CONTROLLER_EXECUTABLE_PATH) {
        controllerCalls += 1;
        if (controllerCalls === 1) return { status: 1, signal: null, stdout: Buffer.alloc(0), stderr: Buffer.alloc(0) };
        return { status: 0, signal: null, stdout: Buffer.from(disarmLine('d'.repeat(64))), stderr: Buffer.alloc(0) };
      }
      return args[0] === 'print' ? launchctlResult('pid = 92\n') : launchctlResult();
    }
  }), /missing or mismatched/u);

  assert.throws(() => recoverQualification({
    expectedReceiptSHA256: RECEIPT,
    runCommand(command, args) {
      if (command === PS_PATH) return launchctlResult(processListing());
      if (command === CONTROLLER_EXECUTABLE_PATH && args[0] === 'status') return { status: 0, signal: null, stdout: Buffer.from(protocolLine('status', 'armed')), stderr: Buffer.alloc(0) };
      throw new Error('disarm must not run while only armed');
    }
  }), /missing or mismatched/u);
});

test('Agent Host accepts scenario-correct rejected exit only for daemon-loss scenarios', async () => {
  const directory = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'agentpass-host-outcome-')));
  try {
    const repository = path.join(directory, 'repository');
    const servicePath = path.join(directory, 'service.json');
    const scenarioPath = path.join(directory, 'scenario.json');
    const activationPath = path.join(directory, 'activation.json');
    fs.mkdirSync(repository, { mode: 0o700 });
    const owner = fs.lstatSync(repository);
    fs.writeFileSync(servicePath, `${JSON.stringify({ allowed_client_uid: owner.uid }, null, 2)}\n`, { mode: 0o600 });
    fs.writeFileSync(scenarioPath, `${JSON.stringify({ schema_version: 1, test_repository: repository }, null, 2)}\n`, { mode: 0o644 });
    fs.writeFileSync(activationPath, canonicalQualificationActivation({
      schema_version: 1, agent_id: '12345678-1234-4123-8123-123456789abc', agent_kind: 'claude_code', requested_ttl_seconds: 60, proof: '{"grant":"xxxxxxxxxxxxxxxx"}'
    }), { mode: 0o600 });
    const launch = (scenario, output, code) => {
      const child = fakeChild();
      const handle = startQualificationAgentActivation({
        production: false, platform: process.platform, effectiveUID: process.geteuid(),
        serviceConfigurationPath: servicePath, scenarioConfigurationPath: scenarioPath, activationDocumentPath: activationPath, scenario,
        spawnProcess() {
          queueMicrotask(() => { child.stdout.emit('data', Buffer.from(output)); child.emit('close', code, null); });
          return child;
        }
      });
      return handle.completion;
    };
    const rejected = '{"error":"agent_activation_rejected","ok":false,"operation":"qualification-activate","status":"rejected"}\n';
    await launch('pre-cloud-kill', rejected, 1);
    await assert.rejects(launch('transport-reply-loss', rejected, 1), /agent activation process failed/u);

    const controllerChild = fakeChild();
    const driver = executeQualification({
      scenario: 'transport-reply-loss', phase: 'transport-reply', candidateSHA256: DIGEST_A, runIDSHA256: DIGEST_B,
      signal: new AbortController().signal, spawnProcess: () => controllerChild,
      startAgentActivation: () => ({ completion: Promise.reject(new Error('host secret')), terminate: () => undefined })
    });
    emitSuccessfulControllerRun(controllerChild);
    await assert.rejects(driver.completion, /scenario execution failed/u);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('execution timeout escalates Controller termination and remains bounded', async () => {
  const child = fakeChild({ closeOnKill: false });
  const handle = executeQualification({
    scenario: EXPECTED_SCENARIOS[5], phase: 'transport-reply', candidateSHA256: DIGEST_A, runIDSHA256: DIGEST_B,
    signal: new AbortController().signal, spawnProcess: () => child, timeoutMs: 1,
    startAgentActivation: () => activationHandle().handle,
    wait: async () => undefined
  });
  await assert.rejects(handle.completion, /scenario execution failed/u);
  assert.deepEqual(child.killCalls, ['SIGTERM', 'SIGKILL']);
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

test('daemon restart uses only fixed launchctl argv, cwd, environment, and bounded pipes', () => {
  const calls = [];
  const result = (stdout) => ({ status: 0, signal: null, stdout: Buffer.from(stdout), stderr: Buffer.alloc(0) });
  const observed = restartQualificationDaemon({ runCommand(command, args, options) {
    calls.push({ command, args, options });
    return args[0] === 'print' ? result('pid = 4312\n') : result('');
  } });
  assert.deepEqual(observed, { pid: 4312 });
  assert.deepEqual(calls.map(({ command, args }) => [command, args]), [
    [LAUNCHCTL_PATH, ['kickstart', '-k', SERVICE_TARGET]],
    [LAUNCHCTL_PATH, ['print', SERVICE_TARGET]]
  ]);
  for (const { options } of calls) {
    assert.equal(options.cwd, '/');
    assert.equal(options.shell, false);
    assert.deepEqual(options.env, { HOME: '/var/empty', LANG: 'C', LC_ALL: 'C', PATH: '/usr/bin:/bin:/usr/sbin:/sbin' });
    assert.deepEqual(options.stdio, ['ignore', 'pipe', 'pipe']);
    assert.equal(options.maxBuffer, 64 * 1024);
  }
});

test('qualification process proof uses fixed ps and detects exact active Controller or Host paths', () => {
  const calls = [];
  const runCommand = (command, args, options) => {
    calls.push({ command, args, options });
    return launchctlResult(`${processListing('/usr/bin/other-process')}501 812 ${CONTROLLER_EXECUTABLE_PATH}\n`);
  };
  assert.equal(proveNoQualificationProcesses({ runCommand }), false);
  assert.equal(calls[0].command, PS_PATH);
  assert.deepEqual(calls[0].args, [...PS_ARGUMENTS]);
  assert.equal(calls[0].options.cwd, '/');
  assert.equal(calls[0].options.shell, false);
  assert.deepEqual(calls[0].options.env, { HOME: '/var/empty', LANG: 'C', LC_ALL: 'C', PATH: '/usr/bin:/bin:/usr/sbin:/sbin' });

  assert.equal(proveNoQualificationProcesses({ runCommand: (command) => {
    assert.equal(command, PS_PATH);
    return launchctlResult(`501 812 ${AGENT_HOST_EXECUTABLE_PATH}\n`);
  } }), false);
  assert.equal(proveNoQualificationProcesses({ runCommand: () => launchctlResult(processListing()) }), true);
});

test('qualification process proof fails closed on malformed, oversized, and failed ps output', () => {
  for (const result of [
    launchctlResult('not-a-process-row\n'),
    launchctlResult(`501 812 ${CONTROLLER_EXECUTABLE_PATH}\nnot-a-process-row\n`),
    launchctlResult(Buffer.alloc(PS_MAX_OUTPUT_BYTES + 1)),
    { status: 1, signal: null, stdout: Buffer.alloc(0), stderr: Buffer.alloc(0) },
    { status: 0, signal: null, stdout: Buffer.from('0 1 /usr/bin/other\n'), stderr: Buffer.from('ps failed') }
  ]) {
    assert.throws(() => proveNoQualificationProcesses({ runCommand: () => result }), /qualification (?:process listing is invalid|process listing exceeded its bound|process proof failed)/u);
  }
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
