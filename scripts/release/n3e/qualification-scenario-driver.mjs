import crypto from 'node:crypto';
import { spawn, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import { isAbsolute, resolve } from 'node:path';
import { SCENARIO_PHASE } from './provision-qualification-config.mjs';
import { QUALIFICATION_ACTIVATION_MAX_BYTES, parseQualificationActivation } from './qualification-activation-contract.mjs';

export const SCENARIOS = Object.freeze(Object.keys(SCENARIO_PHASE));
export const CONTROLLER_EXECUTABLE_PATH = '/Library/Application Support/AgentPass/Qualification/AgentPassQualificationController.app/Contents/MacOS/agentpass-qualification-controller';
export const AGENT_HOST_EXECUTABLE_PATH = '/Applications/AgentPass.app/Contents/Library/HelperTools/AgentPassNativeAgentHost.app/Contents/MacOS/agentpass-native-agent-host';
export const APPROVED_LISTENER_PROBE_PATH = '/opt/agentpass/p0c/probes/controller-approved/AgentPassNegativeXPCProbe.app/Contents/MacOS/agentpass-negative-xpc-probe';
export const SERVICE_CONFIGURATION_PATH = '/Library/Application Support/AgentPass/native-service.json';
export const SCENARIO_CONFIGURATION_PATH = '/opt/agentpass/p0c/scenario-config.json';
export const ACTIVATION_DOCUMENT_PATH = '/private/var/db/agentpass-qualification/activation/activation.json';
export const AGENT_ACTIVATION_ARGUMENTS = Object.freeze(['qualification-activate']);
export const LISTENER_PROBE_ARGUMENTS = Object.freeze(['qualification-controller']);
export const LAUNCHCTL_PATH = '/bin/launchctl';
export const SERVICE_LABEL = 'dev.agentpass.native-service';
export const SERVICE_TARGET = `system/${SERVICE_LABEL}`;
export const PS_PATH = '/bin/ps';
export const PS_ARGUMENTS = Object.freeze(['-axo', 'uid=,pid=,comm=']);
export const PS_MAX_OUTPUT_BYTES = 1024 * 1024;

const CLEAN_ENVIRONMENT = Object.freeze({ HOME: '/var/empty', LANG: 'C', LC_ALL: 'C', PATH: '/usr/bin:/bin:/usr/sbin:/sbin' });
const DIGEST = /^[0-9a-f]{64}$/u;
const RECEIPT = /^[0-9a-f]{64}$/u;
const MAX_OUTPUT_BYTES = 64 * 1024;
const MAX_LINE_BYTES = 2048;
const TERMINATION_GRACE_MS = 5_000;
const COMMAND_TIMEOUT_MS = 30_000;
const SCENARIO_TIMEOUT_MS = 15 * 60 * 1000;
const UINT32_MAX = 0xffff_ffff;

const HOST_EXPECTED_OUTCOME = Object.freeze({
  'pre-cloud-kill': 'rejected',
  'post-cloud-pre-local-kill': 'rejected',
  'post-activation-pre-audit-kill': 'rejected',
  'post-audit-pre-reply-loss': 'rejected',
  'audit-fsync-failure': 'rejected',
  'transport-reply-loss': 'active-closed'
});

const fail = (message) => { throw new Error(message); };
const exactKeys = (value, keys, label) => {
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail(`${label} is invalid`);
  const actual = Object.keys(value).sort(); const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) fail(`${label} is not closed`);
};

const parseControllerLine = (line, candidateSHA256, runIDSHA256) => {
  if (Buffer.byteLength(line, 'utf8') > MAX_LINE_BYTES) fail('qualification controller output exceeded its bound');
  let value;
  try { value = JSON.parse(line); } catch { fail('qualification controller output is invalid'); }
  exactKeys(value, ['schema_version', 'command', 'ok', 'status', 'candidate_sha256', 'run_id_sha256', 'receipt_sha256', 'error'], 'qualification controller result');
  if (value.schema_version !== 1 || value.command !== 'arm' || value.ok !== true || value.error !== null || !['armed', 'fired', 'disarmed'].includes(value.status) || value.candidate_sha256 !== candidateSHA256 || value.run_id_sha256 !== runIDSHA256 || !RECEIPT.test(value.receipt_sha256)) fail('qualification controller result binding is invalid');
  return value;
};

const defaultStartAgentActivation = (input) => startQualificationAgentActivation(input);

const validateActivationHandle = (handle) => {
  if (!handle || typeof handle !== 'object' || typeof handle.completion?.then !== 'function' || typeof handle.terminate !== 'function') fail('agent activation handle is invalid');
  return handle;
};

const validateAgentActivationOutput = (bytes, scenario = 'transport-reply-loss') => {
  const source = bytes.toString('utf8');
  if (!source.endsWith('\n')) fail('agent activation output is invalid');
  const lines = source.slice(0, -1).split('\n');
  const expectedOutcome = HOST_EXPECTED_OUTCOME[scenario];
  if (!expectedOutcome) fail('agent activation scenario is invalid');
  const expectedStatuses = expectedOutcome === 'rejected' ? ['rejected'] : ['active', 'closed'];
  if (lines.length !== expectedStatuses.length) fail('agent activation output is invalid');
  for (let index = 0; index < lines.length; index += 1) {
    let value;
    try { value = JSON.parse(lines[index]); } catch { fail('agent activation output is invalid'); }
    exactKeys(value, ['error', 'ok', 'operation', 'status'], 'agent activation result');
    const expectedError = expectedOutcome === 'rejected' ? 'agent_activation_rejected' : null;
    if (value.error !== expectedError || value.ok !== (expectedOutcome !== 'rejected') || value.operation !== 'qualification-activate' || value.status !== expectedStatuses[index]) fail('agent activation output is invalid');
    const canonical = JSON.stringify(Object.fromEntries(Object.keys(value).sort().map((key) => [key, value[key]])));
    if (canonical !== lines[index]) fail('agent activation output is invalid');
  }
};

const delay = (milliseconds) => new Promise((resolvePromise) => setTimeout(resolvePromise, milliseconds));

const cancellableWait = (milliseconds, wait) => {
  if (wait !== delay) {
    let cancelled = false;
    return {
      promise: Promise.resolve().then(() => wait(milliseconds)).then((value) => (cancelled ? undefined : value)),
      cancel: () => { cancelled = true; }
    };
  }
  let timer;
  let resolvePromise;
  const promise = new Promise((resolveValue) => {
    resolvePromise = resolveValue;
    timer = setTimeout(resolveValue, milliseconds);
  });
  return {
    promise,
    cancel: () => {
      if (timer !== undefined) {
        clearTimeout(timer);
        timer = undefined;
        resolvePromise();
      }
    }
  };
};

const identity = (value) => [value.dev, value.ino, value.mode, value.nlink, value.size, value.mtimeNs, value.ctimeNs, value.uid, value.gid].map(String).join(':');
const canonicalDocument = (value) => Buffer.from(`${JSON.stringify(value, null, 2)}\n`, 'utf8');

const protectedParents = (path, fileSystem, expectedUid) => {
  let current = resolve(path, '..');
  for (;;) {
    const state = fileSystem.lstatSync(current, { bigint: true });
    if (!state.isDirectory() || state.isSymbolicLink() || state.uid !== BigInt(expectedUid) || (state.mode & 0o022n) !== 0n) fail('qualification activation parent is unsafe');
    if (current === '/') break;
    current = resolve(current, '..');
  }
};

const openStableFile = (path, { fileSystem, expectedUid, exactMode, maximumBytes, keepOpen = false, production }) => {
  if (!isAbsolute(path) || resolve(path) !== path) fail('qualification activation path is invalid');
  if (production) protectedParents(path, fileSystem, expectedUid);
  let descriptor;
  try { descriptor = fileSystem.openSync(path, fileSystem.constants.O_RDONLY | fileSystem.constants.O_NOFOLLOW); }
  catch { fail('qualification activation input is unavailable'); }
  try {
    const before = fileSystem.fstatSync(descriptor, { bigint: true });
    if (!before.isFile() || before.isSymbolicLink?.() || before.uid !== BigInt(expectedUid) || before.nlink !== 1n || (before.mode & 0o7777n) !== BigInt(exactMode) || before.size <= 0n || before.size > BigInt(maximumBytes)) fail('qualification activation input is unsafe');
    const bytes = Buffer.alloc(Number(before.size)); let offset = 0;
    while (offset < bytes.length) {
      const count = fileSystem.readSync(descriptor, bytes, offset, bytes.length - offset, offset);
      if (count <= 0) fail('qualification activation input changed');
      offset += count;
    }
    const after = fileSystem.fstatSync(descriptor, { bigint: true });
    if (identity(before) !== identity(after)) fail('qualification activation input changed');
    if (keepOpen) return { descriptor, bytes };
    fileSystem.closeSync(descriptor); descriptor = undefined;
    return { bytes };
  } finally {
    if (!keepOpen && descriptor !== undefined) fileSystem.closeSync(descriptor);
  }
};

const parseCanonicalConfiguration = (snapshot, label) => {
  let value;
  try { value = JSON.parse(snapshot.bytes.toString('utf8')); } catch { fail(`${label} is invalid`); }
  if (!value || typeof value !== 'object' || Array.isArray(value) || !snapshot.bytes.equals(canonicalDocument(value))) fail(`${label} is invalid`);
  return value;
};

export const startQualificationAgentActivation = ({
  spawnProcess = spawn, fileSystem = fs, platform = process.platform, effectiveUID = process.geteuid?.(), production = true,
  serviceConfigurationPath = SERVICE_CONFIGURATION_PATH, scenarioConfigurationPath = SCENARIO_CONFIGURATION_PATH,
  activationDocumentPath = ACTIVATION_DOCUMENT_PATH, scenario: activationScenario = 'transport-reply-loss'
} = {}) => {
  if (!HOST_EXPECTED_OUTCOME[activationScenario]) fail('qualification activation scenario is invalid');
  if (production && (platform !== 'darwin' || effectiveUID !== 0 || serviceConfigurationPath !== SERVICE_CONFIGURATION_PATH || scenarioConfigurationPath !== SCENARIO_CONFIGURATION_PATH || activationDocumentPath !== ACTIVATION_DOCUMENT_PATH)) fail('production qualification activation requires root on macOS and fixed paths');
  const expectedUid = production ? 0 : effectiveUID;
  if (!Number.isSafeInteger(expectedUid) || expectedUid < 0 || expectedUid > UINT32_MAX) fail('qualification activation identity is invalid');
  const service = parseCanonicalConfiguration(openStableFile(serviceConfigurationPath, { fileSystem, expectedUid, exactMode: 0o600, maximumBytes: 1024 * 1024, production }), 'qualification service configuration');
  const runnerUID = service.allowed_client_uid;
  if (!Number.isSafeInteger(runnerUID) || runnerUID <= 0 || runnerUID >= UINT32_MAX) fail('qualification runner identity is invalid');
  const scenario = parseCanonicalConfiguration(openStableFile(scenarioConfigurationPath, { fileSystem, expectedUid, exactMode: 0o644, maximumBytes: 1024 * 1024, production }), 'qualification scenario configuration');
  const repository = scenario.test_repository;
  if (scenario.schema_version !== 1 || typeof repository !== 'string' || !isAbsolute(repository) || resolve(repository) !== repository || fileSystem.realpathSync(repository) !== repository) fail('qualification repository is invalid');
  const repositoryState = fileSystem.lstatSync(repository, { bigint: true });
  if (!repositoryState.isDirectory() || repositoryState.isSymbolicLink() || repositoryState.uid !== BigInt(runnerUID) || (repositoryState.mode & 0o022n) !== 0n) fail('qualification repository is unsafe');

  const activation = openStableFile(activationDocumentPath, { fileSystem, expectedUid, exactMode: 0o600, maximumBytes: QUALIFICATION_ACTIVATION_MAX_BYTES, keepOpen: true, production });
  try { parseQualificationActivation(activation.bytes); }
  catch { fileSystem.closeSync(activation.descriptor); fail('qualification activation document is invalid'); }

  let child;
  try {
    child = spawnProcess(AGENT_HOST_EXECUTABLE_PATH, AGENT_ACTIVATION_ARGUMENTS, {
      cwd: repository, env: CLEAN_ENVIRONMENT, shell: false,
      stdio: ['ignore', 'pipe', 'pipe', activation.descriptor], uid: runnerUID, gid: Number(repositoryState.gid)
    });
  } catch {
    fileSystem.closeSync(activation.descriptor);
    fail('agent activation process failed');
  }
  fileSystem.closeSync(activation.descriptor);
  if (!child || typeof child.once !== 'function' || typeof child.kill !== 'function' || typeof child.stdout?.on !== 'function' || typeof child.stderr?.on !== 'function') fail('agent activation process failed');
  let stdoutBytes = 0; let stderrBytes = 0; let settled = false; const stdoutChunks = [];
  const completion = new Promise((resolveCompletion, rejectCompletion) => {
    const rejectOnce = () => { if (!settled) { settled = true; rejectCompletion(new Error('agent activation process failed')); } };
    const consume = (stream) => (chunk) => {
      if (stream === 'stdout') { stdoutBytes += chunk.length; stdoutChunks.push(Buffer.from(chunk)); } else stderrBytes += chunk.length;
      if (stdoutBytes > MAX_OUTPUT_BYTES || stderrBytes > MAX_OUTPUT_BYTES) { child.kill('SIGKILL'); rejectOnce(); }
    };
    child.stdout.on('data', consume('stdout')); child.stderr.on('data', consume('stderr'));
    child.once('error', rejectOnce);
    child.once('close', (code, closeSignal) => {
      if (settled) return;
      const output = Buffer.concat(stdoutChunks, stdoutBytes);
      const expectedFailure = HOST_EXPECTED_OUTCOME[activationScenario] === 'rejected';
      if (closeSignal !== null || stderrBytes !== 0 || (expectedFailure ? code !== 1 : code !== 0)) { rejectOnce(); return; }
      try { validateAgentActivationOutput(output, activationScenario); } catch { rejectOnce(); return; }
      settled = true; resolveCompletion(Object.freeze({ exited: true }));
    });
  });
  return Object.freeze({ completion, terminate: (terminationSignal = 'SIGTERM') => child.kill(terminationSignal) });
};

export const executeQualification = ({
  scenario, phase, candidateSHA256, runIDSHA256, signal,
  spawnProcess = spawn,
  startAgentActivation = defaultStartAgentActivation,
  wait = delay,
  runCommand = spawnSync,
  restart = restartQualificationDaemon,
  timeoutMs = SCENARIO_TIMEOUT_MS
} = {}) => {
  if (SCENARIO_PHASE[scenario] !== phase || !DIGEST.test(candidateSHA256 ?? '') || !DIGEST.test(runIDSHA256 ?? '') || !(signal instanceof AbortSignal) || !Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > SCENARIO_TIMEOUT_MS) fail('qualification scenario binding is invalid');
  const child = spawnProcess(CONTROLLER_EXECUTABLE_PATH, ['arm'], { cwd: '/', env: CLEAN_ENVIRONMENT, shell: false, stdio: ['ignore', 'pipe', 'pipe'] });
  if (!child || typeof child.once !== 'function' || typeof child.kill !== 'function' || typeof child.stdout?.on !== 'function' || typeof child.stderr?.on !== 'function') fail('qualification controller process is invalid');

  let stdoutBytes = 0; let stderrBytes = 0; let pending = ''; let settled = false; let activationHandle; let activationStarted = false; let timeoutHandle; let escalationWait;
  const transcript = [];
  let resolveCompletion; let rejectCompletion;
  const completion = new Promise((resolvePromise, rejectPromise) => { resolveCompletion = resolvePromise; rejectCompletion = rejectPromise; });
  const removeAbortListener = () => signal.removeEventListener('abort', abort);
  const rejectOnce = () => {
    if (settled) return;
    settled = true;
    removeAbortListener();
    if (timeoutHandle !== undefined) clearTimeout(timeoutHandle);
    escalationWait?.cancel();
    rejectCompletion(new Error('qualification scenario execution failed'));
  };
  const terminateChild = (terminationSignal) => { try { child.kill(terminationSignal); } catch {} };

  const consume = (chunk, stdout) => {
    if (settled) return;
    if (stdout) stdoutBytes += chunk.length; else stderrBytes += chunk.length;
    if (stdoutBytes > MAX_OUTPUT_BYTES || stderrBytes > MAX_OUTPUT_BYTES) { terminateChild('SIGKILL'); rejectOnce(); return; }
    if (!stdout) return;
    pending += chunk.toString('utf8');
    if (Buffer.byteLength(pending, 'utf8') > MAX_LINE_BYTES * 4) { terminateChild('SIGKILL'); rejectOnce(); return; }
    while (pending.includes('\n')) {
      const index = pending.indexOf('\n'); const line = pending.slice(0, index); pending = pending.slice(index + 1);
      if (line.length === 0) { rejectOnce(); return; }
      try {
        const value = parseControllerLine(line, candidateSHA256, runIDSHA256);
        const expected = ['armed', 'fired', 'disarmed'][transcript.length];
        if (value.status !== expected || (transcript.length > 0 && value.receipt_sha256 !== transcript[0].receipt_sha256)) fail('qualification controller transition is invalid');
        transcript.push(value);
        if (value.status === 'armed') {
          if (activationStarted) fail('agent activation was started more than once');
          activationStarted = true;
          activationHandle = validateActivationHandle(startAgentActivation({ signal, scenario, phase, candidateSHA256, runIDSHA256 }));
          activationHandle.completion.catch(() => undefined);
        }
      } catch { terminateChild('SIGKILL'); rejectOnce(); return; }
    }
  };
  child.stdout.on('data', (chunk) => consume(Buffer.from(chunk), true));
  child.stderr.on('data', (chunk) => consume(Buffer.from(chunk), false));
  child.once('error', rejectOnce);

  const stopActivationBounded = async () => {
    if (!activationHandle) return;
    try { activationHandle.terminate('SIGTERM'); } catch { throw new Error('qualification Agent Host termination failed'); }
    let hostFailed = false;
    const completion = activationHandle.completion.then(() => undefined, () => { hostFailed = true; });
    let expired = false;
    const grace = cancellableWait(TERMINATION_GRACE_MS, wait);
    try {
      await Promise.race([completion, grace.promise.then(() => { expired = true; })]);
    } finally { grace.cancel(); }
    if (!expired) {
      if (hostFailed) throw new Error('qualification Agent Host failed');
      return;
    }
    try { activationHandle.terminate('SIGKILL'); } catch { throw new Error('qualification Agent Host termination failed'); }
    let stillRunning = false;
    const killGrace = cancellableWait(TERMINATION_GRACE_MS, wait);
    try {
      await Promise.race([completion, killGrace.promise.then(() => { stillRunning = true; })]);
    } finally { killGrace.cancel(); }
    if (stillRunning) throw new Error('qualification Agent Host termination timed out');
    if (hostFailed) throw new Error('qualification Agent Host failed');
  };

  child.once('close', async (code, closeSignal) => {
    if (settled) return;
    const controllerLost = code !== 0 || closeSignal !== null || pending.length !== 0 || transcript.length !== 3 || !activationStarted;
    try {
      if (controllerLost) {
        await stopActivationBounded();
        if (transcript.length > 0) await Promise.resolve().then(() => recoverQualification({ expectedReceiptSHA256: transcript[0].receipt_sha256, runCommand, restart }));
        rejectOnce();
        return;
      }
      await stopActivationBounded();
      if (settled) return;
      settled = true;
      removeAbortListener();
      if (timeoutHandle !== undefined) clearTimeout(timeoutHandle);
      escalationWait?.cancel();
      const evidence = Buffer.from(transcript.map((value) => JSON.stringify(value)).join('\n') + '\n', 'utf8');
      resolveCompletion(Object.freeze({ ok: true, status: 'passed', evidence_sha256: crypto.createHash('sha256').update(evidence).digest('hex') }));
    } catch { rejectOnce(); }
  });
  const abort = () => { terminateChild('SIGTERM'); try { activationHandle?.terminate('SIGTERM'); } catch {} };
  signal.addEventListener('abort', abort, { once: true });
  if (signal.aborted) queueMicrotask(abort);
  timeoutHandle = setTimeout(() => {
    if (settled) return;
    timeoutHandle = undefined;
    terminateChild('SIGTERM');
    try { activationHandle?.terminate('SIGTERM'); } catch {}
    escalationWait = cancellableWait(TERMINATION_GRACE_MS, wait);
    escalationWait.promise.then(() => {
      escalationWait = undefined;
      if (settled) return;
      terminateChild('SIGKILL');
      try { activationHandle?.terminate('SIGKILL'); } catch {}
      rejectOnce();
    });
  }, timeoutMs);

  const terminate = async () => {
    if (timeoutHandle !== undefined) { clearTimeout(timeoutHandle); timeoutHandle = undefined; }
    escalationWait?.cancel();
    escalationWait = undefined;
    abort();
    const grace = cancellableWait(TERMINATION_GRACE_MS, wait);
    try { await grace.promise; } finally { grace.cancel(); }
    if (!settled) terminateChild('SIGKILL');
    try { activationHandle?.terminate('SIGKILL'); } catch {}
  };
  return Object.freeze({ completion, terminate });
};

const runLaunchctl = (args, runCommand = spawnSync) => {
  const result = runCommand(LAUNCHCTL_PATH, args, {
    cwd: '/', env: CLEAN_ENVIRONMENT, encoding: null, shell: false,
    stdio: ['ignore', 'pipe', 'pipe'], timeout: COMMAND_TIMEOUT_MS, maxBuffer: MAX_OUTPUT_BYTES
  });
  const stdout = Buffer.isBuffer(result?.stdout) ? result.stdout : Buffer.from(result?.stdout ?? '');
  const stderr = Buffer.isBuffer(result?.stderr) ? result.stderr : Buffer.from(result?.stderr ?? '');
  if (!result || result.error || result.signal !== null || result.status !== 0 || stdout.length + stderr.length > MAX_OUTPUT_BYTES) fail('qualification daemon command failed');
  return stdout;
};

export const restartQualificationDaemon = ({ runCommand = spawnSync } = {}) => {
  runLaunchctl(['kickstart', '-k', SERVICE_TARGET], runCommand);
  const output = runLaunchctl(['print', SERVICE_TARGET], runCommand).toString('utf8');
  const pids = [...output.matchAll(/(?:^|\n)\s*pid\s*=\s*([1-9][0-9]*)\s*$/gmu)];
  if (pids.length !== 1) fail('qualification daemon did not become observable');
  const pid = Number(pids[0][1]);
  if (!Number.isSafeInteger(pid) || pid <= 0) fail('qualification daemon PID is invalid');
  return Object.freeze({ pid });
};

const runFixed = (command, args, runCommand = spawnSync) => runCommand(command, args, {
  cwd: '/', env: CLEAN_ENVIRONMENT, encoding: null, shell: false,
  stdio: ['ignore', 'pipe', 'pipe'], timeout: COMMAND_TIMEOUT_MS, maxBuffer: MAX_OUTPUT_BYTES
});

const oneJSON = (result, label) => {
  const stdout = Buffer.isBuffer(result?.stdout) ? result.stdout : Buffer.from(result?.stdout ?? '');
  const stderr = Buffer.isBuffer(result?.stderr) ? result.stderr : Buffer.from(result?.stderr ?? '');
  if (!result || result.error || result.signal !== null || result.status !== 0 || stdout.length + stderr.length > MAX_OUTPUT_BYTES) fail(`${label} failed`);
  let value;
  try { value = JSON.parse(stdout.toString('utf8')); } catch { fail(`${label} output is invalid`); }
  return value;
};

const boundedCommandOutput = (result, label, maximumStdoutBytes = MAX_OUTPUT_BYTES, maximumStderrBytes = MAX_OUTPUT_BYTES, requireEmptyStderr = false) => {
  const stdout = Buffer.isBuffer(result?.stdout) ? result.stdout : Buffer.from(result?.stdout ?? '');
  const stderr = Buffer.isBuffer(result?.stderr) ? result.stderr : Buffer.from(result?.stderr ?? '');
  if (!result || result.error || result.signal !== null || result.status !== 0 || (requireEmptyStderr && stderr.length !== 0) || stdout.length > maximumStdoutBytes || stderr.length > maximumStderrBytes) fail(`${label} failed`);
  return stdout;
};

const parseQualificationProcessList = (bytes) => {
  if (bytes.length > PS_MAX_OUTPUT_BYTES) fail('qualification process listing exceeded its bound');
  const source = bytes.toString('utf8');
  if (source.length === 0) return true;
  if (!source.endsWith('\n')) fail('qualification process listing is invalid');
  const lines = source.slice(0, -1).split('\n');
  let active = false;
  for (const line of lines) {
    const match = /^\s*([0-9]+)\s+([0-9]+)\s+(.+?)\s*$/u.exec(line);
    if (!match) fail('qualification process listing is invalid');
    const uid = Number(match[1]);
    const pid = Number(match[2]);
    const command = match[3];
    if (!Number.isSafeInteger(uid) || uid < 0 || uid > UINT32_MAX || !Number.isSafeInteger(pid) || pid <= 0 || command.length === 0) fail('qualification process listing is invalid');
    if (command === CONTROLLER_EXECUTABLE_PATH || command === AGENT_HOST_EXECUTABLE_PATH) active = true;
  }
  return !active;
};

export const proveNoQualificationProcesses = ({ runCommand = spawnSync } = {}) => parseQualificationProcessList(boundedCommandOutput(runFixed(PS_PATH, PS_ARGUMENTS, runCommand), 'qualification process proof', PS_MAX_OUTPUT_BYTES, MAX_OUTPUT_BYTES, true));

const controllerDisarmResult = ({ runCommand = spawnSync } = {}) => {
  const value = oneJSON(runFixed(CONTROLLER_EXECUTABLE_PATH, ['disarm'], runCommand), 'qualification disarm');
  exactKeys(value, ['schema_version', 'command', 'ok', 'status', 'candidate_sha256', 'run_id_sha256', 'receipt_sha256', 'error'], 'qualification disarm result');
  if (value.schema_version !== 1 || value.command !== 'disarm' || value.ok !== true || value.status !== 'disarmed' || value.error !== null || !DIGEST.test(value.candidate_sha256) || !DIGEST.test(value.run_id_sha256) || !RECEIPT.test(value.receipt_sha256)) fail('qualification disarm result is invalid');
  return value;
};

const controllerStatusResult = ({ runCommand = spawnSync } = {}) => {
  const value = oneJSON(runFixed(CONTROLLER_EXECUTABLE_PATH, ['status'], runCommand), 'qualification status');
  exactKeys(value, ['schema_version', 'command', 'ok', 'status', 'candidate_sha256', 'run_id_sha256', 'receipt_sha256', 'error'], 'qualification status result');
  if (value.schema_version !== 1 || value.command !== 'status' || value.ok !== true || !['armed', 'fired', 'disarmed'].includes(value.status) || value.error !== null || !DIGEST.test(value.candidate_sha256) || !DIGEST.test(value.run_id_sha256) || !RECEIPT.test(value.receipt_sha256)) fail('qualification status result is invalid');
  return value;
};

export const recoverQualification = ({
  expectedReceiptSHA256, runCommand = spawnSync, restart = restartQualificationDaemon,
  proveNoProcesses = proveNoQualificationProcesses
} = {}) => {
  if (!RECEIPT.test(expectedReceiptSHA256 ?? '')) fail('qualification recovery receipt is invalid');
  if (proveNoProcesses({ runCommand }) !== true) fail('qualification process remained active');
  let value;
  try {
    const status = controllerStatusResult({ runCommand });
    if (status.status !== 'fired' || status.receipt_sha256 !== expectedReceiptSHA256) fail('qualification fired receipt is missing or mismatched');
  } catch (error) {
    if (error?.message === 'qualification fired receipt is missing or mismatched') throw error;
  }
  try {
    value = controllerDisarmResult({ runCommand });
  } catch {
    try {
      restart({ runCommand });
      value = controllerDisarmResult({ runCommand });
    } catch {
      fail('qualification recovery failed');
    }
  }
  if (value.receipt_sha256 !== expectedReceiptSHA256) fail('qualification fired receipt is missing or mismatched');
  try { restart({ runCommand }); } catch { fail('qualification daemon restart failed'); }
  if (proveNoProcesses({ runCommand }) !== true) fail('qualification process remained active');
  return true;
};

export const disarmQualification = ({ runCommand = spawnSync } = {}) => {
  controllerDisarmResult({ runCommand });
  return true;
};

export const proveQualificationListenerUnavailable = ({ runCommand = spawnSync } = {}) => {
  const value = oneJSON(runFixed(APPROVED_LISTENER_PROBE_PATH, LISTENER_PROBE_ARGUMENTS, runCommand), 'qualification listener proof');
  exactKeys(value, ['schema_version', 'operation', 'outcome', 'service_protocol_version'], 'qualification listener result');
  return value.schema_version === 1 && value.operation === 'qualification-controller-status' && value.outcome === 'denied-before-selector' && value.service_protocol_version === null;
};
