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

const CLEAN_ENVIRONMENT = Object.freeze({ HOME: '/var/empty', LANG: 'C', LC_ALL: 'C', PATH: '/usr/bin:/bin:/usr/sbin:/sbin' });
const DIGEST = /^[0-9a-f]{64}$/u;
const RECEIPT = /^[0-9a-f]{64}$/u;
const MAX_OUTPUT_BYTES = 64 * 1024;
const MAX_LINE_BYTES = 2048;
const TERMINATION_GRACE_MS = 5_000;
const UINT32_MAX = 0xffff_ffff;

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

const defaultStartAgentActivation = () => startQualificationAgentActivation();

const validateActivationHandle = (handle) => {
  if (!handle || typeof handle !== 'object' || typeof handle.completion?.then !== 'function' || typeof handle.terminate !== 'function') fail('agent activation handle is invalid');
  return handle;
};

const validateAgentActivationOutput = (bytes) => {
  const source = bytes.toString('utf8');
  if (!source.endsWith('\n')) fail('agent activation output is invalid');
  const lines = source.slice(0, -1).split('\n');
  if (lines.length !== 2) fail('agent activation output is invalid');
  const expectedStatuses = ['active', 'closed'];
  for (let index = 0; index < lines.length; index += 1) {
    let value;
    try { value = JSON.parse(lines[index]); } catch { fail('agent activation output is invalid'); }
    exactKeys(value, ['error', 'ok', 'operation', 'status'], 'agent activation result');
    if (value.error !== null || value.ok !== true || value.operation !== 'qualification-activate' || value.status !== expectedStatuses[index]) fail('agent activation output is invalid');
    const canonical = JSON.stringify(Object.fromEntries(Object.keys(value).sort().map((key) => [key, value[key]])));
    if (canonical !== lines[index]) fail('agent activation output is invalid');
  }
};

const delay = (milliseconds) => new Promise((resolvePromise) => setTimeout(resolvePromise, milliseconds));

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
  activationDocumentPath = ACTIVATION_DOCUMENT_PATH
} = {}) => {
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
      if (code !== 0 || closeSignal !== null || stderrBytes !== 0) { rejectOnce(); return; }
      try { validateAgentActivationOutput(Buffer.concat(stdoutChunks, stdoutBytes)); } catch { rejectOnce(); return; }
      settled = true; resolveCompletion(Object.freeze({ exited: true }));
    });
  });
  return Object.freeze({ completion, terminate: (terminationSignal = 'SIGTERM') => child.kill(terminationSignal) });
};

export const executeQualification = ({
  scenario, phase, candidateSHA256, runIDSHA256, signal,
  spawnProcess = spawn,
  startAgentActivation = defaultStartAgentActivation,
  wait = delay
} = {}) => {
  if (SCENARIO_PHASE[scenario] !== phase || !DIGEST.test(candidateSHA256 ?? '') || !DIGEST.test(runIDSHA256 ?? '') || !(signal instanceof AbortSignal)) fail('qualification scenario binding is invalid');
  const child = spawnProcess(CONTROLLER_EXECUTABLE_PATH, ['arm'], { cwd: '/', env: CLEAN_ENVIRONMENT, shell: false, stdio: ['ignore', 'pipe', 'pipe'] });
  if (!child || typeof child.once !== 'function' || typeof child.kill !== 'function' || typeof child.stdout?.on !== 'function' || typeof child.stderr?.on !== 'function') fail('qualification controller process is invalid');

  let stdoutBytes = 0; let stderrBytes = 0; let pending = ''; let settled = false; let activationHandle; let activationStarted = false;
  const transcript = [];
  let resolveCompletion; let rejectCompletion;
  const completion = new Promise((resolvePromise, rejectPromise) => { resolveCompletion = resolvePromise; rejectCompletion = rejectPromise; });
  const removeAbortListener = () => signal.removeEventListener('abort', abort);
  const rejectOnce = () => { if (!settled) { settled = true; removeAbortListener(); rejectCompletion(new Error('qualification scenario execution failed')); } };
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
  child.once('close', (code, closeSignal) => {
    if (settled) return;
    if (code !== 0 || closeSignal !== null || pending.length !== 0 || transcript.length !== 3 || !activationStarted) { rejectOnce(); return; }
    try { activationHandle.terminate('SIGTERM'); } catch { rejectOnce(); return; }
    activationHandle.completion.then(() => {
      if (settled) return;
      settled = true;
      removeAbortListener();
      const evidence = Buffer.from(transcript.map((value) => JSON.stringify(value)).join('\n') + '\n', 'utf8');
      resolveCompletion(Object.freeze({ ok: true, status: 'passed', evidence_sha256: crypto.createHash('sha256').update(evidence).digest('hex') }));
    }).catch(rejectOnce);
  });
  const abort = () => { terminateChild('SIGTERM'); try { activationHandle?.terminate('SIGTERM'); } catch {} };
  signal.addEventListener('abort', abort, { once: true });
  if (signal.aborted) queueMicrotask(abort);

  const terminate = async () => {
    abort();
    await wait(TERMINATION_GRACE_MS);
    if (!settled) terminateChild('SIGKILL');
    try { activationHandle?.terminate('SIGKILL'); } catch {}
  };
  return Object.freeze({ completion, terminate });
};

const runFixed = (command, args, runCommand = spawnSync) => runCommand(command, args, {
  cwd: '/', env: CLEAN_ENVIRONMENT, encoding: null, shell: false,
  stdio: ['ignore', 'pipe', 'pipe'], timeout: 30_000, maxBuffer: MAX_OUTPUT_BYTES
});

const oneJSON = (result, label) => {
  const stdout = Buffer.isBuffer(result?.stdout) ? result.stdout : Buffer.from(result?.stdout ?? '');
  const stderr = Buffer.isBuffer(result?.stderr) ? result.stderr : Buffer.from(result?.stderr ?? '');
  if (!result || result.error || result.signal !== null || result.status !== 0 || stdout.length + stderr.length > MAX_OUTPUT_BYTES) fail(`${label} failed`);
  let value;
  try { value = JSON.parse(stdout.toString('utf8')); } catch { fail(`${label} output is invalid`); }
  return value;
};

export const disarmQualification = ({ runCommand = spawnSync } = {}) => {
  const value = oneJSON(runFixed(CONTROLLER_EXECUTABLE_PATH, ['disarm'], runCommand), 'qualification disarm');
  exactKeys(value, ['schema_version', 'command', 'ok', 'status', 'candidate_sha256', 'run_id_sha256', 'receipt_sha256', 'error'], 'qualification disarm result');
  if (value.schema_version !== 1 || value.command !== 'disarm' || value.ok !== true || value.status !== 'disarmed' || value.error !== null || !DIGEST.test(value.candidate_sha256) || !DIGEST.test(value.run_id_sha256) || !RECEIPT.test(value.receipt_sha256)) fail('qualification disarm result is invalid');
  return true;
};

export const proveQualificationListenerUnavailable = ({ runCommand = spawnSync } = {}) => {
  const value = oneJSON(runFixed(APPROVED_LISTENER_PROBE_PATH, LISTENER_PROBE_ARGUMENTS, runCommand), 'qualification listener proof');
  exactKeys(value, ['schema_version', 'operation', 'outcome', 'service_protocol_version'], 'qualification listener result');
  return value.schema_version === 1 && value.operation === 'qualification-controller-status' && value.outcome === 'denied-before-selector' && value.service_protocol_version === null;
};
