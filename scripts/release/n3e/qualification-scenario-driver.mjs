import crypto from 'node:crypto';
import { spawn, spawnSync } from 'node:child_process';
import { SCENARIO_PHASE } from './provision-qualification-config.mjs';

export const SCENARIOS = Object.freeze(Object.keys(SCENARIO_PHASE));
export const CONTROLLER_EXECUTABLE_PATH = '/Library/Application Support/AgentPass/Qualification/AgentPassQualificationController.app/Contents/MacOS/agentpass-qualification-controller';
export const AGENT_HOST_EXECUTABLE_PATH = '/Applications/AgentPass.app/Contents/Library/HelperTools/AgentPassNativeAgentHost.app/Contents/MacOS/agentpass-native-agent-host';
export const APPROVED_LISTENER_PROBE_PATH = '/opt/agentpass/p0c/probes/controller-approved/AgentPassNegativeXPCProbe.app/Contents/MacOS/agentpass-negative-xpc-probe';
export const AGENT_ACTIVATION_ARGUMENTS = Object.freeze(['qualification-activate']);
export const LISTENER_PROBE_ARGUMENTS = Object.freeze(['qualification-controller']);

const CLEAN_ENVIRONMENT = Object.freeze({ HOME: '/var/empty', LANG: 'C', LC_ALL: 'C', PATH: '/usr/bin:/bin:/usr/sbin:/sbin' });
const DIGEST = /^[0-9a-f]{64}$/u;
const RECEIPT = /^[0-9a-f]{64}$/u;
const MAX_OUTPUT_BYTES = 64 * 1024;
const MAX_LINE_BYTES = 2048;
const TERMINATION_GRACE_MS = 5_000;

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

const defaultStartAgentActivation = () => {
  const child = spawn(AGENT_HOST_EXECUTABLE_PATH, AGENT_ACTIVATION_ARGUMENTS, {
    cwd: '/', env: CLEAN_ENVIRONMENT, shell: false, stdio: ['ignore', 'pipe', 'pipe']
  });
  let stdoutBytes = 0; let stderrBytes = 0; let settled = false;
  const completion = new Promise((resolve, reject) => {
    const failOnce = (message) => { if (!settled) { settled = true; reject(new Error(message)); } };
    const consume = (stream) => (chunk) => {
      if (stream === 'stdout') stdoutBytes += chunk.length; else stderrBytes += chunk.length;
      if (stdoutBytes > MAX_OUTPUT_BYTES || stderrBytes > MAX_OUTPUT_BYTES) {
        child.kill('SIGKILL');
        failOnce('agent activation output exceeded its bound');
      }
    };
    child.stdout.on('data', consume('stdout')); child.stderr.on('data', consume('stderr'));
    child.once('error', () => failOnce('agent activation process failed'));
    child.once('close', (code, signal) => {
      if (settled) return;
      if (stdoutBytes > MAX_OUTPUT_BYTES || stderrBytes > MAX_OUTPUT_BYTES || signal !== null || code !== 0) failOnce('agent activation process failed');
      else { settled = true; resolve(Object.freeze({ exited: true })); }
    });
  });
  return Object.freeze({ completion, terminate: (signal = 'SIGTERM') => child.kill(signal) });
};

const validateActivationHandle = (handle) => {
  if (!handle || typeof handle !== 'object' || typeof handle.completion?.then !== 'function' || typeof handle.terminate !== 'function') fail('agent activation handle is invalid');
  return handle;
};

const delay = (milliseconds) => new Promise((resolvePromise) => setTimeout(resolvePromise, milliseconds));

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
