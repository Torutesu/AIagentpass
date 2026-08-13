#!/usr/bin/env node
import fs from 'node:fs';
import { spawnSync } from 'node:child_process';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  PROVISION_STATE_PATH,
  SCENARIO_PHASE,
  provisionQualificationConfig,
  restoreQualificationConfig
} from './provision-qualification-config.mjs';

export const SERVICE_LABEL = 'dev.agentpass.native-service';
export const SERVICE_TARGET = `system/${SERVICE_LABEL}`;
export const LAUNCHCTL_PATH = '/bin/launchctl';
export const DEFAULT_TIMEOUT_MILLISECONDS = 15 * 60 * 1000;
export const TERMINATION_GRACE_MILLISECONDS = 30 * 1000;
export const RUN_LOCK_PATH = '/Library/Application Support/AgentPass/n3e-qualification-run.lock';

const DIGEST = /^[0-9a-f]{64}$/u;
const SAFE_STATUS = /^[a-z][a-z0-9_-]{0,63}$/u;
const SIGNALS = Object.freeze(['SIGHUP', 'SIGINT', 'SIGTERM']);
const CLEAN_ENVIRONMENT = Object.freeze({
  HOME: '/var/empty',
  LANG: 'C',
  LC_ALL: 'C',
  PATH: '/usr/bin:/bin:/usr/sbin:/sbin'
});

const fail = (message) => { throw new Error(message); };

const commandOutput = (result) => Buffer.concat([
  Buffer.isBuffer(result?.stdout) ? result.stdout : Buffer.from(result?.stdout ?? ''),
  Buffer.isBuffer(result?.stderr) ? result.stderr : Buffer.from(result?.stderr ?? '')
]);

const runLaunchctl = (args, runCommand = spawnSync) => {
  const result = runCommand(LAUNCHCTL_PATH, args, {
    cwd: '/',
    encoding: null,
    env: CLEAN_ENVIRONMENT,
    shell: false,
    stdio: ['ignore', 'pipe', 'pipe'],
    timeout: 30_000,
    maxBuffer: 64 * 1024
  });
  if (!result || result.error || result.signal !== null || result.status !== 0 || commandOutput(result).length > 64 * 1024) {
    fail('launchd service restart failed');
  }
};

export const restartNativeService = ({ runCommand = spawnSync } = {}) => {
  runLaunchctl(['kickstart', '-k', SERVICE_TARGET], runCommand);
  const observed = runCommand(LAUNCHCTL_PATH, ['print', SERVICE_TARGET], {
    cwd: '/',
    encoding: null,
    env: CLEAN_ENVIRONMENT,
    shell: false,
    stdio: ['ignore', 'pipe', 'pipe'],
    timeout: 30_000,
    maxBuffer: 64 * 1024
  });
  const bytes = commandOutput(observed);
  if (!observed || observed.error || observed.signal !== null || observed.status !== 0 || bytes.length > 64 * 1024) {
    fail('launchd service did not become observable');
  }
  const output = bytes.toString('utf8');
  const pids = [...output.matchAll(/(?:^|\n)\s*pid\s*=\s*([1-9][0-9]*)\s*$/gmu)];
  if (pids.length !== 1) fail('launchd service PID was not mechanically observable');
  const pid = Number(pids[0][1]);
  if (!Number.isSafeInteger(pid) || pid <= 0) fail('launchd service PID is invalid');
  return Object.freeze({ pid });
};

const normalizeExecutionResult = (value) => {
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail('qualification execution result is invalid');
  const keys = Object.keys(value).sort();
  const expected = ['evidence_sha256', 'ok', 'status'];
  if (keys.length !== expected.length || keys.some((key, index) => key !== expected[index])) fail('qualification execution result is not closed');
  if (value.ok !== true || typeof value.status !== 'string' || !SAFE_STATUS.test(value.status) || !DIGEST.test(value.evidence_sha256) || /^0+$/u.test(value.evidence_sha256)) fail('qualification execution result is invalid');
  return Object.freeze({ ok: true, status: value.status, evidence_sha256: value.evidence_sha256 });
};

const normalizeCandidateMaterialization = (value) => {
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail('controller candidate materialization result is invalid');
  const keys = Object.keys(value).sort();
  const expected = ['action', 'files', 'manifest_sha256', 'ok', 'public_key_sha256', 'signature_sha256'];
  if (keys.length !== expected.length || keys.some((key, index) => key !== expected[index])) fail('controller candidate materialization result is not closed');
  if (value.ok !== true || value.action !== 'materialized' || value.files !== 3 || !DIGEST.test(value.manifest_sha256) || !DIGEST.test(value.signature_sha256) || !DIGEST.test(value.public_key_sha256)) fail('controller candidate materialization result is invalid');
  return Object.freeze({ ...value });
};

const defaultSignals = (handler) => {
  for (const signal of SIGNALS) process.once(signal, handler);
  return () => { for (const signal of SIGNALS) process.removeListener(signal, handler); };
};

const combineFailures = (primary, cleanup) => {
  if (!primary && cleanup.length === 0) return null;
  const error = new Error(primary ? 'protected qualification failed' : 'protected qualification cleanup failed');
  // Do not attach arbitrary child or filesystem errors: callers may serialize
  // the error, and those messages can contain local paths or command output.
  error.cleanupFailures = Object.freeze(cleanup.map(() => 'cleanup_failed'));
  return error;
};

const stateExists = (fileSystem, statePath) => {
  try {
    const stat = fileSystem.lstatSync(statePath);
    return stat.isFile() || stat.isSymbolicLink() || stat.isDirectory();
  } catch (error) {
    if (error?.code === 'ENOENT') return false;
    throw error;
  }
};

const lockIdentity = (stat) => [stat.dev, stat.ino, stat.mode, stat.nlink, stat.uid, stat.gid].map(String).join(':');

const removeRecoveredRunLock = (fileSystem, lockPath, expectedUid) => {
  let stat;
  try { stat = fileSystem.lstatSync(lockPath, { bigint: true }); }
  catch (error) {
    if (error?.code === 'ENOENT') return false;
    fail('protected qualification recovery lock is unavailable');
  }
  if (!stat.isDirectory() || stat.isSymbolicLink() || stat.uid !== BigInt(expectedUid) || (stat.mode & 0o7777n) !== 0o700n || stat.nlink < 1n) fail('protected qualification recovery lock is unsafe');
  let entries;
  try { entries = fileSystem.readdirSync(lockPath); } catch { fail('protected qualification recovery lock is unavailable'); }
  if (!Array.isArray(entries) || entries.length !== 0) fail('protected qualification recovery lock is not empty');
  const identity = lockIdentity(stat);
  const current = fileSystem.lstatSync(lockPath, { bigint: true });
  if (lockIdentity(current) !== identity) fail('protected qualification recovery lock changed');
  fileSystem.rmdirSync(lockPath);
  return true;
};

export const acquireRunLock = ({ fileSystem = fs, lockPath = RUN_LOCK_PATH, expectedUid = 0 } = {}) => {
  let parent;
  try { parent = fileSystem.lstatSync(dirname(lockPath), { bigint: true }); }
  catch { fail('protected qualification lock parent is unavailable'); }
  if (!parent.isDirectory() || parent.isSymbolicLink() || parent.uid !== BigInt(expectedUid) || (parent.mode & 0o022n) !== 0n) fail('protected qualification lock parent is unsafe');
  try { fileSystem.mkdirSync(lockPath, { mode: 0o700 }); }
  catch (error) {
    if (error?.code === 'EEXIST') fail('protected qualification is already active or requires explicit recovery');
    fail('protected qualification lock is unavailable');
  }
  let stat;
  try { stat = fileSystem.lstatSync(lockPath, { bigint: true }); }
  catch { fail('protected qualification lock verification failed'); }
  if (!stat.isDirectory() || stat.isSymbolicLink() || stat.uid !== BigInt(expectedUid) || (stat.mode & 0o7777n) !== 0o700n || stat.nlink < 1n) {
    fail('protected qualification lock is unsafe');
  }
  const identity = lockIdentity(stat);
  let released = false;
  return () => {
    if (released) return;
    let current;
    try { current = fileSystem.lstatSync(lockPath, { bigint: true }); }
    catch { fail('protected qualification lock changed before release'); }
    if (lockIdentity(current) !== identity) fail('protected qualification lock changed before release');
    try { fileSystem.rmdirSync(lockPath); }
    catch { fail('protected qualification lock release failed'); }
    released = true;
  };
};

const validateExecutionHandle = (value) => {
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail('qualification execution handle is invalid');
  const keys = Object.keys(value).sort();
  if (keys.length !== 2 || keys[0] !== 'completion' || keys[1] !== 'terminate' || typeof value.terminate !== 'function' || typeof value.completion?.then !== 'function') fail('qualification execution handle is invalid');
  return value;
};

const terminateExecution = async (handle, reason, setTimer, clearTimer) => {
  let terminationTimer;
  const deadline = new Promise((_, reject) => {
    terminationTimer = setTimer(() => reject(new Error('qualification termination timed out')), TERMINATION_GRACE_MILLISECONDS);
  });
  try {
    await Promise.race([
      Promise.resolve(handle.terminate(reason)).then(() => handle.completion.catch(() => undefined)),
      deadline
    ]);
  } finally {
    if (terminationTimer !== undefined) clearTimer(terminationTimer);
  }
};

export const recoverProtectedQualification = ({
  platform = process.platform,
  uid = process.getuid?.(),
  fileSystem = fs,
  statePath = PROVISION_STATE_PATH,
  lockPath = RUN_LOCK_PATH,
  restore = restoreQualificationConfig,
  restart = restartNativeService,
  recoverCandidate,
  proveListenerUnavailable,
  proveNoActiveRun
} = {}) => {
  if (platform !== 'darwin' || uid !== 0) fail('protected qualification recovery requires root on macOS');
  if (typeof recoverCandidate !== 'function' || typeof proveListenerUnavailable !== 'function' || typeof proveNoActiveRun !== 'function') fail('qualification recovery callbacks are required');
  try {
    if (proveNoActiveRun() !== true) fail('protected qualification recovery refused an active run');
    recoverCandidate();
    let restored = false;
    if (stateExists(fileSystem, statePath)) {
      restore();
      restored = true;
    }
    restart();
    if (proveListenerUnavailable() !== true) fail('qualification listener remained reachable after recovery');
    const stale_lock_removed = removeRecoveredRunLock(fileSystem, lockPath, uid);
    return Object.freeze({ ok: true, action: 'recovered', restored, stale_lock_removed, listener_unreachable: true });
  } catch {
    fail('protected qualification recovery failed');
  }
};

export const runProtectedQualification = async ({
  provisionOptions,
  materializeCandidate,
  removeCandidate,
  executeQualification,
  disarmQualification,
  proveListenerUnavailable,
  platform = process.platform,
  uid = process.getuid?.(),
  fileSystem = fs,
  statePath = PROVISION_STATE_PATH,
  provision = provisionQualificationConfig,
  restore = restoreQualificationConfig,
  restart = restartNativeService,
  registerSignals = defaultSignals,
  timeoutMilliseconds = DEFAULT_TIMEOUT_MILLISECONDS,
  setTimer = setTimeout,
  clearTimer = clearTimeout
} = {}) => {
  if (platform !== 'darwin' || uid !== 0) fail('protected qualification requires root on macOS');
  if (!provisionOptions || typeof provisionOptions !== 'object' || Array.isArray(provisionOptions)) fail('qualification provision options are required');
  if (SCENARIO_PHASE[provisionOptions.scenario] === undefined) fail('qualification scenario is invalid');
  if (typeof materializeCandidate !== 'function' || typeof removeCandidate !== 'function' || typeof executeQualification !== 'function' || typeof disarmQualification !== 'function' || typeof proveListenerUnavailable !== 'function') fail('fixed qualification lifecycle callbacks are required');
  if (!Number.isSafeInteger(timeoutMilliseconds) || timeoutMilliseconds < 1_000 || timeoutMilliseconds > DEFAULT_TIMEOUT_MILLISECONDS) fail('qualification timeout is invalid');

  const controller = new AbortController();
  let caughtSignal = null;
  let interruptExecution;
  const interruption = new Promise((_, reject) => { interruptExecution = reject; });
  const signalHandler = (signal) => {
    caughtSignal = SIGNALS.includes(signal) ? signal : 'SIGTERM';
    controller.abort(new Error('qualification interrupted'));
    interruptExecution(new Error('qualification interrupted'));
  };
  let unregisterSignals;
  let releaseLock;
  let timer;
  let primaryFailure = null;
  let execution;
  let executionHandle;
  let candidateMaterialization;
  let provisionAttempted = false;
  let provisioned = false;
  const cleanupFailures = [];

  try {
    releaseLock = acquireRunLock({ fileSystem, expectedUid: uid });
    if (stateExists(fileSystem, statePath)) fail('protected qualification requires explicit recovery');
    unregisterSignals = registerSignals(signalHandler);
    provisionAttempted = true;
    const provisionResult = provision(provisionOptions);
    provisioned = true;
    candidateMaterialization = normalizeCandidateMaterialization(materializeCandidate());
    restart();
    executionHandle = validateExecutionHandle(executeQualification({
        signal: controller.signal,
        scenario: provisionResult.scenario,
        phase: provisionResult.phase,
        candidateSHA256: provisionResult.candidate_sha256,
        runIDSHA256: provisionResult.run_id_sha256
    }));
    timer = setTimer(() => {
      controller.abort(new Error('qualification timed out'));
      interruptExecution(new Error('qualification timed out'));
    }, timeoutMilliseconds);
    execution = normalizeExecutionResult(await Promise.race([executionHandle.completion, interruption]));
  } catch (error) {
    primaryFailure = error;
  } finally {
    if (timer !== undefined) clearTimer(timer);
    try { unregisterSignals?.(); } catch (error) { cleanupFailures.push(error); }
    if (primaryFailure && executionHandle) {
      try { await terminateExecution(executionHandle, caughtSignal ? 'signal' : controller.signal.aborted ? 'timeout' : 'failure', setTimer, clearTimer); } catch (error) { cleanupFailures.push(error); }
    }
    let durableStatePresent = false;
    try { durableStatePresent = stateExists(fileSystem, statePath); } catch (error) { cleanupFailures.push(error); }
    if (provisionAttempted && (provisioned || durableStatePresent)) {
      try { await disarmQualification({ signal: controller.signal }); } catch (error) { cleanupFailures.push(error); }
      if (candidateMaterialization) {
        try { removeCandidate({ materialization: candidateMaterialization }); } catch (error) { cleanupFailures.push(error); }
      }
      try { restore(); } catch (error) { cleanupFailures.push(error); }
      try { restart(); } catch (error) { cleanupFailures.push(error); }
    }
    if (provisionAttempted) {
      try {
        if (proveListenerUnavailable() !== true) fail('qualification listener remained reachable after cleanup');
      } catch (error) { cleanupFailures.push(error); }
    }
    try { releaseLock?.(); } catch (error) { cleanupFailures.push(error); }
  }

  const failure = combineFailures(primaryFailure, cleanupFailures);
  if (failure) throw failure;
  if (caughtSignal !== null) fail('protected qualification was interrupted');
  return Object.freeze({
    ok: true,
    action: 'completed',
    scenario: provisionOptions.scenario,
    phase: SCENARIO_PHASE[provisionOptions.scenario],
    execution,
    cleanup: Object.freeze({ restored: true, service_restarted: true, listener_unreachable: true })
  });
};

if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
  process.stderr.write('protected qualification refused: fixed installed scenario driver required\n');
  process.exitCode = 2;
}
