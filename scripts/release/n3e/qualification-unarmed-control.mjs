#!/usr/bin/env node
import crypto from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  AGENT_ACTIVATION_ARGUMENTS,
  AGENT_HOST_EXECUTABLE_PATH,
  CONTROLLER_EXECUTABLE_PATH,
  startQualificationAgentActivation
} from './qualification-scenario-driver.mjs';

export const UNARMED_CONTROL_SCHEMA_VERSION = 1;
export const UNARMED_CONTROL_KIND = 'agentpass-n3e-qualification-unarmed-control';
export const UNARMED_CONTROL_TIMEOUT_MILLISECONDS = 15 * 60 * 1000;
export const UNARMED_CONTROL_COMMAND_TIMEOUT_MILLISECONDS = 30 * 1000;
export const UNARMED_CONTROL_MAX_OUTPUT_BYTES = 64 * 1024;
export const UNARMED_CONTROL_TERMINATION_GRACE_MILLISECONDS = 5 * 1000;
export const UNARMED_CONTROL_AGENT_STATUSES = Object.freeze(['active', 'closed']);
export const UNARMED_CONTROL_CONTROLLER_STATUS = 'disarmed';

const DIGEST = /^[0-9a-f]{64}$/u;
const ZERO_DIGEST = /^0+$/u;
const FIXED_CONTROLLER_ARGUMENTS = Object.freeze(['status']);
const FIXED_ENVIRONMENT = Object.freeze({
  HOME: '/var/empty',
  LANG: 'C',
  LC_ALL: 'C',
  PATH: '/usr/bin:/bin:/usr/sbin:/sbin'
});

const fail = (message) => { throw new Error(message); };

const exactKeys = (value, expected, label) => {
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail(`${label} is invalid`);
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) fail(`${label} is not closed`);
};

const canonicalValue = (value) => {
  if (Array.isArray(value)) return value.map(canonicalValue);
  if (value && typeof value === 'object') return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonicalValue(value[key])]));
  return value;
};

const canonicalJSON = (value) => Buffer.from(`${JSON.stringify(canonicalValue(value))}\n`, 'utf8');

const assertDigest = (value, label) => {
  if (typeof value !== 'string' || !DIGEST.test(value) || ZERO_DIGEST.test(value)) fail(`${label} is invalid`);
  return value;
};

const commandOutput = (result) => {
  const stdout = Buffer.isBuffer(result?.stdout) ? result.stdout : Buffer.from(result?.stdout ?? '');
  const stderr = Buffer.isBuffer(result?.stderr) ? result.stderr : Buffer.from(result?.stderr ?? '');
  if (stdout.length + stderr.length > UNARMED_CONTROL_MAX_OUTPUT_BYTES) fail('qualification Controller output exceeded its bound');
  return stdout;
};

const runFixedControllerStatus = (runCommand = spawnSync) => {
  const result = runCommand(CONTROLLER_EXECUTABLE_PATH, FIXED_CONTROLLER_ARGUMENTS, {
    cwd: '/',
    env: FIXED_ENVIRONMENT,
    encoding: null,
    shell: false,
    stdio: ['ignore', 'pipe', 'pipe'],
    timeout: UNARMED_CONTROL_COMMAND_TIMEOUT_MILLISECONDS,
    maxBuffer: UNARMED_CONTROL_MAX_OUTPUT_BYTES
  });
  if (!result || result.error || result.signal !== null || result.status !== 0) fail('qualification Controller status command failed');
  return commandOutput(result);
};

const parseControllerStatusObject = (value, candidateSHA256, runIDSHA256) => {
  exactKeys(value, ['schema_version', 'command', 'ok', 'status', 'candidate_sha256', 'run_id_sha256', 'receipt_sha256', 'error'], 'qualification Controller status result');
  if (
    value.schema_version !== 1 ||
    value.command !== 'status' ||
    value.ok !== true ||
    value.status !== UNARMED_CONTROL_CONTROLLER_STATUS ||
    value.error !== null ||
    !DIGEST.test(value.candidate_sha256) ||
    !DIGEST.test(value.run_id_sha256) ||
    !DIGEST.test(value.receipt_sha256) ||
    value.candidate_sha256 !== candidateSHA256 ||
    value.run_id_sha256 !== runIDSHA256
  ) fail('qualification Controller status is not the bound disarmed state');
  return Object.freeze({ ...value });
};

export const parseUnarmedControllerStatus = (bytes, { candidateSHA256, runIDSHA256 } = {}) => {
  assertDigest(candidateSHA256, 'qualification candidate digest');
  assertDigest(runIDSHA256, 'qualification run digest');
  if (!Buffer.isBuffer(bytes) || bytes.length === 0 || bytes.length > UNARMED_CONTROL_MAX_OUTPUT_BYTES) fail('qualification Controller status output is invalid');
  let value;
  try { value = JSON.parse(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes)); }
  catch { fail('qualification Controller status output is invalid'); }
  return parseControllerStatusObject(value, candidateSHA256, runIDSHA256);
};

const readControllerStatus = (runCommand, bindings) => parseUnarmedControllerStatus(runFixedControllerStatus(runCommand), bindings);

const fixedAgentActivation = ({ signal }) => startQualificationAgentActivation({
  signal,
  scenario: 'transport-reply-loss'
});

const validateActivationHandle = (value) => {
  if (!value || typeof value !== 'object' || Array.isArray(value) || typeof value.terminate !== 'function' || typeof value.completion?.then !== 'function') fail('qualification Agent Host activation handle is invalid');
  return value;
};

const validateActivationCompletion = (value) => {
  exactKeys(value, ['exited'], 'qualification Agent Host activation result');
  if (value.exited !== true) fail('qualification Agent Host activation did not exit successfully');
  return value;
};

const waitFor = (milliseconds) => new Promise((resolvePromise) => setTimeout(resolvePromise, milliseconds));

const terminateActivationBounded = async (activation, wait, graceMilliseconds) => {
  if (!activation) return;
  try { activation.terminate('SIGTERM'); } catch { fail('qualification Agent Host termination failed'); }
  let expired = false;
  await Promise.race([
    Promise.resolve(activation.completion).then(() => undefined, () => undefined),
    wait(graceMilliseconds).then(() => { expired = true; })
  ]);
  if (!expired) return;
  try { activation.terminate('SIGKILL'); } catch { fail('qualification Agent Host termination failed'); }
};

const buildEvidence = ({ candidateSHA256, runIDSHA256, before, after }) => ({
  schema_version: UNARMED_CONTROL_SCHEMA_VERSION,
  kind: UNARMED_CONTROL_KIND,
  candidate_sha256: candidateSHA256,
  run_id_sha256: runIDSHA256,
  controller: {
    executable: CONTROLLER_EXECUTABLE_PATH,
    argv: [...FIXED_CONTROLLER_ARGUMENTS],
    before,
    after
  },
  agent_host: {
    executable: AGENT_HOST_EXECUTABLE_PATH,
    argv: [...AGENT_ACTIVATION_ARGUMENTS],
    status_sequence: [...UNARMED_CONTROL_AGENT_STATUSES]
  },
  durable_fired_evidence: 'not-observed'
});

export const unarmedControlEvidenceSHA256 = ({ candidateSHA256, runIDSHA256, before, after } = {}) => {
  assertDigest(candidateSHA256, 'qualification candidate digest');
  assertDigest(runIDSHA256, 'qualification run digest');
  const beforeStatus = parseControllerStatusObject(before, candidateSHA256, runIDSHA256);
  const afterStatus = parseControllerStatusObject(after, candidateSHA256, runIDSHA256);
  const bytes = canonicalJSON(buildEvidence({ candidateSHA256, runIDSHA256, before: beforeStatus, after: afterStatus }));
  return crypto.createHash('sha256').update(bytes).digest('hex');
};

const validateExecutionInput = ({ candidateSHA256, runIDSHA256, signal }) => {
  assertDigest(candidateSHA256, 'qualification candidate digest');
  assertDigest(runIDSHA256, 'qualification run digest');
  if (!(signal instanceof AbortSignal)) fail('qualification unarmed-control signal is invalid');
};

const executeWithDependencies = ({
  candidateSHA256,
  runIDSHA256,
  signal,
  runCommand,
  startAgentActivation,
  timeoutMilliseconds,
  terminationGraceMilliseconds,
  wait
}) => {
  validateExecutionInput({ candidateSHA256, runIDSHA256, signal });
  if (!Number.isSafeInteger(timeoutMilliseconds) || timeoutMilliseconds < 1 || timeoutMilliseconds > UNARMED_CONTROL_TIMEOUT_MILLISECONDS) fail('qualification unarmed-control timeout is invalid');
  if (!Number.isSafeInteger(terminationGraceMilliseconds) || terminationGraceMilliseconds < 1 || terminationGraceMilliseconds > UNARMED_CONTROL_TERMINATION_GRACE_MILLISECONDS) fail('qualification unarmed-control termination grace is invalid');
  if (typeof runCommand !== 'function' || typeof startAgentActivation !== 'function' || typeof wait !== 'function') fail('qualification unarmed-control dependencies are invalid');

  let activation;
  let settled = false;
  let timeoutHandle;
  let removeInterruptionListener = () => {};
  let removeAbortListener = () => {};
  let rejectCompletion;
  let resolveCompletion;
  const completion = new Promise((resolvePromise, rejectPromise) => {
    resolveCompletion = resolvePromise;
    rejectCompletion = rejectPromise;
  });
  const failOnce = (error) => {
    if (settled) return;
    settled = true;
    if (timeoutHandle !== undefined) clearTimeout(timeoutHandle);
    removeInterruptionListener();
    removeAbortListener();
    rejectCompletion(error instanceof Error ? error : new Error('qualification unarmed-control failed'));
  };

  const run = async () => {
    try {
      const before = readControllerStatus(runCommand, { candidateSHA256, runIDSHA256 });
      if (signal.aborted) fail('qualification unarmed-control was interrupted');
      activation = validateActivationHandle(startAgentActivation({ signal }));
      const hostCompletion = Promise.resolve(activation.completion).then(
        validateActivationCompletion,
        () => { throw new Error('qualification Agent Host failed'); }
      );
      hostCompletion.catch(() => undefined);
      const timeout = new Promise((_, reject) => {
        timeoutHandle = setTimeout(() => reject(new Error('qualification unarmed-control timed out')), timeoutMilliseconds);
      });
      const interrupted = new Promise((_, reject) => {
        const abort = () => reject(new Error('qualification unarmed-control was interrupted'));
        removeInterruptionListener = () => signal.removeEventListener('abort', abort);
        signal.addEventListener('abort', abort, { once: true });
        if (signal.aborted) abort();
      });
      try {
        await Promise.race([hostCompletion, timeout, interrupted]);
      } catch (error) {
        try { await terminateActivationBounded(activation, wait, terminationGraceMilliseconds); } catch { /* preserve the primary failure */ }
        throw error;
      } finally {
        if (timeoutHandle !== undefined) clearTimeout(timeoutHandle);
        timeoutHandle = undefined;
        removeInterruptionListener();
        removeInterruptionListener = () => {};
      }
      const after = readControllerStatus(runCommand, { candidateSHA256, runIDSHA256 });
      const evidence_sha256 = unarmedControlEvidenceSHA256({ candidateSHA256, runIDSHA256, before, after });
      if (!settled) {
        settled = true;
        resolveCompletion(Object.freeze({ ok: true, status: 'passed', evidence_sha256 }));
      }
    } catch (error) {
      failOnce(error);
    }
  };

  const abort = () => {
    if (settled) return;
    try { activation?.terminate('SIGTERM'); } catch {}
  };
  signal.addEventListener('abort', abort, { once: true });
  removeAbortListener = () => {
    removeInterruptionListener();
    signal.removeEventListener('abort', abort);
  };
  queueMicrotask(run);

  const terminate = async () => {
    if (settled) return;
    try { await terminateActivationBounded(activation, wait, terminationGraceMilliseconds); } catch { /* the parent owns the final failure */ }
    failOnce(new Error('qualification unarmed-control terminated'));
  };
  return Object.freeze({ completion, terminate });
};

/**
 * Production entry point. Only the bound provision digests and AbortSignal are
 * accepted. Executable paths, argv, environment, endpoint, scenario, and
 * activation proof are fixed in this module or in the fixed Host launcher.
 */
export const executeQualificationUnarmedControl = ({ candidateSHA256, runIDSHA256, signal } = {}) => executeWithDependencies({
  candidateSHA256,
  runIDSHA256,
  signal,
  runCommand: spawnSync,
  startAgentActivation: fixedAgentActivation,
  timeoutMilliseconds: UNARMED_CONTROL_TIMEOUT_MILLISECONDS,
  terminationGraceMilliseconds: UNARMED_CONTROL_TERMINATION_GRACE_MILLISECONDS,
  wait: waitFor
});

/**
 * Test seam only: it accepts process-boundary fakes, never caller-controlled
 * executable/path/argv/env values. The production entry point above has no
 * such seam.
 */
export const executeQualificationUnarmedControlForTest = (options = {}) => executeWithDependencies({
  candidateSHA256: options.candidateSHA256,
  runIDSHA256: options.runIDSHA256,
  signal: options.signal,
  runCommand: options.runCommand,
  startAgentActivation: options.startAgentActivation,
  timeoutMilliseconds: options.timeoutMilliseconds ?? 1000,
  terminationGraceMilliseconds: options.terminationGraceMilliseconds ?? 10,
  wait: options.wait ?? waitFor
});

export const runUnarmedControl = executeQualificationUnarmedControl;

if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
  process.stderr.write('qualification unarmed-control refused: fixed protected orchestration required\n');
  process.exitCode = 2;
}
