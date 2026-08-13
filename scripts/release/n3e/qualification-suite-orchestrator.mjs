#!/usr/bin/env node
import crypto from 'node:crypto';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  PROVISION_STATE_PATH,
  provisionQualificationConfig,
  restoreQualificationConfig
} from './provision-qualification-config.mjs';
import { materializeControllerCandidate, removeControllerCandidate } from './materialize-controller-candidate.mjs';
import {
  materializeQualificationActivation,
  removeQualificationActivation
} from './materialize-qualification-activation.mjs';
import { normalizeQualificationActivation } from './qualification-activation-contract.mjs';
import { canonicalFixedQualificationInput } from './qualification-input-materializer.mjs';
import {
  disarmQualification,
  executeQualification,
  proveQualificationListenerUnavailable
} from './qualification-scenario-driver.mjs';
import { executeQualificationUnarmedControl } from './qualification-unarmed-control.mjs';
import {
  FIXED_QUALIFICATION_APPLICATION_PATH,
  parseFixedQualificationInput,
  recoverFixedProtectedQualification
} from './run-fixed-protected-qualification.mjs';
import { restartNativeService, runProtectedQualification } from './run-protected-qualification.mjs';
import {
  FIXED_CANDIDATE_CHECKPOINT_PATH,
  resolveQualificationReleaseTrust
} from './qualification-release-trust.mjs';
import {
  materializeQualificationRunBinding,
  removeQualificationRunBinding
} from './qualification-run-binding.mjs';
import { withVerifiedCandidateCheckpoint } from '../p0c/lib/candidate-checkpoint.mjs';
import {
  QUALIFICATION_SUITE_INPUT_KIND,
  QUALIFICATION_SUITE_INPUT_PATH,
  QUALIFICATION_SUITE_SCENARIOS as INPUT_SUITE_SCENARIOS,
  QUALIFICATION_SUITE_STEPS as INPUT_SUITE_STEPS,
  consumeFixedQualificationSuiteInput
} from './qualification-suite-input.mjs';

export const QUALIFICATION_SUITE_SCHEMA_VERSION = 1;
export const QUALIFICATION_SUITE_KIND = 'agentpass-n3e-qualification-suite-evidence';
export const QUALIFICATION_SUITE_MAX_STEPS = 7;
export const QUALIFICATION_SUITE_STEP_TIMEOUT_MILLISECONDS = 15 * 60 * 1000;
export const QUALIFICATION_SUITE_ABORT_TIMEOUT_MILLISECONDS = 30 * 1000;
export { QUALIFICATION_SUITE_INPUT_KIND, QUALIFICATION_SUITE_INPUT_PATH };

const DIGEST = /^[0-9a-f]{64}$/u;
const ZERO_DIGEST = /^0+$/u;
const SAFE_STATUS = /^[a-z][a-z0-9_-]{0,63}$/u;
const SIGNAL_NAMES = Object.freeze(['SIGHUP', 'SIGINT', 'SIGTERM']);

export const QUALIFICATION_SUITE_SCENARIOS = INPUT_SUITE_SCENARIOS;
export const QUALIFICATION_SUITE_STEPS = INPUT_SUITE_STEPS;

const fail = (message) => { throw new Error(message); };

const isDigest = (value) => typeof value === 'string' && DIGEST.test(value) && !ZERO_DIGEST.test(value);

const exactKeys = (value, expected, label) => {
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail(`${label} is invalid`);
  const ownKeys = Reflect.ownKeys(value);
  if (ownKeys.some((key) => typeof key !== 'string')) fail(`${label} is not closed`);
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) fail(`${label} is not closed`);
  for (const key of expected) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || descriptor.enumerable !== true || !Object.hasOwn(descriptor, 'value')) fail(`${label} contains an accessor`);
  }
};

const sortedJSON = (value) => {
  if (Array.isArray(value)) return value.map(sortedJSON);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, sortedJSON(value[key])]));
  }
  return value;
};

export const canonicalQualificationSuiteJSON = (value) => Buffer.from(`${JSON.stringify(sortedJSON(value), null, 2)}\n`, 'utf8');

const rejectSecretMaterial = (value, path = '$') => {
  if (Array.isArray(value)) {
    value.forEach((item, index) => rejectSecretMaterial(item, `${path}[${index}]`));
    return;
  }
  if (value && typeof value === 'object') {
    for (const [key, child] of Object.entries(value)) {
      if (/(?:secret|token|password|private|credential|authorization|stdout|stderr|raw|proof|grant|output)/iu.test(key)) {
        fail(`${path}.${key} contains non-public material`);
      }
      rejectSecretMaterial(child, `${path}.${key}`);
    }
    return;
  }
  if (typeof value === 'string' && /(?:-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----|\bBearer\s+\S+|private[-_ ]?(?:key|token|credential))/iu.test(value)) {
    fail(`${path} contains non-public material`);
  }
};

const fixedStepAt = (index) => {
  if (!Number.isSafeInteger(index) || index < 0 || index >= QUALIFICATION_SUITE_STEPS.length) fail('qualification suite step index is invalid');
  return QUALIFICATION_SUITE_STEPS[index];
};

const normalizeExecutionResult = (value, label) => {
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail(`${label} is invalid`);
  exactKeys(value, ['evidence_sha256', 'ok', 'status'], label);
  if (value.ok !== true || value.status !== 'passed' || !isDigest(value.evidence_sha256)) fail(`${label} is invalid`);
  return Object.freeze({ ok: true, status: 'passed', evidence_sha256: value.evidence_sha256 });
};

const normalizeIdentity = (value, label) => {
  if (!isDigest(value)) fail(`${label} is invalid`);
  return value;
};

const normalizePublicRecord = (value, expectedStep, label = 'qualification suite evidence') => {
  exactKeys(value, ['candidate_sha256', 'evidence_sha256', 'kind', 'phase', 'run_id_sha256', 'scenario', 'status'], label);
  if (value.kind !== expectedStep.kind || value.scenario !== expectedStep.scenario || value.phase !== expectedStep.phase) fail(`${label} step identity is invalid`);
  if (value.status !== 'passed' || !isDigest(value.candidate_sha256) || !isDigest(value.run_id_sha256) || !isDigest(value.evidence_sha256)) fail(`${label} step is invalid`);
  return Object.freeze({
    candidate_sha256: value.candidate_sha256,
    evidence_sha256: value.evidence_sha256,
    kind: value.kind,
    phase: value.phase,
    run_id_sha256: value.run_id_sha256,
    scenario: value.scenario,
    status: 'passed'
  });
};

const publicRecord = (step, identity, execution) => normalizePublicRecord({
  candidate_sha256: identity.candidateSHA256,
  evidence_sha256: execution.evidence_sha256,
  kind: step.kind,
  phase: step.phase,
  run_id_sha256: identity.runIDSHA256,
  scenario: step.scenario,
  status: execution.status
}, step);

/**
 * Validate the only evidence shape that may enter suite aggregation. It is
 * intentionally a closed public projection: no command output, process
 * output, activation proof, path, or arbitrary metadata can be carried here.
 */
export const validateQualificationSuiteEvidence = (value) => {
  exactKeys(value, ['kind', 'schema_version', 'steps'], 'qualification suite evidence');
  if (value.schema_version !== QUALIFICATION_SUITE_SCHEMA_VERSION || value.kind !== QUALIFICATION_SUITE_KIND) fail('qualification suite evidence identity is invalid');
  if (!Array.isArray(value.steps) || value.steps.length !== QUALIFICATION_SUITE_MAX_STEPS) fail('qualification suite evidence step inventory is invalid');
  const steps = value.steps.map((step, index) => normalizePublicRecord(step, fixedStepAt(index), `qualification suite evidence step ${index}`));
  const scenarioNames = new Set();
  for (let index = 0; index < steps.length; index += 1) {
    const expected = fixedStepAt(index);
    const actual = steps[index];
    if (actual.kind !== expected.kind || actual.scenario !== expected.scenario || actual.phase !== expected.phase) fail('qualification suite evidence is missing, duplicated, or reordered');
    if (actual.kind === 'scenario') {
      if (scenarioNames.has(actual.scenario)) fail('qualification suite evidence contains a duplicate scenario');
      scenarioNames.add(actual.scenario);
    }
  }
  if (scenarioNames.size !== QUALIFICATION_SUITE_SCENARIOS.length) fail('qualification suite evidence is missing a scenario');
  const normalized = Object.freeze({
    kind: QUALIFICATION_SUITE_KIND,
    schema_version: QUALIFICATION_SUITE_SCHEMA_VERSION,
    steps: Object.freeze(steps)
  });
  rejectSecretMaterial(normalized);
  return normalized;
};

export const buildQualificationSuiteEvidence = ({ records } = {}) => {
  if (!Array.isArray(records) || records.length !== QUALIFICATION_SUITE_MAX_STEPS) fail('qualification suite evidence records are invalid');
  const evidence = {
    kind: QUALIFICATION_SUITE_KIND,
    schema_version: QUALIFICATION_SUITE_SCHEMA_VERSION,
    steps: records.map((record, index) => normalizePublicRecord(record, fixedStepAt(index), `qualification suite evidence record ${index}`))
  };
  return validateQualificationSuiteEvidence(evidence);
};

export const qualificationSuiteEvidenceSHA256 = (value) => {
  const evidence = validateQualificationSuiteEvidence(value);
  return crypto.createHash('sha256').update(canonicalQualificationSuiteJSON(evidence)).digest('hex');
};

export const aggregateQualificationSuiteEvidence = ({ records } = {}) => qualificationSuiteEvidenceSHA256(buildQualificationSuiteEvidence({ records }));

const suiteResult = (evidence) => Object.freeze({
  ok: true,
  status: 'passed',
  evidence_sha256: qualificationSuiteEvidenceSHA256(evidence)
});

const validSignal = (signal) => signal && typeof signal.aborted === 'boolean' && typeof signal.addEventListener === 'function' && typeof signal.removeEventListener === 'function';

const validateSuiteOptions = ({ candidateSHA256, runIDSHA256, signal }) => {
  normalizeIdentity(candidateSHA256, 'qualification suite candidate digest');
  normalizeIdentity(runIDSHA256, 'qualification suite run digest');
  if (!validSignal(signal)) fail('qualification suite abort signal is invalid');
};

const validateHandle = (value, label) => {
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail(`${label} handle is invalid`);
  exactKeys(value, ['completion', 'terminate'], `${label} handle`);
  if (typeof value.terminate !== 'function' || typeof value.completion?.then !== 'function') fail(`${label} handle is invalid`);
  return value;
};

const genericFailure = () => new Error('qualification suite execution failed');

const awaitBounded = async (promise, milliseconds, setTimer, clearTimer) => {
  let timer;
  try {
    return await Promise.race([
      Promise.resolve(promise),
      new Promise((_, reject) => { timer = setTimer(() => reject(genericFailure()), milliseconds); })
    ]);
  } finally {
    if (timer !== undefined) clearTimer(timer);
  }
};

const terminateBounded = async (handle, reason, milliseconds, setTimer, clearTimer) => {
  try {
    await awaitBounded(Promise.resolve().then(() => handle.terminate(reason)), milliseconds, setTimer, clearTimer);
  } catch {
    // The public error remains generic. The bound is the safety invariant.
  }
};

const runStepBounded = async ({ step, identity, signal, execute, stepTimeoutMilliseconds, abortTimeoutMilliseconds, setTimer, clearTimer }) => {
  if (signal.aborted) throw genericFailure();
  let handle;
  try {
    handle = validateHandle(await execute({
      candidateSHA256: identity.candidateSHA256,
      kind: step.kind,
      phase: step.phase,
      runIDSHA256: identity.runIDSHA256,
      scenario: step.scenario,
      signal
    }), `${step.kind}${step.scenario ? `:${step.scenario}` : ''}`);
  } catch {
    throw genericFailure();
  }

  let removeAbortListener = () => {};
  let timer;
  let abortReject;
  const aborted = new Promise((_, reject) => { abortReject = reject; });
  const abort = () => abortReject(genericFailure());
  signal.addEventListener('abort', abort, { once: true });
  removeAbortListener = () => signal.removeEventListener('abort', abort);
  try {
    const completion = Promise.resolve(handle.completion).then(
      (value) => normalizeExecutionResult(value, `${step.kind} execution result`),
      () => { throw genericFailure(); }
    );
    const timeout = new Promise((_, reject) => { timer = setTimer(() => reject(genericFailure()), stepTimeoutMilliseconds); });
    try {
      return await Promise.race([completion, timeout, aborted]);
    } catch (error) {
      await terminateBounded(handle, signal.aborted ? 'abort' : 'timeout', abortTimeoutMilliseconds, setTimer, clearTimer);
      throw genericFailure();
    }
  } finally {
    if (timer !== undefined) clearTimer(timer);
    removeAbortListener();
  }
};

const validateTestConfiguration = ({ executeUnarmedControl, executeScenario, stepTimeoutMilliseconds, abortTimeoutMilliseconds, setTimer, clearTimer }) => {
  if (typeof executeUnarmedControl !== 'function' || typeof executeScenario !== 'function') fail('qualification suite dependencies are invalid');
  if (!Number.isSafeInteger(stepTimeoutMilliseconds) || stepTimeoutMilliseconds < 1 || stepTimeoutMilliseconds > QUALIFICATION_SUITE_STEP_TIMEOUT_MILLISECONDS) fail('qualification suite step timeout is invalid');
  if (!Number.isSafeInteger(abortTimeoutMilliseconds) || abortTimeoutMilliseconds < 1 || abortTimeoutMilliseconds > QUALIFICATION_SUITE_ABORT_TIMEOUT_MILLISECONDS) fail('qualification suite abort timeout is invalid');
  if (typeof setTimer !== 'function' || typeof clearTimer !== 'function') fail('qualification suite timer dependencies are invalid');
};

const executeQualificationSuiteWithDependencies = async ({
  candidateSHA256,
  runIDSHA256,
  signal,
  executeUnarmedControl: executeControl,
  executeScenario: executeScenarioStep,
  stepTimeoutMilliseconds = QUALIFICATION_SUITE_STEP_TIMEOUT_MILLISECONDS,
  abortTimeoutMilliseconds = QUALIFICATION_SUITE_ABORT_TIMEOUT_MILLISECONDS,
  setTimer = setTimeout,
  clearTimer = clearTimeout
}) => {
  validateSuiteOptions({ candidateSHA256, runIDSHA256, signal });
  validateTestConfiguration({
    executeUnarmedControl: executeControl,
    executeScenario: executeScenarioStep,
    stepTimeoutMilliseconds,
    abortTimeoutMilliseconds,
    setTimer,
    clearTimer
  });

  const records = [];
  const identity = { candidateSHA256, runIDSHA256 };
  for (const step of QUALIFICATION_SUITE_STEPS) {
    const execution = await runStepBounded({
      step,
      identity,
      signal,
      execute: step.kind === 'unarmed-control' ? executeControl : executeScenarioStep,
      stepTimeoutMilliseconds,
      abortTimeoutMilliseconds,
      setTimer,
      clearTimer
    });
    records.push(publicRecord(step, identity, execution));
  }
  return suiteResult(buildQualificationSuiteEvidence({ records }));
};

/** Test seam: only process-boundary execution functions are injectable. */
export const executeQualificationSuiteForTest = (options = {}) => executeQualificationSuiteWithDependencies(options);
export const runQualificationSuiteForTest = executeQualificationSuiteForTest;

const fixedRunOptions = ({ provisionOptions, activation, executeStep, captureProvision }) => ({
  provisionOptions,
  provision: () => {
    const result = provisionQualificationConfig(provisionOptions);
    captureProvision(result);
    return result;
  },
  materializeCandidate: () => materializeControllerCandidate(),
  removeCandidate: ({ materialization } = {}) => removeControllerCandidate({
    expected: {
      manifest_sha256: materialization?.manifest_sha256,
      signature_sha256: materialization?.signature_sha256,
      public_key_sha256: materialization?.public_key_sha256
    }
  }),
  materializeActivation: () => materializeQualificationActivation({ activation }),
  removeActivation: ({ materialization } = {}) => removeQualificationActivation({ expected: materialization }),
  executeQualification: executeStep,
  disarmQualification: () => disarmQualification(),
  proveListenerUnavailable: () => proveQualificationListenerUnavailable() === true,
  restore: () => restoreQualificationConfig(),
  restart: () => restartNativeService(),
  statePath: PROVISION_STATE_PATH
});

const runFixedStep = async ({ stepInput, step }) => {
  const suiteInput = parseFixedQualificationInput(canonicalFixedQualificationInput(stepInput));
  return withVerifiedCandidateCheckpoint(FIXED_CANDIDATE_CHECKPOINT_PATH, async (checkpoint) => {
    const trusted = resolveQualificationReleaseTrust({ checkpoint });
    const runBinding = materializeQualificationRunBinding({ value: suiteInput.provisionRequest.runBinding });
    const provisionOptions = Object.freeze({
      manifestPath: trusted.manifestPath,
      signaturePath: trusted.signaturePath,
      publicKeyPath: trusted.publicKeyPath,
      expectedFingerprint: trusted.expectedFingerprint,
      productPath: trusted.productPath,
      runBindingPath: trusted.runBindingPath,
      expectedArtifactSha256: trusted.expectedArtifactSha256,
      expectedSourceCommit: trusted.expectedSourceCommit,
      expectedTeamId: trusted.expectedTeamId,
      ...suiteInput.provisionRequest,
      scenario: step.kind === 'unarmed-control' ? QUALIFICATION_SUITE_SCENARIOS[0].scenario : step.scenario
    });
    let binding;
    let result;
    try {
      result = await runProtectedQualification(fixedRunOptions({
        provisionOptions,
        activation: normalizeQualificationActivation(suiteInput.activation),
        captureProvision: (provisionResult) => { binding = Object.freeze({ candidateSHA256: provisionResult.candidate_sha256, runIDSHA256: provisionResult.run_id_sha256 }); },
        executeStep: (input) => {
          if (step.kind === 'unarmed-control') return executeQualificationUnarmedControl({
            candidateSHA256: input.candidateSHA256,
            runIDSHA256: input.runIDSHA256,
            signal: input.signal
          });
          return executeQualification(input);
        }
      }));
    } finally {
      removeQualificationRunBinding({ expected: runBinding });
    }
    if (!binding || !result?.execution) fail('qualification suite binding was not produced');
    return publicRecord(step, binding, normalizeExecutionResult(result.execution, 'qualification suite execution result'));
  }, { expected: { applicationPath: FIXED_QUALIFICATION_APPLICATION_PATH }, production: true });
};

const productionIdentity = () => {
  if (process.platform !== 'darwin' || typeof process.getuid !== 'function' || process.getuid() !== 0) fail('fixed protected qualification suite requires root on macOS');
};

/**
 * Production composition. It has no caller-supplied paths, identities,
 * commands, or callbacks; the one-shot root input is consumed by the fixed
 * protected lifecycle and every step is executed in the closed order above.
 */
export const runFixedProtectedQualificationSuite = async (...args) => {
  if (args.length !== 0) fail('fixed protected qualification suite refuses caller-provided arguments');
  productionIdentity();
  const suiteInput = consumeFixedQualificationSuiteInput();
  const records = [];
  try {
    for (let index = 0; index < QUALIFICATION_SUITE_STEPS.length; index += 1) {
      records.push(await runFixedStep({ stepInput: suiteInput.steps[index].input, step: QUALIFICATION_SUITE_STEPS[index] }));
    }
    return suiteResult(buildQualificationSuiteEvidence({ records }));
  } catch {
    try { recoverFixedProtectedQualification(); } catch { /* keep the public failure generic */ }
    throw genericFailure();
  }
};

export const executeQualificationSuite = runFixedProtectedQualificationSuite;
export const runQualificationSuite = runFixedProtectedQualificationSuite;

export const recoverFixedProtectedQualificationSuite = (...args) => {
  if (args.length !== 0) fail('fixed protected qualification suite recovery refuses caller-provided arguments');
  productionIdentity();
  return recoverFixedProtectedQualification();
};

export const parseQualificationSuiteCLI = (args) => {
  if (!Array.isArray(args) || args.length !== 1 || !['recover', 'run'].includes(args[0])) fail('usage: qualification-suite-orchestrator.mjs run | recover');
  return Object.freeze({ operation: args[0] });
};

const safeCLIError = (error) => error?.message === 'usage: qualification-suite-orchestrator.mjs run | recover'
  ? error.message
  : 'fixed protected qualification suite was refused';

if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
  try {
    const { operation } = parseQualificationSuiteCLI(process.argv.slice(2));
    const result = operation === 'run' ? await runFixedProtectedQualificationSuite() : recoverFixedProtectedQualificationSuite();
    process.stdout.write(`${JSON.stringify(result)}\n`);
  } catch (error) {
    process.stderr.write(`${safeCLIError(error)}\n`);
    process.exitCode = 2;
  }
}
