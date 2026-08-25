#!/usr/bin/env node
import fs from 'node:fs';
import { dirname, isAbsolute, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  PROVISION_STATE_PATH,
  SCENARIO_PHASE,
  provisionQualificationConfig,
  restoreQualificationConfig
} from './provision-qualification-config.mjs';
import {
  CONTROLLER_CANDIDATE_DIRECTORY,
  materializeControllerCandidate,
  removeControllerCandidate
} from './materialize-controller-candidate.mjs';
import {
  QUALIFICATION_ACTIVATION_DIRECTORY,
  materializeQualificationActivation,
  removeQualificationActivation
} from './materialize-qualification-activation.mjs';
import {
  normalizeQualificationActivation
} from './qualification-activation-contract.mjs';
import * as qualificationScenarioDriver from './qualification-scenario-driver.mjs';
import {
  disarmQualification as disarmQualificationScenario,
  executeQualification as executeQualificationScenario,
  proveQualificationListenerUnavailable
} from './qualification-scenario-driver.mjs';
import {
  recoverProtectedQualification,
  restartNativeService,
  runProtectedQualification
} from './run-protected-qualification.mjs';
import {
  FIXED_CANDIDATE_CHECKPOINT_PATH,
  resolveQualificationReleaseTrust
} from './qualification-release-trust.mjs';
import { withVerifiedCandidateCheckpoint } from '../p0c/lib/candidate-checkpoint.mjs';
import {
  materializeQualificationRunBinding,
  recoverQualificationRunBinding,
  removeQualificationRunBinding
} from './qualification-run-binding.mjs';

export const FIXED_QUALIFICATION_INPUT_PATH = '/private/var/db/agentpass-qualification/input.json';
export const FIXED_QUALIFICATION_APPLICATION_PATH = '/Applications/AgentPass.app';
export const QUALIFICATION_INPUT_DOCUMENT_PATH = FIXED_QUALIFICATION_INPUT_PATH;
export const FIXED_INPUT_DOCUMENT_PATH = FIXED_QUALIFICATION_INPUT_PATH;
export const FIXED_INPUT_SCHEMA_VERSION = 1;
export const FIXED_INPUT_KIND = 'agentpass-n3e-fixed-protected-qualification-input';
export const FIXED_INPUT_MAX_BYTES = 64 * 1024;

export const FIXED_DEPENDENCY_KEYS = Object.freeze([
  'disarmQualification',
  'executeQualification',
  'materializeControllerCandidate',
  'materializeQualificationActivation',
  'materializeQualificationRunBinding',
  'proveNoQualificationProcesses',
  'proveQualificationListenerUnavailable',
  'provisionQualificationConfig',
  'recoverProtectedQualification',
  'recoverQualificationRunBinding',
  'resolveQualificationReleaseTrust',
  'removeControllerCandidate',
  'removeQualificationActivation',
  'removeQualificationRunBinding',
  'restartNativeService',
  'restoreQualificationConfig',
  'runProtectedQualification',
  'withVerifiedCandidateCheckpoint'
]);

const PROVISION_INPUT_KEYS = Object.freeze([
  'expires_at_epoch_seconds',
  'run_binding',
  'scenario'
]);
const INPUT_KEYS = Object.freeze(['activation', 'kind', 'provision', 'schema_version']);
const NOFOLLOW = fs.constants.O_NOFOLLOW;
const UINT32_MAX = 0xffff_ffff;
const RUN_BINDING = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;

const fail = (message) => { throw new Error(message); };

const exactKeys = (value, expected, label) => {
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail(`${label} is invalid`);
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) fail(`${label} is not closed`);
};

const sortedJSONValue = (value) => {
  if (Array.isArray(value)) return value.map(sortedJSONValue);
  if (value && typeof value === 'object') return Object.fromEntries(Object.keys(value).sort().map((key) => [key, sortedJSONValue(value[key])]));
  return value;
};

const canonicalInput = (value) => Buffer.from(`${JSON.stringify(sortedJSONValue(value), null, 2)}\n`, 'utf8');

const absolutePath = (value, label) => {
  if (typeof value !== 'string' || value.length === 0 || value.includes('\0') || !isAbsolute(value) || resolve(value) !== value) fail(`${label} is invalid`);
  return value;
};

export const parseFixedQualificationInput = (bytes) => {
  if (!Buffer.isBuffer(bytes) || bytes.length === 0 || bytes.length > FIXED_INPUT_MAX_BYTES) fail('qualification input document is invalid');
  let value;
  try {
    value = JSON.parse(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes));
  } catch {
    fail('qualification input document is invalid');
  }
  exactKeys(value, INPUT_KEYS, 'qualification input document');
  if (value.schema_version !== FIXED_INPUT_SCHEMA_VERSION || value.kind !== FIXED_INPUT_KIND || !bytes.equals(canonicalInput(value))) fail('qualification input document is not canonical');

  exactKeys(value.provision, PROVISION_INPUT_KEYS, 'qualification provision input');
  const provisionRequest = {
    scenario: value.provision.scenario,
    expiresAtEpochSeconds: value.provision.expires_at_epoch_seconds,
    runBinding: value.provision.run_binding
  };
  if (!Object.hasOwn(SCENARIO_PHASE, provisionRequest.scenario)) fail('qualification scenario is invalid');
  if (!Number.isSafeInteger(provisionRequest.expiresAtEpochSeconds) || provisionRequest.expiresAtEpochSeconds <= 0) fail('qualification expiry is invalid');
  if (!RUN_BINDING.test(provisionRequest.runBinding)) fail('qualification run binding is invalid');

  let activation;
  try { activation = normalizeQualificationActivation(value.activation); } catch { fail('qualification activation input is invalid'); }
  return Object.freeze({ provisionRequest: Object.freeze(provisionRequest), activation });
};

const statIdentity = (stat) => [stat.dev, stat.ino, stat.mode, stat.nlink, stat.size, stat.mtimeNs, stat.ctimeNs, stat.uid, stat.gid].map(String).join(':');

const verifyInputParents = (inputPath, fileSystem, expectedUid, production) => {
  let current = dirname(inputPath);
  for (;;) {
    let stat;
    try { stat = fileSystem.lstatSync(current, { bigint: true }); } catch { fail('qualification input parent is unavailable'); }
    if (!stat.isDirectory() || stat.isSymbolicLink() || (stat.mode & 0o022n) !== 0n || (production && stat.uid !== BigInt(expectedUid)) || (production && current === dirname(inputPath) && (stat.mode & 0o7777n) !== 0o700n)) fail('qualification input parent is unsafe');
    if (!production && current !== dirname(inputPath) && stat.uid !== BigInt(expectedUid)) break;
    if (current === '/') break;
    current = resolve(current, '..');
    if (!production) break;
  }
};

const syncInputParent = (inputPath, fileSystem) => {
  let descriptor;
  try {
    descriptor = fileSystem.openSync(dirname(inputPath), fileSystem.constants.O_RDONLY | (fileSystem.constants.O_DIRECTORY ?? 0) | NOFOLLOW);
    fileSystem.fsyncSync(descriptor);
  } catch {
    fail('qualification input parent sync failed');
  } finally {
    if (descriptor !== undefined) {
      try { fileSystem.closeSync(descriptor); } catch { fail('qualification input parent sync failed'); }
    }
  }
};

const unlinkStableInput = (inputPath, { fileSystem, expectedUid, production, allowAbsent }) => {
  if (!Number.isInteger(NOFOLLOW)) fail('qualification input requires O_NOFOLLOW');
  verifyInputParents(inputPath, fileSystem, expectedUid, production);
  let descriptor;
  try { descriptor = fileSystem.openSync(inputPath, fileSystem.constants.O_RDONLY | NOFOLLOW); }
  catch (error) {
    if (allowAbsent && error?.code === 'ENOENT') return Object.freeze({ ok: true, action: 'absent' });
    fail('qualification input document is unavailable');
  }
  try {
    const before = fileSystem.fstatSync(descriptor, { bigint: true });
    if (!before.isFile() || before.nlink !== 1n || before.uid !== BigInt(expectedUid) || (before.mode & 0o7777n) !== 0o600n || before.size <= 0n || before.size > BigInt(FIXED_INPUT_MAX_BYTES)) fail('qualification input document is unsafe');
    const current = fileSystem.lstatSync(inputPath, { bigint: true });
    if (statIdentity(before) !== statIdentity(current)) fail('qualification input document changed before cleanup');
    const beforeUnlink = fileSystem.lstatSync(inputPath, { bigint: true });
    if (statIdentity(before) !== statIdentity(beforeUnlink)) fail('qualification input document changed before cleanup');
    try { fileSystem.unlinkSync(inputPath); } catch { fail('qualification input document cleanup failed'); }
    syncInputParent(inputPath, fileSystem);
    return Object.freeze({ ok: true, action: 'removed' });
  } finally { fileSystem.closeSync(descriptor); }
};

const consumeStableInput = (inputPath, { fileSystem, expectedUid, production }) => {
  if (!Number.isInteger(NOFOLLOW)) fail('qualification input requires O_NOFOLLOW');
  verifyInputParents(inputPath, fileSystem, expectedUid, production);
  let descriptor;
  try { descriptor = fileSystem.openSync(inputPath, fileSystem.constants.O_RDONLY | NOFOLLOW); }
  catch { fail('qualification input document is unavailable'); }
  try {
    const before = fileSystem.fstatSync(descriptor, { bigint: true });
    if (!before.isFile() || before.nlink !== 1n || before.uid !== BigInt(expectedUid) || (before.mode & 0o7777n) !== 0o600n || before.size <= 0n || before.size > BigInt(FIXED_INPUT_MAX_BYTES)) fail('qualification input document is unsafe');
    const bytes = Buffer.alloc(Number(before.size));
    let offset = 0;
    while (offset < bytes.length) {
      const count = fileSystem.readSync(descriptor, bytes, offset, bytes.length - offset, offset);
      if (count <= 0) fail('qualification input document changed while reading');
      offset += count;
    }
    const after = fileSystem.fstatSync(descriptor, { bigint: true });
    const current = fileSystem.lstatSync(inputPath, { bigint: true });
    if (statIdentity(before) !== statIdentity(after) || statIdentity(after) !== statIdentity(current)) fail('qualification input document changed while reading');
    const parsed = parseFixedQualificationInput(bytes);
    const beforeUnlink = fileSystem.lstatSync(inputPath, { bigint: true });
    if (statIdentity(before) !== statIdentity(beforeUnlink)) fail('qualification input document changed before consumption');
    try { fileSystem.unlinkSync(inputPath); } catch { fail('qualification input document consumption failed'); }
    syncInputParent(inputPath, fileSystem);
    return parsed;
  } finally { fileSystem.closeSync(descriptor); }
};

export const consumeFixedQualificationInput = ({
  fileSystem = fs,
  inputPath = FIXED_QUALIFICATION_INPUT_PATH,
  expectedUid = 0,
  platform = process.platform,
  uid = process.getuid?.(),
  production = true
} = {}) => {
  if (production && (platform !== 'darwin' || uid !== 0 || expectedUid !== 0 || inputPath !== FIXED_QUALIFICATION_INPUT_PATH)) fail('qualification input requires root on macOS and the fixed path');
  if (!production && uid !== expectedUid) fail('qualification input requires the expected owner');
  absolutePath(inputPath, 'qualification input document');
  return consumeStableInput(inputPath, { fileSystem, expectedUid, production });
};

export const recoverFixedQualificationInput = ({
  fileSystem = fs,
  inputPath = FIXED_QUALIFICATION_INPUT_PATH,
  expectedUid = 0,
  platform = process.platform,
  uid = process.getuid?.(),
  production = true,
  proveNoActiveRun
} = {}) => {
  if (production && (platform !== 'darwin' || uid !== 0 || expectedUid !== 0 || inputPath !== FIXED_QUALIFICATION_INPUT_PATH)) fail('qualification input recovery requires root on macOS and the fixed path');
  if (!production && uid !== expectedUid) fail('qualification input recovery requires the expected owner');
  if (typeof proveNoActiveRun !== 'function' || proveNoActiveRun() !== true) fail('qualification input recovery refused an active run');
  absolutePath(inputPath, 'qualification input document');
  return unlinkStableInput(inputPath, { fileSystem, expectedUid, production, allowAbsent: true });
};

export const parseFixedQualificationCLI = (args) => {
  if (!Array.isArray(args) || args.length !== 1 || !['recover', 'run'].includes(args[0])) fail('usage: run-fixed-protected-qualification.mjs run | recover');
  return Object.freeze({ operation: args[0] });
};

const rejectCallerDependencies = (args, label) => {
  if (args.length !== 0) fail(`${label} refuses caller-provided dependencies`);
};

const productionIdentity = () => {
  if (process.platform !== 'darwin' || typeof process.getuid !== 'function' || process.getuid() !== 0) fail('protected qualification requires root on macOS');
};

const fixedListenerUnavailable = () => proveQualificationListenerUnavailable() === true;

const fixedNoActiveProof = () => {
  if (typeof qualificationScenarioDriver.proveNoQualificationProcesses !== 'function') fail('fixed qualification process proof is unavailable');
  if (qualificationScenarioDriver.proveNoQualificationProcesses() !== true) fail('fixed qualification recovery proof failed');
  return true;
};

const makeRunOptions = ({ provisionOptions, activation }) => ({
  provisionOptions,
  provision: () => provisionQualificationConfig(provisionOptions),
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
  executeQualification: (input) => executeQualificationScenario(input),
  disarmQualification: () => disarmQualificationScenario(),
  proveListenerUnavailable: fixedListenerUnavailable,
  restore: () => restoreQualificationConfig(),
  restart: () => restartNativeService(),
  statePath: PROVISION_STATE_PATH
});

const makeRecoveryOptions = () => ({
  recoverCandidate: () => removeControllerCandidate({ recovery: true, proveNoActiveController: fixedNoActiveProof }),
  recoverActivation: () => removeQualificationActivation({ recovery: true, proveNoActiveAgent: fixedNoActiveProof }),
  proveListenerUnavailable: fixedListenerUnavailable,
  proveNoActiveRun: fixedNoActiveProof,
  restore: () => restoreQualificationConfig(),
  restart: () => restartNativeService(),
  statePath: PROVISION_STATE_PATH
});

export const runFixedProtectedQualification = async (...args) => {
  rejectCallerDependencies(args, 'fixed protected qualification');
  productionIdentity();
  const input = consumeFixedQualificationInput();
  return withVerifiedCandidateCheckpoint(FIXED_CANDIDATE_CHECKPOINT_PATH, async (checkpoint) => {
    const trusted = resolveQualificationReleaseTrust({ checkpoint });
    const runBinding = materializeQualificationRunBinding({ value: input.provisionRequest.runBinding });
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
      ...input.provisionRequest
    });
    try {
      return await runProtectedQualification(makeRunOptions({ provisionOptions, activation: input.activation }));
    } finally {
      removeQualificationRunBinding({ expected: runBinding });
    }
  }, { expected: { applicationPath: FIXED_QUALIFICATION_APPLICATION_PATH }, production: true });
};

export const recoverFixedProtectedQualification = (...args) => {
  rejectCallerDependencies(args, 'fixed protected qualification recovery');
  productionIdentity();
  recoverFixedQualificationInput({ proveNoActiveRun: fixedNoActiveProof });
  recoverQualificationRunBinding({ proveNoActiveRun: fixedNoActiveProof });
  return recoverProtectedQualification(makeRecoveryOptions());
};

const safeCLIError = (error) => {
  if (error?.message === 'usage: run-fixed-protected-qualification.mjs run | recover') return error.message;
  return 'fixed protected qualification was refused';
};

if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
  try {
    const { operation } = parseFixedQualificationCLI(process.argv.slice(2));
    const result = operation === 'run' ? await runFixedProtectedQualification() : recoverFixedProtectedQualification();
    process.stdout.write(`${JSON.stringify(result)}\n`);
  } catch (error) {
    process.stderr.write(`${safeCLIError(error)}\n`);
    process.exitCode = 2;
  }
}
