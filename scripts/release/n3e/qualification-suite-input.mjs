import crypto from 'node:crypto';
import fs from 'node:fs';
import { dirname, resolve } from 'node:path';

import {
  FIXED_INPUT_KIND,
  FIXED_INPUT_SCHEMA_VERSION,
  FIXED_QUALIFICATION_INPUT_PATH,
  parseFixedQualificationInput
} from './run-fixed-protected-qualification.mjs';
import { SCENARIO_PHASE } from './provision-qualification-config.mjs';

export const QUALIFICATION_SUITE_INPUT_SCHEMA_VERSION = 1;
export const QUALIFICATION_SUITE_INPUT_KIND = 'agentpass-n3e-fixed-protected-qualification-suite-input';
export const QUALIFICATION_SUITE_INPUT_MAX_BYTES = 64 * 1024;
export const QUALIFICATION_SUITE_INPUT_PATH = FIXED_QUALIFICATION_INPUT_PATH;
export const QUALIFICATION_SUITE_INBOX_PATH = '/private/var/db/agentpass-qualification/input.inbox.json';

const INPUT_KEYS = Object.freeze(['activation', 'kind', 'provision', 'schema_version']);
const PROVISION_KEYS = Object.freeze(['expires_at_epoch_seconds', 'run_binding', 'scenario']);
const SUITE_KEYS = Object.freeze(['kind', 'schema_version', 'steps']);
const STEP_KEYS = Object.freeze(['input', 'kind', 'phase', 'scenario']);
const RUN_BINDING = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;
const NOFOLLOW = fs.constants.O_NOFOLLOW;
const O_DIRECTORY = fs.constants.O_DIRECTORY ?? 0;

export const QUALIFICATION_SUITE_SCENARIOS = Object.freeze(Object.entries(SCENARIO_PHASE).map(([scenario, phase]) => Object.freeze({ scenario, phase })));
export const QUALIFICATION_SUITE_STEPS = Object.freeze([
  Object.freeze({ kind: 'unarmed-control', scenario: null, phase: null }),
  ...QUALIFICATION_SUITE_SCENARIOS.map(({ scenario, phase }) => Object.freeze({ kind: 'scenario', scenario, phase }))
]);

const fail = (message) => { throw new Error(message); };
const exactKeys = (value, keys, label) => {
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail(`${label} is invalid`);
  const actual = Object.keys(value).sort(); const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) fail(`${label} is not closed`);
};
const sorted = (value) => Array.isArray(value) ? value.map(sorted) : value && typeof value === 'object' ? Object.fromEntries(Object.keys(value).sort().map((key) => [key, sorted(value[key])])) : value;
const canonical = (value) => Buffer.from(`${JSON.stringify(sorted(value), null, 2)}\n`, 'utf8');

const normalizeSingleInput = (value, expectedScenario) => {
  exactKeys(value, INPUT_KEYS, 'qualification suite step input');
  exactKeys(value.provision, PROVISION_KEYS, 'qualification suite provision input');
  if (value.schema_version !== FIXED_INPUT_SCHEMA_VERSION || value.kind !== FIXED_INPUT_KIND || value.provision.scenario !== expectedScenario || !RUN_BINDING.test(value.provision.run_binding)) fail('qualification suite step input binding is invalid');
  const parsed = parseFixedQualificationInput(canonical(value));
  return Object.freeze({
    document: Object.freeze({
      schema_version: FIXED_INPUT_SCHEMA_VERSION,
      kind: FIXED_INPUT_KIND,
      provision: Object.freeze({
        scenario: parsed.provisionRequest.scenario,
        expires_at_epoch_seconds: parsed.provisionRequest.expiresAtEpochSeconds,
        run_binding: parsed.provisionRequest.runBinding
      }),
      activation: parsed.activation
    }),
    parsed
  });
};

export const normalizeQualificationSuiteInput = (value) => {
  exactKeys(value, SUITE_KEYS, 'qualification suite input');
  if (value.schema_version !== QUALIFICATION_SUITE_INPUT_SCHEMA_VERSION || value.kind !== QUALIFICATION_SUITE_INPUT_KIND || !Array.isArray(value.steps) || value.steps.length !== QUALIFICATION_SUITE_STEPS.length) fail('qualification suite input identity is invalid');
  const runBindings = new Set();
  const proofDigests = new Set();
  const steps = value.steps.map((step, index) => {
    const expected = QUALIFICATION_SUITE_STEPS[index];
    exactKeys(step, STEP_KEYS, `qualification suite step ${index}`);
    if (step.kind !== expected.kind || step.scenario !== expected.scenario || step.phase !== expected.phase) fail('qualification suite steps are missing, duplicated, or reordered');
    const configuredScenario = expected.kind === 'unarmed-control' ? QUALIFICATION_SUITE_SCENARIOS[0].scenario : expected.scenario;
    const normalized = normalizeSingleInput(step.input, configuredScenario);
    if (runBindings.has(normalized.parsed.provisionRequest.runBinding)) fail('qualification suite run binding is reused');
    const proofDigest = crypto.createHash('sha256').update(normalized.parsed.activation.proof, 'utf8').digest('hex');
    if (proofDigests.has(proofDigest)) fail('qualification suite Grant proof is reused');
    runBindings.add(normalized.parsed.provisionRequest.runBinding);
    proofDigests.add(proofDigest);
    return Object.freeze({ kind: expected.kind, scenario: expected.scenario, phase: expected.phase, input: normalized.document });
  });
  return Object.freeze({ schema_version: QUALIFICATION_SUITE_INPUT_SCHEMA_VERSION, kind: QUALIFICATION_SUITE_INPUT_KIND, steps: Object.freeze(steps) });
};

export const canonicalQualificationSuiteInput = (value) => {
  const bytes = canonical(normalizeQualificationSuiteInput(value));
  if (bytes.length === 0 || bytes.length > QUALIFICATION_SUITE_INPUT_MAX_BYTES) fail('qualification suite input exceeds its size limit');
  return bytes;
};

export const parseQualificationSuiteInput = (bytes) => {
  if (!Buffer.isBuffer(bytes) || bytes.length === 0 || bytes.length > QUALIFICATION_SUITE_INPUT_MAX_BYTES) fail('qualification suite input document is invalid');
  let value;
  try { value = JSON.parse(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes)); } catch { fail('qualification suite input document is invalid'); }
  const normalized = normalizeQualificationSuiteInput(value);
  if (!bytes.equals(canonical(normalized))) fail('qualification suite input is not canonical');
  return normalized;
};

const identity = (stat) => [stat.dev, stat.ino, stat.mode, stat.nlink, stat.size, stat.mtimeNs, stat.ctimeNs, stat.uid, stat.gid].map(String).join(':');
const verifyParents = (path, fileSystem, expectedUid, production) => {
  let current = dirname(path);
  for (;;) {
    const stat = fileSystem.lstatSync(current, { bigint: true });
    if (!stat.isDirectory() || stat.isSymbolicLink() || (stat.mode & 0o022n) !== 0n || stat.uid !== BigInt(expectedUid) || (current === dirname(path) && (stat.mode & 0o7777n) !== 0o700n)) fail('qualification suite input parent is unsafe');
    if (!production || current === '/') break;
    current = resolve(current, '..');
  }
};

const consumeProtectedSuiteInput = ({ fileSystem = fs, inputPath, productionPath, expectedUid = 0, platform = process.platform, uid = process.getuid?.(), production = true } = {}) => {
  if (production && (platform !== 'darwin' || uid !== 0 || expectedUid !== 0 || inputPath !== productionPath || fileSystem !== fs)) fail('qualification suite input requires root on macOS and the fixed path');
  if (!production && uid !== expectedUid) fail('qualification suite input requires the expected owner');
  verifyParents(inputPath, fileSystem, expectedUid, production);
  let descriptor;
  try { descriptor = fileSystem.openSync(inputPath, fileSystem.constants.O_RDONLY | NOFOLLOW); } catch { fail('qualification suite input is unavailable'); }
  try {
    const before = fileSystem.fstatSync(descriptor, { bigint: true });
    if (!before.isFile() || before.nlink !== 1n || before.uid !== BigInt(expectedUid) || (before.mode & 0o7777n) !== 0o600n || before.size <= 0n || before.size > BigInt(QUALIFICATION_SUITE_INPUT_MAX_BYTES)) fail('qualification suite input is unsafe');
    const bytes = Buffer.alloc(Number(before.size)); let offset = 0;
    while (offset < bytes.length) { const count = fileSystem.readSync(descriptor, bytes, offset, bytes.length - offset, offset); if (count <= 0) fail('qualification suite input changed while reading'); offset += count; }
    const after = fileSystem.fstatSync(descriptor, { bigint: true }); const current = fileSystem.lstatSync(inputPath, { bigint: true });
    if (identity(before) !== identity(after) || identity(after) !== identity(current)) fail('qualification suite input changed while reading');
    const parsed = parseQualificationSuiteInput(bytes);
    const beforeUnlink = fileSystem.lstatSync(inputPath, { bigint: true });
    if (identity(before) !== identity(beforeUnlink)) fail('qualification suite input changed before consumption');
    fileSystem.unlinkSync(inputPath);
    const parent = fileSystem.openSync(dirname(inputPath), fileSystem.constants.O_RDONLY | O_DIRECTORY | NOFOLLOW);
    try { fileSystem.fsyncSync(parent); } finally { fileSystem.closeSync(parent); }
    return parsed;
  } finally { fileSystem.closeSync(descriptor); }
};

export const consumeFixedQualificationSuiteInput = (options = {}) => consumeProtectedSuiteInput({ inputPath: QUALIFICATION_SUITE_INPUT_PATH, productionPath: QUALIFICATION_SUITE_INPUT_PATH, ...options });
export const consumeFixedQualificationSuiteInbox = (options = {}) => consumeProtectedSuiteInput({ inputPath: QUALIFICATION_SUITE_INBOX_PATH, productionPath: QUALIFICATION_SUITE_INBOX_PATH, ...options });
