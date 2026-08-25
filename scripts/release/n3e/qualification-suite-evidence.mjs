#!/usr/bin/env node
import crypto from 'node:crypto';

/**
 * Additive, secret-free evidence projection for the fixed N3-E qualification
 * suite.  This module deliberately does not import the historical N3-E report
 * schema or the suite runner: the projection is a separate trust boundary.
 */

export const QUALIFICATION_SUITE_EVIDENCE_SCHEMA_VERSION = 1;
export const QUALIFICATION_SUITE_EVIDENCE_KIND = 'agentpass-n3e-qualification-suite-evidence';
export const QUALIFICATION_SUITE_EVIDENCE_MAX_BYTES = 64 * 1024;
export const QUALIFICATION_SUITE_EVIDENCE_MAX_WINDOW_MILLISECONDS = 2 * 60 * 60 * 1000;

export const QUALIFICATION_SUITE_EVIDENCE_SCENARIOS = Object.freeze([
  Object.freeze({ scenario: 'pre-cloud-kill', phase: 'pre-cloud' }),
  Object.freeze({ scenario: 'post-cloud-pre-local-kill', phase: 'post-cloud-pre-local' }),
  Object.freeze({ scenario: 'post-activation-pre-audit-kill', phase: 'post-activation-pre-audit' }),
  Object.freeze({ scenario: 'post-audit-pre-reply-loss', phase: 'post-audit-pre-reply' }),
  Object.freeze({ scenario: 'audit-fsync-failure', phase: 'audit-fsync' }),
  Object.freeze({ scenario: 'transport-reply-loss', phase: 'transport-reply' })
]);

export const QUALIFICATION_SUITE_EVIDENCE_STEPS = Object.freeze([
  Object.freeze({ kind: 'unarmed-control', scenario: null, phase: null }),
  ...QUALIFICATION_SUITE_EVIDENCE_SCENARIOS.map(({ scenario, phase }) => Object.freeze({ kind: 'scenario', scenario, phase }))
]);

export const QUALIFICATION_SUITE_EVIDENCE_KEYS = Object.freeze([
  'artifact_sha256',
  'candidate_checkpoint_sha256',
  'completed_at',
  'kind',
  'lane_class',
  'release_trust_sha256',
  'schema_version',
  'source_commit',
  'started_at',
  'steps',
  'suite_input_sha256',
  'team_id',
  'teardown_proof_sha256'
]);

export const QUALIFICATION_SUITE_EVIDENCE_STEP_KEYS = Object.freeze([
  'evidence_sha256',
  'kind',
  'phase',
  'scenario',
  'status'
]);

const DIGEST = /^[0-9a-f]{64}$/u;
const COMMIT = /^[0-9a-f]{40}$/u;
const TEAM_ID = /^[A-Z0-9]{10}$/u;
const TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u;
const LANE_CLASSES = Object.freeze(['apple_silicon', 'intel_t2']);
const ZERO_DIGEST = '0'.repeat(64);
const ZERO_COMMIT = '0'.repeat(40);
const SECRET_VALUE = /(?:-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----|\bBearer\s+\S+|\b(?:sk|ghp|github_pat|xox[baprs])_[A-Za-z0-9_-]{8,}|\bprivate[-_ ]?(?:key|token|credential)\b)/iu;

const fail = (message) => { throw new Error(message); };

const isRecord = (value) => {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
};

const exactKeys = (value, expected, label) => {
  if (!isRecord(value)) fail(`${label} is invalid`);
  const expectedSet = new Set(expected);
  const ownKeys = Reflect.ownKeys(value);
  if (ownKeys.some((key) => typeof key !== 'string' || !expectedSet.has(key)) || ownKeys.length !== expected.length) {
    fail(`${label} is not closed`);
  }
  for (const key of expected) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || descriptor.enumerable !== true || !Object.hasOwn(descriptor, 'value')) fail(`${label} contains an accessor`);
  }
};

const exactArray = (value, length, label) => {
  if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype || value.length !== length) fail(`${label} is invalid`);
  const ownKeys = Reflect.ownKeys(value).filter((key) => key !== 'length');
  if (ownKeys.length !== length || ownKeys.some((key, index) => key !== String(index))) fail(`${label} is not closed`);
  for (let index = 0; index < length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    if (!descriptor || descriptor.enumerable !== true || !Object.hasOwn(descriptor, 'value')) fail(`${label} contains an accessor`);
  }
};

const isDigest = (value) => typeof value === 'string' && DIGEST.test(value) && value !== ZERO_DIGEST;
const isCommit = (value) => typeof value === 'string' && COMMIT.test(value) && value !== ZERO_COMMIT;

const rejectSecretValues = (value, path = '$') => {
  if (typeof value === 'string' && SECRET_VALUE.test(value)) fail(`${path} contains secret material`);
  if (Array.isArray(value)) {
    value.forEach((item, index) => rejectSecretValues(item, `${path}[${index}]`));
    return;
  }
  if (value && typeof value === 'object') {
    for (const key of Reflect.ownKeys(value)) {
      if (typeof key === 'string') rejectSecretValues(value[key], `${path}.${key}`);
    }
  }
};

const sortedJSON = (value) => {
  if (Array.isArray(value)) return value.map(sortedJSON);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, sortedJSON(value[key])]));
  }
  return value;
};

const canonicalBytes = (value) => Buffer.from(`${JSON.stringify(sortedJSON(value), null, 2)}\n`, 'utf8');

const normalizeTimestamp = (value, label) => {
  if (typeof value !== 'string' || !TIMESTAMP.test(value)) fail(`${label} is invalid`);
  const milliseconds = Date.parse(value);
  if (!Number.isFinite(milliseconds) || new Date(milliseconds).toISOString() !== value) fail(`${label} is invalid`);
  return Object.freeze({ value, milliseconds });
};

const normalizeDigest = (value, label) => {
  if (!isDigest(value)) fail(`${label} is invalid`);
  return value;
};

const normalizeStep = (value, index) => {
  const expected = QUALIFICATION_SUITE_EVIDENCE_STEPS[index];
  exactKeys(value, QUALIFICATION_SUITE_EVIDENCE_STEP_KEYS, `qualification suite step ${index}`);
  if (value.kind !== expected.kind || value.scenario !== expected.scenario || value.phase !== expected.phase) {
    fail('qualification suite steps are missing, duplicated, or reordered');
  }
  if (value.status !== 'passed') {
    fail(`qualification suite step ${index} has a failed public outcome`);
  }
  const evidenceSHA256 = normalizeDigest(value.evidence_sha256, `qualification suite step ${index} evidence digest`);
  return Object.freeze({
    evidence_sha256: evidenceSHA256,
    kind: expected.kind,
    phase: expected.phase,
    scenario: expected.scenario,
    status: 'passed'
  });
};

const normalizeEvidence = (value) => {
  exactKeys(value, QUALIFICATION_SUITE_EVIDENCE_KEYS, 'qualification suite evidence');
  if (value.schema_version !== QUALIFICATION_SUITE_EVIDENCE_SCHEMA_VERSION || value.kind !== QUALIFICATION_SUITE_EVIDENCE_KIND) {
    fail('qualification suite evidence identity is invalid');
  }
  if (!isDigest(value.suite_input_sha256)) fail('qualification suite input digest is invalid');
  if (!isDigest(value.release_trust_sha256)) fail('qualification release trust digest is invalid');
  if (!isDigest(value.candidate_checkpoint_sha256)) fail('candidate checkpoint digest is invalid');
  if (!isCommit(value.source_commit)) fail('qualification source commit is invalid');
  if (!isDigest(value.artifact_sha256)) fail('qualification artifact digest is invalid');
  if (!TEAM_ID.test(value.team_id)) fail('qualification Team ID is invalid');
  if (!LANE_CLASSES.includes(value.lane_class)) fail('qualification lane class is invalid');
  const started = normalizeTimestamp(value.started_at, 'qualification suite started_at');
  const completed = normalizeTimestamp(value.completed_at, 'qualification suite completed_at');
  const window = completed.milliseconds - started.milliseconds;
  if (window <= 0 || window > QUALIFICATION_SUITE_EVIDENCE_MAX_WINDOW_MILLISECONDS) fail('qualification suite timestamp window is invalid');
  exactArray(value.steps, QUALIFICATION_SUITE_EVIDENCE_STEPS.length, 'qualification suite steps');
  const steps = value.steps.map(normalizeStep);
  const stepDigests = new Set();
  for (const step of steps) {
    if (stepDigests.has(step.evidence_sha256)) fail('qualification suite step evidence digest is reused');
    stepDigests.add(step.evidence_sha256);
  }
  if (!isDigest(value.teardown_proof_sha256)) fail('qualification teardown proof digest is invalid');
  const normalized = Object.freeze({
    artifact_sha256: value.artifact_sha256,
    candidate_checkpoint_sha256: value.candidate_checkpoint_sha256,
    completed_at: value.completed_at,
    kind: QUALIFICATION_SUITE_EVIDENCE_KIND,
    lane_class: value.lane_class,
    release_trust_sha256: value.release_trust_sha256,
    schema_version: QUALIFICATION_SUITE_EVIDENCE_SCHEMA_VERSION,
    source_commit: value.source_commit,
    started_at: value.started_at,
    steps: Object.freeze(steps),
    suite_input_sha256: value.suite_input_sha256,
    team_id: value.team_id,
    teardown_proof_sha256: value.teardown_proof_sha256
  });
  rejectSecretValues(normalized);
  return normalized;
};

/**
 * Normalize the closed public projection. No raw input, activation proof,
 * Grant, path, command output, or per-run secret is accepted by this API.
 */
export const normalizeQualificationSuiteEvidence = (value) => normalizeEvidence(value);
export const validateQualificationSuiteEvidence = normalizeQualificationSuiteEvidence;
export const buildQualificationSuiteEvidence = normalizeQualificationSuiteEvidence;

export const canonicalQualificationSuiteEvidence = (value) => {
  const normalized = normalizeQualificationSuiteEvidence(value);
  const bytes = canonicalBytes(normalized);
  if (bytes.length > QUALIFICATION_SUITE_EVIDENCE_MAX_BYTES) fail('qualification suite evidence exceeds its size limit');
  return bytes;
};
export const canonicalQualificationSuiteEvidenceBytes = canonicalQualificationSuiteEvidence;
export const canonicalQualificationSuiteEvidenceJSON = canonicalQualificationSuiteEvidence;

export const qualificationSuiteEvidenceSHA256 = (value) => crypto.createHash('sha256').update(canonicalQualificationSuiteEvidence(value)).digest('hex');
export const qualificationSuiteEvidenceDigest = qualificationSuiteEvidenceSHA256;

export const parseQualificationSuiteEvidence = (bytes) => {
  if (!Buffer.isBuffer(bytes) || bytes.length === 0 || bytes.length > QUALIFICATION_SUITE_EVIDENCE_MAX_BYTES) fail('qualification suite evidence bytes are invalid');
  let value;
  try {
    value = JSON.parse(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes));
  } catch {
    fail('qualification suite evidence bytes are invalid');
  }
  const normalized = normalizeQualificationSuiteEvidence(value);
  if (!bytes.equals(canonicalQualificationSuiteEvidence(normalized))) fail('qualification suite evidence is not canonical');
  return normalized;
};
