import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import test from 'node:test';

import {
  QUALIFICATION_SUITE_EVIDENCE_KIND,
  QUALIFICATION_SUITE_EVIDENCE_MAX_WINDOW_MILLISECONDS,
  QUALIFICATION_SUITE_EVIDENCE_SCHEMA_VERSION,
  QUALIFICATION_SUITE_EVIDENCE_SCENARIOS,
  QUALIFICATION_SUITE_EVIDENCE_STEPS,
  buildQualificationSuiteEvidence,
  canonicalQualificationSuiteEvidence,
  normalizeQualificationSuiteEvidence,
  parseQualificationSuiteEvidence,
  qualificationSuiteEvidenceSHA256
} from './qualification-suite-evidence.mjs';

const digest = (label) => crypto.createHash('sha256').update(label).digest('hex');
const COMMIT = 'a'.repeat(40);
const TEAM_ID = 'ABCDE12345';
const iso = (seconds) => new Date(Date.parse('2026-08-14T00:00:00.000Z') + seconds * 1000).toISOString();

const validEvidence = () => ({
  schema_version: QUALIFICATION_SUITE_EVIDENCE_SCHEMA_VERSION,
  kind: QUALIFICATION_SUITE_EVIDENCE_KIND,
  suite_input_sha256: digest('suite-input'),
  release_trust_sha256: digest('release-trust'),
  candidate_checkpoint_sha256: digest('candidate-checkpoint'),
  source_commit: COMMIT,
  artifact_sha256: digest('artifact'),
  team_id: TEAM_ID,
  lane_class: 'apple_silicon',
  started_at: iso(0),
  completed_at: iso(60),
  teardown_proof_sha256: digest('teardown'),
  steps: QUALIFICATION_SUITE_EVIDENCE_STEPS.map((step, index) => ({
    kind: step.kind,
    scenario: step.scenario,
    phase: step.phase,
    status: 'passed',
    evidence_sha256: digest(`step-${index}`)
  }))
});

test('defines one unarmed control followed by the six ordered scenario identities', () => {
  assert.deepEqual(QUALIFICATION_SUITE_EVIDENCE_SCENARIOS, [
    { scenario: 'pre-cloud-kill', phase: 'pre-cloud' },
    { scenario: 'post-cloud-pre-local-kill', phase: 'post-cloud-pre-local' },
    { scenario: 'post-activation-pre-audit-kill', phase: 'post-activation-pre-audit' },
    { scenario: 'post-audit-pre-reply-loss', phase: 'post-audit-pre-reply' },
    { scenario: 'audit-fsync-failure', phase: 'audit-fsync' },
    { scenario: 'transport-reply-loss', phase: 'transport-reply' }
  ]);
  assert.equal(QUALIFICATION_SUITE_EVIDENCE_STEPS.length, 7);
  assert.deepEqual(QUALIFICATION_SUITE_EVIDENCE_STEPS[0], { kind: 'unarmed-control', scenario: null, phase: null });
  assert.deepEqual(QUALIFICATION_SUITE_EVIDENCE_STEPS.slice(1), QUALIFICATION_SUITE_EVIDENCE_SCENARIOS.map((step) => ({ kind: 'scenario', ...step })));
});

test('normalizes a closed secret-free record and freezes the projection', () => {
  const normalized = normalizeQualificationSuiteEvidence(validEvidence());
  assert.equal(normalized.kind, QUALIFICATION_SUITE_EVIDENCE_KIND);
  assert.equal(normalized.steps.length, 7);
  assert.ok(Object.isFrozen(normalized));
  assert.ok(Object.isFrozen(normalized.steps));
  assert.ok(Object.isFrozen(normalized.steps[0]));
  assert.deepEqual(Object.keys(normalized.steps[0]).sort(), ['evidence_sha256', 'kind', 'phase', 'scenario', 'status']);
  assert.doesNotMatch(JSON.stringify(normalized), /-----BEGIN|Bearer\s+|\b(?:secret|token|password|private|grant)\b/iu);
});

test('canonical bytes and SHA-256 are deterministic across insertion order', () => {
  const first = validEvidence();
  const second = {
    steps: first.steps.map((step) => ({ evidence_sha256: step.evidence_sha256, status: step.status, scenario: step.scenario, phase: step.phase, kind: step.kind })),
    teardown_proof_sha256: first.teardown_proof_sha256,
    completed_at: first.completed_at,
    started_at: first.started_at,
    lane_class: first.lane_class,
    team_id: first.team_id,
    artifact_sha256: first.artifact_sha256,
    source_commit: first.source_commit,
    candidate_checkpoint_sha256: first.candidate_checkpoint_sha256,
    release_trust_sha256: first.release_trust_sha256,
    suite_input_sha256: first.suite_input_sha256,
    kind: first.kind,
    schema_version: first.schema_version
  };
  const bytes = canonicalQualificationSuiteEvidence(first);
  assert.deepEqual(bytes, canonicalQualificationSuiteEvidence(second));
  assert.equal(qualificationSuiteEvidenceSHA256(first), crypto.createHash('sha256').update(bytes).digest('hex'));
  assert.deepEqual(parseQualificationSuiteEvidence(bytes), normalizeQualificationSuiteEvidence(first));
});

test('rejects missing, unknown, accessor, and symbol fields', () => {
  const original = validEvidence();
  const accessor = validEvidence();
  Object.defineProperty(accessor.steps[0], 'status', { enumerable: true, get: () => 'passed' });
  const symbol = validEvidence();
  symbol.steps[0][Symbol('unexpected')] = 'value';
  const arrayAccessor = validEvidence();
  Object.defineProperty(arrayAccessor.steps, '0', { enumerable: true, configurable: true, get: () => validEvidence().steps[0] });
  const cases = [
    () => { const value = validEvidence(); delete value.release_trust_sha256; return value; },
    () => ({ ...original, unexpected: 'value' }),
    () => accessor,
    () => symbol,
    () => arrayAccessor,
    () => ({ ...original, input: { grant: 'raw-secret' } }),
    () => ({ ...original, steps: original.steps.map((step) => ({ ...step, raw_input: 'secret' })) })
  ];
  for (const makeCase of cases) assert.throws(() => normalizeQualificationSuiteEvidence(makeCase()), /closed|secret|unknown|missing|accessor/iu);
});

test('rejects missing, duplicated, reordered, or substituted step identities', () => {
  const original = validEvidence();
  const cases = [
    () => ({ ...original, steps: original.steps.slice(0, -1) }),
    () => ({ ...original, steps: [original.steps[0], original.steps[1], original.steps[1], ...original.steps.slice(2, -1)] }),
    () => ({ ...original, steps: [...original.steps].reverse() }),
    () => ({ ...original, steps: original.steps.map((step, index) => index === 2 ? { ...step, scenario: 'transport-reply-loss', phase: 'transport-reply' } : step) }),
    () => ({ ...original, steps: original.steps.map((step, index) => index === 0 ? { ...step, scenario: 'pre-cloud-kill', phase: 'pre-cloud' } : step) })
  ];
  for (const makeCase of cases) assert.throws(() => normalizeQualificationSuiteEvidence(makeCase()), /invalid|missing|duplicated|reordered|closed/iu);
});

test('rejects cross-step evidence digest reuse and zero or malformed digests', () => {
  const original = validEvidence();
  const duplicate = validEvidence();
  duplicate.steps[6].evidence_sha256 = duplicate.steps[0].evidence_sha256;
  const cases = [
    duplicate,
    { ...original, artifact_sha256: '0'.repeat(64) },
    { ...original, suite_input_sha256: 'not-a-digest' },
    { ...original, source_commit: '0'.repeat(40) },
    { ...original, candidate_checkpoint_sha256: 'A'.repeat(64) },
    { ...original, teardown_proof_sha256: 'f'.repeat(63) }
  ];
  for (const value of cases) assert.throws(() => normalizeQualificationSuiteEvidence(value), /reused|invalid/iu);
});

test('rejects failed outcomes and unarmed-control identity inconsistencies', () => {
  const failed = validEvidence();
  failed.steps[0].status = 'failed';
  const unarmedScenario = validEvidence();
  unarmedScenario.steps[0].scenario = 'pre-cloud-kill';
  const unarmedPhase = validEvidence();
  unarmedPhase.steps[0].phase = 'pre-cloud';
  const failedScenario = validEvidence();
  failedScenario.steps[4].status = 'failed';
  for (const value of [failed, unarmedScenario, unarmedPhase, failedScenario]) {
    assert.throws(() => normalizeQualificationSuiteEvidence(value), /failed|invalid|missing|reordered/iu);
  }
});

test('rejects invalid timestamps and windows', () => {
  const reversed = validEvidence();
  reversed.started_at = reversed.completed_at;
  const badCalendar = validEvidence();
  badCalendar.started_at = '2026-02-30T00:00:00.000Z';
  const wrongZone = validEvidence();
  wrongZone.completed_at = '2026-08-14T00:01:00.000+00:00';
  const tooLong = validEvidence();
  tooLong.completed_at = new Date(Date.parse(tooLong.started_at) + QUALIFICATION_SUITE_EVIDENCE_MAX_WINDOW_MILLISECONDS + 1).toISOString();
  for (const value of [reversed, badCalendar, wrongZone, tooLong]) assert.throws(() => normalizeQualificationSuiteEvidence(value), /timestamp|window|invalid/iu);
});

test('rejects invalid release bindings and secret-bearing material', () => {
  const cases = [
    { ...validEvidence(), team_id: 'bad-team' },
    { ...validEvidence(), lane_class: 'unknown' },
    { ...validEvidence(), source_commit: 'g'.repeat(40) },
    { ...validEvidence(), steps: validEvidence().steps.map((step, index) => index === 1 ? { ...step, evidence_sha256: '-----BEGIN PRIVATE KEY-----' } : step) },
    { ...validEvidence(), secret: '-----BEGIN PRIVATE KEY-----' },
    { ...validEvidence(), steps: validEvidence().steps.map((step, index) => index === 1 ? { ...step, grant: 'opaque-secret' } : step) }
  ];
  for (const value of cases) assert.throws(() => normalizeQualificationSuiteEvidence(value), /invalid|secret|closed/iu);
});

test('parse rejects noncanonical and duplicate-key JSON', () => {
  const bytes = canonicalQualificationSuiteEvidence(validEvidence());
  assert.throws(() => parseQualificationSuiteEvidence(Buffer.from(`${bytes.toString()}\n`, 'utf8')), /canonical/iu);
  const duplicate = Buffer.from(`{"artifact_sha256":"${digest('artifact')}","artifact_sha256":"${digest('artifact')}"}`, 'utf8');
  assert.throws(() => parseQualificationSuiteEvidence(duplicate), /invalid|closed|canonical/iu);
});

test('builder is an additive alias for the closed normalizer', () => {
  assert.deepEqual(buildQualificationSuiteEvidence(validEvidence()), normalizeQualificationSuiteEvidence(validEvidence()));
});
