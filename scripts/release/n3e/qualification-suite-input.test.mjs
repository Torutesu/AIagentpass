import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { FIXED_INPUT_KIND, FIXED_INPUT_SCHEMA_VERSION } from './run-fixed-protected-qualification.mjs';
import { QUALIFICATION_SUITE_INBOX_PATH, QUALIFICATION_SUITE_INPUT_KIND, QUALIFICATION_SUITE_STEPS, canonicalQualificationSuiteInput, consumeFixedQualificationSuiteInbox, consumeFixedQualificationSuiteInput, parseQualificationSuiteInput } from './qualification-suite-input.mjs';

const UID = process.getuid?.();
const input = (scenario, index) => ({ schema_version: FIXED_INPUT_SCHEMA_VERSION, kind: FIXED_INPUT_KIND, provision: { scenario, expires_at_epoch_seconds: 1_800_000_000 + index, run_binding: `run-${index}` }, activation: { schema_version: 1, agent_id: `12345678-1234-4123-8${String(index).padStart(3, '0')}-123456789abc`, agent_kind: 'claude_code', requested_ttl_seconds: 60, proof: `{"grant":"opaque-${index}"}` } });
const suite = () => ({ schema_version: 1, kind: QUALIFICATION_SUITE_INPUT_KIND, steps: QUALIFICATION_SUITE_STEPS.map((step, index) => ({ ...step, input: input(step.scenario ?? 'pre-cloud-kill', index) })) });

test('suite input requires seven ordered one-time activations and run bindings', () => {
  const bytes = canonicalQualificationSuiteInput(suite());
  assert.equal(parseQualificationSuiteInput(bytes).steps.length, 7);
  const duplicate = suite(); duplicate.steps[1].input.provision.run_binding = duplicate.steps[0].input.provision.run_binding;
  assert.throws(() => canonicalQualificationSuiteInput(duplicate), /reused/u);
  const duplicateGrant = suite(); duplicateGrant.steps[1].input.activation.proof = duplicateGrant.steps[0].input.activation.proof;
  assert.throws(() => canonicalQualificationSuiteInput(duplicateGrant), /Grant proof.*reused/u);
  const sameAgent = suite(); sameAgent.steps.forEach((step) => { step.input.activation.agent_id = sameAgent.steps[0].input.activation.agent_id; });
  assert.equal(parseQualificationSuiteInput(canonicalQualificationSuiteInput(sameAgent)).steps.length, 7);
  const reordered = suite(); [reordered.steps[1], reordered.steps[2]] = [reordered.steps[2], reordered.steps[1]];
  assert.throws(() => canonicalQualificationSuiteInput(reordered), /reordered/u);
});

test('suite input is canonical and consumed exactly once from a protected file', () => {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'agentpass-suite-input-'))); fs.chmodSync(root, 0o700);
  const inputPath = path.join(root, 'input.json'); fs.writeFileSync(inputPath, canonicalQualificationSuiteInput(suite()), { mode: 0o600 });
  try {
    assert.equal(consumeFixedQualificationSuiteInput({ inputPath, expectedUid: UID, uid: UID, production: false }).steps.length, 7);
    assert.equal(fs.existsSync(inputPath), false);
    assert.throws(() => consumeFixedQualificationSuiteInput({ inputPath, expectedUid: UID, uid: UID, production: false }), /unavailable/u);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('suite input rejects noncanonical and production path substitution', () => {
  assert.throws(() => parseQualificationSuiteInput(Buffer.from(JSON.stringify(suite()))), /canonical/u);
  assert.throws(() => consumeFixedQualificationSuiteInput({ inputPath: '/tmp/input.json', platform: 'darwin', uid: 0, expectedUid: 0, production: true }), /fixed path/u);
});

test('suite inbox has a distinct fixed production path and the same one-shot contract', () => {
  assert.equal(QUALIFICATION_SUITE_INBOX_PATH, '/private/var/db/agentpass-qualification/input.inbox.json');
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'agentpass-suite-inbox-'))); fs.chmodSync(root, 0o700);
  const inputPath = path.join(root, 'input.inbox.json'); fs.writeFileSync(inputPath, canonicalQualificationSuiteInput(suite()), { mode: 0o600 });
  try {
    assert.equal(consumeFixedQualificationSuiteInbox({ inputPath, expectedUid: UID, uid: UID, production: false }).steps.length, 7);
    assert.equal(fs.existsSync(inputPath), false);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});
