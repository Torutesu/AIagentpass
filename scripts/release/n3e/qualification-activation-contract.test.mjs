import assert from 'node:assert/strict';
import test from 'node:test';

import {
  QUALIFICATION_ACTIVATION_MAX_BYTES,
  QUALIFICATION_ACTIVATION_MAX_PROOF_BYTES,
  QUALIFICATION_ACTIVATION_SCHEMA_VERSION,
  canonicalQualificationActivation,
  normalizeQualificationActivation,
  parseQualificationActivation,
  qualificationActivationPublicMetadata
} from './qualification-activation-contract.mjs';

const AGENT_ID = '11111111-1111-4111-8111-111111111111';
const PROOF = '{"grant_id":"grant-1","signature":"opaque-secret"}';
const VALUE = Object.freeze({
  schema_version: QUALIFICATION_ACTIVATION_SCHEMA_VERSION,
  agent_id: AGENT_ID,
  agent_kind: 'claude_code',
  requested_ttl_seconds: 600,
  proof: PROOF
});

const canonical = () => canonicalQualificationActivation(VALUE);

test('exports a closed five-field activation document and preserves proof bytes', () => {
  const bytes = canonical();
  const expected = '{"agent_id":"11111111-1111-4111-8111-111111111111","agent_kind":"claude_code","proof":"{\\"grant_id\\":\\"grant-1\\",\\"signature\\":\\"opaque-secret\\"}","requested_ttl_seconds":600,"schema_version":1}';
  assert.ok(Buffer.isBuffer(bytes));
  assert.equal(bytes.toString('utf8'), expected);
  const parsed = parseQualificationActivation(bytes);
  assert.deepEqual(parsed, VALUE);
  assert.equal(Buffer.from(parsed.proof, 'utf8').toString('hex'), Buffer.from(PROOF, 'utf8').toString('hex'));
  assert.deepEqual(Object.keys(parsed).sort(), ['agent_id', 'agent_kind', 'proof', 'requested_ttl_seconds', 'schema_version']);
});

test('freezes the exact Swift/XPC size agreement', () => {
  assert.equal(QUALIFICATION_ACTIVATION_MAX_PROOF_BYTES, 4 * 1024);
  assert.equal(QUALIFICATION_ACTIVATION_MAX_BYTES, 16 * 1024);
  assert.ok(QUALIFICATION_ACTIVATION_MAX_PROOF_BYTES < QUALIFICATION_ACTIVATION_MAX_BYTES);
});

test('normalization is closed, frozen, and does not include nonce', () => {
  const normalized = normalizeQualificationActivation({ ...VALUE });
  assert.ok(Object.isFrozen(normalized));
  assert.deepEqual(Object.keys(normalized).sort(), ['agent_id', 'agent_kind', 'proof', 'requested_ttl_seconds', 'schema_version']);
  assert.equal('nonce' in normalized, false);
  assert.throws(() => { normalized.agent_id = '22222222-2222-4222-8222-222222222222'; }, TypeError);
});

test('rejects unknown and missing fields before accepting an activation', () => {
  assert.throws(() => canonicalQualificationActivation({ ...VALUE, nonce: 'must-not-be-present' }), /missing or unknown fields/u);
  const { proof: ignored, ...missingProof } = VALUE;
  void ignored;
  assert.throws(() => canonicalQualificationActivation(missingProof), /missing or unknown fields/u);
  const duplicate = Buffer.from(`{"agent_id":"${AGENT_ID}","agent_id":"${AGENT_ID}","agent_kind":"claude_code","proof":"${PROOF.replaceAll('"', '\\"')}","requested_ttl_seconds":600,"schema_version":1}`, 'utf8');
  assert.throws(() => parseQualificationActivation(duplicate), /duplicate JSON fields/u);
});

test('rejects duplicate fields inside the opaque proof as well', () => {
  const duplicateProof = '{"grant_id":"grant-1","grant_id":"grant-2"}';
  assert.throws(() => canonicalQualificationActivation({ ...VALUE, proof: duplicateProof }), /duplicate JSON fields/u);
});

test('rejects invalid UUID, agent kind, and TTL values', () => {
  for (const agentId of [
    '11111111-1111-0111-8111-111111111111',
    '11111111-1111-4111-7111-111111111111',
    '11111111-1111-4111-8111-11111111111',
    'abcdefab-cdef-4abc-8def-abcdefabcdef'.toUpperCase()
  ]) assert.throws(() => canonicalQualificationActivation({ ...VALUE, agent_id: agentId }), /agent_id is invalid/u);
  for (const agentKind of ['claude-code', 'cursor_agent', '']) assert.throws(() => canonicalQualificationActivation({ ...VALUE, agent_kind: agentKind }), /agent_kind is invalid/u);
  for (const ttl of [59, 28_801, 60.5, Number.NaN, '600']) assert.throws(() => canonicalQualificationActivation({ ...VALUE, requested_ttl_seconds: ttl }), /requested_ttl_seconds is invalid/u);
});

test('enforces independent proof and document byte limits', () => {
  const oversizedProof = JSON.stringify({ payload: 'x'.repeat(QUALIFICATION_ACTIVATION_MAX_PROOF_BYTES) });
  assert.throws(() => canonicalQualificationActivation({ ...VALUE, proof: oversizedProof }), /proof exceeds its size limit/u);
  assert.throws(() => parseQualificationActivation(Buffer.alloc(QUALIFICATION_ACTIVATION_MAX_BYTES + 1, 0x20)), /qualification activation exceeds its size limit/u);
});

test('rejects noncanonical outer documents and noncanonical opaque proofs', () => {
  const outerWithWhitespace = Buffer.concat([canonical(), Buffer.from('\n', 'utf8')]);
  assert.throws(() => parseQualificationActivation(outerWithWhitespace), /not canonical JSON/u);
  const noncanonicalProof = '{"grant_id":"grant-1", "signature":"opaque-secret"}';
  const outer = Buffer.from(`{"agent_id":"${AGENT_ID}","agent_kind":"claude_code","proof":${JSON.stringify(noncanonicalProof)},"requested_ttl_seconds":600,"schema_version":1}`, 'utf8');
  assert.throws(() => parseQualificationActivation(outer), /proof is not canonical JSON/u);
});

test('public metadata is digest-only and cannot leak the proof through JSON or stringification', () => {
  const metadata = qualificationActivationPublicMetadata(VALUE);
  assert.ok(Object.isFrozen(metadata));
  assert.deepEqual(Object.keys(metadata).sort(), ['agent_id', 'agent_kind', 'proof_bytes', 'proof_sha256', 'requested_ttl_seconds', 'schema_version']);
  assert.equal(metadata.proof_bytes, Buffer.byteLength(PROOF, 'utf8'));
  assert.match(metadata.proof_sha256, /^[0-9a-f]{64}$/u);
  assert.equal('proof' in metadata, false);
  assert.doesNotMatch(JSON.stringify(metadata), /opaque-secret/u);
  assert.doesNotMatch(String(metadata), /opaque-secret/u);
  assert.doesNotMatch(Object.getOwnPropertyNames(metadata).join(','), /proof$/u);
});

test('mutating caller input after encoding cannot mutate the canonical document', () => {
  const input = { ...VALUE };
  const bytes = canonicalQualificationActivation(input);
  input.agent_id = '22222222-2222-4222-8222-222222222222';
  input.proof = '{"changed":true}';
  assert.equal(canonicalQualificationActivation(VALUE).toString('utf8'), bytes.toString('utf8'));
  assert.equal(parseQualificationActivation(bytes).agent_id, AGENT_ID);
});
