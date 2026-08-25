import assert from 'node:assert/strict';
import test from 'node:test';

import {
  RELEASE_CANDIDATE_ID_PATTERN,
  RELEASE_CANDIDATE_ID_PREFIX,
  assertReleaseCandidateIdMatchesProduct,
  deriveReleaseCandidateId,
  parseReleaseCandidateId
} from '../lib/release-candidate-identity.mjs';

const digest = '0123456789abcdef'.repeat(4);

test('release candidate identity derivation is deterministic and grammar-compatible', () => {
  const candidateId = deriveReleaseCandidateId(digest);
  assert.equal(candidateId, `${RELEASE_CANDIDATE_ID_PREFIX}${digest}`);
  assert.equal(candidateId.length <= 128, true);
  assert.match(candidateId, /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u);
  assert.equal(RELEASE_CANDIDATE_ID_PATTERN.test(candidateId), true);
  assert.deepEqual(parseReleaseCandidateId(candidateId), {
    candidate_id: candidateId,
    version: 1,
    product: 'pkg',
    sha256: digest
  });
});

test('release candidate identity parser rejects arbitrary, malformed, and noncanonical identities', () => {
  for (const value of [
    'release-2026-08-13-01',
    `${RELEASE_CANDIDATE_ID_PREFIX}${digest.toUpperCase()}`,
    `${RELEASE_CANDIDATE_ID_PREFIX}${digest}0`,
    'release-pkg-sha256-v2-' + digest,
    'release-pkg-sha256-v1-' + digest.slice(0, 63),
    'release-pkg-sha256-v1-' + digest + '/unsafe',
    '',
    null,
    42
  ]) assert.throws(() => parseReleaseCandidateId(value), /candidate_id|identity/iu);
});

test('release candidate identity binding rejects digest substitution and invalid input', () => {
  const candidateId = deriveReleaseCandidateId(digest);
  assert.deepEqual(assertReleaseCandidateIdMatchesProduct(candidateId, digest), parseReleaseCandidateId(candidateId));
  assert.throws(() => assertReleaseCandidateIdMatchesProduct(candidateId, 'f'.repeat(64)), /does not match/iu);
  assert.throws(() => deriveReleaseCandidateId(digest.toUpperCase()), /lowercase SHA-256/iu);
  assert.throws(() => deriveReleaseCandidateId('not-a-digest'), /lowercase SHA-256/iu);
});
