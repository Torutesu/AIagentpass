const PRODUCT_PKG_SHA256 = /^[0-9a-f]{64}$/u;
const CANDIDATE_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;

export const RELEASE_CANDIDATE_ID_VERSION = 1;
export const RELEASE_MANIFEST_SCHEMA_VERSION = 4;
export const RELEASE_CANDIDATE_ID_PREFIX = 'release-pkg-sha256-v1-';
export const RELEASE_CANDIDATE_ID_PATTERN = new RegExp(`^${RELEASE_CANDIDATE_ID_PREFIX}([0-9a-f]{64})$`, 'u');

const invalid = (label, value) => {
  throw new TypeError(`${label} must be a lowercase SHA-256 hex digest` + (value === undefined ? '' : `: ${String(value)}`));
};

const productPackageDigest = (value) => {
  if (typeof value !== 'string' || !PRODUCT_PKG_SHA256.test(value)) invalid('product PKG SHA-256', value);
  return value;
};

/**
 * Derive the stable release candidate identity from the exact product PKG bytes.
 * The input and output are intentionally canonical so the value can be persisted
 * in a later installed receipt without retaining the package itself.
 */
export const deriveReleaseCandidateId = (productPkgSha256) => (
  `${RELEASE_CANDIDATE_ID_PREFIX}${productPackageDigest(productPkgSha256)}`
);

/**
 * Parse only identities produced by deriveReleaseCandidateId.
 * This is stricter than the shared candidate-id grammar by design: arbitrary
 * human-selected IDs must not be accepted as release package identities.
 */
export const parseReleaseCandidateId = (value) => {
  if (typeof value !== 'string' || !CANDIDATE_ID.test(value)) throw new TypeError('release candidate_id is outside the candidate ID grammar');
  const match = RELEASE_CANDIDATE_ID_PATTERN.exec(value);
  if (!match) throw new TypeError('release candidate_id is not a supported product PKG identity');
  return Object.freeze({
    candidate_id: value,
    version: RELEASE_CANDIDATE_ID_VERSION,
    product: 'pkg',
    sha256: match[1]
  });
};

export const assertReleaseCandidateIdMatchesProduct = (candidateId, productPkgSha256) => {
  const parsed = parseReleaseCandidateId(candidateId);
  const expected = deriveReleaseCandidateId(productPkgSha256);
  if (parsed.candidate_id !== expected) throw new Error('release candidate_id does not match the product PKG SHA-256');
  return parsed;
};
