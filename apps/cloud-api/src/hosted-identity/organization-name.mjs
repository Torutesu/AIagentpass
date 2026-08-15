const CONTROL_CHARACTERS = /\p{Cc}/u;
const WHITE_SPACE = /\p{White_Space}+/gu;

export const HOSTED_ORGANIZATION_NAME_MAX_CHARACTERS = 128;
export const HOSTED_ORGANIZATION_NAME_MAX_BYTES = 512;

/**
 * Normalizes the only browser-controlled value used by first-organization
 * bootstrap. The repository requires the returned value to already be in
 * this canonical form so the request hash and database value cannot diverge.
 */
export function normalizeHostedOrganizationName(value, { requireCanonical = false } = {}) {
  if (typeof value !== "string" || CONTROL_CHARACTERS.test(value)) throw new TypeError("organization name is invalid");
  const normalized = value.normalize("NFC").replace(WHITE_SPACE, " ").trim();
  if (normalized.length < 1
    || Array.from(normalized).length > HOSTED_ORGANIZATION_NAME_MAX_CHARACTERS
    || Buffer.byteLength(normalized, "utf8") > HOSTED_ORGANIZATION_NAME_MAX_BYTES
    || (requireCanonical && value !== normalized)) {
    throw new TypeError("organization name is invalid");
  }
  return normalized;
}
