const MAX_PREFLIGHT_BYTES = 8 * 1024;
const PREFLIGHT_KEYS = Object.freeze(["version", "platform", "candidate_id", "device_key_fingerprint"]);
const CANDIDATE_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const DEVICE_KEY_FINGERPRINT = /^SHA256:[A-Za-z0-9_-]{43}$/;

export const PUBLIC_PREFLIGHT_VERSION = 1;
export const PUBLIC_PREFLIGHT_EXAMPLE = Object.freeze({
  version: PUBLIC_PREFLIGHT_VERSION,
  platform: "macos",
  candidate_id: "candidate-2026-08",
  device_key_fingerprint: `SHA256:${"A".repeat(43)}`,
});

export class EnrollmentPreflightError extends Error {
  constructor(message = "Public enrollment preflight is invalid") {
    super(message);
    this.name = "EnrollmentPreflightError";
  }
}

function isPlainRecord(value) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value)
    && Object.getPrototypeOf(value) === Object.prototype;
}

function exactKeys(value) {
  const actual = Object.keys(value).sort();
  const expected = [...PREFLIGHT_KEYS].sort();
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}

function fail() {
  throw new EnrollmentPreflightError();
}

export function validatePublicEnrollmentPreflight(value) {
  if (!isPlainRecord(value) || !exactKeys(value) || value.version !== PUBLIC_PREFLIGHT_VERSION
    || value.platform !== "macos"
    || typeof value.candidate_id !== "string" || !CANDIDATE_ID.test(value.candidate_id)
    || typeof value.device_key_fingerprint !== "string" || !DEVICE_KEY_FINGERPRINT.test(value.device_key_fingerprint)) {
    fail();
  }
  return Object.freeze({
    version: PUBLIC_PREFLIGHT_VERSION,
    platform: "macos",
    candidate_id: value.candidate_id,
    device_key_fingerprint: value.device_key_fingerprint,
  });
}

export function parsePublicEnrollmentPreflight(text) {
  if (typeof text !== "string" || text.length === 0 || text.length > MAX_PREFLIGHT_BYTES) fail();
  try {
    const bytes = typeof TextEncoder === "function" ? new TextEncoder().encode(text).byteLength : text.length;
    if (bytes > MAX_PREFLIGHT_BYTES) fail();
    return validatePublicEnrollmentPreflight(JSON.parse(text));
  } catch (error) {
    if (error instanceof EnrollmentPreflightError) throw error;
    fail();
  }
}

export function publicEnrollmentPreflightKeys() {
  return [...PREFLIGHT_KEYS];
}
