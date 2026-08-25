import assert from "node:assert/strict";
import test from "node:test";
import {
  EnrollmentPreflightError,
  PUBLIC_PREFLIGHT_EXAMPLE,
  parsePublicEnrollmentPreflight,
  publicEnrollmentPreflightKeys,
  validatePublicEnrollmentPreflight,
} from "../lib/enrollment-preflight.mjs";

const valid = {
  version: 1,
  platform: "macos",
  candidate_id: "candidate-2026-08",
  device_key_fingerprint: `SHA256:${"f".repeat(43)}`,
};

test("accepts exactly the public preflight DTO and returns a frozen public copy", () => {
  const parsed = parsePublicEnrollmentPreflight(JSON.stringify(valid));
  assert.deepEqual(parsed, valid);
  assert.deepEqual(Object.keys(parsed).sort(), publicEnrollmentPreflightKeys().sort());
  assert.equal(Object.isFrozen(parsed), true);
  assert.equal(Object.hasOwn(parsed, "credential"), false);
  assert.deepEqual(parsePublicEnrollmentPreflight(JSON.stringify(PUBLIC_PREFLIGHT_EXAMPLE)), PUBLIC_PREFLIGHT_EXAMPLE);
});

test("rejects unknown, missing, malformed, and substituted fields before WebAuthn", () => {
  const invalid = [
    { ...valid, extra: "must-reject" },
    { ...valid, candidate_id: undefined },
    { ...valid, version: 2 },
    { ...valid, platform: "windows" },
    { ...valid, candidate_id: "candidate with spaces" },
    { ...valid, device_key_fingerprint: "SHA256:short" },
    { ...valid, device_key_fingerprint: `SHA256:${"f".repeat(43)}`, credential: "secret" },
  ];
  for (const value of invalid) assert.throws(() => validatePublicEnrollmentPreflight(value), EnrollmentPreflightError);
  assert.throws(() => parsePublicEnrollmentPreflight("[]"), EnrollmentPreflightError);
  assert.throws(() => parsePublicEnrollmentPreflight("{"), EnrollmentPreflightError);
});

test("bounds the imported JSON and never echoes input into the error", () => {
  const secret = "-----BEGIN PRIVATE KEY-----";
  assert.throws(() => parsePublicEnrollmentPreflight(`${secret}${"x".repeat(9_000)}`), (error) => {
    assert.ok(error instanceof EnrollmentPreflightError);
    assert.equal(error.message.includes(secret), false);
    return true;
  });
});
