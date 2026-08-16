import assert from "node:assert/strict";
import crypto from "node:crypto";
import { Readable } from "node:stream";
import test from "node:test";

import {
  SETUP_STDIN_DELIVERY_ERRORS,
  SETUP_STDIN_DELIVERY_MAX_BYTES,
  SetupStdinDeliveryError,
  readSetupEnrollmentInvitationStdin
} from "../lib/setup-stdin-delivery.mjs";

const ENROLLMENT = "11111111-1111-4111-8111-111111111111";
const ORGANIZATION = "22222222-2222-4222-8222-222222222222";
const DEVICE = "33333333-3333-4333-8333-333333333333";
const CANDIDATE = "release-2026-08-15-01";
const FINGERPRINT = `SHA256:${"a".repeat(43)}`;
const ENROLLMENT_URL = "https://api.example/v1";

function invitation({ expires = "2099-01-02T03:04:05.000Z", endpoint = `/v1/enrollments/${ENROLLMENT}` } = {}) {
  const receipt = crypto.generateKeyPairSync("ed25519");
  const publicKey = receipt.publicKey.export({ type: "spki", format: "pem" }).toString();
  const nonce = crypto.randomBytes(32).toString("base64url");
  const binding = {
    version: 1,
    enrollment_id: ENROLLMENT,
    organization_id: ORGANIZATION,
    device_id: DEVICE,
    candidate_id: CANDIDATE,
    artifact_sha256: "b".repeat(64),
    source_commit: "c".repeat(40),
    team_id: "TEAMID1234",
    device_key_fingerprint: FINGERPRINT,
    expires_at: expires
  };
  return {
    version: 2,
    proof_version: 2,
    enrollment_id: ENROLLMENT,
    organization_id: ORGANIZATION,
    device_id: DEVICE,
    label: "build-mac-01",
    platform: "macos",
    candidate_binding: binding,
    challenge_id: ENROLLMENT,
    nonce,
    expires_at: expires,
    challenge: { challenge_id: ENROLLMENT, nonce, expires_at: expires, candidate_id: CANDIDATE, device_key_fingerprint: FINGERPRINT },
    credential: crypto.randomBytes(32).toString("base64url"),
    endpoint,
    possession_receipt_verification: { key_id: "receipt-key-v1", algorithm: "ed25519", public_key: publicKey }
  };
}

function input(value, { isTTY = false } = {}) {
  const stream = Readable.from([Buffer.isBuffer(value) ? value : Buffer.from(value)]);
  Object.defineProperty(stream, "isTTY", { value: isTTY });
  return stream;
}

async function read(value, { isTTY = false, ...options } = {}) {
  return readSetupEnrollmentInvitationStdin({ input: input(value, { isTTY }), enrollmentUrl: ENROLLMENT_URL, ...options });
}

test("reads one validated v2 invitation and retains returned data after buffer cleanup", async () => {
  const value = invitation();
  const source = Buffer.from(JSON.stringify(value));
  const received = await read(source);
  assert.equal(received.version, 2);
  assert.equal(received.endpoint, value.endpoint);
  assert.equal(received.credential, value.credential);
  assert.equal(Object.isFrozen(received), true);
  assert.equal(source.equals(Buffer.alloc(source.length)), true);
});

test("rejects empty, oversized, duplicate-key, and trailing-document stdin", async () => {
  const value = invitation();
  const json = JSON.stringify(value);
  const duplicate = json.replace("{\"version\":2", "{\"version\":2,\"version\":2");
  const cases = [
    [" \t\n", SETUP_STDIN_DELIVERY_ERRORS.EMPTY],
    ["x".repeat(SETUP_STDIN_DELIVERY_MAX_BYTES + 1), SETUP_STDIN_DELIVERY_ERRORS.TOO_LARGE],
    [duplicate, SETUP_STDIN_DELIVERY_ERRORS.INVALID_INVITATION],
    [`${json}\n${json}`, SETUP_STDIN_DELIVERY_ERRORS.INVALID_INVITATION]
  ];
  for (const [body, code] of cases) {
    await assert.rejects(read(body), (error) => error instanceof SetupStdinDeliveryError && error.code === code);
  }
});

test("rejects legacy versions, expired invitations, and an endpoint substitution", async () => {
  const legacy = { ...invitation(), version: 1, proof_version: 1 };
  await assert.rejects(read(JSON.stringify(legacy)), (error) => error.code === SETUP_STDIN_DELIVERY_ERRORS.INVALID_INVITATION);

  const expired = invitation({ expires: "2000-01-02T03:04:05.000Z" });
  await assert.rejects(read(JSON.stringify(expired)), (error) => error.code === SETUP_STDIN_DELIVERY_ERRORS.EXPIRED);

  const wrongEndpoint = invitation({ endpoint: "/v1/enrollments/44444444-4444-4444-8444-444444444444" });
  await assert.rejects(read(JSON.stringify(wrongEndpoint)), (error) => error.code === SETUP_STDIN_DELIVERY_ERRORS.ENDPOINT);
});

test("rejects TTY input before consuming it", async () => {
  const value = invitation();
  await assert.rejects(read(JSON.stringify(value), { isTTY: true }), (error) => error.code === SETUP_STDIN_DELIVERY_ERRORS.TTY);
});

test("consumes a stdin source only once", async () => {
  const stream = input(JSON.stringify(invitation()));
  await readSetupEnrollmentInvitationStdin({ input: stream, enrollmentUrl: ENROLLMENT_URL });
  await assert.rejects(
    readSetupEnrollmentInvitationStdin({ input: stream, enrollmentUrl: ENROLLMENT_URL }),
    (error) => error.code === SETUP_STDIN_DELIVERY_ERRORS.REPLAY
  );
});

test("maps stream errors and bounds an incomplete stdin source", async () => {
  const errorStream = new Readable({ read() { this.destroy(new Error("provider detail")); } });
  await assert.rejects(
    readSetupEnrollmentInvitationStdin({ input: errorStream, enrollmentUrl: ENROLLMENT_URL }),
    (error) => error.code === SETUP_STDIN_DELIVERY_ERRORS.READ && !error.message.includes("provider detail")
  );

  const pending = new Readable({ read() {} });
  await assert.rejects(
    readSetupEnrollmentInvitationStdin({ input: pending, enrollmentUrl: ENROLLMENT_URL, timeoutMs: 100 }),
    (error) => error.code === SETUP_STDIN_DELIVERY_ERRORS.TIMEOUT
  );
});
