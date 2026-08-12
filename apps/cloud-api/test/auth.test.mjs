import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import assert from "node:assert/strict";
import {
  AUTH_ERROR_CODES,
  AuthError,
  authenticateApiToken,
  canonicalDeviceRequest,
  createApiTokenRecord,
  createReplayCache,
  createPersistentReplayCache,
  requireOrganizationRole,
  roleAllows,
  sha256,
  signDeviceRequest,
  verifyApiToken,
  verifyDeviceRequest
} from "../src/auth.mjs";

test("persistent replay cache rejects a nonce after process-style restart", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "agentpass-replay-"));
  fs.chmodSync(directory, 0o700);
  const file = path.join(directory, "replay.json");
  const first = createPersistentReplayCache(file, 10);
  first.set("device:nonce", Date.now() + 60_000);
  const restarted = createPersistentReplayCache(file, 10);
  assert.equal(restarted.has("device:nonce"), true);
  assert.equal(fs.statSync(file).mode & 0o777, 0o600);
  fs.rmSync(directory, { recursive: true, force: true });
});

function deviceFixture() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  const device = { device_id: "device-1", organization_id: "org-1", public_key: publicKey };
  const request = { method: "post", path: "/v1/organizations/org-1/audit/events?z=last&a=first", body: "{\"event\":1}", device_id: device.device_id, timestamp: 1_700_000_000_000, nonce: "nonce-abcdefghijklmnopqrstuvwxyz-1234567890" };
  const headers = signDeviceRequest(request, privateKey);
  return { privateKey, device, request, headers };
}

function verify(fixture, overrides = {}, options = {}) {
  const request = { ...fixture.request, ...overrides };
  const headers = { ...fixture.headers, ...(overrides.headers ?? {}) };
  return verifyDeviceRequest({ ...request, headers }, [fixture.device], { now: 1_700_000_000_000, replayCache: options.replayCache ?? createReplayCache() });
}

test("verifies canonical device signatures and rejects replay", () => {
  const fixture = deviceFixture();
  const cache = createReplayCache();
  assert.deepEqual(verifyDeviceRequest({ ...fixture.request, headers: fixture.headers }, [fixture.device], { now: fixture.request.timestamp, replayCache: cache }), { device_id: "device-1", organization_id: "org-1" });
  assert.throws(() => verifyDeviceRequest({ ...fixture.request, headers: fixture.headers }, [fixture.device], { now: fixture.request.timestamp, replayCache: cache }), (error) => error instanceof AuthError && error.code === AUTH_ERROR_CODES.REPLAY_DETECTED);
});

test("supports Secure Enclave-compatible P-256 device authentication", () => {
  const keys = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const device = { device_id: "secure-enclave-device", organization_id: "org-a", public_key: keys.publicKey.export({ type: "spki", format: "pem" }).toString() };
  const request = { method: "GET", path: "/v1/control", body: Buffer.alloc(0), device_id: device.device_id, timestamp: 1_800_000_000_000, nonce: "nonce-secure-enclave-abcdefghijklmnopqrstuvwxyz" };
  const headers = signDeviceRequest(request, keys.privateKey);
  assert.deepEqual(verifyDeviceRequest({ method: request.method, path: request.path, body: request.body, headers }, [device], { organizationId: "org-a", now: request.timestamp }), { device_id: device.device_id, organization_id: "org-a" });
  const tampered = { ...headers, "AgentPass-Signature": Buffer.alloc(64).toString("base64") };
  assert.throws(() => verifyDeviceRequest({ method: request.method, path: request.path, body: request.body, headers: tampered }, [device], { organizationId: "org-a", now: request.timestamp }), { code: "device_auth_failed" });
});

test("keeps replay state bounded and accepts the cloud verifier config shape", () => {
  const fixture = deviceFixture();
  const cache = createReplayCache(1);
  assert.deepEqual(verifyDeviceRequest({ ...fixture.request, headers: fixture.headers }, { devices: [fixture.device], replayCache: cache, now: fixture.request.timestamp }), { device_id: "device-1", organization_id: "org-1" });
  const next = { ...fixture.request, nonce: "nonce-zyxwvutsrqponmlkjihgfedcba-0987654321" };
  const nextHeaders = signDeviceRequest(next, fixture.privateKey);
  assert.throws(() => verifyDeviceRequest({ ...next, headers: nextHeaders }, { devices: [fixture.device], replayCache: cache, now: next.timestamp }), (error) => error.code === AUTH_ERROR_CODES.REPLAY_CACHE_FULL);
});

test("rejects body, path, and query substitution", () => {
  const fixture = deviceFixture();
  for (const mutation of [
    { body: "{\"event\":2}" },
    { path: "/v1/organizations/org-2/audit/events?z=last&a=first" },
    { path: "/v1/organizations/org-1/audit/events?a=first&z=changed" }
  ]) {
    assert.throws(() => verify(fixture, mutation), (error) => error instanceof AuthError && [AUTH_ERROR_CODES.BODY_DIGEST_MISMATCH, AUTH_ERROR_CODES.DEVICE_AUTH_FAILED].includes(error.code));
  }
  assert.equal(canonicalDeviceRequest({ ...fixture.request, method: "POST" }), canonicalDeviceRequest({ ...fixture.request, method: "post" }));
  assert.equal(sha256(fixture.request.body).length, 64);
});

test("rejects bad clocks, wrong device, wrong key, and malformed headers", () => {
  const fixture = deviceFixture();
  assert.throws(() => verifyDeviceRequest({ ...fixture.request, headers: fixture.headers }, [fixture.device], { now: fixture.request.timestamp + 60_001 }), (error) => error.code === AUTH_ERROR_CODES.CLOCK_SKEW);
  assert.throws(() => verify(fixture, { headers: { "AgentPass-Device": "device-2" } }), (error) => error.code === AUTH_ERROR_CODES.DEVICE_AUTH_FAILED);

  const other = crypto.generateKeyPairSync("ed25519");
  const wrongKeyHeaders = signDeviceRequest(fixture.request, other.privateKey);
  assert.throws(() => verifyDeviceRequest({ ...fixture.request, headers: wrongKeyHeaders }, [fixture.device], { now: fixture.request.timestamp }), (error) => error.code === AUTH_ERROR_CODES.DEVICE_AUTH_FAILED);
  assert.throws(() => verifyDeviceRequest({ ...fixture.request, headers: { ...fixture.headers, "AgentPass-Nonce": ` ${fixture.headers["AgentPass-Nonce"]}` } }, [fixture.device], { now: fixture.request.timestamp }), (error) => error.code === AUTH_ERROR_CODES.INVALID_HEADERS);
});

test("scrypt token records verify without storing or returning the bearer token", () => {
  const token = "ap_test_token_that_is_long_enough";
  const record = createApiTokenRecord({ token, tokenId: "token-1", organizationId: "org-1", memberId: "member-1", role: "auditor" });
  assert.equal(record.token_hash.includes(token), false);
  assert.equal(verifyApiToken(token, record.token_hash), true);
  assert.equal(verifyApiToken("ap_wrong_token_that_is_long_enough", record.token_hash), false);
  const principal = authenticateApiToken(token, [record]);
  assert.deepEqual(principal, { token_id: "token-1", organization_id: "org-1", member_id: "member-1", role: "auditor" });
  assert.equal(Object.hasOwn(principal, "token_hash"), false);
  assert.throws(() => authenticateApiToken("ap_wrong_token_that_is_long_enough", [record]), (error) => error.code === AUTH_ERROR_CODES.INVALID_TOKEN);
});

test("enforces organization role hierarchy and tenant binding", () => {
  assert.equal(roleAllows("owner", "admin"), true);
  assert.equal(roleAllows("auditor", "admin"), false);
  const principal = { organization_id: "org-1", member_id: "member-1", role: "admin" };
  assert.deepEqual(requireOrganizationRole(principal, "org-1", "auditor"), principal);
  assert.throws(() => requireOrganizationRole(principal, "org-1", "owner"), (error) => error.code === AUTH_ERROR_CODES.ROLE_DENIED);
  assert.throws(() => requireOrganizationRole(principal, "org-2", "viewer"), (error) => error.code === AUTH_ERROR_CODES.ORGANIZATION_MISMATCH);
});
