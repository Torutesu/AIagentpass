import assert from "node:assert/strict";
import test from "node:test";

import {
  normalizeDeviceReadModel,
  normalizeDeviceReadModels
} from "../src/device-read-model.mjs";

const organizationId = "11111111-1111-4111-8111-111111111111";
const deviceId = "22222222-2222-4222-8222-222222222222";
const publicKey = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==\n-----END PUBLIC KEY-----";

function model(overrides = {}) {
  return {
    device_id: deviceId,
    organization_id: organizationId,
    name: "Build Mac",
    device_public_key: publicKey,
    key_algorithm: "ed25519",
    status: "active",
    metadata: { environment: "prod" },
    created_at: "2026-08-12T00:00:00.000Z",
    last_seen_at: null,
    version: 1,
    desired_generation: 7,
    observed_generation: 6,
    refresh_state: "applied",
    current_bundle_sequence: 12,
    current_bundle_expires_at: "2026-08-12T00:15:00.000Z",
    last_ack_observed_at: "2026-08-12T00:01:00.000Z",
    last_ack_received_at: "2026-08-12T00:01:01.000Z",
    blocked_reason: null,
    ...overrides
  };
}

test("normalizes the closed public device read model", () => {
  const result = normalizeDeviceReadModel(model());
  assert.equal(Object.isFrozen(result), true);
  assert.equal(result.desired_generation, 7);
  assert.equal(result.bundle_sequence, 12);
  assert.equal(result.bundle_expires_at, "2026-08-12T00:15:00.000Z");
  assert.equal(result.last_ack_at, "2026-08-12T00:01:01.000Z");
  assert.equal(Object.hasOwn(result, "organization_id"), false);
  assert.equal(Object.hasOwn(result, "device_public_key"), false);
  assert.equal(Object.hasOwn(result, "metadata"), false);
  assert.equal(Object.hasOwn(result, "signature"), false);
  assert.equal(Object.hasOwn(result, "nonce"), false);
  assert.equal(Object.hasOwn(result, "policy"), false);
});

test("rejects fields and state combinations outside the public contract", () => {
  for (const invalid of [
    { signature: "not-public" },
    { nonce: "not-public" },
    { policy: { operations: ["git.commit.sign"] } },
    { refresh_state: "blocked", blocked_reason: null },
    { refresh_state: "applied", blocked_reason: "internal_error" },
    { desired_generation: 2, observed_generation: 3 },
    { current_bundle_sequence: null, current_bundle_expires_at: "2026-08-12T00:15:00Z" },
    { device_public_key: "-----BEGIN PRIVATE KEY-----secret-----END PRIVATE KEY-----" }
  ]) {
    assert.throws(() => normalizeDeviceReadModel(model(invalid)), { code: "ERR_DEVICE_READ_MODEL" });
  }
});

test("requires stable blocked reasons and unique tenant-scoped devices", () => {
  assert.throws(() => normalizeDeviceReadModel(model({ refresh_state: "blocked" })), { code: "ERR_DEVICE_READ_MODEL" });
  assert.throws(() => normalizeDeviceReadModels([model(), model()]), { code: "ERR_DEVICE_READ_MODEL" });
  assert.throws(() => normalizeDeviceReadModel(model({ organization_id: "not-a-uuid" })), { code: "ERR_DEVICE_READ_MODEL" });
});
