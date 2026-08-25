import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import {
  createManagedSignerKeyLifecycle,
  createManagedSignerLifecycleProvider,
  MANAGED_SIGNER_KEY_LIFECYCLE_ERROR_CODES as CODES,
  MANAGED_SIGNER_KEY_STATES as STATES,
  parseManagedSignerKeyLifecycleSnapshot
} from "../src/managed-signer-key-lifecycle.mjs";

const PURPOSE = "agentpass.test-signer";
const NOW = Date.parse("2026-08-14T00:00:00.000Z");

function key(id, version, state = STATES.ACTIVE, stateVersion = 1, pair = crypto.generateKeyPairSync("ed25519"), extra = {}) {
  const publicKey = pair.publicKey;
  const publicKeyPem = publicKey.export({ type: "spki", format: "pem" }).toString();
  const fingerprint = crypto.createHash("sha256").update(publicKey.export({ type: "spki", format: "der" })).digest("hex");
  return {
    key_id: id,
    key_version: version,
    purpose: PURPOSE,
    algorithm: "ed25519",
    public_key: publicKeyPem,
    public_key_fingerprint: fingerprint,
    state,
    state_version: stateVersion,
    ...extra,
    __pair: pair
  };
}

function record(value) {
  const { __pair: _pair, ...result } = value;
  return result;
}

function lifecycle({ active = key("key-1", 1), extras = [], now = NOW } = {}) {
  const { __pair: _activePair, ...activeRecord } = active;
  const records = [activeRecord, ...extras.map(({ __pair: _pair, ...record }) => record)];
  return {
    value: createManagedSignerKeyLifecycle({
      purpose: PURPOSE,
      snapshot: { version: 1, purpose: PURPOSE, algorithm: "ed25519", keys: records },
      now: () => now
    }),
    active
  };
}

function later(minutes = 60) {
  return new Date(NOW + minutes * 60 * 1000).toISOString();
}

test("enforces public-only purpose-bound lifecycle configuration", () => {
  const active = key("key-1", 1);
  const { value } = lifecycle({ active });
  assert.deepEqual(value.activeKey(), {
    key_id: "key-1",
    key_version: 1,
    purpose: PURPOSE,
    algorithm: "ed25519",
    public_key: active.public_key,
    public_key_fingerprint: active.public_key_fingerprint,
    state: STATES.ACTIVE,
    state_version: 1
  });
  assert.throws(() => value.assertCanSign("missing"), { code: CODES.CONFIG });
  assert.throws(() => createManagedSignerKeyLifecycle({
    purpose: PURPOSE,
    snapshot: { version: 1, purpose: "other", algorithm: "ed25519", keys: [] }
  }), { code: CODES.CONFIG });
  assert.throws(() => parseManagedSignerKeyLifecycleSnapshot({
    version: 1,
    purpose: PURPOSE,
    algorithm: "ed25519",
    keys: [{ ...record(active), public_key: active.__pair.privateKey.export({ type: "pkcs8", format: "pem" }).toString() }]
  }, { now: () => NOW }), { code: CODES.CONFIG });
  assert.throws(() => parseManagedSignerKeyLifecycleSnapshot({
    version: 1,
    purpose: PURPOSE,
    algorithm: "ed25519",
    keys: [{ ...record(active), private_key: "forbidden" }]
  }, { now: () => NOW }), { code: CODES.CONFIG });
});

test("rotates atomically, bounds verification overlap, and never signs with retiring keys", () => {
  const initial = lifecycle();
  const next = key("key-2", 2);
  const rotated = initial.value.rotate({
    expected_version: 1,
    operation_id: "rotate-1",
    new_key: record(next),
    verification_until: later(60)
  });
  assert.equal(rotated.version, 2);
  assert.deepEqual(rotated.keys.map(({ key_id, state, state_version }) => ({ key_id, state, state_version })), [
    { key_id: "key-1", state: STATES.RETIRING, state_version: 2 },
    { key_id: "key-2", state: STATES.ACTIVE, state_version: 2 }
  ]);
  assert.throws(() => initial.value.assertCanSign("key-1"), { code: CODES.NOT_ACTIVE });
  assert.equal(initial.value.resolveVerificationKey("key-1").state, STATES.RETIRING);
  assert.equal(initial.value.assertCanSign("key-2").state, STATES.ACTIVE);
  assert.throws(() => initial.value.resolveVerificationKey("key-1", NOW + 60 * 60 * 1000), { code: CODES.NOT_VERIFIABLE });
  assert.throws(() => initial.value.rotate({
    expected_version: 2,
    operation_id: "rotate-too-far",
    new_key: record(key("key-3", 3)),
    verification_until: new Date(NOW + 91 * 24 * 60 * 60 * 1000).toISOString()
  }), { code: CODES.OVERLAP });
});

test("later rotations retain every historical verification key", () => {
  const value = lifecycle().value;
  value.rotate({
    expected_version: 1,
    operation_id: "rotate-1",
    new_key: record(key("key-2", 2)),
    verification_until: later(30)
  });
  const result = value.rotate({
    expected_version: 2,
    operation_id: "rotate-2",
    new_key: record(key("key-3", 3)),
    verification_until: later(45)
  });
  assert.deepEqual(result.keys.map(({ key_id, state }) => ({ key_id, state })), [
    { key_id: "key-1", state: STATES.RETIRING },
    { key_id: "key-2", state: STATES.RETIRING },
    { key_id: "key-3", state: STATES.ACTIVE }
  ]);
  assert.equal(value.resolveVerificationKey("key-1").key_id, "key-1");
  assert.equal(value.resolveVerificationKey("key-2").key_id, "key-2");
});

test("transitions are monotonic, version guarded, and idempotent", () => {
  const value = lifecycle().value;
  const first = value.transitionKey({
    expected_version: 1,
    operation_id: "retire-1",
    key_id: "key-1",
    to: STATES.RETIRING,
    verification_until: later(10)
  });
  assert.equal(first.version, 2);
  assert.deepEqual(value.transitionKey({
    expected_version: 1,
    operation_id: "retire-1",
    key_id: "key-1",
    to: STATES.RETIRING,
    verification_until: later(10)
  }), first);
  assert.throws(() => value.transitionKey({
    expected_version: 1,
    operation_id: "retire-1",
    key_id: "key-1",
    to: STATES.REVOKED
  }), { code: CODES.IDEMPOTENCY });
  assert.throws(() => value.transitionKey({
    expected_version: 1,
    operation_id: "stale",
    key_id: "key-1",
    to: STATES.REVOKED
  }), { code: CODES.VERSION });
  assert.throws(() => value.transitionKey({
    expected_version: 2,
    operation_id: "backward",
    key_id: "key-1",
    to: STATES.ACTIVE
  }), { code: CODES.TRANSITION });
  const revoked = value.transitionKey({ expected_version: 2, operation_id: "revoke-1", key_id: "key-1", to: STATES.REVOKED });
  assert.equal(revoked.version, 3);
  assert.throws(() => value.assertCanSign("key-1"), { code: CODES.NOT_ACTIVE });
  assert.throws(() => value.resolveVerificationKey("key-1"), { code: CODES.NOT_VERIFIABLE });
});

test("retains expired retiring metadata for cleanup but never verifies it", () => {
  const active = key("key-2", 2, STATES.ACTIVE, 2);
  const retired = key("key-1", 1, STATES.RETIRING, 1, crypto.generateKeyPairSync("ed25519"), { verification_until: new Date(NOW - 1).toISOString() });
  const value = createManagedSignerKeyLifecycle({
    purpose: PURPOSE,
    snapshot: {
      version: 2,
      purpose: PURPOSE,
      algorithm: "ed25519",
      keys: [
        (({ __pair: _pair, ...record }) => record)(active),
        (({ __pair: _pair, ...record }) => record)(retired)
      ]
    },
    now: () => NOW
  });
  assert.throws(() => value.resolveVerificationKey("key-1"), { code: CODES.NOT_VERIFIABLE });
  const cleaned = value.transitionKey({ expected_version: 2, operation_id: "cleanup-1", key_id: "key-1", to: STATES.REVOKED });
  assert.equal(cleaned.version, 3);
  assert.equal(cleaned.keys.find(({ key_id }) => key_id === "key-1").state, STATES.REVOKED);
});

test("emergency disable is atomic and restore requires a newer key version", () => {
  const initial = lifecycle();
  const disabled = initial.value.emergencyDisable({ expected_version: 1, operation_id: "emergency-1" });
  assert.equal(disabled.version, 2);
  assert.equal(disabled.keys[0].state, STATES.EMERGENCY_DISABLED);
  assert.throws(() => initial.value.assertCanSign("key-1"), { code: CODES.NOT_ACTIVE });
  const restored = initial.value.restore({
    expected_version: 2,
    operation_id: "restore-1",
    new_key: record(key("key-2", 2))
  });
  assert.equal(restored.version, 3);
  assert.equal(initial.value.activeKey().key_id, "key-2");
  assert.equal(initial.value.snapshot().keys[0].state, STATES.EMERGENCY_DISABLED);
});

test("lifecycle provider strips idempotency controls, replays exact bytes, and blocks after rotation", async () => {
  const initial = lifecycle();
  let calls = 0;
  const provider = createManagedSignerLifecycleProvider({
    lifecycle: initial.value,
    provider: {
      key_id: "key-1",
      purpose: PURPOSE,
      algorithm: "ed25519",
      version: 1,
      public_key_fingerprint: initial.active.public_key_fingerprint,
      async publicKeyMetadata() { return { ok: true }; },
      async sign(input) {
        calls += 1;
        assert.equal(Object.hasOwn(input, "idempotency_key"), false);
        return Buffer.from(input.bytes).reverse();
      }
    }
  });
  const first = await provider.sign({ bytes: Buffer.from("same"), idempotency_key: "request-1" });
  const second = await provider.sign({ bytes: Buffer.from("same"), idempotency_key: "request-1" });
  assert.deepEqual(second, first);
  assert.equal(calls, 1);
  await assert.rejects(provider.sign({ bytes: Buffer.from("different"), idempotency_key: "request-1" }), { code: CODES.IDEMPOTENCY });
  await assert.rejects(provider.sign({ bytes: Buffer.from("same"), idempotency_key: "request-1", unexpected: true }), { code: CODES.CONFIG });
  initial.value.rotate({ expected_version: 1, operation_id: "rotate-1", new_key: record(key("key-2", 2)), verification_until: later(10) });
  await assert.rejects(provider.sign({ bytes: Buffer.from("after") }), { code: CODES.NOT_ACTIVE });
});
