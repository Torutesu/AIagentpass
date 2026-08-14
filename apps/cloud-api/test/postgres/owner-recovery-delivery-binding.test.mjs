import assert from "node:assert/strict";
import test from "node:test";

import {
  createOwnerRecoveryDeliveryBinding,
  normalizeOwnerRecoveryDeliveryBinding,
  sameOwnerRecoveryDeliveryBinding
} from "../../src/postgres/owner-recovery-delivery-binding.mjs";

test("delivery binding is deterministic, secret-free, and namespace-sensitive", () => {
  const first = createOwnerRecoveryDeliveryBinding({ binding_id: "hosted-owner-recovery", key_version: 1, namespace: "https://notify.example.test/v1" });
  const same = createOwnerRecoveryDeliveryBinding({ binding_id: "hosted-owner-recovery", key_version: 1, namespace: "https://notify.example.test/v1" });
  const changed = createOwnerRecoveryDeliveryBinding({ binding_id: "hosted-owner-recovery", key_version: 1, namespace: "https://notify.example.test/v2" });
  assert.deepEqual(first, same);
  assert.notEqual(first.binding_digest, changed.binding_digest);
  assert.deepEqual(Object.keys(first).sort(), ["binding_digest", "binding_id", "key_version"]);
  assert.equal(JSON.stringify(first).includes("notify.example.test"), false);
});

test("delivery binding rejects malformed identity, version, digest, and extra fields", () => {
  for (const value of [
    { binding_id: "UPPER", key_version: 1, binding_digest: "a".repeat(64) },
    { binding_id: "valid", key_version: 0, binding_digest: "a".repeat(64) },
    { binding_id: "valid", key_version: 1, binding_digest: "A".repeat(64) },
    { binding_id: "valid", key_version: 1, binding_digest: "a".repeat(64), secret: "x" }
  ]) assert.throws(() => normalizeOwnerRecoveryDeliveryBinding(value), TypeError);
});

test("delivery binding equality is exact and fails closed", () => {
  const binding = { binding_id: "valid", key_version: 2, binding_digest: "b".repeat(64) };
  assert.equal(sameOwnerRecoveryDeliveryBinding(binding, { ...binding }), true);
  assert.equal(sameOwnerRecoveryDeliveryBinding(binding, { ...binding, key_version: 3 }), false);
  assert.equal(sameOwnerRecoveryDeliveryBinding(binding, null), false);
});
