import assert from "node:assert/strict";
import test from "node:test";

import {
  RefreshNonceCodecError,
  createRefreshNonceCodec,
  timingSafeRefreshNonceDigestEqual
} from "../../src/postgres/refresh-nonce-codec.mjs";

const INPUT = Object.freeze({
  organization_id: "11111111-1111-4111-8111-111111111111",
  device_id: "44444444-4444-4444-8444-444444444444",
  authority_generation: 42,
  outbox_id: "88888888-8888-4888-8888-888888888888"
});
const V1_KEY = Buffer.alloc(32, 0x11);
const V3_KEY = Buffer.alloc(32, 0x33);

function codec(activeKeyId = "refresh-nonce-v3") {
  return createRefreshNonceCodec({
    keys: { "refresh-nonce-v1": V1_KEY, "refresh-nonce-v3": V3_KEY },
    activeKeyId
  });
}

test("HMAC-SHA256 derivation has a stable known answer and exactly 16 nonce bytes", () => {
  const derived = codec("refresh-nonce-v1").derive({ ...INPUT, key_id: "refresh-nonce-v1" });
  assert.equal(derived.nonce_base64url, "r-dwOWTU99RYMbjIvHGEBw");
  assert.equal(derived.nonce_digest, "d80ce49d6d40ca3d7d3f60672e5b718147d6a51059764e840f761b07890cb764");
  assert.equal(derived.nonce.length, 16);
  assert.equal(derived.nonce_digest_bytes.length, 32);
  assert.equal(codec("refresh-nonce-v1").matchesDigest(derived, derived.nonce_digest), true);
});

test("rotation is dual-read/single-write and the configured key ring, not the schema, is the allow-list", () => {
  const oldCodec = codec("refresh-nonce-v1");
  const newCodec = codec("refresh-nonce-v3");
  const oldValue = oldCodec.derive({ ...INPUT, key_id: "refresh-nonce-v1" });
  const newValue = newCodec.derive({ ...INPUT });
  assert.notEqual(oldValue.nonce_digest, newValue.nonce_digest);
  assert.equal(newValue.key_id, "refresh-nonce-v3");
  assert.equal(newCodec.derive({ ...INPUT, key_id: "refresh-nonce-v1" }).nonce_digest, oldValue.nonce_digest);
  assert.throws(() => newCodec.derive({ ...INPUT, key_id: "refresh-nonce-v4" }), (error) => error instanceof RefreshNonceCodecError && error.code === "ERR_REFRESH_NONCE_KEY_UNAVAILABLE");
});

test("restart reconstructs the same nonce from the persisted tuple and old key", () => {
  const first = codec().derive({ ...INPUT, key_id: "refresh-nonce-v1" });
  const afterRestart = createRefreshNonceCodec({ keys: { "refresh-nonce-v1": Buffer.from(V1_KEY) }, activeKeyId: "refresh-nonce-v1" })
    .derive({ ...INPUT, key_id: "refresh-nonce-v1" });
  assert.deepEqual(afterRestart.nonce, first.nonce);
  assert.equal(afterRestart.nonce_digest, first.nonce_digest);
});

test("tenant, device, generation, and outbox substitution changes the nonce", () => {
  const base = codec().derive(INPUT);
  for (const field of ["organization_id", "device_id", "outbox_id"]) {
    const replacement = field === "organization_id"
      ? "22222222-2222-4222-8222-222222222222"
      : "99999999-9999-4999-8999-999999999999";
    assert.notEqual(codec().derive({ ...INPUT, [field]: replacement }).nonce_digest, base.nonce_digest, field);
  }
  assert.notEqual(codec().derive({ ...INPUT, authority_generation: 43 }).nonce_digest, base.nonce_digest);
});

test("malformed tuples and exact key-id aliases fail closed", () => {
  assert.throws(() => codec().derive({ ...INPUT, organization_id: "not-a-uuid" }), { code: "ERR_REFRESH_NONCE_INPUT" });
  assert.throws(() => codec().derive({ ...INPUT, authority_generation: 0 }), { code: "ERR_REFRESH_NONCE_INPUT" });
  assert.throws(() => codec().derive({ ...INPUT, key_id: "REFRESH-NONCE-V3" }), { code: "ERR_REFRESH_NONCE_KEY_ID" });
  assert.throws(() => createRefreshNonceCodec({ keys: { "refresh-nonce-v0": V1_KEY }, activeKeyId: "refresh-nonce-v0" }), { code: "ERR_REFRESH_NONCE_KEY_ID" });
});

test("raw nonce is not enumerable or JSON/log output, and digest comparison is timing-safe", () => {
  const derived = codec().derive(INPUT);
  const raw = derived.nonce_base64url;
  const serialized = JSON.stringify(derived);
  assert.equal(serialized.includes(raw), false);
  assert.equal(Object.keys(derived).includes("nonce"), false);
  assert.equal(timingSafeRefreshNonceDigestEqual(derived.nonce_digest_bytes, derived.nonce_digest), true);
  assert.equal(timingSafeRefreshNonceDigestEqual(derived.nonce_digest_bytes, `${"0".repeat(63)}1`), false);
  assert.equal(timingSafeRefreshNonceDigestEqual(derived.nonce_digest_bytes, "malformed"), false);
});
