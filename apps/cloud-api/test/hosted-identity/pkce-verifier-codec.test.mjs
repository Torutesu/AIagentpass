import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import {
  PKCE_VERIFIER_CODEC_ERROR_CODES,
  PKCE_VERIFIER_CODEC_NONCE_BYTES,
  PkceVerifierCodecError,
  createPkceVerifierCodec
} from "../../src/hosted-identity/pkce-verifier-codec.mjs";

const KEY_ID = "hosted-pkce-v1";
const KEY = Buffer.alloc(32, 0x31);
const OTHER_KEY = Buffer.alloc(32, 0x32);
const BINDING = Object.freeze({
  attemptId: "11111111-1111-4111-8111-111111111111",
  oauthStateId: "22222222-2222-4222-8222-222222222222",
  redirectUri: "https://console.example.test/api/auth/bootstrap/github/callback",
  expiresAt: 1_900_000_000_000
});
const VERIFIER = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~";

function codec({ key = KEY, randomBytes = crypto.randomBytes, now = () => 1_800_000_000_000 } = {}) {
  return createPkceVerifierCodec({
    activeKeyId: KEY_ID,
    keyResolver: (keyId) => keyId === KEY_ID ? key : undefined,
    randomBytes,
    now
  });
}

function seal(value = VERIFIER, options = {}) {
  return codec(options).seal({ verifier: value, ...BINDING });
}

function envelopeParts(serialized) {
  return JSON.parse(serialized);
}

function withEnvelopePatch(serialized, patch) {
  const value = envelopeParts(serialized);
  return JSON.stringify({ ...value, ...patch });
}

test("seals and opens an immutable verifier with a closed envelope", () => {
  let randomLength;
  const instance = codec({
    randomBytes(length) {
      randomLength = length;
      return Buffer.alloc(length, 0x44);
    }
  });
  const serialized = instance.seal({ verifier: VERIFIER, ...BINDING });
  const envelope = envelopeParts(serialized);

  assert.equal(randomLength, PKCE_VERIFIER_CODEC_NONCE_BYTES);
  assert.deepEqual(Object.keys(envelope), ["version", "key_id", "nonce", "ciphertext", "tag"]);
  assert.equal(serialized.includes(VERIFIER), false);
  assert.equal(Object.isFrozen(instance), true);
  const result = instance.open(serialized, BINDING);
  assert.deepEqual(result, { verifier: VERIFIER });
  assert.equal(Object.isFrozen(result), true);
  assert.equal(Object.isFrozen(BINDING), true);
});

test("uses a fresh random nonce for each encryption", () => {
  let counter = 0;
  const instance = codec({
    randomBytes(length) {
      counter += 1;
      return Buffer.alloc(length, counter);
    }
  });
  const first = envelopeParts(instance.seal({ verifier: VERIFIER, ...BINDING }));
  const second = envelopeParts(instance.seal({ verifier: VERIFIER, ...BINDING }));
  assert.notEqual(first.nonce, second.nonce);
  assert.equal(counter, 2);
});

test("rejects ciphertext, tag, nonce, key id, and version tampering", () => {
  const serialized = seal();
  const envelope = envelopeParts(serialized);
  const cases = [
    ["ciphertext", withEnvelopePatch(serialized, { ciphertext: flipLastByte(envelope.ciphertext) })],
    ["tag", withEnvelopePatch(serialized, { tag: flipLastByte(envelope.tag) })],
    ["nonce", withEnvelopePatch(serialized, { nonce: flipLastByte(envelope.nonce) })],
    ["key id", withEnvelopePatch(serialized, { key_id: "other-key" })],
    ["version", withEnvelopePatch(serialized, { version: 2 })]
  ];
  for (const [name, tampered] of cases) {
    assert.throws(() => codec().open(tampered, BINDING), (error) => {
      assert.equal(error instanceof PkceVerifierCodecError, true, name);
      return error.code === PKCE_VERIFIER_CODEC_ERROR_CODES.ENVELOPE_INVALID;
    });
  }
});

test("rejects an unknown envelope field, duplicate field, whitespace, and non-canonical base64url", () => {
  const serialized = seal();
  const envelope = envelopeParts(serialized);
  for (const candidate of [
    withEnvelopePatch(serialized, { extra: "rejected" }),
    serialized.replace("\"tag\"", "\"tag\":\"duplicate\",\"tag\""),
    ` ${serialized}`,
    withEnvelopePatch(serialized, { nonce: `${envelope.nonce}=` })
  ]) {
    assert.throws(() => codec().open(candidate, BINDING), (error) => error.code === PKCE_VERIFIER_CODEC_ERROR_CODES.ENVELOPE_INVALID);
  }
});

test("rejects a wrong key and every binding mismatch", () => {
  const serialized = seal();
  assert.throws(() => codec({ key: OTHER_KEY }).open(serialized, BINDING), (error) => error.code === PKCE_VERIFIER_CODEC_ERROR_CODES.ENVELOPE_INVALID);
  for (const field of ["attemptId", "oauthStateId", "redirectUri", "expiresAt"]) {
    const binding = { ...BINDING, [field]: field === "expiresAt" ? BINDING.expiresAt + 1 : field === "attemptId" ? "33333333-3333-4333-8333-333333333333" : field === "oauthStateId" ? "44444444-4444-4444-8444-444444444444" : `${BINDING[field]}-wrong` };
    assert.throws(() => codec().open(serialized, binding), (error) => error.code === PKCE_VERIFIER_CODEC_ERROR_CODES.ENVELOPE_INVALID, field);
  }
});

test("rejects an expired verifier using the injected clock", () => {
  const serialized = seal();
  assert.throws(
    () => codec({ now: () => BINDING.expiresAt }).open(serialized, BINDING),
    (error) => error.code === PKCE_VERIFIER_CODEC_ERROR_CODES.EXPIRED
  );
});

test("rejects malformed or unknown-field seal and binding inputs", () => {
  for (const input of [
    { verifier: VERIFIER, ...BINDING, unknown: true },
    { verifier: VERIFIER, ...BINDING, expiresAt: "1900000000000" },
    { verifier: "short", ...BINDING },
    { verifier: VERIFIER, ...BINDING, redirectUri: "http://console.example.test/callback" }
  ]) {
    assert.throws(() => codec().seal(input), (error) => error.code === PKCE_VERIFIER_CODEC_ERROR_CODES.INPUT_INVALID);
  }
  assert.throws(() => codec().open(seal(), { ...BINDING, unknown: true }), (error) => error.code === PKCE_VERIFIER_CODEC_ERROR_CODES.INPUT_INVALID);
});

test("enforces RFC 7636 verifier and serialized envelope size boundaries", () => {
  for (const length of [42, 129]) {
    assert.throws(
      () => codec().seal({ verifier: "A".repeat(length), ...BINDING }),
      (error) => error.code === PKCE_VERIFIER_CODEC_ERROR_CODES.INPUT_INVALID
    );
  }
  for (const length of [43, 128]) {
    const serialized = codec().seal({ verifier: "A".repeat(length), ...BINDING });
    assert.equal(codec().open(serialized, BINDING).verifier.length, length);
  }
  const serialized = seal();
  assert.throws(() => codec().open(serialized.slice(0, -1), BINDING), (error) => error.code === PKCE_VERIFIER_CODEC_ERROR_CODES.ENVELOPE_INVALID);
  assert.throws(
    () => createPkceVerifierCodec({ activeKeyId: KEY_ID, keyResolver: () => KEY, maxSerializedBytes: 511 }),
    (error) => error.code === PKCE_VERIFIER_CODEC_ERROR_CODES.CONFIG_INVALID
  );
});

test("maps random source failures and invalid random output to stable redacted errors", () => {
  for (const randomBytes of [
    () => { throw new Error("random-secret-value"); },
    () => Buffer.alloc(PKCE_VERIFIER_CODEC_NONCE_BYTES - 1)
  ]) {
    assert.throws(
      () => codec({ randomBytes }).seal({ verifier: VERIFIER, ...BINDING }),
      (error) => error.code === PKCE_VERIFIER_CODEC_ERROR_CODES.RANDOMNESS_UNAVAILABLE
        && !String(error).includes("random-secret-value")
    );
  }
});

test("never includes key material, verifier, bindings, or provider errors in stable failures", () => {
  const secretKey = Buffer.from("key-material-that-must-not-escape-0123456789").subarray(0, 32);
  const secretVerifier = "A".repeat(43);
  const secretBinding = { ...BINDING, attemptId: "55555555-5555-4555-8555-555555555555" };
  let resolverFails = false;
  const instance = createPkceVerifierCodec({
    activeKeyId: "secret-key-id",
    keyResolver() {
      if (resolverFails) throw new Error("resolver-key-material");
      return secretKey;
    },
    now: () => 1_800_000_000_000
  });
  resolverFails = true;
  assert.throws(
    () => instance.seal({ verifier: secretVerifier, ...secretBinding }),
    (error) => error.code === PKCE_VERIFIER_CODEC_ERROR_CODES.KEY_UNAVAILABLE
      && !String(error).includes("resolver-key-material")
      && !String(error).includes(secretVerifier)
      && !String(error).includes(secretBinding.attemptId)
      && !String(error).includes(secretKey.toString())
  );
  const stableCodes = new Set();
  for (const candidate of ["not-json", withEnvelopePatch(seal(), { version: 2 })]) {
    try { codec().open(candidate, BINDING); } catch (error) { stableCodes.add(`${error.code}:${error.message}`); }
  }
  assert.deepEqual(stableCodes, new Set([[PKCE_VERIFIER_CODEC_ERROR_CODES.ENVELOPE_INVALID, "PKCE verifier envelope is invalid"].join(":")]));
});

test("copies byte keys and rejects invalid configuration without leaking resolver details", () => {
  const mutableKey = Buffer.alloc(32, 0x55);
  const instance = createPkceVerifierCodec({ activeKeyId: KEY_ID, keyResolver: () => mutableKey });
  mutableKey.fill(0);
  const serialized = instance.seal({ verifier: VERIFIER, ...BINDING });
  assert.equal(instance.open(serialized, BINDING).verifier, VERIFIER);
  assert.throws(
    () => createPkceVerifierCodec({ activeKeyId: KEY_ID, keyResolver: () => Buffer.alloc(31) }),
    (error) => error.code === PKCE_VERIFIER_CODEC_ERROR_CODES.KEY_UNAVAILABLE && !String(error).includes("31")
  );
});

function flipLastByte(value) {
  const bytes = Buffer.from(value, "base64url");
  bytes[bytes.length - 1] ^= 1;
  return bytes.toString("base64url");
}
