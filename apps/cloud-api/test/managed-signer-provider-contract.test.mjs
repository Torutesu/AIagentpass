import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import {
  LOOKUP_STATES,
  MANAGED_SIGNER_ALGORITHM,
  REQUEST_DIGEST_ALGORITHM,
  SIGNER_PURPOSES,
  SIGNER_PROTOCOL_VERSIONS,
  createAwsDirectSignAdapter,
  createGcpDirectSignAdapter,
  createManagedSignerBinding,
  createManagedSignerProvider,
  verifyManagedSignerSignature,
} from "../src/managed-signer-provider-contract.mjs";
import { SIGNER_PURPOSE_REGISTRY } from "../src/signer-purpose-registry.mjs";

const signingBytes = Buffer.from("the exact protocol signing bytes");
const signingDigest = crypto.createHash("sha256").update(signingBytes).digest("hex");

function bindingFor(purpose = "agentpass.capability", digest = signingDigest) {
  return {
    operation_id: "op-q2-reconciliation-001",
    purpose,
    key_id: "managed-key-2026",
    key_version: "7",
    algorithm: MANAGED_SIGNER_ALGORITHM,
    protocol_version: SIGNER_PROTOCOL_VERSIONS[purpose],
    request_digest: {
      algorithm: REQUEST_DIGEST_ALGORITHM,
      value: digest,
    },
  };
}

function publicKeyShape(publicKey) {
  return {
    algorithm: MANAGED_SIGNER_ALGORITHM,
    encoding: "base64url",
    value: publicKey.export({ format: "der", type: "spki" }).toString("base64url"),
  };
}

function receipt(binding, receiptId = "receipt-001") {
  return {
    provider: "fixture-kms",
    receipt_id: receiptId,
    operation_id: binding.operation_id,
    key_id: binding.key_id,
    key_version: binding.key_version,
  };
}

function signatureFor(binding, bytes, pair = crypto.generateKeyPairSync("ed25519")) {
  return {
    algorithm: MANAGED_SIGNER_ALGORITHM,
    encoding: "base64url",
    value: crypto.sign(null, bytes, pair.privateKey).toString("base64url"),
    public_key: publicKeyShape(pair.publicKey),
  };
}

function fixture({ purpose = "agentpass.capability", pair = crypto.generateKeyPairSync("ed25519"), sign = undefined, lookup = undefined } = {}) {
  const binding = bindingFor(purpose);
  const calls = { sign: [], lookup: [] };
  const adapter = {
    async signOnce(receivedBinding, receivedBytes) {
      calls.sign.push({ binding: receivedBinding, bytes: receivedBytes });
      return sign?.(receivedBinding, receivedBytes, pair) ?? {
        provider_receipt: receipt(receivedBinding),
        signature: signatureFor(receivedBinding, receivedBytes, pair),
      };
    },
    async lookup(receivedBinding, receivedBytes) {
      calls.lookup.push({ binding: receivedBinding, bytes: receivedBytes });
      return lookup?.(receivedBinding, receivedBytes, pair) ?? {
        state: "committed",
        provider_receipt: receipt(receivedBinding),
        signature: signatureFor(receivedBinding, receivedBytes, pair),
      };
    },
  };
  return {
    binding,
    pair,
    calls,
    provider: createManagedSignerProvider({
      binding,
      adapter,
      signingBytes,
      publicKey: pair.publicKey,
    }),
  };
}

test("derives all eight signer purposes and pins each registry protocol version", async () => {
  assert.deepEqual(SIGNER_PURPOSES, Object.values(SIGNER_PURPOSE_REGISTRY).map(({ purpose }) => purpose).sort());
  assert.equal(SIGNER_PURPOSES.length, 8);

  for (const purpose of SIGNER_PURPOSES) {
    const fixtureValue = fixture({ purpose });
    const result = await fixtureValue.provider.signOnce();
    assert.equal(result.purpose, purpose);
    assert.equal(result.algorithm, "ed25519");
    assert.equal(result.protocol_version, Object.values(SIGNER_PURPOSE_REGISTRY).find((definition) => definition.purpose === purpose).protocol_version);
    assert.equal(result.protocol_version, SIGNER_PROTOCOL_VERSIONS[purpose]);
    assert.equal(verifyManagedSignerSignature(
      fixtureValue.binding,
      result.signature,
      signingBytes,
      fixtureValue.pair.publicKey,
    ), true);
  }
});

test("passes only the fixed binding and a copy of the real signing bytes to both operations", async () => {
  const fixtureValue = fixture();
  const signed = await fixtureValue.provider.signOnce();
  const committed = await fixtureValue.provider.lookup();

  for (const call of [...fixtureValue.calls.sign, ...fixtureValue.calls.lookup]) {
    assert.strictEqual(call.binding, fixtureValue.provider.binding);
    assert.notStrictEqual(call.bytes, signingBytes);
    assert.deepEqual(call.bytes, signingBytes);
    assert.equal(Object.isFrozen(call.binding), true);
  }
  assert.equal(signed.signature.algorithm, "ed25519");
  assert.equal(committed.signature.algorithm, "ed25519");
});

test("rejects a signing-bytes digest mismatch while constructing the provider", () => {
  assert.throws(
    () => createManagedSignerProvider({
      binding: bindingFor(),
      adapter: { signOnce() {}, lookup() {} },
      signingBytes: Buffer.from("different bytes"),
      publicKey: crypto.generateKeyPairSync("ed25519").publicKey,
    }),
    (error) => error.code === "REQUEST_DIGEST_MISMATCH",
  );
});

test("verifies signOnce output against the specified bytes and pinned public key", async () => {
  const wrongPair = crypto.generateKeyPairSync("ed25519");
  const wrongKey = fixture({
    sign: (binding, bytes) => ({
      provider_receipt: receipt(binding),
      signature: signatureFor(binding, bytes, wrongPair),
    }),
  });
  await assert.rejects(() => wrongKey.provider.signOnce(), (error) => error.code === "PUBLIC_KEY_MISMATCH");

  const forged = fixture({
    sign: (binding, _bytes, pair) => ({
      provider_receipt: receipt(binding),
      signature: {
        algorithm: MANAGED_SIGNER_ALGORITHM,
        encoding: "base64url",
        value: crypto.randomBytes(64).toString("base64url"),
        public_key: publicKeyShape(pair.publicKey),
      },
    }),
  });
  await assert.rejects(() => forged.provider.signOnce(), (error) => error.code === "INVALID_SIGNATURE");

  const wrongBytes = fixture({
    sign: (binding, bytes, pair) => ({
      provider_receipt: receipt(binding),
      signature: signatureFor(binding, Buffer.from("not the configured bytes"), pair),
    }),
  });
  await assert.rejects(() => wrongBytes.provider.signOnce(), (error) => error.code === "INVALID_SIGNATURE");
});

test("verifies committed lookup output against the same bytes and pinned public key", async () => {
  const wrongPair = crypto.generateKeyPairSync("ed25519");
  const provider = fixture({
    lookup: (binding, bytes) => ({
      state: "committed",
      provider_receipt: receipt(binding),
      signature: signatureFor(binding, bytes, wrongPair),
    }),
  }).provider;
  await assert.rejects(() => provider.lookup(), (error) => error.code === "PUBLIC_KEY_MISMATCH");
});

test("exposes only closed lookup states and rejects extra fields", async () => {
  for (const state of LOOKUP_STATES) {
    const fixtureValue = fixture({
      lookup: (binding, bytes, pair) => state === "committed"
        ? { state, provider_receipt: receipt(binding), signature: signatureFor(binding, bytes, pair) }
        : state === "accepted"
          ? { state, provider_receipt: receipt(binding) }
          : { state },
    });
    assert.equal((await fixtureValue.provider.lookup()).state, state);
  }

  const invalid = fixture({
    lookup: () => ({ state: "provider-pending", diagnostics: "no" }),
  });
  await assert.rejects(() => invalid.provider.lookup(), (error) => error.code === "INVALID_LOOKUP_STATE");
});

test("rejects binding/options additions and caller-selected operations", () => {
  assert.throws(
    () => createManagedSignerBinding({ ...bindingFor(), extra: true }),
    (error) => error.code === "INVALID_BINDING",
  );
  assert.throws(
    () => createManagedSignerProvider({
      binding: bindingFor(),
      adapter: { signOnce() {}, lookup() {} },
      signingBytes,
      publicKey: crypto.generateKeyPairSync("ed25519").publicKey,
      diagnostics: "forbidden",
    }),
    (error) => error.code === "INVALID_PROVIDER_OPTIONS",
  );
  const fixtureValue = fixture();
  return assert.rejects(() => fixtureValue.provider.signOnce({ purpose: "attacker" }), (error) => error.code === "CALLER_INPUT_NOT_ALLOWED");
});

test("AWS/GCP direct Sign adapters are explicit unsupported fail-closed adapters", async () => {
  for (const adapter of [createAwsDirectSignAdapter(), createGcpDirectSignAdapter()]) {
    const provider = createManagedSignerProvider({
      binding: bindingFor(),
      adapter,
      signingBytes,
      publicKey: crypto.generateKeyPairSync("ed25519").publicKey,
    });
    await assert.rejects(provider.signOnce(), (error) => error.code === "UNSUPPORTED_DIRECT_SIGN_LOOKUP");
    await assert.rejects(provider.lookup(), (error) => error.code === "UNSUPPORTED_DIRECT_SIGN_LOOKUP");
  }
});
