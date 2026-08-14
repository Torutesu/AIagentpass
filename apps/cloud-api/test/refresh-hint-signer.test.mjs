import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import {
  REFRESH_HINT_SIGNER_ERROR_CODES,
  createEd25519RefreshHintSigner,
  createManagedRefreshHintSigner
} from "../src/refresh-hint-signer.mjs";
import { REFRESH_HINT_SIGNATURE_DOMAIN, REFRESH_HINT_TYPE } from "../../../packages/protocol/src/index.mjs";

test("signs only the refresh-hint domain and exposes public metadata without private material", async () => {
  const keys = crypto.generateKeyPairSync("ed25519");
  const signer = createEd25519RefreshHintSigner({ privateKey: keys.privateKey, keyId: "refresh-2026-08" });
  const bytes = Buffer.concat([Buffer.from(REFRESH_HINT_SIGNATURE_DOMAIN), Buffer.from("{}")]);
  const signature = await signer.signRefreshHint(bytes);
  assert.equal(signature.length, 64);
  assert.equal(crypto.verify(null, bytes, keys.publicKey, signature), true);
  const metadata = await signer.publicKeyMetadata();
  assert.equal(metadata.key_id, "refresh-2026-08");
  assert.equal(metadata.algorithm, "ed25519");
  assert.equal(metadata.public_key.type, "public");
  assert.equal(Object.hasOwn(signer, "privateKey"), false);
  assert.equal(Object.isFrozen(signer), true);
  assert.equal(Object.isFrozen(metadata), true);
});

test("rejects cross-purpose, empty, oversized, and non-byte signing requests", async () => {
  const keys = crypto.generateKeyPairSync("ed25519");
  const signer = createEd25519RefreshHintSigner({ privateKey: keys.privateKey, keyId: "refresh-1" });
  for (const input of [Buffer.from("AgentPass-Control-Bundle-v2\0{}"), Buffer.alloc(0), Buffer.alloc(21 * 1024), "secret"]) {
    await assert.rejects(signer.signRefreshHint(input), (error) => error.code === REFRESH_HINT_SIGNER_ERROR_CODES.INPUT);
  }
});

test("rejects non-Ed25519 keys, public keys, and unsafe identifiers without exposing causes", () => {
  const ed = crypto.generateKeyPairSync("ed25519");
  const p256 = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  for (const config of [
    { privateKey: ed.publicKey, keyId: "refresh-1" },
    { privateKey: p256.privateKey, keyId: "refresh-1" },
    { privateKey: ed.privateKey, keyId: "bad key" }
  ]) {
    assert.throws(() => createEd25519RefreshHintSigner(config), (error) => error.code === REFRESH_HINT_SIGNER_ERROR_CODES.CONFIG && !Object.hasOwn(error, "cause"));
  }
});

test("managed signer sends only the exact refresh binding and domain bytes to its provider", async () => {
  const keys = crypto.generateKeyPairSync("ed25519");
  const calls = [];
  const provider = {
    key_id: "refresh-managed-1",
    purpose: REFRESH_HINT_TYPE,
    algorithm: "ed25519",
    version: 1,
    async publicKeyMetadata(input) {
      calls.push(["metadata", input]);
      return { key_id: "refresh-managed-1", algorithm: "ed25519", public_key: keys.publicKey.export({ type: "spki", format: "pem" }).toString() };
    },
    async sign(input) {
      calls.push(["sign", input]);
      return crypto.sign(null, input.bytes, keys.privateKey);
    }
  };
  const signer = createManagedRefreshHintSigner({ provider, keyId: "refresh-managed-1" });
  const bytes = Buffer.concat([Buffer.from(REFRESH_HINT_SIGNATURE_DOMAIN), Buffer.from("{}")]);
  const signature = await signer.signRefreshHint(bytes);
  const metadata = await signer.publicKeyMetadata();
  assert.equal(crypto.verify(null, bytes, keys.publicKey, signature), true);
  assert.equal(metadata.public_key.includes("PRIVATE"), false);
  assert.deepEqual(calls[0][1], { algorithm: "ed25519", bytes, key_id: "refresh-managed-1", purpose: REFRESH_HINT_TYPE, version: 1 });
  assert.deepEqual(calls[1][1], { algorithm: "ed25519", key_id: "refresh-managed-1", purpose: REFRESH_HINT_TYPE, version: 1 });
  assert.equal(JSON.stringify(calls).includes("PRIVATE"), false);
});

test("managed refresh signer rejects purpose substitution and provider ambiguity", async () => {
  const keys = crypto.generateKeyPairSync("ed25519");
  assert.throws(() => createManagedRefreshHintSigner({
    provider: { key_id: "refresh-managed-1", purpose: "agentpass.control-bundle", algorithm: "ed25519", version: 1, publicKeyMetadata() {}, sign() {} },
    keyId: "refresh-managed-1"
  }), (error) => error.code === REFRESH_HINT_SIGNER_ERROR_CODES.CONFIG);
  const signer = createManagedRefreshHintSigner({
    keyId: "refresh-managed-1",
    provider: {
      async publicKeyMetadata() { return { key_id: "refresh-managed-1", algorithm: "ed25519", public_key: keys.privateKey }; },
      async sign() { return Buffer.alloc(63); }
    }
  });
  const bytes = Buffer.concat([Buffer.from(REFRESH_HINT_SIGNATURE_DOMAIN), Buffer.from("{}")]);
  await assert.rejects(signer.publicKeyMetadata(), (error) => error.code === REFRESH_HINT_SIGNER_ERROR_CODES.FAILURE);
  await assert.rejects(signer.signRefreshHint(bytes), (error) => error.code === REFRESH_HINT_SIGNER_ERROR_CODES.FAILURE);
  await assert.rejects(signer.signRefreshHint(Buffer.from("AgentPass-Control-Bundle-v2\0{}")), (error) => error.code === REFRESH_HINT_SIGNER_ERROR_CODES.INPUT);
});
