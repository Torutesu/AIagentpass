import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import {
  REFRESH_HINT_SIGNER_ERROR_CODES,
  createEd25519RefreshHintSigner
} from "../src/refresh-hint-signer.mjs";
import { REFRESH_HINT_SIGNATURE_DOMAIN } from "../../../packages/protocol/src/index.mjs";

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
