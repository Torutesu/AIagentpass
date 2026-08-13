import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import {
  createRemoteEd25519KmsProvider,
  REMOTE_KMS_ERROR_CODES,
  RemoteKmsProviderError
} from "../src/remote-kms-provider.mjs";

const keys = crypto.generateKeyPairSync("ed25519");
const otherKeys = crypto.generateKeyPairSync("ed25519");
const publicKey = keys.publicKey.export({ type: "spki", format: "pem" }).toString();
const otherPublicKey = otherKeys.publicKey.export({ type: "spki", format: "pem" }).toString();
const binding = { keyId: "agent-session-2026-08", purpose: "agent-session-grant", algorithm: "ed25519", version: 1 };

function provider(overrides = {}) {
  const calls = [];
  const { transport: transportOverrides = {}, ...options } = overrides;
  const transport = {
    async getPublicKey(request, { signal }) { calls.push(["metadata", request, signal]); return { key_id: binding.keyId, algorithm: binding.algorithm, public_key: publicKey }; },
    async sign(request, { signal }) { calls.push(["sign", request, signal]); return crypto.sign(null, request.bytes, keys.privateKey); },
    ...transportOverrides
  };
  return { calls, provider: createRemoteEd25519KmsProvider({ ...binding, publicKey, transport, ...options }) };
}

function metadataInput(extra = {}) { return { key_id: binding.keyId, purpose: binding.purpose, algorithm: binding.algorithm, version: binding.version, ...extra }; }
function signInput(bytes = Buffer.from("canonical bytes"), extra = {}) { return { ...metadataInput(), bytes, ...extra }; }

test("pins purpose/key/algorithm/version and verifies the remote Ed25519 signature", async () => {
  const value = provider();
  const metadata = await value.provider.publicKeyMetadata(metadataInput());
  assert.deepEqual(metadata, { key_id: binding.keyId, algorithm: "ed25519", public_key: publicKey });
  const signature = await value.provider.sign(signInput());
  assert.equal(signature.length, 64);
  assert.equal(crypto.verify(null, Buffer.from("canonical bytes"), keys.publicKey, signature), true);
  assert.equal(value.calls[0][2] instanceof AbortSignal, true);
  assert.equal(JSON.stringify(value.provider).includes("PRIVATE KEY"), false);
});

test("fills only omitted fixed fields for the qualification signer contract", async () => {
  const value = provider();
  const metadata = await value.provider.publicKeyMetadata({ key_id: binding.keyId, purpose: binding.purpose });
  assert.equal(metadata.key_id, binding.keyId);
  const signature = await value.provider.sign({ key_id: binding.keyId, purpose: binding.purpose, bytes: Buffer.from("qualification") });
  assert.equal(signature.length, 64);
  await assert.rejects(value.provider.sign({ key_id: binding.keyId, purpose: "other", bytes: Buffer.from("qualification") }), (error) => error.code === REMOTE_KMS_ERROR_CODES.PURPOSE);
});

test("rejects purpose, key, algorithm, version, extra fields, and oversized bytes", async () => {
  const value = provider();
  for (const input of [
    metadataInput({ purpose: "qualification-manifest" }),
    metadataInput({ key_id: "other-key" }),
    metadataInput({ algorithm: "rsa" }),
    metadataInput({ version: 2 }),
    { ...metadataInput(), unexpected: true }
  ]) await assert.rejects(value.provider.publicKeyMetadata(input), (error) => error.code === REMOTE_KMS_ERROR_CODES.PURPOSE || error.code === REMOTE_KMS_ERROR_CODES.INPUT);
  await assert.rejects(value.provider.sign(signInput(Buffer.alloc(128), { unexpected: true })), (error) => error.code === REMOTE_KMS_ERROR_CODES.INPUT);
  const bounded = provider({ maxRequestBytes: 8 }).provider;
  await assert.rejects(bounded.sign(signInput(Buffer.alloc(9))), (error) => error.code === REMOTE_KMS_ERROR_CODES.INPUT);
});

test("rejects metadata substitution and cryptographically invalid signatures", async () => {
  const substituted = provider({ transport: { async getPublicKey() { return { ...binding, public_key: otherPublicKey }; } } }).provider;
  await assert.rejects(substituted.publicKeyMetadata(metadataInput()), (error) => error.code === REMOTE_KMS_ERROR_CODES.METADATA);
  const forged = provider({ transport: { async sign() { return crypto.sign(null, Buffer.from("other"), keys.privateKey); } } }).provider;
  await assert.rejects(forged.sign(signInput()), (error) => error.code === REMOTE_KMS_ERROR_CODES.SIGNATURE);
  const wrongLength = provider({ transport: { async sign() { return Buffer.alloc(63); } } }).provider;
  await assert.rejects(wrongLength.sign(signInput()), (error) => error.code === REMOTE_KMS_ERROR_CODES.OUTPUT);
});

test("maps provider errors opaquely and aborts on deadline or caller AbortSignal", async () => {
  const secret = "kms-internal-secret";
  const failed = provider({ transport: { async getPublicKey() { throw new Error(secret); } } }).provider;
  await assert.rejects(failed.publicKeyMetadata(metadataInput()), (error) => error.code === REMOTE_KMS_ERROR_CODES.PROVIDER && !("cause" in error) && !error.message.includes(secret));
  const slow = provider({ timeoutMs: 10, transport: { async getPublicKey(_request, { signal }) { await new Promise((resolve) => setTimeout(resolve, 100)); assert.equal(signal.aborted, true); return { key_id: binding.keyId, algorithm: binding.algorithm, public_key: publicKey }; } } }).provider;
  await assert.rejects(slow.publicKeyMetadata(metadataInput()), (error) => error.code === REMOTE_KMS_ERROR_CODES.TIMEOUT);
  const controller = new AbortController();
  controller.abort();
  const aborted = provider().provider;
  await assert.rejects(aborted.publicKeyMetadata(metadataInput({ signal: controller.signal })), (error) => error.code === REMOTE_KMS_ERROR_CODES.ABORTED);
  assert.equal(new RemoteKmsProviderError(REMOTE_KMS_ERROR_CODES.PROVIDER).message.includes("internal"), false);
});

test("requires an injected transport and public Ed25519 key", () => {
  assert.throws(() => createRemoteEd25519KmsProvider({ ...binding, publicKey, transport: null }), (error) => error.code === REMOTE_KMS_ERROR_CODES.CONFIG);
  assert.throws(() => createRemoteEd25519KmsProvider({ ...binding, publicKey: keys.privateKey, transport: {} }), (error) => error.code === REMOTE_KMS_ERROR_CODES.CONFIG);
});
