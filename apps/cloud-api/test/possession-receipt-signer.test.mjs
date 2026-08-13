import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import {
  POSSESSION_RECEIPT_PURPOSE,
  POSSESSION_RECEIPT_SIGNATURE_DOMAIN,
  POSSESSION_RECEIPT_SIGNER_ERROR_CODES,
  createLocalPossessionReceiptSigner,
  createPossessionReceiptSigner,
  normalizePossessionReceiptStatement,
  possessionReceiptSigningData,
  verifyPossessionReceiptSignature
} from "../src/possession-receipt-signer.mjs";

const STATEMENT = Object.freeze({
  version: 1,
  enrollment_id: "11111111-1111-4111-8111-111111111111",
  organization_id: "22222222-2222-4222-8222-222222222222",
  device_id: "33333333-3333-4333-8333-333333333333",
  candidate_id: "release-2026-08-13-01",
  artifact_sha256: "a".repeat(64),
  source_commit: "b".repeat(40),
  team_id: "ABCDE12345",
  device_key_fingerprint: `SHA256:${"C".repeat(43)}`,
  device_key_epoch: 7,
  challenge_nonce_digest: "d".repeat(64),
  issued_at: "2026-08-13T00:00:00.000Z"
});

function keyPair(algorithm) {
  return algorithm === "ed25519"
    ? crypto.generateKeyPairSync("ed25519")
    : crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
}

test("signs a strict canonical receipt with Ed25519 and verifies it locally", async () => {
  const keys = keyPair("ed25519");
  const signer = createLocalPossessionReceiptSigner({ privateKey: keys.privateKey, keyId: "possession-2026-08", algorithm: "ed25519" });
  const receipt = await signer.signPossessionReceipt(STATEMENT);
  assert.deepEqual(Object.keys(receipt).sort(), ["algorithm", "key_id", "purpose", "signature", "statement", "statement_hash", "version"]);
  assert.equal(receipt.algorithm, "ed25519");
  assert.equal(receipt.key_id, "possession-2026-08");
  assert.equal(receipt.purpose, POSSESSION_RECEIPT_PURPOSE);
  assert.equal(receipt.version, 1);
  assert.equal(verifyPossessionReceiptSignature({ statement: receipt.statement, signature: receipt.signature, publicKey: keys.publicKey, algorithm: receipt.algorithm }), true);
  assert.equal(Object.hasOwn(signer, "privateKey"), false);
  assert.equal(Object.hasOwn(receipt, "privateKey"), false);
  assert.equal(Object.isFrozen(signer), true);
  assert.equal(Object.isFrozen(receipt), true);
  assert.equal((await signer.publicKeyMetadata()).public_key.includes("PRIVATE KEY"), false);
});

test("supports P-256 IEEE-P1363 signatures and keeps purpose separation in the bytes", async () => {
  const keys = keyPair("p256-sha256");
  const signer = createLocalPossessionReceiptSigner({ privateKey: keys.privateKey, keyId: "possession-p256-v1", algorithm: "p256-sha256" });
  const receipt = await signer.signPossessionReceipt(STATEMENT);
  assert.equal(receipt.algorithm, "p256-sha256");
  assert.equal(Buffer.from(receipt.signature, "base64url").length, 64);
  assert.equal(verifyPossessionReceiptSignature({ statement: STATEMENT, signature: receipt.signature, publicKey: keys.publicKey, algorithm: "p256-sha256" }), true);
  assert.equal(possessionReceiptSigningData(STATEMENT).subarray(0, Buffer.byteLength(POSSESSION_RECEIPT_SIGNATURE_DOMAIN)).toString(), POSSESSION_RECEIPT_SIGNATURE_DOMAIN);
  assert.equal(verifyPossessionReceiptSignature({ statement: { ...STATEMENT, candidate_id: "other-release" }, signature: receipt.signature, publicKey: keys.publicKey, algorithm: "p256-sha256" }), false);
});

test("rejects unknown fields, aliases, noncanonical timestamps, and malformed statement values", () => {
  for (const value of [
    { ...STATEMENT, extra: true },
    { ...STATEMENT, candidateId: STATEMENT.candidate_id },
    { ...STATEMENT, issued_at: "2026-08-13T00:00:00Z" },
    { ...STATEMENT, artifact_sha256: STATEMENT.artifact_sha256.toUpperCase() },
    { ...STATEMENT, device_key_epoch: 0 },
    { ...STATEMENT, team_id: "ABCDE1234" }
  ]) {
    assert.throws(() => normalizePossessionReceiptStatement(value), (error) => error.code === POSSESSION_RECEIPT_SIGNER_ERROR_CODES.INPUT);
  }
  const reordered = JSON.parse(`{"issued_at":"${STATEMENT.issued_at}","challenge_nonce_digest":"${STATEMENT.challenge_nonce_digest}","device_key_epoch":7,"device_key_fingerprint":"${STATEMENT.device_key_fingerprint}","team_id":"${STATEMENT.team_id}","source_commit":"${STATEMENT.source_commit}","artifact_sha256":"${STATEMENT.artifact_sha256}","candidate_id":"${STATEMENT.candidate_id}","device_id":"${STATEMENT.device_id}","organization_id":"${STATEMENT.organization_id}","enrollment_id":"${STATEMENT.enrollment_id}","version":1}`);
  assert.equal(possessionReceiptSigningData(reordered).equals(possessionReceiptSigningData(STATEMENT)), true);
});

test("requires explicit purpose-separated signer configuration and supported private keys", () => {
  const ed = keyPair("ed25519");
  const p256 = keyPair("p256-sha256");
  for (const config of [
    {},
    { provider: {}, keyId: "key", algorithm: "ed25519" },
    { provider: { publicKeyMetadata() {}, sign() {} }, keyId: "bad key", algorithm: "ed25519" },
    { provider: { publicKeyMetadata() {}, sign() {} }, keyId: "key", algorithm: "rsa" },
    { provider: { publicKeyMetadata() {}, sign() {} }, keyId: "key", algorithm: "ed25519", timeoutMs: 0 }
  ]) {
    assert.throws(() => createPossessionReceiptSigner(config), (error) => error.code === POSSESSION_RECEIPT_SIGNER_ERROR_CODES.CONFIG);
  }
  assert.throws(() => createLocalPossessionReceiptSigner({ privateKey: ed.publicKey, keyId: "key", algorithm: "ed25519" }), (error) => error.code === POSSESSION_RECEIPT_SIGNER_ERROR_CODES.CONFIG);
  assert.throws(() => createLocalPossessionReceiptSigner({ privateKey: p256.privateKey, keyId: "key", algorithm: "ed25519" }), (error) => error.code === POSSESSION_RECEIPT_SIGNER_ERROR_CODES.CONFIG);
});

test("fails closed on provider metadata substitution, malformed signatures, and provider errors without exposing them", async () => {
  const keys = keyPair("ed25519");
  const secret = "provider-private-secret-should-not-escape";
  const base = {
    async publicKeyMetadata() { return { key_id: "possession-v1", algorithm: "ed25519", public_key: keys.publicKey }; },
    async sign() { return Buffer.alloc(64); }
  };
  const malformed = createPossessionReceiptSigner({ provider: base, keyId: "possession-v1", algorithm: "ed25519" });
  await assert.rejects(() => malformed.signPossessionReceipt(STATEMENT), (error) => error.code === POSSESSION_RECEIPT_SIGNER_ERROR_CODES.VERIFICATION);

  const output = createPossessionReceiptSigner({
    provider: { ...base, async sign() { return { signature: secret }; } },
    keyId: "possession-v1",
    algorithm: "ed25519"
  });
  await assert.rejects(() => output.signPossessionReceipt(STATEMENT), (error) => error.code === POSSESSION_RECEIPT_SIGNER_ERROR_CODES.OUTPUT && !error.message.includes(secret));

  const substituted = createPossessionReceiptSigner({
    provider: { ...base, async publicKeyMetadata() { return { key_id: "other-key", algorithm: "ed25519", public_key: keys.publicKey }; } },
    keyId: "possession-v1",
    algorithm: "ed25519"
  });
  await assert.rejects(() => substituted.signPossessionReceipt(STATEMENT), (error) => error.code === POSSESSION_RECEIPT_SIGNER_ERROR_CODES.OUTPUT);

  const privateMetadata = createPossessionReceiptSigner({
    provider: { ...base, async publicKeyMetadata() { return { key_id: "possession-v1", algorithm: "ed25519", public_key: keys.privateKey }; } },
    keyId: "possession-v1",
    algorithm: "ed25519"
  });
  await assert.rejects(() => privateMetadata.publicKeyMetadata(), (error) => error.code === POSSESSION_RECEIPT_SIGNER_ERROR_CODES.OUTPUT);

  const failed = createPossessionReceiptSigner({
    provider: { ...base, async sign() { throw new Error(secret); } },
    keyId: "possession-v1",
    algorithm: "ed25519"
  });
  await assert.rejects(() => failed.signPossessionReceipt(STATEMENT), (error) => error.code === POSSESSION_RECEIPT_SIGNER_ERROR_CODES.PROVIDER && !error.message.includes(secret) && !Object.hasOwn(error, "cause"));
});

test("bounds provider metadata and signing calls with an abortable timeout", async () => {
  const keys = keyPair("ed25519");
  let aborted = false;
  const signer = createPossessionReceiptSigner({
    provider: {
      async publicKeyMetadata() { return { key_id: "possession-v1", algorithm: "ed25519", public_key: keys.publicKey }; },
      async sign({ signal }) {
        signal.addEventListener("abort", () => { aborted = true; }, { once: true });
        await new Promise(() => {});
      }
    },
    keyId: "possession-v1",
    algorithm: "ed25519",
    timeoutMs: 10
  });
  await assert.rejects(() => signer.signPossessionReceipt(STATEMENT), (error) => error.code === POSSESSION_RECEIPT_SIGNER_ERROR_CODES.TIMEOUT);
  assert.equal(aborted, true);
});

test("fails closed when the advertised public key cannot verify the provider signature", async () => {
  const keys = keyPair("ed25519");
  const other = keyPair("ed25519");
  const signer = createPossessionReceiptSigner({
    provider: {
      async publicKeyMetadata() { return { key_id: "possession-v1", algorithm: "ed25519", public_key: keys.publicKey }; },
      async sign({ bytes }) { return crypto.sign(null, bytes, other.privateKey); }
    },
    keyId: "possession-v1",
    algorithm: "ed25519"
  });
  await assert.rejects(() => signer.signPossessionReceipt(STATEMENT), (error) => error.code === POSSESSION_RECEIPT_SIGNER_ERROR_CODES.VERIFICATION);
});
