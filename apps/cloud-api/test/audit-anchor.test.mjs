import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import { canonicalJson } from "../../../packages/protocol/src/index.mjs";
import {
  AUDIT_ANCHOR_ALGORITHM,
  AUDIT_ANCHOR_ERROR_CODES,
  AUDIT_ANCHOR_PURPOSE,
  AUDIT_ANCHOR_PROTOCOL_VERSION,
  AUDIT_ANCHOR_SIGNATURE_DOMAIN,
  AUDIT_ANCHOR_SIGNING_VERSION,
  AUDIT_ANCHOR_TYPE,
  AUDIT_ANCHOR_VERSION,
  AUDIT_ANCHOR_ZERO_DIGEST,
  auditAnchorPublicKeyFingerprint,
  auditAnchorSigningData,
  auditAnchorStatementHash,
  canonicalizeAuditAnchor,
  canonicalizeAuditAnchorStatement,
  normalizeAuditAnchorStatement,
  parseCanonicalAuditAnchor
} from "../src/audit-anchor-statement.mjs";
import { createHostedAuditAnchorSigner } from "../src/audit-anchor-signer.mjs";
import { verifyAuditAnchor } from "../src/audit-anchor-verifier.mjs";

const NOW = Date.parse("2026-08-15T00:00:00.000Z");
const ORGANIZATION_ID = "11111111-1111-4111-8111-111111111111";
const EXPORT_ID = "22222222-2222-4222-8222-222222222222";
const KEY_ID = "audit-anchor-production-v1";

function statement(overrides = {}) {
  return {
    version: AUDIT_ANCHOR_VERSION,
    type: AUDIT_ANCHOR_TYPE,
    organization_id: ORGANIZATION_ID,
    environment: "production",
    chain: "admin",
    export_id: EXPORT_ID,
    audit_position: 12,
    previous_audit_position: 0,
    root_digest: "a".repeat(64),
    previous_root_digest: AUDIT_ANCHOR_ZERO_DIGEST,
    export_digest: "c".repeat(64),
    record_count: 12,
    purpose: AUDIT_ANCHOR_PURPOSE,
    protocol_version: AUDIT_ANCHOR_PROTOCOL_VERSION,
    signing_version: AUDIT_ANCHOR_SIGNING_VERSION,
    lifecycle_version: 3,
    key_id: KEY_ID,
    key_version: 7,
    issued_at: "2026-08-14T23:30:00.000Z",
    expires_at: "2026-08-15T00:30:00.000Z",
    ...overrides
  };
}

function keyFixture() {
  const keys = crypto.generateKeyPairSync("ed25519");
  return {
    privateKey: keys.privateKey,
    publicKey: keys.publicKey,
    publicKeyPem: keys.publicKey.export({ type: "spki", format: "pem" }).toString()
  };
}

function envelopeFor(value, privateKey, fingerprint) {
  const normalized = normalizeAuditAnchorStatement(value);
  const signature = crypto.sign(null, auditAnchorSigningData(normalized), privateKey).toString("base64url");
  return {
    version: AUDIT_ANCHOR_VERSION,
    type: AUDIT_ANCHOR_TYPE,
    statement: normalized,
    statement_hash: auditAnchorStatementHash(normalized),
    signature_algorithm: AUDIT_ANCHOR_ALGORITHM,
    signer_key_fingerprint: fingerprint,
    signature
  };
}

function context(publicKey, overrides = {}) {
  return {
    publicKey,
    organizationId: ORGANIZATION_ID,
    environment: "production",
    chain: "admin",
    exportId: EXPORT_ID,
    auditPosition: 12,
    rootDigest: "a".repeat(64),
    exportDigest: "c".repeat(64),
    recordCount: 12,
    keyId: KEY_ID,
    keyVersion: 7,
    lifecycleVersion: 3,
    previousAuditPosition: 0,
    previousRootDigest: AUDIT_ANCHOR_ZERO_DIGEST,
    now: NOW,
    ...overrides
  };
}

test("canonicalizes a closed, domain-separated Audit Anchor statement", () => {
  const value = statement();
  const reversed = Object.fromEntries(Object.entries(value).reverse());
  const normalized = normalizeAuditAnchorStatement(reversed);
  assert.equal(canonicalizeAuditAnchorStatement(value), canonicalJson(normalized));
  assert.equal(auditAnchorSigningData(value).subarray(0, Buffer.byteLength(AUDIT_ANCHOR_SIGNATURE_DOMAIN)).toString(), AUDIT_ANCHOR_SIGNATURE_DOMAIN);
  assert.notEqual(auditAnchorSigningData(value).toString("hex"), Buffer.from(canonicalJson(normalized), "utf8").toString("hex"));
  assert.throws(() => normalizeAuditAnchorStatement({ ...value, unexpected: true }), { code: AUDIT_ANCHOR_ERROR_CODES.UNKNOWN_FIELD });
  assert.throws(() => normalizeAuditAnchorStatement({ ...value, audit_position: 0 }), { code: AUDIT_ANCHOR_ERROR_CODES.INPUT });
  assert.throws(() => normalizeAuditAnchorStatement({ ...value, previous_audit_position: 12 }), { code: AUDIT_ANCHOR_ERROR_CODES.ROLLBACK });
  assert.throws(() => normalizeAuditAnchorStatement({ ...value, previous_root_digest: "b".repeat(64) }), { code: AUDIT_ANCHOR_ERROR_CODES.BINDING });
});

test("round-trips only canonical Audit Anchor envelopes", () => {
  const keys = keyFixture();
  const fingerprint = auditAnchorPublicKeyFingerprint(keys.publicKey);
  const envelope = envelopeFor(statement(), keys.privateKey, fingerprint);
  const text = canonicalizeAuditAnchor(envelope);
  assert.deepEqual(parseCanonicalAuditAnchor(text, { now: NOW, allowExpired: false, allowFuture: false }), envelope);
  assert.throws(() => parseCanonicalAuditAnchor(`${text}\n`, { now: NOW, allowExpired: false, allowFuture: false }), { code: AUDIT_ANCHOR_ERROR_CODES.NONCANONICAL });
  assert.throws(() => parseCanonicalAuditAnchor(canonicalJson({ ...envelope, extra: true })), { code: AUDIT_ANCHOR_ERROR_CODES.UNKNOWN_FIELD });
});

test("hosted signer sends only the fixed purpose request and self-verifies provider output", async () => {
  const keys = keyFixture();
  const calls = [];
  const provider = {
    async publicKeyMetadata(input) {
      calls.push({ method: "metadata", input });
      return { algorithm: AUDIT_ANCHOR_ALGORITHM, key_id: KEY_ID, public_key: keys.publicKeyPem };
    },
    async sign(input) {
      calls.push({ method: "sign", input: { ...input, bytes: Buffer.from(input.bytes) } });
      return crypto.sign(null, input.bytes, keys.privateKey);
    }
  };
  const signer = createHostedAuditAnchorSigner({ provider, keyId: KEY_ID, keyVersion: 7, lifecycleVersion: 3, publicKey: keys.publicKey, now: () => NOW });
  const result = await signer.signAuditAnchor(statement());
  assert.equal(result.statement_hash, auditAnchorStatementHash(statement()));
  assert.equal(calls.length, 2);
  assert.deepEqual(calls[0].input, { algorithm: "ed25519", key_id: KEY_ID, purpose: AUDIT_ANCHOR_PURPOSE, version: 1 });
  assert.deepEqual({ ...calls[1].input, bytes: undefined }, {
    algorithm: "ed25519", key_id: KEY_ID, purpose: AUDIT_ANCHOR_PURPOSE, version: 1, bytes: undefined
  });
  assert.equal(crypto.verify(null, auditAnchorSigningData(result.statement), keys.publicKey, Buffer.from(result.signature, "base64url")), true);
  assert.equal(Object.hasOwn(signer, "privateKey"), false);
  assert.equal(Object.hasOwn(signer, "private_key"), false);
  assert.deepEqual(verifyAuditAnchor(result, context(keys.publicKey)), result);
});

test("hosted signer rejects private-material providers, binding drift, timeout, and forged output", async () => {
  const keys = keyFixture();
  assert.throws(() => createHostedAuditAnchorSigner({
    provider: { privateKey: keys.privateKey, publicKeyMetadata() {}, sign() {} },
    keyId: KEY_ID, keyVersion: 7, lifecycleVersion: 3, publicKey: keys.publicKey
  }), { code: AUDIT_ANCHOR_ERROR_CODES.CONFIG });

  const mismatched = createHostedAuditAnchorSigner({
    provider: {
      async publicKeyMetadata() { return { algorithm: AUDIT_ANCHOR_ALGORITHM, key_id: KEY_ID, public_key: keys.publicKey }; },
      async sign() { return crypto.sign(null, Buffer.from("wrong"), keys.privateKey); }
    },
    keyId: KEY_ID, keyVersion: 7, lifecycleVersion: 3, publicKey: keys.publicKey, now: () => NOW
  });
  await assert.rejects(() => mismatched.signAuditAnchor(statement()), { code: AUDIT_ANCHOR_ERROR_CODES.SIGNATURE });

  const timeout = createHostedAuditAnchorSigner({
    provider: { async publicKeyMetadata() { await new Promise(() => {}); }, async sign() {} },
    keyId: KEY_ID, keyVersion: 7, lifecycleVersion: 3, publicKey: keys.publicKey, timeoutMs: 1, now: () => NOW
  });
  await assert.rejects(() => timeout.publicKeyMetadata(), { code: AUDIT_ANCHOR_ERROR_CODES.PROVIDER });
  await assert.rejects(() => mismatched.signAuditAnchor(statement({ key_version: 8 })), { code: AUDIT_ANCHOR_ERROR_CODES.BINDING });
});

test("verifier enforces tenant, environment, lifecycle, key, chain, expiry, and Ed25519 bindings", () => {
  const keys = keyFixture();
  const fingerprint = auditAnchorPublicKeyFingerprint(keys.publicKey);
  const valid = envelopeFor(statement(), keys.privateKey, fingerprint);
  assert.deepEqual(verifyAuditAnchor(valid, context(keys.publicKey)), valid);

  const substitutions = [
    ["organization_id", { organizationId: "22222222-2222-4222-8222-222222222222" }],
    ["environment", { environment: "staging" }],
    ["chain", { chain: "device" }],
    ["export", { exportId: "33333333-3333-4333-8333-333333333333" }],
    ["export digest", { exportDigest: "d".repeat(64) }],
    ["key id", { keyId: "another-key" }],
    ["key version", { keyVersion: 8 }],
    ["lifecycle", { lifecycleVersion: 4 }],
    ["position", { previousAuditPosition: 1, previousRootDigest: "b".repeat(64) }]
  ];
  for (const [label, overrides] of substitutions) {
    assert.throws(() => verifyAuditAnchor(valid, context(keys.publicKey, overrides)), { code: /ERR_AUDIT_ANCHOR_(?:BINDING|ROLLBACK)/u }, label);
  }

  const future = envelopeFor(statement({ issued_at: "2026-08-15T00:01:00.000Z", expires_at: "2026-08-15T00:31:00.000Z" }), keys.privateKey, fingerprint);
  assert.throws(() => verifyAuditAnchor(future, context(keys.publicKey)), { code: AUDIT_ANCHOR_ERROR_CODES.NOT_YET_VALID });
  const expired = envelopeFor(statement({ issued_at: "2026-08-14T22:00:00.000Z", expires_at: "2026-08-14T23:00:00.000Z" }), keys.privateKey, fingerprint);
  assert.throws(() => verifyAuditAnchor(expired, context(keys.publicKey)), { code: AUDIT_ANCHOR_ERROR_CODES.EXPIRED });
  assert.throws(() => verifyAuditAnchor({ ...valid, signer_key_fingerprint: "SHA256:" + "A".repeat(43) }, context(keys.publicKey)), { code: AUDIT_ANCHOR_ERROR_CODES.SIGNATURE });
  const changedSignature = Buffer.from(valid.signature, "base64url");
  changedSignature[0] ^= 0x01;
  assert.throws(() => verifyAuditAnchor({ ...valid, signature: changedSignature.toString("base64url") }, context(keys.publicKey)), { code: AUDIT_ANCHOR_ERROR_CODES.SIGNATURE });
});
