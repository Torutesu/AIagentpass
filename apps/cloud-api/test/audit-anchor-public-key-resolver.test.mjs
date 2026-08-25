import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import {
  AuditAnchorPublicKeyResolverError,
  createAuditAnchorPublicKeyResolver
} from "../src/audit-anchor-public-key-resolver.mjs";
import {
  AUDIT_ANCHOR_ALGORITHM,
  AUDIT_ANCHOR_PROTOCOL_VERSION,
  AUDIT_ANCHOR_PURPOSE,
  AUDIT_ANCHOR_SIGNING_VERSION
} from "../src/audit-anchor-statement.mjs";

function fixture(state = "revoked") {
  const pair = crypto.generateKeyPairSync("ed25519");
  const publicKey = pair.publicKey.export({ type: "spki", format: "pem" }).toString();
  const fingerprint = crypto.createHash("sha256").update(pair.publicKey.export({ type: "spki", format: "der" })).digest("hex");
  const snapshot = {
    version: 5,
    purpose: AUDIT_ANCHOR_PURPOSE,
    algorithm: AUDIT_ANCHOR_ALGORITHM,
    keys: [{
      key_id: "audit-anchor-v1",
      key_version: 1,
      purpose: AUDIT_ANCHOR_PURPOSE,
      algorithm: AUDIT_ANCHOR_ALGORITHM,
      public_key: publicKey,
      public_key_fingerprint: fingerprint,
      state,
      state_version: 5
    }]
  };
  return { pair, snapshot, repository: { async snapshot() { return snapshot; } } };
}

function input(overrides = {}) {
  return {
    purpose: AUDIT_ANCHOR_PURPOSE,
    algorithm: AUDIT_ANCHOR_ALGORITHM,
    protocol_version: AUDIT_ANCHOR_PROTOCOL_VERSION,
    signing_version: AUDIT_ANCHOR_SIGNING_VERSION,
    key_id: "audit-anchor-v1",
    key_version: 1,
    lifecycle_version: 2,
    ...overrides
  };
}

test("resolves an exact historical public key without private material", async () => {
  const value = fixture();
  const metadata = await createAuditAnchorPublicKeyResolver({ repository: value.repository })(input());
  assert.equal(metadata.key_id, "audit-anchor-v1");
  assert.equal(metadata.key_version, 1);
  assert.equal(metadata.lifecycle_version, 2);
  assert.match(metadata.public_key, /BEGIN PUBLIC KEY/u);
  assert.equal(JSON.stringify(metadata).includes("PRIVATE KEY"), false);
  assert.equal(Object.isFrozen(metadata), true);
});

test("fails closed for emergency disable, lifecycle rollback, substitution, and storage failure", async (t) => {
  await t.test("emergency disable", async () => {
    await assert.rejects(createAuditAnchorPublicKeyResolver({ repository: fixture("emergency-disabled").repository })(input()), AuditAnchorPublicKeyResolverError);
  });
  await t.test("future lifecycle", async () => {
    await assert.rejects(createAuditAnchorPublicKeyResolver({ repository: fixture().repository })(input({ lifecycle_version: 6 })), AuditAnchorPublicKeyResolverError);
  });
  await t.test("key substitution", async () => {
    await assert.rejects(createAuditAnchorPublicKeyResolver({ repository: fixture().repository })(input({ key_id: "other" })), AuditAnchorPublicKeyResolverError);
  });
  await t.test("storage", async () => {
    const secret = "database-secret";
    const resolver = createAuditAnchorPublicKeyResolver({ repository: { async snapshot() { throw new Error(secret); } } });
    await assert.rejects(resolver(input()), (error) => error.code === "ERR_AUDIT_ANCHOR_HISTORICAL_KEY" && !String(error).includes(secret));
  });
});
