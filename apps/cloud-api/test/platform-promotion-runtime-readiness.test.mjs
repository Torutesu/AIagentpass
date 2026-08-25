import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import { createPlatformPromotionCompositionReadiness } from "../src/runtime.mjs";
import {
  PROMOTION_EVIDENCE_V3_ALGORITHM,
  PROMOTION_EVIDENCE_V3_PROTOCOL_VERSION,
  PROMOTION_EVIDENCE_V3_PURPOSE,
  PROMOTION_EVIDENCE_V3_SIGNATURE_DOMAIN,
  PROMOTION_EVIDENCE_V3_SIGNING_VERSION,
  PROMOTION_EVIDENCE_V3_TYPE,
  PROMOTION_EVIDENCE_V3_VERSION,
  promotionEvidenceV3PublicKeyFingerprint
} from "../src/promotion-evidence-v3-statement.mjs";

const BINDING = Object.freeze({
  keyId: "promotion-evidence-2026-08",
  keyVersion: 8,
  lifecycleVersion: 7
});

const KEY_PAIR = crypto.generateKeyPairSync("ed25519");
const PUBLIC_KEY = KEY_PAIR.publicKey.export({ type: "spki", format: "pem" }).toString();
const RAW_FINGERPRINT = promotionEvidenceV3PublicKeyFingerprint(KEY_PAIR.publicKey);

function validMetadata(overrides = {}) {
  return {
    version: PROMOTION_EVIDENCE_V3_VERSION,
    type: PROMOTION_EVIDENCE_V3_TYPE,
    purpose: PROMOTION_EVIDENCE_V3_PURPOSE,
    domain: PROMOTION_EVIDENCE_V3_SIGNATURE_DOMAIN,
    protocol_version: PROMOTION_EVIDENCE_V3_PROTOCOL_VERSION,
    signing_version: PROMOTION_EVIDENCE_V3_SIGNING_VERSION,
    algorithm: PROMOTION_EVIDENCE_V3_ALGORITHM,
    key_id: BINDING.keyId,
    key_version: BINDING.keyVersion,
    lifecycle_version: BINDING.lifecycleVersion,
    public_key: PUBLIC_KEY,
    public_key_fingerprint: promotionEvidenceV3PublicKeyFingerprint(KEY_PAIR.publicKey),
    ...overrides
  };
}

function validSigner(metadata = validMetadata()) {
  return {
    purpose: PROMOTION_EVIDENCE_V3_PURPOSE,
    algorithm: PROMOTION_EVIDENCE_V3_ALGORITHM,
    version: PROMOTION_EVIDENCE_V3_SIGNING_VERSION,
    protocol_version: PROMOTION_EVIDENCE_V3_PROTOCOL_VERSION,
    signing_version: PROMOTION_EVIDENCE_V3_SIGNING_VERSION,
    key_id: BINDING.keyId,
    key_version: BINDING.keyVersion,
    lifecycle_version: BINDING.lifecycleVersion,
    public_key_fingerprint: RAW_FINGERPRINT,
    sign() {},
    signPromotionEvidence() {},
    signPromotionEvidenceV3() {},
    async publicKeyMetadata() { return structuredClone(metadata); }
  };
}

function fixture() {
  let providerAvailable = true;
  let metadata = validMetadata();
  let snapshot = {
    version: BINDING.lifecycleVersion,
    keys: [{
      key_id: BINDING.keyId,
      key_version: BINDING.keyVersion,
      state: "active"
    }]
  };
  const readiness = createPlatformPromotionCompositionReadiness({
    httpApi: { paths: { issue: "/api/platform/v1/promotions" }, async handle() {} },
    repository: { forAuthorization() {} },
    signer: { ...validSigner(), async publicKeyMetadata() {
      if (!providerAvailable) throw new Error("provider diagnostics must remain private");
      return structuredClone(metadata);
    } },
    lifecycleRepository: { async snapshot() { return structuredClone(snapshot); } },
    ...BINDING
  });
  return {
    readiness,
    failProvider() { providerAvailable = false; },
    replaceSnapshot(value) { snapshot = value; },
    replaceMetadata(value) { metadata = value; }
  };
}

test("Platform promotion readiness binds route, authorization repository, provider key, and lifecycle", async () => {
  const value = fixture();
  assert.deepEqual(await value.readiness(), { enabled: true, ok: true, code: "ready" });
});

test("Platform promotion readiness fails closed for provider outage and lifecycle drift", async () => {
  const providerFailure = fixture();
  providerFailure.failProvider();
  assert.deepEqual(await providerFailure.readiness(), {
    enabled: true,
    ok: false,
    code: "platform_promotion_unavailable"
  });

  const lifecycleFailure = fixture();
  lifecycleFailure.replaceSnapshot({
    version: BINDING.lifecycleVersion + 1,
    keys: [{ key_id: BINDING.keyId, key_version: BINDING.keyVersion + 1, state: "active" }]
  });
  assert.deepEqual(await lifecycleFailure.readiness(), {
    enabled: true,
    ok: false,
    code: "platform_promotion_unavailable"
  });
});

test("Platform promotion readiness rejects v2, cross-purpose, and substituted key metadata", async () => {
  for (const overrides of [
    { version: 2 },
    { purpose: "generic.sign" },
    { protocol_version: 2 },
    { signing_version: 2 },
    { algorithm: "rsa-pss" },
    { public_key_fingerprint: `SHA256:${"A".repeat(43)}` },
    { key_version: BINDING.keyVersion + 1 },
    { lifecycle_version: BINDING.lifecycleVersion + 1 }
  ]) {
    const value = fixture();
    value.replaceMetadata(validMetadata(overrides));
    assert.deepEqual(await value.readiness(), {
      enabled: true,
      ok: false,
      code: "platform_promotion_unavailable"
    }, JSON.stringify(overrides));
  }
});

test("Platform promotion readiness rejects incomplete composition before serving", () => {
  const accessorSigner = validSigner();
  Object.defineProperty(accessorSigner, "key_id", { enumerable: true, get() { return BINDING.keyId; } });
  for (const override of [
    { httpApi: undefined },
    { repository: undefined },
    { signer: undefined },
    { signer: { ...validSigner(), diagnostics: "must stay private" } },
    { signer: accessorSigner },
    { lifecycleRepository: undefined },
    { keyVersion: 0 },
    { lifecycleVersion: 0 }
  ]) {
    assert.throws(
      () => createPlatformPromotionCompositionReadiness({
        httpApi: { paths: { issue: "/api/platform/v1/promotions" }, async handle() {} },
        repository: { forAuthorization() {} },
        signer: validSigner(),
        lifecycleRepository: { async snapshot() {} },
        ...BINDING,
        ...override
      }),
      /readiness dependencies are unavailable/u
    );
  }
});
