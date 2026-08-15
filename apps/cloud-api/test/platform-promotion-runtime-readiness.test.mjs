import assert from "node:assert/strict";
import test from "node:test";

import { createPlatformPromotionCompositionReadiness } from "../src/runtime.mjs";

const BINDING = Object.freeze({
  keyId: "promotion-evidence-2026-08",
  keyVersion: 8,
  lifecycleVersion: 7
});

function fixture() {
  let providerAvailable = true;
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
    signer: {
      async publicKeyMetadata() {
        if (!providerAvailable) throw new Error("provider diagnostics must remain private");
        return {
          key_id: BINDING.keyId,
          key_version: BINDING.keyVersion,
          lifecycle_version: BINDING.lifecycleVersion
        };
      }
    },
    lifecycleRepository: { async snapshot() { return structuredClone(snapshot); } },
    ...BINDING
  });
  return {
    readiness,
    failProvider() { providerAvailable = false; },
    replaceSnapshot(value) { snapshot = value; }
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

test("Platform promotion readiness rejects incomplete composition before serving", () => {
  for (const override of [
    { httpApi: undefined },
    { repository: undefined },
    { signer: undefined },
    { lifecycleRepository: undefined },
    { keyVersion: 0 },
    { lifecycleVersion: 0 }
  ]) {
    assert.throws(
      () => createPlatformPromotionCompositionReadiness({
        httpApi: { paths: { issue: "/api/platform/v1/promotions" }, async handle() {} },
        repository: { forAuthorization() {} },
        signer: { async publicKeyMetadata() {} },
        lifecycleRepository: { async snapshot() {} },
        ...BINDING,
        ...override
      }),
      /readiness dependencies are unavailable/u
    );
  }
});
