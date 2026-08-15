import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";

import {
  normalizePlatformOperatorAuthorization,
  normalizePlatformPromotionRequest,
  normalizePlatformPromotionResult,
  platformPromotionContextHash,
  PLATFORM_PROMOTION_OPERATIONS
} from "../src/platform-promotion-http-contract.mjs";

const INPUT = Object.freeze({
  promotion_id: "11111111-1111-4111-8111-111111111111",
  deployment_id: "cloud-prod-2026-08",
  environment: "production",
  candidate_id: `release-pkg-sha256-v1-${"a".repeat(64)}`
});
const IDEMPOTENCY_KEY = "platform-promotion-0001";
const EVIDENCE = JSON.parse(fs.readFileSync(new URL("../../../contracts/fixtures/promotion-evidence-v3.valid.json", import.meta.url), "utf8"));

test("normalizes the exact public request and operation-bound recent-auth context", () => {
  const normalized = normalizePlatformPromotionRequest(INPUT, IDEMPOTENCY_KEY);
  assert.deepEqual(normalized, { ...INPUT, idempotency_key: IDEMPOTENCY_KEY });
  const issue = platformPromotionContextHash(normalized, PLATFORM_PROMOTION_OPERATIONS.issue);
  const replay = platformPromotionContextHash(normalized, PLATFORM_PROMOTION_OPERATIONS.replay);
  assert.match(issue, /^[0-9a-f]{64}$/u);
  assert.notEqual(issue, replay);
  assert.throws(() => normalizePlatformPromotionRequest({ ...INPUT, role: "platform_operator" }, IDEMPOTENCY_KEY));
  assert.throws(() => normalizePlatformPromotionRequest(INPUT, "short"));
});

test("accepts only an exact platform role and capability decision", () => {
  assert.deepEqual(normalizePlatformOperatorAuthorization({
    allowed: true,
    role: "platform_operator",
    capability: "platform.promotion.issue"
  }, PLATFORM_PROMOTION_OPERATIONS.issue), {
    allowed: true,
    role: "platform_operator",
    capability: "platform.promotion.issue"
  });
  assert.deepEqual(normalizePlatformOperatorAuthorization({
    allowed: false,
    role: "platform_operator",
    capability: "platform.promotion.issue"
  }, PLATFORM_PROMOTION_OPERATIONS.issue), { allowed: false });
  assert.throws(() => normalizePlatformOperatorAuthorization({
    allowed: true,
    role: "owner",
    capability: "platform.promotion.issue"
  }, PLATFORM_PROMOTION_OPERATIONS.issue));
});

test("projects only the exact public evidence result", () => {
  const expected = normalizePlatformPromotionRequest(INPUT, IDEMPOTENCY_KEY);
  const publicResult = { ...INPUT, promotion_evidence: EVIDENCE, replayed: false };
  assert.deepEqual(normalizePlatformPromotionResult(publicResult, expected), publicResult);
  assert.throws(() => normalizePlatformPromotionResult({ ...publicResult, claim_token: "private" }, expected));
  assert.throws(() => normalizePlatformPromotionResult({
    ...publicResult,
    promotion_evidence: { ...EVIDENCE, provider_diagnostics: {} }
  }, expected));
});
