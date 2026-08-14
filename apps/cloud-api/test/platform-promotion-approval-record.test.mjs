import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import { canonicalJson } from "../../../packages/protocol/src/index.mjs";
import { deriveReleaseCandidateId } from "../../../lib/release-candidate-identity.mjs";
import {
  PLATFORM_PROMOTION_APPROVAL_DIGEST_DOMAIN,
  PLATFORM_PROMOTION_APPROVAL_ERROR_CODES,
  PLATFORM_PROMOTION_APPROVAL_MAX_AUTHORIZATION_EVIDENCE_DIGESTS,
  PLATFORM_PROMOTION_APPROVAL_MAX_PLATFORM_PRINCIPAL_IDS,
  PLATFORM_PROMOTION_APPROVAL_MAX_QUALIFICATION_REPORT_DIGESTS,
  PLATFORM_PROMOTION_APPROVAL_MAX_TTL_MS,
  PLATFORM_PROMOTION_APPROVAL_QUORUM,
  PLATFORM_PROMOTION_APPROVAL_RELEASE_MANIFEST_SCHEMA_VERSION,
  PLATFORM_PROMOTION_APPROVAL_TYPE,
  PLATFORM_PROMOTION_APPROVAL_VERSION,
  canonicalizePlatformPromotionApprovalRecord,
  normalizePlatformPromotionApprovalRecord,
  parseCanonicalPlatformPromotionApprovalRecord,
  platformPromotionApprovalRecordDigest,
  platformPromotionApprovalRecordSigningData,
  summarizePlatformPromotionApprovalRecord,
} from "../src/platform-promotion-approval-record.mjs";

const NOW = Date.parse("2026-08-15T00:00:00.000Z");
const PRODUCT_PKG_SHA256 = "1".repeat(64);
const CANDIDATE_ID = deriveReleaseCandidateId(PRODUCT_PKG_SHA256);
const DOMAIN = Buffer.from(PLATFORM_PROMOTION_APPROVAL_DIGEST_DOMAIN, "utf8");

function record(overrides = {}) {
  return {
    version: PLATFORM_PROMOTION_APPROVAL_VERSION,
    type: PLATFORM_PROMOTION_APPROVAL_TYPE,
    approval_id: "11111111-1111-4111-8111-111111111111",
    deployment_id: "deployment-production-01",
    environment: "production",
    candidate_id: CANDIDATE_ID,
    source_commit: "2".repeat(40),
    source_tree: "3".repeat(40),
    product_pkg_sha256: PRODUCT_PKG_SHA256,
    image_digest: `sha256:${"4".repeat(64)}`,
    sbom_sha256: "5".repeat(64),
    qualification_report_digests: ["6".repeat(64), "7".repeat(64)],
    release_manifest_schema_version: PLATFORM_PROMOTION_APPROVAL_RELEASE_MANIFEST_SCHEMA_VERSION,
    release_manifest_sha256: "8".repeat(64),
    policy_id: "release-promotion-v1",
    policy_version: 3,
    approval_version: 1,
    decision: "approved",
    platform_principal_ids: ["platform-operator-a", "platform-operator-b"],
    quorum: { required: PLATFORM_PROMOTION_APPROVAL_QUORUM.production, satisfied: true },
    authorization_evidence_digests: ["9".repeat(64), "a".repeat(64)],
    approved_at: new Date(NOW).toISOString(),
    expires_at: new Date(NOW + 5 * 60 * 1_000).toISOString(),
    ...overrides,
  };
}

function throwsCode(fn, code, message = code) {
  assert.throws(fn, (error) => error?.code === code, message);
}

test("normalizes a closed deployment-scoped approval record and freezes every value", () => {
  const input = record();
  const normalized = normalizePlatformPromotionApprovalRecord(input, {
    now: NOW,
    allowExpired: false,
    allowFuture: false,
  });

  assert.deepEqual(normalized, input);
  assert.equal(Object.isFrozen(normalized), true);
  assert.equal(Object.isFrozen(normalized.qualification_report_digests), true);
  assert.equal(Object.isFrozen(normalized.platform_principal_ids), true);
  assert.equal(Object.isFrozen(normalized.authorization_evidence_digests), true);
  assert.equal(Object.isFrozen(normalized.quorum), true);
  assert.equal(Object.hasOwn(normalized, "organization_id"), false);
  assert.equal(normalized.quorum.required, 2);
  assert.equal(normalized.quorum.satisfied, true);
});

test("canonicalization is independent of object insertion order but preserves strict array order", () => {
  const input = record();
  const reversedObject = Object.fromEntries(Object.keys(input).reverse().map((key) => [key, input[key]]));
  assert.equal(canonicalizePlatformPromotionApprovalRecord(input), canonicalJson(reversedObject));

  throwsCode(
    () => normalizePlatformPromotionApprovalRecord(record({
      qualification_report_digests: ["7".repeat(64), "6".repeat(64)],
    })),
    PLATFORM_PROMOTION_APPROVAL_ERROR_CODES.ORDERING
  );
});

test("digest uses the fixed domain and the exact canonical record bytes", () => {
  const input = record();
  const canonical = canonicalizePlatformPromotionApprovalRecord(input);
  const signingData = platformPromotionApprovalRecordSigningData(input);
  const expected = crypto.createHash("sha256").update(DOMAIN).update(canonical, "utf8").digest("hex");

  assert.equal(signingData.subarray(0, DOMAIN.length).equals(DOMAIN), true);
  assert.equal(signingData.subarray(DOMAIN.length).toString("utf8"), canonical);
  assert.equal(platformPromotionApprovalRecordDigest(input), expected);
  assert.notEqual(platformPromotionApprovalRecordDigest(input), crypto.createHash("sha256").update(canonical, "utf8").digest("hex"));
  assert.notEqual(
    platformPromotionApprovalRecordDigest(input),
    platformPromotionApprovalRecordDigest(record({ environment: "staging", quorum: { required: 1, satisfied: true } }))
  );
});

test("public summary is a frozen redacted DTO with only the approved fields", () => {
  const input = record();
  const summary = summarizePlatformPromotionApprovalRecord(input, { now: NOW, allowExpired: false, allowFuture: false });

  assert.deepEqual(Object.keys(summary).sort(), [
    "approval_id",
    "approval_version",
    "approved_at",
    "candidate_id",
    "deployment_id",
    "environment",
    "expires_at",
    "policy_id",
    "policy_version",
    "quorum",
    "record_digest",
  ]);
  assert.equal(summary.record_digest, platformPromotionApprovalRecordDigest(input));
  assert.equal(Object.hasOwn(summary, "platform_principal_ids"), false);
  assert.equal(Object.hasOwn(summary, "authorization_evidence_digests"), false);
  assert.equal(Object.hasOwn(summary, "organization_id"), false);
  assert.equal(Object.isFrozen(summary), true);
  assert.equal(Object.isFrozen(summary.quorum), true);
});

test("candidate identity, release bindings, and immutable decisions cannot be substituted", () => {
  const badValues = [
    ["candidate", { candidate_id: deriveReleaseCandidateId("f".repeat(64)) }, PLATFORM_PROMOTION_APPROVAL_ERROR_CODES.BINDING],
    ["product digest", { product_pkg_sha256: "f".repeat(64) }, PLATFORM_PROMOTION_APPROVAL_ERROR_CODES.BINDING],
    ["decision", { decision: "rejected" }, PLATFORM_PROMOTION_APPROVAL_ERROR_CODES.INPUT],
    ["manifest version", { release_manifest_schema_version: 3 }, PLATFORM_PROMOTION_APPROVAL_ERROR_CODES.INPUT],
    ["environment", { environment: "production-eu" }, PLATFORM_PROMOTION_APPROVAL_ERROR_CODES.INPUT],
    ["image digest", { image_digest: "sha512:" + "4".repeat(64) }, PLATFORM_PROMOTION_APPROVAL_ERROR_CODES.INPUT],
    ["source commit", { source_commit: "2".repeat(39) }, PLATFORM_PROMOTION_APPROVAL_ERROR_CODES.INPUT],
    ["source tree", { source_tree: "G".repeat(40) }, PLATFORM_PROMOTION_APPROVAL_ERROR_CODES.INPUT],
    ["sbom digest", { sbom_sha256: "z".repeat(64) }, PLATFORM_PROMOTION_APPROVAL_ERROR_CODES.INPUT],
  ];
  for (const [label, overrides, code] of badValues) throwsCode(() => normalizePlatformPromotionApprovalRecord(record(overrides)), code, label);
});

test("quorum is derived from environment and cannot be caller-selected", () => {
  throwsCode(
    () => normalizePlatformPromotionApprovalRecord(record({ quorum: { required: 1, satisfied: true } })),
    PLATFORM_PROMOTION_APPROVAL_ERROR_CODES.QUORUM
  );
  throwsCode(
    () => normalizePlatformPromotionApprovalRecord(record({ quorum: { required: 2, satisfied: false } })),
    PLATFORM_PROMOTION_APPROVAL_ERROR_CODES.QUORUM
  );
  throwsCode(
    () => normalizePlatformPromotionApprovalRecord(record({
      platform_principal_ids: ["platform-operator-a"],
      authorization_evidence_digests: ["9".repeat(64)],
      quorum: { required: 2, satisfied: true },
    })),
    PLATFORM_PROMOTION_APPROVAL_ERROR_CODES.QUORUM
  );
  throwsCode(
    () => normalizePlatformPromotionApprovalRecord(record({
      environment: "staging",
      quorum: { required: 1, satisfied: true, policy: "caller-selected" },
    })),
    PLATFORM_PROMOTION_APPROVAL_ERROR_CODES.UNKNOWN_FIELD
  );

  const staging = normalizePlatformPromotionApprovalRecord(record({
    environment: "staging",
    deployment_id: "deployment-staging-01",
    platform_principal_ids: ["platform-operator-a"],
    authorization_evidence_digests: ["9".repeat(64)],
    quorum: { required: 1, satisfied: true },
  }));
  assert.deepEqual(staging.quorum, { required: PLATFORM_PROMOTION_APPROVAL_QUORUM.staging, satisfied: true });
});

test("all attestation lists are bounded, strictly sorted, unique, and cardinality-matched", () => {
  const cases = [
    { qualification_report_digests: ["7".repeat(64), "7".repeat(64)] },
    { qualification_report_digests: ["7".repeat(64), "6".repeat(64)] },
    { platform_principal_ids: ["platform-operator-b", "platform-operator-a"] },
    { platform_principal_ids: ["platform-operator-a", "platform-operator-a"] },
    { authorization_evidence_digests: ["a".repeat(64), "9".repeat(64)] },
    { authorization_evidence_digests: ["9".repeat(64), "9".repeat(64)] },
    { authorization_evidence_digests: ["9".repeat(64)] },
  ];
  for (const overrides of cases) {
    const code = overrides.authorization_evidence_digests?.length === 1
      ? PLATFORM_PROMOTION_APPROVAL_ERROR_CODES.BINDING
      : overrides.platform_principal_ids || overrides.authorization_evidence_digests
        ? PLATFORM_PROMOTION_APPROVAL_ERROR_CODES.ORDERING
        : PLATFORM_PROMOTION_APPROVAL_ERROR_CODES.ORDERING;
    throwsCode(() => normalizePlatformPromotionApprovalRecord(record(overrides)), code);
  }
  throwsCode(() => normalizePlatformPromotionApprovalRecord(record({ qualification_report_digests: [] })), PLATFORM_PROMOTION_APPROVAL_ERROR_CODES.INPUT);
  throwsCode(() => normalizePlatformPromotionApprovalRecord(record({ platform_principal_ids: [] })), PLATFORM_PROMOTION_APPROVAL_ERROR_CODES.INPUT);
  throwsCode(() => normalizePlatformPromotionApprovalRecord(record({ authorization_evidence_digests: [] })), PLATFORM_PROMOTION_APPROVAL_ERROR_CODES.INPUT);

  const tooManyQualification = Array.from({ length: PLATFORM_PROMOTION_APPROVAL_MAX_QUALIFICATION_REPORT_DIGESTS + 1 }, (_, index) => (
    index.toString(16).padStart(64, "0")
  ));
  const tooManyPrincipals = Array.from({ length: PLATFORM_PROMOTION_APPROVAL_MAX_PLATFORM_PRINCIPAL_IDS + 1 }, (_, index) => (
    `platform-operator-${index.toString().padStart(2, "0")}`
  ));
  const tooManyEvidence = Array.from({ length: PLATFORM_PROMOTION_APPROVAL_MAX_AUTHORIZATION_EVIDENCE_DIGESTS + 1 }, (_, index) => (
    index.toString(16).padStart(64, "0")
  ));
  throwsCode(() => normalizePlatformPromotionApprovalRecord(record({ qualification_report_digests: tooManyQualification })), PLATFORM_PROMOTION_APPROVAL_ERROR_CODES.INPUT);
  throwsCode(() => normalizePlatformPromotionApprovalRecord(record({
    platform_principal_ids: tooManyPrincipals,
    authorization_evidence_digests: tooManyEvidence,
    quorum: { required: 2, satisfied: true },
  })), PLATFORM_PROMOTION_APPROVAL_ERROR_CODES.INPUT);
  assert.equal(PLATFORM_PROMOTION_APPROVAL_MAX_QUALIFICATION_REPORT_DIGESTS, 16);
});

test("rejects unknown fields, organization fields, accessors, symbols, cycles, and poisoned prototypes", () => {
  throwsCode(() => normalizePlatformPromotionApprovalRecord(record({ organization_id: "22222222-2222-4222-8222-222222222222" })), PLATFORM_PROMOTION_APPROVAL_ERROR_CODES.UNKNOWN_FIELD);
  throwsCode(() => normalizePlatformPromotionApprovalRecord(record({ raw_webauthn_assertion: "secret" })), PLATFORM_PROMOTION_APPROVAL_ERROR_CODES.UNKNOWN_FIELD);

  const accessor = record();
  Object.defineProperty(accessor, "policy_id", { enumerable: true, get() { throw new Error("must not execute"); } });
  throwsCode(() => normalizePlatformPromotionApprovalRecord(accessor), PLATFORM_PROMOTION_APPROVAL_ERROR_CODES.INPUT);

  const symbol = record();
  Object.defineProperty(symbol, Symbol("unknown"), { enumerable: true, value: "unexpected" });
  throwsCode(() => normalizePlatformPromotionApprovalRecord(symbol), PLATFORM_PROMOTION_APPROVAL_ERROR_CODES.UNKNOWN_FIELD);

  const accessorArray = record();
  Object.defineProperty(accessorArray.qualification_report_digests, "0", { enumerable: true, get() { throw new Error("must not execute"); } });
  throwsCode(() => normalizePlatformPromotionApprovalRecord(accessorArray), PLATFORM_PROMOTION_APPROVAL_ERROR_CODES.INPUT);

  const cyclic = record();
  cyclic.quorum.self = cyclic;
  throwsCode(() => normalizePlatformPromotionApprovalRecord(cyclic), PLATFORM_PROMOTION_APPROVAL_ERROR_CODES.INPUT);

  const customPrototype = { poisoned: true };
  const poisoned = Object.assign(Object.create(customPrototype), record());
  throwsCode(() => normalizePlatformPromotionApprovalRecord(poisoned), PLATFORM_PROMOTION_APPROVAL_ERROR_CODES.INPUT);

  const nullPrototype = Object.assign(Object.create(null), record());
  throwsCode(() => normalizePlatformPromotionApprovalRecord(nullPrototype), PLATFORM_PROMOTION_APPROVAL_ERROR_CODES.INPUT);
});

test("rejects malformed authorization material and private/session-like values through closed digest fields", () => {
  const invalid = [
    [{ policy_id: "" }, PLATFORM_PROMOTION_APPROVAL_ERROR_CODES.INPUT],
    [{ policy_version: 0 }, PLATFORM_PROMOTION_APPROVAL_ERROR_CODES.INPUT],
    [{ approval_version: Number.MAX_SAFE_INTEGER + 1 }, PLATFORM_PROMOTION_APPROVAL_ERROR_CODES.INPUT],
    [{ platform_principal_ids: ["principal with spaces", "platform-operator-b"] }, PLATFORM_PROMOTION_APPROVAL_ERROR_CODES.INPUT],
    [{ authorization_evidence_digests: ["not-a-digest", "a".repeat(64)] }, PLATFORM_PROMOTION_APPROVAL_ERROR_CODES.INPUT],
    [{ authorization_evidence_digests: ["9".repeat(64), "a".repeat(63) + "Z"] }, PLATFORM_PROMOTION_APPROVAL_ERROR_CODES.INPUT],
    [{ platform_principal_ids: ["platform-operator-a", "platform-operator-b"], authorization_evidence_digests: ["9".repeat(64), "a".repeat(64), "b".repeat(64)] }, PLATFORM_PROMOTION_APPROVAL_ERROR_CODES.BINDING],
  ];
  for (const [overrides, code] of invalid) throwsCode(() => normalizePlatformPromotionApprovalRecord(record(overrides)), code, JSON.stringify(overrides));
});

test("enforces canonical UTC timestamps, positive TTL, bounded TTL, and validation-time gates", () => {
  const invalidTtl = [
    { expires_at: new Date(NOW).toISOString() },
    { expires_at: new Date(NOW - 1).toISOString() },
    { expires_at: new Date(NOW + PLATFORM_PROMOTION_APPROVAL_MAX_TTL_MS + 1).toISOString() },
    { approved_at: "2026-08-15T00:00:00Z" },
    { expires_at: "2026-08-15T00:05:00+00:00" },
  ];
  for (const overrides of invalidTtl) throwsCode(() => normalizePlatformPromotionApprovalRecord(record(overrides)), overrides.approved_at || overrides.expires_at === "2026-08-15T00:05:00+00:00" ? PLATFORM_PROMOTION_APPROVAL_ERROR_CODES.INPUT : PLATFORM_PROMOTION_APPROVAL_ERROR_CODES.TTL);

  throwsCode(
    () => normalizePlatformPromotionApprovalRecord(record({ approved_at: new Date(NOW + 1_000).toISOString() }), { now: NOW, allowFuture: false }),
    PLATFORM_PROMOTION_APPROVAL_ERROR_CODES.TTL
  );
  throwsCode(
    () => normalizePlatformPromotionApprovalRecord(record(), { now: NOW + 5 * 60 * 1_000, allowExpired: false }),
    PLATFORM_PROMOTION_APPROVAL_ERROR_CODES.TTL
  );
  throwsCode(
    () => normalizePlatformPromotionApprovalRecord(record(), { maxTtlMs: PLATFORM_PROMOTION_APPROVAL_MAX_TTL_MS + 1 }),
    PLATFORM_PROMOTION_APPROVAL_ERROR_CODES.CONFIG
  );
  throwsCode(
    () => normalizePlatformPromotionApprovalRecord(record(), { unknown: true }),
    PLATFORM_PROMOTION_APPROVAL_ERROR_CODES.CONFIG
  );
});

test("canonical parser requires canonical JSON and returns the same frozen record", () => {
  const input = record();
  const text = canonicalizePlatformPromotionApprovalRecord(input);
  const parsed = parseCanonicalPlatformPromotionApprovalRecord(text);
  assert.deepEqual(parsed, normalizePlatformPromotionApprovalRecord(input));
  assert.equal(Object.isFrozen(parsed), true);

  const reordered = Object.fromEntries(Object.keys(input).reverse().map((key) => [key, input[key]]));
  throwsCode(
    () => parseCanonicalPlatformPromotionApprovalRecord(JSON.stringify(reordered)),
    PLATFORM_PROMOTION_APPROVAL_ERROR_CODES.NONCANONICAL
  );
  throwsCode(() => parseCanonicalPlatformPromotionApprovalRecord({ ...input }), PLATFORM_PROMOTION_APPROVAL_ERROR_CODES.NONCANONICAL);
});
