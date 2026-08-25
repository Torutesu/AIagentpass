import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";

import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";

import { canonicalJson } from "../../../packages/protocol/src/index.mjs";
import { deriveReleaseCandidateId } from "../../../lib/release-candidate-identity.mjs";
import {
  PROMOTION_EVIDENCE_V3_ALGORITHM,
  PROMOTION_EVIDENCE_V3_ENVELOPE_KEYS,
  PROMOTION_EVIDENCE_V3_ERROR_CODES,
  PROMOTION_EVIDENCE_V3_MAX_QUALIFICATION_REPORT_DIGESTS,
  PROMOTION_EVIDENCE_V3_MAX_TTL_MS,
  PROMOTION_EVIDENCE_V3_MIN_QUALIFICATION_REPORT_DIGESTS,
  PROMOTION_EVIDENCE_V3_PROTOCOL_VERSION,
  PROMOTION_EVIDENCE_V3_PURPOSE,
  PROMOTION_EVIDENCE_V3_RELEASE_MANIFEST_SCHEMA_VERSION,
  PROMOTION_EVIDENCE_V3_SIGNATURE_DOMAIN,
  PROMOTION_EVIDENCE_V3_SIGNING_VERSION,
  PROMOTION_EVIDENCE_V3_STATEMENT_KEYS,
  PROMOTION_EVIDENCE_V3_TYPE,
  PROMOTION_EVIDENCE_V3_VERSION,
  canonicalSignatureV3,
  canonicalizePromotionEvidenceV3,
  canonicalizePromotionEvidenceV3Statement,
  normalizePromotionEvidenceV3,
  normalizePromotionEvidenceV3Statement,
  parseCanonicalPromotionEvidenceV3,
  parsePromotionEvidenceV3PublicKey,
  promotionEvidenceV3PublicKeyFingerprint,
  promotionEvidenceV3SigningData,
  promotionEvidenceV3StatementHash,
  PromotionEvidenceV3Error,
} from "../src/promotion-evidence-v3-statement.mjs";
import { createHostedPromotionEvidenceV3Signer } from "../src/promotion-evidence-v3-signer.mjs";

const ROOT = path.resolve(import.meta.dirname, "../../..");
const FIXTURE_PATH = path.join(ROOT, "contracts", "fixtures", "promotion-evidence-v3.valid.json");
const SCHEMA_PATH = path.join(ROOT, "contracts", "schemas", "promotion-evidence-v3.schema.json");
const NOW = Date.parse("2026-08-15T00:00:00.000Z");
const PRODUCT_PKG_SHA256 = "a".repeat(64);
const CANDIDATE_ID = deriveReleaseCandidateId(PRODUCT_PKG_SHA256);
const SIGNATURE = "A".repeat(86);
const FINGERPRINT = "SHA256:" + "B".repeat(43);

function statement(overrides = {}) {
  return {
    version: PROMOTION_EVIDENCE_V3_VERSION,
    type: PROMOTION_EVIDENCE_V3_TYPE,
    promotion_id: "11111111-1111-4111-8111-111111111111",
    deployment_id: "cloud-prod-2026-08",
    environment: "production",
    candidate_id: CANDIDATE_ID,
    source_commit: "1".repeat(40),
    source_tree: "2".repeat(40),
    product_pkg_sha256: PRODUCT_PKG_SHA256,
    image_digest: `sha256:${"3".repeat(64)}`,
    sbom_sha256: "4".repeat(64),
    qualification_report_digests: ["0".repeat(63) + "1", "1".repeat(64), "2".repeat(64)],
    release_manifest_schema_version: PROMOTION_EVIDENCE_V3_RELEASE_MANIFEST_SCHEMA_VERSION,
    release_manifest_sha256: "5".repeat(64),
    platform_approval_id: "22222222-2222-4222-8222-222222222222",
    platform_approval_digest: "6".repeat(64),
    approval_state: "approved",
    purpose: PROMOTION_EVIDENCE_V3_PURPOSE,
    protocol_version: PROMOTION_EVIDENCE_V3_PROTOCOL_VERSION,
    signing_version: PROMOTION_EVIDENCE_V3_SIGNING_VERSION,
    lifecycle_version: 3,
    key_id: "promotion-evidence-production-v3",
    key_version: 7,
    issued_at: new Date(NOW).toISOString(),
    expires_at: new Date(NOW + 5 * 60 * 1_000).toISOString(),
    ...overrides,
  };
}

function envelope(input = statement()) {
  const normalized = normalizePromotionEvidenceV3Statement(input, { now: NOW, allowExpired: false, allowFuture: false });
  return {
    version: PROMOTION_EVIDENCE_V3_VERSION,
    type: PROMOTION_EVIDENCE_V3_TYPE,
    statement: normalized,
    statement_hash: promotionEvidenceV3StatementHash(normalized),
    signature_algorithm: PROMOTION_EVIDENCE_V3_ALGORITHM,
    signer_key_fingerprint: FINGERPRINT,
    signature: SIGNATURE,
  };
}

function expectCode(invoke, code) {
  assert.throws(invoke, (error) => error instanceof PromotionEvidenceV3Error && error.code === code);
}

function sortedDigests(count) {
  return Array.from({ length: count }, (_, index) => index.toString(16).padStart(64, "0"));
}

test("v3 canonical statement binds deployment-scoped promotion inputs and preserves sorted evidence cardinality", () => {
  const value = normalizePromotionEvidenceV3Statement(statement(), { now: NOW, allowExpired: false, allowFuture: false });
  assert.equal(value.promotion_id, "11111111-1111-4111-8111-111111111111");
  assert.equal(value.deployment_id, "cloud-prod-2026-08");
  assert.equal(Object.hasOwn(value, "organization_id"), false);
  assert.deepEqual(value.qualification_report_digests, statement().qualification_report_digests);
  assert.equal(Object.isFrozen(value), true);
  assert.equal(Object.isFrozen(value.qualification_report_digests), true);

  const reordered = Object.fromEntries(Object.entries(statement()).reverse());
  assert.equal(canonicalizePromotionEvidenceV3Statement(statement()), canonicalizePromotionEvidenceV3Statement(reordered));
  const signingData = promotionEvidenceV3SigningData(value);
  assert.equal(signingData.subarray(0, Buffer.byteLength(PROMOTION_EVIDENCE_V3_SIGNATURE_DOMAIN)).toString(), PROMOTION_EVIDENCE_V3_SIGNATURE_DOMAIN);
  assert.equal(signingData.length <= 128 * 1024, true);
  assert.equal(value.qualification_report_digests.length >= PROMOTION_EVIDENCE_V3_MIN_QUALIFICATION_REPORT_DIGESTS, true);
});

test("every C3 release and approval binding changes the signed preimage", () => {
  const baseHash = promotionEvidenceV3StatementHash(statement());
  const substitutions = [
    ["promotion_id", "33333333-3333-4333-8333-333333333333"],
    ["deployment_id", "cloud-staging-2026-08"],
    ["environment", "staging"],
    ["source_commit", "7".repeat(40)],
    ["source_tree", "8".repeat(40)],
    ["image_digest", `sha256:${"9".repeat(64)}`],
    ["sbom_sha256", "a".repeat(64)],
    ["qualification_report_digests", ["0".repeat(63) + "1", "1".repeat(64), "3".repeat(64)]],
    ["release_manifest_sha256", "b".repeat(64)],
    ["platform_approval_id", "44444444-4444-4444-8444-444444444444"],
    ["platform_approval_digest", "c".repeat(64)],
    ["lifecycle_version", 4],
    ["key_id", "promotion-evidence-production-v4"],
    ["key_version", 8],
  ];
  for (const [field, replacement] of substitutions) {
    const candidate = { ...statement(), [field]: replacement };
    assert.notEqual(promotionEvidenceV3StatementHash(candidate), baseHash, field);
  }
});

test("candidate identity is derived from the exact product PKG digest", () => {
  expectCode(() => normalizePromotionEvidenceV3Statement({ ...statement(), product_pkg_sha256: "d".repeat(64) }), PROMOTION_EVIDENCE_V3_ERROR_CODES.BINDING);
  expectCode(() => normalizePromotionEvidenceV3Statement({ ...statement(), candidate_id: deriveReleaseCandidateId("e".repeat(64)) }), PROMOTION_EVIDENCE_V3_ERROR_CODES.BINDING);
  expectCode(() => normalizePromotionEvidenceV3Statement({ ...statement(), candidate_id: "release-pkg-sha256-v1-" + "f".repeat(64) }), PROMOTION_EVIDENCE_V3_ERROR_CODES.BINDING);
});

test("purpose, protocol, signing, approval, and manifest versions are exact", () => {
  const invalid = [
    ["purpose", "agentpass.audit-anchor"],
    ["protocol_version", PROMOTION_EVIDENCE_V3_PROTOCOL_VERSION + 1],
    ["signing_version", PROMOTION_EVIDENCE_V3_SIGNING_VERSION + 1],
    ["approval_state", "pending"],
    ["release_manifest_schema_version", 3],
  ];
  for (const [field, replacement] of invalid) expectCode(() => normalizePromotionEvidenceV3Statement({ ...statement(), [field]: replacement }), PROMOTION_EVIDENCE_V3_ERROR_CODES.INPUT);
  expectCode(() => normalizePromotionEvidenceV3Statement({ ...statement(), organization_id: "11111111-1111-4111-8111-111111111111" }), PROMOTION_EVIDENCE_V3_ERROR_CODES.UNKNOWN_FIELD);
});

test("qualification report digest list is sorted, unique, and bounded without assuming two lanes", () => {
  const maximum = sortedDigests(PROMOTION_EVIDENCE_V3_MAX_QUALIFICATION_REPORT_DIGESTS);
  assert.equal(normalizePromotionEvidenceV3Statement({ ...statement(), qualification_report_digests: maximum }).qualification_report_digests.length, 16);
  assert.equal(statement().qualification_report_digests.length, 3);
  expectCode(() => normalizePromotionEvidenceV3Statement({ ...statement(), qualification_report_digests: [] }), PROMOTION_EVIDENCE_V3_ERROR_CODES.INPUT);
  expectCode(() => normalizePromotionEvidenceV3Statement({ ...statement(), qualification_report_digests: sortedDigests(17) }), PROMOTION_EVIDENCE_V3_ERROR_CODES.INPUT);
  expectCode(() => normalizePromotionEvidenceV3Statement({ ...statement(), qualification_report_digests: ["1".repeat(64), "0".repeat(64)] }), PROMOTION_EVIDENCE_V3_ERROR_CODES.ORDERING);
  expectCode(() => normalizePromotionEvidenceV3Statement({ ...statement(), qualification_report_digests: ["1".repeat(64), "1".repeat(64)] }), PROMOTION_EVIDENCE_V3_ERROR_CODES.ORDERING);

  const withExtraProperty = ["0".repeat(63) + "1", "1".repeat(64)];
  Object.defineProperty(withExtraProperty, "extra", { value: "ignored", enumerable: true });
  expectCode(() => normalizePromotionEvidenceV3Statement({ ...statement(), qualification_report_digests: withExtraProperty }), PROMOTION_EVIDENCE_V3_ERROR_CODES.INPUT);
});

test("TTL and validity boundaries are exact and bounded", () => {
  const maximum = statement({ expires_at: new Date(NOW + PROMOTION_EVIDENCE_V3_MAX_TTL_MS).toISOString() });
  assert.doesNotThrow(() => normalizePromotionEvidenceV3Statement(maximum, { now: NOW, allowExpired: false, allowFuture: false }));
  expectCode(() => normalizePromotionEvidenceV3Statement({ ...statement(), expires_at: new Date(NOW + PROMOTION_EVIDENCE_V3_MAX_TTL_MS + 1).toISOString() }, { now: NOW, allowExpired: false, allowFuture: false }), PROMOTION_EVIDENCE_V3_ERROR_CODES.INPUT);
  expectCode(() => normalizePromotionEvidenceV3Statement({ ...statement(), expires_at: new Date(NOW).toISOString() }, { now: NOW, allowExpired: false, allowFuture: false }), PROMOTION_EVIDENCE_V3_ERROR_CODES.INPUT);
  expectCode(() => normalizePromotionEvidenceV3Statement({ ...statement(), issued_at: new Date(NOW + 1).toISOString() }, { now: NOW, allowExpired: false, allowFuture: false }), PROMOTION_EVIDENCE_V3_ERROR_CODES.NOT_YET_VALID);
  expectCode(() => normalizePromotionEvidenceV3Statement(statement(), { now: NOW + 5 * 60 * 1_000, allowExpired: false, allowFuture: false }), PROMOTION_EVIDENCE_V3_ERROR_CODES.EXPIRED);
  expectCode(() => normalizePromotionEvidenceV3Statement(statement(), { maxTtlMs: PROMOTION_EVIDENCE_V3_MAX_TTL_MS + 1 }), PROMOTION_EVIDENCE_V3_ERROR_CODES.CONFIG);
});

test("strict data-tree and unknown-field guards reject hidden or non-data input", () => {
  expectCode(() => normalizePromotionEvidenceV3Statement({ ...statement(), private_key: "-----BEGIN PRIVATE KEY-----" }), PROMOTION_EVIDENCE_V3_ERROR_CODES.UNKNOWN_FIELD);
  const symbolField = { ...statement() };
  symbolField[Symbol("unknown")] = true;
  expectCode(() => normalizePromotionEvidenceV3Statement(symbolField), PROMOTION_EVIDENCE_V3_ERROR_CODES.UNKNOWN_FIELD);

  const accessor = { ...statement() };
  delete accessor.key_id;
  Object.defineProperty(accessor, "key_id", { enumerable: true, get: () => "secret-key" });
  expectCode(() => normalizePromotionEvidenceV3Statement(accessor), PROMOTION_EVIDENCE_V3_ERROR_CODES.INPUT);

  const cyclic = statement();
  cyclic.cycle = cyclic;
  expectCode(() => normalizePromotionEvidenceV3Statement(cyclic), PROMOTION_EVIDENCE_V3_ERROR_CODES.INPUT);
  expectCode(() => normalizePromotionEvidenceV3Statement({ ...statement(), key_id: undefined }), PROMOTION_EVIDENCE_V3_ERROR_CODES.INPUT);
  expectCode(() => normalizePromotionEvidenceV3Statement({ ...statement(), lifecycle_version: 1n }), PROMOTION_EVIDENCE_V3_ERROR_CODES.INPUT);
  expectCode(() => normalizePromotionEvidenceV3Statement({ ...statement(), issued_at: "2026-08-15T00:00:00Z" }), PROMOTION_EVIDENCE_V3_ERROR_CODES.INPUT);
});

test("envelope normalization, canonical parsing, and signature shape are fail-closed", () => {
  const value = envelope();
  const normalized = normalizePromotionEvidenceV3(value, { now: NOW, allowExpired: false, allowFuture: false });
  assert.deepEqual(normalized, value);
  assert.equal(canonicalizePromotionEvidenceV3(value), canonicalJson(value));
  const canonical = canonicalizePromotionEvidenceV3(value, { now: NOW, allowExpired: false, allowFuture: false });
  assert.deepEqual(parseCanonicalPromotionEvidenceV3(Buffer.from(canonical), { now: NOW, allowExpired: false, allowFuture: false }), normalized);
  expectCode(() => parseCanonicalPromotionEvidenceV3(JSON.stringify(value), { now: NOW, allowExpired: false, allowFuture: false }), PROMOTION_EVIDENCE_V3_ERROR_CODES.NONCANONICAL);
  expectCode(() => parseCanonicalPromotionEvidenceV3(Buffer.from("{\"version\":3}"), { now: NOW }), PROMOTION_EVIDENCE_V3_ERROR_CODES.UNKNOWN_FIELD);
  expectCode(() => normalizePromotionEvidenceV3({ ...value, signer_key_fingerprint: "private-key" }), PROMOTION_EVIDENCE_V3_ERROR_CODES.OUTPUT);
  expectCode(() => normalizePromotionEvidenceV3({ ...value, signature_algorithm: "rsa" }), PROMOTION_EVIDENCE_V3_ERROR_CODES.OUTPUT);
  expectCode(() => normalizePromotionEvidenceV3({ ...value, statement_hash: "0".repeat(64) }), PROMOTION_EVIDENCE_V3_ERROR_CODES.SIGNATURE);
  expectCode(() => normalizePromotionEvidenceV3({ ...value, organization_id: "secret" }), PROMOTION_EVIDENCE_V3_ERROR_CODES.UNKNOWN_FIELD);
  expectCode(() => canonicalSignatureV3("A".repeat(85)), PROMOTION_EVIDENCE_V3_ERROR_CODES.OUTPUT);
  expectCode(() => canonicalSignatureV3("A".repeat(86) + "!"), PROMOTION_EVIDENCE_V3_ERROR_CODES.OUTPUT);
  assert.equal(canonicalSignatureV3(SIGNATURE).length, 64);
  assert.deepEqual(Object.keys(normalized).sort(), [...PROMOTION_EVIDENCE_V3_ENVELOPE_KEYS].sort());
});

test("public-key helpers accept only public Ed25519 material and never private keys", () => {
  const pair = crypto.generateKeyPairSync("ed25519");
  const publicPem = pair.publicKey.export({ type: "spki", format: "pem" }).toString();
  assert.equal(parsePromotionEvidenceV3PublicKey(publicPem).type, "public");
  assert.match(promotionEvidenceV3PublicKeyFingerprint(publicPem), /^SHA256:[A-Za-z0-9_-]{43}$/u);
  expectCode(() => parsePromotionEvidenceV3PublicKey(pair.privateKey), PROMOTION_EVIDENCE_V3_ERROR_CODES.CONFIG);
  expectCode(() => parsePromotionEvidenceV3PublicKey(pair.privateKey.export({ type: "pkcs8", format: "pem" }).toString()), PROMOTION_EVIDENCE_V3_ERROR_CODES.CONFIG);
  assert.equal(JSON.stringify({ publicPem }).includes("PRIVATE KEY"), false);
});

test("v3 fixture is canonical, cryptographically shaped, and schema-compatible", () => {
  const fixture = JSON.parse(fs.readFileSync(FIXTURE_PATH, "utf8"));
  const schema = JSON.parse(fs.readFileSync(SCHEMA_PATH, "utf8"));
  const ajv = new Ajv2020({ allErrors: true, strict: true });
  addFormats(ajv);
  const validate = ajv.compile(schema);
  assert.equal(validate(fixture), true, JSON.stringify(validate.errors));
  assert.deepEqual(Object.keys(schema.$defs.statement.properties).sort(), [...PROMOTION_EVIDENCE_V3_STATEMENT_KEYS].sort());
  assert.deepEqual(Object.keys(schema.properties).sort(), [...PROMOTION_EVIDENCE_V3_ENVELOPE_KEYS].sort());
  const normalized = normalizePromotionEvidenceV3(fixture, { now: NOW, allowExpired: false, allowFuture: false });
  assert.equal(fixture.statement_hash, promotionEvidenceV3StatementHash(fixture.statement));
  assert.equal(canonicalizePromotionEvidenceV3(fixture, { now: NOW, allowExpired: false, allowFuture: false }), canonicalJson(fixture));
  assert.deepEqual(parseCanonicalPromotionEvidenceV3(Buffer.from(canonicalizePromotionEvidenceV3(fixture)), { now: NOW, allowExpired: false, allowFuture: false }), normalized);

  const duplicate = structuredClone(fixture);
  duplicate.statement.qualification_report_digests[1] = duplicate.statement.qualification_report_digests[0];
  assert.equal(validate(duplicate), false);
  expectCode(() => normalizePromotionEvidenceV3(duplicate), PROMOTION_EVIDENCE_V3_ERROR_CODES.ORDERING);
});

test("hosted v3 signer emits an envelope accepted by the v3 normalizer and schema", async () => {
  const pair = crypto.generateKeyPairSync("ed25519");
  const publicKey = pair.publicKey.export({ type: "spki", format: "pem" }).toString();
  const now = NOW;
  const signer = createHostedPromotionEvidenceV3Signer({
    provider: {
      purpose: PROMOTION_EVIDENCE_V3_PURPOSE,
      algorithm: PROMOTION_EVIDENCE_V3_ALGORITHM,
      version: PROMOTION_EVIDENCE_V3_SIGNING_VERSION,
      key_id: statement().key_id,
      key_version: statement().key_version,
      async publicKeyMetadata() { return { algorithm: PROMOTION_EVIDENCE_V3_ALGORITHM, key_id: statement().key_id, public_key: publicKey }; },
      async sign(input) { return crypto.sign(null, input.bytes, pair.privateKey); },
    },
    keyId: statement().key_id,
    keyVersion: statement().key_version,
    lifecycleVersion: statement().lifecycle_version,
    publicKey,
    now: () => now,
  });
  const output = await signer.sign(statement());
  const normalized = normalizePromotionEvidenceV3(output, { now, allowExpired: false, allowFuture: false });
  assert.equal(normalized.version, PROMOTION_EVIDENCE_V3_VERSION);
  assert.equal(normalized.statement_hash, promotionEvidenceV3StatementHash(normalized.statement, { now, allowExpired: false, allowFuture: false }));
  assert.equal(crypto.verify(null, promotionEvidenceV3SigningData(normalized.statement, { now, allowExpired: false, allowFuture: false }), pair.publicKey, Buffer.from(normalized.signature, "base64url")), true);
});
