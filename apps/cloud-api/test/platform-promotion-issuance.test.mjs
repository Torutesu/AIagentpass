import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import { deriveReleaseCandidateId } from "../../../lib/release-candidate-identity.mjs";
import {
  PROMOTION_EVIDENCE_V3_ALGORITHM,
  PROMOTION_EVIDENCE_V3_PURPOSE,
  PROMOTION_EVIDENCE_V3_TYPE,
  PROMOTION_EVIDENCE_V3_VERSION,
  promotionEvidenceV3SigningData,
  promotionEvidenceV3StatementHash,
} from "../src/promotion-evidence-v3-statement.mjs";
import {
  PLATFORM_PROMOTION_ISSUANCE_ERROR_CODES,
  PlatformPromotionIssuanceError,
  createPlatformPromotionIssuanceService,
} from "../src/platform-promotion-issuance.mjs";
import { createPromotionEvidenceV3PublicKeyResolver } from "../src/promotion-evidence-v3-public-key-resolver.mjs";

const NOW = Date.parse("2026-08-15T00:00:00.000Z");
const INPUT = Object.freeze({
  promotion_id: "11111111-1111-4111-8111-111111111111",
  deployment_id: "cloud-prod-2026-08",
  environment: "production",
  candidate_id: deriveReleaseCandidateId("a".repeat(64)),
  idempotency_key: "promotion-request-0001",
});
const KEYS = crypto.generateKeyPairSync("ed25519");
const PUBLIC_KEY = KEYS.publicKey.export({ type: "spki", format: "pem" }).toString();
const RAW_FINGERPRINT = crypto.createHash("sha256")
  .update(KEYS.publicKey.export({ type: "spki", format: "der" }))
  .digest("hex");
const FINGERPRINT = `SHA256:${Buffer.from(RAW_FINGERPRINT, "hex").toString("base64url")}`;

function reservation(overrides = {}) {
  return {
    state: "reserved",
    ...INPUT,
    source_commit: "1".repeat(40),
    source_tree: "2".repeat(40),
    product_pkg_sha256: "a".repeat(64),
    image_digest: `sha256:${"3".repeat(64)}`,
    sbom_sha256: "4".repeat(64),
    qualification_report_digests: ["0".repeat(63) + "1", "1".repeat(64)],
    release_manifest_schema_version: 4,
    release_manifest_sha256: "5".repeat(64),
    platform_approval_id: "22222222-2222-4222-8222-222222222222",
    platform_approval_digest: "6".repeat(64),
    approval_state: "approved",
    lifecycle_version: 3,
    key_id: "promotion-evidence-production-v3",
    key_version: 7,
    issued_at: new Date(NOW).toISOString(),
    expires_at: new Date(NOW + 5 * 60_000).toISOString(),
    signer_key_fingerprint: FINGERPRINT,
    claim_token: "claim-token-0000000000000001",
    ...overrides,
  };
}

function envelope(statement, overrides = {}, privateKey = KEYS.privateKey) {
  const signature = crypto.sign(
    null,
    promotionEvidenceV3SigningData(statement, { now: NOW, allowExpired: true, allowFuture: true }),
    privateKey,
  ).toString("base64url");
  return {
    version: PROMOTION_EVIDENCE_V3_VERSION,
    type: PROMOTION_EVIDENCE_V3_TYPE,
    statement,
    statement_hash: promotionEvidenceV3StatementHash(statement),
    signature_algorithm: PROMOTION_EVIDENCE_V3_ALGORITHM,
    signer_key_fingerprint: FINGERPRINT,
    signature,
    ...overrides,
  };
}

function historicalResolver() {
  const snapshot = {
    version: 3,
    purpose: PROMOTION_EVIDENCE_V3_PURPOSE,
    algorithm: PROMOTION_EVIDENCE_V3_ALGORITHM,
    keys: [{
      key_id: "promotion-evidence-production-v3",
      key_version: 7,
      purpose: PROMOTION_EVIDENCE_V3_PURPOSE,
      algorithm: PROMOTION_EVIDENCE_V3_ALGORITHM,
      public_key: PUBLIC_KEY,
      public_key_fingerprint: RAW_FINGERPRINT,
      state: "active",
      state_version: 1,
    }],
  };
  return createPromotionEvidenceV3PublicKeyResolver({
    repository: { async snapshot() { return structuredClone(snapshot); } },
    now: () => NOW,
  });
}

function fixture({ reserve = undefined, commit = undefined, replay = undefined, getCommitted = undefined, signer = undefined, publicKeyResolver = historicalResolver(), now = () => NOW } = {}) {
  const calls = { reserve: [], commit: [], replay: [], uncertain: [], getCommitted: [], sign: [] };
  let committed;
  let uncertain = false;
  const repository = {
    async reservePlatformPromotion(input) {
      calls.reserve.push(structuredClone(input));
      if (typeof reserve === "function") return reserve(input, calls);
      if (uncertain) return { state: "uncertain" };
      return structuredClone(committed ?? reserve ?? reservation());
    },
    async commitPlatformPromotion(input) {
      calls.commit.push(structuredClone(input));
      if (typeof commit === "function") return commit(input, calls, (value) => { committed = value; });
      const current = reservation();
      const { claim_token: ignoredClaimToken, state: ignoredState, ...authority } = current;
      committed = { state: "committed", ...authority, ...structuredClone(input) };
      delete committed.claim_token;
      return structuredClone(committed);
    },
    async replayPlatformPromotion(input) {
      calls.replay.push(structuredClone(input));
      if (typeof replay === "function") return replay(input, calls, () => committed);
      return committed ? structuredClone(committed) : { state: "absent" };
    },
    async markPlatformPromotionUncertain(input) {
      calls.uncertain.push(structuredClone(input));
      uncertain = true;
      return { state: "uncertain" };
    },
    async getCommittedPlatformPromotion(input) {
      calls.getCommitted.push(structuredClone(input));
      if (typeof getCommitted === "function") return getCommitted(input, calls);
      return structuredClone(committed ?? { state: "absent" });
    },
  };
  const signing = async (statement) => {
    calls.sign.push(structuredClone(statement));
    return signer ? signer(statement, calls) : envelope(statement);
  };
  const service = createPlatformPromotionIssuanceService({ repository, signer: { sign: signing }, publicKeyResolver, now });
  return { service, repository, calls, getCommitted: () => committed };
}

function code(error) {
  assert.ok(error instanceof PlatformPromotionIssuanceError);
  return error.code;
}

async function rejects(promise, expected) {
  await assert.rejects(promise, (error) => code(error) === expected);
}

test("reserves authoritative C3 data, signs exact v3 once, independently verifies, and atomically commits", async () => {
  const value = fixture();
  const result = await value.service.issuePlatformPromotion(INPUT);
  assert.equal(result.replayed, false);
  assert.deepEqual(Object.keys(result).sort(), ["candidate_id", "deployment_id", "environment", "promotion_evidence", "promotion_id", "replayed"]);
  assert.deepEqual(Object.keys(value.calls.reserve[0]).sort(), Object.keys(INPUT).sort());
  assert.equal(value.calls.sign.length, 1);
  assert.equal(value.calls.sign[0].version, 3);
  assert.equal(value.calls.sign[0].purpose, PROMOTION_EVIDENCE_V3_PURPOSE);
  assert.deepEqual(Object.keys(value.calls.commit[0]).sort(), [
    "candidate_id", "claim_token", "deployment_id", "environment", "idempotency_key", "promotion_evidence", "promotion_id",
  ]);
  assert.equal(value.calls.uncertain.length, 0);
  assert.equal(Object.isFrozen(result), true);
  assert.equal(Object.isFrozen(result.promotion_evidence), true);
  assert.equal(Object.isFrozen(result.promotion_evidence.statement), true);
  assert.equal(Object.hasOwn(result, "provider_diagnostics"), false);
});

test("independent trusted verification rejects a forged signature and durably quarantines the reservation", async () => {
  const other = crypto.generateKeyPairSync("ed25519");
  const value = fixture({ signer: (statement) => envelope(statement, {}, other.privateKey) });
  await rejects(value.service.issuePlatformPromotion(INPUT), PLATFORM_PROMOTION_ISSUANCE_ERROR_CODES.VERIFIER);
  assert.equal(value.calls.commit.length, 0);
  assert.deepEqual(Object.keys(value.calls.uncertain[0]).sort(), [
    "candidate_id", "claim_token", "deployment_id", "environment", "idempotency_key", "promotion_id", "reason",
  ]);
  assert.equal(value.calls.uncertain[0].reason, "verification_failure");
  await rejects(value.service.issuePlatformPromotion(INPUT), PLATFORM_PROMOTION_ISSUANCE_ERROR_CODES.UNCERTAIN);
  assert.equal(value.calls.sign.length, 1);
});

test("exact replay returns the committed envelope without signing again", async () => {
  const first = fixture();
  const issued = await first.service.issuePlatformPromotion(INPUT);
  const replayed = await first.service.issuePlatformPromotion(INPUT);
  assert.equal(replayed.replayed, true);
  assert.deepEqual(replayed.promotion_evidence, issued.promotion_evidence);
  assert.equal(first.calls.sign.length, 1);
  assert.equal(first.calls.reserve.length, 2);
});

test("historical replay/get verifies expired stored evidence and rejects tampering", async () => {
  let clock = NOW;
  const value = fixture({ now: () => clock });
  const issued = await value.service.issuePlatformPromotion(INPUT);
  clock = NOW + 6 * 60_000;

  const replayed = await value.service.replayPlatformPromotion(INPUT);
  const retrieved = await value.service.getCommittedPlatformPromotion(INPUT);
  assert.equal(replayed.replayed, true);
  assert.deepEqual(replayed.promotion_evidence, issued.promotion_evidence);
  assert.deepEqual(retrieved.promotion_evidence, issued.promotion_evidence);

  const other = crypto.generateKeyPairSync("ed25519");
  const stored = value.getCommitted();
  stored.promotion_evidence.signature = crypto.sign(
    null,
    promotionEvidenceV3SigningData(stored.promotion_evidence.statement, { now: NOW, allowExpired: true, allowFuture: true }),
    other.privateKey,
  ).toString("base64url");
  await rejects(value.service.replayPlatformPromotion(INPUT), PLATFORM_PROMOTION_ISSUANCE_ERROR_CODES.OUTPUT);
  await rejects(value.service.getCommittedPlatformPromotion(INPUT), PLATFORM_PROMOTION_ISSUANCE_ERROR_CODES.OUTPUT);
  assert.equal(value.calls.sign.length, 1);
});

test("lost commit response reconciles through replay and does not re-sign", async () => {
  let resolverCalls = 0;
  const resolver = historicalResolver();
  const value = fixture({
    publicKeyResolver: async (request) => {
      resolverCalls += 1;
      return resolver(request);
    },
    commit(input, calls, save) {
      const current = reservation();
      const { claim_token: ignoredClaimToken, state: ignoredState, ...authority } = current;
      const { claim_token: ignoredCommitClaimToken, ...commitRecord } = structuredClone(input);
      save({ state: "committed", ...authority, ...commitRecord });
      throw new Error("response lost");
    },
  });
  const result = await value.service.issuePlatformPromotion(INPUT);
  assert.equal(result.replayed, true);
  assert.equal(value.calls.sign.length, 1);
  assert.equal(value.calls.commit.length, 1);
  assert.equal(value.calls.replay.length, 1);
  assert.equal(value.calls.uncertain.length, 0);
  assert.equal(resolverCalls, 2, "pre-commit and historical replay both verify cryptographically");
});

test("signer/provider ambiguity is durably uncertain and never blindly retried", async () => {
  let signCalls = 0;
  const value = fixture({ signer: async () => { signCalls += 1; throw new Error("provider timeout"); } });
  await rejects(value.service.issuePlatformPromotion(INPUT), PLATFORM_PROMOTION_ISSUANCE_ERROR_CODES.UNCERTAIN);
  await rejects(value.service.issuePlatformPromotion(INPUT), PLATFORM_PROMOTION_ISSUANCE_ERROR_CODES.UNCERTAIN);
  assert.equal(signCalls, 1);
  assert.equal(value.calls.uncertain.length, 1);
  assert.deepEqual(Object.keys(value.calls.uncertain[0]).sort(), [
    "candidate_id", "claim_token", "deployment_id", "environment", "idempotency_key", "promotion_id", "reason",
  ]);
  assert.equal(Object.hasOwn(value.calls.uncertain[0], "provider_diagnostics"), false);
});

test("hosted issuance accepts only the complete exact v3 envelope, never a raw signature", async (t) => {
  for (const [name, make] of [
    ["raw signature", () => "A".repeat(86)],
    ["signature-only object", () => ({ signature: "A".repeat(86) })],
    ["v2 envelope", (statement) => envelope(statement, { version: 2 })],
    ["diagnostic field", (statement) => ({ ...envelope(statement), provider_diagnostics: "secret" })],
  ]) {
    await t.test(name, async () => {
      const value = fixture({ signer: (statement) => make(statement) });
      await rejects(value.service.issuePlatformPromotion(INPUT), PLATFORM_PROMOTION_ISSUANCE_ERROR_CODES.SIGNER_OUTPUT);
      assert.equal(value.calls.commit.length, 0);
      assert.equal(value.calls.uncertain.length, 1);
    });
  }
});

test("rejects cross-context substitutions before commit and keeps the full reservation binding", async (t) => {
  const cases = [
    ["purpose", (statement) => ({ ...envelope(statement), statement: { ...statement, purpose: "agentpass.audit-anchor" }, statement_hash: "0".repeat(64) }), PLATFORM_PROMOTION_ISSUANCE_ERROR_CODES.SIGNER_OUTPUT],
    ["statement substitution", (statement) => envelope({ ...statement, environment: "staging" }), PLATFORM_PROMOTION_ISSUANCE_ERROR_CODES.BINDING],
    ["key substitution", (statement) => envelope({ ...statement, key_id: "other-key" }), PLATFORM_PROMOTION_ISSUANCE_ERROR_CODES.BINDING],
    ["fingerprint substitution", (statement) => envelope(statement, { signer_key_fingerprint: "SHA256:" + "C".repeat(43) }), PLATFORM_PROMOTION_ISSUANCE_ERROR_CODES.BINDING],
  ];
  for (const [name, make, expected] of cases) {
    await t.test(name, async () => {
      const value = fixture({ signer: (statement) => make(statement) });
      await rejects(value.service.issuePlatformPromotion(INPUT), expected);
      assert.equal(value.calls.commit.length, 0);
      assert.equal(value.calls.uncertain.length, 1);
    });
  }
});

test("historical resolver failures are independent verification failures", async () => {
  const value = fixture({ publicKeyResolver: async () => { throw new Error("database secret"); } });
  await rejects(value.service.issuePlatformPromotion(INPUT), PLATFORM_PROMOTION_ISSUANCE_ERROR_CODES.VERIFIER);
  assert.equal(value.calls.commit.length, 0);
  assert.equal(value.calls.uncertain[0].reason, "verification_failure");
});

test("requires the purpose-specific public key resolver and rejects arbitrary verifier seams", () => {
  const value = fixture();
  assert.throws(() => createPlatformPromotionIssuanceService({ repository: value.repository, signer: { sign: async () => undefined } }), (error) => code(error) === PLATFORM_PROMOTION_ISSUANCE_ERROR_CODES.CONFIG);
  assert.throws(() => createPlatformPromotionIssuanceService({
    repository: value.repository,
    signer: { sign: async () => undefined },
    publicKeyResolver: () => undefined,
    verifier: { verify: async () => true },
  }), (error) => code(error) === PLATFORM_PROMOTION_ISSUANCE_ERROR_CODES.CONFIG);
});

test("rejects caller substitution and closed/public data attacks before signing", async (t) => {
  const invalid = [
    [{ ...INPUT, deployment_id: "other-deployment" }, PLATFORM_PROMOTION_ISSUANCE_ERROR_CODES.BINDING],
    [{ ...INPUT, environment: "staging" }, PLATFORM_PROMOTION_ISSUANCE_ERROR_CODES.BINDING],
    [{ ...INPUT, candidate_id: deriveReleaseCandidateId("b".repeat(64)) }, PLATFORM_PROMOTION_ISSUANCE_ERROR_CODES.BINDING],
    [{ ...INPUT, extra: true }, PLATFORM_PROMOTION_ISSUANCE_ERROR_CODES.INPUT],
  ];
  for (const [input, expected] of invalid) {
    await t.test("invalid public input", async () => {
      const value = fixture();
      await rejects(value.service.issuePlatformPromotion(input), expected);
      assert.equal(value.calls.reserve.length, expected === PLATFORM_PROMOTION_ISSUANCE_ERROR_CODES.INPUT ? 0 : 1);
      assert.equal(value.calls.sign.length, 0);
    });
  }
  await t.test("accessor", async () => {
    const input = { ...INPUT };
    Object.defineProperty(input, "candidate_id", { enumerable: true, get: () => INPUT.candidate_id });
    const value = fixture();
    await rejects(value.service.issuePlatformPromotion(input), PLATFORM_PROMOTION_ISSUANCE_ERROR_CODES.INPUT);
  });
  await t.test("cycle", async () => {
    const input = { ...INPUT };
    input.cycle = input;
    const value = fixture();
    await rejects(value.service.issuePlatformPromotion(input), PLATFORM_PROMOTION_ISSUANCE_ERROR_CODES.INPUT);
  });
});

test("rejects repository artifact, approval, lifecycle, timestamp, and prototype faults", async (t) => {
  const cases = [
    ["artifact substitution", { product_pkg_sha256: "b".repeat(64) }, PLATFORM_PROMOTION_ISSUANCE_ERROR_CODES.BINDING],
    ["expired approval", { approval_expires_at: new Date(NOW - 1).toISOString() }, PLATFORM_PROMOTION_ISSUANCE_ERROR_CODES.APPROVAL],
    ["disabled lifecycle", { lifecycle_state: "disabled" }, PLATFORM_PROMOTION_ISSUANCE_ERROR_CODES.STALE_LIFECYCLE],
    ["bad timestamp", { issued_at: "2026-08-15T00:00:00Z" }, PLATFORM_PROMOTION_ISSUANCE_ERROR_CODES.REPOSITORY],
    ["unknown repository field", { diagnostics: "do not expose" }, PLATFORM_PROMOTION_ISSUANCE_ERROR_CODES.REPOSITORY],
  ];
  for (const [name, overrides, expected] of cases) {
    await t.test(name, async () => {
      const value = fixture({ reserve: reservation(overrides) });
      await rejects(value.service.issuePlatformPromotion(INPUT), expected);
      assert.equal(value.calls.sign.length, 0);
    });
  }
  await t.test("prototype", async () => {
    const poisoned = Object.create({ poisoned: true });
    Object.assign(poisoned, reservation());
    const value = fixture({ reserve: () => poisoned });
    await rejects(value.service.issuePlatformPromotion(INPUT), PLATFORM_PROMOTION_ISSUANCE_ERROR_CODES.REPOSITORY);
  });
});

test("repository state machine is fail-closed and committed retrieval is historical", async (t) => {
  for (const [state, expected] of [
    ["in_progress", PLATFORM_PROMOTION_ISSUANCE_ERROR_CODES.IN_PROGRESS],
    ["uncertain", PLATFORM_PROMOTION_ISSUANCE_ERROR_CODES.UNCERTAIN],
    ["conflict", PLATFORM_PROMOTION_ISSUANCE_ERROR_CODES.CONFLICT],
  ]) {
    await t.test(state, async () => {
      const value = fixture({ reserve: { state } });
      await rejects(value.service.issuePlatformPromotion(INPUT), expected);
      assert.equal(value.calls.sign.length, 0);
    });
  }
  await t.test("committed get", async () => {
    const first = fixture();
    const issued = await first.service.issuePlatformPromotion(INPUT);
    const result = await first.service.getCommittedPlatformPromotion(INPUT);
    assert.equal(result.replayed, true);
    assert.deepEqual(result.promotion_evidence, issued.promotion_evidence);
    assert.equal(first.calls.sign.length, 1);
    assert.equal(first.calls.getCommitted.length, 1);
  });
});
