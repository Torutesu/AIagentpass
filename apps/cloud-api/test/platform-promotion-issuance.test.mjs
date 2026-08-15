import assert from "node:assert/strict";
import test from "node:test";

import { deriveReleaseCandidateId } from "../../../lib/release-candidate-identity.mjs";
import {
  PROMOTION_EVIDENCE_V3_ALGORITHM,
  PROMOTION_EVIDENCE_V3_PURPOSE,
  PROMOTION_EVIDENCE_V3_SIGNING_VERSION,
  PROMOTION_EVIDENCE_V3_TYPE,
  PROMOTION_EVIDENCE_V3_VERSION,
  promotionEvidenceV3StatementHash,
} from "../src/promotion-evidence-v3-statement.mjs";
import {
  PLATFORM_PROMOTION_ISSUANCE_ERROR_CODES,
  PlatformPromotionIssuanceError,
  createPlatformPromotionIssuanceService,
} from "../src/platform-promotion-issuance.mjs";

const NOW = Date.parse("2026-08-15T00:00:00.000Z");
const INPUT = Object.freeze({
  promotion_id: "11111111-1111-4111-8111-111111111111",
  deployment_id: "cloud-prod-2026-08",
  environment: "production",
  candidate_id: deriveReleaseCandidateId("a".repeat(64)),
  idempotency_key: "promotion-request-0001",
});
const FINGERPRINT = "SHA256:" + "B".repeat(43);

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

function envelope(statement, overrides = {}) {
  return {
    version: PROMOTION_EVIDENCE_V3_VERSION,
    type: PROMOTION_EVIDENCE_V3_TYPE,
    statement,
    statement_hash: promotionEvidenceV3StatementHash(statement),
    signature_algorithm: PROMOTION_EVIDENCE_V3_ALGORITHM,
    signer_key_fingerprint: FINGERPRINT,
    signature: "A".repeat(86),
    ...overrides,
  };
}

function fixture({ reserve = undefined, commit = undefined, replay = undefined, getCommitted = undefined, signer = undefined, now = () => NOW } = {}) {
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
      const { claim_token: ignoredClaimToken, ...authority } = structuredClone(input);
      committed = { state: "committed", ...authority };
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
  const signing = signer ?? (async (statement) => {
    calls.sign.push(structuredClone(statement));
    return envelope(statement);
  });
  const service = createPlatformPromotionIssuanceService({
    repository,
    signer: { sign: signing },
    now,
  });
  return { service, repository, calls, getCommitted: () => committed };
}

function code(error) {
  assert.ok(error instanceof PlatformPromotionIssuanceError);
  return error.code;
}

async function rejects(promise, expected) {
  await assert.rejects(promise, (error) => code(error) === expected);
}

test("reserves authoritative C3 data, signs exact v3 once, verifies, and atomically commits", async () => {
  const value = fixture();
  const result = await value.service.issuePlatformPromotion(INPUT);

  assert.equal(result.replayed, false);
  assert.deepEqual(Object.keys(result).sort(), ["candidate_id", "deployment_id", "environment", "promotion_evidence", "promotion_id", "replayed"]);
  assert.deepEqual(Object.keys(value.calls.reserve[0]).sort(), Object.keys(INPUT).sort());
  assert.equal(value.calls.sign.length, 1);
  assert.equal(value.calls.sign[0].version, 3);
  assert.equal(value.calls.sign[0].purpose, PROMOTION_EVIDENCE_V3_PURPOSE);
  assert.equal(value.calls.sign[0].key_id, "promotion-evidence-production-v3");
  assert.deepEqual(Object.keys(value.calls.commit[0]).sort(), [
    "approval_state", "candidate_id", "claim_token", "deployment_id", "environment", "expires_at", "idempotency_key",
    "image_digest", "issued_at", "key_id", "key_version", "lifecycle_version", "platform_approval_digest",
    "platform_approval_id", "product_pkg_sha256", "promotion_evidence", "promotion_id", "qualification_report_digests",
    "release_manifest_schema_version", "release_manifest_sha256", "sbom_sha256", "signer_key_fingerprint", "source_commit", "source_tree",
  ]);
  assert.equal(Object.isFrozen(result), true);
  assert.equal(Object.isFrozen(result.promotion_evidence), true);
  assert.equal(Object.isFrozen(result.promotion_evidence.statement), true);
  assert.equal(Object.hasOwn(result, "provider_diagnostics"), false);
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

test("lost commit response reconciles through replay and does not re-sign", async () => {
  const value = fixture({
    commit(input, calls, save) {
      const { claim_token: ignoredClaimToken, ...authority } = structuredClone(input);
      save({ state: "committed", ...authority });
      throw new Error("response lost");
    },
  });
  const result = await value.service.issuePlatformPromotion(INPUT);
  assert.equal(result.replayed, true);
  assert.equal(value.calls.sign.length, 1);
  assert.equal(value.calls.commit.length, 1);
  assert.equal(value.calls.replay.length, 1);
  assert.equal(value.calls.uncertain.length, 0);
});

test("signer/provider ambiguity is durably uncertain and never blindly retried", async () => {
  let signCalls = 0;
  const value = fixture({ signer: async () => { signCalls += 1; throw new Error("provider timeout"); } });
  await rejects(value.service.issuePlatformPromotion(INPUT), PLATFORM_PROMOTION_ISSUANCE_ERROR_CODES.UNCERTAIN);
  await rejects(value.service.issuePlatformPromotion(INPUT), PLATFORM_PROMOTION_ISSUANCE_ERROR_CODES.UNCERTAIN);
  assert.equal(signCalls, 1);
  assert.equal(value.calls.uncertain.length, 1);
  assert.equal(Object.hasOwn(value.calls.uncertain[0], "provider_diagnostics"), false);
});

test("malformed signer envelopes and cross-purpose/key/fingerprint substitutions fail closed", async (t) => {
  const cases = [
    ["v2", (statement) => envelope(statement, { version: 2 }), PLATFORM_PROMOTION_ISSUANCE_ERROR_CODES.SIGNER_OUTPUT],
    ["purpose", (statement) => ({ ...envelope(statement), statement: { ...statement, purpose: "agentpass.audit-anchor" }, statement_hash: "0".repeat(64) }), PLATFORM_PROMOTION_ISSUANCE_ERROR_CODES.SIGNER_OUTPUT],
    ["statement substitution", (statement) => envelope({ ...statement, environment: "staging" }), PLATFORM_PROMOTION_ISSUANCE_ERROR_CODES.BINDING],
    ["key substitution", (statement) => envelope({ ...statement, key_id: "other-key" }), PLATFORM_PROMOTION_ISSUANCE_ERROR_CODES.BINDING],
    ["fingerprint substitution", (statement) => envelope(statement, { signer_key_fingerprint: "SHA256:" + "C".repeat(43) }), PLATFORM_PROMOTION_ISSUANCE_ERROR_CODES.BINDING],
    ["diagnostics", (statement) => ({ ...envelope(statement), provider_diagnostics: "secret" }), PLATFORM_PROMOTION_ISSUANCE_ERROR_CODES.SIGNER_OUTPUT],
  ];
  for (const [name, make] of cases) {
    await t.test(name, async () => {
      const value = fixture({ signer: async (statement) => make(statement) });
      await rejects(value.service.issuePlatformPromotion(INPUT), cases.find(([label]) => label === name)[2]);
      assert.equal(value.calls.sign.length, 0, "fixture signer does not record direct calls");
      assert.equal(value.calls.uncertain.length, 1);
    });
  }
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
