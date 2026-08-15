import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import {
  createPlatformAuthorizedPromotionService,
  createPostgresPlatformAuthorizationRepository,
  classifyPlatformAuthorizationDatabaseError,
  platformAuthorizationRequestDigest,
  PLATFORM_AUTHORIZATION_REPOSITORY_ERROR_CODES,
  PLATFORM_AUTHORIZATION_RESERVE_SQL,
  PlatformAuthorizationRepositoryError
} from "../../src/postgres/platform-authorization-repository.mjs";
import { platformPromotionAuthorizationRequestDigest } from "../../src/platform-promotion-http-contract.mjs";
import {
  PROMOTION_EVIDENCE_V3_ALGORITHM,
  PROMOTION_EVIDENCE_V3_MAX_TTL_MS,
  PROMOTION_EVIDENCE_V3_PURPOSE,
  PROMOTION_EVIDENCE_V3_TYPE,
  PROMOTION_EVIDENCE_V3_VERSION,
  normalizePromotionEvidenceV3Statement,
  promotionEvidenceV3SigningData
} from "../../src/promotion-evidence-v3-statement.mjs";
import { canonicalManagedSignerRequestDigest } from "../../src/postgres/managed-signer-key-lifecycle-repository.mjs";

const IDS = Object.freeze({
  organization_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
  promotion_id: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
  proof_id: "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
  jti: "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
});
const REQUEST = Object.freeze({
  promotion_id: IDS.promotion_id,
  deployment_id: "cloud-prod-2026-08",
  environment: "production",
  candidate_id: `release-pkg-sha256-v1-${"a".repeat(64)}`,
  idempotency_key: "platform-promotion-0001"
});
const SESSION_HASH = "11".repeat(32);
const CSRF_TOKEN = Buffer.alloc(32, 0x22).toString("base64url");
const CLAIM_TOKEN = Buffer.alloc(32, 0x33).toString("base64url");
const AUTHORIZATION = Object.freeze({
  organization_id: IDS.organization_id,
  session_material_hash: SESSION_HASH,
  csrf_token: CSRF_TOKEN,
  proof_id: IDS.proof_id,
  jti: IDS.jti
});
const INPUT = Object.freeze({ ...REQUEST, ...AUTHORIZATION });
const NOW = "2026-08-15T00:00:00.000Z";
const EXPIRES = "2026-08-15T01:00:00.000Z";
const APPROVAL_EXPIRES = "2026-08-15T02:00:00.000Z";

function sha256(value) { return crypto.createHash("sha256").update(value, "utf8").digest("hex"); }
function result(value) { return { rowCount: 1, rows: [{ result: value }] }; }

function providerOperationId() {
  const statement = normalizePromotionEvidenceV3Statement({
    version: 3,
    type: PROMOTION_EVIDENCE_V3_TYPE,
    promotion_id: IDS.promotion_id,
    deployment_id: REQUEST.deployment_id,
    environment: REQUEST.environment,
    candidate_id: REQUEST.candidate_id,
    source_commit: "1".repeat(40),
    source_tree: "2".repeat(40),
    product_pkg_sha256: "a".repeat(64),
    image_digest: `sha256:${"c".repeat(64)}`,
    sbom_sha256: "d".repeat(64),
    qualification_report_digests: ["e".repeat(64)],
    release_manifest_schema_version: 4,
    release_manifest_sha256: "f".repeat(64),
    platform_approval_id: "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
    platform_approval_digest: "b".repeat(64),
    approval_state: "approved",
    purpose: PROMOTION_EVIDENCE_V3_PURPOSE,
    protocol_version: 3,
    signing_version: 3,
    lifecycle_version: 7,
    key_id: "promotion-evidence-2026-08",
    key_version: 8,
    issued_at: NOW,
    expires_at: EXPIRES
  }, { allowExpired: true, allowFuture: true, maxTtlMs: PROMOTION_EVIDENCE_V3_MAX_TTL_MS });
  const bytes = promotionEvidenceV3SigningData(statement, { allowExpired: true, allowFuture: true, maxTtlMs: PROMOTION_EVIDENCE_V3_MAX_TTL_MS });
  return `managed-signer-v1-${canonicalManagedSignerRequestDigest({
    algorithm: PROMOTION_EVIDENCE_V3_ALGORITHM,
    bytes,
    key_id: statement.key_id,
    purpose: statement.purpose,
    version: statement.signing_version,
    key_version: statement.key_version
  })}`;
}

function atomicReservedResult(overrides = {}) {
  return {
    state: "reserved",
    promotion_id: IDS.promotion_id,
    deployment_id: REQUEST.deployment_id,
    environment: REQUEST.environment,
    candidate_id: REQUEST.candidate_id,
    idempotency_key: REQUEST.idempotency_key,
    platform_approval_id: "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
    platform_approval_digest: "b".repeat(64),
    source_commit: "1".repeat(40),
    source_tree: "2".repeat(40),
    product_pkg_sha256: "a".repeat(64),
    image_digest: `sha256:${"c".repeat(64)}`,
    sbom_sha256: "d".repeat(64),
    qualification_report_digests: ["e".repeat(64)],
    release_manifest_schema_version: 4,
    release_manifest_sha256: "f".repeat(64),
    approval_state: "approved",
    approval_expires_at: APPROVAL_EXPIRES,
    issued_at: NOW,
    expires_at: EXPIRES,
    purpose: PROMOTION_EVIDENCE_V3_PURPOSE,
    protocol_version: 3,
    signing_version: 3,
    lifecycle_version: 7,
    key_id: "promotion-evidence-2026-08",
    key_version: 8,
    signer_key_fingerprint: `SHA256:${Buffer.alloc(32, 0x44).toString("base64url")}`,
    claim_expires_at: "2026-08-15T00:01:00.000Z",
    evidence_bytes: null,
    evidence_digest: null,
    deployment_generation: null,
    uncertain_reason: null,
    created_at: NOW,
    updated_at: NOW,
    claim_issued: true,
    ...overrides
  };
}

function fakeIssuanceRepository(calls) {
  return {
    async reservePlatformPromotion() {
      calls.directReserve += 1;
      throw new Error("legacy direct reserve must never be called");
    },
    async commitPlatformPromotion(input) { calls.commit.push(input); return { state: "uncertain" }; },
    async replayPlatformPromotion(input) { calls.replay.push(input); return { state: "absent" }; },
    async markPlatformPromotionUncertain(input) { calls.uncertain.push(input); return { state: "uncertain" }; },
    async getCommittedPlatformPromotion(input) { calls.get.push(input); return { state: "absent" }; }
  };
}

function makeClient(atomic = atomicReservedResult()) {
  const calls = [];
  return {
    calls,
    async query(text, params) {
      calls.push({ text, params });
      if (text === "BEGIN" || text === "COMMIT" || text === "ROLLBACK") return { rowCount: 0, rows: [] };
      if (text === PLATFORM_AUTHORIZATION_RESERVE_SQL) return result(atomic);
      throw new Error("unexpected SQL");
    }
  };
}

function makeRepository({ atomic = atomicReservedResult(), randomBytes = () => Buffer.alloc(32, 0x33) } = {}) {
  const client = makeClient(atomic);
  const calls = { directReserve: 0, commit: [], replay: [], uncertain: [], get: [] };
  const repository = createPostgresPlatformAuthorizationRepository({
    client,
    promotionRepository: fakeIssuanceRepository(calls),
    randomBytes,
    keyId: "promotion-evidence-2026-08",
    keyVersion: 8,
    lifecycleVersion: 7
  });
  return { client, calls, repository };
}

test("0054 digest is byte-for-byte the SQL canonical JSON and differs from HTTP recent-auth context", async () => {
  const canonical = `{"candidate_id":"${REQUEST.candidate_id}","deployment_id":"${REQUEST.deployment_id}","environment":"production","idempotency_key":"${REQUEST.idempotency_key}","operation":"platform.promotion.issue","organization_id":"${IDS.organization_id}","promotion_id":"${IDS.promotion_id}"}`;
  const expected = sha256(canonical);
  assert.equal(platformAuthorizationRequestDigest(REQUEST, { organizationId: IDS.organization_id }), expected);
  assert.equal(platformPromotionAuthorizationRequestDigest(REQUEST, { organizationId: IDS.organization_id }), expected);
});

test("atomic adapter hashes CSRF/JTI and passes only digests to the exact 0054 function", async () => {
  const { client, calls, repository } = makeRepository();
  assert.equal(Object.hasOwn(repository, "replayPlatformPromotion"), false);
  assert.equal(Object.hasOwn(repository, "getCommittedPlatformPromotion"), false);
  const reserved = await repository.forAuthorization(AUTHORIZATION).reservePlatformPromotion(REQUEST);
  assert.equal(reserved.state, "reserved");
  assert.equal(reserved.claim_token, CLAIM_TOKEN);
  assert.equal(Object.isFrozen(reserved), true);
  assert.equal(calls.directReserve, 0);
  const scoped = repository.forAuthorization(AUTHORIZATION);
  assert.equal(Object.hasOwn(scoped, "replayPlatformPromotion"), false);
  assert.equal(Object.hasOwn(scoped, "getCommittedPlatformPromotion"), false);

  const atomicCall = client.calls.find((call) => call.text === PLATFORM_AUTHORIZATION_RESERVE_SQL);
  assert.ok(atomicCall);
  assert.match(atomicCall.text, /agentpass_consume_platform_authorization_and_reserve/u);
  assert.doesNotMatch(atomicCall.text, /agentpass_platform_promotion_issuance_reserve/u);
  assert.equal(atomicCall.params.length, 16);
  assert.equal(atomicCall.params[0].toString("hex"), SESSION_HASH);
  assert.equal(atomicCall.params[1].toString("hex"), sha256(CSRF_TOKEN));
  assert.equal(atomicCall.params[3].toString("hex"), sha256(IDS.jti));
  assert.equal(atomicCall.params[4].toString("hex"), platformAuthorizationRequestDigest(REQUEST, { organizationId: IDS.organization_id }));
  assert.equal(atomicCall.params[10].toString("hex"), sha256(CLAIM_TOKEN));
  assert.equal(atomicCall.params.some((value) => value === CSRF_TOKEN || value === IDS.jti || value === CLAIM_TOKEN), false);
});

test("unscoped reserve requires the full authorization envelope and never falls back to legacy reserve", async () => {
  const { repository, calls } = makeRepository();
  await assert.rejects(
    repository.reservePlatformPromotion(REQUEST),
    (error) => error instanceof PlatformAuthorizationRepositoryError
      && error.code === PLATFORM_AUTHORIZATION_REPOSITORY_ERROR_CODES.INPUT
  );
  assert.equal(calls.directReserve, 0);
  assert.throws(
    () => repository.forAuthorization({ ...AUTHORIZATION, session_material_hash: "raw-cookie" }),
    (error) => error instanceof PlatformAuthorizationRepositoryError
      && error.code === PLATFORM_AUTHORIZATION_REPOSITORY_ERROR_CODES.INPUT
  );
});

test("strict keys and opaque database errors do not expose raw authorization material", async () => {
  const client = {
    async query(text) {
      if (text === "BEGIN") return { rowCount: 0, rows: [] };
      if (text === "ROLLBACK") return { rowCount: 0, rows: [] };
      throw new Error(`database leaked ${CSRF_TOKEN} ${IDS.jti} ${CLAIM_TOKEN}`);
    }
  };
  const repository = createPostgresPlatformAuthorizationRepository({
    client,
    promotionRepository: fakeIssuanceRepository({ directReserve: 0, commit: [], replay: [], uncertain: [], get: [] }),
    randomBytes: () => Buffer.alloc(32, 0x33),
    keyId: "promotion-evidence-2026-08",
    keyVersion: 8,
    lifecycleVersion: 7
  });
  await assert.rejects(repository.forAuthorization(AUTHORIZATION).reservePlatformPromotion(REQUEST), (error) => {
    assert.equal(error.code, PLATFORM_AUTHORIZATION_REPOSITORY_ERROR_CODES.DATABASE);
    assert.equal(error.message.includes(CSRF_TOKEN), false);
    assert.equal(error.message.includes(IDS.jti), false);
    assert.equal(error.message.includes(CLAIM_TOKEN), false);
    return true;
  });
  await assert.rejects(
    repository.forAuthorization(AUTHORIZATION).reservePlatformPromotion({ ...REQUEST, unexpected: true }),
    (error) => error.code === PLATFORM_AUTHORIZATION_REPOSITORY_ERROR_CODES.INPUT
  );
});

test("classifies database failures from SQLSTATE and exact constraint metadata only", () => {
  const codes = PLATFORM_AUTHORIZATION_REPOSITORY_ERROR_CODES;
  assert.equal(
    classifyPlatformAuthorizationDatabaseError({
      code: "23505",
      constraint: "platform_promotion_issuances_deployment_id_environment_candidate_idempotency_key_key",
      message: `duplicate ${CSRF_TOKEN} ${IDS.jti}`
    }),
    codes.IDEMPOTENCY_CONFLICT
  );
  assert.equal(
    classifyPlatformAuthorizationDatabaseError({
      code: "40001",
      message: `platform authorization is stale ${CSRF_TOKEN}`
    }),
    codes.AUTHORIZATION_UNAVAILABLE
  );
  assert.equal(
    classifyPlatformAuthorizationDatabaseError({
      code: "23014",
      message: `replayed ${IDS.jti}`
    }),
    codes.AUTHORIZATION_UNAVAILABLE
  );
  assert.equal(
    classifyPlatformAuthorizationDatabaseError({ code: "42501", message: `denied ${CLAIM_TOKEN}` }),
    codes.AUTHORIZATION_UNAVAILABLE
  );
  assert.equal(
    classifyPlatformAuthorizationDatabaseError({ code: "08006", message: "connection failed" }),
    codes.DATABASE
  );
  assert.equal(
    classifyPlatformAuthorizationDatabaseError({ message: "unique_violation platform authorization stale" }),
    codes.DATABASE
  );
  assert.equal(
    classifyPlatformAuthorizationDatabaseError(Object.create({ code: "23505" })),
    codes.DATABASE
  );
  assert.equal(
    classifyPlatformAuthorizationDatabaseError({
      code: "P0001",
      constraint: "platform_authorization_proofs_one_use",
      message: `replayed ${CLAIM_TOKEN}`
    }),
    codes.AUTHORIZATION_REPLAYED
  );
  assert.equal(
    classifyPlatformAuthorizationDatabaseError({
      code: "P0001",
      constraint: "platform_promotion_issuances_claim_reclaim_fence",
      message: `stale ${CSRF_TOKEN}`
    }),
    codes.AUTHORIZATION_STALE
  );
});

test("consumeAndReserve returns stable classified errors without SQL message or cause", async () => {
  const sqlError = Object.assign(new Error(`database secret ${CSRF_TOKEN} ${IDS.jti} ${CLAIM_TOKEN}`), {
    code: "23505",
    constraint: "platform_promotion_issuances_deployment_id_environment_candidate_idempotency_key_key"
  });
  const client = {
    async query(text) {
      if (text === "BEGIN" || text === "ROLLBACK") return { rowCount: 0, rows: [] };
      throw sqlError;
    }
  };
  const repository = createPostgresPlatformAuthorizationRepository({
    client,
    promotionRepository: fakeIssuanceRepository({ directReserve: 0, commit: [], replay: [], uncertain: [], get: [] }),
    randomBytes: () => Buffer.alloc(32, 0x33),
    keyId: "promotion-evidence-2026-08",
    keyVersion: 8,
    lifecycleVersion: 7
  });

  await assert.rejects(repository.forAuthorization(AUTHORIZATION).reservePlatformPromotion(REQUEST), (error) => {
    assert.equal(error.code, PLATFORM_AUTHORIZATION_REPOSITORY_ERROR_CODES.IDEMPOTENCY_CONFLICT);
    assert.equal(error.message.includes(CSRF_TOKEN), false);
    assert.equal(error.message.includes(IDS.jti), false);
    assert.equal(error.message.includes(CLAIM_TOKEN), false);
    assert.equal(error.cause, undefined);
    return true;
  });
});

test("service composition binds authorization before invoking the existing issuance contract", async () => {
  const calls = [];
  const scoped = {
    async reservePlatformPromotion(input) { calls.push(input); return { state: "in_progress" }; },
    async commitPlatformPromotion() { return { state: "uncertain" }; },
    async replayPlatformPromotion() { return { state: "absent" }; },
    async markPlatformPromotionUncertain() { return { state: "uncertain" }; },
    async getCommittedPlatformPromotion() { return { state: "absent" }; }
  };
  const service = createPlatformAuthorizedPromotionService({
    repository: { forAuthorization(input) {
      assert.deepEqual(Object.keys(input).sort(), ["csrf_token", "jti", "organization_id", "proof_id", "session_material_hash"]);
      assert.equal(input.organization_id, IDS.organization_id);
      assert.equal(input.session_material_hash.toString("hex"), SESSION_HASH);
      assert.equal(input.csrf_token, CSRF_TOKEN);
      assert.equal(input.proof_id, IDS.proof_id);
      assert.equal(input.jti, IDS.jti);
      return scoped;
    } },
    signer: { async sign() { throw new Error("signer must not run"); } },
    publicKeyResolver: async () => undefined,
    now: () => Date.parse(NOW)
  });
  await assert.rejects(service.issuePlatformPromotion(INPUT), (error) => error.code === "ERR_PLATFORM_PROMOTION_ISSUANCE_IN_PROGRESS");
  assert.deepEqual(calls, [REQUEST]);
  assert.equal(Object.hasOwn(service, "replayPlatformPromotion"), false);
  assert.equal(Object.hasOwn(service, "getCommittedPlatformPromotion"), false);
  await assert.rejects(
    service.issuePlatformPromotion({ ...INPUT, session_material_hash: "raw-cookie" }),
    (error) => error instanceof PlatformAuthorizationRepositoryError
      && error.code === PLATFORM_AUTHORIZATION_REPOSITORY_ERROR_CODES.INPUT
  );
});
