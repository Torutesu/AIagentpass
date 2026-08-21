import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import {
  canonicalizePromotionEvidenceV3,
  PROMOTION_EVIDENCE_V3_ALGORITHM,
  PROMOTION_EVIDENCE_V3_MAX_TTL_MS,
  PROMOTION_EVIDENCE_V3_PURPOSE,
  PROMOTION_EVIDENCE_V3_TYPE,
  PROMOTION_EVIDENCE_V3_VERSION,
  promotionEvidenceV3StatementHash,
  promotionEvidenceV3SigningData
} from "../../src/promotion-evidence-v3-statement.mjs";
import { canonicalManagedSignerRequestDigest } from "../../src/postgres/managed-signer-key-lifecycle-repository.mjs";
import { createPlatformPromotionIssuanceService } from "../../src/platform-promotion-issuance.mjs";
import {
  createPostgresPlatformPromotionIssuanceRepository,
  PlatformPromotionIssuanceRepositoryError,
  PLATFORM_PROMOTION_ISSUANCE_ERROR_CODES as CODES
} from "../../src/postgres/platform-promotion-issuance-repository.mjs";

const IDENTITY = Object.freeze({
  promotion_id: "11111111-1111-4111-8111-111111111111",
  deployment_id: "cloud-prod-2026-08",
  environment: "production",
  candidate_id: `release-pkg-sha256-v1-${"a".repeat(64)}`,
  idempotency_key: "promotion-request-0001"
});
const SIGNER_KEY_FINGERPRINT = `SHA256:${Buffer.alloc(32, 7).toString("base64url")}`;
const AUTHORITY = Object.freeze({
  approval_id: "22222222-2222-4222-8222-222222222222",
  approval_digest: "b".repeat(64),
  source_commit: "1".repeat(40), source_tree: "2".repeat(40),
  product_pkg_sha256: "a".repeat(64), image_digest: `sha256:${"c".repeat(64)}`,
  sbom_sha256: "d".repeat(64), qualification_report_digests: ["e".repeat(64)],
  release_manifest_schema_version: 4, release_manifest_sha256: "f".repeat(64),
  approval_expires_at: "2026-08-15T01:00:00.000Z", lifecycle_version: 3,
  key_id: "promotion-evidence-2026-08", key_version: 7,
  signer_key_fingerprint: SIGNER_KEY_FINGERPRINT
});

function digest(value) { return crypto.createHash("sha256").update(value, "utf8").digest("hex"); }
function result(rows) { return { rows, rowCount: rows.length }; }
function storedRow(values) {
  const authority = values?.authority ?? AUTHORITY;
  const row = {
    ...IDENTITY, state: "reserved", ...authority,
    purpose: PROMOTION_EVIDENCE_V3_PURPOSE, protocol_version: 3, signing_version: 3,
    provider_operation_id: values?.provider_operation_id,
    request_digest: null, claim_token_digest: values?.claim_token_digest ?? digest("unused"),
    claim_expires_at: values?.claim_expires_at ?? "2026-08-15T00:00:30.000Z", evidence_digest: null, evidence_bytes: null,
    deployment_generation: null, uncertain_reason: null,
    issued_at: values?.issued_at ?? "2026-08-15T00:00:00.000Z", expires_at: values?.expires_at ?? "2026-08-15T01:00:00.000Z",
    created_at: "2026-08-15T00:00:00.000Z", updated_at: "2026-08-15T00:00:00.000Z"
  };
  row.provider_operation_id ??= providerOperationId(evidenceFor(row).statement);
  row.request_digest = Buffer.from(row.provider_operation_id.slice("managed-signer-v1-".length), "hex");
  return row;
}

function providerOperationId(statement) {
  const bytes = promotionEvidenceV3SigningData(statement, { allowExpired: true, allowFuture: true, maxTtlMs: PROMOTION_EVIDENCE_V3_MAX_TTL_MS });
  const requestDigest = canonicalManagedSignerRequestDigest({
    algorithm: PROMOTION_EVIDENCE_V3_ALGORITHM,
    bytes,
    key_id: statement.key_id,
    purpose: statement.purpose,
    version: statement.signing_version,
    key_version: statement.key_version
  });
  return `managed-signer-v1-${requestDigest}`;
}

function evidenceFor(reservation) {
  const statement = {
    version: 3, type: PROMOTION_EVIDENCE_V3_TYPE, promotion_id: reservation.promotion_id,
    deployment_id: reservation.deployment_id, environment: reservation.environment, candidate_id: reservation.candidate_id,
    source_commit: reservation.source_commit, source_tree: reservation.source_tree, product_pkg_sha256: reservation.product_pkg_sha256,
    image_digest: reservation.image_digest, sbom_sha256: reservation.sbom_sha256,
    qualification_report_digests: reservation.qualification_report_digests,
    release_manifest_schema_version: reservation.release_manifest_schema_version, release_manifest_sha256: reservation.release_manifest_sha256,
    platform_approval_id: reservation.platform_approval_id ?? reservation.approval_id,
    platform_approval_digest: reservation.platform_approval_digest ?? reservation.approval_digest,
    approval_state: "approved", purpose: PROMOTION_EVIDENCE_V3_PURPOSE, protocol_version: 3, signing_version: 3,
    lifecycle_version: reservation.lifecycle_version, key_id: reservation.key_id, key_version: reservation.key_version,
    issued_at: reservation.issued_at, expires_at: reservation.expires_at
  };
  return { version: PROMOTION_EVIDENCE_V3_VERSION, type: PROMOTION_EVIDENCE_V3_TYPE, statement,
    statement_hash: promotionEvidenceV3StatementHash(statement), signature_algorithm: PROMOTION_EVIDENCE_V3_ALGORITHM,
    signer_key_fingerprint: reservation.signer_key_fingerprint, signature: Buffer.alloc(64, 7).toString("base64url") };
}

function authorityResult(row, claimIssued = false) {
  return {
    state: row.state,
    promotion_id: row.promotion_id,
    deployment_id: row.deployment_id,
    environment: row.environment,
    candidate_id: row.candidate_id,
    idempotency_key: row.idempotency_key,
    source_commit: row.source_commit,
    source_tree: row.source_tree,
    product_pkg_sha256: row.product_pkg_sha256,
    image_digest: row.image_digest,
    sbom_sha256: row.sbom_sha256,
    qualification_report_digests: [...row.qualification_report_digests],
    release_manifest_schema_version: row.release_manifest_schema_version,
    release_manifest_sha256: row.release_manifest_sha256,
    platform_approval_id: row.approval_id,
    platform_approval_digest: row.approval_digest,
    approval_state: "approved",
    purpose: row.purpose,
    protocol_version: row.protocol_version,
    signing_version: row.signing_version,
    lifecycle_version: row.lifecycle_version,
    key_id: row.key_id,
    key_version: row.key_version,
    signer_key_fingerprint: row.signer_key_fingerprint,
    issued_at: row.issued_at,
    expires_at: row.expires_at,
    approval_expires_at: row.approval_expires_at,
    claim_expires_at: row.claim_expires_at,
    evidence_bytes: row.evidence_bytes === null ? null : Buffer.from(row.evidence_bytes).toString("base64"),
    evidence_digest: row.evidence_digest,
    deployment_generation: row.deployment_generation,
    uncertain_reason: row.uncertain_reason,
    created_at: row.created_at,
    updated_at: row.updated_at,
    claim_issued: claimIssued
  };
}

function sameIdentity(row, params) {
  return ["promotion_id", "deployment_id", "environment", "candidate_id", "idempotency_key"]
    .every((key, index) => String(row[key]) === String(params[index]));
}

function repositoryError(code) {
  return new PlatformPromotionIssuanceRepositoryError(code);
}

function assertAuthorityFunctionBoundary(client) {
  const queryTexts = client.calls.map(({ text }) => text);
  assert.ok(queryTexts.some((text) => /agentpass_platform_promotion_issuance_reserve/u.test(text)));
  assert.equal(queryTexts.some((text) => /\b(?:INSERT|UPDATE|DELETE|TRUNCATE)\b/iu.test(text)), false);
  assert.equal(queryTexts.some((text) => /\b(?:FROM|JOIN)\s+platform_promotion_|\bFOR\s+(?:UPDATE|SHARE)\b|pg_advisory_xact_lock/iu.test(text)), false);
}

class FakePg {
  constructor({ lifecycleAvailable = true, commitResponseLost = false, authority = {} } = {}) {
    this.calls = [];
    this.row = undefined;
    this.lifecycleAvailable = lifecycleAvailable;
    this.commitResponseLost = commitResponseLost;
    this.authority = { ...AUTHORITY, ...authority };
    this.dbNow = "2026-08-15T00:00:00.000Z";
    this.head = { deployment_id: IDENTITY.deployment_id, environment: IDENTITY.environment, current_generation: 0, current_candidate_id: null };
    this.commitParams = null;
  }
  async query(text, params = []) {
    const queryText = String(text);
    this.calls.push({ text: queryText, params: params.map((value) => Buffer.isBuffer(value) ? Buffer.from(value) : value) });
    if (["BEGIN", "COMMIT", "ROLLBACK"].includes(queryText)) return result([]);

    const functionName = queryText.match(/SELECT\s+(agentpass_platform_promotion_issuance_[a-z]+)\(/u)?.[1];
    if (!functionName) throw new Error(`unexpected SQL outside authority boundary: ${queryText.slice(0, 120)}`);
    switch (functionName) {
      case "agentpass_platform_promotion_issuance_reserve": return this.reserve(params);
      case "agentpass_platform_promotion_issuance_replay": return this.replay(params);
      case "agentpass_platform_promotion_issuance_commit": return this.commit(params);
      case "agentpass_platform_promotion_issuance_uncertain": return this.uncertain(params);
      case "agentpass_platform_promotion_issuance_get": return this.get(params);
      default: throw new Error(`unexpected authority function: ${functionName}`);
    }
  }

  reserve(params) {
    assert.equal(params.length, 11);
    if (this.row) {
      const exact = sameIdentity(this.row, params);
      const sameLookup = this.row.promotion_id === params[0]
        || this.row.deployment_id === params[1] && this.row.environment === params[2]
          && this.row.candidate_id === params[3] && this.row.idempotency_key === params[4];
      if (sameLookup && !exact) throw repositoryError(CODES.CONFLICT);
      if (exact) {
        if (this.row.state === "reserved" && !this.claimActive()) this.expireReservation();
        if (this.row.state === "reserved" || this.row.state === "uncertain") return result([{ result: authorityResult(this.row) }]);
        return result([{ result: authorityResult(this.row) }]);
      }
      if (this.row.deployment_id === params[1] && this.row.environment === params[2]
        && ["reserved", "uncertain"].includes(this.row.state)) return result([{ result: authorityResult(this.row) }]);
    }
    if (!this.lifecycleAvailable) throw repositoryError(CODES.LIFECYCLE);
    const issuedAt = this.dbNow;
    const requestedExpiry = new Date(Date.parse(issuedAt) + params[7]).toISOString();
    const expiresAt = new Date(Math.min(Date.parse(this.authority.approval_expires_at), Date.parse(requestedExpiry))).toISOString();
    this.row = storedRow({
      authority: this.authority,
      issued_at: issuedAt,
      expires_at: expiresAt,
      claim_expires_at: new Date(Date.parse(issuedAt) + params[6]).toISOString(),
      claim_token_digest: Buffer.from(params[5]).toString("hex"),
      signer_key_fingerprint: this.authority.signer_key_fingerprint
    });
    this.row.promotion_id = params[0];
    this.row.deployment_id = params[1];
    this.row.environment = params[2];
    this.row.candidate_id = params[3];
    this.row.idempotency_key = params[4];
    this.row.created_at = issuedAt;
    this.row.updated_at = issuedAt;
    this.row.provider_operation_id = providerOperationId(evidenceFor(this.row).statement);
    this.row.request_digest = Buffer.from(this.row.provider_operation_id.slice("managed-signer-v1-".length), "hex");
    return result([{ result: authorityResult(this.row, true) }]);
  }

  replay(params) {
    assert.equal(params.length, 5);
    if (!this.row) return result([{ result: { state: "absent" } }]);
    if (!sameIdentity(this.row, params)) throw repositoryError(CODES.CONFLICT);
    if (this.row.state === "reserved" && !this.claimActive()) this.expireReservation();
    if (this.row.state === "reserved") return result([{ result: { state: "in_progress" } }]);
    if (this.row.state === "uncertain") return result([{ result: { state: "uncertain" } }]);
    return result([{ result: authorityResult(this.row) }]);
  }

  get(params) {
    assert.equal(params.length, 6);
    if (!this.row || params[5] === true && this.row.state !== "committed") return result([{ result: null }]);
    if (!sameIdentity(this.row, params)) throw repositoryError(CODES.CONFLICT);
    return result([{ result: authorityResult(this.row) }]);
  }

  commit(params) {
    assert.equal(params.length, 10);
    if (!this.row || !sameIdentity(this.row, params)) throw repositoryError(CODES.CONFLICT);
    const evidenceBytes = Buffer.from(params[8]);
    const signingBytes = Buffer.from(params[6]);
    const signature = Buffer.from(params[7]);
    const evidenceDigest = Buffer.from(params[9]);
    const expectedEvidence = evidenceFor(this.row);
    const expectedSigningBytes = promotionEvidenceV3SigningData(expectedEvidence.statement, {
      allowExpired: true, allowFuture: true, maxTtlMs: PROMOTION_EVIDENCE_V3_MAX_TTL_MS
    });
    const expectedCanonicalEvidence = canonicalizePromotionEvidenceV3(expectedEvidence, {
      allowExpired: true, allowFuture: true
    });
    assert.deepEqual(signingBytes, expectedSigningBytes);
    assert.deepEqual(evidenceBytes, Buffer.from(expectedCanonicalEvidence, "utf8"));
    assert.deepEqual(signature, Buffer.from(expectedEvidence.signature, "base64url"));
    assert.deepEqual(evidenceDigest, Buffer.from(digest(expectedCanonicalEvidence), "hex"));
    this.commitParams = {
      claim_token_digest: Buffer.from(params[5]),
      signing_bytes: signingBytes,
      signature,
      evidence_bytes: evidenceBytes,
      evidence_digest: evidenceDigest
    };
    if (!this.lifecycleAvailable) throw repositoryError(CODES.LIFECYCLE);
    if (Buffer.from(params[5]).toString("hex") !== this.row.claim_token_digest) throw repositoryError(CODES.CLAIM);
    if (this.row.state === "committed") return result([{ result: authorityResult(this.row) }]);
    if (this.row.state === "uncertain") return result([{ result: { state: "uncertain" } }]);
    if (this.row.state !== "reserved" || !this.claimActive() || Date.parse(this.row.approval_expires_at) <= Date.parse(this.dbNow)) {
      throw repositoryError(CODES.CLAIM);
    }
    this.row.state = "committed";
    this.row.claim_token_digest = null;
    this.row.claim_expires_at = null;
    this.row.evidence_bytes = evidenceBytes;
    this.row.evidence_digest = evidenceDigest.toString("hex");
    this.row.deployment_generation = this.head.current_generation + 1;
    this.row.uncertain_reason = null;
    this.head.current_generation = this.row.deployment_generation;
    this.head.current_candidate_id = this.row.candidate_id;
    if (this.commitResponseLost) throw new Error("response lost; provider_diagnostics=private");
    return result([{ result: authorityResult(this.row) }]);
  }

  uncertain(params) {
    assert.equal(params.length, 7);
    if (!this.row || !sameIdentity(this.row, params)) throw repositoryError(CODES.CONFLICT);
    if (this.row.state === "committed") return result([{ result: authorityResult(this.row) }]);
    if (this.row.state === "uncertain") return result([{ result: { state: "uncertain" } }]);
    if (Buffer.from(params[5]).toString("hex") !== this.row.claim_token_digest) throw repositoryError(CODES.CLAIM);
    this.row.state = "uncertain";
    this.row.claim_token_digest = null;
    this.row.claim_expires_at = null;
    this.row.uncertain_reason = params[6];
    return result([{ result: { state: "uncertain" } }]);
  }

  claimActive() {
    return this.row?.claim_expires_at !== null && Date.parse(String(this.row.claim_expires_at)) > Date.parse(this.dbNow);
  }

  expireReservation() {
    this.row.state = "uncertain";
    this.row.claim_token_digest = null;
    this.row.claim_expires_at = null;
    this.row.uncertain_reason = "stale_lifecycle";
  }
}

function repository(options = {}) {
  const client = new FakePg(options);
  let sequence = 0;
  const verifyEvidence = options.verifyEvidence ?? ((evidence, context) => Boolean(
    evidence && context && context.platform_approval_id && context.platform_approval_digest
      && context.signer_key_fingerprint === SIGNER_KEY_FINGERPRINT
  ));
  const repo = createPostgresPlatformPromotionIssuanceRepository({ client, claimLeaseMs: 30_000,
    randomBytes: () => Buffer.alloc(32, 0x31 + sequence++),
    verifyEvidence,
    evidenceTtlMs: options.evidenceTtlMs
  });
  return { client, repo };
}

test("reserves only database-derived approval/candidate authority and hides private approval arrays", async () => {
  const { client, repo } = repository();
  const reserved = await repo.reservePlatformPromotion(IDENTITY);
  assert.equal(reserved.state, "reserved");
  assert.match(reserved.claim_token, /^[A-Za-z0-9_-]{43}$/u);
  assert.equal(Object.hasOwn(reserved, "platform_principal_ids"), false);
  assert.equal(Object.hasOwn(reserved, "authorization_evidence_digests"), false);
  assert.notEqual(client.row.claim_token_digest, reserved.claim_token);
  assertAuthorityFunctionBoundary(client);
});

test("derives the durable provider operation from the exact reserved v3 statement", async () => {
  const { repo, client } = repository();
  const reserved = await repo.reservePlatformPromotion(IDENTITY);
  assert.equal(client.row.provider_operation_id, providerOperationId(evidenceFor(reserved).statement));
  assert.equal(Object.hasOwn(reserved, "provider_operation_id"), false);
  assert.equal(client.calls.some(({ params }) => params.includes("caller-selected-provider-operation")), false);
});

test("requires an independent verifier and rejects forged evidence before state mutation", async () => {
  assert.throws(() => createPostgresPlatformPromotionIssuanceRepository({ client: new FakePg() }), { code: CODES.CONFIG });
  const { repo, client } = repository({ verifyEvidence: async () => false });
  const reserved = await repo.reservePlatformPromotion(IDENTITY);
  await assert.rejects(
    repo.commitPlatformPromotion({ ...IDENTITY, claim_token: reserved.claim_token, promotion_evidence: evidenceFor(reserved) }),
    { code: CODES.EVIDENCE }
  );
  assert.equal(client.row.state, "reserved");
  assert.equal(client.row.evidence_bytes, null);
});

test("durably stores every service uncertainty reason and rejects unknown reasons", async () => {
  for (const reason of ["signer_failure", "signer_output", "verification_failure", "commit_failure", "stale_lifecycle"]) {
    const { repo, client } = repository();
    const reserved = await repo.reservePlatformPromotion(IDENTITY);
    assert.deepEqual(await repo.markPlatformPromotionUncertain({ ...IDENTITY, claim_token: reserved.claim_token, reason }), { state: "uncertain" });
    assert.equal(client.row.state, "uncertain");
    assert.equal(client.row.uncertain_reason, reason);
    assert.equal(client.row.claim_token_digest, null);
  }
  const { repo, client } = repository();
  const reserved = await repo.reservePlatformPromotion(IDENTITY);
  await assert.rejects(
    repo.markPlatformPromotionUncertain({ ...IDENTITY, claim_token: reserved.claim_token, reason: "provider_response_lost" }),
    { code: CODES.INPUT }
  );
  assert.equal(client.row.state, "reserved");
});

test("commits exact v3 evidence with a monotonic generation and replays without a second reservation", async () => {
  const { repo, client } = repository();
  const reserved = await repo.reservePlatformPromotion(IDENTITY);
  const committed = await repo.commitPlatformPromotion({ ...IDENTITY, claim_token: reserved.claim_token, promotion_evidence: evidenceFor(reserved) });
  assert.equal(committed.state, "committed");
  assert.equal(Object.hasOwn(committed, "deployment_generation"), false);
  assert.equal(committed.promotion_evidence.statement.version, 3);
  assert.equal(Object.hasOwn(committed, "provider_operation_id"), false);
  assert.equal(Object.hasOwn(committed, "request_digest"), false);
  assert.equal(Object.hasOwn(committed, "created_at"), false);
  assert.deepEqual(client.commitParams.claim_token_digest, Buffer.from(digest(reserved.claim_token), "hex"));
  assert.deepEqual(client.commitParams.signing_bytes, promotionEvidenceV3SigningData(committed.promotion_evidence.statement, {
    allowExpired: true, allowFuture: true, maxTtlMs: PROMOTION_EVIDENCE_V3_MAX_TTL_MS
  }));
  assert.deepEqual(client.commitParams.evidence_bytes, Buffer.from(canonicalizePromotionEvidenceV3(committed.promotion_evidence, {
    allowExpired: true, allowFuture: true
  }), "utf8"));
  assert.deepEqual(client.commitParams.signature, Buffer.from(committed.promotion_evidence.signature, "base64url"));
  assert.deepEqual(client.commitParams.evidence_digest, Buffer.from(digest(canonicalizePromotionEvidenceV3(committed.promotion_evidence, {
    allowExpired: true, allowFuture: true
  })), "hex"));
  assertAuthorityFunctionBoundary(client);
  assert.deepEqual(await repo.replayPlatformPromotion(IDENTITY), committed);
  assert.deepEqual(await repo.getCommittedPlatformPromotion(IDENTITY), committed);
  assert.equal(client.head.current_candidate_id, IDENTITY.candidate_id);
});

test("requires independent verification for every committed result path", async () => {
  let accepted = true;
  const verificationContexts = [];
  const { repo } = repository({
    verifyEvidence: async (_evidence, context) => {
      verificationContexts.push(context);
      return accepted;
    }
  });
  const reserved = await repo.reservePlatformPromotion(IDENTITY);
  const evidence = evidenceFor(reserved);
  await repo.commitPlatformPromotion({ ...IDENTITY, claim_token: reserved.claim_token, promotion_evidence: evidence });
  assert.deepEqual(verificationContexts.map(({ allowExpired }) => allowExpired), [false, true]);

  assert.equal((await repo.replayPlatformPromotion(IDENTITY)).state, "committed");
  assert.equal((await repo.getCommittedPlatformPromotion(IDENTITY)).promotion_evidence.signature, evidence.signature);
  assert.equal((await repo.reservePlatformPromotion(IDENTITY)).promotion_evidence.signature, evidence.signature);
  assert.deepEqual(verificationContexts.map(({ allowExpired }) => allowExpired), [false, true, true, true, true]);

  accepted = false;
  await assert.rejects(repo.replayPlatformPromotion(IDENTITY), { code: CODES.EVIDENCE });
  await assert.rejects(repo.getCommittedPlatformPromotion(IDENTITY), { code: CODES.EVIDENCE });
  await assert.rejects(repo.reservePlatformPromotion(IDENTITY), { code: CODES.EVIDENCE });
});

test("fences stale claims, rejects substitution, and makes uncertainty terminal", async () => {
  const { repo } = repository();
  const reserved = await repo.reservePlatformPromotion(IDENTITY);
  await assert.rejects(repo.commitPlatformPromotion({ ...IDENTITY, claim_token: "A".repeat(43), promotion_evidence: evidenceFor(reserved) }), { code: CODES.CLAIM });
  await assert.rejects(repo.reservePlatformPromotion({ ...IDENTITY, candidate_id: `release-pkg-sha256-v1-${"b".repeat(64)}` }), { code: CODES.CONFLICT });
  assert.deepEqual(await repo.markPlatformPromotionUncertain({ ...IDENTITY, claim_token: reserved.claim_token, reason: "commit_failure" }), { state: "uncertain" });
  assert.deepEqual(await repo.replayPlatformPromotion(IDENTITY), { state: "uncertain" });
});

test("does not reclaim an expired lease or blindly re-sign an ambiguous reservation", async () => {
  const { repo, client } = repository();
  const first = await repo.reservePlatformPromotion(IDENTITY);
  client.row.created_at = "2026-08-14T00:00:00.000Z";
  client.row.claim_expires_at = "2026-08-14T23:59:59.000Z";
  const replayed = await repo.replayPlatformPromotion(IDENTITY);
  assert.deepEqual(replayed, { state: "uncertain" });
  assert.equal(client.row.state, "uncertain");
  assert.equal(client.row.uncertain_reason, "stale_lifecycle");
  const blocked = await repo.reservePlatformPromotion(IDENTITY);
  assert.deepEqual(blocked, { state: "uncertain" });
  assert.equal(client.row.claim_token_digest, null);
  assert.equal(client.row.state, "uncertain");
  assert.equal(client.row.approval_digest, AUTHORITY.approval_digest);
  assert.equal(client.row.source_commit, AUTHORITY.source_commit);
  assert.equal(client.head.current_generation, 0);
});

test("late uncertainty terminalizes an expired provider claim without an expiry race", async () => {
  const { repo, client } = repository();
  const reserved = await repo.reservePlatformPromotion(IDENTITY);
  client.row.created_at = "2026-08-14T00:00:00.000Z";
  client.row.claim_expires_at = "2026-08-14T23:59:59.000Z";
  assert.deepEqual(await repo.markPlatformPromotionUncertain({
    ...IDENTITY, claim_token: reserved.claim_token, reason: "commit_failure"
  }), { state: "uncertain" });
  assert.equal(client.row.state, "uncertain");
  assert.equal(client.row.claim_token_digest, null);
  assert.equal(client.row.uncertain_reason, "commit_failure");
});

test("does not commit when the pinned promotion lifecycle is disabled", async () => {
  const { repo, client } = repository();
  const reserved = await repo.reservePlatformPromotion(IDENTITY);
  client.lifecycleAvailable = false;
  await assert.rejects(repo.commitPlatformPromotion({ ...IDENTITY, claim_token: reserved.claim_token, promotion_evidence: evidenceFor(reserved) }), { code: CODES.LIFECYCLE });
});

test("a lost commit response is recovered by exact replay", async () => {
  const { repo, client } = repository({ commitResponseLost: true });
  const reserved = await repo.reservePlatformPromotion(IDENTITY);
  await assert.rejects(repo.commitPlatformPromotion({ ...IDENTITY, claim_token: reserved.claim_token, promotion_evidence: evidenceFor(reserved) }), { code: CODES.DATABASE });
  assert.equal((await repo.replayPlatformPromotion(IDENTITY)).state, "committed");
});
