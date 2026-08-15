import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import {
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
  return {
    ...IDENTITY, state: "reserved", ...authority,
    purpose: PROMOTION_EVIDENCE_V3_PURPOSE, protocol_version: 3, signing_version: 3,
    provider_operation_id: values?.provider_operation_id ?? "managed-signer-v1-" + "0".repeat(64),
    request_digest: Buffer.alloc(32, 1), claim_token_digest: values?.claim_token_digest ?? digest("unused"),
    claim_expires_at: "2026-08-15T00:00:30.000Z", evidence_digest: null, evidence_bytes: null,
    deployment_generation: null, uncertain_reason: null,
    issued_at: values?.issued_at ?? "2026-08-15T00:00:00.000Z", expires_at: values?.expires_at ?? "2026-08-15T01:00:00.000Z",
    created_at: "2026-08-15T00:00:00.000Z", updated_at: "2026-08-15T00:00:00.000Z"
  };
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
    platform_approval_id: reservation.platform_approval_id, platform_approval_digest: reservation.platform_approval_digest,
    approval_state: "approved", purpose: PROMOTION_EVIDENCE_V3_PURPOSE, protocol_version: 3, signing_version: 3,
    lifecycle_version: reservation.lifecycle_version, key_id: reservation.key_id, key_version: reservation.key_version,
    issued_at: reservation.issued_at, expires_at: reservation.expires_at
  };
  return { version: PROMOTION_EVIDENCE_V3_VERSION, type: PROMOTION_EVIDENCE_V3_TYPE, statement,
    statement_hash: promotionEvidenceV3StatementHash(statement), signature_algorithm: PROMOTION_EVIDENCE_V3_ALGORITHM,
    signer_key_fingerprint: reservation.signer_key_fingerprint, signature: Buffer.alloc(64, 7).toString("base64url") };
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
  }
  async query(text, params = []) {
    this.calls.push({ text: String(text), params: [...params] });
    if (["BEGIN", "COMMIT", "ROLLBACK"].includes(text)) return result([]);
    if (/pg_advisory_xact_lock/u.test(text)) return result([{ locked: null }]);
    if (/SELECT clock_timestamp\(\) AS now/u.test(text)) return result([{ now: this.dbNow }]);
    if (/FROM platform_promotion_issuances/u.test(text)) {
      if (/claim_expires_at>clock_timestamp/u.test(text)) return result(this.row ? [{ claim_active: this.row.claim_expires_at > "2026-08-15T00:00:00.000Z" }] : []);
      if (this.row && (params[0] === this.row.promotion_id || (params[1] === this.row.deployment_id && params[2] === this.row.environment && params[3] === this.row.candidate_id && params[4] === this.row.idempotency_key))
        && (!/state='committed'/u.test(text) || this.row.state === "committed")) return result([{ ...this.row }]);
      return result([]);
    }
    if (/INSERT INTO platform_promotion_deployments/u.test(text)) return result([]);
    if (/FROM platform_promotion_deployments/u.test(text)) return result([{ ...this.head }]);
    if (/FROM platform_promotion_approvals approval/u.test(text)) return result([{ ...this.authority, candidate_id: IDENTITY.candidate_id }]);
    if (/FROM managed_signer_key_lifecycles lifecycle/u.test(text)) return this.lifecycleAvailable
      ? result([{ lifecycle_version: 3, key_id: this.authority.key_id, key_version: this.authority.key_version, state: "active" }]) : result([]);
    if (/INSERT INTO platform_promotion_issuances/u.test(text)) {
      this.row = storedRow({
        claim_token_digest: Buffer.from(params[24]).toString("hex"),
        provider_operation_id: params[22],
        authority: this.authority,
        issued_at: params[16],
        expires_at: params[17],
        signer_key_fingerprint: `SHA256:${Buffer.from(params[21]).toString("base64url")}`
      });
      return { rowCount: 1, rows: [] };
    }
    if (/SET claim_token_digest=\$2/u.test(text)) {
      this.row.claim_token_digest = Buffer.from(params[1]).toString("hex");
      this.row.claim_expires_at = "2026-08-15T00:00:30.000Z";
      return result([{ ...this.row }]);
    }
    if (/SET state='committed'/u.test(text)) {
      this.row.state = "committed"; this.row.claim_token_digest = null; this.row.claim_expires_at = null;
      this.row.evidence_bytes = params[2]; this.row.evidence_digest = Buffer.from(params[3]).toString("hex"); this.row.deployment_generation = params[4];
      if (this.commitResponseLost) throw new Error("response lost; provider_diagnostics=private");
      return result([{ ...this.row }]);
    }
    if (/SET current_generation=/u.test(text)) {
      this.head.current_generation = params[2]; this.head.current_candidate_id = params[3]; return result([{ ...this.head }]);
    }
    if (/SET state='uncertain'/u.test(text)) {
      this.row.state = "uncertain"; this.row.claim_token_digest = null; this.row.claim_expires_at = null;
      this.row.uncertain_reason = params.length === 2 ? "stale_lifecycle" : params[1];
      return result([{ ...this.row }]);
    }
    throw new Error(`unexpected SQL: ${String(text).slice(0, 120)}`);
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
  assert.match(client.calls.find(({ text }) => /FROM platform_promotion_approvals/u.test(text)).text, /candidate\.artifact_sha256=approval\.product_pkg_sha256/u);
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
  assert.deepEqual(await repo.replayPlatformPromotion(IDENTITY), committed);
  assert.deepEqual(await repo.getCommittedPlatformPromotion(IDENTITY), committed);
  assert.equal(client.head.current_candidate_id, IDENTITY.candidate_id);
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
