import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import {
  PROMOTION_EVIDENCE_V3_ALGORITHM,
  PROMOTION_EVIDENCE_V3_PURPOSE,
  PROMOTION_EVIDENCE_V3_TYPE,
  PROMOTION_EVIDENCE_V3_VERSION,
  promotionEvidenceV3StatementHash
} from "../../src/promotion-evidence-v3-statement.mjs";
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
const AUTHORITY = Object.freeze({
  approval_id: "22222222-2222-4222-8222-222222222222",
  approval_digest: "b".repeat(64),
  source_commit: "1".repeat(40), source_tree: "2".repeat(40),
  product_pkg_sha256: "a".repeat(64), image_digest: `sha256:${"c".repeat(64)}`,
  sbom_sha256: "d".repeat(64), qualification_report_digests: ["e".repeat(64)],
  release_manifest_schema_version: 4, release_manifest_sha256: "f".repeat(64),
  approval_expires_at: "2026-08-15T01:00:00.000Z", lifecycle_version: 3,
  key_id: "promotion-evidence-2026-08", key_version: 7
});

function digest(value) { return crypto.createHash("sha256").update(value, "utf8").digest("hex"); }
function result(rows) { return { rows, rowCount: rows.length }; }
function storedRow(values) {
  return {
    ...IDENTITY, state: "reserved", ...AUTHORITY,
    purpose: PROMOTION_EVIDENCE_V3_PURPOSE, protocol_version: 3, signing_version: 3,
    provider_operation_id: `platform-promotion-v3-${IDENTITY.promotion_id}`,
    request_digest: Buffer.alloc(32, 1), claim_token_digest: values?.claim_token_digest ?? digest("unused"),
    claim_expires_at: "2026-08-15T00:00:30.000Z", evidence_digest: null, evidence_bytes: null,
    deployment_generation: null, uncertain_reason: null,
    created_at: "2026-08-15T00:00:00.000Z", updated_at: "2026-08-15T00:00:00.000Z"
  };
}

function evidence() {
  const statement = {
    version: 3, type: PROMOTION_EVIDENCE_V3_TYPE, promotion_id: IDENTITY.promotion_id,
    deployment_id: IDENTITY.deployment_id, environment: IDENTITY.environment, candidate_id: IDENTITY.candidate_id,
    source_commit: AUTHORITY.source_commit, source_tree: AUTHORITY.source_tree, product_pkg_sha256: AUTHORITY.product_pkg_sha256,
    image_digest: AUTHORITY.image_digest, sbom_sha256: AUTHORITY.sbom_sha256,
    qualification_report_digests: AUTHORITY.qualification_report_digests,
    release_manifest_schema_version: 4, release_manifest_sha256: AUTHORITY.release_manifest_sha256,
    platform_approval_id: AUTHORITY.approval_id, platform_approval_digest: AUTHORITY.approval_digest,
    approval_state: "approved", purpose: PROMOTION_EVIDENCE_V3_PURPOSE, protocol_version: 3, signing_version: 3,
    lifecycle_version: 3, key_id: AUTHORITY.key_id, key_version: 7,
    issued_at: "2026-08-15T00:00:01.000Z", expires_at: "2026-08-15T00:30:00.000Z"
  };
  return { version: PROMOTION_EVIDENCE_V3_VERSION, type: PROMOTION_EVIDENCE_V3_TYPE, statement,
    statement_hash: promotionEvidenceV3StatementHash(statement), signature_algorithm: PROMOTION_EVIDENCE_V3_ALGORITHM,
    signer_key_fingerprint: `SHA256:${"g".repeat(43)}`, signature: Buffer.alloc(64, 7).toString("base64url") };
}

class FakePg {
  constructor({ lifecycleAvailable = true, commitResponseLost = false } = {}) {
    this.calls = [];
    this.row = undefined;
    this.lifecycleAvailable = lifecycleAvailable;
    this.commitResponseLost = commitResponseLost;
    this.head = { deployment_id: IDENTITY.deployment_id, environment: IDENTITY.environment, current_generation: 0, current_candidate_id: null };
  }
  async query(text, params = []) {
    this.calls.push({ text: String(text), params: [...params] });
    if (["BEGIN", "COMMIT", "ROLLBACK"].includes(text)) return result([]);
    if (/pg_advisory_xact_lock/u.test(text)) return result([{ locked: null }]);
    if (/FROM platform_promotion_issuances/u.test(text)) {
      if (/claim_expires_at>clock_timestamp/u.test(text)) return result(this.row ? [{ claim_active: this.row.claim_expires_at > "2026-08-15T00:00:00.000Z" }] : []);
      if (this.row && (params[0] === this.row.promotion_id || (params[1] === this.row.deployment_id && params[2] === this.row.environment && params[3] === this.row.candidate_id && params[4] === this.row.idempotency_key))
        && (!/state='committed'/u.test(text) || this.row.state === "committed")) return result([{ ...this.row }]);
      return result([]);
    }
    if (/INSERT INTO platform_promotion_deployments/u.test(text)) return result([]);
    if (/FROM platform_promotion_deployments/u.test(text)) return result([{ ...this.head }]);
    if (/FROM platform_promotion_approvals approval/u.test(text)) return result([{ ...AUTHORITY, candidate_id: IDENTITY.candidate_id }]);
    if (/FROM managed_signer_key_lifecycles lifecycle/u.test(text)) return this.lifecycleAvailable
      ? result([{ lifecycle_version: 3, key_id: AUTHORITY.key_id, key_version: 7, state: "active" }]) : result([]);
    if (/INSERT INTO platform_promotion_issuances/u.test(text)) {
      this.row = storedRow({ claim_token_digest: Buffer.from(params[21]).toString("hex") });
      this.row.claim_expires_at = "2026-08-15T00:00:30.000Z";
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
      this.row.state = "uncertain"; this.row.claim_token_digest = null; this.row.claim_expires_at = null; this.row.uncertain_reason = params[1];
      return result([{ ...this.row }]);
    }
    throw new Error(`unexpected SQL: ${String(text).slice(0, 120)}`);
  }
}

function repository(options = {}) {
  const client = new FakePg(options);
  let sequence = 0;
  const repo = createPostgresPlatformPromotionIssuanceRepository({ client, claimLeaseMs: 30_000,
    randomBytes: () => Buffer.alloc(32, 0x31 + sequence++) });
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

test("commits exact v3 evidence with a monotonic generation and replays without a second reservation", async () => {
  const { repo, client } = repository();
  const reserved = await repo.reservePlatformPromotion(IDENTITY);
  const committed = await repo.commitPlatformPromotion({ ...IDENTITY, claim_token: reserved.claim_token, evidence: evidence() });
  assert.equal(committed.state, "committed");
  assert.equal(committed.deployment_generation, 1);
  assert.equal(committed.evidence.statement.version, 3);
  assert.deepEqual(await repo.replayPlatformPromotion(IDENTITY), committed);
  assert.deepEqual(await repo.getCommittedPlatformPromotion(IDENTITY), committed);
  assert.equal(client.head.current_candidate_id, IDENTITY.candidate_id);
});

test("fences stale claims, rejects substitution, and makes uncertainty terminal", async () => {
  const { repo } = repository();
  const reserved = await repo.reservePlatformPromotion(IDENTITY);
  await assert.rejects(repo.commitPlatformPromotion({ ...IDENTITY, claim_token: "A".repeat(43), evidence: evidence() }), { code: CODES.CLAIM });
  await assert.rejects(repo.reservePlatformPromotion({ ...IDENTITY, candidate_id: `release-pkg-sha256-v1-${"b".repeat(64)}` }), { code: CODES.CONFLICT });
  assert.deepEqual(await repo.markPlatformPromotionUncertain({ ...IDENTITY, claim_token: reserved.claim_token, reason: "provider_response_lost" }), { state: "uncertain" });
  assert.deepEqual(await repo.replayPlatformPromotion(IDENTITY), { state: "uncertain" });
});

test("reclaims an expired database lease without changing immutable authority", async () => {
  const { repo, client } = repository();
  const first = await repo.reservePlatformPromotion(IDENTITY);
  client.row.claim_expires_at = "2026-08-14T23:59:59.000Z";
  const reclaimed = await repo.reservePlatformPromotion(IDENTITY);
  assert.equal(reclaimed.state, "reserved");
  assert.notEqual(reclaimed.claim_token, first.claim_token);
  assert.equal(client.row.approval_digest, AUTHORITY.approval_digest);
  assert.equal(client.row.source_commit, AUTHORITY.source_commit);
});

test("does not commit when the pinned promotion lifecycle is disabled", async () => {
  const { repo, client } = repository();
  const reserved = await repo.reservePlatformPromotion(IDENTITY);
  client.lifecycleAvailable = false;
  await assert.rejects(repo.commitPlatformPromotion({ ...IDENTITY, claim_token: reserved.claim_token, evidence: evidence() }), { code: CODES.LIFECYCLE });
});

test("a lost commit response is recovered by exact replay", async () => {
  const { repo, client } = repository({ commitResponseLost: true });
  const reserved = await repo.reservePlatformPromotion(IDENTITY);
  await assert.rejects(repo.commitPlatformPromotion({ ...IDENTITY, claim_token: reserved.claim_token, evidence: evidence() }), { code: CODES.DATABASE });
  assert.equal((await repo.replayPlatformPromotion(IDENTITY)).state, "committed");
});
