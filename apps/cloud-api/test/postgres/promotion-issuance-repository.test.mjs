import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import {
  PromotionIssuanceRepositoryError,
  createPostgresPromotionIssuanceRepository,
  normalizePromotionAuthority,
  promotionAuthorityDigest
} from "../../src/postgres/promotion-issuance-repository.mjs";
import { PROMOTION_EVIDENCE_V3_PURPOSE, promotionEvidenceV3SigningData } from "../../src/promotion-evidence-v3-statement.mjs";

const base = Object.freeze({
  deployment_id: "agentpass-prod",
  environment: "production",
  promotion_id: "11111111-1111-4111-8111-111111111111",
  idempotency_key: "promotion-test-0001",
  candidate_id: `release-pkg-sha256-v1-${"a".repeat(64)}`,
  source_commit: "b".repeat(40),
  source_tree: "c".repeat(40),
  product_pkg_sha256: "d".repeat(64),
  release_manifest_sha256: "e".repeat(64),
  sbom_sha256: "f".repeat(64),
  image_digest: `sha256:${"1".repeat(64)}`,
  qualification_report_digests: ["2".repeat(64), "3".repeat(64)],
  approval_id: "22222222-2222-4222-8222-222222222222",
  approval_digest: "4".repeat(64),
  signer_key_id: "kms/promotion-v1",
  signer_key_version: 1,
  signer_lifecycle_version: 7,
  expected_deployment_generation: 0,
  provider_operation_id: "promotion-provider-operation-test"
});

test("normalizes the closed authority and derives a stable digest", () => {
  const normalized = normalizePromotionAuthority(base);
  assert.deepEqual(normalized.qualification_report_digests, base.qualification_report_digests);
  assert.match(normalized.authority_digest, /^[0-9a-f]{64}$/u);
  assert.equal(normalized.authority_digest, promotionAuthorityDigest(base));
  assert.notEqual(promotionAuthorityDigest({ ...base, product_pkg_sha256: "9".repeat(64) }), normalized.authority_digest);
  assert.throws(() => normalizePromotionAuthority({ ...base, qualification_report_digests: [base.qualification_report_digests[0], base.qualification_report_digests[0]] }), PromotionIssuanceRepositoryError);
  assert.throws(() => normalizePromotionAuthority({ ...base, image_digest: "sha256:bad" }), PromotionIssuanceRepositoryError);
});

test("repository rejects invalid configuration before any database call", () => {
  assert.throws(() => createPostgresPromotionIssuanceRepository(), { code: "ERR_PROMOTION_ISSUANCE_CONFIG" });
  assert.throws(() => createPostgresPromotionIssuanceRepository({ client: { query() {} }, claimLeaseMs: 999 }), { code: "ERR_PROMOTION_ISSUANCE_CONFIG" });
});

test("reserve uses a transaction, lane lock, and never returns a clear claim digest", async () => {
  let insertParams;
  let issuanceReads = 0;
  const client = {
    async query(text, params = []) {
      if (text === "BEGIN" || text === "COMMIT" || text === "ROLLBACK") return { rowCount: 0, rows: [] };
      if (text.includes("pg_advisory_xact_lock")) return { rowCount: 1, rows: [] };
      if (text.includes("SELECT generation,state FROM platform_deployment_state")) return { rowCount: 0, rows: [] };
      if (text.includes("FROM platform_promotion_approvals")) return { rowCount: 1, rows: [{
        ...base,
        approval_id: base.approval_id,
        record_digest: base.approval_digest,
        decision: "approved",
        quorum_satisfied: true,
        expires_at: new Date(Date.now() + 60_000).toISOString()
      }] };
      if (text.startsWith("INSERT INTO platform_promotion_issuances")) { insertParams = params; return { rowCount: 1, rows: [] }; }
      if (text.startsWith("SELECT deployment_id,environment,promotion_id")) {
        issuanceReads += 1;
        if (issuanceReads === 1) return { rowCount: 0, rows: [] };
        return { rowCount: 1, rows: [{
          ...base,
          state: "reserved",
          claim_token_digest: insertParams?.[18]?.toString("hex") ?? null,
          claim_expires_at: new Date(Date.now() + 60_000).toISOString(),
          provider_operation_id: insertParams?.[20] ?? null,
          evidence: null,
          rejection_reason: null,
          authority_digest: promotionAuthorityDigest(base),
          created_at: new Date().toISOString(),
          updated_at: new Date().toISOString()
        }] };
      }
      throw new Error(`unexpected query: ${text}`);
    }
  };
  const outcome = await createPostgresPromotionIssuanceRepository({ client }).reservePromotion(base);
  assert.equal(outcome.state, "reserved");
  assert.match(outcome.claim_token, /^[A-Za-z0-9_-]{43}$/u);
  assert.equal(Object.hasOwn(outcome, "claim_token_digest"), false);
  assert.equal(outcome.provider_operation_id, base.provider_operation_id);
  assert.equal(issuanceReads, 2);
});

test("promotion mutation audit callback runs on the mutation transaction client", async () => {
  const client = new PromotionStateClient();
  let callback;
  const repository = createPostgresPromotionIssuanceRepository({ client });
  const result = await repository.reservePromotion({
    ...base,
    onMutation: async ({ tx, result: mutation }) => { callback = { tx, mutation }; }
  });
  assert.equal(callback.tx, client);
  assert.equal(callback.mutation.state, "reserved");
  assert.deepEqual(result, callback.mutation);
  assert.equal(client.snapshots.length, 0);
  assert.equal(client.calls.findIndex(({ text }) => text === "BEGIN") < client.calls.findIndex(({ text }) => text === "COMMIT"), true);
});

test("audit callback failure rolls back the issuance instead of leaving a mutation-only row", async () => {
  const client = new PromotionStateClient();
  const repository = createPostgresPromotionIssuanceRepository({ client });
  await assert.rejects(
    repository.reservePromotion({ ...base, onMutation: async () => { throw new Error("audit unavailable"); } }),
    { code: "ERR_PROMOTION_ISSUANCE_DATABASE" }
  );
  assert.equal(client.issuance, null);
  assert.equal(client.calls.some(({ text }) => text === "ROLLBACK"), true);
});

class PromotionStateClient {
  constructor() {
    this.calls = [];
    this.issuance = null;
    this.deployment = null;
    this.snapshots = [];
  }

  async query(text, params = []) {
    this.calls.push({ text, params });
    if (text === "BEGIN") {
      this.snapshots.push({ issuance: this.issuance, deployment: this.deployment });
      return { rowCount: 0, rows: [] };
    }
    if (text === "COMMIT") {
      this.snapshots.pop();
      return { rowCount: 0, rows: [] };
    }
    if (text === "ROLLBACK") {
      const snapshot = this.snapshots.pop();
      if (snapshot) {
        this.issuance = snapshot.issuance;
        this.deployment = snapshot.deployment;
      }
      return { rowCount: 0, rows: [] };
    }
    if (text.includes("pg_advisory_xact_lock")) return { rowCount: 1, rows: [] };
    if (text.startsWith("SELECT deployment_id,environment,promotion_id")) return { rowCount: this.issuance ? 1 : 0, rows: this.issuance ? [this.issuance] : [] };
    if (text.includes("SELECT generation,state FROM platform_deployment_state")) return { rowCount: this.deployment ? 1 : 0, rows: this.deployment ? [this.deployment] : [] };
    if (text.includes("FROM platform_promotion_approvals")) return { rowCount: 1, rows: [{
      ...base,
      record_digest: base.approval_digest,
      decision: "approved",
      quorum_satisfied: true,
      expires_at: new Date(Date.now() + 60_000).toISOString()
    }] };
    if (text.startsWith("INSERT INTO platform_promotion_issuances")) {
      const now = new Date().toISOString();
      this.issuance = {
        ...base,
        state: "reserved",
        claim_token_digest: params[18].toString("hex"),
        claim_expires_at: new Date(Date.now() + params[19]).toISOString(),
        provider_operation_id: params[20],
        evidence: null,
        rejection_reason: null,
        authority_digest: params[21].toString("hex"),
        created_at: now,
        updated_at: now
      };
      return { rowCount: 1, rows: [] };
    }
    if (text.startsWith("SELECT purpose,operation_id,algorithm")) {
      const bytes = promotionEvidenceV3SigningData(SEAM_EVIDENCE.statement, { allowExpired: true, allowFuture: true });
      return { rowCount: 1, rows: [{ purpose: PROMOTION_EVIDENCE_V3_PURPOSE, operation_id: base.provider_operation_id, algorithm: "ed25519", bytes_length: bytes.length, request_digest: crypto.createHash("sha256").update(bytes).digest("hex"), key_id: base.signer_key_id, key_version: String(base.signer_key_version), state: this.providerState ?? "committed", signature: Buffer.from(SEAM_EVIDENCE.signature, "base64url"), public_key_der: Buffer.alloc(44), provider_receipt_provider: "fixture-provider", provider_receipt_id: "fixture-receipt" }] };
    }
    if (text.startsWith("UPDATE platform_promotion_issuances SET state='committed'")) {
      if (this.failCommitUpdate) throw new Error("simulated database write failure");
      if (this.failDeployment) return { rowCount: 1, rows: [] };
      const evidenceIndex = text.includes("evidence=$5") ? 4 : 6;
      this.issuance = { ...this.issuance, state: "committed", claim_token_digest: null, claim_expires_at: null, evidence: JSON.parse(params[evidenceIndex]), provider_operation_id: params[5] ?? null };
      return { rowCount: 1, rows: [] };
    }
    if (text.startsWith("UPDATE platform_promotion_issuances SET state='uncertain'")) {
      this.issuance = { ...this.issuance, state: "uncertain", claim_token_digest: null, claim_expires_at: null, uncertain_reason: text.includes("uncertain_reason='commit_failure'") ? "commit_failure" : params[7] ?? null, provider_operation_id: params[7] ?? this.issuance.provider_operation_id };
      return { rowCount: 1, rows: [] };
    }
    if (text.startsWith("UPDATE platform_promotion_issuances SET state=$6")) {
      this.issuance = { ...this.issuance, state: params[5], claim_token_digest: null, claim_expires_at: null, rejection_reason: params[6] ?? null, provider_operation_id: this.issuance.provider_operation_id ?? params[7] ?? null };
      return { rowCount: 1, rows: [] };
    }
    if (text.startsWith("INSERT INTO platform_deployment_state")) {
      if (this.failDeployment) throw new Error("simulated deployment database failure");
      this.deployment = { generation: params[2], state: "promoted" };
      return { rowCount: 1, rows: [] };
    }
    throw new Error(`unexpected query: ${text}`);
  }
}

const SEAM_EVIDENCE = Object.freeze({
  signature: "A".repeat(86),
  statement: Object.freeze({
    version: 3,
    type: "agentpass.promotion-evidence",
    promotion_id: base.promotion_id,
    deployment_id: base.deployment_id,
    environment: base.environment,
    candidate_id: `release-pkg-sha256-v1-${base.product_pkg_sha256}`,
    source_commit: base.source_commit,
    source_tree: base.source_tree,
    product_pkg_sha256: base.product_pkg_sha256,
    image_digest: base.image_digest,
    sbom_sha256: base.sbom_sha256,
    qualification_report_digests: base.qualification_report_digests,
    release_manifest_schema_version: 4,
    release_manifest_sha256: base.release_manifest_sha256,
    platform_approval_id: base.approval_id,
    platform_approval_digest: base.approval_digest,
    approval_state: "approved",
    purpose: PROMOTION_EVIDENCE_V3_PURPOSE,
    protocol_version: 3,
    signing_version: 3,
    lifecycle_version: base.signer_lifecycle_version,
    key_id: base.signer_key_id,
    key_version: base.signer_key_version,
    issued_at: "2026-08-20T00:00:00.000Z",
    expires_at: "2026-08-20T00:05:00.000Z"
  })
});

test("issuance, uncertain transition, reconcile, and replay share one authority seam", async () => {
  const client = new PromotionStateClient();
  let verified = 0;
  const repository = createPostgresPromotionIssuanceRepository({
    client,
    evidenceVerifier(evidence, authority) {
      verified += 1;
      assert.equal(typeof evidence.signature, "string");
      assert.match(authority.authority_digest, /^[0-9a-f]{64}$/u);
    }
  });

  const reserved = await repository.reservePromotion(base);
  assert.equal(reserved.state, "reserved");
  assert.match(reserved.claim_token, /^[A-Za-z0-9_-]{43}$/u);

  const uncertain = await repository.markUncertain({ ...base, claim_token: reserved.claim_token, reason: "provider_response_loss", provider_operation_id: base.provider_operation_id });
  assert.deepEqual(uncertain, { state: "uncertain", promotion_id: base.promotion_id, provider_operation_id: base.provider_operation_id });
  await assert.rejects(
    repository.reconcileUncertainPromotion({ ...base, provider_operation_id: "provider-op-2", evidence: SEAM_EVIDENCE }),
    { code: "ERR_PROMOTION_ISSUANCE_CONFLICT" }
  );

  const committed = await repository.reconcileUncertainPromotion({ ...base, provider_operation_id: base.provider_operation_id, evidence: SEAM_EVIDENCE });
  assert.equal(committed.state, "committed");
  assert.equal(committed.generation, 1);
  assert.deepEqual(committed.evidence, SEAM_EVIDENCE);
  assert.deepEqual(await repository.replayPromotion(base), committed);
  assert.equal(verified, 2);
  assert.equal(client.calls.some(({ text }) => text === "BEGIN"), true);
  assert.equal(client.calls.some(({ text }) => text.includes("pg_advisory_xact_lock")), true);
  assert.equal(client.issuance.claim_token_digest, null);
});

test("commit and reconcile fail closed before storage when evidence verification is unavailable", async () => {
  const client = new PromotionStateClient();
  const repository = createPostgresPromotionIssuanceRepository({ client });
  await assert.rejects(
    repository.commitPromotion({ ...base, claim_token: "A".repeat(43), provider_operation_id: base.provider_operation_id, evidence: SEAM_EVIDENCE }),
    { code: "ERR_PROMOTION_ISSUANCE_CONFIG" }
  );
  await assert.rejects(
    repository.reconcileUncertainPromotion({ ...base, provider_operation_id: base.provider_operation_id, evidence: SEAM_EVIDENCE }),
    { code: "ERR_PROMOTION_ISSUANCE_CONFIG" }
  );
  assert.equal(client.calls.length, 0);
});

test("commit requires the exact committed provider operation and never promotes an accepted-only result", async () => {
  const client = new PromotionStateClient();
  client.providerState = "accepted";
  const repository = createPostgresPromotionIssuanceRepository({ client, evidenceVerifier() {} });
  const reserved = await repository.reservePromotion(base);
  await assert.rejects(
    repository.commitPromotion({ ...base, claim_token: reserved.claim_token, evidence: SEAM_EVIDENCE }),
    { code: "ERR_PROMOTION_ISSUANCE_UNCERTAIN" }
  );
  assert.equal(client.issuance.state, "reserved");
  assert.equal(client.deployment, null);
});

test("provider success followed by a database failure is compensated to uncertain without provider retry", async () => {
  const client = new PromotionStateClient();
  client.failCommitUpdate = true;
  let providerCalls = 0;
  const repository = createPostgresPromotionIssuanceRepository({
    client,
    evidenceVerifier() {},
    providerOperationRepository: {
      async reconcileOperation() {
        providerCalls += 1;
        return { state: "committed" };
      }
    }
  });
  const reserved = await repository.reservePromotion(base);
  await assert.rejects(
    repository.commitPromotion({ ...base, claim_token: reserved.claim_token, evidence: SEAM_EVIDENCE }),
    { code: "ERR_PROMOTION_ISSUANCE_UNCERTAIN" }
  );
  assert.equal(client.issuance.state, "uncertain");
  assert.equal(client.issuance.uncertain_reason, "commit_failure");
  assert.equal(providerCalls, 1);
  assert.equal((await repository.replayPromotion(base)).state, "uncertain");
  assert.equal(providerCalls, 1);
});

test("audit failure after provider success rolls back the commit and preserves uncertain without provider retry", async () => {
  const client = new PromotionStateClient();
  let providerCalls = 0;
  const repository = createPostgresPromotionIssuanceRepository({
    client,
    evidenceVerifier() {},
    providerOperationRepository: {
      async reconcileOperation() { providerCalls += 1; return { state: "committed" }; }
    }
  });
  const reserved = await repository.reservePromotion(base);
  await assert.rejects(
    repository.commitPromotion({
      ...base,
      claim_token: reserved.claim_token,
      evidence: SEAM_EVIDENCE,
      onMutation: async () => { throw new Error("audit unavailable"); }
    }),
    { code: "ERR_PROMOTION_ISSUANCE_UNCERTAIN" }
  );
  assert.equal(client.issuance.state, "uncertain");
  assert.equal(client.issuance.uncertain_reason, "commit_failure");
  assert.equal(providerCalls, 1);
});

test("durable provider confirmation is compensated when the deployment write fails without an adapter", async () => {
  const client = new PromotionStateClient();
  client.failDeployment = true;
  const repository = createPostgresPromotionIssuanceRepository({ client, evidenceVerifier() {} });
  const reserved = await repository.reservePromotion(base);
  await assert.rejects(
    repository.commitPromotion({ ...base, claim_token: reserved.claim_token, evidence: SEAM_EVIDENCE }),
    { code: "ERR_PROMOTION_ISSUANCE_UNCERTAIN" }
  );
  assert.equal(client.issuance.state, "uncertain");
  assert.equal(client.issuance.uncertain_reason, "commit_failure");
  assert.equal(client.deployment, null);
});

test("compensation ignores an expired claim but still requires the original claim digest", async () => {
  const client = new PromotionStateClient();
  let providerCalls = 0;
  const repository = createPostgresPromotionIssuanceRepository({
    client,
    evidenceVerifier() {},
    providerOperationRepository: {
      async reconcileOperation() {
        providerCalls += 1;
        client.issuance.claim_expires_at = new Date(Date.now() - 1_000).toISOString();
        return { state: "committed" };
      }
    }
  });
  const reserved = await repository.reservePromotion(base);
  await assert.rejects(
    repository.commitPromotion({ ...base, claim_token: reserved.claim_token, evidence: SEAM_EVIDENCE }),
    { code: "ERR_PROMOTION_ISSUANCE_UNCERTAIN" }
  );
  assert.equal(client.issuance.state, "uncertain");
  assert.equal(client.issuance.uncertain_reason, "commit_failure");
  assert.equal(providerCalls, 1);
  await assert.rejects(
    repository.commitPromotion({ ...base, claim_token: "B".repeat(43), evidence: SEAM_EVIDENCE }),
    { code: "ERR_PROMOTION_ISSUANCE_UNCERTAIN" }
  );
  assert.equal(providerCalls, 1);
});

test("compensation refuses a claim digest changed during provider execution", async () => {
  const client = new PromotionStateClient();
  let providerCalls = 0;
  const repository = createPostgresPromotionIssuanceRepository({
    client,
    evidenceVerifier() {},
    providerOperationRepository: {
      async reconcileOperation() {
        providerCalls += 1;
        client.issuance.claim_token_digest = crypto.createHash("sha256").update("different-claim").digest("hex");
        return { state: "committed" };
      }
    }
  });
  const reserved = await repository.reservePromotion(base);
  await assert.rejects(
    repository.commitPromotion({ ...base, claim_token: reserved.claim_token, evidence: SEAM_EVIDENCE }),
    { code: "ERR_PROMOTION_ISSUANCE_UNCERTAIN" }
  );
  assert.equal(client.issuance.state, "reserved");
  assert.equal(providerCalls, 1);
});

test("reconcile delegates to the provider-operation repository with the exact promotion signing digest", async () => {
  const client = new PromotionStateClient();
  const calls = [];
  const repository = createPostgresPromotionIssuanceRepository({
    client,
    evidenceVerifier() {},
    providerOperationRepository: {
      async reconcileOperation(operation) { calls.push(operation); return { state: "committed" }; }
    }
  });
  const reserved = await repository.reservePromotion(base);
  await repository.markUncertain({ ...base, claim_token: reserved.claim_token, reason: "provider_response_loss", provider_operation_id: base.provider_operation_id });
  const committed = await repository.reconcileUncertainPromotion({ ...base, provider_operation_id: base.provider_operation_id, evidence: SEAM_EVIDENCE });
  const bytes = promotionEvidenceV3SigningData(SEAM_EVIDENCE.statement, { allowExpired: true, allowFuture: true });
  assert.equal(committed.state, "committed");
  assert.deepEqual(calls, [{
    algorithm: "ed25519",
    bytes_length: bytes.length,
    key_id: base.signer_key_id,
    key_version: String(base.signer_key_version),
    operation_id: base.provider_operation_id,
    purpose: PROMOTION_EVIDENCE_V3_PURPOSE,
    request_digest: crypto.createHash("sha256").update(bytes).digest("hex")
  }]);
});

test("reject preserves the bound provider operation without requiring a provider id echo", async () => {
  const client = new PromotionStateClient();
  const repository = createPostgresPromotionIssuanceRepository({ client });
  const reserved = await repository.reservePromotion(base);
  const rejected = await repository.rejectPromotion({ ...base, claim_token: reserved.claim_token, reason: "operator_rejected" });
  assert.deepEqual(rejected, { state: "rejected", reason: "operator_rejected" });
  assert.equal(client.issuance.provider_operation_id, base.provider_operation_id);
});
