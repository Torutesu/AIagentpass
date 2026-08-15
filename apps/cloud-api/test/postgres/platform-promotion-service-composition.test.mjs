import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import { deriveReleaseCandidateId } from "../../../../lib/release-candidate-identity.mjs";
import { verifyPromotionEvidenceV3 } from "../../src/promotion-evidence-v3-verifier.mjs";
import {
  PROMOTION_EVIDENCE_V3_ALGORITHM,
  PROMOTION_EVIDENCE_V3_MAX_TTL_MS,
  PROMOTION_EVIDENCE_V3_PROTOCOL_VERSION,
  PROMOTION_EVIDENCE_V3_PURPOSE,
  PROMOTION_EVIDENCE_V3_SIGNING_VERSION,
  promotionEvidenceV3PublicKeyFingerprint,
  promotionEvidenceV3SigningData,
} from "../../src/promotion-evidence-v3-statement.mjs";
import { createHostedPromotionEvidenceV3Signer } from "../../src/promotion-evidence-v3-signer.mjs";
import {
  PLATFORM_PROMOTION_ISSUANCE_ERROR_CODES as SERVICE_CODES,
  createPlatformPromotionIssuanceService,
} from "../../src/platform-promotion-issuance.mjs";
import { createPromotionEvidenceV3PublicKeyResolver } from "../../src/promotion-evidence-v3-public-key-resolver.mjs";
import { createPostgresPlatformPromotionIssuanceRepository } from "../../src/postgres/platform-promotion-issuance-repository.mjs";

const NOW = Date.parse("2026-08-15T00:00:00.000Z");
const TTL = PROMOTION_EVIDENCE_V3_MAX_TTL_MS;
const CLAIM_LEASE_MS = 30_000;
const INPUT = Object.freeze({
  promotion_id: "11111111-1111-4111-8111-111111111111",
  deployment_id: "cloud-prod-2026-08",
  environment: "production",
  candidate_id: deriveReleaseCandidateId("a".repeat(64)),
  idempotency_key: "promotion-request-0001",
});
const AUTHORITY = Object.freeze({
  approval_id: "22222222-2222-4222-8222-222222222222",
  approval_digest: "b".repeat(64),
  source_commit: "1".repeat(40),
  source_tree: "2".repeat(40),
  product_pkg_sha256: "a".repeat(64),
  image_digest: `sha256:${"c".repeat(64)}`,
  sbom_sha256: "d".repeat(64),
  qualification_report_digests: ["0".repeat(64), "1".repeat(64)],
  release_manifest_schema_version: 4,
  release_manifest_sha256: "f".repeat(64),
  approval_expires_at: "2026-08-15T01:00:00.000Z",
  lifecycle_version: 3,
  key_id: "promotion-evidence-2026-08",
  key_version: 7,
});

function clone(value) {
  if (value === undefined || value === null) return value;
  if (Buffer.isBuffer(value) || value instanceof Uint8Array) return Buffer.from(value);
  if (Array.isArray(value)) return value.map(clone);
  if (typeof value === "object") {
    const result = {};
    for (const [key, child] of Object.entries(value)) result[key] = clone(child);
    return result;
  }
  return value;
}

function result(rows) {
  return { rows, rowCount: rows.length };
}

function timestamp(ms) {
  return new Date(ms).toISOString();
}

function sha256(value) {
  return crypto.createHash("sha256").update(String(value), "utf8").digest("hex");
}

function rawKeyFingerprint(publicKey) {
  return crypto.createHash("sha256")
    .update(publicKey.export({ type: "spki", format: "der" }))
    .digest("hex");
}

function authorityResult(publicKey, publicKeyRawFingerprint) {
  return {
    ...AUTHORITY,
    candidate_id: INPUT.candidate_id,
    signer_key_fingerprint: Buffer.from(publicKeyRawFingerprint, "hex"),
    public_key: publicKey.export({ type: "spki", format: "pem" }).toString(),
    platform_principal_ids: ["private-approval-principal"],
    authorization_evidence_digests: ["private-approval-evidence"],
  };
}

/**
 * A small deterministic pg.Client-shaped state machine. It snapshots state at
 * BEGIN and only publishes the snapshot at COMMIT, while intentionally
 * allowing a commit to succeed and its response to be lost.
 */
class DeterministicPromotionPg {
  constructor({ authority, loseNextCommitResponse = false } = {}) {
    this.authority = clone(authority);
    this.nowMs = NOW;
    this.loseNextCommitResponse = loseNextCommitResponse;
    this.state = {
      row: undefined,
      head: {
        deployment_id: INPUT.deployment_id,
        environment: INPUT.environment,
        current_generation: 0,
        current_candidate_id: null,
      },
    };
    this.transactionState = undefined;
    this.calls = [];
    this.events = [];
  }

  advance(ms) {
    this.nowMs += ms;
  }

  get row() {
    return this.state.row;
  }

  async query(text, params = []) {
    const sql = String(text).trim();
    this.calls.push({ text: sql, params: params.map(clone) });

    if (sql === "BEGIN") {
      assert.equal(this.transactionState, undefined);
      this.transactionState = clone(this.state);
      this.events.push("begin");
      return result([]);
    }
    if (sql === "COMMIT") {
      assert.notEqual(this.transactionState, undefined);
      this.state = this.transactionState;
      this.transactionState = undefined;
      this.events.push("commit");
      if (this.loseNextCommitResponse && this.state.row?.state === "committed") {
        this.loseNextCommitResponse = false;
        throw new Error("commit response lost; provider_diagnostics=private");
      }
      return result([]);
    }
    if (sql === "ROLLBACK") {
      this.transactionState = undefined;
      this.events.push("rollback");
      return result([]);
    }

    const state = this.transactionState ?? this.state;
    if (/pg_advisory_xact_lock\(/u.test(sql)) return result([{ locked: null }]);
    if (/SELECT clock_timestamp\(\) AS now/u.test(sql)) return result([{ now: timestamp(this.nowMs) }]);

    if (/SELECT claim_expires_at>clock_timestamp\(\) AS claim_active/u.test(sql)) {
      const active = state.row?.state === "reserved"
        && Date.parse(state.row.claim_expires_at) > this.nowMs;
      return state.row ? result([{ claim_active: active }]) : result([]);
    }

    if (/FROM platform_promotion_issuances/u.test(sql)) {
      if (/state IN \('reserved','uncertain'\)/u.test(sql)) {
        const open = state.row && ["reserved", "uncertain"].includes(state.row.state)
          ? state.row : undefined;
        return open ? result([clone(open)]) : result([]);
      }
      const matches = state.row && this.matchesIdentity(state.row, params)
        && (!/AND state='committed'/u.test(sql) || state.row.state === "committed");
      return matches ? result([clone(state.row)]) : result([]);
    }

    if (/INSERT INTO platform_promotion_deployments/u.test(sql)) return result([]);
    if (/FROM platform_promotion_deployments/u.test(sql)) return result([clone(state.head)]);
    if (/FROM platform_promotion_approvals approval/u.test(sql)) {
      return result([clone(this.authority)]);
    }
    if (/FROM managed_signer_key_lifecycles lifecycle/u.test(sql)) {
      if (this.authority.lifecycleAvailable === false) return result([]);
      return result([{
        lifecycle_version: AUTHORITY.lifecycle_version,
        key_id: AUTHORITY.key_id,
        key_version: AUTHORITY.key_version,
        state: "active",
      }]);
    }

    if (/INSERT INTO platform_promotion_issuances/u.test(sql)) {
      state.row = {
        ...INPUT,
        state: "reserved",
        approval_id: params[5],
        approval_digest: params[6],
        source_commit: params[7],
        source_tree: params[8],
        product_pkg_sha256: params[9],
        image_digest: params[10],
        sbom_sha256: params[11],
        qualification_report_digests: clone(params[12]),
        release_manifest_schema_version: params[13],
        release_manifest_sha256: params[14],
        approval_expires_at: params[15],
        issued_at: params[16],
        expires_at: params[17],
        purpose: PROMOTION_EVIDENCE_V3_PURPOSE,
        protocol_version: 3,
        signing_version: 3,
        lifecycle_version: params[18],
        key_id: params[19],
        key_version: params[20],
        signer_key_fingerprint: clone(params[21]),
        provider_operation_id: params[22],
        request_digest: clone(params[23]),
        claim_token_digest: Buffer.from(params[24]).toString("hex"),
        claim_expires_at: timestamp(this.nowMs + params[25]),
        evidence_digest: null,
        evidence_bytes: null,
        deployment_generation: null,
        uncertain_reason: null,
        created_at: timestamp(this.nowMs),
        updated_at: timestamp(this.nowMs),
      };
      return { rows: [], rowCount: 1 };
    }

    if (/SET state='committed'/u.test(sql)) {
      if (!state.row || state.row.state !== "reserved"
        || state.row.claim_token_digest !== Buffer.from(params[1]).toString("hex")
        || Date.parse(state.row.claim_expires_at) <= this.nowMs
        || Date.parse(state.row.approval_expires_at) <= this.nowMs) return result([]);
      state.row.state = "committed";
      state.row.claim_token_digest = null;
      state.row.claim_expires_at = null;
      state.row.evidence_bytes = clone(params[2]);
      state.row.evidence_digest = Buffer.from(params[3]).toString("hex");
      state.row.deployment_generation = params[4];
      state.row.uncertain_reason = null;
      state.row.updated_at = timestamp(this.nowMs);
      this.events.push("issuance-committed");
      return result([clone(state.row)]);
    }
    if (/SET current_generation=/u.test(sql)) {
      if (state.head.current_generation !== params[4]) return result([]);
      state.head.current_generation = params[2];
      state.head.current_candidate_id = params[3];
      this.events.push("deployment-advanced");
      return result([clone(state.head)]);
    }
    if (/SET state='uncertain'/u.test(sql)) {
      const claimDigest = params.length === 2 ? params[1] : params[2];
      if (!state.row || state.row.state !== "reserved"
        || state.row.claim_token_digest !== Buffer.from(claimDigest).toString("hex")) return result([]);
      state.row.state = "uncertain";
      state.row.claim_token_digest = null;
      state.row.claim_expires_at = null;
      state.row.uncertain_reason = params.length === 2 ? "stale_lifecycle" : params[1];
      state.row.updated_at = timestamp(this.nowMs);
      this.events.push("issuance-uncertain");
      return result([clone(state.row)]);
    }

    throw new Error(`unexpected SQL: ${sql.slice(0, 160)}`);
  }

  matchesIdentity(row, params) {
    return params[0] === row.promotion_id
      || (params[1] === row.deployment_id && params[2] === row.environment
        && params[3] === row.candidate_id && params[4] === row.idempotency_key);
  }
}

function createComposition({ forged = false, loseNextCommitResponse = false } = {}) {
  const signingKeys = crypto.generateKeyPairSync("ed25519");
  const publicKey = signingKeys.publicKey.export({ type: "spki", format: "pem" }).toString();
  const rawFingerprint = rawKeyFingerprint(signingKeys.publicKey);
  const signerFingerprint = promotionEvidenceV3PublicKeyFingerprint(signingKeys.publicKey);
  let signCalls = 0;
  const publicKeyMetadata = () => ({
    algorithm: PROMOTION_EVIDENCE_V3_ALGORITHM,
    key_id: AUTHORITY.key_id,
    public_key: publicKey,
  });
  const provider = {
    algorithm: PROMOTION_EVIDENCE_V3_ALGORITHM,
    key_id: AUTHORITY.key_id,
    key_version: AUTHORITY.key_version,
    purpose: PROMOTION_EVIDENCE_V3_PURPOSE,
    publicKeyMetadata,
    sign: async ({ bytes }) => {
      signCalls += 1;
      return crypto.sign(null, bytes, signingKeys.privateKey);
    },
    version: PROMOTION_EVIDENCE_V3_SIGNING_VERSION,
  };
  const snapshot = {
    version: AUTHORITY.lifecycle_version,
    purpose: PROMOTION_EVIDENCE_V3_PURPOSE,
    algorithm: PROMOTION_EVIDENCE_V3_ALGORITHM,
    keys: [{
      key_id: AUTHORITY.key_id,
      key_version: AUTHORITY.key_version,
      purpose: PROMOTION_EVIDENCE_V3_PURPOSE,
      algorithm: PROMOTION_EVIDENCE_V3_ALGORITHM,
      public_key: publicKey,
      public_key_fingerprint: rawFingerprint,
      state: "active",
      state_version: AUTHORITY.lifecycle_version,
    }],
  };
  let resolverCalls = 0;
  const lifecycleRepository = {
    async snapshot() {
      resolverCalls += 1;
      return clone(snapshot);
    },
  };
  const publicKeyResolver = createPromotionEvidenceV3PublicKeyResolver({
    repository: lifecycleRepository,
    now: () => NOW,
  });
  const signer = createHostedPromotionEvidenceV3Signer({
    provider,
    keyId: AUTHORITY.key_id,
    keyVersion: AUTHORITY.key_version,
    lifecycleVersion: AUTHORITY.lifecycle_version,
    publicKey,
    publicKeyFingerprint: signerFingerprint,
    maxTtlMs: TTL,
    now: () => NOW,
  });
  const composedSigner = forged
    ? {
      sign: async (statement) => {
        const valid = await signer.sign(statement);
        const other = crypto.generateKeyPairSync("ed25519");
        return {
          ...valid,
          signature: crypto.sign(
            null,
            promotionEvidenceV3SigningData(statement, { now: NOW, allowExpired: true, allowFuture: true }),
            other.privateKey,
          ).toString("base64url"),
        };
      },
    }
    : signer;
  const client = new DeterministicPromotionPg({
    authority: authorityResult(signingKeys.publicKey, rawFingerprint),
    loseNextCommitResponse,
  });
  const repositoryVerification = [];
  const repository = createPostgresPlatformPromotionIssuanceRepository({
    client,
    claimLeaseMs: CLAIM_LEASE_MS,
    evidenceTtlMs: TTL,
    keyId: AUTHORITY.key_id,
    keyVersion: AUTHORITY.key_version,
    lifecycleVersion: AUTHORITY.lifecycle_version,
    randomBytes: () => Buffer.alloc(32, 0x31),
    verifyEvidence: async (evidence, context) => {
      repositoryVerification.push({ evidence, context });
      const verified = await verifyPromotionEvidenceV3(evidence, {
        ...context,
        now: client.nowMs,
        publicKeyResolver,
      });
      assert.deepEqual(verified, evidence);
      return true;
    },
  });
  const service = createPlatformPromotionIssuanceService({
    repository,
    signer: composedSigner,
    publicKeyResolver,
    maxTtlMs: TTL,
    now: () => NOW,
  });
  return {
    client,
    lifecycleRepository,
    publicKeyResolver,
    repository,
    repositoryVerification,
    resolverCalls: () => resolverCalls,
    service,
    signer,
    signerCalls: () => signCalls,
    signerFingerprint,
  };
}

function verificationContext(value) {
  return {
    deployment_id: INPUT.deployment_id,
    environment: INPUT.environment,
    candidate_id: INPUT.candidate_id,
    source_commit: AUTHORITY.source_commit,
    source_tree: AUTHORITY.source_tree,
    product_pkg_sha256: AUTHORITY.product_pkg_sha256,
    image_digest: AUTHORITY.image_digest,
    sbom_sha256: AUTHORITY.sbom_sha256,
    qualification_report_digests: AUTHORITY.qualification_report_digests,
    release_manifest_schema_version: AUTHORITY.release_manifest_schema_version,
    release_manifest_sha256: AUTHORITY.release_manifest_sha256,
    platform_approval_id: AUTHORITY.approval_id,
    platform_approval_digest: AUTHORITY.approval_digest,
    purpose: PROMOTION_EVIDENCE_V3_PURPOSE,
    protocol_version: PROMOTION_EVIDENCE_V3_PROTOCOL_VERSION,
    signing_version: PROMOTION_EVIDENCE_V3_SIGNING_VERSION,
    lifecycle_version: AUTHORITY.lifecycle_version,
    key_id: AUTHORITY.key_id,
    key_version: AUTHORITY.key_version,
    signer_key_fingerprint: value.signerFingerprint,
    publicKeyResolver: value.publicKeyResolver,
    now: NOW,
    maxTtlMs: TTL,
  };
}

async function assertServiceCode(promise, expected) {
  await assert.rejects(promise, (error) => error?.code === expected);
}

test("composes real service, Ed25519 signer, historical resolver, and repository transaction", async () => {
  const value = createComposition();
  const issued = await value.service.issuePlatformPromotion(INPUT);

  assert.equal(issued.replayed, false);
  assert.equal(value.signerCalls(), 1, "one durable reservation permits exactly one sign call");
  assert.equal(value.repositoryVerification.length, 1, "repository independently verifies before commit");
  assert.deepEqual(value.repositoryVerification[0].context.qualification_report_digests, AUTHORITY.qualification_report_digests);
  assert.equal(value.client.row.state, "committed");
  assert.equal(value.client.state.head.current_generation, 1);
  assert.equal(value.client.state.head.current_candidate_id, INPUT.candidate_id);
  assert.ok(value.client.events.indexOf("issuance-committed") < value.client.events.lastIndexOf("commit"));
  assert.ok(value.client.events.indexOf("deployment-advanced") < value.client.events.lastIndexOf("commit"));

  const independentlyVerified = await verifyPromotionEvidenceV3(
    issued.promotion_evidence,
    verificationContext(value),
  );
  assert.deepEqual(independentlyVerified, issued.promotion_evidence);
  await assert.rejects(
    verifyPromotionEvidenceV3(issued.promotion_evidence, {
      ...verificationContext(value),
      source_tree: undefined,
    }),
    /context|config|input/i,
    "a verifier without the row-bound source_tree context fails closed",
  );

  const replayed = await value.service.issuePlatformPromotion(INPUT);
  assert.equal(replayed.replayed, true);
  assert.deepEqual(replayed.promotion_evidence, issued.promotion_evidence);
  assert.equal(value.signerCalls(), 1, "replay returns the durable envelope without signing");
  assert.equal(value.client.state.head.current_generation, 1);

  const serialized = JSON.stringify({ issued, replayed });
  for (const privateField of [
    "platform_principal_ids",
    "authorization_evidence_digests",
    "provider_operation_id",
    "request_digest",
    "private-approval-principal",
    "private-approval-evidence",
  ]) assert.equal(serialized.includes(privateField), false, `private field escaped: ${privateField}`);
  assert.equal(Object.hasOwn(issued, "provider_diagnostics"), false);
  assert.equal(Object.hasOwn(issued.promotion_evidence, "private_key"), false);
  assert.ok(value.resolverCalls() >= 4, "service, repository, direct verification, and replay use the historical resolver");
});

test("a forged Ed25519 response cannot commit and becomes terminally uncertain", async () => {
  const value = createComposition({ forged: true });

  await assertServiceCode(
    value.service.issuePlatformPromotion(INPUT),
    SERVICE_CODES.VERIFIER,
  );
  assert.equal(value.signerCalls(), 1);
  assert.equal(value.repositoryVerification.length, 0, "repository is never reached by a forged envelope");
  assert.equal(value.client.row.state, "uncertain");
  assert.equal(value.client.state.head.current_generation, 0);
  assert.equal(value.client.events.includes("issuance-committed"), false);

  await assertServiceCode(
    value.service.issuePlatformPromotion(INPUT),
    SERVICE_CODES.UNCERTAIN,
  );
  assert.equal(value.signerCalls(), 1, "uncertain state prevents re-signing");
});

test("a lost commit response is recovered by replay with one sign and one atomic generation", async () => {
  const value = createComposition({ loseNextCommitResponse: true });

  const issued = await value.service.issuePlatformPromotion(INPUT);
  assert.equal(issued.replayed, true, "service reconciles the accepted commit response loss");
  assert.equal(value.signerCalls(), 1);
  assert.equal(value.repositoryVerification.length, 1);
  assert.equal(value.client.row.state, "committed");
  assert.equal(value.client.state.head.current_generation, 1);
  assert.equal(value.client.events.filter((event) => event === "issuance-committed").length, 1);
  assert.equal(value.client.events.filter((event) => event === "deployment-advanced").length, 1);
  assert.equal(value.client.events.filter((event) => event === "commit").length, 3);
  assert.equal(value.client.events.includes("rollback"), true, "the mock exposes the lost response path");

  const replayed = await value.service.replayPlatformPromotion(INPUT);
  assert.equal(replayed.replayed, true);
  assert.deepEqual(replayed.promotion_evidence, issued.promotion_evidence);
  assert.equal(value.signerCalls(), 1);
});

test("expired or ambiguous leases are never reclaimed for a second sign", async () => {
  const value = createComposition();
  const reserved = await value.repository.reservePlatformPromotion(INPUT);
  assert.equal(reserved.state, "reserved");
  value.client.advance(CLAIM_LEASE_MS + 1);

  await assertServiceCode(
    value.service.issuePlatformPromotion(INPUT),
    SERVICE_CODES.UNCERTAIN,
  );
  assert.equal(value.signerCalls(), 0);
  assert.equal(value.client.row.state, "uncertain", "a late provider outcome terminalizes the durable lease");
  assert.equal(value.client.row.claim_token_digest, null);
  assert.deepEqual(await value.repository.replayPlatformPromotion(INPUT), { state: "uncertain" });
  assert.equal(value.signerCalls(), 0);
});
