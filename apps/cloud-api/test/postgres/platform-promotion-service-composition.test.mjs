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
import { canonicalManagedSignerRequestDigest } from "../../src/postgres/managed-signer-key-lifecycle-repository.mjs";
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
    this.authorityCalls = [];
    this.events = [];
    this.providerLedger = undefined;
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
    const authorityFunction = sql.match(
      /^SELECT agentpass_platform_promotion_issuance_(reserve|replay|commit|uncertain|get)\(/u,
    );
    if (authorityFunction) {
      const name = authorityFunction[1];
      this.authorityCalls.push({ name, params: params.map(clone) });
      return this.callAuthorityFunction(state, name, params);
    }

    throw new Error(`unexpected SQL outside authority function boundary: ${sql.slice(0, 160)}`);
  }

  recordProviderSignature({ bytes, signature }) {
    const requestDigest = canonicalManagedSignerRequestDigest({
      algorithm: PROMOTION_EVIDENCE_V3_ALGORITHM,
      bytes,
      key_id: AUTHORITY.key_id,
      purpose: PROMOTION_EVIDENCE_V3_PURPOSE,
      version: PROMOTION_EVIDENCE_V3_SIGNING_VERSION,
      key_version: AUTHORITY.key_version,
    });
    this.providerLedger = {
      algorithm: PROMOTION_EVIDENCE_V3_ALGORITHM,
      bytes: Buffer.from(bytes),
      bytes_length: bytes.length,
      key_id: AUTHORITY.key_id,
      key_version: AUTHORITY.key_version,
      lifecycle_version: AUTHORITY.lifecycle_version,
      operation_id: `managed-signer-v1-${requestDigest}`,
      provider_receipt_id: `test-receipt-${requestDigest.slice(0, 16)}`,
      provider_receipt_provider: "deterministic-test-provider",
      request_digest: requestDigest,
      signature: Buffer.from(signature),
      state: "committed",
    };
    if (this.state.row) {
      this.state.row.provider_operation_id = this.providerLedger.operation_id;
      this.state.row.request_digest = requestDigest;
    }
  }

  callAuthorityFunction(state, name, params) {
    switch (name) {
      case "reserve": return this.reserveAuthority(state, params);
      case "replay": return this.replayAuthority(state, params);
      case "commit": return this.commitAuthority(state, params);
      case "uncertain": return this.uncertainAuthority(state, params);
      case "get": return this.getAuthority(state, params);
      default: throw new Error(`unexpected authority function: ${name}`);
    }
  }

  authorityResult(row, claimIssued = false) {
    if (!row) return result([{ result: null }]);
    return result([{
      result: {
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
        qualification_report_digests: clone(row.qualification_report_digests),
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
        signer_key_fingerprint: `SHA256:${Buffer.from(row.signer_key_fingerprint).toString("base64url")}`,
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
        claim_issued: claimIssued,
      },
    }]);
  }

  findIdentity(state, params) {
    const [promotionId, deploymentId, environment, candidateId, idempotencyKey] = params;
    if (!state.row) return undefined;
    if (state.row.promotion_id === promotionId) return state.row;
    if (state.row.deployment_id === deploymentId && state.row.environment === environment
      && state.row.candidate_id === candidateId && state.row.idempotency_key === idempotencyKey) return state.row;
    return undefined;
  }

  assertIdentity(row, params) {
    const [, deploymentId, environment, candidateId, idempotencyKey] = params;
    if (row.deployment_id !== deploymentId || row.environment !== environment
      || row.candidate_id !== candidateId || row.idempotency_key !== idempotencyKey) {
      throw new Error("authority identity conflict");
    }
  }

  reserveAuthority(state, params) {
    const [promotionId, deploymentId, environment, candidateId, idempotencyKey,
      claimTokenDigest, claimLeaseMs, evidenceTtlMs] = params;
    const existing = this.findIdentity(state, params);
    if (existing) {
      this.assertIdentity(existing, params);
      if (existing.state === "reserved" && Date.parse(existing.claim_expires_at) <= this.nowMs) {
        this.transitionUncertain(existing, "stale_lifecycle");
      }
      return this.authorityResult(existing, false);
    }
    const open = state.row && state.row.deployment_id === deploymentId
      && state.row.environment === environment
      && ["reserved", "uncertain"].includes(state.row.state) ? state.row : undefined;
    if (open) return this.authorityResult(open, false);
    if (this.authority.lifecycleAvailable === false) throw new Error("authority unavailable");

    const issuedAt = timestamp(this.nowMs);
    const expiresAt = timestamp(Math.min(
      Date.parse(this.authority.approval_expires_at),
      this.nowMs + evidenceTtlMs,
    ));
    state.row = {
      promotion_id: promotionId,
      deployment_id: deploymentId,
      environment,
      candidate_id: candidateId,
      idempotency_key: idempotencyKey,
      state: "reserved",
      approval_id: this.authority.approval_id,
      approval_digest: this.authority.approval_digest,
      source_commit: this.authority.source_commit,
      source_tree: this.authority.source_tree,
      product_pkg_sha256: this.authority.product_pkg_sha256,
      image_digest: this.authority.image_digest,
      sbom_sha256: this.authority.sbom_sha256,
      qualification_report_digests: clone(this.authority.qualification_report_digests),
      release_manifest_schema_version: this.authority.release_manifest_schema_version,
      release_manifest_sha256: this.authority.release_manifest_sha256,
      approval_expires_at: this.authority.approval_expires_at,
      issued_at: issuedAt,
      expires_at: expiresAt,
      purpose: PROMOTION_EVIDENCE_V3_PURPOSE,
      protocol_version: PROMOTION_EVIDENCE_V3_PROTOCOL_VERSION,
      signing_version: PROMOTION_EVIDENCE_V3_SIGNING_VERSION,
      lifecycle_version: this.authority.lifecycle_version,
      key_id: this.authority.key_id,
      key_version: this.authority.key_version,
      signer_key_fingerprint: Buffer.from(this.authority.signer_key_fingerprint),
      claim_token_digest: Buffer.from(claimTokenDigest),
      claim_expires_at: timestamp(this.nowMs + claimLeaseMs),
      evidence_digest: null,
      evidence_bytes: null,
      deployment_generation: null,
      uncertain_reason: null,
      created_at: issuedAt,
      updated_at: issuedAt,
    };
    return this.authorityResult(state.row, true);
  }

  replayAuthority(state, params) {
    const row = this.findIdentity(state, params);
    if (!row) return result([{ result: { state: "absent" } }]);
    this.assertIdentity(row, params);
    if (row.state === "reserved" && Date.parse(row.claim_expires_at) <= this.nowMs) {
      this.transitionUncertain(row, "stale_lifecycle");
    }
    if (row.state === "reserved") return result([{ result: { state: "in_progress" } }]);
    if (row.state === "uncertain") return result([{ result: { state: "uncertain" } }]);
    return this.authorityResult(row, false);
  }

  commitAuthority(state, params) {
    const [promotionId, deploymentId, environment, candidateId, idempotencyKey,
      claimTokenDigest, signingBytes, signature, evidenceBytes, evidenceDigest] = params;
    const row = state.row;
    if (!row || row.promotion_id !== promotionId) throw new Error("issuance not found");
    this.assertIdentity(row, params);
    const digest = Buffer.from(evidenceDigest).toString("hex");
    if (digest !== sha256(evidenceBytes)) throw new Error("evidence digest");
    const ledger = this.providerLedger;
    if (!ledger || ledger.state !== "committed"
      || !Buffer.from(ledger.bytes).equals(Buffer.from(signingBytes))
      || !Buffer.from(ledger.signature).equals(Buffer.from(signature))
      || ledger.key_id !== row.key_id || ledger.key_version !== row.key_version
      || ledger.lifecycle_version !== row.lifecycle_version
      || ledger.operation_id !== row.provider_operation_id) {
      throw new Error("provider ledger binding");
    }
    if (row.state === "committed") {
      if (row.evidence_digest !== digest || !Buffer.from(row.evidence_bytes).equals(Buffer.from(evidenceBytes))) {
        throw new Error("committed evidence conflict");
      }
      return this.authorityResult(row, false);
    }
    if (row.state !== "reserved"
      || !Buffer.from(row.claim_token_digest).equals(Buffer.from(claimTokenDigest))
      || Date.parse(row.claim_expires_at) <= this.nowMs
      || Date.parse(row.approval_expires_at) <= this.nowMs) throw new Error("claim expired");
    const nextGeneration = state.head.current_generation + 1;
    row.state = "committed";
    row.claim_token_digest = null;
    row.claim_expires_at = null;
    row.evidence_bytes = Buffer.from(evidenceBytes);
    row.evidence_digest = digest;
    row.deployment_generation = nextGeneration;
    row.uncertain_reason = null;
    row.updated_at = timestamp(this.nowMs);
    state.head.current_generation = nextGeneration;
    state.head.current_candidate_id = row.candidate_id;
    this.events.push("issuance-committed");
    this.events.push("deployment-advanced");
    return this.authorityResult(row, false);
  }

  uncertainAuthority(state, params) {
    const row = state.row;
    if (!row || row.promotion_id !== params[0]) throw new Error("issuance not found");
    this.assertIdentity(row, params);
    if (row.state === "committed") return this.authorityResult(row, false);
    if (row.state === "uncertain") return result([{ result: { state: "uncertain" } }]);
    if (!Buffer.from(row.claim_token_digest).equals(Buffer.from(params[5]))) throw new Error("claim invalid");
    this.transitionUncertain(row, params[6]);
    return result([{ result: { state: "uncertain" } }]);
  }

  getAuthority(state, params) {
    const row = state.row && state.row.promotion_id === params[0] ? state.row : undefined;
    if (!row || (params[5] === true && row.state !== "committed")) return result([{ result: null }]);
    this.assertIdentity(row, params);
    return this.authorityResult(row, false);
  }

  transitionUncertain(row, reason) {
    row.state = "uncertain";
    row.claim_token_digest = null;
    row.claim_expires_at = null;
    row.uncertain_reason = reason;
    row.updated_at = timestamp(this.nowMs);
    this.events.push("issuance-uncertain");
  }
}

function createComposition({ forged = false, loseNextCommitResponse = false } = {}) {
  const signingKeys = crypto.generateKeyPairSync("ed25519");
  const publicKey = signingKeys.publicKey.export({ type: "spki", format: "pem" }).toString();
  const rawFingerprint = rawKeyFingerprint(signingKeys.publicKey);
  const signerFingerprint = promotionEvidenceV3PublicKeyFingerprint(signingKeys.publicKey);
  let signCalls = 0;
  let client;
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
      const signature = crypto.sign(null, bytes, signingKeys.privateKey);
      client.recordProviderSignature({ bytes, signature });
      return signature;
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
  client = new DeterministicPromotionPg({
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
  assert.equal(value.repositoryVerification.length, 2, "repository independently verifies before and after commit");
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
  assert.equal(value.repositoryVerification.length, 3, "commit result and durable replay are independently verified");
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
