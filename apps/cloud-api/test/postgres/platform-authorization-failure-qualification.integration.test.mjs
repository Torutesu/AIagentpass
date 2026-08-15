import { POSTGRES_SCHEMA_HEAD } from "../../src/postgres/schema-head.mjs";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import { createHostedPromotionEvidenceV3Signer } from "../../src/promotion-evidence-v3-signer.mjs";
import { verifyPromotionEvidenceV3 } from "../../src/promotion-evidence-v3-verifier.mjs";
import {
  PROMOTION_EVIDENCE_V3_ALGORITHM,
  PROMOTION_EVIDENCE_V3_PROTOCOL_VERSION,
  PROMOTION_EVIDENCE_V3_PURPOSE,
  PROMOTION_EVIDENCE_V3_SIGNATURE_DOMAIN,
  PROMOTION_EVIDENCE_V3_SIGNING_VERSION,
  PROMOTION_EVIDENCE_V3_TYPE,
  PROMOTION_EVIDENCE_V3_VERSION
} from "../../src/promotion-evidence-v3-statement.mjs";
import { createPlatformAuthorizedPromotionService, createPostgresPlatformAuthorizationRepository, PLATFORM_AUTHORIZATION_REPOSITORY_ERROR_CODES, PLATFORM_AUTHORIZATION_RESERVE_SQL } from "../../src/postgres/platform-authorization-repository.mjs";
import { createPostgresManagedSignerKeyLifecycleRepository } from "../../src/postgres/managed-signer-key-lifecycle-repository.mjs";
import { createPostgresProviderOperationRepository } from "../../src/postgres/provider-operation-repository.mjs";
import { createMigrationRunner } from "../../src/postgres/migration-runner.mjs";

const ADMIN_DATABASE_URL = process.env.AGENTPASS_TEST_POSTGRES_ADMIN_URL ?? process.env.P0B_POSTGRES_ADMIN_URL;
const { Pool } = ADMIN_DATABASE_URL ? await import("pg") : { Pool: undefined };
const OPERATION = "platform.promotion.issue";
const PURPOSE = PROMOTION_EVIDENCE_V3_PURPOSE;
const MIGRATION_HEAD = POSTGRES_SCHEMA_HEAD.version;
const QUALIFICATION_SIGNER_KEY_ID = "s1-shared-qualification-key";
const QUALIFICATION_SIGNER_KEY_PAIR = crypto.generateKeyPairSync("ed25519");

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest();
}

function sha256Hex(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function uuid() {
  return crypto.randomUUID();
}

function queryResult(result) {
  return result.rows[0]?.result;
}

function quoteIdentifier(value) {
  if (!/^[a-z][a-z0-9_]{0,62}$/u.test(value)) throw new TypeError("unsafe disposable database name");
  return `"${value}"`;
}

async function createDisposableDatabase(adminUrl) {
  const databaseName = `agentpass_s1_${process.pid}_${crypto.randomBytes(8).toString("hex")}`;
  const adminPool = new Pool({ connectionString: adminUrl, max: 1 });
  let created = false;
  try {
    await adminPool.query(`CREATE DATABASE ${quoteIdentifier(databaseName)}`);
    created = true;
  } finally {
    await adminPool.end().catch(() => {});
  }

  const databaseUrl = new URL(adminUrl);
  databaseUrl.pathname = `/${databaseName}`;
  const pool = new Pool({ connectionString: databaseUrl.toString(), max: 10 });
  let closed = false;
  return Object.freeze({
    pool,
    async close() {
      if (closed) return;
      closed = true;
      await pool.end().catch(() => {});
      if (!created) return;
      const cleanupPool = new Pool({ connectionString: adminUrl, max: 1 });
      try {
        await cleanupPool.query(`DROP DATABASE ${quoteIdentifier(databaseName)} WITH (FORCE)`);
      } finally {
        await cleanupPool.end().catch(() => {});
      }
    }
  });
}

async function migrate(pool) {
  const client = await pool.connect();
  try {
    const result = await createMigrationRunner({
      client,
      applicationVersion: "platform-authorization-failure-qualification"
    }).run();
    assert.equal(result.currentVersion, MIGRATION_HEAD);
    return result;
  } finally {
    client.release();
  }
}

async function seedFixture(pool, suffix = crypto.randomBytes(6).toString("hex"), { withSigner = false } = {}) {
  const client = await pool.connect();
  const organizationId = uuid();
  const memberId = uuid();
  const principalId = uuid();
  const assignmentId = uuid();
  const challengeId = uuid();
  const platformSessionId = uuid();
  const promotionId = uuid();
  const webauthnId = crypto.randomBytes(32);
  const sessionMaterialHash = crypto.randomBytes(32);
  const csrfToken = crypto.randomBytes(32).toString("base64url");
  const csrfHash = sha256(csrfToken);
  const jti = uuid();
  const jtiHash = sha256(jti);
  const challengeHash = crypto.randomBytes(32);
  const bindingHash = crypto.randomBytes(32);
  const claimHash = crypto.randomBytes(32);
  const deploymentId = `s1-failure-${suffix}`;
  const candidateId = `release-pkg-sha256-v1-${"a".repeat(64)}`;
  const idempotencyKey = `s1-request-${suffix}`;
  const sourceCommit = "b".repeat(40);
  const sourceTree = "c".repeat(40);
  const packageDigest = "a".repeat(64);
  const imageDigest = `sha256:${"d".repeat(64)}`;
  const sbomDigest = "e".repeat(64);
  const manifestDigest = "f".repeat(64);
  const qualificationDigest = "1".repeat(64);
  const approvalDigest = "2".repeat(64);
  const approvalId = uuid();
  const keyId = withSigner ? QUALIFICATION_SIGNER_KEY_ID : `s1-key-${suffix}`;
  const keyPair = withSigner ? QUALIFICATION_SIGNER_KEY_PAIR : crypto.generateKeyPairSync("ed25519");
  const keyPublicDer = keyPair.publicKey.export({ type: "spki", format: "der" });
  const request = Object.freeze({
    promotion_id: promotionId,
    deployment_id: deploymentId,
    environment: "staging",
    candidate_id: candidateId,
    idempotency_key: idempotencyKey
  });

  try {
    await client.query("BEGIN");
    const digestResult = await client.query(
      "SELECT public.agentpass_platform_authorization_request_digest($1,$2::uuid,$3::uuid,$4,$5,$6,$7) AS result",
      [OPERATION, organizationId, promotionId, deploymentId, request.environment, candidateId, idempotencyKey]
    );
    const requestDigest = queryResult(digestResult);

    await client.query("INSERT INTO organizations (id,name) VALUES ($1,$2)", [organizationId, `S1 failure ${suffix}`]);
    await client.query("INSERT INTO members (id,github_subject,display_name) VALUES ($1,$2,$3)", [memberId, `s1:${suffix}`, "S1"]);
    const membershipId = uuid();
    await client.query(
      "INSERT INTO memberships (organization_id,id,member_id,role,status) VALUES ($1,$2,$3,'owner','active')",
      [organizationId, membershipId, memberId]
    );
    await client.query(`INSERT INTO webauthn_credentials
      (id,member_id,public_key,sign_count,transports,label,backup_eligible,backup_state)
      VALUES ($1,$2,$3,0,ARRAY['internal']::text[],'S1 qualification credential',false,false)`,
    [webauthnId, memberId, crypto.randomBytes(32)]);
    await client.query(
      "INSERT INTO platform_principals (principal_id,member_id,status) VALUES ($1,$2,'active')",
      [principalId, memberId]
    );
    await client.query(`INSERT INTO platform_operator_assignments
      (assignment_id,principal_id,member_id,organization_id,operation,capability,status,request_digest,requested_authority_generation,requested_at,issued_at,expires_at,activated_at)
      VALUES ($1,$2,$3,$4,$5,$5,'active',$6,1,clock_timestamp(),clock_timestamp(),clock_timestamp()+interval '10 minutes',clock_timestamp())`,
    [assignmentId, principalId, memberId, organizationId, OPERATION, sha256(`assignment:${suffix}`)]);
    await client.query(`INSERT INTO platform_credentials
      (credential_id,principal_id,member_id,webauthn_credential_id,label,status,backup_eligible,backup_state)
      VALUES ($1,$2,$3,$4,'S1 qualification credential','active',false,false)`,
    [uuid(), principalId, memberId, webauthnId]);

    await client.query(`INSERT INTO release_candidates
      (candidate_id,source_commit,artifact_sha256,manifest_sha256,team_id)
      VALUES ($1,$2,$3,$4,'C3TEST0001')`,
    [candidateId, sourceCommit, packageDigest, manifestDigest]);
    if (withSigner) {
      await client.query(`INSERT INTO managed_signer_key_lifecycles (purpose,algorithm,version)
        VALUES ($1,'ed25519',1) ON CONFLICT (purpose) DO NOTHING`, [PURPOSE]);
      await client.query(`INSERT INTO managed_signer_keys
        (purpose,key_id,key_version,algorithm,public_key_fingerprint,state,state_version,key_position)
        VALUES ($1,$2,1,'ed25519',$3,'active',1,0)
        ON CONFLICT (purpose,key_id) DO NOTHING`, [PURPOSE, keyId, sha256(keyPublicDer)]);
    }
    await client.query(`INSERT INTO platform_promotion_approvals
      (version,type,approval_id,deployment_id,environment,candidate_id,source_commit,source_tree,
       product_pkg_sha256,image_digest,sbom_sha256,qualification_report_digests,release_manifest_schema_version,
       release_manifest_sha256,policy_id,policy_version,approval_version,decision,platform_principal_ids,
       authorization_evidence_digests,approved_at,expires_at)
      VALUES (1,'agentpass.platform-promotion-approval',$1,$2,'staging',$3,$4,$5,$6,$7,$8,ARRAY[$9]::text[],4,$10,
       's1-failure-policy',1,1,'approved',ARRAY[$11]::text[],ARRAY[$12]::text[],clock_timestamp(),clock_timestamp()+interval '10 minutes')`,
    [approvalId, deploymentId, candidateId, sourceCommit, sourceTree, packageDigest, imageDigest, sbomDigest,
      qualificationDigest, manifestDigest, principalId, approvalDigest]);

    const challenge = queryResult(await client.query(`SELECT public.agentpass_platform_session_challenge_create(
      $1::uuid,$2::uuid,$3::bytea,$4::bytea,$5::bytea,$6::bytea,ARRAY[$7::bytea],$8::uuid,$9::uuid,$10::uuid,$11::uuid,$12::bigint,
      $13::text,$14::text,'console.agentpass.test','https://console.agentpass.test/','required',120000) AS result`,
    [challengeId, platformSessionId, jtiHash, challengeHash, bindingHash, requestDigest, webauthnId,
      principalId, memberId, organizationId, assignmentId, 1, OPERATION, OPERATION]));
    assert.equal(challenge.status, "pending");
    assert.deepEqual(challenge.allowed_credential_ids, [webauthnId.toString("base64url")]);
    const claimed = queryResult(await client.query(`SELECT public.agentpass_platform_session_challenge_claim(
      $1::uuid,$2::bytea,$3::bytea,$4::bytea,$5::bytea) AS result`,
    [challengeId, jtiHash, challengeHash, bindingHash, requestDigest]));
    assert.equal(claimed.claimed, true);
    const issued = queryResult(await client.query(`SELECT public.agentpass_platform_session_complete_and_issue(
      $1::uuid,$2::bytea,$3::bytea,$4::uuid,$5::bytea,$6::bytea,$7::bytea,$8::bytea,$9::bytea,900,300) AS result`,
    [platformSessionId, sessionMaterialHash, csrfHash, challengeId, jtiHash, challengeHash, bindingHash, requestDigest, webauthnId]));
    assert.equal(issued.challenge.outcome, "completed");
    assert.equal(issued.session.session_id, platformSessionId);
    await client.query("COMMIT");
    return Object.freeze({
      organizationId,
      memberId,
      principalId,
      assignmentId,
      challengeId,
      platformSessionId,
      promotionId,
      deploymentId,
      candidateId,
      idempotencyKey,
      keyId,
      request,
      auth: Object.freeze({
        organization_id: organizationId,
        session_material_hash: sessionMaterialHash,
        csrf_token: csrfToken,
        proof_id: challengeId,
        jti
      }),
      signer: Object.freeze({
        purpose: PURPOSE,
        keyId,
        keyPair,
        sourceCommit,
        sourceTree,
        packageDigest,
        imageDigest,
        sbomDigest,
        manifestDigest,
        qualificationDigest,
        approvalId
      })
    });
  } catch (error) {
    try { await client.query("ROLLBACK"); } catch { /* preserve original error */ }
    throw error;
  } finally {
    client.release();
  }
}

function createCommitLossPool(pool) {
  let armed = false;
  let lost = false;
  return Object.freeze({
    query(...args) { return pool.query(...args); },
    async connect() {
      const inner = await pool.connect();
      return {
        async query(text, params = []) {
          if (typeof text === "string" && text.includes("agentpass_platform_promotion_issuance_commit(")) armed = true;
          const result = await inner.query(text, params);
          if (text === "COMMIT" && armed && !lost) {
            armed = false;
            lost = true;
            throw new Error("qualification commit response intentionally lost");
          }
          return result;
        },
        release(...args) { inner.release(...args); }
      };
    },
    lostResponse() { return lost; }
  });
}

function createDisconnectPool() {
  return {
    async query() {
      throw Object.assign(new Error("simulated PostgreSQL disconnect"), { code: "08006" });
    },
    async connect() {
      throw Object.assign(new Error("simulated PostgreSQL disconnect"), { code: "08006" });
    }
  };
}

async function createPromotionSigner(pool, fixture) {
  const { keyPair } = fixture.signer;
  const publicKey = keyPair.publicKey.export({ type: "spki", format: "pem" }).toString();
  const publicKeyDer = keyPair.publicKey.export({ type: "spki", format: "der" });
  const publicKeyFingerprint = sha256Hex(publicKeyDer);
  const evidenceFingerprint = `SHA256:${Buffer.from(sha256(publicKeyDer)).toString("base64url")}`;
  const provider = {
    provider_id: "s1-qualification-provider",
    async publicKeyMetadata() {
      return { algorithm: PROMOTION_EVIDENCE_V3_ALGORITHM, key_id: fixture.keyId, public_key: publicKey };
    },
    async sign({ bytes }) {
      provider.calls += 1;
      return crypto.sign(null, bytes, keyPair.privateKey);
    },
    calls: 0
  };
  const postgresRuntime = {
    createManagedSignerKeyLifecycleRepository({ purpose, algorithm }) {
      return createPostgresManagedSignerKeyLifecycleRepository({ client: pool, purpose, algorithm });
    },
    createProviderOperationRepository({ purpose, algorithm, keyId, keyVersion }) {
      return createPostgresProviderOperationRepository({ client: pool, purpose, algorithm, keyId, keyVersion });
    }
  };
  const signer = await (await import("../../src/hosted-managed-signer-runtime.mjs")).bindHostedManagedSignerProvider({
    postgresRuntime,
    provider,
    purpose: PURPOSE,
    keyId: fixture.keyId,
    version: PROMOTION_EVIDENCE_V3_SIGNING_VERSION,
    algorithm: PROMOTION_EVIDENCE_V3_ALGORITHM,
    publicKey,
    publicKeyFingerprint
  });
  assert.equal(signer.lifecycle.version, 1);
  const lifecycleVersion = signer.lifecycle.version;
  const promotionSigner = createHostedPromotionEvidenceV3Signer({
    provider: signer.provider,
    keyId: fixture.keyId,
    keyVersion: signer.key_version,
    lifecycleVersion,
    publicKey,
    publicKeyFingerprint: evidenceFingerprint
  });
  const metadata = (request) => ({
    version: PROMOTION_EVIDENCE_V3_VERSION,
    type: PROMOTION_EVIDENCE_V3_TYPE,
    purpose: PURPOSE,
    domain: PROMOTION_EVIDENCE_V3_SIGNATURE_DOMAIN,
    protocol_version: PROMOTION_EVIDENCE_V3_PROTOCOL_VERSION,
    signing_version: PROMOTION_EVIDENCE_V3_SIGNING_VERSION,
    algorithm: PROMOTION_EVIDENCE_V3_ALGORITHM,
    key_id: request.key_id,
    key_version: request.key_version,
    lifecycle_version: request.lifecycle_version,
    public_key: publicKey,
    public_key_fingerprint: evidenceFingerprint
  });
  return Object.freeze({
    signer: promotionSigner,
    provider,
    keyId: fixture.keyId,
    keyVersion: signer.key_version,
    lifecycleVersion,
    publicKeyResolver: async (request) => metadata(request),
    verifyEvidence: async (evidence, context) => {
      await verifyPromotionEvidenceV3(evidence, {
        ...context,
        publicKeyResolver: async (request) => metadata(request)
      });
      return true;
    }
  });
}

function createAuthorizationRepository(client, fixture, signer) {
  return createPostgresPlatformAuthorizationRepository({
    client,
    keyId: signer.keyId,
    keyVersion: signer.keyVersion,
    lifecycleVersion: signer.lifecycleVersion,
    claimLeaseMs: 30_000,
    evidenceTtlMs: 10 * 60_000,
    randomBytes: () => Buffer.alloc(32, 0x71),
    verifyEvidence: signer.verifyEvidence
  });
}

async function countPromotion(pool, promotionId) {
  const result = await pool.query("SELECT count(*)::integer AS count FROM platform_promotion_issuances WHERE promotion_id=$1", [promotionId]);
  return result.rows[0].count;
}

async function proofStatus(pool, proofId) {
  const result = await pool.query("SELECT status FROM platform_authorization_proofs WHERE proof_id=$1", [proofId]);
  return result.rows[0]?.status;
}

test("S1 PostgreSQL failure convergence qualifies rollback, commit-loss reconciliation, and fail-closed database outcomes", {
  skip: ADMIN_DATABASE_URL ? false : "set AGENTPASS_TEST_POSTGRES_ADMIN_URL to run the disposable PostgreSQL qualification lane",
  timeout: 180_000
}, async (t) => {
  let database;
  try {
    database = await createDisposableDatabase(ADMIN_DATABASE_URL);
  } catch (error) {
    if (["ECONNREFUSED", "ENOTFOUND", "ETIMEDOUT", "EAI_AGAIN"].includes(error?.code)) {
      t.skip("PostgreSQL admin endpoint is unavailable");
      return;
    }
    throw error;
  }
  t.after(async () => database.close());
  const { pool } = database;
  await migrate(pool);

  await t.test("a pre-reservation SQL failure rolls back proof consumption and leaves the proof usable", async () => {
    const fixture = await seedFixture(pool, undefined, { withSigner: true });
    let corruptNextAuthorizationDigest = true;
    const client = {
      query(...args) { return pool.query(...args); },
      async connect() {
        const inner = await pool.connect();
        return {
          async query(text, params = []) {
            if (corruptNextAuthorizationDigest && text === PLATFORM_AUTHORIZATION_RESERVE_SQL) {
              corruptNextAuthorizationDigest = false;
              const corrupted = [...params];
              corrupted[4] = Buffer.alloc(32, 0x99);
              return inner.query(text, corrupted);
            }
            return inner.query(text, params);
          },
          release(...args) { inner.release(...args); }
        };
      }
    };
    const repository = createPostgresPlatformAuthorizationRepository({
      client,
      claimLeaseMs: 30_000,
      evidenceTtlMs: 10 * 60_000,
      randomBytes: () => Buffer.alloc(32, 0x72),
      verifyEvidence: async () => true
    });
    const scoped = repository.forAuthorization(fixture.auth);
    await assert.rejects(scoped.reservePlatformPromotion(fixture.request), (error) => {
      assert.equal(error.code, PLATFORM_AUTHORIZATION_REPOSITORY_ERROR_CODES.AUTHORIZATION_UNAVAILABLE);
      assert.equal("message" in error, true);
      assert.doesNotMatch(error.message, /99/u);
      return true;
    });
    assert.equal(await proofStatus(pool, fixture.challengeId), "available");
    assert.equal(await countPromotion(pool, fixture.promotionId), 0);
    const reserved = await scoped.reservePlatformPromotion(fixture.request);
    assert.equal(reserved.state, "reserved");
    assert.equal(await proofStatus(pool, fixture.challengeId), "consumed");
    assert.equal(await countPromotion(pool, fixture.promotionId), 1);
  });

  await t.test("serialization failure is classified as a stable unavailable authorization outcome", async () => {
    const fixture = await seedFixture(pool);
    await pool.query(
      "UPDATE platform_sessions SET status='revoked', revoked_at=clock_timestamp(), revoke_reason='s1-qualification', version=version+1 WHERE session_id=$1",
      [fixture.platformSessionId]
    );
    const repository = createAuthorizationRepository(pool, fixture, {
      keyId: fixture.keyId,
      keyVersion: 1,
      lifecycleVersion: 1,
      verifyEvidence: async () => true
    });
    await assert.rejects(repository.forAuthorization(fixture.auth).reservePlatformPromotion(fixture.request), (error) => {
      assert.equal(error.code, PLATFORM_AUTHORIZATION_REPOSITORY_ERROR_CODES.AUTHORIZATION_UNAVAILABLE);
      assert.equal(error.cause, undefined);
      return true;
    });
    assert.equal(await proofStatus(pool, fixture.challengeId), "available");
    assert.equal(await countPromotion(pool, fixture.promotionId), 0);
  });

  await t.test("a PostgreSQL disconnect before the authority call is a stable storage-unavailable failure", async () => {
    const fixture = await seedFixture(pool);
    const repository = createPostgresPlatformAuthorizationRepository({
      client: createDisconnectPool(),
      randomBytes: () => Buffer.alloc(32, 0x73),
      verifyEvidence: async () => true
    });
    await assert.rejects(repository.forAuthorization(fixture.auth).reservePlatformPromotion(fixture.request), (error) => {
      assert.equal(error.code, PLATFORM_AUTHORIZATION_REPOSITORY_ERROR_CODES.DATABASE);
      assert.equal(error.cause, undefined);
      return true;
    });
    assert.equal(await proofStatus(pool, fixture.challengeId), "available");
    assert.equal(await countPromotion(pool, fixture.promotionId), 0);
  });

  await t.test("a stale signer lifecycle snapshot denies reservation before signing", async () => {
    const fixture = await seedFixture(pool, undefined, { withSigner: true });
    const signer = await createPromotionSigner(pool, fixture);
    const repository = createAuthorizationRepository(pool, fixture, {
      ...signer,
      lifecycleVersion: signer.lifecycleVersion + 1
    });
    await assert.rejects(repository.forAuthorization(fixture.auth).reservePlatformPromotion(fixture.request), (error) => {
      assert.equal(error.code, PLATFORM_AUTHORIZATION_REPOSITORY_ERROR_CODES.AUTHORIZATION_UNAVAILABLE);
      assert.equal(error.cause, undefined);
      return true;
    });
    assert.equal(signer.provider.calls, 0);
    assert.equal(await proofStatus(pool, fixture.challengeId), "available");
    assert.equal(await countPromotion(pool, fixture.promotionId), 0);
  });

  await t.test("a lost durable commit response converges through exact authenticated re-entry with one signer call", async () => {
    const fixture = await seedFixture(pool, undefined, { withSigner: true });
    const signer = await createPromotionSigner(pool, fixture);
    const commitLossClient = createCommitLossPool(pool);
    const repository = createAuthorizationRepository(commitLossClient, fixture, signer);
    const service = createPlatformAuthorizedPromotionService({
      repository,
      signer: signer.signer,
      publicKeyResolver: signer.publicKeyResolver
    });
    const issued = await service.issuePlatformPromotion({ ...fixture.request, ...fixture.auth });
    assert.equal(issued.replayed, true);
    assert.equal(commitLossClient.lostResponse(), true);
    assert.equal(signer.provider.calls, 1);
    assert.equal(await proofStatus(pool, fixture.challengeId), "consumed");
    assert.equal(await countPromotion(pool, fixture.promotionId), 1);
    const durable = await pool.query(
      "SELECT state, deployment_generation, claim_token_digest FROM platform_promotion_issuances WHERE promotion_id=$1",
      [fixture.promotionId]
    );
    assert.deepEqual(durable.rows[0], { state: "committed", deployment_generation: "1", claim_token_digest: null });
  });
});
