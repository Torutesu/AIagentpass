import assert from "node:assert/strict";
import crypto from "node:crypto";
import { randomUUID } from "node:crypto";
import test from "node:test";

import { createMigrationRunner } from "../../src/postgres/migration-runner.mjs";
import { createPostgresPlatformPromotionIssuanceRepository } from "../../src/postgres/platform-promotion-issuance-repository.mjs";
import {
  PROMOTION_EVIDENCE_V3_ALGORITHM,
  PROMOTION_EVIDENCE_V3_PURPOSE,
  PROMOTION_EVIDENCE_V3_TYPE,
  PROMOTION_EVIDENCE_V3_VERSION,
  promotionEvidenceV3StatementHash
} from "../../src/promotion-evidence-v3-statement.mjs";

const DATABASE_URL = process.env.AGENTPASS_TEST_DATABASE_URL ?? process.env.AGENTPASS_TEST_POSTGRES_URL;
const { Pool } = DATABASE_URL ? await import("pg") : { Pool: undefined };

function sha256(value) { return crypto.createHash("sha256").update(value, "utf8").digest("hex"); }
function sha1(value) { return crypto.createHash("sha1").update(value, "utf8").digest("hex"); }

test("0047 real PostgreSQL reserves, commits, and replays one exact promotion", { skip: !DATABASE_URL, timeout: 60_000 }, async (t) => {
  const pool = new Pool({ connectionString: DATABASE_URL, max: 2 });
  t.after(() => pool.end());
  const migrationClient = await pool.connect();
  try {
    const migrated = await createMigrationRunner({ client: migrationClient, applicationVersion: "platform-promotion-issuance" }).run();
    assert.equal(migrated.currentVersion, 47);
  } finally { migrationClient.release(); }

  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const suffix = randomUUID().replaceAll("-", "");
    const deploymentId = `integration-promotion-${suffix}`;
    const promotionId = randomUUID();
    const sourceCommit = sha1(`commit:${suffix}`);
    const sourceTree = sha1(`tree:${suffix}`);
    const pkg = sha256(`pkg:${suffix}`);
    const candidateId = `release-pkg-sha256-v1-${pkg}`;
    const imageDigest = `sha256:${sha256(`image:${suffix}`)}`;
    const sbom = sha256(`sbom:${suffix}`);
    const manifest = sha256(`manifest:${suffix}`);
    const report = sha256(`report:${suffix}`);
    const approvalId = randomUUID();
    const now = new Date();
    const approvedAt = new Date(now.getTime() - 1_000);
    const expiresAt = new Date(now.getTime() + 10 * 60_000);

    let signer = (await client.query(`SELECT lifecycle.version AS lifecycle_version,key.key_id,key.key_version
      FROM managed_signer_key_lifecycles lifecycle JOIN managed_signer_keys key
        ON key.purpose=lifecycle.purpose AND key.state='active'
      WHERE lifecycle.purpose=$1 LIMIT 1`, [PROMOTION_EVIDENCE_V3_PURPOSE])).rows[0];
    if (!signer) {
      const keyId = `integration-promotion-key-${suffix}`;
      await client.query(`INSERT INTO managed_signer_key_lifecycles (purpose,algorithm,version)
        VALUES ($1,'ed25519',1)`, [PROMOTION_EVIDENCE_V3_PURPOSE]);
      await client.query(`INSERT INTO managed_signer_keys
        (purpose,key_id,key_version,algorithm,public_key_fingerprint,state,state_version,key_position)
        VALUES ($1,$2,1,'ed25519',$3,'active',1,0)`, [PROMOTION_EVIDENCE_V3_PURPOSE, keyId, Buffer.alloc(32, 9)]);
      signer = { lifecycle_version: 1, key_id: keyId, key_version: 1 };
    }

    await client.query(`INSERT INTO release_candidates
      (candidate_id,source_commit,artifact_sha256,manifest_sha256,team_id)
      VALUES ($1,$2,$3,$4,'C3TEST0001')`, [candidateId, sourceCommit, pkg, manifest]);
    await client.query(`INSERT INTO platform_promotion_approvals
      (version,type,approval_id,deployment_id,environment,candidate_id,source_commit,source_tree,
       product_pkg_sha256,image_digest,sbom_sha256,qualification_report_digests,release_manifest_schema_version,
       release_manifest_sha256,policy_id,policy_version,approval_version,decision,platform_principal_ids,
       authorization_evidence_digests,approved_at,expires_at)
      VALUES (1,'agentpass.platform-promotion-approval',$1,$2,'staging',$3,$4,$5,$6,$7,$8,ARRAY[$9]::text[],4,$10,
       'integration-policy',1,1,'approved',ARRAY['platform-a']::text[],ARRAY[$11]::text[],$12,$13)`, [
      approvalId, deploymentId, candidateId, sourceCommit, sourceTree, pkg, imageDigest, sbom, report, manifest,
      sha256(`authorization:${suffix}`), approvedAt, expiresAt
    ]);

    const repo = createPostgresPlatformPromotionIssuanceRepository({
      client, keyId: signer.key_id, keyVersion: Number(signer.key_version), lifecycleVersion: Number(signer.lifecycle_version), claimLeaseMs: 30_000,
      randomBytes: () => Buffer.alloc(32, 4),
      verifyEvidence: async (_evidence, context) => typeof context?.signer_key_fingerprint === "string"
    });
    const identity = { promotion_id: promotionId, deployment_id: deploymentId, environment: "staging", candidate_id: candidateId, idempotency_key: "integration-request-0001" };
    const reserved = await repo.reservePlatformPromotion(identity);
    assert.equal(reserved.state, "reserved");
    const statement = {
      version: 3, type: PROMOTION_EVIDENCE_V3_TYPE, promotion_id: promotionId, deployment_id: deploymentId, environment: "staging",
      candidate_id: candidateId, source_commit: reserved.source_commit, source_tree: reserved.source_tree,
      product_pkg_sha256: reserved.product_pkg_sha256, image_digest: reserved.image_digest, sbom_sha256: reserved.sbom_sha256,
      qualification_report_digests: reserved.qualification_report_digests,
      release_manifest_schema_version: reserved.release_manifest_schema_version, release_manifest_sha256: reserved.release_manifest_sha256,
      platform_approval_id: reserved.platform_approval_id, platform_approval_digest: reserved.platform_approval_digest, approval_state: "approved",
      purpose: PROMOTION_EVIDENCE_V3_PURPOSE, protocol_version: 3, signing_version: 3, lifecycle_version: Number(reserved.lifecycle_version),
      key_id: reserved.key_id, key_version: Number(reserved.key_version), issued_at: reserved.issued_at,
      expires_at: reserved.expires_at
    };
    const evidence = { version: PROMOTION_EVIDENCE_V3_VERSION, type: PROMOTION_EVIDENCE_V3_TYPE, statement,
      statement_hash: promotionEvidenceV3StatementHash(statement), signature_algorithm: PROMOTION_EVIDENCE_V3_ALGORITHM,
      signer_key_fingerprint: reserved.signer_key_fingerprint, signature: Buffer.alloc(64, 5).toString("base64url") };
    const committed = await repo.commitPlatformPromotion({ ...identity, claim_token: reserved.claim_token, promotion_evidence: evidence });
    assert.equal(committed.state, "committed");
    assert.equal(Object.hasOwn(committed, "deployment_generation"), false);
    assert.deepEqual(await repo.replayPlatformPromotion(identity), committed);
    const head = await client.query(`SELECT current_generation,current_candidate_id FROM platform_promotion_deployments WHERE deployment_id=$1 AND environment='staging'`, [deploymentId]);
    assert.deepEqual(head.rows[0], { current_generation: "1", current_candidate_id: candidateId });
    const stored = await client.query(`SELECT state,evidence_digest,claim_token_digest FROM platform_promotion_issuances WHERE promotion_id=$1`, [promotionId]);
    assert.equal(stored.rows[0].state, "committed");
    assert.equal(stored.rows[0].claim_token_digest, null);
    assert.match(stored.rows[0].evidence_digest, /^[0-9a-f]{64}$/u);
    await client.query("ROLLBACK");
  } catch (error) {
    try { await client.query("ROLLBACK"); } catch { /* preserve original failure */ }
    throw error;
  } finally { client.release(); }
});
