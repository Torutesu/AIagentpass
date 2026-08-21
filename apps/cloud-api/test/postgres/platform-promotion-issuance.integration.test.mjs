import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";
import { Pool } from "pg";

import {
  normalizePlatformPromotionApprovalRecord,
  platformPromotionApprovalRecordDigest
} from "../../src/platform-promotion-approval-record.mjs";
import { createMigrationRunner } from "../../src/postgres/migration-runner.mjs";

const DATABASE_URL = process.env.AGENTPASS_TEST_DATABASE_URL ?? process.env.AGENTPASS_TEST_POSTGRES_URL;
const SUFFIX = `${process.pid}-${crypto.randomBytes(6).toString("hex")}`;
const PRODUCT = "a".repeat(64);
const QUALIFICATION = ["1".repeat(64), "2".repeat(64)];
const IDS = Object.freeze({
  approval: "11111111-1111-4111-8111-111111111111",
  promotion: "22222222-2222-4222-8222-222222222222"
});

test("0047 SQL fences approval/provider cross-row binding, expired claims, and deployment promotion state", {
  skip: !DATABASE_URL,
  timeout: 60_000
}, async (t) => {
  const pool = new Pool({ connectionString: DATABASE_URL, max: 1 });
  const client = await pool.connect();
  t.after(async () => {
    client.release();
    await pool.end();
  });

  const migrated = await createMigrationRunner({ client, applicationVersion: "platform-promotion-issuance-audit" }).run();
  assert.equal(migrated.currentVersion, 47);

  const deploymentId = `audit-${SUFFIX}`;
  const operationId = `promotion-operation-${SUFFIX}`;
  const now = Date.now();
  const approval = makeApproval({
    approval_id: IDS.approval,
    deployment_id: deploymentId,
    approved_at: new Date(now - 5_000).toISOString(),
    expires_at: new Date(now + 300_000).toISOString(),
    approval_version: 1
  });

  await client.query("BEGIN");
  try {
    await insertApproval(client, approval);
    await insertProviderOperation(client, { operationId, expiresAt: new Date(now + 300_000) });

    await assertSqlRejected(client, insertIssuanceSql(), issuanceParams(approval, operationId, {
      promotion_id: IDS.promotion,
      deployment_id: `${deploymentId}-wrong`
    }), /platform_promotion_issuances_approval_binding|violates foreign key/u);

    await assertSqlRejected(client, insertIssuanceSql(), issuanceParams(approval, operationId, {
      promotion_id: IDS.promotion,
      qualification_report_digests: JSON.stringify(["3".repeat(64)])
    }), /platform_promotion_issuances_approval_binding/u);

    await assertSqlRejected(client, insertIssuanceSql(), issuanceParams(approval, `missing-${SUFFIX}`, {
      promotion_id: IDS.promotion
    }), /platform_promotion_issuances_provider_operation_binding|violates foreign key/u);

    await client.query(insertIssuanceSql(), issuanceParams(approval, operationId, { promotion_id: IDS.promotion }));
    const key = [deploymentId, "production", IDS.promotion];

    await client.query(`UPDATE platform_promotion_issuances
      SET claim_expires_at=clock_timestamp()-interval '1 second'
      WHERE deployment_id=$1 AND environment=$2 AND promotion_id=$3`, key);
    await assertSqlRejected(client, `UPDATE platform_promotion_issuances
      SET state='uncertain',claim_token_digest=NULL,claim_expires_at=NULL,uncertain_reason='provider_response_loss'
      WHERE deployment_id=$1 AND environment=$2 AND promotion_id=$3`, key, /platform_promotion_issuances_claim_clock_fence/u);

    await assertSqlRejected(client, `INSERT INTO platform_deployment_state
      (deployment_id,environment,generation,state,promotion_id)
      VALUES ($1,'production',1,'promoted',$2)`, [deploymentId, IDS.promotion], /platform_deployment_state_committed_issuance_fk/u);

    const expiredApproval = makeApproval({
      approval_id: "33333333-3333-4333-8333-333333333333",
      deployment_id: `${deploymentId}-expired`,
      approved_at: new Date(now - 120_000).toISOString(),
      expires_at: new Date(now - 60_000).toISOString(),
      approval_version: 1
    });
    await insertApproval(client, expiredApproval);
    await assertSqlRejected(client, insertIssuanceSql(), issuanceParams(expiredApproval, operationId, {
      promotion_id: "44444444-4444-4444-8444-444444444444"
    }), /platform_promotion_issuances_approval_clock_fence/u);
  } finally {
    await client.query("ROLLBACK");
  }
});

function makeApproval(overrides) {
  const record = {
    version: 1,
    type: "agentpass.platform-promotion-approval",
    approval_id: overrides.approval_id,
    deployment_id: overrides.deployment_id,
    environment: "production",
    candidate_id: `release-pkg-sha256-v1-${PRODUCT}`,
    source_commit: "b".repeat(40),
    source_tree: "c".repeat(40),
    product_pkg_sha256: PRODUCT,
    image_digest: `sha256:${"d".repeat(64)}`,
    sbom_sha256: "e".repeat(64),
    qualification_report_digests: QUALIFICATION,
    release_manifest_schema_version: 4,
    release_manifest_sha256: "f".repeat(64),
    policy_id: "production-release-v1",
    policy_version: 1,
    approval_version: overrides.approval_version,
    decision: "approved",
    platform_principal_ids: ["platform-operator-a", "platform-operator-b"],
    quorum: { required: 2, satisfied: true },
    authorization_evidence_digests: ["6".repeat(64), "7".repeat(64)],
    approved_at: overrides.approved_at,
    expires_at: overrides.expires_at
  };
  const normalized = normalizePlatformPromotionApprovalRecord(record, {
    now: Date.parse(record.approved_at), allowFuture: false, allowExpired: false
  });
  return Object.freeze({ ...normalized, record_digest: platformPromotionApprovalRecordDigest(normalized, {
    now: Date.parse(record.approved_at), allowFuture: false, allowExpired: false
  }) });
}

async function insertApproval(client, record) {
  await client.query(`INSERT INTO platform_promotion_approvals
    (version,type,approval_id,deployment_id,environment,candidate_id,source_commit,source_tree,
     product_pkg_sha256,image_digest,sbom_sha256,qualification_report_digests,
     release_manifest_schema_version,release_manifest_sha256,policy_id,policy_version,
     approval_version,decision,platform_principal_ids,authorization_evidence_digests,
     approved_at,expires_at)
    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22)`, [
    record.version, record.type, record.approval_id, record.deployment_id, record.environment,
    record.candidate_id, record.source_commit, record.source_tree, record.product_pkg_sha256,
    record.image_digest, record.sbom_sha256, record.qualification_report_digests,
    record.release_manifest_schema_version, record.release_manifest_sha256, record.policy_id,
    record.policy_version, record.approval_version, record.decision, record.platform_principal_ids,
    record.authorization_evidence_digests, record.approved_at, record.expires_at
  ]);
}

async function insertProviderOperation(client, { operationId, expiresAt }) {
  await client.query(`INSERT INTO managed_signer_provider_operations
    (purpose,operation_id,algorithm,bytes_length,request_digest,key_id,key_version,state,
     claim_token_digest,claim_expires_at,expires_at)
    VALUES ('agentpass.promotion-evidence',$1,'ed25519',32,$2,'promotion-key',1,'pending',$3,$4,$5)`, [
    operationId, Buffer.alloc(32, 8), Buffer.alloc(32, 9), new Date(Date.now() + 60_000), expiresAt
  ]);
}

function insertIssuanceSql() {
  return `INSERT INTO platform_promotion_issuances
    (deployment_id,environment,promotion_id,idempotency_key,candidate_id,source_commit,source_tree,
     product_pkg_sha256,release_manifest_sha256,sbom_sha256,image_digest,qualification_report_digests,
     approval_id,approval_digest,signer_key_id,signer_key_version,signer_lifecycle_version,
     expected_deployment_generation,state,claim_token_digest,claim_expires_at,provider_operation_id,authority_digest)
    VALUES ($1,'production',$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,'promotion-key',1,1,0,
      'reserved',$14,clock_timestamp()+interval '60 seconds',$15,$16)`;
}

function issuanceParams(approval, operationId, overrides = {}) {
  return [
    overrides.deployment_id ?? approval.deployment_id,
    overrides.promotion_id,
    `idempotency-${overrides.promotion_id ?? IDS.promotion}`,
    approval.candidate_id, approval.source_commit, approval.source_tree, approval.product_pkg_sha256,
    approval.release_manifest_sha256, approval.sbom_sha256, approval.image_digest,
    overrides.qualification_report_digests ?? JSON.stringify(approval.qualification_report_digests),
    approval.approval_id, approval.record_digest, Buffer.alloc(32, 1), operationId, Buffer.alloc(32, 2)
  ];
}

async function assertSqlRejected(client, text, params, pattern) {
  await client.query("SAVEPOINT promotion_audit_case");
  try {
    await assert.rejects(client.query(text, params), pattern);
  } finally {
    await client.query("ROLLBACK TO SAVEPOINT promotion_audit_case");
    await client.query("RELEASE SAVEPOINT promotion_audit_case");
  }
}
