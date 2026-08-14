import assert from "node:assert/strict";
import test from "node:test";
import { Pool } from "pg";

import {
  normalizePlatformPromotionApprovalRecord,
  platformPromotionApprovalRecordDigest
} from "../../src/platform-promotion-approval-record.mjs";
import { createMigrationRunner } from "../../src/postgres/migration-runner.mjs";

const DATABASE_URL = process.env.AGENTPASS_TEST_DATABASE_URL ?? process.env.AGENTPASS_TEST_POSTGRES_URL;

const RECORD = Object.freeze({
  version: 1,
  type: "agentpass.platform-promotion-approval",
  approval_id: "11111111-1111-4111-8111-111111111111",
  deployment_id: "cloud-prod-2026-08",
  environment: "production",
  candidate_id: `release-pkg-sha256-v1-${"a".repeat(64)}`,
  source_commit: "1".repeat(40),
  source_tree: "2".repeat(40),
  product_pkg_sha256: "a".repeat(64),
  image_digest: `sha256:${"b".repeat(64)}`,
  sbom_sha256: "c".repeat(64),
  qualification_report_digests: ["1".repeat(64), "2".repeat(64)],
  release_manifest_schema_version: 4,
  release_manifest_sha256: "d".repeat(64),
  policy_id: "production-release-v1",
  policy_version: 7,
  approval_version: 1,
  decision: "approved",
  // Mixed case proves the database uses bytewise C ordering like JavaScript,
  // independent of the cluster's locale collation.
  platform_principal_ids: ["Platform-operator-A", "platform-operator-b"],
  quorum: { required: 2, satisfied: true },
  authorization_evidence_digests: ["3".repeat(64), "4".repeat(64)],
  approved_at: "2026-08-15T00:00:00.000Z",
  expires_at: "2026-08-15T01:00:00.000Z"
});

test("0044 PostgreSQL digest is byte-identical to the canonical JavaScript approval record", {
  skip: !DATABASE_URL,
  timeout: 60_000
}, async (t) => {
  const pool = new Pool({ connectionString: DATABASE_URL, max: 1 });
  const client = await pool.connect();
  t.after(async () => { client.release(); await pool.end(); });

  const migrated = await createMigrationRunner({ client, applicationVersion: "platform-approval-parity" }).run();
  assert.equal(migrated.currentVersion, 45);

  const record = normalizePlatformPromotionApprovalRecord(RECORD, {
    now: Date.parse(RECORD.approved_at),
    allowFuture: false,
    allowExpired: false
  });
  const expectedDigest = platformPromotionApprovalRecordDigest(record, {
    now: Date.parse(RECORD.approved_at),
    allowFuture: false,
    allowExpired: false
  });

  await client.query("BEGIN");
  try {
    const inserted = await client.query(`INSERT INTO platform_promotion_approvals
      (version,type,approval_id,deployment_id,environment,candidate_id,source_commit,source_tree,
       product_pkg_sha256,image_digest,sbom_sha256,qualification_report_digests,
       release_manifest_schema_version,release_manifest_sha256,policy_id,policy_version,
       approval_version,decision,platform_principal_ids,authorization_evidence_digests,
       approved_at,expires_at)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22)
      RETURNING record_digest,quorum_required,quorum_satisfied`, [
      record.version,record.type,record.approval_id,record.deployment_id,record.environment,
      record.candidate_id,record.source_commit,record.source_tree,record.product_pkg_sha256,
      record.image_digest,record.sbom_sha256,record.qualification_report_digests,
      record.release_manifest_schema_version,record.release_manifest_sha256,record.policy_id,
      record.policy_version,record.approval_version,record.decision,record.platform_principal_ids,
      record.authorization_evidence_digests,record.approved_at,record.expires_at
    ]);
    assert.deepEqual(inserted.rows[0], {
      record_digest: expectedDigest,
      quorum_required: 2,
      quorum_satisfied: true
    });

    const summary = await client.query("SELECT * FROM platform_promotion_approvals_public WHERE approval_id=$1", [record.approval_id]);
    assert.equal(summary.rowCount, 1);
    assert.equal(summary.rows[0].record_digest, expectedDigest);
    assert.equal(Object.hasOwn(summary.rows[0], "platform_principal_ids"), false);
    assert.equal(Object.hasOwn(summary.rows[0], "authorization_evidence_digests"), false);

    await assert.rejects(
      client.query("UPDATE platform_promotion_approvals SET policy_version=policy_version+1 WHERE approval_id=$1", [record.approval_id]),
      /platform promotion approvals are immutable/u
    );
  } finally {
    await client.query("ROLLBACK");
  }
});
