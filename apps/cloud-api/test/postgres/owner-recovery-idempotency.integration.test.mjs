import assert from "node:assert/strict";
import test from "node:test";
import { Pool } from "pg";

import { createMigrationRunner } from "../../src/postgres/migration-runner.mjs";
import {
  OwnerRecoveryRepositoryError,
  createPostgresOwnerRecoveryRepository
} from "../../src/postgres/owner-recovery-repository.mjs";

const databaseUrl = process.env.AGENTPASS_TEST_DATABASE_URL;
const ORG = "10000000-0000-4000-8000-000000000001";
const SUBJECT = "20000000-0000-4000-8000-000000000001";
const OWNER_A = "20000000-0000-4000-8000-000000000002";
const OWNER_B = "20000000-0000-4000-8000-000000000003";
const MEMBERSHIP = "30000000-0000-4000-8000-000000000001";
const SESSION = "40000000-0000-4000-8000-000000000001";
const REQUEST_A = "50000000-0000-4000-8000-000000000001";
const REQUEST_B = "50000000-0000-4000-8000-000000000002";
const NOW = new Date("2026-08-14T00:00:00.000Z");

test("owner recovery create is concurrently replay-safe and rolls idempotency back with its outbox", { skip: !databaseUrl }, async (t) => {
  const pool = new Pool({ connectionString: databaseUrl, max: 8 });
  t.after(() => pool.end());
  const migrationClient = await pool.connect();
  try { await createMigrationRunner({ client: migrationClient, applicationVersion: "owner-recovery-idempotency-integration" }).run(); }
  finally { migrationClient.release(); }

  await pool.query("INSERT INTO organizations (id,name) VALUES ($1,'Recovery integration')", [ORG]);
  await pool.query(`INSERT INTO members (id,github_subject,display_name) VALUES
    ($1,'recovery-subject','Subject'),($2,'recovery-owner-a','Owner A'),($3,'recovery-owner-b','Owner B')`, [SUBJECT, OWNER_A, OWNER_B]);
  await pool.query(`INSERT INTO memberships (organization_id,id,member_id,role,status) VALUES
    ($1,$2,$3,'owner','active'),
    ($1,'30000000-0000-4000-8000-000000000002',$4,'owner','active'),
    ($1,'30000000-0000-4000-8000-000000000003',$5,'owner','active')`, [ORG, MEMBERSHIP, SUBJECT, OWNER_A, OWNER_B]);
  await pool.query(`INSERT INTO human_sessions
    (id,member_id,organization_id,membership_id,role,token_hash,csrf_token_hash,created_at,expires_at,idle_expires_at,last_seen_at)
    VALUES ($1,$2,$3,$4,'owner',$5,$6,$7,$8,$8,$7)`, [SESSION, SUBJECT, ORG, MEMBERSHIP, Buffer.alloc(32, 1), Buffer.alloc(32, 2), NOW, new Date("2026-08-15T00:00:00.000Z")]);

  const repository = createPostgresOwnerRecoveryRepository({ client: pool, clock: () => NOW });
  const base = {
    organization_id: ORG,
    subject_member_id: SUBJECT,
    creator_member_id: SUBJECT,
    creator_session_id: SESSION,
    threshold: 2,
    idempotency_key: "concurrent-owner-recovery-create"
  };
  const [left, right] = await Promise.all([
    repository.createRecoveryRequest({ ...base, request_id: REQUEST_A }),
    repository.createRecoveryRequest({ ...base, request_id: REQUEST_B })
  ]);
  assert.equal(left.request.request_id, right.request.request_id);
  assert.equal([left, right].filter((value) => value.replayed).length, 1);
  const counts = await pool.query(`SELECT
    (SELECT count(*)::int FROM owner_recovery_requests WHERE organization_id=$1) AS requests,
    (SELECT count(*)::int FROM owner_recovery_outbox WHERE organization_id=$1) AS outbox,
    (SELECT count(*)::int FROM owner_recovery_idempotency_records WHERE organization_id=$1) AS idempotency`, [ORG]);
  assert.deepEqual(counts.rows[0], { requests: 1, outbox: 1, idempotency: 1 });

  await assert.rejects(
    repository.createRecoveryRequest({ ...base, request_id: REQUEST_B, threshold: 3 }),
    (error) => error instanceof OwnerRecoveryRepositoryError && error.code === "idempotency_conflict"
  );

  await pool.query("DELETE FROM owner_recovery_outbox WHERE organization_id=$1", [ORG]);
  await pool.query("DELETE FROM owner_recovery_idempotency_records WHERE organization_id=$1", [ORG]);
  await pool.query("DELETE FROM owner_recovery_requests WHERE organization_id=$1", [ORG]);
  const failingClient = {
    query: (text, params) => pool.query(text, params),
    async connect() {
      const client = await pool.connect();
      return {
        release: (...args) => client.release(...args),
        query(text, params) {
          if (/INSERT INTO owner_recovery_outbox/u.test(text)) throw new Error("injected outbox failure");
          return client.query(text, params);
        }
      };
    }
  };
  const failing = createPostgresOwnerRecoveryRepository({ client: failingClient, clock: () => NOW });
  await assert.rejects(
    failing.createRecoveryRequest({ ...base, request_id: REQUEST_A, idempotency_key: "rollback-owner-recovery-create" }),
    (error) => error instanceof OwnerRecoveryRepositoryError && error.code === "unavailable"
  );
  const rolledBack = await pool.query(`SELECT
    (SELECT count(*)::int FROM owner_recovery_requests WHERE organization_id=$1) AS requests,
    (SELECT count(*)::int FROM owner_recovery_idempotency_records WHERE organization_id=$1) AS idempotency`, [ORG]);
  assert.deepEqual(rolledBack.rows[0], { requests: 0, idempotency: 0 });
});
