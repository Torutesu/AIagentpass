import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";
import { Pool } from "pg";

import { createMigrationRunner } from "../../src/postgres/migration-runner.mjs";
import { createPostgresHumanRepository } from "../../src/postgres/human-repository.mjs";
import { createPostgresOwnerRecoveryOutboxRetentionRepository } from "../../src/postgres/owner-recovery-outbox-retention-repository.mjs";

const DATABASE_URL = process.env.AGENTPASS_TEST_DATABASE_URL ?? process.env.AGENTPASS_TEST_POSTGRES_URL;

test("real PostgreSQL prunes bounded terminal recovery rows into an immutable secret-free ledger", {
  skip: !DATABASE_URL,
  timeout: 60_000
}, async (t) => {
  const pool = new Pool({ connectionString: DATABASE_URL, max: 8 });
  const fixture = await createFixture();
  t.after(async () => {
    try { await cleanup(pool, fixture); }
    finally { await pool.end(); }
  });

  const migrationClient = await pool.connect();
  try {
    const result = await createMigrationRunner({ client: migrationClient, applicationVersion: "owner-recovery-retention-qualification" }).run();
    assert.equal(result.currentVersion, 33);
  } finally {
    migrationClient.release();
  }
  await seed(pool, fixture);

  const metrics = [];
  const repository = createPostgresOwnerRecoveryOutboxRetentionRepository({
    client: pool,
    metrics: { recordOwnerRecoveryOutboxPrune(value) { metrics.push(value); } }
  });
  const first = await repository.prune({ limit: 2 });
  assert.equal(first.total, 2);
  assert.equal(first.published + first.dead_letter + first.suppressed, 2);
  const second = await repository.prune({ limit: 10 });
  assert.deepEqual({
    published: first.published + second.published,
    dead_letter: first.dead_letter + second.dead_letter,
    suppressed: first.suppressed + second.suppressed,
    total: first.total + second.total
  }, { published: 1, dead_letter: 1, suppressed: 1, total: 3 });
  assert.deepEqual(metrics, [2, 1]);

  const live = await pool.query("SELECT status,count(*)::integer AS count FROM owner_recovery_outbox WHERE organization_id=$1 GROUP BY status ORDER BY status", [fixture.organization]);
  assert.deepEqual(live.rows, [
    { status: "dead_letter", count: 1 },
    { status: "published", count: 1 },
    { status: "suppressed", count: 1 }
  ]);
  const ledger = await pool.query(`SELECT terminal_status,count(*)::integer AS count,
      bool_and(terminal_at<=pruned_at) AS ordered,
      bool_and(redrive_count BETWEEN 0 AND 3) AS bounded_redrive
    FROM owner_recovery_outbox_retention_ledger
    WHERE organization_id=$1 GROUP BY terminal_status ORDER BY terminal_status`, [fixture.organization]);
  assert.deepEqual(ledger.rows, [
    { terminal_status: "dead_letter", count: 1, ordered: true, bounded_redrive: true },
    { terminal_status: "published", count: 1, ordered: true, bounded_redrive: true },
    { terminal_status: "suppressed", count: 1, ordered: true, bounded_redrive: true }
  ]);
  const columns = await pool.query(`SELECT column_name FROM information_schema.columns
    WHERE table_schema='public' AND table_name='owner_recovery_outbox_retention_ledger'
    ORDER BY column_name`);
  const columnNames = columns.rows.map((row) => row.column_name);
  for (const forbidden of ["suppression_reason", "claim_token_digest", "destination", "provider_response", "authorization", "credential"]) {
    assert.equal(columnNames.includes(forbidden), false);
  }
  await assert.rejects(
    () => pool.query("UPDATE owner_recovery_outbox_retention_ledger SET total_attempts=total_attempts+1 WHERE organization_id=$1", [fixture.organization]),
    (error) => error.code === "23514" && error.constraint === "owner_recovery_outbox_retention_ledger_immutable"
  );
  await assert.rejects(
    () => pool.query("DELETE FROM owner_recovery_outbox_retention_ledger WHERE organization_id=$1", [fixture.organization]),
    (error) => error.code === "23514" && error.constraint === "owner_recovery_outbox_retention_ledger_immutable"
  );
});

async function createFixture() {
  return {
    organization: crypto.randomUUID(),
    member: crypto.randomUUID(),
    membership: crypto.randomUUID(),
    session: crypto.randomUUID(),
    rows: Array.from({ length: 6 }, (_, index) => ({ request: crypto.randomUUID(), event: crypto.randomUUID(), index }))
  };
}

async function seed(pool, fixture) {
  await pool.query("INSERT INTO organizations (id,name) VALUES ($1,$2)", [fixture.organization, "Retention qualification"]);
  await pool.query("INSERT INTO members (id,github_subject,display_name) VALUES ($1,$2,$3)", [fixture.member, `retention-${crypto.randomUUID()}`, "Retention member"]);
  await pool.query("INSERT INTO memberships (organization_id,id,member_id,role,status) VALUES ($1,$2,$3,'admin','active')", [fixture.organization, fixture.membership, fixture.member]);
  const issuedAt = new Date().toISOString();
  await createPostgresHumanRepository({ client: pool }).createSession({
    session_id: fixture.session,
    member_id: fixture.member,
    membership_id: fixture.membership,
    organization_id: fixture.organization,
    role: "admin",
    token_hash: crypto.createHash("sha256").update(crypto.randomUUID()).digest("hex"),
    csrf_token_hash: crypto.createHash("sha256").update(crypto.randomUUID()).digest("hex"),
    created_at: issuedAt,
    expires_at: new Date(Date.parse(issuedAt) + 60 * 60_000).toISOString(),
    last_seen_at: issuedAt,
    idle_expires_at: new Date(Date.parse(issuedAt) + 30 * 60_000).toISOString()
  });
  const old = "2020-01-01T00:00:00.000Z";
  const recent = issuedAt;
  for (const row of fixture.rows) {
    await pool.query(`INSERT INTO owner_recovery_requests
      (organization_id,request_id,schema_version,kind,subject_member_id,creator_member_id,creator_session_id,state,threshold,expires_at,terminal_reason,created_at,updated_at)
      VALUES ($1,$2,1,'threshold-owner-recovery',$3,$3,$4,'failed',2,$5,'qualification',$6,$6)`, [
      fixture.organization, row.request, fixture.member, fixture.session,
      new Date(Date.parse(issuedAt) + 24 * 60 * 60_000).toISOString(), old
    ]);
    const status = ["published", "dead_letter", "suppressed"][row.index % 3];
    const terminalAt = row.index < 3 ? old : recent;
    await pool.query(`INSERT INTO owner_recovery_outbox
      (organization_id,event_id,request_id,subject_member_id,event_type,status,attempts,available_at,published_at,created_at,updated_at,
       claim_token_digest,claim_expires_at,last_error_code,management_version,redrive_count,total_attempts,suppressed_at,suppression_reason)
      VALUES ($1,$2,$3,$4,'recovery.failed',$5,$6,$7,$8,$7,$7,NULL,NULL,$9,1,0,$6,$10,$11)`, [
      fixture.organization, row.event, row.request, fixture.member, status,
      status === "published" ? 1 : 100, terminalAt,
      status === "published" ? terminalAt : null,
      status === "dead_letter" ? "publisher_rejected" : null,
      status === "suppressed" ? terminalAt : null,
      status === "suppressed" ? "operator-confirmed" : null
    ]);
  }
}

async function cleanup(pool, fixture) {
  await pool.query("DELETE FROM owner_recovery_outbox WHERE organization_id=$1", [fixture.organization]);
  await pool.query("DELETE FROM owner_recovery_requests WHERE organization_id=$1", [fixture.organization]);
  await pool.query("DELETE FROM human_sessions WHERE organization_id=$1", [fixture.organization]);
  await pool.query("DELETE FROM memberships WHERE organization_id=$1", [fixture.organization]);
  await pool.query("DELETE FROM outbox_events WHERE organization_id=$1", [fixture.organization]);
  await pool.query("DELETE FROM control_plane_authority_generations WHERE organization_id=$1", [fixture.organization]);
  await pool.query("DELETE FROM admin_audit_heads WHERE organization_id=$1", [fixture.organization]);
  await pool.query("DELETE FROM organizations WHERE id=$1", [fixture.organization]);
  await pool.query("DELETE FROM members WHERE id=$1", [fixture.member]);
}
