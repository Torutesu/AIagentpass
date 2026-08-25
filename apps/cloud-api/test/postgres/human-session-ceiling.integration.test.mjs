import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";
import { Pool } from "pg";

import { createMigrationRunner } from "../../src/postgres/migration-runner.mjs";
import { createPostgresHumanRepository } from "../../src/postgres/human-repository.mjs";

const DATABASE_URL = process.env.AGENTPASS_TEST_DATABASE_URL ?? process.env.AGENTPASS_TEST_POSTGRES_URL;

test("two PostgreSQL-backed API replicas cannot exceed the Human session ceiling", {
  skip: !DATABASE_URL,
  timeout: 60_000
}, async (t) => {
  const firstPool = new Pool({ connectionString: DATABASE_URL, max: 8 });
  const secondPool = new Pool({ connectionString: DATABASE_URL, max: 8 });
  const ids = {
    organization: crypto.randomUUID(),
    member: crypto.randomUUID(),
    membership: crypto.randomUUID()
  };
  t.after(async () => {
    try {
      await firstPool.query("DELETE FROM human_sessions WHERE member_id=$1", [ids.member]);
      await firstPool.query("DELETE FROM memberships WHERE organization_id=$1", [ids.organization]);
      await firstPool.query("DELETE FROM outbox_events WHERE organization_id=$1", [ids.organization]);
      await firstPool.query("DELETE FROM control_plane_authority_generations WHERE organization_id=$1", [ids.organization]);
      await firstPool.query("DELETE FROM admin_audit_heads WHERE organization_id=$1", [ids.organization]);
      await firstPool.query("DELETE FROM members WHERE id=$1", [ids.member]);
      await firstPool.query("DELETE FROM organizations WHERE id=$1", [ids.organization]);
    } finally {
      await Promise.all([firstPool.end(), secondPool.end()]);
    }
  });

  const migrationClient = await firstPool.connect();
  try {
    await createMigrationRunner({ client: migrationClient, applicationVersion: "human-session-ceiling-qualification" }).run();
  } finally {
    migrationClient.release();
  }
  await firstPool.query("INSERT INTO organizations (id,name) VALUES ($1,$2)", [ids.organization, "Session ceiling qualification"]);
  await firstPool.query("INSERT INTO members (id,github_subject,display_name) VALUES ($1,$2,$3)", [ids.member, `session-ceiling-${crypto.randomUUID()}`, "Session ceiling member"]);
  await firstPool.query("INSERT INTO memberships (organization_id,id,member_id,role,status) VALUES ($1,$2,$3,'admin','active')", [ids.organization, ids.membership, ids.member]);

  const repositories = [
    createPostgresHumanRepository({ client: firstPool }),
    createPostgresHumanRepository({ client: secondPool })
  ];
  const issuedAt = new Date().toISOString();
  const sessions = Array.from({ length: 12 }, (_, index) => sessionRecord(ids, issuedAt, index));
  const created = await Promise.all(sessions.map((session, index) => repositories[index % repositories.length].createSessionWithLimit({
    session,
    max_concurrent_sessions: 3,
    issued_at: issuedAt
  })));
  assert.equal(created.length, 12);

  const state = await firstPool.query(`SELECT
      count(*) FILTER (WHERE revoked_at IS NULL)::integer AS active,
      count(*) FILTER (WHERE revoke_reason='concurrent_session_limit')::integer AS ceiling_revoked,
      count(*)::integer AS total
    FROM human_sessions WHERE member_id=$1`, [ids.member]);
  assert.deepEqual(state.rows, [{ active: 3, ceiling_revoked: 9, total: 12 }]);
  const active = await firstPool.query("SELECT id FROM human_sessions WHERE member_id=$1 AND revoked_at IS NULL ORDER BY id", [ids.member]);
  assert.equal(new Set(active.rows.map((row) => row.id)).size, 3);
});

function sessionRecord(ids, issuedAt, index) {
  return {
    session_id: crypto.randomUUID(),
    member_id: ids.member,
    membership_id: ids.membership,
    organization_id: ids.organization,
    role: "admin",
    token_hash: crypto.createHash("sha256").update(`session-token-${index}-${crypto.randomUUID()}`).digest("hex"),
    csrf_token_hash: crypto.createHash("sha256").update(`session-csrf-${index}-${crypto.randomUUID()}`).digest("hex"),
    created_at: issuedAt,
    expires_at: new Date(Date.parse(issuedAt) + 60 * 60_000).toISOString(),
    last_seen_at: issuedAt,
    idle_expires_at: new Date(Date.parse(issuedAt) + 30 * 60_000).toISOString()
  };
}
