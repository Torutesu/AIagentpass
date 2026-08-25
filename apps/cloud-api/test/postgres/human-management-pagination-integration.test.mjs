import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import test from "node:test";

import { createPostgresHumanManagementRepository } from "../../src/human-auth/management/postgres-adapter.mjs";
import { createHumanCursorCodec } from "../../src/human-auth/pagination/cursor-codec.mjs";
import { createPostgresHumanRepository } from "../../src/postgres/human-repository.mjs";
import { createMigrationRunner } from "../../src/postgres/migration-runner.mjs";

const databaseUrl = process.env.AGENTPASS_TEST_DATABASE_URL;

test("Human management cursors traverse real PostgreSQL credentials and sessions without duplicates", { skip: !databaseUrl }, async (t) => {
  const { Pool } = await import("pg");
  const pool = new Pool({ connectionString: databaseUrl, max: 4 });
  t.after(() => pool.end());
  const migrationClient = await pool.connect();
  try { await createMigrationRunner({ client: migrationClient, applicationVersion: "human-management-pagination-integration" }).run(); }
  finally { migrationClient.release(); }

  const organizationId = randomUUID();
  const memberId = randomUUID();
  const membershipId = randomUUID();
  const sessionIds = [randomUUID(), randomUUID(), randomUUID()];
  await pool.query("INSERT INTO organizations (id,name) VALUES ($1,'Human pagination')", [organizationId]);
  await pool.query("INSERT INTO members (id,github_subject,display_name) VALUES ($1,$2,'Pagination member')", [memberId, `pagination-${memberId}`]);
  await pool.query("INSERT INTO memberships (organization_id,id,member_id,role,status) VALUES ($1,$2,$3,'owner','active')", [organizationId, membershipId, memberId]);
  for (let index = 0; index < sessionIds.length; index += 1) {
    await pool.query(`INSERT INTO human_sessions
      (id,member_id,organization_id,membership_id,role,token_hash,csrf_token_hash,created_at,expires_at,last_seen_at,idle_expires_at)
      VALUES ($1,$2,$3,$4,'owner',$5,$6,$7,clock_timestamp()+interval '1 day',$7,clock_timestamp()+interval '1 hour')`, [
      sessionIds[index], memberId, organizationId, membershipId, Buffer.alloc(32, 110 + index), Buffer.alloc(32, 120 + index), new Date(Date.UTC(2026, 7, 12, 0, 0, index)).toISOString()
    ]);
  }
  const credentialIds = [Buffer.alloc(16, 31), Buffer.alloc(16, 32), Buffer.alloc(16, 33)];
  for (let index = 0; index < credentialIds.length; index += 1) {
    await pool.query(`INSERT INTO webauthn_credentials
      (id,member_id,public_key,transports,label,backup_eligible,backup_state,created_at)
      VALUES ($1,$2,$3,ARRAY['internal']::text[],$4,false,false,$5)`, [
      credentialIds[index], memberId, Buffer.alloc(32, 140 + index), `Credential ${index + 1}`, new Date(Date.UTC(2026, 7, 12, 0, 1, index)).toISOString()
    ]);
  }

  const repository = createPostgresHumanRepository({ client: pool });
  const cursorCodec = createHumanCursorCodec({ secret: Buffer.alloc(32, 0x55) });
  const management = createPostgresHumanManagementRepository({ repository, cursorCodec, now: () => Date.now() });
  const scope = { session_id: sessionIds[0], member_id: memberId, organization_id: organizationId };

  const firstSessions = await management.listSessions({ ...scope, limit: 2 });
  const secondSessions = await management.listSessions({ ...scope, limit: 2, cursor: firstSessions.next_cursor });
  assert.equal(firstSessions.items.length, 2);
  assert.equal(secondSessions.items.length, 1);
  assert.equal(secondSessions.next_cursor, null);
  assert.equal(new Set([...firstSessions.items, ...secondSessions.items].map((item) => item.session_id)).size, 3);

  const firstCredentials = await management.listCredentials({ ...scope, limit: 2 });
  const secondCredentials = await management.listCredentials({ ...scope, limit: 2, cursor: firstCredentials.next_cursor });
  assert.equal(firstCredentials.items.length, 2);
  assert.equal(secondCredentials.items.length, 1);
  assert.equal(secondCredentials.next_cursor, null);
  assert.equal(new Set([...firstCredentials.items, ...secondCredentials.items].map((item) => item.id)).size, 3);
  assert.equal(JSON.stringify([...firstCredentials.items, ...secondCredentials.items]).includes("public_key"), false);
  assert.equal(JSON.stringify([...firstSessions.items, ...secondSessions.items]).includes("token_hash"), false);

  const tampered = `${firstCredentials.next_cursor.slice(0, -1)}${firstCredentials.next_cursor.endsWith("A") ? "B" : "A"}`;
  await assert.rejects(management.listCredentials({ ...scope, limit: 2, cursor: tampered }), { code: "human_cursor_invalid" });
});
