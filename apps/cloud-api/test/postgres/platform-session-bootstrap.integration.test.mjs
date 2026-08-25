import { POSTGRES_SCHEMA_HEAD } from "../../src/postgres/schema-head.mjs";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import { createMigrationRunner } from "../../src/postgres/migration-runner.mjs";

const DATABASE_URL = process.env.AGENTPASS_TEST_DATABASE_URL ?? process.env.AGENTPASS_TEST_POSTGRES_URL;
const { Pool } = DATABASE_URL ? await import("pg") : { Pool: undefined };
const OPERATION = "platform.promotion.issue";

function uuid() { return crypto.randomUUID(); }
function digest(value) { return crypto.createHash("sha256").update(value, "utf8").digest(); }
function callSql() {
  return `SELECT * FROM public.agentpass_platform_session_bootstrap_context(
    $1::bytea, $2::uuid, $3::text, $4::text
  )`;
}

test("0055 real PostgreSQL resolves bootstrap authority only from the human session digest", {
  skip: DATABASE_URL ? false : "set AGENTPASS_TEST_DATABASE_URL to run the real PostgreSQL lane",
  timeout: 60_000,
}, async (t) => {
  const pool = new Pool({ connectionString: DATABASE_URL, max: 3 });
  t.after(() => pool.end());

  const migrationClient = await pool.connect();
  try {
    const migrated = await createMigrationRunner({
      client: migrationClient,
      applicationVersion: "platform-session-bootstrap-0055",
    }).run();
    assert.equal(migrated.currentVersion, POSTGRES_SCHEMA_HEAD.version);
  } finally {
    migrationClient.release();
  }

  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const suffix = uuid().replaceAll("-", "");
    const organizationId = uuid();
    const memberId = uuid();
    const membershipId = uuid();
    const humanSessionId = uuid();
    const principalId = uuid();
    const assignmentId = uuid();
    const webauthnIdA = Buffer.alloc(32, 0x20);
    const webauthnIdB = Buffer.alloc(32, 0x10);
    const humanTokenHash = Buffer.alloc(32, 0x31);

    await client.query("INSERT INTO organizations (id,name) VALUES ($1,$2)", [organizationId, `0055 ${suffix}`]);
    await client.query(
      "INSERT INTO members (id,github_subject,display_name) VALUES ($1,$2,$3)",
      [memberId, `0055:${suffix}`, "Bootstrap test member"],
    );
    await client.query(
      `INSERT INTO memberships (organization_id,id,member_id,role,status)
       VALUES ($1,$2,$3,'owner','active')`,
      [organizationId, membershipId, memberId],
    );
    await client.query(
      `INSERT INTO human_sessions
       (id,member_id,token_hash,created_at,expires_at,organization_id,membership_id,role,
        csrf_token_hash,last_seen_at,idle_expires_at)
       VALUES ($1,$2,$3,clock_timestamp()-interval '1 second',clock_timestamp()+interval '10 minutes',
               $4,$5,'owner',$6,clock_timestamp(),clock_timestamp()+interval '5 minutes')`,
      [humanSessionId, memberId, humanTokenHash, organizationId, membershipId, Buffer.alloc(32, 0x33)],
    );
    await client.query(
      "INSERT INTO webauthn_credentials (id,member_id,public_key,sign_count,transports,label,backup_eligible,backup_state) VALUES ($1,$2,$3,0,ARRAY['internal']::text[],'0055 A',false,false)",
      [webauthnIdA, memberId, Buffer.alloc(32, 0x41)],
    );
    await client.query(
      "INSERT INTO webauthn_credentials (id,member_id,public_key,sign_count,transports,label,backup_eligible,backup_state) VALUES ($1,$2,$3,0,ARRAY['internal']::text[],'0055 B',false,false)",
      [webauthnIdB, memberId, Buffer.alloc(32, 0x42)],
    );
    await client.query(
      "INSERT INTO platform_principals (principal_id,member_id,status) VALUES ($1,$2,'active')",
      [principalId, memberId],
    );
    await client.query(
      `INSERT INTO platform_operator_assignments
       (assignment_id,principal_id,member_id,organization_id,operation,capability,status,
        request_digest,requested_authority_generation,requested_at,issued_at,expires_at,activated_at)
       VALUES ($1,$2,$3,$4,$5,$5,'active',$6,1,clock_timestamp(),clock_timestamp(),
               clock_timestamp()+interval '10 minutes',clock_timestamp())`,
      [assignmentId, principalId, memberId, organizationId, OPERATION, digest(`assignment:${suffix}`)],
    );
    await client.query(
      `INSERT INTO platform_credentials
       (credential_id,principal_id,member_id,webauthn_credential_id,label,status,backup_eligible,backup_state)
       VALUES ($1,$2,$3,$4,'0055 A','active',false,false)`,
      [uuid(), principalId, memberId, webauthnIdA],
    );
    await client.query(
      `INSERT INTO platform_credentials
       (credential_id,principal_id,member_id,webauthn_credential_id,label,status,backup_eligible,backup_state)
       VALUES ($1,$2,$3,$4,'0055 B','active',false,false)`,
      [uuid(), principalId, memberId, webauthnIdB],
    );

    const valid = (await client.query(callSql(), [humanTokenHash, organizationId, OPERATION, OPERATION])).rows;
    assert.equal(valid.length, 1);
    const context = valid[0];
    assert.equal(context.human_session_id, humanSessionId);
    assert.equal(context.organization_id, organizationId);
    assert.equal(context.member_id, memberId);
    assert.equal(context.membership_id, membershipId);
    assert.equal(context.role, "owner");
    assert.equal(context.organization_authority_epoch, "1");
    assert.equal(context.membership_session_epoch, "1");
    assert.equal(context.assignment_id, assignmentId);
    assert.equal(context.principal_id, principalId);
    assert.equal(context.principal_authority_generation, "1");
    assert.equal(context.operation, OPERATION);
    assert.equal(context.capability, OPERATION);
    assert.deepEqual(
      context.allowed_webauthn_credential_ids.map((item) => item.toString("hex")),
      [webauthnIdB, webauthnIdA].map((item) => item.toString("hex")),
    );
    assert.equal(Array.isArray(context.platform_credentials), true);
    assert.equal(context.platform_credentials.length, 2);
    assert.equal(Object.hasOwn(context, "token_hash"), false);
    assert.equal(Object.hasOwn(context, "csrf_token_hash"), false);

    // Assignment selection is durable/member-scoped, while the validated
    // Human session remains a separate returned context field.
    const wrongScope = (await client.query(callSql(), [humanTokenHash, organizationId, "platform.promotion.verify", "platform.promotion.verify"])).rows;
    assert.equal(wrongScope.length, 0);

    await client.query("UPDATE human_sessions SET revoked_at=clock_timestamp() WHERE id=$1", [humanSessionId]);
    const revoked = (await client.query(callSql(), [humanTokenHash, organizationId, OPERATION, OPERATION])).rows;
    assert.equal(revoked.length, 0);

    await client.query("ROLLBACK");
  } catch (error) {
    try { await client.query("ROLLBACK"); } catch { /* preserve original */ }
    throw error;
  } finally {
    client.release();
  }
});
