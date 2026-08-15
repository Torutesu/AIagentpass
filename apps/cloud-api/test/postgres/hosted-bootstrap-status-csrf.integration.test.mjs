import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";
import { Pool } from "pg";

import { createMigrationRunner } from "../../src/postgres/migration-runner.mjs";

const databaseUrl = process.env.AGENTPASS_TEST_DATABASE_URL ?? process.env.AGENTPASS_TEST_POSTGRES_URL;
const digest = (value) => crypto.createHash("sha256").update(value).digest();

test("0064 status and CSRF authority converge under PostgreSQL clock and contention", {
  skip: !databaseUrl,
  timeout: 120_000
}, async (t) => {
  const pool = new Pool({ connectionString: databaseUrl, max: 6, statement_timeout: 15_000, query_timeout: 20_000 });
  t.after(() => pool.end());
  const migrationClient = await pool.connect();
  try {
    await createMigrationRunner({ client: migrationClient, applicationVersion: "hosted-bootstrap-status-csrf-integration" }).run();
  } finally {
    migrationClient.release();
  }

  await t.test("same deterministic CSRF survives restart and a changed digest is denied", async () => {
    const value = await seed(pool, { state: "organization_required" });
    const csrfHash = digest("0064 deterministic csrf");
    const [first, concurrent] = await Promise.all([
      status(pool, value.cookieHash, csrfHash),
      status(pool, value.cookieHash, csrfHash)
    ]);
    assert.equal(first.rowCount, 1);
    assert.deepEqual(first.rows[0], {
      state: "organization_required",
      organization_count: "0",
      webauthn_required: false,
      can_create_first_organization: true,
      expires_at: first.rows[0].expires_at
    });
    assert.deepEqual(concurrent.rows[0], first.rows[0]);
    assert.equal((await verify(pool, value.cookieHash, csrfHash)), true);
    assert.equal((await verify(pool, value.cookieHash, digest("wrong csrf"))), false);
    assert.equal((await status(pool, value.cookieHash, digest("replacement csrf"))).rowCount, 0);
    const stored = await pool.query("SELECT encode(csrf_token_hash,'hex') AS csrf_hash FROM public.hosted_identity_bootstrap_attempts WHERE id=$1", [value.attemptId]);
    assert.equal(stored.rows[0].csrf_hash, csrfHash.toString("hex"));
  });

  await t.test("database expiry advances no_membership and returns a terminal non-CSRF status", async () => {
    const value = await seed(pool, { state: "no_membership", expired: true });
    const csrfHash = digest("0064 expired csrf");
    const result = await status(pool, value.cookieHash, csrfHash);
    assert.equal(result.rowCount, 1);
    assert.equal(result.rows[0].state, "expired");
    assert.equal(result.rows[0].organization_count, "0");
    assert.equal(result.rows[0].webauthn_required, false);
    assert.equal(result.rows[0].can_create_first_organization, false);
    assert.equal((await verify(pool, value.cookieHash, csrfHash)), false);
    const stored = await pool.query("SELECT state,csrf_token_hash,failure_code FROM public.hosted_identity_bootstrap_attempts WHERE id=$1", [value.attemptId]);
    assert.deepEqual(stored.rows[0], { state: "expired", csrf_token_hash: null, failure_code: "bootstrap_expired" });
  });

  await t.test("completed status is observable but cannot install or verify CSRF", async () => {
    const value = await seed(pool, { state: "completed", withOrganization: true });
    const csrfHash = digest("0064 completed csrf");
    const result = await status(pool, value.cookieHash, csrfHash);
    assert.equal(result.rowCount, 1);
    assert.equal(result.rows[0].state, "completed");
    assert.equal(result.rows[0].organization_count, "1");
    assert.equal(result.rows[0].webauthn_required, false);
    assert.equal(result.rows[0].can_create_first_organization, false);
    assert.equal((await verify(pool, value.cookieHash, csrfHash)), false);
    const stored = await pool.query("SELECT csrf_token_hash FROM public.hosted_identity_bootstrap_attempts WHERE id=$1", [value.attemptId]);
    assert.equal(stored.rows[0].csrf_token_hash, null);
  });
});

async function seed(pool, { state, expired = false, withOrganization = false }) {
  const value = {
    memberId: crypto.randomUUID(),
    organizationId: withOrganization ? crypto.randomUUID() : null,
    membershipId: withOrganization ? crypto.randomUUID() : null,
    attemptId: crypto.randomUUID(),
    oauthStateId: crypto.randomUUID(),
    cookieHash: digest(crypto.randomBytes(32))
  };
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await client.query("SET LOCAL ROLE agentpass_migrator");
    const now = (await client.query("SELECT clock_timestamp() AS now")).rows[0].now;
    const createdAt = new Date(now.getTime() - (expired ? 20 * 60_000 : 1_000));
    const expiresAt = new Date(createdAt.getTime() + 15 * 60_000);
    await client.query("INSERT INTO public.members (id,github_subject,display_name) VALUES ($1,NULL,$2)", [value.memberId, "0064 status member"]);
    if (withOrganization) {
      await client.query("INSERT INTO public.organizations (id,name) VALUES ($1,$2)", [value.organizationId, `0064 ${value.organizationId}`]);
      await client.query("INSERT INTO public.memberships (organization_id,id,member_id,role,status) VALUES ($1,$2,$3,'owner','active')", [value.organizationId, value.membershipId, value.memberId]);
    }
    await client.query(`INSERT INTO public.hosted_identity_bootstrap_attempts
      (id,oauth_state_id,state,bootstrap_cookie_hash,provider,member_id,organization_id,membership_id,identity_subject_digest,created_at,expires_at,identity_verified_at,completed_at)
      VALUES ($1,$2,$3,$4,'github',$5,$6,$7,$8,$9,$10,$9,$11)`, [
      value.attemptId,
      value.oauthStateId,
      state,
      value.cookieHash,
      value.memberId,
      value.organizationId,
      value.membershipId,
      digest(value.memberId),
      createdAt,
      expiresAt,
      state === "completed" ? new Date(createdAt.getTime() + 1_000) : null
    ]);
    await client.query("COMMIT");
    return value;
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}

function status(pool, cookieHash, csrfHash) {
  return pool.query(
    "SELECT * FROM public.agentpass_hosted_identity_bootstrap_status_v2($1::bytea,$2::bytea)",
    [cookieHash, csrfHash]
  );
}

async function verify(pool, cookieHash, csrfHash) {
  const result = await pool.query(
    "SELECT public.agentpass_hosted_identity_bootstrap_csrf_verify_v2($1::bytea,$2::bytea) AS valid",
    [cookieHash, csrfHash]
  );
  assert.equal(result.rowCount, 1);
  return result.rows[0].valid;
}
