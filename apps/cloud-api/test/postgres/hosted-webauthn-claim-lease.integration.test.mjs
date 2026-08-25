import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";
import { Pool } from "pg";

import { createMigrationRunner } from "../../src/postgres/migration-runner.mjs";

const databaseUrl = process.env.AGENTPASS_TEST_DATABASE_URL ?? process.env.AGENTPASS_TEST_POSTGRES_URL;
const RP_ID = "console.example.test";
const ORIGIN = "https://console.example.test";
const REDIRECT_URI = `${ORIGIN}/api/auth/bootstrap/github/callback`;
const digest = (value) => crypto.createHash("sha256").update(value).digest();

test("0063 claim lease survives restart, contention, expiry, and response loss in PostgreSQL", {
  skip: !databaseUrl,
  timeout: 120_000
}, async (t) => {
  const pool = new Pool({ connectionString: databaseUrl, max: 8, statement_timeout: 15_000, query_timeout: 20_000 });
  t.after(() => pool.end());
  const migrationClient = await pool.connect();
  try {
    await createMigrationRunner({ client: migrationClient, applicationVersion: "hosted-webauthn-claim-lease-integration" }).run();
  } finally {
    migrationClient.release();
  }

  await t.test("same-response restart and response loss converge to one session", async () => {
    const value = await seed(pool);
    const claimHash = digest("same-response-claim");
    const firstClaim = await claim(pool, value, claimHash);
    assert.equal(firstClaim.rowCount, 1);

    const completion = completionInput(value, claimHash, Number(firstClaim.rows[0].claim_generation));
    const first = await complete(pool, completion);
    assert.equal(first.replayed, false);
    const restartClaim = await claim(pool, value, claimHash);
    assert.equal(restartClaim.rowCount, 1);
    assert.equal(Number(restartClaim.rows[0].claim_generation), completion.claimGeneration);
    const replay = await complete(pool, completion);
    assert.equal(replay.replayed, true);
    assert.equal(replay.session_id, first.session_id);
    assert.equal((await claim(pool, value, claimHash)).rowCount, 0, "one-use recovery must be exhausted");
    assert.equal((await claim(pool, value, digest("changed-response"))).rowCount, 0);

    const evidence = await pool.query(`SELECT
      (SELECT count(*)::int FROM public.webauthn_credentials WHERE id=$1) AS credentials,
      (SELECT count(*)::int FROM public.human_sessions WHERE id=$2) AS sessions,
      (SELECT count(*)::int FROM public.hosted_identity_bootstrap_completions WHERE attempt_id=$3) AS completions`,
    [completion.credentialId, first.session_id, value.attemptId]);
    assert.deepEqual(evidence.rows[0], { credentials: 1, sessions: 1, completions: 1 });
    const events = await pool.query("SELECT event_type,generation FROM public.hosted_identity_bootstrap_webauthn_claim_events WHERE challenge_id=$1 ORDER BY observed_at,event_type", [value.challengeId]);
    assert.deepEqual(events.rows.map((row) => row.event_type).sort(), ["claimed", "completed", "replayed"]);
    assert.ok(events.rows.every((row) => Number(row.generation) === completion.claimGeneration));
  });

  await t.test("two different workers cannot hold the same active lease", async () => {
    const value = await seed(pool);
    const outcomes = await Promise.all([
      claim(pool, value, digest("worker-a")),
      claim(pool, value, digest("worker-b"))
    ]);
    assert.deepEqual(outcomes.map((result) => result.rowCount).sort(), [0, 1]);
    const row = await pool.query("SELECT status,claim_generation FROM public.hosted_identity_bootstrap_webauthn_challenges WHERE id=$1", [value.challengeId]);
    assert.deepEqual(row.rows[0], { status: "consuming", claim_generation: "1" });
  });

  await t.test("expired lease takeover fences the stale verifier and only the holder may fail", async () => {
    const value = await seed(pool);
    const staleHash = digest("stale-worker");
    const replacementHash = staleHash;
    const stale = await claim(pool, value, staleHash);
    assert.equal(stale.rowCount, 1);

    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      await client.query("SET LOCAL ROLE agentpass_migrator");
      await client.query(`UPDATE public.hosted_identity_bootstrap_webauthn_challenges
        SET consume_started_at=clock_timestamp()-interval '60 seconds',
            claim_expires_at=clock_timestamp()-interval '1 second',
            claim_generation=claim_generation+1
        WHERE id=$1`, [value.challengeId]);
      await client.query("COMMIT");
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }

    const replacement = await claim(pool, value, replacementHash);
    assert.equal(replacement.rowCount, 1);
    const replacementGeneration = Number(replacement.rows[0].claim_generation);
    assert.ok(replacementGeneration > Number(stale.rows[0].claim_generation));
    await assert.rejects(
      complete(pool, completionInput(value, staleHash, Number(stale.rows[0].claim_generation))),
      (error) => error.code === "28000"
    );
    await fail(pool, value, staleHash, Number(stale.rows[0].claim_generation));
    assert.equal((await readChallenge(pool, value.challengeId)).status, "consuming");
    await fail(pool, value, replacementHash, replacementGeneration);
    const failed = await readChallenge(pool, value.challengeId);
    assert.equal(failed.status, "failed");
    assert.equal(failed.failure_code, "verification_failed");
    assert.equal(Number(failed.claim_generation), 3);
  });
});

async function seed(pool) {
  const value = {
    memberId: crypto.randomUUID(),
    organizationId: crypto.randomUUID(),
    membershipId: crypto.randomUUID(),
    attemptId: crypto.randomUUID(),
    oauthStateId: crypto.randomUUID(),
    challengeId: crypto.randomUUID(),
    cookieHash: digest(crypto.randomBytes(32)),
    challengeHash: digest(crypto.randomBytes(32))
  };
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await client.query("SET LOCAL ROLE agentpass_migrator");
    await client.query("SET CONSTRAINTS ALL DEFERRED");
    const clock = (await client.query("SELECT clock_timestamp() AS now")).rows[0].now;
    const createdAt = new Date(clock);
    const oauthExpiry = new Date(createdAt.getTime() + 10 * 60_000);
    const attemptExpiry = new Date(createdAt.getTime() + 15 * 60_000);
    const challengeExpiry = new Date(createdAt.getTime() + 5 * 60_000);
    await client.query("INSERT INTO public.members (id,github_subject,display_name) VALUES ($1,NULL,$2)", [value.memberId, "0063 claim member"]);
    await client.query("INSERT INTO public.organizations (id,name) VALUES ($1,$2)", [value.organizationId, `0063 ${value.organizationId}`]);
    await client.query("INSERT INTO public.memberships (organization_id,id,member_id,role,status) VALUES ($1,$2,$3,'owner','active')", [value.organizationId, value.membershipId, value.memberId]);
    await client.query(`INSERT INTO public.hosted_identity_bootstrap_attempts
      (id,oauth_state_id,state,bootstrap_cookie_hash,provider,member_id,organization_id,membership_id,identity_subject_digest,created_at,expires_at,identity_verified_at)
      VALUES ($1,$2,'webauthn_required',$3,'github',$4,$5,$6,$7,$8,$9,$8)`,
    [value.attemptId, value.oauthStateId, value.cookieHash, value.memberId, value.organizationId, value.membershipId, digest(value.memberId), createdAt, attemptExpiry]);
    await client.query(`INSERT INTO public.hosted_identity_oauth_states
      (id,attempt_id,state_hash,code_hash,provider,client_id,redirect_uri,pkce_challenge,pkce_method,status,created_at,expires_at,consume_started_at,consumed_at)
      VALUES ($1,$2,$3,$4,'github','agentpass-0063',$5,$6,'S256','consumed',$7,$8,$7,$7)`,
    [value.oauthStateId, value.attemptId, digest(`state:${value.attemptId}`), digest(`code:${value.attemptId}`), REDIRECT_URI, "A".repeat(43), createdAt, oauthExpiry]);
    await client.query(`INSERT INTO public.hosted_identity_bootstrap_webauthn_challenges
      (id,attempt_id,member_id,organization_id,challenge_hash,operation,rp_id,origin,user_verification,status,created_at,expires_at)
      VALUES ($1,$2,$3,$4,$5,'bootstrap_registration',$6,$7,'required','pending',$8,$9)`,
    [value.challengeId, value.attemptId, value.memberId, value.organizationId, value.challengeHash, RP_ID, ORIGIN, createdAt, challengeExpiry]);
    await client.query("COMMIT");
    return value;
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}

function claim(pool, value, claimHash) {
  return pool.query(
    "SELECT * FROM public.agentpass_hosted_identity_bootstrap_webauthn_claim_v2($1::bytea,$2::uuid,$3::bytea,$4::bytea)",
    [value.cookieHash, value.challengeId, value.challengeHash, claimHash]
  );
}

function completionInput(value, claimHash, claimGeneration) {
  return {
    ...value,
    claimHash,
    claimGeneration,
    requestHash: digest("verified-completion"),
    credentialId: crypto.randomBytes(32),
    publicKey: Buffer.alloc(65, 0x33),
    sessionHash: digest("session-token"),
    csrfHash: digest("csrf-token")
  };
}

async function complete(pool, value) {
  const result = await pool.query(
    "SELECT * FROM public.agentpass_hosted_identity_bootstrap_webauthn_complete_v3($1::uuid,$2::bytea,$3::uuid,$4::bytea,$5::bytea,$6::bigint,$7::bytea,$8::bytea,$9::bytea,$10::bigint,$11::text[],$12::text,$13::boolean,$14::boolean,$15::bytea,$16::bytea)",
    [value.attemptId, value.cookieHash, value.challengeId, value.challengeHash, value.claimHash, value.claimGeneration, value.requestHash, value.credentialId, value.publicKey, 0, ["internal"], "Passkey", false, false, value.sessionHash, value.csrfHash]
  );
  assert.equal(result.rowCount, 1);
  return result.rows[0];
}

async function fail(pool, value, claimHash, claimGeneration) {
  await pool.query(
    "SELECT public.agentpass_hosted_identity_bootstrap_webauthn_fail_v3($1::bytea,$2::uuid,$3::bytea,$4::bytea,$5::bigint,$6::text)",
    [value.cookieHash, value.challengeId, value.challengeHash, claimHash, claimGeneration, "verification_failed"]
  );
}

async function readChallenge(pool, challengeId) {
  const result = await pool.query("SELECT status,failure_code,claim_generation FROM public.hosted_identity_bootstrap_webauthn_challenges WHERE id=$1", [challengeId]);
  assert.equal(result.rowCount, 1);
  return result.rows[0];
}
