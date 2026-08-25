import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";
import { Pool } from "pg";

import { createMigrationRunner } from "../../src/postgres/migration-runner.mjs";

const databaseUrl = process.env.AGENTPASS_TEST_DATABASE_URL;
const REDIRECT = "https://console.example.test/api/auth/bootstrap/github/callback";

const digest = (value) => crypto.createHash("sha256").update(value, "utf8").digest();

async function consumingAttempt(pool) {
  const attemptId = crypto.randomUUID();
  const oauthStateId = crypto.randomUUID();
  const state = crypto.randomBytes(32).toString("base64url");
  const code = crypto.randomBytes(32).toString("base64url");
  const envelopeExpiry = new Date(Date.now() + 5 * 60_000).toISOString();
  await pool.query(
    "SELECT * FROM public.agentpass_hosted_identity_bootstrap_start_v2($1::uuid,$2::uuid,$3::bytea,$4::text,$5::text,$6::text,$7::text,$8::bytea,$9::bytea,$10::bytea,$11::timestamptz)",
    [attemptId, oauthStateId, digest(state), "A".repeat(43), "github-client", REDIRECT, "pkce-integration-v1", Buffer.alloc(12, 1), Buffer.alloc(43, 2), Buffer.alloc(16, 3), envelopeExpiry]
  );
  const claimed = await pool.query(
    "SELECT * FROM public.agentpass_hosted_identity_oauth_state_claim_v2($1::uuid,$2::bytea,$3::bytea,$4::text)",
    [oauthStateId, digest(state), digest(code), REDIRECT]
  );
  assert.equal(claimed.rowCount, 1);
  return { attemptId, oauthStateId };
}

async function complete(pool, attempt, { candidateMemberId = crypto.randomUUID(), subject, cookie = crypto.randomBytes(32).toString("base64url") } = {}) {
  const result = await pool.query(
    "SELECT * FROM public.agentpass_hosted_identity_oauth_complete_v2($1::uuid,$2::uuid,$3::bytea,$4::uuid,$5::text,$6::text,$7::bytea)",
    [attempt.oauthStateId, attempt.attemptId, digest(cookie), candidateMemberId, "github", subject, digest(subject)]
  );
  assert.equal(result.rowCount, 1);
  return { candidateMemberId, row: result.rows[0] };
}

test("0059 converges same-subject completion and classifies complete membership history", {
  skip: !databaseUrl,
  timeout: 120_000
}, async (t) => {
  const pool = new Pool({ connectionString: databaseUrl, max: 8, statement_timeout: 15_000, query_timeout: 20_000 });
  t.after(() => pool.end());
  const migrationClient = await pool.connect();
  try { await createMigrationRunner({ client: migrationClient, applicationVersion: "hosted-identity-atomic-completion-integration" }).run(); }
  finally { migrationClient.release(); }

  const sharedSubject = `8${crypto.randomBytes(8).readBigUInt64BE().toString().slice(0, 18)}`;
  const [firstAttempt, secondAttempt] = await Promise.all([consumingAttempt(pool), consumingAttempt(pool)]);
  const candidates = [crypto.randomUUID(), crypto.randomUUID()];
  const completed = await Promise.all([
    complete(pool, firstAttempt, { candidateMemberId: candidates[0], subject: sharedSubject }),
    complete(pool, secondAttempt, { candidateMemberId: candidates[1], subject: sharedSubject })
  ]);
  assert.deepEqual(completed.map(({ row }) => row.state), ["organization_required", "organization_required"]);
  assert.deepEqual(completed.map(({ row }) => Number(row.organization_count)), [0, 0]);

  const mapping = await pool.query("SELECT member_id FROM public.upstream_identities WHERE provider='github' AND subject=$1", [sharedSubject]);
  assert.equal(mapping.rowCount, 1);
  const mappedMemberId = mapping.rows[0].member_id;
  assert.ok(candidates.includes(mappedMemberId));
  const candidatesStored = await pool.query("SELECT id FROM public.members WHERE id = ANY($1::uuid[]) ORDER BY id", [candidates]);
  assert.equal(candidatesStored.rowCount, 1, "same-subject contention must not leave an orphan member");
  const attempts = await pool.query("SELECT state,member_id FROM public.hosted_identity_bootstrap_attempts WHERE id = ANY($1::uuid[]) ORDER BY id", [[firstAttempt.attemptId, secondAttempt.attemptId]]);
  assert.equal(attempts.rowCount, 2);
  assert.ok(attempts.rows.every((row) => row.state === "organization_required" && row.member_id === mappedMemberId));

  const activeMemberId = crypto.randomUUID();
  const activeSubject = `7${crypto.randomBytes(8).readBigUInt64BE().toString().slice(0, 18)}`;
  const activeOrganizationId = crypto.randomUUID();
  await pool.query("INSERT INTO public.members (id,github_subject) VALUES ($1,NULL)", [activeMemberId]);
  await pool.query("INSERT INTO public.upstream_identities (provider,subject,member_id) VALUES ('github',$1,$2)", [activeSubject, activeMemberId]);
  await pool.query("INSERT INTO public.organizations (id,name) VALUES ($1,'Hosted active integration')", [activeOrganizationId]);
  await pool.query("INSERT INTO public.memberships (organization_id,id,member_id,role,status) VALUES ($1,$2,$3,'owner','active')", [activeOrganizationId, crypto.randomUUID(), activeMemberId]);
  const active = await complete(pool, await consumingAttempt(pool), { subject: activeSubject });
  assert.equal(active.row.state, "identity_verified");
  assert.equal(Number(active.row.organization_count), 1);
  assert.equal((await pool.query("SELECT member_id FROM public.upstream_identities WHERE provider='github' AND subject=$1", [activeSubject])).rows[0].member_id, activeMemberId);
  assert.equal((await pool.query("SELECT count(*)::int AS count FROM public.members WHERE id=$1", [active.candidateMemberId])).rows[0].count, 0);

  const revokedMemberId = crypto.randomUUID();
  const revokedSubject = `6${crypto.randomBytes(8).readBigUInt64BE().toString().slice(0, 18)}`;
  const revokedOrganizationId = crypto.randomUUID();
  await pool.query("INSERT INTO public.members (id,github_subject) VALUES ($1,NULL)", [revokedMemberId]);
  await pool.query("INSERT INTO public.upstream_identities (provider,subject,member_id) VALUES ('github',$1,$2)", [revokedSubject, revokedMemberId]);
  await pool.query("INSERT INTO public.organizations (id,name) VALUES ($1,'Hosted revoked integration')", [revokedOrganizationId]);
  await pool.query("INSERT INTO public.memberships (organization_id,id,member_id,role,status) VALUES ($1,$2,$3,'viewer','revoked')", [revokedOrganizationId, crypto.randomUUID(), revokedMemberId]);
  const revoked = await complete(pool, await consumingAttempt(pool), { subject: revokedSubject });
  assert.equal(revoked.row.state, "no_membership");
  assert.equal(Number(revoked.row.organization_count), 0);
});
