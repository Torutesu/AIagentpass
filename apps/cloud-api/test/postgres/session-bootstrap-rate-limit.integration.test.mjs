import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";
import { Pool } from "pg";

import { createHumanSessionService } from "../../src/human-session.mjs";
import { createHumanSessionHttpApi } from "../../src/human-auth/session-http-api.mjs";
import {
  HUMAN_AUTH_ABUSE_ERROR_CODES,
  HUMAN_AUTH_RATE_LIMIT_OPERATIONS,
  createHumanAuthAbuseControls,
  deriveHumanAuthGlobalBucketId
} from "../../src/human-auth/rate-limit.mjs";
import { createMigrationRunner } from "../../src/postgres/migration-runner.mjs";
import { createPostgresHumanRepository } from "../../src/postgres/human-repository.mjs";
import { createSharedControlRepository } from "../../src/postgres/shared-control-repository.mjs";

const DATABASE_URL = process.env.AGENTPASS_TEST_DATABASE_URL ?? process.env.AGENTPASS_TEST_POSTGRES_URL;
const OPERATION = HUMAN_AUTH_RATE_LIMIT_OPERATIONS.sessionBootstrap;
const ORIGIN = "https://console.agentpass.test";
const BUCKET_SECRET = crypto.randomBytes(32);
const GLOBAL_BUCKET_ID = deriveHumanAuthGlobalBucketId(BUCKET_SECRET, OPERATION);

test("two API replicas share fixed bootstrap admission without attacker-controlled bucket growth", {
  skip: !DATABASE_URL,
  timeout: 60_000
}, async (t) => {
  const firstPool = new Pool({ connectionString: DATABASE_URL, max: 8 });
  const secondPool = new Pool({ connectionString: DATABASE_URL, max: 8 });
  const organizationId = crypto.randomUUID();
  const memberId = crypto.randomUUID();
  const membershipId = crypto.randomUUID();
  t.after(async () => {
    try {
      await firstPool.query("DELETE FROM rate_limit_buckets WHERE organization_id=$1", [organizationId]);
      await firstPool.query("DELETE FROM anonymous_rate_limit_buckets WHERE operation=$1 AND principal_id=$2", [OPERATION, GLOBAL_BUCKET_ID]);
      await firstPool.query("DELETE FROM human_sessions WHERE member_id=$1", [memberId]);
      await firstPool.query("DELETE FROM memberships WHERE organization_id=$1", [organizationId]);
      await firstPool.query("DELETE FROM outbox_events WHERE organization_id=$1", [organizationId]);
      await firstPool.query("DELETE FROM control_plane_authority_generations WHERE organization_id=$1", [organizationId]);
      await firstPool.query("DELETE FROM admin_audit_heads WHERE organization_id=$1", [organizationId]);
      await firstPool.query("DELETE FROM members WHERE id=$1", [memberId]);
      await firstPool.query("DELETE FROM organizations WHERE id=$1", [organizationId]);
    } finally {
      await Promise.all([firstPool.end(), secondPool.end()]);
    }
  });

  const migrationClient = await firstPool.connect();
  try {
    await createMigrationRunner({ client: migrationClient, applicationVersion: "session-bootstrap-rate-limit-qualification" }).run();
  } finally {
    migrationClient.release();
  }
  await firstPool.query("DELETE FROM anonymous_rate_limit_buckets WHERE operation=$1 AND principal_id=$2", [OPERATION, GLOBAL_BUCKET_ID]);
  await firstPool.query("INSERT INTO organizations (id,name) VALUES ($1,$2)", [organizationId, "Bootstrap limiter qualification"]);
  await firstPool.query("INSERT INTO members (id,github_subject,display_name) VALUES ($1,$2,$3)", [memberId, `bootstrap-limit-${crypto.randomUUID()}`, "Bootstrap limiter member"]);
  await firstPool.query("INSERT INTO memberships (organization_id,id,member_id,role,status) VALUES ($1,$2,$3,'admin','active')", [organizationId, membershipId, memberId]);

  const policy = { [OPERATION]: { capacity: 1, refillPerSecond: 0.001 } };
  const controls = [
    createHumanAuthAbuseControls({ repository: createSharedControlRepository({ client: firstPool }), bucketSecret: BUCKET_SECRET, policies: policy, idleTtlMs: 60_000 }),
    createHumanAuthAbuseControls({ repository: createSharedControlRepository({ client: secondPool }), bucketSecret: BUCKET_SECRET, policies: policy, idleTtlMs: 60_000 })
  ];
  const calls = { verify: 0, issue: 0 };
  const apis = controls.map((abuseControls) => createHumanSessionHttpApi({
    origin: ORIGIN,
    abuseControls,
    verifyIdentityRequest: async () => { calls.verify += 1; return Object.freeze({ version: 1 }); },
    humanSession: {
      expectedOrigin: ORIGIN,
      async issueSession() {
        calls.issue += 1;
        return {
          session: publicSession(),
          csrf_token: "c".repeat(43),
          setCookie: `__Host-agentpass_session=${"s".repeat(43)}; Path=/; HttpOnly; Secure; SameSite=Strict`
        };
      },
      async rotateSession() {
        return {
          session: publicSession(),
          csrf_token: "c".repeat(43),
          setCookie: `__Host-agentpass_session=${"s".repeat(43)}; Path=/; HttpOnly; Secure; SameSite=Strict`
        };
      }
    }
  }));

  const responses = await Promise.all(Array.from({ length: 65 }, (_, index) => apis[index % 2].handle(request())));
  assert.equal(responses.filter(({ status }) => status === 201).length, 64);
  assert.equal(responses.filter(({ status }) => status === 429).length, 1);
  assert.equal(responses.find(({ status }) => status === 429).body.error.code, HUMAN_AUTH_ABUSE_ERROR_CODES.RATE_LIMITED);
  assert.equal(calls.verify, 64);
  assert.equal(calls.issue, 64);
  const anonymousRows = await firstPool.query("SELECT count(*)::integer AS count FROM anonymous_rate_limit_buckets WHERE operation=$1 AND principal_id=$2", [OPERATION, GLOBAL_BUCKET_ID]);
  assert.deepEqual(anonymousRows.rows, [{ count: 1 }]);

  const identity = { subject_bucket_id: crypto.randomUUID(), member_id: memberId, organization_id: organizationId };
  const decisions = await Promise.allSettled(controls.map((control) => control.checkIdentity({ operation: OPERATION, identity })));
  assert.equal(decisions.filter(({ status }) => status === "fulfilled").length, 1);
  const rejected = decisions.filter((decision) => decision.status === "rejected");
  assert.equal(rejected.length, 1);
  assert.equal(rejected[0].reason?.code, HUMAN_AUTH_ABUSE_ERROR_CODES.RATE_LIMITED);
  const identityRows = await firstPool.query("SELECT count(*)::integer AS count FROM rate_limit_buckets WHERE organization_id=$1", [organizationId]);
  assert.deepEqual(identityRows.rows, [{ count: 3 }]);

  await firstPool.query("DELETE FROM rate_limit_buckets WHERE organization_id=$1", [organizationId]);
  const issuancePolicy = { [OPERATION]: { capacity: 12, refillPerSecond: 0.1 } };
  const issuanceControls = [
    createHumanAuthAbuseControls({ repository: createSharedControlRepository({ client: firstPool }), bucketSecret: BUCKET_SECRET, policies: issuancePolicy, idleTtlMs: 60_000 }),
    createHumanAuthAbuseControls({ repository: createSharedControlRepository({ client: secondPool }), bucketSecret: BUCKET_SECRET, policies: issuancePolicy, idleTtlMs: 60_000 })
  ];
  const repositories = [
    createPostgresHumanRepository({ client: firstPool }),
    createPostgresHumanRepository({ client: secondPool })
  ];
  const services = repositories.map((repository, index) => createHumanSessionService({
    repository,
    origin: ORIGIN,
    maxConcurrentSessions: 3,
    identityAdapter: { async verify() { return { member_id: memberId, membership_id: membershipId, organization_id: organizationId, subject_bucket_id: identity.subject_bucket_id, role: "admin" }; } },
    authorizeIdentity: (verified) => issuanceControls[index].checkIdentity({ operation: OPERATION, identity: verified })
  }));
  const issued = await Promise.all(Array.from({ length: 12 }, (_, index) => services[index % 2].issueSession({ identityAssertion: Object.freeze({ index }), origin: ORIGIN })));
  assert.equal(issued.length, 12);
  const sessionState = await firstPool.query(`SELECT
      count(*) FILTER (WHERE revoked_at IS NULL)::integer AS active,
      count(*) FILTER (WHERE revoke_reason='concurrent_session_limit')::integer AS ceiling_revoked,
      count(*)::integer AS total
    FROM human_sessions WHERE member_id=$1`, [memberId]);
  assert.deepEqual(sessionState.rows, [{ active: 3, ceiling_revoked: 9, total: 12 }]);
});

function request() {
  return {
    method: "POST",
    url: "/session",
    headers: { origin: ORIGIN, "content-type": "application/json" },
    body: "{}"
  };
}

function publicSession() {
  return {
    version: 1,
    session_id: "11111111-1111-4111-8111-111111111111",
    member_id: "22222222-2222-4222-8222-222222222222",
    organization_id: "33333333-3333-4333-8333-333333333333",
    role: "owner",
    created_at: "2026-08-14T00:00:00.000Z",
    expires_at: "2026-08-14T08:00:00.000Z",
    recent_auth_at: null
  };
}
