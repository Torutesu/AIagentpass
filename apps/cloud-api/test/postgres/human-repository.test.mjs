import assert from "node:assert/strict";
import test from "node:test";
import { createPostgresHumanRepository } from "../../src/postgres/human-repository.mjs";

const ids = { session: "11111111-1111-4111-8111-111111111111", member: "22222222-2222-4222-8222-222222222222", org: "33333333-3333-4333-8333-333333333333", challenge: "44444444-4444-4444-8444-444444444444" };

test("stores session digests as bytes and uses exact tenant/member binding", async () => {
  const calls=[]; const client={async query(text,params){calls.push({text,params});return {rows:[{id:ids.session}],rowCount:1};}};
  const repo=createPostgresHumanRepository({client});
  await repo.createSession({session_id:ids.session,member_id:ids.member,organization_id:ids.org,role:"owner",token_hash:"a".repeat(64),csrf_token_hash:"b".repeat(64),created_at:"2026-08-12T00:00:00.000Z",expires_at:"2026-08-12T01:00:00.000Z",last_seen_at:"2026-08-12T00:00:00.000Z",idle_expires_at:"2026-08-12T00:30:00.000Z"});
  assert.equal(Buffer.isBuffer(calls[0].params[4]),true); assert.equal(calls[0].params[4].length,32); assert.match(calls[0].text,/organization_id/);
});

test("recent authorization consumption is one atomic exact-binding update", async () => {
  const calls=[]; const client={async query(text,params){calls.push({text,params});return {rows:[{authenticated_at:"2026-08-12T00:00:00.000Z"}],rowCount:1};}};
  const repo=createPostgresHumanRepository({client});
  assert.equal(await repo.bindRecentAuth({session_id:ids.session,member_id:ids.member,organization_id:ids.org,operation:"device.enrollment.issue",challenge_id:ids.challenge,authenticated_at:"2026-08-12T00:00:00.000Z"}),true);
  assert.deepEqual(await repo.consumeRecentAuth({member_id:ids.member,organization_id:ids.org,operation:"device.enrollment.issue",challenge_id:ids.challenge,consumed_at:"2026-08-12T00:01:00.000Z"}),{authenticated_at:"2026-08-12T00:00:00.000Z"});
  assert.match(calls[1].text,/recent_auth_consumed_at IS NULL/); assert.match(calls[1].text,/INTERVAL '5 minutes'/); assert.deepEqual(calls[1].params.slice(0,4),[ids.member,ids.org,"device.enrollment.issue",ids.challenge]);
});

test("credential lookup and counter update are session and organization scoped", async () => {
  const credential=Buffer.alloc(16,7).toString("base64url"); const calls=[]; const client={async query(text,params){calls.push({text,params});return {rows:[],rowCount:0};}};
  const repo=createPostgresHumanRepository({client});
  assert.equal(await repo.findCredentialForSession({session_id:ids.session,organization_id:ids.org,credential_id:credential}),null);
  assert.equal(await repo.updateCredentialCounter({session_id:ids.session,organization_id:ids.org,credential_id:credential,sign_count:2,expected_sign_count:1}),false);
  assert.match(calls[0].text,/m\.status='active'/); assert.match(calls[1].text,/c\.sign_count=\$5/);
});

test("credential allow lists are session-bound, active, bounded, and browser-safe", async () => {
  const id = Buffer.alloc(32, 7);
  const calls = [];
  const repo = createPostgresHumanRepository({ client: { async query(text, params) { calls.push({ text, params }); return { rows: [{ id, transports: ["internal", "hybrid"] }] }; } } });
  assert.deepEqual(await repo.listCredentialsForSession({ session_id: ids.session, organization_id: ids.org }), [{ id: id.toString("base64url"), type: "public-key", transports: ["internal", "hybrid"] }]);
  assert.match(calls[0].text, /s\.id=\$1/);
  assert.match(calls[0].text, /s\.organization_id=\$2/);
  assert.match(calls[0].text, /s\.expires_at>clock_timestamp\(\)/);
  assert.match(calls[0].text, /LIMIT 64/);
  const invalid = createPostgresHumanRepository({ client: { async query() { return { rows: [{ id, transports: ["internal", "internal"] }] }; } } });
  await assert.rejects(() => invalid.listCredentialsForSession({ session_id: ids.session, organization_id: ids.org }), /transports/);
});
