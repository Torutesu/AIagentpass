import assert from "node:assert/strict";
import test from "node:test";
import { createPostgresHumanRepository } from "../../src/postgres/human-repository.mjs";

const ids = { session: "11111111-1111-4111-8111-111111111111", member: "22222222-2222-4222-8222-222222222222", org: "33333333-3333-4333-8333-333333333333", membership: "55555555-5555-4555-8555-555555555555", challenge: "44444444-4444-4444-8444-444444444444" };

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

test("upstream identity creation is idempotent but never rebinds a subject", async () => {
  const calls = [];
  const created = { provider: "github", subject: "subject-42", member_id: ids.member, created_at: "2026-08-12T00:00:00.000Z" };
  const repo = createPostgresHumanRepository({ client: { async query(text, params) { calls.push({ text, params }); return { rowCount: 1, rows: [created] }; } } });
  assert.deepEqual(await repo.createUpstreamIdentity({ provider: "github", subject: "subject-42", member_id: ids.member }), created);
  assert.deepEqual(calls[0].params, ["github", "subject-42", ids.member]);
  assert.match(calls[0].text, /ON CONFLICT \(provider,subject\) DO NOTHING/);

  let call = 0;
  const conflictRepo = createPostgresHumanRepository({ client: { async query(text) { call += 1; return call === 1 ? { rowCount: 0, rows: [] } : { rowCount: 1, rows: [{ ...created, member_id: "66666666-6666-4666-8666-666666666666" }] }; } } });
  await assert.rejects(() => conflictRepo.createUpstreamIdentity({ provider: "github", subject: "subject-42", member_id: ids.member }), { code: "ERR_UPSTREAM_IDENTITY_CONFLICT" });
});

test("upstream identity resolution returns only active organization memberships", async () => {
  const calls = [];
  const repo = createPostgresHumanRepository({ client: { async query(text, params) {
    calls.push({ text, params });
    return { rowCount: 1, rows: [{ provider: "github", subject: "subject-42", member_id: ids.member, identity_created_at: "2026-08-12T00:00:00.000Z", organization_id: ids.org, membership_id: ids.membership, role: "owner", status: "active", version: 2, created_at: "2026-08-12T00:00:00.000Z", updated_at: "2026-08-12T00:00:00.000Z", organization_name: "Example" }] };
  } } });
  assert.deepEqual(await repo.resolveUpstreamIdentity({ provider: "github", subject: "subject-42", organization_id: ids.org }), {
    provider: "github",
    subject: "subject-42",
    member_id: ids.member,
    memberships: [{ provider: "github", subject: "subject-42", member_id: ids.member, identity_created_at: "2026-08-12T00:00:00.000Z", organization_id: ids.org, membership_id: ids.membership, role: "owner", status: "active", version: 2, created_at: "2026-08-12T00:00:00.000Z", updated_at: "2026-08-12T00:00:00.000Z", organization_name: "Example" }]
  });
  assert.deepEqual(calls[0].params, ["github", "subject-42", ids.org]);
  assert.match(calls[0].text, /m\.status='active'/);
  assert.match(calls[0].text, /JOIN organizations/);
  assert.match(calls[0].text, /LIMIT 128/);
});

test("credential registration is session and membership bound, stores metadata, and ignores duplicate IDs", async () => {
  const credentialId = Buffer.alloc(32, 9);
  const row = { id: credentialId, member_id: ids.member, public_key: Buffer.alloc(65, 7), sign_count: 0, transports: ["internal"], label: "MacBook Touch ID", backup_eligible: true, backup_state: true, created_at: "2026-08-12T00:00:00.000Z", last_used_at: null, revoked_at: null };
  const calls = [];
  const repo = createPostgresHumanRepository({ client: { async query(text, params) { calls.push({ text, params }); return { rowCount: 1, rows: [row] }; } } });
  const result = await repo.insertCredentialForSession({ session_id: ids.session, member_id: ids.member, organization_id: ids.org, credential_id: credentialId.toString("base64url"), public_key: row.public_key, sign_count: 0, transports: ["internal"], label: row.label, backup_eligible: true, backup_state: true });
  assert.equal(result.id, credentialId.toString("base64url"));
  assert.equal(result.member_id, ids.member);
  assert.equal(Buffer.isBuffer(result.public_key), true);
  assert.equal(result.backup_state, true);
  assert.equal(Buffer.isBuffer(calls[0].params[2]), true);
  assert.equal(Buffer.isBuffer(calls[0].params[3]), true);
  assert.deepEqual(calls[0].params.slice(4), [0, ["internal"], "MacBook Touch ID", true, true, ids.org]);
  assert.match(calls[0].text, /s\.member_id=\$2/);
  assert.match(calls[0].text, /m\.role=s\.role/);
  assert.match(calls[0].text, /ON CONFLICT \(id\) DO NOTHING/);

  const duplicateRepo = createPostgresHumanRepository({ client: { async query() { return { rowCount: 0, rows: [] }; } } });
  assert.equal(await duplicateRepo.insertCredential({ session_id: ids.session, member_id: ids.member, organization_id: ids.org, credential_id: credentialId.toString("base64url"), public_key: row.public_key, sign_count: 0, transports: [], label: "Duplicate", backup_eligible: false, backup_state: false }), null);
});

test("credential registration rejects malformed or contradictory metadata before querying", async () => {
  let calls = 0;
  const repo = createPostgresHumanRepository({ client: { async query() { calls += 1; return { rows: [], rowCount: 0 }; } } });
  const base = { session_id: ids.session, member_id: ids.member, organization_id: ids.org, credential_id: Buffer.alloc(16, 1).toString("base64url"), public_key: Buffer.alloc(32, 2), sign_count: 0, transports: [], label: "Credential", backup_eligible: false, backup_state: false };
  await assert.rejects(() => repo.insertCredential({ ...base, backup_state: true }), /backup_state/);
  await assert.rejects(() => repo.insertCredential({ ...base, transports: ["internal", "internal"] }), /transports/);
  await assert.rejects(() => repo.insertCredential({ ...base, label: "" }), /bounded text/);
  assert.equal(calls, 0);
});

test("registration user is derived from the active session and member, never from browser input", async () => {
  const calls = [];
  const repo = createPostgresHumanRepository({ client: { async query(text, params) { calls.push({ text, params }); return { rowCount: 1, rows: [{ member_id: ids.member, display_name: "Example User" }] }; } } });
  assert.deepEqual(await repo.getRegistrationUser({ session_id: ids.session, member_id: ids.member, organization_id: ids.org }), {
    id: Buffer.from(ids.member.replaceAll("-", ""), "hex").toString("base64url"),
    name: `agentpass:${ids.member}`,
    display_name: "Example User"
  });
  assert.deepEqual(calls[0].params, [ids.session, ids.member, ids.org]);
  assert.match(calls[0].text, /s\.revoked_at IS NULL/);
  assert.match(calls[0].text, /ms\.status='active'/);
});

test("registration adapter maps backup metadata and reports duplicate credentials without returning key material", async () => {
  const credentialId = Buffer.alloc(32, 8);
  const row = { id: credentialId, member_id: ids.member, public_key: Buffer.alloc(65, 6), sign_count: 0, transports: ["internal"], label: "Unnamed credential", backup_eligible: true, backup_state: true, created_at: "2026-08-12T00:00:00.000Z", last_used_at: null, revoked_at: null };
  const calls = [];
  const repo = createPostgresHumanRepository({ client: { async query(text, params) { calls.push({ text, params }); return calls.length === 1 ? { rowCount: 1, rows: [row] } : { rowCount: 0, rows: [] }; } } });
  const created = await repo.createCredential({ session_id: ids.session, member_id: ids.member, organization_id: ids.org, credential_id: credentialId.toString("base64url"), public_key: row.public_key, sign_count: 0, transports: ["internal"], credential_device_type: "multiDevice", credential_backed_up: true });
  assert.deepEqual(created, { created: true, credential_id: credentialId.toString("base64url") });
  assert.equal(calls[0].params[7], true);
  assert.equal(calls[0].params[8], true);

  let queryCount = 0;
  let duplicateSql = "";
  const duplicateRepo = createPostgresHumanRepository({ client: { async query(text) { queryCount += 1; duplicateSql = text; return queryCount === 1 ? { rowCount: 0, rows: [] } : { rowCount: 1, rows: [{ "?column?": 1 }] }; } } });
  await assert.rejects(() => duplicateRepo.createCredential({ session_id: ids.session, member_id: ids.member, organization_id: ids.org, credential_id: credentialId.toString("base64url"), public_key: row.public_key, sign_count: 0, transports: [], credential_device_type: "singleDevice", credential_backed_up: false }), { code: "credential_exists" });
  assert.equal(queryCount, 2);
  assert.match(duplicateSql, /EXISTS \(SELECT 1 FROM human_sessions/);
});
