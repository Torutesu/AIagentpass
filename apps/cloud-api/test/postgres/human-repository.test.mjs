import assert from "node:assert/strict";
import test from "node:test";
import { createPostgresHumanRepository } from "../../src/postgres/human-repository.mjs";

const ids = { session: "11111111-1111-4111-8111-111111111111", member: "22222222-2222-4222-8222-222222222222", org: "33333333-3333-4333-8333-333333333333", membership: "55555555-5555-4555-8555-555555555555", challenge: "44444444-4444-4444-8444-444444444444" };

test("stores session digests as bytes and uses exact tenant/member binding", async () => {
  const calls=[]; const client={async query(text,params){calls.push({text,params});return {rows:[{id:ids.session}],rowCount:1};}};
  const repo=createPostgresHumanRepository({client});
  await repo.createSession({session_id:ids.session,member_id:ids.member,membership_id:ids.membership,organization_id:ids.org,role:"owner",token_hash:"a".repeat(64),csrf_token_hash:"b".repeat(64),created_at:"2026-08-12T00:00:00.000Z",expires_at:"2026-08-12T01:00:00.000Z",last_seen_at:"2026-08-12T00:00:00.000Z",idle_expires_at:"2026-08-12T00:30:00.000Z"});
  assert.equal(Buffer.isBuffer(calls[0].params[4]),true); assert.equal(calls[0].params[4].length,32); assert.match(calls[0].text,/m\.id=\$4/); assert.match(calls[0].text,/m\.status='active'/);
});

test("refuses session issuance when the exact active membership no longer exists", async () => {
  const client = { async query() { return { rows: [], rowCount: 0 }; } };
  const repo = createPostgresHumanRepository({ client });
  await assert.rejects(() => repo.createSession({session_id:ids.session,member_id:ids.member,membership_id:ids.membership,organization_id:ids.org,role:"owner",token_hash:"a".repeat(64),csrf_token_hash:"b".repeat(64),created_at:"2026-08-12T00:00:00.000Z",expires_at:"2026-08-12T01:00:00.000Z",last_seen_at:"2026-08-12T00:00:00.000Z",idle_expires_at:"2026-08-12T00:30:00.000Z"}), /active session membership is unavailable/);
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
  assert.match(calls[1].text,/SET sign_count=\$4,last_used_at=clock_timestamp\(\)/);
  assert.doesNotMatch(calls[1].text,/\bversion\s*=/);
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

test("signed-console identity jti consumption is a durable atomic insert", async () => {
  const calls = [];
  const repo = createPostgresHumanRepository({ client: { async query(text, params) { calls.push({ text, params }); return { rows: [{ consumed: true }], rowCount: 1 }; } } });
  assert.equal(await repo.consumeConsoleIdentityJti({ jti_digest: "a".repeat(64), expires_at: "2026-08-12T00:01:00.000Z" }), true);
  assert.match(calls[0].text, /agentpass_consume_human_identity_assertion/);
  assert.match(calls[0].text, /\$1::bytea/);
  assert.match(calls[0].text, /\$2::timestamptz/);
  assert.deepEqual(calls[0].params, [Buffer.alloc(32, 0xaa), "2026-08-12T00:01:00.000Z"]);
  assert.equal(Buffer.isBuffer(calls[0].params[0]), true);
});

test("signed-console identity replay inputs are validated before PostgreSQL", async () => {
  let calls = 0;
  const repo = createPostgresHumanRepository({ client: { async query() { calls += 1; return { rowCount: 0, rows: [] }; } } });
  await assert.rejects(() => repo.consumeConsoleIdentityJti({ jti_digest: "not-a-digest", expires_at: "2026-08-12T00:01:00.000Z" }), /replay digest/);
  await assert.rejects(() => repo.consumeConsoleIdentityJti({ jti_digest: "a".repeat(64), expires_at: "not-a-date" }), /timestamp/);
  assert.equal(calls, 0);
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

test("safe session listings never select or return bearer digests", async () => {
  const calls = [];
  const row = {
    session_id: ids.session,
    member_id: ids.member,
    organization_id: ids.org,
    role: "owner",
    version: 1,
    created_at: "2026-08-12T00:00:00.000Z",
    expires_at: "2026-08-12T01:00:00.000Z",
    last_seen_at: "2026-08-12T00:01:00.000Z",
    idle_expires_at: "2026-08-12T00:30:00.000Z",
    recent_auth_at: null,
    revoked_at: null,
    revoke_reason: null,
    token_hash_hex: "a".repeat(64),
    csrf_token_hash_hex: "b".repeat(64)
  };
  const repo = createPostgresHumanRepository({ client: { async query(text, params) { calls.push({ text, params }); return { rows: [row], rowCount: 1 }; } } });
  const result = await repo.listSafeSessions({ member_id: ids.member, organization_id: ids.org });
  assert.deepEqual(result, [{
    session_id: ids.session,
    member_id: ids.member,
    organization_id: ids.org,
    role: "owner",
    version: 1,
    created_at: row.created_at,
    expires_at: row.expires_at,
    last_seen_at: row.last_seen_at,
    idle_expires_at: row.idle_expires_at,
    recent_auth_at: null,
    revoked_at: null,
    revoke_reason: null,
    status: "active"
  }]);
  assert.doesNotMatch(calls[0].text, /token_hash|csrf_token_hash/);
  assert.match(calls[0].text, /m\.status='active'/);
  assert.match(calls[0].text, /ORDER BY date_trunc\('milliseconds',s\.created_at\) ASC,s\.id ASC LIMIT \$3/);
  assert.deepEqual(calls[0].params, [ids.member, ids.org, 26]);
});

test("credential management metadata is active-session/member/org scoped and omits key material", async () => {
  const id = Buffer.alloc(32, 6);
  const calls = [];
  const repo = createPostgresHumanRepository({ client: { async query(text, params) {
    calls.push({ text, params });
    return { rows: [{ id, member_id: ids.member, label: "MacBook", transports: ["internal"], backup_eligible: true, backup_state: true, created_at: "2026-08-12T00:00:00.000Z", last_used_at: null, revoked_at: null, version: "3", public_key: Buffer.alloc(65), sign_count: 9 }], rowCount: 1 };
  } } });
  const result = await repo.listCredentialMetadataForSession({ session_id: ids.session, member_id: ids.member, organization_id: ids.org });
  assert.deepEqual(result, [{ id: id.toString("base64url"), member_id: ids.member, label: "MacBook", transports: ["internal"], backup_eligible: true, backup_state: true, created_at: "2026-08-12T00:00:00.000Z", last_used_at: null, revoked_at: null, version: 3 }]);
  assert.doesNotMatch(calls[0].text, /public_key|sign_count|token_hash|csrf_token_hash/);
  assert.match(calls[0].text, /s\.member_id=\$2/);
  assert.match(calls[0].text, /s\.organization_id=\$3/);
  assert.match(calls[0].text, /m\.id=s\.membership_id/);
});

test("management lists use limit+1 millisecond keysets and a SHA-256 credential anchor", async () => {
  const calls = [];
  const repo = createPostgresHumanRepository({ client: { async query(text, params) { calls.push({ text, params }); return { rows: [], rowCount: 0 }; } } });
  const after = "2026-08-12T00:00:00.000Z";
  const anchor = "66666666-6666-4666-8666-666666666666";
  await repo.listSafeSessions({ member_id: ids.member, organization_id: ids.org, limit: 7, after_created_at: after, after_id: ids.session });
  assert.match(calls[0].text, /\(date_trunc\('milliseconds',s\.created_at\),s\.id\) > \(\$3,\$4\)/);
  assert.match(calls[0].text, /LIMIT \$5/);
  assert.deepEqual(calls[0].params, [ids.member, ids.org, after, ids.session, 8]);

  await repo.listCredentialMetadataForSession({ session_id: ids.session, member_id: ids.member, organization_id: ids.org, limit: 9, after_created_at: after, after_id: anchor });
  assert.match(calls[1].text, /encode\(sha256\(anchor\.id\),'hex'\)/);
  assert.match(calls[1].text, /date_trunc\('milliseconds',c\.created_at\),c\.id/);
  assert.match(calls[1].text, /LIMIT \$6/);
  assert.deepEqual(calls[1].params, [ids.session, ids.member, ids.org, after, anchor, 10]);
});

test("credential label update uses an advisory lock and expected version", async () => {
  const calls = [];
  const row = { id: Buffer.alloc(16, 4), member_id: ids.member, label: "Updated", transports: [], backup_eligible: false, backup_state: false, created_at: "2026-08-12T00:00:00.000Z", last_used_at: null, revoked_at: null, version: 2 };
  const repo = createPostgresHumanRepository({ client: { async query(text, params) {
    calls.push({ text, params });
    if (text.startsWith("UPDATE webauthn_credentials c SET label")) return { rows: [row], rowCount: 1 };
    return { rows: [], rowCount: 0 };
  } } });
  const result = await repo.updateCredentialLabel({ session_id: ids.session, member_id: ids.member, organization_id: ids.org, credential_id: row.id.toString("base64url"), label: "Updated", expected_version: 1 });
  assert.equal(result.version, 2);
  assert.deepEqual(calls.map(({ text }) => text), ["BEGIN", "SELECT pg_advisory_xact_lock(hashtextextended('agentpass:webauthn:credentials:' || $1::text, 0)) AS locked", calls[2].text, "COMMIT"]);
  assert.match(calls[2].text, /c\.version=\$6/);
  assert.equal(calls[2].params[5], 1);
});

test("credential revoke is optimistic, atomic, and refuses the last active credential", async () => {
  const credentialId = Buffer.alloc(16, 5);
  const row = { id: credentialId, member_id: ids.member, label: "Old", transports: [], backup_eligible: false, backup_state: false, created_at: "2026-08-12T00:00:00.000Z", last_used_at: null, revoked_at: "2026-08-12T00:02:00.000Z", version: 2 };
  const calls = [];
  const repo = createPostgresHumanRepository({ client: { async query(text, params) {
    calls.push({ text, params });
    if (text.startsWith("SELECT c.id FROM webauthn_credentials")) return { rows: [{ id: credentialId }], rowCount: 1 };
    if (text.startsWith("SELECT count(*)")) return { rows: [{ active_count: "2" }], rowCount: 1 };
    if (text.startsWith("UPDATE webauthn_credentials c SET revoked_at")) return { rows: [row], rowCount: 1 };
    return { rows: [], rowCount: 0 };
  } } });
  const result = await repo.revokeCredential({ session_id: ids.session, member_id: ids.member, organization_id: ids.org, credential_id: credentialId.toString("base64url"), expected_version: 1, revoked_at: "2026-08-12T00:02:00.000Z", reason: "rotated" });
  assert.equal(result.revoked_at, row.revoked_at);
  assert.equal(result.version, 2);
  assert.equal(calls.filter(({ text }) => text === "BEGIN").length, 1);
  assert.equal(calls.at(-1).text, "COMMIT");
  assert.match(calls.find(({ text }) => text.startsWith("UPDATE webauthn_credentials c SET revoked_at")).text, /c\.version=\$5/);

  const lastCalls = [];
  const lastRepo = createPostgresHumanRepository({ client: { async query(text) {
    lastCalls.push(text);
    if (text.startsWith("SELECT c.id FROM webauthn_credentials")) return { rows: [{ id: credentialId }], rowCount: 1 };
    if (text.startsWith("SELECT count(*)")) return { rows: [{ active_count: "1" }], rowCount: 1 };
    return { rows: [], rowCount: 0 };
  } } });
  await assert.rejects(() => lastRepo.revokeCredential({ session_id: ids.session, member_id: ids.member, organization_id: ids.org, credential_id: credentialId.toString("base64url"), expected_version: 1, revoked_at: "2026-08-12T00:02:00.000Z" }), { code: "ERR_LAST_ACTIVE_CREDENTIAL" });
  assert.equal(lastCalls.at(-1), "ROLLBACK");
  assert.equal(lastCalls.some((text) => text.startsWith("UPDATE webauthn_credentials c SET revoked_at")), false);
});

test("other-session revocation is transaction-bound and returns safe rows", async () => {
  const calls = [];
  const other = { session_id: "66666666-6666-4666-8666-666666666666", member_id: ids.member, organization_id: ids.org, role: "owner", created_at: "2026-08-12T00:00:00.000Z", expires_at: "2026-08-12T01:00:00.000Z", last_seen_at: null, idle_expires_at: null, recent_auth_at: null, revoked_at: "2026-08-12T00:03:00.000Z", revoke_reason: "logout_all" , token_hash_hex: "a".repeat(64) };
  const repo = createPostgresHumanRepository({ client: { async query(text, params) {
    calls.push({ text, params });
    if (text.startsWith("UPDATE human_sessions target")) return { rows: [other], rowCount: 1 };
    return { rows: [], rowCount: 0 };
  } } });
  const result = await repo.revokeOtherSessions({ session_id: ids.session, member_id: ids.member, organization_id: ids.org, revoked_at: "2026-08-12T00:03:00.000Z", reason: "logout_all" });
  assert.equal(result[0].session_id, other.session_id);
  assert.equal(result[0].status, "revoked");
  assert.equal(Object.hasOwn(result[0], "token_hash"), false);
  assert.match(calls.find(({ text }) => text.startsWith("UPDATE human_sessions target")).text, /target\.id<>\$1/);
  assert.equal(calls.at(-1).text, "COMMIT");
});

test("serializes concurrent revocations so exactly one caller can revoke from two active credentials", async () => {
  const firstId = Buffer.alloc(16, 1);
  const secondId = Buffer.alloc(16, 2);
  const client = new ConcurrentCredentialPool({
    credentials: [
      managedCredential(firstId),
      managedCredential(secondId),
    ],
  });
  const repo = createPostgresHumanRepository({ client });
  const input = (credentialId) => ({
    session_id: ids.session,
    member_id: ids.member,
    organization_id: ids.org,
    credential_id: credentialId.toString("base64url"),
    expected_version: 1,
    revoked_at: "2026-08-12T00:04:00.000Z",
  });

  const results = await Promise.allSettled([
    repo.revokeCredential(input(firstId)),
    repo.revokeCredential(input(secondId)),
  ]);

  assert.equal(results.filter((result) => result.status === "fulfilled").length, 1);
  assert.equal(results.filter((result) => result.status === "rejected").length, 1);
  assert.equal(results.find((result) => result.status === "rejected").reason.code, "ERR_LAST_ACTIVE_CREDENTIAL");
  assert.equal(client.credentials.filter(({ revoked_at }) => revoked_at === null).length, 1);
  assert.equal(client.calls.filter(({ text }) => text.startsWith("UPDATE webauthn_credentials c SET revoked_at")).length, 1);
  assert.equal(client.lockAcquisitions, 2);
});

function managedCredential(id) {
  return {
    id,
    member_id: ids.member,
    label: "Credential",
    transports: [],
    backup_eligible: false,
    backup_state: false,
    created_at: "2026-08-12T00:00:00.000Z",
    last_used_at: null,
    revoked_at: null,
    version: 1,
  };
}

class ConcurrentCredentialPool {
  constructor({ credentials }) {
    this.credentials = credentials;
    this.calls = [];
    this.locked = false;
    this.waiters = [];
    this.lockAcquisitions = 0;
  }

  async connect() {
    const connection = { lockHeld: false };
    connection.query = (text, params = []) => this.query(connection, text, params);
    connection.release = () => {};
    return connection;
  }

  async query(connection, text, params = []) {
    this.calls.push({ text, params });
    if (text === "BEGIN" || text === "COMMIT" || text === "ROLLBACK") {
      if (text !== "BEGIN" && connection.lockHeld) {
        connection.lockHeld = false;
        this.releaseLock();
      }
      return { rows: [], rowCount: 0 };
    }
    if (text.startsWith("SELECT pg_advisory_xact_lock")) {
      await this.acquireLock();
      connection.lockHeld = true;
      this.lockAcquisitions += 1;
      return { rows: [{ locked: true }], rowCount: 1 };
    }
    if (text.startsWith("SELECT c.id FROM webauthn_credentials")) {
      const id = params[3];
      const expectedVersion = params[4];
      const row = this.credentials.find((candidate) => candidate.id.equals(id) && candidate.revoked_at === null && candidate.version === expectedVersion);
      return { rows: row ? [{ id: row.id }] : [], rowCount: row ? 1 : 0 };
    }
    if (text.startsWith("SELECT count(*)::text AS active_count")) {
      return { rows: [{ active_count: String(this.credentials.filter(({ member_id, revoked_at }) => member_id === ids.member && revoked_at === null).length) }], rowCount: 1 };
    }
    if (text.startsWith("UPDATE webauthn_credentials c SET revoked_at")) {
      const id = params[3];
      const expectedVersion = params[4];
      const row = this.credentials.find((candidate) => candidate.id.equals(id) && candidate.revoked_at === null && candidate.version === expectedVersion);
      if (!row) return { rows: [], rowCount: 0 };
      row.revoked_at = params[6];
      row.version += 1;
      return { rows: [row], rowCount: 1 };
    }
    throw new Error(`unexpected query in concurrency mock: ${text}`);
  }

  async acquireLock() {
    if (!this.locked) {
      this.locked = true;
      return;
    }
    await new Promise((resolve) => this.waiters.push(resolve));
  }

  releaseLock() {
    const next = this.waiters.shift();
    if (next) next();
    else this.locked = false;
  }
}
