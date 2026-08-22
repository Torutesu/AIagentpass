import assert from "node:assert/strict";
import test from "node:test";
import { createPostgresHumanRepository } from "../../src/postgres/human-repository.mjs";

const ids = { session: "11111111-1111-4111-8111-111111111111", member: "22222222-2222-4222-8222-222222222222", org: "33333333-3333-4333-8333-333333333333", membership: "55555555-5555-4555-8555-555555555555", challenge: "44444444-4444-4444-8444-444444444444" };

test("stores session digests as bytes and uses exact tenant/member binding", async () => {
  const calls=[]; const client={async query(text,params){calls.push({text,params});return {rows:[{session:{id:ids.session,member_id:ids.member,membership_id:ids.membership,organization_id:ids.org,role:"owner",token_hash_hex:"a".repeat(64),csrf_token_hash_hex:"b".repeat(64),created_at:"2026-08-12T00:00:00.000Z",expires_at:"2026-08-12T01:00:00.000Z",last_seen_at:"2026-08-12T00:00:00.000Z",idle_expires_at:"2026-08-12T00:30:00.000Z",recent_auth_at:null,revoked_at:null}}],rowCount:1};}};
  const repo=createPostgresHumanRepository({client});
  await repo.createSession({session_id:ids.session,member_id:ids.member,membership_id:ids.membership,organization_id:ids.org,role:"owner",token_hash:"a".repeat(64),csrf_token_hash:"b".repeat(64),created_at:"2026-08-12T00:00:00.000Z",expires_at:"2026-08-12T01:00:00.000Z",last_seen_at:"2026-08-12T00:00:00.000Z",idle_expires_at:"2026-08-12T00:30:00.000Z"});
  assert.equal(Buffer.isBuffer(calls[0].params[5]),true); assert.equal(calls[0].params[5].length,32); assert.match(calls[0].text,/agentpass_human_session_create/);
});

test("refuses session issuance when the exact active membership no longer exists", async () => {
  const client = { async query() { return { rows: [], rowCount: 0 }; } };
  const repo = createPostgresHumanRepository({ client });
  await assert.rejects(() => repo.createSession({session_id:ids.session,member_id:ids.member,membership_id:ids.membership,organization_id:ids.org,role:"owner",token_hash:"a".repeat(64),csrf_token_hash:"b".repeat(64),created_at:"2026-08-12T00:00:00.000Z",expires_at:"2026-08-12T01:00:00.000Z",last_seen_at:"2026-08-12T00:00:00.000Z",idle_expires_at:"2026-08-12T00:30:00.000Z"}), /active session membership is unavailable/);
});

test("atomically enforces the cross-replica session ceiling before insertion", async () => {
  const calls = [];
  const session = {session_id:ids.session,member_id:ids.member,membership_id:ids.membership,organization_id:ids.org,role:"owner",token_hash:"a".repeat(64),csrf_token_hash:"b".repeat(64),created_at:"2026-08-12T00:00:00.000Z",expires_at:"2026-08-12T01:00:00.000Z",last_seen_at:"2026-08-12T00:00:00.000Z",idle_expires_at:"2026-08-12T00:30:00.000Z"};
  const client = { async query(text, params = []) {
    calls.push({ text, params });
    if (text === "BEGIN" || text === "COMMIT" || text === "ROLLBACK") return { rows: [], rowCount: 0 };
    if (text.includes("pg_advisory_xact_lock") && text.includes("agentpass:human:sessions")) return { rows: [{ locked: true }], rowCount: 1 };
    if (text.includes("human_session_create_with_ceiling")) return { rows: [{ session: { id: ids.session, ...session, token_hash_hex: session.token_hash, csrf_token_hash_hex: session.csrf_token_hash, recent_auth_at: null, revoked_at: null } }], rowCount: 1 };
    throw new Error(`unexpected query: ${text}`);
  } };
  const repo = createPostgresHumanRepository({ client });
  const created = await repo.createSessionWithLimit({ session, max_concurrent_sessions: 3, issued_at: session.created_at });
  assert.equal(created.session_id, ids.session);
  assert.deepEqual(calls.map((call) => call.text === "BEGIN" || call.text === "COMMIT" ? call.text : call.text.includes("pg_advisory_xact_lock") ? "LOCK" : call.text.includes("human_session_create_with_ceiling") ? "ISSUE" : "OTHER"), ["BEGIN", "LOCK", "ISSUE", "COMMIT"]);
  const issue = calls.find((call) => call.text.includes("human_session_create_with_ceiling"));
  assert.deepEqual(issue.params.slice(-3), [3, "concurrent_session_limit", session.created_at]);
});

test("consumes signed identity replay state inside the session transaction before authority reduction", async () => {
  const calls = [];
  const session = {session_id:ids.session,member_id:ids.member,membership_id:ids.membership,organization_id:ids.org,role:"owner",token_hash:"a".repeat(64),csrf_token_hash:"b".repeat(64),created_at:"2026-08-12T00:00:00.000Z",expires_at:"2026-08-12T01:00:00.000Z",last_seen_at:"2026-08-12T00:00:00.000Z",idle_expires_at:"2026-08-12T00:30:00.000Z"};
  const client = { async query(text, params = []) {
    calls.push({ text, params });
    if (["BEGIN", "COMMIT", "ROLLBACK"].includes(text)) return { rows: [], rowCount: 0 };
    if (text.includes("pg_advisory_xact_lock")) return { rows: [{ locked: true }], rowCount: 1 };
    if (text.includes("agentpass_consume_human_identity_assertion")) return { rows: [{ consumed: true }], rowCount: 1 };
    if (text.includes("human_session_create_with_ceiling")) return { rows: [{ session: { id: ids.session, ...session, token_hash_hex: session.token_hash, csrf_token_hash: session.csrf_token_hash, recent_auth_at: null, revoked_at: null } }], rowCount: 1 };
    throw new Error(`unexpected query: ${text}`);
  } };
  const repo = createPostgresHumanRepository({ client });
  await repo.createSessionWithLimit({ session, max_concurrent_sessions: 3, identity_replay: { jti_digest: "c".repeat(64), expires_at: "2026-08-12T00:01:00.000Z" } });
  const sequence = calls.map(({ text }) => ["BEGIN", "COMMIT"].includes(text) ? text : text.includes("pg_advisory_xact_lock") ? "LOCK" : text.includes("agentpass_consume_human_identity_assertion") ? "REPLAY" : text.includes("human_session_create_with_ceiling") ? "ISSUE" : "OTHER");
  assert.deepEqual(sequence, ["BEGIN", "LOCK", "REPLAY", "ISSUE", "COMMIT"]);
  const replay = calls.find(({ text }) => text.includes("agentpass_consume_human_identity_assertion"));
  assert.equal(Buffer.isBuffer(replay.params[0]), true);
  assert.equal(replay.params[0].toString("hex"), "c".repeat(64));
});

test("rolls back without reducing sessions when a signed identity assertion is replayed", async () => {
  const calls = [];
  const session = {session_id:ids.session,member_id:ids.member,membership_id:ids.membership,organization_id:ids.org,role:"owner",token_hash:"a".repeat(64),csrf_token_hash:"b".repeat(64),created_at:"2026-08-12T00:00:00.000Z",expires_at:"2026-08-12T01:00:00.000Z",last_seen_at:"2026-08-12T00:00:00.000Z",idle_expires_at:"2026-08-12T00:30:00.000Z"};
  const client = { async query(text) {
    calls.push(text);
    if (["BEGIN", "ROLLBACK"].includes(text)) return { rows: [], rowCount: 0 };
    if (text.includes("pg_advisory_xact_lock")) return { rows: [{ locked: true }], rowCount: 1 };
    if (text.includes("agentpass_consume_human_identity_assertion")) return { rows: [{ consumed: false }], rowCount: 1 };
    throw new Error(`unexpected query: ${text}`);
  } };
  const repo = createPostgresHumanRepository({ client });
  await assert.rejects(
    () => repo.createSessionWithLimit({ session, max_concurrent_sessions: 3, identity_replay: { jti_digest: "d".repeat(64), expires_at: "2026-08-12T00:01:00.000Z" } }),
    (error) => error.code === "human_identity_assertion_replay"
  );
  assert.equal(calls.at(-1), "ROLLBACK");
  assert.equal(calls.some((text) => text.includes("human_session_create_with_ceiling")), false);
});

test("rolls back session-limit revocations when session insertion loses membership authority", async () => {
  const calls = [];
  const session = {session_id:ids.session,member_id:ids.member,membership_id:ids.membership,organization_id:ids.org,role:"owner",token_hash:"a".repeat(64),csrf_token_hash:"b".repeat(64),created_at:"2026-08-12T00:00:00.000Z",expires_at:"2026-08-12T01:00:00.000Z",last_seen_at:"2026-08-12T00:00:00.000Z",idle_expires_at:"2026-08-12T00:30:00.000Z"};
  const client = { async query(text) {
    calls.push(text);
    if (text === "BEGIN" || text === "COMMIT" || text === "ROLLBACK") return { rows: [], rowCount: 0 };
    if (text.includes("pg_advisory_xact_lock")) return { rows: [{ locked: true }], rowCount: 1 };
    if (text.includes("human_session_create_with_ceiling")) return { rows: [{ session: null }], rowCount: 1 };
    throw new Error(`unexpected query: ${text}`);
  } };
  const repo = createPostgresHumanRepository({ client });
  await assert.rejects(() => repo.createSessionWithLimit({ session, max_concurrent_sessions: 3 }), /active session membership is unavailable/);
  assert.equal(calls.at(-1), "ROLLBACK");
  assert.equal(calls.includes("COMMIT"), false);
});

test("recent authorization consumption is one atomic exact-binding update", async () => {
  const calls=[]; const client={async query(text,params){calls.push({text,params});return text.includes("bind_recent_auth") ? {rows:[{bound:true}],rowCount:1} : {rows:[{authorization:{authenticated_at:"2026-08-12T00:00:00.000Z"}}],rowCount:1};}};
  const repo=createPostgresHumanRepository({client});
  assert.equal(await repo.bindRecentAuth({session_id:ids.session,member_id:ids.member,organization_id:ids.org,operation:"device.enrollment.issue",challenge_id:ids.challenge,authenticated_at:"2026-08-12T00:00:00.000Z"}),true);
  assert.deepEqual(await repo.consumeRecentAuth({session_id:ids.session,member_id:ids.member,organization_id:ids.org,operation:"device.enrollment.issue",challenge_id:ids.challenge,consumed_at:"2026-08-12T00:01:00.000Z"}),{authenticated_at:"2026-08-12T00:00:00.000Z"});
  assert.match(calls[0].text,/agentpass_human_session_bind_recent_auth/);
  assert.match(calls[1].text,/agentpass_human_session_consume_recent_auth/);
  assert.deepEqual(calls[1].params.slice(0,5),[ids.session,ids.member,ids.org,"device.enrollment.issue",ids.challenge]);
});

test("compares a resource context hash when binding and consuming recent authorization", async () => {
  const contextHash = "c".repeat(64);
  const calls = [];
  const client = { async query(text, params) { calls.push({ text, params }); return text.includes("bind_recent_auth") ? { rows: [{ bound: true }], rowCount: 1 } : { rows: [{ authorization: { authenticated_at: "2026-08-12T00:00:00.000Z", context_hash: contextHash } }], rowCount: 1 }; } };
  const repo = createPostgresHumanRepository({ client });
  assert.equal(await repo.bindRecentAuth({ session_id: ids.session, member_id: ids.member, organization_id: ids.org, operation: "device.enrollment.issue", challenge_id: ids.challenge, context_hash: contextHash, authenticated_at: "2026-08-12T00:00:00.000Z" }), true);
  assert.deepEqual(await repo.consumeRecentAuth({ session_id: ids.session, member_id: ids.member, organization_id: ids.org, operation: "device.enrollment.issue", challenge_id: ids.challenge, context_hash: contextHash, consumed_at: "2026-08-12T00:01:00.000Z" }), { authenticated_at: "2026-08-12T00:00:00.000Z", context_hash: contextHash });
  assert.equal(calls[0].params[5].toString("hex"), contextHash);
  assert.equal(calls[1].params[5].toString("hex"), contextHash);
  assert.match(calls[0].text, /agentpass_human_session_bind_recent_auth/);
  assert.match(calls[1].text, /agentpass_human_session_consume_recent_auth/);
});

test("credential lookup and counter update are session and organization scoped", async () => {
  const credential=Buffer.alloc(16,7).toString("base64url"); const calls=[]; const client={async query(text,params){calls.push({text,params});return {rows:[],rowCount:0};}};
  const repo=createPostgresHumanRepository({client});
  assert.equal(await repo.findCredentialForSession({session_id:ids.session,organization_id:ids.org,credential_id:credential}),null);
  assert.equal(await repo.updateCredentialCounter({session_id:ids.session,organization_id:ids.org,credential_id:credential,sign_count:2,expected_sign_count:1}),false);
  assert.match(calls[0].text,/agentpass_human_find_credential_for_session/); assert.match(calls[1].text,/agentpass_human_update_credential_counter/);
  assert.match(calls[1].text,/\$4::bigint,\$5::bigint,\$6::boolean,\$7::boolean,\$8::boolean,\$9::boolean/);
  assert.deepEqual(calls[1].params.slice(5), [null, null, null, null]);
});

test("bounds PostgreSQL bigint WebAuthn counters and rejects malformed or overflowing values", async () => {
  const credential=Buffer.alloc(16,7); let signCount=String(Number.MAX_SAFE_INTEGER); let calls=0;
  const repo=createPostgresHumanRepository({client:{async query(){calls += 1; return {rows:[{id:credential,sign_count:signCount,backup_eligible:false,backup_state:false}],rowCount:1};}}});
  const input={session_id:ids.session,organization_id:ids.org,credential_id:credential.toString("base64url")};
  assert.equal((await repo.findCredentialForSession(input)).sign_count,Number.MAX_SAFE_INTEGER);
  for (const invalid of ["01","1.5","-1","1e3",String(Number.MAX_SAFE_INTEGER + 1),"9223372036854775807"]) {
    signCount=invalid;
    await assert.rejects(() => repo.findCredentialForSession(input), /counter is invalid/);
  }
  assert.equal(calls,7);

  let updateCalls=0;
  const updateRepo=createPostgresHumanRepository({client:{async query(){updateCalls += 1; return {rows:[],rowCount:0};}}});
  for (const invalid of ["1",Number.MAX_SAFE_INTEGER + 1,-1,1.5]) {
    await assert.rejects(() => updateRepo.updateCredentialCounter({...input,sign_count:invalid,expected_sign_count:0}), /counter is invalid/);
  }
  assert.equal(updateCalls,0);
});

test("credential allow lists are session-bound, active, bounded, and browser-safe", async () => {
  const id = Buffer.alloc(32, 7);
  const calls = [];
  const repo = createPostgresHumanRepository({ client: { async query(text, params) { calls.push({ text, params }); return { rows: [{ id, transports: ["internal", "hybrid"] }] }; } } });
  assert.deepEqual(await repo.listCredentialsForSession({ session_id: ids.session, organization_id: ids.org }), [{ id: id.toString("base64url"), type: "public-key", transports: ["internal", "hybrid"] }]);
  assert.match(calls[0].text, /agentpass_human_list_credentials_for_session/);
  const invalid = createPostgresHumanRepository({ client: { async query() { return { rows: [{ id, transports: ["internal", "internal"] }] }; } } });
  await assert.rejects(() => invalid.listCredentialsForSession({ session_id: ids.session, organization_id: ids.org }), /transports/);
});

test("upstream identity creation is idempotent but never rebinds a subject", async () => {
  const calls = [];
  const created = { provider: "github", subject: "subject-42", member_id: ids.member, created_at: "2026-08-12T00:00:00.000Z" };
  const repo = createPostgresHumanRepository({ client: { async query(text, params) { calls.push({ text, params }); if (text.startsWith("SELECT public.agentpass_human_identity_bind")) return { rowCount: 1, rows: [{ result: "created" }] }; return { rowCount: 1, rows: [created] }; } } });
  assert.deepEqual(await repo.createUpstreamIdentity({ provider: "github", subject: "subject-42", member_id: ids.member, organization_id: ids.org }), created);
  assert.deepEqual(calls[0].params, ["github", "subject-42", ids.member, ids.org]);
  assert.match(calls[0].text, /agentpass_human_identity_bind/);

  let call = 0;
  const conflictRepo = createPostgresHumanRepository({ client: { async query(text) { call += 1; return call === 1 ? { rowCount: 1, rows: [{ result: "already_exists" }] } : { rowCount: 1, rows: [{ ...created, member_id: "66666666-6666-4666-8666-666666666666" }] }; } } });
  await assert.rejects(() => conflictRepo.createUpstreamIdentity({ provider: "github", subject: "subject-42", member_id: ids.member, organization_id: ids.org }), { code: "ERR_UPSTREAM_IDENTITY_CONFLICT" });
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
  assert.match(calls[0].text, /agentpass_human_identity_list_memberships/);
  assert.doesNotMatch(calls[0].text, /FROM upstream_identities|JOIN memberships|JOIN organizations/);
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
  assert.equal(Buffer.isBuffer(calls[0].params[3]), true);
  assert.equal(Buffer.isBuffer(calls[0].params[4]), true);
  assert.deepEqual(calls[0].params.slice(5), [0, ["internal"], "MacBook Touch ID", true, true]);
  assert.match(calls[0].text, /agentpass_human_register_credential/);

  const duplicateRepo = createPostgresHumanRepository({ client: { async query(text) {
    if (text.startsWith("SELECT * FROM public.agentpass_human_credential_registration_status")) return { rowCount: 1, rows: [{ credential_exists: true, active_count: 1, total_count: 1 }] };
    return { rowCount: 0, rows: [] };
  } } });
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
  assert.match(calls[0].text, /agentpass_human_get_registration_user/);
});

test("registration adapter maps backup metadata and reports duplicate credentials without returning key material", async () => {
  const credentialId = Buffer.alloc(32, 8);
  const row = { id: credentialId, member_id: ids.member, public_key: Buffer.alloc(65, 6), sign_count: 0, transports: ["internal"], label: "Unnamed credential", backup_eligible: true, backup_state: true, created_at: "2026-08-12T00:00:00.000Z", last_used_at: null, revoked_at: null };
  const calls = [];
  const repo = createPostgresHumanRepository({ client: { async query(text, params) { calls.push({ text, params }); return calls.length === 1 ? { rowCount: 1, rows: [row] } : { rowCount: 0, rows: [] }; } } });
  const created = await repo.createCredential({ session_id: ids.session, member_id: ids.member, organization_id: ids.org, credential_id: credentialId.toString("base64url"), public_key: row.public_key, sign_count: 0, transports: ["internal"], credential_device_type: "multiDevice", credential_backed_up: true });
  assert.deepEqual(created, { created: true, credential_id: credentialId.toString("base64url") });
  assert.equal(calls[0].params[8], true);
  assert.equal(calls[0].params[9], true);

  let queryCount = 0;
  let duplicateSql = "";
  const duplicateRepo = createPostgresHumanRepository({ client: { async query(text) { queryCount += 1; duplicateSql = text; return queryCount === 1 ? { rowCount: 0, rows: [] } : { rowCount: 1, rows: [{ credential_exists: true, active_count: 1, total_count: 1 }] }; } } });
  await assert.rejects(() => duplicateRepo.createCredential({ session_id: ids.session, member_id: ids.member, organization_id: ids.org, credential_id: credentialId.toString("base64url"), public_key: row.public_key, sign_count: 0, transports: [], credential_device_type: "singleDevice", credential_backed_up: false }), { code: "credential_exists" });
  assert.equal(queryCount, 2);
  assert.match(duplicateSql, /agentpass_human_credential_registration_status/u);
});

test("credential registration atomically locks, consumes step-up for existing credentials, and permits only the first bootstrap without it", async () => {
  const credentialId = Buffer.alloc(16, 9).toString("base64url");
  const base = { session_id: ids.session, member_id: ids.member, organization_id: ids.org, credential_id: credentialId, public_key: Buffer.alloc(32, 3), sign_count: 0, transports: ["internal"], credential_device_type: "singleDevice", credential_backed_up: false };
  const calls = [];
  let activeCount = "0";
  const client = { async query(text, params) {
    calls.push({ text, params });
    if (text.startsWith("SELECT * FROM public.agentpass_human_credential_registration_status")) return { rows: [{ credential_exists: false, active_count: activeCount, total_count: activeCount }], rowCount: 1 };
    if (text.startsWith("SELECT public.agentpass_human_session_consume_recent_auth")) return { rows: [{ authorization: { authenticated_at: "2026-08-12T00:00:00.000Z" } }], rowCount: 1 };
    if (text.startsWith("SELECT * FROM public.agentpass_human_register_credential")) return { rows: [{ id: Buffer.from(credentialId, "base64url") }], rowCount: 1 };
    return { rows: [], rowCount: 0 };
  } };
  const repo = createPostgresHumanRepository({ client });
  assert.equal((await repo.createCredentialWithRecentAuth(base)).created, true);
  assert.equal(calls.some(({ text }) => text.includes("pg_advisory_xact_lock")), true);
  assert.equal(calls.some(({ text }) => text.startsWith("UPDATE human_sessions")), false);

  calls.length = 0;
  activeCount = "1";
  await assert.rejects(() => repo.createCredentialWithRecentAuth(base), (error) => error.code === "recent_auth_required");
  assert.equal(calls.at(-1).text, "ROLLBACK");

  calls.length = 0;
  const created = await repo.createCredentialWithRecentAuth({ ...base, recent_auth: { authorization_id: ids.challenge, operation: "human.webauthn.credential.register", session_id: ids.session, member_id: ids.member, organization_id: ids.org } });
  assert.equal(created.authorized, true);
  const consumed = calls.find(({ text }) => text.startsWith("SELECT public.agentpass_human_session_consume_recent_auth"));
  assert.match(consumed.text, /agentpass_human_session_consume_recent_auth/);
  assert.equal(calls.at(-1).text, "COMMIT");
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
  const repo = createPostgresHumanRepository({ client: { async query(text, params) { calls.push({ text, params }); return { rows: [{ session: row }], rowCount: 1 }; } } });
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
  assert.match(calls[0].text, /agentpass_human_session_list_safe/);
  assert.deepEqual(calls[0].params, [ids.member, ids.org, null, null, 26]);
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
  assert.match(calls[0].text, /agentpass_human_list_credential_metadata_for_session/);
  assert.deepEqual(calls[0].params, [ids.session, ids.member, ids.org, null, null, 25]);
});

test("management lists use limit+1 millisecond keysets and a SHA-256 credential anchor", async () => {
  const calls = [];
  const repo = createPostgresHumanRepository({ client: { async query(text, params) { calls.push({ text, params }); return { rows: [], rowCount: 0 }; } } });
  const after = "2026-08-12T00:00:00.000Z";
  const anchor = "66666666-6666-4666-8666-666666666666";
  await repo.listSafeSessions({ member_id: ids.member, organization_id: ids.org, limit: 7, after_created_at: after, after_id: ids.session });
  assert.match(calls[0].text, /agentpass_human_session_list_safe/);
  assert.deepEqual(calls[0].params, [ids.member, ids.org, after, ids.session, 8]);

  await repo.listCredentialMetadataForSession({ session_id: ids.session, member_id: ids.member, organization_id: ids.org, limit: 9, after_created_at: after, after_id: anchor });
  assert.match(calls[1].text, /agentpass_human_list_credential_metadata_for_session/);
  assert.deepEqual(calls[1].params, [ids.session, ids.member, ids.org, after, anchor, 9]);
});

test("credential label update uses an advisory lock and expected version", async () => {
  const calls = [];
  const row = { id: Buffer.alloc(16, 4), member_id: ids.member, label: "Updated", transports: [], backup_eligible: false, backup_state: false, created_at: "2026-08-12T00:00:00.000Z", last_used_at: null, revoked_at: null, version: 2 };
  const repo = createPostgresHumanRepository({ client: { async query(text, params) {
    calls.push({ text, params });
    if (text.startsWith("SELECT * FROM public.agentpass_human_update_credential_label")) return { rows: [row], rowCount: 1 };
    return { rows: [], rowCount: 0 };
  } } });
  const result = await repo.updateCredentialLabel({ session_id: ids.session, member_id: ids.member, organization_id: ids.org, credential_id: row.id.toString("base64url"), label: "Updated", expected_version: 1 });
  assert.equal(result.version, 2);
  assert.deepEqual(calls.map(({ text }) => text), [
    "BEGIN",
    "SELECT pg_advisory_xact_lock(hashtextextended('agentpass:human:authority:' || $1::text, 0)) AS locked",
    "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
    "SELECT pg_advisory_xact_lock(hashtextextended('agentpass:human:sessions:' || $1::text, 0)) AS locked",
    "SELECT pg_advisory_xact_lock(hashtextextended('agentpass:webauthn:credentials:' || $1::text, 0)) AS locked",
    calls[5].text,
    "COMMIT"
  ]);
  assert.deepEqual(calls[1].params, [ids.member]);
  assert.deepEqual(calls[2].params, [`agentpass:organization:${ids.org}`]);
  assert.match(calls[5].text, /agentpass_human_update_credential_label/);
  assert.equal(calls[5].params[5], 1);
});

test("credential revoke is optimistic, atomic, and refuses the last active credential", async () => {
  const credentialId = Buffer.alloc(16, 5);
  const row = { id: credentialId, member_id: ids.member, label: "Old", transports: [], backup_eligible: false, backup_state: false, created_at: "2026-08-12T00:00:00.000Z", last_used_at: null, revoked_at: "2026-08-12T00:02:00.000Z", version: 2 };
  const calls = [];
  const repo = createPostgresHumanRepository({ client: { async query(text, params) {
    calls.push({ text, params });
    if (text.startsWith("SELECT * FROM public.agentpass_human_revoke_credential")) return { rows: [row], rowCount: 1 };
    return { rows: [], rowCount: 0 };
  } } });
  const result = await repo.revokeCredential({ session_id: ids.session, member_id: ids.member, organization_id: ids.org, credential_id: credentialId.toString("base64url"), expected_version: 1, revoked_at: "2026-08-12T00:02:00.000Z", reason: "rotated" });
  assert.equal(result.revoked_at, row.revoked_at);
  assert.equal(result.version, 2);
  assert.equal(calls.filter(({ text }) => text === "BEGIN").length, 1);
  assert.equal(calls.at(-1).text, "COMMIT");
  assert.match(calls.find(({ text }) => text.startsWith("SELECT * FROM public.agentpass_human_revoke_credential")).text, /agentpass_human_revoke_credential/);

  const lastCalls = [];
  const lastRepo = createPostgresHumanRepository({ client: { async query(text) {
    lastCalls.push(text);
    if (text.startsWith("SELECT * FROM public.agentpass_human_revoke_credential")) throw Object.assign(new Error("cannot revoke the last usable WebAuthn credential"), { code: "23514", constraint: "webauthn_credentials_last_active" });
    return { rows: [], rowCount: 0 };
  } } });
  await assert.rejects(() => lastRepo.revokeCredential({ session_id: ids.session, member_id: ids.member, organization_id: ids.org, credential_id: credentialId.toString("base64url"), expected_version: 1, revoked_at: "2026-08-12T00:02:00.000Z" }), { code: "ERR_LAST_ACTIVE_CREDENTIAL" });
  assert.equal(lastCalls.at(-1), "ROLLBACK");
  assert.equal(lastCalls.some((text) => text.startsWith("SELECT * FROM public.agentpass_human_revoke_credential")), true);
});

test("administrative revocation invokes the authority hook in the same transaction and self logout does not", async () => {
  const calls = [];
  const reductions = [];
  const credentialId = Buffer.alloc(16, 8);
  const row = { id: credentialId, member_id: ids.member, label: "Old", transports: [], backup_eligible: false, backup_state: false, created_at: "2026-08-12T00:00:00.000Z", last_used_at: null, revoked_at: "2026-08-12T00:05:00.000Z", version: 2 };
  const sessionRowValue = { session_id: ids.challenge, member_id: ids.member, organization_id: ids.org, role: "owner", version: 2, created_at: "2026-08-12T00:00:00.000Z", expires_at: "2026-08-12T01:00:00.000Z", last_seen_at: null, idle_expires_at: null, recent_auth_at: null, revoked_at: "2026-08-12T00:05:00.000Z", revoke_reason: "admin" };
  const client = { async query(text, params) {
    calls.push({ text, params });
    if (text.startsWith("SELECT * FROM public.agentpass_human_revoke_credential")) return { rows: [row], rowCount: 1 };
    if (text.startsWith("SELECT public.agentpass_human_session_revoke_managed")) return { rows: [{ session: sessionRowValue }], rowCount: 1 };
    if (text.startsWith("SELECT public.agentpass_human_session_revoke_others")) return { rows: [{ sessions: [] }], rowCount: 1 };
    return { rows: [], rowCount: 0 };
  } };
  const repo = createPostgresHumanRepository({ client, onAuthorityReduction: async (input) => { reductions.push(input); assert.equal(input.tx, client); return { generation: 2 }; } });
  await repo.revokeCredential({ session_id: ids.session, member_id: ids.member, organization_id: ids.org, credential_id: credentialId.toString("base64url"), expected_version: 1, revoked_at: "2026-08-12T00:05:00.000Z", authority_reduction: true });
  await repo.revokeManagedSession({ session_id: ids.session, target_session_id: ids.challenge, member_id: ids.member, organization_id: ids.org, expected_version: 1, revoked_at: "2026-08-12T00:05:00.000Z", authority_reduction: true });
  await repo.revokeSession({ session_id: ids.session, revoked_at: "2026-08-12T00:05:00.000Z", reason: "logout" });
  assert.equal(reductions.length, 2);
  assert.deepEqual(reductions.map(({ resource }) => resource), ["credential", "session"]);
  assert.equal(calls.filter(({ text }) => text === "BEGIN").length, 2);
  assert.equal(calls.filter(({ text }) => text === "COMMIT").length, 2);
  const locks = calls.filter(({ text }) => text.startsWith("SELECT pg_advisory_xact_lock"));
  assert.deepEqual(locks.map(({ params }) => params), [
    [ids.member], [`agentpass:organization:${ids.org}`], [ids.member], [ids.member]
  ]);
});

test("administrative revocation fails closed when authority propagation is not configured", async () => {
  const credentialId = Buffer.alloc(16, 8);
  const client = { async query(text) {
    if (text.startsWith("SELECT * FROM public.agentpass_human_revoke_credential")) return { rows: [{ id: credentialId, member_id: ids.member, label: "Old", transports: [], backup_eligible: false, backup_state: false, created_at: "2026-08-12T00:00:00.000Z", last_used_at: null, revoked_at: "2026-08-12T00:05:00.000Z", version: 2 }], rowCount: 1 };
    return { rows: [], rowCount: 0 };
  } };
  await assert.rejects(
    createPostgresHumanRepository({ client }).revokeCredential({ session_id: ids.session, member_id: ids.member, organization_id: ids.org, credential_id: credentialId.toString("base64url"), expected_version: 1, revoked_at: "2026-08-12T00:05:00.000Z", authority_reduction: true }),
    { code: "ERR_AUTHORITY_REDUCTION_UNAVAILABLE" }
  );
});

test("other-session revocation is transaction-bound and returns safe rows", async () => {
  const calls = [];
  const other = { session_id: "66666666-6666-4666-8666-666666666666", member_id: ids.member, organization_id: ids.org, role: "owner", created_at: "2026-08-12T00:00:00.000Z", expires_at: "2026-08-12T01:00:00.000Z", last_seen_at: null, idle_expires_at: null, recent_auth_at: null, revoked_at: "2026-08-12T00:03:00.000Z", revoke_reason: "logout_all" , token_hash_hex: "a".repeat(64) };
  const repo = createPostgresHumanRepository({ client: { async query(text, params) {
    calls.push({ text, params });
    if (text.startsWith("SELECT public.agentpass_human_session_revoke_others")) return { rows: [{ sessions: [other] }], rowCount: 1 };
    return { rows: [], rowCount: 0 };
  } } });
  const result = await repo.revokeOtherSessions({ session_id: ids.session, member_id: ids.member, organization_id: ids.org, revoked_at: "2026-08-12T00:03:00.000Z", reason: "logout_all" });
  assert.equal(result[0].session_id, other.session_id);
  assert.equal(result[0].status, "revoked");
  assert.equal(Object.hasOwn(result[0], "token_hash"), false);
  assert.match(calls.find(({ text }) => text.startsWith("SELECT public.agentpass_human_session_revoke_others")).text, /agentpass_human_session_revoke_others/u);
  assert.equal(calls.at(-1).text, "COMMIT");
});

test("other-session revocation excludes the actor, supports an atomic empty no-op, and rolls back propagation failures", async () => {
  const targetA = { session_id: "66666666-6666-4666-8666-666666666666", member_id: ids.member, organization_id: ids.org, role: "owner", version: 2, created_at: "2026-08-12T00:00:00.000Z", expires_at: "2026-08-13T00:00:00.000Z", last_seen_at: null, idle_expires_at: null, recent_auth_at: null, revoked_at: "2026-08-12T00:03:00.000Z", revoke_reason: "logout_all" };
  const targetB = { ...targetA, session_id: "77777777-7777-4777-8777-777777777777" };
  const calls = [];
  const reductions = [];
  let updateRows = [targetA, targetB];
  const client = {
    async query(text, params) {
      calls.push({ text, params });
      if (text.startsWith("SELECT public.agentpass_human_session_revoke_others")) return { rows: [{ sessions: updateRows }], rowCount: 1 };
      return { rows: [], rowCount: 0 };
    }
  };
  const repo = createPostgresHumanRepository({
    client,
    onAuthorityReduction: async (input) => {
      reductions.push(input);
      if (reductions.length === 2) throw new Error("audit publication failed");
      return { generation: 9 };
    }
  });
  await assert.rejects(() => repo.revokeOtherSessions({ session_id: ids.session, member_id: ids.member, organization_id: ids.org, revoked_at: "2026-08-12T00:03:00.000Z", reason: "logout_all", authority_reduction: true }), /audit publication failed/);
  assert.equal(calls.some(({ text }) => text === "COMMIT"), false);
  assert.equal(calls.at(-1).text, "ROLLBACK");
  assert.deepEqual(reductions.map(({ tx, actor_session_id, target_id, resource }) => ({ tx, actor_session_id, target_id, resource })), [
    { tx: client, actor_session_id: ids.session, target_id: targetA.session_id, resource: "session" },
    { tx: client, actor_session_id: ids.session, target_id: targetB.session_id, resource: "session" }
  ]);
  const update = calls.find(({ text }) => text.startsWith("SELECT public.agentpass_human_session_revoke_others"));
  assert.match(update.text, /agentpass_human_session_revoke_others/u);

  updateRows = [];
  const emptyCalls = [];
  const emptyRepo = createPostgresHumanRepository({ client: { async query(text, params) { emptyCalls.push({ text, params }); if (text.startsWith("SELECT public.agentpass_human_session_revoke_others")) return { rows: [{ sessions: [] }], rowCount: 1 }; return { rows: [], rowCount: 0 }; } } });
  assert.deepEqual(await emptyRepo.revokeOtherSessions({ session_id: ids.session, member_id: ids.member, organization_id: ids.org, revoked_at: "2026-08-12T00:04:00.000Z", authority_reduction: true }), []);
  assert.equal(emptyCalls.some(({ text }) => text === "COMMIT"), true);
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
  assert.equal(client.calls.filter(({ text }) => text.startsWith("SELECT * FROM public.agentpass_human_revoke_credential")).length, 2);
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
    if (text.includes("agentpass:human:authority:")) {
      await this.acquireLock();
      connection.lockHeld = true;
      this.lockAcquisitions += 1;
      return { rows: [{ locked: true }], rowCount: 1 };
    }
    if (text === "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))" || text.includes("agentpass:human:sessions:") || text.includes("agentpass:webauthn:credentials:")) return { rows: [{ locked: true }], rowCount: 1 };
    if (text.startsWith("SELECT pg_advisory_xact_lock")) {
      await this.acquireLock();
      connection.lockHeld = true;
      this.lockAcquisitions += 1;
      return { rows: [{ locked: true }], rowCount: 1 };
    }
    if (text.startsWith("SELECT * FROM public.agentpass_human_revoke_credential")) {
      const active = this.credentials.filter(({ member_id, revoked_at }) => member_id === ids.member && revoked_at === null);
      if (active.length <= 1) throw Object.assign(new Error("cannot revoke the last usable WebAuthn credential"), { code: "23514", constraint: "webauthn_credentials_last_active" });
      const id = params[3];
      const expectedVersion = params[4];
      const row = this.credentials.find((candidate) => candidate.id.equals(id) && candidate.revoked_at === null && candidate.version === expectedVersion);
      if (!row) return { rows: [], rowCount: 0 };
      row.revoked_at = params[5];
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
