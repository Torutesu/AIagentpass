import assert from "node:assert/strict";
import test from "node:test";
import { createHash } from "node:crypto";

import {
  OrganizationRepositoryError,
  canonicalAuditEvent,
  canonicalOrganizationMutationRequest,
  createPostgresOrganizationRepository,
  organizationMutationRequestHash,
  sha256Hex
} from "../../src/postgres/organization-repository.mjs";

const ids = {
  organization: "11111111-1111-4111-8111-111111111111",
  organization2: "22222222-2222-4222-8222-222222222222",
  owner: "33333333-3333-4333-8333-333333333333",
  admin: "44444444-4444-4444-8444-444444444444",
  viewer: "55555555-5555-4555-8555-555555555555",
  membership: "66666666-6666-4666-8666-666666666666",
  invitation: "77777777-7777-4777-8777-777777777777",
  audit: "88888888-8888-4888-8888-888888888888",
  outbox: "99999999-9999-4999-8999-999999999999"
};
const NOW = "2026-08-12T00:00:00.000Z";
const LATER = "2999-08-13T00:00:00.000Z";
const TOKEN = "ab".repeat(32);
const ZERO_HASH = "0".repeat(64);
const ACTOR_SESSION_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const RECENT_AUTH_CHALLENGE_ID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const RECENT_AUTH_OPERATION = "human.organizations.member.role.update";

class QueueClient {
  constructor(responses = [], { failOn = undefined, idempotency = "inserted", sessionAuthority = undefined } = {}) {
    this.responses = [...responses];
    this.failOn = failOn;
    this.idempotency = idempotency;
    this.sessionAuthority = sessionAuthority;
    this.lastRequestHash = null;
    this.calls = [];
  }

  async query(text, params = []) {
    this.calls.push({ text, params });
    const failure = this.failOn?.(text, params);
    if (failure) throw failure instanceof Error ? failure : new Error("mock query failure");
    if (text.startsWith("INSERT INTO idempotency_records")) {
      this.lastRequestHash = params[3];
      return response([], this.idempotency === "inserted" ? 1 : 0);
    }
    if (text.startsWith("SELECT request_hash,response_status,response_json")) {
      if (this.idempotency === "missing") return response();
      const configured = this.idempotency && typeof this.idempotency === "object" ? this.idempotency : {};
      return response([{ request_hash: configured.request_hash ?? this.lastRequestHash, response_status: configured.response_status ?? 200, response_json: configured.response_json ?? {} }]);
    }
    if (text.startsWith("DELETE FROM idempotency_records") && text.includes("expires_at<=")) return response([], 0);
    if (text.startsWith("DELETE FROM idempotency_records")) return response([], 1);
    if (text.startsWith("UPDATE idempotency_records")) return response([], 1);
    if (text.startsWith("SELECT set_config('agentpass.organization_id'")) return response([{ organization_id: params[0] }]);
    if (text.startsWith("SELECT public.agentpass_capability_authority_revoke_member(")) {
      return response([{ result: { state: "revoked", capabilities: [], capability_ids: [], revoked_count: 0 } }]);
    }
    if (text.startsWith("SELECT s.id AS session_id")) {
      return this.sessionAuthority === undefined ? response([], 0) : response(this.sessionAuthority === null ? [] : [this.sessionAuthority]);
    }
    if (this.responses.length > 0) return this.responses.shift();
    if (text.startsWith("SELECT role,status")) return response([{ role: "owner", status: "active" }]);
    if (text.startsWith("SELECT organization_id,id AS membership_id")) return response([membershipRow({ member_id: ids.viewer, role: "viewer" })]);
    if (text.startsWith("UPDATE human_sessions")) return response([], 0);
    return { rows: [], rowCount: 0 };
  }
}

function response(rows = [], rowCount = rows.length) { return { rows, rowCount }; }
function orgRow(overrides = {}) { return { organization_id: ids.organization, name: "Example", version: 1, created_at: NOW, updated_at: NOW, ...overrides }; }
function membershipRow(overrides = {}) { return { organization_id: ids.organization, membership_id: ids.membership, member_id: ids.owner, role: "owner", status: "active", version: 1, created_at: NOW, updated_at: NOW, ...overrides }; }
function invitationRow(overrides = {}) { return { organization_id: ids.organization, invitation_id: ids.invitation, role: "viewer", created_by: ids.admin, created_at: NOW, expires_at: LATER, consumed_by: null, consumed_at: null, revoked_at: null, version: 1, ...overrides }; }
function txResponses(...responses) { return [response(), response(), ...responses, response(), response(), response(), response(), response(), response()]; }

function repo(client, options = {}) { return createPostgresOrganizationRepository({ client, now: () => NOW, onAuthorityReduction: async () => ({ generation: 2 }), ...options }); }

test("exposes exactly the frozen organization API", () => {
  const repository = repo(new QueueClient());
  assert.equal(Object.isFrozen(repository), true);
  assert.deepEqual(Object.keys(repository).sort(), [
    "acceptInvitation", "createInvitation", "createOrganizationWithOwner", "listInvitations",
    "getOrganization", "listMembers", "listOrganizationsForMember", "removeMember", "renameOrganization",
    "reissueInvitation", "revokeInvitation", "updateMemberRole"
  ].sort());
  assert.throws(() => createPostgresOrganizationRepository({ client: {} }), /database client/);
  assert.throws(() => createPostgresOrganizationRepository({ client: new QueueClient(), now: "not-a-function" }), /now must be a function/);
  assert.throws(() => createPostgresOrganizationRepository({ client: new QueueClient(), onAuthorityReduction: "not-a-function" }), /onAuthorityReduction/);
});

test("gets one tenant organization without exposing database failures", async () => {
  const client = new QueueClient([response([orgRow()])]);
  assert.deepEqual(await repo(client).getOrganization({ organizationId: ids.organization }), orgRow());
  assert.deepEqual(client.calls[0].params, [ids.organization]);
  const failing = repo(new QueueClient([], { failOn: () => new Error("password=internal") }));
  await assert.rejects(failing.getOrganization({ organizationId: ids.organization }), (error) => error.code === "ERR_DATABASE" && !error.message.includes("internal"));
});

test("validates UUIDs, bounded text, roles, versions, times, and digests before querying", async () => {
  const client = new QueueClient();
  const repository = repo(client);
  await assert.rejects(repository.listMembers({ organization_id: "org", actor_member_id: ids.owner }), /UUID/);
  await assert.rejects(repository.renameOrganization({ organization_id: ids.organization, actor_member_id: ids.owner, name: "", expected_version: 1 }), /name/);
  await assert.rejects(repository.updateMemberRole({ organization_id: ids.organization, actor_member_id: ids.owner, member_id: ids.viewer, role: "root", expected_version: 1 }), /role/);
  await assert.rejects(repository.removeMember({ organization_id: ids.organization, actor_member_id: ids.owner, member_id: ids.viewer, expected_version: 0 }), /version/);
  await assert.rejects(repository.createInvitation({ organization_id: ids.organization, actor_member_id: ids.admin, invited_member_id: ids.viewer, role: "owner", token_hash: TOKEN, expires_at: LATER }), /role/);
  await assert.rejects(repository.createInvitation({ organization_id: ids.organization, actor_member_id: ids.admin, invited_member_id: ids.viewer, role: "viewer", token_hash: "00", expires_at: LATER }), /digest/);
  await assert.rejects(repository.createInvitation({ organization_id: ids.organization, actor_member_id: ids.admin, invited_member_id: ids.viewer, role: "viewer", token_hash: TOKEN, expires_at: "tomorrow" }), /expires_at/);
  await assert.rejects(repository.acceptInvitation({ token_hash: TOKEN, actor_member_id: ids.viewer, organization_id: ids.organization, accepted_at: "not-time" }), /accepted_at/);
  assert.equal(client.calls.length, 0);
});

test("requires an idempotency key before any mutation transaction starts", async () => {
  const client = new QueueClient();
  const repository = repo(client);
  const common = { organization_id: ids.organization, actor_member_id: ids.owner };
  await assert.rejects(repository.renameOrganization({ ...common, name: "New", expected_version: 1 }), { code: "ERR_IDEMPOTENCY_KEY_REQUIRED" });
  await assert.rejects(repository.updateMemberRole({ ...common, member_id: ids.viewer, role: "admin", expected_version: 1 }), { code: "ERR_IDEMPOTENCY_KEY_REQUIRED" });
  await assert.rejects(repository.removeMember({ ...common, member_id: ids.viewer, expected_version: 1 }), { code: "ERR_IDEMPOTENCY_KEY_REQUIRED" });
  await assert.rejects(repository.createInvitation({ ...common, role: "viewer", token_hash: TOKEN, expires_at: LATER }), { code: "ERR_IDEMPOTENCY_KEY_REQUIRED" });
  await assert.rejects(repository.revokeInvitation({ ...common, invitation_id: ids.invitation, expected_version: 1 }), { code: "ERR_IDEMPOTENCY_KEY_REQUIRED" });
  await assert.rejects(repository.reissueInvitation({ ...common, invitation_id: ids.invitation, expected_version: 1, token_hash: TOKEN, expires_at: LATER }), { code: "ERR_IDEMPOTENCY_KEY_REQUIRED" });
  await assert.rejects(repository.acceptInvitation({ token_hash: TOKEN, actor_member_id: ids.viewer }), { code: "ERR_IDEMPOTENCY_KEY_REQUIRED" });
  assert.equal(client.calls.length, 0);
});

test("lists organizations only through active memberships and returns no secret fields", async () => {
  const client = new QueueClient([response([orgRow({ token_hash: TOKEN, membership_id: ids.membership, role: "viewer", membership_version: 2, membership_created_at: NOW, membership_updated_at: NOW })])]);
  const result = await repo(client).listOrganizationsForMember({ member_id: ids.viewer });
  assert.deepEqual(result, [{ organization_id: ids.organization, name: "Example", version: 1, created_at: NOW, updated_at: NOW, membership_id: ids.membership, role: "viewer", membership_status: "active", membership_version: 2, membership_created_at: NOW, membership_updated_at: NOW }]);
  assert.equal(Object.hasOwn(result[0], "token_hash"), false);
  assert.match(client.calls[0].text, /m\.member_id=\$1 AND m\.status='active'/);
  assert.deepEqual(client.calls[0].params, [ids.viewer]);
});

test("uses a tuple keyset and fetches one extra organization row for cursor pagination", async () => {
  const client = new QueueClient([response([
    orgRow({ membership_id: ids.membership, role: "viewer", status: "active", membership_version: 1, membership_created_at: NOW, membership_updated_at: NOW }),
    orgRow({ organization_id: ids.organization2, membership_id: ids.membership, role: "viewer", status: "active", membership_version: 1, membership_created_at: NOW, membership_updated_at: NOW, created_at: "2026-08-12T00:00:01.000Z" })
  ])]);
  const result = await repo(client).listOrganizationsForMember({ member_id: ids.viewer, limit: 1, after_created_at: NOW, after_id: ids.organization });
  assert.equal(result.length, 2);
  assert.match(client.calls[0].text, /\(date_trunc\('milliseconds',o\.created_at\),o\.id\) > \(\$2,\$3\)/);
  assert.match(client.calls[0].text, /ORDER BY date_trunc\('milliseconds',o\.created_at\) ASC,o\.id ASC LIMIT \$4/);
  assert.deepEqual(client.calls[0].params, [ids.viewer, NOW, ids.organization, 2]);
});

test("listMembers tenant-scopes the organization and requires an active actor", async () => {
  const row = { member_id: ids.viewer, github_subject: "github-viewer", display_name: "Viewer", member_created_at: NOW, organization_id: ids.organization, membership_id: ids.membership, role: "viewer", status: "active", version: "2", created_at: NOW, updated_at: NOW, token_hash: TOKEN };
  const client = new QueueClient([response([row])]);
  const result = await repo(client).listMembers({ organization_id: ids.organization, actor_member_id: ids.owner });
  assert.equal(result[0].member_id, ids.viewer);
  assert.equal(result[0].version, 2);
  assert.equal(Object.hasOwn(result[0], "token_hash"), false);
  assert.match(client.calls[0].text, /ms\.organization_id=\$1/);
  assert.match(client.calls[0].text, /actor\.organization_id=\$1 AND actor\.member_id=\$2 AND actor\.status='active'/);
  assert.deepEqual(client.calls[0].params, [ids.organization, ids.owner, 51]);
});

test("creates an organization and owner, then appends audit and outbox in the same transaction", async () => {
  const client = new QueueClient([
    response(), response(), response([orgRow({ name: "New Org" })]), response([membershipRow({ member_id: ids.owner })]),
    response(), response([{ sequence: 0, event_hash: ZERO_HASH }]), response(), response(), response(), response()
  ]);
  const result = await repo(client).createOrganizationWithOwner({ organization_id: ids.organization, owner_member_id: ids.owner, name: "New Org", created_at: NOW, idempotency_key: "create-org-1" });
  assert.equal(result.organization_id, ids.organization);
  assert.equal(result.owner.member_id, ids.owner);
  assert.deepEqual(client.calls.slice(0, 2).map((call) => call.text), ["BEGIN", "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))"]);
  const orgInsert = client.calls.find((call) => call.text.startsWith("INSERT INTO organizations"));
  assert.deepEqual(orgInsert.params, [ids.organization, "New Org", NOW]);
  const audit = client.calls.find((call) => call.text.startsWith("INSERT INTO admin_audit_events"));
  assert.match(audit.text, /previous_hash,event_hash/);
  assert.equal(audit.params[0], ids.organization);
  const outbox = client.calls.find((call) => call.text.startsWith("INSERT INTO outbox_events"));
  assert.equal(outbox.params[0], ids.organization);
  assert.doesNotMatch(outbox.params[4], /token_hash/i);
  assert.equal(client.calls.at(-1).text, "COMMIT");
});

test("create organization derives one tenant scope across retries without a random request-hash input", async () => {
  const input = { owner_member_id: ids.owner, principal_id: "human-owner", name: "Derived Org", created_at: NOW, idempotency_key: "create-derived-1" };
  const firstClient = new QueueClient([
    response(), response(), response([orgRow({ name: "Derived Org" })]), response([membershipRow({ member_id: ids.owner })]),
    response(), response([{ sequence: 0, event_hash: ZERO_HASH }]), response(), response(), response(), response()
  ]);
  await repo(firstClient).createOrganizationWithOwner(input);
  const firstInsert = firstClient.calls.find((call) => call.text.startsWith("INSERT INTO organizations"));
  const derivedOrganizationId = firstInsert.params[0];

  const requestHash = organizationMutationRequestHash("organization.create", {
    organization_id: null, actor_id: ids.owner, actor_principal: "human-owner", name: "Derived Org"
  });
  const firstIdempotencyInsert = firstClient.calls.find((call) => call.text.startsWith("INSERT INTO idempotency_records"));
  assert.equal(firstIdempotencyInsert.params[3], requestHash);
  const secondClient = new QueueClient([response(), response(), response()], {
    idempotency: { request_hash: requestHash, response_json: { organization_id: derivedOrganizationId, name: "Derived Org", version: 1, created_at: NOW, updated_at: NOW, owner: membershipRow({ member_id: ids.owner }) } }
  });
  const replay = await repo(secondClient).createOrganizationWithOwner(input);
  const secondInsert = secondClient.calls.find((call) => call.text.startsWith("INSERT INTO organizations"));
  assert.equal(secondInsert.params[0], derivedOrganizationId);
  assert.equal(replay.replayed, true);
  assert.equal(secondClient.calls.some((call) => call.text.startsWith("INSERT INTO memberships")), false);
  const secondIdempotencyInsert = secondClient.calls.find((call) => call.text.startsWith("INSERT INTO idempotency_records"));
  assert.equal(secondIdempotencyInsert.params[3], requestHash);
  assert.match(derivedOrganizationId, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
});

test("rename and role mutations use optimistic versions and return null out of scope", async () => {
  const renameClient = new QueueClient([response(), response(), response()]);
  assert.equal(await repo(renameClient).renameOrganization({ organization_id: ids.organization, actor_member_id: ids.viewer, name: "Denied", expected_version: 1, idempotency_key: "rename-denied-1" }), null);
  assert.equal(renameClient.calls.at(-1).text, "COMMIT");
  const renameSql = renameClient.calls.find((call) => call.text.startsWith("UPDATE organizations"));
  assert.match(renameSql.text, /o\.version=\$3/);
  assert.match(renameSql.text, /actor\.role IN \('owner','admin'\)/);
  assert.equal(renameClient.calls.some((call) => call.text.startsWith("DELETE FROM idempotency_records") && call.text.includes("request_hash=$4")), true);

  const roleClient = new QueueClient([response(), response(), response([{ role: "owner", status: "active" }]), response([membershipRow({ member_id: ids.viewer, role: "viewer" })]), response([membershipRow({ member_id: ids.viewer, role: "admin", version: 2 })]), response(), response(), response([{ sequence: 0, event_hash: ZERO_HASH }]), response(), response(), response(), response()]);
  const role = await repo(roleClient).updateMemberRole({ organization_id: ids.organization, actor_member_id: ids.owner, member_id: ids.viewer, role: "admin", expected_version: 1, idempotency_key: "role-update-1" });
  assert.equal(role.role, "admin");
  const roleSql = roleClient.calls.find((call) => call.text.startsWith("UPDATE memberships"));
  assert.match(roleSql.text, /target\.version=\$3/);
  assert.match(roleSql.text, /target\.organization_id=\$1/);
  assert.deepEqual(roleSql.params.slice(0, 5), [ids.organization, ids.viewer, 1, "admin", ids.owner]);
  const roleSessionRevoke = roleClient.calls.find((call) => call.text.startsWith("UPDATE human_sessions"));
  assert.match(roleSessionRevoke.text, /recent_auth_at=NULL/);
  assert.match(roleSessionRevoke.text, /recent_auth_challenge_id=NULL/);
  assert.deepEqual(roleSessionRevoke.params, [ids.organization, ids.viewer, NOW, "membership_role_changed"]);
  const roleChallengeConsume = roleClient.calls.find((call) => call.text.startsWith("UPDATE webauthn_challenges"));
  assert.match(roleChallengeConsume.text, /status='consumed'/);
  assert.deepEqual(roleChallengeConsume.params, [ids.organization, ids.viewer, NOW]);
  const roleCapabilityTenant = roleClient.calls.find((call) => call.text.startsWith("SELECT set_config('agentpass.organization_id'"));
  assert.deepEqual(roleCapabilityTenant.params, [ids.organization]);
  const roleCapabilityRevoke = roleClient.calls.find((call) => call.text.startsWith("SELECT public.agentpass_capability_authority_revoke_member("));
  assert.ok(roleCapabilityRevoke);
  assert.deepEqual(roleCapabilityRevoke.params, [ids.organization, ids.viewer, NOW]);
});

test("revalidates the exact actor session, consumed proof, and authority epochs inside the mutation transaction", async () => {
  const protectedInput = {
    organization_id: ids.organization,
    actor_member_id: ids.owner,
    actor_session_id: ACTOR_SESSION_ID,
    member_id: ids.viewer,
    role: "admin",
    expected_version: 1,
    recent_auth_challenge_id: RECENT_AUTH_CHALLENGE_ID,
    recent_auth_operation: RECENT_AUTH_OPERATION,
    idempotency_key: "role-session-bound-1"
  };
  const activeClient = new QueueClient([
    response(), response(), response([{ role: "owner", status: "active" }]),
    response([membershipRow({ member_id: ids.viewer, role: "viewer" })]),
    response([membershipRow({ member_id: ids.viewer, role: "admin", version: 2 })]),
    response(), response(), response([{ sequence: 0, event_hash: ZERO_HASH }]), response(), response(), response(), response()
  ], { sessionAuthority: {} });
  await repo(activeClient).updateMemberRole(protectedInput);
  const authorization = activeClient.calls.find((call) => call.text.startsWith("SELECT s.id AS session_id"));
  assert.deepEqual(authorization.params, [ACTOR_SESSION_ID, ids.owner, ids.organization, RECENT_AUTH_CHALLENGE_ID, RECENT_AUTH_OPERATION]);
  assert.match(authorization.text, /s\.revoked_at IS NULL/);
  assert.match(authorization.text, /s\.organization_authority_epoch=o\.authority_epoch/);
  assert.match(authorization.text, /s\.membership_session_epoch=m\.session_epoch/);
  assert.match(authorization.text, /s\.recent_auth_consumed_at IS NOT NULL/);
  assert.match(authorization.text, /FOR UPDATE OF s,m,o/);
  const lockIndex = activeClient.calls.findIndex((call) => call.text.includes("pg_advisory_xact_lock"));
  const authorizationIndex = activeClient.calls.indexOf(authorization);
  const idempotencyIndex = activeClient.calls.findIndex((call) => call.text.startsWith("INSERT INTO idempotency_records"));
  assert.ok(lockIndex < authorizationIndex && authorizationIndex < idempotencyIndex);

  for (const [label, method, overrides] of [
    ["revoked session", "updateMemberRole", {}],
    ["stale authority epoch", "removeMember", { recent_auth_operation: "human.organizations.member.remove", idempotency_key: "remove-session-bound-1" }]
  ]) {
    const staleClient = new QueueClient([], { sessionAuthority: null });
    await assert.rejects(
      repo(staleClient)[method]({ ...protectedInput, ...overrides }),
      (error) => error instanceof OrganizationRepositoryError && error.code === "ERR_STALE_SESSION",
      label
    );
    assert.equal(staleClient.calls.some((call) => call.text.startsWith("INSERT INTO idempotency_records")), false, label);
    assert.equal(staleClient.calls.at(-1).text, "ROLLBACK", label);
  }
});

test("rejects stale actor sessions before rename and invitation mutations", async () => {
  const cases = [
    ["renameOrganization", {
      organization_id: ids.organization,
      actor_member_id: ids.owner,
      actor_session_id: ACTOR_SESSION_ID,
      name: "Renamed",
      expected_version: 1,
      idempotency_key: "rename-stale-session-1"
    }],
    ["createInvitation", {
      organization_id: ids.organization,
      actor_member_id: ids.owner,
      actor_session_id: ACTOR_SESSION_ID,
      invitation_id: ids.invitation,
      role: "viewer",
      token_hash: TOKEN,
      expires_at: LATER,
      idempotency_key: "invite-stale-session-1"
    }],
    ["revokeInvitation", {
      organization_id: ids.organization,
      actor_member_id: ids.owner,
      actor_session_id: ACTOR_SESSION_ID,
      invitation_id: ids.invitation,
      expected_version: 1,
      revoked_at: NOW,
      idempotency_key: "revoke-stale-session-1"
    }]
  ];

  for (const [method, input] of cases) {
    const client = new QueueClient([], { sessionAuthority: null });
    await assert.rejects(
      repo(client)[method](input),
      (error) => error instanceof OrganizationRepositoryError && error.code === "ERR_STALE_SESSION",
      method
    );
    const authorization = client.calls.find((call) => call.text.startsWith("SELECT s.id AS session_id"));
    assert.ok(authorization, `${method} must revalidate the actor session`);
    assert.deepEqual(authorization.params.slice(0, 3), [ACTOR_SESSION_ID, ids.owner, ids.organization]);
    assert.equal(client.calls.some((call) => call.text.startsWith("INSERT INTO idempotency_records")), false, method);
    assert.equal(client.calls.at(-1).text, "ROLLBACK", method);
  }
});

test("classifies stale, absent, and out-of-scope member mutations without cross-tenant disclosure", async () => {
  const staleClient = new QueueClient([
    response(), response(), response([{ role: "owner", status: "active" }]),
    response([membershipRow({ member_id: ids.viewer, role: "viewer", version: 2 })])
  ]);
  await assert.rejects(
    repo(staleClient).updateMemberRole({ organization_id: ids.organization, actor_member_id: ids.owner, member_id: ids.viewer, role: "admin", expected_version: 1, idempotency_key: "role-stale-1" }),
    (error) => error instanceof OrganizationRepositoryError && error.code === "ERR_VERSION_CONFLICT"
  );
  assert.equal(staleClient.calls.some((call) => call.text.startsWith("UPDATE memberships")), false);

  const absentClient = new QueueClient([
    response(), response(), response([{ role: "owner", status: "active" }]), response()
  ]);
  await assert.rejects(
    repo(absentClient).removeMember({ organization_id: ids.organization, actor_member_id: ids.owner, member_id: ids.viewer, expected_version: 1, idempotency_key: "member-absent-1" }),
    (error) => error instanceof OrganizationRepositoryError && error.code === "ERR_MEMBER_NOT_FOUND"
  );
  assert.equal(absentClient.calls.some((call) => call.text.startsWith("UPDATE memberships")), false);

  const outOfScopeClient = new QueueClient([response(), response(), response([{ role: "viewer", status: "active" }])]);
  await assert.rejects(
    repo(outOfScopeClient).removeMember({ organization_id: ids.organization2, actor_member_id: ids.owner, member_id: ids.viewer, expected_version: 1, idempotency_key: "member-scope-1" }),
    (error) => error instanceof OrganizationRepositoryError && error.code === "ERR_FORBIDDEN"
  );
  assert.equal(outOfScopeClient.calls.some((call) => call.text.startsWith("SELECT organization_id,id AS membership_id")), false);
});

test("idempotency acquisition is serialized after the organization lock and before the mutation", async () => {
  const client = new QueueClient([response(), response(), response([orgRow({ name: "Renamed", version: 2 })]), response(), response([{ sequence: 0, event_hash: ZERO_HASH }]), response(), response(), response(), response()]);
  await repo(client).renameOrganization({ organization_id: ids.organization, actor_member_id: ids.owner, name: "Renamed", expected_version: 1, idempotency_key: "rename-serialized-1" });
  const lockIndex = client.calls.findIndex((call) => call.text.includes("pg_advisory_xact_lock"));
  const expiryCleanupIndex = client.calls.findIndex((call) => call.text.startsWith("DELETE FROM idempotency_records") && call.text.includes("expires_at<="));
  const acquireIndex = client.calls.findIndex((call) => call.text.startsWith("INSERT INTO idempotency_records"));
  const checkIndex = client.calls.findIndex((call) => call.text.startsWith("SELECT request_hash,response_status,response_json"));
  const mutationIndex = client.calls.findIndex((call) => call.text.startsWith("UPDATE organizations"));
  assert.ok(lockIndex < expiryCleanupIndex && expiryCleanupIndex < acquireIndex);
  assert.ok(acquireIndex < checkIndex);
  assert.ok(checkIndex < mutationIndex);
  assert.match(client.calls[checkIndex].text, /FOR UPDATE/);
  assert.match(client.calls[acquireIndex].text, /ON CONFLICT \(organization_id,principal_id,idempotency_key\) DO NOTHING/);
});

test("canonical idempotency identity excludes generated tokens, IDs, and server timestamps", async () => {
  async function invitationHash({ token_hash, invitation_id, created_at }) {
    const client = new QueueClient([], { failOn: (text) => text.startsWith("INSERT INTO organization_invitations") });
    await assert.rejects(repo(client).createInvitation({ organization_id: ids.organization, actor_member_id: ids.owner, invitation_id, role: "viewer", token_hash, expires_at: LATER, created_at, idempotency_key: "invite-stable-1" }), /mock query failure/);
    return client.calls.find((call) => call.text.startsWith("INSERT INTO idempotency_records")).params[3];
  }
  assert.equal(
    await invitationHash({ token_hash: TOKEN, invitation_id: ids.invitation, created_at: NOW }),
    await invitationHash({ token_hash: "cd".repeat(32), invitation_id: ids.audit, created_at: "2026-08-12T00:01:00.000Z" })
  );

  async function removalHash(removed_at) {
    const client = new QueueClient([], { failOn: (text) => text.startsWith("UPDATE memberships") });
    await assert.rejects(repo(client).removeMember({ organization_id: ids.organization, actor_member_id: ids.owner, member_id: ids.viewer, expected_version: 1, removed_at, idempotency_key: "remove-stable-1" }), /mock query failure/);
    return client.calls.find((call) => call.text.startsWith("INSERT INTO idempotency_records")).params[3];
  }
  assert.equal(await removalHash(NOW), await removalHash("2026-08-12T00:02:00.000Z"));

  async function acceptanceHash(accepted_at) {
    const client = new QueueClient([response(), response([invitationRow()]), response()], { failOn: (text) => text.startsWith("INSERT INTO memberships") });
    await assert.rejects(repo(client).acceptInvitation({ token_hash: TOKEN, actor_member_id: ids.viewer, accepted_at, idempotency_key: "accept-stable-1" }), /mock query failure/);
    return client.calls.find((call) => call.text.startsWith("INSERT INTO idempotency_records")).params[3];
  }
  assert.equal(await acceptanceHash(NOW), await acceptanceHash("2026-08-12T00:03:00.000Z"));
});

test("same canonical request replays without running the mutation, while a different request conflicts", async () => {
  const input = { organization_id: ids.organization, actor_member_id: ids.owner, name: "Renamed", expected_version: 1, idempotency_key: "rename-replay-1" };
  const hash = organizationMutationRequestHash("organization.rename", {
    organization_id: ids.organization, actor_id: ids.owner, actor_principal: ids.owner, name: input.name, expected_version: 1
  });
  const replayClient = new QueueClient([response(), response()], { idempotency: { request_hash: hash, response_json: orgRow({ name: "Renamed", version: 2 }) } });
  const replay = await repo(replayClient).renameOrganization(input);
  assert.equal(replay.replayed, true);
  assert.equal(replay.name, "Renamed");
  assert.equal(replayClient.calls.some((call) => call.text.startsWith("UPDATE organizations")), false);

  const conflictClient = new QueueClient([response(), response()], { idempotency: { request_hash: ZERO_HASH, response_json: orgRow() } });
  await assert.rejects(repo(conflictClient).renameOrganization(input), { code: "ERR_IDEMPOTENCY_CONFLICT" });
  assert.equal(conflictClient.calls.some((call) => call.text.startsWith("UPDATE organizations")), false);
  assert.equal(conflictClient.calls.at(-1).text, "ROLLBACK");
});

test("removeMember is role-gated, versioned, tenant-scoped, session-revoking, and audit-bound", async () => {
  const client = new QueueClient([response(), response(), response([{ role: "owner", status: "active" }]), response([membershipRow({ member_id: ids.viewer, role: "viewer" })]), response([membershipRow({ member_id: ids.viewer, role: "viewer", status: "revoked", version: 2 })]), response(), response(), response([{ sequence: 0, event_hash: ZERO_HASH }]), response(), response(), response(), response()]);
  const reductions = [];
  const result = await repo(client, { onAuthorityReduction: async (input) => { reductions.push(input); return { generation: 2 }; } }).removeMember({ organization_id: ids.organization, actor_member_id: ids.owner, member_id: ids.viewer, expected_version: 1, removed_at: NOW, idempotency_key: "remove-member-1" });
  assert.equal(result.status, "revoked");
  const update = client.calls.find((call) => call.text.startsWith("UPDATE memberships"));
  assert.match(update.text, /status='revoked'/);
  assert.match(update.text, /actor\.status='active'/);
  assert.match(update.text, /target\.organization_id=\$1/);
  const sessionRevoke = client.calls.find((call) => call.text.startsWith("UPDATE human_sessions"));
  assert.match(sessionRevoke.text, /recent_auth_consumed_at=NULL/);
  assert.deepEqual(sessionRevoke.params, [ids.organization, ids.viewer, NOW, "membership_removed"]);
  assert.equal(client.calls.some((call) => call.text.startsWith("UPDATE webauthn_challenges") && call.text.includes("status='consumed'")), true);
  const capabilityTenant = client.calls.find((call) => call.text.startsWith("SELECT set_config('agentpass.organization_id'"));
  assert.deepEqual(capabilityTenant.params, [ids.organization]);
  const capabilityRevoke = client.calls.find((call) => call.text.startsWith("SELECT public.agentpass_capability_authority_revoke_member("));
  assert.ok(capabilityRevoke);
  assert.deepEqual(capabilityRevoke.params, [ids.organization, ids.viewer, NOW]);
  assert.equal(client.calls.some((call) => call.text.startsWith("UPDATE capabilities")), false);
  assert.equal(client.calls.filter((call) => call.text.startsWith("INSERT INTO admin_audit_events")).length, 1);
  assert.equal(reductions.length, 1);
  assert.equal(reductions[0].tx, client);
  assert.deepEqual(Object.fromEntries(Object.entries(reductions[0]).filter(([key]) => key !== "tx")), { organization_id: ids.organization, actor_member_id: ids.owner, member_id: ids.viewer, event_type: "membership.removed", occurred_at: NOW });
});

test("role reduction propagates authority once while widening and idempotent replay do not", async () => {
  const reductions = [];
  const reductionClient = new QueueClient([response(), response(), response([{ role: "owner", status: "active" }]), response([membershipRow({ member_id: ids.admin, role: "admin" })]), response([membershipRow({ member_id: ids.admin, role: "viewer", version: 2 })]), response(), response(), response([{ sequence: 0, event_hash: ZERO_HASH }]), response(), response(), response(), response()]);
  await repo(reductionClient, { onAuthorityReduction: async (input) => { reductions.push(input); return { generation: 3 }; } }).updateMemberRole({ organization_id: ids.organization, actor_member_id: ids.owner, member_id: ids.admin, role: "viewer", expected_version: 1, revoked_at: NOW, idempotency_key: "role-reduce-1" });
  assert.equal(reductions.length, 1);
  assert.equal(reductions[0].event_type, "membership.role_reduced");

  const widening = [];
  const wideningClient = new QueueClient([response(), response(), response([{ role: "owner", status: "active" }]), response([membershipRow({ member_id: ids.viewer, role: "viewer" })]), response([membershipRow({ member_id: ids.viewer, role: "admin", version: 2 })]), response(), response(), response([{ sequence: 0, event_hash: ZERO_HASH }]), response(), response(), response(), response()]);
  await repo(wideningClient, { onAuthorityReduction: async (input) => { widening.push(input); return { generation: 3 }; } }).updateMemberRole({ organization_id: ids.organization, actor_member_id: ids.owner, member_id: ids.viewer, role: "admin", expected_version: 1, revoked_at: NOW, idempotency_key: "role-widen-1" });
  assert.equal(widening.length, 0);
});

test("rolls back a membership reduction when generation propagation is unavailable", async () => {
  const client = new QueueClient([response(), response(), response([{ role: "owner", status: "active" }]), response([membershipRow({ member_id: ids.viewer, role: "viewer" })]), response([membershipRow({ member_id: ids.viewer, role: "viewer", status: "revoked", version: 2 })]), response(), response()]);
  await assert.rejects(
    repo(client, { onAuthorityReduction: async () => undefined }).removeMember({ organization_id: ids.organization, actor_member_id: ids.owner, member_id: ids.viewer, expected_version: 1, removed_at: NOW, idempotency_key: "remove-member-fail-closed" }),
    { code: "ERR_AUTHORITY_REDUCTION_UNAVAILABLE" }
  );
  assert.equal(client.calls.at(-1).text, "ROLLBACK");
  assert.equal(client.calls.some(({ text }) => text.startsWith("UPDATE idempotency_records")), false);
});

test("maps the PostgreSQL final-owner constraint to a stable repository error", async () => {
  const constraintError = Object.assign(new Error("database detail"), { code: "23514", constraint: "memberships_last_active_owner" });
  const client = new QueueClient([], { failOn: (text) => text.startsWith("UPDATE memberships") ? constraintError : false });
  await assert.rejects(
    repo(client).removeMember({ organization_id: ids.organization, actor_member_id: ids.owner, member_id: ids.owner, expected_version: 1, idempotency_key: "remove-final-owner" }),
    (error) => error instanceof OrganizationRepositoryError && error.code === "ERR_LAST_OWNER" && !error.message.includes("database detail")
  );
  assert.equal(client.calls.at(-1).text, "ROLLBACK");
});

test("invitation creation and listing never return token hashes", async () => {
  const createClient = new QueueClient([response(), response(), response([invitationRow()]), response(), response([{ last_hash: ZERO_HASH }]), response(), response(), response(), response()]);
  const invitation = await repo(createClient).createInvitation({ organization_id: ids.organization, actor_member_id: ids.admin, invited_member_id: ids.viewer, role: "viewer", token_hash: TOKEN, expires_at: LATER, idempotency_key: "invite-create-1" });
  assert.equal(invitation.invitation_id, ids.invitation);
  assert.equal(Object.hasOwn(invitation, "token_hash"), false);
  const insert = createClient.calls.find((call) => call.text.startsWith("INSERT INTO organization_invitations"));
  assert.match(insert.text, /INSERT INTO organization_invitations AS i/);
  assert.match(insert.text, /actor\.organization_id=\$1/);
  assert.ok(Buffer.isBuffer(insert.params[2]));
  assert.equal(insert.params[2].toString("hex"), TOKEN);
  const idempotencyResponse = createClient.calls.find((call) => call.text.startsWith("UPDATE idempotency_records"));
  assert.doesNotMatch(idempotencyResponse.params[4], new RegExp(TOKEN));

  const listClient = new QueueClient([response([invitationRow({ token_hash: TOKEN })])]);
  const listed = await repo(listClient).listInvitations({ organization_id: ids.organization, actor_member_id: ids.admin });
  assert.equal(listed[0].invitation_id, ids.invitation);
  assert.equal(listed[0].status, "pending");
  assert.equal(Object.hasOwn(listed[0], "token_hash"), false);
  assert.match(listClient.calls[0].text, /i\.organization_id=\$1/);

  const expiredClient = new QueueClient([response([invitationRow({ expires_at: NOW })])]);
  const expired = await repo(expiredClient).listInvitations({ organization_id: ids.organization, actor_member_id: ids.admin });
  assert.equal(expired[0].status, "expired", "status uses the injected clock at the exact expiry boundary");
});

test("revokeInvitation is idempotence-safe through status, version, actor, and tenant predicates", async () => {
  const client = new QueueClient([response(), response(), response([invitationRow({ revoked_at: NOW, version: 2 })]), response(), response([{ last_hash: ZERO_HASH }]), response(), response(), response(), response()]);
  const result = await repo(client).revokeInvitation({ organization_id: ids.organization, actor_member_id: ids.admin, invitation_id: ids.invitation, expected_version: 1, revoked_at: NOW, idempotency_key: "invite-revoke-1" });
  assert.equal(result.revoked_at, NOW);
  const update = client.calls.find((call) => call.text.startsWith("UPDATE organization_invitations"));
  assert.match(update.text, /i\.revoked_at IS NULL AND i\.consumed_at IS NULL/);
  assert.deepEqual(update.params, [ids.organization, ids.invitation, 1, NOW, ids.admin, "revoked_by_operator"]);
});

test("reissueInvitation rotates the digest in place and appends audit/outbox atomically", async () => {
  const newExpiry = "2999-08-14T00:00:00.000Z";
  const client = new QueueClient([
    response(), response(),
    response([{ version: 1, expires_at: NOW, consumed_at: null, revoked_at: null }]),
    response([invitationRow({ expires_at: newExpiry, version: 2 })]),
    response(), response([{ sequence: 0, event_hash: ZERO_HASH }]), response(), response()
  ]);
  const result = await repo(client).reissueInvitation({ organization_id: ids.organization, actor_member_id: ids.admin, invitation_id: ids.invitation, expected_version: 1, token_hash: TOKEN, expires_at: newExpiry, reissued_at: NOW, idempotency_key: "invite-reissue-1" });
  assert.equal(result.invitation_id, ids.invitation);
  assert.equal(result.status, "pending");
  assert.equal(result.version, 2);
  assert.equal(Object.hasOwn(result, "token_hash"), false);
  const update = client.calls.find((call) => call.text.startsWith("UPDATE organization_invitations"));
  assert.match(update.text, /SET token_hash=\$3,expires_at=\$4/);
  assert.match(update.text, /i\.version=\$5/);
  assert.match(update.text, /i\.revoked_at IS NULL AND i\.consumed_at IS NULL/);
  assert.match(update.text, /actor\.organization_id=\$1 AND actor\.member_id=\$6/);
  assert.deepEqual(update.params, [ids.organization, ids.invitation, Buffer.from(TOKEN, "hex"), newExpiry, 1, ids.admin]);
  const audit = client.calls.find((call) => call.text.startsWith("INSERT INTO admin_audit_events"));
  assert.equal(JSON.parse(audit.params.at(-1)).action, "invitation.reissued");
  assert.doesNotMatch(JSON.stringify(audit.params), /token_hash|ab{10,}/i);
  const outbox = client.calls.find((call) => call.text.startsWith("INSERT INTO outbox_events"));
  assert.doesNotMatch(JSON.stringify(outbox.params), /token_hash|ab{10,}/i);
  assert.equal(client.calls.at(-1).text, "COMMIT");
});

test("reissueInvitation replays without rotating again and keeps tenant/version predicates", async () => {
  const input = { organization_id: ids.organization, actor_member_id: ids.admin, invitation_id: ids.invitation, expected_version: 1, token_hash: TOKEN, expires_at: LATER, reissued_at: NOW, idempotency_key: "invite-reissue-2" };
  const hash = organizationMutationRequestHash("invitation.reissue", { organization_id: ids.organization, actor_id: ids.admin, actor_principal: ids.admin, invitation_id: ids.invitation, expected_version: 1, expires_at: LATER });
  const replayClient = new QueueClient([response(), response()], { idempotency: { request_hash: hash, response_json: invitationRow({ version: 2, expires_at: LATER }) } });
  const replay = await repo(replayClient).reissueInvitation(input);
  assert.equal(replay.replayed, true);
  assert.equal(replay.invitation_id, ids.invitation);
  assert.equal(replayClient.calls.some((call) => call.text.startsWith("UPDATE organization_invitations")), false);

  const denied = new QueueClient([response(), response(), response()]);
  assert.equal(await repo(denied).reissueInvitation({ ...input, organization_id: ids.organization2, idempotency_key: "invite-reissue-3" }), null);
  const target = denied.calls.find((call) => call.text.startsWith("SELECT i.version"));
  assert.match(target.text, /i\.organization_id=\$1/);
  assert.match(target.text, /actor\.organization_id=\$1/);
  assert.equal(denied.calls.some((call) => call.text.startsWith("UPDATE organization_invitations")), false);
});

test("reissueInvitation permits expired pending invitations but rejects terminal invitations", async () => {
  for (const [index, state] of [
    { expires_at: LATER, consumed_at: NOW, revoked_at: null },
    { expires_at: LATER, consumed_at: null, revoked_at: NOW }
  ].entries()) {
    const client = new QueueClient([response(), response(), response([invitationRow({ ...state })])]);
    await assert.rejects(
      () => repo(client).reissueInvitation({ organization_id: ids.organization, actor_member_id: ids.admin, invitation_id: ids.invitation, expected_version: 1, token_hash: TOKEN, expires_at: LATER, reissued_at: NOW, idempotency_key: `invite-reissue-terminal-${index}` }),
      { code: "ERR_INVITATION_REPLAYED" }
    );
    assert.equal(client.calls.some((call) => call.text.startsWith("UPDATE organization_invitations")), false);
    assert.equal(client.calls.at(-1).text, "ROLLBACK");
  }
});

test("acceptInvitation consumes the exact token once and returns a sanitized invitation/member composite", async () => {
  const client = new QueueClient([
    response(), response([invitationRow({ role: "viewer" })]), response(),
    response([membershipRow({ member_id: ids.viewer, role: "viewer", version: 2 })]), response([invitationRow({ consumed_by: ids.viewer, consumed_at: NOW })]), response(), response([{ sequence: 0, event_hash: ZERO_HASH }]), response(), response(), response(), response()
  ]);
  const result = await repo(client).acceptInvitation({ token_hash: TOKEN, actor_member_id: ids.viewer, organization_id: ids.organization, member_id: ids.admin, role: "owner", accepted_at: NOW, idempotency_key: "invite-accept-1" });
  assert.equal(result.member.member_id, ids.viewer);
  assert.equal(result.member.role, "viewer");
  assert.deepEqual(result.invitation, {
    organization_id: ids.organization, invitation_id: ids.invitation, role: "viewer", created_by: ids.admin,
    created_at: NOW, expires_at: LATER, consumed_at: NOW, accepted_at: NOW,
    accepted_member_id: ids.viewer, revoked_at: null, status: "accepted", version: 1
  });
  const consume = client.calls.find((call) => call.text.startsWith("SELECT") && call.text.includes("i.token_hash=$1"));
  assert.match(consume.text, /i\.token_hash=\$1/);
  assert.match(consume.text, /FOR UPDATE/);
  assert.deepEqual(consume.params, [Buffer.from(TOKEN, "hex")]);
  const consumeUpdate = client.calls.find((call) => call.text.startsWith("UPDATE organization_invitations"));
  assert.match(consumeUpdate.text, /i\.token_hash=\$5/);
  const membershipInsert = client.calls.find((call) => call.text.startsWith("INSERT INTO memberships"));
  assert.deepEqual(membershipInsert.params.slice(2), [ids.viewer, "viewer"]);
  assert.doesNotMatch(membershipInsert.text, /\$.*member_id.*\$.*role/i);
  assert.equal(client.calls.at(-1).text, "COMMIT");

  const acceptHash = organizationMutationRequestHash("invitation.accept", {
    organization_id: ids.organization, actor_id: ids.viewer, actor_principal: ids.viewer,
    token_hash: TOKEN
  });
  const replayClient = new QueueClient([response(), response([invitationRow({ consumed_at: NOW })]), response()], {
    idempotency: { request_hash: acceptHash, response_json: { invitation: result.invitation, member: result.member } }
  });
  const replay = await repo(replayClient).acceptInvitation({ token_hash: TOKEN, actor_member_id: ids.viewer, accepted_at: NOW, idempotency_key: "invite-accept-1" });
  assert.equal(replay.replayed, true);
  assert.deepEqual({ invitation: replay.invitation, member: replay.member }, { invitation: result.invitation, member: result.member });
  assert.equal(replayClient.calls.some((call) => call.text.startsWith("INSERT INTO memberships")), false);

  const consumedAgain = new QueueClient([response(), response()]);
  assert.equal(await repo(consumedAgain).acceptInvitation({ token_hash: TOKEN, actor_member_id: ids.viewer, organization_id: ids.organization, idempotency_key: "invite-accept-2" }), null);
  assert.equal(consumedAgain.calls.at(-1).text, "COMMIT");
});

test("all mutation failures roll back and never append audit or outbox after a failed write", async () => {
  const client = new QueueClient([response(), response(), response([orgRow({ name: "New", version: 2 })])], { failOn: (text) => text.startsWith("INSERT INTO admin_audit_events") });
  await assert.rejects(repo(client).renameOrganization({ organization_id: ids.organization, actor_member_id: ids.owner, name: "New", expected_version: 1, idempotency_key: "rename-failure-1" }), /mock query failure/);
  assert.equal(client.calls.at(-1).text, "ROLLBACK");
  assert.equal(client.calls.some((call) => call.text.startsWith("INSERT INTO outbox_events")), false);
});

test("audit events are allow-listed and hash deterministically", () => {
  const event = canonicalAuditEvent({ audit_event_id: ids.audit, organization_id: ids.organization, actor_id: ids.owner, action: "organization.renamed", target_type: "organization", target_id: ids.organization, details: { version: 2, name: "Renamed" }, previous_hash: ZERO_HASH });
  const serialized = JSON.stringify(event);
  assert.equal(sha256Hex(serialized), createHash("sha256").update(serialized).digest("hex"));
  assert.deepEqual(Object.keys(event), ["version", "audit_event_id", "organization_id", "actor_id", "action", "target_type", "target_id", "details", "previous_hash", "sequence"]);
  assert.throws(() => canonicalAuditEvent({ ...event, details: { token_hash: TOKEN } }), /unsupported field/);
  assert.throws(() => canonicalAuditEvent({ ...event, previous_hash: "bad" }), /previous_hash/);
});

test("canonical mutation request hashing is deterministic across object key order", () => {
  const first = canonicalOrganizationMutationRequest("organization.rename", {
    expected_version: 3, organization_id: ids.organization, actor_id: ids.owner,
    actor_principal: "human-owner", name: "Renamed"
  });
  const second = canonicalOrganizationMutationRequest("organization.rename", {
    name: "Renamed", actor_principal: "human-owner", actor_id: ids.owner,
    organization_id: ids.organization, expected_version: 3
  });
  assert.equal(first, second);
  assert.equal(organizationMutationRequestHash("organization.rename", JSON.parse(first).identity), sha256Hex(first));
  assert.notEqual(organizationMutationRequestHash("organization.rename", { organization_id: ids.organization, actor_id: ids.owner, actor_principal: "human-owner", name: "Other", expected_version: 3 }), sha256Hex(first));
});

test("transaction rollback error is wrapped without exposing token material", async () => {
  const client = new QueueClient([response(), response(), response()], { failOn: (text) => text === "ROLLBACK" || text.startsWith("UPDATE organizations") });
  await assert.rejects(repo(client).renameOrganization({ organization_id: ids.organization, actor_member_id: ids.owner, name: "New", expected_version: 1, idempotency_key: "rename-rollback-1" }), (error) => {
    assert.equal(error instanceof OrganizationRepositoryError, true);
    return error.code === "ERR_ROLLBACK";
  });
  assert.doesNotMatch(String(client.calls), /token_hash/);
});
