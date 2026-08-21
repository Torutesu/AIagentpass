import assert from "node:assert/strict";
import test from "node:test";
import { createHash } from "node:crypto";

import {
  OrganizationServiceError,
  ORGANIZATION_SERVICE_ERROR_CODES,
  createPostgresOrganizationService
} from "../src/human-auth/organizations/postgres-service.mjs";
import { createHumanCursorCodec } from "../src/human-auth/pagination/cursor-codec.mjs";

const ids = {
  organization: "11111111-1111-4111-8111-111111111111",
  organization2: "22222222-2222-4222-8222-222222222222",
  owner: "33333333-3333-4333-8333-333333333333",
  member: "44444444-4444-4444-8444-444444444444",
  invitation: "55555555-5555-4555-8555-555555555555",
  invitation2: "66666666-6666-4666-8666-666666666666"
};
const NOW = "2026-08-12T00:00:00.000Z";
const EXPIRES = "2026-08-19T00:00:00.000Z";
const ACTOR = { session_id: "77777777-7777-4777-8777-777777777777", member_id: ids.owner, organization_id: ids.organization, role: "owner" };
const RAW_TOKEN = Buffer.alloc(32, 0xab).toString("base64url");
const RAW_TOKEN_2 = Buffer.alloc(32, 0xcd).toString("base64url");

function organization(overrides = {}) {
  return { organization_id: ids.organization, name: "Acme", version: 1, created_at: NOW, updated_at: NOW, ...overrides };
}

function member(overrides = {}) {
  return { organization_id: ids.organization, member_id: ids.member, membership_id: ids.member, role: "viewer", status: "active", version: 1, created_at: NOW, updated_at: NOW, ...overrides };
}

function invitation(overrides = {}) {
  return { organization_id: ids.organization, invitation_id: ids.invitation, role: "viewer", created_by: ids.owner, created_at: NOW, expires_at: EXPIRES, consumed_at: null, revoked_at: null, status: "pending", version: 1, token_hash: "secret", ...overrides };
}

function fixture(overrides = {}) {
  const calls = {};
  const defaults = {
    listOrganizationsForMember: () => [organization()],
    createOrganizationWithOwner: () => organization(),
    renameOrganization: () => organization({ name: "Renamed", version: 2 }),
    listMembers: () => [member()],
    updateMemberRole: () => member({ role: "admin", version: 2 }),
    removeMember: () => member({ status: "revoked", version: 2 }),
    listInvitations: () => [invitation()],
    createInvitation: () => invitation(),
    revokeInvitation: () => invitation({ revoked_at: NOW, status: "revoked", version: 2 }),
    acceptInvitation: () => member({ member_id: ids.owner, role: "viewer" })
  };
  const repository = {};
  for (const method of Object.keys(defaults)) {
    calls[method] = [];
    repository[method] = async (input) => {
      calls[method].push(input);
      const result = Object.hasOwn(overrides, method) ? overrides[method] : defaults[method];
      if (result instanceof Error) throw result;
      return typeof result === "function" ? result(input) : result;
    };
  }
  return { repository, calls };
}

function serviceFixture(overrides = {}) {
  const fixtureValue = fixture(overrides.repository);
  const uuidValues = [ids.invitation2];
  const service = createPostgresOrganizationService({
    repository: fixtureValue.repository,
    now: () => NOW,
    randomBytes: () => Buffer.alloc(32, 0xab),
    randomUUID: () => uuidValues.shift(),
    ...overrides.options
  });
  return { service, ...fixtureValue };
}

test("exposes exactly the ten organization service methods", () => {
  const { service } = serviceFixture();
  assert.equal(Object.isFrozen(service), true);
  assert.deepEqual(Object.keys(service).sort(), [
    "acceptInvitation", "createInvitation", "createOrganization", "listInvitations", "listMembers",
    "listOrganizations", "removeMember", "renameOrganization", "revokeInvitation", "updateMemberRole"
  ].sort());
  assert.throws(() => createPostgresOrganizationService({ repository: {} }), /missing/);
  assert.throws(() => createPostgresOrganizationService({ repository: serviceFixture().repository, now: "not-a-function" }), /now must be a function/);
});

test("returns bounded frozen pages and passes server-derived actor scope", async () => {
  const records = Array.from({ length: 4 }, (_, index) => organization({ organization_id: index % 2 === 0 ? ids.organization : ids.organization2 }));
  const { service, calls } = serviceFixture({ repository: { listOrganizationsForMember: records } });
  const result = await service.listOrganizations({ actor: ACTOR, limit: 2, cursor: "page-1" });
  assert.deepEqual(result.items, records.slice(0, 2));
  assert.equal(result.next_cursor, null);
  assert.equal(Object.isFrozen(result), true);
  assert.equal(Object.isFrozen(result.items), true);
  assert.deepEqual(calls.listOrganizationsForMember[0], { member_id: ids.owner, limit: 2, cursor: "page-1" });
  await assert.rejects(() => service.listMembers({ actor: ACTOR, organization_id: ids.organization, limit: 101 }), { code: "invalid_input" });
});

test("uses the human-v1 default cursor limit of 50", async () => {
  const { service, calls } = serviceFixture();
  await service.listOrganizations({ actor: ACTOR });
  assert.equal(calls.listOrganizationsForMember[0].limit, 50);
});

test("authenticates organization cursors and emits the next keyset position", async () => {
  const cursorCodec = createHumanCursorCodec({ secret: Buffer.alloc(32, 0x42) });
  const records = [
    organization({ organization_id: ids.organization, created_at: "2026-08-12T00:00:00.000Z" }),
    organization({ organization_id: ids.organization2, created_at: "2026-08-12T00:00:01.000Z" }),
    organization({ organization_id: ids.organization, created_at: "2026-08-12T00:00:02.000Z" })
  ];
  const { service, calls } = serviceFixture({ repository: { listOrganizationsForMember: records }, options: { cursorCodec } });
  const first = await service.listOrganizations({ actor: ACTOR, limit: 2 });
  assert.match(first.next_cursor, /^[A-Za-z0-9_-]+$/u);
  assert.deepEqual(cursorCodec.decode(first.next_cursor, { resource: "organizations", tenant_id: ACTOR.organization_id, member_id: ACTOR.member_id, direction: "asc" }), {
    version: 1,
    resource: "organizations",
    tenant_id: ACTOR.organization_id,
    member_id: ACTOR.member_id,
    created_at: records[1].created_at,
    id: records[1].organization_id,
    direction: "asc"
  });
  assert.deepEqual(calls.listOrganizationsForMember[0], { member_id: ACTOR.member_id, limit: 2 });

  await assert.rejects(() => service.listOrganizations({ actor: { ...ACTOR, member_id: ids.member }, limit: 2, cursor: first.next_cursor }), { code: ORGANIZATION_SERVICE_ERROR_CODES.INVALID_INPUT });
  await assert.rejects(() => service.listOrganizations({ actor: ACTOR, limit: 2, cursor: `${first.next_cursor.slice(0, -1)}!` }), { code: ORGANIZATION_SERVICE_ERROR_CODES.INVALID_INPUT });
});

test("binds member and invitation cursors to their own resources and keyset fields", async () => {
  const cursorCodec = createHumanCursorCodec({ secret: Buffer.alloc(32, 0x43) });
  const members = [
    member({ membership_id: ids.member, created_at: NOW }),
    member({ membership_id: ids.invitation, created_at: "2026-08-12T00:00:01.000Z" })
  ];
  const invitations = [
    invitation({ invitation_id: ids.invitation, created_at: NOW }),
    invitation({ invitation_id: ids.invitation2, created_at: "2026-08-12T00:00:01.000Z" })
  ];
  const { service, calls } = serviceFixture({ repository: { listMembers: members, listInvitations: invitations }, options: { cursorCodec } });
  const memberPage = await service.listMembers({ actor: ACTOR, organization_id: ids.organization, limit: 1 });
  const invitationPage = await service.listInvitations({ actor: ACTOR, organization_id: ids.organization, limit: 1 });
  assert.equal(cursorCodec.decode(memberPage.next_cursor, { resource: "members", tenant_id: ACTOR.organization_id, member_id: ACTOR.member_id, direction: "asc" }).id, ids.member);
  assert.equal(cursorCodec.decode(invitationPage.next_cursor, { resource: "invitations", tenant_id: ACTOR.organization_id, member_id: ACTOR.member_id, direction: "asc" }).id, ids.invitation);
  await service.listMembers({ actor: ACTOR, organization_id: ids.organization, limit: 1, cursor: memberPage.next_cursor });
  await service.listInvitations({ actor: ACTOR, organization_id: ids.organization, limit: 1, cursor: invitationPage.next_cursor });
  assert.deepEqual(calls.listMembers[1], { organization_id: ids.organization, actor_member_id: ids.owner, limit: 1, after_created_at: NOW, after_id: ids.member });
  assert.deepEqual(calls.listInvitations[1], { organization_id: ids.organization, actor_member_id: ids.owner, limit: 1, after_created_at: NOW, after_id: ids.invitation });
  await assert.rejects(() => service.listInvitations({ actor: ACTOR, organization_id: ids.organization, limit: 1, cursor: memberPage.next_cursor }), { code: ORGANIZATION_SERVICE_ERROR_CODES.INVALID_INPUT });
});

test("forwards mutation idempotency keys and injected timestamps and UUIDs", async () => {
  const { service, calls } = serviceFixture();
  const key = "mutation-key-1";
  await service.createOrganization({ actor: ACTOR, name: "New", idempotency_key: key });
  await service.renameOrganization({ actor: ACTOR, organization_id: ids.organization, name: "Renamed", expected_version: 1, idempotency_key: key });
  await service.updateMemberRole({ actor: ACTOR, organization_id: ids.organization, member_id: ids.member, role: "admin", expected_version: 1, idempotency_key: key });
  await service.removeMember({ actor: ACTOR, organization_id: ids.organization, member_id: ids.member, expected_version: 1, idempotency_key: key });
  await service.createInvitation({ actor: ACTOR, organization_id: ids.organization, role: "viewer", expires_at: EXPIRES, idempotency_key: key });
  await service.revokeInvitation({ actor: ACTOR, organization_id: ids.organization, invitation_id: ids.invitation, expected_version: 1, idempotency_key: key });
  await service.acceptInvitation({ actor: ACTOR, one_time_token: RAW_TOKEN, idempotency_key: key });

  assert.equal(Object.hasOwn(calls.createOrganizationWithOwner[0], "organization_id"), false);
  assert.equal(calls.createOrganizationWithOwner[0].created_at, NOW);
  assert.equal(calls.createOrganizationWithOwner[0].idempotency_key, key);
  assert.equal(calls.renameOrganization[0].idempotency_key, key);
  assert.equal(calls.renameOrganization[0].actor_session_id, ACTOR.session_id);
  assert.equal(calls.updateMemberRole[0].idempotency_key, key);
  assert.equal(calls.updateMemberRole[0].revoked_at, NOW);
  assert.equal(calls.removeMember[0].removed_at, NOW);
  assert.equal(calls.removeMember[0].idempotency_key, key);
  assert.equal(calls.createInvitation[0].invitation_id, ids.invitation2);
  assert.equal(calls.createInvitation[0].created_at, NOW);
  assert.equal(calls.createInvitation[0].idempotency_key, key);
  assert.equal(calls.createInvitation[0].actor_session_id, ACTOR.session_id);
  assert.equal(calls.revokeInvitation[0].revoked_at, NOW);
  assert.equal(calls.revokeInvitation[0].idempotency_key, key);
  assert.equal(calls.revokeInvitation[0].actor_session_id, ACTOR.session_id);
  assert.equal(calls.acceptInvitation[0].accepted_at, NOW);
  assert.equal(calls.acceptInvitation[0].idempotency_key, key);
});

test("stores only the SHA-256 hex invitation digest and returns raw token once", async () => {
  const { service, calls } = serviceFixture();
  const created = await service.createInvitation({ actor: ACTOR, organization_id: ids.organization, role: "viewer", expires_at: EXPIRES, idempotency_key: "invite-1" });
  assert.equal(created.raw_token, RAW_TOKEN);
  assert.equal(calls.createInvitation[0].token_hash, createHash("sha256").update(RAW_TOKEN).digest("hex"));
  assert.match(calls.createInvitation[0].token_hash, /^[0-9a-f]{64}$/u);
  assert.equal(Object.hasOwn(created.invitation, "token_hash"), false);
  assert.equal(JSON.stringify(created).includes(RAW_TOKEN), true);

  const replayFixture = serviceFixture({ repository: { createInvitation: () => ({ invitation: invitation(), replayed: true }) }, options: { randomBytes: () => Buffer.alloc(32, 0xcd) } });
  const replayed = await replayFixture.service.createInvitation({ actor: ACTOR, organization_id: ids.organization, role: "viewer", expires_at: EXPIRES, idempotency_key: "invite-1" });
  const expectedInvitation = { ...invitation() };
  delete expectedInvitation.token_hash;
  assert.deepEqual(replayed, { invitation: expectedInvitation, replayed: true });
  assert.equal(Object.hasOwn(replayed.invitation, "token_hash"), false);
  assert.equal(Object.hasOwn(replayed, "raw_token"), false);
});

test("hashes one-time tokens before acceptance and never returns token hashes", async () => {
  const { service, calls } = serviceFixture({ repository: { acceptInvitation: member({ token_hash: "secret" }) } });
  const result = await service.acceptInvitation({ actor: ACTOR, one_time_token: RAW_TOKEN, idempotency_key: "accept-1" });
  assert.equal(calls.acceptInvitation[0].token_hash, createHash("sha256").update(RAW_TOKEN).digest("hex"));
  assert.equal(Object.hasOwn(result, "token_hash"), false);
  assert.equal(JSON.stringify(result).includes("secret"), false);
});

test("turns repository nulls and failures into stable, non-secret service errors", async () => {
  const nullCases = [
    ["renameOrganization", "not_found"],
    ["updateMemberRole", "member_not_found"],
    ["revokeInvitation", "invitation_not_found"],
    ["acceptInvitation", "invitation_replayed"]
  ];
  for (const [method, code] of nullCases) {
    const overrides = { [method]: null };
    const { service } = serviceFixture({ repository: overrides });
    const operation = method === "renameOrganization"
      ? service.renameOrganization({ actor: ACTOR, organization_id: ids.organization, name: "x", expected_version: 1, idempotency_key: "test-key-1" })
      : method === "updateMemberRole"
        ? service.updateMemberRole({ actor: ACTOR, organization_id: ids.organization, member_id: ids.member, role: "viewer", expected_version: 1, idempotency_key: "test-key-1" })
        : method === "revokeInvitation"
          ? service.revokeInvitation({ actor: ACTOR, organization_id: ids.organization, invitation_id: ids.invitation, expected_version: 1, idempotency_key: "test-key-1" })
          : service.acceptInvitation({ actor: ACTOR, one_time_token: RAW_TOKEN, idempotency_key: "test-key-1" });
    await assert.rejects(operation, (error) => error instanceof OrganizationServiceError && error.code === code && !JSON.stringify(error).includes("token"));
  }

  const failure = Object.assign(new Error("database secret detail"), { code: "ERR_ROLLBACK" });
  const { service } = serviceFixture({ repository: { renameOrganization: failure } });
  await assert.rejects(
    () => service.renameOrganization({ actor: ACTOR, organization_id: ids.organization, name: "x", expected_version: 1, idempotency_key: "test-key-1" }),
    (error) => error.code === ORGANIZATION_SERVICE_ERROR_CODES.UNAVAILABLE && !JSON.stringify(error).includes("database secret detail")
  );

  const finalOwner = serviceFixture({ repository: { removeMember: Object.assign(new Error("constraint detail"), { code: "ERR_LAST_OWNER" }) } }).service;
  await assert.rejects(
    () => finalOwner.removeMember({ actor: ACTOR, organization_id: ids.organization, member_id: ids.owner, expected_version: 1, idempotency_key: "remove-owner-1" }),
    (error) => error.code === ORGANIZATION_SERVICE_ERROR_CODES.FORBIDDEN && !JSON.stringify(error).includes("constraint detail")
  );
});

test("preserves stale-versus-absent scope errors without exposing repository details", async () => {
  const cases = [
    ["ERR_VERSION_CONFLICT", ORGANIZATION_SERVICE_ERROR_CODES.VERSION_CONFLICT],
    ["ERR_MEMBER_NOT_FOUND", ORGANIZATION_SERVICE_ERROR_CODES.MEMBER_NOT_FOUND],
    ["ERR_FORBIDDEN", ORGANIZATION_SERVICE_ERROR_CODES.FORBIDDEN]
  ];
  for (const [repositoryCode, serviceCode] of cases) {
    const error = Object.assign(new Error("cross-tenant membership detail"), { code: repositoryCode });
    const { service } = serviceFixture({ repository: { updateMemberRole: error } });
    await assert.rejects(
      () => service.updateMemberRole({ actor: ACTOR, organization_id: ids.organization, member_id: ids.member, role: "admin", expected_version: 1, idempotency_key: "scope-error-1" }),
      (caught) => caught instanceof OrganizationServiceError && caught.code === serviceCode && !JSON.stringify(caught).includes("cross-tenant membership detail")
    );
  }
});
