import assert from "node:assert/strict";
import test from "node:test";
import { createHash } from "node:crypto";

import {
  OrganizationRepositoryError,
  canonicalAuditEvent,
  createPostgresOrganizationRepository,
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

class QueueClient {
  constructor(responses = [], { failOn = undefined } = {}) {
    this.responses = [...responses];
    this.failOn = failOn;
    this.calls = [];
  }

  async query(text, params = []) {
    this.calls.push({ text, params });
    if (this.failOn?.(text, params)) throw new Error("mock query failure");
    if (this.responses.length > 0) return this.responses.shift();
    return { rows: [], rowCount: 0 };
  }
}

function response(rows = [], rowCount = rows.length) { return { rows, rowCount }; }
function orgRow(overrides = {}) { return { organization_id: ids.organization, name: "Example", version: 1, created_at: NOW, updated_at: NOW, ...overrides }; }
function membershipRow(overrides = {}) { return { organization_id: ids.organization, membership_id: ids.membership, member_id: ids.owner, role: "owner", status: "active", version: 1, created_at: NOW, updated_at: NOW, ...overrides }; }
function invitationRow(overrides = {}) { return { organization_id: ids.organization, invitation_id: ids.invitation, role: "viewer", created_by: ids.admin, created_at: NOW, expires_at: LATER, consumed_at: null, revoked_at: null, version: 1, ...overrides }; }
function txResponses(...responses) { return [response(), response(), ...responses, response(), response(), response(), response(), response(), response()]; }

function repo(client, options = {}) { return createPostgresOrganizationRepository({ client, now: () => NOW, ...options }); }

test("exposes exactly the frozen organization API", () => {
  const repository = repo(new QueueClient());
  assert.equal(Object.isFrozen(repository), true);
  assert.deepEqual(Object.keys(repository).sort(), [
    "acceptInvitation", "createInvitation", "createOrganizationWithOwner", "listInvitations",
    "listMembers", "listOrganizationsForMember", "removeMember", "renameOrganization",
    "revokeInvitation", "updateMemberRole"
  ].sort());
  assert.throws(() => createPostgresOrganizationRepository({ client: {} }), /database client/);
  assert.throws(() => createPostgresOrganizationRepository({ client: new QueueClient(), now: "not-a-function" }), /now must be a function/);
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

test("lists organizations only through active memberships and returns no secret fields", async () => {
  const client = new QueueClient([response([orgRow({ token_hash: TOKEN, membership_id: ids.membership, role: "viewer", membership_version: 2, membership_created_at: NOW, membership_updated_at: NOW })])]);
  const result = await repo(client).listOrganizationsForMember({ member_id: ids.viewer });
  assert.deepEqual(result, [{ organization_id: ids.organization, name: "Example", version: 1, created_at: NOW, updated_at: NOW, membership_id: ids.membership, role: "viewer", membership_status: "active", membership_version: 2, membership_created_at: NOW, membership_updated_at: NOW }]);
  assert.equal(Object.hasOwn(result[0], "token_hash"), false);
  assert.match(client.calls[0].text, /m\.member_id=\$1 AND m\.status='active'/);
  assert.deepEqual(client.calls[0].params, [ids.viewer]);
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
  assert.deepEqual(client.calls[0].params, [ids.organization, ids.owner]);
});

test("creates an organization and owner, then appends audit and outbox in the same transaction", async () => {
  const client = new QueueClient([
    response(), response(), response([orgRow({ name: "New Org" })]), response([membershipRow({ member_id: ids.owner })]),
    response(), response([{ sequence: 0, event_hash: ZERO_HASH }]), response(), response(), response(), response()
  ]);
  const result = await repo(client).createOrganizationWithOwner({ organization_id: ids.organization, owner_member_id: ids.owner, name: "New Org", created_at: NOW });
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

test("rename and role mutations use optimistic versions and return null out of scope", async () => {
  const renameClient = new QueueClient([response(), response(), response()]);
  assert.equal(await repo(renameClient).renameOrganization({ organization_id: ids.organization, actor_member_id: ids.viewer, name: "Denied", expected_version: 1 }), null);
  assert.equal(renameClient.calls.at(-1).text, "COMMIT");
  const renameSql = renameClient.calls.find((call) => call.text.startsWith("UPDATE organizations"));
  assert.match(renameSql.text, /o\.version=\$3/);
  assert.match(renameSql.text, /actor\.role IN \('owner','admin'\)/);

  const roleClient = new QueueClient([response(), response(), response([membershipRow({ member_id: ids.viewer, role: "admin", version: 2 })]), response(), response([{ sequence: 0, event_hash: ZERO_HASH }]), response(), response(), response(), response()]);
  const role = await repo(roleClient).updateMemberRole({ organization_id: ids.organization, actor_member_id: ids.owner, member_id: ids.viewer, role: "admin", expected_version: 1 });
  assert.equal(role.role, "admin");
  const roleSql = roleClient.calls.find((call) => call.text.startsWith("UPDATE memberships"));
  assert.match(roleSql.text, /target\.version=\$3/);
  assert.match(roleSql.text, /target\.organization_id=\$1/);
  assert.deepEqual(roleSql.params.slice(0, 5), [ids.organization, ids.viewer, 1, "admin", ids.owner]);
});

test("removeMember is role-gated, versioned, tenant-scoped, and audit-bound", async () => {
  const client = new QueueClient([response(), response(), response([membershipRow({ member_id: ids.viewer, role: "viewer", status: "revoked", version: 2 })]), response(), response([{ sequence: 0, event_hash: ZERO_HASH }]), response(), response(), response(), response()]);
  const result = await repo(client).removeMember({ organization_id: ids.organization, actor_member_id: ids.owner, member_id: ids.viewer, expected_version: 1, removed_at: NOW });
  assert.equal(result.status, "revoked");
  const update = client.calls.find((call) => call.text.startsWith("UPDATE memberships"));
  assert.match(update.text, /status='revoked'/);
  assert.match(update.text, /actor\.status='active'/);
  assert.match(update.text, /target\.organization_id=\$1/);
  assert.equal(client.calls.filter((call) => call.text.startsWith("INSERT INTO admin_audit_events")).length, 1);
});

test("invitation creation and listing never return token hashes", async () => {
  const createClient = new QueueClient([response(), response(), response([invitationRow()]), response(), response([{ last_hash: ZERO_HASH }]), response(), response(), response(), response()]);
  const invitation = await repo(createClient).createInvitation({ organization_id: ids.organization, actor_member_id: ids.admin, invited_member_id: ids.viewer, role: "viewer", token_hash: TOKEN, expires_at: LATER });
  assert.equal(invitation.invitation_id, ids.invitation);
  assert.equal(Object.hasOwn(invitation, "token_hash"), false);
  const insert = createClient.calls.find((call) => call.text.startsWith("INSERT INTO organization_invitations"));
  assert.match(insert.text, /actor\.organization_id=\$1/);
  assert.ok(Buffer.isBuffer(insert.params[2]));
  assert.equal(insert.params[2].toString("hex"), TOKEN);

  const listClient = new QueueClient([response([invitationRow({ token_hash: TOKEN })])]);
  const listed = await repo(listClient).listInvitations({ organization_id: ids.organization, actor_member_id: ids.admin });
  assert.equal(listed[0].invitation_id, ids.invitation);
  assert.equal(listed[0].status, "pending");
  assert.equal(Object.hasOwn(listed[0], "token_hash"), false);
  assert.match(listClient.calls[0].text, /i\.organization_id=\$1/);
});

test("revokeInvitation is idempotence-safe through status, version, actor, and tenant predicates", async () => {
  const client = new QueueClient([response(), response(), response([invitationRow({ revoked_at: NOW, version: 2 })]), response(), response([{ last_hash: ZERO_HASH }]), response(), response(), response(), response()]);
  const result = await repo(client).revokeInvitation({ organization_id: ids.organization, actor_member_id: ids.admin, invitation_id: ids.invitation, expected_version: 1, revoked_at: NOW });
  assert.equal(result.revoked_at, NOW);
  const update = client.calls.find((call) => call.text.startsWith("UPDATE organization_invitations"));
  assert.match(update.text, /i\.revoked_at IS NULL AND i\.consumed_at IS NULL/);
  assert.deepEqual(update.params, [ids.organization, ids.invitation, 1, NOW, ids.admin, "revoked_by_operator"]);
});

test("acceptInvitation consumes the exact token once and uses only stored member and role", async () => {
  const client = new QueueClient([
    response(), response([invitationRow({ role: "viewer" })]), response(),
    response([membershipRow({ member_id: ids.viewer, role: "viewer", version: 2 })]), response([invitationRow({ consumed_at: NOW })]), response(), response([{ sequence: 0, event_hash: ZERO_HASH }]), response(), response(), response(), response()
  ]);
  const result = await repo(client).acceptInvitation({ token_hash: TOKEN, actor_member_id: ids.viewer, organization_id: ids.organization, member_id: ids.admin, role: "owner", accepted_at: NOW });
  assert.equal(result.member_id, ids.viewer);
  assert.equal(result.role, "viewer");
  const consume = client.calls.find((call) => call.text.startsWith("SELECT") && call.text.includes("i.token_hash=$1"));
  assert.match(consume.text, /i\.token_hash=\$1/);
  assert.match(consume.text, /i\.consumed_at IS NULL/);
  assert.deepEqual(consume.params, [Buffer.from(TOKEN, "hex"), NOW]);
  const consumeUpdate = client.calls.find((call) => call.text.startsWith("UPDATE organization_invitations"));
  assert.match(consumeUpdate.text, /i\.token_hash=\$5/);
  const membershipInsert = client.calls.find((call) => call.text.startsWith("INSERT INTO memberships"));
  assert.deepEqual(membershipInsert.params.slice(2), [ids.viewer, "viewer"]);
  assert.doesNotMatch(membershipInsert.text, /\$.*member_id.*\$.*role/i);
  assert.equal(client.calls.at(-1).text, "COMMIT");

  const consumedAgain = new QueueClient([response(), response()]);
  assert.equal(await repo(consumedAgain).acceptInvitation({ token_hash: TOKEN, actor_member_id: ids.viewer, organization_id: ids.organization }), null);
  assert.equal(consumedAgain.calls.at(-1).text, "COMMIT");
});

test("all mutation failures roll back and never append audit or outbox after a failed write", async () => {
  const client = new QueueClient([response(), response(), response([orgRow({ name: "New", version: 2 })])], { failOn: (text) => text.startsWith("INSERT INTO admin_audit_events") });
  await assert.rejects(repo(client).renameOrganization({ organization_id: ids.organization, actor_member_id: ids.owner, name: "New", expected_version: 1 }), /mock query failure/);
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

test("transaction rollback error is wrapped without exposing token material", async () => {
  const client = new QueueClient([response(), response(), response()], { failOn: (text) => text === "ROLLBACK" || text.startsWith("UPDATE organizations") });
  await assert.rejects(repo(client).renameOrganization({ organization_id: ids.organization, actor_member_id: ids.owner, name: "New", expected_version: 1 }), (error) => {
    assert.equal(error instanceof OrganizationRepositoryError, true);
    return error.code === "ERR_ROLLBACK";
  });
  assert.doesNotMatch(String(client.calls), /token_hash/);
});
