import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  OrganizationClientError,
  createOrganizationClient,
  getOrganizationVisibility,
  resolveOrganizationSelection,
} from "../app/organization-client.ts";

const organizationId = "11111111-1111-4111-8111-111111111111";
const secondOrganizationId = "22222222-2222-4222-8222-222222222222";
const memberId = "33333333-3333-4333-8333-333333333333";
const membershipId = "44444444-4444-4444-8444-444444444444";
const invitationId = "55555555-5555-4555-8555-555555555555";
const requestId = "66666666-6666-4666-8666-666666666666";
const recentAuthId = "77777777-7777-4777-8777-777777777777";
const csrf = "C".repeat(43);
const token = "T".repeat(43);
const date = "2026-08-12T00:00:00.000Z";

function sessionResponse() {
  return json({
    session: {
      version: 1,
      session_id: "88888888-8888-4888-8888-888888888888",
      member_id: memberId,
      organization_id: organizationId,
      role: "owner",
      created_at: date,
      expires_at: "2026-08-12T08:00:00.000Z",
      recent_auth_at: null,
    },
    csrf_token: csrf,
  }, 201);
}

function organization(id = organizationId, name = "AgentPass Team", version = 2) {
  return { organization_id: id, name, version, created_at: date, updated_at: date };
}

function member(role = "viewer", version = 3) {
  return { membership_id: membershipId, organization_id: organizationId, member_id: memberId, display_name: "佐藤", role, status: "active", version, created_at: date, updated_at: date };
}

function invitation(status = "pending", version = 1) {
  return { invitation_id: invitationId, organization_id: organizationId, role: "viewer", status, version, created_at: date, expires_at: "2026-08-19T00:00:00.000Z", accepted_at: null, accepted_member_id: null };
}

function json(value, status = 200) {
  return new Response(JSON.stringify(value), { status, headers: { "content-type": "application/json; charset=utf-8" } });
}

test("normalizes Organization resources and carries same-origin CSRF, cursor, and mutation headers", async () => {
  const calls = [];
  const fetchImpl = async (url, init) => {
    calls.push({ url: String(url), init });
    if (url === "/api/auth/session") return sessionResponse();
    if (url === "/api/auth/organizations?limit=10&cursor=next_page") return json({ request_id: requestId, organizations: [organization()], next_cursor: null });
    if (url === "/api/auth/organizations" && init.method === "POST") return json({ request_id: requestId, organization: organization(secondOrganizationId, "New Team", 1) }, 201);
    if (url === `/api/auth/organizations/${organizationId}`) return json({ request_id: requestId, organization: organization(organizationId, "Renamed Team", 3) });
    throw new Error(`unexpected ${url}`);
  };
  const client = createOrganizationClient({ fetchImpl });

  const page = await client.listOrganizations({ limit: 10, cursor: "next_page" });
  assert.equal(page.items[0].id, organizationId);
  assert.equal(page.items[0].createdAt, date);
  assert.equal(calls[1].init.headers.get("agentpass-csrf"), csrf);
  assert.equal(calls[1].init.credentials, "same-origin");
  assert.equal(calls[1].init.cache, "no-store");

  const created = await client.createOrganization({ name: "New Team", idempotencyKey: "create-team-1" });
  assert.equal(created.organization.id, secondOrganizationId);
  assert.equal(calls[2].init.headers.get("idempotency-key"), "create-team-1");
  assert.equal(calls[2].init.headers.get("if-match"), null);

  const renamed = await client.renameOrganization({ organizationId, name: "Renamed Team", expectedVersion: 2, idempotencyKey: "rename-team-1" });
  assert.equal(renamed.organization.name, "Renamed Team");
  assert.equal(calls[3].init.headers.get("if-match"), '"2"');
  assert.deepEqual(JSON.parse(calls[3].init.body), { name: "Renamed Team" });
});

test("supports members, invitations, role/remove, revoke, and accept with operation-bound recent auth", async () => {
  const calls = [];
  const recentAuthCalls = [];
  const fetchImpl = async (url, init) => {
    calls.push({ url: String(url), init });
    if (url === "/api/auth/session") return sessionResponse();
    if (url === `/api/auth/organizations/${organizationId}/members?limit=20`) return json({ request_id: requestId, members: [member()], next_cursor: null });
    if (url === `/api/auth/organizations/${organizationId}/invitations`) {
      if (init.method === "GET") return json({ request_id: requestId, invitations: [invitation()], next_cursor: null });
      return json({ request_id: requestId, invitation: invitation(), one_time_token: token }, 201);
    }
    if (url.endsWith(`/members/${memberId}/role`)) return json({ request_id: requestId, member: member("admin", 4) });
    if (url.endsWith(`/members/${memberId}/remove`)) return json({ request_id: requestId, member: member("admin", 5) });
    if (url.endsWith(`/invitations/${invitationId}/revoke`)) return json({ request_id: requestId, invitation: invitation("revoked", 2) });
    if (url === "/api/auth/invitations/accept") return json({ request_id: requestId, invitation: invitation("accepted", 2), member: member("viewer", 1) }, 201);
    throw new Error(`unexpected ${init.method} ${url}`);
  };
  const client = createOrganizationClient({
    fetchImpl,
    authorizeRecentAuthImpl: async (input) => {
      recentAuthCalls.push(input);
      return { authorization_id: recentAuthId };
    },
  });

  const members = await client.listMembers(organizationId, { limit: 20 });
  assert.equal(members.items[0].memberId, memberId);
  const invitations = await client.listInvitations(organizationId);
  assert.equal(invitations.items[0].id, invitationId);
  const created = await client.createInvitation({ organizationId, role: "viewer", expiresAt: "2026-08-19T00:00:00.000Z", idempotencyKey: "invite-team-1" });
  assert.equal(created.oneTimeToken, token);

  const role = await client.updateMemberRole({ organizationId, memberId, role: "admin", expectedVersion: 3, idempotencyKey: "role-team-1" });
  assert.equal(role.member.role, "admin");
  const roleCall = calls.find((call) => call.url.endsWith(`/members/${memberId}/role`));
  assert.equal(roleCall.init.headers.get("agentpass-recent-auth"), recentAuthId);
  assert.equal(roleCall.init.headers.get("if-match"), '"3"');
  assert.deepEqual(JSON.parse(roleCall.init.body), { role: "admin" });

  await client.removeMember({ organizationId, memberId, expectedVersion: 4, idempotencyKey: "remove-team-1" });
  const removeCall = calls.find((call) => call.url.endsWith(`/members/${memberId}/remove`));
  assert.equal(removeCall.init.headers.get("agentpass-recent-auth"), recentAuthId);
  assert.equal(removeCall.init.headers.get("if-match"), '"4"');
  assert.equal(removeCall.init.body, undefined);
  assert.deepEqual(recentAuthCalls.map((item) => item.operation), ["human.organizations.member.role.update", "human.organizations.member.remove"]);

  await client.revokeInvitation({ organizationId, invitationId, expectedVersion: 1, idempotencyKey: "revoke-team-1" });
  await client.acceptInvitation({ oneTimeToken: token, idempotencyKey: "accept-team-1" });
  for (const call of calls.filter((item) => item.url !== "/api/auth/session")) {
    assert.equal(call.init.headers.get("agentpass-csrf"), csrf);
    if (call.init.method !== "GET") assert.match(call.init.headers.get("idempotency-key"), /^[A-Za-z0-9._~-]{8,255}$/);
  }
});

test("rejects malformed data, maps conflicts, and does not persist invitation tokens", async () => {
  const malformed = createOrganizationClient({ fetchImpl: async (url) => {
    if (url === "/api/auth/session") return sessionResponse();
    return json({ request_id: requestId, organizations: [{ organization_id: organizationId, name: "bad", version: 1, created_at: date }] });
  } });
  await assert.rejects(() => malformed.listOrganizations(), (error) => error instanceof OrganizationClientError && error.code === "invalid_response");

  const conflict = createOrganizationClient({ fetchImpl: async (url) => {
    if (url === "/api/auth/session") return sessionResponse();
    return json({ error: { code: "version_conflict", message: "stale version" } }, 409);
  } });
  await assert.rejects(() => conflict.renameOrganization({ organizationId, name: "new", expectedVersion: 1, idempotencyKey: "conflict-1" }), (error) => error instanceof OrganizationClientError && error.code === "conflict" && error.status === 409 && error.serverCode === "version_conflict");

  const source = await readFile(new URL("../app/organization-client.ts", import.meta.url), "utf8");
  assert.doesNotMatch(source, /localStorage|sessionStorage|console\.(?:log|info|warn|error)/);
});

test("classifies expired and recent-auth failures for actionable organization UI states", async () => {
  const expired = createOrganizationClient({ fetchImpl: async (url) => {
    if (url === "/api/auth/session") return sessionResponse();
    return json({ error: { code: "invitation_expired", message: "Invitation expired" } }, 410);
  } });
  await assert.rejects(() => expired.revokeInvitation({ organizationId, invitationId, expectedVersion: 1, idempotencyKey: "expired-invite-1" }), (error) => error instanceof OrganizationClientError && error.code === "expired" && error.status === 410);

  const recentAuth = createOrganizationClient({
    fetchImpl: async (url) => {
      if (url === "/api/auth/session") return sessionResponse();
      throw new Error("request should not reach Cloud when authentication is cancelled");
    },
    authorizeRecentAuthImpl: async () => { throw new Error("passkey cancelled"); },
  });
  await assert.rejects(() => recentAuth.updateMemberRole({ organizationId, memberId, role: "admin", expectedVersion: 3, idempotencyKey: "recent-auth-1" }), (error) => error instanceof OrganizationClientError && error.code === "recent_auth_required");
});

test("drops the cached human session after an unauthorized organization response", async () => {
  let sessionCalls = 0;
  let organizationCalls = 0;
  const client = createOrganizationClient({ fetchImpl: async (url) => {
    if (url === "/api/auth/session") {
      sessionCalls += 1;
      return sessionResponse();
    }
    organizationCalls += 1;
    if (organizationCalls === 1) return json({ error: { code: "session_expired", message: "Session expired" } }, 401);
    return json({ request_id: requestId, organizations: [organization()], next_cursor: null });
  } });

  await assert.rejects(() => client.listOrganizations(), (error) => error instanceof OrganizationClientError && error.code === "unauthorized");
  const page = await client.listOrganizations();
  assert.equal(page.items[0].id, organizationId);
  assert.equal(sessionCalls, 2);
  assert.equal(organizationCalls, 2);
});

test("exposes least-privilege visibility for every organization role", () => {
  assert.deepEqual(getOrganizationVisibility("owner"), { canViewOrganization: true, canViewMembers: true, canViewInvitations: true, canManageOrganization: true, canManageMembers: true, canAssignOwner: true, canInvite: true, canRevokeInvitations: true });
  assert.deepEqual(getOrganizationVisibility("admin"), { canViewOrganization: true, canViewMembers: true, canViewInvitations: true, canManageOrganization: true, canManageMembers: true, canAssignOwner: false, canInvite: true, canRevokeInvitations: true });
  assert.deepEqual(getOrganizationVisibility("auditor"), { canViewOrganization: true, canViewMembers: true, canViewInvitations: true, canManageOrganization: false, canManageMembers: false, canAssignOwner: false, canInvite: false, canRevokeInvitations: false });
  assert.deepEqual(getOrganizationVisibility("viewer"), { canViewOrganization: true, canViewMembers: false, canViewInvitations: false, canManageOrganization: false, canManageMembers: false, canAssignOwner: false, canInvite: false, canRevokeInvitations: false });
});

test("resolves a workspace selection only from the server-returned tenant page", () => {
  const organizations = [
    { id: organizationId, name: "Current", version: 1, createdAt: date, updatedAt: date },
    { id: secondOrganizationId, name: "Second", version: 1, createdAt: date, updatedAt: date },
  ];
  assert.equal(resolveOrganizationSelection(organizations, secondOrganizationId)?.name, "Second");
  assert.equal(resolveOrganizationSelection(organizations, secondOrganizationId.toUpperCase())?.id, secondOrganizationId);
  assert.equal(resolveOrganizationSelection(organizations, "99999999-9999-4999-8999-999999999999"), undefined);
  assert.equal(resolveOrganizationSelection(organizations, "not-a-tenant"), undefined);
  assert.equal(resolveOrganizationSelection(organizations, undefined), undefined);
});
