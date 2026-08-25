import test from "node:test";
import assert from "node:assert/strict";
import { createSmallSoftwareAuthorizationService, SMALL_SOFTWARE_ERROR_CODES } from "../src/small-software/index.mjs";

const ids = Array.from({ length: 12 }, (_, i) => `00000000-0000-4000-8000-${String(i + 1).padStart(12, "0")}`);
const org = ids[0], app = ids[1], owner = ids[2], member = ids[3], viewer = ids[4], share = ids[6];
const now = "2026-08-25T00:00:00.000Z";

function harness() {
  const rules = [], invitations = new Map(), shares = new Map(), operations = new Map();
  const repository = {
    testOnly: true,
    async getApplication() { return { id: app, organization_id: org, owner_member_id: owner, lifecycle_state: "active" }; },
    async listAccessRules() { return rules; },
    async saveAccessRule(value) { const index = rules.findIndex((x) => x.id === value.id || ((x.member_id ?? x.subject_id) === value.member_id && x.state === "active")); if (index >= 0) rules[index] = { ...rules[index], ...value }; else rules.push({ ...value }); return rules[index >= 0 ? index : rules.length - 1]; },
    async revokeAccessRule({ rule_id }) { const row = rules.find((x) => x.id === rule_id); if (row) row.state = "revoked"; return row; },
    async getInvitation({ invitation_id }) { return invitations.get(invitation_id); },
    async saveInvitation(value) { const id = value.invitation_id ?? value.id; invitations.set(id, { ...value, invitation_id: id }); return invitations.get(id); },
    async revokeInvitation({ invitation_id }) { const row = invitations.get(invitation_id); if (row) row.state = "revoked"; return row; },
    async getRoute() { return { organization_id: org, app_id: app, route: "/app", state: "active" }; },
    async getShare({ share_id }) { return shares.get(share_id); },
    async saveShare(value) { shares.set(value.share_id, { ...value }); return shares.get(value.share_id); },
    async revokeShare({ share_id }) { const row = shares.get(share_id); if (row) row.state = "revoked"; return row; },
    async getAuthorizationOperation({ organization_id, app_id, actor_member_id, idempotency_key }) { return operations.get([organization_id, app_id, actor_member_id, idempotency_key].join(":")); },
    async saveAuthorizationOperation(value) { operations.set([value.organization_id, value.app_id, value.actor_member_id, value.idempotency_key].join(":"), value); return value; },
  };
  let id = 6;
  return { repository, service: createSmallSoftwareAuthorizationService({ profile: "test", repository, clock: { testOnly: true, now: () => now }, uuid: { testOnly: true, randomUUID: () => ids[id++] ?? ids[11] } }), rules, invitations, shares };
}
const mutation = (actor_member_id = owner, extra = {}) => ({ organization_id: org, app_id: app, actor_member_id, idempotency_key: "auth-operation-001", ...extra });

test("owner is implicit and explicit grants resolve by highest role", async () => {
  const h = harness();
  assert.equal(await h.service.getRole({ organization_id: org, app_id: app, member_id: owner }), "owner");
  await h.service.grantAccess(mutation(owner, { member_id: member, role: "member" }));
  await h.service.grantAccess(mutation(owner, { member_id: viewer, role: "viewer", idempotency_key: "auth-operation-002" }));
  assert.equal(await h.service.getRole({ organization_id: org, app_id: app, member_id: member }), "member");
  assert.equal(await h.service.getRole({ organization_id: org, app_id: app, member_id: viewer }), "viewer");
});

test("grant idempotency returns the exact result and detects changed requests", async () => {
  const h = harness();
  const first = await h.service.grantAccess(mutation(owner, { member_id: member, role: "viewer" }));
  assert.deepEqual(await h.service.grantAccess(mutation(owner, { member_id: member, role: "viewer" })), first);
  await assert.rejects(() => h.service.grantAccess(mutation(owner, { member_id: member, role: "admin" })), (error) => error.code === SMALL_SOFTWARE_ERROR_CODES.IDEMPOTENCY_CONFLICT);
});

test("invitation is recipient-bound, one-shot, and revocable", async () => {
  const h = harness();
  const invitation = await h.service.invite(mutation(owner, { member_id: member, role: "viewer", idempotency_key: "auth-operation-003" }));
  await assert.rejects(() => h.service.acceptInvitation(mutation(viewer, { invitation_id: invitation.invitation_id, idempotency_key: "auth-operation-004" })), (error) => error.code === SMALL_SOFTWARE_ERROR_CODES.FORBIDDEN);
  const accepted = await h.service.acceptInvitation(mutation(member, { invitation_id: invitation.invitation_id, idempotency_key: "auth-operation-005" }));
  assert.equal(accepted.state, "accepted");
  await assert.rejects(() => h.service.acceptInvitation(mutation(member, { invitation_id: invitation.invitation_id, idempotency_key: "auth-operation-006" })), (error) => error.code === SMALL_SOFTWARE_ERROR_CODES.INVITATION_REVOKED);
});

test("route checks bind tenant, lifecycle, role, and action", async () => {
  const h = harness();
  await h.service.grantAccess(mutation(owner, { member_id: member, role: "member", idempotency_key: "auth-operation-007" }));
  assert.equal((await h.service.authorizeRoute({ organization_id: org, app_id: app, route: "/app", member_id: member, action: "write" })).allowed, true);
  assert.equal((await h.service.authorizeRoute({ organization_id: org, app_id: app, route: "/app", member_id: member, action: "manage_access" })).allowed, false);
  assert.equal((await h.service.authorizeRoute({ organization_id: ids[6], app_id: app, route: "/app", member_id: member })).allowed, false);
});

test("share links contain a revocable locator, never a bearer secret", async () => {
  const h = harness();
  const result = await h.service.createShareLink(mutation(owner, { route: "/app", idempotency_key: "auth-operation-008" }));
  assert.equal(result.share_id, share);
  assert.match(result.share_url, /\/share\/[0-9a-f-]+$/u);
  assert.equal(Object.keys(result).some((key) => /(token|secret|bearer|credential|password)/iu.test(key)), false);
  assert.equal((await h.service.authorizeRoute({ organization_id: org, app_id: app, route: "/app", share_id: result.share_id })).allowed, true);
  await h.service.revokeShareLink(mutation(owner, { share_id: result.share_id, idempotency_key: "auth-operation-009" }));
  assert.equal((await h.service.authorizeRoute({ organization_id: org, app_id: app, route: "/app", share_id: result.share_id })).allowed, false);
});
