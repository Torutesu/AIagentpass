import assert from "node:assert/strict";
import test from "node:test";

import {
  AuthorityReductionAuditError,
  AUTHORITY_REDUCTION_AUDIT_EVENTS,
  createAuthorityReductionAuditAppender,
  authorityReductionAuditIdentity
} from "../../src/postgres/authority-reduction-audit.mjs";

const ids = {
  organization: "11111111-1111-4111-8111-111111111111",
  actor: "22222222-2222-4222-8222-222222222222",
  target: "33333333-3333-4333-8333-333333333333"
};
const base = {
  tx: { query: async () => { throw new Error("tx must be passed through"); } },
  organizationId: ids.organization,
  actor: { member_id: ids.actor },
  resource: { type: "member", id: ids.target },
  eventType: "member.role_reduced",
  mutationKey: "member-reduction-0001",
  occurredAt: "2026-08-13T00:00:00.000Z",
  reason: "operator_request",
  source: "admin_api",
  metadata: { previous_role: "admin", new_role: "viewer" }
};

function stored() {
  return {
    audit_event_id: "44444444-4444-4444-8444-444444444444",
    organization_id: ids.organization,
    event_type: "member.role_reduced",
    actor_id: ids.actor,
    target_type: "member",
    target_id: ids.target,
    event_hash: "a".repeat(64),
    recorded_at: "2026-08-13T00:00:01.000Z"
  };
}

test("appends only through the caller-owned tx with a stable audit idempotency key", async () => {
  const calls = [];
  const tx = { query: async () => undefined };
  const repository = { appendAdminAuditEventInTransaction: async (input) => { calls.push(input); return stored(); } };
  const appender = createAuthorityReductionAuditAppender({ adminAuditRepository: repository });
  const result = await appender.appendAuthorityReductionAudit({ ...base, tx });
  assert.deepEqual(result, stored());
  assert.equal(calls.length, 1);
  assert.equal(calls[0].tx, tx);
  assert.equal(calls[0].idempotencyKey, "member-reduction-0001:audit");
  assert.deepEqual(calls[0].details, {
    occurred_at: base.occurredAt,
    reason: base.reason,
    source: base.source,
    previous_role: "admin",
    new_role: "viewer"
  });
});

test("allows only the bounded authority-reduction event matrix", async () => {
  const calls = [];
  const appender = createAuthorityReductionAuditAppender({ adminAuditRepository: {
    appendAdminAuditEventInTransaction: async (input) => { calls.push(input); return stored(); }
  } });
  await assert.rejects(appender.appendAuthorityReductionAudit({ ...base, eventType: "organization.updated" }), { code: "ERR_AUTHORITY_REDUCTION_AUDIT_INPUT" });
  await assert.rejects(appender.appendAuthorityReductionAudit({ ...base, eventType: "policy.disabled", resource: { type: "member", id: ids.target }, metadata: {} }), { code: "ERR_AUTHORITY_REDUCTION_AUDIT_INPUT" });
  assert.equal(calls.length, 0);
  assert.ok(Object.isFrozen(AUTHORITY_REDUCTION_AUDIT_EVENTS));
});

test("rejects invalid actor and resource metadata before database integration", async () => {
  let calls = 0;
  const appender = createAuthorityReductionAuditAppender({ adminAuditRepository: { appendAdminAuditEventInTransaction: async () => { calls += 1; return stored(); } } });
  for (const patch of [
    { actor: { member_id: ids.actor, role: "admin" }, resource: { type: "member", id: ids.target } },
    { actor: { member_id: "not-a-uuid" } },
    { resource: { type: "member", id: "not-a-uuid" } },
    { resource: { type: "member", id: ids.target }, metadata: { secret: "x" } }
  ]) {
    await assert.rejects(appender.appendAuthorityReductionAudit({ ...base, ...patch }), { code: "ERR_AUTHORITY_REDUCTION_AUDIT_INPUT" });
  }
  assert.equal(calls, 0);
});

test("rejects unknown metadata and secret-like values", async () => {
  const appender = createAuthorityReductionAuditAppender({ adminAuditRepository: { appendAdminAuditEventInTransaction: async () => stored() } });
  await assert.rejects(appender.appendAuthorityReductionAudit({ ...base, metadata: { previous_role: "admin", new_role: "viewer", token: "secret" } }), { code: "ERR_AUTHORITY_REDUCTION_AUDIT_INPUT" });
  await assert.rejects(appender.appendAuthorityReductionAudit({ ...base, reason: "contains\ncontrol" }), { code: "ERR_AUTHORITY_REDUCTION_AUDIT_INPUT" });
});

test("fails closed when the underlying audit append fails or returns malformed data", async () => {
  const failing = createAuthorityReductionAuditAppender({ adminAuditRepository: { appendAdminAuditEventInTransaction: async () => { throw new Error("db password leaked"); } } });
  await assert.rejects(failing.appendAuthorityReductionAudit(base), (error) => error instanceof AuthorityReductionAuditError
    && error.code === "ERR_AUTHORITY_REDUCTION_AUDIT_UNAVAILABLE"
    && !error.message.includes("password"));
  const malformed = createAuthorityReductionAuditAppender({ adminAuditRepository: { appendAdminAuditEventInTransaction: async () => ({}) } });
  await assert.rejects(malformed.appendAuthorityReductionAudit(base), { code: "ERR_AUTHORITY_REDUCTION_AUDIT_INVALID" });
});

test("produces a stable identity for retries of the same mutation", () => {
  const one = authorityReductionAuditIdentity({ organizationId: ids.organization, actorId: ids.actor, eventType: base.eventType, resourceType: "member", resourceId: ids.target, mutationKey: base.mutationKey });
  const two = authorityReductionAuditIdentity({ organizationId: ids.organization, actorId: ids.actor, eventType: base.eventType, resourceType: "member", resourceId: ids.target, mutationKey: base.mutationKey });
  const changed = authorityReductionAuditIdentity({ organizationId: ids.organization, actorId: ids.actor, eventType: base.eventType, resourceType: "member", resourceId: ids.target, mutationKey: "member-reduction-0002" });
  assert.match(one, /^[0-9a-f]{64}$/);
  assert.equal(one, two);
  assert.notEqual(one, changed);
});
