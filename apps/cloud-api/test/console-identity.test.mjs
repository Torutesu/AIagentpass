import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";
import { createApiTokenRecord, generateApiToken } from "../src/auth.mjs";
import { createConsoleIdentityAdapter } from "../src/human-auth/console-identity.mjs";

const ids = { org: "11111111-1111-4111-8111-111111111111", member: "22222222-2222-4222-8222-222222222222" };

test("exchanges a BFF-only service token and verified upstream subject for a short assertion", async () => {
  const token = generateApiToken();
  const calls = [];
  const assertion = Object.freeze({ version: 1 });
  const identityResolver = { assertionTtlMs: 30_000, async resolveIdentity(input) { calls.push(input); return assertion; }, identityAdapter: { async verify(value) { assert.equal(value, assertion); return { member_id: ids.member, organization_id: ids.org, role: "viewer", assertion_expires_at: 1_800_000_030_000 }; } } };
  const adapter = createConsoleIdentityAdapter({ tokenRecords: [createApiTokenRecord({ token, tokenId: crypto.randomUUID(), organizationId: ids.org, memberId: ids.member, role: "owner" })], identityResolver });
  const issued = await adapter.verifyIdentityRequest({ headers: new Headers({ authorization: `Bearer ${token}`, "agentpass-console-user-id": "siwc-user-1" }) });
  assert.equal(issued, assertion);
  assert.deepEqual(calls, [{ provider: "chatgpt", subject: "siwc-user-1", organization_id: ids.org }]);
  assert.deepEqual(await adapter.identityAdapter.verify(issued, { now: 1_800_000_001_000 }), { member_id: ids.member, organization_id: ids.org, role: "viewer", assertion_expires_at: 1_800_000_030_000 });
  assert.equal(Object.hasOwn(assertion, "token"), false);
  assert.equal(Object.hasOwn(assertion, "authorization"), false);
});

test("fails closed on missing identity binding, bad service credentials, expiry, and mutation", async () => {
  const token = generateApiToken();
  const identityResolver = { assertionTtlMs: 30_000, async resolveIdentity() { throw new Error("not mapped"); }, identityAdapter: { async verify() { throw new Error("invalid assertion"); } } };
  const adapter = createConsoleIdentityAdapter({ tokenRecords: [createApiTokenRecord({ token, organizationId: ids.org, memberId: ids.member, role: "admin" })], identityResolver });
  await assert.rejects(() => adapter.verifyIdentityRequest({ headers: { authorization: `Bearer ${token}` } }));
  await assert.rejects(() => adapter.verifyIdentityRequest({ headers: { authorization: "Bearer wrong", "agentpass-console-user-id": "siwc-user-1" } }));
  await assert.rejects(() => adapter.verifyIdentityRequest({ headers: { authorization: `Bearer ${token}`, "agentpass-console-user-id": "siwc-user-1" } }));
});
