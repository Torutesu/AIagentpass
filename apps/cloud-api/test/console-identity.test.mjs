import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";
import { createApiTokenRecord, generateApiToken } from "../src/auth.mjs";
import { createConsoleIdentityAdapter } from "../src/human-auth/console-identity.mjs";

const ids = { org: "11111111-1111-4111-8111-111111111111", member: "22222222-2222-4222-8222-222222222222" };

test("exchanges a BFF-only service token and verified upstream subject for a short assertion", async () => {
  const token = generateApiToken();
  const adapter = createConsoleIdentityAdapter({ tokenRecords: [createApiTokenRecord({ token, tokenId: crypto.randomUUID(), organizationId: ids.org, memberId: ids.member, role: "owner" })], now: () => 1_800_000_000_000 });
  const assertion = await adapter.verifyIdentityRequest({ headers: new Headers({ authorization: `Bearer ${token}`, "agentpass-console-user-id": "siwc-user-1" }) });
  assert.deepEqual(await adapter.identityAdapter.verify(assertion, { now: 1_800_000_001_000 }), { member_id: ids.member, organization_id: ids.org, role: "owner", assertion_expires_at: 1_800_000_030_000 });
  assert.equal(Object.hasOwn(assertion, "token"), false);
  assert.equal(Object.hasOwn(assertion, "authorization"), false);
});

test("fails closed on missing identity binding, bad service credentials, expiry, and mutation", async () => {
  const token = generateApiToken();
  const adapter = createConsoleIdentityAdapter({ tokenRecords: [createApiTokenRecord({ token, organizationId: ids.org, memberId: ids.member, role: "admin" })], now: () => 1_800_000_000_000 });
  await assert.rejects(() => adapter.verifyIdentityRequest({ headers: { authorization: `Bearer ${token}` } }));
  await assert.rejects(() => adapter.verifyIdentityRequest({ headers: { authorization: "Bearer wrong", "agentpass-console-user-id": "siwc-user-1" } }));
  const assertion = await adapter.verifyIdentityRequest({ headers: { authorization: `Bearer ${token}`, "agentpass-console-user-id": "siwc-user-1" } });
  await assert.rejects(() => adapter.identityAdapter.verify(assertion, { now: assertion.expires_at }));
  await assert.rejects(() => adapter.identityAdapter.verify({ ...assertion, role: "owner" }, { now: assertion.issued_at }));
  await assert.rejects(() => adapter.identityAdapter.verify({ ...assertion, extra: true }, { now: assertion.issued_at }));
});
