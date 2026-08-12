import assert from "node:assert/strict";
import test from "node:test";
import {
  createPostgresIdentityResolver,
  IDENTITY_RESOLVER_ERROR_CODES,
  IdentityResolutionError
} from "../src/human-auth/identity/postgres-resolver.mjs";

const ids = {
  organization: "11111111-1111-4111-8111-111111111111",
  member: "22222222-2222-4222-8222-222222222222",
  membership: "33333333-3333-4333-8333-333333333333"
};
const subject = "github-subject-42";
const NOW = 1_800_000_000_000;

function row(extra = {}) {
  return {
    provider: "github",
    member_id: ids.member,
    subject,
    membership_id: ids.membership,
    organization_id: ids.organization,
    role: "owner",
    ...extra
  };
}

function failureWithStatus(expectedStatus) { return (error) => {
  assert.equal(error instanceof IdentityResolutionError, true);
  assert.equal(error.code, IDENTITY_RESOLVER_ERROR_CODES.RESOLUTION_FAILED);
  assert.equal(error.message, "Identity resolution failed");
  assert.equal(error.status, expectedStatus);
  return true;
}; }
const failure = failureWithStatus(401);

test("resolves the durable GitHub subject and active membership without trusting caller role/member fields", async () => {
  const calls = [];
  const resolver = createPostgresIdentityResolver({
    client: {
      async query(text, params) {
        calls.push({ text, params });
        return { rowCount: 1, rows: [row()] };
      }
    },
    now: () => NOW
  });

  const assertion = await resolver.resolveIdentity({ provider: "github", subject, organization_id: ids.organization });
  assert.deepEqual(Object.keys(assertion).sort(), ["expires_at", "issued_at", "version"]);
  assert.equal(Object.hasOwn(assertion, "member_id"), false);
  assert.equal(Object.hasOwn(assertion, "role"), false);
  assert.equal(Object.hasOwn(assertion, "subject"), false);
  assert.equal(Object.isFrozen(assertion), true);
  assert.deepEqual(calls[0].params, ["github", ids.organization, subject]);
  assert.match(calls[0].text, /ui\.provider\s*=\s*\$1/);
  assert.match(calls[0].text, /ui\.subject\s*=\s*\$3/);
  assert.match(calls[0].text, /ms\.organization_id\s*=\s*\$2::uuid/);
  assert.match(calls[0].text, /ms\.status\s*=\s*'active'/);
  assert.match(calls[0].text, /LIMIT 2/);

  assert.deepEqual(resolver.verifyAssertion(assertion, { now: NOW + 1_000 }), {
    provider: "github",
    subject,
    member_id: ids.member,
    membership_id: ids.membership,
    organization_id: ids.organization,
    role: "owner",
    assertion_expires_at: NOW + 30_000
  });
});

test("assertions are opaque, one-use, and cannot be replaced by a structural clone", async () => {
  const resolver = createPostgresIdentityResolver({
    client: { async query() { return { rowCount: 1, rows: [row()] }; } },
    now: () => NOW,
    assertionTtlMs: 10_000
  });
  const assertion = await resolver.resolveIdentity({ provider: "github", subject, organization_id: ids.organization });
  const clone = { ...assertion };

  assert.throws(() => resolver.verifyAssertion(clone, { now: NOW + 1 }), failure);
  assert.deepEqual(resolver.identityAdapter.verify(assertion, { now: NOW + 1 }).member_id, ids.member);
  assert.throws(() => resolver.verifyAssertion(assertion, { now: NOW + 2 }), failure);
});

test("expired assertions are burned and all public failures are constant", async () => {
  let current = NOW;
  const resolver = createPostgresIdentityResolver({
    client: { async query() { return { rowCount: 1, rows: [row()] }; } },
    now: () => current,
    assertionTtlMs: 1_000
  });
  const assertion = await resolver.resolveIdentity({ provider: "github", subject, organization_id: ids.organization });
  current = NOW + 1_000;
  assert.throws(() => resolver.verifyAssertion(assertion), failure);
  assert.throws(() => resolver.verifyAssertion(assertion), failure);

  const unavailable = createPostgresIdentityResolver({ client: { async query() { throw new Error("database details must not escape"); } }, now: () => NOW });
  const errors = await Promise.all([
    unavailable.resolveIdentity({ provider: "github", subject, organization_id: ids.organization }).catch((error) => error),
    unavailable.resolveIdentity({ provider: "github", subject, organization_id: ids.organization, member_id: ids.member }).catch((error) => error),
    unavailable.resolveIdentity({ provider: "github", subject, organization_id: "not-a-uuid" }).catch((error) => error),
    unavailable.resolveIdentity({ provider: "google", subject, organization_id: ids.organization }).catch((error) => error)
  ]);
  [503, 401, 401, 503].forEach((status, index) => assert.equal(failureWithStatus(status)(errors[index]), true));
  assert.equal(new Set(errors.map((error) => `${error.code}:${error.message}`)).size, 1);
});

test("rejects malformed or ambiguous database identity rows and bounded input", async () => {
  const invalidRows = [
    { role: "superuser" },
    { organization_id: "44444444-4444-4444-8444-444444444444" },
    { subject: "different-subject" },
    { member_id: "not-a-uuid" }
  ];
  for (const invalid of invalidRows) {
    const resolver = createPostgresIdentityResolver({ client: { async query() { return { rowCount: 1, rows: [row(invalid)] }; } }, now: () => NOW });
    await assert.rejects(() => resolver.resolveIdentity({ provider: "github", subject, organization_id: ids.organization }), failureWithStatus(503));
  }

  const ambiguous = createPostgresIdentityResolver({ client: { async query() { return { rowCount: 2, rows: [row(), row({ membership_id: "55555555-5555-4555-8555-555555555555" })] }; } }, now: () => NOW });
  await assert.rejects(() => ambiguous.resolveIdentity({ provider: "github", subject, organization_id: ids.organization }), failure);

  const resolver = createPostgresIdentityResolver({ client: { async query() { throw new Error("must not query"); } }, now: () => NOW });
  const badInputs = [
    { provider: "github", subject, organization_id: ids.organization, role: "owner" },
    { provider: "github", subject: "", organization_id: ids.organization },
    { provider: "github", subject: "x".repeat(256), organization_id: ids.organization },
    { provider: "github", subject, organization_id: "not-a-uuid" },
    { provider: "Google", subject, organization_id: ids.organization },
    { provider: "github", subject, organization_id: ids.organization, member_id: ids.member }
  ];
  for (const input of badInputs) await assert.rejects(() => resolver.resolveIdentity(input), failure);
});

test("constructor enforces a bounded assertion lifetime and a database client", () => {
  assert.throws(() => createPostgresIdentityResolver(), /database client/);
  assert.throws(() => createPostgresIdentityResolver({ client: { query() {} }, assertionTtlMs: 999 }), /assertion TTL/);
  assert.throws(() => createPostgresIdentityResolver({ client: { query() {} }, assertionTtlMs: 60_001 }), /assertion TTL/);
});

test("fails closed when the assertion expiry would exceed the safe integer range", async () => {
  const resolver = createPostgresIdentityResolver({
    client: { async query() { return { rowCount: 1, rows: [row()] }; } },
    now: () => Number.MAX_SAFE_INTEGER - 999
  });
  await assert.rejects(() => resolver.resolveIdentity({ provider: "github", subject, organization_id: ids.organization }), failureWithStatus(503));
});
