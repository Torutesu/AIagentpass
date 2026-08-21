import assert from "node:assert/strict";
import test from "node:test";
import { createRecentAuthService } from "../src/human-auth/recent-auth.mjs";

const session = { session_id: "11111111-1111-4111-8111-111111111111", member_id: "22222222-2222-4222-8222-222222222222", organization_id: "33333333-3333-4333-8333-333333333333" };
const challengeId = "44444444-4444-4444-8444-444444444444";
const operation = "device.enrollment.issue";
const contextHash = "a".repeat(64);
const authenticatedAt = Date.parse("2026-08-12T00:00:00.000Z");

test("binds a verified ceremony to the session and consumes one exact operation authorization", async () => {
  let grant;
  const ceremony = { begin(input) { return { challenge_id: challengeId, ...input }; }, async consume() { return { assertion_id: challengeId, authenticated_at: authenticatedAt }; } };
  const repository = {
    async bindRecentAuth(input) { grant = { ...input, consumed: false }; return true; },
    async consumeRecentAuth(input) {
      if (!grant || grant.consumed || grant.session_id !== input.session_id || grant.challenge_id !== input.challenge_id || grant.member_id !== input.member_id || grant.organization_id !== input.organization_id || grant.operation !== input.operation) return null;
      grant.consumed = true;
      return grant;
    }
  };
  const service = createRecentAuthService({ ceremony, sessionRepository: repository });
  assert.equal(service.begin({ session, organization_id: session.organization_id, operation, rp_id: "console.example.test", origin: "https://console.example.test" }).challenge_id, challengeId);
  const verified = await service.verify({ session, organization_id: session.organization_id, operation, assertion: {} });
  assert.equal(verified.authorization_id, challengeId);
  const input = { proof: challengeId, principal: { session_id: session.session_id, member_id: session.member_id }, organization_id: session.organization_id, operation, now: authenticatedAt };
  assert.deepEqual(await service.authorize(input), { verified: true, consumed: true, challenge_id: challengeId, member_id: session.member_id, organization_id: session.organization_id, operation, authenticated_at: authenticatedAt });
  assert.equal((await service.authorize(input)).verified, false, "authorization must be single-use");
});

test("rejects proof consumption from another session of the same member", async () => {
  let consumed = false;
  const service = createRecentAuthService({
    ceremony: { begin() {}, async consume() { return { assertion_id: challengeId, authenticated_at: authenticatedAt }; } },
    sessionRepository: {
      async bindRecentAuth() { return true; },
      async consumeRecentAuth(input) {
        if (input.session_id !== session.session_id || consumed) return null;
        consumed = true;
        return { authenticated_at: new Date(authenticatedAt).toISOString() };
      }
    }
  });
  const result = await service.authorize({
    proof: challengeId,
    principal: { session_id: "55555555-5555-4555-8555-555555555555", member_id: session.member_id },
    organization_id: session.organization_id,
    operation,
    now: authenticatedAt
  });
  assert.equal(result.verified, false);
  assert.equal(consumed, false);
});

test("rejects cross-tenant, cross-operation, and malformed authorizations without widening context", async () => {
  const service = createRecentAuthService({ ceremony: { begin() {}, async consume() { return { assertion_id: challengeId, authenticated_at: authenticatedAt }; } }, sessionRepository: { async bindRecentAuth() { return true; }, async consumeRecentAuth() { return null; } } });
  await assert.rejects(() => service.verify({ session, organization_id: "55555555-5555-4555-8555-555555555555", operation, assertion: {} }), /session is invalid/);
  for (const proof of ["bad", challengeId]) {
    const result = await service.authorize({ proof, principal: { session_id: session.session_id, member_id: session.member_id }, organization_id: session.organization_id, operation: "organization.emergency_stop", now: authenticatedAt });
    assert.equal(result.verified, false);
    assert.equal(result.consumed, false);
  }
});

test("binds an optional resource context through begin, verify, and authorize", async () => {
  const calls = [];
  const ceremony = {
    begin(input) { calls.push(["begin", input]); return { challenge_id: challengeId, ...input }; },
    async consume(input) { calls.push(["consume", input]); return { assertion_id: challengeId, authenticated_at: authenticatedAt, context_hash: contextHash }; }
  };
  let grant;
  const repository = {
    async bindRecentAuth(input) { calls.push(["bind", input]); grant = { ...input, authenticated_at: new Date(authenticatedAt).toISOString(), context_hash: input.context_hash }; return true; },
    async consumeRecentAuth(input) { calls.push(["consumeRecentAuth", input]); return input.context_hash === contextHash ? { authenticated_at: new Date(authenticatedAt).toISOString(), context_hash: input.context_hash } : null; }
  };
  const service = createRecentAuthService({ ceremony, sessionRepository: repository });
  const beginResult = service.begin({ session, organization_id: session.organization_id, operation, context_hash: contextHash, rp_id: "console.example.test", origin: "https://console.example.test" });
  assert.equal(beginResult.context_hash, contextHash);
  const verified = await service.verify({ session, organization_id: session.organization_id, operation, context_hash: contextHash, assertion: {} });
  assert.equal(verified.context_hash, contextHash);
  assert.equal(grant.context_hash, contextHash);
  const authorized = await service.authorize({ proof: challengeId, principal: { session_id: session.session_id, member_id: session.member_id }, organization_id: session.organization_id, operation, context_hash: contextHash, now: authenticatedAt });
  assert.equal(authorized.context_hash, contextHash);
  assert.equal(calls[0][1].context_hash, contextHash);
  assert.equal(calls[1][1].context_hash, contextHash);
  assert.equal(calls.at(-1)[1].context_hash, contextHash);
  await assert.rejects(() => service.verify({ session, organization_id: session.organization_id, operation, context_hash: "b".repeat(64), assertion: {} }), /context binding/);
  await assert.rejects(() => service.verify({ session, organization_id: session.organization_id, operation, context_hash: "A".repeat(64), assertion: {} }), /context_hash is invalid/);
});

test("preserves PostgreSQL Date millisecond precision in an authorization", async () => {
  const precise = new Date("2026-08-12T00:00:00.137Z");
  const service = createRecentAuthService({
    ceremony: { begin() {}, async consume() {} },
    sessionRepository: {
      async bindRecentAuth() { return true; },
      async consumeRecentAuth() { return { authenticated_at: precise }; },
    },
  });
  const result = await service.authorize({
    proof: challengeId,
    principal: { session_id: session.session_id, member_id: session.member_id },
    organization_id: session.organization_id,
    operation,
    now: precise.getTime() + 1,
  });
  assert.equal(result.authenticated_at, precise.getTime());
});

test("enforces recent-auth freshness and returned principal bindings in the service boundary", async () => {
  const now = authenticatedAt + 1;
  let mode = "stale";
  const service = createRecentAuthService({
    ceremony: { begin() {}, async consume() {} },
    sessionRepository: {
      async bindRecentAuth() { return true; },
      async consumeRecentAuth() {
        if (mode === "stale") return { authenticated_at: now - 5 * 60 * 1000 - 1 };
        if (mode === "future") return { authenticated_at: now + 30 * 1000 + 1 };
        return { authenticated_at: now, session_id: "55555555-5555-4555-8555-555555555555" };
      }
    }
  });
  const input = { proof: challengeId, principal: { session_id: session.session_id, member_id: session.member_id }, organization_id: session.organization_id, operation, now };

  assert.equal((await service.authorize(input)).verified, false);
  mode = "future";
  assert.equal((await service.authorize(input)).verified, false);
  mode = "principal-substitution";
  assert.equal((await service.authorize(input)).verified, false);
});
