import assert from "node:assert/strict";
import test from "node:test";

import {
  PLATFORM_AUTH_ERROR_CODES,
  PLATFORM_RECENT_AUTH_HEADER,
  PLATFORM_WORKLOAD_IDENTITY_MAX_TTL_MS,
  PlatformAuthError,
  authorizePlatformOperation,
  createPlatformAuthenticator,
  platformRoleAllows,
  requirePlatformRole,
  verifyPlatformMtls,
  verifyPlatformWorkloadIdentity,
  verifyRecentPlatformWebAuthn
} from "../src/platform-auth.mjs";

const NOW = Date.parse("2026-08-20T00:00:00.000Z");
const PROOF = "11111111-1111-4111-8111-111111111111";
const MEMBER_ID = "member-platform-1";
const WORKLOAD_ID = "spiffe://agentpass.example/workload/platform-api";
const AUDIENCE = "agentpass.platform.promotion";
const FINGERPRINT = "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99";

function principal(overrides = {}) {
  return { member_id: MEMBER_ID, session_id: "session-platform-1", platform_role: "platform_operator", ...overrides };
}

function certificate(overrides = {}) {
  return {
    fingerprint256: FINGERPRINT,
    subjectaltname: `URI:${WORKLOAD_ID}`,
    valid_from: "Aug 19 00:00:00 2026 GMT",
    valid_to: "Aug 21 00:00:00 2026 GMT",
    ...overrides
  };
}

function request(overrides = {}) {
  return {
    headers: { "x-forwarded-client-cert": `URI:${WORKLOAD_ID}` },
    socket: {
      encrypted: true,
      authorized: true,
      authorizationError: undefined,
      getPeerCertificate: () => certificate()
    },
    ...overrides
  };
}

function validWebAuthn(overrides = {}) {
  return {
    authenticated_at: NOW,
    challenge_id: PROOF,
    consumed: true,
    member_id: MEMBER_ID,
    operation: "promotion.approve",
    verified: true,
    ...overrides
  };
}

function validWorkload(overrides = {}) {
  return { verified: true, workload_id: WORKLOAD_ID, audience: AUDIENCE, expires_at: NOW + 60_000, mtls_fingerprint256: FINGERPRINT, ...overrides };
}

test("platform role is separate from organization role", () => {
  assert.equal(platformRoleAllows("platform_operator", "platform_operator"), true);
  assert.equal(platformRoleAllows("platform_admin", "platform_operator"), true);
  assert.equal(platformRoleAllows("owner", "platform_operator"), false);
  assert.throws(() => requirePlatformRole({ role: "owner" }), (error) => error.code === PLATFORM_AUTH_ERROR_CODES.ROLE_REQUIRED);
  assert.throws(() => requirePlatformRole({ role: "owner", platform_role: "platform_auditor" }), (error) => error.code === PLATFORM_AUTH_ERROR_CODES.ROLE_DENIED);
  assert.deepEqual(requirePlatformRole(principal(), "platform_operator"), principal());
});

test("mTLS accepts only the authenticated TLS peer and pinned SPIFFE identity", () => {
  const identity = verifyPlatformMtls({ request: request(), expected: { fingerprint256: FINGERPRINT, spiffe_id: WORKLOAD_ID }, now: NOW });
  assert.deepEqual(identity, { fingerprint256: FINGERPRINT.toLowerCase(), spiffe_id: WORKLOAD_ID });
  for (const mutation of [
    { socket: { ...request().socket, encrypted: false } },
    { socket: { ...request().socket, authorized: false } },
    { socket: { ...request().socket, getPeerCertificate: () => ({}) } },
    { socket: { ...request().socket, getPeerCertificate: () => certificate({ fingerprint256: FINGERPRINT.replace("AA", "AB") }) } },
    { socket: { ...request().socket, getPeerCertificate: () => certificate({ subjectaltname: "DNS:untrusted.example" }) } }
  ]) {
    assert.throws(() => verifyPlatformMtls({ request: mutation, expected: { fingerprint256: FINGERPRINT, spiffe_id: WORKLOAD_ID }, now: NOW }), PlatformAuthError);
  }
});

test("mTLS rejects missing pins, expired certificates, and forwarded certificate headers", () => {
  assert.throws(() => verifyPlatformMtls({ request: request(), now: NOW }), (error) => error.code === PLATFORM_AUTH_ERROR_CODES.MTLS_INVALID);
  assert.throws(() => verifyPlatformMtls({ request: request({ socket: { ...request().socket, getPeerCertificate: () => certificate({ valid_to: "Aug 19 00:00:00 2026 GMT" }) } }), expected: { fingerprint256: FINGERPRINT, spiffe_id: WORKLOAD_ID }, now: NOW }), (error) => error.code === PLATFORM_AUTH_ERROR_CODES.MTLS_INVALID);
  assert.throws(() => verifyPlatformMtls({ request: { headers: { "x-forwarded-client-cert": `URI:${WORKLOAD_ID}` } }, expected: { fingerprint256: FINGERPRINT, spiffe_id: WORKLOAD_ID }, now: NOW }), (error) => error.code === PLATFORM_AUTH_ERROR_CODES.MTLS_REQUIRED);
});

test("custom mTLS verifiers cannot return an untyped or zero identity", async () => {
  for (const mtlsVerifier of [
    async () => ({ spiffe_id: WORKLOAD_ID }),
    async () => ({ fingerprint256: "00:".repeat(31) + "00", spiffe_id: WORKLOAD_ID }),
    async () => ({ fingerprint256: FINGERPRINT, spiffe_id: "spiffe://other.example/workload" })
  ]) {
    await assert.rejects(() => authorizePlatformOperation({
      request: request(),
      principal: principal(),
      mtls: { fingerprint256: FINGERPRINT, spiffe_id: WORKLOAD_ID },
      mtlsVerifier,
      workloadVerifier: async () => validWorkload(),
      recentAuthVerifier: async () => validWebAuthn(),
      proof: PROOF,
      workloadId: WORKLOAD_ID,
      audience: AUDIENCE,
      operation: "promotion.approve",
      now: NOW
    }), (error) => [PLATFORM_AUTH_ERROR_CODES.MTLS_INVALID, PLATFORM_AUTH_ERROR_CODES.MTLS_IDENTITY_MISMATCH].includes(error.code));
  }
});

test("workload identity requires a deployment verifier and exact result", async () => {
  let calls = 0;
  const result = await verifyPlatformWorkloadIdentity({
    request: request(),
    verifier: async (input) => { calls += 1; assert.equal(input.workload_id, WORKLOAD_ID); return validWorkload(); },
    workloadId: WORKLOAD_ID,
    audience: AUDIENCE,
    operation: "promotion.approve",
    now: NOW
  });
  assert.equal(calls, 1);
  assert.equal(result.verified, true);
  for (const value of [undefined, { verified: false, workload_id: WORKLOAD_ID, audience: AUDIENCE }, { verified: true, workload_id: "spiffe://other", audience: AUDIENCE }, { verified: true, workload_id: WORKLOAD_ID, extra: "claim" }, { verified: true, workload_id: WORKLOAD_ID, mtls_fingerprint256: FINGERPRINT }, { verified: true, workload_id: WORKLOAD_ID, audience: AUDIENCE, expires_at: NOW + 60_000 }]) {
    await assert.rejects(() => verifyPlatformWorkloadIdentity({ verifier: async () => value, workloadId: WORKLOAD_ID, audience: AUDIENCE, operation: "promotion.approve", now: NOW }), PlatformAuthError);
  }
  await assert.rejects(() => verifyPlatformWorkloadIdentity({ verifier: async () => validWorkload({ expires_at: NOW }), workloadId: WORKLOAD_ID, audience: AUDIENCE, operation: "promotion.approve", now: NOW }), (error) => error.code === PLATFORM_AUTH_ERROR_CODES.WORKLOAD_INVALID);
  await assert.rejects(() => verifyPlatformWorkloadIdentity({ verifier: async () => validWorkload({ expires_at: NOW + PLATFORM_WORKLOAD_IDENTITY_MAX_TTL_MS + 1 }), workloadId: WORKLOAD_ID, audience: AUDIENCE, operation: "promotion.approve", now: NOW }), (error) => error.code === PLATFORM_AUTH_ERROR_CODES.WORKLOAD_INVALID);
});

test("recent WebAuthn is operation-, principal-, consumption-, and freshness-bound", async () => {
  const calls = [];
  const result = await verifyRecentPlatformWebAuthn({
    verifier: async (input) => { calls.push(input); return validWebAuthn(); },
    proof: PROOF,
    principal: principal(),
    operation: "promotion.approve",
    now: NOW
  });
  assert.equal(result.verified, true);
  assert.equal(calls[0].operation, "promotion.approve");
  const normalizedIso = await verifyRecentPlatformWebAuthn({
    verifier: async () => validWebAuthn({ authenticated_at: new Date(NOW).toISOString() }),
    proof: PROOF,
    principal: principal(),
    operation: "promotion.approve",
    now: NOW
  });
  assert.equal(normalizedIso.authenticated_at, NOW);
  for (const mutation of [
    { challenge_id: "22222222-2222-4222-8222-222222222222" },
    { consumed: false },
    { operation: "promotion.promote" },
    { member_id: "other-member" },
    { authenticated_at: new Date(NOW - (5 * 60 * 1000) - 1).toISOString() },
    { verified: false },
    { extra: "claim" }
  ]) {
    await assert.rejects(() => verifyRecentPlatformWebAuthn({ verifier: async () => validWebAuthn(mutation), proof: PROOF, principal: principal(), operation: "promotion.approve", now: NOW }), PlatformAuthError);
  }
  let invoked = false;
  await assert.rejects(() => verifyRecentPlatformWebAuthn({ verifier: async () => { invoked = true; return validWebAuthn(); }, proof: "not-a-proof", principal: principal(), operation: "promotion.approve", now: NOW }), (error) => error.code === PLATFORM_AUTH_ERROR_CODES.WEBAUTHN_REQUIRED);
  assert.equal(invoked, false);
});

test("composed Platform authorization fails closed when any factor is absent or mismatched", async () => {
  const base = {
    request: request(),
    principal: principal({ role: "owner" }),
    mtls: { fingerprint256: FINGERPRINT, spiffe_id: WORKLOAD_ID },
    workloadVerifier: async () => validWorkload(),
    recentAuthVerifier: async () => validWebAuthn(),
    proof: PROOF,
    workloadId: WORKLOAD_ID,
    audience: AUDIENCE,
    operation: "promotion.approve",
    now: NOW
  };
  const authorized = await authorizePlatformOperation(base);
  assert.equal(authorized.principal.platform_role, "platform_operator");
  assert.equal(authorized.workload.workload_id, WORKLOAD_ID);
  for (const mutation of [
    { workloadVerifier: undefined, verifyWorkloadIdentity: undefined },
    { recentAuthVerifier: undefined },
    { proof: undefined },
    { workloadId: "spiffe://other/workload" },
    { mtls: { fingerprint256: FINGERPRINT, spiffe_id: "spiffe://other/workload" } },
    { principal: { role: "owner" } }
  ]) {
    await assert.rejects(() => authorizePlatformOperation({ ...base, ...mutation }), PlatformAuthError);
  }
});

test("composed authorization binds a verifier-attested mTLS fingerprint", async () => {
  await assert.rejects(() => authorizePlatformOperation({
    request: request(),
    principal: principal(),
    mtls: { fingerprint256: FINGERPRINT, spiffe_id: WORKLOAD_ID },
    workloadVerifier: async () => validWorkload({ mtls_fingerprint256: `BB${FINGERPRINT.slice(2)}` }),
    recentAuthVerifier: async () => validWebAuthn(),
    proof: PROOF,
    workloadId: WORKLOAD_ID,
    audience: AUDIENCE,
    operation: "promotion.approve",
    now: NOW
  }), (error) => error.code === PLATFORM_AUTH_ERROR_CODES.WORKLOAD_MISMATCH);
});

test("does not expose private verifier result fields", async () => {
  const result = await authorizePlatformOperation({
    request: request(),
    principal: principal(),
    mtls: { fingerprint256: FINGERPRINT, spiffe_id: WORKLOAD_ID },
    workloadVerifier: async () => validWorkload(),
    recentAuthVerifier: async () => validWebAuthn(),
    proof: PROOF,
    workloadId: WORKLOAD_ID,
    audience: AUDIENCE,
    operation: "promotion.approve",
    now: NOW
  });
  assert.equal("assertion" in result.webauthn, false);
  assert.equal("credential_public_key" in result.webauthn, false);
});

test("Platform authenticator composes the deployment principal, mTLS, workload, and WebAuthn seams", async () => {
  const calls = [];
  const authenticate = createPlatformAuthenticator({
    resolvePrincipal: async (input) => { calls.push(["principal", input.operation]); return principal(); },
    mtls: { fingerprint256: FINGERPRINT, spiffe_id: WORKLOAD_ID },
    workloadId: WORKLOAD_ID,
    audience: AUDIENCE,
    workloadVerifier: async (input) => { calls.push(["workload", input.operation]); return validWorkload(); },
    recentAuthVerifier: async (input) => { calls.push(["webauthn", input.operation, input.proof]); return validWebAuthn({ operation: input.operation, challenge_id: input.proof }); },
    now: () => NOW
  });
  const result = await authenticate({
    request: request(),
    headers: { [PLATFORM_RECENT_AUTH_HEADER]: PROOF },
    operation: "promotion.approve"
  });
  assert.equal(result.principal.platform_role, "platform_operator");
  assert.deepEqual(calls, [["principal", "promotion.approve"], ["workload", "promotion.approve"], ["webauthn", "promotion.approve", PROOF]]);
});

test("Platform authenticator exposes missing factor wiring as unavailable, never as an organization fallback", async () => {
  const base = {
    resolvePrincipal: async () => principal(),
    mtls: { fingerprint256: FINGERPRINT, spiffe_id: WORKLOAD_ID },
    workloadId: WORKLOAD_ID,
    audience: AUDIENCE,
    workloadVerifier: async () => validWorkload(),
    recentAuthVerifier: async ({ proof, operation }) => validWebAuthn({ challenge_id: proof, operation })
  };
  const cases = [
    [{ resolvePrincipal: undefined }, PLATFORM_AUTH_ERROR_CODES.PRINCIPAL_UNAVAILABLE],
    [{ mtls: undefined }, PLATFORM_AUTH_ERROR_CODES.MTLS_UNAVAILABLE],
    [{ workloadVerifier: undefined }, PLATFORM_AUTH_ERROR_CODES.WORKLOAD_UNAVAILABLE],
    [{ recentAuthVerifier: undefined }, PLATFORM_AUTH_ERROR_CODES.WEBAUTHN_UNAVAILABLE]
  ];
  for (const [override, code] of cases) {
    const authenticate = createPlatformAuthenticator({ ...base, ...override, now: () => NOW });
    await assert.rejects(
      () => authenticate({ request: request(), headers: { [PLATFORM_RECENT_AUTH_HEADER]: PROOF }, operation: "promotion.approve" }),
      (error) => error.code === code
    );
  }
});

test("Platform authenticator rejects duplicate recent-auth headers and passes one request clock to every factor", async () => {
  const observed = [];
  const authenticate = createPlatformAuthenticator({
    resolvePrincipal: async ({ now }) => { observed.push(now); return principal(); },
    mtls: { fingerprint256: FINGERPRINT, spiffe_id: WORKLOAD_ID },
    workloadId: WORKLOAD_ID,
    audience: AUDIENCE,
    workloadVerifier: async ({ now }) => { observed.push(now); return validWorkload({ expires_at: now + 60_000 }); },
    recentAuthVerifier: async ({ now, proof, operation }) => { observed.push(now); return validWebAuthn({ authenticated_at: now, challenge_id: proof, operation }); },
    now: () => NOW
  });
  const accepted = await authenticate({
    request: request(),
    headers: { [PLATFORM_RECENT_AUTH_HEADER]: PROOF },
    operation: "promotion.approve",
    now: NOW
  });
  assert.equal(accepted.principal.member_id, MEMBER_ID);
  assert.deepEqual(observed, [NOW, NOW, NOW]);
  await assert.rejects(() => authenticate({
    request: request(),
    headers: { [PLATFORM_RECENT_AUTH_HEADER]: PROOF, "AgentPass-Platform-Recent-Auth": PROOF },
    operation: "promotion.approve",
    now: NOW
  }), (error) => error.code === PLATFORM_AUTH_ERROR_CODES.WEBAUTHN_REQUIRED);
});
