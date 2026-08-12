import assert from "node:assert/strict";
import test from "node:test";

import {
  createHumanOrganizationsHttpApi,
  HUMAN_ORGANIZATION_SERVICE_METHODS,
  HUMAN_ORGANIZATIONS_RECENT_AUTH_OPERATIONS,
  HUMAN_ORGANIZATIONS_HTTP_ERROR_CODES,
  HUMAN_ORGANIZATIONS_HTTP_PATHS
} from "../src/human-auth/organizations/http-api.mjs";

const ORIGIN = "https://console.agentpass.test";
const SESSION_TOKEN = "s".repeat(43);
const CSRF_TOKEN = "c".repeat(43);
const INVITATION_TOKEN = "i".repeat(43);
const COOKIE = `__Host-agentpass_session=${SESSION_TOKEN}; Path=/; HttpOnly; Secure; SameSite=Strict`;
const ORGANIZATION_ID = "11111111-1111-4111-8111-111111111111";
const OTHER_ORGANIZATION_ID = "22222222-2222-4222-8222-222222222222";
const MEMBER_ID = "33333333-3333-4333-8333-333333333333";
const OTHER_MEMBER_ID = "44444444-4444-4444-8444-444444444444";
const INVITATION_ID = "55555555-5555-4555-8555-555555555555";
const RECENT_AUTH_PROOF = "77777777-7777-4777-8777-777777777777";
const CREATED_AT = "2026-08-12T00:00:00.000Z";
const NOW = 1_800_000_000_000;

function actor(overrides = {}) {
  return {
    session_id: "66666666-6666-4666-8666-666666666666",
    member_id: MEMBER_ID,
    organization_id: ORGANIZATION_ID,
    role: "owner",
    ...overrides
  };
}

function organization(overrides = {}) {
  return { organization_id: ORGANIZATION_ID, version: 1, name: "Acme", created_at: CREATED_AT, ...overrides };
}

function member(overrides = {}) {
  return { member_id: MEMBER_ID, organization_id: ORGANIZATION_ID, version: 1, role: "owner", status: "active", email: "owner@example.test", created_at: CREATED_AT, ...overrides };
}

function invitation(overrides = {}) {
  return { invitation_id: INVITATION_ID, organization_id: ORGANIZATION_ID, version: 1, role: "viewer", status: "pending", created_at: CREATED_AT, expires_at: "2026-08-19T00:00:00.000Z", ...overrides };
}

function service(overrides = {}) {
  const calls = Object.fromEntries(HUMAN_ORGANIZATION_SERVICE_METHODS.map((method) => [method, []]));
  const defaults = {
    async listOrganizations(input) { calls.listOrganizations.push(input); return { items: [organization()], next_cursor: null }; },
    async createOrganization(input) { calls.createOrganization.push(input); return organization({ name: input.name }); },
    async renameOrganization(input) { calls.renameOrganization.push(input); return organization({ name: input.name, version: input.expected_version + 1 }); },
    async listMembers(input) { calls.listMembers.push(input); return { items: [member()], next_cursor: null }; },
    async updateMemberRole(input) { calls.updateMemberRole.push(input); return member({ role: input.role, version: input.expected_version + 1 }); },
    async removeMember(input) { calls.removeMember.push(input); return member({ status: "revoked", version: input.expected_version + 1 }); },
    async listInvitations(input) { calls.listInvitations.push(input); return { items: [invitation()], next_cursor: null }; },
    async createInvitation(input) { calls.createInvitation.push(input); return { invitation: invitation({ role: input.role, expires_at: input.expires_at }), raw_token: INVITATION_TOKEN }; },
    async revokeInvitation(input) { calls.revokeInvitation.push(input); return invitation({ status: "revoked", version: input.expected_version + 1 }); },
    async acceptInvitation(input) { calls.acceptInvitation.push(input); return member({ role: "viewer" }); }
  };
  const result = {};
  for (const method of HUMAN_ORGANIZATION_SERVICE_METHODS) {
    result[method] = async (...args) => {
      calls[method].push(args[0]);
      if (overrides[method] instanceof Error) throw overrides[method];
      if (typeof overrides[method] === "function") return overrides[method](args[0]);
      if (overrides[method] !== undefined) return overrides[method];
      return defaults[method](args[0]);
    };
  }
  return { service: result, calls };
}

function fixture({ role = "owner", sessionError = undefined, serviceOverrides = {}, recentAuthService = undefined, api = {} } = {}) {
  const calls = { authenticate: [] };
  const { service: organizationService, calls: serviceCalls } = service(serviceOverrides);
  const humanSession = {
    expectedOrigin: ORIGIN,
    async authenticateRequest(input) {
      calls.authenticate.push(input);
      if (sessionError) throw sessionError;
      return { session: actor({ role }) };
    }
  };
  return {
    calls: { ...calls, ...serviceCalls },
    api: createHumanOrganizationsHttpApi({ humanSession, organizationService, origin: ORIGIN, ...api, ...(recentAuthService === undefined ? {} : { recentAuthService }) })
  };
}

function request(path, { method = "GET", body = undefined, headers = {} } = {}) {
  return {
    method,
    url: path,
    headers: {
      origin: ORIGIN,
      cookie: COOKIE,
      "agentpass-csrf": CSRF_TOKEN,
      ...(method === "GET" ? {} : { "content-type": "application/json", "idempotency-key": "test-key-1" }),
      ...headers
    },
    ...(body === undefined ? {} : { body: JSON.stringify(body) })
  };
}

function assertNoSecret(result, ...secrets) {
  const serialized = JSON.stringify(result.body);
  for (const secret of secrets) assert.equal(serialized.includes(secret), false);
  assert.equal(Object.hasOwn(result.headers, "Set-Cookie"), false);
}

test("requires the complete injected organization service interface", () => {
  for (const missing of HUMAN_ORGANIZATION_SERVICE_METHODS) {
    const partial = Object.fromEntries(HUMAN_ORGANIZATION_SERVICE_METHODS.filter((method) => method !== missing).map((method) => [method, () => undefined]));
    assert.throws(() => createHumanOrganizationsHttpApi({
      humanSession: { expectedOrigin: ORIGIN, authenticateRequest: async () => ({ session: actor() }) },
      organizationService: partial,
      origin: ORIGIN
    }), new RegExp(`organizationService is missing ${missing}`));
  }
});

test("validates recent-auth dependencies and exposes distinct frozen operations", () => {
  const { service: organizationService } = service();
  const humanSession = { expectedOrigin: ORIGIN, authenticateRequest: async () => ({ session: actor() }) };
  assert.throws(() => createHumanOrganizationsHttpApi({ humanSession, organizationService, origin: ORIGIN, recentAuthService: {} }), /recentAuthService must expose authorize/);
  assert.throws(() => createHumanOrganizationsHttpApi({ humanSession, organizationService, origin: ORIGIN, now: 1 }), /now must be a function/);
  assert.equal(Object.isFrozen(HUMAN_ORGANIZATIONS_RECENT_AUTH_OPERATIONS), true);
  assert.notEqual(HUMAN_ORGANIZATIONS_RECENT_AUTH_OPERATIONS.updateMemberRole, HUMAN_ORGANIZATIONS_RECENT_AUTH_OPERATIONS.removeMember);
});

test("requires an exact HTTPS Origin, valid session cookie, and CSRF on reads and writes", async () => {
  const cases = [
    [{ origin: "https://console.agentpass.test/" }, HUMAN_ORGANIZATIONS_HTTP_ERROR_CODES.ORIGIN_NOT_ALLOWED],
    [{ origin: "https://evil.test" }, HUMAN_ORGANIZATIONS_HTTP_ERROR_CODES.ORIGIN_NOT_ALLOWED],
    [{ origin: undefined }, HUMAN_ORGANIZATIONS_HTTP_ERROR_CODES.ORIGIN_NOT_ALLOWED],
    [{ cookie: "" }, HUMAN_ORGANIZATIONS_HTTP_ERROR_CODES.SESSION_REQUIRED],
    [{ "agentpass-csrf": "bad" }, HUMAN_ORGANIZATIONS_HTTP_ERROR_CODES.CSRF_FAILED]
  ];
  for (const [headers, code] of cases) {
    const { api } = fixture();
    const req = request(HUMAN_ORGANIZATIONS_HTTP_PATHS.organizations, { headers: Object.fromEntries(Object.entries(headers).filter(([, value]) => value !== undefined)) });
    if (Object.hasOwn(headers, "origin") && headers.origin === undefined) delete req.headers.origin;
    const result = await api.handle(req);
    assert.equal(result.status, code === HUMAN_ORGANIZATIONS_HTTP_ERROR_CODES.SESSION_REQUIRED ? 401 : 403);
    assert.equal(result.body.error.code, code);
  }
  const authFailure = fixture({ sessionError: { code: "csrf_token_required", message: "secret detail" } });
  const result = await authFailure.api.handle(request(HUMAN_ORGANIZATIONS_HTTP_PATHS.organizations));
  assert.equal(result.status, 403);
  assert.equal(result.body.error.code, HUMAN_ORGANIZATIONS_HTTP_ERROR_CODES.CSRF_FAILED);
  assertNoSecret(result, "secret detail");
});

test("lists organizations for every role and passes only server-derived actor scope", async () => {
  for (const role of ["owner", "admin", "auditor", "viewer"]) {
    const { api, calls } = fixture({ role });
    const result = await api.handle(request(`${HUMAN_ORGANIZATIONS_HTTP_PATHS.organizations}?limit=10&cursor=page-1`));
    assert.equal(result.status, 200);
    assert.deepEqual(result.body.organizations[0], organization());
    assert.deepEqual(calls.listOrganizations[0], { actor: actor({ role }), limit: 10, cursor: "page-1" });
  }
});

test("creates and renames organizations with strict schemas and optimistic versions", async () => {
  const { api, calls } = fixture();
  const created = await api.handle(request(HUMAN_ORGANIZATIONS_HTTP_PATHS.organizations, { method: "POST", body: { name: "New org" } }));
  assert.equal(created.status, 201);
  assert.equal(created.body.organization.name, "New org");
  assert.deepEqual(calls.createOrganization[0], { actor: actor(), name: "New org", idempotency_key: "test-key-1" });

  const renamed = await api.handle(request(HUMAN_ORGANIZATIONS_HTTP_PATHS.organization(ORGANIZATION_ID), { method: "PATCH", body: { name: "Renamed", expected_version: 3 } }));
  assert.equal(renamed.status, 200);
  assert.deepEqual(calls.renameOrganization[0], { actor: actor(), organization_id: ORGANIZATION_ID, name: "Renamed", expected_version: 3, idempotency_key: "test-key-1" });

  for (const body of [{ name: " padded" }, { expected_version: 1 }, { name: "x", expected_version: 0 }, { name: "x", expected_version: 1, extra: true }]) {
    const result = await api.handle(request(HUMAN_ORGANIZATIONS_HTTP_PATHS.organization(ORGANIZATION_ID), { method: "PATCH", body }));
    assert.equal(result.status, 400);
    assert.equal(result.body.error.code, HUMAN_ORGANIZATIONS_HTTP_ERROR_CODES.INVALID_REQUEST);
  }
});

test("allows every authenticated role to create a separate organization as its owner", async () => {
  for (const role of ["owner", "admin", "auditor", "viewer"]) {
    const { api, calls } = fixture({ role });
    const result = await api.handle(request(HUMAN_ORGANIZATIONS_HTTP_PATHS.organizations, { method: "POST", body: { name: "Independent org" } }));
    assert.equal(result.status, 201);
    assert.equal(calls.createOrganization[0].actor.role, role);
  }
});

test("requires idempotency keys for every mutation and expected versions for updates/revokes", async () => {
  const { api } = fixture();
  const mutations = [
    [HUMAN_ORGANIZATIONS_HTTP_PATHS.organizations, "POST", { name: "x" }],
    [HUMAN_ORGANIZATIONS_HTTP_PATHS.organization(ORGANIZATION_ID), "PATCH", { name: "x", expected_version: 1 }],
    [HUMAN_ORGANIZATIONS_HTTP_PATHS.memberRole(ORGANIZATION_ID, MEMBER_ID), "PATCH", { role: "viewer", expected_version: 1 }],
    [HUMAN_ORGANIZATIONS_HTTP_PATHS.memberRemove(ORGANIZATION_ID, MEMBER_ID), "POST", { expected_version: 1 }],
    [HUMAN_ORGANIZATIONS_HTTP_PATHS.invitations(ORGANIZATION_ID), "POST", { role: "viewer", expires_at: "2026-08-19T00:00:00.000Z" }],
    [HUMAN_ORGANIZATIONS_HTTP_PATHS.invitationRevoke(ORGANIZATION_ID, INVITATION_ID), "POST", { expected_version: 1 }],
    [HUMAN_ORGANIZATIONS_HTTP_PATHS.acceptInvitation, "POST", { one_time_token: INVITATION_TOKEN }]
  ];
  for (const [path, method, body] of mutations) {
    const missingKeyRequest = request(path, { method, body });
    delete missingKeyRequest.headers["idempotency-key"];
    const missingKey = await api.handle(missingKeyRequest);
    assert.equal(missingKey.status, 400);
    assert.equal(missingKey.body.error.code, HUMAN_ORGANIZATIONS_HTTP_ERROR_CODES.IDEMPOTENCY_REQUIRED);
  }
  for (const [path, method, body] of [
    [HUMAN_ORGANIZATIONS_HTTP_PATHS.organization(ORGANIZATION_ID), "PATCH", { name: "x" }],
    [HUMAN_ORGANIZATIONS_HTTP_PATHS.memberRole(ORGANIZATION_ID, MEMBER_ID), "PATCH", { role: "viewer" }],
    [HUMAN_ORGANIZATIONS_HTTP_PATHS.memberRemove(ORGANIZATION_ID, MEMBER_ID), "POST", {}],
    [HUMAN_ORGANIZATIONS_HTTP_PATHS.invitationRevoke(ORGANIZATION_ID, INVITATION_ID), "POST", {}]
  ]) {
    const result = await api.handle(request(path, { method, body }));
    assert.equal(result.status, 400);
    assert.equal(result.body.error.code, HUMAN_ORGANIZATIONS_HTTP_ERROR_CODES.INVALID_REQUEST);
  }
});

test("enforces role matrix without calling the service", async () => {
  for (const role of ["auditor", "viewer"]) {
    const { api, calls } = fixture({ role });
    const writeRoutes = [
      [HUMAN_ORGANIZATIONS_HTTP_PATHS.organization(ORGANIZATION_ID), "PATCH", { name: "x", expected_version: 1 }],
      [HUMAN_ORGANIZATIONS_HTTP_PATHS.memberRole(ORGANIZATION_ID, MEMBER_ID), "PATCH", { role: "viewer", expected_version: 1 }],
      [HUMAN_ORGANIZATIONS_HTTP_PATHS.memberRemove(ORGANIZATION_ID, MEMBER_ID), "POST", { expected_version: 1 }],
      [HUMAN_ORGANIZATIONS_HTTP_PATHS.invitations(ORGANIZATION_ID), "POST", { role: "viewer", expires_at: "2026-08-19T00:00:00.000Z" }]
    ];
    for (const [path, method, body] of writeRoutes) {
      const result = await api.handle(request(path, { method, body }));
      assert.equal(result.status, 403);
      assert.equal(result.body.error.code, HUMAN_ORGANIZATIONS_HTTP_ERROR_CODES.FORBIDDEN);
    }
    assert.equal(calls.renameOrganization.length + calls.updateMemberRole.length + calls.removeMember.length + calls.createInvitation.length, 0);
    if (role === "viewer") {
      const viewerMembers = await api.handle(request(HUMAN_ORGANIZATIONS_HTTP_PATHS.members(ORGANIZATION_ID)));
      assert.equal(viewerMembers.status, 403);
    }
  }
  const { api: ownerApi } = fixture({ role: "owner" });
  const ownerRead = await ownerApi.handle(request(HUMAN_ORGANIZATIONS_HTTP_PATHS.members(ORGANIZATION_ID)));
  assert.equal(ownerRead.status, 200);
});

test("lists members and invitations only for auditor, admin, and owner", async () => {
  for (const role of ["owner", "admin", "auditor"]) {
    const { api } = fixture({ role });
    assert.equal((await api.handle(request(HUMAN_ORGANIZATIONS_HTTP_PATHS.members(ORGANIZATION_ID))).then((result) => result.status)), 200);
    assert.equal((await api.handle(request(HUMAN_ORGANIZATIONS_HTTP_PATHS.invitations(ORGANIZATION_ID))).then((result) => result.status)), 200);
  }
});

test("requires operation-bound recent auth before role updates and member removal", async () => {
  const recentCalls = [];
  const recentAuthService = {
    async authorize(input) {
      recentCalls.push(input);
      return {
        authenticated_at: NOW,
        challenge_id: input.proof,
        consumed: true,
        member_id: input.principal.member_id,
        operation: input.operation,
        organization_id: input.organization_id,
        verified: true
      };
    }
  };
  const { api, calls } = fixture({ recentAuthService, api: { now: () => NOW } });
  const roleResult = await api.handle(request(HUMAN_ORGANIZATIONS_HTTP_PATHS.memberRole(ORGANIZATION_ID, MEMBER_ID), { method: "PATCH", body: { role: "auditor", expected_version: 4 }, headers: { "agentpass-recent-auth": RECENT_AUTH_PROOF } }));
  assert.equal(roleResult.status, 200);
  assert.deepEqual(calls.updateMemberRole[0], { actor: actor(), organization_id: ORGANIZATION_ID, member_id: MEMBER_ID, role: "auditor", expected_version: 4, idempotency_key: "test-key-1" });
  const removeResult = await api.handle(request(HUMAN_ORGANIZATIONS_HTTP_PATHS.memberRemove(ORGANIZATION_ID, MEMBER_ID), { method: "POST", body: { expected_version: 5 }, headers: { "agentpass-recent-auth": RECENT_AUTH_PROOF } }));
  assert.equal(removeResult.status, 200);
  assert.equal(calls.removeMember[0].member_id, MEMBER_ID);
  assert.equal(recentCalls.length, 2);
  assert.deepEqual(recentCalls.map((call) => call.operation), [
    HUMAN_ORGANIZATIONS_RECENT_AUTH_OPERATIONS.updateMemberRole,
    HUMAN_ORGANIZATIONS_RECENT_AUTH_OPERATIONS.removeMember
  ]);
  assert.deepEqual(recentCalls[0].principal, actor());
  assert.equal(recentCalls[0].organization_id, ORGANIZATION_ID);
});

test("rejects missing, cross-operation, cross-tenant, replayed, failed, stale, and unavailable recent auth without mutation", async () => {
  const protectedRoutes = [
    [HUMAN_ORGANIZATIONS_HTTP_PATHS.memberRole(ORGANIZATION_ID, MEMBER_ID), "PATCH", { role: "auditor", expected_version: 1 }, "updateMemberRole"],
    [HUMAN_ORGANIZATIONS_HTTP_PATHS.memberRemove(ORGANIZATION_ID, MEMBER_ID), "POST", { expected_version: 1 }, "removeMember"]
  ];
  for (const [path, method, body] of protectedRoutes) {
    const recentAuthService = { authorize: async () => { throw new Error("should not be called"); } };
    const { api, calls } = fixture({ recentAuthService, api: { now: () => NOW } });
    const result = await api.handle(request(path, { method, body }));
    assert.equal(result.status, 401);
    assert.equal(result.body.error.code, HUMAN_ORGANIZATIONS_HTTP_ERROR_CODES.RECENT_AUTH_REQUIRED);
    assert.equal(calls.updateMemberRole.length + calls.removeMember.length, 0);
  }

  for (const authorization of [
    { verified: true, consumed: true, operation: HUMAN_ORGANIZATIONS_RECENT_AUTH_OPERATIONS.removeMember },
    { verified: true, consumed: false },
    { verified: false, consumed: true }
  ]) {
    const { api, calls } = fixture({
      recentAuthService: { authorize: async () => ({ authenticated_at: NOW, challenge_id: RECENT_AUTH_PROOF, member_id: MEMBER_ID, organization_id: ORGANIZATION_ID, operation: HUMAN_ORGANIZATIONS_RECENT_AUTH_OPERATIONS.updateMemberRole, ...authorization }) },
      api: { now: () => NOW }
    });
    const result = await api.handle(request(HUMAN_ORGANIZATIONS_HTTP_PATHS.memberRole(ORGANIZATION_ID, MEMBER_ID), { method: "PATCH", body: { role: "auditor", expected_version: 1 }, headers: { "agentpass-recent-auth": RECENT_AUTH_PROOF } }));
    assert.equal(result.status, 401);
    assert.equal(result.body.error.code, HUMAN_ORGANIZATIONS_HTTP_ERROR_CODES.RECENT_AUTH_FAILED);
    assert.equal(calls.updateMemberRole.length, 0);
  }

  const stale = fixture({
    recentAuthService: { authorize: async (input) => ({ authenticated_at: NOW - 5 * 60_001, challenge_id: input.proof, consumed: true, member_id: MEMBER_ID, organization_id: ORGANIZATION_ID, operation: HUMAN_ORGANIZATIONS_RECENT_AUTH_OPERATIONS.updateMemberRole, verified: true }) },
    api: { now: () => NOW }
  });
  const staleResult = await stale.api.handle(request(HUMAN_ORGANIZATIONS_HTTP_PATHS.memberRole(ORGANIZATION_ID, MEMBER_ID), { method: "PATCH", body: { role: "auditor", expected_version: 1 }, headers: { "agentpass-recent-auth": RECENT_AUTH_PROOF } }));
  assert.equal(staleResult.body.error.code, HUMAN_ORGANIZATIONS_HTTP_ERROR_CODES.RECENT_AUTH_STALE);
  assert.equal(stale.calls.updateMemberRole.length, 0);

  const unavailable = fixture({ recentAuthService: { authorize: async () => { throw new Error("secret verifier detail"); } } });
  const unavailableResult = await unavailable.api.handle(request(HUMAN_ORGANIZATIONS_HTTP_PATHS.memberRole(ORGANIZATION_ID, MEMBER_ID), { method: "PATCH", body: { role: "auditor", expected_version: 1 }, headers: { "agentpass-recent-auth": RECENT_AUTH_PROOF } }));
  assert.equal(unavailableResult.status, 503);
  assert.equal(unavailableResult.body.error.code, HUMAN_ORGANIZATIONS_HTTP_ERROR_CODES.RECENT_AUTH_UNAVAILABLE);
  assertNoSecret(unavailableResult, "secret verifier detail");
  assert.equal(unavailable.calls.updateMemberRole.length, 0);

  const crossTenant = fixture({ recentAuthService: { authorize: async () => { throw new Error("should not be called"); } } });
  const crossTenantResult = await crossTenant.api.handle(request(HUMAN_ORGANIZATIONS_HTTP_PATHS.memberRole(OTHER_ORGANIZATION_ID, MEMBER_ID), { method: "PATCH", body: { role: "auditor", expected_version: 1 }, headers: { "agentpass-recent-auth": RECENT_AUTH_PROOF } }));
  assert.equal(crossTenantResult.status, 404);
  assert.equal(crossTenantResult.body.error.code, HUMAN_ORGANIZATIONS_HTTP_ERROR_CODES.ORGANIZATION_NOT_FOUND);
  assert.equal(crossTenant.calls.updateMemberRole.length, 0);
});

test("does not require recent auth for reads, invitation creation, or invitation acceptance", async () => {
  const { api, calls } = fixture();
  assert.equal((await api.handle(request(HUMAN_ORGANIZATIONS_HTTP_PATHS.members(ORGANIZATION_ID)))).status, 200);
  assert.equal((await api.handle(request(HUMAN_ORGANIZATIONS_HTTP_PATHS.invitations(ORGANIZATION_ID), { method: "POST", body: { role: "viewer", expires_at: "2026-08-19T00:00:00.000Z" } }))).status, 201);
  assert.equal((await api.handle(request(HUMAN_ORGANIZATIONS_HTTP_PATHS.acceptInvitation, { method: "POST", body: { one_time_token: INVITATION_TOKEN } }))).status, 201);
  assert.equal(calls.listMembers.length > 0, true);
  assert.equal(calls.createInvitation.length > 0, true);
  assert.equal(calls.acceptInvitation.length > 0, true);
});

test("creates invitations with the raw token exactly once and never exposes it on reads/revokes", async () => {
  const { api } = fixture();
  const created = await api.handle(request(HUMAN_ORGANIZATIONS_HTTP_PATHS.invitations(ORGANIZATION_ID), { method: "POST", body: { role: "viewer", expires_at: "2026-08-19T00:00:00.000Z" } }));
  assert.equal(created.status, 201);
  assert.equal(created.body.one_time_token, INVITATION_TOKEN);
  assert.equal(JSON.stringify(created.body).split(INVITATION_TOKEN).length - 1, 1);
  const listed = await api.handle(request(HUMAN_ORGANIZATIONS_HTTP_PATHS.invitations(ORGANIZATION_ID)));
  assert.equal(listed.status, 200);
  assertNoSecret(listed, INVITATION_TOKEN, "token_hash", "public_key");
  const revoked = await api.handle(request(HUMAN_ORGANIZATIONS_HTTP_PATHS.invitationRevoke(ORGANIZATION_ID, INVITATION_ID), { method: "POST", body: { expected_version: 1 } }));
  assert.equal(revoked.status, 200);
  assertNoSecret(revoked, INVITATION_TOKEN, "token_hash", "public_key");
});

test("rejects owner invitations at the HTTP boundary", async () => {
  const { api, calls } = fixture();
  const result = await api.handle(request(HUMAN_ORGANIZATIONS_HTTP_PATHS.invitations(ORGANIZATION_ID), { method: "POST", body: { role: "owner", expires_at: "2026-08-19T00:00:00.000Z" } }));
  assert.equal(result.status, 400);
  assert.equal(calls.createInvitation.length, 0);
});

test("accepts a one-time token for the authenticated member and never returns token material", async () => {
  const { api, calls } = fixture();
  const result = await api.handle(request(HUMAN_ORGANIZATIONS_HTTP_PATHS.acceptInvitation, { method: "POST", body: { one_time_token: INVITATION_TOKEN } }));
  assert.equal(result.status, 201);
  assert.deepEqual(calls.acceptInvitation[0], { actor: actor(), one_time_token: INVITATION_TOKEN, idempotency_key: "test-key-1" });
  assertNoSecret(result, INVITATION_TOKEN, "token_hash", "public_key");
});

test("maps cross-tenant paths to non-disclosing not-found and never calls the service", async () => {
  const { api, calls } = fixture();
  const paths = [
    HUMAN_ORGANIZATIONS_HTTP_PATHS.organization(OTHER_ORGANIZATION_ID),
    HUMAN_ORGANIZATIONS_HTTP_PATHS.members(OTHER_ORGANIZATION_ID),
    HUMAN_ORGANIZATIONS_HTTP_PATHS.memberRole(OTHER_ORGANIZATION_ID, OTHER_MEMBER_ID),
    HUMAN_ORGANIZATIONS_HTTP_PATHS.invitations(OTHER_ORGANIZATION_ID),
    HUMAN_ORGANIZATIONS_HTTP_PATHS.invitationRevoke(OTHER_ORGANIZATION_ID, INVITATION_ID)
  ];
  for (const path of paths) {
    const method = path.endsWith("/members") || path.endsWith("/invitations") ? "GET" : path.endsWith("/invitations/" + INVITATION_ID + "/revoke") ? "POST" : path.includes("/role") ? "PATCH" : "PATCH";
    const body = method === "GET" ? undefined : path.includes("/role") ? { role: "viewer", expected_version: 1 } : path.includes("/revoke") ? { expected_version: 1 } : { name: "x", expected_version: 1 };
    const result = await api.handle(request(path, { method, body }));
    assert.equal(result.status, 404);
    assert.equal(result.body.error.code, HUMAN_ORGANIZATIONS_HTTP_ERROR_CODES.ORGANIZATION_NOT_FOUND);
  }
  assert.equal(calls.renameOrganization.length + calls.listMembers.length + calls.updateMemberRole.length + calls.listInvitations.length + calls.revokeInvitation.length, 0);
});

test("redacts service internals and maps not-found, owner constraints, replay, conflict, and outages", async () => {
  const errors = [
    ["not_found", HUMAN_ORGANIZATIONS_HTTP_ERROR_CODES.ORGANIZATION_NOT_FOUND, 404],
    ["owner_required", HUMAN_ORGANIZATIONS_HTTP_ERROR_CODES.FORBIDDEN, 403],
    ["invitation_token_replayed", HUMAN_ORGANIZATIONS_HTTP_ERROR_CODES.INVITATION_REPLAYED, 409],
    ["expected_version_mismatch", HUMAN_ORGANIZATIONS_HTTP_ERROR_CODES.VERSION_CONFLICT, 409],
    ["idempotency_conflict", HUMAN_ORGANIZATIONS_HTTP_ERROR_CODES.IDEMPOTENCY_CONFLICT, 409],
    ["database secret detail", HUMAN_ORGANIZATIONS_HTTP_ERROR_CODES.ORGANIZATIONS_UNAVAILABLE, 503]
  ];
  for (const [code, expectedCode, status] of errors) {
    const { api } = fixture({ serviceOverrides: { renameOrganization: Object.assign(new Error(code), { code }) } });
    const result = await api.handle(request(HUMAN_ORGANIZATIONS_HTTP_PATHS.organization(ORGANIZATION_ID), { method: "PATCH", body: { name: "x", expected_version: 1 } }));
    assert.equal(result.status, status);
    assert.equal(result.body.error.code, expectedCode);
    assert.equal(JSON.stringify(result.body).includes("secret detail"), false);
  }
});

test("rejects unknown methods, query fields, malformed bodies, and oversized bodies", async () => {
  const { api } = fixture();
  const wrongMethod = await api.handle(request(HUMAN_ORGANIZATIONS_HTTP_PATHS.members(ORGANIZATION_ID), { method: "DELETE" }));
  assert.equal(wrongMethod.status, 405);
  assert.equal(wrongMethod.headers.Allow, "GET");
  const unknownQuery = await api.handle(request(`${HUMAN_ORGANIZATIONS_HTTP_PATHS.members(ORGANIZATION_ID)}?role=owner`));
  assert.equal(unknownQuery.status, 400);
  const badJson = await api.handle({ method: "POST", url: HUMAN_ORGANIZATIONS_HTTP_PATHS.organizations, headers: { origin: ORIGIN, cookie: COOKIE, "agentpass-csrf": CSRF_TOKEN, "content-type": "application/json", "idempotency-key": "x" }, body: "{" });
  assert.equal(badJson.status, 400);
  const oversized = await api.handle(request(HUMAN_ORGANIZATIONS_HTTP_PATHS.organizations, { method: "POST", body: { name: "x" }, headers: { "content-length": "20000" } }));
  assert.equal(oversized.status, 413);
  const badPath = await api.handle(request(`${HUMAN_ORGANIZATIONS_HTTP_PATHS.organizations}/not-a-uuid`, { method: "PATCH", body: { name: "x", expected_version: 1 } }));
  assert.equal(badPath.status, 400);
});

test("rejects invalid invitation tokens and preserves no-cookie-mutation response behavior", async () => {
  const { api } = fixture();
  for (const token of ["", "short", "x".repeat(44)]) {
    const result = await api.handle(request(HUMAN_ORGANIZATIONS_HTTP_PATHS.acceptInvitation, { method: "POST", body: { one_time_token: token } }));
    assert.equal(result.status, 400);
    assert.equal(result.body.error.code, HUMAN_ORGANIZATIONS_HTTP_ERROR_CODES.INVALID_REQUEST);
    assert.equal(Object.hasOwn(result.headers, "Set-Cookie"), false);
  }
});

test("supports Request-like input and Node response output without Set-Cookie", async () => {
  const { api } = fixture();
  const requestLike = new Request(`https://console.agentpass.test${HUMAN_ORGANIZATIONS_HTTP_PATHS.organizations}`, {
    method: "GET",
    headers: { origin: ORIGIN, cookie: COOKIE, "agentpass-csrf": CSRF_TOKEN }
  });
  const result = await api.handle(requestLike);
  assert.equal(result.status, 200);
  let written;
  const nodeResponse = {
    writeHead(status, headers) { written = { status, headers }; },
    end(body) { written.body = JSON.parse(body); }
  };
  await api.handle(requestLike, nodeResponse);
  assert.equal(written.status, 200);
  assert.equal(Object.hasOwn(written.headers, "Set-Cookie"), false);
});
