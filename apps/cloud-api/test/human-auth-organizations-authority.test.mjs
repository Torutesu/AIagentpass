import assert from "node:assert/strict";
import test from "node:test";

import {
  createHumanOrganizationsHttpApi,
  HUMAN_ORGANIZATION_SERVICE_METHODS,
  HUMAN_ORGANIZATIONS_HTTP_ERROR_CODES,
  HUMAN_ORGANIZATIONS_HTTP_PATHS,
  HUMAN_ORGANIZATIONS_RECENT_AUTH_OPERATIONS
} from "../src/human-auth/organizations/http-api.mjs";
import {
  createPostgresOrganizationService,
  ORGANIZATION_SERVICE_ERROR_CODES
} from "../src/human-auth/organizations/postgres-service.mjs";

const ORIGIN = "https://console.agentpass.test";
const COOKIE = `__Host-agentpass_session=${"s".repeat(43)}; Path=/; HttpOnly; Secure; SameSite=Strict`;
const CSRF = "c".repeat(43);
const PROOF = "77777777-7777-4777-8777-777777777777";
const ORGANIZATION_ID = "11111111-1111-4111-8111-111111111111";
const MEMBER_ID = "33333333-3333-4333-8333-333333333333";
const NOW = 1_800_000_000_000;

function actor(role = "owner") {
  return {
    session_id: "66666666-6666-4666-8666-666666666666",
    member_id: MEMBER_ID,
    organization_id: ORGANIZATION_ID,
    role
  };
}

function repository(overrides = {}) {
  const methods = ["listOrganizationsForMember", "createOrganizationWithOwner", "renameOrganization", "listMembers", "updateMemberRole", "removeMember", "listInvitations", "createInvitation", "revokeInvitation", "acceptInvitation"];
  const defaults = Object.fromEntries(methods.map((method) => [method, async () => ({})]));
  return Object.freeze({ ...defaults, ...overrides });
}

function httpService(overrides = {}) {
  const calls = [];
  const service = Object.fromEntries(HUMAN_ORGANIZATION_SERVICE_METHODS.map((method) => [method, async (input) => {
    calls.push({ method, input });
    if (overrides[method] instanceof Error) throw overrides[method];
    return overrides[method] ?? { organization_id: ORGANIZATION_ID, member_id: MEMBER_ID, version: 1, name: "Acme", role: "viewer", status: "active" };
  }]));
  return { service, calls };
}

function request(path, { method = "GET", body = undefined, role = "owner", headers = {} } = {}) {
  const requestHeaders = {
    origin: ORIGIN,
    cookie: COOKIE,
    "agentpass-csrf": CSRF,
    ...(method === "GET" ? {} : { "content-type": "application/json", "idempotency-key": "authority-test-1" }),
    ...(method === "PATCH" || path.endsWith("/remove") ? { "if-match": '"1"' } : {}),
    ...headers
  };
  return {
    method,
    url: path,
    headers: requestHeaders,
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    role
  };
}

function makeHttp({ role = "owner", serviceOverrides = {}, recent = true } = {}) {
  const { service, calls } = httpService(serviceOverrides);
  const humanSession = {
    expectedOrigin: ORIGIN,
    async authenticateRequest() { return { session: actor(role) }; }
  };
  const recentAuthService = recent ? {
    async authorize(input) {
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
  } : undefined;
  return {
    calls,
    api: createHumanOrganizationsHttpApi({ humanSession, organizationService: service, recentAuthService, abuseControls: { async authorize() { return { allowed: true }; } }, origin: ORIGIN, now: () => NOW })
  };
}

test("service rejects invalid roles, invalid versions, and actors without a fixed role before PostgreSQL", async () => {
  const calls = [];
  const repo = repository({
    updateMemberRole: async (input) => { calls.push(input); return {}; },
    renameOrganization: async (input) => { calls.push(input); return {}; }
  });
  const service = createPostgresOrganizationService({ repository: repo, now: () => "2026-08-12T00:00:00.000Z" });

  await assert.rejects(() => service.updateMemberRole({ actor: actor(), organization_id: ORGANIZATION_ID, member_id: MEMBER_ID, role: "root", expected_version: 1, idempotency_key: "authority-1" }), { code: ORGANIZATION_SERVICE_ERROR_CODES.INVALID_INPUT });
  await assert.rejects(() => service.updateMemberRole({ actor: actor(), organization_id: ORGANIZATION_ID, member_id: MEMBER_ID, role: "viewer", expected_version: 0, idempotency_key: "authority-2" }), { code: ORGANIZATION_SERVICE_ERROR_CODES.INVALID_INPUT });
  await assert.rejects(() => service.renameOrganization({ actor: actor(), organization_id: ORGANIZATION_ID, name: "Acme", expected_version: "1", idempotency_key: "authority-3" }), { code: ORGANIZATION_SERVICE_ERROR_CODES.INVALID_INPUT });
  await assert.rejects(() => service.listOrganizations({ actor: actor("unknown") }), { code: ORGANIZATION_SERVICE_ERROR_CODES.INVALID_INPUT });
  assert.equal(calls.length, 0);
});

test("service maps last-owner and role-transition failures without exposing repository details", async () => {
  const lastOwner = Object.assign(new Error("constraint secret detail"), { code: "ERR_LAST_OWNER" });
  const roleDenied = Object.assign(new Error("role downgrade secret detail"), { code: "ERR_ROLE_NOT_ALLOWED" });
  const service = createPostgresOrganizationService({
    repository: repository({
      removeMember: async () => { throw lastOwner; },
      updateMemberRole: async () => { throw roleDenied; },
      acceptInvitation: async () => ({
        member_id: MEMBER_ID,
        organization_id: ORGANIZATION_ID,
        csrfToken: "secret",
        public_key: "public",
        access_token: "secret-access",
        api_key: "secret-api",
        secret_value: "secret-value",
        nested: { session_token: "secret-session", safe: "visible" }
      })
    }),
    now: () => "2026-08-12T00:00:00.000Z"
  });

  await assert.rejects(
    () => service.removeMember({ actor: actor(), organization_id: ORGANIZATION_ID, member_id: MEMBER_ID, expected_version: 1, idempotency_key: "authority-4" }),
    (error) => error.code === ORGANIZATION_SERVICE_ERROR_CODES.FORBIDDEN && error.reason === "last_owner" && !error.message.includes("secret")
  );
  await assert.rejects(
    () => service.updateMemberRole({ actor: actor(), organization_id: ORGANIZATION_ID, member_id: MEMBER_ID, role: "viewer", expected_version: 1, idempotency_key: "authority-5" }),
    (error) => error.code === ORGANIZATION_SERVICE_ERROR_CODES.FORBIDDEN && error.reason === "role_not_allowed" && !error.message.includes("secret")
  );
  const accepted = await service.acceptInvitation({ actor: actor(), one_time_token: "i".repeat(43), idempotency_key: "authority-6" });
  assert.equal(Object.hasOwn(accepted, "csrfToken"), false);
  assert.equal(Object.hasOwn(accepted, "public_key"), false);
  assert.equal(accepted.nested.safe, "visible");
  assert.doesNotMatch(JSON.stringify(accepted), /secret|public|access_token|api_key/iu);
});

test("admin cannot grant owner and does not consume recent auth or call the service", async () => {
  const { api, calls } = makeHttp({ role: "admin" });
  const result = await api.handle(request(HUMAN_ORGANIZATIONS_HTTP_PATHS.memberRole(ORGANIZATION_ID, MEMBER_ID), {
    method: "PATCH",
    body: { role: "owner" },
    headers: { "agentpass-recent-auth": PROOF }
  }));
  assert.equal(result.status, 403);
  assert.equal(result.body.error.code, HUMAN_ORGANIZATIONS_HTTP_ERROR_CODES.ROLE_NOT_ALLOWED);
  assert.equal(calls.length, 0);
});

test("HTTP maps repository error prefixes to stable authority responses", async () => {
  const forbidden = makeHttp({
    role: "admin",
    serviceOverrides: { renameOrganization: Object.assign(new Error("database secret"), { code: "ERR_FORBIDDEN" }) }
  });
  const forbiddenResult = await forbidden.api.handle(request(HUMAN_ORGANIZATIONS_HTTP_PATHS.organization(ORGANIZATION_ID), { method: "PATCH", body: { name: "x" } }));
  assert.equal(forbiddenResult.status, 403);
  assert.equal(forbiddenResult.body.error.code, HUMAN_ORGANIZATIONS_HTTP_ERROR_CODES.FORBIDDEN);
  assert.doesNotMatch(JSON.stringify(forbiddenResult.body), /database secret/iu);

  const lastOwner = makeHttp({
    role: "owner",
    serviceOverrides: { removeMember: Object.assign(new Error("constraint secret"), { code: "ERR_LAST_OWNER" }) }
  });
  const lastOwnerResult = await lastOwner.api.handle(request(HUMAN_ORGANIZATIONS_HTTP_PATHS.memberRemove(ORGANIZATION_ID, MEMBER_ID), {
    method: "POST",
    headers: { "agentpass-recent-auth": PROOF }
  }));
  assert.equal(lastOwnerResult.status, 409);
  assert.equal(lastOwnerResult.body.error.code, HUMAN_ORGANIZATIONS_HTTP_ERROR_CODES.LAST_OWNER_PROTECTED);
  assert.doesNotMatch(JSON.stringify(lastOwnerResult.body), /constraint secret/iu);

  const stale = makeHttp({
    role: "owner",
    serviceOverrides: { renameOrganization: Object.assign(new Error("stale secret"), { code: "ERR_VERSION_CONFLICT" }) }
  });
  const staleResult = await stale.api.handle(request(HUMAN_ORGANIZATIONS_HTTP_PATHS.organization(ORGANIZATION_ID), { method: "PATCH", body: { name: "x" } }));
  assert.equal(staleResult.status, 409);
  assert.equal(staleResult.body.error.code, HUMAN_ORGANIZATIONS_HTTP_ERROR_CODES.VERSION_CONFLICT);
  assert.doesNotMatch(JSON.stringify(staleResult.body), /stale secret/iu);
});

test("recent-auth operations remain distinct for role changes and removals", async () => {
  const seen = [];
  const { service, calls } = httpService();
  const api = createHumanOrganizationsHttpApi({
    humanSession: { expectedOrigin: ORIGIN, async authenticateRequest() { return { session: actor("owner") }; } },
    organizationService: service,
    abuseControls: { async authorize() { return { allowed: true }; } },
    recentAuthService: { async authorize(input) { seen.push(input.operation); return { authenticated_at: NOW, challenge_id: input.proof, consumed: true, member_id: MEMBER_ID, operation: input.operation, organization_id: ORGANIZATION_ID, verified: true }; } },
    origin: ORIGIN,
    now: () => NOW
  });
  await api.handle(request(HUMAN_ORGANIZATIONS_HTTP_PATHS.memberRole(ORGANIZATION_ID, MEMBER_ID), { method: "PATCH", body: { role: "viewer" }, headers: { "agentpass-recent-auth": PROOF } }));
  await api.handle(request(HUMAN_ORGANIZATIONS_HTTP_PATHS.memberRemove(ORGANIZATION_ID, MEMBER_ID), { method: "POST", headers: { "agentpass-recent-auth": PROOF } }));
  assert.deepEqual(seen, [HUMAN_ORGANIZATIONS_RECENT_AUTH_OPERATIONS.updateMemberRole, HUMAN_ORGANIZATIONS_RECENT_AUTH_OPERATIONS.removeMember]);
  assert.equal(calls.length, 2);
});
