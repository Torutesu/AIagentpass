import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import {
  HUMAN_AGENT_SESSION_GRANT_HTTP_ERROR_CODES,
  HUMAN_AGENT_SESSION_GRANT_HTTP_PATHS,
  createHumanAgentSessionGrantHttpApi
} from "../src/human-auth/agent-sessions/http-api.mjs";
import {
  AGENT_SESSION_GRANT_ISSUANCE_ERROR_CODES,
  AGENT_SESSION_GRANT_REPOSITORY_METHODS,
  createAgentSessionGrantIssuanceService
} from "../src/human-auth/agent-sessions/issuance-service.mjs";
import { verifyAgentSessionGrant } from "../src/agent-session-grant.mjs";

const ORIGIN = "https://console.agentpass.test";
const ORGANIZATION_ID = "11111111-1111-4111-8111-111111111111";
const AGENT_ID = "22222222-2222-4222-8222-222222222222";
const DEVICE_ID = "33333333-3333-4333-8333-333333333333";
const ADAPTER_ID = "44444444-4444-4444-8444-444444444444";
const MEMBER_ID = "55555555-5555-4555-8555-555555555555";
const SESSION_ID = "66666666-6666-4666-8666-666666666666";
const RECENT_AUTH_ID = "77777777-7777-4777-8777-777777777777";
const GRANT_ID = "88888888-8888-4888-8888-888888888888";
const REQUEST_ID = "99999999-9999-4999-8999-999999999999";
const NOW = Date.parse("2026-08-13T00:00:00.000Z");
const CSRF = "c".repeat(43);
const SESSION_TOKEN = "s".repeat(43);
const COOKIE = `__Host-agentpass_session=${SESSION_TOKEN}; Path=/; HttpOnly; Secure; SameSite=Strict`;

function intent(overrides = {}) {
  return {
    device_id: DEVICE_ID,
    agent_kind: "claude-code",
    adapter_id: ADAPTER_ID,
    adapter_version: "1.2.3",
    worktree_binding_sha256: "a".repeat(64),
    process_binding_policy_id: "macos-v2",
    scope: {
      operations: ["git.commit.sign"],
      repositories: ["/Users/example/repository"],
      branches: { allow: ["main"], deny: [] },
      remotes: { allow: ["origin"], deny: [] }
    },
    max_signatures: 2,
    ttl_seconds: 600,
    ...overrides
  };
}

function session(overrides = {}) {
  return {
    session_id: SESSION_ID,
    member_id: MEMBER_ID,
    organization_id: ORGANIZATION_ID,
    role: "admin",
    ...overrides
  };
}

function baseRequest(path = HUMAN_AGENT_SESSION_GRANT_HTTP_PATHS.issue(ORGANIZATION_ID, AGENT_ID), overrides = {}) {
  return {
    method: "POST",
    url: path,
    headers: {
      origin: ORIGIN,
      cookie: COOKIE,
      "agentpass-csrf": CSRF,
      "agentpass-recent-auth": RECENT_AUTH_ID,
      "idempotency-key": "grant-request-1",
      "content-type": "application/json",
      ...(overrides.headers ?? {})
    },
    body: overrides.body ?? intent()
  };
}

function fixture({ sessionOverrides = {}, repositoryOverrides = {}, recentAuthResult = undefined, recentAuthError = undefined, signerOverrides = {} } = {}) {
  const calls = { auth: [], recentAuth: [], repository: [], replay: [], signer: [] };
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  const grantSigner = {
    key_id: "grant-key-v1",
    async sign(input) {
      calls.signer.push(input);
      if (signerOverrides.error) throw signerOverrides.error;
      return crypto.sign(null, input.message, privateKey);
    },
    ...signerOverrides
  };
  const repository = {
    async issueAgentSessionGrant(input) {
      calls.repository.push(input);
      if (repositoryOverrides.error) throw repositoryOverrides.error;
      if (repositoryOverrides.result) return repositoryOverrides.result;
      const built = await input.buildGrant({ control_sequence: 9, authority_generation: 7 });
      return { grant: built.grant, request_id: input.request_id };
    },
    ...(Object.hasOwn(repositoryOverrides, "replayResult") ? {
      async replayAgentSessionGrant(input) {
        calls.replay.push(input);
        if (repositoryOverrides.replayError) throw repositoryOverrides.replayError;
        return repositoryOverrides.replayResult;
      }
    } : {})
  };
  const humanSession = {
    expectedOrigin: ORIGIN,
    async authenticateRequest(input) {
      calls.auth.push(input);
      return { session: session(sessionOverrides) };
    }
  };
  const recentAuthService = {
    async authorize(input) {
      calls.recentAuth.push(input);
      if (recentAuthError) throw recentAuthError;
      return recentAuthResult ?? {
        verified: true,
        consumed: true,
        challenge_id: RECENT_AUTH_ID,
        member_id: input.principal.member_id,
        organization_id: input.organization_id,
        operation: input.operation,
        authenticated_at: NOW
      };
    }
  };
  const api = createHumanAgentSessionGrantHttpApi({
    humanSession,
    recentAuthService,
    repository,
    signer: grantSigner,
    origin: ORIGIN,
    clock: { now: () => NOW },
    uuid: (() => {
      let index = 0;
      return () => [GRANT_ID, REQUEST_ID][index++];
    })()
  });
  return { api, calls, publicKey };
}

test("requires the exact repository contract and supports the shared Ed25519 signer boundary", () => {
  for (const missing of AGENT_SESSION_GRANT_REPOSITORY_METHODS) {
    const partial = Object.fromEntries(AGENT_SESSION_GRANT_REPOSITORY_METHODS.filter((method) => method !== missing).map((method) => [method, () => undefined]));
    assert.throws(() => createAgentSessionGrantIssuanceService({ repository: partial, signer: { key_id: "grant-key-v1", sign() {} } }), /repository is missing/u);
  }
});

test("issues a canonical grant only after session, role, CSRF, origin, and recent WebAuthn checks", async () => {
  const { api, calls, publicKey } = fixture();
  const result = await api.handle(baseRequest());

  assert.equal(result.status, 201);
  assert.deepEqual(Object.keys(result.body).sort(), ["grant", "request_id"]);
  assert.equal(result.body.request_id, REQUEST_ID);
  assert.deepEqual(Object.keys(result.body.grant).sort(), ["signature", "statement", "statement_hash", "type", "version"]);
  assert.equal(result.body.grant.statement.organization_id, ORGANIZATION_ID);
  assert.equal(result.body.grant.statement.agent_id, AGENT_ID);
  assert.equal(result.body.grant.statement.device_id, DEVICE_ID);
  assert.equal(result.body.grant.statement.adapter_version, "1.2.3");
  assert.equal(calls.auth[0].method, "POST");
  assert.equal(calls.recentAuth[0].operation, "agent.session_grant.issue");
  assert.deepEqual(calls.repository[0].actor, session());
  assert.equal(calls.repository[0].organization_id, ORGANIZATION_ID);
  assert.equal(calls.repository[0].agent_id, AGENT_ID);
  assert.equal(calls.repository[0].device_id, DEVICE_ID);
  assert.equal(calls.repository[0].intent.adapter_version, "1.2.3");
  assert.equal(calls.repository[0].recent_auth.authorization_id, RECENT_AUTH_ID);
  assert.equal(calls.signer.length, 1);
  assert.equal(calls.signer[0].algorithm, "ed25519");
  assert.equal(Object.hasOwn(calls.signer[0], "privateKey"), false);
  assert.equal(Object.hasOwn(calls.signer[0], "private_key"), false);
  assert.doesNotThrow(() => verifyAgentSessionGrant(result.body.grant, { publicKey, now: NOW }));
  assert.match(result.headers["Cache-Control"], /no-store/u);
  assert.equal(JSON.stringify(result.body).includes("private"), false);
});

test("passes the repository's committed retry result through without signing again", async () => {
  const first = fixture();
  const issued = await first.api.handle(baseRequest());
  const retry = fixture({ repositoryOverrides: { result: { grant: issued.body.grant, request_id: issued.body.request_id, replayed: true } } });
  const result = await retry.api.handle(baseRequest());
  assert.equal(result.status, 201);
  assert.deepEqual(result.body, issued.body);
  assert.equal(retry.calls.signer.length, 0);
});

test("recovers a committed idempotent response before consuming another recent-auth proof", async () => {
  const first = fixture();
  const issued = await first.api.handle(baseRequest());
  const retry = fixture({ repositoryOverrides: { replayResult: { grant: issued.body.grant, request_id: issued.body.request_id, replayed: true } } });
  const request = baseRequest();
  delete request.headers["agentpass-recent-auth"];
  const result = await retry.api.handle(request);
  assert.equal(result.status, 201);
  assert.deepEqual(result.body, issued.body);
  assert.equal(retry.calls.replay.length, 1);
  assert.equal(retry.calls.recentAuth.length, 0);
  assert.equal(retry.calls.repository.length, 0);
  assert.equal(retry.calls.signer.length, 0);
});

test("rejects missing or malformed browser security headers before recent-auth consumption", async () => {
  for (const [headerName, value, code, status] of [
    ["origin", "https://evil.example", HUMAN_AGENT_SESSION_GRANT_HTTP_ERROR_CODES.ORIGIN_NOT_ALLOWED, 403],
    ["cookie", undefined, HUMAN_AGENT_SESSION_GRANT_HTTP_ERROR_CODES.SESSION_REQUIRED, 401],
    ["agentpass-csrf", "short", HUMAN_AGENT_SESSION_GRANT_HTTP_ERROR_CODES.CSRF_FAILED, 403],
    ["agentpass-recent-auth", "not-a-uuid", HUMAN_AGENT_SESSION_GRANT_HTTP_ERROR_CODES.RECENT_AUTH_REQUIRED, 401],
    ["idempotency-key", "short", HUMAN_AGENT_SESSION_GRANT_HTTP_ERROR_CODES.IDEMPOTENCY_REQUIRED, 400]
  ]) {
    const { api, calls } = fixture();
    const request = baseRequest();
    if (value === undefined) delete request.headers[headerName];
    else request.headers[headerName] = value;
    const result = await api.handle(request);
    assert.equal(result.status, status, headerName);
    assert.equal(result.body.error.code, code, headerName);
    assert.equal(calls.recentAuth.length, 0, headerName);
    assert.equal(calls.repository.length, 0, headerName);
  }
});

test("rejects forbidden identity headers, alternate CSRF headers, wrong methods, and query strings", async () => {
  for (const headerName of ["authorization", "agentpass-role", "agentpass-member-id", "agentpass-console-identity", "x-csrf-token"]) {
    const { api, calls } = fixture();
    const result = await api.handle(baseRequest(undefined, { headers: { [headerName]: "attacker-controlled" } }));
    assert.equal(result.status, 400, headerName);
    assert.equal(result.body.error.code, HUMAN_AGENT_SESSION_GRANT_HTTP_ERROR_CODES.INVALID_REQUEST, headerName);
    assert.equal(calls.auth.length, 0, headerName);
  }
  const wrongMethod = fixture();
  const methodResult = await wrongMethod.api.handle({ ...baseRequest(), method: "GET" });
  assert.equal(methodResult.status, 405);
  assert.equal(methodResult.headers.Allow, "POST");
  const query = fixture();
  const queryResult = await query.api.handle({ ...baseRequest(`${HUMAN_AGENT_SESSION_GRANT_HTTP_PATHS.issue(ORGANIZATION_ID, AGENT_ID)}?agent_id=${AGENT_ID}`) });
  assert.equal(queryResult.status, 400);
  assert.equal(queryResult.body.error.code, HUMAN_AGENT_SESSION_GRANT_HTTP_ERROR_CODES.INVALID_REQUEST);
});

test("does not consume recent auth for cross-tenant paths, non-admin roles, or invalid bodies", async () => {
  const crossTenant = fixture();
  const crossTenantResult = await crossTenant.api.handle(baseRequest(HUMAN_AGENT_SESSION_GRANT_HTTP_PATHS.issue("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", AGENT_ID)));
  assert.equal(crossTenantResult.status, 404);
  assert.equal(crossTenant.calls.recentAuth.length, 0);
  assert.equal(crossTenant.calls.repository.length, 0);

  const viewer = fixture({ sessionOverrides: { role: "viewer" } });
  const viewerResult = await viewer.api.handle(baseRequest());
  assert.equal(viewerResult.status, 403);
  assert.equal(viewerResult.body.error.code, HUMAN_AGENT_SESSION_GRANT_HTTP_ERROR_CODES.FORBIDDEN);
  assert.equal(viewer.calls.recentAuth.length, 0);

  for (const body of [
    { ...intent(), organization_id: ORGANIZATION_ID },
    { ...intent(), agent_id: AGENT_ID },
    { ...intent(), adapter_version: "1.2.3+build.7" },
    { ...intent(), ttl_seconds: 59 },
    { ...intent(), worktree_binding_sha256: "A".repeat(64) },
    { ...intent(), scope: { operations: ["ssh.sign"], repositories: ["/repo"], branches: { allow: ["main"], deny: [] }, remotes: { allow: ["origin"], deny: [] } } },
    { ...intent(), private_key: "must-not-be-accepted" }
  ]) {
    const { api, calls } = fixture();
    const result = await api.handle(baseRequest(undefined, { body }));
    assert.equal(result.status, 400, JSON.stringify(body));
    assert.equal(result.body.error.code, HUMAN_AGENT_SESSION_GRANT_HTTP_ERROR_CODES.INVALID_REQUEST, JSON.stringify(body));
    assert.equal(calls.recentAuth.length, 0);
    assert.equal(calls.repository.length, 0);
  }
});

test("rejects path substitutions and malformed path segments without disclosing resource existence", async () => {
  for (const path of [
    "/api/v1/organizations/not-a-uuid/agents/22222222-2222-4222-8222-222222222222/session-grants",
    "/api/v1/organizations/11111111-1111-4111-8111-111111111111/agents/not-a-uuid/session-grants",
    "/api/v1/organizations/11111111-1111-4111-8111-111111111111/agents/22222222-2222-4222-8222-222222222222/session-grants/extra",
    "/api/v1/organizations/11111111-1111-4111-8111-111111111111/agents/22222222-2222-4222-8222-222222222222/session-grants%2Fextra"
  ]) {
    const { api, calls } = fixture();
    const result = await api.handle(baseRequest(path));
    assert.equal(result.status, path.includes("not-a-uuid") ? 400 : 404, path);
    assert.equal(calls.repository.length, 0, path);
  }
});

test("rejects stale, future, mismatched, and malformed recent WebAuthn authorizations", async () => {
  for (const recentAuthResult of [
    { verified: false, consumed: false, challenge_id: RECENT_AUTH_ID, member_id: MEMBER_ID, organization_id: ORGANIZATION_ID, operation: "agent.session_grant.issue", authenticated_at: NOW },
    { verified: true, consumed: true, challenge_id: RECENT_AUTH_ID, member_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", organization_id: ORGANIZATION_ID, operation: "agent.session_grant.issue", authenticated_at: NOW },
    { verified: true, consumed: true, challenge_id: RECENT_AUTH_ID, member_id: MEMBER_ID, organization_id: ORGANIZATION_ID, operation: "other.operation", authenticated_at: NOW },
    { verified: true, consumed: true, challenge_id: RECENT_AUTH_ID, member_id: MEMBER_ID, organization_id: ORGANIZATION_ID, operation: "agent.session_grant.issue", authenticated_at: NOW - 5 * 60_000 - 1 },
    { verified: true, consumed: true, challenge_id: RECENT_AUTH_ID, member_id: MEMBER_ID, organization_id: ORGANIZATION_ID, operation: "agent.session_grant.issue", authenticated_at: NOW + 30_001 }
  ]) {
    const { api, calls } = fixture({ recentAuthResult });
    const result = await api.handle(baseRequest());
    assert.equal(result.status, 401);
    assert.equal(result.body.error.code, recentAuthResult.authenticated_at < NOW || recentAuthResult.authenticated_at > NOW ? HUMAN_AGENT_SESSION_GRANT_HTTP_ERROR_CODES.RECENT_AUTH_STALE : HUMAN_AGENT_SESSION_GRANT_HTTP_ERROR_CODES.RECENT_AUTH_FAILED);
    assert.equal(calls.repository.length, 0);
  }
  const unavailable = fixture({ recentAuthError: Object.assign(new Error("database details"), { code: "db_down" }) });
  const unavailableResult = await unavailable.api.handle(baseRequest());
  assert.equal(unavailableResult.status, 503);
  assert.equal(unavailableResult.body.error.code, HUMAN_AGENT_SESSION_GRANT_HTTP_ERROR_CODES.RECENT_AUTH_UNAVAILABLE);
  assert.equal(JSON.stringify(unavailableResult.body).includes("database details"), false);
});

test("maps repository not-found, idempotency, and outage failures to stable opaque responses", async () => {
  for (const [error, status, code] of [
    [Object.assign(new Error("tenant internals"), { code: "agent_not_found" }), 404, HUMAN_AGENT_SESSION_GRANT_HTTP_ERROR_CODES.NOT_FOUND],
    Object.assign(new Error("secret idempotency details"), { code: "idempotency_key_reused" }),
    Object.assign(new Error("postgres connection secret"), { code: "connection_failure" })
  ].map((value) => Array.isArray(value) ? value : [value, value.code === "idempotency_key_reused" ? 409 : 503, value.code === "idempotency_key_reused" ? HUMAN_AGENT_SESSION_GRANT_HTTP_ERROR_CODES.IDEMPOTENCY_CONFLICT : HUMAN_AGENT_SESSION_GRANT_HTTP_ERROR_CODES.GRANT_UNAVAILABLE])) {
    const { api } = fixture({ repositoryOverrides: { error } });
    const result = await api.handle(baseRequest());
    assert.equal(result.status, status);
    assert.equal(result.body.error.code, code);
    assert.equal(JSON.stringify(result.body).includes("secret"), false);
    assert.equal(JSON.stringify(result.body).includes("internals"), false);
  }
});

test("rejects duplicate JSON keys and enforces the raw JSON content boundary", async () => {
  const duplicate = fixture();
  const duplicateResult = await duplicate.api.handle(baseRequest(undefined, { body: '{"device_id":"33333333-3333-4333-8333-333333333333","device_id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"}' }));
  assert.equal(duplicateResult.status, 400);
  assert.equal(duplicateResult.body.error.code, HUMAN_AGENT_SESSION_GRANT_HTTP_ERROR_CODES.INVALID_REQUEST);
  assert.equal(duplicate.calls.recentAuth.length, 0);

  const oversized = fixture();
  const oversizedResult = await oversized.api.handle(baseRequest(undefined, { body: "{" + "x".repeat(70_000) + "}" }));
  assert.equal(oversizedResult.status, 413);
  assert.equal(oversized.calls.recentAuth.length, 0);

  const wrongType = fixture();
  const wrongTypeResult = await wrongType.api.handle(baseRequest(undefined, { headers: { "content-type": "text/plain" } }));
  assert.equal(wrongTypeResult.status, 400);
  assert.equal(wrongType.calls.recentAuth.length, 0);

  const mismatchedLength = fixture();
  const mismatchedLengthResult = await mismatchedLength.api.handle(baseRequest(undefined, { body: JSON.stringify(intent()), headers: { "content-length": "1" } }));
  assert.equal(mismatchedLengthResult.status, 400);
  assert.equal(mismatchedLength.calls.recentAuth.length, 0);
});

test("does not expose signer or repository private material when the signer fails", async () => {
  const { api } = fixture({ signerOverrides: { error: new Error("PRIVATE KEY and database password") } });
  const result = await api.handle(baseRequest());
  assert.equal(result.status, 503);
  assert.equal(result.body.error.code, HUMAN_AGENT_SESSION_GRANT_HTTP_ERROR_CODES.GRANT_UNAVAILABLE);
  assert.equal(JSON.stringify(result.body).includes("PRIVATE KEY"), false);
  assert.equal(JSON.stringify(result.body).includes("password"), false);
});

test("the direct issuance service rejects adapter build metadata and validates the committed grant", async () => {
  const repository = {
    async issueAgentSessionGrant(input) {
      assert.equal(input.intent.adapter_version, "1.2.3+build.7");
      throw new Error("repository should not be reached for invalid direct intent");
    }
  };
  const service = createAgentSessionGrantIssuanceService({ repository, signer: { key_id: "grant-key-v1", async sign() { return Buffer.alloc(64); } }, clock: { now: () => NOW }, uuid: () => GRANT_ID });
  await assert.rejects(() => service.issue({
    actor: session(),
    organization_id: ORGANIZATION_ID,
    agent_id: AGENT_ID,
    intent: intent({ adapter_version: "1.2.3+build.7" }),
    idempotency_key: "grant-request-1",
    recent_authorization: { authorization_id: RECENT_AUTH_ID, authenticated_at: NOW }
  }), (error) => error.code === AGENT_SESSION_GRANT_ISSUANCE_ERROR_CODES.INVALID_REQUEST);
});
