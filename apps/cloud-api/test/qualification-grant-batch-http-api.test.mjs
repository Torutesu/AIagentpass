import assert from "node:assert/strict";
import test from "node:test";

import {
  HUMAN_QUALIFICATION_GRANT_BATCH_HTTP_ERROR_CODES,
  HUMAN_QUALIFICATION_GRANT_BATCH_HTTP_PATHS,
  createHumanQualificationGrantBatchHttpApi
} from "../src/human-auth/agent-sessions/qualification-batch-http-api.mjs";

const ORIGIN = "https://console.agentpass.test";
const ORGANIZATION_ID = "11111111-1111-4111-8111-111111111111";
const OTHER_ORGANIZATION_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const AGENT_ID = "22222222-2222-4222-8222-222222222222";
const DEVICE_ID = "33333333-3333-4333-8333-333333333333";
const ADAPTER_ID = "44444444-4444-4444-8444-444444444444";
const MEMBER_ID = "55555555-5555-4555-8555-555555555555";
const SESSION_ID = "66666666-6666-4666-8666-666666666666";
const RECENT_AUTH_ID = "77777777-7777-4777-8777-777777777777";
const BATCH_ID = "88888888-8888-4888-8888-888888888888";
const REQUEST_ID = "99999999-9999-4999-8999-999999999999";
const NOW = Date.parse("2026-08-14T00:00:00.000Z");
const CSRF = "c".repeat(43);
const SESSION_TOKEN = "s".repeat(43);
const COOKIE = `__Host-agentpass_session=${SESSION_TOKEN}; Path=/; HttpOnly; Secure; SameSite=Strict`;

function qualificationRequest(overrides = {}) {
  return {
    candidate_sha256: "a".repeat(64),
    artifact_sha256: "b".repeat(64),
    candidate_checkpoint_sha256: "c".repeat(64),
    release_trust_sha256: "d".repeat(64),
    source_commit: "e".repeat(40),
    team_id: "ABCDEFGHIJ",
    grant_intent: {
      device_id: DEVICE_ID,
      agent_kind: "claude-code",
      adapter_id: ADAPTER_ID,
      adapter_version: "1.2.3",
      worktree_binding_sha256: "f".repeat(64),
      process_binding_policy_id: "qualification-v1",
      scope: {
        operations: ["git.commit.sign"],
        repositories: ["/Users/example/repository"],
        branches: { allow: ["main"], deny: [] },
        remotes: { allow: ["origin"], deny: [] }
      },
      max_signatures: 1,
      ttl_seconds: 600
    },
    ...overrides
  };
}

function actor(overrides = {}) {
  return { session_id: SESSION_ID, member_id: MEMBER_ID, organization_id: ORGANIZATION_ID, role: "admin", ...overrides };
}

function publicBatch(overrides = {}) {
  return {
    schema_version: 1,
    kind: "agentpass-n3e-qualification-grant-batch",
    batch_id: BATCH_ID,
    organization_id: ORGANIZATION_ID,
    device_id: DEVICE_ID,
    agent_id: AGENT_ID,
    candidate_sha256: "a".repeat(64),
    artifact_sha256: "b".repeat(64),
    candidate_checkpoint_sha256: "c".repeat(64),
    release_trust_sha256: "d".repeat(64),
    source_commit: "e".repeat(40),
    team_id: "ABCDEFGHIJ",
    issued_at: "2026-08-14T00:00:00.000Z",
    expires_at: "2026-08-14T00:10:00.000Z",
    status: "issued",
    ...overrides
  };
}

function baseRequest(path = HUMAN_QUALIFICATION_GRANT_BATCH_HTTP_PATHS.issue(ORGANIZATION_ID, AGENT_ID), overrides = {}) {
  return {
    method: "POST",
    url: path,
    headers: {
      origin: ORIGIN,
      cookie: COOKIE,
      "agentpass-csrf": CSRF,
      "agentpass-recent-auth": RECENT_AUTH_ID,
      "idempotency-key": "qualification-batch-1",
      "content-type": "application/json",
      ...(overrides.headers ?? {})
    },
    body: overrides.body ?? qualificationRequest()
  };
}

function fixture({ sessionOverrides = {}, recentAuthResult = undefined, recentAuthError = undefined, serviceResult = undefined, serviceError = undefined } = {}) {
  const calls = { auth: [], recentAuth: [], service: [] };
  const service = {
    async issue(input) {
      calls.service.push(input);
      if (serviceError) throw serviceError;
      return serviceResult ?? { batch: publicBatch(), request_id: REQUEST_ID };
    }
  };
  const humanSession = {
    expectedOrigin: ORIGIN,
    async authenticateRequest(input) {
      calls.auth.push(input);
      return { session: actor(sessionOverrides) };
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
  const api = createHumanQualificationGrantBatchHttpApi({ humanSession, recentAuthService, qualificationBatchService: service, origin: ORIGIN, clock: { now: () => NOW } });
  return { api, calls };
}

function assertNoStore(result) {
  assert.match(result.headers["Cache-Control"], /\bno-store\b/u);
  assert.equal(result.headers.Pragma, "no-cache");
  assert.equal(result.headers.Expires, "0");
}

test("issues through the injected service with the exact route and returns only public batch metadata", async () => {
  const { api, calls } = fixture();
  const result = await api.handle(baseRequest());

  assert.equal(result.status, 201);
  assertNoStore(result);
  assert.deepEqual(Object.keys(result.body).sort(), ["batch", "request_id"]);
  assert.deepEqual(Object.keys(result.body.batch).sort(), [
    "agent_id", "artifact_sha256", "batch_id", "candidate_checkpoint_sha256", "candidate_sha256", "device_id", "expires_at", "issued_at", "kind", "organization_id", "release_trust_sha256", "schema_version", "source_commit", "status", "team_id"
  ]);
  assert.equal(Object.hasOwn(result.body, "grants"), false);
  assert.equal(JSON.stringify(result.body).includes("signature"), false);
  assert.equal(JSON.stringify(result.body).includes("private"), false);
  assert.equal(calls.service.length, 1);
  assert.equal(calls.service[0].organization_id, ORGANIZATION_ID);
  assert.equal(calls.service[0].agent_id, AGENT_ID);
  assert.equal(calls.service[0].idempotency_key, "qualification-batch-1");
  assert.deepEqual(calls.service[0].request, qualificationRequest());
  assert.deepEqual(calls.service[0].recent_authorization, {
    authorization_id: RECENT_AUTH_ID,
    authenticated_at: NOW,
    member_id: MEMBER_ID,
    operation: "qualification.grant_batch.issue",
    organization_id: ORGANIZATION_ID
  });
  assert.equal(calls.recentAuth[0].operation, "qualification.grant_batch.issue");
  assert.equal(calls.auth[0].method, "POST");
});

test("enforces exact Origin, session cookie, CSRF, Idempotency-Key, and recent-auth before service invocation", async () => {
  for (const [headerName, value, status, code] of [
    ["origin", "https://evil.example", 403, HUMAN_QUALIFICATION_GRANT_BATCH_HTTP_ERROR_CODES.ORIGIN_NOT_ALLOWED],
    ["cookie", undefined, 401, HUMAN_QUALIFICATION_GRANT_BATCH_HTTP_ERROR_CODES.SESSION_REQUIRED],
    ["agentpass-csrf", "short", 403, HUMAN_QUALIFICATION_GRANT_BATCH_HTTP_ERROR_CODES.CSRF_FAILED],
    ["idempotency-key", "short", 400, HUMAN_QUALIFICATION_GRANT_BATCH_HTTP_ERROR_CODES.IDEMPOTENCY_REQUIRED],
    ["agentpass-recent-auth", "not-a-uuid", 401, HUMAN_QUALIFICATION_GRANT_BATCH_HTTP_ERROR_CODES.RECENT_AUTH_REQUIRED]
  ]) {
    const { api, calls } = fixture();
    const request = baseRequest();
    if (value === undefined) delete request.headers[headerName];
    else request.headers[headerName] = value;
    const result = await api.handle(request);
    assert.equal(result.status, status, headerName);
    assert.equal(result.body.error.code, code, headerName);
    assertNoStore(result);
    assert.equal(calls.recentAuth.length, 0, headerName);
    assert.equal(calls.service.length, 0, headerName);
  }
});

test("requires owner/admin and hides cross-tenant existence", async () => {
  const viewer = fixture({ sessionOverrides: { role: "viewer" } });
  const viewerResult = await viewer.api.handle(baseRequest());
  assert.equal(viewerResult.status, 403);
  assert.equal(viewerResult.body.error.code, HUMAN_QUALIFICATION_GRANT_BATCH_HTTP_ERROR_CODES.FORBIDDEN);
  assert.equal(viewer.calls.recentAuth.length, 0);
  assert.equal(viewer.calls.service.length, 0);

  const crossTenant = fixture();
  const crossTenantResult = await crossTenant.api.handle(baseRequest(HUMAN_QUALIFICATION_GRANT_BATCH_HTTP_PATHS.issue(OTHER_ORGANIZATION_ID, AGENT_ID)));
  assert.equal(crossTenantResult.status, 404);
  assert.equal(crossTenantResult.body.error.code, HUMAN_QUALIFICATION_GRANT_BATCH_HTTP_ERROR_CODES.NOT_FOUND);
  assert.equal(crossTenant.calls.recentAuth.length, 0);
  assert.equal(crossTenant.calls.service.length, 0);
});

test("rejects path aliases, query/hash/method changes, and forbidden identity headers", async () => {
  for (const path of [
    "/api/v1/organizations/not-a-uuid/agents/22222222-2222-4222-8222-222222222222/qualification-grant-batches",
    "/api/v1/organizations/11111111-1111-4111-8111-111111111111/agents/not-a-uuid/qualification-grant-batches",
    "/api/v1/organizations/11111111-1111-4111-8111-111111111111/agents/22222222-2222-4222-8222-222222222222/qualification-grant-batches/extra",
    "/api/v1/organizations/11111111-1111-4111-8111-111111111111/agents/22222222-2222-4222-8222-222222222222/session-grants"
  ]) {
    const { api, calls } = fixture();
    const result = await api.handle(baseRequest(path));
    assert.equal(result.status, path.includes("not-a-uuid") ? 400 : 404, path);
    assert.equal(calls.service.length, 0, path);
  }

  const query = fixture();
  const queryResult = await query.api.handle(baseRequest(`${HUMAN_QUALIFICATION_GRANT_BATCH_HTTP_PATHS.issue(ORGANIZATION_ID, AGENT_ID)}?x=1`));
  assert.equal(queryResult.status, 400);
  assert.equal(query.calls.service.length, 0);

  const hash = fixture();
  const hashResult = await hash.api.handle(baseRequest(`${HUMAN_QUALIFICATION_GRANT_BATCH_HTTP_PATHS.issue(ORGANIZATION_ID, AGENT_ID)}#x`));
  assert.equal(hashResult.status, 404);

  const method = fixture();
  const methodResult = await method.api.handle({ ...baseRequest(), method: "GET" });
  assert.equal(methodResult.status, 405);
  assert.equal(methodResult.headers.Allow, "POST");

  for (const headerName of ["authorization", "agentpass-role", "agentpass-member-id", "agentpass-console-identity", "x-csrf-token"]) {
    const { api, calls } = fixture();
    const result = await api.handle(baseRequest(undefined, { headers: { [headerName]: "attacker-controlled" } }));
    assert.equal(result.status, 400, headerName);
    assert.equal(result.body.error.code, HUMAN_QUALIFICATION_GRANT_BATCH_HTTP_ERROR_CODES.INVALID_REQUEST, headerName);
    assert.equal(calls.auth.length, 0, headerName);
  }
});

test("enforces a closed bounded JSON request and rejects duplicate keys and secret-shaped fields", async () => {
  const invalidBodies = [
    { ...qualificationRequest(), unexpected: true },
    { ...qualificationRequest(), private_key: "do-not-accept" },
    { ...qualificationRequest(), candidate_sha256: "not-a-sha256" },
    { ...qualificationRequest(), source_commit: "a".repeat(64) },
    { ...qualificationRequest(), team_id: "bad" },
    { ...qualificationRequest(), grant_intent: { ...qualificationRequest().grant_intent, secret: "do-not-accept" } },
    { ...qualificationRequest(), grant_intent: { ...qualificationRequest().grant_intent, max_signatures: 2 } }
  ];
  for (const body of invalidBodies) {
    const { api, calls } = fixture();
    const result = await api.handle(baseRequest(undefined, { body }));
    assert.equal(result.status, 400, JSON.stringify(body));
    assert.equal(result.body.error.code, HUMAN_QUALIFICATION_GRANT_BATCH_HTTP_ERROR_CODES.INVALID_REQUEST);
    assert.equal(calls.recentAuth.length, 0);
    assert.equal(calls.service.length, 0);
  }

  const duplicate = fixture();
  const duplicateResult = await duplicate.api.handle(baseRequest(undefined, { body: `{"candidate_sha256":"${"a".repeat(64)}","candidate_sha256":"${"b".repeat(64)}"}` }));
  assert.equal(duplicateResult.status, 400);
  assert.equal(duplicate.calls.service.length, 0);

  const oversized = fixture();
  const oversizedResult = await oversized.api.handle(baseRequest(undefined, { body: `{${"x".repeat(70_000)}}` }));
  assert.equal(oversizedResult.status, 413);
  assert.equal(oversized.calls.service.length, 0);

  const wrongType = fixture();
  const wrongTypeResult = await wrongType.api.handle(baseRequest(undefined, { headers: { "content-type": "text/plain" } }));
  assert.equal(wrongTypeResult.status, 400);
  assert.equal(wrongType.calls.service.length, 0);
});

test("requires the exact recent-auth authorization shape and operation", async () => {
  for (const recentAuthResult of [
    { verified: false, consumed: true, challenge_id: RECENT_AUTH_ID, member_id: MEMBER_ID, organization_id: ORGANIZATION_ID, operation: "qualification.grant_batch.issue", authenticated_at: NOW },
    { verified: true, consumed: true, challenge_id: RECENT_AUTH_ID, member_id: MEMBER_ID, organization_id: ORGANIZATION_ID, operation: "agent.session_grant.issue", authenticated_at: NOW },
    { verified: true, consumed: true, challenge_id: RECENT_AUTH_ID, member_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", organization_id: ORGANIZATION_ID, operation: "qualification.grant_batch.issue", authenticated_at: NOW },
    { verified: true, consumed: true, challenge_id: RECENT_AUTH_ID, member_id: MEMBER_ID, organization_id: ORGANIZATION_ID, operation: "qualification.grant_batch.issue", authenticated_at: NOW - 300_001 },
    { verified: true, consumed: true, challenge_id: RECENT_AUTH_ID, member_id: MEMBER_ID, organization_id: ORGANIZATION_ID, operation: "qualification.grant_batch.issue", authenticated_at: NOW + 30_001 },
    { verified: true, consumed: true, challenge_id: RECENT_AUTH_ID, member_id: MEMBER_ID, organization_id: ORGANIZATION_ID, operation: "qualification.grant_batch.issue", authenticated_at: NOW, extra: "reject" }
  ]) {
    const { api, calls } = fixture({ recentAuthResult });
    const result = await api.handle(baseRequest());
    assert.equal(result.status, 401);
    assert.ok([HUMAN_QUALIFICATION_GRANT_BATCH_HTTP_ERROR_CODES.RECENT_AUTH_FAILED, HUMAN_QUALIFICATION_GRANT_BATCH_HTTP_ERROR_CODES.RECENT_AUTH_STALE].includes(result.body.error.code));
    assert.equal(calls.service.length, 0);
  }

  const unavailable = fixture({ recentAuthError: Object.assign(new Error("database password and secret diagnostics"), { code: "db_down" }) });
  const unavailableResult = await unavailable.api.handle(baseRequest());
  assert.equal(unavailableResult.status, 503);
  assert.equal(unavailableResult.body.error.code, HUMAN_QUALIFICATION_GRANT_BATCH_HTTP_ERROR_CODES.RECENT_AUTH_UNAVAILABLE);
  assert.equal(JSON.stringify(unavailableResult.body).includes("password"), false);
});

test("maps service conflicts and outages to stable no-store responses without secret leakage", async () => {
  const conflict = fixture({ serviceError: Object.assign(new Error("idempotency secret internals"), { code: QUALIFICATION_CODE("idempotency_conflict") }) });
  const conflictResult = await conflict.api.handle(baseRequest());
  assert.equal(conflictResult.status, 409);
  assert.equal(conflictResult.body.error.code, HUMAN_QUALIFICATION_GRANT_BATCH_HTTP_ERROR_CODES.IDEMPOTENCY_CONFLICT);
  assertNoStore(conflictResult);
  assert.equal(JSON.stringify(conflictResult.body).includes("secret"), false);

  const outage = fixture({ serviceError: new Error("postgres password PRIVATE KEY") });
  const outageResult = await outage.api.handle(baseRequest());
  assert.equal(outageResult.status, 503);
  assert.equal(outageResult.body.error.code, HUMAN_QUALIFICATION_GRANT_BATCH_HTTP_ERROR_CODES.BATCH_UNAVAILABLE);
  assertNoStore(outageResult);
  assert.equal(JSON.stringify(outageResult.body).includes("password"), false);
  assert.equal(JSON.stringify(outageResult.body).includes("PRIVATE KEY"), false);
});

test("rejects an injected result that tries to return Grants, steps, or malformed public metadata", async () => {
  for (const serviceResult of [
    { batch: { ...publicBatch(), grants: [{ signature: "secret" }] }, request_id: REQUEST_ID },
    { batch: { ...publicBatch(), steps: [{ grant: "secret" }] }, request_id: REQUEST_ID },
    { batch: { ...publicBatch(), batch_id: "not-a-uuid" }, request_id: REQUEST_ID },
    { batch: publicBatch(), request_id: REQUEST_ID, secret: "must-not-be-forwarded" }
  ]) {
    const { api, calls } = fixture({ serviceResult });
    const result = await api.handle(baseRequest());
    assert.equal(result.status, 503);
    assert.equal(result.body.error.code, HUMAN_QUALIFICATION_GRANT_BATCH_HTTP_ERROR_CODES.BATCH_UNAVAILABLE);
    assertNoStore(result);
    assert.equal(JSON.stringify(result.body).includes("secret"), false);
    assert.equal(calls.service.length, 1);
  }
});

test("accepts owner sessions and a service exposing issueQualificationGrantBatch", async () => {
  const { api, calls } = fixture({ sessionOverrides: { role: "owner" } });
  const service = {
    async issueQualificationGrantBatch(input) {
      calls.service.push(input);
      return { batch: publicBatch(), request_id: REQUEST_ID, replayed: true };
    }
  };
  const ownerApi = createHumanQualificationGrantBatchHttpApi({
    humanSession: { expectedOrigin: ORIGIN, async authenticateRequest() { return { session: actor({ role: "owner" }) }; } },
    recentAuthService: { async authorize(input) { return { verified: true, consumed: true, challenge_id: RECENT_AUTH_ID, member_id: MEMBER_ID, organization_id: ORGANIZATION_ID, operation: input.operation, authenticated_at: NOW }; } },
    qualificationBatchService: service,
    origin: ORIGIN,
    clock: { now: () => NOW }
  });
  const result = await ownerApi.handle(baseRequest());
  assert.equal(result.status, 201);
  assert.equal(result.body.replayed, true);
  assert.equal(calls.service.length, 1);
});

function QUALIFICATION_CODE(code) {
  return `qualification_grant_batch_${code}`;
}
