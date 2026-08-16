import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import { verifyDeviceRequest, signDeviceRequest, createReplayCache } from "../src/auth.mjs";
import {
  AGENT_SESSION_SIGNING_CAPABILITY_HTTP_ERROR_CODES,
  AGENT_SESSION_SIGNING_CAPABILITY_HTTP_PATHS,
  createAgentSessionSigningCapabilityApi
} from "../src/agent-session-signing-capability-api.mjs";
import { canonicalJson } from "../../../packages/protocol/src/index.mjs";

const NOW = Date.parse("2026-08-16T03:00:00.000Z");
const IDS = Object.freeze({
  organization: "11111111-1111-4111-8111-111111111111",
  device: "22222222-2222-4222-8222-222222222222",
  session: "33333333-3333-4333-8333-333333333333",
  agent: "44444444-4444-4444-8444-444444444444",
  capability: "55555555-5555-4555-8555-555555555555",
  request: "66666666-6666-4666-8666-666666666666",
  correlation: "77777777-7777-4777-8777-777777777777"
});
const PATH = `/v1/organizations/${IDS.organization}/devices/${IDS.device}/agent-sessions/${IDS.session}/signing-capabilities`;
const PROCESS_SCOPE = Object.freeze({
  operations: ["git.commit.sign"],
  repositories: ["/work/project"],
  branches: { allow: ["feature/*"], deny: ["main"] },
  remotes: { allow: ["origin"], deny: [] }
});
const SIGNING_DOMAIN = "AgentPass-Agent-Signing-Capability-v1\0";

function capability(overrides = {}) {
  const signingKeys = crypto.generateKeyPairSync("ed25519");
  const { statement: statementOverrides = {}, ...envelopeOverrides } = overrides;
  const statement = {
    version: 1,
    type: "agentpass.agent-signing-capability",
    capability_id: IDS.capability,
    organization_id: IDS.organization,
    session_id: IDS.session,
    device_id: IDS.device,
    agent_id: IDS.agent,
    one_use: true,
    operation: "git.commit.sign",
    scope: PROCESS_SCOPE,
    key_purpose: "git.commit.sign",
    key_id: "git-commit-sign-2026-08",
    algorithm: "ed25519",
    max_signatures: 1,
    issued_at: new Date(NOW).toISOString(),
    not_before: new Date(NOW).toISOString(),
    expires_at: new Date(NOW + 300_000).toISOString(),
    sequence: 1,
    control_sequence: 12,
    authority_generation: 7,
    issuer: "agentpass-cloud",
    ...statementOverrides
  };
  const statementHash = crypto.createHash("sha256").update(canonicalJson(statement), "utf8").digest("hex");
  const signature = crypto.sign(null, Buffer.from(`${SIGNING_DOMAIN}${canonicalJson(statement)}`, "utf8"), signingKeys.privateKey).toString("base64url");
  return {
    version: 1,
    type: "agentpass.agent-signing-capability",
    statement,
    statement_hash: statementHash,
    signature,
    ...envelopeOverrides
  };
}

function successResponse(overrides = {}) {
  const value = capability(overrides.capability);
  return {
    capability: value,
    metadata: {
      operation: "git.commit.sign",
      key_purpose: "git.commit.sign",
      issued_at: value.statement.issued_at,
      expires_at: value.statement.expires_at,
      sequence: value.statement.sequence,
      remaining_session_signatures: 1,
      replayed: false,
      ...overrides.metadata
    },
    request_id: overrides.request_id ?? IDS.request
  };
}

function canonicalRequestBody(requestId = IDS.request) {
  return Buffer.from(canonicalJson({ request_id: requestId }), "utf8");
}

function fixture({ response = successResponse(), serviceError = undefined, serviceFactory = undefined, binder = undefined, rateLimit = undefined, verifier = undefined } = {}) {
  const deviceKeys = crypto.generateKeyPairSync("ed25519");
  const replayCache = createReplayCache();
  const calls = { auth: [], bind: [], issue: [], rate: [] };
  const service = {
    async issue(input) {
      calls.issue.push(structuredClone(input));
      if (serviceError) throw serviceError;
      return structuredClone(response);
    }
  };
  const api = createAgentSessionSigningCapabilityApi({
    now: () => NOW,
    requestIdFactory: () => IDS.correlation,
    ...(serviceFactory ? { issuanceServiceFactory: serviceFactory } : { issuanceService: service }),
    deviceRequestVerifier: async (request, options) => {
      calls.auth.push({ ...request, body: Buffer.from(request.body), options });
      if (verifier) return verifier(request, options);
      return verifyDeviceRequest(request, [{
        device_id: IDS.device,
        organization_id: IDS.organization,
        status: "active",
        device_public_key: deviceKeys.publicKey.export({ type: "spki", format: "pem" }).toString()
      }], { ...options, replayCache });
    },
    sessionBinder: async (input) => {
      calls.bind.push(structuredClone(input));
      if (binder) return binder(input);
      return { authorized: true, organization_id: IDS.organization, device_id: IDS.device, session_id: IDS.session };
    },
    ...(rateLimit ? { rateLimiter: { async acquire(input) { calls.rate.push(input); return rateLimit(input); } } } : {})
  });
  return { api, calls, deviceKeys };
}

function requestFor(fixtureValue, { method = "POST", path = PATH, body = canonicalRequestBody(), nonce = `capability-device-nonce-${crypto.randomBytes(8).toString("hex")}`, headers = {}, ...extra } = {}) {
  const authHeaders = signDeviceRequest({ method, path, body, device_id: IDS.device, timestamp: NOW, nonce }, fixtureValue.deviceKeys.privateKey);
  return { method, url: path, headers: { ...authHeaders, "content-type": "application/json", ...headers }, body, ...extra };
}

function assertError(result, status, code, requestId = IDS.correlation) {
  assert.equal(result.status, status);
  assert.equal(result.body.error.code, code);
  assert.equal(result.body.request_id, requestId);
  assert.equal(result.body.error.message.includes("private"), false);
  assert.equal(result.body.error.message.includes("password"), false);
  assert.equal(result.body.error.message.includes("provider"), false);
}

test("exports the exact frozen POST path binding", () => {
  assert.deepEqual(AGENT_SESSION_SIGNING_CAPABILITY_HTTP_PATHS, { issue: "/v1/organizations/{organization_id}/devices/{device_id}/agent-sessions/{session_id}/signing-capabilities" });
  assert.equal(Object.isFrozen(AGENT_SESSION_SIGNING_CAPABILITY_HTTP_PATHS), true);
});

test("requires a Device verifier, issuance service, and authoritative session binder", () => {
  assert.throws(() => createAgentSessionSigningCapabilityApi({ issuanceService: { issue() {} }, sessionBinder() {} }), /deviceRequestVerifier/);
  assert.throws(() => createAgentSessionSigningCapabilityApi({ deviceRequestVerifier() {}, sessionBinder() {} }), /issuanceService/);
  assert.throws(() => createAgentSessionSigningCapabilityApi({ deviceRequestVerifier() {}, issuanceService: { issue() {} } }), /sessionBinder/);
});

test("authenticates exact raw bytes before canonical body parsing and calls issuance with request_id only", async () => {
  const f = fixture();
  const body = canonicalRequestBody();
  const result = await f.api.handle(requestFor(f, { body, nonce: "capability-device-nonce-success-00000001" }));
  assert.equal(result.status, 201);
  assert.deepEqual(Object.keys(result.body).sort(), ["capability", "metadata", "request_id"]);
  assert.equal(result.body.request_id, IDS.request);
  assert.equal(result.body.capability.statement.organization_id, IDS.organization);
  assert.equal(result.body.capability.statement.device_id, IDS.device);
  assert.equal(result.body.capability.statement.session_id, IDS.session);
  assert.deepEqual(f.calls.issue, [{ request_id: IDS.request }]);
  assert.equal(f.calls.auth.length, 1);
  assert.deepEqual(f.calls.auth[0].body, body);
  assert.equal(f.calls.auth[0].path, PATH);
  assert.deepEqual(f.calls.bind[0], {
    organization_id: IDS.organization,
    device_id: IDS.device,
    session_id: IDS.session,
    authenticated_device: { organization_id: IDS.organization, device_id: IDS.device },
    now: NOW
  });
  assert.equal(result.headers["Cache-Control"], "no-store, max-age=0");
  assert.equal(result.headers.Pragma, "no-cache");
  assert.equal(result.headers["X-Content-Type-Options"], "nosniff");
  assert.equal(Object.isFrozen(result.body), true);
  assert.equal(Object.isFrozen(result.body.capability), true);
  assert.equal(Object.isFrozen(result.body.capability.statement), true);
});

test("accepts a trusted Device boundary without repeating authentication or rate-limit consumption", async () => {
  const f = fixture({ rateLimit: () => ({ allowed: true, limit: 2, remaining: 1, retryAfterSeconds: 0 }) });
  const request = requestFor(f, { nonce: "capability-device-nonce-authenticated-0001" });
  const result = await f.api.handleAuthenticated(request, {
    organization_id: IDS.organization,
    device_id: IDS.device,
    session_id: IDS.session,
    authenticated_device: { organization_id: IDS.organization, device_id: IDS.device },
    now: NOW
  });
  assert.equal(result.status, 201);
  assert.equal(f.calls.auth.length, 0);
  assert.equal(f.calls.rate.length, 0);
  assert.equal(f.calls.bind.length, 1);
  assert.deepEqual(f.calls.issue, [{ request_id: IDS.request }]);

  const mismatch = await f.api.handleAuthenticated(request, {
    organization_id: IDS.organization,
    device_id: IDS.device,
    session_id: "99999999-9999-4999-8999-999999999999",
    authenticated_device: { organization_id: IDS.organization, device_id: IDS.device },
    now: NOW
  });
  assertError(mismatch, 403, AGENT_SESSION_SIGNING_CAPABILITY_HTTP_ERROR_CODES.AUDIENCE_MISMATCH);
  assert.equal(f.calls.bind.length, 1);
  assert.equal(f.calls.issue.length, 1);
});

test("creates a Session-bound issuance service only after Device authentication and binding", async () => {
  const factoryCalls = [];
  let calls;
  const f = fixture({
    serviceFactory: async (context) => {
      factoryCalls.push(context);
      calls = [];
      return { async issue(input) { calls.push(input); return successResponse(); } };
    }
  });
  const result = await f.api.handle(requestFor(f, { nonce: "capability-device-nonce-factory-00000001" }));
  assert.equal(result.status, 201);
  assert.equal(factoryCalls.length, 1);
  assert.deepEqual(factoryCalls[0], {
    organization_id: IDS.organization,
    device_id: IDS.device,
    session_id: IDS.session,
    binding: { authorized: true, organization_id: IDS.organization, device_id: IDS.device, session_id: IDS.session }
  });
  assert.deepEqual(calls, [{ request_id: IDS.request }]);
});

test("rejects noncanonical, duplicate, unknown, and authority-bearing request bodies after Device authentication", async () => {
  const cases = [
    Buffer.from(` {"request_id":"${IDS.request}"} `),
    Buffer.from(`{"request_id":"${IDS.request}","request_id":"${IDS.request}"}`),
    Buffer.from(JSON.stringify({ request_id: IDS.request, organization_id: IDS.organization })),
    Buffer.from(JSON.stringify({ request_id: IDS.request, scope: PROCESS_SCOPE })),
    Buffer.from(JSON.stringify({ request_id: IDS.request, private_key: "must-not-be-used" }))
  ];
  for (const [index, body] of cases.entries()) {
    const f = fixture();
    const result = await f.api.handle(requestFor(f, { body, nonce: `capability-device-nonce-invalid-${String(index).padStart(2, "0")}-0001` }));
    assertError(result, 400, AGENT_SESSION_SIGNING_CAPABILITY_HTTP_ERROR_CODES.INVALID_REQUEST);
    assert.equal(f.calls.auth.length, 1);
    assert.equal(f.calls.bind.length, 0);
    assert.equal(f.calls.issue.length, 0);
  }
});

test("requires application/json and enforces bounded raw body bytes", async () => {
  const contentType = fixture();
  const wrongType = await contentType.api.handle(requestFor(contentType, { headers: { "content-type": "text/plain" }, nonce: "capability-device-nonce-content-type-0001" }));
  assertError(wrongType, 400, AGENT_SESSION_SIGNING_CAPABILITY_HTTP_ERROR_CODES.INVALID_REQUEST);
  assert.equal(contentType.calls.auth.length, 1);
  assert.equal(contentType.calls.issue.length, 0);

  const oversized = fixture();
  const body = Buffer.alloc(65 * 1024, 0x20);
  const tooLarge = await oversized.api.handle(requestFor(oversized, { body, headers: { "content-type": "application/json", "content-length": String(body.length) }, nonce: "capability-device-nonce-too-large-0001" }));
  assertError(tooLarge, 413, AGENT_SESSION_SIGNING_CAPABILITY_HTTP_ERROR_CODES.INVALID_REQUEST);
  assert.equal(oversized.calls.auth.length, 0);
});

test("rejects query/path substitutions, wrong method, bearer headers, and redirected inputs", async () => {
  const method = fixture();
  assertError(await method.api.handle(requestFor(method, { nonce: "capability-device-nonce-method-00000001", method: "GET" })), 400, AGENT_SESSION_SIGNING_CAPABILITY_HTTP_ERROR_CODES.INVALID_REQUEST);

  const query = fixture();
  assertError(await query.api.handle(requestFor(query, { path: `${PATH}?redirect=/evil`, nonce: "capability-device-nonce-query-00000001" })), 400, AGENT_SESSION_SIGNING_CAPABILITY_HTTP_ERROR_CODES.INVALID_REQUEST);
  assert.equal(query.calls.auth.length, 0);

  const bearer = fixture();
  assertError(await bearer.api.handle(requestFor(bearer, { headers: { Authorization: "Bearer secret" }, nonce: "capability-device-nonce-bearer-0000001" })), 400, AGENT_SESSION_SIGNING_CAPABILITY_HTTP_ERROR_CODES.INVALID_REQUEST);
  assert.equal(bearer.calls.auth.length, 0);

  const redirected = fixture();
  assertError(await redirected.api.handle(requestFor(redirected, { redirected: true, nonce: "capability-device-nonce-redirect-000001" })), 400, AGENT_SESSION_SIGNING_CAPABILITY_HTTP_ERROR_CODES.INVALID_REQUEST);
  assert.equal(redirected.calls.auth.length, 0);

  const missing = fixture();
  assertError(await missing.api.handle(requestFor(missing, { path: "/v1/organizations/not-a-uuid/devices/not-a-device/agent-sessions/not-a-session/signing-capabilities", nonce: "capability-device-nonce-missing-000001" })), 404, AGENT_SESSION_SIGNING_CAPABILITY_HTTP_ERROR_CODES.NOT_FOUND);
});

test("fails closed for Device organization/device/session audience substitutions", async () => {
  const wrongDevice = fixture({ verifier: async () => ({ organization_id: IDS.organization, device_id: "88888888-8888-4888-8888-888888888888" }) });
  const result = await wrongDevice.api.handle(requestFor(wrongDevice, { nonce: "capability-device-nonce-audience-000001" }));
  assertError(result, 403, AGENT_SESSION_SIGNING_CAPABILITY_HTTP_ERROR_CODES.AUDIENCE_MISMATCH);
  assert.equal(wrongDevice.calls.bind.length, 0);
  assert.equal(wrongDevice.calls.issue.length, 0);

  const wrongSession = fixture({ binder: async () => ({ authorized: true, organization_id: IDS.organization, device_id: IDS.device, session_id: "88888888-8888-4888-8888-888888888888" }) });
  const sessionResult = await wrongSession.api.handle(requestFor(wrongSession, { nonce: "capability-device-nonce-audience-000002" }));
  assertError(sessionResult, 403, AGENT_SESSION_SIGNING_CAPABILITY_HTTP_ERROR_CODES.AUDIENCE_MISMATCH);
  assert.equal(wrongSession.calls.issue.length, 0);
});

test("treats Device verifier infrastructure failures as unavailable without exposing provider details", async () => {
  const f = fixture({ verifier: async () => { throw { code: "ERR_PROVIDER_UNAVAILABLE", message: "provider=private-kms-secret" }; } });
  const result = await f.api.handle(requestFor(f, { nonce: "capability-device-nonce-provider-000001" }));
  assertError(result, 503, AGENT_SESSION_SIGNING_CAPABILITY_HTTP_ERROR_CODES.UNAVAILABLE);
  assert.equal(JSON.stringify(result.body).includes("private-kms-secret"), false);
  assert.equal(f.calls.bind.length, 0);
  assert.equal(f.calls.issue.length, 0);
});

test("accepts only a session binder result that remains bound to all route identifiers", async () => {
  const f = fixture({ binder: async () => ({ authorized: true, organizationId: IDS.organization, deviceId: IDS.device, sessionId: "88888888-8888-4888-8888-888888888888" }) });
  const result = await f.api.handle(requestFor(f, { nonce: "capability-device-nonce-camel-000001" }));
  assertError(result, 403, AGENT_SESSION_SIGNING_CAPABILITY_HTTP_ERROR_CODES.AUDIENCE_MISMATCH);
  assert.equal(f.calls.issue.length, 0);
});

test("binds the active Agent Session before issuance and maps binding failures", async () => {
  for (const [binder, status, code] of [
    [async () => ({ authorized: false }), 403, AGENT_SESSION_SIGNING_CAPABILITY_HTTP_ERROR_CODES.SESSION_NOT_AUTHORIZED],
    [async () => { throw { code: "session_not_found", message: "database details" }; }, 404, AGENT_SESSION_SIGNING_CAPABILITY_HTTP_ERROR_CODES.NOT_FOUND],
    [async () => { throw { code: "ERR_SESSION_CONFLICT", message: "private diagnostics" }; }, 409, AGENT_SESSION_SIGNING_CAPABILITY_HTTP_ERROR_CODES.CONFLICT],
    [async () => { throw { code: "ERR_DATABASE", message: "password=secret" }; }, 503, AGENT_SESSION_SIGNING_CAPABILITY_HTTP_ERROR_CODES.UNAVAILABLE]
  ]) {
    const f = fixture({ binder });
    const result = await f.api.handle(requestFor(f, { nonce: `capability-device-nonce-binding-${status}-000001` }));
    assertError(result, status, code);
    assert.equal(f.calls.issue.length, 0);
    assert.equal(JSON.stringify(result.body).includes("database"), false);
  }
});

test("applies the Device rate limit after authentication and before binding or body parsing", async () => {
  const f = fixture({ rateLimit: async () => ({ allowed: false, limit: 10, remaining: 0, retryAfterSeconds: 7 }) });
  const result = await f.api.handle(requestFor(f, { body: Buffer.from("not-json"), nonce: "capability-device-nonce-rate-limit-0001" }));
  assertError(result, 429, AGENT_SESSION_SIGNING_CAPABILITY_HTTP_ERROR_CODES.RATE_LIMITED);
  assert.equal(result.headers["Retry-After"], "7");
  assert.equal(f.calls.auth.length, 1);
  assert.equal(f.calls.bind.length, 0);
  assert.equal(f.calls.issue.length, 0);
});

test("rejects an inconsistent Content-Length before Device authentication", async () => {
  const f = fixture();
  const result = await f.api.handle(requestFor(f, {
    headers: { "content-length": "1" },
    nonce: "capability-device-nonce-length-0001"
  }));
  assertError(result, 400, AGENT_SESSION_SIGNING_CAPABILITY_HTTP_ERROR_CODES.INVALID_REQUEST);
  assert.equal(f.calls.auth.length, 0);
  assert.equal(f.calls.issue.length, 0);
});

test("maps a raw-body reader failure to the stable invalid-request error", async () => {
  const f = fixture();
  const result = await f.api.handle({
    method: "POST",
    url: PATH,
    headers: { "content-type": "application/json" },
    async arrayBuffer() { throw new Error("raw body transport secret"); }
  });
  assertError(result, 400, AGENT_SESSION_SIGNING_CAPABILITY_HTTP_ERROR_CODES.INVALID_REQUEST);
  assert.equal(f.calls.auth.length, 0);
  assert.equal(f.calls.issue.length, 0);
});

test("maps issuance replay, conflict, in-progress, outcome-unknown, rate-limit, and outage without diagnostics", async () => {
  const replay = fixture({ response: successResponse({ metadata: { replayed: true } }) });
  const replayResult = await replay.api.handle(requestFor(replay, { nonce: "capability-device-nonce-replay-000001" }));
  assert.equal(replayResult.status, 201);
  assert.equal(replayResult.body.metadata.replayed, true);

  for (const [error, status, code] of [
    [{ code: "ERR_AGENT_SIGNING_CAPABILITY_ISSUANCE_CONFLICT", message: "tenant SQL" }, 409, AGENT_SESSION_SIGNING_CAPABILITY_HTTP_ERROR_CODES.CONFLICT],
    [{ code: "ERR_AGENT_SIGNING_CAPABILITY_ISSUANCE_IN_PROGRESS", message: "internal" }, 409, AGENT_SESSION_SIGNING_CAPABILITY_HTTP_ERROR_CODES.IN_PROGRESS],
    [{ code: "ERR_AGENT_SIGNING_CAPABILITY_ISSUANCE_OUTCOME_UNKNOWN", message: "provider response" }, 503, AGENT_SESSION_SIGNING_CAPABILITY_HTTP_ERROR_CODES.OUTCOME_UNKNOWN],
    [{ code: "ERR_RATE_LIMITED", retryAfterSeconds: 11, message: "secret" }, 429, AGENT_SESSION_SIGNING_CAPABILITY_HTTP_ERROR_CODES.RATE_LIMITED],
    [{ code: "ERR_DATABASE", message: "password=do-not-leak" }, 503, AGENT_SESSION_SIGNING_CAPABILITY_HTTP_ERROR_CODES.UNAVAILABLE]
  ]) {
    const f = fixture({ serviceError: error });
    const result = await f.api.handle(requestFor(f, { nonce: `capability-device-nonce-issuance-${status}-000001` }));
    assertError(result, status, code);
    if (status === 429) assert.equal(result.headers["Retry-After"], "11");
    assert.equal(JSON.stringify(result.body).includes(error.message), false);
  }
});

test("rejects capability response substitution, extra fields, bad hash, and secret-bearing output", async () => {
  const valid = successResponse();
  const overlongCapability = capability({ statement: { expires_at: new Date(NOW + 15 * 60_000 + 1).toISOString() } });
  const overlong = fixture({ response: {
    capability: overlongCapability,
    metadata: { ...valid.metadata, expires_at: overlongCapability.statement.expires_at },
    request_id: IDS.request
  } });
  assertError(await overlong.api.handle(requestFor(overlong, { nonce: "capability-device-nonce-output-ttl-0001" })), 503, AGENT_SESSION_SIGNING_CAPABILITY_HTTP_ERROR_CODES.UNAVAILABLE);

  const cases = [
    { capability: { statement: { organization_id: IDS.device } } },
    { capability: { leaked_secret: "never-return" } },
    { capability: { statement_hash: "0".repeat(64) } },
    { metadata: { unexpected: true } },
    { request_id: IDS.device }
  ];
  for (const [index, overrides] of cases.entries()) {
    const f = fixture({ response: { ...successResponse(), ...overrides } });
    const result = await f.api.handle(requestFor(f, { nonce: `capability-device-nonce-output-${String(index).padStart(2, "0")}-0001` }));
    assertError(result, 503, AGENT_SESSION_SIGNING_CAPABILITY_HTTP_ERROR_CODES.UNAVAILABLE);
  }
});

test("writes a no-store response through the Node adapter", async () => {
  const f = fixture();
  const written = { headers: undefined, status: undefined, body: undefined };
  const nodeResponse = {
    writeHead(status, headers) { written.status = status; written.headers = headers; },
    end(body) { written.body = body; }
  };
  const result = await f.api.handle(requestFor(f, { nonce: "capability-device-nonce-node-00000001" }), nodeResponse);
  assert.equal(result.status, 201);
  assert.equal(written.status, 201);
  assert.equal(written.headers["Cache-Control"], "no-store, max-age=0");
  assert.deepEqual(JSON.parse(written.body), result.body);
});
