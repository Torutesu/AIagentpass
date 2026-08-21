import assert from "node:assert/strict";
import test from "node:test";

import { createCloudApi } from "../src/server.mjs";
import { createPlatformAuthenticator } from "../src/platform-auth.mjs";
import { createPlatformPromotionHttpApi, PLATFORM_PROMOTION_PATHS } from "../src/platform-promotion-http-api.mjs";

const AUTHORITY = Object.freeze({
  deployment_id: "agentpass-prod",
  environment: "production",
  promotion_id: "11111111-1111-4111-8111-111111111111",
  candidate_id: `release-pkg-sha256-v1-${"a".repeat(64)}`,
  source_commit: "b".repeat(40),
  source_tree: "c".repeat(40),
  product_pkg_sha256: "a".repeat(64),
  release_manifest_sha256: "d".repeat(64),
  sbom_sha256: "e".repeat(64),
  image_digest: `sha256:${"f".repeat(64)}`,
  qualification_report_digests: ["1".repeat(64)],
  approval_id: "22222222-2222-4222-8222-222222222222",
  approval_digest: "2".repeat(64),
  signer_key_id: "kms/promotion-v1",
  signer_key_version: 1,
  signer_lifecycle_version: 7,
  expected_deployment_generation: 0
});
const IDEMPOTENCY = "promotion-http-0001";
const PROVIDER_OPERATION_ID = "provider-op-1";
const PLATFORM_WORKLOAD_ID = "spiffe://agentpass.example/workload/platform-api";
const PLATFORM_AUDIENCE = "agentpass.platform.promotion";
const PLATFORM_FINGERPRINT = "aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99";
const PLATFORM_RECENT_AUTH = "11111111-1111-4111-8111-111111111111";
function authorizedPlatformResult({ role = "platform_operator", organization_id, operation = "promotion.issue", context_hash = "0".repeat(64) } = {}) {
  return {
    principal: { member_id: "platform-release-operator", session_id: "platform-session-1", platform_role: role, ...(organization_id === undefined ? {} : { organization_id }) },
    mtls: { fingerprint256: PLATFORM_FINGERPRINT, spiffe_id: PLATFORM_WORKLOAD_ID },
    workload: { verified: true, workload_id: PLATFORM_WORKLOAD_ID, audience: PLATFORM_AUDIENCE, expires_at: Date.parse("2026-08-20T00:01:00.000Z"), mtls_fingerprint256: PLATFORM_FINGERPRINT },
    webauthn: { authenticated_at: Date.parse("2026-08-20T00:00:00.000Z"), challenge_id: PLATFORM_RECENT_AUTH, consumed: true, context_hash, member_id: "platform-release-operator", operation, verified: true }
  };
}

function fakeRepository(calls) {
  const transaction = Object.freeze({ async query() { return { rowCount: 0, rows: [] }; } });
  async function audited(input, result) {
    await input.onMutation?.({ tx: transaction, result });
    return result;
  }
  return {
    supportsAtomicPromotionAudit: true,
    async reservePromotion(input) { calls.push(["reserve", input]); return audited(input, { state: "reserved", promotion_id: input.promotion_id, provider_operation_id: input.provider_operation_id, authority_digest: "3".repeat(64), claim_token: "A".repeat(43), expires_at: "2026-08-20T01:00:00.000Z" }); },
    async commitPromotion(input) { calls.push(["commit", input]); return audited(input, { state: "committed", promotion_id: input.promotion_id, provider_operation_id: input.provider_operation_id, evidence: input.evidence, generation: 1 }); },
    async reconcileUncertainPromotion(input) { calls.push(["reconcile", input]); return audited(input, { state: "committed", promotion_id: input.promotion_id, provider_operation_id: input.provider_operation_id, evidence: input.evidence, generation: 1 }); }
  };
}

async function start(t, options = {}) {
  const calls = [];
  const repository = fakeRepository(calls);
  const platformPromotionApi = createPlatformPromotionHttpApi({
    repository,
    auditAppender: options.auditAppender ?? (async () => {}),
    authenticate: options.authenticate ?? (async ({ operation, context_hash }) => authorizedPlatformResult({ operation, context_hash })),
    expectedWorkloadAudience: options.expectedWorkloadAudience ?? PLATFORM_AUDIENCE,
    expectedSpiffeId: options.expectedSpiffeId ?? PLATFORM_WORKLOAD_ID,
    now: options.now ?? (() => Date.parse("2026-08-20T00:00:00.000Z"))
  });
  const server = createCloudApi({ store: {}, platformPromotionApi, humanSession: options.humanSession });
  t.after(async () => { if (server.listening) await new Promise((resolve) => server.close(resolve)); });
  return { server, calls };
}

function headers() { return { "content-type": "application/json", "idempotency-key": IDEMPOTENCY, "x-agentpass-platform-auth": "edge-attestation" }; }

async function invoke(server, { path, method = "POST", headers: requestHeaders = {}, body = "" }) {
  let resolve;
  let reject;
  const completed = new Promise((resolvePromise, rejectPromise) => { resolve = resolvePromise; reject = rejectPromise; });
  const response = {
    headersSent: false,
    writeHead(status, responseHeaders) { this.status = status; this.headers = responseHeaders; this.headersSent = true; },
    end(value = Buffer.alloc(0)) { resolve({ status: this.status, headers: this.headers, body: Buffer.from(value).toString("utf8") }); },
    destroy(error) { reject(error ?? new Error("response destroyed")); }
  };
  const request = {
    method,
    url: path,
    headers: requestHeaders,
    socket: { remoteAddress: "127.0.0.1" },
    async *[Symbol.asyncIterator]() { if (body.length > 0) yield Buffer.from(body); }
  };
  server.emit("request", request, response);
  const result = await completed;
  return { ...result, json: () => JSON.parse(result.body) };
}

test("routes C3 issue and reconcile through the Platform boundary, never the organization router", async (t) => {
  const f = await start(t, { humanSession: { async authenticateRequest() { throw new Error("organization session must not be called"); } } });
  const issue = await invoke(f.server, { path: PLATFORM_PROMOTION_PATHS.issue, headers: headers(), body: JSON.stringify({ ...AUTHORITY, provider_operation_id: PROVIDER_OPERATION_ID }) });
  assert.equal(issue.status, 201, issue.body);
  const issueBody = issue.json();
  assert.equal(issueBody.promotion.state, "reserved");
  assert.equal(issueBody.promotion.claim_token, "A".repeat(43));
  assert.equal(issueBody.promotion.provider_operation_id, PROVIDER_OPERATION_ID);
  assert.match(issueBody.request_id, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu);
  assert.equal(Object.hasOwn(issueBody, "platform_principal"), false);
  assert.equal(f.calls[0][0], "reserve");
  assert.equal(f.calls[0][1].idempotency_key, IDEMPOTENCY);

  const evidence = { statement: { promotion_id: AUTHORITY.promotion_id }, signature: "B".repeat(86) };
  const commit = await invoke(f.server, { path: PLATFORM_PROMOTION_PATHS.commit, headers: headers(), body: JSON.stringify({ ...AUTHORITY, provider_operation_id: PROVIDER_OPERATION_ID, claim_token: issueBody.promotion.claim_token, evidence }) });
  assert.equal(commit.status, 200, commit.body);
  assert.equal(commit.json().promotion.state, "committed");
  assert.equal(commit.json().promotion.provider_operation_id, PROVIDER_OPERATION_ID);
  assert.equal(f.calls.at(-1)[0], "commit");
  const reconcile = await invoke(f.server, { path: PLATFORM_PROMOTION_PATHS.reconcile, headers: headers(), body: JSON.stringify({ ...AUTHORITY, provider_operation_id: "provider-op-1", evidence }) });
  assert.equal(reconcile.status, 200, reconcile.body);
  assert.equal(reconcile.json().promotion.state, "committed");
  assert.equal(f.calls.at(-1)[0], "reconcile");
  assert.equal(f.calls.at(-1)[1].idempotency_key, IDEMPOTENCY);
});

test("persists a bounded secret-free audit event for a successful Platform operation", async (t) => {
  const events = [];
  const f = await start(t, { auditAppender: async (event) => { events.push(event); } });
  const issue = await invoke(f.server, { path: PLATFORM_PROMOTION_PATHS.issue, headers: headers(), body: JSON.stringify({ ...AUTHORITY, provider_operation_id: PROVIDER_OPERATION_ID }) });
  assert.equal(issue.status, 201, issue.body);
  assert.equal(events.length, 1);
  assert.equal(events[0].event_type, "platform.promotion.issue.reserved");
  assert.equal(events[0].target_id, AUTHORITY.promotion_id);
  assert.equal(events[0].details.source_commit, AUTHORITY.source_commit);
  assert.equal(JSON.stringify(events[0]).includes("claim_token"), false);
  assert.equal(JSON.stringify(events[0]).includes("edge-attestation"), false);
});

test("binds audit idempotency to the business Idempotency-Key rather than request correlation", async (t) => {
  const events = [];
  const f = await start(t, { auditAppender: async (event) => { events.push(event); } });
  const body = JSON.stringify({ ...AUTHORITY, provider_operation_id: PROVIDER_OPERATION_ID });
  await invoke(f.server, { path: PLATFORM_PROMOTION_PATHS.issue, headers: headers(), body });
  await invoke(f.server, { path: PLATFORM_PROMOTION_PATHS.issue, headers: headers(), body });
  assert.equal(events.length, 2);
  assert.equal(events[0].idempotency_key, events[1].idempotency_key);
  assert.match(events[0].idempotency_key, /^platform-promotion:[0-9a-f]{64}$/u);
});

test("maps an audit sink failure to a request-correlated 503 without leaking its error", async (t) => {
  const f = await start(t, { auditAppender: async () => { throw new Error("audit database secret"); } });
  const response = await invoke(f.server, { path: PLATFORM_PROMOTION_PATHS.issue, headers: headers(), body: JSON.stringify({ ...AUTHORITY, provider_operation_id: PROVIDER_OPERATION_ID }) });
  assert.equal(response.status, 503);
  assert.equal(response.json().error.code, "platform_audit_unavailable");
  assert.match(response.json().request_id, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu);
  assert.equal(response.body.includes("audit database secret"), false);
});

test("rejects unauthenticated and organization-session transports before the Platform authenticator", async (t) => {
  let authenticatorCalls = 0;
  const f = await start(t, {
    authenticate: async ({ operation, context_hash }) => { authenticatorCalls += 1; return authorizedPlatformResult({ operation, context_hash }); },
    humanSession: { async authenticateRequest() { throw new Error("organization session must not be called"); } }
  });
  const noAuth = await invoke(f.server, { path: PLATFORM_PROMOTION_PATHS.issue, headers: { ...headers(), authorization: "Bearer organization-token-value" }, body: JSON.stringify({ ...AUTHORITY, provider_operation_id: PROVIDER_OPERATION_ID }) });
  assert.equal(noAuth.status, 401);
  assert.equal(noAuth.json().error.code, "platform_authentication_failed");
  const session = await invoke(f.server, { path: PLATFORM_PROMOTION_PATHS.issue, headers: { ...headers(), cookie: "__Host-agentpass_session=session", "agentpass-csrf": "csrf" }, body: JSON.stringify({ ...AUTHORITY, provider_operation_id: PROVIDER_OPERATION_ID }) });
  assert.equal(session.status, 401);
  assert.equal(session.json().error.code, "platform_authentication_failed");
  const arrayHeader = await invoke(f.server, { path: PLATFORM_PROMOTION_PATHS.issue, headers: { ...headers(), authorization: ["Bearer organization-token-value"] }, body: JSON.stringify({ ...AUTHORITY, provider_operation_id: PROVIDER_OPERATION_ID }) });
  assert.equal(arrayHeader.status, 401);
  assert.equal(arrayHeader.json().error.code, "platform_authentication_failed");
  assert.equal(authenticatorCalls, 0);
});

test("fails closed on missing Platform configuration, scope confusion, query substitution, and unknown fields", async (t) => {
  const unconfigured = createCloudApi({ store: {} });
  t.after(async () => { if (unconfigured.listening) await new Promise((resolve) => unconfigured.close(resolve)); });
  const missing = await invoke(unconfigured, { path: PLATFORM_PROMOTION_PATHS.issue, headers: headers(), body: JSON.stringify({ ...AUTHORITY, provider_operation_id: PROVIDER_OPERATION_ID }) });
  assert.equal(missing.status, 404);

  const f = await start(t, { authenticate: async ({ operation, context_hash }) => authorizedPlatformResult({ operation, context_hash, role: "platform_auditor" }) });
  const denied = await invoke(f.server, { path: PLATFORM_PROMOTION_PATHS.issue, headers: headers(), body: JSON.stringify({ ...AUTHORITY, provider_operation_id: PROVIDER_OPERATION_ID }) });
  assert.equal(denied.status, 403);
  assert.equal(denied.json().error.code, "platform_authorization_denied");

  const query = await invoke(f.server, { path: `${PLATFORM_PROMOTION_PATHS.issue}?operation=organization`, headers: headers(), body: JSON.stringify({ ...AUTHORITY, provider_operation_id: PROVIDER_OPERATION_ID }) });
  assert.equal(query.status, 404);
  const f2 = await start(t);
  const invalid = await invoke(f2.server, { path: PLATFORM_PROMOTION_PATHS.issue, headers: headers(), body: JSON.stringify({ ...AUTHORITY, organization_id: "33333333-3333-4333-8333-333333333333" }) });
  assert.equal(invalid.status, 400);
  assert.equal(invalid.json().error.code, "invalid_platform_request");
});

test("refuses startup when the enabled Platform route lacks a durable audit appender", () => {
  assert.throws(() => createCloudApi({ store: {}, platformPromotionEnabled: true }), /durable audit appender/u);
});

test("requires an exact idempotency header and does not expose repository errors", async (t) => {
  const f = await start(t);
  const missing = await invoke(f.server, { path: PLATFORM_PROMOTION_PATHS.issue, headers: { "content-type": "application/json", "x-agentpass-platform-auth": "edge-attestation" }, body: JSON.stringify({ ...AUTHORITY, provider_operation_id: PROVIDER_OPERATION_ID }) });
  assert.equal(missing.status, 400);
  assert.equal(missing.json().error.code, "invalid_platform_request");
  const malformed = await invoke(f.server, { path: PLATFORM_PROMOTION_PATHS.issue, headers: { ...headers(), "idempotency-key": "short" }, body: JSON.stringify({ ...AUTHORITY, provider_operation_id: PROVIDER_OPERATION_ID }) });
  assert.equal(malformed.status, 400);
  assert.equal(malformed.json().error.code, "invalid_platform_request");
});

test("maps an incompletely wired Platform factor to 503", async (t) => {
  const authenticate = createPlatformAuthenticator({
    resolvePrincipal: async () => ({ member_id: "platform-release-operator", session_id: "platform-session-1", platform_role: "platform_operator" }),
    mtls: { fingerprint256: "aa:aa:aa:aa:aa:aa:aa:aa:aa:aa:aa:aa:aa:aa:aa:aa:aa:aa:aa:aa:aa:aa:aa:aa:aa:aa:aa:aa:aa:aa:aa:aa", spiffe_id: PLATFORM_WORKLOAD_ID },
    mtlsVerifier: async () => ({ fingerprint256: "aa:aa:aa:aa:aa:aa:aa:aa:aa:aa:aa:aa:aa:aa:aa:aa:aa:aa:aa:aa:aa:aa:aa:aa:aa:aa:aa:aa:aa:aa:aa:aa", spiffe_id: PLATFORM_WORKLOAD_ID }),
    workloadId: "spiffe://agentpass.example/workload/platform-api",
    audience: "agentpass.platform.promotion",
    recentAuthVerifier: async () => ({})
  });
  const f = await start(t, { authenticate });
  const response = await invoke(f.server, { path: PLATFORM_PROMOTION_PATHS.issue, headers: headers(), body: JSON.stringify({ ...AUTHORITY, provider_operation_id: PROVIDER_OPERATION_ID }) });
  assert.equal(response.status, 503);
  assert.equal(response.json().error.code, "platform_authentication_unavailable");
});

test("revalidates the short-lived peer-bound workload envelope at the HTTP boundary", async (t) => {
  for (const mutate of [
    (value) => { const { expires_at: _expiresAt, ...workload } = value.workload; return { ...value, workload }; },
    (value) => ({ ...value, workload: { ...value.workload, mtls_fingerprint256: "bb:bb:bb:bb:bb:bb:bb:bb:bb:bb:bb:bb:bb:bb:bb:bb:bb:bb:bb:bb:bb:bb:bb:bb:bb:bb:bb:bb:bb:bb:bb:bb" } }),
    (value) => ({ ...value, workload: { ...value.workload, expires_at: Date.parse("2026-08-20T00:06:00.001Z") } })
  ]) {
    const f = await start(t, { authenticate: async ({ operation, context_hash }) => mutate(authorizedPlatformResult({ operation, context_hash })) });
    const response = await invoke(f.server, { path: PLATFORM_PROMOTION_PATHS.issue, headers: headers(), body: JSON.stringify({ ...AUTHORITY, provider_operation_id: PROVIDER_OPERATION_ID }) });
    assert.equal(response.status, 401);
    assert.equal(response.json().error.code, "platform_authentication_failed");
  }
});

test("rebinds workload audience and SPIFFE identity to deployment configuration", async (t) => {
  const f = await start(t, { expectedWorkloadAudience: "configured.audience", expectedSpiffeId: "spiffe://configured.example/workload/platform-api" });
  const result = await invoke(f.server, { path: PLATFORM_PROMOTION_PATHS.issue, headers: headers(), body: JSON.stringify({ ...AUTHORITY, provider_operation_id: PROVIDER_OPERATION_ID }) });
  assert.equal(result.status, 401);
  assert.equal(result.json().error.code, "platform_authentication_failed");
});

test("rejects an injected authorization result missing WebAuthn challenge/member/freshness bindings", async (t) => {
  const mutations = [
    (value) => ({ ...value, webauthn: { ...value.webauthn, challenge_id: "not-a-uuid" } }),
    (value) => ({ ...value, webauthn: { ...value.webauthn, member_id: "other-member" } }),
    (value) => ({ ...value, webauthn: { ...value.webauthn, authenticated_at: Date.parse("2026-08-19T23:54:59.999Z") } }),
    (value) => ({ ...value, webauthn: { ...value.webauthn, consumed: false } }),
    (value) => ({ ...value, webauthn: { ...value.webauthn, extra: "algorithm=none" } })
  ];
  for (const mutate of mutations) {
    const f = await start(t, { authenticate: async ({ operation, context_hash }) => mutate(authorizedPlatformResult({ operation, context_hash })) });
    const response = await invoke(f.server, { path: PLATFORM_PROMOTION_PATHS.issue, headers: headers(), body: JSON.stringify({ ...AUTHORITY, provider_operation_id: PROVIDER_OPERATION_ID }) });
    assert.equal(response.status, 401, response.body);
    assert.equal(response.json().error.code, "platform_authentication_failed");
  }
});

test("does not replay a recent WebAuthn proof across a different promotion authority", async (t) => {
  let boundContext;
  const f = await start(t, {
    authenticate: async ({ operation, context_hash }) => {
      boundContext ??= context_hash;
      return authorizedPlatformResult({ operation, context_hash: boundContext });
    }
  });
  const first = await invoke(f.server, { path: PLATFORM_PROMOTION_PATHS.issue, headers: headers(), body: JSON.stringify({ ...AUTHORITY, provider_operation_id: PROVIDER_OPERATION_ID }) });
  assert.equal(first.status, 201, first.body);
  const substituted = { ...AUTHORITY, approval_digest: "9".repeat(64), provider_operation_id: PROVIDER_OPERATION_ID };
  const second = await invoke(f.server, { path: PLATFORM_PROMOTION_PATHS.issue, headers: headers(), body: JSON.stringify(substituted) });
  assert.equal(second.status, 401, second.body);
  assert.equal(second.json().error.code, "platform_authentication_failed");
});

test("rejects injected workload audience and mTLS SPIFFE substitutions even when their shape is valid", async (t) => {
  for (const mutate of [
    (value) => ({ ...value, workload: { ...value.workload, audience: "other.audience" } }),
    (value) => ({ ...value, mtls: { ...value.mtls, spiffe_id: "spiffe://other.example/workload/platform-api" }, workload: { ...value.workload, workload_id: "spiffe://other.example/workload/platform-api" } })
  ]) {
    const f = await start(t, { authenticate: async ({ operation, context_hash }) => mutate(authorizedPlatformResult({ operation, context_hash })) });
    const response = await invoke(f.server, { path: PLATFORM_PROMOTION_PATHS.issue, headers: headers(), body: JSON.stringify({ ...AUTHORITY, provider_operation_id: PROVIDER_OPERATION_ID }) });
    assert.equal(response.status, 401, response.body);
    assert.equal(response.json().error.code, "platform_authentication_failed");
  }
});

test("uses one HTTP authorization clock snapshot for workload and WebAuthn freshness", async (t) => {
  const clock = [Date.parse("2026-08-20T00:00:00.000Z"), Date.parse("2026-08-20T00:06:00.000Z")];
  const seen = [];
  const f = await start(t, {
    now: () => clock.shift() ?? Date.parse("2026-08-20T00:06:00.000Z"),
    authenticate: async ({ operation, context_hash, now }) => {
      seen.push(now);
      return authorizedPlatformResult({ operation, context_hash });
    }
  });
  const response = await invoke(f.server, { path: PLATFORM_PROMOTION_PATHS.issue, headers: headers(), body: JSON.stringify({ ...AUTHORITY, provider_operation_id: PROVIDER_OPERATION_ID }) });
  assert.equal(response.status, 201, response.body);
  assert.deepEqual(seen, [Date.parse("2026-08-20T00:00:00.000Z")]);
});

test("fails closed when an HTTP Platform boundary has no deployment audience or SPIFFE pin", async () => {
  const calls = [];
  const api = createPlatformPromotionHttpApi({ repository: fakeRepository(calls), authenticate: async ({ context_hash }) => authorizedPlatformResult({ context_hash }), auditAppender: async () => {} });
  await assert.rejects(() => api.handle({
    method: "POST",
    url: PLATFORM_PROMOTION_PATHS.issue,
    request: { socket: {} },
    headers: headers(),
    body: Buffer.from(JSON.stringify({ ...AUTHORITY, provider_operation_id: PROVIDER_OPERATION_ID }))
  }), (error) => error.code === "platform_authentication_unavailable" && error.status === 503);
  assert.equal(calls.length, 0);
});
