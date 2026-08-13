import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import {
  createReplayCache,
  signDeviceRequest,
  verifyDeviceRequest
} from "../src/auth.mjs";
import {
  createLocalAgentSessionGrantSigner,
  verifyAgentSessionGrant
} from "../src/agent-session-grant.mjs";
import {
  AGENT_SESSION_DEVICE_HTTP_ERROR_CODES,
  createAgentSessionDeviceApi
} from "../src/agent-session-device-api.mjs";

const NOW = Date.parse("2026-08-13T10:00:00.000Z");
const IDS = Object.freeze({
  organization: "11111111-1111-4111-8111-111111111111",
  device: "22222222-2222-4222-8222-222222222222",
  otherDevice: "33333333-3333-4333-8333-333333333333",
  agent: "44444444-4444-4444-8444-444444444444",
  adapter: "55555555-5555-4555-8555-555555555555",
  grant: "66666666-6666-4666-8666-666666666666",
  session: "77777777-7777-4777-8777-777777777777",
  request: "88888888-8888-4888-8888-888888888888"
});
const PROCESS_BINDING = "a".repeat(64);
const ANCESTRY_BINDING = "b".repeat(64);
const OTHER_PROCESS_BINDING = "c".repeat(64);
const PATH = `/v1/organizations/${IDS.organization}/devices/${IDS.device}/agent-session-grants/${IDS.grant}/consume`;

function statement() {
  return {
    version: 1,
    grant_id: IDS.grant,
    organization_id: IDS.organization,
    device_id: IDS.device,
    agent_id: IDS.agent,
    agent_kind: "claude-code",
    adapter_id: IDS.adapter,
    adapter_version: "1.2.3",
    worktree_binding_sha256: "d".repeat(64),
    process_binding_policy_id: "claude-code-v1",
    scope: {
      operations: ["git.commit.sign"],
      repositories: ["/work/project"],
      branches: { allow: ["feature/*"], deny: ["main"] },
      remotes: { allow: ["git@example.test:project.git"], deny: [] }
    },
    max_signatures: 2,
    not_before: new Date(NOW - 1_000).toISOString(),
    expires_at: new Date(NOW + 60_000).toISOString(),
    control_sequence: 12,
    issuer: "agentpass-cloud",
    key_id: "session-grant-2026-08"
  };
}

async function fixture({ repository = undefined, grantVerifier = undefined } = {}) {
  const deviceKeys = crypto.generateKeyPairSync("ed25519");
  const grantKeys = crypto.generateKeyPairSync("ed25519");
  const grantSigner = createLocalAgentSessionGrantSigner({
    privateKey: grantKeys.privateKey,
    keyId: statement().key_id,
    now: () => NOW
  });
  const grant = await grantSigner.signAgentSessionGrant(statement());
  const device = {
    device_id: IDS.device,
    organization_id: IDS.organization,
    status: "active",
    device_public_key: deviceKeys.publicKey.export({ type: "spki", format: "pem" }).toString()
  };
  const replayCache = createReplayCache();
  const calls = { authenticate: [], grantVerify: [], repository: [] };
  const defaultRepository = async (input) => {
    calls.repository.push(input);
    return { lease: lease(grant) };
  };
  const api = createAgentSessionDeviceApi({
    now: () => NOW,
    requestIdFactory: () => IDS.request,
    deviceRequestVerifier: async (request, options) => {
      calls.authenticate.push({ ...request, body: Buffer.from(request.body), options });
      return verifyDeviceRequest(request, [device], { ...options, replayCache });
    },
    grantVerifier: async (value, options) => {
      calls.grantVerify.push({ value, options });
      if (grantVerifier) return grantVerifier(value, options);
      return verifyAgentSessionGrant(value, { publicKey: grantKeys.publicKey, keyId: statement().key_id, now: NOW });
    },
    repository: { consumeAgentSessionGrant: repository ?? defaultRepository }
  });
  return { api, grant, grantKeys, deviceKeys, calls };
}

function lease(grant, overrides = {}) {
  return {
    version: 1,
    type: "agentpass.agent-session-lease",
    session_id: IDS.session,
    grant_id: grant.statement.grant_id,
    organization_id: grant.statement.organization_id,
    device_id: grant.statement.device_id,
    agent_id: grant.statement.agent_id,
    agent_kind: grant.statement.agent_kind,
    adapter_id: grant.statement.adapter_id,
    adapter_version: grant.statement.adapter_version,
    process_binding_sha256: PROCESS_BINDING,
    ancestry_binding_sha256: ANCESTRY_BINDING,
    worktree_binding_sha256: grant.statement.worktree_binding_sha256,
    max_signatures: grant.statement.max_signatures,
    used_signatures: 0,
    not_before: grant.statement.not_before,
    expires_at: grant.statement.expires_at,
    control_sequence: grant.statement.control_sequence,
    ...overrides
  };
}

function bodyFor(grant, overrides = {}) {
  return Buffer.from(JSON.stringify({
    grant,
    process_binding_sha256: PROCESS_BINDING,
    ancestry_binding_sha256: ANCESTRY_BINDING,
    ...overrides
  }));
}

function requestFor(fixtureValue, { path = PATH, body = bodyFor(fixtureValue.grant), nonce = `device-session-nonce-${crypto.randomBytes(12).toString("hex")}` } = {}) {
  nonce = nonce.length >= 32 ? nonce : `${nonce}-${"x".repeat(32 - nonce.length - 1)}`;
  return {
    method: "POST",
    url: path,
    headers: signDeviceRequest({ method: "POST", path, body, device_id: IDS.device, timestamp: NOW, nonce }, fixtureValue.deviceKeys.privateKey),
    body
  };
}

function assertError(result, status, code) {
  assert.equal(result.status, status);
  assert.equal(result.body.error.code, code);
  assert.equal(result.body.error.message.includes("private"), false);
  assert.equal(result.body.error.message.includes("secret"), false);
  assert.equal(result.body.request_id, IDS.request);
}

test("consumes a grant after authenticating exact raw path/body and returns only a normalized lease", async () => {
  const f = await fixture();
  const body = bodyFor(f.grant);
  const result = await f.api.handle(requestFor(f, { body, nonce: "device-session-nonce-success-000000000001" }));

  assert.equal(result.status, 201);
  assert.equal(result.headers["Cache-Control"], "no-store, max-age=0");
  assert.deepEqual(Object.keys(result.body).sort(), ["lease", "request_id"]);
  assert.deepEqual(result.body.lease, lease(f.grant));
  assert.equal(f.calls.authenticate.length, 1);
  assert.deepEqual(f.calls.authenticate[0].body, body);
  assert.equal(f.calls.authenticate[0].path, PATH);
  assert.equal(f.calls.grantVerify.length, 1);
  assert.equal(f.calls.repository.length, 1);
  assert.equal("body" in f.calls.repository[0], false);
  assert.equal("headers" in f.calls.repository[0], false);
  assert.equal("audit_token" in f.calls.repository[0], false);
  assert.equal("raw_process" in f.calls.repository[0], false);
  assert.equal(f.calls.repository[0].process_binding_sha256, PROCESS_BINDING);
  assert.equal(f.calls.repository[0].ancestry_binding_sha256, ANCESTRY_BINDING);
  assert.equal(typeof f.calls.repository[0].retry_identity_sha256, "string");
});

test("rejects path, tenant, and device substitutions without consuming the repository", async () => {
  const f = await fixture();
  const substitutedGrantPath = PATH.replace(IDS.grant, "99999999-9999-4999-8999-999999999999");
  const grantPathResult = await f.api.handle(requestFor(f, { path: substitutedGrantPath, nonce: "device-session-nonce-substitution-000001" }));
  assertError(grantPathResult, 400, AGENT_SESSION_DEVICE_HTTP_ERROR_CODES.INVALID_REQUEST);
  assert.equal(f.calls.grantVerify.length, 0);
  assert.equal(f.calls.repository.length, 0);

  const substitutedDevicePath = PATH.replace(IDS.device, IDS.otherDevice);
  const devicePathResult = await f.api.handle(requestFor(f, { path: substitutedDevicePath, nonce: "device-session-nonce-substitution-000002" }));
  assertError(devicePathResult, 403, AGENT_SESSION_DEVICE_HTTP_ERROR_CODES.AUDIENCE_MISMATCH);
  assert.equal(f.calls.repository.length, 0);

  const substitutedOrganizationPath = PATH.replace(IDS.organization, "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa");
  const organizationPathResult = await f.api.handle(requestFor(f, { path: substitutedOrganizationPath, nonce: "device-session-nonce-substitution-000003" }));
  assertError(organizationPathResult, 401, AGENT_SESSION_DEVICE_HTTP_ERROR_CODES.DEVICE_AUTH_FAILED);
  assert.equal(f.calls.repository.length, 0);
});

test("rejects duplicate and unknown JSON keys after device authentication", async () => {
  const f = await fixture();
  const duplicate = Buffer.from(`{"grant":${JSON.stringify(f.grant)},"process_binding_sha256":"${PROCESS_BINDING}","process_binding_sha256":"${OTHER_PROCESS_BINDING}","ancestry_binding_sha256":"${ANCESTRY_BINDING}"}`);
  const duplicateResult = await f.api.handle(requestFor(f, { body: duplicate, nonce: "device-session-nonce-json-000001" }));
  assertError(duplicateResult, 400, AGENT_SESSION_DEVICE_HTTP_ERROR_CODES.INVALID_REQUEST);
  assert.equal(f.calls.grantVerify.length, 0);

  const unknown = bodyFor(f.grant, { unexpected: true });
  const unknownResult = await f.api.handle(requestFor(f, { body: unknown, nonce: "device-session-nonce-json-000002" }));
  assertError(unknownResult, 400, AGENT_SESSION_DEVICE_HTTP_ERROR_CODES.INVALID_REQUEST);
  assert.equal(f.calls.grantVerify.length, 0);

  const nestedUnknownGrant = Buffer.from(JSON.stringify({
    grant: { ...f.grant, unexpected: true },
    process_binding_sha256: PROCESS_BINDING,
    ancestry_binding_sha256: ANCESTRY_BINDING
  }));
  const nestedResult = await f.api.handle(requestFor(f, { body: nestedUnknownGrant, nonce: "device-session-nonce-json-000003" }));
  assertError(nestedResult, 400, AGENT_SESSION_DEVICE_HTTP_ERROR_CODES.INVALID_REQUEST);
  assert.equal(f.calls.grantVerify.length, 0);
});

test("rejects malformed binding hashes and grant hash substitution before verification", async () => {
  const f = await fixture();
  const malformed = bodyFor(f.grant, { process_binding_sha256: "A".repeat(64) });
  const malformedResult = await f.api.handle(requestFor(f, { body: malformed, nonce: "device-session-nonce-hash-000001" }));
  assertError(malformedResult, 400, AGENT_SESSION_DEVICE_HTTP_ERROR_CODES.INVALID_REQUEST);
  assert.equal(f.calls.grantVerify.length, 0);

  const forgedGrant = { ...f.grant, statement_hash: "e".repeat(64) };
  const forgedResult = await f.api.handle(requestFor(f, { body: bodyFor(forgedGrant), nonce: "device-session-nonce-hash-000002" }));
  assertError(forgedResult, 400, AGENT_SESSION_DEVICE_HTTP_ERROR_CODES.INVALID_REQUEST);
  assert.equal(f.calls.repository.length, 0);
});

test("maps verifier denial, repository replay/conflict, not-found, rate-limit, and outage errors stably", async () => {
  const denied = await fixture({ grantVerifier: async () => false });
  assertError(await denied.api.handle(requestFor(denied, { nonce: "device-session-nonce-map-000001" })), 403, AGENT_SESSION_DEVICE_HTTP_ERROR_CODES.GRANT_NOT_AUTHORIZED);
  assert.equal(denied.calls.repository.length, 0);

  for (const [error, status, code] of [
    [{ code: "ERR_GRANT_CONSUMED", message: "do not expose" }, 409, AGENT_SESSION_DEVICE_HTTP_ERROR_CODES.GRANT_CONFLICT],
    [{ code: "ERR_GRANT_NOT_FOUND", message: "tenant SQL" }, 404, AGENT_SESSION_DEVICE_HTTP_ERROR_CODES.NOT_FOUND],
    [{ code: "ERR_RATE_LIMITED", retryAfterSeconds: 7, message: "secret" }, 429, AGENT_SESSION_DEVICE_HTTP_ERROR_CODES.RATE_LIMITED],
    [{ code: "ERR_DATABASE", message: "password=do-not-leak" }, 503, AGENT_SESSION_DEVICE_HTTP_ERROR_CODES.UNAVAILABLE]
  ]) {
    const f = await fixture({ repository: async () => { throw error; } });
    const result = await f.api.handle(requestFor(f, { nonce: `device-session-nonce-map-${status}-000001` }));
    assertError(result, status, code);
    if (status === 429) assert.equal(result.headers["Retry-After"], "7");
    assert.equal(JSON.stringify(result.body).includes(error.message), false);
  }
});

test("delegates exact retry identity to the repository and maps device-auth replay to 401", async () => {
  let repositoryCalls = 0;
  const repositoryInputs = [];
  const f = await fixture({ repository: async (input) => {
    repositoryCalls += 1;
    repositoryInputs.push(input);
    return { lease: lease(f.grant) };
  } });
  const first = requestFor(f, { nonce: "device-session-nonce-retry-000001" });
  const second = requestFor(f, { nonce: "device-session-nonce-retry-000002" });
  const firstResult = await f.api.handle(first);
  const secondResult = await f.api.handle(second);
  assert.equal(firstResult.status, 201);
  assert.equal(secondResult.status, 201);
  assert.equal(repositoryCalls, 2);
  assert.equal(repositoryInputs[0].retry_identity_sha256, repositoryInputs[1].retry_identity_sha256);

  const replayFixture = await fixture();
  const replayRequest = requestFor(replayFixture, { nonce: "device-session-nonce-replay-000001" });
  assert.equal((await replayFixture.api.handle(replayRequest)).status, 201);
  const replayResult = await replayFixture.api.handle(replayRequest);
  assertError(replayResult, 401, AGENT_SESSION_DEVICE_HTTP_ERROR_CODES.DEVICE_AUTH_FAILED);
  assert.equal(replayFixture.calls.repository.length, 1);
});

test("normalizes repository output and never returns leaked fields or an invalid lease", async () => {
  const f = await fixture({ repository: async () => ({
    lease: { ...lease(f.grant), leaked_secret: "should not cross boundary" },
    raw_audit_event: { process_path: "/private/path" }
  }) });
  const result = await f.api.handle(requestFor(f, { nonce: "device-session-nonce-normalize-000001" }));
  assertError(result, 503, AGENT_SESSION_DEVICE_HTTP_ERROR_CODES.UNAVAILABLE);
  assert.equal(JSON.stringify(result.body).includes("should not cross boundary"), false);

  const normalized = await fixture({ repository: async () => ({ lease: lease(normalized.grant), leaked_secret: "ignored" }) });
  const normalizedResult = await normalized.api.handle(requestFor(normalized, { nonce: "device-session-nonce-normalize-000002" }));
  assert.equal(normalizedResult.status, 201);
  assert.equal("leaked_secret" in normalizedResult.body, false);
  assert.equal("leaked_secret" in normalizedResult.body.lease, false);
});
