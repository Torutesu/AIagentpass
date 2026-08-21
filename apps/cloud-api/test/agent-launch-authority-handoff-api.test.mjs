import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import { canonicalJson } from "../../../packages/protocol/src/index.mjs";
import { agentSessionGrantSigningData, agentSessionGrantStatementHash } from "../src/agent-session-grant.mjs";
import { createReplayCache, signDeviceRequest, verifyDeviceRequest } from "../src/auth.mjs";
import {
  AGENT_LAUNCH_AUTHORITY_HANDOFF_HTTP_ERROR_CODES,
  AGENT_LAUNCH_AUTHORITY_HANDOFF_HTTP_PATHS,
  createAgentLaunchAuthorityHandoffApi
} from "../src/agent-launch-authority-handoff-api.mjs";

const NOW = Date.parse("2026-08-19T03:00:00.000Z");
const IDS = Object.freeze({
  organization: "11111111-1111-4111-8111-111111111111",
  device: "22222222-2222-4222-8222-222222222222",
  session: "33333333-3333-4333-8333-333333333333",
  agent: "44444444-4444-4444-8444-444444444444",
  adapter: "55555555-5555-4555-8555-555555555555",
  request: "66666666-6666-4666-8666-666666666666",
  correlation: "77777777-7777-4777-8777-777777777777"
});
const BODY_NONCE = Buffer.alloc(32, 0x42).toString("base64url");
const PROCESS = "a".repeat(64);
const ANCESTRY = "b".repeat(64);
const WORKTREE = "c".repeat(64);
const PATH = `/v1/organizations/${IDS.organization}/devices/${IDS.device}/agent-sessions/${IDS.session}/launch-authority-handoff`;
const GRANT_KEYS = crypto.generateKeyPairSync("ed25519");

function lease(overrides = {}) {
  return {
    version: 1,
    type: "agentpass.agent-session-lease",
    session_id: IDS.session,
    grant_id: "88888888-8888-4888-8888-888888888888",
    organization_id: IDS.organization,
    device_id: IDS.device,
    agent_id: IDS.agent,
    agent_kind: "claude-code",
    adapter_id: IDS.adapter,
    adapter_version: "1.2.3",
    process_binding_sha256: PROCESS,
    ancestry_binding_sha256: ANCESTRY,
    worktree_binding_sha256: WORKTREE,
    max_signatures: 2,
    used_signatures: 0,
    not_before: new Date(NOW - 1_000).toISOString(),
    expires_at: new Date(NOW + 60_000).toISOString(),
    control_sequence: 12,
    authority_generation: 7,
    ...overrides
  };
}

function requestBody(overrides = {}) {
  return Buffer.from(canonicalJson({
    version: 1,
    type: "agentpass.agent-launch-authority-handoff-request",
    request_id: IDS.request,
    adapter_id: IDS.adapter,
    adapter_version: "1.2.3",
    nonce: BODY_NONCE,
    ...overrides
  }), "utf8");
}

function grant(leaseValue = lease()) {
  const statement = {
    version: 1,
    grant_id: leaseValue.grant_id,
    organization_id: leaseValue.organization_id,
    device_id: leaseValue.device_id,
    agent_id: leaseValue.agent_id,
    agent_kind: leaseValue.agent_kind,
    adapter_id: leaseValue.adapter_id,
    adapter_version: leaseValue.adapter_version,
    worktree_binding_sha256: leaseValue.worktree_binding_sha256,
    process_binding_policy_id: "claude-code-default",
    scope: { operations: ["git.commit.sign"], repositories: ["/work/project"], branches: { allow: ["feature/*"], deny: [] }, remotes: { allow: ["origin"], deny: [] } },
    max_signatures: leaseValue.max_signatures,
    not_before: leaseValue.not_before,
    expires_at: leaseValue.expires_at,
    control_sequence: leaseValue.control_sequence,
    authority_generation: leaseValue.authority_generation,
    issuer: "agentpass-cloud",
    key_id: "agent-session-2026-08"
  };
  return {
    version: 1,
    type: "agentpass.agent-session-grant",
    statement,
    statement_hash: agentSessionGrantStatementHash(statement),
    signature: crypto.sign(null, agentSessionGrantSigningData(statement), GRANT_KEYS.privateKey).toString("base64url")
  };
}

function fixture({ binder = async () => ({ authorized: true, lease: lease(), grant: grant() }), repository = undefined, verifier = undefined, grantVerifier = undefined } = {}) {
  const deviceKeys = crypto.generateKeyPairSync("ed25519");
  const replayCache = createReplayCache();
  const calls = { auth: [], bind: [], repository: [] };
  const handoffRepository = repository ?? {
    async issueAgentLaunchAuthorityHandoff(input) {
      calls.repository.push(input);
      const error = new Error("native authority proof is unavailable");
      error.code = "ERR_NATIVE_AGENT_AUTHORITY_PROOF_UNAVAILABLE";
      throw error;
    }
  };
  const api = createAgentLaunchAuthorityHandoffApi({
    now: () => NOW,
    requestIdFactory: () => IDS.correlation,
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
    grantVerifier: grantVerifier ?? (async (value) => ({ grant: value })),
    sessionBinder: async (input) => {
      calls.bind.push(structuredClone(input));
      return binder(input);
    },
    repository: handoffRepository
  });
  return { api, calls, deviceKeys };
}

function requestFor(fixtureValue, { body = requestBody(), path = PATH, method = "POST", headers = {}, ...extra } = {}) {
  const authHeaders = signDeviceRequest({
    method,
    path,
    body,
    device_id: IDS.device,
    timestamp: NOW,
    nonce: `launch-handoff-device-nonce-${crypto.randomBytes(8).toString("hex")}`
  }, fixtureValue.deviceKeys.privateKey);
  return { method, url: path, headers: { ...authHeaders, "content-type": "application/json", ...headers }, body, ...extra };
}

function assertError(result, status, code) {
  assert.equal(result.status, status);
  assert.equal(result.body.error.code, code);
  assert.equal(result.body.request_id, IDS.correlation);
  assert.doesNotMatch(JSON.stringify(result.body), /token|bearer|secret|private|password/iu);
}

test("exports one exact handoff route and closed request contract", () => {
  assert.deepEqual(AGENT_LAUNCH_AUTHORITY_HANDOFF_HTTP_PATHS, { prepare: "/v1/organizations/{organization_id}/devices/{device_id}/agent-sessions/{session_id}/launch-authority-handoff" });
  assert.equal(Object.isFrozen(AGENT_LAUNCH_AUTHORITY_HANDOFF_HTTP_PATHS), true);
});

test("authenticates the raw request, binds the complete Lease, and fails closed without native proof", async () => {
  const f = fixture();
  const result = await f.api.handle(requestFor(f));
  assertError(result, 503, AGENT_LAUNCH_AUTHORITY_HANDOFF_HTTP_ERROR_CODES.NATIVE_PROOF_UNAVAILABLE);
  assert.equal(f.calls.auth.length, 1);
  assert.equal(f.calls.bind.length, 1);
  assert.deepEqual(f.calls.bind[0], {
    organization_id: IDS.organization,
    device_id: IDS.device,
    session_id: IDS.session,
    authenticated_device: { organization_id: IDS.organization, device_id: IDS.device },
    now: NOW
  });
  assert.equal(f.calls.repository.length, 1);
  assert.deepEqual(Object.keys(f.calls.repository[0]).sort(), [
    "adapter_id", "adapter_version", "agent_id", "agent_kind", "authority_generation", "control_sequence", "device_id", "expires_at", "grant_id",
    "grant", "grant_hash", "lease_sha256", "nonce_sha256", "not_before", "organization_id", "request_id", "session_id", "type", "version", "worktree_binding_sha256"
  ].sort());
  assert.equal(f.calls.repository[0].organization_id, IDS.organization);
  assert.equal(f.calls.repository[0].device_id, IDS.device);
  assert.equal(f.calls.repository[0].agent_id, IDS.agent);
  assert.equal(f.calls.repository[0].adapter_id, IDS.adapter);
  assert.equal(f.calls.repository[0].session_id, IDS.session);
  assert.equal(f.calls.repository[0].expires_at, lease().expires_at);
  assert.equal(f.calls.repository[0].worktree_binding_sha256, WORKTREE);
  assert.equal(f.calls.repository[0].authority_generation, 7);
  assert.equal(f.calls.repository[0].grant.statement.grant_id, lease().grant_id);
  assert.equal(f.calls.repository[0].nonce_sha256, crypto.createHash("sha256").update(Buffer.from(BODY_NONCE, "base64url")).digest("hex"));
  assert.equal(Object.hasOwn(f.calls.repository[0], "nonce"), false);
  assert.equal(Object.hasOwn(result.body, "handoff"), false);
});

test("rejects the existing partial signing-capability binder projection before repository mutation", async () => {
  const f = fixture({ binder: async () => ({
    authorized: true,
    organization_id: IDS.organization,
    device_id: IDS.device,
    session_id: IDS.session,
    grant_id: "88888888-8888-4888-8888-888888888888",
    agent_id: IDS.agent
  }) });
  const result = await f.api.handle(requestFor(f));
  assertError(result, 503, AGENT_LAUNCH_AUTHORITY_HANDOFF_HTTP_ERROR_CODES.UNAVAILABLE);
  assert.equal(f.calls.repository.length, 0);
});

test("rejects unknown, duplicate, noncanonical, authority-bearing, bearer, and query inputs", async () => {
  const cases = [
    { body: Buffer.from(`{"version":1,"type":"agentpass.agent-launch-authority-handoff-request","request_id":"${IDS.request}","adapter_id":"${IDS.adapter}","adapter_version":"1.2.3","nonce":"${BODY_NONCE}","session_id":"${IDS.session}"}`) },
    { body: Buffer.from(`{"version":1,"type":"agentpass.agent-launch-authority-handoff-request","request_id":"${IDS.request}","request_id":"${IDS.request}","adapter_id":"${IDS.adapter}","adapter_version":"1.2.3","nonce":"${BODY_NONCE}"}`) },
    { body: Buffer.from(` {"request_id":"${IDS.request}","adapter_id":"${IDS.adapter}","adapter_version":"1.2.3","nonce":"${BODY_NONCE}"} `) },
    { body: requestBody({ token: "must-not-be-a-bearer" }) },
    { headers: { Authorization: "Bearer attacker-controlled" } },
    { path: `${PATH}?unexpected=1` }
  ];
  for (const [index, value] of cases.entries()) {
    const f = fixture();
    const result = await f.api.handle(requestFor(f, value));
    assert.equal(result.status, 400, `case ${index}`);
    assertError(result, 400, AGENT_LAUNCH_AUTHORITY_HANDOFF_HTTP_ERROR_CODES.INVALID_REQUEST);
    assert.equal(f.calls.repository.length, 0);
  }
});

test("does not return a repository-supplied token-shaped result", async () => {
  const f = fixture({ repository: { async issueAgentLaunchAuthorityHandoff() { return { token: "not-a-native-proof" }; } } });
  const result = await f.api.handle(requestFor(f));
  assertError(result, 503, AGENT_LAUNCH_AUTHORITY_HANDOFF_HTTP_ERROR_CODES.UNAVAILABLE);
  assert.equal(Object.hasOwn(result.body, "token"), false);
});

test("returns the exact already-issued Grant once through a no-store response", async () => {
  const f = fixture({ repository: {
    async issueAgentLaunchAuthorityHandoff(input) {
      assert.equal(Object.hasOwn(input, "nonce"), false);
      return { state: "issued", grant: input.grant };
    }
  } });
  const result = await f.api.handle(requestFor(f));
  assert.equal(result.status, 200);
  assert.deepEqual(result.body.grant, f.calls.bind.length === 1 ? grant() : undefined);
  assert.match(result.headers["Cache-Control"], /no-store/u);
  assert.equal(Object.hasOwn(result.body, "token"), false);
});

test("does not return the Grant again after an atomic replay decision", async () => {
  const f = fixture({ repository: { async issueAgentLaunchAuthorityHandoff() { return { state: "already_returned" }; } } });
  const result = await f.api.handle(requestFor(f));
  assertError(result, 409, AGENT_LAUNCH_AUTHORITY_HANDOFF_HTTP_ERROR_CODES.REPLAYED);
  assert.equal(Object.hasOwn(result.body, "grant"), false);
});

test("rejects expired and exhausted Lease authority before handoff persistence", async () => {
  for (const changed of [
    { expires_at: new Date(NOW - 1).toISOString() },
    { used_signatures: 2 }
  ]) {
    const f = fixture({ binder: async () => ({ authorized: true, lease: lease(changed) }) });
    const result = await f.api.handle(requestFor(f));
    assertError(result, 503, AGENT_LAUNCH_AUTHORITY_HANDOFF_HTTP_ERROR_CODES.UNAVAILABLE);
    assert.equal(f.calls.repository.length, 0);
  }
});

test("requires the cryptographic verifier to attest the exact bound Grant envelope", async () => {
  for (const verifier of [async () => true, async (value) => ({ grant: { ...value, signature: "A".repeat(86) } })]) {
    const f = fixture({ grantVerifier: verifier });
    const result = await f.api.handle(requestFor(f));
    assertError(result, 403, AGENT_LAUNCH_AUTHORITY_HANDOFF_HTTP_ERROR_CODES.SESSION_NOT_AUTHORIZED);
    assert.equal(f.calls.repository.length, 0);
  }
});
