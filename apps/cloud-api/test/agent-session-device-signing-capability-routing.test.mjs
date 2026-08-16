import assert from "node:assert/strict";
import test from "node:test";

import {
  AGENT_SESSION_DEVICE_HTTP_ERROR_CODES,
  AGENT_SESSION_DEVICE_HTTP_PATHS,
  createAgentSessionDeviceApi
} from "../src/agent-session-device-api.mjs";

const NOW = Date.parse("2026-08-16T03:00:00.000Z");
const IDS = Object.freeze({
  organization: "11111111-1111-4111-8111-111111111111",
  device: "22222222-2222-4222-8222-222222222222",
  session: "33333333-3333-4333-8333-333333333333",
  request: "44444444-4444-4444-8444-444444444444",
  correlation: "55555555-5555-4555-8555-555555555555"
});
const PATH = `/v1/organizations/${IDS.organization}/devices/${IDS.device}/agent-sessions/${IDS.session}/signing-capabilities`;
const RAW_BODY = Buffer.from("{this is intentionally not parsed by the shared boundary", "utf8");

function createFixture({ signingCapabilityApi = undefined } = {}) {
  const calls = { authenticate: [], delegate: [], grant: [], repository: [] };
  const api = createAgentSessionDeviceApi({
    now: () => NOW,
    requestIdFactory: () => IDS.correlation,
    deviceRequestVerifier: async (request, options) => {
      calls.authenticate.push({ ...request, body: Buffer.from(request.body), options });
      return { organization_id: IDS.organization, device_id: IDS.device };
    },
    grantVerifier: async () => {
      calls.grant.push(true);
      return true;
    },
    repository: {
      async consumeAgentSessionGrant(input) {
        calls.repository.push(input);
        throw new Error("grant route must not run in this test");
      }
    },
    ...(signingCapabilityApi === undefined ? {} : { signingCapabilityApi })
  });
  return { api, calls };
}

function request(path = PATH, body = RAW_BODY, method = "POST") {
  return {
    method,
    url: path,
    headers: { "agentpass-nonce": "device-routing-nonce", "content-type": "application/json" },
    body
  };
}

test("authenticates once before parsing and delegates the exact raw signing-capability request", async () => {
  const f = createFixture({
    signingCapabilityApi: {
      async handleAuthenticated(input, context) {
        f.calls.delegate.push({ input, context });
        assert.deepEqual(input.body, RAW_BODY);
        assert.equal(input.url, PATH);
        assert.equal(input.path, PATH);
        assert.equal(input.originalUrl, PATH);
        assert.equal(context.organization_id, IDS.organization);
        assert.equal(context.device_id, IDS.device);
        assert.equal(context.session_id, IDS.session);
        assert.equal(context.now, NOW);
        assert.deepEqual(context.authenticated_device, {
          organization_id: IDS.organization,
          device_id: IDS.device
        });
        return { status: 201, headers: { "X-AgentPass-Boundary": "signing-capability" }, body: { issued: true } };
      }
    }
  });

  const result = await f.api.handle(request());

  assert.equal(result.status, 201);
  assert.deepEqual(result.body, { issued: true });
  assert.deepEqual(f.api.paths, {
    consume: "/v1/organizations/{organization_id}/devices/{device_id}/agent-session-grants/{grant_id}/consume",
    issueSigningCapability: "/v1/organizations/{organization_id}/devices/{device_id}/agent-sessions/{session_id}/signing-capabilities"
  });
  assert.equal(f.calls.authenticate.length, 1);
  assert.equal(f.calls.delegate.length, 1);
  assert.equal(f.calls.grant.length, 0);
  assert.equal(f.calls.repository.length, 0);
  assert.equal(f.calls.authenticate[0].options.organization_id, IDS.organization);
  assert.equal(f.calls.authenticate[0].options.device_id, IDS.device);
  assert.equal(f.calls.authenticate[0].options.session_id, IDS.session);
  assert.deepEqual(f.calls.authenticate[0].body, RAW_BODY);
});

test("never delegates exact-route aliases or method variants", async () => {
  const f = createFixture({ signingCapabilityApi: async () => { throw new Error("must not delegate"); } });
  for (const [method, path, expectedStatus] of [
    ["GET", PATH, 400],
    ["POST", `${PATH}/`, 404],
    ["POST", `${PATH}?unexpected=1`, 400],
    ["POST", PATH.replace("agent-sessions", "agent-session"), 404],
    ["POST", PATH.replace(IDS.session, "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA"), 404]
  ]) {
    const result = await f.api.handle(request(path, RAW_BODY, method));
    assert.equal(result.status, expectedStatus, `${method} ${path}`);
    assert.equal(result.body.error.code, expectedStatus === 400 ? AGENT_SESSION_DEVICE_HTTP_ERROR_CODES.INVALID_REQUEST : AGENT_SESSION_DEVICE_HTTP_ERROR_CODES.NOT_FOUND);
  }
  assert.equal(f.calls.authenticate.length, 0);
  assert.equal(f.calls.delegate.length, 0);
});

test("fails closed when the signing-capability composition is absent after shared Device auth", async () => {
  const f = createFixture();
  const result = await f.api.handle(request());
  assert.equal(result.status, 503);
  assert.equal(result.body.error.code, AGENT_SESSION_DEVICE_HTTP_ERROR_CODES.UNAVAILABLE);
  assert.equal(f.calls.authenticate.length, 1);
  assert.equal(f.calls.delegate.length, 0);
  assert.equal(f.calls.grant.length, 0);
});
