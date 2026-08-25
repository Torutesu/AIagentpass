import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import {
  AGENT_SIGNING_CAPABILITY_OPERATION,
  createLocalAgentSigningCapabilitySigner
} from "../src/agent-signing-capability.mjs";
import { createAgentSessionSigningCapabilityRuntimeComposition } from "../src/runtime.mjs";
import { canonicalJson } from "../../../packages/protocol/src/index.mjs";

const NOW = Date.parse("2026-08-16T03:00:00.000Z");
const IDS = Object.freeze({
  organization: "11111111-1111-4111-8111-111111111111",
  device: "22222222-2222-4222-8222-222222222222",
  session: "33333333-3333-4333-8333-333333333333",
  grant: "44444444-4444-4444-8444-444444444444",
  agent: "55555555-5555-4555-8555-555555555555",
  capability: "66666666-6666-4666-8666-666666666666",
  request: "77777777-7777-4777-8777-777777777777"
});
const PATH = `/v1/organizations/${IDS.organization}/devices/${IDS.device}/agent-sessions/${IDS.session}/signing-capabilities`;
const SCOPE = Object.freeze({
  operations: [AGENT_SIGNING_CAPABILITY_OPERATION],
  repositories: ["/work/project"],
  branches: { allow: ["feature/*"], deny: ["main"] },
  remotes: { allow: ["origin"], deny: [] }
});

function baseDependencies(overrides = {}) {
  const keys = crypto.generateKeyPairSync("ed25519");
  const localSigner = createLocalAgentSigningCapabilitySigner({
    privateKey: keys.privateKey,
    keyId: "git-commit-sign-2026-08",
    now: () => NOW
  });
  const signer = Object.freeze({
    ...localSigner,
    key_id: "git-commit-sign-2026-08",
    purpose: AGENT_SIGNING_CAPABILITY_OPERATION
  });
  const repository = {
    async consumeAgentSessionGrant() { return undefined; }
  };
  const binding = {
    authorized: true,
    organization_id: IDS.organization,
    device_id: IDS.device,
    session_id: IDS.session,
    grant_id: IDS.grant,
    agent_id: IDS.agent
  };
  return {
    deviceRequestVerifier: async () => ({ organization_id: IDS.organization, device_id: IDS.device }),
    sessionBinder: async () => binding,
    reservationRepositoryFactory: () => createReservationRepository(),
    signer,
    grantVerifier: async () => true,
    repository,
    now: () => NOW,
    ...overrides
  };
}

function createReservationRepository() {
  const times = {
    issued_at: new Date(NOW).toISOString(),
    not_before: new Date(NOW).toISOString(),
    expires_at: new Date(NOW + 300_000).toISOString()
  };
  const reservation = {
    state: "reserved",
    claim_token: "A".repeat(43),
    capability_id: IDS.capability,
    organization_id: IDS.organization,
    session_id: IDS.session,
    device_id: IDS.device,
    agent_id: IDS.agent,
    scope: SCOPE,
    sequence: 1,
    control_sequence: 12,
    authority_generation: 7,
    remaining_session_signatures: 1,
    ...times
  };
  let committed;
  return {
    async reserveCapability() { return reservation; },
    async commitCapability(input) {
      committed = input.capability;
      return { state: "committed", capability: input.capability, remaining_session_signatures: 1 };
    },
    async replayCapability() {
      return committed
        ? { state: "committed", capability: committed, remaining_session_signatures: 1 }
        : { state: "absent" };
    },
    async markCapabilityUncertain() { return { state: "uncertain" }; }
  };
}

function request() {
  return {
    method: "POST",
    url: PATH,
    headers: { "content-type": "application/json" },
    body: Buffer.from(canonicalJson({ request_id: IDS.request }), "utf8")
  };
}

test("runtime composition rejects every missing production dependency and rejects generic signers", () => {
  const complete = baseDependencies();
  for (const dependency of [
    "deviceRequestVerifier",
    "sessionBinder",
    "reservationRepositoryFactory",
    "signer",
    "grantVerifier",
    "repository"
  ]) {
    const missing = { ...complete, [dependency]: undefined };
    assert.throws(
      () => createAgentSessionSigningCapabilityRuntimeComposition(missing),
      /required|unavailable/
    );
  }
  assert.throws(
    () => createAgentSessionSigningCapabilityRuntimeComposition({
      ...complete,
      signer: { purpose: "capability.issue", key_id: complete.signer.key_id, sign() {} }
    }),
    /purpose-separated/
  );
});

test("runtime composition injects handleAuthenticated and authenticates the Device request only once", async () => {
  const calls = { authenticate: 0, bind: 0, repository: [] };
  const dependencies = baseDependencies({
    deviceRequestVerifier: async (input) => {
      calls.authenticate += 1;
      assert.deepEqual(input.body, request().body);
      return { organization_id: IDS.organization, device_id: IDS.device };
    },
    sessionBinder: async (input) => {
      calls.bind += 1;
      assert.deepEqual(input, {
        organization_id: IDS.organization,
        device_id: IDS.device,
        session_id: IDS.session,
        authenticated_device: { organization_id: IDS.organization, device_id: IDS.device },
        now: NOW
      });
      return {
        authorized: true,
        organization_id: IDS.organization,
        device_id: IDS.device,
        session_id: IDS.session,
        grant_id: IDS.grant,
        agent_id: IDS.agent
      };
    },
    reservationRepositoryFactory: (context) => {
      calls.repository.push(context);
      return createReservationRepository();
    }
  });
  const composed = createAgentSessionSigningCapabilityRuntimeComposition(dependencies);
  const result = await composed.agentSessionDeviceApi.handle(request());

  assert.equal(result.status, 201, JSON.stringify(result));
  assert.equal(result.body.request_id, IDS.request);
  assert.equal(result.body.capability.statement.organization_id, IDS.organization);
  assert.equal(result.body.capability.statement.session_id, IDS.session);
  assert.equal(calls.authenticate, 1);
  assert.equal(calls.bind, 1);
  assert.deepEqual(calls.repository, [{
    organizationId: IDS.organization,
    sessionId: IDS.session,
    grantId: IDS.grant,
    deviceId: IDS.device,
    agentId: IDS.agent
  }]);
});

test("a missing repository returned after binding fails closed without exposing provider details", async () => {
  const composed = createAgentSessionSigningCapabilityRuntimeComposition(baseDependencies({
    reservationRepositoryFactory: () => undefined
  }));
  const result = await composed.agentSessionDeviceApi.handle(request());
  assert.equal(result.status, 503);
  assert.equal(result.body.error.code, "agent_session_signing_capability_unavailable");
  assert.doesNotMatch(JSON.stringify(result.body), /claim|provider|private|password/iu);
});
