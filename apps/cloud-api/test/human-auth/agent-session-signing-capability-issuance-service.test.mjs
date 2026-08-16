import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import { canonicalJson } from "../../../../packages/protocol/src/index.mjs";
import {
  AGENT_SESSION_SIGNATURE_BUDGET,
  AGENT_SIGNING_CAPABILITY_ALGORITHM,
  AGENT_SIGNING_CAPABILITY_ISSUER,
  AGENT_SIGNING_CAPABILITY_ISSUANCE_ERROR_CODES,
  AGENT_SIGNING_CAPABILITY_KEY_PURPOSE,
  AGENT_SIGNING_CAPABILITY_OPERATION,
  AGENT_SIGNING_CAPABILITY_SIGNATURE_DOMAIN,
  createAgentSessionSigningCapabilityIssuanceService
} from "../../src/human-auth/agent-sessions/signing-capability-issuance-service.mjs";

const NOW = Date.parse("2026-08-16T00:00:00.000Z");
const IDS = Object.freeze({
  request: "11111111-1111-4111-8111-111111111111",
  organization: "22222222-2222-4222-8222-222222222222",
  session: "33333333-3333-4333-8333-333333333333",
  device: "44444444-4444-4444-8444-444444444444",
  agent: "55555555-5555-4555-8555-555555555555",
  capability: "66666666-6666-4666-8666-666666666666"
});
const KEY_ID = "git-commit-sign-2026-08";
const KEYS = crypto.generateKeyPairSync("ed25519");

function scope() {
  return {
    operations: [AGENT_SIGNING_CAPABILITY_OPERATION],
    repositories: ["/Users/example/repository"],
    branches: { allow: ["main"], deny: [] },
    remotes: { allow: ["origin"], deny: [] }
  };
}

function reservation(overrides = {}) {
  return {
    state: "reserved",
    capability_id: IDS.capability,
    organization_id: IDS.organization,
    session_id: IDS.session,
    device_id: IDS.device,
    agent_id: IDS.agent,
    scope: scope(),
    sequence: 1,
    control_sequence: 12,
    authority_generation: 7,
    issued_at: new Date(NOW).toISOString(),
    not_before: new Date(NOW).toISOString(),
    expires_at: new Date(NOW + 300_000).toISOString(),
    remaining_session_signatures: 1,
    claim_token: "claim-token-00000001",
    ...overrides
  };
}

function sign(statement) {
  const bytes = Buffer.from(`${AGENT_SIGNING_CAPABILITY_SIGNATURE_DOMAIN}${canonicalJson(statement)}`, "utf8");
  return crypto.sign(null, bytes, KEYS.privateKey).toString("base64url");
}

function fixture({ reserve = undefined, commit = undefined, replay = undefined, signer = undefined, now = () => NOW } = {}) {
  const calls = { reserve: [], commit: [], replay: [], uncertain: [], sign: [] };
  let committed;
  const repository = {
    async reserveCapability(input) {
      calls.reserve.push(structuredClone(input));
      if (typeof reserve === "function") return reserve(input, calls);
      return structuredClone(committed ?? reservation());
    },
    async commitCapability(input) {
      calls.commit.push(structuredClone(input));
      if (typeof commit === "function") return commit(input, calls);
      committed = { state: "committed", capability: input.capability, remaining_session_signatures: input.remaining_session_signatures };
      return structuredClone(committed);
    },
    async replayCapability(input) {
      calls.replay.push(structuredClone(input));
      if (typeof replay === "function") return replay(input, calls);
      return structuredClone(committed ?? { state: "absent" });
    },
    async markCapabilityUncertain(input) {
      calls.uncertain.push(structuredClone(input));
      return { state: "uncertain" };
    }
  };
  const signing = {
    key_id: KEY_ID,
    algorithm: AGENT_SIGNING_CAPABILITY_ALGORITHM,
    purpose: AGENT_SIGNING_CAPABILITY_KEY_PURPOSE,
    async signCapability(statement) {
      calls.sign.push(structuredClone(statement));
      return signer ? signer(statement, calls) : sign(statement);
    }
  };
  const service = createAgentSessionSigningCapabilityIssuanceService({ repository, signer: signing, now });
  return { service, repository, calls, getCommitted: () => committed };
}

test("derives fixed authority fields and returns only a deeply frozen public response", async () => {
  const value = fixture();
  const response = await value.service.issue({ request_id: IDS.request });
  assert.equal(response.request_id, IDS.request);
  assert.equal(response.capability.statement.organization_id, IDS.organization);
  assert.equal(response.capability.statement.session_id, IDS.session);
  assert.equal(response.capability.statement.operation, AGENT_SIGNING_CAPABILITY_OPERATION);
  assert.equal(response.capability.statement.key_purpose, AGENT_SIGNING_CAPABILITY_KEY_PURPOSE);
  assert.equal(response.capability.statement.one_use, true);
  assert.equal(response.capability.statement.max_signatures, 1);
  assert.equal(response.capability.statement.control_sequence, 12);
  assert.equal(response.capability.statement.authority_generation, 7);
  assert.equal(response.metadata.remaining_session_signatures, 1);
  assert.equal(response.metadata.replayed, false);
  assert.equal(response.capability.statement_hash, crypto.createHash("sha256").update(canonicalJson(response.capability.statement), "utf8").digest("hex"));
  assert.equal(crypto.verify(
    null,
    Buffer.from(`${AGENT_SIGNING_CAPABILITY_SIGNATURE_DOMAIN}${canonicalJson(response.capability.statement)}`, "utf8"),
    KEYS.publicKey,
    Buffer.from(response.capability.signature, "base64url")
  ), true);
  assert.deepEqual(Object.keys(value.calls.reserve[0]).sort(), [
    "key_purpose", "max_signatures", "one_use", "operation", "request_id", "ttl_ms"
  ]);
  assert.equal(value.calls.sign.length, 1);
  assert.equal(Object.isFrozen(response), true);
  assert.equal(Object.isFrozen(response.capability), true);
  assert.equal(Object.isFrozen(response.capability.statement), true);
  assert.equal(Object.isFrozen(response.capability.statement.scope), true);
  assert.equal(JSON.stringify(response).includes("claim-token"), false);
  assert.equal(JSON.stringify(response).includes("private"), false);
});

test("accepts only the signature from a minimal signer result", async () => {
  const value = fixture({ signer: async (statement) => ({ signature: sign(statement) }) });
  const response = await value.service.issue({ request_id: IDS.request });
  assert.equal(response.capability.statement.capability_id, IDS.capability);
  assert.equal(value.calls.sign.length, 1);
});

test("composes with the purpose-specific F1 signer envelope and constructor-pinned key id", async () => {
  const repository = fixture().repository;
  const signer = {
    async signAgentSigningCapability(statement) {
      return {
        version: 1,
        type: "agentpass.agent-signing-capability",
        statement,
        statement_hash: crypto.createHash("sha256").update(canonicalJson(statement), "utf8").digest("hex"),
        signature: sign(statement)
      };
    }
  };
  const service = createAgentSessionSigningCapabilityIssuanceService({ repository, signer, signerKeyId: KEY_ID, now: () => NOW });
  const response = await service.issue({ request_id: IDS.request });
  assert.equal(response.capability.statement.key_id, KEY_ID);
  assert.equal(response.metadata.replayed, false);
});

test("rejects every caller-supplied authority field before touching the repository", async () => {
  const value = fixture();
  for (const field of ["organization_id", "session_id", "device_id", "agent_id", "scope", "operation", "key_purpose", "expires_at", "sequence", "control_sequence", "authority_generation"]) {
    await assert.rejects(value.service.issue({ request_id: IDS.request, [field]: "attacker-controlled" }), { code: AGENT_SIGNING_CAPABILITY_ISSUANCE_ERROR_CODES.INPUT });
  }
  assert.equal(value.calls.reserve.length, 0);
});

test("replays a committed result without signing again", async () => {
  let clock = NOW;
  const value = fixture({ now: () => clock });
  const first = await value.service.issue({ request_id: IDS.request });
  clock += 60_000;
  const second = await value.service.issue({ request_id: IDS.request });
  assert.equal(value.calls.sign.length, 1);
  assert.equal(value.calls.commit.length, 1);
  assert.equal(second.metadata.replayed, true);
  assert.deepEqual(second.capability, first.capability);
  assert.deepEqual(value.calls.reserve[1], value.calls.reserve[0]);
});

test("marks a signer failure outcome unknown and never commits", async () => {
  const value = fixture({ signer: async () => { throw new Error("provider diagnostics and private key must not escape"); } });
  await assert.rejects(value.service.issue({ request_id: IDS.request }), { code: AGENT_SIGNING_CAPABILITY_ISSUANCE_ERROR_CODES.OUTCOME_UNKNOWN });
  assert.equal(value.calls.commit.length, 0);
  assert.deepEqual(value.calls.uncertain[0], { request_id: IDS.request, claim_token: "claim-token-00000001", reason: "signer_failure" });
});

test("reconciles a lost commit response without a second signer call", async () => {
  let committed;
  const calls = { sign: 0, uncertain: [] };
  const repository = {
    async reserveCapability() { return reservation(); },
    async commitCapability(input) { committed = { state: "committed", capability: input.capability, remaining_session_signatures: 1 }; throw new Error("lost"); },
    async replayCapability() { return committed; },
    async markCapabilityUncertain(input) { calls.uncertain.push(input); }
  };
  const service = createAgentSessionSigningCapabilityIssuanceService({
    repository,
    signer: { key_id: KEY_ID, async signCapability(statement) { calls.sign += 1; return sign(statement); } },
    now: () => NOW
  });
  const response = await service.issue({ request_id: IDS.request });
  assert.equal(response.metadata.replayed, true);
  assert.equal(calls.sign, 1);
  assert.equal(calls.uncertain.length, 0);
});

test("does not sign a reservation already marked uncertain", async () => {
  const value = fixture({ reserve: async () => ({ state: "uncertain" }) });
  await assert.rejects(value.service.issue({ request_id: IDS.request }), { code: AGENT_SIGNING_CAPABILITY_ISSUANCE_ERROR_CODES.OUTCOME_UNKNOWN });
  assert.equal(value.calls.sign.length, 0);
});

test("rejects signer statement substitution and quarantines the reservation", async () => {
  const value = fixture({ signer: async (statement) => ({ ...statement, organization_id: IDS.agent, signature: sign(statement) }) });
  await assert.rejects(value.service.issue({ request_id: IDS.request }), { code: AGENT_SIGNING_CAPABILITY_ISSUANCE_ERROR_CODES.SIGNER_OUTPUT });
  assert.equal(value.calls.commit.length, 0);
  assert.equal(value.calls.uncertain[0].reason, "signer_output_invalid");
});

test("fails closed for malformed reservation authority and invalid configuration", () => {
  const value = fixture({ reserve: async () => ({ ...reservation(), remaining_session_signatures: 2 }) });
  assert.throws(() => createAgentSessionSigningCapabilityIssuanceService({ repository: {}, signer: {} }), { code: AGENT_SIGNING_CAPABILITY_ISSUANCE_ERROR_CODES.CONFIG });
  return assert.rejects(value.service.issue({ request_id: IDS.request }), { code: AGENT_SIGNING_CAPABILITY_ISSUANCE_ERROR_CODES.REPOSITORY });
});

test("uses the fixed managed signer identity and no local private-key fallback", () => {
  assert.throws(() => createAgentSessionSigningCapabilityIssuanceService({
    repository: fixture().repository,
    signer: { key_id: KEY_ID, private_key: "-----BEGIN PRIVATE KEY-----", signCapability() {} }
  }), { code: AGENT_SIGNING_CAPABILITY_ISSUANCE_ERROR_CODES.CONFIG });
  assert.equal(AGENT_SIGNING_CAPABILITY_ISSUER, "agentpass-cloud");
  assert.equal(AGENT_SESSION_SIGNATURE_BUDGET, 2);
});
