import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import { canonicalJson } from "../../../packages/protocol/src/index.mjs";
import {
  AGENT_SESSION_GRANT_ERROR_CODES,
  AGENT_SESSION_GRANT_SIGNATURE_DOMAIN,
  AgentSessionGrantError,
  agentSessionGrantStatementHash,
  createAgentSessionGrantSigner,
  createLocalAgentSessionGrantSigner,
  normalizeAgentSessionGrantStatement,
  verifyAgentSessionGrant
} from "../src/agent-session-grant.mjs";

const ids = {
  grant: "11111111-1111-4111-8111-111111111111",
  organization: "22222222-2222-4222-8222-222222222222",
  device: "33333333-3333-4333-8333-333333333333",
  agent: "44444444-4444-4444-8444-444444444444",
  adapter: "55555555-5555-4555-8555-555555555555"
};
const now = Date.parse("2026-08-13T10:00:00.000Z");
const keys = crypto.generateKeyPairSync("ed25519");

function statement(overrides = {}) {
  return {
    version: 1,
    grant_id: ids.grant,
    organization_id: ids.organization,
    device_id: ids.device,
    agent_id: ids.agent,
    agent_kind: "claude-code",
    adapter_id: ids.adapter,
    adapter_version: "1.2.3",
    worktree_binding_sha256: "a".repeat(64),
    process_binding_policy_id: "claude-code-v1",
    scope: {
      operations: ["git.commit.sign"],
      repositories: ["/work/project"],
      branches: { allow: ["feature/*"], deny: ["main"] },
      remotes: { allow: ["git@example.test:project.git"], deny: [] }
    },
    max_signatures: 2,
    not_before: "2026-08-13T09:59:00.000Z",
    expires_at: "2026-08-13T10:14:00.000Z",
    control_sequence: 12,
    authority_generation: 7,
    issuer: "agentpass-cloud",
    key_id: "agent-session-2026-08",
    ...overrides
  };
}

test("signs and verifies the exact canonical domain-separated grant", async () => {
  const signer = createLocalAgentSessionGrantSigner({ privateKey: keys.privateKey, keyId: "agent-session-2026-08", now: () => now });
  {
    const grant = await signer.signAgentSessionGrant(statement());
    assert.equal(grant.statement_hash, crypto.createHash("sha256").update(canonicalJson(grant.statement)).digest("hex"));
    assert.equal(agentSessionGrantStatementHash(grant.statement), grant.statement_hash);
    assert.equal(Buffer.from(grant.signature, "base64url").length, 64);
    assert.deepEqual(verifyAgentSessionGrant(grant, { publicKey: keys.publicKey, keyId: "agent-session-2026-08", now }), grant);
    assert.equal(Object.isFrozen(grant.statement.scope), true);
  }
});

test("provider receives only the frozen signing domain and public identifiers", async () => {
  let observed;
  const signer = createAgentSessionGrantSigner({
    keyId: "agent-session-2026-08",
    provider: {
      async publicKeyMetadata(input) { assert.deepEqual(input, { key_id: "agent-session-2026-08", purpose: "agentpass.agent-session-grant" }); return { key_id: input.key_id, algorithm: "ed25519", public_key: keys.publicKey }; },
      async sign(input) { observed = input; return crypto.sign(null, input.bytes, keys.privateKey); }
    },
    now: () => now
  });
  await signer.signAgentSessionGrant(statement());
  assert.equal(observed.bytes.subarray(0, Buffer.byteLength(AGENT_SESSION_GRANT_SIGNATURE_DOMAIN)).toString(), AGENT_SESSION_GRANT_SIGNATURE_DOMAIN);
  assert.deepEqual(Object.keys(observed).sort(), ["algorithm", "bytes", "key_id", "purpose"]);
});

test("rejects mutation, key substitution, noncanonical signatures, and validity boundaries", async () => {
  const signer = createLocalAgentSessionGrantSigner({ privateKey: keys.privateKey, keyId: "agent-session-2026-08", now: () => now });
  const grant = await signer.signAgentSessionGrant(statement());
  const cases = [
    { ...grant, statement: { ...grant.statement, max_signatures: 3 } },
    { ...grant, statement_hash: "b".repeat(64) },
    { ...grant, signature: Buffer.alloc(64).toString("base64url") },
    { ...grant, extra: true }
  ];
  for (const value of cases) assert.throws(() => verifyAgentSessionGrant(value, { publicKey: keys.publicKey, now }), AgentSessionGrantError);
  assert.throws(() => verifyAgentSessionGrant(grant, { publicKey: keys.publicKey, now: Date.parse(grant.statement.expires_at) }), (error) => error.code === AGENT_SESSION_GRANT_ERROR_CODES.EXPIRED);
  assert.throws(() => verifyAgentSessionGrant(grant, { publicKey: keys.publicKey, now: Date.parse(grant.statement.not_before) - 1 }), (error) => error.code === AGENT_SESSION_GRANT_ERROR_CODES.NOT_YET_VALID);
});

test("normalization enforces closed fields, unique scope members, canonical time, and bounds", () => {
  assert.deepEqual(normalizeAgentSessionGrantStatement(statement()), statement());
  for (const value of [
    { ...statement(), unknown: true },
    statement({ adapter_version: "01.0.0" }),
    statement({ expires_at: "2026-08-13T11:14:00.000Z" }),
    statement({ scope: { ...statement().scope, repositories: ["/work/project", "/work/project"] } }),
    statement({ scope: { ...statement().scope, repositories: ["/work/../secret"] } }),
    statement({ max_signatures: 65 })
  ]) assert.throws(() => normalizeAgentSessionGrantStatement(value), (error) => error.code === AGENT_SESSION_GRANT_ERROR_CODES.INPUT);
});

test("fails closed for signer metadata mismatch and forged provider output", async () => {
  {
    const signer = createAgentSessionGrantSigner({ keyId: "agent-session-2026-08", now: () => now, provider: {
      async publicKeyMetadata() { return { key_id: "other", algorithm: "ed25519", public_key: keys.publicKey }; },
      async sign() { return Buffer.alloc(64); }
    } });
    await assert.rejects(signer.signAgentSessionGrant(statement()), (error) => error.code === AGENT_SESSION_GRANT_ERROR_CODES.OUTPUT);
  }
});
