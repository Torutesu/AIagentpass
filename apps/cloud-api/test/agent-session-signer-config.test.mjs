import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import {
  AGENT_SESSION_SIGNER_ERROR_CODES,
  AGENT_SESSION_SIGNER_PURPOSE,
  createHostedAgentSessionGrantSigner,
  parseAgentSessionSignerConfig
} from "../src/agent-session-signer-config.mjs";
import { agentSessionGrantSigningData, verifyAgentSessionGrant } from "../src/agent-session-grant.mjs";

const NOW = Date.parse("2026-08-13T10:00:00.000Z");
const ids = {
  grant: "11111111-1111-4111-8111-111111111111",
  organization: "22222222-2222-4222-8222-222222222222",
  device: "33333333-3333-4333-8333-333333333333",
  agent: "44444444-4444-4444-8444-444444444444",
  adapter: "55555555-5555-4555-8555-555555555555"
};
const agentKeys = crypto.generateKeyPairSync("ed25519");
const otherKeys = crypto.generateKeyPairSync("ed25519");
const agentPublicKey = agentKeys.publicKey.export({ type: "spki", format: "pem" }).toString();
const otherPublicKey = otherKeys.publicKey.export({ type: "spki", format: "pem" }).toString();

function env(overrides = {}) {
  return {
    AGENTPASS_CLOUD_PROFILE: "hosted",
    AGENTPASS_CLOUD_AGENT_SESSION_KEY_ID: "agent-session-2026-08",
    AGENTPASS_CLOUD_AGENT_SESSION_PUBLIC_KEY: agentPublicKey,
    AGENTPASS_CLOUD_AGENT_SESSION_TIMEOUT_MS: "5000",
    ...overrides
  };
}

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

function localProvider({ metadata = agentKeys.publicKey, sign = ({ bytes }) => crypto.sign(null, bytes, agentKeys.privateKey) } = {}) {
  return {
    async publicKeyMetadata(input) {
      assert.equal(input.key_id, "agent-session-2026-08");
      assert.equal(input.algorithm, "ed25519");
      assert.equal(input.purpose, AGENT_SESSION_SIGNER_PURPOSE);
      assert.equal(input.version, 1);
      assert(input.signal);
      return { key_id: input.key_id, algorithm: input.algorithm, public_key: metadata };
    },
    async sign(input) {
      assert.equal(input.key_id, "agent-session-2026-08");
      assert.equal(input.algorithm, "ed25519");
      assert.equal(input.purpose, AGENT_SESSION_SIGNER_PURPOSE);
      assert(input.signal);
      assert.deepEqual(input.bytes, agentSessionGrantSigningData(statement()));
      return sign(input);
    }
  };
}

test("parses hosted Agent Session configuration without exposing private material", () => {
  const config = parseAgentSessionSignerConfig(env());
  assert.deepEqual(Object.keys(config).sort(), [
    "algorithm", "keyId", "profile", "publicKeyFingerprint", "publicKeyPem", "purpose", "timeoutMs"
  ]);
  assert.equal(config.publicKeyPem, agentPublicKey);
  assert.equal(config.timeoutMs, 5000);
  assert.equal(JSON.stringify(config).includes("PRIVATE KEY"), false);
  assert.throws(() => parseAgentSessionSignerConfig(env({ AGENTPASS_CLOUD_PROFILE: "evaluation" })), (error) => error.code === AGENT_SESSION_SIGNER_ERROR_CODES.CONFIG);
  assert.throws(() => parseAgentSessionSignerConfig(env({ AGENTPASS_CLOUD_AGENT_SESSION_PUBLIC_KEY: agentKeys.privateKey.export({ type: "pkcs8", format: "pem" }).toString() })), (error) => error.code === AGENT_SESSION_SIGNER_ERROR_CODES.CONFIG);
  assert.throws(() => parseAgentSessionSignerConfig(env({ AGENTPASS_CLOUD_AGENT_SESSION_TIMEOUT_MS: "30001" })), (error) => error.code === AGENT_SESSION_SIGNER_ERROR_CODES.CONFIG);
});
test("rejects reuse of bundle or refresh key ids and public keys", () => {
  assert.throws(() => parseAgentSessionSignerConfig(env(), { bundle: { keyId: "agent-session-2026-08" } }), (error) => error.code === AGENT_SESSION_SIGNER_ERROR_CODES.KEY_REUSE);
  assert.throws(() => parseAgentSessionSignerConfig(env(), { refresh: { keyId: "refresh-v1", publicKey: agentPublicKey } }), (error) => error.code === AGENT_SESSION_SIGNER_ERROR_CODES.KEY_REUSE);
  assert.doesNotThrow(() => parseAgentSessionSignerConfig(env(), { bundle: { keyId: "bundle-v1", publicKey: otherPublicKey }, refresh: { keyId: "refresh-v1" } }));
});

test("pins provider metadata and signs only with the purpose-separated Ed25519 key", async () => {
  const signer = createHostedAgentSessionGrantSigner({ provider: localProvider(), env: env(), now: () => NOW });
  const metadata = await signer.publicKeyMetadata();
  assert.deepEqual(metadata, {
    version: 1,
    purpose: AGENT_SESSION_SIGNER_PURPOSE,
    key_id: "agent-session-2026-08",
    algorithm: "ed25519",
    public_key: agentPublicKey,
    public_key_fingerprint: signer.config.publicKeyFingerprint
  });
  const grant = await signer.signAgentSessionGrant(statement());
  assert.deepEqual(verifyAgentSessionGrant(grant, { publicKey: agentKeys.publicKey, keyId: "agent-session-2026-08", now: NOW }), grant);
  const health = await signer.health();
  assert.deepEqual(health, {
    ready: true,
    purpose: AGENT_SESSION_SIGNER_PURPOSE,
    algorithm: "ed25519",
    key_id: "agent-session-2026-08",
    public_key_fingerprint: signer.config.publicKeyFingerprint
  });
  assert.equal(Object.hasOwn(signer, "provider"), false);
});

test("fails closed on metadata substitution, forged output, provider errors, and timeout", async () => {
  await assert.rejects(
    createHostedAgentSessionGrantSigner({ provider: localProvider({ metadata: otherKeys.publicKey }), env: env(), now: () => NOW }).publicKeyMetadata(),
    (error) => error.code === AGENT_SESSION_SIGNER_ERROR_CODES.METADATA
  );
  await assert.rejects(
    createHostedAgentSessionGrantSigner({ provider: localProvider({ metadata: agentKeys.privateKey }), env: env(), now: () => NOW }).publicKeyMetadata(),
    (error) => error.code === AGENT_SESSION_SIGNER_ERROR_CODES.METADATA
  );
  await assert.rejects(
    createHostedAgentSessionGrantSigner({ provider: localProvider({ sign: () => Buffer.alloc(64) }), env: env(), now: () => NOW }).signAgentSessionGrant(statement()),
    (error) => error.code === AGENT_SESSION_SIGNER_ERROR_CODES.VERIFICATION
  );
  const secret = "provider-private-material-must-not-escape";
  const providerError = createHostedAgentSessionGrantSigner({
    provider: { async publicKeyMetadata() { throw new Error(secret); }, async sign() { return Buffer.alloc(64); } },
    env: env(),
    now: () => NOW
  });
  await assert.rejects(providerError.publicKeyMetadata(), (error) => error.code === AGENT_SESSION_SIGNER_ERROR_CODES.PROVIDER && !String(error).includes(secret));
  const timeout = createHostedAgentSessionGrantSigner({
    provider: { async publicKeyMetadata() { return new Promise(() => {}); }, async sign() { return Buffer.alloc(64); } },
    env: env({ AGENTPASS_CLOUD_AGENT_SESSION_TIMEOUT_MS: "10" }),
    now: () => NOW
  });
  await assert.rejects(timeout.publicKeyMetadata(), (error) => error.code === AGENT_SESSION_SIGNER_ERROR_CODES.TIMEOUT);
});
