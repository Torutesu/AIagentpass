import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import {
  AGENT_SIGNING_CAPABILITY_SIGNER_ALGORITHM,
  AGENT_SIGNING_CAPABILITY_SIGNER_DOMAIN,
  AGENT_SIGNING_CAPABILITY_SIGNER_ERROR_CODES as CODES,
  AGENT_SIGNING_CAPABILITY_SIGNER_PURPOSE,
  createHostedAgentSigningCapabilitySigner,
  parseAgentSigningCapabilitySignerConfig
} from "../src/agent-signing-capability-signer-config.mjs";
import {
  AGENT_SIGNING_CAPABILITY_SIGNATURE_DOMAIN,
  agentSigningCapabilitySigningData,
  verifyAgentSigningCapability
} from "../src/agent-signing-capability.mjs";

const NOW = Date.parse("2026-08-16T00:00:10.000Z");
const IDS = {
  capability: "11111111-1111-4111-8111-111111111111",
  organization: "22222222-2222-4222-8222-222222222222",
  session: "33333333-3333-4333-8333-333333333333",
  device: "44444444-4444-4444-8444-444444444444",
  agent: "55555555-5555-4555-8555-555555555555"
};
const KEYS = crypto.generateKeyPairSync("ed25519");
const OTHER_KEYS = crypto.generateKeyPairSync("ed25519");
const KEY_ID = "agent-signing-2026-08";
const PUBLIC_KEY = publicPem(KEYS.publicKey);
const OTHER_PUBLIC_KEY = publicPem(OTHER_KEYS.publicKey);

function publicPem(key) { return key.export({ type: "spki", format: "pem" }).toString(); }

function env(overrides = {}) {
  return {
    AGENTPASS_CLOUD_PROFILE: "hosted",
    AGENTPASS_CLOUD_AGENT_SIGNING_CAPABILITY_KEY_ID: KEY_ID,
    AGENTPASS_CLOUD_AGENT_SIGNING_CAPABILITY_PUBLIC_KEY: PUBLIC_KEY,
    AGENTPASS_CLOUD_AGENT_SIGNING_CAPABILITY_TIMEOUT_MS: "5000",
    ...overrides
  };
}

function statement(overrides = {}) {
  return {
    version: 1,
    type: "agentpass.agent-signing-capability",
    capability_id: IDS.capability,
    organization_id: IDS.organization,
    session_id: IDS.session,
    device_id: IDS.device,
    agent_id: IDS.agent,
    one_use: true,
    operation: "git.commit.sign",
    scope: {
      operations: ["git.commit.sign"],
      repositories: ["/work/project"],
      branches: { allow: ["feature/*"], deny: ["main"] },
      remotes: { allow: ["git@example.test:project.git"], deny: [] }
    },
    key_purpose: "git.commit.sign",
    key_id: KEY_ID,
    algorithm: "ed25519",
    max_signatures: 1,
    issued_at: "2026-08-16T00:00:00.000Z",
    not_before: "2026-08-16T00:00:01.000Z",
    expires_at: "2026-08-16T00:05:00.000Z",
    sequence: 7,
    control_sequence: 12,
    authority_generation: 3,
    issuer: "agentpass-cloud",
    ...overrides
  };
}

function provider({ metadata = KEYS.publicKey, sign = ({ bytes }) => crypto.sign(null, bytes, KEYS.privateKey), providerId = "agentpass-aws-kms-ledger-v1" } = {}) {
  const calls = [];
  return {
    provider_id: providerId,
    calls,
    async publicKeyMetadata(input) {
      calls.push({ method: "metadata", input });
      return { key_id: input.key_id, algorithm: input.algorithm, public_key: metadata };
    },
    async sign(input) {
      calls.push({ method: "sign", input: { ...input, bytes: Buffer.from(input.bytes) } });
      return sign(input);
    }
  };
}

test("parses a hosted purpose-separated public configuration", () => {
  const config = parseAgentSigningCapabilitySignerConfig(env(), {}, { now: () => NOW });
  assert.deepEqual(Object.keys(config).sort(), [
    "algorithm", "keyId", "profile", "publicKeyFingerprint", "publicKeyPem", "purpose",
    "signatureDomain", "timeoutMs", "version"
  ]);
  assert.equal(config.profile, "hosted");
  assert.equal(config.purpose, "git.commit.sign");
  assert.equal(config.algorithm, "ed25519");
  assert.equal(config.signatureDomain, AGENT_SIGNING_CAPABILITY_SIGNATURE_DOMAIN);
  assert.equal(config.publicKeyPem, PUBLIC_KEY);
  assert.equal(config.timeoutMs, 5000);
  assert.equal(JSON.stringify(config).includes("PRIVATE KEY"), false);
  assert.equal(Object.isFrozen(config), true);
});

test("pins provider metadata, managed provider selectors, and exact domain-separated output", async () => {
  const value = provider();
  const signer = createHostedAgentSigningCapabilitySigner({ provider: value, env: env(), now: () => NOW });
  assert.equal(Object.hasOwn(signer, "provider"), false);
  const metadata = await signer.publicKeyMetadata();
  assert.deepEqual(metadata, {
    version: 1,
    purpose: AGENT_SIGNING_CAPABILITY_SIGNER_PURPOSE,
    key_id: KEY_ID,
    algorithm: AGENT_SIGNING_CAPABILITY_SIGNER_ALGORITHM,
    public_key: PUBLIC_KEY,
    public_key_fingerprint: signer.config.publicKeyFingerprint
  });
  const envelope = await signer.signAgentSigningCapability(statement());
  assert.deepEqual(envelope, verifyAgentSigningCapability(envelope, {
    publicKey: KEYS.publicKey,
    keyId: KEY_ID,
    organizationId: IDS.organization,
    sessionId: IDS.session,
    deviceId: IDS.device,
    agentId: IDS.agent,
    sequence: 7,
    controlSequence: 12,
    authorityGeneration: 3,
    now: NOW
  }));
  const signingCalls = value.calls.filter((call) => call.method === "sign");
  assert.equal(signingCalls.length, 1);
  assert.deepEqual(Object.keys(signingCalls[0].input).sort(), ["algorithm", "bytes", "key_id", "purpose", "signal", "version"]);
  assert.equal(signingCalls[0].input.purpose, "git.commit.sign");
  assert.equal(signingCalls[0].input.algorithm, "ed25519");
  assert.equal(signingCalls[0].input.key_id, KEY_ID);
  assert.equal(signingCalls[0].input.version, 1);
  assert.deepEqual(signingCalls[0].input.bytes, agentSigningCapabilitySigningData(statement()));
  assert.equal(signingCalls[0].input.bytes.subarray(0, Buffer.byteLength(AGENT_SIGNING_CAPABILITY_SIGNER_DOMAIN)).toString(), AGENT_SIGNING_CAPABILITY_SIGNER_DOMAIN);
  assert.equal((await signer.health()).ready, true);
});

test("rejects provider metadata substitution and invalid provider identity", async () => {
  const substituted = provider({ metadata: OTHER_PUBLIC_KEY });
  const signer = createHostedAgentSigningCapabilitySigner({ provider: substituted, env: env(), now: () => NOW });
  await assert.rejects(signer.publicKeyMetadata(), { code: CODES.METADATA });
  assert.throws(() => createHostedAgentSigningCapabilitySigner({
    provider: provider({ providerId: "local-private-key-file" }), env: env(), now: () => NOW
  }), { code: CODES.CONFIG });
});

test("rejects forged, malformed, and non-domain-separated provider output", async () => {
  const invalidSignature = createHostedAgentSigningCapabilitySigner({
    provider: provider({ sign: () => Buffer.alloc(64) }), env: env(), now: () => NOW
  });
  await assert.rejects(invalidSignature.signAgentSigningCapability(statement()), { code: CODES.VERIFICATION });

  const malformed = createHostedAgentSigningCapabilitySigner({
    provider: provider({ sign: () => Buffer.alloc(65) }), env: env(), now: () => NOW
  });
  await assert.rejects(malformed.signAgentSigningCapability(statement()), { code: CODES.OUTPUT });

  const direct = provider({ sign: ({ bytes }) => crypto.sign(null, Buffer.concat([Buffer.from("wrong\0"), bytes.subarray(Buffer.byteLength(AGENT_SIGNING_CAPABILITY_SIGNATURE_DOMAIN))]), KEYS.privateKey) });
  const signer = createHostedAgentSigningCapabilitySigner({ provider: direct, env: env(), now: () => NOW });
  await assert.rejects(signer.signAgentSigningCapability(statement()), { code: CODES.VERIFICATION });
});

test("rejects cross-purpose key id and public-key reuse", () => {
  assert.throws(() => parseAgentSigningCapabilitySignerConfig(env(), { agentSession: { keyId: KEY_ID } }, { now: () => NOW }), { code: CODES.KEY_REUSE });
  assert.throws(() => parseAgentSigningCapabilitySignerConfig(env(), { possession: { publicKey: PUBLIC_KEY } }, { now: () => NOW }), { code: CODES.KEY_REUSE });
  assert.doesNotThrow(() => parseAgentSigningCapabilitySignerConfig(env(), { other: { keyId: "other-key", publicKey: OTHER_PUBLIC_KEY } }, { now: () => NOW }));
});

test("rejects local private-key material, file fallback, wrong curve, and unsafe config", () => {
  const privatePem = KEYS.privateKey.export({ type: "pkcs8", format: "pem" }).toString();
  for (const invalid of [
    { ...env(), AGENTPASS_CLOUD_PROFILE: "evaluation" },
    { ...env(), AGENTPASS_CLOUD_AGENT_SIGNING_CAPABILITY_KEY_ID: undefined },
    { ...env(), AGENTPASS_CLOUD_AGENT_SIGNING_CAPABILITY_PUBLIC_KEY: privatePem },
    { ...env(), AGENTPASS_CLOUD_AGENT_SIGNING_CAPABILITY_PUBLIC_KEY: publicPem(crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" }).publicKey) },
    { ...env(), AGENTPASS_CLOUD_AGENT_SIGNING_CAPABILITY_TIMEOUT_MS: "30001" },
    { ...env(), AGENTPASS_CLOUD_AGENT_SIGNING_CAPABILITY_PRIVATE_KEY_PATH: "/tmp/key" }
  ]) {
    assert.throws(() => parseAgentSigningCapabilitySignerConfig(invalid, {}, { now: () => NOW }), { code: CODES.CONFIG });
  }
  assert.throws(() => createHostedAgentSigningCapabilitySigner({
    provider: provider(), env: env(), now: () => NOW, privateKey: KEYS.privateKey
  }), { code: CODES.CONFIG });
});

test("maps provider failures and timeouts without leaking provider details", async () => {
  const secret = "kms-private-provider-detail";
  const failed = createHostedAgentSigningCapabilitySigner({
    provider: {
      provider_id: "agentpass-aws-kms-ledger-v1",
      async publicKeyMetadata() { throw new Error(secret); },
      async sign() { throw new Error(secret); }
    }, env: env(), now: () => NOW
  });
  await assert.rejects(failed.publicKeyMetadata(), (error) => error.code === CODES.PROVIDER
    && !String(error).includes(secret) && !Object.hasOwn(error, "cause"));

  const timedOut = createHostedAgentSigningCapabilitySigner({
    provider: {
      provider_id: "agentpass-aws-kms-ledger-v1",
      async publicKeyMetadata() { return new Promise(() => {}); },
      async sign() { return Buffer.alloc(64); }
    }, env: env({ AGENTPASS_CLOUD_AGENT_SIGNING_CAPABILITY_TIMEOUT_MS: "10" }), now: () => NOW
  });
  await assert.rejects(timedOut.publicKeyMetadata(), { code: CODES.TIMEOUT });
});

test("rejects statements outside the pinned authority, purpose, and lifetime", async () => {
  const signer = createHostedAgentSigningCapabilitySigner({ provider: provider(), env: env(), now: () => NOW });
  for (const invalid of [
    { ...statement(), key_id: "other-key" },
    { ...statement(), operation: "git.push.sign" },
    { ...statement(), key_purpose: "other-purpose" },
    { ...statement(), expires_at: "2026-08-16T00:20:00.000Z" },
    { ...statement(), unknown: true }
  ]) {
    await assert.rejects(signer.signAgentSigningCapability(invalid), { code: CODES.INPUT });
  }
});
