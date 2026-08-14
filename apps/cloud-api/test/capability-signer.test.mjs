import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import {
  CAPABILITY_SIGNER_ALGORITHM,
  CAPABILITY_SIGNER_ERROR_CODES,
  CAPABILITY_SIGNER_PROTOCOL_VERSION,
  CAPABILITY_SIGNER_PURPOSE,
  CAPABILITY_SIGNER_REGISTRY_VERSION,
  CAPABILITY_SIGNER_SIGNING_VERSION,
  CAPABILITY_SIGNER_VERSION,
  CapabilitySignerError,
  createHostedCapabilitySigner,
  createLocalCapabilitySigner,
  parseCapabilitySignerConfig
} from "../src/capability-signer.mjs";
import { canonicalCapability } from "../../../packages/capability/src/index.mjs";

const NOW = Date.parse("2026-08-15T10:00:00.000Z");
const ids = {
  capability: "11111111-1111-4111-8111-111111111111",
  agent: "22222222-2222-4222-8222-222222222222",
  device: "33333333-3333-4333-8333-333333333333"
};
const providerKeys = crypto.generateKeyPairSync("ed25519");
const otherKeys = crypto.generateKeyPairSync("ed25519");
const publicKeyPem = providerKeys.publicKey.export({ type: "spki", format: "pem" }).toString();

function input(overrides = {}) {
  return {
    version: 1,
    capability_id: ids.capability,
    nonce: "N".repeat(43),
    issuer: "org-example",
    key_id: "capability-2026-08",
    audience: { agent_id: ids.agent, device_id: ids.device },
    scope: {
      operations: ["git.commit.sign"],
      repositories: ["/work/project"],
      branches: { allow: ["feature/*"], deny: ["main"] },
      remotes: { allow: ["git@github.com:example/project.git"] }
    },
    not_before: "2026-08-15T09:59:00.000Z",
    expires_at: "2026-08-15T10:14:00.000Z",
    sequence: 4,
    ...overrides
  };
}

function provider({ metadata = publicKeyPem, sign = ({ bytes }) => crypto.sign(null, bytes, providerKeys.privateKey), delay = 0 } = {}) {
  const calls = [];
  return {
    calls,
    async publicKeyMetadata(request) {
      calls.push({ method: "metadata", request });
      if (delay) await new Promise((resolve) => setTimeout(resolve, delay));
      return { key_id: request.key_id, algorithm: request.algorithm, public_key: metadata };
    },
    async sign(request) {
      calls.push({ method: "sign", request });
      return sign(request);
    }
  };
}

function signer(options = {}) {
  const service = provider(options);
  return { service, signer: createHostedCapabilitySigner({
    provider: service,
    keyId: "capability-2026-08",
    publicKey: publicKeyPem,
    now: () => NOW,
    ...options
  }) };
}

test("uses the registry purpose and versions, and exposes only public metadata", async () => {
  const { service, signer: value } = signer();
  const metadata = await value.publicKeyMetadata();
  assert.deepEqual(metadata, {
    version: CAPABILITY_SIGNER_VERSION,
    registry_version: CAPABILITY_SIGNER_REGISTRY_VERSION,
    protocol_version: CAPABILITY_SIGNER_PROTOCOL_VERSION,
    signing_version: CAPABILITY_SIGNER_SIGNING_VERSION,
    purpose: CAPABILITY_SIGNER_PURPOSE,
    key_id: "capability-2026-08",
    algorithm: CAPABILITY_SIGNER_ALGORITHM,
    public_key: publicKeyPem,
    public_key_fingerprint: metadata.public_key_fingerprint
  });
  assert.equal(service.calls[0].request.purpose, CAPABILITY_SIGNER_PURPOSE);
  assert.equal(service.calls[0].request.algorithm, CAPABILITY_SIGNER_ALGORITHM);
  assert.equal(service.calls[0].request.version, CAPABILITY_SIGNER_PROTOCOL_VERSION);
  assert.equal(Object.hasOwn(value, "privateKey"), false);
  assert.equal(JSON.stringify(value).includes("PRIVATE KEY"), false);
});

test("signs the exact existing canonical capability statement and verifies it before returning", async () => {
  const { service, signer: value } = signer();
  const result = await value.signCapability(input());
  const expectedBytes = Buffer.from(canonicalCapability(result), "utf8");
  assert.deepEqual(service.calls[1].request.bytes, expectedBytes);
  assert.equal(service.calls[1].request.purpose, CAPABILITY_SIGNER_PURPOSE);
  assert.equal(service.calls[1].request.version, CAPABILITY_SIGNER_PROTOCOL_VERSION);
  assert.equal(crypto.verify(null, expectedBytes, providerKeys.publicKey, Buffer.from(result.signature, "base64")), true);
  assert.equal(result.signature.length, 88);
  assert.equal(Object.isFrozen(result), true);
});

test("supports the existing issue and sign aliases without changing statement semantics", async () => {
  const { signer: value } = signer();
  const first = await value.issueCapability(input());
  const second = await value.sign(input());
  for (const result of [first, second]) {
    assert.equal(result.version, 1);
    assert.equal(result.key_id, "capability-2026-08");
    assert.equal(result.sequence, 4);
    assert.equal(result.scope.repositories[0], "/work/project");
  }
});

test("fails closed on key substitution, private metadata, malformed output, and forged output", async () => {
  await assert.rejects(
    signer({ metadata: otherKeys.publicKey }).signer.publicKeyMetadata(),
    (error) => error.code === CAPABILITY_SIGNER_ERROR_CODES.METADATA
  );
  await assert.rejects(
    signer({ metadata: providerKeys.privateKey }).signer.publicKeyMetadata(),
    (error) => error.code === CAPABILITY_SIGNER_ERROR_CODES.METADATA
  );
  await assert.rejects(
    signer({ sign: () => Buffer.alloc(63) }).signer.signCapability(input()),
    (error) => error.code === CAPABILITY_SIGNER_ERROR_CODES.OUTPUT
  );
  await assert.rejects(
    signer({ sign: () => crypto.sign(null, Buffer.from("wrong"), providerKeys.privateKey) }).signer.signCapability(input()),
    (error) => error.code === CAPABILITY_SIGNER_ERROR_CODES.VERIFICATION
  );
});

test("does not leak provider failures and converts provider timeout to a typed error", async () => {
  const secret = "private-provider-secret";
  const failed = createHostedCapabilitySigner({
    provider: {
      async publicKeyMetadata() { throw new Error(secret); },
      async sign() { return Buffer.alloc(64); }
    },
    keyId: "capability-2026-08",
    publicKey: publicKeyPem,
    now: () => NOW
  });
  await assert.rejects(failed.publicKeyMetadata(), (error) => error.code === CAPABILITY_SIGNER_ERROR_CODES.PROVIDER && !String(error).includes(secret));

  const timeout = createHostedCapabilitySigner({
    provider: provider({ delay: 50 }),
    keyId: "capability-2026-08",
    publicKey: publicKeyPem,
    timeoutMs: 5,
    now: () => NOW
  });
  await assert.rejects(timeout.publicKeyMetadata(), (error) => error.code === CAPABILITY_SIGNER_ERROR_CODES.TIMEOUT);
});

test("rejects private key input and preserves capability validation errors", async () => {
  const { signer: value } = signer();
  await assert.rejects(value.signCapability({ ...input(), private_key: providerKeys.privateKey }), (error) => error.code === CAPABILITY_SIGNER_ERROR_CODES.INPUT);
  await assert.rejects(value.signCapability({ ...input(), sequence: 0 }), (error) => error.reason === "invalid_sequence");
  await assert.rejects(value.signCapability({ ...input(), expires_at: "2026-08-15T10:15:00Z" }), (error) => error.reason === "invalid_timestamp");
});

test("rejects invalid configuration and never accepts a private public-key pin", () => {
  assert.throws(() => parseCapabilitySignerConfig({ keyId: "bad key", publicKey: publicKeyPem }), { code: CAPABILITY_SIGNER_ERROR_CODES.CONFIG });
  assert.throws(() => parseCapabilitySignerConfig({ keyId: "capability-2026-08", publicKey: providerKeys.privateKey }), { code: CAPABILITY_SIGNER_ERROR_CODES.CONFIG });
  assert.throws(() => createHostedCapabilitySigner({ provider: {}, keyId: "capability-2026-08", publicKey: publicKeyPem }), { code: CAPABILITY_SIGNER_ERROR_CODES.CONFIG });
  assert.equal(new CapabilitySignerError(CAPABILITY_SIGNER_ERROR_CODES.CONFIG).code, CAPABILITY_SIGNER_ERROR_CODES.CONFIG);
});

test("local compatibility adapter signs asynchronously without exposing its private key", async () => {
  const value = createLocalCapabilitySigner({
    privateKey: providerKeys.privateKey,
    keyId: "capability-2026-08",
    now: () => NOW
  });
  const result = await value.signCapability(input());
  assert.equal(crypto.verify(null, Buffer.from(canonicalCapability(result)), providerKeys.publicKey, Buffer.from(result.signature, "base64")), true);
  assert.equal(JSON.stringify(value).includes("PRIVATE KEY"), false);
  assert.equal(Object.hasOwn(value, "provider"), false);
});
