import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";

import { canonicalJson } from "../../../packages/protocol/src/index.mjs";
import {
  AGENT_SIGNING_CAPABILITY_ERROR_CODES,
  AGENT_SIGNING_CAPABILITY_SIGNATURE_DOMAIN,
  agentSigningCapabilitySigningData,
  agentSigningCapabilityStatementHash,
  createAgentSigningCapabilitySigner,
  createLocalAgentSigningCapabilitySigner,
  normalizeAgentSigningCapabilityStatement,
  verifyAgentSigningCapability
} from "../src/agent-signing-capability.mjs";

const fixture = JSON.parse(fs.readFileSync(path.resolve(import.meta.dirname, "../../../test/fixtures/agent-signing-capability-v1.json"), "utf8"));
const statement = fixture.envelope.statement;
const now = Date.parse("2026-08-16T00:00:10.000Z");
const keys = crypto.generateKeyPairSync("ed25519");

function context(overrides = {}) {
  return {
    publicKey: keys.publicKey,
    keyId: statement.key_id,
    organizationId: statement.organization_id,
    sessionId: statement.session_id,
    deviceId: statement.device_id,
    agentId: statement.agent_id,
    sequence: statement.sequence,
    controlSequence: statement.control_sequence,
    authorityGeneration: statement.authority_generation,
    now,
    ...overrides
  };
}

test("matches the cross-language canonical statement, hash, and signing preimage", () => {
  assert.deepEqual(normalizeAgentSigningCapabilityStatement(statement), statement);
  assert.equal(canonicalJson(statement), fixture.canonical_statement);
  assert.equal(agentSigningCapabilityStatementHash(statement), fixture.statement_hash);
  assert.equal(agentSigningCapabilitySigningData(statement).toString("base64"), fixture.signed_statement_bytes_base64);
  assert.equal(agentSigningCapabilitySigningData(statement).subarray(0, Buffer.byteLength(AGENT_SIGNING_CAPABILITY_SIGNATURE_DOMAIN)).toString(), AGENT_SIGNING_CAPABILITY_SIGNATURE_DOMAIN);
});

test("signs and verifies only the exact pinned authority context", async () => {
  const signer = createLocalAgentSigningCapabilitySigner({ privateKey: keys.privateKey, keyId: statement.key_id, now: () => now });
  const envelope = await signer.signAgentSigningCapability(statement);
  assert.equal(Buffer.from(envelope.signature, "base64url").length, 64);
  assert.deepEqual(verifyAgentSigningCapability(envelope, context()), envelope);
  for (const override of [
    { organizationId: "99999999-9999-4999-8999-999999999999" },
    { sequence: statement.sequence + 1 },
    { controlSequence: statement.control_sequence + 1 },
    { authorityGeneration: statement.authority_generation + 1 },
    { keyId: "git-commit-signing-v2" }
  ]) {
    assert.throws(() => verifyAgentSigningCapability(envelope, context(override)), (error) => error.code === AGENT_SIGNING_CAPABILITY_ERROR_CODES.AUTHORITY);
  }
  assert.throws(() => verifyAgentSigningCapability(envelope, context({ now: Date.parse(statement.expires_at) })), (error) => error.code === AGENT_SIGNING_CAPABILITY_ERROR_CODES.EXPIRED);
});

test("provider receives only the domain-separated bytes and fixed public selectors", async () => {
  let observed;
  const signer = createAgentSigningCapabilitySigner({
    keyId: statement.key_id,
    now: () => now,
    provider: {
      async publicKeyMetadata(input) { return { key_id: input.key_id, algorithm: "ed25519", public_key: keys.publicKey }; },
      async sign(input) { observed = input; return crypto.sign(null, input.bytes, keys.privateKey); }
    }
  });
  await signer.signAgentSigningCapability(statement);
  assert.deepEqual(Object.keys(observed).sort(), ["algorithm", "bytes", "key_id", "purpose"]);
  assert.equal(observed.purpose, "git.commit.sign");
  assert.equal(observed.bytes.subarray(0, Buffer.byteLength(AGENT_SIGNING_CAPABILITY_SIGNATURE_DOMAIN)).toString(), AGENT_SIGNING_CAPABILITY_SIGNATURE_DOMAIN);
});

test("accepts only a canonical provider signature projection", async () => {
  const signer = createAgentSigningCapabilitySigner({
    keyId: statement.key_id,
    now: () => now,
    provider: {
      async publicKeyMetadata(input) { return { key_id: input.key_id, algorithm: "ed25519", public_key: keys.publicKey }; },
      async sign(input) { return { signature: crypto.sign(null, input.bytes, keys.privateKey).toString("base64url") }; }
    }
  });
  const envelope = await signer.signAgentSigningCapability(statement);
  assert.equal(Buffer.from(envelope.signature, "base64url").length, 64);

  const invalid = createAgentSigningCapabilitySigner({
    keyId: statement.key_id,
    now: () => now,
    provider: {
      async publicKeyMetadata(input) { return { key_id: input.key_id, algorithm: "ed25519", public_key: keys.publicKey }; },
      async sign(input) { return { signature: crypto.sign(null, input.bytes, keys.privateKey).toString("base64url"), provider_trace: "forbidden" }; }
    }
  });
  await assert.rejects(invalid.signAgentSigningCapability(statement), (error) => error.code === AGENT_SIGNING_CAPABILITY_ERROR_CODES.OUTPUT);
});

test("rejects unknown fields, authority selectors, invalid lifetime, and signature mutation", async () => {
  for (const invalid of [
    { ...statement, unknown: true },
    { ...statement, one_use: false },
    { ...statement, max_signatures: 2 },
    { ...statement, operation: "git.push.sign" },
    { ...statement, issued_at: "1970-01-01T00:00:00.000Z" },
    { ...statement, expires_at: statement.not_before },
    { ...statement, scope: { ...statement.scope, operations: ["git.commit.sign", "git.commit.sign"] } }
  ]) assert.throws(() => normalizeAgentSigningCapabilityStatement(invalid), (error) => error.code === AGENT_SIGNING_CAPABILITY_ERROR_CODES.INPUT);

  const signer = createLocalAgentSigningCapabilitySigner({ privateKey: keys.privateKey, keyId: statement.key_id, now: () => now });
  const envelope = await signer.signAgentSigningCapability(statement);
  assert.throws(() => verifyAgentSigningCapability({ ...envelope, statement_hash: "a".repeat(64) }, context()), (error) => error.code === AGENT_SIGNING_CAPABILITY_ERROR_CODES.SIGNATURE);
  assert.throws(() => verifyAgentSigningCapability({ ...envelope, signature: Buffer.alloc(64).toString("base64url") }, context()), (error) => error.code === AGENT_SIGNING_CAPABILITY_ERROR_CODES.SIGNATURE);
});
