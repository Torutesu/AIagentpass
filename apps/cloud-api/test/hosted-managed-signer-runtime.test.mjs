import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import {
  bindHostedManagedSignerProvider,
  HOSTED_MANAGED_SIGNER_RUNTIME_ERROR_CODES as CODES
} from "../src/hosted-managed-signer-runtime.mjs";
import { MANAGED_SIGNER_KEY_LIFECYCLE_REPOSITORY_ERROR_CODES as REPOSITORY_CODES } from "../src/postgres/managed-signer-key-lifecycle-repository.mjs";

const PURPOSE = "agentpass.agent-session-grant";

function fixture({ existing, metadataKeyId = "agent-key-1" } = {}) {
  const keys = crypto.generateKeyPairSync("ed25519");
  const publicKey = keys.publicKey.export({ type: "spki", format: "pem" }).toString();
  const publicKeyFingerprint = crypto.createHash("sha256").update(keys.publicKey.export({ type: "spki", format: "der" })).digest("hex");
  let snapshot = existing;
  const calls = [];
  const repository = {
    async snapshot() {
      calls.push("snapshot");
      if (!snapshot) throw Object.assign(new Error("missing"), { code: REPOSITORY_CODES.NOT_INITIALIZED });
      return snapshot;
    },
    async initialize(input) { calls.push("initialize"); snapshot = input.snapshot; return snapshot; },
    async reserveSignature() { throw new Error("not used"); },
    async commitSignature() { throw new Error("not used"); },
    async markSignatureUncertain() { throw new Error("not used"); }
  };
  const provider = {
    async publicKeyMetadata() { calls.push("metadata"); return { key_id: metadataKeyId, algorithm: "ed25519", public_key: publicKey }; },
    async sign({ bytes }) { return crypto.sign(null, bytes, keys.privateKey); }
  };
  const postgresRuntime = { createManagedSignerKeyLifecycleRepository(input) { calls.push(["repository", input]); return repository; } };
  return { calls, keys, provider, postgresRuntime, publicKey, publicKeyFingerprint, repository, get snapshot() { return snapshot; } };
}

test("initializes a missing purpose once from pinned public metadata", async () => {
  const value = fixture();
  const result = await bindHostedManagedSignerProvider({
    postgresRuntime: value.postgresRuntime,
    provider: value.provider,
    purpose: PURPOSE,
    keyId: "agent-key-1",
    publicKey: value.publicKey,
    publicKeyFingerprint: value.publicKeyFingerprint
  });
  assert.equal(result.key_version, 1);
  assert.equal(result.lifecycle.keys[0].public_key_fingerprint, value.publicKeyFingerprint);
  assert.deepEqual(value.calls.slice(0, 4), ["metadata", ["repository", { purpose: PURPOSE, algorithm: "ed25519" }], "snapshot", "initialize"]);
  assert.equal(typeof result.provider.sign, "function");
});

test("uses an existing authoritative lifecycle without overwriting it", async () => {
  const value = fixture();
  const existing = {
    version: 4,
    purpose: PURPOSE,
    algorithm: "ed25519",
    keys: [{ key_id: "agent-key-1", key_version: 4, purpose: PURPOSE, algorithm: "ed25519", public_key_fingerprint: value.publicKeyFingerprint, public_key: value.publicKey, state: "active", state_version: 2 }]
  };
  const configured = fixture({ existing });
  // The provider and pins must refer to the same key pair as the lifecycle.
  configured.provider.publicKeyMetadata = async () => ({ key_id: "agent-key-1", algorithm: "ed25519", public_key: value.publicKey });
  const result = await bindHostedManagedSignerProvider({ postgresRuntime: configured.postgresRuntime, provider: configured.provider, purpose: PURPOSE, keyId: "agent-key-1", publicKey: value.publicKey, publicKeyFingerprint: value.publicKeyFingerprint });
  assert.equal(result.key_version, 4);
  assert.equal(configured.calls.includes("initialize"), false);
});

test("fails closed for provider substitution and lifecycle disagreement", async () => {
  const substituted = fixture({ metadataKeyId: "other-key" });
  await assert.rejects(bindHostedManagedSignerProvider({ postgresRuntime: substituted.postgresRuntime, provider: substituted.provider, purpose: PURPOSE, keyId: "agent-key-1", publicKey: substituted.publicKey, publicKeyFingerprint: substituted.publicKeyFingerprint }), { code: CODES.PROVIDER });

  const value = fixture();
  const existing = { version: 1, purpose: PURPOSE, algorithm: "ed25519", keys: [{ key_id: "retired-key", key_version: 1, purpose: PURPOSE, algorithm: "ed25519", public_key_fingerprint: value.publicKeyFingerprint, state: "retiring", state_version: 2 }] };
  const mismatch = fixture({ existing });
  mismatch.provider.publicKeyMetadata = async () => ({ key_id: "agent-key-1", algorithm: "ed25519", public_key: value.publicKey });
  await assert.rejects(bindHostedManagedSignerProvider({ postgresRuntime: mismatch.postgresRuntime, provider: mismatch.provider, purpose: PURPOSE, keyId: "agent-key-1", publicKey: value.publicKey, publicKeyFingerprint: value.publicKeyFingerprint }), { code: CODES.LIFECYCLE });
});

test("redacts provider and database failures", async () => {
  const value = fixture();
  value.provider.publicKeyMetadata = async () => { throw new Error("provider-secret"); };
  await assert.rejects(bindHostedManagedSignerProvider({ postgresRuntime: value.postgresRuntime, provider: value.provider, purpose: PURPOSE, keyId: "agent-key-1", publicKey: value.publicKey, publicKeyFingerprint: value.publicKeyFingerprint }), (error) => error.code === CODES.PROVIDER && !error.message.includes("provider-secret"));

  const unavailable = fixture();
  unavailable.postgresRuntime.createManagedSignerKeyLifecycleRepository = () => { throw new Error("database-secret"); };
  await assert.rejects(bindHostedManagedSignerProvider({ postgresRuntime: unavailable.postgresRuntime, provider: unavailable.provider, purpose: PURPOSE, keyId: "agent-key-1", publicKey: unavailable.publicKey, publicKeyFingerprint: unavailable.publicKeyFingerprint }), (error) => error.code === CODES.DATABASE && !error.message.includes("database-secret"));
});
