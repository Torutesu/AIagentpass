import assert from "node:assert/strict";
import test from "node:test";

import {
  classifyManagedSignerFailure,
  createManagedSignerReliabilityProvider,
  MANAGED_SIGNER_RELIABILITY_ERROR_CODES as CODES
} from "../src/managed-signer-reliability.mjs";

function fakeSigner(sign, overrides = {}) {
  return {
    key_id: "logical-key",
    purpose: "test-purpose",
    algorithm: "ed25519",
    version: 1,
    public_key_fingerprint: "a".repeat(64),
    async publicKeyMetadata() { return { ok: true }; },
    sign,
    ...overrides
  };
}

function clock(start = 1_900_000_000_000) {
  let value = start;
  return { now: () => value, advance: (delta) => { value += delta; } };
}

test("classifies timeout, provider, and provider-neutral throttle signals without exposing input", () => {
  assert.deepEqual(classifyManagedSignerFailure({ code: "ERR_REMOTE_KMS_TIMEOUT" }).category, "timeout");
  assert.deepEqual(classifyManagedSignerFailure({ code: "ERR_REMOTE_KMS_PROVIDER" }).category, "provider");
  assert.deepEqual(classifyManagedSignerFailure({ statusCode: 429, message: "secret provider detail" }).category, "throttle");
  assert.deepEqual(classifyManagedSignerFailure({ code: "RESOURCE_EXHAUSTED" }).category, "throttle");
});

test("rejects a purpose relabel or malformed exposed signer metadata at construction", () => {
  assert.throws(
    () => createManagedSignerReliabilityProvider({ provider: fakeSigner(async () => "ok"), purpose: "other-purpose" }),
    (error) => error.code === CODES.CONFIG
  );
  for (const field of ["key_id", "algorithm", "version", "public_key_fingerprint"]) {
    const invalid = fakeSigner(async () => "ok");
    invalid[field] = field === "version" ? 0 : field === "algorithm" ? "rsa" : undefined;
    assert.throws(
      () => createManagedSignerReliabilityProvider({ provider: invalid, purpose: "test-purpose" }),
      (error) => error.code === CODES.CONFIG,
      field
    );
  }
});

test("sanitizes timeout and provider failures and opens after the bounded threshold", async () => {
  const time = clock();
  let calls = 0;
  const provider = createManagedSignerReliabilityProvider({
    provider: fakeSigner(async () => {
      calls += 1;
      if (calls === 1) throw { code: "ERR_REMOTE_KMS_TIMEOUT", message: "internal timeout detail" };
      throw new Error("provider secret");
    }),
    purpose: "test-purpose",
    failureThreshold: 2,
    cooldownMs: 100,
    clock: time.now
  });

  await assert.rejects(provider.sign({}), (error) => error.code === CODES.TIMEOUT && !error.message.includes("internal"));
  await assert.rejects(provider.sign({}), (error) => error.code === CODES.PROVIDER && !error.message.includes("secret"));
  await assert.rejects(provider.sign({}), (error) => error.code === CODES.CIRCUIT_OPEN);
  assert.equal(calls, 2);
});

test("opens on provider integrity failures while caller-side failures do not trip the circuit", async () => {
  const time = clock();
  let integrityCalls = 0;
  const integrity = createManagedSignerReliabilityProvider({
    provider: fakeSigner(async () => {
      integrityCalls += 1;
      throw { code: "ERR_REMOTE_KMS_SIGNATURE", message: "forged signature detail" };
    }),
    purpose: "test-purpose",
    failureThreshold: 1,
    cooldownMs: 100,
    clock: time.now
  });
  await assert.rejects(integrity.sign({}), (error) => error.code === CODES.PROVIDER && !error.message.includes("forged"));
  await assert.rejects(integrity.sign({}), (error) => error.code === CODES.CIRCUIT_OPEN);
  assert.equal(integrityCalls, 1);

  let callerCalls = 0;
  const caller = createManagedSignerReliabilityProvider({
    provider: fakeSigner(async () => {
      callerCalls += 1;
      throw { code: "ERR_REMOTE_KMS_PURPOSE" };
    }),
    purpose: "test-purpose",
    failureThreshold: 1,
    cooldownMs: 100,
    clock: time.now
  });
  await assert.rejects(caller.sign({}), (error) => error.code === "ERR_REMOTE_KMS_PURPOSE");
  await assert.rejects(caller.sign({}), (error) => error.code === "ERR_REMOTE_KMS_PURPOSE");
  assert.equal(caller.reliabilityState().phase, "closed");
  assert.equal(callerCalls, 2);
});

test("classifies throttling and rejects excess work without creating a queue", async () => {
  let release;
  const pending = new Promise((resolve) => { release = resolve; });
  let calls = 0;
  const provider = createManagedSignerReliabilityProvider({
    provider: fakeSigner(async () => {
      calls += 1;
      await pending;
      throw { code: "RESOURCE_EXHAUSTED", message: "quota detail" };
    }),
    purpose: "test-purpose",
    maxInFlight: 1,
    clock: () => 1_900_000_000_000
  });
  const first = provider.sign({});
  await assert.rejects(provider.sign({}), (error) => error.code === CODES.THROTTLED);
  assert.equal(calls, 1);
  release();
  await assert.rejects(first, (error) => error.code === CODES.THROTTLED && !error.message.includes("quota"));
});

test("allows exactly one half-open probe and closes only after that probe succeeds", async () => {
  const time = clock();
  let calls = 0;
  let release;
  const pending = new Promise((resolve) => { release = resolve; });
  const provider = createManagedSignerReliabilityProvider({
    provider: fakeSigner(async () => {
      calls += 1;
      if (calls === 1) throw { code: "ERR_REMOTE_KMS_PROVIDER" };
      if (calls === 2) return pending;
      return "ok";
    }),
    purpose: "test-purpose",
    failureThreshold: 1,
    cooldownMs: 10,
    clock: time.now
  });

  await assert.rejects(provider.sign({}), (error) => error.code === CODES.PROVIDER);
  time.advance(10);
  const probe = provider.sign({});
  await assert.rejects(provider.sign({}), (error) => error.code === CODES.THROTTLED);
  assert.equal(provider.reliabilityState().phase, "half-open");
  release();
  await assert.doesNotReject(probe);
  assert.equal(provider.reliabilityState().phase, "closed");
  assert.equal(provider.reliabilityState().consecutive_failures, 0);
  await assert.doesNotReject(provider.sign({}));
  assert.equal(calls, 3);
});

test("reopens after a failed half-open probe and permits recovery only after a later successful probe", async () => {
  const time = clock();
  let calls = 0;
  const provider = createManagedSignerReliabilityProvider({
    provider: fakeSigner(async () => {
      calls += 1;
      if (calls < 3) throw { code: "ERR_REMOTE_KMS_PROVIDER" };
      return "ok";
    }),
    purpose: "test-purpose",
    failureThreshold: 1,
    cooldownMs: 10,
    clock: time.now
  });

  await assert.rejects(provider.sign({}), (error) => error.code === CODES.PROVIDER);
  time.advance(10);
  await assert.rejects(provider.sign({}), (error) => error.code === CODES.PROVIDER);
  assert.equal(provider.reliabilityState().phase, "open");
  await assert.rejects(provider.sign({}), (error) => error.code === CODES.CIRCUIT_OPEN);
  time.advance(10);
  await assert.doesNotReject(provider.sign({}));
  assert.equal(provider.reliabilityState().phase, "closed");
  assert.equal(calls, 3);
});

test("keeps circuits isolated by purpose", async () => {
  const time = clock();
  let firstCalls = 0;
  const first = createManagedSignerReliabilityProvider({
    provider: fakeSigner(async () => { firstCalls += 1; throw { code: "ERR_REMOTE_KMS_PROVIDER" }; }, { purpose: "agentpass.agent-session-grant" }),
    purpose: "agentpass.agent-session-grant",
    failureThreshold: 1,
    cooldownMs: 100,
    clock: time.now
  });
  let secondCalls = 0;
  const second = createManagedSignerReliabilityProvider({
    provider: fakeSigner(async () => { secondCalls += 1; return "manifest"; }, { purpose: "agentpass.qualification-grant-batch-manifest" }),
    purpose: "agentpass.qualification-grant-batch-manifest",
    failureThreshold: 1,
    cooldownMs: 100,
    clock: time.now
  });

  await assert.rejects(first.sign({}), (error) => error.code === CODES.PROVIDER);
  await assert.doesNotReject(second.sign({}));
  await assert.rejects(first.sign({}), (error) => error.code === CODES.CIRCUIT_OPEN);
  assert.equal(firstCalls, 1);
  assert.equal(secondCalls, 1);
  assert.equal(second.reliabilityState().phase, "closed");
});
