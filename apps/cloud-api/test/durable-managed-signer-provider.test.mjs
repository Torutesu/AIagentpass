import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import {
  createDurableManagedSignerProvider,
  DURABLE_MANAGED_SIGNER_ERROR_CODES as CODES
} from "../src/durable-managed-signer-provider.mjs";
import {
  canonicalManagedSignerRequestDigest,
  MANAGED_SIGNER_KEY_LIFECYCLE_REPOSITORY_ERROR_CODES as REPOSITORY_CODES
} from "../src/postgres/managed-signer-key-lifecycle-repository.mjs";

const PURPOSE = "agentpass.test-signing";
const KEY_ID = "test-key-2026-08";
const KEY_VERSION = 7;
const SIGNING_VERSION = 3;

function makeFixture({ reserveState = undefined, sign = undefined, metadata = undefined, repository = {} } = {}) {
  const pair = crypto.generateKeyPairSync("ed25519");
  const calls = {
    metadata: [],
    sign: [],
    reserve: [],
    commit: [],
    uncertain: []
  };
  const state = { status: reserveState, signature: undefined };
  const provider = {
    async publicKeyMetadata(request) {
      calls.metadata.push(request);
      if (metadata instanceof Error) throw metadata;
      return metadata ?? {
        key_id: KEY_ID,
        algorithm: "ed25519",
        public_key: pair.publicKey
      };
    },
    async sign(request) {
      calls.sign.push(request);
      if (sign) return sign(request, calls, pair);
      return crypto.sign(null, request.bytes, pair.privateKey);
    }
  };
  const durableRepository = {
    async snapshot() {
      if (repository.snapshot) return repository.snapshot(calls);
      return { version: KEY_VERSION, purpose: PURPOSE, algorithm: "ed25519", keys: [{ key_id: KEY_ID, key_version: KEY_VERSION, purpose: PURPOSE, algorithm: "ed25519", public_key_fingerprint: "a".repeat(64), state: "active", state_version: 1 }] };
    },
    async reserveSignature(input) {
      calls.reserve.push(input);
      if (repository.reserveSignature) return repository.reserveSignature(input, calls);
      if (state.status === "pending" || state.status === "uncertain") {
        const code = state.status === "pending" ? REPOSITORY_CODES.SIGNING_PENDING : REPOSITORY_CODES.SIGNING_UNCERTAIN;
        throw Object.assign(new Error("repository secret"), { code });
      }
      if (state.status === "committed") return { state: "committed", signature: Buffer.from(state.signature) };
      state.status = "pending";
      return { state: "pending" };
    },
    async commitSignature(input) {
      calls.commit.push(input);
      if (repository.commitSignature) return repository.commitSignature(input, calls);
      state.status = "committed";
      state.signature = Buffer.from(input.signature);
      return { state: "committed", signature: Buffer.from(input.signature) };
    },
    async markSignatureUncertain(input) {
      calls.uncertain.push(input);
      if (repository.markSignatureUncertain) return repository.markSignatureUncertain(input, calls);
      state.status = "uncertain";
      return { state: "uncertain" };
    }
  };
  return {
    pair,
    calls,
    state,
    provider,
    repository: durableRepository,
    signer: createDurableManagedSignerProvider({
      provider,
      repository: durableRepository,
      purpose: PURPOSE,
      keyId: KEY_ID,
      keyVersion: KEY_VERSION,
      version: SIGNING_VERSION
    })
  };
}

function request(bytes = Buffer.from("commit payload"), overrides = {}) {
  return {
    algorithm: "ed25519",
    bytes,
    key_id: KEY_ID,
    purpose: PURPOSE,
    version: SIGNING_VERSION,
    ...overrides
  };
}

async function rejectsWithCode(action, code) {
  await assert.rejects(action, (error) => error?.code === code);
}

test("commits once and replays the exact durable signature without calling the provider", async () => {
  const fixture = makeFixture();
  const first = await fixture.signer.sign(request());
  const second = await fixture.signer.sign(request(Buffer.from("commit payload")));
  const expected = crypto.sign(null, Buffer.from("commit payload"), fixture.pair.privateKey);

  assert.deepEqual(first, expected);
  assert.deepEqual(second, expected);
  assert.equal(fixture.calls.sign.length, 1);
  assert.equal(fixture.calls.reserve.length, 2);
  assert.equal(fixture.calls.commit.length, 1);
  assert.equal(fixture.calls.reserve[0].operation_id, fixture.calls.reserve[1].operation_id);
  assert.equal(fixture.calls.reserve[0].request_digest, fixture.calls.reserve[1].request_digest);
  const expectedDigest = canonicalManagedSignerRequestDigest({
    algorithm: "ed25519",
    bytes: Buffer.from("commit payload"),
    key_id: KEY_ID,
    purpose: PURPOSE,
    version: SIGNING_VERSION,
    key_version: KEY_VERSION
  });
  assert.equal(fixture.calls.reserve[0].request_digest, expectedDigest);
  assert.equal(fixture.calls.reserve[0].operation_id, `managed-signer-v1-${expectedDigest}`);
  assert.equal(Object.hasOwn(fixture.calls.reserve[0], "signal"), false);
});

test("collapses same-process concurrent identical requests into one provider call", async () => {
  let release;
  const gate = new Promise((resolve) => { release = resolve; });
  const fixture = makeFixture({
    sign: async ({ bytes }, calls, pair) => {
      await gate;
      return crypto.sign(null, bytes, pair.privateKey);
    }
  });
  const first = fixture.signer.sign(request());
  const second = fixture.signer.sign(request(Buffer.from("commit payload"), { signal: new AbortController().signal }));
  assert.strictEqual(first, second);
  release();
  await Promise.all([first, second]);
  assert.equal(fixture.calls.reserve.length, 1);
  assert.equal(fixture.calls.sign.length, 1);
  assert.equal(fixture.calls.commit.length, 1);
});

test("rejects payload substitution and unknown fields before durable or provider calls", async () => {
  const fixture = makeFixture();
  const substitutions = [
    [{ ...request(), key_id: "other-key" }, CODES.BINDING],
    [{ ...request(), purpose: "other-purpose" }, CODES.BINDING],
    [{ ...request(), algorithm: "rsa" }, CODES.BINDING],
    [{ ...request(), version: SIGNING_VERSION + 1 }, CODES.BINDING],
    [{ ...request(), bytes: "secret payload" }, CODES.INPUT],
    [{ ...request(), unexpected: "field" }, CODES.INPUT],
    [{ ...request(), signal: "not-an-abort-signal" }, CODES.INPUT]
  ];
  for (const [input, code] of substitutions) await rejectsWithCode(async () => fixture.signer.sign(input), code);
  assert.equal(fixture.calls.reserve.length, 0);
  assert.equal(fixture.calls.sign.length, 0);
});

test("passes AbortSignal only to the provider and keeps it out of the durable binding", async () => {
  const fixture = makeFixture();
  const controller = new AbortController();
  await fixture.signer.sign(request(Buffer.from("signal payload"), { signal: controller.signal }));
  assert.strictEqual(fixture.calls.sign[0].signal, controller.signal);
  assert.equal(Object.hasOwn(fixture.calls.reserve[0], "signal"), false);
  assert.equal(Object.hasOwn(fixture.calls.commit[0], "signal"), false);
  assert.deepEqual(Object.keys(fixture.calls.sign[0]).sort(), ["algorithm", "bytes", "key_id", "purpose", "signal", "version"]);
});

test("marks a provider failure uncertain and never retries the provider", async () => {
  const fixture = makeFixture({ sign: async () => { throw new Error("KMS private secret"); } });
  await rejectsWithCode(() => fixture.signer.sign(request()), CODES.PROVIDER);
  assert.equal(fixture.calls.sign.length, 1);
  assert.equal(fixture.calls.commit.length, 0);
  assert.equal(fixture.calls.uncertain.length, 1);
  await rejectsWithCode(() => fixture.signer.sign(request()), CODES.UNCERTAIN);
  assert.equal(fixture.calls.sign.length, 1);
});

test("marks a commit failure uncertain and fails closed", async () => {
  const fixture = makeFixture({
    repository: {
      commitSignature: async () => { throw new Error("database password secret"); }
    }
  });
  await rejectsWithCode(() => fixture.signer.sign(request()), CODES.COMMIT);
  assert.equal(fixture.calls.sign.length, 1);
  assert.equal(fixture.calls.commit.length, 1);
  assert.equal(fixture.calls.uncertain.length, 1);
  await rejectsWithCode(() => fixture.signer.sign(request()), CODES.UNCERTAIN);
  assert.equal(fixture.calls.sign.length, 1);
});

test("does not call the provider for pending, uncertain, or conflicting durable state", async () => {
  for (const [state, code] of [["pending", CODES.PENDING], ["uncertain", CODES.UNCERTAIN]]) {
    const fixture = makeFixture({ reserveState: state });
    await rejectsWithCode(() => fixture.signer.sign(request()), code);
    assert.equal(fixture.calls.sign.length, 0);
    assert.equal(fixture.calls.uncertain.length, 0);
  }
  const fixture = makeFixture({
    repository: {
      reserveSignature: async () => { throw Object.assign(new Error("binding secret"), { code: REPOSITORY_CODES.SIGNING_CONFLICT }); }
    }
  });
  await rejectsWithCode(() => fixture.signer.sign(request()), CODES.CONFLICT);
  assert.equal(fixture.calls.sign.length, 0);
  assert.equal(fixture.calls.uncertain.length, 0);
});

test("quarantines malformed provider signatures and rejects non-64-byte storage replay", async () => {
  const malformed = makeFixture({ sign: async () => Buffer.alloc(63) });
  await rejectsWithCode(() => malformed.signer.sign(request()), CODES.OUTPUT);
  assert.equal(malformed.calls.uncertain.length, 1);
  assert.equal(malformed.calls.commit.length, 0);

  const replay = makeFixture({ reserveState: "committed" });
  replay.state.signature = Buffer.alloc(63);
  await rejectsWithCode(() => replay.signer.sign(request()), CODES.OUTPUT);
  assert.equal(replay.calls.sign.length, 0);
});

test("rejects a provider signature made by a different Ed25519 key before commit", async () => {
  const wrongPair = crypto.generateKeyPairSync("ed25519");
  const fixture = makeFixture({
    sign: ({ bytes }) => crypto.sign(null, bytes, wrongPair.privateKey)
  });

  await rejectsWithCode(() => fixture.signer.sign(request()), CODES.OUTPUT);
  assert.equal(fixture.calls.sign.length, 1);
  assert.equal(fixture.calls.commit.length, 0);
  assert.equal(fixture.calls.uncertain.length, 1);
  await rejectsWithCode(() => fixture.signer.sign(request()), CODES.UNCERTAIN);
  assert.equal(fixture.calls.sign.length, 1);
});

test("rejects a random 64-byte provider result before commit", async () => {
  const fixture = makeFixture({
    sign: () => crypto.randomBytes(64)
  });

  await rejectsWithCode(() => fixture.signer.sign(request()), CODES.OUTPUT);
  assert.equal(fixture.calls.sign.length, 1);
  assert.equal(fixture.calls.commit.length, 0);
  assert.equal(fixture.calls.uncertain.length, 1);
});

test("rejects poisoned committed replay signatures without calling the provider", async () => {
  const wrongPair = crypto.generateKeyPairSync("ed25519");
  for (const poisoned of [
    crypto.randomBytes(64),
    crypto.sign(null, Buffer.from("commit payload"), wrongPair.privateKey)
  ]) {
    const fixture = makeFixture({ reserveState: "committed" });
    fixture.state.signature = poisoned;

    await rejectsWithCode(() => fixture.signer.sign(request()), CODES.OUTPUT);
    assert.equal(fixture.calls.sign.length, 0);
    assert.equal(fixture.calls.commit.length, 0);
    assert.equal(fixture.calls.uncertain.length, 0);
  }
});

test("validates metadata binding and canonicalizes only a public Ed25519 key", async () => {
  const fixture = makeFixture();
  const metadata = await fixture.signer.publicKeyMetadata();
  assert.equal(metadata.key_id, KEY_ID);
  assert.equal(metadata.algorithm, "ed25519");
  assert.match(metadata.public_key, /BEGIN PUBLIC KEY/u);
  assert.equal(fixture.calls.reserve.length, 0);
  await rejectsWithCode(() => fixture.signer.publicKeyMetadata({
    algorithm: "ed25519", key_id: "other-key", purpose: PURPOSE, version: SIGNING_VERSION
  }), CODES.BINDING);
  assert.equal(fixture.calls.metadata.length, 1);
});

test("fails readiness closed when the authoritative lifecycle is no longer active", async () => {
  const fixture = makeFixture({
    repository: {
      snapshot: async () => ({
        version: KEY_VERSION + 1,
        purpose: PURPOSE,
        algorithm: "ed25519",
        keys: [{
          key_id: KEY_ID,
          key_version: KEY_VERSION,
          purpose: PURPOSE,
          algorithm: "ed25519",
          public_key_fingerprint: "a".repeat(64),
          state: "emergency_disabled",
          state_version: 2
        }]
      })
    }
  });

  await rejectsWithCode(() => fixture.signer.publicKeyMetadata(), CODES.INACTIVE);
  assert.equal(fixture.calls.metadata.length, 0);
  assert.equal(fixture.calls.reserve.length, 0);
  assert.equal(fixture.calls.sign.length, 0);
});

test("rejects metadata key substitution, extra fields, and private key material", async () => {
  const fixture = makeFixture();
  const cases = [
    { key_id: "other-key", algorithm: "ed25519", public_key: fixture.pair.publicKey },
    { key_id: KEY_ID, algorithm: "rsa", public_key: fixture.pair.publicKey },
    { key_id: KEY_ID, algorithm: "ed25519", public_key: fixture.pair.publicKey, extra: "secret" },
    { key_id: KEY_ID, algorithm: "ed25519", public_key: fixture.pair.privateKey }
  ];
  for (const metadata of cases) {
    const value = makeFixture({ metadata });
    await rejectsWithCode(() => value.signer.publicKeyMetadata(), CODES.METADATA);
    assert.equal(value.calls.reserve.length, 0);
  }
});

test("does not expose provider or repository error details", async () => {
  const providerFailure = makeFixture({ sign: async () => { throw new Error("provider-secret-value"); } });
  await assert.rejects(providerFailure.signer.sign(request()), (error) => {
    assert.equal(error.code, CODES.PROVIDER);
    assert.doesNotMatch(error.message, /provider-secret-value/u);
    assert.doesNotMatch(error.stack, /provider-secret-value/u);
    return true;
  });

  const commitFailure = makeFixture({
    repository: { commitSignature: async () => { throw new Error("postgres-secret-value"); } }
  });
  await assert.rejects(commitFailure.signer.sign(request()), (error) => {
    assert.equal(error.code, CODES.COMMIT);
    assert.doesNotMatch(error.message, /postgres-secret-value/u);
    assert.doesNotMatch(error.stack, /postgres-secret-value/u);
    return true;
  });
});
