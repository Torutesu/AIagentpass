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

function makeFixture({ reserveState = undefined, sign = undefined, metadata = undefined, publicKey = undefined, repository = {} } = {}) {
  const pair = crypto.generateKeyPairSync("ed25519");
  const calls = {
    metadata: [],
    sign: [],
    reserve: [],
    start: [],
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
      return { state: "pending", claim_token: "test-claim-token" };
    },
    async startSignature(input) {
      calls.start.push(input);
      if (repository.startSignature) return repository.startSignature(input, calls);
      return { state: "pending", provider_started_at: "2026-08-15T00:00:00.000Z" };
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
      ...(publicKey === undefined ? {} : { publicKey }),
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

function makeContractFixture({ signOnce, lookup, initialState = undefined } = {}) {
  const purpose = "agentpass.agent-session-grant";
  const keyId = "contract-test-key";
  const keyVersion = 1;
  const pair = crypto.generateKeyPairSync("ed25519");
  const state = { status: initialState, signature: undefined, provider_receipt: undefined };
  const calls = [];
  const provider = {
    async publicKeyMetadata() {
      calls.push("metadata");
      return { key_id: keyId, algorithm: "ed25519", public_key: pair.publicKey };
    }
  };
  const adapter = {
    async signOnce(binding, bytes) {
      calls.push("signOnce");
      if (signOnce) return signOnce(binding, bytes, pair);
      return {
        provider_receipt: {
          provider: "fixture-kms",
          receipt_id: "receipt-1",
          operation_id: binding.operation_id,
          key_id: binding.key_id,
          key_version: binding.key_version
        },
        signature: {
          algorithm: "ed25519",
          encoding: "base64url",
          value: crypto.sign(null, bytes, pair.privateKey).toString("base64url"),
          public_key: {
            algorithm: "ed25519",
            encoding: "base64url",
            value: pair.publicKey.export({ type: "spki", format: "der" }).toString("base64url")
          }
        }
      };
    },
    async lookup(binding, bytes) {
      calls.push("lookup");
      if (lookup) return lookup(binding, bytes, pair);
      return {
        state: "committed",
        provider_receipt: {
          provider: "fixture-kms",
          receipt_id: "receipt-1",
          operation_id: binding.operation_id,
          key_id: binding.key_id,
          key_version: binding.key_version
        },
        signature: {
          algorithm: "ed25519",
          encoding: "base64url",
          value: crypto.sign(null, bytes, pair.privateKey).toString("base64url"),
          public_key: {
            algorithm: "ed25519",
            encoding: "base64url",
            value: pair.publicKey.export({ type: "spki", format: "der" }).toString("base64url")
          }
        }
      };
    }
  };
  function repository() {
    return {
      async snapshot() {
        return { version: 1, purpose, algorithm: "ed25519", keys: [{ key_id: keyId, key_version: keyVersion, purpose, algorithm: "ed25519", state: "active", state_version: 1 }] };
      },
      async reserveSignature(input) {
        if (state.status === "committed") return { state: "committed", signature: Buffer.from(state.signature), ...(state.provider_receipt === undefined ? {} : { provider_receipt: { ...state.provider_receipt } }) };
        if (state.status === "uncertain") throw Object.assign(new Error("uncertain"), { code: REPOSITORY_CODES.SIGNING_UNCERTAIN });
        if (state.status === "pending") throw Object.assign(new Error("pending"), { code: REPOSITORY_CODES.SIGNING_PENDING });
        state.status = "pending";
        state.input = input;
        return { state: "pending", claim_token: "contract-claim-token" };
      },
      async startSignature(input) {
        if (state.status !== "pending" || input.claim_token !== "contract-claim-token") throw Object.assign(new Error("claim lost"), { code: REPOSITORY_CODES.SIGNING_CLAIM_LOST });
        calls.push("start");
        return { state: "pending", provider_started_at: "2026-08-15T00:00:00.000Z" };
      },
      async commitSignature(input) {
        state.status = "committed";
        state.signature = Buffer.from(input.signature);
        state.provider_receipt = { ...input.provider_receipt };
        calls.push("commit");
        return { state: "committed", signature: Buffer.from(state.signature), provider_receipt: { ...state.provider_receipt } };
      },
      async reconcileSignature(input) {
        if (state.status !== "uncertain") throw Object.assign(new Error("not uncertain"), { code: REPOSITORY_CODES.SIGNING_CONFLICT });
        state.status = "committed";
        state.signature = Buffer.from(input.signature);
        state.provider_receipt = { ...input.provider_receipt };
        calls.push("reconcile");
        return { state: "committed", signature: Buffer.from(state.signature), provider_receipt: { ...state.provider_receipt } };
      },
      async markSignatureUncertain() {
        state.status = "uncertain";
        calls.push("uncertain");
        return { state: "uncertain" };
      }
    };
  }
  const makeSigner = () => createDurableManagedSignerProvider({ provider, managedSignerAdapter: adapter, repository: repository(), purpose, keyId, keyVersion, version: 1 });
  return { adapter, calls, makeSigner, pair, state, request: { algorithm: "ed25519", bytes: Buffer.from("contract payload"), key_id: keyId, purpose, version: 1 } };
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
  assert.equal(fixture.calls.start.length, 1);
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
  assert.equal(fixture.calls.start.length, 1);
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
  assert.equal(fixture.calls.start[0].claim_token, "test-claim-token");
  assert.equal(fixture.calls.commit[0].claim_token, "test-claim-token");
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

test("never replaces the startup-pinned verification key with later provider metadata", async () => {
  const expected = crypto.generateKeyPairSync("ed25519");
  const substituted = crypto.generateKeyPairSync("ed25519");
  const fixture = makeFixture({
    publicKey: expected.publicKey,
    metadata: { key_id: KEY_ID, algorithm: "ed25519", public_key: substituted.publicKey }
  });
  await rejectsWithCode(() => fixture.signer.publicKeyMetadata(), CODES.METADATA);
  assert.equal(fixture.calls.reserve.length, 0);
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

test("commits and replays a validated provider receipt without a second signOnce", async () => {
  const fixture = makeContractFixture();
  const signer = fixture.makeSigner();
  const first = await signer.sign(fixture.request);
  const second = await signer.sign({ ...fixture.request, bytes: Buffer.from(fixture.request.bytes) });

  assert.deepEqual(second, first);
  assert.equal(fixture.calls.filter((call) => call === "signOnce").length, 1);
  assert.equal(fixture.calls.filter((call) => call === "commit").length, 1);
  assert.equal(fixture.state.provider_receipt.provider, "fixture-kms");
  assert.equal(fixture.state.provider_receipt.receipt_id, "receipt-1");
});

test("records the boundary before signOnce and reconciles response loss through lookup on a second repository instance", async () => {
  const fixture = makeContractFixture({
    signOnce: async () => { throw new Error("response lost after provider acceptance"); }
  });
  const first = fixture.makeSigner();
  const second = fixture.makeSigner();

  await rejectsWithCode(() => first.sign(fixture.request), CODES.PROVIDER);
  assert.equal(fixture.calls.indexOf("start") < fixture.calls.indexOf("signOnce"), true);
  assert.equal(fixture.state.status, "uncertain");
  const reconciled = await second.sign(fixture.request);
  assert.deepEqual(reconciled, crypto.sign(null, fixture.request.bytes, fixture.pair.privateKey));
  assert.equal(fixture.calls.filter((call) => call === "signOnce").length, 1);
  assert.equal(fixture.calls.filter((call) => call === "lookup").length, 1);
  assert.equal(fixture.calls.filter((call) => call === "reconcile").length, 1);
});

test("keeps accepted, unknown, and rejected lookups uncertain without a blind re-sign", async () => {
  for (const state of ["accepted", "unknown", "rejected"]) {
    const fixture = makeContractFixture({
      signOnce: async () => { throw new Error("provider response lost"); },
      lookup: async (binding) => state === "accepted"
        ? { state, provider_receipt: { provider: "fixture-kms", receipt_id: "receipt-1", operation_id: binding.operation_id, key_id: binding.key_id, key_version: binding.key_version } }
        : { state }
    });
    await rejectsWithCode(() => fixture.makeSigner().sign(fixture.request), CODES.PROVIDER);
    await rejectsWithCode(() => fixture.makeSigner().sign(fixture.request), CODES.UNCERTAIN);
    assert.equal(fixture.calls.filter((call) => call === "signOnce").length, 1);
    assert.equal(fixture.calls.filter((call) => call === "lookup").length, 1);
    assert.equal(fixture.calls.includes("reconcile"), false);
  }
});

test("rejects forged lookup signatures and wrong receipt bindings before reconciliation", async () => {
  const wrongPair = crypto.generateKeyPairSync("ed25519");
  const forged = makeContractFixture({
    signOnce: async () => { throw new Error("response lost"); },
    lookup: async (binding, bytes) => ({
      state: "committed",
      provider_receipt: { provider: "fixture-kms", receipt_id: "receipt-1", operation_id: binding.operation_id, key_id: binding.key_id, key_version: binding.key_version },
      signature: {
        algorithm: "ed25519", encoding: "base64url",
        value: crypto.sign(null, bytes, wrongPair.privateKey).toString("base64url"),
        public_key: { algorithm: "ed25519", encoding: "base64url", value: wrongPair.publicKey.export({ type: "spki", format: "der" }).toString("base64url") }
      }
    })
  });
  await rejectsWithCode(() => forged.makeSigner().sign(forged.request), CODES.PROVIDER);
  await rejectsWithCode(() => forged.makeSigner().sign(forged.request), CODES.OUTPUT);
  assert.equal(forged.calls.includes("reconcile"), false);

  const wrongReceipt = makeContractFixture({
    signOnce: async () => { throw new Error("response lost"); },
    lookup: async (binding, bytes, pair) => ({
      state: "committed",
      provider_receipt: { provider: "fixture-kms", receipt_id: "receipt-1", operation_id: "other-operation", key_id: binding.key_id, key_version: binding.key_version },
      signature: {
        algorithm: "ed25519", encoding: "base64url",
        value: crypto.sign(null, bytes, pair.privateKey).toString("base64url"),
        public_key: { algorithm: "ed25519", encoding: "base64url", value: pair.publicKey.export({ type: "spki", format: "der" }).toString("base64url") }
      }
    })
  });
  await rejectsWithCode(() => wrongReceipt.makeSigner().sign(wrongReceipt.request), CODES.PROVIDER);
  await rejectsWithCode(() => wrongReceipt.makeSigner().sign(wrongReceipt.request), CODES.OUTPUT);
  assert.equal(wrongReceipt.calls.includes("reconcile"), false);
});

test("fails closed for a committed row that has no provider receipt", async () => {
  const fixture = makeContractFixture({ initialState: "committed" });
  fixture.state.signature = crypto.sign(null, fixture.request.bytes, fixture.pair.privateKey);
  fixture.state.provider_receipt = undefined;
  await rejectsWithCode(() => fixture.makeSigner().sign(fixture.request), CODES.COMMIT);
  assert.equal(fixture.calls.includes("signOnce"), false);
  assert.equal(fixture.calls.includes("lookup"), false);
});
