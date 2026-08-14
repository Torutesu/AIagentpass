import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import {
  createManagedSignerProvider,
  REQUEST_DIGEST_ALGORITHM,
  SIGNER_PROTOCOL_VERSIONS,
} from "../src/managed-signer-provider-contract.mjs";
import {
  createProviderOperationReconciliationAdapter,
  PROVIDER_OPERATION_RECONCILIATION_ERROR_CODES as CODES,
} from "../src/provider-operation-reconciliation-adapter.mjs";

const PURPOSE = "agentpass.capability";
const KEY_ID = "fixture-kms-key";
const KEY_VERSION = "7";
const PROVIDER_ID = "fixture-kms";
const PAYLOAD = Buffer.from("provider-operation-reconciliation-payload");

function digest(bytes) {
  return crypto.createHash("sha256").update(bytes).digest("hex");
}

function bindingFor(bytes = PAYLOAD, overrides = {}) {
  const value = {
    operation_id: "managed-signer-v1-provider-operation-001",
    purpose: PURPOSE,
    key_id: KEY_ID,
    key_version: KEY_VERSION,
    algorithm: "ed25519",
    protocol_version: SIGNER_PROTOCOL_VERSIONS[PURPOSE],
    request_digest: {
      algorithm: REQUEST_DIGEST_ALGORITHM,
      value: digest(bytes),
    },
    ...overrides,
  };
  return value;
}

function operationFromInput(input) {
  return {
    algorithm: input.algorithm,
    bytes_length: input.bytes_length,
    key_id: input.key_id,
    key_version: input.key_version,
    operation_id: input.operation_id,
    purpose: input.purpose,
    request_digest: input.request_digest,
  };
}

function cloneValue(value) {
  if (Buffer.isBuffer(value)) return Buffer.from(value);
  if (Array.isArray(value)) return value.map(cloneValue);
  if (value && typeof value === "object") {
    const copy = {};
    for (const [key, child] of Object.entries(value)) copy[key] = cloneValue(child);
    return copy;
  }
  return value;
}

function createRepository({
  failReserve = false,
  failRecordAcceptedOnce = false,
  failAfterRecordAccepted = false,
  failAfterCommit = false,
} = {}) {
  const rows = new Map();
  const events = [];
  const waiters = new Map();
  let claimSequence = 0;
  let recordAcceptedFailures = failRecordAcceptedOnce;
  let acceptedResponseFailure = failAfterRecordAccepted;
  let commitFailure = failAfterCommit;

  function assertIdentity(row, input) {
    for (const field of ["algorithm", "bytes_length", "key_id", "key_version", "operation_id", "purpose", "request_digest"]) {
      if (row[field] !== input[field]) throw Object.assign(new Error("operation identity conflict"), { code: "CONFLICT" });
    }
  }

  function publicRecord(row, includeClaim = false) {
    if (!row) return null;
    const result = {
      algorithm: row.algorithm,
      bytes_length: row.bytes_length,
      key_id: row.key_id,
      key_version: row.key_version,
      operation_id: row.operation_id,
      purpose: row.purpose,
      request_digest: row.request_digest,
      state: row.state,
    };
    if (includeClaim && row.lease) result.claim_token = row.claim_token;
    if (row.signature !== undefined) result.signature = cloneValue(row.signature);
    if (row.provider_receipt !== undefined) result.provider_receipt = cloneValue(row.provider_receipt);
    return Object.freeze(result);
  }

  function notify(row) {
    const pending = waiters.get(row.operation_id) ?? [];
    waiters.delete(row.operation_id);
    for (const resolve of pending) resolve(publicRecord(row));
  }

  function failRepository(message = "repository failure") {
    throw Object.assign(new Error(message), { code: "DATABASE" });
  }

  const repository = {
    async reserveOperation(input) {
      events.push("reserve");
      if (failReserve) failRepository();
      const existing = rows.get(input.operation_id);
      if (existing) {
        assertIdentity(existing, input);
        return publicRecord(existing, false);
      }
      const row = {
        ...operationFromInput(input),
        state: "pending",
        lease: true,
        claim_token: `claim-${++claimSequence}`,
      };
      rows.set(row.operation_id, row);
      return publicRecord(row, true);
    },

    async claimOperation(input) {
      events.push("claim");
      const row = rows.get(input.operation_id);
      if (!row) return null;
      assertIdentity(row, input);
      if (row.lease || !["pending", "started", "accepted", "uncertain"].includes(row.state)) {
        return publicRecord(row, false);
      }
      row.lease = true;
      row.claim_token = `claim-${++claimSequence}`;
      return publicRecord(row, true);
    },

    async startOperation(input) {
      events.push("start");
      const row = rows.get(input.operation_id);
      if (!row) failRepository("missing operation");
      assertIdentity(row, input);
      if (!row.lease || row.claim_token !== input.claim_token || !["pending", "started"].includes(row.state)) {
        failRepository("claim lost");
      }
      row.state = "started";
      notify(row);
      return publicRecord(row, true);
    },

    async recordAccepted(input) {
      events.push("accepted");
      if (recordAcceptedFailures) {
        recordAcceptedFailures = false;
        failRepository("crash after provider boundary");
      }
      const row = rows.get(input.operation_id);
      if (!row) failRepository("missing operation");
      assertIdentity(row, input);
      if (!row.lease || row.claim_token !== input.claim_token) failRepository("claim lost");
      if (!["started", "accepted", "uncertain"].includes(row.state)) failRepository("invalid state");
      row.state = "accepted";
      row.signature = cloneValue(input.signature);
      row.provider_receipt = cloneValue(input.provider_receipt);
      notify(row);
      if (acceptedResponseFailure) {
        acceptedResponseFailure = false;
        failRepository("response lost after provider result persistence");
      }
      return publicRecord(row, true);
    },

    async commitOperation(input) {
      events.push("commit");
      const row = rows.get(input.operation_id);
      if (!row) failRepository("missing operation");
      assertIdentity(row, input);
      if (row.state === "committed") return publicRecord(row);
      if (!row.lease || row.claim_token !== input.claim_token || row.state !== "accepted") failRepository("claim lost");
      row.state = "committed";
      row.lease = false;
      delete row.claim_token;
      notify(row);
      if (commitFailure) {
        commitFailure = false;
        failRepository("response lost after commit");
      }
      return publicRecord(row);
    },

    async reconcileOperation(input) {
      events.push("reconcile");
      const row = rows.get(input.operation_id);
      if (!row) failRepository("missing operation");
      assertIdentity(row, input);
      if (row.state === "committed") return publicRecord(row);
      if (!["accepted", "uncertain"].includes(row.state) || row.signature === undefined || row.provider_receipt === undefined) {
        failRepository("not recoverable");
      }
      row.state = "committed";
      row.lease = false;
      delete row.claim_token;
      notify(row);
      return publicRecord(row);
    },

    async markUncertain(input) {
      events.push("uncertain");
      const row = rows.get(input.operation_id);
      if (!row) return null;
      assertIdentity(row, input);
      if (row.state === "committed") return publicRecord(row);
      if (!row.lease || row.claim_token !== input.claim_token) return publicRecord(row);
      row.state = "uncertain";
      row.lease = false;
      delete row.claim_token;
      notify(row);
      return publicRecord(row);
    },

    async getOperation(input) {
      events.push("get");
      const row = rows.get(input.operation_id);
      if (!row) return null;
      assertIdentity(row, input);
      return publicRecord(row);
    },

    async waitForOperation({ operation, timeout_ms: timeoutMs }) {
      events.push("wait");
      const row = rows.get(operation.operation_id);
      if (!row) return null;
      assertIdentity(row, operation);
      if (!["pending", "started"].includes(row.state)) return publicRecord(row);
      return new Promise((resolve) => {
        const timeout = setTimeout(() => {
          const pending = waiters.get(operation.operation_id) ?? [];
          const index = pending.indexOf(resolveValue);
          if (index >= 0) pending.splice(index, 1);
          if (pending.length === 0) waiters.delete(operation.operation_id);
          resolve(publicRecord(row));
        }, timeoutMs);
        function resolveValue(value) {
          clearTimeout(timeout);
          resolve(value);
        }
        const pending = waiters.get(operation.operation_id) ?? [];
        pending.push(resolveValue);
        waiters.set(operation.operation_id, pending);
      });
    },
  };

  return {
    repository,
    events,
    rows,
    seed(input, state, output = {}) {
      const row = {
        ...operationFromInput(input),
        state,
        lease: false,
        ...cloneValue(output),
      };
      rows.set(row.operation_id, row);
    },
  };
}

function createProvider({ pair = crypto.generateKeyPairSync("ed25519"), sign = undefined, metadata = undefined } = {}) {
  const calls = { metadata: [], sign: [] };
  const provider = {
    purpose: PURPOSE,
    key_id: KEY_ID,
    algorithm: "ed25519",
    version: 1,
    async publicKeyMetadata(request) {
      calls.metadata.push({ ...request });
      return metadata ?? {
        algorithm: "ed25519",
        key_id: KEY_ID,
        public_key: pair.publicKey,
      };
    },
    async sign(request) {
      calls.sign.push({ ...request, bytes: Buffer.from(request.bytes) });
      if (sign) return sign(request, pair);
      return crypto.sign(null, request.bytes, pair.privateKey);
    },
  };
  return { provider, pair, calls };
}

function createAdapterFixture(repositoryOptions = {}, providerOptions = {}) {
  const repo = createRepository(repositoryOptions);
  const providerFixture = createProvider(providerOptions);
  const adapter = createProviderOperationReconciliationAdapter({
    provider: providerFixture.provider,
    providerId: PROVIDER_ID,
    repository: repo.repository,
    purpose: PURPOSE,
    keyId: KEY_ID,
    keyVersion: KEY_VERSION,
    waitTimeoutMs: 50,
  });
  return { ...repo, ...providerFixture, adapter, binding: bindingFor() };
}

test("wraps a direct Ed25519 KMS provider in the exact managed-signer adapter shape", async () => {
  const fixture = createAdapterFixture();
  assert.deepEqual(Object.keys(fixture.adapter).sort(), ["lookup", "signOnce"]);

  const managed = createManagedSignerProvider({
    binding: fixture.binding,
    adapter: fixture.adapter,
    signingBytes: PAYLOAD,
    publicKey: fixture.pair.publicKey,
  });
  const result = await managed.signOnce();
  assert.equal(result.signature.algorithm, "ed25519");
  assert.equal(result.signature.value, crypto.sign(null, PAYLOAD, fixture.pair.privateKey).toString("base64url"));
  assert.equal(result.provider_receipt.provider, PROVIDER_ID);
  assert.equal(result.provider_receipt.operation_id, fixture.binding.operation_id);
  assert.equal(result.provider_receipt.key_version, KEY_VERSION);
  assert.match(result.provider_receipt.receipt_id, /^deterministic-[0-9a-f]{64}$/u);
  assert.deepEqual(fixture.provider && fixture.calls.sign[0] && Object.keys(fixture.calls.sign[0]).sort(), [
    "algorithm", "bytes", "key_id", "purpose", "version",
  ]);
  assert.notStrictEqual(fixture.calls.sign[0].bytes, PAYLOAD);
  assert.deepEqual(fixture.events.slice(0, 4), ["reserve", "start", "accepted", "commit"]);

  const second = await managed.signOnce();
  assert.deepEqual(second, result);
  assert.equal(fixture.calls.sign.length, 1);
  assert.deepEqual(await fixture.adapter.lookup(fixture.binding, PAYLOAD), {
    state: "committed",
    provider_receipt: result.provider_receipt,
    signature: result.signature,
  });
});

test("converges response loss after commit without invoking the direct provider twice", async () => {
  const fixture = createAdapterFixture({ failAfterCommit: true });
  await assert.rejects(fixture.adapter.signOnce(fixture.binding, PAYLOAD), { code: CODES.REPOSITORY });
  const recovered = await fixture.adapter.lookup(fixture.binding, PAYLOAD);
  assert.equal(recovered.state, "committed");
  assert.equal(fixture.calls.sign.length, 1);
  assert.equal(fixture.rows.get(fixture.binding.operation_id).state, "committed");
});

test("reconciles a persisted accepted result without calling the direct provider twice", async () => {
  const fixture = createAdapterFixture({ failAfterRecordAccepted: true });
  await assert.rejects(fixture.adapter.signOnce(fixture.binding, PAYLOAD), { code: CODES.REPOSITORY });
  assert.equal(fixture.rows.get(fixture.binding.operation_id).state, "uncertain");
  assert.equal(fixture.calls.sign.length, 1);
  const recovered = await fixture.adapter.lookup(fixture.binding, PAYLOAD);
  assert.equal(recovered.state, "committed");
  assert.equal(fixture.calls.sign.length, 1);
  assert.ok(fixture.events.includes("reconcile"));
});

test("releases the in-process entry after completion and rechecks durable terminal state", async () => {
  const fixture = createAdapterFixture();
  await fixture.adapter.signOnce(fixture.binding, PAYLOAD);
  await new Promise((resolve) => setImmediate(resolve));
  const row = fixture.rows.get(fixture.binding.operation_id);
  row.state = "rejected";
  row.lease = false;
  delete row.claim_token;
  delete row.signature;
  delete row.provider_receipt;
  await assert.rejects(fixture.adapter.signOnce(fixture.binding, PAYLOAD), { code: CODES.TERMINAL });
  assert.equal(fixture.events.filter((event) => event === "reserve").length, 2);
});

test("recovers a crash after the provider boundary through deterministic retry on a second adapter instance", async () => {
  const fixture = createAdapterFixture({ failRecordAcceptedOnce: true });
  const first = fixture.adapter;
  await assert.rejects(first.signOnce(fixture.binding, PAYLOAD), { code: CODES.REPOSITORY });
  assert.equal(fixture.rows.get(fixture.binding.operation_id).state, "uncertain");

  const second = createProviderOperationReconciliationAdapter({
    provider: fixture.provider,
    providerId: PROVIDER_ID,
    repository: fixture.repository,
    purpose: PURPOSE,
    keyId: KEY_ID,
    keyVersion: KEY_VERSION,
    waitTimeoutMs: 50,
  });
  const result = await second.lookup(fixture.binding, PAYLOAD);
  assert.equal(result.state, "committed");
  assert.equal(fixture.calls.sign.length, 2);
  assert.equal(fixture.calls.sign[0].bytes.toString("hex"), fixture.calls.sign[1].bytes.toString("hex"));
  assert.equal(fixture.calls.sign[0].bytes.length, PAYLOAD.length);
  assert.equal(result.signature.value, crypto.sign(null, PAYLOAD, fixture.pair.privateKey).toString("base64url"));
  assert.equal(fixture.rows.get(fixture.binding.operation_id).state, "committed");
});

test("deduplicates two concurrent adapter instances through the durable repository claim and wait", async () => {
  const gate = {};
  gate.started = new Promise((resolve) => { gate.releaseStarted = resolve; });
  gate.release = new Promise((resolve) => { gate.releaseProvider = resolve; });
  const fixture = createAdapterFixture({}, {
    sign: async (request, pair) => {
      gate.releaseStarted();
      await gate.release;
      return crypto.sign(null, request.bytes, pair.privateKey);
    },
  });
  const second = createProviderOperationReconciliationAdapter({
    provider: fixture.provider,
    providerId: PROVIDER_ID,
    repository: fixture.repository,
    purpose: PURPOSE,
    keyId: KEY_ID,
    keyVersion: KEY_VERSION,
    waitTimeoutMs: 500,
  });
  const firstPromise = fixture.adapter.signOnce(fixture.binding, PAYLOAD);
  await gate.started;
  const secondPromise = second.signOnce(fixture.binding, PAYLOAD);
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(fixture.calls.sign.length, 1);
  gate.releaseProvider();
  const [first, secondResult] = await Promise.all([firstPromise, secondPromise]);
  assert.deepEqual(secondResult, first);
  assert.equal(fixture.calls.sign.length, 1);
  assert.ok(fixture.events.includes("wait"));
});

test("rejects a wrong provider signature and fences the operation as uncertain", async () => {
  const fixture = createAdapterFixture({}, {
    sign: () => crypto.randomBytes(64),
  });
  await assert.rejects(fixture.adapter.signOnce(fixture.binding, PAYLOAD), { code: CODES.OUTPUT });
  assert.equal(fixture.rows.get(fixture.binding.operation_id).state, "uncertain");
  assert.equal(fixture.rows.get(fixture.binding.operation_id).signature, undefined);
});

test("rejects changed bytes, key binding, and cross-purpose substitution before repository or provider use", async () => {
  const fixture = createAdapterFixture();
  await assert.rejects(fixture.adapter.signOnce(fixture.binding, Buffer.from("changed")), { code: CODES.BINDING });
  await assert.rejects(fixture.adapter.signOnce(bindingFor(PAYLOAD, { key_version: "8" }), PAYLOAD), { code: CODES.BINDING });
  await assert.rejects(fixture.adapter.signOnce(bindingFor(PAYLOAD, { purpose: "agentpass.audit-anchor" }), PAYLOAD), { code: CODES.BINDING });
  assert.deepEqual(fixture.events, []);
  assert.equal(fixture.calls.sign.length, 0);

  const wrongProvider = createProvider();
  wrongProvider.provider.purpose = "agentpass.audit-anchor";
  assert.throws(() => createProviderOperationReconciliationAdapter({
    provider: wrongProvider.provider,
    providerId: PROVIDER_ID,
    repository: fixture.repository,
    purpose: PURPOSE,
    keyId: KEY_ID,
    keyVersion: KEY_VERSION,
  }), { code: CODES.CONFIG });
});

test("returns unknown without signing and preserves rejected/failed as terminal states", async () => {
  const fixture = createAdapterFixture();
  assert.deepEqual(await fixture.adapter.lookup(fixture.binding, PAYLOAD), { state: "unknown" });
  fixture.seed({
    ...fixture.binding,
    algorithm: "ed25519",
    bytes_length: PAYLOAD.length,
    request_digest: digest(PAYLOAD),
  }, "rejected");
  assert.deepEqual(await fixture.adapter.lookup(fixture.binding, PAYLOAD), { state: "rejected" });
  await assert.rejects(fixture.adapter.signOnce(fixture.binding, PAYLOAD), { code: CODES.TERMINAL });
  assert.equal(fixture.calls.sign.length, 0);
});

test("fails closed on repository errors, oversized bytes, and private-key configuration", async () => {
  const failed = createAdapterFixture({ failReserve: true });
  await assert.rejects(failed.adapter.signOnce(failed.binding, PAYLOAD), { code: CODES.REPOSITORY });
  assert.equal(failed.calls.sign.length, 0);

  const bounded = createAdapterFixture();
  const tooLarge = Buffer.alloc(17, 0x41);
  const boundedAdapter = createProviderOperationReconciliationAdapter({
    provider: bounded.provider,
    providerId: PROVIDER_ID,
    repository: bounded.repository,
    purpose: PURPOSE,
    keyId: KEY_ID,
    keyVersion: KEY_VERSION,
    maxRequestBytes: 16,
  });
  await assert.rejects(boundedAdapter.signOnce(bindingFor(tooLarge), tooLarge), { code: CODES.INPUT });

  const privateProvider = createProvider();
  privateProvider.provider.privateKey = privateProvider.pair.privateKey;
  assert.throws(() => createProviderOperationReconciliationAdapter({
    provider: privateProvider.provider,
    providerId: PROVIDER_ID,
    repository: bounded.repository,
    purpose: PURPOSE,
    keyId: KEY_ID,
    keyVersion: KEY_VERSION,
  }), { code: CODES.CONFIG });
});

test("rejects a repository record whose immutable binding or stored signature was changed", async () => {
  const fixture = createAdapterFixture();
  const originalGet = fixture.repository.getOperation;
  fixture.repository.getOperation = async (input) => ({
    ...await originalGet(input),
    key_id: "substituted-key",
  });
  await assert.rejects(fixture.adapter.lookup(fixture.binding, PAYLOAD), { code: CODES.CONFLICT });

  const stored = createAdapterFixture();
  await stored.adapter.signOnce(stored.binding, PAYLOAD);
  const originalGetStored = stored.repository.getOperation;
  stored.repository.getOperation = async (input) => {
    const row = await originalGetStored(input);
    return {
      ...row,
      signature: {
        ...row.signature,
        value: crypto.randomBytes(64).toString("base64url"),
      },
    };
  };
  await assert.rejects(stored.adapter.lookup(stored.binding, PAYLOAD), { code: CODES.OUTPUT });
});
