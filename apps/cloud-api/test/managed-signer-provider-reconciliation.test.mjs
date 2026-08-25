import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import {
  createDurableManagedSignerProvider,
  DURABLE_MANAGED_SIGNER_ERROR_CODES as SIGNER_CODES
} from "../src/durable-managed-signer-provider.mjs";
import {
  canonicalManagedSignerRequestDigest,
  MANAGED_SIGNER_KEY_LIFECYCLE_REPOSITORY_ERROR_CODES as REPOSITORY_CODES
} from "../src/postgres/managed-signer-key-lifecycle-repository.mjs";

const PURPOSE = "agentpass.agent-session-grant";
const KEY_ID = "reconciliation-key";
const KEY_VERSION = 1;

function createSharedFixture({ lookupState = "committed", lookupSignature = undefined } = {}) {
  const pair = crypto.generateKeyPairSync("ed25519");
  const shared = new Map();
  const calls = [];
  let providerAccepted = false;
  let signCalls = 0;
  let lookupCalls = 0;

  function repository() {
    return {
      async snapshot() {
        return {
          version: 1,
          purpose: PURPOSE,
          algorithm: "ed25519",
          keys: [{
            key_id: KEY_ID,
            key_version: KEY_VERSION,
            purpose: PURPOSE,
            algorithm: "ed25519",
            public_key_fingerprint: crypto.createHash("sha256").update(pair.publicKey.export({ type: "spki", format: "der" })).digest("hex"),
            state: "active",
            state_version: 1
          }]
        };
      },
      async reserveSignature(input) {
        let row = shared.get(input.operation_id);
        if (row && (row.request_digest !== input.request_digest || row.key_id !== input.key_id || row.key_version !== input.key_version)) {
          throw Object.assign(new Error("binding conflict"), { code: REPOSITORY_CODES.SIGNING_CONFLICT });
        }
        if (row?.status === "committed") return cloneRow(row);
        if (row?.status === "uncertain") throw Object.assign(new Error("uncertain"), { code: REPOSITORY_CODES.SIGNING_UNCERTAIN });
        if (row?.status === "pending") throw Object.assign(new Error("pending"), { code: REPOSITORY_CODES.SIGNING_PENDING });
        row = { ...input, status: "pending", claim_token: `claim-${shared.size + 1}` };
        shared.set(input.operation_id, row);
        calls.push("reserve");
        return cloneRow(row);
      },
      async startSignature(input) {
        const row = shared.get(input.operation_id);
        if (!row || row.status !== "pending" || row.claim_token !== input.claim_token) throw Object.assign(new Error("claim lost"), { code: REPOSITORY_CODES.SIGNING_CLAIM_LOST });
        row.provider_started_at = "2026-08-15T00:00:00.000Z";
        calls.push("start");
        return cloneRow(row);
      },
      async fenceSignature(input) {
        const row = shared.get(input.operation_id);
        if (!row || row.status !== "pending" || row.claim_token !== input.claim_token) throw Object.assign(new Error("claim lost"), { code: REPOSITORY_CODES.SIGNING_CLAIM_LOST });
        return cloneRow(row);
      },
      async commitSignature(input) {
        const row = shared.get(input.operation_id);
        if (!row || row.status !== "pending" || row.claim_token !== input.claim_token) throw Object.assign(new Error("claim lost"), { code: REPOSITORY_CODES.SIGNING_CLAIM_LOST });
        row.status = "committed";
        row.signature = Buffer.from(input.signature);
        row.provider_receipt = input.provider_receipt;
        calls.push("commit");
        return cloneRow(row);
      },
      async reconcileSignature(input) {
        const row = shared.get(input.operation_id);
        if (!row || row.status !== "uncertain") throw Object.assign(new Error("reconcile state"), { code: REPOSITORY_CODES.SIGNING_CONFLICT });
        if (row.request_digest !== input.request_digest || row.key_id !== input.key_id || row.key_version !== input.key_version) throw Object.assign(new Error("reconcile binding"), { code: REPOSITORY_CODES.SIGNING_CONFLICT });
        row.status = "committed";
        row.signature = Buffer.from(input.signature);
        row.provider_receipt = input.provider_receipt;
        calls.push("reconcile");
        return cloneRow(row);
      },
      async markSignatureUncertain(input) {
        const row = shared.get(input.operation_id);
        if (!row || row.status !== "pending") throw Object.assign(new Error("claim lost"), { code: REPOSITORY_CODES.SIGNING_CLAIM_LOST });
        row.status = "uncertain";
        calls.push("uncertain");
        return cloneRow(row);
      }
    };
  }

  const provider = {
    async publicKeyMetadata() {
      return { key_id: KEY_ID, algorithm: "ed25519", public_key: pair.publicKey };
    }
  };
  const adapter = {
    async signOnce(binding, bytes) {
      signCalls += 1;
      calls.push("signOnce");
      assert.equal(binding.operation_id.startsWith("managed-signer-v1-"), true);
      assert.equal(binding.purpose, PURPOSE);
      assert.equal(binding.key_id, KEY_ID);
      assert.equal(binding.key_version, String(KEY_VERSION));
      assert.equal(binding.request_digest.value, crypto.createHash("sha256").update(bytes).digest("hex"));
      providerAccepted = true;
      throw new Error("provider response lost after acceptance");
    },
    async lookup(binding, bytes) {
      lookupCalls += 1;
      calls.push("lookup");
      if (lookupState !== "committed") return { state: lookupState };
      const signature = lookupSignature ?? crypto.sign(null, bytes, pair.privateKey);
      return {
        state: "committed",
        provider_receipt: {
          provider: "fixture-kms",
          receipt_id: "receipt-001",
          operation_id: binding.operation_id,
          key_id: binding.key_id,
          key_version: binding.key_version
        },
        signature: {
          algorithm: "ed25519",
          encoding: "base64url",
          value: Buffer.from(signature).toString("base64url"),
          public_key: {
            algorithm: "ed25519",
            encoding: "base64url",
            value: pair.publicKey.export({ type: "spki", format: "der" }).toString("base64url")
          }
        }
      };
    }
  };

  const request = {
    algorithm: "ed25519",
    bytes: Buffer.from("response-loss-payload"),
    key_id: KEY_ID,
    purpose: PURPOSE,
    version: 1
  };
  const requestDigest = canonicalManagedSignerRequestDigest({
    algorithm: request.algorithm,
    bytes: request.bytes,
    key_id: request.key_id,
    purpose: request.purpose,
    version: request.version,
    key_version: KEY_VERSION
  });
  const makeSigner = () => createDurableManagedSignerProvider({
    provider,
    managedSignerAdapter: adapter,
    repository: repository(),
    purpose: PURPOSE,
    keyId: KEY_ID,
    keyVersion: KEY_VERSION,
    version: 1
  });
  return { adapter, calls, makeSigner, pair, request, requestDigest, providerAccepted: () => providerAccepted, counts: () => ({ signCalls, lookupCalls }), shared };
}

function cloneRow(row) {
  return row ? {
    ...row,
    state: row.status,
    ...(row.signature === undefined ? {} : { signature: Buffer.from(row.signature) }),
    ...(row.provider_receipt === undefined ? {} : { provider_receipt: { ...row.provider_receipt } })
  } : row;
}

test("marks the provider boundary before signOnce and converges response loss through lookup across repository instances", async () => {
  const fixture = createSharedFixture();
  const first = fixture.makeSigner();
  const second = fixture.makeSigner();

  await assert.rejects(first.sign(fixture.request), { code: SIGNER_CODES.PROVIDER });
  assert.deepEqual(fixture.calls.slice(0, 4), ["reserve", "start", "signOnce", "uncertain"]);
  assert.equal(fixture.providerAccepted(), true);

  const signature = await second.sign(fixture.request);
  assert.deepEqual(signature, crypto.sign(null, fixture.request.bytes, fixture.pair.privateKey));
  assert.equal(fixture.counts().signCalls, 1);
  assert.equal(fixture.counts().lookupCalls, 1);
  assert.equal(fixture.calls.includes("reconcile"), true);
});

test("does not blind re-sign when provider lookup is not committed", async () => {
  const fixture = createSharedFixture({ lookupState: "unknown" });
  const first = fixture.makeSigner();
  const second = fixture.makeSigner();

  await assert.rejects(first.sign(fixture.request), { code: SIGNER_CODES.PROVIDER });
  await assert.rejects(second.sign(fixture.request), { code: SIGNER_CODES.UNCERTAIN });
  assert.deepEqual(fixture.counts(), { signCalls: 1, lookupCalls: 1 });
  assert.equal(fixture.calls.includes("reconcile"), false);
});

test("rejects a lookup signature or receipt that is not bound to the exact operation", async () => {
  const wrongPair = crypto.generateKeyPairSync("ed25519");
  const fixture = createSharedFixture({ lookupSignature: crypto.sign(null, Buffer.from("wrong"), wrongPair.privateKey) });
  const first = fixture.makeSigner();
  const second = fixture.makeSigner();

  await assert.rejects(first.sign(fixture.request), { code: SIGNER_CODES.PROVIDER });
  await assert.rejects(second.sign(fixture.request), { code: SIGNER_CODES.OUTPUT });
  assert.equal(fixture.counts().signCalls, 1);
  assert.equal(fixture.calls.includes("reconcile"), false);
});
