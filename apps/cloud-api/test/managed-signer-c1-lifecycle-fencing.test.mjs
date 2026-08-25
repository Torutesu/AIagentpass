import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import {
  createDurableManagedSignerProvider,
  DURABLE_MANAGED_SIGNER_ERROR_CODES as SIGNER_CODES
} from "../src/durable-managed-signer-provider.mjs";
import {
  createManagedSignerKeyLifecycle,
  MANAGED_SIGNER_KEY_STATES as KEY_STATES
} from "../src/managed-signer-key-lifecycle.mjs";
import {
  MANAGED_SIGNER_KEY_LIFECYCLE_REPOSITORY_ERROR_CODES as REPOSITORY_CODES
} from "../src/postgres/managed-signer-key-lifecycle-repository.mjs";
import { createProviderOperationReconciliationAdapter } from "../src/provider-operation-reconciliation-adapter.mjs";
import { createProviderOperationRepositoryFactory } from "./support/managed-signer-repository.mjs";

const PURPOSE = "agentpass.agent-session-grant";
const KEY_ID = "c1-key-1";
const KEY_VERSION = 1;
const PROVIDER_ID = "c1-fixture-kms-ledger-v1";

function keyRecord(keyId, keyVersion, pair, state = KEY_STATES.ACTIVE, stateVersion = 1) {
  const der = pair.publicKey.export({ type: "spki", format: "der" });
  return {
    key_id: keyId,
    key_version: keyVersion,
    purpose: PURPOSE,
    algorithm: "ed25519",
    public_key: pair.publicKey.export({ type: "spki", format: "pem" }).toString(),
    public_key_fingerprint: crypto.createHash("sha256").update(der).digest("hex"),
    state,
    state_version: stateVersion
  };
}

function clone(value) {
  if (Buffer.isBuffer(value)) return Buffer.from(value);
  if (Array.isArray(value)) return value.map(clone);
  if (value && typeof value === "object") {
    const result = {};
    for (const [key, child] of Object.entries(value)) result[key] = clone(child);
    return result;
  }
  return value;
}

function error(code, message = code) {
  return Object.assign(new Error(message), { code });
}

function createFixture() {
  const firstPair = crypto.generateKeyPairSync("ed25519");
  const secondPair = crypto.generateKeyPairSync("ed25519");
  const lifecycle = createManagedSignerKeyLifecycle({
    purpose: PURPOSE,
    snapshot: {
      version: 1,
      purpose: PURPOSE,
      algorithm: "ed25519",
      keys: [keyRecord(KEY_ID, KEY_VERSION, firstPair)]
    }
  });
  const signingRecords = new Map();
  const operationRecords = new Map();
  const events = [];
  let providerCalls = 0;
  let rotated = false;

  function currentKey() {
    return lifecycle.activeKey();
  }

  function publicSigningRecord(row, includeClaim = false) {
    if (!row) return null;
    return Object.freeze({
      state: row.status,
      purpose: PURPOSE,
      operation_id: row.operation_id,
      request_digest: row.request_digest,
      key_id: row.key_id,
      key_version: row.key_version,
      reserved_lifecycle_version: row.reserved_lifecycle_version,
      ...(includeClaim ? { claim_token: row.claim_token } : {}),
      ...(row.provider_started_at === undefined ? {} : { provider_started_at: row.provider_started_at }),
      ...(row.signature === undefined ? {} : { signature: Buffer.from(row.signature) }),
      ...(row.provider_receipt === undefined ? {} : { provider_receipt: clone(row.provider_receipt) })
    });
  }

  function assertSigningIdentity(row, input) {
    if (!row || row.request_digest !== input.request_digest || row.key_id !== input.key_id || row.key_version !== input.key_version) {
      throw error(REPOSITORY_CODES.SIGNING_CONFLICT, "signing identity conflict");
    }
  }

  function assertCurrentLifecycle(row) {
    const active = currentKey();
    if (!active || active.key_id !== row.key_id || active.key_version !== row.key_version
      || active.state !== KEY_STATES.ACTIVE || active.state_version !== row.reserved_lifecycle_version) {
      throw error(REPOSITORY_CODES.SIGNING_CLAIM_LOST, "reserved lifecycle is no longer active");
    }
  }

  const lifecycleRepository = {
    async snapshot() {
      return lifecycle.snapshot();
    },

    async reserveSignature(input) {
      const existing = signingRecords.get(input.operation_id);
      if (existing) {
        assertSigningIdentity(existing, input);
        if (existing.status === "committed") return publicSigningRecord(existing);
        if (existing.status === "uncertain") throw error(REPOSITORY_CODES.SIGNING_UNCERTAIN);
        if (existing.status === "pending") throw error(REPOSITORY_CODES.SIGNING_PENDING);
      }
      const active = currentKey();
      if (!active || active.key_id !== input.key_id || active.key_version !== input.key_version || active.state !== KEY_STATES.ACTIVE) {
        throw error(REPOSITORY_CODES.SIGNING_CLAIM_LOST, "key is not active");
      }
      const row = {
        ...input,
        status: "pending",
        reserved_lifecycle_version: lifecycle.snapshot().version,
        claim_token: "c1-high-level-claim"
      };
      signingRecords.set(input.operation_id, row);
      events.push("high.reserve");
      return publicSigningRecord(row, true);
    },

    async startSignature(input) {
      const row = signingRecords.get(input.operation_id);
      assertSigningIdentity(row, input);
      if (row.status !== "pending" || row.claim_token !== input.claim_token) throw error(REPOSITORY_CODES.SIGNING_CLAIM_LOST);
      assertCurrentLifecycle(row);
      row.provider_started_at = "2026-08-15T00:00:00.000Z";
      events.push("high.start");
      return publicSigningRecord(row, true);
    },

    async fenceSignature(input) {
      const row = signingRecords.get(input.operation_id);
      assertSigningIdentity(row, input);
      if (row.status !== "pending" || row.claim_token !== input.claim_token) throw error(REPOSITORY_CODES.SIGNING_CLAIM_LOST);
      assertCurrentLifecycle(row);
      return publicSigningRecord(row, true);
    },

    async commitSignature(input) {
      const row = signingRecords.get(input.operation_id);
      assertSigningIdentity(row, input);
      if (row.status === "committed") return publicSigningRecord(row);
      if (row.status !== "pending" || row.claim_token !== input.claim_token) throw error(REPOSITORY_CODES.SIGNING_CLAIM_LOST);
      assertCurrentLifecycle(row);
      row.status = "committed";
      row.signature = Buffer.from(input.signature);
      row.provider_receipt = clone(input.provider_receipt);
      delete row.claim_token;
      events.push("high.commit");
      return publicSigningRecord(row);
    },

    async reconcileSignature(input) {
      const row = signingRecords.get(input.operation_id);
      assertSigningIdentity(row, input);
      if (row.status === "committed") return publicSigningRecord(row);
      if (row.status !== "uncertain") throw error(REPOSITORY_CODES.SIGNING_CONFLICT);
      assertCurrentLifecycle(row);
      row.status = "committed";
      row.signature = Buffer.from(input.signature);
      row.provider_receipt = clone(input.provider_receipt);
      events.push("high.reconcile");
      return publicSigningRecord(row);
    },

    async markSignatureUncertain(input) {
      const row = signingRecords.get(input.operation_id);
      assertSigningIdentity(row, input);
      if (row.status === "committed") return publicSigningRecord(row);
      row.status = "uncertain";
      delete row.claim_token;
      events.push("high.uncertain");
      return publicSigningRecord(row);
    }
  };

  function operationRecord(row, includeClaim = false) {
    if (!row) return null;
    return Object.freeze({
      algorithm: row.algorithm,
      bytes_length: row.bytes_length,
      key_id: row.key_id,
      key_version: row.key_version,
      operation_id: row.operation_id,
      purpose: row.purpose,
      request_digest: row.request_digest,
      state: row.state,
      ...(row.state === "uncertain" ? { uncertain_reason: row.uncertain_reason } : {}),
      ...(includeClaim ? { claim_token: row.claim_token } : {}),
      ...(row.signature === undefined ? {} : { signature: clone(row.signature) }),
      ...(row.provider_receipt === undefined ? {} : { provider_receipt: clone(row.provider_receipt) })
    });
  }

  function assertOperationIdentity(row, input) {
    for (const field of ["algorithm", "bytes_length", "key_id", "key_version", "operation_id", "purpose", "request_digest"]) {
      if (row[field] !== input[field]) throw error("ERR_PROVIDER_OPERATION_RECONCILIATION_CONFLICT");
    }
  }

  // Start with the shared shape support, then supply the stateful behavior
  // needed by this single composition test.
  const providerOperationRepository = {
    ...createProviderOperationRepositoryFactory()(),
    async reserveOperation(input) {
      const existing = operationRecords.get(input.operation_id);
      if (existing) {
        assertOperationIdentity(existing, input);
        return operationRecord(existing, existing.state === "pending");
      }
      const row = { ...input, state: "pending", claim_token: "c1-provider-claim" };
      operationRecords.set(input.operation_id, row);
      events.push("provider.reserve");
      return operationRecord(row, true);
    },
    async claimOperation(input) {
      const row = operationRecords.get(input.operation_id);
      if (!row) return null;
      assertOperationIdentity(row, input);
      if (row.state === "committed") return operationRecord(row);
      row.claim_token = "c1-provider-recovery-claim";
      return operationRecord(row, true);
    },
    async startOperation(input) {
      const row = operationRecords.get(input.operation_id);
      if (!row) throw error("ERR_PROVIDER_OPERATION_RECONCILIATION_REPOSITORY");
      assertOperationIdentity(row, input);
      if (row.state !== "pending" || row.claim_token !== input.claim_token) throw error("ERR_PROVIDER_OPERATION_RECONCILIATION_REPOSITORY");
      row.state = "started";
      events.push("provider.start");
      return operationRecord(row, true);
    },
    async recordAccepted(input) {
      const row = operationRecords.get(input.operation_id);
      if (!row) throw error("ERR_PROVIDER_OPERATION_RECONCILIATION_REPOSITORY");
      assertOperationIdentity(row, input);
      if (row.state !== "started" || row.claim_token !== input.claim_token) throw error("ERR_PROVIDER_OPERATION_RECONCILIATION_REPOSITORY");
      row.state = "accepted";
      row.signature = clone(input.signature);
      row.provider_receipt = clone(input.provider_receipt);
      events.push("provider.accepted");
      if (!rotated) {
        rotated = true;
        lifecycle.rotate({
          expected_version: 1,
          operation_id: "c1-rotate-after-provider-acceptance",
          new_key: keyRecord("c1-key-2", 2, secondPair),
          verification_until: new Date(Date.now() + 60_000).toISOString()
        });
        events.push("lifecycle.rotate");
      }
      return operationRecord(row, true);
    },
    async commitOperation(input) {
      const row = operationRecords.get(input.operation_id);
      if (!row) throw error("ERR_PROVIDER_OPERATION_RECONCILIATION_REPOSITORY");
      assertOperationIdentity(row, input);
      if (row.state === "committed") return operationRecord(row);
      if (row.state !== "accepted" || row.claim_token !== input.claim_token) throw error("ERR_PROVIDER_OPERATION_RECONCILIATION_REPOSITORY");
      row.state = "committed";
      delete row.claim_token;
      events.push("provider.commit");
      return operationRecord(row);
    },
    async reconcileOperation(input) {
      const row = operationRecords.get(input.operation_id);
      if (!row) throw error("ERR_PROVIDER_OPERATION_RECONCILIATION_REPOSITORY");
      assertOperationIdentity(row, input);
      if (row.state !== "committed") throw error("ERR_PROVIDER_OPERATION_RECONCILIATION_REPOSITORY");
      return operationRecord(row);
    },
    async markUncertain(input) {
      const row = operationRecords.get(input.operation_id);
      if (!row) return null;
      assertOperationIdentity(row, input);
      if (row.state !== "committed") {
        row.state = "uncertain";
        row.uncertain_reason = input.uncertain_reason;
      }
      return operationRecord(row);
    },
    async getOperation(input) {
      const row = operationRecords.get(input.operation_id);
      if (!row) return null;
      assertOperationIdentity(row, input);
      return operationRecord(row);
    },
    async waitForOperation({ operation }) {
      const row = operationRecords.get(operation.operation_id);
      if (!row) return null;
      assertOperationIdentity(row, operation);
      return operationRecord(row);
    }
  };

  const provider = {
    version: 1,
    async publicKeyMetadata() {
      return {
        algorithm: "ed25519",
        key_id: KEY_ID,
        public_key: firstPair.publicKey
      };
    },
    async sign({ bytes }) {
      providerCalls += 1;
      return crypto.sign(null, bytes, firstPair.privateKey);
    }
  };
  const adapter = createProviderOperationReconciliationAdapter({
    provider,
    providerId: PROVIDER_ID,
    repository: providerOperationRepository,
    purpose: PURPOSE,
    keyId: KEY_ID,
    keyVersion: String(KEY_VERSION),
    waitTimeoutMs: 20
  });
  const signer = createDurableManagedSignerProvider({
    provider,
    managedSignerAdapter: adapter,
    repository: lifecycleRepository,
    purpose: PURPOSE,
    keyId: KEY_ID,
    keyVersion: KEY_VERSION,
    version: 1
  });

  return {
    lifecycle,
    lifecycleRepository,
    operationRecords,
    providerCalls: () => providerCalls,
    signer,
    signingRecords,
    events
  };
}

test("fails closed when lifecycle rotation follows provider acceptance but precedes the high-level commit", async () => {
  const fixture = createFixture();
  const request = {
    algorithm: "ed25519",
    bytes: Buffer.from("c1-rotation-fencing"),
    key_id: KEY_ID,
    purpose: PURPOSE,
    version: 1
  };

  await assert.rejects(fixture.signer.sign(request), { code: SIGNER_CODES.COMMIT });

  const operationId = [...fixture.operationRecords.keys()][0];
  const signingRecord = [...fixture.signingRecords.values()][0];
  assert.ok(operationId);
  assert.equal(fixture.providerCalls(), 1);
  assert.equal(signingRecord.status, "uncertain");
  assert.notEqual(signingRecord.status, "committed");
  assert.equal(fixture.lifecycle.snapshot().version, 2);
  assert.equal(fixture.lifecycle.snapshot().keys.find((key) => key.key_id === KEY_ID).state, KEY_STATES.RETIRING);
  assert.equal(fixture.operationRecords.get(operationId).state, "committed");
  assert.deepEqual(fixture.events.slice(0, 8), [
    "high.reserve",
    "high.start",
    "provider.reserve",
    "provider.start",
    "provider.accepted",
    "lifecycle.rotate",
    "provider.commit",
    "high.uncertain"
  ]);
  assert.equal(fixture.events.includes("high.commit"), false);

  await assert.rejects(fixture.signer.sign(request), { code: SIGNER_CODES.COMMIT });
  assert.equal([...fixture.signingRecords.values()][0].status, "uncertain");
  assert.equal(fixture.events.includes("high.reconcile"), false);
  assert.equal(fixture.providerCalls(), 1, "a stale-lifecycle retry must not blindly invoke the provider again");
});
