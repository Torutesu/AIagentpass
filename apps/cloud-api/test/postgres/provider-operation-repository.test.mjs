import assert from "node:assert/strict";
import crypto from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  createPostgresProviderOperationRepository,
  PROVIDER_OPERATION_REPOSITORY_ERROR_CODES as CODES,
} from "../../src/postgres/provider-operation-repository.mjs";

const PURPOSE = "agentpass.capability";
const KEY_ID = "capability-key-1";
const KEY_VERSION = "1";
const OPERATION_ID = "managed-signer-v1-provider-operation-test";
const REQUEST_DIGEST = "a".repeat(64);

function operation(overrides = {}) {
  return {
    algorithm: "ed25519",
    bytes_length: 32,
    key_id: KEY_ID,
    key_version: KEY_VERSION,
    operation_id: OPERATION_ID,
    purpose: PURPOSE,
    request_digest: REQUEST_DIGEST,
    ...overrides,
  };
}

function providerOutput() {
  const keys = crypto.generateKeyPairSync("ed25519");
  return {
    signature: {
      algorithm: "ed25519",
      encoding: "base64url",
      value: Buffer.alloc(64, 0x41).toString("base64url"),
      public_key: {
        algorithm: "ed25519",
        encoding: "base64url",
        value: keys.publicKey.export({ type: "spki", format: "der" }).toString("base64url"),
      },
    },
    provider_receipt: {
      provider: "agentpass-aws-kms-ledger-v1",
      receipt_id: `deterministic-${"b".repeat(64)}`,
      operation_id: OPERATION_ID,
      key_id: KEY_ID,
      key_version: KEY_VERSION,
    },
  };
}

class FakePg {
  constructor() { this.rows = new Map(); this.calls = []; }

  async query(text, params = []) {
    this.calls.push({ text, params });
    if (["BEGIN", "COMMIT", "ROLLBACK"].includes(text)) return { rows: [], rowCount: 0 };
    if (text.startsWith("SELECT\n        count(*) FILTER")) {
      const rows = [...this.rows.values()].filter((row) => row.purpose === params[0]
        && row.key_id === params[1] && row.key_version === String(params[2]));
      const aggregate = Object.fromEntries(["pending", "started", "accepted", "uncertain", "committed", "rejected", "failed"]
        .map((state) => [state, String(rows.filter((row) => row.state === state).length)]));
      return { rows: [{ ...aggregate, stale_claims: "0", oldest_nonterminal_at: null }], rowCount: 1 };
    }
    if (text.startsWith("WITH doomed AS")) {
      const eligible = [...this.rows.entries()].filter(([, row]) => row.purpose === params[0]
        && row.key_id === params[1] && row.key_version === String(params[2]) && row.state === "committed")
        .slice(0, Number(params[4]));
      for (const [entry] of eligible) this.rows.delete(entry);
      return { rows: eligible.map(([, row]) => ({ operation_id: row.operation_id })), rowCount: eligible.length };
    }
    const key = `${params[0]}\0${params[1]}`;
    if (text.startsWith("SELECT purpose,operation_id")) return this.result(this.rows.get(key));
    if (text.startsWith("INSERT INTO managed_signer_provider_operations")) {
      const [purpose, operationId, algorithm, bytesLength, requestDigest, keyId, keyVersion, claimDigest] = params;
      if (this.rows.has(key)) throw new Error("duplicate");
      const row = { purpose, operation_id: operationId, algorithm, bytes_length: bytesLength,
        request_digest: Buffer.from(requestDigest).toString("hex"), key_id: keyId, key_version: String(keyVersion),
        state: "pending", claim_token_digest: claimDigest, claim_expires_at: new Date(Date.now() + 30_000),
        claim_active: true, provider_started_at: null, signature: null, public_key_der: null,
        provider_receipt_provider: null, provider_receipt_id: null };
      this.rows.set(key, row);
      return this.result(row);
    }
    if (!text.startsWith("UPDATE managed_signer_provider_operations")) return { rows: [], rowCount: 0 };
    const row = this.rows.get(key);
    if (!row) return { rows: [], rowCount: 0 };
    if (text.includes("SET state=$3")) {
      row.state = params[2]; row.claim_token_digest = params[3]; row.claim_active = true;
      row.claim_expires_at = new Date(Date.now() + Number(params[4]));
    } else if (text.includes("SET state='started'")) {
      row.state = "started"; row.provider_started_at ??= new Date();
    } else if (text.includes("SET state='accepted'")) {
      row.state = "accepted"; row.signature = params[2]; row.public_key_der = params[3];
      row.provider_receipt_provider = params[4]; row.provider_receipt_id = params[5];
    } else if (text.includes("SET state='uncertain'")) {
      row.state = "uncertain"; row.claim_token_digest = null; row.claim_expires_at = null;
      row.claim_active = false; row.provider_started_at ??= new Date();
    } else if (text.includes("SET state='committed'")) {
      row.state = "committed"; row.claim_token_digest = null; row.claim_expires_at = null; row.claim_active = false;
    }
    return this.result(row);
  }

  result(row) { return row ? { rows: [{ ...row }], rowCount: 1 } : { rows: [], rowCount: 0 }; }
}

function repository(client = new FakePg()) {
  let tokenSequence = 0;
  return { client, repo: createPostgresProviderOperationRepository({
    client, purpose: PURPOSE, keyId: KEY_ID, keyVersion: KEY_VERSION,
    randomBytes: () => Buffer.alloc(32, 0x31 + tokenSequence++),
  }) };
}

test("0040 defines a closed immutable provider-operation state machine", async () => {
  const sql = await readFile(new URL("../../../../contracts/postgres/0040_managed_signer_provider_operations.sql", import.meta.url), "utf8");
  assert.match(sql, /CREATE TABLE managed_signer_provider_operations/u);
  assert.match(sql, /state IN \('pending', 'started', 'accepted', 'uncertain', 'committed', 'rejected', 'failed'\)/u);
  assert.match(sql, /managed_signer_provider_operation_identity_immutable/u);
  assert.match(sql, /managed_signer_provider_operation_terminal_immutable/u);
  assert.match(sql, /OLD\.state = 'uncertain' AND NEW\.state IN \('accepted', 'committed'/u);
  assert.match(sql, /claim_token_digest/u);
  assert.match(sql, /octet_length\(signature\) = 64/u);
  assert.doesNotMatch(sql, /organization_id|request_bytes|private_key|provider_credential/iu);
});

test("reserves, starts, accepts, and commits one closed provider operation", async () => {
  const { client, repo } = repository();
  const reserved = await repo.reserveOperation(operation());
  assert.equal(reserved.state, "pending");
  assert.match(reserved.claim_token, /^[A-Za-z0-9_-]{43}$/u);
  const stored = client.rows.get(`${PURPOSE}\0${OPERATION_ID}`);
  assert.equal(Object.hasOwn(stored, "claim_token"), false);
  assert.notEqual(Buffer.from(stored.claim_token_digest).toString("base64url"), reserved.claim_token);
  const started = await repo.startOperation({ ...operation(), claim_token: reserved.claim_token });
  assert.equal(started.state, "started");
  const output = providerOutput();
  const accepted = await repo.recordAccepted({ ...operation(), claim_token: reserved.claim_token, ...output });
  assert.equal(accepted.state, "accepted");
  assert.deepEqual(accepted.provider_receipt, output.provider_receipt);
  const committed = await repo.commitOperation({ ...operation(), claim_token: reserved.claim_token });
  assert.equal(committed.state, "committed");
  assert.equal(Object.hasOwn(committed, "claim_token"), false);
  assert.deepEqual(await repo.getOperation(operation()), committed);
  assert.deepEqual(await repo.reserveOperation(operation()), committed);
});

test("persists accepted output across uncertainty and reconciles without a new provider result", async () => {
  const { repo } = repository();
  const reserved = await repo.reserveOperation(operation());
  await repo.startOperation({ ...operation(), claim_token: reserved.claim_token });
  const output = providerOutput();
  await repo.recordAccepted({ ...operation(), claim_token: reserved.claim_token, ...output });
  const uncertain = await repo.markUncertain({ ...operation(), claim_token: reserved.claim_token });
  assert.equal(uncertain.state, "uncertain");
  assert.deepEqual(uncertain.provider_receipt, output.provider_receipt);
  const committed = await repo.reconcileOperation(operation());
  assert.equal(committed.state, "committed");
  assert.deepEqual(committed.provider_receipt, output.provider_receipt);
});

test("rejects operation substitution, stale claims, unknown fields, and forbidden receipts", async () => {
  const { client, repo } = repository();
  const reserved = await repo.reserveOperation(operation());
  await assert.rejects(repo.reserveOperation(operation({ request_digest: "c".repeat(64) })), { code: CODES.CONFLICT });
  await assert.rejects(repo.startOperation({ ...operation(), claim_token: "A".repeat(43) }), { code: CODES.CLAIM_LOST });
  await assert.rejects(repo.getOperation({ ...operation(), private_key: "forbidden" }), { code: CODES.INPUT });
  await repo.startOperation({ ...operation(), claim_token: reserved.claim_token });
  const output = providerOutput();
  output.provider_receipt.provider = "secret-provider";
  await assert.rejects(repo.recordAccepted({ ...operation(), claim_token: reserved.claim_token, ...output }), { code: CODES.INPUT });
  const row = client.rows.get(`${PURPOSE}\0${OPERATION_ID}`);
  row.claim_active = false;
  const reclaimed = await repo.claimOperation(operation());
  assert.notEqual(reclaimed.claim_token, reserved.claim_token);
});

test("waits only within the configured bound and observes a durable transition", async () => {
  const { repo } = repository();
  const reserved = await repo.reserveOperation(operation());
  setTimeout(() => { void repo.markUncertain({ ...operation(), claim_token: reserved.claim_token }); }, 5);
  const result = await repo.waitForOperation({ operation: operation(), timeout_ms: 100 });
  assert.equal(result.state, "uncertain");
  await assert.rejects(repo.waitForOperation({ operation: operation(), timeout_ms: 30_001 }), { code: CODES.INPUT });
});

test("reports fixed-cardinality aggregate health and prunes only correlated committed records", async () => {
  const { client, repo } = repository();
  const reserved = await repo.reserveOperation(operation());
  await repo.startOperation({ ...operation(), claim_token: reserved.claim_token });
  await repo.recordAccepted({ ...operation(), claim_token: reserved.claim_token, ...providerOutput() });
  await repo.commitOperation({ ...operation(), claim_token: reserved.claim_token });

  assert.deepEqual(await repo.health(), {
    version: 1,
    purpose: PURPOSE,
    algorithm: "ed25519",
    key_id: KEY_ID,
    key_version: KEY_VERSION,
    states: { pending: 0, started: 0, accepted: 0, uncertain: 0, committed: 1, rejected: 0, failed: 0 },
    stale_claims: 0,
    oldest_nonterminal_at: null,
  });
  assert.deepEqual(await repo.pruneOperations({ before: "2027-08-15T00:00:00.000Z", limit: 10 }), { pruned: 1 });
  const pruneSql = client.calls.find(({ text }) => text.startsWith("WITH doomed AS"))?.text ?? "";
  assert.match(pruneSql, /JOIN managed_signer_signing_idempotency/u);
  assert.match(pruneSql, /provider\.state='committed' AND signing\.status='committed'/u);
  assert.match(pruneSql, /FOR UPDATE OF provider SKIP LOCKED/u);
  await assert.rejects(repo.pruneOperations({ before: "not-a-time", limit: 1 }), { code: CODES.INPUT });
  await assert.rejects(repo.pruneOperations({ before: "2027-08-15T00:00:00.000Z", limit: 1_001 }), { code: CODES.INPUT });
});
