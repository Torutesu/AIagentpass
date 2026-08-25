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
  constructor() { this.rows = new Map(); this.calls = []; this.conflictOnInsert = false; }

  async query(text, params = []) {
    this.calls.push({ text, params });
    const functionName = text.match(/SELECT public\.agentpass_managed_signer_provider_operation_([a-z]+)\(/u)?.[1];
    if (!functionName) throw new Error("unexpected non-function SQL");
    const key = `${params[0]}\0${params[1]}`;
    const operation = this.rows.get(key);
    const identityMatches = (row) => row && row.algorithm === params[2] && row.bytes_length === Number(params[3])
      && row.request_digest === Buffer.from(params[4]).toString("hex") && row.key_id === params[5]
      && row.key_version === String(params[6]);
    const claimMatches = (row, digest) => row?.claim_token_digest && Buffer.from(row.claim_token_digest).equals(Buffer.from(digest))
      && row.claim_active === true;
    const error = (errorCode) => this.envelope({ status: "error", error_code: errorCode });
    const notFound = () => this.envelope({ status: "not_found" });
    const ok = (row, claimAcquired = false) => this.envelope({ status: "ok", claim_acquired: claimAcquired, record: this.record(row) });

    if (["reserve", "claim", "start", "accept", "commit", "reconcile", "uncertain", "get"].includes(functionName)
      && !identityMatches({ algorithm: params[2], bytes_length: params[3], request_digest: Buffer.from(params[4]).toString("hex"), key_id: params[5], key_version: String(params[6]) })) {
      // The real function validates this before touching the ledger.  The
      // repository already rejects malformed values, so this branch models
      // the stable database error for an impossible contract call.
      return error("INPUT");
    }

    if (functionName === "reserve") {
      const newRow = () => ({ purpose: params[0], operation_id: params[1], algorithm: params[2], bytes_length: Number(params[3]),
        request_digest: Buffer.from(params[4]).toString("hex"), key_id: params[5], key_version: String(params[6]), state: "pending",
        claim_token_digest: params[7], claim_expires_at: new Date(Date.now() + Number(params[8])), claim_active: true,
        provider_started_at: null, uncertain_reason: null, signature: null, public_key_der: null,
        provider_receipt_provider: null, provider_receipt_id: null });
      if (!operation) {
        const row = newRow();
        let claimAcquired = true;
        if (this.conflictOnInsert) {
          this.conflictOnInsert = false;
          row.claim_token_digest = Buffer.alloc(32, 0x7f);
          claimAcquired = false;
        }
        this.rows.set(key, row);
        return ok(row, claimAcquired);
      }
      if (!identityMatches(operation)) return error("CONFLICT");
      if (this.conflictOnInsert) {
        this.conflictOnInsert = false;
        operation.claim_token_digest = Buffer.alloc(32, 0x7f);
        operation.claim_active = true;
      }
      if (operation.state === "pending" && operation.claim_active === false) {
        operation.claim_token_digest = params[7]; operation.claim_active = true;
        operation.claim_expires_at = new Date(Date.now() + Number(params[8]));
        return ok(operation, true);
      }
      return ok(operation, false);
    }
    if (functionName === "claim") {
      if (!operation) return notFound();
      if (!identityMatches(operation)) return error("CONFLICT");
      if (["committed", "rejected", "failed"].includes(operation.state) || claimMatches(operation, params[7])) return ok(operation, false);
      operation.claim_token_digest = params[7]; operation.claim_active = true;
      operation.claim_expires_at = new Date(Date.now() + Number(params[8]));
      return ok(operation, true);
    }
    if (functionName === "start") {
      if (!operation) return error("CLAIM_LOST");
      if (!identityMatches(operation)) return error("CONFLICT");
      if (!["pending", "started"].includes(operation.state) || !claimMatches(operation, params[7])) return error("CLAIM_LOST");
      operation.state = "started"; operation.provider_started_at ??= new Date();
      return ok(operation);
    }
    if (functionName === "accept") {
      if (!operation) return error("CLAIM_LOST");
      if (!identityMatches(operation)) return error("CONFLICT");
      if (!["started", "uncertain", "accepted"].includes(operation.state) || !claimMatches(operation, params[7])) return error("CLAIM_LOST");
      if (operation.state === "accepted") {
        if (!Buffer.from(operation.signature).equals(Buffer.from(params[8])) || !Buffer.from(operation.public_key_der).equals(Buffer.from(params[9]))
          || operation.provider_receipt_provider !== params[10] || operation.provider_receipt_id !== params[11]) return error("CONFLICT");
        return ok(operation);
      }
      operation.state = "accepted"; operation.signature = params[8]; operation.public_key_der = params[9];
      operation.uncertain_reason = null; operation.provider_receipt_provider = params[10]; operation.provider_receipt_id = params[11];
      return ok(operation);
    }
    if (functionName === "commit") {
      if (!operation) return error("CLAIM_LOST");
      if (!identityMatches(operation)) return error("CONFLICT");
      if (operation.state === "committed") return ok(operation);
      if (operation.state !== "accepted" || !claimMatches(operation, params[7])) return error("CLAIM_LOST");
      operation.state = "committed"; operation.uncertain_reason = null; operation.claim_token_digest = null;
      operation.claim_expires_at = null; operation.claim_active = false;
      return ok(operation);
    }
    if (functionName === "reconcile") {
      if (!operation) return notFound();
      if (!identityMatches(operation)) return error("CONFLICT");
      if (operation.state === "committed") return ok(operation);
      if (!["accepted", "uncertain"].includes(operation.state) || !operation.signature || !operation.public_key_der
        || !operation.provider_receipt_provider || !operation.provider_receipt_id) return error("STATE");
      operation.state = "committed"; operation.uncertain_reason = null; operation.claim_token_digest = null;
      operation.claim_expires_at = null; operation.claim_active = false;
      return ok(operation);
    }
    if (functionName === "uncertain") {
      if (!operation) return notFound();
      if (!identityMatches(operation)) return error("CONFLICT");
      if (["committed", "rejected", "failed"].includes(operation.state)) return ok(operation);
      if (!["pending", "started", "accepted", "uncertain"].includes(operation.state) || !claimMatches(operation, params[7])) return error("CLAIM_LOST");
      operation.state = "uncertain"; operation.uncertain_reason = params[8]; operation.claim_token_digest = null;
      operation.claim_expires_at = null; operation.claim_active = false; operation.provider_started_at ??= new Date();
      return ok(operation);
    }
    if (functionName === "get") {
      if (!operation) return notFound();
      if (!identityMatches(operation)) return error("CONFLICT");
      return ok(operation);
    }
    if (functionName === "health") {
      const rows = [...this.rows.values()].filter((row) => row.purpose === params[0] && row.key_id === params[1] && row.key_version === String(params[2]));
      const states = Object.fromEntries(["pending", "started", "accepted", "uncertain", "committed", "rejected", "failed"]
        .map((state) => [state, rows.filter((row) => row.state === state).length]));
      return this.envelope({ status: "ok", health: { version: 1, purpose: params[0], algorithm: params[3], key_id: params[1], key_version: String(params[2]),
        states, stale_claims: 0, oldest_nonterminal_at: null } });
    }
    if (functionName === "prune") {
      const eligible = [...this.rows.entries()].filter(([, row]) => row.purpose === params[0]
        && row.key_id === params[1] && row.key_version === String(params[2]) && row.state === "committed").slice(0, Number(params[5]));
      for (const [entry] of eligible) this.rows.delete(entry);
      return this.envelope({ status: "ok", pruned: eligible.length });
    }
    throw new Error(`unexpected function ${functionName}`);
  }

  envelope(result) { return { rows: [{ result }], rowCount: 1 }; }

  record(row) {
    return { algorithm: row.algorithm, bytes_length: row.bytes_length, key_id: row.key_id, key_version: row.key_version,
      operation_id: row.operation_id, purpose: row.purpose, request_digest: row.request_digest, state: row.state,
      uncertain_reason: row.uncertain_reason, signature_hex: row.signature ? Buffer.from(row.signature).toString("hex") : null,
      public_key_der_hex: row.public_key_der ? Buffer.from(row.public_key_der).toString("hex") : null,
      provider_receipt_provider: row.provider_receipt_provider, provider_receipt_id: row.provider_receipt_id };
  }
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

test("0041 adds closed uncertainty reasons and quarantines only bounded expired started claims", async () => {
  const sql = await readFile(new URL("../../../../contracts/postgres/0041_managed_signer_provider_operation_maintenance.sql", import.meta.url), "utf8");
  assert.match(sql, /ADD COLUMN uncertain_reason text/u);
  assert.match(sql, /SET uncertain_reason = 'process_interrupted'\s+WHERE state = 'uncertain'/u);
  assert.match(sql, /state = 'uncertain'[\s\S]*uncertain_reason IN/u);
  assert.match(sql, /state <> 'uncertain' AND uncertain_reason IS NULL/u);
  assert.match(sql, /agentpass_quarantine_expired_managed_signer_provider_operations/u);
  assert.match(sql, /WHERE state = 'started'[\s\S]*claim_expires_at <= clock_timestamp\(\)/u);
  assert.match(sql, /LIMIT p_limit\s+FOR UPDATE SKIP LOCKED/u);
  assert.match(sql, /uncertain_reason = 'claim_expired_after_start'/u);
  assert.doesNotMatch(sql, /request_bytes|private_key|provider_credential/iu);
});

test("0049 exposes only purpose-specific signer functions and no repository table DML", async () => {
  const source = await readFile(new URL("../../src/postgres/provider-operation-repository.mjs", import.meta.url), "utf8");
  const sql = await readFile(new URL("../../../../contracts/postgres/0049_managed_signer_provider_operation_authority.sql", import.meta.url), "utf8");
  const roles = await readFile(new URL("../../../../scripts/postgres/roles.sql", import.meta.url), "utf8");
  const purposes = ["reserve", "claim", "start", "accept", "commit", "reconcile", "uncertain", "get", "health", "prune"];
  assert.doesNotMatch(source, /managed_signer_provider_operations/u);
  assert.doesNotMatch(source, /(?:INSERT|UPDATE|DELETE)\s+(?:INTO\s+)?[A-Za-z_]+/iu);
  for (const purpose of purposes) {
    assert.match(source, new RegExp(`\\["${purpose}",`, "u"));
    assert.match(sql, new RegExp(`CREATE FUNCTION public\\.agentpass_managed_signer_provider_operation_${purpose}\\([\\s\\S]*?SECURITY DEFINER`, "u"));
    assert.match(sql, new RegExp(`REVOKE ALL ON FUNCTION public\\.agentpass_managed_signer_provider_operation_${purpose}\\(`, "u"));
    assert.match(roles, new RegExp(`agentpass_managed_signer_provider_operation_${purpose}\\(`, "u"));
  }
  assert.match(source, /agentpass_managed_signer_provider_operation_\$\{purpose\}/u);
  assert.match(sql, /SET search_path = pg_catalog, public/gu);
  assert.match(sql, /clock_timestamp\(\)/u);
  assert.match(sql, /FOR UPDATE/u);
  assert.match(sql, /SKIP LOCKED/u);
  assert.doesNotMatch(sql, /GRANT EXECUTE ON FUNCTION public\.agentpass_managed_signer_provider_operation_(?:error|record|binding_valid|not_found)/u);
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

test("first-reservation races converge through the unique operation binding", async () => {
  const client = new FakePg();
  client.conflictOnInsert = true;
  const { repo } = repository(client);

  const reserved = await repo.reserveOperation(operation());
  assert.equal(reserved.state, "pending");
  assert.equal(Object.hasOwn(reserved, "claim_token"), false, "the losing reserver must not receive the winner's claim");
  assert.equal(client.calls.length, 1);
  assert.match(client.calls[0].text, /agentpass_managed_signer_provider_operation_reserve\(/u);
});

test("persists accepted output across uncertainty and reconciles without a new provider result", async () => {
  const { repo } = repository();
  const reserved = await repo.reserveOperation(operation());
  await repo.startOperation({ ...operation(), claim_token: reserved.claim_token });
  const output = providerOutput();
  await repo.recordAccepted({ ...operation(), claim_token: reserved.claim_token, ...output });
  const uncertain = await repo.markUncertain({ ...operation(), claim_token: reserved.claim_token, uncertain_reason: "commit_response_lost" });
  assert.equal(uncertain.state, "uncertain");
  assert.equal(uncertain.uncertain_reason, "commit_response_lost");
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
  setTimeout(() => { void repo.markUncertain({ ...operation(), claim_token: reserved.claim_token, uncertain_reason: "process_interrupted" }); }, 5);
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
  assert.match(client.calls.at(-1).text, /agentpass_managed_signer_provider_operation_prune\(/u);
  await assert.rejects(repo.pruneOperations({ before: "not-a-time", limit: 1 }), { code: CODES.INPUT });
  await assert.rejects(repo.pruneOperations({ before: "2027-08-15T00:00:00.000Z", limit: 1_001 }), { code: CODES.INPUT });
});
