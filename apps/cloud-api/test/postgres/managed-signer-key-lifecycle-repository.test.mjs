import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  canonicalManagedSignerRequestDigest,
  createPostgresManagedSignerKeyLifecycleRepository,
  MANAGED_SIGNER_KEY_LIFECYCLE_REPOSITORY_ERROR_CODES as CODES
} from "../../src/postgres/managed-signer-key-lifecycle-repository.mjs";

const PURPOSE = "agentpass.agent-session-grant";
const OTHER_PURPOSE = "agentpass.qualification-grant-batch-manifest";
const NOW = Date.parse("2026-08-14T12:00:00.000Z");
const NOW_ISO = new Date(NOW).toISOString();
const FINGERPRINT_1 = "a".repeat(64);
const FINGERPRINT_2 = "b".repeat(64);
const SIGNATURE = Buffer.alloc(64, 0x41);
const TOKEN = /^[A-Za-z0-9_-]{43}$/u;

function snapshot(purpose = PURPOSE, fingerprint = FINGERPRINT_1) {
  return {
    version: 1,
    purpose,
    algorithm: "ed25519",
    keys: [{
      key_id: `${purpose === PURPOSE ? "agent" : "manifest"}-key-1`,
      key_version: 1,
      purpose,
      algorithm: "ed25519",
      public_key_fingerprint: fingerprint,
      state: "active",
      state_version: 1
    }]
  };
}

function nextKey(purpose = PURPOSE) {
  return {
    key_id: `${purpose === PURPOSE ? "agent" : "manifest"}-key-2`,
    key_version: 2,
    purpose,
    algorithm: "ed25519",
    public_key_fingerprint: FINGERPRINT_2,
    state: "active",
    state_version: 1
  };
}

class FakePgPool {
  constructor() {
    this.state = { lifecycles: new Map(), keys: new Map(), lifecycleOperations: new Map(), signing: new Map() };
    this.calls = [];
    this.nextConnection = 0;
    this.locks = new Map();
  }

  async query(text, params = []) {
    const connection = await this.connect();
    try {
      return await connection.query(text, params);
    } finally {
      connection.release();
    }
  }

  async connect() {
    const owner = ++this.nextConnection;
    return { query: (text, params) => this.queryFor(owner, text, params), release: () => this.release(owner) };
  }

  async queryFor(owner, text, params = []) {
    this.calls.push({ owner, text, params });
    if (text === "BEGIN") return { rows: [], rowCount: 0 };
    if (text === "COMMIT") { this.release(owner); return { rows: [], rowCount: 0 }; }
    if (text === "ROLLBACK") { this.release(owner); return { rows: [], rowCount: 0 }; }

    if (text.includes("SELECT purpose,algorithm,version") && text.includes("FROM managed_signer_key_lifecycles")) {
      const purpose = params[0];
      if (text.includes("FOR UPDATE")) await this.acquire(owner, purpose);
      const row = this.state.lifecycles.get(purpose);
      if (!row) return { rows: [], rowCount: 0 };
      return { rows: [{ ...row }], rowCount: 1 };
    }

    if (text.startsWith("INSERT INTO managed_signer_key_lifecycles")) {
      const [purpose, algorithm, version, maxKeys, overlap] = params;
      if (this.state.lifecycles.has(purpose)) return { rows: [], rowCount: 0 };
      this.state.lifecycles.set(purpose, { purpose, algorithm, version: String(version), max_keys: maxKeys, max_verification_overlap_ms: String(overlap) });
      return { rows: [{ purpose }], rowCount: 1 };
    }

    if (text.startsWith("UPDATE managed_signer_key_lifecycles")) {
      const row = this.state.lifecycles.get(params[0]);
      if (!row || Number(row.version) !== Number(params[2])) return { rows: [], rowCount: 0 };
      row.version = String(params[1]);
      return { rows: [{ version: row.version }], rowCount: 1 };
    }

    if (text.includes("FROM managed_signer_keys") && text.startsWith("SELECT purpose,key_id")) {
      const purpose = params[0];
      const rows = [...this.state.keys.values()]
        .filter((row) => row.purpose === purpose)
        .sort((left, right) => left.key_position - right.key_position)
        .map((row) => ({ ...row, key_version: String(row.key_version), state_version: String(row.state_version) }));
      return { rows, rowCount: rows.length };
    }

    if (text.startsWith("SELECT key_id,key_version::text AS key_version,state")) {
      const row = this.state.keys.get(`${params[0]}\u0000${params[1]}`);
      return row ? { rows: [{ key_id: row.key_id, key_version: String(row.key_version), state: row.state, state_version: String(row.state_version) }], rowCount: 1 } : { rows: [], rowCount: 0 };
    }

    if (text.startsWith("INSERT INTO managed_signer_keys")) {
      const [purpose, keyId, keyVersion, algorithm, fingerprint, publicKey, state, stateVersion, verificationUntil, position] = params;
      this.state.keys.set(`${purpose}\u0000${keyId}`, { purpose, key_id: keyId, key_version: Number(keyVersion), algorithm, public_key_fingerprint: fingerprint, public_key_pem: publicKey, state, state_version: Number(stateVersion), verification_until: verificationUntil, key_position: Number(position) });
      return { rows: [], rowCount: 1 };
    }

    if (text.startsWith("UPDATE managed_signer_keys")) {
      const row = this.state.keys.get(`${params[0]}\u0000${params[1]}`);
      if (!row) return { rows: [], rowCount: 0 };
      row.state = params[2];
      row.state_version = Number(params[3]);
      row.verification_until = params[4];
      return { rows: [], rowCount: 1 };
    }

    if (text.includes("FROM managed_signer_key_lifecycle_operations")) {
      const row = this.state.lifecycleOperations.get(`${params[0]}\u0000${params[1]}`);
      return row ? { rows: [{ ...row }], rowCount: 1 } : { rows: [], rowCount: 0 };
    }

    if (text.startsWith("INSERT INTO managed_signer_key_lifecycle_operations")) {
      const [purpose, operationId, requestDigest, responseJson, createdAt, expiresAt] = params;
      this.state.lifecycleOperations.set(`${purpose}\u0000${operationId}`, {
        purpose, operation_id: operationId, request_digest: requestDigest, response_snapshot: JSON.parse(responseJson), created_at: createdAt, expires_at: expiresAt
      });
      return { rows: [], rowCount: 1 };
    }

    if (text.includes("FROM managed_signer_signing_idempotency") && text.includes("SELECT")) {
      const row = this.state.signing.get(`${params[0]}\u0000${params[1]}`);
      return row ? { rows: [{ ...row, key_version: String(row.key_version), reserved_lifecycle_version: String(row.reserved_lifecycle_version) }], rowCount: 1 } : { rows: [], rowCount: 0 };
    }

    if (text.startsWith("INSERT INTO managed_signer_signing_idempotency")) {
      const [purpose, operationId, requestDigest, keyId, keyVersion, expiresAt, claimDigest, leaseMs, reservedVersion] = params;
      const row = { purpose, operation_id: operationId, request_digest: requestDigest, key_id: keyId, key_version: Number(keyVersion), status: "pending", signature: null, created_at: NOW_ISO, updated_at: NOW_ISO, expires_at: expiresAt, claim_expires_at: new Date(NOW + Number(leaseMs)).toISOString(), provider_started_at: null, reserved_lifecycle_version: Number(reservedVersion), claim_token_digest: claimDigest };
      this.state.signing.set(`${purpose}\u0000${operationId}`, row);
      return { rows: [{ ...row, request_digest: requestDigest.toString("hex"), key_version: String(row.key_version) }], rowCount: 1 };
    }

    if (text.startsWith("UPDATE managed_signer_signing_idempotency")) {
      const row = this.state.signing.get(`${params[0]}\u0000${params[1]}`);
      if (!row) return { rows: [], rowCount: 0 };
      if (text.includes("claim_expires_at<=clock_timestamp()") && row.claim_expires_at > NOW_ISO) return { rows: [], rowCount: 0 };
      if (text.includes("status='committed'") && (Number(this.state.lifecycles.get(row.purpose)?.version) !== Number(row.reserved_lifecycle_version) || this.state.keys.get(`${row.purpose}\u0000${row.key_id}`)?.state !== "active")) return { rows: [], rowCount: 0 };
      if (text.includes("SET status=CASE")) {
        row.status = row.provider_started_at === null ? "aborted" : "uncertain";
        row.claim_token_digest = null;
        row.claim_expires_at = null;
      } else if (text.includes("provider_started_at=COALESCE")) row.provider_started_at = NOW_ISO;
      else if (text.includes("status='uncertain'")) { row.status = "uncertain"; row.claim_token_digest = null; row.claim_expires_at = null; }
      else if (text.includes("status='committed'")) { row.status = "committed"; row.signature = params[2]; row.claim_token_digest = null; row.claim_expires_at = null; }
      else if (text.includes("status='pending'")) { row.status = "pending"; row.claim_token_digest = params[2]; row.claim_expires_at = NOW_ISO; }
      row.updated_at = NOW_ISO;
      return { rows: [{ ...row, request_digest: row.request_digest.toString("hex"), key_version: String(row.key_version) }], rowCount: 1 };
    }

    if (text.startsWith("WITH doomed AS")) return { rows: [], rowCount: 0 };
    return { rows: [], rowCount: 0 };
  }

  async acquire(owner, purpose) {
    const existing = this.locks.get(purpose);
    if (!existing) { this.locks.set(purpose, { owner, waiters: [] }); return; }
    if (existing.owner === owner) return;
    await new Promise((resolve) => existing.waiters.push({ owner, resolve }));
  }

  release(owner) {
    for (const [purpose, lock] of this.locks.entries()) {
      if (lock.owner !== owner) continue;
      const next = lock.waiters.shift();
      if (next) lock.owner = next.owner, next.resolve();
      else this.locks.delete(purpose);
    }
  }
}

function repository(pool, purpose = PURPOSE) {
  return createPostgresManagedSignerKeyLifecycleRepository({ client: pool, purpose, now: () => NOW });
}

test("0037 creates purpose-scoped public lifecycle and signing ledgers", async () => {
  const sql = await readFile(new URL("../../../../contracts/postgres/0037_managed_signer_lifecycle.sql", import.meta.url), "utf8");
  assert.match(sql, /CREATE TABLE managed_signer_key_lifecycles/u);
  assert.match(sql, /CREATE TABLE managed_signer_keys/u);
  assert.match(sql, /CREATE TABLE managed_signer_key_lifecycle_operations/u);
  assert.match(sql, /CREATE TABLE managed_signer_signing_idempotency/u);
  assert.match(sql, /FOR UPDATE/u);
  assert.match(sql, /status IN \('pending', 'uncertain', 'committed'\)/u);
  assert.match(sql, /octet_length\(signature\) = 64/u);
  assert.doesNotMatch(sql, /organization_id/u);
  assert.doesNotMatch(sql, /private_key/u);
});

test("0038 catalogs the forward-only fencing contract", async () => {
  const sql = await readFile(new URL("../../../../contracts/postgres/0038_managed_signer_fencing.sql", import.meta.url), "utf8");
  assert.match(sql, /ALTER TABLE managed_signer_signing_idempotency/u);
  assert.match(sql, /claim_token_digest/u);
  assert.match(sql, /claim_expires_at/u);
  assert.match(sql, /provider_started_at/u);
  assert.match(sql, /reserved_lifecycle_version/u);
  assert.match(sql, /status IN \('pending', 'uncertain', 'committed', 'aborted'\)/u);
  assert.match(sql, /clock_timestamp\(\)/u);
  assert.match(sql, /CREATE INDEX managed_signer_signing_claim_expiry/u);
  const { loadSqlMigrations, defaultContractDirectory } = await import("../../src/postgres/migration-runner.mjs");
  const migrations = await loadSqlMigrations(defaultContractDirectory());
  assert.equal(migrations.at(-1).version, 38);
  assert.equal(migrations.at(-1).name, "0038_managed_signer_fencing.sql");
});

test("persists compatible snapshots, serializes lifecycle operations, and replays exact responses", async () => {
  const pool = new FakePgPool();
  const repo = repository(pool);
  await repo.initialize({ snapshot: snapshot() });
  assert.deepEqual(await repo.snapshot(), snapshot());

  const rotated = await repo.rotate({ expected_version: 1, operation_id: "rotate-1", new_key: nextKey(), verification_until: "2026-08-14T13:00:00.000Z" });
  assert.equal(rotated.version, 2);
  assert.deepEqual(rotated.keys.map(({ key_id, state }) => ({ key_id, state })), [
    { key_id: "agent-key-1", state: "retiring" },
    { key_id: "agent-key-2", state: "active" }
  ]);
  assert.deepEqual(await repo.rotate({ expected_version: 1, operation_id: "rotate-1", new_key: nextKey(), verification_until: "2026-08-14T13:00:00.000Z" }), rotated);
  await assert.rejects(repo.rotate({ expected_version: 1, operation_id: "rotate-1", new_key: { ...nextKey(), key_id: "agent-key-3" }, verification_until: "2026-08-14T13:00:00.000Z" }), { code: CODES.OPERATION_CONFLICT });
  await assert.rejects(repo.emergencyDisable({ expected_version: 1, operation_id: "stale-1" }), { code: "ERR_MANAGED_SIGNER_KEY_LIFECYCLE_VERSION" });
  assert.equal(pool.calls.filter(({ text }) => text.includes("FROM managed_signer_key_lifecycles") && text.includes("FOR UPDATE")).length > 0, true);
});

test("durably replays public signatures across repository instances and fails closed for uncertainty", async () => {
  const pool = new FakePgPool();
  const first = repository(pool);
  await first.initialize({ snapshot: snapshot() });
  const requestDigest = canonicalManagedSignerRequestDigest({ purpose: PURPOSE, algorithm: "ed25519", key_id: "agent-key-1", version: 1, bytes: Buffer.from("commit") });
  const input = { operation_id: "sign-1", request_digest: requestDigest, key_id: "agent-key-1", key_version: 1 };
  assert.equal((await first.reserveSignature(input)).state, "pending");
  await assert.rejects(first.reserveSignature(input), { code: CODES.SIGNING_PENDING });
  const committed = await first.commitSignature({ ...input, signature: SIGNATURE });
  const second = repository(pool);
  const replay = await second.reserveSignature(input);
  assert.equal(replay.state, "committed");
  assert.deepEqual(replay.signature, SIGNATURE);
  assert.deepEqual(await second.commitSignature({ ...input, signature: SIGNATURE }), replay);
  await assert.rejects(second.commitSignature({ ...input, signature: Buffer.alloc(64, 0x42) }), { code: CODES.SIGNING_CONFLICT });
  assert.deepEqual(committed.signature, SIGNATURE);

  const uncertainDigest = canonicalManagedSignerRequestDigest({ purpose: PURPOSE, algorithm: "ed25519", key_id: "agent-key-1", version: 1, bytes: Buffer.from("uncertain") });
  const uncertain = { operation_id: "sign-uncertain", request_digest: uncertainDigest, key_id: "agent-key-1", key_version: 1 };
  await second.reserveSignature(uncertain);
  assert.equal((await second.markSignatureUncertain(uncertain)).state, "uncertain");
  await assert.rejects(first.reserveSignature(uncertain), { code: CODES.SIGNING_UNCERTAIN });
  await assert.rejects(first.commitSignature({ ...uncertain, signature: SIGNATURE }), { code: CODES.SIGNING_UNCERTAIN });
  assert.equal((await first.reconcileSignature({ ...uncertain, signature: SIGNATURE })).state, "committed");
});

test("reclaims an unstarted expired lease but fences started work after emergency disable", async () => {
  const pool = new FakePgPool();
  const repo = repository(pool);
  await repo.initialize({ snapshot: snapshot() });
  const requestDigest = canonicalManagedSignerRequestDigest({ purpose: PURPOSE, key_id: "agent-key-1", bytes: Buffer.from("fenced") });
  const input = { operation_id: "sign-fenced", request_digest: requestDigest, key_id: "agent-key-1", key_version: 1 };
  const first = await repo.reserveSignature(input);
  assert.match(first.claim_token, TOKEN);
  assert.equal(first.reserved_lifecycle_version, 1);

  pool.state.signing.get(`${PURPOSE}\u0000${input.operation_id}`).claim_expires_at = "2026-08-14T11:59:59.000Z";
  const reclaimed = await repo.reserveSignature(input);
  assert.equal(reclaimed.state, "pending");
  assert.notEqual(reclaimed.claim_token, first.claim_token);

  const started = await repo.startSignature({ ...input, claim_token: reclaimed.claim_token });
  assert.equal(typeof started.provider_started_at, "string");
  pool.state.signing.get(`${PURPOSE}\u0000${input.operation_id}`).claim_expires_at = "2026-08-14T11:59:59.000Z";
  await assert.rejects(repo.reserveSignature(input), { code: CODES.SIGNING_UNCERTAIN });

  const second = await repo.reserveSignature({ ...input, operation_id: "sign-disabled", request_digest: canonicalManagedSignerRequestDigest({ purpose: PURPOSE, key_id: "agent-key-1", bytes: Buffer.from("disabled") }) });
  await repo.startSignature({ operation_id: "sign-disabled", request_digest: second.request_digest, key_id: "agent-key-1", key_version: 1, claim_token: second.claim_token });
  await repo.emergencyDisable({ expected_version: 1, operation_id: "disable-after-reserve" });
  await assert.rejects(repo.commitSignature({ operation_id: "sign-disabled", request_digest: second.request_digest, key_id: "agent-key-1", key_version: 1, claim_token: second.claim_token, signature: SIGNATURE }), { code: CODES.SIGNING_CLAIM_LOST });
  assert.match(pool.calls.findLast(({ text }) => text.startsWith("UPDATE managed_signer_signing_idempotency"))?.text ?? "", /reserved_lifecycle_version/u);
});

test("purpose isolation and row-lock serialization hold across two repository instances", async () => {
  const pool = new FakePgPool();
  const agent = repository(pool, PURPOSE);
  const manifest = repository(pool, OTHER_PURPOSE);
  await agent.initialize({ snapshot: snapshot(PURPOSE) });
  await manifest.initialize({ snapshot: snapshot(OTHER_PURPOSE) });
  const results = await Promise.allSettled([
    agent.emergencyDisable({ expected_version: 1, operation_id: "disable-a" }),
    agent.rotate({ expected_version: 1, operation_id: "rotate-b", new_key: nextKey(), verification_until: "2026-08-14T13:00:00.000Z" })
  ]);
  assert.equal(results.filter((result) => result.status === "fulfilled").length, 1);
  assert.equal(results.filter((result) => result.status === "rejected").length, 1);
  assert.deepEqual((await manifest.snapshot()).purpose, OTHER_PURPOSE);
  await assert.rejects(manifest.lookupSignature({ purpose: PURPOSE, operation_id: "missing", request_digest: "c".repeat(64) }), { code: CODES.SIGNING_CONFLICT });
});
