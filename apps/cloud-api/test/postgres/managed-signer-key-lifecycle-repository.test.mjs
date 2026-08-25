import assert from "node:assert/strict";
import crypto from "node:crypto";
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
const KEY_LIFECYCLE_FUNCTIONS = Object.freeze({
  lifecycle_snapshot: "snapshot",
  lifecycle_initialize: "initialize",
  lifecycle_apply: "apply",
  signing_reserve: "reserve",
  signing_start: "start",
  signing_commit: "commit",
  signing_uncertain: "uncertain",
  signing_reconcile: "reconcile",
  signing_lookup: "lookup",
  signing_prune: "pruneSigning",
  lifecycle_operation_prune: "pruneLifecycle"
});
const EXPECTED_FUNCTIONS = Object.freeze([
  "agentpass_managed_signer_lifecycle_snapshot",
  "agentpass_managed_signer_lifecycle_initialize",
  "agentpass_managed_signer_lifecycle_apply",
  "agentpass_managed_signer_signing_reserve",
  "agentpass_managed_signer_signing_start",
  "agentpass_managed_signer_signing_commit",
  "agentpass_managed_signer_signing_uncertain",
  "agentpass_managed_signer_signing_reconcile",
  "agentpass_managed_signer_signing_lookup",
  "agentpass_managed_signer_signing_prune",
  "agentpass_managed_signer_lifecycle_operation_prune"
]);

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
    this.forcedEnvelopes = new Map();
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

    const match = text.match(/^SELECT public\.(agentpass_managed_signer_[a-z_]+)\(([^)]*)\) AS result$/u);
    if (!match || !EXPECTED_FUNCTIONS.includes(match[1])) {
      throw new Error(`unexpected non-0051 SQL: ${text}`);
    }
    const functionName = KEY_LIFECYCLE_FUNCTIONS[match[1].replace(/^agentpass_managed_signer_/u, "")]
      ?? KEY_LIFECYCLE_FUNCTIONS[match[1]];
    if (!functionName) throw new Error(`unexpected lifecycle function: ${match[1]}`);
    return this.callLifecycleFunction(owner, functionName, params);
  }

  async callLifecycleFunction(owner, functionName, params) {
    if (this.forcedEnvelopes.has(functionName)) return this.envelope(this.forcedEnvelopes.get(functionName));
    const purpose = typeof params[0] === "string" && params[0].startsWith("agentpass.") ? params[0] : PURPOSE;
    const lifecycle = this.state.lifecycles.get(purpose);
    if (functionName === "snapshot") return this.envelope(lifecycle ? { outcome: "ok", snapshot: this.snapshotFor(purpose) } : { outcome: "not_initialized" });
    if (functionName === "initialize") {
      const target = params.map((value) => this.parseJson(value)).find((value) => value?.keys && value?.purpose);
      const value = target ?? snapshot(purpose);
      if (!this.state.lifecycles.has(purpose)) {
        this.state.lifecycles.set(purpose, { purpose, algorithm: "ed25519", version: "1", max_keys: 4, max_verification_overlap_ms: "7776000000" });
        this.state.keys = new Map([...this.state.keys, ...value.keys.map((key, position) => [this.keyOf(purpose, key.key_id), this.dbKey(key, position)])]);
        return this.envelope({ outcome: "ok", snapshot: this.snapshotFor(purpose) });
      }
      return this.envelope({ outcome: "ok", snapshot: this.snapshotFor(purpose) });
    }
    if (functionName === "apply") return this.mutate(purpose, params);
    if (["reserve", "start", "commit", "uncertain", "reconcile", "lookup"].includes(functionName)) {
      return this.signingFunction(functionName, purpose, params);
    }
    if (functionName === "pruneSigning" || functionName === "pruneLifecycle") return this.envelope({ outcome: "ok", pruned: 0 });
    throw new Error(`unexpected lifecycle function: ${functionName}`);
  }

  envelope(result) { return { rows: [{ result }], rowCount: 1 }; }

  parseJson(value) {
    if (typeof value !== "string" || !value.startsWith("{")) return undefined;
    try { return JSON.parse(value); } catch { return undefined; }
  }

  keyOf(purpose, keyId) { return `${purpose}\u0000${keyId}`; }

  dbKey(key, position) {
    return { ...key, public_key_pem: key.public_key ?? null, key_position: position, key_version: Number(key.key_version), state_version: Number(key.state_version), verification_until: key.verification_until ?? null };
  }

  snapshotFor(purpose) {
    const lifecycle = this.state.lifecycles.get(purpose);
    const keys = [...this.state.keys.values()].filter((key) => key.purpose === purpose).sort((a, b) => a.key_position - b.key_position);
    return { version: Number(lifecycle.version), purpose, algorithm: lifecycle.algorithm, keys: keys.map(({ public_key_pem, key_position, ...key }) => ({ ...key, key_version: Number(key.key_version), state_version: Number(key.state_version), ...(public_key_pem ? { public_key: public_key_pem } : {}) })) };
  }

  mutate(purpose, params) {
    const lifecycle = this.state.lifecycles.get(purpose);
    if (!lifecycle) return this.envelope({ outcome: "not_initialized" });
    const operationId = params[1];
    const digest = params[2];
    const expectedVersion = Number(params[3]);
    const target = this.parseJson(params[4]);
    const previous = this.state.lifecycleOperations.get(`${purpose}\u0000${operationId}`);
    if (previous) {
      if (!Buffer.from(previous.request_digest).equals(Buffer.from(digest))) return this.envelope({ outcome: "conflict" });
      return this.envelope({ outcome: "ok", snapshot: structuredClone(previous.response_snapshot) });
    }
    const current = this.snapshotFor(purpose);
    if (current.version !== expectedVersion) return this.envelope({ outcome: "conflict", snapshot: current });
    if (!target || target.version !== current.version + 1) return this.envelope({ outcome: "configuration_conflict" });
    lifecycle.version = String(target.version);
    this.state.keys = new Map([...this.state.keys].filter(([key]) => !key.startsWith(`${purpose}\u0000`)));
    target.keys.forEach((key, position) => this.state.keys.set(this.keyOf(purpose, key.key_id), this.dbKey(key, position)));
    this.state.lifecycleOperations.set(`${purpose}\u0000${operationId}`, { request_digest: Buffer.from(digest), response_snapshot: structuredClone(target) });
    return this.envelope({ outcome: "ok", snapshot: target, transition: transitionName(current, target) });
  }

  signingFunction(functionName, purpose, params) {
    const operationId = params[1];
    const requestDigest = params[2];
    const keyId = functionName === "lookup" ? undefined : params[3];
    const keyVersion = functionName === "lookup" ? undefined : Number(params[4]);
    const rowKey = `${purpose}\u0000${operationId}`;
    let row = this.state.signing.get(rowKey);
    if (functionName === "lookup" && !row) return this.envelope({ outcome: "absent" });
    if (functionName === "reserve" && !row) {
      row = { purpose, operation_id: operationId, request_digest: requestDigest, key_id: keyId, key_version: keyVersion, status: "pending", signature: null, claim_token_digest: params[5], claim_expires_at: new Date(NOW + 30_000).toISOString(), provider_started_at: null, reserved_lifecycle_version: Number(this.state.lifecycles.get(purpose).version), provider_receipt_provider: null, provider_receipt_id: null, created_at: NOW_ISO, updated_at: NOW_ISO, expires_at: new Date(NOW + 86_400_000).toISOString() };
      this.state.signing.set(rowKey, row);
      return this.envelope({ outcome: "ok", record: this.signingRecord(row) });
    }
    if (!row) return this.envelope({ outcome: "claim_lost" });
    if (functionName !== "lookup" && (!Buffer.from(row.request_digest).equals(Buffer.from(requestDigest)) || row.key_id !== keyId || row.key_version !== keyVersion)) return this.envelope({ outcome: "conflict" });
    if (functionName === "reserve") {
      if (row.status === "pending" && Date.parse(row.claim_expires_at) <= NOW) {
        if (row.provider_started_at) { row.status = "uncertain"; row.claim_token_digest = null; row.claim_expires_at = null; }
        else {
          row.claim_token_digest = params[5];
          row.claim_expires_at = new Date(NOW + Number(params[6])).toISOString();
          row.expires_at = new Date(NOW + Number(params[7])).toISOString();
        }
      }
      if (row.status === "pending" && !Buffer.from(row.claim_token_digest).equals(Buffer.from(params[5]))) return this.envelope({ outcome: "pending", record: this.signingRecord(row) });
      if (row.status === "uncertain") return this.envelope({ outcome: "uncertain", record: this.signingRecord(row) });
      if (row.status === "aborted") {
        if (row.reserved_lifecycle_version !== Number(this.state.lifecycles.get(purpose).version)) return this.envelope({ outcome: "not_active" });
        row.status = "pending";
        row.claim_token_digest = params[5];
        row.claim_expires_at = new Date(NOW + Number(params[6])).toISOString();
        row.expires_at = new Date(NOW + Number(params[7])).toISOString();
        row.provider_started_at = null;
      }
      return this.envelope({ outcome: "ok", record: this.signingRecord(row) });
    }
    if (functionName === "start") {
      if (row.status === "committed") return this.envelope({ outcome: "ok", record: this.signingRecord(row) });
      if (row.status === "uncertain") return this.envelope({ outcome: "uncertain" });
      if (row.status !== "pending" || !Buffer.from(row.claim_token_digest).equals(Buffer.from(params[5])) || row.reserved_lifecycle_version !== Number(this.state.lifecycles.get(purpose).version)) return this.envelope({ outcome: "claim_lost" });
      row.provider_started_at = NOW_ISO;
    }
    if (functionName === "uncertain") {
      if (row.status === "committed") return this.envelope({ outcome: "ok", record: this.signingRecord(row) });
      if (row.status === "uncertain") return this.envelope({ outcome: "uncertain", record: this.signingRecord(row) });
      if (!Buffer.from(row.claim_token_digest).equals(Buffer.from(params[5]))) return this.envelope({ outcome: "claim_lost" });
      row.status = "uncertain"; row.claim_token_digest = null; row.claim_expires_at = null; row.provider_started_at ??= NOW_ISO;
      return this.envelope({ outcome: "uncertain", record: this.signingRecord(row) });
    }
    if (functionName === "commit" || functionName === "reconcile") {
      if (row.status === "committed") {
        const expectedSignature = params[functionName === "commit" ? 6 : 5];
        return Buffer.from(row.signature).equals(Buffer.from(expectedSignature)) ? this.envelope({ outcome: "ok", record: this.signingRecord(row) }) : this.envelope({ outcome: "conflict" });
      }
      if (functionName === "commit" && row.status === "uncertain") return this.envelope({ outcome: "uncertain" });
      if (functionName === "reconcile" && row.status === "pending") return this.envelope({ outcome: "pending" });
      if (row.reserved_lifecycle_version !== Number(this.state.lifecycles.get(purpose).version)) return this.envelope({ outcome: "not_active" });
      if (functionName === "commit" && !Buffer.from(row.claim_token_digest).equals(Buffer.from(params[5]))) return this.envelope({ outcome: "claim_lost" });
      row.status = "committed"; row.claim_token_digest = null; row.claim_expires_at = null;
      row.signature = params[functionName === "commit" ? 6 : 5];
      row.provider_receipt_provider = params[functionName === "commit" ? 7 : 6];
      row.provider_receipt_id = params[functionName === "commit" ? 8 : 7];
    }
    return this.envelope({ outcome: "ok", record: this.signingRecord(row) });
  }

  signingRecord(row) {
    return {
      purpose: row.purpose, operation_id: row.operation_id, request_digest: Buffer.from(row.request_digest).toString("hex"),
      key_id: row.key_id, key_version: row.key_version, state: row.status,
      created_at: row.created_at, updated_at: row.updated_at, expires_at: row.expires_at,
      reserved_lifecycle_version: row.reserved_lifecycle_version,
      ...(row.claim_expires_at ? { claim_expires_at: row.claim_expires_at } : {}),
      ...(row.provider_started_at ? { provider_started_at: row.provider_started_at } : {}),
      ...(row.signature ? { signature: Buffer.from(row.signature).toString("base64") } : {}),
      provider_receipt: row.provider_receipt_provider
        ? { provider: row.provider_receipt_provider, receipt_id: row.provider_receipt_id }
        : null
    };
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

function repository(pool, purpose = PURPOSE, options = {}) {
  return createPostgresManagedSignerKeyLifecycleRepository({ client: pool, purpose, now: () => NOW, ...options });
}

function transitionName(current, target) {
  if (target.keys.length === current.keys.length + 1) return current.keys.some((key) => key.state === "active") ? "rotate" : "restore-new-key";
  if (target.keys.every((key) => key.state === "emergency-disabled")) return "emergency-disable-all";
  return "single-key";
}

function assertFixedFunctionCall(call) {
  assert.equal(typeof call?.text, "string");
  const match = call.text.match(/^SELECT public\.(agentpass_managed_signer_[a-z_]+)\(([^)]*)\) AS result$/u);
  assert.ok(match, `not a fixed 0051 function call: ${call.text}`);
  assert.ok(EXPECTED_FUNCTIONS.includes(match[1]), `function is not allow-listed: ${match[1]}`);
  const placeholders = match[2] === "" ? [] : match[2].split(",");
  assert.deepEqual(placeholders.map((value) => value.replace(/::[a-z]+$/u, "")), placeholders.map((_, index) => `$${index + 1}`));
  assert.equal(call.params.length, placeholders.length);
  assert.doesNotMatch(call.text, /(?:FROM|INSERT|UPDATE|DELETE|TRUNCATE)\s/iu);
  assert.doesNotMatch(call.text, /(?:private_key|claim_token_digest)/iu);
  return match[1];
}

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest();
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
  assert.equal(migrations.find(({ name }) => name === "0038_managed_signer_fencing.sql")?.version, 38);
  assert.equal(migrations.find(({ name }) => name === "0039_managed_signer_provider_receipts.sql")?.version, 39);
});

test("0039 stores only closed provider receipt columns", async () => {
  const sql = await readFile(new URL("../../../../contracts/postgres/0039_managed_signer_provider_receipts.sql", import.meta.url), "utf8");
  assert.match(sql, /provider_receipt_provider/u);
  assert.match(sql, /provider_receipt_id/u);
  assert.match(sql, /managed_signer_provider_receipt_shape/u);
  assert.match(sql, /status = 'committed'/u);
  assert.doesNotMatch(sql, /provider_receipt\s+jsonb/iu);
  assert.doesNotMatch(sql, /private_key|raw_provider_response|credential_payload/iu);
});

test("0051 uses exactly the fixed public-schema function allowlist", async () => {
  const source = await readFile(new URL("../../src/postgres/managed-signer-key-lifecycle-repository.mjs", import.meta.url), "utf8");
  for (const name of EXPECTED_FUNCTIONS) assert.match(source, new RegExp(`public\\.${name}\\(`, "u"));
  assert.doesNotMatch(source, /(?:FROM|INSERT|UPDATE|DELETE|TRUNCATE)\s+managed_signer_/iu);
  assert.doesNotMatch(source, /SELECT\s+(?:purpose|key_id|operation_id)[\s\S]*FROM\s+managed_signer_/iu);

  const pool = new FakePgPool();
  const repo = repository(pool);
  await repo.initialize({ snapshot: snapshot() });
  await repo.snapshot();
  await repo.rotate({ expected_version: 1, operation_id: "rotate-allowlist", new_key: nextKey(), verification_until: "2026-08-14T13:00:00.000Z" });

  const firstDigest = canonicalManagedSignerRequestDigest({ purpose: PURPOSE, key_id: "agent-key-1", bytes: Buffer.from("allowlist-1") });
  const first = await repo.reserveSignature({ operation_id: "sign-allowlist-1", request_digest: firstDigest, key_id: "agent-key-1", key_version: 1 });
  await repo.startSignature({ operation_id: "sign-allowlist-1", request_digest: firstDigest, key_id: "agent-key-1", key_version: 1, claim_token: first.claim_token });
  await repo.fenceSignature({ operation_id: "sign-allowlist-1", request_digest: firstDigest, key_id: "agent-key-1", key_version: 1, claim_token: first.claim_token });
  await repo.commitSignature({ operation_id: "sign-allowlist-1", request_digest: firstDigest, key_id: "agent-key-1", key_version: 1, claim_token: first.claim_token, signature: SIGNATURE });

  const secondDigest = canonicalManagedSignerRequestDigest({ purpose: PURPOSE, key_id: "agent-key-2", bytes: Buffer.from("allowlist-2") });
  const second = await repo.reserveSignature({ operation_id: "sign-allowlist-2", request_digest: secondDigest, key_id: "agent-key-2", key_version: 2 });
  await repo.startSignature({ operation_id: "sign-allowlist-2", request_digest: secondDigest, key_id: "agent-key-2", key_version: 2, claim_token: second.claim_token });
  await repo.markSignatureUncertain({ operation_id: "sign-allowlist-2", request_digest: secondDigest, key_id: "agent-key-2", key_version: 2, claim_token: second.claim_token });
  await repo.reconcileSignature({ operation_id: "sign-allowlist-2", request_digest: secondDigest, key_id: "agent-key-2", key_version: 2, signature: SIGNATURE, provider_receipt: { provider: "fixture-kms", receipt_id: "receipt-allowlist", operation_id: "sign-allowlist-2", key_id: "agent-key-2", key_version: 2 } });
  await repo.lookupSignature({ operation_id: "sign-allowlist-1", request_digest: firstDigest, key_id: "agent-key-1", key_version: 1 });
  await repo.pruneSigningRecords({ before: "2027-08-15T00:00:00.000Z", limit: 10 });
  await repo.pruneLifecycleOperations({ before: "2027-08-15T00:00:00.000Z", limit: 10 });

  const databaseCalls = pool.calls.filter(({ text }) => text !== "BEGIN" && text !== "COMMIT" && text !== "ROLLBACK");
  const names = databaseCalls.map(assertFixedFunctionCall);
  assert.deepEqual([...new Set(names)].sort(), [...EXPECTED_FUNCTIONS].sort());
  assert.equal(databaseCalls.some(({ text }) => /\b(?:FROM|INSERT|UPDATE|DELETE|TRUNCATE)\b/iu.test(text)), false);
});

test("0051 rejects malformed, unknown, and closed-outcome envelopes", async () => {
  const malformed = [
    null,
    {},
    { outcome: "ok" },
    { outcome: "ok", snapshot: null },
    { outcome: "ok", snapshot: { ...snapshot(), unexpected: true } },
    { outcome: "ok", record: { state: "pending", claim_token_digest: "secret" } },
    { outcome: "error" },
    { outcome: "ok", unexpected: true },
    { outcome: "closed" }
  ];
  for (const envelope of malformed) {
    const pool = new FakePgPool();
    const repo = repository(pool);
    await repo.initialize({ snapshot: snapshot() });
    pool.forcedEnvelopes.set("snapshot", envelope);
    await assert.rejects(repo.snapshot(), (error) => error.code === CODES.DATABASE);
  }
});

test("0051 sends only claim-token SHA-256 bytea and never returns its digest", async () => {
  const rawToken = Buffer.alloc(32, 0x5a);
  const pool = new FakePgPool();
  const repo = repository(pool, PURPOSE, { randomBytes: () => Buffer.from(rawToken) });
  await repo.initialize({ snapshot: snapshot() });
  const requestDigest = canonicalManagedSignerRequestDigest({ purpose: PURPOSE, key_id: "agent-key-1", bytes: Buffer.from("raw-claim") });
  const reserved = await repo.reserveSignature({ operation_id: "sign-raw-claim", request_digest: requestDigest, key_id: "agent-key-1", key_version: 1 });
  const claimDigest = sha256(reserved.claim_token);
  const reserveCall = pool.calls.find(({ text }) => text.includes("_reserve("));
  assert.ok(reserveCall);
  assert.equal(reserveCall.params.some((value) => typeof value === "string" && value === reserved.claim_token), false);
  assert.equal(reserveCall.params.some((value) => Buffer.isBuffer(value) && value.equals(claimDigest)), true);
  assert.equal(reserveCall.params.some((value) => value instanceof Uint8Array && Buffer.from(value).equals(claimDigest)), true);
  assert.equal(JSON.stringify(reserved).includes("claim_token_digest"), false);
  assert.equal(JSON.stringify(reserved).includes(claimDigest.toString("hex")), false);
  assert.equal(JSON.stringify(pool.state.signing.get(`${PURPOSE}\u0000sign-raw-claim`)).includes(rawToken.toString("base64url")), false);

  await repo.startSignature({ operation_id: "sign-raw-claim", request_digest: requestDigest, key_id: "agent-key-1", key_version: 1, claim_token: reserved.claim_token });
  const startCall = pool.calls.findLast(({ text }) => text.includes("_start("));
  assert.equal(startCall.params.some((value) => Buffer.isBuffer(value) && value.equals(claimDigest)), true);
  assert.equal(startCall.params.some((value) => typeof value === "string" && value === reserved.claim_token), false);
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
  const partiallyDisabled = await repo.transitionKey({
    expected_version: 2,
    operation_id: "disable-retiring-key",
    key_id: "agent-key-1",
    to: "emergency-disabled"
  });
  assert.equal(partiallyDisabled.version, 3);
  const fullyDisabled = await repo.emergencyDisable({ expected_version: 3, operation_id: "disable-all-after-partial" });
  assert.equal(fullyDisabled.version, 4);
  assert.ok(fullyDisabled.keys.every((key) => key.state === "emergency-disabled" && key.state_version === 4));
  assert.equal(pool.calls.some(({ text }) => text.includes("agentpass_managed_signer_lifecycle_apply")), true);
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
  const receipt = { provider: "fixture-kms", receipt_id: "receipt-uncertain", operation_id: uncertain.operation_id, key_id: uncertain.key_id, key_version: uncertain.key_version };
  await second.reserveSignature(uncertain);
  const markedUncertain = await second.markSignatureUncertain(uncertain);
  assert.equal(markedUncertain.state, "uncertain");
  assert.deepEqual(await first.markSignatureUncertain(uncertain), markedUncertain);
  await assert.rejects(first.reserveSignature(uncertain), { code: CODES.SIGNING_UNCERTAIN });
  await assert.rejects(first.commitSignature({ ...uncertain, signature: SIGNATURE }), { code: CODES.SIGNING_UNCERTAIN });
  assert.equal((await first.reconcileSignature({ ...uncertain, signature: SIGNATURE, provider_receipt: receipt })).state, "committed");
  assert.deepEqual((await second.lookupSignature(uncertain)).provider_receipt, receipt);
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
  pool.state.signing.get(`${PURPOSE}\u0000${input.operation_id}`).expires_at = "2026-08-14T11:59:59.000Z";
  const reclaimed = await repo.reserveSignature(input);
  assert.equal(reclaimed.state, "pending");
  assert.notEqual(reclaimed.claim_token, first.claim_token);
  assert.equal(reclaimed.expires_at, new Date(NOW + 30 * 24 * 60 * 60 * 1000).toISOString());

  const started = await repo.startSignature({ ...input, claim_token: reclaimed.claim_token });
  assert.equal(typeof started.provider_started_at, "string");
  pool.state.signing.get(`${PURPOSE}\u0000${input.operation_id}`).claim_expires_at = "2026-08-14T11:59:59.000Z";
  await assert.rejects(repo.reserveSignature(input), { code: CODES.SIGNING_UNCERTAIN });

  const second = await repo.reserveSignature({ ...input, operation_id: "sign-disabled", request_digest: canonicalManagedSignerRequestDigest({ purpose: PURPOSE, key_id: "agent-key-1", bytes: Buffer.from("disabled") }) });
  await repo.startSignature({ operation_id: "sign-disabled", request_digest: second.request_digest, key_id: "agent-key-1", key_version: 1, claim_token: second.claim_token });
  const staleAbortedInput = { ...input, operation_id: "sign-stale-aborted", request_digest: canonicalManagedSignerRequestDigest({ purpose: PURPOSE, key_id: "agent-key-1", bytes: Buffer.from("stale-aborted") }) };
  await repo.reserveSignature(staleAbortedInput);
  const staleAbortedRow = pool.state.signing.get(`${PURPOSE}\u0000${staleAbortedInput.operation_id}`);
  staleAbortedRow.status = "aborted";
  staleAbortedRow.claim_token_digest = null;
  staleAbortedRow.claim_expires_at = null;
  await repo.emergencyDisable({ expected_version: 1, operation_id: "disable-after-reserve" });
  await assert.rejects(repo.commitSignature({ operation_id: "sign-disabled", request_digest: second.request_digest, key_id: "agent-key-1", key_version: 1, claim_token: second.claim_token, signature: SIGNATURE }), { code: CODES.SIGNING_CLAIM_LOST });
  await assert.rejects(repo.reserveSignature(staleAbortedInput), { code: "ERR_MANAGED_SIGNER_KEY_LIFECYCLE_NOT_ACTIVE" });
  assert.match(pool.calls.findLast(({ text }) => text.includes("agentpass_managed_signer_signing_commit"))?.text ?? "", /signing_commit/u);
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
