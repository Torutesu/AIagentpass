import assert from "node:assert/strict";
import crypto from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { WebAuthnCeremonyError, WEBAUTHN_ERROR_CODES } from "../src/human-auth/webauthn/ceremony.mjs";
import { createPostgresWebAuthnCeremony, PostgresWebAuthnCeremonyError, POSTGRES_WEBAUTHN_SCHEMA_REQUIREMENTS } from "../src/human-auth/webauthn/postgres-ceremony.mjs";

const ids = Object.freeze({
  session: "11111111-1111-4111-8111-111111111111",
  member: "22222222-2222-4222-8222-222222222222",
  organization: "33333333-3333-4333-8333-333333333333",
  challenge: "44444444-4444-4444-8444-444444444444"
});
const context = Object.freeze({
  session_id: ids.session,
  organization_id: ids.organization,
  operation: "device.enrollment.issue",
  rp_id: "console.example.test",
  origin: "https://console.example.test",
  user_verification: "required"
});
const contextHash = "a".repeat(64);

function clock(start = 1_900_000_000_000) {
  let value = start;
  return { now: () => value, advance: (milliseconds) => { value += milliseconds; } };
}

function randomSource() {
  let index = 0;
  const uuids = [ids.challenge, "55555555-5555-4555-8555-555555555555", "66666666-6666-4666-8666-666666666666"];
  return {
    uuid: () => uuids[index++] ?? crypto.randomUUID(),
    bytes: () => Buffer.alloc(32, index)
  };
}

function assertion(challenge, overrides = {}) {
  const merged = { ...context, ...overrides };
  const credential_id = Buffer.from("credential-01").toString("base64url");
  const client_data_json = Buffer.from(JSON.stringify({ type: "webauthn.get", challenge, origin: merged.origin, crossOrigin: false })).toString("base64url");
  const rpHash = crypto.createHash("sha256").update(merged.rp_id).digest();
  const authenticator_data = Buffer.concat([rpHash, Buffer.from([0x05]), Buffer.from([0, 0, 0, 1])]).toString("base64url");
  return {
    challenge,
    ...merged,
    credential_id,
    client_data_json,
    authenticator_data,
    signature: Buffer.alloc(64, 7).toString("base64url")
  };
}

function rowFromParams(params) {
  const [id, session_id, organization_id, operation, contextHash, challengeHash, createdAt, expiresAt, rp_id, origin, user_verification] = params;
  return {
    id,
    session_id,
    member_id: ids.member,
    organization_id,
    ceremony: "authentication",
    operation,
    context_hash_hex: contextHash === null ? null : Buffer.from(contextHash).toString("hex"),
    challenge_hash_hex: Buffer.from(challengeHash).toString("hex"),
    created_at: new Date(createdAt),
    expires_at: new Date(expiresAt),
    rp_id,
    origin,
    user_verification,
    status: "pending",
    consume_started_at: null,
    consumed_at: null,
    failed_at: null
  };
}

class FakePgClient {
  constructor({ now = () => Date.now(), store = undefined, failQuery = undefined, failComplete = false } = {}) {
    this.now = now;
    this.failQuery = failQuery;
    this.failComplete = failComplete;
    this.calls = [];
    this.store = store ?? {
      rows: new Map(),
      sessions: new Map([[ids.session, { member_id: ids.member, organization_id: ids.organization, revoked_at: null, expires_at: new Date(2_000_000_000_000), role: "owner" }]])
    };
    this.rows = this.store.rows;
    this.sessions = this.store.sessions;
  }

  async query(text, params = []) {
    const sql = String(text).trim().replace(/\s+/g, " ");
    this.calls.push({ text: String(text), sql, params });
    if (this.failQuery && sql.includes(this.failQuery)) throw new Error(this.failQuery);
    if (sql === "BEGIN" || sql === "COMMIT" || sql === "ROLLBACK") return { rows: [], rowCount: 0 };
    if (sql.startsWith("SELECT pg_advisory_xact_lock")) return { rows: [{ pg_advisory_xact_lock: null }], rowCount: 1 };
    if (sql.startsWith("UPDATE webauthn_challenges SET status = 'expired'")) {
      const cutoff = new Date(params[0]).getTime();
      for (const row of this.rows.values()) if (row.status === "pending" && row.consumed_at === null && row.expires_at.getTime() <= cutoff) row.status = "expired";
      return { rows: [], rowCount: 0 };
    }
    if (sql.startsWith("UPDATE webauthn_challenges SET status = 'failed'") && sql.includes("consume_started_at <= $2")) {
      const failedAt = new Date(params[0]);
      const cutoff = new Date(params[1]).getTime();
      const onlyId = sql.includes("WHERE id = $3") ? params[2] : undefined;
      const reaped = [];
      for (const row of this.rows.values()) {
        if (onlyId !== undefined && row.id !== onlyId) continue;
        if (row.ceremony !== "authentication" || row.status !== "consuming" || row.consumed_at !== null || row.consume_started_at === null || row.consume_started_at.getTime() > cutoff) continue;
        row.status = "failed";
        row.failed_at = failedAt;
        row.consumed_at = failedAt;
        reaped.push({ id: row.id });
      }
      return { rows: reaped, rowCount: reaped.length };
    }
    if (sql.startsWith("SELECT count(*)::text AS pending_count")) {
      const cutoff = new Date(params[0]).getTime();
      const count = [...this.rows.values()].filter((row) => ["pending", "consuming"].includes(row.status) && row.consumed_at === null && row.expires_at.getTime() > cutoff).length;
      return { rows: [{ pending_count: String(count) }], rowCount: 1 };
    }
    if (sql.startsWith("INSERT INTO webauthn_challenges")) {
      const row = rowFromParams(params);
      const session = this.sessions.get(row.session_id);
      if (!session || session.organization_id !== row.organization_id || session.revoked_at !== null || session.expires_at.getTime() <= row.created_at.getTime()) return { rows: [], rowCount: 0 };
      if ([...this.rows.values()].some((existing) => existing.status === "pending" && existing.session_id === row.session_id && existing.organization_id === row.organization_id && existing.operation === row.operation)) {
        const error = new Error("unique constraint");
        error.code = "23505";
        throw error;
      }
      this.rows.set(row.id, row);
      return { rows: [this.clone(row)], rowCount: 1 };
    }
    if (sql.startsWith("SELECT id, session_id, member_id, organization_id")) {
      if (sql.includes("WHERE id = $1")) {
        const row = this.rows.get(params[0]);
        return { rows: row ? [this.clone(row)] : [], rowCount: row ? 1 : 0 };
      }
      return { rows: [...this.rows.values()].sort((left, right) => left.created_at - right.created_at).map((row) => this.clone(row)), rowCount: this.rows.size };
    }
    if (sql.startsWith("UPDATE webauthn_challenges SET status = 'consuming'")) {
      const row = this.rows.get(params[0]);
      const at = new Date(params[1]);
      if (!row || row.status !== "pending" || row.consumed_at !== null || row.expires_at <= at) return { rows: [], rowCount: 0 };
      row.status = "consuming";
      row.consume_started_at = at;
      return { rows: [this.clone(row)], rowCount: 1 };
    }
    if (sql.startsWith("UPDATE webauthn_challenges SET status = 'failed'")) {
      const row = this.rows.get(params[0]);
      const at = new Date(params[1]);
      if (!row || row.status !== "consuming" || row.consumed_at !== null) return { rows: [], rowCount: 0 };
      row.status = "failed";
      row.failed_at = at;
      row.consumed_at = at;
      return { rows: [{ id: row.id, status: row.status, failed_at: row.failed_at, consumed_at: row.consumed_at }], rowCount: 1 };
    }
    if (sql.startsWith("UPDATE webauthn_challenges SET status = 'consumed'")) {
      if (this.failComplete) return { rows: [], rowCount: 0 };
      const row = this.rows.get(params[0]);
      const at = new Date(params[1]);
      if (!row || row.status !== "consuming" || row.consumed_at !== null) return { rows: [], rowCount: 0 };
      row.status = "consumed";
      row.consumed_at = at;
      return { rows: [{ id: row.id, status: row.status, consumed_at: row.consumed_at }], rowCount: 1 };
    }
    throw new Error(`unhandled SQL: ${sql}`);
  }

  clone(row) {
    return { ...row, created_at: new Date(row.created_at), expires_at: new Date(row.expires_at), consume_started_at: row.consume_started_at && new Date(row.consume_started_at), consumed_at: row.consumed_at && new Date(row.consumed_at), failed_at: row.failed_at && new Date(row.failed_at) };
  }
}

class FakePgPool {
  constructor({ now = () => Date.now() } = {}) {
    this.store = {
      rows: new Map(),
      sessions: new Map([[ids.session, { member_id: ids.member, organization_id: ids.organization, revoked_at: null, expires_at: new Date(2_000_000_000_000), role: "owner" }]])
    };
    this.now = now;
    this.queryClient = new FakePgClient({ now, store: this.store });
    this.queryCalls = 0;
    this.connectCalls = 0;
    this.releaseCalls = 0;
    this.activeConnections = 0;
    this.connections = [];
  }

  async query(text, params = []) {
    this.queryCalls += 1;
    return this.queryClient.query(text, params);
  }

  async connect() {
    this.connectCalls += 1;
    const connection = new FakePgClient({ now: this.now, store: this.store });
    const originalCalls = connection.calls;
    let released = false;
    connection.release = () => {
      if (released) throw new Error("connection released twice");
      released = true;
      this.releaseCalls += 1;
      this.activeConnections -= 1;
    };
    this.activeConnections += 1;
    this.connections.push({ connection, calls: originalCalls });
    await new Promise((resolve) => setImmediate(resolve));
    return connection;
  }
}

function create({ verifyAssertion, time = clock(), random = randomSource(), maxPending, verifierTimeoutMs, client: providedClient, metrics } = {}) {
  const client = providedClient ?? new FakePgClient({ now: time.now });
  const coordinator = createPostgresWebAuthnCeremony({ client, verifyAssertion: verifyAssertion ?? (async (input) => ({ verified: true, credential_id: input.assertion.credential_id })), now: time.now, ttlMs: 60_000, random, maxPending, verifierTimeoutMs, metrics });
  return { client, coordinator, time };
}

test("persists only the challenge digest and binds the issued row to the exact context", async () => {
  const { client, coordinator } = create({});
  const issued = await coordinator.begin(context);
  assert.match(issued.challenge, /^[A-Za-z0-9_-]{43}$/);
  const persisted = [...client.rows.values()][0];
  assert.equal(persisted.challenge_hash_hex, crypto.createHash("sha256").update(issued.challenge, "utf8").digest("hex"));
  assert.equal(JSON.stringify(persisted).includes(issued.challenge), false);
  assert.equal(client.calls.some(({ params }) => params.some((value) => value === issued.challenge)), false);
  assert.match(client.calls.find(({ sql }) => sql.startsWith("INSERT INTO webauthn_challenges")).text, /rp_id, origin, user_verification, status/);
  assert.equal(issued.challenge_expires_at, new Date(Date.parse([...client.rows.values()][0].created_at) + 60_000).toISOString());
});

test("persists and claims the optional resource context hash exactly", async () => {
  const { client, coordinator } = create({});
  const issued = await coordinator.begin({ ...context, context_hash: contextHash });
  const persisted = [...client.rows.values()][0];
  assert.equal(persisted.context_hash_hex, contextHash);
  await assert.rejects(
    () => coordinator.consume({ ...assertion(issued.challenge, { context_hash: "b".repeat(64) }), challenge_id: issued.challenge_id }),
    (error) => error.code === WEBAUTHN_ERROR_CODES.BINDING_MISMATCH
  );
  const result = await coordinator.consume({ ...assertion(issued.challenge, { context_hash: contextHash }), challenge_id: issued.challenge_id });
  assert.equal(result.verified, true);
  assert.equal(result.context_hash, contextHash);
  const claim = client.calls.find(({ sql }) => sql.startsWith("UPDATE webauthn_challenges SET status = 'consuming'"));
  assert.equal(Buffer.isBuffer(claim.params[8]), true);
  assert.equal(claim.params[8].toString("hex"), contextHash);
  assert.match(claim.text, /session_id = \$3/);
  assert.match(claim.text, /organization_id = \$4/);
  assert.match(claim.text, /operation = \$5/);
  assert.match(claim.text, /challenge_hash = \$10/);
});

test("consumes through an atomic pending-to-consuming CAS and returns the same public result", async () => {
  const calls = [];
  const { client, coordinator } = create({ verifyAssertion: async (input) => { calls.push(input); return { verified: true, credential_id: input.assertion.credential_id, sign_count: 1 }; } });
  const issued = await coordinator.begin(context);
  const result = await coordinator.consume({ ...assertion(issued.challenge), challenge_id: issued.challenge_id });
  assert.deepEqual(result, {
    verified: true,
    assertion_id: issued.challenge_id,
    session_id: ids.session,
    organization_id: ids.organization,
    operation: context.operation,
    authenticated_at: 1_900_000_000_000,
    credential_id_digest: crypto.createHash("sha256").update(Buffer.from("credential-01").toString("base64url"), "utf8").digest("hex")
  });
  assert.equal(calls.length, 1);
  assert.equal(calls[0].ceremony.expected_challenge, issued.challenge);
  assert.match(client.calls.find(({ sql }) => sql.startsWith("UPDATE webauthn_challenges SET status = 'consuming'")).text, /status = 'pending'/);
  assert.equal([...client.rows.values()][0].status, "consumed");
});

test("accepts signed clientData extension members emitted by real browsers", async () => {
  const { coordinator } = create();
  const issued = await coordinator.begin(context);
  const request = { ...assertion(issued.challenge), challenge_id: issued.challenge_id };
  request.client_data_json = Buffer.from(JSON.stringify({
    type: "webauthn.get", challenge: issued.challenge, origin: context.origin, crossOrigin: false,
    other_keys_can_be_added_here: "do not compare clientDataJSON against a template"
  })).toString("base64url");
  assert.equal((await coordinator.consume(request)).verified, true);
});

test("acquires and releases an independent transaction client for each concurrent begin", async () => {
  const time = clock();
  const random = randomSource();
  const pool = new FakePgPool({ now: time.now });
  const coordinator = createPostgresWebAuthnCeremony({
    client: pool,
    verifyAssertion: async (input) => ({ verified: true, credential_id: input.assertion.credential_id }),
    now: time.now,
    ttlMs: 60_000,
    random
  });
  const [first, second] = await Promise.all([
    coordinator.begin(context),
    coordinator.begin({ ...context, operation: "organization.emergency_stop" })
  ]);
  assert.notEqual(first.challenge_id, second.challenge_id);
  assert.equal(pool.connectCalls, 2);
  assert.equal(pool.releaseCalls, 2);
  assert.equal(pool.activeConnections, 0);
  assert.equal(pool.queryCalls, 0, "begin must not run transaction statements through pool.query");
  for (const { calls } of pool.connections) {
    assert.deepEqual(calls.filter(({ sql }) => ["BEGIN", "COMMIT", "ROLLBACK"].includes(sql)).map(({ sql }) => sql), ["BEGIN", "COMMIT"]);
  }

  await coordinator.consume({ ...assertion(first.challenge), challenge_id: first.challenge_id });
  assert.ok(pool.queryCalls > 0, "query-only consume operations may use pool.query");
});

test("allows only one concurrent verifier and exposes busy/replayed states", async () => {
  let release;
  const gate = new Promise((resolve) => { release = resolve; });
  let calls = 0;
  const { coordinator } = create({ verifyAssertion: async (input) => { calls += 1; await gate; return { verified: true, credential_id: input.assertion.credential_id }; } });
  const issued = await coordinator.begin(context);
  const request = { ...assertion(issued.challenge), challenge_id: issued.challenge_id };
  const first = coordinator.consume(request);
  await new Promise((resolve) => setImmediate(resolve));
  await assert.rejects(() => coordinator.consume(request), (error) => error instanceof WebAuthnCeremonyError && error.code === WEBAUTHN_ERROR_CODES.CHALLENGE_BUSY);
  release();
  await first;
  assert.equal(calls, 1);
  await assert.rejects(() => coordinator.consume(request), (error) => error.code === WEBAUTHN_ERROR_CODES.CHALLENGE_REPLAYED);
});

test("burns a claimed challenge after verifier failure and never persists assertion fields", async () => {
  const { client, coordinator } = create({ verifyAssertion: async () => { throw new Error("invalid signature"); } });
  const issued = await coordinator.begin(context);
  const request = { ...assertion(issued.challenge), challenge_id: issued.challenge_id };
  await assert.rejects(() => coordinator.consume(request), (error) => error instanceof WebAuthnCeremonyError && error.code === WEBAUTHN_ERROR_CODES.VERIFICATION_FAILED);
  assert.equal([...client.rows.values()][0].status, "failed");
  await assert.rejects(() => coordinator.consume(request), (error) => error.code === WEBAUTHN_ERROR_CODES.CHALLENGE_REPLAYED);
  const assertionValues = [request.credential_id, request.client_data_json, request.authenticator_data, request.signature];
  assert.equal(client.calls.some(({ params }) => params.some((value) => assertionValues.includes(value))), false);
});

test("checks every binding before claiming and rejects expiry", async () => {
  const time = clock();
  const { client, coordinator } = create({ time });
  const issued = await coordinator.begin(context);
  await assert.rejects(() => coordinator.consume({ ...assertion(issued.challenge, { origin: "https://other.example.test" }), challenge_id: issued.challenge_id }), (error) => error.code === WEBAUTHN_ERROR_CODES.BINDING_MISMATCH);
  assert.equal(client.calls.some(({ sql }) => sql.startsWith("UPDATE webauthn_challenges SET status = 'consuming'")), false);
  time.advance(60_000);
  await assert.rejects(() => coordinator.consume({ ...assertion(issued.challenge), challenge_id: issued.challenge_id }), (error) => error.code === WEBAUTHN_ERROR_CODES.CHALLENGE_EXPIRED);
});

test("fails closed on malformed PostgreSQL rows", async () => {
  const { client, coordinator } = create({});
  const issued = await coordinator.begin(context);
  [...client.rows.values()][0].origin = null;
  await assert.rejects(() => coordinator.consume({ ...assertion(issued.challenge), challenge_id: issued.challenge_id }), (error) => error instanceof PostgresWebAuthnCeremonyError && error.code === "ERR_WEBAUTHN_STORAGE_RESULT");
});

test("reaps a crashed consuming claim before reporting replay", async () => {
  const time = clock();
  const metrics = { stale: 0, replay: 0, recordHumanAuthStaleClaimRecovery(amount = 1) { this.stale += amount; }, recordHumanAuthReplayDenial(amount = 1) { this.replay += amount; } };
  const { client, coordinator } = create({ time, metrics });
  const issued = await coordinator.begin(context);
  const row = [...client.rows.values()][0];
  row.status = "consuming";
  row.consume_started_at = new Date(time.now() - 40_000);
  await assert.rejects(() => coordinator.consume({ ...assertion(issued.challenge), challenge_id: issued.challenge_id }), (error) => error.code === WEBAUTHN_ERROR_CODES.CHALLENGE_REPLAYED);
  assert.equal(row.status, "failed");
  assert.equal(row.consumed_at instanceof Date, true);
  assert.equal(metrics.stale, 1);
  assert.equal(metrics.replay, 1);
});

test("times out a stuck verifier, burns the claim, and keeps the error secret-free", async () => {
  const metrics = { timeouts: 0, recordHumanAuthVerifierTimeout(amount = 1) { this.timeouts += amount; } };
  const { client, coordinator } = create({
    verifierTimeoutMs: 1_000,
    verifyAssertion: async () => new Promise(() => {}),
    metrics
  });
  const issued = await coordinator.begin(context);
  await assert.rejects(() => coordinator.consume({ ...assertion(issued.challenge), challenge_id: issued.challenge_id }), (error) => {
    assert.equal(error.cause, undefined);
    return error instanceof WebAuthnCeremonyError && error.code === WEBAUTHN_ERROR_CODES.VERIFICATION_FAILED;
  });
  assert.equal([...client.rows.values()][0].status, "failed");
  assert.equal(metrics.timeouts, 1);
});

test("burns a claim when completion loses its storage result", async () => {
  const time = clock();
  const client = new FakePgClient({ now: time.now, failComplete: true });
  const { coordinator } = create({ client, time });
  const issued = await coordinator.begin(context);
  await assert.rejects(() => coordinator.consume({ ...assertion(issued.challenge), challenge_id: issued.challenge_id }), (error) => {
    assert.equal(error.cause, undefined);
    return error instanceof PostgresWebAuthnCeremonyError && error.code === "ERR_WEBAUTHN_CLAIM_LOST";
  });
  assert.equal([...client.rows.values()][0].status, "failed");
  await assert.rejects(() => coordinator.consume({ ...assertion(issued.challenge), challenge_id: issued.challenge_id }), (error) => error.code === WEBAUTHN_ERROR_CODES.CHALLENGE_REPLAYED);
});

test("database errors remain secret-free", async () => {
  const secret = "postgres-assertion-secret";
  const time = clock();
  const client = new FakePgClient({ now: time.now, failQuery: "SELECT id, session_id, member_id" });
  const { coordinator } = create({ client, time });
  const issued = await coordinator.begin(context);
  await assert.rejects(() => coordinator.consume({ ...assertion(issued.challenge), challenge_id: issued.challenge_id }), (error) => {
    assert.equal(error.cause, undefined);
    assert.doesNotMatch(error.message, new RegExp(secret, "u"));
    assert.doesNotMatch(JSON.stringify(error), new RegExp(secret, "u"));
    return error instanceof PostgresWebAuthnCeremonyError && error.code === "ERR_WEBAUTHN_STORAGE";
  });
});

test("does not complete a claim after the challenge expires during verification", async () => {
  const time = clock();
  const { client, coordinator } = create({
    time,
    verifyAssertion: async (input) => {
      time.advance(60_001);
      return { verified: true, credential_id: input.assertion.credential_id };
    }
  });
  const issued = await coordinator.begin(context);
  await assert.rejects(() => coordinator.consume({ ...assertion(issued.challenge), challenge_id: issued.challenge_id }), (error) => error.code === WEBAUTHN_ERROR_CODES.CHALLENGE_EXPIRED);
  assert.equal([...client.rows.values()][0].status, "failed");
});

test("binds the coordinator requirements to the reviewed 0003 migration", async () => {
  assert.equal(POSTGRES_WEBAUTHN_SCHEMA_REQUIREMENTS.migration, "0003_webauthn_challenge_bindings.sql");
  const sql = await readFile(new URL("../../../contracts/postgres/0003_webauthn_challenge_bindings.sql", import.meta.url), "utf8");
  for (const qualified of POSTGRES_WEBAUTHN_SCHEMA_REQUIREMENTS.columns) assert.match(sql, new RegExp(`ADD COLUMN ${qualified.split(".")[1]}`));
  assert.match(sql, /DROP INDEX webauthn_challenges_one_live_operation/);
  assert.match(sql, /DROP INDEX webauthn_challenges_expiry/);
  assert.match(sql, /status IN \('pending', 'consuming'\) AND consumed_at IS NULL/g);
});
