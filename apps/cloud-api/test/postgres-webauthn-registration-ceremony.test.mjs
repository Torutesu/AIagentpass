import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import { WebAuthnRegistrationError, WEBAUTHN_REGISTRATION_ERROR_CODES } from "../src/human-auth/webauthn/registration.mjs";
import {
  createPostgresWebAuthnRegistrationCeremony,
  PostgresWebAuthnRegistrationCeremonyError,
  POSTGRES_WEBAUTHN_REGISTRATION_SCHEMA_REQUIREMENTS
} from "../src/human-auth/webauthn/postgres-registration-ceremony.mjs";

const ids = Object.freeze({
  session: "11111111-1111-4111-8111-111111111111",
  member: "22222222-2222-4222-8222-222222222222",
  organization: "33333333-3333-4333-8333-333333333333",
  challenge: "44444444-4444-4444-8444-444444444444"
});
const context = Object.freeze({
  session_id: ids.session,
  member_id: ids.member,
  organization_id: ids.organization,
  operation: "human.webauthn.registration",
  rp_id: "console.example.test",
  origin: "https://console.example.test",
  user_verification: "required"
});

function clock(start = 1_900_000_000_000) {
  let value = start;
  return { now: () => value, advance: (milliseconds) => { value += milliseconds; } };
}

function randomSource() {
  let index = 0;
  const uuids = [ids.challenge, "55555555-5555-4555-8555-555555555555", "66666666-6666-4666-8666-666666666666"];
  return { uuid: () => uuids[index++] ?? crypto.randomUUID(), bytes: () => Buffer.alloc(32, index + 9) };
}

function registration(challenge, overrides = {}) {
  const merged = { ...context, ...overrides };
  const credential_id = Buffer.alloc(32, 4).toString("base64url");
  const client_data_json = Buffer.from(JSON.stringify({ type: "webauthn.create", challenge, origin: merged.origin, crossOrigin: false })).toString("base64url");
  return {
    ...merged,
    challenge,
    challenge_id: ids.challenge,
    credential_id,
    client_data_json,
    attestation_object: Buffer.from("attestation-only-in-memory").toString("base64url"),
    transports: ["internal"]
  };
}

function rowFromParams(params) {
  const [id, session_id, member_id, organization_id, operation, challengeHash, createdAt, expiresAt, rp_id, origin, user_verification] = params;
  return {
    id,
    session_id,
    member_id,
    organization_id,
    ceremony: "registration",
    operation,
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
  constructor({ store, now = () => Date.now(), failQuery = undefined, failComplete = false } = {}) {
    this.now = now;
    this.failQuery = failQuery;
    this.failComplete = failComplete;
    this.calls = [];
    this.store = store ?? { rows: new Map(), sessions: new Map([[ids.session, { member_id: ids.member, organization_id: ids.organization, revoked_at: null, expires_at: new Date(2_000_000_000_000), role: "owner" }]]) };
    this.rows = this.store.rows;
    this.sessions = this.store.sessions;
  }

  async query(text, params = []) {
    const sql = String(text).trim().replace(/\s+/g, " ");
    this.calls.push({ text: String(text), sql, params });
    if (this.failQuery && sql.includes(this.failQuery)) throw new Error(this.failQuery);
    if (["BEGIN", "COMMIT", "ROLLBACK"].includes(sql)) return { rows: [], rowCount: 0 };
    if (sql.startsWith("SELECT pg_advisory_xact_lock")) return { rows: [{ pg_advisory_xact_lock: null }], rowCount: 1 };
    if (sql.startsWith("UPDATE webauthn_challenges SET status = 'expired'")) {
      const cutoff = new Date(params[0]).getTime();
      const expired = [];
      for (const row of this.rows.values()) if (row.ceremony === "registration" && row.status === "pending" && row.consumed_at === null && row.expires_at.getTime() <= cutoff) { row.status = "expired"; expired.push({ id: row.id }); }
      return { rows: expired, rowCount: expired.length };
    }
    if (sql.startsWith("UPDATE webauthn_challenges SET status = 'failed'") && sql.includes("consume_started_at <= $2")) {
      const failedAt = new Date(params[0]);
      const cutoff = new Date(params[1]).getTime();
      const onlyId = sql.includes("WHERE id = $3") ? params[2] : undefined;
      const reaped = [];
      for (const row of this.rows.values()) {
        if (onlyId !== undefined && row.id !== onlyId) continue;
        if (row.ceremony !== "registration" || row.status !== "consuming" || row.consumed_at !== null || row.consume_started_at === null || row.consume_started_at.getTime() > cutoff) continue;
        row.status = "failed";
        row.failed_at = failedAt;
        row.consumed_at = failedAt;
        reaped.push({ id: row.id });
      }
      return { rows: reaped, rowCount: reaped.length };
    }
    if (sql.startsWith("SELECT count(*)::text AS pending_count")) {
      const cutoff = new Date(params[0]).getTime();
      const count = [...this.rows.values()].filter((row) => row.ceremony === "registration" && ["pending", "consuming"].includes(row.status) && row.consumed_at === null && row.expires_at.getTime() > cutoff).length;
      return { rows: [{ pending_count: String(count) }], rowCount: 1 };
    }
    if (sql.startsWith("INSERT INTO webauthn_challenges")) {
      const row = rowFromParams(params);
      const session = this.sessions.get(row.session_id);
      if (!session || session.member_id !== row.member_id || session.organization_id !== row.organization_id || session.revoked_at !== null || session.expires_at.getTime() <= row.created_at.getTime()) return { rows: [], rowCount: 0 };
      if ([...this.rows.values()].some((existing) => existing.ceremony === "registration" && existing.status === "pending" && existing.session_id === row.session_id && existing.organization_id === row.organization_id && existing.operation === row.operation)) {
        const error = new Error("unique constraint");
        error.code = "23505";
        throw error;
      }
      this.rows.set(row.id, row);
      return { rows: [this.clone(row)], rowCount: 1 };
    }
    if (sql.startsWith("SELECT id, session_id, member_id, organization_id")) {
      const row = this.rows.get(params[0]);
      return row ? { rows: [this.clone(row)], rowCount: 1 } : { rows: [], rowCount: 0 };
    }
    if (sql.startsWith("UPDATE webauthn_challenges SET status = 'consuming'")) {
      const row = this.rows.get(params[0]);
      const at = new Date(params[1]);
      if (!row || row.ceremony !== "registration" || row.status !== "pending" || row.consumed_at !== null || row.expires_at <= at) return { rows: [], rowCount: 0 };
      row.status = "consuming";
      row.consume_started_at = at;
      return { rows: [this.clone(row)], rowCount: 1 };
    }
    if (sql.startsWith("UPDATE webauthn_challenges SET status = 'failed'")) {
      const row = this.rows.get(params[0]);
      const at = new Date(params[1]);
      if (!row || row.ceremony !== "registration" || row.status !== "consuming" || row.consumed_at !== null) return { rows: [], rowCount: 0 };
      row.status = "failed";
      row.failed_at = at;
      row.consumed_at = at;
      return { rows: [{ id: row.id, status: row.status, failed_at: row.failed_at, consumed_at: row.consumed_at }], rowCount: 1 };
    }
    if (sql.startsWith("UPDATE webauthn_challenges SET status = 'consumed'")) {
      if (this.failComplete) return { rows: [], rowCount: 0 };
      const row = this.rows.get(params[0]);
      const at = new Date(params[1]);
      if (!row || row.ceremony !== "registration" || row.status !== "consuming" || row.consumed_at !== null) return { rows: [], rowCount: 0 };
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
  constructor({ now }) {
    this.store = { rows: new Map(), sessions: new Map([[ids.session, { member_id: ids.member, organization_id: ids.organization, revoked_at: null, expires_at: new Date(2_000_000_000_000), role: "owner" }]]) };
    this.now = now;
    this.connectCalls = 0;
    this.releaseCalls = 0;
    this.queryCalls = 0;
    this.connections = [];
  }

  async query(text, params = []) { this.queryCalls += 1; return new FakePgClient({ store: this.store, now: this.now }).query(text, params); }

  async connect() {
    this.connectCalls += 1;
    const connection = new FakePgClient({ store: this.store, now: this.now });
    let released = false;
    connection.release = () => { if (released) throw new Error("released twice"); released = true; this.releaseCalls += 1; };
    this.connections.push(connection);
    return connection;
  }
}

function create({ verifyAttestation, time = clock(), random = randomSource(), maxPending, client = new FakePgClient({ now: time.now }), metrics } = {}) {
  const ceremony = createPostgresWebAuthnRegistrationCeremony({
    client,
    verifyAttestation: verifyAttestation ?? (async (input) => ({ verified: true, credential_id: input.attestation.credential_id, public_key: Buffer.alloc(65, 8), sign_count: 0, transports: ["internal"], user_verified: true })),
    now: time.now,
    ttlMs: 60_000,
    random,
    maxPending,
    metrics
  });
  return { client, ceremony, time };
}

test("persists only a challenge digest and binds registration to session/member/org/context", async () => {
  const { client, ceremony } = create();
  const issued = await ceremony.begin(context);
  const persisted = [...client.rows.values()][0];
  assert.match(issued.challenge, /^[A-Za-z0-9_-]{43}$/);
  assert.equal(persisted.ceremony, "registration");
  assert.equal(persisted.member_id, ids.member);
  assert.equal(persisted.challenge_hash_hex, crypto.createHash("sha256").update(issued.challenge, "utf8").digest("hex"));
  assert.equal(JSON.stringify(persisted).includes(issued.challenge), false);
  assert.equal(client.calls.some(({ params }) => params.some((value) => value === issued.challenge)), false);
  assert.match(client.calls.find(({ sql }) => sql.startsWith("INSERT INTO webauthn_challenges")).text, /'registration'/);
});

test("acquires a dedicated transaction connection for every begin", async () => {
  const time = clock();
  const pool = new FakePgPool({ now: time.now });
  const { ceremony } = create({ client: pool, time });
  await ceremony.begin(context);
  assert.equal(pool.connectCalls, 1);
  assert.equal(pool.releaseCalls, 1);
  assert.equal(pool.queryCalls, 0);
  assert.deepEqual(pool.connections[0].calls.filter(({ sql }) => ["BEGIN", "COMMIT", "ROLLBACK"].includes(sql)).map(({ sql }) => sql), ["BEGIN", "COMMIT"]);
});

test("uses pending-to-consuming CAS and returns the registration service contract", async () => {
  const calls = [];
  const { ceremony, client } = create({ verifyAttestation: async (input) => { calls.push(input); return { verified: true, credential_id: input.attestation.credential_id, public_key: Buffer.alloc(65, 3), sign_count: 7, transports: ["internal"], credential_device_type: "singleDevice", credential_backed_up: false, user_verified: true }; } });
  const issued = await ceremony.begin(context);
  const result = await ceremony.consume(registration(issued.challenge));
  assert.equal(result.verified, true);
  assert.equal(result.registration_id, ids.challenge);
  assert.equal(result.session_id, ids.session);
  assert.equal(result.member_id, ids.member);
  assert.equal(result.organization_id, ids.organization);
  assert.equal(result.operation, context.operation);
  assert.equal(result.authenticated_at, 1_900_000_000_000);
  assert.equal(result.credential_id, registration(issued.challenge).credential_id);
  assert.equal(result.public_key.length, 65);
  assert.equal(result.sign_count, 7);
  assert.equal(result.user_verified, true);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].ceremony.expected_challenge, issued.challenge);
  const claim = client.calls.find(({ sql }) => sql.startsWith("UPDATE webauthn_challenges SET status = 'consuming'"));
  assert.match(claim.text, /session_id = \$3/);
  assert.match(claim.text, /member_id = \$4/);
  assert.match(claim.text, /organization_id = \$5/);
  assert.match(claim.text, /operation = \$6/);
  assert.match(claim.text, /challenge_hash = \$10/);
});

test("accepts signed clientData extension members emitted by real browsers", async () => {
  const { ceremony } = create();
  const issued = await ceremony.begin(context);
  const request = registration(issued.challenge);
  request.client_data_json = Buffer.from(JSON.stringify({
    type: "webauthn.create", challenge: issued.challenge, origin: context.origin, crossOrigin: false,
    other_keys_can_be_added_here: "do not compare clientDataJSON against a template"
  })).toString("base64url");
  assert.equal((await ceremony.consume(request)).verified, true);
});

test("allows one verifier, reports busy, and rejects replay", async () => {
  let release;
  const gate = new Promise((resolve) => { release = resolve; });
  let calls = 0;
  const { ceremony } = create({ verifyAttestation: async (input) => { calls += 1; await gate; return { verified: true, credential_id: input.attestation.credential_id, public_key: Buffer.alloc(65, 1), sign_count: 0, user_verified: true }; } });
  const issued = await ceremony.begin(context);
  const request = registration(issued.challenge);
  const first = ceremony.consume(request);
  await new Promise((resolve) => setImmediate(resolve));
  await assert.rejects(() => ceremony.consume(request), (error) => error instanceof WebAuthnRegistrationError && error.code === WEBAUTHN_REGISTRATION_ERROR_CODES.CHALLENGE_BUSY);
  release();
  await first;
  assert.equal(calls, 1);
  await assert.rejects(() => ceremony.consume(request), (error) => error.code === WEBAUTHN_REGISTRATION_ERROR_CODES.CHALLENGE_REPLAYED);
});

test("burns the challenge after verifier failure and never writes attestation fields", async () => {
  const { client, ceremony } = create({ verifyAttestation: async () => { throw new Error("invalid attestation"); } });
  const issued = await ceremony.begin(context);
  const request = registration(issued.challenge);
  await assert.rejects(() => ceremony.consume(request), (error) => error instanceof WebAuthnRegistrationError && error.code === WEBAUTHN_REGISTRATION_ERROR_CODES.VERIFICATION_FAILED);
  assert.equal([...client.rows.values()][0].status, "failed");
  await assert.rejects(() => ceremony.consume(request), (error) => error.code === WEBAUTHN_REGISTRATION_ERROR_CODES.CHALLENGE_REPLAYED);
  const secretValues = [request.challenge, request.credential_id, request.client_data_json, request.attestation_object];
  assert.equal(client.calls.some(({ params }) => params.some((value) => secretValues.includes(value))), false);
});

test("checks member and every binding before claiming", async () => {
  const { client, ceremony } = create();
  const issued = await ceremony.begin(context);
  await assert.rejects(() => ceremony.consume(registration(issued.challenge, { member_id: "55555555-5555-4555-8555-555555555555" })), (error) => error.code === WEBAUTHN_REGISTRATION_ERROR_CODES.BINDING_MISMATCH);
  assert.equal(client.calls.some(({ sql }) => sql.startsWith("UPDATE webauthn_challenges SET status = 'consuming'")), false);
});

test("requires the RP ID to belong to the exact origin host", async () => {
  const { ceremony } = create();
  await assert.rejects(() => ceremony.begin({ ...context, rp_id: "other.example.test" }), (error) => error.code === WEBAUTHN_REGISTRATION_ERROR_CODES.INVALID_CONTEXT);
});

test("fails closed on malformed storage and malformed verifier output", async () => {
  const { client, ceremony } = create({ verifyAttestation: async (input) => ({ verified: true, credential_id: input.attestation.credential_id, public_key: Buffer.alloc(65), sign_count: -1, user_verified: true }) });
  const issued = await ceremony.begin(context);
  [...client.rows.values()][0].member_id = "not-a-uuid";
  await assert.rejects(() => ceremony.consume(registration(issued.challenge)), (error) => error instanceof PostgresWebAuthnRegistrationCeremonyError && error.code === "ERR_WEBAUTHN_REGISTRATION_STORAGE_RESULT");

  const fresh = create({ verifyAttestation: async (input) => ({ verified: true, credential_id: input.attestation.credential_id, public_key: Buffer.alloc(65), sign_count: -1, user_verified: true }) });
  const freshIssued = await fresh.ceremony.begin(context);
  await assert.rejects(() => fresh.ceremony.consume(registration(freshIssued.challenge)), (error) => error instanceof WebAuthnRegistrationError && error.code === WEBAUTHN_REGISTRATION_ERROR_CODES.INVALID_VERIFIER_RESULT);
});

test("documents the no-attestation persistence boundary", () => {
  assert.equal(POSTGRES_WEBAUTHN_REGISTRATION_SCHEMA_REQUIREMENTS.table, "webauthn_challenges");
  assert.equal(POSTGRES_WEBAUTHN_REGISTRATION_SCHEMA_REQUIREMENTS.ceremony, "registration");
  assert.ok(POSTGRES_WEBAUTHN_REGISTRATION_SCHEMA_REQUIREMENTS.forbidden_persisted_fields.includes("attestation_object"));
  assert.ok(POSTGRES_WEBAUTHN_REGISTRATION_SCHEMA_REQUIREMENTS.forbidden_persisted_fields.includes("public_key"));
});

test("returns canonical credential metadata and rejects impossible backup flags", async () => {
  const publicKey = Buffer.alloc(65, 0xab).toString("base64url");
  const { ceremony } = create({ verifyAttestation: async (input) => ({
    verified: true,
    credential_id: input.attestation.credential_id,
    public_key: publicKey,
    sign_count: 2,
    transports: ["usb", "internal"],
    credential_device_type: "multiDevice",
    credential_backed_up: true,
    user_verified: true
  }) });
  const issued = await ceremony.begin(context);
  const result = await ceremony.consume(registration(issued.challenge));
  assert.deepEqual(result.public_key, Buffer.alloc(65, 0xab));
  assert.deepEqual(result.transports, ["usb", "internal"]);
  assert.equal(result.credential_device_type, "multiDevice");
  assert.equal(result.credential_backed_up, true);

  const invalid = create({ verifyAttestation: async (input) => ({
    verified: true,
    credential_id: input.attestation.credential_id,
    public_key: Buffer.alloc(65, 8),
    sign_count: 0,
    credential_device_type: "singleDevice",
    credential_backed_up: true,
    user_verified: true
  }) });
  const invalidIssued = await invalid.ceremony.begin(context);
  await assert.rejects(() => invalid.ceremony.consume(registration(invalidIssued.challenge)), (error) => error.code === WEBAUTHN_REGISTRATION_ERROR_CODES.INVALID_VERIFIER_RESULT);
});

test("reaps a crashed consuming claim before reporting replay", async () => {
  const time = clock();
  const metrics = { stale: 0, replay: 0, recordHumanAuthStaleClaimRecovery(amount = 1) { this.stale += amount; }, recordHumanAuthReplayDenial(amount = 1) { this.replay += amount; } };
  const { client, ceremony } = create({ time, metrics });
  const issued = await ceremony.begin(context);
  const row = [...client.rows.values()][0];
  row.status = "consuming";
  row.consume_started_at = new Date(time.now() - 40_000);
  await assert.rejects(() => ceremony.consume(registration(issued.challenge)), (error) => error.code === WEBAUTHN_REGISTRATION_ERROR_CODES.CHALLENGE_REPLAYED);
  assert.equal(row.status, "failed");
  assert.equal(row.consumed_at instanceof Date, true);
  assert.equal(metrics.stale, 1);
  assert.equal(metrics.replay, 1);
});

test("burns a claim when completion loses its storage result", async () => {
  const time = clock();
  const client = new FakePgClient({ now: time.now, failComplete: true });
  const { ceremony } = create({ client, time });
  const issued = await ceremony.begin(context);
  await assert.rejects(() => ceremony.consume(registration(issued.challenge)), (error) => {
    assert.equal(error.cause, undefined);
    return error instanceof PostgresWebAuthnRegistrationCeremonyError && error.code === "ERR_WEBAUTHN_REGISTRATION_CLAIM_LOST";
  });
  assert.equal([...client.rows.values()][0].status, "failed");
  await assert.rejects(() => ceremony.consume(registration(issued.challenge)), (error) => error.code === WEBAUTHN_REGISTRATION_ERROR_CODES.CHALLENGE_REPLAYED);
});

test("database errors remain secret-free", async () => {
  const secret = "postgres-attestation-secret";
  const time = clock();
  const client = new FakePgClient({ now: time.now, failQuery: "SELECT id, session_id, member_id" });
  const { ceremony } = create({ client, time });
  const issued = await ceremony.begin(context);
  await assert.rejects(() => ceremony.consume(registration(issued.challenge)), (error) => {
    assert.equal(error.cause, undefined);
    assert.doesNotMatch(error.message, new RegExp(secret, "u"));
    assert.doesNotMatch(JSON.stringify(error), new RegExp(secret, "u"));
    return error instanceof PostgresWebAuthnRegistrationCeremonyError && error.code === "ERR_WEBAUTHN_REGISTRATION_STORAGE";
  });
});

test("does not complete a claim after the challenge expires during verification", async () => {
  const time = clock();
  const { client, ceremony } = create({
    time,
    verifyAttestation: async (input) => {
      time.advance(60_001);
      return { verified: true, credential_id: input.attestation.credential_id, public_key: Buffer.alloc(65, 8), sign_count: 0, user_verified: true };
    }
  });
  const issued = await ceremony.begin(context);
  await assert.rejects(() => ceremony.consume(registration(issued.challenge)), (error) => error.code === WEBAUTHN_REGISTRATION_ERROR_CODES.CHALLENGE_EXPIRED);
  assert.equal([...client.rows.values()][0].status, "failed");
});
