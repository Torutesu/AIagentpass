import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import { canonicalJson } from "../../../../packages/protocol/src/index.mjs";
import {
  AGENT_SIGNING_CAPABILITY_OPERATION,
  agentSigningCapabilityStatementHash
} from "../../src/agent-signing-capability.mjs";
import {
  AGENT_SESSION_SIGNING_CAPABILITY_RESERVATION_ERROR_CODES as CODES,
  AGENT_SESSION_SIGNING_CAPABILITY_BIND_SQL,
  AGENT_SESSION_SIGNING_CAPABILITY_MAINTENANCE_SQL,
  AGENT_SESSION_SIGNING_CAPABILITY_RESERVATION_SQL,
  createPostgresAgentSessionSigningCapabilitySessionBinder,
  createPostgresAgentSessionSigningCapabilityMaintenanceRepository,
  createPostgresAgentSessionSigningCapabilityReservationRepository,
  AgentSessionSigningCapabilityReservationRepositoryError
} from "../../src/postgres/agent-session-signing-capability-reservation-repository.mjs";

const IDS = Object.freeze({
  organization_id: "11111111-1111-4111-8111-111111111111",
  session_id: "22222222-2222-4222-8222-222222222222",
  grant_id: "33333333-3333-4333-8333-333333333333",
  device_id: "44444444-4444-4444-8444-444444444444",
  agent_id: "55555555-5555-4555-8555-555555555555",
  capability_id: "66666666-6666-4666-8666-666666666666",
  request_id: "77777777-7777-4777-8777-777777777777"
});
const SCOPE = Object.freeze({
  operations: [AGENT_SIGNING_CAPABILITY_OPERATION],
  repositories: ["/work/project"],
  branches: { allow: ["feature/*"], deny: ["main"] },
  remotes: { allow: ["origin"], deny: [] }
});
const TIMES = Object.freeze({
  issued_at: "2026-08-16T03:00:00.000Z",
  not_before: "2026-08-16T03:00:00.000Z",
  expires_at: "2026-08-16T03:05:00.000Z"
});
const RESERVATION_ID = "88888888-8888-4888-8888-888888888888";

function result(rows) { return { rows, rowCount: rows.length }; }

function capability() {
  const statement = {
    version: 1,
    type: "agentpass.agent-signing-capability",
    capability_id: IDS.capability_id,
    organization_id: IDS.organization_id,
    session_id: IDS.session_id,
    device_id: IDS.device_id,
    agent_id: IDS.agent_id,
    one_use: true,
    operation: AGENT_SIGNING_CAPABILITY_OPERATION,
    scope: SCOPE,
    key_purpose: AGENT_SIGNING_CAPABILITY_OPERATION,
    key_id: "git-commit-sign-2026-08",
    algorithm: "ed25519",
    max_signatures: 1,
    ...TIMES,
    sequence: 1,
    control_sequence: 12,
    authority_generation: 7,
    issuer: "agentpass-cloud"
  };
  const signingKeys = crypto.generateKeyPairSync("ed25519");
  const signature = crypto.sign(null, Buffer.from(`AgentPass-Agent-Signing-Capability-v1\0${canonicalJson(statement)}`, "utf8"), signingKeys.privateKey).toString("base64url");
  return Object.freeze({ version: 1, type: statement.type, statement, statement_hash: agentSigningCapabilityStatementHash(statement), signature });
}

function reservation({ claim_issued = true } = {}) {
  return {
    state: "reserved", claim_issued, capability_id: IDS.capability_id, organization_id: IDS.organization_id,
    session_id: IDS.session_id, device_id: IDS.device_id, agent_id: IDS.agent_id, scope: SCOPE,
    sequence: 1, control_sequence: 12, authority_generation: 7, ...TIMES, remaining_session_signatures: 1
  };
}

class FakePg {
  constructor({ reserve = reservation(), commit = undefined, replay = undefined, uncertain = { state: "outcome_unknown" }, error = undefined } = {}) {
    this.calls = [];
    this.outputs = { reserve, commit, replay, uncertain };
    this.error = error;
  }

  async query(text, params = []) {
    this.calls.push({ text, params });
    if (["BEGIN", "COMMIT", "ROLLBACK"].includes(text)) return result([]);
    if (this.error) throw this.error;
    if (text.startsWith("SELECT set_config")) return result([{ organization_id: IDS.organization_id }]);
    const method = Object.entries(AGENT_SESSION_SIGNING_CAPABILITY_RESERVATION_SQL).find(([, sql]) => sql === text)?.[0];
    if (!method) throw new Error("unexpected SQL");
    return result([{ result: this.outputs[method] }]);
  }
}

function repository(client, overrides = {}) {
  const generatedIds = [RESERVATION_ID, IDS.capability_id];
  return createPostgresAgentSessionSigningCapabilityReservationRepository({
    client, ...IDS, randomBytes: () => Buffer.alloc(32, 9),
    randomUUID: () => generatedIds.shift(), ...overrides
  });
}

test("reserveCapability uses the tenant-bound Security Definer function and returns a clear claim only once", async () => {
  const client = new FakePg();
  const value = await repository(client).reserveCapability({
    request_id: IDS.request_id, operation: AGENT_SIGNING_CAPABILITY_OPERATION,
    key_purpose: AGENT_SIGNING_CAPABILITY_OPERATION, one_use: true, max_signatures: 1, ttl_ms: 300_000
  });
  assert.equal(value.claim_token, Buffer.alloc(32, 9).toString("base64url"));
  assert.equal(client.calls.filter(({ text }) => text === "BEGIN").length, 1);
  const call = client.calls.find(({ text }) => text === AGENT_SESSION_SIGNING_CAPABILITY_RESERVATION_SQL.reserve);
  assert.ok(call);
  assert.equal(call.params.length, 13);
  assert.deepEqual(call.params.slice(0, 4), [IDS.organization_id, IDS.device_id, IDS.session_id, IDS.request_id]);
  assert.equal(Buffer.isBuffer(call.params[4]), true);
  assert.deepEqual(call.params.slice(5, 7), [RESERVATION_ID, IDS.capability_id]);
  assert.equal(Buffer.isBuffer(call.params[7]), true);
  assert.equal(call.params.some((value) => value === Buffer.alloc(32, 9).toString("base64url")), false);
  assert.deepEqual(Object.keys(value).sort(), [
    "agent_id", "authority_generation", "capability_id", "claim_token", "control_sequence", "device_id",
    "expires_at", "issued_at", "not_before", "organization_id", "remaining_session_signatures", "scope",
    "sequence", "session_id", "state"
  ]);
});

test("a reserved row without a newly issued claim is reported as in_progress", async () => {
  const client = new FakePg({ reserve: reservation({ claim_issued: false }) });
  const value = await repository(client).reserveCapability({
    request_id: IDS.request_id, operation: AGENT_SIGNING_CAPABILITY_OPERATION,
    key_purpose: AGENT_SIGNING_CAPABILITY_OPERATION, one_use: true, max_signatures: 1, ttl_ms: 300_000
  });
  assert.deepEqual(value, { state: "in_progress" });
});

test("commitCapability sends only durable request and claim digests and normalizes committed output", async () => {
  const signed = capability();
  const client = new FakePg({ commit: { state: "completed", capability: signed, remaining_session_signatures: 0 } });
  const value = await repository(client).commitCapability({
    request_id: IDS.request_id, claim_token: Buffer.alloc(32, 9).toString("base64url"), capability: signed,
    capability_hash: signed.statement_hash, remaining_session_signatures: 0
  });
  assert.equal(value.state, "committed");
  assert.deepEqual(value.capability, signed);
  const call = client.calls.find(({ text }) => text === AGENT_SESSION_SIGNING_CAPABILITY_RESERVATION_SQL.commit);
  assert.equal(call.params.length, 6);
  assert.equal(Buffer.isBuffer(call.params[4]), true);
  assert.equal(Buffer.isBuffer(call.params[5]), true);
  assert.equal(call.params.some((value) => value === Buffer.alloc(32, 9).toString("base64url")), false);
});

test("replayCapability returns the exact committed envelope without invoking a signer", async () => {
  const signed = capability();
  const client = new FakePg({ replay: { state: "completed", capability: signed, remaining_session_signatures: 0 } });
  const value = await repository(client).replayCapability({ request_id: IDS.request_id });
  assert.deepEqual(value, { state: "committed", capability: signed, remaining_session_signatures: 0 });
  assert.equal(client.calls.some(({ text }) => /INSERT|UPDATE|DELETE|FROM\s/iu.test(text)), false);
});

test("markCapabilityUncertain hashes the claim and exposes only the terminal state", async () => {
  const client = new FakePg();
  const value = await repository(client).markCapabilityUncertain({
    request_id: IDS.request_id, claim_token: Buffer.alloc(32, 9).toString("base64url"), reason: "signer_failure"
  });
  assert.deepEqual(value, { state: "uncertain" });
  const call = client.calls.find(({ text }) => text === AGENT_SESSION_SIGNING_CAPABILITY_RESERVATION_SQL.uncertain);
  assert.equal(call.params[6], "signer_failure");
  assert.equal(call.params[5].toString("hex"), crypto.createHash("sha256").update(Buffer.alloc(32, 9).toString("base64url"), "utf8").digest("hex"));
});

test("invalid durable output and database errors are generic and never disclose secret material", async () => {
  const malformed = new FakePg({ replay: { state: "completed", capability: { secret: "do-not-disclose" }, remaining_session_signatures: 0 } });
  await assert.rejects(repository(malformed).replayCapability({ request_id: IDS.request_id }), (error) => {
    assert.ok(error instanceof AgentSessionSigningCapabilityReservationRepositoryError);
    assert.equal(error.code, CODES.RESULT);
    assert.equal(error.message.includes("do-not-disclose"), false);
    return true;
  });
  const database = new FakePg({ error: Object.assign(new Error("password=top-secret"), { code: "XX000" }) });
  await assert.rejects(repository(database).replayCapability({ request_id: IDS.request_id }), (error) => {
    assert.equal(error.code, CODES.DATABASE);
    assert.equal(error.message.includes("password"), false);
    return true;
  });
});

test("rejects authority-bearing or malformed inputs before SQL", async () => {
  const client = new FakePg();
  const repo = repository(client);
  await assert.rejects(repo.replayCapability({ request_id: IDS.request_id, organization_id: IDS.organization_id }), { code: CODES.INPUT });
  await assert.rejects(repo.markCapabilityUncertain({ request_id: IDS.request_id, claim_token: "not-a-token", reason: "signer_failure" }), { code: CODES.INPUT });
  assert.equal(client.calls.length, 0);
});

test("maintenance repository is isolated from the normal Agent capability repository", async () => {
  const calls = [];
  const client = {
    async query(text, params = []) {
      calls.push({ text, params });
      if (["BEGIN", "COMMIT", "ROLLBACK"].includes(text)) return result([]);
      assert.equal(text, AGENT_SESSION_SIGNING_CAPABILITY_MAINTENANCE_SQL.recoverExpired);
      return result([{ result: { status: "ok", expired: 2, uncertain: 1 } }]);
    }
  };
  const maintenance = createPostgresAgentSessionSigningCapabilityMaintenanceRepository({ client });
  const value = await maintenance.recoverExpiredReservations({ limit: 8 });
  assert.deepEqual(value, { expired: 2, uncertain: 1 });
  assert.deepEqual(calls.find(({ text }) => text === AGENT_SESSION_SIGNING_CAPABILITY_MAINTENANCE_SQL.recoverExpired).params, [8]);
  assert.equal("reserveCapability" in maintenance, false);
  assert.equal("expireReservations" in repository(new FakePg()), false);
});

test("maintenance repository fails closed for missing or invalid configuration", async () => {
  assert.throws(() => createPostgresAgentSessionSigningCapabilityMaintenanceRepository(), { code: CODES.CONFIG });
  const maintenance = createPostgresAgentSessionSigningCapabilityMaintenanceRepository({ client: new FakePg() });
  await assert.rejects(maintenance.recoverExpiredReservations({ limit: 257 }), { code: CODES.INPUT });
});

test("Session binder installs tenant context and returns only the locked server audience", async () => {
  const calls = [];
  const client = {
    async query(text, params = []) {
      calls.push({ text, params });
      if (["BEGIN", "COMMIT", "ROLLBACK"].includes(text)) return result([]);
      if (text.startsWith("SELECT set_config")) return result([{ organization_id: IDS.organization_id }]);
      if (text === AGENT_SESSION_SIGNING_CAPABILITY_BIND_SQL) return result([{
        organization_id: IDS.organization_id, session_id: IDS.session_id,
        grant_id: IDS.grant_id, device_id: IDS.device_id, agent_id: IDS.agent_id
      }]);
      throw new Error("unexpected SQL");
    }
  };
  const binder = createPostgresAgentSessionSigningCapabilitySessionBinder({ client });
  const value = await binder.bindAgentSession({
    organization_id: IDS.organization_id, device_id: IDS.device_id,
    session_id: IDS.session_id, now: Date.parse(TIMES.issued_at)
  });
  assert.deepEqual(value, {
    authorized: true, organization_id: IDS.organization_id, session_id: IDS.session_id,
    grant_id: IDS.grant_id, device_id: IDS.device_id, agent_id: IDS.agent_id
  });
  assert.deepEqual(calls.find(({ text }) => text === AGENT_SESSION_SIGNING_CAPABILITY_BIND_SQL).params,
    [IDS.organization_id, IDS.device_id, IDS.session_id, TIMES.issued_at]);
});
