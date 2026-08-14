import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import { canonicalJson } from "../../../../packages/protocol/src/index.mjs";
import { createHumanCursorCodec } from "../../src/human-auth/pagination/cursor-codec.mjs";
import {
  OWNER_RECOVERY_OUTBOX_MANAGEMENT_ERROR_CODES,
  OWNER_RECOVERY_OUTBOX_MANAGEMENT_OPERATIONS,
  createPostgresOwnerRecoveryOutboxManagementRepository
} from "../../src/postgres/owner-recovery-outbox-management-repository.mjs";

const ORG = "11111111-1111-4111-8111-111111111111";
const MEMBER = "22222222-2222-4222-8222-222222222222";
const SESSION = "33333333-3333-4333-8333-333333333333";
const EVENT = "44444444-4444-4444-8444-444444444444";
const AUTHORIZATION = "99999999-9999-4999-8999-999999999999";
const REQUEST = "55555555-5555-4555-8555-555555555555";
const SUBJECT = "66666666-6666-4666-8666-666666666666";
const OTHER_ORG = "77777777-7777-4777-8777-777777777777";
const NOW = "2026-08-14T00:00:00.000Z";
const ACTOR = Object.freeze({ organization_id: ORG, member_id: MEMBER, session_id: SESSION, role: "admin" });
const CURSOR_SECRET = Buffer.alloc(32, 0x31);

test("lists tenant-scoped dead letters with bounded keyset pagination and an authority-bound opaque cursor", async () => {
  const client = new ScriptedClient((text, params) => {
    assert.match(text, /status='dead_letter'/u);
    assert.match(text, /ORDER BY created_at ASC,event_id ASC/u);
    assert.match(text, /EXISTS[\s\S]*human_sessions/u);
    assert.match(text, /LIMIT \$5/u);
    assert.deepEqual(params, [ORG, SESSION, MEMBER, "admin", 3]);
    return { rowCount: 2, rows: [deadLetter(1), deadLetter(2)] };
  });
  const repository = createRepository(client);
  const page = await repository.listDeadLetters({ actor: ACTOR, limit: 2 });
  assert.equal(page.items.length, 2);
  assert.equal(page.items[0].event_id, EVENT);
  assert.equal(page.items[0].management_version, 4);
  assert.ok(page.next_cursor === null);
  assert.equal(Object.prototype.hasOwnProperty.call(page.items[0], "claim_token_digest"), false);
  assert.equal(Object.prototype.hasOwnProperty.call(page.items[0], "destination"), false);

  const pagedClient = new ScriptedClient((text, params) => {
    assert.match(text, /\(created_at,event_id\) > \(\$5::timestamptz,\$6::uuid\)/u);
    assert.deepEqual(params, [ORG, SESSION, MEMBER, "admin", "2026-08-14T00:00:01.000Z", EVENT, 3]);
    return { rowCount: 1, rows: [] };
  });
  const pagedRepository = createRepository(pagedClient);
  const cursorCodec = createHumanCursorCodec({ secret: CURSOR_SECRET });
  const cursor = cursorCodec.encode({ resource: "owner_recovery_dead_letters", tenant_id: ORG, member_id: MEMBER, created_at: "2026-08-14T00:00:01.000Z", id: EVENT, direction: "asc" });
  const next = await pagedRepository.listDeadLetters({ actor: ACTOR, cursor, limit: 2 });
  assert.deepEqual(next, { items: [], next_cursor: null });

  await assert.rejects(
    () => pagedRepository.listDeadLetters({ actor: { ...ACTOR, organization_id: OTHER_ORG }, cursor }),
    { code: OWNER_RECOVERY_OUTBOX_MANAGEMENT_ERROR_CODES.INVALID_CURSOR }
  );
});

test("lists tenant-scoped uncertain deliveries with an authority-bound keyset cursor and fixed reasons", async () => {
  const client = new ScriptedClient((text, params) => {
    assert.match(text, /status='uncertain'/u);
    assert.match(text, /ORDER BY uncertain_at ASC,event_id ASC/u);
    assert.match(text, /EXISTS[\s\S]*human_sessions/u);
    assert.match(text, /LIMIT \$5/u);
    assert.deepEqual(params, [ORG, SESSION, MEMBER, "admin", 3]);
    return { rowCount: 2, rows: [uncertain(1), uncertain(2)] };
  });
  const repository = createRepository(client);
  const page = await repository.listUncertain({ actor: ACTOR, limit: 2 });
  assert.equal(page.items.length, 2);
  assert.equal(page.items[0].event_id, EVENT);
  assert.equal(page.items[0].uncertain_reason, "delivery_unknown");
  assert.equal(page.items[0].last_error_code, "delivery_uncertain");
  assert.equal(Object.prototype.hasOwnProperty.call(page.items[0], "claim_token_digest"), false);
  assert.equal(Object.prototype.hasOwnProperty.call(page.items[0], "destination"), false);

  const pagedClient = new ScriptedClient((text, params) => {
    assert.match(text, /\(uncertain_at,event_id\) > \(\$5::timestamptz,\$6::uuid\)/u);
    assert.deepEqual(params, [ORG, SESSION, MEMBER, "admin", "2026-08-14T00:00:01.000Z", EVENT, 3]);
    return { rowCount: 1, rows: [] };
  });
  const pagedRepository = createRepository(pagedClient);
  const cursorCodec = createHumanCursorCodec({ secret: CURSOR_SECRET });
  const cursor = cursorCodec.encode({ resource: "owner_recovery_outbox_uncertain", tenant_id: ORG, member_id: MEMBER, created_at: "2026-08-14T00:00:01.000Z", id: EVENT, direction: "asc" });
  const next = await pagedRepository.listUncertain({ actor: ACTOR, cursor, limit: 2 });
  assert.deepEqual(next, { items: [], next_cursor: null });

  await assert.rejects(
    () => pagedRepository.listUncertain({ actor: { ...ACTOR, organization_id: OTHER_ORG }, cursor }),
    { code: OWNER_RECOVERY_OUTBOX_MANAGEMENT_ERROR_CODES.INVALID_CURSOR }
  );
});

test("redrive performs a management-version CAS and appends the admin audit in the same transaction", async () => {
  const client = new ScriptedClient((text, params, scriptedClient) => {
    if (text.startsWith("UPDATE owner_recovery_outbox")) {
      assert.match(text, /status='pending'/u);
      assert.match(text, /management_version=management_version\+1/u);
      assert.match(text, /provider_binding_state='bound'/u);
      assert.doesNotMatch(text, /total_attempts=/u);
      assert.deepEqual(params, [ORG, EVENT, 4]);
      return { rowCount: 1, rows: [mutation("pending")] };
    }
    return auditResult(text, params, scriptedClient);
  });
  const audit = new FakeAudit();
  const metricCalls = [];
  const repository = createRepository(client, { auditRepository: audit, metrics: metricRecorder(metricCalls) });
  const result = await repository.redriveDeadLetter(mutationInput("redrive", 4, { idempotency_key: "redrive-dead-letter-1" }));
  assert.deepEqual(result, { organization_id: ORG, event_id: EVENT, status: "pending", attempts: 0, total_attempts: 100, management_version: 5, redrive_count: 1, suppressed_at: null, suppression_reason: null });
  assert.equal(client.calls[0].text, "BEGIN");
  assert.ok(client.calls.some(({ text }) => text.startsWith("UPDATE owner_recovery_outbox")));
  assert.equal(client.calls.at(-1).text, "COMMIT");
  assert.equal(audit.calls.length, 1);
  assert.equal(audit.calls[0].tx, client);
  assert.equal(audit.calls[0].details.claim_token_digest, undefined);
  assert.deepEqual(metricCalls, ["redrive_success"]);
});

test("suppress requires a safe reason and CASes the expected version", async () => {
  const client = new ScriptedClient((text, params, scriptedClient) => {
    if (text.startsWith("UPDATE owner_recovery_outbox")) {
      assert.match(text, /status='suppressed'/u);
      assert.match(text, /suppression_reason=\$4/u);
      assert.deepEqual(params, [ORG, EVENT, 9, "operator-confirmed-noise"]);
      return { rowCount: 1, rows: [mutation("suppressed")] };
    }
    return auditResult(text, params, scriptedClient);
  });
  const audit = new FakeAudit();
  const metricCalls = [];
  const repository = createRepository(client, { auditRepository: audit, metrics: metricRecorder(metricCalls) });
  const result = await repository.suppressDeadLetter(mutationInput("suppress", 9, { reason: "operator-confirmed-noise", idempotency_key: "suppress-dead-letter-1" }));
  assert.equal(result.status, "suppressed");
  assert.equal(result.suppression_reason, "operator-confirmed-noise");
  assert.deepEqual(metricCalls, ["suppression"]);
  await assert.rejects(
    () => repository.suppressDeadLetter(mutationInput("suppress", 9, { reason: "bad\nreason", idempotency_key: "suppress-dead-letter-2" })),
    { code: OWNER_RECOVERY_OUTBOX_MANAGEMENT_ERROR_CODES.INVALID_INPUT }
  );
});

test("retryUncertain clears quarantine metadata, preserves attempts, and audits the exact CAS", async () => {
  const client = new ScriptedClient((text, params, scriptedClient) => {
    if (text.startsWith("SELECT s.id")) {
      assert.deepEqual(params.slice(0, 6), [SESSION, MEMBER, ORG, "admin", AUTHORIZATION, OWNER_RECOVERY_OUTBOX_MANAGEMENT_OPERATIONS.retryUncertain]);
    }
    if (text.startsWith("UPDATE owner_recovery_outbox")) {
      assert.match(text, /status='pending'/u);
      assert.match(text, /uncertain_at=NULL,uncertain_reason=NULL,last_error_code=NULL/u);
      assert.match(text, /redrive_count=redrive_count\+1/u);
      assert.match(text, /redrive_count<3/u);
      assert.match(text, /provider_binding_state='bound'/u);
      assert.match(text, /management_version=management_version\+1/u);
      assert.deepEqual(params, [ORG, EVENT, 7]);
      return { rowCount: 1, rows: [uncertainMutation("pending")] };
    }
    return auditResult(text, params, scriptedClient);
  });
  const audit = new FakeAudit();
  const repository = createRepository(client, { auditRepository: audit });
  const result = await repository.retryUncertain(uncertainMutationInput("retry_uncertain", "retryUncertain", 7, { idempotency_key: "retry-uncertain-1" }));
  assert.deepEqual(result, { organization_id: ORG, event_id: EVENT, status: "pending", attempts: 1, total_attempts: 1, management_version: 8, redrive_count: 1, uncertain_at: null, uncertain_reason: null, suppressed_at: null, suppression_reason: null });
  assert.equal(audit.calls.length, 1);
  assert.equal(audit.calls[0].tx, client);
  assert.equal(client.calls[0].text, "BEGIN");
  assert.equal(client.calls.at(-1).text, "COMMIT");
});

test("suppressUncertain requires a bounded reason, clears uncertain metadata, and audits in the same transaction", async () => {
  const client = new ScriptedClient((text, params, scriptedClient) => {
    if (text.startsWith("SELECT s.id")) {
      assert.deepEqual(params.slice(0, 6), [SESSION, MEMBER, ORG, "admin", AUTHORIZATION, OWNER_RECOVERY_OUTBOX_MANAGEMENT_OPERATIONS.suppressUncertain]);
    }
    if (text.startsWith("UPDATE owner_recovery_outbox")) {
      assert.match(text, /status='suppressed'/u);
      assert.match(text, /uncertain_at=NULL,uncertain_reason=NULL/u);
      assert.deepEqual(params, [ORG, EVENT, 8, "operator-reviewed"]);
      return { rowCount: 1, rows: [uncertainMutation("suppressed")] };
    }
    return auditResult(text, params, scriptedClient);
  });
  const audit = new FakeAudit();
  const repository = createRepository(client, { auditRepository: audit });
  const result = await repository.suppressUncertain(uncertainMutationInput("suppress_uncertain", "suppressUncertain", 8, { reason: "operator-reviewed", idempotency_key: "suppress-uncertain-1" }));
  assert.equal(result.status, "suppressed");
  assert.equal(result.uncertain_at, null);
  assert.equal(result.uncertain_reason, null);
  assert.equal(result.suppression_reason, "operator-reviewed");
  assert.equal(audit.calls[0].tx, client);
  await assert.rejects(
    () => repository.suppressUncertain(uncertainMutationInput("suppress_uncertain", "suppressUncertain", 8, { reason: "bad\nreason", idempotency_key: "suppress-uncertain-2" })),
    { code: OWNER_RECOVERY_OUTBOX_MANAGEMENT_ERROR_CODES.INVALID_INPUT }
  );
});

test("uncertain management exposes retry and suppression only, never confirmation", async () => {
  const repository = createRepository(new ScriptedClient(() => ({ rowCount: 0, rows: [] })));
  assert.equal(typeof repository.listUncertain, "function");
  assert.equal(typeof repository.retryUncertain, "function");
  assert.equal(typeof repository.suppressUncertain, "function");
  assert.equal("confirmUncertain" in repository, false);
  assert.equal(Object.values(OWNER_RECOVERY_OUTBOX_MANAGEMENT_OPERATIONS).some((operation) => operation.includes("confirm")), false);
});

test("a stale CAS is stable, rolls back, and does not expose database diagnostics", async () => {
  const client = new ScriptedClient((text, params, scriptedClient) => {
    if (text.startsWith("UPDATE owner_recovery_outbox")) return { rowCount: 0, rows: [] };
    return auditResult(text, params, scriptedClient);
  });
  const metricCalls = [];
  const repository = createRepository(client, { auditRepository: new FakeAudit(), metrics: metricRecorder(metricCalls) });
  await assert.rejects(
    () => repository.redriveDeadLetter(mutationInput("redrive", 3, { idempotency_key: "redrive-stale-version" })),
    (error) => error.code === OWNER_RECOVERY_OUTBOX_MANAGEMENT_ERROR_CODES.VERSION_CONFLICT && !error.message.includes("postgres")
  );
  assert.equal(client.calls.at(-1).text, "ROLLBACK");
  assert.deepEqual(metricCalls, ["redrive_failure"]);
});

test("an audit failure rolls back the outbox mutation and stays secret-free", async () => {
  const client = new ScriptedClient((text, params) => {
    if (text.startsWith("UPDATE owner_recovery_outbox")) return { rowCount: 1, rows: [mutation("pending")] };
    return auditResult(text, params, client);
  });
  const repository = createRepository(client, { auditRepository: { async appendAdminAuditEventInTransaction() { throw new Error("destination secret must not escape"); } } });
  await assert.rejects(
    () => repository.redriveDeadLetter(mutationInput("redrive", 4, { idempotency_key: "redrive-audit-failure" })),
    (error) => error.code === OWNER_RECOVERY_OUTBOX_MANAGEMENT_ERROR_CODES.AUDIT && !error.message.includes("destination")
  );
  assert.equal(client.calls.at(-1).text, "ROLLBACK");
});

test("rejects non-admin server scopes before touching PostgreSQL", async () => {
  const client = new ScriptedClient(() => { throw new Error("must not query"); });
  const repository = createRepository(client);
  await assert.rejects(
    () => repository.listDeadLetters({ actor: { ...ACTOR, role: "auditor" } }),
    { code: OWNER_RECOVERY_OUTBOX_MANAGEMENT_ERROR_CODES.FORBIDDEN }
  );
  assert.equal(client.calls.length, 0);
});

test("rejects a substituted resource-bound authorization before PostgreSQL", async () => {
  const client = new ScriptedClient(() => { throw new Error("must not query"); });
  const repository = createRepository(client);
  const input = mutationInput("redrive", 4, { idempotency_key: "redrive-context-substitution" });
  await assert.rejects(
    () => repository.redriveDeadLetter({ ...input, context_hash: "0".repeat(64) }),
    { code: OWNER_RECOVERY_OUTBOX_MANAGEMENT_ERROR_CODES.FORBIDDEN }
  );
  await assert.rejects(
    () => repository.redriveDeadLetter({ ...input, recent_authorization: { ...input.recent_authorization, context_hash: "f".repeat(64) } }),
    { code: OWNER_RECOVERY_OUTBOX_MANAGEMENT_ERROR_CODES.FORBIDDEN }
  );
  assert.equal(client.calls.length, 0);
});

test("revalidates the current session, role, epochs, and consumed recent auth before idempotency or mutation", async () => {
  const client = new ScriptedClient((text, params, scriptedClient) => {
    if (text.startsWith("SELECT pg_advisory_xact_lock")) return { rowCount: 1, rows: [{}] };
    if (text.startsWith("SELECT s.id")) {
      assert.match(text, /FOR UPDATE OF s,m,o/u);
      assert.match(text, /recent_auth_consumed_at IS NOT NULL/u);
      assert.deepEqual(params.slice(0, 6), [SESSION, MEMBER, ORG, "admin", AUTHORIZATION, OWNER_RECOVERY_OUTBOX_MANAGEMENT_OPERATIONS.redrive]);
      return { rowCount: 0, rows: [] };
    }
    return auditResult(text, params, scriptedClient);
  });
  const repository = createRepository(client, { auditRepository: new FakeAudit() });
  await assert.rejects(
    () => repository.redriveDeadLetter(mutationInput("redrive", 4, { idempotency_key: "redrive-stale-authority" })),
    { code: OWNER_RECOVERY_OUTBOX_MANAGEMENT_ERROR_CODES.FORBIDDEN }
  );
  assert.equal(client.calls.some(({ text }) => text.startsWith("INSERT INTO idempotency_records")), false);
  assert.equal(client.calls.some(({ text }) => text.startsWith("UPDATE owner_recovery_outbox")), false);
  assert.equal(client.calls.at(-1).text, "ROLLBACK");
});

function createRepository(client, overrides = {}) {
  return createPostgresOwnerRecoveryOutboxManagementRepository({
    client,
    cursorCodec: createHumanCursorCodec({ secret: CURSOR_SECRET }),
    now: () => NOW,
    ...overrides
  });
}

function deadLetter(second) {
  return {
    organization_id: ORG,
    event_id: EVENT,
    request_id: REQUEST,
    subject_member_id: SUBJECT,
    event_type: "recovery.request.created",
    status: "dead_letter",
    attempts: 100,
    total_attempts: 100,
    management_version: 4,
    redrive_count: 0,
    last_error_code: "publisher_unavailable",
    suppressed_at: null,
    suppression_reason: null,
    created_at: new Date(Date.parse(NOW) + second * 1_000),
    updated_at: new Date(NOW)
  };
}

function uncertain(second) {
  return {
    organization_id: ORG,
    event_id: EVENT,
    request_id: REQUEST,
    subject_member_id: SUBJECT,
    event_type: "recovery.request.created",
    status: "uncertain",
    attempts: 1,
    total_attempts: 1,
    management_version: 4,
    redrive_count: 0,
    last_error_code: "delivery_uncertain",
    uncertain_at: new Date(Date.parse(NOW) + second * 1_000),
    uncertain_reason: "delivery_unknown",
    created_at: new Date(NOW),
    updated_at: new Date(NOW),
    suppressed_at: null,
    suppression_reason: null
  };
}

function mutation(status) {
  return {
    organization_id: ORG,
    event_id: EVENT,
    status,
    attempts: status === "pending" ? 0 : 100,
    total_attempts: 100,
    management_version: status === "pending" ? 5 : 10,
    redrive_count: 1,
    suppressed_at: status === "suppressed" ? NOW : null,
    suppression_reason: status === "suppressed" ? "operator-confirmed-noise" : null
  };
}

function uncertainMutation(status) {
  return {
    organization_id: ORG,
    event_id: EVENT,
    status,
    attempts: 1,
    total_attempts: 1,
    management_version: status === "pending" ? 8 : 9,
    redrive_count: status === "pending" ? 1 : 0,
    uncertain_at: null,
    uncertain_reason: null,
    suppressed_at: status === "suppressed" ? NOW : null,
    suppression_reason: status === "suppressed" ? "operator-reviewed" : null
  };
}

function auditResult(text, params, client) {
  if (text === "BEGIN" || text === "COMMIT" || text === "ROLLBACK") return { rowCount: 0, rows: [] };
  if (text.startsWith("SELECT pg_advisory_xact_lock")) return { rowCount: 1, rows: [{}] };
  if (text.startsWith("SELECT s.id")) return { rowCount: 1, rows: [{ id: SESSION }] };
  if (text.includes("set_config('agentpass.owner_recovery_actor_type'")) return { rowCount: 1, rows: [{}] };
  if (text.startsWith("DELETE FROM idempotency_records")) return { rowCount: 0, rows: [] };
  if (text.startsWith("INSERT INTO idempotency_records")) { client.requestHash = params[3]; return { rowCount: 1, rows: [] }; }
  if (text.startsWith("SELECT request_hash,response_status,response_json")) return { rowCount: 1, rows: [{ request_hash: client.requestHash, response_status: 102, response_json: {} }] };
  if (text.startsWith("UPDATE idempotency_records")) return { rowCount: 1, rows: [] };
  throw new Error(`unexpected query: ${text}`);
}

function contextHash(operation, expectedManagementVersion) {
  return crypto.createHash("sha256").update(canonicalJson({ version: 1, organization_id: ORG, event_id: EVENT, action: operation, expected_management_version: expectedManagementVersion })).digest("hex");
}

function mutationInput(operation, expectedManagementVersion, overrides = {}) {
  const context_hash = contextHash(operation, expectedManagementVersion);
  return { actor: ACTOR, event_id: EVENT, expected_management_version: expectedManagementVersion, context_hash, recent_authorization: recent(operation, context_hash), ...overrides };
}

function uncertainMutationInput(action, operation, expectedManagementVersion, overrides = {}) {
  const context_hash = contextHash(action, expectedManagementVersion);
  return { actor: ACTOR, event_id: EVENT, expected_management_version: expectedManagementVersion, context_hash, recent_authorization: recent(operation, context_hash), ...overrides };
}

function recent(operation, context_hash) {
  return {
    session_id: SESSION,
    challenge_id: AUTHORIZATION,
    operation: OWNER_RECOVERY_OUTBOX_MANAGEMENT_OPERATIONS[operation],
    authenticated_at: Date.parse(NOW),
    context_hash
  };
}

class FakeAudit {
  constructor() { this.calls = []; }
  async appendAdminAuditEventInTransaction(input) { this.calls.push(input); return { audit_event_id: "88888888-8888-4888-8888-888888888888" }; }
}

function metricRecorder(calls) {
  return {
    recordOwnerRecoveryOutboxRedriveSuccess() { calls.push("redrive_success"); },
    recordOwnerRecoveryOutboxRedriveFailure() { calls.push("redrive_failure"); },
    recordOwnerRecoveryOutboxSuppression() { calls.push("suppression"); }
  };
}

class ScriptedClient {
  constructor(handler) { this.handler = handler; this.calls = []; this.requestHash = null; }
  async query(text, params = []) { this.calls.push({ text, params }); return this.handler(text, params, this); }
}
