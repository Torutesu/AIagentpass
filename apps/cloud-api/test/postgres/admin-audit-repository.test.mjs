import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import { canonicalJson } from "../../../../packages/protocol/src/index.mjs";
import { AdminAuditRepositoryError, createPostgresAdminAuditRepository } from "../../src/postgres/admin-audit-repository.mjs";

const organizationId = "11111111-1111-4111-8111-111111111111";
const actorId = "22222222-2222-4222-8222-222222222222";
const targetId = "33333333-3333-4333-8333-333333333333";
const auditEventId = "44444444-4444-4444-8444-444444444444";
const now = "2026-08-13T00:00:00.000Z";

class AuditClient {
  constructor() { this.calls = []; this.requestHash = null; this.storedResponse = null; this.event = null; this.storedEvent = null; this.storedEventHash = null; }
  async query(text, params = []) {
    this.calls.push({ text, params });
    if (["BEGIN", "COMMIT", "ROLLBACK"].includes(text)) return result([]);
    if (text.startsWith("DELETE FROM idempotency_records")) return result([]);
    if (text.startsWith("INSERT INTO idempotency_records")) { this.requestHash = params[3]; return { rows: [], rowCount: 1 }; }
    if (text.startsWith("SELECT request_hash,response_status,response_json")) return result([{ request_hash: this.requestHash, response_status: 102, response_json: {} }]);
    if (text.startsWith("UPDATE idempotency_records")) { this.storedResponse = JSON.parse(params[4]); return { rows: [], rowCount: 1 }; }
    if (text.includes("pg_advisory_xact_lock")) return result([{}]);
    if (text.startsWith("SELECT public.agentpass_manual_wake_actor_role")) return result([{ role: "admin" }]);
    if (text.startsWith("SELECT sequence,event_hash FROM admin_audit_heads")) return result([{ sequence: 0, event_hash: "0".repeat(64) }]);
    if (text.startsWith("INSERT INTO admin_audit_events")) { this.event = JSON.parse(params[9]); return result([{ created_at: params[10] }]); }
    if (text.startsWith("UPDATE admin_audit_heads")) return { rows: [], rowCount: 1 };
    if (text.startsWith("SELECT id,organization_id,actor_id")) return result([{
      id: auditEventId, organization_id: organizationId, actor_id: actorId, action: "policy.disabled",
      target_type: "policy", target_id: targetId, sequence: this.event?.sequence ?? this.storedEvent?.sequence ?? 1,
      event_hash: this.storedResponse?.event_hash ?? this.storedEventHash,
      event_json: this.event ?? this.storedEvent, created_at: now
    }]);
    throw new Error(`unexpected query: ${text}`);
  }
}

test("append locks the tenant chain and commits idempotency, event, and head on one transaction", async () => {
  const client = new AuditClient();
  const repository = createPostgresAdminAuditRepository({ client, now: () => now });
  const event = await repository.appendAdminAuditEvent({
    organizationId, actorId, auditEventId, eventType: "policy.disabled", targetType: "policy", targetId,
    details: { reason: "operator_request" }, idempotencyKey: "audit-policy-0001"
  });
  assert.equal(event.audit_event_id, auditEventId);
  assert.equal(event.actor_id, actorId);
  assert.equal(event.event_type, "policy.disabled");
  assert.match(event.event_hash, /^[0-9a-f]{64}$/);
  assert.deepEqual(client.event, {
    version: 2,
    audit_event_id: auditEventId,
    organization_id: organizationId,
    actor_id: actorId,
    action: "policy.disabled",
    target_type: "policy",
    target_id: targetId,
    details: { reason: "operator_request" },
    previous_hash: "0".repeat(64),
    sequence: 1
  });
  assert.equal(event.event_hash, crypto.createHash("sha256").update(canonicalJson(client.event), "utf8").digest("hex"));
  assert.deepEqual(client.calls.slice(0, 2).map(({ text }) => text), ["BEGIN", client.calls[1].text]);
  assert.equal(client.calls.at(-1).text, "COMMIT");
  assert.ok(client.calls.some(({ text, params }) => text.startsWith("SELECT public.agentpass_manual_wake_actor_role") && params[0] === organizationId && params[1] === actorId));
  assert.ok(client.calls.some(({ text }) => text.includes("admin_audit_heads") && text.includes("FOR UPDATE")));
  assert.deepEqual(client.storedResponse, event);

  const listed = await repository.listAdminAuditEvents({ organizationId, limit: 10 });
  assert.deepEqual(listed, [event]);
  assert.ok(client.calls.at(-1).text.includes("WHERE organization_id=$1"));
});

test("canonical v2 hashing is stable across nested details key order", async () => {
  async function append(details) {
    const client = new AuditClient();
    const repository = createPostgresAdminAuditRepository({ client, now: () => now });
    const event = await repository.appendAdminAuditEvent({
      organizationId, actorId, auditEventId, eventType: "policy.disabled", targetType: "policy", targetId,
      details, idempotencyKey: "audit-canonical-0001"
    });
    return { client, event };
  }

  const first = await append({ nested: { zulu: "last", alpha: "first" } });
  const second = await append({ nested: { alpha: "first", zulu: "last" } });
  assert.notEqual(JSON.stringify(first.client.event), JSON.stringify(second.client.event));
  assert.equal(first.event.event_hash, second.event.event_hash);
  assert.equal(first.event.event_hash, crypto.createHash("sha256").update(canonicalJson(first.client.event), "utf8").digest("hex"));
});

test("reads an existing stored v1 event without recomputing or relabeling its hash", async () => {
  const client = new AuditClient();
  client.storedEvent = {
    version: 1,
    audit_event_id: auditEventId,
    organization_id: organizationId,
    actor_id: actorId,
    action: "policy.disabled",
    target_type: "policy",
    target_id: targetId,
    details: { nested: { zulu: "last", alpha: "first" } },
    previous_hash: "0".repeat(64),
    sequence: 1
  };
  client.storedEventHash = "a".repeat(64);
  const repository = createPostgresAdminAuditRepository({ client, now: () => now });

  const [event] = await repository.listAdminAuditEvents({ organizationId });
  assert.equal(event.event_hash, client.storedEventHash);
  assert.equal(event.recorded_at, now);
  assert.deepEqual(event.details, client.storedEvent.details);
  assert.equal(client.storedEvent.version, 1);
});

test("reads a legacy v0 event without treating it as a v1 or v2 event", async () => {
  const client = new AuditClient();
  client.storedEvent = {
    version: 0,
    legacy: true,
    audit_event_id: auditEventId,
    organization_id: organizationId,
    actor_id: actorId,
    action: "policy.disabled",
    target_type: "policy",
    target_id: targetId,
    previous_hash: "0".repeat(64),
    event_hash: "b".repeat(64),
    created_at: now
  };
  client.storedEventHash = "b".repeat(64);
  const repository = createPostgresAdminAuditRepository({ client, now: () => now });

  const [event] = await repository.listAdminAuditEvents({ organizationId });
  assert.equal(event.event_hash, client.storedEventHash);
  assert.deepEqual(event.details, {});
  assert.equal(client.storedEvent.version, 0);
  assert.equal(client.storedEvent.legacy, true);
});

test("rejects secret-bearing audit details before touching PostgreSQL", async () => {
  const client = new AuditClient();
  const repository = createPostgresAdminAuditRepository({ client, now: () => now });
  await assert.rejects(repository.appendAdminAuditEvent({ organizationId, actorId, eventType: "test", targetType: "organization", targetId: organizationId, details: { session_token: "must-not-persist" }, idempotencyKey: "audit-secret-0001" }), { code: "ERR_SECRET_MATERIAL" });
  assert.equal(client.calls.length, 0);
});

test("database details are hidden behind a constant repository error", async () => {
  const repository = createPostgresAdminAuditRepository({ client: { async query() { throw new Error("postgres://user:password@internal/db"); } }, now: () => now });
  await assert.rejects(repository.listAdminAuditEvents({ organizationId }), (error) => error instanceof AdminAuditRepositoryError
    && error.code === "ERR_DATABASE" && !error.message.includes("password"));
});

test("accepts the server's derived audit key and stores a deterministic shared-control key", async () => {
  const client = new AuditClient();
  const repository = createPostgresAdminAuditRepository({ client, now: () => now });
  const event = await repository.appendAdminAuditEvent({
    organizationId, actorId, eventType: "policy.disabled", targetType: "policy", targetId,
    details: { reason: "operator_request" }, idempotencyKey: "policy-disable-0001:audit"
  });
  const insert = client.calls.find(({ text }) => text.startsWith("INSERT INTO idempotency_records"));
  assert.match(insert.params[2], /^audit-[0-9a-f]{64}$/);
  assert.equal(event.event_type, "policy.disabled");
});

test("appends on a caller-owned transaction without opening or closing it", async () => {
  const client = new AuditClient();
  const repository = createPostgresAdminAuditRepository({ client, now: () => now });
  const event = await repository.appendAdminAuditEventInTransaction({
    tx: client, organizationId, actorId, eventType: "device.revoked", targetType: "device", targetId,
    details: { source: "atomic_mutation" }, idempotencyKey: "device-revoke-0001:audit"
  });
  assert.equal(event.event_type, "device.revoked");
  assert.equal(client.calls.some(({ text }) => text === "BEGIN" || text === "COMMIT" || text === "ROLLBACK"), false);
  assert.match(client.calls.find(({ text }) => text.startsWith("INSERT INTO idempotency_records")).params[2], /^audit-[0-9a-f]{64}$/);
});

function result(rows) { return { rows, rowCount: rows.length }; }
