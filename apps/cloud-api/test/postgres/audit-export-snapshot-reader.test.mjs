import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import { canonicalJson } from "../../../../packages/protocol/src/index.mjs";
import { AUDIT_ANCHOR_ZERO_DIGEST } from "../../src/audit-anchor-statement.mjs";
import {
  AUDIT_EXPORT_MAX_PAYLOAD_BYTES,
  AUDIT_EXPORT_ROOT_DOMAIN,
  AuditExportSnapshotReaderError,
  canonicalAuditExportEntry,
  createPostgresAuditExportSnapshotReader,
  foldAuditExportRoot
} from "../../src/postgres/audit-export-snapshot-reader.mjs";

const ORGANIZATION_ID = "11111111-1111-4111-8111-111111111111";
const EXPORT_ID = "22222222-2222-4222-8222-222222222222";
const EVENT_ID = "33333333-3333-4333-8333-333333333333";
const ACTOR_ID = "44444444-4444-4444-8444-444444444444";
const ZERO = AUDIT_ANCHOR_ZERO_DIGEST;
const EVENT_HASH = "a".repeat(64);

function identity(overrides = {}) {
  return {
    organization_id: ORGANIZATION_ID,
    export_id: EXPORT_ID,
    environment: "production",
    chain: "admin",
    idempotency_key: "snapshot-reader-test-0001",
    ...overrides
  };
}

function boundary(overrides = {}) {
  return { to_audit_position: 0, root_digest: ZERO, ...overrides };
}

function adminEvent(details = { safe: true }) {
  return {
    version: 1,
    audit_event_id: EVENT_ID,
    organization_id: ORGANIZATION_ID,
    actor_id: ACTOR_ID,
    action: "member.role.changed",
    target_type: "member",
    target_id: null,
    details,
    previous_hash: ZERO,
    sequence: 1
  };
}

function adminV2Event(details = { safe: true }, overrides = {}) {
  return { ...adminEvent(details), version: 2, ...overrides };
}

function adminEventHash(event) {
  return crypto.createHash("sha256").update(canonicalJson(event), "utf8").digest("hex");
}

function adminRow(details) {
  return {
    organization_id: ORGANIZATION_ID,
    sequence: "1",
    id: EVENT_ID,
    actor_id: ACTOR_ID,
    action: "member.role.changed",
    target_type: "member",
    target_id: null,
    previous_hash: ZERO,
    event_hash: EVENT_HASH,
    event_json: adminEvent(details),
    created_at: new Date("2026-08-15T00:00:00.000Z")
  };
}

function fixture({ rows = [adminRow()], keyRows } = {}) {
  const queries = [];
  return {
    queries,
    tx: {
      async query(sql, params) {
        queries.push({ sql, params });
        if (/FROM admin_audit_events e/u.test(sql)) return { rows, rowCount: rows.length };
        if (/FROM managed_signer_key_lifecycles l/u.test(sql)) {
          const result = keyRows ?? [{ lifecycle_version: "7", key_id: "audit-anchor-2026-08", key_version: "3", state: "active", state_version: "7", verification_until: null }];
          return { rows: result, rowCount: result.length };
        }
        throw new Error("unexpected query");
      }
    }
  };
}

test("derives a closed frozen admin payload and binds the active lifecycle in the same transaction", async () => {
  const value = fixture();
  const reader = createPostgresAuditExportSnapshotReader();
  const result = await reader(value.tx, identity(), boundary());

  assert.deepEqual(result.range, {
    from_audit_position: 1,
    to_audit_position: 1,
    previous_root_digest: ZERO,
    root_digest: result.range.root_digest,
    record_count: 1
  });
  assert.notEqual(result.range.root_digest, EVENT_HASH);
  assert.equal(result.payload.entries[0].source_hash, EVENT_HASH);
  assert.equal(result.payload.entries[0].event.version, 1);
  assert.equal(result.payload.entries[0].source_gap, null);
  assert.equal(result.key_id, "audit-anchor-2026-08");
  assert.equal(result.key_version, 3);
  assert.equal(result.lifecycle_version, 7);
  assert.equal(Object.isFrozen(result), true);
  assert.equal(Object.isFrozen(result.payload.entries[0].event), true);
  assert.equal(value.queries.length, 2);
  assert.match(value.queries[0].sql, /LIMIT \$3[\s\S]*FOR SHARE OF e/u);
  assert.match(value.queries[1].sql, /k\.state='active' AND k\.state_version=l\.version/u);
});

test("verifies v2 admin hashes while preserving v1 linkage-only compatibility in a mixed chain", async () => {
  const secondId = "55555555-5555-4555-8555-555555555555";
  const secondEvent = adminV2Event({ nested: { zulu: "last", alpha: "first" } }, {
    audit_event_id: secondId,
    previous_hash: EVENT_HASH,
    sequence: 2
  });
  const value = fixture({ rows: [adminRow({ legacy_v1: true }), {
    organization_id: ORGANIZATION_ID,
    sequence: "2",
    id: secondId,
    actor_id: ACTOR_ID,
    action: "member.role.changed",
    target_type: "member",
    target_id: null,
    previous_hash: EVENT_HASH,
    event_hash: adminEventHash(secondEvent),
    event_json: secondEvent,
    created_at: new Date("2026-08-15T00:00:01.000Z")
  }] });

  const result = await createPostgresAuditExportSnapshotReader()(value.tx, identity(), boundary());
  assert.deepEqual(result.payload.entries.map((entry) => entry.event.version), [1, 2]);
  assert.equal(result.payload.entries[0].source_hash, EVENT_HASH);
  assert.equal(result.payload.entries[1].source_hash, adminEventHash(secondEvent));
});

test("accepts v2 hashes after JSONB-style nested key reordering", async () => {
  const original = adminV2Event({ nested: { zulu: "last", alpha: "first" } });
  const roundTripped = {
    ...original,
    details: { nested: { alpha: "first", zulu: "last" } }
  };
  const value = fixture({ rows: [{
    ...adminRow(),
    event_hash: adminEventHash(original),
    event_json: roundTripped
  }] });

  const result = await createPostgresAuditExportSnapshotReader()(value.tx, identity(), boundary());
  assert.equal(result.payload.entries[0].event.version, 2);
  assert.equal(result.payload.entries[0].source_hash, adminEventHash(original));
});

test("rejects a tampered v2 admin event preimage", async () => {
  const original = adminV2Event({ decision: "allow" });
  const tampered = { ...original, details: { decision: "deny" } };
  const value = fixture({ rows: [{
    ...adminRow(),
    event_hash: adminEventHash(original),
    event_json: tampered
  }] });

  await assert.rejects(createPostgresAuditExportSnapshotReader()(value.tx, identity(), boundary()),
    (error) => error instanceof AuditExportSnapshotReaderError && error.code === "ERR_AUDIT_EXPORT_SNAPSHOT_HASH");
});

test("exports a stable domain-separated root fold for independent verification", () => {
  const entry = canonicalAuditExportEntry({
    version: 1,
    organization_id: ORGANIZATION_ID,
    environment: "production",
    chain: "admin",
    export_position: 1,
    source_id: EVENT_ID,
    source_device_id: null,
    source_previous_hash: ZERO,
    source_hash: EVENT_HASH,
    source_gap: null,
    event: adminEvent()
  });
  const first = foldAuditExportRoot(ZERO, entry);
  const second = foldAuditExportRoot(ZERO, structuredClone(entry));
  assert.match(first, /^[0-9a-f]{64}$/u);
  assert.equal(first, second);
  assert.notEqual(first, EVENT_HASH);
  assert.equal(AUDIT_EXPORT_ROOT_DOMAIN, "AgentPass-Audit-Export-Root-v1");
});

test("fails closed for empty snapshots, sensitive event fields, and ambiguous active keys", async (t) => {
  await t.test("empty", async () => {
    const value = fixture({ rows: [] });
    await assert.rejects(createPostgresAuditExportSnapshotReader()(value.tx, identity(), boundary()),
      (error) => error instanceof AuditExportSnapshotReaderError && error.code === "ERR_AUDIT_EXPORT_SNAPSHOT_EMPTY");
  });
  await t.test("sensitive", async () => {
    const value = fixture({ rows: [adminRow({ credential: "must-not-export" })] });
    await assert.rejects(createPostgresAuditExportSnapshotReader()(value.tx, identity(), boundary()),
      (error) => error instanceof AuditExportSnapshotReaderError && error.code === "ERR_AUDIT_EXPORT_SNAPSHOT_ROW");
  });
  await t.test("lifecycle", async () => {
    const key = { lifecycle_version: "7", key_id: "audit-anchor-2026-08", key_version: "3", state: "active", state_version: "7", verification_until: null };
    const value = fixture({ keyRows: [key, { ...key, key_id: "audit-anchor-other", key_version: "4" }] });
    await assert.rejects(createPostgresAuditExportSnapshotReader()(value.tx, identity(), boundary()),
      (error) => error instanceof AuditExportSnapshotReaderError && error.code === "ERR_AUDIT_EXPORT_SNAPSHOT_LIFECYCLE");
  });
});

test("configuration and identity bounds are closed", async () => {
  assert.throws(() => createPostgresAuditExportSnapshotReader({ maxRecords: 101 }), { code: "ERR_AUDIT_EXPORT_SNAPSHOT_CONFIG" });
  assert.throws(() => createPostgresAuditExportSnapshotReader({ maxPayloadBytes: AUDIT_EXPORT_MAX_PAYLOAD_BYTES + 1 }), { code: "ERR_AUDIT_EXPORT_SNAPSHOT_CONFIG" });
  const value = fixture();
  await assert.rejects(createPostgresAuditExportSnapshotReader()(value.tx, { ...identity(), caller_range: {} }, boundary()),
    (error) => error instanceof AuditExportSnapshotReaderError);
});

test("cuts a canonical prefix before the payload byte ceiling instead of failing an exportable page", async () => {
  const first = adminRow({ message: "x".repeat(7_000) });
  const secondId = "55555555-5555-4555-8555-555555555555";
  const secondEvent = {
    ...adminEvent({ message: "y".repeat(7_000) }),
    audit_event_id: secondId,
    previous_hash: EVENT_HASH,
    sequence: 2
  };
  const second = {
    ...first,
    sequence: "2",
    id: secondId,
    previous_hash: EVENT_HASH,
    event_hash: "b".repeat(64),
    event_json: secondEvent,
    created_at: new Date("2026-08-15T00:00:01.000Z")
  };
  const value = fixture({ rows: [first, second] });
  const result = await createPostgresAuditExportSnapshotReader({ maxPayloadBytes: 10_000 })(value.tx, identity(), boundary());
  assert.equal(result.range.record_count, 1);
  assert.equal(result.range.to_audit_position, 1);
  assert.equal(result.payload.entries[0].source_id, EVENT_ID);
});
