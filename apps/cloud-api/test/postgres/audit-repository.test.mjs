import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import { createAuditCursorCodec } from "../../src/audit-pagination.mjs";
import { createPostgresAuditRepository, PostgresAuditRepositoryError } from "../../src/postgres/audit-repository.mjs";

const organizationId = "11111111-1111-4111-8111-111111111111";
const principalId = "44444444-4444-4444-8444-444444444444";
const deviceA = "22222222-2222-4222-8222-222222222222";
const deviceB = "33333333-3333-4333-8333-333333333333";

test("PostgreSQL audit repository uses tenant-qualified immutable tuple ordering and limit+1", async () => {
  const calls = [];
  const auditQueries = [];
  const client = {
    async query(text, params) {
      calls.push({ text, params });
      if (/^SELECT public\.agentpass_authorize_device_audit_tenant/u.test(text)) {
        return { rowCount: 1, rows: [{ organization_id: organizationId }] };
      }
      if (/^SELECT organization_id,device_id,event_id,redacted_json,received_at/u.test(text)) {
        auditQueries.push({ text, params });
        return {
          rowCount: auditQueries.length === 1 ? 3 : 1,
          rows: auditQueries.length === 1
            ? [row(deviceA, "2026-08-12T00:00:00.000Z"), row(deviceA, "2026-08-12T00:00:01.000Z"), row(deviceA, "2026-08-12T00:00:02.000Z")]
            : [row(deviceA, "2026-08-12T00:00:03.000Z")]
        };
      }
      return {
        rowCount: 0,
        rows: []
      };
    }
  };
  const repository = createPostgresAuditRepository({ client, cursorSecret: Buffer.alloc(32, 0x44), now: () => Date.parse("2026-08-12T00:00:00.000Z") });

  const first = await repository.listDeviceAuditEvents({ organization_id: organizationId, principal_id: principalId, device_id: deviceA, limit: 2 });
  assert.equal(first.events.length, 2);
  assert.ok(first.next_cursor);
  assert.match(auditQueries[0].text, /WHERE organization_id = \$1/);
  assert.match(auditQueries[0].text, /ORDER BY \(redacted_json ->> 'device_timestamp'\) DESC,device_id DESC,event_id DESC/);
  assert.equal(auditQueries[0].params.at(-1), 3);

  const second = await repository.listDeviceAuditEvents({ organization_id: organizationId, principal_id: principalId, device_id: deviceA, limit: 2, cursor: first.next_cursor });
  assert.equal(second.events.length, 1);
  assert.equal(second.next_cursor, null);
  assert.match(auditQueries[1].text, /\(\(redacted_json ->> 'device_timestamp'\), device_id, event_id\) < \(\$3, \$4::uuid, \$5::uuid\)/);
  assert.deepEqual(auditQueries[1].params.slice(0, 5), [organizationId, deviceA, first.events.at(-1).event.device_timestamp, first.events.at(-1).device_id, first.events.at(-1).event_id]);

  await assert.rejects(() => repository.listDeviceAuditEvents({ organization_id: organizationId, principal_id: principalId, device_id: deviceB, cursor: first.next_cursor }), /invalid/);
  await assert.rejects(() => repository.listDeviceAuditEvents({ organization_id: organizationId, principal_id: principalId, device_id: deviceA, cursor: `${first.next_cursor.slice(0, -1)}${first.next_cursor.endsWith("A") ? "B" : "A"}` }), /invalid/);
});

test("PostgreSQL audit repository fails closed on inconsistent stored event timestamps", async () => {
  const client = { async query() { return { rows: [row(deviceA, "2026-08-12T00:00:00.000Z", undefined, crypto.randomUUID())] }; } };
  const repository = createPostgresAuditRepository({ client, cursorSecret: Buffer.alloc(32, 0x45) });
  await assert.rejects(() => repository.listDeviceAuditEvents({ organization_id: organizationId, principal_id: principalId, device_id: deviceA }), PostgresAuditRepositoryError);
});

function row(deviceId, eventTimestamp, eventId = crypto.randomUUID(), storedEventId = eventId) {
  return {
    organization_id: organizationId,
    device_id: deviceId,
    event_id: storedEventId,
    received_at: "2026-08-12T00:00:10.000Z",
    redacted_json: { version: 1, event_id: eventId, agent_id: crypto.randomUUID(), device_timestamp: eventTimestamp }
  };
}
