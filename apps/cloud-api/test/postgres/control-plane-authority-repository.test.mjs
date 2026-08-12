import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import { canonicalJson } from "../../../../packages/protocol/src/index.mjs";
import {
  CONTROL_PLANE_SCHEMA_GAPS,
  createControlPlaneAuthorityRepository
} from "../../src/postgres/control-plane-authority-repository.mjs";

const ids = {
  organization: "11111111-1111-4111-8111-111111111111",
  member: "33333333-3333-4333-8333-333333333333",
  device: "44444444-4444-4444-8444-444444444444",
  agent: "55555555-5555-4555-8555-555555555555",
  revocation: "66666666-6666-4666-8666-666666666666",
  capability: "77777777-7777-4777-8777-777777777777"
};
const HASH = "a".repeat(64);
const NOW = "2026-08-13T00:00:00.000Z";
const LATER = "2026-08-13T00:15:00.000Z";

class FakeClient {
  constructor() {
    this.calls = [];
    this.bundleSequence = 0;
    this.bundleHead = null;
  }

  async query(text, params = []) {
    this.calls.push({ text, params });
    if (["BEGIN", "COMMIT", "ROLLBACK"].includes(text)) return result();
    if (text.includes("pg_advisory_xact_lock")) return result([{ locked: true }]);
    if (text.startsWith("SELECT id FROM organizations")) return result([{ id: ids.organization }]);
    if (text.startsWith("SELECT member_id FROM memberships")) return result([{ member_id: ids.member }]);
    if (text.startsWith("SELECT id FROM devices")) return result([{ id: ids.device }]);
    if (text.startsWith("SELECT id FROM agents")) return result([{ id: ids.agent }]);
    if (text.startsWith("SELECT organization_id,id,sequence,name,scope_json,status,created_at,updated_at,version")) return result([policyRow()]);
    if (text.startsWith("SELECT organization_id,id AS revocation_id,target_type,target_id,sequence,reason,status,created_by")) {
      if (text.includes("target_type=$2")) return result();
      return result([revocationRow()]);
    }
    if (text.startsWith("SELECT id AS capability_id")) return result();
    if (text.startsWith("SELECT COALESCE(MAX(sequence)")) return result([{ sequence: 1 }]);
    if (text.startsWith("INSERT INTO revocations")) return result([revocationRow()]);
    if (text.startsWith("SELECT organization_id,device_id,format_epoch,sequence,statement_hash") && text.includes("bundle_heads")) {
      return result(this.bundleHead ? [this.bundleHead] : []);
    }
    if (text.startsWith("INSERT INTO bundle_heads")) {
      this.bundleSequence = Number(params[2]);
      this.bundleHead = {
        organization_id: params[0], device_id: params[1], format_epoch: 2, sequence: this.bundleSequence,
        statement_hash: params[3], issued_at: params[4], expires_at: params[5]
      };
      return result([this.bundleHead]);
    }
    if (text.startsWith("SELECT format_epoch,sequence,statement_hash")) return result([{ format_epoch: 2, sequence: 1, statement_hash: HASH }]);
    if (text.startsWith("INSERT INTO bundle_acknowledgements")) return result([ackRow(params)]);
    if (text.startsWith("SELECT organization_id,device_id,format_epoch,sequence,statement_hash") && text.includes("bundle_acknowledgements")) return result([ackRow(params)]);
    if (text.startsWith("SELECT last_event_id,last_event_hash,chain_status,gap_count")) return result();
    if (text.startsWith("SELECT organization_id,device_id,event_id,previous_hash,event_hash,redacted_json,received_at") && text.includes("event_id=$3")) return result();
    if (text.startsWith("INSERT INTO device_audit_events")) return result([{ organization_id: params[0], device_id: params[1], event_id: params[2], previous_hash: params[3], event_hash: params[4], redacted_json: params[5], received_at: params[6] }]);
    if (text.startsWith("SELECT id AS device_id FROM devices")) return result([{ device_id: ids.device }]);
    if (text.startsWith("SELECT organization_id,device_id,event_id,previous_hash,event_hash,redacted_json,received_at") && text.includes("ORDER BY device_id")) return result();
    if (text.startsWith("SELECT organization_id,device_id,event_id,redacted_json,received_at")) return result([]);
    throw new Error(`unexpected SQL: ${text}`);
  }
}

function result(rows = [], rowCount = rows.length) { return { rows, rowCount }; }
function revocationRow() {
  return { organization_id: ids.organization, revocation_id: ids.revocation, target_type: "device", target_id: ids.device, sequence: 1, reason: "operator-request", status: "active", created_by: ids.member, revoked_by: ids.member, created_at: NOW, revoked_at: NOW, version: 1 };
}
function policyRow() {
  return {
    organization_id: ids.organization, id: "22222222-2222-4222-8222-222222222222", sequence: 1,
    name: "default", scope_json: { operations: ["git.commit.sign"], repositories: ["/repo"], branches: { allow: ["main"], deny: [] }, remotes: { allow: ["origin"], deny: [] } },
    status: "active", created_at: NOW, updated_at: NOW, version: 1
  };
}
function ackRow(params) {
  return { organization_id: params[0], device_id: params[1], format_epoch: params[2], sequence: params[3], statement_hash: params[4], status: params[5], reason: params[6], applied_at: params[7], received_at: NOW };
}
function repository(client) {
  return createControlPlaneAuthorityRepository({ client, cursorSecret: Buffer.alloc(32, 0x31), now: () => NOW });
}
function auditEvent(previousHash = "0".repeat(64)) {
  const preimage = {
    version: 1,
    event_id: crypto.randomUUID(),
    request_id: crypto.randomUUID(),
    agent_id: ids.agent,
    operation: "git.commit.sign",
    decision: "allow",
    reason: "allowed",
    policy_sequence: 1,
    capability_sequence: 1,
    repository: "/work/repo",
    branch: "main",
    remote: "git@example.test:repo.git",
    payload_digest: HASH,
    device_timestamp: NOW,
    previous_hash: previousHash
  };
  return { ...preimage, event_hash: crypto.createHash("sha256").update(canonicalJson(preimage), "utf8").digest("hex") };
}

test("exposes a frozen control-plane authority API with migration 0011 gaps closed", () => {
  const api = repository(new FakeClient());
  assert.equal(Object.isFrozen(api), true);
  for (const method of [
    "createRevocation", "getRevocation", "listRevocations", "issueCapabilityMetadata", "listRevokedCapabilityIds",
    "assignBundleHead", "acknowledgeBundle", "getBundleAcknowledgement", "ingestDeviceAuditEvents",
    "appendDeviceAuditEvent", "listDeviceAuditEvents", "getAuditHealth", "snapshotAndAssignBundleHead"
  ]) assert.equal(typeof api[method], "function", method);
  assert.deepEqual(CONTROL_PLANE_SCHEMA_GAPS, []);
});

test("revocation mutation is tenant-qualified, locked, transactional, and idempotent by identity", async () => {
  const client = new FakeClient();
  const api = repository(client);
  const revocation = await api.createRevocation({
    organization_id: ids.organization, revocation_id: ids.revocation, target_type: "device", target_id: ids.device,
    reason: "operator-request", created_by: ids.member, created_at: NOW
  });
  assert.deepEqual(revocation, {
    revocation_id: ids.revocation, organization_id: ids.organization, target_type: "device", target_id: ids.device,
    reason: "operator-request", status: "active", revoked_at: NOW, version: 1
  });
  assert.equal(client.calls[0].text, "BEGIN");
  assert.ok(client.calls.some(({ text }) => text.includes("pg_advisory_xact_lock")));
  const active = client.calls.find(({ text }) => text.includes("target_type=$2"));
  assert.match(active.text, /organization_id=\$1/);
  assert.equal(client.calls.at(-1).text, "COMMIT");

});

test("bundle heads remain monotonic and ACKs are append-only against the tenant's current head", async () => {
  const client = new FakeClient();
  const api = repository(client);
  const head = await api.assignBundleHead({ organization_id: ids.organization, device_id: ids.device, state_fingerprint: HASH, minimum_sequence: 7, issued_at: NOW, expires_at: LATER });
  assert.equal(head.sequence, 7);
  assert.equal(head.state_fingerprint, HASH);
  const acknowledgement = await api.acknowledgeBundle({ organization_id: ids.organization, device_id: ids.device, format_epoch: 2, sequence: 1, statement_hash: HASH, status: "applied", applied_at: NOW });
  assert.equal(acknowledgement.version, 1);
  assert.equal(acknowledgement.status, "applied");
  assert.ok(client.calls.some(({ text }) => text.startsWith("INSERT INTO bundle_acknowledgements") && text.includes("ON CONFLICT")));
  assert.ok(client.calls.some(({ text }) => text.startsWith("INSERT INTO bundle_heads")
    && text.includes("ON CONFLICT (organization_id,device_id) DO UPDATE SET")));
  await assert.rejects(() => api.assignBundleHead({ organization_id: ids.organization, device_id: ids.device, state_fingerprint: HASH, minimum_sequence: 1, issued_at: LATER, expires_at: NOW }), { code: "ERR_TIMESTAMP" });
});

test("bundle authority snapshot and head assignment share the revocation organization lock and transaction", async () => {
  const client = new FakeClient();
  const api = repository(client);
  const first = await api.snapshotAndAssignBundleHead({
    organization_id: ids.organization, device_id: ids.device, minimum_sequence: 1, issued_at: NOW, expires_at: LATER
  });

  assert.equal(first.snapshot.organization_id, ids.organization);
  assert.equal(first.snapshot.device_id, ids.device);
  assert.equal(first.snapshot.active_policy.policy_id, "22222222-2222-4222-8222-222222222222");
  assert.deepEqual(first.snapshot.policy_scope.operations, ["git.commit.sign"]);
  assert.deepEqual(first.snapshot.revoked_devices, [ids.device]);
  assert.equal(first.snapshot.global_revoked, false);
  assert.match(first.snapshot.state_fingerprint, /^[0-9a-f]{64}$/u);
  assert.equal(first.head.sequence, 1);
  assert.equal(first.head.state_fingerprint, first.snapshot.state_fingerprint);

  const lockCall = client.calls.find(({ text }) => text.includes("pg_advisory_xact_lock"));
  assert.deepEqual(lockCall.params, [`agentpass:organization:${ids.organization}`]);
  assert.equal(client.calls[0].text, "BEGIN");
  assert.ok(client.calls.findIndex(({ text }) => text.includes("pg_advisory_xact_lock"))
    < client.calls.findIndex(({ text }) => text.startsWith("SELECT organization_id,id,sequence,name")));
  assert.equal(client.calls.at(-1).text, "COMMIT");

  const second = await api.snapshotAndAssignBundleHead({
    organization_id: ids.organization, device_id: ids.device, minimum_sequence: 1, issued_at: NOW, expires_at: LATER,
    state_fingerprint: first.snapshot.state_fingerprint
  });
  assert.equal(second.head.sequence, first.head.sequence + 1);
  await assert.rejects(() => api.snapshotAndAssignBundleHead({
    organization_id: ids.organization, device_id: ids.device, minimum_sequence: 1, issued_at: NOW, expires_at: LATER,
    state_fingerprint: HASH
  }), { code: "ERR_STATE_FINGERPRINT_MISMATCH" });
});

test("audit ingestion verifies the protocol hash, tenant/device agent binding, duplicate evidence, and head shape", async () => {
  const client = new FakeClient();
  const api = repository(client);
  const event = auditEvent();
  const ingested = await api.ingestDeviceAuditEvents({ organization_id: ids.organization, device_id: ids.device, events: [event], received_at: NOW });
  assert.deepEqual(ingested.accepted, [event.event_id]);
  assert.deepEqual(ingested.duplicates, []);
  assert.deepEqual(ingested.gaps, []);
  assert.deepEqual(ingested.head, { last_hash: event.event_hash, last_event_id: event.event_id, chain_status: "continuous", gap_count: 0 });
  const insert = client.calls.find(({ text }) => text.startsWith("INSERT INTO device_audit_events"));
  assert.match(insert.text, /organization_id,device_id,event_id/);
  assert.deepEqual(insert.params.slice(0, 2), [ids.organization, ids.device]);

  const tampered = { ...event, event_hash: "f".repeat(64) };
  await assert.rejects(() => api.ingestDeviceAuditEvents({ organization_id: ids.organization, device_id: ids.device, events: [tampered] }), { code: "ERR_AUDIT_HASH_MISMATCH" });
  await assert.rejects(() => api.ingestDeviceAuditEvents({ organization_id: ids.organization, device_id: ids.device, events: [] }), { code: "ERR_LIMIT_EXCEEDED" });
});

test("invalid tenant and acknowledgement inputs fail before opening a transaction", async () => {
  const client = new FakeClient();
  const api = repository(client);
  await assert.rejects(() => api.listRevocations({ organization_id: "not-a-uuid" }), { code: "ERR_TENANT_SCOPE" });
  await assert.rejects(() => api.acknowledgeBundle({ organization_id: ids.organization, device_id: ids.device, format_epoch: 1, sequence: 1, statement_hash: HASH, status: "blocked" }), { code: "ERR_INPUT" });
  await assert.rejects(() => api.createRevocation({ organization_id: ids.organization, target_type: "device", target_id: ids.device, reason: "missing actor" }), { code: "ERR_UUID" });
  assert.equal(client.calls.length, 0);
});
