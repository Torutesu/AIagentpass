import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import { canonicalJson } from "../../../../packages/protocol/src/index.mjs";
import {
  CONTROL_PLANE_SCHEMA_GAPS,
  DEVICE_REFRESH_POLL_RETURN_SHAPE,
  createControlPlaneAuthorityRepository
} from "../../src/postgres/control-plane-authority-repository.mjs";
import { createRefreshNonceCodec } from "../../src/postgres/refresh-nonce-codec.mjs";

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
    this.refreshState = { organization_id: ids.organization, device_id: ids.device, desired_generation: 3, observed_generation: 2, refresh_state: "pending", refresh_requested_at: NOW, last_delivered_at: null, last_observed_at: NOW, last_error_code: null, updated_at: NOW };
  }

  async query(text, params = []) {
    this.calls.push({ text, params });
    if (["BEGIN", "COMMIT", "ROLLBACK"].includes(text)) return result();
    if (text.includes("pg_advisory_xact_lock")) return result([{ locked: true }]);
    if (text.startsWith("SELECT id FROM organizations")) return result([{ id: ids.organization }]);
    if (text.startsWith("SELECT member_id FROM memberships")) return result([{ member_id: ids.member }]);
    if (text.startsWith("SELECT id FROM devices")) return result([{ id: ids.device }]);
    if (text.startsWith("SELECT id\n        FROM devices")) return result([{ id: ids.device }]);
    if (text.startsWith("SELECT organization_id,generation")) return result([{ organization_id: ids.organization, generation: 3 }]);
    if (text.startsWith("SELECT generation\n")) return result([{ generation: 3 }]);
    if (text.startsWith("SELECT outbox_id,desired_generation,refresh_nonce_key_id,refresh_nonce_digest,replayed")) return result([{ outbox_id: params[0], desired_generation: params[3], refresh_nonce_key_id: params[4], refresh_nonce_digest: params[5], replayed: false }]);
    if (text.startsWith("SELECT state.organization_id")) return result([{ organization_id: ids.organization, device_id: ids.device, desired_generation: 3, refresh_state: "pending", outbox_id: "88888888-8888-4888-8888-888888888888", refresh_nonce_key_id: "refresh-nonce-v3", refresh_nonce_digest: crypto.createHash("sha256").update(Buffer.alloc(16, 0x42)).digest(), published_at: NOW, expires_at: LATER }]);
    if (text.startsWith("SELECT attempt_count,status,expires_at")) return result([{ attempt_count: 0, status: "pending", expires_at: LATER }]);
    if (text.startsWith("SELECT organization_id,device_id,desired_generation,observed_generation,refresh_state")) return result([this.refreshState]);
    if (text.startsWith("SELECT desired_generation,observed_generation,refresh_state")) return result([this.refreshState]);
    if (text.startsWith("UPDATE device_refresh_outbox") && text.includes("attempt_count=$5")) return result([{ outbox_id: params[2], desired_generation: params[3], status: "delivered", attempt_count: params[4] }]);
    if (text.startsWith("INSERT INTO device_refresh_delivery_attempts")) return result([]);
    if (text.startsWith("UPDATE device_control_plane_state") && text.includes("last_delivered_at")) return result([]);
    if (text.startsWith("UPDATE device_refresh_outbox")) return result([]);
    if (text.startsWith("SELECT epochs.organization_id,epochs.device_id,epochs.key_epoch,epochs.status")) return result([{ organization_id: ids.organization, device_id: ids.device, key_epoch: 1, status: "active" }]);
    if (text.startsWith("SELECT organization_id,device_id,device_key_epoch,format_epoch,sequence,statement_hash,result")) return result();
    if (text.startsWith("SELECT organization_id,device_id,format_epoch,sequence,statement_hash,authority_generation")) return result([{ organization_id: ids.organization, device_id: ids.device, format_epoch: 2, sequence: 1, statement_hash: HASH, authority_generation: 3, issued_at: NOW, expires_at: LATER }]);
    if (text.startsWith("SELECT organization_id,device_id,desired_generation,format_epoch,sequence,statement_hash,status")) return result([{ organization_id: ids.organization, device_id: ids.device, desired_generation: 3, format_epoch: 2, sequence: 1, statement_hash: HASH, status: "delivered" }]);
    if (text.startsWith("SELECT accepted,duplicate")) return result([{ accepted: true, duplicate: false }]);
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
  return createControlPlaneAuthorityRepository({
    client,
    cursorSecret: Buffer.alloc(32, 0x31),
    refreshNonceCodec: createRefreshNonceCodec({ keys: { "refresh-nonce-v3": Buffer.alloc(32, 0x33) }, activeKeyId: "refresh-nonce-v3" }),
    now: () => NOW
  });
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
    "appendDeviceAuditEvent", "listDeviceAuditEvents", "getAuditHealth", "snapshotAndAssignBundleHead", "pollDeviceRefresh", "getDeviceRefreshState"
  ]) assert.equal(typeof api[method], "function", method);
  assert.deepEqual(CONTROL_PLANE_SCHEMA_GAPS, []);
  assert.deepEqual(Object.keys(DEVICE_REFRESH_POLL_RETURN_SHAPE), ["organization_id", "device_id", "desired_generation", "refresh_state", "outbox_id", "refresh_nonce_key_id", "refresh_nonce_digest", "published_at", "expires_at"]);
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
    organization_id: ids.organization, device_id: ids.device, minimum_sequence: 1, issued_at: NOW, expires_at: LATER,
    statement_hash_factory: () => HASH
  });

  assert.equal(first.snapshot.organization_id, ids.organization);
  assert.equal(first.snapshot.device_id, ids.device);
  assert.equal(first.snapshot.active_policy.policy_id, "22222222-2222-4222-8222-222222222222");
  assert.deepEqual(first.snapshot.policy_scope.operations, ["git.commit.sign"]);
  assert.deepEqual(first.snapshot.revoked_devices, [ids.device]);
  assert.equal(first.snapshot.global_revoked, false);
  assert.match(first.snapshot.state_fingerprint, /^[0-9a-f]{64}$/u);
  assert.equal(first.head.sequence, 1);
  assert.equal(first.head.state_fingerprint, HASH);
  assert.equal(first.desired_generation, 3);

  const lockCall = client.calls.find(({ text }) => text.includes("pg_advisory_xact_lock"));
  assert.deepEqual(lockCall.params, [`agentpass:organization:${ids.organization}`]);
  assert.equal(client.calls[0].text, "BEGIN");
  assert.ok(client.calls.findIndex(({ text }) => text.includes("pg_advisory_xact_lock"))
    < client.calls.findIndex(({ text }) => text.startsWith("SELECT organization_id,id,sequence,name")));
  assert.equal(client.calls.at(-1).text, "COMMIT");

  const second = await api.snapshotAndAssignBundleHead({
    organization_id: ids.organization, device_id: ids.device, minimum_sequence: 1, issued_at: NOW, expires_at: LATER,
    state_fingerprint: first.snapshot.state_fingerprint,
    statement_hash_factory: () => "a".repeat(64)
  });
  assert.equal(second.head.sequence, first.head.sequence + 1);
  const wireStatementHash = "b".repeat(64);
  let factoryInput;
  const wireBound = await api.snapshotAndAssignBundleHead({
    organization_id: ids.organization, device_id: ids.device, minimum_sequence: 1, issued_at: NOW, expires_at: LATER,
    statement_hash_factory: (input) => { factoryInput = input; return wireStatementHash; }
  });
  assert.equal(factoryInput.snapshot.state_fingerprint, first.snapshot.state_fingerprint);
  assert.equal(factoryInput.head.sequence, wireBound.head.sequence);
  assert.equal(wireBound.head.state_fingerprint, wireStatementHash);
  assert.equal(client.bundleHead.statement_hash, wireStatementHash);
  await assert.rejects(() => api.snapshotAndAssignBundleHead({
    organization_id: ids.organization, device_id: ids.device, minimum_sequence: 1, issued_at: NOW, expires_at: LATER,
    state_fingerprint: HASH,
    statement_hash_factory: () => "c".repeat(64)
  }), { code: "ERR_STATE_FINGERPRINT_MISMATCH" });
});

test("bundle statement hash derivation fails before persistence and rolls back the authority transaction", async () => {
  const client = new FakeClient();
  const api = repository(client);
  await assert.rejects(() => api.snapshotAndAssignBundleHead({
    organization_id: ids.organization,
    device_id: ids.device,
    minimum_sequence: 1,
    issued_at: NOW,
    expires_at: LATER,
    statement_hash_factory: () => { throw new Error("signer configuration unavailable"); }
  }), { code: "ERR_BUNDLE_STATEMENT" });
  assert.equal(client.bundleHead, null);
  assert.equal(client.calls.some(({ text }) => text.startsWith("INSERT INTO bundle_heads")), false);
  assert.equal(client.calls.at(-1).text, "ROLLBACK");
});

test("authority reduction derives a restart-safe nonce and sends only key id plus digest to SQL", async () => {
  const client = new FakeClient();
  const api = repository(client);
  const resultValue = await api.advanceAuthorityGenerationAndEnqueueRefresh({
    organization_id: ids.organization,
    issued_at: NOW,
    expires_at: "2026-08-13T00:04:00.000Z",
    outbox_ids: { [ids.device]: "88888888-8888-4888-8888-888888888888" }
  });
  assert.equal(resultValue.generation, 3);
  assert.equal(resultValue.devices.length, 1);
  assert.equal("refresh_nonce" in resultValue.devices[0], false);
  assert.equal(resultValue.devices[0].refresh_nonce_key_id, "refresh-nonce-v3");
  assert.match(resultValue.devices[0].refresh_nonce_digest, /^[0-9a-f]{64}$/u);
  const enqueue = client.calls.find(({ text }) => text.startsWith("SELECT outbox_id,desired_generation,refresh_nonce_key_id,refresh_nonce_digest,replayed"));
  assert.ok(enqueue);
  assert.equal(enqueue.params.some((value) => typeof value === "string" && value.includes("refresh_nonce")), false);
  assert.equal(enqueue.params.some((value) => typeof value === "string" && value.length === 22), false);
  assert.ok(Buffer.isBuffer(enqueue.params[5]));
  assert.equal(enqueue.params[5].length, 32);
  assert.equal(enqueue.params[4], "refresh-nonce-v3");
  assert.ok(client.calls.some(({ text }) => text.includes("pg_advisory_xact_lock")));
  assert.equal(client.calls.at(-1).text, "COMMIT");
});

test("exact revocation replay returns the committed generation without advancing or enqueueing again", async () => {
  class ReplayClient extends FakeClient {
    async query(text, params = []) {
      if (text.startsWith("INSERT INTO revocations")) {
        this.calls.push({ text, params });
        return result();
      }
      return super.query(text, params);
    }
  }
  const client = new ReplayClient();
  const api = repository(client);
  const replay = await api.reduceAuthorityAndEnqueueRefresh({
    organization_id: ids.organization,
    target_type: "device",
    target_id: ids.device,
    reason: "operator-request",
    created_by: ids.member,
    revocation_id: ids.revocation,
    created_at: NOW,
    issued_at: NOW,
    expires_at: "2026-08-13T00:04:00.000Z"
  });
  assert.equal(replay.generation, 3);
  assert.equal(replay.revocation.replayed, true);
  assert.deepEqual(replay.devices, []);
  assert.equal(client.calls.some(({ text }) => text.startsWith("SELECT organization_id,generation")), false);
  assert.equal(client.calls.some(({ text }) => text.startsWith("SELECT outbox_id,desired_generation")), false);
  assert.equal(client.calls.at(-1).text, "COMMIT");
});

test("refresh polling returns exact unsigned reconstruction metadata in one bounded tenant-qualified query", async () => {
  const client = new FakeClient();
  const api = repository(client);
  const state = await api.pollDeviceRefresh({ organization_id: ids.organization, device_id: ids.device, after_generation: 1, wait_ms: 30_000 });
  assert.deepEqual(state, {
    organization_id: ids.organization,
    device_id: ids.device,
    desired_generation: 3,
    refresh_state: "pending",
    outbox_id: "88888888-8888-4888-8888-888888888888",
    refresh_nonce_key_id: "refresh-nonce-v3",
    refresh_nonce_digest: crypto.createHash("sha256").update(Buffer.alloc(16, 0x42)).digest("hex"),
    published_at: NOW,
    expires_at: LATER
  });
  assert.equal(Object.isFrozen(state), true);
  assert.equal(client.calls.length, 1);
  assert.match(client.calls[0].text, /refresh_outbox\.organization_id=\$1/);
  assert.match(client.calls[0].text, /refresh_outbox\.device_id=\$2/);
  assert.match(client.calls[0].text, /refresh_outbox\.desired_generation>\$3/);
  assert.match(client.calls[0].text, /refresh_nonce_key_id/);
  assert.match(client.calls[0].text, /created_at AS published_at/);
  await assert.rejects(() => api.pollDeviceRefresh({ organization_id: ids.organization, device_id: ids.device, wait_ms: 30_001 }), { code: "ERR_LIMIT" });
});

test("refresh delivery evidence and device fetching state commit atomically without nonce material", async () => {
  const client = new FakeClient();
  const api = repository(client);
  const delivered = await api.markDeviceRefreshDelivered({ organization_id: ids.organization, device_id: ids.device, outbox_id: "88888888-8888-4888-8888-888888888888", desired_generation: 3, delivered_at: NOW });
  assert.deepEqual(delivered, { outbox_id: "88888888-8888-4888-8888-888888888888", desired_generation: 3, status: "delivered", attempt_count: 1 });
  assert.equal(client.calls[0].text, "BEGIN");
  assert.ok(client.calls.some(({ text }) => text.startsWith("INSERT INTO device_refresh_delivery_attempts")));
  assert.ok(client.calls.some(({ text }) => text.includes("refresh_state=CASE") && text.includes("'fetching'")));
  assert.equal(client.calls.flatMap(({ params }) => params).some((value) => typeof value === "string" && /^[A-Za-z0-9_-]{22}$/u.test(value)), false);
  assert.equal(client.calls.at(-1).text, "COMMIT");
});

test("G4 ACK uses the SQL function with only a nonce digest and returns duplicate-safe refresh state", async () => {
  const client = new FakeClient();
  const api = repository(client);
  const nonce = Buffer.alloc(16, 0x42).toString("base64url");
  const acknowledgement = await api.acknowledgeBundle({
    version: 1, type: "agentpass.bundle-ack", organization_id: ids.organization, device_id: ids.device,
    device_key_epoch: 1, format_epoch: 2, sequence: 1, statement_hash: HASH, result: "applied",
    observed_at: NOW, nonce, signature_algorithm: "p256-sha256", signature: Buffer.alloc(64, 0x22).toString("base64url")
  });
  assert.deepEqual(acknowledgement, { duplicate: false, observed_generation: 2, refresh_state: "pending" });
  const ackCall = client.calls.find(({ text }) => text.startsWith("SELECT accepted,duplicate"));
  assert.ok(ackCall);
  assert.equal(ackCall.params.includes(nonce), false);
  assert.ok(Buffer.isBuffer(ackCall.params.at(-1)));
  assert.equal(ackCall.params.at(-1).length, 32);
  await assert.rejects(() => api.acknowledgeBundle({
    version: 1, type: "agentpass.bundle-ack", organization_id: ids.organization, device_id: ids.device,
    device_key_epoch: 1, format_epoch: 2, sequence: 1, statement_hash: HASH, result: "applied",
    observed_at: NOW, nonce, signature_algorithm: "p256-sha256", signature: Buffer.alloc(64, 0x22).toString("base64url"), extra: true
  }), { code: "ERR_ACK_INVALID" });
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
