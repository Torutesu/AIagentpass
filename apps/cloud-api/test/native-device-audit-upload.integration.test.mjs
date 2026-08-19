import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { computeAuditEventHash, createCloudStore } from "../src/store.mjs";

const ZERO_HASH = "0".repeat(64);
const NOW = "2026-08-20T00:00:00.000Z";

test("local Native Device audit upload reconciles response loss as an exact duplicate and preserves a continuous head", async (t) => {
  const fixture = await createLocalFixture(t);
  const first = auditEvent(fixture.agentA, { deviceTimestamp: NOW, previousHash: ZERO_HASH });
  const second = auditEvent(fixture.agentA, { deviceTimestamp: "2026-08-20T00:00:01.000Z", previousHash: first.event_hash });

  // The first committed upload has no response at the client boundary. The
  // retry deliberately uses a fresh batch key so event identity, not the local
  // idempotency record, proves that the server already committed the evidence.
  await fixture.store.ingestDeviceAuditEvents({
    organizationId: fixture.organization,
    deviceId: fixture.deviceA,
    events: [first, second],
    idempotencyKey: "native-upload-response-lost-0001"
  });
  const retry = await fixture.store.ingestDeviceAuditEvents({
    organizationId: fixture.organization,
    deviceId: fixture.deviceA,
    events: [first, second],
    idempotencyKey: "native-upload-response-lost-0002"
  });

  assert.deepEqual(retry.accepted, []);
  assert.deepEqual(retry.duplicates, [first.event_id, second.event_id]);
  assert.deepEqual(retry.gaps, []);
  assert.deepEqual(retry.head, {
    last_hash: second.event_hash,
    last_event_id: second.event_id,
    chain_status: "continuous",
    gap_count: 0
  });
  assert.deepEqual(
    (await fixture.store.getAuditHealth({ organizationId: fixture.organization })).find((item) => item.device_id === fixture.deviceA),
    {
      device_id: fixture.deviceA,
      last_hash: second.event_hash,
      last_event_id: second.event_id,
      chain_status: "continuous",
      gap_count: 0
    }
  );
  assert.equal((await fixture.store.listDeviceAuditEvents({ organizationId: fixture.organization, deviceId: fixture.deviceA })).events.length, 2);
});

test("local Native Device audit upload records a gap and keeps the head in gap state across later events", async (t) => {
  const fixture = await createLocalFixture(t);
  const first = auditEvent(fixture.agentA, { deviceTimestamp: NOW, previousHash: ZERO_HASH });
  const missingPredecessor = auditEvent(fixture.agentA, {
    deviceTimestamp: "2026-08-20T00:00:01.000Z",
    previousHash: "f".repeat(64)
  });
  const continuation = auditEvent(fixture.agentA, {
    deviceTimestamp: "2026-08-20T00:00:02.000Z",
    previousHash: missingPredecessor.event_hash
  });

  await fixture.store.ingestDeviceAuditEvents({
    organizationId: fixture.organization,
    deviceId: fixture.deviceA,
    events: [first],
    idempotencyKey: "native-upload-gap-0001"
  });
  const result = await fixture.store.ingestDeviceAuditEvents({
    organizationId: fixture.organization,
    deviceId: fixture.deviceA,
    events: [missingPredecessor, continuation],
    idempotencyKey: "native-upload-gap-0002"
  });

  assert.deepEqual(result.accepted, [missingPredecessor.event_id, continuation.event_id]);
  assert.equal(result.gaps.length, 1);
  assert.equal(result.gaps[0].event_id, missingPredecessor.event_id);
  assert.equal(result.gaps[0].expected_previous_hash, first.event_hash);
  assert.equal(result.gaps[0].received_previous_hash, missingPredecessor.previous_hash);
  assert.deepEqual(result.head, {
    last_hash: continuation.event_hash,
    last_event_id: continuation.event_id,
    chain_status: "gap",
    gap_count: 1
  });
});

test("local Native Device audit upload rejects hash equivocation without moving the committed head", async (t) => {
  const fixture = await createLocalFixture(t);
  const original = auditEvent(fixture.agentA, { deviceTimestamp: NOW, previousHash: ZERO_HASH });
  await fixture.store.ingestDeviceAuditEvents({
    organizationId: fixture.organization,
    deviceId: fixture.deviceA,
    events: [original],
    idempotencyKey: "native-upload-equivocation-0001"
  });

  const equivocation = withHash({ ...original, decision: "deny", reason: "branch_denied" });
  await assert.rejects(
    () => fixture.store.ingestDeviceAuditEvents({
      organizationId: fixture.organization,
      deviceId: fixture.deviceA,
      events: [equivocation],
      idempotencyKey: "native-upload-equivocation-0002"
    }),
    { code: "ERR_AUDIT_DEDUP_CONFLICT" }
  );

  assert.deepEqual(
    (await fixture.store.getAuditHealth({ organizationId: fixture.organization })).find((item) => item.device_id === fixture.deviceA),
    {
      device_id: fixture.deviceA,
      last_hash: original.event_hash,
      last_event_id: original.event_id,
      chain_status: "continuous",
      gap_count: 0
    }
  );
  assert.equal((await fixture.store.listDeviceAuditEvents({ organizationId: fixture.organization, deviceId: fixture.deviceA })).events.length, 1);
});

test("local Native Device audit upload enforces the authenticated device binding", async (t) => {
  const fixture = await createLocalFixture(t);
  const event = auditEvent(fixture.agentA, { deviceTimestamp: NOW, previousHash: ZERO_HASH });

  await assert.rejects(
    () => fixture.store.ingestDeviceAuditEvents({
      organizationId: fixture.organization,
      deviceId: fixture.deviceB,
      events: [event],
      idempotencyKey: "native-upload-device-binding-0001"
    }),
    { code: "ERR_AUDIT_DEVICE_MISMATCH" }
  );
  assert.deepEqual(await fixture.store.getAuditHealth({ organizationId: fixture.organization }), [
    { device_id: fixture.deviceA, last_hash: ZERO_HASH, last_event_id: null, chain_status: "continuous", gap_count: 0 },
    { device_id: fixture.deviceB, last_hash: ZERO_HASH, last_event_id: null, chain_status: "continuous", gap_count: 0 }
  ]);
});

async function createLocalFixture(t) {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), "agentpass-native-audit-local-"));
  const store = await createCloudStore({ dataDir: directory });
  const organization = crypto.randomUUID();
  const deviceA = crypto.randomUUID();
  const deviceB = crypto.randomUUID();
  const agentA = crypto.randomUUID();
  await store.createOrganization({ organizationId: organization, name: "Native audit local", idempotencyKey: `${organization}-organization` });
  await store.createDevice({ organizationId: organization, deviceId: deviceA, name: "Native audit A", publicKey: "ssh-ed25519 AAAAdeviceA", idempotencyKey: `${deviceA}-device` });
  await store.createDevice({ organizationId: organization, deviceId: deviceB, name: "Native audit B", publicKey: "ssh-ed25519 AAAAdeviceB", idempotencyKey: `${deviceB}-device` });
  await store.createAgent({
    organizationId: organization,
    deviceId: deviceA,
    agentId: agentA,
    version: 1,
    name: "Native audit agent",
    kind: "claude-code",
    publicKey: "-----BEGIN PUBLIC KEY-----\nnative-audit-agent\n-----END PUBLIC KEY-----",
    idempotencyKey: `${agentA}-agent`
  });
  t.after(async () => {
    await store.close();
    await fs.rm(directory, { recursive: true, force: true });
  });
  return { store, organization, deviceA, deviceB, agentA };
}

function auditEvent(agentId, { deviceTimestamp, previousHash }) {
  return withHash({
    version: 1,
    event_id: crypto.randomUUID(),
    request_id: crypto.randomUUID(),
    agent_id: agentId,
    operation: "git.commit.sign",
    decision: "allow",
    reason: "allowed",
    policy_sequence: 1,
    capability_sequence: 1,
    repository: "/work/native-audit",
    branch: "feature/native-audit",
    remote: "git@example.test:native-audit.git",
    payload_digest: "a".repeat(64),
    device_timestamp: deviceTimestamp,
    previous_hash: previousHash
  });
}

function withHash(event) {
  return { ...event, event_hash: computeAuditEventHash(event) };
}
