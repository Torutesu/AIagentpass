import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { CloudStoreError, VersionConflictError, auditEventHashPreimage, computeAuditEventHash, createCapabilityNonce, createCloudStore } from "../src/store.mjs";
import { canonicalJson } from "../../../packages/protocol/src/index.mjs";

const ids = {
  org: "11111111-1111-4111-8111-111111111111",
  org2: "22222222-2222-4222-8222-222222222222",
  device: "33333333-3333-4333-8333-333333333333",
  agent: "44444444-4444-4444-8444-444444444444",
  membership: "55555555-5555-4555-8555-555555555555",
  policy: "66666666-6666-4666-8666-666666666666",
  capability: "77777777-7777-4777-8777-777777777777",
  revocation: "88888888-8888-4888-8888-888888888888",
  event1: "99999999-9999-4999-8999-999999999999",
  event2: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
};

test("store process lock rejects concurrent writers and releases on close", async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), "agentpass-store-lock-"));
  const first = await createCloudStore({ dataDir: directory });
  await assert.rejects(() => createCloudStore({ dataDir: directory }), { code: "ERR_STORE_LOCKED" });
  await first.close();
  const reopened = await createCloudStore({ dataDir: directory });
  await reopened.close();
  await fs.rm(directory, { recursive: true, force: true });
});

const timestamp = "2026-08-11T01:00:00.000Z";
const digest = "a".repeat(64);

test("capability nonce generation normalizes every base64url prefix into the protocol alphabet", () => {
  const nonce = createCapabilityNonce(() => Buffer.alloc(32, 0xff));
  assert.match(nonce, /^[A-Za-z0-9][A-Za-z0-9._:-]{31,127}$/);
  assert.equal(nonce.startsWith("A"), true);
  assert.throws(() => createCapabilityNonce(() => Buffer.alloc(31)), { code: "ERR_INVALID_INPUT" });
});

async function fixture() {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), "agentpass-cloud-"));
  const store = await createCloudStore({ dataDir: directory });
  const organization = await store.createOrganization({ organizationId: ids.org, name: "Acme Build", idempotencyKey: "org-create-1" });
  return { directory, store, organization };
}

async function addDeviceAndAgent(store, suffix = "1") {
  const device = await store.createDevice({
    organizationId: ids.org,
    deviceId: ids.device,
    name: "Build Mac",
    publicKey: `ssh-ed25519 AAAAdevice${suffix}`,
    idempotencyKey: `device-${suffix}`
  });
  const agent = await store.createAgent({
    organizationId: ids.org,
    deviceId: device.device_id,
    version: 1,
    agentId: ids.agent,
    name: "Claude Code",
    kind: "claude-code",
    publicKey: "-----BEGIN PUBLIC KEY-----\nagent\n-----END PUBLIC KEY-----",
    createdAt: timestamp,
    idempotencyKey: `agent-${suffix}`
  });
  return { device, agent };
}

function scope() {
  return {
    operations: ["git.commit.sign"],
    repositories: ["/work/project"],
    branches: { allow: ["feature/*"], deny: ["main"] },
    remotes: { allow: ["git@example.test:project.git"] }
  };
}

function auditEvent(eventId, previousHash, eventHash) {
  const event = {
    version: 1,
    event_id: eventId,
    request_id: ids.event1,
    agent_id: ids.agent,
    operation: "git.commit.sign",
    decision: "allow",
    reason: "allowed",
    policy_sequence: 1,
    capability_sequence: 1,
    repository: "/work/project",
    branch: "feature/cloud-store",
    remote: "git@example.test:project.git",
    payload_digest: digest,
    device_timestamp: timestamp,
    previous_hash: previousHash,
    event_hash: eventHash
  };
  return { ...event, event_hash: eventHash ?? computeAuditEventHash(event) };
}

test("creates explicitly scoped tenant resources and keeps IDs unique", async (t) => {
  const { directory, store } = await fixture();
  t.after(async () => { await store.close(); await fs.rm(directory, { recursive: true, force: true }); });

  const { device, agent } = await addDeviceAndAgent(store);
  assert.equal(device.organization_id, ids.org);
  assert.equal(agent.device_id, ids.device);
  const membership = await store.createMembership({ organizationId: ids.org, membershipId: ids.membership, principalId: "human-1", role: "admin", idempotencyKey: "membership-1" });
  const policy = await store.createPolicy({ organizationId: ids.org, policyId: ids.policy, name: "default", scope: scope(), idempotencyKey: "policy-1" });
  const capability = await store.createCapability({
    organizationId: ids.org,
    capabilityId: ids.capability,
    issuer: "control-plane",
    keyId: "control-key-1",
    agentId: agent.agent_id,
    deviceId: device.device_id,
    operations: ["git.commit.sign"],
    nonce: "0123456789abcdef",
    notBefore: timestamp,
    expiresAt: "2026-08-11T02:00:00Z",
    sequence: 1,
    idempotencyKey: "capability-1"
  });
  assert.equal(membership.version, 1);
  assert.equal(policy.scope.branches.deny[0], "main");
  assert.equal(capability.capability_id, ids.capability);
  assert.equal(capability.signature, undefined);
  await assert.rejects(() => store.createDevice({ organizationId: ids.org, deviceId: ids.device, name: "Other", publicKey: "ssh-ed25519 AAAAother", idempotencyKey: "device-duplicate" }), { code: "ERR_UNIQUE_CONSTRAINT" });
  await assert.rejects(() => store.getDevice({ organizationId: ids.org2, deviceId: ids.device }), { code: "ERR_NOT_FOUND" });
});

test("manual wake is idempotent and never invents authority in the file-store profile", async (t) => {
  const { directory, store } = await fixture();
  t.after(async () => { await store.close(); await fs.rm(directory, { recursive: true, force: true }); });
  await addDeviceAndAgent(store);

  const input = {
    organizationId: ids.org,
    deviceId: ids.device,
    principalId: "operator-1",
    idempotencyKey: "manual-wake-0001",
    requestedAt: "2026-08-11T01:02:00.000Z"
  };
  const first = await store.requestDeviceWake(input);
  const replay = await store.requestDeviceWake({ ...input, requestedAt: "2026-08-11T01:03:00.000Z" });
  assert.deepEqual(replay, first);
  assert.deepEqual(first, {
    version: 1,
    request_id: first.request_id,
    device_id: ids.device,
    desired_generation: null,
    status: "no_pending_refresh",
    requested_at: "2026-08-11T01:02:00.000Z"
  });
  assert.match(first.request_id, /^[0-9a-f-]{36}$/u);
  assert.equal(Object.hasOwn(first, "outbox_id"), false);
  assert.equal(Object.hasOwn(first, "nonce"), false);
  assert.equal(Object.hasOwn(first, "bundle"), false);

  const otherPrincipal = await store.requestDeviceWake({ ...input, principalId: "operator-2", requestedAt: "2026-08-11T01:04:00.000Z" });
  assert.notEqual(otherPrincipal.request_id, first.request_id);
  await assert.rejects(store.requestDeviceWake({ ...input, organizationId: ids.org2 }), { code: "ERR_NOT_FOUND" });
});

test("serializes mutations, deduplicates idempotency, and enforces optimistic versions", async (t) => {
  const { directory, store } = await fixture();
  t.after(async () => { await store.close(); await fs.rm(directory, { recursive: true, force: true }); });
  const first = await store.createMembership({ organizationId: ids.org, principalId: "same-human", role: "viewer", idempotencyKey: "same-key" });
  const replay = await store.createMembership({ organizationId: ids.org, principalId: "same-human", role: "viewer", idempotencyKey: "same-key" });
  assert.deepEqual(replay, first);
  await assert.rejects(() => store.createMembership({ organizationId: ids.org, principalId: "different-human", role: "viewer", idempotencyKey: "same-key" }), { code: "ERR_IDEMPOTENCY_CONFLICT" });
  await assert.rejects(() => store.updateMembership({ organizationId: ids.org, membershipId: first.membership_id, patch: { role: "admin" }, idempotencyKey: "membership-update-1" }), { code: "ERR_VERSION_REQUIRED" });
  const updated = await store.updateMembership({ organizationId: ids.org, membershipId: first.membership_id, expectedVersion: 1, patch: { role: "admin" }, idempotencyKey: "membership-update-2" });
  assert.equal(updated.version, 2);
  await assert.rejects(() => store.updateMembership({ organizationId: ids.org, membershipId: first.membership_id, expectedVersion: 1, patch: { role: "owner" }, idempotencyKey: "membership-update-3" }), VersionConflictError);
  await assert.rejects(() => store.createMembership({ organizationId: ids.org, principalId: "no-key", role: "viewer" }), { code: "ERR_IDEMPOTENCY_KEY_REQUIRED" });
});

test("ingests append-only audit events with dedupe and recorded chain gaps", async (t) => {
  const { directory, store } = await fixture();
  t.after(async () => { await store.close(); await fs.rm(directory, { recursive: true, force: true }); });
  await addDeviceAndAgent(store);
  const firstEvent = auditEvent(ids.event1, "0".repeat(64));
  const firstHash = firstEvent.event_hash;
  const first = await store.ingestDeviceAuditEvents({ organizationId: ids.org, deviceId: ids.device, events: [firstEvent], idempotencyKey: "audit-1" });
  assert.deepEqual(first.accepted, [ids.event1]);
  const duplicate = await store.ingestDeviceAuditEvents({ organizationId: ids.org, deviceId: ids.device, events: [firstEvent], idempotencyKey: "audit-2" });
  assert.deepEqual(duplicate.duplicates, [ids.event1]);
  const gapEvent = auditEvent(ids.event2, "d".repeat(64));
  const second = await store.appendDeviceAuditEvent({ organizationId: ids.org, deviceId: ids.device, event: gapEvent, idempotencyKey: "audit-3" });
  assert.equal(second.gaps.length, 1);
  assert.equal(second.gaps[0].expected_previous_hash, firstHash);
  assert.equal((await store.getAuditHealth({ organizationId: ids.org }))[0].chain_status, "gap");
  assert.equal((await store.listDeviceAuditEvents({ organizationId: ids.org, deviceId: ids.device })).events.length, 2);
});

test("rejects fabricated event hashes before changing the audit head", async (t) => {
  const { directory, store } = await fixture();
  t.after(async () => { await store.close(); await fs.rm(directory, { recursive: true, force: true }); });
  await addDeviceAndAgent(store);
  const valid = auditEvent(ids.event1, "0".repeat(64));
  const validSecond = auditEvent(ids.event2, valid.event_hash);
  const fabricated = { ...validSecond, event_hash: "f".repeat(64) };

  await assert.rejects(
    () => store.ingestDeviceAuditEvents({ organizationId: ids.org, deviceId: ids.device, events: [fabricated], idempotencyKey: "audit-fabricated-1" }),
    (error) => {
      assert.equal(error.code, "ERR_AUDIT_HASH_MISMATCH");
      assert.equal(error.details.event_id, ids.event2);
      assert.equal(error.details.received_hash, fabricated.event_hash);
      assert.equal(error.details.expected_hash, computeAuditEventHash(validSecond));
      return true;
    }
  );

  assert.deepEqual(await store.getAuditHealth({ organizationId: ids.org }), [{
    device_id: ids.device,
    last_hash: "0".repeat(64),
    last_event_id: null,
    chain_status: "continuous",
    gap_count: 0
  }]);
  assert.deepEqual(await store.listDeviceAuditEvents({ organizationId: ids.org, deviceId: ids.device }), { events: [], next_cursor: null });
});

test("uses the redacted event fields as the hash preimage", () => {
  const event = auditEvent(ids.event1, "0".repeat(64));
  const preimage = auditEventHashPreimage(event);
  assert.equal(Object.hasOwn(preimage, "event_hash"), false);
  assert.equal(preimage.previous_hash, event.previous_hash);
  assert.deepEqual(Object.keys(preimage).sort(), [
    "agent_id", "branch", "capability_sequence", "decision", "device_timestamp", "event_id",
    "operation", "payload_digest", "policy_sequence", "previous_hash", "reason", "remote",
    "repository", "request_id", "version"
  ]);
  assert.equal(computeAuditEventHash(event), crypto.createHash("sha256").update(canonicalJson(preimage), "utf8").digest("hex"));
});

test("accepts a valid multi-event hash chain and advances its head", async (t) => {
  const { directory, store } = await fixture();
  t.after(async () => { await store.close(); await fs.rm(directory, { recursive: true, force: true }); });
  await addDeviceAndAgent(store);
  const first = auditEvent(ids.event1, "0".repeat(64));
  const second = auditEvent(ids.event2, first.event_hash);

  const result = await store.ingestDeviceAuditEvents({ organizationId: ids.org, deviceId: ids.device, events: [first, second], idempotencyKey: "audit-valid-chain-1" });

  assert.deepEqual(result.accepted, [ids.event1, ids.event2]);
  assert.deepEqual(result.gaps, []);
  assert.deepEqual(result.head, {
    last_hash: second.event_hash,
    last_event_id: ids.event2,
    chain_status: "continuous",
    gap_count: 0
  });
});

test("persists atomically, recovers after restart, and never writes secret fields", async (t) => {
  const { directory, store } = await fixture();
  const { device, agent } = await addDeviceAndAgent(store);
  const bundleHead = await store.assignBundleHead({
    organizationId: ids.org,
    deviceId: device.device_id,
    stateFingerprint: digest,
    minimumSequence: 7,
    issuedAt: timestamp,
    expiresAt: "2026-08-11T01:05:00.000Z"
  });
  assert.equal(bundleHead.sequence, 7);
  await store.appendAdminAuditEvent({ organizationId: ids.org, eventType: "device.enrolled", actorId: "admin-1", details: { source: "test" }, idempotencyKey: "admin-audit-1" });
  await store.close();
  const file = path.join(directory, "cloud-store.json");
  const onDisk = await fs.readFile(file, "utf8");
  assert.equal(onDisk.includes("PRIVATE KEY"), false);
  assert.equal(onDisk.includes("bearer-token"), false);
  assert.equal(onDisk.includes("session-token"), false);
  const reopened = await createCloudStore({ dataDir: directory });
  t.after(async () => { await reopened.close(); await fs.rm(directory, { recursive: true, force: true }); });
  assert.equal((await reopened.getDevice({ organizationId: ids.org, deviceId: device.device_id })).device_id, ids.device);
  assert.equal((await reopened.getAgent({ organizationId: ids.org, agentId: agent.agent_id })).agent_id, ids.agent);
  assert.equal((await reopened.listAdminAuditEvents({ organizationId: ids.org })).length, 1);
  const replayedHead = await reopened.assignBundleHead({
    organizationId: ids.org,
    deviceId: device.device_id,
    stateFingerprint: digest,
    minimumSequence: 1,
    issuedAt: "2026-08-11T01:01:00.000Z",
    expiresAt: "2026-08-11T01:06:00.000Z"
  });
  assert.deepEqual(replayedHead, bundleHead);
  const advancedHead = await reopened.assignBundleHead({
    organizationId: ids.org,
    deviceId: device.device_id,
    stateFingerprint: "b".repeat(64),
    minimumSequence: 1,
    issuedAt: "2026-08-11T01:02:00.000Z",
    expiresAt: "2026-08-11T01:07:00.000Z"
  });
  assert.equal(advancedHead.sequence, 8);
});

test("rejects secret material, unsafe storage, and unbounded audit input", async (t) => {
  const { directory, store } = await fixture();
  t.after(async () => { await store.close(); await fs.rm(directory, { recursive: true, force: true }); });
  await assert.rejects(() => store.createDevice({ organizationId: ids.org, name: "bad", publicKey: "-----BEGIN PRIVATE KEY-----", idempotencyKey: "bad-device" }), { code: "ERR_SECRET_MATERIAL" });
  await assert.rejects(() => store.appendAdminAuditEvent({ organizationId: ids.org, eventType: "bad", actorId: "admin", details: { session_token: "never" }, idempotencyKey: "bad-audit" }), { code: "ERR_SECRET_MATERIAL" });
  await assert.rejects(() => store.ingestDeviceAuditEvents({ organizationId: ids.org, deviceId: ids.device, events: [], idempotencyKey: "empty-audit" }), { code: "ERR_LIMIT_EXCEEDED" });
  const symlinkDirectory = path.join(directory, "link");
  await fs.symlink(directory, symlinkDirectory);
  await assert.rejects(() => createCloudStore({ dataDir: symlinkDirectory }), { code: "ERR_UNSAFE_PATH" });
});

test("device enrollment stores only a digest and consumes an exact bound request idempotently", async (t) => {
  const { directory, store } = await fixture();
  t.after(async () => { await store.close(); await fs.rm(directory, { recursive: true, force: true }); });
  const enrollmentId = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
  const pendingDevice = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
  const credential = "enrollment-credential-never-persisted";
  const credentialDigest = crypto.createHash("sha256").update(credential).digest("hex");
  const enrollment = await store.createDeviceEnrollment({ organizationId: ids.org, enrollmentId, deviceId: pendingDevice, label: "Build Mac 02", platform: "macos", credentialDigest, createdAt: "2026-08-12T00:00:00.000Z", expiresAt: "2026-08-12T00:15:00.000Z", idempotencyKey: "issue-device-enrollment" });
  assert.equal(enrollment.device_id, pendingDevice);
  assert.equal(Object.hasOwn(enrollment, "credential_digest"), false);
  const keys = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const publicKey = keys.publicKey.export({ type: "spki", format: "pem" }).toString();
  const request = { enrollmentId, organizationId: ids.org, deviceId: pendingDevice, label: "Build Mac 02", platform: "macos", algorithm: "p256-sha256", publicKey, credentialDigest, completedAt: "2026-08-12T00:01:00.000Z" };
  const completed = await store.completeDeviceEnrollment(request);
  assert.equal(completed.status, "active");
  assert.equal(completed.device_public_key, publicKey);
  assert.equal(completed.key_epoch, 1);
  assert.deepEqual(await store.completeDeviceEnrollment(request), completed);
  await assert.rejects(() => store.completeDeviceEnrollment({ ...request, label: "substituted" }), { code: "ERR_ENROLLMENT_BINDING" });
  const disk = await fs.readFile(path.join(directory, "cloud-store.json"), "utf8");
  assert.equal(disk.includes(credential), false);
  assert.equal(disk.includes(credentialDigest), true);
  const rotated = await store.updateDevice({ organizationId: ids.org, deviceId: pendingDevice, expectedVersion: completed.version, patch: { device_public_key: crypto.generateKeyPairSync("ed25519").publicKey.export({ type: "spki", format: "pem" }).toString() }, idempotencyKey: "rotate-device-key" });
  assert.equal(rotated.key_epoch, 2);
});

test("v2 enrollment is candidate-bound, digest-only, and stores append-only possession receipts", async (t) => {
  const { directory, store } = await fixture();
  t.after(async () => { await store.close(); await fs.rm(directory, { recursive: true, force: true }); });
  const candidate = await store.registerReleaseCandidate({
    candidateId: "release-2026-08-13-01",
    sourceCommit: "c".repeat(40),
    artifactSha256: "b".repeat(64),
    manifestSha256: "d".repeat(64),
    teamId: "ABCDE12345",
    createdAt: "2026-08-13T10:00:00.000Z",
    idempotencyKey: "candidate-1"
  });
  assert.equal((await store.getReleaseCandidate({ candidateId: candidate.candidate_id })).artifact_sha256, "b".repeat(64));
  const keys = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const publicKey = keys.publicKey.export({ type: "spki", format: "pem" }).toString();
  const fingerprint = `SHA256:${crypto.createHash("sha256").update(keys.publicKey.export({ type: "spki", format: "der" })).digest("base64url")}`;
  const credential = "v2-credential-never-persisted";
  const credentialDigest = crypto.createHash("sha256").update(credential).digest("hex");
  const challengeNonceDigest = "e".repeat(64);
  const enrollment = await store.createDeviceEnrollment({
    proofVersion: 2,
    organizationId: ids.org,
    enrollmentId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
    deviceId: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
    candidateId: candidate.candidate_id,
    deviceKeyFingerprint: fingerprint,
    credentialDigest,
    challengeNonceDigest,
    label: "Build Mac v2",
    platform: "macos",
    createdAt: "2026-08-13T10:00:00.000Z",
    ttlMs: 15 * 60 * 1000,
    idempotencyKey: "enrollment-v2-1"
  });
  assert.equal(enrollment.proof_version, 2);
  assert.equal(enrollment.challenge.nonce, undefined);
  assert.equal(enrollment.credential_digest, undefined);
  const diskBeforeCompletion = await fs.readFile(path.join(directory, "cloud-store.json"), "utf8");
  assert.equal(diskBeforeCompletion.includes("v2-credential-never-persisted"), false);
  assert.equal(diskBeforeCompletion.includes("challenge_nonce"), true);
  assert.equal(diskBeforeCompletion.includes("raw-challenge-never-accepted"), false);
  await assert.rejects(() => store.completeDeviceEnrollment({
    proofVersion: 2,
    enrollmentId: enrollment.enrollment_id,
    organizationId: ids.org,
    deviceId: enrollment.device_id,
    label: enrollment.label,
    platform: enrollment.platform,
    candidateId: candidate.candidate_id,
    deviceKeyFingerprint: fingerprint,
    credentialDigest,
    challengeNonceDigest,
    challenge: { nonce: "raw-challenge-never-accepted" },
    deviceKey: { algorithm: "p256-sha256", spki_pem: publicKey }
  }), { code: "ERR_INVALID_INPUT" });
  const statement = {
    version: 1,
    enrollment_id: enrollment.enrollment_id,
    organization_id: ids.org,
    device_id: enrollment.device_id,
    candidate_id: candidate.candidate_id,
    artifact_sha256: candidate.artifact_sha256,
    source_commit: candidate.source_commit,
    team_id: candidate.team_id,
    device_key_fingerprint: fingerprint,
    device_key_epoch: 1,
    challenge_nonce_digest: challengeNonceDigest,
    issued_at: "2026-08-13T10:01:00.000Z"
  };
  const possessionReceipt = {
    version: 1,
    purpose: "device-enrollment-possession-receipt",
    key_id: "possession-receipt-v1",
    algorithm: "p256-sha256",
    statement,
    statement_hash: crypto.createHash("sha256").update(canonicalJson(statement), "utf8").digest("hex"),
    signature: Buffer.alloc(64, 7).toString("base64url")
  };
  const completed = await store.completeDeviceEnrollment({
    proofVersion: 2,
    enrollmentId: enrollment.enrollment_id,
    organizationId: ids.org,
    deviceId: enrollment.device_id,
    label: enrollment.label,
    platform: enrollment.platform,
    candidateId: candidate.candidate_id,
    deviceKeyFingerprint: fingerprint,
    credentialDigest,
    challengeNonceDigest,
    deviceKey: { algorithm: "p256-sha256", spki_pem: publicKey },
    possessionReceipt,
    completedAt: "2026-08-13T10:02:00.000Z"
  });
  assert.equal(completed.status, "active");
  const stored = await store.getDevicePossessionReceipt({ organizationId: ids.org, deviceId: enrollment.device_id });
  assert.equal(stored.statement_hash, possessionReceipt.statement_hash);
  assert.equal(stored.signature, possessionReceipt.signature);
  assert.deepEqual(stored.statement, statement);
  assert.equal((await store.listDevicePossessionReceipts({ organizationId: ids.org, deviceId: enrollment.device_id })).length, 1);
  await assert.rejects(() => store.appendDevicePossessionReceipt({
    organizationId: ids.org,
    deviceId: enrollment.device_id,
    receipt: { ...possessionReceipt, statement_hash: "a".repeat(64) },
    idempotencyKey: "receipt-conflict"
  }), { code: "ERR_RECEIPT_BINDING" });
  await store.createOrganization({ organizationId: ids.org2, name: "Other Org", idempotencyKey: "org-2" });
  await assert.rejects(() => store.getDevicePossessionReceipt({ organizationId: ids.org2, deviceId: enrollment.device_id }), { code: "ERR_NOT_FOUND" });
});

test("exports a clean, frozen API", async (t) => {
  const { directory, store } = await fixture();
  t.after(async () => { await store.close(); await fs.rm(directory, { recursive: true, force: true }); });
  assert.equal(Object.isFrozen(store), true);
  assert.equal(typeof store.snapshot, "function");
  assert.equal(typeof store.reserveCapability, "function");
  await assert.rejects(() => store.snapshot({}), CloudStoreError);
});
