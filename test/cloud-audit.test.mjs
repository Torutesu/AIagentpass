import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { canonicalDeviceRequest, verifyDeviceRequest } from "../apps/cloud-api/src/auth.mjs";
import {
  AuditConflictError,
  CloudAuditError,
  QueueFullError,
  createCloudAuditClient,
  computeCloudAuditEventHash,
  readAuditBatch,
  redactAuditEvent,
  validateAuditBatch
} from "../lib/cloud-audit.mjs";

const ORG = "11111111-1111-4111-8111-111111111111";
const DEVICE = "22222222-2222-4222-8222-222222222222";
const AGENT = "33333333-3333-4333-8333-333333333333";
const REQUEST = "44444444-4444-4444-8444-444444444444";
const HASHES = ["0".repeat(64), "1".repeat(64), "2".repeat(64), "3".repeat(64)];
const NONCES = [
  "nonce-abcdefghijklmnopqrstuvwxyz-1234567890",
  "nonce-zyxwvutsrqponmlkjihgfedcba-0987654321",
  "nonce-cloud-audit-retry-abcdefghijklmnopqrstuvwxyz"
];

function event(index = 0, overrides = {}) {
  const previousHash = index === 0 ? HASHES[0] : event(index - 1).event_hash;
  const value = {
    version: 1,
    event_id: `00000000-0000-4000-8000-00000000000${index + 1}`,
    request_id: REQUEST,
    agent_id: AGENT,
    operation: "git.commit.sign",
    decision: "allow",
    reason: "allowed",
    policy_sequence: 1,
    capability_sequence: 1,
    repository: "/work/repo",
    branch: "feature/cloud-audit",
    remote: "git@example.test:repo.git",
    payload_digest: "a".repeat(64),
    device_timestamp: "2026-08-12T00:00:00.000Z",
    previous_hash: previousHash,
    event_hash: HASHES[0],
    ...overrides
  };
  return { ...value, event_hash: overrides.event_hash ?? computeCloudAuditEventHash(value) };
}

async function fixture(t) {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "agentpass-cloud-audit-"));
  const keys = crypto.generateKeyPairSync("ed25519");
  const auditPath = path.join(dir, "audit.jsonl");
  const queuePath = path.join(dir, "queue.json");
  const cursorPath = path.join(dir, "cursor.json");
  t.after(() => fs.rm(dir, { recursive: true, force: true }));
  const clientOptions = (extra = {}) => ({
    baseUrl: "https://cloud.example.test",
    organizationId: ORG,
    deviceId: DEVICE,
    auditPath,
    queuePath,
    cursorPath,
    privateKey: keys.privateKey,
    clock: () => 1_754_963_200_000,
    nonce: () => NONCES[0],
    ...extra
  });
  return { dir, keys, auditPath, queuePath, cursorPath, clientOptions };
}

test("redacts local records to protocol fields and never forwards prohibited material", () => {
  const redacted = redactAuditEvent({
    ...event(),
    payload: "raw commit contents and secret payload",
    env: { API_TOKEN: "do-not-upload" },
    session_token: "session-secret",
    capability_value: "capability-secret",
    private_key_ref: "/private/key/reference"
  });
  assert.deepEqual(Object.keys(redacted).sort(), [
    "agent_id", "branch", "capability_sequence", "decision", "device_timestamp", "event_hash", "event_id",
    "operation", "payload_digest", "policy_sequence", "previous_hash", "reason", "remote", "repository", "request_id", "version"
  ].sort());
  assert.equal(JSON.stringify(redacted).includes("secret"), false);
  assert.equal(JSON.stringify(redacted).includes("raw commit"), false);
});

test("validates schema, batch bounds, unique IDs, and intra-batch chain order", () => {
  assert.equal(validateAuditBatch([event(), event(1)]).events.length, 2);
  assert.throws(() => validateAuditBatch([event(), event(0)]), /event_id must be unique/);
  assert.throws(() => validateAuditBatch([event(), event(1, { previous_hash: HASHES[3] })]), /hash-chain ordered/);
  assert.throws(() => validateAuditBatch([event()], { batchSize: 0 }), /batchSize is out of bounds/);
  assert.throws(() => validateAuditBatch([event()], { maxBatchBytes: 512 }), /batch is too large/);
  assert.throws(() => redactAuditEvent({ ...event(), operation: "ssh.sign" }), /audit_event/);
  const unknownDropped = redactAuditEvent({ ...event(), unknown: "must not be accepted as a protocol field" });
  assert.equal(Object.hasOwn(unknownDropped, "unknown"), false);
});

test("reads complete JSONL records, redacts them, and does not consume a partial final line", async (t) => {
  const f = await fixture(t);
  const first = `${JSON.stringify({ ...event(), payload: "not uploaded" })}\n`;
  const partial = JSON.stringify({ ...event(1), env: { PASSWORD: "not uploaded" } }).slice(0, 20);
  await fs.writeFile(f.auditPath, first + partial, { mode: 0o600 });
  const read = await readAuditBatch(f.auditPath, { version: 1, offset: 0, line: 0, head_hash: HASHES[0] });
  assert.equal(read.events.length, 1);
  assert.equal(read.nextCursor.offset, Buffer.byteLength(first));
  const again = await readAuditBatch(f.auditPath, read.nextCursor);
  assert.deepEqual(again.events, []);
  assert.equal(JSON.stringify(read.events).includes("not uploaded"), false);
  await fs.writeFile(f.auditPath, '{"version":1,"version":1}\n', { mode: 0o600 });
  await assert.rejects(() => readAuditBatch(f.auditPath), /duplicate keys/);
  t.after(async () => {});
});

test("rejects symlinked audit/state files and requires strict HTTPS except explicit loopback test mode", async (t) => {
  const f = await fixture(t);
  await fs.writeFile(f.auditPath, `${JSON.stringify(event())}\n`, { mode: 0o600 });
  const outside = path.join(f.dir, "outside.jsonl");
  await fs.writeFile(outside, `${JSON.stringify(event())}\n`, { mode: 0o600 });
  await fs.unlink(f.auditPath);
  await fs.symlink(outside, f.auditPath);
  await assert.rejects(() => readAuditBatch(f.auditPath), /symlink|regular file/);
  assert.throws(() => createCloudAuditClient(f.clientOptions({ baseUrl: "http://cloud.example.test" })), /HTTPS/);
  assert.throws(() => createCloudAuditClient(f.clientOptions({ baseUrl: "http://127.0.0.1:9000" })), /HTTPS/);
  assert.doesNotThrow(() => createCloudAuditClient(f.clientOptions({ baseUrl: "http://127.0.0.1:9000", loopbackTestMode: true })));
  await fs.unlink(f.auditPath);
  await fs.writeFile(f.auditPath, `${JSON.stringify(event())}\n`, { mode: 0o600 });
  const client = createCloudAuditClient(f.clientOptions());
  await client.enqueue([event()]);
  await fs.unlink(f.queuePath);
  await fs.symlink(outside, f.queuePath);
  await assert.rejects(() => client.pending(), /symlink|regular file/);
});

test("sends the exact device-signed request contract and binds body/path/query", async (t) => {
  const f = await fixture(t);
  let captured;
  const client = createCloudAuditClient(f.clientOptions({
    fetchImpl: async (url, init) => {
      captured = { url, init };
      return { status: 202, text: async () => JSON.stringify({ ingestion: { accepted: [event().event_id], duplicates: [], gaps: [] } }) };
    }
  }));
  await client.enqueue([event()]);
  const result = await client.upload();
  assert.equal(result.status, "accepted");
  assert.equal(captured.init.redirect, "error");
  assert.equal(captured.init.method, "POST");
  const body = Buffer.from(captured.init.body);
  const headers = captured.init.headers;
  const principal = verifyDeviceRequest({ method: "POST", path: new URL(captured.url).pathname, body, headers }, [{ device_id: DEVICE, organization_id: ORG, public_key: f.keys.publicKey }], { now: 1_754_963_200_000 });
  assert.deepEqual(principal, { device_id: DEVICE, organization_id: ORG });
  assert.equal(headers["AgentPass-Content-SHA256"], crypto.createHash("sha256").update(body).digest("hex"));
  assert.equal(body.toString().includes("payload"), true);
  assert.equal(body.toString().includes("raw commit"), false);
  assert.equal(canonicalDeviceRequest({ method: "POST", path: new URL(captured.url).pathname, body_digest: headers["AgentPass-Content-SHA256"], timestamp: Number(headers["AgentPass-Timestamp"]), nonce: headers["AgentPass-Nonce"] }).includes("/v1/organizations/"), true);
  t.after(() => {});
});

test("uses a stable batch ID and preserves it across network retry and client restart", async (t) => {
  const f = await fixture(t);
  const bodies = [];
  let calls = 0;
  const fetchImpl = async (_url, init) => {
    calls += 1;
    bodies.push(Buffer.from(init.body).toString("utf8"));
    if (calls === 1) throw new Error("offline");
    return { status: 202, text: async () => JSON.stringify({ ingestion: { accepted: [event().event_id] } }) };
  };
  const first = createCloudAuditClient(f.clientOptions({ fetchImpl }));
  const queued = await first.enqueue([event()]);
  const retry = await first.upload();
  assert.equal(retry.status, "retry");
  const second = createCloudAuditClient(f.clientOptions({ fetchImpl, nonce: () => NONCES[1] }));
  const uploaded = await second.upload();
  assert.equal(uploaded.status, "accepted");
  assert.equal(JSON.parse(bodies[0]).batch_id, queued.batch_id);
  assert.equal(bodies[0], bodies[1]);
  assert.equal(calls, 2);
  assert.equal((await second.pending()).batches.length, 0);
  t.after(() => {});
});

test("persists the cursor only after the queue is durable and keeps queue growth bounded", async (t) => {
  const f = await fixture(t);
  await fs.writeFile(f.auditPath, `${JSON.stringify(event())}\n${JSON.stringify(event(1))}\n`, { mode: 0o600 });
  const client = createCloudAuditClient(f.clientOptions({ batchSize: 1, maxQueueEvents: 1 }));
  const added = await client.enqueueFromAudit();
  assert.equal(added.queued, true);
  const cursor = JSON.parse(await fs.readFile(f.cursorPath, "utf8"));
  assert.equal(cursor.offset, Buffer.byteLength(`${JSON.stringify(event())}\n`));
  await assert.rejects(() => client.enqueueFromAudit(), QueueFullError);
  const restarted = createCloudAuditClient(f.clientOptions({ batchSize: 1, maxQueueEvents: 1 }));
  assert.equal((await restarted.pending()).batches.length, 1);
  assert.equal((await restarted.cursor()).offset, cursor.offset);
});

test("handles accepted duplicates and visible gaps, but leaves conflicts and rejected gaps queued", async (t) => {
  const f = await fixture(t);
  const responses = [
    { status: 202, body: { ingestion: { accepted: [], duplicates: [event().event_id], gaps: [] } } },
    { status: 202, body: { ingestion: { accepted: [event().event_id], duplicates: [], gaps: [{ gap_id: "gap-1", event_id: event().event_id, expected_previous_hash: HASHES[0], received_previous_hash: HASHES[2] }] } } },
    { status: 409, body: { error: { code: "ERR_AUDIT_DEDUP_CONFLICT" } } },
    { status: 409, body: { error: { code: "audit_gap", expected_previous_hash: HASHES[0] } } }
  ];
  const client = createCloudAuditClient(f.clientOptions({ fetchImpl: async () => {
    const response = responses.shift();
    return { status: response.status, text: async () => JSON.stringify(response.body) };
  }}));
  await client.enqueue([event()]);
  assert.equal((await client.upload()).status, "accepted");
  await client.enqueue([event(1, { event_id: "00000000-0000-4000-8000-000000000099", previous_hash: HASHES[1] })]);
  assert.equal((await client.upload()).status, "gap");
  await client.enqueue([event(2, { event_id: "00000000-0000-4000-8000-000000000098", previous_hash: HASHES[2], event_hash: HASHES[3] })]);
  const conflict = await client.upload();
  assert.equal(conflict.status, "conflict");
  assert.equal((await client.pending()).batches.length, 1);
  // The conflict remains at the head, so a gap response is not sent past it.
  assert.equal((await client.upload()).status, "gap-blocked");
  assert.equal((await client.pending()).batches.length, 1);
  t.after(() => {});
});

test("passes timeout signals and never follows redirects", async (t) => {
  const f = await fixture(t);
  let received;
  const client = createCloudAuditClient(f.clientOptions({
    timeoutMs: 10,
    fetchImpl: async (_url, init) => {
      received = init;
      return new Promise((resolve) => setTimeout(() => resolve({ status: 307, text: async () => "{}" }), 30));
    }
  }));
  await client.enqueue([event()]);
  const result = await client.upload();
  assert.equal(result.status, "retry");
  assert.equal(received.redirect, "error");
  assert.equal(received.signal.aborted, true);
  t.after(() => {});
});

test("does not expose raw response bodies or payloads in conflict errors", async (t) => {
  const f = await fixture(t);
  const secret = "private-session-capability-payload-secret";
  const client = createCloudAuditClient(f.clientOptions({ fetchImpl: async () => ({ status: 409, text: async () => JSON.stringify({ error: { code: "ERR_AUDIT_DEDUP_CONFLICT", message: secret } }) }) }));
  await client.enqueue([event()]);
  const result = await client.upload();
  assert.equal(result.status, "conflict");
  assert.equal(JSON.stringify(result).includes(secret), false);
  assert.equal(result.error_code, "ERR_AUDIT_DEDUP_CONFLICT");
  assert.equal(new AuditConflictError("audit-test").code, "ERR_AUDIT_CONFLICT");
  await assert.rejects(() => client.enqueue([event(0, { operation: "ssh.sign" })]), CloudAuditError);
  t.after(() => {});
});
