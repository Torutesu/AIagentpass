import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  CLOUD_CONTROL_ERRORS,
  CloudControlError,
  buildCloudControlConfigFragment,
  createCloudControlClient
} from "../lib/cloud-control.mjs";
import { createReplayCache, verifyDeviceRequest } from "../apps/cloud-api/src/auth.mjs";
import { CONTROL_BUNDLE_REASONS, issueControlBundle } from "../lib/control-bundle-v2.mjs";

const NOW = Date.parse("2026-08-12T00:00:00.000Z");
const ORGANIZATION = "11111111-1111-4111-8111-111111111111";
const DEVICE = "22222222-2222-4222-8222-222222222222";
const scope = {
  operations: ["git.commit.sign"],
  repositories: ["/work/repo"],
  branches: { allow: ["feature/*"], deny: ["main"] },
  remotes: { allow: ["git@example.test:repo.git"] }
};

const deviceKeys = crypto.generateKeyPairSync("ed25519");
const controlKeys = crypto.generateKeyPairSync("ed25519");

function statePath() {
  return path.join(fs.mkdtempSync(path.join(os.tmpdir(), "agentpass-cloud-control-")), "control-v2.state.json");
}

function bundle(overrides = {}) {
  return issueControlBundle({
    format_epoch: 2,
    issuer: "cloud-control",
    organization_id: ORGANIZATION,
    device_id: DEVICE,
    audience: { organization_id: ORGANIZATION, device_id: DEVICE },
    issued_at: new Date(NOW).toISOString(),
    expires_at: new Date(NOW + 60_000).toISOString(),
    sequence: 1,
    policy_scope: scope,
    global_revoked: false,
    revoked_devices: [],
    revoked_agents: [],
    revoked_capabilities: [],
    offline_ttl_ms: 120_000,
    key_id: "control-v2",
    ...overrides
  }, controlKeys.privateKey, { now: NOW });
}

function client(overrides = {}) {
  const fixedNonce = "nonce-cloud-control-abcdefghijklmnopqrstuvwxyz-123456";
  return createCloudControlClient({
    baseUrl: "https://control.example.test",
    organizationId: ORGANIZATION,
    deviceId: DEVICE,
    issuer: "cloud-control",
    keyId: "control-v2",
    publicKey: controlKeys.publicKey,
    privateKey: deviceKeys.privateKey,
    statePath: statePath(),
    clock: () => NOW,
    nonce: () => fixedNonce,
    ...overrides
  });
}

function response(value, init = {}) {
  return new Response(JSON.stringify(value), { status: 200, headers: { "content-type": "application/json" }, ...init });
}

test("signs the exact GET path and empty body, so replay, path, and body substitution fail", async () => {
  let captured;
  const current = bundle();
  const c = client({ fetchImpl: async (url, init) => { captured = { url, init }; return response({ bundle: current, desired_generation: 1, request_id: crypto.randomUUID() }); } });
  assert.equal((await c.fetchBundle()).sequence, 1);
  assert.equal(captured.init.method, "GET");
  assert.equal(captured.init.redirect, "error");
  assert.equal(captured.init.body, undefined);
  assert.equal(captured.init.headers["AgentPass-Content-SHA256"], crypto.createHash("sha256").update(Buffer.alloc(0)).digest("hex"));
  const target = new URL(captured.url);
  const replay = createReplayCache();
  const enrolled = [{ device_id: DEVICE, organization_id: ORGANIZATION, public_key: deviceKeys.publicKey }];
  assert.deepEqual(verifyDeviceRequest({ method: "GET", path: target.pathname, body: Buffer.alloc(0), headers: captured.init.headers }, enrolled, { now: NOW, replayCache: replay }), { device_id: DEVICE, organization_id: ORGANIZATION });
  assert.throws(() => verifyDeviceRequest({ method: "GET", path: `${target.pathname}/wrong`, body: Buffer.alloc(0), headers: captured.init.headers }, enrolled, { now: NOW, replayCache: createReplayCache() }), /Device authentication failed/);
  assert.throws(() => verifyDeviceRequest({ method: "GET", path: target.pathname, body: Buffer.from("substituted"), headers: captured.init.headers }, enrolled, { now: NOW, replayCache: createReplayCache() }), /Authentication body digest/);
  assert.throws(() => verifyDeviceRequest({ method: "GET", path: target.pathname, body: Buffer.alloc(0), headers: captured.init.headers }, enrolled, { now: NOW, replayCache: replay }), /Authentication request replay/);
});

test("durable synchronization rejects rollback and same-sequence equivocation", async () => {
  const first = bundle();
  let served = first;
  const c = client({ fetchImpl: async () => response({ bundle: served }) });
  assert.equal((await c.sync()).status, "updated");
  served = bundle({ sequence: 1, global_revoked: true });
  await assert.rejects(() => c.sync(), (error) => error.code === CONTROL_BUNDLE_REASONS.SEQUENCE_CONFLICT);
  served = bundle({ sequence: 1 });
  const state = JSON.parse(fs.readFileSync(c.config.statePath, "utf8"));
  assert.equal(state.highest_sequence, 1);
  assert.equal(state.active_bundle.signature, first.signature);
  const rollback = bundle({ sequence: 1, issued_at: new Date(NOW - 1_000).toISOString(), expires_at: new Date(NOW + 60_000).toISOString() });
  served = rollback;
  await assert.rejects(() => c.sync(), (error) => error.code === CONTROL_BUNDLE_REASONS.SEQUENCE_CONFLICT);
});

test("offline cached load is available only through the bundle offline TTL", async () => {
  let now = NOW;
  const current = bundle({ expires_at: new Date(NOW + 1_000).toISOString(), offline_ttl_ms: 2_000 });
  const c = client({ clock: () => now, fetchImpl: async () => response({ bundle: current }) });
  await c.sync();
  now = NOW + 1_500;
  assert.equal(c.loadCached().sequence, 1);
  assert.equal(c.status().available, true);
  now = NOW + 3_001;
  assert.throws(() => c.loadCached(), (error) => error.code === CONTROL_BUNDLE_REASONS.OFFLINE_TTL_EXPIRED);
  assert.equal(c.status().available, false);
  const offlineOnly = createCloudControlClient({
    baseUrl: "https://control.example.test",
    organizationId: ORGANIZATION,
    deviceId: DEVICE,
    issuer: "cloud-control",
    keyId: "control-v2",
    publicKey: controlKeys.publicKey,
    statePath: c.config.statePath,
    clock: () => now
  });
  assert.equal(offlineOnly.status().available, false);
});

test("requires HTTPS, rejects redirects, and bounds the response body", async () => {
  assert.throws(() => client({ baseUrl: "http://control.example.test" }), (error) => error.code === CLOUD_CONTROL_ERRORS.INVALID_URL);
  assert.doesNotThrow(() => client({ baseUrl: "http://127.0.0.1:9000", loopbackTestMode: true }));
  const redirected = client({ fetchImpl: async () => new Response("", { status: 302, headers: { location: "https://other.test" } }) });
  await assert.rejects(() => redirected.fetchBundle(), (error) => error.code === CLOUD_CONTROL_ERRORS.REDIRECT);
  const oversized = client({ maxResponseBytes: 64, fetchImpl: async () => new Response("x".repeat(65), { status: 200, headers: { "content-length": "65" } }) });
  await assert.rejects(() => oversized.fetchBundle(), (error) => error.code === CLOUD_CONTROL_ERRORS.RESPONSE_TOO_LARGE);
  const duplicate = client({ fetchImpl: async () => new Response('{"bundle":{},"bundle":{}}', { status: 200 }) });
  await assert.rejects(() => duplicate.fetchBundle(), (error) => error.code === CONTROL_BUNDLE_REASONS.DUPLICATE_FIELD);
});

test("refuses symlinked state parents and state files", async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "agentpass-cloud-control-links-"));
  const real = path.join(root, "real");
  fs.mkdirSync(real, { mode: 0o700 });
  const linkedParent = path.join(root, "linked");
  fs.symlinkSync(real, linkedParent, "dir");
  const parentClient = client({ statePath: path.join(linkedParent, "state.json") });
  assert.equal(parentClient.status().error, CONTROL_BUNDLE_REASONS.STATE_SYMLINK);

  const realState = path.join(real, "state.json");
  const validClient = client({ statePath: realState, fetchImpl: async () => response({ bundle: bundle() }) });
  await validClient.sync();
  const linkedFile = path.join(root, "linked-state.json");
  fs.symlinkSync(realState, linkedFile);
  const fileClient = client({ statePath: linkedFile });
  assert.throws(() => fileClient.loadCached(), (error) => error.code === CONTROL_BUNDLE_REASONS.STATE_SYMLINK);
});

test("builds a pure enrollment fragment without copying secrets", () => {
  const fragment = buildCloudControlConfigFragment({
    organizationId: ORGANIZATION,
    deviceId: DEVICE,
    issuer: "cloud-control",
    keyId: "control-v2",
    publicKey: controlKeys.publicKey.export({ type: "spki", format: "pem" }).toString(),
    baseUrl: "https://control.example.test",
    statePath: "/Users/example/.agentpass/control-v2.state.json",
    privateKey: "do-not-copy",
    bearerToken: "do-not-copy"
  });
  assert.deepEqual(fragment.control_v2.organization_id, ORGANIZATION);
  assert.equal(fragment.control_v2.required, true);
  assert.equal(Object.hasOwn(fragment.control_v2, "privateKey"), false);
  assert.equal(JSON.stringify(fragment).includes("do-not-copy"), false);
});

test("timeout errors are stable and fail closed", async () => {
  const c = client({ timeoutMs: 5, fetchImpl: () => new Promise(() => {}) });
  await assert.rejects(() => c.fetchBundle(), (error) => error instanceof CloudControlError && error.code === CLOUD_CONTROL_ERRORS.TIMEOUT);
});
