import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import { createDeviceSignature, signDeviceRequest } from "../src/auth.mjs";
import { createCloudApi } from "../src/server.mjs";
import {
  bundleAcknowledgementSigningData,
  normalizeBundleAcknowledgement,
  normalizeRefreshHint,
  refreshHintSigningData
} from "../../../packages/protocol/src/index.mjs";
import { controlBundleStatementHash, issueControlBundle } from "../../../lib/control-bundle-v2.mjs";

// G4.1 runtime dependency contract. These methods are deliberately named here
// so the server implementation cannot hide persistence, ordering, or replay
// semantics behind an untestable route-local map.
//
// refreshHintService.poll(input) -> RefreshHintV1 | null
//   input: { organization_id, device_id, after_generation, wait_ms, signal }
//   result is a purpose-signed RefreshHintV1 and contains no authority. The
//   PostgreSQL repository behind the service returns only unsigned metadata.
//
// snapshotAndAssignBundleHead(input) -> { snapshot, head, desired_generation }
//   snapshot/head are the same transaction boundary used for ControlBundle v2
//   signing. desired_generation is the committed device refresh generation.
//
// acknowledgeBundle(input) -> { duplicate, observed_generation, refresh_state }
//   input is the complete signed BundleAckV1 evidence plus the path binding;
//   persistence must deduplicate exact evidence and reject conflicts.

const ORGANIZATION_ID = "11111111-1111-4111-8111-111111111111";
const DEVICE_ID = "22222222-2222-4222-8222-222222222222";
const OTHER_DEVICE_ID = "33333333-3333-4333-8333-333333333333";
const NOW = Date.parse("2026-08-13T00:00:00.000Z");
const DEVICE_KEY_EPOCH = 7;
const DESIRED_GENERATION = 12;
const BUNDLE_SEQUENCE = 9;
const WAIT_MS = 250;

const SCOPE = {
  operations: ["git.commit.sign"],
  repositories: ["/work/repo"],
  branches: { allow: ["feature/*"], deny: ["main"] },
  remotes: { allow: ["git@example.test:repo.git"] }
};

function createRefreshHint(bundleSigner) {
  const unsigned = {
    version: 1,
    type: "agentpass.refresh-hint",
    organization_id: ORGANIZATION_ID,
    device_id: DEVICE_ID,
    authority_generation: DESIRED_GENERATION,
    published_at: new Date(NOW).toISOString(),
    expires_at: new Date(NOW + 60_000).toISOString(),
    nonce: Buffer.alloc(16, 0x41).toString("base64url"),
    key_id: "control-v1",
    signature_algorithm: "ed25519"
  };
  return normalizeRefreshHint({
    ...unsigned,
    signature: crypto.sign(null, refreshHintSigningData({ ...unsigned, signature: Buffer.alloc(64).toString("base64url") }), bundleSigner.privateKey).toString("base64url")
  });
}

function createControlBundle(bundleSigner) {
  return issueControlBundle({
    format_epoch: 2,
    issuer: "agentpass-cloud",
    organization_id: ORGANIZATION_ID,
    device_id: DEVICE_ID,
    audience: { organization_id: ORGANIZATION_ID, device_id: DEVICE_ID },
    issued_at: new Date(NOW).toISOString(),
    expires_at: new Date(NOW + 60_000).toISOString(),
    sequence: BUNDLE_SEQUENCE,
    policy_scope: SCOPE,
    global_revoked: false,
    revoked_devices: [],
    revoked_agents: [],
    revoked_capabilities: [],
    offline_ttl_ms: 120_000,
    key_id: "control-v1"
  }, bundleSigner.privateKey, { now: NOW, maxTtlMs: 60_000, maxOfflineTtlMs: 120_000 });
}

function createSignedAcknowledgement(devicePrivateKey, bundle, overrides = {}) {
  const unsigned = {
    version: 1,
    type: "agentpass.bundle-ack",
    organization_id: ORGANIZATION_ID,
    device_id: DEVICE_ID,
    device_key_epoch: DEVICE_KEY_EPOCH,
    format_epoch: 2,
    sequence: BUNDLE_SEQUENCE,
    statement_hash: controlBundleStatementHash(bundle),
    result: "applied",
    observed_at: new Date(NOW + 5_000).toISOString(),
    nonce: Buffer.alloc(16, 0x42).toString("base64url"),
    signature_algorithm: "p256-sha256",
    ...overrides
  };
  let placeholder;
  for (let attempt = 0; attempt < 32; attempt += 1) {
    const candidate = crypto.sign("sha256", Buffer.from("AgentPass-G4.1-ACK-placeholder", "utf8"), { key: devicePrivateKey, dsaEncoding: "ieee-p1363" }).toString("base64url");
    try {
      normalizeBundleAcknowledgement({ ...unsigned, signature: candidate });
      placeholder = candidate;
      break;
    } catch (error) {
      if (!hasIssue(error, "noncanonical_signature")) throw error;
    }
  }
  if (!placeholder) throw new Error("could not create a low-S P-256 ACK placeholder");
  const preimage = bundleAcknowledgementSigningData({ ...unsigned, signature: placeholder });
  for (let attempt = 0; attempt < 32; attempt += 1) {
    const signature = crypto.sign("sha256", preimage, { key: devicePrivateKey, dsaEncoding: "ieee-p1363" }).toString("base64url");
    try {
      return normalizeBundleAcknowledgement({ ...unsigned, signature });
    } catch (error) {
      if (!hasIssue(error, "noncanonical_signature")) throw error;
    }
  }
  throw new Error("could not create a low-S P-256 ACK fixture");
}

function hasIssue(error, code) {
  return Array.isArray(error?.issues) && error.issues.some((issue) => issue.code === code);
}

function createDependencies({ refreshResult = null, acknowledge } = {}) {
  const deviceKeys = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const bundleSigner = crypto.generateKeyPairSync("ed25519");
  const bundle = createControlBundle({ privateKey: bundleSigner.privateKey });
  const calls = { refresh: [], bundle: [], acknowledgements: [] };
  const device = {
    device_id: DEVICE_ID,
    organization_id: ORGANIZATION_ID,
    status: "active",
    key_epoch: DEVICE_KEY_EPOCH,
    device_public_key: deviceKeys.publicKey.export({ type: "spki", format: "pem" }).toString()
  };
  const store = {
    listDevices: async ({ organizationId }) => organizationId === ORGANIZATION_ID ? [device] : [],
    pollDeviceRefresh: async (input) => {
      calls.refresh.push(structuredClone({ ...input, signal: input.signal ? "provided" : undefined }));
      return typeof refreshResult === "function" ? refreshResult(input) : refreshResult;
    },
    snapshotAndAssignBundleHead: async (input) => {
      calls.bundle.push(structuredClone(input));
      return {
        snapshot: {
          policy_scope: SCOPE,
          global_revoked: false,
          revoked_devices: [],
          revoked_agents: [],
          revoked_capabilities: []
        },
        head: {
          organization_id: ORGANIZATION_ID,
          device_id: DEVICE_ID,
          format_epoch: 2,
          sequence: BUNDLE_SEQUENCE,
          issued_at: new Date(NOW).toISOString(),
          expires_at: new Date(NOW + 60_000).toISOString()
        },
        desired_generation: DESIRED_GENERATION
      };
    },
    acknowledgeBundle: async (input) => {
      calls.acknowledgements.push(structuredClone(input));
      if (acknowledge) return acknowledge(input, calls.acknowledgements.length);
      return { duplicate: calls.acknowledgements.length > 1, observed_generation: DESIRED_GENERATION, refresh_state: "applied" };
    },
    appendAdminAuditEvent: async () => undefined
  };
  return { store, deviceKeys, bundleSigner, bundle, calls };
}

async function startServer(t, options = {}) {
  const dependencies = createDependencies(options);
  const server = createCloudApi({
    store: dependencies.store,
    refreshHintService: { poll: dependencies.store.pollDeviceRefresh },
    bundleSigner: { privateKey: dependencies.bundleSigner.privateKey, issuer: "agentpass-cloud", keyId: "control-v1", ttlMs: 60_000, offlineTtlMs: 120_000 },
    now: () => NOW,
    ...options.cloudApi
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(async () => new Promise((resolve) => server.close(resolve)));
  return { ...dependencies, base: `http://127.0.0.1:${server.address().port}` };
}

function signRequest({ method, path, body = Buffer.alloc(0), deviceId = DEVICE_ID, nonce, devicePrivateKey }) {
  return signDeviceRequest({ method, path, body, device_id: deviceId, timestamp: NOW, nonce }, devicePrivateKey);
}

function assertRequestId(body) {
  assert.match(body.request_id, /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu);
}

test("G4.1 refresh poll returns a signed device-bound hint when generation is newer", async (t) => {
  const f = await startServer(t, { refreshResult: ({ after_generation, wait_ms }) => {
    assert.equal(after_generation, 4);
    assert.equal(wait_ms, WAIT_MS);
    return createRefreshHint(f.bundleSigner);
  } });
  const path = `/v1/organizations/${ORGANIZATION_ID}/devices/${DEVICE_ID}/refresh?after_generation=4&wait_ms=${WAIT_MS}`;
  const response = await fetch(`${f.base}${path}`, {
    headers: signRequest({ method: "GET", path, devicePrivateKey: f.deviceKeys.privateKey, nonce: "refresh-contract-nonce-0000000000000001" })
  });
  assert.equal(response.status, 200);
  const body = await response.json();
  assertRequestId(body);
  assert.deepEqual(Object.keys(body).filter((key) => key !== "request_id"), ["hint"]);
  assert.equal(body.hint.authority_generation, DESIRED_GENERATION);
  assert.equal("policy_scope" in body.hint, false);
  assert.equal("capability" in body.hint, false);
});

test("G4.1 refresh poll returns an empty 204 without a stale or authority-bearing payload", async (t) => {
  const f = await startServer(t, { refreshResult: null });
  const path = `/v1/organizations/${ORGANIZATION_ID}/devices/${DEVICE_ID}/refresh?after_generation=${DESIRED_GENERATION}&wait_ms=0`;
  const response = await fetch(`${f.base}${path}`, {
    headers: signRequest({ method: "GET", path, devicePrivateKey: f.deviceKeys.privateKey, nonce: "refresh-contract-nonce-0000000000000002" })
  });
  assert.equal(response.status, 204);
  assert.equal(await response.text(), "");
});

test("G4.1 refresh polling capacity failure is stable, retryable, and redacted", async (t) => {
  const error = new Error("tenant SQL and signing input must not escape");
  error.code = "ERR_REFRESH_BUSY";
  const f = await startServer(t, { cloudApi: { refreshHintService: { async poll() { throw error; } } } });
  const path = `/v1/organizations/${ORGANIZATION_ID}/devices/${DEVICE_ID}/refresh?after_generation=1&wait_ms=30000`;
  const response = await fetch(`${f.base}${path}`, {
    headers: signRequest({ method: "GET", path, devicePrivateKey: f.deviceKeys.privateKey, nonce: "refresh-contract-nonce-0000000000000003" })
  });
  assert.equal(response.status, 503);
  assert.equal(response.headers.get("retry-after"), "1");
  const body = await response.json();
  assert.equal(body.error.code, "refresh_busy");
  assert.equal(JSON.stringify(body).includes("tenant SQL"), false);
});

test("G4.1 bundle fetch returns the target envelope with desired_generation", async (t) => {
  const f = await startServer(t);
  const path = `/v1/organizations/${ORGANIZATION_ID}/bundles/${DEVICE_ID}`;
  const response = await fetch(`${f.base}${path}`, {
    headers: signRequest({ method: "GET", path, devicePrivateKey: f.deviceKeys.privateKey, nonce: "bundle-contract-nonce-000000000000001" })
  });
  assert.equal(response.status, 200);
  assert.equal(response.headers.get("cache-control"), "no-store");
  const body = await response.json();
  assertRequestId(body);
  assert.deepEqual(Object.keys(body).filter((key) => key !== "request_id").sort(), ["bundle", "desired_generation"]);
  assert.equal(body.desired_generation, DESIRED_GENERATION);
  assert.equal(body.bundle.sequence, BUNDLE_SEQUENCE);
});

test("G4.1 signed ACK binds path, body, device key epoch, and repository input", async (t) => {
  const f = await startServer(t);
  const acknowledgement = createSignedAcknowledgement(f.deviceKeys.privateKey, f.bundle);
  const body = Buffer.from(JSON.stringify(acknowledgement));
  const path = `/v1/organizations/${ORGANIZATION_ID}/bundles/${DEVICE_ID}/acknowledgements`;
  const response = await fetch(`${f.base}${path}`, {
    method: "POST",
    headers: { ...signRequest({ method: "POST", path, body, devicePrivateKey: f.deviceKeys.privateKey, nonce: "ack-contract-http-nonce-0000000001" }), "content-type": "application/json" },
    body
  });
  assert.equal(response.status, 202);
  const responseBody = await response.json();
  assertRequestId(responseBody);
  assert.deepEqual(Object.fromEntries(Object.entries(responseBody).filter(([key]) => key !== "request_id")), { accepted: true, duplicate: false, observed_generation: DESIRED_GENERATION, refresh_state: "applied" });
  assert.equal(f.calls.acknowledgements[0].device_key_epoch, DEVICE_KEY_EPOCH);
  assert.equal(f.calls.acknowledgements[0].organization_id, ORGANIZATION_ID);
  assert.equal(f.calls.acknowledgements[0].device_id, DEVICE_ID);
  assert.equal(f.calls.acknowledgements[0].statement_hash, acknowledgement.statement_hash);
  assert.equal(f.calls.acknowledgements[0].signature, acknowledgement.signature);
});

test("G4.1 signed ACK rejects body/path device substitution before persistence", async (t) => {
  const f = await startServer(t);
  const acknowledgement = createSignedAcknowledgement(f.deviceKeys.privateKey, f.bundle, { device_id: OTHER_DEVICE_ID });
  const body = Buffer.from(JSON.stringify(acknowledgement));
  const path = `/v1/organizations/${ORGANIZATION_ID}/bundles/${DEVICE_ID}/acknowledgements`;
  const response = await fetch(`${f.base}${path}`, {
    method: "POST",
    headers: { ...signRequest({ method: "POST", path, body, devicePrivateKey: f.deviceKeys.privateKey, nonce: "ack-contract-http-nonce-0000000002" }), "content-type": "application/json" },
    body
  });
  assert.equal(response.status, 400);
  assert.equal((await response.json()).error.code, "acknowledgement_binding_mismatch");
  assert.equal(f.calls.acknowledgements.length, 0);
});

test("G4.1 exact signed ACK request replay is rejected without a second repository call", async (t) => {
  const f = await startServer(t);
  const acknowledgement = createSignedAcknowledgement(f.deviceKeys.privateKey, f.bundle);
  const body = Buffer.from(JSON.stringify(acknowledgement));
  const path = `/v1/organizations/${ORGANIZATION_ID}/bundles/${DEVICE_ID}/acknowledgements`;
  const headers = { ...signRequest({ method: "POST", path, body, devicePrivateKey: f.deviceKeys.privateKey, nonce: "ack-contract-http-replay-00000001" }), "content-type": "application/json" };
  const first = await fetch(`${f.base}${path}`, { method: "POST", headers, body });
  assert.equal(first.status, 202);
  const replay = await fetch(`${f.base}${path}`, { method: "POST", headers, body });
  assert.equal(replay.status, 401);
  assert.equal((await replay.json()).error.code, "auth_replay_detected");
  assert.equal(f.calls.acknowledgements.length, 1);
});

test("G4.1 conflicting ACK for the same device/epoch/sequence is a stable 409", async (t) => {
  const f = await startServer(t, { acknowledge: (input, count) => {
    if (count === 1) return { duplicate: false, observed_generation: DESIRED_GENERATION, refresh_state: "applied" };
    const error = new Error("acknowledgement conflicts with prior evidence");
    error.code = "ERR_ACK_CONFLICT";
    throw error;
  } });
  const firstAck = createSignedAcknowledgement(f.deviceKeys.privateKey, f.bundle);
  const secondAck = createSignedAcknowledgement(f.deviceKeys.privateKey, f.bundle, { result: "blocked", reason_code: "bundle_expired", nonce: Buffer.alloc(16, 0x43).toString("base64url") });
  const path = `/v1/organizations/${ORGANIZATION_ID}/bundles/${DEVICE_ID}/acknowledgements`;
  const send = async (ack, nonce) => {
    const body = Buffer.from(JSON.stringify(ack));
    return fetch(`${f.base}${path}`, { method: "POST", headers: { ...signRequest({ method: "POST", path, body, devicePrivateKey: f.deviceKeys.privateKey, nonce }), "content-type": "application/json" }, body });
  };
  assert.equal((await send(firstAck, "ack-contract-http-conflict-00001")).status, 202);
  const conflict = await send(secondAck, "ack-contract-http-conflict-00002");
  assert.equal(conflict.status, 409);
  assert.equal((await conflict.json()).error.code, "ack_conflict");
  assert.equal(f.calls.acknowledgements.length, 2);
});
