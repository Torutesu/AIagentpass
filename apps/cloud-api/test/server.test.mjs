import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { createApiTokenRecord, signDeviceRequest } from "../src/auth.mjs";
import { createCloudApi } from "../src/server.mjs";
import { computeAuditEventHash, createCloudStore } from "../src/store.mjs";
import { verifyControlBundle } from "../../../lib/control-bundle-v2.mjs";
import { canonicalJson, verifyCapability } from "../../../packages/capability/src/index.mjs";
import { createRateLimiter } from "../src/rate-limit.mjs";

const org = "11111111-1111-4111-8111-111111111111";
const deviceId = "22222222-2222-4222-8222-222222222222";
const agentId = "33333333-3333-4333-8333-333333333333";
const policyId = "44444444-4444-4444-8444-444444444444";
const now = Date.parse("2026-08-12T00:00:00.000Z");

async function fixture(t, apiOptions = {}) {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), "agentpass-api-"));
  const store = await createCloudStore({ dataDir: directory });
  await store.createOrganization({ organizationId: org, name: "Acme", idempotencyKey: "create-org" });
  const deviceKeys = crypto.generateKeyPairSync("ed25519");
  const devicePublic = deviceKeys.publicKey.export({ type: "spki", format: "pem" }).toString();
  await store.createDevice({ organizationId: org, deviceId, name: "Build Mac", publicKey: devicePublic, idempotencyKey: "create-device" });
  const agentKeys = crypto.generateKeyPairSync("ed25519");
  await store.createAgent({ organizationId: org, deviceId, version: 1, agentId, name: "Claude", kind: "claude-code", publicKey: agentKeys.publicKey.export({ type: "spki", format: "pem" }).toString(), createdAt: new Date(now).toISOString(), idempotencyKey: "create-agent" });
  const scope = { operations: ["git.commit.sign"], repositories: ["/work/repo"], branches: { allow: ["feature/*"], deny: ["main"] }, remotes: { allow: ["git@example.test:repo.git"] } };
  await store.createPolicy({ organizationId: org, policyId, name: "default", scope, sequence: 1, idempotencyKey: "create-policy" });
  const token = "ap_owner_token_abcdefghijklmnopqrstuvwxyz";
  const records = [createApiTokenRecord({ token, tokenId: "owner-token", organizationId: org, memberId: "owner-1", role: "owner" })];
  const bundleKeys = crypto.generateKeyPairSync("ed25519");
  const refreshHintKeys = crypto.generateKeyPairSync("ed25519");
  const { storeDecorator, ...cloudApiOptions } = apiOptions;
  const apiStore = typeof storeDecorator === "function" ? storeDecorator(store) : store;
  const server = createCloudApi({ store: apiStore, tokenRecords: records, bundleSigner: { privateKey: bundleKeys.privateKey, issuer: "agentpass-cloud", keyId: "control-v1", ttlMs: 60_000, offlineTtlMs: 120_000 }, refreshHintService: { publicKeyMetadata: async () => ({ key_id: "refresh-hint-v1", algorithm: "ed25519", public_key: refreshHintKeys.publicKey.export({ type: "spki", format: "pem" }).toString() }), poll: async () => null }, now: () => now, verifyRecentWebAuthn: async ({ proof, principal, organization_id, operation }) => ({ verified: proof === "webauthn-proof-abcdefghijklmnopqrstuvwxyz", consumed: true, challenge_id: "99999999-9999-4999-8999-999999999999", member_id: principal.member_id, organization_id, operation, authenticated_at: now }), ...cloudApiOptions });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  t.after(async () => { await new Promise((resolve) => server.close(resolve)); await store.close(); await fs.rm(directory, { recursive: true, force: true }); });
  return { store, token, deviceKeys, bundleKeys, refreshHintKeys, base, scope };
}

function auditListEvent(eventId, requestId, previousHash, deviceTimestamp) {
  const event = { version: 1, event_id: eventId, request_id: requestId, agent_id: agentId, operation: "git.commit.sign", decision: "allow", reason: "allowed", policy_sequence: 1, capability_sequence: 1, repository: "/work/repo", branch: "feature/activity", remote: "git@example.test:repo.git", payload_digest: "a".repeat(64), device_timestamp: deviceTimestamp, previous_hash: previousHash };
  return { ...event, event_hash: computeAuditEventHash(event) };
}

test("human routes enforce bearer role, tenant, and idempotency", async (t) => {
  const f = await fixture(t);
  const ok = await fetch(`${f.base}/v1/organizations/${org}/devices`, { headers: { authorization: `Bearer ${f.token}` } });
  assert.equal(ok.status, 200);
  assert.equal((await ok.json()).devices.length, 1);
  const noAuth = await fetch(`${f.base}/v1/organizations/${org}/devices`);
  assert.equal(noAuth.status, 401);
  const mutation = await fetch(`${f.base}/v1/organizations/${org}/policies`, { method: "POST", headers: { authorization: `Bearer ${f.token}`, "content-type": "application/json" }, body: JSON.stringify({ name: "missing-key", scope: f.scope }) });
  assert.equal(mutation.status, 400);
  assert.equal((await mutation.json()).error.code, "idempotency_key_required");
  const duplicate = await fetch(`${f.base}/v1/organizations/${org}/policies`, { method: "POST", headers: { authorization: `Bearer ${f.token}`, "content-type": "application/json", "idempotency-key": "duplicate-json-0001" }, body: '{"name":"first","name":"second"}' });
  assert.equal(duplicate.status, 400);
  assert.equal((await duplicate.json()).error.code, "invalid_json");
});

test("Human Auth mode uses the hash-only session as control-plane authority and never falls back to bearer", async (t) => {
  const calls = [];
  const policyInputs = [];
  const humanSession = {
    async authenticateRequest(input) {
      calls.push(input);
      if (input.headers.cookie !== `__Host-agentpass_session=${"s".repeat(43)}`) {
        const error = new Error("cookie details must be redacted");
        error.code = "invalid_session_cookie";
        throw error;
      }
      if (input.headers.origin !== "https://console.example.test") {
        const error = new Error("origin details must be redacted");
        error.code = "invalid_origin";
        throw error;
      }
      if (input.method === "POST" && input.headers["agentpass-csrf"] !== "c".repeat(43)) {
        const error = new Error("csrf details must be redacted");
        error.code = "csrf_token_required";
        throw error;
      }
      return { session: { member_id: "owner-1", organization_id: org, role: "owner" } };
    }
  };
  const f = await fixture(t, {
    humanSession,
    storeDecorator: (store) => Object.freeze({
      ...store,
      async createPolicy(input) { policyInputs.push(structuredClone(input)); return store.createPolicy(input); }
    })
  });
  const pathName = `/v1/organizations/${org}/devices`;
  const deniedBearer = await fetch(`${f.base}${pathName}`, { headers: { authorization: `Bearer ${f.token}` } });
  assert.equal(deniedBearer.status, 401);
  assert.deepEqual((await deniedBearer.json()).error, { code: "human_session_invalid", message: "Authentication failed" });

  const accepted = await fetch(`${f.base}${pathName}`, { headers: { cookie: `__Host-agentpass_session=${"s".repeat(43)}`, origin: "https://console.example.test" } });
  assert.equal(accepted.status, 200, JSON.stringify(await accepted.clone().json()));
  assert.equal((await accepted.json()).devices.length, 1);
  assert.equal(calls.at(-1).method, "GET");

  const wrongOrigin = await fetch(`${f.base}${pathName}`, { headers: { cookie: `__Host-agentpass_session=${"s".repeat(43)}`, origin: "https://attacker.example.test" } });
  assert.equal(wrongOrigin.status, 403);
  assert.deepEqual((await wrongOrigin.json()).error, { code: "human_session_request_denied", message: "Authentication failed" });

  const mutationPath = `/v1/organizations/${org}/policies`;
  const mutationHeaders = { cookie: `__Host-agentpass_session=${"s".repeat(43)}`, origin: "https://console.example.test", "content-type": "application/json", "idempotency-key": "human-auth-policy-0001" };
  const missingCsrf = await fetch(`${f.base}${mutationPath}`, { method: "POST", headers: mutationHeaders, body: JSON.stringify({ name: "session-policy", scope: f.scope, sequence: 2 }) });
  assert.equal(missingCsrf.status, 403);
  const acceptedMutation = await fetch(`${f.base}${mutationPath}`, { method: "POST", headers: { ...mutationHeaders, "agentpass-csrf": "c".repeat(43), "idempotency-key": "human-auth-policy-0002" }, body: JSON.stringify({ name: "session-policy", scope: f.scope, sequence: 2 }) });
  assert.equal(acceptedMutation.status, 201, JSON.stringify(await acceptedMutation.clone().json()));
  assert.equal(policyInputs.length, 1);
  assert.equal(policyInputs[0].createdBy, "owner-1");
  assert.equal(policyInputs[0].principalId, "owner-1");
});

test("admin issues a one-time enrollment and a macOS P-256 device completes it", async (t) => {
  const f = await fixture(t, { enrollmentCredentialSecret: Buffer.alloc(32, 0x5e) });
  const enrollmentId = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
  const pendingDevice = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
  const enrollmentBody = JSON.stringify({ enrollment_id: enrollmentId, device_id: pendingDevice, label: "Build Mac 02", platform: "macos", ttl_ms: 600_000 });
  const withoutRecentAuth = await fetch(`${f.base}/v1/organizations/${org}/device-enrollments`, {
    method: "POST",
    headers: { authorization: `Bearer ${f.token}`, "content-type": "application/json", "idempotency-key": "issue-device-enrollment-denied" },
    body: enrollmentBody
  });
  assert.equal(withoutRecentAuth.status, 401);
  assert.equal((await withoutRecentAuth.json()).error.code, "recent_auth_required");
  const issued = await fetch(`${f.base}/v1/organizations/${org}/device-enrollments`, {
    method: "POST",
    headers: { authorization: `Bearer ${f.token}`, "content-type": "application/json", "idempotency-key": "issue-device-enrollment-0001", "AgentPass-Recent-Auth": "webauthn-proof-abcdefghijklmnopqrstuvwxyz" },
    body: enrollmentBody
  });
  assert.equal(issued.status, 201, JSON.stringify(await issued.clone().json()));
  const invitation = (await issued.json()).enrollment;
  assert.match(invitation.credential, /^[A-Za-z0-9_-]{43}$/);
  const retried = await fetch(`${f.base}/v1/organizations/${org}/device-enrollments`, {
    method: "POST",
    headers: { authorization: `Bearer ${f.token}`, "content-type": "application/json", "idempotency-key": "issue-device-enrollment-0001", "AgentPass-Recent-Auth": "webauthn-proof-abcdefghijklmnopqrstuvwxyz" },
    body: enrollmentBody
  });
  assert.equal(retried.status, 201, JSON.stringify(await retried.clone().json()));
  assert.deepEqual((await retried.json()).enrollment, invitation);
  const keys = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const request = { version: 1, enrollment_id: enrollmentId, organization_id: org, device_id: pendingDevice, label: "Build Mac 02", platform: "macos", device_key: { algorithm: "p256-sha256", spki_pem: keys.publicKey.export({ type: "spki", format: "pem" }).toString() } };
  const requestBody = JSON.stringify(request);
  const proof = Buffer.from(["AgentPass-Enrollment-Proof-v1", "POST", invitation.endpoint, crypto.createHash("sha256").update(requestBody).digest("hex"), crypto.createHash("sha256").update(invitation.credential).digest("hex")].join("\n"));
  const signature = crypto.sign("sha256", proof, { key: keys.privateKey, dsaEncoding: "ieee-p1363" }).toString("base64");
  const enrollmentHeaders = { "content-type": "application/json", "AgentPass-Enrollment-Credential": invitation.credential, "AgentPass-Enrollment-Signature": signature };
  const badCredential = crypto.randomBytes(32).toString("base64url");
  const badProof = Buffer.from(["AgentPass-Enrollment-Proof-v1", "POST", invitation.endpoint, crypto.createHash("sha256").update(requestBody).digest("hex"), crypto.createHash("sha256").update(badCredential).digest("hex")].join("\n"));
  const badHeaders = { "content-type": "application/json", "AgentPass-Enrollment-Credential": badCredential, "AgentPass-Enrollment-Signature": crypto.sign("sha256", badProof, { key: keys.privateKey, dsaEncoding: "ieee-p1363" }).toString("base64") };
  const wrongCredential = await fetch(`${f.base}${invitation.endpoint}`, { method: "POST", headers: badHeaders, body: requestBody });
  assert.equal(wrongCredential.status, 401);
  assert.equal((await wrongCredential.json()).error.code, "invalid_enrollment_credential");
  const completed = await fetch(`${f.base}${invitation.endpoint}`, { method: "POST", headers: enrollmentHeaders, body: requestBody });
  assert.equal(completed.status, 201, JSON.stringify(await completed.clone().json()));
  const result = (await completed.json()).enrollment;
  assert.equal(result.status, "active");
  assert.equal(result.device_key_epoch, 1);
  assert.equal(result.control.format_epoch, 2);
  assert.equal(result.control.issuer, "agentpass-cloud");
  assert.equal(result.control.bundle_path, `/v1/organizations/${org}/bundles/${pendingDevice}`);
  assert.equal(result.control.refresh_hint.key_id, "refresh-hint-v1");
  assert.equal(result.control.refresh_hint.algorithm, "ed25519");
  assert.notEqual(result.control.refresh_hint.public_key, result.control.public_key);
  assert.equal(crypto.createPublicKey(result.control.public_key).asymmetricKeyType, "ed25519");
  const replay = await fetch(`${f.base}${invitation.endpoint}`, { method: "POST", headers: enrollmentHeaders, body: requestBody });
  assert.equal(replay.status, 201);
  const substituted = await fetch(`${f.base}${invitation.endpoint}`, { method: "POST", headers: enrollmentHeaders, body: JSON.stringify({ ...request, label: "Other Mac" }) });
  assert.equal(substituted.status, 401);
  assert.equal((await f.store.getDevice({ organizationId: org, deviceId: pendingDevice })).status, "active");
});

test("recent WebAuthn authorization is exact-operation bound and must be atomically consumed", async (t) => {
  const f = await fixture(t, { verifyRecentWebAuthn: async ({ principal, organization_id }) => ({ verified: true, consumed: false, challenge_id: "99999999-9999-4999-8999-999999999999", member_id: principal.member_id, organization_id, operation: "organization.emergency_stop", authenticated_at: now }) });
  const response = await fetch(`${f.base}/v1/organizations/${org}/device-enrollments`, {
    method: "POST",
    headers: { authorization: `Bearer ${f.token}`, "content-type": "application/json", "idempotency-key": "issue-device-enrollment-wrong-binding", "AgentPass-Recent-Auth": "webauthn-proof-abcdefghijklmnopqrstuvwxyz" },
    body: JSON.stringify({ enrollment_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaab", device_id: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbc", label: "Rejected Mac", platform: "macos", ttl_ms: 600_000 })
  });
  assert.equal(response.status, 401);
  assert.equal((await response.json()).error.code, "recent_auth_failed");
  assert.equal((await f.store.listDevices({ organizationId: org })).some((device) => device.device_id === "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbc"), false);
});

test("device routes verify the exact signed request and issue an audience-bound bundle", async (t) => {
  const f = await fixture(t);
  const pathName = `/v1/organizations/${org}/bundles/${deviceId}`;
  const signed = signDeviceRequest({ method: "GET", path: pathName, body: Buffer.alloc(0), device_id: deviceId, timestamp: now, nonce: "nonce-abcdefghijklmnopqrstuvwxyz-1234567890" }, f.deviceKeys.privateKey);
  const response = await fetch(`${f.base}${pathName}`, { headers: signed });
  assert.equal(response.status, 200, JSON.stringify(await response.clone().json()));
  const bundle = (await response.json()).bundle;
  const verifiedBundle = verifyControlBundle(bundle, { public_key: f.bundleKeys.publicKey, issuer: "agentpass-cloud", key_id: "control-v1" }, { now, audience: { organization_id: org, device_id: deviceId } });
  assert.equal(verifiedBundle.format_epoch, 2);
  assert.ok(verifiedBundle.sequence >= 1);

  const secondHeaders = signDeviceRequest({ method: "GET", path: pathName, body: Buffer.alloc(0), device_id: deviceId, timestamp: now, nonce: "nonce-second-abcdefghijklmnopqrstuvwxyz-123456" }, f.deviceKeys.privateKey);
  const second = await fetch(`${f.base}${pathName}`, { headers: secondHeaders });
  assert.equal(second.status, 200);
  assert.deepEqual((await second.json()).bundle, bundle, "unchanged effective state must return byte-equivalent signed bundle data");

  const revokedCapabilityId = "88888888-8888-4888-8888-888888888888";
  await f.store.createCapability({ organizationId: org, capabilityId: revokedCapabilityId, agentId, deviceId, issuer: "agentpass-cloud", keyId: "control-v1", scope: f.scope, operations: ["git.commit.sign"], notBefore: new Date(now).toISOString(), expiresAt: new Date(now + 60_000).toISOString(), sequence: 1, nonce: "capability-nonce-abcdefghijklmnopqrstuvwxyz", idempotencyKey: "bundle-capability" });
  await f.store.createRevocation({ organizationId: org, targetType: "capability", targetId: revokedCapabilityId, reason: "operator-revoked", idempotencyKey: "bundle-capability-revoke" });
  const revokedHeaders = signDeviceRequest({ method: "GET", path: pathName, body: Buffer.alloc(0), device_id: deviceId, timestamp: now, nonce: "nonce-revoked-capability-abcdefghijklmnopqrstuvwxyz" }, f.deviceKeys.privateKey);
  const revokedResponse = await fetch(`${f.base}${pathName}`, { headers: revokedHeaders });
  assert.equal(revokedResponse.status, 200);
  const revokedBundle = (await revokedResponse.json()).bundle;
  assert.deepEqual(revokedBundle.revoked_capabilities, [revokedCapabilityId]);
  assert.ok(revokedBundle.sequence > bundle.sequence);

  const replay = await fetch(`${f.base}${pathName}`, { headers: signed });
  assert.equal(replay.status, 401);
  const otherPath = `/v1/organizations/${org}/bundles/55555555-5555-4555-8555-555555555555`;
  const substitution = await fetch(`${f.base}${otherPath}`, { headers: { ...signed, "AgentPass-Nonce": "nonce-zyxwvutsrqponmlkjihgfedcba-0987654321" } });
  assert.equal(substitution.status, 401);
});

test("ControlBundle merges durable PostgreSQL capability revocations and fails closed when authority is unavailable", async (t) => {
  const durableRevocation = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
  const nextRevocation = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
  let durable = [durableRevocation];
  const calls = [];
  const source = {
    async listRevokedCapabilityIds(input) {
      calls.push(input);
      if (durable instanceof Error) throw durable;
      return durable;
    }
  };
  const f = await fixture(t, { capabilityRevocationSource: source });
  const pathName = `/v1/organizations/${org}/bundles/${deviceId}`;
  const firstHeaders = signDeviceRequest({ method: "GET", path: pathName, body: Buffer.alloc(0), device_id: deviceId, timestamp: now, nonce: "nonce-durable-revocation-abcdefghijklmnopqrstuvwxyz" }, f.deviceKeys.privateKey);
  const first = await fetch(`${f.base}${pathName}`, { headers: firstHeaders });
  assert.equal(first.status, 200, JSON.stringify(await first.clone().json()));
  const firstBundle = (await first.json()).bundle;
  assert.deepEqual(firstBundle.revoked_capabilities, [durableRevocation]);
  assert.deepEqual(calls[0], { organization_id: org, evaluated_at: new Date(now).toISOString() });

  durable = [nextRevocation, durableRevocation];
  const secondHeaders = signDeviceRequest({ method: "GET", path: pathName, body: Buffer.alloc(0), device_id: deviceId, timestamp: now, nonce: "nonce-durable-revocation-second-abcdefghijklmnop" }, f.deviceKeys.privateKey);
  const second = await fetch(`${f.base}${pathName}`, { headers: secondHeaders });
  assert.equal(second.status, 200);
  const secondBundle = (await second.json()).bundle;
  assert.deepEqual(secondBundle.revoked_capabilities, [durableRevocation, nextRevocation]);
  assert.ok(secondBundle.sequence > firstBundle.sequence);

  durable = new Error("database details must not escape");
  const unavailableHeaders = signDeviceRequest({ method: "GET", path: pathName, body: Buffer.alloc(0), device_id: deviceId, timestamp: now, nonce: "nonce-durable-revocation-failure-abcdefghijkl" }, f.deviceKeys.privateKey);
  const unavailable = await fetch(`${f.base}${pathName}`, { headers: unavailableHeaders });
  assert.equal(unavailable.status, 503);
  const failure = await unavailable.json();
  assert.equal(failure.error.code, "capability_revocations_unavailable");
  assert.doesNotMatch(JSON.stringify(failure), /database details/u);
});

test("device audit ingestion is authenticated and rejects body substitution", async (t) => {
  const f = await fixture(t);
  const endpoint = `/v1/organizations/${org}/audit/events`;
  const event = { version: 1, event_id: "66666666-6666-4666-8666-666666666666", request_id: "77777777-7777-4777-8777-777777777777", agent_id: agentId, operation: "git.commit.sign", decision: "allow", reason: "allowed", policy_sequence: 1, capability_sequence: 1, repository: "/work/repo", branch: "feature/api", remote: "git@example.test:repo.git", payload_digest: "a".repeat(64), device_timestamp: new Date(now).toISOString(), previous_hash: "0".repeat(64) };
  event.event_hash = computeAuditEventHash(event);
  const body = JSON.stringify({ batch_id: "audit-batch-1", events: [event] });
  const headers = signDeviceRequest({ method: "POST", path: endpoint, body, device_id: deviceId, timestamp: now, nonce: "nonce-audit-abcdefghijklmnopqrstuvwxyz-12345" }, f.deviceKeys.privateKey);
  const accepted = await fetch(`${f.base}${endpoint}`, { method: "POST", headers: { ...headers, "content-type": "application/json" }, body });
  assert.equal(accepted.status, 202, JSON.stringify(await accepted.clone().json()));
  const tampered = await fetch(`${f.base}${endpoint}`, { method: "POST", headers: { ...headers, "AgentPass-Nonce": "nonce-audit-zyxwvutsrqponmlkjihgfedcba-54321", "content-type": "application/json" }, body: JSON.stringify({ batch_id: "other", events: [event] }) });
  assert.equal(tampered.status, 401);
});

test("device audit listing requires one device scope, returns exact records, and maps cursor failures", async (t) => {
  const f = await fixture(t);
  const endpoint = `/v1/organizations/${org}/audit/events`;
  const first = auditListEvent("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", "0".repeat(64), new Date(now).toISOString());
  const second = auditListEvent("cccccccc-cccc-4ccc-8ccc-cccccccccccc", "dddddddd-dddd-4ddd-8ddd-dddddddddddd", first.event_hash, new Date(now + 1_000).toISOString());
  await f.store.ingestDeviceAuditEvents({ organizationId: org, deviceId, events: [first, second], idempotencyKey: "audit-list-page-0001" });

  const firstPageResponse = await fetch(`${f.base}${endpoint}?device_id=${deviceId}&limit=1`, { headers: { authorization: `Bearer ${f.token}` } });
  assert.equal(firstPageResponse.status, 200);
  const firstPage = await firstPageResponse.json();
  assert.equal(firstPage.events.length, 1);
  assert.deepEqual(Object.keys(firstPage.events[0]).sort(), ["device_id", "event", "event_id", "organization_id", "received_at"]);
  assert.ok(firstPage.next_cursor);

  const next = await fetch(`${f.base}${endpoint}?device_id=${deviceId}&limit=1&cursor=${encodeURIComponent(firstPage.next_cursor)}`, { headers: { authorization: `Bearer ${f.token}` } });
  assert.equal(next.status, 200);
  assert.equal((await next.json()).events.length, 1);

  for (const query of ["", `?device_id=${deviceId}&device_id=${deviceId}`, `?device_id=${deviceId}&unknown=1`, `?device_id=${deviceId}&cursor=${encodeURIComponent(`${firstPage.next_cursor}A`)}`]) {
    const response = await fetch(`${f.base}${endpoint}${query}`, { headers: { authorization: `Bearer ${f.token}` } });
    assert.equal(response.status, 400);
    const body = await response.json();
    assert.equal(body.error.code, query.includes("cursor") ? "invalid_cursor" : "invalid_query");
    if (query.includes("cursor")) assert.equal(body.error.message, "Cursor is invalid");
  }
});

test("admin issues a signed short-lived capability bound to an active agent and device", async (t) => {
  const authorityCalls = [];
  let authorityError;
  const f = await fixture(t, { capabilityAuthorityRepository: { async issueCapabilityMetadata(input) { authorityCalls.push(input); if (authorityError) throw authorityError; return input; } } });
  const endpoint = `${f.base}/v1/organizations/${org}/capabilities`;
  const headers = { authorization: `Bearer ${f.token}`, "content-type": "application/json", "idempotency-key": "capability-request-0001" };
  const body = JSON.stringify({ agent_id: agentId, device_id: deviceId, scope: f.scope, ttl_ms: 60_000, sequence: 1 });
  const response = await fetch(endpoint, {
    method: "POST",
    headers,
    body
  });
  assert.equal(response.status, 201, JSON.stringify(await response.clone().json()));
  const capability = (await response.json()).capability;
  const verified = verifyCapability(capability, { public_key: f.bundleKeys.publicKey, issuer: "agentpass-cloud", key_id: "control-v1" }, { now, audience: { agent_id: agentId, device_id: deviceId } });
  assert.equal(verified.scope.operations[0], "git.commit.sign");
  assert.equal((await f.store.getCapability({ organizationId: org, capabilityId: capability.capability_id })).signature, undefined);
  assert.equal(authorityCalls.length, 1);
  const capabilityStatement = { ...capability };
  delete capabilityStatement.signature;
  assert.deepEqual(authorityCalls[0], {
    organization_id: org,
    capability_id: capability.capability_id,
    agent_id: agentId,
    device_id: deviceId,
    sequence: 1,
    statement_hash: crypto.createHash("sha256").update(canonicalJson(capabilityStatement)).digest("hex"),
    expires_at: capability.expires_at,
    issued_by_member_id: "owner-1"
  });

  const retry = await fetch(endpoint, { method: "POST", headers, body });
  assert.equal(retry.status, 201);
  assert.deepEqual((await retry.json()).capability, capability, "an exact retry must return the same bearer envelope without issuing again");
  assert.equal(authorityCalls.length, 2, "the PostgreSQL authority boundary must verify an exact replay too");
  assert.equal((await f.store.listCapabilities({ organizationId: org })).length, 1);

  authorityError = Object.assign(new Error("database detail must not escape"), { code: "ERR_DATABASE" });
  const unavailable = await fetch(endpoint, {
    method: "POST",
    headers: { ...headers, "idempotency-key": "capability-request-authority-failure" },
    body: JSON.stringify({ agent_id: agentId, device_id: deviceId, scope: f.scope, ttl_ms: 60_000, sequence: 2 })
  });
  assert.equal(unavailable.status, 503);
  const unavailableBody = await unavailable.json();
  assert.equal(unavailableBody.error.code, "capability_authority_unavailable");
  assert.doesNotMatch(JSON.stringify(unavailableBody), /database detail/u);

  const unknown = await fetch(`${f.base}/v1/organizations/${org}/capabilities`, {
    method: "POST",
    headers: { authorization: `Bearer ${f.token}`, "content-type": "application/json", "idempotency-key": "capability-request-0002" },
    body: JSON.stringify({ agent_id: agentId, device_id: deviceId, scope: f.scope, sequence: 2, unexpected: true })
  });
  assert.equal(unknown.status, 400);
});

test("operator routes expose metadata and persist device, policy, and capability controls", async (t) => {
  const f = await fixture(t);
  const auth = { authorization: `Bearer ${f.token}` };
  const capabilities = await fetch(`${f.base}/v1/organizations/${org}/capabilities`, { headers: auth });
  assert.equal(capabilities.status, 200);
  assert.deepEqual((await capabilities.json()).capabilities, []);

  const disabled = await fetch(`${f.base}/v1/organizations/${org}/policies/${policyId}/disable`, {
    method: "POST",
    headers: { ...auth, "content-type": "application/json", "idempotency-key": "disable-policy-0001" },
    body: JSON.stringify({ expected_version: 1, reason: "maintenance" })
  });
  assert.equal(disabled.status, 200, JSON.stringify(await disabled.clone().json()));
  assert.equal((await disabled.json()).policy.status, "disabled");

  const deviceRevocation = await fetch(`${f.base}/v1/organizations/${org}/devices/${deviceId}/revoke`, {
    method: "POST",
    headers: { ...auth, "content-type": "application/json", "idempotency-key": "revoke-device-0001" },
    body: JSON.stringify({ reason: "lost-device" })
  });
  assert.equal(deviceRevocation.status, 201, JSON.stringify(await deviceRevocation.clone().json()));
  const revocations = await fetch(`${f.base}/v1/organizations/${org}/revocations`, { headers: auth });
  assert.equal((await revocations.json()).revocations[0].target_type, "device");

  const adminAudit = await fetch(`${f.base}/v1/organizations/${org}/audit/admin-events`, { headers: auth });
  assert.equal(adminAudit.status, 200);
  assert.ok((await adminAudit.json()).events.some((event) => event.event_type === "policy.disabled"));
  const health = await fetch(`${f.base}/v1/organizations/${org}/audit/health`, { headers: auth });
  assert.equal(health.status, 200);
  assert.equal((await health.json()).health[0].chain_status, "continuous");
});

test("rate limits human and device principals independently and returns retry metadata", async (t) => {
  let monotonic = 10_000;
  const limiter = createRateLimiter({
    now: () => now,
    monotonicNow: () => monotonic,
    maxEntries: 8,
    human: { capacity: 1, refillPerSecond: 1 },
    device: { capacity: 1, refillPerSecond: 1 }
  });
  const f = await fixture(t, { rateLimiter: limiter });
  const humanPath = `/v1/organizations/${org}/devices`;
  const firstHuman = await fetch(`${f.base}${humanPath}`, { headers: { authorization: `Bearer ${f.token}` } });
  assert.equal(firstHuman.status, 200);
  assert.equal(firstHuman.headers.get("x-ratelimit-limit"), "1");
  assert.equal(firstHuman.headers.get("x-ratelimit-remaining"), "0");
  const blockedHuman = await fetch(`${f.base}${humanPath}`, { headers: { authorization: `Bearer ${f.token}` } });
  assert.equal(blockedHuman.status, 429);
  assert.equal(blockedHuman.headers.get("retry-after"), "1");
  assert.equal(blockedHuman.headers.get("x-ratelimit-reset"), String(Math.ceil(now / 1000) + 1));

  const devicePath = `/v1/organizations/${org}/bundles/${deviceId}`;
  const deviceHeaders = signDeviceRequest({ method: "GET", path: devicePath, body: Buffer.alloc(0), device_id: deviceId, timestamp: now, nonce: "nonce-rate-device-abcdefghijklmnopqrstuvwxyz-123" }, f.deviceKeys.privateKey);
  const firstDevice = await fetch(`${f.base}${devicePath}`, { headers: deviceHeaders });
  assert.equal(firstDevice.status, 200);
  assert.equal(firstDevice.headers.get("x-ratelimit-limit"), "1");
  assert.equal(firstDevice.headers.get("x-ratelimit-remaining"), "0");

  monotonic += 1_000;
  const recoveredHuman = await fetch(`${f.base}${humanPath}`, { headers: { authorization: `Bearer ${f.token}` } });
  assert.equal(recoveredHuman.status, 200);
});

test("rate limiter isolates principals, resets buckets, and fails closed at capacity", () => {
  let monotonic = 0;
  const limiter = createRateLimiter({
    now: () => 1_000,
    monotonicNow: () => monotonic,
    maxEntries: 2,
    idleTtlMs: 100,
    human: { capacity: 1, refillPerSecond: 1 },
    device: { capacity: 1, refillPerSecond: 1 }
  });
  assert.equal(limiter.acquire({ tenantId: org, principalType: "human", principalId: "member-a" }).allowed, true);
  assert.equal(limiter.acquire({ tenantId: org, principalType: "human", principalId: "member-b" }).allowed, true);
  assert.throws(() => limiter.acquire({ tenantId: org, principalType: "human", principalId: "member-c" }), { code: "RATE_LIMITER_CAPACITY_EXHAUSTED" });
  assert.equal(limiter.size, 2);
  assert.throws(() => limiter.acquire({ tenantId: org, principalType: "device", principalId: "device-a" }), { code: "RATE_LIMITER_CAPACITY_EXHAUSTED" });
  limiter.reset({ tenantId: org, principalType: "human", principalId: "member-a" });
  assert.equal(limiter.acquire({ tenantId: org, principalType: "human", principalId: "member-a" }).allowed, true);
  monotonic = 100;
  assert.equal(limiter.acquire({ tenantId: org, principalType: "human", principalId: "member-c" }).allowed, true, "idle entries are purged before allocating a new bucket");
});

test("rate limiter rejects unsafe configuration and a backwards monotonic clock", () => {
  assert.throws(() => createRateLimiter({ maxEntries: 0 }), { code: "RATE_LIMITER_CONFIGURATION_INVALID" });
  assert.throws(() => createRateLimiter({ human: { capacity: 1, refillPerSecond: Number.NaN } }), { code: "RATE_LIMITER_CONFIGURATION_INVALID" });
  let monotonic = 10;
  const limiter = createRateLimiter({ now: () => now, monotonicNow: () => monotonic });
  limiter.acquire({ tenantId: org, principalType: "human", principalId: "member-a" });
  monotonic = 9;
  assert.throws(() => limiter.acquire({ tenantId: org, principalType: "human", principalId: "member-a" }), { code: "RATE_LIMITER_CONFIGURATION_INVALID" });
  assert.throws(() => limiter.acquire({ tenantId: org, principalType: "human", principalId: "\u0000" }), { code: "RATE_LIMITER_CONFIGURATION_INVALID" });
});

test("rate limiter preserves exhausted buckets across restart", async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), "agentpass-rate-state-"));
  const statePath = path.join(directory, "rate.json");
  const options = { now: () => now, monotonicNow: () => 1_000, persistencePath: statePath, human: { capacity: 1, refillPerSecond: 1 }, device: { capacity: 1, refillPerSecond: 1 } };
  const first = createRateLimiter(options);
  assert.equal(first.acquire({ tenantId: org, principalType: "human", principalId: "member-a" }).allowed, true);
  const restarted = createRateLimiter(options);
  assert.equal(restarted.acquire({ tenantId: org, principalType: "human", principalId: "member-a" }).allowed, false);
  await fs.rm(directory, { recursive: true, force: true });
});
