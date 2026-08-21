import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import { createApiTokenRecord, signDeviceRequest } from "../src/auth.mjs";
import { createCloudApi } from "../src/server.mjs";
import { canonicalControlBundle, controlBundleStatementHash, verifyControlBundle } from "../../../lib/control-bundle-v2.mjs";

const ORGANIZATION_ID = "11111111-1111-4111-8111-111111111111";
const DEVICE_ID = "22222222-2222-4222-8222-222222222222";
const PENDING_DEVICE_ID = "33333333-3333-4333-8333-333333333333";
const NOW = Date.parse("2026-08-13T00:00:00.000Z");
const RECENT_PROOF = "99999999-9999-4999-8999-999999999999";
const TOKEN = "ap_owner_token_managed_control_bundle_abcdefghijklmnopqrstuvwxyz";
const KEY_ID = "control-bundle-managed-2026-08";
const ISSUER = "agentpass-cloud";
const SCOPE = {
  operations: ["git.commit.sign"],
  repositories: ["/work/repo"],
  branches: { allow: ["feature/*"], deny: ["main"] },
  remotes: { allow: ["git@example.test:repo.git"] }
};

function createManagedSigner({ metadataError = undefined, signError = undefined, signingKeys = undefined, signingPrivateKey = undefined, mutate = undefined } = {}) {
  const keys = signingKeys ?? crypto.generateKeyPairSync("ed25519");
  const calls = { metadata: 0, sign: [] };
  const publicKey = keys.publicKey.export({ type: "spki", format: "pem" }).toString();
  const signer = {
    purpose: "agentpass.control-bundle",
    algorithm: "ed25519",
    key_id: KEY_ID,
    issuer: ISSUER,
    ttlMs: 60_000,
    offlineTtlMs: 120_000,
    async publicKeyMetadata() {
      calls.metadata += 1;
      if (metadataError) throw metadataError;
      return { purpose: "agentpass.control-bundle", key_id: KEY_ID, algorithm: "ed25519", public_key: publicKey };
    },
    async signControlBundle(statement) {
      calls.sign.push(structuredClone(statement));
      if (signError) throw signError;
      const value = mutate ? mutate(structuredClone(statement)) : statement;
      return {
        ...value,
        signature: crypto.sign(null, Buffer.from(canonicalControlBundle(value), "utf8"), signingPrivateKey ?? keys.privateKey).toString("base64")
      };
    }
  };
  return { signer, keys, publicKey, calls };
}

function createFixture(t, bundleSigner, { enrollmentCredentialSecret = Buffer.alloc(32, 0x42) } = {}) {
  const deviceKeys = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const refreshKeys = crypto.generateKeyPairSync("ed25519");
  const state = { expectedBundleHash: undefined, enrollment: undefined, completed: undefined };
  const device = {
    device_id: DEVICE_ID,
    organization_id: ORGANIZATION_ID,
    status: "active",
    key_epoch: 1,
    device_public_key: deviceKeys.publicKey.export({ type: "spki", format: "pem" }).toString()
  };
  const store = {
    async listDevices({ organizationId }) { return organizationId === ORGANIZATION_ID ? [device] : []; },
    async snapshotAndAssignBundleHead(input) {
      const snapshot = {
        policy_scope: SCOPE,
        global_revoked: false,
        revoked_devices: [],
        revoked_agents: [],
        revoked_capabilities: []
      };
      const head = {
        organization_id: ORGANIZATION_ID,
        device_id: DEVICE_ID,
        format_epoch: 2,
        sequence: 9,
        issued_at: new Date(NOW).toISOString(),
        expires_at: new Date(NOW + 60_000).toISOString()
      };
      head.state_fingerprint = await input.statementHashFactory({ snapshot, head });
      state.expectedBundleHash = head.state_fingerprint;
      return { snapshot, head, desired_generation: 12 };
    },
    async createDeviceEnrollment(input) {
      state.enrollment = { ...input, enrollment_id: input.enrollmentId, organization_id: input.organizationId, device_id: input.deviceId, status: "pending" };
      return state.enrollment;
    },
    async completeDeviceEnrollment(input) {
      state.completed = input;
      return { ...device, device_id: input.deviceId, status: "active", key_algorithm: input.algorithm, organization_id: input.organizationId };
    },
    async appendAdminAuditEvent() {}
  };
  const server = createCloudApi({
    store,
    tokenRecords: [createApiTokenRecord({ token: TOKEN, tokenId: "managed-control-owner", organizationId: ORGANIZATION_ID, memberId: "owner-1", role: "owner" })],
    bundleSigner,
    refreshHintService: {
      async publicKeyMetadata() {
        return { key_id: "refresh-hint-v1", algorithm: "ed25519", public_key: refreshKeys.publicKey.export({ type: "spki", format: "pem" }).toString() };
      },
      async poll() { return null; }
    },
    enrollmentCredentialSecret,
    now: () => NOW,
    verifyRecentWebAuthn: async ({ proof, organization_id, principal, operation }) => ({ verified: true, consumed: true, challenge_id: proof, member_id: principal.member_id, organization_id, operation, authenticated_at: NOW })
  });
  return new Promise((resolve) => server.listen(0, "127.0.0.1", () => {
    t.after(async () => new Promise((done) => server.close(done)));
    resolve({ server, store, state, deviceKeys, refreshKeys, base: `http://127.0.0.1:${server.address().port}` });
  }));
}

function deviceHeaders(path, privateKey, nonce = "managed-control-bundle-nonce-0000000001") {
  return signDeviceRequest({ method: "GET", path, body: Buffer.alloc(0), device_id: DEVICE_ID, timestamp: NOW, nonce }, privateKey);
}

test("uses the async purpose signer for bundle issuance and preserves the exact statement hash", async (t) => {
  const managed = createManagedSigner();
  const fixture = await createFixture(t, managed.signer);
  const path = `/v1/organizations/${ORGANIZATION_ID}/bundles/${DEVICE_ID}`;
  const response = await fetch(`${fixture.base}${path}`, { headers: deviceHeaders(path, fixture.deviceKeys.privateKey) });
  assert.equal(response.status, 200, JSON.stringify(await response.clone().json()));
  const body = await response.json();
  assert.equal(managed.calls.metadata, 1);
  assert.equal(managed.calls.sign.length, 1);
  assert.equal(controlBundleStatementHash(body.bundle), fixture.state.expectedBundleHash);
  assert.equal(controlBundleStatementHash(managed.calls.sign[0]), fixture.state.expectedBundleHash);
  assert.equal(crypto.verify(null, Buffer.from(canonicalControlBundle(managed.calls.sign[0]), "utf8"), managed.keys.publicKey, Buffer.from(body.bundle.signature, "base64")), true);
  assert.equal(verifyControlBundle(body.bundle, { public_key: managed.publicKey, issuer: ISSUER, key_id: KEY_ID }, { now: NOW, audience: { organization_id: ORGANIZATION_ID, device_id: DEVICE_ID } }).key_id, KEY_ID);
  assert.equal(JSON.stringify(body).includes("PRIVATE KEY"), false);
  assert.equal(Object.keys(managed.signer).some((key) => /private|secret/i.test(key)), false);
});

test("exposes only managed public metadata on legacy enrollment completion", async (t) => {
  const managed = createManagedSigner();
  const fixture = await createFixture(t, managed.signer);
  const enrollmentId = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
  const issueResponse = await fetch(`${fixture.base}/v1/organizations/${ORGANIZATION_ID}/device-enrollments`, {
    method: "POST",
    headers: { authorization: `Bearer ${TOKEN}`, "content-type": "application/json", "idempotency-key": "managed-enrollment-issue-0001", "AgentPass-Recent-Auth": RECENT_PROOF },
    body: JSON.stringify({ enrollment_id: enrollmentId, device_id: PENDING_DEVICE_ID, label: "Build Mac", platform: "macos", ttl_ms: 600_000 })
  });
  assert.equal(issueResponse.status, 201, JSON.stringify(await issueResponse.clone().json()));
  const enrollment = (await issueResponse.json()).enrollment;
  const completionKeys = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const completion = { version: 1, enrollment_id: enrollmentId, organization_id: ORGANIZATION_ID, device_id: PENDING_DEVICE_ID, label: "Build Mac", platform: "macos", device_key: { algorithm: "p256-sha256", spki_pem: completionKeys.publicKey.export({ type: "spki", format: "pem" }).toString() } };
  const body = JSON.stringify(completion);
  const proof = Buffer.from(["AgentPass-Enrollment-Proof-v1", "POST", enrollment.endpoint, crypto.createHash("sha256").update(body).digest("hex"), crypto.createHash("sha256").update(enrollment.credential).digest("hex")].join("\n"));
  const response = await fetch(`${fixture.base}${enrollment.endpoint}`, {
    method: "POST",
    headers: { "content-type": "application/json", "AgentPass-Enrollment-Credential": enrollment.credential, "AgentPass-Enrollment-Signature": crypto.sign("sha256", proof, { key: completionKeys.privateKey, dsaEncoding: "ieee-p1363" }).toString("base64") },
    body
  });
  assert.equal(response.status, 201, JSON.stringify(await response.clone().json()));
  const result = (await response.json()).enrollment;
  assert.equal(result.control.key_id, KEY_ID);
  assert.equal(result.control.public_key, managed.publicKey);
  assert.equal(result.control.issuer, ISSUER);
  assert.equal(JSON.stringify(result).includes("PRIVATE KEY"), false);
  assert.equal(managed.calls.metadata, 1);
  assert.equal(managed.calls.sign.length, 0);
});

test("fails closed for unavailable or forged managed signing and never falls back to privateKey", async (t) => {
  for (const [name, managed] of [
    ["metadata unavailable", createManagedSigner({ metadataError: new Error("provider-secret") })],
    ["sign unavailable", createManagedSigner({ signError: new Error("kms-secret") })],
    ["forged signature", createManagedSigner({ signingPrivateKey: crypto.generateKeyPairSync("ed25519").privateKey })]
  ]) {
    await testCase(name, managed, t);
  }

  const legacyKeys = crypto.generateKeyPairSync("ed25519");
  const fixture = await createFixture(t, { key_id: KEY_ID, issuer: ISSUER, privateKey: legacyKeys.privateKey });
  const path = `/v1/organizations/${ORGANIZATION_ID}/bundles/${DEVICE_ID}`;
  const response = await fetch(`${fixture.base}${path}`, { headers: deviceHeaders(path, fixture.deviceKeys.privateKey, "managed-control-bundle-no-fallback-0001") });
  assert.equal(response.status, 503);
  assert.equal((await response.json()).error.code, "bundle_signer_unavailable");
});

async function testCase(_name, managed, t) {
  const fixture = await createFixture(t, managed.signer);
  const path = `/v1/organizations/${ORGANIZATION_ID}/bundles/${DEVICE_ID}`;
  const response = await fetch(`${fixture.base}${path}`, { headers: deviceHeaders(path, fixture.deviceKeys.privateKey, `managed-control-bundle-${Math.random().toString(36).slice(2)}`) });
  assert.equal(response.status, 503);
  const body = await response.json();
  assert.equal(body.error.code, "bundle_signer_unavailable");
  assert.equal(JSON.stringify(body).includes("secret"), false);
}
