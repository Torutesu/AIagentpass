import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import { createDeviceEnrollmentSetupHandler } from "../lib/device-enrollment-setup-handler.mjs";
import { canonicalJson } from "../lib/identity.mjs";

const enrollmentId = "11111111-1111-4111-8111-111111111111";
const organizationId = "22222222-2222-4222-8222-222222222222";
const deviceId = "33333333-3333-4333-8333-333333333333";
const nonce = "A".repeat(43);
const expiresAt = "2099-01-02T03:04:05.000Z";

function fingerprint(key) {
  return `SHA256:${crypto.createHash("sha256").update(key.publicKey.export({ type: "spki", format: "der" })).digest("base64url")}`;
}

function candidateBinding(key) {
  return {
    version: 1,
    enrollment_id: enrollmentId,
    organization_id: organizationId,
    device_id: deviceId,
    candidate_id: "release-2026-08-13-01",
    artifact_sha256: "a".repeat(64),
    source_commit: "b".repeat(40),
    team_id: "TEAMID1234",
    device_key_fingerprint: fingerprint(key),
    expires_at: expiresAt
  };
}

function possessionReceipt(key, receiptSigner, binding) {
  const { expires_at: _expiresAt, ...candidate } = binding;
  const statement = {
    ...candidate,
    device_key_epoch: 4,
    challenge_nonce_digest: crypto.createHash("sha256").update(nonce).digest("hex"),
    issued_at: expiresAt
  };
  const statementBytes = Buffer.from(canonicalJson(statement), "utf8");
  const signed = Buffer.from(`AgentPass-Cloud-Possession-Receipt-v1\0${statementBytes.toString("utf8")}`, "utf8");
  return {
    version: 1,
    purpose: "device-enrollment-possession-receipt",
    key_id: "receipt-key-v1",
    algorithm: "ed25519",
    statement,
    statement_hash: crypto.createHash("sha256").update(statementBytes).digest("hex"),
    signature: crypto.sign(null, signed, receiptSigner.privateKey).toString("base64url")
  };
}

function invitation(key, credential, receiptSigner) {
  const binding = candidateBinding(key);
  return {
    version: 2,
    proof_version: 2,
    enrollment_id: enrollmentId,
    organization_id: organizationId,
    device_id: deviceId,
    label: "Build Mac",
    platform: "macos",
    candidate_binding: binding,
    challenge_id: enrollmentId,
    nonce,
    expires_at: expiresAt,
    challenge: {
      challenge_id: enrollmentId,
      nonce,
      expires_at: expiresAt,
      candidate_id: binding.candidate_id,
      device_key_fingerprint: binding.device_key_fingerprint
    },
    credential,
    endpoint: `/v1/enrollments/${enrollmentId}`,
    possession_receipt_verification: {
      key_id: "receipt-key-v1",
      algorithm: "ed25519",
      public_key: receiptSigner.publicKey.export({ type: "spki", format: "pem" }).toString()
    }
  };
}

function completedResponse(control, refreshHint) {
  return {
    request_id: "request-1",
    enrollment: {
      version: 1,
      enrollment_id: enrollmentId,
      organization_id: organizationId,
      device_id: deviceId,
      status: "active",
      key_algorithm: "p256-sha256",
      device_key_epoch: 4,
      control: {
        format_epoch: 2,
        issuer: "agentpass-cloud",
        key_id: "control-v1",
        public_key: control.publicKey.export({ type: "spki", format: "pem" }).toString(),
        bundle_path: `/v1/organizations/${organizationId}/bundles/${deviceId}`,
        refresh_hint: {
          key_id: "refresh-hint-v1",
          algorithm: "ed25519",
          public_key: refreshHint.publicKey.export({ type: "spki", format: "pem" }).toString()
        }
      }
    }
  };
}

function commonOptions({ device, receiptSigner, credential, fetchImpl, baseUrl = "https://api.example.test/v1" } = {}) {
  const binding = candidateBinding(device);
  return {
    runner: {
      publicKey: () => ({ algorithm: "p256-sha256", spki_pem: device.publicKey.export({ type: "spki", format: "pem" }).toString(), fingerprint: fingerprint(device) }),
      sign: ({ bytes }) => crypto.sign("sha256", bytes, { key: device.privateKey, dsaEncoding: "ieee-p1363" })
    },
    provisionControl: async () => ({ changed: true, old_fingerprint: null, new_fingerprint: `SHA256:${"A".repeat(43)}` }),
    restartService: async () => ({ status: "enabled", control_refreshed: true }),
    invitation: invitation(device, credential, receiptSigner),
    baseUrl,
    loadConfig: () => ({}),
    saveConfig: () => {},
    fetchImpl
  };
}

function context() {
  return { current_state: "service_keys_activated", target_state: "device_enrolled", operation_id: "setup:test:enroll_device", action: { id: "enroll_device" } };
}

test("uses the v2 invitation, verifies the receipt, and persists only non-secret control trust", async () => {
  const device = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const receiptSigner = crypto.generateKeyPairSync("ed25519");
  const control = crypto.generateKeyPairSync("ed25519");
  const refreshHint = crypto.generateKeyPairSync("ed25519");
  const credential = crypto.randomBytes(32).toString("base64url");
  const receipt = possessionReceipt(device, receiptSigner, candidateBinding(device));
  const original = { version: 4, native_broker: { enabled: true, mach_service: "dev.agentpass.native-service", client: "/Applications/AgentPass.app/client" } };
  let saved;
  let provisioned;
  let receiptReads = 0;
  const handler = createDeviceEnrollmentSetupHandler({
    ...commonOptions({
      device,
      receiptSigner,
      credential,
      fetchImpl: async (_url, init) => {
        if (init.method === "GET") {
          receiptReads += 1;
          assert.equal(init.headers["AgentPass-Enrollment-Credential"], undefined);
          return receiptReads === 1
            ? new Response("", { status: 401 })
            : new Response(canonicalJson({ request_id: "receipt-1", receipt }), { status: 200, headers: { "content-type": "application/json" } });
        }
        assert.equal(init.headers["AgentPass-Enrollment-Credential"], credential);
        assert.equal(JSON.parse(Buffer.from(init.body).toString("utf8")).proof_version, 2);
        return new Response(canonicalJson(completedResponse(control, refreshHint)), { status: 201, headers: { "content-type": "application/json" } });
      }
    }),
    loadConfig: () => original,
    saveConfig: (value) => { saved = value; },
    provisionControl: async (value) => { provisioned = value; return { changed: true, old_fingerprint: null, new_fingerprint: `SHA256:${"A".repeat(43)}` }; }
  });
  const result = await handler(context());
  assert.deepEqual(result.evidence.proof, {
    organization_id: organizationId,
    device_id: deviceId,
    enrollment_id: enrollmentId,
    device_key_epoch: 4,
    key_fingerprint: fingerprint(device),
    proof_version: 2,
    candidate_id: "release-2026-08-13-01",
    challenge_nonce_digest: crypto.createHash("sha256").update(nonce).digest("hex"),
    receipt_key_id: "receipt-key-v1",
    receipt_statement_hash: receipt.statement_hash
  });
  assert.equal(receiptReads, 2);
  assert.equal(saved.control_v2.required, true);
  assert.equal(saved.control_v2.capability_required, true);
  assert.equal(saved.control_v2.url, `https://api.example.test/v1/organizations/${organizationId}/bundles/${deviceId}`);
  assert.equal(saved.native_broker.control_url, saved.control_v2.url);
  assert.equal(provisioned.control_url, saved.control_v2.url);
  assert.equal(provisioned.control_v2_api_base_url, "https://api.example.test/v1");
  assert.equal(provisioned.device_key_epoch, 4);
  assert.equal(provisioned.refresh_hint.key_id, "refresh-hint-v1");
  assert.equal(provisioned.public_key_pem, saved.control_v2.public_key);
  assert.equal(JSON.stringify(saved).includes(credential), false);
  assert.equal(JSON.stringify(result).includes(credential), false);
});

test("rejects legacy invitations and unsafe enrollment bases before mutation", async () => {
  const device = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const receiptSigner = crypto.generateKeyPairSync("ed25519");
  const credential = crypto.randomBytes(32).toString("base64url");
  const common = commonOptions({ device, receiptSigner, credential, fetchImpl: async () => new Response("", { status: 401 }) });
  const legacy = { enrollment_id: enrollmentId, organization_id: organizationId, device_id: deviceId, label: "Build Mac", credential };
  assert.throws(() => createDeviceEnrollmentSetupHandler({ ...common, invitation: legacy }), (error) => error.code === "INVALID_ENROLLMENT_INVITATION");
  const canonical = invitation(device, credential, receiptSigner);
  const { version: _missingVersion, ...missingVersion } = canonical;
  assert.throws(() => createDeviceEnrollmentSetupHandler({ ...common, invitation: missingVersion }), (error) => error.code === "INVALID_ENROLLMENT_INVITATION");
  assert.throws(() => createDeviceEnrollmentSetupHandler({ ...common, invitation: { ...canonical, version: 1 } }), (error) => error.code === "INVALID_ENROLLMENT_INVITATION");
  const credentialed = createDeviceEnrollmentSetupHandler({ ...common, baseUrl: "https://user:pass@api.example.test/v1" });
  await assert.rejects(() => credentialed(context()), (error) => error.code === "INVALID_ENROLLMENT_INVITATION" || error.code === "ERR_DEVICE_ENROLLMENT_URL");
  const wrongPath = createDeviceEnrollmentSetupHandler({ ...common, baseUrl: "https://api.example.test/api" });
  await assert.rejects(() => wrongPath(context()), (error) => error.code === "ERR_DEVICE_ENROLLMENT_URL" || error.code === "INVALID_ENROLLMENT_INVITATION");
});

test("fails before mutation when dispatched outside the enrollment state", async () => {
  const device = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const receiptSigner = crypto.generateKeyPairSync("ed25519");
  const credential = crypto.randomBytes(32).toString("base64url");
  let saved = false;
  const handler = createDeviceEnrollmentSetupHandler({
    ...commonOptions({ device, receiptSigner, credential, fetchImpl: async () => new Response("", { status: 401 }) }),
    saveConfig: () => { saved = true; }
  });
  await assert.rejects(() => handler({ current_state: "device_enrolled", target_state: "editor_connected", action: { id: "connect_editor" } }), /wrong setup state/);
  assert.equal(saved, false);
});
