import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import { createDeviceEnrollmentSetupHandler } from "../lib/device-enrollment-setup-handler.mjs";
import { canonicalJson } from "../lib/identity.mjs";

const enrollmentId = "11111111-1111-4111-8111-111111111111";
const organizationId = "22222222-2222-4222-8222-222222222222";
const deviceId = "33333333-3333-4333-8333-333333333333";

test("enrolls with native proof and persists only non-secret pinned control trust", async () => {
  const device = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const control = crypto.generateKeyPairSync("ed25519");
  const refreshHint = crypto.generateKeyPairSync("ed25519");
  const publicPem = device.publicKey.export({ type: "spki", format: "pem" }).toString();
  const fingerprint = `SHA256:${crypto.createHash("sha256").update(device.publicKey.export({ type: "spki", format: "der" })).digest("base64url")}`;
  const credential = crypto.randomBytes(32).toString("base64url");
  const original = { version: 4, native_broker: { enabled: true, mach_service: "dev.agentpass.native-service", client: "/Applications/AgentPass.app/client" } };
  let saved;
  let provisioned;
  const handler = createDeviceEnrollmentSetupHandler({
    runner: {
      publicKey: () => ({ algorithm: "p256-sha256", spki_pem: publicPem, fingerprint }),
      sign: ({ bytes }) => crypto.sign("sha256", bytes, { key: device.privateKey, dsaEncoding: "ieee-p1363" })
    },
    provisionControl: async (value) => { provisioned = value; return { changed: true, old_fingerprint: null, new_fingerprint: `SHA256:${"A".repeat(43)}` }; },
    restartService: async () => ({ status: "enabled", control_refreshed: true }),
    invitation: { enrollment_id: enrollmentId, organization_id: organizationId, device_id: deviceId, label: "Build Mac", credential },
    baseUrl: "https://api.example.test/v1",
    loadConfig: () => original,
    saveConfig: (value) => { saved = value; },
    fetchImpl: async (_url, init) => {
      assert.equal(init.headers["AgentPass-Enrollment-Credential"], credential);
      return new Response(canonicalJson({ request_id: "request-1", enrollment: { version: 1, enrollment_id: enrollmentId, organization_id: organizationId, device_id: deviceId, status: "active", key_algorithm: "p256-sha256", device_key_epoch: 4, control: { format_epoch: 2, issuer: "agentpass-cloud", key_id: "control-v1", public_key: control.publicKey.export({ type: "spki", format: "pem" }).toString(), bundle_path: `/v1/organizations/${organizationId}/bundles/${deviceId}`, refresh_hint: { key_id: "refresh-hint-v1", algorithm: "ed25519", public_key: refreshHint.publicKey.export({ type: "spki", format: "pem" }).toString() } } } }), { status: 201, headers: { "content-type": "application/json" } });
    }
  });
  const context = { current_state: "service_keys_activated", target_state: "device_enrolled", operation_id: "setup:test:8:enroll_device", action: { id: "enroll_device" } };
  const result = await handler(context);
  assert.deepEqual(result.evidence.proof, { organization_id: organizationId, device_id: deviceId, enrollment_id: enrollmentId, device_key_epoch: 4, key_fingerprint: fingerprint });
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

test("derives the API base from validated URL components and rejects credentialed bases", async () => {
  const device = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const control = crypto.generateKeyPairSync("ed25519");
  const refreshHint = crypto.generateKeyPairSync("ed25519");
  const publicPem = device.publicKey.export({ type: "spki", format: "pem" }).toString();
  const fingerprint = `SHA256:${crypto.createHash("sha256").update(device.publicKey.export({ type: "spki", format: "der" })).digest("base64url")}`;
  const credential = crypto.randomBytes(32).toString("base64url");
  const payload = {
    request_id: "request-2",
    enrollment: {
      version: 1, enrollment_id: enrollmentId, organization_id: organizationId, device_id: deviceId,
      status: "active", key_algorithm: "p256-sha256", device_key_epoch: 4,
      control: {
        format_epoch: 2, issuer: "agentpass-cloud", key_id: "control-v1",
        public_key: control.publicKey.export({ type: "spki", format: "pem" }).toString(),
        bundle_path: `/v1/organizations/${organizationId}/bundles/${deviceId}`,
        refresh_hint: { key_id: "refresh-hint-v1", algorithm: "ed25519", public_key: refreshHint.publicKey.export({ type: "spki", format: "pem" }).toString() }
      }
    }
  };
  const response = () => new Response(canonicalJson(payload), { status: 201, headers: { "content-type": "application/json" } });
  const common = {
    runner: { publicKey: () => ({ algorithm: "p256-sha256", spki_pem: publicPem, fingerprint }), sign: ({ bytes }) => crypto.sign("sha256", bytes, { key: device.privateKey, dsaEncoding: "ieee-p1363" }) },
    provisionControl: async () => ({ new_fingerprint: `SHA256:${"B".repeat(43)}` }),
    restartService: async () => ({ status: "enabled", control_refreshed: true }),
    invitation: { enrollment_id: enrollmentId, organization_id: organizationId, device_id: deviceId, label: "Build Mac", credential },
    loadConfig: () => ({}), saveConfig: () => {}, fetchImpl: async () => response()
  };
  await assert.rejects(() => createDeviceEnrollmentSetupHandler({ ...common, baseUrl: "https://user:pass@api.example.test/v1" })({ current_state: "service_keys_activated", target_state: "device_enrolled", operation_id: "setup:test:9:enroll_device", action: { id: "enroll_device" } }), /credentials/);
  await assert.rejects(() => createDeviceEnrollmentSetupHandler({ ...common, baseUrl: "https://api.example.test/api" })({ current_state: "service_keys_activated", target_state: "device_enrolled", operation_id: "setup:test:10:enroll_device", action: { id: "enroll_device" } }), /end at \/v1/);
});

test("fails before mutation when dispatched outside the enrollment state", async () => {
  let saved = false;
  const handler = createDeviceEnrollmentSetupHandler({ runner: { publicKey() {}, sign() {} }, provisionControl() {}, restartService() {}, invitation: {}, baseUrl: "https://api.example.test/v1", loadConfig: () => ({}), saveConfig: () => { saved = true; } });
  await assert.rejects(() => handler({ current_state: "device_enrolled", target_state: "editor_connected", action: { id: "connect_editor" } }), /wrong setup state/);
  assert.equal(saved, false);
});
