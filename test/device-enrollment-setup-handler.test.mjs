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
  const publicPem = device.publicKey.export({ type: "spki", format: "pem" }).toString();
  const fingerprint = `SHA256:${crypto.createHash("sha256").update(device.publicKey.export({ type: "spki", format: "der" })).digest("base64url")}`;
  const credential = crypto.randomBytes(32).toString("base64url");
  const original = { version: 4, native_broker: { enabled: true, mach_service: "dev.agentpass.native-service", client: "/Applications/AgentPass.app/client" } };
  let saved;
  const handler = createDeviceEnrollmentSetupHandler({
    runner: {
      publicKey: () => ({ algorithm: "p256-sha256", spki_pem: publicPem, fingerprint }),
      sign: ({ bytes }) => crypto.sign("sha256", bytes, { key: device.privateKey, dsaEncoding: "ieee-p1363" })
    },
    invitation: { enrollment_id: enrollmentId, organization_id: organizationId, device_id: deviceId, label: "Build Mac", credential },
    baseUrl: "https://api.example.test/v1",
    loadConfig: () => original,
    saveConfig: (value) => { saved = value; },
    fetchImpl: async (_url, init) => {
      assert.equal(init.headers["AgentPass-Enrollment-Credential"], credential);
      return new Response(canonicalJson({ request_id: "request-1", enrollment: { version: 1, enrollment_id: enrollmentId, organization_id: organizationId, device_id: deviceId, status: "active", key_algorithm: "p256-sha256", control: { format_epoch: 2, issuer: "agentpass-cloud", key_id: "control-v1", public_key: control.publicKey.export({ type: "spki", format: "pem" }).toString(), bundle_path: `/v1/organizations/${organizationId}/bundles/${deviceId}` } } }), { status: 201, headers: { "content-type": "application/json" } });
    }
  });
  const context = { current_state: "service_keys_activated", target_state: "device_enrolled", operation_id: "setup:test:8:enroll_device", action: { id: "enroll_device" } };
  const result = await handler(context);
  assert.deepEqual(result.evidence.proof, { organization_id: organizationId, device_id: deviceId, enrollment_id: enrollmentId, key_fingerprint: fingerprint });
  assert.equal(saved.control_v2.required, true);
  assert.equal(saved.control_v2.capability_required, true);
  assert.equal(saved.control_v2.url, `https://api.example.test/v1/organizations/${organizationId}/bundles/${deviceId}`);
  assert.equal(saved.native_broker.control_url, saved.control_v2.url);
  assert.equal(JSON.stringify(saved).includes(credential), false);
  assert.equal(JSON.stringify(result).includes(credential), false);
});

test("fails before mutation when dispatched outside the enrollment state", async () => {
  let saved = false;
  const handler = createDeviceEnrollmentSetupHandler({ runner: { publicKey() {}, sign() {} }, invitation: {}, baseUrl: "https://api.example.test/v1", loadConfig: () => ({}), saveConfig: () => { saved = true; } });
  await assert.rejects(() => handler({ current_state: "device_enrolled", target_state: "editor_connected", action: { id: "connect_editor" } }), /wrong setup state/);
  assert.equal(saved, false);
});
