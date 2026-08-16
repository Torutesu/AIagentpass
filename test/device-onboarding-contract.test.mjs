import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";

import {
  ONBOARDING_INVITATION_DELIVERY_TYPE,
  ONBOARDING_TRUST_INSTALLATION_ACK_TYPE,
  canonicalJson,
  normalizeBundleAcknowledgement,
  normalizeOnboardingInvitationDelivery,
  normalizeOnboardingPreflight,
  normalizeOnboardingTrustInstallationAcknowledgement,
  parseOnboardingInvitationDeliveryJson,
  parseOnboardingPreflightJson,
  parseOnboardingTrustInstallationAcknowledgementJson
} from "../packages/protocol/src/index.mjs";

const fixture = (name) => JSON.parse(fs.readFileSync(new URL(`../contracts/fixtures/${name}`, import.meta.url), "utf8"));
const jsonFixture = (name) => fs.readFileSync(new URL(`../contracts/fixtures/${name}`, import.meta.url));

test("accepts the five browser-led onboarding boundary messages", () => {
  const preflight = parseOnboardingPreflightJson(jsonFixture("device-onboarding-preflight.valid.json"));
  const delivery = parseOnboardingInvitationDeliveryJson(jsonFixture("device-onboarding-invitation-delivery.valid.json"));
  const trustAck = parseOnboardingTrustInstallationAcknowledgementJson(jsonFixture("device-trust-installation-ack.valid.json"));
  const controlAck = normalizeBundleAcknowledgement(fixture("bundle-ack.valid.json"));
  assert.equal(preflight.version, 1);
  assert.equal(delivery.type, ONBOARDING_INVITATION_DELIVERY_TYPE);
  assert.equal(delivery.invitation.proof_version, 2);
  assert.equal(delivery.invitation.endpoint, `/v1/enrollments/${delivery.invitation.enrollment_id}`);
  assert.equal(trustAck.type, ONBOARDING_TRUST_INSTALLATION_ACK_TYPE);
  assert.equal(controlAck.type, "agentpass.bundle-ack");
  assert.equal(delivery.invitation.challenge.nonce, delivery.invitation.nonce);
});

test("normalizes canonical values and keeps authority out of caller-controlled messages", () => {
  const preflight = fixture("device-onboarding-preflight.valid.json");
  const trustAck = fixture("device-trust-installation-ack.valid.json");
  assert.equal(canonicalJson(normalizeOnboardingPreflight(preflight)), canonicalJson(preflight));
  assert.equal(canonicalJson(normalizeOnboardingTrustInstallationAcknowledgement(trustAck)), canonicalJson(trustAck));
  for (const value of [preflight, trustAck]) {
    assert.doesNotMatch(JSON.stringify(value), /authority_generation|authority|private_key|credential|bearer|token/u);
  }
  const delivery = fixture("device-onboarding-invitation-delivery.valid.json");
  assert.equal(new URL(`http://127.0.0.1${delivery.invitation.endpoint}`).pathname, delivery.invitation.endpoint);
  assert.equal(delivery.invitation.endpoint.includes(delivery.invitation.credential), false);
  assert.equal(JSON.stringify({ argv: [], env: {}, url: delivery.invitation.endpoint, storage: null }).includes(delivery.invitation.credential), false);
});

test("fails closed on unknown fields, duplicate keys, and downgrade attempts", () => {
  const preflight = fixture("device-onboarding-preflight.valid.json");
  assert.throws(() => normalizeOnboardingPreflight({ ...preflight, authority_generation: 1 }), /unknown_field/u);
  assert.throws(() => normalizeOnboardingPreflight({ ...preflight, version: 0 }), /invalid_version/u);
  assert.throws(() => parseOnboardingPreflightJson(`{"version":1,"version":0,"platform":"macos","candidate_id":"release","device_key_fingerprint":"SHA256:${"A".repeat(43)}"}`), /duplicate_field/u);

  const delivery = fixture("device-onboarding-invitation-delivery.valid.json");
  assert.throws(() => normalizeOnboardingInvitationDelivery({ ...delivery, type: "caller-selected-authority" }), /invalid_value/u);
  assert.throws(() => parseOnboardingInvitationDeliveryJson(JSON.stringify({ ...delivery, version: 0 })), /invalid_version/u);
  assert.throws(() => normalizeOnboardingInvitationDelivery({
    ...delivery,
    invitation: { ...delivery.invitation, endpoint: "/v1/enrollments/00000000-0000-4000-8000-000000000000" }
  }), /inconsistent_value/u);
  const duplicateInvitation = JSON.stringify(delivery).replace('"invitation":{', '"invitation":{"version":2,"version":1,');
  assert.throws(() => parseOnboardingInvitationDeliveryJson(duplicateInvitation), /duplicate_field/u);

  const trustAck = fixture("device-trust-installation-ack.valid.json");
  assert.throws(() => normalizeOnboardingTrustInstallationAcknowledgement({ ...trustAck, authority_generation: 1 }), /unknown_field/u);
  assert.throws(() => normalizeOnboardingTrustInstallationAcknowledgement({ ...trustAck, version: 0 }), /invalid_version/u);
});
