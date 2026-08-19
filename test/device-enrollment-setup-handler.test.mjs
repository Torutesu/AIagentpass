import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { createDeviceEnrollmentSetupHandler } from "../lib/device-enrollment-setup-handler.mjs";
import { canonicalJson } from "../lib/identity.mjs";
import { DeviceOnboardingResumeStore } from "../lib/device-onboarding-resume.mjs";
import { bundleAcknowledgementSigningData, normalizeOnboardingControlAcknowledgement } from "../packages/protocol/src/index.mjs";

const enrollmentId = "11111111-1111-4111-8111-111111111111";
const organizationId = "22222222-2222-4222-8222-222222222222";
const deviceId = "33333333-3333-4333-8333-333333333333";
const nonce = "A".repeat(43);
const expiresAt = "2099-01-02T03:04:05.000Z";
const controlStatementHash = "d".repeat(64);
const halfOrder = Buffer.from("7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8", "hex");

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

function possessionReceipt(key, receiptSigner, binding, control, refreshHint) {
  const { expires_at: _expiresAt, ...candidate } = binding;
  const statement = {
    ...candidate,
    device_key_epoch: 4,
    challenge_nonce_digest: crypto.createHash("sha256").update(nonce).digest("hex"),
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
    },
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

function signedControlAcknowledgement(device, overrides = {}) {
  const unsigned = {
    version: 1,
    type: "agentpass.bundle-ack",
    organization_id: overrides.organization_id ?? organizationId,
    device_id: overrides.device_id ?? deviceId,
    device_key_epoch: overrides.device_key_epoch ?? 4,
    format_epoch: overrides.format_epoch ?? 2,
    sequence: overrides.sequence ?? 1,
    statement_hash: overrides.statement_hash ?? controlStatementHash,
    result: overrides.result ?? "applied",
    ...(overrides.reason_code === undefined ? {} : { reason_code: overrides.reason_code }),
    observed_at: overrides.observed_at ?? "2026-08-16T00:00:00.000Z",
    nonce: overrides.nonce ?? "EREREREREREREREREREREQ",
    signature_algorithm: "p256-sha256"
  };
  const placeholder = { ...unsigned, signature: Buffer.alloc(64, 1).toString("base64url") };
  for (let attempt = 0; attempt < 128; attempt += 1) {
    const signature = crypto.sign("sha256", bundleAcknowledgementSigningData(placeholder), { key: device.privateKey, dsaEncoding: "ieee-p1363" });
    if (signature.subarray(32).compare(halfOrder) <= 0) return normalizeOnboardingControlAcknowledgement({ ...unsigned, signature: signature.toString("base64url") });
  }
  throw new Error("could not create a canonical low-S Control ACK");
}

function controlRefreshEvidence(device, overrides = {}) {
  return {
    status: "enabled",
    control_refreshed: true,
    control_ack: {
      acknowledgement: overrides.acknowledgement ?? signedControlAcknowledgement(device, overrides),
      server_accepted: overrides.server_accepted ?? true,
      observed_generation: overrides.observed_generation ?? 1,
      refresh_state: overrides.refresh_state ?? "applied"
    }
  };
}

function commonOptions({ device, receiptSigner, credential, fetchImpl, baseUrl = "https://api.example.test/v1" } = {}) {
  return {
    runner: {
      publicKey: () => ({ algorithm: "p256-sha256", spki_pem: device.publicKey.export({ type: "spki", format: "pem" }).toString(), fingerprint: fingerprint(device) }),
      sign: ({ bytes }) => crypto.sign("sha256", bytes, { key: device.privateKey, dsaEncoding: "ieee-p1363" })
    },
    provisionControl: async () => ({ changed: true, old_fingerprint: null, new_fingerprint: `SHA256:${"A".repeat(43)}` }),
    restartService: async () => controlRefreshEvidence(device),
    invitation: invitation(device, credential, receiptSigner),
    baseUrl,
    loadConfig: () => ({ control_v2: { statement_hash: controlStatementHash, authority_generation: 1, sequence: 1 } }),
    saveConfig: () => {},
    fetchImpl
  };
}

function context() {
  return { current_state: "service_keys_activated", target_state: "device_enrolled", operation_id: "setup:test:enroll_device", action: { id: "enroll_device" } };
}

function resumeStore() {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "agentpass-setup-resume-"));
  return { directory, store: new DeviceOnboardingResumeStore(path.join(directory, "resume.json")) };
}

function verifiedResult(device, control, refreshHint, receipt, requestDigest) {
  return {
    status: "enrolled",
    enrollment_id: enrollmentId,
    organization_id: organizationId,
    device_id: deviceId,
    label: "Build Mac",
    platform: "macos",
    device_key: { algorithm: "p256-sha256", spki_pem: device.publicKey.export({ type: "spki", format: "pem" }).toString() },
    key_fingerprint: fingerprint(device),
    request_hash: requestDigest,
    request_id: "request-1",
    device_key_epoch: 4,
    control,
    possession_receipt: receipt,
    evidence: {
      organization_id: organizationId,
      device_id: deviceId,
      enrollment_id: enrollmentId,
      device_key_epoch: 4,
      key_fingerprint: fingerprint(device),
      proof_version: 2,
      candidate_id: "release-2026-08-13-01",
      challenge_nonce_digest: crypto.createHash("sha256").update(nonce).digest("hex"),
      receipt_key_id: receipt.key_id,
      receipt_statement_hash: receipt.statement_hash
    },
    refresh_hint: refreshHint
  };
}

function publicSetupOptions({ device, receiptSigner, credential, resume, fetchImpl, invitationValue, provisionControl, restartService, loadConfig, saveConfig, recoverEnrollment, baseUrl = "https://api.example.test/v1" } = {}) {
  return {
    ...commonOptions({ device, receiptSigner, credential, fetchImpl, baseUrl }),
    invitation: invitationValue ?? invitation(device, credential, receiptSigner),
    resumeStore: resume?.store,
    provisionControl: provisionControl ?? (async () => ({ changed: true, old_fingerprint: null, new_fingerprint: `SHA256:${"A".repeat(43)}` })),
    restartService: restartService ?? (async () => controlRefreshEvidence(device)),
    loadConfig: loadConfig ?? (() => ({ control_v2: { statement_hash: controlStatementHash, authority_generation: 1, sequence: 1 } })),
    saveConfig: saveConfig ?? (() => {}),
    recoverEnrollment
  };
}

async function runFreshControlCase(buildRestart) {
  const device = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const receiptSigner = crypto.generateKeyPairSync("ed25519");
  const control = crypto.generateKeyPairSync("ed25519");
  const refreshHint = crypto.generateKeyPairSync("ed25519");
  const credential = crypto.randomBytes(32).toString("base64url");
  const receipt = possessionReceipt(device, receiptSigner, candidateBinding(device), control, refreshHint);
  let receiptReads = 0;
  const base = commonOptions({
    device,
    receiptSigner,
    credential,
    fetchImpl: async (_url, init) => {
      if (init.method === "GET") {
        receiptReads += 1;
        return receiptReads === 1
          ? new Response("", { status: 401 })
          : new Response(canonicalJson({ request_id: "receipt-1", receipt }), { status: 200, headers: { "content-type": "application/json" } });
      }
      return new Response(canonicalJson(completedResponse(control, refreshHint)), { status: 201, headers: { "content-type": "application/json" } });
    }
  });
  return createDeviceEnrollmentSetupHandler({
    ...base,
    restartService: async () => buildRestart(device),
    loadConfig: () => ({ control_v2: { statement_hash: controlStatementHash, authority_generation: 1, sequence: 1 } })
  })(context());
}

test("uses the v2 invitation, verifies the receipt, and persists only non-secret control trust", async () => {
  const device = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const receiptSigner = crypto.generateKeyPairSync("ed25519");
  const control = crypto.generateKeyPairSync("ed25519");
  const refreshHint = crypto.generateKeyPairSync("ed25519");
  const credential = crypto.randomBytes(32).toString("base64url");
  const receipt = possessionReceipt(device, receiptSigner, candidateBinding(device), control, refreshHint);
  const original = { version: 4, control_v2: { statement_hash: controlStatementHash, authority_generation: 1, sequence: 1 }, native_broker: { enabled: true, mach_service: "dev.agentpass.native-service", client: "/Applications/AgentPass.app/client" } };
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
  assert.throws(() => createDeviceEnrollmentSetupHandler({
    ...common,
    invitation: { ...canonical, endpoint: "/v1/enrollments/00000000-0000-4000-8000-000000000000" }
  }), (error) => error.code === "INVALID_ENROLLMENT_INVITATION");
  const expiredAt = "2020-01-02T03:04:05.000Z";
  assert.throws(() => createDeviceEnrollmentSetupHandler({
    ...common,
    invitation: {
      ...canonical,
      expires_at: expiredAt,
      candidate_binding: { ...canonical.candidate_binding, expires_at: expiredAt },
      challenge: { ...canonical.challenge, expires_at: expiredAt }
    }
  }), (error) => error.code === "INVALID_ENROLLMENT_INVITATION");
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

test("durably records every pre-POST boundary and completes the resumed state machine", async () => {
  const device = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const receiptSigner = crypto.generateKeyPairSync("ed25519");
  const control = crypto.generateKeyPairSync("ed25519");
  const refreshHint = crypto.generateKeyPairSync("ed25519");
  const credential = crypto.randomBytes(32).toString("base64url");
  const receipt = possessionReceipt(device, receiptSigner, candidateBinding(device), control, refreshHint);
  const resume = resumeStore();
  let postCount = 0;
  let stateAtPost;
  let receiptReads = 0;
  let acceptedControlAck;
  const base = commonOptions({
    device,
    receiptSigner,
    credential,
    fetchImpl: async (_url, init) => {
      if (init.method === "GET") {
        receiptReads += 1;
        return receiptReads === 1
          ? new Response("", { status: 401 })
          : new Response(canonicalJson({ request_id: "receipt-1", receipt }), { status: 200, headers: { "content-type": "application/json" } });
      }
      postCount += 1;
      stateAtPost = resume.store.read().state;
      assert.equal(JSON.parse(Buffer.from(init.body).toString("utf8")).proof_version, 2);
      return new Response(canonicalJson(completedResponse(control, refreshHint)), { status: 201, headers: { "content-type": "application/json" } });
    }
  });
  const handler = createDeviceEnrollmentSetupHandler({
    ...base,
    resumeStore: resume.store,
    restartService: async () => {
      const response = controlRefreshEvidence(device);
      acceptedControlAck = response.control_ack;
      return response;
    }
  });
  await handler(context());

  assert.equal(postCount, 1);
  assert.equal(stateAtPost, "enrollment_uncertain");
  assert.equal(resume.store.read().state, "control_acknowledged");
  const exactAck = {
    ...acceptedControlAck.acknowledgement,
    server_accepted: true,
    observed_generation: acceptedControlAck.observed_generation,
    refresh_state: acceptedControlAck.refresh_state
  };
  const expectedAckEvidence = {
    organization_id: organizationId,
    device_id: deviceId,
    enrollment_id: enrollmentId,
    control_url: `https://api.example.test/v1/organizations/${organizationId}/bundles/${deviceId}`,
    public_key: control.publicKey.export({ type: "spki", format: "pem" }).toString(),
    key_id: "control-v1",
    control_ack: exactAck
  };
  const expectedAckEvidenceHash = crypto.createHash("sha256").update(canonicalJson(expectedAckEvidence), "utf8").digest("hex");
  assert.equal(resume.store.read().evidence.control.ack_evidence_hash, expectedAckEvidenceHash);
  const signatureMutation = { ...expectedAckEvidence, control_ack: { ...exactAck, signature: "A".repeat(86) } };
  const nonceMutation = { ...expectedAckEvidence, control_ack: { ...exactAck, nonce: "IiIiIiIiIiIiIiIiIiIiIg" } };
  assert.notEqual(expectedAckEvidenceHash, crypto.createHash("sha256").update(canonicalJson(signatureMutation), "utf8").digest("hex"));
  assert.notEqual(expectedAckEvidenceHash, crypto.createHash("sha256").update(canonicalJson(nonceMutation), "utf8").digest("hex"));
  const journal = JSON.parse(fs.readFileSync(`${resume.store.filePath}.journal`, "utf8"));
  assert.deepEqual(journal.entries.map((entry) => entry.state), ["prepared", "invitation_issued", "delivered", "enrollment_uncertain", "receipt_verified", "trust_installed", "control_acknowledged"]);
  const durable = JSON.stringify(resume.store.read());
  assert.equal(resume.store.read().recovery_descriptor.request_digest.length, 64);
  assert.equal(resume.store.read().recovery_descriptor.challenge_digest, crypto.createHash("sha256").update(nonce).digest("hex"));
  assert.equal(resume.store.read().recovery_descriptor.api_base_url, "https://api.example.test/v1");
  assert.equal(durable.includes(credential), false);
  assert.doesNotMatch(durable, /(?:nonce|signature|private.?key|credential)/iu);
});

test("response loss is interruptible and a fresh run recovers GET-only without POST or secret reuse", async () => {
  const device = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const receiptSigner = crypto.generateKeyPairSync("ed25519");
  const control = crypto.generateKeyPairSync("ed25519");
  const refreshHint = crypto.generateKeyPairSync("ed25519");
  const credential = crypto.randomBytes(32).toString("base64url");
  const receipt = possessionReceipt(device, receiptSigner, candidateBinding(device), control, refreshHint);
  const resume = resumeStore();
  let postCount = 0;
  let firstFetches = 0;
  const base = commonOptions({
    device,
    receiptSigner,
    credential,
    fetchImpl: async (_url, init) => {
      firstFetches += 1;
      if (init.method === "POST") {
        postCount += 1;
        return new Response("{malformed", { status: 201, headers: { "content-type": "application/json" } });
      }
      return new Response("", { status: 401 });
    }
  });
  await assert.rejects(() => createDeviceEnrollmentSetupHandler({ ...base, resumeStore: resume.store })(context()), (error) => error.code === "ERR_DEVICE_ENROLLMENT_RECOVERY_UNPROVEN");
  assert.equal(postCount, 1);
  assert.equal(resume.store.read().state, "enrollment_uncertain");
  assert.equal(firstFetches, 3);

  const requestDigest = resume.store.read().recovery_descriptor.request_digest;
  const recovered = verifiedResult(device, {
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
  }, refreshHint, receipt, requestDigest);
  const rejected = createDeviceEnrollmentSetupHandler({
    runner: base.runner,
    resumeStore: resume.store,
    recoverEnrollment: async () => ({ ...recovered, possession_receipt: undefined }),
    provisionControl: async () => { throw new Error("recovery must not provision unverified trust"); },
    restartService: async () => { throw new Error("recovery must not restart unverified trust"); },
    loadConfig: () => ({ control_v2: { statement_hash: controlStatementHash, authority_generation: 1, sequence: 1 } }),
    saveConfig: () => {}
  });
  await assert.rejects(() => rejected(context()), (error) => error.code === "ENROLLMENT_RECOVERY_UNVERIFIED");
  assert.equal(postCount, 1, "unverified recovery must not replay the enrollment POST");

  let recoveryCalls = 0;
  let saved;
  const runner = base.runner;
  const resumed = createDeviceEnrollmentSetupHandler({
    runner,
    resumeStore: resume.store,
    recoverEnrollment: async (input) => {
      recoveryCalls += 1;
      for (const forbidden of ["credential", "nonce", "signature", "privateKey", "private_key", "challengeNonce", "challenge_nonce"]) assert.equal(Object.hasOwn(input, forbidden), false, `recovery input leaked ${forbidden}`);
      assert.equal(input.recovery_descriptor.request_digest, requestDigest);
      assert.equal(Object.hasOwn(input.recovery_descriptor, "nonce"), false);
      assert.equal(Object.hasOwn(input.recovery_descriptor, "signature"), false);
      return recovered;
    },
    provisionControl: async () => ({ changed: true, old_fingerprint: null, new_fingerprint: `SHA256:${"B".repeat(43)}` }),
    restartService: async () => controlRefreshEvidence(device),
    loadConfig: () => ({ control_v2: { statement_hash: controlStatementHash, authority_generation: 1, sequence: 1 } }),
    saveConfig: (value) => { saved = value; }
  });
  const result = await resumed(context());
  assert.equal(recoveryCalls, 1);
  assert.equal(postCount, 1);
  assert.equal(resume.store.read().state, "control_acknowledged");
  assert.equal(saved.control_v2.url, `https://api.example.test/v1/organizations/${organizationId}/bundles/${deviceId}`);
  const serializedResult = JSON.stringify(result);
  assert.equal(serializedResult.includes(credential), false);
  assert.equal(serializedResult.includes(nonce), false);
  assert.doesNotMatch(serializedResult, /(?:"signature"|private.?key|"credential")/iu);
});

test("advances only with exact server-accepted signed Control ACK evidence", async () => {
  const cases = [
    ["absent evidence", async (device) => ({ status: "enabled", control_refreshed: true }), /server-accepted signed Control ACK/iu],
    ["blocked result", async (device) => controlRefreshEvidence(device, { result: "blocked", reason_code: "bundle_expired" }), /installed ControlBundle expectations/iu],
    ["non-applied server state", async (device) => controlRefreshEvidence(device, { refresh_state: "blocked" }), /accepted for an applied refresh/iu],
    ["wrong organization", async (device) => controlRefreshEvidence(device, { organization_id: "44444444-4444-4444-8444-444444444444" }), /installed ControlBundle expectations/iu],
    ["wrong device", async (device) => controlRefreshEvidence(device, { device_id: "55555555-5555-4555-8555-555555555555" }), /installed ControlBundle expectations/iu],
    ["stale generation", async (device) => controlRefreshEvidence(device, { observed_generation: 0 }), /accepted for an applied refresh/iu],
    ["future generation", async (device) => controlRefreshEvidence(device, { observed_generation: 2 }), /installed ControlBundle expectations/iu],
    ["sequence mismatch", async (device) => controlRefreshEvidence(device, { sequence: 2 }), /installed ControlBundle expectations/iu],
    ["statement hash mismatch", async (device) => controlRefreshEvidence(device, { statement_hash: "e".repeat(64) }), /installed ControlBundle expectations/iu],
    ["unknown evidence field", async (device) => { const evidence = controlRefreshEvidence(device); return { ...evidence, control_ack: { ...evidence.control_ack, extra: true } }; }, /unknown or missing fields/iu],
    ["unknown signed ACK field", async (device) => controlRefreshEvidence(device, { acknowledgement: { ...signedControlAcknowledgement(device), extra: true } }), /signed evidence is invalid/iu]
  ];
  for (const [label, buildRestart, message] of cases) {
    await assert.rejects(() => runFreshControlCase(buildRestart), (error) => error.code === "CONTROL_RECONCILIATION_FAILED" && message.test(error.message), label);
  }
  const result = await runFreshControlCase((device) => controlRefreshEvidence(device));
  assert.equal(result.evidence.proof.proof_version, 2, "the exact evidence shape remains completable");
});

test("fails closed when a durable descriptor is incomplete or bound to another device", async () => {
  const device = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const otherDevice = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const receiptSigner = crypto.generateKeyPairSync("ed25519");
  const binding = candidateBinding(device);
  const descriptor = {
    enrollment_id: enrollmentId,
    label: "Build Mac",
    platform: "macos",
    api_base_url: "https://api.example.test/v1",
    candidate_binding: binding,
    challenge_digest: crypto.createHash("sha256").update(nonce).digest("hex"),
    request_digest: "c".repeat(64),
    verification_key_id: "receipt-key-v1",
    verification_algorithm: "ed25519",
    verification_public_key: receiptSigner.publicKey.export({ type: "spki", format: "pem" }).toString()
  };
  const methods = {
    read: () => ({ state: "enrollment_uncertain", release_id: binding.candidate_id, organization_id: organizationId, device_id: deviceId, recovery_descriptor: { ...descriptor, request_digest: undefined } }),
    create_prepared: () => { throw new Error("unexpected mutation"); },
    issue_invitation: () => { throw new Error("unexpected mutation"); },
    record_delivery: () => { throw new Error("unexpected mutation"); },
    mark_enrollment_uncertain: () => { throw new Error("unexpected mutation"); },
    reconcile_enrollment: () => { throw new Error("unexpected mutation"); },
    install_trust: () => { throw new Error("unexpected mutation"); },
    acknowledge_control: () => { throw new Error("unexpected mutation"); }
  };
  const common = commonOptions({ device: otherDevice, receiptSigner, credential: crypto.randomBytes(32).toString("base64url"), fetchImpl: async () => { throw new Error("unexpected network"); } });
  await assert.rejects(() => createDeviceEnrollmentSetupHandler({ ...common, invitation: undefined, resumeStore: methods })(context()), (error) => error.code === "RESUME_BINDING_MISMATCH");
});
