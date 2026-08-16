import crypto from "node:crypto";

import { buildCloudControlConfigFragment } from "./cloud-control.mjs";
import { createDeviceEnrollmentClient, recoverDeviceEnrollment } from "./device-enrollment-client.mjs";
import { canonicalJson } from "./identity.mjs";
import {
  bundleAcknowledgementSigningData,
  normalizeOnboardingControlAcknowledgement,
  normalizeOnboardingInvitation
} from "../packages/protocol/src/index.mjs";

const HASH = /^[0-9a-f]{64}$/u;
const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;
const FINGERPRINT = /^SHA256:[A-Za-z0-9_-]{43}$/u;
const RFC3339_UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u;
const RESUME_SOURCE = "agentpass-device-onboarding";
const CONTROL_ACK_KEYS = new Set(["acknowledgement", "server_accepted", "observed_generation", "refresh_state"]);
const CONTROL_ACK_STATES = new Set(["applied"]);
const RECOVERY_DESCRIPTOR_KEYS = new Set([
  "enrollment_id", "label", "platform", "api_base_url", "candidate_binding", "challenge_digest",
  "request_digest", "verification_key_id", "verification_algorithm", "verification_public_key"
]);
const CANDIDATE_BINDING_KEYS = new Set([
  "version", "enrollment_id", "organization_id", "device_id", "candidate_id", "artifact_sha256",
  "source_commit", "team_id", "device_key_fingerprint", "expires_at"
]);

function fail(code, message) { const error = new Error(message); error.code = code; throw error; }
function object(value) { return value !== null && typeof value === "object" && !Array.isArray(value); }
function hash(value) { return crypto.createHash("sha256").update(canonicalJson(value), "utf8").digest("hex"); }
function hashBytes(value) { return crypto.createHash("sha256").update(value).digest("hex"); }
function clone(value) { return value === undefined ? undefined : JSON.parse(JSON.stringify(value)); }

function strictV2Invitation(value) {
  try {
    const normalized = normalizeOnboardingInvitation(value);
    if (Date.parse(normalized.expires_at) <= Date.now()) fail("INVALID_ENROLLMENT_INVITATION", "The browser-led onboarding invitation has expired");
    return normalized;
  }
  catch { fail("INVALID_ENROLLMENT_INVITATION", "The browser-led onboarding invitation is invalid"); }
}

function credentialFreeApiBaseUrl(baseUrl, loopbackTestMode = false) {
  let base;
  try { base = new URL(baseUrl); } catch { fail("INVALID_ENROLLMENT_INVITATION", "Enrollment base URL is invalid"); }
  const hostname = base.hostname.replace(/^\[|\]$/g, "");
  if (base.protocol !== "https:" && !(loopbackTestMode && base.protocol === "http:" && ["localhost", "127.0.0.1", "::1"].includes(hostname))) fail("INVALID_ENROLLMENT_INVITATION", "Enrollment requires HTTPS");
  if (!hostname || hostname !== hostname.toLowerCase() || base.username || base.password || base.search || base.hash || !/^\/v1\/?$/u.test(base.pathname)) fail("INVALID_ENROLLMENT_INVITATION", "Enrollment base URL must be a credential-free /v1 API base");
  base.pathname = "/v1";
  base.search = "";
  base.hash = "";
  return base.toString();
}

function bundleUrl(baseUrl, bundlePath, organizationId, deviceId, loopbackTestMode = false) {
  const apiBase = new URL(credentialFreeApiBaseUrl(baseUrl, loopbackTestMode));
  const expectedPath = `/v1/organizations/${organizationId}/bundles/${deviceId}`;
  if (bundlePath !== expectedPath) fail("INVALID_ENROLLMENT_RESPONSE", "Control bundle path is not bound to this device");
  return new URL(bundlePath, `${apiBase.origin}/`).toString();
}

function evidence(context, proof) {
  return { evidence: { version: 1, from_state: context.current_state, to_state: context.target_state, action: context.action.id, operation_id: context.operation_id, outcome: "completed", proof } };
}

function publicKey(runner) {
  const key = runner.publicKey();
  if (!object(key) || typeof key.algorithm !== "string" || typeof key.spki_pem !== "string" || typeof key.fingerprint !== "string" || !FINGERPRINT.test(key.fingerprint)) fail("INVALID_ENROLLMENT_RUNNER", "Native enrollment runner returned an invalid public key");
  return Object.freeze({ algorithm: key.algorithm, spki_pem: key.spki_pem, fingerprint: key.fingerprint });
}

function assertCandidateBinding(binding, expected = {}) {
  if (!object(binding) || Object.keys(binding).length !== CANDIDATE_BINDING_KEYS.size || Object.keys(binding).some((key) => !CANDIDATE_BINDING_KEYS.has(key))) fail("RESUME_BINDING_MISMATCH", "Recovery candidate binding is invalid");
  for (const key of ["enrollment_id", "organization_id", "device_id", "candidate_id", "artifact_sha256", "source_commit", "team_id", "device_key_fingerprint", "expires_at"]) {
    if (typeof binding[key] !== "string" || binding[key].length === 0) fail("RESUME_BINDING_MISMATCH", "Recovery candidate binding is invalid");
  }
  if (binding.version !== 1 || !HASH.test(binding.artifact_sha256) || !/^[0-9a-f]{40}$/u.test(binding.source_commit) || !/^[A-Z0-9]{10}$/u.test(binding.team_id) || !FINGERPRINT.test(binding.device_key_fingerprint) || !RFC3339_UTC.test(binding.expires_at)) fail("RESUME_BINDING_MISMATCH", "Recovery candidate binding is invalid");
  for (const [key, value] of Object.entries(expected)) if (value !== undefined && binding[key] !== value) fail("RESUME_BINDING_MISMATCH", "Recovery candidate binding does not match the native device");
  return binding;
}

function validateRecoveryDescriptor(value, expected = {}) {
  if (!object(value) || Object.keys(value).length !== RECOVERY_DESCRIPTOR_KEYS.size || Object.keys(value).some((key) => !RECOVERY_DESCRIPTOR_KEYS.has(key))) fail("RESUME_BINDING_MISMATCH", "Recovery descriptor is invalid");
  if (typeof value.enrollment_id !== "string" || typeof value.label !== "string" || typeof value.platform !== "string" || typeof value.api_base_url !== "string" || typeof value.verification_key_id !== "string" || typeof value.verification_algorithm !== "string" || typeof value.verification_public_key !== "string" || !HASH.test(value.challenge_digest) || !HASH.test(value.request_digest)) fail("RESUME_BINDING_MISMATCH", "Recovery descriptor is invalid");
  if (!SAFE_ID.test(value.enrollment_id) || !SAFE_ID.test(value.verification_key_id) || value.verification_algorithm !== "ed25519" || /[\u0000-\u001f\u007f]/u.test(value.label) || /PRIVATE\s+KEY/iu.test(value.verification_public_key) || /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/u.test(value.verification_public_key) || Buffer.byteLength(value.verification_public_key, "utf8") > 8192) fail("RESUME_BINDING_MISMATCH", "Recovery descriptor is invalid");
  let verificationKey;
  try { verificationKey = crypto.createPublicKey(value.verification_public_key); } catch { fail("RESUME_BINDING_MISMATCH", "Recovery descriptor verification key is invalid"); }
  if (verificationKey.type !== "public" || verificationKey.asymmetricKeyType !== "ed25519" || verificationKey.export({ type: "spki", format: "pem" }).toString() !== value.verification_public_key) fail("RESUME_BINDING_MISMATCH", "Recovery descriptor verification key is not canonical");
  const binding = assertCandidateBinding(value.candidate_binding, expected);
  if (value.enrollment_id !== binding.enrollment_id || expected.organization_id !== undefined && binding.organization_id !== expected.organization_id || expected.device_id !== undefined && binding.device_id !== expected.device_id) fail("RESUME_BINDING_MISMATCH", "Recovery descriptor identity does not match the resume binding");
  const apiBase = credentialFreeApiBaseUrl(value.api_base_url, expected.loopbackTestMode === true);
  return Object.freeze({ ...clone(value), api_base_url: apiBase, candidate_binding: Object.freeze({ ...clone(binding) }) });
}

function descriptorFromInvitation(invitation, baseUrl, loopbackTestMode, requestDigest) {
  const apiBaseURL = credentialFreeApiBaseUrl(baseUrl, loopbackTestMode);
  return validateRecoveryDescriptor({
    enrollment_id: invitation.enrollment_id,
    label: invitation.label,
    platform: invitation.platform,
    api_base_url: apiBaseURL,
    candidate_binding: invitation.candidate_binding,
    challenge_digest: hashBytes(Buffer.from(invitation.nonce, "utf8")),
    request_digest: requestDigest,
    verification_key_id: invitation.possession_receipt_verification.key_id,
    verification_algorithm: invitation.possession_receipt_verification.algorithm,
    verification_public_key: invitation.possession_receipt_verification.public_key
  }, { organization_id: invitation.organization_id, device_id: invitation.device_id, candidate_id: invitation.candidate_binding.candidate_id });
}

function assertDescriptorMatchesInvitation(descriptor, invitation, baseUrl, loopbackTestMode, requestDigest) {
  const expected = descriptorFromInvitation(invitation, baseUrl, loopbackTestMode, requestDigest);
  if (canonicalJson(descriptor) !== canonicalJson(expected)) fail("RESUME_BINDING_MISMATCH", "The invitation does not match the durable recovery descriptor");
}

function assertResumeStore(store) {
  if (!object(store)) fail("INVALID_RESUME_STORE", "A resume store must be an object");
  for (const method of ["read", "create_prepared", "issue_invitation", "record_delivery", "mark_enrollment_uncertain", "reconcile_enrollment", "install_trust", "acknowledge_control"]) {
    if (typeof store[method] !== "function") fail("INVALID_RESUME_STORE", `Resume store is missing ${method}`);
  }
}

function notInitialized(error) { return error?.code === "NOT_INITIALIZED"; }

function publicProof(result, descriptor, key) {
  if (!object(result) || result.status !== "enrolled" || result.enrollment_id !== descriptor.enrollment_id || result.organization_id !== descriptor.candidate_binding.organization_id || result.device_id !== descriptor.candidate_binding.device_id || result.key_fingerprint !== key.fingerprint || !Number.isSafeInteger(result.device_key_epoch) || result.device_key_epoch < 1 || !object(result.control) || !object(result.evidence)) fail("ENROLLMENT_RECOVERY_UNVERIFIED", "Enrollment recovery did not return a verified bound result");
  const required = ["proof_version", "candidate_id", "challenge_nonce_digest", "receipt_key_id", "receipt_statement_hash"];
  if (required.some((field) => result.evidence[field] === undefined) || result.evidence.proof_version !== 2 || result.evidence.candidate_id !== descriptor.candidate_binding.candidate_id || result.evidence.challenge_nonce_digest !== descriptor.challenge_digest || result.evidence.receipt_key_id !== descriptor.verification_key_id || !HASH.test(result.evidence.receipt_statement_hash)) fail("ENROLLMENT_RECOVERY_UNVERIFIED", "Enrollment recovery proof is incomplete or mismatched");
  const expectedPath = `/v1/organizations/${descriptor.candidate_binding.organization_id}/bundles/${descriptor.candidate_binding.device_id}`;
  if (result.control.bundle_path !== expectedPath || result.control.format_epoch !== 2 || typeof result.control.issuer !== "string" || typeof result.control.key_id !== "string" || typeof result.control.public_key !== "string" || !object(result.control.refresh_hint)) fail("ENROLLMENT_RECOVERY_UNVERIFIED", "Enrollment control trust is not bound to the device");
  return Object.freeze({
    organization_id: result.organization_id,
    device_id: result.device_id,
    enrollment_id: result.enrollment_id,
    device_key_epoch: result.device_key_epoch,
    key_fingerprint: result.key_fingerprint,
    proof_version: 2,
    candidate_id: result.evidence.candidate_id,
    challenge_nonce_digest: result.evidence.challenge_nonce_digest,
    receipt_key_id: result.evidence.receipt_key_id,
    receipt_statement_hash: result.evidence.receipt_statement_hash
  });
}

function authorityResult(result, descriptor, proof) {
  const receiptId = `receipt-${proof.receipt_statement_hash}`;
  const authorityRecordId = typeof result.request_id === "string" && SAFE_ID.test(result.request_id) ? result.request_id : `enrollment-${descriptor.enrollment_id}`;
  return {
    status: "found",
    binding: { source: RESUME_SOURCE, release_id: descriptor.candidate_binding.candidate_id, organization_id: descriptor.candidate_binding.organization_id, device_id: descriptor.candidate_binding.device_id },
    authority_record_id: authorityRecordId,
    enrollment_id: descriptor.enrollment_id,
    receipt_id: receiptId,
    receipt_statement_hash: proof.receipt_statement_hash,
    authority_evidence_hash: hash({ proof, control: result.control }),
    observed_at: new Date().toISOString()
  };
}

function deliveryEvidence(descriptor) {
  const deliveryId = `delivery-${descriptor.enrollment_id}`;
  return { delivery_id: deliveryId, delivery_hash: hash({ descriptor }), delivered_at: undefined };
}

function attemptEvidence(descriptor, key) {
  const attemptId = `attempt-${descriptor.enrollment_id}`;
  return { attempt_id: attemptId, attempt_hash: hash({ descriptor, device_key_fingerprint: key.fingerprint }), uncertain_at: undefined };
}

function invitationEvidence(invitation, descriptor) {
  return { invitation_id: descriptor.enrollment_id, invitation_hash: hash(invitation), issued_at: undefined };
}

function trustEvidence(provisioned, result, controlURL) {
  const publicValue = {
    changed: provisioned.changed === true,
    old_fingerprint: typeof provisioned.old_fingerprint === "string" ? provisioned.old_fingerprint : null,
    new_fingerprint: provisioned.new_fingerprint,
    control_url: controlURL,
    device_key_epoch: result.device_key_epoch,
    issuer: result.control.issuer,
    key_id: result.control.key_id,
    refresh_hint: result.control.refresh_hint
  };
  if (typeof publicValue.new_fingerprint !== "string") fail("CONTROL_PROVISIONING_FAILED", "Native ControlBundle v2 trust did not return a public fingerprint");
  return { trust_receipt_id: `trust-${hash(publicValue)}`, trust_evidence_hash: hash(publicValue), installed_at: undefined };
}

function controlEvidence(result, controlURL, acknowledgement) {
  const { ack_evidence_hash: _validatedEvidenceHash, ...exactAcknowledgement } = acknowledgement;
  const publicValue = {
    organization_id: result.organization_id,
    device_id: result.device_id,
    enrollment_id: result.enrollment_id,
    control_url: controlURL,
    public_key: result.control.public_key,
    key_id: result.control.key_id,
    control_ack: exactAcknowledgement
  };
  return { ack_id: `ack-${result.enrollment_id}`, ack_evidence_hash: hash(publicValue), acknowledged_at: undefined };
}

function publicControlExpectation(result, current, reconciled) {
  const configured = object(current?.control_v2) ? current.control_v2 : {};
  const native = object(reconciled?.installed_control) ? reconciled.installed_control : {};
  const statementHash = [
    result.control?.statement_hash,
    configured.statement_hash,
    configured.control_statement_hash,
    native.statement_hash,
    native.control_statement_hash,
    reconciled?.control_statement_hash
  ].find((value) => value !== undefined);
  if (typeof statementHash !== "string" || !HASH.test(statementHash)) fail("CONTROL_RECONCILIATION_FAILED", "Installed ControlBundle statement hash evidence is missing");
  const generation = [
    result.control?.authority_generation,
    configured.authority_generation,
    native.authority_generation,
    reconciled?.refresh_generation
  ].find((value) => value !== undefined);
  const sequence = [
    result.control?.sequence,
    configured.sequence,
    native.sequence,
    reconciled?.refresh_sequence
  ].find((value) => value !== undefined);
  if (!Number.isSafeInteger(generation) || generation < 1) fail("CONTROL_RECONCILIATION_FAILED", "Installed ControlBundle authority generation evidence is missing");
  if (!Number.isSafeInteger(sequence) || sequence < 1) fail("CONTROL_RECONCILIATION_FAILED", "Installed ControlBundle sequence evidence is missing");
  return Object.freeze({
    statement_hash: statementHash,
    authority_generation: generation,
    sequence
  });
}

function validateControlAcknowledgement(reconciled, result, key, current) {
  if (!object(reconciled) || reconciled.status !== "enabled" || reconciled.control_refreshed !== true || !object(reconciled.control_ack)) fail("CONTROL_RECONCILIATION_FAILED", "Native service did not return a server-accepted signed Control ACK");
  const evidence = reconciled.control_ack;
  if (Object.keys(evidence).length !== CONTROL_ACK_KEYS.size || Object.keys(evidence).some((field) => !CONTROL_ACK_KEYS.has(field))) fail("CONTROL_RECONCILIATION_FAILED", "Control ACK evidence contains unknown or missing fields");
  if (evidence.server_accepted !== true || !CONTROL_ACK_STATES.has(evidence.refresh_state) || !Number.isSafeInteger(evidence.observed_generation) || evidence.observed_generation < 1) fail("CONTROL_RECONCILIATION_FAILED", "Control ACK was not accepted for an applied refresh");

  let acknowledgement;
  try { acknowledgement = normalizeOnboardingControlAcknowledgement(evidence.acknowledgement); }
  catch { fail("CONTROL_RECONCILIATION_FAILED", "Control ACK signed evidence is invalid"); }
  const expected = publicControlExpectation(result, current, reconciled);
  if (acknowledgement.organization_id !== result.organization_id || acknowledgement.device_id !== result.device_id || acknowledgement.device_key_epoch !== result.device_key_epoch || acknowledgement.format_epoch !== result.control.format_epoch || acknowledgement.result !== "applied" || acknowledgement.statement_hash !== expected.statement_hash || acknowledgement.sequence !== expected.sequence || evidence.observed_generation !== expected.authority_generation) fail("CONTROL_RECONCILIATION_FAILED", "Control ACK does not match the installed ControlBundle expectations");
  let verified = false;
  try {
    verified = crypto.verify("sha256", bundleAcknowledgementSigningData(acknowledgement), { key: key.spki_pem, dsaEncoding: "ieee-p1363" }, Buffer.from(acknowledgement.signature, "base64url"));
  } catch { verified = false; }
  if (!verified) fail("CONTROL_RECONCILIATION_FAILED", "Control ACK signature is not bound to the enrolled device");
  return Object.freeze({
    ...acknowledgement,
    server_accepted: true,
    observed_generation: evidence.observed_generation,
    refresh_state: evidence.refresh_state,
    ack_evidence_hash: hash({ acknowledgement, server_accepted: true, observed_generation: evidence.observed_generation, refresh_state: evidence.refresh_state })
  });
}

function configForResult(result, baseUrl, loopbackTestMode) {
  const controlV2APIBaseURL = credentialFreeApiBaseUrl(baseUrl, loopbackTestMode);
  const controlURL = bundleUrl(controlV2APIBaseURL, result.control.bundle_path, result.organization_id, result.device_id, loopbackTestMode);
  const fragment = buildCloudControlConfigFragment({ organization_id: result.organization_id, device_id: result.device_id, issuer: result.control.issuer, key_id: result.control.key_id, public_key: result.control.public_key, url: controlURL, refresh_seconds: 60, allow_offline: false, loopbackTestMode });
  return { controlV2APIBaseURL, controlURL, fragment };
}

function makeEnrollmentClient(invitation, key, options) {
  const receiptPublicKey = options.possessionReceiptPublicKey ?? options.possession_receipt_public_key ?? invitation.possession_receipt_verification.public_key;
  const receiptKeyId = options.possessionReceiptKeyId ?? options.possession_receipt_key_id ?? invitation.possession_receipt_verification.key_id;
  return createDeviceEnrollmentClient({
    proofVersion: 2,
    requireV2: true,
    qualification: "p256-sha256",
    baseUrl: options.baseUrl,
    enrollmentId: invitation.enrollment_id,
    organizationId: invitation.organization_id,
    deviceId: invitation.device_id,
    label: invitation.label,
    credential: invitation.credential,
    candidateBinding: invitation.candidate_binding,
    challengeId: invitation.challenge_id,
    challengeNonce: invitation.nonce,
    possessionReceiptPublicKey: receiptPublicKey,
    possessionReceiptKeyId: receiptKeyId,
    deviceKey: { algorithm: key.algorithm, spki_pem: key.spki_pem },
    keyFingerprint: key.fingerprint,
    signer: ({ bytes }) => options.runner.sign({ bytes }),
    fetchImpl: options.fetchImpl,
    loopbackTestMode: options.loopbackTestMode
  });
}

function recoveryInput(descriptor, key, runner, options) {
  const signer = ({ bytes }) => runner.sign({ bytes });
  return {
    descriptor: clone(descriptor),
    recovery_descriptor: clone(descriptor),
    baseUrl: descriptor.api_base_url,
    enrollmentId: descriptor.enrollment_id,
    organizationId: descriptor.candidate_binding.organization_id,
    deviceId: descriptor.candidate_binding.device_id,
    label: descriptor.label,
    deviceKey: { algorithm: key.algorithm, spki_pem: key.spki_pem },
    keyFingerprint: key.fingerprint,
    candidateBinding: clone(descriptor.candidate_binding),
    challengeNonceDigest: descriptor.challenge_digest,
    requestDigest: descriptor.request_digest,
    possessionReceiptPublicKey: descriptor.verification_public_key,
    possessionReceiptKeyId: descriptor.verification_key_id,
    verificationAlgorithm: descriptor.verification_algorithm,
    signer,
    fetchImpl: options.fetchImpl,
    loopbackTestMode: options.loopbackTestMode
  };
}

async function recoverBoundResult(descriptor, key, runner, options) {
  const input = recoveryInput(descriptor, key, runner, options);
  const value = options.recoverEnrollment
    ? await options.recoverEnrollment(input)
    : await recoverDeviceEnrollment({ baseUrl: input.baseUrl, enrollmentId: input.enrollmentId, organizationId: input.organizationId, deviceId: input.deviceId, label: input.label, deviceKey: input.deviceKey, keyFingerprint: input.keyFingerprint, candidateBinding: input.candidateBinding, challengeNonceDigest: input.challengeNonceDigest, requestDigest: input.requestDigest, possessionReceiptPublicKey: input.possessionReceiptPublicKey, possessionReceiptKeyId: input.possessionReceiptKeyId, verificationAlgorithm: input.verificationAlgorithm, signer: input.signer, fetchImpl: input.fetchImpl, loopbackTestMode: input.loopbackTestMode });
  if (value === null || value?.status === "not_found") return null;
  return { result: value?.result ?? value, proof: publicProof(value?.result ?? value, descriptor, key) };
}

function noRecovery(code = "RECOVERY_UNAVAILABLE") { fail(code, "A GET-only enrollment recovery function is required to continue without the invitation"); }

/**
 * Bind a one-time invitation to the fixed native Secure Enclave key. With a
 * resume store, every durable boundary is written before the next side effect.
 * The only code path that can send the one-time POST is the same invocation
 * that created the prepared record; every later invocation uses GET-only
 * signed receipt recovery.
 */
export function createDeviceEnrollmentSetupHandler(options = {}) {
  const { runner, provisionControl, restartService, invitation, baseUrl, loadConfig, saveConfig, resumeStore } = options;
  if (!runner || typeof runner.publicKey !== "function" || typeof runner.sign !== "function") fail("INVALID_ENROLLMENT_RUNNER", "A native enrollment runner is required");
  if (typeof provisionControl !== "function" || typeof restartService !== "function" || typeof loadConfig !== "function" || typeof saveConfig !== "function") fail("INVALID_ENROLLMENT_INVITATION", "A bounded enrollment invitation, privileged control provisioner, service reconciler, and config adapter are required");
  if (resumeStore !== undefined) assertResumeStore(resumeStore);
  const normalizedInvitation = invitation === undefined ? null : strictV2Invitation(invitation);
  if (!normalizedInvitation && resumeStore === undefined) fail("INVALID_ENROLLMENT_INVITATION", "An invitation is required when no resume store is configured");
  let client;

  return async function enrollDevice(context) {
    if (context?.action?.id !== "enroll_device" || context.current_state !== "service_keys_activated" || context.target_state !== "device_enrolled") fail("INVALID_ENROLLMENT_STATE", "Device enrollment handler was dispatched in the wrong setup state");
    const key = publicKey(runner);
    let record;
    let createdHere = false;
    let descriptor;
    if (resumeStore) {
      try { record = resumeStore.read(); }
      catch (error) { if (!notInitialized(error)) throw error; }
      if (record) {
        if (!object(record.recovery_descriptor)) fail("RESUME_BINDING_MISMATCH", "Resume state has no public recovery descriptor");
        descriptor = validateRecoveryDescriptor(record.recovery_descriptor, { organization_id: record.organization_id, device_id: record.device_id, candidate_id: record.release_id, loopbackTestMode: options.loopbackTestMode });
        if (record.organization_id !== descriptor.candidate_binding.organization_id || record.device_id !== descriptor.candidate_binding.device_id || record.release_id !== descriptor.candidate_binding.candidate_id || descriptor.candidate_binding.device_key_fingerprint !== key.fingerprint) fail("RESUME_BINDING_MISMATCH", "Resume state is not bound to this candidate or native device");
        if (normalizedInvitation) {
          const candidateClient = makeEnrollmentClient(normalizedInvitation, key, { ...options, runner, baseUrl: baseUrl ?? descriptor.api_base_url });
          assertDescriptorMatchesInvitation(descriptor, normalizedInvitation, baseUrl ?? descriptor.api_base_url, options.loopbackTestMode === true, candidateClient.request().body_digest);
        }
      } else {
        if (!normalizedInvitation) fail("INVALID_ENROLLMENT_INVITATION", "An invitation is required to initialize resume state");
        client = makeEnrollmentClient(normalizedInvitation, key, { ...options, runner, baseUrl });
        descriptor = descriptorFromInvitation(normalizedInvitation, baseUrl, options.loopbackTestMode === true, client.request().body_digest);
        if (descriptor.candidate_binding.device_key_fingerprint !== key.fingerprint) fail("RESUME_BINDING_MISMATCH", "Invitation is not bound to the native device");
        record = resumeStore.create_prepared({ release_id: descriptor.candidate_binding.candidate_id, organization_id: descriptor.candidate_binding.organization_id, device_id: descriptor.candidate_binding.device_id, resume_id: options.resumeId, created_at: undefined, recovery_descriptor: clone(descriptor) });
        createdHere = true;
      }
    } else {
      if (!normalizedInvitation) fail("INVALID_ENROLLMENT_INVITATION", "An invitation is required");
      descriptor = null;
    }

    if (resumeStore) {
      if (record.state === "failed") fail("RESUME_FAILED", "Device enrollment resume state is terminally failed");
      if (record.state === "control_acknowledged") {
        if (typeof (options.recoverEnrollment ?? recoverDeviceEnrollment) !== "function") noRecovery();
        const recovered = await recoverBoundResult(descriptor, key, runner, options);
        if (!recovered) fail("ENROLLMENT_RECOVERY_PENDING", "Enrollment receipt is not available for the durable acknowledged state");
        return evidence(context, recovered.proof);
      }
      if (record.state === "prepared") {
        if (!normalizedInvitation) fail("INVALID_ENROLLMENT_INVITATION", "The prepared operation still requires its one-time invitation");
        resumeStore.issue_invitation(invitationEvidence(normalizedInvitation, descriptor));
        record = resumeStore.read();
      }
      if (record.state === "invitation_issued") {
        resumeStore.record_delivery(deliveryEvidence(descriptor));
        record = resumeStore.read();
      }
      if (record.state === "delivered") {
        resumeStore.mark_enrollment_uncertain(attemptEvidence(descriptor, key));
        record = resumeStore.read();
      }
      let result;
      let proof;
      if (record.state === "enrollment_uncertain") {
        if (createdHere) {
          client ??= makeEnrollmentClient(normalizedInvitation, key, { ...options, runner, baseUrl });
          result = await client.enroll();
          proof = publicProof(result, descriptor, key);
        } else {
          if (typeof (options.recoverEnrollment ?? recoverDeviceEnrollment) !== "function") noRecovery();
          const recovered = await recoverBoundResult(descriptor, key, runner, options);
          const authority = recovered ? authorityResult(recovered.result, descriptor, recovered.proof) : { status: "not_found", binding: { source: RESUME_SOURCE, release_id: descriptor.candidate_binding.candidate_id, organization_id: descriptor.candidate_binding.organization_id, device_id: descriptor.candidate_binding.device_id }, authority_record_id: null, enrollment_id: null, receipt_id: null, receipt_statement_hash: null, authority_evidence_hash: null, observed_at: new Date().toISOString() };
          const reconciled = await resumeStore.reconcile_enrollment({ lookup: async () => authority });
          if (reconciled.state !== "receipt_verified") fail("ENROLLMENT_RECOVERY_PENDING", "Enrollment receipt is not yet available; no POST was attempted");
          if (!recovered) noRecovery("ENROLLMENT_RECOVERY_UNVERIFIED");
          result = recovered.result;
          proof = recovered.proof;
        }
        if (createdHere) {
          const reconciled = await resumeStore.reconcile_enrollment({ lookup: async () => authorityResult(result, descriptor, proof) });
          if (reconciled.state !== "receipt_verified") fail("ENROLLMENT_RECOVERY_UNVERIFIED", "Verified enrollment result did not reconcile the durable state");
        }
        record = resumeStore.read();
      } else if (record.state === "receipt_verified" || record.state === "trust_installed") {
        if (!createdHere) {
          if (typeof (options.recoverEnrollment ?? recoverDeviceEnrollment) !== "function") noRecovery();
          const recovered = await recoverBoundResult(descriptor, key, runner, options);
          if (!recovered) fail("ENROLLMENT_RECOVERY_PENDING", "Enrollment receipt is not available for the durable verified state");
          result = recovered.result;
          proof = recovered.proof;
        } else {
          fail("RESUME_BINDING_MISMATCH", "Initial enrollment state advanced without a verified result");
        }
      }

      if (record.state === "receipt_verified") {
        const { controlV2APIBaseURL, controlURL } = configForResult(result, descriptor.api_base_url, options.loopbackTestMode === true);
        const provisioned = await provisionControl({ version: 1, issuer: result.control.issuer, key_id: result.control.key_id, organization_id: result.organization_id, device_id: result.device_id, device_key_epoch: result.device_key_epoch, control_v2_api_base_url: controlV2APIBaseURL, control_url: controlURL, public_key_pem: result.control.public_key, refresh_hint: result.control.refresh_hint });
        if (!object(provisioned) || provisioned.new_fingerprint === undefined) fail("CONTROL_PROVISIONING_FAILED", "Native ControlBundle v2 trust was not durably provisioned");
        resumeStore.install_trust(trustEvidence(provisioned, result, controlURL));
        record = resumeStore.read();
      }

      if (record.state === "trust_installed") {
        const { controlURL } = configForResult(result, descriptor.api_base_url, options.loopbackTestMode === true);
        const current = loadConfig();
        const reconciled = await restartService();
        const controlAcknowledgement = validateControlAcknowledgement(reconciled, result, key, current);
        const next = { ...current, ...configForResult(result, descriptor.api_base_url, options.loopbackTestMode === true).fragment, native_broker: { ...current.native_broker, control_url: controlURL } };
        saveConfig(next);
        resumeStore.acknowledge_control(controlEvidence(result, controlURL, controlAcknowledgement));
        record = resumeStore.read();
      }
      if (record.state !== "control_acknowledged") fail("INVALID_RESUME_STATE", `Resume state did not converge: ${record.state}`);
      if (!proof) fail("ENROLLMENT_RECOVERY_UNVERIFIED", "Completed onboarding has no verified possession proof");
      return evidence(context, proof);
    }

    const possessionReceiptPublicKey = options.possessionReceiptPublicKey ?? options.possession_receipt_public_key ?? normalizedInvitation.possession_receipt_verification.public_key;
    const possessionReceiptKeyId = options.possessionReceiptKeyId ?? options.possession_receipt_key_id ?? normalizedInvitation.possession_receipt_verification.key_id;
    if (typeof possessionReceiptPublicKey !== "string" || typeof possessionReceiptKeyId !== "string" || possessionReceiptKeyId.length === 0) fail("INVALID_ENROLLMENT_INVITATION", "A pinned possession receipt verification key and key ID are required for v2 setup");
    client ??= createDeviceEnrollmentClient({ proofVersion: 2, requireV2: true, qualification: "p256-sha256", baseUrl, enrollmentId: normalizedInvitation.enrollment_id, organizationId: normalizedInvitation.organization_id, deviceId: normalizedInvitation.device_id, label: normalizedInvitation.label, credential: normalizedInvitation.credential, candidateBinding: normalizedInvitation.candidate_binding, challengeId: normalizedInvitation.challenge_id, challengeNonce: normalizedInvitation.nonce, possessionReceiptPublicKey, possessionReceiptKeyId, deviceKey: { algorithm: key.algorithm, spki_pem: key.spki_pem }, keyFingerprint: key.fingerprint, signer: ({ bytes }) => runner.sign({ bytes }), fetchImpl: options.fetchImpl, loopbackTestMode: options.loopbackTestMode });
    const result = await client.enroll();
    const { controlV2APIBaseURL, controlURL } = configForResult(result, baseUrl, options.loopbackTestMode === true);
    const provisioned = await provisionControl({ version: 1, issuer: result.control.issuer, key_id: result.control.key_id, organization_id: result.organization_id, device_id: result.device_id, device_key_epoch: result.device_key_epoch, control_v2_api_base_url: controlV2APIBaseURL, control_url: controlURL, public_key_pem: result.control.public_key, refresh_hint: result.control.refresh_hint });
    if (!object(provisioned) || provisioned.new_fingerprint === undefined) fail("CONTROL_PROVISIONING_FAILED", "Native ControlBundle v2 trust was not durably provisioned");
    const current = loadConfig();
    const reconciled = await restartService();
    validateControlAcknowledgement(reconciled, result, key, current);
    const fragment = buildCloudControlConfigFragment({ organization_id: result.organization_id, device_id: result.device_id, issuer: result.control.issuer, key_id: result.control.key_id, public_key: result.control.public_key, url: controlURL, refresh_seconds: 60, allow_offline: false, loopbackTestMode: options.loopbackTestMode });
    const next = { ...current, ...fragment, native_broker: { ...current.native_broker, control_url: controlURL } };
    saveConfig(next);
    return evidence(context, result.evidence);
  };
}
