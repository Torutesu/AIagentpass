import { buildCloudControlConfigFragment } from "./cloud-control.mjs";
import { buildEnrollmentCandidateBinding, createDeviceEnrollmentClient } from "./device-enrollment-client.mjs";

function fail(code, message) { const error = new Error(message); error.code = code; throw error; }
function object(value) { return value !== null && typeof value === "object" && !Array.isArray(value); }
const INVITATION_KEYS = new Set(["proof_version", "enrollment_id", "organization_id", "device_id", "label", "platform", "candidate_binding", "challenge_id", "nonce", "expires_at", "challenge", "credential", "endpoint", "possession_receipt_verification"]);
const CHALLENGE_KEYS = new Set(["challenge_id", "nonce", "expires_at", "candidate_id", "device_key_fingerprint"]);
const RECEIPT_VERIFICATION_KEYS = new Set(["key_id", "algorithm", "public_key"]);

function exactKeys(value, allowed, label) {
  if (!object(value) || Object.keys(value).some((key) => !allowed.has(key))) fail("INVALID_ENROLLMENT_INVITATION", `${label} contains unknown fields`);
}

function strictV2Invitation(value) {
  if (!object(value)) fail("INVALID_ENROLLMENT_INVITATION", "A v2 enrollment invitation is required");
  exactKeys(value, INVITATION_KEYS, "Enrollment invitation");
  if (value.proof_version !== 2 || value.platform !== "macos") fail("INVALID_ENROLLMENT_INVITATION", "A v2 macOS enrollment invitation is required");
  for (const key of ["enrollment_id", "organization_id", "device_id", "label", "credential", "endpoint", "challenge_id", "nonce", "expires_at"]) {
    if (typeof value[key] !== "string" || value[key].length === 0) fail("INVALID_ENROLLMENT_INVITATION", "Enrollment invitation is missing a required v2 field");
  }
  if (value.endpoint !== `/v1/enrollments/${value.enrollment_id}`) fail("INVALID_ENROLLMENT_INVITATION", "Enrollment invitation endpoint is not bound to its enrollment");
  let candidateBinding;
  try { candidateBinding = buildEnrollmentCandidateBinding(value.candidate_binding); }
  catch { fail("INVALID_ENROLLMENT_INVITATION", "Enrollment invitation candidate binding is invalid"); }
  if (candidateBinding.enrollment_id !== value.enrollment_id || candidateBinding.organization_id !== value.organization_id || candidateBinding.device_id !== value.device_id) fail("INVALID_ENROLLMENT_INVITATION", "Enrollment invitation candidate binding identity is invalid");
  if (candidateBinding.expires_at !== value.expires_at) fail("INVALID_ENROLLMENT_INVITATION", "Enrollment invitation expiry is not consistently bound");
  if (Date.parse(candidateBinding.expires_at) <= Date.now()) fail("INVALID_ENROLLMENT_INVITATION", "Enrollment invitation has expired");
  if (!object(value.challenge)) fail("INVALID_ENROLLMENT_INVITATION", "Enrollment invitation challenge is invalid");
  exactKeys(value.challenge, CHALLENGE_KEYS, "Enrollment invitation challenge");
  if (value.challenge.challenge_id !== value.challenge_id || value.challenge.challenge_id !== value.enrollment_id
    || value.challenge.nonce !== value.nonce || value.challenge.expires_at !== value.expires_at
    || value.challenge.candidate_id !== candidateBinding.candidate_id
    || value.challenge.device_key_fingerprint !== candidateBinding.device_key_fingerprint) {
    fail("INVALID_ENROLLMENT_INVITATION", "Enrollment invitation challenge binding is invalid");
  }
  exactKeys(value.possession_receipt_verification, RECEIPT_VERIFICATION_KEYS, "Possession receipt verification metadata");
  if (!["ed25519", "p256-sha256"].includes(value.possession_receipt_verification.algorithm)
    || typeof value.possession_receipt_verification.key_id !== "string" || value.possession_receipt_verification.key_id.length === 0
    || typeof value.possession_receipt_verification.public_key !== "string" || value.possession_receipt_verification.public_key.length === 0) {
    fail("INVALID_ENROLLMENT_INVITATION", "Possession receipt verification metadata is invalid");
  }
  return Object.freeze({
    proof_version: 2,
    enrollment_id: value.enrollment_id,
    organization_id: value.organization_id,
    device_id: value.device_id,
    label: value.label,
    platform: "macos",
    candidate_binding: Object.freeze({ ...candidateBinding }),
    challenge_id: value.challenge_id,
    nonce: value.nonce,
    expires_at: value.expires_at,
    challenge: Object.freeze({ ...value.challenge }),
    credential: value.credential,
    endpoint: value.endpoint,
    possession_receipt_verification: Object.freeze({ ...value.possession_receipt_verification })
  });
}
function credentialFreeApiBaseUrl(baseUrl, loopbackTestMode = false) {
  let base;
  try { base = new URL(baseUrl); } catch { fail("INVALID_ENROLLMENT_INVITATION", "Enrollment base URL is invalid"); }
  const hostname = base.hostname.replace(/^\[|\]$/g, "");
  if (base.protocol !== "https:" && !(loopbackTestMode && base.protocol === "http:" && ["localhost", "127.0.0.1", "::1"].includes(hostname))) fail("INVALID_ENROLLMENT_INVITATION", "Enrollment requires HTTPS");
  if (!hostname || hostname !== hostname.toLowerCase() || base.username || base.password || base.search || base.hash || !/^\/v1\/?$/.test(base.pathname)) fail("INVALID_ENROLLMENT_INVITATION", "Enrollment base URL must be a credential-free /v1 API base");
  base.pathname = "/v1";
  base.search = "";
  base.hash = "";
  return base.toString();
}
function bundleUrl(baseUrl, bundlePath, loopbackTestMode = false) {
  const apiBase = new URL(credentialFreeApiBaseUrl(baseUrl, loopbackTestMode));
  if (typeof bundlePath !== "string" || !bundlePath.startsWith("/v1/organizations/")) fail("INVALID_ENROLLMENT_RESPONSE", "Control bundle path is invalid");
  // The enrollment client already binds bundlePath to the device. Resolve it
  // with URL semantics from the validated origin; never derive an API base by
  // slicing the legacy bundle URL string.
  return new URL(bundlePath, `${apiBase.origin}/`).toString();
}
function evidence(context, proof) {
  return { evidence: { version: 1, from_state: context.current_state, to_state: context.target_state, action: context.action.id, operation_id: context.operation_id, outcome: "completed", proof } };
}

/**
 * Bind a one-time invitation to the fixed native Secure Enclave key. The
 * credential is held only by the enrollment client closure and is never added
 * to configuration, journal evidence, or thrown error details.
 */
export function createDeviceEnrollmentSetupHandler(options = {}) {
  const { runner, provisionControl, restartService, invitation, baseUrl, loadConfig, saveConfig } = options;
  if (!runner || typeof runner.publicKey !== "function" || typeof runner.sign !== "function") fail("INVALID_ENROLLMENT_RUNNER", "A native enrollment runner is required");
  if (!object(invitation) || typeof provisionControl !== "function" || typeof restartService !== "function" || typeof loadConfig !== "function" || typeof saveConfig !== "function") fail("INVALID_ENROLLMENT_INVITATION", "A bounded enrollment invitation, privileged control provisioner, service reconciler, and config adapter are required");
  const normalizedInvitation = strictV2Invitation(invitation);
  const possessionReceiptPublicKey = options.possessionReceiptPublicKey ?? options.possession_receipt_public_key ?? normalizedInvitation.possession_receipt_verification.public_key;
  const possessionReceiptKeyId = options.possessionReceiptKeyId ?? options.possession_receipt_key_id ?? normalizedInvitation.possession_receipt_verification.key_id;
  if (typeof possessionReceiptPublicKey !== "string" || typeof possessionReceiptKeyId !== "string" || possessionReceiptKeyId.length === 0) fail("INVALID_ENROLLMENT_INVITATION", "A pinned possession receipt verification key and key ID are required for v2 setup");
  let client;
  return async function enrollDevice(context) {
    if (context?.action?.id !== "enroll_device" || context.current_state !== "service_keys_activated" || context.target_state !== "device_enrolled") fail("INVALID_ENROLLMENT_STATE", "Device enrollment handler was dispatched in the wrong setup state");
    const key = runner.publicKey();
    client ??= createDeviceEnrollmentClient({
      proofVersion: 2,
      requireV2: true,
      qualification: "p256-sha256",
      baseUrl,
      enrollmentId: normalizedInvitation.enrollment_id,
      organizationId: normalizedInvitation.organization_id,
      deviceId: normalizedInvitation.device_id,
      label: normalizedInvitation.label,
      credential: normalizedInvitation.credential,
      candidateBinding: normalizedInvitation.candidate_binding,
      challengeId: normalizedInvitation.challenge_id,
      challengeNonce: normalizedInvitation.nonce,
      possessionReceiptPublicKey,
      possessionReceiptKeyId,
      deviceKey: { algorithm: key.algorithm, spki_pem: key.spki_pem },
      keyFingerprint: key.fingerprint,
      signer: ({ bytes }) => runner.sign({ bytes }),
      fetchImpl: options.fetchImpl,
      loopbackTestMode: options.loopbackTestMode
    });
    const result = await client.enroll();
    const controlV2APIBaseURL = credentialFreeApiBaseUrl(baseUrl, options.loopbackTestMode === true);
    const controlURL = bundleUrl(controlV2APIBaseURL, result.control.bundle_path, options.loopbackTestMode === true);
    const provisioned = await provisionControl({
      version: 1,
      issuer: result.control.issuer,
      key_id: result.control.key_id,
      organization_id: result.organization_id,
      device_id: result.device_id,
      device_key_epoch: result.device_key_epoch,
      control_v2_api_base_url: controlV2APIBaseURL,
      control_url: controlURL,
      public_key_pem: result.control.public_key,
      refresh_hint: result.control.refresh_hint
    });
    if (!object(provisioned) || provisioned.new_fingerprint === undefined) fail("CONTROL_PROVISIONING_FAILED", "Native ControlBundle v2 trust was not durably provisioned");
    const reconciled = await restartService();
    if (!object(reconciled) || reconciled.status !== "enabled" || reconciled.control_refreshed !== true) fail("CONTROL_RECONCILIATION_FAILED", "Native service did not restart and refresh enrolled control state");
    const fragment = buildCloudControlConfigFragment({
      organization_id: result.organization_id,
      device_id: result.device_id,
      issuer: result.control.issuer,
      key_id: result.control.key_id,
      public_key: result.control.public_key,
      url: controlURL,
      refresh_seconds: 60,
      allow_offline: false,
      loopbackTestMode: options.loopbackTestMode
    });
    const current = loadConfig();
    const next = {
      ...current,
      ...fragment,
      native_broker: { ...current.native_broker, control_url: controlURL }
    };
    saveConfig(next);
    return evidence(context, result.evidence);
  };
}
