import { buildCloudControlConfigFragment } from "./cloud-control.mjs";
import { createDeviceEnrollmentClient } from "./device-enrollment-client.mjs";

function fail(code, message) { const error = new Error(message); error.code = code; throw error; }
function object(value) { return value !== null && typeof value === "object" && !Array.isArray(value); }
function bundleUrl(baseUrl, bundlePath) {
  let base;
  try { base = new URL(baseUrl); } catch { fail("INVALID_ENROLLMENT_INVITATION", "Enrollment base URL is invalid"); }
  if (base.protocol !== "https:" && !(base.protocol === "http:" && ["localhost", "127.0.0.1", "::1"].includes(base.hostname))) fail("INVALID_ENROLLMENT_INVITATION", "Enrollment requires HTTPS");
  if (typeof bundlePath !== "string" || !bundlePath.startsWith("/v1/organizations/")) fail("INVALID_ENROLLMENT_RESPONSE", "Control bundle path is invalid");
  return new URL(bundlePath, base.origin).toString();
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
  let client;
  return async function enrollDevice(context) {
    if (context?.action?.id !== "enroll_device" || context.current_state !== "service_keys_activated" || context.target_state !== "device_enrolled") fail("INVALID_ENROLLMENT_STATE", "Device enrollment handler was dispatched in the wrong setup state");
    const key = runner.publicKey();
    client ??= createDeviceEnrollmentClient({
      baseUrl,
      enrollmentId: invitation.enrollment_id,
      organizationId: invitation.organization_id,
      deviceId: invitation.device_id,
      label: invitation.label,
      credential: invitation.credential,
      deviceKey: { algorithm: key.algorithm, spki_pem: key.spki_pem },
      keyFingerprint: key.fingerprint,
      signer: ({ bytes }) => runner.sign({ bytes }),
      fetchImpl: options.fetchImpl,
      loopbackTestMode: options.loopbackTestMode
    });
    const result = await client.enroll();
    const controlURL = bundleUrl(baseUrl, result.control.bundle_path);
    const provisioned = await provisionControl({
      version: 1,
      issuer: result.control.issuer,
      key_id: result.control.key_id,
      organization_id: result.organization_id,
      device_id: result.device_id,
      device_key_epoch: result.device_key_epoch,
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
