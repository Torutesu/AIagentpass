import { verifyAuthenticationResponse } from "@simplewebauthn/server";

const BASE64URL = /^[A-Za-z0-9_-]+$/;
const MAX_CREDENTIAL_ID_LENGTH = 1366;
const MAX_CLIENT_DATA_LENGTH = 21_846;
const MAX_AUTHENTICATOR_DATA_LENGTH = 8_192;
const MAX_SIGNATURE_LENGTH = 1_366;
const MAX_USER_HANDLE_LENGTH = 128;
const MAX_SIGN_COUNT = 0xffff_ffff;
const DEVICE_TYPES = new Set(["singleDevice", "multiDevice"]);

export function createSimpleWebAuthnAssertionVerifier({ credentialRepository, verify = verifyAuthenticationResponse } = {}) {
  if (!credentialRepository || typeof credentialRepository.findCredentialForSession !== "function" || typeof credentialRepository.updateCredentialCounter !== "function") throw new TypeError("credentialRepository is invalid");
  if (typeof verify !== "function") throw new TypeError("verify must be a function");

  return async function verifyAssertion(input) {
    const ceremony = input?.ceremony;
    const assertion = input?.assertion;
    validateCeremony(ceremony);
    validateAssertion(assertion);
    let stored;
    try {
      stored = await credentialRepository.findCredentialForSession({
        session_id: ceremony.session_id,
        organization_id: ceremony.organization_id,
        credential_id: assertion.credential_id
      });
    } catch {
      throw new Error("WebAuthn credential is unavailable");
    }
    if (!stored || stored.revoked_at || stored.status === "revoked") throw new Error("WebAuthn credential is unavailable");
    const publicKey = bytes(stored.public_key ?? stored.publicKey, 32, 4096, "credential public key");
    const counter = integer(stored.sign_count ?? stored.counter ?? 0, "credential counter");
    const response = {
      id: assertion.credential_id,
      rawId: assertion.credential_id,
      type: "public-key",
      clientExtensionResults: {},
      response: {
        clientDataJSON: assertion.client_data_json,
        authenticatorData: assertion.authenticator_data,
        signature: assertion.signature,
        userHandle: assertion.user_handle ?? null
      }
    };
    let result;
    try {
      result = await verify({
        response,
        expectedChallenge: ceremony.expected_challenge,
        expectedOrigin: ceremony.origin,
        expectedRPID: ceremony.rp_id,
        credential: {
          id: assertion.credential_id,
          publicKey,
          counter,
          transports: transports(stored.transports)
        },
        expectedType: "webauthn.get",
        requireUserVerification: true
      });
    } catch {
      throw new Error("WebAuthn assertion verification failed");
    }
    const info = result?.authenticationInfo;
    if (!result?.verified || info?.credentialID !== assertion.credential_id || info?.userVerified !== true || info?.origin !== ceremony.origin || info?.rpID !== ceremony.rp_id) throw new Error("WebAuthn assertion verification failed");
    const newCounter = integer(info.newCounter, "new credential counter");
    validateCounterTransition(counter, newCounter);
    const backup = validateBackupTransition(stored, info);
    let updated;
    try {
      updated = await credentialRepository.updateCredentialCounter({
        credential_id: assertion.credential_id,
        session_id: ceremony.session_id,
        organization_id: ceremony.organization_id,
        expected_sign_count: counter,
        sign_count: newCounter,
        expected_backup_eligible: backup.previous_eligible,
        expected_backup_state: backup.previous_backed_up,
        credential_device_type: backup.device_type,
        credential_backed_up: backup.backed_up,
        backup_eligible: backup.eligible,
        backup_state: backup.backed_up
      });
    } catch {
      throw new Error("WebAuthn credential counter update failed");
    }
    if (!updated) throw new Error("WebAuthn credential counter conflict");
    return Object.freeze({ verified: true, credential_id: assertion.credential_id, sign_count: newCounter });
  };
}

function bytes(value, minimum, maximum, label) {
  let result;
  if (value instanceof Uint8Array) result = new Uint8Array(value);
  else if (Buffer.isBuffer(value)) result = new Uint8Array(value);
  else if (typeof value === "string" && base64url(value, 1, Math.ceil(maximum * 4 / 3) + 2)) result = new Uint8Array(Buffer.from(value, "base64url"));
  else throw new TypeError(`${label} is invalid`);
  if (result.byteLength < minimum || result.byteLength > maximum) throw new TypeError(`${label} is invalid`);
  return result;
}

function integer(value, label) {
  if (!Number.isSafeInteger(value) || value < 0 || value > MAX_SIGN_COUNT) throw new TypeError(`${label} is invalid`);
  return value;
}

function transports(value) {
  if (value === undefined) return undefined;
  if (!Array.isArray(value) || value.length > 8 || value.some((item) => !["ble", "cable", "hybrid", "internal", "nfc", "smart-card", "usb"].includes(item))) throw new TypeError("credential transports are invalid");
  return [...new Set(value)];
}

function validateCeremony(value) {
  if (!value || typeof value !== "object" || typeof value.session_id !== "string" || typeof value.organization_id !== "string" || typeof value.expected_challenge !== "string" || typeof value.origin !== "string" || typeof value.rp_id !== "string") throw new TypeError("WebAuthn assertion input is invalid");
}

function validateAssertion(value) {
  if (!value || typeof value !== "object" || !base64url(value.credential_id, 1, MAX_CREDENTIAL_ID_LENGTH) || !base64url(value.client_data_json, 1, MAX_CLIENT_DATA_LENGTH) || !base64url(value.authenticator_data, 1, MAX_AUTHENTICATOR_DATA_LENGTH) || !base64url(value.signature, 1, MAX_SIGNATURE_LENGTH) || (value.user_handle !== undefined && value.user_handle !== null && !base64url(value.user_handle, 1, MAX_USER_HANDLE_LENGTH))) throw new TypeError("WebAuthn assertion input is invalid");
}

function base64url(value, minimum, maximum) {
  return typeof value === "string" && value.length >= minimum && value.length <= maximum && BASE64URL.test(value);
}

function validateCounterTransition(previous, next) {
  // A zero/zero pair is explicitly allowed for authenticators that do not
  // expose a usable signature counter. Any non-zero counter is reliable and
  // must move strictly forward; equal/rollback values are clone/replay risk.
  if ((previous !== 0 || next !== 0) && next <= previous) throw new Error("WebAuthn assertion verification failed");
}

function validateBackupTransition(stored, info) {
  const deviceType = info.credentialDeviceType;
  const backedUp = info.credentialBackedUp;
  if (!DEVICE_TYPES.has(deviceType) || typeof backedUp !== "boolean" || (deviceType === "singleDevice" && backedUp)) throw new Error("WebAuthn assertion verification failed");

  const storedEligible = stored.backup_eligible !== undefined ? stored.backup_eligible : stored.backupEligible;
  const storedState = stored.backup_state !== undefined ? stored.backup_state : stored.backupState !== undefined ? stored.backupState : stored.credential_backed_up;
  const storedDeviceType = stored.credential_device_type !== undefined ? stored.credential_device_type : stored.credentialDeviceType;
  if (storedEligible !== undefined && typeof storedEligible !== "boolean") throw new Error("WebAuthn assertion verification failed");
  if (storedState !== undefined && typeof storedState !== "boolean") throw new Error("WebAuthn assertion verification failed");
  if (storedState === true && storedEligible !== true) throw new Error("WebAuthn assertion verification failed");
  if (storedDeviceType !== undefined && !DEVICE_TYPES.has(storedDeviceType)) throw new Error("WebAuthn assertion verification failed");

  const eligible = deviceType === "multiDevice";
  if (storedEligible !== undefined && storedEligible !== eligible) throw new Error("WebAuthn assertion verification failed");
  if (storedDeviceType !== undefined && storedDeviceType !== deviceType) throw new Error("WebAuthn assertion verification failed");
  return Object.freeze({
    device_type: deviceType,
    eligible,
    backed_up: backedUp,
    previous_eligible: storedEligible ?? eligible,
    previous_backed_up: storedState ?? false
  });
}
