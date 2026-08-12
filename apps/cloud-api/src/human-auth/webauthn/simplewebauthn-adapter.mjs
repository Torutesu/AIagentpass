import { verifyAuthenticationResponse } from "@simplewebauthn/server";

const BASE64URL = /^[A-Za-z0-9_-]{1,1366}$/;

export function createSimpleWebAuthnAssertionVerifier({ credentialRepository, verify = verifyAuthenticationResponse } = {}) {
  if (!credentialRepository || typeof credentialRepository.findCredentialForSession !== "function" || typeof credentialRepository.updateCredentialCounter !== "function") throw new TypeError("credentialRepository is invalid");
  if (typeof verify !== "function") throw new TypeError("verify must be a function");

  return async function verifyAssertion(input) {
    const ceremony = input?.ceremony;
    const assertion = input?.assertion;
    if (!ceremony || !assertion || !BASE64URL.test(assertion.credential_id)) throw new TypeError("WebAuthn assertion input is invalid");
    const stored = await credentialRepository.findCredentialForSession({
      session_id: ceremony.session_id,
      organization_id: ceremony.organization_id,
      credential_id: assertion.credential_id
    });
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
    const result = await verify({
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
    if (!result?.verified || result.authenticationInfo?.credentialID !== assertion.credential_id || result.authenticationInfo?.userVerified !== true || result.authenticationInfo?.origin !== ceremony.origin || result.authenticationInfo?.rpID !== ceremony.rp_id) throw new Error("WebAuthn assertion verification failed");
    const newCounter = integer(result.authenticationInfo.newCounter, "new credential counter");
    const updated = await credentialRepository.updateCredentialCounter({
      credential_id: assertion.credential_id,
      session_id: ceremony.session_id,
      organization_id: ceremony.organization_id,
      expected_sign_count: counter,
      sign_count: newCounter,
      credential_device_type: result.authenticationInfo.credentialDeviceType,
      credential_backed_up: result.authenticationInfo.credentialBackedUp
    });
    if (!updated) throw new Error("WebAuthn credential counter conflict");
    return Object.freeze({ verified: true, credential_id: assertion.credential_id, sign_count: newCounter });
  };
}

function bytes(value, minimum, maximum, label) {
  let result;
  if (value instanceof Uint8Array) result = new Uint8Array(value);
  else if (Buffer.isBuffer(value)) result = new Uint8Array(value);
  else if (typeof value === "string" && BASE64URL.test(value)) result = new Uint8Array(Buffer.from(value, "base64url"));
  else throw new TypeError(`${label} is invalid`);
  if (result.byteLength < minimum || result.byteLength > maximum) throw new TypeError(`${label} is invalid`);
  return result;
}

function integer(value, label) {
  if (!Number.isSafeInteger(value) || value < 0) throw new TypeError(`${label} is invalid`);
  return value;
}

function transports(value) {
  if (value === undefined) return undefined;
  if (!Array.isArray(value) || value.length > 8 || value.some((item) => !["ble", "cable", "hybrid", "internal", "nfc", "smart-card", "usb"].includes(item))) throw new TypeError("credential transports are invalid");
  return [...new Set(value)];
}
