import crypto from "node:crypto";

import { generateRegistrationOptions, verifyRegistrationResponse } from "@simplewebauthn/server";

const DEFAULT_TTL_MS = 120_000;
const MAX_TTL_MS = 300_000;
const MAX_PENDING = 10_000;
const CHALLENGE_BYTES = 32;
const MAX_CLIENT_DATA_BYTES = 16 * 1024;
const MAX_ATTESTATION_OBJECT_BYTES = 64 * 1024;
const MAX_CREDENTIAL_ID_BYTES = 1024;
const MAX_PUBLIC_KEY_BYTES = 4096;
const MAX_USER_HANDLE_BYTES = 64;
const MAX_USER_NAME_LENGTH = 320;
const MAX_DISPLAY_NAME_LENGTH = 128;
const MAX_RP_NAME_LENGTH = 128;
const MAX_CLOCK_SKEW_MS = 30_000;
const BASE64URL = /^[A-Za-z0-9_-]+$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/;
const OPERATION = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$/;
const RP_ID = /^[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$/;
const ORIGIN_SCHEMES = new Set(["https:", "http:"]);
const CLIENT_DATA_KEYS = new Set(["type", "challenge", "origin", "crossOrigin", "tokenBinding"]);
const STATUS = new Set(["pending", "consuming", "consumed", "failed", "expired"]);
const TRANSPORTS = new Set(["ble", "cable", "hybrid", "internal", "nfc", "smart-card", "usb"]);
const REGISTRATION_OPERATION = "human.webauthn.registration";

export const WEBAUTHN_REGISTRATION_OPERATION = REGISTRATION_OPERATION;

export const WEBAUTHN_REGISTRATION_ERROR_CODES = Object.freeze({
  INVALID_REQUEST: "webauthn_registration_invalid_request",
  INVALID_CONTEXT: "webauthn_registration_invalid_context",
  CHALLENGE_NOT_FOUND: "webauthn_registration_challenge_not_found",
  CHALLENGE_EXPIRED: "webauthn_registration_challenge_expired",
  CHALLENGE_REPLAYED: "webauthn_registration_challenge_replayed",
  CHALLENGE_BUSY: "webauthn_registration_challenge_busy",
  CHALLENGE_MISMATCH: "webauthn_registration_challenge_mismatch",
  BINDING_MISMATCH: "webauthn_registration_binding_mismatch",
  INVALID_RESPONSE: "webauthn_registration_invalid_response",
  VERIFICATION_FAILED: "webauthn_registration_verification_failed",
  VERIFIER_UNAVAILABLE: "webauthn_registration_verifier_unavailable",
  INVALID_VERIFIER_RESULT: "webauthn_registration_invalid_verifier_result",
  CAPACITY_EXCEEDED: "webauthn_registration_capacity_exceeded",
  CREDENTIAL_EXISTS: "webauthn_registration_credential_exists",
  CREDENTIAL_STORAGE_UNAVAILABLE: "webauthn_registration_credential_storage_unavailable"
});

const ERROR_MESSAGES = Object.freeze({
  [WEBAUTHN_REGISTRATION_ERROR_CODES.INVALID_REQUEST]: "WebAuthn registration request is invalid",
  [WEBAUTHN_REGISTRATION_ERROR_CODES.INVALID_CONTEXT]: "WebAuthn registration context is invalid",
  [WEBAUTHN_REGISTRATION_ERROR_CODES.CHALLENGE_NOT_FOUND]: "WebAuthn registration challenge was not found",
  [WEBAUTHN_REGISTRATION_ERROR_CODES.CHALLENGE_EXPIRED]: "WebAuthn registration challenge has expired",
  [WEBAUTHN_REGISTRATION_ERROR_CODES.CHALLENGE_REPLAYED]: "WebAuthn registration challenge has already been consumed",
  [WEBAUTHN_REGISTRATION_ERROR_CODES.CHALLENGE_BUSY]: "WebAuthn registration challenge is already being consumed",
  [WEBAUTHN_REGISTRATION_ERROR_CODES.CHALLENGE_MISMATCH]: "WebAuthn registration challenge does not match",
  [WEBAUTHN_REGISTRATION_ERROR_CODES.BINDING_MISMATCH]: "WebAuthn registration challenge binding does not match",
  [WEBAUTHN_REGISTRATION_ERROR_CODES.INVALID_RESPONSE]: "WebAuthn registration response is invalid",
  [WEBAUTHN_REGISTRATION_ERROR_CODES.VERIFICATION_FAILED]: "WebAuthn registration verification failed",
  [WEBAUTHN_REGISTRATION_ERROR_CODES.VERIFIER_UNAVAILABLE]: "WebAuthn registration verifier is unavailable",
  [WEBAUTHN_REGISTRATION_ERROR_CODES.INVALID_VERIFIER_RESULT]: "WebAuthn registration verifier result is invalid",
  [WEBAUTHN_REGISTRATION_ERROR_CODES.CAPACITY_EXCEEDED]: "WebAuthn registration capacity is exhausted",
  [WEBAUTHN_REGISTRATION_ERROR_CODES.CREDENTIAL_EXISTS]: "The WebAuthn credential is already registered",
  [WEBAUTHN_REGISTRATION_ERROR_CODES.CREDENTIAL_STORAGE_UNAVAILABLE]: "The WebAuthn credential could not be stored"
});

const VERIFIER_RESULT_KEYS = new Set([
  "verified", "credential_id", "public_key", "sign_count", "transports",
  "credential_device_type", "credential_backed_up", "user_verified"
]);

export class WebAuthnRegistrationError extends Error {
  constructor(code, details = undefined, { cause = undefined } = {}) {
    super(ERROR_MESSAGES[code] ?? "WebAuthn registration failed", { cause });
    this.name = "WebAuthnRegistrationError";
    this.code = code;
    if (details !== undefined) this.details = details;
  }
}

/**
 * Registration challenge coordinator.
 *
 * Only a SHA-256 digest and public binding fields are retained in the
 * coordinator. A production deployment must use a durable adapter with the
 * same begin/consume semantics when more than one Cloud instance is active.
 * Raw challenges and attestation responses are never written to a store.
 */
export function createWebAuthnRegistrationCeremony({
  verifyAttestation,
  now = () => Date.now(),
  ttlMs = DEFAULT_TTL_MS,
  maxPending = MAX_PENDING,
  randomBytes = crypto.randomBytes,
  randomUUID = crypto.randomUUID
} = {}) {
  if (typeof verifyAttestation !== "function") throw new TypeError("verifyAttestation must be a function");
  if (typeof now !== "function" || !Number.isSafeInteger(now()) || now() < 0) throw new TypeError("now must be a clock function");
  if (!Number.isSafeInteger(ttlMs) || ttlMs < 1_000 || ttlMs > MAX_TTL_MS) throw new TypeError("ttlMs is invalid");
  if (!Number.isSafeInteger(maxPending) || maxPending < 1 || maxPending > MAX_PENDING) throw new TypeError("maxPending is invalid");
  if (typeof randomBytes !== "function" || typeof randomUUID !== "function") throw new TypeError("random source is invalid");

  const records = new Map();

  function begin(input = {}) {
    const context = normalizeContext(input);
    const issuedAt = clock(now);
    purge(records, issuedAt);
    if (pendingCount(records) >= maxPending) fail(WEBAUTHN_REGISTRATION_ERROR_CODES.CAPACITY_EXCEEDED);
    const challengeId = randomUUID();
    if (!isUuidV4(challengeId)) throw new TypeError("randomUUID returned an invalid UUID");
    const challengeBytes = randomBytes(CHALLENGE_BYTES);
    if (!(challengeBytes instanceof Uint8Array) || challengeBytes.byteLength !== CHALLENGE_BYTES) throw new TypeError("randomBytes returned an invalid challenge");
    const challenge = Buffer.from(challengeBytes).toString("base64url");
    const requestedTtl = input.ttlMs ?? ttlMs;
    if (!Number.isSafeInteger(requestedTtl) || requestedTtl < 1_000 || requestedTtl > ttlMs) fail(WEBAUTHN_REGISTRATION_ERROR_CODES.INVALID_CONTEXT, "ttl_ms");
    const expiresAt = issuedAt + requestedTtl;
    records.set(challengeId.toLowerCase(), {
      challenge_digest: sha256(challenge),
      session_id: context.session_id,
      member_id: context.member_id,
      organization_id: context.organization_id,
      operation: context.operation,
      rp_id: context.rp_id,
      origin: context.origin,
      user_verification: context.user_verification,
      issued_at: issuedAt,
      expires_at: expiresAt,
      status: "pending"
    });
    return Object.freeze({
      challenge_id: challengeId.toLowerCase(),
      challenge,
      challenge_expires_at: new Date(expiresAt).toISOString(),
      rp_id: context.rp_id,
      origin: context.origin,
      user_verification: context.user_verification
    });
  }

  async function consume(input = {}) {
    const request = normalizeConsumeInput(input);
    const currentTime = clock(now);
    purge(records, currentTime);
    const record = records.get(request.challenge_id);
    if (!record) fail(WEBAUTHN_REGISTRATION_ERROR_CODES.CHALLENGE_NOT_FOUND);
    if (record.status === "consuming") fail(WEBAUTHN_REGISTRATION_ERROR_CODES.CHALLENGE_BUSY);
    if (record.status === "consumed" || record.status === "failed") fail(WEBAUTHN_REGISTRATION_ERROR_CODES.CHALLENGE_REPLAYED);
    if (record.status === "expired" || currentTime >= record.expires_at) {
      record.status = "expired";
      fail(WEBAUTHN_REGISTRATION_ERROR_CODES.CHALLENGE_EXPIRED);
    }
    if (!sameBinding(record, request)) fail(WEBAUTHN_REGISTRATION_ERROR_CODES.BINDING_MISMATCH);
    if (!constantTimeHexEqual(record.challenge_digest, sha256(request.challenge))) fail(WEBAUTHN_REGISTRATION_ERROR_CODES.CHALLENGE_MISMATCH);

    const verifierInput = buildVerifierInput(record, request);
    record.status = "consuming";
    record.consume_started_at = currentTime;

    let verification;
    try {
      verification = await verifyAttestation(verifierInput);
      validateVerifierResult(verification, request, currentTime);
    } catch (error) {
      record.status = "failed";
      record.failed_at = clock(now);
      if (error instanceof WebAuthnRegistrationError && error.code === WEBAUTHN_REGISTRATION_ERROR_CODES.INVALID_VERIFIER_RESULT) throw error;
      fail(WEBAUTHN_REGISTRATION_ERROR_CODES.VERIFICATION_FAILED);
    }

    record.status = "consumed";
    record.consumed_at = clock(now);
    return Object.freeze({
      verified: true,
      registration_id: request.challenge_id,
      session_id: record.session_id,
      member_id: record.member_id,
      organization_id: record.organization_id,
      operation: record.operation,
      authenticated_at: record.consumed_at,
      credential_id: verification.credential_id,
      public_key: verification.public_key,
      sign_count: verification.sign_count,
      transports: verification.transports,
      ...(verification.credential_device_type === undefined ? {} : { credential_device_type: verification.credential_device_type }),
      ...(verification.credential_backed_up === undefined ? {} : { credential_backed_up: verification.credential_backed_up }),
      user_verified: verification.user_verified
    });
  }

  function snapshot() {
    purge(records, clock(now));
    return Object.freeze([...records].map(([challenge_id, record]) => Object.freeze({ challenge_id, ...publicRecord(record) })));
  }

  return Object.freeze({ begin, consume, snapshot });
}

/**
 * Adapter around the maintained SimpleWebAuthn server verifier. It exposes a
 * narrow interface so the service does not depend on a provider's result
 * object or persist attestation material.
 */
export function createSimpleWebAuthnRegistrationVerifier({
  generateOptions = generateRegistrationOptions,
  verify = verifyRegistrationResponse
} = {}) {
  if (typeof generateOptions !== "function" || typeof verify !== "function") throw new TypeError("WebAuthn registration verifier is invalid");

  return Object.freeze({
    async generateOptions(input) {
      if (!input?.rp || !input?.user || typeof input.challenge !== "string") throw new TypeError("registration options input is invalid");
      return generateOptions({
        rpName: input.rp.name,
        rpID: input.rp.id,
        userName: input.user.name,
        userID: Buffer.from(input.user.id, "base64url"),
        userDisplayName: input.user.displayName,
        challenge: Buffer.from(input.challenge, "base64url"),
        excludeCredentials: input.excludeCredentials,
        timeout: input.timeout,
        attestationType: "none",
        authenticatorSelection: { residentKey: "preferred", userVerification: "required" },
        supportedAlgorithmIDs: [-8, -7, -257]
      });
    },

    async verifyAttestation(input) {
      const response = {
        id: input.attestation.credential_id,
        rawId: input.attestation.credential_id,
        type: "public-key",
        response: {
          clientDataJSON: input.attestation.client_data_json,
          attestationObject: input.attestation.attestation_object,
          ...(input.attestation.transports === undefined ? {} : { transports: input.attestation.transports })
        },
        clientExtensionResults: {}
      };
      const result = await verify({
        response,
        expectedChallenge: input.ceremony.expected_challenge,
        expectedOrigin: input.ceremony.origin,
        expectedRPID: input.ceremony.rp_id,
        expectedType: "webauthn.create",
        requireUserPresence: true,
        requireUserVerification: true,
        supportedAlgorithmIDs: [-8, -7, -257]
      });
      const info = result?.registrationInfo;
      if (!result?.verified || !info) return { verified: false };
      if (info.userVerified !== true || info.origin !== input.ceremony.origin || info.rpID !== input.ceremony.rp_id) return { verified: false };
      return {
        verified: true,
        credential_id: info.credential?.id ?? info.credentialID,
        public_key: info.credential?.publicKey ?? info.credentialPublicKey,
        sign_count: info.credential?.counter ?? info.counter,
        transports: info.credential?.transports ?? input.attestation.transports,
        user_verified: info.userVerified,
        ...(info.credentialDeviceType === undefined ? {} : { credential_device_type: info.credentialDeviceType }),
        ...(info.credentialBackedUp === undefined ? {} : { credential_backed_up: info.credentialBackedUp })
      };
    }
  });
}

/**
 * Service layer for session-bound credential registration. The repository
 * contract is intentionally small and receives no browser assertion, raw
 * challenge, or client data.
 */
export function createWebAuthnRegistrationService({
  ceremony,
  credentialRepository,
  registrationVerifier,
  rpId,
  origin,
  rpName = "AgentPass",
  operation = REGISTRATION_OPERATION,
  now = () => Date.now()
} = {}) {
  if (!ceremony || typeof ceremony.begin !== "function" || typeof ceremony.consume !== "function") throw new TypeError("registration ceremony is invalid");
  if (!credentialRepository || typeof credentialRepository.getRegistrationUser !== "function" || typeof credentialRepository.listCredentialsForSession !== "function" || typeof credentialRepository.createCredential !== "function") throw new TypeError("credentialRepository is invalid");
  if (!registrationVerifier || typeof registrationVerifier.generateOptions !== "function") throw new TypeError("registrationVerifier.generateOptions is required");
  if (typeof rpName !== "string" || rpName.length < 1 || rpName.length > MAX_RP_NAME_LENGTH || hasControl(rpName)) throw new TypeError("rpName is invalid");
  const expectedRpId = requiredRpId(rpId);
  const expectedOrigin = requiredOrigin(origin);
  const expectedOperation = requiredOperation(operation);
  if (typeof now !== "function") throw new TypeError("now must be a function");

  async function begin({ session, organization_id } = {}) {
    const context = assertSession(session, organization_id);
    let user;
    let credentials;
    try {
      user = normalizeRegistrationUser(await credentialRepository.getRegistrationUser(context));
      credentials = normalizeCredentialDescriptors(await credentialRepository.listCredentialsForSession(context));
    } catch (error) {
      if (error instanceof WebAuthnRegistrationError) throw error;
      throw new WebAuthnRegistrationError(WEBAUTHN_REGISTRATION_ERROR_CODES.CREDENTIAL_STORAGE_UNAVAILABLE, undefined, { cause: error });
    }
    let issued;
    try {
      issued = await ceremony.begin({ ...context, rp_id: expectedRpId, origin: expectedOrigin, operation: expectedOperation, user_verification: "required" });
    } catch (error) {
      throw mapCeremonyError(error, "begin");
    }
    const normalizedIssued = normalizeIssuedChallenge(issued, context, expectedOperation, expectedRpId, expectedOrigin, clock(now));
    let options;
    try {
      options = await registrationVerifier.generateOptions({
        rp: { id: expectedRpId, name: rpName },
        user,
        challenge: normalizedIssued.challenge,
        excludeCredentials: credentials,
        timeout: Math.max(1_000, Date.parse(normalizedIssued.challenge_expires_at) - now())
      });
    } catch (error) {
      throw new WebAuthnRegistrationError(WEBAUTHN_REGISTRATION_ERROR_CODES.VERIFIER_UNAVAILABLE, undefined, { cause: error });
    }
    return Object.freeze({
      challenge_id: normalizedIssued.challenge_id,
      options: normalizeRegistrationOptions(options, normalizedIssued, user, expectedRpId)
    });
  }

  async function verify({ session, organization_id, challenge_id, credential } = {}) {
    const context = assertSession(session, organization_id);
    const normalizedCredential = normalizeAttestation(credential);
    const challengeId = requiredUuidV4(challenge_id, "challenge_id");
    const challenge = extractRegistrationChallenge(normalizedCredential.client_data_json, expectedOrigin);
    let result;
    try {
      result = await ceremony.consume({
        ...context,
        rp_id: expectedRpId,
        origin: expectedOrigin,
        operation: expectedOperation,
        user_verification: "required",
        challenge_id: challengeId,
        challenge,
        credential_id: normalizedCredential.credential_id,
        client_data_json: normalizedCredential.client_data_json,
        attestation_object: normalizedCredential.attestation_object,
        ...(normalizedCredential.transports === undefined ? {} : { transports: normalizedCredential.transports })
      });
    } catch (error) {
      throw mapCeremonyError(error, "verify");
    }
    const verified = normalizeConsumedResult(result, context, expectedOperation, challengeId);
    try {
      const stored = await credentialRepository.createCredential({
        session_id: context.session_id,
        member_id: context.member_id,
        organization_id: context.organization_id,
        credential_id: verified.credential_id,
        public_key: Buffer.from(verified.public_key),
        sign_count: verified.sign_count,
        transports: verified.transports,
        ...(verified.credential_device_type === undefined ? {} : { credential_device_type: verified.credential_device_type }),
        ...(verified.credential_backed_up === undefined ? {} : { credential_backed_up: verified.credential_backed_up })
      });
      if (stored !== true && stored?.created !== true) throw new Error("credential repository did not confirm creation");
    } catch (error) {
      if (error?.code === WEBAUTHN_REGISTRATION_ERROR_CODES.CREDENTIAL_EXISTS || error?.code === "23505" || error?.code === "credential_exists") throw new WebAuthnRegistrationError(WEBAUTHN_REGISTRATION_ERROR_CODES.CREDENTIAL_EXISTS);
      throw new WebAuthnRegistrationError(WEBAUTHN_REGISTRATION_ERROR_CODES.CREDENTIAL_STORAGE_UNAVAILABLE, undefined, { cause: error });
    }
    return Object.freeze({ credential_id: verified.credential_id, registered_at: new Date(clock(now)).toISOString() });
  }

  return Object.freeze({ begin, verify, rpId: expectedRpId, origin: expectedOrigin, operation: expectedOperation, rpName });
}

function normalizeContext(input) {
  if (!isObject(input)) fail(WEBAUTHN_REGISTRATION_ERROR_CODES.INVALID_CONTEXT);
  return Object.freeze({
    session_id: requiredUuid(input.session_id ?? input.sessionId, "session_id"),
    member_id: requiredUuid(input.member_id ?? input.memberId, "member_id"),
    organization_id: requiredUuid(input.organization_id ?? input.organizationId, "organization_id"),
    operation: requiredOperation(input.operation),
    rp_id: requiredRpId(input.rp_id ?? input.rpId),
    origin: requiredOrigin(input.origin),
    user_verification: requiredUserVerification(input.user_verification ?? input.userVerification)
  });
}

function normalizeConsumeInput(input) {
  if (!isObject(input)) fail(WEBAUTHN_REGISTRATION_ERROR_CODES.INVALID_REQUEST);
  const context = normalizeContext(input);
  const challenge_id = requiredUuidV4(input.challenge_id ?? input.challengeId, "challenge_id");
  const challenge = requiredBase64Url(input.challenge, CHALLENGE_BYTES, CHALLENGE_BYTES, "challenge");
  const credential_id = requiredBase64Url(input.credential_id ?? input.credentialId, 16, MAX_CREDENTIAL_ID_BYTES, "credential_id");
  const client_data_json = requiredBase64Url(input.client_data_json ?? input.clientDataJSON, 1, MAX_CLIENT_DATA_BYTES, "client_data_json");
  const attestation_object = requiredBase64Url(input.attestation_object ?? input.attestationObject, 1, MAX_ATTESTATION_OBJECT_BYTES, "attestation_object");
  const transports = input.transports === undefined ? undefined : normalizeTransports(input.transports);
  return Object.freeze({ ...context, challenge_id, challenge, credential_id, client_data_json, attestation_object, ...(transports === undefined ? {} : { transports }) });
}

function buildVerifierInput(record, request) {
  const clientData = decodeClientData(request.client_data_json, request.challenge, record.origin);
  return Object.freeze({
    ceremony: Object.freeze({ challenge_id: request.challenge_id, session_id: record.session_id, member_id: record.member_id, organization_id: record.organization_id, operation: record.operation, rp_id: record.rp_id, origin: record.origin, user_verification: record.user_verification, expected_challenge: request.challenge }),
    attestation: Object.freeze({ credential_id: request.credential_id, client_data_json: request.client_data_json, attestation_object: request.attestation_object, ...(request.transports === undefined ? {} : { transports: request.transports }) }),
    parsed: Object.freeze({ client_data: Object.freeze(clientData) })
  });
}

function decodeClientData(encoded, expectedChallenge, expectedOrigin) {
  const bytes = decodeBase64Url(encoded, 1, MAX_CLIENT_DATA_BYTES);
  const text = Buffer.from(bytes).toString("utf8");
  if (Buffer.from(text, "utf8").compare(bytes) !== 0) fail(WEBAUTHN_REGISTRATION_ERROR_CODES.INVALID_RESPONSE);
  let value;
  try { value = JSON.parse(text); } catch { fail(WEBAUTHN_REGISTRATION_ERROR_CODES.INVALID_RESPONSE); }
  if (!isObject(value) || Object.keys(value).some((key) => !CLIENT_DATA_KEYS.has(key)) || value.type !== "webauthn.create" || value.challenge !== expectedChallenge || value.origin !== expectedOrigin || (value.crossOrigin !== undefined && value.crossOrigin !== false)) fail(WEBAUTHN_REGISTRATION_ERROR_CODES.INVALID_RESPONSE);
  if (value.tokenBinding !== undefined && (!isObject(value.tokenBinding) || typeof value.tokenBinding.status !== "string")) fail(WEBAUTHN_REGISTRATION_ERROR_CODES.INVALID_RESPONSE);
  return { type: value.type, challenge: value.challenge, origin: value.origin, ...(value.crossOrigin === undefined ? {} : { cross_origin: value.crossOrigin }) };
}

function validateVerifierResult(result, request, currentTime) {
  if (!isObject(result) || result.verified !== true || Object.keys(result).some((key) => !VERIFIER_RESULT_KEYS.has(key))) fail(WEBAUTHN_REGISTRATION_ERROR_CODES.INVALID_VERIFIER_RESULT);
  const credentialId = requiredBase64Url(result.credential_id, 16, MAX_CREDENTIAL_ID_BYTES, "credential_id");
  if (!sameBase64Url(credentialId, request.credential_id)) fail(WEBAUTHN_REGISTRATION_ERROR_CODES.INVALID_VERIFIER_RESULT);
  const publicKey = normalizePublicKey(result.public_key);
  if (result.user_verified !== true) fail(WEBAUTHN_REGISTRATION_ERROR_CODES.INVALID_VERIFIER_RESULT);
  if (!Number.isSafeInteger(result.sign_count) || result.sign_count < 0 || result.sign_count > 0xffffffff) fail(WEBAUTHN_REGISTRATION_ERROR_CODES.INVALID_VERIFIER_RESULT);
  if (currentTime !== undefined && (!Number.isSafeInteger(currentTime) || currentTime < 0)) fail(WEBAUTHN_REGISTRATION_ERROR_CODES.INVALID_VERIFIER_RESULT);
  const transports = result.transports === undefined ? request.transports : normalizeTransports(result.transports);
  if (result.credential_device_type !== undefined && !["singleDevice", "multiDevice"].includes(result.credential_device_type)) fail(WEBAUTHN_REGISTRATION_ERROR_CODES.INVALID_VERIFIER_RESULT);
  if (result.credential_backed_up !== undefined && typeof result.credential_backed_up !== "boolean") fail(WEBAUTHN_REGISTRATION_ERROR_CODES.INVALID_VERIFIER_RESULT);
  return Object.freeze({ credential_id: credentialId, public_key: publicKey, sign_count: result.sign_count, transports, ...(result.credential_device_type === undefined ? {} : { credential_device_type: result.credential_device_type }), ...(result.credential_backed_up === undefined ? {} : { credential_backed_up: result.credential_backed_up }) });
}

function normalizeConsumedResult(result, context, operation, registrationId) {
  const allowed = new Set(["verified", "registration_id", "session_id", "member_id", "organization_id", "operation", "authenticated_at", ...VERIFIER_RESULT_KEYS]);
  if (!isObject(result) || Object.keys(result).some((key) => !allowed.has(key)) || result.verified !== true || result.registration_id !== registrationId || result.session_id !== context.session_id || result.member_id !== context.member_id || result.organization_id !== context.organization_id || result.operation !== operation || !Number.isSafeInteger(result.authenticated_at) || result.authenticated_at < 0) throw new WebAuthnRegistrationError(WEBAUTHN_REGISTRATION_ERROR_CODES.INVALID_VERIFIER_RESULT);
  return validateVerifierResult({
    verified: true,
    credential_id: result.credential_id,
    public_key: result.public_key,
    sign_count: result.sign_count,
    ...(result.transports === undefined ? {} : { transports: result.transports }),
    ...(result.credential_device_type === undefined ? {} : { credential_device_type: result.credential_device_type }),
    ...(result.credential_backed_up === undefined ? {} : { credential_backed_up: result.credential_backed_up }),
    user_verified: result.user_verified
  }, { credential_id: result.credential_id, transports: result.transports }, result.authenticated_at);
}

function normalizeIssuedChallenge(value, context, operation, rpId, origin, currentTime) {
  const allowed = new Set(["challenge_id", "challenge", "challenge_expires_at", "rp_id", "origin", "user_verification"]);
  if (!isObject(value) || Object.keys(value).some((key) => !allowed.has(key)) || !isUuidV4(value.challenge_id) || !isBase64Url(value.challenge, CHALLENGE_BYTES, CHALLENGE_BYTES) || typeof value.challenge_expires_at !== "string" || value.rp_id !== rpId || value.origin !== origin || value.user_verification !== "required") throw new WebAuthnRegistrationError(WEBAUTHN_REGISTRATION_ERROR_CODES.VERIFIER_UNAVAILABLE);
  const expiry = Date.parse(value.challenge_expires_at);
  if (!Number.isSafeInteger(expiry) || expiry <= currentTime || expiry - currentTime > MAX_TTL_MS) throw new WebAuthnRegistrationError(WEBAUTHN_REGISTRATION_ERROR_CODES.VERIFIER_UNAVAILABLE);
  void context;
  void operation;
  return Object.freeze({ challenge_id: value.challenge_id.toLowerCase(), challenge: value.challenge, challenge_expires_at: new Date(expiry).toISOString(), rp_id: rpId, origin, user_verification: "required" });
}

function normalizeRegistrationUser(value) {
  if (!isObject(value) || Object.keys(value).some((key) => !new Set(["id", "name", "display_name", "displayName"]).has(key))) throw new WebAuthnRegistrationError(WEBAUTHN_REGISTRATION_ERROR_CODES.CREDENTIAL_STORAGE_UNAVAILABLE);
  const id = requiredBase64Url(value.id, 1, MAX_USER_HANDLE_BYTES, "user.id");
  const name = boundedText(value.name, MAX_USER_NAME_LENGTH, "user.name");
  const displayName = boundedText(value.display_name ?? value.displayName, MAX_DISPLAY_NAME_LENGTH, "user.displayName");
  return Object.freeze({ id, name, displayName });
}

function normalizeCredentialDescriptors(value) {
  if (!Array.isArray(value) || value.length > 64) throw new WebAuthnRegistrationError(WEBAUTHN_REGISTRATION_ERROR_CODES.CREDENTIAL_STORAGE_UNAVAILABLE);
  const seen = [];
  return Object.freeze(value.map((entry) => {
    if (!isObject(entry) || Object.keys(entry).some((key) => !new Set(["id", "type", "transports"]).has(key)) || entry.type !== "public-key") throw new WebAuthnRegistrationError(WEBAUTHN_REGISTRATION_ERROR_CODES.CREDENTIAL_STORAGE_UNAVAILABLE);
    const id = requiredBase64Url(entry.id, 16, MAX_CREDENTIAL_ID_BYTES, "credential.id");
    if (seen.some((existing) => sameBase64Url(existing, id))) throw new WebAuthnRegistrationError(WEBAUTHN_REGISTRATION_ERROR_CODES.CREDENTIAL_STORAGE_UNAVAILABLE);
    seen.push(id);
    return Object.freeze({ id, type: "public-key", ...(entry.transports === undefined ? {} : { transports: normalizeTransports(entry.transports) }) });
  }));
}

function normalizeRegistrationOptions(value, issued, user, rpId) {
  if (!isObject(value)) throw new WebAuthnRegistrationError(WEBAUTHN_REGISTRATION_ERROR_CODES.VERIFIER_UNAVAILABLE);
  const allowed = new Set(["challenge", "rp", "user", "pubKeyCredParams", "timeout", "attestation", "excludeCredentials", "authenticatorSelection", "extensions", "hints"]);
  if (Object.keys(value).some((key) => !allowed.has(key)) || value.challenge !== issued.challenge || !isObject(value.rp) || Object.keys(value.rp).some((key) => !["id", "name"].includes(key)) || value.rp.id !== rpId || typeof value.rp.name !== "string" || !isObject(value.user) || Object.keys(value.user).some((key) => !["id", "name", "displayName"].includes(key)) || value.user.id !== user.id || value.user.name !== user.name || value.user.displayName !== user.displayName) throw new WebAuthnRegistrationError(WEBAUTHN_REGISTRATION_ERROR_CODES.VERIFIER_UNAVAILABLE);
  if (!Array.isArray(value.pubKeyCredParams) || value.pubKeyCredParams.length < 1 || value.pubKeyCredParams.length > 32 || value.pubKeyCredParams.some((item) => !isObject(item) || Object.keys(item).some((key) => !["type", "alg"].includes(key)) || item.type !== "public-key" || !Number.isSafeInteger(item.alg))) throw new WebAuthnRegistrationError(WEBAUTHN_REGISTRATION_ERROR_CODES.VERIFIER_UNAVAILABLE);
  if (value.timeout !== undefined && (!Number.isSafeInteger(value.timeout) || value.timeout < 1_000 || value.timeout > MAX_TTL_MS)) throw new WebAuthnRegistrationError(WEBAUTHN_REGISTRATION_ERROR_CODES.VERIFIER_UNAVAILABLE);
  if (value.attestation !== undefined && !["none", "direct", "enterprise"].includes(value.attestation)) throw new WebAuthnRegistrationError(WEBAUTHN_REGISTRATION_ERROR_CODES.VERIFIER_UNAVAILABLE);
  const excludeCredentials = normalizeCredentialDescriptors(value.excludeCredentials ?? []);
  const selection = normalizeAuthenticatorSelection(value.authenticatorSelection);
  if (!isObject(value.extensions) || Object.keys(value.extensions).some((key) => key !== "credProps") || value.extensions.credProps !== true) throw new WebAuthnRegistrationError(WEBAUTHN_REGISTRATION_ERROR_CODES.VERIFIER_UNAVAILABLE);
  const hints = value.hints === undefined ? [] : value.hints;
  if (!Array.isArray(hints) || hints.length > 4 || hints.some((hint) => !["security-key", "client-device", "hybrid"].includes(hint))) throw new WebAuthnRegistrationError(WEBAUTHN_REGISTRATION_ERROR_CODES.VERIFIER_UNAVAILABLE);
  return Object.freeze({
    challenge: issued.challenge,
    rp: Object.freeze({ name: value.rp.name, id: rpId }),
    user: Object.freeze({ id: user.id, name: user.name, displayName: user.displayName }),
    pubKeyCredParams: Object.freeze(value.pubKeyCredParams.map((item) => Object.freeze({ type: "public-key", alg: item.alg }))),
    ...(value.timeout === undefined ? {} : { timeout: value.timeout }),
    ...(value.attestation === undefined ? {} : { attestation: value.attestation }),
    excludeCredentials,
    authenticatorSelection: selection,
    extensions: Object.freeze({ credProps: true }),
    hints: Object.freeze([...new Set(hints)])
  });
}

function normalizeAuthenticatorSelection(value) {
  if (!isObject(value) || Object.keys(value).some((key) => !["authenticatorAttachment", "residentKey", "requireResidentKey", "userVerification"].includes(key)) || value.userVerification !== "required") throw new WebAuthnRegistrationError(WEBAUTHN_REGISTRATION_ERROR_CODES.VERIFIER_UNAVAILABLE);
  if (value.authenticatorAttachment !== undefined && !["platform", "cross-platform"].includes(value.authenticatorAttachment)) throw new WebAuthnRegistrationError(WEBAUTHN_REGISTRATION_ERROR_CODES.VERIFIER_UNAVAILABLE);
  if (value.residentKey !== undefined && !["discouraged", "preferred", "required"].includes(value.residentKey)) throw new WebAuthnRegistrationError(WEBAUTHN_REGISTRATION_ERROR_CODES.VERIFIER_UNAVAILABLE);
  if (value.requireResidentKey !== undefined && typeof value.requireResidentKey !== "boolean") throw new WebAuthnRegistrationError(WEBAUTHN_REGISTRATION_ERROR_CODES.VERIFIER_UNAVAILABLE);
  return Object.freeze({
    ...(value.authenticatorAttachment === undefined ? {} : { authenticatorAttachment: value.authenticatorAttachment }),
    ...(value.residentKey === undefined ? {} : { residentKey: value.residentKey }),
    ...(value.requireResidentKey === undefined ? {} : { requireResidentKey: value.requireResidentKey }),
    userVerification: "required"
  });
}

function normalizeAttestation(value) {
  if (!isObject(value)) fail(WEBAUTHN_REGISTRATION_ERROR_CODES.INVALID_REQUEST);
  const allowed = new Set(["credential_id", "client_data_json", "attestation_object", "transports"]);
  if (Object.keys(value).some((key) => !allowed.has(key))) fail(WEBAUTHN_REGISTRATION_ERROR_CODES.INVALID_REQUEST);
  const credential_id = requiredBase64Url(value.credential_id, 16, MAX_CREDENTIAL_ID_BYTES, "credential_id");
  const client_data_json = requiredBase64Url(value.client_data_json, 1, MAX_CLIENT_DATA_BYTES, "client_data_json");
  const attestation_object = requiredBase64Url(value.attestation_object, 1, MAX_ATTESTATION_OBJECT_BYTES, "attestation_object");
  const transports = value.transports === undefined ? undefined : normalizeTransports(value.transports);
  return Object.freeze({ credential_id, client_data_json, attestation_object, ...(transports === undefined ? {} : { transports }) });
}

export function normalizeBrowserRegistrationCredential(value) {
  if (!isObject(value)) fail(WEBAUTHN_REGISTRATION_ERROR_CODES.INVALID_REQUEST);
  const allowed = new Set(["id", "rawId", "response", "type", "clientExtensionResults", "authenticatorAttachment"]);
  if (Object.keys(value).some((key) => !allowed.has(key)) || value.type !== "public-key" || typeof value.id !== "string" || value.id !== value.rawId || !isBase64Url(value.id, 16, MAX_CREDENTIAL_ID_BYTES) || !isObject(value.clientExtensionResults) || Object.keys(value.clientExtensionResults).length > 32 || !isObject(value.response)) fail(WEBAUTHN_REGISTRATION_ERROR_CODES.INVALID_REQUEST);
  if (value.authenticatorAttachment !== undefined && !["platform", "cross-platform"].includes(value.authenticatorAttachment)) fail(WEBAUTHN_REGISTRATION_ERROR_CODES.INVALID_REQUEST);
  if (Object.keys(value.response).some((key) => !["clientDataJSON", "attestationObject", "transports"].includes(key))) fail(WEBAUTHN_REGISTRATION_ERROR_CODES.INVALID_REQUEST);
  return normalizeAttestation({
    credential_id: value.rawId,
    client_data_json: value.response.clientDataJSON,
    attestation_object: value.response.attestationObject,
    ...(value.response.transports === undefined ? {} : { transports: value.response.transports })
  });
}

function extractRegistrationChallenge(encoded, expectedOrigin) {
  const bytes = decodeBase64Url(encoded, 1, MAX_CLIENT_DATA_BYTES);
  const text = Buffer.from(bytes).toString("utf8");
  if (Buffer.from(text, "utf8").compare(bytes) !== 0) fail(WEBAUTHN_REGISTRATION_ERROR_CODES.INVALID_RESPONSE);
  let value;
  try { value = JSON.parse(text); } catch { fail(WEBAUTHN_REGISTRATION_ERROR_CODES.INVALID_RESPONSE); }
  if (!isObject(value) || Object.keys(value).some((key) => !CLIENT_DATA_KEYS.has(key)) || value.type !== "webauthn.create" || value.origin !== expectedOrigin || (value.crossOrigin !== undefined && value.crossOrigin !== false) || !isBase64Url(value.challenge, CHALLENGE_BYTES, CHALLENGE_BYTES)) fail(WEBAUTHN_REGISTRATION_ERROR_CODES.INVALID_RESPONSE);
  return value.challenge;
}

function assertSession(session, organizationId) {
  if (!isObject(session) || !isUuid(session.session_id) || !isUuid(session.member_id) || !isUuid(session.organization_id) || session.organization_id !== organizationId || session.revoked_at) throw new WebAuthnRegistrationError(WEBAUTHN_REGISTRATION_ERROR_CODES.INVALID_CONTEXT);
  return Object.freeze({ session_id: session.session_id.toLowerCase(), member_id: session.member_id.toLowerCase(), organization_id: session.organization_id.toLowerCase() });
}

function mapCeremonyError(error, phase) {
  if (error instanceof WebAuthnRegistrationError) return error;
  if (error?.code && Object.values(WEBAUTHN_REGISTRATION_ERROR_CODES).includes(error.code)) return new WebAuthnRegistrationError(error.code);
  return new WebAuthnRegistrationError(phase === "begin" ? WEBAUTHN_REGISTRATION_ERROR_CODES.VERIFIER_UNAVAILABLE : WEBAUTHN_REGISTRATION_ERROR_CODES.VERIFICATION_FAILED);
}

function publicRecord(record) {
  return { session_id: record.session_id, member_id: record.member_id, organization_id: record.organization_id, operation: record.operation, rp_id: record.rp_id, origin: record.origin, user_verification: record.user_verification, issued_at: record.issued_at, expires_at: record.expires_at, status: record.status, ...(record.consume_started_at === undefined ? {} : { consume_started_at: record.consume_started_at }), ...(record.consumed_at === undefined ? {} : { consumed_at: record.consumed_at }), ...(record.failed_at === undefined ? {} : { failed_at: record.failed_at }) };
}

function purge(records, now) {
  for (const [id, record] of records) {
    if (record.status === "pending" && now >= record.expires_at) record.status = "expired";
    if (record.status !== "pending" && record.status !== "consuming" && now - record.expires_at > MAX_TTL_MS) records.delete(id);
  }
}

function pendingCount(records) { return [...records.values()].filter((record) => record.status === "pending" || record.status === "consuming").length; }
function sha256(value) { return crypto.createHash("sha256").update(value, "utf8").digest("hex"); }
function constantTimeHexEqual(left, right) { const a = Buffer.from(left, "hex"); const b = Buffer.from(right, "hex"); return a.length === b.length && crypto.timingSafeEqual(a, b); }
function sameBase64Url(left, right) { const a = Buffer.from(left, "base64url"); const b = Buffer.from(right, "base64url"); return a.length === b.length && crypto.timingSafeEqual(a, b); }
function normalizePublicKey(value) { let bytes; if (Buffer.isBuffer(value) || value instanceof Uint8Array) bytes = Buffer.from(value); else if (typeof value === "string" && isBase64Url(value, 32, MAX_PUBLIC_KEY_BYTES)) bytes = Buffer.from(value, "base64url"); else fail(WEBAUTHN_REGISTRATION_ERROR_CODES.INVALID_VERIFIER_RESULT); if (bytes.length < 32 || bytes.length > MAX_PUBLIC_KEY_BYTES) fail(WEBAUTHN_REGISTRATION_ERROR_CODES.INVALID_VERIFIER_RESULT); return Buffer.from(bytes); }
function normalizeTransports(value) { if (!Array.isArray(value) || value.length > 7 || value.some((item) => typeof item !== "string" || !TRANSPORTS.has(item)) || new Set(value).size !== value.length) fail(WEBAUTHN_REGISTRATION_ERROR_CODES.INVALID_REQUEST); return Object.freeze([...value]); }
function boundedText(value, max, field) { if (typeof value !== "string" || value.length < 1 || value.length > max || hasControl(value)) fail(WEBAUTHN_REGISTRATION_ERROR_CODES.INVALID_CONTEXT, field); return value; }
function hasControl(value) { return /[\u0000-\u001f\u007f]/.test(value); }
function clock(now) { const value = now(); if (!Number.isSafeInteger(value) || value < 0) throw new TypeError("clock value is invalid"); return value; }
function requiredUuid(value, field) { if (typeof value !== "string" || !UUID.test(value)) fail(WEBAUTHN_REGISTRATION_ERROR_CODES.INVALID_CONTEXT, field); return value.toLowerCase(); }
function requiredUuidV4(value, field) { if (typeof value !== "string" || !UUID_V4.test(value)) fail(WEBAUTHN_REGISTRATION_ERROR_CODES.INVALID_REQUEST, field); return value.toLowerCase(); }
function isUuid(value) { return typeof value === "string" && UUID.test(value); }
function isUuidV4(value) { return typeof value === "string" && UUID_V4.test(value); }
function requiredOperation(value) { if (typeof value !== "string" || !OPERATION.test(value) || hasControl(value)) fail(WEBAUTHN_REGISTRATION_ERROR_CODES.INVALID_CONTEXT, "operation"); return value; }
function requiredUserVerification(value) { if (value !== "required") fail(WEBAUTHN_REGISTRATION_ERROR_CODES.INVALID_CONTEXT, "user_verification"); return value; }
function requiredRpId(value) { if (typeof value !== "string" || value.length < 1 || value.length > 253 || !RP_ID.test(value) || value.includes("..")) throw new TypeError("rpId is invalid"); return value.toLowerCase(); }
function requiredOrigin(value) { if (typeof value !== "string" || value.length > 512 || hasControl(value)) throw new TypeError("origin is invalid"); let url; try { url = new URL(value); } catch { throw new TypeError("origin is invalid"); } if (!ORIGIN_SCHEMES.has(url.protocol) || url.username || url.password || url.pathname !== "/" || url.search || url.hash || (url.protocol === "http:" && !["localhost", "127.0.0.1", "[::1]"].includes(url.hostname)) || url.origin !== value) throw new TypeError("origin is invalid"); return url.origin; }
function requiredBase64Url(value, min, max, field) { if (!isBase64Url(value, min, max)) fail(WEBAUTHN_REGISTRATION_ERROR_CODES.INVALID_REQUEST, field); return value; }
function isBase64Url(value, min, max) { if (typeof value !== "string" || !BASE64URL.test(value)) return false; let bytes; try { bytes = Buffer.from(value, "base64url"); } catch { return false; } return bytes.length >= min && bytes.length <= max && bytes.toString("base64url") === value; }
function decodeBase64Url(value, min, max) { if (!isBase64Url(value, min, max)) fail(WEBAUTHN_REGISTRATION_ERROR_CODES.INVALID_RESPONSE); return Buffer.from(value, "base64url"); }
function sameBinding(record, request) { return record.session_id === request.session_id && record.member_id === request.member_id && record.organization_id === request.organization_id && record.operation === request.operation && record.rp_id === request.rp_id && record.origin === request.origin && record.user_verification === request.user_verification; }
function isObject(value) { return value !== null && typeof value === "object" && !Array.isArray(value); }
function fail(code, details = undefined) { throw new WebAuthnRegistrationError(code, details); }
