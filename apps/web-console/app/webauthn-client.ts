import {
  startAuthentication,
  startRegistration,
  WebAuthnAbortService,
  type AuthenticationResponseJSON,
  type PublicKeyCredentialCreationOptionsJSON,
  type PublicKeyCredentialRequestOptionsJSON,
  type RegistrationResponseJSON,
} from "@simplewebauthn/browser";

const DEFAULT_OPTIONS_PATH = "/api/auth/webauthn/options";
const DEFAULT_VERIFY_PATH = "/api/auth/webauthn/verify";
const DEFAULT_REGISTRATION_OPTIONS_PATH = "/api/auth/webauthn/registration/options";
const DEFAULT_REGISTRATION_VERIFY_PATH = "/api/auth/webauthn/registration/verify";
const REGISTRATION_RECENT_AUTH_OPERATION = "human.webauthn.credential.register";
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const BASE64URL = /^[A-Za-z0-9_-]+$/;
const MAX_JSON_BYTES = 128 * 1024;
const MAX_OPTIONS_TIMEOUT_MS = 120_000;
const MAX_ALLOW_CREDENTIALS = 100;
const MAX_PUB_KEY_CRED_PARAMS = 32;
const MAX_ATTESTATION_FORMATS = 16;
const MAX_OPERATION_LENGTH = 128;
const MAX_ORGANIZATION_ID_LENGTH = 64;

const OPTION_KEYS = new Set([
  "challenge",
  "timeout",
  "rpId",
  "allowCredentials",
  "userVerification",
  "hints",
  "extensions",
]);
const ALLOW_CREDENTIAL_KEYS = new Set(["id", "type", "transports"]);
const ASSERTION_KEYS = new Set([
  "id",
  "rawId",
  "response",
  "type",
  "clientExtensionResults",
  "authenticatorAttachment",
]);
const ASSERTION_RESPONSE_KEYS = new Set([
  "authenticatorData",
  "clientDataJSON",
  "signature",
  "userHandle",
]);
const CREATION_OPTION_KEYS = new Set([
  "rp",
  "user",
  "challenge",
  "pubKeyCredParams",
  "timeout",
  "excludeCredentials",
  "authenticatorSelection",
  "hints",
  "attestation",
  "attestationFormats",
  "extensions",
]);
const RP_KEYS = new Set(["id", "name"]);
const USER_KEYS = new Set(["id", "name", "displayName"]);
const PUB_KEY_CRED_PARAM_KEYS = new Set(["type", "alg"]);
const AUTHENTICATOR_SELECTION_KEYS = new Set(["authenticatorAttachment", "residentKey", "requireResidentKey", "userVerification"]);
const REGISTRATION_CREDENTIAL_KEYS = new Set(["id", "rawId", "response", "type", "clientExtensionResults", "authenticatorAttachment"]);
const REGISTRATION_RESPONSE_KEYS = new Set(["clientDataJSON", "attestationObject", "transports", "publicKeyAlgorithm", "publicKey", "authenticatorData"]);

export type WebAuthnClientInput = Readonly<{
  operation: string;
  organizationId: string;
  csrfToken: string;
  signal?: AbortSignal;
  optionsPath?: string;
  verifyPath?: string;
  fetchImpl?: typeof fetch;
  startAuthenticationImpl?: typeof startAuthentication;
}>;

export type AuthorizationResult = Readonly<{ authorization_id: string }>;
export type RegistrationResult = Readonly<{ registered: true }>;

export type WebAuthnRegistrationInput = Readonly<{
  organizationId: string;
  csrfToken: string;
  signal?: AbortSignal;
  optionsPath?: string;
  verifyPath?: string;
  fetchImpl?: typeof fetch;
  startRegistrationImpl?: typeof startRegistration;
  startAuthenticationImpl?: typeof startAuthentication;
}>;

export class WebAuthnClientError extends Error {
  readonly code: string;
  readonly status?: number;

  constructor(code: string, message: string, status?: number) {
    super(message);
    this.name = "WebAuthnClientError";
    this.code = code;
    this.status = status;
  }
}

/**
 * Run one operation-bound recent-authentication ceremony.
 *
 * The challenge and assertion exist only in local call frames and the browser
 * credential API. This module intentionally has no storage, logging, or URL
 * construction path that accepts ceremony material.
 */
export async function authenticateRecentAuth(input: WebAuthnClientInput): Promise<AuthorizationResult> {
  const operation = requiredBoundedString(input?.operation, MAX_OPERATION_LENGTH, "operation");
  const organizationId = requiredBoundedString(input?.organizationId, MAX_ORGANIZATION_ID_LENGTH, "organizationId");
  const csrfToken = requiredBoundedString(input?.csrfToken, 512, "csrfToken");
  const signal = input?.signal;
  assertAbortSignal(signal);
  throwIfAborted(signal);

  const fetchImpl = input?.fetchImpl ?? globalThis.fetch;
  if (typeof fetchImpl !== "function") throw new WebAuthnClientError("fetch_unavailable", "Authentication transport is unavailable");
  const startAuthenticationImpl = input?.startAuthenticationImpl ?? startAuthentication;
  if (typeof startAuthenticationImpl !== "function") throw new WebAuthnClientError("webauthn_unavailable", "WebAuthn authentication is unavailable");

  const optionsPath = validateRelativePath(input?.optionsPath ?? DEFAULT_OPTIONS_PATH, "optionsPath");
  const verifyPath = validateRelativePath(input?.verifyPath ?? DEFAULT_VERIFY_PATH, "verifyPath");

  const optionsResponse = await postJson(fetchImpl, optionsPath, {
    organization_id: organizationId,
    operation,
  }, csrfToken, signal);
  const challenge = validateOptionsResponse(optionsResponse);
  throwIfAborted(signal);

  const assertion = await runAuthentication(startAuthenticationImpl, challenge.options, signal);
  throwIfAborted(signal);
  const verified = await postJson(fetchImpl, verifyPath, {
    organization_id: organizationId,
    operation,
    challenge_id: challenge.challenge_id,
    credential: validateAssertion(assertion),
  }, csrfToken, signal);

  return Object.freeze({ authorization_id: validateAuthorizationResponse(verified).authorization_id });
}

/**
 * Register one passkey for the current human session.
 *
 * Registration options and the browser credential stay in local call frames.
 * Only the server's boolean completion result leaves this function, so React
 * state and browser-readable storage never receive ceremony material.
 */
export async function registerPasskey(input: WebAuthnRegistrationInput): Promise<RegistrationResult> {
  const organizationId = requiredBoundedString(input?.organizationId, MAX_ORGANIZATION_ID_LENGTH, "organizationId");
  const csrfToken = requiredBoundedString(input?.csrfToken, 512, "csrfToken");
  const signal = input?.signal;
  assertAbortSignal(signal);
  throwIfAborted(signal);

  const fetchImpl = input?.fetchImpl ?? globalThis.fetch;
  if (typeof fetchImpl !== "function") throw new WebAuthnClientError("fetch_unavailable", "Registration transport is unavailable");
  const startRegistrationImpl = input?.startRegistrationImpl ?? startRegistration;
  if (typeof startRegistrationImpl !== "function") throw new WebAuthnClientError("webauthn_unavailable", "WebAuthn registration is unavailable");

  const optionsPath = validateRelativePath(input?.optionsPath ?? DEFAULT_REGISTRATION_OPTIONS_PATH, "registrationOptionsPath");
  const verifyPath = validateRelativePath(input?.verifyPath ?? DEFAULT_REGISTRATION_VERIFY_PATH, "registrationVerifyPath");
  let recentAuth: string | undefined;
  let optionsResponse: unknown;
  try {
    optionsResponse = await postJson(fetchImpl, optionsPath, { organization_id: organizationId }, csrfToken, signal);
  } catch (error) {
    if (!(error instanceof WebAuthnClientError) || error.code !== "http_failed" || error.status !== 428) throw error;
    const authorization = await authenticateRecentAuth({
      operation: REGISTRATION_RECENT_AUTH_OPERATION,
      organizationId,
      csrfToken,
      signal,
      fetchImpl,
      startAuthenticationImpl: input?.startAuthenticationImpl
    });
    recentAuth = authorization.authorization_id;
    optionsResponse = await postJson(fetchImpl, optionsPath, { organization_id: organizationId }, csrfToken, signal, recentAuth);
  }
  const challenge = validateRegistrationOptionsResponse(optionsResponse);
  throwIfAborted(signal);

  const credential = await runRegistration(startRegistrationImpl, challenge.options, signal);
  throwIfAborted(signal);
  const verified = await postJson(fetchImpl, verifyPath, {
    organization_id: organizationId,
    challenge_id: challenge.challenge_id,
    credential: validateRegistrationCredential(credential),
  }, csrfToken, signal, recentAuth);

  return Object.freeze({ registered: validateRegistrationResponse(verified).registered });
}

export const createWebAuthnClient = (defaults: Omit<Partial<WebAuthnClientInput>, "operation" | "organizationId" | "csrfToken"> = {}) =>
  Object.freeze({
    authenticate: (input: Pick<WebAuthnClientInput, "operation" | "organizationId" | "csrfToken"> & Omit<Partial<WebAuthnClientInput>, "operation" | "organizationId" | "csrfToken">) =>
      authenticateRecentAuth({ ...defaults, ...input }),
  });

function assertAbortSignal(signal: AbortSignal | undefined): void {
  if (signal === undefined) return;
  if (!signal || typeof signal !== "object" || typeof signal.aborted !== "boolean" || typeof signal.addEventListener !== "function" || typeof signal.removeEventListener !== "function") {
    throw new TypeError("signal must be an AbortSignal");
  }
}

function throwIfAborted(signal: AbortSignal | undefined): void {
  if (signal?.aborted) throw abortError();
}

async function postJson(fetchImpl: typeof fetch, path: string, body: Record<string, unknown>, csrfToken: string, signal: AbortSignal | undefined, recentAuth?: string): Promise<unknown> {
  let response: Response;
  try {
    const headers = new Headers({
      accept: "application/json",
      "cache-control": "no-store",
      "content-type": "application/json",
      "agentpass-csrf": csrfToken,
      pragma: "no-cache",
    });
    if (recentAuth !== undefined) headers.set("agentpass-recent-auth", recentAuth);
    response = await fetchImpl(path, {
      method: "POST",
      headers,
      body: JSON.stringify(body),
      cache: "no-store",
      credentials: "same-origin",
      redirect: "error",
      signal,
    });
  } catch (error) {
    if (signal?.aborted || error instanceof DOMException && error.name === "AbortError") throw abortError();
    throw new WebAuthnClientError("transport_failed", "Authentication transport failed");
  }

  if (!response || typeof response.ok !== "boolean" || !response.ok || ![200, 201].includes(response.status)) {
    throw new WebAuthnClientError("http_failed", "Authentication request was rejected", response?.status);
  }
  const contentType = response.headers?.get("content-type") ?? "";
  if (!/^application\/json(?:\s*;|\s*$)/i.test(contentType)) throw new WebAuthnClientError("invalid_response", "Authentication response is invalid", response.status);

  const contentLength = response.headers?.get("content-length");
  if (contentLength !== null && (!/^\d+$/.test(contentLength) || Number(contentLength) > MAX_JSON_BYTES)) {
    throw new WebAuthnClientError("invalid_response", "Authentication response is invalid", response.status);
  }
  let text: string;
  try {
    text = await response.text();
  } catch {
    throw new WebAuthnClientError("invalid_response", "Authentication response is invalid", response.status);
  }
  if (text.length > MAX_JSON_BYTES) throw new WebAuthnClientError("invalid_response", "Authentication response is invalid", response.status);
  try {
    return JSON.parse(text);
  } catch {
    throw new WebAuthnClientError("invalid_response", "Authentication response is invalid", response.status);
  }
}

function validateOptionsResponse(value: unknown): Readonly<{ challenge_id: string; options: PublicKeyCredentialRequestOptionsJSON }> {
  if (!plainObject(value) || exactKeys(value, ["challenge_id", "options"]) === false || typeof value.challenge_id !== "string" || !UUID.test(value.challenge_id) || !plainObject(value.options)) {
    throw new WebAuthnClientError("invalid_options", "WebAuthn options are invalid");
  }
  validateRequestOptions(value.options);
  return Object.freeze({ challenge_id: value.challenge_id, options: value.options as unknown as PublicKeyCredentialRequestOptionsJSON });
}

function validateRequestOptions(value: Record<string, unknown>): void {
  if (Object.keys(value).some((key) => !OPTION_KEYS.has(key))) throw new WebAuthnClientError("invalid_options", "WebAuthn options are invalid");
  if (!base64url(value.challenge, 16, 128)) throw new WebAuthnClientError("invalid_options", "WebAuthn options are invalid");
  if (value.timeout !== undefined && (typeof value.timeout !== "number" || !Number.isSafeInteger(value.timeout) || value.timeout < 1 || value.timeout > MAX_OPTIONS_TIMEOUT_MS)) throw new WebAuthnClientError("invalid_options", "WebAuthn options are invalid");
  if (value.rpId !== undefined && (!string(value.rpId) || value.rpId.length < 1 || value.rpId.length > 253 || hasControlCharacters(value.rpId) || /[ /\\?#]/.test(value.rpId))) throw new WebAuthnClientError("invalid_options", "WebAuthn options are invalid");
  if (value.userVerification !== undefined && !["required", "preferred", "discouraged"].includes(value.userVerification as string)) throw new WebAuthnClientError("invalid_options", "WebAuthn options are invalid");
  if (value.allowCredentials !== undefined) {
    if (!Array.isArray(value.allowCredentials) || value.allowCredentials.length > MAX_ALLOW_CREDENTIALS) throw new WebAuthnClientError("invalid_options", "WebAuthn options are invalid");
    for (const credential of value.allowCredentials) validateAllowCredential(credential);
  }
  if (value.hints !== undefined) {
    if (!Array.isArray(value.hints) || value.hints.length > 3 || value.hints.some((hint) => !["security-key", "client-device", "hybrid"].includes(hint as string))) throw new WebAuthnClientError("invalid_options", "WebAuthn options are invalid");
  }
  if (value.extensions !== undefined && !jsonObject(value.extensions, 16_384)) throw new WebAuthnClientError("invalid_options", "WebAuthn options are invalid");
}

function validateAllowCredential(value: unknown, errorCode = "invalid_options"): void {
  if (!plainObject(value) || Object.keys(value).some((key) => !ALLOW_CREDENTIAL_KEYS.has(key)) || value.type !== "public-key" || !base64url(value.id, 1, 1024)) throw new WebAuthnClientError(errorCode, "WebAuthn options are invalid");
  if (value.transports !== undefined && (!Array.isArray(value.transports) || value.transports.length > 7 || value.transports.some((transport) => !["ble", "cable", "hybrid", "internal", "nfc", "smart-card", "usb"].includes(transport as string)))) throw new WebAuthnClientError(errorCode, "WebAuthn options are invalid");
}

async function runAuthentication(startAuthenticationImpl: typeof startAuthentication, options: PublicKeyCredentialRequestOptionsJSON, signal: AbortSignal | undefined): Promise<AuthenticationResponseJSON> {
  throwIfAborted(signal);
  let abortListener: (() => void) | undefined;
  let abortPromise: Promise<never> | undefined;
  if (signal) {
    abortPromise = new Promise((_, reject) => {
      abortListener = () => {
        WebAuthnAbortService.cancelCeremony();
        reject(abortError());
      };
      signal.addEventListener("abort", abortListener, { once: true });
    });
  }
  try {
    const authenticationPromise = Promise.resolve().then(() => startAuthenticationImpl({ optionsJSON: options }));
    const result = abortPromise ? await Promise.race([authenticationPromise, abortPromise]) : await authenticationPromise;
    return validateAssertion(result);
  } catch (error) {
    if (signal?.aborted || error instanceof WebAuthnClientError && error.code === "aborted") throw abortError();
    if (error instanceof WebAuthnClientError) throw error;
    throw new WebAuthnClientError("webauthn_failed", "WebAuthn authentication failed");
  } finally {
    if (signal && abortListener) signal.removeEventListener("abort", abortListener);
  }
}

async function runRegistration(startRegistrationImpl: typeof startRegistration, options: PublicKeyCredentialCreationOptionsJSON, signal: AbortSignal | undefined): Promise<RegistrationResponseJSON> {
  throwIfAborted(signal);
  let abortListener: (() => void) | undefined;
  let abortPromise: Promise<never> | undefined;
  if (signal) {
    abortPromise = new Promise((_, reject) => {
      abortListener = () => {
        WebAuthnAbortService.cancelCeremony();
        reject(abortError());
      };
      signal.addEventListener("abort", abortListener, { once: true });
    });
  }
  try {
    const registrationPromise = Promise.resolve().then(() => startRegistrationImpl({ optionsJSON: options }));
    const result = abortPromise ? await Promise.race([registrationPromise, abortPromise]) : await registrationPromise;
    return validateRegistrationCredential(result);
  } catch (error) {
    if (signal?.aborted || error instanceof WebAuthnClientError && error.code === "aborted") throw abortError();
    if (error instanceof WebAuthnClientError) throw error;
    throw new WebAuthnClientError("webauthn_failed", "WebAuthn registration failed");
  } finally {
    if (signal && abortListener) signal.removeEventListener("abort", abortListener);
  }
}

function validateAssertion(value: unknown): AuthenticationResponseJSON {
  if (!plainObject(value) || Object.keys(value).some((key) => !ASSERTION_KEYS.has(key)) || !string(value.id) || hasControlCharacters(value.id) || !base64url(value.rawId, 1, 4096) || value.type !== "public-key" || !plainObject(value.response) || !plainObject(value.clientExtensionResults)) throw new WebAuthnClientError("invalid_assertion", "WebAuthn assertion is invalid");
  if (value.authenticatorAttachment !== undefined && !["platform", "cross-platform"].includes(value.authenticatorAttachment as string)) throw new WebAuthnClientError("invalid_assertion", "WebAuthn assertion is invalid");
  if (Object.keys(value.response).some((key) => !ASSERTION_RESPONSE_KEYS.has(key)) || !base64url(value.response.authenticatorData, 1, 16_384) || !base64url(value.response.clientDataJSON, 1, 16_384) || !base64url(value.response.signature, 1, 16_384)) throw new WebAuthnClientError("invalid_assertion", "WebAuthn assertion is invalid");
  if (value.response.userHandle !== undefined && value.response.userHandle !== null && !base64url(value.response.userHandle, 1, 1024)) throw new WebAuthnClientError("invalid_assertion", "WebAuthn assertion is invalid");
  return value as unknown as AuthenticationResponseJSON;
}

function validateRegistrationOptionsResponse(value: unknown): Readonly<{ challenge_id: string; options: PublicKeyCredentialCreationOptionsJSON }> {
  if (!plainObject(value) || !exactKeys(value, ["challenge_id", "options"]) || typeof value.challenge_id !== "string" || !UUID.test(value.challenge_id) || !plainObject(value.options)) {
    throw new WebAuthnClientError("invalid_registration_options", "WebAuthn registration options are invalid");
  }
  validateCreationOptions(value.options);
  return Object.freeze({ challenge_id: value.challenge_id, options: value.options as unknown as PublicKeyCredentialCreationOptionsJSON });
}

function validateCreationOptions(value: Record<string, unknown>): void {
  if (Object.keys(value).some((key) => !CREATION_OPTION_KEYS.has(key)) || !plainObject(value.rp) || !plainObject(value.user) || !base64url(value.challenge, 16, 128) || !Array.isArray(value.pubKeyCredParams) || value.pubKeyCredParams.length < 1 || value.pubKeyCredParams.length > MAX_PUB_KEY_CRED_PARAMS) {
    throw new WebAuthnClientError("invalid_registration_options", "WebAuthn registration options are invalid");
  }
  validateRp(value.rp);
  validateUser(value.user);
  for (const parameter of value.pubKeyCredParams) validatePubKeyCredentialParameter(parameter);
  if (value.timeout !== undefined && (typeof value.timeout !== "number" || !Number.isSafeInteger(value.timeout) || value.timeout < 1 || value.timeout > MAX_OPTIONS_TIMEOUT_MS)) throw new WebAuthnClientError("invalid_registration_options", "WebAuthn registration options are invalid");
  if (value.excludeCredentials !== undefined) {
    if (!Array.isArray(value.excludeCredentials) || value.excludeCredentials.length > MAX_ALLOW_CREDENTIALS) throw new WebAuthnClientError("invalid_registration_options", "WebAuthn registration options are invalid");
    for (const credential of value.excludeCredentials) validateAllowCredential(credential, "invalid_registration_options");
  }
  if (value.authenticatorSelection !== undefined) validateAuthenticatorSelection(value.authenticatorSelection);
  if (value.hints !== undefined) validateHints(value.hints);
  if (value.attestation !== undefined && !["none", "indirect", "direct", "enterprise"].includes(value.attestation as string)) throw new WebAuthnClientError("invalid_registration_options", "WebAuthn registration options are invalid");
  if (value.attestationFormats !== undefined && (!Array.isArray(value.attestationFormats) || value.attestationFormats.length > MAX_ATTESTATION_FORMATS || value.attestationFormats.some((format) => typeof format !== "string" || !["packed", "tpm", "android-key", "android-safetynet", "fido-u2f", "none", "apple"].includes(format)))) throw new WebAuthnClientError("invalid_registration_options", "WebAuthn registration options are invalid");
  if (value.extensions !== undefined && !jsonObject(value.extensions, 16_384)) throw new WebAuthnClientError("invalid_registration_options", "WebAuthn registration options are invalid");
}

function validateRp(value: Record<string, unknown>): void {
  if (Object.keys(value).some((key) => !RP_KEYS.has(key)) || !string(value.id) || !string(value.name) || value.id.length > 253 || value.name.length > 128 || hasControlCharacters(value.id) || hasControlCharacters(value.name) || /[ /\\?#]/.test(value.id)) throw new WebAuthnClientError("invalid_registration_options", "WebAuthn registration options are invalid");
}

function validateUser(value: Record<string, unknown>): void {
  if (Object.keys(value).some((key) => !USER_KEYS.has(key)) || !base64url(value.id, 1, 64) || !string(value.name) || !string(value.displayName) || value.name.length > 128 || value.displayName.length > 128 || hasControlCharacters(value.name) || hasControlCharacters(value.displayName)) throw new WebAuthnClientError("invalid_registration_options", "WebAuthn registration options are invalid");
}

function validatePubKeyCredentialParameter(value: unknown): void {
  if (!plainObject(value) || Object.keys(value).some((key) => !PUB_KEY_CRED_PARAM_KEYS.has(key)) || value.type !== "public-key" || typeof value.alg !== "number" || !Number.isSafeInteger(value.alg) || value.alg < -65_535 || value.alg > 65_535) throw new WebAuthnClientError("invalid_registration_options", "WebAuthn registration options are invalid");
}

function validateAuthenticatorSelection(value: unknown): void {
  if (!plainObject(value) || Object.keys(value).some((key) => !AUTHENTICATOR_SELECTION_KEYS.has(key))) throw new WebAuthnClientError("invalid_registration_options", "WebAuthn registration options are invalid");
  if (value.authenticatorAttachment !== undefined && !["platform", "cross-platform"].includes(value.authenticatorAttachment as string)) throw new WebAuthnClientError("invalid_registration_options", "WebAuthn registration options are invalid");
  if (value.residentKey !== undefined && !["discouraged", "preferred", "required"].includes(value.residentKey as string)) throw new WebAuthnClientError("invalid_registration_options", "WebAuthn registration options are invalid");
  if (value.requireResidentKey !== undefined && typeof value.requireResidentKey !== "boolean") throw new WebAuthnClientError("invalid_registration_options", "WebAuthn registration options are invalid");
  if (value.userVerification !== undefined && !["required", "preferred", "discouraged"].includes(value.userVerification as string)) throw new WebAuthnClientError("invalid_registration_options", "WebAuthn registration options are invalid");
}

function validateHints(value: unknown): void {
  if (!Array.isArray(value) || value.length > 3 || value.some((hint) => !["security-key", "client-device", "hybrid"].includes(hint as string))) throw new WebAuthnClientError("invalid_registration_options", "WebAuthn registration options are invalid");
}

function validateRegistrationCredential(value: unknown): RegistrationResponseJSON {
  if (!plainObject(value) || Object.keys(value).some((key) => !REGISTRATION_CREDENTIAL_KEYS.has(key)) || !string(value.id) || hasControlCharacters(value.id) || !base64url(value.rawId, 16, 1024) || value.id !== value.rawId || value.type !== "public-key" || !plainObject(value.response) || !plainObject(value.clientExtensionResults)) throw new WebAuthnClientError("invalid_registration_credential", "WebAuthn registration credential is invalid");
  if (value.authenticatorAttachment !== undefined && !["platform", "cross-platform"].includes(value.authenticatorAttachment as string)) throw new WebAuthnClientError("invalid_registration_credential", "WebAuthn registration credential is invalid");
  if (Object.keys(value.response).some((key) => !REGISTRATION_RESPONSE_KEYS.has(key)) || !base64url(value.response.attestationObject, 1, 65_536) || !base64url(value.response.clientDataJSON, 1, 16_384)) throw new WebAuthnClientError("invalid_registration_credential", "WebAuthn registration credential is invalid");
  if (value.response.authenticatorData !== undefined && !base64url(value.response.authenticatorData, 37, 16_384)) throw new WebAuthnClientError("invalid_registration_credential", "WebAuthn registration credential is invalid");
  if (value.response.publicKey !== undefined && !base64url(value.response.publicKey, 1, 16_384)) throw new WebAuthnClientError("invalid_registration_credential", "WebAuthn registration credential is invalid");
  if (value.response.publicKeyAlgorithm !== undefined && (typeof value.response.publicKeyAlgorithm !== "number" || !Number.isSafeInteger(value.response.publicKeyAlgorithm) || value.response.publicKeyAlgorithm < -65_535 || value.response.publicKeyAlgorithm > 65_535)) throw new WebAuthnClientError("invalid_registration_credential", "WebAuthn registration credential is invalid");
  if (value.response.transports !== undefined && (!Array.isArray(value.response.transports) || value.response.transports.length > 7 || value.response.transports.some((transport) => !["ble", "cable", "hybrid", "internal", "nfc", "smart-card", "usb"].includes(transport as string)))) throw new WebAuthnClientError("invalid_registration_credential", "WebAuthn registration credential is invalid");
  return {
    id: value.id,
    rawId: value.rawId,
    response: {
      clientDataJSON: value.response.clientDataJSON,
      attestationObject: value.response.attestationObject,
      ...(value.response.transports === undefined ? {} : { transports: value.response.transports }),
    },
    type: "public-key",
    clientExtensionResults: value.clientExtensionResults,
    ...(value.authenticatorAttachment === undefined ? {} : { authenticatorAttachment: value.authenticatorAttachment }),
  } as unknown as RegistrationResponseJSON;
}

function validateRegistrationResponse(value: unknown): RegistrationResult {
  if (!plainObject(value) || !exactKeys(value, ["credential_id", "registered_at"]) || !base64url(value.credential_id, 16, 1024) || typeof value.registered_at !== "string" || !isCanonicalIsoDate(value.registered_at)) throw new WebAuthnClientError("invalid_registration_result", "WebAuthn registration response is invalid");
  return Object.freeze({ registered: true });
}

function isCanonicalIsoDate(value: string): boolean {
  try { return new Date(value).toISOString() === value; } catch { return false; }
}

function validateAuthorizationResponse(value: unknown): AuthorizationResult {
  if (!plainObject(value) || !exactKeys(value, ["authorization_id"]) || typeof value.authorization_id !== "string" || !UUID.test(value.authorization_id)) throw new WebAuthnClientError("invalid_authorization", "Authorization response is invalid");
  return Object.freeze({ authorization_id: value.authorization_id });
}

function validateRelativePath(value: unknown, name: string): string {
  if (!string(value) || !value.startsWith("/") || value.startsWith("//") || value.includes("?") || value.includes("#") || hasWhitespaceOrControlCharacters(value)) throw new TypeError(`${name} must be a same-origin relative path`);
  try {
    const parsed = new URL(value, "https://agentpass.invalid");
    if (parsed.origin !== "https://agentpass.invalid" || parsed.pathname !== value) throw new TypeError(`${name} must be a same-origin relative path`);
  } catch {
    throw new TypeError(`${name} must be a same-origin relative path`);
  }
  return value;
}

function requiredBoundedString(value: unknown, max: number, name: string): string {
  if (!string(value) || value.length > max || hasControlCharacters(value)) throw new TypeError(`${name} is invalid`);
  return value;
}

function base64url(value: unknown, min: number, max: number): value is string {
  return string(value) && value.length >= min && value.length <= max && BASE64URL.test(value);
}

function string(value: unknown): value is string {
  return typeof value === "string";
}

function plainObject(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype;
}

function exactKeys(value: Record<string, unknown>, expected: string[]): boolean {
  const keys = Object.keys(value).sort();
  return keys.length === expected.length && keys.every((key, index) => key === [...expected].sort()[index]);
}

function jsonObject(value: unknown, maxBytes: number): boolean {
  if (!plainObject(value)) return false;
  try {
    const encoded = JSON.stringify(value);
    return encoded.length <= maxBytes && !hasControlCharacters(encoded);
  } catch {
    return false;
  }
}

function hasControlCharacters(value: string): boolean {
  for (const character of value) {
    const codePoint = character.codePointAt(0) ?? 0;
    if (codePoint <= 0x1f || codePoint === 0x7f) return true;
  }
  return false;
}

function hasWhitespaceOrControlCharacters(value: string): boolean {
  for (const character of value) {
    const codePoint = character.codePointAt(0) ?? 0;
    if (codePoint <= 0x20 || codePoint === 0x7f) return true;
  }
  return false;
}

function abortError(): Error {
  if (typeof DOMException === "function") return new DOMException("The authentication operation was aborted", "AbortError");
  const error = new Error("The authentication operation was aborted");
  error.name = "AbortError";
  return error;
}
