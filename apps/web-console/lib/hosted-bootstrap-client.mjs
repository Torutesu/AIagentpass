// @ts-check

const MAX_RESPONSE_BYTES = 256 * 1024;
const MAX_REQUEST_BYTES = 64 * 1024;
const MAX_NAME_BYTES = 128;
const MAX_IDEMPOTENCY_KEY_LENGTH = 255;
const MAX_CREDENTIAL_ID_BYTES = 1_024;
const MAX_CREDENTIAL_DATA_BYTES = 64 * 1_024;
const MAX_JSON_OBJECT_KEYS = 64;
const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
const BASE64URL = /^[A-Za-z0-9_-]+$/u;
const CSRF_TOKEN = /^[A-Za-z0-9_-]{43}$/u;
const IDEMPOTENCY_KEY = /^[A-Za-z0-9._~-]{8,255}$/u;
const RFC3339_UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/u;
// eslint-disable-next-line no-control-regex
const CONTROL_CHARACTERS = /[\u0000-\u001f\u007f]/u;
const SESSION_ROLES = new Set(["owner", "admin", "auditor", "viewer"]);
const STATUS_STATES = new Set(["oauth_started", "identity_verified", "organization_required", "webauthn_required", "ready", "no_membership", "completed", "expired"]);
const TRANSPORTS = new Set(["ble", "cable", "hybrid", "internal", "nfc", "smart-card", "usb"]);
const RESPONSE_ERROR_CODES = new Set([
  "bootstrap_origin_not_allowed",
  "bootstrap_csrf_failed",
  "bootstrap_session_required",
  "bootstrap_session_expired",
  "github_oauth_state_invalid",
  "github_subject_unverified",
  "github_provider_unavailable",
  "bootstrap_invalid_request",
  "bootstrap_idempotency_required",
  "bootstrap_idempotency_conflict",
  "bootstrap_already_completed",
  "bootstrap_no_membership",
  "bootstrap_webauthn_required",
  "bootstrap_webauthn_invalid",
  "bootstrap_webauthn_replayed",
  "bootstrap_unavailable",
  "not_found",
]);

/** @typedef {"oauth_started" | "identity_verified" | "organization_required" | "webauthn_required" | "ready" | "no_membership" | "completed" | "expired"} HostedBootstrapState */

/** @typedef {Readonly<{
 * state: HostedBootstrapState,
 * webauthnRequired: boolean,
 * canCreateFirstOrganization: boolean,
 * organizationCount: number,
 * expiresAt: string,
 * }>} HostedBootstrapStatus */

/** @typedef {Readonly<{
 * organization_id: string,
 * name: string,
 * version: number,
 * created_at: string,
 * updated_at: string,
 * }>} HostedOrganization */

/** @typedef {Readonly<{
 * version: 1,
 * session_id: string,
 * member_id: string,
 * organization_id: string,
 * role: "owner" | "admin" | "auditor" | "viewer",
 * created_at: string,
 * expires_at: string,
 * recent_auth_at: string | null,
 * }>} HostedSession */

/** @typedef {Readonly<{ challenge_id: string, options: Readonly<Record<string, unknown>> }>} HostedWebAuthnOptions */

/** @typedef {Readonly<{
 * fetchImpl?: typeof fetch,
 * startRegistrationImpl?: (input: { optionsJSON: Readonly<Record<string, unknown>> }) => Promise<unknown>,
 * }>} HostedBootstrapClientOptions */

export const HOSTED_BOOTSTRAP_CLIENT_PATHS = Object.freeze({
  githubStart: "/api/auth/bootstrap/github/start",
  githubCallback: "/api/auth/bootstrap/github/callback",
  status: "/api/auth/bootstrap/status",
  organization: "/api/auth/bootstrap/organization",
  webauthnOptions: "/api/auth/bootstrap/webauthn/registration/options",
  webauthnVerify: "/api/auth/bootstrap/webauthn/registration/verify",
});

export const HOSTED_BOOTSTRAP_CLIENT_ERROR_CODES = Object.freeze({
  INVALID_INPUT: "invalid_input",
  FETCH_UNAVAILABLE: "fetch_unavailable",
  TRANSPORT_FAILED: "transport_failed",
  ABORTED: "aborted",
  INVALID_RESPONSE: "invalid_response",
  SERVER_REJECTED: "server_rejected",
  CSRF_REQUIRED: "csrf_required",
  WEBAUTHN_UNAVAILABLE: "webauthn_unavailable",
  WEBAUTHN_FAILED: "webauthn_failed",
});

/**
 * UI-facing failures use a stable client code. For an HTTP rejection, the
 * allowlisted Cloud code is exposed separately as `serverCode` so React can
 * branch on `bootstrap_session_required` and friends without trusting an
 * arbitrary error payload.
 */
export class HostedBootstrapClientError extends Error {
  /** @param {string} code @param {string} message @param {{status?: number, serverCode?: string}} [meta] */
  constructor(code, message, meta = {}) {
    super(message);
    this.name = "HostedBootstrapClientError";
    this.code = code;
    if (meta.status !== undefined) this.status = meta.status;
    if (meta.serverCode !== undefined) this.serverCode = meta.serverCode;
  }
}

/**
 * Browser-only client for the six Hosted bootstrap routes.
 *
 * The bootstrap and session cookies are HttpOnly and are intentionally never
 * inspected here. The CSRF token returned by status() lives only in this
 * closure and is sent with the two mutating bootstrap requests.
 *
 * @param {HostedBootstrapClientOptions} [input]
 */
export function createHostedBootstrapClient(input = {}) {
  if (!isRecord(input)) invalidInput();
  const fetchImpl = input.fetchImpl ?? globalThis.fetch;
  if (typeof fetchImpl !== "function") throw clientError("FETCH_UNAVAILABLE", "Bootstrap transport is unavailable");
  const startRegistrationImpl = input.startRegistrationImpl;
  if (startRegistrationImpl !== undefined && typeof startRegistrationImpl !== "function") invalidInput();

  /** @type {string | undefined} */
  let csrfToken;

  async function githubStart({ signal } = {}) {
    const response = await requestRedirect(fetchImpl, HOSTED_BOOTSTRAP_CLIENT_PATHS.githubStart, 302, signal);
    return Object.freeze({ location: response.location });
  }

  async function githubCallback({ url, signal } = {}) {
    const callbackUrl = normalizeCallbackUrl(url);
    const response = await requestRedirect(fetchImpl, callbackUrl, 303, signal);
    return Object.freeze({ location: response.location });
  }

  async function status({ signal } = {}) {
    const value = await requestJson(fetchImpl, HOSTED_BOOTSTRAP_CLIENT_PATHS.status, { method: "GET", signal });
    const parsed = parseStatus(value);
    // Install the token only after the complete response has passed validation.
    csrfToken = parsed.csrf_token;
    return publicStatus(parsed);
  }

  async function createOrganization({ name, idempotencyKey, signal } = {}) {
    const currentCsrf = requireCsrf(csrfToken);
    const normalizedName = requiredOrganizationName(name);
    const key = idempotencyKey === undefined ? makeIdempotencyKey() : requiredIdempotencyKey(idempotencyKey);
    const value = await requestJson(fetchImpl, HOSTED_BOOTSTRAP_CLIENT_PATHS.organization, {
      method: "POST",
      body: { name: normalizedName },
      headers: { "agentpass-bootstrap-csrf": currentCsrf, "idempotency-key": key },
      signal,
    });
    return parseOrganizationResponse(value);
  }

  async function webauthnOptions({ signal } = {}) {
    const currentCsrf = requireCsrf(csrfToken);
    const value = await requestJson(fetchImpl, HOSTED_BOOTSTRAP_CLIENT_PATHS.webauthnOptions, {
      method: "POST",
      body: {},
      headers: { "agentpass-bootstrap-csrf": currentCsrf },
      signal,
    });
    return parseWebAuthnOptions(value);
  }

  async function webauthnVerify({ challengeId, credential, signal } = {}) {
    const currentCsrf = requireCsrf(csrfToken);
    const challenge = requiredUuid(challengeId, "challengeId");
    const credentialJson = normalizeRegistrationCredential(credential);
    const value = await requestJson(fetchImpl, HOSTED_BOOTSTRAP_CLIENT_PATHS.webauthnVerify, {
      method: "POST",
      body: { challenge_id: challenge, credential: credentialJson },
      headers: { "agentpass-bootstrap-csrf": currentCsrf },
      signal,
    });
    return parseSessionResponse(value);
  }

  async function registerPasskey({ signal } = {}) {
    const challenge = await webauthnOptions({ signal });
    const runner = startRegistrationImpl ?? await loadDefaultStartRegistration();
    throwIfAborted(signal);
    let credential;
    try {
      credential = await raceWithAbort(Promise.resolve().then(() => runner({ optionsJSON: challenge.options })), signal);
    } catch (error) {
      if (isAbort(error, signal)) throw clientError("ABORTED", "WebAuthn registration was cancelled");
      throw clientError("WEBAUTHN_FAILED", "WebAuthn registration failed");
    }
    throwIfAborted(signal);
    return webauthnVerify({ challengeId: challenge.challenge_id, credential, signal });
  }

  return Object.freeze({
    githubStart,
    githubCallback,
    status,
    createOrganization,
    webauthnOptions,
    webauthnVerify,
    registerPasskey,
  });
}

async function requestRedirect(fetchImpl, path, expectedStatus, signal) {
  let response;
  try {
    response = await fetchImpl(path, {
      method: "GET",
      headers: new Headers({ accept: "application/json", "cache-control": "no-store", pragma: "no-cache" }),
      cache: "no-store",
      credentials: "include",
      redirect: "manual",
      signal,
    });
  } catch (error) {
    throw transportError(error, signal);
  }
  if (!response || response.status !== expectedStatus) {
    if (response && response.status >= 400) throw await parseServerError(response);
    throw invalidResponse(response?.status);
  }
  const location = response.headers?.get("location");
  if (typeof location !== "string") throw invalidResponse(expectedStatus);
  await readEmptyResponse(response, expectedStatus);
  return { location: expectedStatus === 302 ? validateGithubLocation(location) : validateOnboardingLocation(location) };
}

async function requestJson(fetchImpl, path, { method, body, headers: extraHeaders, signal }) {
  const headers = new Headers({ accept: "application/json", "cache-control": "no-store", pragma: "no-cache" });
  if (body !== undefined) headers.set("content-type", "application/json");
  for (const [name, value] of Object.entries(extraHeaders ?? {})) headers.set(name, value);
  const serialized = body === undefined ? undefined : JSON.stringify(body);
  if (serialized !== undefined && byteLength(serialized) > MAX_REQUEST_BYTES) invalidInput();
  let response;
  try {
    response = await fetchImpl(path, {
      method,
      headers,
      body: serialized,
      cache: "no-store",
      credentials: "include",
      redirect: "error",
      signal,
    });
  } catch (error) {
    throw transportError(error, signal);
  }
  const value = await readJsonResponse(response);
  if (!response.ok || response.status < 200 || response.status > 299) throw parseServerErrorValue(value, response.status);
  return value;
}

async function readJsonResponse(response) {
  if (!response || typeof response.status !== "number" || response.status < 200 || response.status > 599 || (response.status >= 300 && response.status < 400)) throw invalidResponse(response?.status);
  const contentType = response.headers?.get("content-type") ?? "";
  if (!/^application\/json(?:\s*;|\s*$)/iu.test(contentType)) throw invalidResponse(response.status);
  const contentLength = response.headers?.get("content-length");
  if (contentLength !== null && (!/^\d+$/u.test(contentLength) || Number(contentLength) > MAX_RESPONSE_BYTES)) throw invalidResponse(response.status);
  let bytes;
  try { bytes = new Uint8Array(await response.arrayBuffer()); } catch { throw invalidResponse(response.status); }
  if (bytes.byteLength > MAX_RESPONSE_BYTES) throw invalidResponse(response.status);
  let text;
  try { text = new TextDecoder("utf-8", { fatal: true }).decode(bytes); } catch { throw invalidResponse(response.status); }
  try { return parseJsonStrict(text); } catch { throw invalidResponse(response.status); }
}

async function readEmptyResponse(response, status) {
  const contentLength = response.headers?.get("content-length");
  if (contentLength !== null && (!/^\d+$/u.test(contentLength) || Number(contentLength) !== 0)) throw invalidResponse(status);
  let bytes;
  try { bytes = new Uint8Array(await response.arrayBuffer()); } catch { throw invalidResponse(status); }
  if (bytes.byteLength !== 0) throw invalidResponse(status);
}

async function parseServerError(response) {
  try {
    const value = await readJsonResponse(response);
    return parseServerErrorValue(value, response.status);
  } catch (error) {
    if (error instanceof HostedBootstrapClientError) throw error;
    throw invalidResponse(response.status);
  }
}

function parseServerErrorValue(value, status) {
  if (!isRecord(value) || !exactKeys(value, ["error"]) || !isRecord(value.error) || !exactKeys(value.error, ["code", "message"])
    || typeof value.error.code !== "string" || !RESPONSE_ERROR_CODES.has(value.error.code)
    || typeof value.error.message !== "string" || value.error.message.length > 512 || CONTROL_CHARACTERS.test(value.error.message)) {
    throw invalidResponse(status);
  }
  throw clientError("SERVER_REJECTED", "The bootstrap request was rejected", { status, serverCode: value.error.code });
}

function parseStatus(value) {
  if (!isRecord(value) || !exactKeys(value, ["version", "state", "webauthn_required", "can_create_first_organization", "organization_count", "csrf_token", "expires_at"])
    || value.version !== 1 || typeof value.state !== "string" || !STATUS_STATES.has(value.state)
    || typeof value.webauthn_required !== "boolean" || typeof value.can_create_first_organization !== "boolean"
    || !safeInteger(value.organization_count, 0) || !csrf(value.csrf_token) || !timestamp(value.expires_at)) throw invalidResponse();
  if (value.can_create_first_organization && value.state !== "organization_required") throw invalidResponse();
  if (value.webauthn_required !== (value.state === "webauthn_required")) throw invalidResponse();
  return Object.freeze({
    version: 1,
    state: value.state,
    webauthn_required: value.webauthn_required,
    can_create_first_organization: value.can_create_first_organization,
    organization_count: value.organization_count,
    csrf_token: value.csrf_token,
    expires_at: value.expires_at,
  });
}

function publicStatus(value) {
  return Object.freeze({
    state: value.state,
    webauthnRequired: value.webauthn_required,
    canCreateFirstOrganization: value.can_create_first_organization,
    organizationCount: value.organization_count,
    expiresAt: value.expires_at,
  });
}

function parseOrganizationResponse(value) {
  if (!isRecord(value) || !exactKeys(value, ["version", "organization", "onboarding"]) || value.version !== 1 || !isRecord(value.onboarding) || !exactKeys(value.onboarding, ["state"]) || value.onboarding.state !== "webauthn_required") throw invalidResponse();
  return parseOrganization(value.organization);
}

function parseOrganization(value) {
  if (!isRecord(value) || !exactKeys(value, ["organization_id", "name", "version", "created_at", "updated_at"])
    || !uuid(value.organization_id) || !validName(value.name) || !safeInteger(value.version, 1) || !timestamp(value.created_at) || !timestamp(value.updated_at)) throw invalidResponse();
  return Object.freeze({ organization_id: value.organization_id.toLowerCase(), name: value.name, version: value.version, created_at: value.created_at, updated_at: value.updated_at });
}

function parseWebAuthnOptions(value) {
  if (!isRecord(value) || !exactKeys(value, ["challenge_id", "options"]) || !uuid(value.challenge_id) || !isRecord(value.options)) throw invalidResponse();
  validateCreationOptions(value.options);
  return Object.freeze({ challenge_id: value.challenge_id.toLowerCase(), options: value.options });
}

function parseSessionResponse(value) {
  if (!isRecord(value) || !exactKeys(value, ["version", "state", "session", "csrf_token"]) || value.version !== 1 || value.state !== "completed" || !csrf(value.csrf_token)) throw invalidResponse();
  if (!isRecord(value.session) || !exactKeys(value.session, ["version", "session_id", "member_id", "organization_id", "role", "created_at", "expires_at", "recent_auth_at"])
    || value.session.version !== 1 || !uuid(value.session.session_id) || !uuid(value.session.member_id) || !uuid(value.session.organization_id) || !SESSION_ROLES.has(value.session.role)
    || !timestamp(value.session.created_at) || !timestamp(value.session.expires_at) || (value.session.recent_auth_at !== null && !timestamp(value.session.recent_auth_at))) throw invalidResponse();
  return Object.freeze({
    version: 1,
    session_id: value.session.session_id.toLowerCase(),
    member_id: value.session.member_id.toLowerCase(),
    organization_id: value.session.organization_id.toLowerCase(),
    role: value.session.role,
    created_at: value.session.created_at,
    expires_at: value.session.expires_at,
    recent_auth_at: value.session.recent_auth_at,
  });
}

function validateCreationOptions(value) {
  const allowed = new Set(["rp", "user", "challenge", "pubKeyCredParams", "timeout", "excludeCredentials", "authenticatorSelection", "hints", "attestation", "attestationFormats", "extensions"]);
  if (Object.keys(value).some((key) => !allowed.has(key)) || !isRecord(value.rp) || !exactKeys(value.rp, ["id", "name"]) || !validRpId(value.rp.id) || !safeText(value.rp.name, 128)
    || !isRecord(value.user) || !exactKeys(value.user, ["id", "name", "displayName"]) || !base64(value.user.id, 1, 128) || !safeText(value.user.name, 320) || !safeText(value.user.displayName, 128)
    || !base64(value.challenge, 16, 128) || !Array.isArray(value.pubKeyCredParams) || value.pubKeyCredParams.length < 1 || value.pubKeyCredParams.length > 32
    || value.pubKeyCredParams.some((item) => !isRecord(item) || !exactKeys(item, ["type", "alg"]) || item.type !== "public-key" || !Number.isSafeInteger(item.alg))) throw invalidResponse();
  if (value.timeout !== undefined && (!Number.isSafeInteger(value.timeout) || value.timeout < 1 || value.timeout > 120_000)) throw invalidResponse();
  if (value.excludeCredentials !== undefined && (!Array.isArray(value.excludeCredentials) || value.excludeCredentials.length > 100 || value.excludeCredentials.some((item) => !validCredentialDescriptor(item)))) throw invalidResponse();
  if (!isRecord(value.authenticatorSelection) || Object.keys(value.authenticatorSelection).some((key) => !new Set(["authenticatorAttachment", "residentKey", "requireResidentKey", "userVerification"]).has(key)) || value.authenticatorSelection.userVerification !== "required") throw invalidResponse();
  if (value.hints !== undefined && (!Array.isArray(value.hints) || value.hints.length > 3 || value.hints.some((hint) => !["security-key", "client-device", "hybrid"].includes(hint)))) throw invalidResponse();
  if (value.attestation !== undefined && !["none", "indirect", "direct", "enterprise"].includes(value.attestation)) throw invalidResponse();
  if (value.attestationFormats !== undefined && (!Array.isArray(value.attestationFormats) || value.attestationFormats.length > 16 || value.attestationFormats.some((format) => typeof format !== "string"))) throw invalidResponse();
  if (value.extensions !== undefined && !jsonObject(value.extensions, 16 * 1024)) throw invalidResponse();
}

function validCredentialDescriptor(value) {
  return isRecord(value) && (exactKeys(value, ["id", "type"]) || exactKeys(value, ["id", "type", "transports"])) && value.type === "public-key" && base64(value.id, 1, MAX_CREDENTIAL_ID_BYTES) && (value.transports === undefined || validTransports(value.transports));
}

function normalizeRegistrationCredential(value) {
  if (!value || typeof value !== "object") invalidInput();
  let json;
  try {
    json = typeof value.toJSON === "function" ? value.toJSON() : isRecord(value) && typeof value.rawId === "string" ? value : credentialFromWebApi(value);
  } catch {
    throw clientError("INVALID_INPUT", "The WebAuthn credential is invalid");
  }
  if (!isRecord(json) || !exactKeys(json, ["id", "rawId", "response", "type", "clientExtensionResults"]) && !exactKeys(json, ["id", "rawId", "response", "type", "clientExtensionResults", "authenticatorAttachment"])) throw clientError("INVALID_INPUT", "The WebAuthn credential is invalid");
  if (json.type !== "public-key" || typeof json.id !== "string" || !base64(json.id, 16, MAX_CREDENTIAL_ID_BYTES) || json.rawId !== json.id || !isRecord(json.clientExtensionResults) || Object.keys(json.clientExtensionResults).length > 32 || !isRecord(json.response)) throw clientError("INVALID_INPUT", "The WebAuthn credential is invalid");
  if (json.authenticatorAttachment !== undefined && !["platform", "cross-platform"].includes(json.authenticatorAttachment)) throw clientError("INVALID_INPUT", "The WebAuthn credential is invalid");
  // SimpleWebAuthn adds derived metadata to the browser credential. Accept
  // those known fields here, but keep the Hosted request canonical below.
  const registrationResponseKeys = new Set(["clientDataJSON", "attestationObject", "transports", "publicKeyAlgorithm", "publicKey", "authenticatorData"]);
  if (Object.keys(json.response).some((key) => !registrationResponseKeys.has(key))) throw clientError("INVALID_INPUT", "The WebAuthn credential is invalid");
  if (!base64(json.response.clientDataJSON, 1, MAX_CREDENTIAL_DATA_BYTES) || !base64(json.response.attestationObject, 1, MAX_CREDENTIAL_DATA_BYTES) || (json.response.transports !== undefined && !validTransports(json.response.transports))) throw clientError("INVALID_INPUT", "The WebAuthn credential is invalid");
  return Object.freeze({
    id: json.id,
    rawId: json.rawId,
    response: Object.freeze({ clientDataJSON: json.response.clientDataJSON, attestationObject: json.response.attestationObject, ...(json.response.transports === undefined ? {} : { transports: [...json.response.transports] }) }),
    type: "public-key",
    clientExtensionResults: Object.freeze({ ...json.clientExtensionResults }),
    ...(json.authenticatorAttachment === undefined ? {} : { authenticatorAttachment: json.authenticatorAttachment }),
  });
}

function credentialFromWebApi(value) {
  const response = value.response;
  if (!response || typeof response !== "object") throw new TypeError("response missing");
  const extensions = typeof value.getClientExtensionResults === "function" ? value.getClientExtensionResults() : value.clientExtensionResults;
  return {
    id: value.id,
    rawId: toBase64Url(value.rawId),
    response: {
      clientDataJSON: toBase64Url(response.clientDataJSON),
      attestationObject: toBase64Url(response.attestationObject),
      ...(typeof response.getTransports === "function" && response.getTransports().length > 0 ? { transports: response.getTransports() } : {}),
    },
    type: value.type,
    clientExtensionResults: extensions ?? {},
    ...(value.authenticatorAttachment == null ? {} : { authenticatorAttachment: value.authenticatorAttachment }),
  };
}

async function loadDefaultStartRegistration() {
  try {
    const simpleWebAuthn = await import("@simplewebauthn/browser");
    if (typeof simpleWebAuthn.startRegistration !== "function") throw new TypeError("startRegistration unavailable");
    return simpleWebAuthn.startRegistration;
  } catch {
    throw clientError("WEBAUTHN_UNAVAILABLE", "WebAuthn registration is unavailable");
  }
}

function normalizeCallbackUrl(value) {
  const raw = value ?? (typeof globalThis.location?.href === "string" ? globalThis.location.href : undefined);
  if (typeof raw !== "string") invalidInput();
  let parsed;
  try { parsed = new URL(raw, globalThis.location?.origin ?? "https://console.invalid"); } catch { invalidInput(); }
  if (parsed.pathname !== HOSTED_BOOTSTRAP_CLIENT_PATHS.githubCallback || parsed.hash || [...parsed.searchParams.keys()].sort().join(",") !== "code,state") invalidInput();
  if (parsed.searchParams.getAll("code").length !== 1 || parsed.searchParams.getAll("state").length !== 1) invalidInput();
  return `${parsed.pathname}?${parsed.searchParams.toString()}`;
}

function validateGithubLocation(value) {
  let parsed;
  try { parsed = new URL(value); } catch { throw invalidResponse(302); }
  const keys = [...parsed.searchParams.keys()];
  if (parsed.protocol !== "https:" || parsed.username || parsed.password || parsed.hash || keys.length !== 7 || keys.join(",") !== "client_id,response_type,redirect_uri,scope,state,code_challenge,code_challenge_method" || parsed.searchParams.get("response_type") !== "code" || parsed.searchParams.get("code_challenge_method") !== "S256" || !nonEmpty(parsed.searchParams.get("state")) || !base64(parsed.searchParams.get("code_challenge"), 16, 128)) throw invalidResponse(302);
  return parsed.href;
}

function validateOnboardingLocation(value) {
  let parsed;
  try { parsed = new URL(value, globalThis.location?.origin ?? "https://console.invalid"); } catch { throw invalidResponse(303); }
  if (parsed.origin !== (globalThis.location?.origin ?? parsed.origin) || parsed.pathname !== "/onboarding" || parsed.search || parsed.hash || parsed.username || parsed.password) throw invalidResponse(303);
  return `${parsed.origin}${parsed.pathname}`;
}

function requireCsrf(value) {
  if (!value) throw clientError("CSRF_REQUIRED", "Call status() before a bootstrap mutation");
  return value;
}

function makeIdempotencyKey() {
  const randomUUID = globalThis.crypto?.randomUUID;
  if (typeof randomUUID !== "function") throw clientError("WEBAUTHN_UNAVAILABLE", "A secure idempotency key source is unavailable");
  return randomUUID.call(globalThis.crypto);
}

function requiredOrganizationName(value) {
  if (!validName(value)) invalidInput();
  return value;
}

function requiredIdempotencyKey(value) {
  if (typeof value !== "string" || value.length > MAX_IDEMPOTENCY_KEY_LENGTH || !IDEMPOTENCY_KEY.test(value)) invalidInput();
  return value;
}

function requiredUuid(value, name) {
  if (typeof value !== "string" || !UUID_V4.test(value)) throw clientError("INVALID_INPUT", `${name} is invalid`);
  return value.toLowerCase();
}

function validName(value) {
  return typeof value === "string" && value.length >= 1 && value.length <= MAX_NAME_BYTES && value.trim() === value && !CONTROL_CHARACTERS.test(value);
}

function validRpId(value) {
  return typeof value === "string" && value.length >= 1 && value.length <= 253 && /^[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$/u.test(value);
}

function safeText(value, maxLength) {
  return typeof value === "string" && value.length >= 1 && value.length <= maxLength && !CONTROL_CHARACTERS.test(value);
}

function timestamp(value) {
  return typeof value === "string" && RFC3339_UTC.test(value) && Number.isFinite(Date.parse(value));
}

function uuid(value) { return typeof value === "string" && UUID_V4.test(value); }
function csrf(value) { return typeof value === "string" && CSRF_TOKEN.test(value); }
function nonEmpty(value) { return typeof value === "string" && value.length > 0 && !CONTROL_CHARACTERS.test(value); }
function safeInteger(value, min) { return Number.isSafeInteger(value) && value >= min; }
function validTransports(value) { return Array.isArray(value) && value.length <= 7 && value.every((item) => typeof item === "string" && TRANSPORTS.has(item)); }
function isRecord(value) { return value !== null && typeof value === "object" && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype; }
function exactKeys(value, expected) { const actual = Object.keys(value).sort(); const keys = [...expected].sort(); return actual.length === keys.length && actual.every((key, index) => key === keys[index]); }
function byteLength(value) { return new TextEncoder().encode(value).byteLength; }
function jsonObject(value, maxBytes) { try { return isRecord(value) && Object.keys(value).length <= MAX_JSON_OBJECT_KEYS && byteLength(JSON.stringify(value)) <= maxBytes; } catch { return false; } }
function base64(value, minBytes, maxBytes) { if (typeof value !== "string" || !BASE64URL.test(value)) return false; try { const bytes = fromBase64Url(value); return bytes.byteLength >= minBytes && bytes.byteLength <= maxBytes; } catch { return false; } }
function toBase64Url(value) { const bytes = value instanceof ArrayBuffer ? new Uint8Array(value) : ArrayBuffer.isView(value) ? new Uint8Array(value.buffer, value.byteOffset, value.byteLength) : null; if (!bytes) throw new TypeError("binary value missing"); let binary = ""; for (const byte of bytes) binary += String.fromCharCode(byte); if (typeof btoa === "function") return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, ""); if (typeof Buffer !== "undefined") return Buffer.from(bytes).toString("base64url"); throw new TypeError("base64 encoder unavailable"); }
function fromBase64Url(value) { const normalized = value.replaceAll("-", "+").replaceAll("_", "/") + "=".repeat((4 - value.length % 4) % 4); if (typeof atob === "function") return Uint8Array.from(atob(normalized), (character) => character.charCodeAt(0)); if (typeof Buffer !== "undefined") return new Uint8Array(Buffer.from(value, "base64url")); throw new TypeError("base64 decoder unavailable"); }

function clientError(code, message, meta = {}) { return new HostedBootstrapClientError(HOSTED_BOOTSTRAP_CLIENT_ERROR_CODES[code] ?? code, message, meta); }
function invalidInput() { throw clientError("INVALID_INPUT", "The bootstrap input is invalid"); }
function invalidResponse(status) { return new HostedBootstrapClientError("invalid_response", "The bootstrap response is invalid", status === undefined ? {} : { status }); }
function transportError(error, signal) { return isAbort(error, signal) ? clientError("ABORTED", "The bootstrap request was cancelled") : clientError("TRANSPORT_FAILED", "The bootstrap service is unavailable"); }
function isAbort(error, signal) { return Boolean(signal?.aborted) || error?.name === "AbortError"; }
function throwIfAborted(signal) { if (signal?.aborted) throw clientError("ABORTED", "The bootstrap request was cancelled"); }
function raceWithAbort(promise, signal) { if (!signal) return promise; if (signal.aborted) return Promise.reject(clientError("ABORTED", "The bootstrap request was cancelled")); return Promise.race([promise, new Promise((_, reject) => signal.addEventListener("abort", () => reject(clientError("ABORTED", "The bootstrap request was cancelled")), { once: true }))]); }

function parseJsonStrict(text) {
  let index = 0;
  const value = parseValue();
  skipWhitespace();
  if (index !== text.length) throw new SyntaxError("trailing JSON");
  return value;
  function parseValue() {
    skipWhitespace();
    const character = text[index];
    if (character === "{") return parseObject();
    if (character === "[") return parseArray();
    if (character === '"') return parseString();
    for (const literal of ["true", "false", "null"]) if (text.startsWith(literal, index)) { index += literal.length; return literal === "true" ? true : literal === "false" ? false : null; }
    const match = /^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/u.exec(text.slice(index));
    if (!match) throw new SyntaxError("invalid JSON value");
    index += match[0].length;
    const number = Number(match[0]);
    if (!Number.isFinite(number)) throw new SyntaxError("invalid JSON number");
    return number;
  }
  function parseObject() {
    index += 1; const result = {}; const keys = new Set(); skipWhitespace();
    if (text[index] === "}") { index += 1; return result; }
    while (true) {
      skipWhitespace(); if (text[index] !== '"') throw new SyntaxError("object key expected");
      const key = parseString(); if (keys.has(key)) throw new SyntaxError("duplicate key"); keys.add(key); skipWhitespace(); if (text[index++] !== ":") throw new SyntaxError("colon expected");
      Object.defineProperty(result, key, { value: parseValue(), enumerable: true, writable: true, configurable: true }); skipWhitespace();
      if (text[index] === "}") { index += 1; return result; } if (text[index++] !== ",") throw new SyntaxError("comma expected");
    }
  }
  function parseArray() {
    index += 1; const result = []; skipWhitespace(); if (text[index] === "]") { index += 1; return result; }
    while (true) { result.push(parseValue()); skipWhitespace(); if (text[index] === "]") { index += 1; return result; } if (text[index++] !== ",") throw new SyntaxError("comma expected"); }
  }
  function parseString() {
    const start = index++; let escaped = false;
    while (index < text.length) { const character = text[index++]; if (character === "\\") { escaped = true; index += 1; continue; } if (character === '"') { const raw = text.slice(start, index); const value = JSON.parse(raw); if (typeof value !== "string") throw new SyntaxError("invalid string"); return value; } if (character < " ") throw new SyntaxError("control character"); }
    void escaped; throw new SyntaxError("unterminated string");
  }
  function skipWhitespace() { while (/\s/u.test(text[index] ?? "")) index += 1; }
}
