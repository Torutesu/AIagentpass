import crypto from "node:crypto";

import { parseControlBundleJson } from "./control-bundle-v2.mjs";
import { canonicalJson } from "./identity.mjs";

const VERSION = 1;
const PLATFORM = "macos";
const METHOD = "POST";
const PROOF_HEADER = "AgentPass-Enrollment-Signature";
const CREDENTIAL_HEADER = "AgentPass-Enrollment-Credential";
const PROOF_PROTOCOL = "AgentPass-Enrollment-Proof-v1";
const DEFAULT_TIMEOUT_MS = 15_000;
const DEFAULT_MAX_RESPONSE_BYTES = 128 * 1024;
const MAX_REQUEST_BYTES = 16 * 1024;
const MAX_RESPONSE_DEPTH = 16;
const MAX_LABEL_CODE_POINTS = 128;
const MAX_PEM_BYTES = 8 * 1024;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const HASH = /^[0-9a-f]{64}$/;
const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const BASE64URL_CREDENTIAL = /^[A-Za-z0-9_-]{43}$/;
const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const FINGERPRINT = /^SHA256:[A-Za-z0-9_-]{43}$/;
const CONTROL = /[\u0000-\u001f\u007f]/;
const LOOPBACK = new Set(["localhost", "127.0.0.1", "::1"]);
const RESPONSE_KEYS = new Set(["request_id", "enrollment"]);
const ENROLLMENT_KEYS = new Set(["version", "enrollment_id", "organization_id", "device_id", "status", "key_algorithm", "device_key_epoch", "control"]);
const CONTROL_KEYS = new Set(["format_epoch", "issuer", "key_id", "public_key", "bundle_path", "refresh_hint"]);
const REFRESH_HINT_KEYS = new Set(["key_id", "algorithm", "public_key"]);
const REQUEST_INPUT_KEYS = new Set(["enrollmentId", "enrollment_id", "organizationId", "organization_id", "deviceId", "device_id", "label", "deviceKey", "device_key"]);
const SECRET_KEY = /(?:private(?:[_-]?key)?|bearer(?:[_-]?token)?|access(?:[_-]?token)?|refresh[_-]?token|session[_-]?token|secret|password|credential(?:[_-]?digest)?|completion[_-]?hash)/i;

export const DEVICE_ENROLLMENT_ERRORS = Object.freeze({
  INVALID_CONFIG: "ERR_DEVICE_ENROLLMENT_CONFIG",
  INVALID_REQUEST: "ERR_DEVICE_ENROLLMENT_REQUEST",
  INVALID_KEY: "ERR_DEVICE_ENROLLMENT_KEY",
  SIGNER: "ERR_DEVICE_ENROLLMENT_SIGNER",
  INVALID_URL: "ERR_DEVICE_ENROLLMENT_URL",
  TIMEOUT: "ERR_DEVICE_ENROLLMENT_TIMEOUT",
  NETWORK: "ERR_DEVICE_ENROLLMENT_NETWORK",
  REDIRECT: "ERR_DEVICE_ENROLLMENT_REDIRECT",
  HTTP: "ERR_DEVICE_ENROLLMENT_HTTP",
  RESPONSE: "ERR_DEVICE_ENROLLMENT_RESPONSE",
  RESPONSE_TOO_LARGE: "ERR_DEVICE_ENROLLMENT_RESPONSE_TOO_LARGE",
  BINDING: "ERR_DEVICE_ENROLLMENT_BINDING"
});

export class DeviceEnrollmentError extends Error {
  constructor(code, message, details = undefined) {
    super(message);
    this.name = "DeviceEnrollmentError";
    this.code = code;
    if (details !== undefined) this.details = details;
  }
}

/**
 * Build the exact v1 enrollment body. The returned bytes have no whitespace,
 * aliases, secret, or private-key material and are safe to hand to a signer.
 */
export function buildDeviceEnrollmentRequest(input = {}) {
  try {
    if (!plainObject(input)) fail(DEVICE_ENROLLMENT_ERRORS.INVALID_REQUEST, "enrollment request must be an object");
    if (Object.keys(input).some((key) => !REQUEST_INPUT_KEYS.has(key))) fail(DEVICE_ENROLLMENT_ERRORS.INVALID_REQUEST, "enrollment request contains unknown fields");
    const enrollmentId = uuid(input.enrollmentId ?? input.enrollment_id, "enrollment_id");
    const organizationId = uuid(input.organizationId ?? input.organization_id, "organization_id");
    const deviceId = uuid(input.deviceId ?? input.device_id, "device_id");
    const label = boundedLabel(input.label);
    const deviceKey = normalizeDeviceKey(input.deviceKey ?? input.device_key);
    const bodyObject = {
      version: VERSION,
      enrollment_id: enrollmentId,
      organization_id: organizationId,
      device_id: deviceId,
      label,
      platform: PLATFORM,
      device_key: { algorithm: deviceKey.algorithm, spki_pem: deviceKey.spki_pem }
    };
    const body = Buffer.from(canonicalJson(bodyObject), "utf8");
    if (body.length > MAX_REQUEST_BYTES) fail(DEVICE_ENROLLMENT_ERRORS.INVALID_REQUEST, "enrollment request is too large");
    return Object.freeze({
      body: Buffer.from(body),
      body_digest: sha256(body),
      enrollment_id: enrollmentId,
      organization_id: organizationId,
      device_id: deviceId,
      label,
      platform: PLATFORM,
      device_key: Object.freeze({ algorithm: deviceKey.algorithm, spki_pem: deviceKey.spki_pem })
    });
  } catch (error) {
    if (error instanceof DeviceEnrollmentError) throw error;
    throw new DeviceEnrollmentError(DEVICE_ENROLLMENT_ERRORS.INVALID_REQUEST, "enrollment request is invalid");
  }
}

/**
 * The enrollment proof binds the method, exact endpoint path, exact body
 * digest, and the SHA-256 digest of the one-time credential. The raw
 * credential is sent only in its dedicated HTTP header. It is signed by the
 * newly generated device key through a callback; this module never accepts or
 * stores a device private key.
 */
export function canonicalEnrollmentProof({ method = METHOD, path, bodyDigest, credentialDigest }) {
  const canonicalMethod = typeof method === "string" ? method.toUpperCase() : "";
  if (canonicalMethod !== METHOD || !validPath(path) || !HASH.test(bodyDigest ?? "") || !HASH.test(credentialDigest ?? "")) {
    throw new DeviceEnrollmentError(DEVICE_ENROLLMENT_ERRORS.INVALID_REQUEST, "enrollment proof input is invalid");
  }
  return [PROOF_PROTOCOL, canonicalMethod, path, bodyDigest, credentialDigest].join("\n");
}

/**
 * Create a one-shot enrollment client. Concurrent calls share one request;
 * successful enrollment is cached locally so setup cannot accidentally submit
 * the one-time enrollment twice. Failed calls are not retried automatically.
 */
export function createDeviceEnrollmentClient(options = {}) {
  const config = normalizeOptions(options);
  let inFlight = null;
  let completed = null;

  async function enroll() {
    if (completed) return clone(completed);
    if (inFlight) return inFlight;
    inFlight = performEnrollment(config).then((result) => {
      completed = result;
      return clone(result);
    }).finally(() => { inFlight = null; });
    return inFlight;
  }

  return Object.freeze({
    config: Object.freeze({
      endpoint: config.endpoint.toString(),
      enrollment_id: config.request.enrollment_id,
      organization_id: config.request.organization_id,
      device_id: config.request.device_id,
      label: config.request.label,
      platform: config.request.platform,
      key_fingerprint: config.key_fingerprint,
      device_key: Object.freeze({ ...config.request.device_key })
    }),
    request: () => cloneRequest(config.request),
    enroll,
    status: () => completed ? "enrolled" : (inFlight ? "in_flight" : "ready")
  });
}

export async function enrollDevice(options = {}) {
  return createDeviceEnrollmentClient(options).enroll();
}

/** Return the non-secret evidence envelope consumed by setup state adapters. */
export function deviceEnrollmentEvidence(result) {
  if (!plainObject(result)) throw new DeviceEnrollmentError(DEVICE_ENROLLMENT_ERRORS.BINDING, "enrollment result is invalid");
  const enrollmentId = uuid(result.enrollment_id ?? result.enrollmentId, "enrollment_id");
  const organizationId = uuid(result.organization_id ?? result.organizationId, "organization_id");
  const deviceId = uuid(result.device_id ?? result.deviceId, "device_id");
  const deviceKeyEpoch = positiveInteger(result.device_key_epoch, "device_key_epoch");
  if (typeof result.key_fingerprint !== "string" || !FINGERPRINT.test(result.key_fingerprint)) throw new DeviceEnrollmentError(DEVICE_ENROLLMENT_ERRORS.BINDING, "enrollment key fingerprint is invalid");
  return Object.freeze({ organization_id: organizationId, device_id: deviceId, enrollment_id: enrollmentId, device_key_epoch: deviceKeyEpoch, key_fingerprint: result.key_fingerprint });
}

async function performEnrollment(config) {
  const request = config.request;
  const path = config.endpoint.pathname;
  const proof = canonicalEnrollmentProof({ path, bodyDigest: request.body_digest, credentialDigest: config.credential_digest });
  const signature = await signProof(config.signer, {
    version: VERSION,
    method: METHOD,
    path,
    body_digest: request.body_digest,
    credential_digest: config.credential_digest,
    body: Buffer.from(request.body),
    bytes: Buffer.from(proof, "utf8")
  }, request.device_key);
  const headers = {
    accept: "application/json",
    "content-type": "application/json",
    [PROOF_HEADER]: signature,
    [CREDENTIAL_HEADER]: config.credential
  };
  const response = await requestHttp(config, headers);
  const parsed = await parseResponse(response, config.maxResponseBytes);
  const safeResponse = validateResponseBinding(parsed, request, config.key_fingerprint);
  const evidence = deviceEnrollmentEvidence({ enrollment_id: request.enrollment_id, organization_id: request.organization_id, device_id: request.device_id, device_key_epoch: safeResponse.device_key_epoch, key_fingerprint: config.key_fingerprint });
  return Object.freeze({
    status: "enrolled",
    enrollment_id: request.enrollment_id,
    organization_id: request.organization_id,
    device_id: request.device_id,
    label: request.label,
    platform: request.platform,
    device_key: Object.freeze({ ...request.device_key }),
    key_fingerprint: config.key_fingerprint,
    request_hash: request.body_digest,
    request_id: safeResponse.request_id ?? null,
    device_key_epoch: safeResponse.device_key_epoch,
    control: Object.freeze({ ...safeResponse.control }),
    server: Object.freeze(safeResponse.server),
    evidence
  });
}

async function signProof(signer, input, deviceKey) {
  const callback = typeof signer === "function" ? signer : signer?.sign;
  if (typeof callback !== "function") fail(DEVICE_ENROLLMENT_ERRORS.SIGNER, "a native device signing callback is required");
  let value;
  try {
    value = await callback({ ...input, body: Buffer.from(input.body), bytes: Buffer.from(input.bytes) });
  } catch {
    fail(DEVICE_ENROLLMENT_ERRORS.SIGNER, "device enrollment proof signing failed");
  }
  if (value && typeof value === "object" && !Buffer.isBuffer(value)) value = value.signature;
  const signature = decodeSignature(value);
  const publicKey = crypto.createPublicKey(deviceKey.spki_pem);
  let valid = false;
  try {
    valid = deviceKey.algorithm === "ed25519"
      ? crypto.verify(null, Buffer.from(input.bytes), publicKey, signature)
      : crypto.verify("sha256", Buffer.from(input.bytes), { key: publicKey, dsaEncoding: "ieee-p1363" }, signature);
  } catch { valid = false; }
  if (!valid) fail(DEVICE_ENROLLMENT_ERRORS.SIGNER, "device enrollment proof does not match the enrolled public key");
  return signature.toString("base64");
}

async function requestHttp(config, headers) {
  const controller = new AbortController();
  let timer;
  let raceTimer;
  let timedOut = false;
  try {
    timer = setTimeout(() => { timedOut = true; controller.abort(); }, config.timeoutMs);
    return await Promise.race([
      Promise.resolve(config.fetchImpl(config.endpoint.toString(), {
        method: METHOD,
        headers,
        body: Buffer.from(config.request.body),
        redirect: "error",
        signal: controller.signal
      })),
      new Promise((_, reject) => {
        raceTimer = setTimeout(() => {
          timedOut = true;
          controller.abort();
          reject(new DeviceEnrollmentError(DEVICE_ENROLLMENT_ERRORS.TIMEOUT, "device enrollment request timed out"));
        }, config.timeoutMs);
      })
    ]);
  } catch (error) {
    if (error instanceof DeviceEnrollmentError) throw error;
    if (timedOut || error?.name === "AbortError") throw new DeviceEnrollmentError(DEVICE_ENROLLMENT_ERRORS.TIMEOUT, "device enrollment request timed out");
    throw new DeviceEnrollmentError(DEVICE_ENROLLMENT_ERRORS.NETWORK, "device enrollment request could not be completed");
  } finally {
    clearTimeout(timer);
    if (raceTimer) clearTimeout(raceTimer);
  }
}

async function parseResponse(response, maxBytes) {
  if (!response || !Number.isInteger(response.status)) fail(DEVICE_ENROLLMENT_ERRORS.RESPONSE, "device enrollment response is invalid");
  if (response.status >= 300 && response.status < 400) fail(DEVICE_ENROLLMENT_ERRORS.REDIRECT, "device enrollment redirects are not permitted");
  if (response.status !== 201) fail(DEVICE_ENROLLMENT_ERRORS.HTTP, `device enrollment request failed with HTTP ${response.status}`);
  const bytes = await readBoundedResponse(response, maxBytes);
  try {
    return parseControlBundleJson(bytes, { maxBytes, maxDepth: MAX_RESPONSE_DEPTH });
  } catch {
    fail(DEVICE_ENROLLMENT_ERRORS.RESPONSE, "device enrollment response is not valid canonical JSON");
  }
}

async function readBoundedResponse(response, maxBytes) {
  const declared = response.headers?.get?.("content-length") ?? response.headers?.["content-length"] ?? response.headers?.["Content-Length"];
  if (declared !== undefined && declared !== null && declared !== "") {
    if (!/^\d+$/.test(String(declared)) || Number(declared) > maxBytes) fail(DEVICE_ENROLLMENT_ERRORS.RESPONSE_TOO_LARGE, "device enrollment response is too large");
  }
  const chunks = [];
  let total = 0;
  const add = (value) => {
    const chunk = Buffer.from(value);
    total += chunk.length;
    if (total > maxBytes) fail(DEVICE_ENROLLMENT_ERRORS.RESPONSE_TOO_LARGE, "device enrollment response is too large");
    chunks.push(chunk);
  };
  try {
    if (response.body?.getReader) {
      const reader = response.body.getReader();
      try { while (true) { const next = await reader.read(); if (next.done) break; add(next.value); } }
      finally { reader.releaseLock?.(); }
    } else if (response.body && typeof response.body[Symbol.asyncIterator] === "function") {
      for await (const chunk of response.body) add(chunk);
    } else if (typeof response.arrayBuffer === "function") {
      add(await response.arrayBuffer());
    } else if (typeof response.text === "function") {
      add(Buffer.from(await response.text(), "utf8"));
    } else {
      fail(DEVICE_ENROLLMENT_ERRORS.RESPONSE, "device enrollment response body is unreadable");
    }
  } catch (error) {
    if (error instanceof DeviceEnrollmentError) throw error;
    fail(DEVICE_ENROLLMENT_ERRORS.RESPONSE, "device enrollment response body could not be read");
  }
  if (total === 0) fail(DEVICE_ENROLLMENT_ERRORS.RESPONSE, "device enrollment response body is empty");
  try { return Buffer.from(new TextDecoder("utf-8", { fatal: true }).decode(Buffer.concat(chunks, total)), "utf8"); }
  catch { fail(DEVICE_ENROLLMENT_ERRORS.RESPONSE, "device enrollment response is not valid UTF-8"); }
}

function validateResponseBinding(value, request, expectedFingerprint) {
  if (!plainObject(value)) fail(DEVICE_ENROLLMENT_ERRORS.RESPONSE, "device enrollment response must be an object");
  exactKeys(value, RESPONSE_KEYS, "device enrollment response");
  rejectSecrets(value, 0);
  if (typeof value.request_id !== "string" || !SAFE_ID.test(value.request_id)) fail(DEVICE_ENROLLMENT_ERRORS.RESPONSE, "device enrollment response request_id is invalid");
  const enrollment = responseObject(value.enrollment, ENROLLMENT_KEYS, "enrollment");
  if (enrollment.version !== VERSION || enrollment.enrollment_id !== request.enrollment_id || enrollment.organization_id !== request.organization_id || enrollment.device_id !== request.device_id) fail(DEVICE_ENROLLMENT_ERRORS.BINDING, "device enrollment response binding does not match");
  if (enrollment.status !== "active") fail(DEVICE_ENROLLMENT_ERRORS.BINDING, "device enrollment response does not activate the device");
  if (enrollment.key_algorithm !== request.device_key.algorithm) fail(DEVICE_ENROLLMENT_ERRORS.BINDING, "device enrollment response key algorithm does not match");
  const deviceKeyEpoch = positiveInteger(enrollment.device_key_epoch, "device_key_epoch");
  const control = responseObject(enrollment.control, CONTROL_KEYS, "control");
  if (!Number.isSafeInteger(control.format_epoch) || control.format_epoch !== 2) fail(DEVICE_ENROLLMENT_ERRORS.BINDING, "device enrollment control format is unsupported");
  if (typeof control.issuer !== "string" || !SAFE_ID.test(control.issuer) || typeof control.key_id !== "string" || !SAFE_ID.test(control.key_id)) fail(DEVICE_ENROLLMENT_ERRORS.RESPONSE, "device enrollment control identifiers are invalid");
  const controlKey = normalizeEd25519PublicKey(control.public_key);
  const refreshHint = responseObject(control.refresh_hint, REFRESH_HINT_KEYS, "refresh hint");
  if (typeof refreshHint.key_id !== "string" || !SAFE_ID.test(refreshHint.key_id) || refreshHint.algorithm !== "ed25519") fail(DEVICE_ENROLLMENT_ERRORS.RESPONSE, "device enrollment refresh hint trust metadata is invalid");
  const refreshHintKey = normalizeEd25519PublicKey(refreshHint.public_key);
  if (refreshHintKey === controlKey) fail(DEVICE_ENROLLMENT_ERRORS.BINDING, "device enrollment refresh hint key must be purpose-separated from the control key");
  if (typeof control.bundle_path !== "string" || control.bundle_path.length < 1 || control.bundle_path.length > 1024 || CONTROL.test(control.bundle_path)) fail(DEVICE_ENROLLMENT_ERRORS.RESPONSE, "device enrollment bundle path is invalid");
  if (control.bundle_path !== `/v1/organizations/${request.organization_id}/bundles/${request.device_id}`) fail(DEVICE_ENROLLMENT_ERRORS.BINDING, "device enrollment control path does not match the device");
  return {
    request_id: value.request_id,
    device_key_epoch: deviceKeyEpoch,
    control: { ...control, public_key: controlKey, refresh_hint: { key_id: refreshHint.key_id, algorithm: "ed25519", public_key: refreshHintKey } },
    server: {
      version: VERSION,
      enrollment_id: request.enrollment_id,
      organization_id: request.organization_id,
      device_id: request.device_id,
      status: enrollment.status,
      key_algorithm: enrollment.key_algorithm,
      device_key_epoch: deviceKeyEpoch,
      control: { format_epoch: 2, issuer: control.issuer, key_id: control.key_id, public_key: controlKey, bundle_path: control.bundle_path, refresh_hint: { key_id: refreshHint.key_id, algorithm: "ed25519", public_key: refreshHintKey } },
      key_fingerprint: expectedFingerprint
    }
  };
}

function normalizeEd25519PublicKey(value) {
  if (typeof value !== "string" || Buffer.byteLength(value, "utf8") > MAX_PEM_BYTES || /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(value) || /PRIVATE KEY/.test(value)) fail(DEVICE_ENROLLMENT_ERRORS.RESPONSE, "device enrollment control public key is invalid");
  let key;
  try { key = crypto.createPublicKey(value); }
  catch { fail(DEVICE_ENROLLMENT_ERRORS.RESPONSE, "device enrollment control public key is invalid"); }
  if (key.type !== "public" || key.asymmetricKeyType !== "ed25519") fail(DEVICE_ENROLLMENT_ERRORS.RESPONSE, "device enrollment control public key is invalid");
  const canonical = key.export({ type: "spki", format: "pem" }).toString();
  if (canonical !== value) fail(DEVICE_ENROLLMENT_ERRORS.RESPONSE, "device enrollment control public key is not canonical");
  return canonical;
}

function responseObject(value, allowed, label) {
  if (!plainObject(value)) fail(DEVICE_ENROLLMENT_ERRORS.RESPONSE, `${label} response must be an object`);
  exactKeys(value, allowed, `${label} response`);
  return value;
}

function normalizeOptions(input) {
  if (!plainObject(input)) fail(DEVICE_ENROLLMENT_ERRORS.INVALID_CONFIG, "device enrollment options must be an object");
  for (const forbidden of ["privateKey", "private_key", "devicePrivateKey", "device_private_key", "bearerToken", "bearer_token", "authorization"]) {
    if (Object.hasOwn(input, forbidden)) fail(DEVICE_ENROLLMENT_ERRORS.INVALID_CONFIG, "device enrollment options must not contain secret material");
  }
  const request = buildDeviceEnrollmentRequest({
    enrollmentId: input.enrollmentId ?? input.enrollment_id,
    organizationId: input.organizationId ?? input.organization_id,
    deviceId: input.deviceId ?? input.device_id,
    label: input.label,
    deviceKey: input.deviceKey ?? input.device_key
  });
  const baseUrl = input.baseUrl ?? input.url;
  if (typeof baseUrl !== "string") fail(DEVICE_ENROLLMENT_ERRORS.INVALID_URL, "device enrollment baseUrl is required");
  const parsed = validateBaseUrl(baseUrl, input.loopbackTestMode === true || input.allowLoopbackHttp === true);
  const endpoint = new URL(`enrollments/${encodeURIComponent(request.enrollment_id)}`, parsed);
  if (!/^\/v1\/enrollments\/[0-9a-f-]+$/i.test(endpoint.pathname)) fail(DEVICE_ENROLLMENT_ERRORS.INVALID_URL, "device enrollment endpoint must be under /v1");
  const signer = input.signer ?? input.sign;
  if (signer && typeof signer === "object" && Object.hasOwn(signer, "privateKey")) fail(DEVICE_ENROLLMENT_ERRORS.INVALID_CONFIG, "device signer must not contain private key material");
  const credential = input.credential ?? input.enrollmentCredential ?? input.enrollment_credential;
  if (typeof credential !== "string" || !BASE64URL_CREDENTIAL.test(credential) || Buffer.from(credential, "base64url").length !== 32 || Buffer.from(credential, "base64url").toString("base64url") !== credential) fail(DEVICE_ENROLLMENT_ERRORS.INVALID_CONFIG, "a 32-byte enrollment credential is required");
  const keyFingerprint = input.keyFingerprint ?? input.key_fingerprint;
  if (typeof keyFingerprint !== "string" || !FINGERPRINT.test(keyFingerprint)) fail(DEVICE_ENROLLMENT_ERRORS.INVALID_CONFIG, "a native device key fingerprint is required");
  if (keyFingerprint !== publicKeyFingerprint(request.device_key.spki_pem)) fail(DEVICE_ENROLLMENT_ERRORS.INVALID_CONFIG, "native device key fingerprint does not match the public key");
  if (Object.hasOwn(input, "headers") || Object.hasOwn(input, "requestHeaders")) fail(DEVICE_ENROLLMENT_ERRORS.INVALID_CONFIG, "custom enrollment headers are not permitted");
  const fetchImpl = input.fetchImpl ?? input.fetch ?? globalThis.fetch;
  if (typeof fetchImpl !== "function") fail(DEVICE_ENROLLMENT_ERRORS.INVALID_CONFIG, "fetchImpl must be a function");
  const timeoutMs = boundedInteger(input.timeoutMs ?? DEFAULT_TIMEOUT_MS, 1, 120_000, "timeoutMs");
  const maxResponseBytes = boundedInteger(input.maxResponseBytes ?? DEFAULT_MAX_RESPONSE_BYTES, 1, 4 * 1024 * 1024, "maxResponseBytes");
  return Object.freeze({ endpoint, request, signer, fetchImpl, timeoutMs, maxResponseBytes, credential, credential_digest: sha256(Buffer.from(credential, "utf8")), key_fingerprint: keyFingerprint });
}

function validateBaseUrl(value, allowLoopbackHttp) {
  let parsed;
  try { parsed = new URL(value.endsWith("/") ? value : `${value}/`); }
  catch { fail(DEVICE_ENROLLMENT_ERRORS.INVALID_URL, "device enrollment baseUrl is invalid"); }
  const hostname = parsed.hostname.replace(/^\[|\]$/g, "");
  if (parsed.protocol !== "https:" && !(allowLoopbackHttp && parsed.protocol === "http:" && LOOPBACK.has(hostname))) fail(DEVICE_ENROLLMENT_ERRORS.INVALID_URL, "device enrollment requires HTTPS");
  if (parsed.username || parsed.password || parsed.search || parsed.hash) fail(DEVICE_ENROLLMENT_ERRORS.INVALID_URL, "device enrollment URL cannot contain credentials, query, or fragment");
  if (!/^\/v1\/?$/.test(parsed.pathname)) fail(DEVICE_ENROLLMENT_ERRORS.INVALID_URL, "device enrollment baseUrl must end at /v1");
  parsed.pathname = "/v1/";
  return parsed;
}

function normalizeDeviceKey(value) {
  if (!plainObject(value)) fail(DEVICE_ENROLLMENT_ERRORS.INVALID_KEY, "device_key must be an object");
  if (Object.keys(value).some((key) => !["algorithm", "spki_pem", "spkiPem"].includes(key))) fail(DEVICE_ENROLLMENT_ERRORS.INVALID_KEY, "device_key contains unknown fields");
  const algorithm = value.algorithm;
  if (!["p256-sha256", "ed25519"].includes(algorithm)) fail(DEVICE_ENROLLMENT_ERRORS.INVALID_KEY, "device key algorithm is invalid");
  const pem = value.spki_pem ?? value.spkiPem;
  if (typeof pem !== "string" || Buffer.byteLength(pem, "utf8") > MAX_PEM_BYTES || /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(pem) || /PRIVATE KEY/.test(pem)) fail(DEVICE_ENROLLMENT_ERRORS.INVALID_KEY, "device public key encoding is invalid");
  let key;
  try { key = crypto.createPublicKey(pem); }
  catch { fail(DEVICE_ENROLLMENT_ERRORS.INVALID_KEY, "device public key encoding is invalid"); }
  if (key.type !== "public" || (algorithm === "ed25519" && key.asymmetricKeyType !== "ed25519") || (algorithm === "p256-sha256" && (key.asymmetricKeyType !== "ec" || key.asymmetricKeyDetails?.namedCurve !== "prime256v1"))) fail(DEVICE_ENROLLMENT_ERRORS.INVALID_KEY, "device public key algorithm does not match");
  const canonical = key.export({ type: "spki", format: "pem" }).toString();
  if (Buffer.byteLength(canonical, "utf8") < 80 || Buffer.byteLength(canonical, "utf8") > MAX_PEM_BYTES) fail(DEVICE_ENROLLMENT_ERRORS.INVALID_KEY, "device public key encoding is invalid");
  return { algorithm, spki_pem: canonical };
}

function boundedLabel(value) {
  if (typeof value !== "string" || value.length < 1 || value.length > MAX_LABEL_CODE_POINTS || [...value].length > MAX_LABEL_CODE_POINTS || CONTROL.test(value) || value.trim().length === 0) fail(DEVICE_ENROLLMENT_ERRORS.INVALID_REQUEST, "device label is invalid");
  return value;
}

function boundedText(value, label, maxBytes, required) {
  if (value === undefined && !required) return value;
  if (typeof value !== "string" || value.length < (required ? 1 : 0) || value.length > maxBytes || CONTROL.test(value)) fail(DEVICE_ENROLLMENT_ERRORS.RESPONSE, `${label} is invalid`);
  return value;
}

function uuid(value, label) {
  if (typeof value !== "string" || !UUID.test(value)) fail(DEVICE_ENROLLMENT_ERRORS.INVALID_REQUEST, `${label} is invalid`);
  return value.toLowerCase();
}

function decodeSignature(value) {
  if (Buffer.isBuffer(value)) {
    if (value.length !== 64) fail(DEVICE_ENROLLMENT_ERRORS.SIGNER, "device enrollment proof signature is invalid");
    return Buffer.from(value);
  }
  if (typeof value !== "string" || !BASE64.test(value)) fail(DEVICE_ENROLLMENT_ERRORS.SIGNER, "device enrollment proof signature is invalid");
  const bytes = Buffer.from(value, "base64");
  if (bytes.length !== 64 || bytes.toString("base64") !== value) fail(DEVICE_ENROLLMENT_ERRORS.SIGNER, "device enrollment proof signature is invalid");
  return bytes;
}

function rejectSecrets(value, depth) {
  if (depth > MAX_RESPONSE_DEPTH) fail(DEVICE_ENROLLMENT_ERRORS.RESPONSE, "device enrollment response is too deeply nested");
  if (Array.isArray(value)) { for (const child of value) rejectSecrets(child, depth + 1); return; }
  if (!value || typeof value !== "object") return;
  for (const [key, child] of Object.entries(value)) {
    if (SECRET_KEY.test(key)) fail(DEVICE_ENROLLMENT_ERRORS.RESPONSE, "device enrollment response contains prohibited data");
    rejectSecrets(child, depth + 1);
  }
}

function exactKeys(value, allowed, label) {
  if (Object.keys(value).some((key) => !allowed.has(key))) fail(DEVICE_ENROLLMENT_ERRORS.RESPONSE, `${label} contains unknown fields`);
}

function validPath(value) { return typeof value === "string" && /^\/v1\/enrollments\/[0-9a-f-]+$/i.test(value) && !CONTROL.test(value); }
function boundedInteger(value, min, max, label) { if (!Number.isSafeInteger(value) || value < min || value > max) fail(DEVICE_ENROLLMENT_ERRORS.INVALID_CONFIG, `${label} is out of bounds`); return value; }
function positiveInteger(value, label) { if (!Number.isSafeInteger(value) || value < 1) fail(DEVICE_ENROLLMENT_ERRORS.BINDING, `${label} is invalid`); return value; }
function sha256(value) { return crypto.createHash("sha256").update(value).digest("hex"); }
function publicKeyFingerprint(pem) { return `SHA256:${crypto.createHash("sha256").update(crypto.createPublicKey(pem).export({ type: "spki", format: "der" })).digest("base64url")}`; }
function plainObject(value) { const prototype = value && typeof value === "object" && !Array.isArray(value) ? Object.getPrototypeOf(value) : undefined; return prototype === Object.prototype || prototype === null; }
function cloneRequest(request) { return { ...request, body: Buffer.from(request.body), device_key: { ...request.device_key } }; }
function clone(value) { return structuredClone(value); }
function fail(code, message, details) { throw new DeviceEnrollmentError(code, message, details); }
