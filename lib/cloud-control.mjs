import crypto from "node:crypto";
import path from "node:path";

import {
  CONTROL_BUNDLE_MAX_BYTES,
  ControlBundleError,
  applyControlBundle as applyV2ControlBundle,
  loadControlBundleState,
  parseControlBundleJson,
  verifyCachedControlBundle,
  verifyControlBundle
} from "./control-bundle-v2.mjs";
import {
  canonicalDeviceRequest,
  createDeviceSignature,
  sha256
} from "../apps/cloud-api/src/auth.mjs";

export const CLOUD_CONTROL_MAX_RESPONSE_BYTES = CONTROL_BUNDLE_MAX_BYTES;
export const CLOUD_CONTROL_DEFAULT_TIMEOUT_MS = 15_000;

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const NONCE = /^[A-Za-z0-9][A-Za-z0-9._:-]{31,127}$/;
const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const LOOPBACK = new Set(["localhost", "127.0.0.1", "::1"]);

export const CLOUD_CONTROL_ERRORS = Object.freeze({
  INVALID_CONFIG: "ERR_CLOUD_CONTROL_CONFIG",
  INVALID_URL: "ERR_CLOUD_CONTROL_URL",
  TIMEOUT: "ERR_CLOUD_CONTROL_TIMEOUT",
  NETWORK: "ERR_CLOUD_CONTROL_NETWORK",
  HTTP: "ERR_CLOUD_CONTROL_HTTP",
  REDIRECT: "ERR_CLOUD_CONTROL_REDIRECT",
  RESPONSE: "ERR_CLOUD_CONTROL_RESPONSE",
  RESPONSE_TOO_LARGE: "ERR_CLOUD_CONTROL_RESPONSE_TOO_LARGE",
  SIGNATURE: "ERR_CLOUD_CONTROL_SIGNATURE",
  OFFLINE_UNAVAILABLE: "ERR_CLOUD_CONTROL_OFFLINE_UNAVAILABLE",
  STATE: "ERR_CLOUD_CONTROL_STATE"
});

export class CloudControlError extends Error {
  constructor(code, message, details = undefined) {
    super(message);
    this.name = "CloudControlError";
    this.code = code;
    if (details !== undefined) this.details = details;
  }
}

/**
 * Construct a client for the device-authenticated ControlBundle v2 endpoint.
 * No network request or filesystem write happens during construction.
 */
export function createCloudControlClient(input = {}) {
  const config = normalizeOptions(input);
  let lastFetchAt = null;
  let lastFetchError = null;

  async function fetchBundle() {
    try {
      const { bundle, now } = await requestBundle(config);
      const state = loadControlBundleState(config.statePath);
      const verified = verifyControlBundle(bundle, config.trust, {
        now,
        audience: config.audience,
        sequenceState: state
      });
      lastFetchAt = new Date(now).toISOString();
      lastFetchError = null;
      return verified;
    } catch (error) {
      const stable = stableError(error);
      lastFetchError = stable.code;
      throw stable;
    }
  }

  async function sync() {
    const bundle = await fetchBundle();
    return applyBundle(bundle);
  }

  function applyBundle(bundle) {
    let previous;
    try { previous = loadControlBundleState(config.statePath).active_bundle; }
    catch (error) { throw stableError(error); }
    try {
      const applied = applyV2ControlBundle(bundle, config.trust, config.statePath, {
        now: clockMilliseconds(config.clock()),
        audience: config.audience
      });
      return {
        status: previous?.sequence === applied.sequence ? "unchanged" : "updated",
        sequence: applied.sequence,
        bundle: applied,
        last_fetch_at: lastFetchAt,
        last_fetch_error: null
      };
    } catch (error) {
      const stable = stableError(error);
      lastFetchError = stable.code;
      throw stable;
    }
  }

  function loadCached() {
    try {
      const now = clockMilliseconds(config.clock());
      const state = loadControlBundleState(config.statePath);
      if (!state.active_bundle) throw new CloudControlError(CLOUD_CONTROL_ERRORS.OFFLINE_UNAVAILABLE, "No cached control bundle is available");
      return verifyCachedControlBundle(state.active_bundle, config.trust, {
        now,
        audience: config.audience,
        sequenceState: state
      });
    } catch (error) {
      throw stableError(error);
    }
  }

  function status() {
    try {
      const state = loadControlBundleState(config.statePath);
      if (!state.active_bundle) {
        return { available: false, state: "missing", sequence: 0, last_fetch_at: lastFetchAt, last_fetch_error: lastFetchError };
      }
      const bundle = loadCached();
      return {
        available: true,
        state: "cached",
        sequence: bundle.sequence,
        expires_at: bundle.expires_at,
        offline_expires_at: new Date(Date.parse(bundle.expires_at) + bundle.offline_ttl_ms).toISOString(),
        global_revoked: bundle.global_revoked,
        revoked_devices: bundle.revoked_devices.length,
        revoked_agents: bundle.revoked_agents.length,
        revoked_capabilities: bundle.revoked_capabilities.length,
        last_fetch_at: lastFetchAt,
        last_fetch_error: lastFetchError
      };
    } catch (error) {
      const stable = stableError(error);
      return { available: false, state: "invalid", error: stable.code, last_fetch_at: lastFetchAt, last_fetch_error: lastFetchError };
    }
  }

  return Object.freeze({
    config,
    fetchBundle,
    sync,
    apply: applyBundle,
    applyControlBundle: applyBundle,
    loadCached,
    loadOffline: loadCached,
    status
  });
}

export const createCloudControlSyncClient = createCloudControlClient;

/** Fetch and cryptographically verify a bundle without installing it. */
export async function fetchCloudControlBundle(options = {}) {
  return createCloudControlClient(options).fetchBundle();
}

export const fetchControlBundle = fetchCloudControlBundle;

/** Fetch, verify, and atomically install the current bundle head. */
export async function syncCloudControl(options = {}) {
  return createCloudControlClient(options).sync();
}

export const syncControlBundle = syncCloudControl;

/** Load and verify the durable bundle while offline, including its offline TTL. */
export function loadCachedCloudControlBundle(options = {}) {
  return createCloudControlClient(options).loadCached();
}

export const loadOfflineControlBundle = loadCachedCloudControlBundle;
export const loadCachedControlBundle = loadCachedCloudControlBundle;
export const getCloudControlStatus = (options = {}) => createCloudControlClient(options).status();
export const applyControlBundle = applyV2ControlBundle;

/**
 * Build only the non-secret config fragment needed by an enrolled device.
 * Private keys, tokens, and other secret-looking input fields are deliberately
 * ignored; this function never writes a file.
 */
export function buildCloudControlConfigFragment(input = {}) {
  if (!plainObject(input)) throw new CloudControlError(CLOUD_CONTROL_ERRORS.INVALID_CONFIG, "cloud control config must be an object");
  const organizationId = input.organizationId ?? input.organization_id;
  const deviceId = input.deviceId ?? input.device_id;
  const issuer = input.issuer ?? input.controlIssuer;
  const keyId = input.keyId ?? input.key_id ?? input.controlKeyId;
  const publicKey = input.publicKey ?? input.public_key ?? input.controlPublicKey;
  if (!UUID.test(organizationId ?? "") || !UUID.test(deviceId ?? "")) {
    throw new CloudControlError(CLOUD_CONTROL_ERRORS.INVALID_CONFIG, "organization_id and device_id must be UUIDs");
  }
  if (!IDENTIFIER.test(issuer ?? "") || !IDENTIFIER.test(keyId ?? "")) {
    throw new CloudControlError(CLOUD_CONTROL_ERRORS.INVALID_CONFIG, "issuer and key_id must be safe identifiers");
  }
  assertPublicKey(publicKey);
  if (input.required !== undefined && input.required !== true) throw new CloudControlError(CLOUD_CONTROL_ERRORS.INVALID_CONFIG, "required must be true");
  if ((input.capabilityRequired ?? input.capability_required) !== undefined && (input.capabilityRequired ?? input.capability_required) !== true) throw new CloudControlError(CLOUD_CONTROL_ERRORS.INVALID_CONFIG, "capability_required must be true");
  const url = input.url ?? input.baseUrl ?? input.endpoint;
  if (url !== undefined) validateEndpoint(url, input.loopbackTestMode === true || input.allowLoopbackHttp === true);
  const statePath = input.statePath ?? input.state_path;
  if (statePath !== undefined && (!path.isAbsolute(statePath) || path.basename(statePath) === "." || path.basename(statePath) === "..")) {
    throw new CloudControlError(CLOUD_CONTROL_ERRORS.INVALID_CONFIG, "state_path must be an absolute file path");
  }
  const devicePrivateKeyPath = input.devicePrivateKeyPath ?? input.device_private_key_path;
  if (devicePrivateKeyPath !== undefined && (!path.isAbsolute(devicePrivateKeyPath) || path.basename(devicePrivateKeyPath) === "." || path.basename(devicePrivateKeyPath) === "..")) throw new CloudControlError(CLOUD_CONTROL_ERRORS.INVALID_CONFIG, "device_private_key_path must be an absolute file path");
  const allowOffline = input.allowOffline ?? input.allow_offline;
  if (allowOffline !== undefined && typeof allowOffline !== "boolean") throw new CloudControlError(CLOUD_CONTROL_ERRORS.INVALID_CONFIG, "allow_offline must be boolean");
  const refreshSeconds = input.refreshSeconds ?? input.refresh_seconds ?? (url !== undefined ? 60 : undefined);
  if (refreshSeconds !== undefined && (!Number.isSafeInteger(refreshSeconds) || refreshSeconds < 15 || refreshSeconds > 3600)) throw new CloudControlError(CLOUD_CONTROL_ERRORS.INVALID_CONFIG, "refresh_seconds must be between 15 and 3600");
  const control = {
    required: true,
    capability_required: true,
    public_key: publicKey,
    issuer,
    key_id: keyId,
    organization_id: organizationId,
    device_id: deviceId
  };
  if (url !== undefined) control.url = String(url);
  if (statePath !== undefined) control.state_path = statePath;
  if (refreshSeconds !== undefined) control.refresh_seconds = refreshSeconds;
  if (allowOffline !== undefined) control.allow_offline = allowOffline;
  if (devicePrivateKeyPath !== undefined) control.device_private_key_path = devicePrivateKeyPath;
  return { control_v2: control };
}

export const buildControlConfigFragment = buildCloudControlConfigFragment;
export const buildCloudControlConfig = buildCloudControlConfigFragment;
export const buildEnrollmentConfigFragment = buildCloudControlConfigFragment;
export const buildControlV2Config = buildCloudControlConfigFragment;

async function requestBundle(config) {
  const body = Buffer.alloc(0);
  const timestamp = clockMilliseconds(config.clock());
  const nonce = await Promise.resolve(config.nonce());
  if (typeof nonce !== "string" || !NONCE.test(nonce)) throw new CloudControlError(CLOUD_CONTROL_ERRORS.INVALID_CONFIG, "nonce is invalid");
  const target = `${config.endpoint.pathname}${config.endpoint.search}`;
  const bodyDigest = sha256(body);
  const canonical = canonicalDeviceRequest({ method: "GET", path: target, body_digest: bodyDigest, timestamp, nonce });
  const signature = await signRequest(config, { canonical, method: "GET", path: target, body, bodyDigest, timestamp, nonce });
  const headers = {
    accept: "application/json",
    "AgentPass-Device": config.deviceId,
    "AgentPass-Timestamp": String(timestamp),
    "AgentPass-Nonce": nonce,
    "AgentPass-Content-SHA256": bodyDigest,
    "AgentPass-Signature": signature
  };
  const controller = new AbortController();
  let timedOut = false;
  let raceTimer;
  const timer = setTimeout(() => { timedOut = true; controller.abort(); }, config.timeoutMs);
  try {
    const response = await Promise.race([
      Promise.resolve(config.fetchImpl(config.endpoint.toString(), { method: "GET", headers, redirect: "error", signal: controller.signal })),
      new Promise((_, reject) => { raceTimer = setTimeout(() => { timedOut = true; controller.abort(); reject(new CloudControlError(CLOUD_CONTROL_ERRORS.TIMEOUT, "cloud control request timed out")); }, config.timeoutMs); })
    ]);
    if (!response || !Number.isInteger(response.status)) throw new CloudControlError(CLOUD_CONTROL_ERRORS.RESPONSE, "cloud control response is invalid");
    if (response.status >= 300 && response.status < 400) throw new CloudControlError(CLOUD_CONTROL_ERRORS.REDIRECT, "cloud control redirects are not permitted");
    if (response.status < 200 || response.status >= 300) throw new CloudControlError(CLOUD_CONTROL_ERRORS.HTTP, `cloud control request failed with HTTP ${response.status}`);
    const bytes = await readBoundedBody(response, config.maxResponseBytes);
    const parsed = parseControlBundleJson(bytes, { maxBytes: config.maxResponseBytes });
    const bundle = extractBundle(parsed);
    return { bundle, now: clockMilliseconds(config.clock()) };
  } catch (error) {
    if (error instanceof CloudControlError) throw error;
    if (error instanceof ControlBundleError) throw error;
    if (timedOut || error?.name === "AbortError") throw new CloudControlError(CLOUD_CONTROL_ERRORS.TIMEOUT, "cloud control request timed out");
    throw new CloudControlError(CLOUD_CONTROL_ERRORS.NETWORK, "cloud control request could not be completed");
  } finally {
    clearTimeout(timer);
    if (raceTimer) clearTimeout(raceTimer);
  }
}

async function signRequest(config, request) {
  let result;
  try {
    const sign = typeof config.signer === "function" ? config.signer : config.signer?.sign;
    if (sign) result = await sign({ ...request });
    else if (config.privateKey !== undefined) result = createDeviceSignature({ method: request.method, path: request.path, body_digest: request.bodyDigest, timestamp: request.timestamp, nonce: request.nonce }, config.privateKey);
    else throw new Error("missing signer");
  } catch {
    throw new CloudControlError(CLOUD_CONTROL_ERRORS.SIGNATURE, "device request signing failed");
  }
  if (result && typeof result === "object" && !Buffer.isBuffer(result)) result = result.signature;
  if (Buffer.isBuffer(result)) result = result.toString("base64");
  if (typeof result !== "string" || !BASE64.test(result) || Buffer.from(result, "base64").length !== 64 || Buffer.from(result, "base64").toString("base64") !== result) {
    throw new CloudControlError(CLOUD_CONTROL_ERRORS.SIGNATURE, "signer returned an invalid device signature");
  }
  return result;
}

async function readBoundedBody(response, maxBytes) {
  const declared = response.headers?.get?.("content-length") ?? response.headers?.["content-length"] ?? response.headers?.["Content-Length"];
  if (declared !== undefined && declared !== null && declared !== "") {
    if (!/^\d+$/.test(String(declared)) || Number(declared) > maxBytes) throw new CloudControlError(CLOUD_CONTROL_ERRORS.RESPONSE_TOO_LARGE, "cloud control response is too large");
  }
  const chunks = [];
  let total = 0;
  const add = (value) => {
    const chunk = Buffer.from(value);
    total += chunk.length;
    if (total > maxBytes) throw new CloudControlError(CLOUD_CONTROL_ERRORS.RESPONSE_TOO_LARGE, "cloud control response is too large");
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
      throw new CloudControlError(CLOUD_CONTROL_ERRORS.RESPONSE, "cloud control response body is unreadable");
    }
  } catch (error) {
    if (error instanceof CloudControlError) throw error;
    throw new CloudControlError(CLOUD_CONTROL_ERRORS.RESPONSE, "cloud control response body could not be read");
  }
  if (total === 0) throw new CloudControlError(CLOUD_CONTROL_ERRORS.RESPONSE, "cloud control response body is empty");
  return Buffer.concat(chunks, total);
}

function extractBundle(value) {
  if (!plainObject(value)) throw new CloudControlError(CLOUD_CONTROL_ERRORS.RESPONSE, "cloud control response must be an object");
  if (Object.hasOwn(value, "bundle")) {
    const keys = Object.keys(value);
    if (keys.some((key) => !["bundle", "request_id"].includes(key))) throw new CloudControlError(CLOUD_CONTROL_ERRORS.RESPONSE, "cloud control response contains unknown fields");
    if (value.request_id !== undefined && (typeof value.request_id !== "string" || value.request_id.length > 128)) throw new CloudControlError(CLOUD_CONTROL_ERRORS.RESPONSE, "cloud control response request ID is invalid");
    return value.bundle;
  }
  return value;
}

function normalizeOptions(input) {
  if (!plainObject(input)) throw new CloudControlError(CLOUD_CONTROL_ERRORS.INVALID_CONFIG, "cloud control options must be an object");
  const organizationId = input.organizationId ?? input.organization_id;
  const deviceId = input.deviceId ?? input.device_id;
  const issuer = input.issuer ?? input.controlIssuer;
  const keyId = input.keyId ?? input.key_id ?? input.controlKeyId;
  const publicKey = input.publicKey ?? input.public_key ?? input.controlPublicKey;
  if (!UUID.test(organizationId ?? "") || !UUID.test(deviceId ?? "")) throw new CloudControlError(CLOUD_CONTROL_ERRORS.INVALID_CONFIG, "organizationId and deviceId must be UUIDs");
  if (!IDENTIFIER.test(issuer ?? "") || !IDENTIFIER.test(keyId ?? "")) throw new CloudControlError(CLOUD_CONTROL_ERRORS.INVALID_CONFIG, "issuer and keyId must be safe identifiers");
  assertPublicKey(publicKey);
  const loopbackTestMode = input.loopbackTestMode === true || input.allowLoopbackHttp === true;
  const suppliedUrl = input.endpoint ?? input.url ?? input.baseUrl;
  if (typeof suppliedUrl !== "string") throw new CloudControlError(CLOUD_CONTROL_ERRORS.INVALID_CONFIG, "url or endpoint is required");
  const parsed = validateEndpoint(suppliedUrl, loopbackTestMode);
  const endpoint = input.endpoint
    ? parsed
    : new URL(`/v1/organizations/${encodeURIComponent(organizationId)}/bundles/${encodeURIComponent(deviceId)}`, parsed);
  const statePath = input.statePath ?? input.state_path ?? path.join(input.stateDir ?? process.cwd(), "control-v2.state.json");
  if (!path.isAbsolute(statePath)) throw new CloudControlError(CLOUD_CONTROL_ERRORS.INVALID_CONFIG, "statePath must be absolute");
  const clock = input.clock ?? input.now ?? (() => Date.now());
  const nonce = input.nonce ?? (() => `A${crypto.randomBytes(32).toString("base64url")}`);
  const fetchImpl = input.fetchImpl ?? input.fetch ?? globalThis.fetch;
  const signer = input.signer ?? input.sign ?? input.signRequest ?? input.signing;
  const privateKey = input.privateKey ?? input.devicePrivateKey ?? input.signingKey;
  if (typeof clock !== "function" || typeof nonce !== "function" || typeof fetchImpl !== "function") throw new CloudControlError(CLOUD_CONTROL_ERRORS.INVALID_CONFIG, "clock, nonce, and fetchImpl must be functions");
  const trust = { public_key: publicKey, issuer, key_id: keyId };
  const audience = { organization_id: organizationId, device_id: deviceId };
  return Object.freeze({
    endpoint,
    organizationId,
    deviceId,
    audience,
    trust,
    statePath,
    clock,
    nonce,
    fetchImpl,
    signer,
    privateKey,
    timeoutMs: boundedInteger(input.timeoutMs ?? CLOUD_CONTROL_DEFAULT_TIMEOUT_MS, 1, 120_000),
    maxResponseBytes: boundedInteger(input.maxResponseBytes ?? CLOUD_CONTROL_MAX_RESPONSE_BYTES, 1, 4 * 1024 * 1024)
  });
}

function validateEndpoint(value, loopbackTestMode) {
  let parsed;
  try { parsed = new URL(value); } catch { throw new CloudControlError(CLOUD_CONTROL_ERRORS.INVALID_URL, "cloud control URL is invalid"); }
  const hostname = parsed.hostname.replace(/^\[|\]$/g, "");
  if (parsed.protocol !== "https:" && !(loopbackTestMode && parsed.protocol === "http:" && LOOPBACK.has(hostname))) {
    throw new CloudControlError(CLOUD_CONTROL_ERRORS.INVALID_URL, "cloud control endpoint must use HTTPS (HTTP is limited to explicit loopback test mode)");
  }
  if (parsed.username || parsed.password || parsed.hash) throw new CloudControlError(CLOUD_CONTROL_ERRORS.INVALID_URL, "cloud control URL cannot contain credentials or fragments");
  return parsed;
}

function assertPublicKey(value) {
  try {
    if ((typeof value === "string" && /PRIVATE KEY/.test(value)) || Buffer.isBuffer(value) && /PRIVATE KEY/.test(value.toString("utf8"))) throw new Error();
    if (value?.type === "private") throw new Error();
    const key = value?.type === "public" ? value : crypto.createPublicKey(value);
    if (key.asymmetricKeyType !== "ed25519") throw new Error();
    if (key.type !== "public") throw new Error();
  } catch {
    throw new CloudControlError(CLOUD_CONTROL_ERRORS.INVALID_CONFIG, "a pinned Ed25519 public key is required");
  }
}

function clockMilliseconds(value) {
  const result = value instanceof Date ? value.getTime() : Number(value);
  if (!Number.isSafeInteger(result) || result < 0) throw new CloudControlError(CLOUD_CONTROL_ERRORS.INVALID_CONFIG, "clock must return a non-negative integer timestamp");
  return result;
}

function boundedInteger(value, min, max) {
  if (!Number.isSafeInteger(value) || value < min || value > max) throw new CloudControlError(CLOUD_CONTROL_ERRORS.INVALID_CONFIG, "numeric cloud control option is out of bounds");
  return value;
}

function stableError(error) {
  if (error instanceof CloudControlError) return error;
  if (error instanceof ControlBundleError) return error;
  return new CloudControlError(CLOUD_CONTROL_ERRORS.STATE, "cloud control state operation failed");
}

function plainObject(value) {
  const prototype = value && typeof value === "object" && !Array.isArray(value) ? Object.getPrototypeOf(value) : undefined;
  return prototype === Object.prototype || prototype === null;
}
