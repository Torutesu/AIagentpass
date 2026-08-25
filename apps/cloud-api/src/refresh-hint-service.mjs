import crypto from "node:crypto";

import {
  PROTOCOL_VERSION,
  REFRESH_HINT_SIGNATURE_ALGORITHM,
  REFRESH_HINT_TYPE,
  normalizeRefreshHint,
  refreshHintSigningData
} from "../../../packages/protocol/src/index.mjs";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
const KEY_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$/u;
const NONCE = /^[A-Za-z0-9_-]{22}$/u;
const MAX_WAIT_MS = 30_000;
const MAX_HINT_TTL_MS = 5 * 60_000;
const DEFAULT_HINT_TTL_MS = 60_000;
const DEFAULT_MAX_WAITERS = 1_024;

export const REFRESH_HINT_SERVICE_ERROR_CODES = Object.freeze({
  ABORTED: "ERR_REFRESH_ABORTED",
  BUSY: "ERR_REFRESH_BUSY",
  INPUT: "ERR_REFRESH_INPUT",
  UNAVAILABLE: "ERR_REFRESH_UNAVAILABLE"
});

export class RefreshHintServiceError extends Error {
  constructor(code) {
    super(code === REFRESH_HINT_SERVICE_ERROR_CODES.BUSY ? "refresh polling capacity is exhausted"
      : code === REFRESH_HINT_SERVICE_ERROR_CODES.ABORTED ? "refresh polling was aborted"
        : code === REFRESH_HINT_SERVICE_ERROR_CODES.INPUT ? "refresh polling input is invalid"
          : "refresh polling is unavailable");
    this.name = "RefreshHintServiceError";
    this.code = code;
  }
}

/**
 * Turns committed, unsigned refresh metadata into a purpose-signed hint.
 * Notifications only wake a waiter; the source is queried before and after
 * every wait so notification loss cannot lose a committed generation.
 */
export function createRefreshHintService({
  source,
  nonceDeriver,
  signer,
  notifier,
  metrics,
  now = () => Date.now(),
  hintTtlMs = DEFAULT_HINT_TTL_MS,
  maxWaiters = DEFAULT_MAX_WAITERS
} = {}) {
  if (!source || typeof source.pollDeviceRefresh !== "function" || typeof source.markDeviceRefreshDelivered !== "function"
    || !nonceDeriver || typeof nonceDeriver.derive !== "function" || typeof nonceDeriver.matchesDigest !== "function"
    || !signer || typeof signer.signRefreshHint !== "function" || typeof signer.publicKeyMetadata !== "function"
    || (notifier !== undefined && (!notifier || typeof notifier.waitForRefresh !== "function"))
    || (metrics !== undefined && (!metrics || typeof metrics.snapshot !== "function"))
    || typeof now !== "function" || !Number.isSafeInteger(hintTtlMs) || hintTtlMs < 1 || hintTtlMs > MAX_HINT_TTL_MS
    || !Number.isSafeInteger(maxWaiters) || maxWaiters < 1 || maxWaiters > 100_000) {
    throw new RefreshHintServiceError(REFRESH_HINT_SERVICE_ERROR_CODES.INPUT);
  }

  let activeWaiters = 0;

  async function poll(input = {}) {
    const request = normalizePollInput(input);
    let state = await query(request);
    if (state) {
      recordMetric(metrics, "recordRefreshPropagationObservation");
      return issueHint(state, request);
    }
    if (request.waitMs === 0) return null;
    if (activeWaiters >= maxWaiters) {
      recordMetric(metrics, "recordRefreshWaiterRejection");
      throw new RefreshHintServiceError(REFRESH_HINT_SERVICE_ERROR_CODES.BUSY);
    }
    activeWaiters += 1;
    try {
      await wait(request);
    } finally {
      activeWaiters -= 1;
    }
    state = await query(request);
    recordMetric(metrics, state ? "recordRefreshPropagationObservation" : "recordRefreshPropagationTimeout");
    return state ? issueHint(state, request) : null;
  }

  async function query(request) {
    assertNotAborted(request.signal);
    let result;
    try {
      result = await source.pollDeviceRefresh({
        organization_id: request.organizationId,
        device_id: request.deviceId,
        after_generation: request.afterGeneration,
        wait_ms: 0,
        ...(request.signal ? { signal: request.signal } : {})
      });
    } catch (error) {
      if (request.signal?.aborted || error?.name === "AbortError") throw new RefreshHintServiceError(REFRESH_HINT_SERVICE_ERROR_CODES.ABORTED);
      throw new RefreshHintServiceError(REFRESH_HINT_SERVICE_ERROR_CODES.UNAVAILABLE);
    }
    return result === null || result === undefined ? null : normalizeRefreshMetadata(result, request);
  }

  async function wait(request) {
    assertNotAborted(request.signal);
    try {
      if (notifier) {
        await withDeadline(notifier.waitForRefresh({
          organization_id: request.organizationId,
          device_id: request.deviceId,
          after_generation: request.afterGeneration,
          timeout_ms: request.waitMs,
          ...(request.signal ? { signal: request.signal } : {})
        }), request.waitMs, request.signal);
      } else await boundedDelay(request.waitMs, request.signal);
    } catch (error) {
      if (request.signal?.aborted || error?.name === "AbortError" || error?.code === REFRESH_HINT_SERVICE_ERROR_CODES.ABORTED) {
        throw new RefreshHintServiceError(REFRESH_HINT_SERVICE_ERROR_CODES.ABORTED);
      }
      // A notifier is an optimization only. Its failure still reaches the
      // authoritative final query instead of converting into lost refresh.
      recordMetric(metrics, "recordRefreshNotificationWakeFailure");
    }
  }

  async function issueHint(state, request) {
    const publishedMs = clockMilliseconds(now());
    const requestedMs = Date.parse(state.publishedAt);
    const stateExpiryMs = Date.parse(state.expiresAt);
    const expiresMs = Math.min(stateExpiryMs, publishedMs + hintTtlMs);
    if (!Number.isFinite(requestedMs) || requestedMs > publishedMs + 60_000 || !Number.isFinite(stateExpiryMs) || expiresMs <= publishedMs) throw new RefreshHintServiceError(REFRESH_HINT_SERVICE_ERROR_CODES.UNAVAILABLE);
    let nonce;
    let metadata;
    try {
      nonce = await nonceDeriver.derive({
        organization_id: state.organizationId,
        device_id: state.deviceId,
        authority_generation: state.desiredGeneration,
        outbox_id: state.outboxId,
        key_id: state.nonceKeyId
      });
      metadata = await loadSignerMetadata();
    } catch {
      recordMetric(metrics, "recordRefreshDeliveryFailure");
      throw new RefreshHintServiceError(REFRESH_HINT_SERVICE_ERROR_CODES.UNAVAILABLE);
    }
    const nonceValue = nonce?.nonce_base64url ?? (Buffer.isBuffer(nonce?.nonce) ? nonce.nonce.toString("base64url") : undefined);
    if (typeof nonceValue !== "string" || !NONCE.test(nonceValue) || nonceDeriver.matchesDigest(nonce, state.nonceDigest) !== true
      || !metadata || typeof metadata !== "object" || Array.isArray(metadata)
      || !KEY_ID.test(metadata.keyId ?? "") || !metadata.publicKey || typeof metadata.publicKeyPEM !== "string") {
      throw new RefreshHintServiceError(REFRESH_HINT_SERVICE_ERROR_CODES.UNAVAILABLE);
    }
    const unsigned = {
      version: PROTOCOL_VERSION,
      type: REFRESH_HINT_TYPE,
      organization_id: request.organizationId,
      device_id: request.deviceId,
      authority_generation: state.desiredGeneration,
      published_at: new Date(publishedMs).toISOString(),
      expires_at: new Date(expiresMs).toISOString(),
      nonce: nonceValue,
      key_id: metadata.keyId,
      signature_algorithm: REFRESH_HINT_SIGNATURE_ALGORITHM
    };
    let signature;
    try {
      const placeholder = { ...unsigned, signature: Buffer.alloc(64).toString("base64url") };
      signature = await signer.signRefreshHint(refreshHintSigningData(placeholder));
      if (Buffer.isBuffer(signature) || signature instanceof Uint8Array) signature = Buffer.from(signature).toString("base64url");
      const hint = normalizeRefreshHint({ ...unsigned, signature });
      if (!crypto.verify(null, refreshHintSigningData(hint), metadata.publicKey, Buffer.from(hint.signature, "base64url"))) {
        throw new Error("invalid signature");
      }
      await source.markDeviceRefreshDelivered({
        organization_id: state.organizationId,
        device_id: state.deviceId,
        outbox_id: state.outboxId,
        desired_generation: state.desiredGeneration,
        delivered_at: new Date(publishedMs).toISOString()
      });
      return hint;
    } catch {
      throw new RefreshHintServiceError(REFRESH_HINT_SERVICE_ERROR_CODES.UNAVAILABLE);
    }
  }

  return Object.freeze({
    poll,
    // Expose only the canonical public trust metadata required by native
    // provisioning. The signer-owned KeyObject never crosses this boundary.
    publicKeyMetadata: async () => {
      const metadata = await loadSignerMetadata();
      return Object.freeze({ key_id: metadata.keyId, algorithm: REFRESH_HINT_SIGNATURE_ALGORITHM, public_key: metadata.publicKeyPEM });
    },
    snapshot: () => Object.freeze({ active_waiters: activeWaiters, max_waiters: maxWaiters })
  });

  async function loadSignerMetadata() {
    let metadata;
    try { metadata = await signer.publicKeyMetadata(); } catch { throw new Error("refresh signer metadata unavailable"); }
    if (!metadata || typeof metadata !== "object" || Array.isArray(metadata)
      || Object.keys(metadata).some((key) => !["key_id", "algorithm", "public_key"].includes(key))
      || Object.keys(metadata).length !== 3
      || !KEY_ID.test(metadata.key_id ?? "")
      || metadata.algorithm !== REFRESH_HINT_SIGNATURE_ALGORITHM) {
      throw new Error("refresh signer metadata is invalid");
    }
    let publicKey;
    try { publicKey = metadata.public_key?.type === "public" ? metadata.public_key : crypto.createPublicKey(metadata.public_key); }
    catch { throw new Error("refresh signer public key is invalid"); }
    if (publicKey.type !== "public" || publicKey.asymmetricKeyType !== "ed25519") throw new Error("refresh signer public key is invalid");
    const publicKeyPEM = publicKey.export({ type: "spki", format: "pem" }).toString();
    if (typeof metadata.public_key === "string" && metadata.public_key !== publicKeyPEM) throw new Error("refresh signer public key is not canonical");
    return { keyId: metadata.key_id, publicKey, publicKeyPEM };
  }
}

function recordMetric(metrics, method, amount = 1) {
  try { metrics?.[method]?.(amount); } catch { /* Metrics never alter refresh correctness. */ }
}

function normalizePollInput(input) {
  if (!input || typeof input !== "object" || Array.isArray(input)) failInput();
  const organizationId = input.organization_id ?? input.organizationId;
  const deviceId = input.device_id ?? input.deviceId;
  const afterGeneration = input.after_generation ?? input.afterGeneration ?? 0;
  const waitMs = input.wait_ms ?? input.waitMs ?? 0;
  const signal = input.signal;
  if (!UUID.test(organizationId ?? "") || !UUID.test(deviceId ?? "")
    || !Number.isSafeInteger(afterGeneration) || afterGeneration < 0
    || !Number.isSafeInteger(waitMs) || waitMs < 0 || waitMs > MAX_WAIT_MS
    || (signal !== undefined && (!signal || typeof signal.aborted !== "boolean" || typeof signal.addEventListener !== "function"))) failInput();
  return { organizationId: organizationId.toLowerCase(), deviceId: deviceId.toLowerCase(), afterGeneration, waitMs, signal };
}

function normalizeRefreshMetadata(value, request) {
  if (!value || typeof value !== "object" || Array.isArray(value)) unavailable();
  const allowed = new Set(["organization_id", "device_id", "desired_generation", "refresh_state", "outbox_id", "refresh_nonce_key_id", "refresh_nonce_digest", "published_at", "expires_at"]);
  if (Object.keys(value).some((key) => !allowed.has(key))) unavailable();
  const organizationId = value.organization_id;
  const deviceId = value.device_id;
  const desiredGeneration = value.desired_generation;
  const outboxId = value.outbox_id;
  const nonceKeyId = value.refresh_nonce_key_id;
  const nonceDigest = value.refresh_nonce_digest;
  const publishedAt = canonicalTimestamp(value.published_at);
  const expiresAt = canonicalTimestamp(value.expires_at);
  if (organizationId !== request.organizationId || deviceId !== request.deviceId || !UUID.test(outboxId ?? "")
    || !KEY_ID.test(nonceKeyId ?? "") || !/^[0-9a-f]{64}$/u.test(nonceDigest ?? "")
    || !Number.isSafeInteger(desiredGeneration) || desiredGeneration <= request.afterGeneration
    || Date.parse(expiresAt) <= Date.parse(publishedAt)) unavailable();
  return { organizationId, deviceId, desiredGeneration, outboxId: outboxId.toLowerCase(), nonceKeyId, nonceDigest, publishedAt, expiresAt };
}

function canonicalTimestamp(value) {
  if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(value) || !Number.isFinite(Date.parse(value))) unavailable();
  return value;
}

function clockMilliseconds(value) {
  const result = value instanceof Date ? value.getTime() : value;
  if (!Number.isSafeInteger(result) || result < 0) unavailable();
  return result;
}

function assertNotAborted(signal) {
  if (signal?.aborted) throw new RefreshHintServiceError(REFRESH_HINT_SERVICE_ERROR_CODES.ABORTED);
}

function boundedDelay(timeoutMs, signal) {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) return reject(new RefreshHintServiceError(REFRESH_HINT_SERVICE_ERROR_CODES.ABORTED));
    const timer = setTimeout(done, timeoutMs);
    const aborted = () => { clearTimeout(timer); cleanup(); reject(new RefreshHintServiceError(REFRESH_HINT_SERVICE_ERROR_CODES.ABORTED)); };
    function cleanup() { signal?.removeEventListener("abort", aborted); }
    function done() { cleanup(); resolve(); }
    signal?.addEventListener("abort", aborted, { once: true });
  });
}

function withDeadline(promise, timeoutMs, signal) {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) return reject(new RefreshHintServiceError(REFRESH_HINT_SERVICE_ERROR_CODES.ABORTED));
    let settled = false;
    const timer = setTimeout(() => finish(resolve), timeoutMs);
    const aborted = () => finish(reject, new RefreshHintServiceError(REFRESH_HINT_SERVICE_ERROR_CODES.ABORTED));
    const finish = (callback, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      signal?.removeEventListener("abort", aborted);
      callback(value);
    };
    signal?.addEventListener("abort", aborted, { once: true });
    Promise.resolve(promise).then((value) => finish(resolve, value), (error) => finish(reject, error));
  });
}

function failInput() { throw new RefreshHintServiceError(REFRESH_HINT_SERVICE_ERROR_CODES.INPUT); }
function unavailable() { throw new RefreshHintServiceError(REFRESH_HINT_SERVICE_ERROR_CODES.UNAVAILABLE); }

export default createRefreshHintService;
