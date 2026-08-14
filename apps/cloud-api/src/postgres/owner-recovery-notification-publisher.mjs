import https from "node:https";

import { createOwnerRecoveryDeliveryBinding, normalizeOwnerRecoveryDeliveryBinding } from "./owner-recovery-delivery-binding.mjs";

export const OWNER_RECOVERY_NOTIFICATION_PUBLISHER_DEFAULT_MAX_RESPONSE_BYTES = 64 * 1024;
export const OWNER_RECOVERY_NOTIFICATION_PUBLISHER_MAX_RESPONSE_BYTES = 1024 * 1024;

export const OWNER_RECOVERY_NOTIFICATION_PUBLISHER_ERROR_CODES = Object.freeze({
  CONFIG: "ERR_OWNER_RECOVERY_NOTIFICATION_PUBLISHER_CONFIG",
  INPUT: "ERR_OWNER_RECOVERY_NOTIFICATION_PUBLISHER_INPUT",
  ABORTED: "ERR_OWNER_RECOVERY_NOTIFICATION_PUBLISHER_ABORTED",
  UNAVAILABLE: "ERR_OWNER_RECOVERY_NOTIFICATION_PUBLISHER_UNAVAILABLE",
  REJECTED: "ERR_OWNER_RECOVERY_NOTIFICATION_PUBLISHER_REJECTED",
  RESPONSE_TOO_LARGE: "ERR_OWNER_RECOVERY_NOTIFICATION_PUBLISHER_RESPONSE_TOO_LARGE",
  RESOLVER: "ERR_OWNER_RECOVERY_NOTIFICATION_PUBLISHER_RESOLVER"
});

const MESSAGES = Object.freeze({
  [OWNER_RECOVERY_NOTIFICATION_PUBLISHER_ERROR_CODES.CONFIG]: "owner recovery notification publisher configuration is invalid",
  [OWNER_RECOVERY_NOTIFICATION_PUBLISHER_ERROR_CODES.INPUT]: "owner recovery notification publisher input is invalid",
  [OWNER_RECOVERY_NOTIFICATION_PUBLISHER_ERROR_CODES.ABORTED]: "owner recovery notification publisher request was aborted",
  [OWNER_RECOVERY_NOTIFICATION_PUBLISHER_ERROR_CODES.UNAVAILABLE]: "owner recovery notification provider is unavailable",
  [OWNER_RECOVERY_NOTIFICATION_PUBLISHER_ERROR_CODES.REJECTED]: "owner recovery notification provider rejected the event",
  [OWNER_RECOVERY_NOTIFICATION_PUBLISHER_ERROR_CODES.RESPONSE_TOO_LARGE]: "owner recovery notification provider response is too large",
  [OWNER_RECOVERY_NOTIFICATION_PUBLISHER_ERROR_CODES.RESOLVER]: "owner recovery notification publisher resolver is invalid"
});

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
const EVENT_TYPE = /^[a-z0-9][a-z0-9._:-]{0,127}$/u;
const SECRET = /^[\x21-\x7e]+$/u;
const PUBLIC_EVENT_KEYS = Object.freeze([
  "created_at",
  "event_id",
  "event_type",
  "kind",
  "organization_id",
  "request_id",
  "schema_version",
  "subject_member_id"
]);

export class OwnerRecoveryNotificationPublisherError extends Error {
  constructor(code) {
    super(MESSAGES[code] ?? MESSAGES[OWNER_RECOVERY_NOTIFICATION_PUBLISHER_ERROR_CODES.UNAVAILABLE]);
    this.name = "OwnerRecoveryNotificationPublisherError";
    this.code = code;
  }
}

/**
 * Create the HTTPS-only provider adapter used by the owner-recovery outbox.
 * Endpoint and authorization material are intentionally construction-time or
 * resolver inputs; neither is read from, or copied into, the event payload.
 */
export function createOwnerRecoveryNotificationPublisher({
  webhookUrl,
  authorizationSecret,
  resolveWebhookUrl,
  resolveAuthorizationSecret,
  bindingId = "hosted-owner-recovery-webhook",
  bindingKeyVersion = 1,
  bindingDigest,
  requestFn = https.request,
  maxResponseBytes = OWNER_RECOVERY_NOTIFICATION_PUBLISHER_DEFAULT_MAX_RESPONSE_BYTES
} = {}) {
  const fixedUrl = fixedValue(webhookUrl, resolveWebhookUrl, normalizeWebhookUrl);
  const fixedSecret = fixedValue(authorizationSecret, resolveAuthorizationSecret, normalizeAuthorizationSecret);
  let binding;
  try {
    binding = bindingDigest === undefined
      ? createOwnerRecoveryDeliveryBinding({ binding_id: bindingId, key_version: bindingKeyVersion, namespace: fixedUrl })
      : normalizeOwnerRecoveryDeliveryBinding({ binding_id: bindingId, key_version: bindingKeyVersion, binding_digest: bindingDigest });
  } catch { throw invalidConfig(); }
  if (fixedUrl === undefined && bindingDigest === undefined) throw invalidConfig();
  if (typeof requestFn !== "function" || !Number.isSafeInteger(maxResponseBytes)
    || maxResponseBytes < 1 || maxResponseBytes > OWNER_RECOVERY_NOTIFICATION_PUBLISHER_MAX_RESPONSE_BYTES) {
    throw invalidConfig();
  }

  async function publish(input) {
    const request = normalizePublishInput(input);
    if (request.signal?.aborted) throw aborted();

    const resolverInput = Object.freeze({ event: request.event, idempotency_key: request.idempotency_key, signal: request.signal });
    const url = await resolveConfigured(fixedUrl, resolveWebhookUrl, resolverInput, normalizeWebhookUrl);
    if (request.signal?.aborted) throw aborted();
    const secret = await resolveConfigured(fixedSecret, resolveAuthorizationSecret, resolverInput, normalizeAuthorizationSecret);
    if (request.signal?.aborted) throw aborted();

    const body = Buffer.from(JSON.stringify(request.event), "utf8");
    const response = await requestHttps({
      requestFn,
      url,
      secret,
      idempotencyKey: request.idempotency_key,
      body,
      signal: request.signal,
      maxResponseBytes
    });
    if (request.signal?.aborted) throw aborted();
    return validateAcceptedResponse(response, request.idempotency_key);
  }

  return Object.freeze({ publish, binding });
}

function fixedValue(value, resolver, normalize) {
  const hasValue = value !== undefined;
  const hasResolver = resolver !== undefined;
  if (hasValue === hasResolver || (hasResolver && typeof resolver !== "function")) throw invalidConfig();
  return hasValue ? normalize(value) : undefined;
}

async function resolveConfigured(fixed, resolver, input, normalize) {
  if (fixed !== undefined) return fixed;
  let value;
  try { value = await resolver(input); }
  catch { throw resolverError(); }
  try { return normalize(value, OWNER_RECOVERY_NOTIFICATION_PUBLISHER_ERROR_CODES.RESOLVER); }
  catch (error) {
    if (error instanceof OwnerRecoveryNotificationPublisherError) throw error;
    throw resolverError();
  }
}

function normalizePublishInput(input) {
  if (!plainObject(input) || !onlyKeys(input, ["event", "idempotency_key", "signal"])
    || typeof input.idempotency_key !== "string" || !UUID.test(input.idempotency_key)
    || (input.signal !== undefined && !(input.signal instanceof AbortSignal))) throw invalidInput();
  const event = normalizePublicEvent(input.event);
  if (event.event_id !== input.idempotency_key) throw invalidInput();
  return Object.freeze({ event, idempotency_key: input.idempotency_key, signal: input.signal });
}

function normalizePublicEvent(value) {
  if (!plainObject(value) || !sameKeys(value, PUBLIC_EVENT_KEYS)
    || value.schema_version !== 1 || value.kind !== "owner-recovery-notification"
    || !UUID.test(value.event_id) || !UUID.test(value.organization_id) || !UUID.test(value.request_id)
    || !UUID.test(value.subject_member_id) || typeof value.event_type !== "string" || !EVENT_TYPE.test(value.event_type)
    || typeof value.created_at !== "string" || value.created_at.length > 64 || !Number.isFinite(Date.parse(value.created_at))) throw invalidInput();
  return Object.freeze({
    schema_version: 1,
    kind: "owner-recovery-notification",
    event_id: value.event_id,
    organization_id: value.organization_id,
    request_id: value.request_id,
    subject_member_id: value.subject_member_id,
    event_type: value.event_type,
    created_at: value.created_at
  });
}

function normalizeWebhookUrl(value, code = OWNER_RECOVERY_NOTIFICATION_PUBLISHER_ERROR_CODES.CONFIG) {
  if (typeof value !== "string" || value.length < 1 || value.length > 2_048) throw publisherError(code);
  let url;
  try { url = new URL(value); }
  catch { throw publisherError(code); }
  if (url.protocol !== "https:" || url.username !== "" || url.password !== "" || url.hash !== "" || value.includes("#")
    || hasAuthorityUserInfo(value) || url.hostname === "") {
    throw publisherError(code);
  }
  return url.href;
}

function normalizeAuthorizationSecret(value, code = OWNER_RECOVERY_NOTIFICATION_PUBLISHER_ERROR_CODES.CONFIG) {
  if (typeof value !== "string" || value.length < 1 || value.length > 4_096
    || Buffer.byteLength(value, "utf8") > 4_096 || !SECRET.test(value)) throw publisherError(code);
  return value;
}

function requestHttps({ requestFn, url, secret, idempotencyKey, body, signal, maxResponseBytes }) {
  return new Promise((resolve, reject) => {
    let request;
    let settled = false;
    let abortListener;
    const finish = (fn, value) => {
      if (settled) return;
      settled = true;
      signal?.removeEventListener("abort", abortListener);
      fn(value);
    };
    const fail = (error) => finish(reject, error);
    const onAbort = () => {
      try { request?.destroy?.(); }
      catch { /* The stable abort error remains authoritative. */ }
      fail(aborted());
    };
    abortListener = onAbort;
    if (signal?.aborted) { fail(aborted()); return; }

    const onRequestError = () => fail(signal?.aborted ? aborted() : unavailable());
    const onResponse = (response) => {
      try {
        if (!response || typeof response.on !== "function" || typeof response.once !== "function") { fail(unavailable()); return; }
        const headers = response.headers;
        const onResponseError = () => fail(signal?.aborted ? aborted() : unavailable());
        response.once("error", onResponseError);
        response.once("aborted", onResponseError);
        const declaredLength = responseLength(headers);
        if (declaredLength > maxResponseBytes) {
          safeDestroy(response);
          fail(responseTooLarge());
          return;
        }
        const chunks = [];
        let total = 0;
        const onData = (chunk) => {
          if (settled) return;
          let bytes;
          try {
            bytes = Buffer.isBuffer(chunk) || chunk instanceof Uint8Array
              ? Buffer.from(chunk)
              : Buffer.from(String(chunk), "utf8");
          } catch {
            safeDestroy(response);
            fail(rejected());
            return;
          }
          total += bytes.length;
          if (total > maxResponseBytes) {
            safeDestroy(response);
            fail(responseTooLarge());
            return;
          }
          chunks.push(bytes);
        };
        const onEnd = () => {
          try {
            finish(resolve, Object.freeze({
              statusCode: response.statusCode,
              headers,
              body: Buffer.concat(chunks)
            }));
          } catch {
            fail(rejected());
          }
        };
        response.on("data", onData);
        response.once("end", onEnd);
      } catch {
        safeDestroy(response);
        fail(signal?.aborted ? aborted() : rejected());
      }
    };

    signal?.addEventListener("abort", abortListener, { once: true });
    try {
      request = requestFn(new URL(url), {
        method: "POST",
        headers: {
          accept: "application/json",
          authorization: `Bearer ${secret}`,
          "content-type": "application/json",
          "content-length": body.length,
          "idempotency-key": idempotencyKey
        },
        signal
      }, onResponse);
      if (!request || typeof request.end !== "function") { fail(unavailable()); return; }
      if (typeof request.once === "function") request.once("error", onRequestError);
      else if (typeof request.on === "function") request.on("error", onRequestError);
      else { fail(unavailable()); return; }
      if (signal?.aborted) { onAbort(); return; }
      request.end(body);
    } catch { fail(signal?.aborted ? aborted() : unavailable()); }
  });
}

function responseLength(headers) {
  try {
    const values = headerValues(headers, "content-length");
    if (values.length === 0) return -1;
    if (values.length !== 1) throw rejected();
    const [value] = values;
    if (headerValues(headers, "transfer-encoding").length > 0 || typeof value !== "string" || !/^\d+$/u.test(value)) throw rejected();
    const length = Number(value);
    if (!Number.isSafeInteger(length)) throw rejected();
    return length;
  } catch (error) {
    if (error instanceof OwnerRecoveryNotificationPublisherError) throw error;
    throw rejected();
  }
}

function validateAcceptedResponse(response, idempotencyKey) {
  try {
    if (!Number.isSafeInteger(response?.statusCode) || response.statusCode < 200 || response.statusCode >= 300
      || contentType(response?.headers) !== "application/json" || !Buffer.isBuffer(response?.body)) throw rejected();
    let body;
    try { body = new TextDecoder("utf-8", { fatal: true }).decode(response.body); }
    catch { throw rejected(); }
    const parsed = parseResponseJson(body);
    if (!plainObject(parsed) || !sameKeys(parsed, ["accepted", "duplicate", "idempotency_key"])
      || typeof parsed.accepted !== "boolean" || typeof parsed.duplicate !== "boolean"
      || typeof parsed.idempotency_key !== "string" || parsed.idempotency_key !== idempotencyKey
      || (parsed.accepted === false && parsed.duplicate !== false)) throw rejected();
    return Object.freeze({ accepted: parsed.accepted, duplicate: parsed.duplicate, idempotency_key: parsed.idempotency_key });
  } catch (error) {
    if (error instanceof OwnerRecoveryNotificationPublisherError) throw error;
    throw rejected();
  }
}

function contentType(headers) {
  try {
    const values = headerValues(headers, "content-type");
    if (values.length !== 1 || typeof values[0] !== "string") return undefined;
    return values[0].split(";", 1)[0].trim().toLowerCase();
  } catch {
    return undefined;
  }
}

function headerValues(headers, name) {
  if (headers === undefined || headers === null) return [];
  if (typeof headers !== "object") throw rejected();
  const values = [];
  for (const key of Reflect.ownKeys(headers)) {
    if (typeof key !== "string" || key.toLowerCase() !== name) continue;
    const descriptor = Object.getOwnPropertyDescriptor(headers, key);
    if (!descriptor || !("value" in descriptor)) throw rejected();
    if (Array.isArray(descriptor.value)) values.push(...descriptor.value);
    else values.push(descriptor.value);
  }
  return values;
}

function parseResponseJson(body) {
  let parsed;
  try { parsed = JSON.parse(body); }
  catch { throw rejected(); }
  if (hasDuplicateJsonObjectKeys(body)) throw rejected();
  return parsed;
}

function hasDuplicateJsonObjectKeys(source) {
  let index = 0;
  const skipWhitespace = () => {
    while (/\s/u.test(source[index] ?? "")) index += 1;
  };
  const skipString = () => {
    if (source[index] !== '"') return false;
    index += 1;
    while (index < source.length) {
      if (source[index] === "\\") { index += 2; continue; }
      if (source[index] === '"') { index += 1; return true; }
      index += 1;
    }
    return false;
  };
  const scanValue = () => {
    skipWhitespace();
    if (source[index] === '"') { skipString(); return false; }
    if (source[index] === "{") {
      index += 1;
      skipWhitespace();
      const keys = new Set();
      if (source[index] === "}") { index += 1; return false; }
      while (index < source.length) {
        skipWhitespace();
        const keyStart = index;
        if (!skipString()) return false;
        const key = JSON.parse(source.slice(keyStart, index));
        if (keys.has(key)) return true;
        keys.add(key);
        skipWhitespace();
        if (source[index] !== ":") return false;
        index += 1;
        if (scanValue()) return true;
        skipWhitespace();
        if (source[index] === "}") { index += 1; return false; }
        if (source[index] !== ",") return false;
        index += 1;
      }
      return false;
    }
    if (source[index] === "[") {
      index += 1;
      skipWhitespace();
      if (source[index] === "]") { index += 1; return false; }
      while (index < source.length) {
        if (scanValue()) return true;
        skipWhitespace();
        if (source[index] === "]") { index += 1; return false; }
        if (source[index] !== ",") return false;
        index += 1;
      }
      return false;
    }
    while (index < source.length && !/[\s,\]}]/u.test(source[index])) index += 1;
    return false;
  };
  const duplicate = scanValue();
  skipWhitespace();
  return duplicate || index !== source.length;
}

function publisherError(code) { return new OwnerRecoveryNotificationPublisherError(code); }
function invalidConfig() { return publisherError(OWNER_RECOVERY_NOTIFICATION_PUBLISHER_ERROR_CODES.CONFIG); }
function invalidInput() { return publisherError(OWNER_RECOVERY_NOTIFICATION_PUBLISHER_ERROR_CODES.INPUT); }
function aborted() { return publisherError(OWNER_RECOVERY_NOTIFICATION_PUBLISHER_ERROR_CODES.ABORTED); }
function unavailable() { return publisherError(OWNER_RECOVERY_NOTIFICATION_PUBLISHER_ERROR_CODES.UNAVAILABLE); }
function rejected() { return publisherError(OWNER_RECOVERY_NOTIFICATION_PUBLISHER_ERROR_CODES.REJECTED); }
function responseTooLarge() { return publisherError(OWNER_RECOVERY_NOTIFICATION_PUBLISHER_ERROR_CODES.RESPONSE_TOO_LARGE); }
function resolverError() { return publisherError(OWNER_RECOVERY_NOTIFICATION_PUBLISHER_ERROR_CODES.RESOLVER); }
function safeDestroy(value) { try { value?.destroy?.(); } catch { /* Provider stream cleanup cannot replace the stable error. */ } }
function hasAuthorityUserInfo(value) {
  const authorityStart = value.indexOf("//");
  if (authorityStart < 0) return false;
  const authority = value.slice(authorityStart + 2).split(/[/?#]/u, 1)[0];
  return authority.includes("@");
}
function onlyKeys(value, allowed) { return Reflect.ownKeys(value).every((key) => typeof key === "string" && allowed.includes(key)); }
function sameKeys(value, expected) {
  const keys = Reflect.ownKeys(value);
  return keys.length === expected.length && keys.every((key) => typeof key === "string" && expected.includes(key)
    && Object.getOwnPropertyDescriptor(value, key)?.enumerable === true
    && Object.getOwnPropertyDescriptor(value, key)?.value !== undefined);
}
function plainObject(value) { return value !== null && typeof value === "object" && !Array.isArray(value) && (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null); }

export default createOwnerRecoveryNotificationPublisher;
