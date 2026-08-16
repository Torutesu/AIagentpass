const HANDOFF_VERSION = 1;
const HANDOFF_TYPE = "agentpass.browser-onboarding.invitation";
const PREFLIGHT_VERSION = 1;
const SAFE_TOKEN = /^[A-Za-z0-9_-]{43}$/u;
const SAFE_CANDIDATE_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;
const SAFE_FINGERPRINT = /^SHA256:[A-Za-z0-9_-]{43}$/u;
const LAUNCH_FRAGMENT = /^http:\/\/127\.0\.0\.1:(\d{1,5})\/v1\/browser-cli-handoffs\/([A-Za-z0-9_-]{43})$/u;
const PREFLIGHT_KEYS = Object.freeze(["version", "correlation_id", "nonce", "platform", "candidate_id", "device_key_fingerprint"]);
const ACK_KEYS = Object.freeze(["version", "ok", "consumed"]);

export const BROWSER_CLI_HANDOFF_ERRORS = Object.freeze({
  INVALID_FRAGMENT: "ERR_BROWSER_CLI_HANDOFF_FRAGMENT",
  INVALID_PREFLIGHT: "ERR_BROWSER_CLI_HANDOFF_PREFLIGHT",
  PREFLIGHT_UNAVAILABLE: "ERR_BROWSER_CLI_HANDOFF_PREFLIGHT_UNAVAILABLE",
  INVALID_ACK: "ERR_BROWSER_CLI_HANDOFF_ACK",
  DELIVERY_FAILED: "ERR_BROWSER_CLI_HANDOFF_DELIVERY",
  INVALID_STATE: "ERR_BROWSER_CLI_HANDOFF_STATE",
  DELIVERY_ALREADY_ATTEMPTED: "ERR_BROWSER_CLI_HANDOFF_ALREADY_ATTEMPTED",
});

/**
 * The browser only renders outcomes that were proven at the loopback
 * boundary. There is no retry edge: a handoff is consumed by the first POST
 * attempt, whether the caller receives a valid ACK or an error.
 */
export const BROWSER_CLI_HANDOFF_STATES = Object.freeze({
  NONE: "none",
  LOADING: "loading",
  CONNECTED: "connected",
  DELIVERED: "delivered",
  FAILED: "failed",
});

export const BROWSER_CLI_HANDOFF_EVENTS = Object.freeze({
  LAUNCH: "launch",
  LAUNCH_FAILED: "launch_failed",
  PREFLIGHT_SUCCEEDED: "preflight_succeeded",
  PREFLIGHT_FAILED: "preflight_failed",
  DELIVERY_SUCCEEDED: "delivery_succeeded",
  DELIVERY_FAILED: "delivery_failed",
});

const HANDOFF_TRANSITIONS = Object.freeze({
  none: Object.freeze({ launch: "loading", launch_failed: "failed" }),
  loading: Object.freeze({ preflight_succeeded: "connected", preflight_failed: "failed" }),
  connected: Object.freeze({ delivery_succeeded: "delivered", delivery_failed: "failed" }),
  delivered: Object.freeze({}),
  failed: Object.freeze({}),
});

export class BrowserCliHandoffClientError extends Error {
  constructor(code, message, { cause } = {}) {
    super(message, cause === undefined ? undefined : { cause });
    this.name = "BrowserCliHandoffClientError";
    this.code = code;
  }
}

/**
 * Apply one result from the bounded handoff protocol. Invalid edges are
 * rejected rather than silently turning a UI-only state into authority.
 */
export function transitionBrowserCliHandoffState(state, event) {
  const next = HANDOFF_TRANSITIONS[state]?.[event];
  if (next === undefined) {
    throw new BrowserCliHandoffClientError(BROWSER_CLI_HANDOFF_ERRORS.INVALID_STATE, "The local setup handoff state transition is invalid");
  }
  return next;
}

/**
 * Parse the optional launch fragment. The fragment is deliberately a complete
 * loopback URL, with no query, userinfo, nonce, invitation, or extra marker.
 * The returned URL must stay in the caller's ephemeral ref and must never be
 * copied into React state, storage, telemetry, or diagnostics.
 */
export function parseBrowserCliHandoffLaunchFragment(fragment) {
  if (fragment === "") return null;
  if (typeof fragment !== "string" || !fragment.startsWith("#") || fragment.length <= 1) invalidFragment();
  let value;
  try {
    value = decodeURIComponent(fragment.slice(1));
  } catch (error) {
    invalidFragment(error);
  }
  const match = LAUNCH_FRAGMENT.exec(value);
  if (!match) invalidFragment();
  const port = Number(match[1]);
  if (!Number.isSafeInteger(port) || port < 1 || port > 65_535) invalidFragment();
  const correlationId = match[2];
  const url = `http://127.0.0.1:${match[1]}/v1/browser-cli-handoffs/${correlationId}`;
  return Object.freeze({
    url,
    preflight_url: `${url}/preflight`,
    correlation_id: correlationId,
  });
}

/**
 * Validate the exact public response returned by the loopback preflight.
 * `nonce` remains in this return value only so the caller can keep it in an
 * ephemeral ref for the subsequent bound POST.
 */
export function parseBrowserCliHandoffPreflight(value, expectedCorrelationId) {
  if (!plainObject(value) || !exactKeys(value, PREFLIGHT_KEYS)
    || value.version !== PREFLIGHT_VERSION
    || typeof value.correlation_id !== "string" || !SAFE_TOKEN.test(value.correlation_id)
    || value.correlation_id !== expectedCorrelationId
    || typeof value.nonce !== "string" || !SAFE_TOKEN.test(value.nonce)
    || value.platform !== "macos"
    || typeof value.candidate_id !== "string" || !SAFE_CANDIDATE_ID.test(value.candidate_id)
    || typeof value.device_key_fingerprint !== "string" || !SAFE_FINGERPRINT.test(value.device_key_fingerprint)) {
    throw new BrowserCliHandoffClientError(BROWSER_CLI_HANDOFF_ERRORS.INVALID_PREFLIGHT, "The local setup preflight is unavailable");
  }
  return Object.freeze({
    version: PREFLIGHT_VERSION,
    correlation_id: value.correlation_id,
    nonce: value.nonce,
    platform: "macos",
    candidate_id: value.candidate_id,
    device_key_fingerprint: value.device_key_fingerprint,
  });
}

/** Return only the public DTO consumed by the existing guided enrollment UI. */
export function publicEnrollmentPreflight(value) {
  const parsed = parseBrowserCliHandoffPreflight(value, value?.correlation_id);
  return Object.freeze({
    version: parsed.version,
    platform: parsed.platform,
    candidate_id: parsed.candidate_id,
    device_key_fingerprint: parsed.device_key_fingerprint,
  });
}

export async function fetchBrowserCliHandoffPreflight({ handoff, fetchImpl = globalThis.fetch, signal } = {}) {
  if (!plainObject(handoff) || typeof handoff.preflight_url !== "string" || typeof handoff.correlation_id !== "string") {
    throw new BrowserCliHandoffClientError(BROWSER_CLI_HANDOFF_ERRORS.INVALID_FRAGMENT, "The local setup handoff is unavailable");
  }
  if (typeof fetchImpl !== "function") throw new BrowserCliHandoffClientError(BROWSER_CLI_HANDOFF_ERRORS.PREFLIGHT_UNAVAILABLE, "The local setup handoff is unavailable");
  let response;
  try {
    response = await fetchImpl(handoff.preflight_url, {
      method: "GET",
      headers: { accept: "application/json" },
      cache: "no-store",
      credentials: "omit",
      mode: "cors",
      redirect: "error",
      signal,
    });
  } catch (error) {
    throw new BrowserCliHandoffClientError(BROWSER_CLI_HANDOFF_ERRORS.PREFLIGHT_UNAVAILABLE, "The local setup handoff is unavailable", { cause: error });
  }
  if (!response || response.status !== 200 || !response.ok) {
    throw new BrowserCliHandoffClientError(BROWSER_CLI_HANDOFF_ERRORS.PREFLIGHT_UNAVAILABLE, "The local setup handoff is unavailable");
  }
  let body;
  try {
    body = await response.json();
  } catch (error) {
    throw new BrowserCliHandoffClientError(BROWSER_CLI_HANDOFF_ERRORS.INVALID_PREFLIGHT, "The local setup preflight is unavailable", { cause: error });
  }
  return parseBrowserCliHandoffPreflight(body, handoff.correlation_id);
}

export function buildBrowserCliHandoffEnvelope(input = {}) {
  if (!plainObject(input) || !exactKeys(input, ["correlation_id", "nonce", "invitation"])) {
    throw new BrowserCliHandoffClientError(BROWSER_CLI_HANDOFF_ERRORS.DELIVERY_FAILED, "The local setup handoff could not be prepared");
  }
  const { correlation_id, nonce, invitation } = input;
  if (typeof correlation_id !== "string" || !SAFE_TOKEN.test(correlation_id)
    || typeof nonce !== "string" || !SAFE_TOKEN.test(nonce)
    || !plainObject(invitation)) {
    throw new BrowserCliHandoffClientError(BROWSER_CLI_HANDOFF_ERRORS.DELIVERY_FAILED, "The local setup handoff could not be prepared");
  }
  return Object.freeze({ version: HANDOFF_VERSION, type: HANDOFF_TYPE, correlation_id, nonce, invitation });
}

/** @returns {Promise<true>} */
export async function postBrowserCliHandoff({ handoff, correlation_id, nonce, invitation, fetchImpl = globalThis.fetch, signal } = {}) {
  if (!plainObject(handoff) || typeof handoff.url !== "string") {
    throw new BrowserCliHandoffClientError(BROWSER_CLI_HANDOFF_ERRORS.DELIVERY_FAILED, "The local setup handoff could not be delivered");
  }
  const body = buildBrowserCliHandoffEnvelope({ correlation_id, nonce, invitation });
  if (typeof fetchImpl !== "function") throw new BrowserCliHandoffClientError(BROWSER_CLI_HANDOFF_ERRORS.DELIVERY_FAILED, "The local setup handoff could not be delivered");
  let response;
  try {
    response = await fetchImpl(handoff.url, {
      method: "POST",
      headers: { accept: "application/json", "content-type": "application/json" },
      body: JSON.stringify(body),
      cache: "no-store",
      credentials: "omit",
      mode: "cors",
      redirect: "error",
      signal,
    });
  } catch (error) {
    throw new BrowserCliHandoffClientError(BROWSER_CLI_HANDOFF_ERRORS.DELIVERY_FAILED, "The local setup handoff could not be delivered", { cause: error });
  }
  if (!response || response.status !== 200 || !response.ok) {
    throw new BrowserCliHandoffClientError(BROWSER_CLI_HANDOFF_ERRORS.DELIVERY_FAILED, "The local setup handoff could not be delivered");
  }
  let ack;
  try {
    ack = await response.json();
  } catch (error) {
    throw new BrowserCliHandoffClientError(BROWSER_CLI_HANDOFF_ERRORS.INVALID_ACK, "The local setup handoff acknowledgement is invalid", { cause: error });
  }
  if (!plainObject(ack) || !exactKeys(ack, ACK_KEYS) || ack.version !== HANDOFF_VERSION || ack.ok !== true || ack.consumed !== true) {
    throw new BrowserCliHandoffClientError(BROWSER_CLI_HANDOFF_ERRORS.INVALID_ACK, "The local setup handoff acknowledgement is invalid");
  }
  return true;
}

/**
 * Create an ephemeral, one-consume delivery controller after a validated
 * preflight. The controller never exposes the nonce or invitation and refuses
 * every second send, including after a response-loss/invalid-ACK outcome.
 *
 * @param {{ handoff?: { url?: string, correlation_id?: string }, preflight?: { correlation_id?: string, nonce?: string }, fetchImpl?: typeof globalThis.fetch }} options
 * @returns {{ deliver: (invitation: Record<string, unknown>, options?: { signal?: AbortSignal }) => Promise<true> }}
 */
export function createBrowserCliHandoffDelivery(options = {}) {
  const { handoff, preflight, fetchImpl = globalThis.fetch } = options;
  if (!plainObject(handoff) || typeof handoff.url !== "string" || typeof handoff.correlation_id !== "string"
    || !plainObject(preflight) || preflight.correlation_id !== handoff.correlation_id
    || typeof preflight.nonce !== "string" || !SAFE_TOKEN.test(preflight.nonce)) {
    throw new BrowserCliHandoffClientError(BROWSER_CLI_HANDOFF_ERRORS.DELIVERY_FAILED, "The local setup handoff could not be prepared");
  }
  let attempted = false;
  return Object.freeze({
    async deliver(invitation, { signal } = {}) {
      if (attempted) {
        throw new BrowserCliHandoffClientError(BROWSER_CLI_HANDOFF_ERRORS.DELIVERY_ALREADY_ATTEMPTED, "The local setup handoff has already been consumed");
      }
      attempted = true;
      return postBrowserCliHandoff({
        handoff,
        correlation_id: handoff.correlation_id,
        nonce: preflight.nonce,
        invitation,
        fetchImpl,
        signal,
      });
    },
  });
}

function exactKeys(value, expected) {
  const actual = Object.keys(value).sort();
  const sortedExpected = [...expected].sort();
  return actual.length === sortedExpected.length && actual.every((key, index) => key === sortedExpected[index]);
}

function plainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype;
}

function invalidFragment(cause) {
  throw new BrowserCliHandoffClientError(BROWSER_CLI_HANDOFF_ERRORS.INVALID_FRAGMENT, "The local setup handoff link is invalid", { cause });
}
