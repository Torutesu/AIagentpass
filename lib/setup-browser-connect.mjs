import { spawnSync } from "node:child_process";

import {
  createBrowserCliHandoff,
  normalizeBrowserCliHandoffPreflight
} from "./browser-cli-handoff.mjs";

export const SETUP_BROWSER_CONNECT_ERRORS = Object.freeze({
  INVALID_OPTIONS: "ERR_SETUP_BROWSER_CONNECT_OPTIONS",
  INVALID_CONSOLE_URL: "ERR_SETUP_BROWSER_CONNECT_CONSOLE_URL",
  INVALID_CLOUD_URL: "ERR_SETUP_BROWSER_CONNECT_CLOUD_URL",
  INVALID_PREFLIGHT: "ERR_SETUP_BROWSER_CONNECT_PREFLIGHT",
  INVALID_HANDOFF: "ERR_SETUP_BROWSER_CONNECT_HANDOFF",
  OPEN_FAILED: "ERR_SETUP_BROWSER_CONNECT_OPEN_FAILED",
  OPEN_TIMEOUT: "ERR_SETUP_BROWSER_CONNECT_OPEN_TIMEOUT",
  TIMEOUT: "ERR_SETUP_BROWSER_CONNECT_TIMEOUT",
  ABORTED: "ERR_SETUP_BROWSER_CONNECT_ABORTED",
  HANDOFF_FAILED: "ERR_SETUP_BROWSER_CONNECT_HANDOFF_FAILED",
  CLOSE_FAILED: "ERR_SETUP_BROWSER_CONNECT_CLOSE_FAILED"
});

export const SETUP_BROWSER_CONNECT_EXECUTABLE = "/usr/bin/open";
export const SETUP_BROWSER_CONNECT_LIMITS = Object.freeze({
  maxUrlBytes: 2048,
  defaultOpenTimeoutMs: 10_000,
  minOpenTimeoutMs: 100,
  maxOpenTimeoutMs: 30_000
});

const MINIMAL_OPEN_ENV = Object.freeze({ PATH: "/usr/bin:/bin:/usr/sbin:/sbin" });
const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"]);
const CONTROL = /[\u0000-\u001f\u007f]/u;
const HANDOFF_PATH = /^\/v1\/browser-cli-handoffs\/[A-Za-z0-9_-]{43}$/u;
const STATIC_MESSAGES = Object.freeze({
  [SETUP_BROWSER_CONNECT_ERRORS.INVALID_OPTIONS]: "Browser setup options are invalid",
  [SETUP_BROWSER_CONNECT_ERRORS.INVALID_CONSOLE_URL]: "The Console URL is invalid",
  [SETUP_BROWSER_CONNECT_ERRORS.INVALID_CLOUD_URL]: "The Cloud API URL is invalid",
  [SETUP_BROWSER_CONNECT_ERRORS.INVALID_PREFLIGHT]: "The public setup preflight is invalid",
  [SETUP_BROWSER_CONNECT_ERRORS.INVALID_HANDOFF]: "The local browser handoff is invalid",
  [SETUP_BROWSER_CONNECT_ERRORS.OPEN_FAILED]: "The Console could not be opened",
  [SETUP_BROWSER_CONNECT_ERRORS.OPEN_TIMEOUT]: "Opening the Console timed out",
  [SETUP_BROWSER_CONNECT_ERRORS.TIMEOUT]: "The browser setup handoff timed out",
  [SETUP_BROWSER_CONNECT_ERRORS.ABORTED]: "The browser setup handoff was interrupted",
  [SETUP_BROWSER_CONNECT_ERRORS.HANDOFF_FAILED]: "The browser setup handoff failed",
  [SETUP_BROWSER_CONNECT_ERRORS.CLOSE_FAILED]: "The browser setup handoff could not be closed"
});

/**
 * Errors from this module intentionally contain only a stable code and a
 * fixed message. In particular, an opener exception, URL, path, or
 * credential is never copied into an error or retained as `cause`.
 */
export class SetupBrowserConnectError extends Error {
  constructor(code) {
    super(STATIC_MESSAGES[code] ?? STATIC_MESSAGES[SETUP_BROWSER_CONNECT_ERRORS.HANDOFF_FAILED]);
    this.name = "SetupBrowserConnectError";
    this.code = code;
  }
}

/**
 * Normalize the browser-facing Console root. HTTPS is mandatory except for
 * an explicitly enabled loopback development URL. The returned value always
 * has a root slash and contains no query, fragment, credentials, or path.
 */
export function normalizeConsoleBaseUrl(value, { allowHttpLoopback = false } = {}) {
  const parsed = parseRootUrl(value, SETUP_BROWSER_CONNECT_ERRORS.INVALID_CONSOLE_URL);
  const isLoopback = LOOPBACK_HOSTS.has(parsed.hostname.toLowerCase());
  if (parsed.protocol !== "https:" && !(parsed.protocol === "http:" && allowHttpLoopback === true && isLoopback)) {
    throw new SetupBrowserConnectError(SETUP_BROWSER_CONNECT_ERRORS.INVALID_CONSOLE_URL);
  }
  return `${parsed.origin}/`;
}

/**
 * Normalize the Cloud API v1 root independently from the Console origin.
 * This function never derives an API URL from a Console URL and does not
 * accept HTTP, including loopback HTTP.
 */
export function normalizeCloudV1BaseUrl(value) {
  const parsed = parseRootUrl(value, SETUP_BROWSER_CONNECT_ERRORS.INVALID_CLOUD_URL, { allowPath: "/v1" });
  if (parsed.protocol !== "https:" || (parsed.pathname !== "/v1" && parsed.pathname !== "/v1/")) {
    throw new SetupBrowserConnectError(SETUP_BROWSER_CONNECT_ERRORS.INVALID_CLOUD_URL);
  }
  return `${parsed.origin}/v1`;
}

// A short alias keeps the contract readable at call sites that name the
// endpoint rather than its role.
export const normalizeCloudApiV1Url = normalizeCloudV1BaseUrl;

/**
 * Build the only browser URL this helper emits. Its fragment is exactly the
 * opaque loopback handoff URL; no nonce, invitation, query, or second field
 * is placed in the launch URL.
 */
export function buildConsoleLaunchUrl({ consoleBaseUrl, handoffUrl, allowHttpLoopback = false } = {}) {
  const consoleUrl = normalizeConsoleBaseUrl(consoleBaseUrl, { allowHttpLoopback });
  assertLocalHandoffUrl(handoffUrl);
  const launchUrl = `${consoleUrl}#${handoffUrl}`;
  const parsed = new URL(launchUrl);
  if (parsed.origin !== new URL(consoleUrl).origin || parsed.search !== "" || parsed.hash !== `#${handoffUrl}`) {
    throw new SetupBrowserConnectError(SETUP_BROWSER_CONNECT_ERRORS.INVALID_HANDOFF);
  }
  return launchUrl;
}

/**
 * Invoke the macOS system browser without a shell and with a fixed, minimal
 * environment. `spawn` is injectable for deterministic tests; production
 * callers use the imported `spawnSync` implementation.
 */
export function openConsoleWithSystem(url, { timeoutMs = SETUP_BROWSER_CONNECT_LIMITS.defaultOpenTimeoutMs, spawn = spawnSync, allowHttpLoopback = false } = {}) {
  assertLaunchUrl(url, { allowHttpLoopback });
  const timeout = boundedInteger(timeoutMs, SETUP_BROWSER_CONNECT_LIMITS.minOpenTimeoutMs, SETUP_BROWSER_CONNECT_LIMITS.maxOpenTimeoutMs);
  if (typeof spawn !== "function") throw new SetupBrowserConnectError(SETUP_BROWSER_CONNECT_ERRORS.INVALID_OPTIONS);
  let result;
  try {
    result = spawn(SETUP_BROWSER_CONNECT_EXECUTABLE, [url], {
      shell: false,
      env: { ...MINIMAL_OPEN_ENV },
      stdio: "ignore",
      timeout,
      killSignal: "SIGTERM"
    });
  } catch {
    throw new SetupBrowserConnectError(SETUP_BROWSER_CONNECT_ERRORS.OPEN_FAILED);
  }
  if (!result || result.error || result.signal || result.status !== 0) {
    if (result?.error?.code === "ETIMEDOUT" || result?.signal === "SIGTERM") {
      throw new SetupBrowserConnectError(SETUP_BROWSER_CONNECT_ERRORS.OPEN_TIMEOUT);
    }
    throw new SetupBrowserConnectError(SETUP_BROWSER_CONNECT_ERRORS.OPEN_FAILED);
  }
}

/**
 * Start the bounded browser-assisted onboarding journey. The invitation is
 * returned directly from the in-memory handoff and is never serialized,
 * logged, persisted, placed in argv, or placed in an environment variable.
 */
export async function connectSetupInBrowser(options = {}) {
  const config = normalizeOptions(options);
  throwIfAborted(config.signal);

  let handoff;
  let primaryError;
  try {
    handoff = await createBrowserCliHandoff({
      allowedOrigins: [config.consoleOrigin],
      preflight: config.preflight,
      signal: config.signal,
      ttlMs: config.ttlMs,
      maxBodyBytes: config.maxBodyBytes,
      requestTimeoutMs: config.requestTimeoutMs
    });
    // The handoff owns a rejecting promise for timeout/abort/close. Attach a
    // sink immediately so an opener failure cannot create an unhandled
    // rejection before this function reaches its normal wait point.
    void handoff.waitForInvitation().catch(() => {});
    const launchUrl = buildConsoleLaunchUrl({
      consoleBaseUrl: config.consoleBaseUrl,
      handoffUrl: handoff.url,
      allowHttpLoopback: config.allowHttpLoopback
    });
    await invokeOpener(config.opener, launchUrl, config.openTimeoutMs, config.signal);
    throwIfAborted(config.signal);
    try {
      return await handoff.waitForInvitation();
    } catch (error) {
      throw mapHandoffError(error, config.signal);
    }
  } catch (error) {
    primaryError = error instanceof SetupBrowserConnectError
      ? error
      : new SetupBrowserConnectError(SETUP_BROWSER_CONNECT_ERRORS.HANDOFF_FAILED);
    throw primaryError;
  } finally {
    if (handoff) {
      try {
        await handoff.close();
      } catch {
        if (!primaryError) throw new SetupBrowserConnectError(SETUP_BROWSER_CONNECT_ERRORS.CLOSE_FAILED);
      }
    }
  }
}

function normalizeOptions(options) {
  if (!plainObject(options)) throw new SetupBrowserConnectError(SETUP_BROWSER_CONNECT_ERRORS.INVALID_OPTIONS);
  const allowed = new Set([
    "consoleBaseUrl",
    "cloudBaseUrl",
    "preflight",
    "opener",
    "signal",
    "allowHttpLoopback",
    "openTimeoutMs",
    "ttlMs",
    "maxBodyBytes",
    "requestTimeoutMs"
  ]);
  if (Object.keys(options).some((key) => !allowed.has(key))) throw new SetupBrowserConnectError(SETUP_BROWSER_CONNECT_ERRORS.INVALID_OPTIONS);

  let consoleBaseUrl;
  try {
    consoleBaseUrl = normalizeConsoleBaseUrl(options.consoleBaseUrl, { allowHttpLoopback: options.allowHttpLoopback === true });
  } catch (error) {
    if (error instanceof SetupBrowserConnectError) throw error;
    throw new SetupBrowserConnectError(SETUP_BROWSER_CONNECT_ERRORS.INVALID_CONSOLE_URL);
  }
  if (options.cloudBaseUrl !== undefined) normalizeCloudV1BaseUrl(options.cloudBaseUrl);

  let preflight;
  try {
    preflight = normalizeBrowserCliHandoffPreflight(options.preflight);
  } catch {
    throw new SetupBrowserConnectError(SETUP_BROWSER_CONNECT_ERRORS.INVALID_PREFLIGHT);
  }
  if (options.opener !== undefined && typeof options.opener !== "function") throw new SetupBrowserConnectError(SETUP_BROWSER_CONNECT_ERRORS.INVALID_OPTIONS);
  if (options.signal !== undefined && !validSignal(options.signal)) throw new SetupBrowserConnectError(SETUP_BROWSER_CONNECT_ERRORS.INVALID_OPTIONS);
  if (options.allowHttpLoopback !== undefined && typeof options.allowHttpLoopback !== "boolean") throw new SetupBrowserConnectError(SETUP_BROWSER_CONNECT_ERRORS.INVALID_OPTIONS);

  const openTimeoutMs = boundedInteger(options.openTimeoutMs ?? SETUP_BROWSER_CONNECT_LIMITS.defaultOpenTimeoutMs, SETUP_BROWSER_CONNECT_LIMITS.minOpenTimeoutMs, SETUP_BROWSER_CONNECT_LIMITS.maxOpenTimeoutMs);
  const ttlMs = boundedInteger(options.ttlMs ?? 120_000, 1_000, 5 * 60 * 1000);
  const maxBodyBytes = boundedInteger(options.maxBodyBytes ?? 64 * 1024, 1, 128 * 1024);
  const requestTimeoutMs = boundedInteger(options.requestTimeoutMs ?? 5_000, 100, 30 * 1000);
  return {
    consoleBaseUrl,
    consoleOrigin: new URL(consoleBaseUrl).origin,
    preflight,
    opener: options.opener ?? ((url, context) => openConsoleWithSystem(url, { timeoutMs: context.timeoutMs, allowHttpLoopback: options.allowHttpLoopback === true })),
    signal: options.signal,
    allowHttpLoopback: options.allowHttpLoopback === true,
    openTimeoutMs,
    ttlMs,
    maxBodyBytes,
    requestTimeoutMs
  };
}

async function invokeOpener(opener, url, timeoutMs, signal) {
  throwIfAborted(signal);
  let pending;
  try {
    pending = Promise.resolve().then(() => opener(url, { signal, timeoutMs }));
  } catch {
    throw new SetupBrowserConnectError(SETUP_BROWSER_CONNECT_ERRORS.OPEN_FAILED);
  }
  // A timed-out injected opener may settle later. Attach a rejection handler
  // so a late failure cannot become an unhandled rejection or carry secrets.
  pending.catch(() => {});
  let timer;
  let abortListener;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new SetupBrowserConnectError(SETUP_BROWSER_CONNECT_ERRORS.OPEN_TIMEOUT)), timeoutMs);
    timer.unref?.();
  });
  const aborted = new Promise((_, reject) => {
    if (!signal) return;
    abortListener = () => reject(new SetupBrowserConnectError(SETUP_BROWSER_CONNECT_ERRORS.ABORTED));
    signal.addEventListener("abort", abortListener, { once: true });
    if (signal.aborted) abortListener();
  });
  try {
    await Promise.race(signal ? [pending, timeout, aborted] : [pending, timeout]);
  } catch (error) {
    if (error instanceof SetupBrowserConnectError) throw error;
    throw new SetupBrowserConnectError(SETUP_BROWSER_CONNECT_ERRORS.OPEN_FAILED);
  } finally {
    clearTimeout(timer);
    if (signal && abortListener) signal.removeEventListener("abort", abortListener);
  }
}

function mapHandoffError(error, signal) {
  if (signal?.aborted || error?.code === "ERR_BROWSER_CLI_HANDOFF_ABORTED") return new SetupBrowserConnectError(SETUP_BROWSER_CONNECT_ERRORS.ABORTED);
  if (error?.code === "ERR_BROWSER_CLI_HANDOFF_TIMEOUT") return new SetupBrowserConnectError(SETUP_BROWSER_CONNECT_ERRORS.TIMEOUT);
  return new SetupBrowserConnectError(SETUP_BROWSER_CONNECT_ERRORS.HANDOFF_FAILED);
}

function parseRootUrl(value, code, { allowPath = "/" } = {}) {
  if (typeof value !== "string" || value.length < 1 || Buffer.byteLength(value, "utf8") > SETUP_BROWSER_CONNECT_LIMITS.maxUrlBytes || value.trim() !== value || CONTROL.test(value)) {
    throw new SetupBrowserConnectError(code);
  }
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    throw new SetupBrowserConnectError(code);
  }
  const canonical = parsed.origin + allowPath;
  const accepted = allowPath === "/"
    ? new Set([parsed.origin, canonical])
    : new Set([canonical, `${canonical}/`]);
  if (parsed.username || parsed.password || parsed.search || parsed.hash || (parsed.pathname !== allowPath && parsed.pathname !== `${allowPath}/`) || !accepted.has(value)) {
    throw new SetupBrowserConnectError(code);
  }
  return parsed;
}

function assertLocalHandoffUrl(value) {
  if (typeof value !== "string" || value.length < 1 || Buffer.byteLength(value, "utf8") > SETUP_BROWSER_CONNECT_LIMITS.maxUrlBytes || value.trim() !== value || CONTROL.test(value)) {
    throw new SetupBrowserConnectError(SETUP_BROWSER_CONNECT_ERRORS.INVALID_HANDOFF);
  }
  let parsed;
  try { parsed = new URL(value); } catch { throw new SetupBrowserConnectError(SETUP_BROWSER_CONNECT_ERRORS.INVALID_HANDOFF); }
  if (parsed.protocol !== "http:" || parsed.hostname !== "127.0.0.1" || !parsed.port || parsed.username || parsed.password || parsed.search || parsed.hash || !HANDOFF_PATH.test(parsed.pathname) || value !== parsed.href) {
    throw new SetupBrowserConnectError(SETUP_BROWSER_CONNECT_ERRORS.INVALID_HANDOFF);
  }
}

function assertLaunchUrl(value, { allowHttpLoopback = false } = {}) {
  if (typeof value !== "string" || value.length < 1 || Buffer.byteLength(value, "utf8") > SETUP_BROWSER_CONNECT_LIMITS.maxUrlBytes || CONTROL.test(value)) {
    throw new SetupBrowserConnectError(SETUP_BROWSER_CONNECT_ERRORS.INVALID_HANDOFF);
  }
  let parsed;
  try { parsed = new URL(value); } catch { throw new SetupBrowserConnectError(SETUP_BROWSER_CONNECT_ERRORS.INVALID_HANDOFF); }
  if ((parsed.protocol !== "https:" && parsed.protocol !== "http:") || parsed.username || parsed.password || parsed.pathname !== "/" || parsed.search || parsed.hash.length < 2) {
    throw new SetupBrowserConnectError(SETUP_BROWSER_CONNECT_ERRORS.INVALID_HANDOFF);
  }
  try {
    normalizeConsoleBaseUrl(`${parsed.origin}/`, { allowHttpLoopback });
    const handoffUrl = parsed.hash.slice(1);
    assertLocalHandoffUrl(handoffUrl);
    if (value !== `${parsed.origin}/#${handoffUrl}`) throw new Error("non-canonical launch URL");
  } catch {
    throw new SetupBrowserConnectError(SETUP_BROWSER_CONNECT_ERRORS.INVALID_HANDOFF);
  }
}

function boundedInteger(value, minimum, maximum) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) throw new SetupBrowserConnectError(SETUP_BROWSER_CONNECT_ERRORS.INVALID_OPTIONS);
  return value;
}

function validSignal(value) {
  return value !== null && typeof value === "object" && typeof value.addEventListener === "function" && typeof value.removeEventListener === "function" && typeof value.aborted === "boolean";
}

function throwIfAborted(signal) {
  if (signal?.aborted) throw new SetupBrowserConnectError(SETUP_BROWSER_CONNECT_ERRORS.ABORTED);
}

function plainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype;
}
