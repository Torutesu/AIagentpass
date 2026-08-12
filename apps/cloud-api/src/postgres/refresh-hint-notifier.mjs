const REFRESH_HINT_NOTIFY_CHANNEL = "agentpass_refresh_hint_v1";
const LISTEN_SQL = `LISTEN ${REFRESH_HINT_NOTIFY_CHANNEL}`;
const UNLISTEN_SQL = `UNLISTEN ${REFRESH_HINT_NOTIFY_CHANNEL}`;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
const MAX_NOTIFY_PAYLOAD_BYTES = 2_048;
const MAX_WAIT_MS = 30_000;
const DEFAULT_MAX_WAITERS = 1_024;
const DEFAULT_RECONNECT_COOLDOWN_MS = 250;

export const REFRESH_HINT_NOTIFICATION_CHANNEL = REFRESH_HINT_NOTIFY_CHANNEL;
export const REFRESH_HINT_NOTIFIER_ERROR_CODES = Object.freeze({
  INPUT: "ERR_REFRESH_NOTIFIER_INPUT",
  BUSY: "ERR_REFRESH_NOTIFIER_BUSY",
  ABORTED: "ERR_REFRESH_NOTIFIER_ABORTED",
  CLOSED: "ERR_REFRESH_NOTIFIER_CLOSED"
});

export class RefreshHintNotifierError extends Error {
  constructor(code, message = code) {
    super(message);
    this.name = "RefreshHintNotifierError";
    this.code = code;
  }
}

/**
 * Owns exactly one checked-out PostgreSQL client for the process while the
 * notifier is active. Notifications are only hints: callers must perform an
 * authoritative query after this promise resolves, including after failure.
 *
 * The channel and LISTEN statement are deliberately constants. PostgreSQL
 * does not parameterize LISTEN identifiers, so accepting a caller-provided
 * channel here would turn a notification optimization into identifier input.
 */
export function createPostgresRefreshHintNotifier({
  pool,
  clientFactory,
  now = () => Date.now(),
  maxWaiters = DEFAULT_MAX_WAITERS,
  maxWaitMs = MAX_WAIT_MS,
  reconnectCooldownMs = DEFAULT_RECONNECT_COOLDOWN_MS
} = {}) {
  const connect = clientFactory ?? (pool && typeof pool.connect === "function" ? () => pool.connect() : undefined);
  if (typeof connect !== "function"
    || typeof now !== "function"
    || !Number.isSafeInteger(maxWaiters) || maxWaiters < 1 || maxWaiters > 100_000
    || !Number.isSafeInteger(maxWaitMs) || maxWaitMs < 1 || maxWaitMs > MAX_WAIT_MS
    || !Number.isSafeInteger(reconnectCooldownMs) || reconnectCooldownMs < 0 || reconnectCooldownMs > MAX_WAIT_MS) {
    throw new RefreshHintNotifierError(REFRESH_HINT_NOTIFIER_ERROR_CODES.INPUT, "refresh notifier configuration is invalid");
  }

  let connection = null;
  let connectPromise = null;
  let closePromise = null;
  let lastFailureAt = Number.NEGATIVE_INFINITY;
  let draining = false;
  const waiters = new Set();
  const emptyWaiters = new Set();
  const disposalPromises = new Set();

  async function waitForRefresh(input = {}) {
    const request = normalizeRequest(input, maxWaitMs);
    if (request.signal?.aborted) throw abortedError();
    if (closePromise || draining) throw new RefreshHintNotifierError(REFRESH_HINT_NOTIFIER_ERROR_CODES.CLOSED, "refresh notifier is closed");
    if (request.timeoutMs === 0) return false;
    if (waiters.size >= maxWaiters) throw new RefreshHintNotifierError(REFRESH_HINT_NOTIFIER_ERROR_CODES.BUSY, "refresh notifier waiter capacity is exhausted");

    const waiter = createWaiter(request);
    waiters.add(waiter);
    // Do not await connection establishment here: a stuck pool.connect()
    // must not delay the request's timeout or AbortSignal. The waiter is
    // resolved by the connection outcome, timeout, abort, or close path.
    void ensureConnection().catch(() => settle(waiter, false));
    return waiter.promise;
  }

  async function ensureConnection() {
    if (closePromise || draining) return null;
    if (connection) return connection.client;
    if (connectPromise) return connectPromise;

    const currentTime = clock(now);
    if (currentTime - lastFailureAt < reconnectCooldownMs) {
      settleAll(false);
      return null;
    }

    connectPromise = connectClient();
    try {
      return await connectPromise;
    } finally {
      connectPromise = null;
    }
  }

  async function connectClient() {
    await waitForDisposals();
    if (closePromise || draining) return null;

    let candidate;
    let candidateConnection;
    try {
      candidate = await connect();
      validateClient(candidate);
      candidateConnection = attach(candidate);
      connection = candidateConnection;
      await candidate.query(LISTEN_SQL);
      if (closePromise || draining) {
        connection = null;
        await dispose(candidateConnection, false);
        return null;
      }
      return candidate;
    } catch {
      if (candidateConnection) {
        if (connection === candidateConnection) connection = null;
        await dispose(candidateConnection, true);
      } else if (candidate) {
        await releaseUnattached(candidate, true);
      }
      lastFailureAt = clock(now);
      settleAll(false);
      return null;
    }
  }

  function attach(client) {
    const state = {
      client,
      released: false,
      onNotification: (message) => handleNotification(message),
      onError: () => handleConnectionFailure(state),
      onEnd: () => handleConnectionFailure(state)
    };
    client.on("notification", state.onNotification);
    client.on("error", state.onError);
    client.on("end", state.onEnd);
    return state;
  }

  function handleNotification(message) {
    const tuple = parseNotification(message);
    if (!tuple) return;
    for (const waiter of [...waiters]) {
      if (waiter.organizationId === tuple.organizationId
        && waiter.deviceId === tuple.deviceId
        && tuple.desiredGeneration > waiter.afterGeneration) {
        settle(waiter, true);
      }
    }
  }

  function handleConnectionFailure(failedConnection) {
    if (failedConnection.released) return;
    const wasCurrent = connection === failedConnection;
    if (wasCurrent) {
      connection = null;
      lastFailureAt = clock(now);
    }
    const disposal = dispose(failedConnection, true);
    disposalPromises.add(disposal);
    disposal.finally(() => disposalPromises.delete(disposal)).catch(() => {});
    // Do not reject with a database error. The service's final query is the
    // source of truth and must still run after a broken listener connection.
    if (wasCurrent) settleAll(false);
  }

  async function drain({ timeout_ms: timeoutMs = maxWaitMs } = {}) {
    const boundedTimeout = boundedInteger(timeoutMs, 0, maxWaitMs, "timeout_ms");
    if (closePromise) return;
    draining = true;
    if (waiters.size === 0) return;
    await waitForNoWaiters(boundedTimeout);
    if (waiters.size > 0) settleAll(false);
  }

  async function close() {
    if (closePromise) return closePromise;
    closePromise = (async () => {
      draining = true;
      settleAll(false);
      // A pool implementation may not provide cancellation for an in-flight
      // connect. Do not make shutdown depend on that external promise; the
      // connect path observes `draining` and releases any late client.
      void connectPromise?.catch(() => {});
      const current = connection;
      connection = null;
      if (current) await dispose(current, false);
      await waitForDisposals();
    })();
    return closePromise;
  }

  function snapshot() {
    return Object.freeze({
      channel: REFRESH_HINT_NOTIFY_CHANNEL,
      connected: connection !== null,
      connecting: connectPromise !== null,
      active_waiters: waiters.size,
      max_waiters: maxWaiters,
      max_wait_ms: maxWaitMs,
      draining: draining || closePromise !== null
    });
  }

  return Object.freeze({
    waitForRefresh,
    drain,
    close,
    snapshot
  });

  async function waitForDisposals() {
    if (disposalPromises.size === 0) return;
    await Promise.allSettled([...disposalPromises]);
  }

  async function dispose(state, destroy) {
    if (!state || state.released) return;
    state.released = true;
    removeListener(state.client, "notification", state.onNotification);
    removeListener(state.client, "error", state.onError);
    removeListener(state.client, "end", state.onEnd);
    let shouldDestroy = destroy === true;
    if (!shouldDestroy && typeof state.client.query === "function") {
      try {
        await state.client.query(UNLISTEN_SQL);
      } catch {
        shouldDestroy = true;
      }
    }
    await releaseUnattached(state.client, shouldDestroy);
  }

  function settleAll(value) {
    for (const waiter of [...waiters]) settle(waiter, value);
  }

  function settle(waiter, value, error) {
    if (!waiters.has(waiter) || waiter.settled) return;
    waiter.settled = true;
    waiters.delete(waiter);
    clearTimeout(waiter.timer);
    waiter.signal?.removeEventListener("abort", waiter.onAbort);
    if (waiters.size === 0) {
      for (const resolveEmpty of [...emptyWaiters]) resolveEmpty();
      emptyWaiters.clear();
    }
    if (error) waiter.reject(error);
    else waiter.resolve(value);
  }

  function createWaiter(request) {
    let resolve;
    let reject;
    const promise = new Promise((resolvePromise, rejectPromise) => {
      resolve = resolvePromise;
      reject = rejectPromise;
    });
    const waiter = {
      ...request,
      promise,
      resolve,
      reject,
      settled: false,
      timer: null,
      onAbort: null
    };
    waiter.timer = setTimeout(() => settle(waiter, false), request.timeoutMs);
    waiter.onAbort = () => settle(waiter, undefined, abortedError());
    request.signal?.addEventListener("abort", waiter.onAbort, { once: true });
    return waiter;
  }

  function waitForNoWaiters(timeoutMs) {
    if (waiters.size === 0) return Promise.resolve();
    return new Promise((resolve) => {
      const timer = setTimeout(done, timeoutMs);
      emptyWaiters.add(done);
      function done() {
        clearTimeout(timer);
        emptyWaiters.delete(done);
        resolve();
      }
    });
  }
}

function normalizeRequest(input, maxWaitMs) {
  if (!input || typeof input !== "object" || Array.isArray(input)) invalidInput();
  const organizationId = input.organization_id ?? input.organizationId;
  const deviceId = input.device_id ?? input.deviceId;
  const afterGeneration = input.after_generation ?? input.afterGeneration ?? 0;
  const timeoutMs = input.timeout_ms ?? input.timeoutMs ?? maxWaitMs;
  const signal = input.signal;
  if (!UUID.test(organizationId ?? "") || !UUID.test(deviceId ?? "")
    || !Number.isSafeInteger(afterGeneration) || afterGeneration < 0
    || !Number.isSafeInteger(timeoutMs) || timeoutMs < 0 || timeoutMs > maxWaitMs
    || (signal !== undefined && (!signal || typeof signal.aborted !== "boolean" || typeof signal.addEventListener !== "function"))) invalidInput();
  return Object.freeze({
    organizationId: organizationId.toLowerCase(),
    deviceId: deviceId.toLowerCase(),
    afterGeneration,
    timeoutMs,
    signal
  });
}

function parseNotification(message) {
  if (!message || message.channel !== REFRESH_HINT_NOTIFY_CHANNEL || typeof message.payload !== "string"
    || Buffer.byteLength(message.payload, "utf8") > MAX_NOTIFY_PAYLOAD_BYTES) return null;
  let payload;
  try { payload = JSON.parse(message.payload); } catch { return null; }
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) return null;
  const keys = Object.keys(payload).sort();
  if (keys.length !== 3 || keys[0] !== "desired_generation" || keys[1] !== "device_id" || keys[2] !== "organization_id"
    || !UUID.test(payload.organization_id ?? "") || !UUID.test(payload.device_id ?? "")
    || !Number.isSafeInteger(payload.desired_generation) || payload.desired_generation < 1) return null;
  return Object.freeze({
    organizationId: payload.organization_id.toLowerCase(),
    deviceId: payload.device_id.toLowerCase(),
    desiredGeneration: payload.desired_generation
  });
}

function validateClient(client) {
  if (!client || typeof client.query !== "function" || typeof client.on !== "function"
    || typeof client.removeListener !== "function" || typeof client.release !== "function") {
    throw new RefreshHintNotifierError(REFRESH_HINT_NOTIFIER_ERROR_CODES.INPUT, "pool.connect() did not return a releasable pg client");
  }
}

async function releaseUnattached(client, destroy) {
  if (!client) return;
  if (typeof client.release === "function") {
    try { await client.release(destroy === true); } catch { /* release is best effort during failure */ }
  } else if (typeof client.end === "function") {
    try { await client.end(); } catch { /* end is best effort during failure */ }
  }
}

function removeListener(client, event, handler) {
  try { client.removeListener(event, handler); } catch { /* fake/test clients may not support removal */ }
}

function boundedInteger(value, min, max, name) {
  if (!Number.isSafeInteger(value) || value < min || value > max) {
    throw new RefreshHintNotifierError(REFRESH_HINT_NOTIFIER_ERROR_CODES.INPUT, `${name} is invalid`);
  }
  return value;
}

function clock(now) {
  const value = now();
  return value instanceof Date ? value.getTime() : value;
}

function invalidInput() {
  throw new RefreshHintNotifierError(REFRESH_HINT_NOTIFIER_ERROR_CODES.INPUT, "refresh notifier input is invalid");
}

function abortedError() {
  const error = new RefreshHintNotifierError(REFRESH_HINT_NOTIFIER_ERROR_CODES.ABORTED, "refresh notification wait was aborted");
  error.name = "AbortError";
  return error;
}

export default createPostgresRefreshHintNotifier;
export const createRefreshHintNotifier = createPostgresRefreshHintNotifier;
