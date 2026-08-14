import { REMOTE_KMS_ALGORITHM, REMOTE_KMS_ERROR_CODES } from "./remote-kms-provider.mjs";

export const MANAGED_SIGNER_RELIABILITY_ERROR_CODES = Object.freeze({
  CONFIG: "ERR_MANAGED_SIGNER_RELIABILITY_CONFIG",
  TIMEOUT: "ERR_MANAGED_SIGNER_TIMEOUT",
  PROVIDER: "ERR_MANAGED_SIGNER_PROVIDER",
  THROTTLED: "ERR_MANAGED_SIGNER_THROTTLED",
  CIRCUIT_OPEN: "ERR_MANAGED_SIGNER_CIRCUIT_OPEN"
});

export const MANAGED_SIGNER_RELIABILITY_DEFAULTS = Object.freeze({
  failureThreshold: 3,
  cooldownMs: 5_000,
  maxInFlight: 8
});

const PHASES = Object.freeze({ CLOSED: "closed", OPEN: "open", HALF_OPEN: "half-open" });
const THROTTLE_CODES = new Set([
  "429",
  "ERR_REMOTE_KMS_THROTTLED",
  "ERR_TOO_MANY_REQUESTS",
  "RATE_LIMITED",
  "RESOURCE_EXHAUSTED",
  "TOO_MANY_REQUESTS",
  "THROTTLED",
  "THROTTLINGEXCEPTION"
]);

const MESSAGES = Object.freeze({
  [MANAGED_SIGNER_RELIABILITY_ERROR_CODES.CONFIG]: "managed signer reliability configuration is invalid",
  [MANAGED_SIGNER_RELIABILITY_ERROR_CODES.TIMEOUT]: "managed signer timed out",
  [MANAGED_SIGNER_RELIABILITY_ERROR_CODES.PROVIDER]: "managed signer provider is unavailable",
  [MANAGED_SIGNER_RELIABILITY_ERROR_CODES.THROTTLED]: "managed signer request was throttled",
  [MANAGED_SIGNER_RELIABILITY_ERROR_CODES.CIRCUIT_OPEN]: "managed signer circuit is open"
});

export class ManagedSignerReliabilityError extends Error {
  constructor(code) {
    super(MESSAGES[code] ?? MESSAGES[MANAGED_SIGNER_RELIABILITY_ERROR_CODES.PROVIDER]);
    this.name = "ManagedSignerReliabilityError";
    this.code = code;
  }
}

/**
 * Add a bounded, fail-closed reliability boundary to one managed signer.
 * There is no queue: work above maxInFlight is rejected synchronously. The
 * returned object keeps one circuit per provider instance, which also keeps
 * independently bound signing purposes isolated.
 */
export function createManagedSignerReliabilityProvider({
  provider,
  purpose,
  failureThreshold = MANAGED_SIGNER_RELIABILITY_DEFAULTS.failureThreshold,
  cooldownMs = MANAGED_SIGNER_RELIABILITY_DEFAULTS.cooldownMs,
  maxInFlight = MANAGED_SIGNER_RELIABILITY_DEFAULTS.maxInFlight,
  clock = () => Date.now()
} = {}) {
  validateConfig({ provider, purpose, failureThreshold, cooldownMs, maxInFlight, clock });

  const state = {
    phase: PHASES.CLOSED,
    consecutiveFailures: 0,
    openedAt: undefined,
    active: 0,
    probeInFlight: false
  };

  async function publicKeyMetadata(input) {
    return invoke("publicKeyMetadata", input);
  }

  async function sign(input) {
    return invoke("sign", input);
  }

  function snapshot() {
    return Object.freeze({
      purpose,
      phase: state.phase,
      consecutive_failures: state.consecutiveFailures,
      active: state.active,
      probe_in_flight: state.probeInFlight,
      opened_at: state.openedAt
    });
  }

  async function invoke(method, input) {
    const permit = acquire();
    try {
      const result = await provider[method](input);
      onSuccess(permit);
      return result;
    } catch (error) {
      onFailure(permit, error);
      throw sanitizeFailure(error);
    } finally {
      state.active -= 1;
      if (permit.probe) state.probeInFlight = false;
    }
  }

  function acquire() {
    const now = readClock(clock);
    if (state.phase === PHASES.OPEN) {
      if (now < state.openedAt + cooldownMs) throw new ManagedSignerReliabilityError(MANAGED_SIGNER_RELIABILITY_ERROR_CODES.CIRCUIT_OPEN);
      state.phase = PHASES.HALF_OPEN;
      state.probeInFlight = false;
    }
    if (state.phase === PHASES.HALF_OPEN) {
      if (state.probeInFlight || state.active !== 0) throw new ManagedSignerReliabilityError(MANAGED_SIGNER_RELIABILITY_ERROR_CODES.THROTTLED);
      state.probeInFlight = true;
    }
    if (state.active >= maxInFlight) {
      if (state.phase === PHASES.HALF_OPEN) state.probeInFlight = false;
      throw new ManagedSignerReliabilityError(MANAGED_SIGNER_RELIABILITY_ERROR_CODES.THROTTLED);
    }
    state.active += 1;
    return Object.freeze({ probe: state.phase === PHASES.HALF_OPEN });
  }

  function onSuccess(permit) {
    if (permit.probe) {
      state.phase = PHASES.CLOSED;
      state.consecutiveFailures = 0;
      state.openedAt = undefined;
      return;
    }
    if (state.phase === PHASES.CLOSED) state.consecutiveFailures = 0;
  }

  function onFailure(permit, error) {
    const category = classifyManagedSignerFailure(error);
    if (permit.probe || category.transient) {
      state.consecutiveFailures = permit.probe ? failureThreshold : state.consecutiveFailures + 1;
      if (permit.probe || state.consecutiveFailures >= failureThreshold) {
        state.phase = PHASES.OPEN;
        state.openedAt = readClock(clock);
      }
    }
  }

  return Object.freeze({
    key_id: provider.key_id,
    purpose,
    algorithm: provider.algorithm,
    version: provider.version,
    public_key_fingerprint: provider.public_key_fingerprint,
    publicKeyMetadata,
    sign,
    reliabilityState: snapshot
  });
}

export function classifyManagedSignerFailure(error) {
  const code = typeof error?.code === "string" ? error.code.toUpperCase() : "";
  const name = typeof error?.name === "string" ? error.name.toUpperCase() : "";
  const status = error?.statusCode ?? error?.status ?? error?.$metadata?.httpStatusCode;
  if (error?.code === REMOTE_KMS_ERROR_CODES.TIMEOUT || code === MANAGED_SIGNER_RELIABILITY_ERROR_CODES.TIMEOUT) {
    return Object.freeze({ category: "timeout", transient: true, code: MANAGED_SIGNER_RELIABILITY_ERROR_CODES.TIMEOUT });
  }
  if (isThrottle(code, name, status) || error?.code === REMOTE_KMS_ERROR_CODES.THROTTLED) {
    return Object.freeze({ category: "throttle", transient: true, code: MANAGED_SIGNER_RELIABILITY_ERROR_CODES.THROTTLED });
  }
  if (error?.code === REMOTE_KMS_ERROR_CODES.PROVIDER || code === MANAGED_SIGNER_RELIABILITY_ERROR_CODES.PROVIDER) {
    return Object.freeze({ category: "provider", transient: true, code: MANAGED_SIGNER_RELIABILITY_ERROR_CODES.PROVIDER });
  }
  if (code === REMOTE_KMS_ERROR_CODES.INPUT || code === REMOTE_KMS_ERROR_CODES.PURPOSE
    || code === REMOTE_KMS_ERROR_CODES.ABORTED) {
    return Object.freeze({ category: "permanent", transient: false, code });
  }
  if (code === REMOTE_KMS_ERROR_CODES.METADATA || code === REMOTE_KMS_ERROR_CODES.OUTPUT
    || code === REMOTE_KMS_ERROR_CODES.SIGNATURE) {
    return Object.freeze({ category: "integrity", transient: true, code: MANAGED_SIGNER_RELIABILITY_ERROR_CODES.PROVIDER });
  }
  return Object.freeze({ category: "provider", transient: true, code: MANAGED_SIGNER_RELIABILITY_ERROR_CODES.PROVIDER });
}

function sanitizeFailure(error) {
  const category = classifyManagedSignerFailure(error);
  if (category.category === "timeout") return new ManagedSignerReliabilityError(MANAGED_SIGNER_RELIABILITY_ERROR_CODES.TIMEOUT);
  if (category.category === "throttle") return new ManagedSignerReliabilityError(MANAGED_SIGNER_RELIABILITY_ERROR_CODES.THROTTLED);
  if (category.category === "provider" || category.category === "integrity") {
    return new ManagedSignerReliabilityError(MANAGED_SIGNER_RELIABILITY_ERROR_CODES.PROVIDER);
  }
  return error;
}

function isThrottle(code, name, status) {
  return THROTTLE_CODES.has(code) || THROTTLE_CODES.has(name) || status === 429;
}

function readClock(clock) {
  const value = clock();
  if (!Number.isSafeInteger(value) || value < 0) throw new ManagedSignerReliabilityError(MANAGED_SIGNER_RELIABILITY_ERROR_CODES.CONFIG);
  return value;
}

function validateConfig({ provider, purpose, failureThreshold, cooldownMs, maxInFlight, clock }) {
  if (!provider || typeof provider.publicKeyMetadata !== "function" || typeof provider.sign !== "function"
    || typeof purpose !== "string" || purpose.length < 1 || purpose.length > 128
    || !Number.isSafeInteger(failureThreshold) || failureThreshold < 1 || failureThreshold > 100
    || !Number.isSafeInteger(cooldownMs) || cooldownMs < 1 || cooldownMs > 86_400_000
    || !Number.isSafeInteger(maxInFlight) || maxInFlight < 1 || maxInFlight > 32
    || typeof clock !== "function"
    || provider.purpose !== purpose
    || typeof provider.key_id !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$/u.test(provider.key_id)
    || provider.algorithm !== REMOTE_KMS_ALGORITHM
    || !Number.isSafeInteger(provider.version) || provider.version < 1 || provider.version > 255
    || typeof provider.public_key_fingerprint !== "string" || !/^[a-f0-9]{64}$/u.test(provider.public_key_fingerprint)) {
    throw new ManagedSignerReliabilityError(MANAGED_SIGNER_RELIABILITY_ERROR_CODES.CONFIG);
  }
}
