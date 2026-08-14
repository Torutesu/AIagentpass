import crypto from "node:crypto";

export const MANAGED_SIGNER_KEY_STATES = Object.freeze({
  ACTIVE: "active",
  RETIRING: "retiring",
  REVOKED: "revoked",
  EMERGENCY_DISABLED: "emergency-disabled"
});

export const MANAGED_SIGNER_KEY_LIFECYCLE_DEFAULTS = Object.freeze({
  maxVerificationOverlapMs: 90 * 24 * 60 * 60 * 1000,
  maxKeys: 4,
  maxIdempotencyEntries: 512
});

export const MANAGED_SIGNER_KEY_LIFECYCLE_ERROR_CODES = Object.freeze({
  CONFIG: "ERR_MANAGED_SIGNER_KEY_LIFECYCLE_CONFIG",
  PURPOSE: "ERR_MANAGED_SIGNER_KEY_LIFECYCLE_PURPOSE",
  VERSION: "ERR_MANAGED_SIGNER_KEY_LIFECYCLE_VERSION",
  TRANSITION: "ERR_MANAGED_SIGNER_KEY_LIFECYCLE_TRANSITION",
  OVERLAP: "ERR_MANAGED_SIGNER_KEY_LIFECYCLE_OVERLAP",
  DUPLICATE: "ERR_MANAGED_SIGNER_KEY_LIFECYCLE_DUPLICATE",
  NOT_ACTIVE: "ERR_MANAGED_SIGNER_KEY_LIFECYCLE_NOT_ACTIVE",
  NOT_VERIFIABLE: "ERR_MANAGED_SIGNER_KEY_LIFECYCLE_NOT_VERIFIABLE",
  IDEMPOTENCY: "ERR_MANAGED_SIGNER_KEY_LIFECYCLE_IDEMPOTENCY"
});

const STATES = new Set(Object.values(MANAGED_SIGNER_KEY_STATES));
const KEY_ID = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$/u;
const PURPOSE = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/u;
const ALGORITHM = "ed25519";
const FINGERPRINT = /^[0-9a-f]{64}$/u;
const ISO = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u;
const PUBLIC_KEY_PEM = /^-----BEGIN PUBLIC KEY-----\n[\s\S]+\n-----END PUBLIC KEY-----\n$/u;
const SNAPSHOT_KEYS = Object.freeze(["algorithm", "keys", "purpose", "version"]);
const KEY_REQUIRED_KEYS = Object.freeze(["algorithm", "key_id", "key_version", "public_key_fingerprint", "purpose", "state", "state_version"]);
const KEY_OPTIONAL_KEYS = Object.freeze(["public_key", "verification_until"]);
const ERROR_MESSAGES = Object.freeze({
  [MANAGED_SIGNER_KEY_LIFECYCLE_ERROR_CODES.CONFIG]: "managed signer key lifecycle configuration is invalid",
  [MANAGED_SIGNER_KEY_LIFECYCLE_ERROR_CODES.PURPOSE]: "managed signer key lifecycle purpose is invalid",
  [MANAGED_SIGNER_KEY_LIFECYCLE_ERROR_CODES.VERSION]: "managed signer key lifecycle version is invalid",
  [MANAGED_SIGNER_KEY_LIFECYCLE_ERROR_CODES.TRANSITION]: "managed signer key lifecycle transition is not permitted",
  [MANAGED_SIGNER_KEY_LIFECYCLE_ERROR_CODES.OVERLAP]: "managed signer key verification overlap is invalid",
  [MANAGED_SIGNER_KEY_LIFECYCLE_ERROR_CODES.DUPLICATE]: "managed signer key lifecycle contains a duplicate",
  [MANAGED_SIGNER_KEY_LIFECYCLE_ERROR_CODES.NOT_ACTIVE]: "managed signer key is not active",
  [MANAGED_SIGNER_KEY_LIFECYCLE_ERROR_CODES.NOT_VERIFIABLE]: "managed signer key is not verifiable",
  [MANAGED_SIGNER_KEY_LIFECYCLE_ERROR_CODES.IDEMPOTENCY]: "managed signer key lifecycle idempotency conflict"
});

export class ManagedSignerKeyLifecycleError extends Error {
  constructor(code) {
    super(ERROR_MESSAGES[code] ?? ERROR_MESSAGES[MANAGED_SIGNER_KEY_LIFECYCLE_ERROR_CODES.CONFIG]);
    this.name = "ManagedSignerKeyLifecycleError";
    this.code = code;
  }
}

/**
 * Keep key authority transitions in one versioned, fail-closed state machine.
 * The controller contains public metadata only. Private key material is never
 * accepted and the provider boundary separately enforces the active key.
 */
export function createManagedSignerKeyLifecycle({
  purpose,
  algorithm = ALGORITHM,
  snapshot,
  now = () => Date.now(),
  maxVerificationOverlapMs = MANAGED_SIGNER_KEY_LIFECYCLE_DEFAULTS.maxVerificationOverlapMs,
  maxKeys = MANAGED_SIGNER_KEY_LIFECYCLE_DEFAULTS.maxKeys,
  maxIdempotencyEntries = MANAGED_SIGNER_KEY_LIFECYCLE_DEFAULTS.maxIdempotencyEntries
} = {}) {
  validateOptions({ purpose, algorithm, now, maxVerificationOverlapMs, maxKeys, maxIdempotencyEntries });
  let current = normalizeSnapshot(snapshot, { purpose, algorithm, now: readNow(now), maxVerificationOverlapMs, maxKeys, allowExpiredRetiring: true });
  const operations = new Map();

  function currentSnapshot() {
    return cloneSnapshot(current);
  }

  function activeKey() {
    return current.keys.find((key) => key.state === MANAGED_SIGNER_KEY_STATES.ACTIVE);
  }

  function assertCanSign(keyId) {
    const key = findKey(keyId);
    if (key.state !== MANAGED_SIGNER_KEY_STATES.ACTIVE) fail(MANAGED_SIGNER_KEY_LIFECYCLE_ERROR_CODES.NOT_ACTIVE);
    return cloneKey(key);
  }

  function resolveVerificationKey(keyId, at = undefined) {
    const key = findKey(keyId);
    const currentNow = readNow(at === undefined ? now : at);
    if (!isVerifiable(key, currentNow)) fail(MANAGED_SIGNER_KEY_LIFECYCLE_ERROR_CODES.NOT_VERIFIABLE);
    return cloneKey(key);
  }

  function transitionKey({ expected_version, operation_id, key_id, to, verification_until } = {}) {
    const request = { expected_version, key_id, to, ...(verification_until === undefined ? {} : { verification_until }) };
    return idempotent(operation_id, request, () => {
      assertExpectedVersion(expected_version, current.version);
      requireOperationId(operation_id);
      const index = current.keys.findIndex((key) => key.key_id === key_id);
      if (index < 0) fail(MANAGED_SIGNER_KEY_LIFECYCLE_ERROR_CODES.TRANSITION);
      const source = current.keys[index];
      assertTransition(source.state, to);
      const updated = transitionRecord(source, to, verification_until, readNow(now), current.version + 1);
      return commit({ ...current, keys: replaceAt(current.keys, index, updated) });
    });
  }

  /** Atomically activates a new key and moves the current active key to overlap. */
  function rotate({ expected_version, operation_id, new_key, verification_until } = {}) {
    const request = { expected_version, new_key, verification_until };
    return idempotent(operation_id, request, () => {
      assertExpectedVersion(expected_version, current.version);
      requireOperationId(operation_id);
      const currentActive = activeKey();
      if (!currentActive || verification_until === undefined) fail(MANAGED_SIGNER_KEY_LIFECYCLE_ERROR_CODES.TRANSITION);
      const currentNow = readNow(now);
      const newRecord = normalizeKey(new_key, { purpose, algorithm, now: currentNow, maxVerificationOverlapMs, allowExpiredRetiring: false });
      if (newRecord.state !== MANAGED_SIGNER_KEY_STATES.ACTIVE || current.keys.some((key) => key.key_id === newRecord.key_id
        || key.public_key_fingerprint === newRecord.public_key_fingerprint)) {
        fail(MANAGED_SIGNER_KEY_LIFECYCLE_ERROR_CODES.DUPLICATE);
      }
      if (current.keys.length >= maxKeys) fail(MANAGED_SIGNER_KEY_LIFECYCLE_ERROR_CODES.CONFIG);
      if (!Number.isSafeInteger(newRecord.key_version) || newRecord.key_version <= maxKeyVersion(current.keys)) {
        fail(MANAGED_SIGNER_KEY_LIFECYCLE_ERROR_CODES.VERSION);
      }
      const retiring = transitionRecord(currentActive, MANAGED_SIGNER_KEY_STATES.RETIRING, verification_until, currentNow, current.version + 1);
      const activated = Object.freeze({ ...newRecord, state_version: current.version + 1 });
      const retained = current.keys.map((key) => key.key_id === currentActive.key_id ? retiring : key);
      return commit({ ...current, keys: [...retained, activated] });
    });
  }

  /** Emergency disable is an atomic terminal transition for every key. */
  function emergencyDisable({ expected_version, operation_id } = {}) {
    const request = { expected_version };
    return idempotent(operation_id, request, () => {
      assertExpectedVersion(expected_version, current.version);
      requireOperationId(operation_id);
      if (current.keys.every((key) => key.state === MANAGED_SIGNER_KEY_STATES.EMERGENCY_DISABLED)) {
        fail(MANAGED_SIGNER_KEY_LIFECYCLE_ERROR_CODES.TRANSITION);
      }
      const transitionVersion = current.version + 1;
      return commit({
        ...current,
        version: transitionVersion,
        keys: current.keys.map((key) => Object.freeze({ ...key, state: MANAGED_SIGNER_KEY_STATES.EMERGENCY_DISABLED, state_version: transitionVersion, verification_until: undefined }))
      });
    });
  }

  /** Restore only by introducing a strictly newer key; disabled keys stay terminal. */
  function restore({ expected_version, operation_id, new_key } = {}) {
    const request = { expected_version, new_key };
    return idempotent(operation_id, request, () => {
      assertExpectedVersion(expected_version, current.version);
      requireOperationId(operation_id);
      if (activeKey()) fail(MANAGED_SIGNER_KEY_LIFECYCLE_ERROR_CODES.TRANSITION);
      const currentNow = readNow(now);
      const newRecord = normalizeKey(new_key, { purpose, algorithm, now: currentNow, maxVerificationOverlapMs, allowExpiredRetiring: false });
      if (newRecord.state !== MANAGED_SIGNER_KEY_STATES.ACTIVE || current.keys.some((key) => key.key_id === newRecord.key_id
        || key.public_key_fingerprint === newRecord.public_key_fingerprint)) {
        fail(MANAGED_SIGNER_KEY_LIFECYCLE_ERROR_CODES.DUPLICATE);
      }
      if (newRecord.key_version <= maxKeyVersion(current.keys)) fail(MANAGED_SIGNER_KEY_LIFECYCLE_ERROR_CODES.VERSION);
      if (current.keys.length >= maxKeys) fail(MANAGED_SIGNER_KEY_LIFECYCLE_ERROR_CODES.CONFIG);
      return commit({ ...current, keys: [...current.keys, Object.freeze({ ...newRecord, state_version: current.version + 1 })] });
    });
  }

  function idempotent(operationId, request, operation) {
    requireOperationId(operationId);
    const digest = canonicalDigest(request);
    const previous = operations.get(operationId);
    if (previous) {
      if (previous.digest !== digest) fail(MANAGED_SIGNER_KEY_LIFECYCLE_ERROR_CODES.IDEMPOTENCY);
      return cloneSnapshot(previous.result);
    }
    const result = operation();
    operations.set(operationId, { digest, result: cloneSnapshot(result) });
    while (operations.size > maxIdempotencyEntries) operations.delete(operations.keys().next().value);
    return currentSnapshot(result);
  }

  function commit(next) {
    const version = current.version + 1;
    if (!Number.isSafeInteger(version) || version <= current.version) fail(MANAGED_SIGNER_KEY_LIFECYCLE_ERROR_CODES.VERSION);
    current = normalizeSnapshot({ ...next, version }, { purpose, algorithm, now: readNow(now), maxVerificationOverlapMs, maxKeys, allowExpiredRetiring: true });
    return current;
  }

  function findKey(keyId) {
    if (typeof keyId !== "string") fail(MANAGED_SIGNER_KEY_LIFECYCLE_ERROR_CODES.CONFIG);
    const key = current.keys.find((candidate) => candidate.key_id === keyId);
    if (!key) fail(MANAGED_SIGNER_KEY_LIFECYCLE_ERROR_CODES.CONFIG);
    return key;
  }

  return Object.freeze({
    purpose,
    algorithm,
    snapshot: currentSnapshot,
    activeKey: () => {
      const key = activeKey();
      return key ? cloneKey(key) : undefined;
    },
    assertCanSign,
    resolveVerificationKey,
    transitionKey,
    rotate,
    emergencyDisable,
    restore
  });
}

/** Validate a serializable lifecycle snapshot before it is trusted. */
export function parseManagedSignerKeyLifecycleSnapshot(snapshot, options = {}) {
  const purpose = options.purpose ?? snapshot?.purpose;
  const algorithm = options.algorithm ?? snapshot?.algorithm ?? ALGORITHM;
  const now = options.now ?? (() => Date.now());
  const maxVerificationOverlapMs = options.maxVerificationOverlapMs ?? MANAGED_SIGNER_KEY_LIFECYCLE_DEFAULTS.maxVerificationOverlapMs;
  const maxKeys = options.maxKeys ?? MANAGED_SIGNER_KEY_LIFECYCLE_DEFAULTS.maxKeys;
  validateOptions({ purpose, algorithm, now, maxVerificationOverlapMs, maxKeys, maxIdempotencyEntries: MANAGED_SIGNER_KEY_LIFECYCLE_DEFAULTS.maxIdempotencyEntries });
  return cloneSnapshot(normalizeSnapshot(snapshot, { purpose, algorithm, now: readNow(now), maxVerificationOverlapMs, maxKeys, allowExpiredRetiring: true }));
}

function normalizeSnapshot(snapshot, options) {
  if (!plainObject(snapshot) || !exactKeys(snapshot, SNAPSHOT_KEYS) || snapshot.purpose !== options.purpose || snapshot.algorithm !== options.algorithm
    || !Number.isSafeInteger(snapshot.version) || snapshot.version < 1 || snapshot.version > Number.MAX_SAFE_INTEGER
    || !Array.isArray(snapshot.keys) || snapshot.keys.length < 1 || snapshot.keys.length > options.maxKeys) {
    fail(MANAGED_SIGNER_KEY_LIFECYCLE_ERROR_CODES.CONFIG);
  }
  const keys = snapshot.keys.map((key) => normalizeKey(key, options));
  const ids = new Set();
  const fingerprints = new Set();
  const keyVersions = new Set();
  for (const key of keys) {
    if (ids.has(key.key_id) || fingerprints.has(key.public_key_fingerprint) || keyVersions.has(key.key_version)) fail(MANAGED_SIGNER_KEY_LIFECYCLE_ERROR_CODES.DUPLICATE);
    ids.add(key.key_id);
    fingerprints.add(key.public_key_fingerprint);
    keyVersions.add(key.key_version);
    if (key.state_version > snapshot.version) fail(MANAGED_SIGNER_KEY_LIFECYCLE_ERROR_CODES.VERSION);
  }
  if (keys.filter((key) => key.state === MANAGED_SIGNER_KEY_STATES.ACTIVE).length > 1) {
    fail(MANAGED_SIGNER_KEY_LIFECYCLE_ERROR_CODES.TRANSITION);
  }
  return Object.freeze({ version: snapshot.version, purpose: options.purpose, algorithm: options.algorithm, keys: Object.freeze(keys) });
}

function normalizeKey(value, options) {
  if (!plainObject(value) || !closedKeys(value, KEY_REQUIRED_KEYS, KEY_OPTIONAL_KEYS) || !KEY_ID.test(value.key_id ?? "") || value.purpose !== options.purpose
    || value.algorithm !== options.algorithm || !Number.isSafeInteger(value.key_version) || value.key_version < 1
    || value.key_version > Number.MAX_SAFE_INTEGER || !STATES.has(value.state)
    || !Number.isSafeInteger(value.state_version) || value.state_version < 1
    || typeof value.public_key_fingerprint !== "string" || !FINGERPRINT.test(value.public_key_fingerprint)) {
    fail(MANAGED_SIGNER_KEY_LIFECYCLE_ERROR_CODES.CONFIG);
  }
  const publicKey = validatePublicKey(value.public_key, value.public_key_fingerprint);
  const normalized = {
    key_id: value.key_id,
    key_version: value.key_version,
    purpose: options.purpose,
    algorithm: options.algorithm,
    public_key_fingerprint: value.public_key_fingerprint,
    state: value.state,
    state_version: value.state_version,
    ...(publicKey === undefined ? {} : { public_key: publicKey })
  };
  if (value.state === MANAGED_SIGNER_KEY_STATES.RETIRING) {
    if (typeof value.verification_until !== "string" || !validIso(value.verification_until)) fail(MANAGED_SIGNER_KEY_LIFECYCLE_ERROR_CODES.OVERLAP);
    const expiry = Date.parse(value.verification_until);
    if (!options.allowExpiredRetiring && expiry <= options.now) fail(MANAGED_SIGNER_KEY_LIFECYCLE_ERROR_CODES.OVERLAP);
    if (expiry > options.now + options.maxVerificationOverlapMs) fail(MANAGED_SIGNER_KEY_LIFECYCLE_ERROR_CODES.OVERLAP);
    normalized.verification_until = value.verification_until;
  } else if (value.verification_until !== undefined && value.verification_until !== null) {
    fail(MANAGED_SIGNER_KEY_LIFECYCLE_ERROR_CODES.CONFIG);
  }
  return Object.freeze(normalized);
}

function transitionRecord(source, to, verificationUntil, now, transitionVersion) {
  if (to === MANAGED_SIGNER_KEY_STATES.RETIRING) {
    const expiry = parseOverlap(verificationUntil, now);
    return Object.freeze({ ...source, state: to, state_version: transitionVersion, verification_until: expiry });
  }
  return Object.freeze({ ...source, state: to, state_version: transitionVersion, verification_until: undefined });
}

function assertTransition(from, to) {
  const allowed = {
    [MANAGED_SIGNER_KEY_STATES.ACTIVE]: new Set([MANAGED_SIGNER_KEY_STATES.RETIRING, MANAGED_SIGNER_KEY_STATES.REVOKED, MANAGED_SIGNER_KEY_STATES.EMERGENCY_DISABLED]),
    [MANAGED_SIGNER_KEY_STATES.RETIRING]: new Set([MANAGED_SIGNER_KEY_STATES.REVOKED, MANAGED_SIGNER_KEY_STATES.EMERGENCY_DISABLED]),
    [MANAGED_SIGNER_KEY_STATES.REVOKED]: new Set([MANAGED_SIGNER_KEY_STATES.EMERGENCY_DISABLED]),
    [MANAGED_SIGNER_KEY_STATES.EMERGENCY_DISABLED]: new Set()
  };
  if (!STATES.has(to) || !allowed[from]?.has(to)) fail(MANAGED_SIGNER_KEY_LIFECYCLE_ERROR_CODES.TRANSITION);
}

function parseOverlap(value, now) {
  if (typeof value !== "string" || !validIso(value) || Date.parse(value) <= now) fail(MANAGED_SIGNER_KEY_LIFECYCLE_ERROR_CODES.OVERLAP);
  return value;
}

function isVerifiable(key, now) {
  return key.state === MANAGED_SIGNER_KEY_STATES.ACTIVE
    || (key.state === MANAGED_SIGNER_KEY_STATES.RETIRING && Date.parse(key.verification_until) > now);
}

function maxKeyVersion(keys) {
  return Math.max(...keys.map((key) => key.key_version));
}

function validatePublicKey(value, fingerprint) {
  if (value === undefined) return undefined;
  if (typeof value !== "string" || !PUBLIC_KEY_PEM.test(value) || /PRIVATE\s+KEY/iu.test(value)) fail(MANAGED_SIGNER_KEY_LIFECYCLE_ERROR_CODES.CONFIG);
  let key;
  try { key = crypto.createPublicKey(value); } catch { fail(MANAGED_SIGNER_KEY_LIFECYCLE_ERROR_CODES.CONFIG); }
  if (key.type !== "public" || key.asymmetricKeyType !== ALGORITHM) fail(MANAGED_SIGNER_KEY_LIFECYCLE_ERROR_CODES.CONFIG);
  const pem = key.export({ type: "spki", format: "pem" }).toString();
  const actual = crypto.createHash("sha256").update(key.export({ type: "spki", format: "der" })).digest("hex");
  if (actual !== fingerprint || pem !== value) fail(MANAGED_SIGNER_KEY_LIFECYCLE_ERROR_CODES.CONFIG);
  return pem;
}

function validateOptions({ purpose, algorithm, now, maxVerificationOverlapMs, maxKeys, maxIdempotencyEntries }) {
  if (typeof purpose !== "string" || !PURPOSE.test(purpose) || algorithm !== ALGORITHM || typeof now !== "function"
    || !Number.isSafeInteger(maxVerificationOverlapMs) || maxVerificationOverlapMs < 1 || maxVerificationOverlapMs > 365 * 24 * 60 * 60 * 1000
    || !Number.isSafeInteger(maxKeys) || maxKeys < 1 || maxKeys > 32
    || !Number.isSafeInteger(maxIdempotencyEntries) || maxIdempotencyEntries < 1 || maxIdempotencyEntries > 4096) {
    fail(MANAGED_SIGNER_KEY_LIFECYCLE_ERROR_CODES.CONFIG);
  }
}

function assertExpectedVersion(value, currentVersion) {
  if (!Number.isSafeInteger(value) || value < 1 || value !== currentVersion) fail(MANAGED_SIGNER_KEY_LIFECYCLE_ERROR_CODES.VERSION);
}

function requireOperationId(value) {
  if (typeof value !== "string" || value.length < 1 || value.length > 256 || !/^[A-Za-z0-9][A-Za-z0-9._:/-]*$/u.test(value)) {
    fail(MANAGED_SIGNER_KEY_LIFECYCLE_ERROR_CODES.CONFIG);
  }
}

function readNow(clockOrValue) {
  const value = typeof clockOrValue === "function" ? clockOrValue() : clockOrValue;
  const result = value instanceof Date ? value.getTime() : value;
  if (!Number.isSafeInteger(result) || result < 0) fail(MANAGED_SIGNER_KEY_LIFECYCLE_ERROR_CODES.CONFIG);
  return result;
}

function validIso(value) {
  return ISO.test(value) && Number.isFinite(Date.parse(value)) && new Date(Date.parse(value)).toISOString() === value;
}

function canonicalDigest(value) {
  return crypto.createHash("sha256").update(canonicalJson(value)).digest("hex");
}

function canonicalJson(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
}

function cloneSnapshot(value) {
  return Object.freeze({ ...value, keys: Object.freeze(value.keys.map(cloneKey)) });
}

function cloneKey(value) {
  return Object.freeze({ ...value });
}

function replaceAt(values, index, value) {
  return values.map((candidate, candidateIndex) => candidateIndex === index ? value : candidate);
}

function fail(code) {
  throw new ManagedSignerKeyLifecycleError(code);
}

/**
 * Bind a cloud provider to the lifecycle. Optional idempotency keys are
 * consumed at this boundary and never forwarded to strict KMS requests.
 * Providers that expose `signIdempotent` may durably reconcile response loss;
 * ordinary AWS/GCP Sign calls retain only bounded in-process replay results.
 */
export function createManagedSignerLifecycleProvider({ provider, lifecycle, maxIdempotencyEntries = 128 } = {}) {
  if (!provider || typeof provider.publicKeyMetadata !== "function" || typeof provider.sign !== "function"
    || !lifecycle || typeof lifecycle.assertCanSign !== "function" || typeof lifecycle.snapshot !== "function"
    || provider.purpose !== lifecycle.purpose || provider.algorithm !== lifecycle.algorithm || typeof provider.key_id !== "string"
    || !Number.isSafeInteger(maxIdempotencyEntries) || maxIdempotencyEntries < 1 || maxIdempotencyEntries > 1024) {
    fail(MANAGED_SIGNER_KEY_LIFECYCLE_ERROR_CODES.CONFIG);
  }
  assertProviderActive(provider, lifecycle);
  const cache = new Map();

  async function publicKeyMetadata(input) {
    assertProviderActive(provider, lifecycle);
    return provider.publicKeyMetadata(input);
  }

  async function sign(input) {
    assertProviderActive(provider, lifecycle);
    const { request, idempotencyKey, digest } = normalizeIdempotentRequest(input, provider);
    if (idempotencyKey === undefined) return provider.sign(request);
    const existing = cache.get(idempotencyKey);
    if (existing) {
      if (existing.digest !== digest) fail(MANAGED_SIGNER_KEY_LIFECYCLE_ERROR_CODES.IDEMPOTENCY);
      return cloneBytes(await existing.promise);
    }
    const operation = typeof provider.signIdempotent === "function"
      ? provider.signIdempotent({ ...request, idempotency_key: idempotencyKey })
      : provider.sign(request);
    const promise = Promise.resolve(operation).then((value) => {
      const bytes = normalizeResultBytes(value);
      cache.set(idempotencyKey, { digest, promise: Promise.resolve(bytes) });
      return bytes;
    }, (error) => {
      cache.delete(idempotencyKey);
      throw error;
    });
    cache.set(idempotencyKey, { digest, promise });
    while (cache.size > maxIdempotencyEntries) cache.delete(cache.keys().next().value);
    return cloneBytes(await promise);
  }

  return Object.freeze({
    key_id: provider.key_id,
    purpose: provider.purpose,
    algorithm: provider.algorithm,
    version: provider.version,
    public_key_fingerprint: provider.public_key_fingerprint,
    lifecycleState: () => lifecycle.snapshot(),
    publicKeyMetadata,
    sign
  });
}

function normalizeIdempotentRequest(input, provider) {
  if (!plainObject(input) || !closedKeys(input, ["bytes"], ["algorithm", "idempotency_key", "key_id", "purpose", "request_id", "signal", "version"])
    || (input.idempotency_key !== undefined && input.request_id !== undefined)) fail(MANAGED_SIGNER_KEY_LIFECYCLE_ERROR_CODES.CONFIG);
  const idempotencyKey = input.idempotency_key ?? input.request_id;
  if (idempotencyKey !== undefined && (typeof idempotencyKey !== "string" || idempotencyKey.length < 1 || idempotencyKey.length > 256
    || !/^[A-Za-z0-9][A-Za-z0-9._:/-]*$/u.test(idempotencyKey))) fail(MANAGED_SIGNER_KEY_LIFECYCLE_ERROR_CODES.CONFIG);
  const request = { ...input };
  delete request.idempotency_key;
  delete request.request_id;
  const bytes = Buffer.isBuffer(request.bytes) || request.bytes instanceof Uint8Array
    ? Buffer.from(request.bytes)
    : fail(MANAGED_SIGNER_KEY_LIFECYCLE_ERROR_CODES.CONFIG);
  const digest = canonicalDigest({
    key_id: request.key_id ?? provider.key_id,
    purpose: request.purpose ?? provider.purpose,
    algorithm: request.algorithm ?? provider.algorithm,
    version: request.version ?? provider.version,
    bytes: bytes.toString("base64")
  });
  return { request, idempotencyKey, digest };
}

function normalizeResultBytes(value) {
  if (!Buffer.isBuffer(value) && !(value instanceof Uint8Array)) fail(MANAGED_SIGNER_KEY_LIFECYCLE_ERROR_CODES.CONFIG);
  return Buffer.from(value);
}

function cloneBytes(value) {
  return Buffer.from(value);
}

function plainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    && (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null);
}

function assertProviderActive(provider, lifecycle) {
  const key = lifecycle.assertCanSign(provider.key_id);
  if (!plainObject(key) || key.key_id !== provider.key_id || key.purpose !== provider.purpose
    || key.algorithm !== provider.algorithm || key.public_key_fingerprint !== provider.public_key_fingerprint
    || key.state !== MANAGED_SIGNER_KEY_STATES.ACTIVE) fail(MANAGED_SIGNER_KEY_LIFECYCLE_ERROR_CODES.CONFIG);
  return key;
}

function exactKeys(value, expected) {
  return closedKeys(value, expected, []) && Reflect.ownKeys(value).length === expected.length;
}

function closedKeys(value, required, optional) {
  if (!plainObject(value)) return false;
  const allowed = new Set([...required, ...optional]);
  const keys = Reflect.ownKeys(value);
  return keys.every((key) => typeof key === "string" && allowed.has(key)
      && Object.getOwnPropertyDescriptor(value, key)?.enumerable === true)
    && required.every((key) => Object.hasOwn(value, key) && value[key] !== undefined);
}
