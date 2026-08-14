import crypto from "node:crypto";

import {
  CAPABILITY_REASONS,
  CAPABILITY_VERSION,
  DEFAULT_CLOCK_SKEW_MS,
  DEFAULT_MAX_TTL_MS,
  MIN_NONCE_BYTES,
  CapabilityError,
  canonicalCapability,
  validateCapability
} from "../../../packages/capability/src/index.mjs";
import { SIGNER_PURPOSE_REGISTRY } from "./signer-purpose-registry.mjs";

const REGISTRY_ENTRY = SIGNER_PURPOSE_REGISTRY.capability;

export const CAPABILITY_SIGNER_PURPOSE = REGISTRY_ENTRY.purpose;
export const CAPABILITY_SIGNER_ALGORITHM = REGISTRY_ENTRY.managed_algorithm;
export const CAPABILITY_SIGNER_REGISTRY_VERSION = REGISTRY_ENTRY.registry_version;
export const CAPABILITY_SIGNER_PROTOCOL_VERSION = REGISTRY_ENTRY.protocol_version;
export const CAPABILITY_SIGNER_SIGNING_VERSION = REGISTRY_ENTRY.signing_version;
export const CAPABILITY_SIGNER_VERSION = CAPABILITY_VERSION;

export const CAPABILITY_SIGNER_ERROR_CODES = Object.freeze({
  CONFIG: "ERR_CAPABILITY_SIGNER_CONFIG",
  INPUT: "ERR_CAPABILITY_SIGNER_INPUT",
  PROVIDER: "ERR_CAPABILITY_SIGNER_PROVIDER",
  TIMEOUT: "ERR_CAPABILITY_SIGNER_TIMEOUT",
  METADATA: "ERR_CAPABILITY_SIGNER_METADATA",
  OUTPUT: "ERR_CAPABILITY_SIGNER_OUTPUT",
  VERIFICATION: "ERR_CAPABILITY_SIGNER_VERIFICATION"
});

const KEY_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;
const PUBLIC_KEY_PEM = /^-----BEGIN PUBLIC KEY-----\n[\s\S]+\n-----END PUBLIC KEY-----\n$/u;
const MAX_PUBLIC_KEY_BYTES = 8 * 1024;
const MAX_SIGNATURE_BYTES = 64;
const DEFAULT_ISSUE_TTL_MS = 60 * 1000;
const ISSUE_INPUT_KEYS = new Set([
  "version", "capability_id", "nonce", "issuer", "key_id", "audience",
  "scope", "not_before", "expires_at", "sequence", "signature",
  "private_key", "signing_key", "ttl_ms", "ttlMs", "notBefore", "expiresAt", "keyId", "now"
]);

const MESSAGES = Object.freeze({
  [CAPABILITY_SIGNER_ERROR_CODES.CONFIG]: "capability signer configuration is invalid",
  [CAPABILITY_SIGNER_ERROR_CODES.INPUT]: "capability signer input is invalid",
  [CAPABILITY_SIGNER_ERROR_CODES.PROVIDER]: "capability signer provider failed",
  [CAPABILITY_SIGNER_ERROR_CODES.TIMEOUT]: "capability signer provider timed out",
  [CAPABILITY_SIGNER_ERROR_CODES.METADATA]: "capability signer metadata is invalid",
  [CAPABILITY_SIGNER_ERROR_CODES.OUTPUT]: "capability signer output is invalid",
  [CAPABILITY_SIGNER_ERROR_CODES.VERIFICATION]: "capability signer output could not be verified"
});

export class CapabilitySignerError extends Error {
  constructor(code) {
    super(MESSAGES[code] ?? MESSAGES[CAPABILITY_SIGNER_ERROR_CODES.CONFIG]);
    this.name = "CapabilitySignerError";
    this.code = code;
  }
}

/**
 * Create the hosted capability signing boundary.
 *
 * `provider` receives only purpose-bound public metadata requests and the
 * canonical unsigned capability bytes. It never receives a private key or a
 * caller-controlled protocol version. The public key is pinned at creation
 * time and every returned signature is verified before it becomes a
 * transport capability.
 */
export function createHostedCapabilitySigner({
  provider,
  keyId,
  publicKey,
  timeoutMs = 5_000,
  maxTtlMs = DEFAULT_MAX_TTL_MS,
  clockSkewMs = DEFAULT_CLOCK_SKEW_MS,
  now = () => Date.now()
} = {}) {
  const config = parseCapabilitySignerConfig({ keyId, publicKey, timeoutMs, maxTtlMs, clockSkewMs, now });
  if (!provider || typeof provider.publicKeyMetadata !== "function" || typeof provider.sign !== "function") {
    throw new CapabilitySignerError(CAPABILITY_SIGNER_ERROR_CODES.CONFIG);
  }

  let metadataPromise;

  async function loadMetadata() {
    if (!metadataPromise) {
      metadataPromise = (async () => {
        let metadata;
        try {
          metadata = await withDeadline((signal) => provider.publicKeyMetadata({
            key_id: config.keyId,
            algorithm: CAPABILITY_SIGNER_ALGORITHM,
            purpose: CAPABILITY_SIGNER_PURPOSE,
            version: CAPABILITY_SIGNER_PROTOCOL_VERSION,
            signal
          }), config.timeoutMs);
        } catch (error) {
          metadataPromise = undefined;
          if (error instanceof CapabilitySignerError) throw error;
          throw new CapabilitySignerError(CAPABILITY_SIGNER_ERROR_CODES.PROVIDER);
        }
        try {
          validateProviderMetadata(metadata, config);
        } catch (error) {
          metadataPromise = undefined;
          if (error instanceof CapabilitySignerError) throw error;
          throw new CapabilitySignerError(CAPABILITY_SIGNER_ERROR_CODES.METADATA);
        }
        return Object.freeze({
          version: CAPABILITY_SIGNER_VERSION,
          registry_version: CAPABILITY_SIGNER_REGISTRY_VERSION,
          protocol_version: CAPABILITY_SIGNER_PROTOCOL_VERSION,
          signing_version: CAPABILITY_SIGNER_SIGNING_VERSION,
          purpose: CAPABILITY_SIGNER_PURPOSE,
          key_id: config.keyId,
          algorithm: CAPABILITY_SIGNER_ALGORITHM,
          public_key: config.publicKeyPem,
          public_key_fingerprint: config.publicKeyFingerprint
        });
      })();
    }
    return metadataPromise;
  }

  async function publicKeyMetadata() {
    return loadMetadata();
  }

  async function signCapability(input) {
    const statement = normalizeStatement(input, config, now);
    const bytes = Buffer.from(canonicalCapability(statement), "utf8");
    await loadMetadata();

    let output;
    try {
      output = await withDeadline((signal) => provider.sign({
        bytes: Buffer.from(bytes),
        key_id: config.keyId,
        algorithm: CAPABILITY_SIGNER_ALGORITHM,
        purpose: CAPABILITY_SIGNER_PURPOSE,
        version: CAPABILITY_SIGNER_PROTOCOL_VERSION,
        signal
      }), config.timeoutMs);
    } catch (error) {
      if (error instanceof CapabilitySignerError) throw error;
      throw new CapabilitySignerError(CAPABILITY_SIGNER_ERROR_CODES.PROVIDER);
    }

    const signature = normalizeSignature(output);
    let verified = false;
    try { verified = crypto.verify(null, bytes, config.publicKey, signature); } catch { verified = false; }
    if (!verified) throw new CapabilitySignerError(CAPABILITY_SIGNER_ERROR_CODES.VERIFICATION);

    return deepFreeze({
      ...statement,
      signature: signature.toString("base64")
    });
  }

  async function health() {
    const metadata = await loadMetadata();
    return Object.freeze({
      ready: true,
      purpose: metadata.purpose,
      algorithm: metadata.algorithm,
      key_id: metadata.key_id,
      version: metadata.version,
      registry_version: metadata.registry_version,
      protocol_version: metadata.protocol_version,
      signing_version: metadata.signing_version,
      public_key_fingerprint: metadata.public_key_fingerprint
    });
  }

  const signer = {
    key_id: config.keyId,
    algorithm: CAPABILITY_SIGNER_ALGORITHM,
    purpose: CAPABILITY_SIGNER_PURPOSE,
    config,
    publicKeyMetadata,
    signCapability,
    issueCapability: signCapability,
    sign: signCapability,
    health
  };
  return Object.freeze(signer);
}

export const createCapabilitySigner = createHostedCapabilitySigner;

/**
 * Compatibility adapter for evaluation/local deployments. The private key is
 * captured only by the local provider closure and is not part of the returned
 * signer or any hosted provider request.
 */
export function createLocalCapabilitySigner({ privateKey, keyId, timeoutMs, maxTtlMs, clockSkewMs, now } = {}) {
  let signingKey;
  try { signingKey = privateKey?.type === "private" ? privateKey : crypto.createPrivateKey(privateKey); }
  catch { throw new CapabilitySignerError(CAPABILITY_SIGNER_ERROR_CODES.CONFIG); }
  if (signingKey.type !== "private" || signingKey.asymmetricKeyType !== CAPABILITY_SIGNER_ALGORITHM) {
    throw new CapabilitySignerError(CAPABILITY_SIGNER_ERROR_CODES.CONFIG);
  }
  const publicKey = crypto.createPublicKey(signingKey);
  return createHostedCapabilitySigner({
    keyId,
    publicKey,
    timeoutMs,
    maxTtlMs,
    clockSkewMs,
    now,
    provider: {
      async publicKeyMetadata() {
        return { key_id: keyId, algorithm: CAPABILITY_SIGNER_ALGORITHM, public_key: publicKey };
      },
      async sign({ bytes }) {
        return crypto.sign(null, bytes, signingKey);
      }
    }
  });
}

export function parseCapabilitySignerConfig({ keyId, publicKey, timeoutMs = 5_000, maxTtlMs = DEFAULT_MAX_TTL_MS, clockSkewMs = DEFAULT_CLOCK_SKEW_MS, now = () => Date.now() } = {}) {
  if (typeof keyId !== "string" || !KEY_ID.test(keyId) || typeof now !== "function"
    || !Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 30_000
    || !Number.isSafeInteger(maxTtlMs) || maxTtlMs < 1
    || !Number.isSafeInteger(clockSkewMs) || clockSkewMs < 0) {
    throw new CapabilitySignerError(CAPABILITY_SIGNER_ERROR_CODES.CONFIG);
  }
  const normalizedPublicKey = parsePublicKey(publicKey, CAPABILITY_SIGNER_ERROR_CODES.CONFIG);
  return deepFreeze({
    keyId,
    timeoutMs,
    maxTtlMs,
    clockSkewMs,
    publicKeyPem: normalizedPublicKey.export({ type: "spki", format: "pem" }).toString(),
    publicKeyFingerprint: fingerprint(normalizedPublicKey),
    publicKey: normalizedPublicKey
  });
}

function normalizeStatement(input, config, now) {
  if (!input || typeof input !== "object" || Array.isArray(input)
    || Object.hasOwn(input, "private_key") || Object.hasOwn(input, "signing_key")) {
    throw new CapabilitySignerError(CAPABILITY_SIGNER_ERROR_CODES.INPUT);
  }
  try {
    rejectUnknownInput(input);
    rejectAliases(input);

    const current = exactNow(now());
    const statement = {
      version: input.version ?? CAPABILITY_VERSION,
      capability_id: input.capability_id ?? crypto.randomUUID(),
      nonce: input.nonce ?? randomNonce(),
      issuer: input.issuer,
      key_id: input.key_id ?? input.keyId,
      audience: input.audience,
      scope: input.scope,
      not_before: input.not_before ?? input.notBefore,
      expires_at: input.expires_at ?? input.expiresAt,
      sequence: input.sequence
    };
    if (statement.not_before === undefined) statement.not_before = new Date(current).toISOString();
    else statement.not_before = issueTimestamp(statement.not_before);
    if (statement.expires_at === undefined) {
      const ttlMs = input.ttl_ms ?? input.ttlMs ?? DEFAULT_ISSUE_TTL_MS;
      if (!Number.isFinite(ttlMs) || ttlMs <= 0) throw new CapabilityError(CAPABILITY_REASONS.TTL_EXCEEDED);
      statement.expires_at = new Date(parseTimestamp(statement.not_before) + ttlMs).toISOString();
    } else statement.expires_at = issueTimestamp(statement.expires_at);

    const normalized = validateCapability(statement, {
      now: current,
      maxTtlMs: config.maxTtlMs,
      clockSkewMs: config.clockSkewMs
    });
    const { signature: _discardedSignature, ...normalizedStatement } = normalized;
    const finalStatement = normalizedStatement;
    if (finalStatement.key_id !== config.keyId) throw new CapabilitySignerError(CAPABILITY_SIGNER_ERROR_CODES.INPUT);
    return deepFreeze(finalStatement);
  } catch (error) {
    if (error instanceof CapabilitySignerError || error instanceof CapabilityError) throw error;
    throw new CapabilitySignerError(CAPABILITY_SIGNER_ERROR_CODES.INPUT);
  }
}

function rejectUnknownInput(input) {
  for (const key of Object.keys(input)) {
    if (!ISSUE_INPUT_KEYS.has(key)) throw new CapabilityError(CAPABILITY_REASONS.UNKNOWN_FIELD);
  }
}

function rejectAliases(input) {
  for (const [left, right] of [["key_id", "keyId"], ["not_before", "notBefore"], ["expires_at", "expiresAt"], ["ttl_ms", "ttlMs"], ["private_key", "signing_key"]]) {
    if (Object.hasOwn(input, left) && Object.hasOwn(input, right)) throw new CapabilityError(CAPABILITY_REASONS.UNKNOWN_FIELD);
  }
}

function parseTimestamp(value) {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (value instanceof Date && Number.isFinite(value.getTime())) return value.getTime();
  if (typeof value === "string") {
    const parsed = Date.parse(value);
    if (Number.isFinite(parsed) && new Date(parsed).toISOString() === value) return parsed;
  }
  throw new CapabilityError(CAPABILITY_REASONS.INVALID_TIMESTAMP);
}

function issueTimestamp(value) {
  const timestamp = parseTimestamp(value);
  if (!Number.isSafeInteger(timestamp)) throw new CapabilityError(CAPABILITY_REASONS.INVALID_TIMESTAMP);
  return new Date(timestamp).toISOString();
}

function randomNonce() {
  const nonce = crypto.randomBytes(MIN_NONCE_BYTES).toString("base64url");
  return /^[A-Za-z0-9]/u.test(nonce) ? nonce : `A${nonce.slice(1)}`;
}

function validateProviderMetadata(value, config) {
  if (!plainObject(value) || !sameKeys(value, ["algorithm", "key_id", "public_key"]) || value.key_id !== config.keyId
    || value.algorithm !== CAPABILITY_SIGNER_ALGORITHM) {
    throw new CapabilitySignerError(CAPABILITY_SIGNER_ERROR_CODES.METADATA);
  }
  const received = parsePublicKey(value.public_key, CAPABILITY_SIGNER_ERROR_CODES.METADATA);
  if (fingerprint(received) !== config.publicKeyFingerprint) throw new CapabilitySignerError(CAPABILITY_SIGNER_ERROR_CODES.METADATA);
}

function normalizeSignature(value) {
  if (!(Buffer.isBuffer(value) || value instanceof Uint8Array)) throw new CapabilitySignerError(CAPABILITY_SIGNER_ERROR_CODES.OUTPUT);
  const signature = Buffer.from(value);
  if (signature.length !== MAX_SIGNATURE_BYTES) throw new CapabilitySignerError(CAPABILITY_SIGNER_ERROR_CODES.OUTPUT);
  return signature;
}

function parsePublicKey(value, errorCode) {
  try {
    if (value?.type === "private" || (typeof value === "string" && /PRIVATE\s+KEY/iu.test(value))) throw new Error("private key rejected");
    const key = value?.type === "public" ? value : crypto.createPublicKey(value);
    if (key.type !== "public" || key.asymmetricKeyType !== CAPABILITY_SIGNER_ALGORITHM) throw new Error("wrong key type");
    const pem = key.export({ type: "spki", format: "pem" }).toString();
    if (Buffer.byteLength(pem, "utf8") > MAX_PUBLIC_KEY_BYTES || !PUBLIC_KEY_PEM.test(pem)) throw new Error("invalid public key");
    return key;
  } catch {
    throw new CapabilitySignerError(errorCode);
  }
}

function fingerprint(key) {
  return crypto.createHash("sha256").update(key.export({ type: "spki", format: "der" })).digest("hex");
}

function exactNow(value) {
  const current = value instanceof Date ? value.getTime() : value;
  if (!Number.isSafeInteger(current) || current < 0) throw new CapabilitySignerError(CAPABILITY_SIGNER_ERROR_CODES.CONFIG);
  return current;
}

function withDeadline(operation, timeoutMs) {
  const controller = new AbortController();
  let timer;
  return new Promise((resolve, reject) => {
    let settled = false;
    const finish = (fn, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      fn(value);
    };
    timer = setTimeout(() => {
      controller.abort();
      finish(reject, new CapabilitySignerError(CAPABILITY_SIGNER_ERROR_CODES.TIMEOUT));
    }, timeoutMs);
    Promise.resolve().then(() => operation(controller.signal)).then(
      (value) => finish(resolve, value),
      (error) => finish(reject, error)
    );
  });
}

function sameKeys(value, keys) {
  const actual = Reflect.ownKeys(value);
  return actual.every((key) => typeof key === "string")
    && actual.sort().join("\0") === [...keys].sort().join("\0");
}

function plainObject(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function deepFreeze(value) {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}
