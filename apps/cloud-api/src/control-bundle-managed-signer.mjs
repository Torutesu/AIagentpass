import crypto from "node:crypto";

import {
  CONTROL_BUNDLE_FORMAT_EPOCH,
  CONTROL_BUNDLE_MAX_BYTES,
  MAX_BUNDLE_TTL_MS,
  MAX_OFFLINE_TTL_MS,
  canonicalControlBundle,
  controlBundleStatementHash,
  validateControlBundle
} from "../../../lib/control-bundle-v2.mjs";
import { SIGNER_PURPOSE_REGISTRY } from "./signer-purpose-registry.mjs";

const REGISTRY_ENTRY = SIGNER_PURPOSE_REGISTRY.control_bundle;

export const CONTROL_BUNDLE_MANAGED_SIGNER_PURPOSE = REGISTRY_ENTRY.purpose;
export const CONTROL_BUNDLE_MANAGED_SIGNER_ALGORITHM = REGISTRY_ENTRY.managed_algorithm;
export const CONTROL_BUNDLE_MANAGED_SIGNER_VERSION = REGISTRY_ENTRY.signing_version;
export const CONTROL_BUNDLE_MANAGED_SIGNER_PROTOCOL_VERSION = REGISTRY_ENTRY.protocol_version;
export const CONTROL_BUNDLE_SIGNATURE_DOMAIN = REGISTRY_ENTRY.domain;

export const CONTROL_BUNDLE_MANAGED_SIGNER_ERROR_CODES = Object.freeze({
  CONFIG: "ERR_CONTROL_BUNDLE_SIGNER_CONFIG",
  INPUT: "ERR_CONTROL_BUNDLE_SIGNER_INPUT",
  PROVIDER: "ERR_CONTROL_BUNDLE_SIGNER_PROVIDER",
  METADATA: "ERR_CONTROL_BUNDLE_SIGNER_METADATA",
  OUTPUT: "ERR_CONTROL_BUNDLE_SIGNER_OUTPUT",
  VERIFICATION: "ERR_CONTROL_BUNDLE_SIGNER_VERIFICATION"
});

const KEY_ID = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$/u;
const PUBLIC_KEY_PEM = /^-----BEGIN PUBLIC KEY-----\n[\s\S]+\n-----END PUBLIC KEY-----\n$/u;
const MAX_SIGNATURE_BYTES = 64;
const SIGN_REQUEST_KEYS = Object.freeze(["algorithm", "bytes", "key_id", "purpose", "version"]);
const METADATA_REQUEST_KEYS = Object.freeze(["algorithm", "key_id", "purpose", "version"]);
const HOSTED_OPTIONS_KEYS = Object.freeze(["keyId", "maxOfflineTtlMs", "maxTtlMs", "now", "provider", "publicKey"]);

const ERROR_MESSAGES = Object.freeze({
  [CONTROL_BUNDLE_MANAGED_SIGNER_ERROR_CODES.CONFIG]: "ControlBundle managed signer configuration is invalid",
  [CONTROL_BUNDLE_MANAGED_SIGNER_ERROR_CODES.INPUT]: "ControlBundle signing input is invalid",
  [CONTROL_BUNDLE_MANAGED_SIGNER_ERROR_CODES.PROVIDER]: "ControlBundle managed signer provider is unavailable",
  [CONTROL_BUNDLE_MANAGED_SIGNER_ERROR_CODES.METADATA]: "ControlBundle managed signer metadata is invalid",
  [CONTROL_BUNDLE_MANAGED_SIGNER_ERROR_CODES.OUTPUT]: "ControlBundle managed signer output is invalid",
  [CONTROL_BUNDLE_MANAGED_SIGNER_ERROR_CODES.VERIFICATION]: "ControlBundle managed signer output could not be verified"
});

export class ControlBundleManagedSignerError extends Error {
  constructor(code) {
    super(ERROR_MESSAGES[code] ?? ERROR_MESSAGES[CONTROL_BUNDLE_MANAGED_SIGNER_ERROR_CODES.PROVIDER]);
    this.name = "ControlBundleManagedSignerError";
    this.code = Object.hasOwn(ERROR_MESSAGES, code) ? code : CONTROL_BUNDLE_MANAGED_SIGNER_ERROR_CODES.PROVIDER;
  }
}

/**
 * Create the hosted ControlBundle v2 signer boundary.
 *
 * The private key is never an accepted option and never appears on the
 * returned object. `provider` is purpose-bound before it is used, and every
 * response is checked against the pinned public key and the exact v2
 * canonical statement bytes.
 */
export function createHostedControlBundleSigner(options = {}) {
  if (!plainObject(options) || !sameKeys(options, HOSTED_OPTIONS_KEYS.filter((key) => Object.hasOwn(options, key)))) {
    throw signerError(CONTROL_BUNDLE_MANAGED_SIGNER_ERROR_CODES.CONFIG);
  }
  const {
    provider,
    keyId,
    publicKey,
    maxTtlMs = MAX_BUNDLE_TTL_MS,
    maxOfflineTtlMs = MAX_OFFLINE_TTL_MS,
    now = () => Date.now()
  } = options;
  const pinnedPublicKey = validateConfiguration({ provider, keyId, publicKey, maxTtlMs, maxOfflineTtlMs, now });

  async function loadProviderMetadata(signal = undefined) {
    let metadata;
    try {
      metadata = await provider.publicKeyMetadata({
        algorithm: CONTROL_BUNDLE_MANAGED_SIGNER_ALGORITHM,
        key_id: keyId,
        purpose: CONTROL_BUNDLE_MANAGED_SIGNER_PURPOSE,
        version: CONTROL_BUNDLE_MANAGED_SIGNER_VERSION,
        ...(signal === undefined ? {} : { signal })
      });
    } catch {
      throw signerError(CONTROL_BUNDLE_MANAGED_SIGNER_ERROR_CODES.PROVIDER);
    }
    validateProviderMetadata(metadata, pinnedPublicKey);
    return Object.freeze({
      version: CONTROL_BUNDLE_MANAGED_SIGNER_VERSION,
      purpose: CONTROL_BUNDLE_MANAGED_SIGNER_PURPOSE,
      algorithm: CONTROL_BUNDLE_MANAGED_SIGNER_ALGORITHM,
      key_id: keyId,
      domain: CONTROL_BUNDLE_SIGNATURE_DOMAIN,
      protocol_version: CONTROL_BUNDLE_MANAGED_SIGNER_PROTOCOL_VERSION,
      signing_version: CONTROL_BUNDLE_MANAGED_SIGNER_VERSION,
      public_key: pinnedPublicKey.pem
    });
  }

  async function publicKeyMetadata() {
    return loadProviderMetadata();
  }

  async function signControlBundle(statement, options = {}) {
    const { signal } = normalizeSignOptions(options);
    const normalized = normalizeStatement(statement, { maxTtlMs, maxOfflineTtlMs, now: readNow(now) });
    // Existing ControlBundle v2 signs the raw canonical statement. The
    // registry domain below is the managed-key/purpose domain; it is not
    // prepended to the wire preimage because that would break v2 clients.
    const signingText = canonicalControlBundle(normalized);
    const signingBytes = Buffer.from(signingText, "utf8");
    if (signingBytes.length > CONTROL_BUNDLE_MAX_BYTES) throw signerError(CONTROL_BUNDLE_MANAGED_SIGNER_ERROR_CODES.INPUT);

    await loadProviderMetadata(signal);
    let output;
    try {
      output = await provider.sign({
        algorithm: CONTROL_BUNDLE_MANAGED_SIGNER_ALGORITHM,
        bytes: Buffer.from(signingBytes),
        key_id: keyId,
        purpose: CONTROL_BUNDLE_MANAGED_SIGNER_PURPOSE,
        version: CONTROL_BUNDLE_MANAGED_SIGNER_VERSION,
        ...(signal === undefined ? {} : { signal })
      });
    } catch {
      throw signerError(CONTROL_BUNDLE_MANAGED_SIGNER_ERROR_CODES.PROVIDER);
    }

    const signature = validateProviderSignature(output);
    let valid = false;
    try { valid = crypto.verify(null, signingBytes, pinnedPublicKey.key, signature); }
    catch { valid = false; }
    if (!valid) throw signerError(CONTROL_BUNDLE_MANAGED_SIGNER_ERROR_CODES.VERIFICATION);

    return Object.freeze({
      ...normalized,
      signature: signature.toString("base64")
    });
  }

  return Object.freeze({
    purpose: CONTROL_BUNDLE_MANAGED_SIGNER_PURPOSE,
    algorithm: CONTROL_BUNDLE_MANAGED_SIGNER_ALGORITHM,
    version: CONTROL_BUNDLE_MANAGED_SIGNER_VERSION,
    protocol_version: CONTROL_BUNDLE_MANAGED_SIGNER_PROTOCOL_VERSION,
    signing_version: CONTROL_BUNDLE_MANAGED_SIGNER_VERSION,
    domain: CONTROL_BUNDLE_SIGNATURE_DOMAIN,
    key_id: keyId,
    publicKeyMetadata,
    signControlBundle,
    sign: signControlBundle,
    statementHash: (statement) => {
      const normalized = normalizeStatement(statement, { maxTtlMs, maxOfflineTtlMs, now: readNow(now) });
      return controlBundleStatementHash(normalized);
    }
  });
}

/**
 * Development/test-only provider. The private key is captured in a closure;
 * it is intentionally absent from the returned provider's public shape.
 */
export function createLocalControlBundleProvider({ privateKey, keyId } = {}) {
  if (!KEY_ID.test(keyId ?? "")) throw signerError(CONTROL_BUNDLE_MANAGED_SIGNER_ERROR_CODES.CONFIG);
  let signingKey;
  try { signingKey = privateKey?.type === "private" ? privateKey : crypto.createPrivateKey(privateKey); }
  catch { throw signerError(CONTROL_BUNDLE_MANAGED_SIGNER_ERROR_CODES.CONFIG); }
  if (signingKey.type !== "private" || signingKey.asymmetricKeyType !== CONTROL_BUNDLE_MANAGED_SIGNER_ALGORITHM) {
    throw signerError(CONTROL_BUNDLE_MANAGED_SIGNER_ERROR_CODES.CONFIG);
  }
  const publicKey = crypto.createPublicKey(signingKey);
  const publicKeyPem = publicKey.export({ type: "spki", format: "pem" }).toString();

  function assertRequest(input, expectedKeys) {
    if (!plainObject(input) || (!sameKeys(input, expectedKeys) && !sameKeys(input, [...expectedKeys, "signal"]))
      || input.algorithm !== CONTROL_BUNDLE_MANAGED_SIGNER_ALGORITHM
      || input.key_id !== keyId || input.purpose !== CONTROL_BUNDLE_MANAGED_SIGNER_PURPOSE
      || input.version !== CONTROL_BUNDLE_MANAGED_SIGNER_VERSION) {
      throw signerError(CONTROL_BUNDLE_MANAGED_SIGNER_ERROR_CODES.INPUT);
    }
  }

  return Object.freeze({
    purpose: CONTROL_BUNDLE_MANAGED_SIGNER_PURPOSE,
    algorithm: CONTROL_BUNDLE_MANAGED_SIGNER_ALGORITHM,
    version: CONTROL_BUNDLE_MANAGED_SIGNER_VERSION,
    key_id: keyId,
    async publicKeyMetadata(input) {
      assertRequest(input, METADATA_REQUEST_KEYS);
      return { key_id: keyId, algorithm: CONTROL_BUNDLE_MANAGED_SIGNER_ALGORITHM, public_key: publicKeyPem };
    },
    async sign(input) {
      assertRequest(input, SIGN_REQUEST_KEYS);
      if (!(Buffer.isBuffer(input.bytes) || input.bytes instanceof Uint8Array) || input.bytes.length < 1) {
        throw signerError(CONTROL_BUNDLE_MANAGED_SIGNER_ERROR_CODES.INPUT);
      }
      return crypto.sign(null, Buffer.from(input.bytes), signingKey);
    }
  });
}

function validateConfiguration({ provider, keyId, publicKey, maxTtlMs, maxOfflineTtlMs, now }) {
  if (!plainObject(provider) || typeof provider.publicKeyMetadata !== "function" || typeof provider.sign !== "function"
    || provider.purpose !== CONTROL_BUNDLE_MANAGED_SIGNER_PURPOSE
    || provider.algorithm !== CONTROL_BUNDLE_MANAGED_SIGNER_ALGORITHM
    || provider.version !== CONTROL_BUNDLE_MANAGED_SIGNER_VERSION
    || provider.key_id !== keyId || !KEY_ID.test(keyId ?? "")
    || !Number.isSafeInteger(maxTtlMs) || maxTtlMs < 1 || maxTtlMs > MAX_BUNDLE_TTL_MS
    || !Number.isSafeInteger(maxOfflineTtlMs) || maxOfflineTtlMs < 1 || maxOfflineTtlMs > MAX_OFFLINE_TTL_MS
    || typeof now !== "function") {
    throw signerError(CONTROL_BUNDLE_MANAGED_SIGNER_ERROR_CODES.CONFIG);
  }
  let key;
  try {
    if (publicKey?.type === "private" || (typeof publicKey === "string" && /PRIVATE\s+KEY/iu.test(publicKey))) throw new Error();
    key = publicKey?.type === "public" ? publicKey : crypto.createPublicKey(publicKey);
    if (key.type !== "public" || key.asymmetricKeyType !== CONTROL_BUNDLE_MANAGED_SIGNER_ALGORITHM) throw new Error();
  } catch { throw signerError(CONTROL_BUNDLE_MANAGED_SIGNER_ERROR_CODES.CONFIG); }
  const pem = key.export({ type: "spki", format: "pem" }).toString();
  if (!PUBLIC_KEY_PEM.test(pem)) throw signerError(CONTROL_BUNDLE_MANAGED_SIGNER_ERROR_CODES.CONFIG);
  return Object.freeze({ key, pem, keyId });
}

function validateProviderMetadata(value, pinnedPublicKey) {
  if (!plainObject(value) || !sameKeys(value, ["algorithm", "key_id", "public_key"])
    || value.algorithm !== CONTROL_BUNDLE_MANAGED_SIGNER_ALGORITHM
    || value.key_id !== pinnedPublicKey.keyId) {
    throw signerError(CONTROL_BUNDLE_MANAGED_SIGNER_ERROR_CODES.METADATA);
  }
  let received;
  try {
    if (value.public_key?.type === "private" || (typeof value.public_key === "string" && /PRIVATE\s+KEY/iu.test(value.public_key))) throw new Error();
    received = value.public_key?.type === "public" ? value.public_key : crypto.createPublicKey(value.public_key);
    if (received.type !== "public" || received.asymmetricKeyType !== CONTROL_BUNDLE_MANAGED_SIGNER_ALGORITHM) throw new Error();
  } catch { throw signerError(CONTROL_BUNDLE_MANAGED_SIGNER_ERROR_CODES.METADATA); }
  const receivedDer = received.export({ type: "spki", format: "der" });
  const pinnedDer = pinnedPublicKey.key.export({ type: "spki", format: "der" });
  if (receivedDer.length !== pinnedDer.length || !crypto.timingSafeEqual(receivedDer, pinnedDer)) {
    throw signerError(CONTROL_BUNDLE_MANAGED_SIGNER_ERROR_CODES.METADATA);
  }
}

function validateProviderSignature(value) {
  if (!(Buffer.isBuffer(value) || value instanceof Uint8Array)) throw signerError(CONTROL_BUNDLE_MANAGED_SIGNER_ERROR_CODES.OUTPUT);
  const signature = Buffer.from(value);
  if (signature.length !== MAX_SIGNATURE_BYTES) throw signerError(CONTROL_BUNDLE_MANAGED_SIGNER_ERROR_CODES.OUTPUT);
  return signature;
}

function normalizeStatement(statement, { maxTtlMs, maxOfflineTtlMs, now }) {
  if (!plainObject(statement) || Object.hasOwn(statement, "signature")) throw signerError(CONTROL_BUNDLE_MANAGED_SIGNER_ERROR_CODES.INPUT);
  try {
    const normalized = validateControlBundle({ ...statement, format_epoch: statement.format_epoch ?? CONTROL_BUNDLE_FORMAT_EPOCH }, {
      maxTtlMs,
      maxOfflineTtlMs,
      now,
      allowExpired: false,
      allowFuture: false
    });
    return Object.freeze(normalized);
  } catch { throw signerError(CONTROL_BUNDLE_MANAGED_SIGNER_ERROR_CODES.INPUT); }
}

function normalizeSignOptions(value) {
  if (!plainObject(value) || (!sameKeys(value, []) && !sameKeys(value, ["signal"]))) throw signerError(CONTROL_BUNDLE_MANAGED_SIGNER_ERROR_CODES.INPUT);
  if (value.signal !== undefined && (typeof AbortSignal === "undefined" || !(value.signal instanceof AbortSignal))) {
    throw signerError(CONTROL_BUNDLE_MANAGED_SIGNER_ERROR_CODES.INPUT);
  }
  return value;
}

function sameKeys(value, keys) {
  const actual = Reflect.ownKeys(value);
  return actual.every((key) => typeof key === "string") && actual.sort().join("\0") === [...keys].sort().join("\0");
}

function plainObject(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function signerError(code) {
  return new ControlBundleManagedSignerError(code);
}

function readNow(now) {
  const value = now();
  if (value instanceof Date) return value.getTime();
  if (Number.isFinite(value)) return value;
  throw signerError(CONTROL_BUNDLE_MANAGED_SIGNER_ERROR_CODES.INPUT);
}
