import crypto from "node:crypto";

export const REMOTE_KMS_ALGORITHM = "ed25519";
export const REMOTE_KMS_VERSION = 1;
export const REMOTE_KMS_DEFAULT_TIMEOUT_MS = 5_000;
export const REMOTE_KMS_DEFAULT_MAX_REQUEST_BYTES = 128 * 1024;
export const REMOTE_KMS_MAX_TIMEOUT_MS = 30_000;
export const REMOTE_KMS_MAX_REQUEST_BYTES = 1024 * 1024;

export const REMOTE_KMS_ERROR_CODES = Object.freeze({
  CONFIG: "ERR_REMOTE_KMS_CONFIG",
  INPUT: "ERR_REMOTE_KMS_INPUT",
  PURPOSE: "ERR_REMOTE_KMS_PURPOSE",
  METADATA: "ERR_REMOTE_KMS_METADATA",
  PROVIDER: "ERR_REMOTE_KMS_PROVIDER",
  THROTTLED: "ERR_REMOTE_KMS_THROTTLED",
  TIMEOUT: "ERR_REMOTE_KMS_TIMEOUT",
  ABORTED: "ERR_REMOTE_KMS_ABORTED",
  OUTPUT: "ERR_REMOTE_KMS_OUTPUT",
  SIGNATURE: "ERR_REMOTE_KMS_SIGNATURE"
});

const KEY_ID = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$/u;
const PURPOSE = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/u;
const MAX_SIGNATURE_BYTES = 64;
const PUBLIC_KEY_PEM = /^-----BEGIN PUBLIC KEY-----\n[\s\S]+\n-----END PUBLIC KEY-----\n$/u;

const MESSAGES = Object.freeze({
  [REMOTE_KMS_ERROR_CODES.CONFIG]: "remote KMS provider configuration is invalid",
  [REMOTE_KMS_ERROR_CODES.INPUT]: "remote KMS provider input is invalid",
  [REMOTE_KMS_ERROR_CODES.PURPOSE]: "remote KMS provider request is not purpose bound",
  [REMOTE_KMS_ERROR_CODES.METADATA]: "remote KMS provider metadata is invalid",
  [REMOTE_KMS_ERROR_CODES.PROVIDER]: "remote KMS provider is unavailable",
  [REMOTE_KMS_ERROR_CODES.THROTTLED]: "remote KMS provider request was throttled",
  [REMOTE_KMS_ERROR_CODES.TIMEOUT]: "remote KMS provider timed out",
  [REMOTE_KMS_ERROR_CODES.ABORTED]: "remote KMS provider request was aborted",
  [REMOTE_KMS_ERROR_CODES.OUTPUT]: "remote KMS provider output is invalid",
  [REMOTE_KMS_ERROR_CODES.SIGNATURE]: "remote KMS provider returned an invalid signature"
});

export class RemoteKmsProviderError extends Error {
  constructor(code) {
    super(MESSAGES[code] ?? MESSAGES[REMOTE_KMS_ERROR_CODES.PROVIDER]);
    this.name = "RemoteKmsProviderError";
    this.code = code;
  }
}

/**
 * Create the only supported hosted signing boundary. The transport never
 * receives a private key: it receives an exact purpose/key/algorithm/version
 * tuple and bounded signing bytes, plus an AbortSignal.
 */
export function createRemoteEd25519KmsProvider({
  purpose,
  keyId,
  version = REMOTE_KMS_VERSION,
  algorithm = REMOTE_KMS_ALGORITHM,
  publicKey,
  transport,
  timeoutMs = REMOTE_KMS_DEFAULT_TIMEOUT_MS,
  maxRequestBytes = REMOTE_KMS_DEFAULT_MAX_REQUEST_BYTES
} = {}) {
  const config = validateConfig({ purpose, keyId, version, algorithm, publicKey, transport, timeoutMs, maxRequestBytes });
  const pinned = canonicalEd25519PublicKey(publicKey, REMOTE_KMS_ERROR_CODES.CONFIG);
  const binding = Object.freeze({ purpose, key_id: keyId, algorithm, version });

  async function publicKeyMetadata(input) {
    const request = normalizeMetadataInput(input, binding);
    let result;
    try {
      result = await withDeadline(
        (signal) => transport.getPublicKey(binding, { signal }),
        request.signal,
        timeoutMs
      );
    } catch (error) {
      throw mapRemoteError(error);
    }
    return validateMetadata(result, binding, pinned);
  }

  async function sign(input) {
    const request = normalizeSignInput(input, binding, maxRequestBytes);
    await publicKeyMetadata({ ...binding, signal: request.signal });
    let output;
    try {
      output = await withDeadline(
        (signal) => transport.sign({ ...binding, bytes: request.bytes }, { signal }),
        request.signal,
        timeoutMs
      );
    } catch (error) {
      throw mapRemoteError(error);
    }
    const signature = normalizeSignature(output);
    if (!crypto.verify(null, request.bytes, pinned, signature)) {
      throw new RemoteKmsProviderError(REMOTE_KMS_ERROR_CODES.SIGNATURE);
    }
    return Buffer.from(signature);
  }

  return Object.freeze({
    key_id: keyId,
    purpose,
    algorithm,
    version,
    public_key_fingerprint: publicKeyFingerprint(pinned),
    publicKeyMetadata,
    sign
  });
}

/** Canonicalize and reject private keys before they can cross a provider boundary. */
export function canonicalEd25519PublicKey(value, code = REMOTE_KMS_ERROR_CODES.METADATA) {
  try {
    if (value?.type === "private" || (typeof value === "string" && /PRIVATE\s+KEY/iu.test(value))) fail(code);
    const key = value?.type === "public" ? value : crypto.createPublicKey(value);
    if (key.type !== "public" || key.asymmetricKeyType !== REMOTE_KMS_ALGORITHM) fail(code);
    const pem = key.export({ type: "spki", format: "pem" }).toString();
    if (!PUBLIC_KEY_PEM.test(pem)) fail(code);
    return key;
  } catch (error) {
    if (error instanceof RemoteKmsProviderError) throw error;
    throw new RemoteKmsProviderError(code);
  }
}

/** Validate the request a cloud KMS adapter receives from the boundary. */
export function assertBoundRemoteKmsRequest(request, binding, { signing = false, maxRequestBytes = REMOTE_KMS_MAX_REQUEST_BYTES } = {}) {
  if (!plainObject(request)) throw new RemoteKmsProviderError(REMOTE_KMS_ERROR_CODES.INPUT);
  const expected = signing ? ["algorithm", "bytes", "key_id", "purpose", "version"] : ["algorithm", "key_id", "purpose", "version"];
  if (!sameKeys(request, expected) || request.key_id !== binding.key_id || request.purpose !== binding.purpose
    || request.algorithm !== binding.algorithm || request.version !== binding.version) {
    throw new RemoteKmsProviderError(REMOTE_KMS_ERROR_CODES.PURPOSE);
  }
  if (signing) {
    if (!(Buffer.isBuffer(request.bytes) || request.bytes instanceof Uint8Array)) throw new RemoteKmsProviderError(REMOTE_KMS_ERROR_CODES.INPUT);
    if (request.bytes.byteLength < 1 || request.bytes.byteLength > maxRequestBytes) throw new RemoteKmsProviderError(REMOTE_KMS_ERROR_CODES.INPUT);
  }
  return request;
}

function validateConfig({ purpose, keyId, version, algorithm, publicKey, transport, timeoutMs, maxRequestBytes }) {
  if (typeof purpose !== "string" || !PURPOSE.test(purpose) || typeof keyId !== "string" || !KEY_ID.test(keyId)
    || algorithm !== REMOTE_KMS_ALGORITHM || !Number.isSafeInteger(version) || version < 1 || version > 255
    || !transport || typeof transport.getPublicKey !== "function" || typeof transport.sign !== "function"
    || !Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > REMOTE_KMS_MAX_TIMEOUT_MS
    || !Number.isSafeInteger(maxRequestBytes) || maxRequestBytes < 1 || maxRequestBytes > REMOTE_KMS_MAX_REQUEST_BYTES) {
    throw new RemoteKmsProviderError(REMOTE_KMS_ERROR_CODES.CONFIG);
  }
  try { canonicalEd25519PublicKey(publicKey, REMOTE_KMS_ERROR_CODES.CONFIG); }
  catch { throw new RemoteKmsProviderError(REMOTE_KMS_ERROR_CODES.CONFIG); }
  return Object.freeze({ purpose, keyId, version, algorithm, timeoutMs, maxRequestBytes });
}

function normalizeMetadataInput(input, binding) {
  if (input === undefined) input = binding;
  if (!plainObject(input) || !onlyKeys(input, ["algorithm", "key_id", "purpose", "version", "signal"])
    || (input !== binding && (typeof input.key_id !== "string" || typeof input.purpose !== "string"))) {
    throw new RemoteKmsProviderError(REMOTE_KMS_ERROR_CODES.INPUT);
  }
  assertOptionalBinding(input, binding);
  validateSignal(input.signal);
  return Object.freeze({ ...binding, signal: input.signal });
}

function normalizeSignInput(input, binding, maxRequestBytes) {
  if (!plainObject(input) || !onlyKeys(input, ["algorithm", "bytes", "key_id", "purpose", "signal", "version"])
    || typeof input.key_id !== "string" || typeof input.purpose !== "string") {
    throw new RemoteKmsProviderError(REMOTE_KMS_ERROR_CODES.INPUT);
  }
  assertOptionalBinding(input, binding);
  if (!(Buffer.isBuffer(input.bytes) || input.bytes instanceof Uint8Array) || input.bytes.byteLength < 1 || input.bytes.byteLength > maxRequestBytes) {
    throw new RemoteKmsProviderError(REMOTE_KMS_ERROR_CODES.INPUT);
  }
  validateSignal(input.signal);
  return Object.freeze({ ...binding, bytes: Buffer.from(input.bytes), signal: input.signal });
}

function assertOptionalBinding(input, binding) {
  for (const [field, expected] of [["key_id", binding.key_id], ["purpose", binding.purpose], ["algorithm", binding.algorithm], ["version", binding.version]]) {
    if (input[field] !== undefined && input[field] !== expected) throw new RemoteKmsProviderError(REMOTE_KMS_ERROR_CODES.PURPOSE);
  }
}

function validateMetadata(value, binding, pinned) {
  try {
    if (!plainObject(value) || !sameKeys(value, ["algorithm", "key_id", "public_key"])
      || value.key_id !== binding.key_id || value.algorithm !== binding.algorithm) fail(REMOTE_KMS_ERROR_CODES.METADATA);
    const received = canonicalEd25519PublicKey(value.public_key, REMOTE_KMS_ERROR_CODES.METADATA);
    if (publicKeyFingerprint(received) !== publicKeyFingerprint(pinned)) fail(REMOTE_KMS_ERROR_CODES.METADATA);
    return Object.freeze({ key_id: binding.key_id, algorithm: binding.algorithm, public_key: received.export({ type: "spki", format: "pem" }).toString() });
  } catch (error) {
    if (error instanceof RemoteKmsProviderError) throw error;
    throw new RemoteKmsProviderError(REMOTE_KMS_ERROR_CODES.METADATA);
  }
}

function normalizeSignature(value) {
  if (!(Buffer.isBuffer(value) || value instanceof Uint8Array)) throw new RemoteKmsProviderError(REMOTE_KMS_ERROR_CODES.OUTPUT);
  const signature = Buffer.from(value);
  if (signature.length !== MAX_SIGNATURE_BYTES) throw new RemoteKmsProviderError(REMOTE_KMS_ERROR_CODES.OUTPUT);
  return signature;
}

function withDeadline(operation, externalSignal, timeoutMs) {
  if (externalSignal?.aborted) return Promise.reject(new RemoteKmsProviderError(REMOTE_KMS_ERROR_CODES.ABORTED));
  const controller = new AbortController();
  let timer;
  let abortListener;
  return new Promise((resolve, reject) => {
    let settled = false;
    const finish = (fn, value) => { if (settled) return; settled = true; clearTimeout(timer); if (externalSignal && abortListener) externalSignal.removeEventListener("abort", abortListener); fn(value); };
    abortListener = () => { controller.abort(); finish(reject, new RemoteKmsProviderError(REMOTE_KMS_ERROR_CODES.ABORTED)); };
    if (externalSignal) externalSignal.addEventListener("abort", abortListener, { once: true });
    timer = setTimeout(() => { controller.abort(); finish(reject, new RemoteKmsProviderError(REMOTE_KMS_ERROR_CODES.TIMEOUT)); }, timeoutMs);
    Promise.resolve().then(() => operation(controller.signal)).then((value) => finish(resolve, value), (error) => finish(reject, error));
  });
}

function mapRemoteError(error) {
  if (error instanceof RemoteKmsProviderError) return error;
  if (isThrottleError(error)) return new RemoteKmsProviderError(REMOTE_KMS_ERROR_CODES.THROTTLED);
  return new RemoteKmsProviderError(REMOTE_KMS_ERROR_CODES.PROVIDER);
}

function isThrottleError(error) {
  const values = [error?.code, error?.name].filter((value) => typeof value === "string").map((value) => value.toUpperCase());
  const status = error?.statusCode ?? error?.status ?? error?.$metadata?.httpStatusCode;
  return status === 429 || values.some((value) => [
    "429", "RATE_LIMITED", "RESOURCE_EXHAUSTED", "THROTTLED", "THROTTLINGEXCEPTION", "TOO_MANY_REQUESTS",
    "ERR_TOO_MANY_REQUESTS"
  ].includes(value));
}

function publicKeyFingerprint(key) { return crypto.createHash("sha256").update(key.export({ type: "spki", format: "der" })).digest("hex"); }
function validateSignal(signal) { if (signal !== undefined && !(signal instanceof AbortSignal)) throw new RemoteKmsProviderError(REMOTE_KMS_ERROR_CODES.INPUT); }
function sameKeys(value, required) {
  const keys = Reflect.ownKeys(value);
  return keys.length === required.length && keys.every((key) => typeof key === "string" && required.includes(key)
    && Object.getOwnPropertyDescriptor(value, key)?.enumerable === true && Object.getOwnPropertyDescriptor(value, key)?.value !== undefined);
}
function onlyKeys(value, allowed) {
  const keys = Reflect.ownKeys(value);
  return keys.every((key) => typeof key === "string" && allowed.includes(key)
    && Object.getOwnPropertyDescriptor(value, key)?.enumerable === true);
}
function plainObject(value) { return value !== null && typeof value === "object" && !Array.isArray(value) && (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null); }
function fail(code) { throw new RemoteKmsProviderError(code); }
