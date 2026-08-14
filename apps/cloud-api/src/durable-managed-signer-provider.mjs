import crypto from "node:crypto";

import {
  canonicalManagedSignerRequestDigest,
  MANAGED_SIGNER_KEY_LIFECYCLE_REPOSITORY_ERROR_CODES
} from "./postgres/managed-signer-key-lifecycle-repository.mjs";

const PURPOSE = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/u;
const KEY_ID = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$/u;
const ALGORITHM = "ed25519";
const SIGNATURE_BYTES = 64;
const OPERATION_PREFIX = "managed-signer-v1-";
const REQUEST_FIELDS = Object.freeze(["algorithm", "bytes", "key_id", "purpose", "version"]);
const METADATA_FIELDS = Object.freeze(["algorithm", "key_id", "purpose", "version"]);

export const DURABLE_MANAGED_SIGNER_ERROR_CODES = Object.freeze({
  CONFIG: "ERR_DURABLE_MANAGED_SIGNER_CONFIG",
  INPUT: "ERR_DURABLE_MANAGED_SIGNER_INPUT",
  BINDING: "ERR_DURABLE_MANAGED_SIGNER_BINDING",
  METADATA: "ERR_DURABLE_MANAGED_SIGNER_METADATA",
  PROVIDER: "ERR_DURABLE_MANAGED_SIGNER_PROVIDER",
  REPOSITORY: "ERR_DURABLE_MANAGED_SIGNER_REPOSITORY",
  INACTIVE: "ERR_DURABLE_MANAGED_SIGNER_INACTIVE",
  PENDING: "ERR_DURABLE_MANAGED_SIGNER_PENDING",
  UNCERTAIN: "ERR_DURABLE_MANAGED_SIGNER_UNCERTAIN",
  CONFLICT: "ERR_DURABLE_MANAGED_SIGNER_CONFLICT",
  COMMIT: "ERR_DURABLE_MANAGED_SIGNER_COMMIT",
  OUTPUT: "ERR_DURABLE_MANAGED_SIGNER_OUTPUT"
});

const MESSAGES = Object.freeze({
  [DURABLE_MANAGED_SIGNER_ERROR_CODES.CONFIG]: "durable managed signer configuration is invalid",
  [DURABLE_MANAGED_SIGNER_ERROR_CODES.INPUT]: "durable managed signer request is invalid",
  [DURABLE_MANAGED_SIGNER_ERROR_CODES.BINDING]: "durable managed signer request is not bound to this signer",
  [DURABLE_MANAGED_SIGNER_ERROR_CODES.METADATA]: "durable managed signer metadata is invalid",
  [DURABLE_MANAGED_SIGNER_ERROR_CODES.PROVIDER]: "durable managed signer provider is unavailable",
  [DURABLE_MANAGED_SIGNER_ERROR_CODES.REPOSITORY]: "durable managed signer storage is unavailable",
  [DURABLE_MANAGED_SIGNER_ERROR_CODES.INACTIVE]: "durable managed signer key is not active",
  [DURABLE_MANAGED_SIGNER_ERROR_CODES.PENDING]: "durable managed signer operation is already pending",
  [DURABLE_MANAGED_SIGNER_ERROR_CODES.UNCERTAIN]: "durable managed signer operation is uncertain",
  [DURABLE_MANAGED_SIGNER_ERROR_CODES.CONFLICT]: "durable managed signer operation conflicts with its binding",
  [DURABLE_MANAGED_SIGNER_ERROR_CODES.COMMIT]: "durable managed signer result could not be committed",
  [DURABLE_MANAGED_SIGNER_ERROR_CODES.OUTPUT]: "durable managed signer returned an invalid result"
});

export class DurableManagedSignerError extends Error {
  constructor(code) {
    super(MESSAGES[code] ?? MESSAGES[DURABLE_MANAGED_SIGNER_ERROR_CODES.PROVIDER]);
    this.name = "DurableManagedSignerError";
    this.code = Object.hasOwn(MESSAGES, code) ? code : DURABLE_MANAGED_SIGNER_ERROR_CODES.PROVIDER;
  }
}

/**
 * Add durable, exactly-once-at-the-provider-boundary semantics to a managed
 * signer. The repository contains only public request bindings and signatures;
 * private key material remains behind the injected provider.
 */
export function createDurableManagedSignerProvider({
  provider,
  repository,
  purpose,
  keyId,
  keyVersion,
  version = 1,
  algorithm = ALGORITHM
} = {}) {
  validateConfiguration({ provider, repository, purpose, keyId, keyVersion, version, algorithm });
  const binding = Object.freeze({ purpose, keyId, keyVersion, version, algorithm });
  const inFlight = new Map();
  let verificationKey;

  async function publicKeyMetadata(input = undefined) {
    const request = normalizeMetadataRequest(input, binding);
    await assertActiveLifecycle(repository, binding);
    let metadata;
    try {
      metadata = await provider.publicKeyMetadata(request);
    } catch {
      throw durableError(DURABLE_MANAGED_SIGNER_ERROR_CODES.PROVIDER);
    }
    const normalized = validatePublicKeyMetadata(metadata, binding);
    verificationKey = parsePublicEd25519Key(normalized.public_key);
    return normalized;
  }

  async function loadVerificationKey(signal = undefined) {
    if (verificationKey) return verificationKey;
    let metadata;
    try {
      metadata = await provider.publicKeyMetadata({
        algorithm: binding.algorithm,
        key_id: binding.keyId,
        purpose: binding.purpose,
        version: binding.version,
        ...(signal === undefined ? {} : { signal })
      });
    } catch {
      throw durableError(DURABLE_MANAGED_SIGNER_ERROR_CODES.PROVIDER);
    }
    const normalized = validatePublicKeyMetadata(metadata, binding);
    verificationKey = parsePublicEd25519Key(normalized.public_key);
    return verificationKey;
  }

  function sign(input) {
    const request = normalizeSignRequest(input, binding);
    const existing = inFlight.get(request.operationId);
    if (existing) return existing;

    const operation = executeSign(request, binding, provider, repository, loadVerificationKey);
    inFlight.set(request.operationId, operation);
    operation.then(
      () => { if (inFlight.get(request.operationId) === operation) inFlight.delete(request.operationId); },
      () => { if (inFlight.get(request.operationId) === operation) inFlight.delete(request.operationId); }
    );
    return operation;
  }

  return Object.freeze({
    purpose,
    key_id: keyId,
    key_version: keyVersion,
    version,
    algorithm,
    publicKeyMetadata,
    sign
  });
}

async function executeSign(request, binding, provider, repository, loadVerificationKey) {
  const durableInput = {
    purpose: binding.purpose,
    operation_id: request.operationId,
    request_digest: request.requestDigest,
    key_id: binding.keyId,
    key_version: binding.keyVersion
  };

  let reservation;
  try {
    reservation = await repository.reserveSignature(durableInput);
  } catch (error) {
    throw mapReserveError(error);
  }

  if (reservation?.state === "committed") {
    const verificationKey = await loadVerificationKey(request.signal);
    return verifySignature(reservation.signature, request.bytes, verificationKey);
  }
  if (reservation?.state === "pending") {
    return signReserved(request, binding, provider, repository, durableInput, loadVerificationKey);
  }
  if (reservation?.state === "uncertain") {
    throw durableError(DURABLE_MANAGED_SIGNER_ERROR_CODES.UNCERTAIN);
  }
  throw durableError(DURABLE_MANAGED_SIGNER_ERROR_CODES.REPOSITORY);
}

async function signReserved(request, binding, provider, repository, durableInput, loadVerificationKey) {
  let signature;
  try {
    const verificationKey = await loadVerificationKey(request.signal);
    const output = await provider.sign(toProviderSignRequest(request));
    signature = verifySignature(output, request.bytes, verificationKey);
  } catch (error) {
    await markUncertainBestEffort(repository, durableInput);
    if (error instanceof DurableManagedSignerError && error.code === DURABLE_MANAGED_SIGNER_ERROR_CODES.OUTPUT) throw error;
    throw durableError(DURABLE_MANAGED_SIGNER_ERROR_CODES.PROVIDER);
  }

  let committed;
  try {
    committed = await repository.commitSignature({ ...durableInput, signature });
  } catch (error) {
    await markUncertainBestEffort(repository, durableInput);
    throw mapCommitError(error);
  }

  if (committed?.state !== "committed") {
    await markUncertainBestEffort(repository, durableInput);
    throw durableError(DURABLE_MANAGED_SIGNER_ERROR_CODES.COMMIT);
  }

  let committedSignature;
  try {
    const verificationKey = await loadVerificationKey(request.signal);
    committedSignature = verifySignature(committed.signature, request.bytes, verificationKey);
  } catch {
    await markUncertainBestEffort(repository, durableInput);
    throw durableError(DURABLE_MANAGED_SIGNER_ERROR_CODES.COMMIT);
  }
  if (!sameBytes(signature, committedSignature)) {
    await markUncertainBestEffort(repository, durableInput);
    throw durableError(DURABLE_MANAGED_SIGNER_ERROR_CODES.COMMIT);
  }
  return Buffer.from(signature);
}

function normalizeSignRequest(input, binding) {
  assertPlainObject(input, DURABLE_MANAGED_SIGNER_ERROR_CODES.INPUT);
  assertExactFields(input, REQUEST_FIELDS, ["signal"]);
  for (const field of REQUEST_FIELDS) {
    if (!Object.hasOwn(input, field) || input[field] === undefined) throw durableError(DURABLE_MANAGED_SIGNER_ERROR_CODES.INPUT);
  }
  const bytes = normalizeBytes(input.bytes);
  assertBinding(input, binding);
  const signal = normalizeSignal(input.signal);
  const requestDigest = canonicalManagedSignerRequestDigest({
    algorithm: binding.algorithm,
    bytes,
    key_id: binding.keyId,
    purpose: binding.purpose,
    version: binding.version,
    key_version: binding.keyVersion
  });
  return Object.freeze({
    algorithm: binding.algorithm,
    bytes,
    keyId: binding.keyId,
    keyVersion: binding.keyVersion,
    version: binding.version,
    purpose: binding.purpose,
    signal,
    requestDigest,
    operationId: `${OPERATION_PREFIX}${requestDigest}`
  });
}

function normalizeMetadataRequest(input, binding) {
  if (input === undefined) return Object.freeze({
    algorithm: binding.algorithm,
    key_id: binding.keyId,
    purpose: binding.purpose,
    version: binding.version
  });
  assertPlainObject(input, DURABLE_MANAGED_SIGNER_ERROR_CODES.INPUT);
  assertExactFields(input, METADATA_FIELDS, ["signal"]);
  for (const field of METADATA_FIELDS) {
    if (!Object.hasOwn(input, field) || input[field] === undefined) throw durableError(DURABLE_MANAGED_SIGNER_ERROR_CODES.INPUT);
  }
  assertBinding(input, binding);
  const signal = normalizeSignal(input.signal);
  return Object.freeze({
    algorithm: binding.algorithm,
    key_id: binding.keyId,
    purpose: binding.purpose,
    version: binding.version,
    ...(signal === undefined ? {} : { signal })
  });
}

function toProviderSignRequest(request) {
  return Object.freeze({
    algorithm: request.algorithm,
    bytes: Buffer.from(request.bytes),
    key_id: request.keyId,
    purpose: request.purpose,
    version: request.version,
    ...(request.signal === undefined ? {} : { signal: request.signal })
  });
}

function validatePublicKeyMetadata(value, binding) {
  try {
    assertPlainObject(value, DURABLE_MANAGED_SIGNER_ERROR_CODES.METADATA);
    assertExactFields(value, ["key_id", "algorithm", "public_key"]);
    if (value.key_id !== binding.keyId || value.algorithm !== binding.algorithm) throw durableError(DURABLE_MANAGED_SIGNER_ERROR_CODES.METADATA);
    const publicKey = parsePublicEd25519Key(value.public_key);
    return Object.freeze({
      key_id: binding.keyId,
      algorithm: binding.algorithm,
      public_key: publicKey.export({ type: "spki", format: "pem" }).toString()
    });
  } catch (error) {
    if (error instanceof DurableManagedSignerError && error.code === DURABLE_MANAGED_SIGNER_ERROR_CODES.METADATA) throw error;
    throw durableError(DURABLE_MANAGED_SIGNER_ERROR_CODES.METADATA);
  }
}

function parsePublicEd25519Key(value) {
  if (value?.type === "private" || (typeof value === "string" && /PRIVATE\s+KEY/iu.test(value))) throw new Error("private key");
  const key = value?.type === "public" ? value : crypto.createPublicKey(value);
  if (key.type !== "public" || key.asymmetricKeyType !== ALGORITHM) throw new Error("not ed25519");
  return key;
}

function normalizeSignature(value) {
  if (!(Buffer.isBuffer(value) || value instanceof Uint8Array) || value.byteLength !== SIGNATURE_BYTES) {
    throw durableError(DURABLE_MANAGED_SIGNER_ERROR_CODES.OUTPUT);
  }
  return Buffer.from(value);
}

function verifySignature(value, bytes, publicKey) {
  const signature = normalizeSignature(value);
  let valid = false;
  try { valid = crypto.verify(null, bytes, publicKey, signature); }
  catch { valid = false; }
  if (!valid) throw durableError(DURABLE_MANAGED_SIGNER_ERROR_CODES.OUTPUT);
  return Buffer.from(signature);
}

function sameBytes(left, right) {
  return left.length === right.length && crypto.timingSafeEqual(left, right);
}

async function markUncertainBestEffort(repository, input) {
  try { await repository.markSignatureUncertain(input); }
  catch { /* The operation remains closed even if the quarantine write is unavailable. */ }
}

function mapReserveError(error) {
  const code = error?.code;
  if (code === MANAGED_SIGNER_KEY_LIFECYCLE_REPOSITORY_ERROR_CODES.SIGNING_PENDING) return durableError(DURABLE_MANAGED_SIGNER_ERROR_CODES.PENDING);
  if (code === MANAGED_SIGNER_KEY_LIFECYCLE_REPOSITORY_ERROR_CODES.SIGNING_UNCERTAIN) return durableError(DURABLE_MANAGED_SIGNER_ERROR_CODES.UNCERTAIN);
  if (code === MANAGED_SIGNER_KEY_LIFECYCLE_REPOSITORY_ERROR_CODES.SIGNING_CONFLICT) return durableError(DURABLE_MANAGED_SIGNER_ERROR_CODES.CONFLICT);
  return durableError(DURABLE_MANAGED_SIGNER_ERROR_CODES.REPOSITORY);
}

function mapCommitError(error) {
  if (error?.code === MANAGED_SIGNER_KEY_LIFECYCLE_REPOSITORY_ERROR_CODES.SIGNING_CONFLICT) {
    return durableError(DURABLE_MANAGED_SIGNER_ERROR_CODES.CONFLICT);
  }
  return durableError(DURABLE_MANAGED_SIGNER_ERROR_CODES.COMMIT);
}

function assertBinding(input, binding) {
  if (input.key_id !== binding.keyId || input.algorithm !== binding.algorithm || input.purpose !== binding.purpose || input.version !== binding.version) {
    throw durableError(DURABLE_MANAGED_SIGNER_ERROR_CODES.BINDING);
  }
}

function assertExactFields(value, required, optional = []) {
  const allowed = new Set([...required, ...optional]);
  const keys = Reflect.ownKeys(value);
  if (keys.some((key) => typeof key !== "string" || !allowed.has(key))) throw durableError(DURABLE_MANAGED_SIGNER_ERROR_CODES.INPUT);
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor?.enumerable) throw durableError(DURABLE_MANAGED_SIGNER_ERROR_CODES.INPUT);
  }
}

function assertPlainObject(value, code) {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || (Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null)) {
    throw durableError(code);
  }
}

function normalizeBytes(value) {
  if (!(Buffer.isBuffer(value) || value instanceof Uint8Array)) throw durableError(DURABLE_MANAGED_SIGNER_ERROR_CODES.INPUT);
  return Buffer.from(value);
}

function normalizeSignal(value) {
  if (value === undefined) return undefined;
  if (typeof AbortSignal === "undefined" || !(value instanceof AbortSignal)) throw durableError(DURABLE_MANAGED_SIGNER_ERROR_CODES.INPUT);
  return value;
}

function validateConfiguration({ provider, repository, purpose, keyId, keyVersion, version, algorithm }) {
  if (!provider || typeof provider.publicKeyMetadata !== "function" || typeof provider.sign !== "function"
    || !repository || typeof repository.reserveSignature !== "function" || typeof repository.commitSignature !== "function"
    || typeof repository.markSignatureUncertain !== "function" || typeof repository.snapshot !== "function"
    || typeof purpose !== "string" || !PURPOSE.test(purpose)
    || typeof keyId !== "string" || !KEY_ID.test(keyId) || !Number.isSafeInteger(keyVersion) || keyVersion < 1
    || !Number.isSafeInteger(version) || version < 1
    || algorithm !== ALGORITHM) throw durableError(DURABLE_MANAGED_SIGNER_ERROR_CODES.CONFIG);
}

async function assertActiveLifecycle(repository, binding) {
  let snapshot;
  try { snapshot = await repository.snapshot(); }
  catch { throw durableError(DURABLE_MANAGED_SIGNER_ERROR_CODES.REPOSITORY); }
  const active = Array.isArray(snapshot?.keys) ? snapshot.keys.filter((key) => key?.state === "active") : [];
  if (snapshot?.purpose !== binding.purpose || snapshot?.algorithm !== binding.algorithm || active.length !== 1
    || active[0].key_id !== binding.keyId || active[0].key_version !== binding.keyVersion) {
    throw durableError(DURABLE_MANAGED_SIGNER_ERROR_CODES.INACTIVE);
  }
}

function durableError(code) { return new DurableManagedSignerError(code); }
