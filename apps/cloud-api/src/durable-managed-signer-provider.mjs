import crypto from "node:crypto";

import {
  canonicalManagedSignerRequestDigest,
  MANAGED_SIGNER_KEY_LIFECYCLE_REPOSITORY_ERROR_CODES
} from "./postgres/managed-signer-key-lifecycle-repository.mjs";
import {
  createManagedSignerProvider,
  SIGNER_PROTOCOL_VERSIONS,
  ManagedSignerContractError
} from "./managed-signer-provider-contract.mjs";

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
  DRAINING: "ERR_DURABLE_MANAGED_SIGNER_DRAINING",
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
  [DURABLE_MANAGED_SIGNER_ERROR_CODES.DRAINING]: "durable managed signer is draining",
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
 * Add durable lifecycle fencing and verified-result convergence to a managed
 * signer. Direct KMS calls can be at-least-once after an ambiguous provider
 * response; only one exact, verified result may become durably committed.
 * The repository contains only public request bindings and signatures;
 * private key material remains behind the injected provider.
 */
export function createDurableManagedSignerProvider({
  provider,
  managedSignerAdapter,
  repository,
  purpose,
  keyId,
  keyVersion,
  publicKey,
  version = 1,
  algorithm = ALGORITHM,
  protocolVersion = SIGNER_PROTOCOL_VERSIONS[purpose],
  operationGate
} = {}) {
  const adapter = managedSignerAdapter ?? (typeof provider?.signOnce === "function" && typeof provider?.lookup === "function" ? provider : undefined);
  validateConfiguration({ provider, managedSignerAdapter: adapter, repository, purpose, keyId, keyVersion, publicKey, version, protocolVersion, algorithm, operationGate });
  const binding = Object.freeze({ purpose, keyId, keyVersion, version, algorithm });
  const inFlight = new Map();
  let verificationKey = publicKey === undefined ? undefined : parsePinnedConfigurationKey(publicKey);

  async function publicKeyMetadata(input = undefined) {
    const request = normalizeMetadataRequest(input, binding);
    assertOperationGate(operationGate);
    await assertActiveLifecycle(repository, binding);
    let metadata;
    try {
      metadata = await provider.publicKeyMetadata(request);
    } catch {
      throw durableError(DURABLE_MANAGED_SIGNER_ERROR_CODES.PROVIDER);
    }
    const normalized = validatePublicKeyMetadata(metadata, binding);
    const candidate = parsePublicEd25519Key(normalized.public_key);
    if (verificationKey && !samePublicKey(verificationKey, candidate)) {
      throw durableError(DURABLE_MANAGED_SIGNER_ERROR_CODES.METADATA);
    }
    verificationKey ??= candidate;
    return normalized;
  }

  async function loadVerificationKey(signal = undefined) {
    if (verificationKey) return verificationKey;
    assertOperationGate(operationGate);
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

    const operation = operationGate
      ? trackDurableOperation(operationGate, () => executeSign(request, binding, provider, adapter, protocolVersion, repository, loadVerificationKey, operationGate))
      : executeSign(request, binding, provider, adapter, protocolVersion, repository, loadVerificationKey, operationGate);
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

async function executeSign(request, binding, provider, adapter, protocolVersion, repository, loadVerificationKey, operationGate) {
  const durableInput = {
    purpose: binding.purpose,
    operation_id: request.operationId,
    request_digest: request.requestDigest,
    key_id: binding.keyId,
    key_version: binding.keyVersion
  };

  assertOperationGate(operationGate);
  let reservation;
  try {
    reservation = await repository.reserveSignature(durableInput);
  } catch (error) {
    if (adapter && error?.code === MANAGED_SIGNER_KEY_LIFECYCLE_REPOSITORY_ERROR_CODES.SIGNING_UNCERTAIN) {
      return reconcileUncertain(request, binding, adapter, protocolVersion, repository, loadVerificationKey, durableInput, operationGate);
    }
    throw mapReserveError(error);
  }

  if (reservation?.state === "committed") {
    const verificationKey = await loadVerificationKey(request.signal);
    if (adapter && !reservation.provider_receipt) throw durableError(DURABLE_MANAGED_SIGNER_ERROR_CODES.COMMIT);
    return verifySignature(reservation.signature, request.bytes, verificationKey);
  }
  if (reservation?.state === "pending") {
    if (typeof reservation.claim_token !== "string" || reservation.claim_token.length === 0) {
      throw durableError(DURABLE_MANAGED_SIGNER_ERROR_CODES.REPOSITORY);
    }
    return signReserved(request, binding, provider, adapter, protocolVersion, repository, {
      ...durableInput,
      claim_token: reservation.claim_token
    }, loadVerificationKey, operationGate);
  }
  if (reservation?.state === "uncertain") {
    if (adapter) return reconcileUncertain(request, binding, adapter, protocolVersion, repository, loadVerificationKey, durableInput, operationGate);
    throw durableError(DURABLE_MANAGED_SIGNER_ERROR_CODES.UNCERTAIN);
  }
  throw durableError(DURABLE_MANAGED_SIGNER_ERROR_CODES.REPOSITORY);
}

async function signReserved(request, binding, provider, adapter, protocolVersion, repository, durableInput, loadVerificationKey, operationGate) {
  await fenceBeforeProviderBoundary(operationGate, repository, durableInput);
  try {
    const started = await repository.startSignature(durableInput);
    if (started?.state !== "pending" || typeof started.provider_started_at !== "string") {
      throw durableError(DURABLE_MANAGED_SIGNER_ERROR_CODES.COMMIT);
    }
  } catch (error) {
    if (error instanceof DurableManagedSignerError) throw error;
    throw mapCommitError(error);
  }

  // A drain may begin while startSignature is awaiting PostgreSQL.  Never let
  // that accepted lease cross into a new provider call; quarantine it instead.
  await fenceBeforeProviderBoundary(operationGate, repository, durableInput);
  // A different instance may rotate or emergency-disable the lifecycle after
  // the first start transaction has returned. Re-enter the same durable
  // authority immediately before the provider boundary. The named method is
  // mandatory so a local-only or stale repository cannot weaken this fence.
  let admitted;
  try {
    admitted = await repository.fenceSignature(durableInput);
    if (!admitted || !["pending", "committed"].includes(admitted.state)
      || (admitted.state === "pending" && typeof admitted.provider_started_at !== "string")) {
      throw durableError(DURABLE_MANAGED_SIGNER_ERROR_CODES.COMMIT);
    }
  } catch (error) {
    await markUncertainBestEffort(repository, durableInput);
    if (error instanceof DurableManagedSignerError) throw error;
    throw mapCommitError(error);
  }
  if (admitted.state === "committed") {
    const verificationKey = await loadVerificationKey(request.signal);
    if (adapter && !admitted.provider_receipt) throw durableError(DURABLE_MANAGED_SIGNER_ERROR_CODES.COMMIT);
    return verifySignature(admitted.signature, request.bytes, verificationKey);
  }
  let signature;
  let providerReceipt;
  try {
    const verificationKey = await loadVerificationKey(request.signal);
    await fenceBeforeProviderBoundary(operationGate, repository, durableInput);
    if (adapter) {
      const contract = createProviderContract(request, binding, protocolVersion, adapter, request.bytes, verificationKey);
      const output = await contract.signOnce();
      signature = Buffer.from(output.signature.value, "base64url");
      providerReceipt = output.provider_receipt;
    } else {
      const output = await provider.sign(toProviderSignRequest(request));
      signature = verifySignature(output, request.bytes, verificationKey);
    }
  } catch (error) {
    await markUncertainBestEffort(repository, durableInput);
    if (error instanceof DurableManagedSignerError && error.code === DURABLE_MANAGED_SIGNER_ERROR_CODES.OUTPUT) throw error;
    throw durableError(DURABLE_MANAGED_SIGNER_ERROR_CODES.PROVIDER);
  }

  let committed;
  try {
    committed = await repository.commitSignature({
      ...durableInput,
      signature,
      ...(providerReceipt === undefined ? {} : { provider_receipt: toRepositoryReceipt(providerReceipt) })
    });
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
  if (adapter && !sameReceipt(committed.provider_receipt, providerReceipt)) {
    await markUncertainBestEffort(repository, durableInput);
    throw durableError(DURABLE_MANAGED_SIGNER_ERROR_CODES.COMMIT);
  }
  return Buffer.from(signature);
}

async function reconcileUncertain(request, binding, adapter, protocolVersion, repository, loadVerificationKey, durableInput, operationGate) {
  let result;
  try {
    assertOperationGate(operationGate);
    const verificationKey = await loadVerificationKey(request.signal);
    // lookup may itself invoke the provider to converge an ambiguous result.
    // It is a new provider boundary and must be fenced independently.
    assertOperationGate(operationGate);
    const contract = createProviderContract(request, binding, protocolVersion, adapter, request.bytes, verificationKey);
    result = await contract.lookup();
    if (result.state !== "committed") throw durableError(DURABLE_MANAGED_SIGNER_ERROR_CODES.UNCERTAIN);
    const signature = Buffer.from(result.signature.value, "base64url");
    const committed = await repository.reconcileSignature({
      ...durableInput,
      signature,
      provider_receipt: toRepositoryReceipt(result.provider_receipt)
    });
    if (committed?.state !== "committed" || !sameReceipt(committed.provider_receipt, result.provider_receipt)) {
      throw durableError(DURABLE_MANAGED_SIGNER_ERROR_CODES.COMMIT);
    }
    const committedSignature = verifySignature(committed.signature, request.bytes, verificationKey);
    if (!sameBytes(signature, committedSignature)) throw durableError(DURABLE_MANAGED_SIGNER_ERROR_CODES.COMMIT);
    return Buffer.from(committedSignature);
  } catch (error) {
    if (error instanceof DurableManagedSignerError) throw error;
    if (error instanceof ManagedSignerContractError) {
      throw durableError(error.code === "LOOKUP_FAILED"
        ? DURABLE_MANAGED_SIGNER_ERROR_CODES.UNCERTAIN
        : DURABLE_MANAGED_SIGNER_ERROR_CODES.OUTPUT);
    }
    throw mapCommitError(error);
  }
}

function createProviderContract(request, binding, protocolVersion, adapter, signingBytes, publicKey) {
  try {
    return createManagedSignerProvider({
      binding: {
        operation_id: request.operationId,
        purpose: binding.purpose,
        key_id: binding.keyId,
        key_version: String(binding.keyVersion),
        algorithm: binding.algorithm,
        protocol_version: protocolVersion,
        request_digest: {
          algorithm: "SHA-256",
          value: crypto.createHash("sha256").update(signingBytes).digest("hex")
        }
      },
      adapter,
      signingBytes,
      publicKey
    });
  } catch (error) {
    if (error instanceof ManagedSignerContractError) throw durableError(DURABLE_MANAGED_SIGNER_ERROR_CODES.OUTPUT);
    throw durableError(DURABLE_MANAGED_SIGNER_ERROR_CODES.OUTPUT);
  }
}

function toRepositoryReceipt(receipt) {
  return {
    provider: receipt.provider,
    receipt_id: receipt.receipt_id,
    operation_id: receipt.operation_id,
    key_id: receipt.key_id,
    key_version: Number(receipt.key_version)
  };
}

function sameReceipt(left, right) {
  return Boolean(left && right)
    && left.provider === right.provider
    && left.receipt_id === right.receipt_id
    && left.operation_id === right.operation_id
    && left.key_id === right.key_id
    && Number(left.key_version) === Number(right.key_version);
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

function samePublicKey(left, right) {
  const leftDer = Buffer.from(left.export({ type: "spki", format: "der" }));
  const rightDer = Buffer.from(right.export({ type: "spki", format: "der" }));
  return sameBytes(leftDer, rightDer);
}

async function markUncertainBestEffort(repository, input) {
  try { await repository.markSignatureUncertain(input); }
  catch { /* The operation remains closed even if the quarantine write is unavailable. */ }
}

function assertOperationGate(operationGate) {
  if (operationGate === undefined) return;
  try { operationGate.assertAccepting(); }
  catch { throw durableError(DURABLE_MANAGED_SIGNER_ERROR_CODES.DRAINING); }
}

function trackDurableOperation(operationGate, operation) {
  try {
    return Promise.resolve(operationGate.track(operation)).catch((error) => {
      if (error?.code === "draining") throw durableError(DURABLE_MANAGED_SIGNER_ERROR_CODES.DRAINING);
      throw error;
    });
  } catch (error) {
    if (error?.code === "draining") return Promise.reject(durableError(DURABLE_MANAGED_SIGNER_ERROR_CODES.DRAINING));
    return Promise.reject(error);
  }
}

async function fenceBeforeProviderBoundary(operationGate, repository, durableInput) {
  try {
    assertOperationGate(operationGate);
  } catch (error) {
    await markUncertainBestEffort(repository, durableInput);
    throw error;
  }
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

function validateConfiguration({ provider, managedSignerAdapter, repository, purpose, keyId, keyVersion, publicKey, version, protocolVersion, algorithm, operationGate }) {
  if (!provider || typeof provider.publicKeyMetadata !== "function"
    || (managedSignerAdapter === undefined && typeof provider.sign !== "function")
    || (managedSignerAdapter !== undefined && (typeof managedSignerAdapter.signOnce !== "function" || typeof managedSignerAdapter.lookup !== "function"))
    || !repository || typeof repository.reserveSignature !== "function" || typeof repository.startSignature !== "function"
    || typeof repository.fenceSignature !== "function"
    || typeof repository.commitSignature !== "function"
    || typeof repository.markSignatureUncertain !== "function" || typeof repository.snapshot !== "function"
    || (managedSignerAdapter !== undefined && typeof repository.reconcileSignature !== "function")
    || typeof purpose !== "string" || !PURPOSE.test(purpose)
    || typeof keyId !== "string" || !KEY_ID.test(keyId) || !Number.isSafeInteger(keyVersion) || keyVersion < 1
    || !Number.isSafeInteger(version) || version < 1
    || (managedSignerAdapter !== undefined && (!Number.isSafeInteger(protocolVersion) || protocolVersion < 1))
    || algorithm !== ALGORITHM
    || (operationGate !== undefined && (!operationGate
      || typeof operationGate.track !== "function" || typeof operationGate.assertAccepting !== "function"))) {
    throw durableError(DURABLE_MANAGED_SIGNER_ERROR_CODES.CONFIG);
  }
  if (publicKey !== undefined) parsePinnedConfigurationKey(publicKey);
}

function parsePinnedConfigurationKey(value) {
  try { return parsePublicEd25519Key(value); }
  catch { throw durableError(DURABLE_MANAGED_SIGNER_ERROR_CODES.CONFIG); }
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
