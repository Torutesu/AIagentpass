import crypto from "node:crypto";

import {
  MANAGED_SIGNER_ALGORITHM,
  REQUEST_DIGEST_ALGORITHM,
  SIGNER_PROTOCOL_VERSIONS,
  createManagedSignerBinding,
} from "./managed-signer-provider-contract.mjs";

/**
 * Durable adapter for direct Ed25519 KMS APIs which expose `sign` but no
 * provider-side operation lookup.
 *
 * The injected repository is the authority for operation identity and state.
 * Its required methods are:
 *
 *   reserveOperation(operation)
 *   claimOperation(operation)
 *   startOperation({ ...operation, claim_token })
 *   recordAccepted({ ...operation, claim_token, signature, provider_receipt })
 *   commitOperation({ ...operation, claim_token })
 *   reconcileOperation(operation)
 *   markUncertain({ ...operation, claim_token })
 *   getOperation(operation)
 *   waitForOperation({ operation, timeout_ms })
 *
 * Every repository method must atomically preserve the immutable operation
 * identity (`operation_id`, purpose, key, version, and request digest). A
 * claim token is an opaque lease and must never be returned as a signer
 * result. The repository may implement these methods with PostgreSQL row
 * locks, an equivalent serializable transaction, or another durable store.
 *
 * The direct provider is purpose-bound before construction. It has the same
 * narrow public shape as the existing remote KMS provider:
 *
 *   publicKeyMetadata({ algorithm, key_id, purpose, version })
 *   sign({ algorithm, bytes, key_id, purpose, version })
 *
 * The adapter never accepts or forwards private key material. It also never
 * treats a direct provider exception as proof that the provider did not
 * accept a request; the operation is fenced as `uncertain` before retry.
 *
 * Ed25519 signing is deterministic for a fixed private key and exact bytes.
 * Therefore a retry after `started`/`uncertain` is safe only if the durable
 * repository confirms the exact operation binding and the provider remains
 * pinned to the same purpose, key, key version, and public key. This adapter
 * enforces those preconditions and compares a recovered signature with any
 * signature already persisted by the repository. It does not claim exactly
 * once execution at the external KMS boundary; the guarantee is deterministic
 * convergence, not absence of duplicate provider attempts.
 */

export const PROVIDER_OPERATION_RECONCILIATION_ADAPTER_VERSION = 1;
export const DEFAULT_PROVIDER_OPERATION_MAX_REQUEST_BYTES = 128 * 1024;
export const DEFAULT_PROVIDER_OPERATION_WAIT_TIMEOUT_MS = 5_000;
export const DEFAULT_PROVIDER_OPERATION_MAX_RECOVERY_ATTEMPTS = 3;

export const PROVIDER_OPERATION_STATES = Object.freeze([
  "pending",
  "started",
  "accepted",
  "uncertain",
  "committed",
  "rejected",
  "failed",
]);

export const PROVIDER_OPERATION_RECONCILIATION_ERROR_CODES = Object.freeze({
  CONFIG: "ERR_PROVIDER_OPERATION_RECONCILIATION_CONFIG",
  INPUT: "ERR_PROVIDER_OPERATION_RECONCILIATION_INPUT",
  BINDING: "ERR_PROVIDER_OPERATION_RECONCILIATION_BINDING",
  CONFLICT: "ERR_PROVIDER_OPERATION_RECONCILIATION_CONFLICT",
  REPOSITORY: "ERR_PROVIDER_OPERATION_RECONCILIATION_REPOSITORY",
  PROVIDER: "ERR_PROVIDER_OPERATION_RECONCILIATION_PROVIDER",
  OUTPUT: "ERR_PROVIDER_OPERATION_RECONCILIATION_OUTPUT",
  TERMINAL: "ERR_PROVIDER_OPERATION_RECONCILIATION_TERMINAL",
  PENDING: "ERR_PROVIDER_OPERATION_RECONCILIATION_PENDING",
  UNCERTAIN: "ERR_PROVIDER_OPERATION_RECONCILIATION_UNCERTAIN",
  BUSY: "ERR_PROVIDER_OPERATION_RECONCILIATION_BUSY",
});

const {
  CONFIG,
  INPUT,
  BINDING,
  CONFLICT,
  REPOSITORY,
  PROVIDER,
  OUTPUT,
  TERMINAL,
  PENDING,
  UNCERTAIN,
  BUSY,
} = PROVIDER_OPERATION_RECONCILIATION_ERROR_CODES;

const PURPOSE = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/u;
const KEY_ID = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$/u;
const KEY_VERSION = /^[1-9][0-9]{0,31}$/u;
const OPERATION_ID = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$/u;
const DIGEST = /^[0-9a-f]{64}$/u;
const PROVIDER_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$/u;
const RECEIPT_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;
const BASE64URL = /^[A-Za-z0-9_-]+$/u;
const MAX_SIGNATURE_BYTES = 64;
const OPERATION_FIELDS = Object.freeze([
  "algorithm",
  "bytes_length",
  "key_id",
  "key_version",
  "operation_id",
  "purpose",
  "request_digest",
]);
const SIGNATURE_FIELDS = Object.freeze(["algorithm", "encoding", "public_key", "value"]);
const PUBLIC_KEY_FIELDS = Object.freeze(["algorithm", "encoding", "value"]);
const RECEIPT_FIELDS = Object.freeze(["key_id", "key_version", "operation_id", "provider", "receipt_id"]);
const REPOSITORY_METHODS = Object.freeze([
  "reserveOperation",
  "claimOperation",
  "startOperation",
  "recordAccepted",
  "commitOperation",
  "reconcileOperation",
  "markUncertain",
  "getOperation",
  "waitForOperation",
]);

export class ProviderOperationReconciliationError extends Error {
  constructor(code, message = code) {
    super(message);
    this.name = "ProviderOperationReconciliationError";
    this.code = Object.values(PROVIDER_OPERATION_RECONCILIATION_ERROR_CODES).includes(code) ? code : PROVIDER;
  }
}

function fail(code, message = code) {
  throw new ProviderOperationReconciliationError(code, message);
}

function isPlainObject(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function exactKeys(value, keys, code = INPUT) {
  if (!isPlainObject(value)) fail(code);
  const actual = Reflect.ownKeys(value);
  if (actual.length !== keys.length || actual.some((key) => typeof key !== "string" || !keys.includes(key))) fail(code);
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || descriptor.enumerable !== true || !("value" in descriptor) || descriptor.value === undefined) fail(code);
  }
}

function onlyKeys(value, keys, code = INPUT) {
  if (!isPlainObject(value)) fail(code);
  const actual = Reflect.ownKeys(value);
  if (actual.some((key) => typeof key !== "string" || !keys.includes(key))) fail(code);
  for (const key of actual) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || descriptor.enumerable !== true || !("value" in descriptor)) fail(code);
  }
}

function string(value, expression, code = INPUT) {
  if (typeof value !== "string" || !expression.test(value)) fail(code);
  return value;
}

function positiveInteger(value, code = INPUT) {
  if (!Number.isSafeInteger(value) || value < 1) fail(code);
  return value;
}

function bytes(value, maxRequestBytes) {
  if (!(Buffer.isBuffer(value) || value instanceof Uint8Array)
    || value.byteLength < 1 || value.byteLength > maxRequestBytes) {
    fail(INPUT, "signing bytes are outside the configured bound");
  }
  return Buffer.from(value);
}

function publicKey(value, code = OUTPUT) {
  try {
    if (value?.type === "private" || (typeof value === "string" && /PRIVATE\s+KEY/iu.test(value))) fail(code);
    const key = value?.type === "public" ? value : crypto.createPublicKey(value);
    if (key.type !== "public" || key.asymmetricKeyType !== MANAGED_SIGNER_ALGORITHM) fail(code);
    return key;
  } catch (error) {
    if (error instanceof ProviderOperationReconciliationError) throw error;
    fail(code, "public key is not a canonical Ed25519 public key");
  }
}

function publicKeyShape(key) {
  const der = key.export({ type: "spki", format: "der" });
  return Object.freeze({
    algorithm: MANAGED_SIGNER_ALGORITHM,
    encoding: "base64url",
    value: Buffer.from(der).toString("base64url"),
  });
}

function normalizeSignature(value, expectedKey, signingBytes) {
  if (!(Buffer.isBuffer(value) || value instanceof Uint8Array)) fail(OUTPUT, "provider signature is not a byte string");
  const signature = Buffer.from(value);
  if (signature.length !== MAX_SIGNATURE_BYTES) fail(OUTPUT, "provider signature has an invalid length");
  let valid = false;
  try { valid = crypto.verify(null, signingBytes, expectedKey, signature); } catch { valid = false; }
  if (!valid) fail(OUTPUT, "provider signature does not verify against the pinned public key");
  return signature;
}

function normalizePublicKeyShape(value) {
  exactKeys(value, PUBLIC_KEY_FIELDS, OUTPUT);
  if (value.algorithm !== MANAGED_SIGNER_ALGORITHM || value.encoding !== "base64url"
    || typeof value.value !== "string" || !BASE64URL.test(value.value) || value.value.includes("=")) {
    fail(OUTPUT, "provider public key shape is invalid");
  }
  const key = publicKey({ key: Buffer.from(value.value, "base64url"), format: "der", type: "spki" }, OUTPUT);
  const canonical = publicKeyShape(key);
  if (canonical.value !== value.value) fail(OUTPUT, "provider public key is not canonical");
  return Object.freeze({ shape: canonical, key });
}

function normalizeReceipt(value, operation, expectedProviderId) {
  exactKeys(value, RECEIPT_FIELDS, OUTPUT);
  const provider = string(value.provider, PROVIDER_ID, OUTPUT);
  const receiptId = string(value.receipt_id, RECEIPT_ID, OUTPUT);
  if (/(?:private|secret|credential|diagnostic|debug|trace|token|pem)/iu.test(provider)
    || /(?:private|secret|credential|diagnostic|debug|trace|token|pem)/iu.test(receiptId)) {
    fail(OUTPUT, "provider receipt contains forbidden material");
  }
  if (provider !== expectedProviderId || value.operation_id !== operation.operation_id
    || value.key_id !== operation.key_id || value.key_version !== operation.key_version) {
    fail(CONFLICT, "provider receipt is not bound to the operation");
  }
  return Object.freeze({
    provider,
    receipt_id: receiptId,
    operation_id: operation.operation_id,
    key_id: operation.key_id,
    key_version: operation.key_version,
  });
}

function signatureShape(signature, expectedKey, signingBytes) {
  exactKeys(signature, SIGNATURE_FIELDS, OUTPUT);
  if (signature.algorithm !== MANAGED_SIGNER_ALGORITHM || signature.encoding !== "base64url"
    || typeof signature.value !== "string" || !BASE64URL.test(signature.value) || signature.value.includes("=")) {
    fail(OUTPUT, "stored signature shape is invalid");
  }
  const raw = Buffer.from(signature.value, "base64url");
  if (raw.length !== MAX_SIGNATURE_BYTES) fail(OUTPUT, "stored signature length is invalid");
  const receivedKey = normalizePublicKeyShape(signature.public_key);
  const expectedDer = expectedKey.export({ type: "spki", format: "der" });
  const receivedDer = receivedKey.key.export({ type: "spki", format: "der" });
  if (!crypto.timingSafeEqual(Buffer.from(expectedDer), Buffer.from(receivedDer))) {
    fail(CONFLICT, "stored signature public key is not the pinned key");
  }
  let valid = false;
  try { valid = crypto.verify(null, signingBytes, expectedKey, raw); } catch { valid = false; }
  if (!valid) fail(OUTPUT, "stored signature does not verify");
  return Object.freeze({
    algorithm: MANAGED_SIGNER_ALGORITHM,
    encoding: "base64url",
    value: signature.value,
    public_key: receivedKey.shape,
  });
}

function sameBytes(left, right) {
  return left.length === right.length && crypto.timingSafeEqual(left, right);
}

function sameReceipt(left, right) {
  return left.provider === right.provider
    && left.receipt_id === right.receipt_id
    && left.operation_id === right.operation_id
    && left.key_id === right.key_id
    && left.key_version === right.key_version;
}

function cloneBytes(value) {
  return Buffer.from(value);
}

function freezeOperation(operation) {
  const result = {
    algorithm: operation.algorithm,
    bytes_length: operation.bytes_length,
    key_id: operation.key_id,
    key_version: operation.key_version,
    operation_id: operation.operation_id,
    purpose: operation.purpose,
    request_digest: operation.request_digest,
  };
  return Object.freeze(result);
}

function operationFromBinding(binding, signingBytes, expectedBinding) {
  const normalized = createManagedSignerBinding(binding);
  if (normalized.purpose !== expectedBinding.purpose || normalized.key_id !== expectedBinding.key_id
    || normalized.key_version !== expectedBinding.key_version) {
    fail(BINDING, "caller binding is not bound to this adapter");
  }
  const digest = crypto.createHash("sha256").update(signingBytes).digest("hex");
  if (normalized.request_digest.algorithm !== REQUEST_DIGEST_ALGORITHM || normalized.request_digest.value !== digest) {
    fail(BINDING, "binding request digest does not match exact signing bytes");
  }
  return freezeOperation({
    algorithm: normalized.algorithm,
    bytes_length: signingBytes.length,
    key_id: normalized.key_id,
    key_version: normalized.key_version,
    operation_id: normalized.operation_id,
    purpose: normalized.purpose,
    request_digest: normalized.request_digest.value,
  });
}

function assertOperationMatches(record, operation) {
  if (!isPlainObject(record)) fail(REPOSITORY, "repository returned a non-object operation");
  for (const field of OPERATION_FIELDS) {
    if (record[field] !== operation[field]) fail(CONFLICT, "repository operation binding changed");
  }
}

function normalizeRepositoryRecord(value, operation, maxRequestBytes, { allowClaimToken = true } = {}) {
  if (value === null || value === undefined) return null;
  if (!isPlainObject(value)) fail(REPOSITORY, "repository returned an invalid operation record");
  assertOperationMatches(value, operation);
  exactKeys(value, [
    ...OPERATION_FIELDS,
    "state",
    ...(allowClaimToken && Object.hasOwn(value, "claim_token") ? ["claim_token"] : []),
    ...(Object.hasOwn(value, "signature") ? ["signature"] : []),
    ...(Object.hasOwn(value, "provider_receipt") ? ["provider_receipt"] : []),
  ], REPOSITORY);
  if (!PROVIDER_OPERATION_STATES.includes(value.state)) fail(REPOSITORY, "repository returned an invalid operation state");
  if (value.algorithm !== MANAGED_SIGNER_ALGORITHM || !OPERATION_ID.test(value.operation_id)
    || !PURPOSE.test(value.purpose) || !KEY_ID.test(value.key_id) || !KEY_VERSION.test(value.key_version)
    || !DIGEST.test(value.request_digest) || !Number.isSafeInteger(value.bytes_length)
    || value.bytes_length < 1 || value.bytes_length > maxRequestBytes) {
    fail(REPOSITORY, "repository operation identity is invalid");
  }

  if (Object.hasOwn(value, "claim_token")) string(value.claim_token, /^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/u, REPOSITORY);
  const hasSignature = Object.hasOwn(value, "signature");
  const hasReceipt = Object.hasOwn(value, "provider_receipt");
  if (hasSignature !== hasReceipt) fail(REPOSITORY, "repository stored only part of a provider result");
  if (value.state === "pending" || value.state === "started") {
    if (hasSignature || hasReceipt) fail(REPOSITORY, "pre-acceptance operation contains a provider result");
  }
  if (value.state === "accepted" || value.state === "committed") {
    if (!hasSignature || !hasReceipt) fail(REPOSITORY, "accepted operation is missing its provider result");
  }
  if (value.state === "rejected" || value.state === "failed") {
    if (hasSignature || hasReceipt || Object.hasOwn(value, "claim_token")) fail(REPOSITORY, "terminal operation contains mutable output");
  }
  if (value.state === "committed" && Object.hasOwn(value, "claim_token")) {
    fail(REPOSITORY, "committed operation still contains a claim");
  }
  return Object.freeze({ ...value });
}

function operationInput(operation, claimToken = undefined) {
  if (claimToken === undefined) return operation;
  string(claimToken, /^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/u, INPUT);
  return Object.freeze({ ...operation, claim_token: claimToken });
}

function receiptFor(operation, providerId) {
  const material = [
    "agentpass-provider-receipt-v1",
    providerId,
    operation.operation_id,
    operation.purpose,
    operation.key_id,
    operation.key_version,
    operation.request_digest,
  ].join("\0");
  const digest = crypto.createHash("sha256").update(material, "utf8").digest("hex");
  return Object.freeze({
    provider: providerId,
    receipt_id: `deterministic-${digest}`,
    operation_id: operation.operation_id,
    key_id: operation.key_id,
    key_version: operation.key_version,
  });
}

function resultFromRecord(record, operation, pinnedKey, signingBytes, expectedProviderId, { lookup = false } = {}) {
  if (record.state === "rejected" || record.state === "failed") {
    return Object.freeze({ state: record.state });
  }
  if (record.state !== "committed" && record.state !== "accepted") {
    if (lookup) fail(UNCERTAIN, "operation has no committed provider result");
    fail(PENDING, "operation has no committed provider result");
  }
  const signature = signatureShape(record.signature, pinnedKey, signingBytes);
  const providerReceipt = normalizeReceipt(record.provider_receipt, operation, expectedProviderId);
  if (record.state === "accepted") return Object.freeze({ state: "accepted", provider_receipt: providerReceipt });
  return Object.freeze({
    state: "committed",
    provider_receipt: providerReceipt,
    signature,
  });
}

function committedResult(record, operation, pinnedKey, signingBytes, expectedProviderId) {
  const result = resultFromRecord(record, operation, pinnedKey, signingBytes, expectedProviderId);
  if (result.state !== "committed") fail(REPOSITORY, "repository did not return a committed result");
  return Object.freeze({
    provider_receipt: result.provider_receipt,
    signature: result.signature,
  });
}

function validateProviderMetadata(value, expected) {
  exactKeys(value, ["algorithm", "key_id", "public_key"], OUTPUT);
  if (value.algorithm !== MANAGED_SIGNER_ALGORITHM || value.key_id !== expected.key_id) {
    fail(CONFLICT, "provider metadata is not bound to the configured purpose/key");
  }
  const key = publicKey(value.public_key, OUTPUT);
  return Object.freeze({ key, shape: publicKeyShape(key) });
}

function validateDirectProvider(provider, expected) {
  if (!isPlainObject(provider) || typeof provider.publicKeyMetadata !== "function" || typeof provider.sign !== "function") {
    fail(CONFIG, "direct provider must expose publicKeyMetadata and sign");
  }
  if (["privateKey", "private_key", "private_key_pem", "secret"].some((field) => Object.hasOwn(provider, field))) {
    fail(CONFIG, "private key material is not accepted");
  }
  for (const [field, expectedValue] of [
    ["purpose", expected.purpose],
    ["key_id", expected.key_id],
    ["algorithm", MANAGED_SIGNER_ALGORITHM],
  ]) {
    if (provider[field] !== undefined && provider[field] !== expectedValue) fail(CONFIG, "direct provider is not purpose bound");
  }
  if (provider.key_version !== undefined && provider.key_version !== expected.key_version) {
    fail(CONFIG, "direct provider key version does not match");
  }
  if (!Number.isSafeInteger(provider.version) || provider.version < 1 || provider.version > 255) {
    fail(CONFIG, "direct provider protocol version is invalid");
  }
}

function validateRepository(repository) {
  if (!isPlainObject(repository)) fail(CONFIG, "durable operation repository is invalid");
  for (const method of REPOSITORY_METHODS) {
    if (typeof repository[method] !== "function") fail(CONFIG, `repository is missing ${method}`);
  }
}

function mapRepositoryError() {
  return new ProviderOperationReconciliationError(REPOSITORY);
}

function mapProviderError() {
  return new ProviderOperationReconciliationError(PROVIDER);
}

/**
 * Create a closed adapter suitable for passing to createManagedSignerProvider.
 * The returned signOnce/lookup methods accept exactly the binding and bytes
 * supplied by that contract; callers cannot choose a provider or key.
 */
export function createProviderOperationReconciliationAdapter(options = {}) {
  const optionKeys = [
    "provider",
    "providerId",
    "repository",
    "purpose",
    "keyId",
    "keyVersion",
    "publicKey",
    "maxRequestBytes",
    "waitTimeoutMs",
    "maxRecoveryAttempts",
  ];
  onlyKeys(options, optionKeys, CONFIG);
  const {
    provider,
    providerId,
    repository,
    purpose,
    keyId,
    keyVersion,
    publicKey: configuredPublicKey,
    maxRequestBytes = DEFAULT_PROVIDER_OPERATION_MAX_REQUEST_BYTES,
    waitTimeoutMs = DEFAULT_PROVIDER_OPERATION_WAIT_TIMEOUT_MS,
    maxRecoveryAttempts = DEFAULT_PROVIDER_OPERATION_MAX_RECOVERY_ATTEMPTS,
  } = options;
  string(purpose, PURPOSE, CONFIG);
  string(keyId, KEY_ID, CONFIG);
  string(keyVersion, KEY_VERSION, CONFIG);
  string(providerId, PROVIDER_ID, CONFIG);
  if (/(?:private|secret|credential|diagnostic|debug|trace|token|pem)/iu.test(providerId)) {
    fail(CONFIG, "provider identifier contains forbidden material");
  }
  positiveInteger(maxRequestBytes, CONFIG);
  if (maxRequestBytes > 1024 * 1024) fail(CONFIG, "maximum request bytes is too large");
  positiveInteger(waitTimeoutMs, CONFIG);
  if (waitTimeoutMs > 30_000) fail(CONFIG, "wait timeout is too large");
  positiveInteger(maxRecoveryAttempts, CONFIG);
  if (maxRecoveryAttempts > 8) fail(CONFIG, "recovery attempts are too large");

  const expectedProviderBinding = Object.freeze({ purpose, key_id: keyId });
  validateDirectProvider(provider, { purpose, key_id: keyId, key_version: keyVersion });
  validateRepository(repository);

  let pinnedMetadata = configuredPublicKey === undefined ? undefined : (() => {
    const key = publicKey(configuredPublicKey, CONFIG);
    return Object.freeze({ key, shape: publicKeyShape(key) });
  })();
  const inFlight = new Map();

  async function loadPublicKey() {
    if (pinnedMetadata) return pinnedMetadata;
    let value;
    try {
      value = await provider.publicKeyMetadata({
        algorithm: MANAGED_SIGNER_ALGORITHM,
        key_id: keyId,
        purpose,
        version: provider.version,
      });
    } catch {
      throw mapProviderError();
    }
    const normalized = validateProviderMetadata(value, expectedProviderBinding);
    pinnedMetadata = normalized;
    return normalized;
  }

  async function callProvider(operation, signingBytes) {
    const metadata = await loadPublicKey();
    let output;
    try {
      output = await provider.sign({
        algorithm: MANAGED_SIGNER_ALGORITHM,
        bytes: cloneBytes(signingBytes),
        key_id: keyId,
        purpose,
        version: provider.version,
      });
    } catch {
      throw mapProviderError();
    }
    const rawSignature = normalizeSignature(output, metadata.key, signingBytes);
    const providerReceipt = receiptFor(operation, providerId);
    return Object.freeze({
      provider_receipt: providerReceipt,
      signature: Object.freeze({
        algorithm: MANAGED_SIGNER_ALGORITHM,
        encoding: "base64url",
        value: rawSignature.toString("base64url"),
        public_key: metadata.shape,
      }),
      rawSignature,
    });
  }

  async function repoCall(method, input) {
    try {
      return await repository[method](input);
    } catch {
      throw mapRepositoryError();
    }
  }

  async function readRecord(method, input) {
    const value = await repoCall(method, input);
    return normalizeRepositoryRecord(value, input, maxRequestBytes);
  }

  async function waitForNext(operation) {
    const value = await repoCall("waitForOperation", Object.freeze({
      operation,
      timeout_ms: waitTimeoutMs,
    }));
    return normalizeRepositoryRecord(value, operation, maxRequestBytes, { allowClaimToken: false });
  }

  async function markUncertainBestEffort(operation, claimToken) {
    try {
      const value = await repository.markUncertain(operationInput(operation, claimToken));
      return normalizeRepositoryRecord(value, operation, maxRequestBytes);
    } catch {
      return null;
    }
  }

  function assertPersistedProviderResult(record, operation, result, publicKey, signingBytes) {
    const storedSignature = signatureShape(record.signature, publicKey, signingBytes);
    const storedReceipt = normalizeReceipt(record.provider_receipt, operation, providerId);
    if (!sameBytes(Buffer.from(storedSignature.value, "base64url"), result.rawSignature)
      || !sameReceipt(storedReceipt, result.provider_receipt)) {
      fail(CONFLICT, "repository changed the provider result during reconciliation");
    }
  }

  async function claimAndRecover(operation, record, signingBytes, lookup) {
    const claimed = await readRecord("claimOperation", operation);
    if (!claimed) fail(REPOSITORY, "repository returned no operation while claiming recovery");
    if (!Object.hasOwn(claimed, "claim_token")) return null;

    let recovered;
    try {
      recovered = await callProvider(operation, signingBytes);
    } catch (error) {
      await markUncertainBestEffort(operation, claimed.claim_token);
      throw error;
    }

    const metadata = await loadPublicKey();
    if (record.signature !== undefined) {
      const stored = signatureShape(record.signature, metadata.key, signingBytes);
      if (!sameBytes(Buffer.from(stored.value, "base64url"), recovered.rawSignature)) {
        await markUncertainBestEffort(operation, claimed.claim_token);
        fail(CONFLICT, "deterministic recovery returned a different signature");
      }
    }
    const acceptedInput = Object.freeze({
      ...operation,
      claim_token: claimed.claim_token,
      signature: recovered.signature,
      provider_receipt: recovered.provider_receipt,
    });
    let accepted;
    try {
      accepted = await repository.recordAccepted(acceptedInput);
    } catch {
      await markUncertainBestEffort(operation, claimed.claim_token);
      throw mapRepositoryError();
    }
    const acceptedRecord = normalizeRepositoryRecord(accepted, operation, maxRequestBytes);
    if (acceptedRecord.state !== "accepted" && acceptedRecord.state !== "committed") {
      await markUncertainBestEffort(operation, claimed.claim_token);
      fail(REPOSITORY, "repository did not persist accepted provider output");
    }
    if (acceptedRecord.state === "committed") {
      assertPersistedProviderResult(acceptedRecord, operation, recovered, metadata.key, signingBytes);
      return committedResult(acceptedRecord, operation, metadata.key, signingBytes, providerId);
    }
    assertPersistedProviderResult(acceptedRecord, operation, recovered, metadata.key, signingBytes);
    let committed;
    try {
      committed = await repository.commitOperation(operationInput(operation, claimed.claim_token));
    } catch {
      await markUncertainBestEffort(operation, claimed.claim_token);
      throw mapRepositoryError();
    }
    const committedRecord = normalizeRepositoryRecord(committed, operation, maxRequestBytes, { allowClaimToken: false });
    assertPersistedProviderResult(committedRecord, operation, recovered, metadata.key, signingBytes);
    return committedResult(committedRecord, operation, metadata.key, signingBytes, providerId);
  }

  async function reconcilePersistedResult(operation, signingBytes) {
    let committed;
    try {
      committed = await repository.reconcileOperation(operation);
    } catch {
      throw mapRepositoryError();
    }
    const record = normalizeRepositoryRecord(committed, operation, maxRequestBytes, { allowClaimToken: false });
    if (!record || record.state !== "committed") fail(REPOSITORY, "repository did not reconcile the persisted provider result");
    const metadata = await loadPublicKey();
    return committedResult(record, operation, metadata.key, signingBytes, providerId);
  }

  async function performInitialSign(operation, claimToken, signingBytes) {
    const started = await readRecord("startOperation", operationInput(operation, claimToken));
    if (!started || (started.state !== "pending" && started.state !== "started")) {
      fail(REPOSITORY, "repository did not persist the provider boundary");
    }
    let result;
    try {
      result = await callProvider(operation, signingBytes);
    } catch (error) {
      await markUncertainBestEffort(operation, claimToken);
      throw error;
    }
    const acceptedInput = Object.freeze({
      ...operation,
      claim_token: claimToken,
      signature: result.signature,
      provider_receipt: result.provider_receipt,
    });
    let accepted;
    try {
      accepted = await repository.recordAccepted(acceptedInput);
    } catch {
      await markUncertainBestEffort(operation, claimToken);
      throw mapRepositoryError();
    }
    const metadata = await loadPublicKey();
    const acceptedRecord = normalizeRepositoryRecord(accepted, operation, maxRequestBytes);
    if (acceptedRecord.state === "committed") {
      assertPersistedProviderResult(acceptedRecord, operation, result, metadata.key, signingBytes);
      return committedResult(acceptedRecord, operation, metadata.key, signingBytes, providerId);
    }
    if (acceptedRecord.state !== "accepted") {
      await markUncertainBestEffort(operation, claimToken);
      fail(REPOSITORY, "repository did not persist accepted provider output");
    }
    assertPersistedProviderResult(acceptedRecord, operation, result, metadata.key, signingBytes);
    let committed;
    try {
      committed = await repository.commitOperation(operationInput(operation, claimToken));
    } catch {
      await markUncertainBestEffort(operation, claimToken);
      throw mapRepositoryError();
    }
    const committedRecord = normalizeRepositoryRecord(committed, operation, maxRequestBytes, { allowClaimToken: false });
    assertPersistedProviderResult(committedRecord, operation, result, metadata.key, signingBytes);
    return committedResult(committedRecord, operation, metadata.key, signingBytes, providerId);
  }

  async function executeSign(operation, signingBytes) {
    let record = await readRecord("reserveOperation", operation);
    for (let attempt = 0; attempt <= maxRecoveryAttempts; attempt += 1) {
      if (record === null) fail(REPOSITORY, "reserveOperation returned no operation");
      if (record.state === "committed") return committedResult(record, operation, (await loadPublicKey()).key, signingBytes, providerId);
      if (record.state === "rejected" || record.state === "failed") fail(TERMINAL, `operation is terminal: ${record.state}`);
      if ((record.state === "accepted" || record.state === "uncertain")
        && record.signature !== undefined && record.provider_receipt !== undefined) {
        return reconcilePersistedResult(operation, signingBytes);
      }
      if (record.state === "pending") {
        if (Object.hasOwn(record, "claim_token")) return performInitialSign(operation, record.claim_token, signingBytes);
      } else if (record.state === "started" || record.state === "uncertain" || record.state === "accepted") {
        const recovered = await claimAndRecover(operation, record, signingBytes, false);
        if (recovered) return recovered;
      }
      if (attempt === maxRecoveryAttempts) fail(BUSY, "operation did not become claimable before the recovery bound");
      record = await waitForNext(operation);
      if (!record) fail(REPOSITORY, "waitForOperation returned no operation");
    }
    fail(BUSY);
  }

  async function executeLookup(operation, signingBytes) {
    let record = await readRecord("getOperation", operation);
    if (record === null) return Object.freeze({ state: "unknown" });
    for (let attempt = 0; attempt <= maxRecoveryAttempts; attempt += 1) {
      if (record.state === "committed") {
        const metadata = await loadPublicKey();
        return Object.freeze({ state: "committed", ...committedResult(record, operation, metadata.key, signingBytes, providerId) });
      }
      if (record.state === "rejected" || record.state === "failed") return Object.freeze({ state: record.state });
      if (record.state === "pending") fail(PENDING, "operation has not crossed the provider boundary");
      if ((record.state === "accepted" || record.state === "uncertain")
        && record.signature !== undefined && record.provider_receipt !== undefined) {
        return Object.freeze({ state: "committed", ...await reconcilePersistedResult(operation, signingBytes) });
      }
      if (record.state === "accepted" || record.state === "uncertain" || record.state === "started") {
        const recovered = await claimAndRecover(operation, record, signingBytes, true);
        if (recovered) return Object.freeze({ state: "committed", ...recovered });
      }
      if (attempt === maxRecoveryAttempts) fail(UNCERTAIN, "operation recovery did not converge");
      record = await waitForNext(operation);
      if (!record) fail(REPOSITORY, "waitForOperation returned no operation");
    }
    fail(UNCERTAIN);
  }

  function normalizeCall(binding, signingBytes) {
    let normalizedBytes;
    try { normalizedBytes = bytes(signingBytes, maxRequestBytes); }
    catch (error) { if (error instanceof ProviderOperationReconciliationError) throw error; throw new ProviderOperationReconciliationError(INPUT); }
    let operation;
    try {
      operation = operationFromBinding(binding, normalizedBytes, {
        purpose,
        key_id: keyId,
        key_version: keyVersion,
      });
    }
    catch (error) {
      if (error instanceof ProviderOperationReconciliationError) throw error;
      throw new ProviderOperationReconciliationError(BINDING);
    }
    return Object.freeze({ operation, signingBytes: normalizedBytes });
  }

  async function signOnce(binding, signingBytes) {
    const request = normalizeCall(binding, signingBytes);
    const existing = inFlight.get(request.operation.operation_id);
    if (existing) return existing;
    const operation = executeSign(request.operation, request.signingBytes);
    inFlight.set(request.operation.operation_id, operation);
    operation.finally(() => {
      if (inFlight.get(request.operation.operation_id) === operation) inFlight.delete(request.operation.operation_id);
    }).catch(() => {});
    return operation.then((result) => Object.freeze(result));
  }

  async function lookup(binding, signingBytes) {
    const request = normalizeCall(binding, signingBytes);
    return executeLookup(request.operation, request.signingBytes);
  }

  return Object.freeze({
    signOnce,
    lookup,
  });
}
