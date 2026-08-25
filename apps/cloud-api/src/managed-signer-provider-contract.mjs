import crypto from "node:crypto";

import { SIGNER_PURPOSE_REGISTRY } from "./signer-purpose-registry.mjs";

/**
 * Protocol versions are selected from the frozen signer-purpose registry. It
 * is deliberately not accepted as a signOnce/lookup argument: a provider
 * cannot select the protocol that its result is interpreted under.
 */
export const MANAGED_SIGNER_ALGORITHM = "ed25519";
export const REQUEST_DIGEST_ALGORITHM = "SHA-256";

export const SIGNER_PURPOSES = Object.freeze(Object.values(SIGNER_PURPOSE_REGISTRY).map(({ purpose }) => purpose).sort());
export const SIGNER_PROTOCOL_VERSIONS = Object.freeze(
  Object.fromEntries(Object.values(SIGNER_PURPOSE_REGISTRY).map(({ purpose, protocol_version: version }) => [purpose, version])),
);

export const LOOKUP_STATES = Object.freeze([
  "accepted",
  "committed",
  "unknown",
  "rejected",
  "failed",
]);

const BASE64URL = /^[A-Za-z0-9_-]+$/;
const HEX_SHA256 = /^[0-9a-f]{64}$/;
const TOKEN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const RECEIPT_PROVIDER = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$/;

export class ManagedSignerContractError extends Error {
  constructor(code, message = code) {
    super(message);
    this.name = "ManagedSignerContractError";
    this.code = code;
  }
}

export class UnsupportedManagedSignerError extends ManagedSignerContractError {
  constructor(provider) {
    super(
      "UNSUPPORTED_DIRECT_SIGN_LOOKUP",
      `${provider} direct Sign has no lookup capability and is unsupported`,
    );
    this.provider = provider;
  }
}

function fail(code, message = code) {
  throw new ManagedSignerContractError(code, message);
}

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function assertRecord(value, code) {
  if (!isRecord(value)) fail(code);
}

function assertExactKeys(value, keys, code = "UNKNOWN_FIELD") {
  assertRecord(value, code);
  const ownKeys = Reflect.ownKeys(value);
  if (ownKeys.some((key) => typeof key !== "string" || !Object.getOwnPropertyDescriptor(value, key)?.enumerable)) {
    fail(code);
  }
  const actual = ownKeys.sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    fail(code);
  }
}

function assertString(value, code, pattern = null) {
  if (typeof value !== "string" || value.length === 0 || (pattern && !pattern.test(value))) {
    fail(code);
  }
}

function rejectForbiddenString(value, code) {
  if (typeof value === "string" && /(private|secret|credential|diagnostic|debug|trace|token|pem)/i.test(value)) {
    fail(code);
  }
}

function freezeDeep(value) {
  if (isRecord(value)) {
    for (const child of Object.values(value)) freezeDeep(child);
    Object.freeze(value);
  }
  return value;
}

function validateRequestDigest(value) {
  assertExactKeys(value, ["algorithm", "value"], "INVALID_REQUEST_DIGEST");
  if (value.algorithm !== REQUEST_DIGEST_ALGORITHM) fail("INVALID_REQUEST_DIGEST");
  assertString(value.value, "INVALID_REQUEST_DIGEST", HEX_SHA256);
  return {
    algorithm: REQUEST_DIGEST_ALGORITHM,
    value: value.value,
  };
}

/**
 * Validate and freeze the caller-owned request binding.  The returned object
 * is the only value handed to an adapter, so provider code cannot add or
 * replace security-relevant fields.
 */
export function createManagedSignerBinding(input) {
  assertExactKeys(
    input,
    ["operation_id", "purpose", "key_id", "key_version", "algorithm", "protocol_version", "request_digest"],
    "INVALID_BINDING",
  );
  assertString(input.operation_id, "INVALID_OPERATION_ID", TOKEN);
  if (!SIGNER_PURPOSES.includes(input.purpose)) fail("INVALID_PURPOSE");
  assertString(input.key_id, "INVALID_KEY_ID", TOKEN);
  assertString(input.key_version, "INVALID_KEY_VERSION", TOKEN);
  if (input.algorithm !== MANAGED_SIGNER_ALGORITHM) fail("INVALID_ALGORITHM");
  if (input.protocol_version !== SIGNER_PROTOCOL_VERSIONS[input.purpose]) fail("INVALID_PROTOCOL_VERSION");

  const binding = {
    operation_id: input.operation_id,
    purpose: input.purpose,
    key_id: input.key_id,
    key_version: input.key_version,
    algorithm: MANAGED_SIGNER_ALGORITHM,
    protocol_version: SIGNER_PROTOCOL_VERSIONS[input.purpose],
    request_digest: validateRequestDigest(input.request_digest),
  };
  return freezeDeep(binding);
}

export function canonicalizeManagedSignerBinding(binding) {
  const fixed = createManagedSignerBinding(binding);
  return JSON.stringify(fixed);
}

export function managedSignerBindingBytes(binding) {
  return Buffer.from(canonicalizeManagedSignerBinding(binding), "utf8");
}

function validateProviderReceipt(value, binding) {
  assertExactKeys(
    value,
    ["provider", "receipt_id", "operation_id", "key_id", "key_version"],
    "INVALID_PROVIDER_RECEIPT",
  );
  assertString(value.provider, "INVALID_PROVIDER_RECEIPT", RECEIPT_PROVIDER);
  assertString(value.receipt_id, "INVALID_PROVIDER_RECEIPT", TOKEN);
  if (value.operation_id !== binding.operation_id) fail("RECEIPT_BINDING_MISMATCH");
  if (value.key_id !== binding.key_id) fail("RECEIPT_BINDING_MISMATCH");
  if (value.key_version !== binding.key_version) fail("RECEIPT_BINDING_MISMATCH");
  for (const field of Object.values(value)) rejectForbiddenString(field, "FORBIDDEN_RECEIPT_FIELD");
  return freezeDeep({
    provider: value.provider,
    receipt_id: value.receipt_id,
    operation_id: value.operation_id,
    key_id: value.key_id,
    key_version: value.key_version,
  });
}

function decodeBase64url(value, code) {
  assertString(value, code);
  if (!BASE64URL.test(value) || value.includes("=")) fail(code);
  try {
    return Buffer.from(value, "base64url");
  } catch {
    fail(code);
  }
}

function validatePublicKey(value) {
  assertExactKeys(value, ["algorithm", "encoding", "value"], "INVALID_PUBLIC_KEY");
  if (value.algorithm !== MANAGED_SIGNER_ALGORITHM || value.encoding !== "base64url") {
    fail("INVALID_PUBLIC_KEY");
  }
  const der = decodeBase64url(value.value, "INVALID_PUBLIC_KEY");
  if (der.length < 32) fail("INVALID_PUBLIC_KEY");
  try {
    const key = crypto.createPublicKey({ key: der, format: "der", type: "spki" });
    if (key.asymmetricKeyType !== "ed25519") fail("INVALID_PUBLIC_KEY");
  } catch {
    fail("INVALID_PUBLIC_KEY");
  }
  return freezeDeep({ algorithm: MANAGED_SIGNER_ALGORITHM, encoding: "base64url", value: value.value });
}

function normalizeExpectedPublicKey(value) {
  try {
    if (value?.type === "private" || (typeof value === "string" && /PRIVATE\s+KEY/iu.test(value))) {
      fail("INVALID_PUBLIC_KEY");
    }
    const shape = isRecord(value) && Object.keys(value).sort().join(",") === "algorithm,encoding,value"
      ? validatePublicKey(value)
      : undefined;
    const key = value?.type === "public"
      ? value
      : shape
        ? crypto.createPublicKey({ key: decodeBase64url(shape.value, "INVALID_PUBLIC_KEY"), format: "der", type: "spki" })
        : crypto.createPublicKey(value);
    if (key.type !== "public" || key.asymmetricKeyType !== MANAGED_SIGNER_ALGORITHM) fail("INVALID_PUBLIC_KEY");
    const der = key.export({ type: "spki", format: "der" });
    return Object.freeze({
      key,
      der: Buffer.from(der),
      shape: freezeDeep({ algorithm: MANAGED_SIGNER_ALGORITHM, encoding: "base64url", value: Buffer.from(der).toString("base64url") }),
    });
  } catch (error) {
    if (error instanceof ManagedSignerContractError) throw error;
    fail("INVALID_PUBLIC_KEY");
  }
}

function validateSignature(value, expectedPublicKey = undefined) {
  assertExactKeys(value, ["algorithm", "encoding", "value", "public_key"], "INVALID_SIGNATURE");
  if (value.algorithm !== MANAGED_SIGNER_ALGORITHM || value.encoding !== "base64url") {
    fail("INVALID_SIGNATURE");
  }
  const signature = decodeBase64url(value.value, "INVALID_SIGNATURE");
  if (signature.length !== 64) fail("INVALID_SIGNATURE");
  const publicKey = validatePublicKey(value.public_key);
  if (expectedPublicKey) {
    const received = Buffer.from(publicKey.value, "base64url");
    if (received.length !== expectedPublicKey.der.length || !crypto.timingSafeEqual(received, expectedPublicKey.der)) {
      fail("PUBLIC_KEY_MISMATCH");
    }
  }
  return freezeDeep({
    algorithm: MANAGED_SIGNER_ALGORITHM,
    encoding: "base64url",
    value: value.value,
    public_key: publicKey,
  });
}

function normalizeSigningBytes(value) {
  if (!(Buffer.isBuffer(value) || value instanceof Uint8Array) || value.byteLength < 1) {
    fail("INVALID_SIGNING_BYTES");
  }
  return Buffer.from(value);
}

function assertSigningDigest(binding, signingBytes) {
  const digest = crypto.createHash("sha256").update(signingBytes).digest("hex");
  if (digest !== binding.request_digest.value) fail("REQUEST_DIGEST_MISMATCH");
}

function validateAndVerifySignature(value, binding, signingBytes, expectedPublicKey) {
  const signature = validateSignature(value, expectedPublicKey);
  let valid = false;
  try {
    valid = crypto.verify(
      null,
      signingBytes,
      expectedPublicKey.key,
      Buffer.from(signature.value, "base64url"),
    );
  } catch {
    valid = false;
  }
  if (!valid) fail("INVALID_SIGNATURE");
  return signature;
}

function validateSignOnceResult(value, binding, signingBytes, expectedPublicKey) {
  assertExactKeys(value, ["provider_receipt", "signature"], "INVALID_SIGN_ONCE_RESULT");
  const providerReceipt = validateProviderReceipt(value.provider_receipt, binding);
  const signature = validateAndVerifySignature(value.signature, binding, signingBytes, expectedPublicKey);
  return freezeDeep({
    ...binding,
    provider_receipt: providerReceipt,
    signature,
  });
}

function validateLookupResult(value, binding, signingBytes, expectedPublicKey) {
  assertRecord(value, "INVALID_LOOKUP_RESULT");
  assertString(value.state, "INVALID_LOOKUP_STATE");
  if (!LOOKUP_STATES.includes(value.state)) fail("INVALID_LOOKUP_STATE");

  const expected = value.state === "committed"
    ? ["state", "provider_receipt", "signature"]
    : value.state === "accepted"
      ? ["state", "provider_receipt"]
      : ["state"];
  assertExactKeys(value, expected, "INVALID_LOOKUP_RESULT");

  const result = { ...binding, state: value.state };
  if (value.state === "accepted" || value.state === "committed") {
    result.provider_receipt = validateProviderReceipt(value.provider_receipt, binding);
  }
  if (value.state === "committed") {
    result.signature = validateAndVerifySignature(value.signature, binding, signingBytes, expectedPublicKey);
  }
  return freezeDeep(result);
}

function assertNoCallArguments(args) {
  if (args.length !== 0) fail("CALLER_INPUT_NOT_ALLOWED");
}

function assertAdapter(adapter) {
  assertExactKeys(adapter, ["signOnce", "lookup"], "INVALID_ADAPTER");
  if (typeof adapter.signOnce !== "function" || typeof adapter.lookup !== "function") fail("INVALID_ADAPTER");
}

/**
 * Build the closed provider-neutral contract.  `binding` is validated once
 * and then frozen; both operations are zero-argument by design.
 */
export function createManagedSignerProvider(options) {
  assertExactKeys(options, ["binding", "adapter", "signingBytes", "publicKey"], "INVALID_PROVIDER_OPTIONS");
  const { binding, adapter, signingBytes, publicKey } = options;
  const fixedBinding = createManagedSignerBinding(binding);
  const fixedSigningBytes = normalizeSigningBytes(signingBytes);
  assertSigningDigest(fixedBinding, fixedSigningBytes);
  const expectedPublicKey = normalizeExpectedPublicKey(publicKey);
  assertAdapter(adapter);

  return Object.freeze({
    binding: fixedBinding,
    async signOnce(...args) {
      assertNoCallArguments(args);
      let providerResult;
      try {
        providerResult = await adapter.signOnce(fixedBinding, Buffer.from(fixedSigningBytes));
      } catch (error) {
        if (error instanceof UnsupportedManagedSignerError) throw error;
        throw new ManagedSignerContractError("SIGN_ONCE_FAILED", "managed signer signOnce failed");
      }
      return validateSignOnceResult(providerResult, fixedBinding, fixedSigningBytes, expectedPublicKey);
    },
    async lookup(...args) {
      assertNoCallArguments(args);
      let providerResult;
      try {
        providerResult = await adapter.lookup(fixedBinding, Buffer.from(fixedSigningBytes));
      } catch (error) {
        if (error instanceof UnsupportedManagedSignerError) throw error;
        throw new ManagedSignerContractError("LOOKUP_FAILED", "managed signer lookup failed");
      }
      return validateLookupResult(providerResult, fixedBinding, fixedSigningBytes, expectedPublicKey);
    },
  });
}

/**
 * Verify the returned Ed25519 signature against the exact supplied bytes and
 * pinned public key.
 * Public keys are SPKI DER, so the result is independently verifiable by
 * standard Node/OpenSSL tooling without exposing a private key.
 */
export function verifyManagedSignerSignature(binding, signature, signingBytes, publicKey) {
  const fixedBinding = createManagedSignerBinding(binding);
  const fixedSigningBytes = normalizeSigningBytes(signingBytes);
  assertSigningDigest(fixedBinding, fixedSigningBytes);
  const expectedPublicKey = normalizeExpectedPublicKey(publicKey);
  validateAndVerifySignature(signature, fixedBinding, fixedSigningBytes, expectedPublicKey);
  return true;
}

function createUnsupportedDirectSignAdapter(provider) {
  const unsupported = async () => {
    throw new UnsupportedManagedSignerError(provider);
  };
  return Object.freeze({ signOnce: unsupported, lookup: unsupported });
}

/**
 * Direct AWS/GCP Sign APIs do not expose a durable lookup operation.  They
 * therefore have explicit fail-closed adapters; neither adapter delegates to
 * another provider or silently turns an unverifiable operation into success.
 */
export function createAwsDirectSignAdapter() {
  return createUnsupportedDirectSignAdapter("aws-direct-sign");
}

export function createGcpDirectSignAdapter() {
  return createUnsupportedDirectSignAdapter("gcp-direct-sign");
}

export const createAwsKmsDirectSignAdapter = createAwsDirectSignAdapter;
export const createGcpKmsDirectSignAdapter = createGcpDirectSignAdapter;
