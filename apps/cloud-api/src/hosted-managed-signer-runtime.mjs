import crypto from "node:crypto";

import { createDurableManagedSignerProvider } from "./durable-managed-signer-provider.mjs";
import { createProviderOperationReconciliationAdapter } from "./provider-operation-reconciliation-adapter.mjs";
import {
  MANAGED_SIGNER_KEY_LIFECYCLE_REPOSITORY_ERROR_CODES
} from "./postgres/managed-signer-key-lifecycle-repository.mjs";

const KEY_ID = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$/u;
const PURPOSE = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/u;
const SHA256 = /^[0-9a-f]{64}$/u;

export const HOSTED_MANAGED_SIGNER_RUNTIME_ERROR_CODES = Object.freeze({
  CONFIG: "ERR_HOSTED_MANAGED_SIGNER_RUNTIME_CONFIG",
  DATABASE: "ERR_HOSTED_MANAGED_SIGNER_RUNTIME_DATABASE",
  PROVIDER: "ERR_HOSTED_MANAGED_SIGNER_RUNTIME_PROVIDER",
  LIFECYCLE: "ERR_HOSTED_MANAGED_SIGNER_RUNTIME_LIFECYCLE"
});

const MESSAGES = Object.freeze({
  [HOSTED_MANAGED_SIGNER_RUNTIME_ERROR_CODES.CONFIG]: "hosted managed signer runtime configuration is invalid",
  [HOSTED_MANAGED_SIGNER_RUNTIME_ERROR_CODES.DATABASE]: "hosted managed signer lifecycle storage is unavailable",
  [HOSTED_MANAGED_SIGNER_RUNTIME_ERROR_CODES.PROVIDER]: "hosted managed signer provider is unavailable",
  [HOSTED_MANAGED_SIGNER_RUNTIME_ERROR_CODES.LIFECYCLE]: "hosted managed signer lifecycle does not match the provider"
});

export class HostedManagedSignerRuntimeError extends Error {
  constructor(code) {
    super(MESSAGES[code] ?? MESSAGES[HOSTED_MANAGED_SIGNER_RUNTIME_ERROR_CODES.CONFIG]);
    this.name = "HostedManagedSignerRuntimeError";
    this.code = MESSAGES[code] ? code : HOSTED_MANAGED_SIGNER_RUNTIME_ERROR_CODES.CONFIG;
  }
}

/**
 * Bind one purpose-specific KMS provider to its deployment-global PostgreSQL
 * lifecycle and signing ledger. Initialization is create-only: an existing
 * lifecycle is authoritative and must identify the same active provider key.
 */
export async function bindHostedManagedSignerProvider({
  postgresRuntime,
  provider,
  purpose,
  keyId,
  version = 1,
  algorithm = "ed25519",
  publicKey,
  publicKeyFingerprint
} = {}) {
  validateInput({ postgresRuntime, provider, purpose, keyId, version, algorithm, publicKeyFingerprint });
  const normalizedPublicKey = parsePinnedPublicKey(publicKey);
  const pinnedFingerprint = fingerprint(normalizedPublicKey);
  if (pinnedFingerprint !== publicKeyFingerprint) fail(HOSTED_MANAGED_SIGNER_RUNTIME_ERROR_CODES.CONFIG);

  const metadata = await loadProviderMetadata(provider, { purpose, keyId, version, algorithm });
  if (metadata.key_id !== keyId || metadata.algorithm !== algorithm
    || fingerprint(parsePinnedPublicKey(metadata.public_key, HOSTED_MANAGED_SIGNER_RUNTIME_ERROR_CODES.PROVIDER)) !== pinnedFingerprint) {
    fail(HOSTED_MANAGED_SIGNER_RUNTIME_ERROR_CODES.PROVIDER);
  }

  let repository;
  try {
    repository = postgresRuntime.createManagedSignerKeyLifecycleRepository({ purpose, algorithm });
  } catch {
    fail(HOSTED_MANAGED_SIGNER_RUNTIME_ERROR_CODES.DATABASE);
  }
  validateRepository(repository);

  let snapshot;
  try {
    snapshot = await repository.snapshot();
  } catch (error) {
    if (error?.code !== MANAGED_SIGNER_KEY_LIFECYCLE_REPOSITORY_ERROR_CODES.NOT_INITIALIZED) {
      fail(HOSTED_MANAGED_SIGNER_RUNTIME_ERROR_CODES.DATABASE);
    }
    try {
      snapshot = await repository.initialize({
        snapshot: {
          version: 1,
          purpose,
          algorithm,
          keys: [{
            key_id: keyId,
            key_version: 1,
            purpose,
            algorithm,
            public_key_fingerprint: pinnedFingerprint,
            public_key: normalizedPublicKey,
            state: "active",
            state_version: 1
          }]
        }
      });
    } catch {
      fail(HOSTED_MANAGED_SIGNER_RUNTIME_ERROR_CODES.DATABASE);
    }
  }

  const active = validateAuthoritativeSnapshot(snapshot, { purpose, algorithm, keyId, publicKeyFingerprint: pinnedFingerprint });
  let managedSignerAdapter;
  let operationRepository;
  const hasReconciliationAdapter = typeof provider.signOnce === "function" && typeof provider.lookup === "function";
  if (hasReconciliationAdapter) {
    managedSignerAdapter = provider;
  } else {
    try {
      operationRepository = postgresRuntime.createProviderOperationRepository({
        purpose,
        algorithm,
        keyId,
        keyVersion: String(active.key_version)
      });
      managedSignerAdapter = createProviderOperationReconciliationAdapter({
        provider,
        providerId: provider.provider_id,
        repository: operationRepository,
        purpose,
        keyId,
        keyVersion: String(active.key_version),
        publicKey: normalizedPublicKey
      });
    } catch {
      fail(HOSTED_MANAGED_SIGNER_RUNTIME_ERROR_CODES.DATABASE);
    }
  }
  let durableProvider;
  try {
    durableProvider = createDurableManagedSignerProvider({
      provider,
      managedSignerAdapter,
      repository,
      purpose,
      keyId,
      keyVersion: active.key_version,
      publicKey: normalizedPublicKey,
      version,
      algorithm
    });
  } catch {
    fail(HOSTED_MANAGED_SIGNER_RUNTIME_ERROR_CODES.CONFIG);
  }
  return Object.freeze({ provider: durableProvider, repository, operationRepository, lifecycle: snapshot, key_version: active.key_version });
}

async function loadProviderMetadata(provider, binding) {
  try {
    const metadata = await provider.publicKeyMetadata({
      key_id: binding.keyId,
      algorithm: binding.algorithm,
      purpose: binding.purpose,
      version: binding.version
    });
    if (!plainObject(metadata) || Reflect.ownKeys(metadata).some((key) => typeof key !== "string")
      || Object.keys(metadata).sort().join(",") !== "algorithm,key_id,public_key") {
      fail(HOSTED_MANAGED_SIGNER_RUNTIME_ERROR_CODES.PROVIDER);
    }
    return metadata;
  } catch (error) {
    if (error instanceof HostedManagedSignerRuntimeError) throw error;
    fail(HOSTED_MANAGED_SIGNER_RUNTIME_ERROR_CODES.PROVIDER);
  }
}

function validateAuthoritativeSnapshot(snapshot, expected) {
  if (!plainObject(snapshot) || snapshot.purpose !== expected.purpose || snapshot.algorithm !== expected.algorithm
    || !Number.isSafeInteger(snapshot.version) || snapshot.version < 1 || !Array.isArray(snapshot.keys)) {
    fail(HOSTED_MANAGED_SIGNER_RUNTIME_ERROR_CODES.LIFECYCLE);
  }
  const active = snapshot.keys.filter((key) => key?.state === "active");
  if (active.length !== 1 || active[0].key_id !== expected.keyId
    || active[0].purpose !== expected.purpose || active[0].algorithm !== expected.algorithm
    || active[0].public_key_fingerprint !== expected.publicKeyFingerprint
    || !Number.isSafeInteger(active[0].key_version) || active[0].key_version < 1) {
    fail(HOSTED_MANAGED_SIGNER_RUNTIME_ERROR_CODES.LIFECYCLE);
  }
  if (active[0].public_key !== undefined
    && fingerprint(parsePinnedPublicKey(active[0].public_key, HOSTED_MANAGED_SIGNER_RUNTIME_ERROR_CODES.LIFECYCLE)) !== expected.publicKeyFingerprint) {
    fail(HOSTED_MANAGED_SIGNER_RUNTIME_ERROR_CODES.LIFECYCLE);
  }
  return active[0];
}

function validateInput(value) {
  const hasDirectSign = typeof value.provider?.sign === "function";
  const hasReconciliationAdapter = typeof value.provider?.signOnce === "function" && typeof value.provider?.lookup === "function";
  if (!value.postgresRuntime || typeof value.postgresRuntime.createManagedSignerKeyLifecycleRepository !== "function"
    || (hasDirectSign && typeof value.postgresRuntime.createProviderOperationRepository !== "function")
    || !value.provider || typeof value.provider.publicKeyMetadata !== "function" || (!hasDirectSign && !hasReconciliationAdapter)
    || (typeof value.provider.signOnce === "function") !== (typeof value.provider.lookup === "function")
    || typeof value.purpose !== "string" || !PURPOSE.test(value.purpose)
    || typeof value.keyId !== "string" || !KEY_ID.test(value.keyId)
    || !Number.isSafeInteger(value.version) || value.version < 1
    || value.algorithm !== "ed25519" || typeof value.publicKeyFingerprint !== "string" || !SHA256.test(value.publicKeyFingerprint)
    || (hasDirectSign && (typeof value.provider.provider_id !== "string"
      || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$/u.test(value.provider.provider_id)
      || /(?:private|secret|credential|diagnostic|debug|trace|token|pem)/iu.test(value.provider.provider_id)))) {
    fail(HOSTED_MANAGED_SIGNER_RUNTIME_ERROR_CODES.CONFIG);
  }
}

function validateRepository(value) {
  for (const method of ["snapshot", "initialize", "reserveSignature", "startSignature", "commitSignature", "markSignatureUncertain", "reconcileSignature"]) {
    if (typeof value?.[method] !== "function") fail(HOSTED_MANAGED_SIGNER_RUNTIME_ERROR_CODES.DATABASE);
  }
}

function parsePinnedPublicKey(value, errorCode = HOSTED_MANAGED_SIGNER_RUNTIME_ERROR_CODES.CONFIG) {
  try {
    if (value?.type === "private" || (typeof value === "string" && /PRIVATE\s+KEY/iu.test(value))) throw new Error("private key rejected");
    const key = value?.type === "public" ? value : crypto.createPublicKey(value);
    if (key.type !== "public" || key.asymmetricKeyType !== "ed25519") throw new Error("wrong key type");
    return key.export({ type: "spki", format: "pem" }).toString();
  } catch {
    fail(errorCode);
  }
}

function fingerprint(value) {
  const key = crypto.createPublicKey(value);
  return crypto.createHash("sha256").update(key.export({ type: "spki", format: "der" })).digest("hex");
}

function plainObject(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function fail(code) { throw new HostedManagedSignerRuntimeError(code); }

export default bindHostedManagedSignerProvider;
