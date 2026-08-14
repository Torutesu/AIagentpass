import crypto from "node:crypto";

import {
  createAwsKmsEd25519Provider
} from "./aws-kms-provider.mjs";
import {
  createGcpCloudKmsEd25519Provider
} from "./gcp-kms-provider.mjs";
import { parseAgentSessionSignerConfig } from "./agent-session-signer-config.mjs";
import { parseQualificationManifestSignerConfig } from "./qualification-manifest-signer-config.mjs";
import {
  AGENT_SESSION_GRANT_TYPE,
  AGENT_SESSION_GRANT_VERSION
} from "./agent-session-grant.mjs";
import {
  QUALIFICATION_GRANT_BATCH_MANIFEST_PURPOSE,
  QUALIFICATION_GRANT_BATCH_MANIFEST_VERSION
} from "./qualification-grant-batch-manifest.mjs";
import {
  createManagedSignerReliabilityProvider,
  MANAGED_SIGNER_RELIABILITY_DEFAULTS
} from "./managed-signer-reliability.mjs";
import {
  createManagedSignerKeyLifecycle,
  createManagedSignerLifecycleProvider
} from "./managed-signer-key-lifecycle.mjs";
import {
  POSSESSION_RECEIPT_PURPOSE,
  POSSESSION_RECEIPT_VERSION
} from "./possession-receipt-signer.mjs";
import { parsePossessionReceiptSignerConfig } from "./possession-receipt-signer-config.mjs";
import { SIGNER_PURPOSE_REGISTRY } from "./signer-purpose-registry.mjs";
import {
  PROTOCOL_VERSION,
  REFRESH_HINT_SIGNATURE_ALGORITHM,
  REFRESH_HINT_TYPE
} from "../../../packages/protocol/src/index.mjs";

export const KMS_PROVIDER_RUNTIME_ENV = Object.freeze({
  provider: "AGENTPASS_KMS_PROVIDER",
  agentSessionResource: "AGENTPASS_KMS_AGENT_SESSION_KEY_RESOURCE",
  qualificationManifestResource: "AGENTPASS_KMS_QUALIFICATION_MANIFEST_KEY_RESOURCE",
  possessionReceiptResource: "AGENTPASS_KMS_POSSESSION_RECEIPT_KEY_RESOURCE",
  refreshHintResource: "AGENTPASS_KMS_REFRESH_HINT_KEY_RESOURCE",
  capabilityResource: "AGENTPASS_KMS_CAPABILITY_KEY_RESOURCE",
  controlBundleResource: "AGENTPASS_KMS_CONTROL_BUNDLE_KEY_RESOURCE",
  auditAnchorResource: "AGENTPASS_KMS_AUDIT_ANCHOR_KEY_RESOURCE",
  promotionEvidenceResource: "AGENTPASS_KMS_PROMOTION_EVIDENCE_KEY_RESOURCE"
});

export const KMS_PROVIDER_RUNTIME_ERROR_CODES = Object.freeze({
  CONFIG: "ERR_KMS_PROVIDER_RUNTIME_CONFIG",
  SDK: "ERR_KMS_PROVIDER_RUNTIME_SDK",
  UNAVAILABLE: "ERR_KMS_PROVIDER_RUNTIME_UNAVAILABLE"
});

const KMS_ENV_PREFIX = "AGENTPASS_KMS_";
const ALLOWED_KMS_ENV = new Set(Object.values(KMS_PROVIDER_RUNTIME_ENV));
const PROVIDERS = new Set(["aws", "gcp"]);
const AWS_KEY_RESOURCE = /^arn:aws:kms:[a-z0-9-]+:[0-9]{12}:key\/[A-Za-z0-9][A-Za-z0-9:/._-]{0,2047}$/u;
const GCP_RESOURCE = /^projects\/[A-Za-z0-9._-]+\/locations\/[A-Za-z0-9._-]+\/keyRings\/[A-Za-z0-9._-]+\/cryptoKeys\/[A-Za-z0-9._-]+\/cryptoKeyVersions\/[A-Za-z0-9._-]+$/u;
const KEY_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$/u;
const MAX_PUBLIC_KEY_BYTES = 8 * 1024;

const PURPOSE_DEFINITIONS = Object.freeze([
  { name: "agentSession", registryName: "agent_session_grant", providerName: "agentSessionSignerProvider", resource: "agentSessionResource", keyIdEnv: "AGENTPASS_CLOUD_AGENT_SESSION_KEY_ID", publicKeyEnv: "AGENTPASS_CLOUD_AGENT_SESSION_PUBLIC_KEY", timeoutEnv: "AGENTPASS_CLOUD_AGENT_SESSION_TIMEOUT_MS", purpose: AGENT_SESSION_GRANT_TYPE, version: AGENT_SESSION_GRANT_VERSION, parse: parseAgentSessionSignerConfig },
  { name: "qualificationManifest", registryName: "qualification_manifest", providerName: "qualificationManifestSignerProvider", resource: "qualificationManifestResource", keyIdEnv: "AGENTPASS_CLOUD_QUALIFICATION_MANIFEST_KEY_ID", publicKeyEnv: "AGENTPASS_CLOUD_QUALIFICATION_MANIFEST_PUBLIC_KEY", timeoutEnv: "AGENTPASS_CLOUD_QUALIFICATION_MANIFEST_TIMEOUT_MS", purpose: QUALIFICATION_GRANT_BATCH_MANIFEST_PURPOSE, version: QUALIFICATION_GRANT_BATCH_MANIFEST_VERSION, parse: parseQualificationManifestSignerConfig },
  { name: "possessionReceipt", registryName: "possession_receipt", providerName: "possessionReceiptSignerProvider", resource: "possessionReceiptResource", keyIdEnv: "AGENTPASS_CLOUD_POSSESSION_RECEIPT_KEY_ID", publicKeyEnv: "AGENTPASS_CLOUD_POSSESSION_RECEIPT_PUBLIC_KEY", timeoutEnv: "AGENTPASS_CLOUD_POSSESSION_RECEIPT_TIMEOUT_MS", purpose: POSSESSION_RECEIPT_PURPOSE, version: POSSESSION_RECEIPT_VERSION, parse: parsePossessionReceiptSignerConfig },
  { name: "refreshHint", registryName: "refresh_hint", providerName: "refreshHintSignerProvider", resource: "refreshHintResource", keyIdEnv: "AGENTPASS_CLOUD_REFRESH_KEY_ID", publicKeyEnv: "AGENTPASS_CLOUD_REFRESH_PUBLIC_KEY", timeoutEnv: "AGENTPASS_CLOUD_REFRESH_TIMEOUT_MS", purpose: REFRESH_HINT_TYPE, version: PROTOCOL_VERSION, parse: parseRefreshHintSignerConfig },
  { name: "capability", registryName: "capability", providerName: "capabilitySignerProvider", resource: "capabilityResource", keyIdEnv: "AGENTPASS_CLOUD_CAPABILITY_KEY_ID", publicKeyEnv: "AGENTPASS_CLOUD_CAPABILITY_PUBLIC_KEY", timeoutEnv: "AGENTPASS_CLOUD_CAPABILITY_TIMEOUT_MS", purpose: SIGNER_PURPOSE_REGISTRY.capability.purpose, version: SIGNER_PURPOSE_REGISTRY.capability.protocol_version },
  { name: "controlBundle", registryName: "control_bundle", providerName: "controlBundleSignerProvider", resource: "controlBundleResource", keyIdEnv: "AGENTPASS_CLOUD_CONTROL_BUNDLE_KEY_ID", publicKeyEnv: "AGENTPASS_CLOUD_CONTROL_BUNDLE_PUBLIC_KEY", timeoutEnv: "AGENTPASS_CLOUD_CONTROL_BUNDLE_TIMEOUT_MS", purpose: SIGNER_PURPOSE_REGISTRY.control_bundle.purpose, version: SIGNER_PURPOSE_REGISTRY.control_bundle.protocol_version },
  { name: "auditAnchor", registryName: "audit_anchor", providerName: "auditAnchorSignerProvider", resource: "auditAnchorResource", keyIdEnv: "AGENTPASS_CLOUD_AUDIT_ANCHOR_KEY_ID", publicKeyEnv: "AGENTPASS_CLOUD_AUDIT_ANCHOR_PUBLIC_KEY", timeoutEnv: "AGENTPASS_CLOUD_AUDIT_ANCHOR_TIMEOUT_MS", purpose: SIGNER_PURPOSE_REGISTRY.audit_anchor.purpose, version: SIGNER_PURPOSE_REGISTRY.audit_anchor.protocol_version },
  { name: "promotionEvidence", registryName: "promotion_evidence", providerName: "promotionEvidenceSignerProvider", resource: "promotionEvidenceResource", keyIdEnv: "AGENTPASS_CLOUD_PROMOTION_EVIDENCE_KEY_ID", publicKeyEnv: "AGENTPASS_CLOUD_PROMOTION_EVIDENCE_PUBLIC_KEY", timeoutEnv: "AGENTPASS_CLOUD_PROMOTION_EVIDENCE_TIMEOUT_MS", purpose: SIGNER_PURPOSE_REGISTRY.promotion_evidence.purpose, version: SIGNER_PURPOSE_REGISTRY.promotion_evidence.protocol_version }
]);

const ERROR_MESSAGES = Object.freeze({
  [KMS_PROVIDER_RUNTIME_ERROR_CODES.CONFIG]: "hosted KMS provider configuration is invalid",
  [KMS_PROVIDER_RUNTIME_ERROR_CODES.SDK]: "hosted KMS provider SDK is unavailable",
  [KMS_PROVIDER_RUNTIME_ERROR_CODES.UNAVAILABLE]: "hosted KMS provider is unavailable"
});

export class KmsProviderRuntimeError extends Error {
  constructor(code) {
    super(ERROR_MESSAGES[code] ?? ERROR_MESSAGES[KMS_PROVIDER_RUNTIME_ERROR_CODES.UNAVAILABLE]);
    this.name = "KmsProviderRuntimeError";
    this.code = code;
  }
}

/**
 * Compose all hosted signing providers from official cloud SDK clients.
 *
 * AWS SDK credentials and Google Application Default Credentials are resolved
 * by their official clients. This function accepts no private-key path,
 * private-key material, credential blob, or local signer fallback.
 */
export async function createHostedKmsProviders({
  env = process.env,
  sdkLoader = loadOfficialSdk,
  clock = () => Date.now(),
  reliability = MANAGED_SIGNER_RELIABILITY_DEFAULTS,
  keyLifecycles = {}
} = {}) {
  const config = parseKmsProviderRuntimeConfig(env);
  const allowedLifecycleKeys = new Set(config.purposes.map(({ name }) => name));
  if (!plainObject(keyLifecycles) || Object.keys(keyLifecycles).some((key) => !allowedLifecycleKeys.has(key))) {
    throw new KmsProviderRuntimeError(KMS_PROVIDER_RUNTIME_ERROR_CODES.CONFIG);
  }
  let sdk;
  try {
    sdk = await sdkLoader(config.provider);
  } catch {
    throw new KmsProviderRuntimeError(KMS_PROVIDER_RUNTIME_ERROR_CODES.SDK);
  }
  if (!sdk || typeof sdk !== "object") throw new KmsProviderRuntimeError(KMS_PROVIDER_RUNTIME_ERROR_CODES.SDK);

  try {
    const options = { ...reliability, clock };
    if (config.provider === "aws") return createAwsProviders({ config, sdk, reliability: options, keyLifecycles });
    return createGcpProviders({ config, sdk, reliability: options, keyLifecycles });
  } catch (error) {
    if (error instanceof KmsProviderRuntimeError) throw error;
    throw new KmsProviderRuntimeError(KMS_PROVIDER_RUNTIME_ERROR_CODES.UNAVAILABLE);
  }
}

export function parseKmsProviderRuntimeConfig(env = process.env) {
  if (!plainObject(env) || env.AGENTPASS_CLOUD_PROFILE !== "hosted") fail(KMS_PROVIDER_RUNTIME_ERROR_CODES.CONFIG);
  for (const name of Object.keys(env)) {
    if (name.startsWith(KMS_ENV_PREFIX) && !ALLOWED_KMS_ENV.has(name)) fail(KMS_PROVIDER_RUNTIME_ERROR_CODES.CONFIG);
  }
  const provider = env[KMS_PROVIDER_RUNTIME_ENV.provider];
  const resources = Object.fromEntries(PURPOSE_DEFINITIONS.map((definition) => [
    definition.name,
    env[KMS_PROVIDER_RUNTIME_ENV[definition.resource]]
  ]));
  const resourceValues = PURPOSE_DEFINITIONS.map(({ name }) => resources[name]);
  if (!PROVIDERS.has(provider)
    || resourceValues.some((resource) => typeof resource !== "string" || resource.length < 1)
    || new Set(resourceValues).size !== PURPOSE_DEFINITIONS.length) {
    fail(KMS_PROVIDER_RUNTIME_ERROR_CODES.CONFIG);
  }
  const resourcePattern = provider === "aws" ? AWS_KEY_RESOURCE : GCP_RESOURCE;
  if (resourceValues.some((resource) => !resourcePattern.test(resource))) {
    fail(KMS_PROVIDER_RUNTIME_ERROR_CODES.CONFIG);
  }

  const parsed = {};
  try {
    for (const definition of PURPOSE_DEFINITIONS) {
      parsed[definition.name] = definition.parse
        ? definition.parse(env)
        : parseGenericSignerConfig(env, definition);
    }
  } catch {
    fail(KMS_PROVIDER_RUNTIME_ERROR_CODES.CONFIG);
  }
  if (new Set(PURPOSE_DEFINITIONS.map(({ name }) => parsed[name].keyId)).size !== PURPOSE_DEFINITIONS.length
    || new Set(PURPOSE_DEFINITIONS.map(({ name }) => parsed[name].publicKeyFingerprint)).size !== PURPOSE_DEFINITIONS.length) {
    fail(KMS_PROVIDER_RUNTIME_ERROR_CODES.CONFIG);
  }
  const purposes = PURPOSE_DEFINITIONS.map((definition) => Object.freeze({
    ...definition,
    resourceId: resources[definition.name],
    keyId: parsed[definition.name].keyId,
    publicKey: parsed[definition.name].publicKeyPem ?? env[definition.publicKeyEnv],
    publicKeyFingerprint: parsed[definition.name].publicKeyFingerprint,
    timeoutMs: parsed[definition.name].timeoutMs
  }));
  return deepFreeze({
    provider,
    ...Object.fromEntries(PURPOSE_DEFINITIONS.map(({ name, resource }) => [resource, resources[name]])),
    ...Object.fromEntries(purposes.map((purpose) => [purpose.name, Object.freeze({
      keyId: purpose.keyId,
      publicKey: purpose.publicKey,
      timeoutMs: purpose.timeoutMs
    })])),
    purposes,
    allPurposes: true
  });
}

async function loadOfficialSdk(provider) {
  if (provider === "aws") return import("@aws-sdk/client-kms");
  if (provider === "gcp") return import("@google-cloud/kms");
  throw new KmsProviderRuntimeError(KMS_PROVIDER_RUNTIME_ERROR_CODES.CONFIG);
}

function createAwsProviders({ config, sdk, reliability, keyLifecycles }) {
  if (typeof sdk.KMSClient !== "function" || typeof sdk.GetPublicKeyCommand !== "function" || typeof sdk.SignCommand !== "function") {
    throw new KmsProviderRuntimeError(KMS_PROVIDER_RUNTIME_ERROR_CODES.SDK);
  }
  const baseClient = new sdk.KMSClient({});
  if (typeof baseClient.destroy !== "function") {
    throw new KmsProviderRuntimeError(KMS_PROVIDER_RUNTIME_ERROR_CODES.SDK);
  }
  try {
    const providers = Object.fromEntries(config.purposes.map((definition) => {
      const provider = createAwsKmsEd25519Provider({
        publicKey: definition.publicKey,
        timeoutMs: definition.timeoutMs,
        client: bindAwsClient({ baseClient, sdk, logicalKeyId: definition.keyId, resourceId: definition.resourceId }),
        commands: bindAwsCommands({ sdk, resourceId: definition.resourceId }),
        keyId: definition.keyId,
        purpose: definition.purpose,
        version: definition.version
      });
      return [definition.providerName, managedSigner(provider, definition.purpose, reliability, keyLifecycles[definition.name])];
    }));
    return ownedProviders(providers, () => baseClient.destroy?.());
  } catch (error) {
    baseClient.destroy?.();
    throw error;
  }
}

function bindAwsCommands({ sdk, resourceId }) {
  return Object.freeze({
    GetPublicKeyCommand: class BoundGetPublicKeyCommand {
      constructor(input) { this.delegate = new sdk.GetPublicKeyCommand({ ...input, KeyId: resourceId }); }
    },
    SignCommand: class BoundSignCommand {
      constructor(input) { this.delegate = new sdk.SignCommand({ ...input, KeyId: resourceId }); }
    }
  });
}

function bindAwsClient({ baseClient, sdk, logicalKeyId, resourceId }) {
  return Object.freeze({
    async send(command, options) {
      if (!command?.delegate || !(command.delegate instanceof sdk.GetPublicKeyCommand || command.delegate instanceof sdk.SignCommand)) {
        throw new Error("invalid AWS KMS command");
      }
      const result = await baseClient.send(command.delegate, options);
      if (result?.KeyId !== undefined && result.KeyId !== resourceId) throw new Error("AWS KMS resource substitution");
      return result?.KeyId === undefined ? result : { ...result, KeyId: logicalKeyId };
    }
  });
}

function createGcpProviders({ config, sdk, reliability, keyLifecycles }) {
  if (typeof sdk.KeyManagementServiceClient !== "function") {
    throw new KmsProviderRuntimeError(KMS_PROVIDER_RUNTIME_ERROR_CODES.SDK);
  }
  const baseClient = new sdk.KeyManagementServiceClient({});
  if (typeof baseClient.close !== "function") {
    throw new KmsProviderRuntimeError(KMS_PROVIDER_RUNTIME_ERROR_CODES.SDK);
  }
  try {
    const providers = Object.fromEntries(config.purposes.map((definition) => {
      const provider = createGcpCloudKmsEd25519Provider({
        publicKey: definition.publicKey,
        timeoutMs: definition.timeoutMs,
        client: bindGcpClient({ baseClient, logicalKeyName: definition.keyId, resourceName: definition.resourceId }),
        keyName: definition.keyId,
        purpose: definition.purpose,
        version: definition.version
      });
      return [definition.providerName, managedSigner(provider, definition.purpose, reliability, keyLifecycles[definition.name])];
    }));
    return ownedProviders(providers, () => baseClient.close?.());
  } catch (error) {
    void baseClient.close?.();
    throw error;
  }
}

function ownedProviders(providers, destroy) {
  let closed = false;
  let closePromise;
  return Object.freeze({
    ...providers,
    async close() {
      if (closed) return;
      if (closePromise) return closePromise;
      closePromise = (async () => {
        try {
          await destroy();
          closed = true;
        } catch {
          closePromise = undefined;
          throw new KmsProviderRuntimeError(KMS_PROVIDER_RUNTIME_ERROR_CODES.UNAVAILABLE);
        }
      })();
      return closePromise;
    }
  });
}

function managedSigner(provider, purpose, reliability, lifecycle) {
  const keyLifecycle = lifecycle ?? createInitialKeyLifecycle(provider, purpose);
  const lifecycleBoundProvider = createManagedSignerLifecycleProvider({ provider, lifecycle: keyLifecycle });
  return createManagedSignerReliabilityProvider({ provider: lifecycleBoundProvider, purpose, ...reliability });
}

function createInitialKeyLifecycle(provider, purpose) {
  return createManagedSignerKeyLifecycle({
    purpose,
    algorithm: provider.algorithm,
    snapshot: {
      version: 1,
      purpose,
      algorithm: provider.algorithm,
      keys: [{
        key_id: provider.key_id,
        key_version: 1,
        purpose,
        algorithm: provider.algorithm,
        public_key_fingerprint: provider.public_key_fingerprint,
        state: "active",
        state_version: 1
      }]
    }
  });
}

function bindGcpClient({ baseClient, logicalKeyName, resourceName }) {
  return Object.freeze({
    async getPublicKey(request, options) {
      const response = await baseClient.getPublicKey({ ...request, name: resourceName }, options);
      return remapGcpResponse(response, logicalKeyName, resourceName);
    },
    async asymmetricSign(request, options) {
      const response = await baseClient.asymmetricSign({ ...request, name: resourceName }, options);
      return remapGcpResponse(response, logicalKeyName, resourceName);
    }
  });
}

function remapGcpResponse(response, logicalName, resourceName) {
  const map = (value) => {
    if (!value || typeof value !== "object" || Array.isArray(value)) return value;
    if (value.name !== undefined && value.name !== resourceName) throw new Error("Google Cloud KMS resource substitution");
    return value.name === undefined ? value : { ...value, name: logicalName };
  };
  if (Array.isArray(response)) return response.map(map);
  return map(response);
}

function plainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    && (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null);
}

function parseGenericSignerConfig(env, definition) {
  const keyId = env[definition.keyIdEnv];
  const publicKeyPem = env[definition.publicKeyEnv];
  const timeoutText = env[definition.timeoutEnv];
  if (!KEY_ID.test(keyId ?? "") || typeof publicKeyPem !== "string"
    || publicKeyPem.length < 1 || Buffer.byteLength(publicKeyPem, "utf8") > MAX_PUBLIC_KEY_BYTES
    || /PRIVATE\s+KEY/iu.test(publicKeyPem)) {
    fail(KMS_PROVIDER_RUNTIME_ERROR_CODES.CONFIG);
  }
  let publicKey;
  try { publicKey = crypto.createPublicKey(publicKeyPem); } catch { fail(KMS_PROVIDER_RUNTIME_ERROR_CODES.CONFIG); }
  if (publicKey.type !== "public" || publicKey.asymmetricKeyType !== "ed25519") fail(KMS_PROVIDER_RUNTIME_ERROR_CODES.CONFIG);
  const timeoutMs = timeoutText === undefined ? 5_000 : Number(timeoutText);
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 30_000
    || String(timeoutMs) !== String(timeoutText ?? 5_000)) fail(KMS_PROVIDER_RUNTIME_ERROR_CODES.CONFIG);
  const canonicalPem = publicKey.export({ type: "spki", format: "pem" }).toString();
  const fingerprint = crypto.createHash("sha256").update(publicKey.export({ type: "spki", format: "der" })).digest("hex");
  const registry = SIGNER_PURPOSE_REGISTRY[definition.registryName];
  if (!registry || registry.purpose !== definition.purpose || registry.protocol_version !== definition.version
    || registry.signing_version < 1 || registry.managed_algorithm !== "ed25519") {
    fail(KMS_PROVIDER_RUNTIME_ERROR_CODES.CONFIG);
  }
  return Object.freeze({ keyId, publicKeyPem: canonicalPem, publicKeyFingerprint: fingerprint, timeoutMs });
}

function parseRefreshHintSignerConfig(env) {
  const keyId = env.AGENTPASS_CLOUD_REFRESH_KEY_ID;
  const publicKeyPem = env.AGENTPASS_CLOUD_REFRESH_PUBLIC_KEY;
  const timeoutText = env.AGENTPASS_CLOUD_REFRESH_TIMEOUT_MS;
  if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$/u.test(keyId ?? "") || typeof publicKeyPem !== "string"
    || publicKeyPem.length < 1 || publicKeyPem.length > 8 * 1024) fail(KMS_PROVIDER_RUNTIME_ERROR_CODES.CONFIG);
  let publicKey;
  try { publicKey = crypto.createPublicKey(publicKeyPem); } catch { fail(KMS_PROVIDER_RUNTIME_ERROR_CODES.CONFIG); }
  if (publicKey.asymmetricKeyType !== REFRESH_HINT_SIGNATURE_ALGORITHM) fail(KMS_PROVIDER_RUNTIME_ERROR_CODES.CONFIG);
  const timeoutMs = timeoutText === undefined ? 5_000 : Number(timeoutText);
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 30_000 || String(timeoutMs) !== String(timeoutText ?? 5_000)) {
    fail(KMS_PROVIDER_RUNTIME_ERROR_CODES.CONFIG);
  }
  const der = publicKey.export({ type: "spki", format: "der" });
  return Object.freeze({
    keyId,
    publicKeyPem: publicKey.export({ type: "spki", format: "pem" }).toString(),
    publicKeyFingerprint: crypto.createHash("sha256").update(der).digest("hex"),
    timeoutMs
  });
}

function deepFreeze(value) {
  if (value !== null && typeof value === "object" && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}

function fail(code) { throw new KmsProviderRuntimeError(code); }
