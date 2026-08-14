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

export const KMS_PROVIDER_RUNTIME_ENV = Object.freeze({
  provider: "AGENTPASS_KMS_PROVIDER",
  agentSessionResource: "AGENTPASS_KMS_AGENT_SESSION_KEY_RESOURCE",
  qualificationManifestResource: "AGENTPASS_KMS_QUALIFICATION_MANIFEST_KEY_RESOURCE"
});

export const KMS_PROVIDER_RUNTIME_ERROR_CODES = Object.freeze({
  CONFIG: "ERR_KMS_PROVIDER_RUNTIME_CONFIG",
  SDK: "ERR_KMS_PROVIDER_RUNTIME_SDK",
  UNAVAILABLE: "ERR_KMS_PROVIDER_RUNTIME_UNAVAILABLE"
});

const KMS_ENV_PREFIX = "AGENTPASS_KMS_";
const ALLOWED_KMS_ENV = new Set(Object.values(KMS_PROVIDER_RUNTIME_ENV));
const PROVIDERS = new Set(["aws", "gcp"]);
const AWS_RESOURCE = /^[A-Za-z0-9][A-Za-z0-9:/._-]{0,2047}$/u;
const GCP_RESOURCE = /^projects\/[A-Za-z0-9._-]+\/locations\/[A-Za-z0-9._-]+\/keyRings\/[A-Za-z0-9._-]+\/cryptoKeys\/[A-Za-z0-9._-]+\/cryptoKeyVersions\/[A-Za-z0-9._-]+$/u;

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
 * Compose both hosted signing providers from official cloud SDK clients.
 *
 * AWS SDK credentials and Google Application Default Credentials are resolved
 * by their official clients. This function accepts no private-key path,
 * private-key material, credential blob, or local signer fallback.
 */
export async function createHostedKmsProviders({
  env = process.env,
  sdkLoader = loadOfficialSdk,
  clock = () => Date.now(),
  reliability = MANAGED_SIGNER_RELIABILITY_DEFAULTS
} = {}) {
  const config = parseKmsProviderRuntimeConfig(env);
  let sdk;
  try {
    sdk = await sdkLoader(config.provider);
  } catch {
    throw new KmsProviderRuntimeError(KMS_PROVIDER_RUNTIME_ERROR_CODES.SDK);
  }
  if (!sdk || typeof sdk !== "object") throw new KmsProviderRuntimeError(KMS_PROVIDER_RUNTIME_ERROR_CODES.SDK);

  try {
    const options = { ...reliability, clock };
    if (config.provider === "aws") return createAwsProviders({ config, sdk, reliability: options });
    return createGcpProviders({ config, sdk, reliability: options });
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
  const agentSessionResource = env[KMS_PROVIDER_RUNTIME_ENV.agentSessionResource];
  const qualificationManifestResource = env[KMS_PROVIDER_RUNTIME_ENV.qualificationManifestResource];
  if (!PROVIDERS.has(provider) || typeof agentSessionResource !== "string" || typeof qualificationManifestResource !== "string"
    || agentSessionResource.length < 1 || qualificationManifestResource.length < 1
    || agentSessionResource === qualificationManifestResource) {
    fail(KMS_PROVIDER_RUNTIME_ERROR_CODES.CONFIG);
  }
  const resourcePattern = provider === "aws" ? AWS_RESOURCE : GCP_RESOURCE;
  if (!resourcePattern.test(agentSessionResource) || !resourcePattern.test(qualificationManifestResource)) {
    fail(KMS_PROVIDER_RUNTIME_ERROR_CODES.CONFIG);
  }

  let agentSession;
  let qualificationManifest;
  try {
    agentSession = parseAgentSessionSignerConfig(env);
    qualificationManifest = parseQualificationManifestSignerConfig(env);
  } catch {
    fail(KMS_PROVIDER_RUNTIME_ERROR_CODES.CONFIG);
  }
  if (agentSession.keyId === qualificationManifest.keyId
    || agentSession.publicKeyFingerprint === qualificationManifest.publicKeyFingerprint) {
    fail(KMS_PROVIDER_RUNTIME_ERROR_CODES.CONFIG);
  }
  return Object.freeze({
    provider,
    agentSessionResource,
    qualificationManifestResource,
    agentSession: Object.freeze({
      keyId: agentSession.keyId,
      publicKey: agentSession.publicKeyPem,
      timeoutMs: agentSession.timeoutMs
    }),
    qualificationManifest: Object.freeze({
      keyId: qualificationManifest.keyId,
      publicKey: env.AGENTPASS_CLOUD_QUALIFICATION_MANIFEST_PUBLIC_KEY,
      timeoutMs: qualificationManifest.timeoutMs
    })
  });
}

async function loadOfficialSdk(provider) {
  if (provider === "aws") return import("@aws-sdk/client-kms");
  if (provider === "gcp") return import("@google-cloud/kms");
  throw new KmsProviderRuntimeError(KMS_PROVIDER_RUNTIME_ERROR_CODES.CONFIG);
}

function createAwsProviders({ config, sdk, reliability }) {
  if (typeof sdk.KMSClient !== "function" || typeof sdk.GetPublicKeyCommand !== "function" || typeof sdk.SignCommand !== "function") {
    throw new KmsProviderRuntimeError(KMS_PROVIDER_RUNTIME_ERROR_CODES.SDK);
  }
  const baseClient = new sdk.KMSClient({});
  if (typeof baseClient.destroy !== "function") {
    throw new KmsProviderRuntimeError(KMS_PROVIDER_RUNTIME_ERROR_CODES.SDK);
  }
  try {
    const agent = createAwsKmsEd25519Provider({
      ...config.agentSession,
      client: bindAwsClient({ baseClient, sdk, logicalKeyId: config.agentSession.keyId, resourceId: config.agentSessionResource }),
      commands: bindAwsCommands({ sdk, resourceId: config.agentSessionResource }),
      keyId: config.agentSession.keyId,
      purpose: AGENT_SESSION_GRANT_TYPE,
      version: AGENT_SESSION_GRANT_VERSION
    });
    const qualification = createAwsKmsEd25519Provider({
      ...config.qualificationManifest,
      client: bindAwsClient({ baseClient, sdk, logicalKeyId: config.qualificationManifest.keyId, resourceId: config.qualificationManifestResource }),
      commands: bindAwsCommands({ sdk, resourceId: config.qualificationManifestResource }),
      keyId: config.qualificationManifest.keyId,
      purpose: QUALIFICATION_GRANT_BATCH_MANIFEST_PURPOSE,
      version: QUALIFICATION_GRANT_BATCH_MANIFEST_VERSION
    });
    return ownedProviders({
      agentSessionSignerProvider: managedSigner(agent, AGENT_SESSION_GRANT_TYPE, reliability),
      qualificationManifestSignerProvider: managedSigner(qualification, QUALIFICATION_GRANT_BATCH_MANIFEST_PURPOSE, reliability)
    }, () => baseClient.destroy?.());
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

function createGcpProviders({ config, sdk, reliability }) {
  if (typeof sdk.KeyManagementServiceClient !== "function") {
    throw new KmsProviderRuntimeError(KMS_PROVIDER_RUNTIME_ERROR_CODES.SDK);
  }
  const baseClient = new sdk.KeyManagementServiceClient({});
  if (typeof baseClient.close !== "function") {
    throw new KmsProviderRuntimeError(KMS_PROVIDER_RUNTIME_ERROR_CODES.SDK);
  }
  try {
    const agent = createGcpCloudKmsEd25519Provider({
      ...config.agentSession,
      client: bindGcpClient({ baseClient, logicalKeyName: config.agentSession.keyId, resourceName: config.agentSessionResource }),
      keyName: config.agentSession.keyId,
      purpose: AGENT_SESSION_GRANT_TYPE,
      version: AGENT_SESSION_GRANT_VERSION
    });
    const qualification = createGcpCloudKmsEd25519Provider({
      ...config.qualificationManifest,
      client: bindGcpClient({ baseClient, logicalKeyName: config.qualificationManifest.keyId, resourceName: config.qualificationManifestResource }),
      keyName: config.qualificationManifest.keyId,
      purpose: QUALIFICATION_GRANT_BATCH_MANIFEST_PURPOSE,
      version: QUALIFICATION_GRANT_BATCH_MANIFEST_VERSION
    });
    return ownedProviders({
      agentSessionSignerProvider: managedSigner(agent, AGENT_SESSION_GRANT_TYPE, reliability),
      qualificationManifestSignerProvider: managedSigner(qualification, QUALIFICATION_GRANT_BATCH_MANIFEST_PURPOSE, reliability)
    }, () => baseClient.close?.());
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

function managedSigner(provider, purpose, reliability) {
  return createManagedSignerReliabilityProvider({ provider, purpose, ...reliability });
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

function fail(code) { throw new KmsProviderRuntimeError(code); }
