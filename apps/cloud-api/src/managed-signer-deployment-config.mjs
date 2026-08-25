import { SIGNER_PURPOSE_REGISTRY, SIGNER_PURPOSE_REGISTRY_VERSION } from "./signer-purpose-registry.mjs";

/**
 * Closed, provider-neutral deployment configuration for every managed signer.
 *
 * This module is intentionally independent from the runtime and provider
 * adapters. It validates the public configuration boundary before any provider
 * is constructed; callers must not use it as a source of private key material.
 */
export const MANAGED_SIGNER_DEPLOYMENT_CONFIG_VERSION = 1;
export const MANAGED_SIGNER_DEPLOYMENT_ALGORITHM = "ed25519";

const REGISTRY_ENTRIES = Object.freeze(Object.values(SIGNER_PURPOSE_REGISTRY));
const EXPECTED_PURPOSES = Object.freeze(REGISTRY_ENTRIES.map(({ purpose }) => purpose).sort());
const EXPECTED_PROTOCOL_VERSIONS = Object.freeze(Object.fromEntries(REGISTRY_ENTRIES.map(({ purpose, protocol_version }) => [purpose, protocol_version])));

const TOP_LEVEL_FIELDS = Object.freeze(["schema_version", "registry_version", "signers"]);
const SIGNER_FIELDS = Object.freeze([
  "purpose",
  "provider",
  "account_id",
  "project_id",
  "region",
  "key_resource",
  "key_version",
  "public_key_fingerprint",
  "algorithm",
  "registry_version",
  "protocol_version",
  "signing_version",
  "lifecycle_version",
]);

const PROVIDERS = new Set(["aws-kms", "gcp-cloud-kms", "hsm"]);
const VERSION = /^[1-9][0-9]{0,19}$/u;
const FINGERPRINT = /^[0-9a-f]{64}$/u;
const AWS_ACCOUNT = /^[0-9]{12}$/u;
const GCP_PROJECT = /^[a-z][a-z0-9-]{4,28}[a-z0-9]$/u;
const SEGMENT = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;
const PROJECT_OR_SCOPE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u;
const REGION = /^[a-z0-9][a-z0-9-]{0,62}$/u;
const AWS_KEY_RESOURCE = /^arn:aws:kms:([a-z0-9-]+):([0-9]{12}):key\/([0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})$/u;
const GCP_KEY_RESOURCE = /^projects\/([a-z][a-z0-9-]{4,28}[a-z0-9])\/locations\/([a-z0-9][a-z0-9-]{0,62})\/keyRings\/([A-Za-z0-9_-]{1,63})\/cryptoKeys\/([A-Za-z0-9_-]{1,63})\/cryptoKeyVersions\/([1-9][0-9]{0,19})$/u;
const HSM_KEY_RESOURCE = /^hsm:([A-Za-z0-9][A-Za-z0-9._:-]{0,127})\/([A-Za-z0-9][A-Za-z0-9._:-]{0,127})\/([a-z0-9][a-z0-9-]{0,62})\/key\/([A-Za-z0-9][A-Za-z0-9._:-]{0,127})\/version\/([1-9][0-9]{0,19})$/u;
const UNSAFE_STRING = /[\u0000-\u001f\u007f\u2028\u2029]|[\\]|\.\.|\$\{|\r|\n/u;
const FORBIDDEN_FIELD = /(?:private(?:[_-](?:key|material))?|secret(?:[_-](?:key|material))?|pem|file|local(?:[_-]?(?:path|key|secret))?)/iu;

export const MANAGED_SIGNER_DEPLOYMENT_PURPOSES = EXPECTED_PURPOSES;
export const MANAGED_SIGNER_DEPLOYMENT_PROTOCOL_VERSIONS = EXPECTED_PROTOCOL_VERSIONS;
export const MANAGED_SIGNER_DEPLOYMENT_TOP_LEVEL_FIELDS = TOP_LEVEL_FIELDS;
export const MANAGED_SIGNER_DEPLOYMENT_SIGNER_FIELDS = SIGNER_FIELDS;

export class ManagedSignerDeploymentConfigError extends TypeError {
  constructor(code, message = "managed signer deployment configuration is invalid") {
    super(message);
    this.name = "ManagedSignerDeploymentConfigError";
    this.code = code;
  }
}

/**
 * Validate, normalize, and deeply freeze the complete public deployment
 * configuration. Exactly one entry is required for each frozen registry
 * purpose. The returned object contains no caller-owned objects or private
 * material and can safely be passed to readiness/reporting code.
 */
export function validateManagedSignerDeploymentConfig(input) {
  assertPlainRecord(input, "INVALID_INPUT");
  assertExactKeys(input, TOP_LEVEL_FIELDS, "UNKNOWN_FIELD");
  assertVersion(input.schema_version, MANAGED_SIGNER_DEPLOYMENT_CONFIG_VERSION, "INVALID_SCHEMA_VERSION");
  assertVersion(input.registry_version, SIGNER_PURPOSE_REGISTRY_VERSION, "INVALID_REGISTRY_VERSION");
  if (!Array.isArray(input.signers) || input.signers.length !== EXPECTED_PURPOSES.length) fail("INCOMPLETE_PURPOSES");
  assertExactArrayKeys(input.signers, "UNKNOWN_FIELD");

  const seenPurposes = new Set();
  const seenResources = new Set();
  const seenFingerprints = new Set();
  const normalized = input.signers.map((entry) => {
    const value = normalizeSigner(entry);
    if (seenPurposes.has(value.purpose)) fail("DUPLICATE_PURPOSE");
    if (seenResources.has(value.key_resource)) fail("SHARED_KEY_RESOURCE");
    if (seenFingerprints.has(value.public_key_fingerprint)) fail("SHARED_PUBLIC_KEY");
    seenPurposes.add(value.purpose);
    seenResources.add(value.key_resource);
    seenFingerprints.add(value.public_key_fingerprint);
    return value;
  });

  if (seenPurposes.size !== EXPECTED_PURPOSES.length || EXPECTED_PURPOSES.some((purpose) => !seenPurposes.has(purpose))) {
    fail("INCOMPLETE_PURPOSES");
  }

  normalized.sort((left, right) => left.purpose.localeCompare(right.purpose));
  return deepFreeze({
    schema_version: MANAGED_SIGNER_DEPLOYMENT_CONFIG_VERSION,
    registry_version: SIGNER_PURPOSE_REGISTRY_VERSION,
    signers: normalized,
  });
}

// Explicit aliases make the boundary usable by both parser- and validator-
// oriented callers without introducing a second implementation.
export const parseManagedSignerDeploymentConfig = validateManagedSignerDeploymentConfig;
export const normalizeManagedSignerDeploymentConfig = validateManagedSignerDeploymentConfig;

function normalizeSigner(input) {
  assertPlainRecord(input, "INVALID_SIGNER");
  assertExactKeys(input, SIGNER_FIELDS, "UNKNOWN_FIELD");
  const purpose = safeString(input.purpose, "INVALID_PURPOSE", /^[a-z][a-z0-9.-]{2,127}$/u);
  const expected = SIGNER_PURPOSE_REGISTRY_BY_PURPOSE.get(purpose);
  if (!expected) fail("UNKNOWN_PURPOSE");
  const provider = safeString(input.provider, "INVALID_PROVIDER", /^[a-z][a-z0-9-]{2,31}$/u);
  if (!PROVIDERS.has(provider)) fail("INVALID_PROVIDER");
  const accountId = safeString(input.account_id, "INVALID_ACCOUNT", SEGMENT);
  const projectId = safeString(input.project_id, "INVALID_PROJECT", PROJECT_OR_SCOPE);
  const region = safeString(input.region, "INVALID_REGION", REGION);
  const keyResource = safeString(input.key_resource, "INVALID_KEY_RESOURCE");
  const keyVersion = safeString(input.key_version, "INVALID_KEY_VERSION", VERSION);
  const fingerprint = safeString(input.public_key_fingerprint, "INVALID_PUBLIC_KEY_FINGERPRINT", FINGERPRINT);

  if (input.algorithm !== MANAGED_SIGNER_DEPLOYMENT_ALGORITHM) fail("INVALID_ALGORITHM");
  assertVersion(input.registry_version, SIGNER_PURPOSE_REGISTRY_VERSION, "INVALID_REGISTRY_VERSION");
  assertVersion(input.protocol_version, expected.protocol_version, "INVALID_PROTOCOL_VERSION");
  assertVersion(input.signing_version, expected.signing_version, "INVALID_SIGNING_VERSION");
  assertPositiveVersion(input.lifecycle_version, "INVALID_LIFECYCLE_VERSION");
  validateProviderResource({ provider, accountId, projectId, region, keyResource, keyVersion });

  return {
    purpose,
    provider,
    account_id: accountId,
    project_id: projectId,
    region,
    key_resource: keyResource,
    key_version: keyVersion,
    public_key_fingerprint: fingerprint,
    algorithm: MANAGED_SIGNER_DEPLOYMENT_ALGORITHM,
    registry_version: SIGNER_PURPOSE_REGISTRY_VERSION,
    protocol_version: expected.protocol_version,
    signing_version: expected.signing_version,
    lifecycle_version: input.lifecycle_version,
  };
}

function validateProviderResource({ provider, accountId, projectId, region, keyResource, keyVersion }) {
  if (provider === "aws-kms") {
    if (!AWS_ACCOUNT.test(accountId)) fail("INVALID_ACCOUNT");
    const match = AWS_KEY_RESOURCE.exec(keyResource);
    if (!match || match[1] !== region || match[2] !== accountId || keyVersion === "latest") fail("INVALID_KEY_RESOURCE");
    return;
  }
  if (provider === "gcp-cloud-kms") {
    if (!GCP_PROJECT.test(projectId)) fail("INVALID_PROJECT");
    const match = GCP_KEY_RESOURCE.exec(keyResource);
    if (!match || match[1] !== projectId || match[2] !== region || match[5] !== keyVersion) fail("INVALID_KEY_RESOURCE");
    return;
  }
  const match = HSM_KEY_RESOURCE.exec(keyResource);
  if (!match || match[1] !== accountId || match[2] !== projectId || match[3] !== region || match[5] !== keyVersion) fail("INVALID_KEY_RESOURCE");
}

function safeString(value, code, pattern = null) {
  if (typeof value !== "string" || value.length === 0 || value.length > 1024 || UNSAFE_STRING.test(value) || value.trim() !== value) fail(code);
  if (pattern && !pattern.test(value)) fail(code);
  return value;
}

function assertVersion(value, expected, code) {
  if (!Number.isSafeInteger(value) || value !== expected) fail(code);
}

function assertPositiveVersion(value, code) {
  if (!Number.isSafeInteger(value) || value < 1) fail(code);
}

function assertPlainRecord(value, code) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) fail(code);
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) fail(code);
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key !== "string" || FORBIDDEN_FIELD.test(key)) fail("PRIVATE_MATERIAL");
  }
}

function assertExactKeys(value, expected, code) {
  const keys = Reflect.ownKeys(value);
  if (keys.some((key) => typeof key !== "string" || !Object.prototype.propertyIsEnumerable.call(value, key))) fail(code);
  const actual = keys.slice().sort();
  const sortedExpected = [...expected].sort();
  if (actual.length !== sortedExpected.length || actual.some((key, index) => key !== sortedExpected[index])) fail(code);
}

function assertExactArrayKeys(value, code) {
  const keys = Reflect.ownKeys(value);
  for (const key of keys) {
    if (key === "length") continue;
    if (typeof key !== "string" || !/^\d+$/u.test(key) || Number(key) >= value.length || !Object.prototype.propertyIsEnumerable.call(value, key)) {
      if (typeof key === "string" && FORBIDDEN_FIELD.test(key)) fail("PRIVATE_MATERIAL");
      fail(code);
    }
  }
}

function deepFreeze(value) {
  if (value !== null && typeof value === "object" && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}

function fail(code) {
  throw new ManagedSignerDeploymentConfigError(code);
}

const SIGNER_PURPOSE_REGISTRY_BY_PURPOSE = new Map(REGISTRY_ENTRIES.map((entry) => [entry.purpose, entry]));
