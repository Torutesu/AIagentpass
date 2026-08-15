import { AGENT_SESSION_GRANT_SIGNATURE_DOMAIN, AGENT_SESSION_GRANT_TYPE } from "./agent-session-grant.mjs";
import { POSSESSION_RECEIPT_PURPOSE, POSSESSION_RECEIPT_SIGNATURE_ALGORITHMS, POSSESSION_RECEIPT_SIGNATURE_DOMAIN } from "./possession-receipt-signer.mjs";
import {
  QUALIFICATION_GRANT_BATCH_MANIFEST_PURPOSE,
  QUALIFICATION_GRANT_BATCH_MANIFEST_SIGNATURE_DOMAIN,
} from "./qualification-grant-batch-manifest.mjs";
import {
  PROMOTION_EVIDENCE_V3_PROTOCOL_VERSION,
  PROMOTION_EVIDENCE_V3_PURPOSE,
  PROMOTION_EVIDENCE_V3_SIGNATURE_DOMAIN,
  PROMOTION_EVIDENCE_V3_SIGNING_VERSION,
} from "./promotion-evidence-v3-statement.mjs";
import { REFRESH_HINT_SIGNATURE_DOMAIN, REFRESH_HINT_TYPE } from "../../../packages/protocol/src/index.mjs";

export const SIGNER_PURPOSE_REGISTRY_VERSION = 1;
const definitions = [
  { name: "capability", purpose: "agentpass.capability", domain: "AgentPass-Capability-v1\0", allowedAlgorithms: ["ed25519"], protocolVersion: 1, signingVersion: 1, hostedStatus: "managed_kms_integrated" },
  { name: "control_bundle", purpose: "agentpass.control-bundle", domain: "AgentPass-Control-Bundle-v2\0", allowedAlgorithms: ["ed25519"], protocolVersion: 2, signingVersion: 2, hostedStatus: "managed_kms_integrated" },
  { name: "refresh_hint", purpose: REFRESH_HINT_TYPE, domain: REFRESH_HINT_SIGNATURE_DOMAIN, allowedAlgorithms: ["ed25519"], protocolVersion: 1, signingVersion: 1, hostedStatus: "managed_kms_integrated" },
  { name: "possession_receipt", purpose: POSSESSION_RECEIPT_PURPOSE, domain: POSSESSION_RECEIPT_SIGNATURE_DOMAIN, allowedAlgorithms: POSSESSION_RECEIPT_SIGNATURE_ALGORITHMS, protocolVersion: 1, signingVersion: 1, hostedStatus: "managed_kms_integrated" },
  { name: "agent_session_grant", purpose: AGENT_SESSION_GRANT_TYPE, domain: AGENT_SESSION_GRANT_SIGNATURE_DOMAIN, allowedAlgorithms: ["ed25519"], protocolVersion: 1, signingVersion: 1, hostedStatus: "managed_kms_integrated" },
  { name: "qualification_manifest", purpose: QUALIFICATION_GRANT_BATCH_MANIFEST_PURPOSE, domain: QUALIFICATION_GRANT_BATCH_MANIFEST_SIGNATURE_DOMAIN, allowedAlgorithms: ["ed25519"], protocolVersion: 2, signingVersion: 2, hostedStatus: "managed_kms_integrated" },
  { name: "audit_anchor", purpose: "agentpass.audit-anchor", domain: "AgentPass-Audit-Anchor-v1\0", allowedAlgorithms: ["ed25519"], protocolVersion: 1, signingVersion: 1, hostedStatus: "managed_kms_integrated" },
  { name: "promotion_evidence", purpose: PROMOTION_EVIDENCE_V3_PURPOSE, domain: PROMOTION_EVIDENCE_V3_SIGNATURE_DOMAIN, allowedAlgorithms: ["ed25519"], protocolVersion: PROMOTION_EVIDENCE_V3_PROTOCOL_VERSION, signingVersion: PROMOTION_EVIDENCE_V3_SIGNING_VERSION, hostedStatus: "managed_kms_integrated" },
];

const HOSTED_STATUSES = new Set(["file_backed_hosted", "managed_kms_integrated", "migration_required", "primitive_only", "schema_only"]);
const LEGACY_BINDING_FIELDS = ["algorithm", "domain", "key_id", "key_version", "name", "provider", "provider_resource_id", "public_key_fingerprint", "purpose", "version"];
const CURRENT_BINDING_FIELDS = ["algorithm", "domain", "hosted_status", "key_id", "key_version", "name", "provider", "provider_resource_id", "public_key_fingerprint", "protocol_version", "purpose", "registry_version", "signing_version", "version"];

export const SIGNER_PURPOSE_REGISTRY = deepFreeze(Object.fromEntries(definitions.map((definition) => [definition.name, {
  version: SIGNER_PURPOSE_REGISTRY_VERSION,
  registry_version: SIGNER_PURPOSE_REGISTRY_VERSION,
  protocol_version: definition.protocolVersion,
  signing_version: definition.signingVersion,
  name: definition.name,
  purpose: definition.purpose,
  domain: definition.domain,
  allowed_algorithms: definition.allowedAlgorithms,
  managed_algorithm: "ed25519",
  hosted_status: definition.hostedStatus,
}])));

export class SignerPurposeRegistryError extends TypeError {
  constructor(code, message) {
    super(message);
    this.name = "SignerPurposeRegistryError";
    this.code = code;
  }
}

/**
 * Validate the complete provider-neutral hosted binding set. This is a
 * qualification boundary, not a runtime fallback: all eight purposes must be
 * present and every binding must match the frozen registry byte-for-byte.
 */
export function validateSignerPurposeBindings(input) {
  if (!Array.isArray(input)) invalid("ERR_SIGNER_REGISTRY_INPUT", "signer bindings must be an array");
  if (input.length !== definitions.length) invalid("ERR_SIGNER_REGISTRY_INCOMPLETE", "signer bindings are incomplete");
  const byName = new Map();
  const keyVersions = new Set();
  const publicKeyFingerprints = new Set();
  for (const value of input) {
    if (!plainObject(value) || (!sameKeys(value, LEGACY_BINDING_FIELDS) && !sameKeys(value, CURRENT_BINDING_FIELDS))) {
      invalid("ERR_SIGNER_REGISTRY_INPUT", "signer binding shape is invalid");
    }
    if (byName.has(value.name)) invalid("ERR_SIGNER_REGISTRY_DUPLICATE", "signer purpose is duplicated");
    const expected = SIGNER_PURPOSE_REGISTRY[value.name];
    if (!expected) invalid("ERR_SIGNER_REGISTRY_PURPOSE", "signer purpose is unknown");
    const binding = normalizeBinding(value, expected);
    if (!validVersion(binding.version) || !validVersion(binding.registry_version) || !validVersion(binding.protocol_version) || !validVersion(binding.signing_version)) {
      invalid("ERR_SIGNER_REGISTRY_STATE", "signer version fields are invalid");
    }
    for (const field of ["version", "registry_version", "protocol_version", "signing_version", "purpose", "domain"]) {
      if (binding[field] !== expected[field]) invalid("ERR_SIGNER_REGISTRY_SUBSTITUTION", `signer ${field} does not match the registry`);
    }
    if (!HOSTED_STATUSES.has(binding.hosted_status) || binding.hosted_status !== expected.hosted_status) {
      invalid("ERR_SIGNER_REGISTRY_STATE", "signer hosted status does not match the registry");
    }
    if (binding.algorithm !== expected.managed_algorithm) invalid("ERR_SIGNER_REGISTRY_SUBSTITUTION", "signer algorithm does not match the managed profile");
    if (!identifier(binding.key_id) || !identifier(binding.key_version)) invalid("ERR_SIGNER_REGISTRY_KEY", "signer key metadata is invalid");
    if (!managedProvider(binding.provider) || !resourceId(binding.provider_resource_id)) invalid("ERR_SIGNER_REGISTRY_PROVIDER", "hosted signer provider must be managed and non-file-backed");
    if (typeof binding.public_key_fingerprint !== "string" || !/^[0-9a-f]{64}$/u.test(binding.public_key_fingerprint)) invalid("ERR_SIGNER_REGISTRY_KEY", "signer public key fingerprint is invalid");
    const identity = `${binding.provider}\0${binding.provider_resource_id}\0${binding.key_id}\0${binding.key_version}`;
    if (keyVersions.has(identity)) invalid("ERR_SIGNER_REGISTRY_KEY_REUSE", "signer key/version is shared across purposes");
    if (publicKeyFingerprints.has(binding.public_key_fingerprint)) invalid("ERR_SIGNER_REGISTRY_KEY_REUSE", "signer public key is shared across purposes");
    keyVersions.add(identity);
    publicKeyFingerprints.add(binding.public_key_fingerprint);
    byName.set(binding.name, Object.freeze(binding));
  }
  for (const { name } of definitions) if (!byName.has(name)) invalid("ERR_SIGNER_REGISTRY_INCOMPLETE", "signer bindings are incomplete");
  return deepFreeze({ version: SIGNER_PURPOSE_REGISTRY_VERSION, registry_version: SIGNER_PURPOSE_REGISTRY_VERSION, bindings: Object.fromEntries([...byName].sort(([left], [right]) => left.localeCompare(right))) });
}

function normalizeBinding(value, expected) {
  const legacy = sameKeys(value, LEGACY_BINDING_FIELDS);
  return {
    ...value,
    version: value.version,
    registry_version: legacy ? value.version : value.registry_version,
    protocol_version: legacy ? expected.protocol_version : value.protocol_version,
    signing_version: legacy ? expected.signing_version : value.signing_version,
    hosted_status: legacy ? expected.hosted_status : value.hosted_status,
  };
}

function validVersion(value) {
  return Number.isSafeInteger(value) && value >= 1;
}

function managedProvider(value) {
  return value === "aws-kms" || value === "gcp-cloud-kms" || value === "hsm";
}

function identifier(value) {
  return typeof value === "string" && /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$/u.test(value);
}

function resourceId(value) {
  return typeof value === "string" && value.length <= 1024 && /^(?:arn:aws:kms:|projects\/|hsm:)[A-Za-z0-9][A-Za-z0-9._:/-]+$/u.test(value)
    && !/(?:^|[/:])(?:file|local|pem|private-key)(?:$|[/:])/iu.test(value);
}

function plainObject(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function sameKeys(value, keys) {
  const actual = Reflect.ownKeys(value);
  if (actual.some((key) => typeof key !== "string")) return false;
  return actual.sort().join("\0") === [...keys].sort().join("\0");
}

function deepFreeze(value) {
  if (value !== null && typeof value === "object" && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}

function invalid(code, message) {
  throw new SignerPurposeRegistryError(code, message);
}
