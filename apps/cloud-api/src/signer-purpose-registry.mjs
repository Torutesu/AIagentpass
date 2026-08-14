import { AGENT_SESSION_GRANT_SIGNATURE_DOMAIN, AGENT_SESSION_GRANT_TYPE } from "./agent-session-grant.mjs";
import { POSSESSION_RECEIPT_PURPOSE, POSSESSION_RECEIPT_SIGNATURE_ALGORITHMS, POSSESSION_RECEIPT_SIGNATURE_DOMAIN } from "./possession-receipt-signer.mjs";
import {
  QUALIFICATION_GRANT_BATCH_MANIFEST_PURPOSE,
  QUALIFICATION_GRANT_BATCH_MANIFEST_SIGNATURE_DOMAIN,
} from "./qualification-grant-batch-manifest.mjs";
import { REFRESH_HINT_SIGNATURE_DOMAIN, REFRESH_HINT_TYPE } from "../../../packages/protocol/src/index.mjs";

export const SIGNER_PURPOSE_REGISTRY_VERSION = 1;
const definitions = [
  ["capability", "agentpass.capability", "AgentPass-Capability-v1\0", ["ed25519"], "migration_required"],
  ["control_bundle", "agentpass.control-bundle", "AgentPass-Control-Bundle-v2\0", ["ed25519"], "migration_required"],
  ["refresh_hint", REFRESH_HINT_TYPE, REFRESH_HINT_SIGNATURE_DOMAIN, ["ed25519"], "file_backed_hosted"],
  ["possession_receipt", POSSESSION_RECEIPT_PURPOSE, POSSESSION_RECEIPT_SIGNATURE_DOMAIN, POSSESSION_RECEIPT_SIGNATURE_ALGORITHMS, "primitive_only"],
  ["agent_session_grant", AGENT_SESSION_GRANT_TYPE, AGENT_SESSION_GRANT_SIGNATURE_DOMAIN, ["ed25519"], "managed_kms_integrated"],
  ["qualification_manifest", QUALIFICATION_GRANT_BATCH_MANIFEST_PURPOSE, QUALIFICATION_GRANT_BATCH_MANIFEST_SIGNATURE_DOMAIN, ["ed25519"], "managed_kms_integrated"],
  ["audit_anchor", "agentpass.audit-anchor", "AgentPass-Audit-Anchor-v1\0", ["ed25519"], "migration_required"],
  ["promotion_evidence", "agentpass.promotion-evidence", "AgentPass-Promotion-Evidence-v1\0", ["ed25519"], "schema_only"],
];

export const SIGNER_PURPOSE_REGISTRY = deepFreeze(Object.fromEntries(definitions.map(([name, purpose, domain, allowedAlgorithms, hostedStatus]) => [name, {
  version: SIGNER_PURPOSE_REGISTRY_VERSION,
  name,
  purpose,
  domain,
  allowed_algorithms: allowedAlgorithms,
  managed_algorithm: "ed25519",
  hosted_status: hostedStatus,
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
    if (!plainObject(value) || !sameKeys(value, ["algorithm", "domain", "key_id", "key_version", "name", "provider", "provider_resource_id", "public_key_fingerprint", "purpose", "version"])) {
      invalid("ERR_SIGNER_REGISTRY_INPUT", "signer binding shape is invalid");
    }
    if (byName.has(value.name)) invalid("ERR_SIGNER_REGISTRY_DUPLICATE", "signer purpose is duplicated");
    const expected = SIGNER_PURPOSE_REGISTRY[value.name];
    if (!expected) invalid("ERR_SIGNER_REGISTRY_PURPOSE", "signer purpose is unknown");
    for (const field of ["version", "purpose", "domain"]) {
      if (value[field] !== expected[field]) invalid("ERR_SIGNER_REGISTRY_SUBSTITUTION", `signer ${field} does not match the registry`);
    }
    if (value.algorithm !== expected.managed_algorithm) invalid("ERR_SIGNER_REGISTRY_SUBSTITUTION", "signer algorithm does not match the managed profile");
    if (!identifier(value.key_id) || !identifier(value.key_version)) invalid("ERR_SIGNER_REGISTRY_KEY", "signer key metadata is invalid");
    if (!managedProvider(value.provider) || !resourceId(value.provider_resource_id)) invalid("ERR_SIGNER_REGISTRY_PROVIDER", "hosted signer provider must be managed and non-file-backed");
    if (typeof value.public_key_fingerprint !== "string" || !/^[0-9a-f]{64}$/u.test(value.public_key_fingerprint)) invalid("ERR_SIGNER_REGISTRY_KEY", "signer public key fingerprint is invalid");
    const identity = `${value.provider}\0${value.provider_resource_id}\0${value.key_id}\0${value.key_version}`;
    if (keyVersions.has(identity)) invalid("ERR_SIGNER_REGISTRY_KEY_REUSE", "signer key/version is shared across purposes");
    if (publicKeyFingerprints.has(value.public_key_fingerprint)) invalid("ERR_SIGNER_REGISTRY_KEY_REUSE", "signer public key is shared across purposes");
    keyVersions.add(identity);
    publicKeyFingerprints.add(value.public_key_fingerprint);
    byName.set(value.name, Object.freeze({ ...value }));
  }
  for (const [name] of definitions) if (!byName.has(name)) invalid("ERR_SIGNER_REGISTRY_INCOMPLETE", "signer bindings are incomplete");
  return deepFreeze({ version: SIGNER_PURPOSE_REGISTRY_VERSION, bindings: Object.fromEntries([...byName].sort(([left], [right]) => left.localeCompare(right))) });
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
