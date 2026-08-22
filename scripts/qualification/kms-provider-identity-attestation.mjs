import { createHash, createPublicKey, verify } from "node:crypto";

import { canonicalJson } from "../../packages/protocol/src/index.mjs";

export const KMS_PROVIDER_IDENTITY_ATTESTATION_SCHEMA_VERSION = 1;
export const KMS_PROVIDER_IDENTITY_ATTESTATION_KIND = "agentpass.kms-provider-identity-attestation";
export const KMS_PROVIDER_IDENTITY_ATTESTATION_DOMAIN = "AgentPass-KMS-Provider-Identity-Attestation-v1\0";

const HEX64 = /^[0-9a-f]{64}$/u;
const B64URL = /^[A-Za-z0-9_-]+$/u;
const FINGERPRINT = /^SHA256:[A-Za-z0-9_-]{43}$/u;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$/u;
const TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u;
const PROVIDERS = new Set(["aws-kms", "gcp-cloud-kms"]);

const PAYLOAD_KEYS = Object.freeze([
  "schema_version", "kind", "provider", "account_or_project", "identity", "identity_fingerprint", "region",
  "resource_ids", "challenge", "provider_claims"
]);
const CHALLENGE_KEYS = Object.freeze(["nonce", "binding_digest", "issued_at", "expires_at"]);
const CHALLENGE_KEYS_WITH_RESOURCES = Object.freeze([...CHALLENGE_KEYS, "resource_ids"]);
const CLAIM_KEYS = Object.freeze(["identity_document_digest", "request_digest", "response_digest"]);
const ATTESTATION_KEYS = Object.freeze([
  ...PAYLOAD_KEYS, "signature_algorithm", "attestor_key_id", "attestor_public_key_fingerprint", "signature_base64url"
]);
const TRUST_ENTRY_KEYS = Object.freeze(["fingerprint", "key_id", "public_key"]);
const TRUST_ENTRY_DER_KEYS = Object.freeze(["key_id", "public_key_der_base64url", "public_key_fingerprint"]);

export const KMS_PROVIDER_IDENTITY_ATTESTOR_TRUST_SCHEMA_VERSION = 1;

function exactObject(value, keys, label) {
  if (value === null || typeof value !== "object" || Array.isArray(value)
    || Object.getPrototypeOf(value) !== Object.prototype
    || JSON.stringify(Object.keys(value).sort()) !== JSON.stringify([...keys].sort())) {
    throw new Error(`${label} has missing or unknown fields`);
  }
}

function publicKeyFromInput(input) {
  if (input && typeof input === "object" && input.type === "public") return input;
  if (input && typeof input === "object" && input.type === "private") throw new Error("private attestor key is forbidden");
  if (typeof input === "string" && input.includes("PRIVATE KEY")) throw new Error("private attestor key is forbidden");
  if (Buffer.isBuffer(input)) {
    if (input.includes(Buffer.from("PRIVATE KEY"))) throw new Error("private attestor key is forbidden");
    return input.includes(Buffer.from("BEGIN PUBLIC KEY"))
      ? createPublicKey({ key: input, format: "pem", type: "spki" })
      : createPublicKey({ key: input, format: "der", type: "spki" });
  }
  const key = createPublicKey(input);
  if (key.type !== "public") throw new Error("attestor key must be public");
  return key;
}

export function publicKeyFingerprint(input) {
  const key = publicKeyFromInput(input);
  if (key.asymmetricKeyType !== "ed25519") throw new Error("attestor key must be Ed25519");
  return `SHA256:${createHash("sha256").update(key.export({ type: "spki", format: "der" })).digest("base64url")}`;
}

function publicKeyDerBase64url(input) {
  return publicKeyFromInput(input).export({ type: "spki", format: "der" }).toString("base64url");
}

/**
 * Normalize the two historical qualification trust environment shapes into
 * one strict, provider-keyed representation.  The returned value never
 * contains PEM text, private key material, or an unverified fingerprint.
 */
export function normalizeKmsProviderIdentityAttestorTrust(value, { expectedProviders } = {}) {
  if (value === undefined || value === null || value === "") return null;
  let parsed = value;
  if (typeof value === "string") {
    try { parsed = JSON.parse(value); } catch { throw new Error("KMS attestor trust is invalid"); }
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)
    || Object.getPrototypeOf(parsed) !== Object.prototype) throw new Error("KMS attestor trust is invalid");
  const providers = Object.keys(parsed).sort();
  const required = expectedProviders === undefined ? providers : [...expectedProviders].sort();
  if (required.length === 0 || required.some((provider) => !PROVIDERS.has(provider))
    || JSON.stringify(providers) !== JSON.stringify(required)) throw new Error("KMS attestor trust providers are invalid");
  exactObject(parsed, required, "KMS attestor trust");
  const result = Object.create(null);
  for (const provider of required) {
    const item = parsed[provider];
    if (item === null || typeof item !== "object" || Array.isArray(item)) throw new Error("KMS attestor trust entry is invalid");
    const keys = Object.keys(item).sort();
    let keyId;
    let fingerprint;
    let der;
    if (JSON.stringify(keys) === JSON.stringify([...TRUST_ENTRY_KEYS].sort())) {
      exactObject(item, TRUST_ENTRY_KEYS, "KMS attestor trust entry");
      if (typeof item.key_id !== "string" || !IDENTIFIER.test(item.key_id)
        || typeof item.public_key !== "string" || item.public_key.includes("PRIVATE KEY")
        || typeof item.fingerprint !== "string" || !FINGERPRINT.test(item.fingerprint)) throw new Error("KMS attestor trust entry is invalid");
      keyId = item.key_id;
      fingerprint = item.fingerprint;
      der = publicKeyDerBase64url(item.public_key);
    } else if (JSON.stringify(keys) === JSON.stringify([...TRUST_ENTRY_DER_KEYS].sort())) {
      exactObject(item, TRUST_ENTRY_DER_KEYS, "KMS attestor trust entry");
      if (typeof item.key_id !== "string" || !IDENTIFIER.test(item.key_id)
        || typeof item.public_key_der_base64url !== "string" || !B64URL.test(item.public_key_der_base64url)
        || typeof item.public_key_fingerprint !== "string" || !FINGERPRINT.test(item.public_key_fingerprint)) throw new Error("KMS attestor trust entry is invalid");
      keyId = item.key_id;
      fingerprint = item.public_key_fingerprint;
      der = item.public_key_der_base64url;
      if (Buffer.from(der, "base64url").toString("base64url") !== der) throw new Error("KMS attestor trust key encoding is invalid");
    } else {
      throw new Error("KMS attestor trust entry has missing or unknown fields");
    }
    if (publicKeyFingerprint(Buffer.from(der, "base64url")) !== fingerprint) throw new Error("KMS attestor trust fingerprint is invalid");
    result[provider] = Object.freeze({
      key_id: keyId,
      public_key_der_base64url: der,
      public_key_fingerprint: fingerprint
    });
  }
  return Object.freeze(result);
}

/**
 * Accept either trust environment variable for compatibility.  If both are
 * supplied they must describe exactly the same trusted keys.
 */
export function normalizeKmsProviderIdentityAttestorTrustInputs({ identityAttestationTrust, attestorPublicKeys, expectedProviders } = {}) {
  const values = [identityAttestationTrust, attestorPublicKeys].filter((value) => value !== undefined && value !== null && value !== "");
  if (values.length === 0) return null;
  const normalized = values.map((value) => normalizeKmsProviderIdentityAttestorTrust(value, { expectedProviders }));
  if (normalized.length === 2 && canonicalJson(normalized[0]) !== canonicalJson(normalized[1])) throw new Error("KMS attestor trust sources are mismatched");
  return normalized[0];
}

export function identityBindingDigest({ source_commit, source_tree, deployment_digest, artifact_sha256, run_id, job_id, provider, account_or_project, identity, identity_fingerprint, region, resource_ids } = {}) {
  const payload = { source_commit, source_tree, deployment_digest, artifact_sha256, run_id: String(run_id), job_id: String(job_id), provider, account_or_project, identity, identity_fingerprint, region, resource_ids: [...resource_ids].sort() };
  return createHash("sha256").update(canonicalJson(payload), "utf8").digest("hex");
}

export function attestationSigningData(value) {
  const payload = Object.fromEntries(PAYLOAD_KEYS.map((key) => [key, value[key]]));
  return Buffer.concat([Buffer.from(KMS_PROVIDER_IDENTITY_ATTESTATION_DOMAIN, "utf8"), Buffer.from(canonicalJson(payload), "utf8")]);
}

export function normalizeKmsProviderIdentityAttestation(value, { now = Date.now(), expectedNonce, expectedBindingDigest, enforceValidity = true } = {}) {
  exactObject(value, ATTESTATION_KEYS, "KMS provider identity attestation");
  if (value.schema_version !== KMS_PROVIDER_IDENTITY_ATTESTATION_SCHEMA_VERSION
    || value.kind !== KMS_PROVIDER_IDENTITY_ATTESTATION_KIND
    || !PROVIDERS.has(value.provider)
    || !IDENTIFIER.test(value.account_or_project) || !IDENTIFIER.test(value.identity) || !HEX64.test(value.identity_fingerprint) || !IDENTIFIER.test(value.region)
    || !Array.isArray(value.resource_ids) || value.resource_ids.length === 0
    || new Set(value.resource_ids).size !== value.resource_ids.length || value.resource_ids.some((id) => !IDENTIFIER.test(id))) {
    throw new Error("KMS provider identity attestation payload is invalid");
  }
  exactObject(value.challenge, Object.prototype.hasOwnProperty.call(value.challenge, "resource_ids") ? CHALLENGE_KEYS_WITH_RESOURCES : CHALLENGE_KEYS, "KMS provider identity attestation challenge");
  exactObject(value.provider_claims, CLAIM_KEYS, "KMS provider identity attestation claims");
  if (!B64URL.test(value.challenge.nonce) || !HEX64.test(value.challenge.binding_digest)
    || !TIMESTAMP.test(value.challenge.issued_at) || !TIMESTAMP.test(value.challenge.expires_at)
    || !CLAIM_KEYS.slice(0).every((key) => HEX64.test(value.provider_claims[key]))) throw new Error("KMS provider identity attestation challenge is invalid");
  if (expectedNonce !== undefined && value.challenge.nonce !== expectedNonce) throw new Error("KMS provider identity attestation nonce is mismatched");
  if (expectedBindingDigest !== undefined && value.challenge.binding_digest !== expectedBindingDigest) throw new Error("KMS provider identity attestation binding is mismatched");
  if (Object.prototype.hasOwnProperty.call(value.challenge, "resource_ids")
    && (!Array.isArray(value.challenge.resource_ids) || value.challenge.resource_ids.some((id) => typeof id !== "string" || !IDENTIFIER.test(id)))) throw new Error("KMS provider identity attestation resource binding is invalid");
  const issued = Date.parse(value.challenge.issued_at);
  const expires = Date.parse(value.challenge.expires_at);
  if (!Number.isFinite(issued) || !Number.isFinite(expires) || expires <= issued
    || (enforceValidity && (now < issued || now >= expires))) throw new Error("KMS provider identity attestation is outside its validity window");
  if (value.signature_algorithm !== "ed25519" || !IDENTIFIER.test(value.attestor_key_id)
    || !FINGERPRINT.test(value.attestor_public_key_fingerprint) || !B64URL.test(value.signature_base64url)) throw new Error("KMS provider identity attestation signature is invalid");
  return Object.freeze(structuredClone(value));
}

export function verifyKmsProviderIdentityAttestation(value, { trustedPublicKey, expectedNonce, expectedBindingDigest, now = Date.now() } = {}) {
  const normalized = normalizeKmsProviderIdentityAttestation(value, { now, expectedNonce, expectedBindingDigest });
  const key = publicKeyFromInput(trustedPublicKey);
  if (normalized.attestor_public_key_fingerprint !== publicKeyFingerprint(key)
    || !verify(null, attestationSigningData(normalized), key, Buffer.from(normalized.signature_base64url, "base64url"))) {
    throw new Error("KMS provider identity attestation signature is invalid");
  }
  return normalized;
}
