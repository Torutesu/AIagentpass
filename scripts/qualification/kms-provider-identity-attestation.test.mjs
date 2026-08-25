import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import test from "node:test";

import { canonicalJson } from "../../packages/protocol/src/index.mjs";
import {
  KMS_PROVIDER_IDENTITY_ATTESTATION_KIND,
  attestationSigningData,
  identityBindingDigest,
  normalizeKmsProviderIdentityAttestorTrust,
  normalizeKmsProviderIdentityAttestorTrustInputs,
  normalizeKmsProviderIdentityAttestation,
  publicKeyFingerprint,
  verifyKmsProviderIdentityAttestation
} from "./kms-provider-identity-attestation.mjs";

const { privateKey, publicKey } = generateKeyPairSync("ed25519");
const NOW = Date.parse("2026-08-21T00:00:00.000Z");
const binding = {
  source_commit: "a".repeat(40), source_tree: "b".repeat(40), deployment_digest: "c".repeat(64),
  artifact_sha256: "d".repeat(64), run_id: "42", job_id: "1001", provider: "aws-kms",
  account_or_project: "123456789012", identity: "arn:aws:iam::123456789012:role/agentpass",
  identity_fingerprint: "e".repeat(64), region: "us-east-1", resource_ids: ["arn:aws:kms:us-east-1:123456789012:key/key-a"]
};
const nonce = "n".repeat(32);

function unsigned() {
  return {
    schema_version: 1,
    kind: KMS_PROVIDER_IDENTITY_ATTESTATION_KIND,
    provider: binding.provider,
    account_or_project: binding.account_or_project,
    identity: binding.identity,
    identity_fingerprint: binding.identity_fingerprint,
    region: binding.region,
    resource_ids: binding.resource_ids,
    challenge: {
      nonce,
      binding_digest: identityBindingDigest(binding),
      issued_at: "2026-08-21T00:00:00.000Z",
      expires_at: "2026-08-21T00:05:00.000Z"
    },
    provider_claims: {
      identity_document_digest: "1".repeat(64), request_digest: "2".repeat(64), response_digest: "3".repeat(64)
    },
    signature_algorithm: "ed25519",
    attestor_key_id: "aws-identity-attestor-v1",
    attestor_public_key_fingerprint: publicKeyFingerprint(publicKey),
    signature_base64url: "placeholder"
  };
}

function signed() {
  const value = unsigned();
  value.signature_base64url = sign(null, attestationSigningData(value), privateKey).toString("base64url");
  return value;
}

test("verifies a provider identity attestation bound to nonce and run/resource digest", () => {
  const value = signed();
  const result = verifyKmsProviderIdentityAttestation(value, {
    trustedPublicKey: publicKey,
    expectedNonce: nonce,
    expectedBindingDigest: identityBindingDigest(binding),
    now: NOW
  });
  assert.equal(result.kind, KMS_PROVIDER_IDENTITY_ATTESTATION_KIND);
  assert.equal(canonicalJson(result), canonicalJson(value));
});

test("rejects forged identity fields, key substitution, nonce replay, expiry, and unknown fields", () => {
  const base = signed();
  assert.throws(() => verifyKmsProviderIdentityAttestation({ ...base, account_or_project: "999999999999" }, { trustedPublicKey: publicKey, expectedNonce: nonce, expectedBindingDigest: identityBindingDigest(binding), now: NOW }));
  assert.throws(() => verifyKmsProviderIdentityAttestation(base, { trustedPublicKey: generateKeyPairSync("ed25519").publicKey, expectedNonce: nonce, expectedBindingDigest: identityBindingDigest(binding), now: NOW }));
  assert.throws(() => verifyKmsProviderIdentityAttestation(base, { trustedPublicKey: publicKey, expectedNonce: "x".repeat(32), expectedBindingDigest: identityBindingDigest(binding), now: NOW }));
  assert.throws(() => verifyKmsProviderIdentityAttestation(base, { trustedPublicKey: publicKey, expectedNonce: nonce, expectedBindingDigest: "e".repeat(64), now: NOW }));
  assert.throws(() => verifyKmsProviderIdentityAttestation({ ...base, challenge: { ...base.challenge, expires_at: "2026-08-20T23:59:00.000Z" } }, { trustedPublicKey: publicKey, expectedNonce: nonce, expectedBindingDigest: identityBindingDigest(binding), now: NOW }));
  assert.throws(() => normalizeKmsProviderIdentityAttestation({ ...base, extra: true }, { now: NOW }));
});

test("rejects private attestor keys", () => {
  assert.throws(() => publicKeyFingerprint(privateKey));
});

test("normalizes legacy PEM and runner DER trust schemas to the same strict key", () => {
  const legacy = { "aws-kms": {
    fingerprint: publicKeyFingerprint(publicKey),
    key_id: "aws-attestor-v1",
    public_key: publicKey.export({ type: "spki", format: "pem" }).toString()
  } };
  const der = { "aws-kms": {
    key_id: "aws-attestor-v1",
    public_key_der_base64url: publicKey.export({ type: "spki", format: "der" }).toString("base64url"),
    public_key_fingerprint: publicKeyFingerprint(publicKey)
  } };
  const expectedProviders = new Set(["aws-kms"]);
  assert.deepEqual(
    normalizeKmsProviderIdentityAttestorTrust(legacy, { expectedProviders }),
    normalizeKmsProviderIdentityAttestorTrust(der, { expectedProviders })
  );
  assert.deepEqual(
    normalizeKmsProviderIdentityAttestorTrustInputs({ identityAttestationTrust: JSON.stringify(legacy), attestorPublicKeys: JSON.stringify(der), expectedProviders }),
    normalizeKmsProviderIdentityAttestorTrust(legacy, { expectedProviders })
  );
});

test("rejects trust schema drift, unknown providers, and expired live attestations while allowing a verified snapshot", () => {
  const legacy = { "aws-kms": {
    fingerprint: publicKeyFingerprint(publicKey),
    key_id: "aws-attestor-v1",
    public_key: publicKey.export({ type: "spki", format: "pem" }).toString()
  } };
  const mismatched = structuredClone(legacy);
  mismatched["aws-kms"].key_id = "different-attestor-v1";
  assert.throws(() => normalizeKmsProviderIdentityAttestorTrustInputs({
    identityAttestationTrust: legacy,
    attestorPublicKeys: mismatched,
    expectedProviders: new Set(["aws-kms"])
  }));
  assert.throws(() => normalizeKmsProviderIdentityAttestorTrust(legacy, { expectedProviders: new Set(["gcp-cloud-kms"]) }));

  const value = signed();
  assert.throws(() => normalizeKmsProviderIdentityAttestation(value, { now: NOW + 301_000 }));
  assert.equal(normalizeKmsProviderIdentityAttestation(value, { now: NOW + 301_000, enforceValidity: false }).challenge.expires_at, value.challenge.expires_at);
});
