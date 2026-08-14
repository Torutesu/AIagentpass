import assert from "node:assert/strict";
import test from "node:test";

import {
  SIGNER_PURPOSE_REGISTRY,
  SIGNER_PURPOSE_REGISTRY_VERSION,
  SignerPurposeRegistryError,
  validateSignerPurposeBindings,
} from "../src/signer-purpose-registry.mjs";

function bindings({ legacy = false } = {}) {
  return Object.values(SIGNER_PURPOSE_REGISTRY).map((definition, index) => ({
    ...(legacy ? {} : {
      registry_version: definition.registry_version,
      protocol_version: definition.protocol_version,
      signing_version: definition.signing_version,
      hosted_status: definition.hosted_status,
    }),
    version: definition.version,
    name: definition.name,
    purpose: definition.purpose,
    algorithm: definition.managed_algorithm,
    domain: definition.domain,
    provider: "aws-kms",
    provider_resource_id: `arn:aws:kms:ap-northeast-1:123456789012:key/resource-${index}`,
    key_id: `key-${index}`,
    key_version: `version-${index}`,
    public_key_fingerprint: index.toString(16).padStart(64, "0"),
  }));
}

function rejects(code, mutate) {
  const values = bindings();
  mutate(values);
  assert.throws(() => validateSignerPurposeBindings(values), (error) => error instanceof SignerPurposeRegistryError && error.code === code);
}

test("freezes one closed registry with eight distinct purposes and domains", () => {
  const entries = Object.values(SIGNER_PURPOSE_REGISTRY);
  assert.equal(entries.length, 8);
  assert.equal(new Set(entries.map(({ purpose }) => purpose)).size, 8);
  assert.equal(new Set(entries.map(({ domain }) => domain)).size, 8);
  assert.ok(entries.every(({ version, registry_version, managed_algorithm, domain }) => version === SIGNER_PURPOSE_REGISTRY_VERSION && registry_version === SIGNER_PURPOSE_REGISTRY_VERSION && managed_algorithm === "ed25519" && domain.endsWith("\0")));
  assert.ok(Object.isFrozen(SIGNER_PURPOSE_REGISTRY));
  assert.ok(entries.every(Object.isFrozen));
  assert.equal(SIGNER_PURPOSE_REGISTRY.capability.hosted_status, "migration_required");
  assert.equal(SIGNER_PURPOSE_REGISTRY.refresh_hint.hosted_status, "managed_kms_integrated");
  assert.equal(SIGNER_PURPOSE_REGISTRY.possession_receipt.hosted_status, "managed_kms_integrated");
  assert.equal(SIGNER_PURPOSE_REGISTRY.agent_session_grant.hosted_status, "managed_kms_integrated");
  assert.equal(SIGNER_PURPOSE_REGISTRY.control_bundle.protocol_version, 2);
  assert.equal(SIGNER_PURPOSE_REGISTRY.control_bundle.signing_version, 2);
  assert.equal(SIGNER_PURPOSE_REGISTRY.qualification_manifest.protocol_version, 2);
  assert.deepEqual(SIGNER_PURPOSE_REGISTRY.possession_receipt.allowed_algorithms, ["ed25519", "p256-sha256"]);
});

test("accepts only one complete managed binding per frozen purpose", () => {
  const result = validateSignerPurposeBindings(bindings().reverse());
  assert.equal(result.version, 1);
  assert.equal(result.registry_version, 1);
  assert.deepEqual(Object.keys(result.bindings), Object.keys(result.bindings).sort());
  assert.ok(Object.isFrozen(result));
  assert.ok(Object.isFrozen(result.bindings.capability));
  assert.equal(result.bindings.control_bundle.protocol_version, 2);
  assert.equal(result.bindings.control_bundle.signing_version, 2);
});

test("accepts the legacy version-only shape and normalizes explicit version fields", () => {
  const result = validateSignerPurposeBindings(bindings({ legacy: true }));
  assert.equal(result.version, SIGNER_PURPOSE_REGISTRY_VERSION);
  assert.equal(result.registry_version, SIGNER_PURPOSE_REGISTRY_VERSION);
  assert.equal(result.bindings.possession_receipt.registry_version, SIGNER_PURPOSE_REGISTRY_VERSION);
  assert.equal(result.bindings.possession_receipt.protocol_version, 1);
  assert.equal(result.bindings.possession_receipt.signing_version, 1);
  assert.equal(result.bindings.possession_receipt.hosted_status, "managed_kms_integrated");
});

test("rejects missing, duplicate, and unknown purposes", () => {
  rejects("ERR_SIGNER_REGISTRY_INCOMPLETE", (values) => values.pop());
  rejects("ERR_SIGNER_REGISTRY_DUPLICATE", (values) => { values[1] = { ...values[0], key_id: "another", key_version: "another", provider_resource_id: "arn:aws:kms:ap-northeast-1:123456789012:key/another", public_key_fingerprint: "f".repeat(64) }; });
  rejects("ERR_SIGNER_REGISTRY_PURPOSE", (values) => { values[0] = { ...values[0], name: "unknown" }; });
});

test("rejects algorithm, domain, purpose, and every version substitution", () => {
  for (const [field, value] of [["algorithm", "p256"], ["domain", "AgentPass-Wrong-v1\0"], ["purpose", "agentpass.wrong"], ["version", 2], ["registry_version", 2], ["protocol_version", 2], ["signing_version", 2]]) {
    rejects("ERR_SIGNER_REGISTRY_SUBSTITUTION", (values) => { values[0] = { ...values[0], [field]: value }; });
  }
});

test("fails closed for incomplete, malformed, or substituted hosted state", () => {
  rejects("ERR_SIGNER_REGISTRY_INPUT", (values) => { const { signing_version: _signingVersion, ...incomplete } = values[0]; values[0] = incomplete; });
  rejects("ERR_SIGNER_REGISTRY_STATE", (values) => { values[0] = { ...values[0], hosted_status: "schema_only" }; });
  rejects("ERR_SIGNER_REGISTRY_STATE", (values) => { values[0] = { ...values[0], protocol_version: 0 }; });
  rejects("ERR_SIGNER_REGISTRY_STATE", (values) => { values[0] = { ...values[0], signing_version: "1" }; });
});

test("rejects shared key versions and file-backed hosted fallbacks", () => {
  rejects("ERR_SIGNER_REGISTRY_KEY_REUSE", (values) => { values[1] = { ...values[1], provider: values[0].provider, provider_resource_id: values[0].provider_resource_id, key_id: values[0].key_id, key_version: values[0].key_version }; });
  rejects("ERR_SIGNER_REGISTRY_KEY_REUSE", (values) => { values[1] = { ...values[1], public_key_fingerprint: values[0].public_key_fingerprint }; });
  for (const provider of ["file", "local", "pem", "aws-kms:file/key"]) {
    rejects("ERR_SIGNER_REGISTRY_PROVIDER", (values) => { values[0] = { ...values[0], provider }; });
  }
  rejects("ERR_SIGNER_REGISTRY_PROVIDER", (values) => { values[0] = { ...values[0], provider_resource_id: "file:/tmp/key.pem" }; });
});

test("rejects caller-controlled, symbol, and non-enumerable fields", () => {
  rejects("ERR_SIGNER_REGISTRY_INPUT", (values) => { values[0] = { ...values[0], requested_key_id: "attacker" }; });
  rejects("ERR_SIGNER_REGISTRY_INPUT", (values) => { values[0][Symbol("attacker")] = true; });
  rejects("ERR_SIGNER_REGISTRY_INPUT", (values) => { Object.defineProperty(values[0], "hidden", { value: true }); });
});
