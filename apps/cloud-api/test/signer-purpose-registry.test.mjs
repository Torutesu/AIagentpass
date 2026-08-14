import assert from "node:assert/strict";
import test from "node:test";

import {
  SIGNER_PURPOSE_REGISTRY,
  SIGNER_PURPOSE_REGISTRY_VERSION,
  SignerPurposeRegistryError,
  validateSignerPurposeBindings,
} from "../src/signer-purpose-registry.mjs";

function bindings() {
  return Object.values(SIGNER_PURPOSE_REGISTRY).map((definition, index) => ({
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
  assert.ok(entries.every(({ version, managed_algorithm, domain }) => version === SIGNER_PURPOSE_REGISTRY_VERSION && managed_algorithm === "ed25519" && domain.endsWith("\0")));
  assert.ok(Object.isFrozen(SIGNER_PURPOSE_REGISTRY));
  assert.ok(entries.every(Object.isFrozen));
  assert.equal(SIGNER_PURPOSE_REGISTRY.capability.hosted_status, "migration_required");
  assert.equal(SIGNER_PURPOSE_REGISTRY.refresh_hint.hosted_status, "file_backed_hosted");
  assert.equal(SIGNER_PURPOSE_REGISTRY.possession_receipt.hosted_status, "primitive_only");
  assert.equal(SIGNER_PURPOSE_REGISTRY.agent_session_grant.hosted_status, "managed_kms_integrated");
  assert.deepEqual(SIGNER_PURPOSE_REGISTRY.possession_receipt.allowed_algorithms, ["ed25519", "p256-sha256"]);
});

test("accepts only one complete managed binding per frozen purpose", () => {
  const result = validateSignerPurposeBindings(bindings().reverse());
  assert.equal(result.version, 1);
  assert.deepEqual(Object.keys(result.bindings), Object.keys(result.bindings).sort());
  assert.ok(Object.isFrozen(result));
  assert.ok(Object.isFrozen(result.bindings.capability));
});

test("rejects missing, duplicate, and unknown purposes", () => {
  rejects("ERR_SIGNER_REGISTRY_INCOMPLETE", (values) => values.pop());
  rejects("ERR_SIGNER_REGISTRY_DUPLICATE", (values) => { values[1] = { ...values[0], key_id: "another", key_version: "another", provider_resource_id: "arn:aws:kms:ap-northeast-1:123456789012:key/another", public_key_fingerprint: "f".repeat(64) }; });
  rejects("ERR_SIGNER_REGISTRY_PURPOSE", (values) => { values[0] = { ...values[0], name: "unknown" }; });
});

test("rejects algorithm, domain, purpose, and version substitution", () => {
  for (const [field, value] of [["algorithm", "p256"], ["domain", "AgentPass-Wrong-v1\0"], ["purpose", "agentpass.wrong"], ["version", 2]]) {
    rejects("ERR_SIGNER_REGISTRY_SUBSTITUTION", (values) => { values[0] = { ...values[0], [field]: value }; });
  }
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
