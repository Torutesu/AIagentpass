import assert from "node:assert/strict";
import test from "node:test";

import {
  MANAGED_SIGNER_DEPLOYMENT_ALGORITHM,
  MANAGED_SIGNER_DEPLOYMENT_CONFIG_VERSION,
  MANAGED_SIGNER_DEPLOYMENT_PROTOCOL_VERSIONS,
  MANAGED_SIGNER_DEPLOYMENT_PURPOSES,
  MANAGED_SIGNER_DEPLOYMENT_SIGNER_FIELDS,
  MANAGED_SIGNER_DEPLOYMENT_TOP_LEVEL_FIELDS,
  parseManagedSignerDeploymentConfig,
  validateManagedSignerDeploymentConfig,
} from "../src/managed-signer-deployment-config.mjs";
import { SIGNER_PURPOSE_REGISTRY, SIGNER_PURPOSE_REGISTRY_VERSION } from "../src/signer-purpose-registry.mjs";

const AWS_ACCOUNT = "123456789012";
const AWS_PROJECT = "agentpass-production";
const AWS_REGION = "us-west-2";
const AWS_KEYS = [
  "11111111-1111-4111-8111-111111111111",
  "22222222-2222-4222-8222-222222222222",
  "33333333-3333-4333-8333-333333333333",
  "44444444-4444-4444-8444-444444444444",
  "55555555-5555-4555-8555-555555555555",
  "66666666-6666-4666-8666-666666666666",
  "77777777-7777-4777-8777-777777777777",
  "88888888-8888-4888-8888-888888888888",
];

function fingerprint(index) {
  return String(index + 1).repeat(64).slice(0, 64);
}

function awsResource(key) {
  return `arn:aws:kms:${AWS_REGION}:${AWS_ACCOUNT}:key/${key}`;
}

function validSigner(purpose, index) {
  const definition = Object.values(SIGNER_PURPOSE_REGISTRY).find((entry) => entry.purpose === purpose);
  return {
    purpose,
    provider: "aws-kms",
    account_id: AWS_ACCOUNT,
    project_id: AWS_PROJECT,
    region: AWS_REGION,
    key_resource: awsResource(AWS_KEYS[index]),
    key_version: String(index + 1),
    public_key_fingerprint: fingerprint(index),
    algorithm: MANAGED_SIGNER_DEPLOYMENT_ALGORITHM,
    registry_version: SIGNER_PURPOSE_REGISTRY_VERSION,
    protocol_version: definition.protocol_version,
    signing_version: definition.signing_version,
    lifecycle_version: 1,
  };
}

function validConfig() {
  return {
    schema_version: MANAGED_SIGNER_DEPLOYMENT_CONFIG_VERSION,
    registry_version: SIGNER_PURPOSE_REGISTRY_VERSION,
    signers: MANAGED_SIGNER_DEPLOYMENT_PURPOSES.map(validSigner),
  };
}

function rejects(mutator, code) {
  const value = validConfig();
  mutator(value);
  assert.throws(() => validateManagedSignerDeploymentConfig(value), { code });
}

test("derives exactly eight purposes and protocol versions from the frozen registry", () => {
  assert.deepEqual(MANAGED_SIGNER_DEPLOYMENT_PURPOSES, Object.values(SIGNER_PURPOSE_REGISTRY).map(({ purpose }) => purpose).sort());
  assert.deepEqual(MANAGED_SIGNER_DEPLOYMENT_PROTOCOL_VERSIONS, Object.fromEntries(
    Object.values(SIGNER_PURPOSE_REGISTRY).map(({ purpose, protocol_version }) => [purpose, protocol_version]),
  ));
  assert.equal(MANAGED_SIGNER_DEPLOYMENT_PURPOSES.length, 8);
  assert.equal(new Set(MANAGED_SIGNER_DEPLOYMENT_PURPOSES).size, 8);
});

test("accepts one exact entry for every purpose and returns a sorted deep-frozen public config", () => {
  const input = validConfig();
  input.signers.reverse();
  const result = validateManagedSignerDeploymentConfig(input);

  assert.deepEqual(result.signers.map(({ purpose }) => purpose), [...MANAGED_SIGNER_DEPLOYMENT_PURPOSES].sort());
  assert.equal(Object.isFrozen(result), true);
  assert.equal(Object.isFrozen(result.signers), true);
  assert.ok(result.signers.every((entry) => Object.isFrozen(entry)));
  assert.deepEqual(Object.keys(result).sort(), [...MANAGED_SIGNER_DEPLOYMENT_TOP_LEVEL_FIELDS].sort());
  assert.deepEqual(Object.keys(result.signers[0]).sort(), [...MANAGED_SIGNER_DEPLOYMENT_SIGNER_FIELDS].sort());
  assert.equal(JSON.stringify(result).includes("PRIVATE"), false);
  assert.equal(JSON.stringify(result).includes("private"), false);
  const parsed = parseManagedSignerDeploymentConfig(validConfig());
  input.signers[0].project_id = "mutated-after-validation";
  assert.equal(result.signers[0].project_id, AWS_PROJECT);
  assert.deepEqual(parsed, result);
});

test("normalizes registry-owned version fields and rejects substitutions", () => {
  rejects((value) => { value.signers[0].protocol_version += 1; }, "INVALID_PROTOCOL_VERSION");
  rejects((value) => { value.signers[0].signing_version += 1; }, "INVALID_SIGNING_VERSION");
  rejects((value) => { value.signers[0].registry_version += 1; }, "INVALID_REGISTRY_VERSION");
  rejects((value) => { value.signers[0].algorithm = "p256"; }, "INVALID_ALGORITHM");
  rejects((value) => { value.signers[0].lifecycle_version = 0; }, "INVALID_LIFECYCLE_VERSION");
});

test("rejects missing, extra, duplicate, and unknown purposes", () => {
  const missing = validConfig();
  missing.signers.pop();
  assert.throws(() => validateManagedSignerDeploymentConfig(missing), { code: "INCOMPLETE_PURPOSES" });

  const extra = validConfig();
  extra.signers.push({ ...extra.signers[0], purpose: "agentpass.unknown" });
  assert.throws(() => validateManagedSignerDeploymentConfig(extra), { code: "INCOMPLETE_PURPOSES" });

  const duplicate = validConfig();
  duplicate.signers[1].purpose = duplicate.signers[0].purpose;
  assert.throws(() => validateManagedSignerDeploymentConfig(duplicate), { code: "DUPLICATE_PURPOSE" });

  const unknown = validConfig();
  unknown.signers[0].purpose = "agentpass.unknown";
  assert.throws(() => validateManagedSignerDeploymentConfig(unknown), { code: "UNKNOWN_PURPOSE" });
});

test("rejects shared key resources and shared public-key fingerprints", () => {
  rejects((value) => { value.signers[1].key_resource = value.signers[0].key_resource; }, "SHARED_KEY_RESOURCE");
  rejects((value) => { value.signers[1].public_key_fingerprint = value.signers[0].public_key_fingerprint; }, "SHARED_PUBLIC_KEY");
});

test("rejects unknown, file, local, and private-key fields at every closed boundary", () => {
  rejects((value) => { value.extra = true; }, "UNKNOWN_FIELD");
  rejects((value) => { value.signers[0].extra = true; }, "UNKNOWN_FIELD");
  rejects((value) => { value.signers[0].private_key = "-----BEGIN PRIVATE KEY-----"; }, "PRIVATE_MATERIAL");
  rejects((value) => { value.signers[0].local_path = "/tmp/key"; }, "PRIVATE_MATERIAL");
  rejects((value) => { value.signers[0].file = "key.pem"; }, "PRIVATE_MATERIAL");
  rejects((value) => { value.signers.private_key = "private"; }, "PRIVATE_MATERIAL");
});

test("requires immutable AWS key ARNs and versioned GCP CryptoKeyVersion resources", () => {
  rejects((value) => {
    value.signers[0].key_resource = `arn:aws:kms:${AWS_REGION}:${AWS_ACCOUNT}:alias/active`;
  }, "INVALID_KEY_RESOURCE");
  rejects((value) => {
    value.signers[0].key_resource = `arn:aws:kms:${AWS_REGION}:999999999999:key/${AWS_KEYS[0]}`;
  }, "INVALID_KEY_RESOURCE");

  const gcp = validConfig();
  const entry = gcp.signers[0];
  entry.provider = "gcp-cloud-kms";
  entry.account_id = "service-account-01";
  entry.project_id = "agentpass-prod";
  entry.region = "us-central1";
  entry.key_version = "7";
  entry.key_resource = "projects/agentpass-prod/locations/us-central1/keyRings/signing/cryptoKeys/capability/cryptoKeyVersions/7";
  assert.doesNotThrow(() => validateManagedSignerDeploymentConfig(gcp));

  const unversioned = validConfig();
  unversioned.signers[0].provider = "gcp-cloud-kms";
  unversioned.signers[0].account_id = "service-account-01";
  unversioned.signers[0].project_id = "agentpass-prod";
  unversioned.signers[0].region = "us-central1";
  unversioned.signers[0].key_resource = "projects/agentpass-prod/locations/us-central1/keyRings/signing/cryptoKeys/capability";
  assert.throws(() => validateManagedSignerDeploymentConfig(unversioned), { code: "INVALID_KEY_RESOURCE" });
});

test("rejects unsafe strings and cross-field provider/resource substitutions", () => {
  rejects((value) => { value.signers[0].project_id = "agentpass\nproduction"; }, "INVALID_PROJECT");
  rejects((value) => { value.signers[0].region = "../us-west-2"; }, "INVALID_REGION");
  rejects((value) => { value.signers[0].key_resource = "file:///tmp/key"; }, "INVALID_KEY_RESOURCE");
  rejects((value) => { value.signers[0].account_id = "999999999999"; }, "INVALID_KEY_RESOURCE");
  rejects((value) => { value.signers[0].key_version = "latest"; }, "INVALID_KEY_VERSION");
  rejects((value) => { value.signers[0].public_key_fingerprint = "A".repeat(64); }, "INVALID_PUBLIC_KEY_FINGERPRINT");
});
