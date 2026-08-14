import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import {
  createHostedKmsProviders,
  KMS_PROVIDER_RUNTIME_ERROR_CODES,
  parseKmsProviderRuntimeConfig
} from "../src/kms-provider-runtime.mjs";
import {
  POSSESSION_RECEIPT_PURPOSE,
  POSSESSION_RECEIPT_VERSION,
  possessionReceiptSigningData
} from "../src/possession-receipt-signer.mjs";
import { createManagedSignerKeyLifecycle } from "../src/managed-signer-key-lifecycle.mjs";
import { SIGNER_PURPOSE_REGISTRY } from "../src/signer-purpose-registry.mjs";

const AGENT_PURPOSE = "agentpass.agent-session-grant";
const MANIFEST_PURPOSE = "agentpass.qualification-grant-batch-manifest";
const awsAgentResource = "arn:aws:kms:us-east-1:123456789012:key/agent-session";
const awsManifestResource = "arn:aws:kms:us-east-1:123456789012:key/qualification-manifest";
const awsPossessionResource = "arn:aws:kms:us-east-1:123456789012:key/possession-receipt";
const awsRefreshResource = "arn:aws:kms:us-east-1:123456789012:key/refresh-hint";
const gcpAgentResource = "projects/demo/locations/global/keyRings/agentpass/cryptoKeys/agent-session/cryptoKeyVersions/1";
const gcpManifestResource = "projects/demo/locations/global/keyRings/agentpass/cryptoKeys/qualification-manifest/cryptoKeyVersions/1";
const gcpPossessionResource = "projects/demo/locations/global/keyRings/agentpass/cryptoKeys/possession-receipt/cryptoKeyVersions/1";
const gcpRefreshResource = "projects/demo/locations/global/keyRings/agentpass/cryptoKeys/refresh-hint/cryptoKeyVersions/1";
const EXTENDED_FIXTURE_DEFINITIONS = [
  { name: "capability", envName: "CAPABILITY", resource: "arn:aws:kms:us-east-1:123456789012:key/capability", gcpResource: "projects/demo/locations/global/keyRings/agentpass/cryptoKeys/capability/cryptoKeyVersions/1", purpose: "agentpass.capability", version: 1 },
  { name: "controlBundle", envName: "CONTROL_BUNDLE", resource: "arn:aws:kms:us-east-1:123456789012:key/control-bundle", gcpResource: "projects/demo/locations/global/keyRings/agentpass/cryptoKeys/control-bundle/cryptoKeyVersions/1", purpose: "agentpass.control-bundle", version: 2 },
  { name: "auditAnchor", envName: "AUDIT_ANCHOR", resource: "arn:aws:kms:us-east-1:123456789012:key/audit-anchor", gcpResource: "projects/demo/locations/global/keyRings/agentpass/cryptoKeys/audit-anchor/cryptoKeyVersions/1", purpose: "agentpass.audit-anchor", version: 1 },
  { name: "promotionEvidence", envName: "PROMOTION_EVIDENCE", resource: "arn:aws:kms:us-east-1:123456789012:key/promotion-evidence", gcpResource: "projects/demo/locations/global/keyRings/agentpass/cryptoKeys/promotion-evidence/cryptoKeyVersions/1", purpose: "agentpass.promotion-evidence", version: 2 }
];

function baseEnv({ provider = "aws", agentResource = awsAgentResource, manifestResource = awsManifestResource, possessionResource } = {}) {
  const agent = crypto.generateKeyPairSync("ed25519");
  const manifest = crypto.generateKeyPairSync("ed25519");
  const possession = crypto.generateKeyPairSync("ed25519");
  const refresh = crypto.generateKeyPairSync("ed25519");
  const resolvedPossessionResource = possessionResource ?? (provider === "gcp" ? gcpPossessionResource : awsPossessionResource);
  const env = {
    AGENTPASS_CLOUD_PROFILE: "hosted",
    AGENTPASS_CLOUD_AGENT_SESSION_KEY_ID: "agent-session-2026-08",
    AGENTPASS_CLOUD_AGENT_SESSION_PUBLIC_KEY: agent.publicKey.export({ type: "spki", format: "pem" }).toString(),
    AGENTPASS_CLOUD_QUALIFICATION_MANIFEST_KEY_ID: "qualification-manifest-2026-08",
    AGENTPASS_CLOUD_QUALIFICATION_MANIFEST_PUBLIC_KEY: manifest.publicKey.export({ type: "spki", format: "pem" }).toString(),
    AGENTPASS_CLOUD_POSSESSION_RECEIPT_KEY_ID: "possession-receipt-2026-08",
    AGENTPASS_CLOUD_POSSESSION_RECEIPT_PUBLIC_KEY: possession.publicKey.export({ type: "spki", format: "pem" }).toString(),
    AGENTPASS_CLOUD_POSSESSION_RECEIPT_TIMEOUT_MS: "5000",
    AGENTPASS_CLOUD_REFRESH_KEY_ID: "refresh-hint-2026-08",
    AGENTPASS_CLOUD_REFRESH_PUBLIC_KEY: refresh.publicKey.export({ type: "spki", format: "pem" }).toString(),
    AGENTPASS_KMS_PROVIDER: provider,
    AGENTPASS_KMS_AGENT_SESSION_KEY_RESOURCE: agentResource,
    AGENTPASS_KMS_QUALIFICATION_MANIFEST_KEY_RESOURCE: manifestResource,
    AGENTPASS_KMS_POSSESSION_RECEIPT_KEY_RESOURCE: resolvedPossessionResource,
    AGENTPASS_KMS_REFRESH_HINT_KEY_RESOURCE: provider === "gcp" ? gcpRefreshResource : awsRefreshResource,
    __keys: { agent, manifest, possession, refresh }
  };
  for (const definition of EXTENDED_FIXTURE_DEFINITIONS) {
    const pair = crypto.generateKeyPairSync("ed25519");
    env[`AGENTPASS_CLOUD_${definition.envName}_KEY_ID`] = `${definition.name}-2026-08`;
    env[`AGENTPASS_CLOUD_${definition.envName}_PUBLIC_KEY`] = pair.publicKey.export({ type: "spki", format: "pem" }).toString();
    env[`AGENTPASS_CLOUD_${definition.envName}_TIMEOUT_MS`] = "5000";
    env[`AGENTPASS_KMS_${definition.envName}_KEY_RESOURCE`] = provider === "gcp" ? definition.gcpResource : definition.resource;
    env.__keys[definition.name] = pair;
  }
  return env;
}

function publicDer(keyPair) { return keyPair.publicKey.export({ type: "spki", format: "der" }); }

function allPurposeEnv() {
  return baseEnv();
}

function possessionStatement() {
  return {
    version: 1,
    enrollment_id: "11111111-1111-4111-8111-111111111111",
    organization_id: "22222222-2222-4222-8222-222222222222",
    device_id: "33333333-3333-4333-8333-333333333333",
    candidate_id: "candidate-2026-08",
    artifact_sha256: "a".repeat(64),
    source_commit: "b".repeat(40),
    team_id: "ABCDE12345",
    device_key_fingerprint: `SHA256:${"C".repeat(43)}`,
    device_key_epoch: 1,
    challenge_nonce_digest: "d".repeat(64),
    issued_at: "2026-08-14T00:00:00.000Z"
  };
}

test("hosted KMS config is exactly eight-purpose, explicit, and keeps logical IDs separate from resources", () => {
  const env = baseEnv();
  const config = parseKmsProviderRuntimeConfig(env);
  assert.equal(config.provider, "aws");
  assert.equal(config.allPurposes, true);
  assert.equal(config.purposes.length, 8);
  assert.equal(config.agentSession.keyId, "agent-session-2026-08");
  assert.equal(config.agentSessionResource, awsAgentResource);
  assert.equal(config.possessionReceipt.keyId, "possession-receipt-2026-08");
  assert.equal(config.possessionReceiptResource, awsPossessionResource);
  assert.equal(config.capabilityResource, EXTENDED_FIXTURE_DEFINITIONS[0].resource);
  assert.equal(config.promotionEvidenceResource, EXTENDED_FIXTURE_DEFINITIONS[3].resource);
  assert.notEqual(config.agentSession.keyId, config.agentSessionResource);

  for (const value of [
    { AGENTPASS_KMS_PROVIDER: undefined },
    { AGENTPASS_KMS_AGENT_SESSION_KEY_RESOURCE: undefined },
    { AGENTPASS_KMS_QUALIFICATION_MANIFEST_KEY_RESOURCE: undefined },
    { AGENTPASS_KMS_POSSESSION_RECEIPT_KEY_RESOURCE: undefined },
    { AGENTPASS_KMS_REFRESH_HINT_KEY_RESOURCE: undefined },
    { AGENTPASS_KMS_PROVIDER: "local" },
    { AGENTPASS_KMS_AGENT_SESSION_KEY_RESOURCE: awsManifestResource },
    { AGENTPASS_KMS_POSSESSION_RECEIPT_KEY_RESOURCE: awsManifestResource },
    { AGENTPASS_KMS_REFRESH_HINT_KEY_RESOURCE: awsManifestResource },
    { AGENTPASS_CLOUD_POSSESSION_RECEIPT_KEY_ID: "agent-session-2026-08" },
    { AGENTPASS_CLOUD_POSSESSION_RECEIPT_PUBLIC_KEY: env.AGENTPASS_CLOUD_AGENT_SESSION_PUBLIC_KEY },
    { AGENTPASS_CLOUD_REFRESH_KEY_ID: "agent-session-2026-08" },
    { AGENTPASS_CLOUD_REFRESH_PUBLIC_KEY: env.AGENTPASS_CLOUD_AGENT_SESSION_PUBLIC_KEY },
    { AGENTPASS_CLOUD_POSSESSION_RECEIPT_TIMEOUT_MS: "30001" },
    { AGENTPASS_KMS_UNKNOWN_SETTING: "unexpected" },
    { AGENTPASS_KMS_PRIVATE_KEY_PATH: "/tmp/key" },
    { AGENTPASS_CLOUD_PROFILE: "evaluation" }
  ]) {
    const invalid = { ...env, ...value };
    assert.throws(() => parseKmsProviderRuntimeConfig(invalid), (error) => error.code === KMS_PROVIDER_RUNTIME_ERROR_CODES.CONFIG);
  }
});

test("hosted KMS config binds every signer-purpose-registry purpose with unique pinned public keys", () => {
  const env = allPurposeEnv();
  const config = parseKmsProviderRuntimeConfig(env);
  assert.equal(config.allPurposes, true);
  assert.equal(config.purposes.length, 8);
  assert.deepEqual(new Set(config.purposes.map(({ purpose }) => purpose)), new Set(Object.values(SIGNER_PURPOSE_REGISTRY).map(({ purpose }) => purpose)));
  assert.equal(Object.isFrozen(config), true);
  assert.equal(Object.isFrozen(config.purposes), true);
  assert.equal(new Set(config.purposes.map(({ resourceId }) => resourceId)).size, 8);
  assert.equal(new Set(config.purposes.map(({ publicKeyFingerprint }) => publicKeyFingerprint)).size, 8);
  for (const definition of EXTENDED_FIXTURE_DEFINITIONS) {
    const signer = config[definition.name];
    assert.equal(signer.keyId, `${definition.name}-2026-08`);
    assert.equal(config.purposes.find(({ name }) => name === definition.name).version, definition.version);
  }
});

test("hosted KMS config rejects legacy four-purpose and partial purpose configuration", () => {
  for (const definition of EXTENDED_FIXTURE_DEFINITIONS) {
    for (const suffix of ["KEY_RESOURCE", "KEY_ID", "PUBLIC_KEY"]) {
      const env = allPurposeEnv();
      delete env[`AGENTPASS_${suffix === "KEY_RESOURCE" ? "KMS" : "CLOUD"}_${definition.envName}_${suffix}`];
      assert.throws(() => parseKmsProviderRuntimeConfig(env), (error) => error.code === KMS_PROVIDER_RUNTIME_ERROR_CODES.CONFIG);
    }
  }
  const timeoutEnv = allPurposeEnv();
  timeoutEnv.AGENTPASS_CLOUD_CAPABILITY_TIMEOUT_MS = "0";
  assert.throws(() => parseKmsProviderRuntimeConfig(timeoutEnv), (error) => error.code === KMS_PROVIDER_RUNTIME_ERROR_CODES.CONFIG);
});

test("hosted KMS creation rejects a missing new-purpose mapping before loading the SDK", async () => {
  for (const definition of EXTENDED_FIXTURE_DEFINITIONS) {
    const env = allPurposeEnv();
    delete env[`AGENTPASS_KMS_${definition.envName}_KEY_RESOURCE`];
    let loaded = false;
    await assert.rejects(
      createHostedKmsProviders({
        env,
        sdkLoader: async () => { loaded = true; return {}; }
      }),
      (error) => error.code === KMS_PROVIDER_RUNTIME_ERROR_CODES.CONFIG
    );
    assert.equal(loaded, false);
  }
});

test("hosted KMS config rejects shared resources, shared pins, private key material, and unversioned keys", () => {
  const sharedResource = allPurposeEnv();
  sharedResource.AGENTPASS_KMS_CAPABILITY_KEY_RESOURCE = awsAgentResource;
  assert.throws(() => parseKmsProviderRuntimeConfig(sharedResource), (error) => error.code === KMS_PROVIDER_RUNTIME_ERROR_CODES.CONFIG);

  const aliasedResource = allPurposeEnv();
  aliasedResource.AGENTPASS_KMS_CAPABILITY_KEY_RESOURCE = "arn:aws:kms:us-east-1:123456789012:alias/agentpass-capability";
  assert.throws(() => parseKmsProviderRuntimeConfig(aliasedResource), (error) => error.code === KMS_PROVIDER_RUNTIME_ERROR_CODES.CONFIG);

  const sharedKeyId = allPurposeEnv();
  sharedKeyId.AGENTPASS_CLOUD_CAPABILITY_KEY_ID = sharedKeyId.AGENTPASS_CLOUD_AGENT_SESSION_KEY_ID;
  assert.throws(() => parseKmsProviderRuntimeConfig(sharedKeyId), (error) => error.code === KMS_PROVIDER_RUNTIME_ERROR_CODES.CONFIG);

  const sharedPublicKey = allPurposeEnv();
  sharedPublicKey.AGENTPASS_CLOUD_CAPABILITY_PUBLIC_KEY = sharedPublicKey.AGENTPASS_CLOUD_AGENT_SESSION_PUBLIC_KEY;
  assert.throws(() => parseKmsProviderRuntimeConfig(sharedPublicKey), (error) => error.code === KMS_PROVIDER_RUNTIME_ERROR_CODES.CONFIG);

  const privateKey = allPurposeEnv();
  privateKey.AGENTPASS_CLOUD_CAPABILITY_PUBLIC_KEY = privateKey.__keys.capability.privateKey.export({ type: "pkcs8", format: "pem" }).toString();
  assert.throws(() => parseKmsProviderRuntimeConfig(privateKey), (error) => error.code === KMS_PROVIDER_RUNTIME_ERROR_CODES.CONFIG);

  const unversionedGcpResource = baseEnv({ provider: "gcp", agentResource: gcpAgentResource, manifestResource: gcpManifestResource });
  unversionedGcpResource.AGENTPASS_KMS_CAPABILITY_KEY_RESOURCE = "projects/demo/locations/global/keyRings/agentpass/cryptoKeys/capability";
  assert.throws(() => parseKmsProviderRuntimeConfig(unversionedGcpResource), (error) => error.code === KMS_PROVIDER_RUNTIME_ERROR_CODES.CONFIG);
});

test("AWS composition constructs and purpose-binds all eight hosted KMS providers", async () => {
  const env = allPurposeEnv();
  const observed = [];
  const resourceToKey = new Map([
    [awsAgentResource, env.__keys.agent],
    [awsManifestResource, env.__keys.manifest],
    [awsPossessionResource, env.__keys.possession],
    [awsRefreshResource, env.__keys.refresh],
    ...EXTENDED_FIXTURE_DEFINITIONS.map(({ name, resource }) => [resource, env.__keys[name]])
  ]);
  class GetPublicKeyCommand { constructor(input) { this.input = input; this.kind = "get"; } }
  class SignCommand { constructor(input) { this.input = input; this.kind = "sign"; } }
  class KMSClient {
    destroy() {}
    async send(command) {
      observed.push(command);
      const pair = resourceToKey.get(command.input.KeyId);
      assert.ok(pair);
      if (command.kind === "get") return { KeyId: command.input.KeyId, KeyUsage: "SIGN_VERIFY", KeySpec: "ECC_NIST_EDWARDS25519", SigningAlgorithms: ["ED25519_SHA_512"], PublicKey: publicDer(pair) };
      return { KeyId: command.input.KeyId, SigningAlgorithm: "ED25519_SHA_512", Signature: crypto.sign(null, command.input.Message, pair.privateKey) };
    }
  }
  const providers = await createHostedKmsProviders({ env, sdkLoader: async () => ({ KMSClient, GetPublicKeyCommand, SignCommand }) });
  const expectedProviders = [
    "agentSessionSignerProvider", "qualificationManifestSignerProvider", "possessionReceiptSignerProvider", "refreshHintSignerProvider",
    "capabilitySignerProvider", "controlBundleSignerProvider", "auditAnchorSignerProvider", "promotionEvidenceSignerProvider"
  ];
  assert.deepEqual(expectedProviders.every((name) => providers[name] && typeof providers[name].sign === "function"), true);
  for (const definition of [
    { provider: "agentSessionSignerProvider", name: "agent", purpose: AGENT_PURPOSE, keyId: "agent-session-2026-08", version: 1 },
    { provider: "qualificationManifestSignerProvider", name: "manifest", purpose: MANIFEST_PURPOSE, keyId: "qualification-manifest-2026-08", version: 2 },
    { provider: "possessionReceiptSignerProvider", name: "possession", purpose: POSSESSION_RECEIPT_PURPOSE, keyId: "possession-receipt-2026-08", version: POSSESSION_RECEIPT_VERSION },
    { provider: "refreshHintSignerProvider", name: "refresh", purpose: "agentpass.refresh-hint", keyId: "refresh-hint-2026-08", version: 1 }
  ]) {
    const bytes = Buffer.from(`all-purpose:${definition.name}`);
    const signature = await providers[definition.provider].sign({ algorithm: "ed25519", bytes, key_id: definition.keyId, purpose: definition.purpose, version: definition.version });
    assert.equal(crypto.verify(null, bytes, env.__keys[definition.name].publicKey, signature), true);
  }
  for (const definition of [
    { provider: "capabilitySignerProvider", name: "capability", purpose: "agentpass.capability", keyId: "capability-2026-08", version: 1 },
    { provider: "controlBundleSignerProvider", name: "controlBundle", purpose: "agentpass.control-bundle", keyId: "controlBundle-2026-08", version: 2 },
    { provider: "auditAnchorSignerProvider", name: "auditAnchor", purpose: "agentpass.audit-anchor", keyId: "auditAnchor-2026-08", version: 1 },
    { provider: "promotionEvidenceSignerProvider", name: "promotionEvidence", purpose: "agentpass.promotion-evidence", keyId: "promotionEvidence-2026-08", version: 2 }
  ]) {
    const bytes = Buffer.from(`all-purpose:${definition.name}`);
    const signature = await providers[definition.provider].sign({ algorithm: "ed25519", bytes, key_id: definition.keyId, purpose: definition.purpose, version: definition.version });
    assert.equal(crypto.verify(null, bytes, env.__keys[definition.name].publicKey, signature), true);
  }
  assert.deepEqual(new Set(observed.map((command) => command.input.KeyId)), new Set([
    awsAgentResource, awsManifestResource, awsPossessionResource, awsRefreshResource,
    ...EXTENDED_FIXTURE_DEFINITIONS.map(({ resource }) => resource)
  ]));
  await providers.close();
});

test("AWS composition instantiates official-shaped clients and signs all purpose-separated providers with mapped remote resources", async () => {
  const env = baseEnv();
  const observed = [];
  let destroyed = 0;
  class GetPublicKeyCommand { constructor(input) { this.input = input; this.kind = "get"; } }
  class SignCommand { constructor(input) { this.input = input; this.kind = "sign"; } }
  class KMSClient {
    destroy() { destroyed += 1; }
    async send(command) {
      observed.push(command);
      const keyPair = command.input.KeyId === awsAgentResource
        ? env.__keys.agent
        : command.input.KeyId === awsManifestResource ? env.__keys.manifest
          : command.input.KeyId === awsPossessionResource ? env.__keys.possession : env.__keys.refresh;
      if (command.kind === "get") {
        return {
          KeyId: command.input.KeyId,
          KeyUsage: "SIGN_VERIFY",
          KeySpec: "ECC_NIST_EDWARDS25519",
          SigningAlgorithms: ["ED25519_SHA_512"],
          PublicKey: publicDer(keyPair)
        };
      }
      return {
        KeyId: command.input.KeyId,
        SigningAlgorithm: "ED25519_SHA_512",
        Signature: crypto.sign(null, command.input.Message, keyPair.privateKey)
      };
    }
  }
  const providers = await createHostedKmsProviders({ env, sdkLoader: async () => ({ KMSClient, GetPublicKeyCommand, SignCommand }) });
  assert.equal(providers.agentSessionSignerProvider.key_id, "agent-session-2026-08");
  assert.equal(providers.agentSessionSignerProvider.provider_id, "agentpass-aws-kms-ledger-v1");
  assert.equal(providers.qualificationManifestSignerProvider.key_id, "qualification-manifest-2026-08");
  const data = Buffer.from("aws runtime composition");
  const signature = await providers.agentSessionSignerProvider.sign({
    algorithm: "ed25519", bytes: data, key_id: "agent-session-2026-08", purpose: AGENT_PURPOSE, version: 1
  });
  assert.equal(crypto.verify(null, data, env.__keys.agent.publicKey, signature), true);
  const possessionBytes = possessionReceiptSigningData(possessionStatement());
  const possessionSignature = await providers.possessionReceiptSignerProvider.sign({ algorithm: "ed25519", bytes: possessionBytes, key_id: "possession-receipt-2026-08", purpose: POSSESSION_RECEIPT_PURPOSE, version: POSSESSION_RECEIPT_VERSION });
  assert.equal(crypto.verify(null, possessionBytes, env.__keys.possession.publicKey, possessionSignature), true);
  assert.equal(observed.some((command) => command.input.KeyId === awsPossessionResource), true);
  const refreshBytes = Buffer.from("agentpass.refresh-hint.v1\0aws runtime refresh");
  const refreshSignature = await providers.refreshHintSignerProvider.sign({ algorithm: "ed25519", bytes: refreshBytes, key_id: "refresh-hint-2026-08", purpose: "agentpass.refresh-hint", version: 1 });
  assert.equal(crypto.verify(null, refreshBytes, env.__keys.refresh.publicKey, refreshSignature), true);
  assert.equal(observed.filter((command) => command.input.KeyId === awsAgentResource).length > 0, true);
  assert.equal(observed.every((command) => [awsAgentResource, awsManifestResource, awsPossessionResource, awsRefreshResource].includes(command.input.KeyId)), true);
  assert.equal(providers.agentSessionSignerProvider.close, undefined);
  await Promise.all([providers.close(), providers.close(), providers.close()]);
  assert.equal(destroyed, 1);
});

test("GCP composition instantiates official-shaped clients and maps cryptoKeyVersion resources", async () => {
  const env = baseEnv({ provider: "gcp", agentResource: gcpAgentResource, manifestResource: gcpManifestResource });
  const observed = [];
  let closed = 0;
  class KeyManagementServiceClient {
    async close() { closed += 1; }
    async getPublicKey(input) {
      observed.push({ operation: "getPublicKey", input });
      const pair = input.name === gcpAgentResource
        ? env.__keys.agent
        : input.name === gcpManifestResource ? env.__keys.manifest
          : input.name === gcpPossessionResource ? env.__keys.possession : env.__keys.refresh;
      return [{ name: input.name, algorithm: "EC_SIGN_ED25519", protectionLevel: "HSM", pem: pair.publicKey.export({ type: "spki", format: "pem" }).toString() }];
    }
    async asymmetricSign(input) {
      observed.push({ operation: "asymmetricSign", input });
      const pair = input.name === gcpAgentResource
        ? env.__keys.agent
        : input.name === gcpManifestResource ? env.__keys.manifest
          : input.name === gcpPossessionResource ? env.__keys.possession : env.__keys.refresh;
      return [{ name: input.name, protectionLevel: "HSM", signature: crypto.sign(null, input.data, pair.privateKey).toString("base64") }];
    }
  }
  const providers = await createHostedKmsProviders({ env, sdkLoader: async () => ({ KeyManagementServiceClient }) });
  assert.equal(providers.qualificationManifestSignerProvider.provider_id, "agentpass-gcp-kms-ledger-v1");
  const data = Buffer.from("gcp runtime composition");
  const signature = await providers.qualificationManifestSignerProvider.sign({
    algorithm: "ed25519", bytes: data, key_id: "qualification-manifest-2026-08", purpose: MANIFEST_PURPOSE, version: 2
  });
  assert.equal(crypto.verify(null, data, env.__keys.manifest.publicKey, signature), true);
  const possessionBytes = possessionReceiptSigningData(possessionStatement());
  const possessionSignature = await providers.possessionReceiptSignerProvider.sign({ algorithm: "ed25519", bytes: possessionBytes, key_id: "possession-receipt-2026-08", purpose: POSSESSION_RECEIPT_PURPOSE, version: POSSESSION_RECEIPT_VERSION });
  assert.equal(crypto.verify(null, possessionBytes, env.__keys.possession.publicKey, possessionSignature), true);
  assert.equal(observed.some(({ input }) => input.name === gcpPossessionResource), true);
  const refreshBytes = Buffer.from("agentpass.refresh-hint.v1\0gcp runtime refresh");
  const refreshSignature = await providers.refreshHintSignerProvider.sign({ algorithm: "ed25519", bytes: refreshBytes, key_id: "refresh-hint-2026-08", purpose: "agentpass.refresh-hint", version: 1 });
  assert.equal(crypto.verify(null, refreshBytes, env.__keys.refresh.publicKey, refreshSignature), true);
  assert.equal(observed.every(({ input }) => [gcpAgentResource, gcpManifestResource, gcpPossessionResource, gcpRefreshResource].includes(input.name)), true);
  assert.equal(providers.qualificationManifestSignerProvider.close, undefined);
  await Promise.all([providers.close(), providers.close()]);
  assert.equal(closed, 1);
});

test("AWS possession receipt binding rejects a substituted KMS resource", async () => {
  const env = baseEnv();
  let signCalls = 0;
  let destroyed = 0;
  class GetPublicKeyCommand { constructor(input) { this.input = input; this.kind = "get"; } }
  class SignCommand { constructor(input) { this.input = input; this.kind = "sign"; } }
  class KMSClient {
    destroy() { destroyed += 1; }
    async send(command) {
      if (command.kind === "get") return {
        KeyId: awsManifestResource,
        KeyUsage: "SIGN_VERIFY",
        KeySpec: "ECC_NIST_EDWARDS25519",
        SigningAlgorithms: ["ED25519_SHA_512"],
        PublicKey: publicDer(env.__keys.possession)
      };
      signCalls += 1;
      return { KeyId: awsManifestResource, SigningAlgorithm: "ED25519_SHA_512", Signature: Buffer.alloc(64) };
    }
  }
  const providers = await createHostedKmsProviders({ env, sdkLoader: async () => ({ KMSClient, GetPublicKeyCommand, SignCommand }) });
  await assert.rejects(
    providers.possessionReceiptSignerProvider.publicKeyMetadata({ algorithm: "ed25519", key_id: "possession-receipt-2026-08", purpose: POSSESSION_RECEIPT_PURPOSE, version: POSSESSION_RECEIPT_VERSION })
  );
  assert.equal(signCalls, 0);
  await providers.close();
  assert.equal(destroyed, 1);
});

test("GCP possession receipt binding rejects a substituted cryptoKeyVersion", async () => {
  const env = baseEnv({ provider: "gcp", agentResource: gcpAgentResource, manifestResource: gcpManifestResource });
  let signCalls = 0;
  let closed = 0;
  class KeyManagementServiceClient {
    async close() { closed += 1; }
    async getPublicKey(input) {
      return [{ name: gcpManifestResource, algorithm: "EC_SIGN_ED25519", protectionLevel: "HSM", pem: env.__keys.possession.publicKey.export({ type: "spki", format: "pem" }).toString() }];
    }
    async asymmetricSign() { signCalls += 1; return [{ name: gcpManifestResource, protectionLevel: "HSM", signature: Buffer.alloc(64).toString("base64") }]; }
  }
  const providers = await createHostedKmsProviders({ env, sdkLoader: async () => ({ KeyManagementServiceClient }) });
  await assert.rejects(
    providers.possessionReceiptSignerProvider.publicKeyMetadata({ algorithm: "ed25519", key_id: "possession-receipt-2026-08", purpose: POSSESSION_RECEIPT_PURPOSE, version: POSSESSION_RECEIPT_VERSION })
  );
  assert.equal(signCalls, 0);
  await providers.close();
  assert.equal(closed, 1);
});

test("possession receipt lifecycle injection is purpose-bound and can disable only that provider", async () => {
  const env = baseEnv();
  const fingerprint = crypto.createHash("sha256").update(publicDer(env.__keys.possession)).digest("hex");
  const lifecycle = createManagedSignerKeyLifecycle({
    purpose: POSSESSION_RECEIPT_PURPOSE,
    snapshot: {
      version: 1,
      purpose: POSSESSION_RECEIPT_PURPOSE,
      algorithm: "ed25519",
      keys: [{
        key_id: env.AGENTPASS_CLOUD_POSSESSION_RECEIPT_KEY_ID,
        key_version: 1,
        purpose: POSSESSION_RECEIPT_PURPOSE,
        algorithm: "ed25519",
        public_key_fingerprint: fingerprint,
        state: "active",
        state_version: 1
      }]
    }
  });
  class GetPublicKeyCommand { constructor(input) { this.input = input; this.kind = "get"; } }
  class SignCommand { constructor(input) { this.input = input; this.kind = "sign"; } }
  class KMSClient {
    destroy() {}
    async send(command) {
      const pair = command.input.KeyId === awsPossessionResource ? env.__keys.possession : env.__keys.agent;
      if (command.kind === "get") return { KeyId: command.input.KeyId, KeyUsage: "SIGN_VERIFY", KeySpec: "ECC_NIST_EDWARDS25519", SigningAlgorithms: ["ED25519_SHA_512"], PublicKey: publicDer(pair) };
      return { KeyId: command.input.KeyId, SigningAlgorithm: "ED25519_SHA_512", Signature: crypto.sign(null, command.input.Message, pair.privateKey) };
    }
  }
  const providers = await createHostedKmsProviders({
    env,
    keyLifecycles: { possessionReceipt: lifecycle },
    sdkLoader: async () => ({ KMSClient, GetPublicKeyCommand, SignCommand })
  });
  lifecycle.emergencyDisable({ expected_version: 1, operation_id: "disable-possession-receipt" });
  await assert.rejects(
    providers.possessionReceiptSignerProvider.sign({ algorithm: "ed25519", bytes: possessionReceiptSigningData(possessionStatement()), key_id: "possession-receipt-2026-08", purpose: POSSESSION_RECEIPT_PURPOSE, version: POSSESSION_RECEIPT_VERSION })
  );
  await providers.close();
});

test("third-purpose construction failure closes the owned cloud client", async () => {
  const env = baseEnv();
  let destroyed = 0;
  class GetPublicKeyCommand { constructor(input) { this.input = input; } }
  class SignCommand { constructor(input) { this.input = input; } }
  class KMSClient {
    destroy() { destroyed += 1; }
    async send() { throw new Error("not reached"); }
  }
  await assert.rejects(
    createHostedKmsProviders({
      env,
      keyLifecycles: { possessionReceipt: {} },
      sdkLoader: async () => ({ KMSClient, GetPublicKeyCommand, SignCommand })
    }),
    { code: KMS_PROVIDER_RUNTIME_ERROR_CODES.UNAVAILABLE }
  );
  assert.equal(destroyed, 1);
});

test("hosted runtime applies an isolated fail-closed circuit at each managed signer boundary", async () => {
  const env = baseEnv();
  let now = 1_900_000_000_000;
  let calls = 0;
  class GetPublicKeyCommand { constructor(input) { this.input = input; this.kind = "get"; } }
  class SignCommand { constructor(input) { this.input = input; this.kind = "sign"; } }
  class KMSClient {
    destroy() {}
    async send(command) {
      calls += 1;
      if (command.kind === "get" && command.input.KeyId === awsAgentResource) {
        const error = new Error("provider quota detail");
        error.name = "ThrottlingException";
        throw error;
      }
      if (command.kind === "get") {
        return {
          KeyId: command.input.KeyId,
          KeyUsage: "SIGN_VERIFY",
          KeySpec: "ECC_NIST_EDWARDS25519",
          SigningAlgorithms: ["ED25519_SHA_512"],
          PublicKey: publicDer(env.__keys.manifest)
        };
      }
      return {
        KeyId: command.input.KeyId,
        SigningAlgorithm: "ED25519_SHA_512",
        Signature: crypto.sign(null, command.input.Message, env.__keys.manifest.privateKey)
      };
    }
  }
  const providers = await createHostedKmsProviders({
    env,
    clock: () => now,
    reliability: { clock: () => { throw new Error("reliability clock must not override top-level clock"); }, failureThreshold: 1, cooldownMs: 100, maxInFlight: 1 },
    sdkLoader: async () => ({ KMSClient, GetPublicKeyCommand, SignCommand })
  });
  const agentRequest = { algorithm: "ed25519", bytes: Buffer.from("agent"), key_id: "agent-session-2026-08", purpose: AGENT_PURPOSE, version: 1 };
  await assert.rejects(providers.agentSessionSignerProvider.sign(agentRequest), (error) => error.code === "ERR_MANAGED_SIGNER_THROTTLED");
  await assert.rejects(providers.agentSessionSignerProvider.sign(agentRequest), (error) => error.code === "ERR_MANAGED_SIGNER_CIRCUIT_OPEN");
  const callsWhenOpen = calls;
  const manifestRequest = { algorithm: "ed25519", bytes: Buffer.from("manifest"), key_id: "qualification-manifest-2026-08", purpose: MANIFEST_PURPOSE, version: 2 };
  await assert.doesNotReject(providers.qualificationManifestSignerProvider.sign(manifestRequest));
  assert.equal(calls, callsWhenOpen + 2);
  now += 100;
  await assert.rejects(providers.agentSessionSignerProvider.sign(agentRequest), (error) => error.code === "ERR_MANAGED_SIGNER_THROTTLED");
  await providers.close();
});

test("SDK and constructor failures are opaque and fail closed", async () => {
  const env = baseEnv();
  await assert.rejects(
    createHostedKmsProviders({ env, sdkLoader: async () => ({}) }),
    (error) => error.code === KMS_PROVIDER_RUNTIME_ERROR_CODES.SDK && !error.message.includes("AWS")
  );
  await assert.rejects(
    createHostedKmsProviders({ env, sdkLoader: async () => { throw new Error("credential details"); } }),
    (error) => error.code === KMS_PROVIDER_RUNTIME_ERROR_CODES.SDK && !error.message.includes("credential")
  );
});

test("evaluation profile rejects hosted KMS composition before loading any SDK", async () => {
  let loaded = false;
  await assert.rejects(
    createHostedKmsProviders({
      env: { AGENTPASS_CLOUD_PROFILE: "evaluation" },
      sdkLoader: async () => { loaded = true; return {}; }
    }),
    (error) => error.code === KMS_PROVIDER_RUNTIME_ERROR_CODES.CONFIG
  );
  assert.equal(loaded, false);
});

test("hosted composition rejects unknown lifecycle injection slots before loading an SDK", async () => {
  let loaded = false;
  await assert.rejects(createHostedKmsProviders({
    env: baseEnv(),
    keyLifecycles: { arbitraryPurpose: {} },
    sdkLoader: async () => { loaded = true; return {}; }
  }), { code: KMS_PROVIDER_RUNTIME_ERROR_CODES.CONFIG });
  assert.equal(loaded, false);
});
