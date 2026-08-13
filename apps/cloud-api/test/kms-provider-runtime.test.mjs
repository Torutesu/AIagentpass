import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import {
  createHostedKmsProviders,
  KMS_PROVIDER_RUNTIME_ERROR_CODES,
  parseKmsProviderRuntimeConfig
} from "../src/kms-provider-runtime.mjs";

const AGENT_PURPOSE = "agentpass.agent-session-grant";
const MANIFEST_PURPOSE = "agentpass.qualification-grant-batch-manifest";
const awsAgentResource = "arn:aws:kms:us-east-1:123456789012:key/agent-session";
const awsManifestResource = "arn:aws:kms:us-east-1:123456789012:key/qualification-manifest";
const gcpAgentResource = "projects/demo/locations/global/keyRings/agentpass/cryptoKeys/agent-session/cryptoKeyVersions/1";
const gcpManifestResource = "projects/demo/locations/global/keyRings/agentpass/cryptoKeys/qualification-manifest/cryptoKeyVersions/1";

function baseEnv({ provider = "aws", agentResource = awsAgentResource, manifestResource = awsManifestResource } = {}) {
  const agent = crypto.generateKeyPairSync("ed25519");
  const manifest = crypto.generateKeyPairSync("ed25519");
  return {
    AGENTPASS_CLOUD_PROFILE: "hosted",
    AGENTPASS_CLOUD_AGENT_SESSION_KEY_ID: "agent-session-2026-08",
    AGENTPASS_CLOUD_AGENT_SESSION_PUBLIC_KEY: agent.publicKey.export({ type: "spki", format: "pem" }).toString(),
    AGENTPASS_CLOUD_QUALIFICATION_MANIFEST_KEY_ID: "qualification-manifest-2026-08",
    AGENTPASS_CLOUD_QUALIFICATION_MANIFEST_PUBLIC_KEY: manifest.publicKey.export({ type: "spki", format: "pem" }).toString(),
    AGENTPASS_KMS_PROVIDER: provider,
    AGENTPASS_KMS_AGENT_SESSION_KEY_RESOURCE: agentResource,
    AGENTPASS_KMS_QUALIFICATION_MANIFEST_KEY_RESOURCE: manifestResource,
    __keys: { agent, manifest }
  };
}

function publicDer(keyPair) { return keyPair.publicKey.export({ type: "spki", format: "der" }); }

test("hosted KMS config is explicit, closed, and keeps logical IDs separate from resources", () => {
  const env = baseEnv();
  const config = parseKmsProviderRuntimeConfig(env);
  assert.equal(config.provider, "aws");
  assert.equal(config.agentSession.keyId, "agent-session-2026-08");
  assert.equal(config.agentSessionResource, awsAgentResource);
  assert.notEqual(config.agentSession.keyId, config.agentSessionResource);

  for (const value of [
    { AGENTPASS_KMS_PROVIDER: undefined },
    { AGENTPASS_KMS_AGENT_SESSION_KEY_RESOURCE: undefined },
    { AGENTPASS_KMS_QUALIFICATION_MANIFEST_KEY_RESOURCE: undefined },
    { AGENTPASS_KMS_PROVIDER: "local" },
    { AGENTPASS_KMS_AGENT_SESSION_KEY_RESOURCE: awsManifestResource },
    { AGENTPASS_KMS_PRIVATE_KEY_PATH: "/tmp/key" },
    { AGENTPASS_CLOUD_PROFILE: "evaluation" }
  ]) {
    const invalid = { ...env, ...value };
    assert.throws(() => parseKmsProviderRuntimeConfig(invalid), (error) => error.code === KMS_PROVIDER_RUNTIME_ERROR_CODES.CONFIG);
  }
});

test("AWS composition instantiates official-shaped clients and signs with mapped remote resources", async () => {
  const env = baseEnv();
  const observed = [];
  let destroyed = 0;
  class GetPublicKeyCommand { constructor(input) { this.input = input; this.kind = "get"; } }
  class SignCommand { constructor(input) { this.input = input; this.kind = "sign"; } }
  class KMSClient {
    destroy() { destroyed += 1; }
    async send(command) {
      observed.push(command);
      if (command.kind === "get") {
        return {
          KeyId: command.input.KeyId,
          KeyUsage: "SIGN_VERIFY",
          KeySpec: "ECC_NIST_EDWARDS25519",
          SigningAlgorithms: ["ED25519_SHA_512"],
          PublicKey: publicDer(command.input.KeyId === awsAgentResource ? env.__keys.agent : env.__keys.manifest)
        };
      }
      const pair = command.input.KeyId === awsAgentResource ? env.__keys.agent : env.__keys.manifest;
      return {
        KeyId: command.input.KeyId,
        SigningAlgorithm: "ED25519_SHA_512",
        Signature: crypto.sign(null, command.input.Message, pair.privateKey)
      };
    }
  }
  const providers = await createHostedKmsProviders({ env, sdkLoader: async () => ({ KMSClient, GetPublicKeyCommand, SignCommand }) });
  assert.equal(providers.agentSessionSignerProvider.key_id, "agent-session-2026-08");
  assert.equal(providers.qualificationManifestSignerProvider.key_id, "qualification-manifest-2026-08");
  const data = Buffer.from("aws runtime composition");
  const signature = await providers.agentSessionSignerProvider.sign({
    algorithm: "ed25519", bytes: data, key_id: "agent-session-2026-08", purpose: AGENT_PURPOSE, version: 1
  });
  assert.equal(crypto.verify(null, data, env.__keys.agent.publicKey, signature), true);
  assert.equal(observed.every((command) => command.input.KeyId === awsAgentResource), true);
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
      const pair = input.name === gcpAgentResource ? env.__keys.agent : env.__keys.manifest;
      return [{ name: input.name, algorithm: "EC_SIGN_ED25519", protectionLevel: "HSM", pem: pair.publicKey.export({ type: "spki", format: "pem" }).toString() }];
    }
    async asymmetricSign(input) {
      observed.push({ operation: "asymmetricSign", input });
      const pair = input.name === gcpAgentResource ? env.__keys.agent : env.__keys.manifest;
      return [{ name: input.name, protectionLevel: "HSM", signature: crypto.sign(null, input.data, pair.privateKey).toString("base64") }];
    }
  }
  const providers = await createHostedKmsProviders({ env, sdkLoader: async () => ({ KeyManagementServiceClient }) });
  const data = Buffer.from("gcp runtime composition");
  const signature = await providers.qualificationManifestSignerProvider.sign({
    algorithm: "ed25519", bytes: data, key_id: "qualification-manifest-2026-08", purpose: MANIFEST_PURPOSE, version: 2
  });
  assert.equal(crypto.verify(null, data, env.__keys.manifest.publicKey, signature), true);
  assert.equal(observed.every(({ input }) => input.name === gcpManifestResource), true);
  assert.equal(providers.qualificationManifestSignerProvider.close, undefined);
  await Promise.all([providers.close(), providers.close()]);
  assert.equal(closed, 1);
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
