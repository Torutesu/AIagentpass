import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import { createHostedKmsProviders } from "../src/kms-provider-runtime.mjs";
import {
  createManagedSignerKeyLifecycle,
  MANAGED_SIGNER_KEY_LIFECYCLE_ERROR_CODES as CODES
} from "../src/managed-signer-key-lifecycle.mjs";

const PURPOSE = "agentpass.agent-session-grant";
const RESOURCE = "arn:aws:kms:us-east-1:123456789012:key/agent-session";
const MANIFEST_RESOURCE = "arn:aws:kms:us-east-1:123456789012:key/manifest";
const POSSESSION_RESOURCE = "arn:aws:kms:us-east-1:123456789012:key/possession";

function fixture() {
  const agent = crypto.generateKeyPairSync("ed25519");
  const manifest = crypto.generateKeyPairSync("ed25519");
  const possession = crypto.generateKeyPairSync("ed25519");
  const env = {
    AGENTPASS_CLOUD_PROFILE: "hosted",
    AGENTPASS_CLOUD_AGENT_SESSION_KEY_ID: "agent-session-2026-08",
    AGENTPASS_CLOUD_AGENT_SESSION_PUBLIC_KEY: agent.publicKey.export({ type: "spki", format: "pem" }).toString(),
    AGENTPASS_CLOUD_QUALIFICATION_MANIFEST_KEY_ID: "manifest-2026-08",
    AGENTPASS_CLOUD_QUALIFICATION_MANIFEST_PUBLIC_KEY: manifest.publicKey.export({ type: "spki", format: "pem" }).toString(),
    AGENTPASS_CLOUD_POSSESSION_RECEIPT_KEY_ID: "possession-2026-08",
    AGENTPASS_CLOUD_POSSESSION_RECEIPT_PUBLIC_KEY: possession.publicKey.export({ type: "spki", format: "pem" }).toString(),
    AGENTPASS_KMS_PROVIDER: "aws",
    AGENTPASS_KMS_AGENT_SESSION_KEY_RESOURCE: RESOURCE,
    AGENTPASS_KMS_QUALIFICATION_MANIFEST_KEY_RESOURCE: MANIFEST_RESOURCE,
    AGENTPASS_KMS_POSSESSION_RECEIPT_KEY_RESOURCE: POSSESSION_RESOURCE
  };
  return { agent, manifest, possession, env };
}

function fingerprint(pair) {
  return crypto.createHash("sha256").update(pair.publicKey.export({ type: "spki", format: "der" })).digest("hex");
}

test("hosted AWS composition enforces lifecycle state independently per purpose", async () => {
  const value = fixture();
  let calls = 0;
  class GetPublicKeyCommand { constructor(input) { this.input = input; this.kind = "get"; } }
  class SignCommand { constructor(input) { this.input = input; this.kind = "sign"; } }
  class KMSClient {
    destroy() {}
    async send(command) {
      calls += 1;
      const pair = command.input.KeyId === RESOURCE ? value.agent : command.input.KeyId === MANIFEST_RESOURCE ? value.manifest : value.possession;
      if (command.kind === "get") {
        return {
          KeyId: command.input.KeyId,
          KeyUsage: "SIGN_VERIFY",
          KeySpec: "ECC_NIST_EDWARDS25519",
          SigningAlgorithms: ["ED25519_SHA_512"],
          PublicKey: pair.publicKey.export({ type: "spki", format: "der" })
        };
      }
      return {
        KeyId: command.input.KeyId,
        SigningAlgorithm: "ED25519_SHA_512",
        Signature: crypto.sign(null, command.input.Message, pair.privateKey)
      };
    }
  }
  const lifecycle = createManagedSignerKeyLifecycle({
    purpose: PURPOSE,
    snapshot: {
      version: 1,
      purpose: PURPOSE,
      algorithm: "ed25519",
      keys: [{
        key_id: "agent-session-2026-08",
        key_version: 1,
        purpose: PURPOSE,
        algorithm: "ed25519",
        public_key_fingerprint: fingerprint(value.agent),
        state: "active",
        state_version: 1
      }]
    }
  });
  const providers = await createHostedKmsProviders({
    env: value.env,
    keyLifecycles: { agentSession: lifecycle },
    sdkLoader: async () => ({ KMSClient, GetPublicKeyCommand, SignCommand })
  });
  const request = { algorithm: "ed25519", bytes: Buffer.from("lifecycle"), key_id: "agent-session-2026-08", purpose: PURPOSE, version: 1 };
  await assert.doesNotReject(providers.agentSessionSignerProvider.sign(request));
  const callsBeforeDisable = calls;
  lifecycle.emergencyDisable({ expected_version: 1, operation_id: "emergency-1" });
  await assert.rejects(providers.agentSessionSignerProvider.sign(request), { code: CODES.NOT_ACTIVE });
  assert.equal(calls, callsBeforeDisable);
  const manifestRequest = { algorithm: "ed25519", bytes: Buffer.from("manifest"), key_id: "manifest-2026-08", purpose: "agentpass.qualification-grant-batch-manifest", version: 2 };
  await assert.doesNotReject(providers.qualificationManifestSignerProvider.sign(manifestRequest));
  assert.deepEqual(providers.agentSessionSignerProvider.key_lifecycle_state(), lifecycle.snapshot());
  assert.equal(Object.hasOwn(providers.agentSessionSignerProvider, "key_lifecycle"), false);
  await providers.close();
});

test("hosted GCP composition applies the same active-key boundary", async () => {
  const value = fixture();
  const agentResource = "projects/demo/locations/global/keyRings/agentpass/cryptoKeys/agent/cryptoKeyVersions/1";
  const manifestResource = "projects/demo/locations/global/keyRings/agentpass/cryptoKeys/manifest/cryptoKeyVersions/1";
  const possessionResource = "projects/demo/locations/global/keyRings/agentpass/cryptoKeys/possession/cryptoKeyVersions/1";
  value.env.AGENTPASS_KMS_PROVIDER = "gcp";
  value.env.AGENTPASS_KMS_AGENT_SESSION_KEY_RESOURCE = agentResource;
  value.env.AGENTPASS_KMS_QUALIFICATION_MANIFEST_KEY_RESOURCE = manifestResource;
  value.env.AGENTPASS_KMS_POSSESSION_RECEIPT_KEY_RESOURCE = possessionResource;
  const lifecycle = createManagedSignerKeyLifecycle({
    purpose: PURPOSE,
    snapshot: {
      version: 1,
      purpose: PURPOSE,
      algorithm: "ed25519",
      keys: [{
        key_id: "agent-session-2026-08",
        key_version: 1,
        purpose: PURPOSE,
        algorithm: "ed25519",
        public_key_fingerprint: fingerprint(value.agent),
        state: "active",
        state_version: 1
      }]
    }
  });
  class KeyManagementServiceClient {
    async close() {}
    async getPublicKey({ name }) {
      const pair = name === agentResource ? value.agent : name === manifestResource ? value.manifest : value.possession;
      return [{ name, algorithm: "EC_SIGN_ED25519", protectionLevel: "HSM", pem: pair.publicKey.export({ type: "spki", format: "pem" }).toString() }];
    }
    async asymmetricSign({ name, data }) {
      const pair = name === agentResource ? value.agent : name === manifestResource ? value.manifest : value.possession;
      return [{ name, protectionLevel: "HSM", signature: crypto.sign(null, data, pair.privateKey).toString("base64") }];
    }
  }
  const providers = await createHostedKmsProviders({
    env: value.env,
    keyLifecycles: { agentSession: lifecycle },
    sdkLoader: async () => ({ KeyManagementServiceClient })
  });
  const request = { algorithm: "ed25519", bytes: Buffer.from("gcp-lifecycle"), key_id: "agent-session-2026-08", purpose: PURPOSE, version: 1 };
  await assert.doesNotReject(providers.agentSessionSignerProvider.sign(request));
  lifecycle.transitionKey({ expected_version: 1, operation_id: "revoke-1", key_id: "agent-session-2026-08", to: "revoked" });
  await assert.rejects(providers.agentSessionSignerProvider.sign(request), { code: CODES.NOT_ACTIVE });
  await providers.close();
});
