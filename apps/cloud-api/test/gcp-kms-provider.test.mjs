import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import { GCP_CLOUD_KMS_ED25519_SIGNING_ALGORITHM, GCP_CLOUD_KMS_HSM_MAX_DATA_BYTES, createGcpCloudKmsEd25519Provider } from "../src/gcp-kms-provider.mjs";

const keys = crypto.generateKeyPairSync("ed25519");
const publicKey = keys.publicKey.export({ type: "spki", format: "pem" }).toString();
const keyName = "projects/agentpass/locations/global/keyRings/signing/cryptoKeys/agent-session/cryptoKeyVersions/1";
const request = { key_id: keyName, purpose: "agent-session-grant", algorithm: "ed25519", version: 1 };
const publicMetadata = { pem: publicKey, name: keyName, algorithm: GCP_CLOUD_KMS_ED25519_SIGNING_ALGORITHM, protectionLevel: "HSM" };

test("uses injected Google Cloud KMS client with exact resource and signal", async () => {
  const seen = [];
  const client = {
    async getPublicKey(input, options) { seen.push(["get", input, options]); return [publicMetadata]; },
    async asymmetricSign(input, options) { seen.push(["sign", input, options]); return [{ name: keyName, protectionLevel: "HSM", signature: crypto.sign(null, input.data, keys.privateKey).toString("base64") }]; }
  };
  const provider = createGcpCloudKmsEd25519Provider({ keyName, purpose: request.purpose, publicKey, client });
  await provider.publicKeyMetadata(request);
  const signature = await provider.sign({ ...request, bytes: Buffer.from("gcp") });
  assert.equal(signature.length, 64);
  assert.deepEqual(seen[0][1], { name: keyName });
  assert.equal(seen.at(-1)[1].name, keyName);
  assert.equal(seen.at(-1)[1].algorithm, GCP_CLOUD_KMS_ED25519_SIGNING_ALGORITHM);
  assert.equal(seen.at(-1)[2].signal instanceof AbortSignal, true);
});

test("fails closed on resource substitution, malformed public key, and missing client", async () => {
  assert.throws(() => createGcpCloudKmsEd25519Provider({ keyName, purpose: request.purpose, publicKey, client: {} }), /invalid|configuration/u);
  const provider = createGcpCloudKmsEd25519Provider({ keyName, purpose: request.purpose, publicKey, client: {
    async getPublicKey() { return [{ ...publicMetadata, pem: "not a key" }]; },
    async asymmetricSign() { return [{ signature: "AA==" }]; }
  } });
  await assert.rejects(provider.publicKeyMetadata(request), (error) => error.code === "ERR_REMOTE_KMS_METADATA");
  await assert.rejects(provider.publicKeyMetadata({ ...request, key_id: "other" }), (error) => error.code === "ERR_REMOTE_KMS_PURPOSE");
});

test("enforces the Cloud HSM 8 KiB user-data limit without prehashing", async () => {
  const client = {
    async getPublicKey() { return [publicMetadata]; },
    async asymmetricSign() { return [{ signature: crypto.sign(null, Buffer.from("x"), keys.privateKey).toString("base64") }]; }
  };
  const provider = createGcpCloudKmsEd25519Provider({ keyName, purpose: request.purpose, publicKey, client });
  await assert.rejects(provider.sign({ ...request, bytes: Buffer.alloc(GCP_CLOUD_KMS_HSM_MAX_DATA_BYTES + 1) }), (error) => error.code === "ERR_REMOTE_KMS_INPUT");
  assert.throws(() => createGcpCloudKmsEd25519Provider({ keyName, purpose: request.purpose, publicKey, client, maxRequestBytes: GCP_CLOUD_KMS_HSM_MAX_DATA_BYTES + 1 }), (error) => error.code === "ERR_REMOTE_KMS_CONFIG");
});
