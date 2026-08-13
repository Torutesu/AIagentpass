import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import { AWS_KMS_ED25519_SIGNING_ALGORITHM, AWS_KMS_MAX_RAW_MESSAGE_BYTES, createAwsKmsEd25519Provider } from "../src/aws-kms-provider.mjs";

const keys = crypto.generateKeyPairSync("ed25519");
const der = keys.publicKey.export({ type: "spki", format: "der" });
const keyId = "arn:aws:kms:us-east-1:123456789012:key/ed25519-v1";
const commands = { GetPublicKeyCommand: class { constructor(input) { this.input = input; this.kind = "get"; } }, SignCommand: class { constructor(input) { this.input = input; this.kind = "sign"; } } };
const base = { keyId, purpose: "agent-session-grant", publicKey: keys.publicKey, commands };
const request = { key_id: keyId, purpose: "agent-session-grant", algorithm: "ed25519", version: 1 };
const publicMetadata = { PublicKey: der, KeyUsage: "SIGN_VERIFY", KeySpec: "ECC_NIST_EDWARDS25519", SigningAlgorithms: [AWS_KMS_ED25519_SIGNING_ALGORITHM] };

test("uses injected AWS KMS commands with exact key and abort signal", async () => {
  const seen = [];
  const client = { async send(command, options) { seen.push([command, options]); return command.kind === "get" ? publicMetadata : { KeyId: keyId, SigningAlgorithm: AWS_KMS_ED25519_SIGNING_ALGORITHM, Signature: crypto.sign(null, command.input.Message, keys.privateKey) }; } };
  const provider = createAwsKmsEd25519Provider({ ...base, client });
  await provider.publicKeyMetadata(request);
  const signature = await provider.sign({ ...request, bytes: Buffer.from("aws") });
  assert.equal(signature.length, 64);
  assert.equal(seen[0][0].input.KeyId, keyId);
  assert.equal(seen.at(-1)[0].input.SigningAlgorithm, AWS_KMS_ED25519_SIGNING_ALGORITHM);
  assert.equal(seen.at(-1)[0].input.MessageType, "RAW");
  assert.equal(seen.at(-1)[1].abortSignal instanceof AbortSignal, true);
});

test("rejects adapter construction and request substitution", async () => {
  assert.throws(() => createAwsKmsEd25519Provider({ ...base, client: {} }), /invalid|configuration/u);
  const client = { async send(command) { return command.kind === "get" ? publicMetadata : { Signature: crypto.sign(null, command.input.Message, keys.privateKey) }; } };
  const provider = createAwsKmsEd25519Provider({ ...base, client });
  await assert.rejects(provider.sign({ ...request, key_id: "other", bytes: Buffer.from("x") }), (error) => error.code === "ERR_REMOTE_KMS_PURPOSE");
  await assert.rejects(provider.sign({ ...request, bytes: Buffer.alloc(AWS_KMS_MAX_RAW_MESSAGE_BYTES + 1) }), (error) => error.code === "ERR_REMOTE_KMS_INPUT");
  assert.throws(() => createAwsKmsEd25519Provider({ ...base, client, maxRequestBytes: AWS_KMS_MAX_RAW_MESSAGE_BYTES + 1 }), (error) => error.code === "ERR_REMOTE_KMS_CONFIG");
  const wrongUsage = createAwsKmsEd25519Provider({ ...base, client: { async send(command) { return command.kind === "get" ? { ...publicMetadata, KeyUsage: "ENCRYPT_DECRYPT" } : {}; } } });
  await assert.rejects(wrongUsage.publicKeyMetadata(request), (error) => error.code === "ERR_REMOTE_KMS_PROVIDER");
});
