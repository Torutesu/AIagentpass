import crypto from "node:crypto";

import {
  assertBoundRemoteKmsRequest,
  createRemoteEd25519KmsProvider,
  REMOTE_KMS_ALGORITHM,
  REMOTE_KMS_ERROR_CODES,
  REMOTE_KMS_VERSION,
  RemoteKmsProviderError
} from "./remote-kms-provider.mjs";

export const AWS_KMS_ED25519_SIGNING_ALGORITHM = "ED25519_SHA_512";
export const AWS_KMS_MAX_RAW_MESSAGE_BYTES = 4 * 1024;

/** Thin AWS KMS adapter. Inject the official KMSClient and command classes. */
export function createAwsKmsEd25519Transport({ client, commands, keyId, purpose, version = REMOTE_KMS_VERSION } = {}) {
  if (!client || typeof client.send !== "function" || !commands?.GetPublicKeyCommand || !commands?.SignCommand) {
    throw new RemoteKmsProviderError(REMOTE_KMS_ERROR_CODES.CONFIG);
  }
  const binding = Object.freeze({ key_id: keyId, purpose, algorithm: REMOTE_KMS_ALGORITHM, version });
  return Object.freeze({
    async getPublicKey(request, { signal } = {}) {
      assertBoundRemoteKmsRequest(request, binding);
      const result = await client.send(new commands.GetPublicKeyCommand({ KeyId: keyId }), { abortSignal: signal });
      if (result?.KeyId !== keyId || result?.KeyUsage !== "SIGN_VERIFY" || result?.KeySpec !== "ECC_NIST_EDWARDS25519"
        || !Array.isArray(result?.SigningAlgorithms) || !result.SigningAlgorithms.includes(AWS_KMS_ED25519_SIGNING_ALGORITHM)) {
        throw new Error("invalid AWS KMS key metadata");
      }
      return { key_id: keyId, algorithm: REMOTE_KMS_ALGORITHM, public_key: awsDerToPem(result?.PublicKey) };
    },
    async sign(request, { signal } = {}) {
      // AWS KMS ED25519_SHA_512 with MessageType RAW signs these exact bytes.
      // The 4 KiB limit is enforced here so callers cannot accidentally turn
      // this boundary into a prehashing or truncation boundary.
      assertBoundRemoteKmsRequest(request, binding, { signing: true, maxRequestBytes: AWS_KMS_MAX_RAW_MESSAGE_BYTES });
      const result = await client.send(new commands.SignCommand({
        KeyId: keyId,
        Message: Buffer.from(request.bytes),
        MessageType: "RAW",
        SigningAlgorithm: AWS_KMS_ED25519_SIGNING_ALGORITHM
      }), { abortSignal: signal });
      if (result?.KeyId !== keyId) throw new Error("AWS KMS signing key identity is missing or substituted");
      if (result?.SigningAlgorithm !== AWS_KMS_ED25519_SIGNING_ALGORITHM) throw new Error("AWS KMS signing algorithm identity is missing or substituted");
      return result?.Signature;
    }
  });
}

export function createAwsKmsEd25519Provider(options = {}) {
  const transport = createAwsKmsEd25519Transport(options);
  if (options.maxRequestBytes !== undefined && options.maxRequestBytes > AWS_KMS_MAX_RAW_MESSAGE_BYTES) {
    throw new RemoteKmsProviderError(REMOTE_KMS_ERROR_CODES.CONFIG);
  }
  return createRemoteEd25519KmsProvider({ ...options, algorithm: REMOTE_KMS_ALGORITHM, maxRequestBytes: AWS_KMS_MAX_RAW_MESSAGE_BYTES, transport });
}

function awsDerToPem(value) {
  if (!(Buffer.isBuffer(value) || value instanceof Uint8Array) || value.byteLength < 1) throw new Error("invalid AWS KMS public key");
  const key = crypto.createPublicKey({ key: Buffer.from(value), format: "der", type: "spki" });
  if (key.type !== "public" || key.asymmetricKeyType !== REMOTE_KMS_ALGORITHM) throw new Error("invalid AWS KMS public key");
  return key.export({ type: "spki", format: "pem" }).toString();
}
