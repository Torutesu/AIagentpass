import {
  assertBoundRemoteKmsRequest,
  createRemoteEd25519KmsProvider,
  REMOTE_KMS_ALGORITHM,
  REMOTE_KMS_ERROR_CODES,
  REMOTE_KMS_VERSION,
  RemoteKmsProviderError
} from "./remote-kms-provider.mjs";

export const GCP_CLOUD_KMS_ED25519_SIGNING_ALGORITHM = "EC_SIGN_ED25519";
export const GCP_CLOUD_KMS_HSM_MAX_DATA_BYTES = 8 * 1024;

/**
 * Thin Google Cloud KMS adapter. The injected client is a narrow wrapper over
 * the official client: getPublicKey(request, { signal }) and
 * asymmetricSign(request, { signal }). No Google SDK dependency is imported.
 */
export function createGcpCloudKmsEd25519Transport({ client, keyName, purpose, version = REMOTE_KMS_VERSION } = {}) {
  if (!client || typeof client.getPublicKey !== "function" || typeof client.asymmetricSign !== "function") {
    throw new RemoteKmsProviderError(REMOTE_KMS_ERROR_CODES.CONFIG);
  }
  const binding = Object.freeze({ key_id: keyName, purpose, algorithm: REMOTE_KMS_ALGORITHM, version });
  return Object.freeze({
    async getPublicKey(request, { signal } = {}) {
      assertBoundRemoteKmsRequest(request, binding);
      const response = await client.getPublicKey({ name: keyName }, { signal });
      const value = unaryResponse(response);
      if (typeof value?.pem !== "string" || value.name !== keyName
        || value.algorithm !== GCP_CLOUD_KMS_ED25519_SIGNING_ALGORITHM || value.protectionLevel !== "HSM") {
        throw new Error("invalid Google Cloud KMS public key");
      }
      return { key_id: keyName, algorithm: REMOTE_KMS_ALGORITHM, public_key: value.pem };
    },
    async sign(request, { signal } = {}) {
      // Cloud HSM accepts at most 8 KiB of user-provided data. `data` is sent
      // as-is for PureEdDSA; no prehashing, truncation, or padding is allowed.
      assertBoundRemoteKmsRequest(request, binding, { signing: true, maxRequestBytes: GCP_CLOUD_KMS_HSM_MAX_DATA_BYTES });
      const response = await client.asymmetricSign({ name: keyName, data: Buffer.from(request.bytes), algorithm: GCP_CLOUD_KMS_ED25519_SIGNING_ALGORITHM }, { signal });
      const value = unaryResponse(response);
      if (value?.name !== keyName || value?.protectionLevel !== "HSM") throw new Error("Google Cloud KMS signing key substitution");
      return decodeSignature(value?.signature);
    }
  });
}

export function createGcpCloudKmsEd25519Provider(options = {}) {
  const transport = createGcpCloudKmsEd25519Transport(options);
  if (options.maxRequestBytes !== undefined && options.maxRequestBytes > GCP_CLOUD_KMS_HSM_MAX_DATA_BYTES) {
    throw new RemoteKmsProviderError(REMOTE_KMS_ERROR_CODES.CONFIG);
  }
  return createRemoteEd25519KmsProvider({ ...options, keyId: options.keyName, algorithm: REMOTE_KMS_ALGORITHM, maxRequestBytes: GCP_CLOUD_KMS_HSM_MAX_DATA_BYTES, transport });
}

function unaryResponse(value) {
  if (Array.isArray(value) && value.length === 1) return value[0];
  if (value && typeof value === "object" && !Array.isArray(value)) return value;
  throw new Error("invalid Google Cloud KMS response");
}

function decodeSignature(value) {
  if (Buffer.isBuffer(value) || value instanceof Uint8Array) return Buffer.from(value);
  if (typeof value !== "string" || value.length === 0 || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u.test(value)) throw new Error("invalid Google Cloud KMS signature");
  return Buffer.from(value, "base64");
}
