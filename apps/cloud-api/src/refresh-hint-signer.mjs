import crypto from "node:crypto";

import {
  PROTOCOL_VERSION,
  REFRESH_HINT_SIGNATURE_ALGORITHM,
  REFRESH_HINT_SIGNATURE_DOMAIN,
  REFRESH_HINT_TYPE
} from "../../../packages/protocol/src/index.mjs";

const KEY_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$/u;
const MAX_SIGNING_BYTES = 20 * 1024;
const DOMAIN = Buffer.from(REFRESH_HINT_SIGNATURE_DOMAIN, "utf8");

export const REFRESH_HINT_SIGNER_ERROR_CODES = Object.freeze({
  CONFIG: "ERR_REFRESH_SIGNER_CONFIG",
  INPUT: "ERR_REFRESH_SIGNER_INPUT",
  FAILURE: "ERR_REFRESH_SIGNER_FAILURE"
});

export class RefreshHintSignerError extends Error {
  constructor(code) {
    super(code === REFRESH_HINT_SIGNER_ERROR_CODES.CONFIG ? "refresh hint signer configuration is invalid"
      : code === REFRESH_HINT_SIGNER_ERROR_CODES.INPUT ? "refresh hint signing input is invalid"
        : "refresh hint signing failed");
    this.name = "RefreshHintSignerError";
    this.code = code;
  }
}

/**
 * Local provider used by evaluation and as the conformance reference for a
 * future KMS/HSM adapter. It is intentionally an exact-domain signing oracle.
 */
export function createEd25519RefreshHintSigner({ privateKey, keyId } = {}) {
  let key;
  try { key = privateKey?.type === "private" ? privateKey : crypto.createPrivateKey(privateKey); }
  catch { throw new RefreshHintSignerError(REFRESH_HINT_SIGNER_ERROR_CODES.CONFIG); }
  if (key.asymmetricKeyType !== "ed25519" || !KEY_ID.test(keyId ?? "")) {
    throw new RefreshHintSignerError(REFRESH_HINT_SIGNER_ERROR_CODES.CONFIG);
  }
  const publicKey = crypto.createPublicKey(key);
  const metadata = Object.freeze({
    key_id: keyId,
    algorithm: REFRESH_HINT_SIGNATURE_ALGORITHM,
    public_key: publicKey
  });

  async function signRefreshHint(input) {
    if ((!Buffer.isBuffer(input) && !(input instanceof Uint8Array)) || input.byteLength <= DOMAIN.length || input.byteLength > MAX_SIGNING_BYTES) {
      throw new RefreshHintSignerError(REFRESH_HINT_SIGNER_ERROR_CODES.INPUT);
    }
    const bytes = Buffer.from(input);
    if (!bytes.subarray(0, DOMAIN.length).equals(DOMAIN)) throw new RefreshHintSignerError(REFRESH_HINT_SIGNER_ERROR_CODES.INPUT);
    try {
      const signature = crypto.sign(null, bytes, key);
      if (signature.length !== 64) throw new Error("invalid signature length");
      return signature;
    } catch (error) {
      if (error instanceof RefreshHintSignerError) throw error;
      throw new RefreshHintSignerError(REFRESH_HINT_SIGNER_ERROR_CODES.FAILURE);
    }
  }

  return Object.freeze({
    publicKeyMetadata: async () => metadata,
    signRefreshHint
  });
}

/**
 * Hosted refresh-hint signer backed by the same closed managed-provider
 * boundary as the other Cloud signing purposes. The adapter accepts no local
 * key material and asks the provider to sign the exact domain-prefixed bytes.
 */
export function createManagedRefreshHintSigner({ provider, keyId } = {}) {
  if (!provider || typeof provider.publicKeyMetadata !== "function" || typeof provider.sign !== "function"
    || !KEY_ID.test(keyId ?? "")
    || (provider.key_id !== undefined && provider.key_id !== keyId)
    || (provider.purpose !== undefined && provider.purpose !== REFRESH_HINT_TYPE)
    || (provider.algorithm !== undefined && provider.algorithm !== REFRESH_HINT_SIGNATURE_ALGORITHM)
    || (provider.version !== undefined && provider.version !== PROTOCOL_VERSION)) {
    throw new RefreshHintSignerError(REFRESH_HINT_SIGNER_ERROR_CODES.CONFIG);
  }
  const binding = Object.freeze({
    algorithm: REFRESH_HINT_SIGNATURE_ALGORITHM,
    key_id: keyId,
    purpose: REFRESH_HINT_TYPE,
    version: PROTOCOL_VERSION
  });

  async function publicKeyMetadata() {
    let value;
    try { value = await provider.publicKeyMetadata(binding); }
    catch { throw new RefreshHintSignerError(REFRESH_HINT_SIGNER_ERROR_CODES.FAILURE); }
    try {
      if (!value || typeof value !== "object" || Array.isArray(value)
        || Object.keys(value).sort().join(",") !== "algorithm,key_id,public_key"
        || value.key_id !== keyId || value.algorithm !== REFRESH_HINT_SIGNATURE_ALGORITHM
        || (typeof value.public_key === "string" && /PRIVATE\s+KEY/iu.test(value.public_key))
        || value.public_key?.type === "private") throw new Error("invalid metadata");
      const key = value.public_key?.type === "public" ? value.public_key : crypto.createPublicKey(value.public_key);
      if (key.type !== "public" || key.asymmetricKeyType !== "ed25519") throw new Error("invalid key");
      return Object.freeze({
        key_id: keyId,
        algorithm: REFRESH_HINT_SIGNATURE_ALGORITHM,
        public_key: key.export({ type: "spki", format: "pem" }).toString()
      });
    } catch {
      throw new RefreshHintSignerError(REFRESH_HINT_SIGNER_ERROR_CODES.FAILURE);
    }
  }

  async function signRefreshHint(input) {
    const bytes = normalizeSigningBytes(input);
    let signature;
    try { signature = await provider.sign({ ...binding, bytes }); }
    catch { throw new RefreshHintSignerError(REFRESH_HINT_SIGNER_ERROR_CODES.FAILURE); }
    if (!(Buffer.isBuffer(signature) || signature instanceof Uint8Array) || signature.byteLength !== 64) {
      throw new RefreshHintSignerError(REFRESH_HINT_SIGNER_ERROR_CODES.FAILURE);
    }
    return Buffer.from(signature);
  }

  return Object.freeze({
    key_id: keyId,
    publicKeyMetadata,
    signRefreshHint,
    async verificationKeyMetadata() {
      const metadata = await publicKeyMetadata();
      const fingerprint = publicKeyFingerprint(metadata.public_key);
      return Object.freeze({
        version: 1,
        purpose: REFRESH_HINT_TYPE,
        active_key_id: keyId,
        keys: Object.freeze([Object.freeze({
          key_id: keyId,
          algorithm: REFRESH_HINT_SIGNATURE_ALGORITHM,
          public_key: metadata.public_key,
          public_key_fingerprint: fingerprint,
          status: "active"
        })])
      });
    },
    async health() {
      try {
        const metadata = await publicKeyMetadata();
        return Object.freeze({
          ready: metadata.key_id === keyId,
          purpose: REFRESH_HINT_TYPE,
          algorithm: REFRESH_HINT_SIGNATURE_ALGORITHM,
          key_id: keyId,
          public_key_fingerprint: publicKeyFingerprint(metadata.public_key)
        });
      } catch {
        return Object.freeze({ ready: false, purpose: REFRESH_HINT_TYPE, algorithm: REFRESH_HINT_SIGNATURE_ALGORITHM, key_id: keyId, public_key_fingerprint: null });
      }
    }
  });
}

function publicKeyFingerprint(publicKey) {
  const key = crypto.createPublicKey(publicKey);
  return crypto.createHash("sha256").update(key.export({ type: "spki", format: "der" })).digest("hex");
}

function normalizeSigningBytes(input) {
  if ((!Buffer.isBuffer(input) && !(input instanceof Uint8Array)) || input.byteLength <= DOMAIN.length || input.byteLength > MAX_SIGNING_BYTES) {
    throw new RefreshHintSignerError(REFRESH_HINT_SIGNER_ERROR_CODES.INPUT);
  }
  const bytes = Buffer.from(input);
  if (!bytes.subarray(0, DOMAIN.length).equals(DOMAIN)) throw new RefreshHintSignerError(REFRESH_HINT_SIGNER_ERROR_CODES.INPUT);
  return bytes;
}

export default createEd25519RefreshHintSigner;
