import crypto from "node:crypto";

import {
  REFRESH_HINT_SIGNATURE_ALGORITHM,
  REFRESH_HINT_SIGNATURE_DOMAIN
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

export default createEd25519RefreshHintSigner;
