import crypto from "node:crypto";
import { canonicalDigest, normalizeSourceBundleStatement } from "../../../../packages/small-software-contracts/src/index.mjs";
import { SmallSoftwareError, SMALL_SOFTWARE_ERROR_CODES } from "./errors.mjs";
import { smallSoftwareSourceStorage } from "./interfaces.mjs";

const MAX_SOURCE_BYTES = 1024 * 1024 * 1024;
const SHA256 = /^[0-9a-f]{64}$/;

const fail = (code, details) => { throw new SmallSoftwareError(code, details); };
const isBytes = (value) => value instanceof Uint8Array || Buffer.isBuffer(value);
const byteLength = (value) => isBytes(value) ? value.byteLength : -1;

/**
 * Validate and call the object-storage boundary. The statement digest is the
 * immutable object identity; storage implementations must verify it again
 * before acknowledging a write. No provider SDK or credential is accepted
 * here.
 */
export function createSmallSoftwareSourceStorage({ storage, profile = "hosted" } = {}) {
  if (profile === "hosted" && storage?.testOnly === true) fail(SMALL_SOFTWARE_ERROR_CODES.INVALID_CONFIGURATION);
  const objects = smallSoftwareSourceStorage(storage);
  return Object.freeze({
    async putBundle({ statement, bytes } = {}) {
      let normalized;
      try { normalized = normalizeSourceBundleStatement(statement); }
      catch (error) { fail(SMALL_SOFTWARE_ERROR_CODES.INVALID_INPUT, { issue: "source_bundle" }); }
      if (!isBytes(bytes) || byteLength(bytes) < 0 || byteLength(bytes) > MAX_SOURCE_BYTES) {
        fail(SMALL_SOFTWARE_ERROR_CODES.INVALID_INPUT, { issue: "source_bytes" });
      }
      const digest = canonicalDigest(normalized);
      let result;
      try {
        result = await objects.put({ digest, statement: normalized, bytes: Buffer.from(bytes) });
      } catch (error) {
        fail(SMALL_SOFTWARE_ERROR_CODES.DEPENDENCY_UNAVAILABLE);
      }
      assertStored(result, digest, byteLength(bytes));
      return Object.freeze({ digest, size: byteLength(bytes), statement: normalized, metadata: result });
    },
    async getBundle(digest) {
      if (typeof digest !== "string" || !SHA256.test(digest)) fail(SMALL_SOFTWARE_ERROR_CODES.INVALID_INPUT, { issue: "digest" });
      let result;
      try { result = await objects.get(digest); }
      catch { fail(SMALL_SOFTWARE_ERROR_CODES.DEPENDENCY_UNAVAILABLE); }
      if (result === undefined || result === null) fail(SMALL_SOFTWARE_ERROR_CODES.OPERATION_NOT_FOUND);
      if (result.digest !== digest) fail(SMALL_SOFTWARE_ERROR_CODES.DIGEST_MISMATCH, { field: "source_bundle" });
      if (!isBytes(result.bytes) || byteLength(result.bytes) > MAX_SOURCE_BYTES) fail(SMALL_SOFTWARE_ERROR_CODES.INVALID_INPUT, { issue: "stored_source" });
      return result;
    },
    async deleteBundle(digest) {
      if (typeof digest !== "string" || !SHA256.test(digest)) fail(SMALL_SOFTWARE_ERROR_CODES.INVALID_INPUT, { issue: "digest" });
      try { return await objects.delete(digest); }
      catch { fail(SMALL_SOFTWARE_ERROR_CODES.DEPENDENCY_UNAVAILABLE); }
    }
  });
}

function assertStored(result, digest, size) {
  if (!result || result.digest !== digest || (result.size !== undefined && result.size !== size)) {
    fail(SMALL_SOFTWARE_ERROR_CODES.DIGEST_MISMATCH, { field: "source_bundle" });
  }
}

/** Small deterministic storage adapter useful for isolated service tests.
 * It is explicitly marked testOnly and must not be passed to a hosted profile.
 */
export function createMemorySmallSoftwareSourceStorage() {
  const objects = new Map();
  return {
    testOnly: true,
    async put({ digest, statement, bytes }) {
      if (!SHA256.test(digest) || !isBytes(bytes)) throw new Error("invalid object");
      const prior = objects.get(digest);
      if (prior) {
        const previous = Buffer.from(prior.bytes);
        const current = Buffer.from(bytes);
        if (previous.length !== current.length || crypto.timingSafeEqual(previous, current) === false) throw new Error("object conflict");
      }
      const value = { digest, size: bytes.byteLength, statement, bytes: Buffer.from(bytes) };
      objects.set(digest, value);
      return { digest, size: value.size };
    },
    async get(digest) { return objects.get(digest); },
    async delete(digest) { objects.delete(digest); return { deleted: true }; }
  };
}
