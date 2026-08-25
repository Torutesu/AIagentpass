import crypto from "node:crypto";

import { canonicalJson } from "../../../../packages/protocol/src/index.mjs";

const IDENTIFIER = /^[a-z0-9][a-z0-9._:-]{0,127}$/u;
const DIGEST = /^[0-9a-f]{64}$/u;

export function createOwnerRecoveryDeliveryBinding({ binding_id, key_version, namespace } = {}) {
  const bindingId = identifier(binding_id);
  const keyVersion = positiveInteger(key_version);
  if (typeof namespace !== "string" || namespace.length < 1 || namespace.length > 4_096) throw new TypeError("owner recovery delivery namespace is invalid");
  const bindingDigest = crypto.createHash("sha256").update(canonicalJson({
    version: 1,
    binding_id: bindingId,
    key_version: keyVersion,
    namespace
  }), "utf8").digest("hex");
  return Object.freeze({ binding_id: bindingId, key_version: keyVersion, binding_digest: bindingDigest });
}

export function normalizeOwnerRecoveryDeliveryBinding(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || Object.keys(value).sort().join(",") !== "binding_digest,binding_id,key_version") throw new TypeError("owner recovery delivery binding is invalid");
  return Object.freeze({
    binding_id: identifier(value.binding_id),
    key_version: positiveInteger(value.key_version),
    binding_digest: digest(value.binding_digest)
  });
}

export function sameOwnerRecoveryDeliveryBinding(left, right) {
  try {
    const a = normalizeOwnerRecoveryDeliveryBinding(left);
    const b = normalizeOwnerRecoveryDeliveryBinding(right);
    return a.binding_id === b.binding_id && a.key_version === b.key_version
      && crypto.timingSafeEqual(Buffer.from(a.binding_digest, "hex"), Buffer.from(b.binding_digest, "hex"));
  } catch {
    return false;
  }
}

function identifier(value) {
  if (typeof value !== "string" || !IDENTIFIER.test(value)) throw new TypeError("owner recovery delivery binding identifier is invalid");
  return value;
}

function positiveInteger(value) {
  if (!Number.isSafeInteger(value) || value < 1 || value > 2_147_483_647) throw new TypeError("owner recovery delivery binding key version is invalid");
  return value;
}

function digest(value) {
  if (typeof value !== "string" || !DIGEST.test(value)) throw new TypeError("owner recovery delivery binding digest is invalid");
  return value;
}
