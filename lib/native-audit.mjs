import crypto from "node:crypto";
import { canonicalJson } from "./identity.mjs";

const P256_ALGORITHM = "ecdsa-sha2-nistp256";
const P256_CURVE = "nistp256";

export function parseNativeAuditPublicKey(value) {
  if (typeof value !== "string") throw new Error("Native audit public key is invalid");
  const fields = value.trim().split(/\s+/);
  if (fields.length < 2 || fields[0] !== P256_ALGORITHM || !isCanonicalBase64(fields[1])) throw new Error("Native audit public key must be an OpenSSH P-256 key");
  const blob = Buffer.from(fields[1], "base64");
  const cursor = { offset: 0 };
  const algorithm = readSSHString(blob, cursor).toString("utf8");
  const curve = readSSHString(blob, cursor).toString("utf8");
  const point = readSSHString(blob, cursor);
  if (cursor.offset !== blob.length || algorithm !== P256_ALGORITHM || curve !== P256_CURVE || point.length !== 65 || point[0] !== 0x04) throw new Error("Native audit public key encoding is invalid");
  const key = crypto.createPublicKey({
    key: { kty: "EC", crv: "P-256", x: point.subarray(1, 33).toString("base64url"), y: point.subarray(33, 65).toString("base64url") },
    format: "jwk"
  });
  return { authorizedKey: `${P256_ALGORITHM} ${fields[1]}`, key, point };
}

export function nativeAuditPublicKeyFingerprint(value) {
  const { point } = typeof value === "object" && Buffer.isBuffer(value.point) ? value : parseNativeAuditPublicKey(value);
  return `SHA256:${crypto.createHash("sha256").update(point).digest("base64url")}`;
}

export function verifyNativeCheckpointRecord(record, publicKey, { previousCheckpointHash } = {}) {
  if (!record || typeof record !== "object" || Array.isArray(record)) throw checkpointError("invalid_record");
  let parsed;
  try { parsed = typeof publicKey === "object" && publicKey.key ? publicKey : parseNativeAuditPublicKey(publicKey); }
  catch { throw checkpointError("public_key_invalid"); }
  const statement = {
    version: record.version,
    created_at: record.created_at,
    entries: record.entries,
    head_hash: record.head_hash,
    previous_checkpoint_hash: record.previous_checkpoint_hash
  };
  if (statement.version !== 1 || !Number.isFinite(Date.parse(statement.created_at))) throw checkpointError("invalid_statement");
  if (!Number.isSafeInteger(statement.entries) || statement.entries < 0 || !isHash(statement.head_hash) || !isHash(statement.previous_checkpoint_hash)) throw checkpointError("invalid_statement");
  if (previousCheckpointHash !== undefined && statement.previous_checkpoint_hash !== previousCheckpointHash) throw checkpointError("checkpoint_chain_invalid");
  if (record.public_key_fingerprint !== nativeAuditPublicKeyFingerprint(parsed)) throw checkpointError("public_key_mismatch");
  if (typeof record.signature !== "string" || !isCanonicalBase64(record.signature)) throw checkpointError("signature_encoding_invalid");
  let signatureValid = false;
  try {
    const signature = Buffer.from(record.signature, "base64");
    signatureValid = signature.length === 64 && crypto.verify("sha256", Buffer.from(canonicalJson(statement)), { key: parsed.key, dsaEncoding: "ieee-p1363" }, signature);
  } catch {}
  if (!signatureValid) throw checkpointError("signature_invalid");
  const copy = { ...statement, public_key_fingerprint: record.public_key_fingerprint, signature: record.signature };
  if (sha256Canonical(copy) !== record.checkpoint_hash) throw checkpointError("checkpoint_hash_invalid");
  return { ...copy, checkpoint_hash: record.checkpoint_hash };
}

function readSSHString(blob, cursor) {
  if (cursor.offset + 4 > blob.length) throw new Error("Native audit public key is truncated");
  const length = blob.readUInt32BE(cursor.offset);
  cursor.offset += 4;
  if (length > blob.length - cursor.offset) throw new Error("Native audit public key field is truncated");
  const value = blob.subarray(cursor.offset, cursor.offset + length);
  cursor.offset += length;
  return value;
}

function isCanonicalBase64(value) {
  if (typeof value !== "string" || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) return false;
  try { return Buffer.from(value, "base64").toString("base64") === value; }
  catch { return false; }
}

function isHash(value) { return typeof value === "string" && /^[0-9a-f]{64}$/.test(value); }
function sha256Canonical(value) { return crypto.createHash("sha256").update(canonicalJson(value)).digest("hex"); }
function checkpointError(code) {
  const error = new Error(`Native audit checkpoint is invalid: ${code}`);
  error.code = code;
  return error;
}
