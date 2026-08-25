import { createHash, createPublicKey, verify } from "node:crypto";
import fs from "node:fs";
import { canonicalJson } from "../../packages/protocol/src/index.mjs";

export const EXTERNAL_QUALIFICATION_TRUST_TYPE = "agentpass.external-qualification-trust";
export const EXTERNAL_QUALIFICATION_TRUST_DOMAIN = "AgentPass-External-Qualification-Trust-v1\0";
const FINGERPRINT = /^SHA256:[A-Za-z0-9_-]{43}$/u;
const SIGNATURE = /^[A-Za-z0-9_-]{86}$/u;
const ID = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/u;
const TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u;
const PAYLOAD_KEYS = ["schema_version", "type", "authority_id", "aggregate_fingerprint", "child_fingerprint", "not_before", "not_after"];
const ENVELOPE_KEYS = [...PAYLOAD_KEYS, "signature_algorithm", "signer_key_fingerprint", "signature"];

function exactObject(value, keys, label) {
  if (value === null || typeof value !== "object" || Array.isArray(value) || JSON.stringify(Object.keys(value).sort()) !== JSON.stringify([...keys].sort())) throw new Error(`${label} has missing or unknown fields`);
}

function publicKeyFromInput(input) {
  if (input instanceof Object && input.type === "private") throw new Error("external qualification trust root must be public");
  if (typeof input === "string" && input.includes("PRIVATE KEY")) throw new Error("external qualification trust root must be public");
  if (Buffer.isBuffer(input)) {
    if (input.includes(Buffer.from("PRIVATE KEY"))) throw new Error("external qualification trust root must be public");
    return input.includes(Buffer.from("BEGIN PUBLIC KEY")) ? createPublicKey({ key: input, format: "pem", type: "spki" }) : createPublicKey({ key: input, format: "der", type: "spki" });
  }
  return createPublicKey(input);
}

export function externalQualificationTrustPublicKeyFingerprint(publicKey) {
  const key = publicKey instanceof Object && publicKey.type === "public" ? publicKey : publicKeyFromInput(publicKey);
  return `SHA256:${createHash("sha256").update(key.export({ type: "spki", format: "der" })).digest("base64url")}`;
}

export function normalizeExternalQualificationTrust(input, { now = Date.now(), allowExpired = false, allowFuture = false } = {}) {
  exactObject(input, ENVELOPE_KEYS, "external qualification trust manifest");
  if (input.schema_version !== 1 || input.type !== EXTERNAL_QUALIFICATION_TRUST_TYPE || input.signature_algorithm !== "ed25519" || !ID.test(input.authority_id) || !FINGERPRINT.test(input.aggregate_fingerprint) || !FINGERPRINT.test(input.child_fingerprint) || input.aggregate_fingerprint === input.child_fingerprint || !TIME.test(input.not_before) || !TIME.test(input.not_after) || !FINGERPRINT.test(input.signer_key_fingerprint) || !SIGNATURE.test(input.signature)) throw new Error("external qualification trust manifest is invalid");
  const notBefore = Date.parse(input.not_before); const notAfter = Date.parse(input.not_after);
  if (!Number.isFinite(notBefore) || !Number.isFinite(notAfter) || notAfter <= notBefore || (!allowFuture && now < notBefore) || (!allowExpired && now >= notAfter)) throw new Error("external qualification trust manifest is outside its validity window");
  return Object.freeze({ ...input });
}

export function externalQualificationTrustSigningData(input) {
  const payload = Object.fromEntries(PAYLOAD_KEYS.map((key) => [key, input[key]]));
  return Buffer.concat([Buffer.from(EXTERNAL_QUALIFICATION_TRUST_DOMAIN, "utf8"), Buffer.from(canonicalJson(payload), "utf8")]);
}

export function verifyExternalQualificationTrustManifest(input, { rootPublicKey, now = Date.now() } = {}) {
  const trust = normalizeExternalQualificationTrust(input, { now });
  const key = rootPublicKey instanceof Object && rootPublicKey.type === "public" ? rootPublicKey : publicKeyFromInput(rootPublicKey);
  if (key.asymmetricKeyType !== "ed25519" || trust.signer_key_fingerprint !== externalQualificationTrustPublicKeyFingerprint(key) || !verify(null, externalQualificationTrustSigningData(trust), key, Buffer.from(trust.signature, "base64url"))) throw new Error("external qualification trust manifest signature is invalid");
  return trust;
}

export function assertExternalQualificationSignerTrust({ trustManifest, publicKey, role, now = Date.now() } = {}) {
  const trust = normalizeExternalQualificationTrust(trustManifest, { now });
  if (role !== "aggregate" && role !== "child") throw new Error("external qualification trust role is invalid");
  const fingerprint = externalQualificationTrustPublicKeyFingerprint(publicKey);
  if (fingerprint !== trust[role === "aggregate" ? "aggregate_fingerprint" : "child_fingerprint"]) throw new Error(`external qualification ${role} signer is not trusted`);
  return Object.freeze({ authority_id: trust.authority_id, role, signer_fingerprint: fingerprint, not_after: trust.not_after });
}

export function readExternalQualificationTrustManifest(filePath, { rootPublicKey, now = Date.now() } = {}) {
  const fd = fs.openSync(filePath, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  try {
    const stat = fs.fstatSync(fd);
    if (!stat.isFile() || stat.nlink !== 1 || stat.size <= 0 || stat.size > 64 * 1024) throw new Error("external qualification trust manifest is unsafe");
    const text = fs.readFileSync(fd, "utf8");
    const value = JSON.parse(text);
    if (text !== canonicalJson(value)) throw new Error("external qualification trust manifest must be canonical JSON");
    return verifyExternalQualificationTrustManifest(value, { rootPublicKey, now });
  } finally { fs.closeSync(fd); }
}
