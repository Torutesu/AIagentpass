#!/usr/bin/env node
import { createHash, createPublicKey, verify } from "node:crypto";
import fs from "node:fs";
import { canonicalJson } from "../../packages/protocol/src/index.mjs";
import { assertExternalQualificationSignerTrust, readExternalQualificationTrustManifest } from "./external-qualification-trust.mjs";

const FINGERPRINT = /^SHA256:[A-Za-z0-9_-]{43}$/u;
const B64_SIGNATURE = /^(?:[A-Za-z0-9+/]{4}){21}[A-Za-z0-9+/]{2}==$/u;

function exactObject(value, label) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error(`${label} must be an object`);
}

function readCanonicalJson(file, label) {
  const text = fs.readFileSync(file, "utf8");
  let value;
  try { value = JSON.parse(text); } catch { throw new Error(`${label} is not JSON`); }
  if (text !== canonicalJson(value)) throw new Error(`${label} must be canonical JSON`);
  exactObject(value, label);
  return value;
}

function readSingleFile(file, label, maximum) {
  const descriptor = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  try {
    const stat = fs.fstatSync(descriptor);
    if (!stat.isFile() || stat.nlink !== 1 || stat.size <= 0 || stat.size > maximum) throw new Error(`${label} is unsafe`);
    return fs.readFileSync(descriptor);
  } finally { fs.closeSync(descriptor); }
}

export function verifyExternalQualificationSignature({ evidence, binding, childEvidence = undefined, signatureBase64, publicKeyBytes, expectedFingerprint, trustManifest = undefined, trustRole = undefined, now = Date.now() }) {
  exactObject(evidence, "external qualification evidence");
  exactObject(binding, "external qualification binding");
  if (childEvidence !== undefined) exactObject(childEvidence, "external qualification child evidence");
  if (typeof signatureBase64 !== "string" || !B64_SIGNATURE.test(signatureBase64)) throw new Error("external qualification signature encoding is invalid");
  if (!Buffer.isBuffer(publicKeyBytes) || publicKeyBytes.length === 0) throw new Error("external qualification public key is missing");
  if (typeof expectedFingerprint !== "string" || !FINGERPRINT.test(expectedFingerprint)) throw new Error("external qualification public key fingerprint is invalid");
  if (publicKeyBytes.includes(Buffer.from("PRIVATE KEY"))) throw new Error("external qualification public key must not contain private key material");
  const publicKey = publicKeyBytes.includes(Buffer.from("BEGIN PUBLIC KEY"))
    ? createPublicKey({ key: publicKeyBytes, format: "pem", type: "spki" })
    : createPublicKey({ key: publicKeyBytes, format: "der", type: "spki" });
  if (publicKey.asymmetricKeyType !== "ed25519") throw new Error("external qualification public key must be Ed25519");
  const fingerprint = `SHA256:${createHash("sha256").update(publicKey.export({ type: "spki", format: "der" })).digest("base64url")}`;
  if (fingerprint !== expectedFingerprint) throw new Error("external qualification public key fingerprint mismatch");
  const trust = trustManifest === undefined ? undefined : assertExternalQualificationSignerTrust({ trustManifest, publicKey, role: trustRole, now });
  const payloadValue = childEvidence === undefined ? { evidence, binding } : { evidence, binding, child_evidence: childEvidence };
  const payload = Buffer.from(canonicalJson(payloadValue), "utf8");
  const signature = Buffer.from(signatureBase64, "base64");
  if (signature.length !== 64 || !verify(null, payload, publicKey, signature)) throw new Error("external qualification signature is invalid");
  return Object.freeze({ verified: true, fingerprint, payload_sha256: createHash("sha256").update(payload).digest("hex"), ...(trust ? { trust } : {}) });
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const [evidencePath, bindingPath, signaturePath, publicKeyPath, expectedFingerprint, childEvidencePath, trustManifestPath, trustRootPublicKeyPath, trustRole] = process.argv.slice(2);
  if (!evidencePath || !bindingPath || !signaturePath || !publicKeyPath || !expectedFingerprint || process.argv.slice(2).length > 9) throw new Error("Usage: verify-external-qualification-signature.mjs EVIDENCE BINDING SIGNATURE PUBLIC-KEY EXPECTED-FINGERPRINT [CHILD-EVIDENCE TRUST-MANIFEST TRUST-ROOT-PUBLIC-KEY ROLE]");
  if (Boolean(trustManifestPath) !== Boolean(trustRootPublicKeyPath) || Boolean(trustManifestPath) !== Boolean(trustRole)) throw new Error("trust manifest, trust root public key, and trust role must be supplied together");
  const evidence = readCanonicalJson(evidencePath, "external qualification evidence");
  const binding = readCanonicalJson(bindingPath, "external qualification binding");
  const childEvidence = childEvidencePath ? readCanonicalJson(childEvidencePath, "external qualification child evidence") : undefined;
  const signatureText = readSingleFile(signaturePath, "external qualification signature", 1024).toString("utf8").trim();
  const publicKeyBytes = readSingleFile(publicKeyPath, "external qualification public key", 16 * 1024);
  const trustManifest = trustManifestPath ? readExternalQualificationTrustManifest(trustManifestPath, { rootPublicKey: readSingleFile(trustRootPublicKeyPath, "external qualification trust root public key", 16 * 1024) }) : undefined;
  process.stdout.write(`${JSON.stringify(verifyExternalQualificationSignature({ evidence, binding, childEvidence, signatureBase64: signatureText, publicKeyBytes, expectedFingerprint, trustManifest, trustRole }))}\n`);
}
