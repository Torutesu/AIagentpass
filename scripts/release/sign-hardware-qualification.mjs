#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import { resolve } from "node:path";

const REPORT_KEYS = [
  "schema_version", "source_commit", "dependency_lock_sha256", "release_manifest_sha256", "artifact_name", "artifact_sha256",
  "architecture", "hardware_class", "model_identifier", "macos_version", "macos_build", "secure_enclave", "team_id",
  "nested_code_identities", "notarization", "cloud_image_digest", "database_migration_manifest_sha256", "signer_key_versions",
  "browser_versions", "started_at", "completed_at", "operator", "operator_key_fingerprint", "qualified", "tests", "gates"
];
const FINGERPRINT = /^SHA256:[A-Za-z0-9_-]{43}$/u;
const COMMIT = /^[0-9a-f]{40}$/u;
const DIGEST = /^[0-9a-f]{64}$/u;
const SAFE_NAME = /^[0-9A-Za-z][0-9A-Za-z._-]*$/u;
const OPERATOR = /^[A-Za-z0-9][A-Za-z0-9@._-]{2,127}$/u;
const MAX_REPORT_BYTES = 4 * 1024 * 1024;
const MAX_KEY_BYTES = 16 * 1024;

export function signHardwareQualification({ reportPath, privateKeyPath, signaturePath, publicKeyPath, expectedFingerprint } = {}) {
  const report = readStableFile(reportPath, MAX_REPORT_BYTES, "hardware qualification report");
  const reportValue = parseCanonicalReport(report);
  const publicPathProvided = publicKeyPath !== undefined;
  const fingerprintProvided = expectedFingerprint !== undefined;
  if (publicPathProvided !== fingerprintProvided) throw new Error("public key and expected fingerprint must be provided together");
  if (!publicPathProvided) throw new Error("operator public key and expected fingerprint are required");
  if (typeof expectedFingerprint !== "string" || !FINGERPRINT.test(expectedFingerprint)) throw new Error("expected operator fingerprint is invalid");
  if (reportValue.operator_key_fingerprint !== expectedFingerprint) throw new Error("operator fingerprint does not match the report");

  const privateBytes = readPrivateKey(privateKeyPath);
  let privateKey;
  try { privateKey = crypto.createPrivateKey(privateBytes); }
  catch (error) { throw new Error("operator private key is invalid", { cause: error }); }
  finally { privateBytes.fill(0); }
  if (privateKey.asymmetricKeyType !== "ed25519") throw new Error("operator private key must be Ed25519");

  const publicBytes = readStableFile(publicKeyPath, MAX_KEY_BYTES, "operator public key");
  let publicKey;
  try { publicKey = crypto.createPublicKey(publicBytes); }
  catch (error) { throw new Error("operator public key is invalid", { cause: error }); }
  if (publicKey.asymmetricKeyType !== "ed25519") throw new Error("operator public key must be Ed25519");
  const derivedPublicKey = crypto.createPublicKey(privateKey);
  if (!derivedPublicKey.export({ type: "spki", format: "der" }).equals(publicKey.export({ type: "spki", format: "der" }))) throw new Error("operator public key does not match the private key");
  const actualFingerprint = publicKeyFingerprint(publicKey);
  if (actualFingerprint !== expectedFingerprint || actualFingerprint !== reportValue.operator_key_fingerprint) throw new Error("operator public key fingerprint does not match the report");

  const signature = crypto.sign(null, report, privateKey);
  if (signature.length !== 64) throw new Error("Ed25519 signature has an invalid length");
  const output = requireAbsolutePath(signaturePath, "signature output");
  const encoded = Buffer.from(`${signature.toString("base64")}\n`, "utf8");
  writeExclusive(output, encoded, 0o600);
  return Object.freeze({ output_path: output, signature_bytes: signature.length, fingerprint: actualFingerprint });
}

function parseCanonicalReport(bytes) {
  let text;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch (error) { throw new Error("hardware qualification report is not valid UTF-8", { cause: error }); }
  let value;
  try { value = JSON.parse(text); }
  catch (error) { throw new Error("hardware qualification report is not valid JSON", { cause: error }); }
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("hardware qualification report must be an object");
  if (JSON.stringify(Object.keys(value).sort()) !== JSON.stringify([...REPORT_KEYS].sort())) throw new Error("hardware qualification report schema keys are invalid");
  if (value.schema_version !== 2 || !COMMIT.test(value.source_commit) || typeof value.operator !== "string" || !OPERATOR.test(value.operator) || !FINGERPRINT.test(value.operator_key_fingerprint) || typeof value.qualified !== "boolean" || !Array.isArray(value.tests) || !Array.isArray(value.gates)) throw new Error("hardware qualification report structure is invalid");
  for (const field of ["dependency_lock_sha256", "release_manifest_sha256", "artifact_sha256", "database_migration_manifest_sha256"]) if (!DIGEST.test(value[field])) throw new Error(`hardware qualification report has invalid ${field}`);
  const canonical = Buffer.from(`${JSON.stringify(value, null, 2)}\n`, "utf8");
  if (!bytes.equals(canonical)) throw new Error("hardware qualification report is not canonical JSON");
  return value;
}

function readPrivateKey(value) {
  const data = readStableFile(value, MAX_KEY_BYTES, "operator private key", { requirePrivateMode: true });
  return data;
}

function readStableFile(value, maximum, label, { requirePrivateMode = false } = {}) {
  const file = requireAbsolutePath(value, label);
  const noFollow = fs.constants.O_NOFOLLOW;
  if (!Number.isInteger(noFollow)) throw new Error("O_NOFOLLOW is unavailable on this platform");
  let descriptor;
  try { descriptor = fs.openSync(file, fs.constants.O_RDONLY | noFollow); }
  catch (error) { throw new Error(`cannot open ${label}`, { cause: error }); }
  try {
    const before = fs.fstatSync(descriptor, { bigint: true });
    if (!before.isFile() || before.nlink !== 1n || before.size <= 0n || before.size > BigInt(maximum) || before.size > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error(`${label} must be a nonempty single-link regular file`);
    if (requirePrivateMode && (before.mode & 0o777n) !== 0o600n) throw new Error("operator private key must have mode 0600");
    if (requirePrivateMode && typeof process.getuid === "function" && before.uid !== BigInt(process.getuid())) throw new Error("operator private key must be owned by the current user");
    const data = Buffer.alloc(Number(before.size));
    let offset = 0;
    while (offset < data.length) {
      const count = fs.readSync(descriptor, data, offset, data.length - offset, offset);
      if (count === 0) throw new Error(`${label} changed while reading`);
      offset += count;
    }
    const after = fs.fstatSync(descriptor, { bigint: true });
    if (statIdentity(before) !== statIdentity(after)) throw new Error(`${label} changed while reading`);
    return data;
  } finally { fs.closeSync(descriptor); }
}

function statIdentity(stat) {
  return [stat.dev, stat.ino, stat.mode, stat.nlink, stat.size, stat.mtimeNs, stat.ctimeNs].join(":");
}

function publicKeyFingerprint(publicKey) {
  return `SHA256:${crypto.createHash("sha256").update(publicKey.export({ type: "spki", format: "der" })).digest("base64url")}`;
}

function writeExclusive(output, bytes, mode) {
  const noFollow = fs.constants.O_NOFOLLOW;
  if (!Number.isInteger(noFollow)) throw new Error("O_NOFOLLOW is unavailable on this platform");
  let descriptor;
  try {
    descriptor = fs.openSync(output, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | noFollow, mode);
    let offset = 0;
    while (offset < bytes.length) offset += fs.writeSync(descriptor, bytes, offset, bytes.length - offset);
    fs.fsyncSync(descriptor);
  } catch (error) { throw new Error(`cannot write signature output: ${output}`, { cause: error }); }
  finally { if (descriptor !== undefined) fs.closeSync(descriptor); }
}

function requireAbsolutePath(value, label) {
  if (typeof value !== "string" || !value || !value.startsWith("/")) throw new Error(`${label} must be an absolute path`);
  return resolve(value);
}

function parseArguments(argv) {
  const values = new Map();
  for (let index = 0; index < argv.length; index += 2) {
    const name = argv[index];
    const value = argv[index + 1];
    if (!["--report", "--private-key", "--signature", "--public-key", "--expected-fingerprint"].includes(name) || value === undefined || value.startsWith("--") || values.has(name)) throw new Error("Usage: sign-hardware-qualification.mjs --report REPORT --private-key PRIVATE-KEY --signature SIGNATURE --public-key PUBLIC-KEY --expected-fingerprint FINGERPRINT");
    values.set(name, value);
  }
  if (values.size !== 5) throw new Error("Usage: sign-hardware-qualification.mjs --report REPORT --private-key PRIVATE-KEY --signature SIGNATURE --public-key PUBLIC-KEY --expected-fingerprint FINGERPRINT");
  return values;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  try {
    const values = parseArguments(process.argv.slice(2));
    const result = signHardwareQualification({ reportPath: values.get("--report"), privateKeyPath: values.get("--private-key"), signaturePath: values.get("--signature"), publicKeyPath: values.get("--public-key"), expectedFingerprint: values.get("--expected-fingerprint") });
    console.log(JSON.stringify({ ok: true, signature_bytes: result.signature_bytes, operator_key_fingerprint: result.fingerprint }));
  } catch (error) {
    process.stderr.write(`${error instanceof Error ? error.message : "hardware qualification signing failed"}\n`);
    process.exitCode = 1;
  }
}

export function canonicalReportBytes(value) {
  return Buffer.from(`${JSON.stringify(value, null, 2)}\n`, "utf8");
}

export { publicKeyFingerprint };
