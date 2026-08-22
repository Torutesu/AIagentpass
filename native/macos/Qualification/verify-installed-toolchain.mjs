#!/usr/bin/env node
import crypto, { createPublicKey, verify } from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const DIGEST = /^[0-9a-f]{64}$/u;
const SAFE_RELATIVE = /^[A-Za-z0-9][A-Za-z0-9._/-]*$/u;
const fail = (message) => { throw new Error(`qualification toolchain refused: ${message}`); };
const sha256 = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");
const canonicalJSON = (value) => `${JSON.stringify(value, Object.keys(value).sort())}\n`;

function snapshot(file, label) {
  let fd;
  try { fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW); } catch { fail(`${label} is unavailable`); }
  try {
    const before = fs.fstatSync(fd, { bigint: true });
    if (!before.isFile() || before.nlink !== 1n || before.uid !== 0n || (before.mode & 0o022n) !== 0n) fail(`${label} is not a protected root-owned file`);
    const bytes = Buffer.alloc(Number(before.size)); let offset = 0;
    while (offset < bytes.length) { const count = fs.readSync(fd, bytes, offset, bytes.length - offset, offset); if (count === 0) fail(`${label} changed while reading`); offset += count; }
    const after = fs.fstatSync(fd, { bigint: true });
    if ([before.dev, before.ino, before.mode, before.nlink, before.size, before.mtimeNs, before.ctimeNs].join(":") !== [after.dev, after.ino, after.mode, after.nlink, after.size, after.mtimeNs, after.ctimeNs].join(":")) fail(`${label} changed while reading`);
    return { bytes, sha256: sha256(bytes) };
  } finally { fs.closeSync(fd); }
}

function protectedDirectory(directory, label) {
  let stat;
  try { stat = fs.lstatSync(directory); } catch { fail(`${label} is unavailable`); }
  if (!stat.isDirectory() || stat.isSymbolicLink() || stat.uid !== 0 || (stat.mode & 0o022) !== 0) fail(`${label} is not protected`);
}

function protectedParentChain(file, root, label) {
  let current = path.dirname(file);
  while (true) {
    protectedDirectory(current, `${label} parent`);
    if (current === root) return;
    if (!current.startsWith(`${root}${path.sep}`)) fail(`${label} escapes the toolchain root`);
    current = path.dirname(current);
  }
}

function verifyManifestSignature(bytes, signatureFile, publicKeyFile, expectedFingerprint) {
  if (!/^SHA256:[A-Za-z0-9_-]{43}$/u.test(expectedFingerprint ?? "")) fail("toolchain manifest public-key fingerprint is invalid");
  const signature = snapshot(signatureFile, "toolchain manifest signature");
  const publicKey = snapshot(publicKeyFile, "toolchain manifest public key");
  let key; try { key = createPublicKey(publicKey.bytes); } catch { fail("toolchain manifest public key is invalid"); }
  if (key.asymmetricKeyType !== "ed25519") fail("toolchain manifest public key must be Ed25519");
  const fingerprint = `SHA256:${crypto.createHash("sha256").update(key.export({ type: "spki", format: "der" })).digest("base64url")}`;
  if (fingerprint !== expectedFingerprint) fail("toolchain manifest public-key fingerprint mismatch");
  const encoded = signature.bytes.toString("ascii");
  if (!/^(?:[A-Za-z0-9+/]{4}){21}[A-Za-z0-9+/]{2}==\n$/u.test(encoded)) fail("toolchain manifest signature encoding is invalid");
  if (!verify(null, bytes, key, Buffer.from(encoded.trim(), "base64"))) fail("toolchain manifest signature is invalid");
  return fingerprint;
}

export function verifyInstalledToolchain(root, expectedManifestSha256, expectedFingerprint) {
  if (typeof root !== "string" || !path.isAbsolute(root) || path.resolve(root) !== root) fail("root must be a normalized absolute path");
  if (!DIGEST.test(expectedManifestSha256 ?? "")) fail("expected manifest digest is invalid");
  protectedDirectory(root, "toolchain root");
  const manifestPath = path.join(root, "manifest.json");
  const manifest = snapshot(manifestPath, "toolchain manifest");
  if (manifest.sha256 !== expectedManifestSha256) fail("toolchain manifest digest does not match the protected environment binding");
  const manifestFingerprint = verifyManifestSignature(manifest.bytes, path.join(root, "manifest.sig"), path.join(root, "manifest.pub"), expectedFingerprint);
  let value; try { value = JSON.parse(manifest.bytes.toString("utf8")); } catch { fail("toolchain manifest is not JSON"); }
  if (JSON.stringify(value) + "\n" !== manifest.bytes.toString("utf8")) fail("toolchain manifest is not canonical JSON");
  const keys = Object.keys(value).sort(); if (keys.join(",") !== "entrypoint,files,schema_version,verifier") fail("toolchain manifest has unexpected fields");
  if (value.schema_version !== 1 || typeof value.entrypoint !== "string" || typeof value.verifier !== "string" || !Array.isArray(value.files) || value.files.length === 0) fail("toolchain manifest is invalid");
  const names = new Set();
  for (const item of value.files) {
    if (!item || typeof item !== "object" || Object.keys(item).sort().join(",") !== "path,sha256" || !SAFE_RELATIVE.test(item.path) || item.path.startsWith("/") || item.path.includes("..") || !DIGEST.test(item.sha256) || names.has(item.path)) fail("toolchain file binding is invalid");
    names.add(item.path);
    const file = path.join(root, item.path);
    protectedParentChain(file, root, `toolchain file ${item.path}`);
    const inspected = snapshot(file, `toolchain file ${item.path}`);
    if (inspected.sha256 !== item.sha256) fail(`toolchain file ${item.path} digest mismatch`);
  }
  for (const name of [value.entrypoint, value.verifier]) if (!names.has(name)) fail(`${name} is not included in the manifest`);
  const actualEntries = fs.readdirSync(root).sort();
  const expectedEntries = ["manifest.json", "manifest.pub", "manifest.sig", ...[...names].sort()].sort();
  if (actualEntries.length !== expectedEntries.length || actualEntries.some((entry, index) => entry !== expectedEntries[index])) fail("toolchain root contains an unexpected entry");
  return Object.freeze({ root, manifest_sha256: manifest.sha256, manifest_public_key_fingerprint: manifestFingerprint, entrypoint: path.join(root, value.entrypoint), verifier: path.join(root, value.verifier), file_count: value.files.length });
}

if (import.meta.url === `file://${process.argv[1]}`) {
  try { const result = verifyInstalledToolchain(process.argv[2], process.argv[3], process.argv[4]); process.stdout.write(`${JSON.stringify({ ok: true, ...result })}\n`); } catch (error) { process.stderr.write(`${error.message}\n`); process.exitCode = 1; }
}
