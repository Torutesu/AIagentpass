#!/usr/bin/env node

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { canonicalJson } from "../../packages/protocol/src/index.mjs";

export const CURSOR_AGENT_RUNTIME_ID = "cursor-agent";
export const CURSOR_AGENT_RUNTIME_SCHEMA_VERSION = 1;
export const CURSOR_AGENT_RUNTIME_SIGNATURE_DOMAIN = "AgentPass-Cursor-Agent-Runtime-Manifest-v1\0";
export const CURSOR_AGENT_RUNTIME_DESTINATION_PARENT = "/Library/Application Support/AgentPass/CursorAgent";
export const CURSOR_AGENT_RUNTIME_TRUST_PARENT = "/Library/Application Support/AgentPass/Trust";
export const CURSOR_AGENT_RUNTIME_TRUST_CONFIG_NAME = "cursor-agent-runtime-key-v1.json";
export const CURSOR_AGENT_RUNTIME_TRUST_CONFIG_PATH = `${CURSOR_AGENT_RUNTIME_TRUST_PARENT}/${CURSOR_AGENT_RUNTIME_TRUST_CONFIG_NAME}`;
export const CURSOR_AGENT_RUNTIME_DIRECTORY_NAME = "runtime";
export const CURSOR_AGENT_RUNTIME_MANIFEST_NAME = "runtime-manifest.json";
export const CURSOR_AGENT_RUNTIME_NODE_NAME = "node";
export const CURSOR_AGENT_RUNTIME_INDEX_NAME = "index.js";
export const CURSOR_AGENT_RUNTIME_MAX_FILES = 4_096;
export const CURSOR_AGENT_RUNTIME_MAX_DIRECTORIES = 4_096;
export const CURSOR_AGENT_RUNTIME_MAX_INVENTORY_ENTRIES = 8_192;
export const CURSOR_AGENT_RUNTIME_MAX_FILE_BYTES = 256 * 1024 * 1024;
export const CURSOR_AGENT_RUNTIME_MAX_BYTES = 512 * 1024 * 1024;
export const CURSOR_AGENT_RUNTIME_MAX_MANIFEST_BYTES = 2 * 1024 * 1024;
export const CURSOR_AGENT_RUNTIME_PUBLIC_KEY_BYTES = 44;
export const CURSOR_AGENT_RUNTIME_PRIVATE_KEY_MAX_BYTES = 16 * 1024;

const NOFOLLOW = fs.constants.O_NOFOLLOW;
const DIRECTORY = fs.constants.O_DIRECTORY ?? 0;
const SHA256 = /^[0-9a-f]{64}$/u;
const RELEASE_DIGEST = /^sha256:[0-9a-f]{64}$/u;
const SAFE_KEY_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u;
const SAFE_RUNTIME_VERSION = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u;
const BASE64URL_SIGNATURE = /^[A-Za-z0-9_-]{86}$/u;
const CONTROL = /[\u0000-\u001f\u007f\u2028\u2029\r\n]/u;
const RAW_PATH_SEGMENT = /^(?:credential|credentials|secret|secrets|token|tokens|log|logs)$/iu;
const RAW_PATH_BASENAME = /^(?:credential|credentials|secret|secrets|token|tokens)(?:[._-].*)?$/iu;
const RAW_PATH_SUFFIX = /(?:^|\.)log(?:\.[0-9]+)?$/iu;

if (!Number.isInteger(NOFOLLOW)) {
  throw new Error("cursor runtime materializer requires O_NOFOLLOW");
}

export class CursorRuntimeMaterializerError extends Error {
  constructor(code, message = code) {
    super(message);
    this.name = "CursorRuntimeMaterializerError";
    this.code = code;
  }
}

function fail(code, message = code) {
  throw new CursorRuntimeMaterializerError(code, message);
}

function exactKeys(value, expected, label) {
  if (value === null || typeof value !== "object" || Array.isArray(value)
    || Object.getPrototypeOf(value) !== Object.prototype) {
    fail("invalid_manifest", `${label} shape is invalid`);
  }
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) {
    fail("invalid_manifest", `${label} fields are invalid`);
  }
}

function absolutePath(value, label) {
  if (typeof value !== "string" || value.length === 0 || value.includes("\0") || !path.isAbsolute(value)
    || path.normalize(value) !== value || (value.endsWith(path.sep) && value !== path.parse(value).root)) {
    fail("invalid_arguments", `${label} must be a normalized absolute path`);
  }
  return value;
}

function safeText(value, pattern, label, { allowNul = false } = {}) {
  if (typeof value !== "string" || value.length === 0 || value.length > 4096
    || (!allowNul && value.includes("\0")) || (!allowNul && CONTROL.test(value))
    || (pattern && !pattern.test(value))) {
    fail("invalid_manifest", `${label} is invalid`);
  }
  return value;
}

function positiveInteger(value, label) {
  if (!Number.isSafeInteger(value) || value < 1) fail("invalid_manifest", `${label} is invalid`);
  return value;
}

function canonicalRelativePath(value) {
  if (typeof value !== "string" || value.length === 0 || value.length > 1024 || value.includes("\0")
    || value.includes("\\") || value.startsWith("/") || value.endsWith("/") || value.includes("//")) {
    fail("invalid_manifest", "runtime file path is invalid");
  }
  const components = value.split("/");
  if (components.some((component) => component.length === 0 || component === "." || component === ".."
    || !/^[A-Za-z0-9._@+-]+$/u.test(component))) {
    fail("invalid_manifest", "runtime file path is invalid");
  }
  if (components.some((component) => RAW_PATH_SEGMENT.test(component) || RAW_PATH_BASENAME.test(component) || RAW_PATH_SUFFIX.test(component))) {
    fail("forbidden_runtime_path", "credential and log paths are not materialized");
  }
  return value;
}

function parseSignatureBytes(value) {
  safeText(value, BASE64URL_SIGNATURE, "signature_base64url");
  const bytes = Buffer.from(value, "base64url");
  if (bytes.length !== 64 || bytes.toString("base64url") !== value) fail("invalid_signature", "signature encoding is invalid");
  return bytes;
}

function requireCursorLaunchFiles(files) {
  const node = files.find((file) => file.relative_path === CURSOR_AGENT_RUNTIME_NODE_NAME);
  const index = files.find((file) => file.relative_path === CURSOR_AGENT_RUNTIME_INDEX_NAME);
  if (!node || !node.executable || !index || index.executable) {
    fail("invalid_manifest", "runtime must contain executable node and non-executable index.js");
  }
}

function parseManifestBytes(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length < 1 || bytes.length > CURSOR_AGENT_RUNTIME_MAX_MANIFEST_BYTES) {
    fail("invalid_manifest", "manifest size is invalid");
  }
  let text;
  try { text = new TextDecoder("utf-8", { fatal: true }).decode(bytes); }
  catch { fail("invalid_manifest", "manifest is not valid UTF-8"); }
  if (text.startsWith("\uFEFF") || !text.endsWith("\n") || text.slice(0, -1).includes("\n")) {
    fail("noncanonical_manifest", "manifest must be canonical JSON followed by one LF");
  }
  let value;
  try { value = JSON.parse(text); }
  catch { fail("invalid_manifest", "manifest is not valid JSON"); }
  let canonical;
  try { canonical = canonicalJson(value); }
  catch { fail("invalid_manifest", "manifest contains unsupported JSON values"); }
  if (`${canonical}\n` !== text) fail("noncanonical_manifest", "manifest is not canonical JSON");
  exactKeys(value, ["core", "signature"], "manifest");
  exactKeys(value.core, ["schema_version", "runtime_id", "runtime_version", "release_digest", "materialization_epoch", "files"], "core");
  exactKeys(value.signature, ["algorithm", "domain", "key_id", "signature_base64url"], "signature");

  if (value.core.schema_version !== CURSOR_AGENT_RUNTIME_SCHEMA_VERSION
    || value.core.runtime_id !== CURSOR_AGENT_RUNTIME_ID) fail("invalid_manifest", "runtime identity is invalid");
  safeText(value.core.runtime_version, SAFE_RUNTIME_VERSION, "runtime_version");
  safeText(value.core.release_digest, RELEASE_DIGEST, "release_digest");
  positiveInteger(value.core.materialization_epoch, "materialization_epoch");
  if (!Array.isArray(value.core.files) || value.core.files.length < 1 || value.core.files.length > CURSOR_AGENT_RUNTIME_MAX_FILES) {
    fail("invalid_manifest", "runtime file count is invalid");
  }

  let previous = null;
  let total = 0;
  const seen = new Set();
  for (const file of value.core.files) {
    exactKeys(file, ["relative_path", "sha256", "size", "executable"], "runtime file");
    const relativePath = canonicalRelativePath(file.relative_path);
    if (previous !== null && previous >= relativePath) fail("invalid_manifest", "runtime files are not sorted");
    previous = relativePath;
    if (!seen.add(relativePath)) fail("invalid_manifest", "runtime file paths are duplicated");
    safeText(file.sha256, SHA256, "runtime file digest");
    if (!Number.isSafeInteger(file.size) || file.size < 0 || file.size > CURSOR_AGENT_RUNTIME_MAX_FILE_BYTES) {
      fail("invalid_manifest", "runtime file size is invalid");
    }
    if (typeof file.executable !== "boolean") fail("invalid_manifest", "runtime executable flag is invalid");
    total += file.size;
    if (total > CURSOR_AGENT_RUNTIME_MAX_BYTES) fail("runtime_too_large", "runtime exceeds the size bound");
  }
  requireCursorLaunchFiles(value.core.files);

  if (value.signature.algorithm !== "ed25519"
    || value.signature.domain !== CURSOR_AGENT_RUNTIME_SIGNATURE_DOMAIN) fail("invalid_signature", "signature metadata is invalid");
  safeText(value.signature.key_id, SAFE_KEY_ID, "signature key_id");
  const signatureBytes = parseSignatureBytes(value.signature.signature_base64url);
  return Object.freeze({ value, signatureBytes });
}

function signatureInput(core) {
  let canonical;
  try { canonical = canonicalJson(core); }
  catch { fail("invalid_manifest", "manifest core is not canonicalizable"); }
  return Buffer.concat([
    Buffer.from(CURSOR_AGENT_RUNTIME_SIGNATURE_DOMAIN, "utf8"),
    Buffer.from(canonical, "utf8")
  ]);
}

function readRegularFile(input, maximum, { requireRootControlled = false, requireNonWritable = false } = {}) {
  const file = absolutePath(input, "file");
  let descriptor;
  try { descriptor = fs.openSync(file, fs.constants.O_RDONLY | NOFOLLOW); }
  catch { fail("input_unavailable", "input file is unavailable"); }
  try {
    const before = fs.fstatSync(descriptor, { bigint: true });
    if (!before.isFile() || before.nlink !== 1n || before.size > BigInt(maximum) || before.size > BigInt(Number.MAX_SAFE_INTEGER)
      || (requireRootControlled && (before.uid !== 0n || (before.mode & 0o022n) !== 0n))
      || (requireNonWritable && (before.mode & 0o022n) !== 0n)) {
      fail("unsafe_input", "input file is unsafe");
    }
    const bytes = Buffer.alloc(Number(before.size));
    let offset = 0;
    while (offset < bytes.length) {
      const count = fs.readSync(descriptor, bytes, offset, bytes.length - offset, offset);
      if (count === 0) fail("input_changed", "input file changed while reading");
      offset += count;
    }
    const after = fs.fstatSync(descriptor, { bigint: true });
    if (statIdentity(before) !== statIdentity(after)) fail("input_changed", "input file changed while reading");
    return bytes;
  } finally { fs.closeSync(descriptor); }
}

function statIdentity(stat) {
  return [stat.dev, stat.ino, stat.mode, stat.nlink, stat.size, stat.mtimeNs, stat.ctimeNs].map(String).join(":");
}

function validateTrustedKey(bytes) {
  if (bytes.length !== CURSOR_AGENT_RUNTIME_PUBLIC_KEY_BYTES) fail("untrusted_key", "trusted key must be a 44-byte SPKI DER key");
  let key;
  try { key = crypto.createPublicKey({ key: bytes, format: "der", type: "spki" }); }
  catch { fail("untrusted_key", "trusted key is not a valid SPKI key"); }
  if (key.asymmetricKeyType !== "ed25519" || !key.export({ format: "der", type: "spki" }).equals(bytes)) {
    fail("untrusted_key", "trusted key is not canonical Ed25519 SPKI DER");
  }
  return key;
}

function validateSignature(manifest, trustedKeyBytes, trustedKeyId) {
  safeText(trustedKeyId, SAFE_KEY_ID, "trusted key_id");
  const key = validateTrustedKey(trustedKeyBytes);
  if (manifest.value.signature.key_id !== trustedKeyId) fail("untrusted_signature_key", "manifest key_id is not pinned");
  let verified = false;
  try { verified = crypto.verify(null, signatureInput(manifest.value.core), key, manifest.signatureBytes); }
  catch { verified = false; }
  if (!verified) fail("invalid_signature", "manifest signature is invalid");
}

function buildTrustConfigBytes(trustedKeyBytes, trustedKeyId) {
  safeText(trustedKeyId, SAFE_KEY_ID, "trusted key_id");
  validateTrustedKey(trustedKeyBytes);
  const value = {
    schema_version: CURSOR_AGENT_RUNTIME_SCHEMA_VERSION,
    key_id: trustedKeyId,
    public_key_der_base64url: trustedKeyBytes.toString("base64url")
  };
  return Buffer.from(canonicalJson(value), "utf8");
}

function lstatOrFail(target, code = "unsafe_input") {
  try { return fs.lstatSync(target, { bigint: true }); }
  catch { fail(code, "filesystem object is unavailable"); }
}

function validateDirectoryStat(stat, { production = false } = {}) {
  if (!stat.isDirectory() || (stat.mode & 0o022n) !== 0n || (production && stat.uid !== 0n)) {
    fail("unsafe_directory", "directory is not private and regular");
  }
}

function validateDirectoryPath(directory, { production = false } = {}) {
  const stat = lstatOrFail(directory, "destination_unavailable");
  if (stat.isSymbolicLink()) fail("unsafe_directory", "directory symlinks are not accepted");
  validateDirectoryStat(stat, { production });
  return stat;
}

function checkRelativePathInside(root, relativePath) {
  const target = path.join(root, relativePath);
  if (path.relative(root, target).startsWith(`..${path.sep}`) || path.relative(root, target) === ".." || path.isAbsolute(path.relative(root, target))) {
    fail("invalid_manifest", "runtime path escapes the source root");
  }
  return target;
}

function scanSourceTree(sourceRoot, { production = false } = {}) {
  const rootStat = lstatOrFail(sourceRoot);
  if (rootStat.isSymbolicLink()) fail("source_symlink", "source root is a symlink");
  validateDirectoryStat(rootStat, { production });
  const files = new Map();
  const directories = new Set();
  const pending = [{ absolute: sourceRoot, relative: "" }];
  while (pending.length > 0) {
    const current = pending.pop();
    const beforeDirectory = lstatOrFail(current.absolute);
    if (beforeDirectory.isSymbolicLink()) fail("source_symlink", "source symlinks are not accepted");
    validateDirectoryStat(beforeDirectory, { production });
    directories.add(current.relative);
    if (directories.size > CURSOR_AGENT_RUNTIME_MAX_DIRECTORIES
      || directories.size + files.size > CURSOR_AGENT_RUNTIME_MAX_INVENTORY_ENTRIES) {
      fail("runtime_too_large", "runtime directory inventory exceeds the bound");
    }
    let names;
    try { names = fs.readdirSync(current.absolute, { encoding: "utf8" }).sort(); }
    catch { fail("source_unavailable", "source directory cannot be read"); }
    const afterDirectory = lstatOrFail(current.absolute);
    if (statIdentity(beforeDirectory) !== statIdentity(afterDirectory)) fail("source_changed", "source directory changed while reading");
    for (const name of names) {
      if (name.length === 0 || name === "." || name === ".." || name.includes("\0")) fail("source_invalid", "source entry name is invalid");
      const relativePath = current.relative ? `${current.relative}/${name}` : name;
      canonicalRelativePath(relativePath);
      const absolute = checkRelativePathInside(sourceRoot, relativePath);
      const stat = lstatOrFail(absolute);
      if (stat.isSymbolicLink()) fail("source_symlink", "source symlinks are not accepted");
      if (stat.isDirectory()) {
        validateDirectoryStat(stat, { production });
        pending.push({ absolute, relative: relativePath });
      } else if (stat.isFile()) {
        if (stat.nlink !== 1n || stat.size > BigInt(CURSOR_AGENT_RUNTIME_MAX_FILE_BYTES)
          || (stat.mode & 0o022n) !== 0n || (production && stat.uid !== 0n)) fail("source_invalid", "source file links, size, or modes are unsafe");
        if (files.size >= CURSOR_AGENT_RUNTIME_MAX_FILES) fail("runtime_too_large", "runtime file count exceeds the bound");
        files.set(relativePath, {
          relativePath,
          absolute,
          size: Number(stat.size),
          executable: (stat.mode & 0o111n) !== 0n,
          identity: statIdentity(stat)
        });
        if (directories.size + files.size > CURSOR_AGENT_RUNTIME_MAX_INVENTORY_ENTRIES) {
          fail("runtime_too_large", "runtime inventory exceeds the bound");
        }
      } else {
        fail("source_invalid", "source contains a special file");
      }
    }
  }
  if (files.size === 0) fail("invalid_manifest", "runtime must contain at least one file");
  return { files, directories };
}

function derivedDirectories(files) {
  const directories = new Set([""]);
  for (const relativePath of files) {
    const components = relativePath.split("/");
    components.pop();
    let current = "";
    for (const component of components) {
      current = current ? `${current}/${component}` : component;
      directories.add(current);
      if (directories.size > CURSOR_AGENT_RUNTIME_MAX_DIRECTORIES) {
        fail("runtime_too_large", "runtime directory inventory exceeds the bound");
      }
    }
  }
  return directories;
}

function hashSourceFile(sourceFile) {
  let descriptor;
  try { descriptor = fs.openSync(sourceFile.absolute, fs.constants.O_RDONLY | NOFOLLOW); }
  catch { fail("source_unavailable", "source file could not be opened"); }
  try {
    const before = fs.fstatSync(descriptor, { bigint: true });
    if (!before.isFile() || before.nlink !== 1n || before.size > BigInt(CURSOR_AGENT_RUNTIME_MAX_FILE_BYTES)
      || before.size > BigInt(Number.MAX_SAFE_INTEGER) || (before.mode & 0o022n) !== 0n) {
      fail("source_invalid", "source file is unsafe");
    }
    const digest = crypto.createHash("sha256");
    const buffer = Buffer.allocUnsafe(1024 * 1024);
    let total = 0;
    while (total < Number(before.size)) {
      const count = fs.readSync(descriptor, buffer, 0, Math.min(buffer.length, Number(before.size) - total), null);
      if (count === 0) fail("source_changed", "source file ended while hashing");
      digest.update(buffer.subarray(0, count));
      total += count;
    }
    const after = fs.fstatSync(descriptor, { bigint: true });
    if (statIdentity(before) !== statIdentity(after) || total !== Number(before.size)) {
      fail("source_changed", "source file changed while hashing");
    }
    return { sha256: digest.digest("hex"), size: Number(before.size) };
  } finally { fs.closeSync(descriptor); }
}

function privateSigningKey(bytes) {
  let key;
  try { key = crypto.createPrivateKey({ key: bytes, format: "der", type: "pkcs8" }); }
  catch { fail("invalid_signing_key", "signing key is not valid Ed25519 PKCS8 DER"); }
  if (key.asymmetricKeyType !== "ed25519") fail("invalid_signing_key", "signing key is not Ed25519");
  let publicKey;
  try { publicKey = crypto.createPublicKey(key); }
  catch { fail("invalid_signing_key", "signing key public projection is unavailable"); }
  const publicKeyDER = publicKey.export({ format: "der", type: "spki" });
  validateTrustedKey(publicKeyDER);
  return { key, publicKeyDER };
}

function writeExclusiveCanonicalFile(outputFile, bytes) {
  const file = absolutePath(outputFile, "manifest output file");
  const parent = path.dirname(file);
  validateDirectoryPath(parent);
  let descriptor;
  try { descriptor = fs.openSync(file, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | NOFOLLOW, 0o600); }
  catch (error) {
    if (error?.code === "EEXIST") fail("manifest_exists", "manifest output already exists");
    fail("manifest_output_unavailable", "manifest output could not be created");
  }
  try {
    let offset = 0;
    while (offset < bytes.length) offset += fs.writeSync(descriptor, bytes, offset, bytes.length - offset);
    fsyncFileDescriptor(descriptor);
    fs.fchmodSync(descriptor, 0o444);
    fsyncFileDescriptor(descriptor);
  } catch (error) {
    if (error instanceof CursorRuntimeMaterializerError) throw error;
    fail("manifest_output_failed", "manifest output could not be written");
  } finally { fs.closeSync(descriptor); }
  fsyncDirectory(parent);
  return file;
}

/**
 * Creates the signed release manifest consumed by the root-only materializer.
 * The private key is read once from a caller-owned PKCS#8 DER file and is never
 * included in the returned document or diagnostic output.
 */
export function createCursorAgentRuntimeManifest(options = {}) {
  const sourceRuntimeDirectory = absolutePath(options.sourceRuntimeDirectory, "source runtime directory");
  const outputFile = absolutePath(options.outputFile, "manifest output file");
  const privateKeyFile = absolutePath(options.privateKeyFile, "private signing key file");
  const runtimeVersion = safeText(options.runtimeVersion, SAFE_RUNTIME_VERSION, "runtime_version");
  const releaseDigest = safeText(options.releaseDigest, RELEASE_DIGEST, "release_digest");
  const materializationEpoch = options.materializationEpoch;
  positiveInteger(materializationEpoch, "materialization_epoch");
  safeText(options.keyId, SAFE_KEY_ID, "signing key_id");

  const source = scanSourceTree(sourceRuntimeDirectory);
  const files = [...source.files.values()].sort((left, right) => left.relativePath.localeCompare(right.relativePath));
  const coreFiles = files.map((file) => {
    const digest = hashSourceFile(file);
    return {
      relative_path: file.relativePath,
      sha256: digest.sha256,
      size: digest.size,
      executable: file.executable
    };
  });
  requireCursorLaunchFiles(coreFiles);
  const total = coreFiles.reduce((sum, file) => sum + file.size, 0);
  if (total > CURSOR_AGENT_RUNTIME_MAX_BYTES) fail("runtime_too_large", "runtime exceeds the size bound");

  const privateKeyBytes = readRegularFile(privateKeyFile, CURSOR_AGENT_RUNTIME_PRIVATE_KEY_MAX_BYTES, { requireNonWritable: true });
  const signing = privateSigningKey(privateKeyBytes);
  const core = {
    schema_version: CURSOR_AGENT_RUNTIME_SCHEMA_VERSION,
    runtime_id: CURSOR_AGENT_RUNTIME_ID,
    runtime_version: runtimeVersion,
    release_digest: releaseDigest,
    materialization_epoch: materializationEpoch,
    files: coreFiles
  };
  const signature = crypto.sign(null, signatureInput(core), signing.key).toString("base64url");
  const manifest = {
    core,
    signature: {
      algorithm: "ed25519",
      domain: CURSOR_AGENT_RUNTIME_SIGNATURE_DOMAIN,
      key_id: options.keyId,
      signature_base64url: signature
    }
  };
  const bytes = Buffer.from(`${canonicalJson(manifest)}\n`, "utf8");
  if (bytes.length > CURSOR_AGENT_RUNTIME_MAX_MANIFEST_BYTES) fail("manifest_too_large", "signed manifest exceeds the size bound");
  const writtenFile = writeExclusiveCanonicalFile(outputFile, bytes);
  return Object.freeze({
    manifestFile: writtenFile,
    manifestBytes: bytes,
    publicKeyDER: signing.publicKeyDER,
    runtimeVersion,
    releaseDigest,
    materializationEpoch
  });
}

function compareInventory(source, coreFiles) {
  const expected = new Map(coreFiles.map((file) => [file.relative_path, file]));
  if (source.files.size !== expected.size) fail("inventory_mismatch", "source file inventory differs from manifest");
  for (const [relativePath, file] of source.files) {
    const expectedFile = expected.get(relativePath);
    if (!expectedFile || file.size !== expectedFile.size || file.executable !== expectedFile.executable) {
      fail("inventory_mismatch", "source file inventory differs from manifest");
    }
  }
  const expectedDirectories = derivedDirectories(expected.keys());
  if (source.directories.size !== expectedDirectories.size || [...source.directories].some((item) => !expectedDirectories.has(item))) {
    fail("inventory_mismatch", "source directory inventory differs from manifest");
  }
}

function ensureAbsent(target) {
  try { fs.lstatSync(target); fail("destination_exists", "destination already exists"); }
  catch (error) {
    if (error instanceof CursorRuntimeMaterializerError) throw error;
    if (error?.code !== "ENOENT") fail("destination_unavailable", "destination cannot be inspected");
  }
}

function chmodChown(target, mode, production) {
  try {
    fs.chmodSync(target, mode);
    if (production) fs.chownSync(target, 0, 0);
  } catch { fail("materialization_failed", "destination permissions could not be set"); }
}

function fsyncFileDescriptor(descriptor) {
  try { fs.fsyncSync(descriptor); }
  catch { fail("durability_failed", "file could not be fsync'd"); }
}

function fsyncDirectory(directory) {
  let descriptor;
  try { descriptor = fs.openSync(directory, fs.constants.O_RDONLY | DIRECTORY | NOFOLLOW); }
  catch { fail("durability_failed", "directory could not be opened for fsync"); }
  try { fsyncFileDescriptor(descriptor); }
  finally { fs.closeSync(descriptor); }
}

function createDirectory(directory, production) {
  try { fs.mkdirSync(directory, { mode: 0o700 }); }
  catch { fail("materialization_failed", "staging directory could not be created"); }
  chmodChown(directory, 0o700, production);
}

function copyVerifiedFile(sourceFile, destinationFile, expected, production) {
  let sourceDescriptor;
  let destinationDescriptor;
  try {
    sourceDescriptor = fs.openSync(sourceFile.absolute, fs.constants.O_RDONLY | NOFOLLOW);
    const before = fs.fstatSync(sourceDescriptor, { bigint: true });
    if (!before.isFile() || before.nlink !== 1n || Number(before.size) !== expected.size
      || ((before.mode & 0o111n) !== 0n) !== expected.executable
      || (before.mode & 0o022n) !== 0n) fail("source_changed", "source file is unsafe or changed");
    destinationDescriptor = fs.openSync(destinationFile, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | NOFOLLOW, 0o600);
    const digest = crypto.createHash("sha256");
    const buffer = Buffer.allocUnsafe(1024 * 1024);
    let total = 0;
    while (total < Number(before.size)) {
      const count = fs.readSync(sourceDescriptor, buffer, 0, Math.min(buffer.length, Number(before.size) - total), null);
      if (count === 0) fail("source_changed", "source file ended while copying");
      const chunk = buffer.subarray(0, count);
      digest.update(chunk);
      let written = 0;
      while (written < count) written += fs.writeSync(destinationDescriptor, chunk, written, count - written);
      total += count;
    }
    if (total !== expected.size || digest.digest("hex") !== expected.sha256) fail("digest_mismatch", "source digest does not match the signed manifest");
    const after = fs.fstatSync(sourceDescriptor, { bigint: true });
    if (statIdentity(before) !== statIdentity(after)) fail("source_changed", "source file changed while copying");
    fsyncFileDescriptor(destinationDescriptor);
    chmodChown(destinationFile, expected.executable ? 0o555 : 0o444, production);
    fsyncFileDescriptor(destinationDescriptor);
  } catch (error) {
    if (error instanceof CursorRuntimeMaterializerError) throw error;
    fail("materialization_failed", "runtime file could not be copied");
  } finally {
    if (destinationDescriptor !== undefined) fs.closeSync(destinationDescriptor);
    if (sourceDescriptor !== undefined) fs.closeSync(sourceDescriptor);
  }
}

function copyCanonicalFile(manifestBytes, stagingManifest, production) {
  let descriptor;
  try { descriptor = fs.openSync(stagingManifest, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | NOFOLLOW, 0o600); }
  catch { fail("materialization_failed", "canonical metadata staging failed"); }
  try {
    let offset = 0;
    while (offset < manifestBytes.length) offset += fs.writeSync(descriptor, manifestBytes, offset, manifestBytes.length - offset);
    fsyncFileDescriptor(descriptor);
    chmodChown(stagingManifest, 0o444, production);
    fsyncFileDescriptor(descriptor);
  } catch (error) {
    if (error instanceof CursorRuntimeMaterializerError) throw error;
    fail("materialization_failed", "canonical metadata staging failed");
  } finally { fs.closeSync(descriptor); }
}

function readExactPublishedFile(destination, expected, maximum, production, mismatchCode) {
  let stat;
  try { stat = fs.lstatSync(destination, { bigint: true }); }
  catch (error) {
    if (error?.code === "ENOENT") return false;
    fail(mismatchCode, "published metadata cannot be inspected");
  }
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1n) fail(mismatchCode, "published metadata is unsafe");
  let actual;
  try {
    actual = readRegularFile(destination, maximum, {
      requireRootControlled: production,
      requireNonWritable: true
    });
  } catch {
    fail(mismatchCode, "published metadata is unsafe");
  }
  if (!actual.equals(expected)) fail(mismatchCode, "published metadata does not match the requested bytes");
  return true;
}

function publishCanonicalMetadataNoClobber({ parent, destination, bytes, maximum, production, mismatchCode }) {
  if (readExactPublishedFile(destination, bytes, maximum, production, mismatchCode)) {
    fsyncDirectory(parent);
    return;
  }
  const staging = path.join(parent, `.${path.basename(destination)}.${process.pid}.${crypto.randomBytes(16).toString("hex")}.staging`);
  createDirectory(staging, production);
  const stagedFile = path.join(staging, path.basename(destination));
  try {
    copyCanonicalFile(bytes, stagedFile, production);
    fsyncDirectory(staging);
    try {
      fs.linkSync(stagedFile, destination);
      fs.unlinkSync(stagedFile);
    } catch (error) {
      if (error?.code !== "EEXIST") fail("publish_failed", "metadata could not be published");
      readExactPublishedFile(destination, bytes, maximum, production, mismatchCode);
    }
    fsyncDirectory(parent);
    readExactPublishedFile(destination, bytes, maximum, production, mismatchCode);
    fsyncDirectory(parent);
  } finally {
    removePrivateStaging(staging);
  }
}

function resolveTrustLocations(options, destinationParent, production) {
  const suppliedConfig = options.trustConfigPath;
  const suppliedParent = options.trustParent;
  const suppliedConfigPath = suppliedConfig === undefined ? undefined : absolutePath(suppliedConfig, "trust config path");
  const defaultParent = production
    ? CURSOR_AGENT_RUNTIME_TRUST_PARENT
    : (suppliedParent ?? (suppliedConfigPath ? path.dirname(suppliedConfigPath) : path.join(destinationParent, "Trust")));
  const trustParent = absolutePath(defaultParent, "trust parent");
  const trustConfigPath = suppliedConfigPath ?? path.join(trustParent, CURSOR_AGENT_RUNTIME_TRUST_CONFIG_NAME);
  if (path.dirname(trustConfigPath) !== trustParent) fail("invalid_destination", "trust config must be directly under its trust parent");
  if (production && (trustParent !== CURSOR_AGENT_RUNTIME_TRUST_PARENT || trustConfigPath !== CURSOR_AGENT_RUNTIME_TRUST_CONFIG_PATH)) {
    fail("invalid_destination", "production trust config location is fixed");
  }
  return { trustParent, trustConfigPath };
}

function renameDirectoryNoClobber(source, destination) {
  ensureAbsent(destination);
  let reservationIdentity;
  try {
    // mkdir is an atomic exclusive reservation for the final name. The
    // destination parent is private/root-owned in production, so an
    // untrusted process cannot replace the reservation before rename.
    fs.mkdirSync(destination, { mode: 0o700 });
    reservationIdentity = statIdentity(fs.lstatSync(destination, { bigint: true }));
  } catch (error) {
    if (error?.code === "EEXIST") fail("destination_exists", "destination already exists");
    fail("publish_failed", "runtime destination reservation failed");
  }
  try { fs.renameSync(source, destination); }
  catch (error) {
    if (error?.code === "EEXIST" || error?.code === "ENOTEMPTY") fail("destination_exists", "destination already exists");
    fail("publish_failed", "runtime directory could not be published");
  }
  try {
    const stat = fs.lstatSync(destination);
    if (!stat.isDirectory() || stat.isSymbolicLink()) fail("publish_failed", "published runtime is unsafe");
    if (statIdentity(stat) === reservationIdentity) fail("publish_failed", "runtime reservation was not replaced");
    fs.lstatSync(source);
    fail("publish_failed", "staging runtime remains after publication");
  } catch (error) {
    if (error instanceof CursorRuntimeMaterializerError) throw error;
    if (error?.code !== "ENOENT") fail("publish_failed", "published runtime postcondition failed");
  }
}

function removePrivateStaging(staging) {
  try {
    const stat = fs.lstatSync(staging);
    if (stat.isDirectory() && !stat.isSymbolicLink()) {
      for (const name of fs.readdirSync(staging)) removePrivateStaging(path.join(staging, name));
      fs.chmodSync(staging, 0o700);
      fs.rmdirSync(staging);
    } else {
      if (stat.isFile()) fs.chmodSync(staging, 0o600);
      fs.unlinkSync(staging);
    }
  } catch (error) {
    if (error?.code !== "ENOENT") { /* private cleanup is best effort and never masks the operation result */ }
  }
}

function productionPolicy(options) {
  const production = options.production === true;
  const platform = options.platform ?? process.platform;
  const effectiveUserId = options.effectiveUserId ?? process.geteuid?.();
  if (production) {
    if (platform !== "darwin") fail("unsupported_platform", "production materialization requires macOS");
    if (effectiveUserId !== 0) fail("root_required", "production materialization requires root");
    if (options.destinationParent !== CURSOR_AGENT_RUNTIME_DESTINATION_PARENT) fail("invalid_destination", "production destination is fixed");
  }
  return production;
}

export function materializeCursorAgentRuntime(options = {}) {
  const sourceRuntimeDirectory = absolutePath(options.sourceRuntimeDirectory, "source runtime directory");
  const signedManifestFile = absolutePath(options.signedManifestFile, "signed manifest file");
  const trustedPublicKeyFile = absolutePath(options.trustedPublicKeyFile, "trusted public key file");
  const destinationParent = absolutePath(options.destinationParent, "destination parent");
  const production = productionPolicy({ ...options, destinationParent });
  const { trustParent, trustConfigPath } = resolveTrustLocations(options, destinationParent, production);
  const trustedKeyId = options.trustedKeyId;
  validateDirectoryPath(destinationParent, { production });
  validateDirectoryPath(trustParent, { production });

  const manifestBytes = readRegularFile(signedManifestFile, CURSOR_AGENT_RUNTIME_MAX_MANIFEST_BYTES, { requireRootControlled: production });
  const manifest = parseManifestBytes(manifestBytes);
  const trustedKeyBytes = readRegularFile(trustedPublicKeyFile, CURSOR_AGENT_RUNTIME_PUBLIC_KEY_BYTES, { requireRootControlled: production });
  validateSignature(manifest, trustedKeyBytes, trustedKeyId);
  const trustConfigBytes = buildTrustConfigBytes(trustedKeyBytes, trustedKeyId);

  const destinationRuntime = path.join(destinationParent, CURSOR_AGENT_RUNTIME_DIRECTORY_NAME);
  const destinationManifest = path.join(destinationParent, CURSOR_AGENT_RUNTIME_MANIFEST_NAME);
  ensureAbsent(destinationRuntime);

  const firstInventory = scanSourceTree(sourceRuntimeDirectory, { production });
  compareInventory(firstInventory, manifest.value.core.files);

  // A crash may leave exact metadata behind while runtime publication has not
  // happened. Preflight both files before publishing either one so a
  // mismatch never causes the other metadata file to be modified.
  const trustConfigExists = readExactPublishedFile(
    trustConfigPath,
    trustConfigBytes,
    CURSOR_AGENT_RUNTIME_MAX_MANIFEST_BYTES,
    production,
    "trust_config_mismatch"
  );
  const manifestExists = readExactPublishedFile(
    destinationManifest,
    manifestBytes,
    CURSOR_AGENT_RUNTIME_MAX_MANIFEST_BYTES,
    production,
    "manifest_mismatch"
  );
  if (!trustConfigExists) {
    publishCanonicalMetadataNoClobber({
      parent: trustParent,
      destination: trustConfigPath,
      bytes: trustConfigBytes,
      maximum: CURSOR_AGENT_RUNTIME_MAX_MANIFEST_BYTES,
      production,
      mismatchCode: "trust_config_mismatch"
    });
  }
  if (!manifestExists) {
    publishCanonicalMetadataNoClobber({
      parent: destinationParent,
      destination: destinationManifest,
      bytes: manifestBytes,
      maximum: CURSOR_AGENT_RUNTIME_MAX_MANIFEST_BYTES,
      production,
      mismatchCode: "manifest_mismatch"
    });
  }
  // These are the recovery markers. They must be durable and exact before a
  // runtime directory can become visible.
  readExactPublishedFile(trustConfigPath, trustConfigBytes, CURSOR_AGENT_RUNTIME_MAX_MANIFEST_BYTES, production, "trust_config_mismatch");
  readExactPublishedFile(destinationManifest, manifestBytes, CURSOR_AGENT_RUNTIME_MAX_MANIFEST_BYTES, production, "manifest_mismatch");
  fsyncDirectory(trustParent);
  fsyncDirectory(destinationParent);

  const staging = path.join(destinationParent, `.${CURSOR_AGENT_RUNTIME_DIRECTORY_NAME}.${process.pid}.${crypto.randomBytes(16).toString("hex")}.staging`);
  createDirectory(staging, production);
  const stagingRuntime = path.join(staging, CURSOR_AGENT_RUNTIME_DIRECTORY_NAME);
  createDirectory(stagingRuntime, production);
  try {
    const directories = [...derivedDirectories(manifest.value.core.files.map((file) => file.relative_path))].filter(Boolean).sort((left, right) => left.split("/").length - right.split("/").length || left.localeCompare(right));
    for (const relativeDirectory of directories) createDirectory(path.join(stagingRuntime, relativeDirectory), production);
    for (const expected of manifest.value.core.files) {
      const sourceFile = firstInventory.files.get(expected.relative_path);
      if (!sourceFile) fail("inventory_mismatch", "source file inventory differs from manifest");
      copyVerifiedFile(sourceFile, path.join(stagingRuntime, expected.relative_path), expected, production);
    }
    const secondInventory = scanSourceTree(sourceRuntimeDirectory, { production });
    compareInventory(secondInventory, manifest.value.core.files);
    for (const relativeDirectory of [...derivedDirectories(manifest.value.core.files.map((file) => file.relative_path))].sort((left, right) => right.length - left.length)) {
      if (relativeDirectory) fsyncDirectory(path.join(stagingRuntime, relativeDirectory));
    }
    fsyncDirectory(stagingRuntime);
    fsyncDirectory(staging);
    ensureAbsent(destinationRuntime);
    renameDirectoryNoClobber(stagingRuntime, destinationRuntime);
    const finalDirectories = [...derivedDirectories(manifest.value.core.files.map((file) => file.relative_path))].sort((left, right) => right.length - left.length);
    for (const relativeDirectory of finalDirectories) {
      chmodChown(relativeDirectory ? path.join(destinationRuntime, relativeDirectory) : destinationRuntime, 0o555, production);
    }
    for (const relativeDirectory of finalDirectories) {
      fsyncDirectory(relativeDirectory ? path.join(destinationRuntime, relativeDirectory) : destinationRuntime);
    }
    fsyncDirectory(destinationParent);
    return Object.freeze({
      runtimeDirectory: destinationRuntime,
      manifestFile: destinationManifest,
      trustConfigFile: trustConfigPath,
      runtimeVersion: manifest.value.core.runtime_version,
      releaseDigest: manifest.value.core.release_digest,
      materializationEpoch: manifest.value.core.materialization_epoch
    });
  } catch (error) {
    if (error instanceof CursorRuntimeMaterializerError) throw error;
    fail("materialization_failed", "runtime materialization failed");
  } finally {
    removePrivateStaging(staging);
  }
}

function runCli() {
  const args = process.argv.slice(2);
  if (args.length !== 4 || args.some((value) => value.startsWith("-"))) {
    process.stderr.write("cursor-runtime-materialize: usage SOURCE_RUNTIME_DIR SIGNED_MANIFEST TRUSTED_PUBLIC_KEY_DER TRUSTED_KEY_ID\n");
    process.exitCode = 2;
    return;
  }
  try {
    const result = materializeCursorAgentRuntime({
      sourceRuntimeDirectory: args[0],
      signedManifestFile: args[1],
      trustedPublicKeyFile: args[2],
      trustedKeyId: args[3],
      destinationParent: CURSOR_AGENT_RUNTIME_DESTINATION_PARENT,
      production: true
    });
    process.stdout.write(`${JSON.stringify({ ok: true, runtime_directory: result.runtimeDirectory, manifest_file: result.manifestFile })}\n`);
  } catch (error) {
    const code = error instanceof CursorRuntimeMaterializerError && /^[a-z][a-z0-9_]*$/u.test(error.code) ? error.code : "materialization_failed";
    process.stderr.write(`cursor-runtime-materialize: ${code}\n`);
    process.exitCode = 1;
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) runCli();
