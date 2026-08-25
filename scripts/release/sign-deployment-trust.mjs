#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  DEPLOYMENT_ATTESTATION_ALGORITHM,
  deploymentAttestationPublicKeyFingerprint,
  deploymentAttestationTrustSigningData,
  normalizeDeploymentAttestationTrust,
  verifyDeploymentAttestationTrustManifest
} from "./deployment-attestation.mjs";
import { canonicalJson } from "../../packages/protocol/src/index.mjs";

const MAX_MANIFEST_BYTES = 256 * 1024;
const MAX_KEY_BYTES = 16 * 1024;
const MAX_KEY_SET_BYTES = 256 * 1024;
const PLACEHOLDER_FINGERPRINT = `SHA256:${"A".repeat(43)}`;
const PLACEHOLDER_SIGNATURE = "A".repeat(86);
const TRUST_TYPE = "agentpass.deployment-attestation-trust";
const TRUST_ENVELOPE_KEYS = ["schema_version", "type", "keys", "signature_algorithm", "signer_key_fingerprint", "signature"];

export class DeploymentTrustSigningError extends Error {
  constructor(message, options) {
    super(message, options);
    this.name = "DeploymentTrustSigningError";
    this.code = "ERR_DEPLOYMENT_TRUST_SIGNING";
  }
}

/**
 * Sign a deployment-attestation trust manifest without accepting key material
 * from an environment variable or printing it to the process output.
 *
 * `keysPath` is a canonical JSON file containing the complete desired key
 * array. Supplying the complete set makes rotation reviewable: existing active
 * and unexpired identities may not disappear as an accidental side effect.
 */
export function signDeploymentTrust({ manifestPath, privateKeyPath, outputPath, keysPath, now = Date.now() } = {}) {
  const source = readCanonicalJsonFile(manifestPath, MAX_MANIFEST_BYTES, "trust manifest");
  const privateKey = readEd25519PrivateKey(privateKeyPath);
  const rootPublicKey = crypto.createPublicKey(privateKey);
  const sourceManifest = parseTrustEnvelope(source.value);
  const sourceIsPlaceholder = isPlaceholderManifest(sourceManifest);

  if (!sourceIsPlaceholder) {
    try { verifyDeploymentAttestationTrustManifest(sourceManifest, { rootPublicKey }); }
    catch (error) { throw new DeploymentTrustSigningError("existing trust manifest signature is invalid", { cause: error }); }
  }

  const requestedKeys = keysPath === undefined
    ? sourceManifest.keys
    : readKeySet(keysPath);
  const keys = updateTrustKeySet(sourceManifest.keys, requestedKeys, { now, sourceIsPlaceholder });
  const signed = buildSignedDeploymentTrustManifest({ keys, privateKey });
  writeExclusiveRegularFile(outputPath, Buffer.from(`${canonicalJson(signed)}\n`, "utf8"), 0o600);

  return Object.freeze({
    output_path: requireAbsolutePath(outputPath, "trust manifest output"),
    key_count: keys.length,
    signer_key_fingerprint: signed.signer_key_fingerprint
  });
}

export function buildSignedDeploymentTrustManifest({ keys, privateKey } = {}) {
  const normalized = normalizeKeys(keys);
  if (!privateKey || !(privateKey instanceof crypto.KeyObject) || privateKey.type !== "private" || privateKey.asymmetricKeyType !== "ed25519") {
    throw new DeploymentTrustSigningError("root private key must be an Ed25519 private key");
  }
  const rootPublicKey = crypto.createPublicKey(privateKey);
  const payload = { schema_version: 1, type: TRUST_TYPE, keys: normalized };
  const signature = crypto.sign(null, deploymentAttestationTrustSigningData(payload), privateKey);
  if (signature.length !== 64) throw new DeploymentTrustSigningError("Ed25519 signature has an invalid length");
  const envelope = {
    ...payload,
    signature_algorithm: DEPLOYMENT_ATTESTATION_ALGORITHM,
    signer_key_fingerprint: deploymentAttestationPublicKeyFingerprint(rootPublicKey),
    signature: signature.toString("base64url")
  };
  try { verifyDeploymentAttestationTrustManifest(envelope, { rootPublicKey }); }
  catch (error) { throw new DeploymentTrustSigningError("generated trust manifest failed self-verification", { cause: error }); }
  return Object.freeze(envelope);
}

function updateTrustKeySet(previousKeys, nextKeys, { now, sourceIsPlaceholder }) {
  if (!Number.isFinite(now)) throw new DeploymentTrustSigningError("rotation validation time is invalid");
  const previous = normalizeKeys(previousKeys);
  const next = normalizeKeys(nextKeys);
  const nextByIdentity = new Map(next.map((entry) => [identityOf(entry), entry]));

  for (const oldEntry of previous) {
    const identity = identityOf(oldEntry);
    const replacement = nextByIdentity.get(identity);
    if (!replacement) {
      const expired = now >= Date.parse(oldEntry.not_after);
      if (!sourceIsPlaceholder && oldEntry.status !== "revoked" && !expired) {
        throw new DeploymentTrustSigningError(`refusing to remove active unexpired trust identity: ${identity}`);
      }
      continue;
    }
    if (!sourceIsPlaceholder && oldEntry.fingerprint !== PLACEHOLDER_FINGERPRINT && replacement.fingerprint !== oldEntry.fingerprint) {
      throw new DeploymentTrustSigningError(`refusing to replace the fingerprint of an existing trust identity: ${identity}`);
    }
  }

  if (next.some((entry) => entry.fingerprint === PLACEHOLDER_FINGERPRINT)) {
    throw new DeploymentTrustSigningError("trust manifest still contains a placeholder fingerprint");
  }
  return next;
}

function normalizeKeys(keys) {
  try {
    return normalizeDeploymentAttestationTrust({ schema_version: 1, type: TRUST_TYPE, keys }).keys;
  } catch (error) {
    throw new DeploymentTrustSigningError("trust key set is malformed, duplicated, or otherwise invalid", { cause: error });
  }
}

function parseTrustEnvelope(value) {
  exactObject(value, TRUST_ENVELOPE_KEYS, "trust manifest");
  if (value.schema_version !== 1 || value.type !== TRUST_TYPE || value.signature_algorithm !== DEPLOYMENT_ATTESTATION_ALGORITHM) {
    throw new DeploymentTrustSigningError("trust manifest envelope is unsupported");
  }
  normalizeKeys(value.keys);
  return value;
}

function isPlaceholderManifest(value) {
  return value.signature === PLACEHOLDER_SIGNATURE
    && value.signer_key_fingerprint === PLACEHOLDER_FINGERPRINT
    && value.keys.every((entry) => entry.fingerprint === PLACEHOLDER_FINGERPRINT);
}

function readKeySet(filePath) {
  const input = readCanonicalJsonFile(filePath, MAX_KEY_SET_BYTES, "trust key set");
  if (!Array.isArray(input.value)) throw new DeploymentTrustSigningError("trust key set must be a JSON array");
  return input.value;
}

function readEd25519PrivateKey(filePath) {
  const input = readStableRegularFile(filePath, MAX_KEY_BYTES, "root private key", { privateKey: true });
  try {
    const text = new TextDecoder("utf-8", { fatal: true }).decode(input.bytes);
    if (!/^-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----\r?\n[\s\S]+\r?\n-----END [A-Z0-9 ]*PRIVATE KEY-----\r?\n?$/u.test(text)) {
      throw new Error("not PEM");
    }
    const key = crypto.createPrivateKey(input.bytes);
    if (key.asymmetricKeyType !== "ed25519") throw new Error("not Ed25519");
    return key;
  } catch (error) {
    throw new DeploymentTrustSigningError("root private key is not a valid Ed25519 PEM", { cause: error });
  } finally {
    input.bytes.fill(0);
  }
}

function readCanonicalJsonFile(filePath, maximum, label) {
  const input = readStableRegularFile(filePath, maximum, label);
  let text;
  try { text = new TextDecoder("utf-8", { fatal: true }).decode(input.bytes); }
  catch (error) { throw new DeploymentTrustSigningError(`${label} is not valid UTF-8`, { cause: error }); }
  let value;
  try { value = JSON.parse(text); }
  catch (error) { throw new DeploymentTrustSigningError(`${label} is not valid JSON`, { cause: error }); }
  if (text !== `${canonicalJson(value)}\n`) throw new DeploymentTrustSigningError(`${label} is not canonical JSON`);
  return Object.freeze({ value, bytes: input.bytes });
}

function readStableRegularFile(filePath, maximum, label, { privateKey = false } = {}) {
  const target = requireAbsolutePath(filePath, label);
  if (!Number.isInteger(fs.constants.O_NOFOLLOW)) throw new DeploymentTrustSigningError("O_NOFOLLOW is unavailable on this platform");
  let descriptor;
  try { descriptor = fs.openSync(target, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW); }
  catch (error) { throw new DeploymentTrustSigningError(`cannot open ${label}`, { cause: error }); }
  try {
    const before = fs.fstatSync(descriptor, { bigint: true });
    if (!before.isFile() || before.nlink !== 1n || before.size === 0n || before.size > BigInt(maximum) || before.size > BigInt(Number.MAX_SAFE_INTEGER)) {
      throw new DeploymentTrustSigningError(`${label} must be a bounded single-link regular file`);
    }
    if ((before.mode & 0o022n) !== 0n) throw new DeploymentTrustSigningError(`${label} must not be group/world writable`);
    if (privateKey && (before.mode & 0o777n) !== 0o600n) throw new DeploymentTrustSigningError("root private key must have mode 0600");
    if (privateKey && typeof process.getuid === "function" && before.uid !== BigInt(process.getuid())) throw new DeploymentTrustSigningError("root private key must be owned by the current user");
    const bytes = Buffer.alloc(Number(before.size));
    let offset = 0;
    while (offset < bytes.length) {
      const count = fs.readSync(descriptor, bytes, offset, bytes.length - offset, offset);
      if (count === 0) throw new DeploymentTrustSigningError(`${label} changed while reading`);
      offset += count;
    }
    const after = fs.fstatSync(descriptor, { bigint: true });
    if (statIdentity(before) !== statIdentity(after)) throw new DeploymentTrustSigningError(`${label} changed while reading`);
    return Object.freeze({ bytes, path: target });
  } finally { fs.closeSync(descriptor); }
}

function writeExclusiveRegularFile(filePath, bytes, mode) {
  const target = requireAbsolutePath(filePath, "trust manifest output");
  if (!Buffer.isBuffer(bytes) || bytes.length === 0) throw new DeploymentTrustSigningError("trust manifest output is empty");
  if (!Number.isInteger(fs.constants.O_NOFOLLOW)) throw new DeploymentTrustSigningError("O_NOFOLLOW is unavailable on this platform");
  let descriptor;
  try {
    descriptor = fs.openSync(target, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, mode);
    let offset = 0;
    while (offset < bytes.length) offset += fs.writeSync(descriptor, bytes, offset, bytes.length - offset);
    fs.fchmodSync(descriptor, 0o600);
    fs.fsyncSync(descriptor);
    const stat = fs.fstatSync(descriptor, { bigint: true });
    if (!stat.isFile() || stat.nlink !== 1n || (stat.mode & 0o777n) !== 0o600n) throw new DeploymentTrustSigningError("trust manifest output is not a regular mode-0600 file");
  } catch (error) {
    if (error instanceof DeploymentTrustSigningError) throw error;
    throw new DeploymentTrustSigningError("cannot create trust manifest output", { cause: error });
  } finally { if (descriptor !== undefined) fs.closeSync(descriptor); }
}

function exactObject(value, keys, label) {
  if (!value || typeof value !== "object" || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) throw new DeploymentTrustSigningError(`${label} must be a plain object`);
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) throw new DeploymentTrustSigningError(`${label} has missing or unknown fields`);
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || descriptor.get || descriptor.set || descriptor.enumerable !== true || !Object.hasOwn(descriptor, "value")) throw new DeploymentTrustSigningError(`${label} contains an accessor property`);
  }
}

function identityOf(entry) { return `${entry.environment}\0${entry.key_id}\0${entry.key_version}`; }

function statIdentity(stat) { return [stat.dev, stat.ino, stat.mode, stat.nlink, stat.size, stat.mtimeNs, stat.ctimeNs].join(":"); }

function requireAbsolutePath(value, label) {
  if (typeof value !== "string" || value.length === 0 || !path.isAbsolute(value)) throw new DeploymentTrustSigningError(`${label} must be an absolute path`);
  return path.resolve(value);
}

function parseArguments(argv) {
  const allowed = new Set(["--manifest", "--private-key", "--output", "--keys"]);
  const values = new Map();
  for (let index = 0; index < argv.length; index += 2) {
    const name = argv[index];
    const value = argv[index + 1];
    if (!allowed.has(name) || value === undefined || value.startsWith("--") || values.has(name)) throw new DeploymentTrustSigningError("Usage: sign-deployment-trust.mjs --manifest MANIFEST --private-key ROOT-PRIVATE-KEY-PEM --output OUTPUT [--keys KEY-SET.json]");
    values.set(name, value);
  }
  if (!["--manifest", "--private-key", "--output"].every((name) => values.has(name))) throw new DeploymentTrustSigningError("Usage: sign-deployment-trust.mjs --manifest MANIFEST --private-key ROOT-PRIVATE-KEY-PEM --output OUTPUT [--keys KEY-SET.json]");
  return { manifestPath: values.get("--manifest"), privateKeyPath: values.get("--private-key"), outputPath: values.get("--output"), keysPath: values.get("--keys") };
}

const invokedPath = process.argv[1] && path.resolve(process.argv[1]);
if (invokedPath === fileURLToPath(import.meta.url)) {
  try {
    const result = signDeploymentTrust(parseArguments(process.argv.slice(2)));
    process.stdout.write(`${JSON.stringify({ ok: true, ...result })}\n`);
  } catch (error) {
    process.stderr.write(`${error instanceof Error ? error.message : "deployment trust signing failed"}\n`);
    process.exitCode = 1;
  }
}

export { PLACEHOLDER_FINGERPRINT, PLACEHOLDER_SIGNATURE, TRUST_TYPE };
