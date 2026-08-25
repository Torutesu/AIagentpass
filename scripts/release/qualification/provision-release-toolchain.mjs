#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { createReleaseToolchainManifest, RELEASE_TOOLCHAIN_FILES } from "./create-release-toolchain-manifest.mjs";

export const PRODUCTION_RELEASE_TOOLCHAIN_ROOT = "/opt/agentpass/release/qualification-tool";
const SOURCE_FILES = Object.freeze({
  "verify-installed-toolchain.mjs": "native/macos/Qualification/verify-installed-toolchain.mjs",
  "verify-external-qualification-signature.mjs": "scripts/release/verify-external-qualification-signature.mjs",
  "external-qualification-trust.mjs": "scripts/release/external-qualification-trust.mjs",
  "verify-hardware-qualification-set.mjs": "scripts/release/verify-hardware-qualification-set.mjs",
  "validate-hardware-qualification.mjs": "scripts/release/validate-hardware-qualification.mjs",
  "generate-hardware-qualification-template.mjs": "scripts/release/generate-hardware-qualification-template.mjs",
  "run-p0c-qualification.mjs": "scripts/release/run-p0c-qualification.mjs",
  "sign-hardware-qualification.mjs": "scripts/release/sign-hardware-qualification.mjs",
  "p0c/verify-runner-attestation.mjs": "scripts/release/p0c/verify-runner-attestation.mjs",
  "n3e/controller-identity-contract.mjs": "scripts/release/n3e/controller-identity-contract.mjs",
  "n3e/qualification-suite-evidence.mjs": "scripts/release/n3e/qualification-suite-evidence.mjs",
  "lib/release-candidate-identity.mjs": "lib/release-candidate-identity.mjs"
});

const canonical = (value) => Buffer.from(`${JSON.stringify(value, null, 2)}\n`, "utf8");
const sha256 = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");
const identity = (stat) => [stat.dev, stat.ino, stat.mode, stat.nlink, stat.size, stat.mtimeNs, stat.ctimeNs].join(":");
const canChown = (uid) => uid !== undefined && (typeof process.geteuid !== "function" || uid !== process.geteuid());

function readStable(file, label, { ownerUid } = {}) {
  let fd;
  try { fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW); } catch { throw new Error(`${label} is unavailable`); }
  try {
    const before = fs.fstatSync(fd, { bigint: true });
    if (!before.isFile() || before.nlink !== 1n || (before.mode & 0o022n) !== 0n || (ownerUid !== undefined && before.uid !== BigInt(ownerUid))) throw new Error(`${label} is not protected`);
    const bytes = Buffer.alloc(Number(before.size)); let offset = 0;
    while (offset < bytes.length) { const count = fs.readSync(fd, bytes, offset, bytes.length - offset, offset); if (count === 0) throw new Error(`${label} changed while reading`); offset += count; }
    const after = fs.fstatSync(fd, { bigint: true });
    if (identity(before) !== identity(after)) throw new Error(`${label} changed while reading`);
    return bytes;
  } finally { fs.closeSync(fd); }
}

function ensureDirectory(directory, mode, uid) {
  if (!fs.existsSync(directory)) fs.mkdirSync(directory, { mode });
  const stat = fs.lstatSync(directory);
  if (!stat.isDirectory() || stat.isSymbolicLink()) throw new Error("release toolchain directory is unsafe");
  fs.chmodSync(directory, mode);
  if (canChown(uid)) fs.chownSync(directory, uid, uid);
}

function writeExclusive(file, bytes, mode, uid) {
  const fd = fs.openSync(file, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, mode);
  try {
    let offset = 0;
    while (offset < bytes.length) offset += fs.writeSync(fd, bytes, offset, bytes.length - offset);
    fs.fsyncSync(fd); fs.fchmodSync(fd, mode); if (canChown(uid)) fs.fchownSync(fd, uid, uid);
  } finally { fs.closeSync(fd); }
}

function protectedParent(parent, uid) {
  const stat = fs.lstatSync(parent);
  if (!stat.isDirectory() || stat.isSymbolicLink() || (stat.mode & 0o022) !== 0 || (uid !== undefined && stat.uid !== uid)) throw new Error("release toolchain parent is not protected");
}

export function provisionReleaseToolchain({ sourceRoot, destination = PRODUCTION_RELEASE_TOOLCHAIN_ROOT, signingKey, production = true, uid = production ? 0 : process.geteuid?.() } = {}) {
  if (typeof sourceRoot !== "string" || !path.isAbsolute(sourceRoot) || path.resolve(sourceRoot) !== sourceRoot) throw new Error("source root must be a normalized absolute path");
  if (typeof destination !== "string" || !path.isAbsolute(destination) || path.resolve(destination) !== destination) throw new Error("destination must be a normalized absolute path");
  if (production && (destination !== PRODUCTION_RELEASE_TOOLCHAIN_ROOT || uid !== 0)) throw new Error("production release toolchain requires root at the fixed destination");
  if (typeof signingKey !== "string" || !path.isAbsolute(signingKey)) throw new Error("signing key path is invalid");
  const parent = path.dirname(destination); protectedParent(parent, uid);
  if (fs.existsSync(destination)) throw new Error("release toolchain destination already exists; replacement is forbidden");
  const sourceOwner = production ? 0 : undefined;
  const sourceBytes = Object.fromEntries(RELEASE_TOOLCHAIN_FILES.map((name) => [name, readStable(path.join(sourceRoot, SOURCE_FILES[name]), `source ${name}`, { ownerUid: sourceOwner })]));
  const keyBytes = readStable(signingKey, "release toolchain signing key", { ownerUid: sourceOwner });
  let privateKey; try { privateKey = crypto.createPrivateKey(keyBytes); } catch { throw new Error("release toolchain signing key is invalid"); }
  if (privateKey.asymmetricKeyType !== "ed25519") throw new Error("release toolchain signing key must be Ed25519");
  const stage = path.join(parent, `.agentpass-release-toolchain-stage-${crypto.randomBytes(16).toString("hex")}`);
  try {
    ensureDirectory(stage, 0o755, uid);
    for (const name of RELEASE_TOOLCHAIN_FILES) {
      const target = path.join(stage, name); ensureDirectory(path.dirname(target), 0o755, uid); writeExclusive(target, sourceBytes[name], 0o444, uid);
    }
    const manifest = createReleaseToolchainManifest(stage);
    const manifestBytes = canonical(manifest);
    const signature = crypto.sign(null, manifestBytes, privateKey);
    const publicKey = crypto.createPublicKey(privateKey).export({ type: "spki", format: "der" });
    writeExclusive(path.join(stage, "manifest.json"), manifestBytes, 0o444, uid);
    writeExclusive(path.join(stage, "manifest.sig"), Buffer.from(`${signature.toString("base64")}\n`, "ascii"), 0o444, uid);
    writeExclusive(path.join(stage, "manifest.pub"), publicKey, 0o444, uid);
    fs.renameSync(stage, destination);
    if (canChown(uid)) fs.chownSync(destination, uid, uid);
    const manifestDigest = sha256(manifestBytes);
    const fingerprint = `SHA256:${crypto.createHash("sha256").update(publicKey).digest("base64url")}`;
    return Object.freeze({ destination, manifest_sha256: manifestDigest, public_key_fingerprint: fingerprint, files: manifest.files.map(({ path: file }) => file) });
  } catch (error) {
    if (fs.existsSync(stage)) fs.rmSync(stage, { recursive: true, force: false });
    throw error;
  }
}

function parseArgs(args) {
  const values = {}; for (let i = 0; i < args.length; i += 2) { const key = args[i]; const value = args[i + 1]; if (!["--source-root", "--destination", "--signing-key"].includes(key) || !value || values[key]) throw new Error("invalid provisioning arguments"); values[key] = value; }
  if (Object.keys(values).length !== 3) throw new Error("usage: provision-release-toolchain.mjs --source-root ABSOLUTE_PATH --destination ABSOLUTE_PATH --signing-key ABSOLUTE_PATH");
  return { sourceRoot: path.resolve(values["--source-root"]), destination: path.resolve(values["--destination"]), signingKey: path.resolve(values["--signing-key"]) };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  try { process.stdout.write(`${JSON.stringify(provisionReleaseToolchain(parseArgs(process.argv.slice(2))))}\n`); }
  catch (error) { process.stderr.write(`${error instanceof Error ? error.message : "release toolchain provisioning failed"}\n`); process.exitCode = 1; }
}
