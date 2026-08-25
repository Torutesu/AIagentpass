import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

import { parseControlBundleJson } from "./control-bundle-v2.mjs";
import { canonicalJson } from "./identity.mjs";
import { assertReleaseCandidateIdMatchesProduct } from "./release-candidate-identity.mjs";
import { parseReleaseVersion } from "./release-version.mjs";
import { parseValidatedInstallReceipt } from "./setup-preflight.mjs";

export const INSTALLED_RELEASE_RECEIPT_VERSION = 2;
export const INSTALLED_RELEASE_RECEIPT_KIND = "agentpass.installed-release-receipt";
export const PROTECTED_STATE_ROOT = "/Library/Application Support/AgentPass";
export const INSTALLED_RELEASE_RECEIPT_ROOT = "/Library/Application Support/AgentPass-Release";
export const INSTALLED_RELEASE_RECEIPT_FILENAME = "installed-release-receipt.json";
export const INSTALLED_RELEASE_RECEIPT_MAX_BYTES = 16 * 1024;

const TEMP_FILE = /^\.installed-release-receipt\.[0-9]+\.[0-9a-f]{48}\.tmp$/u;
const DIGEST = /^[0-9a-f]{64}$/u;
const COMMIT = /^[0-9a-f]{40}$/u;
const TEAM_ID = /^[A-Z0-9]{10}$/u;
const FINGERPRINT = /^SHA256:[A-Za-z0-9_-]{43}$/u;
const RECEIPT_KEYS = Object.freeze([
  "version",
  "kind",
  "candidate_id",
  "release_version",
  "manifest_sha256",
  "artifact_sha256",
  "source_commit",
  "team_id",
  "release_signer_fingerprint"
]);

export const INSTALLED_RELEASE_RECEIPT_CODES = Object.freeze({
  INVALID_ROOT: "INSTALLED_RECEIPT_ROOT_UNSAFE",
  MISSING: "INSTALLED_RECEIPT_MISSING",
  INVALID: "INSTALLED_RECEIPT_INVALID",
  WRITE_FAILED: "INSTALLED_RECEIPT_WRITE_FAILED",
  DESTINATION_UNSAFE: "INSTALLED_RECEIPT_DESTINATION_UNSAFE"
});

export class InstalledReleaseReceiptError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "InstalledReleaseReceiptError";
    this.code = code;
  }
}

function fail(code, message) {
  throw new InstalledReleaseReceiptError(code, message);
}

function object(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function exactKeys(value, keys) {
  return object(value) && Object.keys(value).sort().join("\0") === [...keys].sort().join("\0");
}

function absolutePath(value, label) {
  if (typeof value !== "string" || !path.isAbsolute(value) || value.includes("\0")) fail(INSTALLED_RELEASE_RECEIPT_CODES.INVALID_ROOT, `${label} is invalid`);
  const resolved = path.resolve(value);
  if (resolved !== value) fail(INSTALLED_RELEASE_RECEIPT_CODES.INVALID_ROOT, `${label} is not canonical`);
  return resolved;
}

function owner(value) {
  if (!Number.isSafeInteger(value) || value < 0) fail(INSTALLED_RELEASE_RECEIPT_CODES.INVALID_ROOT, "receipt owner is invalid");
  return value;
}

function receiptRoot(options = {}, { create = false } = {}) {
  const root = absolutePath(options.root ?? INSTALLED_RELEASE_RECEIPT_ROOT, "receipt root");
  const expectedOwner = owner(options.owner ?? 0);
  const filesystem = options.fs ?? fs;
  let stat;
  try { stat = filesystem.lstatSync(root); }
  catch (error) {
    if (error?.code === "ENOENT" && !create) fail(INSTALLED_RELEASE_RECEIPT_CODES.MISSING, "installed release receipt is unavailable");
    if (error?.code !== "ENOENT" || !create) fail(INSTALLED_RELEASE_RECEIPT_CODES.INVALID_ROOT, "receipt root is unavailable");
    const parent = path.dirname(root);
    let parentStat;
    try { parentStat = filesystem.lstatSync(parent); } catch { fail(INSTALLED_RELEASE_RECEIPT_CODES.INVALID_ROOT, "receipt root parent is unavailable"); }
    if (!parentStat.isDirectory() || parentStat.isSymbolicLink() || parentStat.uid !== expectedOwner || (parentStat.mode & 0o022) !== 0 || (parentStat.mode & 0o6000) !== 0) {
      fail(INSTALLED_RELEASE_RECEIPT_CODES.INVALID_ROOT, "receipt root parent is unsafe");
    }
    try { filesystem.mkdirSync(root, { mode: 0o755 }); }
    catch { fail(INSTALLED_RELEASE_RECEIPT_CODES.WRITE_FAILED, "receipt root could not be created"); }
    try { filesystem.chmodSync(root, 0o755); } catch { fail(INSTALLED_RELEASE_RECEIPT_CODES.WRITE_FAILED, "receipt root permissions could not be set"); }
    try { stat = filesystem.lstatSync(root); } catch { fail(INSTALLED_RELEASE_RECEIPT_CODES.WRITE_FAILED, "receipt root could not be verified"); }
    fsyncDirectory(filesystem, parent);
  }
  if (!stat.isDirectory() || stat.isSymbolicLink() || stat.uid !== expectedOwner || (stat.mode & 0o777) !== 0o755 || (stat.mode & 0o6000) !== 0) {
    fail(INSTALLED_RELEASE_RECEIPT_CODES.INVALID_ROOT, "receipt root is unsafe");
  }
  return { root, expectedOwner, filesystem };
}

function receiptPath(root) {
  return path.join(root, INSTALLED_RELEASE_RECEIPT_FILENAME);
}

function safeReceiptStat(stat, expectedOwner, code = INSTALLED_RELEASE_RECEIPT_CODES.INVALID) {
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 || stat.uid !== expectedOwner || (stat.mode & 0o777) !== 0o644 || (stat.mode & 0o6000) !== 0) {
    fail(code, "installed release receipt is unsafe");
  }
  return stat;
}

function safeTemporaryReceiptStat(stat, expectedOwner) {
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 || stat.uid !== expectedOwner || ![0o600, 0o644].includes(stat.mode & 0o777) || (stat.mode & 0o6000) !== 0) {
    fail(INSTALLED_RELEASE_RECEIPT_CODES.WRITE_FAILED, "interrupted receipt state is unsafe");
  }
  return stat;
}

function normalizeReceipt(value) {
  let receipt;
  try { receipt = parseValidatedInstallReceipt(value); }
  catch { fail(INSTALLED_RELEASE_RECEIPT_CODES.INVALID, "installed release receipt is invalid"); }
  if (receipt.version !== INSTALLED_RELEASE_RECEIPT_VERSION || receipt.kind !== INSTALLED_RELEASE_RECEIPT_KIND || !exactKeys(receipt, RECEIPT_KEYS)) {
    fail(INSTALLED_RELEASE_RECEIPT_CODES.INVALID, "installed release receipt identity is invalid");
  }
  return Object.freeze({ ...receipt });
}

function receiptText(value) {
  return `${canonicalJson(normalizeReceipt(value))}\n`;
}

function parseReceiptBytes(bytes) {
  if (!Buffer.isBuffer(bytes) || bytes.length === 0 || bytes.length > INSTALLED_RELEASE_RECEIPT_MAX_BYTES) fail(INSTALLED_RELEASE_RECEIPT_CODES.INVALID, "installed release receipt size is invalid");
  let value;
  try { value = parseControlBundleJson(bytes, { maxBytes: INSTALLED_RELEASE_RECEIPT_MAX_BYTES, maxDepth: 8 }); }
  catch { fail(INSTALLED_RELEASE_RECEIPT_CODES.INVALID, "installed release receipt JSON is invalid"); }
  const normalized = normalizeReceipt(value);
  if (receiptText(normalized) !== bytes.toString("utf8")) fail(INSTALLED_RELEASE_RECEIPT_CODES.INVALID, "installed release receipt is not canonical");
  return normalized;
}

function noFollowReadFlags() {
  const flags = fs.constants.O_RDONLY;
  if (!Number.isInteger(fs.constants.O_NOFOLLOW)) fail(INSTALLED_RELEASE_RECEIPT_CODES.INVALID, "no-follow receipt reads are unavailable");
  return flags | fs.constants.O_NOFOLLOW;
}

function readReceiptFile(rootInfo) {
  const file = receiptPath(rootInfo.root);
  let descriptor;
  try { descriptor = rootInfo.filesystem.openSync(file, noFollowReadFlags()); }
  catch (error) {
    if (error?.code === "ENOENT") fail(INSTALLED_RELEASE_RECEIPT_CODES.MISSING, "installed release receipt is unavailable");
    fail(INSTALLED_RELEASE_RECEIPT_CODES.INVALID, "installed release receipt cannot be opened");
  }
  try {
    const before = safeReceiptStat(rootInfo.filesystem.fstatSync(descriptor), rootInfo.expectedOwner);
    if (before.size > INSTALLED_RELEASE_RECEIPT_MAX_BYTES) fail(INSTALLED_RELEASE_RECEIPT_CODES.INVALID, "installed release receipt is too large");
    const bytes = rootInfo.filesystem.readFileSync(descriptor);
    const after = safeReceiptStat(rootInfo.filesystem.fstatSync(descriptor), rootInfo.expectedOwner);
    if (before.dev !== after.dev || before.ino !== after.ino || before.size !== after.size || bytes.length !== after.size) fail(INSTALLED_RELEASE_RECEIPT_CODES.INVALID, "installed release receipt changed while reading");
    return parseReceiptBytes(bytes);
  } catch (error) {
    if (error instanceof InstalledReleaseReceiptError) throw error;
    fail(INSTALLED_RELEASE_RECEIPT_CODES.INVALID, "installed release receipt cannot be read");
  } finally {
    try { rootInfo.filesystem.closeSync(descriptor); } catch {}
  }
}

function validateExistingDestination(filesystem, file, expectedOwner) {
  let stat;
  try { stat = filesystem.lstatSync(file); }
  catch (error) {
    if (error?.code === "ENOENT") return false;
    fail(INSTALLED_RELEASE_RECEIPT_CODES.DESTINATION_UNSAFE, "installed release receipt destination cannot be inspected");
  }
  safeReceiptStat(stat, expectedOwner, INSTALLED_RELEASE_RECEIPT_CODES.DESTINATION_UNSAFE);
  return true;
}

function fsyncDirectory(filesystem, directory) {
  const descriptor = filesystem.openSync(directory, fs.constants.O_RDONLY);
  try { filesystem.fsyncSync(descriptor); }
  finally { filesystem.closeSync(descriptor); }
}

function removeInterruptedTemps(rootInfo) {
  let changed = false;
  for (const name of rootInfo.filesystem.readdirSync(rootInfo.root)) {
    if (!TEMP_FILE.test(name)) continue;
    const file = path.join(rootInfo.root, name);
    let stat;
    try { stat = rootInfo.filesystem.lstatSync(file); }
    catch { fail(INSTALLED_RELEASE_RECEIPT_CODES.WRITE_FAILED, "interrupted receipt state cannot be inspected"); }
    safeTemporaryReceiptStat(stat, rootInfo.expectedOwner);
    try { rootInfo.filesystem.unlinkSync(file); }
    catch { fail(INSTALLED_RELEASE_RECEIPT_CODES.WRITE_FAILED, "interrupted receipt state cannot be removed"); }
    changed = true;
  }
  if (changed) fsyncDirectory(rootInfo.filesystem, rootInfo.root);
}

function createReceiptTemp(rootInfo) {
  const name = `.installed-release-receipt.${process.pid}.${crypto.randomBytes(24).toString("hex")}.tmp`;
  return path.join(rootInfo.root, name);
}

/** Construct the exact public receipt from the bytes verified by the release verifier. */
export function createInstalledReleaseReceipt({ manifest, manifestBytes, artifactSha256, teamId, releaseSignerFingerprint } = {}) {
  if (!object(manifest) || !Buffer.isBuffer(manifestBytes)) fail(INSTALLED_RELEASE_RECEIPT_CODES.INVALID, "verified release manifest is unavailable");
  if (!DIGEST.test(artifactSha256 ?? "") || !TEAM_ID.test(teamId ?? "") || !FINGERPRINT.test(releaseSignerFingerprint ?? "")) fail(INSTALLED_RELEASE_RECEIPT_CODES.INVALID, "verified release binding is invalid");
  if (!object(manifest.source) || !COMMIT.test(manifest.source.commit ?? "")) fail(INSTALLED_RELEASE_RECEIPT_CODES.INVALID, "verified release source commit is invalid");
  try { parseReleaseVersion(manifest.version); }
  catch { fail(INSTALLED_RELEASE_RECEIPT_CODES.INVALID, "verified release version is invalid"); }
  try { assertReleaseCandidateIdMatchesProduct(manifest.candidate_id, artifactSha256); }
  catch { fail(INSTALLED_RELEASE_RECEIPT_CODES.INVALID, "verified release candidate identity is invalid"); }
  return normalizeReceipt({
    version: INSTALLED_RELEASE_RECEIPT_VERSION,
    kind: INSTALLED_RELEASE_RECEIPT_KIND,
    candidate_id: manifest.candidate_id,
    release_version: manifest.version,
    manifest_sha256: crypto.createHash("sha256").update(manifestBytes).digest("hex"),
    artifact_sha256: artifactSha256,
    source_commit: manifest.source.commit,
    team_id: teamId,
    release_signer_fingerprint: releaseSignerFingerprint
  });
}

/** Read only the durable final receipt; interrupted temporary files are ignored. */
export function readInstalledReleaseReceipt(options = {}) {
  return readReceiptFile(receiptRoot(options));
}

/** Re-validate the durable receipt as an installed-release proof. */
export function verifyInstalledReleaseReceipt(options = {}) {
  return readInstalledReleaseReceipt(options);
}

/** Atomically persist a new receipt after the installer has verified the app. */
export function writeInstalledReleaseReceipt(value, options = {}) {
  const rootInfo = receiptRoot(options, { create: true });
  const receipt = normalizeReceipt(value);
  const file = receiptPath(rootInfo.root);
  removeInterruptedTemps(rootInfo);
  validateExistingDestination(rootInfo.filesystem, file, rootInfo.expectedOwner);
  const temporary = createReceiptTemp(rootInfo);
  let descriptor;
  let renamed = false;
  try {
    if (!Number.isInteger(fs.constants.O_NOFOLLOW)) fail(INSTALLED_RELEASE_RECEIPT_CODES.WRITE_FAILED, "no-follow receipt writes are unavailable");
    const flags = fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW;
    descriptor = rootInfo.filesystem.openSync(temporary, flags, 0o600);
    const bytes = Buffer.from(receiptText(receipt), "utf8");
    rootInfo.filesystem.writeSync(descriptor, bytes, 0, bytes.length);
    rootInfo.filesystem.fchmodSync(descriptor, 0o644);
    rootInfo.filesystem.fsyncSync(descriptor);
    rootInfo.filesystem.closeSync(descriptor);
    descriptor = undefined;
    validateExistingDestination(rootInfo.filesystem, file, rootInfo.expectedOwner);
    rootInfo.filesystem.renameSync(temporary, file);
    renamed = true;
    fsyncDirectory(rootInfo.filesystem, rootInfo.root);
    safeReceiptStat(rootInfo.filesystem.lstatSync(file), rootInfo.expectedOwner);
    return Object.freeze({ receipt, path: file, replaced: true });
  } catch (error) {
    if (descriptor !== undefined) try { rootInfo.filesystem.closeSync(descriptor); } catch {}
    if (!renamed) try { rootInfo.filesystem.unlinkSync(temporary); } catch {}
    if (error instanceof InstalledReleaseReceiptError) throw error;
    fail(INSTALLED_RELEASE_RECEIPT_CODES.WRITE_FAILED, "installed release receipt could not be persisted");
  }
}

export function installedReleaseReceiptPath(root = INSTALLED_RELEASE_RECEIPT_ROOT) {
  return receiptPath(absolutePath(root, "protected state root"));
}
