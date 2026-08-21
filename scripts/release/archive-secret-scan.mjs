import crypto from "node:crypto";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const MAX_FILE_BYTES = 64 * 1024 * 1024;
const MAX_TOTAL_BYTES = 256 * 1024 * 1024;
const MAX_ENTRIES = 100_000;
const MAX_MEMBER_PATH_BYTES = 4 * 1024;
const MAX_LISTING_BYTES = 8 * 1024 * 1024;
const MAX_INPUTS = 1_024;
const OPAQUE = /\.(?:7z|bz2|dmg|gz|iso|pkg|rar|zip)$/iu;
const TAR = /\.(?:tar|tgz|tar\.gz|tar\.bz2)$/iu;
const TEXT_SECRET_MARKERS = [
  /-----BEGIN (?:RSA |EC |OPENSSH |ED25519 )?PRIVATE KEY-----/u,
  /AGENTPASS_[A-Z0-9_]*(?:SECRET|PASSWORD|TOKEN|PRIVATE|P12|KEY)/u
];
const LEGACY_SECRET_MARKERS = [
  ...TEXT_SECRET_MARKERS,
  /(?:aws_secret_access_key|client_secret|api[_-]?key|access[_-]?token)\s*["']?\s*[:=]/iu,
  /(?:password|secret|token|private[_-]?key)\s*["']?\s*[:=]\s*["']?[A-Za-z0-9+/=_-]{16,}/iu
];
const JSON_SECRET_KEYS = new Set([
  "accesstoken",
  "apitoken",
  "apikey",
  "awssecretaccesskey",
  "clientsecret",
  "password",
  "privatekey",
  "secret",
  "token"
]);
const JSON_PLACEHOLDER_VALUES = new Set([
  "",
  "hidden",
  "masked",
  "na",
  "none",
  "notavailable",
  "notset",
  "null",
  "omitted",
  "placeholder",
  "redacted",
  "removed",
  "unset"
]);

export class ArchiveSecretScanError extends Error {
  constructor(message) { super(message); this.name = "ArchiveSecretScanError"; }
}

export function scanArchives(inputs, options = {}) {
  if (!Array.isArray(inputs) || inputs.length === 0 || inputs.length > MAX_INPUTS) throw new ArchiveSecretScanError("artifact paths are required and bounded");
  if (options === null || typeof options !== "object" || Array.isArray(options)) throw new ArchiveSecretScanError("scan limits must be an object");
  const allowedOptions = new Set(["maximumFileBytes", "maximumTotalBytes", "maximumEntries", "maximumMemberPathBytes"]);
  if (Object.keys(options).some((key) => !allowedOptions.has(key))) throw new ArchiveSecretScanError("scan limits contain an unknown option");
  const limits = {
    maximumFileBytes: validateLimit(options.maximumFileBytes === undefined ? MAX_FILE_BYTES : options.maximumFileBytes, "maximumFileBytes", MAX_FILE_BYTES),
    maximumTotalBytes: validateLimit(options.maximumTotalBytes === undefined ? MAX_TOTAL_BYTES : options.maximumTotalBytes, "maximumTotalBytes", MAX_TOTAL_BYTES),
    maximumEntries: validateLimit(options.maximumEntries === undefined ? MAX_ENTRIES : options.maximumEntries, "maximumEntries", MAX_ENTRIES),
    maximumMemberPathBytes: validateLimit(options.maximumMemberPathBytes === undefined ? MAX_MEMBER_PATH_BYTES : options.maximumMemberPathBytes, "maximumMemberPathBytes", MAX_MEMBER_PATH_BYTES)
  };
  const state = { files: [], seenInodes: new Set(), totalBytes: 0, entries: 0 };
  for (const input of inputs) {
    const target = resolveInputPath(input);
    const stat = lstatOrThrow(target);
    if (stat.isSymbolicLink()) throw new ArchiveSecretScanError(`artifact path is a symlink: ${target}`);
    if (stat.isDirectory()) walkDirectory(target, state, limits, (file) => addFile(file, state, limits));
    else if (stat.isFile() && TAR.test(target)) scanTar(target, state, limits);
    else if (OPAQUE.test(target)) throw new ArchiveSecretScanError(`opaque archive requires a dedicated format scanner: ${target}`);
    else if (stat.isFile()) addFile(target, state, limits);
    else throw new ArchiveSecretScanError(`artifact contains an unsupported entry: ${target}`);
  }
  return Object.freeze({ version: 1, clean: true, files: Object.freeze(state.files.sort(compareFiles)), total_bytes: state.totalBytes });
}

function walkDirectory(directory, state, limits, visit, { countEntries = true } = {}) {
  const stat = lstatOrThrow(directory);
  if (stat.isSymbolicLink()) throw new ArchiveSecretScanError(`artifact contains a symlink: ${directory}`);
  if (!stat.isDirectory()) throw new ArchiveSecretScanError(`artifact directory is not a directory: ${directory}`);
  for (const entry of fs.readdirSync(directory).sort(compareStrings)) {
    const target = path.join(directory, entry);
    const child = lstatOrThrow(target);
    if (countEntries) registerEntry(state, limits);
    if (child.isDirectory()) walkDirectory(target, state, limits, visit, { countEntries });
    else if (child.isSymbolicLink() || !child.isFile()) throw new ArchiveSecretScanError(`artifact contains an unsupported entry: ${target}`);
    else if (TAR.test(target)) throw new ArchiveSecretScanError(`nested archive must be scanned explicitly: ${target}`);
    else if (OPAQUE.test(target)) throw new ArchiveSecretScanError(`opaque archive requires a dedicated format scanner: ${target}`);
    else visit(target);
  }
}

function scanTar(archive, state, limits) {
  const listing = runTarListing(["-tvf", archive], archive);
  const detailedEntries = splitListing(listing, archive);
  for (const line of detailedEntries) {
    const type = line[0];
    if (type !== "-" && type !== "d") throw new ArchiveSecretScanError(`tar contains an unsupported entry type: ${archive}`);
  }
  const names = splitListing(runTarListing(["-tf", archive], archive), archive);
  if (detailedEntries.length !== names.length) throw new ArchiveSecretScanError(`tar listing is inconsistent: ${archive}`);
  const members = new Map();
  const memberKeys = new Set();
  const entries = names.map((name, index) => {
    const member = normalizeMemberName(name, limits.maximumMemberPathBytes, archive);
    const memberKey = member.normalize("NFC").toLowerCase();
    if (members.has(member) || memberKeys.has(memberKey)) throw new ArchiveSecretScanError(`tar contains a duplicate or colliding path: ${name}`);
    members.set(member, name);
    memberKeys.add(memberKey);
    registerEntry(state, limits);
    return Object.freeze({ member, type: detailedEntries[index][0] });
  });
  for (const entry of entries) {
    if (entry.type !== "-") continue;
    if (TAR.test(entry.member)) throw new ArchiveSecretScanError(`nested archive must be scanned explicitly: ${entry.member}`);
    if (OPAQUE.test(entry.member)) throw new ArchiveSecretScanError(`opaque archive requires a dedicated format scanner: ${entry.member}`);
    const remainingBytes = limits.maximumTotalBytes - state.totalBytes;
    const maximumOutput = Math.min(limits.maximumFileBytes, remainingBytes);
    const bytes = extractTarMember(archive, members.get(entry.member), maximumOutput + 1);
    addBytes(bytes, state, limits, `${archive}::${entry.member}`);
  }
}

function addFile(file, state, limits, displayPath = file, { countEntry = true } = {}) {
  if (countEntry) registerEntry(state, limits);
  const descriptor = fs.constants.O_NOFOLLOW ?? 0;
  let fd;
  try { fd = fs.openSync(file, fs.constants.O_RDONLY | descriptor); }
  catch { throw new ArchiveSecretScanError(`artifact file could not be opened safely: ${file}`); }
  let stat;
  let bytes;
  try {
    stat = fs.fstatSync(fd);
    if (!stat.isFile()) throw new ArchiveSecretScanError(`artifact contains an unsupported file: ${file}`);
    if (stat.size > limits.maximumFileBytes || state.totalBytes + stat.size > limits.maximumTotalBytes) throw new ArchiveSecretScanError(`artifact exceeds scan size limit: ${file}`);
    bytes = Buffer.allocUnsafe(stat.size);
    let offset = 0;
    while (offset < bytes.length) {
      const bytesRead = fs.readSync(fd, bytes, offset, bytes.length - offset, offset);
      if (bytesRead === 0) throw new ArchiveSecretScanError(`artifact file changed while being scanned: ${file}`);
      offset += bytesRead;
    }
    const after = fs.fstatSync(fd);
    if (after.dev !== stat.dev || after.ino !== stat.ino || after.size !== stat.size || after.nlink !== stat.nlink) throw new ArchiveSecretScanError(`artifact file changed while being scanned: ${file}`);
  } finally {
    fs.closeSync(fd);
  }
  if (stat.nlink !== 1) throw new ArchiveSecretScanError(`artifact contains a hardlink: ${file}`);
  const inode = `${stat.dev}:${stat.ino}`;
  if (state.seenInodes.has(inode)) throw new ArchiveSecretScanError(`artifact contains a duplicate hardlink: ${file}`);
  state.seenInodes.add(inode);
  addBytes(bytes, state, limits, displayPath);
}

function addBytes(bytes, state, limits, displayPath) {
  if (!Buffer.isBuffer(bytes)) throw new ArchiveSecretScanError(`artifact file is not a byte buffer: ${displayPath}`);
  if (bytes.length > limits.maximumFileBytes || state.totalBytes + bytes.length > limits.maximumTotalBytes) throw new ArchiveSecretScanError(`artifact exceeds scan size limit: ${displayPath}`);
  if (containsSecretMaterial(bytes.toString("utf8"))) throw new ArchiveSecretScanError(`artifact contains secret material: ${displayPath}`);
  state.files.push(Object.freeze({ path: displayPath, bytes: bytes.length, sha256: crypto.createHash("sha256").update(bytes).digest("hex") }));
  state.totalBytes += bytes.length;
}

function containsSecretMaterial(text) {
  const parsed = parseJsonDocument(text);
  if (parsed.valid) return containsJsonSecret(parsed.value) || TEXT_SECRET_MARKERS.some((marker) => marker.test(text));
  return LEGACY_SECRET_MARKERS.some((marker) => marker.test(text));
}

function parseJsonDocument(text) {
  const candidate = text.charCodeAt(0) === 0xfeff ? text.slice(1) : text;
  const trimmed = candidate.trim();
  if (!trimmed.startsWith("{") && !trimmed.startsWith("[")) return { valid: false, value: undefined };
  try { return { valid: true, value: JSON.parse(trimmed) }; }
  catch { return { valid: false, value: undefined }; }
}

function containsJsonSecret(value) {
  const pending = [value];
  while (pending.length > 0) {
    const current = pending.pop();
    if (Array.isArray(current)) {
      for (const item of current) pending.push(item);
      continue;
    }
    if (current === null || typeof current !== "object") continue;
    for (const [key, child] of Object.entries(current)) {
      if (JSON_SECRET_KEYS.has(normalizeJsonKey(key)) && isMeaningfulJsonSecret(child)) return true;
      pending.push(child);
    }
  }
  return false;
}

function normalizeJsonKey(key) {
  return key.normalize("NFKC").replace(/[\s_-]+/gu, "").toLowerCase();
}

function isMeaningfulJsonSecret(value) {
  if (typeof value !== "string") return false;
  const normalized = value.trim().normalize("NFKC").toLowerCase().replace(/[\s_-]+/gu, "");
  if (JSON_PLACEHOLDER_VALUES.has(normalized)) return false;
  if (/^(?:\[|<)?(?:redacted|placeholder|masked|hidden|removed)(?:[\s_-]+(?:value|secret|token|password|key|by[\s_-]+policy))?(?:\]|>)?$/iu.test(value.trim())) return false;
  if (/^[*#x-]{3,}$/iu.test(value.trim())) return false;
  return normalized.length > 0;
}

function registerEntry(state, limits) {
  state.entries += 1;
  if (state.entries > limits.maximumEntries) throw new ArchiveSecretScanError("artifact exceeds entry count limit");
}

function validateLimit(value, name, maximum) {
  if (!Number.isSafeInteger(value) || value < 0 || value > maximum) throw new ArchiveSecretScanError(`${name} must be a non-negative safe integer no greater than ${maximum}`);
  return value;
}

function extractTarMember(archive, name, maximumBuffer) {
  try {
    return execFileSync("tar", ["-xOf", archive, "--", name], { encoding: null, maxBuffer: maximumBuffer, stdio: ["ignore", "pipe", "ignore"] });
  } catch (error) {
    if (error?.code === "ENOBUFS" || /maxBuffer/iu.test(error?.message ?? "")) throw new ArchiveSecretScanError(`tar member exceeds scan size limit: ${archive}::${name}`);
    throw new ArchiveSecretScanError(`tar member extraction failed: ${archive}::${name}`);
  }
}

function resolveInputPath(input) {
  try {
    if (input instanceof URL) {
      if (input.protocol !== "file:" || input.search || input.hash) throw new ArchiveSecretScanError("artifact URL must be a query-free file URL");
      return path.resolve(fileURLToPath(input));
    }
    if (typeof input !== "string" || input.length === 0) throw new ArchiveSecretScanError("artifact paths must be non-empty strings or file URLs");
    if (/^file:/iu.test(input)) {
      const url = new URL(input);
      if (url.protocol !== "file:" || url.search || url.hash) throw new ArchiveSecretScanError("artifact URL must be a query-free file URL");
      return path.resolve(fileURLToPath(url));
    }
    if (/^[A-Za-z][A-Za-z0-9+.-]*:/u.test(input)) throw new ArchiveSecretScanError("artifact URL must use the file scheme");
    return path.resolve(input);
  } catch (error) {
    if (error instanceof ArchiveSecretScanError) throw error;
    throw new ArchiveSecretScanError(`invalid artifact path: ${error instanceof Error ? error.message : String(error)}`);
  }
}

function lstatOrThrow(target) {
  try { return fs.lstatSync(target); }
  catch (error) { throw new ArchiveSecretScanError(`artifact path could not be inspected: ${target}`); }
}

function runTarListing(args, archive) {
  try {
    return execFileSync("tar", args, { encoding: "utf8", maxBuffer: MAX_LISTING_BYTES, stdio: ["ignore", "pipe", "ignore"] });
  } catch {
    throw new ArchiveSecretScanError(`tar listing failed: ${archive}`);
  }
}

function splitListing(listing, archive) {
  if (Buffer.byteLength(listing, "utf8") > MAX_LISTING_BYTES) throw new ArchiveSecretScanError(`tar listing exceeds scan limit: ${archive}`);
  return listing.split("\n").filter((line) => line.length > 0);
}

function normalizeMemberName(name, maximumMemberPathBytes, archive) {
  if (typeof name !== "string" || name.length === 0 || name.includes("\0") || name.includes("\\") || Buffer.byteLength(name, "utf8") > maximumMemberPathBytes) {
    throw new ArchiveSecretScanError(`tar contains an invalid member path: ${archive}`);
  }
  if (name.startsWith("/") || /^[A-Za-z]:/u.test(name)) throw new ArchiveSecretScanError(`tar contains an unsafe path: ${name}`);
  const parts = name.split("/");
  if (parts.includes("..")) throw new ArchiveSecretScanError(`tar contains an unsafe path: ${name}`);
  const normalized = parts.filter((part) => part !== "" && part !== ".").join("/");
  return normalized || ".";
}

function compareStrings(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function compareFiles(left, right) {
  return compareStrings(left.path, right.path);
}

const invokedAs = process.argv[1];
const invokedPath = invokedAs && (/^file:/iu.test(invokedAs) ? fileURLToPath(new URL(invokedAs)) : path.resolve(invokedAs));
if (invokedPath && invokedPath === fileURLToPath(import.meta.url)) {
  try { process.stdout.write(`${JSON.stringify(scanArchives(process.argv.slice(2)))}\n`); }
  catch (error) { process.stderr.write(`archive secret scan failed: ${error.message}\n`); process.exitCode = 1; }
}
