import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";

const ROOT_NAME = "AgentPassQualificationController.app";
const ROOT_PREFIX = `${ROOT_NAME}/`;
const BLOCK_SIZE = 512;
const END_BLOCKS = 2;
const REGULAR_TYPE = 0x30;
const DIRECTORY_TYPE = 0x35;
const DIRECTORY_MODE = 0o040000;
const REGULAR_MODE = 0o100000;
const SAFE_MODE_MASK = 0o777;
const NOFOLLOW = fs.constants.O_NOFOLLOW ?? 0;
const DIRECTORY_FLAG = fs.constants.O_DIRECTORY ?? 0;

export const CONTROLLER_ARCHIVE_ROOT = ROOT_NAME;
export const CONTROLLER_ARCHIVE_LIMITS = Object.freeze({
  maxEntries: 4_096,
  maxEntryBytes: 64 * 1024 * 1024,
  maxArchiveBytes: 256 * 1024 * 1024,
  maxPathBytes: 255,
});

function fail(message, code = "ERR_CONTROLLER_ARCHIVE") {
  const error = new Error(message);
  error.code = code;
  return error;
}

function assertAbsolute(value, label) {
  if (typeof value !== "string" || value.length === 0 || value.includes("\0") || !path.isAbsolute(value)) {
    throw fail(`${label} must be an absolute path`);
  }
}

function effectiveLimits(value) {
  const limits = { ...CONTROLLER_ARCHIVE_LIMITS, ...(value ?? {}) };
  for (const key of Object.keys(CONTROLLER_ARCHIVE_LIMITS)) {
    if (!Number.isSafeInteger(limits[key]) || limits[key] <= 0) throw fail(`invalid ${key} limit`);
  }
  return Object.freeze(limits);
}

function allZero(buffer) {
  for (const byte of buffer) if (byte !== 0) return false;
  return true;
}

function sameStat(left, right) {
  return ["dev", "ino", "mode", "nlink", "size", "mtimeNs", "ctimeNs"].every((key) => String(left[key]) === String(right[key]));
}

function statSnapshot(stat) {
  return {
    dev: String(stat.dev),
    ino: String(stat.ino),
    mode: String(stat.mode),
    nlink: String(stat.nlink),
    size: String(stat.size),
    mtimeNs: String(stat.mtimeNs ?? BigInt(Math.trunc(Number(stat.mtimeMs) * 1_000_000))),
    ctimeNs: String(stat.ctimeNs ?? BigInt(Math.trunc(Number(stat.ctimeMs) * 1_000_000))),
  };
}

function assertRegularArchiveInput(archivePath, limits) {
  assertAbsolute(archivePath, "archive");
  let stat;
  try {
    stat = fs.lstatSync(archivePath, { bigint: true });
  } catch (error) {
    throw fail(`archive is unavailable: ${error.message}`, error.code);
  }
  const mode = Number(stat.mode);
  if ((mode & 0o170000) !== REGULAR_MODE || stat.isSymbolicLink?.()) throw fail("archive must be a regular file");
  if (String(stat.nlink) !== "1") throw fail("hard-linked archive inputs are not permitted");
  if ((mode & 0o7000) !== 0) throw fail("archive has unsafe modes");
  if (Number(stat.size) > limits.maxArchiveBytes) throw fail("archive exceeds the size limit");
  return statSnapshot(stat);
}

function readStableArchive(archivePath, limits) {
  assertSafeDirectoryAncestry(path.dirname(archivePath));
  const initial = assertRegularArchiveInput(archivePath, limits);
  let fd;
  try {
    fd = fs.openSync(archivePath, fs.constants.O_RDONLY | NOFOLLOW);
    const opened = statSnapshot(fs.fstatSync(fd, { bigint: true }));
    if (!sameStat(initial, opened)) throw fail("archive changed while opening");
    const length = Number(opened.size);
    if (length > limits.maxArchiveBytes) throw fail("archive exceeds the size limit");
    const bytes = Buffer.allocUnsafe(length);
    let offset = 0;
    while (offset < length) {
      const count = fs.readSync(fd, bytes, offset, length - offset, offset);
      if (count === 0) throw fail("archive ended while being read");
      offset += count;
    }
    const after = statSnapshot(fs.fstatSync(fd, { bigint: true }));
    if (!sameStat(initial, after)) throw fail("archive changed while being read");
    return bytes;
  } catch (error) {
    if (error.code === "ELOOP") throw fail("archive must not be a symlink");
    throw error;
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
  }
}

function decodeTextField(header, offset, length, label) {
  const field = header.subarray(offset, offset + length);
  const nul = field.indexOf(0);
  const end = nul === -1 ? field.length : nul;
  if (nul !== -1 && !allZero(field.subarray(nul))) throw fail(`${label} has noncanonical padding`);
  const bytes = field.subarray(0, end);
  const value = bytes.toString("utf8");
  if (!Buffer.from(value, "utf8").equals(bytes)) throw fail(`${label} is not valid UTF-8`);
  if (value.includes("\0")) throw fail(`${label} contains NUL`);
  return value;
}

function decodeOctalField(header, offset, length, label) {
  const field = header.subarray(offset, offset + length);
  if (field[length - 1] !== 0) throw fail(`${label} is not a canonical octal field`);
  for (let index = 0; index < length - 1; index += 1) {
    if (field[index] < 0x30 || field[index] > 0x37) throw fail(`${label} is not a canonical octal field`);
  }
  return BigInt(`0o${field.subarray(0, length - 1).toString("ascii")}`);
}

function decodeChecksum(header) {
  const field = header.subarray(148, 156);
  for (let index = 0; index < 6; index += 1) {
    if (field[index] < 0x30 || field[index] > 0x37) throw fail("checksum field is not canonical");
  }
  if (field[6] !== 0 || field[7] !== 0x20) throw fail("checksum field is not canonical");
  return BigInt(`0o${field.subarray(0, 6).toString("ascii")}`);
}

function checksum(header) {
  let total = 0;
  for (let index = 0; index < header.length; index += 1) total += index >= 148 && index < 156 ? 0x20 : header[index];
  return BigInt(total);
}

function splitUstarPath(archivePath) {
  if (Buffer.byteLength(archivePath, "utf8") <= 100) return { name: archivePath, prefix: "" };
  const slashIndexes = [...archivePath.matchAll(/\//gu)]
    .map(({ index }) => index)
    .filter((index) => index > 0 && index < archivePath.length - 1);
  for (let index = slashIndexes.length - 1; index >= 0; index -= 1) {
    const slash = slashIndexes[index];
    const prefix = archivePath.slice(0, slash);
    const name = archivePath.slice(slash + 1);
    if (Buffer.byteLength(prefix, "utf8") <= 155 && Buffer.byteLength(name, "utf8") <= 100) return { name, prefix };
  }
  throw fail("archive path cannot be represented by ustar");
}

function validateArchivePath(archivePath, limits) {
  if (Buffer.byteLength(archivePath, "utf8") === 0 || Buffer.byteLength(archivePath, "utf8") > limits.maxPathBytes) {
    throw fail("archive path exceeds the path limit");
  }
  if (archivePath !== ROOT_PREFIX && !archivePath.startsWith(ROOT_PREFIX)) throw fail("archive path is outside the controller app root");
  if (archivePath.startsWith("/") || archivePath.includes("\\") || archivePath.includes("\0")) throw fail("archive path is unsafe");
  const components = archivePath.split("/");
  const trailing = archivePath.endsWith("/");
  const pathComponents = trailing ? components.slice(0, -1) : components;
  if (pathComponents.some((component) => component.length === 0 || component === "." || component === "..")) throw fail("archive path is unsafe");
  if (pathComponents[0] !== ROOT_NAME) throw fail("archive path is outside the controller app root");
  const canonical = splitUstarPath(archivePath);
  return { directory: trailing, canonical };
}

function parseHeader(header, limits) {
  if (header.length !== BLOCK_SIZE) throw fail("archive header is truncated");
  if (!header.subarray(257, 263).equals(Buffer.from("ustar\0", "ascii")) || !header.subarray(263, 265).equals(Buffer.from("00", "ascii"))) {
    throw fail("archive header is not canonical USTAR");
  }
  if (!allZero(header.subarray(157, 257)) || !allZero(header.subarray(265, 345)) || !allZero(header.subarray(500, 512))) {
    throw fail("archive header contains noncanonical fields");
  }
  const expectedChecksum = decodeChecksum(header);
  if (expectedChecksum !== checksum(header)) throw fail("archive header checksum is invalid");
  const name = decodeTextField(header, 0, 100, "name");
  const prefix = decodeTextField(header, 345, 155, "prefix");
  if (name.length === 0) throw fail("archive header has an empty name");
  const archivePath = prefix.length === 0 ? name : `${prefix}/${name}`;
  const pathInfo = validateArchivePath(archivePath, limits);
  if (pathInfo.canonical.name !== name || pathInfo.canonical.prefix !== prefix) throw fail("archive path encoding is not canonical");
  const mode = decodeOctalField(header, 100, 8, "mode");
  const uid = decodeOctalField(header, 108, 8, "uid");
  const gid = decodeOctalField(header, 116, 8, "gid");
  const size = decodeOctalField(header, 124, 12, "size");
  const mtime = decodeOctalField(header, 136, 12, "mtime");
  const type = header[156];
  if (uid !== 0n || gid !== 0n || mtime !== 0n) throw fail("uid, gid, and mtime must be zero");
  if (mode > BigInt(SAFE_MODE_MASK)) throw fail("archive entry has unsafe modes");
  if ((Number(mode) & 0o022) !== 0) throw fail("archive entry is writable by another user");
  if (size > BigInt(limits.maxEntryBytes)) throw fail("archive entry exceeds the size limit");
  if (type !== REGULAR_TYPE && type !== DIRECTORY_TYPE) throw fail("archive entry type is not permitted");
  if (pathInfo.directory !== (type === DIRECTORY_TYPE)) throw fail("archive entry type does not match its path");
  if (type === DIRECTORY_TYPE && (size !== 0n || (Number(mode) & 0o100) === 0)) throw fail("archive directory metadata is unsafe");
  return { archivePath, mode: Number(mode), size: Number(size), type, directory: type === DIRECTORY_TYPE };
}

function assertEntryParents(entries) {
  if (entries.length === 0 || entries[0].archivePath !== ROOT_PREFIX || !entries[0].directory) throw fail("archive must begin with the controller app root directory");
  const seen = new Map();
  for (const entry of entries) {
    if (seen.has(entry.archivePath)) throw fail("archive contains duplicate paths");
    seen.set(entry.archivePath, entry);
    if (entry.archivePath === ROOT_PREFIX) continue;
    const withoutSlash = entry.archivePath.endsWith("/") ? entry.archivePath.slice(0, -1) : entry.archivePath;
    const slash = withoutSlash.lastIndexOf("/");
    const parent = `${withoutSlash.slice(0, slash + 1)}`;
    const parentEntry = seen.get(parent);
    if (!parentEntry || !parentEntry.directory) throw fail("archive is missing a parent directory");
  }
}

export function parseControllerArchive(input, options = {}) {
  if (!Buffer.isBuffer(input) && !(input instanceof Uint8Array)) throw fail("archive bytes must be a Buffer");
  const archive = Buffer.from(input);
  const limits = effectiveLimits(options.limits ?? options);
  if (archive.length > limits.maxArchiveBytes) throw fail("archive exceeds the size limit");
  if (archive.length < END_BLOCKS * BLOCK_SIZE || archive.length % BLOCK_SIZE !== 0) throw fail("archive is truncated or has a non-block-aligned size");
  const entries = [];
  let offset = 0;
  let terminated = false;
  while (offset < archive.length) {
    const header = archive.subarray(offset, offset + BLOCK_SIZE);
    if (header.length !== BLOCK_SIZE) throw fail("archive header is truncated");
    if (allZero(header)) {
      if (offset + END_BLOCKS * BLOCK_SIZE !== archive.length || !allZero(archive.subarray(offset + BLOCK_SIZE, offset + END_BLOCKS * BLOCK_SIZE))) {
        throw fail("archive has trailing data or an incomplete end marker");
      }
      terminated = true;
      break;
    }
    if (entries.length >= limits.maxEntries) throw fail("archive contains too many entries");
    const entry = parseHeader(header, limits);
    const dataStart = offset + BLOCK_SIZE;
    const padding = (BLOCK_SIZE - (entry.size % BLOCK_SIZE)) % BLOCK_SIZE;
    const next = dataStart + entry.size + padding;
    if (next > archive.length) throw fail("archive entry is truncated");
    const data = entry.directory ? Buffer.alloc(0) : Buffer.from(archive.subarray(dataStart, dataStart + entry.size));
    if (!allZero(archive.subarray(dataStart + entry.size, next))) throw fail("archive data padding is not canonical");
    entries.push({ ...entry, data });
    offset = next;
  }
  if (!terminated) throw fail("archive is missing its two-block end marker");
  for (let index = 1; index < entries.length; index += 1) {
    if (Buffer.from(entries[index - 1].archivePath, "utf8").compare(Buffer.from(entries[index].archivePath, "utf8")) >= 0) {
      throw fail("archive entries are not in canonical byte order");
    }
  }
  assertEntryParents(entries);
  return Object.freeze({ entries: Object.freeze(entries), bytes: archive.length });
}

function assertSafeDirectoryAncestry(directory) {
  const parsed = path.parse(directory);
  let current = parsed.root;
  const parts = directory.slice(parsed.root.length).split(path.sep).filter(Boolean);
  for (const part of parts) {
    current = path.join(current, part);
    let stat;
    try {
      stat = fs.lstatSync(current, { bigint: true });
    } catch (error) {
      throw fail(`output ancestry is unavailable: ${error.message}`, error.code);
    }
    const mode = Number(stat.mode);
    if ((mode & 0o170000) !== DIRECTORY_MODE || stat.isSymbolicLink?.()) throw fail("output ancestry contains an unsafe path");
    if ((mode & 0o6000) !== 0 || ((mode & 0o022) !== 0 && (mode & 0o1000) === 0)) throw fail("output ancestry has unsafe modes");
  }
}

function assertDestination(destination) {
  assertAbsolute(destination, "destination");
  const parent = path.dirname(destination);
  assertSafeDirectoryAncestry(parent);
  const parentStat = fs.lstatSync(parent, { bigint: true });
  if ((Number(parentStat.mode) & 0o022) !== 0) throw fail("destination parent is writable by another user");
  try {
    fs.lstatSync(destination, { bigint: true });
    throw fail("destination already exists", "EEXIST");
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }
  return parent;
}

function writeAll(fd, data) {
  let offset = 0;
  while (offset < data.length) offset += fs.writeSync(fd, data, offset, data.length - offset, offset);
}

function fsyncDirectory(directory) {
  const fd = fs.openSync(directory, fs.constants.O_RDONLY | DIRECTORY_FLAG | NOFOLLOW);
  try {
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
}

function removeStage(stage) {
  if (stage === undefined) return;
  try { fs.rmSync(stage, { recursive: true, force: true }); } catch {}
}

function extractToStage(parsed, parent) {
  const stage = fs.mkdtempSync(path.join(parent, ".agentpass-controller-extract-"));
  try {
    fs.chmodSync(stage, 0o700);
    const directories = [{ target: stage, mode: parsed.entries[0].mode }];
    for (const entry of parsed.entries.slice(1)) {
      const relative = entry.archivePath.slice(ROOT_PREFIX.length).replace(/\/$/u, "");
      const target = path.join(stage, ...relative.split("/"));
      if (entry.directory) {
        fs.mkdirSync(target, { mode: 0o700 });
        directories.push({ target, mode: entry.mode });
        continue;
      }
      const fd = fs.openSync(target, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | NOFOLLOW, 0o600);
      try {
        writeAll(fd, entry.data);
        fs.fchmodSync(fd, entry.mode);
        fs.fsyncSync(fd);
      } finally {
        fs.closeSync(fd);
      }
      const stat = fs.lstatSync(target, { bigint: true });
      if ((Number(stat.mode) & 0o170000) !== REGULAR_MODE || String(stat.nlink) !== "1") throw fail("extracted file identity is unsafe");
      fsyncDirectory(path.dirname(target));
    }
    const directoryDescriptors = directories.map(({ target, mode }) => ({ fd: fs.openSync(target, fs.constants.O_RDONLY | DIRECTORY_FLAG | NOFOLLOW), mode, target }));
    try {
      for (const directory of directoryDescriptors) {
        fs.chmodSync(directory.target, directory.mode);
        fs.fsyncSync(directory.fd);
      }
    } finally {
      for (const directory of directoryDescriptors) fs.closeSync(directory.fd);
    }
    fsyncDirectory(parent);
    return stage;
  } catch (error) {
    removeStage(stage);
    throw error;
  }
}

export function verifyAndExtractControllerArchive({ archivePath, archive, destination, limits } = {}) {
  assertAbsolute(destination, "destination");
  const parent = assertDestination(destination);
  const effective = effectiveLimits(limits);
  const archiveBytes = archive === undefined ? readStableArchive(archivePath, effective) : Buffer.from(archive);
  const parsed = parseControllerArchive(archiveBytes, effective);
  const digest = crypto.createHash("sha256").update(archiveBytes).digest("hex");
  let stage;
  try {
    stage = extractToStage(parsed, parent);
    try {
      fs.lstatSync(destination, { bigint: true });
      throw fail("destination already exists", "EEXIST");
    } catch (error) {
      if (error.code !== "ENOENT") throw error;
    }
    fs.renameSync(stage, destination);
    stage = undefined;
    fsyncDirectory(parent);
  } finally {
    removeStage(stage);
  }
  return Object.freeze({ destination, bytes: archiveBytes.length, entries: parsed.entries.length, sha256: digest });
}

export const extractControllerArchive = verifyAndExtractControllerArchive;
export const verifyControllerArchive = verifyAndExtractControllerArchive;
export const parseUstarControllerArchive = parseControllerArchive;

function main(argv) {
  if (argv.length !== 2 || !path.isAbsolute(argv[0]) || !path.isAbsolute(argv[1])) throw fail("Usage: verify-controller-archive.mjs ARCHIVE ABSOLUTE-DESTINATION", "ERR_USAGE");
  const result = verifyAndExtractControllerArchive({ archivePath: argv[0], destination: argv[1] });
  process.stdout.write(`${JSON.stringify({ ok: true, sha256: result.sha256, entries: result.entries })}\n`);
}

if (process.argv[1] && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url) {
  try {
    main(process.argv.slice(2));
  } catch (error) {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  }
}
