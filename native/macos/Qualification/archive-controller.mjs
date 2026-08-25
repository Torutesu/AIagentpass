import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { spawnSync } from "node:child_process";

const ROOT_NAME = "AgentPassQualificationController.app";
const TAR_BLOCK = 512;
const TAR_EOF_BLOCKS = 2;
const DEFAULT_LIMITS = Object.freeze({
  maxEntries: 4_096,
  maxEntryBytes: 64 * 1024 * 1024,
  maxArchiveBytes: 256 * 1024 * 1024,
  maxPathBytes: 255,
  maxXattrOutputBytes: 64 * 1024,
});

const SEMVER = /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-((?:0|[1-9A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9A-Za-z-][0-9A-Za-z-]*))*))?(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$/u;
const NOFOLLOW = fs.constants.O_NOFOLLOW ?? 0;
const READ_ONLY = fs.constants.O_RDONLY;
const REGULAR_FILE = 0o100000;
const DIRECTORY = 0o040000;
const SAFE_MODE_MASK = 0o0777;
const ALLOWED_XATTRS = new Set(["com.apple.provenance"]);

export const CONTROLLER_ARCHIVE_ROOT = ROOT_NAME;
export const CONTROLLER_ARCHIVE_LIMITS = DEFAULT_LIMITS;
export const CONTROLLER_ARCHIVE_ALLOWED_XATTRS = Object.freeze([...ALLOWED_XATTRS]);

function fail(message, code = "ERR_CONTROLLER_ARCHIVE") {
  const error = new Error(message);
  error.code = code;
  return error;
}

function assertString(value, label) {
  if (typeof value !== "string" || value.length === 0 || value.includes("\0")) {
    throw fail(`${label} must be a non-empty path-safe string`);
  }
}

function assertSemver(version) {
  assertString(version, "version");
  if (!SEMVER.test(version)) throw fail("version must be a strict semantic version");
}

function expectedArchiveName(version) {
  return `AgentPassQualificationController-${version}-macos-universal.tar`;
}

function assertAbsolutePath(value, label) {
  assertString(value, label);
  if (!path.isAbsolute(value)) throw fail(`${label} must be absolute`);
}

function statKind(stat) {
  const mode = typeof stat.mode === "bigint" ? Number(stat.mode) : stat.mode;
  const type = mode & 0o170000;
  if (type === DIRECTORY) return "directory";
  if (type === REGULAR_FILE) return "file";
  if (stat.isSymbolicLink?.() || type === 0o120000) throw fail("symbolic links are not permitted");
  throw fail("only regular files and directories are permitted");
}

function metadata(stat, kind) {
  const mode = typeof stat.mode === "bigint" ? Number(stat.mode) : stat.mode;
  return Object.freeze({
    kind,
    dev: String(stat.dev),
    ino: String(stat.ino),
    mode: mode & 0o7777,
    uid: String(stat.uid),
    gid: String(stat.gid),
    size: String(stat.size),
    nlink: String(stat.nlink),
    mtimeNs: String(stat.mtimeNs ?? BigInt(Math.trunc(Number(stat.mtimeMs) * 1_000_000))),
    ctimeNs: String(stat.ctimeNs ?? BigInt(Math.trunc(Number(stat.ctimeMs) * 1_000_000))),
  });
}

function metadataEqual(left, right) {
  return Object.keys(left).every((key) => left[key] === right[key]);
}

function assertSafeMode(stat) {
  const rawMode = typeof stat.mode === "bigint" ? Number(stat.mode) : stat.mode;
  const mode = rawMode & 0o7777;
  if ((mode & ~SAFE_MODE_MASK) !== 0) throw fail("setuid, setgid, and sticky modes are not permitted");
}

function validateLimits(value) {
  const limits = { ...DEFAULT_LIMITS, ...(value ?? {}) };
  for (const key of Object.keys(DEFAULT_LIMITS)) {
    if (!Number.isSafeInteger(limits[key]) || limits[key] <= 0) throw fail(`invalid ${key} limit`);
  }
  return Object.freeze(limits);
}

function lexicalCompare(left, right) {
  return Buffer.from(left.archivePath, "utf8").compare(Buffer.from(right.archivePath, "utf8"));
}

function validateArchivePath(archivePath, limits) {
  const bytes = Buffer.byteLength(archivePath, "utf8");
  if (bytes === 0 || bytes > limits.maxPathBytes) throw fail("archive path is too long");
  if (archivePath.startsWith("/") || archivePath.includes("\0") || archivePath.split("/").includes("..")) {
    throw fail("archive path is unsafe");
  }
  if (archivePath.split("/").some((component) => component.length === 0 && !archivePath.endsWith("/"))) {
    throw fail("archive path contains an empty component");
  }
}

function inspectXattrsWithPlatformTool(target, limits = DEFAULT_LIMITS) {
  const tool = process.platform === "darwin"
    ? "/usr/bin/xattr"
    : process.platform === "linux"
      ? ["/usr/bin/getfattr", "/bin/getfattr"].find((candidate) => fs.existsSync(candidate))
      : undefined;
  if (!tool) return [];

  const args = process.platform === "darwin"
    ? ["-l", target]
    : ["-d", "-m", "-", "--", target];
  const result = spawnSync(tool, args, { encoding: "buffer", maxBuffer: limits.maxXattrOutputBytes });
  if (result.error) throw fail(`xattr inspection failed: ${result.error.message}`);
  if (result.status !== 0) throw fail("xattr inspection failed");
  const output = Buffer.isBuffer(result.stdout) ? result.stdout : Buffer.from(result.stdout ?? "");
  if (output.length > limits.maxXattrOutputBytes) throw fail("xattr metadata is too large");
  if (process.platform === "darwin") {
    if (output.length === 0) return [];
    const names = output.toString("utf8").split(/\r?\n/u)
      .map((line) => /^([^:\r\n]+):/u.exec(line)?.[1])
      .filter((name) => name !== undefined);
    return names.length > 0 ? names : ["<unparsed-xattr>"];
  }
  return output.toString("utf8").split(/\r?\n/u)
    .map((line) => /^([^=#\r\n]+)=/u.exec(line)?.[1])
    .filter((name) => name !== undefined);
}

function assertNoXattrs(target, inspector, limits) {
  const names = inspector(target, limits);
  const present = names === true
    ? ["<unknown-xattr>"]
    : Array.isArray(names)
      ? names
      : typeof names === "string" && names.length > 0
        ? [names]
        : [];
  if (present.some((name) => !ALLOWED_XATTRS.has(name))) {
    throw fail("extended attributes are not permitted");
  }
}

function readStableFile(target, initialStat, limits) {
  if (Number(initialStat.size) > limits.maxEntryBytes) throw fail("file exceeds the per-entry size limit");
  const fd = fs.openSync(target, READ_ONLY | NOFOLLOW);
  try {
    const opened = fs.fstatSync(fd, { bigint: true });
    const kind = statKind(opened);
    if (kind !== "file" || !metadataEqual(metadata(initialStat, "file"), metadata(opened, "file"))) {
      throw fail("file changed while opening");
    }
    const length = Number(opened.size);
    const data = Buffer.allocUnsafe(length);
    let offset = 0;
    while (offset < data.length) {
      const count = fs.readSync(fd, data, offset, data.length - offset, offset);
      if (count === 0) throw fail("file ended while being read");
      offset += count;
    }
    const after = fs.fstatSync(fd, { bigint: true });
    if (!metadataEqual(metadata(initialStat, "file"), metadata(after, "file"))) throw fail("file changed while reading");
    return data;
  } finally {
    fs.closeSync(fd);
  }
}

function assertRegularFileIdentity(stat, identities) {
  if (String(stat.nlink) !== "1") throw fail("hard-linked files are not permitted");
  const identity = `${stat.dev}:${stat.ino}`;
  if (identities.has(identity)) throw fail("hard-linked files are not permitted");
  identities.add(identity);
}

function entryFor(target, archivePath, stat, kind, data) {
  return {
    target,
    archivePath,
    kind,
    stat: metadata(stat, kind),
    data,
    digest: data ? crypto.createHash("sha256").update(data).digest("hex") : undefined,
  };
}

function collectEntries(source, limits, inspector, { readData }) {
  const entries = [];
  const regularIdentities = new Set();
  const visit = (target, relative) => {
    const stat = fs.lstatSync(target, { bigint: true });
    const kind = statKind(stat);
    assertSafeMode(stat);
    assertNoXattrs(target, inspector, limits);
    const archivePath = relative.length === 0
      ? `${ROOT_NAME}/`
      : `${ROOT_NAME}/${relative}${kind === "directory" ? "/" : ""}`;
    validateArchivePath(archivePath, limits);
    if (entries.length >= limits.maxEntries) throw fail("archive contains too many entries");
    if (kind === "file") {
      assertRegularFileIdentity(stat, regularIdentities);
      const data = readData ? readStableFile(target, stat, limits) : undefined;
      entries.push(entryFor(target, archivePath, stat, kind, data));
      return;
    }

    entries.push(entryFor(target, archivePath, stat, kind, undefined));
    const children = fs.readdirSync(target, { encoding: "utf8" });
    children.sort((left, right) => Buffer.from(left, "utf8").compare(Buffer.from(right, "utf8")));
    for (const child of children) {
      if (child.includes("\0") || child === "." || child === "..") throw fail("unsafe directory entry");
      const childRelative = relative.length === 0 ? child : `${relative}/${child}`;
      visit(path.join(target, child), childRelative);
    }
  };
  visit(source, "");
  entries.sort(lexicalCompare);
  return entries;
}

function assertSnapshotUnchanged(source, snapshot, limits, inspector) {
  const current = collectEntries(source, limits, inspector, { readData: true });
  if (current.length !== snapshot.length) throw fail("source changed during archiving");
  for (let index = 0; index < snapshot.length; index += 1) {
    const expected = snapshot[index];
    const actual = current[index];
    if (expected.archivePath !== actual.archivePath || expected.kind !== actual.kind || !metadataEqual(expected.stat, actual.stat)) {
      throw fail("source changed during archiving");
    }
    if (expected.kind === "file" && expected.digest !== actual.digest) throw fail("file content changed during archiving");
  }
}

function writeOctal(header, offset, length, value, checksum = false) {
  const number = typeof value === "bigint" ? value : BigInt(value);
  if (number < 0n) throw fail("negative tar field");
  const digits = number.toString(8);
  const capacity = checksum ? length - 2 : length - 1;
  if (digits.length > capacity) throw fail("tar field overflow");
  const field = `${digits.padStart(capacity, "0")}\0${checksum ? " " : ""}`;
  header.write(field, offset, length, "ascii");
}

function writeText(header, offset, length, value) {
  const data = Buffer.from(value, "utf8");
  if (data.length > length) throw fail("tar text field overflow");
  data.copy(header, offset);
}

function splitUstarPath(archivePath) {
  const pathBytes = Buffer.byteLength(archivePath, "utf8");
  if (pathBytes <= 100) return { name: archivePath, prefix: "" };
  const slashIndexes = [...archivePath.matchAll(/\//gu)].map((match) => match.index).filter((index) => index > 0 && index < archivePath.length - 1);
  for (let index = slashIndexes.length - 1; index >= 0; index -= 1) {
    const split = slashIndexes[index];
    const prefix = archivePath.slice(0, split);
    const name = archivePath.slice(split + 1);
    if (Buffer.byteLength(prefix, "utf8") <= 155 && Buffer.byteLength(name, "utf8") <= 100) return { name, prefix };
  }
  throw fail("archive path cannot be represented by ustar");
}

function tarHeader(entry) {
  const header = Buffer.alloc(TAR_BLOCK, 0);
  const { name, prefix } = splitUstarPath(entry.archivePath);
  writeText(header, 0, 100, name);
  writeOctal(header, 100, 8, entry.stat.mode & SAFE_MODE_MASK);
  writeOctal(header, 108, 8, 0);
  writeOctal(header, 116, 8, 0);
  writeOctal(header, 124, 12, entry.kind === "file" ? entry.data.length : 0);
  writeOctal(header, 136, 12, 0);
  header.fill(0x20, 148, 156);
  header[156] = entry.kind === "directory" ? 0x35 : 0x30;
  header.write("ustar\0", 257, 6, "ascii");
  header.write("00", 263, 2, "ascii");
  writeText(header, 345, 155, prefix);
  let sum = 0;
  for (const byte of header) sum += byte;
  writeOctal(header, 148, 8, sum, true);
  return header;
}

function padLength(length) {
  return (TAR_BLOCK - (length % TAR_BLOCK)) % TAR_BLOCK;
}

function encodeTar(entries, limits) {
  let total = TAR_EOF_BLOCKS * TAR_BLOCK;
  for (const entry of entries) {
    const size = entry.kind === "file" ? entry.data.length : 0;
    total += TAR_BLOCK + size + padLength(size);
    if (total > limits.maxArchiveBytes) throw fail("archive exceeds the size limit");
  }
  const output = Buffer.alloc(total, 0);
  let offset = 0;
  for (const entry of entries) {
    output.set(tarHeader(entry), offset);
    offset += TAR_BLOCK;
    if (entry.kind === "file") {
      output.set(entry.data, offset);
      offset += entry.data.length + padLength(entry.data.length);
    }
  }
  return output;
}

function writeAll(fd, data) {
  let offset = 0;
  while (offset < data.length) offset += fs.writeSync(fd, data, offset, data.length - offset, offset);
}

function atomicNoReplaceWrite(output, data) {
  const parent = path.dirname(output);
  const stageDirectory = fs.mkdtempSync(path.join(parent, ".agentpass-controller-archive-"), { encoding: "utf8" });
  let temporary;
  let fd;
  try {
    fs.chmodSync(stageDirectory, 0o700);
    temporary = path.join(stageDirectory, "payload.tar");
    fd = fs.openSync(temporary, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | NOFOLLOW, 0o600);
    writeAll(fd, data);
    fs.fsyncSync(fd);
    fs.closeSync(fd);
    fd = undefined;
    fs.linkSync(temporary, output);
    fs.unlinkSync(temporary);
  } catch (error) {
    if (fd !== undefined) {
      try { fs.closeSync(fd); } catch {}
    }
    throw error;
  } finally {
    try { if (temporary && fs.existsSync(temporary)) fs.unlinkSync(temporary); } catch {}
    try { fs.rmdirSync(stageDirectory); } catch {}
  }
}

function assertOutputPath(output, version) {
  assertAbsolutePath(output, "output");
  const expected = expectedArchiveName(version);
  if (path.basename(output) !== expected) throw fail(`output basename must be ${expected}`);
  const parent = path.dirname(output);
  const parentStat = fs.statSync(parent, { bigint: true });
  const parentMode = typeof parentStat.mode === "bigint" ? Number(parentStat.mode) : parentStat.mode;
  if ((parentMode & 0o170000) !== DIRECTORY) throw fail("output parent must be a directory");
  try {
    fs.lstatSync(output, { bigint: true });
    throw fail("output already exists", "EEXIST");
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }
}

export function archiveController({ source, output, version, limits, inspectXattrs = inspectXattrsWithPlatformTool, beforeFinalVerify } = {}) {
  assertAbsolutePath(source, "source");
  assertSemver(version);
  assertOutputPath(output, version);
  const sourceStat = fs.lstatSync(source, { bigint: true });
  if (path.basename(source) !== ROOT_NAME || statKind(sourceStat) !== "directory") throw fail(`source must be exactly ${ROOT_NAME}`);
  const resolvedSource = fs.realpathSync.native(source);
  const resolvedOutputParent = fs.realpathSync.native(path.dirname(output));
  const relativeOutput = path.relative(resolvedSource, path.join(resolvedOutputParent, path.basename(output)));
  if (relativeOutput === "" || (!relativeOutput.startsWith(`..${path.sep}`) && relativeOutput !== ".." && !path.isAbsolute(relativeOutput))) {
    throw fail("output must not be inside the controller app");
  }
  const effectiveLimits = validateLimits(limits);
  const snapshot = collectEntries(source, effectiveLimits, inspectXattrs, { readData: true });
  if (typeof beforeFinalVerify === "function") beforeFinalVerify(snapshot);
  assertSnapshotUnchanged(source, snapshot, effectiveLimits, inspectXattrs);
  const archive = encodeTar(snapshot, effectiveLimits);
  assertSnapshotUnchanged(source, snapshot, effectiveLimits, inspectXattrs);
  atomicNoReplaceWrite(output, archive);
  return Object.freeze({ output, bytes: archive.length, entries: snapshot.length, sha256: crypto.createHash("sha256").update(archive).digest("hex") });
}

function usage() {
  return "Usage: archive-controller.mjs /absolute/AgentPassQualificationController.app /absolute/AgentPassQualificationController-<semver>-macos-universal.tar <semver>";
}

function main(argv) {
  if (argv.length !== 3) throw fail(usage(), "ERR_USAGE");
  const result = archiveController({ source: argv[0], output: argv[1], version: argv[2] });
  process.stdout.write(`${JSON.stringify(result)}\n`);
}

if (process.argv[1] && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url) {
  try {
    main(process.argv.slice(2));
  } catch (error) {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  }
}

export const __test = Object.freeze({
  DEFAULT_LIMITS,
  encodeTar,
  expectedArchiveName,
  inspectXattrsWithPlatformTool,
  metadata,
  splitUstarPath,
});
