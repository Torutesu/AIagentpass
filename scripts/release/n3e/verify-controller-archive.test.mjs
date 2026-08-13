import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { archiveController } from "../../../native/macos/Qualification/archive-controller.mjs";
import { CONTROLLER_ARCHIVE_LIMITS, parseControllerArchive, verifyAndExtractControllerArchive } from "./verify-controller-archive.mjs";

const SCRIPT = path.resolve(new URL("./verify-controller-archive.mjs", import.meta.url).pathname);
const VERSION = "0.18.0";
const ARCHIVE_NAME = `AgentPassQualificationController-${VERSION}-macos-universal.tar`;
const roots = [];

function fixture() {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "agentpass-controller-verify-")));
  roots.push(root);
  const app = path.join(root, "AgentPassQualificationController.app");
  fs.mkdirSync(path.join(app, "Contents", "MacOS"), { recursive: true, mode: 0o755 });
  fs.mkdirSync(path.join(app, "Contents", "Resources"), { recursive: true, mode: 0o755 });
  fs.writeFileSync(path.join(app, "Contents", "Info.plist"), "plist\n", { mode: 0o644 });
  fs.writeFileSync(path.join(app, "Contents", "MacOS", "agentpass-qualification-controller"), "binary\n", { mode: 0o755 });
  fs.writeFileSync(path.join(app, "Contents", "Resources", "empty"), Buffer.alloc(0), { mode: 0o600 });
  const archive = path.join(root, ARCHIVE_NAME);
  archiveController({ source: app, output: archive, version: VERSION, inspectXattrs: () => [] });
  return { root, app, archive, bytes: fs.readFileSync(archive) };
}

test.afterEach(() => {
  for (const root of roots.splice(0)) fs.rmSync(root, { recursive: true, force: true });
});

function headerOffsets(bytes) {
  const offsets = [];
  let offset = 0;
  while (offset < bytes.length) {
    const header = bytes.subarray(offset, offset + 512);
    if (header.every((byte) => byte === 0)) break;
    offsets.push(offset);
    const sizeText = header.toString("ascii", 124, 136).replace(/\0.*$/u, "");
    const size = Number.parseInt(sizeText, 8);
    offset += 512 + size + ((512 - (size % 512)) % 512);
  }
  return offsets;
}

function rewriteChecksum(bytes, offset) {
  const header = bytes.subarray(offset, offset + 512);
  header.fill(0x20, 148, 156);
  let sum = 0;
  for (const byte of header) sum += byte;
  header.write(`${sum.toString(8).padStart(6, "0")}\0 `, 148, 8, "ascii");
}

function mutateHeader(fixtureValue, entryIndex, mutate) {
  const copy = Buffer.from(fixtureValue.bytes);
  mutate(copy.subarray(headerOffsets(copy)[entryIndex], headerOffsets(copy)[entryIndex] + 512));
  rewriteChecksum(copy, headerOffsets(copy)[entryIndex]);
  return copy;
}

function assertRejectsBytes(bytes, pattern, options = {}) {
  assert.throws(() => parseControllerArchive(bytes, options), pattern);
}

test("verifies and extracts a native-generated canonical archive", () => {
  const value = fixture();
  const destination = path.join(value.root, "extracted");
  const result = verifyAndExtractControllerArchive({ archivePath: value.archive, destination });
  assert.deepEqual(result, {
    destination,
    bytes: value.bytes.length,
    entries: 7,
    sha256: crypto.createHash("sha256").update(value.bytes).digest("hex")
  });
  assert.equal(fs.readFileSync(path.join(destination, "Contents", "Info.plist"), "utf8"), "plist\n");
  assert.equal(fs.readFileSync(path.join(destination, "Contents", "MacOS", "agentpass-qualification-controller"), "utf8"), "binary\n");
  assert.equal(fs.statSync(path.join(destination, "Contents", "Info.plist")).mode & 0o777, 0o644);
  assert.equal(fs.statSync(path.join(destination, "Contents", "MacOS", "agentpass-qualification-controller")).mode & 0o777, 0o755);
  assert.equal(fs.statSync(path.join(destination, "Contents", "Resources", "empty")).mode & 0o777, 0o600);
});

test("rejects noncanonical headers, checksums, types, metadata, paths, and duplicates", () => {
  const value = fixture();
  const badChecksum = Buffer.from(value.bytes);
  badChecksum[headerOffsets(badChecksum)[1] + 148] ^= 1;
  assertRejectsBytes(badChecksum, /checksum/u);
  const mutations = [
    ["magic", (header) => { header.write("ustar ", 257, 6, "ascii"); }, /canonical USTAR/u],
    ["mode", (header) => { header.write("0004000\0", 100, 8, "ascii"); }, /unsafe modes/u],
    ["writable mode", (header) => { header.write("0000777\0", 100, 8, "ascii"); }, /writable by another user/u],
    ["directory size", (header) => { header.write("00000000001\0", 124, 12, "ascii"); }, /directory metadata/u],
    ["uid", (header) => { header.write("0000001\0", 108, 8, "ascii"); }, /uid.*gid.*mtime/u],
    ["mtime", (header) => { header.write("00000000001\0", 136, 12, "ascii"); }, /uid.*gid.*mtime/u],
    ["symlink", (header) => { header[156] = 0x32; }, /type is not permitted/u],
    ["pax", (header) => { header[156] = 0x78; }, /type is not permitted/u],
    ["gnu", (header) => { header[156] = 0x4c; }, /type is not permitted/u],
    ["outside root", (header) => { header.fill(0, 0, 100); header.write("../escape", 0, "ascii"); }, /outside.*root|unsafe/u],
    ["duplicate", (header) => { header.fill(0, 0, 100); header.write("AgentPassQualificationController.app/Contents/Info.plist", 0, "ascii"); }, /duplicate|canonical byte order/u]
  ];
  for (const [label, mutate, pattern] of mutations) {
    assertRejectsBytes(mutateHeader(value, label === "duplicate" ? 4 : 1, mutate), pattern);
  }
});

test("rejects truncation, trailing data, missing parents, limits, and unsafe padding", () => {
  const value = fixture();
  assertRejectsBytes(value.bytes.subarray(0, -512), /truncated|end marker/u);
  assertRejectsBytes(Buffer.concat([value.bytes, Buffer.alloc(512)]), /trailing data/u);
  const missingParent = mutateHeader(value, 4, (header) => {
    header.fill(0, 0, 100);
    header.write("AgentPassQualificationController.app/Missing/file", 0, "ascii");
  });
  assertRejectsBytes(missingParent, /parent|canonical byte order/u);
  assertRejectsBytes(value.bytes, /too many entries/u, { maxEntries: 2 });
  assertRejectsBytes(value.bytes, /size limit/u, { maxArchiveBytes: value.bytes.length - 1 });
  assertRejectsBytes(value.bytes, /path limit/u, { maxPathBytes: 10 });
  const nonzeroPadding = Buffer.from(value.bytes);
  nonzeroPadding[headerOffsets(nonzeroPadding)[2] + 512 + 6] = 0x01;
  assertRejectsBytes(nonzeroPadding, /padding/u);
  assert.equal(CONTROLLER_ARCHIVE_LIMITS.maxEntries, 4096);
});

test("rejects symlink and hard-linked archive inputs, and never publishes failed extraction", () => {
  const value = fixture();
  const symlink = path.join(value.root, "archive-symlink.tar");
  fs.symlinkSync(value.archive, symlink);
  assert.throws(() => verifyAndExtractControllerArchive({ archivePath: symlink, destination: path.join(value.root, "symlink-out") }), /regular file|symlink/u);
  const hardlink = path.join(value.root, "archive-hardlink.tar");
  fs.linkSync(value.archive, hardlink);
  assert.throws(() => verifyAndExtractControllerArchive({ archivePath: hardlink, destination: path.join(value.root, "hardlink-out") }), /hard-linked/u);
  const destination = path.join(value.root, "failed-out");
  assert.throws(() => verifyAndExtractControllerArchive({ archive: mutateHeader(value, 1, (header) => { header[156] = 0x32; }), destination }), /type is not permitted/u);
  assert.equal(fs.existsSync(destination), false);
  const existing = path.join(value.root, "existing");
  fs.mkdirSync(existing, { mode: 0o700 });
  fs.writeFileSync(path.join(existing, "keep"), "keep");
  assert.throws(() => verifyAndExtractControllerArchive({ archivePath: value.archive, destination: existing }), /already exists/u);
  assert.equal(fs.readFileSync(path.join(existing, "keep"), "utf8"), "keep");
});

test("rejects unsafe output ancestry and emits only bounded CLI JSON", () => {
  const value = fixture();
  const unsafeParent = path.join(value.root, "unsafe-parent");
  fs.mkdirSync(unsafeParent, { mode: 0o777 });
  fs.chmodSync(unsafeParent, 0o777);
  assert.throws(() => verifyAndExtractControllerArchive({ archivePath: value.archive, destination: path.join(unsafeParent, "out") }), /ancestry.*unsafe modes/u);
  const result = spawnSync(process.execPath, [SCRIPT, value.archive, path.join(value.root, "cli-out")], { encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout, `{"ok":true,"sha256":"${crypto.createHash("sha256").update(value.bytes).digest("hex")}","entries":7}\n`);
  assert.doesNotMatch(result.stdout, /AgentPass|plist|binary|path/iu);
});
