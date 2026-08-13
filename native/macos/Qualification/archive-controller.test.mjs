import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { archiveController } from "./archive-controller.mjs";

const VERSION = "0.18.0";
const ARCHIVE_NAME = `AgentPassQualificationController-${VERSION}-macos-universal.tar`;
const NO_XATTRS = () => [];

function tempRoot() {
  return fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "agentpass-controller-archive-test-")));
}

function makeApp(root, suffix = "") {
  const app = path.join(root, `AgentPassQualificationController.app${suffix}`);
  fs.mkdirSync(path.join(app, "Contents", "MacOS"), { recursive: true, mode: 0o755 });
  fs.mkdirSync(path.join(app, "Contents", "Resources"), { recursive: true, mode: 0o755 });
  fs.writeFileSync(path.join(app, "Contents", "Info.plist"), "plist\n", { mode: 0o644 });
  fs.writeFileSync(path.join(app, "Contents", "MacOS", "agentpass-qualification-controller"), "binary\n", { mode: 0o755 });
  fs.writeFileSync(path.join(app, "Contents", "Resources", "empty"), Buffer.alloc(0), { mode: 0o600 });
  return app;
}

function octalField(buffer, offset, length) {
  return Number.parseInt(buffer.toString("ascii", offset, offset + length).replace(/\0.*$/u, "").trim() || "0", 8);
}

function textField(buffer, offset, length) {
  return buffer.toString("utf8", offset, offset + length).replace(/\0.*$/u, "");
}

function parseTar(archive) {
  const entries = [];
  for (let offset = 0; offset < archive.length; offset += 512) {
    const header = archive.subarray(offset, offset + 512);
    if (header.every((byte) => byte === 0)) break;
    const name = textField(header, 0, 100);
    const prefix = textField(header, 345, 155);
    const fullName = prefix ? `${prefix}/${name}` : name;
    const size = octalField(header, 124, 12);
    const type = String.fromCharCode(header[156]);
    const dataStart = offset + 512;
    const data = archive.subarray(dataStart, dataStart + size);
    entries.push({
      name: fullName,
      mode: octalField(header, 100, 8),
      uid: octalField(header, 108, 8),
      gid: octalField(header, 116, 8),
      mtime: octalField(header, 136, 12),
      type,
      size,
      data: Buffer.from(data),
      header: Buffer.from(header),
    });
    offset = dataStart + size + ((512 - (size % 512)) % 512) - 512;
  }
  return entries;
}

function archivePath(root, name = ARCHIVE_NAME) {
  return path.join(root, name);
}

test("writes a reproducible ustar archive with normalized metadata and preserved safe modes", () => {
  const firstRoot = tempRoot();
  const secondRoot = tempRoot();
  const firstApp = makeApp(firstRoot);
  const secondApp = makeApp(secondRoot);
  fs.utimesSync(path.join(firstApp, "Contents", "Info.plist"), 1, 1);
  fs.utimesSync(path.join(secondApp, "Contents", "Info.plist"), 2, 2);
  const firstOutput = archivePath(firstRoot);
  const secondOutput = archivePath(secondRoot);
  archiveController({ source: firstApp, output: firstOutput, version: VERSION, inspectXattrs: NO_XATTRS });
  archiveController({ source: secondApp, output: secondOutput, version: VERSION, inspectXattrs: NO_XATTRS });
  const first = fs.readFileSync(firstOutput);
  const second = fs.readFileSync(secondOutput);
  assert.deepEqual(first, second);
  assert.equal(first.length % 512, 0);

  const entries = parseTar(first);
  assert.deepEqual(entries.map((entry) => entry.name), [
    "AgentPassQualificationController.app/",
    "AgentPassQualificationController.app/Contents/",
    "AgentPassQualificationController.app/Contents/Info.plist",
    "AgentPassQualificationController.app/Contents/MacOS/",
    "AgentPassQualificationController.app/Contents/MacOS/agentpass-qualification-controller",
    "AgentPassQualificationController.app/Contents/Resources/",
    "AgentPassQualificationController.app/Contents/Resources/empty",
  ]);
  assert.deepEqual(entries.filter((entry) => entry.name.endsWith("/")) .map((entry) => entry.type), ["5", "5", "5", "5"]);
  assert.equal(entries.find((entry) => entry.name.endsWith("Info.plist")).mode, 0o644);
  assert.equal(entries.find((entry) => entry.name.endsWith("agentpass-qualification-controller")).mode, 0o755);
  for (const entry of entries) {
    assert.equal(entry.uid, 0);
    assert.equal(entry.gid, 0);
    assert.equal(entry.mtime, 0);
    assert.ok(entry.type === "0" || entry.type === "5");
    assert.equal(entry.header.toString("ascii", 257, 263), "ustar\0");
  }
});

test("rejects symlinks, hard links, special modes, and injected extended attributes", () => {
  const root = tempRoot();
  const symlinkApp = makeApp(root);
  fs.symlinkSync("Info.plist", path.join(symlinkApp, "Contents", "link"));
  assert.throws(() => archiveController({ source: symlinkApp, output: archivePath(root), version: VERSION, inspectXattrs: NO_XATTRS }), /symbolic links/u);

  const hardlinkRoot = tempRoot();
  const hardlinkApp = makeApp(hardlinkRoot);
  fs.linkSync(path.join(hardlinkApp, "Contents", "Info.plist"), path.join(hardlinkApp, "Contents", "Info-copy.plist"));
  assert.throws(() => archiveController({ source: hardlinkApp, output: archivePath(hardlinkRoot), version: VERSION, inspectXattrs: NO_XATTRS }), /hard-linked/u);

  const modeRoot = tempRoot();
  const modeApp = makeApp(modeRoot);
  fs.chmodSync(path.join(modeApp, "Contents", "Info.plist"), 0o4644);
  assert.throws(() => archiveController({ source: modeApp, output: archivePath(modeRoot), version: VERSION, inspectXattrs: NO_XATTRS }), /setuid/u);

  const xattrRoot = tempRoot();
  const xattrApp = makeApp(xattrRoot);
  assert.throws(() => archiveController({
    source: xattrApp,
    output: archivePath(xattrRoot),
    version: VERSION,
    inspectXattrs: (target) => target.endsWith("Info.plist") ? ["com.example.test"] : [],
  }), /extended attributes/u);
});

test("rejects source mutation before finalization and never publishes partial output", () => {
  const root = tempRoot();
  const app = makeApp(root);
  const output = archivePath(root);
  let mutated = false;
  assert.throws(() => archiveController({
    source: app,
    output,
    version: VERSION,
    inspectXattrs: NO_XATTRS,
    beforeFinalVerify: () => {
      if (!mutated) {
        mutated = true;
        fs.appendFileSync(path.join(app, "Contents", "Info.plist"), "tampered\n");
      }
    },
  }), /changed during archiving|content changed/u);
  assert.equal(fs.existsSync(output), false);
});

test("uses an atomic no-overwrite publication", () => {
  const root = tempRoot();
  const app = makeApp(root);
  const output = archivePath(root);
  const first = archiveController({ source: app, output, version: VERSION, inspectXattrs: NO_XATTRS });
  const bytes = fs.readFileSync(output);
  assert.equal(first.sha256, crypto.createHash("sha256").update(bytes).digest("hex"));
  assert.throws(() => archiveController({ source: app, output, version: VERSION, inspectXattrs: NO_XATTRS }), (error) => error.code === "EEXIST");
  assert.deepEqual(fs.readFileSync(output), bytes);
});

test("requires the exact source and strict archive basename", () => {
  const root = tempRoot();
  const app = makeApp(root);
  assert.throws(() => archiveController({ source: app, output: path.join(root, "wrong.tar"), version: VERSION }), /output basename/u);
  assert.throws(() => archiveController({ source: path.join(root, "AgentPassQualificationController.app.backup"), output: archivePath(root), version: VERSION }), /ENOENT|source must/u);
  assert.throws(() => archiveController({ source: app, output: archivePath(root, "AgentPassQualificationController-v0.18.0-macos-universal.tar"), version: "v0.18.0" }), /strict semantic|output basename/u);
});
