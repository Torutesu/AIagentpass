import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {
  ATOMIC_RENAME_CODES,
  ATOMIC_RENAME_EXIT_CODES,
  ATOMIC_RENAME_HELPER_PROTOCOL,
  atomicRenameNoReplaceSync
} from "../lib/macos-atomic-rename.mjs";

const owner = process.getuid?.();

function fixture({ destination = false } = {}) {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "agentpass-atomic-rename-")));
  const boundary = path.join(root, "project");
  const helperBoundary = path.join(root, "helper");
  const source = path.join(boundary, "agentpass-remove.replacement");
  const target = path.join(boundary, "settings.json");
  const helper = path.join(helperBoundary, "agentpass-atomic-rename");
  fs.mkdirSync(boundary, { mode: 0o700 });
  fs.mkdirSync(helperBoundary, { mode: 0o700 });
  fs.writeFileSync(source, "replacement\n", { mode: 0o600 });
  if (destination) fs.writeFileSync(target, "concurrent\n", { mode: 0o600 });
  fs.writeFileSync(helper, "packaged-helper-placeholder\n", { mode: 0o755 });
  fs.chmodSync(helper, 0o755);
  return { root, boundary, helperBoundary, source, target, helper };
}

function options(value, extra = {}) {
  return {
    platform: "darwin",
    source: value.source,
    destination: value.target,
    boundary: value.boundary,
    helperPath: value.helper,
    helperBoundary: value.helperBoundary,
    owner,
    helperOwner: owner,
    ...extra
  };
}

function injectedRename(value, calls = []) {
  return (file, args, spawnOptions) => {
    calls.push({ file, args, spawnOptions });
    fs.renameSync(value.source, value.target);
    return { status: ATOMIC_RENAME_EXIT_CODES.SUCCESS, stdout: "", stderr: "" };
  };
}

test("invokes the packaged helper without a shell and performs an atomic no-replace move", () => {
  const value = fixture();
  try {
    const calls = [];
    const sourceStat = fs.lstatSync(value.source);
    const result = atomicRenameNoReplaceSync({ ...options(value), spawnFileSync: injectedRename(value, calls) });
    assert.equal(result.code, ATOMIC_RENAME_CODES.COMPLETE);
    assert.equal(fs.existsSync(value.source), false);
    assert.equal(fs.readFileSync(value.target, "utf8"), "replacement\n");
    assert.equal(calls.length, 1);
    assert.equal(calls[0].file, value.helper);
    assert.equal(calls[0].spawnOptions.shell, false);
    assert.deepEqual(calls[0].args, [
      "--protocol", ATOMIC_RENAME_HELPER_PROTOCOL,
      "--operation", "rename-no-replace",
      "--source-parent", value.boundary,
      "--source-name", "agentpass-remove.replacement",
      "--destination-parent", value.boundary,
      "--destination-name", "settings.json",
      "--boundary", value.boundary,
      "--owner", String(owner),
      "--source-dev", String(sourceStat.dev),
      "--source-ino", String(sourceStat.ino),
      "--source-size", String(sourceStat.size),
      "--source-mtime-ns", typeof sourceStat.mtimeNs === "bigint" ? sourceStat.mtimeNs.toString() : String(Math.round(sourceStat.mtimeMs * 1_000_000))
    ]);
  } finally { fs.rmSync(value.root, { recursive: true, force: true }); }
});

test("maps helper EEXIST to a stable destination-exists failure and never overwrites", () => {
  const value = fixture({ destination: true });
  try {
    assert.throws(() => atomicRenameNoReplaceSync({
      ...options(value),
      spawnFileSync: () => ({ status: ATOMIC_RENAME_EXIT_CODES.DESTINATION_EXISTS, stdout: "", stderr: "destination exists" })
    }), (error) => error.code === ATOMIC_RENAME_CODES.DESTINATION_EXISTS);
    assert.equal(fs.readFileSync(value.target, "utf8"), "concurrent\n");
    assert.equal(fs.readFileSync(value.source, "utf8"), "replacement\n");
  } finally { fs.rmSync(value.root, { recursive: true, force: true }); }
});

test("preserves a destination created after wrapper validation", () => {
  const value = fixture();
  try {
    assert.throws(() => atomicRenameNoReplaceSync({
      ...options(value),
      spawnFileSync: () => {
        fs.writeFileSync(value.target, "concurrent-after-validation\n", { flag: "wx", mode: 0o600 });
        return { status: ATOMIC_RENAME_EXIT_CODES.DESTINATION_EXISTS, stdout: "", stderr: "EEXIST" };
      }
    }), (error) => error.code === ATOMIC_RENAME_CODES.DESTINATION_EXISTS);
    assert.equal(fs.readFileSync(value.target, "utf8"), "concurrent-after-validation\n");
    assert.equal(fs.readFileSync(value.source, "utf8"), "replacement\n");
  } finally { fs.rmSync(value.root, { recursive: true, force: true }); }
});

test("fails closed before helper invocation off macOS", () => {
  assert.throws(() => atomicRenameNoReplaceSync({ platform: "linux" }), (error) => error.code === ATOMIC_RENAME_CODES.UNSUPPORTED_PLATFORM);
});

test("fails closed when the packaged helper is absent or unsafe", () => {
  const missing = fixture();
  try {
    fs.unlinkSync(missing.helper);
    assert.throws(() => atomicRenameNoReplaceSync({ ...options(missing), spawnFileSync: () => { throw new Error("must not spawn"); } }), (error) => error.code === ATOMIC_RENAME_CODES.HELPER_UNAVAILABLE);
  } finally { fs.rmSync(missing.root, { recursive: true, force: true }); }

  const symlinked = fixture();
  try {
    const real = path.join(symlinked.helperBoundary, "real-helper");
    fs.renameSync(symlinked.helper, real);
    fs.symlinkSync(real, symlinked.helper);
    assert.throws(() => atomicRenameNoReplaceSync({ ...options(symlinked), spawnFileSync: () => { throw new Error("must not spawn"); } }), (error) => error.code === ATOMIC_RENAME_CODES.HELPER_UNSAFE);
  } finally { fs.rmSync(symlinked.root, { recursive: true, force: true }); }
});

test("rejects path escapes, symlink sources, insecure parents, and owner mismatches", () => {
  const value = fixture();
  try {
    assert.throws(() => atomicRenameNoReplaceSync({ ...options(value), boundary: path.join(value.root, "other") }), (error) => error.code === ATOMIC_RENAME_CODES.INVALID_BOUNDARY);

    fs.unlinkSync(value.source);
    fs.symlinkSync(value.target, value.source);
    assert.throws(() => atomicRenameNoReplaceSync({ ...options(value), spawnFileSync: () => { throw new Error("must not spawn"); } }), (error) => error.code === ATOMIC_RENAME_CODES.SOURCE_UNSAFE);
    fs.unlinkSync(value.source);
    fs.writeFileSync(value.source, "replacement\n", { mode: 0o600 });

    fs.chmodSync(value.boundary, 0o777);
    assert.throws(() => atomicRenameNoReplaceSync({ ...options(value), spawnFileSync: () => { throw new Error("must not spawn"); } }), (error) => error.code === ATOMIC_RENAME_CODES.INVALID_BOUNDARY);
    fs.chmodSync(value.boundary, 0o700);

    assert.throws(() => atomicRenameNoReplaceSync({ ...options(value), helperOwner: owner + 1, spawnFileSync: () => { throw new Error("must not spawn"); } }), (error) => error.code === ATOMIC_RENAME_CODES.HELPER_UNSAFE);
    assert.throws(() => atomicRenameNoReplaceSync({ ...options(value), source: `${value.boundary}/../outside` }), (error) => error.code === ATOMIC_RENAME_CODES.INVALID_PATH);
  } finally { fs.rmSync(value.root, { recursive: true, force: true }); }
});

test("fails closed on malformed helper results and helper errors", () => {
  const value = fixture();
  try {
    assert.throws(() => atomicRenameNoReplaceSync({ ...options(value), spawnFileSync: () => ({ status: null }) }), (error) => error.code === ATOMIC_RENAME_CODES.HELPER_PROTOCOL);
    assert.throws(() => atomicRenameNoReplaceSync({ ...options(value), spawnFileSync: () => ({ status: 1, signal: "SIGTERM", stderr: "failed" }) }), (error) => error.code === ATOMIC_RENAME_CODES.HELPER_FAILED);
    assert.equal(fs.existsSync(value.source), true);
    assert.equal(fs.existsSync(value.target), false);
  } finally { fs.rmSync(value.root, { recursive: true, force: true }); }
});
