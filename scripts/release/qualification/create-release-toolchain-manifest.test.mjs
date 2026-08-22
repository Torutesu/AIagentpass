import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { createReleaseToolchainManifest, RELEASE_TOOLCHAIN_FILES } from "./create-release-toolchain-manifest.mjs";

test("release toolchain manifest is a closed digest-bound inventory", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "agentpass-release-toolchain-"));
  for (const file of RELEASE_TOOLCHAIN_FILES) {
    const target = path.join(root, file);
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, `${file}\n`, { mode: 0o644 });
  }
  const manifest = createReleaseToolchainManifest(root);
  assert.deepEqual(manifest.files.map((item) => item.path), [...RELEASE_TOOLCHAIN_FILES]);
  for (const item of manifest.files) assert.equal(item.sha256, crypto.createHash("sha256").update(fs.readFileSync(path.join(root, item.path))).digest("hex"));
  assert.equal(manifest.entrypoint, "verify-hardware-qualification-set.mjs");
  assert.equal(manifest.verifier, "verify-installed-toolchain.mjs");
});

test("release toolchain manifest rejects writable or symlinked entries", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "agentpass-release-toolchain-"));
  for (const file of RELEASE_TOOLCHAIN_FILES) {
    const target = path.join(root, file);
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, file, { mode: 0o644 });
  }
  fs.chmodSync(path.join(root, RELEASE_TOOLCHAIN_FILES[0]), 0o664);
  assert.throws(() => createReleaseToolchainManifest(root), /writable/u);
});
