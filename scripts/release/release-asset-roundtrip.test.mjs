import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { buildReleaseAssetInventory, verifyReleaseAssetRoundTrip } from "./release-asset-roundtrip.mjs";

test("round-trip inventory binds the complete asset set and bytes", (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "agentpass-roundtrip-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const source = path.join(root, "source"); const remote = path.join(root, "remote"); fs.mkdirSync(source); fs.mkdirSync(remote);
  for (const [name, value] of [["manifest.json", "manifest"], ["manifest.sig", "signature"], ["installer.pkg", "pkg"]]) { fs.writeFileSync(path.join(source, name), value); fs.copyFileSync(path.join(source, name), path.join(remote, name)); }
  const inventory = buildReleaseAssetInventory(["manifest.json", "manifest.sig", "installer.pkg"].map((name) => ({ name, path: path.join(source, name) })));
  const result = verifyReleaseAssetRoundTrip(inventory, remote);
  assert.equal(result.assets.length, 3);
  fs.writeFileSync(path.join(remote, "installer.pkg"), "tampered");
  assert.throws(() => verifyReleaseAssetRoundTrip(inventory, remote), /digest mismatch/u);
});

test("round-trip rejects missing, extra, symlink, and hardlink assets", (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "agentpass-roundtrip-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const source = path.join(root, "source"); const remote = path.join(root, "remote"); fs.mkdirSync(source); fs.mkdirSync(remote);
  fs.writeFileSync(path.join(source, "one.txt"), "one"); fs.copyFileSync(path.join(source, "one.txt"), path.join(remote, "one.txt"));
  const inventory = buildReleaseAssetInventory([{ name: "one.txt", path: path.join(source, "one.txt") }]);
  fs.writeFileSync(path.join(remote, "extra.txt"), "extra"); assert.throws(() => verifyReleaseAssetRoundTrip(inventory, remote), /set mismatch/u); fs.rmSync(path.join(remote, "extra.txt"));
  fs.mkdirSync(path.join(remote, "unexpected-directory")); assert.throws(() => verifyReleaseAssetRoundTrip(inventory, remote), /non-regular entry/u); fs.rmSync(path.join(remote, "unexpected-directory"), { recursive: true });
  fs.rmSync(path.join(remote, "one.txt")); fs.symlinkSync(path.join(source, "one.txt"), path.join(remote, "one.txt")); assert.throws(() => verifyReleaseAssetRoundTrip(inventory, remote), /release asset|set mismatch/u);
});
