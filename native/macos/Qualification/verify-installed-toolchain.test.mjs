import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { verifyInstalledToolchain } from "./verify-installed-toolchain.mjs";

const digest = (value) => crypto.createHash("sha256").update(value).digest("hex");
const makeFixture = () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "agentpass-toolchain-"));
  const entrypoint = "run.sh"; const verifier = "verify.mjs";
  fs.writeFileSync(path.join(root, entrypoint), "#!/bin/sh\n", { mode: 0o755 });
  fs.writeFileSync(path.join(root, verifier), "export {};\n", { mode: 0o644 });
  const value = { schema_version: 1, entrypoint, verifier, files: [{ path: entrypoint, sha256: digest(fs.readFileSync(path.join(root, entrypoint))) }, { path: verifier, sha256: digest(fs.readFileSync(path.join(root, verifier))) }] };
  const bytes = Buffer.from(`${JSON.stringify(value)}\n`); fs.writeFileSync(path.join(root, "manifest.json"), bytes, { mode: 0o644 });
  return { root, manifest: digest(bytes) };
};

test("verifies the exact protected toolchain inventory", (t) => {
  const fixture = makeFixture();
  if (process.getuid?.() !== 0) { t.skip("requires root-owned fixture files"); return; }
  assert.deepEqual(verifyInstalledToolchain(fixture.root, fixture.manifest).file_count, 2);
});

test("rejects a manifest digest substitution", (t) => {
  const fixture = makeFixture();
  if (process.getuid?.() !== 0) { t.skip("requires root-owned fixture files"); return; }
  assert.throws(() => verifyInstalledToolchain(fixture.root, "0".repeat(64)), /manifest digest/u);
});
