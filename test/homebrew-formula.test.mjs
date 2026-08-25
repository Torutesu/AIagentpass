import assert from "node:assert/strict";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import test from "node:test";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

test("Homebrew formula passes offline static validation", () => {
  const result = spawnSync(process.execPath, [path.join(root, "scripts", "test-homebrew-formula.mjs")], {
    cwd: root,
    encoding: "utf8"
  });
  assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
  const report = JSON.parse(result.stdout);
  assert.equal(report.ok, true);
  assert.equal(report.version, "0.18.0");
  assert.equal(report.sha256.length, 64);
});
