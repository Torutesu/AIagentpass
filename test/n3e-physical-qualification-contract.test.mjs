import assert from "node:assert/strict";
import fs from "node:fs";
import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const ROOT = join(fileURLToPath(new URL("..", import.meta.url)));
const read = (relativePath) => fs.readFileSync(join(ROOT, relativePath), "utf8");

const runCLI = (relativePath, args = [], env = {}) => spawnSync(process.execPath, [join(ROOT, relativePath), ...args], {
  cwd: ROOT,
  env: { ...process.env, ...env },
  encoding: "utf8",
  timeout: 10_000,
});

test("N3-E physical entrypoints fail closed instead of accepting simulation or partial input", () => {
  const qualification = runCLI("scripts/release/run-p0c-qualification.mjs");
  assert.notEqual(qualification.status, 0);
  assert.match(`${qualification.stdout}${qualification.stderr}`, /invalid P0-C qualification arguments|usage/u);

  const aggregate = runCLI("scripts/release/verify-hardware-qualification-set.mjs");
  assert.notEqual(aggregate.status, 0);
  assert.match(`${aggregate.stdout}${aggregate.stderr}`, /Usage: verify-hardware-qualification-set\.mjs/u);

  const validator = runCLI("scripts/release/validate-hardware-qualification.mjs");
  assert.notEqual(validator.status, 0);
  assert.match(`${validator.stdout}${validator.stderr}`, /Usage: validate-hardware-qualification\.mjs/u);

  const source = read("scripts/release/run-p0c-qualification.mjs");
  assert.match(source, /if \(production && platform !== 'darwin'\)/u);
  assert.match(source, /production qualification cannot use injected runners or metadata/u);
  assert.match(source, /if \(result\.exitCode === 0/u);
  assert.match(source, /status: passed/u);
  assert.match(source, /status: 'skipped'/u);
  assert.match(source, /qualified: production && platform === 'darwin'/u);
  assert.match(source, /const qualified = result\.report\.qualified === true/u);
  assert.match(source, /if \(!qualified\) process\.exitCode = 1/u);
});
