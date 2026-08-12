import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { atomicWrite, loadConfig, secureMkdir } from "../lib/config.mjs";

test("configuration writes are durable, restrictive, and replace regular files atomically", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "agentpass-config-security-"));
  const directory = path.join(root, "config");
  secureMkdir(directory);
  const file = path.join(directory, "value.json");
  atomicWrite(file, "one\n");
  atomicWrite(file, "two\n");
  assert.equal(fs.readFileSync(file, "utf8"), "two\n");
  assert.equal(fs.statSync(directory).mode & 0o777, 0o700);
  assert.equal(fs.statSync(file).mode & 0o777, 0o600);
  assert.deepEqual(fs.readdirSync(directory), ["value.json"]);
});

test("configuration helpers refuse symlinked directories and files", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "agentpass-config-symlink-"));
  const realDirectory = path.join(root, "real");
  fs.mkdirSync(realDirectory, { mode: 0o700 });
  const linkedDirectory = path.join(root, "linked");
  fs.symlinkSync(realDirectory, linkedDirectory);
  assert.throws(() => secureMkdir(linkedDirectory), /unsafe configuration directory/);

  const victim = path.join(root, "victim");
  fs.writeFileSync(victim, "unchanged", { mode: 0o600 });
  const linkedFile = path.join(realDirectory, "config.json");
  fs.symlinkSync(victim, linkedFile);
  assert.throws(() => atomicWrite(linkedFile, "replaced"), /unsafe configuration file/);
  assert.equal(fs.readFileSync(victim, "utf8"), "unchanged");
  assert.throws(() => loadConfig(realDirectory), /not a regular file/);
});
