import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const cli = path.join(root, "bin", "agentpass.mjs");

test("setup status is read-only before journal initialization", () => {
  const home = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "agentpass-setup-cli-")));
  const result = spawnSync(process.execPath, [cli, "setup", "status"], { encoding: "utf8", env: { ...process.env, HOME: home } });
  assert.equal(result.status, 0, result.stderr);
  const status = JSON.parse(result.stdout);
  assert.equal(status.initialized, false);
  assert.equal(status.state, "not_started");
  assert.equal(status.next_actions[0].command, "agentpass setup --client claude-code --project DIR --team-id TEAMID --execute");
  assert.equal(status.next_actions[0].command.includes("|"), false);
  assert.equal(fs.existsSync(path.join(home, ".agentpass")), false);
});
