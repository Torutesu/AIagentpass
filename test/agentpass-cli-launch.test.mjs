import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const cli = path.join(root, "bin", "agentpass.mjs");

function run(...arguments_) {
  return spawnSync(process.execPath, [cli, ...arguments_], {
    encoding: "utf8",
    env: { ...process.env, AGENTPASS_SESSION: "environment-secret-that-must-be-ignored" }
  });
}

test("launch accepts the bounded public arguments, then remains fail-closed without a native Host", () => {
  const result = run("launch", "--agent", "claude-code", "--project", "/tmp/project", "--ttl", "600");

  assert.equal(result.status, 1);
  assert.equal(result.stderr, "");
  assert.deepEqual(JSON.parse(result.stdout), {
    ok: false,
    operation: "launch",
    error: {
      code: "AGENT_LIFECYCLE_NOT_AVAILABLE",
      message: "The process-bound Agent lifecycle is not available in this build"
    }
  });
});

test("launch contract failures remain stable fail-closed JSON and never echo forbidden values", () => {
  const secret = "launch-secret-must-not-appear";
  const result = run("launch", "--agent", "claude-code", "--token", secret);

  assert.equal(result.status, 1);
  assert.equal(result.stderr, "");
  assert.deepEqual(JSON.parse(result.stdout), {
    ok: false,
    operation: "launch",
    error: {
      code: "AGENT_LIFECYCLE_NOT_AVAILABLE",
      message: "The process-bound Agent lifecycle is not available in this build"
    }
  });
  assert.equal(`${result.stdout}${result.stderr}`.includes(secret), false);
});

test("launch rejects noncanonical input before the unavailable lifecycle response", () => {
  const result = run("launch", "--agent", "claude-code", "--project", "/tmp/project/../other");

  assert.equal(result.status, 1);
  assert.equal(result.stderr, "");
  const output = JSON.parse(result.stdout);
  assert.equal(output.ok, false);
  assert.equal(output.operation, "launch");
  assert.equal(output.error.code, "AGENT_LIFECYCLE_NOT_AVAILABLE");
  assert.equal(output.error.message.includes("/tmp/project/../other"), false);
});

test("help remains successful and unknown commands remain usage failures", () => {
  const help = run("--help");
  assert.equal(help.status, 0);
  assert.match(help.stdout, /^AgentPass 0\.18\.0/u);
  assert.equal(help.stderr, "");

  const unknown = run("not-a-command");
  assert.equal(unknown.status, 2);
  assert.equal(unknown.stdout, "");
  assert.equal(unknown.stderr, "agentpass: unknown command\n");
});
