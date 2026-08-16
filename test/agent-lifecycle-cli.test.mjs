import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { AGENT_LIFECYCLE_UNAVAILABLE, unavailableAgentLifecycle } from "../lib/agent-lifecycle-cli.mjs";

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const cli = path.join(root, "bin", "agentpass.mjs");

test("bounded lifecycle failures expose no arguments or authority selectors", () => {
  const result = unavailableAgentLifecycle("launch");
  assert.deepEqual(result, {
    ok: false,
    operation: "launch",
    error: {
      code: AGENT_LIFECYCLE_UNAVAILABLE,
      message: "The process-bound Agent lifecycle is not available in this build"
    }
  });
  assert.throws(() => unavailableAgentLifecycle("sign"), /operation is invalid/u);
});

for (const operation of ["launch", "close"]) {
  test(`${operation} fails closed until the signed Agent Host lifecycle is connected`, () => {
    const secret = "authority-material-that-must-not-be-echoed";
    const result = spawnSync(process.execPath, [cli, operation, "--token", secret, "--key", secret, "--algorithm", "unsafe"], {
      encoding: "utf8",
      env: { ...process.env, AGENTPASS_SESSION: secret }
    });
    assert.equal(result.status, 1);
    assert.equal(result.stderr, "");
    const output = JSON.parse(result.stdout);
    assert.equal(output.ok, false);
    assert.equal(output.operation, operation);
    assert.equal(output.error.code, AGENT_LIFECYCLE_UNAVAILABLE);
    assert.equal(`${result.stdout}${result.stderr}`.includes(secret), false);
    assert.equal(`${result.stdout}${result.stderr}`.includes("unsafe"), false);
  });
}

test("unknown commands and subcommands never return success", () => {
  for (const arguments_ of [["unknown-command"], ["broker", "unknown-subcommand"], ["session", "unknown-subcommand"]]) {
    const result = spawnSync(process.execPath, [cli, ...arguments_], { encoding: "utf8" });
    assert.equal(result.status, 2, arguments_.join(" "));
    assert.match(result.stderr, /^agentpass: unknown command\n$/u);
  }
});

test("help remains an explicit successful operation", () => {
  for (const argument of ["--help", "-h"]) {
    const result = spawnSync(process.execPath, [cli, argument], { encoding: "utf8" });
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /^AgentPass 0\.18\.0/u);
    assert.equal(result.stderr, "");
  }
});
