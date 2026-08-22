import assert from "node:assert/strict";
import test from "node:test";

import {
  AGENT_LAUNCH_DEFAULT_TTL_SECONDS,
  AGENT_LAUNCH_ERROR_CODES,
  AGENT_LAUNCH_MAX_TTL_SECONDS,
  AGENT_LAUNCH_MIN_TTL_SECONDS,
  AgentLaunchContractError,
  parseAgentLaunchArgs
} from "../lib/agent-launch-contract.mjs";

function errorFor(argv) {
  try {
    parseAgentLaunchArgs(argv);
    assert.fail("expected launch contract rejection");
  } catch (error) {
    assert.ok(error instanceof AgentLaunchContractError);
    return error;
  }
}

test("normalizes the Claude launch contract and freezes the result", () => {
  const result = parseAgentLaunchArgs([
    "launch",
    "--agent",
    "claude-code",
    "--project",
    "/tmp/nonexistent-project",
    "--ttl",
    "600"
  ]);

  assert.deepEqual(result, {
    agent: "claude-code",
    project: "/tmp/nonexistent-project",
    ttl_seconds: 600
  });
  assert.equal(Object.isFrozen(result), true);
});

test("accepts arguments after launch and applies the native default TTL", () => {
  assert.deepEqual(parseAgentLaunchArgs(["--agent", "claude-code"]), {
    agent: "claude-code",
    project: null,
    ttl_seconds: AGENT_LAUNCH_DEFAULT_TTL_SECONDS
  });
});

test("requires the exact Claude agent and rejects positional arguments", () => {
  assert.equal(errorFor([]).code, AGENT_LAUNCH_ERROR_CODES.MISSING_AGENT);
  assert.deepEqual(parseAgentLaunchArgs(["--agent", "cursor"]), {
    agent: "cursor",
    project: null,
    ttl_seconds: AGENT_LAUNCH_DEFAULT_TTL_SECONDS
  });
  assert.equal(errorFor(["--agent", "claude-code", "command"]).code, AGENT_LAUNCH_ERROR_CODES.POSITIONAL_ARGUMENT);
});

test("rejects duplicates, unknown flags, and authority selectors without echoing values", () => {
  const secret = "super-secret-session-token";
  const cases = [
    [["--agent", "claude-code", "--agent", "claude-code"], AGENT_LAUNCH_ERROR_CODES.DUPLICATE_FLAG],
    [["--agent", "claude-code", "--unknown", secret], AGENT_LAUNCH_ERROR_CODES.UNKNOWN_FLAG],
    [["--agent", "claude-code", "--token", secret], AGENT_LAUNCH_ERROR_CODES.FORBIDDEN_SELECTOR],
    [["--agent", "claude-code", `--session=${secret}`], AGENT_LAUNCH_ERROR_CODES.FORBIDDEN_SELECTOR],
    [["--agent", "claude-code", "--key", secret], AGENT_LAUNCH_ERROR_CODES.FORBIDDEN_SELECTOR],
    [["--agent", "claude-code", "--private-key", secret], AGENT_LAUNCH_ERROR_CODES.FORBIDDEN_SELECTOR],
    [["--agent", "claude-code", "--algorithm", secret], AGENT_LAUNCH_ERROR_CODES.FORBIDDEN_SELECTOR],
    [["--agent", "claude-code", "--namespace", secret], AGENT_LAUNCH_ERROR_CODES.FORBIDDEN_SELECTOR],
    [["--agent", "claude-code", "--fd", secret], AGENT_LAUNCH_ERROR_CODES.FORBIDDEN_SELECTOR],
    [["--agent", "claude-code", "--socket", secret], AGENT_LAUNCH_ERROR_CODES.FORBIDDEN_SELECTOR],
    [["--agent", "claude-code", "--host", secret], AGENT_LAUNCH_ERROR_CODES.FORBIDDEN_SELECTOR],
    [["--agent", "claude-code", "--executable", secret], AGENT_LAUNCH_ERROR_CODES.FORBIDDEN_SELECTOR]
  ];

  for (const [argv, code] of cases) {
    const error = errorFor(argv);
    assert.equal(error.code, code);
    assert.equal(error.message.includes(secret), false);
  }
});

test("requires an absolute canonical project path without checking or changing the filesystem", () => {
  for (const project of ["relative", "/tmp/project/../other", "/tmp/project/", "/tmp/project\0secret"]) {
    const error = errorFor(["--agent", "claude-code", "--project", project]);
    assert.equal(error.code, AGENT_LAUNCH_ERROR_CODES.INVALID_PROJECT);
    assert.equal(error.message.includes(project), false);
  }

  assert.equal(parseAgentLaunchArgs(["--agent", "claude-code", "--project", "/"] ).project, "/");
});

test("enforces integer TTL values within native session limits", () => {
  assert.equal(parseAgentLaunchArgs(["--agent", "claude-code", "--ttl", String(AGENT_LAUNCH_MIN_TTL_SECONDS)]).ttl_seconds, AGENT_LAUNCH_MIN_TTL_SECONDS);
  assert.equal(parseAgentLaunchArgs(["--agent", "claude-code", "--ttl", String(AGENT_LAUNCH_MAX_TTL_SECONDS)]).ttl_seconds, AGENT_LAUNCH_MAX_TTL_SECONDS);

  for (const value of ["", "60.0", "1e3", "01", "not-a-number"]) {
    assert.equal(errorFor(["--agent", "claude-code", "--ttl", value]).code, AGENT_LAUNCH_ERROR_CODES.INVALID_TTL);
  }
  for (const value of ["0", "59", "86401"]) {
    assert.equal(errorFor(["--agent", "claude-code", "--ttl", value]).code, AGENT_LAUNCH_ERROR_CODES.TTL_OUT_OF_RANGE);
  }
});
