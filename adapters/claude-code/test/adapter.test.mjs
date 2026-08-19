import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import path from "node:path";
import test from "node:test";

import {
  CLAUDE_CODE_ARGUMENTS,
  CLAUDE_CODE_ENVIRONMENT,
  CLAUDE_CODE_EXECUTABLE,
  CLAUDE_CODE_MCP_ARGUMENTS,
  CLAUDE_CODE_MCP_SERVER,
  ClaudeCodeAdapterError,
  createClaudeCodeLaunchPlan,
  projectClaudeCodeAdapterError,
  projectClaudeCodeState,
  validateClaudeCodeLaunchPlan
} from "../src/adapter.mjs";
import { ClaudeCodeSecretScanError, scanClaudeCodeAdapterArtifacts } from "../src/secret-scan.mjs";

const CLI = path.resolve("adapters/claude-code/bin/agentpass-claude-code.mjs");

test("Claude Code plan is fixed to the AgentPass MCP boundary", () => {
  const plan = createClaudeCodeLaunchPlan({ projectDirectory: "/work/project" });
  assert.equal(plan.executable, CLAUDE_CODE_EXECUTABLE);
  assert.deepEqual(plan.arguments, CLAUDE_CODE_ARGUMENTS);
  assert.deepEqual(plan.environment, CLAUDE_CODE_ENVIRONMENT);
  assert.equal(plan.mcp_server.command, CLAUDE_CODE_MCP_SERVER);
  assert.deepEqual(plan.mcp_server.arguments, CLAUDE_CODE_MCP_ARGUMENTS);
  assert.deepEqual(plan.mcp_server.environment, { AGENTPASS_PROJECT_DIR: "/work/project" });
  assert.equal(plan.native_host, "unavailable");
  assert.equal(Object.hasOwn(plan, "session_id"), false);
  assert.equal(Object.hasOwn(plan, "key_id"), false);
  assert.equal(validateClaudeCodeLaunchPlan(plan), true);
});

test("plan rejects executable, flags, env, session, key, and path substitutions", () => {
  assert.throws(() => createClaudeCodeLaunchPlan({ projectDirectory: "relative" }), (error) => error.code === "invalid_arguments");
  for (const extra of ["executable", "arguments", "environment", "sessionId", "keyId", "algorithm"]) {
    assert.throws(() => createClaudeCodeLaunchPlan({ projectDirectory: "/work/project", [extra]: "attacker" }), (error) => error.code === "invalid_arguments");
  }
  const plan = createClaudeCodeLaunchPlan({ projectDirectory: "/work/project" });
  for (const mutation of [
    { ...plan, executable: "/tmp/claude" },
    { ...plan, arguments: ["--dangerously-skip-permissions"] },
    { ...plan, environment: { AGENTPASS_SESSION: "opaque" } },
    { ...plan, native_host: "connected" },
    { ...plan, mcp_server: { ...plan.mcp_server, command: "/tmp/mcp" } },
    { ...plan, mcp_server: { ...plan.mcp_server, environment: { AGENTPASS_KEY: "x" } } },
    { ...plan, mcp_server: { ...plan.mcp_server, environment: { AGENTPASS_PROJECT_DIR: "/other" } } },
    { ...plan, project_directory: "/work/../escape" },
    { ...plan, extra: true }
  ]) assert.throws(() => validateClaudeCodeLaunchPlan(mutation), (error) => error.code === "invalid_arguments");
});

test("native Host is never claimed by this adapter boundary", () => {
  const plan = createClaudeCodeLaunchPlan({ projectDirectory: "/work/project" });
  assert.equal(plan.native_host, "unavailable");
});

test("state projection is closed and bounded", () => {
  assert.deepEqual(projectClaudeCodeState({ state: "host_unavailable", generation: 2 }), { schema_version: 1, state: "host_unavailable", generation: 2 });
  assert.throws(() => projectClaudeCodeState({ state: "ready", message: "/private/token" }), (error) => error.code === "invalid_arguments");
  assert.throws(() => projectClaudeCodeState({ state: "running" }), (error) => error.code === "invalid_state");
  assert.throws(() => projectClaudeCodeState({ state: "blocked", reason: "raw secret" }), (error) => error.code === "invalid_state");
});

test("error projection never returns internal details", () => {
  const projected = projectClaudeCodeAdapterError(new Error("/Users/alice/private/token.pem: leaked"));
  assert.deepEqual(projected, { version: 1, ok: false, error: { code: "adapter_failed", message: "Claude Code adapter failed", retryable: false } });
  const unknown = projectClaudeCodeAdapterError(new ClaudeCodeAdapterError("unknown_outcome", "raw response body", { outcome: "unknown" }));
  assert.deepEqual(unknown.error, { code: "unknown_outcome", message: "Claude Code operation outcome is unknown", retryable: false, outcome: "unknown" });
  assert.doesNotMatch(JSON.stringify(projected), /Users|private|token|leaked/u);
});

test("CLI emits only a safe plan and bounded errors", () => {
  const plan = spawnSync(process.execPath, [CLI, "plan", "/work/project"], { encoding: "utf8" });
  assert.equal(plan.status, 0);
  assert.equal(JSON.parse(plan.stdout).executable, CLAUDE_CODE_EXECUTABLE);
  const invalid = spawnSync(process.execPath, [CLI, "plan", "/work/../private/token"], { encoding: "utf8" });
  assert.equal(invalid.status, 1);
  assert.equal(invalid.stderr.trim(), "agentpass-claude-code: invalid_arguments");
  assert.doesNotMatch(invalid.stderr, /private|token/u);
});

test("secret scan accepts safe artifacts and returns counts only", () => {
  assert.deepEqual(scanClaudeCodeAdapterArtifacts({
    argv: [], environment: { PATH: "/usr/bin:/bin" }, stdout: "status=ready", stderr: ""
  }), { version: 1, safe: true, checked: { argv: 0, environment: 1, stdout: 1, stderr: 1 } });
});

test("secret scan rejects secret-bearing keys, values, argv, and output", () => {
  for (const input of [
    { environment: { AGENTPASS_SESSION: "session_1" } },
    { environment: { API_KEY: "not-for-output" } },
    { argv: ["--token=abc123456789"] },
    { stdout: "Authorization: Bearer abcdefghijklmnop" },
    { stderr: "-----BEGIN PRIVATE KEY-----" },
    { stdout: "github_pat_abcdefghijklmnopqrstuvwxyz" }
  ]) {
    assert.throws(() => scanClaudeCodeAdapterArtifacts(input), (error) => error instanceof ClaudeCodeSecretScanError && error.code === "secret_detected");
  }
  for (const input of [null, [], { unexpected: "value" }, { argv: [42] }]) {
    assert.throws(() => scanClaudeCodeAdapterArtifacts(input), (error) => error instanceof ClaudeCodeSecretScanError && error.code === "secret_detected");
  }
});

test("scan CLI fails closed without echoing the secret", () => {
  const result = spawnSync(process.execPath, [CLI, "scan"], {
    input: JSON.stringify({ stdout: "Authorization: Bearer abcdefghijklmnop" }), encoding: "utf8"
  });
  assert.equal(result.status, 1);
  assert.equal(result.stderr.trim(), "agentpass-claude-code: adapter_failed");
  assert.doesNotMatch(`${result.stdout}${result.stderr}`, /Bearer|abcdefghijklmnop/u);
});
