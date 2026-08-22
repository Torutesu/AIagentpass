import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import path from "node:path";
import test from "node:test";

import {
  CURSOR_RUNTIME_ARGUMENTS,
  CURSOR_RUNTIME_ENVIRONMENT,
  CURSOR_RUNTIME_INDEX,
  CURSOR_RUNTIME_NODE,
  CursorAdapterError,
  createCursorLifecycleDescriptor,
  createCursorLaunchPlan,
  cursorAdapterErrorEnvelope,
  launchCursorLifecycle,
  projectCursorAdapterError,
  projectCursorState,
  validateCursorLaunchPlan
} from "../src/adapter.mjs";
import { CursorSecretScanError, scanCursorAdapterArtifacts } from "../src/secret-scan.mjs";

const CLI = path.resolve("adapters/cursor/bin/agentpass-cursor.mjs");

test("Cursor launch plan is fixed to the trusted runtime and minimal environment", () => {
  const plan = createCursorLaunchPlan({ projectDirectory: "/work/project" });
  assert.equal(plan.executable, CURSOR_RUNTIME_NODE);
  assert.deepEqual(plan.arguments, CURSOR_RUNTIME_ARGUMENTS);
  assert.deepEqual(plan.environment, CURSOR_RUNTIME_ENVIRONMENT);
  assert.equal(Object.hasOwn(plan, "session_id"), false);
  assert.equal(validateCursorLaunchPlan(plan), true);
});

test("launch plan rejects executable, flags, environment, and path substitutions", () => {
  assert.throws(() => createCursorLaunchPlan({ projectDirectory: "relative" }), (error) => error.code === "invalid_arguments");
  assert.throws(() => createCursorLaunchPlan({ projectDirectory: "/work/project", executable: "/tmp/node" }), (error) => error.code === "invalid_arguments");
  const plan = createCursorLaunchPlan({ projectDirectory: "/work/project" });
  for (const mutation of [
    { ...plan, executable: "/tmp/node" },
    { ...plan, arguments: ["--inspect", CURSOR_RUNTIME_INDEX] },
    { ...plan, environment: { ...plan.environment, AGENTPASS_SESSION: "secret" } },
    { ...plan, project_directory: "/work/../escape" },
    { ...plan, extra: true }
  ]) assert.throws(() => validateCursorLaunchPlan(mutation), (error) => error.code === "invalid_arguments");
});

test("Cursor lifecycle descriptor contains only bounded public launch data", () => {
  const descriptor = createCursorLifecycleDescriptor({ projectDirectory: "/work/project", ttlSeconds: 600 });
  assert.deepEqual(descriptor, { version: 1, operation: "launch", agent: "cursor", project: "/work/project", ttl_seconds: 600, handoff_fd: 3 });
  assert.throws(() => createCursorLifecycleDescriptor({ projectDirectory: "/work/project", ttlSeconds: 600, key: "secret" }), { code: "invalid_arguments" });
  assert.throws(() => createCursorLifecycleDescriptor({ projectDirectory: "/work/project", ttlSeconds: 600, authority: "secret" }), { code: "invalid_arguments" });
});

test("Cursor lifecycle fails closed outside macOS without consuming authority", async () => {
  await assert.rejects(
    launchCursorLifecycle({ projectDirectory: "/work/project", ttlSeconds: 600 }, { platform: "linux" }),
    (error) => error.code === "runtime_unavailable"
  );
});

test("state projection is closed and rejects raw detail or unsafe values", () => {
  assert.deepEqual(projectCursorState({ state: "ready", generation: 2 }), { schema_version: 1, state: "ready", generation: 2 });
  assert.throws(() => projectCursorState({ state: "ready", message: "/private/token" }), (error) => error.code === "invalid_arguments");
  assert.throws(() => projectCursorState({ state: "ready", generation: -1 }), (error) => error.code === "invalid_state");
  assert.throws(() => projectCursorState({ state: "running" }), (error) => error.code === "invalid_state");
  assert.throws(() => projectCursorState({ state: "blocked", reason: "raw secret" }), (error) => error.code === "invalid_state");
});

test("error projection never returns internal message, cause, or path", () => {
  const projected = projectCursorAdapterError(new Error("/Users/alice/private/token.pem: leaked"));
  assert.deepEqual(projected, { version: 1, ok: false, error: { code: "adapter_failed", message: "Cursor adapter failed", retryable: false } });
  const unknown = cursorAdapterErrorEnvelope(new CursorAdapterError("unknown_outcome", "raw response body", { outcome: "unknown" }));
  assert.deepEqual(unknown.error, { code: "unknown_outcome", message: "Cursor Agent operation outcome is unknown", retryable: false, outcome: "unknown" });
  assert.doesNotMatch(JSON.stringify(projected), /Users|private|token|leaked/u);
});

test("CLI emits only safe plan JSON and bounded error codes", () => {
  const plan = spawnSync(process.execPath, [CLI, "plan", "/work/project"], { encoding: "utf8" });
  assert.equal(plan.status, 0);
  assert.equal(JSON.parse(plan.stdout).executable, CURSOR_RUNTIME_NODE);
  const invalid = spawnSync(process.execPath, [CLI, "plan", "/work/../private/token"], { encoding: "utf8" });
  assert.equal(invalid.status, 1);
  assert.equal(invalid.stderr.trim(), "agentpass-cursor: invalid_arguments");
  assert.doesNotMatch(invalid.stderr, /private|token/u);
});

test("secret scan accepts the fixed adapter boundary and returns counts only", () => {
  const result = scanCursorAdapterArtifacts({
    argv: ["--use-system-ca", CURSOR_RUNTIME_INDEX],
    environment: { CURSOR_INVOKED_AS: "cursor-agent", PATH: "/usr/bin:/bin" },
    stdout: "status=ready",
    stderr: ""
  });
  assert.deepEqual(result, { version: 1, safe: true, checked: { argv: 2, environment: 2, stdout: 1, stderr: 1 } });
});

test("secret scan rejects secret-bearing keys, values, and command output without echoing matches", () => {
  const cases = [
    { environment: { AGENTPASS_SESSION: "session_1" } },
    { environment: { API_KEY: "not-for-output" } },
    { argv: ["--token=abc123456789"] },
    { stdout: "Authorization: Bearer abcdefghijklmnop" },
    { stderr: "-----BEGIN PRIVATE KEY-----" },
    { stdout: "github_pat_abcdefghijklmnopqrstuvwxyz" }
  ];
  for (const input of cases) {
    assert.throws(() => scanCursorAdapterArtifacts(input), (error) => error instanceof CursorSecretScanError && error.code === "secret_detected");
  }
});

test("scan CLI fails with a stable code and never prints the matching secret", () => {
  const result = spawnSync(process.execPath, [CLI, "scan"], {
    input: JSON.stringify({ stdout: "Authorization: Bearer abcdefghijklmnop" }),
    encoding: "utf8"
  });
  assert.equal(result.status, 1);
  assert.equal(result.stderr.trim(), "agentpass-cursor: adapter_failed");
  assert.doesNotMatch(`${result.stdout}${result.stderr}`, /Bearer|abcdefghijklmnop/u);
});
