import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  DEFAULT_TIMEOUT_MS,
  DIAGNOSTIC_CODES,
  MAX_TIMEOUT_MS,
  TIMEOUT_EXIT_CODE,
  formatDiagnostic,
  main,
  parseArgs,
  runNativeTest
} from "./run-native-tests.mjs";

const node = process.execPath;
const cwd = process.cwd();
const env = { PATH: process.env.PATH ?? "", NODE_OPTIONS: "" };

function script(source) {
  return ["-e", source];
}

test("parses a bounded command without exposing environment values", () => {
  assert.deepEqual(parseArgs(["--timeout-ms", "1200", "--", "swift", "test"], { NATIVE_TEST_TIMEOUT_MS: "9000" }), {
    timeoutMs: 1200,
    command: "swift",
    args: ["test"]
  });
  assert.equal(parseArgs(["--", "swift", "test"], {}).timeoutMs, DEFAULT_TIMEOUT_MS);
  assert.throws(() => parseArgs(["--timeout-ms", String(MAX_TIMEOUT_MS + 1), "--", "swift"]), /between/);
  assert.throws(() => parseArgs(["--", "swift", "test"], { NATIVE_TEST_TIMEOUT_MS: "secret" }), /positive integer/);
});

test("formats only stable, non-secret diagnostics", () => {
  assert.equal(formatDiagnostic({ phase: "timeout", code: DIAGNOSTIC_CODES.timeout, timeoutMs: 1200 }), "native-test phase=timeout code=native_test_timeout timeout_ms=1200\n");
  assert.equal(formatDiagnostic({ phase: "exit", code: DIAGNOSTIC_CODES.nonzero, exitCode: 7 }), "native-test phase=exit code=native_test_exit_nonzero exit_code=7\n");
  assert.equal(formatDiagnostic({ phase: "signal", code: DIAGNOSTIC_CODES.signal, signal: "SIGTERM" }), "native-test phase=signal code=native_test_signal signal=SIGTERM\n");
});

test("preserves a successful and nonzero child exit status", async () => {
  const passed = await runNativeTest(node, script("process.exit(0)"), { cwd, env, timeoutMs: 2_000 });
  assert.equal(passed.exitCode, 0);
  assert.equal(passed.reason, DIAGNOSTIC_CODES.passed);

  const failed = await runNativeTest(node, script("process.exit(7)"), { cwd, env, timeoutMs: 2_000 });
  assert.equal(failed.exitCode, 7);
  assert.equal(failed.reason, DIAGNOSTIC_CODES.nonzero);

  const signalled = await runNativeTest(node, script("process.kill(process.pid, 'SIGTERM')"), { cwd, env, timeoutMs: 2_000 });
  assert.equal(signalled.exitCode, 143);
  assert.equal(signalled.signal, "SIGTERM");
  assert.equal(signalled.reason, DIAGNOSTIC_CODES.signal);
});

test("kills a timed-out process group, including a descendant", async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), "agentpass-native-runner-test-"));
  const marker = path.join(directory, "descendant-survived");
  const pidFile = path.join(directory, "descendant.pid");
  const childSource = [
    "const { spawn } = require('node:child_process');",
    `const marker = ${JSON.stringify(marker)};`,
    `const pidFile = ${JSON.stringify(pidFile)};`,
    "const descendant = spawn(process.execPath, ['-e', `setTimeout(() => require('node:fs').writeFileSync(${JSON.stringify(marker)}, 'survived'), 4000)`], { stdio: 'ignore' });",
    "require('node:fs').writeFileSync(pidFile, String(descendant.pid));",
    "setInterval(() => {}, 1000);"
  ].join("\n");
  try {
    const result = await runNativeTest(node, script(childSource), { cwd, env, timeoutMs: 80 });
    assert.equal(result.timedOut, true);
    assert.equal(result.exitCode, TIMEOUT_EXIT_CODE);
    assert.equal(result.reason, DIAGNOSTIC_CODES.timeout);
    await new Promise((resolve) => setTimeout(resolve, 100));
    await assert.rejects(fs.stat(marker), { code: "ENOENT" });
    assert.match(await fs.readFile(pidFile, "utf8"), /^\d+$/u);
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test("handles a parent signal with teardown and a signal-derived status", async () => {
  const runner = path.join(cwd, "scripts/ci/run-native-tests.mjs");
  const child = spawn(node, [runner, "--timeout-ms", "5000", "--", node, ...script("setInterval(() => {}, 1000)")], {
    cwd,
    env,
    stdio: ["ignore", "pipe", "pipe"]
  });
  let stderr = "";
  child.stderr.setEncoding("utf8");
  child.stderr.on("data", (chunk) => { stderr += chunk; });
  await new Promise((resolve) => setTimeout(resolve, 100));
  child.kill("SIGTERM");
  const exitCode = await new Promise((resolve) => child.once("close", (code) => resolve(code)));
  assert.equal(exitCode, 143);
  assert.match(stderr, /phase=signal code=native_test_signal/u);
  assert.match(stderr, /phase=teardown code=native_test_teardown/u);
});

test("CLI returns the child status and a bounded timeout status", async () => {
  assert.equal(await main(["--", node, ...script("process.exit(9)")], env), 9);
  assert.equal(await main(["--timeout-ms", "30", "--", node, ...script("setInterval(() => {}, 1000)")], env), TIMEOUT_EXIT_CODE);
});
