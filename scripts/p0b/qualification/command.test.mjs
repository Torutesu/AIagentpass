import assert from "node:assert/strict";
import test from "node:test";

import { runQualificationCommand } from "./command.mjs";

const node = process.execPath;
const cwd = process.cwd();
const env = { PATH: process.env.PATH ?? "", NODE_OPTIONS: "" };

function script(source) {
  return ["-e", source];
}

test("hashes raw stdout/stderr exactly and detects a skip marker split across chunks", async () => {
  const result = await runQualificationCommand(node, script([
    "process.stdout.write('out-');",
    "process.stderr.write('err-');",
    "setTimeout(() => { process.stdout.write('put'); process.stderr.write('stream'); process.stdout.write('# SK'); }, 5);",
    "setTimeout(() => process.stdout.write('IP\\n'), 10);"
  ].join("")), { cwd, env, timeoutMs: 2_000 });

  assert.equal(result.status, "failed");
  assert.equal(result.exit_code, 0);
  assert.equal(result.signal, null);
  assert.equal(result.reason, "test_skipped");
  assert.equal(result.stdout_bytes, Buffer.byteLength("out-put# SKIP\n"));
  assert.equal(result.stderr_bytes, Buffer.byteLength("err-stream"));
  assert.equal(result.stdout_sha256, "7f29793b7ba7df5830e6f948116f488d3de80fb6a07108c74c1d52f97c43923e");
  assert.equal(result.stderr_sha256, "5861da828cce04a4749602ee6639482d24b9f7e3a3e83d51e2f8d30f703c2e10");
  assert.equal(result.internal.skip_marker, true);
  assert.equal(result.internal.settled, true);
  assert.equal(Object.keys(result).includes("stdout"), false);
});

test("detects a skip marker fragmented across more than two chunks", async () => {
  const result = await runQualificationCommand(node, script([
    "process.stdout.write('# ');",
    "setTimeout(() => process.stdout.write('S'), 5);",
    "setTimeout(() => process.stdout.write('K'), 10);",
    "setTimeout(() => process.stdout.write('IP'), 15);"
  ].join("")), { cwd, env, timeoutMs: 2_000 });

  assert.equal(result.status, "failed");
  assert.equal(result.reason, "test_skipped");
  assert.equal(result.internal.skip_marker, true);
});

test("never returns or serializes child output", async () => {
  const secret = "qualification-secret-7f3c";
  const result = await runQualificationCommand(node, script([
    `process.stdout.write(${JSON.stringify(secret)});`,
    `process.stderr.write(${JSON.stringify(`${secret}-stderr`)});`
  ].join("")), { cwd, env, timeoutMs: 2_000 });

  assert.equal(result.status, "passed");
  assert.equal(result.stdout_bytes, Buffer.byteLength(secret));
  assert.equal(result.stderr_bytes, Buffer.byteLength(`${secret}-stderr`));
  assert.equal(JSON.stringify(result).includes(secret), false);
  assert.equal(Object.getOwnPropertyNames(result).some((key) => key === "stdout" || key === "stderr" || key === "output"), false);
});

test("represents a spawn error with a null exit code and safe flags", async () => {
  const result = await runQualificationCommand("/this/path/does/not/exist/agentpass-child", [], { cwd, env, timeoutMs: 2_000 });

  assert.equal(result.status, "failed");
  assert.equal(result.exit_code, null);
  assert.equal(result.signal, null);
  assert.equal(result.reason, "child_spawn_failed");
  assert.equal(result.internal.spawn_error, true);
  assert.equal(JSON.stringify(result).includes("ENOENT"), false);
});

test("returns a nonzero exit as a failed report-compatible result", async () => {
  const result = await runQualificationCommand(node, script("process.stderr.write('failure'); process.exit(7);"), { cwd, env, timeoutMs: 2_000 });

  assert.equal(result.status, "failed");
  assert.equal(result.exit_code, 7);
  assert.equal(result.signal, null);
  assert.equal(result.reason, "child_exit_nonzero");
  assert.equal(result.stderr_bytes, Buffer.byteLength("failure"));
  assert.equal(result.internal.spawn_error, false);
});

test("reports only an allow-listed failure code without retaining matching child output", async () => {
  const marker = "not ok 7 - owner stale authorization is rejected";
  const secret = "credential-material-must-not-survive";
  const result = await runQualificationCommand(node, script([
    `process.stdout.write(${JSON.stringify(`${secret} not ok 7 - owner stale`)});`,
    `setTimeout(() => process.stdout.write(${JSON.stringify(" authorization is rejected")}), 5);`,
    "setTimeout(() => process.exit(9), 10);"
  ].join("")), {
    cwd,
    env,
    timeoutMs: 2_000,
    safeFailureMarkers: [{ marker, code: "browser_stale_authorization" }]
  });

  assert.equal(result.status, "failed");
  assert.equal(result.reason, "child_exit_nonzero");
  assert.equal(result.internal.safe_failure_code, "browser_stale_authorization");
  assert.equal(result.safeFailureCode, "browser_stale_authorization");
  assert.equal(JSON.stringify(result).includes(secret), false);
  assert.equal(JSON.stringify(result).includes(marker), false);
  assert.equal(Object.keys(result).includes("safeFailureCode"), false);
});

test("supports the bounded live-browser failure marker registry", async () => {
  const safeFailureMarkers = Array.from({ length: 192 }, (_, index) => ({
    marker: `P0B_SAFE_STAGE_${index}_FAILED`,
    code: `stage_${index}`
  }));
  const result = await runQualificationCommand(node, script(""), { cwd, env, timeoutMs: 2_000, safeFailureMarkers });
  assert.equal(result.status, "passed");

  assert.throws(() => runQualificationCommand(node, script(""), {
    cwd,
    env,
    timeoutMs: 2_000,
    safeFailureMarkers: Array.from({ length: 193 }, (_, index) => ({ marker: `m${index}`, code: `m_${index}` }))
  }), TypeError);
});

test("rejects caller-defined unsafe or duplicate failure diagnostics", () => {
  assert.throws(() => runQualificationCommand(node, script(""), { cwd, env, timeoutMs: 2_000, safeFailureMarkers: [{ marker: "x", code: "contains-secret:value" }] }), TypeError);
  assert.throws(() => runQualificationCommand(node, script(""), { cwd, env, timeoutMs: 2_000, safeFailureMarkers: [{ marker: "x", code: "duplicate" }, { marker: "y", code: "duplicate" }] }), TypeError);
});

test("terminates a timed-out child with SIGTERM and then SIGKILL if needed", async () => {
  const result = await runQualificationCommand(node, script("process.on('SIGTERM', () => {}); setInterval(() => {}, 1000);"), { cwd, env, timeoutMs: 40 });

  assert.equal(result.status, "failed");
  assert.equal(result.exit_code, null);
  assert.equal(result.reason, "child_timeout");
  assert.equal(result.internal.timed_out, true);
  assert.equal(result.duration_ms >= 40, true);
});

test("reports an externally signalled child without settling twice", async () => {
  let callbackCount = 0;
  const result = await runQualificationCommand(node, script("setInterval(() => {}, 1000);"), {
    cwd,
    env,
    timeoutMs: 2_000,
    onChild(child) {
      callbackCount += 1;
      setTimeout(() => child.kill("SIGTERM"), 10).unref();
    }
  });

  assert.equal(callbackCount, 1);
  assert.equal(result.status, "failed");
  assert.equal(result.exit_code, null);
  assert.equal(result.signal, "SIGTERM");
  assert.equal(result.reason, "child_signal");
  assert.equal(result.internal.timed_out, false);
  assert.equal(result.internal.settled, true);
});
