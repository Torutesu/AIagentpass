#!/usr/bin/env node

import { spawn } from "node:child_process";

const REPOSITORY_ROOT = new URL("../../", import.meta.url).pathname;
const TEST_FILE = "test/p0b-live-browser.integration.test.mjs";
const SCENARIOS = Object.freeze([
  "renders all six real PostgreSQL device states",
  "accepts keyboard wake from the real pending device",
  "shows accepted, coalesced, and no-pending outcomes from the real wake ledger",
  "admin completes real WebAuthn and wake mutation",
  "auditor receives no wake mutation control",
  "viewer receives no wake mutation control",
  "owner without an available authenticator fails before wake mutation",
  "owner stale authorization is rejected by the real Cloud boundary",
  "owner replayed authorization is rejected by the real Cloud boundary",
  "owner cross_operation authorization is rejected by the real Cloud boundary",
  "owner cross_tenant authorization is rejected by the real Cloud boundary",
  "owner completes distinct real WebAuthn device revoke",
  "admin completes distinct real WebAuthn device revoke"
]);
// A hosted runner may spend nearly a minute pulling/starting the disposable
// PostgreSQL and TLS stack before the 120-second scenario budget begins. Keep
// a hard ten-minute process boundary while leaving the complete 13-scenario
// matrix below the supervisor's 150-minute outer bound.
const SCENARIO_TIMEOUT_MS = 600_000;
const POSIX = process.platform !== "win32";

function terminate(child) {
  if (POSIX && Number.isSafeInteger(child.pid) && child.pid > 0) {
    try { process.kill(-child.pid, "SIGTERM"); } catch {}
    setTimeout(() => { try { process.kill(-child.pid, "SIGKILL"); } catch {} }, 250).unref?.();
    return;
  }
  try { child.kill("SIGTERM"); } catch {}
  setTimeout(() => { try { child.kill("SIGKILL"); } catch {} }, 250).unref?.();
}

function runScenario(name) {
  return new Promise((resolve) => {
    process.stderr.write("P0B_STAGE_SCENARIO_START_START\n");
    const child = spawn(process.execPath, ["--test", "--test-reporter", "tap", TEST_FILE], {
      cwd: REPOSITORY_ROOT,
      env: { ...process.env, P0B_LIVE_BROWSER: "1", P0B_LIVE_BROWSER_SCENARIO: name },
      detached: POSIX,
      shell: false,
      stdio: ["ignore", "pipe", "pipe"]
    });
    let lastStage = "UNKNOWN";
    const stageTrace = [];
    let failureTail = "";
    let failureObserved = false;
    const observeStage = (chunk) => {
      const matches = [...String(chunk).matchAll(/P0B_STAGE_([A-Z][A-Z0-9_]{1,47})_START/gu)];
      for (const match of matches) {
        lastStage = match[1];
        stageTrace.push(lastStage);
        // Keep enough fixed, secret-free stages to identify the scenario
        // boundary when a child is terminated before TAP can serialize its
        // failure. This remains bounded and excludes page/error payloads.
        if (stageTrace.length > 32) stageTrace.shift();
      }
    };
    const observeFailure = (chunk) => {
      if (failureObserved) return;
      failureTail = `${failureTail}${String(chunk)}`.slice(-1024);
      if (/P0B_SAFE_[A-Z][A-Z0-9_]{1,127}_FAILED/gu.test(failureTail)) {
        failureObserved = true;
        emitStageTrace();
        const diagnostics = [...failureTail.matchAll(/P0B_DIAGNOSTIC_[A-Z_]+ [A-Za-z0-9_=,.:\[\]-]{1,256}/gu)].map((match) => match[0]);
        for (const diagnostic of diagnostics.slice(-4)) process.stderr.write(`${diagnostic}\n`);
        if (failureTail.includes("P0B_SAFE_SCENARIO_RUNTIME_TIMEOUT_FAILED")) {
          emitStageTrace();
          process.stderr.write(`P0B_SAFE_SCENARIO_TIMEOUT_${lastStage}_FAILED\n`);
        }
        // Give the child streams one bounded turn to flush the already-written
        // code-only diagnostics before terminating the isolated process.
        const flushTimer = setTimeout(() => terminate(child), 100);
        flushTimer.unref?.();
      }
    };
    child.stdout?.on("data", (chunk) => {
      observeStage(chunk);
      observeFailure(chunk);
      process.stdout.write(chunk);
    });
    child.stderr?.on("data", (chunk) => {
      observeStage(chunk);
      observeFailure(chunk);
      process.stderr.write(chunk);
    });
    let settled = false;
    const finish = (passed) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (!passed && !failureObserved) emitStageTrace();
      resolve(passed);
    };
    function emitStageTrace() {
      process.stderr.write(`P0B_DIAGNOSTIC_STAGE_TRACE stages=${stageTrace.length > 0 ? stageTrace.join(",") : "UNKNOWN"}\n`);
    }
    const timer = setTimeout(() => {
      terminate(child);
      process.stderr.write(`P0B_SAFE_SCENARIO_TIMEOUT_${lastStage}_FAILED\n`);
      finish(false);
    }, SCENARIO_TIMEOUT_MS);
    timer.unref?.();
    child.once("error", () => finish(false));
    child.once("close", (code, signal) => finish(code === 0 && signal === null));
  });
}

for (const scenario of SCENARIOS) {
  // Run serially: every scenario owns a fresh database, Cloud, Console, and
  // browser stack. A hard child boundary guarantees leaked handles cannot
  // stall the complete qualification matrix indefinitely.
  if (!(await runScenario(scenario))) process.exitCode = 1;
  if (process.exitCode === 1) break;
}
