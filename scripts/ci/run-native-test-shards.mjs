#!/usr/bin/env node

import path from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";
import { runNativeTest } from "./run-native-tests.mjs";

// Keep the shard inventory closed. A mutable test target, executable, or filter
// supplied by a job input would turn this qualification command into an
// execution primitive. These are the package's committed test targets.
export const NATIVE_TEST_TARGETS = Object.freeze([
  "AgentPassAppTests",
  "AgentPassNativeCoreTests",
  "AgentPassNativeServiceSupportTests",
  "AgentPassNativeServiceTests",
  "AgentPassOnboardingUITests",
  "AgentPassQualificationGrantClientTests"
]);

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const execFileAsync = promisify(execFile);

function filterFor(target) {
  return `^${target}\\.`;
}

export function nativeShardCommand(target) {
  if (!NATIVE_TEST_TARGETS.includes(target)) throw new TypeError("unknown native test target");
  return Object.freeze({
    command: process.execPath,
    args: Object.freeze([
      path.join(ROOT, "scripts/ci/run-native-tests.mjs"), "--",
      "swift", "test", "--package-path", "native/macos", "--no-parallel",
      "--filter", filterFor(target)
    ])
  });
}

function escapeRegex(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
}

export async function listNativeTestIdentifiers({ target, cwd = ROOT, timeoutMs = 15 * 60 * 1000 } = {}) {
  if (!NATIVE_TEST_TARGETS.includes(target)) throw new TypeError("unknown native test target");
  const { stdout, stderr } = await execFileAsync("swift", ["test", "list", "--package-path", "native/macos"], {
    cwd, timeout: timeoutMs, maxBuffer: 2 * 1024 * 1024, windowsHide: true
  });
  const prefix = `${target}.`;
  return Object.freeze([...new Set(`${stdout}\n${stderr}`.split(/\r?\n/u)
    .map((line) => line.trim())
    .filter((line) => line.startsWith(prefix) && line.length > prefix.length))]);
}

export function nativeTestIdentifierCommand(identifier) {
  if (typeof identifier !== "string" || !NATIVE_TEST_TARGETS.some((target) => identifier.startsWith(`${target}.`))) {
    throw new TypeError("unknown native test identifier");
  }
  return Object.freeze({
    command: process.execPath,
    args: Object.freeze([
      path.join(ROOT, "scripts/ci/run-native-tests.mjs"), "--",
      "swift", "test", "--package-path", "native/macos", "--no-parallel",
      "--filter", `^${escapeRegex(identifier)}$`
    ])
  });
}

export async function runNativeTestShards({
  cwd = ROOT,
  timeoutMs = 15 * 60 * 1000,
  run = runNativeTest,
  listTests = listNativeTestIdentifiers,
  onDiagnostic
} = {}) {
  if (typeof cwd !== "string" || cwd.length === 0) throw new TypeError("cwd is invalid");
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1) throw new TypeError("timeoutMs is invalid");
  if (typeof run !== "function") throw new TypeError("run is invalid");
  if (typeof listTests !== "function") throw new TypeError("listTests is invalid");
  const results = [];
  for (const target of NATIVE_TEST_TARGETS) {
    const command = nativeShardCommand(target);
    let result = await run(command.command, command.args, {
      cwd,
      timeoutMs,
      onDiagnostic
    });
    if (result.exitCode !== 0) {
      let identifiers;
      try {
        identifiers = await listTests({ target, cwd, timeoutMs });
      } catch {
        // Preserve the original bounded failure and continue the remaining
        // closed shards; never turn a diagnostic-list failure into a false
        // pass or silently skip the target.
        identifiers = [];
      }
      const fallback = [];
      for (const identifier of identifiers) {
        const individual = nativeTestIdentifierCommand(identifier);
        fallback.push(await run(individual.command, individual.args, { cwd, timeoutMs, onDiagnostic }));
      }
      if (fallback.length > 0 && fallback.every((value) => value.exitCode === 0)) {
        result = { ...result, exitCode: 0, reason: "native_test_passed_after_fallback", recovered: true, fallbackCount: fallback.length };
        onDiagnostic?.({ phase: "recovered", code: "native_test_shard_recovered", target, fallback_count: fallback.length });
      } else {
        result = { ...result, recovered: false, fallbackCount: fallback.length };
      }
    }
    results.push(Object.freeze({ target, ...result }));
  }
  return Object.freeze(results);
}

function parseArgs(argv) {
  let timeoutMs = 15 * 60 * 1000;
  for (let index = 0; index < argv.length; index += 1) {
    if (argv[index] !== "--timeout-ms" || index + 1 >= argv.length || !/^\d+$/u.test(argv[index + 1])) {
      throw new TypeError("usage: run-native-test-shards.mjs [--timeout-ms INTEGER]");
    }
    timeoutMs = Number(argv[++index]);
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 60 * 60 * 1000) {
      throw new TypeError("timeout must be between 1 and 3600000");
    }
  }
  return { timeoutMs };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  try {
    const { timeoutMs } = parseArgs(process.argv.slice(2));
    const results = await runNativeTestShards({ timeoutMs, onDiagnostic: (value) => process.stderr.write(JSON.stringify(value) + "\n") });
    const failed = results.filter((result) => result.exitCode !== 0);
    process.stderr.write(`native-test-shards completed=${results.length} failed=${failed.length}\n`);
    if (failed.length > 0) {
      for (const result of failed) process.stderr.write(`native-test-shard target=${result.target} reason=${result.reason} exit_code=${result.exitCode ?? "unknown"}\n`);
      process.exitCode = 1;
    }
  } catch (error) {
    process.stderr.write(`native-test-shards error=${error instanceof Error ? error.message : "invalid_invocation"}\n`);
    process.exitCode = 64;
  }
}
