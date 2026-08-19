#!/usr/bin/env node

import os from "node:os";
import fs from "node:fs/promises";
import { spawn } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

export const DEFAULT_TIMEOUT_MS = 15 * 60 * 1000;
export const MAX_TIMEOUT_MS = 60 * 60 * 1000;
export const TERMINATION_GRACE_MS = 2_000;
export const TEARDOWN_SETTLE_MS = 50;
export const TIMEOUT_EXIT_CODE = 124;
export const ARGUMENT_EXIT_CODE = 64;
export const SPAWN_EXIT_CODE = 127;
export const ENVIRONMENT_EXIT_CODE = 78;

export const DIAGNOSTIC_CODES = Object.freeze({
  arguments: "native_test_invalid_arguments",
  spawn: "native_test_spawn",
  running: "native_test_running",
  timeout: "native_test_timeout",
  signal: "native_test_signal",
  teardown: "native_test_teardown",
  passed: "native_test_passed",
  nonzero: "native_test_exit_nonzero",
  unknown: "native_test_exit_unknown",
  spawnFailed: "native_test_spawn_failed",
  environment: "native_test_environment"
});

const SIGNAL_NUMBERS = Object.freeze(os.constants.signals ?? {});

function assertCommand(command, args) {
  if (typeof command !== "string" || command.length === 0 || command.includes("\u0000")) {
    throw new TypeError("command must be a non-empty string");
  }
  if (!Array.isArray(args) || args.some((argument) => typeof argument !== "string" || argument.includes("\u0000"))) {
    throw new TypeError("args must be an array of strings");
  }
}

function parseTimeoutValue(value, source) {
  if (typeof value !== "string" || !/^\d+$/u.test(value)) {
    throw new TypeError(`${source} must be a positive integer`);
  }
  const timeoutMs = Number(value);
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > MAX_TIMEOUT_MS) {
    throw new TypeError(`${source} must be between 1 and ${MAX_TIMEOUT_MS}`);
  }
  return timeoutMs;
}

export function parseArgs(argv, environment = process.env) {
  if (!Array.isArray(argv)) throw new TypeError("arguments must be an array");
  const configuredTimeout = environment.NATIVE_TEST_TIMEOUT_MS === undefined
    ? DEFAULT_TIMEOUT_MS
    : parseTimeoutValue(environment.NATIVE_TEST_TIMEOUT_MS, "NATIVE_TEST_TIMEOUT_MS");
  let timeoutMs = configuredTimeout;
  let commandStart = -1;

  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === "--help" || argument === "-h") return Object.freeze({ help: true });
    if (argument === "--timeout-ms") {
      const value = argv[++index];
      timeoutMs = parseTimeoutValue(value, "--timeout-ms");
      continue;
    }
    if (argument === "--") {
      commandStart = index + 1;
      break;
    }
    throw new TypeError("command must follow --");
  }

  if (commandStart < 0 || typeof argv[commandStart] !== "string" || argv[commandStart].length === 0) {
    throw new TypeError("a command must follow --");
  }
  return Object.freeze({
    timeoutMs,
    command: argv[commandStart],
    args: Object.freeze(argv.slice(commandStart + 1))
  });
}

export function formatDiagnostic({ phase, code, timeoutMs, signal, exitCode } = {}) {
  if (typeof phase !== "string" || !/^[a-z][a-z0-9_]*$/u.test(phase)) throw new TypeError("phase is invalid");
  if (typeof code !== "string" || !/^[a-z][a-z0-9_]*$/u.test(code)) throw new TypeError("code is invalid");
  const fields = [`native-test phase=${phase}`, `code=${code}`];
  if (Number.isSafeInteger(timeoutMs)) fields.push(`timeout_ms=${timeoutMs}`);
  if (typeof signal === "string") fields.push(`signal=${signal}`);
  if (Number.isSafeInteger(exitCode)) fields.push(`exit_code=${exitCode}`);
  return `${fields.join(" ")}\n`;
}

function emit(onDiagnostic, diagnostic) {
  onDiagnostic?.(Object.freeze(diagnostic));
}

function normalizeOptions(options = {}) {
  if (options === null || typeof options !== "object" || Array.isArray(options)) {
    throw new TypeError("options must be an object");
  }
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > MAX_TIMEOUT_MS) {
    throw new TypeError("timeoutMs is invalid");
  }
  if (options.cwd !== undefined && (typeof options.cwd !== "string" || options.cwd.length === 0 || options.cwd.includes("\u0000"))) {
    throw new TypeError("cwd is invalid");
  }
  if (options.env !== undefined && (options.env === null || typeof options.env !== "object" || Array.isArray(options.env))) {
    throw new TypeError("env is invalid");
  }
  if (options.onDiagnostic !== undefined && typeof options.onDiagnostic !== "function") {
    throw new TypeError("onDiagnostic must be a function");
  }
  return {
    timeoutMs,
    cwd: options.cwd,
    env: options.env,
    onDiagnostic: options.onDiagnostic
  };
}

/**
 * Give a native test process a private temporary directory. macOS file
 * protection and runner sandboxes can reject writes through a shared system
 * TMPDIR; the runner must own the directory lifecycle instead of weakening
 * file permissions in individual tests.
 */
export async function prepareNativeTestEnvironment(environment = process.env) {
  if (environment === null || typeof environment !== "object" || Array.isArray(environment)) {
    throw new TypeError("environment is invalid");
  }
  const requested = environment.NATIVE_TEST_TMPDIR;
  const directory = requested === undefined
    ? await fs.mkdtemp(path.join(os.tmpdir(), "agentpass-native-suite-"))
    : requested;
  if (typeof directory !== "string" || directory.length === 0 || !path.isAbsolute(directory) || directory.includes("\u0000")) {
    throw new TypeError("NATIVE_TEST_TMPDIR must be an absolute path");
  }
  if (requested !== undefined) {
    try { await fs.stat(directory); }
    catch (error) {
      if (error?.code !== "ENOENT") throw error;
      await fs.mkdir(directory, { recursive: true, mode: 0o700 });
    }
  }
  const stat = await fs.stat(directory);
  if (!stat.isDirectory() || (stat.mode & 0o077) !== 0) throw new Error("native test temporary directory is unsafe");
  const ownsDirectory = requested === undefined;
  return Object.freeze({
    environment: Object.freeze({ ...environment, TMPDIR: directory }),
    directory,
    async cleanup() { if (ownsDirectory) await fs.rm(directory, { recursive: true, force: true }); }
  });
}

function isRunning(child) {
  return child && child.exitCode === null && child.signalCode === null;
}

function requestTermination(child, signal) {
  let attempted = false;
  let failed = false;

  if (process.platform !== "win32" && Number.isInteger(child?.pid) && child.pid > 0) {
    try {
      process.kill(-child.pid, signal);
      attempted = true;
    } catch (error) {
      if (error?.code !== "ESRCH") failed = true;
    }
  }

  try {
    const result = child?.kill(signal);
    attempted ||= result === true;
  } catch (error) {
    if (error?.code !== "ESRCH") failed = true;
  }

  return { attempted, failed };
}

function signalExitCode(signal) {
  const number = SIGNAL_NUMBERS[signal];
  return Number.isInteger(number) ? 128 + number : 1;
}

function resultReason({ exitCode, signal, timedOut, spawnFailed, teardownFailed }) {
  if (spawnFailed) return DIAGNOSTIC_CODES.spawnFailed;
  if (timedOut) return DIAGNOSTIC_CODES.timeout;
  if (teardownFailed) return DIAGNOSTIC_CODES.teardown;
  if (signal) return DIAGNOSTIC_CODES.signal;
  if (exitCode === 0) return DIAGNOSTIC_CODES.passed;
  if (Number.isInteger(exitCode)) return DIAGNOSTIC_CODES.nonzero;
  return DIAGNOSTIC_CODES.unknown;
}

/**
 * Run a command with a hard deadline and process-group teardown.
 *
 * Child output is inherited by the caller and is never captured, logged, or
 * included in the result. Diagnostics are stable fields only; callers should
 * not add command output, environment values, or exception messages.
 */
export function runNativeTest(command, args = [], options = {}) {
  assertCommand(command, args);
  const { cwd, env, onDiagnostic, timeoutMs } = normalizeOptions(options);
  const startedAt = process.hrtime.bigint();

  return new Promise((resolve) => {
    let child;
    let settled = false;
    let closeSeen = false;
    let closeCode = null;
    let closeSignal = null;
    let spawnFailed = false;
    let timedOut = false;
    let interruptedSignal = null;
    let teardownFailed = false;
    let timeoutHandle;
    let graceHandle;
    let settleHandle;
    const signalHandlers = new Map();

    const cleanupSignalHandlers = () => {
      for (const [signal, handler] of signalHandlers) process.removeListener(signal, handler);
      signalHandlers.clear();
    };

    const finish = () => {
      if (settled) return;
      settled = true;
      clearTimeout(timeoutHandle);
      clearTimeout(graceHandle);
      clearTimeout(settleHandle);
      cleanupSignalHandlers();
      const exitCode = Number.isInteger(closeCode) && closeCode >= 0 && closeCode <= 255
        ? closeCode
        : (interruptedSignal
          ? signalExitCode(interruptedSignal)
          : (timedOut ? TIMEOUT_EXIT_CODE : (closeSignal ? signalExitCode(closeSignal) : null)));
      const signal = closeSignal ?? interruptedSignal;
      resolve(Object.freeze({
        exitCode,
        signal,
        timedOut,
        interrupted: interruptedSignal !== null,
        teardownFailed,
        durationMs: Number((process.hrtime.bigint() - startedAt) / 1_000_000n),
        reason: resultReason({ exitCode, signal, timedOut, spawnFailed, teardownFailed })
      }));
    };

    const finishAfterTeardown = () => {
      clearTimeout(graceHandle);
      settleHandle = setTimeout(finish, TEARDOWN_SETTLE_MS);
    };

    const forceKill = () => {
      const result = requestTermination(child, "SIGKILL");
      teardownFailed ||= result.failed || (!result.attempted && isRunning(child));
      finishAfterTeardown();
    };

    const beginTeardown = (kind, signal) => {
      if (settled || timedOut || interruptedSignal !== null) return;
      if (kind === "timeout") timedOut = true;
      else interruptedSignal = signal;
      emit(onDiagnostic, {
        phase: kind,
        code: kind === "timeout" ? DIAGNOSTIC_CODES.timeout : DIAGNOSTIC_CODES.signal,
        ...(kind === "timeout" ? { timeoutMs } : { signal })
      });
      emit(onDiagnostic, { phase: "teardown", code: DIAGNOSTIC_CODES.teardown });
      const result = requestTermination(child, "SIGTERM");
      teardownFailed ||= result.failed || (!result.attempted && isRunning(child));
      graceHandle = setTimeout(forceKill, TERMINATION_GRACE_MS);
      if (closeSeen) forceKill();
    };

    const onParentSignal = (signal) => beginTeardown("signal", signal);
    for (const signal of ["SIGINT", "SIGTERM"]) {
      const handler = () => onParentSignal(signal);
      signalHandlers.set(signal, handler);
      process.once(signal, handler);
    }

    emit(onDiagnostic, { phase: "spawn", code: DIAGNOSTIC_CODES.spawn });
    try {
      child = spawn(command, args, {
        cwd,
        env,
        shell: false,
        detached: process.platform !== "win32",
        stdio: "inherit"
      });
    } catch {
      spawnFailed = true;
      emit(onDiagnostic, { phase: "spawn", code: DIAGNOSTIC_CODES.spawnFailed });
      finish();
      return;
    }

    child.once("error", () => {
      if (settled) return;
      spawnFailed = true;
      emit(onDiagnostic, { phase: "spawn", code: DIAGNOSTIC_CODES.spawnFailed });
      if (!closeSeen) finish();
    });
    child.once("close", (code, signal) => {
      if (settled) return;
      closeSeen = true;
      closeCode = code;
      closeSignal = signal;
      if (timedOut || interruptedSignal !== null) {
        forceKill();
      } else {
        emit(onDiagnostic, {
          phase: "exit",
          code: signal ? DIAGNOSTIC_CODES.signal : (code === 0 ? DIAGNOSTIC_CODES.passed : DIAGNOSTIC_CODES.nonzero),
          ...(signal ? { signal } : { exitCode: code })
        });
        finish();
      }
    });

    emit(onDiagnostic, { phase: "running", code: DIAGNOSTIC_CODES.running });
    timeoutHandle = setTimeout(() => beginTeardown("timeout"), timeoutMs);
    timeoutHandle.unref?.();
  });
}

export function usage() {
  return `Usage: node scripts/ci/run-native-tests.mjs [--timeout-ms INTEGER] -- COMMAND [ARGS...]\n\nRun the native test command with a bounded process-group lifetime.\n`;
}

export async function main(argv = process.argv.slice(2), environment = process.env) {
  let options;
  try {
    options = parseArgs(argv, environment);
  } catch {
    process.stderr.write(formatDiagnostic({ phase: "arguments", code: DIAGNOSTIC_CODES.arguments }));
    return ARGUMENT_EXIT_CODE;
  }
  if (options.help) {
    process.stdout.write(usage());
    return 0;
  }

  let isolated;
  try {
    isolated = await prepareNativeTestEnvironment(environment);
  } catch {
    process.stderr.write(formatDiagnostic({ phase: "environment", code: DIAGNOSTIC_CODES.environment }));
    return ENVIRONMENT_EXIT_CODE;
  }
  let result;
  try {
    result = await runNativeTest(options.command, options.args, {
      cwd: process.cwd(),
      env: isolated.environment,
      timeoutMs: options.timeoutMs,
      onDiagnostic(diagnostic) {
        process.stderr.write(formatDiagnostic(diagnostic));
      }
    });
  } finally {
    await isolated.cleanup().catch(() => {});
  }
  if (result.reason === DIAGNOSTIC_CODES.timeout) return TIMEOUT_EXIT_CODE;
  if (result.reason === DIAGNOSTIC_CODES.spawnFailed) return SPAWN_EXIT_CODE;
  if (result.interrupted) return result.exitCode ?? 1;
  if (Number.isInteger(result.exitCode)) return result.exitCode;
  return 1;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().then((code) => { process.exitCode = code; }).catch(() => {
    process.stderr.write(formatDiagnostic({ phase: "runner", code: DIAGNOSTIC_CODES.unknown }));
    process.exitCode = 1;
  });
}
