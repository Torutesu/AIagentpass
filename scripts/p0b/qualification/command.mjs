import { createHash } from "node:crypto";
import { spawn } from "node:child_process";

const SKIP_MARKER = Buffer.from("# SKIP", "utf8");
const MARKER_TAIL_BYTES = SKIP_MARKER.byteLength - 1;
const TERMINATION_GRACE_MS = 250;
const DEFAULT_TIMEOUT_MS = 120_000;
const SAFE_REASON = Object.freeze({
  spawn: "child_spawn_failed",
  timeout: "child_timeout",
  signal: "child_signal",
  nonzero: "child_exit_nonzero",
  skipped: "test_skipped",
  unknown: "child_exit_unknown",
  callback: "child_callback_failed"
});

function assertCommand(command, args) {
  if (typeof command !== "string" || command.length === 0 || command.includes("\u0000")) {
    throw new TypeError("command must be a non-empty string");
  }
  if (!Array.isArray(args) || args.some((argument) => typeof argument !== "string" || argument.includes("\u0000"))) {
    throw new TypeError("args must be an array of strings");
  }
}

function normalizeEnvironment(env) {
  if (env === undefined) return Object.create(null);
  if (env === null || typeof env !== "object" || Array.isArray(env)) throw new TypeError("env must be an object");
  const copy = Object.create(null);
  for (const [key, value] of Object.entries(env)) {
    if (typeof key !== "string" || key.length === 0 || key.includes("\u0000")) throw new TypeError("env key is invalid");
    if (value !== undefined && typeof value !== "string" && typeof value !== "number" && typeof value !== "boolean") {
      throw new TypeError("env value is invalid");
    }
    copy[key] = value;
  }
  return copy;
}

function normalizeOptions(options) {
  if (options === null || typeof options !== "object" || Array.isArray(options)) throw new TypeError("options are required");
  if (options.cwd !== undefined && (typeof options.cwd !== "string" || options.cwd.length === 0 || options.cwd.includes("\u0000"))) {
    throw new TypeError("cwd is invalid");
  }
  if (options.onChild !== undefined && typeof options.onChild !== "function") throw new TypeError("onChild must be a function");
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1) throw new TypeError("timeoutMs must be a positive integer");
  return {
    cwd: options.cwd,
    env: normalizeEnvironment(options.env),
    onChild: options.onChild,
    timeoutMs
  };
}

function asBytes(chunk) {
  if (Buffer.isBuffer(chunk)) return chunk;
  if (chunk instanceof Uint8Array) return Buffer.from(chunk.buffer, chunk.byteOffset, chunk.byteLength);
  return Buffer.from(String(chunk), "utf8");
}

function includesMarker(haystack, needle) {
  if (haystack.byteLength < needle.byteLength) return false;
  for (let offset = 0; offset <= haystack.byteLength - needle.byteLength; offset += 1) {
    let matches = true;
    for (let index = 0; index < needle.byteLength; index += 1) {
      if (haystack[offset + index] !== needle[index]) {
        matches = false;
        break;
      }
    }
    if (matches) return true;
  }
  return false;
}

function makeInternalFlags({ spawnError, timedOut, skipMarker, callbackFailed }) {
  return Object.freeze({
    spawn_error: spawnError,
    timed_out: timedOut,
    skip_marker: skipMarker,
    callback_failed: callbackFailed,
    settled: true
  });
}

function attachInternalFlags(result, flags) {
  // These properties are deliberately non-enumerable: the enumerable shape is
  // accepted by the qualification report schema, while the runner can still
  // make fail-closed decisions without retaining or exposing child output.
  Object.defineProperties(result, {
    internal: { configurable: false, enumerable: false, writable: false, value: flags },
    spawnError: { configurable: false, enumerable: false, writable: false, value: flags.spawn_error },
    timedOut: { configurable: false, enumerable: false, writable: false, value: flags.timed_out },
    skipMarker: { configurable: false, enumerable: false, writable: false, value: flags.skip_marker }
  });
  return Object.freeze(result);
}

function durationMilliseconds(startedAt) {
  const elapsed = process.hrtime.bigint() - startedAt;
  const milliseconds = Number(elapsed / 1_000_000n);
  return Number.isSafeInteger(milliseconds) && milliseconds >= 0 ? milliseconds : Number.MAX_SAFE_INTEGER;
}

/**
 * Run one qualification command without retaining its output.
 *
 * The returned enumerable fields are compatible with a command result in the
 * P0-B qualification report. `internal` and its aliases are non-enumerable,
 * safe boolean flags for the orchestration layer. No command, environment,
 * exception, or output text is included in the returned value.
 */
export function runQualificationCommand(command, args, options) {
  assertCommand(command, args);
  const { cwd, env, onChild, timeoutMs } = normalizeOptions(options);
  const startedAt = process.hrtime.bigint();
  const stdoutHash = createHash("sha256");
  const stderrHash = createHash("sha256");
  let stdoutBytes = 0;
  let stderrBytes = 0;
  let stdoutMarkerTail = Buffer.alloc(0);
  let stderrMarkerTail = Buffer.alloc(0);
  let skipMarker = false;
  let spawnError = false;
  let timedOut = false;
  let callbackFailed = false;
  let settled = false;
  let timeoutHandle;
  let killHandle;
  let child;

  const observeMarker = (chunk, stream) => {
    if (skipMarker) return;
    const bytes = asBytes(chunk);
    const markerTail = stream === "stdout" ? stdoutMarkerTail : stderrMarkerTail;
    const candidate = markerTail.byteLength === 0 ? bytes : Buffer.concat([markerTail, bytes]);
    if (includesMarker(candidate, SKIP_MARKER)) {
      skipMarker = true;
      stdoutMarkerTail = Buffer.alloc(0);
      stderrMarkerTail = Buffer.alloc(0);
      return;
    }
    // Copy only a suffix; retaining a subarray would retain the whole stream
    // chunk and could accidentally keep arbitrary child output alive.
    const nextTail = candidate.byteLength <= MARKER_TAIL_BYTES
      ? Buffer.from(candidate)
      : Buffer.from(candidate.subarray(candidate.byteLength - MARKER_TAIL_BYTES));
    if (stream === "stdout") stdoutMarkerTail = nextTail;
    else stderrMarkerTail = nextTail;
  };

  return new Promise((resolve) => {
    const settle = (code, signal, reasonKind = null) => {
      if (settled) return;
      settled = true;
      if (timeoutHandle !== undefined) clearTimeout(timeoutHandle);
      if (killHandle !== undefined) clearTimeout(killHandle);

      const exitCode = Number.isSafeInteger(code) && code >= 0 && code <= 255 ? code : null;
      const normalizedSignal = typeof signal === "string" && /^[A-Z][A-Z0-9]{0,15}$/u.test(signal) ? signal : null;
      let reason = reasonKind;
      if (reason === null) {
        if (spawnError) reason = SAFE_REASON.spawn;
        else if (timedOut) reason = SAFE_REASON.timeout;
        else if (callbackFailed) reason = SAFE_REASON.callback;
        else if (normalizedSignal !== null) reason = SAFE_REASON.signal;
        else if (exitCode === null) reason = SAFE_REASON.unknown;
        else if (exitCode !== 0) reason = SAFE_REASON.nonzero;
        else if (skipMarker) reason = SAFE_REASON.skipped;
      }
      const passed = !spawnError && !timedOut && !callbackFailed && normalizedSignal === null && exitCode === 0 && !skipMarker;
      const result = {
        status: passed ? "passed" : "failed",
        exit_code: exitCode,
        signal: normalizedSignal,
        duration_ms: durationMilliseconds(startedAt),
        stdout_sha256: stdoutHash.digest("hex"),
        stdout_bytes: stdoutBytes,
        stderr_sha256: stderrHash.digest("hex"),
        stderr_bytes: stderrBytes,
        reason: passed ? null : reason ?? SAFE_REASON.unknown
      };
      resolve(attachInternalFlags(result, makeInternalFlags({ spawnError, timedOut, skipMarker, callbackFailed })));
    };

    const requestKill = (signal) => {
      try {
        child?.kill(signal);
      } catch {
        // The close/error event remains authoritative. Never expose a kill
        // exception or a command-specific diagnostic to the report.
      }
    };

    try {
      child = spawn(command, args, {
        cwd,
        env,
        shell: false,
        stdio: ["ignore", "pipe", "pipe"]
      });
    } catch {
      spawnError = true;
      settle(null, null);
      return;
    }

    child.stdout?.on("data", (chunk) => {
      const bytes = asBytes(chunk);
      stdoutHash.update(bytes);
      stdoutBytes += bytes.byteLength;
      observeMarker(bytes, "stdout");
    });
    child.stderr?.on("data", (chunk) => {
      const bytes = asBytes(chunk);
      stderrHash.update(bytes);
      stderrBytes += bytes.byteLength;
      observeMarker(bytes, "stderr");
    });
    child.once("error", () => {
      spawnError = true;
      settle(null, null);
    });
    child.once("close", (code, signal) => settle(code, signal));

    timeoutHandle = setTimeout(() => {
      if (settled) return;
      timedOut = true;
      requestKill("SIGTERM");
      killHandle = setTimeout(() => {
        if (!settled) requestKill("SIGKILL");
      }, TERMINATION_GRACE_MS);
      killHandle.unref?.();
    }, timeoutMs);
    timeoutHandle.unref?.();

    if (onChild) {
      try {
        onChild(child);
      } catch {
        callbackFailed = true;
        requestKill("SIGTERM");
        killHandle = setTimeout(() => {
          if (!settled) requestKill("SIGKILL");
        }, TERMINATION_GRACE_MS);
        killHandle.unref?.();
      }
    }
  });
}
