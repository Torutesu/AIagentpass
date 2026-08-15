import { createHash } from "node:crypto";
import { spawn } from "node:child_process";

const SKIP_MARKER = Buffer.from("# SKIP", "utf8");
const MARKER_TAIL_BYTES = SKIP_MARKER.byteLength - 1;
// The live browser authority matrix has one fixed, non-sensitive marker per
// bounded failure stage. Keep enough room for the complete matrix while still
// rejecting an unbounded caller-controlled registry.
const MAX_SAFE_FAILURE_MARKERS = 128;
const MAX_SAFE_FAILURE_MARKER_BYTES = 512;
const SAFE_FAILURE_CODE = /^[a-z][a-z0-9_]{0,63}$/u;
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
  const safeFailureMarkers = normalizeSafeFailureMarkers(options.safeFailureMarkers);
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1) throw new TypeError("timeoutMs must be a positive integer");
  return {
    cwd: options.cwd,
    env: normalizeEnvironment(options.env),
    onChild: options.onChild,
    safeFailureMarkers,
    timeoutMs
  };
}

function normalizeSafeFailureMarkers(value) {
  if (value === undefined) return Object.freeze([]);
  if (!Array.isArray(value) || value.length > MAX_SAFE_FAILURE_MARKERS) throw new TypeError("safeFailureMarkers must be a bounded array");
  const codes = new Set();
  return Object.freeze(value.map((entry) => {
    if (entry === null || typeof entry !== "object" || Array.isArray(entry)
      || Object.keys(entry).sort().join(",") !== "code,marker"
      || typeof entry.marker !== "string" || entry.marker.length === 0 || entry.marker.includes("\u0000")
      || Buffer.byteLength(entry.marker) > MAX_SAFE_FAILURE_MARKER_BYTES
      || typeof entry.code !== "string" || !SAFE_FAILURE_CODE.test(entry.code)
      || codes.has(entry.code)) throw new TypeError("safe failure marker is invalid");
    codes.add(entry.code);
    return Object.freeze({ code: entry.code, marker: Buffer.from(entry.marker, "utf8") });
  }));
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

function makeInternalFlags({ spawnError, timedOut, skipMarker, callbackFailed, safeFailureCode }) {
  return Object.freeze({
    spawn_error: spawnError,
    timed_out: timedOut,
    skip_marker: skipMarker,
    callback_failed: callbackFailed,
    safe_failure_code: safeFailureCode,
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
    skipMarker: { configurable: false, enumerable: false, writable: false, value: flags.skip_marker },
    safeFailureCode: { configurable: false, enumerable: false, writable: false, value: flags.safe_failure_code }
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
  const { cwd, env, onChild, safeFailureMarkers, timeoutMs } = normalizeOptions(options);
  const startedAt = process.hrtime.bigint();
  const stdoutHash = createHash("sha256");
  const stderrHash = createHash("sha256");
  let stdoutBytes = 0;
  let stderrBytes = 0;
  let stdoutMarkerTail = Buffer.alloc(0);
  let stderrMarkerTail = Buffer.alloc(0);
  let skipMarker = false;
  let safeFailureCode = null;
  let safeFailureStdoutTail = Buffer.alloc(0);
  let safeFailureStderrTail = Buffer.alloc(0);
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

  const observeSafeFailureMarker = (chunk, stream) => {
    if (safeFailureCode !== null || safeFailureMarkers.length === 0) return;
    const bytes = asBytes(chunk);
    const previous = stream === "stdout" ? safeFailureStdoutTail : safeFailureStderrTail;
    const candidate = previous.byteLength === 0 ? bytes : Buffer.concat([previous, bytes]);
    for (const entry of safeFailureMarkers) {
      if (includesMarker(candidate, entry.marker)) {
        safeFailureCode = entry.code;
        safeFailureStdoutTail = Buffer.alloc(0);
        safeFailureStderrTail = Buffer.alloc(0);
        return;
      }
    }
    const longest = Math.max(...safeFailureMarkers.map((entry) => entry.marker.byteLength));
    const tailBytes = Math.max(0, longest - 1);
    const nextTail = candidate.byteLength <= tailBytes ? Buffer.from(candidate) : Buffer.from(candidate.subarray(candidate.byteLength - tailBytes));
    if (stream === "stdout") safeFailureStdoutTail = nextTail;
    else safeFailureStderrTail = nextTail;
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
      resolve(attachInternalFlags(result, makeInternalFlags({ spawnError, timedOut, skipMarker, callbackFailed, safeFailureCode })));
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
      observeSafeFailureMarker(bytes, "stdout");
    });
    child.stderr?.on("data", (chunk) => {
      const bytes = asBytes(chunk);
      stderrHash.update(bytes);
      stderrBytes += bytes.byteLength;
      observeMarker(bytes, "stderr");
      observeSafeFailureMarker(bytes, "stderr");
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
