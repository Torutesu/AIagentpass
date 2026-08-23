import { createHash } from "node:crypto";
import { spawn } from "node:child_process";

const SKIP_MARKER = Buffer.from("# SKIP", "utf8");
const MARKER_TAIL_BYTES = SKIP_MARKER.byteLength - 1;
// The live browser authority matrix has one fixed, non-sensitive marker per
// bounded failure stage. Keep enough room for the complete matrix while still
// rejecting an unbounded caller-controlled registry.
// The protected browser matrix currently has more than 128 fixed stage
// markers. Keep a finite ceiling above that reviewed registry so adding a
// marker cannot make qualification fail before the child process starts.
const MAX_SAFE_FAILURE_MARKERS = 384;
const MAX_SAFE_FAILURE_MARKER_BYTES = 512;
const SAFE_FAILURE_CODE = /^[a-z][a-z0-9_]{0,63}$/u;
const TERMINATION_GRACE_MS = 250;
// A provisional TAP marker is intentionally not terminal: a more specific,
// reviewed marker may be emitted immediately afterwards. It must nevertheless
// have a bounded lifetime. Without this deadline, a test runner that emits the
// coarse `not ok` line and then keeps a browser/socket handle open can survive
// until the supervisor's much larger process timeout.
const PROVISIONAL_FAILURE_GRACE_MS = 1_000;
const DIAGNOSTIC_TAIL_BYTES = 2_048;
const DEFAULT_TIMEOUT_MS = 120_000;
const SUPPORTS_PROCESS_GROUPS = process.platform !== "win32";
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
  if (options.terminateOnSafeFailure !== undefined && typeof options.terminateOnSafeFailure !== "boolean") {
    throw new TypeError("terminateOnSafeFailure must be a boolean");
  }
  const safeFailureMarkers = normalizeSafeFailureMarkers(options.safeFailureMarkers);
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1) throw new TypeError("timeoutMs must be a positive integer");
  return {
    cwd: options.cwd,
    env: normalizeEnvironment(options.env),
    onChild: options.onChild,
    safeFailureMarkers,
    terminateOnSafeFailure: options.terminateOnSafeFailure === true,
    timeoutMs
  };
}

function normalizeSafeFailureMarkers(value) {
  if (value === undefined) return Object.freeze([]);
  if (!Array.isArray(value) || value.length > MAX_SAFE_FAILURE_MARKERS) throw new TypeError("safeFailureMarkers must be a bounded array");
  const codes = new Set();
  return Object.freeze(value.map((entry) => {
    const keys = Object.keys(entry ?? {}).sort().join(",");
    if (entry === null || typeof entry !== "object" || Array.isArray(entry)
      || (keys !== "code,marker" && keys !== "code,marker,terminate")
      || typeof entry.marker !== "string" || entry.marker.length === 0 || entry.marker.includes("\u0000")
      || Buffer.byteLength(entry.marker) > MAX_SAFE_FAILURE_MARKER_BYTES
      || typeof entry.code !== "string" || !SAFE_FAILURE_CODE.test(entry.code)
      || (entry.terminate !== undefined && typeof entry.terminate !== "boolean")
      || codes.has(entry.code)) throw new TypeError("safe failure marker is invalid");
    codes.add(entry.code);
    return Object.freeze({ code: entry.code, marker: Buffer.from(entry.marker, "utf8"), terminate: entry.terminate !== false });
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

function makeInternalFlags({ spawnError, timedOut, skipMarker, callbackFailed, safeFailureCode, diagnostics }) {
  return Object.freeze({
    spawn_error: spawnError,
    timed_out: timedOut,
    skip_marker: skipMarker,
    callback_failed: callbackFailed,
    safe_failure_code: safeFailureCode,
    diagnostics: Object.freeze([...diagnostics]),
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
  const { cwd, env, onChild, safeFailureMarkers, terminateOnSafeFailure, timeoutMs } = normalizeOptions(options);
  const startedAt = process.hrtime.bigint();
  const stdoutHash = createHash("sha256");
  const stderrHash = createHash("sha256");
  let stdoutBytes = 0;
  let stderrBytes = 0;
  let stdoutMarkerTail = Buffer.alloc(0);
  let stderrMarkerTail = Buffer.alloc(0);
  let stdoutDiagnosticTail = Buffer.alloc(0);
  let stderrDiagnosticTail = Buffer.alloc(0);
  let skipMarker = false;
  let safeFailureCode = null;
  let safeFailureTerminal = false;
  let safeFailureStdoutTail = Buffer.alloc(0);
  let safeFailureStderrTail = Buffer.alloc(0);
  const diagnostics = new Set();
  const observeDiagnostics = (chunk, stream) => {
    const bytes = asBytes(chunk);
    const previous = stream === "stdout" ? stdoutDiagnosticTail : stderrDiagnosticTail;
    const candidate = previous.byteLength === 0 ? bytes : Buffer.concat([previous, bytes]);
    for (const match of candidate.toString("utf8").matchAll(/P0B_DIAGNOSTIC_(?:CLOUD_READINESS state=(?:ready|unavailable)|KEYBOARD_OPTIONS code=[a-z][a-z0-9_]{0,63}|KEYBOARD_OUTCOME code=[a-z][a-z0-9_]{0,63}|KEYBOARD_STORAGE code=[a-z][a-z0-9_]{0,127}|SUMMARY_CODE code=(?:[a-z][a-z0-9_]{0,63}|none)|SUMMARY_STATUS status=\d{3}|SUMMARY_HEADER status=\d{3} code=(?:[a-z][a-z0-9_]{0,63}|none) content_type=(?:json|other)|SUMMARY_REFRESH code=[A-Za-z0-9_.:-]{1,96}|SUMMARY_PARSE path=[.$\w\[\]]{1,128} reason=[a-z_]{1,64}|SUMMARY_RESPONSES statuses=\d{3}(?:,\d{3}){0,7}|STAGE_TRACE stages=[A-Z][A-Z0-9_]{1,47}(?:,[A-Z][A-Z0-9_]{1,47}){0,63}|SCENARIO_ERROR kind=(?:assertion|fixture|timeout|other) stage=(?:callback|before_open|after_open))/gu)) {
      if (diagnostics.size < 8) diagnostics.add(match[0]);
    }
    const next = candidate.byteLength <= DIAGNOSTIC_TAIL_BYTES
      ? Buffer.from(candidate)
      : Buffer.from(candidate.subarray(candidate.byteLength - DIAGNOSTIC_TAIL_BYTES));
    if (stream === "stdout") stdoutDiagnosticTail = next;
    else stderrDiagnosticTail = next;
  };
  let spawnError = false;
  let timedOut = false;
  let callbackFailed = false;
  let settled = false;
  let timeoutHandle;
  let killHandle;
  let provisionalFailureHandle;
  let child;
  let requestTermination = () => {};

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
    if (safeFailureTerminal || safeFailureMarkers.length === 0) return;
    const bytes = asBytes(chunk);
    const previous = stream === "stdout" ? safeFailureStdoutTail : safeFailureStderrTail;
    const candidate = previous.byteLength === 0 ? bytes : Buffer.concat([previous, bytes]);
    for (const entry of safeFailureMarkers) {
      if (includesMarker(candidate, entry.marker)) {
        if (entry.code === "scenario_timeout") {
          const diagnostic = candidate.toString("utf8").match(/P0B_SAFE_SCENARIO_TIMEOUT_([A-Z][A-Z0-9_]*)_FAILED/u)?.[1];
          safeFailureCode = diagnostic === undefined ? entry.code : `${entry.code}_${diagnostic.toLowerCase()}`;
        } else if (entry.code === "lifecycle_cloud_health_unknown_key" || entry.code === "lifecycle_cloud_readiness_code") {
          const prefix = entry.code === "lifecycle_cloud_health_unknown_key" ? "P0B_SAFE_LIFECYCLE_CLOUD_HEALTH_UNKNOWN_KEY_" : "P0B_SAFE_LIFECYCLE_CLOUD_READINESS_CODE_";
          const diagnostic = candidate.toString("utf8").match(new RegExp(`${prefix}([A-Z][A-Z0-9_]*)_FAILED`, "u"))?.[1];
          safeFailureCode = diagnostic === undefined ? entry.code : `${entry.code}_${diagnostic.toLowerCase()}`;
        } else safeFailureCode = entry.code;
        if (entry.terminate) {
          safeFailureTerminal = true;
          safeFailureStdoutTail = Buffer.alloc(0);
          safeFailureStderrTail = Buffer.alloc(0);
          if (provisionalFailureHandle !== undefined) clearTimeout(provisionalFailureHandle);
          if (terminateOnSafeFailure) setImmediate(() => requestTermination());
          return;
        }
        if (terminateOnSafeFailure && provisionalFailureHandle === undefined) {
          provisionalFailureHandle = setTimeout(() => {
            provisionalFailureHandle = undefined;
            if (settled || safeFailureTerminal || safeFailureCode === null) return;
            safeFailureTerminal = true;
            requestTermination();
          }, PROVISIONAL_FAILURE_GRACE_MS);
          provisionalFailureHandle.unref?.();
        }
        break;
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
      if (provisionalFailureHandle !== undefined) clearTimeout(provisionalFailureHandle);

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
      resolve(attachInternalFlags(result, makeInternalFlags({ spawnError, timedOut, skipMarker, callbackFailed, safeFailureCode, diagnostics })));
    };

    const requestKill = (signal) => {
      try {
        // A qualification command can start browsers and service processes
        // which inherit its stdout/stderr pipes. Killing only the direct child
        // leaves those descendants alive and prevents the ChildProcess
        // `close` event from ever firing. A detached POSIX child is the leader
        // of a private process group, so a negative pid terminates the complete
        // command tree without risking an unrelated process.
        if (SUPPORTS_PROCESS_GROUPS && Number.isSafeInteger(child?.pid) && child.pid > 0) {
          process.kill(-child.pid, signal);
        } else {
          child?.kill(signal);
        }
      } catch {
        // The close/error event remains authoritative. Never expose a kill
        // exception or a command-specific diagnostic to the report.
      }
    };

    requestTermination = () => {
      if (settled) return;
      requestKill("SIGTERM");
      if (killHandle !== undefined) clearTimeout(killHandle);
      killHandle = setTimeout(() => {
        if (!settled) requestKill("SIGKILL");
      }, TERMINATION_GRACE_MS);
      killHandle.unref?.();
    };

    try {
      child = spawn(command, args, {
        cwd,
        env,
        // On POSIX this creates the private process group used by requestKill.
        // Windows has no equivalent negative-pid group signalling, so retain
        // the normal ChildProcess fallback there.
        detached: SUPPORTS_PROCESS_GROUPS,
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
      observeDiagnostics(bytes, "stdout");
      observeMarker(bytes, "stdout");
      observeSafeFailureMarker(bytes, "stdout");
    });
    child.stderr?.on("data", (chunk) => {
      const bytes = asBytes(chunk);
      stderrHash.update(bytes);
      stderrBytes += bytes.byteLength;
      observeDiagnostics(bytes, "stderr");
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
      requestTermination();
    }, timeoutMs);
    timeoutHandle.unref?.();

    if (onChild) {
      try {
        // The second argument is an intentionally narrow tree-termination
        // capability for supervisors handling their own SIGINT/SIGTERM. It
        // keeps the process-group implementation private to this runner.
        onChild(child, requestTermination);
      } catch {
        callbackFailed = true;
        requestTermination();
      }
    }
  });
}
