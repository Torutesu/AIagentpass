import path from "node:path";

import {
  CURSOR_AGENT_RUNTIME_DESTINATION_PARENT,
  CURSOR_AGENT_RUNTIME_DIRECTORY_NAME,
  CURSOR_AGENT_RUNTIME_INDEX_NAME,
  CURSOR_AGENT_RUNTIME_MANIFEST_NAME,
  CURSOR_AGENT_RUNTIME_NODE_NAME,
  CURSOR_AGENT_RUNTIME_TRUST_CONFIG_PATH
} from "../../../scripts/cursor-runtime/materialize.mjs";

export const CURSOR_ADAPTER_SCHEMA_VERSION = 1;
export const CURSOR_RUNTIME_ROOT = `${CURSOR_AGENT_RUNTIME_DESTINATION_PARENT}/${CURSOR_AGENT_RUNTIME_DIRECTORY_NAME}`;
export const CURSOR_RUNTIME_MANIFEST = `${CURSOR_AGENT_RUNTIME_DESTINATION_PARENT}/${CURSOR_AGENT_RUNTIME_MANIFEST_NAME}`;
export const CURSOR_RUNTIME_TRUST_CONFIG = CURSOR_AGENT_RUNTIME_TRUST_CONFIG_PATH;
export const CURSOR_RUNTIME_NODE = `${CURSOR_RUNTIME_ROOT}/${CURSOR_AGENT_RUNTIME_NODE_NAME}`;
export const CURSOR_RUNTIME_INDEX = `${CURSOR_RUNTIME_ROOT}/${CURSOR_AGENT_RUNTIME_INDEX_NAME}`;
export const CURSOR_RUNTIME_ARGUMENTS = Object.freeze(["--use-system-ca", CURSOR_RUNTIME_INDEX]);
export const CURSOR_RUNTIME_ENVIRONMENT = Object.freeze({ CURSOR_INVOKED_AS: "cursor-agent" });

export const CURSOR_ADAPTER_STATES = Object.freeze([
  "uninitialized",
  "ready",
  "blocked",
  "expired",
  "revoked",
  "unknown"
]);

const SAFE_CODE = /^[A-Za-z][A-Za-z0-9_.:-]{0,63}$/u;
const ISO_DATE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/u;

const ERROR_PROJECTIONS = Object.freeze({
  invalid_arguments: { message: "Cursor adapter request is invalid", retryable: false },
  invalid_state: { message: "Cursor adapter state is invalid", retryable: false },
  runtime_unavailable: { message: "Cursor Agent runtime is unavailable", retryable: true },
  runtime_untrusted: { message: "Cursor Agent runtime trust could not be established", retryable: false },
  not_ready: { message: "Cursor Agent is not ready", retryable: true },
  authorization_denied: { message: "Cursor Agent operation was denied", retryable: false },
  session_expired: { message: "Cursor Agent session expired", retryable: false },
  session_revoked: { message: "Cursor Agent session was revoked", retryable: false },
  timeout: { message: "Cursor Agent operation timed out", retryable: true },
  signing_failed: { message: "Cursor Agent signing failed", retryable: false },
  unknown_outcome: { message: "Cursor Agent operation outcome is unknown", retryable: false, outcome: "unknown" },
  adapter_failed: { message: "Cursor adapter failed", retryable: false }
});

export class CursorAdapterError extends Error {
  constructor(code, message = code, options = {}) {
    super(message);
    this.name = "CursorAdapterError";
    this.code = code;
    if (options.outcome !== undefined) this.outcome = options.outcome;
  }
}

function fail(code, message = code, options = {}) {
  throw new CursorAdapterError(code, message, options);
}

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    && Object.getPrototypeOf(value) === Object.prototype;
}

function exactKeys(value, expected, label) {
  if (!isPlainObject(value)) fail("invalid_arguments", `${label} is invalid`);
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) {
    fail("invalid_arguments", `${label} has unsupported fields`);
  }
}

function normalizedAbsolutePath(value, label) {
  if (typeof value !== "string" || value.length === 0 || value.length > 4096
    || value.includes("\0") || !path.isAbsolute(value) || path.normalize(value) !== value) {
    fail("invalid_arguments", `${label} is invalid`);
  }
  return value;
}

function safeCodeOrUndefined(value, label) {
  if (value === undefined) return undefined;
  if (typeof value !== "string" || !SAFE_CODE.test(value)) fail("invalid_state", `${label} is invalid`);
  return value;
}

function safeDateOrUndefined(value, label) {
  if (value === undefined) return undefined;
  if (typeof value !== "string" || !ISO_DATE.test(value) || Number.isNaN(Date.parse(value))) {
    fail("invalid_state", `${label} is invalid`);
  }
  return value;
}

/**
 * Create the only launch shape accepted by the Cursor adapter. The runtime,
 * executable, arguments, and environment are release-owned constants. A
 * caller can bind the project directory, but cannot select a binary, add
 * flags, inherit an environment, or provide a secret. Session authority is
 * carried by the authenticated Host channel and is intentionally absent here.
 */
export function createCursorLaunchPlan({ projectDirectory } = {}) {
  const options = arguments[0] ?? {};
  exactKeys(options, ["projectDirectory"], "launch options");
  const normalizedProject = normalizedAbsolutePath(projectDirectory, "project_directory");
  return Object.freeze({
    schema_version: CURSOR_ADAPTER_SCHEMA_VERSION,
    client: "cursor",
    project_directory: normalizedProject,
    executable: CURSOR_RUNTIME_NODE,
    arguments: Object.freeze([...CURSOR_RUNTIME_ARGUMENTS]),
    environment: Object.freeze({ ...CURSOR_RUNTIME_ENVIRONMENT })
  });
}

/**
 * Revalidate a plan at the process boundary. This intentionally checks the
 * complete envelope, not merely the executable, so a stale caller cannot add
 * authority through an omitted or unknown field.
 */
export function validateCursorLaunchPlan(plan) {
  exactKeys(plan, ["arguments", "client", "environment", "executable", "project_directory", "schema_version"], "launch plan");
  if (plan.schema_version !== CURSOR_ADAPTER_SCHEMA_VERSION || plan.client !== "cursor") fail("invalid_arguments", "launch plan identity is invalid");
  normalizedAbsolutePath(plan.project_directory, "project_directory");
  if (plan.executable !== CURSOR_RUNTIME_NODE || !Array.isArray(plan.arguments)
    || plan.arguments.length !== CURSOR_RUNTIME_ARGUMENTS.length
    || plan.arguments.some((value, index) => value !== CURSOR_RUNTIME_ARGUMENTS[index])) {
    fail("invalid_arguments", "launch plan runtime is not fixed");
  }
  if (!isPlainObject(plan.environment) || Object.keys(plan.environment).sort().join("\0") !== "CURSOR_INVOKED_AS"
    || plan.environment.CURSOR_INVOKED_AS !== CURSOR_RUNTIME_ENVIRONMENT.CURSOR_INVOKED_AS) {
    fail("invalid_arguments", "launch plan environment is not fixed");
  }
  return true;
}

/**
 * Project internal state into a closed, machine-readable public state. Raw
 * process errors, paths, claims, and response bodies never cross this API.
 */
export function projectCursorState(raw) {
  exactKeys(raw, ["state", "generation", "expires_at", "reason"] .filter((key) => raw && Object.hasOwn(raw, key)), "state");
  if (!isPlainObject(raw) || typeof raw.state !== "string" || !CURSOR_ADAPTER_STATES.includes(raw.state)) {
    fail("invalid_state", "state is invalid");
  }
  if (raw.generation !== undefined && (!Number.isSafeInteger(raw.generation) || raw.generation < 0)) fail("invalid_state", "generation is invalid");
  const expiresAt = safeDateOrUndefined(raw.expires_at, "expires_at");
  const reason = safeCodeOrUndefined(raw.reason, "reason");
  return Object.freeze({
    schema_version: CURSOR_ADAPTER_SCHEMA_VERSION,
    state: raw.state,
    ...(raw.generation === undefined ? {} : { generation: raw.generation }),
    ...(expiresAt === undefined ? {} : { expires_at: expiresAt }),
    ...(reason === undefined ? {} : { reason })
  });
}

function errorCode(error) {
  return typeof error?.code === "string" && Object.hasOwn(ERROR_PROJECTIONS, error.code) ? error.code : "adapter_failed";
}

/** Return a static error projection with no raw message, cause, or path. */
export function projectCursorAdapterError(error) {
  const code = errorCode(error);
  const projection = ERROR_PROJECTIONS[code];
  return Object.freeze({
    version: CURSOR_ADAPTER_SCHEMA_VERSION,
    ok: false,
    error: Object.freeze({
      code,
      message: projection.message,
      retryable: projection.retryable,
      ...(projection.outcome === undefined ? {} : { outcome: projection.outcome })
    })
  });
}

export function cursorAdapterErrorEnvelope(error) {
  return projectCursorAdapterError(error);
}
