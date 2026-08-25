import path from "node:path";

import {
  createAgentLifecycleLaunchDescriptor,
  launchAgentLifecycleWithHandoff
} from "../../../lib/agent-lifecycle-cli.mjs";

export const CLAUDE_CODE_ADAPTER_SCHEMA_VERSION = 1;
export const CLAUDE_CODE_CLIENT = "claude-code";

// These values are release-owned. This adapter describes a launch boundary;
// it does not resolve PATH, accept a caller-selected executable, or spawn a
// Claude Code process. The production installer may replace these constants
// only as part of a signed release, never through adapter input.
export const CLAUDE_CODE_EXECUTABLE = "/usr/local/bin/claude";
export const CLAUDE_CODE_MCP_SERVER = "/usr/local/bin/agentpass-mcp";
export const CLAUDE_CODE_ARGUMENTS = Object.freeze([]);
export const CLAUDE_CODE_ENVIRONMENT = Object.freeze({});
export const CLAUDE_CODE_MCP_ARGUMENTS = Object.freeze([]);

// No process lifecycle is claimed by this package. A real authenticated Host
// connection must be supplied by the native layer before a future lifecycle
// implementation can be enabled.
export const CLAUDE_NATIVE_HOST_STATUS = "unavailable";

export const CLAUDE_CODE_ADAPTER_STATES = Object.freeze([
  "uninitialized",
  "ready",
  "blocked",
  "expired",
  "revoked",
  "host_unavailable",
  "unknown"
]);

const SAFE_CODE = /^[A-Za-z][A-Za-z0-9_.:-]{0,63}$/u;
const ISO_DATE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/u;

const ERROR_PROJECTIONS = Object.freeze({
  invalid_arguments: { message: "Claude Code adapter request is invalid", retryable: false },
  invalid_state: { message: "Claude Code adapter state is invalid", retryable: false },
  native_host_unavailable: { message: "AgentPass native Host is unavailable", retryable: true },
  native_host_untrusted: { message: "AgentPass native Host trust could not be established", retryable: false },
  not_ready: { message: "Claude Code is not ready", retryable: true },
  authorization_denied: { message: "Claude Code operation was denied", retryable: false },
  session_expired: { message: "Claude Code session expired", retryable: false },
  session_revoked: { message: "Claude Code session was revoked", retryable: false },
  timeout: { message: "Claude Code operation timed out", retryable: true },
  signing_failed: { message: "Claude Code signing failed", retryable: false },
  unknown_outcome: { message: "Claude Code operation outcome is unknown", retryable: false, outcome: "unknown" },
  adapter_failed: { message: "Claude Code adapter failed", retryable: false }
});

export class ClaudeCodeAdapterError extends Error {
  constructor(code, message = code, options = {}) {
    super(message);
    this.name = "ClaudeCodeAdapterError";
    this.code = code;
    if (options.outcome !== undefined) this.outcome = options.outcome;
  }
}

function fail(code, message = code, options = {}) {
  throw new ClaudeCodeAdapterError(code, message, options);
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

function fixedEmptyObject(value, label) {
  if (!isPlainObject(value) || Object.keys(value).length !== 0) fail("invalid_arguments", `${label} is not fixed`);
}

function fixedEmptyArray(value, label) {
  if (!Array.isArray(value) || value.length !== 0) fail("invalid_arguments", `${label} is not fixed`);
}

/**
 * Return the only launch shape accepted by the Claude Code boundary.
 * `projectDirectory` is the sole caller-controlled value. This function is a
 * plan constructor only; it deliberately does not start or monitor a child.
 */
export function createClaudeCodeLaunchPlan({ projectDirectory } = {}) {
  const options = arguments[0] ?? {};
  exactKeys(options, ["projectDirectory"], "launch options");
  const normalizedProject = normalizedAbsolutePath(projectDirectory, "project_directory");
  return Object.freeze({
    schema_version: CLAUDE_CODE_ADAPTER_SCHEMA_VERSION,
    client: CLAUDE_CODE_CLIENT,
    project_directory: normalizedProject,
    executable: CLAUDE_CODE_EXECUTABLE,
    arguments: Object.freeze([...CLAUDE_CODE_ARGUMENTS]),
    environment: Object.freeze({ ...CLAUDE_CODE_ENVIRONMENT }),
    mcp_server: Object.freeze({
      command: CLAUDE_CODE_MCP_SERVER,
      arguments: Object.freeze([...CLAUDE_CODE_MCP_ARGUMENTS]),
      environment: Object.freeze({ AGENTPASS_PROJECT_DIR: normalizedProject })
    }),
    native_host: CLAUDE_NATIVE_HOST_STATUS
  });
}

/** Revalidate the complete closed envelope at the process boundary. */
export function validateClaudeCodeLaunchPlan(plan) {
  exactKeys(plan, [
    "arguments", "client", "environment", "executable", "mcp_server",
    "native_host", "project_directory", "schema_version"
  ], "launch plan");
  if (plan.schema_version !== CLAUDE_CODE_ADAPTER_SCHEMA_VERSION || plan.client !== CLAUDE_CODE_CLIENT) {
    fail("invalid_arguments", "launch plan identity is invalid");
  }
  normalizedAbsolutePath(plan.project_directory, "project_directory");
  if (plan.executable !== CLAUDE_CODE_EXECUTABLE) fail("invalid_arguments", "launch plan executable is not fixed");
  fixedEmptyArray(plan.arguments, "launch plan arguments");
  fixedEmptyObject(plan.environment, "launch plan environment");
  if (!isPlainObject(plan.mcp_server)) fail("invalid_arguments", "launch plan MCP server is invalid");
  exactKeys(plan.mcp_server, ["arguments", "command", "environment"], "launch plan MCP server");
  if (plan.mcp_server.command !== CLAUDE_CODE_MCP_SERVER) fail("invalid_arguments", "MCP server command is not fixed");
  fixedEmptyArray(plan.mcp_server.arguments, "MCP server arguments");
  if (!isPlainObject(plan.mcp_server.environment)
    || Object.keys(plan.mcp_server.environment).sort().join("\0") !== "AGENTPASS_PROJECT_DIR"
    || plan.mcp_server.environment.AGENTPASS_PROJECT_DIR !== plan.project_directory) {
    fail("invalid_arguments", "MCP server environment is not project-bound");
  }
  if (plan.native_host !== CLAUDE_NATIVE_HOST_STATUS) fail("invalid_arguments", "native Host status is invalid");
  return true;
}

/** Build only the public process-bound launch descriptor; authority stays on FD3. */
export function createClaudeCodeLifecycleDescriptor({ projectDirectory, ttlSeconds } = {}) {
  const options = arguments[0] ?? {};
  exactKeys(options, ["projectDirectory", "ttlSeconds"], "lifecycle options");
  const project = normalizedAbsolutePath(projectDirectory, "project_directory");
  if (!Number.isSafeInteger(ttlSeconds)) fail("invalid_arguments", "ttl_seconds is invalid");
  try {
    return createAgentLifecycleLaunchDescriptor({ agent: "claude-code", project, ttl_seconds: ttlSeconds });
  } catch {
    fail("invalid_arguments", "lifecycle descriptor is invalid");
  }
}

/** Relay the inherited one-time handoff to the fixed Native Host. */
export async function launchClaudeCodeLifecycle(input, options = {}) {
  const descriptor = createClaudeCodeLifecycleDescriptor(input);
  const result = await launchAgentLifecycleWithHandoff(descriptor, options);
  if (result.ok === true) return Object.freeze({ version: 1, ok: true, operation: "launch", status: result.status });
  const error = result.error;
  if (!error || typeof error.code !== "string") fail("adapter_failed");
  if (error.code === "AGENT_LIFECYCLE_NOT_AVAILABLE" || error.code === "AGENT_LIFECYCLE_HANDOFF_NOT_AVAILABLE") fail("native_host_unavailable");
  if (error.code === "AGENT_LIFECYCLE_NATIVE_HOST_REJECTED") fail("native_host_untrusted");
  fail("adapter_failed");
}

export function projectClaudeCodeState(raw) {
  if (!isPlainObject(raw)) fail("invalid_state", "state is invalid");
  const allowed = ["state", "generation", "expires_at", "reason"];
  exactKeys(raw, Object.keys(raw), "state");
  if (Object.keys(raw).some((key) => !allowed.includes(key))) fail("invalid_arguments", "state has unsupported fields");
  if (typeof raw.state !== "string" || !CLAUDE_CODE_ADAPTER_STATES.includes(raw.state)) fail("invalid_state", "state is invalid");
  if (raw.generation !== undefined && (!Number.isSafeInteger(raw.generation) || raw.generation < 0)) fail("invalid_state", "generation is invalid");
  const expiresAt = safeDateOrUndefined(raw.expires_at, "expires_at");
  const reason = safeCodeOrUndefined(raw.reason, "reason");
  return Object.freeze({
    schema_version: CLAUDE_CODE_ADAPTER_SCHEMA_VERSION,
    state: raw.state,
    ...(raw.generation === undefined ? {} : { generation: raw.generation }),
    ...(expiresAt === undefined ? {} : { expires_at: expiresAt }),
    ...(reason === undefined ? {} : { reason })
  });
}

function errorCode(error) {
  return typeof error?.code === "string" && Object.hasOwn(ERROR_PROJECTIONS, error.code) ? error.code : "adapter_failed";
}

/** Return a static error projection without raw messages, causes, or paths. */
export function projectClaudeCodeAdapterError(error) {
  const code = errorCode(error);
  const projection = ERROR_PROJECTIONS[code];
  return Object.freeze({
    version: CLAUDE_CODE_ADAPTER_SCHEMA_VERSION,
    ok: false,
    error: Object.freeze({
      code,
      message: projection.message,
      retryable: projection.retryable,
      ...(projection.outcome === undefined ? {} : { outcome: projection.outcome })
    })
  });
}

export const claudeCodeAdapterErrorEnvelope = projectClaudeCodeAdapterError;
