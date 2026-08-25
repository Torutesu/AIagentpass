import path from "node:path";

export const AGENT_LAUNCH_MIN_TTL_SECONDS = 60;
export const AGENT_LAUNCH_MAX_TTL_SECONDS = 86_400;
export const AGENT_LAUNCH_DEFAULT_TTL_SECONDS = 3_600;

export const AGENT_LAUNCH_ERROR_CODES = Object.freeze({
  INVALID_ARGUMENTS: "AGENT_LAUNCH_INVALID_ARGUMENTS",
  MISSING_AGENT: "AGENT_LAUNCH_AGENT_MISSING",
  UNSUPPORTED_AGENT: "AGENT_LAUNCH_AGENT_UNSUPPORTED",
  DUPLICATE_FLAG: "AGENT_LAUNCH_DUPLICATE_FLAG",
  MISSING_VALUE: "AGENT_LAUNCH_VALUE_MISSING",
  UNKNOWN_FLAG: "AGENT_LAUNCH_UNKNOWN_FLAG",
  FORBIDDEN_SELECTOR: "AGENT_LAUNCH_FORBIDDEN_SELECTOR",
  POSITIONAL_ARGUMENT: "AGENT_LAUNCH_POSITIONAL_ARGUMENT",
  INVALID_PROJECT: "AGENT_LAUNCH_PROJECT_INVALID",
  INVALID_TTL: "AGENT_LAUNCH_TTL_INVALID",
  TTL_OUT_OF_RANGE: "AGENT_LAUNCH_TTL_OUT_OF_RANGE"
});

export const AGENT_LAUNCH_FORBIDDEN_FLAGS = Object.freeze([
  "--token",
  "--session",
  "--key",
  "--private-key",
  "--algorithm",
  "--namespace",
  "--fd",
  "--socket",
  "--host",
  "--executable",
  "--host-executable"
]);

const ALLOWED_FLAGS = new Set(["--agent", "--project", "--ttl"]);
const FORBIDDEN_FLAGS = new Set(AGENT_LAUNCH_FORBIDDEN_FLAGS);
const MESSAGES = Object.freeze({
  INVALID_ARGUMENTS: "Launch arguments are invalid",
  MISSING_AGENT: "Launch requires --agent",
  UNSUPPORTED_AGENT: "Launch agent is unsupported",
  DUPLICATE_FLAG: "Launch option was supplied more than once",
  MISSING_VALUE: "Launch option requires a value",
  UNKNOWN_FLAG: "Launch option is unknown",
  FORBIDDEN_SELECTOR: "Launch selector is forbidden",
  POSITIONAL_ARGUMENT: "Launch does not accept positional arguments",
  INVALID_PROJECT: "Launch project must be an absolute canonical directory",
  INVALID_TTL: "Launch TTL must be an integer number of seconds",
  TTL_OUT_OF_RANGE: "Launch TTL is outside the native session limits"
});

export class AgentLaunchContractError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "AgentLaunchContractError";
    this.code = code;
  }
}

function fail(code, message) {
  throw new AgentLaunchContractError(code, message);
}

function optionName(token) {
  const equals = token.indexOf("=");
  return equals === -1 ? token : token.slice(0, equals);
}

function forbiddenSelector(token) {
  return FORBIDDEN_FLAGS.has(optionName(token));
}

function validateArgumentVector(argv) {
  if (!Array.isArray(argv) || argv.some((token) => typeof token !== "string")) {
    fail(AGENT_LAUNCH_ERROR_CODES.INVALID_ARGUMENTS, MESSAGES.INVALID_ARGUMENTS);
  }
}

function readValue(tokens, index) {
  const value = tokens[index + 1];
  if (value === undefined) fail(AGENT_LAUNCH_ERROR_CODES.MISSING_VALUE, MESSAGES.MISSING_VALUE);
  if (forbiddenSelector(value)) fail(AGENT_LAUNCH_ERROR_CODES.FORBIDDEN_SELECTOR, MESSAGES.FORBIDDEN_SELECTOR);
  if (value.startsWith("--")) fail(AGENT_LAUNCH_ERROR_CODES.MISSING_VALUE, MESSAGES.MISSING_VALUE);
  return value;
}

function canonicalProject(value) {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.includes("\0") ||
    !path.isAbsolute(value) ||
    (value.length > 1 && value.endsWith(path.sep)) ||
    path.normalize(value) !== value
  ) {
    fail(AGENT_LAUNCH_ERROR_CODES.INVALID_PROJECT, MESSAGES.INVALID_PROJECT);
  }
  return value;
}

function normalizedTtl(value) {
  if (value === undefined) return AGENT_LAUNCH_DEFAULT_TTL_SECONDS;
  if (!/^(?:0|[1-9]\d*)$/u.test(value)) {
    fail(AGENT_LAUNCH_ERROR_CODES.INVALID_TTL, MESSAGES.INVALID_TTL);
  }
  const seconds = Number(value);
  if (!Number.isSafeInteger(seconds)) {
    fail(AGENT_LAUNCH_ERROR_CODES.INVALID_TTL, MESSAGES.INVALID_TTL);
  }
  if (seconds < AGENT_LAUNCH_MIN_TTL_SECONDS || seconds > AGENT_LAUNCH_MAX_TTL_SECONDS) {
    fail(AGENT_LAUNCH_ERROR_CODES.TTL_OUT_OF_RANGE, MESSAGES.TTL_OUT_OF_RANGE);
  }
  return seconds;
}

/**
 * Parse the launch command, or the arguments immediately following `launch`.
 * The returned DTO contains only the bounded launch parameters and is frozen.
 */
export function parseAgentLaunchArgs(argv) {
  validateArgumentVector(argv);
  const tokens = argv[0] === "launch" ? argv.slice(1) : argv;
  const seen = new Set();
  let agent;
  let project;
  let ttl;

  for (let index = 0; index < tokens.length; index += 1) {
    const token = tokens[index];
    if (!token.startsWith("--")) {
      fail(AGENT_LAUNCH_ERROR_CODES.POSITIONAL_ARGUMENT, MESSAGES.POSITIONAL_ARGUMENT);
    }
    if (forbiddenSelector(token)) {
      fail(AGENT_LAUNCH_ERROR_CODES.FORBIDDEN_SELECTOR, MESSAGES.FORBIDDEN_SELECTOR);
    }
    if (!ALLOWED_FLAGS.has(token)) {
      fail(AGENT_LAUNCH_ERROR_CODES.UNKNOWN_FLAG, MESSAGES.UNKNOWN_FLAG);
    }
    if (seen.has(token)) {
      fail(AGENT_LAUNCH_ERROR_CODES.DUPLICATE_FLAG, MESSAGES.DUPLICATE_FLAG);
    }
    seen.add(token);
    const value = readValue(tokens, index);
    index += 1;
    if (token === "--agent") agent = value;
    else if (token === "--project") project = canonicalProject(value);
    else ttl = value;
  }

  if (agent === undefined) fail(AGENT_LAUNCH_ERROR_CODES.MISSING_AGENT, MESSAGES.MISSING_AGENT);
  if (agent !== "claude-code" && agent !== "cursor") fail(AGENT_LAUNCH_ERROR_CODES.UNSUPPORTED_AGENT, MESSAGES.UNSUPPORTED_AGENT);

  return Object.freeze({
    agent,
    project: project ?? null,
    ttl_seconds: normalizedTtl(ttl)
  });
}

export const normalizeAgentLaunchArgs = parseAgentLaunchArgs;
