import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

import { OWNER_RECOVERY_DELIVERY_FAULT_BOUNDARIES } from "./owner-recovery-delivery-fault-controller.mjs";

const CHILD_URL = new URL("./owner-recovery-process-loss-qualification-child.mjs", import.meta.url);
const REPOSITORY_ROOT = fileURLToPath(new URL("../../../../", import.meta.url));
const BOUNDARY_SET = new Set(OWNER_RECOVERY_DELIVERY_FAULT_BOUNDARIES);
const MODES = new Set(["contract", "contract_noisy", "delivery", "reclaim"]);
const COMMANDS = new Set(["run", "continue"]);
const MESSAGE_TYPES = new Set(["ready", "boundary_reached", "completed", "reclaimed", "error"]);
const OUTCOMES = new Set(["published", "claim_lost", "uncertain", "retried", "dead_lettered"]);
const STATES = new Set(["pending", "published", "uncertain", "dead_letter", "suppressed"]);

const DEFAULTS = Object.freeze({
  deadlineMs: 10_000,
  maxOutputBytes: 32 * 1024,
  maxMessageBytes: 4 * 1024,
  leaseMs: 1_500
});

export const OWNER_RECOVERY_PROCESS_LOSS_QUALIFICATION_ERROR_CODES = Object.freeze({
  DATABASE_REQUIRED: "owner_recovery_process_loss_database_required",
  DATABASE_INVALID: "owner_recovery_process_loss_database_invalid",
  INVALID_ARGUMENT: "owner_recovery_process_loss_invalid_argument",
  OUTPUT_LIMIT: "owner_recovery_process_loss_output_limit",
  IPC_LIMIT: "owner_recovery_process_loss_ipc_limit",
  DEADLINE: "owner_recovery_process_loss_deadline",
  PROTOCOL: "owner_recovery_process_loss_protocol",
  CHILD_EXITED: "owner_recovery_process_loss_child_exited",
  CHILD_FAILED: "owner_recovery_process_loss_child_failed"
});

export class OwnerRecoveryProcessLossQualificationError extends Error {
  constructor(code) {
    super(messageFor(code));
    this.name = "OwnerRecoveryProcessLossQualificationError";
    this.code = code;
  }
}

export function requireOwnerRecoveryQualificationDatabase(env = process.env) {
  const databaseUrl = env?.AGENTPASS_TEST_DATABASE_URL;
  if (typeof databaseUrl !== "string" || databaseUrl.length === 0) {
    throw qualificationError("DATABASE_REQUIRED");
  }
  try {
    const parsed = new URL(databaseUrl);
    if (parsed.protocol !== "postgres:" && parsed.protocol !== "postgresql:") throw new Error();
  } catch {
    throw qualificationError("DATABASE_INVALID");
  }
  return databaseUrl;
}

/**
 * Start the isolated qualification child. The child environment is
 * intentionally allowlisted: no ambient test variables, provider settings,
 * request data, or diagnostics are inherited by the child.
 */
export function launchOwnerRecoveryProcessLossQualificationChild({
  databaseUrl = requireOwnerRecoveryQualificationDatabase(),
  mode,
  boundary,
  organizationId,
  eventId,
  leaseMs = DEFAULTS.leaseMs,
  deadlineMs = DEFAULTS.deadlineMs,
  maxOutputBytes = DEFAULTS.maxOutputBytes,
  maxMessageBytes = DEFAULTS.maxMessageBytes
} = {}) {
  validateMode(mode);
  validateBoundary(boundary);
  if ((mode === "contract" || mode === "delivery") && boundary === undefined) throw qualificationError("INVALID_ARGUMENT");
  if ((mode === "delivery" || mode === "reclaim") && (organizationId === undefined || eventId === undefined)) throw qualificationError("INVALID_ARGUMENT");
  validateUuidOption(organizationId);
  validateUuidOption(eventId);
  validateInteger(leaseMs, 1_000, 5 * 60_000);
  validateInteger(deadlineMs, 100, 60_000);
  validateInteger(maxOutputBytes, 1, 4 * 1024 * 1024);
  validateInteger(maxMessageBytes, 64, 64 * 1024);

  const child = spawn(process.execPath, [
    fileURLToPath(CHILD_URL),
    `--mode=${mode}`,
    ...(boundary === undefined ? [] : [`--boundary=${boundary}`]),
    ...(organizationId === undefined ? [] : [`--organization-id=${organizationId}`]),
    ...(eventId === undefined ? [] : [`--event-id=${eventId}`]),
    `--lease-ms=${leaseMs}`
  ], {
    cwd: REPOSITORY_ROOT,
    env: {
      NODE_ENV: "test",
      AGENTPASS_TEST_DATABASE_URL: databaseUrl
    },
    shell: false,
    stdio: ["pipe", "pipe", "pipe"],
    windowsHide: true
  });

  let stdoutBytes = 0;
  let stderrBytes = 0;
  let stdoutBuffer = "";
  let settled = false;
  let deadlineTimer;
  const messages = [];
  const waiters = [];
  let protocolError;

  const session = {
    pid: child.pid,
    send(command) {
      validateCommand(command);
      if (settled || !child.stdin.writable) throw qualificationError("CHILD_EXITED");
      const line = `${JSON.stringify(command)}\n`;
      if (Buffer.byteLength(line, "utf8") > maxMessageBytes) throw qualificationError("IPC_LIMIT");
      child.stdin.write(line);
    },
    waitForMessage(type) {
      if (!MESSAGE_TYPES.has(type)) throw qualificationError("INVALID_ARGUMENT");
      const index = messages.findIndex((message) => message.type === type || message.type === "error");
      if (index !== -1) {
        const [message] = messages.splice(index, 1);
        return message.type === "error" ? Promise.reject(qualificationError("CHILD_FAILED")) : Promise.resolve(message);
      }
      return new Promise((resolve, reject) => waiters.push({ type, resolve, reject }));
    },
    async kill(signal = "SIGKILL") {
      if (signal !== "SIGKILL") throw qualificationError("INVALID_ARGUMENT");
      if (!settled) child.kill(signal);
      return waitForExit();
    },
    waitForExit,
    snapshot() {
      return Object.freeze({ stdout_bytes: stdoutBytes, stderr_bytes: stderrBytes, settled });
    }
  };

  const finishWaiters = (error) => {
    while (waiters.length > 0) waiters.shift().reject(error);
  };

  const failProtocol = (code) => {
    if (protocolError) return;
    protocolError = qualificationError(code);
    finishWaiters(protocolError);
    if (!settled) child.kill("SIGKILL");
  };

  child.once("error", () => failProtocol("CHILD_EXITED"));
  child.stdin.on("error", () => failProtocol("CHILD_EXITED"));

  const acceptMessage = (message) => {
    try {
      validateMessage(message);
      const waiterIndex = waiters.findIndex(({ type }) => type === message.type);
      if (waiterIndex !== -1) {
        const [{ resolve }] = waiters.splice(waiterIndex, 1);
        resolve(message);
      } else if (message.type === "error") {
        finishWaiters(qualificationError("CHILD_FAILED"));
      } else {
        messages.push(message);
      }
    } catch (error) {
      failProtocol(error.code === OWNER_RECOVERY_PROCESS_LOSS_QUALIFICATION_ERROR_CODES.IPC_LIMIT
        ? "IPC_LIMIT"
        : "PROTOCOL");
    }
  };

  child.stdout.on("data", (chunk) => {
    stdoutBytes += chunk.length;
    if (stdoutBytes > maxOutputBytes) {
      failProtocol("OUTPUT_LIMIT");
      return;
    }
    stdoutBuffer += chunk.toString("utf8");
    if (Buffer.byteLength(stdoutBuffer, "utf8") > maxMessageBytes) {
      failProtocol("IPC_LIMIT");
      return;
    }
    let newline;
    while ((newline = stdoutBuffer.indexOf("\n")) !== -1) {
      const line = stdoutBuffer.slice(0, newline);
      stdoutBuffer = stdoutBuffer.slice(newline + 1);
      if (Buffer.byteLength(line, "utf8") > maxMessageBytes) {
        failProtocol("IPC_LIMIT");
        return;
      }
      let message;
      try { message = JSON.parse(line); }
      catch { failProtocol("PROTOCOL"); return; }
      acceptMessage(message);
    }
  });
  child.stderr.on("data", (chunk) => {
    stderrBytes += chunk.length;
    if (stderrBytes > maxOutputBytes) failProtocol("OUTPUT_LIMIT");
  });

  const exitPromise = new Promise((resolve) => {
    child.once("close", (code, signal) => {
      settled = true;
      clearTimeout(deadlineTimer);
      if (stdoutBuffer.length > 0 && !protocolError) failProtocol("PROTOCOL");
      const result = Object.freeze({ code, signal });
      finishWaiters(protocolError ?? (signal === "SIGKILL" ? undefined : qualificationError("CHILD_EXITED")));
      resolve(result);
    });
  });
  function waitForExit() { return exitPromise; }

  deadlineTimer = setTimeout(() => failProtocol("DEADLINE"), deadlineMs);
  deadlineTimer.unref?.();
  return Object.freeze(session);
}

function validateMessage(message) {
  if (!message || typeof message !== "object" || Array.isArray(message) || typeof message.type !== "string" || !MESSAGE_TYPES.has(message.type)) throw qualificationError("PROTOCOL");
  const keys = Object.keys(message);
  if (message.type === "ready" && keys.length === 1) return;
  if (message.type === "boundary_reached" && keys.length === 2 && typeof message.boundary === "string") {
    validateBoundary(message.boundary);
    return;
  }
  if (message.type === "completed" && keys.length === 2 && OUTCOMES.has(message.outcome)) return;
  if (message.type === "reclaimed" && keys.length === 3 && STATES.has(message.state) && Number.isSafeInteger(message.claimed) && message.claimed >= 0 && message.claimed <= 100) return;
  if (message.type === "error" && keys.length === 2 && message.code === "CHILD_FAILURE") return;
  throw qualificationError("PROTOCOL");
}

function validateCommand(command) {
  if (!command || typeof command !== "object" || Array.isArray(command) || Object.keys(command).length !== 1 || !COMMANDS.has(command.type)) throw qualificationError("INVALID_ARGUMENT");
}

function validateMode(mode) {
  if (typeof mode !== "string" || !MODES.has(mode)) throw qualificationError("INVALID_ARGUMENT");
}

function validateBoundary(boundary) {
  if (boundary !== undefined && (typeof boundary !== "string" || !BOUNDARY_SET.has(boundary))) throw qualificationError("INVALID_ARGUMENT");
}

function validateUuidOption(value) {
  if (value !== undefined && (typeof value !== "string" || !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu.test(value))) throw qualificationError("INVALID_ARGUMENT");
}

function validateInteger(value, minimum, maximum) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) throw qualificationError("INVALID_ARGUMENT");
}

function qualificationError(name) {
  return new OwnerRecoveryProcessLossQualificationError(OWNER_RECOVERY_PROCESS_LOSS_QUALIFICATION_ERROR_CODES[name]);
}

function messageFor(code) {
  return {
    [OWNER_RECOVERY_PROCESS_LOSS_QUALIFICATION_ERROR_CODES.DATABASE_REQUIRED]: "AGENTPASS_TEST_DATABASE_URL is required for PostgreSQL qualification",
    [OWNER_RECOVERY_PROCESS_LOSS_QUALIFICATION_ERROR_CODES.DATABASE_INVALID]: "AGENTPASS_TEST_DATABASE_URL is invalid",
    [OWNER_RECOVERY_PROCESS_LOSS_QUALIFICATION_ERROR_CODES.INVALID_ARGUMENT]: "Process-loss qualification argument is invalid",
    [OWNER_RECOVERY_PROCESS_LOSS_QUALIFICATION_ERROR_CODES.OUTPUT_LIMIT]: "Process-loss qualification child output limit exceeded",
    [OWNER_RECOVERY_PROCESS_LOSS_QUALIFICATION_ERROR_CODES.IPC_LIMIT]: "Process-loss qualification IPC limit exceeded",
    [OWNER_RECOVERY_PROCESS_LOSS_QUALIFICATION_ERROR_CODES.DEADLINE]: "Process-loss qualification child deadline exceeded",
    [OWNER_RECOVERY_PROCESS_LOSS_QUALIFICATION_ERROR_CODES.PROTOCOL]: "Process-loss qualification child protocol is invalid",
    [OWNER_RECOVERY_PROCESS_LOSS_QUALIFICATION_ERROR_CODES.CHILD_EXITED]: "Process-loss qualification child exited unexpectedly",
    [OWNER_RECOVERY_PROCESS_LOSS_QUALIFICATION_ERROR_CODES.CHILD_FAILED]: "Process-loss qualification child failed"
  }[code] ?? "Process-loss qualification failed";
}

export default launchOwnerRecoveryProcessLossQualificationChild;
