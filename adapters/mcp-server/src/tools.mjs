import { CliRunnerError } from "./cli-runner.mjs";
import { validateToolArguments } from "./schemas.mjs";
import { fileURLToPath } from "node:url";

const MCP_SERVER_PATH = fileURLToPath(new URL("../bin/agentpass-mcp.mjs", import.meta.url));

const SAFE_AUDIT_FIELDS = [
  "timestamp", "operation", "decision", "reason", "request_id", "evaluated_at",
  "agent_id", "generation", "sequence", "policy_sequence", "capability_sequence",
  "payload_digest", "hash", "previous_hash"
];

function parseJson(stdout, label) {
  try {
    const value = JSON.parse(stdout.trim());
    if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error();
    return value;
  } catch {
    throw new Error(`AgentPass returned invalid ${label} data`);
  }
}

function safeString(value, max = 256) {
  return typeof value === "string" && value.length <= max ? value : undefined;
}

function safeCode(value, max = 256) {
  return typeof value === "string" && value.length > 0 && value.length <= max && /^[A-Za-z0-9][A-Za-z0-9_.:-]*$/.test(value) ? value : undefined;
}

function redactedStatus(raw) {
  const result = { initialized: true };
  if (Number.isInteger(raw.version)) result.version = raw.version;
  if (Array.isArray(raw.agents)) {
    result.agents = raw.agents.filter((agent) => agent && typeof agent === "object").map((agent) => {
      const safe = {};
      if (safeString(agent.id, 128)) safe.id = agent.id;
      if (safeCode(agent.name, 64)) safe.name = agent.name;
      if (typeof agent.default === "boolean") safe.default = agent.default;
      return safe;
    });
  }
  if (Array.isArray(raw.operations) && raw.operations.every((item) => safeCode(item, 128))) result.operations = raw.operations;
  if (typeof raw.revoked === "boolean") result.revoked = raw.revoked;
  if (Number.isInteger(raw.generation) && raw.generation >= 0) result.generation = raw.generation;
  if (safeCode(raw.audit_key_fingerprint, 256)) result.audit_key_fingerprint = raw.audit_key_fingerprint;
  return result;
}

function redactedCheck(raw) {
  if (typeof raw.allowed !== "boolean" || !safeCode(raw.reason, 128)) throw new Error("AgentPass returned invalid check data");
  const result = { allowed: raw.allowed, reason: raw.reason };
  if (safeCode(raw.operation, 128)) result.operation = raw.operation;
  return result;
}

function redactAuditEvent(raw) {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return null;
  const safe = {};
  for (const key of SAFE_AUDIT_FIELDS) {
    const value = raw[key];
    if (key === "timestamp" || key === "operation" || key === "decision" || key === "reason" || key === "agent_id") {
      if (safeCode(value)) safe[key] = value;
    } else if (typeof value === "string" && /^[A-Za-z0-9_-]{1,256}$/.test(value)) safe[key] = value;
    else if (Number.isInteger(value) && value >= 0) safe[key] = value;
  }
  return Object.keys(safe).length ? safe : null;
}

function redactedAuditTail(stdout, count) {
  const events = stdout.split(/\r?\n/).map((line) => line.trim()).filter(Boolean).map((line) => {
    try { return redactAuditEvent(JSON.parse(line)); } catch { return null; }
  }).filter(Boolean);
  return { events: events.slice(-count), count: Math.min(events.length, count) };
}

function setupResult(editor) {
  return {
    editor,
    transport: "stdio",
    mcp_server: { command: process.execPath, args: [MCP_SERVER_PATH] },
    instructions: [
      `Configure ${editor} to launch the agentpass-mcp executable over stdio.`,
      "Keep signing Git-native: use git commit and the configured AgentPass Git signing helper.",
      "Do not send signing payloads, session tokens, or private key material to this MCP server."
    ],
    configuration: {
      mcpServers: { agentpass: { command: process.execPath, args: [MCP_SERVER_PATH] } }
    }
  };
}

export function createToolHandler(commandRunner) {
  if (typeof commandRunner !== "function") throw new TypeError("commandRunner must be a function");
  return async function callTool(name, argumentsValue = {}) {
    const args = validateToolArguments(name, argumentsValue);
    if (name === "agentpass_status") {
      const result = await commandRunner(["status"]);
      if (result.code !== 0) throw new CliRunnerError("status failed");
      return redactedStatus(parseJson(result.stdout, "status"));
    }
    if (name === "agentpass_check") {
      const result = await commandRunner(["check"]);
      if (result.code !== 0 && result.code !== 1) throw new CliRunnerError("check failed");
      return redactedCheck(parseJson(result.stdout, "check"));
    }
    if (name === "agentpass_setup") {
      const result = await commandRunner(["integrate", args.editor]);
      if (result.code !== 0) throw new CliRunnerError("setup failed");
      return setupResult(args.editor);
    }
    const result = await commandRunner(["audit", "--tail", String(args.count)]);
    if (result.code !== 0) throw new CliRunnerError("audit failed");
    return redactedAuditTail(result.stdout, args.count);
  };
}

export function safeToolError(error) {
  if (error instanceof CliRunnerError) return "AgentPass command failed";
  if (error instanceof Error && /invalid (?:status|check|audit) data|Tool arguments|accepts only|must be|Unknown tool/.test(error.message)) return error.message;
  return "AgentPass tool failed";
}
