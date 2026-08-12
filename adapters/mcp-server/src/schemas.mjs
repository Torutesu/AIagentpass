const EDITORS = ["claude-code", "cursor"];
export const MAX_AUDIT_TAIL_COUNT = 50;

function schemaError(message) {
  const error = new Error(message);
  error.code = "invalid_params";
  return error;
}

export const TOOLS = [
  {
    name: "agentpass_status",
    description: "Return a redacted AgentPass policy, agent, revocation, and audit-key summary.",
    inputSchema: { type: "object", properties: {}, additionalProperties: false }
  },
  {
    name: "agentpass_check",
    description: "Evaluate the current repository for the Git-native signing operation.",
    inputSchema: { type: "object", properties: {}, additionalProperties: false }
  },
  {
    name: "agentpass_setup",
    description: "Return safe, editor-specific MCP setup instructions; this tool never signs arbitrary payloads.",
    inputSchema: {
      type: "object",
      properties: { editor: { type: "string", enum: EDITORS } },
      required: ["editor"],
      additionalProperties: false
    }
  },
  {
    name: "agentpass_audit_tail",
    description: "Return a bounded tail of redacted AgentPass decisions.",
    inputSchema: {
      type: "object",
      properties: { count: { type: "integer", minimum: 1, maximum: MAX_AUDIT_TAIL_COUNT, default: 10 } },
      additionalProperties: false
    }
  }
].map((tool) => ({ ...tool, annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false } }));

const TOOL_NAMES = new Set(TOOLS.map(({ name }) => name));

function object(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function exactKeys(value, keys) {
  return Object.keys(value).every((key) => keys.includes(key));
}

export function validateToolArguments(name, value) {
  if (!object(value)) throw schemaError("Tool arguments must be an object");
  if (!TOOL_NAMES.has(name)) throw schemaError("Unknown tool");
  if (name === "agentpass_setup") {
    if (!exactKeys(value, ["editor"]) || !EDITORS.includes(value.editor)) throw schemaError("editor must be claude-code or cursor");
    return { editor: value.editor };
  }
  if (name === "agentpass_audit_tail") {
    if (!exactKeys(value, ["count"])) throw schemaError("audit_tail accepts only count");
    const count = value.count ?? 10;
    if (!Number.isInteger(count) || count < 1 || count > MAX_AUDIT_TAIL_COUNT) throw schemaError(`count must be an integer from 1 to ${MAX_AUDIT_TAIL_COUNT}`);
    return { count };
  }
  if (Object.keys(value).length !== 0) throw schemaError(`${name} accepts no arguments`);
  return {};
}

export function validateInitializeParams(params) {
  if (!object(params) || typeof params.protocolVersion !== "string" || !object(params.capabilities) || !object(params.clientInfo)) {
    throw schemaError("initialize requires protocolVersion, capabilities, and clientInfo");
  }
  if (typeof params.clientInfo.name !== "string" || typeof params.clientInfo.version !== "string") throw schemaError("clientInfo is invalid");
}

export function isObject(value) {
  return object(value);
}
