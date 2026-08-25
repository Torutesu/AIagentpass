const EDITORS = ["claude-code", "cursor"];
export const MAX_AUDIT_TAIL_COUNT = 50;
export const MAX_APP_LIST_COUNT = 50;
export const MAX_MAINTENANCE_STATUS_COUNT = 50;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const IDEMPOTENCY = /^[A-Za-z0-9][A-Za-z0-9._:-]{7,255}$/;
const SECRET_KEY = /(secret|token|password|private.?key|api.?key|authorization|cookie|credential)/i;

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
  },
  {
    name: "agentpass_app_inspect",
    description: "Inspect one tenant-bound Small Software app using a redacted lifecycle summary.",
    inputSchema: {
      type: "object",
      properties: { organization_id: { type: "string", format: "uuid" }, app_id: { type: "string", format: "uuid" } },
      required: ["organization_id", "app_id"],
      additionalProperties: false
    }
  },
  {
    name: "agentpass_publish_prepare",
    description: "Prepare or replay a private Small Software preview; approval and access widening are unavailable.",
    inputSchema: {
      type: "object",
      properties: {
        organization_id: { type: "string", format: "uuid" },
        app_id: { type: "string", format: "uuid" },
        idempotency_key: { type: "string", minLength: 8, maxLength: 256 },
        source_bundle: { type: "object", additionalProperties: true },
        publish_plan: { type: "object", additionalProperties: true }
      },
      required: ["organization_id", "app_id", "idempotency_key", "source_bundle"],
      additionalProperties: false
    }
  },
  {
    name: "agentpass_deployment_status",
    description: "Return the redacted, reconciled deployment state for one tenant-bound app.",
    inputSchema: {
      type: "object",
      properties: { organization_id: { type: "string", format: "uuid" }, app_id: { type: "string", format: "uuid" }, release_id: { type: "string", format: "uuid" } },
      required: ["organization_id", "app_id"],
      additionalProperties: false
    }
  },
  {
    name: "agentpass_apps_list",
    description: "List a bounded set of redacted Small Software apps within one organization.",
    inputSchema: {
      type: "object",
      properties: { organization_id: { type: "string", format: "uuid" }, limit: { type: "integer", minimum: 1, maximum: MAX_APP_LIST_COUNT, default: 20 } },
      required: ["organization_id"],
      additionalProperties: false
    }
  },
  {
    name: "agentpass_app_open",
    description: "Return a protected app or Console URL; local filesystem paths and bearer links are never returned.",
    inputSchema: {
      type: "object",
      properties: { organization_id: { type: "string", format: "uuid" }, app_id: { type: "string", format: "uuid" }, target: { type: "string", enum: ["app", "console"], default: "app" } },
      required: ["organization_id", "app_id"],
      additionalProperties: false
    }
  },
  {
    name: "agentpass_maintenance_status",
    description: "Return bounded, redacted maintenance state for one organization or app.",
    inputSchema: {
      type: "object",
      properties: { organization_id: { type: "string", format: "uuid" }, app_id: { type: "string", format: "uuid" }, limit: { type: "integer", minimum: 1, maximum: MAX_MAINTENANCE_STATUS_COUNT, default: 20 } },
      required: ["organization_id"],
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
  if (name === "agentpass_app_inspect") return validateTenantApp(value, ["organization_id", "app_id"]);
  if (name === "agentpass_publish_prepare") {
    if (!exactKeys(value, ["organization_id", "app_id", "idempotency_key", "source_bundle", "publish_plan"])) throw schemaError("publish_prepare has unknown arguments");
    const base = validateTenantApp(value, ["organization_id", "app_id", "idempotency_key", "source_bundle", "publish_plan"]);
    if (typeof value.idempotency_key !== "string" || !IDEMPOTENCY.test(value.idempotency_key)) throw schemaError("idempotency_key is invalid");
    if (!object(value.source_bundle) || JSON.stringify(value.source_bundle).length > 64 * 1024 || containsSecretKey(value.source_bundle)) throw schemaError("source_bundle is invalid, too large, or contains secret-like data");
    if (value.publish_plan !== undefined && (!object(value.publish_plan) || JSON.stringify(value.publish_plan).length > 64 * 1024 || containsSecretKey(value.publish_plan))) throw schemaError("publish_plan is invalid, too large, or contains secret-like data");
    return { ...base, idempotency_key: value.idempotency_key, source_bundle: value.source_bundle, ...(value.publish_plan === undefined ? {} : { publish_plan: value.publish_plan }) };
  }
  if (name === "agentpass_deployment_status") {
    const result = validateTenantApp(value, ["organization_id", "app_id", "release_id"]);
    if (value.release_id !== undefined && !UUID.test(value.release_id)) throw schemaError("release_id is invalid");
    return result;
  }
  if (name === "agentpass_apps_list") {
    if (!exactKeys(value, ["organization_id", "limit"])) throw schemaError("apps_list has unknown arguments");
    if (!UUID.test(value.organization_id ?? "")) throw schemaError("organization_id is invalid");
    const limit = value.limit ?? 20;
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > MAX_APP_LIST_COUNT) throw schemaError(`limit must be an integer from 1 to ${MAX_APP_LIST_COUNT}`);
    return { organization_id: value.organization_id, limit };
  }
  if (name === "agentpass_app_open") {
    const result = validateTenantApp(value, ["organization_id", "app_id", "target"]);
    const target = value.target ?? "app";
    if (!["app", "console"].includes(target)) throw schemaError("target must be app or console");
    return { ...result, target };
  }
  if (name === "agentpass_maintenance_status") {
    if (!exactKeys(value, ["organization_id", "app_id", "limit"])) throw schemaError("maintenance_status has unknown arguments");
    if (!UUID.test(value.organization_id ?? "")) throw schemaError("organization_id is invalid");
    if (value.app_id !== undefined && !UUID.test(value.app_id)) throw schemaError("app_id is invalid");
    const limit = value.limit ?? 20;
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > MAX_MAINTENANCE_STATUS_COUNT) throw schemaError(`limit must be an integer from 1 to ${MAX_MAINTENANCE_STATUS_COUNT}`);
    return { organization_id: value.organization_id, ...(value.app_id === undefined ? {} : { app_id: value.app_id }), limit };
  }
  if (Object.keys(value).length !== 0) throw schemaError(`${name} accepts no arguments`);
  return {};
}

function validateTenantApp(value, allowed) {
  if (!exactKeys(value, allowed)) throw schemaError("tenant app arguments contain unknown fields");
  if (!UUID.test(value.organization_id ?? "")) throw schemaError("organization_id is invalid");
  if (!UUID.test(value.app_id ?? "")) throw schemaError("app_id is invalid");
  return { organization_id: value.organization_id, app_id: value.app_id };
}

function containsSecretKey(value) {
  if (!value || typeof value !== "object") return false;
  if (Array.isArray(value)) return value.some(containsSecretKey);
  return Object.entries(value).some(([key, child]) => SECRET_KEY.test(key) || containsSecretKey(child));
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
