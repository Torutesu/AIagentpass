import { createCliRunner } from "./cli-runner.mjs";
import { isObject, TOOLS, validateInitializeParams } from "./schemas.mjs";
import { createToolHandler, safeToolError } from "./tools.mjs";

export const SERVER_INFO = { name: "agentpass-mcp", version: "0.1.0" };
export const SUPPORTED_PROTOCOL_VERSIONS = ["2025-06-18", "2025-03-26", "2024-11-05"];

function isRequestId(id) {
  return id === null || typeof id === "string" || (typeof id === "number" && Number.isFinite(id));
}

function response(id, result) {
  return { jsonrpc: "2.0", id, result };
}

function errorResponse(id, code, message) {
  return { jsonrpc: "2.0", id, error: { code, message } };
}

function selectProtocolVersion(requested) {
  return SUPPORTED_PROTOCOL_VERSIONS.includes(requested) ? requested : SUPPORTED_PROTOCOL_VERSIONS[0];
}

export function createMcpServer({ commandRunner = createCliRunner(), smallSoftwareSurface = undefined } = {}) {
  const callTool = createToolHandler(commandRunner, { smallSoftwareSurface });
  let initialized = false;
  let negotiated = false;

  async function handle(message) {
    if (!isObject(message) || message.jsonrpc !== "2.0" || typeof message.method !== "string" || ("id" in message && !isRequestId(message.id))) {
      const invalidId = isObject(message) && "id" in message ? message.id : null;
      return errorResponse(invalidId, -32600, "Invalid Request");
    }
    const hasId = "id" in message;
    const id = hasId ? message.id : null;
    const params = message.params;
    try {
      if (message.method === "initialize") {
        if (!hasId) return null;
        validateInitializeParams(params);
        negotiated = true;
        return response(id, {
          protocolVersion: selectProtocolVersion(params.protocolVersion),
          capabilities: { tools: { listChanged: false } },
          serverInfo: SERVER_INFO,
          instructions: "AgentPass exposes policy/status tools only; signing remains Git-native."
        });
      }
      if (message.method === "notifications/initialized") {
        initialized = true;
        return null;
      }
      if (message.method === "tools/list") {
        if (!hasId) return null;
        if (!negotiated) return errorResponse(id, -32002, "Server is not initialized");
        if (params !== undefined && (!isObject(params) || Object.keys(params).length)) {
          const error = new Error("tools/list accepts no parameters");
          error.code = "invalid_params";
          throw error;
        }
        return response(id, { tools: TOOLS });
      }
      if (message.method === "ping") {
        if (!hasId) return null;
        return response(id, {});
      }
      if (message.method === "tools/call") {
        if (!hasId) return null;
        if (!negotiated || !initialized) return errorResponse(id, -32002, "Server is not initialized");
        if (!isObject(params) || typeof params.name !== "string" || !Object.keys(params).every((key) => ["name", "arguments"].includes(key))) {
          const error = new Error("tools/call requires name and optional arguments");
          error.code = "invalid_params";
          throw error;
        }
        const result = await callTool(params.name, params.arguments === undefined ? {} : params.arguments);
        return response(id, { content: [{ type: "text", text: JSON.stringify(result) }] });
      }
      if (message.method.startsWith("notifications/")) return null;
      if (!hasId) return null;
      return errorResponse(id, -32601, "Method not found");
    } catch (error) {
      if (!hasId) return null;
      if (error?.code === "invalid_params") return errorResponse(id, -32602, error.message);
      if (message.method === "tools/call" && !(error?.message === "tools/call requires name and optional arguments")) {
        return response(id, { isError: true, content: [{ type: "text", text: safeToolError(error) }] });
      }
      const code = error?.message?.startsWith("tools/") || error?.message?.includes("requires") || error?.message?.includes("accepts") ? -32602 : -32603;
      return errorResponse(id, code, code === -32602 ? error.message : "Internal error");
    }
  }

  return { handle };
}

export async function runStdio({ input = process.stdin, output = process.stdout, server = createMcpServer() } = {}) {
  let buffer = "";
  for await (const chunk of input) {
    buffer += chunk.toString();
    if (buffer.length > 4 * 1024 * 1024) throw new Error("MCP input exceeded the limit");
    let newline;
    while ((newline = buffer.indexOf("\n")) >= 0) {
      const line = buffer.slice(0, newline).trim();
      buffer = buffer.slice(newline + 1);
      if (!line) continue;
      let message;
      try { message = JSON.parse(line); }
      catch { output.write(`${JSON.stringify(errorResponse(null, -32700, "Parse error"))}\n`); continue; }
      const result = await server.handle(message);
      if (result) output.write(`${JSON.stringify(result)}\n`);
    }
  }
  if (buffer.trim()) output.write(`${JSON.stringify(errorResponse(null, -32700, "Parse error"))}\n`);
}
