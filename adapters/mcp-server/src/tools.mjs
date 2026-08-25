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

const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/;
const SAFE_DIGEST = /^[0-9a-f]{64}$/;
const SAFE_TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const SAFE_URL = /^https:\/\/[^\s\0]{1,2048}$/;

function safeId(value) { return typeof value === "string" && SAFE_ID.test(value) ? value : undefined; }
function safeUuid(value) { return typeof value === "string" && /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value) ? value : undefined; }
function safeDigest(value) { return typeof value === "string" && SAFE_DIGEST.test(value) ? value : undefined; }
function safeTime(value) { return typeof value === "string" && SAFE_TIME.test(value) ? value : undefined; }
function safeUrl(value) { return typeof value === "string" && SAFE_URL.test(value) ? value : undefined; }

function requireSurface(surface, method) {
  if (!surface || typeof surface[method] !== "function") {
    const error = new Error("Small Software surface is unavailable");
    error.code = "surface_unavailable";
    throw error;
  }
  return surface[method].bind(surface);
}

async function authorizeSurface(surface, args, operation) {
  if (surface && typeof surface.authorize === "function") {
    const allowed = await surface.authorize({ organization_id: args.organization_id, ...(args.app_id ? { app_id: args.app_id } : {}), operation });
    if (allowed !== true) {
      const error = new Error("Small Software operation is not authorized");
      error.code = "not_authorized";
      throw error;
    }
  }
}

function assertTenant(result, organizationId, appId = undefined) {
  if (!result || typeof result !== "object" || Array.isArray(result)) throw new Error("Small Software returned invalid data");
  if (result.organization_id !== organizationId) throw new Error("Small Software returned a cross-tenant result");
  if (appId !== undefined && result.app_id !== appId) throw new Error("Small Software returned a cross-app result");
}

function lifecycleSummary(raw, organizationId, appId = undefined) {
  assertTenant(raw, organizationId, appId);
  const result = { organization_id: organizationId, ...(appId === undefined ? {} : { app_id: appId }) };
  for (const key of ["state", "status", "next_action", "name", "runtime_provider", "provider_deployment_id", "audience", "risk_classification"]) {
    const value = safeCode(raw[key], 256);
    if (value !== undefined) result[key] = value;
  }
  const route = safeUrl(raw.route);
  if (route !== undefined) result.route = route;
  for (const key of ["release_id", "build_receipt_digest", "publish_plan_digest", "source_bundle_digest", "artifact_digest", "deployment_receipt_digest"]) {
    const value = safeUuid(raw[key]) ?? safeDigest(raw[key]);
    if (value !== undefined) result[key] = value;
  }
  for (const key of ["created_at", "expires_at", "started_at", "finished_at", "observed_at", "updated_at"]) {
    const value = safeTime(raw[key]);
    if (value !== undefined) result[key] = value;
  }
  if (Number.isSafeInteger(raw.active_generation) && raw.active_generation >= 1 && raw.active_generation <= 0x7fffffff) result.active_generation = raw.active_generation;
  if (typeof raw.approval_required === "boolean") result.approval_required = raw.approval_required;
  return result;
}

function publishSummary(raw, args) {
  assertTenant(raw, args.organization_id, args.app_id);
  const result = lifecycleSummary(raw, args.organization_id, args.app_id);
  if (safeId(raw.idempotency_key)) result.idempotency_key = raw.idempotency_key;
  for (const key of ["publish_plan", "deployment_receipt"]) {
    if (raw[key] && typeof raw[key] === "object" && !Array.isArray(raw[key])) result[key] = lifecycleSummary(raw[key], args.organization_id, args.app_id);
  }
  return result;
}

function appListSummary(raw, organizationId) {
  if (!raw || typeof raw !== "object" || Array.isArray(raw) || raw.organization_id !== organizationId || !Array.isArray(raw.apps) || raw.apps.length > 50) throw new Error("Small Software returned invalid app list");
  return {
    organization_id: organizationId,
    apps: raw.apps.map((app) => lifecycleSummary(app, organizationId, app.app_id)).filter((app) => app.app_id !== undefined),
    ...(typeof raw.next_cursor === "string" && raw.next_cursor.length <= 256 && SAFE_ID.test(raw.next_cursor) ? { next_cursor: raw.next_cursor } : {})
  };
}

function openSummary(raw, args) {
  assertTenant(raw, args.organization_id, args.app_id);
  const result = { organization_id: args.organization_id, app_id: args.app_id };
  for (const key of ["url", "app_url", "console_url"]) {
    const value = safeUrl(raw[key]);
    if (value !== undefined) result[key] = value;
  }
  if (Object.keys(result).length === 2) throw new Error("Small Software returned no protected URL");
  return result;
}

function maintenanceSummary(raw, args) {
  assertTenant(raw, args.organization_id, args.app_id);
  const result = lifecycleSummary(raw, args.organization_id, args.app_id);
  if (Array.isArray(raw.jobs) && raw.jobs.length <= 50) result.jobs = raw.jobs.map((job) => lifecycleSummary(job, args.organization_id, args.app_id)).filter((job) => job.state || job.status);
  // Maintenance records may contain provider responses, patch bodies, or
  // repository paths. Expose only the already-projected PR state and digest
  // bound verification outcome; never forward the raw nested objects.
  if (raw.pull_request && typeof raw.pull_request === "object" && !Array.isArray(raw.pull_request)) {
    assertTenant(raw.pull_request, args.organization_id, args.app_id);
    result.pull_request = lifecycleSummary(raw.pull_request, args.organization_id, args.app_id);
    for (const key of ["head_branch", "base_commit", "head_commit", "approval_id", "intent_id", "operation_id", "external_number"]) {
      if (safeId(raw.pull_request[key])) result.pull_request[key] = raw.pull_request[key];
      else if (key === "external_number" && Number.isSafeInteger(raw.pull_request[key]) && raw.pull_request[key] >= 1) result.pull_request[key] = raw.pull_request[key];
    }
    for (const key of ["patch_digest", "result_digest", "check_runs_digest", "request_digest", "response_digest"]) {
      const value = safeDigest(raw.pull_request[key]);
      if (value !== undefined) result.pull_request[key] = value;
    }
    const url = safeUrl(raw.pull_request.url);
    if (url !== undefined) result.pull_request.url = url;
  }
  if (raw.verification && typeof raw.verification === "object" && !Array.isArray(raw.verification)) {
    const verification = {};
    for (const key of ["status", "verification_status"]) if (safeCode(raw.verification[key], 32)) verification[key] = raw.verification[key];
    for (const key of ["result_digest", "patch_digest"]) {
      const value = safeDigest(raw.verification[key]);
      if (value !== undefined) verification[key] = value;
    }
    if (Array.isArray(raw.verification.uncertainty) && raw.verification.uncertainty.length <= 16 && raw.verification.uncertainty.every((value) => safeCode(value, 64))) verification.uncertainty = [...raw.verification.uncertainty];
    if (Object.keys(verification).length > 0) result.verification = verification;
  }
  return result;
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

export function createToolHandler(commandRunner, { smallSoftwareSurface = undefined } = {}) {
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
    if (name === "agentpass_app_inspect") {
      await authorizeSurface(smallSoftwareSurface, args, "app.inspect");
      return lifecycleSummary(await requireSurface(smallSoftwareSurface, "inspectApp")(args), args.organization_id, args.app_id);
    }
    if (name === "agentpass_publish_prepare") {
      await authorizeSurface(smallSoftwareSurface, args, "app.preview.prepare");
      return publishSummary(await requireSurface(smallSoftwareSurface, "preparePublish")(args), args);
    }
    if (name === "agentpass_deployment_status") {
      await authorizeSurface(smallSoftwareSurface, args, "app.deployment.status");
      return lifecycleSummary(await requireSurface(smallSoftwareSurface, "deploymentStatus")(args), args.organization_id, args.app_id);
    }
    if (name === "agentpass_apps_list") {
      await authorizeSurface(smallSoftwareSurface, args, "app.list");
      return appListSummary(await requireSurface(smallSoftwareSurface, "listApps")(args), args.organization_id);
    }
    if (name === "agentpass_app_open") {
      await authorizeSurface(smallSoftwareSurface, args, "app.open");
      return openSummary(await requireSurface(smallSoftwareSurface, "openApp")(args), args);
    }
    if (name === "agentpass_maintenance_status") {
      await authorizeSurface(smallSoftwareSurface, args, "maintenance.status");
      return maintenanceSummary(await requireSurface(smallSoftwareSurface, "maintenanceStatus")(args), args);
    }
    const result = await commandRunner(["audit", "--tail", String(args.count)]);
    if (result.code !== 0) throw new CliRunnerError("audit failed");
    return redactedAuditTail(result.stdout, args.count);
  };
}

export function safeToolError(error) {
  if (error instanceof CliRunnerError) return "AgentPass command failed";
  if (error instanceof Error && /invalid (?:status|check|audit) data|Small Software returned|Small Software operation|surface is unavailable|Tool arguments|accepts only|must be|Unknown tool/.test(error.message)) return error.message;
  return "AgentPass tool failed";
}
