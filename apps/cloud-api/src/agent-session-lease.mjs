export const AGENT_SESSION_LEASE_VERSION = 1;
export const AGENT_SESSION_LEASE_TYPE = "agentpass.agent-session-lease";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const SHA256 = /^[0-9a-f]{64}$/u;
const SEMVER = /^(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/u;
const TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u;
const KEYS = Object.freeze([
  "version", "type", "session_id", "grant_id", "organization_id", "device_id", "agent_id",
  "agent_kind", "adapter_id", "adapter_version", "process_binding_sha256", "ancestry_binding_sha256",
  "worktree_binding_sha256", "max_signatures", "used_signatures", "not_before", "expires_at", "control_sequence", "authority_generation"
]);

export class AgentSessionLeaseError extends TypeError {
  constructor() {
    super("agent session lease is invalid");
    this.name = "AgentSessionLeaseError";
    this.code = "ERR_AGENT_SESSION_LEASE_INVALID";
  }
}

export function normalizeAgentSessionLease(input, { expectedGrant, processBindingSha256, ancestryBindingSha256, now, allowExpired = true } = {}) {
  try {
    exactObject(input);
    const lease = {
      version: exact(input.version, AGENT_SESSION_LEASE_VERSION),
      type: exact(input.type, AGENT_SESSION_LEASE_TYPE),
      session_id: pattern(input.session_id, UUID),
      grant_id: pattern(input.grant_id, UUID),
      organization_id: pattern(input.organization_id, UUID),
      device_id: pattern(input.device_id, UUID),
      agent_id: pattern(input.agent_id, UUID),
      agent_kind: enumeration(input.agent_kind, ["claude-code", "cursor"]),
      adapter_id: pattern(input.adapter_id, UUID),
      adapter_version: pattern(input.adapter_version, SEMVER),
      process_binding_sha256: pattern(input.process_binding_sha256, SHA256),
      ancestry_binding_sha256: pattern(input.ancestry_binding_sha256, SHA256),
      worktree_binding_sha256: pattern(input.worktree_binding_sha256, SHA256),
      max_signatures: integer(input.max_signatures, 1, 64),
      used_signatures: integer(input.used_signatures, 0, 64),
      not_before: timestamp(input.not_before),
      expires_at: timestamp(input.expires_at),
      control_sequence: integer(input.control_sequence, 1, Number.MAX_SAFE_INTEGER),
      authority_generation: integer(input.authority_generation, 1, Number.MAX_SAFE_INTEGER)
    };
    if (lease.used_signatures > lease.max_signatures || Date.parse(lease.expires_at) <= Date.parse(lease.not_before)) fail();
    if (now !== undefined && !allowExpired && exactNow(now) >= Date.parse(lease.expires_at)) fail();
    if (processBindingSha256 !== undefined && lease.process_binding_sha256 !== pattern(processBindingSha256, SHA256)) fail();
    if (ancestryBindingSha256 !== undefined && lease.ancestry_binding_sha256 !== pattern(ancestryBindingSha256, SHA256)) fail();
    if (expectedGrant !== undefined) bindGrant(lease, expectedGrant?.statement ?? expectedGrant);
    return deepFreeze(lease);
  } catch (error) {
    if (error instanceof AgentSessionLeaseError) throw error;
    throw new AgentSessionLeaseError();
  }
}

export function agentSessionLeaseFromRow(row) {
  if (!row || typeof row !== "object" || Array.isArray(row)) fail();
  return normalizeAgentSessionLease({
    version: 1,
    type: AGENT_SESSION_LEASE_TYPE,
    session_id: row.session_id,
    grant_id: row.grant_id,
    organization_id: row.organization_id,
    device_id: row.device_id,
    agent_id: row.agent_id,
    agent_kind: row.agent_kind,
    adapter_id: row.adapter_id,
    adapter_version: row.adapter_version,
    process_binding_sha256: row.process_binding_sha256,
    ancestry_binding_sha256: row.ancestry_binding_sha256,
    worktree_binding_sha256: row.worktree_binding_sha256,
    max_signatures: numeric(row.max_signatures),
    used_signatures: numeric(row.used_signatures),
    not_before: databaseTimestamp(row.not_before ?? row.created_at),
    expires_at: databaseTimestamp(row.expires_at),
    control_sequence: numeric(row.control_sequence),
    authority_generation: numeric(row.authority_generation)
  });
}

function bindGrant(lease, statement) {
  if (!statement || typeof statement !== "object" || Array.isArray(statement)) fail();
  const bindings = [
    ["grant_id", "grant_id"], ["organization_id", "organization_id"], ["device_id", "device_id"],
    ["agent_id", "agent_id"], ["agent_kind", "agent_kind"], ["adapter_id", "adapter_id"],
    ["adapter_version", "adapter_version"], ["worktree_binding_sha256", "worktree_binding_sha256"],
    ["max_signatures", "max_signatures"], ["not_before", "not_before"], ["expires_at", "expires_at"],
    ["control_sequence", "control_sequence"], ["authority_generation", "authority_generation"]
  ];
  for (const [leaseKey, statementKey] of bindings) if (lease[leaseKey] !== statement[statementKey]) fail();
}
function exactObject(value) { if (!value || typeof value !== "object" || Array.isArray(value) || (Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null) || Reflect.ownKeys(value).some((key) => typeof key !== "string") || Object.keys(value).length !== KEYS.length || Object.keys(value).some((key) => !KEYS.includes(key))) fail(); }
function exact(value, expected) { if (value !== expected) fail(); return expected; }
function pattern(value, expression) { if (typeof value !== "string" || !expression.test(value)) fail(); return value; }
function enumeration(value, allowed) { if (!allowed.includes(value)) fail(); return value; }
function integer(value, min, max) { if (!Number.isSafeInteger(value) || value < min || value > max) fail(); return value; }
function numeric(value) { const output = typeof value === "string" && /^(?:0|[1-9][0-9]*)$/u.test(value) ? Number(value) : value; if (!Number.isSafeInteger(output)) fail(); return output; }
function timestamp(value) { if (typeof value !== "string" || !TIMESTAMP.test(value) || new Date(value).toISOString() !== value) fail(); return value; }
function databaseTimestamp(value) { const date = value instanceof Date ? value : new Date(value); if (!Number.isFinite(date.getTime())) fail(); return date.toISOString(); }
function exactNow(value) { const output = value instanceof Date ? value.getTime() : value; if (!Number.isSafeInteger(output) || output < 0) fail(); return output; }
function deepFreeze(value) { Object.freeze(value); for (const nested of Object.values(value)) if (nested && typeof nested === "object") deepFreeze(nested); return value; }
function fail() { throw new AgentSessionLeaseError(); }
