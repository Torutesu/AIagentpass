import path from "node:path";

const PROTOCOL_VERSION = 1;

const ALLOWED_AGENT_KINDS = Object.freeze([
  "claude-code",
  "cursor",
  "mcp",
  "cli",
  "custom"
]);

// v1 intentionally exposes only the operation described by the platform contract.
const ALLOWED_OPERATIONS = Object.freeze(["git.commit.sign"]);

const DECISION_REASONS = Object.freeze([
  "allowed",
  "branch_denied",
  "branch_not_allowed",
  "capability_expired",
  "capability_missing",
  "operation_not_allowed",
  "policy_changed",
  "remote_control_stale",
  "remote_denied",
  "remote_not_allowed",
  "repository_not_allowed",
  "revoked",
  "session_required",
  "signer_failed",
  "tag_denied",
  "tag_not_allowed"
]);

const AUDIT_DECISIONS = Object.freeze(["allow", "deny", "error"]);

const LIMITS = Object.freeze({
  maxDocumentBytes: 16 * 1024,
  maxStringBytes: 4096,
  maxNameBytes: 128,
  maxPublicKeyBytes: 8192,
  maxReasonBytes: 128,
  maxArrayItems: 64,
  maxPatternBytes: 2048,
  maxRepositoryBytes: 4096,
  maxNonceBytes: 128
});

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const SHA256_PATTERN = /^[0-9a-f]{64}$/;
const NONCE_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$/;
const RFC3339_UTC_PATTERN =
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/;
const CONTROL_CHARACTER_PATTERN = /[\u0000-\u001f\u007f]/;

export { ALLOWED_AGENT_KINDS, ALLOWED_OPERATIONS, AUDIT_DECISIONS, DECISION_REASONS, LIMITS, PROTOCOL_VERSION };

// Short aliases make the protocol constants convenient for adapters while retaining
// the explicit names used by the architecture document.
export const AGENT_KINDS = ALLOWED_AGENT_KINDS;
export const OPERATIONS = ALLOWED_OPERATIONS;
export const PROTOCOL_V1 = PROTOCOL_VERSION;

export class ProtocolValidationError extends TypeError {
  constructor(issues) {
    const normalizedIssues = issues.map((issue) => Object.freeze({
      path: issue.path,
      code: issue.code,
      message: issue.message
    }));
    super(normalizedIssues.map((issue) => `${issue.code} at ${issue.path}: ${issue.message}`).join("; "));
    this.name = "ProtocolValidationError";
    this.code = "ERR_PROTOCOL_VALIDATION";
    this.issues = Object.freeze(normalizedIssues);
  }
}

export function canonicalJson(value) {
  const seen = new Set();
  return canonicalizeValue(value, seen, "$", false);
}

export const canonicalize = canonicalJson;

export function normalizeAgentDescriptor(input) {
  const object = asObject(input, "agent");
  const issues = [];
  exactKeys(object, ["version", "agent_id", "name", "kind", "public_key", "created_at"], "agent", issues);
  const publicKey = stringValue(object.public_key, "agent.public_key", { maxBytes: LIMITS.maxPublicKeyBytes, nonEmpty: true, allowNewlines: true }, issues);
  if (publicKey !== undefined && /PRIVATE KEY/.test(publicKey)) {
    issues.push(issue("agent.public_key", "invalid_public_key", "private key material is not allowed"));
  }
  const value = {
    version: protocolVersion(object.version, "agent.version", issues),
    agent_id: uuid(object.agent_id, "agent.agent_id", issues),
    name: stringValue(object.name, "agent.name", { maxBytes: LIMITS.maxNameBytes, nonEmpty: true }, issues),
    kind: enumValue(object.kind, "agent.kind", ALLOWED_AGENT_KINDS, issues),
    public_key: publicKey,
    created_at: timestamp(object.created_at, "agent.created_at", issues)
  };
  return finish(value, issues, "agent");
}

export function normalizeScope(input) {
  const object = asObject(input, "scope");
  const issues = [];
  exactKeys(object, ["operations", "repositories", "branches", "remotes", "tags"], "scope", issues);
  const value = {
    operations: stringArray(object.operations, "scope.operations", {
      maxBytes: LIMITS.maxPatternBytes,
      nonEmpty: true,
      values: ALLOWED_OPERATIONS
    }, issues),
    repositories: stringArray(object.repositories, "scope.repositories", {
      maxBytes: LIMITS.maxRepositoryBytes,
      nonEmpty: true,
      absolutePath: true
    }, issues),
    branches: normalizePatternSet(object.branches, "scope.branches", issues, true),
    remotes: normalizePatternSet(object.remotes, "scope.remotes", issues, true),
    tags: object.tags === undefined ? undefined : normalizePatternSet(object.tags, "scope.tags", issues, false)
  };
  if (value.tags === undefined) delete value.tags;
  return finish(value, issues, "scope");
}

export function normalizeOperationRequest(input) {
  const object = asObject(input, "request");
  const issues = [];
  exactKeys(object, [
    "version",
    "request_id",
    "agent_id",
    "operation",
    "nonce",
    "requested_at",
    "repository",
    "branch",
    "remote",
    "payload_digest"
  ], "request", issues);
  const value = {
    version: protocolVersion(object.version, "request.version", issues),
    request_id: uuid(object.request_id, "request.request_id", issues),
    agent_id: uuid(object.agent_id, "request.agent_id", issues),
    operation: enumValue(object.operation, "request.operation", ALLOWED_OPERATIONS, issues),
    nonce: nonce(object.nonce, "request.nonce", issues),
    requested_at: timestamp(object.requested_at, "request.requested_at", issues),
    repository: stringValue(object.repository, "request.repository", {
      maxBytes: LIMITS.maxRepositoryBytes,
      nonEmpty: true,
      absolutePath: true
    }, issues),
    branch: stringValue(object.branch, "request.branch", { maxBytes: LIMITS.maxPatternBytes, nonEmpty: true }, issues),
    remote: stringValue(object.remote, "request.remote", { maxBytes: LIMITS.maxPatternBytes, nonEmpty: true }, issues),
    payload_digest: sha256(object.payload_digest, "request.payload_digest", issues)
  };
  return finish(value, issues, "request");
}

export function normalizeDecision(input) {
  const object = asObject(input, "decision");
  const issues = [];
  exactKeys(object, ["version", "allowed", "reason", "operation", "request_id", "evaluated_at"], "decision", issues);
  const value = {
    version: protocolVersion(object.version, "decision.version", issues),
    allowed: booleanValue(object.allowed, "decision.allowed", issues),
    reason: enumValue(object.reason, "decision.reason", DECISION_REASONS, issues),
    operation: enumValue(object.operation, "decision.operation", ALLOWED_OPERATIONS, issues),
    request_id: uuid(object.request_id, "decision.request_id", issues),
    evaluated_at: timestamp(object.evaluated_at, "decision.evaluated_at", issues)
  };
  if (value.allowed === true && value.reason !== undefined && value.reason !== "allowed") {
    issues.push(issue("decision.reason", "inconsistent_value", "allowed decisions must use reason allowed"));
  }
  if (value.allowed === false && value.reason === "allowed") {
    issues.push(issue("decision.reason", "inconsistent_value", "denied decisions cannot use reason allowed"));
  }
  return finish(value, issues, "decision");
}

export function normalizeAuditEvent(input) {
  const object = asObject(input, "audit");
  const issues = [];
  exactKeys(object, [
    "version",
    "event_id",
    "request_id",
    "agent_id",
    "operation",
    "decision",
    "reason",
    "policy_sequence",
    "capability_sequence",
    "repository",
    "branch",
    "remote",
    "payload_digest",
    "device_timestamp",
    "previous_hash",
    "event_hash"
  ], "audit", issues);
  const value = {
    version: protocolVersion(object.version, "audit.version", issues),
    event_id: uuid(object.event_id, "audit.event_id", issues),
    request_id: uuid(object.request_id, "audit.request_id", issues),
    agent_id: uuid(object.agent_id, "audit.agent_id", issues),
    operation: enumValue(object.operation, "audit.operation", ALLOWED_OPERATIONS, issues),
    decision: enumValue(object.decision, "audit.decision", AUDIT_DECISIONS, issues),
    reason: enumValue(object.reason, "audit.reason", DECISION_REASONS, issues),
    policy_sequence: sequence(object.policy_sequence, "audit.policy_sequence", issues),
    capability_sequence: sequence(object.capability_sequence, "audit.capability_sequence", issues),
    repository: stringValue(object.repository, "audit.repository", {
      maxBytes: LIMITS.maxRepositoryBytes,
      nonEmpty: true,
      absolutePath: true
    }, issues),
    branch: stringValue(object.branch, "audit.branch", { maxBytes: LIMITS.maxPatternBytes, nonEmpty: true }, issues),
    remote: stringValue(object.remote, "audit.remote", { maxBytes: LIMITS.maxPatternBytes, nonEmpty: true }, issues),
    payload_digest: sha256(object.payload_digest, "audit.payload_digest", issues),
    device_timestamp: timestamp(object.device_timestamp, "audit.device_timestamp", issues),
    previous_hash: sha256(object.previous_hash, "audit.previous_hash", issues),
    event_hash: sha256(object.event_hash, "audit.event_hash", issues)
  };
  if (value.decision === "allow" && value.reason !== undefined && value.reason !== "allowed") {
    issues.push(issue("audit.reason", "inconsistent_value", "allow audit events must use reason allowed"));
  }
  if (value.decision !== undefined && value.decision !== "allow" && value.reason === "allowed") {
    issues.push(issue("audit.reason", "inconsistent_value", "non-allow audit events cannot use reason allowed"));
  }
  return finish(value, issues, "audit");
}

export function validateAgentDescriptor(input) { return normalizeAgentDescriptor(input); }
export function validateScope(input) { return normalizeScope(input); }
export function validateOperationRequest(input) { return normalizeOperationRequest(input); }
export function validateDecision(input) { return normalizeDecision(input); }
export function validateAuditEvent(input) { return normalizeAuditEvent(input); }

export function isValidAgentDescriptor(input) { return valid(normalizeAgentDescriptor, input); }
export function isValidScope(input) { return valid(normalizeScope, input); }
export function isValidOperationRequest(input) { return valid(normalizeOperationRequest, input); }
export function isValidDecision(input) { return valid(normalizeDecision, input); }
export function isValidAuditEvent(input) { return valid(normalizeAuditEvent, input); }

function normalizePatternSet(input, path, issues, required) {
  const object = input === undefined && !required ? {} : asObject(input, path);
  exactKeys(object, ["allow", "deny"], path, issues);
  const value = {
    allow: stringArray(object.allow, `${path}.allow`, {
      maxBytes: LIMITS.maxPatternBytes,
      nonEmpty: required,
      allowEmpty: !required
    }, issues),
    deny: stringArray(object.deny, `${path}.deny`, {
      maxBytes: LIMITS.maxPatternBytes,
      allowEmpty: true
    }, issues)
  };
  return value;
}

function finish(value, issues, label) {
  if (issues.length) throw new ProtocolValidationError(issues);
  const normalized = stripUndefined(value);
  const encoded = canonicalJson(normalized);
  if (Buffer.byteLength(encoded, "utf8") > LIMITS.maxDocumentBytes) {
    throw new ProtocolValidationError([issue(label, "limit_exceeded", `canonical document exceeds ${LIMITS.maxDocumentBytes} bytes`)]);
  }
  return deepFreeze(normalized);
}

function asObject(value, path) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new ProtocolValidationError([issue(path, "invalid_type", "expected a JSON object")]);
  }
  if (Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null) {
    throw new ProtocolValidationError([issue(path, "invalid_type", "expected a plain JSON object")]);
  }
  return value;
}

function exactKeys(object, allowed, path, issues) {
  const allowedSet = new Set(allowed);
  for (const key of Reflect.ownKeys(object)) {
    if (typeof key !== "string" || !allowedSet.has(key)) {
      issues.push(issue(`${path}.${typeof key === "string" ? key : "<symbol>"}`, "unknown_field", "field is not allowed"));
    }
  }
}

function protocolVersion(value, path, issues) {
  if (value !== PROTOCOL_VERSION) {
    issues.push(issue(path, "invalid_version", `expected protocol version ${PROTOCOL_VERSION}`));
    return undefined;
  }
  return PROTOCOL_VERSION;
}

function uuid(value, path, issues) {
  if (typeof value !== "string") {
    issues.push(issue(path, "invalid_type", "expected a UUID string"));
    return undefined;
  }
  if (!UUID_PATTERN.test(value)) {
    issues.push(issue(path, "invalid_uuid", "expected a canonical RFC 4122 UUID"));
    return undefined;
  }
  return value.toLowerCase();
}

function nonce(value, path, issues) {
  const result = stringValue(value, path, { maxBytes: LIMITS.maxNonceBytes, nonEmpty: true }, issues);
  if (result !== undefined && !NONCE_PATTERN.test(result)) {
    issues.push(issue(path, "invalid_nonce", "expected a bounded token using letters, digits, or . _ : -"));
  }
  return result;
}

function timestamp(value, path, issues) {
  if (typeof value !== "string") {
    issues.push(issue(path, "invalid_type", "expected an RFC 3339 UTC string"));
    return undefined;
  }
  if (!RFC3339_UTC_PATTERN.test(value)) {
    issues.push(issue(path, "invalid_timestamp", "expected an RFC 3339 UTC timestamp ending in Z"));
    return undefined;
  }
  const date = new Date(value);
  if (!Number.isFinite(date.getTime())) {
    issues.push(issue(path, "invalid_timestamp", "timestamp is not a real date"));
    return undefined;
  }
  return date.toISOString();
}

function sha256(value, path, issues) {
  if (typeof value !== "string") {
    issues.push(issue(path, "invalid_type", "expected a lowercase SHA-256 hex digest"));
    return undefined;
  }
  if (!SHA256_PATTERN.test(value)) {
    issues.push(issue(path, "invalid_digest", "expected exactly 64 lowercase hexadecimal characters"));
    return undefined;
  }
  return value;
}

function sequence(value, path, issues) {
  if (!Number.isSafeInteger(value) || value < 0) {
    issues.push(issue(path, "invalid_sequence", "expected a non-negative safe integer"));
    return undefined;
  }
  return value;
}

function booleanValue(value, path, issues) {
  if (typeof value !== "boolean") {
    issues.push(issue(path, "invalid_type", "expected a boolean"));
    return undefined;
  }
  return value;
}

function enumValue(value, path, allowed, issues) {
  if (typeof value !== "string") {
    issues.push(issue(path, "invalid_type", `expected one of ${allowed.join(", ")}`));
    return undefined;
  }
  if (!allowed.includes(value)) {
    issues.push(issue(path, "invalid_value", `expected one of ${allowed.join(", ")}`));
    return undefined;
  }
  return value;
}

function stringArray(value, path, options, issues) {
  if (!Array.isArray(value)) {
    if (options.allowEmpty && value === undefined) return [];
    issues.push(issue(path, "invalid_type", "expected an array of strings"));
    return [];
  }
  if (value.length > LIMITS.maxArrayItems) {
    issues.push(issue(path, "limit_exceeded", `array cannot contain more than ${LIMITS.maxArrayItems} items`));
  }
  if (options.nonEmpty && value.length === 0) {
    issues.push(issue(path, "empty_value", "array must contain at least one item"));
  }
  const result = [];
  for (let index = 0; index < value.length; index += 1) {
    const item = stringValue(value[index], `${path}[${index}]`, {
      maxBytes: options.maxBytes,
      nonEmpty: true,
      absolutePath: options.absolutePath
    }, issues);
    if (item !== undefined && options.values && !options.values.includes(item)) {
      issues.push(issue(`${path}[${index}]`, "invalid_value", `expected one of ${options.values.join(", ")}`));
    }
    if (item !== undefined) result.push(item);
  }
  return result;
}

function stringValue(value, path, options, issues) {
  if (typeof value !== "string") {
    issues.push(issue(path, "invalid_type", "expected a string"));
    return undefined;
  }
  const bytes = Buffer.byteLength(value, "utf8");
  if (bytes > options.maxBytes) {
    issues.push(issue(path, "limit_exceeded", `string cannot exceed ${options.maxBytes} UTF-8 bytes`));
  }
  if (options.nonEmpty && value.length === 0) {
    issues.push(issue(path, "empty_value", "string must not be empty"));
  }
  const controls = options.allowNewlines ? value.replace(/[\r\n]/g, "") : value;
  if (CONTROL_CHARACTER_PATTERN.test(controls)) {
    issues.push(issue(path, "unsafe_string", "control characters are not allowed"));
  }
  if (options.absolutePath && (!value.startsWith("/") || value.split("/").some((segment) => segment === "." || segment === "..") || pathModuleNormalize(value) !== value)) {
    issues.push(issue(path, "invalid_path", "repository paths must be absolute and canonical"));
  }
  return value;
}

function pathModuleNormalize(value) { return path.posix.normalize(value); }

function issue(path, code, message) {
  return { path, code, message };
}

function stripUndefined(value) {
  if (Array.isArray(value)) return value.map(stripUndefined);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value)
      .filter(([, item]) => item !== undefined)
      .map(([key, item]) => [key, stripUndefined(item)]));
  }
  return value;
}

function deepFreeze(value) {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    for (const item of Object.values(value)) deepFreeze(item);
    Object.freeze(value);
  }
  return value;
}

function valid(normalizer, value) {
  try {
    normalizer(value);
    return true;
  } catch (error) {
    if (error instanceof ProtocolValidationError) return false;
    throw error;
  }
}

function canonicalizeValue(value, seen, path, inArray) {
  if (value === null) return "null";
  if (typeof value === "string" || typeof value === "boolean") return JSON.stringify(value);
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw canonicalError(path, "non-finite numbers are not valid JSON");
    return JSON.stringify(value);
  }
  if (typeof value !== "object") throw canonicalError(path, "value is not JSON-serializable");
  if (seen.has(value)) throw canonicalError(path, "cyclic values are not valid JSON");
  seen.add(value);
  let result;
  if (Array.isArray(value)) {
    for (let index = 0; index < value.length; index += 1) {
      if (!Object.hasOwn(value, index)) throw canonicalError(`${path}[${index}]`, "sparse arrays are not valid JSON");
    }
    const keys = Reflect.ownKeys(value);
    if (keys.some((key) => typeof key !== "string" || (key !== "length" && !/^\d+$/.test(key)))) {
      throw canonicalError(path, "arrays may not have symbol or extra properties");
    }
    result = `[${value.map((item, index) => canonicalizeValue(item, seen, `${path}[${index}]`, true)).join(",")}]`;
  } else {
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) throw canonicalError(path, "only plain objects are valid JSON");
    const keys = Reflect.ownKeys(value);
    if (keys.some((key) => typeof key !== "string")) throw canonicalError(path, "symbol keys are not valid JSON");
    result = `{${keys.sort().map((key) => `${JSON.stringify(key)}:${canonicalizeValue(value[key], seen, `${path}.${key}`, false)}`).join(",")}}`;
  }
  seen.delete(value);
  return result;
}

function canonicalError(path, message) {
  return new ProtocolValidationError([issue(path, "invalid_json", message)]);
}
