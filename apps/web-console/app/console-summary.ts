export type ConsoleTone = "green" | "amber" | "red";
export type ConsoleSummaryStatus = "pending" | "active" | "revoked" | "disabled";
export type ConsoleAgentKind = "claude-code" | "cursor" | "mcp" | "cli" | "custom";
export type ConsoleRefreshState = "pending" | "fetching" | "applied" | "blocked" | "stale" | "offline" | "revoked";
export type ConsoleDecision = "allow" | "deny" | "error";

export type ConsolePolicyScope = Readonly<{
  operations: readonly string[];
  repositories: readonly string[];
  branches: Readonly<{ allow: readonly string[]; deny: readonly string[] }>;
  remotes: Readonly<{ allow: readonly string[]; deny: readonly string[] }>;
  tags: Readonly<{ allow: readonly string[]; deny: readonly string[] }> | null;
}>;

export type ConsoleSummaryViewModel = Readonly<{
  organization: Readonly<{
    id: string;
    name: string;
    slug: string;
    createdAt: string;
    version: number;
  }>;
  devices: ReadonlyArray<Readonly<{
    id: string;
    name: string;
    status: "pending" | "active" | "revoked";
    tone: ConsoleTone;
    createdAt: string | null;
    lastSeenAt: string | null;
    version: number | null;
    desiredGeneration: number | null;
    observedGeneration: number | null;
    refreshState: ConsoleRefreshState | null;
    bundleSequence: number | null;
    bundleExpiresAt: string | null;
    lastAckAt: string | null;
    blockedReason: string | null;
  }>>;
  agents: ReadonlyArray<Readonly<{
    id: string;
    name: string;
    kind: ConsoleAgentKind;
    status: "active" | "revoked";
    tone: ConsoleTone;
    deviceId: string | null;
    createdAt: string;
    version: number;
  }>>;
  policies: ReadonlyArray<Readonly<{
    id: string;
    name: string;
    status: "active" | "disabled";
    tone: ConsoleTone;
    scope: ConsolePolicyScope;
    sequence: number;
    version: number;
    createdAt: string;
    updatedAt: string;
  }>>;
  audit: Readonly<{
    health: ReadonlyArray<Readonly<{
      deviceId: string;
      chainStatus: "continuous" | "gap" | "unknown";
      tone: ConsoleTone;
      gapCount: number;
      eventCount: number;
      lastEventId: string | null;
    }>>;
    activity: ReadonlyArray<Readonly<{
      eventId: string;
      deviceId: string;
      agentId: string | null;
      operation: string | null;
      decision: ConsoleDecision | null;
      tone: ConsoleTone | null;
      reason: string | null;
      deviceTimestamp: string;
      receivedAt: string | null;
    }>>;
    nextCursor: string | null;
  }>;
}>;

export type ConsoleSummaryParseOptions = Readonly<{
  organizationId?: string;
}>;

export class ConsoleSummaryParseError extends TypeError {
  readonly code = "ERR_CONSOLE_SUMMARY_PARSE" as const;
  readonly path: string;
  readonly reason: string;

  constructor(path: string, reason: string) {
    super(`Invalid console summary at ${path}: ${reason}`);
    this.name = "ConsoleSummaryParseError";
    this.path = path;
    this.reason = reason;
  }
}

const MAX_RECORDS = 500;
const MAX_ACTIVITY_RECORDS = 500;
const MAX_TEXT = 4_096;
const MAX_NAME = 128;
const MAX_SCOPE_ITEMS = 64;
const MAX_CURSOR = 512;
const MAX_ID = 128;
const RFC3339_UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/u;
const ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;
const SHA256 = /^[0-9a-f]{64}$/u;
const CURSOR = /^[A-Za-z0-9_-]{1,512}\.[A-Za-z0-9_-]{1,512}\.[A-Za-z0-9_-]{1,512}$/u;
const PUBLIC_KEY_PEM = /^-----BEGIN PUBLIC KEY-----\r?\n[A-Za-z0-9+/=\r\n]+\r?\n-----END PUBLIC KEY-----$/u;
const SECRET_VALUE = /(?:-----BEGIN(?: [A-Z]+)? PRIVATE KEY-----|\b(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]+|\b(?:api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret|password)\s*[:=]|https?:\/\/[^\s/@:]+:[^\s/@]+@)/iu;
const SENSITIVE_FIELD = /(?:authorization|bearer|cookie|credential|password|private[_-]?key|refresh[_-]?token|secret|session[_-]?token|access[_-]?token|api[_-]?token)/iu;

const DEVICE_STATUSES = new Set(["pending", "active", "revoked"] as const);
const AGENT_STATUSES = new Set(["active", "revoked"] as const);
const POLICY_STATUSES = new Set(["active", "disabled"] as const);
const AGENT_KINDS = new Set(["claude-code", "cursor", "mcp", "cli", "custom"] as const);
const REFRESH_STATES = new Set(["pending", "fetching", "applied", "blocked", "stale", "offline", "revoked"] as const);
const DECISIONS = new Set(["allow", "deny", "error"] as const);
const OPERATIONS = new Set(["git.commit.sign"]);
const CHAIN_STATUSES = new Set(["continuous", "gap", "unknown"] as const);
const AUDIT_EVENT_KEYS = new Set([
  "version", "event_id", "request_id", "agent_id", "operation", "decision", "reason",
  "policy_sequence", "capability_sequence", "repository", "branch", "remote", "payload_digest",
  "device_timestamp", "previous_hash", "event_hash",
]);

/**
 * Parse the closed `/api/console?resource=summary` response into data that is
 * safe to hand to a browser view. The parser deliberately does not provide a
 * fallback model: an unavailable or changed server contract is an error.
 */
export function parseConsoleSummary(input: unknown, options: ConsoleSummaryParseOptions = {}): ConsoleSummaryViewModel {
  const root = record(input, "$", ["organization", "devices", "agents", "policies", "audit"]);
  const organization = parseOrganization(root.organization, "$.organization");
  const expectedOrganizationId = options.organizationId === undefined
    ? organization.id
    : id(options.organizationId, "options.organizationId");
  if (organization.id !== expectedOrganizationId) fail("$.organization.organization_id", "tenant_mismatch");

  const devices = array(root.devices, "$.devices", MAX_RECORDS).map((value, index) => parseDevice(value, `$.devices[${index}]`));
  const deviceIds = new Set(devices.map((device) => device.id));
  if (deviceIds.size !== devices.length) fail("$.devices", "duplicate_id");

  const agents = array(root.agents, "$.agents", MAX_RECORDS).map((value, index) => parseAgent(value, `$.agents[${index}]`, expectedOrganizationId));
  if (new Set(agents.map((agent) => agent.id)).size !== agents.length) fail("$.agents", "duplicate_id");
  const policies = array(root.policies, "$.policies", MAX_RECORDS).map((value, index) => parsePolicy(value, `$.policies[${index}]`, expectedOrganizationId));
  if (new Set(policies.map((policy) => policy.id)).size !== policies.length) fail("$.policies", "duplicate_id");

  const auditRecord = record(root.audit, "$.audit", ["health", "activity", "next_cursor"]);
  const health = array(auditRecord.health, "$.audit.health", MAX_RECORDS).map((value, index) => parseHealth(value, `$.audit.health[${index}]`, deviceIds));
  if (new Set(health.map((item) => item.deviceId)).size !== health.length) fail("$.audit.health", "duplicate_device_id");
  const activity = array(auditRecord.activity, "$.audit.activity", MAX_ACTIVITY_RECORDS).map((value, index) => parseActivity(value, `$.audit.activity[${index}]`, expectedOrganizationId, deviceIds));
  if (new Set(activity.map((item) => item.eventId)).size !== activity.length) fail("$.audit.activity", "duplicate_event_id");
  const nextCursor = nullableCursor(auditRecord.next_cursor, "$.audit.next_cursor");

  return deepFreeze({
    organization,
    devices,
    agents,
    policies,
    audit: { health, activity, nextCursor },
  });
}

function parseOrganization(value: unknown, path: string): ConsoleSummaryViewModel["organization"] {
  const object = record(value, path, ["organization_id", "name", "slug", "created_at", "version"]);
  return {
    id: id(required(object.organization_id, `${path}.organization_id`), `${path}.organization_id`),
    name: text(required(object.name, `${path}.name`), `${path}.name`, MAX_NAME),
    slug: text(required(object.slug, `${path}.slug`), `${path}.slug`, MAX_NAME),
    createdAt: timestamp(required(object.created_at, `${path}.created_at`), `${path}.created_at`),
    version: positiveInteger(required(object.version, `${path}.version`), `${path}.version`),
  };
}

function parseDevice(value: unknown, path: string): ConsoleSummaryViewModel["devices"][number] {
  const object = record(value, path, [
    "device_id", "name", "status", "created_at", "last_seen_at", "version", "desired_generation",
    "observed_generation", "refresh_state", "bundle_sequence", "bundle_expires_at", "last_ack_at", "blocked_reason",
  ]);
  const status = enumValue(required(object.status, `${path}.status`), DEVICE_STATUSES, `${path}.status`);
  const refreshState = enumValue(required(object.refresh_state, `${path}.refresh_state`), REFRESH_STATES, `${path}.refresh_state`);
  const blockedReason = nullableText(object.blocked_reason, `${path}.blocked_reason`, MAX_NAME);
  if (refreshState === "blocked" && blockedReason === null) fail(`${path}.blocked_reason`, "required_for_blocked_device");
  if (refreshState !== "blocked" && blockedReason !== null) fail(`${path}.blocked_reason`, "only_valid_for_blocked_device");
  const desiredGeneration = nullablePositiveInteger(object.desired_generation, `${path}.desired_generation`);
  const observedGeneration = nullablePositiveInteger(object.observed_generation, `${path}.observed_generation`);
  if (desiredGeneration !== null && observedGeneration !== null && observedGeneration > desiredGeneration) {
    fail(`${path}.observed_generation`, "exceeds_desired_generation");
  }
  const bundleSequence = nullablePositiveInteger(object.bundle_sequence, `${path}.bundle_sequence`);
  const bundleExpiresAt = nullableTimestamp(object.bundle_expires_at, `${path}.bundle_expires_at`);
  if (bundleExpiresAt !== null && bundleSequence === null) fail(`${path}.bundle_expires_at`, "requires_bundle_sequence");
  return {
    id: id(required(object.device_id, `${path}.device_id`), `${path}.device_id`),
    name: text(required(object.name, `${path}.name`), `${path}.name`, MAX_NAME),
    status,
    tone: deviceTone(status),
    createdAt: nullableTimestamp(object.created_at, `${path}.created_at`),
    lastSeenAt: nullableTimestamp(object.last_seen_at, `${path}.last_seen_at`),
    version: nullablePositiveInteger(object.version, `${path}.version`),
    desiredGeneration,
    observedGeneration,
    refreshState,
    bundleSequence,
    bundleExpiresAt,
    lastAckAt: nullableTimestamp(object.last_ack_at, `${path}.last_ack_at`),
    blockedReason,
  };
}

function parseAgent(value: unknown, path: string, organizationId: string): ConsoleSummaryViewModel["agents"][number] {
  const object = record(value, path, ["version", "agent_id", "organization_id", "name", "kind", "public_key", "created_at", "device_id", "status"]);
  tenant(object.organization_id, `${path}.organization_id`, organizationId);
  const status = enumValue(required(object.status, `${path}.status`), AGENT_STATUSES, `${path}.status`);
  const kind = enumValue(required(object.kind, `${path}.kind`), AGENT_KINDS, `${path}.kind`);
  const publicKey = required(object.public_key, `${path}.public_key`);
  safePublicKey(publicKey, `${path}.public_key`);
  return {
    id: id(required(object.agent_id, `${path}.agent_id`), `${path}.agent_id`),
    name: text(required(object.name, `${path}.name`), `${path}.name`, MAX_NAME),
    kind,
    status,
    tone: agentTone(status),
    deviceId: nullableId(object.device_id, `${path}.device_id`),
    createdAt: timestamp(required(object.created_at, `${path}.created_at`), `${path}.created_at`),
    version: positiveInteger(required(object.version, `${path}.version`), `${path}.version`),
  };
}

function parsePolicy(value: unknown, path: string, organizationId: string): ConsoleSummaryViewModel["policies"][number] {
  const object = record(value, path, ["policy_id", "organization_id", "name", "scope", "sequence", "status", "created_at", "updated_at", "version"]);
  tenant(object.organization_id, `${path}.organization_id`, organizationId);
  const status = enumValue(required(object.status, `${path}.status`), POLICY_STATUSES, `${path}.status`);
  return {
    id: id(required(object.policy_id, `${path}.policy_id`), `${path}.policy_id`),
    name: text(required(object.name, `${path}.name`), `${path}.name`, MAX_NAME),
    status,
    tone: policyTone(status),
    scope: parseScope(required(object.scope, `${path}.scope`), `${path}.scope`),
    sequence: positiveInteger(required(object.sequence, `${path}.sequence`), `${path}.sequence`),
    version: positiveInteger(required(object.version, `${path}.version`), `${path}.version`),
    createdAt: timestamp(required(object.created_at, `${path}.created_at`), `${path}.created_at`),
    updatedAt: timestamp(required(object.updated_at, `${path}.updated_at`), `${path}.updated_at`),
  };
}

function parseScope(value: unknown, path: string): ConsolePolicyScope {
  const object = record(value, path, ["operations", "repositories", "branches", "remotes", "tags"], ["tags"]);
  const operations = stringArray(object.operations, `${path}.operations`, MAX_SCOPE_ITEMS, 128, (item) => OPERATIONS.has(item));
  const repositories = stringArray(object.repositories, `${path}.repositories`, MAX_SCOPE_ITEMS, 4_096, (item) => item.startsWith("/") && !item.includes("\\"));
  const branches = parsePatternSet(object.branches, `${path}.branches`);
  const remotes = parsePatternSet(object.remotes, `${path}.remotes`);
  return {
    operations,
    repositories,
    branches,
    remotes,
    tags: object.tags === undefined ? null : parsePatternSet(object.tags, `${path}.tags`),
  };
}

function parsePatternSet(value: unknown, path: string): Readonly<{ allow: readonly string[]; deny: readonly string[] }> {
  const object = record(value, path, ["allow", "deny"]);
  return {
    allow: stringArray(object.allow, `${path}.allow`, MAX_SCOPE_ITEMS, 2_048),
    deny: stringArray(object.deny, `${path}.deny`, MAX_SCOPE_ITEMS, 2_048),
  };
}

function parseHealth(value: unknown, path: string, deviceIds: ReadonlySet<string>): ConsoleSummaryViewModel["audit"]["health"][number] {
  const object = record(value, path, ["device_id", "chain_status", "gap_count", "last_event_id", "last_hash", "event_count"]);
  const deviceId = id(required(object.device_id, `${path}.device_id`), `${path}.device_id`);
  if (!deviceIds.has(deviceId)) fail(`${path}.device_id`, "unknown_device");
  const chainStatus = enumValue(required(object.chain_status, `${path}.chain_status`), CHAIN_STATUSES, `${path}.chain_status`);
  const lastHash = object.last_hash;
  if (lastHash !== null && (typeof lastHash !== "string" || !SHA256.test(lastHash))) fail(`${path}.last_hash`, "invalid_hash");
  return {
    deviceId,
    chainStatus,
    tone: chainTone(chainStatus),
    gapCount: nonNegativeInteger(required(object.gap_count, `${path}.gap_count`), `${path}.gap_count`),
    eventCount: nonNegativeInteger(required(object.event_count, `${path}.event_count`), `${path}.event_count`),
    lastEventId: nullableId(object.last_event_id, `${path}.last_event_id`),
  };
}

function parseActivity(value: unknown, path: string, organizationId: string, deviceIds: ReadonlySet<string>): ConsoleSummaryViewModel["audit"]["activity"][number] {
  const object = record(value, path, ["organization_id", "device_id", "event_id", "event", "received_at"]);
  tenant(object.organization_id, `${path}.organization_id`, organizationId);
  const deviceId = id(required(object.device_id, `${path}.device_id`), `${path}.device_id`);
  if (!deviceIds.has(deviceId)) fail(`${path}.device_id`, "unknown_device");
  const eventId = id(required(object.event_id, `${path}.event_id`), `${path}.event_id`);
  const sourcePath = `${path}.event`;
  const source = record(object.event, sourcePath, [...AUDIT_EVENT_KEYS]);
  const nestedEventId = id(required(source.event_id, `${sourcePath}.event_id`), `${sourcePath}.event_id`);
  if (eventId !== nestedEventId) fail(`${path}.event_id`, "event_id_mismatch");
  return activityView(source, sourcePath, deviceId, eventId, object.received_at);
}

function activityView(source: Record<string, unknown>, path: string, deviceId: string, eventId: string, receivedAtValue: unknown): ConsoleSummaryViewModel["audit"]["activity"][number] {
  const timestampValue = timestamp(required(source.device_timestamp, `${path}.device_timestamp`), `${path}.device_timestamp`);
  const agentId = id(required(source.agent_id, `${path}.agent_id`), `${path}.agent_id`);
  const operation = enumValue(required(source.operation, `${path}.operation`), OPERATIONS, `${path}.operation`);
  const decision = enumValue(required(source.decision, `${path}.decision`), DECISIONS, `${path}.decision`);
  const reason = text(required(source.reason, `${path}.reason`), `${path}.reason`, 128);
  id(required(source.request_id, `${path}.request_id`), `${path}.request_id`);
  positiveInteger(required(source.version, `${path}.version`), `${path}.version`);
  nonNegativeInteger(required(source.policy_sequence, `${path}.policy_sequence`), `${path}.policy_sequence`);
  nonNegativeInteger(required(source.capability_sequence, `${path}.capability_sequence`), `${path}.capability_sequence`);
  for (const field of ["repository", "branch", "remote"]) text(required(source[field], `${path}.${field}`), `${path}.${field}`, MAX_TEXT);
  for (const field of ["payload_digest", "previous_hash", "event_hash"]) {
    if (typeof source[field] !== "string" || !SHA256.test(source[field])) fail(`${path}.${field}`, "invalid_hash");
  }
  return {
    eventId,
    deviceId,
    agentId,
    operation,
    decision,
    tone: decisionTone(decision),
    reason,
    deviceTimestamp: timestampValue,
    receivedAt: nullableTimestamp(receivedAtValue, `${path}.received_at`),
  };
}

function record(value: unknown, path: string, allowedKeys: readonly string[], optionalKeys: readonly string[] = []): Record<string, unknown> {
  if (!isRecord(value)) fail(path, "object_required");
  const allowed = new Set(allowedKeys);
  const optional = new Set(optionalKeys);
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key !== "string" || !allowed.has(key) || SENSITIVE_FIELD.test(key)) fail(path, "unknown_field");
  }
  for (const key of allowed) {
    if (!optional.has(key) && !Object.hasOwn(value, key)) fail(`${path}.${key}`, "missing");
  }
  return value;
}

function required(value: unknown, path: string): unknown {
  if (value === undefined) fail(path, "missing");
  return value;
}

function array(value: unknown, path: string, maximum: number): unknown[] {
  if (!Array.isArray(value)) fail(path, "array_required");
  if (value.length > maximum) fail(path, "too_many_items");
  return value;
}

function stringArray(value: unknown, path: string, maximum: number, maximumLength: number, predicate?: (value: string) => boolean): readonly string[] {
  const values = array(value, path, maximum);
  return values.map((item, index) => {
    const normalized = text(item, `${path}[${index}]`, maximumLength);
    if (predicate !== undefined && !predicate(normalized)) fail(`${path}[${index}]`, "unsupported_value");
    return normalized;
  });
}

function isRecord(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function text(value: unknown, path: string, maximum: number): string {
  if (typeof value !== "string" || value.length < 1 || value.length > maximum || hasControl(value) || SECRET_VALUE.test(value)) fail(path, "invalid_text");
  return value;
}

function safePublicKey(value: unknown, path: string): void {
  if (typeof value !== "string" || value.length < 1 || value.length > 8_192 || hasControl(value, true)
    || !PUBLIC_KEY_PEM.test(value) || /PRIVATE KEY/u.test(value) || SECRET_VALUE.test(value)) fail(path, "invalid_public_key");
}

function id(value: unknown, path: string): string {
  if (typeof value !== "string" || value.length > MAX_ID || !ID.test(value)) fail(path, "invalid_id");
  return value;
}

function nullableId(value: unknown, path: string): string | null {
  return value === null || value === undefined ? null : id(value, path);
}

function tenant(value: unknown, path: string, expected: string): void {
  if (value === undefined) return;
  if (id(value, path) !== expected) fail(path, "tenant_mismatch");
}

function timestamp(value: unknown, path: string): string {
  if (typeof value !== "string" || !RFC3339_UTC.test(value) || !Number.isFinite(Date.parse(value))) fail(path, "invalid_timestamp");
  const normalized = new Date(value).toISOString();
  const inputSecond = value.slice(0, 19);
  if (normalized.slice(0, 19) !== inputSecond) fail(path, "invalid_timestamp");
  return normalized;
}

function nullableTimestamp(value: unknown, path: string): string | null {
  return value === null || value === undefined ? null : timestamp(value, path);
}

function positiveInteger(value: unknown, path: string): number {
  if (!Number.isSafeInteger(value) || (value as number) < 1) fail(path, "invalid_positive_integer");
  return value as number;
}

function nonNegativeInteger(value: unknown, path: string): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0) fail(path, "invalid_integer");
  return value as number;
}

function nullablePositiveInteger(value: unknown, path: string): number | null {
  return value === null || value === undefined ? null : positiveInteger(value, path);
}

function enumValue<T extends string>(value: unknown, allowed: ReadonlySet<T>, path: string): T {
  if (typeof value !== "string" || !allowed.has(value as T)) fail(path, "unsupported_value");
  return value as T;
}

function nullableText(value: unknown, path: string, maximum: number): string | null {
  return value === null || value === undefined ? null : text(value, path, maximum);
}

function nullableCursor(value: unknown, path: string): string | null {
  if (value === null) return null;
  if (typeof value !== "string" || value.length > MAX_CURSOR || !CURSOR.test(value)) fail(path, "invalid_cursor");
  return value;
}

function deviceTone(status: "pending" | "active" | "revoked"): ConsoleTone {
  return { pending: "amber", active: "green", revoked: "red" }[status];
}

function agentTone(status: "active" | "revoked"): ConsoleTone {
  return { active: "green", revoked: "red" }[status];
}

function policyTone(status: "active" | "disabled"): ConsoleTone {
  return { active: "green", disabled: "amber" }[status];
}

function chainTone(status: "continuous" | "gap" | "unknown"): ConsoleTone {
  return { continuous: "green", gap: "red", unknown: "amber" }[status];
}

function decisionTone(decision: ConsoleDecision): ConsoleTone {
  return { allow: "green", deny: "red", error: "amber" }[decision];
}

function hasControl(value: string, allowLineBreaks = false): boolean {
  for (const character of value) {
    const code = character.codePointAt(0) ?? 0;
    if (code === 0x7f || (code < 0x20 && !(allowLineBreaks && (code === 0x0a || code === 0x0d)))) return true;
  }
  return false;
}

function deepFreeze<T>(value: T): T {
  if (value !== null && typeof value === "object" && !Object.isFrozen(value)) {
    for (const child of Object.values(value as Record<string, unknown>)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}

function fail(path: string, reason: string): never {
  throw new ConsoleSummaryParseError(path, reason);
}
