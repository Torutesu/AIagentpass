const ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const CSRF = /^[A-Za-z0-9_-]{43}$/;
const ISO_INSTANT = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/;
const MAX_ITEMS = 100;

export type SecurityPasskey = Readonly<{
  id: string;
  version: number;
  label: string;
  createdAt: string;
  lastUsedAt: string | null;
}>;

export type SecuritySession = Readonly<{
  id: string;
  version: number;
  label: string;
  platform: string;
  createdAt: string;
  lastSeenAt: string;
  expiresAt: string;
  current: boolean;
}>;

export type SecuritySnapshot = Readonly<{
  passkeys: readonly SecurityPasskey[];
  sessions: readonly SecuritySession[];
}>;

type FetchLike = typeof fetch;
type ClientOptions = Readonly<{ fetchImpl?: FetchLike; signal?: AbortSignal }>;

export class SecurityClientError extends Error {
  readonly code: "http_failed" | "invalid_response" | "transport_failed";
  readonly status?: number;

  constructor(code: "http_failed" | "invalid_response" | "transport_failed", message: string, status?: number) {
    super(message);
    this.name = "SecurityClientError";
    this.code = code;
    this.status = status;
  }
}

/**
 * The Cloud contract intentionally returns only safe management metadata.
 * Credential bytes, public keys, counters, IPs and user-agent strings are not
 * accepted by this client and are never placed in React state.
 */
export async function getSecuritySnapshot(options: ClientOptions = {}): Promise<SecuritySnapshot> {
  const { csrfToken } = await bootstrapSession(options);
  const [credentials, sessions] = await Promise.all([
    requestJson("/api/auth/security/passkeys", "GET", csrfToken, undefined, options),
    requestJson("/api/auth/security/sessions", "GET", csrfToken, undefined, options),
  ]);
  return Object.freeze({ passkeys: Object.freeze(parseCredentialPage(credentials)), sessions: Object.freeze(parseSessionPage(sessions)) });
}

export async function renamePasskey(id: string, label: string, version: number, options: ClientOptions = {}): Promise<void> {
  assertCredentialId(id);
  assertLabel(label);
  assertVersion(version);
  const { csrfToken } = await bootstrapSession(options);
  const response = await requestJson(`/api/auth/security/passkeys/${encodeURIComponent(id)}`, "PATCH", csrfToken, { label, expected_version: version }, options);
  expectCredentialMutation(response);
}

export async function revokePasskey(id: string, version: number, options: ClientOptions = {}): Promise<void> {
  assertCredentialId(id);
  assertVersion(version);
  const { csrfToken } = await bootstrapSession(options);
  const response = await requestJson(`/api/auth/security/passkeys/${encodeURIComponent(id)}/revoke`, "POST", csrfToken, { expected_version: version }, options);
  expectCredentialMutation(response);
}

export async function revokeSession(id: string, version: number, options: ClientOptions = {}): Promise<void> {
  if (!isUuid(id)) throw new SecurityClientError("invalid_response", "対象を確認できませんでした。");
  assertVersion(version);
  const { csrfToken } = await bootstrapSession(options);
  const response = await requestJson(`/api/auth/security/sessions/${encodeURIComponent(id)}/revoke`, "POST", csrfToken, { expected_version: version }, options);
  expectSessionMutation(response);
}

async function bootstrapSession(options: ClientOptions): Promise<{ csrfToken: string }> {
  const response = await requestJson("/api/auth/session", "POST", undefined, {}, options);
  if (!isRecord(response) || !hasExactKeys(response, ["session", "csrf_token"]) || !isRecord(response.session) || typeof response.csrf_token !== "string" || !CSRF.test(response.csrf_token)) {
    throw new SecurityClientError("invalid_response", "セッション応答を確認できませんでした。");
  }
  return { csrfToken: response.csrf_token };
}

async function requestJson(path: string, method: "GET" | "POST" | "PATCH", csrfToken: string | undefined, body: Record<string, unknown> | undefined, options: ClientOptions): Promise<unknown> {
  const fetchImpl = options.fetchImpl ?? globalThis.fetch;
  if (typeof fetchImpl !== "function") throw new SecurityClientError("transport_failed", "セキュリティ情報を取得できませんでした。");
  const headers = new Headers({ accept: "application/json" });
  if (body !== undefined) headers.set("content-type", "application/json");
  if (csrfToken !== undefined) headers.set("agentpass-csrf", csrfToken);
  let response: Response;
  try {
    response = await fetchImpl(path, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
      cache: "no-store",
      credentials: "same-origin",
      redirect: "error",
      signal: options.signal,
    });
  } catch (error) {
    if (error instanceof DOMException && error.name === "AbortError") throw error;
    throw new SecurityClientError("transport_failed", "セキュリティ情報を取得できませんでした。");
  }
  const type = response.headers.get("content-type") ?? "";
  if (!/^application\/json(?:\s*;|\s*$)/i.test(type)) throw new SecurityClientError("invalid_response", "セキュリティ応答を確認できませんでした。", response.status);
  let value: unknown;
  try { value = await response.json(); } catch { throw new SecurityClientError("invalid_response", "セキュリティ応答を確認できませんでした。", response.status); }
  if (!response.ok) throw new SecurityClientError("http_failed", "セキュリティ操作を完了できませんでした。", response.status);
  return value;
}

function parseCredentialPage(value: unknown): SecurityPasskey[] {
  if (!isRecord(value) || !hasExactKeys(value, ["credentials", "next_cursor"]) || !Array.isArray(value.credentials) || value.credentials.length > MAX_ITEMS || !isNullableCursor(value.next_cursor)) {
    throw new SecurityClientError("invalid_response", "セキュリティ情報を確認できませんでした。");
  }
  return value.credentials.map(parsePasskey).filter((item) => item.status === "active").map(toPublicPasskey);
}

function parseSessionPage(value: unknown): SecuritySession[] {
  if (!isRecord(value) || !hasExactKeys(value, ["sessions", "next_cursor"]) || !Array.isArray(value.sessions) || value.sessions.length > MAX_ITEMS || !isNullableCursor(value.next_cursor)) {
    throw new SecurityClientError("invalid_response", "セキュリティ情報を確認できませんでした。");
  }
  return value.sessions.map(parseSession).filter((item) => item.status === "active").map(toPublicSession);
}

function parsePasskey(value: unknown): SecurityPasskey & { status: "active" | "revoked" } {
  if (!isRecord(value) || !hasExactKeys(value, ["credential_id", "version", "label", "transports", "backup_eligible", "backup_state", "status", "created_at", "last_used_at", "revoked_at"]) || !isCredentialId(value.credential_id) || !isVersion(value.version) || !isLabel(value.label) || !isTransports(value.transports) || typeof value.backup_eligible !== "boolean" || typeof value.backup_state !== "boolean" || (value.status !== "active" && value.status !== "revoked") || !isInstant(value.created_at) || !isNullableInstant(value.last_used_at) || !isNullableInstant(value.revoked_at)) {
    throw new SecurityClientError("invalid_response", "セキュリティ情報を確認できませんでした。");
  }
  return { id: value.credential_id, version: value.version, label: value.label, createdAt: value.created_at, lastUsedAt: value.last_used_at, status: value.status };
}

function parseSession(value: unknown): SecuritySession & { status: "active" | "revoked" | "expired" } {
  if (!isRecord(value) || !hasExactKeys(value, ["session_id", "version", "member_id", "organization_id", "role", "status", "is_current", "created_at", "expires_at", "last_seen_at", "recent_auth_at", "revoked_at"]) || !isId(value.session_id) || !isVersion(value.version) || !isUuid(value.member_id) || !isUuid(value.organization_id) || !["owner", "admin", "auditor", "viewer"].includes(String(value.role)) || !["active", "revoked", "expired"].includes(String(value.status)) || typeof value.is_current !== "boolean" || !isInstant(value.created_at) || !isInstant(value.expires_at) || !isNullableInstant(value.last_seen_at) || !isNullableInstant(value.recent_auth_at) || !isNullableInstant(value.revoked_at)) {
    throw new SecurityClientError("invalid_response", "セキュリティ情報を確認できませんでした。");
  }
  return { id: value.session_id, version: value.version, label: value.is_current ? "現在のブラウザ" : "別のブラウザセッション", platform: "Web Console", createdAt: value.created_at, lastSeenAt: value.last_seen_at ?? value.created_at, expiresAt: value.expires_at, current: value.is_current, status: value.status as "active" | "revoked" | "expired" };
}

function expectCredentialMutation(value: unknown): void {
  if (!isRecord(value) || !hasExactKeys(value, ["credential"])) throw new SecurityClientError("invalid_response", "セキュリティ操作の応答を確認できませんでした。");
  parsePasskey(value.credential);
}

function expectSessionMutation(value: unknown): void {
  if (!isRecord(value) || !hasExactKeys(value, ["session"])) throw new SecurityClientError("invalid_response", "セキュリティ操作の応答を確認できませんでした。");
  parseSession(value.session);
}

function toPublicPasskey(value: SecurityPasskey & { status: "active" | "revoked" }): SecurityPasskey {
  return { id: value.id, version: value.version, label: value.label, createdAt: value.createdAt, lastUsedAt: value.lastUsedAt };
}

function toPublicSession(value: SecuritySession & { status: "active" | "revoked" | "expired" }): SecuritySession {
  return { id: value.id, version: value.version, label: value.label, platform: value.platform, createdAt: value.createdAt, lastSeenAt: value.lastSeenAt, expiresAt: value.expiresAt, current: value.current };
}

function assertCredentialId(value: string): asserts value is string { if (!isCredentialId(value)) throw new SecurityClientError("invalid_response", "対象を確認できませんでした。"); }
function assertLabel(value: string): asserts value is string { if (!isLabel(value)) throw new SecurityClientError("invalid_response", "表示名を確認できませんでした。"); }
function assertVersion(value: number): asserts value is number { if (!isVersion(value)) throw new SecurityClientError("invalid_response", "更新番号を確認できませんでした。"); }
function isId(value: unknown): value is string { return typeof value === "string" && ID.test(value); }
function isCredentialId(value: unknown): value is string { return typeof value === "string" && /^[A-Za-z0-9_-]{16,1024}$/.test(value) && !value.includes("="); }
function isUuid(value: unknown): value is string { return typeof value === "string" && /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value); }
function isLabel(value: unknown): value is string { return typeof value === "string" && value.length >= 1 && value.length <= 80 && value.trim() === value && !hasControl(value); }
function isVersion(value: unknown): value is number { return typeof value === "number" && Number.isSafeInteger(value) && value > 0; }
function isTransports(value: unknown): value is string[] { const allowed = new Set(["ble", "cable", "hybrid", "internal", "nfc", "smart-card", "usb"]); return Array.isArray(value) && value.length <= 7 && new Set(value).size === value.length && value.every((item) => typeof item === "string" && allowed.has(item)); }
function isNullableCursor(value: unknown): value is string | null { return value === null || (typeof value === "string" && /^[A-Za-z0-9_-]{1,512}$/.test(value)); }
function isInstant(value: unknown): value is string { return typeof value === "string" && ISO_INSTANT.test(value) && !Number.isNaN(Date.parse(value)); }
function isNullableInstant(value: unknown): value is string | null { return value === null || isInstant(value); }
function hasControl(value: string): boolean { for (const character of value) { const code = character.codePointAt(0) ?? 0; if (code <= 0x1f || code === 0x7f) return true; } return false; }
function isRecord(value: unknown): value is Record<string, unknown> { return Boolean(value) && typeof value === "object" && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype; }
function hasExactKeys(value: Record<string, unknown>, expected: string[]): boolean { const actual = Object.keys(value).sort(); const keys = [...expected].sort(); return actual.length === keys.length && actual.every((key, index) => key === keys[index]); }
