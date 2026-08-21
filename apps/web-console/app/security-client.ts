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
  passkeysComplete: boolean;
  sessions: readonly SecuritySession[];
}>;

type FetchLike = typeof fetch;
export type SecuritySessionContext = Readonly<{ csrfToken: string; organizationId: string }>;
export type SecuritySessionProvider = Readonly<{
  get(signal?: AbortSignal): Promise<SecuritySessionContext>;
  clear(session?: SecuritySessionContext): void;
}>;

type ClientOptions = Readonly<{
  fetchImpl?: FetchLike;
  signal?: AbortSignal;
  authenticateRecentAuthImpl?: (input: WebAuthnClientInput) => Promise<AuthorizationResult>;
  registerPasskeyImpl?: (input: WebAuthnRegistrationInput) => Promise<RegistrationResult>;
  sessionProvider?: SecuritySessionProvider;
}>;
type SecurityRequestOptions = Readonly<{ signal?: AbortSignal }>;
type MutationControls = Readonly<{ idempotencyKey?: string; expectedVersion?: number; recentAuth?: string; recentAuthContext?: string }>;

export type SecurityClient = Readonly<{
  getSnapshot(options?: SecurityRequestOptions): Promise<SecuritySnapshot>;
  getSecuritySnapshot(options?: SecurityRequestOptions): Promise<SecuritySnapshot>;
  addPasskey(options?: SecurityRequestOptions): Promise<void>;
  registerPasskey(options?: SecurityRequestOptions): Promise<void>;
  renamePasskey(id: string, label: string, version: number, options?: SecurityRequestOptions): Promise<void>;
  revokePasskey(id: string, version: number, options?: SecurityRequestOptions): Promise<void>;
  revokeSession(id: string, version: number, options?: SecurityRequestOptions): Promise<void>;
  revokeCurrentSession(id: string, version: number, options?: SecurityRequestOptions): Promise<void>;
  signOut(id: string, version: number, options?: SecurityRequestOptions): Promise<void>;
  revokeOtherSessions(sessions: readonly SecuritySession[], options?: SecurityRequestOptions): Promise<number>;
}>;

export class SecurityClientError extends Error {
  readonly code: "http_failed" | "invalid_response" | "transport_failed";
  readonly status?: number;
  readonly serviceCode?: string;

  constructor(code: "http_failed" | "invalid_response" | "transport_failed", message: string, status?: number, serviceCode?: string) {
    super(message);
    this.name = "SecurityClientError";
    this.code = code;
    this.status = status;
    this.serviceCode = serviceCode;
  }
}

/**
 * A mutation may have committed before its response is lost or rejected.
 * Callers must refresh authoritative state and must not resend automatically.
 */
export function isAmbiguousSecurityMutationError(error: unknown): boolean {
  return error instanceof SecurityClientError && (
    error.code === "transport_failed"
    || error.code === "invalid_response"
    || error.code === "http_failed" && error.status !== undefined && error.status >= 500 && error.status <= 599
  );
}

/**
 * The Cloud contract intentionally returns only safe management metadata.
 * Credential bytes, public keys, counters, IPs and user-agent strings are not
 * accepted by this client and are never placed in React state.
 */
export async function getSecuritySnapshot(options: ClientOptions = {}): Promise<SecuritySnapshot> {
  return createSecurityClient(options).getSnapshot(options);
}

export async function renamePasskey(id: string, label: string, version: number, options: ClientOptions = {}): Promise<void> {
  return createSecurityClient(options).renamePasskey(id, label, version, options);
}

export async function registerPasskey(options: ClientOptions = {}): Promise<void> {
  return createSecurityClient(options).registerPasskey(options);
}

export async function revokePasskey(id: string, version: number, options: ClientOptions = {}): Promise<void> {
  return createSecurityClient(options).revokePasskey(id, version, options);
}

export async function revokeSession(id: string, version: number, options: ClientOptions = {}): Promise<void> {
  return createSecurityClient(options).revokeSession(id, version, options);
}

export async function revokeCurrentSession(id: string, version: number, options: ClientOptions = {}): Promise<void> {
  return createSecurityClient(options).revokeCurrentSession(id, version, options);
}

export async function signOut(id: string, version: number, options: ClientOptions = {}): Promise<void> {
  return revokeCurrentSession(id, version, options);
}

export function createSecurityClient(options: ClientOptions = {}): SecurityClient {
  const fetchImpl = options.fetchImpl;
  const authenticateImpl = options.authenticateRecentAuthImpl ?? authenticateRecentAuth;
  const registerImpl = options.registerPasskeyImpl ?? runPasskeyRegistration;
  const sessionProvider = options.sessionProvider;
  let sessionContext: SecuritySessionContext | undefined;
  let bootstrapPromise: Promise<SecuritySessionContext> | undefined;
  let closed = false;

  const ensureSession = async (requestOptions: SecurityRequestOptions = {}): Promise<SecuritySessionContext> => {
    if (closed) throw closedSessionError();
    if (sessionProvider !== undefined) return sessionProvider.get(requestOptions.signal);
    if (sessionContext !== undefined) return sessionContext;
    if (bootstrapPromise === undefined) {
      const pending = bootstrapSession({ fetchImpl, signal: requestOptions.signal }).then((context) => {
        sessionContext = context;
        return context;
      });
      bootstrapPromise = pending;
      void pending.catch(() => {
        if (bootstrapPromise === pending) bootstrapPromise = undefined;
      });
    }
    return bootstrapPromise;
  };

  const getSnapshot = async (requestOptions: SecurityRequestOptions = {}): Promise<SecuritySnapshot> => {
    const { csrfToken: token } = await ensureSession(requestOptions);
    const request = requestOptionsFor(requestOptions);
    const [credentials, sessions] = await Promise.all([
      requestJson("/api/auth/security/passkeys", "GET", token, undefined, request),
      requestJson("/api/auth/security/sessions", "GET", token, undefined, request),
    ]);
    const credentialPage = parseCredentialPage(credentials);
    return Object.freeze({ passkeys: Object.freeze(credentialPage.items), passkeysComplete: credentialPage.complete, sessions: Object.freeze(parseSessionPage(sessions)) });
  };

  const mutatePasskey = async (id: string, method: "POST" | "PATCH", body: Record<string, unknown>, version: number, requestOptions: SecurityRequestOptions, recentAuthOperation?: string, label?: string): Promise<void> => {
    const context = await ensureSession(requestOptions);
    const idempotencyKey = makeIdempotencyKey();
    const recentAuthContext = recentAuthOperation === undefined ? undefined : await credentialContextHash(recentAuthOperation, id, version);
    const recentAuth = recentAuthOperation === undefined ? undefined : await authorize(context, recentAuthOperation, requestOptions, recentAuthContext);
    const response = await requestJson(`/api/auth/security/passkeys/${encodeURIComponent(id)}${method === "POST" ? "/revoke" : ""}`, method, context.csrfToken, body, requestOptionsFor(requestOptions), { idempotencyKey, expectedVersion: version, recentAuth, recentAuthContext });
    expectCredentialMutation(response, { id, version, status: method === "POST" ? "revoked" : "active", label });
  };

  const registerSecurityPasskey = async (requestOptions: SecurityRequestOptions): Promise<void> => {
    const context = await ensureSession(requestOptions);
    const result = await registerImpl({
      organizationId: context.organizationId,
      csrfToken: context.csrfToken,
      signal: requestOptions.signal,
      fetchImpl,
    });
    if (!result || result.registered !== true) throw new SecurityClientError("invalid_response", "パスキー登録の結果を確認できませんでした。");
  };

  const revokeSessionRecord = async (id: string, version: number, requestOptions: SecurityRequestOptions, current: boolean): Promise<boolean> => {
    const context = await ensureSession(requestOptions);
    const recentAuth = current ? await authorize(context, "human.management.session.revoke", requestOptions) : undefined;
    const response = await requestJson(`/api/auth/security/sessions/${encodeURIComponent(id)}/revoke`, "POST", context.csrfToken, { expected_version: version }, requestOptionsFor(requestOptions), { recentAuth });
    const revoked = expectSessionMutation(response);
    if (revoked.current) {
      if (sessionProvider !== undefined) sessionProvider.clear(context);
      else {
        sessionContext = undefined;
        bootstrapPromise = undefined;
      }
      closed = true;
    }
    return revoked.current;
  };

  const client: SecurityClient = {
    getSnapshot,
    getSecuritySnapshot: getSnapshot,
    addPasskey: async (requestOptions = {}) => registerSecurityPasskey(requestOptions),
    registerPasskey: async (requestOptions = {}) => registerSecurityPasskey(requestOptions),
    renamePasskey: async (id, label, version, requestOptions = {}) => {
      assertCredentialId(id);
      assertLabel(label);
      assertVersion(version);
      await mutatePasskey(id, "PATCH", { label }, version, requestOptions, undefined, label);
    },
    revokePasskey: async (id, version, requestOptions = {}) => {
      assertCredentialId(id);
      assertVersion(version);
      await mutatePasskey(id, "POST", {}, version, requestOptions, "human.management.credential.revoke");
    },
    revokeSession: async (id, version, requestOptions = {}) => {
      assertSessionTarget(id, version);
      await revokeSessionRecord(id, version, requestOptions, false);
    },
    revokeCurrentSession: async (id, version, requestOptions = {}) => {
      assertSessionTarget(id, version);
      if (!(await revokeSessionRecord(id, version, requestOptions, true))) throw new SecurityClientError("invalid_response", "現在のセッションを確認できませんでした。");
    },
    signOut: async (id, version, requestOptions = {}) => {
      assertSessionTarget(id, version);
      if (!(await revokeSessionRecord(id, version, requestOptions, true))) throw new SecurityClientError("invalid_response", "現在のセッションを確認できませんでした。");
    },
    revokeOtherSessions: async (sessions, requestOptions = {}) => {
      if (!Array.isArray(sessions)) throw new SecurityClientError("invalid_response", "セッション情報を確認できませんでした。");
      const targets = sessions.filter((session) => !session.current);
      for (const session of targets) assertSessionTarget(session.id, session.version);
      const context = await ensureSession(requestOptions);
      const recentAuth = await authorize(context, "human.management.sessions.revoke_others", requestOptions);
      const response = await requestJson("/api/auth/security/sessions/revoke-others", "POST", context.csrfToken, {}, requestOptionsFor(requestOptions), { recentAuth });
      return expectOtherSessionsMutation(response, context.organizationId);
    },
  };
  return Object.freeze(client);

  function requestOptionsFor(requestOptions: SecurityRequestOptions): ClientOptions {
    return { fetchImpl, signal: requestOptions.signal };
  }

  async function authorize(context: SecuritySessionContext, operation: string, requestOptions: SecurityRequestOptions, contextHash?: string): Promise<string> {
    const result = await authenticateImpl({ operation, organizationId: context.organizationId, csrfToken: context.csrfToken, signal: requestOptions.signal, fetchImpl, ...(contextHash === undefined ? {} : { contextHash }) });
    if (!isUuid(result?.authorization_id)) throw new SecurityClientError("invalid_response", "再認証の結果を確認できませんでした。");
    return result.authorization_id.toLowerCase();
  }
}

async function bootstrapSession(options: ClientOptions): Promise<SecuritySessionContext> {
  const response = await requestJson("/api/auth/session", "POST", undefined, {}, options);
  if (!isRecord(response) || !hasExactKeys(response, ["session", "csrf_token"]) || !isRecord(response.session) || !isUuid(response.session.organization_id) || typeof response.csrf_token !== "string" || !CSRF.test(response.csrf_token)) {
    throw new SecurityClientError("invalid_response", "セッション応答を確認できませんでした。");
  }
  return { csrfToken: response.csrf_token, organizationId: response.session.organization_id.toLowerCase() };
}

async function requestJson(path: string, method: "GET" | "POST" | "PATCH", csrfToken: string | undefined, body: Record<string, unknown> | undefined, options: ClientOptions, controls: MutationControls = {}): Promise<unknown> {
  const fetchImpl = options.fetchImpl ?? globalThis.fetch;
  if (typeof fetchImpl !== "function") throw new SecurityClientError("transport_failed", "セキュリティ情報を取得できませんでした。");
  const headers = new Headers({ accept: "application/json" });
  if (body !== undefined) headers.set("content-type", "application/json");
  if (csrfToken !== undefined) headers.set("agentpass-csrf", csrfToken);
  if (controls.recentAuth !== undefined) headers.set("agentpass-recent-auth", controls.recentAuth);
  if (controls.recentAuthContext !== undefined) headers.set("agentpass-recent-auth-context", controls.recentAuthContext);
  if (controls.idempotencyKey !== undefined) headers.set("idempotency-key", controls.idempotencyKey);
  if (controls.expectedVersion !== undefined) headers.set("if-match", `"${controls.expectedVersion}"`);
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
  if (!response.ok) throw new SecurityClientError("http_failed", "セキュリティ操作を完了できませんでした。", response.status, serviceErrorCode(value));
  return value;
}

function parseCredentialPage(value: unknown): { items: SecurityPasskey[]; complete: boolean } {
  if (!isRecord(value) || !hasExactKeys(value, ["credentials", "next_cursor"]) || !Array.isArray(value.credentials) || value.credentials.length > MAX_ITEMS || !isNullableCursor(value.next_cursor)) {
    throw new SecurityClientError("invalid_response", "セキュリティ情報を確認できませんでした。");
  }
  const items = value.credentials.map(parsePasskey).filter((item) => item.status === "active").map(toPublicPasskey);
  if (new Set(items.map((item) => item.id)).size !== items.length) throw new SecurityClientError("invalid_response", "セキュリティ情報を確認できませんでした。");
  return { items, complete: value.next_cursor === null };
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

function expectCredentialMutation(value: unknown, expected: Readonly<{ id: string; version: number; status: "active" | "revoked"; label?: string }>): void {
  if (!isRecord(value) || !hasExactKeys(value, ["credential"])) throw new SecurityClientError("invalid_response", "セキュリティ操作の応答を確認できませんでした。");
  const credential = parsePasskey(value.credential);
  if (credential.id !== expected.id || credential.version !== expected.version + 1 || credential.status !== expected.status || expected.label !== undefined && credential.label !== expected.label) throw new SecurityClientError("invalid_response", "セキュリティ操作の応答を確認できませんでした。");
}

function expectSessionMutation(value: unknown): SecuritySession {
  if (!isRecord(value) || !hasExactKeys(value, ["session"])) throw new SecurityClientError("invalid_response", "セキュリティ操作の応答を確認できませんでした。");
  return toPublicSession(parseSession(value.session));
}

function expectOtherSessionsMutation(value: unknown, organizationId: string): number {
  if (!isRecord(value) || !hasExactKeys(value, ["revoked_sessions", "revoked_count", "truncated"]) || !Array.isArray(value.revoked_sessions) || value.revoked_sessions.length > MAX_ITEMS || !Number.isSafeInteger(value.revoked_count) || Number(value.revoked_count) < 0 || typeof value.truncated !== "boolean" || value.truncated !== (Number(value.revoked_count) > value.revoked_sessions.length) || (!value.truncated && value.revoked_count !== value.revoked_sessions.length) || (value.truncated && value.revoked_sessions.length !== MAX_ITEMS)) {
    throw new SecurityClientError("invalid_response", "セッション一括無効化の応答を確認できませんでした。");
  }
  const records = value.revoked_sessions.map((session) => {
    if (!isRecord(session) || session.organization_id !== organizationId || session.is_current !== false || session.status !== "revoked" || !isInstant(session.revoked_at)) {
      throw new SecurityClientError("invalid_response", "セッション一括無効化の応答を確認できませんでした。");
    }
    return parseSession(session);
  });
  if (new Set(records.map((session) => session.id)).size !== records.length) throw new SecurityClientError("invalid_response", "セッション一括無効化の応答を確認できませんでした。");
  return Number(value.revoked_count);
}

function assertSessionTarget(id: string, version: number): void {
  if (!isUuid(id)) throw new SecurityClientError("invalid_response", "対象を確認できませんでした。");
  assertVersion(version);
}

function makeIdempotencyKey(): string {
  const value = globalThis.crypto?.randomUUID?.();
  if (typeof value === "string") return value;
  throw new SecurityClientError("transport_failed", "安全な操作IDを生成できませんでした。");
}

async function credentialContextHash(operation: string, credentialId: string, expectedVersion: number): Promise<string> {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) throw new SecurityClientError("transport_failed", "再認証コンテキストを生成できませんでした。");
  const canonical = `{"credential_id":${JSON.stringify(credentialId)},"expected_version":${expectedVersion},"operation":${JSON.stringify(operation)},"version":1}`;
  const digest = await subtle.digest("SHA-256", new TextEncoder().encode(canonical));
  return [...new Uint8Array(digest)].map((item) => item.toString(16).padStart(2, "0")).join("");
}

function closedSessionError(): SecurityClientError {
  return new SecurityClientError("http_failed", "セッションの有効期限が切れています。", 401);
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
function isCredentialId(value: unknown): value is string { return typeof value === "string" && /^[A-Za-z0-9_-]{22,1366}$/.test(value) && !value.includes("="); }
function isUuid(value: unknown): value is string { return typeof value === "string" && /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value); }
function isLabel(value: unknown): value is string { return typeof value === "string" && value.length >= 1 && value.length <= 80 && value.trim() === value && !hasControl(value); }
function isVersion(value: unknown): value is number { return typeof value === "number" && Number.isSafeInteger(value) && value > 0; }
function isTransports(value: unknown): value is string[] { const allowed = new Set(["ble", "cable", "hybrid", "internal", "nfc", "smart-card", "usb"]); return Array.isArray(value) && value.length <= 7 && new Set(value).size === value.length && value.every((item) => typeof item === "string" && allowed.has(item)); }
function isNullableCursor(value: unknown): value is string | null { return value === null || (typeof value === "string" && /^[A-Za-z0-9_-]{1,512}$/.test(value)); }
function isInstant(value: unknown): value is string { return typeof value === "string" && ISO_INSTANT.test(value) && !Number.isNaN(Date.parse(value)); }
function isNullableInstant(value: unknown): value is string | null { return value === null || isInstant(value); }
function hasControl(value: string): boolean { for (const character of value) { const code = character.codePointAt(0) ?? 0; if (code <= 0x1f || code === 0x7f) return true; } return false; }
function serviceErrorCode(value: unknown): string | undefined {
  if (!isRecord(value) || !isRecord(value.error) || typeof value.error.code !== "string" || !/^[A-Za-z0-9_-]{1,128}$/.test(value.error.code)) return undefined;
  return value.error.code;
}
function isRecord(value: unknown): value is Record<string, unknown> { return Boolean(value) && typeof value === "object" && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype; }
function hasExactKeys(value: Record<string, unknown>, expected: string[]): boolean { const actual = Object.keys(value).sort(); const keys = [...expected].sort(); return actual.length === keys.length && actual.every((key, index) => key === keys[index]); }
import { authenticateRecentAuth, registerPasskey as runPasskeyRegistration, type AuthorizationResult, type RegistrationResult, type WebAuthnClientInput, type WebAuthnRegistrationInput } from "./webauthn-client.ts";
