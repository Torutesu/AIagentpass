"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { authenticateRecentAuth, registerPasskey, WebAuthnClientError } from "../webauthn-client";
import { createSecurityClient, SecurityClientError, type SecurityClient, type SecurityPasskey, type SecuritySession, type SecuritySnapshot } from "../security-client";
import { parseConsoleSummary, type ConsoleSummaryViewModel } from "../console-summary";
import { OrganizationPanel } from "./OrganizationPanel";
import { OwnerRecoveryPanel } from "./OwnerRecoveryPanel";

export type ConsoleView =
  | "overview"
  | "setup"
  | "agents"
  | "policies"
  | "activity"
  | "security"
  | "organizations"
  | "recovery"
  | "emergency";

export type AgentPassInitialData = {
  workspace: string;
  operator: { name: string; role: string; initials: string };
  session: { expires: string; remaining: string; lastVerified: string };
  capabilities: string[];
  capabilityRecords?: Array<{ capabilityId: string; agentId: string; deviceId: string; expiresAt: string; sequence: number }>;
  devices: Array<{
    deviceId?: string;
    name: string;
    detail: string;
    status: string;
    location: string;
    checked: string;
    desiredGeneration?: number;
    observedGeneration?: number;
    refreshState?: string;
    bundleSequence?: number;
    bundleExpiresAt?: string;
    lastAckAt?: string;
    blockedReason?: string;
  }>;
  agents: Array<{
    agentId?: string;
    deviceId?: string;
    name: string;
    client: string;
    detail: string;
    state: string;
    stateTone: "green" | "amber" | "red";
  }>;
  policies: Array<{
    policyId?: string;
    version?: number;
    scope?: Record<string, unknown>;
    name: string;
    detail: string;
    state: string;
    tone: "green" | "amber" | "red";
  }>;
  activities: Array<{
    symbol: string;
    title: string;
    description: string;
    time: string;
  }>;
};

function emptyConsoleData(): AgentPassInitialData {
  return {
    workspace: "ワークスペース未取得",
    operator: { name: "ユーザー情報未取得", role: "セッション確認中", initials: "—" },
    session: { expires: "未取得", remaining: "未取得", lastVerified: "未同期" },
    capabilities: [],
    capabilityRecords: [],
    devices: [],
    agents: [],
    policies: [],
    activities: [],
  };
}

function summaryViewData(summary: ConsoleSummaryViewModel): AgentPassInitialData {
  return {
    ...emptyConsoleData(),
    workspace: summary.organization.name,
    devices: summary.devices.map((device) => ({
      deviceId: device.id,
      name: device.name,
      detail: device.refreshState ?? device.status,
      status: device.status === "revoked" ? "停止" : device.status === "pending" ? "登録待ち" : "正常",
      location: "Cloud管理",
      checked: device.lastSeenAt ?? "未確認",
      desiredGeneration: device.desiredGeneration ?? undefined,
      observedGeneration: device.observedGeneration ?? undefined,
      refreshState: device.refreshState ?? undefined,
      bundleSequence: device.bundleSequence ?? undefined,
      bundleExpiresAt: device.bundleExpiresAt ?? undefined,
      lastAckAt: device.lastAckAt ?? undefined,
      blockedReason: device.blockedReason ?? undefined,
    })),
    agents: summary.agents.map((agent) => ({
      agentId: agent.id,
      deviceId: agent.deviceId ?? undefined,
      name: agent.name,
      client: agent.kind === "claude-code" ? "Claude Code" : agent.kind === "cursor" ? "Cursor" : agent.kind,
      detail: agent.deviceId ?? "端末未割り当て",
      state: agent.status === "revoked" ? "停止" : "待機中",
      stateTone: agent.tone,
    })),
    policies: summary.policies.map((policy) => ({
      policyId: policy.id,
      version: policy.version,
      scope: policy.scope as Record<string, unknown>,
      name: policy.name,
      detail: `sequence ${policy.sequence} · Cloud署名対象`,
      state: policy.status === "active" ? "保護中" : "停止",
      tone: policy.tone,
    })),
    activities: summary.audit.activity.slice(-20).reverse().map((event) => ({
      symbol: event.decision === "allow" ? "✓" : "□",
      title: event.decision === "allow" ? "操作を許可しました" : event.decision === "deny" ? "操作をブロックしました" : "操作を記録しました",
      description: `${event.operation ?? "agent operation"} · ${event.reason ?? "recorded"}`,
      time: event.deviceTimestamp,
    })),
  };
}

type ToastTone = "success" | "error";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const OPAQUE_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const RFC3339_UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/;
const BASE64URL_CSRF = /^[A-Za-z0-9_-]{43}$/;
const RECENT_AUTH_OPERATION = "device.enrollment.issue";
const DEVICE_REVOKE_RECENT_AUTH_OPERATION = "device.revoke";
const DEVICE_REFRESH_REQUEST_RECENT_AUTH_OPERATION = "device.refresh.request";
const EMERGENCY_STOP_RECENT_AUTH_OPERATION = "organization.emergency_stop";
const SESSION_BOOTSTRAP_PATH = "/api/auth/session";
const CSRF_HEADER = "agentpass-csrf";

type DeviceRefreshRequestStatus = "accepted" | "coalesced" | "no_pending_refresh";

type ConsoleSession = Readonly<{ organizationId: string; csrfToken: string }>;

class ConsoleSessionError extends Error {
  readonly status?: number;

  constructor(message: string, status?: number) {
    super(message);
    this.name = "ConsoleSessionError";
    this.status = status;
  }
}

class EnrollmentFlowError extends Error {
  readonly code: "session" | "enrollment" | "unsupported";

  constructor(code: "session" | "enrollment" | "unsupported", message: string) {
    super(message);
    this.name = "EnrollmentFlowError";
    this.code = code;
  }
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype;
}

function hasExactKeys(value: Record<string, unknown>, expected: string[]): boolean {
  const actual = Object.keys(value).sort();
  const sortedExpected = [...expected].sort();
  return actual.length === sortedExpected.length && actual.every((key, index) => key === sortedExpected[index]);
}

function parseDeviceRefreshResponse(value: unknown, expectedDeviceId: string): DeviceRefreshRequestStatus {
  if (!isPlainRecord(value) || !hasExactKeys(value, ["request_id", "refresh_request"]) || typeof value.request_id !== "string" || !OPAQUE_ID.test(value.request_id)) {
    throw new Error("invalid refresh response");
  }
  const refreshRequest = value.refresh_request;
  if (!isPlainRecord(refreshRequest) || !hasExactKeys(refreshRequest, ["version", "request_id", "device_id", "desired_generation", "status", "requested_at"])) {
    throw new Error("invalid refresh response");
  }
  if (refreshRequest.version !== 1 || typeof refreshRequest.request_id !== "string" || !OPAQUE_ID.test(refreshRequest.request_id) || refreshRequest.device_id !== expectedDeviceId || typeof refreshRequest.device_id !== "string" || !OPAQUE_ID.test(refreshRequest.device_id)) {
    throw new Error("invalid refresh response");
  }
  if (refreshRequest.desired_generation !== null && (!Number.isSafeInteger(refreshRequest.desired_generation) || refreshRequest.desired_generation < 1)) {
    throw new Error("invalid refresh response");
  }
  if (typeof refreshRequest.status !== "string" || !new Set<DeviceRefreshRequestStatus>(["accepted", "coalesced", "no_pending_refresh"]).has(refreshRequest.status as DeviceRefreshRequestStatus) || typeof refreshRequest.requested_at !== "string" || !RFC3339_UTC.test(refreshRequest.requested_at) || !Number.isFinite(Date.parse(refreshRequest.requested_at))) {
    throw new Error("invalid refresh response");
  }
  return refreshRequest.status as DeviceRefreshRequestStatus;
}

function deviceRefreshOutcome(status: DeviceRefreshRequestStatus): string {
  return {
    accepted: "依頼を受け付けました。端末への配信は未確認です。",
    coalesced: "既存の依頼へ統合し、再通知しました。端末への配信は未確認です。",
    no_pending_refresh: "反映待ちの更新はなく、通知は送信していません。",
  }[status];
}

function parseCapabilityRecords(value: unknown, agentIds: ReadonlySet<string>, deviceIds: ReadonlySet<string>): NonNullable<AgentPassInitialData["capabilityRecords"]> {
  if (!isPlainRecord(value) || !Object.keys(value).every((key) => key === "capabilities" || key === "request_id") || !Array.isArray(value.capabilities)) throw new Error("invalid capability response");
  if (value.request_id !== undefined && (typeof value.request_id !== "string" || !OPAQUE_ID.test(value.request_id))) throw new Error("invalid capability response");
  if (value.capabilities.length > 100) throw new Error("invalid capability response");
  return value.capabilities.map((item) => {
    if (!isPlainRecord(item) || !hasExactKeys(item, ["version", "capability_id", "agent_id", "device_id", "expires_at", "sequence"])
      || item.version !== 1 || typeof item.capability_id !== "string" || !OPAQUE_ID.test(item.capability_id)
      || typeof item.agent_id !== "string" || !agentIds.has(item.agent_id)
      || typeof item.device_id !== "string" || !deviceIds.has(item.device_id)
      || typeof item.expires_at !== "string" || !validTimestamp(item.expires_at)
      || !Number.isSafeInteger(item.sequence) || (item.sequence as number) < 1) throw new Error("invalid capability response");
    return { capabilityId: item.capability_id, agentId: item.agent_id, deviceId: item.device_id, expiresAt: item.expires_at, sequence: item.sequence as number };
  });
}

function parseAdminActivities(value: unknown, organizationId: string): AgentPassInitialData["activities"] {
  if (!isPlainRecord(value) || !hasExactKeys(value, ["events"]) || !Array.isArray(value.events) || value.events.length > 100) throw new Error("invalid admin audit response");
  return value.events.slice().reverse().map((item) => {
    if (!isPlainRecord(item) || !Object.keys(item).every((key) => ["audit_event_id", "organization_id", "event_type", "actor_id", "target_type", "target_id", "details", "event_hash", "recorded_at"].includes(key))
      || !["audit_event_id", "organization_id", "event_type", "actor_id", "target_type", "details", "event_hash", "recorded_at"].every((key) => Object.hasOwn(item, key))
      || typeof item.audit_event_id !== "string" || !OPAQUE_ID.test(item.audit_event_id)
      || item.organization_id !== organizationId || typeof item.actor_id !== "string" || !OPAQUE_ID.test(item.actor_id)
      || typeof item.event_type !== "string" || !safeDisplayText(item.event_type, 128)
      || typeof item.target_type !== "string" || !safeDisplayText(item.target_type, 64)
      || (item.target_id !== undefined && (typeof item.target_id !== "string" || !OPAQUE_ID.test(item.target_id)))
      || !isPlainRecord(item.details) || containsSensitiveField(item.details)
      || typeof item.event_hash !== "string" || !/^[0-9a-f]{64}$/u.test(item.event_hash)
      || typeof item.recorded_at !== "string" || !validTimestamp(item.recorded_at)) throw new Error("invalid admin audit response");
    return { symbol: "⌁", title: item.event_type, description: `${item.target_type} · ${item.actor_id}`, time: item.recorded_at };
  });
}

function parseOrganizationStopped(value: unknown, organizationId: string): boolean {
  if (!isPlainRecord(value) || !Object.keys(value).every((key) => key === "revocations" || key === "request_id") || !Array.isArray(value.revocations) || value.revocations.length > 100) throw new Error("invalid revocation response");
  if (value.request_id !== undefined && (typeof value.request_id !== "string" || !OPAQUE_ID.test(value.request_id))) throw new Error("invalid revocation response");
  return value.revocations.some((item) => {
    const allowed = ["revocation_id", "organization_id", "target_type", "target_id", "reason", "status", "sequence", "created_at", "revoked_at", "version"];
    if (!isPlainRecord(item) || !Object.keys(item).every((key) => allowed.includes(key))
      || item.organization_id !== organizationId || typeof item.target_type !== "string" || !safeDisplayText(item.target_type, 64)
      || typeof item.status !== "string" || !["active", "revoked"].includes(item.status)) throw new Error("invalid revocation response");
    return item.target_type === "organization" && item.status === "active";
  });
}

function validTimestamp(value: string): boolean {
  if (!RFC3339_UTC.test(value) || !Number.isFinite(Date.parse(value))) return false;
  return new Date(value).toISOString().slice(0, 19) === value.slice(0, 19);
}

function safeDisplayText(value: string, maximum: number): boolean {
  return value.length > 0 && value.length <= maximum && ![...value].some((character) => (character.codePointAt(0) ?? 0) < 0x20 || character.codePointAt(0) === 0x7f);
}

function containsSensitiveField(value: Record<string, unknown>): boolean {
  const pending: unknown[] = [value];
  let visited = 0;
  while (pending.length) {
    const current = pending.pop();
    if (++visited > 256) return true;
    if (Array.isArray(current)) { pending.push(...current); continue; }
    if (!isPlainRecord(current)) continue;
    for (const [key, child] of Object.entries(current)) {
      if (/(?:authorization|cookie|credential|password|private[_-]?key|secret|token)/iu.test(key)) return true;
      pending.push(child);
    }
  }
  return false;
}

function parseSessionBootstrap(value: unknown): ConsoleSession {
  if (!isPlainRecord(value) || !hasExactKeys(value, ["session", "csrf_token"])) throw new ConsoleSessionError("セッションを確認できませんでした。ページを再読み込みして、もう一度お試しください。");
  const session = value.session;
  const csrfToken = value.csrf_token;
  if (!isPlainRecord(session) || typeof session.organization_id !== "string" || !UUID.test(session.organization_id) || typeof csrfToken !== "string" || !BASE64URL_CSRF.test(csrfToken)) {
    throw new ConsoleSessionError("セッションを確認できませんでした。ページを再読み込みして、もう一度お試しください。");
  }
  return { organizationId: session.organization_id, csrfToken };
}

function abortError(): DOMException {
  return new DOMException("The operation was aborted", "AbortError");
}

function throwIfAborted(signal?: AbortSignal): void {
  if (signal?.aborted) throw abortError();
}

function isAbortError(error: unknown): boolean {
  return error instanceof DOMException && error.name === "AbortError";
}

function clearConsoleSessionOnUnauthorized(error: unknown): void {
  if (error instanceof WebAuthnClientError && (error.status === 401 || error.status === 403)) consoleSessionContext.clear();
}

function withAbort<T>(promise: Promise<T>, signal?: AbortSignal): Promise<T> {
  throwIfAborted(signal);
  if (!signal) return promise;
  return new Promise<T>((resolve, reject) => {
    const onAbort = () => reject(abortError());
    signal.addEventListener("abort", onAbort, { once: true });
    promise.then((value) => {
      signal.removeEventListener("abort", onAbort);
      resolve(value);
    }, (error: unknown) => {
      signal.removeEventListener("abort", onAbort);
      reject(error);
    });
  });
}

async function bootstrapConsoleSession(signal?: AbortSignal): Promise<ConsoleSession> {
  throwIfAborted(signal);
  let response: Response;
  try {
    response = await fetch(SESSION_BOOTSTRAP_PATH, {
      method: "POST",
      headers: { accept: "application/json", "content-type": "application/json" },
      body: "{}",
      cache: "no-store",
      credentials: "same-origin",
      redirect: "error",
      signal,
    });
  } catch (error) {
    if (signal?.aborted || isAbortError(error)) throw abortError();
    throw new ConsoleSessionError("セッションを確認できませんでした。ページを再読み込みして、もう一度お試しください。");
  }
  if (!response.ok || !/^application\/json(?:\s*;|\s*$)/i.test(response.headers.get("content-type") ?? "")) {
    throw new ConsoleSessionError("セッションを確認できませんでした。ページを再読み込みして、もう一度お試しください。", response.status);
  }
  let payload: unknown;
  try {
    payload = await response.json();
  } catch {
    throw new ConsoleSessionError("セッションを確認できませんでした。ページを再読み込みして、もう一度お試しください。", response.status);
  }
  return parseSessionBootstrap(payload);
}

function createConsoleSessionContext() {
  let result: ConsoleSession | undefined;
  let pending: Promise<ConsoleSession> | undefined;

  const get = (signal?: AbortSignal): Promise<ConsoleSession> => {
    throwIfAborted(signal);
    if (result) return Promise.resolve(result);
    if (!pending) {
      const current = bootstrapConsoleSession(signal);
      const shared = current.then((value) => {
        result = Object.freeze(value);
        if (pending === shared) pending = undefined;
        return result;
      });
      pending = shared;
      void shared.catch(() => {
        if (pending === shared) pending = undefined;
      });
    }
    return withAbort(pending, signal);
  };

  const clear = (session?: ConsoleSession): void => {
    if (!session || result === session) result = undefined;
  };

  return Object.freeze({ get, clear });
}

const consoleSessionContext = createConsoleSessionContext();

let nextEnrollmentStoreId = 0;
const enrollmentStores = new Map<number, Record<string, string>>();

function allocateEnrollmentStoreId(): number {
  nextEnrollmentStoreId += 1;
  return nextEnrollmentStoreId;
}

function readEnrollmentStore(id: number): Record<string, string> | undefined {
  return enrollmentStores.get(id);
}

function writeEnrollmentStore(id: number, value: Record<string, string>): void {
  enrollmentStores.set(id, value);
}

function clearEnrollmentStore(id: number): void {
  enrollmentStores.delete(id);
}

function isMutationMethod(method: string): boolean {
  return method !== "GET" && method !== "HEAD" && method !== "OPTIONS";
}

async function fetchConsole(path: string, init: RequestInit = {}): Promise<Response> {
  const session = await consoleSessionContext.get(init.signal ?? undefined);
  const method = String(init.method ?? "GET").toUpperCase();
  const headers = new Headers(init.headers);
  headers.set("accept", "application/json");
  if (isMutationMethod(method)) headers.set(CSRF_HEADER, session.csrfToken);
  let response: Response;
  try {
    response = await fetch(path, {
      ...init,
      method,
      headers,
      cache: "no-store",
      credentials: "same-origin",
      redirect: "error",
    });
  } catch (error) {
    if (init.signal?.aborted || isAbortError(error)) throw abortError();
    throw error;
  }
  if (response.status === 401 || response.status === 403) consoleSessionContext.clear(session);
  return response;
}

async function logoutConsoleSession(): Promise<void> {
  const session = await consoleSessionContext.get();
  const response = await fetch(SESSION_BOOTSTRAP_PATH, {
    method: "DELETE",
    headers: { accept: "application/json", [CSRF_HEADER]: session.csrfToken },
    cache: "no-store",
    credentials: "same-origin",
    redirect: "error",
  });
  if (!response.ok || !/^application\/json(?:\s*;|\s*$)/i.test(response.headers.get("content-type") ?? "")) {
    if (response.status === 401 || response.status === 403) consoleSessionContext.clear(session);
    throw new ConsoleSessionError("サインアウトを完了できませんでした。", response.status);
  }
  const payload: unknown = await response.json();
  if (!isPlainRecord(payload) || !hasExactKeys(payload, ["session"]) || payload.session !== null) {
    throw new ConsoleSessionError("サインアウトを完了できませんでした。", response.status);
  }
  consoleSessionContext.clear(session);
}

function supportsWebAuthn(): boolean {
  return typeof window !== "undefined" && typeof window.PublicKeyCredential !== "undefined" && typeof navigator.credentials?.get === "function";
}

function supportsWebAuthnRegistration(): boolean {
  return typeof window !== "undefined" && typeof window.PublicKeyCredential !== "undefined" && typeof navigator.credentials?.create === "function";
}

function enrollmentErrorMessage(error: unknown): string {
  if (error instanceof ConsoleSessionError) return error.message;
  if (error instanceof EnrollmentFlowError) return error.message;
  if (error instanceof WebAuthnClientError) {
    if (error.code === "webauthn_unavailable" || error.code === "fetch_unavailable") return "このブラウザはTouch ID/パスキーに対応していません。対応ブラウザでお試しください。";
    if (error.code === "http_failed" && (error.status === 401 || error.status === 403)) return "セッションの有効期限が切れました。ページを再読み込みして、もう一度お試しください。";
    if (error.code === "aborted" || error.code === "webauthn_failed") return "Touch ID/パスキー確認を完了できませんでした。キャンセルした場合は、もう一度お試しください。";
    return "認証を確認できませんでした。ページを再読み込みして、もう一度お試しください。";
  }
  if (error instanceof DOMException && (error.name === "NotAllowedError" || error.name === "AbortError")) return "Touch ID/パスキー確認を完了できませんでした。キャンセルした場合は、もう一度お試しください。";
  return "登録情報を発行できませんでした。接続と権限を確認して、もう一度お試しください。";
}

function passkeyErrorMessage(error: unknown): string {
  if (error instanceof ConsoleSessionError) return error.message;
  if (error instanceof EnrollmentFlowError) return error.message;
  if (error instanceof WebAuthnClientError) {
    if (error.code === "webauthn_unavailable" || error.code === "fetch_unavailable") return "このブラウザはパスキー登録に対応していません。対応ブラウザでお試しください。";
    if (error.code === "http_failed" && (error.status === 401 || error.status === 403)) return "セッションの有効期限が切れました。ページを再読み込みして、もう一度お試しください。";
    if (error.code === "http_failed" && error.status === 409) return "このパスキーはすでに登録されているか、登録状態が更新されています。登録済みのパスキーを確認してください。";
    if (error.code === "aborted" || error.code === "webauthn_failed") return "パスキー登録を完了できませんでした。キャンセルした場合は、もう一度お試しください。";
    return "パスキーを登録できませんでした。ページを再読み込みして、もう一度お試しください。";
  }
  if (error instanceof DOMException && (error.name === "NotAllowedError" || error.name === "AbortError")) return "パスキー登録を完了できませんでした。キャンセルした場合は、もう一度お試しください。";
  return "パスキーを登録できませんでした。接続と権限を確認して、もう一度お試しください。";
}

const navItems: Array<{ id: ConsoleView; label: string; icon: string; badge?: string }> = [
  { id: "overview", label: "概要", icon: "⌂" },
  { id: "setup", label: "セットアップ", icon: "＋" },
  { id: "agents", label: "Agents", icon: "◈", badge: "3" },
  { id: "policies", label: "ポリシー", icon: "▤" },
  { id: "activity", label: "アクティビティ", icon: "◷" },
  { id: "security", label: "セキュリティ", icon: "◇" },
  { id: "organizations", label: "Organizations", icon: "◎" },
  { id: "recovery", label: "アカウント復旧", icon: "◌" },
  { id: "emergency", label: "緊急停止", icon: "■" },
];

function StatusTag({ tone, children }: { tone: "green" | "amber" | "red"; children: React.ReactNode }) {
  return <span className={`tag ${tone}`}>{children}</span>;
}

type DeviceStateLabel = "同期済み" | "反映待ち" | "ブロック中" | "古い状態" | "オフライン" | "失効済み";
type DeviceStateTone = "synced" | "pending" | "blocked" | "stale" | "offline" | "revoked";

function deviceState(device: AgentPassInitialData["devices"][number], now = Date.now()): DeviceStateTone {
  const refresh = device.refreshState?.toLowerCase();
  if (device.status === "停止" || device.status.toLowerCase() === "revoked" || refresh === "revoked" || refresh === "disabled") return "revoked";
  if (refresh === "offline" || refresh === "disconnected") return "offline";
  if (refresh === "blocked" || Boolean(device.blockedReason)) return "blocked";
  if (refresh === "stale" || (device.bundleExpiresAt && Date.parse(device.bundleExpiresAt) <= now)) return "stale";
  if (refresh === "pending" || refresh === "hinted" || refresh === "fetching" || refresh === "verifying" || refresh === "staging") return "pending";
  if (typeof device.desiredGeneration === "number" && typeof device.observedGeneration === "number" && device.desiredGeneration > device.observedGeneration) return "pending";
  return "synced";
}

function deviceStateLabel(state: DeviceStateTone): DeviceStateLabel {
  return { synced: "同期済み", pending: "反映待ち", blocked: "ブロック中", stale: "古い状態", offline: "オフライン", revoked: "失効済み" }[state];
}

function deviceStateDescription(state: DeviceStateTone): string {
  return {
    synced: "Cloudのdesired世代と端末のobserved世代が一致しています。",
    pending: "Cloudの更新を端末がまだ反映しています。",
    blocked: "更新がブロックされています。理由を確認してください。",
    stale: "Bundleの期限が切れているか、更新確認が必要です。",
    offline: "端末からの応答がありません。再接続後に同期されます。",
    revoked: "端末は失効済みです。新しい操作は許可されません。",
  }[state];
}

function deviceDate(value?: string): string {
  if (!value) return "未取得";
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return "日時不明";
  return new Intl.DateTimeFormat("ja-JP", { dateStyle: "medium", timeStyle: "short", timeZone: "Asia/Tokyo" }).format(parsed);
}

function DeviceStateCard({ device, onRequestRefresh }: { device: AgentPassInitialData["devices"][number]; onRequestRefresh: (deviceId: string) => Promise<DeviceRefreshRequestStatus> }) {
  const state = deviceState(device);
  const label = deviceStateLabel(state);
  const desired = device.desiredGeneration;
  const observed = device.observedGeneration;
  const hasProgress = typeof desired === "number" && typeof observed === "number";
  const progress = hasProgress ? Math.max(0, Math.min(100, desired === 0 ? 100 : Math.round((Math.min(observed, desired) / desired) * 100))) : 0;
  const canRequestRefresh = Boolean(device.deviceId && ["pending", "blocked", "stale", "offline"].includes(state));
  const [wakePending, setWakePending] = useState(false);
  const [wakeError, setWakeError] = useState("");
  const [wakeOutcome, setWakeOutcome] = useState("");
  const wakeInFlight = useRef(false);
  const requestWake = async () => {
    if (!canRequestRefresh || !device.deviceId || wakeInFlight.current) return;
    wakeInFlight.current = true;
    setWakePending(true);
    setWakeError("");
    setWakeOutcome("");
    try {
      const status = await onRequestRefresh(device.deviceId);
      setWakeOutcome(deviceRefreshOutcome(status));
    } catch {
      setWakeError("Wake requestを送信できませんでした。接続と権限を確認して、もう一度お試しください。");
    } finally {
      wakeInFlight.current = false;
      setWakePending(false);
    }
  };
  return (
    <article className={`health-card device-state-card state-${state}`} aria-busy={wakePending}>
      <div className="health-head">
        <div><h3 className="health-name">{device.name}</h3><p className="health-subtitle">{device.detail}</p></div>
        <span className="device-state-badge" data-state={state} aria-label={`同期状態: ${label}`}><span className="status-dot" aria-hidden="true" />{label}</span>
      </div>
      <p className="device-state-description">{deviceStateDescription(state)}</p>
      {canRequestRefresh ? <div className="device-wake-action">
        <button className="secondary-button device-wake-button" type="button" disabled={wakePending} onClick={() => void requestWake()}>{wakePending ? "Wake requestを送信中…" : "Wake requestを依頼"}</button>
        <p className="device-wake-copy">端末への配信は未確認です。適用・同期の完了を示す操作ではありません。</p>
        {wakeOutcome ? <p className="device-wake-outcome" role="status" aria-live="polite">{wakeOutcome}</p> : null}
        {wakeError ? <p className="device-wake-error" role="alert">{wakeError}</p> : null}
      </div> : null}
      <div className="device-sync-progress" aria-label={`${device.name}の世代反映状況`}>
        <div className="device-sync-progress-heading"><span>Cloud desired世代</span><strong>{desired ?? "未取得"}</strong><span aria-hidden="true">→</span><span>端末 observed世代</span><strong>{observed ?? "未取得"}</strong></div>
        {hasProgress ? <div className="device-sync-track" role="progressbar" aria-label="desired世代からobserved世代への反映状況" aria-valuemin={0} aria-valuemax={desired} aria-valuenow={Math.min(observed, desired)}><span style={{ width: `${progress}%` }} /></div> : <p className="device-sync-missing">世代情報を取得できていません。</p>}
      </div>
      <dl className="device-state-details">
        <div><dt>Bundle sequence</dt><dd>{device.bundleSequence ?? "未取得"}</dd></div>
        <div><dt>Bundle有効期限</dt><dd>{device.bundleExpiresAt ? <time dateTime={device.bundleExpiresAt}>{deviceDate(device.bundleExpiresAt)}</time> : "未取得"}</dd></div>
        <div><dt>最終ACK</dt><dd>{device.lastAckAt ? <time dateTime={device.lastAckAt}>{deviceDate(device.lastAckAt)}</time> : "未取得"}</dd></div>
        {state === "blocked" ? <div><dt>ブロック理由</dt><dd>{device.blockedReason || "理由はCloudで確認してください"}</dd></div> : null}
      </dl>
      <div className="health-details device-state-footer">
        <span className="health-detail"><span className="health-detail-label">ロケーション</span><span className="health-detail-value">{device.location}</span></span>
        <span className="health-detail"><span className="health-detail-label">最終確認</span><span className="health-detail-value">{device.checked}</span></span>
      </div>
    </article>
  );
}

function Overview({ data, goTo, onRequestRefresh, summaryState }: { data: AgentPassInitialData; goTo: (view: ConsoleView) => void; onRequestRefresh: (deviceId: string) => Promise<DeviceRefreshRequestStatus>; summaryState: "loading" | "ready" | "error" }) {
  const activeAgents = data.agents.filter((agent) => agent.state !== "停止").length;
  const connectedDevices = data.devices.filter((device) => device.status !== "停止").length;
  const protectedOperations = data.policies.length + data.capabilities.length;
  return (
    <>
      <header>
        <p className="eyebrow">運用コンソール / LIVE STATUS</p>
        <h1 className="page-heading">{summaryState === "ready" ? <>Agentの状態を、<br />確認できました。</> : <>Agentの状態を、<br />確認しています。</>}</h1>
        <p className="page-intro">
          Cloudから取得した端末、権限、監査状態だけを表示します。未検証の情報を安全状態として扱いません。
        </p>
      </header>

      <section className="hero-status" aria-labelledby="safe-status-heading">
        <div className="hero-message">
          <div className="status-kicker"><span className="status-check" aria-hidden="true">{summaryState === "ready" ? "✓" : "!"}</span> {summaryState === "ready" ? "SUMMARY VERIFIED" : summaryState === "loading" ? "SUMMARY LOADING" : "SUMMARY UNAVAILABLE"}</div>
          <h2 id="safe-status-heading" className="hero-title">{summaryState === "ready" ? "Agent status is available" : summaryState === "loading" ? "Cloudの状態を確認中です" : "安全状態を確認できません"}</h2>
          <p className="hero-copy">
            {summaryState === "ready" ? "Cloudが返した端末・Agent・ポリシー・監査情報を検証して表示しています。" : summaryState === "loading" ? "確認が完了するまで、表示上の情報を権限判断に使用しないでください。" : "Cloudの応答を検証できなかったため、運用データを消去しました。再同期してください。"}
          </p>
          <div className="hero-action">
            <button className="primary-button" type="button" onClick={() => goTo("setup")}>セットアップを確認する&nbsp; →</button>
            <button className="text-button" type="button" onClick={() => goTo("policies")}>ポリシーを見る</button>
          </div>
        </div>
        <div className="hero-meta">
          <div>
            <span className="meta-label">SESSION EXPIRES</span>
            <strong className="meta-value">情報未提供</strong>
            <p className="meta-detail">Summary APIはセッション権限を返しません</p>
          </div>
          <div>
            <span className="meta-label">CAPABILITIES</span>
            <strong className="meta-value">情報未提供</strong>
            <p className="meta-detail">Capability APIで個別に確認します</p>
          </div>
        </div>
      </section>

      <div className="metric-grid" aria-label="システム概要">
        <article className="metric-card">
          <div className="metric-topline"><span className="metric-title">有効なAgent登録</span><span className="metric-icon" aria-hidden="true">◈</span></div>
          <p className="metric-value">{activeAgents} / {data.agents.length}</p>
          <p className="metric-detail">Cloud上で有効な登録（接続状態ではありません）</p>
        </article>
        <article className="metric-card">
          <div className="metric-topline"><span className="metric-title">保護されている操作</span><span className="metric-icon" aria-hidden="true">◆</span></div>
          <p className="metric-value">{protectedOperations}項目</p>
          <p className="metric-detail">PolicyとCapabilityで保護中</p>
        </article>
        <article className="metric-card">
          <div className="metric-topline"><span className="metric-title">最終チェック</span><span className="metric-icon" aria-hidden="true">✓</span></div>
          <p className="metric-value">{connectedDevices}端末</p>
          <p className="metric-detail">{data.session.lastVerified}</p>
        </article>
      </div>

      <div className="section-heading-row">
        <div><span className="section-kicker">HEALTH CHECK</span><h2 className="section-heading">端末とCloudの健康状態</h2></div>
        <p className="section-note">自動更新：30秒ごと</p>
      </div>
      <div className="health-grid">
        {data.devices.map((device) => <DeviceStateCard device={device} onRequestRefresh={onRequestRefresh} key={device.deviceId ?? device.name} />)}
      </div>

      <div className="section-heading-row">
        <div><span className="section-kicker">RECENT ACTIVITY</span><h2 className="section-heading">最近のアクティビティ</h2></div>
        <button className="text-button" type="button" onClick={() => goTo("activity")}>すべて見る&nbsp; →</button>
      </div>
      <ActivityList activities={data.activities.slice(0, 3)} />
    </>
  );
}

function EmptyState({ title, copy }: { title: string; copy: string }) {
  return <div className="empty-state"><span className="empty-state-mark" aria-hidden="true">—</span><p className="empty-state-title">{title}</p><p className="empty-state-copy">{copy}</p></div>;
}

function ActivityList({ activities }: { activities: AgentPassInitialData["activities"] }) {
  if (!activities.length) return <EmptyState title="まだ記録はありません" copy="Agentが操作すると、ここに監査ログが表示されます。" />;
  return (
    <div className="activity-panel">
      <ul className="activity-list">
        {activities.map((activity) => (
          <li className="activity-item" key={`${activity.title}-${activity.time}`}>
            <span className="activity-symbol" aria-hidden="true">{activity.symbol}</span>
            <div><p className="activity-title">{activity.title}</p><p className="activity-description">{activity.description}</p></div>
            <time className="activity-time">{activity.time}</time>
          </li>
        ))}
      </ul>
    </div>
  );
}

function SurfaceHeader({ eyebrow, title, copy }: { eyebrow: string; title: string; copy: string }) {
  return <header className="surface-header"><div><p className="eyebrow">{eyebrow}</p><h1 className="page-heading">{title}</h1><p className="page-intro">{copy}</p></div></header>;
}

function SessionEndedSurface({ reason }: { reason: "expired" | "signed-out" }) {
  const signedOut = reason === "signed-out";
  return <><SurfaceHeader eyebrow={signedOut ? "SESSION / SIGNED OUT" : "SESSION / EXPIRED"} title={signedOut ? "サインアウトしました" : "セッションの有効期限が切れました"} copy={signedOut ? "このブラウザのAgentPassセッションを安全に終了しました。" : "安全のため、Consoleのデータと操作を停止しました。再認証してから続けてください。"} /><div className="surface-content"><article className="surface-card" role="alert"><span className="section-kicker">REAUTHENTICATION REQUIRED</span><h2 className="surface-card-title">もう一度サインインしてください</h2><p className="surface-card-copy">この画面に残っている情報は権限判断には使われません。ページを再読み込みすると、現在の認証状態から新しいセッションを開始します。</p><button className="primary-button" type="button" onClick={() => window.location.reload()}>再認証する</button></article></div></>;
}

function SetupSurface({ data, goTo, operate, online }: { data: AgentPassInitialData; goTo: (view: ConsoleView) => void; operate: (operation: string, body: Record<string, unknown>, success: string) => Promise<void>; online: boolean }) {
  const [deviceLabel, setDeviceLabel] = useState("");
  const [enrollmentStoreId] = useState(allocateEnrollmentStoreId);
  const [enrollmentVisible, setEnrollmentVisible] = useState(false);
  const [enrollmentPending, setEnrollmentPending] = useState(false);
  const [enrollmentError, setEnrollmentError] = useState("");
  const enrollmentInFlight = useRef(false);
  const [passkeyPending, setPasskeyPending] = useState(false);
  const [passkeyRegistered, setPasskeyRegistered] = useState(false);
  const [passkeyError, setPasskeyError] = useState("");
  const passkeyInFlight = useRef(false);
  const [agent, setAgent] = useState({ name: "", kind: "claude-code", public_key: "", device_id: data.devices[0]?.deviceId ?? "" });
  const [capabilityPending, setCapabilityPending] = useState(false);
  const defaultScope = data.policies.find((policy) => policy.scope)?.scope ?? { operations: ["git.commit.sign"], repositories: ["/"], branches: { allow: ["*"], deny: [] }, remotes: { allow: ["*"], deny: [] } };
  const issueCapability = async () => {
    const selectedAgent = data.agents.find((item) => item.agentId);
    const selectedDevice = data.devices.find((item) => item.deviceId);
    if (!selectedAgent?.agentId || !selectedDevice?.deviceId) return;
    setCapabilityPending(true);
    try { await operate("issue-capability", { agent_id: selectedAgent.agentId, device_id: selectedDevice.deviceId, scope: defaultScope, ttl_ms: 15 * 60 * 1000 }, "短期Capabilityを発行しました"); } finally { setCapabilityPending(false); }
  };
  const issueEnrollment = async () => {
    if (enrollmentInFlight.current) return;
    enrollmentInFlight.current = true;
    setEnrollmentPending(true);
    clearEnrollmentStore(enrollmentStoreId);
    setEnrollmentVisible(false);
    setEnrollmentError("");
    try {
      const { organizationId, csrfToken } = await consoleSessionContext.get();
      if (!supportsWebAuthn()) throw new EnrollmentFlowError("unsupported", "このブラウザはTouch ID/パスキーに対応していません。対応ブラウザでお試しください。");
      const { authorization_id } = await authenticateRecentAuth({
        operation: RECENT_AUTH_OPERATION,
        organizationId,
        csrfToken,
      });
      const response = await fetchConsole("/api/console?operation=issue-device-enrollment", {
        method: "POST",
        headers: { "content-type": "application/json", "idempotency-key": crypto.randomUUID(), "agentpass-recent-auth": authorization_id },
        body: JSON.stringify({ label: deviceLabel.trim(), platform: "macos", ttl_ms: 10 * 60 * 1000 }),
      });
      let payload: unknown;
      try { payload = await response.json(); } catch { throw new EnrollmentFlowError("enrollment", "登録情報を発行できませんでした。接続と権限を確認して、もう一度お試しください。"); }
      if (!response.ok || !isPlainRecord(payload) || !isPlainRecord(payload.enrollment)) throw new EnrollmentFlowError("enrollment", "登録情報を発行できませんでした。接続と権限を確認して、もう一度お試しください。");
      writeEnrollmentStore(enrollmentStoreId, payload.enrollment as Record<string, string>);
      setEnrollmentVisible(true);
    } catch (error) {
      clearConsoleSessionOnUnauthorized(error);
      setEnrollmentError(enrollmentErrorMessage(error));
    } finally {
      enrollmentInFlight.current = false;
      setEnrollmentPending(false);
    }
  };
  const registerPasskeyOnDevice = async () => {
    if (passkeyInFlight.current) return;
    passkeyInFlight.current = true;
    setPasskeyPending(true);
    setPasskeyRegistered(false);
    setPasskeyError("");
    try {
      const { organizationId, csrfToken } = await consoleSessionContext.get();
      if (!supportsWebAuthnRegistration()) throw new EnrollmentFlowError("unsupported", "このブラウザはパスキー登録に対応していません。対応ブラウザでお試しください。");
      await registerPasskey({ organizationId, csrfToken });
      setPasskeyRegistered(true);
    } catch (error) {
      clearConsoleSessionOnUnauthorized(error);
      setPasskeyError(passkeyErrorMessage(error));
    } finally {
      passkeyInFlight.current = false;
      setPasskeyPending(false);
    }
  };
  const enrollmentPayload = readEnrollmentStore(enrollmentStoreId);
  const enrollmentJson = enrollmentPayload ? JSON.stringify({ enrollment: enrollmentPayload }, null, 2) : "";
  useEffect(() => () => clearEnrollmentStore(enrollmentStoreId), [enrollmentStoreId]);
  useEffect(() => {
    if (!enrollmentVisible) return;
    const timer = window.setTimeout(() => {
      clearEnrollmentStore(enrollmentStoreId);
      setEnrollmentVisible(false);
    }, 5 * 60 * 1000);
    return () => window.clearTimeout(timer);
  }, [enrollmentStoreId, enrollmentVisible]);
  const copyEnrollment = async () => {
    await navigator.clipboard.writeText(enrollmentJson);
    window.setTimeout(() => void navigator.clipboard.writeText("").catch(() => {}), 60_000);
  };
  return (
    <>
      <SurfaceHeader eyebrow="SETUP / 01" title={<>まずは、<br />この3つだけ。</>} copy="難しい設定はAgentPassが保護します。いまの環境は、Agentが安全に作業できるところまで準備できています。" />
      <div className="surface-content">
        <article className="surface-card">
          <span className="section-kicker">CURRENT SESSION</span>
          <h2 className="surface-card-title">このセッションでできること</h2>
          <p className="surface-card-copy">セッションが切れると、Agentは作業を一時停止します。期限を過ぎる前に更新してください。</p>
          <ul className="row-list">
            {data.capabilities.map((capability, index) => <li className="row-list-item" key={capability}><div className="row-main"><span className="row-icon" aria-hidden="true">{index + 1}</span><div><p className="row-title">{capability}</p><p className="row-description">AgentPassの保護レイヤー内で許可されています</p></div></div><StatusTag tone="green">許可中</StatusTag></li>)}
          </ul>
          <div className="stop-action-row"><span className="section-note">有効期限：{data.session.expires}</span><button type="button" className="secondary-button" onClick={() => goTo("policies")}>権限を見直す</button></div>
        </article>
        <article className="surface-card">
          <span className="section-kicker">OPERATE SAFELY</span><h2 className="surface-card-title">安全な操作</h2>
          <p className="surface-card-copy">Capabilityは現在のPolicyの範囲に自動で絞られ、15分以内で失効します。</p>
          <button className="primary-button" type="button" disabled={capabilityPending || !data.agents.some((item) => item.agentId) || !data.devices.some((item) => item.deviceId)} onClick={issueCapability}>{capabilityPending ? "発行中…" : "短期Capabilityを発行"}</button>
          {data.capabilityRecords?.length ? <ul className="row-list">{data.capabilityRecords.map((capability) => <li className="row-list-item" key={capability.capabilityId}><div><p className="row-title">{capability.capabilityId}</p><p className="row-description">Agent {capability.agentId} · 端末 {capability.deviceId} · sequence {capability.sequence}</p></div><StatusTag tone="green">{capability.expiresAt.slice(0, 16).replace("T", " ")}まで</StatusTag></li>)}</ul> : <p className="row-description">発行済みの短期Capabilityはありません。</p>}
        </article>
        <article className="surface-card"><span className="section-kicker">DEVICES</span><h2 className="surface-card-title">登録済み端末</h2><ul className="row-list">{data.devices.map((device) => <li className="row-list-item" key={device.deviceId ?? device.name}><div><p className="row-title">{device.name}</p><p className="row-description">{device.deviceId ?? "ID未同期"} · {device.location}</p></div><span><StatusTag tone={device.status === "停止" ? "red" : "green"}>{device.status}</StatusTag>{device.deviceId && device.status !== "停止" ? <button className="text-button" type="button" onClick={() => operate("revoke-device", { target_id: device.deviceId, reason: "web-console-operator" }, `${device.name}を停止しました`)}>停止</button> : null}</span></li>)}</ul></article>
        <article className="surface-card">
          <span className="section-kicker">ACCOUNT SECURITY</span>
          <h2 className="surface-card-title">パスキーを登録</h2>
          <p className="surface-card-copy">このブラウザのTouch IDやパスキーを、AgentPassへのログインと重要操作の確認に使います。秘密鍵は端末の認証器から取り出されません。パスキーの名前は端末の認証器が管理します。</p>
          <button className="secondary-button" type="button" disabled={!online || passkeyPending} onClick={() => void registerPasskeyOnDevice()}>{passkeyPending ? "パスキーを登録中…" : "Touch ID / パスキーを登録"}</button>
          {passkeyRegistered ? <p className="section-note" role="status">パスキーを登録しました。この端末から重要操作を確認できます。</p> : null}
          {passkeyError ? <p className="form-error" role="alert">{passkeyError}</p> : null}
        </article>
        <article className="surface-card">
          <span className="section-kicker">ENROLL A MAC</span><h2 className="surface-card-title">Macを安全に追加</h2>
          <p className="surface-card-copy">10分だけ有効なワンタイム登録情報を発行します。秘密鍵はMacのSecure Enclave内で生成され、外へ出ません。</p>
          <div className="form-grid"><label>端末名<input required maxLength={128} autoComplete="off" value={deviceLabel} onChange={(event) => setDeviceLabel(event.target.value)} /></label></div>
          <button className="secondary-button" type="button" disabled={!online || enrollmentPending || !deviceLabel.trim()} onClick={issueEnrollment}>{enrollmentPending ? "認証・発行中…" : "Touch ID/パスキー確認"}</button>
          {enrollmentError ? <p className="form-error" role="alert">{enrollmentError}</p> : null}
          {enrollmentVisible ? <div className="enrollment-result" aria-live="polite"><p className="row-title">一度だけ表示しています</p><p className="surface-card-copy">下のJSONをMacへ安全に渡し、標準入力からセットアップしてください。5分後または再読込で消え、コピー内容も60秒後に消去を試みます。</p><pre className="secret-output">{enrollmentJson}</pre><div className="stop-action-row"><button className="primary-button" type="button" onClick={() => void copyEnrollment()}>JSONをコピー</button><button className="text-button" type="button" onClick={() => { clearEnrollmentStore(enrollmentStoreId); setEnrollmentVisible(false); }}>表示を消す</button></div><code className="command-hint">agentpass setup continue --execute --enrollment-url &lt;Cloud API URL&gt; --enrollment-stdin</code></div> : null}
        </article>
        <article className="surface-card">
          <span className="section-kicker">REGISTER</span><h2 className="surface-card-title">Agentを追加</h2>
          <p className="surface-card-copy">Agentの表示名・種類・公開鍵を登録し、端末に紐付けます。</p>
          <div className="form-grid"><label>Agent名<input value={agent.name} onChange={(event) => setAgent({ ...agent, name: event.target.value })} /></label><label>種類<input value={agent.kind} onChange={(event) => setAgent({ ...agent, kind: event.target.value })} /></label><label>公開鍵<textarea value={agent.public_key} onChange={(event) => setAgent({ ...agent, public_key: event.target.value })} /></label><label>端末ID<input value={agent.device_id} onChange={(event) => setAgent({ ...agent, device_id: event.target.value })} /></label></div>
          <button className="secondary-button" type="button" disabled={!agent.name || !agent.kind || !agent.public_key || !agent.device_id} onClick={async () => { await operate("create-agent", agent, "Agentを登録しました"); setAgent({ ...agent, name: "", public_key: "" }); }}>Agentを登録</button>
        </article>
        <div className="setup-steps">
          <article className="setup-step"><span className="setup-step-number">01</span><h3 className="setup-step-title">端末をつなぐ</h3><p className="setup-step-copy">Claude Code / Cursorの拡張機能を確認します。</p></article>
          <article className="setup-step"><span className="setup-step-number">02</span><h3 className="setup-step-title">できることを選ぶ</h3><p className="setup-step-copy">Agentに任せてよい操作だけを許可します。</p></article>
          <article className="setup-step"><span className="setup-step-number">03</span><h3 className="setup-step-title">作業を見守る</h3><p className="setup-step-copy">履歴を確認し、いつでも停止できます。</p></article>
        </div>
      </div>
    </>
  );
}

function AgentsSurface({ data, operate }: { data: AgentPassInitialData; operate: (operation: string, body: Record<string, unknown>, success: string) => Promise<void> }) {
  return <><SurfaceHeader eyebrow="AGENTS / 03" title="つながっているAgent" copy="Claude Code と Cursor の作業状態を、プロジェクト単位で確認できます。停止したAgentは新しい作業を開始できません。" /><div className="surface-content"><article className="surface-card"><span className="section-kicker">CONNECTED CLIENTS</span><h2 className="surface-card-title">現在の作業</h2>{data.agents.length ? <ul className="row-list">{data.agents.map((agent) => <li className="row-list-item" key={agent.agentId ?? agent.name}><div className="row-main"><span className="row-icon" aria-hidden="true">{agent.client === "Cursor" ? "C" : "A"}</span><div><p className="row-title">{agent.name}</p><p className="row-description">{agent.client} · {agent.detail}</p></div></div><span><StatusTag tone={agent.stateTone}>{agent.state}</StatusTag>{agent.agentId && agent.state !== "停止" ? <button className="text-button" type="button" onClick={() => operate("revoke-agent", { target_id: agent.agentId, reason: "web-console-operator" }, `${agent.name}を停止しました`)}>停止</button> : null}</span></li>)}</ul> : <EmptyState title="接続されたAgentはありません" copy="Claude CodeまたはCursorを端末から接続すると、ここに表示されます。" />}</article><article className="surface-card"><span className="section-kicker">DEVICE COVERAGE</span><h2 className="surface-card-title">端末のカバレッジ</h2><p className="surface-card-copy">確認済み端末からAgentを操作できます。端末を失った場合は、ここではなく端末の停止操作で即時に認証を止めてください。</p>{data.devices.length ? data.devices.map((device) => <p className="row-description" key={device.deviceId ?? device.name}>{device.name} · {device.deviceId ?? "ID未同期"}</p>) : <EmptyState title="登録済み端末はありません" copy="セットアップから端末を追加してください。" />}</article></div></>;
}

function PoliciesSurface({ data, operate }: { data: AgentPassInitialData; operate: (operation: string, body: Record<string, unknown>, success: string) => Promise<void> }) {
  const [name, setName] = useState("");
  const [repository, setRepository] = useState("/work/repo");
  const scope = { operations: ["git.commit.sign"], repositories: [repository], branches: { allow: ["*"], deny: ["main"] }, remotes: { allow: ["*"], deny: [] } };
  return <><SurfaceHeader eyebrow="POLICIES / 04" title="守られているルール" copy="Agentができること・できないことを、読みやすい言葉で表示しています。無効化したPolicyは新しいBundleに入りません。" /><div className="surface-content"><article className="surface-card"><span className="section-kicker">ACTIVE POLICIES</span><h2 className="surface-card-title">現在のポリシー</h2>{data.policies.length ? <ul className="row-list">{data.policies.map((policy) => <li className="row-list-item" key={policy.policyId ?? policy.name}><div className="row-main"><span className="row-icon" aria-hidden="true">◆</span><div><p className="row-title">{policy.name}</p><p className="row-description">{policy.detail}</p></div></div><span><StatusTag tone={policy.tone}>{policy.state}</StatusTag>{policy.policyId && policy.state === "保護中" ? <button className="text-button" type="button" onClick={() => operate("disable-policy", { policy_id: policy.policyId, expected_version: policy.version ?? 1, reason: "web-console-operator" }, `${policy.name}を無効化しました`)}>無効化</button> : null}</span></li>)}</ul> : <EmptyState title="ポリシーはまだありません" copy="最小限の権限から新しいルールを追加してください。" />}</article><article className="surface-card"><span className="section-kicker">CREATE POLICY</span><h2 className="surface-card-title">新しいルールを追加</h2><p className="surface-card-copy">許可範囲は狭く始め、必要なRepositoryだけを登録してください。</p><div className="form-grid"><label>ルール名<input required value={name} onChange={(event) => setName(event.target.value)} /></label><label>Repositoryの絶対パス<input required value={repository} onChange={(event) => setRepository(event.target.value)} /></label></div><button className="secondary-button" type="button" disabled={!name.trim() || !repository.trim()} onClick={async () => { await operate("create-policy", { name: name.trim(), scope }, "Policyを追加しました"); setName(""); }}>Policyを追加</button></article></div></>;
}

function ActivitySurface({ data }: { data: AgentPassInitialData }) {
  return <><SurfaceHeader eyebrow="ACTIVITY / 05" title="何が起きたか" copy="AgentPassが確認・許可・ブロックした操作を、時系列で記録しています。" /><div className="surface-content"><article className="surface-card"><span className="section-kicker">AUDIT LOG · TODAY</span><h2 className="surface-card-title">きょうの記録</h2><ActivityList activities={data.activities} /></article></div></>;
}

type SecurityLoadState = "loading" | "ready" | "error";

function securityErrorMessage(error: unknown): string {
  if (error instanceof DOMException && error.name === "AbortError") return "";
  if (error instanceof SecurityClientError && (error.status === 401 || error.status === 403)) return "セッションの有効期限が切れています。ページを再読み込みして、もう一度お試しください。";
  return "セキュリティ情報を取得できませんでした。接続と権限を確認して、もう一度お試しください。";
}

function securityDate(value: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "日時不明";
  return new Intl.DateTimeFormat("ja-JP", { dateStyle: "medium", timeStyle: "short", timeZone: "Asia/Tokyo" }).format(date);
}

function PasskeyRow({ passkey, actionKey, confirmKey, onRename, onRevoke, onCancelRevoke, onConfirmRevoke }: { passkey: SecurityPasskey; actionKey: string; confirmKey: string | null; onRename: () => void; onRevoke: () => void; onCancelRevoke: () => void; onConfirmRevoke: () => void }) {
  const busy = actionKey === `passkey:${passkey.id}`;
  const confirming = confirmKey === `passkey:${passkey.id}`;
  return <li className="row-list-item"><div className="row-main"><span className="row-icon" aria-hidden="true">⌁</span><div><p className="row-title">{passkey.label}</p><p className="row-description">登録：{securityDate(passkey.createdAt)} · 最終使用：{passkey.lastUsedAt ? securityDate(passkey.lastUsedAt) : "まだ使用されていません"}</p></div></div><span>{confirming ? <><button className="text-button" type="button" disabled={busy} onClick={onConfirmRevoke}>取り消す</button><button className="text-button" type="button" disabled={busy} onClick={onCancelRevoke}>キャンセル</button></> : <><button className="text-button" type="button" disabled={busy} onClick={onRename}>名前を変更</button><button className="text-button" type="button" disabled={busy} onClick={onRevoke}>無効化</button></>}</span></li>;
}

function SessionRow({ session, actionKey, confirmKey, onRevoke, onCancelRevoke, onConfirmRevoke }: { session: SecuritySession; actionKey: string; confirmKey: string | null; onRevoke: () => void; onCancelRevoke: () => void; onConfirmRevoke: () => void }) {
  const busy = actionKey === `session:${session.id}`;
  const confirming = confirmKey === `session:${session.id}`;
  return <li className="row-list-item"><div className="row-main"><span className="row-icon" aria-hidden="true">◌</span><div><p className="row-title">{session.label}{session.current ? "（この端末）" : ""}</p><p className="row-description">{session.platform} · 最終確認：{securityDate(session.lastSeenAt)} · 有効期限：{securityDate(session.expiresAt)}</p></div></div><span>{confirming ? <><button className="text-button" type="button" disabled={busy} onClick={onConfirmRevoke}>{session.current ? "サインアウト" : "取り消す"}</button><button className="text-button" type="button" disabled={busy} onClick={onCancelRevoke}>キャンセル</button></> : <>{session.current ? <StatusTag tone="green">現在のセッション</StatusTag> : null}<button className="text-button" type="button" disabled={busy} onClick={onRevoke}>{session.current ? "サインアウト" : "無効化"}</button></>}</span></li>;
}

function SecuritySurface() {
  const securityClientRef = useRef<SecurityClient | null>(null);
  if (securityClientRef.current === null) securityClientRef.current = createSecurityClient();
  const securityClient = securityClientRef.current;
  const [snapshot, setSnapshot] = useState<SecuritySnapshot | null>(null);
  const [loadState, setLoadState] = useState<SecurityLoadState>("loading");
  const [error, setError] = useState("");
  const [actionKey, setActionKey] = useState("");
  const [confirmKey, setConfirmKey] = useState<string | null>(null);
  const [renameTarget, setRenameTarget] = useState<string | null>(null);
  const [renameLabel, setRenameLabel] = useState("");
  const [notice, setNotice] = useState("");
  const [signedOut, setSignedOut] = useState(false);

  const load = useCallback(async (signal?: AbortSignal) => {
    setLoadState("loading");
    setError("");
    try {
      setSnapshot(await securityClient.getSnapshot({ signal }));
      setLoadState("ready");
    } catch (caught) {
      if (caught instanceof DOMException && caught.name === "AbortError") return;
      setLoadState("error");
      setError(securityErrorMessage(caught));
    }
  }, [securityClient]);

  useEffect(() => {
    const controller = new AbortController();
    const timer = window.setTimeout(() => void load(controller.signal), 0);
    return () => { window.clearTimeout(timer); controller.abort(); };
  }, [load]);

  const finishAction = async (key: string, action: () => Promise<void>, message: string, reload = true) => {
    if (actionKey) return;
    setActionKey(key);
    setError("");
    setNotice("");
    try {
      await action();
      setConfirmKey(null);
      setRenameTarget(null);
      setRenameLabel("");
      setNotice(message);
      if (reload) await load();
      else {
        setSignedOut(true);
        setSnapshot(null);
        setLoadState("ready");
      }
    } catch (caught) {
      setError(securityErrorMessage(caught));
    } finally {
      setActionKey("");
    }
  };

  const startRename = (passkey: SecurityPasskey) => {
    setConfirmKey(null);
    setRenameTarget(passkey.id);
    setRenameLabel(passkey.label);
    setNotice("");
  };

  const passkeys = snapshot?.passkeys ?? [];
  const sessions = snapshot?.sessions ?? [];
  const otherSessions = sessions.filter((session) => !session.current);
  return <><SurfaceHeader eyebrow="SECURITY / 06" title="アカウントを守る" copy="登録済みのパスキーと、AgentPassへ接続中のセッションを管理します。秘密鍵や認証器の内部データは、この画面には表示されません。" /><div className="surface-content">{signedOut ? <article className="surface-card"><span className="section-kicker">SIGNED OUT</span><h2 className="surface-card-title">このセッションを終了しました</h2><p className="surface-card-copy">現在のブラウザセッションを無効化し、セッション情報を画面から消去しました。続けるにはページを再読み込みしてください。</p></article> : <><article className="surface-card"><div className="stop-title-row"><div><span className="section-kicker">REGISTERED PASSKEYS</span><h2 className="surface-card-title">登録済みのパスキー</h2><p className="surface-card-copy">名前の変更や無効化ができます。無効化したパスキーは、以後の再認証に使えません。</p></div><button className="secondary-button" type="button" disabled={loadState === "loading"} onClick={() => void load()}>再読み込み</button></div>{loadState === "loading" ? <p className="section-note" role="status">読み込み中…</p> : loadState === "error" ? <div role="alert"><p className="section-note">{error}</p><button className="text-button" type="button" onClick={() => void load()}>もう一度試す</button></div> : passkeys.length ? <ul className="row-list">{passkeys.map((passkey) => <PasskeyRow key={passkey.id} passkey={passkey} actionKey={actionKey} confirmKey={confirmKey} onRename={() => startRename(passkey)} onRevoke={() => setConfirmKey(`passkey:${passkey.id}`)} onCancelRevoke={() => setConfirmKey(null)} onConfirmRevoke={() => void finishAction(`passkey:${passkey.id}`, () => securityClient.revokePasskey(passkey.id, passkey.version), "パスキーを無効化しました")} />)}</ul> : <EmptyState title="登録済みのパスキーはありません" copy="セットアップからTouch IDまたはパスキーを登録してください。" />}{renameTarget ? <form className="form-grid" onSubmit={(event) => { event.preventDefault(); const target = renameTarget; const passkey = passkeys.find((item) => item.id === target); if (!passkey) return; void finishAction(`passkey:${target}`, () => securityClient.renamePasskey(target, renameLabel, passkey.version), "パスキーの名前を変更しました"); }}><label>パスキーの表示名<input required maxLength={80} value={renameLabel} onChange={(event) => setRenameLabel(event.target.value)} autoComplete="off" /></label><div><button className="primary-button" type="submit" disabled={!renameLabel.trim() || Boolean(actionKey)}>保存</button><button className="text-button" type="button" disabled={Boolean(actionKey)} onClick={() => { setRenameTarget(null); setRenameLabel(""); }}>キャンセル</button></div></form> : null}</article><article className="surface-card"><div className="stop-title-row"><div><span className="section-kicker">ACTIVE SESSIONS</span><h2 className="surface-card-title">アクティブなセッション</h2></div><button className="secondary-button" type="button" disabled={loadState === "loading" || Boolean(actionKey) || otherSessions.length === 0} onClick={() => setConfirmKey("other-sessions")}>他のセッションをすべて無効化</button></div><p className="surface-card-copy">使っていないブラウザや端末のセッションは無効化してください。現在のセッションからサインアウトすることもできます。</p>{confirmKey === "other-sessions" ? <div className="stop-action-row"><span className="section-note">{otherSessions.length}件の他セッションを無効化します。</span><button className="text-button" type="button" disabled={Boolean(actionKey)} onClick={() => void finishAction("other-sessions", () => securityClient.revokeOtherSessions(sessions).then(() => undefined), "他のセッションをすべて無効化しました")}>確認</button><button className="text-button" type="button" disabled={Boolean(actionKey)} onClick={() => setConfirmKey(null)}>キャンセル</button></div> : null}{loadState === "loading" ? <p className="section-note" role="status">読み込み中…</p> : loadState === "error" ? <p className="section-note">セッション情報を取得できませんでした。</p> : sessions.length ? <ul className="row-list">{sessions.map((session) => <SessionRow key={session.id} session={session} actionKey={actionKey} confirmKey={confirmKey} onRevoke={() => setConfirmKey(`session:${session.id}`)} onCancelRevoke={() => setConfirmKey(null)} onConfirmRevoke={() => void finishAction(`session:${session.id}`, session.current ? () => securityClient.revokeCurrentSession(session.id, session.version) : () => securityClient.revokeSession(session.id, session.version), session.current ? "サインアウトしました" : "セッションを無効化しました", session.current ? false : true)} />)}</ul> : <EmptyState title="アクティブなセッションはありません" copy="再読み込みして、現在のログイン状態を確認してください。" />}</article>{notice ? <p className="section-note" role="status">✓ {notice}</p> : null}{error && loadState === "ready" ? <p className="section-note" role="alert">{error}</p> : null}</>}</div></>;
}

function EmergencySurface({ data, onOpenConfirm, stopped }: { data: AgentPassInitialData; onOpenConfirm: () => void; stopped: boolean }) {
  const activeCount = data.agents.filter((agent) => agent.state !== "停止").length;
  return <><SurfaceHeader eyebrow="EMERGENCY STOP / 06" title={<>いつでも、<br />止められます。</>} copy="Agentが予想外の動きをしたときは、すべての作業をただちに一時停止できます。" /><div className="surface-content"><article className="surface-card stop-card"><div className="stop-title-row"><div><span className="section-kicker">CONTROL ROOM</span><h2 className="surface-card-title">すべてのAgentを緊急停止</h2><p className="surface-card-copy">停止すると、有効なAgent登録に対する作業・セッション・キューを一時停止します。ファイルは削除されません。</p></div><span className="stop-mark" aria-hidden="true">■</span></div><div className="stop-action-row">{stopped ? <><StatusTag tone="red">停止済み</StatusTag><span className="section-note">すべてのAgentを停止しました。再開はセットアップから行えます。</span></> : <><span className="section-note">現在 {activeCount}件の有効なAgent登録があります</span><button type="button" className="danger-button" onClick={onOpenConfirm}>緊急停止を開始する</button></>}</div></article><article className="surface-card"><span className="section-kicker">WHEN TO USE</span><h2 className="surface-card-title">こんなときに使います</h2><ul className="row-list"><li className="row-list-item"><div className="row-main"><span className="row-icon" aria-hidden="true">!</span><div><p className="row-title">意図しないファイル変更が続いている</p><p className="row-description">作業を止めてから、アクティビティで操作を確認します。</p></div></div></li><li className="row-list-item"><div className="row-main"><span className="row-icon" aria-hidden="true">!</span><div><p className="row-title">不明なサービスへの接続が見つかった</p><p className="row-description">接続を止め、ポリシーと端末を確認します。</p></div></div></li></ul></article></div></>;
}

export function AgentPassConsole() {
  const [data, setData] = useState(emptyConsoleData);
  const [activeView, setActiveView] = useState<ConsoleView>("overview");
  const [mobileOpen, setMobileOpen] = useState(false);
  const [workspaceOpen, setWorkspaceOpen] = useState(false);
  const [helpOpen, setHelpOpen] = useState(false);
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [confirmChecked, setConfirmChecked] = useState(false);
  const [stopped, setStopped] = useState(false);
  const [toast, setToast] = useState("");
  const [toastTone, setToastTone] = useState<ToastTone>("success");
  const [stopPending, setStopPending] = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  const [summaryState, setSummaryState] = useState<"loading" | "ready" | "error">("loading");
  const [sessionState, setSessionState] = useState<"active" | "expired" | "signed-out">("active");
  const [signOutPending, setSignOutPending] = useState(false);
  const [lastSynced, setLastSynced] = useState("未同期");
  const modalRef = useRef<HTMLElement | null>(null);
  const summaryEpoch = useRef(0);
  const capabilityEpoch = useRef(0);
  const adminAuditEpoch = useRef(0);
  const organizationIdRef = useRef<string | null>(null);

  const showToast = (message: string, tone: ToastTone = "success") => {
    setToast(message);
    setToastTone(tone);
    window.setTimeout(() => setToast(""), 4200);
  };

  const refreshSummary = useCallback(async (signal?: AbortSignal) => {
    const epoch = ++summaryEpoch.current;
    setRefreshing(true);
    try {
      const { organizationId } = await consoleSessionContext.get(signal);
      const response = await fetchConsole("/api/console?resource=summary", { signal });
      if (response.status === 401 || response.status === 403) throw new ConsoleSessionError("セッションの有効期限が切れました。", response.status);
      if (!response.ok) throw new Error("summary unavailable");
      const next = summaryViewData(parseConsoleSummary(await response.json(), { organizationId }));
      if (epoch !== summaryEpoch.current) return;
      organizationIdRef.current = organizationId;
      setData(next);
      setSessionState("active");
      setSummaryState("ready");
      setLastSynced("たった今");
    } catch (error) {
      if (error instanceof DOMException && error.name === "AbortError") return;
      if (epoch !== summaryEpoch.current) return;
      organizationIdRef.current = null;
      if (error instanceof ConsoleSessionError && (error.status === 401 || error.status === 403)) {
        consoleSessionContext.clear();
        setSessionState("expired");
      }
      setSummaryState("error");
      setData(emptyConsoleData());
    } finally {
      if (!signal?.aborted && epoch === summaryEpoch.current) setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    if (!confirmOpen) return;
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") setConfirmOpen(false);
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [confirmOpen]);

  useEffect(() => {
    if (!helpOpen && !confirmOpen) return;
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key !== "Escape") return;
      setHelpOpen(false);
      setConfirmOpen(false);
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [helpOpen, confirmOpen]);

  useEffect(() => {
    if (!confirmOpen) return;
    modalRef.current?.querySelector<HTMLInputElement>("input")?.focus();
  }, [confirmOpen]);

  useEffect(() => {
    const controller = new AbortController();
    const timer = window.setTimeout(() => void refreshSummary(controller.signal), 0);
    return () => {
      window.clearTimeout(timer);
      controller.abort();
    };
  }, [refreshSummary]);

  useEffect(() => {
    if (summaryState !== "ready") return;
    const epoch = ++capabilityEpoch.current;
    const controller = new AbortController();
    const agentIds = new Set(data.agents.flatMap((agent) => agent.agentId ? [agent.agentId] : []));
    const deviceIds = new Set(data.devices.flatMap((device) => device.deviceId ? [device.deviceId] : []));
    Promise.all([
      consoleSessionContext.get(controller.signal),
      fetchConsole("/api/console?resource=capabilities&limit=100", { signal: controller.signal }),
      fetchConsole("/api/console?resource=revocations&limit=100", { signal: controller.signal }),
    ]).then(async ([session, capabilityResponse, revocationResponse]) => {
        if (!capabilityResponse.ok || !revocationResponse.ok) throw new Error("authority metadata unavailable");
        const records = parseCapabilityRecords(await capabilityResponse.json(), agentIds, deviceIds);
        const stopped = parseOrganizationStopped(await revocationResponse.json(), session.organizationId);
        if (controller.signal.aborted || epoch !== capabilityEpoch.current || session.organizationId !== organizationIdRef.current) return;
        setData((current) => ({ ...current, capabilityRecords: records }));
        setStopped(stopped);
      })
      .catch(() => { if (epoch === capabilityEpoch.current && !controller.signal.aborted) setData((current) => ({ ...current, capabilityRecords: [] })); });
    return () => controller.abort();
  }, [summaryState, data.agents, data.devices]);

  useEffect(() => {
    if (activeView !== "activity" || summaryState !== "ready") return;
    const epoch = ++adminAuditEpoch.current;
    const controller = new AbortController();
    Promise.all([consoleSessionContext.get(controller.signal), fetchConsole("/api/console?resource=admin-audit&limit=100", { signal: controller.signal })])
      .then(async ([session, response]) => {
        if (!response.ok) throw new Error("audit unavailable");
        const activities = parseAdminActivities(await response.json(), session.organizationId);
        if (controller.signal.aborted || epoch !== adminAuditEpoch.current || session.organizationId !== organizationIdRef.current) return;
        setData((current) => ({ ...current, activities }));
      })
      .catch(() => { if (epoch === adminAuditEpoch.current && !controller.signal.aborted) setData((current) => ({ ...current, activities: [] })); });
    return () => controller.abort();
  }, [activeView, summaryState]);

  const goTo = (view: ConsoleView) => {
    setActiveView(view);
    setMobileOpen(false);
    setWorkspaceOpen(false);
    window.scrollTo({ top: 0, behavior: "smooth" });
  };

  const signOut = async () => {
    if (signOutPending) return;
    setSignOutPending(true);
    try {
      await logoutConsoleSession();
      organizationIdRef.current = null;
      setData(emptyConsoleData());
      setSessionState("signed-out");
      setSummaryState("error");
    } catch (error) {
      if (error instanceof ConsoleSessionError && (error.status === 401 || error.status === 403)) {
        setData(emptyConsoleData());
        setSessionState("expired");
        setSummaryState("error");
      } else {
        showToast("サインアウトを完了できませんでした。もう一度お試しください", "error");
      }
    } finally {
      setSignOutPending(false);
    }
  };

  const triggerStop = async () => {
    setStopPending(true);
    try {
      const { organizationId, csrfToken } = await consoleSessionContext.get();
      if (!supportsWebAuthn()) throw new Error("WebAuthn unavailable");
      const { authorization_id } = await authenticateRecentAuth({ operation: EMERGENCY_STOP_RECENT_AUTH_OPERATION, organizationId, csrfToken });
      const response = await fetchConsole("/api/console?operation=emergency-stop", {
        method: "POST",
        headers: { "content-type": "application/json", "idempotency-key": crypto.randomUUID(), "agentpass-recent-auth": authorization_id },
        body: JSON.stringify({ reason: "web-console-emergency-stop" }),
      });
      if (!response.ok) throw new Error("stop rejected");
      setConfirmOpen(false);
      setConfirmChecked(false);
      setStopped(true);
      showToast("すべてのAgentを停止しました");
    } catch {
      showToast("停止を確認できませんでした。接続を確認して再試行してください", "error");
    } finally {
      setStopPending(false);
    }
  };

  const operate = async (operation: string, body: Record<string, unknown>, success: string) => {
    try {
      let recentAuthHeader: Record<string, string> = {};
      if (operation === "revoke-device") {
        const { organizationId, csrfToken } = await consoleSessionContext.get();
        if (!supportsWebAuthn()) throw new Error("WebAuthn unavailable");
        const { authorization_id } = await authenticateRecentAuth({ operation: DEVICE_REVOKE_RECENT_AUTH_OPERATION, organizationId, csrfToken });
        recentAuthHeader = { "agentpass-recent-auth": authorization_id };
      }
      const response = await fetchConsole(`/api/console?operation=${encodeURIComponent(operation)}`, {
        method: "POST",
        headers: { "content-type": "application/json", "idempotency-key": crypto.randomUUID(), ...recentAuthHeader },
        body: JSON.stringify(body),
      });
      if (!response.ok) throw new Error("operation rejected");
      showToast(success);
      await refreshSummary();
      const capabilityResponse = await fetchConsole("/api/console?resource=capabilities&limit=100");
      if (capabilityResponse.ok) {
        const payload = await capabilityResponse.json();
        const records = Array.isArray(payload.capabilities) ? payload.capabilities as Array<Record<string, unknown>> : [];
        setData((current) => ({ ...current, capabilityRecords: records.map((item) => ({ capabilityId: String(item.capability_id ?? ""), agentId: String(item.agent_id ?? ""), deviceId: String(item.device_id ?? ""), expiresAt: String(item.expires_at ?? ""), sequence: Number(item.sequence ?? 0) })) }));
      }
      return true;
    } catch {
      showToast("操作を確認できませんでした。権限と接続を確認してください", "error");
      return false;
    }
  };

  const requestDeviceRefresh = async (deviceId: string): Promise<DeviceRefreshRequestStatus> => {
    const { organizationId, csrfToken } = await consoleSessionContext.get();
    if (!supportsWebAuthn()) throw new Error("WebAuthn unavailable");
    const { authorization_id } = await authenticateRecentAuth({ operation: DEVICE_REFRESH_REQUEST_RECENT_AUTH_OPERATION, organizationId, csrfToken });
    const response = await fetchConsole("/api/console?operation=device.refresh.request", {
      method: "POST",
      headers: { "content-type": "application/json", "idempotency-key": crypto.randomUUID(), "agentpass-recent-auth": authorization_id },
      body: JSON.stringify({ target_id: deviceId }),
    });
    let payload: unknown;
    try {
      payload = await response.json();
    } catch {
      throw new Error("invalid refresh response");
    }
    if (response.status !== 202 || !response.ok) throw new Error("refresh request rejected");
    return parseDeviceRefreshResponse(payload, deviceId);
  };

  const currentLabel = navItems.find((item) => item.id === activeView)?.label ?? "概要";
  const activeAgents = data.agents.filter((agent) => agent.state !== "停止").length;

  return (
    <div className="console-shell">
      <aside className={`sidebar${mobileOpen ? " mobile-open" : ""}`} aria-label="メインナビゲーション">
        <a className="brand" href="#top" onClick={(event) => { event.preventDefault(); goTo("overview"); }}>
          <span className="brand-mark" aria-hidden="true">A</span>
          <span><span className="brand-name">AgentPass</span><span className="brand-note">CONSOLE</span></span>
        </a>
        <button className="workspace-switcher" type="button" aria-label={`${data.workspace}ワークスペースを選択`} aria-expanded={workspaceOpen} onClick={() => setWorkspaceOpen((open) => !open)}><span><span className="workspace-label">WORKSPACE</span><span className="workspace-name">{data.workspace}</span></span><span className="chevron" aria-hidden="true">⌄</span></button>
        {workspaceOpen ? <div className="workspace-menu" role="status"><strong>{data.workspace}</strong><span>現在のワークスペース</span><small>ワークスペースの切り替えは管理者設定から行います</small></div> : null}
        <p className="nav-label">MANAGE</p>
        <nav>
          <ul className="nav-list">
            {navItems.map((item) => <li key={item.id}><button className={`nav-item${activeView === item.id ? " active" : ""}${item.id === "emergency" ? " danger" : ""}`} type="button" onClick={() => goTo(item.id)} aria-current={activeView === item.id ? "page" : undefined}><span className="nav-icon" aria-hidden="true">{item.icon}</span><span className="nav-copy">{item.label}</span>{item.badge ? <span className="nav-badge">{item.badge}</span> : null}</button></li>)}
          </ul>
        </nav>
        <div className="sidebar-footer"><div className="operator"><span className="avatar" aria-hidden="true">{data.operator.initials}</span><div><p className="operator-name">{data.operator.name}</p><p className="operator-role">{data.operator.role}</p></div></div>{sessionState === "active" ? <button className="text-button" type="button" disabled={signOutPending} onClick={() => void signOut()}>{signOutPending ? "終了中…" : "サインアウト"}</button> : null}</div>
      </aside>

      <div className="main-column" id="top">
        <div className="topbar">
          <div className="breadcrumbs"><button className="mobile-menu" type="button" aria-label="メニューを開く" aria-expanded={mobileOpen} onClick={() => setMobileOpen((open) => !open)}>☰</button><span className="breadcrumb-root">AgentPass</span><span aria-hidden="true">/</span><span className="breadcrumb-current">{currentLabel}</span></div>
          <div className="topbar-actions"><span className={`connection-status${summaryState === "error" ? " is-error" : ""}`}><span className="status-dot" aria-hidden="true" />{summaryState === "error" ? "同期エラー" : refreshing || summaryState === "loading" ? "同期中…" : "応答検証済み"}</span><button className="refresh-button" type="button" onClick={() => void refreshSummary()} disabled={refreshing}>{refreshing ? "同期中" : `最終同期 ${lastSynced}`}</button><button className="help-button" type="button" aria-label="ヘルプを開く" aria-expanded={helpOpen} onClick={() => setHelpOpen(true)}>?</button><button className="icon-button" type="button" aria-label="アクティビティを見る" onClick={() => goTo("activity")}>◌</button></div>
        </div>
        <div className={`content${activeView === "organizations" || activeView === "recovery" ? " organization-content" : ""}`} role={activeView === "organizations" || activeView === "recovery" ? undefined : "main"}>
          {sessionState !== "active" ? <SessionEndedSurface reason={sessionState} /> : null}
          {sessionState === "active" && activeView === "overview" ? <Overview data={data} goTo={goTo} onRequestRefresh={requestDeviceRefresh} summaryState={summaryState} /> : null}
          {sessionState === "active" && activeView === "setup" ? <SetupSurface data={data} goTo={goTo} operate={operate} online={summaryState === "ready"} /> : null}
          {sessionState === "active" && activeView === "agents" ? <AgentsSurface data={data} operate={operate} /> : null}
          {sessionState === "active" && activeView === "policies" ? <PoliciesSurface data={data} operate={operate} /> : null}
          {sessionState === "active" && activeView === "activity" ? <ActivitySurface data={data} /> : null}
          {sessionState === "active" && activeView === "security" ? <SecuritySurface /> : null}
          {sessionState === "active" && activeView === "organizations" ? <OrganizationPanel /> : null}
          {sessionState === "active" && activeView === "recovery" ? <OwnerRecoveryPanel /> : null}
          {sessionState === "active" && activeView === "emergency" ? <EmergencySurface data={data} onOpenConfirm={() => setConfirmOpen(true)} stopped={stopped} /> : null}
        </div>
      </div>

      {mobileOpen ? <button className="mobile-scrim" type="button" aria-label="メニューを閉じる" onClick={() => setMobileOpen(false)} /> : null}
      {helpOpen ? <div className="modal-backdrop" role="presentation" onMouseDown={(event) => { if (event.currentTarget === event.target) setHelpOpen(false); }}><section className="help-modal" role="dialog" aria-modal="true" aria-labelledby="help-title"><div className="modal-header"><span className="modal-label">HELP / QUICK GUIDE</span><button className="modal-close" type="button" aria-label="ヘルプを閉じる" onClick={() => setHelpOpen(false)}>×</button></div><h2 className="modal-title" id="help-title">AgentPassの見方</h2><p className="modal-copy">Agentが作業を開始する前に、概要で「システム正常」と表示されていることを確認してください。</p><ul className="help-list"><li><strong>セットアップ</strong><span>端末・Agent・短期Capabilityを管理します。</span></li><li><strong>ポリシー</strong><span>Agentに許可する操作とRepositoryを絞ります。</span></li><li><strong>緊急停止</strong><span>不審な動きがあれば、すべてのAgentを即時停止できます。</span></li></ul><button className="secondary-button" type="button" onClick={() => { setHelpOpen(false); goTo("activity"); }}>監査ログを見る</button></section></div> : null}
      {confirmOpen ? <div className="modal-backdrop" role="presentation" onMouseDown={(event) => { if (!stopPending && event.currentTarget === event.target) setConfirmOpen(false); }}><section className="confirm-modal" ref={modalRef} role="dialog" aria-modal="true" aria-labelledby="confirm-title" aria-describedby="confirm-copy"><span className="modal-label">EMERGENCY STOP</span><h2 className="modal-title" id="confirm-title">Agentをすべて停止しますか？</h2><p className="modal-copy" id="confirm-copy">Cloud上で有効な{activeAgents}件のAgent登録を停止対象にします。現在の接続数を示すものではありません。</p><label className="confirm-check"><input type="checkbox" checked={confirmChecked} disabled={stopPending} onChange={(event) => setConfirmChecked(event.target.checked)} /><span>影響を理解しました。すべてのAgentを停止します。</span></label><div className="modal-actions"><button className="secondary-button" type="button" disabled={stopPending} onClick={() => setConfirmOpen(false)}>キャンセル</button><button className="danger-button" type="button" disabled={!confirmChecked || stopPending} onClick={triggerStop}>{stopPending ? "停止を配信中…" : "停止を確認する"}</button></div></section></div> : null}
      {toast ? <div className={`toast ${toastTone}`} role="status" aria-live="polite">{toastTone === "success" ? "✓" : "!"} {toast}</div> : null}
    </div>
  );
}
