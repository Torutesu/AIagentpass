"use client";

import { useCallback, useEffect, useMemo, useRef, useState, type RefObject } from "react";
import { authenticateRecentAuth, registerPasskey, WebAuthnClientError } from "../webauthn-client";
import { ConsoleSummaryParseError, parseConsoleSummary, type ConsoleSummaryViewModel } from "../console-summary";
import { parseDeploymentReadiness, type DeploymentReadiness } from "../deployment-readiness";
import { deriveAccessPosture, type AccessPostureInput, type PostureItem } from "../access-posture";
import { BROWSER_CLI_HANDOFF_EVENTS, BROWSER_CLI_HANDOFF_LIMITS, createBrowserCliHandoffDelivery, fetchBrowserCliHandoffPreflight, parseBrowserCliHandoffLaunchFragment, publicEnrollmentPreflight as publicBrowserCliEnrollmentPreflight, transitionBrowserCliHandoffState } from "../../lib/browser-cli-handoff.mjs";
import { OrganizationPanel } from "./OrganizationPanel";
import { createOrganizationClient, OrganizationClientError, resolveOrganizationSelection, type Organization, type OrganizationClient, type OrganizationSession } from "../organization-client";
import { loadOrganizationSwitcherOrganizations } from "../organization-switcher";
import { OwnerRecoveryPanel } from "./OwnerRecoveryPanel";
import { AuditExportPanel } from "./AuditExportPanel";
import { SecurityPanel } from "./SecurityPanel";
import { createSecurityClient, type SecurityClient } from "../security-client";
import { createSessionAuthority } from "../session-authority";

export type ConsoleView =
  | "overview"
  | "setup"
  | "agents"
  | "policies"
  | "activity"
  | "audit-exports"
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
  audit: Array<{ deviceId: string; chainStatus: "continuous" | "gap" | "unknown" }>;
  devices: Array<{
    deviceId?: string;
    name: string;
    detail: string;
    status: string;
    lifecycleStatus?: "pending" | "active" | "revoked";
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
  deployment: DeploymentReadiness | null;
};

function emptyConsoleData(): AgentPassInitialData {
  return {
    workspace: "ワークスペース未取得",
    operator: { name: "ユーザー情報未取得", role: "セッション確認中", initials: "—" },
    session: { expires: "未取得", remaining: "未取得", lastVerified: "未同期" },
    capabilities: [],
    capabilityRecords: [],
    audit: [],
    devices: [],
    agents: [],
    policies: [],
    activities: [],
    deployment: null,
  };
}

function summaryViewData(summary: ConsoleSummaryViewModel, deployment: DeploymentReadiness | null, session: ConsoleSession): AgentPassInitialData {
  const roleLabel = { owner: "Owner", admin: "Admin", auditor: "Auditor", viewer: "Viewer" }[session.role];
  const remainingMs = Math.max(0, Date.parse(session.expiresAt) - Date.now());
  const remainingMinutes = Math.ceil(remainingMs / 60_000);
  return {
    ...emptyConsoleData(),
    workspace: summary.organization.name,
    operator: { name: "認証済みメンバー", role: roleLabel, initials: roleLabel.slice(0, 1) },
    session: {
      expires: deviceDate(session.expiresAt),
      remaining: remainingMinutes > 0 ? `残り約${remainingMinutes}分` : "期限切れ",
      lastVerified: session.recentAuthAt ? deviceDate(session.recentAuthAt) : "追加認証なし",
    },
    devices: summary.devices.map((device) => ({
      deviceId: device.id,
      name: device.name,
      detail: device.refreshState ?? device.status,
      status: device.status === "revoked" ? "停止" : device.status === "pending" ? "登録待ち" : "正常",
      lifecycleStatus: device.status,
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
    audit: summary.audit.health.map((health) => ({ deviceId: health.deviceId, chainStatus: health.chainStatus })),
    deployment,
  };
}

type ToastTone = "success" | "error";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const OPAQUE_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
// PostgreSQL's JSON representation of timestamptz may use either the
// canonical `Z` suffix or the equivalent explicit UTC offset. Keep the
// accepted surface UTC-only and let Date perform the calendar validation.
const RFC3339_UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|\+00:00)$/;
const BASE64URL_CSRF = /^[A-Za-z0-9_-]{43}$/;
const RECENT_AUTH_OPERATION = "device.enrollment.issue";
const ENROLLMENT_CANDIDATE_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const ENROLLMENT_DEVICE_FINGERPRINT = /^SHA256:[A-Za-z0-9_-]{43}$/;
const ENROLLMENT_BASE64URL_32 = /^[A-Za-z0-9_-]{43}$/;
const ENROLLMENT_UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const ENROLLMENT_V2_KEYS = ["version", "proof_version", "enrollment_id", "organization_id", "device_id", "label", "platform", "candidate_binding", "challenge_id", "nonce", "expires_at", "challenge", "credential", "possession_receipt_verification", "endpoint"] as const;
const ENROLLMENT_BINDING_KEYS = ["version", "enrollment_id", "organization_id", "device_id", "candidate_id", "artifact_sha256", "source_commit", "team_id", "device_key_fingerprint", "expires_at"] as const;
const ENROLLMENT_CHALLENGE_KEYS = ["challenge_id", "nonce", "expires_at", "candidate_id", "device_key_fingerprint"] as const;
const ENROLLMENT_RECEIPT_KEYS = ["key_id", "algorithm", "public_key"] as const;
const DEVICE_REVOKE_RECENT_AUTH_OPERATION = "device.revoke";
const DEVICE_REFRESH_REQUEST_RECENT_AUTH_OPERATION = "device.refresh.request";
const EMERGENCY_STOP_RECENT_AUTH_OPERATION = "organization.emergency_stop";
const SESSION_BOOTSTRAP_PATH = "/api/auth/session";
const SESSION_RESUME_PATH = "/api/auth/session/resume";
const CSRF_HEADER = "agentpass-csrf";
const CONSOLE_SESSION_ENDED_EVENT = "agentpass:session-ended";
const MAX_ERROR_BODY_BYTES = 16_384;

type DeviceRefreshRequestStatus = "accepted" | "coalesced" | "no_pending_refresh";

type ConsoleRole = "owner" | "admin" | "auditor" | "viewer";
type ConsoleSession = Readonly<{
  version: number;
  sessionId: string;
  memberId: string;
  organizationId: string;
  role: ConsoleRole;
  createdAt: string;
  expiresAt: string;
  recentAuthAt: string | null;
  csrfToken: string;
}>;
type OrganizationSwitcherState = "closed" | "loading" | "ready" | "error";

const FOCUSABLE_SELECTOR = [
  "a[href]",
  "area[href]",
  "button:not([disabled])",
  "input:not([disabled])",
  "select:not([disabled])",
  "textarea:not([disabled])",
  "[contenteditable=\"true\"]",
  "[tabindex]:not([tabindex=\"-1\"])",
].join(",");

function getFocusableElements(container: HTMLElement | null): HTMLElement[] {
  if (!container) return [];
  return Array.from(container.querySelectorAll<HTMLElement>(FOCUSABLE_SELECTOR))
    .filter((element) => !element.hasAttribute("hidden") && element.getAttribute("aria-hidden") !== "true" && !element.closest("[hidden]"));
}

function focusFirstElement(container: HTMLElement | null): void {
  getFocusableElements(container)[0]?.focus();
}

function scrollConsoleToTop(): void {
  const reducedMotion = window.matchMedia?.("(prefers-reduced-motion: reduce)").matches ?? false;
  window.scrollTo({ top: 0, behavior: reducedMotion ? "auto" : "smooth" });
}

function useDeterministicDialogFocus(
  open: boolean,
  containerRef: RefObject<HTMLElement | null>,
  restoreRef: RefObject<HTMLElement | null>,
): void {
  const previousFocusRef = useRef<HTMLElement | null>(null);

  useEffect(() => {
    if (!open) return;
    previousFocusRef.current = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    const restoreTarget = restoreRef.current;
    const timer = window.setTimeout(() => {
      const initial = containerRef.current?.querySelector<HTMLElement>("[data-dialog-initial-focus]");
      if (initial) initial.focus();
      else focusFirstElement(containerRef.current);
    }, 0);
    return () => {
      window.clearTimeout(timer);
      const target = restoreTarget ?? previousFocusRef.current;
      if (target?.isConnected) target.focus();
      previousFocusRef.current = null;
    };
  }, [containerRef, open, restoreRef]);
}

class ConsoleSessionError extends Error {
  readonly status?: number;

  constructor(message: string, status?: number) {
    super(message);
    this.name = "ConsoleSessionError";
    this.status = status;
  }
}

function organizationSwitcherMessage(error: unknown): string {
  if (error instanceof OrganizationClientError && error.code === "forbidden") return "このセッションでは組織の一覧を確認できません。管理者にアクセス権を確認してもらってください。";
  if (error instanceof OrganizationClientError && error.code === "unauthorized") return "セッションの有効期限が切れています。この画面の再認証から続けてください。";
  return "組織の一覧を読み込めませんでした。下の「もう一度試す」を押して再読み込みしてください。";
}

class EnrollmentFlowError extends Error {
  readonly code: "session" | "enrollment" | "unsupported" | "outcome-unknown";

  constructor(code: "session" | "enrollment" | "unsupported" | "outcome-unknown", message: string) {
    super(message);
    this.name = "EnrollmentFlowError";
    this.code = code;
  }
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype;
}

function hasExactV2Keys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  return Object.keys(value).length === keys.length && keys.every((key) => Object.hasOwn(value, key));
}

type PublicEnrollmentPreflight = Readonly<{
  version: 1;
  platform: "macos";
  candidate_id: string;
  device_key_fingerprint: string;
}>;

type LiveHandoffStatus = "none" | "loading" | "connected" | "delivered" | "failed";
type LiveHandoffEvent = "launch" | "launch_failed" | "preflight_succeeded" | "preflight_failed" | "delivery_succeeded" | "delivery_failed";
type LiveHandoffPreflight = Readonly<{
  version: 1;
  correlation_id: string;
  nonce: string;
  platform: "macos";
  candidate_id: string;
  device_key_fingerprint: string;
}>;
type LiveHandoffDescriptor = Readonly<{
  url: string;
  preflight_url: string;
  correlation_id: string;
}>;
type LiveHandoffSession = Readonly<{
  url: string;
  preflight_url: string;
  correlation_id: string;
  preflight: LiveHandoffPreflight;
  delivery: Readonly<{
    deliver: (invitation: Record<string, unknown>) => Promise<true>;
  }>;
}>;
type LiveHandoffRef = { current: LiveHandoffSession | null };
type LiveHandoffDelivery = LiveHandoffSession["delivery"];
const createLiveHandoffDelivery = createBrowserCliHandoffDelivery as unknown as (options: { handoff: LiveHandoffDescriptor; preflight: LiveHandoffPreflight }) => LiveHandoffDelivery;

function parseV2EnrollmentInvitation(payload: unknown, organizationId: string, expectedPreflight: PublicEnrollmentPreflight): Record<string, unknown> {
  if (!isPlainRecord(payload) || !isPlainRecord(payload.enrollment)) throw new EnrollmentFlowError("enrollment", "登録情報の形式を検証できませんでした。もう一度発行してください。");
  const enrollment = payload.enrollment;
  if (!hasExactV2Keys(enrollment, ENROLLMENT_V2_KEYS) || enrollment.version !== 2 || enrollment.proof_version !== 2
    || enrollment.organization_id !== organizationId || enrollment.platform !== "macos"
    || typeof enrollment.label !== "string" || !ENROLLMENT_UUID_V4.test(String(enrollment.enrollment_id))
    || !ENROLLMENT_UUID_V4.test(String(enrollment.device_id)) || enrollment.challenge_id !== enrollment.enrollment_id
    || typeof enrollment.nonce !== "string" || !ENROLLMENT_BASE64URL_32.test(enrollment.nonce)
    || typeof enrollment.credential !== "string" || !ENROLLMENT_BASE64URL_32.test(enrollment.credential)
    || typeof enrollment.expires_at !== "string" || Date.parse(enrollment.expires_at) <= Date.now()
    || enrollment.endpoint !== `/v1/enrollments/${enrollment.enrollment_id}`) {
    throw new EnrollmentFlowError("enrollment", "登録情報の形式を検証できませんでした。もう一度発行してください。");
  }
  if (!isPlainRecord(enrollment.candidate_binding) || !hasExactV2Keys(enrollment.candidate_binding, ENROLLMENT_BINDING_KEYS)
    || enrollment.candidate_binding.enrollment_id !== enrollment.enrollment_id || enrollment.candidate_binding.organization_id !== organizationId
    || enrollment.candidate_binding.device_id !== enrollment.device_id || enrollment.candidate_binding.expires_at !== enrollment.expires_at
    || !ENROLLMENT_CANDIDATE_ID.test(String(enrollment.candidate_binding.candidate_id))
    || !ENROLLMENT_DEVICE_FINGERPRINT.test(String(enrollment.candidate_binding.device_key_fingerprint))
    || enrollment.candidate_binding.candidate_id !== expectedPreflight.candidate_id
    || enrollment.candidate_binding.device_key_fingerprint !== expectedPreflight.device_key_fingerprint) {
    throw new EnrollmentFlowError("enrollment", "登録対象のリリースまたは端末キーを検証できませんでした。");
  }
  if (!isPlainRecord(enrollment.challenge) || !hasExactV2Keys(enrollment.challenge, ENROLLMENT_CHALLENGE_KEYS)
    || enrollment.challenge.challenge_id !== enrollment.enrollment_id || enrollment.challenge.nonce !== enrollment.nonce
    || enrollment.challenge.expires_at !== enrollment.expires_at || enrollment.challenge.candidate_id !== enrollment.candidate_binding.candidate_id
    || enrollment.challenge.device_key_fingerprint !== enrollment.candidate_binding.device_key_fingerprint) {
    throw new EnrollmentFlowError("enrollment", "登録チャレンジの束縛を検証できませんでした。");
  }
  if (!isPlainRecord(enrollment.possession_receipt_verification) || !hasExactV2Keys(enrollment.possession_receipt_verification, ENROLLMENT_RECEIPT_KEYS)
    || !["ed25519", "p256-sha256"].includes(String(enrollment.possession_receipt_verification.algorithm))
    || typeof enrollment.possession_receipt_verification.key_id !== "string"
    || typeof enrollment.possession_receipt_verification.public_key !== "string"
    || /PRIVATE\s+KEY/i.test(enrollment.possession_receipt_verification.public_key)) {
    throw new EnrollmentFlowError("enrollment", "署名レシートの検証情報を確認できませんでした。");
  }
  return enrollment;
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
  if (refreshRequest.desired_generation !== null && (!Number.isSafeInteger(refreshRequest.desired_generation as number) || (refreshRequest.desired_generation as number) < 1)) {
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
  if (!isPlainRecord(session) || !hasExactKeys(session, ["version", "session_id", "member_id", "organization_id", "role", "created_at", "expires_at", "recent_auth_at"])
    || session.version !== 1 || typeof session.session_id !== "string" || !UUID.test(session.session_id)
    || typeof session.member_id !== "string" || !UUID.test(session.member_id)
    || typeof session.organization_id !== "string" || !UUID.test(session.organization_id)
    || !new Set<ConsoleRole>(["owner", "admin", "auditor", "viewer"]).has(session.role as ConsoleRole)
    || typeof session.created_at !== "string" || !validTimestamp(session.created_at)
    || typeof session.expires_at !== "string" || !validTimestamp(session.expires_at)
    || (session.recent_auth_at !== null && (typeof session.recent_auth_at !== "string" || !validTimestamp(session.recent_auth_at)))
    || typeof csrfToken !== "string" || !BASE64URL_CSRF.test(csrfToken)) {
    throw new ConsoleSessionError("セッションを確認できませんでした。ページを再読み込みして、もう一度お試しください。");
  }
  return {
    version: session.version,
    sessionId: session.session_id,
    memberId: session.member_id,
    organizationId: session.organization_id,
    role: session.role as ConsoleRole,
    createdAt: session.created_at,
    expiresAt: session.expires_at,
    recentAuthAt: session.recent_auth_at as string | null,
    csrfToken,
  };
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

async function requestConsoleSession(path: string, signal?: AbortSignal): Promise<{ response: Response; payload: unknown }> {
  throwIfAborted(signal);
  let response: Response;
  try {
    response = await fetch(path, {
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
  if (!/^application\/json(?:\s*;|\s*$)/i.test(response.headers.get("content-type") ?? "")) {
    throw new ConsoleSessionError("セッションを確認できませんでした。ページを再読み込みして、もう一度お試しください。", response.status);
  }
  let payload: unknown;
  try {
    payload = await response.json();
  } catch {
    throw new ConsoleSessionError("セッションを確認できませんでした。ページを再読み込みして、もう一度お試しください。", response.status);
  }
  return { response, payload };
}

function isSessionResumeRequired(response: Response, payload: unknown): boolean {
  return response.status === 401
    && isPlainRecord(payload)
    && hasExactKeys(payload, ["error"])
    && isPlainRecord(payload.error)
    && hasExactKeys(payload.error, ["code", "message"])
    && payload.error.code === "human_session_session_required"
    && typeof payload.error.message === "string";
}

async function bootstrapConsoleSession(signal?: AbortSignal): Promise<ConsoleSession> {
  const resumed = await requestConsoleSession(SESSION_RESUME_PATH, signal);
  if (isSessionResumeRequired(resumed.response, resumed.payload)) {
    const bootstrapped = await requestConsoleSession(SESSION_BOOTSTRAP_PATH, signal);
    if (!bootstrapped.response.ok) {
      throw new ConsoleSessionError("セッションを確認できませんでした。ページを再読み込みして、もう一度お試しください。", bootstrapped.response.status);
    }
    return parseSessionBootstrap(bootstrapped.payload);
  }
  if (!resumed.response.ok) {
    throw new ConsoleSessionError("セッションを確認できませんでした。ページを再読み込みして、もう一度お試しください。", resumed.response.status);
  }
  return parseSessionBootstrap(resumed.payload);
}

const consoleSessionContext = createSessionAuthority<ConsoleSession>(bootstrapConsoleSession);

function isMutationMethod(method: string): boolean {
  return method !== "GET" && method !== "HEAD" && method !== "OPTIONS";
}

async function responseEndsConsoleSession(response: Response): Promise<boolean> {
  if (response.status !== 401 && response.status !== 403) return false;
  let code = "";
  try {
    const text = await response.clone().text();
    if (text.length <= MAX_ERROR_BODY_BYTES) {
      const payload: unknown = JSON.parse(text);
      if (isPlainRecord(payload) && isPlainRecord(payload.error) && typeof payload.error.code === "string") code = payload.error.code;
    }
  } catch {
    // An unparseable 401 is still an authentication failure. A 403 is an
    // operation denial unless the server explicitly identifies the session.
  }
  if (/recent[_-]?auth/u.test(code)) return false;
  if (response.status === 401) return true;
  return ["authentication_required", "human_session_invalid", "session_expired", "session_revoked", "session_not_found", "invalid_session_cookie"].includes(code);
}

async function fetchConsole(path: string, init: RequestInit = {}, sessionOverride?: ConsoleSession): Promise<Response> {
  // A recent-authenticated mutation must use the exact session snapshot that
  // was supplied to the WebAuthn ceremony. Re-reading the authority after
  // that ceremony creates a race with session invalidation/rotation: the
  // proof can belong to one session while the CSRF-bound mutation belongs to
  // another. Callers that do not own a ceremony continue to use the shared
  // authority as before.
  const session = sessionOverride ?? await consoleSessionContext.get(init.signal ?? undefined);
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
  if (await responseEndsConsoleSession(response)) {
    consoleSessionContext.clear(session);
    if (typeof window !== "undefined") window.dispatchEvent(new Event(CONSOLE_SESSION_ENDED_EVENT));
  }
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

function isEnrollmentOutcomeUnknown(error: unknown): boolean {
  return error instanceof EnrollmentFlowError && error.code === "outcome-unknown";
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

const navItems: Array<{ id: ConsoleView; label: string; icon: string }> = [
  { id: "overview", label: "概要", icon: "⌂" },
  { id: "setup", label: "セットアップ", icon: "＋" },
  { id: "agents", label: "Agents", icon: "◈" },
  { id: "policies", label: "ポリシー", icon: "▤" },
  { id: "activity", label: "アクティビティ", icon: "◷" },
  { id: "audit-exports", label: "監査エクスポート", icon: "⇩" },
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
  return ({ synced: "同期済み", pending: "反映待ち", blocked: "ブロック中", stale: "古い状態", offline: "オフライン", revoked: "失効済み" } as Record<DeviceStateTone, DeviceStateLabel>)[state];
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

function DeviceStateCard({ device, onRequestRefresh, canManage }: { device: AgentPassInitialData["devices"][number]; onRequestRefresh: (deviceId: string) => Promise<DeviceRefreshRequestStatus>; canManage: boolean }) {
  const state = deviceState(device);
  const label = deviceStateLabel(state);
  const desired = device.desiredGeneration;
  const observed = device.observedGeneration;
  const hasProgress = typeof desired === "number" && typeof observed === "number";
  const progress = hasProgress ? Math.max(0, Math.min(100, desired === 0 ? 100 : Math.round((Math.min(observed, desired) / desired) * 100))) : 0;
  const canRequestRefresh = Boolean(device.deviceId && ["pending", "blocked", "stale", "offline"].includes(state));
  const canRequestRefreshForRole = canManage && canRequestRefresh;
  const [wakePending, setWakePending] = useState(false);
  const [wakeError, setWakeError] = useState("");
  const [wakeOutcome, setWakeOutcome] = useState("");
  const wakeInFlight = useRef(false);
  const requestWake = async () => {
    if (!canRequestRefreshForRole || !device.deviceId || wakeInFlight.current) return;
    wakeInFlight.current = true;
    setWakePending(true);
    setWakeError("");
    setWakeOutcome("");
    try {
      const status = await onRequestRefresh(device.deviceId);
      setWakeOutcome(deviceRefreshOutcome(status));
    } catch {
      setWakeError("Wake requestを送信できませんでした。接続と権限を確認し、この端末カードのボタンからもう一度お試しください。");
    } finally {
      wakeInFlight.current = false;
      setWakePending(false);
    }
  };
  const requestWakeWithConfirmation = () => {
    if (wakePending || wakeInFlight.current) return;
    setWakeError("");
    setWakeOutcome("");
    setWakeConfirming(true);
  };
  const [wakeConfirming, setWakeConfirming] = useState(false);
  return (
    <article className={`health-card device-state-card state-${state}`} aria-busy={wakePending}>
      <div className="health-head">
        <div><h3 className="health-name">{device.name}</h3><p className="health-subtitle">{device.detail}</p></div>
        <span className="device-state-badge" data-state={state} aria-label={`同期状態: ${label}`}><span className="status-dot" aria-hidden="true" />{label}</span>
      </div>
      <p className="device-state-description">{deviceStateDescription(state)}</p>
      {canRequestRefreshForRole ? <div className="device-wake-action">
        {wakeConfirming && !wakePending ? <span className="operation-control"><span className="section-note" role="status" aria-live="polite">端末へWake requestを送信します。適用完了はこの操作では確認しません。</span><button className="secondary-button device-wake-button" type="button" onClick={() => { setWakeConfirming(false); void requestWake(); }}>確認して送信</button><button className="text-button" type="button" onClick={() => setWakeConfirming(false)}>キャンセル</button></span> : <button className="secondary-button device-wake-button" type="button" disabled={wakePending} onClick={requestWakeWithConfirmation}>{wakePending ? "Wake requestを送信中…" : "Wake requestを依頼"}</button>}
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

function Overview({ data, session, goTo, onRequestRefresh, onRefresh, onSessionEnded, summaryState, canManage, stopped }: { data: AgentPassInitialData; session: ConsoleSession | null; goTo: (view: ConsoleView) => void; onRequestRefresh: (deviceId: string) => Promise<DeviceRefreshRequestStatus>; onRefresh: () => void; onSessionEnded: () => void; summaryState: "loading" | "ready" | "error"; canManage: boolean; stopped: boolean }) {
  const activeAgents = data.agents.filter((agent) => agent.state !== "停止").length;
  const connectedDevices = data.devices.filter((device) => device.status !== "停止").length;
  const protectedOperations = data.policies.length + data.capabilities.length;
  return (
    <>
      <header>
        <p className="eyebrow">運用コンソール / LIVE STATUS</p>
        <h1 className="page-heading" id="console-page-heading">{summaryState === "ready" ? <>Agentの状態を、<br />確認できました。</> : <>Agentの状態を、<br />確認しています。</>}</h1>
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
            <strong className="meta-value">{data.session.remaining}</strong>
            <p className="meta-detail">{data.session.expires}</p>
          </div>
          <div>
            <span className="meta-label">CAPABILITIES</span>
            <strong className="meta-value">{data.capabilityRecords?.length ?? 0}件</strong>
            <p className="meta-detail">短期権限のライフサイクル情報のみ表示</p>
          </div>
          <div>
            <span className="meta-label">DEPLOYMENT VERIFIED</span>
            <strong className="meta-value">{data.deployment?.deploymentIdentity.revision ?? "未確認"}</strong>
            <p className="meta-detail">source / schema / catalogを束縛</p>
          </div>
        </div>
      </section>

      <OperationalPosture data={data} session={session} summaryState={summaryState} stopped={stopped} goTo={goTo} onRefresh={onRefresh} onSessionEnded={onSessionEnded} />

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
        {data.devices.map((device) => <DeviceStateCard device={device} onRequestRefresh={onRequestRefresh} canManage={canManage} key={device.deviceId ?? device.name} />)}
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

function SurfaceHeader({ eyebrow, title, copy }: { eyebrow: string; title: React.ReactNode; copy: string }) {
  return <header className="surface-header"><div><p className="eyebrow">{eyebrow}</p><h1 className="page-heading" id="console-page-heading">{title}</h1><p className="page-intro">{copy}</p></div></header>;
}

function SessionEndedSurface({ reason }: { reason: "expired" | "signed-out" }) {
  const signedOut = reason === "signed-out";
  return <><SurfaceHeader eyebrow={signedOut ? "SESSION / SIGNED OUT" : "SESSION / EXPIRED"} title={signedOut ? "サインアウトしました" : "セッションの有効期限が切れました"} copy={signedOut ? "このブラウザのAgentPassセッションを安全に終了しました。" : "安全のため、Consoleのデータと操作を停止しました。再認証してから続けてください。"} /><div className="surface-content"><article className="surface-card" role="alert"><span className="section-kicker">REAUTHENTICATION REQUIRED</span><h2 className="surface-card-title">もう一度サインインしてください</h2><p className="surface-card-copy">この画面に残っている情報は権限判断には使われません。ページを再読み込みすると、現在の認証状態から新しいセッションを開始します。</p><button className="primary-button" type="button" onClick={() => window.location.reload()}>再認証する</button></article></div></>;
}

type IssuedEnrollmentSummary = Readonly<{ enrollmentId: string; deviceId: string; label: string; candidateId: string; deviceKeyFingerprint: string; expiresAt: string }>;

type SummaryRefreshResult = "ready" | "unavailable";
type EnrollmentReconciliationState = "checking" | "pending" | "enrolled" | "response-loss" | "timed-out";
const ENROLLMENT_RECONCILIATION_MAX_ATTEMPTS = 5;
const ENROLLMENT_RECONCILIATION_INITIAL_DELAY_MS = 250;
const ENROLLMENT_RECONCILIATION_RETRY_DELAY_MS = 2_500;

function enrollmentProgress(device: AgentPassInitialData["devices"][number] | undefined): "pending" | "enrolled" | "recovery-proven" {
  if (!device || device.lifecycleStatus === "pending") return "pending";
  // A signed device ACK proves that the enrolled device observed control state,
  // but it is not the v2 possession receipt. The Console must not promote this
  // observation to recovery-proven without the native receipt verification.
  return device.lifecycleStatus === "active" && device.lastAckAt ? "enrolled" : "enrolled";
}

function progressLabel(progress: "pending" | "enrolled" | "recovery-proven"): string {
  return ({
    pending: "受け入れ待ち",
    enrolled: "登録済み",
    "recovery-proven": "復旧確認済み",
  } as const)[progress];
}

function EnrollmentReconciliationCard({ progress, refresh }: { progress: "pending" | "enrolled" | "recovery-proven"; refresh: () => Promise<SummaryRefreshResult> }) {
  const [state, setState] = useState<EnrollmentReconciliationState>(progress === "pending" ? "checking" : "enrolled");
  const [cycle, setCycle] = useState(0);
  const [attempts, setAttempts] = useState(0);
  const attemptRef = useRef(0);
  const inFlightRef = useRef(false);

  useEffect(() => {
    if (progress !== "pending") return;
    if (attemptRef.current >= ENROLLMENT_RECONCILIATION_MAX_ATTEMPTS) return;

    let cancelled = false;
    const delay = attemptRef.current === 0 ? ENROLLMENT_RECONCILIATION_INITIAL_DELAY_MS : ENROLLMENT_RECONCILIATION_RETRY_DELAY_MS;
    const timer = window.setTimeout(() => {
      if (cancelled || inFlightRef.current) return;
      inFlightRef.current = true;
      attemptRef.current += 1;
      setAttempts(attemptRef.current);
      setState("checking");
      void refresh().then((result) => {
        if (cancelled) return;
        if (result !== "ready") {
          setState("response-loss");
          return;
        }
        setState("pending");
        setCycle((value) => value + 1);
      }).finally(() => {
        inFlightRef.current = false;
      });
    }, delay);

    return () => {
      cancelled = true;
      window.clearTimeout(timer);
    };
  }, [cycle, progress, refresh]);

  const retry = () => {
    if (inFlightRef.current) return;
    attemptRef.current = 0;
    setAttempts(0);
    setState("checking");
    setCycle((value) => value + 1);
  };

  const effectiveState: EnrollmentReconciliationState = progress !== "pending"
    ? "enrolled"
    : attempts >= ENROLLMENT_RECONCILIATION_MAX_ATTEMPTS && state === "pending"
      ? "timed-out"
      : state;
  const failure = effectiveState === "response-loss" || effectiveState === "timed-out";
  const message = effectiveState === "enrolled"
    ? "Cloudで端末登録の完了を確認しました。"
    : effectiveState === "checking"
      ? "Cloudで端末登録の完了を確認しています。"
      : effectiveState === "response-loss"
        ? "最新状態の応答を確認できませんでした。操作は再送していません。"
        : effectiveState === "timed-out"
          ? "一定時間内に端末登録を確認できませんでした。操作は再送していません。"
          : "まだCloudで端末登録の完了を確認できません。";

  return <div className="enrollment-reconciliation" data-reconciliation-state={effectiveState} role={failure ? "alert" : "status"} aria-live={failure ? "assertive" : "polite"} aria-atomic="true">
    <p className="row-title">{message}</p>
    {effectiveState === "pending" ? <p className="row-description">端末が受け入れを完了するまで待機します。短期招待の再発行は行いません。</p> : null}
    {effectiveState === "checking" ? <p className="row-description">最新のsummaryを読み込んでいます。登録操作そのものは再送しません。</p> : null}
    {effectiveState === "enrolled" ? <p className="row-description">この表示はCloudの端末状態に基づく確認です。署名済みpossession receiptをConsole側で推測しません。</p> : null}
    {failure ? <button className="text-button" type="button" onClick={retry}>状態を再確認</button> : null}
  </div>;
}

type InstallGuidanceState = "not-detected" | "checking" | "connected" | "delivered" | "failed";
type InstallGuidance = Readonly<{
  state: InstallGuidanceState;
  tone: "green" | "amber" | "red";
  label: string;
  title: string;
  copy: string;
}>;

function installGuidance(status: LiveHandoffStatus): InstallGuidance {
  switch (status) {
    case "loading":
      return { state: "checking", tone: "amber", label: "確認中", title: "Macヘルパーの接続を確認しています", copy: "Macで起動したセットアップ接続から、公開情報だけを読み込んでいます。" };
    case "connected":
      return { state: "connected", tone: "green", label: "接続済み", title: "Macヘルパーが接続されています", copy: "公開preflightを読み込みました。端末名を入力して、Touch ID / パスキーで発行を承認してください。" };
    case "delivered":
      return { state: "delivered", tone: "green", label: "受け渡し済み", title: "セットアップ情報をMacへ渡しました", copy: "Mac側のセットアップ完了を待っています。招待情報をコピーしたり、もう一度発行したりする必要はありません。" };
    case "failed":
      return { state: "failed", tone: "red", label: "接続できません", title: "Macヘルパーへ自動接続できませんでした", copy: "CLIを終了して、管理者から案内されたセットアップコマンドを新しく実行してください。期限切れの接続は再利用できません。" };
    case "none":
    default:
      return { state: "not-detected", tone: "amber", label: "未接続", title: "Macヘルパーの接続を待っています", copy: "署名済みAgentPassパッケージをMacへインストールし、管理者から案内されたセットアップコマンドを実行すると自動で接続されます。" };
  }
}

function InstallStatusCard({ status }: { status: LiveHandoffStatus }) {
  const guidance = installGuidance(status);
  return (
    <article className="surface-card" data-install-state={guidance.state}>
      <div className="stop-title-row">
        <div>
          <span className="section-kicker">INSTALL / 00</span>
          <h2 className="surface-card-title">Macヘルパーを準備する</h2>
          <p className="surface-card-copy">秘密鍵やCloud資格情報をこの画面へ入力する必要はありません。接続状態と次にすることだけを表示します。</p>
        </div>
        <StatusTag tone={guidance.tone}>{guidance.label}</StatusTag>
      </div>
      <div className="device-wake-action" role="status" aria-live="polite">
        <p className="row-title">{guidance.title}</p>
        <p className="device-state-description">{guidance.copy}</p>
      </div>
      {guidance.state === "not-detected" ? <ol className="row-list" aria-label="Macセットアップの手順">
        <li className="row-list-item"><div className="row-main"><span className="row-icon" aria-hidden="true">1</span><div><p className="row-title">署名済みAgentPassパッケージをインストール</p><p className="row-description">管理者が指定した配布元のパッケージだけを使用してください。</p></div></div></li>
        <li className="row-list-item"><div className="row-main"><span className="row-icon" aria-hidden="true">2</span><div><p className="row-title">セットアップコマンドを実行</p><p className="row-description">管理者から案内されたコマンドをそのまま実行します。候補ID、指紋、招待JSONを自分で入力する必要はありません。</p></div></div></li>
        <li className="row-list-item"><div className="row-main"><span className="row-icon" aria-hidden="true">3</span><div><p className="row-title">この画面で接続を確認</p><p className="row-description">接続されると、公開preflightが自動で表示されます。</p></div></div></li>
      </ol> : null}
      {guidance.state === "failed" ? <details className="advanced-enrollment">
        <summary>自動接続できない場合の復旧</summary>
        <p className="field-help">古いloopback接続や期限切れの接続は使い回さず、CLIを終了して新しいセットアップコマンドを実行してください。招待を発行した後に自動受け渡しが失敗した場合だけ、画面に表示される一度きりの標準入力手順を使います。</p>
      </details> : null}
    </article>
  );
}

function SetupSurface({ data, goTo, operate, online, canManage, refresh, liveHandoffRef, livePreflight, liveHandoffStatus, onLiveHandoffEvent }: { data: AgentPassInitialData; goTo: (view: ConsoleView) => void; operate: (operation: string, body: Record<string, unknown>, success: string) => Promise<void | boolean>; online: boolean; canManage: boolean; refresh: () => Promise<SummaryRefreshResult>; liveHandoffRef: LiveHandoffRef; livePreflight: PublicEnrollmentPreflight | null; liveHandoffStatus: LiveHandoffStatus; onLiveHandoffEvent: (event: LiveHandoffEvent) => void }) {
  const [deviceLabel, setDeviceLabel] = useState("");
  const [issuedEnrollment, setIssuedEnrollment] = useState<IssuedEnrollmentSummary | null>(null);
  const [enrollmentPending, setEnrollmentPending] = useState(false);
  const [enrollmentError, setEnrollmentError] = useState("");
  const [enrollmentOutcomeUnknown, setEnrollmentOutcomeUnknown] = useState(false);
  const enrollmentInFlight = useRef(false);
  const [passkeyPending, setPasskeyPending] = useState(false);
  const [passkeyRegistered, setPasskeyRegistered] = useState(false);
  const [passkeyError, setPasskeyError] = useState("");
  const passkeyInFlight = useRef(false);
  const [agent, setAgent] = useState({ name: "", kind: "claude-code", public_key: "", device_id: data.devices[0]?.deviceId ?? "" });
  const [capabilityPending, setCapabilityPending] = useState(false);
  const defaultScope = data.policies.find((policy) => policy.scope)?.scope ?? { operations: ["git.commit.sign"], repositories: ["/"], branches: { allow: ["*"], deny: [] }, remotes: { allow: ["*"], deny: [] } };
  const activeGuidedPreflight = livePreflight;
  const issueCapability = async () => {
    const selectedAgent = data.agents.find((item) => item.agentId);
    const selectedDevice = data.devices.find((item) => item.deviceId);
    if (!selectedAgent?.agentId || !selectedDevice?.deviceId) return;
    setCapabilityPending(true);
    try { await operate("issue-capability", { agent_id: selectedAgent.agentId, device_id: selectedDevice.deviceId, scope: defaultScope, ttl_ms: 15 * 60 * 1000 }, "短期Capabilityを発行しました"); } finally { setCapabilityPending(false); }
  };
  const issueEnrollment = async () => {
    if (enrollmentInFlight.current || enrollmentOutcomeUnknown) return;
    enrollmentInFlight.current = true;
    setEnrollmentPending(true);
    setEnrollmentError("");
    let mutationAttempted = false;
    let handoffConsumed = false;
    try {
      const { organizationId, csrfToken } = await consoleSessionContext.get();
      const liveHandoff = liveHandoffRef.current;
      if (!liveHandoff || !activeGuidedPreflight) throw new EnrollmentFlowError("enrollment", "Macのセットアップ接続が確認できません。新しいセットアップコマンドを実行してください。");
      const activePreflight = activeGuidedPreflight;
      if (liveHandoff.preflight.candidate_id !== activePreflight.candidate_id || liveHandoff.preflight.device_key_fingerprint !== activePreflight.device_key_fingerprint) throw new EnrollmentFlowError("enrollment", "公開preflightとMacの接続が一致しません。古い接続は再利用せず、新しいセットアップコマンドを実行してください。");
      liveHandoffRef.current = null;
      handoffConsumed = true;
      if (!deviceLabel.trim()) throw new EnrollmentFlowError("enrollment", "端末名を入力してください。");
      if (!supportsWebAuthn()) throw new EnrollmentFlowError("unsupported", "このブラウザはTouch ID/パスキーに対応していません。対応ブラウザでお試しください。");
      const { authorization_id } = await authenticateRecentAuth({
        operation: RECENT_AUTH_OPERATION,
        organizationId,
        csrfToken,
      });
      mutationAttempted = true;
      const response = await fetchConsole("/api/console?operation=issue-device-enrollment", {
        method: "POST",
        headers: { "content-type": "application/json", "idempotency-key": crypto.randomUUID(), "agentpass-recent-auth": authorization_id },
        body: JSON.stringify({ proof_version: 2, candidate_id: activePreflight.candidate_id, device_key_fingerprint: activePreflight.device_key_fingerprint, label: deviceLabel.trim(), platform: "macos", ttl_ms: 10 * 60 * 1000 }),
      });
      let payload: unknown;
      try { payload = await response.json(); } catch { throw new EnrollmentFlowError("outcome-unknown", "発行結果を確認できませんでした。"); }
      if (!response.ok) {
        if (response.status >= 500) throw new EnrollmentFlowError("outcome-unknown", "発行結果を確認できませんでした。");
        throw new EnrollmentFlowError("enrollment", "登録情報を発行できませんでした。接続と権限を確認して、もう一度お試しください。");
      }
      const invitation = parseV2EnrollmentInvitation(payload, organizationId, activePreflight);
      setIssuedEnrollment({
        enrollmentId: String(invitation.enrollment_id),
        deviceId: String(invitation.device_id),
        label: String(invitation.label),
        candidateId: String(invitation.candidate_binding && (invitation.candidate_binding as Record<string, unknown>).candidate_id),
        deviceKeyFingerprint: String(invitation.candidate_binding && (invitation.candidate_binding as Record<string, unknown>).device_key_fingerprint),
        expiresAt: String(invitation.expires_at),
      });
      try {
        await liveHandoff.delivery.deliver(invitation);
        onLiveHandoffEvent(BROWSER_CLI_HANDOFF_EVENTS.DELIVERY_SUCCEEDED);
      } catch {
        onLiveHandoffEvent(BROWSER_CLI_HANDOFF_EVENTS.DELIVERY_FAILED);
        setEnrollmentError("Macへの安全な受け渡しを確認できませんでした。発行済みcredentialは表示せず破棄しました。Macの接続を確認してください。");
      }
    } catch (error) {
      clearConsoleSessionOnUnauthorized(error);
      if (mutationAttempted && (isEnrollmentOutcomeUnknown(error) || !(error instanceof EnrollmentFlowError))) {
        if (handoffConsumed) onLiveHandoffEvent(BROWSER_CLI_HANDOFF_EVENTS.DELIVERY_FAILED);
        setEnrollmentOutcomeUnknown(true);
        setEnrollmentError("");
        // The request may have committed before its response was lost. Read
        // the authoritative summary once, but never issue a second invitation.
        void refresh();
      } else {
        setEnrollmentError(enrollmentErrorMessage(error));
      }
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
  const issuedDevice = issuedEnrollment ? data.devices.find((device) => device.deviceId === issuedEnrollment.deviceId) : undefined;
  const progress = enrollmentProgress(issuedDevice);
  useEffect(() => {
    if (!issuedEnrollment || progress !== "pending") return;
    let stopped = false;
    let timer: number | undefined;
    const deadline = Math.min(Date.parse(issuedEnrollment.expiresAt), Date.now() + 5 * 60 * 1000);
    const poll = async () => {
      if (stopped) return;
      if (Date.now() >= deadline) return;
      try {
        await refresh();
        if (!stopped) setEnrollmentError("");
      } catch {
        if (!stopped) setEnrollmentError("端末の状態を確認できませんでした。接続を確認して、状態を再確認してください。");
      }
      if (!stopped && Date.now() < deadline) timer = window.setTimeout(() => void poll(), 5_000);
    };
    timer = window.setTimeout(() => void poll(), 3_000);
    return () => {
      stopped = true;
      if (timer !== undefined) window.clearTimeout(timer);
    };
  }, [issuedEnrollment, progress, refresh]);
  return (
    <>
      <SurfaceHeader eyebrow="SETUP / 01" title={<>まずは、<br />公開preflightから。</>} copy="Macが準備した公開情報を読み込み、内容を確認してから、Touch ID / パスキーで安全に招待を発行します。" />
      <div className="surface-content">
        {liveHandoffStatus !== "none" ? <div className={`handoff-notice handoff-${liveHandoffStatus}`} role={liveHandoffStatus === "failed" ? "alert" : "status"} data-live-handoff-state={liveHandoffStatus}>
          {liveHandoffStatus === "loading" ? "Macのセットアップ接続を確認しています。" : null}
          {liveHandoffStatus === "connected" ? "公開preflightを読み込みました。招待を発行すると、Macへ自動で渡します。" : null}
          {liveHandoffStatus === "delivered" ? "招待をMacへ安全に渡しました。Mac側のセットアップ完了を待っています。" : null}
          {liveHandoffStatus === "failed" ? "自動受け渡しに失敗しました。発行済みcredentialは表示せず破棄しました。Macの接続を確認してから、もう一度発行してください。" : null}
        </div> : null}
        <InstallStatusCard status={liveHandoffStatus} />
        {!canManage ? <article className="surface-card" role="status"><span className="section-kicker">READ ONLY</span><h2 className="surface-card-title">閲覧権限で表示しています</h2><p className="surface-card-copy">このロールでは端末・Agent・Capabilityを変更できません。変更が必要な場合はOwnerまたはAdminへ依頼してください。</p></article> : null}
        <article className="surface-card">
          <span className="section-kicker">CURRENT SESSION</span>
          <h2 className="surface-card-title">このセッションでできること</h2>
          <p className="surface-card-copy">セッションが切れると、Agentは作業を一時停止します。期限を過ぎる前に更新してください。</p>
          <ul className="row-list">
            {data.capabilities.map((capability, index) => <li className="row-list-item" key={capability}><div className="row-main"><span className="row-icon" aria-hidden="true">{index + 1}</span><div><p className="row-title">{capability}</p><p className="row-description">AgentPassの保護レイヤー内で許可されています</p></div></div><StatusTag tone="green">許可中</StatusTag></li>)}
          </ul>
          <div className="stop-action-row"><span className="section-note">有効期限：{data.session.expires}</span><button type="button" className="secondary-button" onClick={() => goTo("policies")}>権限を見直す</button></div>
        </article>
        {canManage ? <article className="surface-card">
          <span className="section-kicker">OPERATE SAFELY</span><h2 className="surface-card-title">安全な操作</h2>
          <p className="surface-card-copy">Capabilityは現在のPolicyの範囲に自動で絞られ、15分以内で失効します。</p>
          <button className="primary-button" type="button" disabled={capabilityPending || !data.agents.some((item) => item.agentId) || !data.devices.some((item) => item.deviceId)} onClick={issueCapability}>{capabilityPending ? "発行中…" : "短期Capabilityを発行"}</button>
          {data.capabilityRecords?.length ? <ul className="row-list">{data.capabilityRecords.map((capability) => <li className="row-list-item" key={capability.capabilityId}><div><p className="row-title">{capability.capabilityId}</p><p className="row-description">Agent {capability.agentId} · 端末 {capability.deviceId} · sequence {capability.sequence}</p></div><StatusTag tone="green">{capability.expiresAt.slice(0, 16).replace("T", " ")}まで</StatusTag></li>)}</ul> : <p className="row-description">発行済みの短期Capabilityはありません。</p>}
        </article> : null}
        <article className="surface-card"><span className="section-kicker">DEVICES</span><h2 className="surface-card-title">登録済み端末</h2><ul className="row-list">{data.devices.map((device) => <li className="row-list-item" key={device.deviceId ?? device.name}><div><p className="row-title">{device.name}</p><p className="row-description">{device.deviceId ?? "ID未同期"} · {device.location}</p></div><span><StatusTag tone={device.status === "停止" ? "red" : "green"}>{device.status}</StatusTag>{canManage && device.deviceId && device.status !== "停止" ? <button className="text-button" type="button" onClick={() => operate("revoke-device", { target_id: device.deviceId, reason: "web-console-operator" }, `${device.name}を停止しました`)}>停止</button> : null}</span></li>)}</ul></article>
        <article className="surface-card">
          <span className="section-kicker">ACCOUNT SECURITY</span>
          <h2 className="surface-card-title">パスキーを登録</h2>
          <p className="surface-card-copy">このブラウザのTouch IDやパスキーを、AgentPassへのログインと重要操作の確認に使います。秘密鍵は端末の認証器から取り出されません。パスキーの名前は端末の認証器が管理します。</p>
          <button className="secondary-button" type="button" disabled={!online || passkeyPending} onClick={() => void registerPasskeyOnDevice()}>{passkeyPending ? "パスキーを登録中…" : "Touch ID / パスキーを登録"}</button>
          {passkeyRegistered ? <p className="section-note" role="status">パスキーを登録しました。この端末から重要操作を確認できます。</p> : null}
          {passkeyError ? <p className="form-error" role="alert">{passkeyError}</p> : null}
        </article>
        {canManage ? <article className="surface-card">
          <span className="section-kicker">ENROLL A MAC · GUIDED</span><h2 className="surface-card-title">Macを安全に追加</h2>
          <p className="surface-card-copy">Macのセットアップ接続から届いた公開情報だけを確認します。招待credentialは画面・ブラウザ保存領域・clipboardへ表示せず、Macの安全な接続へ一度だけ渡します。</p>
          <div className="guided-enrollment-steps">
            <div className="guided-enrollment-step"><span className="setup-step-number">01</span><div><h3 className="setup-step-title">公開preflightを確認</h3><p className="field-help">Macヘルパーから届いたmacOS用の候補IDとP-256公開キーの指紋だけを受け付けます。</p>{activeGuidedPreflight ? <div className="preflight-preview" role="status"><p className="row-title">公開preflightを確認しました</p><p className="row-description">macOS · 候補 {activeGuidedPreflight.candidate_id} · P-256 {activeGuidedPreflight.device_key_fingerprint}</p><StatusTag tone="green">PUBLIC ONLY</StatusTag></div> : <p className="field-help">Macのセットアップコマンドを実行すると、ここに公開情報が表示されます。</p>}</div></div>
            <div className="guided-enrollment-step"><span className="setup-step-number">02</span><div><h3 className="setup-step-title">名前を付けて認証する</h3><p className="field-help">表示名だけを入力し、Touch ID / パスキーで発行を承認します。</p><label>端末名<input required maxLength={128} autoComplete="off" value={deviceLabel} onChange={(event) => setDeviceLabel(event.target.value)} /></label><button className="secondary-button" type="button" disabled={!online || enrollmentPending || enrollmentOutcomeUnknown || !activeGuidedPreflight || !deviceLabel.trim()} onClick={() => void issueEnrollment()}>{enrollmentPending ? "認証・発行中…" : "Touch ID/パスキー確認して発行"}</button></div></div>
          </div>
          {enrollmentError ? <p className="form-error" role="alert">{enrollmentError}</p> : null}
          {enrollmentOutcomeUnknown ? <div className="enrollment-outcome-unknown" data-enrollment-state="outcome-unknown" role="alert" aria-live="assertive">
            <p className="row-title">発行結果を確認できませんでした</p>
            <p className="row-description">Cloudへの依頼後に応答を受け取れませんでした。招待JSONは表示せず、発行操作も再送していません。下の登録済み端末で状態を確認し、意図しない端末があれば「停止」を選んでください。</p>
            <button className="text-button" type="button" onClick={() => void refresh()}>状態を再確認</button>
          </div> : null}
          {issuedEnrollment ? <div className="enrollment-progress" data-enrollment-state={progress}><div className="stop-title-row"><div><p className="row-title">{issuedEnrollment.label}</p><p className="row-description">有効期限 {deviceDate(issuedEnrollment.expiresAt)} · 候補 {issuedEnrollment.candidateId} · {issuedEnrollment.deviceKeyFingerprint}</p></div><StatusTag tone={progress === "pending" ? "amber" : "green"}>{progressLabel(progress)}</StatusTag></div><ol className="enrollment-steps"><li data-state="pending"><strong>pending</strong><span>招待を発行済み。Macからの受け入れを待っています。</span></li><li data-state="enrolled"><strong>enrolled</strong><span>{progress === "pending" ? "Cloudが端末の登録完了を確認するまで待機します。" : "Cloudが端末の登録完了を確認しました。"}</span></li><li data-state="recovery-proven"><strong>recovery-proven</strong><span>署名済みpossession receiptの検証はMac側で完了します。Consoleはreceiptを受け取って成功扱いにしません。</span></li></ol><EnrollmentReconciliationCard key={`${issuedEnrollment.enrollmentId}:${progress}`} progress={progress} refresh={refresh} /></div> : null}
        </article> : null}
        {canManage ? <article className="surface-card">
          <span className="section-kicker">REGISTER</span><h2 className="surface-card-title">Agentを追加</h2>
          <p className="surface-card-copy">Agentの表示名・種類・公開鍵を登録し、端末に紐付けます。</p>
          <div className="form-grid"><label>Agent名<input value={agent.name} onChange={(event) => setAgent({ ...agent, name: event.target.value })} /></label><label>種類<input value={agent.kind} onChange={(event) => setAgent({ ...agent, kind: event.target.value })} /></label><label>公開鍵<textarea value={agent.public_key} onChange={(event) => setAgent({ ...agent, public_key: event.target.value })} /></label><label>端末ID<input value={agent.device_id} onChange={(event) => setAgent({ ...agent, device_id: event.target.value })} /></label></div>
          <button className="secondary-button" type="button" disabled={!agent.name || !agent.kind || !agent.public_key || !agent.device_id} onClick={async () => { await operate("create-agent", agent, "Agentを登録しました"); setAgent({ ...agent, name: "", public_key: "" }); }}>Agentを登録</button>
        </article> : null}
        <div className="setup-steps">
          <article className="setup-step"><span className="setup-step-number">01</span><h3 className="setup-step-title">端末をつなぐ</h3><p className="setup-step-copy">Claude Code / Cursorの拡張機能を確認します。</p></article>
          <article className="setup-step"><span className="setup-step-number">02</span><h3 className="setup-step-title">できることを選ぶ</h3><p className="setup-step-copy">Agentに任せてよい操作だけを許可します。</p></article>
          <article className="setup-step"><span className="setup-step-number">03</span><h3 className="setup-step-title">作業を見守る</h3><p className="setup-step-copy">履歴を確認し、いつでも停止できます。</p></article>
        </div>
      </div>
    </>
  );
}

function AgentsSurface({ data, operate, canManage }: { data: AgentPassInitialData; operate: (operation: string, body: Record<string, unknown>, success: string) => Promise<void | boolean>; canManage: boolean }) {
  return <><SurfaceHeader eyebrow="AGENTS / 03" title="つながっているAgent" copy="Claude Code と Cursor の作業状態を、プロジェクト単位で確認できます。停止したAgentは新しい作業を開始できません。" /><div className="surface-content"><article className="surface-card"><span className="section-kicker">CONNECTED CLIENTS</span><h2 className="surface-card-title">現在の作業</h2>{data.agents.length ? <ul className="row-list">{data.agents.map((agent) => <li className="row-list-item" key={agent.agentId ?? agent.name}><div className="row-main"><span className="row-icon" aria-hidden="true">{agent.client === "Cursor" ? "C" : "A"}</span><div><p className="row-title">{agent.name}</p><p className="row-description">{agent.client} · {agent.detail}</p></div></div><span><StatusTag tone={agent.stateTone}>{agent.state}</StatusTag>{canManage && agent.agentId && agent.state !== "停止" ? <button className="text-button" type="button" onClick={() => operate("revoke-agent", { target_id: agent.agentId, reason: "web-console-operator" }, `${agent.name}を停止しました`)}>停止</button> : null}</span></li>)}</ul> : <EmptyState title="接続されたAgentはありません" copy="Claude CodeまたはCursorを端末から接続すると、ここに表示されます。" />}</article><article className="surface-card"><span className="section-kicker">DEVICE COVERAGE</span><h2 className="surface-card-title">端末のカバレッジ</h2><p className="surface-card-copy">確認済み端末からAgentを操作できます。端末を失った場合は、ここではなく端末の停止操作で即時に認証を止めてください。</p>{data.devices.length ? data.devices.map((device) => <p className="row-description" key={device.deviceId ?? device.name}>{device.name} · {device.deviceId ?? "ID未同期"}</p>) : <EmptyState title="登録済み端末はありません" copy="セットアップから端末を追加してください。" />}</article><AgentLaunchGuide /></div></>;
}

function AgentLaunchGuide() {
  const [copied, setCopied] = useState<"claude" | "cursor" | null>(null);
  const commands = {
    claude: "agentpass launch --agent claude-code --project \"$PWD\" --ttl 600",
    cursor: "agentpass launch --agent cursor --project \"$PWD\" --ttl 600",
  } as const;

  const copy = async (kind: keyof typeof commands) => {
    try {
      await navigator.clipboard.writeText(commands[kind]);
      setCopied(kind);
      window.setTimeout(() => setCopied((current) => current === kind ? null : current), 2_000);
    } catch {
      setCopied(null);
    }
  };

  return <article className="surface-card" aria-labelledby="agent-launch-guide-title"><span className="section-kicker">START SAFELY</span><h2 className="surface-card-title" id="agent-launch-guide-title">Agentを安全に開始する</h2><p className="surface-card-copy">端末のプロジェクトフォルダで実行します。短期の権限だけが渡され、秘密鍵や認証情報はコマンドに含まれません。</p><div className="row-list"><div className="row-list-item"><div><p className="row-title">Claude Code</p><code className="row-description">{commands.claude}</code></div><button className="secondary-button" type="button" onClick={() => void copy("claude")} aria-label="Claude Codeの起動コマンドをコピー">{copied === "claude" ? "コピーしました" : "コピー"}</button></div><div className="row-list-item"><div><p className="row-title">Cursor</p><code className="row-description">{commands.cursor}</code></div><button className="secondary-button" type="button" onClick={() => void copy("cursor")} aria-label="Cursorの起動コマンドをコピー">{copied === "cursor" ? "コピーしました" : "コピー"}</button></div></div><p className="field-help" role="note">起動に失敗した場合は、セットアップと端末の状態を確認してください。利用できない環境ではAgentPassが安全側に停止します。</p></article>;
}

function PoliciesSurface({ data, operate, canManage }: { data: AgentPassInitialData; operate: (operation: string, body: Record<string, unknown>, success: string) => Promise<void | boolean>; canManage: boolean }) {
  const [name, setName] = useState("");
  const [repository, setRepository] = useState("");
  const scope = { operations: ["git.commit.sign"], repositories: [repository], branches: { allow: ["*"], deny: ["main"] }, remotes: { allow: ["*"], deny: [] } };
  return <><SurfaceHeader eyebrow="POLICIES / 04" title="守られているルール" copy="Agentができること・できないことを、読みやすい言葉で表示しています。無効化したPolicyは新しいBundleに入りません。" /><div className="surface-content"><article className="surface-card"><span className="section-kicker">ACTIVE POLICIES</span><h2 className="surface-card-title">現在のポリシー</h2>{data.policies.length ? <ul className="row-list">{data.policies.map((policy) => <li className="row-list-item" key={policy.policyId ?? policy.name}><div className="row-main"><span className="row-icon" aria-hidden="true">◆</span><div><p className="row-title">{policy.name}</p><p className="row-description">{policy.detail}</p></div></div><span><StatusTag tone={policy.tone}>{policy.state}</StatusTag>{canManage && policy.policyId && policy.state === "保護中" ? <button className="text-button" type="button" onClick={() => operate("disable-policy", { policy_id: policy.policyId, expected_version: policy.version ?? 1, reason: "web-console-operator" }, `${policy.name}を無効化しました`)}>無効化</button> : null}</span></li>)}</ul> : <EmptyState title="ポリシーはまだありません" copy="最小限の権限から新しいルールを追加してください。" />}</article>{canManage ? <article className="surface-card"><span className="section-kicker">CREATE POLICY</span><h2 className="surface-card-title">新しいルールを追加</h2><p className="surface-card-copy">許可範囲は狭く始め、必要なRepositoryだけを登録してください。</p><div className="form-grid"><label>ルール名<input required value={name} onChange={(event) => setName(event.target.value)} /></label><label>Repositoryの絶対パス<input required placeholder="/absolute/path/to/repository" value={repository} onChange={(event) => setRepository(event.target.value)} /></label></div><button className="secondary-button" type="button" disabled={!name.trim() || !repository.trim()} onClick={async () => { await operate("create-policy", { name: name.trim(), scope }, "Policyを追加しました"); setName(""); setRepository(""); }}>Policyを追加</button></article> : <article className="surface-card" role="status"><span className="section-kicker">READ ONLY</span><p className="surface-card-copy">このロールではPolicyを変更できません。</p></article>}</div></>;
}

function ActivitySurface({ data }: { data: AgentPassInitialData }) {
  return <><SurfaceHeader eyebrow="ACTIVITY / 05" title="何が起きたか" copy="AgentPassが確認・許可・ブロックした操作を、時系列で記録しています。" /><div className="surface-content"><article className="surface-card"><span className="section-kicker">AUDIT LOG · TODAY</span><h2 className="surface-card-title">きょうの記録</h2><ActivityList activities={data.activities} /></article></div></>;
}

function EmergencySurface({ data, onOpenConfirm, stopped, stopError }: { data: AgentPassInitialData; onOpenConfirm: () => void; stopped: boolean; stopError: string | null }) {
  const activeCount = data.agents.filter((agent) => agent.state !== "停止").length;
  return <><SurfaceHeader eyebrow="EMERGENCY STOP / 06" title={<>いつでも、<br />止められます。</>} copy="Agentが予想外の動きをしたときは、すべての作業をただちに一時停止できます。" /><div className="surface-content"><article className="surface-card stop-card"><div className="stop-title-row"><div><span className="section-kicker">CONTROL ROOM</span><h2 className="surface-card-title">すべてのAgentを緊急停止</h2><p className="surface-card-copy">停止すると、有効なAgent登録に対する作業・セッション・キューを一時停止します。ファイルは削除されません。</p></div><span className="stop-mark" aria-hidden="true">■</span></div>{stopError ? <p className="form-error" role="alert" aria-live="assertive">{stopError}</p> : null}<div className="stop-action-row">{stopped ? <><StatusTag tone="red">停止済み</StatusTag><span className="section-note">すべてのAgentを停止しました。再開はセットアップから行えます。</span></> : <><span className="section-note">現在 {activeCount}件の有効なAgent登録があります</span><button type="button" className="danger-button" onClick={onOpenConfirm}>緊急停止を開始する</button></>}</div></article><article className="surface-card"><span className="section-kicker">WHEN TO USE</span><h2 className="surface-card-title">こんなときに使います</h2><ul className="row-list"><li className="row-list-item"><div className="row-main"><span className="row-icon" aria-hidden="true">!</span><div><p className="row-title">意図しないファイル変更が続いている</p><p className="row-description">作業を止めてから、アクティビティで操作を確認します。</p></div></div></li><li className="row-list-item"><div className="row-main"><span className="row-icon" aria-hidden="true">!</span><div><p className="row-title">不明なサービスへの接続が見つかった</p><p className="row-description">接続を止め、ポリシーと端末を確認します。</p></div></div></li></ul></article></div></>;
}

function OperationalPosture({ data, session, summaryState, stopped, goTo, onRefresh, onSessionEnded }: { data: AgentPassInitialData; session: ConsoleSession | null; summaryState: "loading" | "ready" | "error"; stopped: boolean; goTo: (view: ConsoleView) => void; onRefresh: () => void; onSessionEnded: () => void }) {
  const postureInput: AccessPostureInput = {
    summaryState,
    session: session ? { expiresAt: session.expiresAt, recentAuthAt: session.recentAuthAt } : null,
    platformAuth: {
      loadState: summaryState === "loading" ? "loading" : summaryState === "error" ? "error" : "ready",
      browserSupported: supportsWebAuthn(),
      // The console intentionally has no permission to enumerate credential
      // material. Until the server exposes an attested count, zero means
      // "registration is required", never "a secret was found".
      passkeyCount: 0,
    },
    agents: data.agents.map((agent) => ({ status: agent.state === "停止" ? "revoked" : "active" })),
    devices: data.devices.map((device) => ({
      status: device.lifecycleStatus ?? (device.status === "停止" ? "revoked" : device.status === "登録待ち" ? "pending" : "active"),
      refreshState: device.refreshState ?? null,
      blockedReason: device.blockedReason ?? null,
    })),
    capabilities: (data.capabilityRecords ?? []).map((capability) => ({ expiresAt: capability.expiresAt })),
    auditHealth: data.audit.map((health) => ({ chainStatus: health.chainStatus })),
    stopped,
  };
  const posture = deriveAccessPosture(postureInput);
  const nextAction = posture.nextAction;
  const action = () => {
    if (!nextAction) return;
    if (nextAction.action === "retry") {
      if (posture.items.find((item) => item.key === "human-session")?.state === "blocked") onSessionEnded();
      else onRefresh();
      return;
    }
    goTo(nextAction.action);
  };
  return <section className="access-posture" aria-labelledby="access-posture-heading">
    <div className="access-posture-header">
      <div><span className="section-kicker">OPERATIONAL POSTURE</span><h2 className="section-heading" id="access-posture-heading">Agentを動かせる状態か</h2><p className="access-posture-copy">認証・短期権限・監査・停止状態をまとめて確認します。確認できない項目は安全とは判定しません。</p></div>
      <span className="access-posture-note">秘密値は表示しません</span>
    </div>
    <div className="posture-grid">
      {posture.items.map((item: PostureItem) => <article className={`posture-item posture-${item.tone}`} key={item.key}>
        <div className="posture-item-head"><span className="posture-item-label">{item.label}</span><span className={`posture-state posture-state-${item.tone}`}><span className="status-dot" aria-hidden="true" />{item.status}</span></div>
        <p className="posture-item-detail">{item.detail}</p>
      </article>)}
    </div>
    {nextAction ? <div className={`next-action next-action-${nextAction.action}`}>
      <div><span className="section-kicker">NEXT ACTION</span><h3>{nextAction.title}</h3><p>{nextAction.detail}</p></div>
      <button className={nextAction.action === "emergency" ? "danger-button" : "secondary-button"} type="button" onClick={action}>{nextAction.actionLabel}</button>
    </div> : null}
  </section>;
}

export function AgentPassConsole() {
  const [data, setData] = useState(emptyConsoleData);
  const [activeView, setActiveView] = useState<ConsoleView>("overview");
  const [mobileOpen, setMobileOpen] = useState(false);
  const [workspaceOpen, setWorkspaceOpen] = useState(false);
  const [organizationSwitcherState, setOrganizationSwitcherState] = useState<OrganizationSwitcherState>("closed");
  const [organizationOptions, setOrganizationOptions] = useState<readonly Organization[]>([]);
  const [selectedOrganizationId, setSelectedOrganizationId] = useState<string | null>(null);
  const [organizationSwitcherError, setOrganizationSwitcherError] = useState<string | null>(null);
  const [helpOpen, setHelpOpen] = useState(false);
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [confirmChecked, setConfirmChecked] = useState(false);
  const [stopped, setStopped] = useState(false);
  const [stopError, setStopError] = useState<string | null>(null);
  const [toast, setToast] = useState("");
  const [toastTone, setToastTone] = useState<ToastTone>("success");
  const [stopPending, setStopPending] = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  const [summaryState, setSummaryState] = useState<"loading" | "ready" | "error">("loading");
  const [sessionState, setSessionState] = useState<"active" | "expired" | "signed-out">("active");
  const [sessionRole, setSessionRole] = useState<ConsoleRole | null>(null);
  const [auditSession, setAuditSession] = useState<ConsoleSession | null>(null);
  const [signOutPending, setSignOutPending] = useState(false);
  const [lastSynced, setLastSynced] = useState("未同期");
  const sidebarRef = useRef<HTMLElement | null>(null);
  const workspaceTriggerRef = useRef<HTMLButtonElement | null>(null);
  const workspaceMenuRef = useRef<HTMLDivElement | null>(null);
  const mobileTriggerRef = useRef<HTMLButtonElement | null>(null);
  const helpTriggerRef = useRef<HTMLButtonElement | null>(null);
  const helpModalRef = useRef<HTMLElement | null>(null);
  const confirmTriggerRef = useRef<HTMLButtonElement | null>(null);
  const modalRef = useRef<HTMLElement | null>(null);
  const summaryEpoch = useRef(0);
  const summaryInFlightRef = useRef<Promise<SummaryRefreshResult> | null>(null);
  const initialSummaryStartedRef = useRef(false);
  const capabilityEpoch = useRef(0);
  const adminAuditEpoch = useRef(0);
  const organizationOptionsEpoch = useRef(0);
  const organizationIdRef = useRef<string | null>(null);
  const organizationClient = useMemo<OrganizationClient>(() => createOrganizationClient({ sessionProvider: consoleSessionContext }), []);
  const securityClient = useMemo<SecurityClient>(() => createSecurityClient({ sessionProvider: consoleSessionContext }), []);
  const liveHandoffRef = useRef<LiveHandoffSession | null>(null);
  const liveHandoffReadRef = useRef(false);
  const liveHandoffMountedRef = useRef(false);
  const [liveHandoffStatus, setLiveHandoffStatus] = useState<LiveHandoffStatus>("none");
  const [livePreflight, setLivePreflight] = useState<PublicEnrollmentPreflight | null>(null);

  const advanceLiveHandoff = useCallback((event: LiveHandoffEvent) => {
    if (!liveHandoffMountedRef.current) return;
    setLiveHandoffStatus((current) => {
      try {
        return transitionBrowserCliHandoffState(current, event) as LiveHandoffStatus;
      } catch {
        return "failed";
      }
    });
  }, []);

  useDeterministicDialogFocus(mobileOpen, sidebarRef, mobileTriggerRef);
  useDeterministicDialogFocus(workspaceOpen, workspaceMenuRef, workspaceTriggerRef);
  useDeterministicDialogFocus(helpOpen, helpModalRef, helpTriggerRef);
  useDeterministicDialogFocus(confirmOpen, modalRef, confirmTriggerRef);

  useEffect(() => {
    if (!workspaceOpen || organizationSwitcherState === "loading") return;
    const timer = window.setTimeout(() => focusFirstElement(workspaceMenuRef.current), 0);
    return () => window.clearTimeout(timer);
  }, [organizationSwitcherState, workspaceOpen]);

  const endSession = useCallback((nextState: "expired" | "signed-out") => {
    summaryEpoch.current += 1;
    capabilityEpoch.current += 1;
    adminAuditEpoch.current += 1;
    consoleSessionContext.clear();
    organizationIdRef.current = null;
    organizationOptionsEpoch.current += 1;
    setOrganizationOptions([]);
    setSelectedOrganizationId(null);
    setOrganizationSwitcherState("closed");
    setOrganizationSwitcherError(null);
    setSessionRole(null);
    setAuditSession(null);
    setData(emptyConsoleData());
    setSessionState(nextState);
    setSummaryState("error");
    setConfirmOpen(false);
    setConfirmChecked(false);
  }, []);

  const expireSession = useCallback(() => endSession("expired"), [endSession]);
  const markSessionSignedOut = useCallback(() => endSession("signed-out"), [endSession]);

  const showToast = (message: string, tone: ToastTone = "success") => {
    setToast(message);
    setToastTone(tone);
    window.setTimeout(() => setToast(""), 4200);
  };

  const loadOrganizationOptions = useCallback(async () => {
    const epoch = ++organizationOptionsEpoch.current;
    setOrganizationSwitcherState("loading");
    setOrganizationSwitcherError(null);
    try {
      const [organizations, session] = await Promise.all([
        loadOrganizationSwitcherOrganizations(organizationClient),
        organizationClient.getSession(),
      ]);
      if (epoch !== organizationOptionsEpoch.current) return;
      const currentOrganizationId = organizationIdRef.current ?? session.organizationId;
      setOrganizationOptions(organizations);
      setSelectedOrganizationId((current) => {
        if (current !== null && organizations.some((organization) => organization.id === current)) return current;
        return organizations.some((organization) => organization.id === currentOrganizationId) ? currentOrganizationId : null;
      });
      setOrganizationSwitcherState("ready");
    } catch (error) {
      if (epoch !== organizationOptionsEpoch.current) return;
      if (error instanceof OrganizationClientError && error.code === "unauthorized") {
        expireSession();
        return;
      }
      setOrganizationSwitcherState("error");
      setOrganizationSwitcherError(organizationSwitcherMessage(error));
    }
  }, [expireSession, organizationClient]);

  const toggleOrganizationSwitcher = () => {
    if (workspaceOpen) {
      setWorkspaceOpen(false);
      return;
    }
    setWorkspaceOpen(true);
    if (organizationSwitcherState === "closed" || organizationSwitcherState === "error") void loadOrganizationOptions();
  };

  const selectOrganizationFromSwitcher = (organization: Organization) => {
    if (resolveOrganizationSelection(organizationOptions, organization.id) === undefined) {
      setOrganizationSwitcherState("error");
      setOrganizationSwitcherError("選択した組織を確認できないため、操作を中止しました。");
      return;
    }
    setSelectedOrganizationId(organization.id);
    setWorkspaceOpen(false);
    setActiveView("organizations");
    setMobileOpen(false);
    scrollConsoleToTop();
  };

  const refreshSummaryCore = useCallback(async (signal?: AbortSignal): Promise<SummaryRefreshResult> => {
    const epoch = ++summaryEpoch.current;
    setRefreshing(true);
    try {
      const session = await consoleSessionContext.get(signal);
      const { organizationId } = session;
      const fetchSummary = async (): Promise<Response> => {
        let response = await fetchConsole("/api/console?resource=summary", { signal });
        if (![502, 503, 504].includes(response.status)) return response;
        await new Promise<void>((resolve, reject) => {
          const timer = window.setTimeout(() => {
            signal?.removeEventListener("abort", abort);
            resolve();
          }, 250);
          const abort = () => {
            window.clearTimeout(timer);
            reject(new DOMException("The operation was aborted.", "AbortError"));
          };
          signal?.addEventListener("abort", abort, { once: true });
        });
        return fetchConsole("/api/console?resource=summary", { signal });
      };
      const [response, deploymentResponse] = await Promise.all([
        fetchSummary(),
        fetchConsole("/api/console?resource=deployment-readiness", { signal }),
      ]);
      if (response.status === 401 || response.status === 403 || deploymentResponse.status === 401 || deploymentResponse.status === 403) throw new ConsoleSessionError("セッションの有効期限が切れました。", response.status === 401 || response.status === 403 ? response.status : deploymentResponse.status);
      if (!response.ok) throw new Error("summary unavailable");
      let deployment: DeploymentReadiness | null = null;
      if (deploymentResponse.ok) {
        try {
          deployment = parseDeploymentReadiness(await deploymentResponse.json());
        } catch {
          // A summary without a valid deployment attestation remains usable for
          // read-only visibility, but the deployment badge stays unverified.
          deployment = null;
        }
      }
      const next = summaryViewData(parseConsoleSummary(await response.json(), { organizationId }), deployment, session);
      if (epoch !== summaryEpoch.current) return "unavailable";
      organizationIdRef.current = organizationId;
      setSessionRole(session.role);
      setAuditSession(session);
      setData(next);
      setSessionState("active");
      setSummaryState("ready");
      setLastSynced("たった今");
      return "ready";
    } catch (error) {
      if (error instanceof DOMException && error.name === "AbortError") return "unavailable";
      if (epoch !== summaryEpoch.current) return "unavailable";
      const diagnostic = error instanceof Error ? error.message : "unknown_error";
      if (/^[A-Za-z0-9_.:-]{1,96}$/u.test(diagnostic)) console.warn("AgentPass summary refresh rejected", diagnostic);
      if (error instanceof ConsoleSummaryParseError) {
        console.warn("AgentPass summary contract rejected", error.path, error.reason);
      }
      organizationIdRef.current = null;
      setSessionRole(null);
      setAuditSession(null);
      if (error instanceof ConsoleSessionError && (error.status === 401 || error.status === 403)) {
        consoleSessionContext.clear();
        setSessionState("expired");
      }
      setSummaryState("error");
      setData(emptyConsoleData());
      return "unavailable";
    } finally {
      if (!signal?.aborted && epoch === summaryEpoch.current) setRefreshing(false);
    }
  }, []);

  const refreshSummary = useCallback((signal?: AbortSignal): Promise<SummaryRefreshResult> => {
    if (summaryInFlightRef.current !== null) return summaryInFlightRef.current;
    const promise = refreshSummaryCore(signal);
    summaryInFlightRef.current = promise;
    void promise.finally(() => {
      if (summaryInFlightRef.current === promise) summaryInFlightRef.current = null;
    });
    return promise;
  }, [refreshSummaryCore]);

  const handleOrganizationSwitched = useCallback((session: OrganizationSession): void => {
    // Fence the previous tenant projection before the new summary request
    // starts. The old devices/agents/policies must never remain visible while
    // the server-backed session is changing organization.
    summaryEpoch.current += 1;
    setData(emptyConsoleData());
    setSummaryState("loading");
    setAuditSession(null);
    setLastSynced("確認中");
    consoleSessionContext.replace(session);
    void refreshSummary();
  }, [refreshSummary]);

  useEffect(() => {
    window.addEventListener(CONSOLE_SESSION_ENDED_EVENT, expireSession);
    return () => window.removeEventListener(CONSOLE_SESSION_ENDED_EVENT, expireSession);
  }, [expireSession]);

  useEffect(() => {
    liveHandoffMountedRef.current = true;
    return () => {
      liveHandoffMountedRef.current = false;
      liveHandoffRef.current = null;
    };
  }, []);

  useEffect(() => {
    if (liveHandoffReadRef.current) return;
    liveHandoffReadRef.current = true;
    const launchFragment = window.location.hash;
    if (launchFragment === "") return;
    const failLiveHandoff = (event: "launch_failed" | "preflight_failed") => window.setTimeout(() => {
      advanceLiveHandoff(event);
    }, 0);
    try {
      const pageUrl = new URL(window.location.href);
      pageUrl.hash = "";
      window.history.replaceState(window.history.state, "", `${pageUrl.pathname}${pageUrl.search}`);
    } catch {
      failLiveHandoff(BROWSER_CLI_HANDOFF_EVENTS.LAUNCH_FAILED);
      return;
    }
    let handoff: ReturnType<typeof parseBrowserCliHandoffLaunchFragment>;
    try {
      handoff = parseBrowserCliHandoffLaunchFragment(launchFragment);
      if (!handoff) return;
    } catch {
      failLiveHandoff(BROWSER_CLI_HANDOFF_EVENTS.LAUNCH_FAILED);
      return;
    }
    queueMicrotask(() => {
      advanceLiveHandoff(BROWSER_CLI_HANDOFF_EVENTS.LAUNCH);
    });
    void fetchBrowserCliHandoffPreflight(({ handoff, timeoutMs: BROWSER_CLI_HANDOFF_LIMITS.defaultTimeoutMs } as never)).then((preflight) => {
      if (!liveHandoffMountedRef.current) return;
      liveHandoffRef.current = {
        ...handoff,
        preflight,
        delivery: createLiveHandoffDelivery({ handoff, preflight }),
      };
      setLivePreflight(publicBrowserCliEnrollmentPreflight(preflight));
      advanceLiveHandoff(BROWSER_CLI_HANDOFF_EVENTS.PREFLIGHT_SUCCEEDED);
    }).catch(() => {
      failLiveHandoff(BROWSER_CLI_HANDOFF_EVENTS.PREFLIGHT_FAILED);
    });
  }, [advanceLiveHandoff]);

  useEffect(() => {
    const activeDialog = confirmOpen ? modalRef.current : helpOpen ? helpModalRef.current : workspaceOpen ? workspaceMenuRef.current : mobileOpen ? sidebarRef.current : null;
    if (!activeDialog) return;
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        event.preventDefault();
        if (confirmOpen) setConfirmOpen(false);
        else if (helpOpen) setHelpOpen(false);
        else if (workspaceOpen) setWorkspaceOpen(false);
        else setMobileOpen(false);
        return;
      }
      if (event.key === "Tab") {
        const focusable = getFocusableElements(activeDialog);
        if (focusable.length === 0) {
          event.preventDefault();
          activeDialog.focus();
          return;
        }
        const first = focusable[0];
        const last = focusable[focusable.length - 1];
        if (event.shiftKey && document.activeElement === first) {
          event.preventDefault();
          last.focus();
        } else if (!event.shiftKey && document.activeElement === last) {
          event.preventDefault();
          first.focus();
        }
        return;
      }
      if (workspaceOpen && (event.key === "ArrowDown" || event.key === "ArrowUp" || event.key === "Home" || event.key === "End")) {
        const options = Array.from(activeDialog.querySelectorAll<HTMLElement>("[role=\"option\"]"));
        if (options.length === 0) return;
        const currentIndex = Math.max(0, options.indexOf(document.activeElement as HTMLElement));
        const nextIndex = event.key === "Home"
          ? 0
          : event.key === "End"
            ? options.length - 1
            : (currentIndex + (event.key === "ArrowDown" ? 1 : -1) + options.length) % options.length;
        event.preventDefault();
        options[nextIndex]?.focus();
      }
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [confirmOpen, helpOpen, mobileOpen, workspaceOpen]);

  useEffect(() => {
    if (initialSummaryStartedRef.current) return;
    const controller = new AbortController();
    const timer = window.setTimeout(() => {
      if (initialSummaryStartedRef.current) return;
      initialSummaryStartedRef.current = true;
      void refreshSummary(controller.signal);
    }, 0);
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
    scrollConsoleToTop();
  };

  const signOut = async () => {
    if (signOutPending) return;
    setSignOutPending(true);
    try {
      await logoutConsoleSession();
      markSessionSignedOut();
    } catch (error) {
      if (error instanceof ConsoleSessionError && (error.status === 401 || error.status === 403)) {
        setData(emptyConsoleData());
        setSessionState("expired");
        setSummaryState("error");
      } else {
        showToast("サインアウトを完了できませんでした。画面を再読み込みしてから、もう一度サインアウトしてください。", "error");
      }
    } finally {
      setSignOutPending(false);
    }
  };

  const triggerStop = async () => {
    if (stopPending) return;
    if (sessionRole !== "owner") {
      showToast("Owner権限が必要です", "error");
      return;
    }
    setStopPending(true);
    setStopError(null);
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
      setStopError("停止を確認できませんでした。接続と認証状態を確認し、もう一度お試しください。");
      showToast("停止を確認できませんでした。接続を確認し、緊急停止画面のボタンからもう一度お試しください。", "error");
    } finally {
      setStopPending(false);
    }
  };

  const operate = async (operation: string, body: Record<string, unknown>, success: string) => {
    try {
      if (sessionRole !== "owner" && sessionRole !== "admin") throw new Error("role denied");
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
      return true;
    } catch {
      showToast("操作を確認できませんでした。権限と接続を確認し、この画面からもう一度お試しください。", "error");
      return false;
    }
  };

  const requestDeviceRefresh = async (deviceId: string): Promise<DeviceRefreshRequestStatus> => {
    if (sessionRole !== "owner" && sessionRole !== "admin") throw new Error("role denied");
    const session = await consoleSessionContext.get();
    const { organizationId, csrfToken } = session;
    if (!supportsWebAuthn()) throw new Error("WebAuthn unavailable");
    const { authorization_id } = await authenticateRecentAuth({ operation: DEVICE_REFRESH_REQUEST_RECENT_AUTH_OPERATION, organizationId, csrfToken });
    const response = await fetchConsole("/api/console?operation=device.refresh.request", {
      method: "POST",
      headers: { "content-type": "application/json", "idempotency-key": crypto.randomUUID(), "agentpass-recent-auth": authorization_id },
      body: JSON.stringify({ target_id: deviceId }),
    }, session);
    let payload: unknown;
    try {
      payload = await response.json();
    } catch {
      throw new Error("invalid refresh response");
    }
    if (response.status !== 202 || !response.ok) throw new Error("refresh request rejected");
    return parseDeviceRefreshResponse(payload, deviceId);
  };

  const liveSetupActive = activeView === "overview" && liveHandoffStatus !== "none";
  const currentLabel = liveSetupActive ? "セットアップ" : navItems.find((item) => item.id === activeView)?.label ?? "概要";
  const selectedOrganization = organizationOptions.find((organization) => organization.id === selectedOrganizationId);
  // A Human Session is still bound to one organization. Until the Cloud
  // exposes an atomic tenant-rotation endpoint, another organization is only
  // an administration-panel context and must not relabel operational views.
  const workspaceName = activeView === "organizations" ? selectedOrganization?.name ?? data.workspace : data.workspace;
  const activeAgents = data.agents.filter((agent) => agent.state !== "停止").length;
  const canManage = sessionRole === "owner" || sessionRole === "admin";
  const canEmergencyStop = sessionRole === "owner";
  const visibleNavItems = navItems.filter((item) => item.id !== "emergency" || sessionRole === null || canEmergencyStop);

  return (
    <div className="console-shell">
      <a className="skip-link" href="#main-content">メインコンテンツへ移動</a>
      <aside className={`sidebar${mobileOpen ? " mobile-open" : ""}`} ref={sidebarRef} role={mobileOpen ? "dialog" : undefined} aria-modal={mobileOpen ? "true" : undefined} aria-label="AgentPass Consoleサイドバー">
        <a className="brand" href="#top" onClick={(event) => { event.preventDefault(); goTo("overview"); }}>
          <span className="brand-mark" aria-hidden="true">A</span>
          <span><span className="brand-name">AgentPass</span><span className="brand-note">CONSOLE</span></span>
        </a>
        <button className="workspace-switcher" ref={workspaceTriggerRef} type="button" aria-label={`${workspaceName}ワークスペースを選択`} aria-expanded={workspaceOpen} aria-controls="workspace-menu" data-dialog-initial-focus onClick={toggleOrganizationSwitcher}><span><span className="workspace-label">WORKSPACE</span><span className="workspace-name">{workspaceName}</span></span><span className="chevron" aria-hidden="true">⌄</span></button>
        {workspaceOpen ? <div className="workspace-menu" ref={workspaceMenuRef} id="workspace-menu" role="dialog" aria-modal="true" aria-labelledby="workspace-dialog-title" aria-busy={organizationSwitcherState === "loading"} tabIndex={-1}>
          <strong id="workspace-dialog-title">組織を選択</strong>
          <span>アクセス可能な組織だけを表示しています</span>
          {organizationSwitcherState === "loading" ? <small role="status">組織を確認中です…</small> : null}
          {organizationSwitcherState === "error" ? <div role="alert"><small>{organizationSwitcherError}</small><button className="text-button" type="button" onClick={() => void loadOrganizationOptions()}>もう一度試す</button></div> : null}
          {organizationSwitcherState === "ready" && organizationOptions.length === 0 ? <small role="status">利用可能な組織がありません。</small> : null}
          {organizationSwitcherState === "ready" && organizationOptions.length > 0 ? <ul className="workspace-options" role="listbox" aria-label="利用可能な組織">{organizationOptions.map((organization) => <li key={organization.id}><button className={`workspace-option${organization.id === selectedOrganizationId ? " is-selected" : ""}`} type="button" role="option" aria-selected={organization.id === selectedOrganizationId} onClick={() => selectOrganizationFromSwitcher(organization)}><span>{organization.name}</span><small>{organization.id === selectedOrganizationId ? "選択済み" : "組織管理を開く"}</small></button></li>)}</ul> : null}
          <small>選択後も権限とテナントはCloudで再検証されます。確認できない組織の操作は実行しません。</small>
        </div> : null}
        <p className="nav-label">MANAGE</p>
        <nav id="main-navigation" aria-label="メインナビゲーション">
          <ul className="nav-list">
            {visibleNavItems.map((item) => <li key={item.id}><button className={`nav-item${activeView === item.id ? " active" : ""}${item.id === "emergency" ? " danger" : ""}`} type="button" onClick={() => goTo(item.id)} aria-current={activeView === item.id ? "page" : undefined}><span className="nav-icon" aria-hidden="true">{item.icon}</span><span className="nav-copy">{item.label}</span>{item.id === "agents" && data.agents.length > 0 ? <span className="nav-badge">{data.agents.length}</span> : null}</button></li>)}
          </ul>
        </nav>
        <div className="sidebar-footer"><div className="operator"><span className="avatar" aria-hidden="true">{data.operator.initials}</span><div><p className="operator-name">{data.operator.name}</p><p className="operator-role">{data.operator.role}</p></div></div>{sessionState === "active" ? <button className="text-button" type="button" disabled={signOutPending} onClick={() => void signOut()}>{signOutPending ? "終了中…" : "サインアウト"}</button> : null}</div>
      </aside>

      <div className="main-column" id="top">
        <header className="topbar" aria-label="Console操作">
          <nav className="breadcrumbs" aria-label="パンくず"><button className="mobile-menu" ref={mobileTriggerRef} type="button" aria-label={mobileOpen ? "メニューを閉じる" : "メニューを開く"} aria-expanded={mobileOpen} aria-controls="main-navigation" onClick={() => setMobileOpen((open) => !open)}>☰</button><span className="breadcrumb-root">AgentPass</span><span aria-hidden="true">/</span><span className="breadcrumb-current" aria-current="page">{currentLabel}</span></nav>
          <div className="topbar-actions"><span className={`connection-status${summaryState === "error" ? " is-error" : ""}`} role={summaryState === "error" ? "alert" : refreshing || summaryState === "loading" ? "status" : undefined} aria-live={summaryState === "error" ? "assertive" : refreshing || summaryState === "loading" ? "polite" : undefined}><span className="status-dot" aria-hidden="true" />{summaryState === "error" ? "同期エラー。最終同期ボタンから再試行してください" : refreshing || summaryState === "loading" ? "同期中…" : "応答検証済み"}</span><button className="refresh-button" type="button" onClick={() => void refreshSummary()} disabled={refreshing}>{refreshing ? "同期中" : `最終同期 ${lastSynced}`}</button><button className="help-button" ref={helpTriggerRef} type="button" aria-label="ヘルプを開く" aria-expanded={helpOpen} aria-controls="help-dialog" onClick={() => setHelpOpen(true)}>?</button><button className="icon-button" type="button" aria-label="アクティビティを見る" onClick={() => goTo("activity")}>◌</button></div>
        </header>
        <main id="main-content" tabIndex={-1} aria-labelledby="console-page-heading" className={`content${activeView === "organizations" || activeView === "recovery" ? " organization-content" : ""}`}>
          {sessionState !== "active" ? <SessionEndedSurface reason={sessionState} /> : null}
          {sessionState === "active" && activeView === "overview" ? <Overview data={data} session={auditSession} goTo={goTo} onRequestRefresh={requestDeviceRefresh} onRefresh={() => void refreshSummary()} onSessionEnded={() => expireSession()} summaryState={summaryState} canManage={canManage} stopped={stopped} /> : null}
          {sessionState === "active" && (activeView === "setup" || liveSetupActive) ? <SetupSurface data={data} goTo={goTo} operate={operate} online={summaryState === "ready"} canManage={canManage} refresh={refreshSummary} liveHandoffRef={liveHandoffRef} livePreflight={livePreflight} liveHandoffStatus={liveHandoffStatus} onLiveHandoffEvent={advanceLiveHandoff} /> : null}
          {sessionState === "active" && activeView === "agents" ? <AgentsSurface data={data} operate={operate} canManage={canManage} /> : null}
          {sessionState === "active" && activeView === "policies" ? <PoliciesSurface data={data} operate={operate} canManage={canManage} /> : null}
          {sessionState === "active" && activeView === "activity" ? <ActivitySurface data={data} /> : null}
          {sessionState === "active" && activeView === "audit-exports" && auditSession ? <AuditExportPanel role={auditSession.role} organizationId={auditSession.organizationId} csrfToken={auditSession.csrfToken} /> : null}
          {sessionState === "active" && activeView === "security" ? <SecurityPanel securityClient={securityClient} onSessionExpired={expireSession} onSessionSignedOut={markSessionSignedOut} /> : null}
          {sessionState === "active" && activeView === "organizations" ? <OrganizationPanel key={selectedOrganizationId ?? "session-organization"} client={organizationClient} initialOrganizationId={selectedOrganizationId ?? undefined} onOrganizationSwitched={handleOrganizationSwitched} /> : null}
          {sessionState === "active" && activeView === "recovery" ? <OwnerRecoveryPanel /> : null}
          {sessionState === "active" && activeView === "emergency" && canEmergencyStop ? <EmergencySurface data={data} onOpenConfirm={() => { setStopError(null); setConfirmOpen(true); }} stopped={stopped} stopError={stopError} /> : null}
        </main>
      </div>

      {mobileOpen ? <button className="mobile-scrim" type="button" aria-label="メニューを閉じる（背景）" onClick={() => setMobileOpen(false)} /> : null}
      {helpOpen ? <div className="modal-backdrop" role="presentation" onMouseDown={(event) => { if (event.currentTarget === event.target) setHelpOpen(false); }}><section className="help-modal" ref={helpModalRef} id="help-dialog" role="dialog" aria-modal="true" aria-labelledby="help-title" aria-describedby="help-copy" tabIndex={-1}><div className="modal-header"><span className="modal-label">HELP / QUICK GUIDE</span><button className="modal-close" data-dialog-initial-focus type="button" aria-label="ヘルプを閉じる" onClick={() => setHelpOpen(false)}>×</button></div><h2 className="modal-title" id="help-title">AgentPassの見方</h2><p className="modal-copy" id="help-copy">Agentが作業を開始する前に、概要で「システム正常」と表示されていることを確認してください。</p><ul className="help-list"><li><strong>セットアップ</strong><span>端末・Agent・短期Capabilityを管理します。</span></li><li><strong>ポリシー</strong><span>Agentに許可する操作とRepositoryを絞ります。</span></li><li><strong>緊急停止</strong><span>不審な動きがあれば、すべてのAgentを即時停止できます。</span></li></ul><button className="secondary-button" type="button" onClick={() => { setHelpOpen(false); goTo("activity"); }}>監査ログを見る</button></section></div> : null}
      {confirmOpen ? <div className="modal-backdrop" role="presentation" onMouseDown={(event) => { if (!stopPending && event.currentTarget === event.target) setConfirmOpen(false); }}><section className="confirm-modal" ref={modalRef} role="dialog" aria-modal="true" aria-labelledby="confirm-title" aria-describedby="confirm-copy" tabIndex={-1}><span className="modal-label">EMERGENCY STOP</span><h2 className="modal-title" id="confirm-title">Agentをすべて停止しますか？</h2><p className="modal-copy" id="confirm-copy">Cloud上で有効な{activeAgents}件のAgent登録を停止対象にします。現在の接続数を示すものではありません。</p><label className="confirm-check"><input data-dialog-initial-focus type="checkbox" checked={confirmChecked} disabled={stopPending} onChange={(event) => setConfirmChecked(event.target.checked)} /><span>影響を理解しました。すべてのAgentを停止します。</span></label><div className="modal-actions"><button className="secondary-button" type="button" disabled={stopPending} onClick={() => setConfirmOpen(false)}>キャンセル</button><button className="danger-button" type="button" disabled={!confirmChecked || stopPending} onClick={triggerStop}>{stopPending ? "停止を配信中…" : "停止を確認する"}</button></div></section></div> : null}
      {toast ? <div className={`toast ${toastTone}`} role={toastTone === "error" ? "alert" : "status"} aria-live={toastTone === "error" ? "assertive" : "polite"} aria-atomic="true">{toastTone === "success" ? "✓" : "!"} {toast}</div> : null}
      <div className="sr-only" aria-live="polite" aria-atomic="true">{summaryState === "error" ? "同期に失敗しました。最終同期ボタンから再試行してください。" : ""}</div>
    </div>
  );
}
