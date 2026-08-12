"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { authenticateRecentAuth, registerPasskey, WebAuthnClientError } from "../webauthn-client";

export type ConsoleView =
  | "overview"
  | "setup"
  | "agents"
  | "policies"
  | "activity"
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

export const defaultInitialData: AgentPassInitialData = {
  workspace: "プロダクトチーム",
  operator: { name: "佐藤さん", role: "運用管理者", initials: "ST" },
  session: {
    expires: "2026年8月12日 18:30",
    remaining: "あと 42分",
    lastVerified: "たった今確認済み",
  },
  capabilities: ["プロジェクトを読む", "ファイルを編集", "テストを実行"],
  capabilityRecords: [],
  devices: [
    {
      name: "Hiroko の MacBook Pro",
      detail: "Claude Code · v1.0.58",
      status: "接続中",
      location: "東京 / ローカル",
      checked: "たった今",
    },
    {
      name: "AgentPass Cloud",
      detail: "ポリシー・監査ログ",
      status: "正常",
      location: "ap-northeast-1",
      checked: "14秒前",
    },
  ],
  agents: [
    {
      name: "営業資料リライト",
      client: "Claude Code",
      detail: "/projects/sales-deck · 12分前に活動",
      state: "作業中",
      stateTone: "green",
    },
    {
      name: "ランディングページ調整",
      client: "Cursor",
      detail: "/projects/website · 1時間前に活動",
      state: "待機中",
      stateTone: "amber",
    },
    {
      name: "週次テスト確認",
      client: "Claude Code",
      detail: "/projects/checkout · きょう 09:18 に完了",
      state: "完了",
      stateTone: "green",
    },
  ],
  policies: [
    {
      name: "変更の反映",
      detail: "本番反映は人の確認後にのみ許可",
      state: "保護中",
      tone: "green",
    },
    {
      name: "外部サービスへの接続",
      detail: "登録済みのサービスだけ利用可能",
      state: "3サービス",
      tone: "amber",
    },
    {
      name: "危険なコマンド",
      detail: "削除・権限変更・外部公開をブロック",
      state: "ブロック中",
      tone: "red",
    },
  ],
  activities: [
    {
      symbol: "✓",
      title: "ポリシーの確認が完了しました",
      description: "AgentPass Cloud · すべて正常",
      time: "たった今",
    },
    {
      symbol: "↗",
      title: "営業資料リライトが作業を開始",
      description: "Claude Code · sales-deck",
      time: "12分前",
    },
    {
      symbol: "⌁",
      title: "セッションを更新しました",
      description: "Hiroko の MacBook Pro · 佐藤さん",
      time: "27分前",
    },
    {
      symbol: "□",
      title: "危険な操作を1件ブロックしました",
      description: "本番データベースへの直接削除",
      time: "きょう 09:42",
    },
  ],
};

type AgentPassConsoleProps = {
  initialData?: AgentPassInitialData;
};

type ToastTone = "success" | "error";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const BASE64URL_CSRF = /^[A-Za-z0-9_-]{43}$/;
const RECENT_AUTH_OPERATION = "device.enrollment.issue";

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

function parseSessionBootstrap(value: unknown): { organizationId: string; csrfToken: string } {
  if (!isPlainRecord(value) || !hasExactKeys(value, ["session", "csrf_token"])) throw new EnrollmentFlowError("session", "セッションを確認できませんでした。ページを再読み込みして、もう一度お試しください。");
  const session = value.session;
  const csrfToken = value.csrf_token;
  if (!isPlainRecord(session) || typeof session.organization_id !== "string" || !UUID.test(session.organization_id) || typeof csrfToken !== "string" || !BASE64URL_CSRF.test(csrfToken)) {
    throw new EnrollmentFlowError("session", "セッションを確認できませんでした。ページを再読み込みして、もう一度お試しください。");
  }
  return { organizationId: session.organization_id, csrfToken };
}

async function startEnrollmentSession(): Promise<{ organizationId: string; csrfToken: string }> {
  let response: Response;
  try {
    response = await fetch("/api/auth/session", {
      method: "POST",
      headers: { accept: "application/json", "content-type": "application/json" },
      body: "{}",
      cache: "no-store",
      credentials: "same-origin",
      redirect: "error",
    });
  } catch {
    throw new EnrollmentFlowError("session", "セッションを確認できませんでした。ページを再読み込みして、もう一度お試しください。");
  }
  if (!response.ok || !/^application\/json(?:\s*;|\s*$)/i.test(response.headers.get("content-type") ?? "")) {
    throw new EnrollmentFlowError("session", "セッションを確認できませんでした。ページを再読み込みして、もう一度お試しください。");
  }
  let payload: unknown;
  try {
    payload = await response.json();
  } catch {
    throw new EnrollmentFlowError("session", "セッションを確認できませんでした。ページを再読み込みして、もう一度お試しください。");
  }
  return parseSessionBootstrap(payload);
}

function supportsWebAuthn(): boolean {
  return typeof window !== "undefined" && typeof window.PublicKeyCredential !== "undefined" && typeof navigator.credentials?.get === "function";
}

function supportsWebAuthnRegistration(): boolean {
  return typeof window !== "undefined" && typeof window.PublicKeyCredential !== "undefined" && typeof navigator.credentials?.create === "function";
}

function enrollmentErrorMessage(error: unknown): string {
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
  { id: "emergency", label: "緊急停止", icon: "■" },
];

function StatusTag({ tone, children }: { tone: "green" | "amber" | "red"; children: React.ReactNode }) {
  return <span className={`tag ${tone}`}>{children}</span>;
}

function Overview({ data, goTo }: { data: AgentPassInitialData; goTo: (view: ConsoleView) => void }) {
  const activeAgents = data.agents.filter((agent) => agent.state !== "停止").length;
  const connectedDevices = data.devices.filter((device) => device.status !== "停止").length;
  const protectedOperations = data.policies.length + data.capabilities.length;
  return (
    <>
      <header>
        <p className="eyebrow">運用コンソール / 2026.08.12</p>
        <h1 className="page-heading">Agentは、<br />安全に作業できます。</h1>
        <p className="page-intro">
          接続された端末、権限、セッションの状態をまとめて確認。いま何ができるかが、すぐにわかります。
        </p>
      </header>

      <section className="hero-status" aria-labelledby="safe-status-heading">
        <div className="hero-message">
          <div className="status-kicker"><span className="status-check" aria-hidden="true">✓</span> ALL SYSTEMS READY</div>
          <h2 id="safe-status-heading" className="hero-title">Agent can safely work now</h2>
          <p className="hero-copy">
            端末とCloudの接続、今日のポリシー、操作セッションを確認しました。いまの設定なら、Agentに作業を任せられます。
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
            <p className="meta-detail">今日 {data.session.expires.split(" ").slice(-1)[0]} まで</p>
          </div>
          <div>
            <span className="meta-label">CAPABILITIES</span>
            <strong className="meta-value">{data.capabilities.length}つ許可</strong>
            <p className="meta-detail">読み取り / 編集 / テスト</p>
          </div>
        </div>
      </section>

      <div className="metric-grid" aria-label="システム概要">
        <article className="metric-card">
          <div className="metric-topline"><span className="metric-title">接続中のAgent</span><span className="metric-icon" aria-hidden="true">◈</span></div>
          <p className="metric-value">{activeAgents} / {data.agents.length}</p>
          <p className="metric-detail">接続済みのCoding Agent</p>
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
        {data.devices.map((device) => (
          <article className="health-card" key={device.name}>
            <div className="health-head">
              <div><h3 className="health-name">{device.name}</h3><p className="health-subtitle">{device.detail}</p></div>
              <span className="health-status"><span className="status-dot" aria-hidden="true" />{device.status}</span>
            </div>
            <div className="health-details">
              <span className="health-detail"><span className="health-detail-label">ロケーション</span><span className="health-detail-value">{device.location}</span></span>
              <span className="health-detail"><span className="health-detail-label">最終確認</span><span className="health-detail-value">{device.checked}</span></span>
            </div>
          </article>
        ))}
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

function SetupSurface({ data, goTo, operate, online }: { data: AgentPassInitialData; goTo: (view: ConsoleView) => void; operate: (operation: string, body: Record<string, unknown>, success: string) => Promise<void>; online: boolean }) {
  const [deviceLabel, setDeviceLabel] = useState("");
  const [enrollment, setEnrollment] = useState<Record<string, string> | null>(null);
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
    setEnrollment(null);
    setEnrollmentError("");
    try {
      const { organizationId, csrfToken } = await startEnrollmentSession();
      if (!supportsWebAuthn()) throw new EnrollmentFlowError("unsupported", "このブラウザはTouch ID/パスキーに対応していません。対応ブラウザでお試しください。");
      const { authorization_id } = await authenticateRecentAuth({
        operation: RECENT_AUTH_OPERATION,
        organizationId,
        csrfToken,
      });
      const response = await fetch("/api/console?operation=issue-device-enrollment", {
        method: "POST",
        cache: "no-store",
        credentials: "same-origin",
        headers: { "content-type": "application/json", "idempotency-key": crypto.randomUUID(), "agentpass-recent-auth": authorization_id },
        body: JSON.stringify({ label: deviceLabel.trim(), platform: "macos", ttl_ms: 10 * 60 * 1000 }),
      });
      let payload: unknown;
      try { payload = await response.json(); } catch { throw new EnrollmentFlowError("enrollment", "登録情報を発行できませんでした。接続と権限を確認して、もう一度お試しください。"); }
      if (!response.ok || !isPlainRecord(payload) || !isPlainRecord(payload.enrollment)) throw new EnrollmentFlowError("enrollment", "登録情報を発行できませんでした。接続と権限を確認して、もう一度お試しください。");
      setEnrollment(payload.enrollment as Record<string, string>);
    } catch (error) {
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
      const { organizationId, csrfToken } = await startEnrollmentSession();
      if (!supportsWebAuthnRegistration()) throw new EnrollmentFlowError("unsupported", "このブラウザはパスキー登録に対応していません。対応ブラウザでお試しください。");
      await registerPasskey({ organizationId, csrfToken });
      setPasskeyRegistered(true);
    } catch (error) {
      setPasskeyError(passkeyErrorMessage(error));
    } finally {
      passkeyInFlight.current = false;
      setPasskeyPending(false);
    }
  };
  const enrollmentJson = enrollment ? JSON.stringify({ enrollment }, null, 2) : "";
  useEffect(() => {
    if (!enrollment) return;
    const timer = window.setTimeout(() => setEnrollment(null), 5 * 60 * 1000);
    return () => window.clearTimeout(timer);
  }, [enrollment]);
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
          {enrollment ? <div className="enrollment-result" aria-live="polite"><p className="row-title">一度だけ表示しています</p><p className="surface-card-copy">下のJSONをMacへ安全に渡し、標準入力からセットアップしてください。5分後または再読込で消え、コピー内容も60秒後に消去を試みます。</p><pre className="secret-output">{enrollmentJson}</pre><div className="stop-action-row"><button className="primary-button" type="button" onClick={() => void copyEnrollment()}>JSONをコピー</button><button className="text-button" type="button" onClick={() => setEnrollment(null)}>表示を消す</button></div><code className="command-hint">agentpass setup continue --execute --enrollment-url &lt;Cloud API URL&gt; --enrollment-stdin</code></div> : null}
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

function EmergencySurface({ data, onOpenConfirm, stopped }: { data: AgentPassInitialData; onOpenConfirm: () => void; stopped: boolean }) {
  const activeCount = data.agents.filter((agent) => agent.state !== "停止").length;
  return <><SurfaceHeader eyebrow="EMERGENCY STOP / 06" title={<>いつでも、<br />止められます。</>} copy="Agentが予想外の動きをしたときは、すべての作業をただちに一時停止できます。" /><div className="surface-content"><article className="surface-card stop-card"><div className="stop-title-row"><div><span className="section-kicker">CONTROL ROOM</span><h2 className="surface-card-title">すべてのAgentを緊急停止</h2><p className="surface-card-copy">停止すると、つながっている端末の作業・セッション・キューがすべて一時停止します。ファイルは削除されません。</p></div><span className="stop-mark" aria-hidden="true">■</span></div><div className="stop-action-row">{stopped ? <><StatusTag tone="red">停止済み</StatusTag><span className="section-note">すべてのAgentを停止しました。再開はセットアップから行えます。</span></> : <><span className="section-note">現在 {activeCount}つのAgentが接続中</span><button type="button" className="danger-button" onClick={onOpenConfirm}>緊急停止を開始する</button></>}</div></article><article className="surface-card"><span className="section-kicker">WHEN TO USE</span><h2 className="surface-card-title">こんなときに使います</h2><ul className="row-list"><li className="row-list-item"><div className="row-main"><span className="row-icon" aria-hidden="true">!</span><div><p className="row-title">意図しないファイル変更が続いている</p><p className="row-description">作業を止めてから、アクティビティで操作を確認します。</p></div></div></li><li className="row-list-item"><div className="row-main"><span className="row-icon" aria-hidden="true">!</span><div><p className="row-title">不明なサービスへの接続が見つかった</p><p className="row-description">接続を止め、ポリシーと端末を確認します。</p></div></div></li></ul></article></div></>;
}

export function AgentPassConsole({ initialData = defaultInitialData }: AgentPassConsoleProps) {
  const [data, setData] = useState(initialData);
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
  const [syncError, setSyncError] = useState(false);
  const [lastSynced, setLastSynced] = useState("未同期");
  const modalRef = useRef<HTMLElement | null>(null);

  const showToast = (message: string, tone: ToastTone = "success") => {
    setToast(message);
    setToastTone(tone);
    window.setTimeout(() => setToast(""), 4200);
  };

  const refreshSummary = useCallback(async (signal?: AbortSignal) => {
    setRefreshing(true);
    try {
      const response = await fetch("/api/console?resource=summary", { cache: "no-store", signal });
      if (!response.ok) throw new Error("summary unavailable");
      setData(mergeCloudSummary(initialData, await response.json()));
      setSyncError(false);
      setLastSynced("たった今");
    } catch (error) {
      if (error instanceof DOMException && error.name === "AbortError") return;
      setSyncError(true);
      setData((current) => ({ ...current, devices: [], agents: [], policies: [], activities: [], capabilityRecords: [] }));
    } finally {
      if (!signal?.aborted) setRefreshing(false);
    }
  }, [initialData]);

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
    const controller = new AbortController();
    Promise.all([
      fetch("/api/console?resource=capabilities&limit=100", { cache: "no-store", signal: controller.signal }),
      fetch("/api/console?resource=revocations&limit=100", { cache: "no-store", signal: controller.signal }),
    ]).then(async ([capabilityResponse, revocationResponse]) => {
      const capabilityPayload = capabilityResponse.ok ? await capabilityResponse.json() : {};
      const revocationPayload = revocationResponse.ok ? await revocationResponse.json() : {};
      const raw = Array.isArray(capabilityPayload.capabilities) ? capabilityPayload.capabilities as Array<Record<string, unknown>> : [];
      setData((current) => ({ ...current, capabilityRecords: raw.map((item) => ({ capabilityId: String(item.capability_id ?? ""), agentId: String(item.agent_id ?? ""), deviceId: String(item.device_id ?? ""), expiresAt: String(item.expires_at ?? ""), sequence: Number(item.sequence ?? 0) })) }));
      const revoked = Array.isArray(revocationPayload.revocations) && revocationPayload.revocations.some((item: Record<string, unknown>) => item.target_type === "organization" && item.status === "active");
      if (revoked) setStopped(true);
    }).catch(() => {});
    return () => controller.abort();
  }, [activeView]);

  useEffect(() => {
    if (activeView !== "activity") return;
    const controller = new AbortController();
    fetch("/api/console?resource=admin-audit&limit=100", { cache: "no-store", signal: controller.signal })
      .then(async (response) => response.ok ? response.json() : Promise.reject(new Error("audit unavailable")))
      .then((payload) => {
        const events = Array.isArray(payload.events) ? payload.events as Array<Record<string, unknown>> : [];
        if (!events.length) return;
        setData((current) => ({ ...current, activities: events.slice().reverse().map((event) => ({ symbol: "⌁", title: String(event.event_type ?? "管理操作"), description: `${String(event.target_type ?? "組織")} · ${String(event.actor_id ?? "運用者")}`, time: String(event.recorded_at ?? "同期済み") })) }));
      })
      .catch(() => {});
    return () => controller.abort();
  }, [activeView]);

  const goTo = (view: ConsoleView) => {
    setActiveView(view);
    setMobileOpen(false);
    setWorkspaceOpen(false);
    window.scrollTo({ top: 0, behavior: "smooth" });
  };

  const triggerStop = async () => {
    setStopPending(true);
    try {
      const response = await fetch("/api/console?operation=emergency-stop", {
        method: "POST",
        headers: { "content-type": "application/json", "idempotency-key": crypto.randomUUID() },
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
      const response = await fetch(`/api/console?operation=${encodeURIComponent(operation)}`, {
        method: "POST",
        headers: { "content-type": "application/json", "idempotency-key": crypto.randomUUID() },
        body: JSON.stringify(body),
      });
      if (!response.ok) throw new Error("operation rejected");
      showToast(success);
      await refreshSummary();
      const capabilityResponse = await fetch("/api/console?resource=capabilities&limit=100", { cache: "no-store" });
      if (capabilityResponse.ok) {
        const payload = await capabilityResponse.json();
        const records = Array.isArray(payload.capabilities) ? payload.capabilities as Array<Record<string, unknown>> : [];
        setData((current) => ({ ...current, capabilityRecords: records.map((item) => ({ capabilityId: String(item.capability_id ?? ""), agentId: String(item.agent_id ?? ""), deviceId: String(item.device_id ?? ""), expiresAt: String(item.expires_at ?? ""), sequence: Number(item.sequence ?? 0) })) }));
      }
    } catch {
      showToast("操作を確認できませんでした。権限と接続を確認してください", "error");
    }
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
        <div className="sidebar-footer"><div className="operator"><span className="avatar" aria-hidden="true">{data.operator.initials}</span><div><p className="operator-name">{data.operator.name}</p><p className="operator-role">{data.operator.role}</p></div></div></div>
      </aside>

      <div className="main-column" id="top">
        <div className="topbar">
          <div className="breadcrumbs"><button className="mobile-menu" type="button" aria-label="メニューを開く" aria-expanded={mobileOpen} onClick={() => setMobileOpen((open) => !open)}>☰</button><span className="breadcrumb-root">AgentPass</span><span aria-hidden="true">/</span><span className="breadcrumb-current">{currentLabel}</span></div>
          <div className="topbar-actions"><span className={`connection-status${syncError ? " is-error" : ""}`}><span className="status-dot" aria-hidden="true" />{syncError ? "同期を確認" : refreshing ? "同期中…" : "システム正常"}</span><button className="refresh-button" type="button" onClick={() => void refreshSummary()} disabled={refreshing}>{refreshing ? "同期中" : `最終同期 ${lastSynced}`}</button><button className="help-button" type="button" aria-label="ヘルプを開く" aria-expanded={helpOpen} onClick={() => setHelpOpen(true)}>?</button><button className="icon-button" type="button" aria-label="アクティビティを見る" onClick={() => goTo("activity")}>◌</button></div>
        </div>
        <main className="content">
          {activeView === "overview" ? <Overview data={data} goTo={goTo} /> : null}
          {activeView === "setup" ? <SetupSurface data={data} goTo={goTo} operate={operate} online={!syncError} /> : null}
          {activeView === "agents" ? <AgentsSurface data={data} operate={operate} /> : null}
          {activeView === "policies" ? <PoliciesSurface data={data} operate={operate} /> : null}
          {activeView === "activity" ? <ActivitySurface data={data} /> : null}
          {activeView === "emergency" ? <EmergencySurface data={data} onOpenConfirm={() => setConfirmOpen(true)} stopped={stopped} /> : null}
        </main>
      </div>

      {mobileOpen ? <button className="mobile-scrim" type="button" aria-label="メニューを閉じる" onClick={() => setMobileOpen(false)} /> : null}
      {helpOpen ? <div className="modal-backdrop" role="presentation" onMouseDown={(event) => { if (event.currentTarget === event.target) setHelpOpen(false); }}><section className="help-modal" role="dialog" aria-modal="true" aria-labelledby="help-title"><div className="modal-header"><span className="modal-label">HELP / QUICK GUIDE</span><button className="modal-close" type="button" aria-label="ヘルプを閉じる" onClick={() => setHelpOpen(false)}>×</button></div><h2 className="modal-title" id="help-title">AgentPassの見方</h2><p className="modal-copy">Agentが作業を開始する前に、概要で「システム正常」と表示されていることを確認してください。</p><ul className="help-list"><li><strong>セットアップ</strong><span>端末・Agent・短期Capabilityを管理します。</span></li><li><strong>ポリシー</strong><span>Agentに許可する操作とRepositoryを絞ります。</span></li><li><strong>緊急停止</strong><span>不審な動きがあれば、すべてのAgentを即時停止できます。</span></li></ul><button className="secondary-button" type="button" onClick={() => { setHelpOpen(false); goTo("activity"); }}>監査ログを見る</button></section></div> : null}
      {confirmOpen ? <div className="modal-backdrop" role="presentation" onMouseDown={(event) => { if (!stopPending && event.currentTarget === event.target) setConfirmOpen(false); }}><section className="confirm-modal" ref={modalRef} role="dialog" aria-modal="true" aria-labelledby="confirm-title" aria-describedby="confirm-copy"><span className="modal-label">EMERGENCY STOP</span><h2 className="modal-title" id="confirm-title">Agentをすべて停止しますか？</h2><p className="modal-copy" id="confirm-copy">接続中の{activeAgents}つのAgentがただちに一時停止します。進行中の作業は再開するまで待機します。</p><label className="confirm-check"><input type="checkbox" checked={confirmChecked} disabled={stopPending} onChange={(event) => setConfirmChecked(event.target.checked)} /><span>影響を理解しました。すべてのAgentを停止します。</span></label><div className="modal-actions"><button className="secondary-button" type="button" disabled={stopPending} onClick={() => setConfirmOpen(false)}>キャンセル</button><button className="danger-button" type="button" disabled={!confirmChecked || stopPending} onClick={triggerStop}>{stopPending ? "停止を配信中…" : "停止を確認する"}</button></div></section></div> : null}
      {toast ? <div className={`toast ${toastTone}`} role="status" aria-live="polite">{toastTone === "success" ? "✓" : "!"} {toast}</div> : null}
    </div>
  );
}

function mergeCloudSummary(fallback: AgentPassInitialData, summary: Record<string, unknown>): AgentPassInitialData {
  const organization = summary.organization && typeof summary.organization === "object" ? summary.organization as Record<string, unknown> : {};
  const rawDevices = Array.isArray(summary.devices) ? summary.devices as Array<Record<string, unknown>> : [];
  const rawAgents = Array.isArray(summary.agents) ? summary.agents as Array<Record<string, unknown>> : [];
  const rawPolicies = Array.isArray(summary.policies) ? summary.policies as Array<Record<string, unknown>> : [];
  const audit = summary.audit && typeof summary.audit === "object" ? summary.audit as Record<string, unknown> : {};
  const rawActivity = Array.isArray(audit.activity) ? audit.activity as Array<Record<string, unknown>> : [];
  return {
    ...fallback,
    workspace: typeof organization.name === "string" ? organization.name : fallback.workspace,
    devices: rawDevices.map((device) => ({ deviceId: String(device.device_id ?? ""), name: String(device.name ?? "確認済み端末"), detail: String(device.status ?? "active"), status: device.status === "revoked" ? "停止" : "正常", location: "ローカル / Cloud管理", checked: "同期済み" })),
    agents: rawAgents.map((agent) => ({ agentId: String(agent.agent_id ?? ""), deviceId: typeof agent.device_id === "string" ? agent.device_id : undefined, name: String(agent.name ?? "Coding Agent"), client: agent.kind === "cursor" ? "Cursor" : "Claude Code", detail: String(agent.device_id ?? "登録済み端末"), state: agent.status === "revoked" ? "停止" : "待機中", stateTone: agent.status === "revoked" ? "red" : "green" as "red" | "green" })),
    policies: rawPolicies.map((policy) => ({ policyId: String(policy.policy_id ?? ""), version: typeof policy.version === "number" ? policy.version : 1, scope: policy.scope as Record<string, unknown> | undefined, name: String(policy.name ?? "Policy"), detail: `sequence ${String(policy.sequence ?? 0)} · Cloud署名対象`, state: policy.status === "active" ? "保護中" : "停止", tone: policy.status === "active" ? "green" : "amber" as "green" | "amber" })),
    activities: rawActivity.slice(-20).reverse().map((event) => ({ symbol: event.decision === "allow" ? "✓" : "□", title: event.decision === "allow" ? "操作を許可しました" : "操作をブロックしました", description: `${String(event.operation ?? "agent operation")} · ${String(event.reason ?? "recorded")}`, time: String(event.device_timestamp ?? "同期済み") })),
  };
}
