"use client";

import { FormEvent, useCallback, useEffect, useRef, useState } from "react";
import Link from "next/link";

import {
  createHostedBootstrapClient,
  deriveHostedOnboardingState,
  HostedBootstrapClientError,
} from "../../lib/hosted-bootstrap-client.mjs";

type BootstrapState =
  | "oauth_started"
  | "identity_verified"
  | "organization_required"
  | "webauthn_required"
  | "ready"
  | "no_membership"
  | "completed"
  | "expired";

type PublicStatus = Readonly<{
  state: BootstrapState;
  organizationCount: number;
  canCreateFirstOrganization: boolean;
  webauthnRequired: boolean;
  expiresAt: string;
}>;

type Screen = "loading" | "signin" | "flow" | "recovery" | "error" | "terminal";
type Guidance = Readonly<{ kind: "retryable" | "terminal"; message: string }>;

const STEPS = [
  { id: "github", label: "GitHubで本人確認", detail: "GitHub identity" },
  { id: "organization", label: "ワークスペース作成", detail: "Organization" },
  { id: "passkey", label: "パスキーで保護", detail: "Passkey" },
  { id: "device", label: "端末をAgentへ引き渡す", detail: "Device handoff" },
] as const;

function activeStep(state: BootstrapState | null): number {
  if (state === "organization_required" || state === "identity_verified") return 2;
  if (state === "webauthn_required") return 3;
  if (state === "ready" || state === "completed") return 4;
  return 0;
}

function friendlyError(error: unknown): Guidance {
  if (error instanceof HostedBootstrapClientError) {
    const code = error.serverCode ?? error.code;
    if (code === "bootstrap_session_expired") return { kind: "terminal", message: "セットアップの有効期限が切れました。GitHubから新しく始めてください。" };
    if (code === "bootstrap_no_membership") return { kind: "terminal", message: "以前の所属履歴があるため、新しいワークスペースは作成できません。管理者の招待または復旧が必要です。" };
    if (code === "bootstrap_webauthn_replayed") return { kind: "terminal", message: "このパスキー確認はすでに使われました。状態を確認するにはConsoleを開いてください。" };
    if (code === "webauthn_failed" || code === "aborted") return { kind: "retryable", message: "パスキーの確認がキャンセルされました。準備ができたらもう一度お試しください。" };
    if (error.code === "transport_failed") return { kind: "retryable", message: "ネットワークへ接続できません。接続を確認してもう一度お試しください。" };
  }
  return { kind: "retryable", message: "セットアップを続けられませんでした。しばらく待ってからもう一度お試しください。" };
}

export function HostedOnboarding() {
  const clientRef = useRef<ReturnType<typeof createHostedBootstrapClient> | null>(null);
  if (clientRef.current === null) clientRef.current = createHostedBootstrapClient();

  const [screen, setScreen] = useState<Screen>("loading");
  const [status, setStatus] = useState<PublicStatus | null>(null);
  const [organizationName, setOrganizationName] = useState("");
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [guidanceKind, setGuidanceKind] = useState<Guidance["kind"] | null>(null);
  const [deviceHandoffReady, setDeviceHandoffReady] = useState(false);

  const loadStatus = useCallback(async (signal?: AbortSignal) => {
    setMessage("");
    setGuidanceKind(null);
    try {
      const next = await clientRef.current!.status({ signal }) as PublicStatus;
      setStatus(next);
      setDeviceHandoffReady(false);
      setScreen(next.state === "no_membership" ? "recovery" : "flow");
      return { ok: true as const, status: next };
    } catch (error) {
      if (signal?.aborted) return { ok: false as const, error };
      if (error instanceof HostedBootstrapClientError && error.serverCode === "bootstrap_session_required") {
        setScreen("signin");
        setGuidanceKind("terminal");
        return { ok: false as const, error };
      }
      const guidance = friendlyError(error);
      setMessage(guidance.message);
      setGuidanceKind(guidance.kind);
      setScreen(guidance.kind === "terminal" ? "terminal" : "error");
      return { ok: false as const, error };
    }
  }, []);

  useEffect(() => {
    const controller = new AbortController();
    const timer = window.setTimeout(() => void loadStatus(controller.signal), 0);
    return () => {
      window.clearTimeout(timer);
      controller.abort();
    };
  }, [loadStatus]);

  async function submitOrganization(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (busy) return;
    setBusy(true);
    setMessage("");
    try {
      await clientRef.current!.createOrganization({ name: organizationName });
      setOrganizationName("");
      await loadStatus();
    } catch (error) {
      // The organization mutation is idempotent, but its key is intentionally
      // not durable. Reconcile once from the authoritative status before
      // showing a retry. This avoids resending after a lost 201 response.
      const reconciled = await loadStatus();
      if (reconciled.ok && reconciled.status.state !== "organization_required") {
        setOrganizationName("");
        return;
      }
      const guidance = friendlyError(error);
      setMessage(guidance.message);
      setGuidanceKind(guidance.kind);
      if (guidance.kind === "terminal") setScreen("terminal");
    } finally {
      setBusy(false);
    }
  }

  async function registerPasskey() {
    if (busy) return;
    setBusy(true);
    setMessage("");
    try {
      await clientRef.current!.registerPasskey();
      // Verification atomically rotates the bootstrap cookie into the normal
      // HttpOnly Session cookie. A follow-up bootstrap status request would
      // therefore be unauthorized; transition only from the verified result.
      // The boolean is ephemeral UI state, not a session or credential cache.
      setDeviceHandoffReady(true);
      setStatus((current) => current === null ? null : {
        ...current,
        state: "completed",
        webauthnRequired: false,
      });
      setScreen("flow");
    } catch (error) {
      const guidance = friendlyError(error);
      setMessage(guidance.message);
      setGuidanceKind(guidance.kind);
      if (guidance.kind === "terminal") setScreen("terminal");
    } finally {
      setBusy(false);
    }
  }

  const currentStep = activeStep(status?.state ?? null);
  const onboardingState = deriveHostedOnboardingState(status, { deviceHandoffReady });

  return (
    <main className="onboarding-shell">
      <header className="onboarding-brand" aria-label="AgentPass">
        <span className="brand-mark" aria-hidden="true">A</span>
        <span>
          <strong>AgentPass</strong>
          <small>Secure autonomy for coding agents</small>
        </span>
      </header>

      <section className="onboarding-card" aria-labelledby="onboarding-title" aria-busy={busy || screen === "loading"} data-onboarding-state={onboardingState}>
        <div className="onboarding-intro">
          <p className="eyebrow">SECURE ONBOARDING</p>
          <h1 id="onboarding-title">Agentが安全に動ける場所をつくる</h1>
          <p>秘密鍵を渡さず、Claude CodeやCursorに必要な権限だけを許可するための初期設定です。</p>
        </div>

        {screen !== "signin" && (
          <ol className="onboarding-stepper" aria-label="セットアップの進行状況">
            {STEPS.map((step, index) => {
              const number = index + 1;
              const state = number < currentStep ? "complete" : number === currentStep ? "current" : "upcoming";
              return (
                <li key={step.id} data-state={state} aria-current={state === "current" ? "step" : undefined}>
                  <span className="step-number" aria-hidden="true">{state === "complete" ? "✓" : number}</span>
                  <span><strong>{step.label}</strong><small>{step.detail}</small></span>
                </li>
              );
            })}
          </ol>
        )}

        <div className="onboarding-action" aria-live="polite">
          {screen === "loading" && (
            <div className="onboarding-loading"><span aria-hidden="true" />安全なセットアップ状態を確認しています…</div>
          )}

          {screen === "signin" && (
            <div className="onboarding-panel">
              <span className="panel-icon" aria-hidden="true">GH</span>
              <div>
                <h2>GitHubで本人確認</h2>
                <p>メールアドレスやアクセストークンはAgentPassへ保存しません。GitHubが確認した数値IDだけをサーバーで使用します。</p>
              </div>
              {/* OAuth must perform a top-level browser navigation so the
                  provider redirect and HttpOnly state cookie stay intact. */}
              {/* eslint-disable-next-line @next/next/no-html-link-for-pages */}
              <a className="onboarding-primary" href="/api/auth/bootstrap/github/start">GitHubで続ける <span aria-hidden="true">→</span></a>
            </div>
          )}

          {screen === "flow" && onboardingState === "organization" && status?.state === "organization_required" && (
            <form className="onboarding-panel" onSubmit={submitOrganization}>
              <span className="panel-icon" aria-hidden="true">01</span>
              <div>
                <h2>最初のワークスペースを作成</h2>
                <p>会社名、チーム名、またはプロジェクト名を入力してください。後から変更できます。</p>
              </div>
              <label className="onboarding-field">
                <span>ワークスペース名</span>
                <input
                  value={organizationName}
                  onChange={(event) => setOrganizationName(event.target.value)}
                  minLength={1}
                  maxLength={128}
                  autoComplete="organization"
                  placeholder="例：Acme Engineering"
                  disabled={busy}
                  required
                />
              </label>
              <button className="onboarding-primary" type="submit" disabled={busy || organizationName.trim().length === 0}>
                {busy ? "作成しています…" : "ワークスペースを作成"}
              </button>
            </form>
          )}

          {screen === "flow" && onboardingState === "identity" && status?.state === "identity_verified" && (
            <div className="onboarding-panel">
              <h2>所属情報を確認しています</h2>
              <p>サーバー上の権限を確認しています。表示が変わらない場合は状態を更新してください。</p>
              <button className="onboarding-secondary" type="button" onClick={() => void loadStatus()} disabled={busy}>状態を更新</button>
            </div>
          )}

          {screen === "flow" && onboardingState === "identity" && status?.state === "oauth_started" && (
            <div className="onboarding-panel">
              <h2>GitHubの確認を待っています</h2>
              <p>GitHubの画面へ戻って本人確認を完了するか、最初からやり直してください。</p>
              {/* eslint-disable-next-line @next/next/no-html-link-for-pages */}
              <a className="onboarding-secondary" href="/api/auth/bootstrap/github/start">GitHubへ進む</a>
            </div>
          )}

          {screen === "flow" && onboardingState === "terminal" && status?.state === "expired" && (
            <div className="onboarding-panel onboarding-warning" role="alert">
              <h2>セットアップの有効期限が切れました</h2>
              <p>安全のため途中の権限は無効になりました。GitHubから新しく始めてください。</p>
              {/* eslint-disable-next-line @next/next/no-html-link-for-pages */}
              <a className="onboarding-secondary" href="/api/auth/bootstrap/github/start">最初からやり直す</a>
            </div>
          )}

          {screen === "flow" && onboardingState === "webauthn" && status?.state === "webauthn_required" && (
            <div className="onboarding-panel">
              <span className="panel-icon passkey-icon" aria-hidden="true">⌁</span>
              <div>
                <h2>パスキーで管理者アカウントを保護</h2>
                <p>Touch ID、セキュリティキー、または端末のパスキーを登録します。秘密鍵そのものがAgentPassへ送られることはありません。</p>
              </div>
              <ul className="onboarding-assurances" aria-label="パスキーの保護内容">
                <li>フィッシング耐性のある本人確認</li>
                <li>このサイトと端末に暗号学的に紐付け</li>
                <li>重要操作はサーバー側の権限を再確認</li>
              </ul>
              <button className="onboarding-primary" type="button" onClick={() => void registerPasskey()} disabled={busy}>
                {busy ? "パスキーを確認しています…" : "パスキーを登録"}
              </button>
            </div>
          )}

          {screen === "flow" && onboardingState === "device_handoff" && status?.state === "ready" && (
            <div className="onboarding-panel" data-device-handoff="ready">
              <h2>既存のパスキーが見つかりました</h2>
              <p>本人確認が完了しています。Consoleで端末を追加すると、Coding Agentへ権限を引き渡せます。</p>
              <Link className="onboarding-primary" href="/">Consoleで端末を追加</Link>
            </div>
          )}

          {screen === "flow" && onboardingState === "device_handoff" && status?.state === "completed" && (
            <div className="onboarding-panel onboarding-complete" data-device-handoff="ready">
              <span className="complete-mark" aria-hidden="true">✓</span>
              <div><h2>準備ができました</h2><p>次はConsoleで端末を追加します。端末の秘密鍵はブラウザやAgentPassへ送られません。</p></div>
              <Link className="onboarding-primary" href="/">Consoleを開く <span aria-hidden="true">→</span></Link>
            </div>
          )}

          {screen === "recovery" && (
            <div className="onboarding-panel onboarding-warning" role="status">
              <span className="panel-icon" aria-hidden="true">!</span>
              <div><h2>管理者の確認が必要です</h2><p>このアカウントには過去の所属履歴があります。安全のため、新しいOwner権限を自動作成しません。組織のOwnerから招待を受けるか、復旧手続きを利用してください。</p></div>
              <Link className="onboarding-secondary" href="/">復旧オプションを確認</Link>
            </div>
          )}

          {screen === "terminal" && (
            <div className="onboarding-panel onboarding-warning" role="alert" data-guidance="terminal">
              <h2>セットアップを再開してください</h2>
              <p>{message || "現在のセットアップはこの画面から続行できません。GitHubから新しいセットアップを開始してください。"}</p>
              {/* eslint-disable-next-line @next/next/no-html-link-for-pages */}
              <a className="onboarding-secondary" href="/api/auth/bootstrap/github/start">GitHubからやり直す</a>
            </div>
          )}

          {screen === "error" && (
            <div className="onboarding-panel onboarding-warning" role="alert">
              <h2>状態を確認できませんでした</h2>
              <p>{message}</p>
              <button className="onboarding-secondary" type="button" onClick={() => { setScreen("loading"); void loadStatus(); }}>もう一度試す</button>
            </div>
          )}

          {message && (screen === "flow" || screen === "error" || screen === "recovery") && <p className="onboarding-error" role="alert" data-guidance={guidanceKind ?? undefined}>{message}</p>}
        </div>

        <footer className="onboarding-footnote">
          <span aria-hidden="true">◈</span>
          <p><strong>秘密情報はブラウザに保存しません。</strong> セットアップ用CookieはHttpOnlyで保護され、CSRF・WebAuthnデータはこの処理の間だけメモリに保持されます。</p>
        </footer>
      </section>
    </main>
  );
}
