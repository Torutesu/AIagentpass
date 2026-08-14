"use client";

import { startAuthentication, startRegistration } from "@simplewebauthn/browser";
import { useEffect, useMemo, useState } from "react";
import { authenticateRecentAuth } from "../webauthn-client";
import { createOwnerRecoveryClient, createOwnerRecoveryDeadLetterClient, getOwnerRecoveryVisibility, ownerRecoveryDeadLetterContextHash, OwnerRecoveryApiError } from "../../lib/owner-recovery-api.mjs";
import { OwnerRecoveryDeadLetterPanel, type OwnerRecoveryDeadLetterApi, type RequestRecoveryRecentAuth } from "./OwnerRecoveryDeadLetterPanel";

type RecoveryRecord = Readonly<Record<string, unknown>>;
type RecoveryClient = ReturnType<typeof createOwnerRecoveryClient>;

const DATE = (value: unknown): string => typeof value === "string" ? new Date(value).toLocaleString("ja-JP", { timeZone: "Asia/Tokyo" }) : "日時不明";
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

const styles = {
  shell: { display: "grid", gap: 24, maxWidth: 1180, margin: "0 auto", padding: "36px 24px 64px", color: "#1e2a25" },
  header: { display: "grid", gap: 8 },
  eyebrow: { margin: 0, color: "#64716a", fontSize: 11, fontWeight: 700, letterSpacing: "0.14em" },
  heading: { margin: 0, fontSize: "clamp(26px, 4vw, 42px)", lineHeight: 1.12, letterSpacing: "-0.04em" },
  copy: { maxWidth: 720, margin: 0, color: "#64716a", lineHeight: 1.7 },
  grid: { display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(290px, 1fr))", gap: 16 },
  card: { display: "grid", gap: 14, padding: 20, border: "1px solid #dcded5", borderRadius: 12, background: "#fbfaf6", boxShadow: "0 12px 28px rgba(33,46,39,.05)" },
  title: { margin: 0, fontSize: 17 },
  muted: { margin: 0, color: "#64716a", fontSize: 13 },
  label: { display: "grid", gap: 6, color: "#64716a", fontSize: 12, fontWeight: 700 },
  input: { minHeight: 40, width: "100%", padding: "8px 10px", border: "1px solid #c5cec3", borderRadius: 7, background: "#fff", color: "#1e2a25" },
  row: { display: "flex", alignItems: "center", justifyContent: "space-between", gap: 12, flexWrap: "wrap" as const },
  actions: { display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" as const },
  button: { minHeight: 38, padding: "7px 13px", border: "1px solid #164a3a", borderRadius: 7, background: "#164a3a", color: "#fff", fontWeight: 700 },
  secondary: { minHeight: 36, padding: "6px 11px", border: "1px solid #c5cec3", borderRadius: 7, background: "#fff", color: "#164a3a", fontWeight: 700 },
  danger: { minHeight: 36, padding: "6px 11px", border: "1px solid #a13f37", borderRadius: 7, background: "#fff", color: "#a13f37", fontWeight: 700 },
  warning: { padding: 16, border: "1px solid #d7b66e", borderRadius: 9, background: "#fff9e9", color: "#80551b" },
  error: { padding: 14, borderRadius: 8, background: "#f3ddda", color: "#7d302b" },
  secret: { display: "block", overflowWrap: "anywhere" as const, padding: 12, border: "1px dashed #a86c1f", borderRadius: 7, background: "#fff9e9", color: "#80551b", fontFamily: "SFMono-Regular, Consolas, monospace", fontSize: 12, userSelect: "all" as const },
} as const;

function errorMessage(error: unknown): string {
  if (error instanceof OwnerRecoveryApiError && error.serverCode?.includes("threshold")) return "この組織はOwnerが2人未満のため復旧できません。先に独立したOwnerを2人以上登録してください。";
  if (error instanceof OwnerRecoveryApiError && error.serverCode?.includes("stale")) return "別のOwnerが先に状態を更新しました。最新状態を読み込んでください。";
  if (error instanceof OwnerRecoveryApiError && error.serverCode?.includes("replay")) return "この操作はすでに使われています。新しい状態を確認してください。";
  if (error instanceof OwnerRecoveryApiError && error.serverCode?.includes("delay")) return "固定待機時間がまだ終わっていません。短縮はできません。";
  if (error instanceof OwnerRecoveryApiError && error.code === "forbidden") return "この操作を実行する権限がありません。";
  if (error instanceof OwnerRecoveryApiError && error.code === "aborted") return "操作をキャンセルしました。必要ならもう一度お試しください。";
  return "復旧情報を確認できませんでした。接続と権限を確認して、もう一度お試しください。";
}

function stateLabel(state: unknown): string {
  return ({ pending: "承認待ち", approved: "承認完了", delayed: "固定待機中", session_issued: "復旧セッション発行済み", credential_enrolled: "新しいパスキー登録済み", activated: "復旧完了", cancelled: "キャンセル済み", expired: "期限切れ", failed: "失敗" } as Record<string, string>)[String(state)] ?? "状態不明";
}

type OwnerRecoveryPanelProps = Readonly<{
  deadLetterApi?: OwnerRecoveryDeadLetterApi;
  requestRecentAuth?: RequestRecoveryRecentAuth;
}>;

export function OwnerRecoveryPanel({ deadLetterApi, requestRecentAuth }: OwnerRecoveryPanelProps = {}) {
  const client = useMemo<RecoveryClient>(() => createOwnerRecoveryClient(), []);
  const deadLetterClient = useMemo(() => createOwnerRecoveryDeadLetterClient(), []);
  const [role, setRole] = useState<string | null>(null);
  const [organizationId, setOrganizationId] = useState("");
  const [requestId, setRequestId] = useState("");
  const [requestInput, setRequestInput] = useState("");
  const [recovery, setRecovery] = useState<RecoveryRecord | null>(null);
  const [eligibility, setEligibility] = useState<RecoveryRecord | null>(null);
  const [exchange, setExchange] = useState<string | null>(null);
  const [activation, setActivation] = useState<Readonly<{ challengeId: string; options: Record<string, unknown> }> | null>(null);
  const [loading, setLoading] = useState(true);
  const [pending, setPending] = useState("");
  const [error, setError] = useState("");

  const visibility = getOwnerRecoveryVisibility(role ?? "");
  const effectiveDeadLetterApi = useMemo<OwnerRecoveryDeadLetterApi>(() => deadLetterApi ?? Object.freeze({
    listDeadLetters: ({ organizationId: targetOrganizationId, limit, cursor, signal }) => deadLetterClient.listDeadLetters(targetOrganizationId, { limit, cursor, signal }),
    redriveDeadLetter: async ({ organizationId: targetOrganizationId, eventId, expectedManagementVersion, authorizationId, idempotencyKey, signal }) => (await deadLetterClient.redriveDeadLetter(targetOrganizationId, eventId, expectedManagementVersion, authorizationId, { idempotencyKey, signal })).deadLetter,
    suppressDeadLetter: async ({ organizationId: targetOrganizationId, eventId, expectedManagementVersion, reason, authorizationId, idempotencyKey, signal }) => (await deadLetterClient.suppressDeadLetter(targetOrganizationId, eventId, expectedManagementVersion, reason, authorizationId, { idempotencyKey, signal })).deadLetter,
  }), [deadLetterApi, deadLetterClient]);
  const effectiveRecentAuth = useMemo<RequestRecoveryRecentAuth>(() => requestRecentAuth ?? (async ({ organizationId: targetOrganizationId, eventId, action, expectedManagementVersion, operation, signal }) => {
    const session = await deadLetterClient.getSession({ signal });
    if (session.organizationId !== targetOrganizationId) throw new Error("organization session mismatch");
    const contextHash = await ownerRecoveryDeadLetterContextHash({ organizationId: targetOrganizationId, eventId, action, expectedManagementVersion });
    return authenticateRecentAuth({ operation, organizationId: targetOrganizationId, csrfToken: session.csrfToken, contextHash, signal });
  }), [deadLetterClient, requestRecentAuth]);

  useEffect(() => {
    let active = true;
    void client.getSession().then((session) => {
      if (!active) return;
      setRole(session.role);
      setOrganizationId(session.organizationId);
    }).catch((reason) => { if (active) setError(errorMessage(reason)); }).finally(() => { if (active) setLoading(false); });
    return () => { active = false; setExchange(null); };
  }, [client]);

  const applyResult = (result: Readonly<{ requestId: string; recovery: RecoveryRecord; eligibility?: RecoveryRecord; exchangeValue?: string }>) => {
    setRequestId(result.requestId);
    setRequestInput(result.requestId);
    setRecovery(result.recovery);
    if (result.eligibility !== undefined) setEligibility(result.eligibility);
    if (result.exchangeValue !== undefined) setExchange(result.exchangeValue);
  };

  const createRequest = async () => {
    if (!organizationId || pending) return;
    setPending("create"); setError("");
    try { applyResult(await client.createRequest(organizationId)); } catch (reason) { setError(errorMessage(reason)); } finally { setPending(""); }
  };

  const loadStatus = async () => {
    if (!organizationId || !UUID.test(requestInput) || pending) return;
    setPending("status"); setError("");
    try { applyResult(await client.getStatus(organizationId, requestInput)); } catch (reason) { setError(errorMessage(reason)); } finally { setPending(""); }
  };

  const approve = async () => {
    if (!organizationId || !requestId || !recovery || pending) return;
    setPending("approve"); setError("");
    try {
      const session = await client.getSession();
      const proof = await authenticateRecentAuth({ operation: "human.recovery.approve", organizationId, csrfToken: session.csrfToken });
      applyResult(await client.approve(organizationId, requestId, Number(recovery.version), proof.authorization_id));
    } catch (reason) { setError(errorMessage(reason)); } finally { setPending(""); }
  };

  const cancel = async () => {
    if (!organizationId || !requestId || !recovery || pending) return;
    setPending("cancel"); setError("");
    try { applyResult(await client.cancel(organizationId, requestId, Number(recovery.version))); } catch (reason) { setError(errorMessage(reason)); } finally { setPending(""); }
  };

  const exchangeOnce = async () => {
    if (!exchange || pending) return;
    const oneTimeExchange = exchange;
    setPending("exchange"); setError("");
    try { setExchange(null); await client.exchange(oneTimeExchange); await enrollCredential(); } catch (reason) { setError(errorMessage(reason)); } finally { setPending(""); }
  };

  const enrollCredential = async () => {
    const optionsResult = await client.registrationOptions(requestId);
    const credential = await startRegistration({ optionsJSON: optionsResult.options as never });
    const verified = await client.registrationVerify(organizationId, optionsResult.challengeId, credential);
    setRecovery(verified.recovery);
    setActivation(verified.activation);
  };

  const activate = async () => {
    if (!activation || pending) return;
    setPending("activate"); setError("");
    try {
      const assertion = await startAuthentication({ optionsJSON: activation.options as never });
      const result = await client.activate(organizationId, activation.challengeId, assertion);
      setRecovery(result.recovery);
      setActivation(null);
    } catch (reason) { setError(errorMessage(reason)); } finally { setPending(""); }
  };

  if (loading) return null;
  if (!visibility.canView) {
    return role === "admin" ? <main className="owner-recovery-panel" style={styles.shell} aria-label="復旧通知の失敗管理">
      <OwnerRecoveryDeadLetterPanel organizationId={organizationId} role={role} api={effectiveDeadLetterApi} requestRecentAuth={effectiveRecentAuth} />
    </main> : null;
  }
  const state = String(recovery?.state ?? "");
  const threshold = Number(eligibility?.threshold ?? recovery?.threshold ?? 2);
  const ownerCount = Number(eligibility?.eligible_owner_count ?? 0);
  const recoverable = eligibility?.recoverable !== false && (eligibility === null || ownerCount >= threshold);

  return <main className="owner-recovery-panel" style={styles.shell} aria-labelledby="owner-recovery-title" aria-busy={pending !== ""}>
    <header style={styles.header}>
      <p style={styles.eyebrow}>RECOVERY / OWNER THRESHOLD</p>
      <h1 id="owner-recovery-title" style={styles.heading}>アカウント復旧を準備する</h1>
      <p style={styles.copy}>パスキーを失ったメンバーの復旧は、独立したOwnerの承認と固定待機時間を使って進みます。秘密の値はこのブラウザのメモリにだけ置き、画面を閉じると消去します。</p>
    </header>
    <section style={styles.warning} role="note" aria-label="復旧の条件"><strong>復旧には、対象者以外の独立したOwnerが2人以上必要です。</strong><p style={styles.muted}>Ownerが2人未満の組織はこの方法では復旧できません。先に復旧Ownerを追加してください。</p>{eligibility ? <p style={styles.muted}>現在確認できるOwner: {ownerCount}人 / 必要: {threshold}人</p> : null}</section>
    {error ? <p style={styles.error} role="alert" aria-live="assertive">{error}</p> : null}
    <section style={styles.grid}>
      <article style={styles.card} aria-labelledby="owner-recovery-create-title">
        <h2 id="owner-recovery-create-title" style={styles.title}>1. 復旧リクエストを作成</h2>
        <p style={styles.muted}>現在のOwnerアカウント自身を復旧対象として登録します。対象メンバーIDは入力しません。</p>
        <button type="button" style={styles.button} onClick={() => void createRequest()} disabled={!recoverable || pending !== ""}>{pending === "create" ? "作成中…" : "復旧リクエストを作成"}</button>
      </article>
      <article style={styles.card} aria-labelledby="owner-recovery-status-title">
        <div style={styles.row}><h2 id="owner-recovery-status-title" style={styles.title}>2. 状態を確認</h2><span style={styles.muted}>{state ? stateLabel(state) : "未作成"}</span></div>
        <label style={styles.label}>リクエストID<input style={styles.input} value={requestInput} onChange={(event) => setRequestInput(event.target.value)} autoComplete="off" spellCheck={false} placeholder="作成後に表示されます" /></label>
        <div style={styles.actions}><button type="button" style={styles.secondary} onClick={() => void loadStatus()} disabled={!UUID.test(requestInput) || pending !== ""}>{pending === "status" ? "確認中…" : "最新状態を確認"}</button>{recovery ? <span style={styles.muted}>v{String(recovery.version)} · 期限 {DATE(recovery.expires_at)}</span> : null}</div>
        {recovery?.delay_until ? <p style={styles.muted}>固定待機の終了: {DATE(recovery.delay_until)}（短縮不可）</p> : null}
      </article>
    </section>
    {recovery ? <section style={styles.card} aria-labelledby="owner-recovery-action-title"><h2 id="owner-recovery-action-title" style={styles.title}>3. 承認と復旧セッション</h2><p style={styles.muted}>承認はOwner本人の新しいPasskey確認が必要です。承認後は固定待機を経て、一度だけ交換値を使えます。</p><div style={styles.actions}>{["pending", "approved"].includes(state) ? <button type="button" style={styles.button} onClick={() => void approve()} disabled={pending !== ""}>{pending === "approve" ? "確認中…" : "Ownerとして承認する"}</button> : null}{exchange ? <button type="button" style={styles.button} onClick={() => void exchangeOnce()} disabled={pending !== ""}>{pending === "exchange" ? "交換中…" : "一度だけ表示された交換値を使う"}</button> : null}{["pending", "approved", "delayed", "session_issued", "credential_enrolled"].includes(state) ? <button type="button" style={styles.danger} onClick={() => void cancel()} disabled={pending !== ""}>{pending === "cancel" ? "キャンセル中…" : "復旧をキャンセル"}</button> : null}</div>{exchange ? <div><p style={styles.muted}>交換値（一度だけ表示・保存しません）</p><code style={styles.secret} data-testid="recovery-exchange-value">{exchange}</code><p style={styles.muted}>この値はブラウザの保存領域、URL、ログには保存しません。使うか、この画面を閉じると消えます。</p></div> : null}</section> : null}
    {activation ? <section style={styles.card} aria-labelledby="owner-recovery-activate-title"><h2 id="owner-recovery-activate-title" style={styles.title}>4. 新しいパスキーを有効化</h2><p style={styles.muted}>登録直後に、このパスキーでWebAuthn確認を行います。成功すると復旧セッションと以前の通常セッションが無効になります。</p><button type="button" style={styles.button} onClick={() => void activate()} disabled={pending !== ""}>{pending === "activate" ? "有効化中…" : "新しいパスキーを有効化"}</button></section> : null}
    <OwnerRecoveryDeadLetterPanel organizationId={organizationId} role={role} api={effectiveDeadLetterApi} requestRecentAuth={effectiveRecentAuth} />
  </main>;
}
