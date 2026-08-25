"use client";

import { useCallback, useEffect, useMemo, useState } from "react";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const AUTHORIZATION_ID = UUID;
const MAX_REASON_BYTES = 128;

export type RecoveryDeadLetterStatus = "dead_letter" | "pending" | "suppressed";

export type RecoveryDeadLetter = Readonly<{
  organizationId: string;
  eventId: string;
  requestId: string;
  subjectMemberId: string;
  eventType: string;
  status: RecoveryDeadLetterStatus;
  attempts: number;
  totalAttempts: number;
  managementVersion: number;
  redriveCount: number;
  lastErrorCode: string;
  createdAt: string;
  updatedAt: string;
  suppressedAt: string | null;
  suppressionReason: string | null;
}>;

export type RecoveryDeadLetterPage = Readonly<{
  items: readonly RecoveryDeadLetter[];
  nextCursor: string | null;
}>;

export type RecoveryDeadLetterMutation = Readonly<{
  organizationId: string;
  eventId: string;
  status: "pending" | "suppressed";
  attempts: number;
  totalAttempts: number;
  managementVersion: number;
  redriveCount: number;
  suppressedAt: string | null;
  suppressionReason: string | null;
}>;

export type RecoveryDeadLetterListInput = Readonly<{
  organizationId: string;
  limit: number;
  cursor?: string;
  signal?: AbortSignal;
}>;

export type RecoveryDeadLetterMutationInput = Readonly<{
  organizationId: string;
  eventId: string;
  expectedManagementVersion: number;
  authorizationId: string;
  idempotencyKey?: string;
  signal?: AbortSignal;
}>;

export type RecoveryDeadLetterSuppressInput = RecoveryDeadLetterMutationInput & Readonly<{ reason: string }>;

/**
 * Deliberately narrow UI boundary. The adapter owns HTTP headers, CSRF,
 * idempotency, response validation, and tenant routing.
 */
export type OwnerRecoveryDeadLetterApi = Readonly<{
  listDeadLetters(input: RecoveryDeadLetterListInput): Promise<RecoveryDeadLetterPage>;
  redriveDeadLetter(input: RecoveryDeadLetterMutationInput): Promise<RecoveryDeadLetterMutation>;
  suppressDeadLetter(input: RecoveryDeadLetterSuppressInput): Promise<RecoveryDeadLetterMutation>;
}>;

export type RecoveryRecentAuthRequest = Readonly<{
  organizationId: string;
  eventId: string;
  action: "redrive" | "suppress";
  expectedManagementVersion: number;
  operation: "human.recovery.outbox.redrive" | "human.recovery.outbox.suppress";
  signal?: AbortSignal;
}>;

/** The component never handles credentials; the host injects this ceremony. */
export type RequestRecoveryRecentAuth = (input: RecoveryRecentAuthRequest) => Promise<string | Readonly<{ authorization_id: string }> >;

type Props = Readonly<{
  organizationId: string;
  role: string | null;
  api?: OwnerRecoveryDeadLetterApi;
  requestRecentAuth?: RequestRecoveryRecentAuth;
}>;

type Confirmation = Readonly<{ action: "redrive" | "suppress"; eventId: string }>;
type LoadState = Readonly<{ kind: "loading" | "ready" | "unavailable" | "error"; message?: string; stale?: boolean }>;

function isManagementRole(role: string | null): boolean {
  return role === "owner" || role === "admin";
}

function dateLabel(value: string | null): string {
  if (value === null) return "—";
  const date = new Date(value);
  return Number.isFinite(date.getTime())
    ? new Intl.DateTimeFormat("ja-JP", { timeZone: "Asia/Tokyo", dateStyle: "medium", timeStyle: "short" }).format(date)
    : "日時不明";
}

function errorCode(error: unknown): string {
  if (!error || typeof error !== "object") return "";
  const value = error as Record<string, unknown>;
  return [value.code, value.serverCode, value.reason].find((item): item is string => typeof item === "string")?.toLowerCase() ?? "";
}

function isStaleVersion(error: unknown): boolean {
  const code = errorCode(error);
  return code.includes("version_conflict") || code.includes("stale_version") || code.includes("expected_version_mismatch") || (error !== null && typeof error === "object" && (error as { status?: unknown }).status === 409);
}

function isRecentAuthFailure(error: unknown): boolean {
  const code = errorCode(error);
  return code.includes("recent_auth") || code.includes("webauthn") || code.includes("authentication");
}

function isValidAuthorizationId(value: string): boolean {
  return AUTHORIZATION_ID.test(value);
}

function reasonBytes(value: string): number {
  return new TextEncoder().encode(value).byteLength;
}

function mutationError(error: unknown): string {
  if (isStaleVersion(error)) return "別の管理者が先に更新しました。最新の状態を読み込んでから、もう一度お試しください。";
  if (isRecentAuthFailure(error)) return "本人確認を完了できませんでした。もう一度確認してからお試しください。";
  if (errorCode(error).includes("forbidden")) return "この操作を実行する権限がありません。";
  return "操作を完了できませんでした。接続と権限を確認して、もう一度お試しください。";
}

function listError(error: unknown): string {
  if (errorCode(error).includes("forbidden")) return "この組織のdead-letterを閲覧する権限がありません。";
  return "dead-letterの一覧を取得できませんでした。接続と権限を確認して、もう一度お試しください。";
}

function operationLabel(action: Confirmation["action"]): string {
  return action === "redrive" ? "再送" : "抑制";
}

function newIdempotencyKey(): string {
  if (typeof globalThis.crypto?.randomUUID === "function") return globalThis.crypto.randomUUID();
  return `dead-letter-${Date.now()}-${Math.random().toString(36).slice(2)}`;
}

export function OwnerRecoveryDeadLetterPanel({ organizationId, role, api, requestRecentAuth }: Props) {
  const canManage = isManagementRole(role);
  const [items, setItems] = useState<readonly RecoveryDeadLetter[]>([]);
  const [nextCursor, setNextCursor] = useState<string | null>(null);
  const [loadState, setLoadState] = useState<LoadState>({ kind: api ? "loading" : "unavailable" });
  const [confirmation, setConfirmation] = useState<Confirmation | null>(null);
  const [reason, setReason] = useState("");
  const [pendingEventId, setPendingEventId] = useState<string | null>(null);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  const load = useCallback(async (cursor?: string, options: Readonly<{ preserveNotice?: boolean }> = {}) => {
    if (!api || !organizationId || !canManage) return;
    const controller = new AbortController();
    setLoadState({ kind: "loading" });
    setError("");
    if (!options.preserveNotice) setNotice("");
    try {
      const page = await api.listDeadLetters({ organizationId, limit: 25, ...(cursor === undefined ? {} : { cursor }), signal: controller.signal });
      setItems(page.items);
      setNextCursor(page.nextCursor);
      setLoadState({ kind: "ready" });
    } catch (reasonValue) {
      if (reasonValue instanceof DOMException && reasonValue.name === "AbortError") return;
      setLoadState({ kind: "error", message: listError(reasonValue) });
    }
  }, [api, canManage, organizationId]);

  useEffect(() => {
    const timer = window.setTimeout(() => { void load(); }, 0);
    return () => window.clearTimeout(timer);
  }, [load]);

  const openConfirmation = (action: Confirmation["action"], item: RecoveryDeadLetter) => {
    setConfirmation({ action, eventId: item.eventId });
    setReason("");
    setError("");
    setNotice("");
  };

  const closeConfirmation = () => {
    if (pendingEventId !== null) return;
    setConfirmation(null);
    setReason("");
  };

  const confirmMutation = async () => {
    if (!api || !requestRecentAuth || !confirmation || pendingEventId !== null) return;
    const item = items.find((candidate) => candidate.eventId === confirmation.eventId);
    if (!item) return setError("対象のdead-letterが一覧から消えています。最新の状態を読み込んでください。");
    const trimmedReason = reason.trim();
    if (confirmation.action === "suppress" && (trimmedReason.length === 0 || reasonBytes(trimmedReason) > MAX_REASON_BYTES)) {
      setError("抑制理由を入力してください（128バイト以内）。");
      return;
    }
    setPendingEventId(item.eventId);
    setError("");
    setNotice("");
    const controller = new AbortController();
    try {
      const proof = await requestRecentAuth({
        organizationId,
        eventId: item.eventId,
        action: confirmation.action,
        expectedManagementVersion: item.managementVersion,
        operation: confirmation.action === "redrive" ? "human.recovery.outbox.redrive" : "human.recovery.outbox.suppress",
        signal: controller.signal,
      });
      const authorizationId = typeof proof === "string" ? proof : proof.authorization_id;
      if (!isValidAuthorizationId(authorizationId)) throw new Error("invalid recent authorization");
      const mutation = confirmation.action === "redrive"
        ? await api.redriveDeadLetter({ organizationId, eventId: item.eventId, expectedManagementVersion: item.managementVersion, authorizationId, idempotencyKey: newIdempotencyKey(), signal: controller.signal })
        : await api.suppressDeadLetter({ organizationId, eventId: item.eventId, expectedManagementVersion: item.managementVersion, authorizationId, idempotencyKey: newIdempotencyKey(), reason: trimmedReason, signal: controller.signal });
      setItems((current) => current.map((candidate) => candidate.eventId === item.eventId ? { ...candidate, ...mutation } : candidate));
      setConfirmation(null);
      setReason("");
      setNotice(`${operationLabel(confirmation.action)}を受け付けました。管理バージョンはv${mutation.managementVersion}です。`);
    } catch (reasonValue) {
      if (reasonValue instanceof DOMException && reasonValue.name === "AbortError") return;
      if (isStaleVersion(reasonValue)) {
        setError(mutationError(reasonValue));
        await load(undefined, { preserveNotice: true });
        setNotice("最新の状態に更新しました。内容を確認してから再度操作してください。");
      } else {
        setError(mutationError(reasonValue));
      }
    } finally {
      setPendingEventId(null);
    }
  };

  const pageTitle = useMemo(() => canManage ? "復旧通知の失敗を管理" : "復旧通知の失敗", [canManage]);

  return <section className="surface-content" aria-labelledby="recovery-dead-letter-title" data-organization-id={organizationId}>
    <div className="surface-header">
      <div>
        <p className="eyebrow">RECOVERY / DEAD-LETTER</p>
        <h2 className="page-heading" id="recovery-dead-letter-title">{pageTitle}</h2>
        <p className="surface-card-copy">この組織のOwner復旧通知で、配信をあきらめたイベントを確認・再送・抑制します。</p>
      </div>
      {organizationId ? <span className="tag" title={organizationId}>組織 {organizationId}</span> : null}
    </div>

    {!api ? <section className="surface-card" data-state="unavailable" role="status"><div className="empty-state"><div className="empty-state-mark" aria-hidden="true">i</div><h3 className="empty-state-title">管理APIが未接続です</h3><p className="empty-state-copy">dead-letter管理APIを接続すると、この組織の失敗通知を確認できます。</p></div></section> : null}
    {api && !canManage ? <section className="surface-card" data-state="forbidden" role="status"><div className="empty-state"><div className="empty-state-mark" aria-hidden="true">—</div><h3 className="empty-state-title">管理者向けの画面です</h3><p className="empty-state-copy">dead-letterの操作はOwnerまたはAdminだけが実行できます。</p></div></section> : null}
    {api && canManage && loadState.kind === "loading" ? <section className="surface-card" data-state="loading" aria-busy="true" role="status"><div className="empty-state"><div className="empty-state-mark" aria-hidden="true">…</div><h3 className="empty-state-title">読み込み中です</h3><p className="empty-state-copy">組織に紐づくdead-letterを確認しています。</p></div></section> : null}
    {api && canManage && loadState.kind === "error" ? <section className="surface-card" data-state="error" role="alert"><div className="empty-state"><div className="empty-state-mark" aria-hidden="true">!</div><h3 className="empty-state-title">一覧を読み込めませんでした</h3><p className="empty-state-copy">{loadState.message}</p><button className="secondary-button" type="button" onClick={() => void load()}>もう一度読み込む</button></div></section> : null}
    {api && canManage && loadState.kind === "ready" && items.length === 0 ? <section className="surface-card" data-state="empty"><div className="empty-state"><div className="empty-state-mark" aria-hidden="true">✓</div><h3 className="empty-state-title">失敗通知はありません</h3><p className="empty-state-copy">この組織で管理が必要なdead-letterは現在ありません。</p></div></section> : null}

    {api && canManage && loadState.kind === "ready" && items.length > 0 ? <section className="surface-card" data-state="list" aria-live="polite">
      {error ? <p className="form-error" role="alert" aria-live="assertive">{error}</p> : null}
      {notice ? <p className="section-note" role="status" aria-live="polite">{notice}</p> : null}
      <ul className="row-list" aria-label="復旧通知dead-letter一覧">
        {items.map((item) => {
          const activeConfirmation = confirmation?.eventId === item.eventId ? confirmation : null;
          const busy = pendingEventId === item.eventId;
          const suppressed = item.status === "suppressed";
          return <li className="row-list-item" key={item.eventId} data-state={item.status}>
            <div className="row-main" style={{ alignItems: "flex-start" }}>
              <span className={`row-icon${suppressed ? "" : ""}`} aria-hidden="true">{suppressed ? "—" : "!"}</span>
              <div style={{ minWidth: 0 }}>
                <p className="row-title">{item.eventType}</p>
                <p className="row-description"><code>{item.eventId}</code> · {item.lastErrorCode}</p>
                <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(130px, 1fr))", gap: "4px 16px", marginTop: 9, color: "var(--ink-soft)", fontSize: 11 }}>
                  <span>状態: <strong>{item.status === "suppressed" ? "抑制済み" : item.status === "pending" ? "再送待ち" : "dead-letter"}</strong></span>
                  <span>試行: <strong>{item.attempts} / 累計 {item.totalAttempts}</strong></span>
                  <span>管理v: <strong>{item.managementVersion}</strong></span>
                  <span>再送回数: <strong>{item.redriveCount}</strong></span>
                  <span>更新: <strong>{dateLabel(item.updatedAt)}</strong></span>
                  {item.suppressionReason ? <span>理由: <strong>{item.suppressionReason}</strong></span> : null}
                </div>
              </div>
            </div>
            <div style={{ display: "grid", gap: 8, minWidth: 220 }}>
              {!suppressed && !activeConfirmation ? <div className="hero-action" style={{ marginTop: 0, justifyContent: "flex-end" }}><button className="secondary-button" type="button" onClick={() => openConfirmation("redrive", item)} disabled={busy}>再送</button><button className="danger-button" type="button" onClick={() => openConfirmation("suppress", item)} disabled={busy}>抑制</button></div> : null}
              {activeConfirmation ? <div className="organization-confirmation" role="dialog" aria-label={`${operationLabel(activeConfirmation.action)}の確認`}>
                <span>{activeConfirmation.action === "redrive" ? "この通知を再送しますか？" : "この通知を抑制しますか？"}</span>
                    {activeConfirmation.action === "suppress" ? <input aria-label="抑制理由" value={reason} onChange={(event) => setReason(event.target.value)} maxLength={128} disabled={busy} placeholder="抑制理由" /> : null}
                <button className="secondary-button" type="button" onClick={closeConfirmation} disabled={busy}>戻る</button><button className={activeConfirmation.action === "suppress" ? "danger-button" : "primary-button"} type="button" onClick={() => void confirmMutation()} disabled={busy || !requestRecentAuth || activeConfirmation.action === "suppress" && (reason.trim().length === 0 || reasonBytes(reason.trim()) > MAX_REASON_BYTES)}>{busy ? "本人確認中…" : `${operationLabel(activeConfirmation.action)}を確定`}</button>
              </div> : null}
              {!requestRecentAuth && !suppressed ? <p className="form-error">操作には最近のWebAuthn本人確認が必要です。</p> : null}
            </div>
          </li>;
        })}
      </ul>
          {nextCursor ? <div className="hero-action" style={{ justifyContent: "center" }}><button className="secondary-button" type="button" onClick={() => void load(nextCursor)}>次のページを読み込む</button></div> : null}
      <p className="section-note">一覧・操作対象は組織IDに紐づいています。管理バージョンが変わった場合は、自動で最新一覧を再取得します。</p>
    </section> : null}
  </section>;
}
