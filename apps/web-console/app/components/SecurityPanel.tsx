"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { SecurityClientError, createSecurityClient, isAmbiguousSecurityMutationError, type SecurityClient, type SecurityPasskey, type SecuritySession, type SecuritySnapshot } from "../security-client";
import { WebAuthnClientError } from "../webauthn-client";

type LoadState = "loading" | "ready" | "error";
type SecurityPanelProps = Readonly<{
  onSessionExpired?: () => void;
  onSessionSignedOut?: () => void;
  securityClient?: SecurityClient;
}>;

const SESSION_RETRY_STATUSES = new Set([401, 403]);

export function SecurityPanel({ onSessionExpired, onSessionSignedOut, securityClient: injectedClient }: SecurityPanelProps) {
  const clientRef = useRef<SecurityClient | null>(null);
  if (clientRef.current === null) clientRef.current = injectedClient ?? createSecurityClient();
  const client = clientRef.current;
  const [snapshot, setSnapshot] = useState<SecuritySnapshot | null>(null);
  const [loadState, setLoadState] = useState<LoadState>("loading");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [actionKey, setActionKey] = useState<string | null>(null);
  const [confirmKey, setConfirmKey] = useState<string | null>(null);
  const [renameTarget, setRenameTarget] = useState<string | null>(null);
  const [renameLabel, setRenameLabel] = useState("");
  const [signedOut, setSignedOut] = useState(false);

  const load = useCallback(async (signal?: AbortSignal): Promise<boolean> => {
    setLoadState("loading");
    setError("");
    setNotice("");
    try {
      setSnapshot(await client.getSnapshot({ signal }));
      setLoadState("ready");
      return true;
    } catch (caught) {
      if (isAbortError(caught)) return false;
      handleSessionFailure(caught, onSessionExpired);
      setLoadState("error");
      setError(securityPanelError(caught));
      return false;
    }
  }, [client, onSessionExpired]);

  useEffect(() => {
    const controller = new AbortController();
    const timer = window.setTimeout(() => void load(controller.signal), 0);
    return () => {
      window.clearTimeout(timer);
      controller.abort();
    };
  }, [load]);

  const runAction = async (key: string, action: () => Promise<void>, successMessage: string, reload = true) => {
    if (actionKey !== null) return;
    setActionKey(key);
    setError("");
    setNotice("");
    try {
      await action();
      setConfirmKey(null);
      setRenameTarget(null);
      setRenameLabel("");
      if (reload && !(await load())) return;
      setNotice(successMessage);
    } catch (caught) {
      if (isAbortError(caught)) return;
      handleSessionFailure(caught, onSessionExpired);
      const ambiguous = isAmbiguousSecurityMutationError(caught);
      const conflict = caught instanceof SecurityClientError && caught.status === 409;
      if (ambiguous || conflict) {
        const reconciled = await load();
        if (ambiguous) {
          setError(reconciled
            ? "操作結果を確認できなかったため、最新の権威状態を再取得しました。操作は自動再送していません。内容を確認してください。"
            : "操作結果を確認できず、最新の権威状態も取得できませんでした。操作は自動再送していません。接続を確認して再読み込みしてください。");
        } else {
          setError(reconciled
            ? "情報が更新されていたため、最新の権威状態を再取得しました。内容を確認してから操作してください。"
            : securityPanelError(caught));
        }
      } else {
        setError(securityPanelError(caught));
      }
    } finally {
      setActionKey(null);
    }
  };

  const addPasskey = () => void runAction("passkey:add", async () => {
    await client.addPasskey();
  }, "新しいパスキーを登録しました。");

  const passkeys = snapshot?.passkeys ?? [];
  const passkeysComplete = snapshot?.passkeysComplete ?? false;
  const onlyUsableActivePasskey = passkeysComplete && passkeys.length === 1;
  const sessions = snapshot?.sessions ?? [];
  const otherSessions = sessions.filter((session) => !session.current);
  const busy = actionKey !== null;

  if (signedOut) {
    return <section className="security-panel" aria-labelledby="security-panel-title"><div className="security-panel__header"><span className="section-kicker">SECURITY / HUMAN SESSION</span><h1 id="security-panel-title">アカウントを守る</h1></div><article className="security-panel__card" role="status"><span className="section-kicker">SIGNED OUT</span><h2 className="surface-card-title">このセッションを終了しました</h2><p className="surface-card-copy">現在のブラウザセッションを無効化しました。続けるにはページを再読み込みしてください。</p></article></section>;
  }

  return <section className="security-panel" aria-labelledby="security-panel-title">
    <div className="security-panel__header">
      <span className="section-kicker">SECURITY / HUMAN SESSION</span>
      <h1 id="security-panel-title">アカウントを守る</h1>
      <p>パスキーとログイン中のセッションを管理します。認証器の内部データは画面に表示しません。</p>
    </div>

    <article className="security-panel__card">
      <div className="security-panel__title-row">
        <div><span className="section-kicker">REGISTERED PASSKEYS</span><h2 className="surface-card-title">登録済みのパスキー</h2><p className="surface-card-copy">登録・名前変更・無効化ができます。追加や無効化では、必要に応じてTouch IDまたはパスキーで確認します。</p></div>
        <div className="security-panel__actions"><button className="secondary-button" type="button" disabled={busy || loadState === "loading"} onClick={addPasskey}>{actionKey === "passkey:add" ? "登録中…" : "パスキーを追加"}</button><button className="secondary-button" type="button" disabled={busy || loadState === "loading"} onClick={() => void load()}>再読み込み</button></div>
      </div>
      {loadState === "loading" ? <p className="section-note" role="status">セキュリティ情報を読み込み中…</p> : loadState === "error" ? <RetryState message={error} onRetry={() => void load()} /> : passkeys.length === 0 ? <EmptyState title="登録済みのパスキーはありません" copy="パスキーを追加すると、次回から安全に再認証できます。" /> : <>
        {onlyUsableActivePasskey ? <p id="security-passkey-revoke-guidance" className="section-note" role="note">このパスキーは、確認できた唯一の利用可能なパスキーです。先に別のパスキーを登録してから無効化してください。</p> : null}
        {!passkeysComplete ? <p id="security-passkey-pagination-status" className="section-note" role="status" aria-live="polite">パスキー一覧を最後まで確認できていないため、唯一のパスキーとは判定していません。</p> : null}
        <ul className="row-list">{passkeys.map((passkey) => <PasskeyRow key={passkey.id} passkey={passkey} lastUsable={onlyUsableActivePasskey} actionKey={actionKey} confirmKey={confirmKey} onRename={() => { setConfirmKey(null); setRenameTarget(passkey.id); setRenameLabel(passkey.label); setError(""); }} onRevoke={() => { setRenameTarget(null); setConfirmKey(`passkey:${passkey.id}`); }} onCancel={() => setConfirmKey(null)} onConfirm={() => void runAction(`passkey:${passkey.id}`, () => client.revokePasskey(passkey.id, passkey.version), "パスキーを無効化しました。")} />)}</ul>
      </>}
      {renameTarget !== null ? <RenameForm label={renameLabel} busy={busy} onChange={setRenameLabel} onCancel={() => { setRenameTarget(null); setRenameLabel(""); }} onSubmit={() => { const target = passkeys.find((passkey) => passkey.id === renameTarget); if (target === undefined) return; void runAction(`passkey:${target.id}`, () => client.renamePasskey(target.id, renameLabel, target.version), "パスキーの名前を変更しました。"); }} /> : null}
    </article>

    <article className="security-panel__card">
      <div className="security-panel__title-row"><div><span className="section-kicker">ACTIVE SESSIONS</span><h2 className="surface-card-title">アクティブなセッション</h2><p className="surface-card-copy">現在のブラウザと、他の端末・ブラウザのログイン状態を確認できます。</p></div><button className="secondary-button" type="button" disabled={busy || loadState !== "ready" || otherSessions.length === 0} onClick={() => setConfirmKey("other-sessions")}>他のセッションをすべて無効化</button></div>
      {confirmKey === "other-sessions" ? <div className="security-panel__confirm" role="group" aria-label="他のセッションを無効化"><span className="section-note">{otherSessions.length}件の他セッションを無効化します。</span><button className="text-button" type="button" disabled={busy} onClick={() => void runAction("other-sessions", () => client.revokeOtherSessions(sessions).then(() => undefined), "他のセッションをすべて無効化しました。")}>確認</button><button className="text-button" type="button" disabled={busy} onClick={() => setConfirmKey(null)}>キャンセル</button></div> : null}
      {loadState === "loading" ? <p className="section-note" role="status">セッション情報を読み込み中…</p> : loadState === "error" ? <RetryState message={error} onRetry={() => void load()} /> : sessions.length === 0 ? <EmptyState title="アクティブなセッションはありません" copy="再読み込みして、現在のログイン状態を確認してください。" /> : <ul className="row-list">{sessions.map((session) => <SessionRow key={session.id} session={session} actionKey={actionKey} confirmKey={confirmKey} onRevoke={() => setConfirmKey(`session:${session.id}`)} onCancel={() => setConfirmKey(null)} onConfirm={() => void runAction(`session:${session.id}`, async () => { if (session.current) { await client.revokeCurrentSession(session.id, session.version); setSignedOut(true); onSessionSignedOut?.(); } else await client.revokeSession(session.id, session.version); }, session.current ? "サインアウトしました。" : "セッションを無効化しました。", !session.current)} />)}</ul>}
    </article>
    {notice ? <p className="security-panel__notice" role="status">✓ {notice}</p> : null}
    {error && loadState === "ready" ? <p className="security-panel__error" role="alert">{error}</p> : null}
  </section>;
}

function PasskeyRow({ passkey, lastUsable, actionKey, confirmKey, onRename, onRevoke, onCancel, onConfirm }: { passkey: SecurityPasskey; lastUsable: boolean; actionKey: string | null; confirmKey: string | null; onRename: () => void; onRevoke: () => void; onCancel: () => void; onConfirm: () => void }) {
  const key = `passkey:${passkey.id}`;
  const busy = actionKey === key;
  return <li className="row-list-item"><div className="row-main"><span className="row-icon" aria-hidden="true">⌁</span><div><p className="row-title">{passkey.label}</p><p className="row-description">登録：{formatSecurityDate(passkey.createdAt)} · 最終使用：{passkey.lastUsedAt ? formatSecurityDate(passkey.lastUsedAt) : "まだ使用されていません"}</p></div></div><span className="security-panel__row-actions">{confirmKey === key ? <><button className="text-button" type="button" disabled={actionKey !== null || lastUsable} aria-describedby={lastUsable ? "security-passkey-revoke-guidance" : undefined} onClick={onConfirm}>{busy ? "処理中…" : "無効化する"}</button><button className="text-button" type="button" disabled={actionKey !== null} onClick={onCancel}>キャンセル</button></> : <><button className="text-button" type="button" disabled={actionKey !== null} onClick={onRename}>名前を変更</button><button className="text-button" type="button" disabled={actionKey !== null || lastUsable} aria-describedby={lastUsable ? "security-passkey-revoke-guidance" : undefined} onClick={onRevoke}>無効化</button></>}</span></li>;
}

function SessionRow({ session, actionKey, confirmKey, onRevoke, onCancel, onConfirm }: { session: SecuritySession; actionKey: string | null; confirmKey: string | null; onRevoke: () => void; onCancel: () => void; onConfirm: () => void }) {
  const key = `session:${session.id}`;
  const busy = actionKey === key;
  return <li className="row-list-item"><div className="row-main"><span className="row-icon" aria-hidden="true">◌</span><div><p className="row-title">{session.label}{session.current ? "（この端末）" : ""}</p><p className="row-description">{session.platform} · 最終確認：{formatSecurityDate(session.lastSeenAt)} · 有効期限：{formatSecurityDate(session.expiresAt)}</p></div></div><span className="security-panel__row-actions">{session.current ? <StatusTag>現在のセッション</StatusTag> : null}{confirmKey === key ? <><button className="text-button" type="button" disabled={actionKey !== null} onClick={onConfirm}>{busy ? "処理中…" : session.current ? "サインアウトする" : "無効化する"}</button><button className="text-button" type="button" disabled={actionKey !== null} onClick={onCancel}>キャンセル</button></> : <button className="text-button" type="button" disabled={actionKey !== null} onClick={onRevoke}>{session.current ? "サインアウト" : "無効化"}</button>}</span></li>;
}

function RenameForm({ label, busy, onChange, onCancel, onSubmit }: { label: string; busy: boolean; onChange: (value: string) => void; onCancel: () => void; onSubmit: () => void }) {
  return <form className="security-panel__rename" onSubmit={(event) => { event.preventDefault(); onSubmit(); }}><label htmlFor="security-passkey-label">パスキーの表示名<input id="security-passkey-label" required maxLength={80} value={label} onChange={(event) => onChange(event.target.value)} autoComplete="off" /></label><div><button className="primary-button" type="submit" disabled={busy || label.trim().length === 0}>保存</button><button className="text-button" type="button" disabled={busy} onClick={onCancel}>キャンセル</button></div></form>;
}

function RetryState({ message, onRetry }: { message: string; onRetry: () => void }) {
  return <div className="security-panel__retry" role="alert"><p className="section-note">{message}</p><button className="text-button" type="button" onClick={onRetry}>もう一度試す</button></div>;
}

function EmptyState({ title, copy }: { title: string; copy: string }) {
  return <div className="security-panel__empty"><p className="row-title">{title}</p><p className="row-description">{copy}</p></div>;
}

function StatusTag({ children }: { children: string }) {
  return <span className="tag green">{children}</span>;
}

function formatSecurityDate(value: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "日時不明";
  return new Intl.DateTimeFormat("ja-JP", { dateStyle: "medium", timeStyle: "short", timeZone: "Asia/Tokyo" }).format(date);
}

function securityPanelError(error: unknown): string {
  if (isLastActiveCredentialError(error)) return "このパスキーは最後の利用可能なパスキーのため無効化できません。先に別のパスキーを登録してください。";
  if (isSessionError(error)) return "セッションの有効期限が切れています。ページを再読み込みして、もう一度お試しください。";
  if (error instanceof SecurityClientError && error.status === 409) return "情報が更新されています。再読み込みしてから、もう一度お試しください。";
  if (error instanceof WebAuthnClientError) return "パスキーの確認を完了できませんでした。キャンセルした場合は、もう一度お試しください。";
  return "セキュリティ操作を完了できませんでした。接続と権限を確認して、もう一度お試しください。";
}

const LAST_ACTIVE_CREDENTIAL_CODES = new Set([
  "human_management_last_active_credential",
  "last_active_credential",
  "sole_active_credential",
  "last_credential",
  "err_last_active_credential",
  "err_sole_active_credential",
]);

function isLastActiveCredentialError(error: unknown): boolean {
  return error instanceof SecurityClientError && error.serviceCode !== undefined && LAST_ACTIVE_CREDENTIAL_CODES.has(error.serviceCode.toLowerCase());
}

function handleSessionFailure(error: unknown, onSessionExpired: (() => void) | undefined): void {
  if (isSessionError(error)) onSessionExpired?.();
}

function isSessionError(error: unknown): boolean {
  return (error instanceof SecurityClientError || error instanceof WebAuthnClientError) && SESSION_RETRY_STATUSES.has(error.status ?? 0);
}

function isAbortError(error: unknown): boolean {
  return error instanceof DOMException && error.name === "AbortError";
}
