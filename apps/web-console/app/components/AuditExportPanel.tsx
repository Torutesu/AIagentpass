"use client";

import { useEffect, useMemo, useState } from "react";
import { createAuditExportClient, type AuditExport, type AuditExportChain, type AuditExportEnvironment, type AuditExportRole, type AuditExportVerification } from "../audit-export-client";
import { authenticateRecentAuth } from "../webauthn-client";

type ViewState = "loading" | "empty" | "success" | "expired" | "corrupt" | "offline" | "response-loss";

async function contextHash(organizationId: string, exportId: string, environment: AuditExportEnvironment, chain: AuditExportChain): Promise<string> {
  const context = { version: 1, organization_id: organizationId, export_id: exportId, environment, chain };
  const context_hash = `{${Object.keys(context).sort().map((key) => `${JSON.stringify(key)}:${JSON.stringify(context[key as keyof typeof context])}`).join(",")}}`;
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(context_hash));
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function messageFor(state: ViewState): string {
  return {
    loading: "読み込み中…",
    empty: "監査エクスポートはまだありません。作成すると、監査記録を署名付きで保存できます。",
    success: "検証済みの監査エクスポートです。",
    expired: "有効期限が切れています。記録は確認できますが、新しいエクスポートの作成を推奨します。",
    corrupt: "内容を検証できません。ダウンロードや共有を中止してください。",
    offline: "接続できません。ネットワークを確認して、もう一度お試しください。",
    "response-loss": "応答を確認できません。再作成せず、同じIDで取得を再試行してください。",
  }[state];
}

function resultState(error: unknown): ViewState {
  const code = typeof error === "object" && error && "code" in error ? String(error.code) : "response_loss";
  if (code === "empty") return "empty";
  if (code === "expired") return "expired";
  if (code === "offline") return "offline";
  if (code === "corrupt" || code === "invalid_response") return "corrupt";
  return "response-loss";
}

export function AuditExportPanel({ role, organizationId, csrfToken }: { role: AuditExportRole; organizationId: string; csrfToken: string }) {
  const [environment, setEnvironment] = useState<AuditExportEnvironment>("production");
  const [chain, setChain] = useState<AuditExportChain>("admin");
  const [exportId, setExportId] = useState("");
  const [auditExport, setAuditExport] = useState<AuditExport | null>(null);
  const [verification, setVerification] = useState<AuditExportVerification | null>(null);
  const [state, setState] = useState<ViewState>("empty");
  const [error, setError] = useState("");
  const client = useMemo(() => createAuditExportClient({ role }), [role]);
  const canCreate = role === "owner" || role === "admin";
  const canRead = role === "owner" || role === "admin" || role === "auditor";

  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") setError("");
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, []);

  if (!canRead) {
    return <section className="audit-export-panel" aria-labelledby="audit-export-title"><h1 id="audit-export-title">監査エクスポート</h1><p role="alert">監査エクスポートを表示する権限がありません。viewer は閲覧権限がありません。</p></section>;
  }

  const authenticate = async (operation: "audit.export.create" | "audit.export.retrieve" | "audit.export.verify" | "audit.export.download", id: string) => {
    const hash = await contextHash(organizationId, id, environment, chain);
    return authenticateRecentAuth({ operation, organizationId, csrfToken, contextHash: hash });
  };

  const create = async () => {
    const id = crypto.randomUUID();
    setExportId(id);
    setState("loading");
    setError("");
    try {
      const { authorization_id } = await authenticate("audit.export.create", id);
      const value = await client.createAuditExport({ export_id: id, environment, chain, csrf: csrfToken, recentAuth: authorization_id, contextHash: await contextHash(organizationId, id, environment, chain) });
      setAuditExport(value);
      setVerification(null);
      setState(value.validity === "expired" ? "expired" : "success");
    } catch (caught) {
      const next = resultState(caught);
      setState(next);
      setError(messageFor(next));
    }
  };

  const retrieve = async () => {
    if (!exportId) return;
    setState("loading");
    setError("");
    try {
      const hash = await contextHash(organizationId, exportId, environment, chain);
      const { authorization_id } = await authenticate("audit.export.retrieve", exportId);
      const value = await client.getAuditExport({ export_id: exportId, environment, chain, recentAuth: authorization_id, context_hash: hash });
      setAuditExport(value);
      setVerification(null);
      setState(value.validity === "expired" ? "expired" : "success");
    } catch (caught) {
      const next = resultState(caught);
      setState(next);
      setError(messageFor(next));
    }
  };

  const verify = async () => {
    if (!auditExport) return;
    setState("loading");
    try {
      const { authorization_id } = await authenticate("audit.export.verify", auditExport.export_id);
      const result = await client.verifyAuditExport(auditExport, authorization_id, csrfToken);
      setVerification(result);
      setState(result.valid ? (auditExport.validity === "expired" ? "expired" : "success") : "corrupt");
    } catch (caught) {
      const next = resultState(caught);
      setState(next);
      setError(messageFor(next));
    }
  };

  const download = async () => {
    if (!auditExport) return;
    try {
      const { authorization_id } = await authenticate("audit.export.download", auditExport.export_id);
      await client.downloadAuditExport({ export_id: auditExport.export_id, environment, chain, recentAuth: authorization_id });
    } catch (caught) {
      const next = resultState(caught);
      setState(next);
      setError(messageFor(next));
    }
  };

  // Kept local so any future in-memory canonical copy follows the same bounded,
  // revocable browser lifecycle as the server download path.
  const downloadCanonicalCopy = (bytes: Uint8Array, filename: string) => {
    const blob = new Blob([bytes], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    try {
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = filename;
      anchor.click();
    } finally {
      URL.revokeObjectURL(url);
    }
  };
  void downloadCanonicalCopy;

  return <section className="audit-export-panel" aria-labelledby="audit-export-title" aria-busy={state === "loading"} data-state={state}>
    <header className="audit-export-header"><div><span className="section-kicker">AUDIT EXPORTS</span><h1 id="audit-export-title">監査エクスポート</h1><p>Agentの操作記録を改ざん検知できる署名付きファイルとして作成・検証します。作成と取得にはTouch IDまたはパスキーで再認証します。</p></div></header>
    <div className="audit-export-controls" aria-describedby="audit-export-help">
      <label htmlFor="audit-export-environment">環境</label><select id="audit-export-environment" value={environment} onChange={(event) => setEnvironment(event.target.value as AuditExportEnvironment)}><option value="production">production（本番）</option><option value="staging">staging（検証）</option></select>
      <label htmlFor="audit-export-chain">対象チェーン</label><select id="audit-export-chain" value={chain} onChange={(event) => setChain(event.target.value as AuditExportChain)}><option value="admin">admin（管理操作）</option><option value="device">device（端末操作）</option><option value="cloud_agent">cloud_agent（Cloud Agent）</option></select>
      <label htmlFor="audit-export-id">エクスポートID</label><input id="audit-export-id" value={exportId} onChange={(event) => setExportId(event.target.value.trim().toLowerCase())} placeholder="作成時は自動生成されます" autoComplete="off" />
      <p id="audit-export-help">既存の記録を開く場合は、作成時に表示されたIDを入力してください。</p>
      <div className="audit-export-actions">{canCreate ? <button type="button" className="primary-button" disabled={state === "loading"} onClick={() => void create()}>パスキーで認証してエクスポートを作成</button> : <span>auditor は作成できません。</span>}<button type="button" className="secondary-button" disabled={!exportId || state === "loading"} onClick={() => void retrieve()}>再認証して取得</button></div>
    </div>
    <div className="audit-export-status" aria-live="polite" role="status"><strong>{state === "success" ? "検証済み" : state}</strong><p>{messageFor(state)}</p>{["offline", "response-loss", "corrupt"].includes(state) ? <button type="button" className="text-button" onClick={() => void retrieve()}>もう一度試す</button> : null}</div>
    {error ? <p role="alert">{error}</p> : null}
    {auditExport ? <article className="audit-export-details"><h2>検証の詳細</h2><dl><div><dt>environment</dt><dd>{auditExport.environment}</dd></div><div><dt>chain</dt><dd>{auditExport.chain}</dd></div><div><dt>payload_digest</dt><dd>{auditExport.payload_digest}</dd></div><div><dt>監査範囲 range</dt><dd>{JSON.stringify(auditExport.range)}</dd></div><div><dt>署名 audit_anchor</dt><dd>key_id {String(auditExport.audit_anchor.key_id)} / key_version {String(auditExport.audit_anchor.key_version)} / lifecycle_version {String(auditExport.audit_anchor.lifecycle_version)} / expires_at {String(auditExport.audit_anchor.expires_at)}</dd></div><div><dt>validity</dt><dd>{auditExport.validity}</dd></div></dl><div className="audit-export-actions"><button type="button" className="secondary-button" onClick={() => void verify()}>検証する</button><button type="button" className="secondary-button" onClick={() => void download()}>ダウンロード</button></div>{verification ? <p className={verification.valid ? "verification-valid" : "verification-invalid"}>検証結果: {verification.valid ? "署名・監査範囲ともに正常" : `不一致（${verification.reason}）`}</p> : null}</article> : null}
  </section>;
}
