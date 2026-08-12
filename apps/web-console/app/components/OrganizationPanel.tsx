"use client";

import { useCallback, useEffect, useMemo, useRef, useState, type FormEvent } from "react";
import {
  createOrganizationClient,
  getOrganizationVisibility,
  OrganizationClientError,
  type InvitationRole,
  type Organization,
  type OrganizationClient,
  type OrganizationInvitation,
  type OrganizationMember,
  type OrganizationRole,
  type RecentAuthInput,
} from "../organization-client";

export type OrganizationPanelProps = Readonly<{
  client?: OrganizationClient;
  initialOrganizationId?: string;
  authorizeRecentAuthImpl?: (input: RecentAuthInput) => Promise<string | Readonly<{ authorization_id: string }>>;
}>;

type LoadStatus = "idle" | "loading" | "ready" | "empty" | "error";
type ResourceState = Readonly<{ status: LoadStatus; error?: string }>;

const INITIAL_RESOURCE: ResourceState = Object.freeze({ status: "idle" });
const ROLES: readonly OrganizationRole[] = ["owner", "admin", "auditor", "viewer"];
const INVITE_ROLES: readonly InvitationRole[] = ["admin", "auditor", "viewer"];

const panelStyle = {
  shell: { display: "grid", gap: 24, maxWidth: 1180, margin: "0 auto", padding: "36px 24px 64px", color: "#1e2a25" },
  header: { display: "flex", justifyContent: "space-between", gap: 20, alignItems: "flex-start", flexWrap: "wrap" as const },
  eyebrow: { margin: 0, color: "#64716a", fontSize: 11, fontWeight: 700, letterSpacing: "0.14em" },
  heading: { margin: "6px 0 0", fontSize: "clamp(26px, 4vw, 42px)", lineHeight: 1.12, letterSpacing: "-0.04em" },
  copy: { maxWidth: 680, margin: "10px 0 0", color: "#64716a", lineHeight: 1.7 },
  grid: { display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(290px, 1fr))", gap: 16 },
  card: { display: "grid", gap: 14, padding: 20, border: "1px solid #dcded5", borderRadius: 12, background: "#fbfaf6", boxShadow: "0 12px 28px rgba(33,46,39,.05)" },
  cardTitle: { margin: 0, fontSize: 17, letterSpacing: "-0.02em" },
  label: { display: "grid", gap: 6, color: "#64716a", fontSize: 12, fontWeight: 700 },
  input: { minHeight: 40, width: "100%", padding: "8px 10px", border: "1px solid #c5cec3", borderRadius: 7, background: "#fff", color: "#1e2a25" },
  select: { minHeight: 36, padding: "6px 8px", border: "1px solid #c5cec3", borderRadius: 7, background: "#fff", color: "#1e2a25" },
  button: { minHeight: 38, padding: "7px 13px", border: "1px solid #164a3a", borderRadius: 7, background: "#164a3a", color: "#fff", fontWeight: 700 },
  secondaryButton: { minHeight: 36, padding: "6px 11px", border: "1px solid #c5cec3", borderRadius: 7, background: "#fff", color: "#164a3a", fontWeight: 700 },
  dangerButton: { minHeight: 36, padding: "6px 11px", border: "1px solid #a13f37", borderRadius: 7, background: "#fff", color: "#a13f37", fontWeight: 700 },
  row: { display: "flex", alignItems: "center", justifyContent: "space-between", gap: 12, flexWrap: "wrap" as const },
  muted: { margin: 0, color: "#64716a", fontSize: 13 },
  list: { display: "grid", gap: 8, margin: 0, padding: 0, listStyle: "none" },
  listRow: { display: "grid", gap: 8, padding: "12px 0", borderTop: "1px solid #ecece5" },
  actionRow: { display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" as const },
  state: { padding: 14, borderRadius: 8, background: "#f2f0e8", color: "#64716a" },
  error: { padding: 14, borderRadius: 8, background: "#f3ddda", color: "#7d302b" },
  conflict: { padding: 14, borderRadius: 8, background: "#f4e8c9", color: "#80551b" },
  token: { display: "block", overflowWrap: "anywhere" as const, padding: 12, border: "1px dashed #a86c1f", borderRadius: 7, background: "#fff9e9", color: "#80551b", fontFamily: "SFMono-Regular, Consolas, monospace", fontSize: 12 },
} as const;

export function getOrganizationPanelVisibility(role: OrganizationRole) {
  return getOrganizationVisibility(role);
}

export function OrganizationPanel({ client: suppliedClient, initialOrganizationId, authorizeRecentAuthImpl }: OrganizationPanelProps) {
  const client = useMemo(() => suppliedClient ?? createOrganizationClient({ authorizeRecentAuthImpl }), [suppliedClient, authorizeRecentAuthImpl]);
  const [organizations, setOrganizations] = useState<readonly Organization[]>([]);
  const [selectedOrganizationId, setSelectedOrganizationId] = useState<string>(initialOrganizationId ?? "");
  const [selectedOrganization, setSelectedOrganization] = useState<Organization | undefined>();
  const [sessionRole, setSessionRole] = useState<OrganizationRole>("viewer");
  const [sessionOrganizationId, setSessionOrganizationId] = useState<string | undefined>();
  const [sessionMemberId, setSessionMemberId] = useState<string | undefined>();
  const [roleOverrides, setRoleOverrides] = useState<Readonly<Record<string, OrganizationRole>>>({});
  const [organizationState, setOrganizationState] = useState<ResourceState>({ status: "loading" });
  const [members, setMembers] = useState<readonly OrganizationMember[]>([]);
  const [memberState, setMemberState] = useState<ResourceState>(INITIAL_RESOURCE);
  const [invitations, setInvitations] = useState<readonly OrganizationInvitation[]>([]);
  const [invitationState, setInvitationState] = useState<ResourceState>(INITIAL_RESOURCE);
  const [mutationError, setMutationError] = useState<ResourceState>(INITIAL_RESOURCE);
  const [pendingAction, setPendingAction] = useState<string | null>(null);
  const [refreshNonce, setRefreshNonce] = useState(0);
  const [createName, setCreateName] = useState("");
  const [renameName, setRenameName] = useState("");
  const [inviteRole, setInviteRole] = useState<InvitationRole>("viewer");
  const [inviteExpiresAt, setInviteExpiresAt] = useState("");
  const [acceptToken, setAcceptToken] = useState("");
  const [oneTimeToken, setOneTimeToken] = useState<string | null>(null);
  const [roleDrafts, setRoleDrafts] = useState<Readonly<Record<string, OrganizationRole>>>({});
  const loadSequence = useRef(0);
  const selectedOrganizationRef = useRef(initialOrganizationId ?? "");

  const effectiveRole = selectedOrganizationId !== "" && roleOverrides[selectedOrganizationId] !== undefined
    ? roleOverrides[selectedOrganizationId]
    : selectedOrganizationId !== "" && selectedOrganizationId === sessionOrganizationId ? sessionRole : "viewer";
  const visibility = useMemo(() => getOrganizationPanelVisibility(effectiveRole), [effectiveRole]);

  const loadOrganizations = useCallback(async (signal?: AbortSignal) => {
    const sequence = ++loadSequence.current;
    setOrganizationState({ status: "loading" });
    try {
      const [page, session] = await Promise.all([client.listOrganizations({ signal }), client.getSession({ signal })]);
      if (sequence !== loadSequence.current || signal?.aborted) return;
      setOrganizations(page.items);
      setSessionRole(session.role);
      setSessionOrganizationId(session.organizationId);
      setSessionMemberId(session.memberId);
      setRoleOverrides((current) => ({ ...current, [session.organizationId]: session.role }));
      const nextId = chooseOrganization(page.items, initialOrganizationId ?? selectedOrganizationRef.current, session.organizationId);
      selectedOrganizationRef.current = nextId;
      setSelectedOrganizationId(nextId);
      setSelectedOrganization(nextId === "" ? undefined : page.items.find((item) => item.id === nextId));
      setRenameName(nextId === "" ? "" : page.items.find((item) => item.id === nextId)?.name ?? "");
      setOrganizationState({ status: page.items.length === 0 ? "empty" : "ready" });
    } catch (error) {
      if (sequence !== loadSequence.current || signal?.aborted) return;
      setOrganizationState(resourceError(error));
    }
  }, [client, initialOrganizationId]);

  const loadMembers = useCallback(async (organizationId: string, signal?: AbortSignal) => {
    setMemberState({ status: "loading" });
    try {
      const page = await client.listMembers(organizationId, { signal });
      if (signal?.aborted) return;
      setMembers(page.items);
      setMemberState({ status: page.items.length === 0 ? "empty" : "ready" });
    } catch (error) {
      if (!signal?.aborted) setMemberState(resourceError(error));
    }
  }, [client]);

  const loadInvitations = useCallback(async (organizationId: string, signal?: AbortSignal) => {
    setInvitationState({ status: "loading" });
    try {
      const page = await client.listInvitations(organizationId, { signal });
      if (signal?.aborted) return;
      setInvitations(page.items);
      setInvitationState({ status: page.items.length === 0 ? "empty" : "ready" });
    } catch (error) {
      if (!signal?.aborted) setInvitationState(resourceError(error));
    }
  }, [client]);

  useEffect(() => {
    const controller = new AbortController();
    const timer = setTimeout(() => void loadOrganizations(controller.signal), 0);
    return () => { clearTimeout(timer); controller.abort(); };
  }, [loadOrganizations, refreshNonce]);

  useEffect(() => {
    const controller = new AbortController();
    const timer = setTimeout(() => {
      if (selectedOrganizationId === "" || !visibility.canViewMembers) {
        setMembers([]);
        setInvitations([]);
        setMemberState(INITIAL_RESOURCE);
        setInvitationState(INITIAL_RESOURCE);
        return;
      }
      void loadMembers(selectedOrganizationId, controller.signal);
      void loadInvitations(selectedOrganizationId, controller.signal);
    }, 0);
    return () => { clearTimeout(timer); controller.abort(); };
  }, [loadInvitations, loadMembers, selectedOrganizationId, visibility.canViewMembers, refreshNonce]);

  useEffect(() => {
    if (selectedOrganizationId === "" || sessionMemberId === undefined || selectedOrganizationId === sessionOrganizationId || roleOverrides[selectedOrganizationId] !== undefined) return;
    const controller = new AbortController();
    void client.listMembers(selectedOrganizationId, { signal: controller.signal }).then((page) => {
      if (controller.signal.aborted) return;
      const actorMembership = page.items.find((member) => member.memberId === sessionMemberId && member.status === "active");
      setRoleOverrides((current) => ({ ...current, [selectedOrganizationId]: actorMembership?.role ?? "viewer" }));
    }).catch((error) => {
      if (controller.signal.aborted) return;
      if (error instanceof OrganizationClientError && (error.code === "forbidden" || error.code === "unauthorized")) {
        setRoleOverrides((current) => ({ ...current, [selectedOrganizationId]: "viewer" }));
      }
    });
    return () => controller.abort();
  }, [client, roleOverrides, selectedOrganizationId, sessionMemberId, sessionOrganizationId]);

  const selectOrganization = (id: string) => {
    const next = organizations.find((item) => item.id === id);
    selectedOrganizationRef.current = id;
    setSelectedOrganizationId(id);
    setSelectedOrganization(next);
    setRenameName(next?.name ?? "");
    setMutationError(INITIAL_RESOURCE);
  };

  const runMutation = async (action: string, operation: () => Promise<void>) => {
    if (pendingAction !== null) return;
    setPendingAction(action);
    setMutationError(INITIAL_RESOURCE);
    try {
      await operation();
      setRefreshNonce((value) => value + 1);
    } catch (error) {
      setMutationError(resourceError(error));
    } finally {
      setPendingAction(null);
    }
  };

  const createOrganization = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const name = createName.trim();
    if (name === "") return setMutationError({ status: "error", error: "組織名を入力してください。" });
    await runMutation("create-organization", async () => {
      const result = await client.createOrganization({ name });
      setCreateName("");
      setRoleOverrides((current) => ({ ...current, [result.organization.id]: "owner" }));
      selectedOrganizationRef.current = result.organization.id;
      setSelectedOrganizationId(result.organization.id);
    });
  };

  const renameOrganization = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!selectedOrganization || !visibility.canManageOrganization) return;
    const name = renameName.trim();
    if (name === "") return setMutationError({ status: "error", error: "組織名を入力してください。" });
    await runMutation("rename-organization", async () => {
      const result = await client.renameOrganization({ organizationId: selectedOrganization.id, name, expectedVersion: selectedOrganization.version });
      setSelectedOrganization(result.organization);
    });
  };

  const createInvitation = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!selectedOrganization || !visibility.canInvite) return;
    const expiresAt = parseDateTimeLocal(inviteExpiresAt);
    if (expiresAt === undefined) return setMutationError({ status: "error", error: "有効期限を入力してください。" });
    await runMutation("create-invitation", async () => {
      const result = await client.createInvitation({ organizationId: selectedOrganization.id, role: inviteRole, expiresAt });
      setOneTimeToken(result.oneTimeToken);
      setInviteExpiresAt("");
    });
  };

  const acceptInvitation = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const token = acceptToken.trim();
    if (token === "") return setMutationError({ status: "error", error: "招待トークンを入力してください。" });
    await runMutation("accept-invitation", async () => {
      await client.acceptInvitation({ oneTimeToken: token });
      setAcceptToken("");
    });
  };

  const refresh = () => setRefreshNonce((value) => value + 1);
  const roleLabel = { owner: "Owner", admin: "Admin", auditor: "Auditor", viewer: "Viewer" }[effectiveRole];

  return (
    <main style={panelStyle.shell} aria-labelledby="organization-panel-title">
      <header style={panelStyle.header}>
        <div>
          <p style={panelStyle.eyebrow}>ORGANIZATION ADMINISTRATION</p>
          <h1 id="organization-panel-title" style={panelStyle.heading}>組織を安全に管理する</h1>
          <p style={panelStyle.copy}>Agentの利用単位となる組織、メンバー、招待を管理します。変更にはバージョン競合検知と監査可能な操作境界が適用されます。</p>
        </div>
        <button type="button" style={panelStyle.secondaryButton} onClick={refresh} disabled={pendingAction !== null}>再読み込み</button>
      </header>

      {organizationState.status === "loading" && <p style={panelStyle.state} data-state="loading" role="status">組織を読み込み中です…</p>}
      {organizationState.status === "error" && <p style={panelStyle.error} data-state="error" role="alert">{organizationState.error}</p>}
      {organizationState.status === "empty" && (
        <section style={panelStyle.card} data-state="empty" aria-labelledby="organization-empty-title">
          <h2 id="organization-empty-title" style={panelStyle.cardTitle}>組織がまだありません</h2>
          <p style={panelStyle.muted}>最初の組織を作成すると、Coding Agentのメンバーと権限を管理できます。</p>
          <CreateOrganizationForm name={createName} setName={setCreateName} onSubmit={createOrganization} pending={pendingAction === "create-organization"} />
        </section>
      )}

      {organizations.length > 0 && (
        <section style={panelStyle.card} aria-labelledby="organization-selector-title">
          <div style={panelStyle.row}>
            <div><h2 id="organization-selector-title" style={panelStyle.cardTitle}>組織</h2><p style={panelStyle.muted}>現在の権限: {roleLabel}</p></div>
            <label style={{ ...panelStyle.label, minWidth: 260 }}><span className="sr-only">組織を選択</span><select value={selectedOrganizationId} onChange={(event) => selectOrganization(event.target.value)} style={panelStyle.select} aria-label="組織を選択">{organizations.map((organization) => <option key={organization.id} value={organization.id}>{organization.name}</option>)}</select></label>
          </div>
          {selectedOrganization && <div style={panelStyle.row}><span>{selectedOrganization.name} · v{selectedOrganization.version}</span><span style={panelStyle.muted}>更新: {formatDate(selectedOrganization.updatedAt)}</span></div>}
          {visibility.canManageOrganization && selectedOrganization && <form onSubmit={renameOrganization} style={panelStyle.actionRow}><label style={{ ...panelStyle.label, flex: "1 1 280px" }}><span>組織名を変更</span><input value={renameName} onChange={(event) => setRenameName(event.target.value)} maxLength={128} style={panelStyle.input} /></label><button type="submit" style={panelStyle.button} disabled={pendingAction !== null}>{pendingAction === "rename-organization" ? "変更中…" : "名前を変更"}</button></form>}
          {!visibility.canManageOrganization && <p style={panelStyle.muted}>この組織では閲覧権限のみです。管理操作は表示されません。</p>}
        </section>
      )}

      {mutationError.status === "error" && <p style={mutationError.error?.includes("競合") ? panelStyle.conflict : panelStyle.error} data-state={mutationError.error?.includes("競合") ? "conflict" : "error"} role="alert">{mutationError.error}</p>}

      {selectedOrganization && visibility.canViewMembers && (
        <section style={panelStyle.card} aria-labelledby="organization-members-title">
          <div style={panelStyle.row}><div><h2 id="organization-members-title" style={panelStyle.cardTitle}>メンバー</h2><p style={panelStyle.muted}>Owner / Admin / Auditorはメンバー情報を閲覧できます。</p></div><span style={panelStyle.muted}>{members.length}人</span></div>
          <ResourceStateView state={memberState} empty="メンバーはいません。" error="メンバー情報を取得できませんでした。" />
          {memberState.status === "ready" && <ul style={panelStyle.list}>{members.map((member) => <MemberRow key={member.membershipId} member={member} canManage={visibility.canManageMembers && (member.role !== "owner" || visibility.canAssignOwner)} canAssignOwner={visibility.canAssignOwner} draft={roleDrafts[member.memberId] ?? member.role} setDraft={(role) => setRoleDrafts((current) => ({ ...current, [member.memberId]: role }))} pendingAction={pendingAction} onRoleChange={() => void runMutation(`member-role-${member.memberId}`, async () => { await client.updateMemberRole({ organizationId: member.organizationId, memberId: member.memberId, role: roleDrafts[member.memberId] ?? member.role, expectedVersion: member.version }); })} onRemove={() => void runMutation(`member-remove-${member.memberId}`, async () => { await client.removeMember({ organizationId: member.organizationId, memberId: member.memberId, expectedVersion: member.version }); })} />)}</ul>}
        </section>
      )}

      {selectedOrganization && visibility.canViewInvitations && (
        <section style={panelStyle.grid} aria-label="招待管理">
          <section style={panelStyle.card} aria-labelledby="organization-invitations-title">
            <div style={panelStyle.row}><div><h2 id="organization-invitations-title" style={panelStyle.cardTitle}>招待</h2><p style={panelStyle.muted}>招待トークンは発行時のコンポーネントメモリにのみ保持します。</p></div><span style={panelStyle.muted}>{invitations.length}件</span></div>
            <ResourceStateView state={invitationState} empty="招待はありません。" error="招待情報を取得できませんでした。" />
            {invitationState.status === "ready" && <ul style={panelStyle.list}>{invitations.map((invitation) => <InvitationRow key={invitation.id} invitation={invitation} canRevoke={visibility.canRevokeInvitations} pendingAction={pendingAction} onRevoke={() => void runMutation(`invitation-revoke-${invitation.id}`, async () => { await client.revokeInvitation({ organizationId: invitation.organizationId, invitationId: invitation.id, expectedVersion: invitation.version }); })} />)}</ul>}
          </section>
          {visibility.canInvite && <InviteForm role={inviteRole} setRole={setInviteRole} expiresAt={inviteExpiresAt} setExpiresAt={setInviteExpiresAt} onSubmit={createInvitation} pending={pendingAction === "create-invitation"} />}
        </section>
      )}

      <section style={panelStyle.card} aria-labelledby="accept-invitation-title">
        <h2 id="accept-invitation-title" style={panelStyle.cardTitle}>招待を受け入れる</h2>
        <p style={panelStyle.muted}>受け取った一回限りのトークンを、この画面のメモリ上でのみ送信します。</p>
        <form onSubmit={acceptInvitation} style={panelStyle.actionRow}><label style={{ ...panelStyle.label, flex: "1 1 460px" }}><span>招待トークン</span><input value={acceptToken} onChange={(event) => setAcceptToken(event.target.value)} autoComplete="off" inputMode="text" style={panelStyle.input} /></label><button type="submit" style={panelStyle.button} disabled={pendingAction !== null}>{pendingAction === "accept-invitation" ? "受け入れ中…" : "招待を受け入れる"}</button></form>
      </section>

      {oneTimeToken !== null && <section style={panelStyle.card} aria-live="polite" aria-labelledby="one-time-token-title"><div style={panelStyle.row}><h2 id="one-time-token-title" style={panelStyle.cardTitle}>招待トークン（一度だけ表示）</h2><button type="button" style={panelStyle.secondaryButton} onClick={() => setOneTimeToken(null)}>閉じる</button></div><p style={panelStyle.muted}>安全な経路で招待相手へ渡してください。ページを離れる、再読み込みする、または閉じると再取得できません。</p><code style={panelStyle.token}>{oneTimeToken}</code></section>}
    </main>
  );
}

function CreateOrganizationForm({ name, setName, onSubmit, pending }: { name: string; setName: (value: string) => void; onSubmit: (event: FormEvent<HTMLFormElement>) => void; pending: boolean }) {
  return <form onSubmit={onSubmit} style={panelStyle.actionRow}><label style={{ ...panelStyle.label, flex: "1 1 320px" }}><span>組織名</span><input value={name} onChange={(event) => setName(event.target.value)} maxLength={128} required style={panelStyle.input} /></label><button type="submit" style={panelStyle.button} disabled={pending}>{pending ? "作成中…" : "組織を作成"}</button></form>;
}

function InviteForm({ role, setRole, expiresAt, setExpiresAt, onSubmit, pending }: { role: InvitationRole; setRole: (value: InvitationRole) => void; expiresAt: string; setExpiresAt: (value: string) => void; onSubmit: (event: FormEvent<HTMLFormElement>) => void; pending: boolean }) {
  return <section style={panelStyle.card} aria-labelledby="create-invitation-title"><h2 id="create-invitation-title" style={panelStyle.cardTitle}>招待を作成</h2><form onSubmit={onSubmit} style={{ display: "grid", gap: 12 }}><label style={panelStyle.label}><span>付与するロール</span><select value={role} onChange={(event) => setRole(event.target.value as InvitationRole)} style={panelStyle.select}>{INVITE_ROLES.map((value) => <option key={value} value={value}>{value}</option>)}</select></label><label style={panelStyle.label}><span>有効期限</span><input type="datetime-local" value={expiresAt} onChange={(event) => setExpiresAt(event.target.value)} required style={panelStyle.input} /></label><button type="submit" style={panelStyle.button} disabled={pending}>{pending ? "発行中…" : "招待を発行"}</button></form></section>;
}

function MemberRow({ member, canManage, canAssignOwner, draft, setDraft, pendingAction, onRoleChange, onRemove }: { member: OrganizationMember; canManage: boolean; canAssignOwner: boolean; draft: OrganizationRole; setDraft: (role: OrganizationRole) => void; pendingAction: string | null; onRoleChange: () => void; onRemove: () => void }) {
  const editableRoles = canAssignOwner ? ROLES : ROLES.filter((role) => role !== "owner");
  return <li style={panelStyle.listRow}><div style={panelStyle.row}><div><strong>{member.displayName ?? "名前未設定"}</strong><p style={panelStyle.muted}>{member.role} · {member.status === "active" ? "有効" : "失効"} · v{member.version}</p></div>{canManage && member.status === "active" && <div style={panelStyle.actionRow}><select aria-label={`${member.memberId}のロール`} value={draft} onChange={(event) => setDraft(event.target.value as OrganizationRole)} style={panelStyle.select}>{editableRoles.map((role) => <option key={role} value={role}>{role}</option>)}</select><button type="button" style={panelStyle.secondaryButton} disabled={pendingAction !== null} onClick={onRoleChange}>変更</button><button type="button" style={panelStyle.dangerButton} disabled={pendingAction !== null} onClick={onRemove}>削除</button></div>}</div></li>;
}

function InvitationRow({ invitation, canRevoke, pendingAction, onRevoke }: { invitation: OrganizationInvitation; canRevoke: boolean; pendingAction: string | null; onRevoke: () => void }) {
  return <li style={panelStyle.listRow}><div style={panelStyle.row}><div><strong>{invitation.role} 招待</strong><p style={panelStyle.muted}>{invitation.status} · {formatDate(invitation.expiresAt)} · v{invitation.version}</p></div>{canRevoke && invitation.status === "pending" && <button type="button" style={panelStyle.dangerButton} disabled={pendingAction !== null} onClick={onRevoke}>取り消す</button>}</div></li>;
}

function ResourceStateView({ state, empty, error }: { state: ResourceState; empty: string; error: string }) {
  if (state.status === "loading") return <p style={panelStyle.state} data-state="loading" role="status">読み込み中です…</p>;
  if (state.status === "empty") return <p style={panelStyle.state} data-state="empty">{empty}</p>;
  if (state.status === "error") return <p style={state.error?.includes("競合") ? panelStyle.conflict : panelStyle.error} data-state={state.error?.includes("競合") ? "conflict" : "error"} role="alert">{state.error ?? error}</p>;
  return null;
}

function chooseOrganization(items: readonly Organization[], requested: string, sessionOrganizationId: string): string {
  if (requested !== "" && items.some((item) => item.id === requested)) return requested;
  if (items.some((item) => item.id === sessionOrganizationId)) return sessionOrganizationId;
  return items[0]?.id ?? "";
}

function resourceError(error: unknown): ResourceState {
  if (error instanceof OrganizationClientError && error.code === "conflict") return { status: "error", error: "競合が発生しました。最新情報を読み込んでから、もう一度お試しください。" };
  if (error instanceof OrganizationClientError && error.code === "forbidden") return { status: "error", error: "この操作を実行する権限がありません。" };
  if (error instanceof OrganizationClientError && error.code === "unauthorized") return { status: "error", error: "セッションの有効期限が切れています。再読み込みしてください。" };
  if (error instanceof OrganizationClientError && error.code === "validation_failed") return { status: "error", error: "入力内容を確認してください。" };
  return { status: "error", error: "組織情報を取得できませんでした。接続を確認して、もう一度お試しください。" };
}

function parseDateTimeLocal(value: string): string | undefined {
  if (value === "") return undefined;
  const date = new Date(value);
  return Number.isFinite(date.getTime()) ? date.toISOString() : undefined;
}

function formatDate(value: string): string {
  const date = new Date(value);
  return Number.isFinite(date.getTime()) ? date.toLocaleString("ja-JP") : value;
}
