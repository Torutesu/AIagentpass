"use client";

import { useCallback, useEffect, useMemo, useRef, useState, type FormEvent } from "react";
import {
  createOrganizationClient,
  getOrganizationVisibility,
  isAmbiguousOrganizationMutationError,
  OrganizationClientError,
  type InvitationRole,
  type Organization,
  type OrganizationClient,
  type OrganizationClientErrorCode,
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
type ResourceState = Readonly<{ status: LoadStatus; error?: string; code?: OrganizationClientErrorCode | "last_owner_protected" | "reconciliation_required" }>;
type Rollback = () => void;
type MutationOptions = Readonly<{ optimistic?: () => Rollback; reconcile?: () => Promise<void>; retry?: () => Promise<void>; retryLabel?: string }>;
type RetryAction = Readonly<{ label: string; run: () => Promise<void> }>;

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
  const [memberNextCursor, setMemberNextCursor] = useState<string | null>(null);
  const [invitations, setInvitations] = useState<readonly OrganizationInvitation[]>([]);
  const [invitationState, setInvitationState] = useState<ResourceState>(INITIAL_RESOURCE);
  const [invitationNextCursor, setInvitationNextCursor] = useState<string | null>(null);
  const [loadingMore, setLoadingMore] = useState<"members" | "invitations" | null>(null);
  const [mutationError, setMutationError] = useState<ResourceState>(INITIAL_RESOURCE);
  const [pendingAction, setPendingAction] = useState<string | null>(null);
  const [retryAction, setRetryAction] = useState<RetryAction | null>(null);
  const [refreshNonce, setRefreshNonce] = useState(0);
  const [createName, setCreateName] = useState("");
  const [renameName, setRenameName] = useState("");
  const [inviteRole, setInviteRole] = useState<InvitationRole>("viewer");
  const [inviteExpiresAt, setInviteExpiresAt] = useState("");
  const [acceptToken, setAcceptToken] = useState("");
  const [oneTimeToken, setOneTimeToken] = useState<string | null>(null);
  const [reissueConfirmationId, setReissueConfirmationId] = useState<string | null>(null);
  const [reissueExpiresAt, setReissueExpiresAt] = useState("");
  const [roleDrafts, setRoleDrafts] = useState<Readonly<Record<string, OrganizationRole>>>({});
  const [removalConfirmationId, setRemovalConfirmationId] = useState<string | null>(null);
  const [nowMs, setNowMs] = useState(0);
  const loadSequence = useRef(0);
  const selectedOrganizationRef = useRef(initialOrganizationId ?? "");

  const effectiveRole = selectedOrganizationId !== "" && roleOverrides[selectedOrganizationId] !== undefined
    ? roleOverrides[selectedOrganizationId]
    : selectedOrganizationId !== "" && selectedOrganizationId === sessionOrganizationId ? sessionRole : "viewer";
  const visibility = useMemo(() => getOrganizationPanelVisibility(effectiveRole), [effectiveRole]);
  const activeOwnerCount = members.reduce((count, member) => count + (member.status === "active" && member.role === "owner" ? 1 : 0), 0);
  const ownerSnapshotComplete = memberNextCursor === null;
  const isFinalOwnerProtection = (member: OrganizationMember, nextRole: OrganizationRole | undefined): boolean => ownerSnapshotComplete && activeOwnerCount === 1 && member.status === "active" && member.role === "owner" && (nextRole === undefined || nextRole !== "owner");
  const showLastOwnerProtection = (member: OrganizationMember): void => {
    setRoleDrafts((current) => ({ ...current, [member.memberId]: member.role }));
    setRemovalConfirmationId(null);
    setMutationError({ status: "error", code: "last_owner_protected", error: "最後のOwnerは降格・失効できません。先に別のメンバーをOwnerに変更してから、もう一度お試しください。" });
  };

  const refreshOrganizationSnapshot = useCallback(async (signal?: AbortSignal): Promise<{ organizations: readonly Organization[]; session: Awaited<ReturnType<OrganizationClient["getSession"]>> }> => {
    const [organizationItems, session] = await Promise.all([loadAllOrganizations(client, signal), client.getSession({ signal })]);
    if (signal?.aborted) throw abortError();
    setOrganizations(organizationItems);
    setSessionRole(session.role);
    setSessionOrganizationId(session.organizationId);
    setSessionMemberId(session.memberId);
    setRoleOverrides((current) => current[session.organizationId] === undefined ? { ...current, [session.organizationId]: session.role } : current);
    const nextId = chooseOrganization(organizationItems, initialOrganizationId ?? selectedOrganizationRef.current, session.organizationId);
    selectedOrganizationRef.current = nextId;
    setSelectedOrganizationId(nextId);
    setSelectedOrganization(nextId === "" ? undefined : organizationItems.find((item) => item.id === nextId));
    setRenameName(nextId === "" ? "" : organizationItems.find((item) => item.id === nextId)?.name ?? "");
    return { organizations: organizationItems, session };
  }, [client, initialOrganizationId]);

  const loadOrganizations = useCallback(async (signal?: AbortSignal) => {
    const sequence = ++loadSequence.current;
    setOrganizationState({ status: "loading" });
    try {
      const { organizations: organizationItems } = await refreshOrganizationSnapshot(signal);
      if (sequence !== loadSequence.current || signal?.aborted) return;
      setOrganizationState({ status: organizationItems.length === 0 ? "empty" : "ready" });
    } catch (error) {
      if (sequence !== loadSequence.current || signal?.aborted) return;
      setOrganizations([]);
      setSelectedOrganizationId("");
      setSelectedOrganization(undefined);
      setMembers([]);
      setInvitations([]);
      setMemberState(INITIAL_RESOURCE);
      setInvitationState(INITIAL_RESOURCE);
      setMemberNextCursor(null);
      setInvitationNextCursor(null);
      setOrganizationState(resourceError(error));
    }
  }, [refreshOrganizationSnapshot]);

  const loadMembers = useCallback(async (organizationId: string, signal?: AbortSignal, cursor?: string) => {
    const append = cursor !== undefined;
    if (append) setLoadingMore("members");
    else {
      setMemberState({ status: "loading" });
      setMemberNextCursor(null);
      setRoleDrafts({});
    }
    try {
      const page = await client.listMembers(organizationId, { signal, limit: 100, ...(cursor === undefined ? {} : { cursor }) });
      if (signal?.aborted || selectedOrganizationRef.current !== organizationId) return;
      setMembers((current) => append ? [...current, ...page.items] : page.items);
      setMemberNextCursor(page.nextCursor);
      setMemberState((current) => append ? current : { status: page.items.length === 0 ? "empty" : "ready" });
      const actorMembership = page.items.find((member) => member.memberId === sessionMemberId);
      if (actorMembership !== undefined) {
        setRoleOverrides((current) => ({ ...current, [organizationId]: actorMembership.status === "active" ? actorMembership.role : "viewer" }));
      }
    } catch (error) {
      if (signal?.aborted) return;
      setMemberState(resourceError(error));
      if (error instanceof OrganizationClientError && (error.code === "forbidden" || error.code === "unauthorized")) {
        setRoleOverrides((current) => ({ ...current, [organizationId]: "viewer" }));
        setMembers([]);
        setInvitations([]);
        setMemberNextCursor(null);
        setInvitationNextCursor(null);
        setInvitationState(INITIAL_RESOURCE);
      }
    } finally {
      if (append) setLoadingMore(null);
    }
  }, [client, sessionMemberId]);

  const loadInvitations = useCallback(async (organizationId: string, signal?: AbortSignal, cursor?: string) => {
    const append = cursor !== undefined;
    if (append) setLoadingMore("invitations");
    else {
      setInvitationState({ status: "loading" });
      setInvitationNextCursor(null);
    }
    try {
      const page = await client.listInvitations(organizationId, { signal, limit: 100, ...(cursor === undefined ? {} : { cursor }) });
      if (signal?.aborted || selectedOrganizationRef.current !== organizationId) return;
      setInvitations((current) => append ? [...current, ...page.items] : page.items);
      setInvitationNextCursor(page.nextCursor);
      setInvitationState((current) => append ? current : { status: page.items.length === 0 ? "empty" : "ready" });
    } catch (error) {
      if (signal?.aborted) return;
      setInvitationState(resourceError(error));
      if (error instanceof OrganizationClientError && (error.code === "forbidden" || error.code === "unauthorized")) {
        setRoleOverrides((current) => ({ ...current, [organizationId]: "viewer" }));
        setInvitations([]);
        setInvitationNextCursor(null);
      }
    } finally {
      if (append) setLoadingMore(null);
    }
  }, [client]);

  const reconcileResources = useCallback(async (organizationId: string, resources: Readonly<{ members?: boolean; invitations?: boolean }>): Promise<void> => {
    const snapshot = await refreshOrganizationSnapshot();
    if (!snapshot.organizations.some((organization) => organization.id === organizationId)) {
      throw new OrganizationClientError("invalid_response", "対象の組織を確認できませんでした。");
    }
    if (selectedOrganizationRef.current !== organizationId) return;
    if (resources.members) {
      const memberItems = await loadAllMembers(client, organizationId);
      setMembers(memberItems);
      setMemberNextCursor(null);
      setMemberState({ status: memberItems.length === 0 ? "empty" : "ready" });
      const actorMembership = memberItems.find((member) => member.memberId === snapshot.session.memberId);
      if (actorMembership !== undefined) {
        setRoleOverrides((current) => ({ ...current, [organizationId]: actorMembership.status === "active" ? actorMembership.role : "viewer" }));
      }
    }
    if (resources.invitations) {
      const invitationItems = await loadAllInvitations(client, organizationId);
      setInvitations(invitationItems);
      setInvitationNextCursor(null);
      setInvitationState({ status: invitationItems.length === 0 ? "empty" : "ready" });
    }
  }, [client, refreshOrganizationSnapshot]);

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
        setMemberNextCursor(null);
        setInvitationNextCursor(null);
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
    void findOrganizationMemberRole(client, selectedOrganizationId, sessionMemberId, controller.signal).then((role) => {
      if (controller.signal.aborted) return;
      setRoleOverrides((current) => ({ ...current, [selectedOrganizationId]: role }));
    }).catch((error) => {
      if (controller.signal.aborted) return;
      if (error instanceof OrganizationClientError && (error.code === "forbidden" || error.code === "unauthorized")) {
        setRoleOverrides((current) => ({ ...current, [selectedOrganizationId]: "viewer" }));
      }
    });
    return () => controller.abort();
  }, [client, roleOverrides, selectedOrganizationId, sessionMemberId, sessionOrganizationId]);

  useEffect(() => {
    const initialTimer = window.setTimeout(() => setNowMs(Date.now()), 0);
    const interval = window.setInterval(() => setNowMs(Date.now()), 30_000);
    return () => {
      window.clearTimeout(initialTimer);
      window.clearInterval(interval);
    };
  }, []);

  const selectOrganization = (id: string) => {
    const next = organizations.find((item) => item.id === id);
    selectedOrganizationRef.current = id;
    setSelectedOrganizationId(id);
    setSelectedOrganization(next);
    setRenameName(next?.name ?? "");
    setMembers([]);
    setInvitations([]);
    setMemberState(INITIAL_RESOURCE);
    setInvitationState(INITIAL_RESOURCE);
    setMemberNextCursor(null);
    setInvitationNextCursor(null);
    setLoadingMore(null);
    setRoleDrafts({});
    setRemovalConfirmationId(null);
    setOneTimeToken(null);
    setReissueConfirmationId(null);
    setReissueExpiresAt("");
    setMutationError(INITIAL_RESOURCE);
  };

  const runMutation = async (action: string, operation: () => Promise<void>, options: MutationOptions = {}): Promise<boolean> => {
    if (pendingAction !== null) return false;
    setPendingAction(action);
    setMutationError(INITIAL_RESOURCE);
    setRetryAction(null);
    const rollback = options.optimistic?.() ?? (() => undefined);
    let operationCommitted = false;
    try {
      await operation();
      operationCommitted = true;
      if (options.reconcile !== undefined) await options.reconcile();
      return true;
    } catch (error) {
      const responseOutcomeIsAmbiguous = !operationCommitted && isAmbiguousOrganizationMutationError(error);
      if (options.reconcile !== undefined && (responseOutcomeIsAmbiguous || operationCommitted)) {
        let reconciliationError: unknown = operationCommitted ? error : undefined;
        try {
          if (!operationCommitted) await options.reconcile();
        } catch (caught) {
          reconciliationError = caught;
        }
        const message = reconciliationError === undefined
          ? "応答を確認できなかったため、権威状態を再取得しました。操作は再送していません。表示された状態を確認してください。"
          : "変更結果を確認できませんでした。再送せず、最新の状態をもう一度確認してください。";
        setMutationError({ status: "error", code: "reconciliation_required", error: message });
        setRetryAction({
          label: "最新の状態を再確認",
          run: async () => {
            if (pendingAction !== null) return;
            setPendingAction("reconcile");
            setMutationError(INITIAL_RESOURCE);
            try {
              await options.reconcile?.();
              setMutationError({ status: "error", code: "reconciliation_required", error: "最新の権威状態を取得しました。操作は再送していません。" });
            } catch {
              setMutationError({ status: "error", code: "reconciliation_required", error: "変更結果を確認できませんでした。接続を確認して、再送せずにもう一度確認してください。" });
            } finally {
              setPendingAction(null);
            }
          },
        });
        return false;
      }
      rollback();
      const nextError = resourceError(error);
      setMutationError(nextError);
      if ((nextError.code === "recent_auth_required" || nextError.code === "aborted") && options.retry !== undefined) {
        setRetryAction({ label: options.retryLabel ?? "本人確認をやり直す", run: options.retry });
      }
      return false;
    } finally {
      setPendingAction(null);
    }
  };

  const createOrganization = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const name = createName.trim();
    if (name === "") return setMutationError({ status: "error", error: "組織名を入力してください。" });
    let createdOrganizationId: string | undefined;
    await runMutation("create-organization", async () => {
      const result = await client.createOrganization({ name });
      createdOrganizationId = result.organization.id;
      setCreateName("");
      setRoleOverrides((current) => ({ ...current, [result.organization.id]: "owner" }));
      selectedOrganizationRef.current = result.organization.id;
      setSelectedOrganizationId(result.organization.id);
    }, {
      reconcile: async () => {
        if (createdOrganizationId === undefined) await refreshOrganizationSnapshot();
        else await reconcileResources(createdOrganizationId, {});
      },
    });
  };

  const renameOrganization = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!selectedOrganization || !visibility.canManageOrganization) return;
    const name = renameName.trim();
    if (name === "") return setMutationError({ status: "error", error: "組織名を入力してください。" });
    const previousOrganization = selectedOrganization;
    const previousOrganizations = organizations;
    const previousRenameName = renameName;
    await runMutation("rename-organization", async () => {
      const result = await client.renameOrganization({ organizationId: selectedOrganization.id, name, expectedVersion: selectedOrganization.version });
      setSelectedOrganization(result.organization);
    }, {
      optimistic: () => {
        const optimisticOrganization = { ...selectedOrganization, name };
        setSelectedOrganization(optimisticOrganization);
        setOrganizations((current) => current.map((item) => item.id === selectedOrganization.id ? optimisticOrganization : item));
        return () => {
          setSelectedOrganization(previousOrganization);
          setOrganizations(previousOrganizations);
          setRenameName(previousRenameName);
        };
      },
      reconcile: () => reconcileResources(selectedOrganization.id, {}),
    });
  };

  const createInvitation = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!selectedOrganization || !visibility.canInvite) return;
    setOneTimeToken(null);
    const expiresAt = parseDateTimeLocal(inviteExpiresAt);
    if (expiresAt === undefined) return setMutationError({ status: "error", error: "有効期限を入力してください。" });
    if (Date.parse(expiresAt) <= Date.now()) return setMutationError({ status: "error", code: "expired", error: "有効期限は現在より後に設定してください。" });
    let createdToken: string | undefined;
    const committed = await runMutation("create-invitation", async () => {
      const result = await client.createInvitation({ organizationId: selectedOrganization.id, role: inviteRole, expiresAt });
      createdToken = result.oneTimeToken;
    }, {
      reconcile: () => reconcileResources(selectedOrganization.id, { invitations: true }),
    });
    if (committed && createdToken !== undefined) {
      setOneTimeToken(createdToken);
      setInviteExpiresAt("");
    }
  };

  const beginInvitationReissue = (invitation: OrganizationInvitation): void => {
    if (!visibility.canInvite || !isInvitationReissuable(invitation, nowMs) || pendingAction !== null) return;
    setMutationError(INITIAL_RESOURCE);
    setRetryAction(null);
    setOneTimeToken(null);
    setReissueConfirmationId(invitation.id);
    setReissueExpiresAt(minimumDateTimeLocal());
  };

  const cancelInvitationReissue = (): void => {
    if (pendingAction !== null) return;
    setReissueConfirmationId(null);
    setReissueExpiresAt("");
  };

  const submitInvitationReissue = async (invitation: OrganizationInvitation, expiresAt: string): Promise<void> => {
    let reissuedToken: string | undefined;
    const committed = await runMutation(`invitation-reissue-${invitation.id}`, async () => {
      const result = await client.reissueInvitation({
        organizationId: invitation.organizationId,
        invitationId: invitation.id,
        expiresAt,
        expectedVersion: invitation.version,
      });
      reissuedToken = result.oneTimeToken;
      setInvitations((current) => current.map((item) => item.id === invitation.id ? result.invitation : item));
    }, {
      retry: () => submitInvitationReissue(invitation, expiresAt),
      reconcile: () => reconcileResources(invitation.organizationId, { invitations: true }),
    });
    if (committed && reissuedToken !== undefined) {
      setOneTimeToken(reissuedToken);
      setReissueConfirmationId(null);
      setReissueExpiresAt("");
    }
  };

  const reissueInvitation = async (event: FormEvent<HTMLFormElement>, invitation: OrganizationInvitation): Promise<void> => {
    event.preventDefault();
    if (!selectedOrganization || !visibility.canInvite || !isInvitationReissuable(invitation, nowMs)) return;
    const expiresAt = parseDateTimeLocal(reissueExpiresAt);
    if (expiresAt === undefined) {
      setMutationError({ status: "error", code: "validation_failed", error: "新しい有効期限を入力してください。" });
      return;
    }
    if (nowMs > 0 && Date.parse(expiresAt) <= nowMs) {
      setMutationError({ status: "error", code: "expired", error: "新しい有効期限は現在より後に設定してください。" });
      return;
    }
    await submitInvitationReissue(invitation, expiresAt);
  };

  const changeMemberRole = (member: OrganizationMember, role: OrganizationRole): Promise<boolean> => {
    if (!visibility.canManageMembers || (role === "owner" && !visibility.canAssignOwner) || role === member.role || member.status !== "active") return Promise.resolve(false);
    if (isFinalOwnerProtection(member, role)) {
      showLastOwnerProtection(member);
      return Promise.resolve(false);
    }
    const previousMembers = members;
    return runMutation(`member-role-${member.memberId}`, async () => {
      const result = await client.updateMemberRole({ organizationId: member.organizationId, memberId: member.memberId, role, expectedVersion: member.version });
      setMembers((current) => current.map((item) => item.memberId === member.memberId ? result.member : item));
      setRoleDrafts((current) => ({ ...current, [member.memberId]: result.member.role }));
      if (member.memberId === sessionMemberId) {
        setSessionRole(result.member.role);
        setRoleOverrides((current) => ({ ...current, [member.organizationId]: result.member.role }));
      }
    }, {
      optimistic: () => {
        setMembers((current) => current.map((item) => item.memberId === member.memberId ? { ...item, role, version: item.version + 1 } : item));
        return () => setMembers(previousMembers);
      },
      retry: () => changeMemberRole(member, role),
      reconcile: () => reconcileResources(member.organizationId, { members: true }),
    });
  };

  const removeMember = (member: OrganizationMember): Promise<boolean> => {
    if (!visibility.canManageMembers || (member.role === "owner" && !visibility.canAssignOwner) || member.status !== "active") return Promise.resolve(false);
    if (isFinalOwnerProtection(member, undefined)) {
      showLastOwnerProtection(member);
      return Promise.resolve(false);
    }
    const previousMembers = members;
    setRemovalConfirmationId(null);
    return runMutation(`member-remove-${member.memberId}`, async () => {
      const result = await client.removeMember({ organizationId: member.organizationId, memberId: member.memberId, expectedVersion: member.version });
      setMembers((current) => current.map((item) => item.memberId === member.memberId ? result.member : item));
      if (member.memberId === sessionMemberId) {
        setSessionRole("viewer");
        setRoleOverrides((current) => ({ ...current, [member.organizationId]: "viewer" }));
      }
    }, {
      optimistic: () => {
        setMembers((current) => current.map((item) => item.memberId === member.memberId ? { ...item, status: "revoked", version: item.version + 1 } : item));
        return () => setMembers(previousMembers);
      },
      retry: () => removeMember(member),
      reconcile: () => reconcileResources(member.organizationId, { members: true }),
    });
  };

  const revokeInvitation = (invitation: OrganizationInvitation): Promise<void> => {
    if (!visibility.canRevokeInvitations || invitation.status !== "pending" || isInvitationExpired(invitation, nowMs)) return Promise.resolve();
    setOneTimeToken(null);
    const previousInvitations = invitations;
    return runMutation(`invitation-revoke-${invitation.id}`, async () => {
      const result = await client.revokeInvitation({ organizationId: invitation.organizationId, invitationId: invitation.id, expectedVersion: invitation.version });
      setInvitations((current) => current.map((item) => item.id === invitation.id ? result.invitation : item));
    }, {
      optimistic: () => {
        setInvitations((current) => current.map((item) => item.id === invitation.id ? { ...item, status: "revoked", version: item.version + 1 } : item));
        return () => setInvitations(previousInvitations);
      },
      reconcile: () => reconcileResources(invitation.organizationId, { invitations: true }),
    });
  };

  const acceptInvitation = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const token = acceptToken.trim();
    if (token === "") return setMutationError({ status: "error", error: "招待トークンを入力してください。" });
    setOneTimeToken(null);
    await runMutation("accept-invitation", async () => {
      await client.acceptInvitation({ oneTimeToken: token });
      setAcceptToken("");
    }, {
      reconcile: () => refreshOrganizationSnapshot().then(() => undefined),
    });
  };

  const refresh = () => {
    setMutationError(INITIAL_RESOURCE);
    setRetryAction(null);
    setOneTimeToken(null);
    setReissueConfirmationId(null);
    setReissueExpiresAt("");
    setRefreshNonce((value) => value + 1);
  };
  const roleLabel = { owner: "Owner", admin: "Admin", auditor: "Auditor", viewer: "Viewer" }[effectiveRole];

  return (
    <main className="organization-panel" style={panelStyle.shell} aria-labelledby="organization-panel-title" aria-busy={pendingAction !== null}>
      <header style={panelStyle.header}>
        <div>
          <p style={panelStyle.eyebrow}>ORGANIZATION ADMINISTRATION</p>
          <h1 id="organization-panel-title" style={panelStyle.heading}>組織を安全に管理する</h1>
          <p style={panelStyle.copy}>Agentの利用単位となる組織、メンバー、招待を管理します。変更にはバージョン競合検知と監査可能な操作境界が適用されます。</p>
        </div>
        <button type="button" style={panelStyle.secondaryButton} onClick={refresh} disabled={pendingAction !== null} aria-label="組織情報を再読み込み">再読み込み</button>
      </header>

      {organizationState.status === "loading" && <p style={panelStyle.state} data-state="loading" role="status">組織を読み込み中です…</p>}
      {organizationState.status === "error" && <ResourceStateView state={organizationState} empty="" error="組織情報を取得できませんでした。" onRetry={refresh} retryLabel="組織情報を再試行" />}
      {organizationState.status === "empty" && (
        <section style={panelStyle.card} data-state="empty" aria-labelledby="organization-empty-title">
          <h2 id="organization-empty-title" style={panelStyle.cardTitle}>組織がまだありません</h2>
          <p style={panelStyle.muted}>最初の組織を作成すると、Coding Agentのメンバーと権限を管理できます。</p>
          <CreateOrganizationForm name={createName} setName={setCreateName} onSubmit={createOrganization} pending={pendingAction === "create-organization"} />
        </section>
      )}

      {organizationState.status === "ready" && organizations.length > 0 && (
        <section style={panelStyle.card} aria-labelledby="organization-selector-title">
          <div style={panelStyle.row}>
            <div><h2 id="organization-selector-title" style={panelStyle.cardTitle}>組織</h2><p style={panelStyle.muted}>現在の権限: {roleLabel}</p></div>
            <label style={{ ...panelStyle.label, minWidth: 260 }}><span className="sr-only">組織を選択</span><select value={selectedOrganizationId} onChange={(event) => selectOrganization(event.target.value)} style={panelStyle.select} aria-label="組織を選択" disabled={pendingAction !== null}>{organizations.map((organization) => <option key={organization.id} value={organization.id}>{organization.name}</option>)}</select></label>
          </div>
          {selectedOrganization && <div style={panelStyle.row}><span>{selectedOrganization.name} · v{selectedOrganization.version}</span><span style={panelStyle.muted}>更新: {formatDate(selectedOrganization.updatedAt)}</span></div>}
          {visibility.canManageOrganization && selectedOrganization && <form onSubmit={renameOrganization} style={panelStyle.actionRow}><label style={{ ...panelStyle.label, flex: "1 1 280px" }}><span>組織名を変更</span><input value={renameName} onChange={(event) => setRenameName(event.target.value)} maxLength={128} style={panelStyle.input} /></label><button type="submit" style={panelStyle.button} disabled={pendingAction !== null}>{pendingAction === "rename-organization" ? "変更中…" : "名前を変更"}</button></form>}
          {!visibility.canManageOrganization && <p style={panelStyle.muted}>この組織では閲覧権限のみです。管理操作は表示されません。</p>}
        </section>
      )}

      {pendingAction !== null && <p className="organization-status" style={panelStyle.state} data-state="pending" role="status" aria-live="polite">{pendingActionLabel(pendingAction)}</p>}
      {mutationError.status === "error" && <MutationNotice state={mutationError} retryAction={retryAction} onRefresh={refresh} />}

      {selectedOrganization && visibility.canViewMembers && (
        <section style={panelStyle.card} aria-labelledby="organization-members-title">
          <div style={panelStyle.row}><div><h2 id="organization-members-title" style={panelStyle.cardTitle}>メンバー</h2><p style={panelStyle.muted}>Owner / Admin / Auditorはメンバー情報を閲覧できます。</p></div><span style={panelStyle.muted}>{members.length}人</span></div>
          <ResourceStateView state={memberState} empty="メンバーはいません。" error="メンバー情報を取得できませんでした。" onRetry={refresh} retryLabel="メンバー情報を再試行" />
          {memberState.status === "ready" && <ul style={panelStyle.list}>{members.map((member) => {
            const finalOwner = visibility.canAssignOwner && isFinalOwnerProtection(member, undefined);
            return <MemberRow key={member.membershipId} member={member} canManage={visibility.canManageMembers && (member.role !== "owner" || visibility.canAssignOwner)} canAssignOwner={visibility.canAssignOwner} lastOwnerProtected={finalOwner} draft={roleDrafts[member.memberId] ?? member.role} setDraft={(role) => setRoleDrafts((current) => ({ ...current, [member.memberId]: role }))} pendingAction={pendingAction} actionKey={`member-role-${member.memberId}`} confirmRemoval={removalConfirmationId === member.memberId} onConfirmRemoval={() => { if (finalOwner) showLastOwnerProtection(member); else setRemovalConfirmationId(member.memberId); }} onCancelRemoval={() => setRemovalConfirmationId(null)} onRoleChange={(role) => void changeMemberRole(member, role)} onRemove={() => void removeMember(member)} />;
          })}</ul>}
          {memberState.status === "ready" && memberNextCursor !== null && <LoadMoreButton label="メンバーをさらに読み込む" pending={loadingMore === "members"} disabled={loadingMore !== null} onClick={() => void loadMembers(selectedOrganization.id, undefined, memberNextCursor)} />}
        </section>
      )}

      {selectedOrganization && visibility.canViewInvitations && (
        <section style={panelStyle.grid} aria-label="招待管理">
          <section style={panelStyle.card} aria-labelledby="organization-invitations-title">
            <div style={panelStyle.row}><div><h2 id="organization-invitations-title" style={panelStyle.cardTitle}>招待</h2><p style={panelStyle.muted}>招待トークンは発行時のコンポーネントメモリにのみ保持します。</p></div><span style={panelStyle.muted}>{invitations.length}件</span></div>
            <ResourceStateView state={invitationState} empty="招待はありません。" error="招待情報を取得できませんでした。" onRetry={refresh} retryLabel="招待情報を再試行" />
            {invitationState.status === "ready" && <ul style={panelStyle.list}>{invitations.map((invitation) => <InvitationRow key={invitation.id} invitation={invitation} canRevoke={visibility.canRevokeInvitations} canReissue={visibility.canInvite} expired={isInvitationExpired(invitation, nowMs)} pendingAction={pendingAction} actionKey={`invitation-revoke-${invitation.id}`} reissueActionKey={`invitation-reissue-${invitation.id}`} confirmReissue={reissueConfirmationId === invitation.id} reissueExpiresAt={reissueExpiresAt} setReissueExpiresAt={setReissueExpiresAt} onBeginReissue={() => beginInvitationReissue(invitation)} onCancelReissue={cancelInvitationReissue} onSubmitReissue={(event) => void reissueInvitation(event, invitation)} onRevoke={() => void revokeInvitation(invitation)} />)}</ul>}
            {invitationState.status === "ready" && invitationNextCursor !== null && <LoadMoreButton label="招待をさらに読み込む" pending={loadingMore === "invitations"} disabled={loadingMore !== null} onClick={() => void loadInvitations(selectedOrganization.id, undefined, invitationNextCursor)} />}
          </section>
          {visibility.canInvite && <InviteForm role={inviteRole} setRole={setInviteRole} expiresAt={inviteExpiresAt} setExpiresAt={setInviteExpiresAt} onSubmit={createInvitation} pending={pendingAction === "create-invitation"} />}
        </section>
      )}

      <section style={panelStyle.card} aria-labelledby="accept-invitation-title">
        <h2 id="accept-invitation-title" style={panelStyle.cardTitle}>招待を受け入れる</h2>
        <p style={panelStyle.muted}>受け取った一回限りのトークンを、この画面のメモリ上でのみ送信します。</p>
        <form onSubmit={acceptInvitation} style={panelStyle.actionRow}><label style={{ ...panelStyle.label, flex: "1 1 460px" }}><span>招待トークン</span><input value={acceptToken} onChange={(event) => setAcceptToken(event.target.value)} autoComplete="off" inputMode="text" style={panelStyle.input} /></label><button type="submit" style={panelStyle.button} disabled={pendingAction !== null}>{pendingAction === "accept-invitation" ? "受け入れ中…" : "招待を受け入れる"}</button></form>
      </section>

      {oneTimeToken !== null && <section className="organization-one-time-secret" style={panelStyle.card} aria-labelledby="one-time-token-title"><div style={panelStyle.row}><h2 id="one-time-token-title" style={panelStyle.cardTitle}>招待トークン（一度だけ表示）</h2><button type="button" style={panelStyle.secondaryButton} onClick={() => setOneTimeToken(null)} aria-label="招待トークンを閉じる">閉じる</button></div><p style={panelStyle.muted} role="status" aria-live="polite">招待トークンを一度だけ表示しています。安全な経路で招待相手へ渡してください。ページを離れる、再読み込みする、または閉じると再取得できません。</p><code className="organization-token" style={panelStyle.token}>{oneTimeToken}</code></section>}
    </main>
  );
}

function CreateOrganizationForm({ name, setName, onSubmit, pending }: { name: string; setName: (value: string) => void; onSubmit: (event: FormEvent<HTMLFormElement>) => void; pending: boolean }) {
  return <form onSubmit={onSubmit} style={panelStyle.actionRow} aria-busy={pending}><label style={{ ...panelStyle.label, flex: "1 1 320px" }}><span>組織名</span><input value={name} onChange={(event) => setName(event.target.value)} maxLength={128} required style={panelStyle.input} /></label><button type="submit" style={panelStyle.button} disabled={pending}>{pending ? "作成中…" : "組織を作成"}</button></form>;
}

function InviteForm({ role, setRole, expiresAt, setExpiresAt, onSubmit, pending }: { role: InvitationRole; setRole: (value: InvitationRole) => void; expiresAt: string; setExpiresAt: (value: string) => void; onSubmit: (event: FormEvent<HTMLFormElement>) => void; pending: boolean }) {
  return <section style={panelStyle.card} aria-labelledby="create-invitation-title"><h2 id="create-invitation-title" style={panelStyle.cardTitle}>招待を作成</h2><p style={panelStyle.muted}>有効期限を過ぎた招待は自動的に受け入れできません。</p><form onSubmit={onSubmit} style={{ display: "grid", gap: 12 }} aria-busy={pending}><label style={panelStyle.label}><span>付与するロール</span><select value={role} onChange={(event) => setRole(event.target.value as InvitationRole)} style={panelStyle.select}>{INVITE_ROLES.map((value) => <option key={value} value={value}>{roleLabel(value)}</option>)}</select></label><label style={panelStyle.label}><span>有効期限</span><input type="datetime-local" value={expiresAt} onChange={(event) => setExpiresAt(event.target.value)} min={minimumDateTimeLocal()} required style={panelStyle.input} /></label><button type="submit" style={panelStyle.button} disabled={pending}>{pending ? "発行中…" : "招待を発行"}</button></form></section>;
}

function MemberRow({ member, canManage, canAssignOwner, lastOwnerProtected, draft, setDraft, pendingAction, actionKey, confirmRemoval, onConfirmRemoval, onCancelRemoval, onRoleChange, onRemove }: { member: OrganizationMember; canManage: boolean; canAssignOwner: boolean; lastOwnerProtected: boolean; draft: OrganizationRole; setDraft: (role: OrganizationRole) => void; pendingAction: string | null; actionKey: string; confirmRemoval: boolean; onConfirmRemoval: () => void; onCancelRemoval: () => void; onRoleChange: (role: OrganizationRole) => void; onRemove: () => void }) {
  const editableRoles = canAssignOwner ? ROLES : ROLES.filter((role) => role !== "owner");
  const name = member.displayName ?? "名前未設定";
  const detailsId = `member-details-${member.memberId}`;
  const lastOwnerWarningId = `member-last-owner-warning-${member.memberId}`;
  const busy = pendingAction !== null;
  const describedBy = lastOwnerProtected ? `${detailsId} ${lastOwnerWarningId}` : detailsId;
  return <li className="organization-list-row" style={panelStyle.listRow} data-state={member.status === "revoked" ? "revoked" : pendingAction === actionKey ? "pending" : "active"} aria-busy={pendingAction === actionKey}><div style={panelStyle.row}><div><strong>{name}</strong><p id={detailsId} style={panelStyle.muted}>{roleLabel(member.role)} · {member.status === "active" ? "有効" : "失効"} · v{member.version}</p>{lastOwnerProtected ? <p id={lastOwnerWarningId} className="organization-last-owner-warning" role="note">この組織の最後のOwnerです。先に別のメンバーをOwnerに変更してから、降格または失効してください。</p> : null}</div>{canManage && member.status === "active" ? <div style={panelStyle.actionRow}><label style={panelStyle.label}><span className="sr-only">{name}のロール</span><select id={`member-role-${member.memberId}`} aria-label={`${name}のロール`} aria-describedby={describedBy} value={draft} onChange={(event) => setDraft(event.target.value as OrganizationRole)} style={panelStyle.select} disabled={busy}>{editableRoles.map((role) => <option key={role} value={role}>{roleLabel(role)}</option>)}</select></label><button type="button" style={panelStyle.secondaryButton} disabled={busy || draft === member.role} onClick={() => onRoleChange(draft)} aria-label={`${name}を${roleLabel(draft)}に変更`} aria-describedby={describedBy}>{pendingAction === actionKey ? "変更中…" : "変更"}</button>{confirmRemoval ? <div className="organization-confirmation" role="alert"><span>このメンバーを失効させますか？</span><button type="button" style={panelStyle.dangerButton} disabled={busy} onClick={onRemove}>失効を確定</button><button type="button" style={panelStyle.secondaryButton} disabled={busy} onClick={onCancelRemoval}>キャンセル</button></div> : <button type="button" style={panelStyle.dangerButton} disabled={busy} onClick={onConfirmRemoval} aria-label={`${name}のアクセスを失効`} aria-describedby={describedBy}>アクセスを失効</button>}</div> : member.status === "revoked" ? <span style={panelStyle.muted}>このメンバーは失効しています</span> : null}</div></li>;
}

function InvitationRow({ invitation, canRevoke, canReissue, expired, pendingAction, actionKey, reissueActionKey, confirmReissue, reissueExpiresAt, setReissueExpiresAt, onBeginReissue, onCancelReissue, onSubmitReissue, onRevoke }: { invitation: OrganizationInvitation; canRevoke: boolean; canReissue: boolean; expired: boolean; pendingAction: string | null; actionKey: string; reissueActionKey: string; confirmReissue: boolean; reissueExpiresAt: string; setReissueExpiresAt: (value: string) => void; onBeginReissue: () => void; onCancelReissue: () => void; onSubmitReissue: (event: FormEvent<HTMLFormElement>) => void; onRevoke: () => void }) {
  const status = expired ? "expired" : invitation.status;
  const statusLabel = status === "pending" ? "有効" : status === "expired" ? "期限切れ" : status === "accepted" ? "受け入れ済み" : "取り消し済み";
  const busy = pendingAction !== null;
  const reissuable = canReissue && (status === "pending" || status === "expired");
  const detailsId = `invitation-details-${invitation.id}`;
  const reissueWarningId = `invitation-reissue-warning-${invitation.id}`;
  return <li className="organization-list-row" style={panelStyle.listRow} data-state={status} aria-busy={pendingAction === actionKey || pendingAction === reissueActionKey}>
    <div style={panelStyle.row}>
      <div><strong>{roleLabel(invitation.role)} 招待</strong><p id={detailsId} style={panelStyle.muted}>{statusLabel} · 有効期限 {formatDate(invitation.expiresAt)} · v{invitation.version}</p></div>
      <div style={panelStyle.actionRow}>
        {canRevoke && status === "pending" && <button type="button" style={panelStyle.dangerButton} disabled={busy} onClick={onRevoke} aria-label={`${roleLabel(invitation.role)}招待を取り消す`} aria-describedby={detailsId}>{pendingAction === actionKey ? "取り消し中…" : "取り消す"}</button>}
        {reissuable && !confirmReissue && <button type="button" style={panelStyle.secondaryButton} disabled={busy} onClick={onBeginReissue} aria-label={`${roleLabel(invitation.role)}招待を再発行`} aria-describedby={detailsId}>再発行</button>}
      </div>
    </div>
    {reissuable && confirmReissue && <form onSubmit={onSubmitReissue} style={{ display: "grid", gap: 10 }} aria-busy={pendingAction === reissueActionKey} aria-describedby={`${detailsId} ${reissueWarningId}`}>
      <p id={reissueWarningId} style={panelStyle.conflict} role="note">現在の招待トークンは無効になり、新しいトークンを一度だけ表示します。応答を確認できない場合は自動再送せず、最新状態を再取得します。</p>
      <label style={panelStyle.label}><span>再発行後の有効期限</span><input type="datetime-local" value={reissueExpiresAt} onChange={(event) => setReissueExpiresAt(event.target.value)} min={minimumDateTimeLocal()} required style={panelStyle.input} disabled={busy} /></label>
      <div style={panelStyle.actionRow}><button type="submit" style={panelStyle.button} disabled={busy}>{pendingAction === reissueActionKey ? "再発行中…" : "再発行を確定"}</button><button type="button" style={panelStyle.secondaryButton} disabled={busy} onClick={onCancelReissue}>キャンセル</button></div>
    </form>}
  </li>;
}

function ResourceStateView({ state, empty, error, onRetry, retryLabel }: { state: ResourceState; empty: string; error: string; onRetry?: () => void; retryLabel?: string }) {
  if (state.status === "loading") return <p className="organization-status" style={panelStyle.state} data-state="loading" role="status" aria-live="polite">読み込み中です…</p>;
  if (state.status === "empty") return <p style={panelStyle.state} data-state="empty">{empty}</p>;
  if (state.status === "error") return <div className="organization-status" style={state.code === "conflict" || state.code === "last_owner_protected" ? panelStyle.conflict : panelStyle.error} data-state={state.code ?? "error"} role="alert" aria-live="assertive"><span>{state.error ?? error}</span>{onRetry !== undefined && <button type="button" style={panelStyle.secondaryButton} onClick={onRetry}>{retryLabel ?? "再試行"}</button>}</div>;
  return null;
}

function LoadMoreButton({ label, pending, disabled, onClick }: { label: string; pending: boolean; disabled: boolean; onClick: () => void }) {
  return <button type="button" style={panelStyle.secondaryButton} onClick={onClick} disabled={disabled} aria-busy={pending}>{pending ? "読み込み中…" : label}</button>;
}

function MutationNotice({ state, retryAction, onRefresh }: { state: ResourceState; retryAction: RetryAction | null; onRefresh: () => void }) {
  const refreshLabel = state.code === "unauthorized" ? "セッションを更新" : "最新情報を読み込む";
  const canRefresh = state.code === "conflict" || state.code === "last_owner_protected" || state.code === "unauthorized";
  const canRetry = state.code === "recent_auth_required" || state.code === "aborted" || state.code === "reconciliation_required";
  return <div className="organization-status" style={state.code === "conflict" || state.code === "last_owner_protected" ? panelStyle.conflict : panelStyle.error} data-state={state.code ?? "error"} role="alert" aria-live="assertive"><span>{state.error}</span>{retryAction !== null && canRetry ? <button type="button" style={panelStyle.secondaryButton} onClick={() => void retryAction.run()}>{retryAction.label}</button> : canRefresh ? <button type="button" style={panelStyle.secondaryButton} onClick={onRefresh}>{refreshLabel}</button> : null}</div>;
}

function chooseOrganization(items: readonly Organization[], requested: string, sessionOrganizationId: string): string {
  if (requested !== "" && items.some((item) => item.id === requested)) return requested;
  if (items.some((item) => item.id === sessionOrganizationId)) return sessionOrganizationId;
  return items[0]?.id ?? "";
}

async function loadAllOrganizations(client: OrganizationClient, signal?: AbortSignal): Promise<readonly Organization[]> {
  const items: Organization[] = [];
  const seenCursors = new Set<string>();
  let cursor: string | undefined;
  for (let pageNumber = 0; pageNumber < 100; pageNumber += 1) {
    const page = await client.listOrganizations({ signal, limit: 100, ...(cursor === undefined ? {} : { cursor }) });
    items.push(...page.items);
    if (page.nextCursor === null) return items;
    if (seenCursors.has(page.nextCursor)) throw new OrganizationClientError("invalid_response", "Organization pagination cursor repeated");
    seenCursors.add(page.nextCursor);
    cursor = page.nextCursor;
  }
  throw new OrganizationClientError("invalid_response", "Organization pagination exceeded the supported limit");
}

async function loadAllMembers(client: OrganizationClient, organizationId: string, signal?: AbortSignal): Promise<readonly OrganizationMember[]> {
  const items: OrganizationMember[] = [];
  const seenCursors = new Set<string>();
  let cursor: string | undefined;
  for (let pageNumber = 0; pageNumber < 100; pageNumber += 1) {
    const page = await client.listMembers(organizationId, { signal, limit: 100, ...(cursor === undefined ? {} : { cursor }) });
    items.push(...page.items);
    if (page.nextCursor === null) return items;
    if (seenCursors.has(page.nextCursor)) throw new OrganizationClientError("invalid_response", "Member pagination cursor repeated");
    seenCursors.add(page.nextCursor);
    cursor = page.nextCursor;
  }
  throw new OrganizationClientError("invalid_response", "Member pagination exceeded the supported limit");
}

async function loadAllInvitations(client: OrganizationClient, organizationId: string, signal?: AbortSignal): Promise<readonly OrganizationInvitation[]> {
  const items: OrganizationInvitation[] = [];
  const seenCursors = new Set<string>();
  let cursor: string | undefined;
  for (let pageNumber = 0; pageNumber < 100; pageNumber += 1) {
    const page = await client.listInvitations(organizationId, { signal, limit: 100, ...(cursor === undefined ? {} : { cursor }) });
    items.push(...page.items);
    if (page.nextCursor === null) return items;
    if (seenCursors.has(page.nextCursor)) throw new OrganizationClientError("invalid_response", "Invitation pagination cursor repeated");
    seenCursors.add(page.nextCursor);
    cursor = page.nextCursor;
  }
  throw new OrganizationClientError("invalid_response", "Invitation pagination exceeded the supported limit");
}

async function findOrganizationMemberRole(client: OrganizationClient, organizationId: string, memberId: string, signal?: AbortSignal): Promise<OrganizationRole> {
  const seenCursors = new Set<string>();
  let cursor: string | undefined;
  for (let pageNumber = 0; pageNumber < 100; pageNumber += 1) {
    const page = await client.listMembers(organizationId, { signal, limit: 100, ...(cursor === undefined ? {} : { cursor }) });
    const actorMembership = page.items.find((member) => member.memberId === memberId);
    if (actorMembership !== undefined) return actorMembership.status === "active" ? actorMembership.role : "viewer";
    if (page.nextCursor === null) return "viewer";
    if (seenCursors.has(page.nextCursor)) throw new OrganizationClientError("invalid_response", "Member pagination cursor repeated");
    seenCursors.add(page.nextCursor);
    cursor = page.nextCursor;
  }
  throw new OrganizationClientError("invalid_response", "Member pagination exceeded the supported limit");
}

function resourceError(error: unknown): ResourceState {
  if (isLastOwnerProtectionError(error)) return { status: "error", code: "last_owner_protected", error: "最後のOwnerは降格・失効できません。先に別のメンバーをOwnerに変更してから、もう一度お試しください。" };
  if (error instanceof OrganizationClientError && error.code === "conflict") return { status: "error", code: "conflict", error: "他の管理者が先に変更しました。最新情報を読み込んでから、もう一度お試しください。" };
  if (error instanceof OrganizationClientError && error.code === "expired") return { status: "error", code: "expired", error: "この招待または操作の有効期限が切れています。最新情報を確認してください。" };
  if (error instanceof OrganizationClientError && error.code === "recent_auth_required") return { status: "error", code: "recent_auth_required", error: "安全な本人確認が必要です。もう一度実行してPasskey認証を完了してください。" };
  if (error instanceof OrganizationClientError && error.code === "aborted") return { status: "error", code: "aborted", error: "本人確認がキャンセルされました。必要であれば、もう一度実行してください。" };
  if (error instanceof OrganizationClientError && error.code === "forbidden") return { status: "error", code: "forbidden", error: "この操作を実行する権限がありません。" };
  if (error instanceof OrganizationClientError && error.code === "unauthorized") return { status: "error", code: "unauthorized", error: "セッションの有効期限が切れています。セッションを更新してください。" };
  if (error instanceof OrganizationClientError && error.code === "validation_failed") return { status: "error", code: "validation_failed", error: "入力内容を確認してください。" };
  return { status: "error", error: "組織情報を取得できませんでした。接続を確認して、もう一度お試しください。" };
}

function isLastOwnerProtectionError(error: unknown): error is OrganizationClientError {
  if (!(error instanceof OrganizationClientError) || error.code !== "conflict") return false;
  const serverCode = error.serverCode?.toLowerCase().replace(/[.-]/g, "_") ?? "";
  return serverCode.includes("last_owner") || serverCode.includes("final_active_owner");
}

function abortError(): OrganizationClientError {
  return new OrganizationClientError("aborted", "Organization refresh was cancelled");
}

function pendingActionLabel(action: string): string {
  if (action === "rename-organization") return "組織名を変更しています…";
  if (action === "create-invitation") return "招待を発行しています…";
  if (action.startsWith("invitation-reissue-")) return "招待を再発行しています…";
  if (action === "accept-invitation") return "招待を受け入れています…";
  if (action.startsWith("member-role-")) return "メンバーのロールを変更しています…";
  if (action.startsWith("member-remove-")) return "メンバーを失効しています…";
  if (action.startsWith("invitation-revoke-")) return "招待を取り消しています…";
  return "変更を反映しています…";
}

function isInvitationExpired(invitation: OrganizationInvitation, nowMs: number): boolean {
  return invitation.status === "expired" || nowMs > 0 && Date.parse(invitation.expiresAt) <= nowMs;
}

function isInvitationReissuable(invitation: OrganizationInvitation, nowMs: number): boolean {
  const status = isInvitationExpired(invitation, nowMs) ? "expired" : invitation.status;
  return status === "pending" || status === "expired";
}

function minimumDateTimeLocal(): string {
  const date = new Date(Date.now() + 5 * 60_000);
  date.setSeconds(0, 0);
  const offset = date.getTimezoneOffset();
  return new Date(date.getTime() - offset * 60_000).toISOString().slice(0, 16);
}

function roleLabel(role: OrganizationRole | InvitationRole): string {
  return { owner: "Owner", admin: "Admin", auditor: "Auditor", viewer: "Viewer" }[role];
}

function parseDateTimeLocal(value: string): string | undefined {
  if (value === "") return undefined;
  const date = new Date(value);
  return Number.isFinite(date.getTime()) ? date.toISOString() : undefined;
}

function formatDate(value: string): string {
  const date = new Date(value);
  return Number.isFinite(date.getTime()) ? date.toLocaleString("ja-JP", { timeZone: "Asia/Tokyo" }) : value;
}
