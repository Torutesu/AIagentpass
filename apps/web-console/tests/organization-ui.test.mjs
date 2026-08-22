import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { getOrganizationVisibility } from "../app/organization-client.ts";

const componentPath = new URL("../app/components/OrganizationPanel.tsx", import.meta.url);
const consolePath = new URL("../app/components/AgentPassConsole.tsx", import.meta.url);
const cssPath = new URL("../app/globals.css", import.meta.url);

test("OrganizationPanel is standalone and covers the administration flow", async () => {
  const source = await readFile(componentPath, "utf8");
  assert.match(source, /export function OrganizationPanel/);
  assert.match(source, /createOrganizationClient/);
  for (const operation of ["listOrganizations", "createOrganization", "renameOrganization", "listMembers", "listInvitations", "createInvitation", "reissueInvitation", "revokeInvitation", "acceptInvitation", "updateMemberRole", "removeMember"]) assert.match(source, new RegExp(`\\.${operation}\\(`));
  for (const state of ["loading", "empty", "error", "conflict"]) assert.match(source, new RegExp(state));
  assert.match(source, /oneTimeToken/);
  assert.match(source, /一度だけ表示/);
  assert.match(source, /再発行を確定/);
  assert.match(source, /現在の招待トークンは無効/);
  assert.match(source, /応答を確認できない場合は自動再送せず/);
  assert.match(source, /isAmbiguousOrganizationMutationError\(error\)/);
  assert.match(source, /最新の状態を再確認/);
  assert.match(source, /optimistic/);
  assert.match(source, /setMembers\(previousMembers\)/);
  assert.match(source, /data-state=\{status\}/);
  assert.match(source, /recent_auth_required/);
  assert.match(source, /serverCode/);
  assert.match(source, /idempotency/);
  assert.match(source, /すでに使用されています/);
  assert.match(source, /isRetryableMutationError/);
  assert.match(source, /responseMayHaveCommitted/);
  assert.match(source, /通信結果を確認/);
  assert.doesNotMatch(source, /state\.code === "transport_failed" \|\| state\.code === "http_failed"\) \? <button/);
  assert.match(source, /aria-busy/);
  assert.match(source, /role="alert" aria-live="assertive"/);
  assert.match(source, /失効を確定/);
  assert.match(source, /アクセスを失効/);
  assert.match(source, /reconcileOnConflict: true/);
  assert.ok((source.match(/reconcileOnConflict: true/g) ?? []).length >= 3, "invitation and both member mutations must reconcile 409 without replay");
  assert.match(source, /client\.invalidateSession\(\)/);
  assert.match(source, /現在の権限変更を確認できないため、共有セッションを無効化/);
  assert.match(source, /受け入れ済みです/);
  assert.match(source, /取り消し済みです/);
  assert.match(source, /期限切れです。管理者に招待の再発行/);
  assert.match(source, /setAcceptToken\(""\)/);
  assert.match(source, /invitationErrorState/);
  assert.match(source, /accepted\.role !== "viewer"/);
  assert.match(source, /A lost response does not reveal which tenant accepted the token/);
  assert.match(source, /limit: 100/);
  assert.match(source, /nextCursor/);
  assert.match(source, /LoadMoreButton/);
  assert.match(source, /onRetry=\{refresh\}/);
  assert.match(source, /setOrganizations\(\[\]\)/);
  assert.match(source, /actorMembership\.status === "active"/);
  assert.match(source, /findOrganizationMemberRole/);
  assert.match(source, /Member pagination cursor repeated/);
  assert.doesNotMatch(source, /AgentPassConsole/);
  assert.doesNotMatch(source, /localStorage|sessionStorage|console\.(?:log|info|warn|error)/);
  assert.doesNotMatch(source, /navigator\.clipboard|document\.cookie|location\.(?:href|assign|replace)/);
});

test("invitation reissue is role-gated and the raw token has one display sink", async () => {
  const source = await readFile(componentPath, "utf8");
  assert.match(source, /canReissue=\{visibility\.canInvite\}/);
  assert.match(source, /const reissuable = canReissue && \(status === "pending" \|\| status === "expired"\)/);
  assert.match(source, /\{oneTimeToken !== null && <section[^>]*organization-one-time-secret/);
  assert.equal((source.match(/className="organization-token"/g) ?? []).length, 1);
  assert.equal((source.match(/\{oneTimeToken\}/g) ?? []).length, 1);
  assert.doesNotMatch(source, /navigator\.clipboard|localStorage|sessionStorage|document\.cookie|console\.(?:log|info|warn|error)/);
  assert.doesNotMatch(source, /new URL\([^)]*oneTimeToken|URLSearchParams\([^)]*oneTimeToken/);
});

test("organization styling keeps pending, expired, revoked, and keyboard-visible states in the existing visual system", async () => {
  const source = await readFile(cssPath, "utf8");
  assert.match(source, /\.organization-panel/);
  assert.match(source, /organization-list-row\[data-state="pending"\]/);
  assert.match(source, /organization-list-row\[data-state="expired"\]/);
  assert.match(source, /organization-list-row\[data-state="revoked"\]/);
  assert.match(source, /organization-confirmation/);
  assert.match(source, /\.sr-only/);
});

test("panel visibility matches owner/admin/auditor/viewer policy", () => {
  assert.equal(getOrganizationVisibility("owner").canManageMembers, true);
  assert.equal(getOrganizationVisibility("admin").canInvite, true);
  assert.equal(getOrganizationVisibility("auditor").canViewMembers, true);
  assert.equal(getOrganizationVisibility("auditor").canInvite, false);
  assert.equal(getOrganizationVisibility("viewer").canViewMembers, false);
  assert.equal(getOrganizationVisibility("viewer").canViewInvitations, false);
});

test("AgentPassConsole exposes the Organization administration view", async () => {
  const source = await readFile(consolePath, "utf8");
  assert.match(source, /import \{ OrganizationPanel \} from "\.\/OrganizationPanel"/);
  assert.match(source, /\| "organizations"/);
  assert.match(source, /label: "Organizations"/);
  assert.match(source, /activeView === "organizations" \? <OrganizationPanel key=\{selectedOrganizationId \?\? "session-organization"\} client=\{organizationClient\} initialOrganizationId=\{selectedOrganizationId \?\? undefined\} onOrganizationSwitched=\{handleOrganizationSwitched\} \/> : null/);
  assert.match(source, /organization-content/);
  assert.match(source, /onOrganizationSwitched=\{handleOrganizationSwitched\}/);
});

test("authenticated workspace selection is BFF-backed and fail-closed", async () => {
  const source = await readFile(consolePath, "utf8");
  assert.match(source, /createOrganizationClient/);
  assert.match(source, /loadOrganizationSwitcherOrganizations\(organizationClient\)/);
  assert.match(source, /resolveOrganizationSelection\(organizationOptions, organization\.id\)/);
  assert.match(source, /setActiveView\("organizations"\)/);
  assert.match(source, /initialOrganizationId=\{selectedOrganizationId \?\? undefined\}/);
  assert.match(source, /activeView === "organizations" \? selectedOrganization\?\.name \?\? data\.workspace : data\.workspace/);
  assert.match(source, /選択後も権限とテナントはCloudで再検証されます/);
  assert.match(source, /このセッションでは組織の一覧を確認できません/);
  assert.doesNotMatch(source, /localStorage|sessionStorage|document\.cookie|console\.(?:log|info|warn|error)/);
});

test("organization mutations reconcile authoritative state after response loss without resending", async () => {
  const source = await readFile(componentPath, "utf8");
  assert.match(source, /reconcile\?: \(\) => Promise<void>/);
  assert.match(source, /const reconcileResources = useCallback/);
  assert.match(source, /loadAllMembers\(client, organizationId\)/);
  assert.match(source, /loadAllInvitations\(client, organizationId\)/);
  assert.match(source, /isAmbiguousOrganizationMutationError\(error\)/);
  assert.match(source, /code: "reconciliation_required"/);
  assert.match(source, /state\.code === "reconciliation_required"/);
  assert.match(source, /権威状態を再取得しました。操作は再送していません/);
  assert.match(source, /再送せず、最新の状態をもう一度確認/);
  assert.match(source, /await options\.reconcile\(\)/);
  assert.match(source, /setPendingAction\("reconcile"\)/);
  assert.match(source, /disabled=\{pendingAction !== null\}/);
});

test("last-owner protection is visible, actionable, and reconciles server-side protection errors", async () => {
  const source = await readFile(componentPath, "utf8");
  assert.match(source, /activeOwnerCount/);
  assert.match(source, /ownerSnapshotComplete/);
  assert.match(source, /last_owner_protected/);
  assert.match(source, /最後のOwnerは降格・失効できません/);
  assert.match(source, /先に別のメンバーをOwnerに変更/);
  assert.match(source, /isLastOwnerProtectionError/);
  assert.match(source, /serverCode\?\.toLowerCase\(\)/);
  assert.match(source, /aria-describedby=\{describedBy\}/);
  assert.match(source, /data-state=\{state\.code \?\? "error"\}/);
  assert.match(source, /const LAST_OWNER_REMEDIATION/);
});
