import { expect, test, type Page, type Route } from "@playwright/test";
import {
  AUTHORIZATION_ID,
  CREDENTIAL_ID,
  CSRF_TOKEN,
  ORGANIZATION_ID,
  OTHER_MEMBER_ID,
  SESSION_ID,
  browserStorageSnapshot,
  consoleSummary,
  disposeVirtualAuthenticator,
  installVirtualAuthenticator,
  json,
  parseRequestBody,
  session,
} from "./support/browser-fixtures";

const DATE = "2026-08-12T00:00:00.000Z";
const FUTURE = "2099-01-02T12:00:00.000Z";
const ORGANIZATION_NAME = "Mutation E2E Organization";
const RENAMED_ORGANIZATION = "Renamed Mutation Organization";
const INVITATION_TOKEN = "i".repeat(64);
const REISSUED_INVITATION_TOKEN = "r".repeat(64);
const OTHER_SESSION_ID = "23333333-3333-4333-8333-333333333333";
const INVITATION_ID = "85555555-5555-4555-8555-555555555555";
const SECOND_CREDENTIAL_ID = "B".repeat(22);
const REQUEST_IDS = {
  list: "69999999-9999-4999-8999-999999999999",
  rename: "6a999999-9999-4999-8999-999999999999",
  role: "6b999999-9999-4999-8999-999999999999",
  remove: "6c999999-9999-4999-8999-999999999999",
  invitationCreate: "6d999999-9999-4999-8999-999999999999",
  invitationRevoke: "6e999999-9999-4999-8999-999999999999",
  invitationReissue: "6f999999-9999-4999-8999-999999999999",
};
const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

type MutationRequest = Readonly<{
  method: string;
  path: string;
  body: Record<string, unknown>;
  headers: Record<string, string>;
}>;

type OrganizationRouteState = {
  organizationName: string;
  organizationVersion: number;
  memberRole: "viewer" | "auditor";
  memberStatus: "active" | "revoked";
  memberVersion: number;
  invitationStatus: "pending" | "revoked";
  invitationVersion: number;
  invitationExpiresAt: string;
  roleConflictOnce: boolean;
  recentAuthFailureOnce: boolean;
  mutations: MutationRequest[];
  recentAuthOperations: string[];
  reissueResponseLossOnce?: boolean;
};

type SecurityRouteState = {
  passkeyLabel: string;
  passkeyVersion: number;
  passkeyStatus: "active" | "revoked";
  passkeyListReads: number;
  passkeyCount: 1 | 2;
  passkeyNextCursor: string | null;
  revokePasskeyErrorCode?: string;
  otherSessionStatus: "active" | "revoked";
  currentSessionStatus: "active" | "revoked";
  mutations: MutationRequest[];
  recentAuthOperations: string[];
  failStatus?: 401 | 403;
};

function organizationRecord(state: OrganizationRouteState) {
  return {
    organization_id: ORGANIZATION_ID,
    name: state.organizationName,
    version: state.organizationVersion,
    created_at: DATE,
    updated_at: DATE,
  };
}

function memberRecord(state: OrganizationRouteState) {
  return {
    membership_id: "34444444-4444-4444-8444-444444444444",
    organization_id: ORGANIZATION_ID,
    member_id: OTHER_MEMBER_ID,
    display_name: "共同管理者",
    role: state.memberRole,
    status: state.memberStatus,
    version: state.memberVersion,
    created_at: DATE,
    updated_at: DATE,
  };
}

function invitationRecord(state: OrganizationRouteState) {
  return {
    invitation_id: INVITATION_ID,
    organization_id: ORGANIZATION_ID,
    role: "viewer",
    status: state.invitationStatus,
    version: state.invitationVersion,
    created_at: DATE,
    expires_at: state.invitationExpiresAt,
    accepted_at: null,
    accepted_member_id: null,
  };
}

function securityPasskey(state: SecurityRouteState, credentialId = CREDENTIAL_ID) {
  return {
    credential_id: credentialId,
    version: credentialId === CREDENTIAL_ID ? state.passkeyVersion : 1,
    label: credentialId === CREDENTIAL_ID ? state.passkeyLabel : "Recovery Touch ID",
    transports: ["internal"],
    backup_eligible: false,
    backup_state: false,
    status: credentialId === CREDENTIAL_ID ? state.passkeyStatus : "active",
    created_at: DATE,
    last_used_at: null,
    revoked_at: credentialId === CREDENTIAL_ID && state.passkeyStatus === "revoked" ? FUTURE : null,
  };
}

function securitySession(state: SecurityRouteState, current: boolean) {
  const revoked = current ? state.currentSessionStatus === "revoked" : state.otherSessionStatus === "revoked";
  return {
    session_id: current ? SESSION_ID : OTHER_SESSION_ID,
    version: revoked ? 2 : 1,
    member_id: "33333333-3333-4333-8333-333333333333",
    organization_id: ORGANIZATION_ID,
    role: "owner",
    status: revoked ? "revoked" : "active",
    is_current: current,
    created_at: DATE,
    expires_at: FUTURE,
    last_seen_at: DATE,
    recent_auth_at: null,
    revoked_at: revoked ? FUTURE : null,
  };
}

function requestMutation(route: Route): MutationRequest {
  return {
    method: route.request().method(),
    path: new URL(route.request().url()).pathname,
    body: parseRequestBody(route),
    headers: route.request().headers(),
  };
}

function assertOrganizationMutation(
  request: MutationRequest,
  expected: { method: string; path: string; body: Record<string, unknown>; ifMatch?: string; recentAuth?: string },
): void {
  expect(request.method).toBe(expected.method);
  expect(request.path).toBe(expected.path);
  expect(request.body).toEqual(expected.body);
  expect(request.headers["agentpass-csrf"]).toBe(CSRF_TOKEN);
  expect(request.headers.accept).toBe("application/json");
  expect(request.headers["cache-control"]).toBe("no-store");
  expect(request.headers["idempotency-key"]).toMatch(UUID_V4);
  if (expected.ifMatch === undefined) expect(request.headers["if-match"]).toBeUndefined();
  else expect(request.headers["if-match"]).toBe(expected.ifMatch);
  if (expected.recentAuth === undefined) expect(request.headers["agentpass-recent-auth"]).toBeUndefined();
  else expect(request.headers["agentpass-recent-auth"]).toBe(expected.recentAuth);
}

function assertSecurityMutation(
  request: MutationRequest,
  expected: {
    method: string;
    path: string;
    body: Record<string, unknown>;
    ifMatch?: string;
    idempotency?: boolean;
    recentAuth?: string;
    recentAuthContext?: boolean;
  },
): void {
  expect(request.method).toBe(expected.method);
  expect(request.path).toBe(expected.path);
  expect(request.body).toEqual(expected.body);
  expect(request.headers["agentpass-csrf"]).toBe(CSRF_TOKEN);
  expect(request.headers.accept).toBe("application/json");
  if (expected.ifMatch === undefined) expect(request.headers["if-match"]).toBeUndefined();
  else expect(request.headers["if-match"]).toBe(expected.ifMatch);
  if (expected.idempotency === true) expect(request.headers["idempotency-key"]).toMatch(UUID_V4);
  else expect(request.headers["idempotency-key"]).toBeUndefined();
  if (expected.recentAuth === undefined) expect(request.headers["agentpass-recent-auth"]).toBeUndefined();
  else expect(request.headers["agentpass-recent-auth"]).toBe(expected.recentAuth);
  if (expected.recentAuthContext === true) expect(request.headers["agentpass-recent-auth-context"]).toMatch(/^[0-9a-f]{64}$/u);
  else expect(request.headers["agentpass-recent-auth-context"]).toBeUndefined();
}

async function assertNoReusableAuthority(page: Page, secrets: readonly string[]): Promise<void> {
  const body = await page.locator("body").innerText();
  const storage = await browserStorageSnapshot(page);
  const serializedStorage = JSON.stringify(storage);
  const url = page.url();
  for (const secret of secrets) {
    expect(body).not.toContain(secret);
    expect(serializedStorage).not.toContain(secret);
    expect(url).not.toContain(secret);
  }
  expect(Object.keys(storage.local)).toHaveLength(0);
  expect(Object.keys(storage.session)).toHaveLength(0);
}

async function openOrganizationPanel(page: Page): Promise<void> {
  await page.goto("/");
  await expect(page.getByRole("heading", { name: /Agentの状態を、\s*確認できました。/u })).toBeVisible();
  await page.getByRole("button", { name: "Organizations", exact: true }).click();
  await expect(page.getByRole("heading", { name: "組織を安全に管理する" })).toBeVisible();
}

async function openSecurityPanel(page: Page, options: { expectPanel?: boolean } = {}): Promise<void> {
  await page.goto("/");
  await expect(page.getByRole("heading", { name: /Agentの状態を、\s*確認できました。/u })).toBeVisible();
  await page.getByRole("button", { name: "セキュリティ", exact: true }).click();
  if (options.expectPanel !== false) await expect(page.getByRole("heading", { name: "アカウントを守る" })).toBeVisible();
}

async function installOrganizationRoutes(page: Page, role: "owner" | "admin"): Promise<OrganizationRouteState> {
  const state: OrganizationRouteState = {
    organizationName: ORGANIZATION_NAME,
    organizationVersion: 1,
    memberRole: "viewer",
    memberStatus: "active",
    memberVersion: 1,
    invitationStatus: "pending",
    invitationVersion: 1,
    invitationExpiresAt: FUTURE,
    roleConflictOnce: true,
    recentAuthFailureOnce: false,
    mutations: [],
    recentAuthOperations: [],
  };

  await page.route("**/api/auth/**", async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    if (url.pathname === "/api/auth/session/resume" || url.pathname === "/api/auth/session") return json(route, session(role));
    if (url.pathname === "/api/auth/webauthn/options") {
      const body = parseRequestBody(route);
      state.recentAuthOperations.push(String(body.operation ?? ""));
      if (state.recentAuthFailureOnce) {
        state.recentAuthFailureOnce = false;
        return json(route, { error: { code: "recent_auth_required", message: "Recent authentication required" } }, 403);
      }
      return json(route, {
        challenge_id: "57777777-7777-4777-8777-777777777777",
        options: {
          challenge: "Q0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NA",
          rpId: "localhost",
          userVerification: "required",
          allowCredentials: [{ id: CREDENTIAL_ID, type: "public-key", transports: ["internal"] }],
        },
      });
    }
    if (url.pathname === "/api/auth/webauthn/verify") {
      const body = parseRequestBody(route);
      expect(body.organization_id).toBe(ORGANIZATION_ID);
      expect(typeof body.credential).toBe("object");
      state.recentAuthOperations.push(String(body.operation ?? ""));
      return json(route, { authorization_id: AUTHORIZATION_ID });
    }
    if (url.pathname === `/api/auth/organizations/${ORGANIZATION_ID}` && request.method() === "PATCH") {
      state.mutations.push(requestMutation(route));
      state.organizationName = String(parseRequestBody(route).name);
      state.organizationVersion = 2;
      return json(route, { request_id: REQUEST_IDS.rename, organization: organizationRecord(state) });
    }
    if (url.pathname === `/api/auth/organizations/${ORGANIZATION_ID}/members/${OTHER_MEMBER_ID}/role` && request.method() === "PATCH") {
      state.mutations.push(requestMutation(route));
      if (state.roleConflictOnce) {
        state.roleConflictOnce = false;
        return json(route, { error: { code: "version_conflict", message: "Version conflict" } }, 409);
      }
      state.memberRole = parseRequestBody(route).role as "auditor";
      state.memberVersion = 2;
      return json(route, { request_id: REQUEST_IDS.role, member: memberRecord(state) });
    }
    if (url.pathname === `/api/auth/organizations/${ORGANIZATION_ID}/members/${OTHER_MEMBER_ID}/remove` && request.method() === "POST") {
      state.mutations.push(requestMutation(route));
      state.memberStatus = "revoked";
      state.memberVersion = 3;
      return json(route, { request_id: REQUEST_IDS.remove, member: memberRecord(state) });
    }
    if (url.pathname === `/api/auth/organizations/${ORGANIZATION_ID}/invitations` && request.method() === "POST") {
      state.mutations.push(requestMutation(route));
      const body = parseRequestBody(route);
      state.invitationExpiresAt = String(body.expires_at);
      if (body.reissue_invitation_id !== undefined) {
        state.invitationVersion = 2;
        if (state.reissueResponseLossOnce) {
          state.reissueResponseLossOnce = false;
          await route.abort("connectionreset");
          return;
        }
        return json(route, {
          request_id: REQUEST_IDS.invitationReissue,
          invitation: invitationRecord(state),
          one_time_token: REISSUED_INVITATION_TOKEN,
        }, 201);
      }
      return json(route, {
        request_id: REQUEST_IDS.invitationCreate,
        invitation: invitationRecord(state),
        one_time_token: INVITATION_TOKEN,
      }, 201);
    }
    if (url.pathname === `/api/auth/organizations/${ORGANIZATION_ID}/invitations/${INVITATION_ID}/revoke` && request.method() === "POST") {
      state.mutations.push(requestMutation(route));
      state.invitationStatus = "revoked";
      state.invitationVersion = 2;
      return json(route, { request_id: REQUEST_IDS.invitationRevoke, invitation: invitationRecord(state) });
    }
    if (url.pathname === `/api/auth/organizations/${ORGANIZATION_ID}/members` && request.method() === "GET") {
      return json(route, {
        request_id: REQUEST_IDS.list,
        members: [
          { membership_id: "33333333-3333-4333-8333-333333333333", organization_id: ORGANIZATION_ID, member_id: "33333333-3333-4333-8333-333333333333", display_name: "現在の利用者", role, status: "active", version: 1, created_at: DATE, updated_at: DATE },
          memberRecord(state),
        ],
        next_cursor: null,
      });
    }
    if (url.pathname === `/api/auth/organizations/${ORGANIZATION_ID}/invitations` && request.method() === "GET") {
      return json(route, { request_id: REQUEST_IDS.list, invitations: [invitationRecord(state)], next_cursor: null });
    }
    if (url.pathname === "/api/auth/organizations" && request.method() === "GET") {
      return json(route, { request_id: REQUEST_IDS.list, organizations: [organizationRecord(state)], next_cursor: null });
    }
    return json(route, { error: { code: "not_found", message: "Not found" } }, 404);
  });
  await page.route("**/api/console**", async (route) => {
    if (route.request().method() === "GET") return json(route, consoleSummary());
    return json(route, { error: { code: "forbidden", message: "Forbidden" } }, 403);
  });
  return state;
}

async function installSecurityRoutes(page: Page, failStatus?: 401 | 403, options: { passkeyCount?: 1 | 2; passkeyNextCursor?: string | null; revokePasskeyErrorCode?: string } = {}): Promise<SecurityRouteState> {
  const state: SecurityRouteState = {
    passkeyLabel: "Mac Touch ID",
    passkeyVersion: 1,
    passkeyStatus: "active",
    passkeyListReads: 0,
    passkeyCount: options.passkeyCount ?? 2,
    passkeyNextCursor: options.passkeyNextCursor ?? null,
    revokePasskeyErrorCode: options.revokePasskeyErrorCode,
    otherSessionStatus: "active",
    currentSessionStatus: "active",
    mutations: [],
    recentAuthOperations: [],
    failStatus,
  };
  await page.route("**/api/auth/**", async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    if (url.pathname === "/api/auth/session/resume" || url.pathname === "/api/auth/session") return json(route, session("owner"));
    if (url.pathname === "/api/auth/webauthn/options") {
      const body = parseRequestBody(route);
      state.recentAuthOperations.push(String(body.operation ?? ""));
      return json(route, {
        challenge_id: "57777777-7777-4777-8777-777777777777",
        options: {
          challenge: "Q0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NA",
          rpId: "localhost",
          userVerification: "required",
          allowCredentials: [{ id: CREDENTIAL_ID, type: "public-key", transports: ["internal"] }],
        },
      });
    }
    if (url.pathname === "/api/auth/webauthn/verify") {
      state.recentAuthOperations.push(String(parseRequestBody(route).operation ?? ""));
      return json(route, { authorization_id: AUTHORIZATION_ID });
    }
    if (url.pathname === "/api/auth/security/passkeys" && request.method() === "GET") {
      if (state.failStatus !== undefined) return json(route, { error: { code: "security_unavailable", message: "Security unavailable" } }, state.failStatus);
      state.passkeyListReads += 1;
      // The production management endpoint is active-only. A revoked credential
      // is accepted on the mutation response but must disappear from the next list.
      const credentials = state.passkeyStatus === "active" ? [securityPasskey(state)] : [];
      if (state.passkeyCount === 2) credentials.push(securityPasskey(state, SECOND_CREDENTIAL_ID));
      return json(route, { credentials, next_cursor: state.passkeyNextCursor });
    }
    if (url.pathname === "/api/auth/security/sessions" && request.method() === "GET") {
      if (state.failStatus !== undefined) return json(route, { error: { code: "security_unavailable", message: "Security unavailable" } }, state.failStatus);
      return json(route, { sessions: [securitySession(state, true), securitySession(state, false)], next_cursor: null });
    }
    if (url.pathname === `/api/auth/security/passkeys/${CREDENTIAL_ID}` && request.method() === "PATCH") {
      state.mutations.push(requestMutation(route));
      const body = parseRequestBody(route);
      state.passkeyLabel = String(body.label);
      state.passkeyVersion = 2;
      return json(route, { credential: securityPasskey(state) });
    }
    if (url.pathname === `/api/auth/security/passkeys/${CREDENTIAL_ID}/revoke` && request.method() === "POST") {
      state.mutations.push(requestMutation(route));
      if (state.revokePasskeyErrorCode !== undefined) return json(route, { error: { code: state.revokePasskeyErrorCode, message: "The last active credential cannot be revoked" } }, 409);
      state.passkeyStatus = "revoked";
      state.passkeyVersion += 1;
      return json(route, { credential: securityPasskey(state) });
    }
    if (url.pathname === "/api/auth/security/sessions/revoke-others" && request.method() === "POST") {
      state.mutations.push(requestMutation(route));
      state.otherSessionStatus = "revoked";
      return json(route, { revoked_sessions: [securitySession(state, false)], revoked_count: 1, truncated: false });
    }
    if (url.pathname === `/api/auth/security/sessions/${SESSION_ID}/revoke` && request.method() === "POST") {
      state.mutations.push(requestMutation(route));
      state.currentSessionStatus = "revoked";
      return json(route, { session: securitySession(state, true) });
    }
    return json(route, { error: { code: "not_found", message: "Not found" } }, 404);
  });
  await page.route("**/api/console**", async (route) => json(route, consoleSummary()));
  return state;
}

for (const role of ["owner", "admin"] as const) {
  test(`production Console organization mutations preserve ${role} authorization boundaries`, async ({ page }) => {
    const consoleMessages: string[] = [];
    page.on("console", (message) => consoleMessages.push(message.text()));
    const authenticator = await installVirtualAuthenticator(page);
    const state = await installOrganizationRoutes(page, role);
    try {
      await openOrganizationPanel(page);

      if (role === "owner") {
        const currentRole = page.getByLabel("現在の利用者のロール");
        await currentRole.selectOption("admin");
        await page.getByRole("button", { name: "現在の利用者をAdminに変更", exact: true }).click();
        await expect(page.getByRole("alert")).toContainText("最後のOwnerは降格・失効できません");
        await expect(currentRole).toHaveValue("owner");
        expect(state.mutations).toHaveLength(0);

        await page.getByRole("button", { name: "現在の利用者のアクセスを失効", exact: true }).click();
        await expect(page.getByRole("alert")).toContainText("先に別のメンバーをOwnerに変更");
        await expect(page.getByRole("button", { name: "失効を確定", exact: true })).toHaveCount(0);
        expect(state.mutations).toHaveLength(0);
      }

      await page.getByLabel("組織名を変更").fill(RENAMED_ORGANIZATION);
      await page.getByRole("button", { name: "名前を変更", exact: true }).click();
      await expect(page.getByText(`${RENAMED_ORGANIZATION} · v2`, { exact: true })).toBeVisible();

      await page.getByLabel("付与するロール").selectOption("viewer");
      const invitationExpiryLocal = "2099-01-02T12:00";
      const expectedInvitationExpiry = await page.evaluate((value) => new Date(value).toISOString(), invitationExpiryLocal);
      await page.getByLabel("有効期限").fill(invitationExpiryLocal);
      await page.getByRole("button", { name: "招待を発行", exact: true }).click();
      await expect(page.getByText(INVITATION_TOKEN, { exact: true })).toBeVisible();
      expect(page.url()).not.toContain(INVITATION_TOKEN);
      expect(JSON.stringify(await browserStorageSnapshot(page))).not.toContain(INVITATION_TOKEN);
      await page.getByRole("button", { name: "Viewer招待を再発行", exact: true }).click();
      await expect(page.getByText(INVITATION_TOKEN, { exact: true })).toHaveCount(0);
      const reissueExpiryLocal = "2099-01-03T12:00";
      const expectedReissueExpiry = await page.evaluate((value) => new Date(value).toISOString(), reissueExpiryLocal);
      await page.getByLabel("再発行後の有効期限").fill(reissueExpiryLocal);
      await page.getByRole("button", { name: "再発行を確定", exact: true }).click();
      await expect(page.getByText(REISSUED_INVITATION_TOKEN, { exact: true })).toBeVisible();
      expect(page.url()).not.toContain(REISSUED_INVITATION_TOKEN);
      expect(JSON.stringify(await browserStorageSnapshot(page))).not.toContain(REISSUED_INVITATION_TOKEN);
      await page.getByRole("button", { name: "招待トークンを閉じる", exact: true }).click();
      await expect(page.getByText(REISSUED_INVITATION_TOKEN, { exact: true })).toHaveCount(0);
      await page.getByRole("button", { name: "Viewer招待を取り消す", exact: true }).click();
      await expect(page.getByText(/^取り消し済み · 有効期限/u)).toBeVisible();

      const roleSelect = page.getByLabel("共同管理者のロール");
      await roleSelect.selectOption("auditor");
      await page.getByRole("button", { name: "共同管理者をAuditorに変更", exact: true }).click();
      await expect(page.getByRole("alert")).toContainText("他の管理者が先に変更しました");
      await page.getByRole("button", { name: "最新情報を読み込む", exact: true }).click();
      await expect(roleSelect).toHaveValue("viewer");

      state.recentAuthFailureOnce = true;
      await roleSelect.selectOption("auditor");
      await page.getByRole("button", { name: "共同管理者をAuditorに変更", exact: true }).click();
      await expect(page.getByRole("alert")).toContainText("安全な本人確認が必要です");
      await page.getByRole("button", { name: "本人確認をやり直す", exact: true }).click();
      await expect(page.getByText("Auditor · 有効 · v2", { exact: true })).toBeVisible();

      await page.getByRole("button", { name: "共同管理者のアクセスを失効", exact: true }).click();
      const confirm = page.getByRole("button", { name: "失効を確定", exact: true });
      await expect(confirm).toBeVisible();
      await confirm.focus();
      await page.keyboard.press("Enter");
      await expect.poll(() => state.mutations.length).toBe(7);
      await expect(page.getByText("このメンバーは失効しています", { exact: true })).toBeVisible();

      const [rename, invitationCreate, invitationReissue, invitationRevoke, roleConflict, roleRequest, remove] = state.mutations;
      assertOrganizationMutation(rename, {
        method: "PATCH",
        path: `/api/auth/organizations/${ORGANIZATION_ID}`,
        body: { name: RENAMED_ORGANIZATION },
        ifMatch: '"1"',
      });
      assertOrganizationMutation(invitationCreate, {
        method: "POST",
        path: `/api/auth/organizations/${ORGANIZATION_ID}/invitations`,
        body: { role: "viewer", expires_at: expectedInvitationExpiry },
      });
      assertOrganizationMutation(invitationReissue, {
        method: "POST",
        path: `/api/auth/organizations/${ORGANIZATION_ID}/invitations`,
        body: { reissue_invitation_id: INVITATION_ID, expires_at: expectedReissueExpiry },
        ifMatch: '"1"',
        recentAuth: AUTHORIZATION_ID,
      });
      assertOrganizationMutation(invitationRevoke, {
        method: "POST",
        path: `/api/auth/organizations/${ORGANIZATION_ID}/invitations/${INVITATION_ID}/revoke`,
        body: {},
        ifMatch: '"2"',
        recentAuth: AUTHORIZATION_ID,
      });
      assertOrganizationMutation(roleRequest, {
        method: "PATCH",
        path: `/api/auth/organizations/${ORGANIZATION_ID}/members/${OTHER_MEMBER_ID}/role`,
        body: { role: "auditor" },
        ifMatch: '"1"',
        recentAuth: AUTHORIZATION_ID,
      });
      assertOrganizationMutation(roleConflict, {
        method: "PATCH",
        path: `/api/auth/organizations/${ORGANIZATION_ID}/members/${OTHER_MEMBER_ID}/role`,
        body: { role: "auditor" },
        ifMatch: '"1"',
        recentAuth: AUTHORIZATION_ID,
      });
      assertOrganizationMutation(remove, {
        method: "POST",
        path: `/api/auth/organizations/${ORGANIZATION_ID}/members/${OTHER_MEMBER_ID}/remove`,
        body: {},
        ifMatch: '"2"',
        recentAuth: AUTHORIZATION_ID,
      });
      expect(state.mutations).toHaveLength(7);
      expect(state.recentAuthOperations).toContain("human.organizations.invitation.reissue");
      expect(state.recentAuthOperations).toContain("human.organizations.member.role.update");
      expect(state.recentAuthOperations).toContain("human.organizations.member.remove");
      expect(consoleMessages.join("\n")).not.toContain(AUTHORIZATION_ID);
      await assertNoReusableAuthority(page, [AUTHORIZATION_ID, CSRF_TOKEN, CREDENTIAL_ID, INVITATION_TOKEN, REISSUED_INVITATION_TOKEN]);
    } finally {
      await disposeVirtualAuthenticator(authenticator);
    }
  });
}

test("production Console SecurityPanel executes passkey and session mutations with keyboard confirmations", async ({ page }) => {
  const consoleMessages: string[] = [];
  page.on("console", (message) => consoleMessages.push(message.text()));
  const authenticator = await installVirtualAuthenticator(page);
  const state = await installSecurityRoutes(page);
  try {
    await openSecurityPanel(page);

    await page.getByRole("button", { name: "名前を変更", exact: true }).first().click();
    await page.getByLabel("パスキーの表示名").fill("Mac Touch ID renamed");
    await page.getByRole("button", { name: "保存", exact: true }).click();
    await expect(page.getByText("Mac Touch ID renamed", { exact: true })).toBeVisible();

    await page.getByRole("button", { name: "無効化", exact: true }).first().click();
    const revokePasskey = page.getByRole("button", { name: "無効化する", exact: true });
    await revokePasskey.focus();
    await page.keyboard.press("Enter");
    await expect.poll(() => state.passkeyListReads).toBeGreaterThan(1);
    await expect(page.getByText("Mac Touch ID renamed", { exact: true })).toHaveCount(0);
    await expect(page.getByText("✓ パスキーを無効化しました。", { exact: true })).toBeVisible();

    await page.getByRole("button", { name: "他のセッションをすべて無効化", exact: true }).click();
    const confirmOther = page.getByRole("button", { name: "確認", exact: true });
    await confirmOther.focus();
    await page.keyboard.press("Enter");
    await expect(page.getByText("✓ 他のセッションをすべて無効化しました。", { exact: true })).toBeVisible();
    await expect(page.getByText("別のブラウザセッション", { exact: true })).toHaveCount(0);

    const securityPanel = page.locator('section[aria-labelledby="security-panel-title"]');
    await securityPanel.getByRole("button", { name: "サインアウト", exact: true }).click();
    const signOut = page.getByRole("button", { name: "サインアウトする", exact: true });
    await signOut.focus();
    await page.keyboard.press("Enter");
    await expect(page.getByRole("heading", { name: "サインアウトしました" })).toBeVisible();

    const [rename, revokePasskeyRequest, revokeOther, revokeCurrent] = state.mutations;
    assertSecurityMutation(rename, {
      method: "PATCH",
      path: `/api/auth/security/passkeys/${CREDENTIAL_ID}`,
      body: { label: "Mac Touch ID renamed" },
      ifMatch: '"1"',
      idempotency: true,
    });
    assertSecurityMutation(revokePasskeyRequest, {
      method: "POST",
      path: `/api/auth/security/passkeys/${CREDENTIAL_ID}/revoke`,
      body: {},
      ifMatch: '"2"',
      idempotency: true,
      recentAuth: AUTHORIZATION_ID,
      recentAuthContext: true,
    });
    assertSecurityMutation(revokeOther, {
      method: "POST",
      path: "/api/auth/security/sessions/revoke-others",
      body: {},
      recentAuth: AUTHORIZATION_ID,
    });
    assertSecurityMutation(revokeCurrent, {
      method: "POST",
      path: `/api/auth/security/sessions/${SESSION_ID}/revoke`,
      body: { expected_version: 1 },
      recentAuth: AUTHORIZATION_ID,
    });
    expect(state.mutations).toHaveLength(4);
    expect(state.recentAuthOperations).toEqual([
      "human.management.credential.revoke",
      "human.management.credential.revoke",
      "human.management.sessions.revoke_others",
      "human.management.sessions.revoke_others",
      "human.management.session.revoke",
      "human.management.session.revoke",
    ]);
    expect(consoleMessages.join("\n")).not.toContain(AUTHORIZATION_ID);
    await assertNoReusableAuthority(page, [AUTHORIZATION_ID, CSRF_TOKEN, CREDENTIAL_ID]);
  } finally {
    await disposeVirtualAuthenticator(authenticator);
  }
});

test("production Console blocks revoking the only active passkey after a complete inventory", async ({ page }) => {
  const authenticator = await installVirtualAuthenticator(page);
  const state = await installSecurityRoutes(page, undefined, { passkeyCount: 1 });
  try {
    await openSecurityPanel(page);
    const passkeys = page.getByRole("article").filter({ has: page.getByRole("heading", { name: "登録済みのパスキー" }) });
    await expect(passkeys.getByRole("note")).toContainText("唯一の利用可能なパスキーです");
    const revoke = passkeys.getByRole("button", { name: "無効化", exact: true });
    await expect(revoke).toBeDisabled();
    expect(await revoke.getAttribute("aria-describedby")).toBe("security-passkey-revoke-guidance");
    expect(state.mutations).toHaveLength(0);
  } finally {
    await disposeVirtualAuthenticator(authenticator);
  }
});

test("production Console does not infer the only passkey from a partial inventory", async ({ page }) => {
  const authenticator = await installVirtualAuthenticator(page);
  const state = await installSecurityRoutes(page, undefined, { passkeyCount: 1, passkeyNextCursor: "next-page" });
  try {
    await openSecurityPanel(page);
    const passkeys = page.getByRole("article").filter({ has: page.getByRole("heading", { name: "登録済みのパスキー" }) });
    await expect(passkeys.getByRole("status").filter({ hasText: "最後まで確認できていない" })).toBeVisible();
    await expect(passkeys.getByRole("button", { name: "無効化", exact: true })).toBeEnabled();
    expect(state.mutations).toHaveLength(0);
  } finally {
    await disposeVirtualAuthenticator(authenticator);
  }
});

test("production Console maps the final-passkey Cloud conflict without replaying the mutation", async ({ page }) => {
  const consoleMessages: string[] = [];
  page.on("console", (message) => consoleMessages.push(message.text()));
  const authenticator = await installVirtualAuthenticator(page);
  const state = await installSecurityRoutes(page, undefined, { passkeyCount: 2, revokePasskeyErrorCode: "ERR_LAST_ACTIVE_CREDENTIAL" });
  try {
    await openSecurityPanel(page);
    await page.getByRole("button", { name: "無効化", exact: true }).first().click();
    await page.getByRole("button", { name: "無効化する", exact: true }).click();
    await expect(page.getByRole("alert")).toContainText("最後の利用可能なパスキーのため無効化できません");
    expect(state.mutations).toHaveLength(1);
    expect(state.recentAuthOperations).toEqual(["human.management.credential.revoke", "human.management.credential.revoke"]);
    expect(consoleMessages.join("\n")).not.toContain("ERR_LAST_ACTIVE_CREDENTIAL");
  } finally {
    await disposeVirtualAuthenticator(authenticator);
  }
});

for (const status of [401, 403] as const) {
  test(`SecurityPanel fails closed on authoritative ${status} responses`, async ({ page }) => {
    const consoleMessages: string[] = [];
    page.on("console", (message) => consoleMessages.push(message.text()));
    const state = await installSecurityRoutes(page, status);
    await openSecurityPanel(page, { expectPanel: false });
    await expect(page.getByText("セッションの有効期限が切れました", { exact: true })).toBeVisible();
    await expect(page.getByRole("button", { name: "名前を変更", exact: true })).toHaveCount(0);
    await expect(page.getByRole("button", { name: "サインアウト", exact: true })).toHaveCount(0);
    expect(state.mutations).toHaveLength(0);
    expect(consoleMessages.join("\n")).not.toContain(AUTHORIZATION_ID);
    await assertNoReusableAuthority(page, [AUTHORIZATION_ID, CSRF_TOKEN, CREDENTIAL_ID]);
  });
}
