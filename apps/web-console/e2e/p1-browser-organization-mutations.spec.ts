import { expect, test, type Page, type Request, type Route } from "@playwright/test";
import {
  ACTIVE_EXPIRES_AT,
  AUTHORIZATION_ID,
  CHALLENGE,
  CREDENTIAL_ID,
  CSRF_TOKEN,
  MEMBER_ID,
  ORGANIZATION_ID,
  OTHER_MEMBER_ID,
  disposeVirtualAuthenticator,
  deploymentReadiness,
  installVirtualAuthenticator,
  json,
  parseRequestBody,
  session,
  type VirtualAuthenticator,
} from "./support/browser-fixtures";

/**
 * These are browser contract tests over deterministic API mocks. They do not
 * start or qualify a production API, database, identity provider, or release.
 * A mutation is considered successful only when the mocked response is
 * accepted by the client; every failure mode below must leave the optimistic
 * UI state rolled back.
 */
type FailureMode = "organization_conflict" | "role_conflict" | "member_forbidden" | "invitation_stale" | "invitation_idempotency" | "invitation_replay";

type MutationCall = Readonly<{
  path: string;
  method: string;
  body: Record<string, unknown>;
  headers: Record<string, string>;
}>;

type MutationState = {
  failure: FailureMode;
  mutationCalls: MutationCall[];
  authenticationOptions: Array<Record<string, unknown>>;
  authenticationVerifies: Array<Record<string, unknown>>;
  acceptedInvitationCalls: number;
};

const DATE = "2026-08-12T00:00:00.000Z";
const REQUEST_ID = "69999999-9999-4999-8999-999999999999";
const ROLE_MEMBER_MEMBERSHIP_ID = "34444444-4444-4444-8444-444444444444";
const INVITATION_ID = "85555555-5555-4555-8555-555555555555";
const INVITATION_TOKEN = "one-time-invitation-token-for-e2e-123456789";
const IDEMPOTENCY_KEY = /^[A-Za-z0-9][A-Za-z0-9._~-]{7,254}$/u;
const activeAuthenticators = new WeakMap<Page, VirtualAuthenticator>();

function authenticationOptions() {
  return {
    challenge: CHALLENGE,
    rpId: "localhost",
    userVerification: "required",
    timeout: 1_000,
    allowCredentials: [{ id: CREDENTIAL_ID, type: "public-key", transports: ["internal"] }],
  };
}

function organization() {
  return {
    organization_id: ORGANIZATION_ID,
    name: "Mutation E2E Organization",
    version: 1,
    created_at: DATE,
    updated_at: DATE,
  };
}

function member(memberId: string, displayName: string, role: "owner" | "admin" | "auditor" | "viewer", status: "active" | "revoked" = "active", version = 1) {
  return {
    membership_id: memberId === OTHER_MEMBER_ID ? ROLE_MEMBER_MEMBERSHIP_ID : "33333333-3333-4333-8333-333333333333",
    organization_id: ORGANIZATION_ID,
    member_id: memberId,
    display_name: displayName,
    role,
    status,
    version,
    created_at: DATE,
    updated_at: DATE,
  };
}

function invitation(status: "pending" | "revoked" = "pending", version = 1) {
  return {
    invitation_id: INVITATION_ID,
    organization_id: ORGANIZATION_ID,
    role: "viewer",
    status,
    version,
    created_at: DATE,
    expires_at: ACTIVE_EXPIRES_AT,
    accepted_at: null,
    accepted_member_id: null,
  };
}

function failureResponse(route: Route, mode: FailureMode): Promise<void> {
  if (mode === "organization_conflict" || mode === "role_conflict" || mode === "invitation_stale") {
    return json(route, { error: { code: "conflict", message: "The resource version is stale" } }, 409);
  }
  if (mode === "member_forbidden") {
    return json(route, { error: { code: "forbidden", message: "The operation is not permitted" } }, 403);
  }
  if (mode === "invitation_idempotency") {
    return json(route, { error: { code: "idempotency_conflict", message: "The idempotency key is already bound to another result" } }, 409);
  }
  return json(route, { error: { code: "invitation_replayed", message: "The invitation has already been consumed" } }, 409);
}

function requestBody(request: Request): Record<string, unknown> {
  try {
    const value: unknown = JSON.parse(request.postData() ?? "{}");
    return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : {};
  } catch {
    return {};
  }
}

function recordMutation(state: MutationState, request: Request, url: URL): void {
  state.mutationCalls.push({
    path: url.pathname,
    method: request.method(),
    body: requestBody(request),
    headers: request.headers(),
  });
}

async function installRoutes(page: Page, failure: FailureMode): Promise<MutationState> {
  const state: MutationState = {
    failure,
    mutationCalls: [],
    authenticationOptions: [],
    authenticationVerifies: [],
    acceptedInvitationCalls: 0,
  };

  await page.route("**/api/auth/**", async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    if (url.pathname === "/api/auth/session" || url.pathname === "/api/auth/session/resume") return json(route, session("owner"));
    if (url.pathname === "/api/auth/webauthn/options" && request.method() === "POST") {
      state.authenticationOptions.push(parseRequestBody(route));
      return json(route, { challenge_id: "57777777-7777-4777-8777-777777777777", options: authenticationOptions() });
    }
    if (url.pathname === "/api/auth/webauthn/verify" && request.method() === "POST") {
      state.authenticationVerifies.push(parseRequestBody(route));
      return json(route, { authorization_id: AUTHORIZATION_ID });
    }
    if (url.pathname === "/api/auth/organizations" && request.method() === "GET") {
      return json(route, { request_id: REQUEST_ID, organizations: [organization()], next_cursor: null });
    }
    if (url.pathname === `/api/auth/organizations/${ORGANIZATION_ID}/members` && request.method() === "GET") {
      return json(route, {
        request_id: REQUEST_ID,
        members: [member(MEMBER_ID, "現在の利用者", "owner"), member(OTHER_MEMBER_ID, "監査担当", "auditor")],
        next_cursor: null,
      });
    }
    if (url.pathname === `/api/auth/organizations/${ORGANIZATION_ID}/invitations` && request.method() === "GET") {
      return json(route, { request_id: REQUEST_ID, invitations: [invitation()], next_cursor: null });
    }
    if (url.pathname === "/api/auth/invitations/accept" && request.method() === "POST") {
      state.acceptedInvitationCalls += 1;
      recordMutation(state, request, url);
      return failureResponse(route, "invitation_replay");
    }
    if (url.pathname === `/api/auth/organizations/${ORGANIZATION_ID}` && request.method() === "PATCH") {
      recordMutation(state, request, url);
      if (failure === "organization_conflict") return failureResponse(route, failure);
      return json(route, { request_id: REQUEST_ID, organization: { ...organization(), name: "Renamed E2E Organization", version: 2 } });
    }
    if (url.pathname === `/api/auth/organizations/${ORGANIZATION_ID}/members/${OTHER_MEMBER_ID}/role` && request.method() === "PATCH") {
      recordMutation(state, request, url);
      if (failure === "role_conflict") return failureResponse(route, failure);
      return json(route, { request_id: REQUEST_ID, member: member(OTHER_MEMBER_ID, "監査担当", "admin", "active", 2) });
    }
    if (url.pathname === `/api/auth/organizations/${ORGANIZATION_ID}/members/${OTHER_MEMBER_ID}/remove` && request.method() === "POST") {
      recordMutation(state, request, url);
      if (failure === "member_forbidden") return failureResponse(route, failure);
      return json(route, { request_id: REQUEST_ID, member: member(OTHER_MEMBER_ID, "監査担当", "auditor", "revoked", 2) });
    }
    if (url.pathname === `/api/auth/organizations/${ORGANIZATION_ID}/invitations/${INVITATION_ID}/revoke` && request.method() === "POST") {
      recordMutation(state, request, url);
      if (failure === "invitation_stale" || failure === "invitation_idempotency") return failureResponse(route, failure);
      return json(route, { request_id: REQUEST_ID, invitation: invitation("revoked", 2) });
    }
    return json(route, { error: { code: "not_found", message: "Not found" } }, 404);
  });

  await page.route("**/api/console**", async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    if (request.method() === "GET" && url.searchParams.get("resource") === "deployment-readiness") return json(route, deploymentReadiness());
    if (request.method() === "GET" && url.searchParams.get("resource") === "summary") {
      return json(route, {
        organization: {
          organization_id: ORGANIZATION_ID,
          name: "Mutation E2E Organization",
          created_at: DATE,
          updated_at: DATE,
          version: 1,
        },
        devices: [{
          device_id: "41111111-1111-4111-8111-111111111111",
          name: "E2E Mac",
          status: "active",
          created_at: DATE,
          last_seen_at: DATE,
          version: 1,
          bundle_sequence: 1,
          bundle_expires_at: ACTIVE_EXPIRES_AT,
          last_ack_at: DATE,
          desired_generation: 1,
          observed_generation: 1,
          refresh_state: "applied",
          blocked_reason: null,
        }],
        agents: [],
        policies: [],
        audit: { health: [], activity: [], next_cursor: null },
      });
    }
    return json(route, { capabilities: [], revocations: [], events: [] });
  });

  return state;
}

async function openOrganization(page: Page, failure: FailureMode): Promise<MutationState> {
  const state = await installRoutes(page, failure);
  activeAuthenticators.set(page, await installVirtualAuthenticator(page));
  await page.goto("/");
  await expect(page.getByRole("heading", { name: /Agentの状態を、\s*確認できました。/u })).toBeVisible();
  await page.getByRole("button", { name: "Organizations", exact: true }).click();
  await expect(page.getByRole("heading", { name: "組織を安全に管理する" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "メンバー", exact: true })).toBeVisible();
  await expect(page.getByRole("heading", { name: "招待", exact: true })).toBeVisible();
  return state;
}

function assertIdempotentMutation(state: MutationState, expectedPath: string, expectedMethod: string, expectedVersion?: number): void {
  expect(state.mutationCalls).toHaveLength(1);
  const call = state.mutationCalls[0];
  expect(call.path).toBe(expectedPath);
  expect(call.method).toBe(expectedMethod);
  expect(call.headers["agentpass-csrf"]).toBe(CSRF_TOKEN);
  expect(call.headers["idempotency-key"]).toMatch(IDEMPOTENCY_KEY);
  expect(call.headers.origin).toMatch(/^http:\/\/localhost(?::\d+)?$/u);
  if (expectedVersion !== undefined) expect(call.headers["if-match"]).toBe(`"${expectedVersion}"`);
}

test("fails closed when a mocked organization rename returns a stale version", async ({ page }) => {
  const state = await openOrganization(page, "organization_conflict");
  const renameInput = page.getByRole("textbox", { name: "組織名を変更", exact: true });
  await renameInput.fill("別の管理名");
  await page.getByRole("button", { name: "名前を変更", exact: true }).click();

  await expect(page.getByRole("alert")).toContainText("他の管理者が先に変更しました");
  await expect(page.getByRole("button", { name: "最新情報を読み込む", exact: true })).toBeVisible();
  await expect(page.getByText("Mutation E2E Organization · v1", { exact: true })).toBeVisible();
  assertIdempotentMutation(state, `/api/auth/organizations/${ORGANIZATION_ID}`, "PATCH", 1);
  expect(state.mutationCalls[0].body).toEqual({ name: "別の管理名" });
});

test("fails closed when a mocked role change returns a stale version", async ({ page }) => {
  const state = await openOrganization(page, "role_conflict");
  const roleSelect = page.getByLabel("監査担当のロール");
  await roleSelect.selectOption("admin");
  await page.getByRole("button", { name: "監査担当をAdminに変更", exact: true }).click();

  await expect(page.getByRole("alert")).toContainText("他の管理者が先に変更しました");
  await expect(page.getByRole("button", { name: "最新情報を読み込む", exact: true })).toBeVisible();
  await expect(page.locator(`#member-details-${OTHER_MEMBER_ID}`)).toHaveText("Auditor · 有効 · v1");
  assertIdempotentMutation(state, `/api/auth/organizations/${ORGANIZATION_ID}/members/${OTHER_MEMBER_ID}/role`, "PATCH", 1);
  expect(state.mutationCalls[0].body).toEqual({ role: "admin" });
  expect(state.authenticationOptions[0]).toMatchObject({ operation: "human.organizations.member.role.update", organization_id: ORGANIZATION_ID });
  expect(state.authenticationVerifies).toHaveLength(1);
});

test("fails closed when a mocked member revoke is forbidden", async ({ page }) => {
  const state = await openOrganization(page, "member_forbidden");
  await page.getByRole("button", { name: "監査担当のアクセスを失効", exact: true }).click();
  await page.getByRole("button", { name: "失効を確定", exact: true }).click();

  await expect(page.getByRole("alert")).toContainText("この操作を実行する権限がありません");
  await expect(page.locator(`#member-details-${OTHER_MEMBER_ID}`)).toHaveText("Auditor · 有効 · v1");
  assertIdempotentMutation(state, `/api/auth/organizations/${ORGANIZATION_ID}/members/${OTHER_MEMBER_ID}/remove`, "POST", 1);
  expect(state.mutationCalls[0].body).toEqual({});
  expect(state.authenticationOptions[0]).toMatchObject({ operation: "human.organizations.member.remove", organization_id: ORGANIZATION_ID });
});

test("fails closed on a mocked stale invitation revoke and restores the pending row", async ({ page }) => {
  const state = await openOrganization(page, "invitation_stale");
  await page.getByRole("button", { name: "Viewer招待を取り消す", exact: true }).click();

  await expect(page.getByRole("alert")).toContainText("招待の状態が別の操作で変わったため");
  const row = page.locator("li.organization-list-row").filter({ hasText: "Viewer 招待" });
  await expect(row).toHaveAttribute("data-state", "pending");
  await expect(row).toContainText("有効 · 有効期限");
  assertIdempotentMutation(state, `/api/auth/organizations/${ORGANIZATION_ID}/invitations/${INVITATION_ID}/revoke`, "POST", 1);
  expect(state.mutationCalls[0].body).toEqual({});
});

test("fails closed on a mocked idempotency conflict without accepting optimistic revoke state", async ({ page }) => {
  const state = await openOrganization(page, "invitation_idempotency");
  await page.getByRole("button", { name: "Viewer招待を取り消す", exact: true }).click();

  await expect(page.getByRole("alert")).toContainText("招待の状態が別の操作で変わったため");
  await expect(page.getByRole("button", { name: "最新情報を読み込む", exact: true })).toBeVisible();
  const row = page.locator("li.organization-list-row").filter({ hasText: "Viewer 招待" });
  await expect(row).toHaveAttribute("data-state", "pending");
  await expect(row.getByRole("button", { name: "Viewer招待を取り消す", exact: true })).toBeVisible();
  assertIdempotentMutation(state, `/api/auth/organizations/${ORGANIZATION_ID}/invitations/${INVITATION_ID}/revoke`, "POST", 1);
  expect(state.mutationCalls[0].headers["idempotency-key"]).toBeTruthy();
});

test("fails closed when a mocked invitation replay is rejected", async ({ page }) => {
  const state = await openOrganization(page, "invitation_replay");
  const tokenInput = page.getByLabel("招待トークン");
  await tokenInput.fill(INVITATION_TOKEN);
  await page.getByRole("button", { name: "招待を受け入れる", exact: true }).click();

  await expect(page.getByRole("alert")).toContainText("招待の状態を確認できなかったため");
  await expect(page.getByRole("button", { name: "最新情報を読み込む", exact: true })).toBeVisible();
  await expect(tokenInput).toHaveValue("");
  await expect(page.getByRole("heading", { name: "招待トークン（一度だけ表示）" })).toHaveCount(0);
  expect(state.acceptedInvitationCalls).toBe(1);
  assertIdempotentMutation(state, "/api/auth/invitations/accept", "POST");
  expect(state.mutationCalls[0].body).toEqual({ one_time_token: INVITATION_TOKEN });
});

test("keeps the help modal keyboard reachable and returns focus to its launcher", async ({ page }) => {
  await openOrganization(page, "role_conflict");
  const launcher = page.getByRole("button", { name: "ヘルプを開く", exact: true });
  await launcher.focus();
  await launcher.press("Enter");

  const dialog = page.getByRole("dialog", { name: "AgentPassの見方", exact: true });
  await expect(dialog).toBeVisible();
  await expect(dialog).toHaveAttribute("aria-modal", "true");
  await expect(dialog).toHaveAttribute("aria-labelledby", "help-title");
  await expect(dialog).toHaveAttribute("aria-describedby", "help-copy");
  await expect(launcher).toHaveAttribute("aria-expanded", "true");
  await expect(page.getByRole("button", { name: "ヘルプを閉じる", exact: true })).toBeFocused();

  await page.keyboard.press("Tab");
  await expect(page.getByRole("button", { name: "監査ログを見る", exact: true })).toBeFocused();
  await page.keyboard.press("Tab");
  await expect(page.getByRole("button", { name: "ヘルプを閉じる", exact: true })).toBeFocused();
  await page.keyboard.press("Shift+Tab");
  await expect(page.getByRole("button", { name: "監査ログを見る", exact: true })).toBeFocused();

  await page.keyboard.press("Escape");
  await expect(dialog).toHaveCount(0);
  await expect(launcher).toHaveAttribute("aria-expanded", "false");
  await expect(launcher).toBeFocused();
});

test.afterEach(async ({ page }) => {
  const authenticator = activeAuthenticators.get(page);
  if (authenticator) await disposeVirtualAuthenticator(authenticator);
  await page.unrouteAll({ behavior: "ignoreErrors" });
});
