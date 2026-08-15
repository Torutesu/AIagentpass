import { expect, test, type Page, type Route } from "@playwright/test";
import {
  AUTHORIZATION_ID,
  CREDENTIAL_ID,
  CSRF_TOKEN,
  MEMBER_ID,
  ORGANIZATION_ID,
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
const INITIAL_NAME = "Response Loss Organization";
const RENAMED_NAME = "Authoritative Rename Organization";
const REQUEST_ID = "69999999-9999-4999-8999-999999999999";

type RouteState = Readonly<{ renameRequests: number; organizationName: string; organizationVersion: number; headers: Record<string, string>; invitationReissueRequests: number; invitationVersion: number; invitationExpiresAt: string; invitationHeaders: Record<string, string>; invitationResponseLossOnce: boolean; recentAuthOperations: string[] }>;

function organizationRecord(state: RouteState) {
  return {
    organization_id: ORGANIZATION_ID,
    name: state.organizationName,
    version: state.organizationVersion,
    created_at: DATE,
    updated_at: DATE,
  };
}

function memberRecord() {
  return {
    membership_id: "44444444-4444-4444-8444-444444444444",
    organization_id: ORGANIZATION_ID,
    member_id: MEMBER_ID,
    display_name: "現在の利用者",
    role: "owner",
    status: "active",
    version: 1,
    created_at: DATE,
    updated_at: DATE,
  };
}

function invitationRecord(state: RouteState) {
  return {
    invitation_id: "85555555-5555-4555-8555-555555555555",
    organization_id: ORGANIZATION_ID,
    role: "viewer",
    status: "pending",
    version: state.invitationVersion,
    created_at: DATE,
    expires_at: state.invitationExpiresAt,
    accepted_at: null,
    accepted_member_id: null,
  };
}

async function installRoutes(page: Page): Promise<RouteState> {
  const state: { renameRequests: number; organizationName: string; organizationVersion: number; headers: Record<string, string>; invitationReissueRequests: number; invitationVersion: number; invitationExpiresAt: string; invitationHeaders: Record<string, string>; invitationResponseLossOnce: boolean; recentAuthOperations: string[] } = {
    renameRequests: 0,
    organizationName: INITIAL_NAME,
    organizationVersion: 1,
    headers: {},
    invitationReissueRequests: 0,
    invitationVersion: 1,
    invitationExpiresAt: FUTURE,
    invitationHeaders: {},
    invitationResponseLossOnce: true,
    recentAuthOperations: [],
  };
  await page.route("**/api/auth/**", async (route: Route) => {
    const request = route.request();
    const url = new URL(request.url());
    if (url.pathname === "/api/auth/session" || url.pathname === "/api/auth/session/resume") return json(route, session("owner"));
    if (url.pathname === "/api/auth/webauthn/options") {
      state.recentAuthOperations.push(String(parseRequestBody(route).operation ?? ""));
      return json(route, { challenge_id: "57777777-7777-4777-8777-777777777777", options: { challenge: "Q0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NA", rpId: "localhost", userVerification: "required", allowCredentials: [{ id: CREDENTIAL_ID, type: "public-key", transports: ["internal"] }] } });
    }
    if (url.pathname === "/api/auth/webauthn/verify") {
      state.recentAuthOperations.push(String(parseRequestBody(route).operation ?? ""));
      return json(route, { authorization_id: AUTHORIZATION_ID });
    }
    if (url.pathname === `/api/auth/organizations/${ORGANIZATION_ID}` && request.method() === "PATCH") {
      state.renameRequests += 1;
      state.headers = request.headers();
      state.organizationName = String(parseRequestBody(route).name);
      state.organizationVersion = 2;
      await route.abort("connectionreset");
      return;
    }
    if (url.pathname === `/api/auth/organizations/${ORGANIZATION_ID}/invitations` && request.method() === "POST") {
      state.invitationReissueRequests += 1;
      state.invitationHeaders = request.headers();
      state.invitationVersion = 2;
      state.invitationExpiresAt = String(parseRequestBody(route).expires_at);
      if (state.invitationResponseLossOnce) {
        state.invitationResponseLossOnce = false;
        await route.abort("connectionreset");
        return;
      }
      return json(route, { request_id: REQUEST_ID, invitation: invitationRecord(state), one_time_token: "r".repeat(64) }, 201);
    }
    if (url.pathname === "/api/auth/organizations" && request.method() === "GET") return json(route, { request_id: REQUEST_ID, organizations: [organizationRecord(state)], next_cursor: null });
    if (url.pathname === `/api/auth/organizations/${ORGANIZATION_ID}/members` && request.method() === "GET") return json(route, { request_id: REQUEST_ID, members: [memberRecord()], next_cursor: null });
    if (url.pathname === `/api/auth/organizations/${ORGANIZATION_ID}/invitations` && request.method() === "GET") return json(route, { request_id: REQUEST_ID, invitations: [invitationRecord(state)], next_cursor: null });
    return json(route, { error: { code: "not_found", message: "Not found" } }, 404);
  });
  await page.route("**/api/console**", async (route) => json(route, consoleSummary()));
  return state;
}

test("reconciles a committed organization rename after the mutation response is lost without resending", async ({ page }) => {
  const state = await installRoutes(page);
  await page.goto("/");
  await expect(page.getByRole("heading", { name: /Agentの状態を、\s*確認できました。/u })).toBeVisible();
  await page.getByRole("button", { name: "Organizations", exact: true }).click();
  await expect(page.getByRole("heading", { name: "組織を安全に管理する" })).toBeVisible();

  await page.getByLabel("組織名を変更").fill(RENAMED_NAME);
  await page.getByRole("button", { name: "名前を変更", exact: true }).click();
  await expect(page.getByText(`${RENAMED_NAME} · v2`, { exact: true })).toBeVisible();
  await expect(page.getByRole("alert")).toContainText("権威状態を再取得しました");
  await expect(page.getByRole("button", { name: "最新の状態を再確認", exact: true })).toBeVisible();

  expect(state.renameRequests).toBe(1);
  expect(state.headers["agentpass-csrf"]).toBe(CSRF_TOKEN);
  expect(state.headers["idempotency-key"]).toMatch(/^[A-Za-z0-9._~-]{8,255}$/u);
  expect(state.headers["if-match"]).toBe('"1"');
  expect(JSON.stringify(await browserStorageSnapshot(page))).not.toContain(CSRF_TOKEN);
  expect(page.url()).not.toContain(CSRF_TOKEN);
});

test("reconciles an invitation reissue after response loss without resending or exposing a token", async ({ page }) => {
  const state = await installRoutes(page);
  const authenticator = await installVirtualAuthenticator(page);
  try {
    await page.goto("/");
    await expect(page.getByRole("heading", { name: /Agentの状態を、\s*確認できました。/u })).toBeVisible();
    await page.getByRole("button", { name: "Organizations", exact: true }).click();
    await expect(page.getByRole("heading", { name: "組織を安全に管理する" })).toBeVisible();

    await page.getByRole("button", { name: "Viewer招待を再発行", exact: true }).click();
    await page.getByLabel("再発行後の有効期限").fill("2099-01-03T12:00");
    await page.getByRole("button", { name: "再発行を確定", exact: true }).click();
    await expect(page.getByRole("alert")).toContainText("権威状態を再取得しました");
    await expect(page.getByText(/有効 · 有効期限 .* · v2/u)).toBeVisible();
    await expect(page.getByText("r".repeat(64), { exact: true })).toHaveCount(0);
    expect(state.invitationReissueRequests).toBe(1);
    expect(state.invitationHeaders["if-match"]).toBe('"1"');
    expect(state.invitationHeaders["agentpass-recent-auth"]).toBe(AUTHORIZATION_ID);
    expect(state.invitationHeaders["idempotency-key"]).toMatch(/^[A-Za-z0-9._~-]{8,255}$/u);
    expect(state.recentAuthOperations).toEqual(["human.organizations.invitation.reissue", "human.organizations.invitation.reissue"]);
    expect(JSON.stringify(await browserStorageSnapshot(page))).not.toContain("r".repeat(64));
  } finally {
    await disposeVirtualAuthenticator(authenticator);
  }
});
