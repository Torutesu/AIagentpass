import { expect, test, type Page, type Route } from "@playwright/test";
import {
  CSRF_TOKEN,
  MEMBER_ID,
  ORGANIZATION_ID,
  browserStorageSnapshot,
  consoleSummary,
  json,
  parseRequestBody,
  session,
} from "./support/browser-fixtures";

const DATE = "2026-08-12T00:00:00.000Z";
const ACCEPTED_AT = "2026-08-12T00:45:00.000Z";
const FUTURE = "2099-01-02T12:00:00.000Z";
const INVITATION_TOKEN = "t".repeat(64);
const ACCEPTED_ORGANIZATION_ID = "45555555-5555-4555-8555-555555555555";
const ACCEPTED_ORGANIZATION_NAME = "Accepted Agent Organization";
const INVITATION_ID = "46666666-6666-4666-8666-666666666666";
const ACCEPTED_MEMBERSHIP_ID = "47777777-7777-4777-8777-777777777777";
const ACCEPTED_MEMBER_ID = MEMBER_ID;
const REQUEST_ID = "48888888-8888-4888-8888-888888888888";

type AcceptanceRequest = Readonly<{
  method: string;
  path: string;
  body: Record<string, unknown>;
  headers: Record<string, string>;
}>;

type RouteState = {
  accepted: boolean;
  acceptanceRequests: AcceptanceRequest[];
};

function currentOrganization() {
  return {
    organization_id: ORGANIZATION_ID,
    name: "Current Agent Organization",
    version: 1,
    created_at: DATE,
    updated_at: DATE,
  };
}

function acceptedOrganization() {
  return {
    organization_id: ACCEPTED_ORGANIZATION_ID,
    name: ACCEPTED_ORGANIZATION_NAME,
    version: 1,
    created_at: DATE,
    updated_at: DATE,
  };
}

function acceptedInvitation() {
  return {
    invitation_id: INVITATION_ID,
    organization_id: ACCEPTED_ORGANIZATION_ID,
    role: "viewer",
    status: "accepted",
    version: 2,
    created_at: DATE,
    expires_at: FUTURE,
    accepted_at: ACCEPTED_AT,
    accepted_member_id: ACCEPTED_MEMBER_ID,
  };
}

function acceptedMember() {
  return {
    membership_id: ACCEPTED_MEMBERSHIP_ID,
    organization_id: ACCEPTED_ORGANIZATION_ID,
    member_id: ACCEPTED_MEMBER_ID,
    display_name: "招待を受け入れた利用者",
    role: "viewer",
    status: "active",
    version: 1,
    created_at: ACCEPTED_AT,
    updated_at: ACCEPTED_AT,
  };
}

function requestRecord(route: Route): AcceptanceRequest {
  return {
    method: route.request().method(),
    path: new URL(route.request().url()).pathname,
    body: parseRequestBody(route),
    headers: route.request().headers(),
  };
}

function assertAcceptanceRequest(request: AcceptanceRequest): void {
  expect(request).toMatchObject({
    method: "POST",
    path: "/api/auth/invitations/accept",
    body: { one_time_token: INVITATION_TOKEN },
  });
  expect(request.body).toEqual({ one_time_token: INVITATION_TOKEN });
  expect(request.headers).toMatchObject({
    accept: "application/json",
    "cache-control": "no-store",
    "content-type": "application/json",
    pragma: "no-cache",
    "agentpass-csrf": CSRF_TOKEN,
  });
  expect(request.headers["idempotency-key"]).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu);
  expect(request.headers["if-match"]).toBeUndefined();
  expect(request.headers["agentpass-recent-auth"]).toBeUndefined();
  expect(request.headers.authorization).toBeUndefined();
}

function assertNoTokenInBrowser(page: Page, consoleMessages: readonly string[]): Promise<void> {
  return (async () => {
    const storage = await browserStorageSnapshot(page);
    expect(page.url()).not.toContain(INVITATION_TOKEN);
    expect(JSON.stringify(storage)).not.toContain(INVITATION_TOKEN);
    expect(consoleMessages.join("\n")).not.toContain(INVITATION_TOKEN);
  })();
}

async function installRoutes(page: Page, responseLost: boolean): Promise<RouteState> {
  const state: RouteState = { accepted: false, acceptanceRequests: [] };
  await page.route("**/api/auth/**", async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    if (url.pathname === "/api/auth/session" || url.pathname === "/api/auth/session/resume") return json(route, session("viewer"));
    if (url.pathname === "/api/auth/organizations" && request.method() === "GET") {
      return json(route, {
        request_id: REQUEST_ID,
        organizations: state.accepted ? [currentOrganization(), acceptedOrganization()] : [currentOrganization()],
        next_cursor: null,
      });
    }
    if (url.pathname === `/api/auth/organizations/${ORGANIZATION_ID}/members` && request.method() === "GET") {
      return json(route, { request_id: REQUEST_ID, members: [], next_cursor: null });
    }
    if (url.pathname === `/api/auth/organizations/${ORGANIZATION_ID}/invitations` && request.method() === "GET") {
      return json(route, { request_id: REQUEST_ID, invitations: [], next_cursor: null });
    }
    if (url.pathname === "/api/auth/invitations/accept" && request.method() === "POST") {
      state.accepted = true;
      state.acceptanceRequests.push(requestRecord(route));
      const response = {
        request_id: REQUEST_ID,
        invitation: acceptedInvitation(),
        member: acceptedMember(),
      };
      expect(Object.keys(response).sort()).toEqual(["invitation", "member", "request_id"]);
      expect(JSON.stringify(response)).not.toContain(INVITATION_TOKEN);
      if (responseLost) {
        await route.abort("connectionreset");
        return;
      }
      return json(route, response, 201);
    }
    return json(route, { error: { code: "not_found", message: "Not found" } }, 404);
  });
  await page.route("**/api/console**", async (route) => json(route, consoleSummary()));
  return state;
}

async function openOrganizationPanel(page: Page): Promise<void> {
  await page.goto("/");
  await expect(page.getByRole("heading", { name: /Agentの状態を、\s*確認できました。/u })).toBeVisible();
  await page.getByRole("button", { name: "Organizations", exact: true }).click();
  await expect(page.getByRole("heading", { name: "組織を安全に管理する" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "招待を受け入れる" })).toBeVisible();
}

async function submitAcceptance(page: Page): Promise<void> {
  await page.getByLabel("招待トークン").fill(INVITATION_TOKEN);
  await page.getByRole("button", { name: "招待を受け入れる", exact: true }).click();
}

async function assertAcceptedOrganizationVisible(page: Page): Promise<void> {
  await expect(page.getByLabel("組織を選択")).toContainText(ACCEPTED_ORGANIZATION_NAME);
}

test("accepts an invitation in OrganizationPanel with the exact contract and exposes the accepted organization", async ({ page }) => {
  const consoleMessages: string[] = [];
  page.on("console", (message) => consoleMessages.push(message.text()));
  const state = await installRoutes(page, false);

  await openOrganizationPanel(page);
  await submitAcceptance(page);
  await assertAcceptedOrganizationVisible(page);

  expect(state.acceptanceRequests).toHaveLength(1);
  assertAcceptanceRequest(state.acceptanceRequests[0]);
  await expect(page.getByLabel("招待トークン")).toHaveValue("");
  await assertNoTokenInBrowser(page, consoleMessages);
});

test("reconciles a lost invitation acceptance response without sending a second POST", async ({ page }) => {
  const consoleMessages: string[] = [];
  page.on("console", (message) => consoleMessages.push(message.text()));
  const state = await installRoutes(page, true);

  await openOrganizationPanel(page);
  await submitAcceptance(page);
  await assertAcceptedOrganizationVisible(page);
  await expect(page.getByRole("alert")).toContainText("応答を確認できなかったため、権威状態を再取得しました");
  await expect(page.getByRole("button", { name: "最新の状態を再確認", exact: true })).toBeVisible();

  expect(state.acceptanceRequests).toHaveLength(1);
  assertAcceptanceRequest(state.acceptanceRequests[0]);
  await assertNoTokenInBrowser(page, consoleMessages);
});
