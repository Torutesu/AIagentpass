import { expect, test as base, type Page } from "@playwright/test";
import {
  ORGANIZATION_ID,
  consoleSummary,
  browserStorageSnapshot,
  json,
  parseRequestBody,
  session,
  type BrowserRole,
} from "./support/browser-fixtures";

type RecoveryE2EOptions = { role: BrowserRole };
const test = base.extend<RecoveryE2EOptions>({ role: ["owner", { option: true }] });

const REQUEST_ID = "69999999-9999-4999-8999-999999999999";
const ONE_TIME_EXCHANGE = "one-time-exchange-value-that-is-never-stored-123456789";
const DATE = "2099-01-01T00:00:00.000Z";

function recovery(state: string) {
  return {
    schema_version: 1,
    kind: "threshold-owner-recovery",
    request_id: REQUEST_ID,
    organization_id: ORGANIZATION_ID,
    subject_member_id: "33333333-3333-4333-8333-333333333333",
    state,
    threshold: 2,
    approved_owner_count: 0,
    approved_at: null,
    delay_until: state === "delayed" ? DATE : null,
    session_issued_at: null,
    credential_enrolled_at: null,
    activated_at: null,
    expires_at: DATE,
    terminal_reason: null,
    version: 1,
    created_at: DATE,
    updated_at: DATE,
  };
}

async function installRecoveryRoutes(page: Page, role: BrowserRole) {
  const bodies: Record<string, unknown>[] = [];
  await page.route("**/api/auth/**", async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    if (url.pathname === "/api/auth/session") return json(route, session(role));
    if (url.pathname === "/api/auth/organizations/" + ORGANIZATION_ID + "/recovery-requests" && request.method() === "POST") {
      bodies.push(parseRequestBody(route));
      return json(route, { request_id: REQUEST_ID, recovery: recovery("pending"), eligibility: { eligible_owner_count: 2, threshold: 2, recoverable: true } }, 201);
    }
    if (url.pathname.endsWith(`/recovery-requests/${REQUEST_ID}`) && request.method() === "GET") {
      return json(route, { request_id: REQUEST_ID, recovery: recovery("delayed"), exchange_value: ONE_TIME_EXCHANGE, eligibility: { eligible_owner_count: 2, threshold: 2, recoverable: true } });
    }
    if (url.pathname === "/api/auth/recovery/exchange" && request.method() === "POST") {
      bodies.push(parseRequestBody(route));
      return json(route, { error: { code: "recovery_exchange_replay", message: "Replay rejected" } }, 409);
    }
    return json(route, { error: { code: "not_found", message: "Not found" } }, 404);
  });
  await page.route("**/api/console**", async (route) => json(route, consoleSummary()));
  return bodies;
}

async function openRecovery(page: Page) {
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Agentは、" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "E2E Mac" })).toBeVisible();
  await page.getByRole("button", { name: "アカウント復旧", exact: true }).click();
}

for (const role of ["owner", "admin", "auditor", "viewer"] as const) {
  test.describe(role, () => {
    test.use({ role });

    test(`enforces ${role} recovery visibility in a real browser`, async ({ page }) => {
      await installRecoveryRoutes(page, role);
      await openRecovery(page);
      if (role === "owner") {
        await expect(page.getByRole("heading", { name: "アカウント復旧を準備する" })).toBeVisible();
        await expect(page.getByRole("button", { name: "復旧リクエストを作成" })).toBeVisible();
      } else {
        await expect(page.getByRole("heading", { name: "アカウント復旧を準備する" })).toHaveCount(0);
        await expect(page.getByRole("button", { name: "復旧リクエストを作成" })).toHaveCount(0);
      }
    });
  });
}

test("keeps one-time exchange material out of storage and handles replay in a real browser", async ({ page }) => {
  const bodies = await installRecoveryRoutes(page, "owner");
  await openRecovery(page);
  await page.getByRole("button", { name: "復旧リクエストを作成" }).click();
  await expect(page.getByRole("textbox", { name: "リクエストID" })).toHaveValue(REQUEST_ID);
  await page.getByRole("button", { name: "最新状態を確認" }).click();
  await expect(page.getByTestId("recovery-exchange-value")).toHaveText(ONE_TIME_EXCHANGE);

  expect((await browserStorageSnapshot(page)).local).toEqual({});
  expect((await browserStorageSnapshot(page)).session).toEqual({});
  expect(page.url()).not.toContain(ONE_TIME_EXCHANGE);

  await page.getByRole("button", { name: "一度だけ表示された交換値を使う" }).click();
  await expect(page.getByRole("alert")).toContainText("すでに使われています");
  await expect(page.getByTestId("recovery-exchange-value")).toHaveCount(0);
  expect((await browserStorageSnapshot(page)).local).toEqual({});
  expect((await browserStorageSnapshot(page)).session).toEqual({});
  expect(bodies).toContainEqual({});
  expect(bodies).toContainEqual({ exchange: ONE_TIME_EXCHANGE });
});
