import { expect, test as base, type Page } from "@playwright/test";
import {
  ACTIVE_EXPIRES_AT,
  MEMBER_ID,
  ORGANIZATION_ID,
  OTHER_MEMBER_ID,
  consoleSummary,
  deploymentReadiness,
  json,
  session,
  type BrowserRole,
} from "./support/browser-fixtures";

type OrganizationVisibilityOptions = {
  role: BrowserRole;
};

const test = base.extend<OrganizationVisibilityOptions>({
  role: ["viewer", { option: true }],
});

const ORGANIZATION_NAME = "Visibility E2E Organization";
const REQUEST_ID = "69999999-9999-4999-8999-999999999999";
const DATE = "2026-08-12T00:00:00.000Z";

function organization() {
  return {
    organization_id: ORGANIZATION_ID,
    name: ORGANIZATION_NAME,
    version: 1,
    created_at: DATE,
    updated_at: DATE,
  };
}

function member(memberId: string, displayName: string, role: BrowserRole) {
  return {
    membership_id: `${memberId.slice(0, 8)}-aaaa-4aaa-8aaa-aaaaaaaaaaaa`,
    organization_id: ORGANIZATION_ID,
    member_id: memberId,
    display_name: displayName,
    role,
    status: "active",
    version: 1,
    created_at: DATE,
    updated_at: DATE,
  };
}

function invitations() {
  return [
    {
      invitation_id: "85555555-5555-4555-8555-555555555555",
      organization_id: ORGANIZATION_ID,
      role: "viewer",
      status: "pending",
      version: 1,
      created_at: DATE,
      expires_at: ACTIVE_EXPIRES_AT,
      accepted_at: null,
      accepted_member_id: null,
    },
    {
      invitation_id: "86666666-6666-4666-8666-666666666666",
      organization_id: ORGANIZATION_ID,
      role: "auditor",
      status: "pending",
      version: 1,
      created_at: DATE,
      expires_at: "2026-08-01T00:00:00.000Z",
      accepted_at: null,
      accepted_member_id: null,
    },
  ];
}

async function installOrganizationRoutes(page: Page, role: BrowserRole): Promise<void> {
  await page.route("**/api/auth/**", async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    if (url.pathname === "/api/auth/session") return json(route, session(role));
    if (url.pathname === "/api/auth/organizations" && request.method() === "GET") {
      return json(route, { request_id: REQUEST_ID, organizations: [organization()], next_cursor: null });
    }
    if (url.pathname === `/api/auth/organizations/${ORGANIZATION_ID}/members` && request.method() === "GET") {
      return json(route, {
        request_id: REQUEST_ID,
        members: [member(MEMBER_ID, "現在の利用者", role), member(OTHER_MEMBER_ID, "監査担当", "auditor")],
        next_cursor: null,
      });
    }
    if (url.pathname === `/api/auth/organizations/${ORGANIZATION_ID}/invitations` && request.method() === "GET") {
      return json(route, { request_id: REQUEST_ID, invitations: invitations(), next_cursor: null });
    }
    return json(route, { error: { code: "not_found", message: "Not found" } }, 404);
  });

  await page.route("**/api/console**", async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    if (request.method() === "GET" && url.searchParams.get("resource") === "summary") return json(route, consoleSummary());
    if (request.method() === "GET" && url.searchParams.get("resource") === "deployment-readiness") return json(route, deploymentReadiness());
    if (request.method() === "GET") return json(route, { capabilities: [], revocations: [], events: [] });
    return json(route, { error: { code: "forbidden", message: "Forbidden" } }, 403);
  });
}

async function openOrganizationAdmin(page: Page): Promise<void> {
  await page.goto("/");
  await expect(page.getByRole("heading", { name: /Agentの状態を、\s*確認できました。/u })).toBeVisible();
  await expect(page.getByRole("heading", { name: "E2E Mac" })).toBeVisible();
  await page.getByRole("button", { name: "Organizations", exact: true }).click();
  await expect(page.getByRole("heading", { name: "組織を安全に管理する" })).toBeVisible();
}

test.beforeEach(async ({ page, role }) => {
  await installOrganizationRoutes(page, role);
});

for (const role of ["owner", "admin", "auditor", "viewer"] as const) {
  test.describe(role, () => {
    test.use({ role });

    test(`renders the ${role} visibility boundary in a real browser`, async ({ page }) => {
      await openOrganizationAdmin(page);
      await expect(page.getByText(`現在の権限: ${role === "owner" ? "Owner" : role === "admin" ? "Admin" : role === "auditor" ? "Auditor" : "Viewer"}`, { exact: true })).toBeVisible();

      if (role === "viewer") {
        await expect(page.getByText("この組織では閲覧権限のみです。管理操作は表示されません。", { exact: true })).toBeVisible();
        await expect(page.getByRole("heading", { name: "メンバー", exact: true })).toHaveCount(0);
        await expect(page.getByRole("heading", { name: "招待", exact: true })).toHaveCount(0);
        await expect(page.getByText("組織名を変更", { exact: true })).toHaveCount(0);
        await expect(page.getByRole("heading", { name: "招待を作成", exact: true })).toHaveCount(0);
        return;
      }

      await expect(page.getByRole("heading", { name: "メンバー", exact: true })).toBeVisible();
      await expect(page.getByRole("heading", { name: "招待", exact: true })).toBeVisible();
      await expect(page.locator(`#member-details-${OTHER_MEMBER_ID}`)).toHaveText("Auditor · 有効 · v1");
      await expect(page.getByText("Viewer 招待", { exact: true })).toBeVisible();
      await expect(page.getByText("Auditor 招待", { exact: true })).toBeVisible();

      if (role === "auditor") {
        await expect(page.getByText("この組織では閲覧権限のみです。管理操作は表示されません。", { exact: true })).toBeVisible();
        await expect(page.getByText("組織名を変更", { exact: true })).toHaveCount(0);
        await expect(page.getByRole("heading", { name: "招待を作成", exact: true })).toHaveCount(0);
        await expect(page.getByRole("button", { name: /^監査担当を.*に変更$/ })).toHaveCount(0);
        await expect(page.getByRole("button", { name: "Viewer招待を取り消す", exact: true })).toHaveCount(0);
        return;
      }

      await expect(page.getByText("組織名を変更", { exact: true })).toBeVisible();
      await expect(page.getByRole("heading", { name: "招待を作成", exact: true })).toBeVisible();
      await expect(page.getByRole("button", { name: "招待を発行", exact: true })).toBeVisible();
      await expect(page.getByRole("button", { name: /^監査担当を.*に変更$/ })).toBeVisible();
      const roleSelect = page.getByLabel("監査担当のロール");
      const optionLabels = await roleSelect.locator("option").allTextContents();
      if (role === "owner") expect(optionLabels).toContain("Owner");
      if (role === "admin") expect(optionLabels).not.toContain("Owner");
    });
  });
}

test.afterEach(async ({ page }) => {
  await page.unrouteAll({ behavior: "ignoreErrors" });
});
