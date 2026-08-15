import { expect, test, type Page, type Route } from "@playwright/test";
import {
  ORGANIZATION_ID,
  MEMBER_ID,
  OTHER_MEMBER_ID,
  browserStorageSnapshot,
  consoleSummary,
  json,
  session,
} from "./support/browser-fixtures";

const DATE = "2026-08-12T00:00:00.000Z";
const FUTURE = "2099-01-02T12:00:00.000Z";
const SENTINEL = "server-only-secret-should-never-render";

type RouteState = {
  renameRequests: number;
  failRename: boolean;
};

function organization() {
  return {
    organization_id: ORGANIZATION_ID,
    name: "Accessibility E2E Organization",
    version: 1,
    created_at: DATE,
    updated_at: DATE,
  };
}

function member(memberId: string, displayName: string, role: "owner" | "admin" | "auditor" | "viewer") {
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

function invitation() {
  return {
    invitation_id: "85555555-5555-4555-8555-555555555555",
    organization_id: ORGANIZATION_ID,
    role: "viewer",
    status: "pending",
    version: 1,
    created_at: DATE,
    expires_at: FUTURE,
    accepted_at: null,
    accepted_member_id: null,
  };
}

async function installRoutes(page: Page): Promise<RouteState> {
  const state: RouteState = { renameRequests: 0, failRename: true };

  await page.route("**/api/auth/**", async (route: Route) => {
    const request = route.request();
    const url = new URL(request.url());
    if (url.pathname === "/api/auth/session" || url.pathname === "/api/auth/session/resume") return json(route, session("owner"));
    if (url.pathname === "/api/auth/organizations" && request.method() === "GET") {
      return json(route, { request_id: "a1111111-1111-4111-8111-111111111111", organizations: [organization()], next_cursor: null });
    }
    if (url.pathname === `/api/auth/organizations/${ORGANIZATION_ID}` && request.method() === "GET") return json(route, { request_id: "a1111111-1111-4111-8111-111111111111", organization: organization() });
    if (url.pathname === `/api/auth/organizations/${ORGANIZATION_ID}` && request.method() === "PATCH") {
      state.renameRequests += 1;
      if (state.failRename) return json(route, { error: { code: "upstream_failure", message: SENTINEL } }, 503);
      return json(route, { request_id: "a1111111-1111-4111-8111-111111111111", organization: organization() });
    }
    if (url.pathname === `/api/auth/organizations/${ORGANIZATION_ID}/members` && request.method() === "GET") {
      return json(route, {
        request_id: "a1111111-1111-4111-8111-111111111111",
        members: [member(MEMBER_ID, "現在の利用者", "owner"), member(OTHER_MEMBER_ID, "監査担当", "auditor")],
        next_cursor: null,
      });
    }
    if (url.pathname === `/api/auth/organizations/${ORGANIZATION_ID}/invitations` && request.method() === "GET") {
      return json(route, { request_id: "a1111111-1111-4111-8111-111111111111", invitations: [invitation()], next_cursor: null });
    }
    return json(route, { error: { code: "not_found", message: "Not found" } }, 404);
  });

  await page.route("**/api/console**", async (route: Route) => {
    const request = route.request();
    const url = new URL(request.url());
    if (request.method() === "GET" && url.searchParams.get("resource") === "summary") return json(route, consoleSummary());
    if (request.method() === "GET") return json(route, { capabilities: [], revocations: [], events: [] });
    return json(route, { error: { code: "forbidden", message: "Forbidden" } }, 403);
  });

  return state;
}

async function openConsole(page: Page): Promise<void> {
  await page.goto("/");
  await expect(page.getByRole("heading", { name: /Agentの状態を、\s*確認できました。/u })).toBeVisible();
}

async function openOrganizations(page: Page): Promise<void> {
  await openConsole(page);
  await page.getByRole("button", { name: "Organizations", exact: true }).click();
  await expect(page.getByRole("heading", { name: "組織を安全に管理する" })).toBeVisible();
}

test("help dialog is keyboard operable and restores focus to its trigger", async ({ page }) => {
  await openConsole(page);
  const trigger = page.getByRole("button", { name: "ヘルプを開く", exact: true });
  await trigger.click();

  const dialog = page.getByRole("dialog", { name: "AgentPassの見方" });
  await expect(dialog).toHaveAttribute("aria-modal", "true");
  await expect(dialog.getByRole("heading", { name: "AgentPassの見方" })).toBeVisible();
  await expect(dialog.getByRole("button", { name: "ヘルプを閉じる" })).toBeFocused();

  await dialog.getByRole("button", { name: "監査ログを見る" }).focus();
  await page.keyboard.press("Tab");
  await expect(dialog.getByRole("button", { name: "ヘルプを閉じる" })).toBeFocused();
  await page.keyboard.press("Escape");
  await expect(dialog).toBeHidden();
  await expect(trigger).toBeFocused();
});

test("workspace chooser is an accessible dialog and Escape restores focus", async ({ page }) => {
  await openConsole(page);
  const trigger = page.getByRole("button", { name: /ワークスペースを選択$/u });
  await trigger.click();

  const dialog = page.getByRole("dialog", { name: "組織を選択" });
  await expect(dialog).toHaveAttribute("aria-modal", "true");
  await expect(dialog.getByRole("listbox", { name: "利用可能な組織" })).toBeVisible();
  await expect(dialog.locator("button").first()).toBeFocused();

  await page.keyboard.press("Escape");
  await expect(dialog).toBeHidden();
  await expect(trigger).toBeFocused();
});

test("mobile navigation closes with Escape and restores focus", async ({ page }) => {
  await page.setViewportSize({ width: 640, height: 900 });
  await openConsole(page);
  const trigger = page.getByRole("button", { name: "メニューを開く", exact: true });
  await trigger.click();

  const sidebar = page.locator("aside.sidebar");
  await expect(sidebar).toHaveClass(/mobile-open/u);
  await expect(page.getByRole("button", { name: "メニューを閉じる", exact: true })).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(sidebar).not.toHaveClass(/mobile-open/u);
  await expect(trigger).toBeFocused();
});

test("organization failure is announced without leaking server text and offers non-CLI recovery", async ({ page }) => {
  const state = await installRoutes(page);
  const consoleMessages: string[] = [];
  page.on("console", (message) => consoleMessages.push(message.text()));
  await openOrganizations(page);

  await page.getByLabel("組織名を変更").fill("変更後の組織名");
  await page.getByRole("button", { name: "名前を変更", exact: true }).click();

  const alert = page.getByRole("alert").last();
  await expect(alert).toHaveAttribute("aria-live", "assertive");
  await expect(alert).not.toContainText(SENTINEL);
  await expect(alert.getByRole("button")).toHaveCount(1);
  await expect(alert).toContainText(/再|確認|読み込|retry|refresh/iu);
  expect(state.renameRequests).toBe(1);

  const storage = await browserStorageSnapshot(page);
  const browserText = await page.locator("body").innerText();
  expect(browserText).not.toContain(SENTINEL);
  expect(JSON.stringify(storage)).not.toContain(SENTINEL);
  expect(page.url()).not.toContain(SENTINEL);
  expect(consoleMessages.join("\n")).not.toContain(SENTINEL);
});

test("Console reflows at a 200 percent effective zoom without horizontal overflow", async ({ page }) => {
  await page.setViewportSize({ width: 640, height: 900 });
  await openConsole(page);
  await page.evaluate(() => {
    document.documentElement.style.zoom = "2";
  });

  const metrics = await page.evaluate(() => ({
    clientWidth: document.documentElement.clientWidth,
    scrollWidth: Math.max(document.documentElement.scrollWidth, document.body.scrollWidth),
    headingVisible: Boolean(document.querySelector("h1")),
  }));
  expect(metrics.headingVisible).toBe(true);
  expect(metrics.scrollWidth).toBeLessThanOrEqual(metrics.clientWidth + 1);
});

test("reduced motion disables shell scrolling and transition motion", async ({ page }) => {
  await page.emulateMedia({ reducedMotion: "reduce" });
  await openConsole(page);

  const styles = await page.evaluate(() => {
    const sidebar = document.querySelector(".sidebar");
    const html = document.documentElement;
    return {
      scrollBehavior: getComputedStyle(html).scrollBehavior,
      transitionDuration: sidebar ? getComputedStyle(sidebar).transitionDuration : "",
    };
  });
  expect(styles.scrollBehavior).toBe("auto");
  expect(Number.parseFloat(styles.transitionDuration)).toBeLessThanOrEqual(0.01);
});
