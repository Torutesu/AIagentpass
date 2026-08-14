import { createHash } from "node:crypto";
import { expect, test as base, type Page, type Route } from "@playwright/test";
import {
  AUTHORIZATION_ID,
  CHALLENGE,
  CREDENTIAL_ID,
  ORGANIZATION_ID,
  consoleSummary,
  disposeVirtualAuthenticator,
  installVirtualAuthenticator,
  json,
  parseRequestBody,
  session,
  type BrowserRole,
  type VirtualAuthenticator,
} from "./support/browser-fixtures";

type RecoveryDeadLetterE2EOptions = { role: BrowserRole };
const test = base.extend<RecoveryDeadLetterE2EOptions>({ role: ["owner", { option: true }] });

const EVENT_ID = "44444444-4444-4444-8444-444444444444";
const SECOND_EVENT_ID = "45555555-5555-4555-8555-555555555555";
const REQUEST_ID = "46666666-6666-4666-8666-666666666666";
const SUBJECT_MEMBER_ID = "47777777-7777-4777-8777-777777777777";
const DATE = "2099-01-01T00:00:00.000Z";

type DeadLetterOverrides = Partial<{
  event_id: string;
  management_version: number;
  status: "dead_letter";
  suppression_reason: string | null;
}>;

type OperationState = {
  listCalls: number;
  redriveCalls: Array<{ body: Record<string, unknown>; headers: Record<string, string> }>;
  suppressCalls: Array<{ body: Record<string, unknown>; headers: Record<string, string> }>;
  authenticationOptions: Array<Record<string, unknown>>;
  authenticationVerifyBodies: Array<Record<string, unknown>>;
  staleVersionTriggered: boolean;
};

function deferred(): { promise: Promise<void>; resolve: () => void } {
  let resolvePromise!: () => void;
  const promise = new Promise<void>((resolve) => { resolvePromise = resolve; });
  return { promise, resolve: resolvePromise };
}

function deadLetter(overrides: DeadLetterOverrides = {}) {
  return {
    organization_id: ORGANIZATION_ID,
    event_id: overrides.event_id ?? EVENT_ID,
    request_id: REQUEST_ID,
    subject_member_id: SUBJECT_MEMBER_ID,
    event_type: "recovery.session.issued",
    status: overrides.status ?? "dead_letter",
    attempts: 5,
    total_attempts: 7,
    management_version: overrides.management_version ?? 7,
    redrive_count: 1,
    last_error_code: "provider_timeout",
    created_at: DATE,
    updated_at: DATE,
    suppressed_at: null,
    suppression_reason: overrides.suppression_reason ?? null,
  };
}

function mutation(eventId: string, status: "pending" | "suppressed", managementVersion: number, reason: string | null = null) {
  return {
    dead_letter: {
      organization_id: ORGANIZATION_ID,
      event_id: eventId,
      status,
      attempts: status === "pending" ? 0 : 5,
      total_attempts: 7,
      management_version: managementVersion,
      redrive_count: status === "pending" ? 2 : 1,
      suppressed_at: status === "suppressed" ? DATE : null,
      suppression_reason: status === "suppressed" ? reason : null,
    },
  };
}

function authenticationOptions() {
  return {
    challenge: CHALLENGE,
    rpId: "localhost",
    userVerification: "required",
    timeout: 1_000,
    allowCredentials: [{ id: CREDENTIAL_ID, type: "public-key", transports: ["internal"] }],
  };
}

function resourceContextHash(eventId: string, action: "redrive" | "suppress", expectedManagementVersion: number): string {
  const canonical = JSON.stringify({
    action,
    event_id: eventId,
    expected_management_version: expectedManagementVersion,
    organization_id: ORGANIZATION_ID,
    version: 1,
  });
  return createHash("sha256").update(canonical, "utf8").digest("hex");
}

function webAuthnEvidence(route: Route): Record<string, unknown> {
  const body = parseRequestBody(route);
  return {
    organization_id: body.organization_id,
    operation: body.operation,
    context_hash: body.context_hash,
    challenge_id: body.challenge_id,
    has_credential: Boolean(body.credential),
  };
}

function recoverySession(role: BrowserRole) {
  const current = session(role);
  const deadLetterSession = Object.fromEntries(Object.entries(current.session).filter(([key]) => key !== "version"));
  return { ...current, session: deadLetterSession };
}

function headers(route: Route): Record<string, string> {
  return route.request().headers();
}

async function installRoutes(page: Page, role: BrowserRole, options: Readonly<{ list: "items" | "empty"; delayFirstList?: boolean }> = { list: "items" }) {
  const state: OperationState = {
    listCalls: 0,
    redriveCalls: [],
    suppressCalls: [],
    authenticationOptions: [],
    authenticationVerifyBodies: [],
    staleVersionTriggered: false,
  };
  const loading = deferred();

  await page.route("**/api/auth/**", async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    if (url.pathname === "/api/auth/session") return json(route, recoverySession(role));

    if (url.pathname.endsWith("/recovery-outbox/dead-letters") && request.method() === "GET") {
      state.listCalls += 1;
      if (options.delayFirstList && state.listCalls === 1) await loading.promise;
      if (options.list === "empty") return json(route, { dead_letters: [], next_cursor: null });
      const refreshed = state.staleVersionTriggered;
      return json(route, {
        dead_letters: [
          deadLetter({ management_version: refreshed ? 8 : 7 }),
          deadLetter({ event_id: SECOND_EVENT_ID, management_version: 4 }),
        ],
        next_cursor: null,
      });
    }

    if (url.pathname === "/api/auth/webauthn/options" && request.method() === "POST") {
      state.authenticationOptions.push(parseRequestBody(route));
      return json(route, { challenge_id: "48888888-8888-4888-8888-888888888888", options: authenticationOptions() });
    }

    if (url.pathname === "/api/auth/webauthn/verify" && request.method() === "POST") {
      state.authenticationVerifyBodies.push(webAuthnEvidence(route));
      return json(route, { authorization_id: AUTHORIZATION_ID });
    }

    if (url.pathname.endsWith(`/dead-letters/${EVENT_ID}/redrive`) && request.method() === "POST") {
      state.redriveCalls.push({ body: parseRequestBody(route), headers: headers(route) });
      if (!state.staleVersionTriggered) {
        state.staleVersionTriggered = true;
        return json(route, { error: { code: "owner_recovery_outbox_management_version_conflict", message: "stale version" } }, 409);
      }
      return json(route, mutation(EVENT_ID, "pending", 9));
    }

    if (url.pathname.endsWith(`/dead-letters/${SECOND_EVENT_ID}/suppress`) && request.method() === "POST") {
      state.suppressCalls.push({ body: parseRequestBody(route), headers: headers(route) });
      return json(route, mutation(SECOND_EVENT_ID, "suppressed", 5, "manual review"));
    }

    return json(route, { error: { code: "not_found", message: "Not found" } }, 404);
  });
  await page.route("**/api/console**", async (route) => json(route, consoleSummary()));
  return { state, releaseLoading: loading.resolve };
}

async function openRecovery(page: Page): Promise<void> {
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Agentは、" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "E2E Mac" })).toBeVisible();
  await page.getByRole("button", { name: "アカウント復旧", exact: true }).click();
}

function deadLetterList(page: Page) {
  return page.getByRole("list", { name: "復旧通知dead-letter一覧" });
}

function deadLetterRow(page: Page, eventId: string) {
  return deadLetterList(page).locator("li.row-list-item").filter({ hasText: eventId });
}

for (const role of ["owner", "admin"] as const) {
  test.describe(`${role} recovery dead-letter states`, () => {
    test.use({ role });

    test("shows loading and then the organization-scoped list", async ({ page }) => {
      const routes = await installRoutes(page, role, { list: "items", delayFirstList: true });
      await openRecovery(page);
      await expect(page.locator('section[data-state="loading"]')).toBeVisible();
      routes.releaseLoading();
      await expect(page.locator('section[data-state="list"]')).toBeVisible();
      await expect(deadLetterRow(page, EVENT_ID)).toContainText("管理v: 7");
      await expect(deadLetterRow(page, SECOND_EVENT_ID)).toContainText("管理v: 4");
    });

    test("shows the empty state after a successful empty list response", async ({ page }) => {
      const routes = await installRoutes(page, role, { list: "empty", delayFirstList: true });
      await openRecovery(page);
      await expect(page.locator('section[data-state="loading"]')).toBeVisible();
      routes.releaseLoading();
      await expect(page.locator('section[data-state="empty"]')).toContainText("失敗通知はありません");
    });
  });
}

test.describe("virtual WebAuthn recovery dead-letter operations", () => {
  const authenticators = new WeakMap<Page, VirtualAuthenticator>();

  for (const role of ["owner", "admin"] as const) {
    test.describe(role, () => {
      test.use({ role });

      test("redrives and suppresses with authoritative versions, refreshes stale state, and supports keyboard confirmation", async ({ page }) => {
        authenticators.set(page, await installVirtualAuthenticator(page));
        const routes = await installRoutes(page, role, { list: "items" });
        await openRecovery(page);
        await expect(page.locator('section[data-state="list"]')).toBeVisible();

        const firstRow = deadLetterRow(page, EVENT_ID);
        await expect(firstRow).toContainText("管理v: 7");
        const firstRedrive = firstRow.getByRole("button", { name: "再送", exact: true });
        await firstRedrive.focus();
        await page.keyboard.press("Enter");
        const redriveConfirmation = page.getByRole("dialog", { name: "再送の確認" });
        await expect(redriveConfirmation).toBeVisible();
        const confirmRedrive = redriveConfirmation.getByRole("button", { name: "再送を確定", exact: true });
        await confirmRedrive.focus();
        await page.keyboard.press("Enter");

        await expect(page.locator('section[data-state="list"] [role="status"]')).toContainText("最新の状態に更新しました");
        await expect(deadLetterRow(page, EVENT_ID)).toContainText("管理v: 8");
        expect(routes.state.listCalls).toBe(2);
        expect(routes.state.redriveCalls).toHaveLength(1);
        expect(routes.state.redriveCalls[0].headers["if-match"]).toBe('"7"');

        await page.getByRole("dialog", { name: "再送の確認" }).getByRole("button", { name: "戻る", exact: true }).click();
        const refreshedRow = deadLetterRow(page, EVENT_ID);
        await refreshedRow.getByRole("button", { name: "再送", exact: true }).click();
        await page.getByRole("dialog", { name: "再送の確認" }).getByRole("button", { name: "再送を確定", exact: true }).click();
        await expect(page.locator('section[data-state="list"] [role="status"]')).toContainText("再送を受け付けました。管理バージョンはv9です。");
        await expect(deadLetterRow(page, EVENT_ID)).toContainText("管理v: 9");

        const secondRow = deadLetterRow(page, SECOND_EVENT_ID);
        await secondRow.getByRole("button", { name: "抑制", exact: true }).click();
        const suppressConfirmation = page.getByRole("dialog", { name: "抑制の確認" });
        await suppressConfirmation.getByLabel("抑制理由").fill("manual review");
        await suppressConfirmation.getByRole("button", { name: "抑制を確定", exact: true }).click();
        await expect(page.locator('section[data-state="list"] [role="status"]')).toContainText("抑制を受け付けました。管理バージョンはv5です。");

        await expect(deadLetterRow(page, SECOND_EVENT_ID)).toHaveAttribute("data-state", "suppressed");
        await expect(deadLetterRow(page, SECOND_EVENT_ID)).toContainText("理由: manual review");
        expect(routes.state.suppressCalls).toHaveLength(1);
        expect(routes.state.suppressCalls[0].body).toEqual({ reason: "manual review" });
        expect(routes.state.suppressCalls[0].headers["if-match"]).toBe('"4"');
        expect(routes.state.suppressCalls[0].headers["agentpass-recent-auth"]).toBe(AUTHORIZATION_ID);
        expect(routes.state.authenticationOptions.map((body) => body.operation)).toEqual([
          "human.recovery.outbox.redrive",
          "human.recovery.outbox.redrive",
          "human.recovery.outbox.suppress",
        ]);
        const expectedContexts = [
          resourceContextHash(EVENT_ID, "redrive", 7),
          resourceContextHash(EVENT_ID, "redrive", 8),
          resourceContextHash(SECOND_EVENT_ID, "suppress", 4),
        ];
        expect(routes.state.authenticationOptions.map((body) => body.context_hash)).toEqual(expectedContexts);
        expect(routes.state.authenticationVerifyBodies).toHaveLength(3);
        expect(routes.state.authenticationVerifyBodies.map((body) => body.context_hash)).toEqual(expectedContexts);
        expect(routes.state.authenticationVerifyBodies.every((body) => body.has_credential === true)).toBe(true);
      });
    });
  }

  test.afterEach(async ({ page }) => {
    const authenticator = authenticators.get(page);
    if (authenticator) await disposeVirtualAuthenticator(authenticator);
    await page.unrouteAll({ behavior: "ignoreErrors" });
  });
});

test.afterEach(async ({ page }) => {
  await page.unrouteAll({ behavior: "ignoreErrors" });
});
