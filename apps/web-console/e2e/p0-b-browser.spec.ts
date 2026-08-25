import { generateKeyPairSync } from "node:crypto";
import { test as base, expect, type Page, type Route } from "@playwright/test";
import { deploymentReadiness, disposeVirtualAuthenticator } from "./support/browser-fixtures";

type Role = "owner" | "admin" | "auditor" | "viewer";
type WakeStatus = "accepted" | "coalesced" | "no_pending_refresh";
type AuthorizationFailure = "none" | "stale" | "replayed" | "cross_operation" | "cross_tenant";

type E2EOptions = {
  role: Role;
  recentAuth: boolean;
  wakeStatuses: WakeStatus[];
  authorizationFailure: AuthorizationFailure;
};

type RouteState = {
  sessionRole: Role;
  sessionExpired: boolean;
  logoutCalls: number;
  wakeCalls: number;
  revokeCalls: number;
  recentAuthVerificationCalls: number;
  recentAuthOperations: string[];
  protocolViolations: string[];
};

const routeStates = new WeakMap<Page, RouteState>();

const test = base.extend<E2EOptions>({
  role: ["owner", { option: true }],
  recentAuth: [true, { option: true }],
  wakeStatuses: [["accepted", "coalesced", "no_pending_refresh"], { option: true }],
  authorizationFailure: ["none", { option: true }],
});

const ORGANIZATION_ID = "11111111-1111-4111-8111-111111111111";
const SESSION_ID = "22222222-2222-4222-8222-222222222222";
const MEMBER_ID = "33333333-3333-4333-8333-333333333333";
const DEVICE_IDS = [
  "41111111-1111-4111-8111-111111111111",
  "42222222-2222-4222-8222-222222222222",
  "43333333-3333-4333-8333-333333333333",
  "44444444-4444-4444-8444-444444444444",
  "45555555-5555-4555-8555-555555555555",
  "46666666-6666-4666-8666-666666666666",
];
const CSRF_TOKEN = "c".repeat(43);
const CHALLENGE_ID = "57777777-7777-4777-8777-777777777777";
const AUTHORIZATION_ID = "58888888-8888-4888-8888-888888888888";
const CHALLENGE = Buffer.alloc(32, 0x43).toString("base64url");
const CREDENTIAL_ID_BYTES = Buffer.from("agentpass-p0b-credential");
const ACTIVE_SESSION_EXPIRES_AT = "2099-01-01T00:00:00.000Z";
const ACTIVE_BUNDLE_EXPIRES_AT = "2099-01-01T00:00:00.000Z";
type VirtualAuthenticatorHandle = {
  cdp: Awaited<ReturnType<ReturnType<Page["context"]>["newCDPSession"]>>;
  authenticatorId: string;
};
const activeAuthenticators = new WeakMap<Page, VirtualAuthenticatorHandle>();

function json(route: Route, body: unknown, status = 200): Promise<void> {
  return route.fulfill({
    status,
    contentType: "application/json",
    body: JSON.stringify(body),
  });
}

function session(role: Role) {
  return {
    session: {
      version: 1,
      session_id: SESSION_ID,
      member_id: MEMBER_ID,
      organization_id: ORGANIZATION_ID,
      role,
      created_at: "2026-08-12T00:00:00.000Z",
      expires_at: ACTIVE_SESSION_EXPIRES_AT,
      recent_auth_at: null,
    },
    csrf_token: CSRF_TOKEN,
  };
}

function devices() {
  const common = {
    created_at: "2026-08-12T00:00:00.000Z",
    last_seen_at: "2026-08-12T00:30:00.000Z",
    version: 1,
    bundle_sequence: 10,
    bundle_expires_at: ACTIVE_BUNDLE_EXPIRES_AT,
    last_ack_at: "2026-08-12T00:30:00.000Z",
    blocked_reason: null,
  };
  return [
    { ...common, device_id: DEVICE_IDS[0], name: "同期済み Mac", status: "active", desired_generation: 1, observed_generation: 1, refresh_state: "applied" },
    { ...common, device_id: DEVICE_IDS[1], name: "反映待ち Mac", status: "active", desired_generation: 2, observed_generation: 1, refresh_state: "pending" },
    { ...common, device_id: DEVICE_IDS[2], name: "ブロック中 Mac", status: "active", desired_generation: 3, observed_generation: 2, refresh_state: "blocked", blocked_reason: "policy_denied" },
    { ...common, device_id: DEVICE_IDS[3], name: "古い状態 Mac", status: "active", desired_generation: 4, observed_generation: 4, refresh_state: "stale", bundle_expires_at: "2026-08-01T00:00:00.000Z" },
    { ...common, device_id: DEVICE_IDS[4], name: "オフライン Mac", status: "active", desired_generation: 5, observed_generation: 4, refresh_state: "offline" },
    { ...common, device_id: DEVICE_IDS[5], name: "失効済み Mac", status: "revoked", desired_generation: 6, observed_generation: 6, refresh_state: "revoked" },
  ];
}

function summary() {
  return {
    organization: {
      organization_id: ORGANIZATION_ID,
      name: "P0-B E2E Organization",
      created_at: "2026-08-12T00:00:00.000Z",
      updated_at: "2026-08-12T00:00:00.000Z",
      version: 1,
    },
    devices: devices(),
    agents: [],
    policies: [],
    audit: { health: [], activity: [], next_cursor: null },
  };
}

async function installRoutes(page: Page, options: E2EOptions): Promise<RouteState> {
  const state: RouteState = {
    sessionRole: options.role,
    sessionExpired: false,
    logoutCalls: 0,
    wakeCalls: 0,
    revokeCalls: 0,
    recentAuthVerificationCalls: 0,
    recentAuthOperations: [],
    protocolViolations: [],
  };

  await page.route("**/api/auth/**", async (route) => {
    const url = new URL(route.request().url());
    if (url.pathname === "/api/auth/session/resume") {
      if (state.sessionExpired) return json(route, { error: { code: "session_expired", message: "Session expired" } }, 401);
      return json(route, session(options.role));
    }
    if (url.pathname === "/api/auth/session") {
      const request = route.request();
      if (request.method() === "DELETE") {
        if (request.headers()["agentpass-csrf"] !== CSRF_TOKEN || request.postData() !== null) state.protocolViolations.push("logout-contract");
        state.logoutCalls += 1;
        return json(route, { session: null });
      }
      if (state.sessionExpired) return json(route, { error: { code: "session_expired", message: "Session expired" } }, 401);
      return json(route, session(options.role));
    }
    if (url.pathname === "/api/auth/webauthn/options") {
      if (!options.recentAuth) return json(route, { error: { code: "recent_auth_required", message: "Recent authentication required" } }, 401);
      state.recentAuthOperations.push(`begin:${requestOperation(route)}`);
      return json(route, {
        challenge_id: CHALLENGE_ID,
        options: {
          challenge: CHALLENGE,
          rpId: "localhost",
          userVerification: "required",
          allowCredentials: [{ id: CREDENTIAL_ID_BYTES.toString("base64url"), type: "public-key", transports: ["internal"] }],
        },
      });
    }
    if (url.pathname === "/api/auth/webauthn/verify") {
      state.recentAuthVerificationCalls += 1;
      state.recentAuthOperations.push(`verify:${requestOperation(route)}`);
      return json(route, options.recentAuth ? { authorization_id: AUTHORIZATION_ID } : { error: { code: "recent_auth_required", message: "Recent authentication required" } }, options.recentAuth ? 200 : 401);
    }
    return json(route, { error: { code: "not_found", message: "Not found" } }, 404);
  });

  await page.route("**/api/console**", async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    if (state.sessionExpired) return json(route, { error: { code: "session_expired", message: "Session expired" } }, 401);
    if (request.method() === "GET" && url.searchParams.get("resource") === "summary") return json(route, summary());
    if (request.method() === "GET" && url.searchParams.get("resource") === "deployment-readiness") return json(route, deploymentReadiness());
    if (request.method() === "GET") return json(route, { capabilities: [], revocations: [], events: [] });
    if (request.method() !== "POST") return json(route, { error: { code: "forbidden", message: "Forbidden" } }, 403);

    let body: unknown;
    try { body = JSON.parse(request.postData() ?? ""); } catch { body = null; }
    const headers = request.headers();
    const operation = url.searchParams.get("operation");
    if (operation === "revoke-device") {
      if (JSON.stringify(body) !== JSON.stringify({ target_id: DEVICE_IDS[0], reason: "web-console-operator" })) state.protocolViolations.push("revoke-body");
      if (!headers["agentpass-csrf"] || !headers["idempotency-key"] || headers["agentpass-recent-auth"] !== AUTHORIZATION_ID) state.protocolViolations.push("revoke-auth-headers");
      if (options.authorizationFailure !== "none" || !options.recentAuth || !["owner", "admin"].includes(options.role)) return json(route, { error: { code: "forbidden", message: "Forbidden" } }, 403);
      state.revokeCalls += 1;
      return json(route, {
        request_id: `revoke-request-${state.revokeCalls}`,
        revocation: {
          revocation_id: "69999999-9999-4999-8999-999999999999",
          organization_id: ORGANIZATION_ID,
          target_type: "device",
          target_id: DEVICE_IDS[0],
          reason: "web-console-operator",
          status: "active",
          version: 1,
        },
      }, 201);
    }
    if (operation !== "device.refresh.request") return json(route, { error: { code: "forbidden", message: "Forbidden" } }, 403);
    if (JSON.stringify(body) !== JSON.stringify({ target_id: DEVICE_IDS[1] }) && JSON.stringify(body) !== JSON.stringify({ target_id: DEVICE_IDS[2] }) && JSON.stringify(body) !== JSON.stringify({ target_id: DEVICE_IDS[3] }) && JSON.stringify(body) !== JSON.stringify({ target_id: DEVICE_IDS[4] })) {
      state.protocolViolations.push("body");
    }
    if (!headers["agentpass-csrf"] || !headers["idempotency-key"] || headers["agentpass-recent-auth"] !== AUTHORIZATION_ID) state.protocolViolations.push("auth-headers");
    if (options.authorizationFailure !== "none" || !options.recentAuth || !["owner", "admin"].includes(options.role)) return json(route, { error: { code: options.authorizationFailure === "none" ? "forbidden" : options.authorizationFailure, message: "Forbidden" } }, 403);

    const status = options.wakeStatuses[Math.min(state.wakeCalls, options.wakeStatuses.length - 1)] ?? "accepted";
    const deviceId = (body as { target_id?: string })?.target_id ?? DEVICE_IDS[1];
    state.wakeCalls += 1;
    return json(route, {
      request_id: `request-${state.wakeCalls}`,
      refresh_request: {
        version: 1,
        request_id: `refresh-request-${state.wakeCalls}`,
        device_id: deviceId,
        desired_generation: status === "no_pending_refresh" ? null : 2,
        status,
        requested_at: "2026-08-12T00:30:00.000Z",
      },
    }, 202);
  });
  routeStates.set(page, state);
  return state;
}

function requestOperation(route: Route): string {
  try { return String(JSON.parse(route.request().postData() ?? "{}").operation ?? ""); }
  catch { return ""; }
}

async function installVirtualAuthenticator(page: Page): Promise<void> {
  const cdp = await page.context().newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  const { authenticatorId } = await cdp.send("WebAuthn.addVirtualAuthenticator", {
    options: {
      protocol: "ctap2",
      transport: "internal",
      hasResidentKey: true,
      hasUserVerification: true,
      automaticPresenceSimulation: true,
      isUserVerified: true,
    },
  });
  await cdp.send("WebAuthn.setUserVerified", { authenticatorId, isUserVerified: true });
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  await cdp.send("WebAuthn.addCredential", {
    authenticatorId,
    credential: {
      credentialId: CREDENTIAL_ID_BYTES.toString("base64"),
      isResidentCredential: false,
      rpId: "localhost",
      privateKey: privateKey.export({ type: "pkcs8", format: "der" }).toString("base64"),
      signCount: 0,
    },
  });
  activeAuthenticators.set(page, { cdp, authenticatorId });
}

test.beforeEach(async ({ page, role, recentAuth, wakeStatuses, authorizationFailure }) => {
  await installVirtualAuthenticator(page);
  await installRoutes(page, { role, recentAuth, wakeStatuses, authorizationFailure });
  await page.goto("/");
  await expect(page.getByRole("heading", { name: /Agentの状態を、\s*確認できました。/u })).toBeVisible();
  await expect(page.getByRole("heading", { name: "同期済み Mac" })).toBeVisible();
});

test("renders all device states with accessible labels and keyboard wake", async ({ page }) => {
  for (const label of ["同期済み", "反映待ち", "ブロック中", "古い状態", "オフライン", "失効済み"]) {
    await expect(page.getByLabel(`同期状態: ${label}`)).toBeVisible();
  }
  const pendingCard = page.getByRole("article").filter({ has: page.getByRole("heading", { name: "反映待ち Mac" }) });
  const wake = pendingCard.getByRole("button", { name: "Wake requestを依頼" });
  await wake.focus();
  await expect(wake).toBeFocused();
  await page.keyboard.press("Enter");
  const confirm = pendingCard.getByRole("button", { name: "確認して送信" });
  await expect(confirm).toBeFocused();
  await page.keyboard.press("Enter");
  await expect(pendingCard.getByRole("status")).toContainText("依頼を受け付けました");
});

test("proves accepted, coalesced, and no-pending-refresh UI outcomes", async ({ page }) => {
  const names = ["反映待ち Mac", "ブロック中 Mac", "古い状態 Mac"];
  const messages = ["依頼を受け付けました", "既存の依頼へ統合し、再通知しました", "反映待ちの更新はなく、通知は送信していません"];
  for (let index = 0; index < names.length; index += 1) {
    const card = page.getByRole("article").filter({ has: page.getByRole("heading", { name: names[index] }) });
    await card.getByRole("button", { name: "Wake requestを依頼" }).click();
    await card.getByRole("button", { name: "確認して送信" }).click();
    await expect(card.getByRole("status")).toContainText(messages[index]);
  }
});

test("self-logout clears the Console and exposes only the reauthentication surface", async ({ page }) => {
  const state = routeStates.get(page)!;
  await page.getByRole("button", { name: "サインアウト", exact: true }).click();

  await expect(page.getByRole("heading", { name: "サインアウトしました" })).toBeVisible();
  await expect(page.getByRole("button", { name: "再認証する" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "同期済み Mac" })).toHaveCount(0);
  expect(state.logoutCalls).toBe(1);
  expect(state.protocolViolations).toEqual([]);
});

test("an expired session replaces every operational view with a fail-closed gate", async ({ page }) => {
  const state = routeStates.get(page)!;
  state.sessionExpired = true;
  await page.getByRole("button", { name: /最終同期/u }).click();

  await expect(page.getByRole("heading", { name: "セッションの有効期限が切れました" })).toBeVisible();
  await expect(page.getByRole("button", { name: "再認証する" })).toBeVisible();
  await expect(page.getByRole("button", { name: "緊急停止を開始する" })).toHaveCount(0);
  await expect(page.getByRole("heading", { name: "同期済み Mac" })).toHaveCount(0);
});

test.describe("role and recent-auth matrix", () => {
  test.describe("owner", () => {
    test.use({ role: "owner", recentAuth: true, wakeStatuses: ["accepted"] });
    test("allows a recent-authenticated wake request", async ({ page }) => {
      const card = page.getByRole("article").filter({ has: page.getByRole("heading", { name: "反映待ち Mac" }) });
      await card.getByRole("button", { name: "Wake requestを依頼" }).click();
      await card.getByRole("button", { name: "確認して送信" }).click();
      await page.waitForTimeout(1_000);
      await expect(card.getByRole("status")).toContainText("依頼を受け付けました");
      expect(routeStates.get(page)).toMatchObject({ wakeCalls: 1, recentAuthVerificationCalls: 1, recentAuthOperations: ["begin:device.refresh.request", "verify:device.refresh.request"], protocolViolations: [] });
    });

    test("allows a device revoke bound to its distinct recent-auth operation", async ({ page }) => {
      await page.getByRole("button", { name: "セットアップ", exact: true }).click();
      const device = page.getByRole("listitem").filter({ hasText: "同期済み Mac" });
      await device.getByRole("button", { name: "停止" }).click();
      await expect(page.getByText("同期済み Macを停止しました")).toBeVisible();
      expect(routeStates.get(page)).toMatchObject({ revokeCalls: 1, recentAuthVerificationCalls: 1, recentAuthOperations: ["begin:device.revoke", "verify:device.revoke"], protocolViolations: [] });
    });
  });

  test.describe("admin", () => {
    test.use({ role: "admin", recentAuth: true, wakeStatuses: ["coalesced"] });
    test("allows a recent-authenticated coalesced request", async ({ page }) => {
      const card = page.getByRole("article").filter({ has: page.getByRole("heading", { name: "反映待ち Mac" }) });
      await card.getByRole("button", { name: "Wake requestを依頼" }).click();
      await card.getByRole("button", { name: "確認して送信" }).click();
      await expect(card.getByRole("status")).toContainText("既存の依頼へ統合し、再通知しました");
      expect(routeStates.get(page)).toMatchObject({ wakeCalls: 1, recentAuthVerificationCalls: 1, recentAuthOperations: ["begin:device.refresh.request", "verify:device.refresh.request"], protocolViolations: [] });
    });

    test("allows a device revoke without reusing the wake authorization", async ({ page }) => {
      await page.getByRole("button", { name: "セットアップ", exact: true }).click();
      const device = page.getByRole("listitem").filter({ hasText: "同期済み Mac" });
      await device.getByRole("button", { name: "停止" }).click();
      await expect(page.getByText("同期済み Macを停止しました")).toBeVisible();
      expect(routeStates.get(page)).toMatchObject({ revokeCalls: 1, recentAuthVerificationCalls: 1, recentAuthOperations: ["begin:device.revoke", "verify:device.revoke"], protocolViolations: [] });
    });
  });

  for (const role of ["auditor", "viewer"] as const) {
    test.describe(role, () => {
      test.use({ role, recentAuth: true, wakeStatuses: ["accepted"] });
      test("does not expose a wake mutation control", async ({ page }) => {
        const card = page.getByRole("article").filter({ has: page.getByRole("heading", { name: "反映待ち Mac" }) });
        await expect(card.getByRole("button", { name: "Wake requestを依頼" })).toHaveCount(0);
        expect(routeStates.get(page)).toMatchObject({ wakeCalls: 0, recentAuthVerificationCalls: 0, protocolViolations: [] });
      });
    });
  }

  test.describe("owner without recent auth", () => {
    test.use({ role: "owner", recentAuth: false, wakeStatuses: ["accepted"] });
    test("fails closed before the wake request", async ({ page }) => {
      const card = page.getByRole("article").filter({ has: page.getByRole("heading", { name: "反映待ち Mac" }) });
      await card.getByRole("button", { name: "Wake requestを依頼" }).click();
      await card.getByRole("button", { name: "確認して送信" }).click();
      await expect(card.getByRole("alert")).toContainText("Wake requestを送信できませんでした");
      expect(routeStates.get(page)).toMatchObject({ wakeCalls: 0, recentAuthVerificationCalls: 0, protocolViolations: [] });
    });
  });

  for (const failure of ["stale", "replayed", "cross_operation", "cross_tenant"] as const) {
    test.describe(`owner with ${failure} authorization`, () => {
      test.use({ role: "owner", recentAuth: true, wakeStatuses: ["accepted"], authorizationFailure: failure });
      test("fails closed after the WebAuthn ceremony and before wake mutation", async ({ page }) => {
        const card = page.getByRole("article").filter({ has: page.getByRole("heading", { name: "反映待ち Mac" }) });
        await card.getByRole("button", { name: "Wake requestを依頼" }).click();
        await card.getByRole("button", { name: "確認して送信" }).click();
        await expect(card.getByRole("alert")).toContainText("Wake requestを送信できませんでした");
        expect(routeStates.get(page)).toMatchObject({ wakeCalls: 0, recentAuthVerificationCalls: 1, recentAuthOperations: ["begin:device.refresh.request", "verify:device.refresh.request"], protocolViolations: [] });
      });
    });
  }
});

test.afterEach(async ({ page }) => {
  const authenticator = activeAuthenticators.get(page);
  if (authenticator) await disposeVirtualAuthenticator(authenticator);
  await page.unrouteAll({ behavior: "ignoreErrors" });
});
