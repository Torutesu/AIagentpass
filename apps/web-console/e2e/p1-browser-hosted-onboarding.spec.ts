import { expect, test, type Page } from "@playwright/test";
import {
  CREDENTIAL_ID,
  CSRF_TOKEN,
  ORGANIZATION_ID,
  REGISTRATION_CHALLENGE,
  SESSION_ID,
  MEMBER_ID,
  installVirtualAuthenticator,
  disposeVirtualAuthenticator,
  json,
  type VirtualAuthenticator,
} from "./support/browser-fixtures";

const ORGANIZATION_NAME = "Hosted E2E Organization";
const CHALLENGE_ID = "57777777-7777-4777-8777-777777777777";
const SESSION_CSRF_TOKEN = "s".repeat(43);
const EXPIRES_AT = "2099-01-01T00:00:00.000Z";
const CREATED_AT = "2026-08-15T00:00:00.000Z";
const USER_ID = "dXNlci1lMmU";

type HostedMode =
  | "unauthenticated"
  | "organization"
  | "no_membership"
  | "expired"
  | "error";

type HostedRouteState = {
  mode: HostedMode;
  statusCalls: number;
  organizationCalls: number;
  webauthnOptionsCalls: number;
  webauthnVerifyCalls: number;
  organizationBodies: Array<Record<string, unknown>>;
  organizationHeaders: Array<Record<string, string>>;
  webauthnOptionsBodies: Array<Record<string, unknown>>;
  webauthnVerifyBodies: Array<Record<string, unknown>>;
  unexpectedRequests: string[];
  holdOrganizationResponse: boolean;
  dropOrganizationResponse: boolean;
  releaseOrganizationResponse?: () => void;
};

const activeAuthenticators = new WeakMap<Page, VirtualAuthenticator>();

function statusBody(state: "organization_required" | "webauthn_required" | "no_membership" | "expired" | "completed") {
  return {
    version: 1,
    state,
    webauthn_required: state === "webauthn_required",
    can_create_first_organization: state === "organization_required",
    organization_count: state === "organization_required" ? 0 : 1,
    csrf_token: CSRF_TOKEN,
    expires_at: EXPIRES_AT,
  };
}

function registrationOptions() {
  return {
    challenge_id: CHALLENGE_ID,
    options: {
      challenge: REGISTRATION_CHALLENGE,
      rp: { id: "localhost", name: "AgentPass" },
      user: { id: USER_ID, name: "hosted-e2e@example.test", displayName: "Hosted E2E User" },
      pubKeyCredParams: [{ type: "public-key", alg: -7 }],
      timeout: 2_000,
      excludeCredentials: [],
      authenticatorSelection: { residentKey: "preferred", userVerification: "required" },
      attestation: "none",
    },
  };
}

function completedBody() {
  return {
    version: 1,
    state: "completed",
    session: {
      version: 1,
      session_id: SESSION_ID,
      member_id: MEMBER_ID,
      organization_id: ORGANIZATION_ID,
      role: "owner",
      created_at: CREATED_AT,
      expires_at: EXPIRES_AT,
      recent_auth_at: null,
    },
    csrf_token: SESSION_CSRF_TOKEN,
  };
}

function organizationBody() {
  return {
    version: 1,
    organization: {
      organization_id: ORGANIZATION_ID,
      name: ORGANIZATION_NAME,
      version: 1,
      created_at: CREATED_AT,
      updated_at: CREATED_AT,
    },
    onboarding: { state: "webauthn_required" },
  };
}

function requestJson(route: import("@playwright/test").Route): Record<string, unknown> {
  try {
    const body: unknown = JSON.parse(route.request().postData() ?? "{}");
    return body && typeof body === "object" && !Array.isArray(body) ? body as Record<string, unknown> : {};
  } catch {
    return {};
  }
}

async function installHostedRoutes(page: Page, mode: HostedMode, options: { holdOrganizationResponse?: boolean; dropOrganizationResponse?: boolean } = {}): Promise<HostedRouteState> {
  const state: HostedRouteState = {
    mode,
    statusCalls: 0,
    organizationCalls: 0,
    webauthnOptionsCalls: 0,
    webauthnVerifyCalls: 0,
    organizationBodies: [],
    organizationHeaders: [],
    webauthnOptionsBodies: [],
    webauthnVerifyBodies: [],
    unexpectedRequests: [],
    holdOrganizationResponse: options.holdOrganizationResponse === true,
    dropOrganizationResponse: options.dropOrganizationResponse === true,
  };

  await page.route("**/api/auth/bootstrap/**", async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    const method = request.method();

    if (url.pathname === "/api/auth/bootstrap/github/start" && method === "GET" && !url.search) {
      return route.fulfill({
        status: 302,
        headers: {
          location: "https://github.com/login/oauth/authorize?client_id=agentpass-e2e&response_type=code&redirect_uri=http%3A%2F%2Flocalhost%3A4173%2Fapi%2Fauth%2Fbootstrap%2Fgithub%2Fcallback&scope=read%3Auser&state=e2e-state-12345678&code_challenge=e2e-code-challenge-12345678&code_challenge_method=S256",
        },
        body: "",
      });
    }

    if (url.pathname === "/api/auth/bootstrap/status" && method === "GET" && !url.search) {
      state.statusCalls += 1;
      if (mode === "unauthenticated") return json(route, { error: { code: "bootstrap_session_required", message: "Sign in required" } }, 401);
      if (mode === "expired") return json(route, { ...statusBody("expired"), csrf_token: CSRF_TOKEN });
      if (mode === "error") return json(route, { error: { code: "bootstrap_unavailable", message: "Temporarily unavailable" } }, 503);
      if (mode === "no_membership") return json(route, statusBody("no_membership"));
      if (mode === "organization") return json(route, statusBody(state.statusCalls === 1 ? "organization_required" : "webauthn_required"));
    }

    if (url.pathname === "/api/auth/bootstrap/organization" && method === "POST" && !url.search) {
      state.organizationCalls += 1;
      state.organizationBodies.push(requestJson(route));
      state.organizationHeaders.push({
        csrf: request.headers()["agentpass-bootstrap-csrf"] ?? "",
        idempotency: request.headers()["idempotency-key"] ?? "",
        contentType: request.headers()["content-type"] ?? "",
        authorization: request.headers()["authorization"] ?? "",
      });
      if (state.holdOrganizationResponse && state.organizationCalls === 1) {
        await new Promise<void>((resolve) => { state.releaseOrganizationResponse = resolve; });
      }
      if (state.dropOrganizationResponse && state.organizationCalls === 1) return route.abort("failed");
      return json(route, organizationBody(), 201);
    }

    if (url.pathname === "/api/auth/bootstrap/webauthn/registration/options" && method === "POST" && !url.search) {
      state.webauthnOptionsCalls += 1;
      state.webauthnOptionsBodies.push(requestJson(route));
      return json(route, registrationOptions());
    }

    if (url.pathname === "/api/auth/bootstrap/webauthn/registration/verify" && method === "POST" && !url.search) {
      state.webauthnVerifyCalls += 1;
      state.webauthnVerifyBodies.push(requestJson(route));
      return json(route, completedBody());
    }

    state.unexpectedRequests.push(`${method} ${url.pathname}${url.search}`);
    return json(route, { error: { code: "unexpected_e2e_request", message: "Unexpected Hosted request" } }, 500);
  });

  await page.route("**/github.com/**", async (route) => {
    state.unexpectedRequests.push(`external ${route.request().method()} ${new URL(route.request().url()).pathname}`);
    return route.fulfill({ status: 418, contentType: "text/plain", body: "External GitHub access is disabled in this E2E" });
  });

  return state;
}

async function assertNoReusableAuthority(page: Page, sensitiveValues: string[]): Promise<void> {
  const contextCookies = await page.context().cookies();
  const browserState = await page.evaluate(async () => {
    const readStorage = (storage: Storage) => Object.fromEntries(Object.keys(storage).map((key) => [key, storage.getItem(key) ?? ""]));
    const cacheState: Array<{ cache: string; url: string; body: string }> = [];
    if ("caches" in window) {
      for (const cacheName of await caches.keys()) {
        const cache = await caches.open(cacheName);
        for (const responseRequest of await cache.keys()) {
          const response = await cache.match(responseRequest);
          cacheState.push({ cache: cacheName, url: responseRequest.url, body: response ? await response.clone().text() : "" });
        }
      }
    }
    const databases = typeof indexedDB.databases === "function" ? await indexedDB.databases() : [];
    return {
      url: window.location.href,
      localStorage: readStorage(window.localStorage),
      sessionStorage: readStorage(window.sessionStorage),
      indexedDB: databases,
      caches: cacheState,
      dom: document.documentElement.outerHTML,
    };
  });
  const serialized = JSON.stringify({ browserState, contextCookies });
  for (const value of sensitiveValues) {
    if (value.length >= 8) expect(serialized).not.toContain(value);
  }
  expect(browserState.url).toMatch(/\/onboarding$/u);
  expect(browserState.localStorage).toEqual({});
  expect(browserState.sessionStorage).toEqual({});
  expect(contextCookies).toEqual([]);
}

function assertNoSensitiveConsoleMessages(messages: string[], sensitiveValues: string[]): void {
  for (const message of messages) {
    for (const value of sensitiveValues) {
      if (value.length >= 8) expect(message).not.toContain(value);
    }
  }
}

async function openOnboarding(page: Page, mode: HostedMode, options: { holdOrganizationResponse?: boolean; dropOrganizationResponse?: boolean } = {}) {
  const state = await installHostedRoutes(page, mode, options);
  const consoleMessages: string[] = [];
  page.on("console", (message) => consoleMessages.push(`${message.type()}: ${message.text()}`));
  await page.goto("/onboarding");
  return { state, consoleMessages };
}

test("shows the unauthenticated GitHub sign-in entrypoint with strict Cloud/GitHub mocks", async ({ page }) => {
  const { state, consoleMessages } = await openOnboarding(page, "unauthenticated");

  await expect(page.getByRole("heading", { name: "GitHubで本人確認" })).toBeVisible();
  await expect(page.getByRole("link", { name: /GitHubで続ける/u })).toHaveAttribute("href", "/api/auth/bootstrap/github/start");
  expect(state.statusCalls).toBe(1);
  expect(state.unexpectedRequests).toEqual([]);
  await assertNoReusableAuthority(page, [CSRF_TOKEN, CHALLENGE_ID, REGISTRATION_CHALLENGE, CREDENTIAL_ID]);
  assertNoSensitiveConsoleMessages(consoleMessages, [CSRF_TOKEN, CHALLENGE_ID, REGISTRATION_CHALLENGE, CREDENTIAL_ID]);
});

test("creates an organization with the exact JSON/header contract, registers a passkey, and completes", async ({ page }) => {
  const authenticator = await installVirtualAuthenticator(page);
  activeAuthenticators.set(page, authenticator);
  const { state, consoleMessages } = await openOnboarding(page, "organization");

  await expect(page.getByRole("heading", { name: "最初のワークスペースを作成" })).toBeVisible();
  await page.getByLabel("ワークスペース名").fill(ORGANIZATION_NAME);
  await page.getByRole("button", { name: "ワークスペースを作成", exact: true }).click();
  await expect(page.getByRole("heading", { name: "パスキーで管理者アカウントを保護" })).toBeVisible();

  expect(state.organizationCalls).toBe(1);
  expect(state.organizationBodies).toEqual([{ name: ORGANIZATION_NAME }]);
  expect(state.organizationHeaders[0]).toMatchObject({
    csrf: CSRF_TOKEN,
    contentType: "application/json",
    authorization: "",
  });
  expect(state.organizationHeaders[0].idempotency).toMatch(/^[A-Za-z0-9._~-]{8,255}$/u);
  expect(state.webauthnOptionsCalls).toBe(0);

  await page.getByRole("button", { name: "パスキーを登録", exact: true }).click();
  await expect(page.getByText("準備ができました", { exact: true })).toBeVisible();
  expect(state.webauthnOptionsCalls).toBe(1);
  expect(state.webauthnVerifyCalls).toBe(1);
  expect(state.webauthnOptionsBodies).toEqual([{}]);
  expect(state.webauthnVerifyBodies[0]).toMatchObject({ challenge_id: CHALLENGE_ID, credential: { type: "public-key" } });
  expect(state.webauthnVerifyBodies[0]).not.toHaveProperty("csrf_token");
  expect(state.unexpectedRequests).toEqual([]);

  const credential = state.webauthnVerifyBodies[0].credential as Record<string, unknown>;
  const response = credential.response as Record<string, unknown>;
  const sensitiveValues = [CSRF_TOKEN, SESSION_CSRF_TOKEN, CHALLENGE_ID, REGISTRATION_CHALLENGE, CREDENTIAL_ID, String(credential.id), String(response.clientDataJSON), String(response.attestationObject)];
  await expect(page.locator('[data-onboarding-state="device_handoff"]')).toBeVisible();
  await expect(page.locator('[data-device-handoff="ready"]')).toBeVisible();
  await expect(page.getByText("端末をAgentへ引き渡す", { exact: true })).toBeVisible();
  // The verify response is authoritative for this in-memory handoff screen.
  // The current status route accepts only the bootstrap cookie, which is
  // rotated away by verify; a post-verify refresh assertion therefore waits
  // for a future session-aware onboarding status contract.
  await assertNoReusableAuthority(page, sensitiveValues);
  assertNoSensitiveConsoleMessages(consoleMessages, sensitiveValues);
});

test("reconciles a lost organization response from server status and resumes after refresh", async ({ page }) => {
  const { state } = await openOnboarding(page, "organization", { dropOrganizationResponse: true });
  await page.getByLabel("ワークスペース名").fill(ORGANIZATION_NAME);
  await page.getByRole("button", { name: "ワークスペースを作成", exact: true }).click();
  await expect(page.getByRole("heading", { name: "パスキーで管理者アカウントを保護" })).toBeVisible();
  expect(state.organizationCalls).toBe(1);
  expect(state.statusCalls).toBe(2);
  expect(state.unexpectedRequests).toEqual([]);

  // The mock deliberately drops the 201. The UI must use the next
  // authoritative status response, and must not resend the mutation.
  await page.reload();
  await expect(page.getByRole("heading", { name: "パスキーで管理者アカウントを保護" })).toBeVisible();
  await expect(page.locator('[data-onboarding-state="webauthn"]')).toBeVisible();
  expect(state.organizationCalls).toBe(1);
  expect(state.statusCalls).toBe(3);
  await assertNoReusableAuthority(page, [CSRF_TOKEN, CHALLENGE_ID, REGISTRATION_CHALLENGE, CREDENTIAL_ID]);
});

test("prevents organization double submission while the first request is in flight", async ({ page }) => {
  const { state } = await openOnboarding(page, "organization", { holdOrganizationResponse: true });
  await page.getByLabel("ワークスペース名").fill(ORGANIZATION_NAME);
  const form = page.locator("form").filter({ has: page.getByLabel("ワークスペース名") });
  const submit = form.locator("button[type=submit]");
  await submit.click();
  await expect.poll(() => state.organizationCalls).toBe(1);

  await form.evaluate((element) => {
    for (let index = 0; index < 2; index += 1) {
      element.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
    }
  });
  expect(state.organizationCalls).toBe(1);
  state.releaseOrganizationResponse?.();
  await expect(page.getByRole("heading", { name: "パスキーで管理者アカウントを保護" })).toBeVisible();
  expect(state.organizationCalls).toBe(1);
  expect(state.unexpectedRequests).toEqual([]);
});

test("renders the no-membership recovery state without exposing ceremony authority", async ({ page }) => {
  const { state, consoleMessages } = await openOnboarding(page, "no_membership");
  await expect(page.getByRole("heading", { name: "管理者の確認が必要です" })).toBeVisible();
  await expect(page.getByText(/過去の所属履歴/u)).toBeVisible();
  expect(state.statusCalls).toBe(1);
  expect(state.unexpectedRequests).toEqual([]);
  await assertNoReusableAuthority(page, [CSRF_TOKEN, CHALLENGE_ID, REGISTRATION_CHALLENGE, CREDENTIAL_ID]);
  assertNoSensitiveConsoleMessages(consoleMessages, [CSRF_TOKEN, CHALLENGE_ID, REGISTRATION_CHALLENGE, CREDENTIAL_ID]);
});

test("renders expired bootstrap state and gives a safe restart path", async ({ page }) => {
  const { state, consoleMessages } = await openOnboarding(page, "expired");
  await expect(page.getByRole("heading", { name: "セットアップの有効期限が切れました" })).toBeVisible();
  await expect(page.getByRole("link", { name: "最初からやり直す", exact: true })).toHaveAttribute("href", "/api/auth/bootstrap/github/start");
  expect(state.statusCalls).toBe(1);
  expect(state.unexpectedRequests).toEqual([]);
  await assertNoReusableAuthority(page, [CSRF_TOKEN, CHALLENGE_ID, REGISTRATION_CHALLENGE, CREDENTIAL_ID]);
  assertNoSensitiveConsoleMessages(consoleMessages, [CSRF_TOKEN, CHALLENGE_ID, REGISTRATION_CHALLENGE, CREDENTIAL_ID]);
});

test("fails closed on Hosted bootstrap errors without retrying automatically", async ({ page }) => {
  const { state, consoleMessages } = await openOnboarding(page, "error");
  await expect(page.getByRole("heading", { name: "状態を確認できませんでした" })).toBeVisible();
  await expect(page.getByRole("button", { name: "もう一度試す", exact: true })).toBeVisible();
  expect(state.statusCalls).toBe(1);
  expect(state.unexpectedRequests).toEqual([]);
  await assertNoReusableAuthority(page, [CSRF_TOKEN, CHALLENGE_ID, REGISTRATION_CHALLENGE, CREDENTIAL_ID]);
  assertNoSensitiveConsoleMessages(consoleMessages, [CSRF_TOKEN, CHALLENGE_ID, REGISTRATION_CHALLENGE, CREDENTIAL_ID]);
});

test.afterEach(async ({ page }) => {
  const authenticator = activeAuthenticators.get(page);
  if (authenticator) await disposeVirtualAuthenticator(authenticator);
  await page.unrouteAll({ behavior: "ignoreErrors" });
});
