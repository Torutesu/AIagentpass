import { createHash } from "node:crypto";
import { expect, test, type Page, type Request, type Route } from "@playwright/test";
import {
  AUTHORIZATION_ID,
  CHALLENGE,
  CHALLENGE_ID,
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
  type BrowserRole,
  type VirtualAuthenticator,
} from "./support/browser-fixtures";

type Action = "redrive" | "suppress";
type FailureMode = "none" | "replay" | "malformed_authorization" | "stale_version";

type CapturedNetwork = Readonly<{ kind: "request" | "response"; url: string; text: string }>;
type WebAuthnEvidence = Readonly<{
  organization_id: unknown;
  operation: unknown;
  context_hash: unknown;
  challenge_id: unknown;
  has_credential: boolean;
}>;
type MutationRequest = Readonly<{
  action: Action;
  body: Record<string, unknown>;
  headers: Record<string, string>;
  url: string;
}>;

type BrowserSecurityState = {
  action: Action | null;
  failure: FailureMode;
  listCalls: number;
  mutationCalls: number;
  webauthnOptionsCalls: number;
  webauthnVerifyCalls: number;
  webauthnOptionBodies: Record<string, unknown>[];
  webauthnVerifyBodies: WebAuthnEvidence[];
  mutationRequests: MutationRequest[];
  protocolViolations: string[];
  networkPayloads: CapturedNetwork[];
  consoleMessages: string[];
  tenantSubstitutionCalls: number;
  originChecks: number;
};

const EVENT_ID = "22222222-2222-4222-8222-222222222222";
const UNKNOWN_EVENT_ID = "23333333-3333-4333-8333-333333333333";
const ALTERNATE_ORGANIZATION_ID = "77777777-7777-4777-8777-777777777777";
const REQUEST_ID = "33333333-3333-4333-8333-333333333333";
const DATE = "2099-01-01T00:00:00.000Z";
const EVENT_TYPE = "recovery.session.issued";
const ERROR_CODE = "provider_timeout";
const MANAGEMENT_VERSION = 3;

// These values model secrets that must never be copied into a browser-visible sink.
const FORBIDDEN_PAYLOADS = [
  "credential-secret-must-not-leak",
  "challenge-secret-must-not-leak",
  "__Host-agentpass_session=forbidden-cookie-sentinel",
  "capability-secret-must-not-leak",
  "recovery-secret-must-not-leak",
] as const;

const activeAuthenticators = new WeakMap<Page, VirtualAuthenticator>();
const activeStates = new WeakMap<Page, BrowserSecurityState>();

function deadLetter(organizationId = ORGANIZATION_ID, managementVersion = MANAGEMENT_VERSION) {
  return {
    organization_id: organizationId,
    event_id: EVENT_ID,
    request_id: REQUEST_ID,
    subject_member_id: MEMBER_ID,
    event_type: EVENT_TYPE,
    status: "dead_letter",
    attempts: 5,
    total_attempts: 5,
    management_version: managementVersion,
    redrive_count: 1,
    last_error_code: ERROR_CODE,
    created_at: DATE,
    updated_at: DATE,
    suppressed_at: null,
    suppression_reason: null,
  };
}

function mutation(action: Action, managementVersion: number) {
  return {
    organization_id: ORGANIZATION_ID,
    event_id: EVENT_ID,
    status: action === "suppress" ? "suppressed" : "pending",
    attempts: action === "suppress" ? 5 : 0,
    total_attempts: 5,
    management_version: managementVersion,
    redrive_count: action === "suppress" ? 1 : 2,
    suppressed_at: action === "suppress" ? DATE : null,
    suppression_reason: action === "suppress" ? "manual review" : null,
  };
}

function deadLetterSession(role: BrowserRole) {
  // The dead-letter client intentionally parses a smaller session shape than the
  // owner-recovery client. Keeping this response exact exercises that boundary.
  return {
    session: {
      version: 1,
      session_id: "55555555-5555-4555-8555-555555555555",
      member_id: MEMBER_ID,
      organization_id: ORGANIZATION_ID,
      role,
      created_at: "2026-08-12T00:00:00.000Z",
      expires_at: DATE,
      recent_auth_at: null,
    },
    csrf_token: CSRF_TOKEN,
  };
}

function resourceContextHash(action: Action, expectedManagementVersion: number): string {
  const canonical = JSON.stringify({
    action,
    event_id: EVENT_ID,
    expected_management_version: expectedManagementVersion,
    organization_id: ORGANIZATION_ID,
    version: 1,
  });
  return createHash("sha256").update(canonical, "utf8").digest("hex");
}

function webAuthnEvidence(body: Record<string, unknown>): WebAuthnEvidence {
  return Object.freeze({
    organization_id: body.organization_id,
    operation: body.operation,
    context_hash: body.context_hash,
    challenge_id: body.challenge_id,
    has_credential: Boolean(body.credential),
  });
}

function installBrowserCapture(page: Page, state: BrowserSecurityState): void {
  page.on("console", (message) => state.consoleMessages.push(message.text()));
  page.on("request", (request) => {
    const url = new URL(request.url());
    state.networkPayloads.push({
      kind: "request",
      url: url.pathname,
      text: JSON.stringify({ path: url.pathname, method: request.method(), headerNames: Object.keys(request.headers()).sort(), bodyBytes: request.postDataBuffer()?.byteLength ?? 0 }),
    });
  });
  page.on("response", (response) => {
    const url = new URL(response.url());
    state.networkPayloads.push({
      kind: "response",
      url: url.pathname,
      text: JSON.stringify({ path: url.pathname, status: response.status(), declaredBodyBytes: response.headers()["content-length"] ?? null }),
    });
  });
}

function failureResponse(route: Route, status: number, code: string, message = "The recovery outbox operation was not allowed") {
  return json(route, { error: { code, message } }, status);
}

function routeAction(url: URL): Action | null {
  if (url.pathname.endsWith("/redrive")) return "redrive";
  if (url.pathname.endsWith("/suppress")) return "suppress";
  return null;
}

function routeOrganization(url: URL): string | null {
  const match = /^\/api\/auth\/organizations\/([^/]+)\/recovery-outbox\/dead-letters/.exec(url.pathname);
  return match?.[1] ?? null;
}

function checkMutationProtocol(state: BrowserSecurityState, request: Request, expectedVersion: number, action: Action): void {
  const headers = request.headers();
  state.originChecks += 1;
  if (headers.origin !== new URL(request.url()).origin) state.protocolViolations.push("origin");
  if (headers["agentpass-csrf"] !== CSRF_TOKEN) state.protocolViolations.push("csrf");
  if (headers["agentpass-recent-auth"] !== AUTHORIZATION_ID) state.protocolViolations.push("recent-auth");
  if (headers["if-match"] !== `"${expectedVersion}"`) state.protocolViolations.push("if-match");
  if (!headers["idempotency-key"] || !/^[A-Za-z0-9][A-Za-z0-9._~-]{7,254}$/.test(headers["idempotency-key"])) state.protocolViolations.push("idempotency");

  let body: Record<string, unknown> = {};
  try {
    const parsed: unknown = JSON.parse(request.postData() ?? "{}");
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) body = parsed as Record<string, unknown>;
  } catch {
    state.protocolViolations.push("body-json");
  }
  const expectedBody = action === "suppress" ? { reason: "manual review" } : {};
  if (JSON.stringify(body) !== JSON.stringify(expectedBody)) state.protocolViolations.push("body");
  state.mutationRequests.push({ action, body, headers, url: request.url() });
}

async function installRoutes(page: Page, role: BrowserRole, failure: FailureMode, action: Action | null = null): Promise<BrowserSecurityState> {
  const state: BrowserSecurityState = {
    action,
    failure,
    listCalls: 0,
    mutationCalls: 0,
    webauthnOptionsCalls: 0,
    webauthnVerifyCalls: 0,
    webauthnOptionBodies: [],
    webauthnVerifyBodies: [],
    mutationRequests: [],
    protocolViolations: [],
    networkPayloads: [],
    consoleMessages: [],
    tenantSubstitutionCalls: 0,
    originChecks: 0,
  };
  activeStates.set(page, state);
  installBrowserCapture(page, state);

  await page.route("**/api/auth/**", async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    const organizationId = routeOrganization(url);

    if (url.pathname === "/api/auth/session") return json(route, deadLetterSession(role));
    if (url.pathname === "/api/auth/webauthn/options" && request.method() === "POST") {
      state.webauthnOptionsCalls += 1;
      state.webauthnOptionBodies.push(parseRequestBody(route));
      return json(route, {
        challenge_id: CHALLENGE_ID,
        options: {
          challenge: CHALLENGE,
          rpId: "localhost",
          userVerification: "required",
          timeout: 1_000,
          allowCredentials: [{ id: CREDENTIAL_ID, type: "public-key", transports: ["internal"] }],
        },
      });
    }
    if (url.pathname === "/api/auth/webauthn/verify" && request.method() === "POST") {
      state.webauthnVerifyCalls += 1;
      const body = parseRequestBody(route);
      state.webauthnVerifyBodies.push(webAuthnEvidence(body));
      if (state.failure === "malformed_authorization") return json(route, { authorization_id: "malformed-authorization" });
      return json(route, { authorization_id: AUTHORIZATION_ID });
    }

    if (!organizationId || !url.pathname.includes("/recovery-outbox/dead-letters")) return failureResponse(route, 404, "not_found", "Resource not found");
    if (organizationId !== ORGANIZATION_ID) {
      state.tenantSubstitutionCalls += 1;
      return failureResponse(route, 404, "not_found", "Resource not found");
    }

    const actionForRequest = routeAction(url);
    if (actionForRequest === null && request.method() === "GET") {
      if (request.headers()["agentpass-csrf"] !== CSRF_TOKEN) return failureResponse(route, 403, "csrf_required");
      state.listCalls += 1;
      return json(route, { dead_letters: [deadLetter(ORGANIZATION_ID, state.listCalls > 1 ? 4 : state.listCalls === 1 ? 3 : 4)], next_cursor: null });
    }

    if (actionForRequest === null || request.method() !== "POST") return failureResponse(route, 404, "not_found", "Resource not found");
    if (url.pathname.endsWith(`/${UNKNOWN_EVENT_ID}/${actionForRequest}`)) return failureResponse(route, 404, "not_found", "Resource not found");

    const expectedVersion = state.failure === "stale_version" && state.mutationCalls === 0 ? 3 : state.mutationCalls > 0 ? 4 : 3;
    const headers = request.headers();
    const originValid = headers.origin === new URL(request.url()).origin;
    const csrfValid = headers["agentpass-csrf"] === CSRF_TOKEN;
    if (!originValid || !csrfValid) return failureResponse(route, 403, !originValid ? "origin_not_allowed" : "csrf_required");
    checkMutationProtocol(state, request, expectedVersion, actionForRequest);

    state.mutationCalls += 1;
    if (state.failure === "stale_version" && state.mutationCalls === 1) {
      return failureResponse(route, 409, "owner_recovery_outbox_management_version_conflict", "The recovery outbox item could not be changed");
    }
    if (state.failure === "replay" && state.mutationCalls > 1) {
      return failureResponse(route, 403, "recent_auth_replayed", "The recovery outbox operation is not allowed");
    }
    return json(route, { dead_letter: mutation(actionForRequest, expectedVersion + 1) });
  });

  await page.route("**/api/console**", async (route) => json(route, consoleSummary()));
  return state;
}

async function openRecovery(page: Page): Promise<void> {
  await page.goto("/");
  await expect(page.getByRole("heading", { name: /Agentの状態を、\s*確認できました。/u })).toBeVisible();
  await expect(page.getByRole("heading", { name: "E2E Mac" })).toBeVisible();
  await page.getByRole("button", { name: "アカウント復旧", exact: true }).click();
}

async function openDeadLetters(page: Page): Promise<ReturnType<Page["getByRole"]>> {
  await expect(page.getByRole("heading", { name: "復旧通知の失敗を管理", exact: true })).toBeVisible();
  const row = page.getByRole("listitem").filter({ hasText: EVENT_TYPE });
  await expect(row).toBeVisible();
  return row;
}

async function assertNoForbiddenBrowserExposure(page: Page, state: BrowserSecurityState): Promise<void> {
  const storage = await browserStorageSnapshot(page);
  const dom = `${await page.locator("body").innerText()}\n${await page.content()}`;
  const unsafeVisible = JSON.stringify({ dom, storage, url: page.url(), console: state.consoleMessages });

  // Transient ceremony values are allowed only in the WebAuthn transport itself.
  for (const transient of [CREDENTIAL_ID, CHALLENGE, CHALLENGE_ID, AUTHORIZATION_ID]) {
    expect(unsafeVisible).not.toContain(transient);
  }
  expect(storage.local).toEqual({});
  expect(storage.session).toEqual({});
  expect(await page.evaluate(() => document.cookie)).toBe("");

  const nonWebAuthnNetwork = state.networkPayloads.filter(({ url }) => !url.includes("/api/auth/webauthn/"));
  for (const payload of FORBIDDEN_PAYLOADS) {
    expect(unsafeVisible).not.toContain(payload);
    expect(JSON.stringify(state.networkPayloads)).not.toContain(payload);
  }
  for (const transient of [CREDENTIAL_ID, CHALLENGE, CHALLENGE_ID]) {
    expect(JSON.stringify(nonWebAuthnNetwork)).not.toContain(transient);
  }
}

async function confirmAction(page: Page, row: ReturnType<Page["getByRole"]>, action: Action): Promise<void> {
  await row.getByRole("button", { name: action === "redrive" ? "再送" : "抑制", exact: true }).click();
  const dialog = page.getByRole("dialog", { name: action === "redrive" ? "再送の確認" : "抑制の確認" });
  await expect(dialog).toBeVisible();
  if (action === "suppress") await dialog.getByRole("textbox", { name: "抑制理由" }).fill("manual review");
  await dialog.getByRole("button", { name: `${action === "redrive" ? "再送" : "抑制"}を確定`, exact: true }).click();
}

test("denies auditor and viewer recovery dead-letter access without enumeration", async ({ page }) => {
  for (const role of ["auditor", "viewer"] as const) {
    const state = await installRoutes(page, role, "none");
    await openRecovery(page);
    await expect(page.getByRole("heading", { name: "復旧通知の失敗管理", exact: true })).toHaveCount(0);
    await expect(page.getByRole("heading", { name: "復旧通知の失敗", exact: true })).toHaveCount(0);
    expect(state.listCalls).toBe(0);
    expect(state.mutationCalls).toBe(0);
    await page.reload();
    await page.getByRole("button", { name: "アカウント復旧", exact: true }).click();
    await expect(page.getByRole("heading", { name: "復旧通知の失敗管理", exact: true })).toHaveCount(0);
    await assertNoForbiddenBrowserExposure(page, state);
    await page.unrouteAll({ behavior: "ignoreErrors" });
  }
});

for (const [role, action] of [["owner", "redrive"], ["admin", "suppress"]] as const) {
  test(`${role} completes ${action} only after a virtual WebAuthn ceremony`, async ({ page }) => {
    const authenticator = await installVirtualAuthenticator(page);
    activeAuthenticators.set(page, authenticator);
    const state = await installRoutes(page, role, "none", action);
    await openRecovery(page);
    const row = await openDeadLetters(page);
    await confirmAction(page, row, action);
    await expect(page.getByRole("status")).toContainText(action === "redrive" ? "再送を受け付けました" : "抑制を受け付けました");

    expect(state.webauthnOptionsCalls).toBe(1);
    expect(state.webauthnVerifyCalls).toBe(1);
    expect(state.webauthnOptionBodies[0]).toMatchObject({
      organization_id: ORGANIZATION_ID,
      operation: action === "redrive" ? "human.recovery.outbox.redrive" : "human.recovery.outbox.suppress",
    });
    expect(state.webauthnOptionBodies[0].context_hash).toMatch(/^[0-9a-f]{64}$/);
    expect(state.webauthnOptionBodies[0].context_hash).toBe(resourceContextHash(action, MANAGEMENT_VERSION));
    expect(state.webauthnVerifyBodies[0].has_credential).toBe(true);
    expect(state.webauthnVerifyBodies[0]).toMatchObject({
      organization_id: ORGANIZATION_ID,
      operation: action === "redrive" ? "human.recovery.outbox.redrive" : "human.recovery.outbox.suppress",
      challenge_id: CHALLENGE_ID,
      context_hash: state.webauthnOptionBodies[0].context_hash,
    });
    expect(state.mutationCalls).toBe(1);
    expect(state.mutationRequests[0].action).toBe(action);
    expect(state.protocolViolations).toEqual([]);
    expect(state.originChecks).toBe(1);
    if (action === "redrive") expect(state.mutationRequests[0].body).toEqual({});
    else expect(state.mutationRequests[0].body).toEqual({ reason: "manual review" });
    expect(state.mutationRequests[0].headers["if-match"]).toBe('"3"');
    await assertNoForbiddenBrowserExposure(page, state);
  });
}

test("rejects a consumed recent-auth authorization on the second browser mutation", async ({ page }) => {
  const authenticator = await installVirtualAuthenticator(page);
  activeAuthenticators.set(page, authenticator);
  const state = await installRoutes(page, "owner", "replay", "redrive");
  await openRecovery(page);
  const row = await openDeadLetters(page);

  await confirmAction(page, row, "redrive");
  await expect(page.getByRole("status")).toContainText("再送を受け付けました");
  await confirmAction(page, row, "redrive");
  await expect(page.getByRole("alert")).toContainText("この操作を実行する権限がありません");

  expect(state.webauthnVerifyCalls).toBe(2);
  expect(state.mutationCalls).toBe(2);
  expect(state.mutationRequests).toHaveLength(2);
  expect(state.mutationRequests[0].headers["agentpass-recent-auth"]).toBe(AUTHORIZATION_ID);
  expect(state.mutationRequests[1].headers["agentpass-recent-auth"]).toBe(AUTHORIZATION_ID);
  expect(state.protocolViolations).toEqual([]);
  await assertNoForbiddenBrowserExposure(page, state);
});

test("fails closed for malformed and stale authorization results", async ({ page }) => {
  for (const failure of ["malformed_authorization", "stale_version"] as const) {
    const authenticator = await installVirtualAuthenticator(page);
    activeAuthenticators.set(page, authenticator);
    const state = await installRoutes(page, "owner", failure, "redrive");
    await openRecovery(page);
    const row = await openDeadLetters(page);
    await confirmAction(page, row, "redrive");

    if (failure === "malformed_authorization") {
      await expect(page.getByRole("alert")).toContainText("操作を完了できませんでした");
      expect(state.webauthnVerifyCalls).toBe(1);
      expect(state.mutationCalls).toBe(0);
    } else {
      await expect(page.getByRole("status")).toContainText("最新の状態に更新しました");
      expect(state.webauthnVerifyCalls).toBe(1);
      expect(state.mutationCalls).toBe(1);
      expect(state.listCalls).toBe(2);
      expect(state.mutationRequests[0].headers["if-match"]).toBe('"3"');
    }
    expect(state.protocolViolations).toEqual([]);
    await assertNoForbiddenBrowserExposure(page, state);
    await page.unrouteAll({ behavior: "ignoreErrors" });
    await disposeVirtualAuthenticator(authenticator);
    activeAuthenticators.delete(page);
  }
});

test("prevents cross-tenant dead-letter substitution, enumeration, and CSRF mutation", async ({ page }) => {
  const authenticator = await installVirtualAuthenticator(page);
  activeAuthenticators.set(page, authenticator);
  const state = await installRoutes(page, "owner", "none", "redrive");
  await openRecovery(page);
  await openDeadLetters(page);

  const alternateTenant = await page.evaluate(async ({ organizationId, csrf }) => {
    const response = await fetch(`/api/auth/organizations/${organizationId}/recovery-outbox/dead-letters?limit=25`, { headers: { "agentpass-csrf": csrf } });
    return { status: response.status, body: await response.text() };
  }, { organizationId: ALTERNATE_ORGANIZATION_ID, csrf: CSRF_TOKEN });
  expect(alternateTenant.status).toBe(404);
  expect(alternateTenant.body).not.toContain(EVENT_ID);
  expect(alternateTenant.body).not.toContain(ERROR_CODE);

  const unknownEvent = await page.evaluate(async ({ organizationId, eventId, csrf, authorizationId }) => {
    const response = await fetch(`/api/auth/organizations/${organizationId}/recovery-outbox/dead-letters/${eventId}/redrive`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "agentpass-csrf": csrf,
        "agentpass-recent-auth": authorizationId,
        "idempotency-key": "unknown-event-key",
        "if-match": '"3"',
      },
      body: "{}",
    });
    return { status: response.status, body: await response.text() };
  }, { organizationId: ORGANIZATION_ID, eventId: UNKNOWN_EVENT_ID, csrf: CSRF_TOKEN, authorizationId: AUTHORIZATION_ID });
  expect(unknownEvent.status).toBe(404);
  expect(unknownEvent.body).not.toContain(EVENT_ID);
  expect(unknownEvent.body).not.toContain(ERROR_CODE);

  const missingCsrf = await page.evaluate(async ({ organizationId, eventId, authorizationId }) => {
    const response = await fetch(`/api/auth/organizations/${organizationId}/recovery-outbox/dead-letters/${eventId}/redrive`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "agentpass-recent-auth": authorizationId,
        "idempotency-key": "missing-csrf-key",
        "if-match": '"3"',
      },
      body: "{}",
    });
    return { status: response.status, body: await response.text() };
  }, { organizationId: ORGANIZATION_ID, eventId: EVENT_ID, authorizationId: AUTHORIZATION_ID });
  expect(missingCsrf.status).toBe(403);
  expect(missingCsrf.body).not.toContain(EVENT_ID);
  expect(state.protocolViolations).toEqual([]);
  expect(state.tenantSubstitutionCalls).toBe(1);
  await assertNoForbiddenBrowserExposure(page, state);
});

test.afterEach(async ({ page }) => {
  const authenticator = activeAuthenticators.get(page);
  if (authenticator) await disposeVirtualAuthenticator(authenticator);
  activeAuthenticators.delete(page);
  activeStates.delete(page);
  await page.unrouteAll({ behavior: "ignoreErrors" });
});
