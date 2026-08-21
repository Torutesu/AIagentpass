import { expect, test, type Page } from "@playwright/test";
import {
  ACTIVE_EXPIRES_AT,
  AUTHORIZATION_ID,
  CHALLENGE,
  CREDENTIAL_ID,
  ORGANIZATION_ID,
  browserStorageSnapshot,
  consoleSummary,
  deploymentReadiness,
  disposeVirtualAuthenticator,
  installVirtualAuthenticator,
  json,
  parseRequestBody,
  session,
  type VirtualAuthenticator,
} from "./support/browser-fixtures";

const HANDOFF_PORT = 49152;
const CORRELATION_ID = "A".repeat(43);
const NONCE = "B".repeat(43);
const ENROLLMENT_SECRET = "C".repeat(43);
const CANDIDATE_ID = "candidate-live-2026-08";
const FINGERPRINT = `SHA256:${"D".repeat(43)}`;
const HANDOFF_URL = `http://127.0.0.1:${HANDOFF_PORT}/v1/browser-cli-handoffs/${CORRELATION_ID}`;
const HandoffMode = {
  success: "success",
  corsFailure: "cors-failure",
  substitutedCorrelation: "substituted-correlation",
  invalidAck: "invalid-ack",
} as const;
type HandoffMode = typeof HandoffMode[keyof typeof HandoffMode];

type HandoffState = {
  preflightCalls: number;
  postBodies: Array<Record<string, unknown>>;
  consoleMessages: string[];
};

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

function enrollment() {
  const enrollmentId = "78888888-8888-4888-8888-888888888888";
  const deviceId = "41111111-1111-4111-8111-111111111111";
  const challenge = { challenge_id: enrollmentId, nonce: CHALLENGE, expires_at: ACTIVE_EXPIRES_AT, candidate_id: CANDIDATE_ID, device_key_fingerprint: FINGERPRINT };
  return {
    version: 2,
    proof_version: 2,
    enrollment_id: enrollmentId,
    device_id: deviceId,
    organization_id: ORGANIZATION_ID,
    label: "Live handoff Mac",
    platform: "macos",
    candidate_binding: {
      version: 1,
      enrollment_id: enrollmentId,
      organization_id: ORGANIZATION_ID,
      device_id: deviceId,
      candidate_id: CANDIDATE_ID,
      artifact_sha256: "e".repeat(64),
      source_commit: "f".repeat(40),
      team_id: "APPLETEAM1",
      device_key_fingerprint: FINGERPRINT,
      expires_at: ACTIVE_EXPIRES_AT,
    },
    challenge_id: enrollmentId,
    nonce: CHALLENGE,
    expires_at: ACTIVE_EXPIRES_AT,
    challenge,
    credential: ENROLLMENT_SECRET,
    possession_receipt_verification: { key_id: "possession-live", algorithm: "ed25519", public_key: "-----BEGIN PUBLIC KEY-----\nlive\n-----END PUBLIC KEY-----" },
    endpoint: `/v1/enrollments/${enrollmentId}`,
  };
}

async function installRoutes(page: Page, mode: HandoffMode): Promise<HandoffState> {
  const state: HandoffState = { preflightCalls: 0, postBodies: [], consoleMessages: [] };
  page.on("console", (message) => state.consoleMessages.push(message.text()));
  await page.route("**/api/auth/**", async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    if (url.pathname === "/api/auth/session") return json(route, session("owner"));
    if (url.pathname === "/api/auth/webauthn/options") return json(route, { challenge_id: "57777777-7777-4777-8777-777777777777", options: authenticationOptions() });
    if (url.pathname === "/api/auth/webauthn/verify") return json(route, { authorization_id: AUTHORIZATION_ID });
    return json(route, { error: { code: "not_found", message: "Not found" } }, 404);
  });
  await page.route("**/api/console**", async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    if (request.method() === "GET" && url.searchParams.get("resource") === "summary") return json(route, consoleSummary());
    if (request.method() === "GET" && url.searchParams.get("resource") === "deployment-readiness") return json(route, deploymentReadiness());
    if (request.method() === "GET" && url.searchParams.get("resource") === "capabilities") return json(route, { capabilities: [] });
    if (request.method() === "GET" && url.searchParams.get("resource") === "revocations") return json(route, { revocations: [] });
    if (request.method() === "POST" && url.searchParams.get("operation") === "issue-device-enrollment") return json(route, { enrollment: enrollment() }, 201);
    return json(route, { error: { code: "not_found", message: "Not found" } }, 404);
  });
  await page.route(`http://127.0.0.1:${HANDOFF_PORT}/**`, async (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    const origin = request.headers().origin ?? "http://localhost:4173";
    const cors = mode !== HandoffMode.corsFailure;
    const headers = {
      "access-control-allow-headers": "content-type",
      "access-control-allow-methods": "GET, POST, OPTIONS",
      "access-control-allow-private-network": "true",
      "cache-control": "no-store",
      "content-type": "application/json",
      vary: "Origin",
      ...(cors ? { "access-control-allow-origin": origin } : {}),
    };
    if (request.method() === "OPTIONS") return route.fulfill({ status: cors ? 204 : 403, headers, body: "" });
    if (request.method() === "GET" && path.endsWith("/preflight")) {
      state.preflightCalls += 1;
      return route.fulfill({
        status: mode === HandoffMode.corsFailure ? 403 : 200,
        headers,
        body: JSON.stringify({ version: 1, correlation_id: mode === HandoffMode.substitutedCorrelation ? "E".repeat(43) : CORRELATION_ID, nonce: NONCE, platform: "macos", candidate_id: CANDIDATE_ID, device_key_fingerprint: FINGERPRINT }),
      });
    }
    if (request.method() === "POST" && path.endsWith(`/browser-cli-handoffs/${CORRELATION_ID}`)) {
      state.postBodies.push(parseRequestBody(route));
      return route.fulfill({
        status: 200,
        headers,
        body: JSON.stringify(mode === HandoffMode.invalidAck ? { version: 1, ok: true, consumed: false } : { version: 1, ok: true, consumed: true }),
      });
    }
    return route.fulfill({ status: 404, headers, body: JSON.stringify({ error: { code: "not_found" } }) });
  });
  return state;
}

async function assertNoHandoffSecret(page: Page, state: HandoffState, ...secrets: string[]): Promise<void> {
  const storage = await browserStorageSnapshot(page);
  const pageSurface = `${await page.locator("body").textContent() ?? ""}\n${await page.content()}\n${page.url()}\n${state.consoleMessages.join("\n")}`;
  for (const secret of secrets) expect(pageSurface).not.toContain(secret);
  expect(storage.local).toEqual({});
  expect(storage.session).toEqual({});
  await expect(page.locator(".secret-output")).toHaveCount(0);
}

async function openLiveSetup(page: Page, mode: HandoffMode): Promise<HandoffState> {
  const state = await installRoutes(page, mode);
  await page.context().grantPermissions(["local-network-access"], { origin: "http://localhost:4173" });
  activeAuthenticators.set(page, await installVirtualAuthenticator(page));
  await page.goto(`/#${HANDOFF_URL}`);
  await expect(page).toHaveURL(/\/$/u);
  await expect.poll(() => state.preflightCalls).toBe(1);
  await expect(page.getByText("公開preflightを確認しました")).toBeVisible();
  return state;
}

test("clears malformed launch fragments immediately and shows a safe error", async ({ page }) => {
  const state = await installRoutes(page, HandoffMode.success);
  await page.goto("/#not-a-loopback-handoff");
  await expect(page).toHaveURL(/\/$/u);
  await expect(page.getByRole("alert")).toContainText("自動受け渡しに失敗しました");
  expect(state.preflightCalls).toBe(0);
  await assertNoHandoffSecret(page, state, NONCE, ENROLLMENT_SECRET);
});

test("fails closed on unavailable or substituted-preflight responses without rendering handoff secrets", async ({ page }) => {
  const corsFailureState = await installRoutes(page, HandoffMode.corsFailure);
  await page.goto(`/#${HANDOFF_URL}`);
  await expect(page.getByRole("alert")).toContainText("自動受け渡しに失敗しました");
  await assertNoHandoffSecret(page, corsFailureState, NONCE, ENROLLMENT_SECRET);

  await page.unrouteAll({ behavior: "ignoreErrors" });
  const substitutedState = await installRoutes(page, HandoffMode.substitutedCorrelation);
  await page.goto(`/#${HANDOFF_URL}`);
  await expect(page.getByRole("alert")).toContainText("自動受け渡しに失敗しました");
  await assertNoHandoffSecret(page, substitutedState, NONCE, ENROLLMENT_SECRET);
});

test("posts the exact bound envelope and marks delivery only after the exact ACK", async ({ page }) => {
  const state = await openLiveSetup(page, HandoffMode.success);
  await page.getByLabel("端末名").fill("Live handoff Mac");
  await page.getByRole("button", { name: "Touch ID/パスキー確認して発行", exact: true }).click();
  await expect(page.locator('[data-live-handoff-state="delivered"]')).toBeVisible();
  expect(state.postBodies).toHaveLength(1);
  expect(state.postBodies[0]).toEqual({ version: 1, correlation_id: CORRELATION_ID, nonce: NONCE, invitation: enrollment() });
  const rendered = (await page.locator("body").textContent()) ?? "";
  expect(rendered).not.toContain(NONCE);
  expect(rendered).not.toContain(ENROLLMENT_SECRET);
  await assertNoHandoffSecret(page, state, NONCE, ENROLLMENT_SECRET);
});

test("discards the invitation when the ACK is not exact and never renders a manual secret fallback", async ({ page }) => {
  const state = await openLiveSetup(page, HandoffMode.invalidAck);
  await page.getByLabel("端末名").fill("Fallback handoff Mac");
  await page.getByRole("button", { name: "Touch ID/パスキー確認して発行", exact: true }).click();
  await expect(page.locator('[data-live-handoff-state="failed"]')).toContainText("表示せず破棄しました");
  await assertNoHandoffSecret(page, state, NONCE, ENROLLMENT_SECRET);
});

test.afterEach(async ({ page }) => {
  const authenticator = activeAuthenticators.get(page);
  if (authenticator) await disposeVirtualAuthenticator(authenticator);
  await page.unrouteAll({ behavior: "ignoreErrors" });
});
