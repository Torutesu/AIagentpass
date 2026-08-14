import { expect, test, type Page } from "@playwright/test";
import {
  ACTIVE_EXPIRES_AT,
  AUTHORIZATION_ID,
  CHALLENGE,
  CHALLENGE_ID,
  CREDENTIAL_ID,
  ORGANIZATION_ID,
  REGISTRATION_CHALLENGE,
  browserStorageSnapshot,
  consoleSummary,
  disposeVirtualAuthenticator,
  installVirtualAuthenticator,
  json,
  parseRequestBody,
  session,
  type VirtualAuthenticator,
} from "./support/browser-fixtures";

type SecurityMode = "initial_registration" | "step_up_registration" | "replay" | "credential_loss";

type BrowserSecurityState = {
  registrationOptionsCalls: number;
  registrationOptionRecentAuth: Array<string | undefined>;
  registrationVerifyCalls: number;
  registrationVerifyRecentAuth: Array<string | undefined>;
  registrationVerifyBodies: Array<Record<string, unknown>>;
  authenticationOptionsCalls: number;
  authenticationVerifyCalls: number;
  authenticationOperations: string[];
  enrollmentCalls: number;
  enrollmentRecentAuth: Array<string | undefined>;
  enrollmentBodies: Array<Record<string, unknown>>;
};

const ENROLLMENT_SECRET = "enrollment-secret-must-not-leak";
const activeAuthenticators = new WeakMap<Page, VirtualAuthenticator>();

function registrationOptions() {
  return {
    challenge: REGISTRATION_CHALLENGE,
    rp: { id: "localhost", name: "AgentPass" },
    user: { id: "dXNlci1lMmU", name: "e2e@example.test", displayName: "E2E User" },
    pubKeyCredParams: [{ type: "public-key", alg: -7 }],
    authenticatorSelection: { residentKey: "preferred", userVerification: "required" },
    timeout: 2_000,
    attestation: "none",
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

async function installSecurityRoutes(page: Page, mode: SecurityMode): Promise<BrowserSecurityState> {
  const state: BrowserSecurityState = {
    registrationOptionsCalls: 0,
    registrationOptionRecentAuth: [],
    registrationVerifyCalls: 0,
    registrationVerifyRecentAuth: [],
    registrationVerifyBodies: [],
    authenticationOptionsCalls: 0,
    authenticationVerifyCalls: 0,
    authenticationOperations: [],
    enrollmentCalls: 0,
    enrollmentRecentAuth: [],
    enrollmentBodies: [],
  };

  await page.route("**/api/auth/**", async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    const headers = request.headers();

    if (url.pathname === "/api/auth/session") return json(route, session("owner"));

    if (url.pathname === "/api/auth/webauthn/registration/options") {
      state.registrationOptionsCalls += 1;
      state.registrationOptionRecentAuth.push(headers["agentpass-recent-auth"]);
      if (mode === "step_up_registration" && state.registrationOptionsCalls === 1) {
        return json(route, { error: { code: "recent_auth_required", message: "Recent authentication required" } }, 428);
      }
      return json(route, { challenge_id: CHALLENGE_ID, options: registrationOptions() });
    }

    if (url.pathname === "/api/auth/webauthn/registration/verify") {
      state.registrationVerifyCalls += 1;
      state.registrationVerifyRecentAuth.push(headers["agentpass-recent-auth"]);
      state.registrationVerifyBodies.push(parseRequestBody(route));
      return json(route, { credential_id: CREDENTIAL_ID, registered_at: "2026-08-12T10:00:00.000Z" }, 201);
    }

    if (url.pathname === "/api/auth/webauthn/options") {
      const body = parseRequestBody(route);
      state.authenticationOptionsCalls += 1;
      state.authenticationOperations.push(String(body.operation ?? ""));
      return json(route, { challenge_id: CHALLENGE_ID, options: authenticationOptions() });
    }

    if (url.pathname === "/api/auth/webauthn/verify") {
      state.authenticationVerifyCalls += 1;
      return json(route, { authorization_id: AUTHORIZATION_ID });
    }

    return json(route, { error: { code: "not_found", message: "Not found" } }, 404);
  });

  await page.route("**/api/console**", async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    if (request.method() === "GET" && url.searchParams.get("resource") === "summary") return json(route, consoleSummary());
    if (request.method() === "GET") return json(route, { capabilities: [], revocations: [], events: [] });
    if (request.method() !== "POST" || url.searchParams.get("operation") !== "issue-device-enrollment") return json(route, { error: { code: "forbidden", message: "Forbidden" } }, 403);

    state.enrollmentCalls += 1;
    state.enrollmentRecentAuth.push(request.headers()["agentpass-recent-auth"]);
    state.enrollmentBodies.push(parseRequestBody(route));
    if (mode === "replay" && state.enrollmentCalls > 1) return json(route, { error: { code: "replayed", message: "Recent authentication has already been consumed" } }, 403);
    return json(route, {
      request_id: "69999999-9999-4999-8999-999999999999",
      enrollment: {
        enrollment_id: "78888888-8888-4888-8888-888888888888",
        device_id: "41111111-1111-4111-8111-111111111111",
        label: String(state.enrollmentBodies.at(-1)?.label ?? "E2E Mac"),
        platform: "macos",
        organization_id: ORGANIZATION_ID,
        expires_at: ACTIVE_EXPIRES_AT,
        credential: ENROLLMENT_SECRET,
      },
    }, 201);
  });

  return state;
}

async function openSetup(page: Page): Promise<void> {
  await page.goto("/");
  await expect(page.getByRole("heading", { name: /Agentの状態を、\s*確認できました。/u })).toBeVisible();
  await expect(page.getByRole("heading", { name: "E2E Mac" })).toBeVisible();
  await page.getByRole("button", { name: "セットアップ", exact: true }).click();
  await expect(page.getByRole("heading", { name: "パスキーを登録" })).toBeVisible();
}

async function assertNoBrowserStorageSecret(page: Page, secret: string): Promise<void> {
  const storage = await browserStorageSnapshot(page);
  const serialized = JSON.stringify(storage);
  expect(serialized).not.toContain(secret);
  expect(Object.keys(storage.local)).toHaveLength(0);
  expect(Object.keys(storage.session)).toHaveLength(0);
}

test("registers a passkey through the production browser API and keeps credential material out of storage", async ({ page }) => {
  activeAuthenticators.set(page, await installVirtualAuthenticator(page));
  const state = await installSecurityRoutes(page, "initial_registration");
  await openSetup(page);
  await page.getByRole("button", { name: "Touch ID / パスキーを登録", exact: true }).click();
  await expect(page.getByRole("status")).toContainText("パスキーを登録しました");

  expect(state.registrationOptionsCalls).toBe(1);
  expect(state.registrationOptionRecentAuth).toEqual([undefined]);
  expect(state.authenticationVerifyCalls).toBe(0);
  expect(state.registrationVerifyCalls).toBe(1);
  expect(state.registrationVerifyRecentAuth).toEqual([undefined]);
  expect(state.registrationVerifyBodies[0]).toHaveProperty("credential");
  expect(state.registrationVerifyBodies[0]).not.toHaveProperty("authorization_id");
  await assertNoBrowserStorageSecret(page, CREDENTIAL_ID);
  await assertNoBrowserStorageSecret(page, ENROLLMENT_SECRET);
});

test("requires operation-bound step-up before registering another passkey", async ({ page }) => {
  activeAuthenticators.set(page, await installVirtualAuthenticator(page));
  const state = await installSecurityRoutes(page, "step_up_registration");
  await openSetup(page);
  await page.getByRole("button", { name: "Touch ID / パスキーを登録", exact: true }).click();
  await expect(page.getByRole("status")).toContainText("パスキーを登録しました");

  expect(state.registrationOptionsCalls).toBe(2);
  expect(state.registrationOptionRecentAuth).toEqual([undefined, AUTHORIZATION_ID]);
  expect(state.authenticationOptionsCalls).toBe(1);
  expect(state.authenticationOperations).toEqual(["human.webauthn.credential.register"]);
  expect(state.authenticationVerifyCalls).toBe(1);
  expect(state.registrationVerifyCalls).toBe(1);
  expect(state.registrationVerifyRecentAuth).toEqual([AUTHORIZATION_ID]);
  expect(state.registrationVerifyBodies[0]).not.toHaveProperty("authorization_id");
  await assertNoBrowserStorageSecret(page, AUTHORIZATION_ID);
  await assertNoBrowserStorageSecret(page, CREDENTIAL_ID);
});

test("fails closed when the server replays the same recent-auth proof", async ({ page }) => {
  activeAuthenticators.set(page, await installVirtualAuthenticator(page));
  const state = await installSecurityRoutes(page, "replay");
  await openSetup(page);
  const label = page.getByLabel("端末名");
  await label.fill("Replay E2E Mac");
  const issue = page.getByRole("button", { name: "Touch ID/パスキー確認", exact: true });

  await issue.click();
  await expect(page.getByText("一度だけ表示しています")).toBeVisible();
  await expect(page.locator(".secret-output")).toContainText(ENROLLMENT_SECRET);
  await page.getByRole("button", { name: "表示を消す", exact: true }).click();

  await issue.click();
  await expect(page.getByRole("alert")).toContainText("登録情報を発行できませんでした");
  expect(state.enrollmentCalls).toBe(2);
  expect(state.enrollmentRecentAuth).toEqual([AUTHORIZATION_ID, AUTHORIZATION_ID]);
  expect(state.enrollmentBodies).toEqual([{ label: "Replay E2E Mac", platform: "macos", ttl_ms: 600000 }, { label: "Replay E2E Mac", platform: "macos", ttl_ms: 600000 }]);
  await assertNoBrowserStorageSecret(page, ENROLLMENT_SECRET);
  await assertNoBrowserStorageSecret(page, AUTHORIZATION_ID);
});

test("fails closed when the virtual authenticator has lost the credential", async ({ page }) => {
  const authenticator = await installVirtualAuthenticator(page);
  activeAuthenticators.set(page, authenticator);
  const state = await installSecurityRoutes(page, "credential_loss");
  await removeCredential(authenticator);
  await openSetup(page);
  await page.getByLabel("端末名").fill("Lost Credential E2E Mac");
  await page.getByRole("button", { name: "Touch ID/パスキー確認", exact: true }).click();
  await expect(page.getByRole("alert")).toContainText("Touch ID/パスキー確認を完了できませんでした");
  expect(state.authenticationOptionsCalls).toBe(1);
  expect(state.authenticationVerifyCalls).toBe(0);
  expect(state.enrollmentCalls).toBe(0);
  await assertNoBrowserStorageSecret(page, ENROLLMENT_SECRET);
  await assertNoBrowserStorageSecret(page, AUTHORIZATION_ID);
});

async function removeCredential(authenticator: VirtualAuthenticator): Promise<void> {
  await authenticator.cdp.send("WebAuthn.removeCredential", { authenticatorId: authenticator.authenticatorId, credentialId: authenticator.credentialId });
}

test.afterEach(async ({ page }) => {
  const authenticator = activeAuthenticators.get(page);
  if (authenticator) await disposeVirtualAuthenticator(authenticator);
  await page.unrouteAll({ behavior: "ignoreErrors" });
});
