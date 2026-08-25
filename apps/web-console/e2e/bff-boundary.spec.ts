import { expect, test, type Page } from "@playwright/test";
import {
  BFF_AUTHORIZATION_ID,
  BFF_CHALLENGE_ID,
  BFF_CSRF_TOKEN,
  BFF_ORGANIZATION_ID,
  BFF_SESSION_TOKEN,
  startBffCloudFixture,
  type BffCloudFixture,
} from "./support/bff-cloud-fixture";

const configuredCloudPort = Number.parseInt(process.env.PLAYWRIGHT_CLOUD_API_PORT ?? "", 10);
const cloudPort = Number.isInteger(configuredCloudPort) && configuredCloudPort >= 1024 && configuredCloudPort <= 65_535
  ? configuredCloudPort
  : 4_310;

type BrowserResponse = Readonly<{
  status: number;
  cacheControl: string | null;
  body: Record<string, unknown>;
}>;

let cloud: BffCloudFixture | undefined;
let cloudStartError: unknown;

async function browserJson(page: Page, path: string, init: { method?: string; headers?: Record<string, string>; body?: string } = {}): Promise<BrowserResponse> {
  return page.evaluate(async ({ path, init }) => {
    const response = await fetch(path, {
      ...init,
      credentials: "same-origin",
      redirect: "error",
      cache: "no-store",
    });
    let body: Record<string, unknown> = {};
    try {
      const parsed: unknown = await response.json();
      if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) body = parsed as Record<string, unknown>;
    } catch {
      // The assertion below reports a useful status even for an invalid body.
    }
    return { status: response.status, cacheControl: response.headers.get("cache-control"), body };
  }, { path, init });
}

async function establishSession(page: Page): Promise<BrowserResponse> {
  const response = await browserJson(page, "/api/auth/session/resume", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: "{}",
  });
  expect(response.status).toBe(200);
  expect(response.body).toHaveProperty("csrf_token", BFF_CSRF_TOKEN);
  return response;
}

test.beforeAll(async () => {
  try {
    cloud = await startBffCloudFixture(cloudPort);
  } catch (error) {
    cloudStartError = error;
  }
});

test.beforeEach(async ({ page }, testInfo) => {
  if (cloudStartError !== undefined || cloud === undefined) {
    const code = cloudStartError && typeof cloudStartError === "object" && "code" in cloudStartError
      ? String((cloudStartError as { code?: unknown }).code)
      : "unknown";
    if (code === "EPERM") {
      testInfo.skip(true, "loopback Cloud fixture is unavailable in this sandbox; external BFF E2E is not_proven");
      return;
    }
    throw cloudStartError ?? new Error("BFF Cloud fixture did not start");
  }

  await page.context().addCookies([{
    name: "__Host-agentpass_session",
    value: BFF_SESSION_TOKEN,
    domain: process.env.PLAYWRIGHT_BROWSER_HOST === "127.0.0.1" ? "127.0.0.1" : "localhost",
    path: "/",
    secure: true,
    httpOnly: true,
    sameSite: "Strict",
  }]);
  await page.goto("/");
  cloud.setState({ role: "owner", mode: "active" });
});

test("passes the real browser session, CSRF, and WebAuthn transport through the BFF", async ({ page }) => {
  const resumed = await establishSession(page);
  const cookies = await page.context().cookies();
  const sessionCookie = cookies.find((cookie) => cookie.name === "__Host-agentpass_session");
  expect(sessionCookie).toMatchObject({ httpOnly: true, secure: true, sameSite: "Strict" });

  const beforeCsrf = cloud?.observations().length ?? 0;
  const missingCsrf = await browserJson(page, "/api/auth/webauthn/options", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ organization_id: BFF_ORGANIZATION_ID, operation: "human.device.enrollment.issue" }),
  });
  expect(missingCsrf.status).toBe(403);
  expect(cloud?.observations()).toHaveLength(beforeCsrf);

  const options = await browserJson(page, "/api/auth/webauthn/options", {
    method: "POST",
    headers: { "content-type": "application/json", "agentpass-csrf": String(resumed.body.csrf_token) },
    body: JSON.stringify({ organization_id: BFF_ORGANIZATION_ID, operation: "human.device.enrollment.issue" }),
  });
  expect(options.status).toBe(200);
  expect(options.body).toHaveProperty("challenge_id", BFF_CHALLENGE_ID);

  const verified = await browserJson(page, "/api/auth/webauthn/verify", {
    method: "POST",
    headers: { "content-type": "application/json", "agentpass-csrf": String(resumed.body.csrf_token) },
    body: JSON.stringify({
      organization_id: BFF_ORGANIZATION_ID,
      operation: "human.device.enrollment.issue",
      challenge_id: BFF_CHALLENGE_ID,
      credential: { id: "browser-credential", response: {} },
    }),
  });
  expect(verified.status).toBe(200);
  expect(verified.body).toHaveProperty("authorization_id", BFF_AUTHORIZATION_ID);

  const organization = await browserJson(page, `/api/console?resource=organization`);
  expect(organization.status).toBe(200);
  expect(organization.cacheControl).toBe("no-store");
  expect(organization.body).toMatchObject({ organization: { organization_id: BFF_ORGANIZATION_ID } });

  const observations = cloud?.observations() ?? [];
  expect(observations.filter(({ path }) => path === "/api/auth/webauthn/options").at(-1)).toMatchObject({
    cookiePresent: true,
    csrfPresent: true,
    origin: expect.stringMatching(/^http:\/\/localhost:/u),
  });
  expect(observations.filter(({ path }) => path === "/api/auth/webauthn/verify").at(-1)).toMatchObject({
    cookiePresent: true,
    csrfPresent: true,
  });
  expect(observations.find(({ path }) => path === `/v1/organizations/${BFF_ORGANIZATION_ID}`)).toMatchObject({ cookiePresent: true });
});

test("fails closed when the same browser session is downgraded or expires", async ({ page }) => {
  const resumed = await establishSession(page);
  const csrf = String(resumed.body.csrf_token);

  cloud?.setState({ role: "viewer" });
  const denied = await browserJson(page, `/api/auth/organizations/${BFF_ORGANIZATION_ID}`, {
    method: "PATCH",
    headers: {
      "content-type": "application/json",
      "agentpass-csrf": csrf,
      "idempotency-key": "role-downgrade-e2e",
      "if-match": '"1"',
    },
    body: JSON.stringify({ name: "must-not-apply" }),
  });
  expect(denied.status).toBe(403);
  expect(denied.body).toMatchObject({ error: { code: "role_denied" } });

  cloud?.setState({ mode: "expired" });
  const expired = await browserJson(page, `/api/console?resource=organization`);
  expect(expired.status).toBe(401);
  expect(expired.body).toMatchObject({ error: { code: "session_expired", message: "Cloud API request failed" } });
  expect(JSON.stringify(expired.body)).not.toContain("fixture-session_expired");

  cloud?.setState({ mode: "revoked" });
  const revoked = await browserJson(page, "/api/auth/session/resume", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: "{}",
  });
  expect(revoked.status).toBe(401);
  expect(revoked.body).toMatchObject({ error: { code: "session_revoked", message: "fixture-session_revoked" } });
  expect((await page.context().cookies()).find((cookie) => cookie.name === "__Host-agentpass_session")).toBeUndefined();
  expect(cloud?.observations()).toContainEqual(expect.objectContaining({ path: "/api/auth/session/resume", cookiePresent: true }));
});

test.afterAll(async () => {
  await cloud?.close();
  cloud = undefined;
});
