import assert from "node:assert/strict";
import test from "node:test";

import { chromium } from "../apps/web-console/node_modules/@playwright/test/index.mjs";
import { P0BSkip } from "./support/p0b/harness.mjs";
import { startP0BLiveBrowserFixture } from "./support/p0b/live-browser-fixture.mjs";

const enabled = process.env.P0B_LIVE_BROWSER === "1";
const scenarioFilter = process.env.P0B_LIVE_BROWSER_SCENARIO?.trim() ?? "";
let selectedScenarioCount = 0;

test("P0-B live browser role, WebAuthn, and recent-auth matrix", { skip: !enabled, timeout: 840_000 }, async (t) => {
  await scenario(t, "renders all six real PostgreSQL device states", async ({ open }) => {
    const page = await open("owner");
    await Promise.all([
      ["同期済み", "P0B_SAFE_STATE_MISSING_SYNCED"],
      ["反映待ち", "P0B_SAFE_STATE_MISSING_PENDING"],
      ["ブロック中", "P0B_SAFE_STATE_MISSING_BLOCKED"],
      ["古い状態", "P0B_SAFE_STATE_MISSING_STALE"],
      ["オフライン", "P0B_SAFE_STATE_MISSING_OFFLINE"],
      ["失効済み", "P0B_SAFE_STATE_MISSING_REVOKED"]
    ].map(([label, safeCode]) => page.getByLabel(`同期状態: ${label}`).waitFor()
      .catch(() => assert.fail(safeCode))));
  });

  await scenario(t, "accepts keyboard wake from the real pending device", async ({ open }) => {
    const page = await open("owner");
    const card = deviceCard(page, "反映待ち Mac");
    const wake = card.getByRole("button", { name: "Wake requestを依頼" });
    try {
      await wake.focus();
      assert.equal(await wake.evaluate((element) => element === document.activeElement), true);
    } catch { assert.fail("P0B_SAFE_KEYBOARD_FOCUS_FAILED"); }
    // Send Enter through the already-resolved control. This still exercises
    // keyboard activation while preventing a late focus shift (for example a
    // hydration or live-region update) from dispatching Enter to the page.
    try { await wake.press("Enter"); }
    catch { assert.fail("P0B_SAFE_KEYBOARD_PRESS_FAILED"); }
    try {
      assert.match(await requireWakeStatus(card, "P0B_SAFE_KEYBOARD_OUTCOME"), /依頼を受け付けました|既存の依頼へ統合し/u);
    } catch (error) {
      const marker = error instanceof Error && /^P0B_SAFE_KEYBOARD_OUTCOME_(?:ALERT|TIMEOUT|INVALID)_FAILED$/u.test(error.message)
        ? error.message
        : "P0B_SAFE_KEYBOARD_OUTCOME_FAILED";
      assert.fail(marker);
    }
  });

  await scenario(t, "shows accepted, coalesced, and no-pending outcomes from the real wake ledger", async ({ fixture, open }) => {
    await fixture.resetManualWakeEvidence();
    const page = await open("owner");
    for (const [name, expected, safeCode] of [
      ["反映待ち Mac", /依頼を受け付けました/u, "P0B_SAFE_WAKE_ACCEPTED_FAILED"],
      ["反映待ち Mac", /既存の依頼へ統合し/u, "P0B_SAFE_WAKE_COALESCED_FAILED"],
      ["古い状態 Mac", /反映待ちの更新はなく/u, "P0B_SAFE_WAKE_NO_PENDING_FAILED"]
    ]) {
      const card = deviceCard(page, name);
      try {
        await card.getByRole("button", { name: "Wake requestを依頼" }).click();
        assert.match(await requireWakeStatus(card), expected);
      } catch { assert.fail(safeCode); }
    }
  });

  await scenario(t, "admin completes real WebAuthn and wake mutation", async ({ open }) => {
    const page = await open("admin", { safeOpenPrefix: "P0B_SAFE_ADMIN_OPEN" });
    const card = deviceCard(page, "反映待ち Mac");
    try { await card.getByRole("button", { name: "Wake requestを依頼" }).click(); }
    catch { assert.fail("P0B_SAFE_ADMIN_WAKE_CLICK_FAILED"); }
    try { assert.match(await requireWakeStatus(card), /依頼を受け付けました|既存の依頼へ統合し/u); }
    catch { assert.fail("P0B_SAFE_ADMIN_WAKE_OUTCOME_FAILED"); }
  });

  for (const role of ["auditor", "viewer"]) {
    await scenario(t, `${role} receives no wake mutation control`, async ({ open }) => {
      let page;
      if (role === "auditor") page = await open(role, { safeOpenPrefix: "P0B_SAFE_AUDITOR_OPEN" });
      else {
        try { page = await open(role); }
        catch { assert.fail("P0B_SAFE_VIEWER_OPEN_FAILED"); }
      }
      const card = deviceCard(page, "反映待ち Mac");
      try { assert.equal(await card.getByRole("button", { name: "Wake requestを依頼" }).count(), 0); }
      catch { assert.fail(role === "auditor" ? "P0B_SAFE_AUDITOR_WAKE_CONTROL_FAILED" : "P0B_SAFE_VIEWER_WAKE_CONTROL_FAILED"); }
    });
  }

  await scenario(t, "owner without an available authenticator fails before wake mutation", async ({ open }) => {
    const page = await open("owner", { register: false });
    const mutation = mutationCounter(page);
    const card = deviceCard(page, "反映待ち Mac");
    await card.getByRole("button", { name: "Wake requestを依頼" }).click();
    await card.getByRole("alert").waitFor();
    assert.equal(mutation.count(), 0);
  });

  for (const failure of ["stale", "replayed", "cross_operation", "cross_tenant"]) {
    await scenario(t, `owner ${failure} authorization is rejected by the real Cloud boundary`, async ({ fixture, open }) => {
      const page = await open("owner");
      let intercepted = false;
      let responseStatus;
      page.on("response", (response) => {
        const url = new URL(response.url());
        if (response.request().method() === "POST" && url.pathname === "/api/console" && url.searchParams.get("operation") === "device.refresh.request") responseStatus = response.status();
      });
      const pattern = "**/api/console?operation=device.refresh.request";
      await page.route(pattern, async (route) => {
        if (route.request().method() !== "POST") return route.continue();
        intercepted = true;
        await fixture.invalidateRecentAuth("owner", failure);
        await route.continue();
      });
      const card = deviceCard(page, "反映待ち Mac");
      await card.getByRole("button", { name: "Wake requestを依頼" }).click();
      await card.getByRole("alert").waitFor();
      await page.unroute(pattern);
      assert.equal(intercepted, true);
      assert.equal(responseStatus, 401);
    });
  }

  for (const [role, deviceName] of [["owner", "同期済み Mac"], ["admin", "オフライン Mac"]]) {
    await scenario(t, `${role} completes distinct real WebAuthn device revoke`, async ({ open }) => {
      const page = await open(role);
      await page.getByRole("button", { name: "セットアップ", exact: true }).click();
      const device = page.getByRole("listitem").filter({ hasText: deviceName });
      await device.getByRole("button", { name: "停止" }).click();
      await page.getByText(`${deviceName}を停止しました`).waitFor();
    });
  }

  if (scenarioFilter !== "" && selectedScenarioCount === 0) assert.fail("P0B_SAFE_SCENARIO_NOT_FOUND");
});

async function scenario(parent, name, callback) {
  if (scenarioFilter !== "" && !name.includes(scenarioFilter)) return;
  selectedScenarioCount += 1;
  // Each scenario intentionally starts a fresh PostgreSQL/Cloud/Console stack.
  // Hosted CI can spend most of the fixture's 30-second readiness budget before
  // Chromium registration begins, so the scenario timeout must not race that
  // bounded startup deadline. UI assertions still retain Playwright's focused
  // per-action timeout and therefore fail promptly when a state is absent.
  await parent.test(name, { timeout: 75_000 }, async () => {
    let fixture;
    let browser;
    try {
      try { fixture = await startP0BLiveBrowserFixture({ waitTimeoutMs: 30_000 }); }
      catch (error) {
        if (error instanceof P0BSkip) assert.fail(`live browser qualification cannot skip: ${error.code}`);
        throw error;
      }
      browser = await chromium.launch({ headless: true, args: [`--ignore-certificate-errors-spki-list=${fixture.tlsSpkiPin}`] });
      const contexts = [];
      const open = async (role, { register = true, safeOpenPrefix = null } = {}) => {
        const effectiveSafeOpenPrefix = safeOpenPrefix ?? (role === "owner" ? "P0B_SAFE_OWNER_OPEN" : null);
        let context;
        let page;
        try {
          context = await browser.newContext({ ignoreHTTPSErrors: false });
          contexts.push(context);
          page = await context.newPage();
        } catch { failSafeOpen(effectiveSafeOpenPrefix, "CONTEXT"); }
        if (register) {
          try { await fixture.installVirtualAuthenticator(page, role); }
          catch { failSafeOpen(effectiveSafeOpenPrefix, "AUTHENTICATOR"); }
        }
        try { await fixture.bootstrap(page, role); }
        catch (error) {
          const bootstrap503Marker = safeBootstrap503Marker(error?.code);
          if (bootstrap503Marker !== null) assert.fail(bootstrap503Marker);
          if (effectiveSafeOpenPrefix === "P0B_SAFE_OWNER_OPEN") {
            const ownerMarker = safeRoleBootstrapMarker(error?.code, effectiveSafeOpenPrefix);
            if (ownerMarker !== null) assert.fail(ownerMarker);
          }
          if (effectiveSafeOpenPrefix === "P0B_SAFE_ADMIN_OPEN") {
            if (error?.code === "session_bootstrap_navigation_failed") assert.fail("P0B_SAFE_ADMIN_OPEN_BOOTSTRAP_NAVIGATION_FAILED");
            if (error?.code === "session_bootstrap_response_failed") assert.fail("P0B_SAFE_ADMIN_OPEN_BOOTSTRAP_RESPONSE_FAILED");
            if (error?.code === "session_bootstrap_http_400_failed") assert.fail("P0B_SAFE_ADMIN_OPEN_BOOTSTRAP_HTTP_400_FAILED");
            if (error?.code === "session_bootstrap_http_401_failed") assert.fail("P0B_SAFE_ADMIN_OPEN_BOOTSTRAP_HTTP_401_FAILED");
            if (error?.code === "session_bootstrap_http_403_failed") assert.fail("P0B_SAFE_ADMIN_OPEN_BOOTSTRAP_HTTP_403_FAILED");
            if (error?.code === "session_bootstrap_http_404_failed") assert.fail("P0B_SAFE_ADMIN_OPEN_BOOTSTRAP_HTTP_404_FAILED");
            if (error?.code === "session_bootstrap_http_405_failed") assert.fail("P0B_SAFE_ADMIN_OPEN_BOOTSTRAP_HTTP_405_FAILED");
            if (error?.code === "session_bootstrap_http_409_failed") assert.fail("P0B_SAFE_ADMIN_OPEN_BOOTSTRAP_HTTP_409_FAILED");
            if (error?.code === "session_bootstrap_http_415_failed") assert.fail("P0B_SAFE_ADMIN_OPEN_BOOTSTRAP_HTTP_415_FAILED");
            if (error?.code === "session_bootstrap_http_422_failed") assert.fail("P0B_SAFE_ADMIN_OPEN_BOOTSTRAP_HTTP_422_FAILED");
            if (error?.code === "session_bootstrap_http_429_failed") assert.fail("P0B_SAFE_ADMIN_OPEN_BOOTSTRAP_HTTP_429_FAILED");
            if (error?.code === "session_bootstrap_http_500_failed") assert.fail("P0B_SAFE_ADMIN_OPEN_BOOTSTRAP_HTTP_500_FAILED");
            if (error?.code === "session_bootstrap_http_502_bff_invalid_response_failed") assert.fail("P0B_SAFE_ADMIN_OPEN_BOOTSTRAP_HTTP_502_BFF_INVALID_RESPONSE_FAILED");
            if (error?.code === "session_bootstrap_http_502_proxy_unavailable_failed") assert.fail("P0B_SAFE_ADMIN_OPEN_BOOTSTRAP_HTTP_502_PROXY_UNAVAILABLE_FAILED");
            if (error?.code === "session_bootstrap_http_502_cloud_exited_failed") assert.fail("P0B_SAFE_ADMIN_OPEN_BOOTSTRAP_HTTP_502_CLOUD_EXITED_FAILED");
            if (error?.code === "session_bootstrap_http_504_failed") assert.fail("P0B_SAFE_ADMIN_OPEN_BOOTSTRAP_HTTP_504_FAILED");
            if (error?.code === "session_bootstrap_http_4xx_failed") assert.fail("P0B_SAFE_ADMIN_OPEN_BOOTSTRAP_HTTP_4XX_FAILED");
            if (error?.code === "session_bootstrap_http_5xx_failed") assert.fail("P0B_SAFE_ADMIN_OPEN_BOOTSTRAP_HTTP_5XX_FAILED");
            if (error?.code === "session_bootstrap_http_other_failed") assert.fail("P0B_SAFE_ADMIN_OPEN_BOOTSTRAP_HTTP_OTHER_FAILED");
            if (error?.code === "session_bootstrap_contract_failed") assert.fail("P0B_SAFE_ADMIN_OPEN_BOOTSTRAP_CONTRACT_FAILED");
          }
          failSafeOpen(effectiveSafeOpenPrefix, "BOOTSTRAP");
        }
        if (register) {
          try { await fixture.registerWebAuthn(page); }
          catch (error) {
            const registrationMarker = safeRegistrationMarker(error?.code, effectiveSafeOpenPrefix);
            if (registrationMarker !== null) assert.fail(registrationMarker);
            failSafeOpen(effectiveSafeOpenPrefix, "REGISTRATION");
          }
        }
        try { await page.reload({ waitUntil: "domcontentloaded" }); }
        catch { failSafeOpen(effectiveSafeOpenPrefix, "RELOAD"); }
        try {
          await page.getByRole("heading", { name: /Agentの状態を、\s*確認できました。/u }).waitFor();
          await deviceCard(page, "反映待ち Mac").getByRole("heading", { name: "反映待ち Mac" }).waitFor();
        } catch { failSafeOpen(effectiveSafeOpenPrefix, "READINESS"); }
        return page;
      };
      await callback({ fixture, browser, open });
      await Promise.all(contexts.map((context) => context.close()));
    } finally {
      await browser?.close().catch(() => {});
      await fixture?.close().catch(() => {});
    }
  });
}

function safeBootstrap503Marker(code) {
  const suffix = new Map([
    ["session_bootstrap_http_503_session_unavailable_failed", "SESSION_UNAVAILABLE"],
    ["session_bootstrap_http_503_human_auth_unavailable_failed", "HUMAN_AUTH_UNAVAILABLE"],
    ["session_bootstrap_http_503_rate_limiter_unavailable_failed", "RATE_LIMITER_UNAVAILABLE"],
    ["session_bootstrap_http_503_cloud_api_unavailable_failed", "CLOUD_API_UNAVAILABLE"],
    ["session_bootstrap_http_503_identity_unavailable_failed", "IDENTITY_UNAVAILABLE"],
    ["session_bootstrap_http_503_other_failed", "OTHER"],
  ]).get(code);
  return suffix === undefined ? null : `P0B_SAFE_BOOTSTRAP_HTTP_503_${suffix}_FAILED`;
}

function safeRoleBootstrapMarker(code, prefix) {
  const suffix = new Map([
    ["session_bootstrap_navigation_failed", "NAVIGATION"],
    ["session_bootstrap_response_failed", "RESPONSE"],
    ["session_bootstrap_http_400_failed", "HTTP_400"],
    ["session_bootstrap_http_401_failed", "HTTP_401"],
    ["session_bootstrap_http_403_failed", "HTTP_403"],
    ["session_bootstrap_http_404_failed", "HTTP_404"],
    ["session_bootstrap_http_405_failed", "HTTP_405"],
    ["session_bootstrap_http_409_failed", "HTTP_409"],
    ["session_bootstrap_http_415_failed", "HTTP_415"],
    ["session_bootstrap_http_422_failed", "HTTP_422"],
    ["session_bootstrap_http_429_failed", "HTTP_429"],
    ["session_bootstrap_http_500_failed", "HTTP_500"],
    ["session_bootstrap_http_502_bff_invalid_response_failed", "HTTP_502_BFF_INVALID_RESPONSE"],
    ["session_bootstrap_http_502_proxy_unavailable_failed", "HTTP_502_PROXY_UNAVAILABLE"],
    ["session_bootstrap_http_502_cloud_exited_failed", "HTTP_502_CLOUD_EXITED"],
    ["session_bootstrap_http_504_failed", "HTTP_504"],
    ["session_bootstrap_http_4xx_failed", "HTTP_4XX"],
    ["session_bootstrap_http_5xx_failed", "HTTP_5XX"],
    ["session_bootstrap_http_other_failed", "HTTP_OTHER"],
    ["session_bootstrap_contract_failed", "CONTRACT"]
  ]).get(code);
  return suffix === undefined ? null : `${prefix}_BOOTSTRAP_${suffix}_FAILED`;
}

function safeRegistrationMarker(code, prefix) {
  if (prefix !== "P0B_SAFE_OWNER_OPEN") return null;
  const detailed = new Map([
    ["registration_options_503_human_auth_control_unavailable", "OPTIONS_503_CONTROL_UNAVAILABLE"],
    ["registration_options_503_webauthn_registration_http_session_unavailable", "OPTIONS_503_SESSION_UNAVAILABLE"],
    ["registration_options_503_webauthn_registration_http_unavailable", "OPTIONS_503_SERVICE_UNAVAILABLE"],
    ["registration_verify_401_webauthn_registration_http_session_required", "VERIFY_401_SESSION_REQUIRED"],
    ["registration_verify_401_webauthn_registration_http_session_required_missing", "VERIFY_401_SESSION_MISSING"],
    ["registration_verify_401_webauthn_registration_http_session_required_revoked", "VERIFY_401_SESSION_REVOKED"],
    ["registration_verify_401_webauthn_registration_http_session_required_revoked_expired", "VERIFY_401_SESSION_REVOKED_EXPIRED"],
    ["registration_verify_401_webauthn_registration_http_session_required_revoked_concurrent_session_limit", "VERIFY_401_SESSION_REVOKED_CONCURRENT"],
    ["registration_verify_401_webauthn_registration_http_session_required_revoked_session_rotation", "VERIFY_401_SESSION_REVOKED_ROTATED"],
    ["registration_verify_401_webauthn_registration_http_session_required_revoked_logout", "VERIFY_401_SESSION_REVOKED_LOGOUT"],
    ["registration_verify_401_webauthn_registration_http_session_required_revoked_other", "VERIFY_401_SESSION_REVOKED_OTHER"],
    ["registration_verify_401_webauthn_registration_http_session_required_absolute_expired", "VERIFY_401_SESSION_ABSOLUTE_EXPIRED"],
    ["registration_verify_401_webauthn_registration_http_session_required_idle_expired", "VERIFY_401_SESSION_IDLE_EXPIRED"],
    ["registration_verify_401_webauthn_registration_http_session_required_active", "VERIFY_401_SESSION_ACTIVE"],
    ["registration_verify_401_webauthn_registration_http_session_required_unavailable", "VERIFY_401_SESSION_UNAVAILABLE"],
    ["registration_verify_401_session_required", "VERIFY_401_COOKIE_MISSING"]
  ]).get(code);
  if (detailed !== undefined) return `${prefix}_REGISTRATION_${detailed}_FAILED`;
  const match = String(code ?? "").match(/^registration_(options|verify)_(400|401|403|409|413|422|428|500|503)(?:_[a-z][a-z0-9_]{0,95})?$/u);
  return match === null ? null : `${prefix}_REGISTRATION_${match[1].toUpperCase()}_${match[2]}_FAILED`;
}

async function requireWakeStatus(card, failurePrefix) {
  const outcome = await Promise.race([
    card.getByRole("status").waitFor().then(() => "status").catch(() => null),
    card.getByRole("alert").waitFor().then(() => "alert").catch(() => null),
  ]);
  if (outcome === "alert") {
    if (failurePrefix !== undefined) throw new Error(`${failurePrefix}_ALERT_FAILED`);
    assert.fail("wake failed");
  }
  if (outcome !== "status") {
    if (failurePrefix !== undefined) throw new Error(`${failurePrefix}_TIMEOUT_FAILED`);
    assert.fail("wake status unavailable");
  }
  try { return await card.getByRole("status").innerText(); }
  catch {
    if (failurePrefix !== undefined) throw new Error(`${failurePrefix}_INVALID_FAILED`);
    throw new Error("wake status unavailable");
  }
}

function deviceCard(page, name) { return page.getByRole("article").filter({ has: page.getByRole("heading", { name }) }); }

function mutationCounter(page) {
  let calls = 0;
  page.on("request", (request) => {
    const url = new URL(request.url());
    if (request.method() === "POST" && url.pathname === "/api/console" && url.searchParams.get("operation") === "device.refresh.request") calls += 1;
  });
  return Object.freeze({ count: () => calls });
}

function failSafeOpen(prefix, stage) {
  if (typeof prefix === "string" && /^[A-Z0-9_]{1,64}$/u.test(prefix)) assert.fail(`${prefix}_${stage}_FAILED`);
  throw new Error("P0-B browser open failed");
}
