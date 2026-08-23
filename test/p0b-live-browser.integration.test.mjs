import assert from "node:assert/strict";
import test from "node:test";

import { chromium } from "../apps/web-console/node_modules/@playwright/test/index.mjs";
import { P0BSkip } from "./support/p0b/harness.mjs";
import { P0BLiveBrowserFixtureError, runP0BLifecycle, startP0BLiveBrowserFixture } from "./support/p0b/live-browser-fixture.mjs";

// Keep supervisor diagnostics fixed and secret-free when the browser child
// exits before Node's TAP reporter can serialize a test failure.
process.on("uncaughtExceptionMonitor", () => process.stderr.write("P0B_SAFE_CHILD_UNCAUGHT_EXCEPTION\n"));
process.on("unhandledRejection", () => process.stderr.write("P0B_SAFE_CHILD_UNHANDLED_REJECTION\n"));

const enabled = process.env.P0B_LIVE_BROWSER === "1";
if (enabled) process.stderr.write("P0B_STAGE_TEST_MODULE_START\n");
const scenarioFilter = process.env.P0B_LIVE_BROWSER_SCENARIO?.trim() ?? "";
const BROWSER_STARTUP_TIMEOUT_MS = 15_000;
const BROWSER_CLEANUP_TIMEOUT_MS = 15_000;
const CONTEXT_CLEANUP_TIMEOUT_MS = 10_000;
const WAKE_OUTCOME_TIMEOUT_MS = 15_000;
const SCENARIO_RUNTIME_TIMEOUT_MS = 150_000;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
let selectedScenarioCount = 0;

// Thirteen authority scenarios each own a fresh TLS PostgreSQL/Cloud/Console
// stack. A complete successful matrix is longer than the earlier failure-
// masked 14-minute ceiling on hosted runners. The first complete traversal
// reached its thirteenth isolated stack after 20 minutes; per-scenario
// 120-second bounds remain the owning hang detector.
test("P0-B live browser role, WebAuthn, and recent-auth matrix", { skip: !enabled, timeout: 1_800_000 }, async (t) => {
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
    let refreshRequestObserved = false;
    let refreshRequestFailed = false;
    const recentAuthObservation = {
      optionsObserved: false,
      optionsFailed: false,
      optionsStatus: null,
      verifyObserved: false,
      verifyFailed: false,
      verifyStatus: null,
      verifyResponse: null,
      sessionObserved: false,
      sessionFailed: false,
      sessionStatus: null,
      webAuthnSupported: await page.evaluate(() => typeof window.PublicKeyCredential !== "undefined" && typeof navigator.credentials?.get === "function"),
    };
    page.on("request", (request) => {
      if (isKeyboardRefreshRequest(request)) refreshRequestObserved = true;
      const phase = keyboardRecentAuthPhase(request);
      if (phase === "options") recentAuthObservation.optionsObserved = true;
      if (phase === "verify") recentAuthObservation.verifyObserved = true;
      if (isKeyboardSessionRequest(request)) recentAuthObservation.sessionObserved = true;
    });
    page.on("requestfailed", (request) => {
      if (isKeyboardRefreshRequest(request)) refreshRequestFailed = true;
      const phase = keyboardRecentAuthPhase(request);
      if (phase === "options") recentAuthObservation.optionsFailed = true;
      if (phase === "verify") recentAuthObservation.verifyFailed = true;
      if (isKeyboardSessionRequest(request)) recentAuthObservation.sessionFailed = true;
    });
    page.on("response", (response) => {
      const phase = keyboardRecentAuthPhase(response.request());
      if (phase === "options") recentAuthObservation.optionsStatus = response.status();
      if (phase === "verify") {
        recentAuthObservation.verifyStatus = response.status();
        recentAuthObservation.verifyResponse = response;
      }
      if (isKeyboardSessionRequest(response.request())) recentAuthObservation.sessionStatus = response.status();
    });
    const refreshResponsePromise = page.waitForResponse((response) => {
      return isKeyboardRefreshRequest(response.request());
    }, { timeout: 15_000 }).catch(() => null);
    // Send Enter through the already-resolved control. This still exercises
    // keyboard activation while preventing a late focus shift (for example a
    // hydration or live-region update) from dispatching Enter to the page.
    try { await wake.press("Enter"); }
    catch { assert.fail("P0B_SAFE_KEYBOARD_PRESS_FAILED"); }
    const refreshResponse = await refreshResponsePromise;
    try {
      assert.match(await requireWakeStatus(card, "P0B_SAFE_KEYBOARD_OUTCOME"), /依頼を受け付けました|既存の依頼へ統合し/u);
    } catch (error) {
      assert.fail(await keyboardOutcomeFailureMarker(refreshResponse, { refreshRequestObserved, refreshRequestFailed, recentAuthObservation }));
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
      const diagnosis = safeCode === "P0B_SAFE_WAKE_ACCEPTED_FAILED" ? observeWakeAttempt(page) : null;
      try {
        await card.getByRole("button", { name: "Wake requestを依頼" }).click();
        assert.match(await requireWakeStatus(card), expected);
      } catch {
        if (diagnosis !== null) {
          const refreshResponse = await diagnosis.refreshResponsePromise;
          assert.fail(await wakeAcceptedFailureMarker(refreshResponse, diagnosis.observation));
        }
        assert.fail(safeCode);
      }
    }
  });

  await scenario(t, "admin completes real WebAuthn and wake mutation", async ({ open }) => {
    const page = await open("admin", { safeOpenPrefix: "P0B_SAFE_ADMIN_OPEN" });
    const card = deviceCard(page, "反映待ち Mac");
    const diagnosis = observeWakeAttempt(page);
    try { await card.getByRole("button", { name: "Wake requestを依頼" }).click(); }
    catch { assert.fail("P0B_SAFE_ADMIN_WAKE_CLICK_FAILED"); }
    try {
      assert.match(await requireWakeStatus(card, "P0B_SAFE_ADMIN_WAKE_UI"), /依頼を受け付けました|既存の依頼へ統合し/u);
    } catch (error) {
      const refreshResponse = await diagnosis.refreshResponsePromise;
      const uiFailure = error instanceof Error && error.message === "P0B_SAFE_ADMIN_WAKE_UI_ALERT_FAILED"
        ? "alert"
        : error instanceof Error && error.message === "P0B_SAFE_ADMIN_WAKE_UI_TIMEOUT_FAILED"
          ? "timeout"
          : "copy_mismatch";
      assert.fail(await adminWakeFailureMarker(refreshResponse, diagnosis.observation, uiFailure));
    }
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
    try { await card.getByRole("button", { name: "Wake requestを依頼" }).click(); }
    catch { assert.fail("P0B_SAFE_MISSING_AUTHENTICATOR_WAKE_CLICK_FAILED"); }
    try { await card.getByRole("button", { name: "確認して送信" }).click(); }
    catch { assert.fail("P0B_SAFE_MISSING_AUTHENTICATOR_CONFIRM_FAILED"); }
    try { await card.getByRole("alert").waitFor(); }
    catch { assert.fail("P0B_SAFE_MISSING_AUTHENTICATOR_ALERT_FAILED"); }
    try { assert.equal(mutation.count(), 0); }
    catch { assert.fail("P0B_SAFE_MISSING_AUTHENTICATOR_MUTATION_FAILED"); }
  });

  for (const failure of ["stale", "replayed", "cross_operation", "cross_tenant"]) {
    await scenario(t, `owner ${failure} authorization is rejected by the real Cloud boundary`, async ({ fixture, open }) => {
      const page = await open("owner", { safeOpenPrefix: "P0B_SAFE_OWNER_OPEN" });
      const targetId = fixture.devices.find(({ label }) => label === "反映待ち Mac")?.deviceId;
      if (failure === "stale" && !UUID.test(targetId ?? "")) assert.fail("P0B_SAFE_STALE_AUTH_TARGET_FAILED");
      assert.match(targetId ?? "", UUID);
      if (failure === "stale") {
        let outcome;
        try {
          outcome = await fixture.withRecentAuth(page, "device.refresh.request", async ({ authorizationId, csrfToken }) => {
            try { await fixture.invalidateRecentAuth(page, failure); }
            catch { return Object.freeze({ phase: "invalidation_failed", status: null }); }
            try {
              const status = await requestRefreshStatus(page, { authorizationId, csrfToken, targetId });
              return Object.freeze({ phase: "response", status });
            } catch {
              return Object.freeze({ phase: "fetch_failed", status: null });
            }
          });
        } catch (error) {
          assert.fail(staleAuthCeremonyFailureMarker(error));
        }
        const marker = staleAuthorizationFailureMarker(outcome);
        if (marker !== null) assert.fail(marker);
        return;
      }
      const responseStatus = await fixture.withRecentAuth(page, "device.refresh.request", async ({ authorizationId, csrfToken }) => {
        await fixture.invalidateRecentAuth(page, failure);
        return requestRefreshStatus(page, { authorizationId, csrfToken, targetId });
      });
      assert.equal(responseStatus, 401);
    });
  }

  for (const [role, deviceName] of [["owner", "同期済み Mac"], ["admin", "オフライン Mac"]]) {
    await scenario(t, `${role} completes distinct real WebAuthn device revoke`, async ({ open }) => {
      let page;
      try { page = await open(role, role === "admin" ? { safeOpenPrefix: "P0B_SAFE_ADMIN_OPEN" } : {}); }
      catch { if (role === "admin") assert.fail("P0B_SAFE_ADMIN_FINAL_OPEN_FAILED"); throw new Error("owner final open failed"); }
      try { await page.getByRole("button", { name: "セットアップ", exact: true }).click(); }
      catch { if (role === "admin") assert.fail("P0B_SAFE_ADMIN_FINAL_SETUP_FAILED"); throw new Error("owner final setup failed"); }
      const device = page.getByRole("listitem").filter({ hasText: deviceName });
      try { await device.getByRole("button", { name: "停止" }).click(); }
      catch { if (role === "admin") assert.fail("P0B_SAFE_ADMIN_FINAL_STOP_FAILED"); throw new Error("owner final stop failed"); }
      try { await page.getByText(`${deviceName}を停止しました`).waitFor(); }
      catch { if (role === "admin") assert.fail("P0B_SAFE_ADMIN_FINAL_CONFIRM_FAILED"); throw new Error("owner final confirmation failed"); }
    });
  }

  if (scenarioFilter !== "" && selectedScenarioCount === 0) assert.fail("P0B_SAFE_SCENARIO_NOT_FOUND");
});

async function requestRefreshStatus(page, { authorizationId, csrfToken, targetId }) {
  return page.evaluate(async ({ authorizationId, csrfToken, targetId }) => {
    const response = await fetch("/api/console?operation=device.refresh.request", {
      method: "POST",
      headers: {
        accept: "application/json",
        "content-type": "application/json",
        "agentpass-csrf": csrfToken,
        "agentpass-recent-auth": authorizationId,
        "idempotency-key": crypto.randomUUID()
      },
      credentials: "same-origin",
      cache: "no-store",
      redirect: "error",
      body: JSON.stringify({ target_id: targetId })
    });
    await response.arrayBuffer();
    return response.status;
  }, { authorizationId, csrfToken, targetId });
}

export function staleAuthorizationFailureMarker(outcome) {
  if (outcome?.phase === "invalidation_failed") return "P0B_SAFE_STALE_AUTH_INVALIDATION_FAILED";
  if (outcome?.phase === "fetch_failed") return "P0B_SAFE_STALE_AUTH_FETCH_FAILED";
  if (outcome?.phase !== "response" || !Number.isInteger(outcome.status)) return "P0B_SAFE_STALE_AUTH_RESPONSE_FAILED";
  if (outcome.status === 401) return null;
  if (outcome.status >= 200 && outcome.status < 300) return "P0B_SAFE_STALE_AUTH_HTTP_2XX_FAILED";
  if (outcome.status >= 400 && outcome.status < 500) return "P0B_SAFE_STALE_AUTH_HTTP_4XX_FAILED";
  if (outcome.status >= 500 && outcome.status < 600) return "P0B_SAFE_STALE_AUTH_HTTP_5XX_FAILED";
  return "P0B_SAFE_STALE_AUTH_HTTP_OTHER_FAILED";
}

export function staleAuthCeremonyFailureMarker(error) {
  const code = typeof error?.code === "string" ? error.code : "";
  if (code.startsWith("recent_auth_options_")) return "P0B_SAFE_STALE_AUTH_CEREMONY_OPTIONS_FAILED";
  if (code.startsWith("recent_auth_verify_")) return "P0B_SAFE_STALE_AUTH_CEREMONY_VERIFY_FAILED";
  if (code === "recent_auth_response_invalid") return "P0B_SAFE_STALE_AUTH_CEREMONY_RESPONSE_FAILED";
  return "P0B_SAFE_STALE_AUTH_CEREMONY_FAILED";
}

async function scenario(parent, name, callback) {
  if (scenarioFilter !== "" && !name.includes(scenarioFilter)) return;
  selectedScenarioCount += 1;
  const scenarioOrdinal = selectedScenarioCount;
  // Each scenario intentionally starts a fresh PostgreSQL/Cloud/Console stack.
  // Hosted CI can spend most of the fixture's 30-second readiness budget before
  // Chromium registration begins, so the scenario timeout must not race that
  // bounded startup deadline. UI assertions still retain Playwright's focused
  // per-action timeout and therefore fail promptly when a state is absent.
  await parent.test(name, { timeout: 120_000 }, async () => {
    const runtimeTimer = setTimeout(() => process.stderr.write("P0B_SAFE_SCENARIO_RUNTIME_TIMEOUT_FAILED\n"), SCENARIO_RUNTIME_TIMEOUT_MS);
    let fixture;
    let browser;
    let scenarioError;
    let cleanupError;
    let browserCleanupAttempted = false;
    try {
      try {
        fixture = await startP0BLiveBrowserFixture({
          waitTimeoutMs: 30_000,
          startupTimeoutMs: 90_000,
          cleanupTimeoutMs: BROWSER_CLEANUP_TIMEOUT_MS
        });
      }
      catch (error) {
        if (error instanceof P0BSkip) assert.fail("P0B_SAFE_LIFECYCLE_EXTERNAL_DEPENDENCY_FAILED");
        failLifecycle(error);
      }
      try {
        emitLiveStage("BROWSER_START");
        browser = await runP0BLifecycle(
          () => chromium.launch({ headless: true, args: [`--ignore-certificate-errors-spki-list=${fixture.tlsSpkiPin}`] }),
          {
            timeoutMs: BROWSER_STARTUP_TIMEOUT_MS,
            timeoutCode: "browser_startup_timeout",
            timeoutMessage: "P0-B live browser startup timed out",
            onLateSuccess: (lateBrowser) => lateBrowser?.close?.()
          }
        );
      } catch (error) {
        throw error instanceof P0BLiveBrowserFixtureError
          ? error
          : new P0BLiveBrowserFixtureError("browser_startup_failed", "P0-B live browser startup failed");
      }
      emitLiveStage("BROWSER_READY");
      const contexts = [];
      const open = async (role, { register = true, safeOpenPrefix = null } = {}) => {
        const effectiveSafeOpenPrefix = safeOpenPrefix ?? (role === "owner" ? "P0B_SAFE_OWNER_OPEN" : null);
        let context;
        let page;
        try {
          emitLiveStage("OPEN_CONTEXT");
          context = await runP0BLifecycle(
            () => browser.newContext({ ignoreHTTPSErrors: false }),
            {
              timeoutMs: BROWSER_STARTUP_TIMEOUT_MS,
              timeoutCode: "context_startup_timeout",
              timeoutMessage: "P0-B browser context startup timed out",
              onLateSuccess: (lateContext) => lateContext?.close?.()
            }
          );
          contexts.push(context);
          emitLiveStage("OPEN_PAGE");
          page = await runP0BLifecycle(
            () => context.newPage(),
            {
              timeoutMs: BROWSER_STARTUP_TIMEOUT_MS,
              timeoutCode: "page_startup_timeout",
              timeoutMessage: "P0-B browser page startup timed out",
              onLateSuccess: () => context.close()
            }
          );
        } catch { failSafeOpen(effectiveSafeOpenPrefix, "CONTEXT"); }
        let summaryStatus = null;
        let summaryErrorCode = null;
        let deploymentStatus = null;
        let summaryBodyCode = null;
        let summaryParseDiagnostic = null;
        let summaryRefreshDiagnostic = null;
        const summaryStatuses = [];
        let summaryBodyPromise = Promise.resolve();
        const summaryResponseListener = (response) => {
          try {
            const url = new URL(response.url());
            if (url.pathname === "/api/console" && url.searchParams.get("resource") === "deployment-readiness") {
              deploymentStatus ??= response.status();
              return;
            }
            if (url.pathname === "/api/console" && url.searchParams.get("resource") === "summary") {
              summaryStatus = response.status();
              if (summaryStatuses.length < 8) summaryStatuses.push(summaryStatus);
              summaryBodyCode = null;
              if (summaryStatus >= 500) process.stderr.write(`P0B_DIAGNOSTIC_SUMMARY_STATUS status=${summaryStatus}\n`);
              if (summaryStatus >= 500) {
                let statusText = "none";
                try {
                  const candidateStatusText = response.statusText();
                  if (typeof candidateStatusText === "string" && /^[a-z][a-z0-9_]{0,63}$/u.test(candidateStatusText)) statusText = candidateStatusText;
                } catch {}
                process.stderr.write(`P0B_DIAGNOSTIC_SUMMARY_CODE code=${statusText}\n`);
                let responseHeaders = {};
                try {
                  const candidateHeaders = response.headers();
                  if (candidateHeaders && typeof candidateHeaders === "object") responseHeaders = candidateHeaders;
                } catch {}
                const rawContentType = responseHeaders["content-type"];
                const contentType = typeof rawContentType === "string" ? rawContentType.split(";", 1)[0]?.trim().toLowerCase() : undefined;
                const headerCode = responseHeaders["x-agentpass-error-code"];
                process.stderr.write(`P0B_DIAGNOSTIC_SUMMARY_HEADER status=${summaryStatus} code=${typeof headerCode === "string" && /^[a-z][a-z0-9_]{0,63}$/.test(headerCode) ? headerCode : "none"} content_type=${contentType === "application/json" ? "json" : "other"}\n`);
                summaryErrorCode = typeof headerCode === "string" && /^[a-z][a-z0-9_]{0,63}$/.test(headerCode)
                  ? headerCode
                  : contentType === "application/json" ? "body_pending" : "cloud_api_invalid_response";
              }
              summaryBodyPromise = response.text().then((text) => {
                  try {
                    const body = JSON.parse(text);
                    if (summaryStatus >= 500) {
                      const code = body?.error?.code;
                      summaryErrorCode = typeof code === "string" && /^[a-z][a-z0-9_]{0,63}$/.test(code) ? code : "body_unavailable";
                    } else {
                      const keys = (value) => value && typeof value === "object" && !Array.isArray(value) ? Object.keys(value).sort().join(",") : "";
                      summaryBodyCode = keys(body) === "agents,audit,devices,organization,policies"
                        && keys(body.organization) === "created_at,name,organization_id,updated_at,version"
                        && Array.isArray(body.devices) && Array.isArray(body.agents) && Array.isArray(body.policies)
                        && keys(body.audit) === "activity,health,next_cursor" ? "body_shape_ok" : "body_shape_invalid";
                    }
                  } catch {
                    if (summaryStatus >= 500) summaryErrorCode = "body_unavailable";
                    else summaryBodyCode = "body_invalid";
                  }
                }).catch(() => {
                  if (summaryStatus >= 500) summaryErrorCode = "body_unavailable";
                  else summaryBodyCode = "body_invalid";
              });
            }
          } catch {}
        };
        page.on("response", summaryResponseListener);
        page.on("console", (message) => {
          const match = message.text().match(/^AgentPass summary contract rejected ([.$\w\[\]]+) ([a-z_]+)$/u);
          if (match && match[1].length <= 128 && match[2].length <= 64) summaryParseDiagnostic = Object.freeze({ path: match[1], reason: match[2] });
          const refresh = message.text().match(/^AgentPass summary refresh rejected ([A-Za-z0-9_.:-]{1,96})$/u);
          if (refresh) summaryRefreshDiagnostic = refresh[1];
        });
        if (register) {
          emitLiveStage("OPEN_AUTHENTICATOR");
          try { await fixture.installVirtualAuthenticator(page, role); }
          catch { failSafeOpen(effectiveSafeOpenPrefix, "AUTHENTICATOR"); }
        }
        emitLiveStage("OPEN_BOOTSTRAP");
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
        emitLiveStage("OPEN_RELOAD");
        try { await fixture.reloadAndAdoptSession(page); }
        catch { failSafeOpen(effectiveSafeOpenPrefix, "RELOAD"); }
        emitLiveStage("OPEN_READY");
        try {
          await page.getByRole("heading", { name: /Agentの状態を、\s*確認できました。/u }).waitFor({ timeout: 30_000 });
          await deviceCard(page, "反映待ち Mac").getByRole("heading", { name: "反映待ち Mac" }).waitFor({ timeout: 30_000 });
          emitLiveStage("OPEN_UI_READY");
        } catch {
          if (effectiveSafeOpenPrefix === "P0B_SAFE_OWNER_OPEN") {
            const summaryReady = await page.getByRole("heading", { name: /Agentの状態を、\s*確認できました。/u }).count().catch(() => 0);
            if (summaryReady === 0) {
              await Promise.race([summaryBodyPromise, new Promise((resolve) => setTimeout(resolve, 5_000))]);
              if (summaryStatus === null) assert.fail("P0B_SAFE_OWNER_OPEN_SUMMARY_NO_RESPONSE_FAILED");
              if (summaryStatus === 401) assert.fail("P0B_SAFE_OWNER_OPEN_SUMMARY_HTTP_401_FAILED");
              if (summaryStatus === 403) assert.fail("P0B_SAFE_OWNER_OPEN_SUMMARY_HTTP_403_FAILED");
              if (deploymentStatus === 401) assert.fail("P0B_SAFE_OWNER_OPEN_DEPLOYMENT_HTTP_401_FAILED");
              if (deploymentStatus === 403) assert.fail("P0B_SAFE_OWNER_OPEN_DEPLOYMENT_HTTP_403_FAILED");
              if (summaryParseDiagnostic !== null) {
                process.stdout.write(`P0B_DIAGNOSTIC_SUMMARY_PARSE path=${summaryParseDiagnostic.path} reason=${summaryParseDiagnostic.reason}\n`);
              }
              if (summaryRefreshDiagnostic !== null) process.stdout.write(`P0B_DIAGNOSTIC_SUMMARY_REFRESH code=${summaryRefreshDiagnostic}\n`);
              if (summaryStatuses.length > 0) process.stdout.write(`P0B_DIAGNOSTIC_SUMMARY_RESPONSES statuses=${summaryStatuses.join(",")}\n`);
              if (summaryBodyCode === "body_invalid") assert.fail("P0B_SAFE_OWNER_OPEN_SUMMARY_BODY_INVALID_FAILED");
              if (summaryBodyCode === "body_shape_invalid") assert.fail("P0B_SAFE_OWNER_OPEN_SUMMARY_BODY_SHAPE_FAILED");
              if (summaryBodyCode === "body_shape_ok") assert.fail("P0B_SAFE_OWNER_OPEN_SUMMARY_BODY_SHAPE_OK_FAILED");
              if (summaryErrorCode === "cloud_api_invalid_response") assert.fail("P0B_SAFE_OWNER_OPEN_SUMMARY_CLOUD_INVALID_RESPONSE_FAILED");
              if (summaryErrorCode === "cloud_api_unavailable") assert.fail("P0B_SAFE_OWNER_OPEN_SUMMARY_CLOUD_UNAVAILABLE_FAILED");
              if (summaryErrorCode === "cloud_api_timeout") assert.fail("P0B_SAFE_OWNER_OPEN_SUMMARY_CLOUD_TIMEOUT_FAILED");
              if (summaryErrorCode === "cloud_api_error") assert.fail("P0B_SAFE_OWNER_OPEN_SUMMARY_CLOUD_ERROR_FAILED");
              if (summaryErrorCode === "body_pending") assert.fail("P0B_SAFE_OWNER_OPEN_SUMMARY_CLOUD_BODY_PENDING_FAILED");
              if (summaryErrorCode === "body_unavailable") assert.fail("P0B_SAFE_OWNER_OPEN_SUMMARY_CLOUD_BODY_UNAVAILABLE_FAILED");
              if (summaryErrorCode === "internal_error") assert.fail("P0B_SAFE_OWNER_OPEN_SUMMARY_INTERNAL_ERROR_FAILED");
              if (summaryStatus >= 500) assert.fail("P0B_SAFE_OWNER_OPEN_SUMMARY_CLOUD_OTHER_ERROR_FAILED");
              const status = await page.locator("#safe-status-heading").textContent().catch(() => "");
              if (status === "安全状態を確認できません") assert.fail("P0B_SAFE_OWNER_OPEN_SUMMARY_ERROR_FAILED");
              if (status === "Cloudの状態を確認中です") assert.fail("P0B_SAFE_OWNER_OPEN_SUMMARY_LOADING_FAILED");
              if (summaryStatus >= 200 && summaryStatus < 300) assert.fail("P0B_SAFE_OWNER_OPEN_SUMMARY_RESPONSE_CONTRACT_FAILED");
              assert.fail("P0B_SAFE_OWNER_OPEN_SUMMARY_NOT_READY_FAILED");
            }
            const deviceReady = await deviceCard(page, "反映待ち Mac").getByRole("heading", { name: "反映待ち Mac" }).count().catch(() => 0);
            if (deviceReady === 0) assert.fail("P0B_SAFE_OWNER_OPEN_DEVICE_CARD_NOT_READY_FAILED");
          } else if (effectiveSafeOpenPrefix === "P0B_SAFE_ADMIN_OPEN") {
            await Promise.race([summaryBodyPromise, new Promise((resolve) => setTimeout(resolve, 5_000))]);
            if (summaryStatus === null) assert.fail("P0B_SAFE_ADMIN_OPEN_SUMMARY_NO_RESPONSE_FAILED");
            if (summaryStatus >= 400 && summaryStatus < 500) assert.fail("P0B_SAFE_ADMIN_OPEN_SUMMARY_HTTP_4XX_FAILED");
            if (summaryErrorCode === "cloud_api_invalid_response") assert.fail("P0B_SAFE_ADMIN_OPEN_SUMMARY_CLOUD_INVALID_RESPONSE_FAILED");
            if (summaryErrorCode === "cloud_api_unavailable") assert.fail("P0B_SAFE_ADMIN_OPEN_SUMMARY_CLOUD_UNAVAILABLE_FAILED");
            if (summaryStatus >= 500) assert.fail("P0B_SAFE_ADMIN_OPEN_SUMMARY_HTTP_5XX_FAILED");
            if (summaryStatus >= 200 && summaryStatus < 300) assert.fail("P0B_SAFE_ADMIN_OPEN_SUMMARY_RESPONSE_CONTRACT_FAILED");
          } else if (effectiveSafeOpenPrefix === "P0B_SAFE_AUDITOR_OPEN") {
            await Promise.race([summaryBodyPromise, new Promise((resolve) => setTimeout(resolve, 5_000))]);
            if (summaryStatus === null) assert.fail("P0B_SAFE_AUDITOR_OPEN_SUMMARY_NO_RESPONSE_FAILED");
            if (summaryErrorCode === "cloud_api_invalid_response") assert.fail("P0B_SAFE_AUDITOR_OPEN_SUMMARY_CLOUD_INVALID_RESPONSE_FAILED");
            if (summaryStatus >= 400) assert.fail("P0B_SAFE_AUDITOR_OPEN_SUMMARY_HTTP_FAILED");
            if (summaryStatus >= 200 && summaryStatus < 300) assert.fail("P0B_SAFE_AUDITOR_OPEN_SUMMARY_RESPONSE_CONTRACT_FAILED");
          }
          failSafeOpen(effectiveSafeOpenPrefix, "READINESS");
        }
        return page;
      };
      try {
        emitLiveStage("SCENARIO_ASSERTIONS");
        await callback({ fixture, browser, open });
      } catch (error) {
        scenarioError = error;
      }
      cleanupError = await closeBrowserResources(browser, contexts);
      browserCleanupAttempted = true;
    } catch (error) {
      scenarioError ??= error;
    } finally {
      clearTimeout(runtimeTimer);
      if (!browserCleanupAttempted) cleanupError = await closeBrowserResources(browser, []);
      try { await fixture?.close(); }
      catch (error) {
        // Fixture implementations may reject with a plain process/container
        // error. Normalize it at this authority boundary so cleanup failures
        // remain classified and never leak arbitrary child diagnostics.
        cleanupError ??= error instanceof P0BLiveBrowserFixtureError
          ? error
          : new P0BLiveBrowserFixtureError("cleanup_failed", "P0-B live browser fixture cleanup failed");
      }
    }
    if (scenarioError) {
      // The supervisor intentionally discards arbitrary TAP diagnostics. If a
      // failure escaped the reviewed marker mappers, retain only its bounded
      // scenario ordinal so CI can identify the failing matrix slice without
      // exposing assertion text, URLs, or fixture data.
      const message = scenarioError instanceof Error ? scenarioError.message : "";
      const safeMessage = /^P0B_SAFE_[A-Z0-9_]+$/u.test(message);
      if (safeMessage) {
        // The callback's assertion is captured so resources can be closed;
        // re-emit its fixed marker after cleanup before propagating failure.
        process.stderr.write(`${message}\n`);
        throw scenarioError;
      }
      if (lifecycleFailureMarker(scenarioError) === null) {
        process.stderr.write(`P0B_SAFE_SCENARIO_UNCLASSIFIED_${String(scenarioOrdinal).padStart(2, "0")}_FAILED\n`);
      }
      failLifecycle(scenarioError);
    }
    if (cleanupError) failLifecycle(cleanupError);
  });
}

function emitLiveStage(stage) {
  if (/^[A-Z][A-Z0-9_]{1,47}$/u.test(stage)) process.stderr.write(`P0B_STAGE_${stage}_START\n`);
}

async function closeBrowserResources(browser, contexts) {
  let firstError;
  for (const context of contexts) {
    try {
      await runP0BLifecycle(() => context.close(), {
        timeoutMs: CONTEXT_CLEANUP_TIMEOUT_MS,
        timeoutCode: "context_cleanup_timeout",
        timeoutMessage: "P0-B browser context cleanup timed out"
      });
    } catch (error) {
      firstError ??= error instanceof P0BLiveBrowserFixtureError
        ? error
        : new P0BLiveBrowserFixtureError("context_cleanup_failed", "P0-B browser context cleanup failed");
    }
  }
  if (browser) {
    try {
      await runP0BLifecycle(() => browser.close(), {
        timeoutMs: BROWSER_CLEANUP_TIMEOUT_MS,
        timeoutCode: "browser_cleanup_timeout",
        timeoutMessage: "P0-B live browser cleanup timed out"
      });
    } catch (error) {
      firstError ??= error instanceof P0BLiveBrowserFixtureError
        ? error
        : new P0BLiveBrowserFixtureError("browser_cleanup_failed", "P0-B live browser cleanup failed");
    }
  }
  return firstError;
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
  const status = card.getByRole("status");
  const alert = card.getByRole("alert");
  const outcome = card.locator('[role="status"]:visible, [role="alert"]:visible').first();
  try { await outcome.waitFor({ state: "visible", timeout: WAKE_OUTCOME_TIMEOUT_MS }); }
  catch { return failWakeStatus(failurePrefix, "TIMEOUT"); }
  let alertVisible = false;
  try { alertVisible = await alert.isVisible(); } catch {}
  const outcomeType = alertVisible ? "alert" : "status";
  if (outcomeType === "alert") {
    if (failurePrefix !== undefined) throw new Error(`${failurePrefix}_ALERT_FAILED`);
    assert.fail("wake failed");
  }
  if (outcomeType !== "status") return failWakeStatus(failurePrefix, "TIMEOUT");
  try { return await card.getByRole("status").innerText(); }
  catch {
    if (failurePrefix !== undefined) throw new Error(`${failurePrefix}_INVALID_FAILED`);
    throw new Error("wake status unavailable");
  }
}

function failWakeStatus(failurePrefix, suffix) {
  if (failurePrefix !== undefined) throw new Error(`${failurePrefix}_${suffix}_FAILED`);
  assert.fail("wake status unavailable");
}

function failLifecycle(error) {
  const marker = lifecycleFailureMarker(error);
  if (marker !== null) {
    process.stderr.write(`${marker}\n`);
    assert.fail(marker);
  }
  throw error;
}

export function lifecycleFailureMarker(error) {
  const message = typeof error?.message === "string" ? error.message : "";
  if (/^P0-B cloud exited before readiness\b/u.test(message)) return "P0B_SAFE_LIFECYCLE_CLOUD_START_FAILED";
  if (/^P0-B console exited before readiness\b/u.test(message)) return "P0B_SAFE_LIFECYCLE_CONSOLE_START_FAILED";
  if (/^P0-B cloud (?:kms_start_failed|dependency_start_failed|signer_start_failed) before readiness\b/u.test(message)) return "P0B_SAFE_LIFECYCLE_CLOUD_START_FAILED";
  if (/^P0-B console (?:kms_start_failed|dependency_start_failed|signer_start_failed) before readiness\b/u.test(message)) return "P0B_SAFE_LIFECYCLE_CONSOLE_START_FAILED";
  if (/^P0-B cloud readiness failed\b/u.test(message)) return "P0B_SAFE_LIFECYCLE_CLOUD_READINESS_FAILED";
  if (/^P0-B console readiness failed\b/u.test(message)) return "P0B_SAFE_LIFECYCLE_CONSOLE_READINESS_FAILED";
  if (/ERR_KMS_PROVIDER_RUNTIME_CONFIG|ERR_KMS_PROVIDER_RUNTIME_SDK|ERR_KMS_PROVIDER_RUNTIME_UNAVAILABLE/u.test(message)) return "P0B_SAFE_LIFECYCLE_CLOUD_KMS_START_FAILED";
  if (/ERR_MODULE_NOT_FOUND|Cannot find package/u.test(message)) return "P0B_SAFE_LIFECYCLE_DEPENDENCY_START_FAILED";
  if (/P0-B signer (?:public key|private key|path)/u.test(message)) return "P0B_SAFE_LIFECYCLE_SIGNER_START_FAILED";
  if (!(error instanceof P0BLiveBrowserFixtureError)) return null;
  return new Map([
    ["startup_timeout", "P0B_SAFE_LIFECYCLE_FIXTURE_STARTUP_TIMEOUT_FAILED"],
    ["startup_failed", "P0B_SAFE_LIFECYCLE_FIXTURE_START_FAILED"],
    ["cloud_start_failed", "P0B_SAFE_LIFECYCLE_CLOUD_START_FAILED"],
    ["cloud_postgres_start_failed", "P0B_SAFE_LIFECYCLE_CLOUD_POSTGRES_START_FAILED"],
    ["cloud_config_start_failed", "P0B_SAFE_LIFECYCLE_CLOUD_CONFIG_START_FAILED"],
    ["cloud_signer_start_failed", "P0B_SAFE_LIFECYCLE_CLOUD_SIGNER_START_FAILED"],
    ["cloud_platform_session_start_failed", "P0B_SAFE_LIFECYCLE_CLOUD_PLATFORM_SESSION_START_FAILED"],
    ["cloud_dependency_start_failed", "P0B_SAFE_LIFECYCLE_CLOUD_DEPENDENCY_START_FAILED"],
    ["cloud_unknown_start_failed", "P0B_SAFE_LIFECYCLE_CLOUD_UNKNOWN_START_FAILED"],
    ["console_start_failed", "P0B_SAFE_LIFECYCLE_CONSOLE_START_FAILED"],
    ["cloud_readiness_failed", "P0B_SAFE_LIFECYCLE_CLOUD_READINESS_FAILED"],
    ["cloud_schema_readiness_failed", "P0B_SAFE_LIFECYCLE_CLOUD_SCHEMA_READINESS_FAILED"],
    ["cloud_signer_readiness_failed", "P0B_SAFE_LIFECYCLE_CLOUD_SIGNER_READINESS_FAILED"],
    ["cloud_platform_session_readiness_failed", "P0B_SAFE_LIFECYCLE_CLOUD_PLATFORM_SESSION_READINESS_FAILED"],
    ["console_readiness_failed", "P0B_SAFE_LIFECYCLE_CONSOLE_READINESS_FAILED"],
    ["cloud_kms_start_failed", "P0B_SAFE_LIFECYCLE_CLOUD_KMS_START_FAILED"],
    ["dependency_start_failed", "P0B_SAFE_LIFECYCLE_DEPENDENCY_START_FAILED"],
    ["signer_start_failed", "P0B_SAFE_LIFECYCLE_SIGNER_START_FAILED"],
    ["fixture_start_failed", "P0B_SAFE_LIFECYCLE_FIXTURE_START_FAILED"],
    ["database_prepare_failed", "P0B_SAFE_LIFECYCLE_DATABASE_PREPARE_FAILED"],
    ["database_schema_relation_failed", "P0B_SAFE_LIFECYCLE_DATABASE_SCHEMA_RELATION_FAILED"],
    ["database_schema_column_failed", "P0B_SAFE_LIFECYCLE_DATABASE_SCHEMA_COLUMN_FAILED"],
    ["database_schema_function_failed", "P0B_SAFE_LIFECYCLE_DATABASE_SCHEMA_FUNCTION_FAILED"],
    ["database_schema_type_failed", "P0B_SAFE_LIFECYCLE_DATABASE_SCHEMA_TYPE_FAILED"],
    ["database_schema_permission_failed", "P0B_SAFE_LIFECYCLE_DATABASE_SCHEMA_PERMISSION_FAILED"],
    ["database_schema_syntax_failed", "P0B_SAFE_LIFECYCLE_DATABASE_SCHEMA_SYNTAX_FAILED"],
    ["database_schema_feature_failed", "P0B_SAFE_LIFECYCLE_DATABASE_SCHEMA_FEATURE_FAILED"],
    ["database_schema_connection_failed", "P0B_SAFE_LIFECYCLE_DATABASE_SCHEMA_CONNECTION_FAILED"],
    ["database_schema_query_failed", "P0B_SAFE_LIFECYCLE_DATABASE_SCHEMA_QUERY_FAILED"],
    ["browser_startup_timeout", "P0B_SAFE_LIFECYCLE_BROWSER_STARTUP_TIMEOUT_FAILED"],
    ["browser_startup_failed", "P0B_SAFE_LIFECYCLE_BROWSER_START_FAILED"],
    ["cleanup_failed", "P0B_SAFE_LIFECYCLE_FIXTURE_CLEANUP_FAILED"],
    ["cleanup_timeout", "P0B_SAFE_LIFECYCLE_FIXTURE_CLEANUP_TIMEOUT_FAILED"],
    ["context_cleanup_timeout", "P0B_SAFE_LIFECYCLE_CONTEXT_CLEANUP_TIMEOUT_FAILED"],
    ["context_cleanup_failed", "P0B_SAFE_LIFECYCLE_CONTEXT_CLEANUP_FAILED"],
    ["browser_cleanup_timeout", "P0B_SAFE_LIFECYCLE_BROWSER_CLEANUP_TIMEOUT_FAILED"],
    ["browser_cleanup_failed", "P0B_SAFE_LIFECYCLE_BROWSER_CLEANUP_FAILED"]
  ]).get(error.code) ?? null;
}

export async function keyboardOutcomeFailureMarker(response, observation = {}) {
  if (response === null) {
    if (observation.refreshRequestFailed === true) return "P0B_SAFE_KEYBOARD_OUTCOME_TRANSPORT_FAILED";
    if (observation.refreshRequestObserved === true) return "P0B_SAFE_KEYBOARD_OUTCOME_RESPONSE_TIMEOUT_FAILED";
    return Object.hasOwn(observation, "recentAuthObservation")
      ? keyboardRecentAuthFailureMarker(observation.recentAuthObservation)
      : "P0B_SAFE_KEYBOARD_OUTCOME_NO_REQUEST_FAILED";
  }
  const status = response.status();
  const statusMarker = new Map([
    [400, "P0B_SAFE_KEYBOARD_OUTCOME_HTTP_400_FAILED"],
    [401, "P0B_SAFE_KEYBOARD_OUTCOME_HTTP_401_FAILED"],
    [403, "P0B_SAFE_KEYBOARD_OUTCOME_HTTP_403_FAILED"],
    [409, "P0B_SAFE_KEYBOARD_OUTCOME_HTTP_409_FAILED"],
    [422, "P0B_SAFE_KEYBOARD_OUTCOME_HTTP_422_FAILED"],
    [429, "P0B_SAFE_KEYBOARD_OUTCOME_HTTP_429_FAILED"],
    [500, "P0B_SAFE_KEYBOARD_OUTCOME_HTTP_500_FAILED"],
    [502, "P0B_SAFE_KEYBOARD_OUTCOME_HTTP_502_FAILED"],
    [503, "P0B_SAFE_KEYBOARD_OUTCOME_HTTP_503_FAILED"],
    [504, "P0B_SAFE_KEYBOARD_OUTCOME_HTTP_504_FAILED"],
  ]).get(status);
  if (statusMarker !== undefined) return statusMarker;
  if (status < 200 || status >= 300) {
    return status >= 400 && status < 500
      ? "P0B_SAFE_KEYBOARD_OUTCOME_HTTP_4XX_FAILED"
      : status >= 500 && status < 600
        ? "P0B_SAFE_KEYBOARD_OUTCOME_HTTP_5XX_FAILED"
        : "P0B_SAFE_KEYBOARD_OUTCOME_HTTP_OTHER_FAILED";
  }
  let payload;
  try { payload = await response.json(); }
  catch { return "P0B_SAFE_KEYBOARD_OUTCOME_2XX_RESPONSE_CONTRACT_FAILED"; }
  if (!isKeyboardRefreshResponseContract(payload)) return "P0B_SAFE_KEYBOARD_OUTCOME_2XX_RESPONSE_CONTRACT_FAILED";
  return "P0B_SAFE_KEYBOARD_OUTCOME_2XX_UI_PARSE_FAILED";
}

function observeWakeAttempt(page) {
  const observation = {
    refreshRequestObserved: false,
    refreshRequestFailed: false,
    recentAuthObservation: {
      optionsObserved: false, optionsFailed: false, optionsStatus: null,
      verifyObserved: false, verifyFailed: false, verifyStatus: null, verifyResponse: null,
      sessionObserved: false, sessionFailed: false, sessionStatus: null,
      webAuthnSupported: true,
    },
  };
  page.on("request", (request) => {
    if (isKeyboardRefreshRequest(request)) observation.refreshRequestObserved = true;
    const phase = keyboardRecentAuthPhase(request);
    if (phase === "options") observation.recentAuthObservation.optionsObserved = true;
    if (phase === "verify") observation.recentAuthObservation.verifyObserved = true;
    if (isKeyboardSessionRequest(request)) observation.recentAuthObservation.sessionObserved = true;
  });
  page.on("requestfailed", (request) => {
    if (isKeyboardRefreshRequest(request)) observation.refreshRequestFailed = true;
    const phase = keyboardRecentAuthPhase(request);
    if (phase === "options") observation.recentAuthObservation.optionsFailed = true;
    if (phase === "verify") observation.recentAuthObservation.verifyFailed = true;
    if (isKeyboardSessionRequest(request)) observation.recentAuthObservation.sessionFailed = true;
  });
  page.on("response", (response) => {
    const phase = keyboardRecentAuthPhase(response.request());
    if (phase === "options") observation.recentAuthObservation.optionsStatus = response.status();
    if (phase === "verify") {
      observation.recentAuthObservation.verifyStatus = response.status();
      observation.recentAuthObservation.verifyResponse = response;
    }
    if (isKeyboardSessionRequest(response.request())) observation.recentAuthObservation.sessionStatus = response.status();
  });
  return {
    observation,
    refreshResponsePromise: page.waitForResponse((response) => isKeyboardRefreshRequest(response.request()), { timeout: 15_000 }).catch(() => null),
  };
}

export async function wakeAcceptedFailureMarker(response, observation = {}) {
  if (response === null || response.status() < 200 || response.status() >= 300) {
    return keyboardOutcomeFailureMarker(response, observation);
  }
  let payload;
  try { payload = await response.json(); }
  catch { return "P0B_SAFE_KEYBOARD_OUTCOME_2XX_RESPONSE_CONTRACT_FAILED"; }
  if (!isKeyboardRefreshResponseContract(payload)) return "P0B_SAFE_KEYBOARD_OUTCOME_2XX_RESPONSE_CONTRACT_FAILED";
  if (payload.refresh_request.status === "coalesced") return "P0B_SAFE_WAKE_ACCEPTED_GOT_COALESCED_FAILED";
  if (payload.refresh_request.status === "no_pending_refresh") return "P0B_SAFE_WAKE_ACCEPTED_GOT_NO_PENDING_FAILED";
  if (payload.refresh_request.status !== "accepted") return "P0B_SAFE_WAKE_ACCEPTED_STATUS_MISMATCH_FAILED";
  return "P0B_SAFE_WAKE_ACCEPTED_UI_STATUS_FAILED";
}

export async function adminWakeFailureMarker(response, observation = {}, uiFailure = null) {
  const recentAuth = observation?.recentAuthObservation ?? {};
  const optionsFailure = await adminRecentAuthPhaseFailureMarker("OPTIONS", recentAuth);
  if (optionsFailure !== null) return optionsFailure;
  const verifyFailure = await adminRecentAuthPhaseFailureMarker("VERIFY", recentAuth);
  if (verifyFailure !== null) return verifyFailure;

  if (response === null || response === undefined) {
    if (observation?.refreshRequestFailed === true) return "P0B_SAFE_ADMIN_WAKE_REFRESH_TRANSPORT_FAILED";
    if (uiFailure === "alert") return "P0B_SAFE_ADMIN_WAKE_UI_ALERT_FAILED";
    if (uiFailure === "timeout") return "P0B_SAFE_ADMIN_WAKE_UI_TIMEOUT_FAILED";
    return "P0B_SAFE_ADMIN_WAKE_REFRESH_RESPONSE_TIMEOUT_FAILED";
  }
  const status = response.status();
  if (status < 200 || status >= 300) return adminRefreshHttpFailureMarker(status);
  let payload;
  try { payload = await response.json(); }
  catch { return "P0B_SAFE_ADMIN_WAKE_REFRESH_2XX_RESPONSE_CONTRACT_FAILED"; }
  if (!isKeyboardRefreshResponseContract(payload)) return "P0B_SAFE_ADMIN_WAKE_REFRESH_2XX_RESPONSE_CONTRACT_FAILED";
  if (uiFailure === "alert") return "P0B_SAFE_ADMIN_WAKE_UI_ALERT_FAILED";
  if (uiFailure === "timeout") return "P0B_SAFE_ADMIN_WAKE_UI_TIMEOUT_FAILED";
  return "P0B_SAFE_ADMIN_WAKE_UI_COPY_MISMATCH_FAILED";
}

async function adminRecentAuthPhaseFailureMarker(phase, observation) {
  const prefix = `P0B_SAFE_ADMIN_WAKE_AUTH_${phase}`;
  const key = phase.toLowerCase();
  const observed = observation?.[`${key}Observed`] === true;
  const failed = observation?.[`${key}Failed`] === true;
  const status = observation?.[`${key}Status`];
  if (phase === "VERIFY" && observation?.optionsObserved === true && observation?.optionsStatus !== null
    && observation.optionsStatus >= 200 && observation.optionsStatus < 300 && !observed) {
    return `${prefix}_TRANSPORT_FAILED`;
  }
  if (!observed) return null;
  if (failed || !Number.isInteger(status)) return `${prefix}_TRANSPORT_FAILED`;
  if (status >= 200 && status < 300) return null;
  if (phase === "VERIFY" && status === 401) {
    const code = await safeRecentAuthErrorCode(observation.verifyResponse);
    const detail = new Map([
      ["human_auth_credential_not_allowed", "CREDENTIAL_NOT_ALLOWED"],
      ["human_auth_webauthn_verification_failed", "WEBAUTHN_VERIFICATION_FAILED"],
      ["human_auth_session_required", "SESSION_REQUIRED"],
    ]).get(code);
    if (detail !== undefined) return `${prefix}_HTTP_401_${detail}_FAILED`;
  }
  if (phase === "VERIFY" && [400, 401, 403, 409, 422, 428, 429].includes(status)) {
    return `${prefix}_HTTP_${status}_FAILED`;
  }
  if (status >= 400 && status < 500) return `${prefix}_HTTP_4XX_FAILED`;
  if (status >= 500 && status < 600) return `${prefix}_HTTP_5XX_FAILED`;
  return `${prefix}_HTTP_OTHER_FAILED`;
}

function adminRefreshHttpFailureMarker(status) {
  if (status >= 400 && status < 500) return "P0B_SAFE_ADMIN_WAKE_REFRESH_HTTP_4XX_FAILED";
  if (status >= 500 && status < 600) return "P0B_SAFE_ADMIN_WAKE_REFRESH_HTTP_5XX_FAILED";
  return "P0B_SAFE_ADMIN_WAKE_REFRESH_HTTP_OTHER_FAILED";
}

export async function keyboardRecentAuthFailureMarker(observation) {
  if (!observation || observation.optionsObserved !== true) {
    if (observation?.webAuthnSupported === false) return "P0B_SAFE_KEYBOARD_AUTH_WEBAUTHN_UNAVAILABLE_FAILED";
    if (observation?.sessionFailed === true) return "P0B_SAFE_KEYBOARD_AUTH_SESSION_TRANSPORT_FAILED";
    if (observation?.sessionObserved === true) {
      const sessionFailure = keyboardPhaseStatusMarker("SESSION", observation.sessionStatus);
      return sessionFailure ?? "P0B_SAFE_KEYBOARD_AUTH_SESSION_SUCCEEDED_NO_OPTIONS_FAILED";
    }
    return "P0B_SAFE_KEYBOARD_AUTH_OPTIONS_NO_REQUEST_FAILED";
  }
  if (observation.optionsFailed === true) return "P0B_SAFE_KEYBOARD_AUTH_OPTIONS_TRANSPORT_FAILED";
  const optionsFailure = keyboardPhaseStatusMarker("OPTIONS", observation.optionsStatus);
  if (optionsFailure !== null) return optionsFailure;
  if (observation.verifyObserved !== true) return "P0B_SAFE_KEYBOARD_AUTH_VERIFY_NO_REQUEST_FAILED";
  if (observation.verifyFailed === true) return "P0B_SAFE_KEYBOARD_AUTH_VERIFY_TRANSPORT_FAILED";
  if (observation.verifyStatus === 401) {
    const code = await safeRecentAuthErrorCode(observation.verifyResponse);
    const detail = new Map([
      ["human_auth_credential_not_allowed", "CREDENTIAL_NOT_ALLOWED"],
      ["human_auth_webauthn_verification_failed", "WEBAUTHN_VERIFICATION_FAILED"],
      ["human_auth_session_required", "SESSION_REQUIRED"],
    ]).get(code);
    if (detail !== undefined) return `P0B_SAFE_KEYBOARD_AUTH_VERIFY_HTTP_401_${detail}_FAILED`;
  }
  const verifyFailure = keyboardPhaseStatusMarker("VERIFY", observation.verifyStatus);
  if (verifyFailure !== null) return verifyFailure;
  return "P0B_SAFE_KEYBOARD_AUTH_VERIFIED_NO_REFRESH_FAILED";
}

async function safeRecentAuthErrorCode(response) {
  if (!response || typeof response.json !== "function") return null;
  try {
    const body = await response.json();
    const code = body?.error?.code;
    return typeof code === "string" ? code : null;
  } catch { return null; }
}

function keyboardPhaseStatusMarker(phase, status) {
  if (!Number.isInteger(status)) return `P0B_SAFE_KEYBOARD_AUTH_${phase}_RESPONSE_MISSING_FAILED`;
  if (status >= 200 && status < 300) return null;
  if (phase === "VERIFY" && [400, 401, 403, 409, 422, 428, 429].includes(status)) {
    return `P0B_SAFE_KEYBOARD_AUTH_VERIFY_HTTP_${status}_FAILED`;
  }
  if (status >= 400 && status < 500) return `P0B_SAFE_KEYBOARD_AUTH_${phase}_HTTP_4XX_FAILED`;
  if (status >= 500 && status < 600) return `P0B_SAFE_KEYBOARD_AUTH_${phase}_HTTP_5XX_FAILED`;
  return `P0B_SAFE_KEYBOARD_AUTH_${phase}_HTTP_OTHER_FAILED`;
}

function isKeyboardRefreshResponseContract(value) {
  const opaqueID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;
  const utcInstant = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/u;
  if (!value || typeof value !== "object" || Array.isArray(value) || Object.keys(value).sort().join(",") !== "refresh_request,request_id") return false;
  if (typeof value.request_id !== "string" || !opaqueID.test(value.request_id)) return false;
  const refresh = value.refresh_request;
  if (!refresh || typeof refresh !== "object" || Array.isArray(refresh)
    || Object.keys(refresh).sort().join(",") !== "desired_generation,device_id,request_id,requested_at,status,version") return false;
  return refresh.version === 1
    && typeof refresh.request_id === "string" && opaqueID.test(refresh.request_id)
    && typeof refresh.device_id === "string" && opaqueID.test(refresh.device_id)
    && (refresh.desired_generation === null || Number.isSafeInteger(refresh.desired_generation) && refresh.desired_generation >= 1)
    && ["accepted", "coalesced", "no_pending_refresh"].includes(refresh.status)
    && typeof refresh.requested_at === "string" && utcInstant.test(refresh.requested_at) && Number.isFinite(Date.parse(refresh.requested_at));
}

function isKeyboardRefreshRequest(request) {
  const url = new URL(request.url());
  return request.method() === "POST"
    && url.pathname === "/api/console"
    && url.searchParams.get("operation") === "device.refresh.request";
}

function keyboardRecentAuthPhase(request) {
  if (request.method() !== "POST") return null;
  const pathname = new URL(request.url()).pathname;
  if (pathname === "/api/auth/webauthn/options") return "options";
  if (pathname === "/api/auth/webauthn/verify") return "verify";
  return null;
}

function isKeyboardSessionRequest(request) {
  if (request.method() !== "POST") return false;
  const pathname = new URL(request.url()).pathname;
  return pathname === "/api/auth/session" || pathname === "/api/auth/session/resume";
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
