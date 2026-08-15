import assert from "node:assert/strict";
import test from "node:test";

import { chromium } from "../apps/web-console/node_modules/@playwright/test/index.mjs";
import { P0BSkip } from "./support/p0b/harness.mjs";
import { startP0BLiveBrowserFixture } from "./support/p0b/live-browser-fixture.mjs";

const enabled = process.env.P0B_LIVE_BROWSER === "1";

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
    try { assert.match(await requireWakeStatus(card), /依頼を受け付けました|既存の依頼へ統合し/u); }
    catch { assert.fail("P0B_SAFE_KEYBOARD_OUTCOME_FAILED"); }
  });

  await scenario(t, "shows accepted, coalesced, and no-pending outcomes from the real wake ledger", async ({ fixture, open }) => {
    await fixture.resetManualWakeEvidence();
    const page = await open("owner");
    for (const [name, expected] of [["反映待ち Mac", /依頼を受け付けました/u], ["反映待ち Mac", /既存の依頼へ統合し/u], ["古い状態 Mac", /反映待ちの更新はなく/u]]) {
      const card = deviceCard(page, name);
      await card.getByRole("button", { name: "Wake requestを依頼" }).click();
      assert.match(await requireWakeStatus(card), expected);
    }
  });

  await scenario(t, "admin completes real WebAuthn and wake mutation", async ({ open }) => {
    const page = await open("admin");
    const card = deviceCard(page, "反映待ち Mac");
    await card.getByRole("button", { name: "Wake requestを依頼" }).click();
    assert.match(await requireWakeStatus(card), /依頼を受け付けました|既存の依頼へ統合し/u);
  });

  for (const role of ["auditor", "viewer"]) {
    await scenario(t, `${role} receives no wake mutation control`, async ({ open }) => {
      const page = await open(role);
      const card = deviceCard(page, "反映待ち Mac");
      assert.equal(await card.getByRole("button", { name: "Wake requestを依頼" }).count(), 0);
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
});

async function scenario(parent, name, callback) {
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
      const open = async (role, { register = true } = {}) => {
        const context = await browser.newContext({ ignoreHTTPSErrors: false });
        contexts.push(context);
        const page = await context.newPage();
        if (register) await fixture.installVirtualAuthenticator(page, role);
        await fixture.bootstrap(page, role);
        if (register) await fixture.registerWebAuthn(page);
        await page.reload({ waitUntil: "domcontentloaded" });
        await page.getByRole("heading", { name: /Agentの状態を、\s*確認できました。/u }).waitFor();
        await deviceCard(page, "反映待ち Mac").getByRole("heading", { name: "反映待ち Mac" }).waitFor();
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

async function requireWakeStatus(card) {
  const outcome = await Promise.race([card.getByRole("status").waitFor().then(() => "status"), card.getByRole("alert").waitFor().then(() => "alert")]);
  if (outcome === "alert") assert.fail(`wake failed: ${await card.getByRole("alert").innerText()}`);
  return card.getByRole("status").innerText();
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
