import assert from "node:assert/strict";
import test from "node:test";

import { chromium } from "../apps/web-console/node_modules/@playwright/test/index.mjs";
import { P0BSkip } from "./support/p0b/harness.mjs";
import { startP0BLiveBrowserFixture } from "./support/p0b/live-browser-fixture.mjs";

const enabled = process.env.P0B_LIVE_BROWSER === "1";

test("P0-B live browser role, WebAuthn, and recent-auth matrix", { skip: !enabled, timeout: 480_000 }, async (t) => {
  await scenario(t, "renders all six real PostgreSQL device states and accepts keyboard wake", async ({ open }) => {
    const page = await open("owner");
    for (const label of ["同期済み", "反映待ち", "ブロック中", "古い状態", "オフライン", "失効済み"]) await page.getByLabel(`同期状態: ${label}`).waitFor();
    const card = deviceCard(page, "反映待ち Mac");
    const wake = card.getByRole("button", { name: "Wake requestを依頼" });
    await wake.focus();
    assert.equal(await wake.evaluate((element) => element === document.activeElement), true);
    await page.keyboard.press("Enter");
    assert.match(await requireWakeStatus(card), /依頼を受け付けました|既存の依頼へ統合し/u);
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
    await scenario(t, `${role} remains read-only after valid real WebAuthn`, async ({ open }) => {
      const page = await open(role);
      const card = deviceCard(page, "反映待ち Mac");
      await card.getByRole("button", { name: "Wake requestを依頼" }).click();
      await card.getByRole("alert").waitFor();
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
  await parent.test(name, { timeout: 45_000 }, async () => {
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
