import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const componentRoot = new URL("../app/components/", import.meta.url);
const cssUrl = new URL("../app/globals.css", import.meta.url);
const playwrightConfigUrl = new URL("../playwright.config.ts", import.meta.url);

async function source(name) {
  return readFile(new URL(name, componentRoot), "utf8");
}

test("generic Console dialogs expose an accessible modal contract", async () => {
  const shell = await source("AgentPassConsole.tsx");

  assert.match(shell, /role="dialog"/u);
  assert.match(shell, /aria-modal="true"/u);
  assert.match(shell, /aria-labelledby="[^"]+"/u);
  assert.match(shell, /aria-describedby="[^"]+"/u);
  assert.match(shell, /Escape/u, "modal dismissal must remain keyboard discoverable");
});

test("organization and session failures use live regions and a user recovery path", async () => {
  const organization = await source("OrganizationPanel.tsx");

  assert.match(organization, /role="alert"/u);
  assert.match(organization, /aria-live="assertive"/u);
  assert.match(organization, /最新|再試行|再発行|確認|読み込む/u);
});

test("reduced motion and narrow reflow contracts are present in the generic stylesheet", async () => {
  const css = await readFile(cssUrl, "utf8");

  assert.match(css, /@media\s*\(prefers-reduced-motion:\s*reduce\)/u);
  assert.match(css, /scroll-behavior:\s*auto\s*!important/u);
  assert.match(css, /transition-duration:\s*0\.01ms\s*!important/u);
  assert.match(css, /animation-duration:\s*0\.01ms\s*!important/u);
  assert.match(css, /@media\s*\(max-width:\s*720px\)/u);
  assert.match(css, /grid-template-columns:\s*1fr/u);
});

test("generic Console code does not persist session or invitation material in browser storage", async () => {
  const shell = await source("AgentPassConsole.tsx");
  const organization = await source("OrganizationPanel.tsx");

  assert.doesNotMatch(shell, /localStorage|sessionStorage/u);
  assert.doesNotMatch(organization, /localStorage|sessionStorage/u);
  assert.doesNotMatch(shell, /console\.(?:log|info|warn|error)\s*\(/u);
  assert.doesNotMatch(organization, /console\.(?:log|info|warn|error)\s*\(/u);
});

test("browser artifacts do not persist transient credential-bearing payloads", async () => {
  const config = await readFile(playwrightConfigUrl, "utf8");

  assert.match(config, /trace:\s*"off"/u);
  assert.match(config, /video:\s*"off"/u);
  assert.match(config, /screenshot:\s*"off"/u);
});
