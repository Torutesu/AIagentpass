import { defineConfig, devices } from "@playwright/test";

const configuredPort = Number.parseInt(process.env.PLAYWRIGHT_PORT ?? "", 10);
const e2ePort = Number.isInteger(configuredPort) && configuredPort >= 1024 && configuredPort <= 65_535
  ? configuredPort
  : 4_173;

function boundedTimeout(value: string | undefined, fallback: number, maximum: number): number {
  const parsed = Number.parseInt(value ?? "", 10);
  return Number.isInteger(parsed) && parsed >= 1_000 && parsed <= maximum ? parsed : fallback;
}

const webServerTimeout = boundedTimeout(process.env.PLAYWRIGHT_STARTUP_TIMEOUT_MS, 60_000, 180_000);
const shutdownTimeout = boundedTimeout(process.env.PLAYWRIGHT_CLEANUP_TIMEOUT_MS, 5_000, 30_000);
const outputDir = process.env.AGENTPASS_PLAYWRIGHT_OUTPUT_DIR ?? "./e2e/test-results";
const bffCloudPort = Number.parseInt(process.env.PLAYWRIGHT_CLOUD_API_PORT ?? "4310", 10);
const configuredBffCloudPort = Number.isInteger(bffCloudPort) && bffCloudPort >= 1024 && bffCloudPort <= 65_535
  ? bffCloudPort
  : 4_310;
const browserHost = process.env.PLAYWRIGHT_BROWSER_HOST === "127.0.0.1" ? "127.0.0.1" : "localhost";
const bffCloudUrl = `http://127.0.0.1:${configuredBffCloudPort}/`;
const bffOrganizationId = "11111111-1111-4111-8111-111111111111";
const bffCursorSecret = "A".repeat(43);
const managedBrowserE2eServer = process.env.AGENTPASS_BROWSER_E2E_MANAGED_SERVER === "true";

export default defineConfig({
  testDir: "./e2e",
  testMatch: "**/*.spec.ts",
  timeout: 30_000,
  globalTimeout: 5 * 60_000,
  expect: { timeout: 5_000 },
  fullyParallel: false,
  workers: 1,
  outputDir,
  forbidOnly: Boolean(process.env.CI),
  // Qualification is a complete-set gate; retries would double-count tests
  // and could hide a flaky first execution in the evidence summary.
  retries: 0,
  reporter: process.env.CI ? "line" : "list",
  // Playwright's failure context is a Markdown file that the repository-wide
  // artifact gate cannot parse. Screenshots, video, and traces are disabled
  // below, so retaining test output would add no supported diagnostic value.
  preserveOutput: "never",
  use: {
    baseURL: `http://${browserHost}:${e2ePort}`,
    ...devices["Desktop Chrome"],
    browserName: "chromium",
    headless: true,
    // WebAuthn request/response bodies contain transient assertion material.
    // Playwright traces persist network payloads, so this security suite keeps
    // traces disabled and uses bounded, explicitly redacted diagnostics instead.
    trace: "off",
    video: "off",
    screenshot: "off",
  },
  // The repository runner owns the server in CI so the port is held by one
  // process from bind through browser execution. Direct `playwright test`
  // invocations retain Playwright's non-reuse server lifecycle.
  webServer: managedBrowserE2eServer ? undefined : {
    // Codex/CI shells may inherit NODE_OPTIONS=--inspect=...; the dev server
    // must not open a public inspector listener during browser qualification.
    command: [
      "env -u NODE_OPTIONS -u NODE_DEBUG",
      `NODE_ENV=test AGENTPASS_CLOUD_API_URL=${bffCloudUrl}`,
      "AGENTPASS_ALLOW_INSECURE_LOOPBACK_CLOUD_API=true",
      `AGENTPASS_ORGANIZATION_ID=${bffOrganizationId}`,
      `AGENTPASS_CONSOLE_CURSOR_SECRET=${bffCursorSecret}`,
      `npm run dev -- --hostname 127.0.0.1 --port ${e2ePort}`,
    ].join(" "),
    cwd: ".",
    url: `http://${browserHost}:${e2ePort}/`,
    timeout: webServerTimeout,
    reuseExistingServer: false,
    gracefulShutdown: { signal: "SIGTERM", timeout: shutdownTimeout },
    stdout: "ignore",
    stderr: "pipe",
  },
});
