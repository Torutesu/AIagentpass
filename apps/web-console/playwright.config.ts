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

export default defineConfig({
  testDir: "./e2e",
  testMatch: "**/*.spec.ts",
  timeout: 30_000,
  globalTimeout: 5 * 60_000,
  expect: { timeout: 5_000 },
  fullyParallel: false,
  workers: 1,
  forbidOnly: Boolean(process.env.CI),
  // Qualification is a complete-set gate; retries would double-count tests
  // and could hide a flaky first execution in the evidence summary.
  retries: 0,
  reporter: process.env.CI ? "line" : "list",
  // Playwright's failure context is a Markdown file that the repository-wide
  // artifact gate cannot parse. Screenshots, video, and traces are disabled
  // below, so retaining test output would add no supported diagnostic value.
  preserveOutput: "never",
  outputDir: "./e2e/test-results",
  use: {
    baseURL: `http://127.0.0.1:${e2ePort}`,
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
  webServer: {
    // Codex/CI shells may inherit NODE_OPTIONS=--inspect=...; the dev server
    // must not open a public inspector listener during browser qualification.
    command: `env -u NODE_OPTIONS -u NODE_DEBUG npm run dev -- --hostname 127.0.0.1 --port ${e2ePort}`,
    cwd: ".",
    url: `http://127.0.0.1:${e2ePort}/`,
    timeout: webServerTimeout,
    reuseExistingServer: false,
    gracefulShutdown: { signal: "SIGTERM", timeout: shutdownTimeout },
    stdout: "ignore",
    stderr: "pipe",
  },
});
