import { defineConfig, devices } from "@playwright/test";

const configuredPort = Number.parseInt(process.env.PLAYWRIGHT_PORT ?? "", 10);
const e2ePort = Number.isInteger(configuredPort) && configuredPort >= 1024 && configuredPort <= 65_535
  ? configuredPort
  : 4_173;

export default defineConfig({
  testDir: "./e2e",
  testMatch: "**/*.spec.ts",
  timeout: 30_000,
  expect: { timeout: 5_000 },
  fullyParallel: false,
  workers: 1,
  forbidOnly: Boolean(process.env.CI),
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? "line" : "list",
  outputDir: "./e2e/test-results",
  use: {
    baseURL: `http://localhost:${e2ePort}`,
    ...devices["Desktop Chrome"],
    browserName: "chromium",
    headless: true,
    trace: "retain-on-failure",
    video: "off",
    screenshot: "off",
  },
  webServer: {
    command: `npm run dev -- --hostname localhost --port ${e2ePort}`,
    cwd: ".",
    url: `http://localhost:${e2ePort}/`,
    timeout: 60_000,
    reuseExistingServer: false,
    gracefulShutdown: { signal: "SIGTERM", timeout: 5_000 },
    stdout: "ignore",
    stderr: "pipe",
  },
});
