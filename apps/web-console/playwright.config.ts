import { defineConfig, devices } from "@playwright/test";

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
    baseURL: "http://localhost:4173",
    ...devices["Desktop Chrome"],
    browserName: "chromium",
    headless: true,
    trace: "retain-on-failure",
    video: "off",
    screenshot: "off",
  },
  webServer: {
    command: "npm run dev -- --hostname localhost --port 4173",
    cwd: ".",
    url: "http://localhost:4173/",
    timeout: 60_000,
    reuseExistingServer: !process.env.CI,
    stdout: "ignore",
    stderr: "pipe",
  },
});
