import assert from "node:assert/strict";
import test from "node:test";

import { parseSetupContinueOptions } from "../lib/setup-continue-options.mjs";

test("parses preview, ordinary execute, browser, and stdin setup modes", () => {
  assert.deepEqual(parseSetupContinueOptions([]), {
    execute: false, browser: false, enrollmentStdin: false, consoleUrl: undefined, enrollmentUrl: undefined
  });
  assert.equal(parseSetupContinueOptions(["--execute"]).execute, true);
  assert.deepEqual(parseSetupContinueOptions([
    "--execute", "--browser", "--console-url", "https://console.example", "--enrollment-url", "https://api.example/v1"
  ]), {
    execute: true,
    browser: true,
    enrollmentStdin: false,
    consoleUrl: "https://console.example",
    enrollmentUrl: "https://api.example/v1"
  });
  assert.deepEqual(parseSetupContinueOptions([
    "--execute", "--enrollment-url", "https://api.example/v1", "--enrollment-stdin"
  ]), {
    execute: true,
    browser: false,
    enrollmentStdin: true,
    consoleUrl: undefined,
    enrollmentUrl: "https://api.example/v1"
  });
});

test("fails closed on ambiguous, partial, duplicate, and preview enrollment flags", () => {
  const rejected = [
    ["--browser"],
    ["--execute", "--browser"],
    ["--execute", "--browser", "--console-url", "https://console.example"],
    ["--execute", "--browser", "--enrollment-url", "https://api.example/v1"],
    ["--execute", "--browser", "--console-url", "https://console.example", "--enrollment-url", "https://api.example/v1", "--enrollment-stdin"],
    ["--execute", "--enrollment-stdin"],
    ["--execute", "--enrollment-url", "https://api.example/v1"],
    ["--execute", "--console-url", "https://console.example"],
    ["--execute", "--execute"],
    ["--execute", "--browser", "--browser", "--console-url", "https://console.example", "--enrollment-url", "https://api.example/v1"],
    ["--execute", "--unknown"]
  ];
  for (const args of rejected) assert.throws(() => parseSetupContinueOptions(args));
});
