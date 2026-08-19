import assert from "node:assert/strict";
import test from "node:test";

import { assertFixedResumeDescriptorOptions, parseSetupContinueOptions } from "../lib/setup-continue-options.mjs";

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

test("rejects control characters, oversized values, and secret-like argument values", () => {
  for (const value of [
    "https://console.example/?token=redacted",
    "https://console.example/#secret=redacted",
    "https://console.example/\u0000",
    "x".repeat(2049)
  ]) {
    assert.throws(() => parseSetupContinueOptions(["--execute", "--browser", "--console-url", value, "--enrollment-url", "https://api.example/v1"]));
  }
});

test("does not allow a resumed enrollment to replace its fixed descriptor", () => {
  const descriptor = { api_base_url: "https://api.example/v1" };
  assert.doesNotThrow(() => assertFixedResumeDescriptorOptions(parseSetupContinueOptions(["--execute"]), descriptor));
  for (const argv of [
    ["--execute", "--browser", "--console-url", "https://console.example", "--enrollment-url", "https://api.example/v1"],
    ["--execute", "--enrollment-url", "https://api.example/v1", "--enrollment-stdin"],
    ["--execute", "--enrollment-url", "https://other.example/v1", "--enrollment-stdin"]
  ]) {
    let flags;
    assert.doesNotThrow(() => { flags = parseSetupContinueOptions(argv); });
    assert.throws(() => assertFixedResumeDescriptorOptions(flags, descriptor), /durable enrollment recovery/u);
  }
});
