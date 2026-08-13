import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";

import { canonicalJson } from "./report.mjs";
import {
  collectBrowserMetadata,
  evidenceDigest,
  RuntimeEvidenceError
} from "./runtime-evidence.mjs";

function fakeBrowser({ version = "140.0.7339.1", versionError, closeError } = {}) {
  const calls = { version: 0, close: 0 };
  return {
    calls,
    async version() {
      calls.version += 1;
      if (versionError) throw versionError;
      return version;
    },
    async close() {
      calls.close += 1;
      if (closeError) throw closeError;
    }
  };
}

test("launches injected Chromium headless, returns only safe metadata, and closes it", async () => {
  const browser = fakeBrowser();
  const launchOptions = [];
  const chromium = {
    async launch(options) {
      launchOptions.push(options);
      return browser;
    }
  };

  assert.deepEqual(await collectBrowserMetadata({ chromium }), {
    name: "Chromium",
    version: "140.0.7339.1",
    engine: "Playwright"
  });
  assert.deepEqual(launchOptions, [{ headless: true }]);
  assert.deepEqual(browser.calls, { version: 1, close: 1 });
});

test("supports an injected browser and always closes it", async () => {
  const browser = fakeBrowser();
  assert.deepEqual(await collectBrowserMetadata({ browser }), {
    name: "Chromium",
    version: "140.0.7339.1",
    engine: "Playwright"
  });
  assert.equal(browser.calls.close, 1);
});

test("does not leak launch failures and has no browser to close", async () => {
  const secret = "/Users/example/.ssh/private-key-secret";
  const error = new Error(`launch failed: ${secret}`);
  let closeCalls = 0;
  await assert.rejects(
    () => collectBrowserMetadata({ chromium: { async launch() { throw error; } } }),
    (caught) => {
      assert.equal(caught.code, "browser_metadata_failed");
      assert.equal(String(caught).includes(secret), false);
      assert.ok(caught instanceof RuntimeEvidenceError);
      return true;
    }
  );
  assert.equal(closeCalls, 0);
});

test("rejects unsafe versions and closes the browser after version failure", async () => {
  const secretPath = "/Users/example/.config/agentpass/token";
  const browser = fakeBrowser({ version: `140.0.1 ${secretPath}` });
  await assert.rejects(
    () => collectBrowserMetadata({ browser }),
    (error) => {
      assert.equal(error.code, "invalid_browser_version");
      assert.equal(String(error).includes(secretPath), false);
      return true;
    }
  );
  assert.equal(browser.calls.close, 1);
});

test("closes the browser after a version failure and preserves a stable error", async () => {
  const secret = "password=never-return-this";
  const browser = fakeBrowser({ versionError: new Error(secret) });
  await assert.rejects(
    () => collectBrowserMetadata({ browser }),
    (error) => {
      assert.equal(error.code, "browser_metadata_failed");
      assert.equal(String(error).includes(secret), false);
      return true;
    }
  );
  assert.equal(browser.calls.close, 1);
});

test("reports close failure without exposing the underlying error", async () => {
  const secret = "token=do-not-leak";
  const browser = fakeBrowser({ closeError: new Error(secret) });
  await assert.rejects(
    () => collectBrowserMetadata({ browser }),
    (error) => {
      assert.equal(error.code, "browser_close_failed");
      assert.equal(String(error).includes(secret), false);
      return true;
    }
  );
});

test("evidenceDigest hashes canonical safe metadata and is key-order independent", () => {
  const first = { browser: { engine: "Playwright", name: "Chromium", version: "140.0.7339.1" }, status: "passed" };
  const second = { status: "passed", browser: { version: "140.0.7339.1", name: "Chromium", engine: "Playwright" } };
  const expected = createHash("sha256").update(Buffer.from(canonicalJson(first), "utf8")).digest("hex");
  assert.equal(evidenceDigest(first), expected);
  assert.equal(evidenceDigest(first), evidenceDigest(second));
  assert.match(evidenceDigest(first), /^[0-9a-f]{64}$/u);
});

test("accepts digest-only command evidence but rejects paths, raw output, and secrets", () => {
  const safe = {
    command: {
      duration_ms: 123,
      exit_code: 0,
      stderr_bytes: 0,
      stderr_sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      stdout_bytes: 0,
      stdout_sha256: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    }
  };
  assert.match(evidenceDigest(safe), /^[0-9a-f]{64}$/u);
  assert.match(evidenceDigest({ postgres: { image_digest: `sha256:${"c".repeat(64)}` } }), /^[0-9a-f]{64}$/u);

  for (const unsafe of [
    { path: "/tmp/qualification.json" },
    { cwd: "/workspace/project" },
    { stdout: "private-key-content" },
    { api_key: "secret-value" },
    { client_secret: "secret-value" },
    { password: "secret-value" },
    { note: "token=secret-value" },
    { endpoint: "https://user:password@example.test" }
  ]) {
    assert.throws(() => evidenceDigest(unsafe), { code: "unsafe_metadata" });
  }
});

test("rejects missing browser injection without revealing filesystem or secret data", async () => {
  await assert.rejects(
    () => collectBrowserMetadata(),
    (error) => {
      assert.equal(error.code, "browser_unavailable");
      assert.equal(String(error).includes("/"), false);
      assert.equal(String(error).toLowerCase().includes("secret"), false);
      return true;
    }
  );
});
