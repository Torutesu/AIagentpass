import assert from "node:assert/strict";
import crypto from "node:crypto";
import http from "node:http";
import test from "node:test";

import {
  SETUP_BROWSER_CONNECT_ERRORS,
  SETUP_BROWSER_CONNECT_EXECUTABLE,
  SetupBrowserConnectError,
  buildConsoleLaunchUrl,
  connectSetupInBrowser,
  normalizeCloudV1BaseUrl,
  normalizeConsoleBaseUrl,
  openConsoleWithSystem
} from "../lib/setup-browser-connect.mjs";
import { ONBOARDING_INVITATION_DELIVERY_TYPE } from "../lib/onboarding-contract.mjs";

const CONSOLE = "https://console.example";
const DEV_CONSOLE = "http://localhost:3001";
const CLOUD = "https://api.example/v1";
const CANDIDATE = "release-2026-08-15-01";
const FINGERPRINT = `SHA256:${"a".repeat(43)}`;
const HANDOFF_PATH = `/v1/browser-cli-handoffs/${"a".repeat(43)}`;
const ENROLLMENT = "11111111-1111-4111-8111-111111111111";
const ORGANIZATION = "22222222-2222-4222-8222-222222222222";
const DEVICE = "33333333-3333-4333-8333-333333333333";
let loopbackUnavailable = false;

function preflight(overrides = {}) {
  return { version: 1, platform: "macos", candidate_id: CANDIDATE, device_key_fingerprint: FINGERPRINT, ...overrides };
}

function invitation(overrides = {}) {
  const receipt = crypto.generateKeyPairSync("ed25519");
  const publicKey = receipt.publicKey.export({ type: "spki", format: "pem" }).toString();
  const expires = "2099-01-02T03:04:05.000Z";
  const nonce = crypto.randomBytes(32).toString("base64url");
  return {
    version: 2,
    proof_version: 2,
    enrollment_id: ENROLLMENT,
    organization_id: ORGANIZATION,
    device_id: DEVICE,
    label: "build-mac-01",
    platform: "macos",
    candidate_binding: {
      version: 1,
      enrollment_id: ENROLLMENT,
      organization_id: ORGANIZATION,
      device_id: DEVICE,
      candidate_id: CANDIDATE,
      artifact_sha256: "b".repeat(64),
      source_commit: "c".repeat(40),
      team_id: "TEAMID1234",
      device_key_fingerprint: FINGERPRINT,
      expires_at: expires
    },
    challenge_id: ENROLLMENT,
    nonce,
    expires_at: expires,
    challenge: { challenge_id: ENROLLMENT, nonce, expires_at: expires, candidate_id: CANDIDATE, device_key_fingerprint: FINGERPRINT },
    credential: crypto.randomBytes(32).toString("base64url"),
    endpoint: `/v1/enrollments/${ENROLLMENT}`,
    possession_receipt_verification: { key_id: "receipt-key-v1", algorithm: "ed25519", public_key: publicKey },
    ...overrides
  };
}

function request(url, { method = "GET", origin = CONSOLE, headers = {}, body } = {}) {
  const parsed = new URL(url);
  return new Promise((resolve, reject) => {
    const requestHeaders = { Origin: origin, ...headers };
    if (body !== undefined && requestHeaders["Content-Length"] === undefined) requestHeaders["Content-Length"] = Buffer.byteLength(body);
    const client = http.request({ hostname: parsed.hostname, port: Number(parsed.port), path: `${parsed.pathname}${parsed.search}`, method, headers: requestHeaders }, (response) => {
      const chunks = [];
      response.on("data", (chunk) => chunks.push(chunk));
      response.on("end", () => resolve({ status: response.statusCode, body: Buffer.concat(chunks).toString("utf8") }));
    });
    client.once("error", reject);
    if (body !== undefined) client.write(body);
    client.end();
  });
}

function localHandoffFromLaunch(url) {
  const parsed = new URL(url);
  return parsed.hash.slice(1);
}

async function runOrSkipWhenLoopbackUnavailable(t, operation) {
  if (loopbackUnavailable) {
    t.skip("loopback listener is unavailable in this sandbox; external browser E2E remains not_proven");
    return undefined;
  }
  try {
    return await operation();
  } catch (error) {
    if (error?.code === SETUP_BROWSER_CONNECT_ERRORS.LOOPBACK_UNAVAILABLE) {
      loopbackUnavailable = true;
      t.skip("loopback listener is unavailable in this sandbox; external browser E2E remains not_proven");
      return undefined;
    }
    throw error;
  }
}

test("validates Console root and Cloud /v1 independently", () => {
  assert.equal(normalizeConsoleBaseUrl(CONSOLE), "https://console.example/");
  assert.equal(normalizeConsoleBaseUrl(`${CONSOLE}/`), "https://console.example/");
  assert.equal(normalizeConsoleBaseUrl(DEV_CONSOLE, { allowHttpLoopback: true }), `${DEV_CONSOLE}/`);
  assert.equal(normalizeCloudV1BaseUrl(CLOUD), CLOUD);
  assert.equal(normalizeCloudV1BaseUrl(`${CLOUD}/`), CLOUD);

  for (const value of ["http://console.example", "https://console.example/app", "https://console.example/?x=1", "https://user:secret@console.example", "javascript:alert(1)"]) {
    assert.throws(() => normalizeConsoleBaseUrl(value), (error) => error.code === SETUP_BROWSER_CONNECT_ERRORS.INVALID_CONSOLE_URL);
  }
  assert.throws(() => normalizeConsoleBaseUrl(DEV_CONSOLE), (error) => error.code === SETUP_BROWSER_CONNECT_ERRORS.INVALID_CONSOLE_URL);
  assert.throws(() => normalizeConsoleBaseUrl("http://evil.test", { allowHttpLoopback: true }), (error) => error.code === SETUP_BROWSER_CONNECT_ERRORS.INVALID_CONSOLE_URL);
  for (const value of ["https://api.example", "https://api.example/v2", "http://localhost:4000/v1", "https://user:secret@api.example/v1", "https://api.example/v1?token=secret"]) {
    assert.throws(() => normalizeCloudV1BaseUrl(value), (error) => error.code === SETUP_BROWSER_CONNECT_ERRORS.INVALID_CLOUD_URL);
  }
});

test("launch URL contains only the raw local handoff URL in its fragment", () => {
  const handoff = `http://127.0.0.1:43123${HANDOFF_PATH}`;
  const url = buildConsoleLaunchUrl({ consoleBaseUrl: CONSOLE, handoffUrl: handoff });
  assert.equal(url, `${CONSOLE}/#${handoff}`);
  assert.equal(new URL(url).hash, `#${handoff}`);
  assert.equal(new URL(url).search, "");
  assert.throws(() => buildConsoleLaunchUrl({ consoleBaseUrl: CONSOLE, handoffUrl: `${handoff}?credential=secret` }), (error) => error.code === SETUP_BROWSER_CONNECT_ERRORS.INVALID_HANDOFF);
  assert.throws(() => buildConsoleLaunchUrl({ consoleBaseUrl: "https://console.example/?credential=secret", handoffUrl: handoff }), (error) => error.code === SETUP_BROWSER_CONNECT_ERRORS.INVALID_CONSOLE_URL);
});

test("system opener uses the fixed executable, no shell, and minimal environment", () => {
  let call;
  openConsoleWithSystem(`${CONSOLE}/#http://127.0.0.1:43123${HANDOFF_PATH}`, {
    timeoutMs: 100,
    spawn: (...args) => {
      call = args;
      return { status: 0, signal: null, error: undefined };
    }
  });
  assert.equal(call[0], SETUP_BROWSER_CONNECT_EXECUTABLE);
  assert.equal(call[1].length, 1);
  assert.equal(call[2].shell, false);
  assert.deepEqual(call[2].env, { PATH: "/usr/bin:/bin:/usr/sbin:/sbin" });
  assert.equal(call[2].timeout, 100);
  assert.throws(
    () => openConsoleWithSystem(`http://localhost:3001/#http://127.0.0.1:43123${HANDOFF_PATH}`, { spawn: () => ({ status: 0 }) }),
    (error) => error.code === SETUP_BROWSER_CONNECT_ERRORS.INVALID_HANDOFF
  );
  openConsoleWithSystem(`http://localhost:3001/#http://127.0.0.1:43123${HANDOFF_PATH}`, {
    allowHttpLoopback: true,
    spawn: () => ({ status: 0, signal: null, error: undefined })
  });
});

test("opens Console and returns exactly one invitation from memory", async (t) => {
  await runOrSkipWhenLoopbackUnavailable(t, async () => {
  let launchUrl;
  const value = invitation();
  const received = await connectSetupInBrowser({
    consoleBaseUrl: CONSOLE,
    cloudBaseUrl: CLOUD,
    preflight: preflight(),
    opener: async (url) => {
      launchUrl = url;
      const handoffUrl = localHandoffFromLaunch(url);
      const challengeResponse = await request(`${handoffUrl}/preflight`);
      const challenge = JSON.parse(challengeResponse.body);
      const response = await request(handoffUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ version: 1, type: ONBOARDING_INVITATION_DELIVERY_TYPE, correlation_id: challenge.correlation_id, nonce: challenge.nonce, invitation: value })
      });
      assert.equal(response.status, 200);
    }
  });
  assert.deepEqual(received, value);
  assert.equal(launchUrl.includes(FINGERPRINT), false);
  assert.equal(launchUrl.includes(value.credential), false);
  const launch = new URL(launchUrl);
  assert.equal(launch.pathname, "/", "Cloud /v1 must not become the Console pathname");
  assert.equal(launch.search, "", "Cloud query parameters must not become the Console query");
  assert.equal(launchUrl.includes(CLOUD), false, "Cloud /v1 must not be inferred into the Console launch URL");
  assert.equal(launch.hash.startsWith("#http://127.0.0.1:"), true);
  });
});

test("closes the listener after opener failure and keeps errors path/secret-free", async (t) => {
  await runOrSkipWhenLoopbackUnavailable(t, async () => {
  let launchUrl;
  const secret = "credential-secret-/tmp/private-key";
  await assert.rejects(
    connectSetupInBrowser({
      consoleBaseUrl: CONSOLE,
      preflight: preflight(),
      opener: (url) => {
        launchUrl = url;
        throw new Error(secret);
      }
    }),
    (error) => {
      assert.equal(error.code, SETUP_BROWSER_CONNECT_ERRORS.OPEN_FAILED);
      assert.equal(error.message.includes(secret), false);
      assert.equal(error.message.includes("/tmp"), false);
      assert.equal(JSON.stringify(error).includes(secret), false);
      return error instanceof SetupBrowserConnectError;
    }
  );
  await assert.rejects(request(`${localHandoffFromLaunch(launchUrl)}/preflight`));
  });
});

test("classifies loopback listener permission and availability failures without exposing cause data", async () => {
  const originalListen = http.Server.prototype.listen;
  const secretPath = "/private/agentpass/credential-secret.pem";
  const failureCodes = ["EPERM", "EACCES", "EADDRINUSE", "EADDRNOTAVAIL"];

  try {
    for (const failureCode of failureCodes) {
      http.Server.prototype.listen = function patchedListen() {
        process.nextTick(() => this.emit("error", Object.assign(new Error(`listen ${failureCode}: ${secretPath}`), { code: failureCode })));
        return this;
      };

      await assert.rejects(
        connectSetupInBrowser({ consoleBaseUrl: CONSOLE, preflight: preflight() }),
        (error) => {
          assert.equal(error.code, SETUP_BROWSER_CONNECT_ERRORS.LOOPBACK_UNAVAILABLE);
          assert.equal(error.message, "The local browser handoff is unavailable");
          assert.equal(error.cause, undefined);
          assert.equal(Object.hasOwn(error, "cause"), false);
          assert.equal(error.message.includes(secretPath), false);
          assert.equal(error.message.includes(failureCode), false);
          assert.equal(JSON.stringify(error).includes(secretPath), false);
          assert.equal(JSON.stringify(error).includes(failureCode), false);
          return error instanceof SetupBrowserConnectError;
        }
      );
    }
  } finally {
    http.Server.prototype.listen = originalListen;
  }
});

test("bounds a stuck opener and closes the listener", async (t) => {
  await runOrSkipWhenLoopbackUnavailable(t, async () => {
  let launchUrl;
  const started = Date.now();
  await assert.rejects(
    connectSetupInBrowser({
      consoleBaseUrl: CONSOLE,
      preflight: preflight(),
      openTimeoutMs: 100,
      opener: (url) => {
        launchUrl = url;
        return new Promise(() => {});
      }
    }),
    (error) => error.code === SETUP_BROWSER_CONNECT_ERRORS.OPEN_TIMEOUT
  );
  assert.ok(Date.now() - started < 2_000);
  await assert.rejects(request(`${localHandoffFromLaunch(launchUrl)}/preflight`));
  });
});

test("propagates AbortSignal to the bounded journey and tears down the listener", async (t) => {
  await runOrSkipWhenLoopbackUnavailable(t, async () => {
  const controller = new AbortController();
  let launchUrl;
  const pending = connectSetupInBrowser({
    consoleBaseUrl: CONSOLE,
    preflight: preflight(),
    opener: (url) => {
      launchUrl = url;
      return new Promise(() => {});
    },
    signal: controller.signal,
    openTimeoutMs: 5_000
  });
  await new Promise((resolve) => setImmediate(resolve));
  controller.abort();
  await assert.rejects(pending, (error) => error.code === SETUP_BROWSER_CONNECT_ERRORS.ABORTED);
  await assert.rejects(request(`${localHandoffFromLaunch(launchUrl)}/preflight`));
  });
});

test("rejects unknown options and malformed public preflight without echoing input", async () => {
  const secretPath = "/Users/example/private/credential.json";
  await assert.rejects(connectSetupInBrowser({ consoleBaseUrl: CONSOLE, preflight: preflight({ credential: secretPath }) }), (error) => {
    assert.equal(error.code, SETUP_BROWSER_CONNECT_ERRORS.INVALID_PREFLIGHT);
    assert.equal(error.message.includes(secretPath), false);
    return true;
  });
  await assert.rejects(connectSetupInBrowser({ consoleBaseUrl: CONSOLE, preflight: preflight(), unknown: secretPath }), (error) => {
    assert.equal(error.code, SETUP_BROWSER_CONNECT_ERRORS.INVALID_OPTIONS);
    assert.equal(error.message.includes(secretPath), false);
    return true;
  });
});

test("maps handoff expiry to a stable error", async (t) => {
  await runOrSkipWhenLoopbackUnavailable(t, async () => {
  await assert.rejects(
    connectSetupInBrowser({ consoleBaseUrl: CONSOLE, preflight: preflight(), opener: () => {}, ttlMs: 1_000 }),
    (error) => error.code === SETUP_BROWSER_CONNECT_ERRORS.TIMEOUT
  );
  });
});
