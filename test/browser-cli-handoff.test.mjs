import assert from "node:assert/strict";
import crypto from "node:crypto";
import http from "node:http";
import test from "node:test";

import {
  BROWSER_CLI_HANDOFF_ERRORS,
  BrowserCliHandoffError,
  canonicalizeBrowserCliInvitation,
  createBrowserCliHandoff,
  normalizeBrowserCliHandoffPreflight
} from "../lib/browser-cli-handoff.mjs";
import { ONBOARDING_INVITATION_DELIVERY_TYPE } from "../lib/onboarding-contract.mjs";
import { canonicalJson } from "../lib/identity.mjs";

const ORIGIN = "http://localhost:3001";
const CANDIDATE = "release-2026-08-15-01";
const FINGERPRINT = `SHA256:${"a".repeat(43)}`;
const ENROLLMENT = "11111111-1111-4111-8111-111111111111";
const ORGANIZATION = "22222222-2222-4222-8222-222222222222";
const DEVICE = "33333333-3333-4333-8333-333333333333";

function preflight(overrides = {}) {
  return {
    version: 1,
    platform: "macos",
    candidate_id: CANDIDATE,
    device_key_fingerprint: FINGERPRINT,
    ...overrides
  };
}

function invitation(overrides = {}) {
  const receipt = crypto.generateKeyPairSync("ed25519");
  const publicKey = receipt.publicKey.export({ type: "spki", format: "pem" }).toString();
  const candidateBinding = {
    version: 1,
    enrollment_id: ENROLLMENT,
    organization_id: ORGANIZATION,
    device_id: DEVICE,
    candidate_id: CANDIDATE,
    artifact_sha256: "b".repeat(64),
    source_commit: "c".repeat(40),
    team_id: "TEAMID1234",
    device_key_fingerprint: FINGERPRINT,
    expires_at: "2099-01-02T03:04:05.000Z"
  };
  const nonce = crypto.randomBytes(32).toString("base64url");
  return {
    version: 2,
    proof_version: 2,
    enrollment_id: ENROLLMENT,
    organization_id: ORGANIZATION,
    device_id: DEVICE,
    label: "build-mac-01",
    platform: "macos",
    candidate_binding: candidateBinding,
    challenge_id: ENROLLMENT,
    nonce,
    expires_at: candidateBinding.expires_at,
    challenge: {
      challenge_id: ENROLLMENT,
      nonce,
      expires_at: candidateBinding.expires_at,
      candidate_id: CANDIDATE,
      device_key_fingerprint: FINGERPRINT
    },
    credential: crypto.randomBytes(32).toString("base64url"),
    endpoint: `/v1/enrollments/${ENROLLMENT}`,
    possession_receipt_verification: { key_id: "receipt-key-v1", algorithm: "ed25519", public_key: publicKey },
    ...overrides
  };
}

function bodyFor(handle, value = invitation()) {
  const challenge = handle.getPublicPreflight();
  return JSON.stringify({ version: 1, type: ONBOARDING_INVITATION_DELIVERY_TYPE, correlation_id: challenge.correlation_id, nonce: challenge.nonce, invitation: value });
}

function request(url, { method = "GET", origin = ORIGIN, host, headers = {}, body = undefined } = {}) {
  const parsed = new URL(url);
  return new Promise((resolve, reject) => {
    const requestHeaders = { Origin: origin, ...headers };
    if (host !== undefined) requestHeaders.Host = host;
    if (body !== undefined && requestHeaders["Content-Length"] === undefined && requestHeaders["content-length"] === undefined) requestHeaders["Content-Length"] = Buffer.byteLength(body);
    const client = http.request({ hostname: "127.0.0.1", port: Number(parsed.port), path: `${parsed.pathname}${parsed.search}`, method, headers: requestHeaders }, (response) => {
      const chunks = [];
      response.on("data", (chunk) => chunks.push(chunk));
      response.on("end", () => resolve({ status: response.statusCode, headers: response.headers, body: Buffer.concat(chunks).toString("utf8") }));
    });
    client.once("error", reject);
    if (body !== undefined) client.write(body);
    client.end();
  });
}

async function start(overrides = {}) {
  return createBrowserCliHandoff({ allowedOrigins: [ORIGIN], preflight: preflight(), ...overrides });
}

test("normalizes only public preflight data and rejects aliases/unknown fields", () => {
  assert.deepEqual(normalizeBrowserCliHandoffPreflight(preflight()), preflight());
  assert.throws(() => normalizeBrowserCliHandoffPreflight({ ...preflight(), credential: "secret" }), (error) => error.code === BROWSER_CLI_HANDOFF_ERRORS.INVALID_PREFLIGHT);
  assert.throws(() => normalizeBrowserCliHandoffPreflight({ ...preflight(), device_key_fingerprint: "not-a-fingerprint" }), (error) => error.code === BROWSER_CLI_HANDOFF_ERRORS.INVALID_PREFLIGHT);
  assert.throws(() => normalizeBrowserCliHandoffPreflight({ ...preflight(), platform: "linux" }), (error) => error.code === BROWSER_CLI_HANDOFF_ERRORS.INVALID_PREFLIGHT);
});

test("allows HTTPS production Origins and limits HTTP to loopback development Origins", async () => {
  await assert.rejects(createBrowserCliHandoff({ allowedOrigins: ["http://console.example"], preflight: preflight() }), (error) => error.code === BROWSER_CLI_HANDOFF_ERRORS.INVALID_CONFIG);
  const handle = await createBrowserCliHandoff({ allowedOrigins: ["https://console.example"], preflight: preflight() });
  void handle.waitForInvitation().catch(() => {});
  await handle.close();
});

test("starts an IPv4 loopback listener with an opaque path and returns canonical v2 invitation", async (t) => {
  const handle = await start();
  t.after(() => handle.close());
  assert.equal(new URL(handle.url).search, "");
  assert.equal(new URL(handle.url).hash, "");
  assert.equal(handle.url.includes("credential"), false);
  assert.equal(handle.url.includes("token"), false);
  assert.match(handle.correlation_id, /^[A-Za-z0-9_-]{43}$/u);

  const publicChallenge = handle.getPublicPreflight();
  assert.deepEqual(Object.keys(publicChallenge).sort(), ["candidate_id", "correlation_id", "device_key_fingerprint", "nonce", "platform", "version"].sort());
  assert.match(publicChallenge.nonce, /^[A-Za-z0-9_-]{43}$/u);
  const preflightResponse = await request(handle.preflight_url);
  assert.equal(preflightResponse.status, 200);
  assert.deepEqual(JSON.parse(preflightResponse.body), publicChallenge);
  assert.equal(preflightResponse.headers["cache-control"], "no-store");

  const optionsResponse = await request(handle.preflight_url, { method: "OPTIONS", headers: { "Access-Control-Request-Method": "GET", "Access-Control-Request-Private-Network": "true" } });
  assert.equal(optionsResponse.status, 204);
  assert.equal(optionsResponse.headers["access-control-allow-private-network"], "true");
  const postOptionsResponse = await request(handle.url, { method: "OPTIONS", headers: { "Access-Control-Request-Method": "POST", "Access-Control-Request-Headers": "content-type", "Access-Control-Request-Private-Network": "true" } });
  assert.equal(postOptionsResponse.status, 204);
  assert.equal(postOptionsResponse.headers["access-control-allow-private-network"], "true");
  const value = invitation();
  const response = await request(handle.url, { method: "POST", headers: { "Content-Type": "application/json" }, body: bodyFor(handle, value) });
  assert.equal(response.status, 200);
  assert.deepEqual(JSON.parse(response.body), { consumed: true, ok: true, version: 1 });
  const received = await handle.waitForInvitation();
  assert.deepEqual(received, value);
  assert.equal(canonicalJson(received), canonicalJson(value));
  await handle.close();
});

test("binds the successful consume to the nonce and rejects a concurrent replay once", async (t) => {
  const handle = await start();
  t.after(() => handle.close());
  const body = bodyFor(handle);
  const [first, second] = await Promise.all([
    request(handle.url, { method: "POST", headers: { "Content-Type": "application/json" }, body }),
    request(handle.url, { method: "POST", headers: { "Content-Type": "application/json" }, body })
  ]);
  assert.deepEqual([first.status, second.status].sort((a, b) => a - b), [200, 409]);
  await handle.waitForInvitation();
});

test("rejects origin, host, content type, query, and unknown-field substitutions", async (t) => {
  const originHandle = await start();
  void originHandle.waitForInvitation().catch(() => {});
  t.after(() => originHandle.close());
  const originResponse = await request(originHandle.preflight_url, { origin: "https://evil.example" });
  assert.equal(originResponse.status, 403);
  assert.equal(JSON.parse(originResponse.body).error.code, BROWSER_CLI_HANDOFF_ERRORS.ORIGIN);
  assert.equal(originResponse.headers["access-control-allow-origin"], undefined);

  const hostResponse = await request(originHandle.preflight_url, { host: `localhost:${originHandle.port}` });
  assert.equal(hostResponse.status, 400);
  assert.equal(JSON.parse(hostResponse.body).error.code, BROWSER_CLI_HANDOFF_ERRORS.HOST);

  const contentTypeResponse = await request(originHandle.url, { method: "POST", headers: { "Content-Type": "text/plain" }, body: bodyFor(originHandle) });
  assert.equal(contentTypeResponse.status, 415);
  assert.equal(JSON.parse(contentTypeResponse.body).error.code, BROWSER_CLI_HANDOFF_ERRORS.CONTENT_TYPE);

  const queryResponse = await request(`${originHandle.url}?credential=not-in-url`, { method: "POST", headers: { "Content-Type": "application/json" }, body: bodyFor(originHandle) });
  assert.equal(queryResponse.status, 400);
  assert.equal(queryResponse.body.includes("not-in-url"), false);

  const unknownResponse = await request(originHandle.url, { method: "POST", headers: { "Content-Type": "application/json" }, body: `${bodyFor(originHandle).slice(0, -1)},"unexpected":true}` });
  assert.equal(unknownResponse.status, 400);
  assert.equal(JSON.parse(unknownResponse.body).error.code, BROWSER_CLI_HANDOFF_ERRORS.INVALID_REQUEST);
});

test("rejects duplicate JSON keys and bodies over the configured bound", async (t) => {
  const handle = await start({ maxBodyBytes: 4096 });
  void handle.waitForInvitation().catch(() => {});
  t.after(() => handle.close());
  const challenge = handle.getPublicPreflight();
  const duplicate = JSON.stringify({ version: 1, correlation_id: challenge.correlation_id, nonce: challenge.nonce, invitation: invitation() }).replace("{\"version\":1", "{\"version\":1,\"version\":1");
  const duplicateResponse = await request(handle.url, { method: "POST", headers: { "Content-Type": "application/json" }, body: duplicate });
  assert.equal(duplicateResponse.status, 400);
  const tooLarge = await request(handle.url, { method: "POST", headers: { "Content-Type": "application/json", "Content-Length": "4097" }, body: "x" });
  assert.equal(tooLarge.status, 413);
});

test("bounds an incomplete request and tears down the socket on timeout", async (t) => {
  const handle = await start({ requestTimeoutMs: 100 });
  t.after(() => handle.close());
  void handle.waitForInvitation().catch(() => {});
  const parsed = new URL(handle.url);
  const began = Date.now();
  await assert.rejects(new Promise((resolve, reject) => {
    const client = http.request({
      hostname: "127.0.0.1",
      port: Number(parsed.port),
      path: parsed.pathname,
      method: "POST",
      headers: {
        Origin: ORIGIN,
        "Content-Type": "application/json",
        "Content-Length": "100"
      }
    });
    client.once("error", reject);
    client.write("{");
  }));
  assert.ok(Date.now() - began < 2_000, "incomplete requests must not remain open");
});

test("expires and aborts without leaving a listener or a durable side effect", async () => {
  const timeoutHandle = await start({ ttlMs: 1_000 });
  await assert.rejects(timeoutHandle.waitForInvitation(), (error) => error.code === BROWSER_CLI_HANDOFF_ERRORS.TIMEOUT);
  await timeoutHandle.close();

  const controller = new AbortController();
  const abortedHandle = await start({ signal: controller.signal });
  const waiting = abortedHandle.waitForInvitation();
  controller.abort();
  await assert.rejects(waiting, (error) => error.code === BROWSER_CLI_HANDOFF_ERRORS.ABORTED);
  await abortedHandle.close();
});

test("canonical invitation helper rejects a candidate substitution", () => {
  const value = invitation();
  assert.equal(canonicalizeBrowserCliInvitation(value, preflight()).invitation.version, 2);
  assert.throws(() => canonicalizeBrowserCliInvitation({ ...value, candidate_binding: { ...value.candidate_binding, candidate_id: "other-release" } }, preflight()), (error) => error instanceof BrowserCliHandoffError && error.code === BROWSER_CLI_HANDOFF_ERRORS.INVALID_INVITATION);
});
