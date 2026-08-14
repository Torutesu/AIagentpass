import assert from "node:assert/strict";
import test from "node:test";
import {
  BROWSER_CLI_HANDOFF_ERRORS,
  BrowserCliHandoffClientError,
  buildBrowserCliHandoffEnvelope,
  fetchBrowserCliHandoffPreflight,
  parseBrowserCliHandoffLaunchFragment,
  parseBrowserCliHandoffPreflight,
  postBrowserCliHandoff,
  publicEnrollmentPreflight,
} from "../lib/browser-cli-handoff.mjs";

const correlationId = "A".repeat(43);
const nonce = "B".repeat(43);
const url = `http://127.0.0.1:49152/v1/browser-cli-handoffs/${correlationId}`;
const handoff = { url, preflight_url: `${url}/preflight`, correlation_id: correlationId };
const invitation = { version: 2, proof_version: 2, platform: "macos", credential: "C".repeat(43) };

function preflight(overrides = {}) {
  return {
    version: 1,
    correlation_id: correlationId,
    nonce,
    platform: "macos",
    candidate_id: "candidate-2026-08",
    device_key_fingerprint: `SHA256:${"D".repeat(43)}`,
    ...overrides,
  };
}

function response(body, status = 200) {
  return { status, ok: status >= 200 && status < 300, json: async () => body };
}

test("accepts only a raw loopback handoff URL and derives the preflight path", () => {
  assert.deepEqual(parseBrowserCliHandoffLaunchFragment(`#${url}`), handoff);
  assert.deepEqual(parseBrowserCliHandoffLaunchFragment(`#${encodeURIComponent(url)}`), handoff);
  for (const fragment of [
    "#https://127.0.0.1:49152/v1/browser-cli-handoffs/" + correlationId,
    "#http://localhost:49152/v1/browser-cli-handoffs/" + correlationId,
    "#http://127.0.0.1:49152/v1/browser-cli-handoffs/" + correlationId + "?nonce=" + nonce,
    "#http://user:pass@127.0.0.1:49152/v1/browser-cli-handoffs/" + correlationId,
    "#http://127.0.0.1:49152/v1/browser-cli-handoffs/short",
    "#handoff=" + url,
    "#http://127.0.0.1:49152/v1/browser-cli-handoffs/" + correlationId + "/",
    "#http://127.0.0.1:49152/v1/browser-cli-handoffs/" + correlationId + "#nonce",
  ]) {
    assert.throws(() => parseBrowserCliHandoffLaunchFragment(fragment), (error) => error.code === BROWSER_CLI_HANDOFF_ERRORS.INVALID_FRAGMENT);
  }
  assert.equal(parseBrowserCliHandoffLaunchFragment(""), null);
});

test("validates exact preflight fields and rejects substituted correlation or sensitive extras", () => {
  const value = parseBrowserCliHandoffPreflight(preflight(), correlationId);
  assert.equal(value.nonce, nonce);
  assert.deepEqual(publicEnrollmentPreflight(value), {
    version: 1,
    platform: "macos",
    candidate_id: "candidate-2026-08",
    device_key_fingerprint: `SHA256:${"D".repeat(43)}`,
  });
  for (const valueToReject of [
    preflight({ correlation_id: "E".repeat(43) }),
    preflight({ credential: "secret" }),
    preflight({ platform: "windows" }),
    preflight({ candidate_id: "candidate with spaces" }),
  ]) {
    assert.throws(() => parseBrowserCliHandoffPreflight(valueToReject, correlationId), BrowserCliHandoffClientError);
  }
});

test("GETs preflight with no-store and validates the response before exposing public fields", async () => {
  let request;
  const value = await fetchBrowserCliHandoffPreflight({
    handoff,
    fetchImpl: async (input, init) => {
      request = { input, init };
      return response(preflight());
    },
  });
  assert.equal(request.input, handoff.preflight_url);
  assert.equal(request.init.method, "GET");
  assert.equal(request.init.cache, "no-store");
  assert.equal(request.init.credentials, "omit");
  assert.equal(request.init.redirect, "error");
  assert.deepEqual(publicEnrollmentPreflight(value).candidate_id, "candidate-2026-08");
  await assert.rejects(fetchBrowserCliHandoffPreflight({ handoff, fetchImpl: async () => response(preflight({ correlation_id: "E".repeat(43) })) }), (error) => error.code === BROWSER_CLI_HANDOFF_ERRORS.INVALID_PREFLIGHT);
  await assert.rejects(fetchBrowserCliHandoffPreflight({ handoff, fetchImpl: async () => { throw new Error("CORS"); } }), (error) => error.code === BROWSER_CLI_HANDOFF_ERRORS.PREFLIGHT_UNAVAILABLE);
});

test("POSTs exactly the bound envelope and accepts only the exact ACK", async () => {
  let request;
  const envelope = buildBrowserCliHandoffEnvelope({ correlation_id: correlationId, nonce, invitation });
  assert.deepEqual(Object.keys(envelope), ["version", "correlation_id", "nonce", "invitation"]);
  await postBrowserCliHandoff({
    handoff,
    correlation_id: correlationId,
    nonce,
    invitation,
    fetchImpl: async (input, init) => {
      request = { input, init };
      return response({ version: 1, ok: true, consumed: true });
    },
  });
  assert.equal(request.input, url);
  assert.equal(request.init.method, "POST");
  assert.equal(request.init.cache, "no-store");
  assert.equal(request.init.credentials, "omit");
  assert.deepEqual(JSON.parse(request.init.body), { version: 1, correlation_id: correlationId, nonce, invitation });
  await assert.rejects(postBrowserCliHandoff({ handoff, correlation_id: correlationId, nonce, invitation, fetchImpl: async () => response({ version: 1, ok: true, consumed: false }) }), (error) => error.code === BROWSER_CLI_HANDOFF_ERRORS.INVALID_ACK);
  await assert.rejects(postBrowserCliHandoff({ handoff, correlation_id: correlationId, nonce, invitation, fetchImpl: async () => response({ version: 1, ok: true, consumed: true, credential: "must-not-be-accepted" }) }), (error) => error.code === BROWSER_CLI_HANDOFF_ERRORS.INVALID_ACK);
  assert.throws(() => buildBrowserCliHandoffEnvelope({ correlation_id: correlationId, nonce, invitation, extra: "reject" }), BrowserCliHandoffClientError);
});
