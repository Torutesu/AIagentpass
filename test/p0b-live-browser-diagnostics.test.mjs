import assert from "node:assert/strict";
import test from "node:test";

import { adminWakeFailureMarker, keyboardOutcomeFailureMarker, keyboardRecentAuthFailureMarker, lifecycleFailureMarker, staleAuthorizationFailureMarker, wakeAcceptedFailureMarker } from "./p0b-live-browser.integration.test.mjs";
import { classifyP0BStartupError, P0BLiveBrowserFixtureError } from "./support/p0b/live-browser-fixture.mjs";

function response(status, payload, parse = true) {
  return {
    status: () => status,
    json: async () => {
      if (!parse) throw new Error("invalid JSON");
      return payload;
    },
  };
}

const validPayload = {
  request_id: "request-id",
  refresh_request: {
    version: 1,
    request_id: "refresh-request-id",
    device_id: "device-id",
    desired_generation: 2,
    status: "accepted",
    requested_at: "2026-08-16T00:00:00.000Z",
  },
};

const verifiedRecentAuth = {
  optionsObserved: true,
  optionsStatus: 200,
  verifyObserved: true,
  verifyStatus: 200,
};

test("P0-B lifecycle diagnostics expose only reviewed timeout classes", () => {
  for (const [code, marker] of [
    ["startup_timeout", "P0B_SAFE_LIFECYCLE_FIXTURE_STARTUP_TIMEOUT_FAILED"],
    ["startup_failed", "P0B_SAFE_LIFECYCLE_FIXTURE_START_FAILED"],
    ["fixture_start_failed", "P0B_SAFE_LIFECYCLE_FIXTURE_START_FAILED"],
    ["database_prepare_failed", "P0B_SAFE_LIFECYCLE_DATABASE_PREPARE_FAILED"],
    ["browser_startup_timeout", "P0B_SAFE_LIFECYCLE_BROWSER_STARTUP_TIMEOUT_FAILED"],
    ["browser_startup_failed", "P0B_SAFE_LIFECYCLE_BROWSER_START_FAILED"],
    ["cleanup_timeout", "P0B_SAFE_LIFECYCLE_FIXTURE_CLEANUP_TIMEOUT_FAILED"],
    ["context_cleanup_timeout", "P0B_SAFE_LIFECYCLE_CONTEXT_CLEANUP_TIMEOUT_FAILED"],
    ["context_cleanup_failed", "P0B_SAFE_LIFECYCLE_CONTEXT_CLEANUP_FAILED"],
    ["browser_cleanup_timeout", "P0B_SAFE_LIFECYCLE_BROWSER_CLEANUP_TIMEOUT_FAILED"],
    ["browser_cleanup_failed", "P0B_SAFE_LIFECYCLE_BROWSER_CLEANUP_FAILED"]
  ]) {
    assert.equal(lifecycleFailureMarker(new P0BLiveBrowserFixtureError(code, "unsafe diagnostic")), marker);
  }
  assert.equal(lifecycleFailureMarker(new P0BLiveBrowserFixtureError("unknown", "unsafe")), null);
  for (const [message, marker] of [
    ["P0-B cloud exited before readiness (redacted)", "P0B_SAFE_LIFECYCLE_CLOUD_START_FAILED"],
    ["P0-B console exited before readiness (redacted)", "P0B_SAFE_LIFECYCLE_CONSOLE_START_FAILED"],
    ["P0-B cloud readiness failed (redacted)", "P0B_SAFE_LIFECYCLE_CLOUD_READINESS_FAILED"],
    ["P0-B console readiness failed (redacted)", "P0B_SAFE_LIFECYCLE_CONSOLE_READINESS_FAILED"],
    ["P0-B signer private key is invalid", "P0B_SAFE_LIFECYCLE_SIGNER_START_FAILED"],
  ]) assert.equal(lifecycleFailureMarker(new Error(message)), marker);
  assert.equal(lifecycleFailureMarker(new Error("unsafe")), null);
});

test("P0-B startup classification retains only fixed service categories", () => {
  assert.equal(classifyP0BStartupError(new Error("P0-B cloud kms_start_failed before readiness (redacted)")), "cloud_start_failed");
  assert.equal(classifyP0BStartupError(new Error("P0-B console dependency_start_failed before readiness (redacted)")), "console_start_failed");
  assert.equal(classifyP0BStartupError(new Error("P0-B cloud readiness failed (redacted)")), "cloud_readiness_failed");
  assert.equal(classifyP0BStartupError(new Error("ERR_KMS_PROVIDER_RUNTIME_CONFIG")), "cloud_kms_start_failed");
  assert.equal(classifyP0BStartupError(new Error("unsafe arbitrary diagnostic")), null);
});

test("P0-B stale-authorization diagnostics expose only a fixed phase or status class", () => {
  assert.equal(staleAuthorizationFailureMarker({ phase: "response", status: 401 }), null);
  assert.equal(staleAuthorizationFailureMarker({ phase: "invalidation_failed", status: null }), "P0B_SAFE_STALE_AUTH_INVALIDATION_FAILED");
  assert.equal(staleAuthorizationFailureMarker({ phase: "fetch_failed", status: null }), "P0B_SAFE_STALE_AUTH_FETCH_FAILED");
  assert.equal(staleAuthorizationFailureMarker({ phase: "response", status: 204 }), "P0B_SAFE_STALE_AUTH_HTTP_2XX_FAILED");
  assert.equal(staleAuthorizationFailureMarker({ phase: "response", status: 403 }), "P0B_SAFE_STALE_AUTH_HTTP_4XX_FAILED");
  assert.equal(staleAuthorizationFailureMarker({ phase: "response", status: 503 }), "P0B_SAFE_STALE_AUTH_HTTP_5XX_FAILED");
  assert.equal(staleAuthorizationFailureMarker({ phase: "response", status: 302 }), "P0B_SAFE_STALE_AUTH_HTTP_OTHER_FAILED");
  assert.equal(staleAuthorizationFailureMarker({ phase: "unexpected", status: 401 }), "P0B_SAFE_STALE_AUTH_RESPONSE_FAILED");
});

test("P0-B keyboard diagnostics classify the reviewed HTTP statuses without payload output", async () => {
  for (const [status, marker] of [
    [400, "P0B_SAFE_KEYBOARD_OUTCOME_HTTP_400_FAILED"],
    [401, "P0B_SAFE_KEYBOARD_OUTCOME_HTTP_401_FAILED"],
    [403, "P0B_SAFE_KEYBOARD_OUTCOME_HTTP_403_FAILED"],
    [409, "P0B_SAFE_KEYBOARD_OUTCOME_HTTP_409_FAILED"],
    [422, "P0B_SAFE_KEYBOARD_OUTCOME_HTTP_422_FAILED"],
    [429, "P0B_SAFE_KEYBOARD_OUTCOME_HTTP_429_FAILED"],
    [500, "P0B_SAFE_KEYBOARD_OUTCOME_HTTP_500_FAILED"],
    [502, "P0B_SAFE_KEYBOARD_OUTCOME_HTTP_502_FAILED"],
    [503, "P0B_SAFE_KEYBOARD_OUTCOME_HTTP_503_FAILED"],
    [504, "P0B_SAFE_KEYBOARD_OUTCOME_HTTP_504_FAILED"],
    [418, "P0B_SAFE_KEYBOARD_OUTCOME_HTTP_4XX_FAILED"],
    [508, "P0B_SAFE_KEYBOARD_OUTCOME_HTTP_5XX_FAILED"],
    [301, "P0B_SAFE_KEYBOARD_OUTCOME_HTTP_OTHER_FAILED"],
  ]) {
    assert.equal(await keyboardOutcomeFailureMarker(response(status, { secret: "not inspected" })), marker);
  }
});

test("P0-B keyboard diagnostics separate transport, 2xx contract, and UI parsing failures", async () => {
  assert.equal(await keyboardOutcomeFailureMarker(null), "P0B_SAFE_KEYBOARD_OUTCOME_NO_REQUEST_FAILED");
  assert.equal(await keyboardOutcomeFailureMarker(null, { refreshRequestObserved: true }), "P0B_SAFE_KEYBOARD_OUTCOME_RESPONSE_TIMEOUT_FAILED");
  assert.equal(await keyboardOutcomeFailureMarker(null, { refreshRequestObserved: true, refreshRequestFailed: true }), "P0B_SAFE_KEYBOARD_OUTCOME_TRANSPORT_FAILED");
  assert.equal(await keyboardOutcomeFailureMarker(response(202, null, false)), "P0B_SAFE_KEYBOARD_OUTCOME_2XX_RESPONSE_CONTRACT_FAILED");
  assert.equal(await keyboardOutcomeFailureMarker(response(202, { refresh_request: {} })), "P0B_SAFE_KEYBOARD_OUTCOME_2XX_RESPONSE_CONTRACT_FAILED");
  assert.equal(await keyboardOutcomeFailureMarker(response(202, validPayload)), "P0B_SAFE_KEYBOARD_OUTCOME_2XX_UI_PARSE_FAILED");
});

test("P0-B keyboard diagnostics localize pre-refresh recent-auth failures without unsafe response bodies", async () => {
  assert.equal(await keyboardRecentAuthFailureMarker(), "P0B_SAFE_KEYBOARD_AUTH_CONFIRM_NO_ACTION_FAILED");
  assert.equal(await keyboardRecentAuthFailureMarker({ wakePendingObserved: true }), "P0B_SAFE_KEYBOARD_AUTH_OPTIONS_NO_REQUEST_FAILED");
  assert.equal(await keyboardRecentAuthFailureMarker({ webAuthnSupported: false }), "P0B_SAFE_KEYBOARD_AUTH_WEBAUTHN_UNAVAILABLE_FAILED");
  assert.equal(await keyboardRecentAuthFailureMarker({ webAuthnSupported: true, sessionObserved: true, sessionFailed: true }), "P0B_SAFE_KEYBOARD_AUTH_SESSION_TRANSPORT_FAILED");
  assert.equal(await keyboardRecentAuthFailureMarker({ webAuthnSupported: true, sessionObserved: true, sessionStatus: 401 }), "P0B_SAFE_KEYBOARD_AUTH_SESSION_HTTP_4XX_FAILED");
  assert.equal(await keyboardRecentAuthFailureMarker({ webAuthnSupported: true, sessionObserved: true, sessionStatus: 503 }), "P0B_SAFE_KEYBOARD_AUTH_SESSION_HTTP_5XX_FAILED");
  assert.equal(await keyboardRecentAuthFailureMarker({ webAuthnSupported: true, sessionObserved: true, sessionStatus: 200 }), "P0B_SAFE_KEYBOARD_AUTH_SESSION_SUCCEEDED_NO_OPTIONS_FAILED");
  assert.equal(await keyboardRecentAuthFailureMarker({ optionsObserved: true, optionsFailed: true }), "P0B_SAFE_KEYBOARD_AUTH_OPTIONS_TRANSPORT_FAILED");
  assert.equal(await keyboardRecentAuthFailureMarker({ optionsObserved: true, optionsStatus: 403 }), "P0B_SAFE_KEYBOARD_AUTH_OPTIONS_HTTP_4XX_FAILED");
  assert.equal(await keyboardRecentAuthFailureMarker({ optionsObserved: true, optionsStatus: 503 }), "P0B_SAFE_KEYBOARD_AUTH_OPTIONS_HTTP_5XX_FAILED");
  assert.equal(await keyboardRecentAuthFailureMarker({ optionsObserved: true, optionsStatus: 200 }), "P0B_SAFE_KEYBOARD_AUTH_VERIFY_NO_REQUEST_FAILED");
  assert.equal(await keyboardRecentAuthFailureMarker({ optionsObserved: true, optionsStatus: 200, verifyObserved: true, verifyFailed: true }), "P0B_SAFE_KEYBOARD_AUTH_VERIFY_TRANSPORT_FAILED");
  for (const status of [400, 401, 403, 409, 422, 428, 429]) {
    assert.equal(await keyboardRecentAuthFailureMarker({ optionsObserved: true, optionsStatus: 200, verifyObserved: true, verifyStatus: status }), `P0B_SAFE_KEYBOARD_AUTH_VERIFY_HTTP_${status}_FAILED`);
  }
  for (const [code, suffix] of [["human_auth_credential_not_allowed", "CREDENTIAL_NOT_ALLOWED"], ["human_auth_webauthn_verification_failed", "WEBAUTHN_VERIFICATION_FAILED"], ["human_auth_session_required", "SESSION_REQUIRED"]]) {
    assert.equal(await keyboardRecentAuthFailureMarker({ optionsObserved: true, optionsStatus: 200, verifyObserved: true, verifyStatus: 401, verifyResponse: response(401, { error: { code, unsafe: "ignored" } }) }), `P0B_SAFE_KEYBOARD_AUTH_VERIFY_HTTP_401_${suffix}_FAILED`);
  }
  assert.equal(await keyboardRecentAuthFailureMarker({ optionsObserved: true, optionsStatus: 200, verifyObserved: true, verifyStatus: 418 }), "P0B_SAFE_KEYBOARD_AUTH_VERIFY_HTTP_4XX_FAILED");
  assert.equal(await keyboardRecentAuthFailureMarker({ optionsObserved: true, optionsStatus: 200, verifyObserved: true, verifyStatus: 502 }), "P0B_SAFE_KEYBOARD_AUTH_VERIFY_HTTP_5XX_FAILED");
  assert.equal(await keyboardRecentAuthFailureMarker({ optionsObserved: true, optionsStatus: 200, verifyObserved: true, verifyStatus: 200 }), "P0B_SAFE_KEYBOARD_AUTH_VERIFIED_NO_REFRESH_FAILED");
});

test("accepted wake diagnostics distinguish authority failures, ledger outcomes, and UI parsing", async () => {
  assert.equal(await wakeAcceptedFailureMarker(null, { recentAuthObservation: { optionsObserved: true, optionsStatus: 200 } }), "P0B_SAFE_KEYBOARD_AUTH_VERIFY_NO_REQUEST_FAILED");
  assert.equal(await wakeAcceptedFailureMarker(response(503, { secret: "ignored" })), "P0B_SAFE_KEYBOARD_OUTCOME_HTTP_503_FAILED");
  assert.equal(await wakeAcceptedFailureMarker(response(202, null, false)), "P0B_SAFE_KEYBOARD_OUTCOME_2XX_RESPONSE_CONTRACT_FAILED");
  assert.equal(await wakeAcceptedFailureMarker(response(202, { ...validPayload, refresh_request: { ...validPayload.refresh_request, status: "coalesced" } })), "P0B_SAFE_WAKE_ACCEPTED_GOT_COALESCED_FAILED");
  assert.equal(await wakeAcceptedFailureMarker(response(202, { ...validPayload, refresh_request: { ...validPayload.refresh_request, status: "no_pending_refresh" } })), "P0B_SAFE_WAKE_ACCEPTED_GOT_NO_PENDING_FAILED");
  assert.equal(await wakeAcceptedFailureMarker(response(202, validPayload)), "P0B_SAFE_WAKE_ACCEPTED_UI_STATUS_FAILED");
});

test("P0-B admin wake diagnostics distinguish WebAuthn options and verify phases", async () => {
  for (const [observation, marker] of [
    [{ optionsObserved: true, optionsFailed: true }, "P0B_SAFE_ADMIN_WAKE_AUTH_OPTIONS_TRANSPORT_FAILED"],
    [{ optionsObserved: true, optionsStatus: null }, "P0B_SAFE_ADMIN_WAKE_AUTH_OPTIONS_TRANSPORT_FAILED"],
    [{ optionsObserved: true, optionsStatus: 403 }, "P0B_SAFE_ADMIN_WAKE_AUTH_OPTIONS_HTTP_4XX_FAILED"],
    [{ optionsObserved: true, optionsStatus: 503 }, "P0B_SAFE_ADMIN_WAKE_AUTH_OPTIONS_HTTP_5XX_FAILED"],
    [{ optionsObserved: true, optionsStatus: 302 }, "P0B_SAFE_ADMIN_WAKE_AUTH_OPTIONS_HTTP_OTHER_FAILED"],
    [{ optionsObserved: true, optionsStatus: 200 }, "P0B_SAFE_ADMIN_WAKE_AUTH_VERIFY_TRANSPORT_FAILED"],
    [{ optionsObserved: true, optionsStatus: 200, verifyObserved: true, verifyFailed: true }, "P0B_SAFE_ADMIN_WAKE_AUTH_VERIFY_TRANSPORT_FAILED"],
    [{ optionsObserved: true, optionsStatus: 200, verifyObserved: true, verifyStatus: null }, "P0B_SAFE_ADMIN_WAKE_AUTH_VERIFY_TRANSPORT_FAILED"],
    [{ optionsObserved: true, optionsStatus: 200, verifyObserved: true, verifyStatus: 403 }, "P0B_SAFE_ADMIN_WAKE_AUTH_VERIFY_HTTP_403_FAILED"],
    [{ optionsObserved: true, optionsStatus: 200, verifyObserved: true, verifyStatus: 503 }, "P0B_SAFE_ADMIN_WAKE_AUTH_VERIFY_HTTP_5XX_FAILED"],
    [{ optionsObserved: true, optionsStatus: 200, verifyObserved: true, verifyStatus: 302 }, "P0B_SAFE_ADMIN_WAKE_AUTH_VERIFY_HTTP_OTHER_FAILED"],
  ]) {
    assert.equal(await adminWakeFailureMarker(null, { recentAuthObservation: observation }), marker);
  }
  for (const [code, suffix] of [["human_auth_credential_not_allowed", "CREDENTIAL_NOT_ALLOWED"], ["human_auth_webauthn_verification_failed", "WEBAUTHN_VERIFICATION_FAILED"], ["human_auth_session_required", "SESSION_REQUIRED"]]) {
    const verifyResponse = response(401, { error: { code, unsafe: "ignored" } });
    assert.equal(await adminWakeFailureMarker(null, { recentAuthObservation: { optionsObserved: true, optionsStatus: 200, verifyObserved: true, verifyStatus: 401, verifyResponse } }), `P0B_SAFE_ADMIN_WAKE_AUTH_VERIFY_HTTP_401_${suffix}_FAILED`);
  }
});

test("P0-B admin wake diagnostics distinguish refresh transport, HTTP, and response contract failures", async () => {
  assert.equal(await adminWakeFailureMarker(null, { recentAuthObservation: verifiedRecentAuth, refreshRequestFailed: true }), "P0B_SAFE_ADMIN_WAKE_REFRESH_TRANSPORT_FAILED");
  assert.equal(await adminWakeFailureMarker(null, { recentAuthObservation: verifiedRecentAuth, refreshRequestObserved: true }), "P0B_SAFE_ADMIN_WAKE_REFRESH_RESPONSE_TIMEOUT_FAILED");
  for (const [status, marker] of [
    [400, "P0B_SAFE_ADMIN_WAKE_REFRESH_HTTP_4XX_FAILED"],
    [503, "P0B_SAFE_ADMIN_WAKE_REFRESH_HTTP_5XX_FAILED"],
    [301, "P0B_SAFE_ADMIN_WAKE_REFRESH_HTTP_OTHER_FAILED"],
  ]) {
    assert.equal(await adminWakeFailureMarker(response(status, { secret: "not inspected" }), { recentAuthObservation: verifiedRecentAuth }), marker);
  }
  assert.equal(await adminWakeFailureMarker(response(202, null, false), { recentAuthObservation: verifiedRecentAuth }), "P0B_SAFE_ADMIN_WAKE_REFRESH_2XX_RESPONSE_CONTRACT_FAILED");
  assert.equal(await adminWakeFailureMarker(response(202, { refresh_request: {} }), { recentAuthObservation: verifiedRecentAuth }), "P0B_SAFE_ADMIN_WAKE_REFRESH_2XX_RESPONSE_CONTRACT_FAILED");
});

test("P0-B admin wake diagnostics distinguish UI alert, timeout, and copy mismatch", async () => {
  const observation = { recentAuthObservation: verifiedRecentAuth };
  assert.equal(await adminWakeFailureMarker(null, observation, "alert"), "P0B_SAFE_ADMIN_WAKE_UI_ALERT_FAILED");
  assert.equal(await adminWakeFailureMarker(null, observation, "timeout"), "P0B_SAFE_ADMIN_WAKE_UI_TIMEOUT_FAILED");
  assert.equal(await adminWakeFailureMarker(response(202, validPayload), observation, "alert"), "P0B_SAFE_ADMIN_WAKE_UI_ALERT_FAILED");
  assert.equal(await adminWakeFailureMarker(response(202, validPayload), observation, "timeout"), "P0B_SAFE_ADMIN_WAKE_UI_TIMEOUT_FAILED");
  assert.equal(await adminWakeFailureMarker(response(202, validPayload), observation, "copy_mismatch"), "P0B_SAFE_ADMIN_WAKE_UI_COPY_MISMATCH_FAILED");
  assert.equal(await adminWakeFailureMarker(response(202, validPayload), observation), "P0B_SAFE_ADMIN_WAKE_UI_COPY_MISMATCH_FAILED");
});

test("P0-B admin wake diagnostics prioritize the earliest safe failure boundary", async () => {
  assert.equal(await adminWakeFailureMarker(response(503, { secret: "ignored" }), {
    recentAuthObservation: { optionsObserved: true, optionsStatus: 403 },
  }, "alert"), "P0B_SAFE_ADMIN_WAKE_AUTH_OPTIONS_HTTP_4XX_FAILED");
  assert.equal(await adminWakeFailureMarker(response(503, { secret: "ignored" }), {
    recentAuthObservation: verifiedRecentAuth,
  }, "alert"), "P0B_SAFE_ADMIN_WAKE_REFRESH_HTTP_5XX_FAILED");
  assert.equal(await adminWakeFailureMarker(null, {}, "alert"), "P0B_SAFE_ADMIN_WAKE_UI_ALERT_FAILED");
});
