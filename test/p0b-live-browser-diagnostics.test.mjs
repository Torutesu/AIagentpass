import assert from "node:assert/strict";
import test from "node:test";

import { keyboardOutcomeFailureMarker, keyboardRecentAuthFailureMarker } from "./p0b-live-browser.integration.test.mjs";

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

test("P0-B keyboard diagnostics localize pre-refresh recent-auth failures without response bodies", () => {
  assert.equal(keyboardRecentAuthFailureMarker(), "P0B_SAFE_KEYBOARD_AUTH_OPTIONS_NO_REQUEST_FAILED");
  assert.equal(keyboardRecentAuthFailureMarker({ optionsObserved: true, optionsFailed: true }), "P0B_SAFE_KEYBOARD_AUTH_OPTIONS_TRANSPORT_FAILED");
  assert.equal(keyboardRecentAuthFailureMarker({ optionsObserved: true, optionsStatus: 403 }), "P0B_SAFE_KEYBOARD_AUTH_OPTIONS_HTTP_4XX_FAILED");
  assert.equal(keyboardRecentAuthFailureMarker({ optionsObserved: true, optionsStatus: 503 }), "P0B_SAFE_KEYBOARD_AUTH_OPTIONS_HTTP_5XX_FAILED");
  assert.equal(keyboardRecentAuthFailureMarker({ optionsObserved: true, optionsStatus: 200 }), "P0B_SAFE_KEYBOARD_AUTH_VERIFY_NO_REQUEST_FAILED");
  assert.equal(keyboardRecentAuthFailureMarker({ optionsObserved: true, optionsStatus: 200, verifyObserved: true, verifyFailed: true }), "P0B_SAFE_KEYBOARD_AUTH_VERIFY_TRANSPORT_FAILED");
  assert.equal(keyboardRecentAuthFailureMarker({ optionsObserved: true, optionsStatus: 200, verifyObserved: true, verifyStatus: 401 }), "P0B_SAFE_KEYBOARD_AUTH_VERIFY_HTTP_4XX_FAILED");
  assert.equal(keyboardRecentAuthFailureMarker({ optionsObserved: true, optionsStatus: 200, verifyObserved: true, verifyStatus: 502 }), "P0B_SAFE_KEYBOARD_AUTH_VERIFY_HTTP_5XX_FAILED");
  assert.equal(keyboardRecentAuthFailureMarker({ optionsObserved: true, optionsStatus: 200, verifyObserved: true, verifyStatus: 200 }), "P0B_SAFE_KEYBOARD_AUTH_VERIFIED_NO_REFRESH_FAILED");
});
