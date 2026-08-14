import assert from "node:assert/strict";
import test from "node:test";
import { authenticateRecentAuth, registerPasskey, WebAuthnClientError } from "../app/webauthn-client.ts";

const organizationId = "11111111-1111-4111-8111-111111111111";
const challengeId = "22222222-2222-4222-8222-222222222222";
const authorizationId = "33333333-3333-4333-8333-333333333333";
const challenge = "A".repeat(43);
const csrfToken = "csrf-token-that-is-never-persisted";

const options = Object.freeze({
  challenge,
  rpId: "console.example.test",
  userVerification: "required",
  allowCredentials: [{ id: "Y3JlZGVudGlhbC0x", type: "public-key", transports: ["internal"] }],
});

const assertion = Object.freeze({
  id: "A".repeat(22),
  rawId: "A".repeat(22),
  response: {
    authenticatorData: "YXV0aGVudGljYXRvci1kYXRh",
    clientDataJSON: "Y2xpZW50LWRhdGE",
    signature: "c2lnbmF0dXJl",
  },
  type: "public-key",
  clientExtensionResults: {},
});

const registrationOptions = Object.freeze({
  rp: { id: "console.example.test", name: "AgentPass Console" },
  user: { id: "dXNlci0x", name: "operator@example.test", displayName: "Operator" },
  challenge,
  pubKeyCredParams: [{ type: "public-key", alg: -7 }, { type: "public-key", alg: -257 }],
  authenticatorSelection: { residentKey: "preferred", userVerification: "required" },
  attestation: "none",
  excludeCredentials: [],
});

const registrationCredential = Object.freeze({
  id: "A".repeat(22),
  rawId: "A".repeat(22),
  response: {
    clientDataJSON: "Y2xpZW50LWRhdGE",
    attestationObject: "YXR0ZXN0YXRpb24tb2JqZWN0",
    authenticatorData: "A".repeat(50),
    transports: ["internal"],
    publicKeyAlgorithm: -7,
  },
  type: "public-key",
  clientExtensionResults: {},
});

function jsonResponse(body, status = 200, headers = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", ...headers },
  });
}

function successfulTransport(calls, overrides = {}) {
  return async (url, init) => {
    calls.push({ url: String(url), init });
    const parsed = new URL(url, "https://console.example.test");
    if (parsed.pathname === "/api/auth/webauthn/options") return jsonResponse({ challenge_id: challengeId, options });
    if (parsed.pathname === "/api/auth/webauthn/verify") return jsonResponse({ authorization_id: authorizationId, ...overrides.verify });
    throw new Error(`unexpected path: ${parsed.pathname}`);
  };
}

test("posts options, runs startAuthentication, verifies, and returns only authorization_id", async () => {
  const calls = [];
  const authenticationCalls = [];
  const controller = new AbortController();
  const result = await authenticateRecentAuth({
    operation: "device.enrollment.issue",
    organizationId,
    csrfToken,
    signal: controller.signal,
    fetchImpl: successfulTransport(calls),
    startAuthenticationImpl: async (input) => {
      authenticationCalls.push(input);
      return assertion;
    },
  });

  assert.deepEqual(result, { authorization_id: authorizationId });
  assert.deepEqual(Object.keys(result), ["authorization_id"]);
  assert.equal(calls.length, 2);
  assert.deepEqual(calls.map((call) => call.url), ["/api/auth/webauthn/options", "/api/auth/webauthn/verify"]);
  for (const call of calls) {
    assert.equal(call.init.method, "POST");
    assert.equal(call.init.cache, "no-store");
    assert.equal(call.init.credentials, "same-origin");
    assert.equal(call.init.redirect, "error");
    assert.equal(call.init.signal, controller.signal);
    assert.equal(call.init.headers.get("cache-control"), "no-store");
    assert.equal(call.init.headers.get("content-type"), "application/json");
    assert.equal(call.init.headers.get("agentpass-csrf"), csrfToken);
    assert.equal(call.init.headers.get("accept"), "application/json");
    assert.equal(call.init.headers.get("pragma"), "no-cache");
  }
  assert.deepEqual(JSON.parse(calls[0].init.body), { organization_id: organizationId, operation: "device.enrollment.issue" });
  assert.deepEqual(authenticationCalls, [{ optionsJSON: options }]);
  const verifyBody = JSON.parse(calls[1].init.body);
  assert.deepEqual(verifyBody, { organization_id: organizationId, operation: "device.enrollment.issue", challenge_id: challengeId, credential: assertion });
  assert.equal(calls[1].url.includes(challenge), false);
});

test("posts strict registration options, runs startRegistration, and returns only completion state", async () => {
  const calls = [];
  const registrationCalls = [];
  const result = await registerPasskey({
    organizationId,
    csrfToken,
    fetchImpl: async (url, init) => {
      calls.push({ url: String(url), init });
      const parsed = new URL(url, "https://console.example.test");
      if (parsed.pathname === "/api/auth/webauthn/registration/options") return jsonResponse({ challenge_id: challengeId, options: registrationOptions });
      if (parsed.pathname === "/api/auth/webauthn/registration/verify") return jsonResponse({ credential_id: registrationCredential.id, registered_at: "2026-08-12T10:00:00.000Z" }, 201);
      throw new Error(`unexpected path: ${parsed.pathname}`);
    },
    startRegistrationImpl: async (input) => {
      registrationCalls.push(input);
      return registrationCredential;
    },
  });

  assert.deepEqual(result, { registered: true });
  assert.deepEqual(Object.keys(result), ["registered"]);
  assert.deepEqual(calls.map((call) => call.url), [
    "/api/auth/webauthn/registration/options",
    "/api/auth/webauthn/registration/verify",
  ]);
  assert.deepEqual(registrationCalls, [{ optionsJSON: registrationOptions }]);
  assert.deepEqual(JSON.parse(calls[0].init.body), { organization_id: organizationId });
  assert.deepEqual(JSON.parse(calls[1].init.body), {
    organization_id: organizationId,
    challenge_id: challengeId,
    credential: {
      id: registrationCredential.id,
      rawId: registrationCredential.rawId,
      response: {
        clientDataJSON: registrationCredential.response.clientDataJSON,
        attestationObject: registrationCredential.response.attestationObject,
        transports: registrationCredential.response.transports,
      },
      type: registrationCredential.type,
      clientExtensionResults: registrationCredential.clientExtensionResults,
    },
  });
  for (const call of calls) {
    assert.equal(call.init.method, "POST");
    assert.equal(call.init.credentials, "same-origin");
    assert.equal(call.init.cache, "no-store");
    assert.equal(call.init.redirect, "error");
    assert.equal(call.init.headers.get("agentpass-csrf"), csrfToken);
    assert.equal(call.init.headers.get("cache-control"), "no-store");
  }
  assert.equal(calls[1].url.includes(challenge), false);
});

test("steps up with the existing passkey before adding another credential and forwards only the opaque authorization id", async () => {
  const calls = [];
  let registrationOptionsCalls = 0;
  const result = await registerPasskey({
    organizationId,
    csrfToken,
    fetchImpl: async (url, init) => {
      calls.push({ url: String(url), init });
      const path = new URL(url, "https://console.example.test").pathname;
      if (path === "/api/auth/webauthn/registration/options") {
        registrationOptionsCalls += 1;
        if (registrationOptionsCalls === 1) return jsonResponse({ error: { code: "webauthn_registration_http_recent_auth_required", message: "Recent authentication required" } }, 428);
        return jsonResponse({ challenge_id: challengeId, options: registrationOptions });
      }
      if (path === "/api/auth/webauthn/options") return jsonResponse({ challenge_id: challengeId, options });
      if (path === "/api/auth/webauthn/verify") return jsonResponse({ authorization_id: authorizationId });
      if (path === "/api/auth/webauthn/registration/verify") return jsonResponse({ credential_id: registrationCredential.id, registered_at: "2026-08-12T10:00:00.000Z" }, 201);
      throw new Error(`unexpected path: ${path}`);
    },
    startAuthenticationImpl: async () => assertion,
    startRegistrationImpl: async () => registrationCredential,
  });

  assert.deepEqual(result, { registered: true });
  assert.deepEqual(calls.map(({ url }) => url), [
    "/api/auth/webauthn/registration/options",
    "/api/auth/webauthn/options",
    "/api/auth/webauthn/verify",
    "/api/auth/webauthn/registration/options",
    "/api/auth/webauthn/registration/verify",
  ]);
  for (const call of calls.slice(0, 3)) assert.equal(call.init.headers.has("agentpass-recent-auth"), false);
  assert.equal(calls[3].init.headers.get("agentpass-recent-auth"), authorizationId);
  assert.equal(calls[4].init.headers.get("agentpass-recent-auth"), authorizationId);
});

test("rejects malformed registration options without invoking the authenticator", async () => {
  let registrationCalls = 0;
  await assert.rejects(
    () => registerPasskey({
      organizationId,
      csrfToken,
      fetchImpl: async () => jsonResponse({ challenge_id: challengeId, options: { ...registrationOptions, unexpected: true } }),
      startRegistrationImpl: async () => {
        registrationCalls += 1;
        return registrationCredential;
      },
    }),
    (error) => error instanceof WebAuthnClientError && error.code === "invalid_registration_options",
  );
  assert.equal(registrationCalls, 0);
});

test("rejects malformed registration credential and never posts it", async () => {
  const calls = [];
  await assert.rejects(
    () => registerPasskey({
      organizationId,
      csrfToken,
      fetchImpl: async (url, init) => {
        calls.push({ url: String(url), init });
        return jsonResponse({ challenge_id: challengeId, options: registrationOptions });
      },
      startRegistrationImpl: async () => ({ ...registrationCredential, rawId: "different" }),
    }),
    (error) => error instanceof WebAuthnClientError && error.code === "invalid_registration_credential",
  );
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, "/api/auth/webauthn/registration/options");
});

test("rejects a non-exact registration completion response", async () => {
  await assert.rejects(
    () => registerPasskey({
      organizationId,
      csrfToken,
      fetchImpl: async (url) => String(url).includes("/options")
        ? jsonResponse({ challenge_id: challengeId, options: registrationOptions })
        : jsonResponse({ credential_id: registrationCredential.id, registered_at: "2026-08-12T10:00:00.000Z", extra: "must reject" }, 201),
      startRegistrationImpl: async () => registrationCredential,
    }),
    (error) => error instanceof WebAuthnClientError && error.code === "invalid_registration_result",
  );
});

test("rejects malformed options without invoking WebAuthn or verification", async () => {
  const calls = [];
  let authenticationCalls = 0;
  await assert.rejects(
    () => authenticateRecentAuth({
      operation: "device.enrollment.issue",
      organizationId,
      csrfToken,
      fetchImpl: async (url, init) => {
        calls.push({ url, init });
        return jsonResponse({ challenge_id: challengeId, options: { ...options, unexpected: true } });
      },
      startAuthenticationImpl: async () => {
        authenticationCalls += 1;
        return assertion;
      },
    }),
    (error) => error instanceof WebAuthnClientError && error.code === "invalid_options",
  );
  assert.equal(calls.length, 1);
  assert.equal(authenticationCalls, 0);
});

test("rejects malformed assertion and never posts it", async () => {
  const calls = [];
  await assert.rejects(
    () => authenticateRecentAuth({
      operation: "device.enrollment.issue",
      organizationId,
      csrfToken,
      fetchImpl: successfulTransport(calls),
      startAuthenticationImpl: async () => ({ ...assertion, response: { ...assertion.response, signature: "not base64 with spaces" } }),
    }),
    (error) => error instanceof WebAuthnClientError && error.code === "invalid_assertion",
  );
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, "/api/auth/webauthn/options");
});

test("rejects a non-exact authorization response", async () => {
  const calls = [];
  await assert.rejects(
    () => authenticateRecentAuth({
      operation: "device.enrollment.issue",
      organizationId,
      csrfToken,
      fetchImpl: successfulTransport(calls, { verify: { extra: "must reject" } }),
      startAuthenticationImpl: async () => assertion,
    }),
    (error) => error instanceof WebAuthnClientError && error.code === "invalid_authorization",
  );
  assert.equal(calls.length, 2);
});

test("allows only same-origin relative endpoint paths", async () => {
  for (const path of ["https://attacker.example.test/options", "//attacker.example.test/options", "/options?challenge=secret", "/options#challenge"]) {
    await assert.rejects(
      () => authenticateRecentAuth({
        operation: "device.enrollment.issue",
        organizationId,
        csrfToken,
        optionsPath: path,
        fetchImpl: async () => jsonResponse({}),
        startAuthenticationImpl: async () => assertion,
      }),
      (error) => error instanceof TypeError && /same-origin relative path/.test(error.message),
    );
  }
});

test("propagates AbortSignal through fetch and aborts an active WebAuthn ceremony", async () => {
  const controller = new AbortController();
  let resolveAuthentication;
  let authenticationStarted = false;
  const promise = authenticateRecentAuth({
    operation: "device.enrollment.issue",
    organizationId,
    csrfToken,
    signal: controller.signal,
    fetchImpl: async (url, init) => {
      assert.equal(init.signal, controller.signal);
      return jsonResponse({ challenge_id: challengeId, options });
    },
    startAuthenticationImpl: async () => {
      authenticationStarted = true;
      return new Promise((resolve) => { resolveAuthentication = resolve; });
    },
  });
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(authenticationStarted, true);
  controller.abort();
  await assert.rejects(promise, (error) => error?.name === "AbortError");
  resolveAuthentication?.(assertion);
});

test("does not access storage or logging APIs", async () => {
  const calls = [];
  const originalLog = console.log;
  const originalStorage = globalThis.localStorage;
  let logged = false;
  Object.defineProperty(console, "log", { configurable: true, value: () => { logged = true; } });
  Object.defineProperty(globalThis, "localStorage", { configurable: true, get() { throw new Error("storage access is forbidden"); } });
  try {
    await authenticateRecentAuth({
      operation: "device.enrollment.issue",
      organizationId,
      csrfToken,
      fetchImpl: successfulTransport(calls),
      startAuthenticationImpl: async () => assertion,
    });
  } finally {
    Object.defineProperty(console, "log", { configurable: true, value: originalLog });
    if (originalStorage === undefined) delete globalThis.localStorage;
    else Object.defineProperty(globalThis, "localStorage", { configurable: true, value: originalStorage });
  }
  assert.equal(logged, false);
});
