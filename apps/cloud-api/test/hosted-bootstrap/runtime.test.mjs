import assert from "node:assert/strict";
import test from "node:test";

import {
  createHostedBootstrapRateLimiter,
  createHostedBootstrapRuntime,
  loadHostedBootstrapRuntimeConfig
} from "../../src/hosted-bootstrap/runtime.mjs";
import { HOSTED_BOOTSTRAP_HTTP_PATHS, HOSTED_BOOTSTRAP_OPERATIONS } from "../../src/hosted-bootstrap/http-api.mjs";

const HUMAN_KEY = Buffer.alloc(32, 0x61);

function env(overrides = {}) {
  return {
    AGENTPASS_CLOUD_PROFILE: "hosted",
    AGENTPASS_CONSOLE_ORIGIN: "https://console.example.test",
    AGENTPASS_WEBAUTHN_RP_ID: "example.test",
    AGENTPASS_GITHUB_CLIENT_ID: "agentpass-test",
    AGENTPASS_GITHUB_CLIENT_SECRET: "github-test-secret",
    AGENTPASS_GITHUB_REDIRECT_URI: "https://console.example.test/api/auth/bootstrap/github/callback",
    AGENTPASS_HOSTED_CONSOLE_ONBOARDING_URL: "https://console.example.test/onboarding",
    AGENTPASS_HOSTED_PKCE_KEY_ID: "pkce-v1",
    AGENTPASS_HOSTED_PKCE_KEY: Buffer.alloc(32, 0x62).toString("base64url"),
    AGENTPASS_HOSTED_BOOTSTRAP_CSRF_KEY: Buffer.alloc(32, 0x63).toString("base64url"),
    AGENTPASS_HOSTED_WEBAUTHN_RESPONSE_KEY: Buffer.alloc(32, 0x64).toString("base64url"),
    ...overrides
  };
}

function repository() {
  return Object.fromEntries([
    "startOAuthV2", "claimOAuthStateV2", "failOAuthState", "completeOAuthStateV2",
    "getBootstrapStatus", "verifyBootstrapCsrf", "commitOrganizationV2",
    "createChallenge", "claimChallengeV2", "completeWebAuthnRegistrationV3", "failChallengeV3"
  ].map((method) => [method, async () => { throw new Error(`unexpected call: ${method}`); }]));
}

test("Hosted composition exposes six routes while keeping every key private", () => {
  const runtime = createHostedBootstrapRuntime({
    env: env(),
    repository: repository(),
    registrationVerifier: { async generateOptions() {}, async verifyAttestation() {} },
    rateLimitRepository: { async acquireAnonymousRateLimit() { return { allowed: true }; } },
    rateLimitSecret: Buffer.alloc(32, 0x65),
    humanAuthSecret: HUMAN_KEY
  });
  assert.equal(typeof runtime.api.handle, "function");
  assert.deepEqual(runtime.api.paths, HOSTED_BOOTSTRAP_HTTP_PATHS);
  assert.deepEqual(runtime.config, {
    origin: "https://console.example.test",
    rpId: "example.test",
    consoleOnboardingUrl: "https://console.example.test/onboarding",
    pkceKeyId: "pkce-v1"
  });
  assert.equal(JSON.stringify(runtime).includes(env().AGENTPASS_HOSTED_PKCE_KEY), false);
  assert.equal(JSON.stringify(runtime).includes(env().AGENTPASS_HOSTED_BOOTSTRAP_CSRF_KEY), false);
  assert.equal(JSON.stringify(runtime).includes(env().AGENTPASS_HOSTED_WEBAUTHN_RESPONSE_KEY), false);
});

test("Hosted configuration fails closed on missing, aliased, or mismatched authority", () => {
  assert.throws(() => loadHostedBootstrapRuntimeConfig(env({ AGENTPASS_HOSTED_BOOTSTRAP_CSRF_KEY: undefined }), { humanAuthSecret: HUMAN_KEY }), /CSRF_KEY/);
  assert.throws(() => loadHostedBootstrapRuntimeConfig(env({ AGENTPASS_HOSTED_BOOTSTRAP_CSRF_KEY: env().AGENTPASS_HOSTED_PKCE_KEY }), { humanAuthSecret: HUMAN_KEY }), /purpose-separated/);
  assert.throws(() => loadHostedBootstrapRuntimeConfig(env({ AGENTPASS_HOSTED_CONSOLE_ONBOARDING_URL: "https://evil.example/onboarding" }), { humanAuthSecret: HUMAN_KEY }), /ONBOARDING_URL/);
  assert.throws(() => createHostedBootstrapRuntime({
    env: env({ AGENTPASS_GITHUB_REDIRECT_URI: "https://console.example.test/wrong" }),
    repository: repository(),
    registrationVerifier: { async generateOptions() {}, async verifyAttestation() {} },
    rateLimitRepository: { async acquireAnonymousRateLimit() { return { allowed: true }; } },
    rateLimitSecret: Buffer.alloc(32, 0x65),
    humanAuthSecret: HUMAN_KEY
  }), /redirect URI/);
});

test("Hosted limiter binds each exact operation/method/path to a stable PostgreSQL bucket", async () => {
  const calls = [];
  const repository = {
    async acquireAnonymousRateLimit(input) {
      calls.push(input);
      return { allowed: calls.length === 1 };
    }
  };
  const first = createHostedBootstrapRateLimiter({ repository, secret: Buffer.alloc(32, 0x66) });
  const restarted = createHostedBootstrapRateLimiter({ repository, secret: Buffer.alloc(32, 0x66) });
  assert.deepEqual(await first.authorize({ operation: HOSTED_BOOTSTRAP_OPERATIONS.status, method: "GET", path: HOSTED_BOOTSTRAP_HTTP_PATHS.status }), { allowed: true });
  assert.deepEqual(await restarted.authorize({ operation: HOSTED_BOOTSTRAP_OPERATIONS.status, method: "GET", path: HOSTED_BOOTSTRAP_HTTP_PATHS.status }), { allowed: false });
  assert.equal(calls[0].operation, HOSTED_BOOTSTRAP_OPERATIONS.status);
  assert.equal(calls[0].principalId, calls[1].principalId);
  assert.match(calls[0].principalId, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u);
  await assert.rejects(first.authorize({ operation: HOSTED_BOOTSTRAP_OPERATIONS.status, method: "POST", path: HOSTED_BOOTSTRAP_HTTP_PATHS.status }), /invalid/);
  assert.equal(calls.length, 2);
});
