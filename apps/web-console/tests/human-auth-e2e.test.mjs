import assert from "node:assert/strict";
import test from "node:test";
import { createCloudApi } from "../../cloud-api/src/server.mjs";
import { createHumanAuthBridge } from "../lib/human-auth-api.mjs";

const cookie = `__Host-agentpass_session=${"A".repeat(43)}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=3600`;
const csrf = "B".repeat(43);
const organizationId = "11111111-1111-4111-8111-111111111111";
const challengeId = "22222222-2222-4222-8222-222222222222";
const authorizationId = "33333333-3333-4333-8333-333333333333";
const decision = { allowed: true, limit: 30, remaining: 29, retryAfterSeconds: 0, resetAt: Date.now() + 60_000 };

test("browser-shaped requests cross Console BFF and Cloud Human Auth without exposing the service token", async (t) => {
  const cloudCalls = [];
  const cloud = createCloudApi({
    store: {},
    rateLimiter: { acquire: () => ({ ...decision }) },
    admissionRateLimiter: { acquire: () => ({ ...decision }) },
    humanAuthApi: {
      async handle(input) {
        cloudCalls.push(input);
        if (input.url === "/api/auth/session") return { status: 201, headers: { "Set-Cookie": cookie }, body: { session: { version: 1, session_id: "11111111-1111-4111-8111-111111111111", member_id: "22222222-2222-4222-8222-222222222222", organization_id: organizationId, role: "owner", created_at: "2026-08-12T00:00:00.000Z", expires_at: "2026-08-12T01:00:00.000Z", recent_auth_at: null }, csrf_token: csrf } };
        if (input.url === "/api/auth/webauthn/options") return { status: 200, headers: {}, body: { challenge_id: challengeId, options: { challenge: "C".repeat(43), rpId: "console.example.test", userVerification: "required", allowCredentials: [] } } };
        if (input.url === "/api/auth/webauthn/verify") return { status: 200, headers: {}, body: { authorization_id: authorizationId } };
        throw new Error("unexpected route");
      }
    }
  });
  try {
    await new Promise((resolve, reject) => {
      cloud.once("error", reject);
      cloud.listen(0, "127.0.0.1", resolve);
    });
  } catch (error) {
    if (error?.code === "EPERM") {
      t.skip("loopback listen is unavailable in this sandbox; external browser-shaped E2E is not_proven");
      return;
    }
    throw error;
  }
  t.after(() => new Promise((resolve) => cloud.close(resolve)));
  const address = cloud.address();
  const serviceToken = "server-only-cloud-token";
  const bridge = createHumanAuthBridge({
    env: { NODE_ENV: "test", AGENTPASS_ALLOW_LEGACY_SESSION_BOOTSTRAP: "true", AGENTPASS_CLOUD_API_URL: `http://127.0.0.1:${address.port}`, AGENTPASS_CLOUD_TOKEN: serviceToken, AGENTPASS_OPERATOR_USER_IDS: "operator-1", AGENTPASS_ALLOW_INSECURE_LOOPBACK_CLOUD_API: "true" },
    getSiwcUser: async () => ({ userId: "operator-1" }),
  });
  const browser = (path, body, headers = {}) => new Request(`https://console.example.test${path}`, { method: "POST", headers: { origin: "https://console.example.test", "content-type": "application/json", ...headers }, body: JSON.stringify(body) });

  const session = await bridge.handle(browser("/api/auth/session", {}));
  assert.equal(session.status, 201);
  assert.equal(session.headers.get("set-cookie"), cookie);
  assert.equal((await session.clone().text()).includes(serviceToken), false);

  const browserCookie = cookie.split(";", 1)[0];
  const options = await bridge.handle(browser("/api/auth/webauthn/options", { organization_id: organizationId, operation: "device.enrollment.issue" }, { cookie: browserCookie, "agentpass-csrf": csrf }));
  assert.equal(options.status, 200);
  assert.equal((await options.json()).challenge_id, challengeId);
  const verify = await bridge.handle(browser("/api/auth/webauthn/verify", { organization_id: organizationId, operation: "device.enrollment.issue", challenge_id: challengeId, credential: {} }, { cookie: browserCookie, "agentpass-csrf": csrf }));
  assert.equal(verify.status, 200);
  assert.equal((await verify.json()).authorization_id, authorizationId);

  assert.deepEqual(cloudCalls.map((call) => call.url), ["/api/auth/session", "/api/auth/webauthn/options", "/api/auth/webauthn/verify"]);
  assert.equal(cloudCalls[0].headers.authorization, `Bearer ${serviceToken}`);
  assert.equal(cloudCalls[1].headers.cookie, browserCookie);
  assert.equal(cloudCalls[1].headers["agentpass-csrf"], csrf);
  assert.equal(cloudCalls[2].headers["agentpass-csrf"], csrf);
});
