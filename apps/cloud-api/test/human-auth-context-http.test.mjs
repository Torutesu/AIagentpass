import assert from "node:assert/strict";
import test from "node:test";

import { createHumanAuthHttpApi, HUMAN_AUTH_HTTP_PATHS } from "../src/human-auth/http-api.mjs";

const ORIGIN = "https://console.agentpass.test";
const ORG = "33333333-3333-4333-8333-333333333333";
const SESSION = "11111111-1111-4111-8111-111111111111";
const MEMBER = "22222222-2222-4222-8222-222222222222";
const CHALLENGE_ID = "44444444-4444-4444-8444-444444444444";
const CONTEXT_HASH = "a".repeat(64);

test("WebAuthn options pass only a canonical resource context hash to recent auth", async () => {
  const calls = [];
  const api = createHumanAuthHttpApi({
    humanSession: { expectedOrigin: ORIGIN, async authenticateRequest() { return { session: session() }; } },
    recentAuthService: {
      begin(input) { calls.push(input); return { challenge_id: CHALLENGE_ID, challenge: "A".repeat(43), challenge_expires_at: "2026-08-14T00:02:00.000Z" }; },
      async verify() { throw new Error("not used"); }
    },
    credentialAllowList: { async listCredentials() { return [{ id: "Y3JlZGVudGlhbA" }]; } },
    abuseControls: { async authorize() { return { allowed: true }; } },
    rpId: "console.agentpass.test",
    origin: ORIGIN,
    basePath: "/api/auth",
    allowedOperations: ["human.recovery.outbox.redrive"],
    now: () => Date.parse("2026-08-14T00:00:00.000Z")
  });
  const response = await api.handle(request(HUMAN_AUTH_HTTP_PATHS.authenticationOptions, { organization_id: ORG, operation: "human.recovery.outbox.redrive", context_hash: CONTEXT_HASH }));
  assert.equal(response.status, 200);
  assert.equal(calls[0].context_hash, CONTEXT_HASH);
  assert.equal(JSON.stringify(response.body).includes(CONTEXT_HASH), false);
  assert.equal((await api.handle(request(HUMAN_AUTH_HTTP_PATHS.authenticationOptions, { organization_id: ORG, operation: "human.recovery.outbox.redrive", context_hash: "A".repeat(64) }))).status, 400);
});

function session() { return { session_id: SESSION, member_id: MEMBER, organization_id: ORG, role: "owner" }; }
function request(path, body) {
  return { method: "POST", url: `/api/auth${path}`, headers: { origin: ORIGIN, cookie: `__Host-agentpass_session=${"s".repeat(43)}`, "agentpass-csrf": "c".repeat(43), "content-type": "application/json" }, body: JSON.stringify(body) };
}
