import assert from "node:assert/strict";
import test from "node:test";
import { createHumanAuthRouter } from "../src/human-auth/router.mjs";

function fixture() {
  const calls = [];
  const result = { status: 200, headers: {}, body: { ok: true } };
  const router = createHumanAuthRouter({
    sessionApi: { async handle(input) { calls.push(["session", input]); return result; } },
    webauthnApi: { async handle(input) { calls.push(["webauthn", input]); return result; } },
    registrationApi: { async handle(input) { calls.push(["registration", input]); return result; } },
    managementApi: { async handle(input) { calls.push(["management", input]); return result; } },
  });
  return { router, calls };
}

test("routes exact public auth paths and translates only the session path", async () => {
  const { router, calls } = fixture();
  const base = { method: "POST", headers: { origin: "https://console.test" }, body: Buffer.from("{}") };
  await router.handle({ ...base, url: "/api/auth/session" });
  await router.handle({ ...base, url: "/api/auth/webauthn/options" });
  await router.handle({ ...base, url: "/api/auth/webauthn/verify" });
  await router.handle({ ...base, url: "/api/auth/webauthn/registration/options" });
  await router.handle({ ...base, url: "/api/auth/webauthn/registration/verify" });
  await router.handle({ ...base, method: "GET", url: "/api/auth/management/credentials?limit=25" });
  assert.deepEqual(calls.map(([kind, input]) => [kind, input.url]), [["session", "/session"], ["webauthn", "/api/auth/webauthn/options"], ["webauthn", "/api/auth/webauthn/verify"], ["registration", "/api/auth/webauthn/registration/options"], ["registration", "/api/auth/webauthn/registration/verify"], ["management", "/api/auth/management/credentials?limit=25"]]);
  assert.equal(calls.every(([, input]) => input.headers === base.headers && input.body === base.body), true);
});

test("rejects aliases, queries, and malformed input without delegation", async () => {
  const { router, calls } = fixture();
  for (const url of ["/api/auth/session/", "/api/auth/session?x=1", "/api/auth/webauthn/options/", "/api/auth/webauthn/verify#x", "/other"]) {
    const result = await router.handle({ method: "POST", url, headers: {}, body: "{}" });
    assert.equal(result.status, 404);
    assert.match(result.headers["Cache-Control"], /no-store/);
  }
  assert.equal(calls.length, 0);
});
