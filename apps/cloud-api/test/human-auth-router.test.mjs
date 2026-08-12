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
    organizationApi: { async handle(input) { calls.push(["organization", input]); return result; } },
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
  await router.handle({ ...base, method: "GET", url: "/api/auth/organizations?limit=25&cursor=next" });
  await router.handle({ ...base, method: "GET", url: "/api/auth/organizations/11111111-1111-4111-8111-111111111111/members?limit=10" });
  await router.handle({ ...base, method: "POST", url: "/api/auth/organizations/11111111-1111-4111-8111-111111111111/invitations" });
  await router.handle({ ...base, method: "POST", url: "/api/auth/invitations/accept" });
  assert.deepEqual(calls.map(([kind, input]) => [kind, input.url]), [["session", "/session"], ["webauthn", "/api/auth/webauthn/options"], ["webauthn", "/api/auth/webauthn/verify"], ["registration", "/api/auth/webauthn/registration/options"], ["registration", "/api/auth/webauthn/registration/verify"], ["management", "/api/auth/management/credentials?limit=25"], ["organization", "/api/auth/organizations?limit=25&cursor=next"], ["organization", "/api/auth/organizations/11111111-1111-4111-8111-111111111111/members?limit=10"], ["organization", "/api/auth/organizations/11111111-1111-4111-8111-111111111111/invitations"], ["organization", "/api/auth/invitations/accept"]]);
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

test("forwards organization queries only for list routes and rejects malformed paths", async () => {
  const { router, calls } = fixture();
  const organization = "/api/auth/organizations/11111111-1111-4111-8111-111111111111";
  const rejected = [
    `${organization}?limit=1`,
    `${organization}/members/22222222-2222-4222-8222-222222222222/role?unexpected=1`,
    `${organization}/invitations/33333333-3333-4333-8333-333333333333/revoke/`,
    `${organization}/members/22222222-2222-4222-8222-222222222222/revoke`,
    `${organization}/invitations/33333333-3333-4333-8333-333333333333/role`,
    "/api/auth/organizations/",
    "/api/auth/invitations/accept?unexpected=1",
    "/api/auth/invitations/accept#fragment"
  ];
  for (const url of rejected) {
    const result = await router.handle({ method: "POST", url, headers: {}, body: "{}" });
    assert.equal(result.status, 404, url);
  }
  await router.handle({ method: "GET", url: `${organization}/invitations?limit=10`, headers: {}, body: undefined });
  assert.deepEqual(calls.map(([kind, input]) => [kind, input.url]), [["organization", `${organization}/invitations?limit=10`]]);
});
