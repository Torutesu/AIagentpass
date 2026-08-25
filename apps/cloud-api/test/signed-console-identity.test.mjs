import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";
import {
  consoleIdentityJtiDigest,
  createSignedConsoleIdentityAdapter,
  SIGNED_CONSOLE_IDENTITY_ERROR_CODES,
  SIGNED_CONSOLE_IDENTITY_HEADER,
  SignedConsoleIdentityError
} from "../src/human-auth/identity/signed-console.mjs";

const NOW = 1_800_000_000_000;
const NOW_SECONDS = Math.floor(NOW / 1_000);
const REPLAY_SECRET = Buffer.alloc(32, 0x61);
const ids = { org: "11111111-1111-4111-8111-111111111111", member: "22222222-2222-4222-8222-222222222222" };
const config = {
  issuer: "https://console.example.test",
  audience: "agentpass-cloud-session",
  provider: "chatgpt",
  origin: "https://console.example.test",
  keyId: "console-2026-08",
  now: () => NOW
};

function canonicalJson(value) {
  if (value === null || typeof value === "string" || typeof value === "boolean" || typeof value === "number") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
}

function b64(value) { return Buffer.from(typeof value === "string" ? value : canonicalJson(value), "utf8").toString("base64url"); }

function makeAssertion(privateKey, overrides = {}) {
  const header = { alg: "EdDSA", kid: config.keyId, typ: "agentpass.console.identity", version: 1 };
  const payload = {
    aud: config.audience,
    exp: NOW_SECONDS + 30,
    iat: NOW_SECONDS,
    iss: config.issuer,
    jti: "jti-" + crypto.randomBytes(18).toString("base64url"),
    nbf: NOW_SECONDS,
    org: ids.org,
    origin: config.origin,
    provider: config.provider,
    sub: "siwc-subject-42",
    ...overrides
  };
  const encodedHeader = b64(header);
  const encodedPayload = b64(payload);
  const signingInput = `${encodedHeader}.${encodedPayload}`;
  const signature = crypto.sign(null, Buffer.from(signingInput, "ascii"), privateKey).toString("base64url");
  return { compact: `${signingInput}.${signature}`, header, payload };
}

function adapterFixture(overrides = {}) {
  const pair = crypto.generateKeyPairSync("ed25519");
  const events = [];
  const opaque = Object.freeze({ version: 1, issued_at: NOW, expires_at: NOW + 30_000 });
  const identityResolver = {
    identityAdapter: { async verify() { return { provider: config.provider, subject: "siwc-subject-42", member_id: ids.member, membership_id: "33333333-3333-4333-8333-333333333333", organization_id: ids.org, role: "owner", assertion_expires_at: NOW + 30_000 }; } },
    async resolveIdentity(input) { events.push(["resolve", input]); return opaque; }
  };
  const adapter = createSignedConsoleIdentityAdapter({ ...config, publicKey: pair.publicKey, identityResolver, replaySecret: REPLAY_SECRET, ...overrides });
  return { adapter, pair, events, opaque };
}

function request(assertion, extra = {}) {
  return { headers: { [SIGNED_CONSOLE_IDENTITY_HEADER]: assertion, ...extra } };
}

test("verifies the pinned compact Ed25519 assertion and carries only a keyed replay digest", async () => {
  const fixture = adapterFixture();
  const { compact, header, payload } = makeAssertion(fixture.pair.privateKey);
  assert.deepEqual(Object.keys(header).sort(), ["alg", "kid", "typ", "version"]);
  assert.deepEqual(Object.keys(payload).sort(), ["aud", "exp", "iat", "iss", "jti", "nbf", "org", "origin", "provider", "sub"]);
  assert.equal(Object.hasOwn(payload, "redirect_uri"), false);
  assert.equal(await fixture.adapter.verifyIdentityRequest(request(compact)), fixture.opaque);
  assert.equal(fixture.events[0][0], "resolve");
  assert.deepEqual(fixture.events[0][1], { provider: config.provider, subject: payload.sub, organization_id: ids.org });
  const verified = await fixture.adapter.identityAdapter.verify(fixture.opaque, { now: NOW });
  assert.equal(verified.identity_replay.jti_digest, consoleIdentityJtiDigest({ iss: payload.iss, aud: payload.aud, jti: payload.jti }, REPLAY_SECRET));
  assert.equal(Object.hasOwn(verified.identity_replay, "jti"), false);
  await assert.rejects(() => fixture.adapter.identityAdapter.verify(fixture.opaque, { now: NOW }), SignedConsoleIdentityError);
});

test("rejects conflicting caller identity headers and never returns signed assertion material", async () => {
  const fixture = adapterFixture();
  const { compact } = makeAssertion(fixture.pair.privateKey, { sub: "verified-subject" });
  const result = await fixture.adapter.verifyIdentityRequest(request(compact));
  assert.equal(result, fixture.opaque);
  assert.equal(fixture.events[0][1].subject, "verified-subject");
  assert.equal(JSON.stringify(result).includes(compact), false);
  for (const headers of [
    { authorization: "Bearer attacker-token" },
    { "agentpass-console-user-id": "attacker-controlled-subject" },
    { "agentpass-member-id": ids.member },
    { "agentpass-role": "owner" }
  ]) {
    await assert.rejects(() => fixture.adapter.verifyIdentityRequest(request(compact, headers)), SignedConsoleIdentityError);
  }
  assert.equal(fixture.events.length, 1);
});

test("rejects a resolver principal projected into a different tenant", async () => {
  const fixture = adapterFixture();
  const { compact } = makeAssertion(fixture.pair.privateKey);
  const crossTenant = "44444444-4444-4444-8444-444444444444";
  const adapter = createSignedConsoleIdentityAdapter({
    ...config,
    replaySecret: REPLAY_SECRET,
    publicKey: fixture.pair.publicKey,
    identityResolver: {
      async resolveIdentity() { return fixture.opaque; },
      identityAdapter: {
        async verify() {
          return {
            provider: config.provider,
            subject: "siwc-subject-42",
            member_id: ids.member,
            membership_id: "33333333-3333-4333-8333-333333333333",
            organization_id: crossTenant,
            role: "owner",
            assertion_expires_at: NOW + 30_000
          };
        }
      }
    }
  });
  await adapter.verifyIdentityRequest(request(compact));
  await assert.rejects(() => adapter.identityAdapter.verify(fixture.opaque, { now: NOW }), (error) => {
    assert.equal(error.code, SIGNED_CONSOLE_IDENTITY_ERROR_CODES.INVALID_ASSERTION);
    assert.equal(error.status, 401);
    return true;
  });
});

test("keys replay digests so raw assertion identifiers are not stable database identifiers", () => {
  const claims = { iss: config.issuer, aud: config.audience, jti: "jti-replay-digest-abcdefgh" };
  const first = consoleIdentityJtiDigest(claims, REPLAY_SECRET);
  const second = consoleIdentityJtiDigest(claims, Buffer.alloc(32, 0x62));
  assert.match(first, /^[0-9a-f]{64}$/u);
  assert.notEqual(first, second);
  assert.equal(first.includes(claims.jti), false);
});

test("fails closed on resolver outage without leaking details", async () => {
  const resolverOutage = adapterFixture();
  resolverOutage.adapter = createSignedConsoleIdentityAdapter({ ...config, replaySecret: REPLAY_SECRET, publicKey: resolverOutage.pair.publicKey, identityResolver: { async resolveIdentity() { throw new Error("provider-subject-secret"); }, identityAdapter: { async verify() {} } } });
  await assert.rejects(() => resolverOutage.adapter.verifyIdentityRequest(request(makeAssertion(resolverOutage.pair.privateKey).compact)), (error) => {
    assert.equal(error.code, SIGNED_CONSOLE_IDENTITY_ERROR_CODES.UNAVAILABLE);
    assert.equal(error.status, 503);
    assert.equal(error.message.includes("provider-subject-secret"), false);
    return true;
  });

  const resolverDenial = adapterFixture();
  resolverDenial.adapter = createSignedConsoleIdentityAdapter({ ...config, replaySecret: REPLAY_SECRET, publicKey: resolverDenial.pair.publicKey, identityResolver: { async resolveIdentity() { throw Object.assign(new Error("inactive-membership"), { status: 401 }); }, identityAdapter: { async verify() {} } } });
  await assert.rejects(() => resolverDenial.adapter.verifyIdentityRequest(request(makeAssertion(resolverDenial.pair.privateKey).compact)), (error) => {
    assert.equal(error.code, SIGNED_CONSOLE_IDENTITY_ERROR_CODES.INVALID_ASSERTION);
    assert.equal(error.status, 401);
    assert.equal(error.message.includes("inactive-membership"), false);
    return true;
  });
});

test("fails closed when the identity resolver returns a structural or mutable assertion", async () => {
  const fixture = adapterFixture();
  const signed = makeAssertion(fixture.pair.privateKey).compact;
  for (const output of [null, { version: 1 }, { version: 1, issued_at: NOW, expires_at: NOW + 30_000 }, Object.freeze({ version: 1, issued_at: NOW, expires_at: NOW })]) {
    const adapter = createSignedConsoleIdentityAdapter({
      ...config,
      replaySecret: REPLAY_SECRET,
      publicKey: fixture.pair.publicKey,
      identityResolver: { async resolveIdentity() { return output; }, identityAdapter: { async verify() {} } }
    });
    await assert.rejects(() => adapter.verifyIdentityRequest(request(signed)), (error) => {
      assert.equal(error.code, SIGNED_CONSOLE_IDENTITY_ERROR_CODES.UNAVAILABLE);
      assert.equal(error.message, "Signed console identity could not be verified");
      return true;
    });
  }
});

test("rejects altered, non-canonical, wrong-key, and wrong-binding assertions", async () => {
  const fixture = adapterFixture();
  const valid = makeAssertion(fixture.pair.privateKey);
  const cases = [
    valid.compact.replace(/.$/u, valid.compact.endsWith("A") ? "B" : "A"),
    `${valid.compact.split(".")[0]}.${b64(" { } ")}.${valid.compact.split(".")[2]}`,
    makeAssertion(crypto.generateKeyPairSync("ed25519").privateKey).compact,
    makeAssertion(fixture.pair.privateKey, { aud: "other-audience" }).compact,
    makeAssertion(fixture.pair.privateKey, { origin: "https://evil.example.test" }).compact,
    makeAssertion(fixture.pair.privateKey, { redirect_uri: "https://evil.example.test/callback" }).compact,
    makeAssertion(fixture.pair.privateKey, { jti: "too-short" }).compact,
    makeAssertion(fixture.pair.privateKey, { org: "not-a-uuid" }).compact,
    makeAssertion(fixture.pair.privateKey, { provider: "github" }).compact
  ];
  for (const compact of cases) {
    await assert.rejects(() => fixture.adapter.verifyIdentityRequest(request(compact)), (error) => {
      assert.equal(error instanceof SignedConsoleIdentityError, true);
      assert.equal(error.message, "Signed console identity could not be verified");
      return true;
    });
  }
  assert.equal(fixture.events.length, 0);
});

test("enforces nbf/iat/exp relationships, sixty-second TTL, and configured clock skew", async () => {
  const fixture = adapterFixture();
  const invalid = [
    { exp: NOW_SECONDS + 61 },
    { nbf: NOW_SECONDS + 6 },
    { iat: NOW_SECONDS - 66, nbf: NOW_SECONDS - 66, exp: NOW_SECONDS - 6 },
    { iat: NOW_SECONDS + 6, nbf: NOW_SECONDS + 6 },
    { nbf: NOW_SECONDS + 1, iat: NOW_SECONDS }
  ];
  for (const claims of invalid) {
    await assert.rejects(() => fixture.adapter.verifyIdentityRequest(request(makeAssertion(fixture.pair.privateKey, claims).compact)), SignedConsoleIdentityError);
  }
  const withinSkew = makeAssertion(fixture.pair.privateKey, { iat: NOW_SECONDS + 5, nbf: NOW_SECONDS + 5, exp: NOW_SECONDS + 35 }).compact;
  assert.equal(await fixture.adapter.verifyIdentityRequest(request(withinSkew)), fixture.opaque);
});

test("requires an Ed25519 pinned key and complete production configuration", () => {
  const pair = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  const resolver = { async resolveIdentity() {}, identityAdapter: { async verify() {} } };
  assert.throws(() => createSignedConsoleIdentityAdapter({ ...config, replaySecret: REPLAY_SECRET, publicKey: pair.publicKey, identityResolver: {} }), /identityResolver/);
  assert.throws(() => createSignedConsoleIdentityAdapter({ ...config, replaySecret: REPLAY_SECRET, publicKey: pair.publicKey, identityResolver: resolver }), /Ed25519/);
  assert.throws(() => createSignedConsoleIdentityAdapter({ ...config, replaySecret: REPLAY_SECRET, origin: undefined, publicKey: crypto.generateKeyPairSync("ed25519").publicKey, identityResolver: resolver }), /configuration/);
  assert.throws(() => createSignedConsoleIdentityAdapter({ ...config, publicKey: crypto.generateKeyPairSync("ed25519").publicKey, identityResolver: resolver }), /replay secret/);
});
