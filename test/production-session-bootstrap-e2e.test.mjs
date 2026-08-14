import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import { createCloudApi } from "../apps/cloud-api/src/server.mjs";
import { createHumanAuthRuntime } from "../apps/cloud-api/src/human-auth/runtime.mjs";
import { createHumanAuthBridge } from "../apps/web-console/lib/human-auth-api.mjs";
import { createIdentityAssertionSigner, IDENTITY_ASSERTION_HEADER } from "../apps/web-console/lib/identity-assertion.mjs";

const ORIGIN = "https://console.example.test";
const ISSUER = "agentpass-console";
const AUDIENCE = "agentpass-cloud";
const KEY_ID = "console-2026-08";
const PROVIDER = "chatgpt";
const NOW = Date.parse("2026-08-12T12:00:00.000Z");
const NOW_SECONDS = Math.floor(NOW / 1_000);
const MAIN_ORGANIZATION = "11111111-1111-4111-8111-111111111111";
const OTHER_ORGANIZATION = "44444444-4444-4444-8444-444444444444";
const MEMBER_ID = "22222222-2222-4222-8222-222222222222";
const MAIN_MEMBERSHIP = "33333333-3333-4333-8333-333333333333";
const TRUSTED_SUBJECT = "siwc-subject-1";
const INACTIVE_SUBJECT = "siwc-inactive-1";
const CURSOR_SECRET = Buffer.alloc(32, 0x42).toString("base64url");

const keyPair = crypto.generateKeyPairSync("ed25519");
const privateKeyPem = keyPair.privateKey.export({ type: "pkcs8", format: "pem" });
const assertionConfig = Object.freeze({
  privateKeyPem,
  issuer: ISSUER,
  audience: AUDIENCE,
  keyId: KEY_ID,
  provider: PROVIDER,
});

test("production Console BFF to Cloud Human Auth boundary rejects adversarial bootstrap inputs", async (t) => {
  const state = createMemoryPostgresState();
  const humanAuth = createHumanAuthRuntime({
    postgresRuntime: state.postgresRuntime,
    origin: ORIGIN,
    rpId: "console.example.test",
    cursorSecret: CURSOR_SECRET,
    identityProvider: PROVIDER,
    signedConsoleIdentity: {
      issuer: ISSUER,
      audience: AUDIENCE,
      keyId: KEY_ID,
      publicKey: keyPair.publicKey,
    },
    now: () => NOW,
  });
  const alwaysAllowed = {
    acquire() {
      return { allowed: true, limit: 100, remaining: 99, retryAfterSeconds: 0, resetAt: NOW + 60_000 };
    },
  };
  const cloud = createCloudApi({
    store: {},
    humanAuthApi: humanAuth.api,
    humanSession: humanAuth.humanSession,
    rateLimiter: alwaysAllowed,
    admissionRateLimiter: alwaysAllowed,
  });
  await listen(cloud);
  t.after(() => close(cloud));
  const address = cloud.address();
  const cloudUrl = `http://127.0.0.1:${address.port}`;
  const signer = createIdentityAssertionSigner(assertionConfig);
  const productionEnv = Object.freeze({
    NODE_ENV: "production",
    AGENTPASS_CLOUD_API_URL: cloudUrl,
    AGENTPASS_ALLOW_INSECURE_LOOPBACK_CLOUD_API: "true",
    AGENTPASS_CONSOLE_ORIGIN: ORIGIN,
    AGENTPASS_ORGANIZATION_ID: MAIN_ORGANIZATION,
    AGENTPASS_IDENTITY_ASSERTION_PRIVATE_KEY: privateKeyPem,
    AGENTPASS_IDENTITY_ASSERTION_ISSUER: ISSUER,
    AGENTPASS_IDENTITY_ASSERTION_AUDIENCE: AUDIENCE,
    AGENTPASS_IDENTITY_ASSERTION_KID: KEY_ID,
    AGENTPASS_IDENTITY_PROVIDER: PROVIDER,
  });

  // Seed a real Cloud session so the independent CSRF/origin cases still run
  // when the strict BFF success assertion exposes a current wiring defect.
  const seeded = await cloudSession(cloudUrl, createCompactAssertion({
    subject: TRUSTED_SUBJECT,
    organizationId: MAIN_ORGANIZATION,
    jti: "seed-session-jti-0000001",
    iat: NOW_SECONDS,
    exp: NOW_SECONDS + 60,
  }));
  assert.equal(seeded.response.status, 201, JSON.stringify(seeded.body));
  const seededCookie = seeded.response.headers.get("set-cookie").split(";", 1)[0];
  const seededCsrf = seeded.body.csrf_token;

  await t.test("normal production bootstrap uses the signed assertion and rotates a fixation cookie", async () => {
    const calls = [];
    const attackerCookie = `__Host-agentpass_session=${"A".repeat(43)}`;
    const bridge = createBridge({ env: productionEnv, signer, calls });
    const response = await bridge.handle(browserRequest("/api/auth/session", {
      headers: {
        cookie: attackerCookie,
        "agentpass-console-user-id": "attacker-controlled-subject",
        "agentpass-member-id": MEMBER_ID,
        "agentpass-role": "owner",
      },
    }));
    const body = await json(response);

    assert.equal(response.status, 201, JSON.stringify({ body, calls, identityQueries: state.identityQueries, replayAttempts: state.replayAttempts }));
    assert.equal(body.session.organization_id, MAIN_ORGANIZATION);
    assert.equal(body.session.member_id, MEMBER_ID);
    assert.match(body.csrf_token, /^[A-Za-z0-9_-]{43}$/u);
    const setCookie = response.headers.get("set-cookie");
    assert.match(setCookie, /^__Host-agentpass_session=[A-Za-z0-9_-]{43}; Path=\//u);
    assert.notEqual(setCookie.split(";", 1)[0], attackerCookie);
    assert.equal(calls.length, 1);
    assert.equal(calls[0].headers["authorization"], undefined);
    assert.equal(calls[0].headers["agentpass-console-user-id"], undefined);
    assert.equal(calls[0].headers["agentpass-member-id"], undefined);
    assert.equal(calls[0].headers["agentpass-role"], undefined);
    assert.equal(calls[0].headers.cookie, undefined, "bootstrap must not forward a browser session cookie");
    assert.equal(calls[0].body, "{}", "Cloud bootstrap body must be the exact empty JSON object");
    assert.equal(typeof calls[0].headers[IDENTITY_ASSERTION_HEADER], "string");
    assert.doesNotMatch(JSON.stringify(body), /siwc-subject|agentpass-console-identity|server-only/u);
    assert.deepEqual(state.identityQueries.at(-1), {
      provider: PROVIDER,
      subject: TRUSTED_SUBJECT,
      organization_id: MAIN_ORGANIZATION,
    });

  });

  await t.test("browser identity headers cannot replace the platform-verified subject", async () => {
    const calls = [];
    const bridge = createBridge({
      env: productionEnv,
      signer,
      calls,
      user: { userId: TRUSTED_SUBJECT },
    });
    const response = await bridge.handle(browserRequest("/api/auth/session", {
      headers: {
        "agentpass-console-user-id": "attacker-subject",
        "agentpass-member-id": "attacker-member",
        "agentpass-role": "owner",
      },
    }));
    const body = await json(response);
    assert.equal(response.status, 201, JSON.stringify({ body, calls, identityQueries: state.identityQueries }));
    assert.equal(calls[0].headers["agentpass-console-user-id"], undefined);
    assert.equal(state.identityQueries.at(-1).subject, TRUSTED_SUBJECT);
    assert.equal(state.identityQueries.at(-1).organization_id, MAIN_ORGANIZATION);
  });

  await t.test("BFF enforces Origin and CSRF before forwarding protected requests", async () => {
    const calls = [];
    const before = calls.length;
    const bridge = createBridge({ env: productionEnv, signer, calls });
    const payload = { organization_id: MAIN_ORGANIZATION, operation: "device.enrollment.issue" };
    const missingCsrf = await bridge.handle(browserRequest("/api/auth/webauthn/options", {
      body: payload,
      headers: { cookie: seededCookie },
    }));
    assert.equal(missingCsrf.status, 403);
    const invalidCsrf = await bridge.handle(browserRequest("/api/auth/webauthn/options", {
      body: payload,
      headers: { cookie: seededCookie, "agentpass-csrf": "invalid" },
    }));
    assert.equal(invalidCsrf.status, 403);
    const wrongOrigin = await bridge.handle(browserRequest("/api/auth/session", {
      origin: "https://evil.example.test",
    }));
    assert.equal(wrongOrigin.status, 403);
    assert.equal(calls.length, before, "BFF rejected origin/CSRF requests before Cloud");
  });

  await t.test("Cloud enforces CSRF and Origin at the Human Auth boundary", async () => {
    const payload = { organization_id: MAIN_ORGANIZATION, operation: "device.enrollment.issue" };
    const missingCsrf = await cloudRequest(cloudUrl, "/api/auth/webauthn/options", {
      headers: { origin: ORIGIN, cookie: seededCookie },
      body: payload,
    });
    assert.equal(missingCsrf.response.status, 403);
    assert.match(missingCsrf.body.error.code, /csrf/u);

    const wrongOrigin = await cloudRequest(cloudUrl, "/api/auth/webauthn/options", {
      headers: { origin: "https://evil.example.test", cookie: seededCookie, "agentpass-csrf": seededCsrf },
      body: payload,
    });
    assert.equal(wrongOrigin.response.status, 403);
    assert.match(wrongOrigin.body.error.code, /origin/u);
  });

  await t.test("the BFF rejects malformed envelopes and Cloud rejects a tampered signature", async () => {
    const malformedCalls = [];
    const malformedResponse = await createBridge({
      env: productionEnv,
      calls: malformedCalls,
      signer: { sign: async () => "not-a-compact-assertion" },
    }).handle(browserRequest("/api/auth/session"));
    assert.ok(malformedResponse.status >= 400);
    assert.equal(malformedCalls.length, 0, "the BFF must reject malformed assertion syntax before forwarding");

    const calls = [];
    const valid = await signer.sign({ subject: TRUSTED_SUBJECT, organizationId: MAIN_ORGANIZATION, origin: ORIGIN, now: NOW, jti: "tampered-assertion-jti-0001" });
    const compactParts = valid.split(".");
    const signatureBytes = Buffer.from(compactParts[2], "base64url");
    signatureBytes[0] ^= 1;
    const tampered = `${compactParts[0]}.${compactParts[1]}.${signatureBytes.toString("base64url")}`;
    const response = await createBridge({
      env: productionEnv,
      calls,
      signer: { sign: async () => tampered },
    }).handle(browserRequest("/api/auth/session"));
    const body = await json(response);
    assert.ok(response.status >= 400, JSON.stringify({ body, calls }));
    assert.equal(calls.length, 1, "only Cloud has the public key needed to reject a structurally valid tampered signature");
    assert.equal(response.status, 401);
    const direct = await cloudSession(cloudUrl, tampered);
    assert.equal(direct.response.status, 401);
    assert.equal(direct.body.error.code, "human_session_identity_verification_failed");
  });

  await t.test("an expired assertion is rejected by Cloud even when the transport bypasses the BFF", async () => {
    const expired = createCompactAssertion({
      subject: TRUSTED_SUBJECT,
      organizationId: MAIN_ORGANIZATION,
      jti: "expired-assertion-jti-0001",
      iat: NOW_SECONDS - 120,
      exp: NOW_SECONDS - 60,
    });
    const result = await cloudSession(cloudUrl, expired);
    assert.equal(result.response.status, 401);
    assert.equal(result.body.error.code, "human_session_identity_verification_failed");
  });

  await t.test("the same JTI can issue at most one session", async () => {
    const fixed = createCompactAssertion({
      subject: TRUSTED_SUBJECT,
      organizationId: MAIN_ORGANIZATION,
      jti: "replayed-assertion-jti-0001",
      iat: NOW_SECONDS,
      exp: NOW_SECONDS + 60,
    });
    const first = await cloudSession(cloudUrl, fixed);
    const second = await cloudSession(cloudUrl, fixed);
    assert.equal(first.response.status, 201, JSON.stringify(first.body));
    assert.equal(second.response.status, 409, JSON.stringify(second.body));
    assert.equal(second.body.error.code, "human_session_identity_replay");
    assert.equal(state.replayAttempts.filter((digest) => digest === state.replayAttempts.at(-1)).length >= 1, true);
  });

  await t.test("an inactive membership cannot bootstrap a session", async () => {
    const inactive = createCompactAssertion({
      subject: INACTIVE_SUBJECT,
      organizationId: MAIN_ORGANIZATION,
      jti: "inactive-membership-jti-0001",
      iat: NOW_SECONDS,
      exp: NOW_SECONDS + 60,
    });
    const before = state.sessions.size;
    const result = await cloudSession(cloudUrl, inactive);
    assert.equal(result.response.status, 401, JSON.stringify(result.body));
    assert.equal(result.body.error.code, "human_session_identity_verification_failed");
    assert.equal(state.sessions.size, before, "an inactive membership must not create a session");
  });

  await t.test("organization replacement is rejected even with a correctly signed assertion", async () => {
    const replaced = createCompactAssertion({
      subject: TRUSTED_SUBJECT,
      organizationId: OTHER_ORGANIZATION,
      jti: "organization-replacement-jti-0001",
      iat: NOW_SECONDS,
      exp: NOW_SECONDS + 60,
    });
    const result = await cloudSession(cloudUrl, replaced);
    // The resolver must prove an active membership in the signed organization;
    // a valid Console signature alone is not an organization authorization.
    assert.equal(result.response.status, 401, JSON.stringify(result.body));
    assert.equal(result.body.error.code, "human_session_identity_verification_failed");
  });
});

function createBridge({ env, signer, calls = [], user = { userId: TRUSTED_SUBJECT } }) {
  const fetchImpl = async (url, init) => {
    calls.push({
      url: String(url),
      method: init.method,
      headers: Object.fromEntries(new Headers(init.headers).entries()),
      body: typeof init.body === "string" ? init.body : new TextDecoder().decode(init.body ?? new Uint8Array()),
    });
    return fetch(url, init);
  };
  return createHumanAuthBridge({
    env,
    fetchImpl,
    getSiwcUser: async () => user,
    signIdentityAssertion: signer,
    now: () => NOW,
  });
}

function browserRequest(path, { body = {}, headers = {}, method = "POST", origin = ORIGIN } = {}) {
  const requestHeaders = { origin, ...headers };
  if (method !== "GET" && method !== "HEAD") requestHeaders["content-type"] ??= "application/json";
  const init = { method, headers: requestHeaders };
  if (method !== "GET" && method !== "HEAD") init.body = typeof body === "string" ? body : JSON.stringify(body);
  return new Request(`${ORIGIN}${path}`, init);
}

async function cloudSession(cloudUrl, assertion, headers = {}) {
  const response = await fetch(`${cloudUrl}/api/auth/session`, {
    method: "POST",
    headers: {
      origin: ORIGIN,
      "content-type": "application/json",
      [IDENTITY_ASSERTION_HEADER]: assertion,
      ...headers,
    },
    body: "{}",
  });
  return { response, body: await json(response) };
}

async function cloudRequest(cloudUrl, path, { headers = {}, body = undefined, method = "POST" } = {}) {
  const response = await fetch(`${cloudUrl}${path}`, {
    method,
    headers: {
      "content-type": "application/json",
      ...headers,
    },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  return { response, body: await json(response) };
}

async function json(response) {
  return JSON.parse(await response.text());
}

function createCompactAssertion({ subject, organizationId, jti, iat, exp }) {
  const header = { alg: "EdDSA", kid: KEY_ID, typ: "agentpass.console.identity", version: 1 };
  const payload = {
    aud: AUDIENCE,
    exp,
    iat,
    iss: ISSUER,
    jti,
    nbf: iat,
    org: organizationId,
    origin: ORIGIN,
    provider: PROVIDER,
    sub: subject,
  };
  const encodedHeader = Buffer.from(canonicalJson(header), "utf8").toString("base64url");
  const encodedPayload = Buffer.from(canonicalJson(payload), "utf8").toString("base64url");
  const signingInput = `${encodedHeader}.${encodedPayload}`;
  const signature = crypto.sign(null, Buffer.from(signingInput, "ascii"), keyPair.privateKey).toString("base64url");
  return `${signingInput}.${signature}`;
}

function canonicalJson(value) {
  if (value === null || typeof value === "string" || typeof value === "boolean" || typeof value === "number") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
}

function createMemoryPostgresState() {
  const sessions = new Map();
  const consumedJtis = new Set();
  const replayAttempts = [];
  const identityQueries = [];
  const identities = [
    { provider: PROVIDER, subject: TRUSTED_SUBJECT, member_id: MEMBER_ID, membership_id: MAIN_MEMBERSHIP, organization_id: MAIN_ORGANIZATION, role: "owner", status: "active" },
    { provider: PROVIDER, subject: INACTIVE_SUBJECT, member_id: MEMBER_ID, membership_id: MAIN_MEMBERSHIP, organization_id: MAIN_ORGANIZATION, role: "owner", status: "inactive" },
  ];

  const humanRepository = {
    async createSession(record) {
      sessions.set(record.session_id, { ...record });
      return { ...record };
    },
    async findSessionByTokenHash(input) {
      const hash = input.token_hash ?? input.tokenHash;
      return [...sessions.values()].find((record) => record.token_hash === hash) ?? null;
    },
    async updateSessionActivity(input) {
      const record = sessions.get(input.session_id ?? input.sessionId);
      if (!record) return null;
      Object.assign(record, {
        last_seen_at: input.last_seen_at ?? input.lastSeenAt,
        idle_expires_at: input.idle_expires_at ?? input.idleExpiresAt,
      });
      return { ...record };
    },
    async revokeSession(input) {
      const id = input.session_id ?? input.sessionId;
      const record = sessions.get(id);
      if (!record) return null;
      record.revoked_at = input.revoked_at ?? input.revokedAt;
      record.revoke_reason = input.revoke_reason ?? input.reason;
      return { ...record };
    },
    async listSessions(input) {
      return [...sessions.values()].filter((record) => record.member_id === (input.member_id ?? input.memberId)).map((record) => ({ ...record }));
    },
    async consumeConsoleIdentityJti(input) {
      replayAttempts.push(input.jti_digest);
      if (consumedJtis.has(input.jti_digest)) return false;
      consumedJtis.add(input.jti_digest);
      return true;
    },
    async bindRecentAuth() { return true; },
    async consumeRecentAuth() { return null; },
    async listCredentialsForSession() { return []; },
    async listCredentialMetadataForSession() { return []; },
    async findCredentialForSession() { return null; },
    async getRegistrationUser() { return null; },
    async createCredential() { return null; },
    async insertCredential() { return null; },
    async updateCredentialCounter() { return false; },
    async updateCredentialLabel() { return null; },
    async revokeCredential() { return null; },
    async listSafeSessions() { return []; },
    async revokeManagedSession() { return null; },
  };
  const organizationRepository = {
    async listOrganizationsForMember() { return []; },
    async createOrganizationWithOwner() { return null; },
    async renameOrganization() { return null; },
    async listMembers() { return []; },
    async updateMemberRole() { return null; },
    async removeMember() { return null; },
    async listInvitations() { return []; },
    async createInvitation() { return null; },
    async revokeInvitation() { return null; },
    async acceptInvitation() { return null; },
  };
  const pool = {
    async query(text, params = []) {
      if (String(text).includes("FROM upstream_identities AS ui")) {
        const [provider, organizationId, subject] = params;
        identityQueries.push({ provider, subject, organization_id: organizationId });
        const row = identities.find((candidate) => candidate.provider === provider
          && candidate.subject === subject
          && candidate.organization_id === organizationId
          && candidate.status === "active");
        return row ? { rows: [{ ...row }], rowCount: 1 } : { rows: [], rowCount: 0 };
      }
      return { rows: [], rowCount: 0 };
    },
    async connect() {
      return { query: async (...args) => pool.query(...args), release() {} };
    },
  };
  return {
    sessions,
    replayAttempts,
    identityQueries,
    postgresRuntime: {
      pool,
      humanRepository,
      organizationRepository,
      sharedControlRepository: {
        async acquireRateLimit() {
          return { allowed: true, limit: 100, remaining: 99, retryAfterMs: 0 };
        }
      }
    },
  };
}

function listen(server) {
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      server.off("error", reject);
      resolve();
    });
  });
}

function close(server) {
  return new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
}
