import assert from "node:assert/strict";
import test from "node:test";

import {
  HUMAN_SESSION_COOKIE_NAME,
  HUMAN_SESSION_ERROR_CODES,
  HumanSessionError,
  createHumanSessionService,
  parseSessionCookie,
  publicSession,
  serializeSessionCookie
} from "../src/human-session.mjs";

const ORIGIN = "https://console.agentpass.test";
const MEMBER_ID = "11111111-1111-4111-8111-111111111111";
const ORGANIZATION_ID = "22222222-2222-4222-8222-222222222222";
const MEMBERSHIP_ID = "44444444-4444-4444-8444-444444444444";
const OTHER_MEMBER_ID = "33333333-3333-4333-8333-333333333333";
const START = Date.parse("2026-08-12T00:00:00.000Z");

class MemorySessionRepository {
  constructor() {
    this.records = new Map();
    this.created = [];
  }

  async createSession(record) {
    this.created.push(structuredClone(record));
    this.records.set(record.session_id, structuredClone(record));
    return structuredClone(record);
  }

  async findSessionByTokenHash({ tokenHash, token_hash: alternate }) {
    const hash = tokenHash ?? alternate;
    for (const record of this.records.values()) {
      if (record.token_hash === hash) return structuredClone(record);
    }
    return null;
  }

  async updateSessionActivity(input) {
    const record = this.records.get(input.session_id ?? input.sessionId);
    if (!record) return null;
    Object.assign(record, {
      last_seen_at: input.last_seen_at ?? input.lastSeenAt,
      idle_expires_at: input.idle_expires_at ?? input.idleExpiresAt
    });
    return structuredClone(record);
  }

  async revokeSession(input) {
    const record = this.records.get(input.session_id ?? input.sessionId);
    if (record) {
      record.revoked_at = input.revoked_at ?? input.revokedAt;
      record.revoke_reason = input.revoke_reason ?? input.reason;
      record.status = "revoked";
    }
    return record ? structuredClone(record) : null;
  }

  async listSessions({ member_id: memberId, memberId: alternate }) {
    const member = memberId ?? alternate;
    return [...this.records.values()]
      .filter((record) => record.member_id === member)
      .map((record) => structuredClone(record));
  }
}

function fixture(options = {}) {
  const repository = options.repository ?? new MemorySessionRepository();
  let now = options.start ?? START;
  const service = createHumanSessionService({
    repository,
    origin: ORIGIN,
    idleTtlMs: options.idleTtlMs ?? 30_000,
    absoluteTtlMs: options.absoluteTtlMs ?? 120_000,
    maxConcurrentSessions: options.maxConcurrentSessions ?? 3,
    now: () => now,
    identityAdapter: {
      async verify(assertion) {
        if (assertion !== "upstream-assertion") return null;
        return { member_id: MEMBER_ID, membership_id: MEMBERSHIP_ID, organization_id: ORGANIZATION_ID, role: "owner" };
      }
    }
  });
  return { repository, service, advance: (milliseconds) => { now += milliseconds; } };
}

async function issue(fixtureValue, assertion = "upstream-assertion") {
  return fixtureValue.service.issueSession({ identityAssertion: assertion, origin: ORIGIN });
}

test("issues a 256-bit opaque cookie and stores only hashes", async () => {
  const f = fixture();
  const issued = await issue(f);
  const token = parseSessionCookie(issued.cookie);

  assert.equal(Buffer.from(token, "base64url").length, 32);
  assert.equal(issued.cookie.startsWith(`${HUMAN_SESSION_COOKIE_NAME}=`), true);
  assert.match(issued.cookie, /Path=\//);
  assert.match(issued.cookie, /HttpOnly/);
  assert.match(issued.cookie, /Secure/);
  assert.match(issued.cookie, /SameSite=Strict/);
  assert.match(issued.cookie, /Max-Age=120/);
  assert.equal(f.repository.created.length, 1);
  assert.equal(Object.hasOwn(f.repository.created[0], "token"), false);
  assert.equal(Object.hasOwn(f.repository.created[0], "csrf_token"), false);
  assert.equal(f.repository.created[0].token_hash.includes(token), false);
  assert.match(f.repository.created[0].token_hash, /^[0-9a-f]{64}$/);
  assert.match(f.repository.created[0].csrf_token_hash, /^[0-9a-f]{64}$/);
  assert.equal(f.repository.created[0].membership_id, MEMBERSHIP_ID);

  assert.deepEqual(Object.keys(issued.session).sort(), [
    "created_at", "expires_at", "member_id", "organization_id", "recent_auth_at", "role", "session_id", "version"
  ].sort());
  assert.equal(Object.hasOwn(issued.session, "token_hash"), false);
  assert.equal(Object.hasOwn(issued.session, "csrfToken"), false);
  assert.equal(Object.hasOwn(issued.session, "csrf_token_hash"), false);
});

test("requires a verified upstream assertion and exact Origin", async () => {
  const f = fixture();
  await assert.rejects(() => f.service.issueSession({ identityAssertion: "bad", origin: ORIGIN }), (error) => error.code === HUMAN_SESSION_ERROR_CODES.IDENTITY_VERIFICATION_FAILED);
  await assert.rejects(() => f.service.issueSession({ identityAssertion: "upstream-assertion" }), (error) => error.code === HUMAN_SESSION_ERROR_CODES.INVALID_ORIGIN);
  await assert.rejects(() => f.service.issueSession({ identityAssertion: "upstream-assertion", origin: "https://console.agentpass.test.attacker" }), (error) => error.code === HUMAN_SESSION_ERROR_CODES.INVALID_ORIGIN);
  await assert.rejects(() => f.service.issueSession({ identityAssertion: "upstream-assertion", origin: "null" }), (error) => error.code === HUMAN_SESSION_ERROR_CODES.INVALID_ORIGIN);
});

test("authenticates with the HttpOnly cookie and a session-bound CSRF token", async () => {
  const f = fixture();
  const issued = await issue(f);
  const cookie = issued.cookie;

  const read = await f.service.authenticateRequest({ cookie, method: "GET", origin: ORIGIN });
  assert.deepEqual(read.session, issued.session);
  await assert.rejects(() => f.service.authenticateRequest({ cookie, method: "POST", origin: ORIGIN }), (error) => error.code === HUMAN_SESSION_ERROR_CODES.CSRF_REQUIRED);
  await assert.rejects(() => f.service.authenticateRequest({ cookie, method: "POST", origin: ORIGIN, csrfToken: "wrong".padEnd(43, "a") }), (error) => error.code === HUMAN_SESSION_ERROR_CODES.CSRF_INVALID);
  const changed = await f.service.authenticateRequest({ cookie, method: "POST", origin: ORIGIN, csrfToken: issued.csrfToken });
  assert.deepEqual(changed.session, issued.session);
  await assert.rejects(() => f.service.authenticateRequest({ cookie, method: "POST", origin: "https://console.agentpass.test.evil", csrfToken: issued.csrfToken }), (error) => error.code === HUMAN_SESSION_ERROR_CODES.INVALID_ORIGIN);
});

test("enforces idle and absolute expiry", async () => {
  const f = fixture({ idleTtlMs: 2_000, absoluteTtlMs: 5_000 });
  const issued = await issue(f);
  f.advance(2_001);
  await assert.rejects(() => f.service.authenticateRequest({ cookie: issued.cookie, method: "GET", origin: ORIGIN }), (error) => error.code === HUMAN_SESSION_ERROR_CODES.SESSION_EXPIRED);

  const absolute = fixture({ idleTtlMs: 2_000, absoluteTtlMs: 5_000 });
  const second = await issue(absolute);
  absolute.advance(1_500);
  await absolute.service.authenticateRequest({ cookie: second.cookie, method: "GET", origin: ORIGIN });
  absolute.advance(1_500);
  await absolute.service.authenticateRequest({ cookie: second.cookie, method: "GET", origin: ORIGIN });
  absolute.advance(1_999);
  await absolute.service.authenticateRequest({ cookie: second.cookie, method: "GET", origin: ORIGIN });
  absolute.advance(1);
  await assert.rejects(() => absolute.service.authenticateRequest({ cookie: second.cookie, method: "GET", origin: ORIGIN }), (error) => error.code === HUMAN_SESSION_ERROR_CODES.SESSION_EXPIRED);
});

test("rotates the session and invalidates the old bearer to prevent fixation", async () => {
  const f = fixture();
  const first = await issue(f);
  const rotated = await f.service.rotateSession({ cookie: first.cookie, origin: ORIGIN, csrfToken: first.csrfToken });

  assert.notEqual(rotated.cookie, first.cookie);
  assert.notEqual(rotated.session.session_id, first.session.session_id);
  assert.equal(rotated.session.expires_at, first.session.expires_at);
  await assert.rejects(() => f.service.authenticateRequest({ cookie: first.cookie, method: "GET", origin: ORIGIN }), (error) => error.code === HUMAN_SESSION_ERROR_CODES.SESSION_REVOKED);
  const current = await f.service.authenticateRequest({ cookie: rotated.cookie, method: "GET", origin: ORIGIN });
  assert.equal(current.session.session_id, rotated.session.session_id);
});

test("logout and explicit revocation invalidate sessions and clear the cookie", async () => {
  const f = fixture();
  const issued = await issue(f);
  const loggedOut = await f.service.logout({ cookie: issued.cookie, origin: ORIGIN, csrfToken: issued.csrfToken });
  assert.equal(loggedOut.clearCookie, "__Host-agentpass_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0");
  await assert.rejects(() => f.service.authenticateRequest({ cookie: issued.cookie, method: "GET", origin: ORIGIN }), (error) => error.code === HUMAN_SESSION_ERROR_CODES.SESSION_REVOKED);

  const second = await issue(f);
  const revoked = await f.service.revokeSession({ sessionId: second.session.session_id, origin: ORIGIN, reason: "admin-revoked" });
  assert.equal(revoked.session_id, second.session.session_id);
  await assert.rejects(() => f.service.authenticateRequest({ cookie: second.cookie, method: "GET", origin: ORIGIN }), (error) => error.code === HUMAN_SESSION_ERROR_CODES.SESSION_REVOKED);
});

test("bounds active sessions per member", async () => {
  const f = fixture({ maxConcurrentSessions: 2 });
  const first = await issue(f);
  f.advance(1_000);
  const second = await issue(f);
  f.advance(1_000);
  const third = await issue(f);
  const active = [...f.repository.records.values()].filter((record) => !record.revoked_at);
  assert.equal(active.length, 2);
  assert.equal(f.repository.records.get(first.session.session_id).revoked_at !== null, true);
  await f.service.authenticateRequest({ cookie: second.cookie, method: "GET", origin: ORIGIN });
  await f.service.authenticateRequest({ cookie: third.cookie, method: "GET", origin: ORIGIN });
});

test("publicSession is a closed, secret-free projection", () => {
  const session = publicSession({
    session_id: "11111111-1111-4111-8111-111111111111",
    member_id: MEMBER_ID,
    organization_id: ORGANIZATION_ID,
    role: "viewer",
    created_at: "2026-08-12T00:00:00.000Z",
    expires_at: "2026-08-12T01:00:00.000Z",
    recent_auth_at: null,
    token_hash: "a".repeat(64),
    csrf_token_hash: "b".repeat(64)
  });
  assert.deepEqual(session, {
    version: 1,
    session_id: "11111111-1111-4111-8111-111111111111",
    member_id: MEMBER_ID,
    organization_id: ORGANIZATION_ID,
    role: "viewer",
    created_at: "2026-08-12T00:00:00.000Z",
    expires_at: "2026-08-12T01:00:00.000Z",
    recent_auth_at: null
  });
  assert.equal(parseSessionCookie(serializeSessionCookie("a".repeat(43))), "a".repeat(43));
  assert.throws(() => parseSessionCookie(`${HUMAN_SESSION_COOKIE_NAME}=a; ${HUMAN_SESSION_COOKIE_NAME}=b`), (error) => error instanceof HumanSessionError && error.code === HUMAN_SESSION_ERROR_CODES.INVALID_COOKIE);
});

test("does not silently accept a repository without the required adapter surface", () => {
  assert.throws(() => createHumanSessionService({ repository: {}, origin: ORIGIN, identityAdapter: async () => ({}) }), (error) => error.code === HUMAN_SESSION_ERROR_CODES.REPOSITORY_INVALID);
  assert.throws(() => createHumanSessionService({ repository: new MemorySessionRepository(), origin: ORIGIN }), (error) => error.code === HUMAN_SESSION_ERROR_CODES.INVALID_CONFIGURATION);
  void OTHER_MEMBER_ID;
});
