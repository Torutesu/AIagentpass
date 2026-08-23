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
const SUBJECT_BUCKET_ID = "55555555-5555-4555-8555-555555555555";
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

  async switchSessionOrganization(input) {
    const old = this.records.get(input.old_session_id);
    if (!old || old.token_hash !== input.old_token_hash || old.revoked_at) return null;
    const session = {
      ...input.session,
      membership_id: "66666666-6666-4666-8666-666666666666",
      role: "admin",
      version: 1,
      recent_auth_at: null,
      revoked_at: null,
      revoke_reason: null,
      status: "active"
    };
    old.revoked_at = input.switched_at;
    old.revoke_reason = input.reason;
    old.status = "revoked";
    this.records.set(session.session_id, structuredClone(session));
    return structuredClone(session);
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
  const authorizedIdentities = [];
  let now = options.start ?? START;
  const service = createHumanSessionService({
    repository,
    origin: ORIGIN,
    idleTtlMs: options.idleTtlMs ?? 30_000,
    absoluteTtlMs: options.absoluteTtlMs ?? 120_000,
    maxConcurrentSessions: options.maxConcurrentSessions ?? 3,
    now: () => now,
    authorizeIdentity: options.authorizeIdentity ?? (async (identity) => { authorizedIdentities.push(identity); }),
    identityAdapter: {
      async verify(assertion) {
        if (assertion !== "upstream-assertion") return null;
        return { member_id: MEMBER_ID, membership_id: MEMBERSHIP_ID, organization_id: ORGANIZATION_ID, subject_bucket_id: SUBJECT_BUCKET_ID, role: "owner" };
      }
    }
  });
  return { repository, service, authorizedIdentities, advance: (milliseconds) => { now += milliseconds; } };
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
  assert.deepEqual(f.authorizedIdentities, [{ subject_bucket_id: SUBJECT_BUCKET_ID, member_id: MEMBER_ID, organization_id: ORGANIZATION_ID }]);

  assert.deepEqual(Object.keys(issued.session).sort(), [
    "created_at", "expires_at", "member_id", "organization_id", "recent_auth_at", "role", "session_id", "version"
  ].sort());
  assert.equal(Object.hasOwn(issued.session, "token_hash"), false);
  assert.equal(Object.hasOwn(issued.session, "csrfToken"), false);
  assert.equal(Object.hasOwn(issued.session, "csrf_token_hash"), false);
});

test("switchOrganization rotates credentials, clears recent auth, and revokes the old session", async () => {
  const f = fixture();
  const issued = await issue(f);
  const oldToken = parseSessionCookie(issued.cookie);
  const target = "77777777-7777-4777-8777-777777777777";
  const switched = await f.service.switchOrganization({
    method: "POST",
    origin: ORIGIN,
    cookie: issued.cookie,
    csrfToken: issued.csrfToken,
    organization_id: target
  });
  assert.equal(switched.session.organization_id, target);
  assert.notEqual(parseSessionCookie(switched.cookie), oldToken);
  assert.equal(switched.session.recent_auth_at, null);
  assert.equal([...f.repository.records.values()].filter((record) => record.status === "revoked").length, 1);
  await assert.rejects(() => f.service.authenticateRequest({ method: "GET", origin: ORIGIN, cookie: issued.cookie }), (error) => error.code === HUMAN_SESSION_ERROR_CODES.SESSION_REVOKED);
});

test("uses the repository atomic session ceiling when production storage exposes it", async () => {
  const repository = new MemorySessionRepository();
  const calls = [];
  repository.createSession = async () => { throw new Error("non-atomic issuance must not run"); };
  repository.listSessions = async () => { throw new Error("process-local limit must not run"); };
  repository.createSessionWithLimit = async (input) => {
    calls.push(structuredClone(input));
    repository.records.set(input.session.session_id, structuredClone(input.session));
    return structuredClone(input.session);
  };
  const f = fixture({ repository, maxConcurrentSessions: 2 });
  const issued = await issue(f);
  assert.equal(issued.session.member_id, MEMBER_ID);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].max_concurrent_sessions, 2);
  assert.equal(calls[0].revoke_reason, "concurrent_session_limit");
  assert.equal(calls[0].issued_at, calls[0].session.created_at);
  assert.match(calls[0].session.token_hash, /^[0-9a-f]{64}$/);
  assert.equal(Object.hasOwn(calls[0].session, "token"), false);
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
  f.repository.records.get(first.session.session_id).recent_auth_at = "2026-08-12T00:00:00.000Z";
  const rotated = await f.service.rotateSession({ cookie: first.cookie, origin: ORIGIN, csrfToken: first.csrfToken });

  assert.notEqual(rotated.cookie, first.cookie);
  assert.notEqual(rotated.session.session_id, first.session.session_id);
  assert.equal(rotated.session.expires_at, first.session.expires_at);
  assert.equal(rotated.session.recent_auth_at, null);
  await assert.rejects(() => f.service.authenticateRequest({ cookie: first.cookie, method: "GET", origin: ORIGIN }), (error) => error.code === HUMAN_SESSION_ERROR_CODES.SESSION_REVOKED);
  const current = await f.service.authenticateRequest({ cookie: rotated.cookie, method: "GET", origin: ORIGIN });
  assert.equal(current.session.session_id, rotated.session.session_id);
});

test("fails closed when authority changes between session lookup and activity update", async () => {
  const repository = new MemorySessionRepository();
  const f = fixture({ repository });
  const issued = await issue(f);
  repository.updateSessionActivity = async () => null;

  await assert.rejects(
    () => f.service.authenticateRequest({ cookie: issued.cookie, method: "GET", origin: ORIGIN }),
    (error) => error.code === HUMAN_SESSION_ERROR_CODES.SESSION_REVOKED
  );
});

test("coalesces concurrent activity touches for one session", async () => {
  const repository = new MemorySessionRepository();
  const f = fixture({ repository });
  const issued = await issue(f);
  let release;
  const gate = new Promise((resolve) => { release = resolve; });
  let touchCalls = 0;
  const originalTouch = repository.updateSessionActivity.bind(repository);
  repository.updateSessionActivity = async (input) => {
    touchCalls += 1;
    await gate;
    return originalTouch(input);
  };

  const first = f.service.authenticateRequest({ cookie: issued.cookie, method: "GET", origin: ORIGIN });
  const second = f.service.authenticateRequest({ cookie: issued.cookie, method: "GET", origin: ORIGIN });
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(touchCalls, 1);
  release();
  const [a, b] = await Promise.all([first, second]);
  assert.equal(a.session.session_id, issued.session.session_id);
  assert.equal(b.session.session_id, issued.session.session_id);
  assert.equal(touchCalls, 1);
});

test("rejects a role or tenant substitution returned by the activity update", async () => {
  const repository = new MemorySessionRepository();
  const f = fixture({ repository });
  const issued = await issue(f);
  repository.updateSessionActivity = async (input) => ({
    ...repository.records.get(input.session_id),
    role: "admin",
    organization_id: "88888888-8888-4888-8888-888888888888"
  });

  await assert.rejects(
    () => f.service.authenticateRequest({ cookie: issued.cookie, method: "GET", origin: ORIGIN }),
    (error) => error.code === HUMAN_SESSION_ERROR_CODES.SESSION_REVOKED
  );
});

test("rejects a tenant-substituted replacement during organization switch", async () => {
  const repository = new MemorySessionRepository();
  const f = fixture({ repository });
  const issued = await issue(f);
  repository.switchSessionOrganization = async (input) => ({
    ...input.session,
    membership_id: MEMBERSHIP_ID,
    role: "owner",
    recent_auth_at: null,
    token_hash: "a".repeat(64),
    csrf_token_hash: "b".repeat(64),
    organization_id: "99999999-9999-4999-8999-999999999999"
  });

  await assert.rejects(
    () => f.service.switchOrganization({ cookie: issued.cookie, origin: ORIGIN, csrfToken: issued.csrfToken, organization_id: "77777777-7777-4777-8777-777777777777" }),
    (error) => error.code === HUMAN_SESSION_ERROR_CODES.SESSION_REVOKED
  );
});

test("does not return a replacement cookie when atomic rotation loses the old session", async () => {
  const repository = new MemorySessionRepository();
  repository.rotateSession = async () => null;
  const f = fixture({ repository });
  const issued = await issue(f);

  await assert.rejects(
    () => f.service.rotateSession({ cookie: issued.cookie, origin: ORIGIN, csrfToken: issued.csrfToken }),
    (error) => error.code === HUMAN_SESSION_ERROR_CODES.SESSION_REVOKED
  );
  assert.equal(repository.records.size, 1);
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

test("logout uses the atomic adapter when the repository provides one", async () => {
  const repository = new MemorySessionRepository();
  const calls = [];
  repository.logoutSession = async (input) => {
    calls.push(input);
    return MemorySessionRepository.prototype.revokeSession.call(repository, input);
  };
  const f = fixture({ repository });
  const issued = await issue(f);

  await f.service.logout({ cookie: issued.cookie, origin: ORIGIN, csrfToken: issued.csrfToken });

  assert.equal(calls.length, 1);
  assert.equal(calls[0].session_id, issued.session.session_id);
  assert.equal(calls[0].member_id, MEMBER_ID);
  assert.equal(calls[0].organization_id, ORGANIZATION_ID);
  assert.match(calls[0].token_hash, /^[0-9a-f]{64}$/);
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
  assert.throws(() => createHumanSessionService({ repository: {}, origin: ORIGIN, identityAdapter: async () => ({}), authorizeIdentity: async () => {} }), (error) => error.code === HUMAN_SESSION_ERROR_CODES.REPOSITORY_INVALID);
  assert.throws(() => createHumanSessionService({ repository: new MemorySessionRepository(), origin: ORIGIN, authorizeIdentity: async () => {} }), (error) => error.code === HUMAN_SESSION_ERROR_CODES.INVALID_CONFIGURATION);
  assert.throws(() => createHumanSessionService({ repository: new MemorySessionRepository(), origin: ORIGIN, identityAdapter: async () => ({}) }), (error) => error.code === HUMAN_SESSION_ERROR_CODES.INVALID_CONFIGURATION);
  void OTHER_MEMBER_ID;
});

test("verified identity admission runs before token generation and session insertion", async () => {
  let randomCalls = 0;
  const repository = new MemorySessionRepository();
  const denial = Object.assign(new Error("limiter-secret"), { code: "human_auth_rate_limited", status: 429 });
  const service = createHumanSessionService({
    repository,
    origin: ORIGIN,
    idleTtlMs: 30_000,
    absoluteTtlMs: 120_000,
    now: () => START,
    randomBytes(size) { randomCalls += 1; return Buffer.alloc(size, 1); },
    identityAdapter: { async verify() { return { member_id: MEMBER_ID, membership_id: MEMBERSHIP_ID, organization_id: ORGANIZATION_ID, subject_bucket_id: SUBJECT_BUCKET_ID, role: "owner" }; } },
    async authorizeIdentity(identity) {
      assert.deepEqual(identity, { subject_bucket_id: SUBJECT_BUCKET_ID, member_id: MEMBER_ID, organization_id: ORGANIZATION_ID });
      throw denial;
    }
  });
  await assert.rejects(() => service.issueSession({ identityAssertion: "upstream-assertion", origin: ORIGIN }), (error) => error === denial);
  assert.equal(randomCalls, 0);
  assert.equal(repository.created.length, 0);
});
