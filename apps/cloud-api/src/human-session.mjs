import crypto from "node:crypto";

const TOKEN_BYTES = 32;
const SESSION_COOKIE = "__Host-agentpass_session";
const CSRF_HEADER = "agentpass-csrf";
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const TOKEN_PATTERN = /^[A-Za-z0-9_-]{43}$/;
const HASH_PATTERN = /^[0-9a-f]{64}$/;
const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);
const ROLES = new Set(["owner", "admin", "auditor", "viewer"]);
const DEFAULT_IDLE_TTL_MS = 30 * 60 * 1000;
const DEFAULT_ABSOLUTE_TTL_MS = 8 * 60 * 60 * 1000;
const DEFAULT_MAX_CONCURRENT_SESSIONS = 5;

export const HUMAN_SESSION_COOKIE_NAME = SESSION_COOKIE;
export const HUMAN_SESSION_CSRF_HEADER = CSRF_HEADER;
export const HUMAN_SESSION_REPOSITORY_METHODS = Object.freeze([
  "createSession",
  "findSessionByTokenHash",
  "updateSessionActivity",
  "revokeSession",
  "listSessions"
]);

export const HUMAN_SESSION_ERROR_CODES = Object.freeze({
  INVALID_CONFIGURATION: "invalid_session_configuration",
  INVALID_INPUT: "invalid_session_input",
  IDENTITY_VERIFICATION_FAILED: "identity_verification_failed",
  IDENTITY_REPLAY: "identity_assertion_replay",
  INVALID_ORIGIN: "invalid_origin",
  INVALID_COOKIE: "invalid_session_cookie",
  SESSION_NOT_FOUND: "session_not_found",
  SESSION_REVOKED: "session_revoked",
  SESSION_EXPIRED: "session_expired",
  CSRF_REQUIRED: "csrf_token_required",
  CSRF_INVALID: "invalid_csrf_token",
  REPOSITORY_INVALID: "invalid_session_repository"
});

const ERROR_MESSAGES = Object.freeze({
  [HUMAN_SESSION_ERROR_CODES.INVALID_CONFIGURATION]: "Human session configuration is invalid",
  [HUMAN_SESSION_ERROR_CODES.INVALID_INPUT]: "Human session input is invalid",
  [HUMAN_SESSION_ERROR_CODES.IDENTITY_VERIFICATION_FAILED]: "Upstream identity assertion could not be verified",
  [HUMAN_SESSION_ERROR_CODES.IDENTITY_REPLAY]: "Upstream identity assertion was already consumed",
  [HUMAN_SESSION_ERROR_CODES.INVALID_ORIGIN]: "Request origin is not allowed",
  [HUMAN_SESSION_ERROR_CODES.INVALID_COOKIE]: "Session cookie is invalid",
  [HUMAN_SESSION_ERROR_CODES.SESSION_NOT_FOUND]: "Session is invalid",
  [HUMAN_SESSION_ERROR_CODES.SESSION_REVOKED]: "Session is invalid",
  [HUMAN_SESSION_ERROR_CODES.SESSION_EXPIRED]: "Session is invalid",
  [HUMAN_SESSION_ERROR_CODES.CSRF_REQUIRED]: "CSRF token is required",
  [HUMAN_SESSION_ERROR_CODES.CSRF_INVALID]: "CSRF token is invalid",
  [HUMAN_SESSION_ERROR_CODES.REPOSITORY_INVALID]: "Session repository is invalid"
});

export class HumanSessionError extends Error {
  constructor(code, details = undefined) {
    super(ERROR_MESSAGES[code] ?? ERROR_MESSAGES[HUMAN_SESSION_ERROR_CODES.INVALID_INPUT]);
    this.name = "HumanSessionError";
    this.code = code;
    if (details !== undefined) this.details = details;
  }
}

/**
 * The repository contract deliberately receives only digests for bearer
 * material. A production adapter should implement the same operations in a
 * transaction (and lock the member's active-session set when issuing or
 * rotating) so the concurrent-session limit also holds across instances.
 * PostgreSQL exposes this stronger optional seam as createSessionWithLimit;
 * reference stores retain the process-local fallback below.
 */
export function assertHumanSessionRepository(repository) {
  if (!repository || typeof repository !== "object") fail(HUMAN_SESSION_ERROR_CODES.REPOSITORY_INVALID);
  for (const method of HUMAN_SESSION_REPOSITORY_METHODS) {
    if (typeof repository[method] !== "function") {
      fail(HUMAN_SESSION_ERROR_CODES.REPOSITORY_INVALID, { missing: method });
    }
  }
  return repository;
}

export function sha256(value) {
  return crypto.createHash("sha256").update(String(value), "utf8").digest("hex");
}

export function generateOpaqueToken(randomBytes = crypto.randomBytes) {
  const bytes = randomBytes(TOKEN_BYTES);
  if (!Buffer.isBuffer(bytes) || bytes.length !== TOKEN_BYTES) {
    fail(HUMAN_SESSION_ERROR_CODES.INVALID_CONFIGURATION);
  }
  return bytes.toString("base64url");
}

export function hashOpaqueToken(token) {
  if (!isOpaqueToken(token)) fail(HUMAN_SESSION_ERROR_CODES.INVALID_INPUT);
  return sha256(token);
}

export function isOpaqueToken(value) {
  return typeof value === "string" && TOKEN_PATTERN.test(value);
}

export function serializeSessionCookie(token, { maxAgeSeconds } = {}) {
  if (!isOpaqueToken(token)) fail(HUMAN_SESSION_ERROR_CODES.INVALID_INPUT);
  const parts = [`${SESSION_COOKIE}=${token}`, "Path=/", "HttpOnly", "Secure", "SameSite=Strict"];
  if (maxAgeSeconds !== undefined) {
    if (!Number.isSafeInteger(maxAgeSeconds) || maxAgeSeconds < 0) fail(HUMAN_SESSION_ERROR_CODES.INVALID_INPUT);
    parts.push(`Max-Age=${maxAgeSeconds}`);
  }
  return parts.join("; ");
}

export function serializeClearedSessionCookie() {
  return `${SESSION_COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`;
}

/** Parse one Cookie header without accepting a second session cookie. */
export function parseSessionCookie(cookieHeader) {
  if (typeof cookieHeader !== "string" || cookieHeader.length > 8192) {
    fail(HUMAN_SESSION_ERROR_CODES.INVALID_COOKIE);
  }
  let found;
  for (const part of cookieHeader.split(";")) {
    const separator = part.indexOf("=");
    if (separator < 1) continue;
    const name = part.slice(0, separator).trim();
    const value = part.slice(separator + 1).trim();
    if (name !== SESSION_COOKIE) continue;
    if (found !== undefined || !isOpaqueToken(value)) fail(HUMAN_SESSION_ERROR_CODES.INVALID_COOKIE);
    found = value;
  }
  if (found === undefined) fail(HUMAN_SESSION_ERROR_CODES.INVALID_COOKIE);
  return found;
}

/**
 * Return only the public human-session contract. Internal fields such as
 * token_hash, csrf_token_hash, idle_expires_at and revoked_at are never
 * allowed to cross this boundary.
 */
export function publicSession(record) {
  if (!record || typeof record !== "object") fail(HUMAN_SESSION_ERROR_CODES.INVALID_INPUT);
  return {
    version: 1,
    session_id: record.session_id,
    member_id: record.member_id,
    organization_id: record.organization_id,
    role: record.role,
    created_at: record.created_at,
    expires_at: record.expires_at,
    recent_auth_at: record.recent_auth_at ?? null
  };
}

export function assertStrictOrigin(actual, expected) {
  if (typeof expected !== "string" || expected.length === 0 || expected.endsWith("/")) {
    fail(HUMAN_SESSION_ERROR_CODES.INVALID_CONFIGURATION);
  }
  if (typeof actual !== "string" || actual !== expected || actual === "null") {
    fail(HUMAN_SESSION_ERROR_CODES.INVALID_ORIGIN);
  }
  return true;
}

/**
 * Create the identity-backed session service. `identityAdapter.verify` is
 * mandatory: caller-supplied identity fields are never trusted directly.
 * `authorizeIdentity` is also mandatory and runs after one-use identity
 * verification but before credential generation or durable insertion.
 */
export function createHumanSessionService(options = {}) {
  const repository = assertHumanSessionRepository(options.repository);
  const identityAdapter = options.identityAdapter ?? options.identity;
  const verifyIdentity = typeof identityAdapter === "function"
    ? identityAdapter
    : identityAdapter?.verify ?? identityAdapter?.assert;
  if (typeof verifyIdentity !== "function") fail(HUMAN_SESSION_ERROR_CODES.INVALID_CONFIGURATION);
  const authorizeIdentity = options.authorizeIdentity;
  if (typeof authorizeIdentity !== "function") fail(HUMAN_SESSION_ERROR_CODES.INVALID_CONFIGURATION);

  const expectedOrigin = options.origin ?? options.expectedOrigin;
  if (typeof expectedOrigin !== "string" || expectedOrigin.length === 0 || expectedOrigin.endsWith("/")) {
    fail(HUMAN_SESSION_ERROR_CODES.INVALID_CONFIGURATION);
  }
  const idleTtlMs = boundedDuration(options.idleTtlMs ?? options.idleTtl ?? DEFAULT_IDLE_TTL_MS, "idleTtlMs");
  const absoluteTtlMs = boundedDuration(options.absoluteTtlMs ?? options.absoluteTtl ?? DEFAULT_ABSOLUTE_TTL_MS, "absoluteTtlMs");
  if (idleTtlMs > absoluteTtlMs) fail(HUMAN_SESSION_ERROR_CODES.INVALID_CONFIGURATION);
  const maxConcurrentSessions = options.maxConcurrentSessions ?? DEFAULT_MAX_CONCURRENT_SESSIONS;
  if (!Number.isSafeInteger(maxConcurrentSessions) || maxConcurrentSessions < 1 || maxConcurrentSessions > 10_000) {
    fail(HUMAN_SESSION_ERROR_CODES.INVALID_CONFIGURATION);
  }
  const clock = options.now ?? options.clock ?? (() => Date.now());
  const randomBytes = options.randomBytes ?? crypto.randomBytes;
  if (typeof clock !== "function" || typeof randomBytes !== "function") fail(HUMAN_SESSION_ERROR_CODES.INVALID_CONFIGURATION);
  const locks = new Map();

  const nowMs = () => normalizeNow(clock());

  async function issueSession(input = {}) {
    assertStrictOrigin(input.origin ?? input.requestOrigin, expectedOrigin);
    if (input.identityAssertion === undefined && input.assertion === undefined) {
      fail(HUMAN_SESSION_ERROR_CODES.INVALID_INPUT);
    }
    const now = nowMs();
    const assertion = input.identityAssertion ?? input.assertion;
    let identity;
    try {
      identity = await verifyIdentity(assertion, { now, origin: expectedOrigin });
    } catch {
      fail(HUMAN_SESSION_ERROR_CODES.IDENTITY_VERIFICATION_FAILED);
    }
    const principal = normalizeIdentity(identity);
    if (principal.assertion_expires_at !== undefined && principal.assertion_expires_at <= now) {
      fail(HUMAN_SESSION_ERROR_CODES.IDENTITY_VERIFICATION_FAILED);
    }
    await authorizeIdentity(Object.freeze({
      subject_bucket_id: principal.subject_bucket_id,
      member_id: principal.member_id,
      organization_id: principal.organization_id
    }));

    return withLock(locks, principal.member_id, async () => {
      const token = generateOpaqueToken(randomBytes);
      const csrfToken = generateOpaqueToken(randomBytes);
      const createdAt = new Date(now).toISOString();
      const absoluteExpiresAt = new Date(now + absoluteTtlMs).toISOString();
      const record = {
        session_id: randomUuid(randomBytes),
        member_id: principal.member_id,
        membership_id: principal.membership_id,
        organization_id: principal.organization_id,
        role: principal.role,
        created_at: createdAt,
        expires_at: absoluteExpiresAt,
        recent_auth_at: null,
        last_seen_at: createdAt,
        idle_expires_at: new Date(Math.min(now + idleTtlMs, now + absoluteTtlMs)).toISOString(),
        token_hash: hashOpaqueToken(token),
        csrf_token_hash: hashOpaqueToken(csrfToken),
        revoked_at: null,
        revoke_reason: null
      };
      const storedRecord = stripForRepository(record);
      if (typeof repository.createSessionWithLimit === "function") {
        try {
          await repository.createSessionWithLimit({
            session: storedRecord,
            max_concurrent_sessions: maxConcurrentSessions,
            issued_at: createdAt,
            revoke_reason: "concurrent_session_limit",
            ...(principal.identity_replay === undefined ? {} : { identity_replay: principal.identity_replay })
          });
        } catch (error) {
          if (error?.code === "human_identity_assertion_replay") fail(HUMAN_SESSION_ERROR_CODES.IDENTITY_REPLAY);
          throw error;
        }
      } else {
        if (principal.identity_replay !== undefined) fail(HUMAN_SESSION_ERROR_CODES.INVALID_CONFIGURATION);
        await enforceSessionLimit(principal.member_id, now, maxConcurrentSessions);
        await repository.createSession(storedRecord);
      }
      const maxAgeSeconds = Math.max(0, Math.floor((Date.parse(record.expires_at) - now) / 1000));
      return {
        session: publicSession(record),
        cookie: serializeSessionCookie(token, { maxAgeSeconds }),
        setCookie: serializeSessionCookie(token, { maxAgeSeconds }),
        csrfToken,
        csrf_token: csrfToken
      };
    });
  }

  async function authenticateRequest(input = {}) {
    const authenticated = await authenticateRecord(input);
    return { session: authenticated.session };
  }

  async function authenticateRecord(input = {}) {
    const method = String(input.method ?? "GET").toUpperCase();
    const headers = input.headers;
    const cookieHeader = input.cookie ?? input.cookieHeader ?? headerValue(headers, "cookie");
    const origin = input.origin ?? input.requestOrigin ?? headerValue(headers, "origin");
    assertStrictOrigin(origin, expectedOrigin);
    const token = parseSessionCookie(cookieHeader);
    const record = await findByToken(token);
    const now = nowMs();
    const active = await ensureActive(record, now);
    if (!SAFE_METHODS.has(method)) {
      const csrfToken = input.csrfToken ?? input.csrf_token ?? headerValue(headers, CSRF_HEADER);
      assertCsrf(active, csrfToken);
    }
    const touched = await touch(active, now);
    return { session: publicSession(touched), record: touched };
  }

  async function rotateSession(input = {}) {
    const authenticated = await authenticateRecord({ ...input, method: input.method ?? "POST" });
    const oldRecord = authenticated.record;
    const now = nowMs();
    await ensureActive(oldRecord, now);
    return withLock(locks, oldRecord.member_id, async () => {
      const token = generateOpaqueToken(randomBytes);
      const csrfToken = generateOpaqueToken(randomBytes);
      const createdAt = new Date(now).toISOString();
      const absoluteExpiresAt = oldRecord.expires_at;
      if (Date.parse(absoluteExpiresAt) <= now) fail(HUMAN_SESSION_ERROR_CODES.SESSION_EXPIRED);
      const newRecord = {
        session_id: randomUuid(randomBytes),
        member_id: oldRecord.member_id,
        membership_id: oldRecord.membership_id,
        organization_id: oldRecord.organization_id,
        role: oldRecord.role,
        created_at: createdAt,
        expires_at: absoluteExpiresAt,
        // Rotation never carries a step-up WebAuthn authorization forward.
        // A fresh session must complete its own recent-auth ceremony.
        recent_auth_at: null,
        last_seen_at: createdAt,
        idle_expires_at: new Date(Math.min(now + idleTtlMs, Date.parse(absoluteExpiresAt))).toISOString(),
        token_hash: hashOpaqueToken(token),
        csrf_token_hash: hashOpaqueToken(csrfToken),
        revoked_at: null,
        revoke_reason: null
      };
      if (typeof repository.rotateSession === "function") {
        const committed = await repository.rotateSession({ old_session_id: oldRecord.session_id, old_token_hash: oldRecord.token_hash, session: stripForRepository(newRecord), reason: "session_rotation", rotated_at: createdAt });
        if (!committed) fail(HUMAN_SESSION_ERROR_CODES.SESSION_REVOKED);
      } else {
        await repository.createSession(stripForRepository(newRecord));
        await repository.revokeSession({ sessionId: oldRecord.session_id, session_id: oldRecord.session_id, revokedAt: createdAt, revoked_at: createdAt, reason: "session_rotation", revoke_reason: "session_rotation" });
      }
      const maxAgeSeconds = Math.max(0, Math.floor((Date.parse(newRecord.expires_at) - now) / 1000));
      return {
        session: publicSession(newRecord),
        cookie: serializeSessionCookie(token, { maxAgeSeconds }),
        setCookie: serializeSessionCookie(token, { maxAgeSeconds }),
        csrfToken,
        csrf_token: csrfToken
      };
    });
  }

  async function switchOrganization(input = {}) {
    const authenticated = await authenticateRecord({ ...input, method: input.method ?? "POST" });
    const oldRecord = authenticated.record;
    const targetOrganizationId = input.organization_id ?? input.organizationId;
    if (!isUuid(targetOrganizationId) || targetOrganizationId === oldRecord.organization_id) fail(HUMAN_SESSION_ERROR_CODES.INVALID_INPUT);
    const now = nowMs();
    await ensureActive(oldRecord, now);
    return withLock(locks, oldRecord.member_id, async () => {
      const token = generateOpaqueToken(randomBytes);
      const csrfToken = generateOpaqueToken(randomBytes);
      const createdAt = new Date(now).toISOString();
      if (Date.parse(oldRecord.expires_at) <= now) fail(HUMAN_SESSION_ERROR_CODES.SESSION_EXPIRED);
      if (typeof repository.switchSessionOrganization !== "function") fail(HUMAN_SESSION_ERROR_CODES.REPOSITORY_INVALID);
      const switched = await repository.switchSessionOrganization({
        old_session_id: oldRecord.session_id,
        old_token_hash: oldRecord.token_hash,
        member_id: oldRecord.member_id,
        old_organization_id: oldRecord.organization_id,
        target_organization_id: targetOrganizationId,
        session: {
          session_id: randomUuid(randomBytes),
          member_id: oldRecord.member_id,
          organization_id: targetOrganizationId,
          created_at: createdAt,
          expires_at: oldRecord.expires_at,
          last_seen_at: createdAt,
          idle_expires_at: new Date(Math.min(now + idleTtlMs, Date.parse(oldRecord.expires_at))).toISOString(),
          token_hash: hashOpaqueToken(token),
          csrf_token_hash: hashOpaqueToken(csrfToken)
        },
        switched_at: createdAt,
        reason: "organization_switch"
      });
      if (!switched) fail(HUMAN_SESSION_ERROR_CODES.SESSION_REVOKED);
      assertSwitchedSession(oldRecord, switched, targetOrganizationId);
      await ensureActive(switched, now);
      const maxAgeSeconds = Math.max(0, Math.floor((Date.parse(switched.expires_at) - now) / 1000));
      return { session: publicSession(switched), cookie: serializeSessionCookie(token, { maxAgeSeconds }), setCookie: serializeSessionCookie(token, { maxAgeSeconds }), csrfToken, csrf_token: csrfToken };
    });
  }

  async function logout(input = {}) {
    assertStrictOrigin(input.origin ?? input.requestOrigin ?? headerValue(input.headers, "origin"), expectedOrigin);
    let token;
    try { token = parseSessionCookie(input.cookie ?? input.cookieHeader ?? headerValue(input.headers, "cookie")); }
    catch (error) {
      if (error instanceof HumanSessionError && error.code === HUMAN_SESSION_ERROR_CODES.INVALID_COOKIE) {
        return { session: null, clearCookie: serializeClearedSessionCookie(), setCookie: serializeClearedSessionCookie() };
      }
      throw error;
    }
    const record = await findByToken(token);
    const now = nowMs();
    const active = await ensureActive(record, now);
    assertCsrf(active, input.csrfToken ?? input.csrf_token ?? headerValue(input.headers, CSRF_HEADER));
    const revokedAt = new Date(now).toISOString();
    await repository.revokeSession({ sessionId: record.session_id, session_id: record.session_id, revokedAt, revoked_at: revokedAt, reason: "logout", revoke_reason: "logout" });
    return { session: publicSession({ ...record, revoked_at: revokedAt, revoke_reason: "logout" }), clearCookie: serializeClearedSessionCookie(), setCookie: serializeClearedSessionCookie() };
  }

  async function revokeSession(input = {}) {
    assertStrictOrigin(input.origin ?? input.requestOrigin, expectedOrigin);
    const sessionId = input.sessionId ?? input.session_id;
    if (!isUuid(sessionId)) fail(HUMAN_SESSION_ERROR_CODES.INVALID_INPUT);
    const now = nowMs();
    const revokedAt = new Date(now).toISOString();
    await repository.revokeSession({ sessionId, session_id: sessionId, revokedAt, revoked_at: revokedAt, reason: input.reason ?? "revoked", revoke_reason: input.reason ?? "revoked" });
    return { session_id: sessionId, revoked_at: revokedAt };
  }

  async function getSession(input = {}) {
    return authenticateRequest(input);
  }

  return Object.freeze({
    issueSession,
    issueFromIdentityAssertion: issueSession,
    createSessionFromIdentityAssertion: issueSession,
    authenticateRequest,
    authenticateSession: authenticateRequest,
    getSession,
    rotateSession,
    switchOrganization,
    logout,
    revokeSession,
    publicSession,
    expectedOrigin,
    idleTtlMs,
    absoluteTtlMs,
    maxConcurrentSessions
  });

  async function findByToken(token) {
    const tokenHash = hashOpaqueToken(token);
    const record = await repository.findSessionByTokenHash({ tokenHash, token_hash: tokenHash });
    if (!record) fail(HUMAN_SESSION_ERROR_CODES.SESSION_NOT_FOUND);
    return record;
  }

  async function ensureActive(record, now) {
    if (!record || typeof record !== "object") fail(HUMAN_SESSION_ERROR_CODES.SESSION_NOT_FOUND);
    if (record.revoked_at || record.revokedAt || record.status === "revoked") fail(HUMAN_SESSION_ERROR_CODES.SESSION_REVOKED);
    if (!isUuid(record.session_id) || !isUuid(record.member_id) || !isUuid(record.organization_id)) fail(HUMAN_SESSION_ERROR_CODES.SESSION_NOT_FOUND);
    if (!ROLES.has(record.role)) fail(HUMAN_SESSION_ERROR_CODES.SESSION_NOT_FOUND);
    const absolute = Date.parse(record.expires_at);
    const idle = Date.parse(record.idle_expires_at);
    if (!Number.isFinite(absolute) || !Number.isFinite(idle) || now >= absolute || now >= idle) {
      const expiredAt = new Date(now).toISOString();
      try { await repository.revokeSession({ sessionId: record.session_id, session_id: record.session_id, revokedAt: expiredAt, revoked_at: expiredAt, reason: "expired", revoke_reason: "expired" }); } catch {}
      fail(HUMAN_SESSION_ERROR_CODES.SESSION_EXPIRED);
    }
    if (!HASH_PATTERN.test(record.token_hash) || !HASH_PATTERN.test(record.csrf_token_hash)) fail(HUMAN_SESSION_ERROR_CODES.SESSION_NOT_FOUND);
    return record;
  }

  async function touch(record, now) {
    const nextIdleMs = Math.min(now + idleTtlMs, Date.parse(record.expires_at));
    const activityAt = new Date(now).toISOString();
    const patch = { sessionId: record.session_id, session_id: record.session_id, activityAt, activity_at: activityAt, lastSeenAt: activityAt, last_seen_at: activityAt, idleExpiresAt: new Date(nextIdleMs).toISOString(), idle_expires_at: new Date(nextIdleMs).toISOString() };
    if (typeof repository.updateSessionActivity === "function") {
      const updated = await repository.updateSessionActivity(patch);
      // A concurrent role/revocation/epoch change makes the conditional
      // activity update miss. Never continue with the stale pre-change row.
      if (!updated) fail(HUMAN_SESSION_ERROR_CODES.SESSION_REVOKED);
      assertSessionContinuity(record, updated);
      await ensureActive(updated, now);
      return updated;
    }
    return record;
  }

  async function enforceSessionLimit(memberId, now, limit) {
    const sessions = await repository.listSessions({ memberId, member_id: memberId, includeRevoked: false, include_revoked: false });
    const active = (Array.isArray(sessions) ? sessions : []).filter((item) => isActiveForLimit(item, now));
    const excess = Math.max(0, active.length - limit + 1);
    active.sort((a, b) => Date.parse(a.created_at) - Date.parse(b.created_at) || String(a.session_id).localeCompare(String(b.session_id)));
    for (const session of active.slice(0, excess)) {
      const revokedAt = new Date(now).toISOString();
      await repository.revokeSession({ sessionId: session.session_id, session_id: session.session_id, revokedAt, revoked_at: revokedAt, reason: "concurrent_session_limit", revoke_reason: "concurrent_session_limit" });
    }
  }

  function isActiveForLimit(record, now) {
    return record && !record.revoked_at && !record.revokedAt && record.status !== "revoked"
      && Number.isFinite(Date.parse(record.expires_at)) && Date.parse(record.expires_at) > now
      && Number.isFinite(Date.parse(record.idle_expires_at)) && Date.parse(record.idle_expires_at) > now;
  }

  function assertCsrf(record, token) {
    if (!isOpaqueToken(token)) fail(HUMAN_SESSION_ERROR_CODES.CSRF_REQUIRED);
    const actual = Buffer.from(hashOpaqueToken(token), "hex");
    const expected = Buffer.from(record.csrf_token_hash, "hex");
    if (actual.length !== expected.length || !crypto.timingSafeEqual(actual, expected)) fail(HUMAN_SESSION_ERROR_CODES.CSRF_INVALID);
  }
}

function assertSessionContinuity(previous, next) {
  if (!next || typeof next !== "object"
    || next.session_id !== previous.session_id
    || next.member_id !== previous.member_id
    || next.membership_id !== previous.membership_id
    || next.organization_id !== previous.organization_id
    || next.role !== previous.role) {
    fail(HUMAN_SESSION_ERROR_CODES.SESSION_REVOKED);
  }
}

function assertSwitchedSession(previous, next, targetOrganizationId) {
  if (!next || typeof next !== "object"
    || next.session_id === previous.session_id
    || next.member_id !== previous.member_id
    || next.organization_id !== targetOrganizationId
    || next.recent_auth_at !== null) {
    fail(HUMAN_SESSION_ERROR_CODES.SESSION_REVOKED);
  }
}

function normalizeIdentity(identity) {
  const value = identity?.principal ?? identity?.identity ?? identity;
  if (!value || typeof value !== "object" || value.verified === false) fail(HUMAN_SESSION_ERROR_CODES.IDENTITY_VERIFICATION_FAILED);
  const memberId = value.member_id ?? value.memberId ?? value.sub;
  const membershipId = value.membership_id ?? value.membershipId;
  const organizationId = value.organization_id ?? value.organizationId ?? value.org_id;
  const role = value.role;
  const subjectBucketId = identity?.subject_bucket_id ?? identity?.subjectBucketId ?? value.subject_bucket_id ?? value.subjectBucketId;
  if (!isUuid(memberId) || !isUuid(membershipId) || !isUuid(organizationId) || !isUuid(subjectBucketId) || !ROLES.has(role)) fail(HUMAN_SESSION_ERROR_CODES.IDENTITY_VERIFICATION_FAILED);
  const assertionExpiry = value.expires_at ?? value.expiresAt;
  const assertionExpiresAt = assertionExpiry === undefined ? undefined : Date.parse(assertionExpiry);
  if (assertionExpiry !== undefined && !Number.isFinite(assertionExpiresAt)) fail(HUMAN_SESSION_ERROR_CODES.IDENTITY_VERIFICATION_FAILED);
  const replayValue = identity?.identity_replay ?? identity?.identityReplay;
  let identityReplay;
  if (replayValue !== undefined) {
    const jtiDigest = replayValue?.jti_digest ?? replayValue?.jtiDigest;
    const expiresAt = replayValue?.expires_at ?? replayValue?.expiresAt;
    if (typeof jtiDigest !== "string" || !HASH_PATTERN.test(jtiDigest) || typeof expiresAt !== "string" || !Number.isFinite(Date.parse(expiresAt))) fail(HUMAN_SESSION_ERROR_CODES.IDENTITY_VERIFICATION_FAILED);
    identityReplay = Object.freeze({ jti_digest: jtiDigest, expires_at: expiresAt });
  }
  return { member_id: memberId, membership_id: membershipId, organization_id: organizationId, subject_bucket_id: subjectBucketId, role, assertion_expires_at: assertionExpiresAt, identity_replay: identityReplay };
}

function stripForRepository(record) {
  return { ...record };
}

function randomUuid(randomBytes) {
  const bytes = randomBytes(16);
  if (!Buffer.isBuffer(bytes) || bytes.length !== 16) fail(HUMAN_SESSION_ERROR_CODES.INVALID_CONFIGURATION);
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  return [...bytes].map((byte, index) => {
    const text = byte.toString(16).padStart(2, "0");
    return [4, 6, 8, 10].includes(index) ? `-${text}` : text;
  }).join("");
}

function isUuid(value) {
  return typeof value === "string" && UUID_PATTERN.test(value);
}

function boundedDuration(value, name) {
  if (!Number.isSafeInteger(value) || value < 1_000 || value > 7 * 24 * 60 * 60 * 1000) {
    fail(HUMAN_SESSION_ERROR_CODES.INVALID_CONFIGURATION, { field: name });
  }
  return value;
}

function normalizeNow(value) {
  const now = value instanceof Date ? value.getTime() : value;
  if (!Number.isSafeInteger(now) || now < 0) fail(HUMAN_SESSION_ERROR_CODES.INVALID_CONFIGURATION);
  return now;
}

function headerValue(headers, name) {
  if (!headers) return undefined;
  if (typeof headers.get === "function") return headers.get(name) ?? headers.get(name.toLowerCase()) ?? undefined;
  if (typeof headers !== "object") return undefined;
  const target = name.toLowerCase();
  const key = Object.keys(headers).find((candidate) => candidate.toLowerCase() === target);
  return key === undefined ? undefined : headers[key];
}

function withLock(locks, key, operation) {
  const previous = locks.get(key) ?? Promise.resolve();
  const current = previous.then(operation, operation);
  const settled = current.catch(() => undefined);
  locks.set(key, settled);
  return current.finally(() => {
    if (locks.get(key) === settled) locks.delete(key);
  });
}

function fail(code, details = undefined) {
  throw new HumanSessionError(code, details);
}
