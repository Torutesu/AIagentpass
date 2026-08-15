import assert from "node:assert/strict";
import test from "node:test";

import {
  createHumanManagementHttpApi,
  HUMAN_MANAGEMENT_HTTP_ERROR_CODES,
  HUMAN_MANAGEMENT_HTTP_PATHS,
  HUMAN_MANAGEMENT_REPOSITORY_METHODS
} from "../src/human-auth/management/http-api.mjs";

const ORIGIN = "https://console.agentpass.test";
const TOKEN = "s".repeat(43);
const CSRF = "c".repeat(43);
const COOKIE = `__Host-agentpass_session=${TOKEN}; Path=/; HttpOnly; Secure; SameSite=Strict`;
const MEMBER_ID = "11111111-1111-4111-8111-111111111111";
const ORGANIZATION_ID = "22222222-2222-4222-8222-222222222222";
const CURRENT_SESSION_ID = "33333333-3333-4333-8333-333333333333";
const OTHER_SESSION_ID = "44444444-4444-4444-8444-444444444444";
const CREDENTIAL_ID = Buffer.alloc(16).toString("base64url");
const OTHER_CREDENTIAL_ID = Buffer.alloc(17, 1).toString("base64url");
const RECENT_AUTHORIZATION_ID = "55555555-5555-4555-8555-555555555555";
const CREATED = "2026-08-12T00:00:00.000Z";
const EXPIRES = "2026-08-12T08:00:00.000Z";
const NOW = Date.parse(CREATED);

function authenticatedSession(overrides = {}) {
  return {
    session_id: CURRENT_SESSION_ID,
    member_id: MEMBER_ID,
    organization_id: ORGANIZATION_ID,
    role: "owner",
    ...overrides
  };
}

function credential(overrides = {}) {
  return {
    id: CREDENTIAL_ID,
    member_id: MEMBER_ID,
    organization_id: ORGANIZATION_ID,
    version: 1,
    label: "MacBook Touch ID",
    transports: ["internal"],
    backup_eligible: false,
    backup_state: false,
    status: "active",
    created_at: CREATED,
    last_used_at: null,
    revoked_at: null,
    public_key: Buffer.from("private-public-key-fixture"),
    ...overrides
  };
}

function session(overrides = {}) {
  return {
    id: CURRENT_SESSION_ID,
    session_id: CURRENT_SESSION_ID,
    member_id: MEMBER_ID,
    organization_id: ORGANIZATION_ID,
    role: "owner",
    version: 1,
    status: "active",
    created_at: CREATED,
    expires_at: EXPIRES,
    last_seen_at: CREATED,
    recent_auth_at: null,
    revoked_at: null,
    token_hash: "token-hash-must-not-escape",
    csrf_token_hash: "csrf-hash-must-not-escape",
    ...overrides
  };
}

function revokedOtherSession(sessionId, overrides = {}) {
  return session({
    id: sessionId,
    session_id: sessionId,
    status: "revoked",
    revoked_at: "2026-08-12T01:00:00.000Z",
    version: 2,
    ...overrides
  });
}

function repository(overrides = {}) {
  const calls = { listCredentials: [], renameCredential: [], revokeCredential: [], listSessions: [], revokeSession: [], revokeOtherSessions: [] };
  const repo = {
    async listCredentials(input) {
      calls.listCredentials.push(input);
      return overrides.listCredentials ?? { items: [credential()], next_cursor: null };
    },
    async renameCredential(input) {
      calls.renameCredential.push(input);
      if (overrides.renameCredential instanceof Error) throw overrides.renameCredential;
      return overrides.renameCredential ?? credential({ label: input.label, version: input.expected_version + 1 });
    },
    async revokeCredential(input) {
      calls.revokeCredential.push(input);
      if (overrides.revokeCredential instanceof Error) throw overrides.revokeCredential;
      return overrides.revokeCredential ?? credential({ status: "revoked", revoked_at: "2026-08-12T01:00:00.000Z", version: input.expected_version + 1 });
    },
    async listSessions(input) {
      calls.listSessions.push(input);
      return overrides.listSessions ?? { items: [session()], next_cursor: null };
    },
    async revokeSession(input) {
      calls.revokeSession.push(input);
      if (overrides.revokeSession instanceof Error) throw overrides.revokeSession;
      return overrides.revokeSession ?? session({ session_id: input.target_session_id, id: input.target_session_id, status: "revoked", revoked_at: "2026-08-12T01:00:00.000Z", version: input.expected_version + 1 });
    },
    async revokeOtherSessions(input) {
      calls.revokeOtherSessions.push(input);
      if (overrides.revokeOtherSessions instanceof Error) throw overrides.revokeOtherSessions;
      return Object.hasOwn(overrides, "revokeOtherSessions") ? overrides.revokeOtherSessions : [revokedOtherSession(OTHER_SESSION_ID)];
    }
  };
  return { repo, calls };
}

function fixture({ repositoryOverrides = {}, sessionOverrides = {}, authError = undefined, recentAuthError = undefined, recentAuthResult = undefined, recentAuthService = undefined } = {}) {
  const calls = { auth: [], recentAuth: [] };
  const { repo, calls: repositoryCalls } = repository(repositoryOverrides);
  const humanSession = {
    expectedOrigin: ORIGIN,
    async authenticateRequest(input) {
      calls.auth.push(input);
      if (authError) throw authError;
      return { session: authenticatedSession(sessionOverrides) };
    }
  };
  const defaultRecentAuthService = {
    async authorize(input) {
      calls.recentAuth.push(input);
      if (recentAuthError) throw recentAuthError;
      if (typeof recentAuthResult === "function") return recentAuthResult(input);
      return recentAuthResult ?? {
        verified: true,
        consumed: true,
        challenge_id: RECENT_AUTHORIZATION_ID,
        member_id: input.principal.member_id,
        organization_id: input.organization_id,
        operation: input.operation,
        authenticated_at: NOW
      };
    }
  };
  const api = createHumanManagementHttpApi({ humanSession, recentAuthService: recentAuthService ?? defaultRecentAuthService, repository: repo, origin: ORIGIN, now: () => NOW });
  return { api, calls: { ...calls, ...repositoryCalls } };
}

function request(path, { method = "GET", body = undefined, headers = {} } = {}) {
  return {
    method,
    url: path,
    headers: {
      origin: ORIGIN,
      cookie: COOKIE,
      "agentpass-csrf": CSRF,
      "agentpass-recent-auth": RECENT_AUTHORIZATION_ID,
      ...(method === "GET" ? {} : { "content-type": "application/json" }),
      ...headers
    },
    ...(body === undefined ? {} : { body })
  };
}

function assertNoStore(result) {
  assert.match(result.headers["Cache-Control"], /no-store/u);
}

test("requires the complete injected repository contract", () => {
  for (const missing of HUMAN_MANAGEMENT_REPOSITORY_METHODS) {
    const partial = Object.fromEntries(HUMAN_MANAGEMENT_REPOSITORY_METHODS.filter((method) => method !== missing).map((method) => [method, () => undefined]));
    assert.throws(() => createHumanManagementHttpApi({
      humanSession: { expectedOrigin: ORIGIN, authenticateRequest: async () => ({ session: authenticatedSession() }) },
      repository: partial,
      origin: ORIGIN
    }), /management repository is missing/u);
  }
});

test("lists credentials with exact session scope and never returns public keys", async () => {
  const { api, calls } = fixture({ repositoryOverrides: { listCredentials: { items: [credential()], next_cursor: "nextCursor" } } });
  const result = await api.handle(request(`${HUMAN_MANAGEMENT_HTTP_PATHS.credentials}?limit=10&cursor=previous`));

  assert.equal(result.status, 200);
  assert.deepEqual(calls.listCredentials[0], {
    session_id: CURRENT_SESSION_ID,
    member_id: MEMBER_ID,
    organization_id: ORGANIZATION_ID,
    limit: 10,
    cursor: "previous"
  });
  assert.deepEqual(result.body, {
    credentials: [{
      credential_id: CREDENTIAL_ID,
      version: 1,
      label: "MacBook Touch ID",
      transports: ["internal"],
      backup_eligible: false,
      backup_state: false,
      status: "active",
      created_at: CREATED,
      last_used_at: null,
      revoked_at: null
    }],
    next_cursor: "nextCursor"
  });
  assert.equal(JSON.stringify(result.body).includes("private-public-key-fixture"), false);
  assertNoStore(result);
});

test("lists sessions only within the authenticated member and organization and strips bearer hashes", async () => {
  const { api, calls } = fixture({ repositoryOverrides: { listSessions: { items: [session()], next_cursor: null } } });
  const result = await api.handle(request(`${HUMAN_MANAGEMENT_HTTP_PATHS.sessions}?limit=1`));

  assert.equal(result.status, 200);
  assert.deepEqual(calls.listSessions[0], {
    session_id: CURRENT_SESSION_ID,
    member_id: MEMBER_ID,
    organization_id: ORGANIZATION_ID,
    limit: 1
  });
  assert.deepEqual(result.body.sessions[0], {
    session_id: CURRENT_SESSION_ID,
    version: 1,
    member_id: MEMBER_ID,
    organization_id: ORGANIZATION_ID,
    role: "owner",
    status: "active",
    is_current: true,
    created_at: CREATED,
    expires_at: EXPIRES,
    last_seen_at: CREATED,
    recent_auth_at: null,
    revoked_at: null
  });
  assert.equal(JSON.stringify(result.body).includes("token-hash-must-not-escape"), false);
  assert.equal(JSON.stringify(result.body).includes("csrf-hash-must-not-escape"), false);
});

test("requires origin, session cookie, and CSRF for every management endpoint", async () => {
  for (const [headers, code, status] of [
    [{ origin: "https://evil.test" }, HUMAN_MANAGEMENT_HTTP_ERROR_CODES.ORIGIN_NOT_ALLOWED, 403],
    [{ cookie: undefined }, HUMAN_MANAGEMENT_HTTP_ERROR_CODES.SESSION_REQUIRED, 401],
    [{ "agentpass-csrf": undefined }, HUMAN_MANAGEMENT_HTTP_ERROR_CODES.CSRF_FAILED, 403],
    [{ "agentpass-csrf": "short" }, HUMAN_MANAGEMENT_HTTP_ERROR_CODES.CSRF_FAILED, 403]
  ]) {
    const { api, calls } = fixture();
    const merged = { ...request(HUMAN_MANAGEMENT_HTTP_PATHS.sessions).headers, ...headers };
    if (Object.hasOwn(headers, "cookie") && headers.cookie === undefined) delete merged.cookie;
    if (Object.hasOwn(headers, "agentpass-csrf") && headers["agentpass-csrf"] === undefined) delete merged["agentpass-csrf"];
    const result = await api.handle({ method: "GET", url: HUMAN_MANAGEMENT_HTTP_PATHS.sessions, headers: merged });
    assert.equal(result.status, status);
    assert.equal(result.body.error.code, code);
    assert.equal(calls.auth.length, 0);
    assertNoStore(result);
  }
});

test("bounds pagination and rejects unknown or duplicated query parameters", async () => {
  for (const suffix of ["?limit=0", "?limit=101", "?limit=01", "?limit=1&limit=2", "?unknown=x", "?cursor=bad%3D"]) {
    const { api, calls } = fixture();
    const result = await api.handle(request(`${HUMAN_MANAGEMENT_HTTP_PATHS.credentials}${suffix}`));
    assert.equal(result.status, 400, suffix);
    assert.equal(result.body.error.code, HUMAN_MANAGEMENT_HTTP_ERROR_CODES.INVALID_PAGINATION, suffix);
    assert.equal(calls.listCredentials.length, 0);
  }
  const { api } = fixture({ repositoryOverrides: { listCredentials: { items: Array.from({ length: 26 }, (_, index) => credential({ id: index === 0 ? CREDENTIAL_ID : `${OTHER_CREDENTIAL_ID.slice(0, -1)}${String(index % 10)}` })) } } });
  const result = await api.handle(request(`${HUMAN_MANAGEMENT_HTTP_PATHS.credentials}?limit=25`));
  assert.equal(result.status, 503);
  assert.equal(result.body.error.code, HUMAN_MANAGEMENT_HTTP_ERROR_CODES.MANAGEMENT_UNAVAILABLE);
});

test("renames a credential with an atomic expected version and rejects caller-supplied scope", async () => {
  const { api, calls } = fixture();
  const result = await api.handle(request(HUMAN_MANAGEMENT_HTTP_PATHS.credential(CREDENTIAL_ID), {
    method: "PATCH",
    body: { label: "Work Mac", expected_version: 7 }
  }));
  assert.equal(result.status, 200);
  assert.deepEqual(calls.renameCredential[0], {
    session_id: CURRENT_SESSION_ID,
    member_id: MEMBER_ID,
    organization_id: ORGANIZATION_ID,
    credential_id: CREDENTIAL_ID,
    label: "Work Mac",
    expected_version: 7
  });
  assert.equal(result.body.credential.label, "Work Mac");
  assert.equal(result.body.credential.version, 8);

  const rejected = await api.handle(request(HUMAN_MANAGEMENT_HTTP_PATHS.credential(CREDENTIAL_ID), {
    method: "PATCH",
    body: { label: "Work Mac", expected_version: 7, member_id: "attacker" }
  }));
  assert.equal(rejected.status, 400);
  assert.equal(calls.renameCredential.length, 1);
});

test("accepts a Fetch Request body without changing the management contract", async () => {
  const { api } = fixture();
  const fetchRequest = new Request(`https://api.agentpass.test${HUMAN_MANAGEMENT_HTTP_PATHS.credential(CREDENTIAL_ID)}`, {
    method: "PATCH",
    headers: {
      Origin: ORIGIN,
      Cookie: COOKIE,
      "agentpass-csrf": CSRF,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({ label: "Fetch Mac", expected_version: 1 })
  });
  const result = await api.handle(fetchRequest);
  assert.equal(result.status, 200);
  assert.equal(result.body.credential.label, "Fetch Mac");
});

test("maps optimistic conflicts and sole-active-credential protection to stable redacted errors", async () => {
  const conflict = new Error("actual version=99 and database password");
  conflict.code = "version_conflict";
  const conflictFixture = fixture({ repositoryOverrides: { renameCredential: conflict } });
  const conflictResult = await conflictFixture.api.handle(request(HUMAN_MANAGEMENT_HTTP_PATHS.credential(CREDENTIAL_ID), { method: "PATCH", body: { label: "x", expected_version: 1 } }));
  assert.equal(conflictResult.status, 409);
  assert.equal(conflictResult.body.error.code, HUMAN_MANAGEMENT_HTTP_ERROR_CODES.VERSION_CONFLICT);
  assert.equal(JSON.stringify(conflictResult.body).includes("database password"), false);

  const sole = new Error("sole credential");
  sole.code = "sole_active_credential";
  const soleFixture = fixture({ repositoryOverrides: { revokeCredential: sole } });
  const soleResult = await soleFixture.api.handle(request(HUMAN_MANAGEMENT_HTTP_PATHS.credentialRevoke(CREDENTIAL_ID), { method: "POST", body: { expected_version: 1 } }));
  assert.equal(soleResult.status, 409);
  assert.equal(soleResult.body.error.code, HUMAN_MANAGEMENT_HTTP_ERROR_CODES.LAST_ACTIVE_CREDENTIAL);
  assert.equal(soleFixture.calls.revokeCredential[0].protect_last_active, true);
});

test("revoking the current session clears only the current session cookie", async () => {
  const current = fixture();
  const currentResult = await current.api.handle(request(HUMAN_MANAGEMENT_HTTP_PATHS.sessionRevoke(CURRENT_SESSION_ID), { method: "POST", body: { expected_version: 1 } }));
  assert.equal(currentResult.status, 200);
  assert.equal(currentResult.headers["Set-Cookie"], "__Host-agentpass_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0");
  assert.equal(current.calls.revokeSession[0].target_session_id, CURRENT_SESSION_ID);
  assert.equal(current.calls.revokeSession[0].expected_version, 1);
  assert.equal(currentResult.body.session.is_current, true);
  assert.equal(current.calls.recentAuth[0].operation, "human.management.session.revoke");
  assert.equal(current.calls.recentAuth[0].principal.member_id, MEMBER_ID);
  assert.equal(current.calls.recentAuth[0].principal.organization_id, ORGANIZATION_ID);

  const other = fixture({ repositoryOverrides: { revokeSession: session({ session_id: OTHER_SESSION_ID, id: OTHER_SESSION_ID, status: "revoked", revoked_at: "2026-08-12T01:00:00.000Z", version: 2 }) } });
  const otherResult = await other.api.handle(request(HUMAN_MANAGEMENT_HTTP_PATHS.sessionRevoke(OTHER_SESSION_ID), { method: "POST", body: { expected_version: 1 } }));
  assert.equal(otherResult.status, 200);
  assert.equal(Object.hasOwn(otherResult.headers, "Set-Cookie"), false);
  assert.equal(otherResult.body.session.is_current, false);
  assert.equal(other.calls.recentAuth.length, 0);
});

test("revokes zero or more other sessions with an exact envelope, current exclusion, and one repository call", async () => {
  const empty = fixture({ repositoryOverrides: { revokeOtherSessions: [] } });
  const emptyResult = await empty.api.handle(request(HUMAN_MANAGEMENT_HTTP_PATHS.revokeOtherSessions, { method: "POST", body: {} }));
  assert.equal(emptyResult.status, 200);
  assert.deepEqual(emptyResult.body, { revoked_sessions: [], revoked_count: 0 });
  assert.equal(empty.calls.revokeOtherSessions.length, 1);
  assert.deepEqual(empty.calls.revokeOtherSessions[0], {
    session_id: CURRENT_SESSION_ID,
    member_id: MEMBER_ID,
    organization_id: ORGANIZATION_ID,
    reason: "human_management"
  });
  assert.equal(empty.calls.recentAuth.length, 1);
  assert.equal(empty.calls.recentAuth[0].operation, "human.management.sessions.revoke_others");

  const other = fixture({ repositoryOverrides: {
    revokeOtherSessions: [
      revokedOtherSession(OTHER_SESSION_ID),
      revokedOtherSession("66666666-6666-4666-8666-666666666666", { role: "admin" })
    ]
  } });
  const result = await other.api.handle(request(HUMAN_MANAGEMENT_HTTP_PATHS.revokeOtherSessions, { method: "POST", body: {} }));
  assert.equal(result.status, 200);
  assert.deepEqual(result.body, {
    revoked_sessions: [
      {
        session_id: OTHER_SESSION_ID,
        version: 2,
        member_id: MEMBER_ID,
        organization_id: ORGANIZATION_ID,
        role: "owner",
        status: "revoked",
        is_current: false,
        created_at: CREATED,
        expires_at: EXPIRES,
        last_seen_at: CREATED,
        recent_auth_at: null,
        revoked_at: "2026-08-12T01:00:00.000Z"
      },
      {
        session_id: "66666666-6666-4666-8666-666666666666",
        version: 2,
        member_id: MEMBER_ID,
        organization_id: ORGANIZATION_ID,
        role: "admin",
        status: "revoked",
        is_current: false,
        created_at: CREATED,
        expires_at: EXPIRES,
        last_seen_at: CREATED,
        recent_auth_at: null,
        revoked_at: "2026-08-12T01:00:00.000Z"
      }
    ],
    revoked_count: 2
  });
  assert.equal(result.body.revoked_sessions.some(({ session_id }) => session_id === CURRENT_SESSION_ID), false);
  assert.equal(other.calls.revokeOtherSessions.length, 1);
  assert.equal(Object.hasOwn(result.headers, "Set-Cookie"), false);
});

test("fails closed for a malformed other-session adapter result and never retries", async () => {
  for (const malformed of [null, {}, [session()], [revokedOtherSession(OTHER_SESSION_ID, { revoked_at: null })], [revokedOtherSession(CURRENT_SESSION_ID)]]) {
    const fixtureValue = fixture({ repositoryOverrides: { revokeOtherSessions: malformed } });
    const result = await fixtureValue.api.handle(request(HUMAN_MANAGEMENT_HTTP_PATHS.revokeOtherSessions, { method: "POST", body: {} }));
    assert.equal(result.status, 503);
    assert.equal(result.body.error.code, HUMAN_MANAGEMENT_HTTP_ERROR_CODES.MANAGEMENT_UNAVAILABLE);
    assert.equal(fixtureValue.calls.revokeOtherSessions.length, 1);
  }
});

test("requires CSRF, operation-bound recent auth, exact empty body, and no mutation query", async () => {
  const missingCsrf = fixture();
  const csrfRequest = request(HUMAN_MANAGEMENT_HTTP_PATHS.revokeOtherSessions, { method: "POST", body: {} });
  delete csrfRequest.headers["agentpass-csrf"];
  const csrfResult = await missingCsrf.api.handle(csrfRequest);
  assert.equal(csrfResult.status, 403);
  assert.equal(csrfResult.body.error.code, HUMAN_MANAGEMENT_HTTP_ERROR_CODES.CSRF_FAILED);
  assert.equal(missingCsrf.calls.revokeOtherSessions.length, 0);

  const missingRecentAuth = fixture();
  const recentRequest = request(HUMAN_MANAGEMENT_HTTP_PATHS.revokeOtherSessions, { method: "POST", body: {} });
  delete recentRequest.headers["agentpass-recent-auth"];
  const recentResult = await missingRecentAuth.api.handle(recentRequest);
  assert.equal(recentResult.status, 401);
  assert.equal(recentResult.body.error.code, HUMAN_MANAGEMENT_HTTP_ERROR_CODES.RECENT_AUTH_REQUIRED);
  assert.equal(missingRecentAuth.calls.revokeOtherSessions.length, 0);

  const wrongOperation = fixture({ recentAuthResult: (input) => ({
    verified: true,
    consumed: true,
    challenge_id: RECENT_AUTHORIZATION_ID,
    member_id: input.principal.member_id,
    organization_id: input.organization_id,
    operation: "human.management.session.revoke",
    authenticated_at: NOW
  }) });
  const wrongResult = await wrongOperation.api.handle(request(HUMAN_MANAGEMENT_HTTP_PATHS.revokeOtherSessions, { method: "POST", body: {} }));
  assert.equal(wrongResult.status, 401);
  assert.equal(wrongResult.body.error.code, HUMAN_MANAGEMENT_HTTP_ERROR_CODES.RECENT_AUTH_FAILED);
  assert.equal(wrongOperation.calls.revokeOtherSessions.length, 0);

  for (const [body, suffix] of [[{ unexpected: true }, "body"], [[], "array"], [null, "null"]]) {
    const malformed = fixture();
    const result = await malformed.api.handle(request(HUMAN_MANAGEMENT_HTTP_PATHS.revokeOtherSessions, { method: "POST", body }));
    assert.equal(result.status, 400, suffix);
    assert.equal(result.body.error.code, HUMAN_MANAGEMENT_HTTP_ERROR_CODES.INVALID_REQUEST, suffix);
    assert.equal(malformed.calls.revokeOtherSessions.length, 0);
  }

  const queried = fixture();
  const queryResult = await queried.api.handle(request(`${HUMAN_MANAGEMENT_HTTP_PATHS.revokeOtherSessions}?unexpected=1`, { method: "POST", body: {} }));
  assert.equal(queryResult.status, 400);
  assert.equal(queryResult.body.error.code, HUMAN_MANAGEMENT_HTTP_ERROR_CODES.INVALID_REQUEST);
  assert.equal(queried.calls.revokeOtherSessions.length, 0);
});

test("fails closed when a session revoke response is not the exact revoked target", async () => {
  const wrongTarget = fixture({
    repositoryOverrides: {
      revokeSession: session({
        session_id: OTHER_SESSION_ID,
        id: OTHER_SESSION_ID,
        status: "revoked",
        revoked_at: "2026-08-12T01:00:00.000Z",
        version: 2
      })
    }
  });
  const wrongTargetResult = await wrongTarget.api.handle(request(HUMAN_MANAGEMENT_HTTP_PATHS.sessionRevoke(CURRENT_SESSION_ID), {
    method: "POST",
    body: { expected_version: 1 }
  }));
  assert.equal(wrongTargetResult.status, 503);
  assert.equal(wrongTargetResult.body.error.code, HUMAN_MANAGEMENT_HTTP_ERROR_CODES.MANAGEMENT_UNAVAILABLE);
  assert.equal(Object.hasOwn(wrongTargetResult.headers, "Set-Cookie"), false);

  const stillActive = fixture({
    repositoryOverrides: {
      revokeSession: session({ status: "active", revoked_at: null })
    }
  });
  const stillActiveResult = await stillActive.api.handle(request(HUMAN_MANAGEMENT_HTTP_PATHS.sessionRevoke(CURRENT_SESSION_ID), {
    method: "POST",
    body: { expected_version: 1 }
  }));
  assert.equal(stillActiveResult.status, 503);
  assert.equal(stillActiveResult.body.error.code, HUMAN_MANAGEMENT_HTTP_ERROR_CODES.MANAGEMENT_UNAVAILABLE);
  assert.equal(Object.hasOwn(stillActiveResult.headers, "Set-Cookie"), false);
});

test("requires exact single-use recent auth for credential and current-session revocation", async () => {
  for (const path of [
    HUMAN_MANAGEMENT_HTTP_PATHS.credentialRevoke(CREDENTIAL_ID),
    HUMAN_MANAGEMENT_HTTP_PATHS.sessionRevoke(CURRENT_SESSION_ID)
  ]) {
    const missing = fixture();
    const missingRequest = request(path, { method: "POST", body: { expected_version: 1 } });
    delete missingRequest.headers["agentpass-recent-auth"];
    const missingResult = await missing.api.handle(missingRequest);
    assert.equal(missingResult.status, 401);
    assert.equal(missingResult.body.error.code, HUMAN_MANAGEMENT_HTTP_ERROR_CODES.RECENT_AUTH_REQUIRED);
    assert.equal(missing.calls.revokeCredential.length + missing.calls.revokeSession.length, 0);

    const wrong = fixture({ recentAuthResult: (input) => ({
      verified: true,
      consumed: true,
      challenge_id: RECENT_AUTHORIZATION_ID,
      member_id: input.principal.member_id,
      organization_id: input.organization_id,
      operation: "wrong.operation",
      authenticated_at: NOW
    }) });
    const wrongResult = await wrong.api.handle(request(path, { method: "POST", body: { expected_version: 1 } }));
    assert.equal(wrongResult.status, 401);
    assert.equal(wrongResult.body.error.code, HUMAN_MANAGEMENT_HTTP_ERROR_CODES.RECENT_AUTH_FAILED);
    assert.equal(wrong.calls.revokeCredential.length + wrong.calls.revokeSession.length, 0);
  }

  let consumed = false;
  const replay = fixture({ recentAuthResult: (input) => {
    if (consumed) return {
      verified: false,
      consumed: false,
      challenge_id: RECENT_AUTHORIZATION_ID,
      member_id: input.principal.member_id,
      organization_id: input.organization_id,
      operation: input.operation,
      authenticated_at: NOW
    };
    consumed = true;
    return {
      verified: true,
      consumed: true,
      challenge_id: RECENT_AUTHORIZATION_ID,
      member_id: input.principal.member_id,
      organization_id: input.organization_id,
      operation: input.operation,
      authenticated_at: NOW
    };
  } });
  const first = await replay.api.handle(request(HUMAN_MANAGEMENT_HTTP_PATHS.credentialRevoke(CREDENTIAL_ID), { method: "POST", body: { expected_version: 1 } }));
  assert.equal(first.status, 200);
  const second = await replay.api.handle(request(HUMAN_MANAGEMENT_HTTP_PATHS.credentialRevoke(CREDENTIAL_ID), { method: "POST", body: { expected_version: 1 } }));
  assert.equal(second.status, 401);
  assert.equal(second.body.error.code, HUMAN_MANAGEMENT_HTTP_ERROR_CODES.RECENT_AUTH_FAILED);
  assert.equal(replay.calls.revokeCredential.length, 1);
});

test("fails closed when repository output crosses tenant bindings or is malformed", async () => {
  const wrongBinding = fixture({ repositoryOverrides: { listCredentials: { items: [credential({ member_id: "55555555-5555-4555-8555-555555555555" })] } } });
  const wrongResult = await wrongBinding.api.handle(request(HUMAN_MANAGEMENT_HTTP_PATHS.credentials));
  assert.equal(wrongResult.status, 503);
  assert.equal(wrongResult.body.error.code, HUMAN_MANAGEMENT_HTTP_ERROR_CODES.MANAGEMENT_UNAVAILABLE);

  const malformed = fixture({ repositoryOverrides: { listSessions: { items: [session({ version: 0 })] } } });
  const malformedResult = await malformed.api.handle(request(HUMAN_MANAGEMENT_HTTP_PATHS.sessions));
  assert.equal(malformedResult.status, 503);
  assert.equal(JSON.stringify(malformedResult.body).includes("version"), false);
});

test("rejects mutation bodies without content type, expected version, or exact fields", async () => {
  const { api, calls } = fixture();
  for (const body of [{ label: "x" }, { expected_version: 1 }, { label: "x", expected_version: 1.5 }, { label: "x", expected_version: 1, extra: true }]) {
    const result = await api.handle(request(HUMAN_MANAGEMENT_HTTP_PATHS.credential(CREDENTIAL_ID), { method: "PATCH", body }));
    assert.equal(result.status, 400);
  }
  const noContentType = await api.handle({
    method: "PATCH",
    url: HUMAN_MANAGEMENT_HTTP_PATHS.credential(CREDENTIAL_ID),
    headers: { origin: ORIGIN, cookie: COOKIE, "agentpass-csrf": CSRF },
    body: { label: "x", expected_version: 1 }
  });
  assert.equal(noContentType.status, 400);
  assert.equal(calls.renameCredential.length, 0);
});

test("maps session authentication failures without exposing causes", async () => {
  const error = new Error("session token hash=super-secret");
  error.code = "session_not_found";
  const { api } = fixture({ authError: error });
  const result = await api.handle(request(HUMAN_MANAGEMENT_HTTP_PATHS.sessions));
  assert.equal(result.status, 401);
  assert.equal(result.body.error.code, HUMAN_MANAGEMENT_HTTP_ERROR_CODES.SESSION_REQUIRED);
  assert.equal(JSON.stringify(result.body).includes("super-secret"), false);
});
