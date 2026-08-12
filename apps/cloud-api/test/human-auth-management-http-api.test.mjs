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
const CREATED = "2026-08-12T00:00:00.000Z";
const EXPIRES = "2026-08-12T08:00:00.000Z";

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

function repository(overrides = {}) {
  const calls = { listCredentials: [], renameCredential: [], revokeCredential: [], listSessions: [], revokeSession: [] };
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
    }
  };
  return { repo, calls };
}

function fixture({ repositoryOverrides = {}, sessionOverrides = {}, authError = undefined } = {}) {
  const calls = { auth: [] };
  const { repo, calls: repositoryCalls } = repository(repositoryOverrides);
  const humanSession = {
    expectedOrigin: ORIGIN,
    async authenticateRequest(input) {
      calls.auth.push(input);
      if (authError) throw authError;
      return { session: authenticatedSession(sessionOverrides) };
    }
  };
  const api = createHumanManagementHttpApi({ humanSession, repository: repo, origin: ORIGIN });
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

  const other = fixture({ repositoryOverrides: { revokeSession: session({ session_id: OTHER_SESSION_ID, id: OTHER_SESSION_ID, status: "revoked", revoked_at: "2026-08-12T01:00:00.000Z", version: 2 }) } });
  const otherResult = await other.api.handle(request(HUMAN_MANAGEMENT_HTTP_PATHS.sessionRevoke(OTHER_SESSION_ID), { method: "POST", body: { expected_version: 1 } }));
  assert.equal(otherResult.status, 200);
  assert.equal(Object.hasOwn(otherResult.headers, "Set-Cookie"), false);
  assert.equal(otherResult.body.session.is_current, false);
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
