import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import { canonicalJson } from "../../../../packages/protocol/src/index.mjs";
import {
  HUMAN_SESSION_CSRF_HEADER
} from "../../src/human-session.mjs";
import {
  OWNER_RECOVERY_DEAD_LETTER_HTTP_ERROR_CODES as HCODE,
  OWNER_RECOVERY_DEAD_LETTER_HTTP_PATHS as PATHS,
  OWNER_RECOVERY_DEAD_LETTER_OPERATIONS as OPERATIONS,
  createOwnerRecoveryDeadLetterHttpApi,
  ownerRecoveryDeadLetterContextHash
} from "../../src/human-auth/recovery/dead-letter-http-api.mjs";

const ORG = "11111111-1111-4111-8111-111111111111";
const OTHER_ORG = "77777777-7777-4777-8777-777777777777";
const MEMBER = "22222222-2222-4222-8222-222222222222";
const SESSION = "33333333-3333-4333-8333-333333333333";
const EVENT = "44444444-4444-4444-8444-444444444444";
const REQUEST = "55555555-5555-4555-8555-555555555555";
const SUBJECT = "66666666-6666-4666-8666-666666666666";
const PROOF = "99999999-9999-4999-8999-999999999999";
const ORIGIN = "https://console.agentpass.test";
const SESSION_TOKEN = Buffer.alloc(32, 0x11).toString("base64url");
const CSRF_TOKEN = Buffer.alloc(32, 0x22).toString("base64url");
const NOW = Date.parse("2026-08-14T00:00:00.000Z");

test("lists dead letters after exact origin, session+CSRF, tenant and role checks", async () => {
  const calls = [];
  const fixture = createFixture({ calls });
  const result = await fixture.api.handle({
    method: "GET",
    url: `${PATHS.list(ORG)}?limit=2&cursor=opaque_cursor`,
    headers: fixture.headers()
  });

  assert.equal(result.status, 200);
  assert.equal(result.body.dead_letters.length, 1);
  assert.equal(result.body.dead_letters[0].organization_id, ORG);
  assert.deepEqual(calls.map((call) => call[0]), ["session", "limiter", "list"]);
  assert.equal(calls[1][1].operation, OPERATIONS.list);
  assert.equal(calls[2][1].limit, 2);
  assert.equal(calls[2][1].cursor, "opaque_cursor");
  assert.equal(calls[0][1].method, "POST", "GET still uses the CSRF-enforcing session lane");
});

test("requires the exact origin and a CSRF token on GET", async () => {
  const fixture = createFixture();
  const wrongOrigin = await fixture.api.handle({
    method: "GET",
    url: PATHS.list(ORG),
    headers: fixture.headers({ origin: `${ORIGIN}/` })
  });
  assert.equal(wrongOrigin.status, 403);
  assert.equal(wrongOrigin.body.error.code, HCODE.ORIGIN_NOT_ALLOWED);
  assert.equal(fixture.calls.length, 0);

  const missingCsrf = await fixture.api.handle({
    method: "GET",
    url: PATHS.list(ORG),
    headers: fixture.headers({ [HUMAN_SESSION_CSRF_HEADER]: undefined })
  });
  assert.equal(missingCsrf.status, 403);
  assert.equal(missingCsrf.body.error.code, HCODE.CSRF_FAILED);
  assert.equal(fixture.calls.length, 0);
});

test("returns 404 for a tenant mismatch before touching the limiter", async () => {
  const fixture = createFixture({ organizationId: OTHER_ORG });
  const result = await fixture.api.handle({
    method: "GET",
    url: PATHS.list(ORG),
    headers: fixture.headers()
  });
  assert.equal(result.status, 404);
  assert.equal(result.body.error.code, "not_found");
  assert.deepEqual(fixture.calls.map((call) => call[0]), ["session"]);
});

test("allows owner and admin but rejects viewer and auditor before the limiter", async () => {
  for (const role of ["owner", "admin"]) {
    const fixture = createFixture({ role });
    const result = await fixture.api.handle({ method: "GET", url: PATHS.list(ORG), headers: fixture.headers() });
    assert.equal(result.status, 200, role);
  }
  for (const role of ["viewer", "auditor"]) {
    const fixture = createFixture({ role });
    const result = await fixture.api.handle({ method: "GET", url: PATHS.list(ORG), headers: fixture.headers() });
    assert.equal(result.status, 403, role);
    assert.equal(result.body.error.code, HCODE.FORBIDDEN);
    assert.deepEqual(fixture.calls.map((call) => call[0]), ["session"]);
  }
});

test("rejects unknown and duplicate list query parameters", async () => {
  for (const suffix of ["?unknown=1", "?limit=2&limit=3", "?cursor=not%20opaque"]) {
    const fixture = createFixture();
    const result = await fixture.api.handle({ method: "GET", url: `${PATHS.list(ORG)}${suffix}`, headers: fixture.headers() });
    assert.equal(result.status, 400, suffix);
    assert.ok([HCODE.INVALID_PAGINATION, HCODE.INVALID_CURSOR].includes(result.body.error.code));
    assert.deepEqual(fixture.calls.map((call) => call[0]), ["session"]);
  }
});

test("binds recent WebAuthn to the dead-letter context hash and passes only validated data onward", async () => {
  const fixture = createFixture();
  const result = await fixture.api.handle({
    method: "POST",
    url: PATHS.suppress(ORG, EVENT),
    headers: fixture.headers({
      "content-type": "application/json",
      "if-match": '"4"',
      "idempotency-key": "suppress-dead-letter-1",
      "agentpass-recent-auth": PROOF
    }),
    body: { reason: "operator-confirmed-noise" }
  });
  assert.equal(result.status, 200);
  const expectedHash = ownerRecoveryDeadLetterContextHash({ organization_id: ORG, event_id: EVENT, action: "suppress", expected_management_version: 4 });
  assert.equal(fixture.calls[2][1].context_hash, expectedHash);
  assert.equal(fixture.calls[2][1].operation, OPERATIONS.suppress);
  assert.deepEqual(fixture.calls[3][1].recent_authorization, {
    session_id: SESSION,
    challenge_id: PROOF,
    operation: OPERATIONS.suppress,
    authenticated_at: NOW,
    context_hash: expectedHash
  });
  assert.equal(Object.hasOwn(fixture.calls[3][1], "proof"), false);
  assert.equal(Object.hasOwn(fixture.calls[3][1], "csrf_token"), false);
  assert.equal(result.body.dead_letter.status, "suppressed");
  assert.equal(Object.hasOwn(result.body.dead_letter, "provider_payload"), false);
});

test("uses the exact canonical context hash preimage", () => {
  const expected = crypto.createHash("sha256").update(canonicalJson({
    version: 1,
    organization_id: ORG,
    event_id: EVENT,
    action: "redrive",
    expected_management_version: 4
  }), "utf8").digest("hex");
  assert.equal(ownerRecoveryDeadLetterContextHash({ organization_id: ORG, event_id: EVENT, action: "redrive", expected_management_version: 4 }), expected);
});

test("lists and manages uncertain deliveries with distinct bounded operations", async () => {
  const fixture = createFixture();
  const listed = await fixture.api.handle({ method: "GET", url: PATHS.listUncertain(ORG), headers: fixture.headers() });
  assert.equal(listed.status, 200);
  assert.equal(listed.body.uncertain_deliveries[0].status, "uncertain");
  assert.equal(fixture.calls.at(-2)[1].operation, OPERATIONS.listUncertain);

  const retried = await fixture.api.handle({
    method: "POST",
    url: PATHS.retryUncertain(ORG, EVENT),
    headers: fixture.headers({ "content-type": "application/json", "if-match": '"4"', "idempotency-key": "retry-uncertain-event-1", "agentpass-recent-auth": PROOF }),
    body: {}
  });
  assert.equal(retried.status, 200);
  assert.equal(retried.body.uncertain_delivery.status, "pending");
  const retryCall = fixture.calls.find((call) => call[0] === "retryUncertain");
  assert.equal(retryCall[1].recent_authorization.operation, OPERATIONS.retryUncertain);
  assert.equal(retryCall[1].context_hash, ownerRecoveryDeadLetterContextHash({ organization_id: ORG, event_id: EVENT, action: "retry_uncertain", expected_management_version: 4 }));

  const suppressed = await fixture.api.handle({
    method: "POST",
    url: PATHS.suppressUncertain(ORG, EVENT),
    headers: fixture.headers({ "content-type": "application/json", "if-match": '"4"', "idempotency-key": "suppress-uncertain-1", "agentpass-recent-auth": PROOF }),
    body: { reason: "operator-quarantine" }
  });
  assert.equal(suppressed.status, 200);
  assert.equal(suppressed.body.uncertain_delivery.status, "suppressed");
  assert.equal(fixture.calls.find((call) => call[0] === "suppressUncertain")[1].reason, "operator-quarantine");
});

test("requires strict mutation headers and bodies", async () => {
  const missing = createFixture();
  const missingHeaders = await missing.api.handle({
    method: "POST",
    url: PATHS.redrive(ORG, EVENT),
    headers: missing.headers({ "content-type": "application/json" }),
    body: {}
  });
  assert.equal(missingHeaders.status, 400);
  assert.equal(missingHeaders.body.error.code, HCODE.INVALID_REQUEST);

  const extraBody = createFixture();
  const extra = await extraBody.api.handle({
    method: "POST",
    url: PATHS.redrive(ORG, EVENT),
    headers: extraBody.headers({ "content-type": "application/json", "if-match": '"4"', "idempotency-key": "redrive-dead-letter-1", "agentpass-recent-auth": PROOF }),
    body: { unexpected: true }
  });
  assert.equal(extra.status, 400);
  assert.equal(extra.body.error.code, HCODE.INVALID_REQUEST);

  const unknownHeader = createFixture();
  const unknown = await unknownHeader.api.handle({
    method: "GET",
    url: PATHS.list(ORG),
    headers: unknownHeader.headers({ authorization: "Bearer secret" })
  });
  assert.equal(unknown.status, 400);
  assert.equal(unknown.body.error.code, HCODE.INVALID_REQUEST);
});

test("rejects a recent-auth result that is stale, mismatched, or not consumed", async () => {
  for (const authorization of [
    { verified: false, consumed: true },
    { verified: true, consumed: false },
    { verified: true, consumed: true, context_hash: "0".repeat(64) },
    { verified: true, consumed: true, authenticated_at: NOW - 6 * 60 * 1000 }
  ]) {
    const fixture = createFixture({ authorization });
    const result = await fixture.api.handle({
      method: "POST",
      url: PATHS.redrive(ORG, EVENT),
      headers: fixture.headers({ "content-type": "application/json", "if-match": '"4"', "idempotency-key": "redrive-dead-letter-1", "agentpass-recent-auth": PROOF }),
      body: {}
    });
    assert.equal(result.status, 401);
    assert.equal(result.body.error.code, HCODE.RECENT_AUTH_FAILED);
    assert.equal(fixture.calls.some((call) => call[0] === "redrive"), false);
  }
});

test("maps provider, SQL, and repository diagnostics to stable secret-free errors", async () => {
  const fixture = createFixture({ repositoryError: Object.assign(new Error("postgres password=super-secret"), { code: "owner_recovery_outbox_management_unavailable" }) });
  const result = await fixture.api.handle({ method: "GET", url: PATHS.list(ORG), headers: fixture.headers() });
  assert.equal(result.status, 503);
  assert.equal(result.body.error.code, HCODE.UNAVAILABLE);
  assert.doesNotMatch(JSON.stringify(result.body), /super-secret|postgres/iu);
});

test("maps repository CAS, idempotency, and in-progress errors without exposing internals", async () => {
  for (const [repositoryCode, expectedStatus, expectedCode] of [
    ["owner_recovery_outbox_management_version_conflict", 409, HCODE.VERSION_CONFLICT],
    ["owner_recovery_outbox_management_idempotency_conflict", 409, HCODE.IDEMPOTENCY_CONFLICT],
    ["owner_recovery_outbox_management_idempotency_in_progress", 409, HCODE.MUTATION_IN_PROGRESS]
  ]) {
    const fixture = createFixture({ repositoryError: { code: repositoryCode, message: "secret diagnostic" } });
    const result = await fixture.api.handle({
      method: "POST",
      url: PATHS.redrive(ORG, EVENT),
      headers: fixture.headers({ "content-type": "application/json", "if-match": '"4"', "idempotency-key": "redrive-dead-letter-1", "agentpass-recent-auth": PROOF }),
      body: {}
    });
    assert.equal(result.status, expectedStatus);
    assert.equal(result.body.error.code, expectedCode);
    assert.doesNotMatch(JSON.stringify(result.body), /secret diagnostic/u);
  }
});

test("returns method and mutation-query errors with safe response headers", async () => {
  const fixture = createFixture();
  const method = await fixture.api.handle({ method: "PATCH", url: PATHS.list(ORG), headers: fixture.headers() });
  assert.equal(method.status, 405);
  assert.equal(method.headers.Allow, "GET");

  const query = createFixture();
  const result = await query.api.handle({
    method: "POST",
    url: `${PATHS.redrive(ORG, EVENT)}?limit=1`,
    headers: query.headers({ "content-type": "application/json", "if-match": '"4"', "idempotency-key": "redrive-dead-letter-1", "agentpass-recent-auth": PROOF }),
    body: {}
  });
  assert.equal(result.status, 400);
  assert.equal(result.body.error.code, HCODE.INVALID_REQUEST);
  assert.equal(result.headers["Cache-Control"], "no-store, max-age=0");
  assert.equal(result.headers["X-Content-Type-Options"], "nosniff");
});

function createFixture({ role = "admin", organizationId = ORG, authorization = undefined, repositoryError = undefined, calls = [] } = {}) {
  const actor = Object.freeze({ session_id: SESSION, member_id: MEMBER, organization_id: organizationId, role });
  const fixture = { calls };
  const repository = {
    async listDeadLetters(input) {
      calls.push(["list", input]);
      if (repositoryError) throw repositoryError;
      return { items: [deadLetter()], next_cursor: null };
    },
    async redriveDeadLetter(input) {
      calls.push(["redrive", input]);
      if (repositoryError) throw repositoryError;
      return mutation("pending", input.event_id);
    },
    async suppressDeadLetter(input) {
      calls.push(["suppress", input]);
      if (repositoryError) throw repositoryError;
      return mutation("suppressed", input.event_id);
    },
    async listUncertain(input) {
      calls.push(["listUncertain", input]);
      if (repositoryError) throw repositoryError;
      return { items: [uncertainDelivery()], next_cursor: null };
    },
    async retryUncertain(input) {
      calls.push(["retryUncertain", input]);
      if (repositoryError) throw repositoryError;
      return mutation("pending", input.event_id);
    },
    async suppressUncertain(input) {
      calls.push(["suppressUncertain", input]);
      if (repositoryError) throw repositoryError;
      return mutation("suppressed", input.event_id);
    }
  };
  const humanSession = {
    async authenticateRequest(input) {
      calls.push(["session", input]);
      return { session: actor };
    }
  };
  const recentAuthService = {
    async authorize(input) {
      calls.push(["recent", input]);
      if (authorization !== undefined) return { ...validAuthorization(input), ...authorization };
      return validAuthorization(input);
    }
  };
  const abuseControls = {
    async authorize(input) { calls.push(["limiter", input]); }
  };
  fixture.api = createOwnerRecoveryDeadLetterHttpApi({ humanSession, recentAuthService, repository, abuseControls, origin: ORIGIN, now: () => NOW });
  fixture.headers = (overrides = {}) => {
    const headers = {
      origin: ORIGIN,
      cookie: `__Host-agentpass_session=${SESSION_TOKEN}`,
      [HUMAN_SESSION_CSRF_HEADER]: CSRF_TOKEN,
      ...overrides
    };
    for (const key of Object.keys(headers)) if (headers[key] === undefined) delete headers[key];
    return headers;
  };
  return fixture;
}

function validAuthorization(input) {
  return {
    verified: true,
    consumed: true,
    challenge_id: input.proof,
    member_id: MEMBER,
    organization_id: ORG,
    operation: input.operation,
    authenticated_at: NOW,
    context_hash: input.context_hash
  };
}

function deadLetter() {
  return {
    organization_id: ORG,
    event_id: EVENT,
    request_id: REQUEST,
    subject_member_id: SUBJECT,
    event_type: "recovery.request.created",
    status: "dead_letter",
    attempts: 100,
    total_attempts: 100,
    management_version: 4,
    redrive_count: 0,
    last_error_code: "publisher_unavailable",
    created_at: "2026-08-14T00:00:00.000Z",
    updated_at: "2026-08-14T00:00:01.000Z",
    suppressed_at: null,
    suppression_reason: null,
    provider_payload: "must not escape",
    claim_token: "must not escape"
  };
}

function mutation(status, eventId) {
  return {
    organization_id: ORG,
    event_id: eventId,
    status,
    attempts: status === "pending" ? 0 : 100,
    total_attempts: 100,
    management_version: 5,
    redrive_count: 1,
    suppressed_at: status === "suppressed" ? "2026-08-14T00:00:02.000Z" : null,
    suppression_reason: status === "suppressed" ? "operator-confirmed-noise" : null,
    provider_response: "must not escape"
  };
}

function uncertainDelivery() {
  return {
    ...deadLetter(),
    status: "uncertain",
    attempts: 0,
    last_error_code: "delivery_uncertain",
    uncertain_at: "2026-08-14T00:00:01.000Z",
    uncertain_reason: "legacy_unbound"
  };
}
