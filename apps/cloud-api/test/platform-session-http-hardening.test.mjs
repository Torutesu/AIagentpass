import test from "node:test";
import assert from "node:assert/strict";

import {
  createPlatformSessionHttpApi,
  PLATFORM_SESSION_HTTP_ERROR_CODES,
  PLATFORM_SESSION_HTTP_PATHS
} from "../src/platform-session-http-api.mjs";
import {
  PLATFORM_SESSION_COOKIE_NAME,
  PLATFORM_SESSION_CSRF_HEADER,
  hashPlatformSessionToken
} from "../src/platform-session-transport.mjs";
import { HUMAN_SESSION_COOKIE_NAME } from "../src/human-session.mjs";
import { platformPromotionAuthorizationRequestDigest } from "../src/platform-promotion-http-contract.mjs";

const ORIGIN = "https://console.agentpass.test";
const IDS = Object.freeze({
  principal: "11111111-1111-4111-8111-111111111111",
  member: "22222222-2222-4222-8222-222222222222",
  organization: "33333333-3333-4333-8333-333333333333",
  assignment: "44444444-4444-4444-8444-444444444444",
  challenge: "55555555-5555-4555-8555-555555555555",
  session: "66666666-6666-4666-8666-666666666666",
  jti: "77777777-7777-4777-8777-777777777777",
  promotion: "88888888-8888-4888-8888-888888888888"
});
const CREDENTIAL_ID = Buffer.alloc(32, 7).toString("base64url");
const BEARER = Buffer.alloc(32, 1).toString("base64url");
const OTHER_BEARER = Buffer.alloc(32, 4).toString("base64url");
const CSRF = Buffer.alloc(32, 2).toString("base64url");
const HUMAN_TOKEN = Buffer.alloc(32, 9).toString("base64url");
const INTENT = Object.freeze({
  operation: "platform.promotion.issue",
  organization_id: IDS.organization,
  promotion_id: IDS.promotion,
  deployment_id: "production-api",
  environment: "production",
  candidate_id: `release-pkg-sha256-v1-${"a".repeat(64)}`
});
const IDEMPOTENCY_KEY = "platform-intent-1";
const REQUEST_DIGEST = platformPromotionAuthorizationRequestDigest({
  promotion_id: INTENT.promotion_id,
  deployment_id: INTENT.deployment_id,
  environment: INTENT.environment,
  candidate_id: INTENT.candidate_id,
  idempotency_key: IDEMPOTENCY_KEY
}, { organizationId: IDS.organization });
const AUTHORITY = Object.freeze({
  principal_id: IDS.principal,
  member_id: IDS.member,
  organization_id: IDS.organization,
  assignment_id: IDS.assignment,
  authority_generation: 4,
  operation: INTENT.operation,
  capability: INTENT.operation,
  rp_id: "console.agentpass.test",
  origin: ORIGIN,
  request_digest_sha256: REQUEST_DIGEST,
  allowed_credential_ids: [CREDENTIAL_ID],
  user_verification: "required"
});
const ASSERTION = Object.freeze({
  version: 1,
  type: "agentpass.platform-session-assertion",
  challenge_id: IDS.challenge,
  jti: IDS.jti,
  credential_id: CREDENTIAL_ID,
  client_data_json: Buffer.from("client-data").toString("base64url"),
  authenticator_data: Buffer.from("authenticator-data").toString("base64url"),
  signature: Buffer.from("signature").toString("base64url")
});

function jsonRequest(path, body, headers = {}) {
  return {
    method: "POST",
    url: path,
    headers: { Origin: ORIGIN, "Content-Type": "application/json", ...headers },
    body: JSON.stringify(body)
  };
}

function challengeRequest(headers = {}) {
  return jsonRequest(PLATFORM_SESSION_HTTP_PATHS.challenge, INTENT, {
    Cookie: `${HUMAN_SESSION_COOKIE_NAME}=${HUMAN_TOKEN}`,
    "Idempotency-Key": IDEMPOTENCY_KEY,
    ...headers
  });
}

function assertionRequest(headers = {}) {
  return jsonRequest(PLATFORM_SESSION_HTTP_PATHS.assertion, ASSERTION, headers);
}

function revokeRequest(headers = {}) {
  return {
    method: "POST",
    url: PLATFORM_SESSION_HTTP_PATHS.revoke,
    headers: {
      Origin: ORIGIN,
      Cookie: `${PLATFORM_SESSION_COOKIE_NAME}=${BEARER}`,
      [PLATFORM_SESSION_CSRF_HEADER]: CSRF,
      ...headers
    },
    body: ""
  };
}

function fixture() {
  const calls = { bootstrap: [], authority: [], begin: [], verify: [], revoke: [] };
  const api = createPlatformSessionHttpApi({
    webauthnService: {
      async begin(input) {
        calls.begin.push(input);
        return {
          version: 1,
          type: "agentpass.platform-session-challenge",
          challenge_id: IDS.challenge,
          challenge: Buffer.alloc(32, 3).toString("base64url"),
          jti: IDS.jti,
          platform_session_id: IDS.session,
          ...AUTHORITY,
          issued_at: "2026-08-15T00:00:00.000Z",
          expires_at: "2026-08-15T00:02:00.000Z",
          one_use: true
        };
      },
      async verify(input) {
        calls.verify.push(input);
        return {
          session: {
            session_id: IDS.session,
            principal_id: IDS.principal,
            member_id: IDS.member,
            organization_id: IDS.organization,
            assignment_id: IDS.assignment,
            credential_id: "internal-credential-id",
            operation: INTENT.operation,
            capability: INTENT.operation,
            principal_authority_generation: AUTHORITY.authority_generation,
            request_digest_sha256: REQUEST_DIGEST,
            authenticated_at: "2026-08-15T00:00:00.000Z",
            created_at: "2026-08-15T00:00:00.000Z",
            expires_at: "2026-08-15T00:15:00.000Z",
            status: "active"
          },
          session_bearer: BEARER,
          csrf_token: CSRF,
          authenticated_at: "2026-08-15T00:00:00.000Z"
        };
      }
    },
    authenticateBootstrap: async (input) => {
      calls.bootstrap.push(input);
      return { user_id: IDS.member };
    },
    resolveAuthorityContext: async (input) => {
      calls.authority.push(input);
      return AUTHORITY;
    },
    revokeService: {
      bearerBound: true,
      acceptsSessionMaterialHash: true,
      async revokeSelf(input) {
        calls.revoke.push(input);
        return { revoked: true };
      }
    },
    rateLimiter: { async acquire() { return { allowed: true }; } },
    origin: ORIGIN
  });
  return { api, calls };
}

function assertInvalidRequest(result) {
  assert.equal(result.status, 400);
  assert.equal(result.body.error.code, PLATFORM_SESSION_HTTP_ERROR_CODES.INVALID_REQUEST);
}

function assertNoSensitiveResponseKeys(value, { allowCredentialIds = false } = {}) {
  const forbidden = new Set([
    "principal_id", "assignment_id", "authority_generation", "principal_authority_generation",
    "request_digest_sha256"
  ]);
  if (!allowCredentialIds) {
    for (const key of ["credential_id", "allowed_credential_ids", "credential_ids", "allowedCredentialIds", "credentialId"]) forbidden.add(key);
  }
  const seen = [];
  function walk(current, path = "body") {
    if (!current || typeof current !== "object") return;
    for (const [key, child] of Object.entries(current)) {
      if (forbidden.has(key)) seen.push(`${path}.${key}`);
      walk(child, `${path}.${key}`);
    }
  }
  walk(value);
  assert.deepEqual(seen, [], `sensitive response keys exposed: ${seen.join(", ")}`);
  const serialized = JSON.stringify(value);
  const secrets = [IDS.principal, IDS.assignment, REQUEST_DIGEST, ...(allowCredentialIds ? [] : [CREDENTIAL_ID])];
  for (const secret of secrets) {
    assert.equal(serialized.includes(secret), false, `sensitive response value exposed: ${secret}`);
  }
}

test("a valid Platform cookie is forbidden on challenge, including alongside a Human cookie", async () => {
  const { api, calls } = fixture();
  const standalone = await api.handle(challengeRequest({ Cookie: `${PLATFORM_SESSION_COOKIE_NAME}=${BEARER}` }));
  assertInvalidRequest(standalone);
  const mixed = await api.handle(challengeRequest({
    Cookie: `${HUMAN_SESSION_COOKIE_NAME}=${HUMAN_TOKEN}; ${PLATFORM_SESSION_COOKIE_NAME}=${BEARER}`
  }));
  assertInvalidRequest(mixed);
  assert.equal(calls.bootstrap.length, 0);
  assert.equal(calls.begin.length, 0);
});

test("a valid Platform cookie is forbidden on assertion before WebAuthn verification", async () => {
  const { api, calls } = fixture();
  const standalone = await api.handle(assertionRequest({ Cookie: `${PLATFORM_SESSION_COOKIE_NAME}=${BEARER}` }));
  assertInvalidRequest(standalone);
  const mixed = await api.handle(assertionRequest({
    Cookie: `${HUMAN_SESSION_COOKIE_NAME}=${HUMAN_TOKEN}; ${PLATFORM_SESSION_COOKIE_NAME}=${BEARER}`
  }));
  assertInvalidRequest(mixed);
  assert.equal(calls.verify.length, 0);
  assert.equal(calls.authority.length, 0);
});

test("challenge accepts a Human cookie and assertion accepts no cookie", async () => {
  const challengeFixture = fixture();
  const challenge = await challengeFixture.api.handle(challengeRequest());
  assert.equal(challenge.status, 201);
  assert.equal(challengeFixture.calls.bootstrap.length, 1);
  assert.equal(challengeFixture.calls.begin.length, 1);

  const assertionFixture = fixture();
  const assertion = await assertionFixture.api.handle(assertionRequest());
  assert.equal(assertion.status, 201);
  assert.equal(assertionFixture.calls.verify.length, 1);
  assert.equal(assertionFixture.calls.authority[0].session_material_hash, null);
});

test("revoke requires only a valid Platform cookie and Platform CSRF", async () => {
  const { api, calls } = fixture();
  const result = await api.handle(revokeRequest());
  assert.equal(result.status, 200);
  assert.deepEqual(calls.revoke[0], {
    session_material_hash: hashPlatformSessionToken(BEARER),
    csrf_token: CSRF
  });

  const humanOnly = await api.handle(revokeRequest({ Cookie: `${HUMAN_SESSION_COOKIE_NAME}=${HUMAN_TOKEN}` }));
  assert.equal(humanOnly.status, 401);
  const missingCsrf = await api.handle({
    ...revokeRequest(),
    headers: { Origin: ORIGIN, Cookie: `${PLATFORM_SESSION_COOKIE_NAME}=${BEARER}` }
  });
  assert.equal(missingCsrf.status, 403);
});

test("challenge exposes only WebAuthn credential selectors while assertion hides authority and credential identifiers", async () => {
  const challengeFixture = fixture();
  const challenge = await challengeFixture.api.handle(challengeRequest());
  assert.equal(challenge.status, 201);
  // WebAuthn allowCredentials is required by the browser ceremony and is not
  // session authority. It is permitted only on this one-use challenge.
  assertNoSensitiveResponseKeys(challenge.body, { allowCredentialIds: true });
  assert.deepEqual(challenge.body.allowed_credential_ids, [CREDENTIAL_ID]);

  const assertionFixture = fixture();
  const assertion = await assertionFixture.api.handle(assertionRequest());
  assert.equal(assertion.status, 201);
  assertNoSensitiveResponseKeys(assertion.body);
});

test("duplicate or ambiguous Platform cookies fail closed before any service is called", async () => {
  const cases = [
    ["challenge", (api) => api.handle(challengeRequest({
      Cookie: `${PLATFORM_SESSION_COOKIE_NAME}=${BEARER}; ${PLATFORM_SESSION_COOKIE_NAME}=${BEARER}`
    }))],
    ["assertion", (api) => api.handle(assertionRequest({
      Cookie: `${PLATFORM_SESSION_COOKIE_NAME}=${BEARER}; ${PLATFORM_SESSION_COOKIE_NAME}=${OTHER_BEARER}`
    }))],
    ["revoke", (api) => api.handle(revokeRequest({
      Cookie: `${PLATFORM_SESSION_COOKIE_NAME}=${BEARER}; ${PLATFORM_SESSION_COOKIE_NAME}=${OTHER_BEARER}`
    }))]
  ];
  for (const [route, run] of cases) {
    const { api, calls } = fixture();
    const result = await run(api);
    assertInvalidRequest(result);
    assert.equal(calls.bootstrap.length, 0, `${route} called bootstrap`);
    assert.equal(calls.begin.length, 0, `${route} called begin`);
    assert.equal(calls.verify.length, 0, `${route} called verify`);
    assert.equal(calls.revoke.length, 0, `${route} called revoke`);
  }
});
