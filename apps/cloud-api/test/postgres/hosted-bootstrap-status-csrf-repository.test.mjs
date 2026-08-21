import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import {
  HOSTED_IDENTITY_BOOTSTRAP_REPOSITORY_ERROR_CODES as CODES,
  HOSTED_IDENTITY_BOOTSTRAP_REPOSITORY_SQL as SQL,
  createPostgresHostedIdentityBootstrapRepository
} from "../../src/postgres/hosted-identity-bootstrap-repository.mjs";

const COOKIE = "bootstrap-cookie-that-never-reaches-postgresql";
const CSRF = "C".repeat(43);
const EXPIRES_AT = "2026-08-15T00:15:00.000Z";

function digest(value) {
  return crypto.createHash("sha256").update(value, "utf8").digest();
}

function fixture(handler) {
  const calls = [];
  const repository = createPostgresHostedIdentityBootstrapRepository({
    client: {
      async query(text, params) {
        calls.push({ text, params });
        return handler(text, params);
      }
    }
  });
  return { calls, repository };
}

test("status atomically binds only cookie and CSRF digests to the 0064 function", async () => {
  const row = {
    state: "organization_required",
    organization_count: "0",
    webauthn_required: false,
    can_create_first_organization: true,
    expires_at: new Date(EXPIRES_AT)
  };
  const { calls, repository } = fixture((text) => {
    assert.equal(text, SQL.getBootstrapStatus);
    return { rows: [row], rowCount: 1 };
  });

  const result = await repository.getBootstrapStatus({ bootstrap_cookie: COOKIE, csrf_token: CSRF });

  assert.deepEqual(result, { ...row, organization_count: 0, expires_at: EXPIRES_AT });
  assert.deepEqual(calls, [{
    text: "SELECT * FROM public.agentpass_hosted_identity_bootstrap_status_v2($1::bytea,$2::bytea)",
    params: [digest(COOKIE), digest(CSRF)]
  }]);
  assert.equal(calls[0].params.includes(COOKIE), false);
  assert.equal(calls[0].params.includes(CSRF), false);
});

test("status preserves an absent authority result and rejects contradictory DB output", async () => {
  const absent = fixture(() => ({ rows: [], rowCount: 0 }));
  assert.equal(await absent.repository.getBootstrapStatus({ bootstrap_cookie: COOKIE, csrf_token: CSRF }), null);

  for (const row of [
    { state: "organization_required", organization_count: 1, webauthn_required: false, can_create_first_organization: true, expires_at: EXPIRES_AT },
    { state: "webauthn_required", organization_count: 1, webauthn_required: false, can_create_first_organization: false, expires_at: EXPIRES_AT },
    { state: "oauth_started", organization_count: 0, webauthn_required: false, can_create_first_organization: false, expires_at: EXPIRES_AT },
    { state: "ready", organization_count: -1, webauthn_required: false, can_create_first_organization: false, expires_at: EXPIRES_AT },
    { state: "ready", organization_count: 1, webauthn_required: false, can_create_first_organization: false, expires_at: "invalid" },
    { state: "ready", organization_count: 1, webauthn_required: false, can_create_first_organization: false, expires_at: EXPIRES_AT, selector: "leak" }
  ]) {
    const invalid = fixture(() => ({ rows: [row], rowCount: 1 }));
    await assert.rejects(
      invalid.repository.getBootstrapStatus({ bootstrap_cookie: COOKIE, csrf_token: CSRF }),
      (error) => error.code === CODES.RESULT
    );
  }
});

test("CSRF verification uses the exact function, hashes authority, and requires boolean output", async () => {
  const accepted = fixture((text) => {
    assert.equal(text, SQL.verifyBootstrapCsrf);
    return { rows: [{ result: true }], rowCount: 1 };
  });
  assert.equal(await accepted.repository.verifyBootstrapCsrf({ bootstrap_cookie: COOKIE, csrf_token: CSRF }), true);
  assert.deepEqual(accepted.calls[0].params, [digest(COOKIE), digest(CSRF)]);

  const denied = fixture(() => ({ rows: [{ result: false }], rowCount: 1 }));
  assert.equal(await denied.repository.verifyBootstrapCsrf({ bootstrap_cookie: COOKIE, csrf_token: CSRF }), false);

  const malformed = fixture(() => ({ rows: [{ result: "true" }], rowCount: 1 }));
  await assert.rejects(
    malformed.repository.verifyBootstrapCsrf({ bootstrap_cookie: COOKIE, csrf_token: CSRF }),
    (error) => error.code === CODES.RESULT
  );
});

test("status and CSRF verification keep closed input and stable storage errors", async () => {
  const input = fixture(() => ({ rows: [], rowCount: 0 }));
  await assert.rejects(
    input.repository.getBootstrapStatus({ bootstrap_cookie: COOKIE, csrf_token: CSRF, extra: true }),
    (error) => error.code === CODES.INPUT
  );
  assert.equal(input.calls.length, 0);

  const unavailable = fixture(() => {
    const error = new Error(`database leaked ${COOKIE} ${CSRF}`);
    error.code = "XX000";
    throw error;
  });
  await assert.rejects(
    unavailable.repository.verifyBootstrapCsrf({ bootstrap_cookie: COOKIE, csrf_token: CSRF }),
    (error) => error.code === CODES.DATABASE
      && !error.message.includes(COOKIE)
      && !error.message.includes(CSRF)
  );
});
