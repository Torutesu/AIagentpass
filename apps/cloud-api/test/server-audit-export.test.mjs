import assert from "node:assert/strict";
import crypto from "node:crypto";
import http from "node:http";
import test from "node:test";

import { createCloudApi } from "../src/server.mjs";
import { canonicalJson } from "../../../packages/protocol/src/index.mjs";

const ORIGIN = "https://console.agentpass.test";
const ORGANIZATION_ID = "11111111-1111-4111-8111-111111111111";
const OTHER_ORGANIZATION_ID = "99999999-9999-4999-8999-999999999999";
const EXPORT_ID = "22222222-2222-4222-8222-222222222222";
const SESSION_ID = "33333333-3333-4333-8333-333333333333";
const MEMBER_ID = "44444444-4444-4444-8444-444444444444";
const RECENT_AUTH_ID = "55555555-5555-4555-8555-555555555555";
const NOW = Date.parse("2026-08-15T00:00:00.000Z");
const CSRF = "c".repeat(43);
const SESSION_TOKEN = "s".repeat(43);
const IDEMPOTENCY_KEY = "audit-export-create-0001";
const CONTEXT = Object.freeze({
  version: 1,
  organization_id: ORGANIZATION_ID,
  export_id: EXPORT_ID,
  environment: "production",
  chain: "admin"
});
const CONTEXT_HASH = sha256(canonicalJson(CONTEXT));
const CREATE_PATH = `/v1/organizations/${ORGANIZATION_ID}/audit/exports`;
const GET_PATH = `${CREATE_PATH}/${EXPORT_ID}?environment=production&chain=admin`;

const PUBLIC_RESULT = Object.freeze({
  organization_id: ORGANIZATION_ID,
  export_id: EXPORT_ID,
  environment: "production",
  chain: "admin",
  range: Object.freeze({
    from_audit_position: 1,
    to_audit_position: 1,
    previous_root_digest: "0".repeat(64),
    root_digest: "a".repeat(64),
    record_count: 1
  }),
  payload_digest: "b".repeat(64),
  payload: Object.freeze({
    version: 1,
    type: "agentpass.audit-export",
    organization_id: ORGANIZATION_ID,
    environment: "production",
    chain: "admin",
    range: Object.freeze({
      from_audit_position: 1,
      to_audit_position: 1,
      previous_root_digest: "0".repeat(64),
      root_digest: "a".repeat(64),
      record_count: 1
    }),
    entries: Object.freeze([])
  }),
  audit_anchor: Object.freeze({
    statement: Object.freeze({
      version: 1,
      type: "agentpass.audit-anchor",
      organization_id: ORGANIZATION_ID,
      environment: "production",
      chain: "admin",
      export_id: EXPORT_ID,
      audit_position: 1,
      previous_audit_position: 0,
      root_digest: "a".repeat(64),
      previous_root_digest: "0".repeat(64),
      export_digest: "b".repeat(64),
      record_count: 1
    }),
    signature: "S".repeat(86),
    signer_key_fingerprint: "f".repeat(64)
  }),
  validity: "active"
});
const SERVICE_RESULT = Object.freeze({ ...PUBLIC_RESULT, replayed: false });

function sha256(value) {
  return crypto.createHash("sha256").update(value, "utf8").digest("hex");
}

function actor(role = "admin", organizationId = ORGANIZATION_ID) {
  return { session_id: SESSION_ID, member_id: MEMBER_ID, organization_id: organizationId, role };
}

function headers(overrides = {}) {
  return Object.fromEntries(Object.entries({
    origin: ORIGIN,
    cookie: `__Host-agentpass_session=${SESSION_TOKEN}`,
    "agentpass-csrf": CSRF,
    "agentpass-recent-auth": RECENT_AUTH_ID,
    "content-type": "application/json",
    "idempotency-key": IDEMPOTENCY_KEY,
    ...overrides
  }).filter(([, value]) => value !== undefined));
}

function createFixture({ role = "admin", organizationId = ORGANIZATION_ID, serviceResult = SERVICE_RESULT, serviceError = undefined } = {}) {
  const calls = { auth: [], recentAuth: [], issue: [], retrieve: [] };
  const auditExportIssuanceService = {
    async issueAuditExport(input) {
      calls.issue.push(input);
      if (serviceError) throw serviceError;
      return structuredClone(serviceResult);
    },
    async retrieveAuditExport(input) {
      calls.retrieve.push(input);
      if (serviceError) throw serviceError;
      return structuredClone(serviceResult);
    }
  };
  const humanSession = {
    expectedOrigin: ORIGIN,
    async authenticateRequest(input) {
      calls.auth.push(input);
      if (input.headers.origin !== ORIGIN) throw Object.assign(new Error("origin denied"), { code: "invalid_origin" });
      if (input.headers["agentpass-csrf"] !== CSRF) throw Object.assign(new Error("csrf denied"), { code: "csrf_token_required" });
      if (!input.headers.cookie?.startsWith("__Host-agentpass_session=")) throw Object.assign(new Error("session denied"), { code: "session_not_found" });
      return { session: actor(role, organizationId) };
    }
  };
  const recentAuthService = {
    async authorize(input) {
      calls.recentAuth.push(input);
      if (input.context_hash !== CONTEXT_HASH) throw Object.assign(new Error("context mismatch"), { code: "recent_auth_failed" });
      return {
        verified: true,
        consumed: true,
        challenge_id: RECENT_AUTH_ID,
        member_id: MEMBER_ID,
        organization_id: ORGANIZATION_ID,
        operation: input.operation,
        authenticated_at: NOW,
        context_hash: CONTEXT_HASH
      };
    }
  };
  const server = createCloudApi({
    store: {},
    humanSession,
    recentAuthService,
    auditExportIssuanceService,
    now: () => NOW
  });
  return { server, calls };
}

async function startFixture(t, options = {}) {
  const fixture = createFixture(options);
  await new Promise((resolve, reject) => {
    fixture.server.once("error", reject);
    fixture.server.listen(0, "127.0.0.1", () => {
      fixture.server.off("error", reject);
      resolve();
    });
  });
  t.after(() => new Promise((resolve) => fixture.server.close(resolve)));
  return { ...fixture, base: `http://127.0.0.1:${fixture.server.address().port}` };
}

async function request(base, path, { method = "GET", requestHeaders = headers(), body = undefined } = {}) {
  const response = await fetch(`${base}${path}`, {
    method,
    headers: requestHeaders,
    ...(body === undefined ? {} : { body: JSON.stringify(body) })
  });
  const text = await response.text();
  return { response, body: text ? JSON.parse(text) : null };
}

function assertNoStore(response) {
  assert.match(response.headers.get("cache-control") ?? "", /no-store/u);
}

function assertSecretFree(value) {
  const encoded = JSON.stringify(value);
  for (const secret of ["claim_token", "private_key", "provider_diagnostics", "signing_bytes", "raw_signature", "password"]) {
    assert.equal(encoded.includes(secret), false, secret);
  }
}

test("creates an audit export through the injected service with strict owner/admin BFF authorization", async (t) => {
  for (const role of ["owner", "admin"]) {
    const fixture = await startFixture(t, { role });
    const result = await request(fixture.base, CREATE_PATH, {
      method: "POST",
      body: { export_id: EXPORT_ID, environment: "production", chain: "admin" }
    });

    assert.equal(result.response.status, 201, role);
    assertNoStore(result.response);
    assert.deepEqual(Object.keys(result.body).sort(), ["audit_export", "request_id"]);
    assert.deepEqual(result.body.audit_export, PUBLIC_RESULT);
    assertSecretFree(result.body);
    assert.equal(fixture.calls.issue.length, 1);
    assert.deepEqual(fixture.calls.issue[0], {
      organization_id: ORGANIZATION_ID,
      export_id: EXPORT_ID,
      environment: "production",
      chain: "admin",
      idempotency_key: IDEMPOTENCY_KEY
    });
    assert.equal(fixture.calls.recentAuth[0].operation, "audit.export.create");
    assert.equal(fixture.calls.recentAuth[0].context_hash, CONTEXT_HASH);
  }
});

test("retrieves an audit export for owner/admin/auditor without a body or Idempotency-Key", async (t) => {
  for (const role of ["owner", "admin", "auditor"]) {
    const fixture = await startFixture(t, { role });
    const result = await request(fixture.base, GET_PATH, {
      method: "GET",
      requestHeaders: headers({ "content-type": undefined, "idempotency-key": undefined })
    });

    assert.equal(result.response.status, 200, role);
    assertNoStore(result.response);
    assert.deepEqual(Object.keys(result.body).sort(), ["audit_export", "request_id"]);
    assert.deepEqual(result.body.audit_export, PUBLIC_RESULT);
    assertSecretFree(result.body);
    assert.equal(fixture.calls.issue.length, 0);
    assert.equal(fixture.calls.retrieve.length, 1);
    assert.deepEqual(fixture.calls.retrieve[0], {
      organization_id: ORGANIZATION_ID,
      export_id: EXPORT_ID,
      environment: "production",
      chain: "admin"
    });
    assert.equal(fixture.calls.recentAuth[0].operation, "audit.export.retrieve");
    assert.equal(fixture.calls.recentAuth[0].context_hash, CONTEXT_HASH);
  }
});

test("denies viewers and does not invoke recent auth or issuance", async (t) => {
  const create = await startFixture(t, { role: "viewer" });
  const createResult = await request(create.base, CREATE_PATH, {
    method: "POST",
    body: { export_id: EXPORT_ID, environment: "production", chain: "admin" }
  });
  assert.equal(createResult.response.status, 403);
  assert.equal(create.calls.recentAuth.length, 0);
  assert.equal(create.calls.issue.length, 0);

  const get = await startFixture(t, { role: "viewer" });
  const getResult = await request(get.base, GET_PATH, {
    requestHeaders: headers({ "content-type": undefined, "idempotency-key": undefined })
  });
  assert.equal(getResult.response.status, 403);
  assert.equal(get.calls.recentAuth.length, 0);
  assert.equal(get.calls.retrieve.length, 0);
});

test("requires same-origin session CSRF, recent WebAuthn, and create idempotency", async (t) => {
  for (const [requestHeaders, status] of [
    [headers({ origin: "https://evil.example" }), 403],
    [headers({ "agentpass-csrf": undefined }), 403],
    [headers({ "agentpass-recent-auth": undefined }), 401],
    [headers({ "idempotency-key": undefined }), 400]
  ]) {
    const fixture = await startFixture(t);
    const result = await request(fixture.base, CREATE_PATH, {
      method: "POST",
      requestHeaders,
      body: { export_id: EXPORT_ID, environment: "production", chain: "admin" }
    });
    assert.equal(result.response.status, status);
    assertNoStore(result.response);
    assert.equal(fixture.calls.issue.length, 0);
  }
});

test("enforces exact create body and GET transport shape before service invocation", async (t) => {
  for (const body of [
    { export_id: EXPORT_ID, environment: "production", chain: "admin", unexpected: true },
    { export_id: EXPORT_ID, environment: "production" },
    { export_id: EXPORT_ID, environment: "development", chain: "admin" },
    { export_id: "not-a-uuid", environment: "production", chain: "admin" }
  ]) {
    const fixture = await startFixture(t);
    const result = await request(fixture.base, CREATE_PATH, { method: "POST", body });
    assert.equal(result.response.status, 400, JSON.stringify(body));
    assert.equal(fixture.calls.issue.length, 0);
    assert.equal(fixture.calls.recentAuth.length, 0);
  }

  const fixture = await startFixture(t);
  const result = await request(fixture.base, GET_PATH, {
    requestHeaders: headers({ "content-type": undefined, "idempotency-key": "forbidden-on-get" })
  });
  assert.equal(result.response.status, 400);
  assert.equal(fixture.calls.retrieve.length, 0);
  assert.equal(fixture.calls.recentAuth.length, 0);
});

test("hides absent, reserved, uncertain, and wrong-tenant retrieval states as one opaque 404", async (t) => {
  for (const code of ["not_found", "in_progress", "uncertain", "organization_mismatch"]) {
    const fixture = await startFixture(t, { serviceError: Object.assign(new Error(`internal ${code} secret`), { code }) });
    const result = await request(fixture.base, GET_PATH, {
      requestHeaders: headers({ "content-type": undefined, "idempotency-key": undefined })
    });
    assert.equal(result.response.status, 404, code);
    assert.equal(result.body.error.code, "not_found", code);
    assert.equal(/reserved|uncertain|tenant|organization|secret/iu.test(JSON.stringify(result.body)), false, code);
    assertNoStore(result.response);
  }

  const crossTenant = await startFixture(t, { organizationId: OTHER_ORGANIZATION_ID });
  const crossTenantResult = await request(crossTenant.base, `${CREATE_PATH}/${EXPORT_ID}?environment=production&chain=admin`, {
    requestHeaders: headers({ "content-type": undefined, "idempotency-key": undefined })
  });
  assert.equal(crossTenantResult.response.status, 404);
  assert.equal(crossTenant.calls.retrieve.length, 0);
});

test("rejects injected secret-bearing public results without exposing them", async (t) => {
  const fixture = await startFixture(t, {
    serviceResult: {
      ...SERVICE_RESULT,
      claim_token: "clear-claim-token",
      provider_diagnostics: "provider secret",
      signing_bytes: "raw bytes",
      private_key: "-----BEGIN PRIVATE KEY-----"
    }
  });
  const result = await request(fixture.base, CREATE_PATH, {
    method: "POST",
    body: { export_id: EXPORT_ID, environment: "production", chain: "admin" }
  });
  assert.equal(result.response.status, 503);
  assertSecretFree(result.body);
  assertNoStore(result.response);
  assert.equal(fixture.calls.issue.length, 1);
});
