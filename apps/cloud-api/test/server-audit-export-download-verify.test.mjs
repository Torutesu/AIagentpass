import assert from "node:assert/strict";
import crypto from "node:crypto";
import http from "node:http";
import nodeTest from "node:test";

import { canonicalJson } from "../../../packages/protocol/src/index.mjs";
import { AUDIT_ANCHOR_ZERO_DIGEST } from "../src/audit-anchor-statement.mjs";
import { createCloudApi } from "../src/server.mjs";
import { foldAuditExportRoot } from "../src/postgres/audit-export-snapshot-reader.mjs";
import { createLoopbackAwareTest } from "./support/loopback-test.mjs";

const test = createLoopbackAwareTest(nodeTest);

const ORIGIN = "https://console.agentpass.test";
const ORGANIZATION_ID = "11111111-1111-4111-8111-111111111111";
const OTHER_ORGANIZATION_ID = "99999999-9999-4999-8999-999999999999";
const EXPORT_ID = "22222222-2222-4222-8222-222222222222";
const OTHER_EXPORT_ID = "88888888-8888-4888-8888-888888888888";
const SESSION_ID = "33333333-3333-4333-8333-333333333333";
const MEMBER_ID = "44444444-4444-4444-8444-444444444444";
const RECENT_AUTH_ID = "55555555-5555-4555-8555-555555555555";
const NOW = Date.parse("2026-08-15T00:00:00.000Z");
const CSRF = "c".repeat(43);
const SESSION_TOKEN = "s".repeat(43);
const CREATE_IDEMPOTENCY_KEY = "audit-export-create-0001";
const CONTEXT = Object.freeze({
  version: 1,
  organization_id: ORGANIZATION_ID,
  export_id: EXPORT_ID,
  environment: "production",
  chain: "admin"
});
const CONTEXT_HASH = sha256(canonicalJson(CONTEXT));
const EXPORT_PATH = `/v1/organizations/${ORGANIZATION_ID}/audit/exports/${EXPORT_ID}`;
const DOWNLOAD_PATH = `${EXPORT_PATH}/download?environment=production&chain=admin`;
const VERIFY_PATH = `/v1/organizations/${ORGANIZATION_ID}/audit/exports/verify`;
const DOWNLOAD_FILENAME = "agentpass-audit-export.json";

const ENTRY = {
  version: 1,
  organization_id: ORGANIZATION_ID,
  environment: "production",
  chain: "admin",
  export_position: 1,
  source_id: "66666666-6666-4666-8666-666666666666",
  source_device_id: null,
  source_previous_hash: AUDIT_ANCHOR_ZERO_DIGEST,
  source_hash: "a".repeat(64),
  source_gap: null,
  event: {
    version: 1,
    audit_event_id: "66666666-6666-4666-8666-666666666666",
    organization_id: ORGANIZATION_ID,
    actor_id: MEMBER_ID,
    action: "member.role.changed",
    target_type: "member",
    target_id: "77777777-7777-4777-8777-777777777777",
    details: { from: "viewer", to: "auditor" },
    previous_hash: AUDIT_ANCHOR_ZERO_DIGEST,
    sequence: 1
  }
};
const ROOT_DIGEST = foldAuditExportRoot(AUDIT_ANCHOR_ZERO_DIGEST, ENTRY);
const RANGE = Object.freeze({
  from_audit_position: 1,
  to_audit_position: 1,
  previous_root_digest: AUDIT_ANCHOR_ZERO_DIGEST,
  root_digest: ROOT_DIGEST,
  record_count: 1
});
const PAYLOAD = Object.freeze({
  version: 1,
  type: "agentpass.audit-export",
  organization_id: ORGANIZATION_ID,
  environment: "production",
  chain: "admin",
  range: RANGE,
  entries: Object.freeze([ENTRY])
});
const PAYLOAD_DIGEST = sha256(canonicalJson(PAYLOAD));
const ANCHOR_STATEMENT = Object.freeze({
  version: 1,
  type: "agentpass.audit-anchor",
  organization_id: ORGANIZATION_ID,
  environment: "production",
  chain: "admin",
  export_id: EXPORT_ID,
  audit_position: 1,
  previous_audit_position: 0,
  root_digest: ROOT_DIGEST,
  previous_root_digest: AUDIT_ANCHOR_ZERO_DIGEST,
  export_digest: PAYLOAD_DIGEST,
  record_count: 1,
  purpose: "agentpass.audit-anchor",
  protocol_version: 1,
  signing_version: 1,
  lifecycle_version: 1,
  key_id: "audit-anchor-2026",
  key_version: 1,
  issued_at: "2026-08-15T00:00:00.000Z",
  expires_at: "2026-08-15T01:00:00.000Z"
});
const AUDIT_ANCHOR = Object.freeze({
  version: 1,
  type: "agentpass.audit-anchor",
  statement: ANCHOR_STATEMENT,
  statement_hash: sha256(canonicalJson(ANCHOR_STATEMENT)),
  signature_algorithm: "ed25519",
  signer_key_fingerprint: `SHA256:${"f".repeat(43)}`,
  signature: "S".repeat(86)
});
const SERVICE_RESULT = Object.freeze({
  organization_id: ORGANIZATION_ID,
  export_id: EXPORT_ID,
  environment: "production",
  chain: "admin",
  range: RANGE,
  payload_digest: PAYLOAD_DIGEST,
  payload: PAYLOAD,
  audit_anchor: AUDIT_ANCHOR,
  replayed: true,
  validity: "active"
});
const PUBLIC_EXPORT = Object.freeze(((value) => {
  const { replayed: _replayed, ...publicExport } = value;
  return publicExport;
})(SERVICE_RESULT));
const PUBLIC_EXPORT_BYTES = Buffer.from(canonicalJson(PUBLIC_EXPORT), "utf8");
const VERIFY_RESULT = Object.freeze({
  payload_digest: true,
  root: true,
  anchor: true,
  historical_key: true,
  valid: true,
  reason: "valid"
});

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
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
    "idempotency-key": CREATE_IDEMPOTENCY_KEY,
    ...overrides
  }).filter(([, value]) => value !== undefined));
}

function getHeaders(overrides = {}) {
  return headers({ "agentpass-csrf": undefined, "content-type": undefined, "idempotency-key": undefined, ...overrides });
}

function createFixture({ role = "admin", organizationId = ORGANIZATION_ID, serviceResult = SERVICE_RESULT, serviceError = undefined, verifierResult = VERIFY_RESULT, verifierError = undefined } = {}) {
  const calls = { auth: [], recentAuth: [], issue: [], retrieve: [], verify: [], audit: [] };
  const auditExportIssuanceService = {
    async issueAuditExport(input) {
      calls.issue.push(input);
      return structuredClone(serviceResult);
    },
    async retrieveAuditExport(input) {
      calls.retrieve.push(input);
      if (serviceError) throw serviceError;
      return structuredClone(serviceResult);
    }
  };
  const auditExportVerifier = {
    async verifyAuditExport(input) {
      calls.verify.push(input);
      if (verifierError) throw verifierError;
      return structuredClone(verifierResult);
    }
  };
  const humanSession = {
    expectedOrigin: ORIGIN,
    async authenticateRequest(input) {
      calls.auth.push(input);
      if (input.headers.origin !== ORIGIN) throw Object.assign(new Error("origin denied"), { code: "invalid_origin" });
      if (input.method === "POST" && input.headers["agentpass-csrf"] !== CSRF) {
        throw Object.assign(new Error("csrf denied"), { code: "csrf_token_required" });
      }
      if (!input.headers.cookie?.startsWith("__Host-agentpass_session=")) {
        throw Object.assign(new Error("session denied"), { code: "session_not_found" });
      }
      return { session: actor(role, organizationId) };
    }
  };
  const recentAuthService = {
    async authorize(input) {
      calls.recentAuth.push(input);
      if (!input.proof) throw Object.assign(new Error("recent auth required"), { code: "recent_auth_failed" });
      if (input.context_hash !== CONTEXT_HASH) throw Object.assign(new Error("context mismatch"), { code: "recent_auth_failed" });
      return {
        verified: true,
        consumed: true,
        challenge_id: RECENT_AUTH_ID,
        context_hash: CONTEXT_HASH,
        member_id: MEMBER_ID,
        organization_id: ORGANIZATION_ID,
        operation: input.operation,
        authenticated_at: NOW
      };
    }
  };
  const server = createCloudApi({
    store: { async appendAdminAuditEvent(input) { calls.audit.push(structuredClone(input)); return {}; } },
    humanSession,
    recentAuthService,
    auditExportIssuanceService,
    auditExportVerifier,
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
  return new Promise((resolve, reject) => {
    const requestUrl = new URL(`${base}${path}`);
    const bodyBytes = body === undefined ? undefined : Buffer.from(JSON.stringify(body), "utf8");
    const requestOptions = {
      method,
      headers: bodyBytes === undefined
        ? requestHeaders
        : { ...requestHeaders, "content-length": String(bodyBytes.length) }
    };
    const client = http.request(requestUrl, requestOptions, (response) => {
      const chunks = [];
      response.on("data", (chunk) => chunks.push(chunk));
      response.on("end", () => {
        const bytes = Buffer.concat(chunks);
        let parsed = null;
        try { parsed = bytes.length === 0 ? null : JSON.parse(bytes.toString("utf8")); } catch { /* Download bytes are intentionally not parsed here. */ }
        resolve({ response, body: parsed, bytes });
      });
    });
    client.on("error", reject);
    if (bodyBytes !== undefined) client.write(bodyBytes);
    client.end();
  });
}

function assertNoStoreNoSniff(response) {
  assert.match(response.headers["cache-control"] ?? "", /no-store/u);
  assert.equal(response.headers["x-content-type-options"], "nosniff");
}

function assertSecretFree(value) {
  const encoded = JSON.stringify(value);
  for (const secret of ["claim_token", "private_key", "provider_diagnostics", "signing_bytes", "raw_signature", "password"]) {
    assert.equal(encoded.includes(secret), false, secret);
  }
}

function assertRetrieveCall(call) {
  assert.deepEqual(Object.keys(call).sort(), ["chain", "environment", "export_id", "organization_id"]);
  assert.deepEqual(call, {
    organization_id: ORGANIZATION_ID,
    export_id: EXPORT_ID,
    environment: "production",
    chain: "admin"
  });
}

function assertVerifyCall(call) {
  assert.deepEqual(Object.keys(call).sort(), Object.keys(PUBLIC_EXPORT).sort());
  assert.deepEqual(call, PUBLIC_EXPORT);
  assert.equal("actor" in call, false);
  assert.equal("recent_authorization" in call, false);
}

test("downloads canonical immutable audit bytes for owner/admin/auditor with strict retrieve input", async (t) => {
  for (const role of ["owner", "admin", "auditor"]) {
    const fixture = await startFixture(t, { role });
    const result = await request(fixture.base, DOWNLOAD_PATH, { requestHeaders: getHeaders() });

    assert.equal(result.response.statusCode, 200, role);
    assert.deepEqual(result.bytes, PUBLIC_EXPORT_BYTES);
    assert.equal(result.response.headers["content-type"], "application/json");
    assert.equal(result.response.headers["content-disposition"], `attachment; filename="${DOWNLOAD_FILENAME}"`);
    assertNoStoreNoSniff(result.response);
    assert.equal(fixture.calls.issue.length, 0);
    assert.equal(fixture.calls.retrieve.length, 1);
    assertRetrieveCall(fixture.calls.retrieve[0]);
    assert.equal(fixture.calls.recentAuth[0].operation, "audit.export.download");
    assert.equal(fixture.calls.recentAuth[0].context_hash, CONTEXT_HASH);
    assert.equal(fixture.calls.audit[0].eventType, "audit.export.download.succeeded");
    assert.equal(fixture.calls.audit[0].targetId, EXPORT_ID);
    assertSecretFree(result.bytes.toString("utf8"));
  }
});

test("verifies an immutable audit export for owner/admin/auditor with strict result and verifier input", async (t) => {
  for (const role of ["owner", "admin", "auditor"]) {
    const fixture = await startFixture(t, { role });
    const result = await request(fixture.base, VERIFY_PATH, {
      method: "POST",
      requestHeaders: headers({ "idempotency-key": undefined }),
      body: PUBLIC_EXPORT
    });

    assert.equal(result.response.statusCode, 200, role);
    assert.deepEqual(Object.keys(result.body).sort(), Object.keys(VERIFY_RESULT).sort());
    assert.deepEqual(result.body, VERIFY_RESULT);
    assertSecretFree(result.body);
    assertNoStoreNoSniff(result.response);
    assert.equal(fixture.calls.issue.length, 0);
    assert.equal(fixture.calls.retrieve.length, 0);
    assert.equal(fixture.calls.verify.length, 1);
    assertVerifyCall(fixture.calls.verify[0]);
    assert.equal(fixture.calls.recentAuth[0].operation, "audit.export.verify");
    assert.equal(fixture.calls.recentAuth[0].context_hash, CONTEXT_HASH);
    assert.equal(fixture.calls.audit[0].eventType, "audit.export.verify.succeeded");
    assert.equal(fixture.calls.audit[0].details.valid, true);
  }
});

test("audits create and retrieval success without recording authorization material", async (t) => {
  const createdFixture = await startFixture(t);
  const created = await request(createdFixture.base, `/v1/organizations/${ORGANIZATION_ID}/audit/exports`, {
    method: "POST",
    requestHeaders: headers(),
    body: { export_id: EXPORT_ID, environment: "production", chain: "admin" }
  });
  assert.equal(created.response.statusCode, 201);
  assert.equal(createdFixture.calls.audit[0].eventType, "audit.export.create.succeeded");
  assert.equal(JSON.stringify(createdFixture.calls.audit[0]).includes(RECENT_AUTH_ID), false);
  assert.equal(JSON.stringify(createdFixture.calls.audit[0]).includes(CSRF), false);

  const retrievedFixture = await startFixture(t, { role: "auditor" });
  const retrieved = await request(retrievedFixture.base, `${EXPORT_PATH}?environment=production&chain=admin`, { requestHeaders: getHeaders() });
  assert.equal(retrieved.response.statusCode, 200);
  assert.equal(retrievedFixture.calls.audit[0].eventType, "audit.export.retrieve.succeeded");
  assert.equal(retrievedFixture.calls.audit[0].details.payload_digest, PAYLOAD_DIGEST);
});

test("denies viewers and hides wrong-tenant download/verify resources", async (t) => {
  for (const [path, options] of [
    [DOWNLOAD_PATH, { requestHeaders: getHeaders() }],
    [VERIFY_PATH, { method: "POST", requestHeaders: headers({ "idempotency-key": undefined }), body: PUBLIC_EXPORT }]
  ]) {
    const viewer = await startFixture(t, { role: "viewer" });
    const denied = await request(viewer.base, path, options);
    assert.equal(denied.response.statusCode, 403, path);
    assert.equal(viewer.calls.recentAuth.length, 0);
    assert.equal(viewer.calls.retrieve.length, 0);
    assert.equal(viewer.calls.verify.length, 0);
    assert.equal(viewer.calls.audit[0].eventType, path.includes("download") ? "audit.export.download.denied" : "audit.export.verify.denied");
  }

  for (const [path, options] of [
    [DOWNLOAD_PATH, { requestHeaders: getHeaders() }],
    [VERIFY_PATH, { method: "POST", requestHeaders: headers({ "idempotency-key": undefined }), body: PUBLIC_EXPORT }]
  ]) {
    const wrongTenant = await startFixture(t, { organizationId: OTHER_ORGANIZATION_ID });
    const hidden = await request(wrongTenant.base, path, options);
    assert.equal(hidden.response.statusCode, 404, path);
    assert.equal(hidden.body.error.code, "not_found");
    assert.equal(wrongTenant.calls.recentAuth.length, 0);
    assert.equal(wrongTenant.calls.retrieve.length, 0);
    assert.equal(wrongTenant.calls.verify.length, 0);
  }
});

test("enforces same-origin, resource-bound recent auth, CSRF, and method-specific headers", async (t) => {
  const downloadCases = [
    [getHeaders({ origin: "https://evil.example" }), undefined, 403],
    [getHeaders({ "agentpass-recent-auth": undefined }), undefined, 401],
    [getHeaders({ "agentpass-csrf": CSRF }), undefined, 400],
    [getHeaders({ "idempotency-key": "not-allowed" }), undefined, 400],
    [getHeaders(), {} , 400]
  ];
  for (const [requestHeaders, body, status] of downloadCases) {
    const fixture = await startFixture(t);
    const result = await request(fixture.base, DOWNLOAD_PATH, { requestHeaders, body });
    assert.equal(result.response.statusCode, status);
    assert.equal(fixture.calls.retrieve.length, 0);
  }

  const verifyCases = [
    [headers({ origin: "https://evil.example", "idempotency-key": undefined }), PUBLIC_EXPORT, 403],
    [headers({ "agentpass-csrf": undefined, "idempotency-key": undefined }), PUBLIC_EXPORT, 403],
    [headers({ "agentpass-recent-auth": undefined, "idempotency-key": undefined }), PUBLIC_EXPORT, 401],
    [headers(), PUBLIC_EXPORT, 400]
  ];
  for (const [requestHeaders, body, status] of verifyCases) {
    const fixture = await startFixture(t);
    const result = await request(fixture.base, VERIFY_PATH, { method: "POST", requestHeaders, body });
    assert.equal(result.response.statusCode, status);
    assert.equal(fixture.calls.retrieve.length, 0);
    assert.equal(fixture.calls.verify.length, 0);
  }
});

test("requires the exact public export verify body and rejects query/header ambiguity", async (t) => {
  for (const body of [
    { ...PUBLIC_EXPORT, private_key: "-----BEGIN PRIVATE KEY-----" },
    { ...PUBLIC_EXPORT, extra: true },
    { ...PUBLIC_EXPORT, payload: { ...PUBLIC_EXPORT.payload, entries: [] } },
    null
  ]) {
    const fixture = await startFixture(t);
    const result = await request(fixture.base, VERIFY_PATH, {
      method: "POST",
      requestHeaders: headers({ "idempotency-key": undefined }),
      body
    });
    assert.equal(result.response.statusCode, 400, `${JSON.stringify(body)} -> ${JSON.stringify(result.body)}`);
    assert.equal(fixture.calls.recentAuth.length, 0);
    assert.equal(fixture.calls.retrieve.length, 0);
    assert.equal(fixture.calls.verify.length, 0);
  }
  const query = await startFixture(t);
  const result = await request(query.base, `${VERIFY_PATH}?extra=1`, {
    method: "POST",
    requestHeaders: headers({ "idempotency-key": undefined }),
    body: PUBLIC_EXPORT
  });
  assert.equal(result.response.statusCode, 400);
  assert.equal(query.calls.retrieve.length, 0);
  assert.equal(query.calls.verify.length, 0);
});

test("maps absent, reserved, uncertain, and wrong-tenant service states to opaque 404", async (t) => {
  for (const code of ["not_found", "in_progress", "uncertain", "organization_mismatch"]) {
    const fixture = await startFixture(t, { serviceError: Object.assign(new Error(`internal ${code} secret`), { code }) });
    const result = await request(fixture.base, DOWNLOAD_PATH, { requestHeaders: getHeaders() });
    assert.equal(result.response.statusCode, 404, code);
    assert.equal(result.body.error.code, "not_found");
    assert.equal(/reserved|uncertain|tenant|organization|secret/iu.test(JSON.stringify(result.body)), false);
    assertNoStoreNoSniff(result.response);
    assert.equal(fixture.calls.audit.at(-1).eventType, "audit.export.download.failed");

    const verifyFixture = await startFixture(t, { verifierError: Object.assign(new Error(`internal ${code} secret`), { code }) });
    const verification = await request(verifyFixture.base, VERIFY_PATH, {
      method: "POST",
      requestHeaders: headers({ "idempotency-key": undefined }),
      body: PUBLIC_EXPORT
    });
    assert.equal(verification.response.statusCode, 404, `${code}:verify`);
    assert.equal(verification.body.error.code, "not_found");
    assert.equal(/reserved|uncertain|tenant|organization|secret/iu.test(JSON.stringify(verification.body)), false);
    assertNoStoreNoSniff(verification.response);
    assert.equal(verifyFixture.calls.audit.at(-1).eventType, "audit.export.verify.failed");
  }
});

test("fails closed for private extras, oversize payloads, digest/root corruption, and anchor mismatch", async (t) => {
  const invalidResults = [
    ["private", { ...SERVICE_RESULT, claim_token: "clear-claim-token" }],
    ["oversize", { ...SERVICE_RESULT, payload: { ...PAYLOAD, oversized: "x".repeat(270_000) } }],
    ["digest", { ...SERVICE_RESULT, payload_digest: "c".repeat(64) }],
    ["root", { ...SERVICE_RESULT, range: { ...RANGE, root_digest: "d".repeat(64) } }],
    ["anchor", { ...SERVICE_RESULT, audit_anchor: { ...SERVICE_RESULT.audit_anchor, statement: { ...SERVICE_RESULT.audit_anchor.statement, export_id: OTHER_EXPORT_ID } } }]
  ];
  for (const [name, serviceResult] of invalidResults) {
    const fixture = await startFixture(t, { serviceResult });
    const result = await request(fixture.base, DOWNLOAD_PATH, { requestHeaders: getHeaders() });
    assert.equal(result.response.statusCode, 503, `${name}:download`);
    assertSecretFree(result.body);
    assertNoStoreNoSniff(result.response);
  }

  for (const [name, verifierResult] of [
    ["digest", { ...VERIFY_RESULT, payload_digest: false, valid: false, reason: "payload_digest_mismatch" }],
    ["root", { ...VERIFY_RESULT, root: false, valid: false, reason: "root_mismatch" }],
    ["anchor", { ...VERIFY_RESULT, anchor: false, valid: false, reason: "anchor_invalid" }]
  ]) {
    const fixture = await startFixture(t, { verifierResult });
    const result = await request(fixture.base, VERIFY_PATH, {
      method: "POST",
      requestHeaders: headers({ "idempotency-key": undefined }),
      body: PUBLIC_EXPORT
    });
    assert.equal(result.response.statusCode, 200, name);
    assert.deepEqual(result.body, verifierResult);
    assertSecretFree(result.body);
    assertNoStoreNoSniff(result.response);
    assert.equal(fixture.calls.verify.length, 1);
    assertVerifyCall(fixture.calls.verify[0]);
  }
});
