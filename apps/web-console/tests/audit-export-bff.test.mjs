import assert from "node:assert/strict";
import test from "node:test";
import { createConsoleApi } from "../lib/console-api.mjs";

const organizationId = "11111111-1111-4111-8111-111111111111";
const otherOrganizationId = "99999999-9999-4999-8999-999999999999";
const exportId = "22222222-2222-4222-8222-222222222222";
const sessionCookie = `__Host-agentpass_session=${"s".repeat(43)}`;
const csrf = "c".repeat(43);
const recentAuth = "55555555-5555-4555-8555-555555555555";
const idempotencyKey = "audit-export-request-01";
const requestId = "cloud-request-01";
const payloadDigest = "a".repeat(64);
const cursorSecret = "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE";

const env = Object.freeze({
  AGENTPASS_CLOUD_API_URL: "https://cloud.example.test",
  AGENTPASS_ORGANIZATION_ID: organizationId,
  AGENTPASS_CONSOLE_CURSOR_SECRET: cursorSecret,
});

const range = Object.freeze({
  from_audit_position: 1,
  to_audit_position: 1,
  previous_root_digest: "0".repeat(64),
  root_digest: "b".repeat(64),
  record_count: 1,
});

const committedExport = Object.freeze({
  organization_id: organizationId,
  export_id: exportId,
  environment: "production",
  chain: "admin",
  range,
  payload_digest: payloadDigest,
  payload: {
    version: 1,
    type: "agentpass.audit-export",
    organization_id: organizationId,
    environment: "production",
    chain: "admin",
    range,
    entries: [{
      version: 1,
      organization_id: organizationId,
      environment: "production",
      chain: "admin",
      export_position: 1,
      source_id: "audit-event-1",
      source_device_id: null,
      source_previous_hash: "0".repeat(64),
      source_hash: "b".repeat(64),
      source_gap: false,
      event: { action: "export.created", details: { count: 1 } },
    }],
  },
  audit_anchor: {
    version: 1,
    type: "agentpass.audit-anchor",
    statement_hash: "d".repeat(64),
    signature: "signed-anchor",
  },
  validity: "active",
});

function request(path, { method = "GET", body, headers = {} } = {}) {
  return new Request(`https://console.example.test${path}`, {
    method,
    headers: {
      origin: "https://console.example.test",
      "content-type": "application/json",
      ...headers,
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}

function jsonResponse(body, status = 200, headers = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", ...headers },
  });
}

function cloudAuditExportResponse(auditExport = committedExport, extra = {}) {
  return { audit_export: auditExport, request_id: requestId, ...extra };
}

async function bodyOf(response) {
  return response.json();
}

function api(fetchImpl) {
  return createConsoleApi({ env, fetchImpl });
}

function auditExportGetPath({ id = exportId, organization = undefined, extra = "" } = {}) {
  const tenant = organization === undefined ? "" : `&organization_id=${organization}`;
  return `/api/console?resource=audit-export&export_id=${id}&environment=production&chain=admin${tenant}${extra}`;
}

function canonical(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
}

test("forwards a canonical audit-export attachment without JSON mutation", async () => {
  const calls = [];
  const bytes = canonical(committedExport);
  const result = await api(async (url, init) => {
    calls.push({ url: String(url), init });
    return new Response(bytes, { status: 200, headers: {
      "content-type": "application/json",
      "content-disposition": "attachment; filename=\"agentpass-audit-export.json\"",
      "cache-control": "no-store, max-age=0",
      "x-content-type-options": "nosniff",
    } });
  }).handle(request(`/api/console?resource=audit-export-download&export_id=${exportId}&environment=production&chain=admin`, {
    headers: { cookie: sessionCookie, "agentpass-recent-auth": recentAuth },
  }));

  assert.equal(result.status, 200);
  assert.equal(await result.text(), bytes);
  assert.equal(result.headers.get("content-disposition"), "attachment; filename=\"agentpass-audit-export.json\"");
  assert.equal(result.headers.get("cache-control"), "no-store, max-age=0");
  assert.equal(result.headers.get("x-content-type-options"), "nosniff");
  assert.equal(calls[0].url, `https://cloud.example.test/v1/organizations/${organizationId}/audit/exports/${exportId}/download?environment=production&chain=admin`);
  assert.equal(calls[0].init.method, "GET");
  assert.equal(calls[0].init.headers.has("agentpass-csrf"), false);
  assert.equal(calls[0].init.headers.has("idempotency-key"), false);
});

test("forwards exact public audit-export verification without idempotency", async () => {
  const calls = [];
  const verification = { payload_digest: true, root: true, anchor: true, historical_key: true, valid: true, reason: "valid" };
  const result = await api(async (url, init) => {
    calls.push({ url: String(url), init });
    return jsonResponse(verification);
  }).handle(request("/api/console?operation=audit-export-verify", {
    method: "POST",
    body: committedExport,
    headers: { cookie: sessionCookie, "agentpass-csrf": csrf, "agentpass-recent-auth": recentAuth },
  }));

  assert.equal(result.status, 200);
  assert.deepEqual(await bodyOf(result), verification);
  assert.equal(calls[0].url, `https://cloud.example.test/v1/organizations/${organizationId}/audit/exports/verify`);
  assert.deepEqual(JSON.parse(calls[0].init.body), committedExport);
  assert.equal(calls[0].init.headers.get("agentpass-csrf"), csrf);
  assert.equal(calls[0].init.headers.get("agentpass-recent-auth"), recentAuth);
  assert.equal(calls[0].init.headers.has("idempotency-key"), false);
});

test("fails closed on noncanonical downloads and idempotent verify requests", async () => {
  const noncanonical = await api(async () => new Response(JSON.stringify(committedExport), { status: 200, headers: {
    "content-type": "application/json",
    "content-disposition": "attachment; filename=\"agentpass-audit-export.json\"",
    "cache-control": "no-store, max-age=0",
    "x-content-type-options": "nosniff",
  } })).handle(request(`/api/console?resource=audit-export-download&export_id=${exportId}&environment=production&chain=admin`, {
    headers: { cookie: sessionCookie, "agentpass-recent-auth": recentAuth },
  }));
  assert.equal(noncanonical.status, 502);

  let calls = 0;
  const idempotent = await api(async () => { calls += 1; return jsonResponse({}); }).handle(request("/api/console?operation=audit-export-verify", {
    method: "POST",
    body: committedExport,
    headers: { cookie: sessionCookie, "agentpass-csrf": csrf, "agentpass-recent-auth": recentAuth, "idempotency-key": idempotencyKey },
  }));
  assert.equal(idempotent.status, 400);
  assert.equal(calls, 0);
});

test("forwards the org-pinned audit-export POST with exact session controls and preserves the committed payload", async () => {
  const calls = [];
  const responseBody = cloudAuditExportResponse(structuredClone(committedExport));
  const result = await api(async (url, init) => {
    calls.push({ url: String(url), init });
    return jsonResponse(responseBody, 201);
  }).handle(request("/api/console?operation=audit-export", {
    method: "POST",
    body: { export_id: exportId, environment: "production", chain: "admin" },
    headers: {
      cookie: sessionCookie,
      "agentpass-csrf": csrf,
      "agentpass-recent-auth": recentAuth,
      "idempotency-key": idempotencyKey,
    },
  }));

  assert.equal(result.status, 201);
  const browserBody = await bodyOf(result);
  assert.deepEqual(browserBody, responseBody.audit_export);
  assert.equal(browserBody.request_id, undefined);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, `https://cloud.example.test/v1/organizations/${organizationId}/audit/exports`);
  assert.equal(calls[0].init.method, "POST");
  assert.equal(calls[0].init.redirect, "error");
  assert.equal(calls[0].init.cache, "no-store");
  assert.equal(calls[0].init.headers.get("cookie"), sessionCookie);
  assert.equal(calls[0].init.headers.get("origin"), "https://console.example.test");
  assert.equal(calls[0].init.headers.get("agentpass-csrf"), csrf);
  assert.equal(calls[0].init.headers.get("agentpass-recent-auth"), recentAuth);
  assert.equal(calls[0].init.headers.get("idempotency-key"), idempotencyKey);
  assert.deepEqual(JSON.parse(calls[0].init.body), { export_id: exportId, environment: "production", chain: "admin" });
  assert.equal(calls[0].init.headers.has("authorization"), false);
});

test("forwards committed audit-export GET by exact identity query with recent auth and without POST-only headers", async () => {
  const calls = [];
  const result = await api(async (url, init) => {
    calls.push({ url: String(url), init });
    return jsonResponse(cloudAuditExportResponse());
  }).handle(request(auditExportGetPath(), { headers: { cookie: sessionCookie, "agentpass-recent-auth": recentAuth } }));

  assert.equal(result.status, 200);
  assert.deepEqual(await bodyOf(result), committedExport);
  assert.equal(calls[0].url, `https://cloud.example.test/v1/organizations/${organizationId}/audit/exports/${exportId}?environment=production&chain=admin`);
  assert.equal(calls[0].init.method, "GET");
  assert.equal(calls[0].init.headers.get("cookie"), sessionCookie);
  assert.equal(calls[0].init.headers.get("origin"), "https://console.example.test");
  assert.equal(calls[0].init.headers.get("agentpass-recent-auth"), recentAuth);
  assert.equal(calls[0].init.headers.has("agentpass-csrf"), false);
  assert.equal(calls[0].init.headers.has("idempotency-key"), false);
});

test("requires same-origin session controls, CSRF, recent auth, and Idempotency-Key only on POST", async () => {
  let calls = 0;
  const fetchImpl = async () => {
    calls += 1;
    return jsonResponse(cloudAuditExportResponse());
  };

  const getWithoutCsrf = await api(fetchImpl).handle(request(auditExportGetPath(), { headers: { cookie: sessionCookie, "agentpass-recent-auth": recentAuth } }));
  assert.equal(getWithoutCsrf.status, 200);

  const getWithoutRecentAuth = await api(fetchImpl).handle(request(auditExportGetPath(), { headers: { cookie: sessionCookie } }));
  assert.equal(getWithoutRecentAuth.status, 401);

  const getWithCsrf = await api(fetchImpl).handle(request(auditExportGetPath(), { headers: { cookie: sessionCookie, "agentpass-csrf": csrf, "agentpass-recent-auth": recentAuth } }));
  assert.equal(getWithCsrf.status, 400);

  const getWithIdempotency = await api(fetchImpl).handle(request(auditExportGetPath(), { headers: { cookie: sessionCookie, "agentpass-recent-auth": recentAuth, "idempotency-key": idempotencyKey } }));
  assert.equal(getWithIdempotency.status, 400);

  const postWithoutCsrf = await api(fetchImpl).handle(request("/api/console?operation=audit-export", {
    method: "POST",
    body: { export_id: exportId, environment: "production", chain: "admin" },
    headers: { cookie: sessionCookie, "idempotency-key": idempotencyKey, "agentpass-recent-auth": recentAuth },
  }));
  assert.equal(postWithoutCsrf.status, 403);

  const postWithoutRecentAuth = await api(fetchImpl).handle(request("/api/console?operation=audit-export", {
    method: "POST",
    body: { export_id: exportId, environment: "production", chain: "admin" },
    headers: { cookie: sessionCookie, "agentpass-csrf": csrf, "idempotency-key": idempotencyKey },
  }));
  assert.equal(postWithoutRecentAuth.status, 401);

  const postWithoutIdempotency = await api(fetchImpl).handle(request("/api/console?operation=audit-export", {
    method: "POST",
    body: { export_id: exportId, environment: "production", chain: "admin" },
    headers: { cookie: sessionCookie, "agentpass-csrf": csrf, "agentpass-recent-auth": recentAuth },
  }));
  assert.equal(postWithoutIdempotency.status, 400);

  const crossOrigin = await api(fetchImpl).handle(request(auditExportGetPath(), {
    headers: { cookie: sessionCookie, origin: "https://evil.example.test" },
  }));
  assert.equal(crossOrigin.status, 403);

  const crossSite = await api(fetchImpl).handle(request(auditExportGetPath(), {
    headers: { cookie: sessionCookie, "sec-fetch-site": "cross-site" },
  }));
  assert.equal(crossSite.status, 403);
  assert.equal(calls, 1);
});

test("rejects cross-tenant, path, query, and unknown request fields before Cloud", async () => {
  let calls = 0;
  const apiInstance = api(async () => {
    calls += 1;
    return jsonResponse(cloudAuditExportResponse());
  });
  const cases = [
    request(auditExportGetPath({ organization: otherOrganizationId }), { headers: { cookie: sessionCookie } }),
    request(`/api/console/organizations/${otherOrganizationId}/audit-exports/${exportId}`, { headers: { cookie: sessionCookie } }),
    request(auditExportGetPath({ extra: "&unknown=1" }), { headers: { cookie: sessionCookie } }),
    request(auditExportGetPath({ extra: `&export_id=${exportId}` }), { headers: { cookie: sessionCookie } }),
    request(`/api/console?resource=audit-export&operation=audit-export&export_id=${exportId}`, { headers: { cookie: sessionCookie } }),
    request("/api/console?operation=audit-export", {
      method: "POST",
      body: { export_id: exportId, environment: "production", chain: "admin", organization_id: otherOrganizationId },
      headers: { cookie: sessionCookie, "agentpass-csrf": csrf, "agentpass-recent-auth": recentAuth, "idempotency-key": idempotencyKey },
    }),
  ];

  for (const invalidRequest of cases) {
    const result = await apiInstance.handle(invalidRequest);
    assert.ok(result.status >= 400 && result.status < 500, `expected client rejection, got ${result.status}`);
  }
  assert.equal(calls, 0);
});

test("rejects redirects, Set-Cookie, private extras, and responses over 256 KiB", async () => {
  const postRequest = request("/api/console?operation=audit-export", {
    method: "POST",
    body: { export_id: exportId, environment: "production", chain: "admin" },
    headers: { cookie: sessionCookie, "agentpass-csrf": csrf, "agentpass-recent-auth": recentAuth, "idempotency-key": idempotencyKey },
  });

  const atLimit = cloudAuditExportResponse(structuredClone(committedExport));
  atLimit.audit_export.payload.entries[0].event.details.padding = "";
  const baseBytes = new TextEncoder().encode(JSON.stringify(atLimit)).byteLength;
  atLimit.audit_export.payload.entries[0].event.details.padding = "x".repeat(262144 - baseBytes);
  assert.equal(new TextEncoder().encode(JSON.stringify(atLimit)).byteLength, 262144);
  const acceptedAtLimit = await api(async () => jsonResponse(atLimit, 201)).handle(postRequest.clone());
  assert.equal(acceptedAtLimit.status, 201);
  assert.deepEqual(await bodyOf(acceptedAtLimit), atLimit.audit_export);

  const redirect = await api(async () => new Response("", { status: 302, headers: { location: "https://evil.example.test" } })).handle(postRequest.clone());
  assert.equal(redirect.status, 502);

  const setCookie = await api(async () => jsonResponse(cloudAuditExportResponse(), 201, { "set-cookie": "__Host-agentpass_session=attacker" })).handle(postRequest.clone());
  assert.equal(setCookie.status, 502);
  assert.equal(setCookie.headers.get("set-cookie"), null);

  const privateExtra = await api(async () => jsonResponse(cloudAuditExportResponse({ ...committedExport, private_key: "-----BEGIN PRIVATE KEY-----" }))).handle(postRequest.clone());
  assert.equal(privateExtra.status, 502);

  const unknownCloudField = await api(async () => jsonResponse(cloudAuditExportResponse(committedExport, { extra: "must-not-reach-browser" }))).handle(postRequest.clone());
  assert.equal(unknownCloudField.status, 502);

  const oversized = await api(async () => jsonResponse(cloudAuditExportResponse({ ...committedExport, payload: "x".repeat(262144) }))).handle(postRequest.clone());
  assert.equal(oversized.status, 502);
});
