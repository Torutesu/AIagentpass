import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import {
  HOSTED_BOOTSTRAP_SERVICE_ERROR_CODES as CODES,
  createHostedBootstrapService
} from "../../src/hosted-identity/bootstrap-service.mjs";

const BOOTSTRAP_TOKEN = "bootstrap-cookie-0123456789";
const CSRF_KEY = Buffer.alloc(32, 0x42);
const ORGANIZATION = Object.freeze({ organization_id: "11111111-1111-4111-8111-111111111111", name: "Acme", version: 1, created_at: "2026-08-15T00:00:00.000Z", updated_at: "2026-08-15T00:00:00.000Z" });
const STATUS = Object.freeze({ state: "organization_required", organization_count: 0, webauthn_required: false, can_create_first_organization: true, expires_at: "2099-01-01T00:00:00.000Z" });

function fixture({ status = STATUS, verify = true, organizationResult = { response_status: 201, response_json: { organization: ORGANIZATION }, replayed: false }, repository = {}, organizationService = {} } = {}) {
  const calls = { status: [], verify: [], organization: [] };
  const service = createHostedBootstrapService({
    repository: {
      async getBootstrapStatus(input) { calls.status.push(input); if (repository.statusError) throw repository.statusError; return status; },
      async verifyBootstrapCsrf(input) { calls.verify.push(input); if (repository.verifyError) throw repository.verifyError; return verify; }
    },
    organizationService: {
      async createOrganization(input) { calls.organization.push(input); if (organizationService.error) throw organizationService.error; return organizationService.result ?? organizationResult; }
    },
    csrfKey: CSRF_KEY
  });
  return { service, calls };
}

function expectedCsrf(token = BOOTSTRAP_TOKEN) {
  return crypto.createHmac("sha256", CSRF_KEY)
    .update("agentpass/hosted-identity-bootstrap\0v1\0csrf\0", "utf8")
    .update(token, "utf8")
    .digest("base64url");
}

test("status deterministically reconstructs the same CSRF token after restart", async () => {
  const first = fixture().service;
  const second = fixture().service;
  const a = await first.status({ bootstrap_token: BOOTSTRAP_TOKEN });
  const b = await second.status({ bootstrap_token: BOOTSTRAP_TOKEN });
  assert.deepEqual(a, { ...STATUS, csrf_token: expectedCsrf() });
  assert.deepEqual(b, a);
  assert.match(a.csrf_token, /^[A-Za-z0-9_-]{43}$/u);
});

test("status passes only the deterministic CSRF projection and returns exactly six fields", async () => {
  const { service, calls } = fixture();
  const result = await service.status({ bootstrap_token: BOOTSTRAP_TOKEN });
  assert.deepEqual(Object.keys(result).sort(), ["can_create_first_organization", "csrf_token", "expires_at", "organization_count", "state", "webauthn_required"].sort());
  assert.deepEqual(calls.status, [{ bootstrap_cookie: BOOTSTRAP_TOKEN, csrf_token: expectedCsrf() }]);
});

test("status maps absent and expired sessions to stable public errors", async () => {
  await assert.rejects(fixture({ status: null }).service.status({ bootstrap_token: BOOTSTRAP_TOKEN }), { code: CODES.SESSION_REQUIRED });
  await assert.rejects(fixture({ status: { ...STATUS, state: "expired" } }).service.status({ bootstrap_token: BOOTSTRAP_TOKEN }), { code: CODES.SESSION_EXPIRED });
  const databaseAuthoritative = { ...STATUS, expires_at: "2000-01-01T00:00:00.000Z" };
  assert.deepEqual(await fixture({ status: databaseAuthoritative }).service.status({ bootstrap_token: BOOTSTRAP_TOKEN }), { ...databaseAuthoritative, csrf_token: expectedCsrf() });
});

test("verifyCsrf rejects a wrong token before repository verification", async () => {
  const { service, calls } = fixture();
  const result = await service.verifyCsrf({ bootstrap_token: BOOTSTRAP_TOKEN, csrf_token: "wrong" });
  assert.equal(result, false);
  assert.deepEqual(calls.verify, []);
});

test("verifyCsrf uses constant-time comparison and requires repository approval", async () => {
  const { service, calls } = fixture({ verify: false });
  assert.equal(await service.verifyCsrf({ bootstrap_token: BOOTSTRAP_TOKEN, csrf_token: expectedCsrf() }), false);
  assert.deepEqual(calls.verify, [{ bootstrap_cookie: BOOTSTRAP_TOKEN, csrf_token: expectedCsrf() }]);
  const approved = fixture({ verify: true }).service;
  assert.equal(await approved.verifyCsrf({ bootstrap_token: BOOTSTRAP_TOKEN, csrf_token: expectedCsrf() }), true);
});

test("constructor enforces the dedicated exactly-32-byte key and closed configuration", () => {
  const repository = { getBootstrapStatus() {}, verifyBootstrapCsrf() {} };
  const organizationService = { createOrganization() {} };
  for (const csrfKey of [Buffer.alloc(31), Buffer.alloc(33), new Uint8Array(31), "x".repeat(32)]) {
    assert.throws(() => createHostedBootstrapService({ repository, organizationService, csrfKey }), { code: CODES.CONFIG });
  }
  assert.throws(() => createHostedBootstrapService({ repository, organizationService, csrfKey: CSRF_KEY, extra: true }), { code: CODES.CONFIG });
});

test("methods reject malformed and extra input before dependencies", async () => {
  const { service, calls } = fixture();
  for (const input of [
    {},
    { bootstrap_token: BOOTSTRAP_TOKEN, extra: true },
    { bootstrap_token: "short" },
    { bootstrap_token: BOOTSTRAP_TOKEN, csrf_token: "x" },
  ]) await assert.rejects(service.status(input), { code: CODES.INPUT });
  await assert.rejects(service.verifyCsrf({ bootstrap_token: BOOTSTRAP_TOKEN, csrf_token: expectedCsrf(), extra: true }), { code: CODES.INPUT });
  await assert.rejects(service.createOrganization({ bootstrap_token: BOOTSTRAP_TOKEN, name: "Acme", idempotency_key: "bootstrap-0001", role: "owner" }), { code: CODES.INPUT });
  assert.equal(calls.status.length, 0);
  assert.equal(calls.verify.length, 0);
  assert.equal(calls.organization.length, 0);
});

test("repository failures are redacted to bootstrap_unavailable", async () => {
  const secret = `${BOOTSTRAP_TOKEN}-database-secret`;
  const { service } = fixture({ repository: { statusError: new Error(secret) } });
  await assert.rejects(service.status({ bootstrap_token: BOOTSTRAP_TOKEN }), (error) => {
    assert.equal(error.code, CODES.UNAVAILABLE);
    assert.equal(String(error).includes(secret), false);
    assert.equal(String(error).includes(BOOTSTRAP_TOKEN), false);
    assert.equal(Object.hasOwn(error, "cause"), false);
    return true;
  });
  const verify = fixture({ repository: { verifyError: new Error(secret) } }).service;
  await assert.rejects(verify.verifyCsrf({ bootstrap_token: BOOTSTRAP_TOKEN, csrf_token: expectedCsrf() }), { code: CODES.UNAVAILABLE });
});

test("createOrganization delegates the closed public request and maps the response", async () => {
  const { service, calls } = fixture();
  const result = await service.createOrganization({ bootstrap_token: BOOTSTRAP_TOKEN, name: "  Acme  ", idempotency_key: "bootstrap-0001", request_hash: "A".repeat(64) });
  assert.deepEqual(result, { organization: ORGANIZATION, replayed: false });
  assert.deepEqual(calls.organization, [{ bootstrap_token: BOOTSTRAP_TOKEN, name: "Acme", idempotency_key: "bootstrap-0001" }]);

  const replay = fixture({ organizationResult: { response_status: 200, response_json: { organization: ORGANIZATION }, replayed: true } }).service;
  assert.deepEqual(await replay.createOrganization({ bootstrap_token: BOOTSTRAP_TOKEN, name: "Acme", idempotency_key: "bootstrap-0001" }), { organization: ORGANIZATION, replayed: true });
});

test("createOrganization maps idempotency conflicts, redacts failures, and rejects unsafe results", async () => {
  const conflict = fixture({ organizationService: { error: { code: CODES.IDEMPOTENCY_CONFLICT } } }).service;
  await assert.rejects(conflict.createOrganization({ bootstrap_token: BOOTSTRAP_TOKEN, name: "Acme", idempotency_key: "bootstrap-0001" }), { code: CODES.IDEMPOTENCY_CONFLICT });
  const unavailable = fixture({ organizationService: { error: new Error(BOOTSTRAP_TOKEN) } }).service;
  await assert.rejects(unavailable.createOrganization({ bootstrap_token: BOOTSTRAP_TOKEN, name: "Acme", idempotency_key: "bootstrap-0001" }), (error) => error.code === CODES.UNAVAILABLE && !String(error).includes(BOOTSTRAP_TOKEN));
  for (const result of [
    { response_json: {}, replayed: false },
    { response_json: { organization: ORGANIZATION }, replayed: "false" },
    { response_json: { organization: ORGANIZATION }, replayed: false, extra: true },
    { response_status: 200, response_json: { organization: ORGANIZATION }, replayed: false },
    { response_status: 201, response_json: { organization: ORGANIZATION }, replayed: true }
  ]) {
    const unsafe = fixture({ organizationService: { result } }).service;
    await assert.rejects(unsafe.createOrganization({ bootstrap_token: BOOTSTRAP_TOKEN, name: "Acme", idempotency_key: "bootstrap-0001" }), { code: CODES.UNAVAILABLE });
  }
});
