import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import {
  HOSTED_ORGANIZATION_BOOTSTRAP_SERVICE_ERROR_CODES as CODES,
  createHostedOrganizationBootstrapService
} from "../../src/hosted-identity/organization-bootstrap-service.mjs";

const IDS = Object.freeze([
  "11111111-1111-4111-8111-111111111111",
  "22222222-2222-4222-8222-222222222222",
  "33333333-3333-4333-8333-333333333333"
]);
const TOKEN = "bootstrap-cookie-secret";
const RESPONSE = Object.freeze({
  version: 1,
  organization: Object.freeze({
    organization_id: IDS[0],
    name: "é team",
    version: 1,
    created_at: "2026-08-15T00:00:00.000Z",
    updated_at: "2026-08-15T00:00:00.000Z"
  }),
  onboarding: Object.freeze({ state: "webauthn_required" })
});

function hash(value) { return crypto.createHash("sha256").update(value, "utf8").digest("hex"); }
function fixture({ result = { response_status: 201, response_json: RESPONSE, replayed: false }, repository = {}, randomUUID = undefined } = {}) {
  const calls = [];
  let idIndex = 0;
  const service = createHostedOrganizationBootstrapService({
    repository: {
      async commitOrganizationV2(input) { calls.push(input); if (repository.error) throw repository.error; return repository.result ?? result; }
    },
    randomUUID: randomUUID ?? (() => IDS[idIndex++])
  });
  return { service, calls };
}

test("createOrganization normalizes the name, hashes its UTF-8 bytes, and generates all durable IDs", async () => {
  const { service, calls } = fixture();
  assert.deepEqual(Object.keys(service), ["createOrganization"]);
  const result = await service.createOrganization({
    bootstrap_token: TOKEN,
    name: "  e\u0301   team  ",
    idempotency_key: "bootstrap-0001"
  });

  assert.deepEqual(result, { response_status: 201, response_json: RESPONSE, replayed: false });
  assert.deepEqual(calls, [{
    bootstrap_cookie: TOKEN,
    idempotency_key: "bootstrap-0001",
    request_hash: hash("é team"),
    organization_name: "é team",
    organization_id: IDS[0],
    membership_id: IDS[1],
    audit_event_id: IDS[2]
  }]);
});

test("derives the request hash internally and preserves replay status", async () => {
  const { service, calls } = fixture({ result: { response_status: 200, response_json: RESPONSE, replayed: true } });
  const result = await service.createOrganization({ bootstrap_token: TOKEN, name: "é team", idempotency_key: "bootstrap-0001" });
  assert.equal(result.response_status, 200);
  assert.equal(result.replayed, true);
  assert.equal(calls[0].request_hash, hash("é team"));
});

test("rejects browser authority fields and malformed names before the repository", async () => {
  const { service, calls } = fixture();
  for (const invalid of [
    { bootstrap_token: TOKEN, name: "Acme", idempotency_key: "bootstrap-0001", organization_id: IDS[0] },
    { bootstrap_token: TOKEN, name: "Acme", idempotency_key: "bootstrap-0001", public_response: RESPONSE },
    { bootstrap_token: TOKEN, name: "Acme", idempotency_key: "bootstrap-0001", request_hash: "A".repeat(64) },
    { bootstrap_token: TOKEN, name: "\u0000", idempotency_key: "bootstrap-0001" },
    { bootstrap_token: TOKEN, name: " ", idempotency_key: "bootstrap-0001" },
    { bootstrap_token: TOKEN, name: "Acme", idempotency_key: "short" },
    { bootstrap_token: TOKEN, name: "Acme", idempotency_key: "bootstrap-0001", request_digest: "A".repeat(64) }
  ]) {
    await assert.rejects(service.createOrganization(invalid), (error) => error.code === CODES.INPUT && !String(error).includes(TOKEN));
  }
  assert.equal(calls.length, 0);
});

test("redacts repository failures and rejects unsafe public responses", async () => {
  const secret = `${TOKEN}-database-secret`;
  const { service } = fixture({ repository: { error: new Error(secret) } });
  await assert.rejects(service.createOrganization({ bootstrap_token: TOKEN, name: "Acme", idempotency_key: "bootstrap-0001" }), (error) => {
    assert.equal(error.code, CODES.UNAVAILABLE);
    assert.equal(String(error).includes(secret), false);
    assert.equal(String(error).includes(TOKEN), false);
    return true;
  });

  for (const result of [
    { response_status: 201, response_json: RESPONSE, replayed: true },
    { response_status: 200, response_json: RESPONSE, replayed: false },
    { response_status: 201, response_json: { ...RESPONSE, member_id: IDS[1] }, replayed: false },
    { response_status: 201, response_json: { ...RESPONSE, organization: { ...RESPONSE.organization, name: "substituted" } }, replayed: false },
    { response_status: 201, response_json: { ...RESPONSE, organization: { ...RESPONSE.organization, organization_id: IDS[1] } }, replayed: false }
  ]) {
    const fixtureResult = fixture({ result });
    await assert.rejects(fixtureResult.service.createOrganization({ bootstrap_token: TOKEN, name: "Acme", idempotency_key: "bootstrap-0001" }), { code: CODES.UNAVAILABLE });
  }
});
