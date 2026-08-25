import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import {
  HOSTED_IDENTITY_BOOTSTRAP_REPOSITORY_ERROR_CODES as CODES,
  HOSTED_IDENTITY_BOOTSTRAP_REPOSITORY_SQL as SQL,
  createPostgresHostedIdentityBootstrapRepository
} from "../../src/postgres/hosted-identity-bootstrap-repository.mjs";

const IDS = Object.freeze({
  organization: "11111111-1111-4111-8111-111111111111",
  membership: "22222222-2222-4222-8222-222222222222",
  audit: "33333333-3333-4333-8333-333333333333"
});
const COOKIE = "bootstrap-cookie-secret";
const NAME = "Acme Team";
const RESPONSE = Object.freeze({
  version: 1,
  organization: Object.freeze({
    organization_id: IDS.organization,
    name: NAME,
    version: 1,
    created_at: "2026-08-15T00:00:00.000Z",
    updated_at: "2026-08-15T00:00:00.000Z"
  }),
  onboarding: Object.freeze({ state: "webauthn_required" })
});

class FakeClient {
  constructor(handler) { this.handler = handler; this.calls = []; }
  async query(text, params) { this.calls.push({ text, params }); return this.handler(text, params); }
}

function digest(value) { return crypto.createHash("sha256").update(value, "utf8").digest(); }
function makeRepository(handler) {
  const client = new FakeClient(handler);
  return { client, repository: createPostgresHostedIdentityBootstrapRepository({ client }) };
}
function input(overrides = {}) {
  return {
    bootstrap_cookie: COOKIE,
    idempotency_key: "bootstrap-0001",
    request_hash: digest(NAME),
    organization_name: NAME,
    organization_id: IDS.organization,
    membership_id: IDS.membership,
    audit_event_id: IDS.audit,
    ...overrides
  };
}

test("commitOrganizationV2 calls the frozen SQL signature and hashes only the raw cookie", async () => {
  const { client, repository } = makeRepository((text) => {
    assert.equal(text, SQL.commitOrganizationV2);
    return { rows: [{ response_status: 201, response_json: RESPONSE, replayed: false }], rowCount: 1 };
  });

  const result = await repository.commitOrganizationV2(input());

  assert.deepEqual(result, { response_status: 201, response_json: RESPONSE, replayed: false });
  assert.deepEqual(client.calls, [{
    text: "SELECT * FROM public.agentpass_hosted_identity_bootstrap_organization_commit_v2($1::bytea,$2::text,$3::bytea,$4::text,$5::uuid,$6::uuid,$7::uuid)",
    params: [digest(COOKIE), "bootstrap-0001", digest(NAME), NAME, IDS.organization, IDS.membership, IDS.audit]
  }]);
  assert.equal(client.calls[0].params.includes(COOKIE), false);
});

test("commitOrganizationV2 preserves 200 replay semantics and rejects non-canonical boundaries", async () => {
  const { repository } = makeRepository(() => ({ rows: [{ response_status: 200, response_json: RESPONSE, replayed: true }], rowCount: 1 }));
  assert.deepEqual((await repository.commitOrganizationV2(input())).response_status, 200);

  for (const invalid of [
    { ...input(), organization_name: " Acme Team" },
    { ...input(), organization_name: "Acme\nTeam" },
    { ...input(), organization_id: "11111111-1111-3111-8111-111111111111" },
    { ...input(), audit_event_id: "not-a-uuid" },
    { ...input(), public_response: RESPONSE },
    { ...input(), request_hash: "not-a-digest" }
  ]) {
    await assert.rejects(repository.commitOrganizationV2(invalid), (error) => error.code === CODES.INPUT);
  }
});

test("commitOrganizationV2 rejects unsafe result status combinations", async () => {
  for (const row of [
    { response_status: 201, response_json: RESPONSE, replayed: true },
    { response_status: 200, response_json: RESPONSE, replayed: false },
    { response_status: 202, response_json: RESPONSE, replayed: false },
    { response_status: 201, response_json: { ...RESPONSE, member_id: IDS.membership }, replayed: false }
  ]) {
    const { repository } = makeRepository(() => ({ rows: [row], rowCount: 1 }));
    await assert.rejects(repository.commitOrganizationV2(input()), (error) => error.code === CODES.RESULT);
  }
});
