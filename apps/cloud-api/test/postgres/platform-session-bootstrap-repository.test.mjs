import assert from "node:assert/strict";
import test from "node:test";

import {
  createPostgresPlatformSessionBootstrapRepository,
  PLATFORM_SESSION_BOOTSTRAP_REPOSITORY_ERROR_CODES as CODES,
  PLATFORM_SESSION_BOOTSTRAP_SQL,
  PlatformSessionBootstrapRepositoryError
} from "../../src/postgres/platform-session-bootstrap-repository.mjs";

const IDS = Object.freeze({
  humanSession: "11111111-1111-4111-8111-111111111111",
  organization: "22222222-2222-4222-8222-222222222222",
  member: "33333333-3333-4333-8333-333333333333",
  membership: "44444444-4444-4444-8444-444444444444",
  assignment: "55555555-5555-4555-8555-555555555555",
  principal: "66666666-6666-4666-8666-666666666666"
});
const HASH = "ab".repeat(32);
const CREDENTIAL = Buffer.alloc(32, 7);

function row() {
  return {
    human_session_id: IDS.humanSession,
    organization_id: IDS.organization,
    member_id: IDS.member,
    membership_id: IDS.membership,
    role: "admin",
    organization_authority_epoch: "4",
    membership_session_epoch: "8",
    assignment_id: IDS.assignment,
    principal_id: IDS.principal,
    principal_authority_generation: "12",
    assignment_version: "3",
    operation: "platform.promotion.issue",
    capability: "platform.promotion.issue",
    allowed_webauthn_credential_ids: [CREDENTIAL],
    platform_credentials: []
  };
}

test("bootstrap repository sends only human token hash and public intent scope to 0055", async () => {
  const calls = [];
  const repository = createPostgresPlatformSessionBootstrapRepository({
    client: { async query(text, values) { calls.push({ text, values }); return { rows: [row()] }; } }
  });
  const result = await repository.resolvePlatformSessionBootstrap({
    session_material_hash: HASH,
    organization_id: IDS.organization,
    operation: "platform.promotion.issue",
    capability: "platform.promotion.issue"
  });
  assert.equal(calls[0].text, PLATFORM_SESSION_BOOTSTRAP_SQL);
  assert.deepEqual(calls[0].values, [Buffer.from(HASH, "hex"), IDS.organization, "platform.promotion.issue", "platform.promotion.issue"]);
  assert.equal(result.principal_id, IDS.principal);
  assert.equal(result.allowed_webauthn_credential_ids[0].equals(CREDENTIAL), true);
  assert.equal(Object.hasOwn(result, "session_material_hash"), false);
});

test("bootstrap repository is fail-closed for invalid input, absent authority, and database errors", async () => {
  const repository = createPostgresPlatformSessionBootstrapRepository({ client: { async query() { return { rows: [] }; } } });
  assert.equal(await repository.resolvePlatformSessionBootstrap({
    session_material_hash: HASH,
    organization_id: IDS.organization,
    operation: "platform.promotion.issue",
    capability: "platform.promotion.issue"
  }), null);
  await assert.rejects(() => repository.resolvePlatformSessionBootstrap({
    session_material_hash: HASH,
    organization_id: IDS.organization,
    operation: "platform.promotion.issue",
    capability: "platform.promotion.issue",
    principal_id: IDS.principal
  }), (error) => error instanceof PlatformSessionBootstrapRepositoryError && error.code === CODES.INPUT);
  const failing = createPostgresPlatformSessionBootstrapRepository({ client: { async query() { throw new Error("secret database detail"); } } });
  await assert.rejects(() => failing.resolvePlatformSessionBootstrap({
    session_material_hash: HASH,
    organization_id: IDS.organization,
    operation: "platform.promotion.issue",
    capability: "platform.promotion.issue"
  }), (error) => error instanceof PlatformSessionBootstrapRepositoryError && error.code === CODES.DATABASE && !String(error).includes("secret database detail"));
});
