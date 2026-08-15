import assert from "node:assert/strict";
import test from "node:test";

import {
  createHostedPlatformSessionComposition,
  normalizePlatformSessionRuntimeConfig
} from "../src/runtime.mjs";

const IDS = Object.freeze({
  principal: "11111111-1111-4111-8111-111111111111",
  member: "22222222-2222-4222-8222-222222222222",
  organization: "33333333-3333-4333-8333-333333333333",
  assignment: "44444444-4444-4444-8444-444444444444",
  challenge: "55555555-5555-4555-8555-555555555555"
});
const DIGEST = "ab".repeat(32);
const CREDENTIAL = Buffer.alloc(32, 4).toString("base64url");

function challengeRecord() {
  return {
    challenge_id: IDS.challenge,
    principal_id: IDS.principal,
    member_id: IDS.member,
    organization_id: IDS.organization,
    assignment_id: IDS.assignment,
    authority_generation: 7,
    operation: "platform.promotion.issue",
    capability: "platform.promotion.issue",
    request_digest_sha256: Buffer.from(DIGEST, "hex"),
    allowed_credential_ids: [CREDENTIAL]
  };
}

test("hosted default composition bootstraps with the Human Session hash and resolves assertion authority from durable challenge", async () => {
  const calls = { bootstrap: [], challenge: [] };
  const composition = createHostedPlatformSessionComposition({
    origin: "https://console.agentpass.test",
    rpId: "console.agentpass.test",
    bootstrapRepository: {
      async resolvePlatformSessionBootstrap(input) {
        calls.bootstrap.push(input);
        return { ...challengeRecord(), allowed_webauthn_credential_ids: [Buffer.alloc(32, 4)] , principal_authority_generation: 7 };
      }
    },
    webauthnRepository: {
      async findPlatformSessionChallenge(input) {
        calls.challenge.push(input);
        return challengeRecord();
      }
    }
  });
  const intent = Object.freeze({
    operation: "platform.promotion.issue",
    organization_id: IDS.organization,
    request_digest_sha256: DIGEST
  });
  const bootstrap = await composition.bootstrapAuthenticator({
    phase: "challenge",
    intent,
    session_material_hash: DIGEST
  });
  assert.deepEqual(calls.bootstrap[0], {
    session_material_hash: DIGEST,
    organization_id: IDS.organization,
    operation: "platform.promotion.issue",
    capability: "platform.promotion.issue"
  });
  assert.equal(bootstrap.principal_id, IDS.principal);

  const assertion = await composition.authorityResolver({
    phase: "assertion",
    challenge_id: IDS.challenge,
    session_material_hash: null,
    bootstrap: null
  });
  assert.deepEqual(calls.challenge, [{ challenge_id: IDS.challenge }]);
  assert.equal(assertion.request_digest_sha256, DIGEST);
  assert.equal(assertion.allowed_credential_ids[0], CREDENTIAL);
  assert.equal(assertion.origin, "https://console.agentpass.test");
});

test("hosted platform session composition is explicit about disabled and missing dependencies", () => {
  assert.deepEqual(normalizePlatformSessionRuntimeConfig({ platformSession: false }), { enabled: false });
  assert.deepEqual(normalizePlatformSessionRuntimeConfig({ origin: undefined, rpId: undefined }), { enabled: false, code: "platform_session_configuration_unavailable" });
  assert.throws(() => createHostedPlatformSessionComposition({ origin: "https://console.agentpass.test", rpId: "console.agentpass.test" }), /bootstrap authority is unavailable/);
});
