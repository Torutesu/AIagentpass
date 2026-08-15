import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import {
  createPlatformSessionWebAuthnService,
  PLATFORM_SESSION_WEBAUTHN_ERROR_CODES,
  PlatformSessionWebAuthnError
} from "../src/platform-session-webauthn.mjs";

const IDS = Object.freeze({
  principal: "11111111-1111-4111-8111-111111111111",
  member: "22222222-2222-4222-8222-222222222222",
  organization: "33333333-3333-4333-8333-333333333333",
  assignment: "44444444-4444-4444-8444-444444444444",
  challenge: "55555555-5555-4555-8555-555555555555",
  session: "66666666-6666-4666-8666-666666666666",
  jti: "77777777-7777-4777-8777-777777777777",
  platformCredential: "88888888-8888-4888-8888-888888888888",
  credential: Buffer.alloc(32, 7).toString("base64url")
});

const ORIGIN = "https://console.agentpass.test";
const RP_ID = "console.agentpass.test";
const CAPABILITY = "platform.promotion.issue";
const OPERATION = CAPABILITY;
const NOW = 1_800_000_000_000;

function deterministicRandom() {
  const uuids = [IDS.challenge, IDS.session, IDS.jti];
  const bytes = [Buffer.alloc(32, 1), Buffer.alloc(32, 2)];
  return {
    uuid: () => {
      const value = uuids.shift();
      if (!value) throw new Error("unexpected UUID request");
      return value;
    },
    bytes: () => {
      const value = bytes.shift();
      if (!value) throw new Error("unexpected random byte request");
      return value;
    }
  };
}

function context(overrides = {}) {
  return {
    principal_id: IDS.principal,
    member_id: IDS.member,
    organization_id: IDS.organization,
    assignment_id: IDS.assignment,
    authority_generation: 8,
    operation: OPERATION,
    capability: CAPABILITY,
    rp_id: RP_ID,
    origin: ORIGIN,
    user_verification: "required",
    ...overrides
  };
}

function makeRepository({ credential = {} } = {}) {
  const challenges = new Map();
  const sessions = new Map();
  const calls = [];
  const repository = {
    calls,
    challenges,
    sessions,
    async createPlatformSessionChallenge(record) {
      calls.push(["createChallenge", record]);
      challenges.set(record.challenge_id, clone(record));
      return clone(record);
    },
    async findPlatformSessionChallenge({ challenge_id }) {
      calls.push(["findChallenge", { challenge_id }]);
      return clone(challenges.get(challenge_id));
    },
    async claimPlatformSessionChallenge(input) {
      calls.push(["claimChallenge", input]);
      const row = challenges.get(input.challenge_id);
      if (!row) return { outcome: "replayed" };
      if (row.status === "consuming") return { outcome: "busy" };
      if (row.status !== "pending") return { outcome: row.status === "expired" ? "expired" : "replayed" };
      if (!row.challenge_hash.equals(input.challenge_hash) || !row.jti_hash.equals(input.jti_hash) || !row.binding_hash.equals(input.binding_hash)) return { outcome: "mismatch" };
      row.status = "consuming";
      return { claimed: true, record: clone(row) };
    },
    async failPlatformSessionChallenge(input) {
      calls.push(["failChallenge", input]);
      const row = challenges.get(input.challenge_id);
      if (row) row.status = "failed";
      return { outcome: "failed" };
    },
    async completePlatformSessionChallenge(input) {
      calls.push(["completeChallenge", input]);
      const row = challenges.get(input.challenge_id);
      if (!row || row.status !== "consuming") return { outcome: "invalid" };
      row.status = "consumed";
      return { outcome: "completed" };
    },
    async findPlatformCredentialForSession(input) {
      calls.push(["findCredential", input]);
      return {
        credential_id: input.credential_id,
        webauthn_credential_id: input.credential_id,
        platform_credential_id: IDS.platformCredential,
        principal_id: IDS.principal,
        member_id: IDS.member,
        status: "active",
        sign_count: 0,
        backup_eligible: false,
        backup_state: false,
        credential_device_type: "singleDevice",
        public_key: Buffer.alloc(32, 3),
        ...credential
      };
    },
    async advancePlatformCredentialCounter(input) {
      calls.push(["advanceCounter", input]);
      return { outcome: "accepted" };
    },
    async issuePlatformSession(input) {
      calls.push(["issueSession", input]);
      const session = {
        session_id: input.session_id,
        principal_id: input.principal_id,
        member_id: input.member_id,
        organization_id: input.organization_id,
        assignment_id: input.assignment_id,
        credential_id: IDS.platformCredential,
        operation: input.operation,
        capability: input.capability,
        status: "active",
        version: 1
      };
      sessions.set(input.session_id, session);
      return clone(session);
    }
  };
  return repository;
}

function beginInput(overrides = {}) { return context(overrides); }

function assertionFor(issued, overrides = {}) {
  const clientData = Buffer.from(JSON.stringify({ type: "webauthn.get", challenge: issued.challenge, origin: ORIGIN })).toString("base64url");
  const authenticatorData = Buffer.concat([
    crypto.createHash("sha256").update(RP_ID).digest(),
    Buffer.from([0x05]),
    Buffer.from([0, 0, 0, 1])
  ]).toString("base64url");
  return {
    challenge_id: issued.challenge_id,
    challenge: issued.challenge,
    jti: issued.jti,
    platform_session_id: issued.platform_session_id,
    credential_id: IDS.credential,
    client_data_json: clientData,
    authenticator_data: authenticatorData,
    signature: Buffer.alloc(64, 9).toString("base64url"),
    ...beginInput(),
    ...overrides
  };
}

function createService({ repository = makeRepository(), verifyAssertion, webauthnVerify, clock = () => NOW, random = deterministicRandom() } = {}) {
  return {
    repository,
    service: createPlatformSessionWebAuthnService({
      repository,
      verifyAssertion,
      webauthnVerify,
      now: clock,
      randomUUID: random.uuid,
      randomBytes: random.bytes,
      ttlMs: 60_000,
      sessionTtlSeconds: 120,
      sessionIdleTimeoutSeconds: 60
    })
  };
}

function clone(value) {
  if (value === undefined) return undefined;
  if (Buffer.isBuffer(value)) return Buffer.from(value);
  if (value instanceof Uint8Array) return Buffer.from(value);
  if (Array.isArray(value)) return value.map(clone);
  if (isObject(value)) return Object.fromEntries(Object.entries(value).map(([key, entry]) => [key, clone(entry)]));
  return value;
}

function isObject(value) { return value !== null && typeof value === "object" && !Array.isArray(value); }

function errorCode(code) {
  return (error) => error instanceof PlatformSessionWebAuthnError && error.code === code;
}

test("begin stores only hashes and returns platform-bound challenge material", async () => {
  const { service, repository } = createService();
  const issued = await service.begin(beginInput());
  const stored = repository.challenges.get(issued.challenge_id);

  assert.equal(issued.challenge, Buffer.alloc(32, 1).toString("base64url"));
  assert.equal(issued.jti, IDS.jti);
  assert.equal(issued.platform_session_id, IDS.session);
  assert.ok(Buffer.isBuffer(stored.challenge_hash));
  assert.ok(Buffer.isBuffer(stored.jti_hash));
  assert.ok(Buffer.isBuffer(stored.binding_hash));
  assert.equal(Object.hasOwn(stored, "challenge"), false);
  assert.equal(Object.hasOwn(stored, "jti"), false);
});

test("begin requires RP/origin compatibility and required user verification", async () => {
  const { service } = createService();
  await assert.rejects(() => service.begin(beginInput({ origin: "https://evil.example" })), errorCode(PLATFORM_SESSION_WEBAUTHN_ERROR_CODES.INVALID_CONTEXT));
  await assert.rejects(() => service.begin(beginInput({ user_verification: "preferred" })), errorCode(PLATFORM_SESSION_WEBAUTHN_ERROR_CODES.INVALID_CONTEXT));
});

test("verify binds operation, capability, principal, assignment, generation, RP, origin, and credential", async () => {
  const repository = makeRepository();
  const verifierInputs = [];
  const { service } = createService({ repository, verifyAssertion: async (input) => {
    verifierInputs.push(input);
    return { verified: true, credential_id: input.assertion.credential_id, sign_count: 1 };
  }});
  const issued = await service.begin(beginInput());
  const result = await service.verify(assertionFor(issued));

  assert.equal(result.session.session_id, IDS.session);
  assert.equal(typeof result.session_bearer, "string");
  assert.equal(result.session_bearer.length, 43);
  assert.equal(verifierInputs.length, 1);
  assert.deepEqual(verifierInputs[0].ceremony, {
    challenge_id: IDS.challenge,
    session_id: IDS.session,
    platform_session_id: IDS.session,
    principal_id: IDS.principal,
    member_id: IDS.member,
    organization_id: IDS.organization,
    assignment_id: IDS.assignment,
    authority_generation: 8,
    operation: OPERATION,
    capability: CAPABILITY,
    jti: IDS.jti,
    context_hash: verifierInputs[0].ceremony.context_hash,
    rp_id: RP_ID,
    origin: ORIGIN,
    user_verification: "required",
    expected_challenge: issued.challenge
  });
  assert.equal(repository.challenges.get(IDS.challenge).status, "consumed");
  const repoCallText = JSON.stringify(repository.calls, (_, value) => Buffer.isBuffer(value) ? { buffer_length: value.length, digest: value.toString("hex") } : value);
  assert.equal(repoCallText.includes(issued.challenge), false);
  assert.equal(repoCallText.includes(issued.jti), false);
  assert.equal(repoCallText.includes(assertionFor(issued).signature), false);
  const issue = repository.calls.find(([name]) => name === "issueSession")[1];
  assert.equal(Object.hasOwn(issue, "session_bearer"), false);
  assert.ok(Buffer.isBuffer(issue.session_material_hash));
  assert.equal(issue.session_material_hash.length, 32);
  assert.equal(issue.session_material_hash.toString("hex"), crypto.createHash("sha256").update(result.session_bearer).digest("hex"));
  assert.equal(issue.credential_id, IDS.platformCredential);
});

test("challenge/JTI mismatch fails before one-use claim", async () => {
  const repository = makeRepository();
  const { service } = createService({ repository, verifyAssertion: async () => ({ verified: true, credential_id: IDS.credential, sign_count: 1 }) });
  const issued = await service.begin(beginInput());

  await assert.rejects(() => service.verify(assertionFor(issued, { capability: "platform.other" })), errorCode(PLATFORM_SESSION_WEBAUTHN_ERROR_CODES.INVALID_CONTEXT));
  await assert.rejects(() => service.verify(assertionFor(issued, { jti: IDS.assignment })), errorCode(PLATFORM_SESSION_WEBAUTHN_ERROR_CODES.JTI_MISMATCH));
  assert.equal(repository.challenges.get(IDS.challenge).status, "pending");
  assert.equal(repository.calls.filter(([name]) => name === "claimChallenge").length, 0);
});

test("every authority binding field is exact and cannot be substituted", async () => {
  const fields = [
    ["operation", "platform.promotion.verify", undefined, PLATFORM_SESSION_WEBAUTHN_ERROR_CODES.INVALID_CONTEXT],
    ["capability", "platform.promotion.verify", undefined, PLATFORM_SESSION_WEBAUTHN_ERROR_CODES.INVALID_CONTEXT],
    ["principal_id", "99999999-9999-4999-8999-999999999999"],
    ["member_id", "99999999-9999-4999-8999-999999999999"],
    ["organization_id", "99999999-9999-4999-8999-999999999999"],
    ["assignment_id", "99999999-9999-4999-8999-999999999999"],
    ["authority_generation", 9],
    ["platform_session_id", "99999999-9999-4999-8999-999999999999"],
    ["rp_id", "other.agentpass.test", { rp_id: "other.agentpass.test", origin: "https://other.agentpass.test" }],
    ["origin", "https://other.agentpass.test", { rp_id: "other.agentpass.test", origin: "https://other.agentpass.test" }]
  ];
  for (const [field, value, pair, expectedCode = PLATFORM_SESSION_WEBAUTHN_ERROR_CODES.BINDING_MISMATCH] of fields) {
    const repository = makeRepository();
    const { service } = createService({ repository, verifyAssertion: async () => ({ verified: true, credential_id: IDS.credential, sign_count: 1 }) });
    const issued = await service.begin(beginInput());
    await assert.rejects(() => service.verify(assertionFor(issued, pair ?? { [field]: value })), errorCode(expectedCode));
    assert.equal(repository.challenges.get(IDS.challenge).status, "pending");
  }
});

test("successful verification never replays bearer material after a lost response", async () => {
  const repository = makeRepository();
  let verifierCalls = 0;
  const { service } = createService({ repository, verifyAssertion: async (input) => {
    verifierCalls += 1;
    return { verified: true, credential_id: input.assertion.credential_id, sign_count: 1 };
  }});
  const issued = await service.begin(beginInput());
  const request = assertionFor(issued);
  await service.verify(request);

  await assert.rejects(() => service.verify(request), errorCode(PLATFORM_SESSION_WEBAUTHN_ERROR_CODES.RESPONSE_LOST));
  assert.equal(verifierCalls, 1);
  assert.equal(repository.calls.filter(([name]) => name === "issueSession").length, 1);
  await assert.rejects(() => service.verify({ ...request, signature: Buffer.alloc(64, 8).toString("base64url") }), errorCode(PLATFORM_SESSION_WEBAUTHN_ERROR_CODES.CHALLENGE_REPLAYED));
});

test("verification failure burns the challenge and never issues a session", async () => {
  const repository = makeRepository();
  const { service } = createService({ repository, verifyAssertion: async () => { throw new Error("bad signature"); } });
  const issued = await service.begin(beginInput());
  await assert.rejects(() => service.verify(assertionFor(issued)), errorCode(PLATFORM_SESSION_WEBAUTHN_ERROR_CODES.VERIFICATION_FAILED));
  assert.equal(repository.challenges.get(IDS.challenge).status, "failed");
  assert.equal(repository.calls.filter(([name]) => name === "issueSession").length, 0);
  await assert.rejects(() => service.verify(assertionFor(issued)), errorCode(PLATFORM_SESSION_WEBAUTHN_ERROR_CODES.CHALLENGE_REPLAYED));
});

test("default verifier composes SimpleWebAuthn with platform credential lookup", async () => {
  const repository = makeRepository({ credential: { public_key: Buffer.alloc(32, 4) } });
  let verifierOptions;
  const { service } = createService({ repository, webauthnVerify: async (options) => {
    verifierOptions = options;
    return {
      verified: true,
      authenticationInfo: {
        credentialID: IDS.credential,
        userVerified: true,
        origin: ORIGIN,
        rpID: RP_ID,
        newCounter: 1,
        credentialDeviceType: "singleDevice",
        credentialBackedUp: false
      }
    };
  }});
  const issued = await service.begin(beginInput());
  await service.verify(assertionFor(issued));

  assert.equal(verifierOptions.expectedChallenge, issued.challenge);
  assert.equal(verifierOptions.expectedOrigin, ORIGIN);
  assert.equal(verifierOptions.expectedRPID, RP_ID);
  assert.equal(verifierOptions.requireUserVerification, true);
  const credentialLookup = repository.calls.find(([name]) => name === "findCredential")[1];
  assert.equal(credentialLookup.principal_id, IDS.principal);
  assert.equal(credentialLookup.member_id, IDS.member);
  assert.equal(credentialLookup.assignment_id, IDS.assignment);
  assert.equal(credentialLookup.authority_generation, 8);
});
