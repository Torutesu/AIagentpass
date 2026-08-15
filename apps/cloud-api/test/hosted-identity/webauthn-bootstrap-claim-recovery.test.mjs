import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import {
  HOSTED_WEBAUTHN_BOOTSTRAP_ERROR_CODES as CODES,
  createHostedWebAuthnBootstrapService
} from "../../src/hosted-identity/webauthn-bootstrap-service.mjs";

const IDS = Object.freeze({
  challenge: "11111111-1111-4111-8111-111111111111",
  attempt: "22222222-2222-4222-8222-222222222222",
  member: "33333333-3333-4333-8333-333333333333",
  organization: "44444444-4444-4444-8444-444444444444",
  membership: "55555555-5555-4555-8555-555555555555",
  session: "66666666-6666-4666-8666-666666666666"
});
const ORIGIN = "https://console.example.test";
const RP_ID = "console.example.test";
const BOOTSTRAP = Buffer.alloc(32, 0x11).toString("base64url");
const CREDENTIAL_ID = Buffer.alloc(32, 0x22).toString("base64url");
const PUBLIC_KEY = Buffer.alloc(65, 0x33);
const RESPONSE_KEY = Buffer.alloc(32, 0x44);
const CHALLENGE = Buffer.alloc(32, 0x55).toString("base64url");
const NOW = Date.parse("2026-08-15T00:00:00.000Z");

function clientData(challenge, overrides = {}) {
  return Buffer.from(JSON.stringify({
    type: "webauthn.create",
    challenge,
    origin: ORIGIN,
    crossOrigin: false,
    ...overrides
  })).toString("base64url");
}

function request({ attestationByte = 0x66, clientDataOverrides = {} } = {}) {
  return {
    bootstrap_token: BOOTSTRAP,
    challenge_id: IDS.challenge,
    credential: {
      credential_id: CREDENTIAL_ID,
      client_data_json: clientData(CHALLENGE, clientDataOverrides),
      attestation_object: Buffer.alloc(64, attestationByte).toString("base64url"),
      transports: ["internal"]
    },
    rp_id: RP_ID,
    origin: ORIGIN,
    user_verification: "required"
  };
}

function binding() {
  return {
    attempt_id: IDS.attempt,
    member_id: IDS.member,
    organization_id: IDS.organization,
    rp_id: RP_ID,
    origin: ORIGIN,
    user_verification: "required"
  };
}

function session() {
  return {
    version: 1,
    session_id: IDS.session,
    member_id: IDS.member,
    organization_id: IDS.organization,
    role: "owner",
    created_at: new Date(NOW).toISOString(),
    expires_at: new Date(NOW + 8 * 60 * 60 * 1000).toISOString(),
    recent_auth_at: null
  };
}

function verifier() {
  return {
    async generateOptions(input) {
      return {
        challenge: input.challenge,
        rp: { id: input.rp.id, name: input.rp.name },
        user: { id: input.user.id, name: input.user.name, displayName: input.user.displayName },
        pubKeyCredParams: [{ type: "public-key", alg: -7 }],
        timeout: input.timeout,
        attestation: "none",
        excludeCredentials: [],
        authenticatorSelection: { residentKey: "preferred", userVerification: "required" },
        extensions: { credProps: true },
        hints: []
      };
    },
    async verifyAttestation(input) {
      return {
        verified: true,
        credential_id: input.attestation.credential_id,
        public_key: PUBLIC_KEY,
        sign_count: 0,
        transports: ["internal"],
        credential_device_type: "singleDevice",
        credential_backed_up: false,
        user_verified: true
      };
    }
  };
}

function repositoryFixture({ claim = () => "claimed" } = {}) {
  const calls = Object.freeze({
    claim: [],
    consume: [],
    replay: [],
    complete: [],
    fail: [],
    sql: [],
    logs: []
  });
  let completed = false;

  const repo = {
    async createChallenge() {
      return {
        challenge_id: IDS.challenge,
        member_id: IDS.member,
        organization_id: IDS.organization,
        rp_id: RP_ID,
        origin: ORIGIN,
        expires_at: new Date(NOW + 120_000).toISOString()
      };
    },

    // This is the lease-aware boundary that the implementation must add. The
    // fake SQL adapter intentionally receives only a SHA-256 digest.
    async claimChallengeV2(input) {
      calls.claim.push(structuredClone(input));
      const digest = sha256(input.claim_token);
      calls.sql.push({
        text: "SELECT * FROM agentpass_hosted_identity_bootstrap_webauthn_claim_v2($1,$2,$3,$4)",
        params: [input.challenge_id, digest, input.challenge, input.bootstrap_cookie]
      });
      calls.logs.push({ event: "webauthn_claim", challenge_id: input.challenge_id, outcome: "durable" });
      const outcome = await claim(input, { completed, calls });
      if (outcome === null) return null;
      if (!["claimed", "reclaimed", "replayed"].includes(outcome)) return null;
      return { ...binding(), claim_state: outcome, claim_generation: outcome === "reclaimed" ? 2 : 1, claim_expires_at: new Date(NOW + 30_000).toISOString() };
    },

    async completeWebAuthnRegistrationV3(input) {
      calls.complete.push(structuredClone(input));
      calls.sql.push({
        text: "SELECT * FROM agentpass_hosted_identity_bootstrap_webauthn_complete_v3($1,$2)",
        params: [input.attempt_id, sha256(input.claim_token ?? "missing-claim-token")]
      });
      completed = true;
      return {
        attempt_id: IDS.attempt,
        membership_id: IDS.membership,
        replayed: calls.complete.length > 1,
        session: session()
      };
    },
    async failChallengeV3(input) {
      calls.fail.push(structuredClone(input));
      return true;
    }
  };

  return { calls, repository: repo };
}

function service(repository, randomBytes = () => Buffer.alloc(32, 0x77)) {
  return createHostedWebAuthnBootstrapService({
    repository,
    registrationVerifier: verifier(),
    responseKey: RESPONSE_KEY,
    rpId: RP_ID,
    origin: ORIGIN,
    now: () => NOW,
    randomUUID: () => IDS.challenge,
    randomBytes
  });
}

function sha256(value) {
  return crypto.createHash("sha256").update(value, "utf8").digest();
}

test("derives one deterministic claim token from one exact browser response", async () => {
  const firstFixture = repositoryFixture();
  const first = await service(firstFixture.repository).verify(request());
  const restartedFixture = repositoryFixture({
    claim(input) {
      assert.equal(input.claim_token, firstFixture.calls.claim[0].claim_token);
      return "replayed";
    }
  });
  const retry = await service(restartedFixture.repository).verify(request());

  assert.match(firstFixture.calls.claim[0].claim_token, /^[A-Za-z0-9_-]{43}$/u);
  assert.equal(restartedFixture.calls.claim[0].claim_token, firstFixture.calls.claim[0].claim_token);
  assert.equal(retry.session_token, first.session_token);
  assert.equal(retry.csrf_token, first.csrf_token);
});

test("recovers an identical response after a process restart without a new claim", async () => {
  const state = { claimToken: null, completed: false };
  const makeRepository = () => repositoryFixture({
    claim(input) {
      if (state.claimToken === null) {
        state.claimToken = input.claim_token;
        return "claimed";
      }
      return input.claim_token === state.claimToken ? "replayed" : null;
    }
  });

  const firstFixture = makeRepository();
  const first = await service(firstFixture.repository).verify(request());
  state.completed = true;
  const secondFixture = makeRepository();
  const second = await service(secondFixture.repository).verify(request());

  assert.equal(second.session_token, first.session_token);
  assert.equal(second.csrf_token, first.csrf_token);
  assert.equal(second.session.session_id, IDS.session);
  assert.equal(secondFixture.calls.complete.length, 1);
  assert.equal(secondFixture.calls.complete[0].claim_token, state.claimToken);
});

test("reclaims an expired unstarted lease and completes exactly once", async () => {
  const fixture = repositoryFixture({
    claim(input, state) {
      assert.equal(state.completed, false);
      assert.equal(input.claim_token.length, 43);
      return "reclaimed";
    }
  });
  const result = await service(fixture.repository).verify(request());

  assert.equal(result.session.session_id, IDS.session);
  assert.equal(fixture.calls.claim.length, 1);
  assert.equal(fixture.calls.complete.length, 1);
  assert.equal(fixture.calls.complete[0].claim_token, fixture.calls.claim[0].claim_token);
  assert.equal(fixture.calls.complete[0].claim_generation, 2);
});

test("fails closed when an expired lease may already have started verification", async () => {
  const fixture = repositoryFixture({ claim: () => null });
  await assert.rejects(
    service(fixture.repository).verify(request()),
    (error) => error.code === CODES.REPLAYED
  );
  assert.equal(fixture.calls.complete.length, 0);
  assert.equal(fixture.calls.fail.length, 0, "an ambiguous lease must not be burned by a second worker");
});

test("rejects a changed browser response after a claim has been committed", async () => {
  let claimToken;
  const fixture = repositoryFixture({
    claim(input) {
      if (claimToken === undefined) {
        claimToken = input.claim_token;
        return "claimed";
      }
      return input.claim_token === claimToken ? "replayed" : null;
    }
  });
  const firstService = service(fixture.repository);
  await firstService.verify(request());
  const secondService = service(fixture.repository);

  await assert.rejects(
    secondService.verify(request({ attestationByte: 0x67 })),
    (error) => error.code === CODES.REPLAYED
  );
  assert.equal(fixture.calls.complete.length, 1);
  assert.notEqual(fixture.calls.claim[0].claim_token, fixture.calls.claim[1].claim_token);
});

test("never sends or logs the raw claim token at the SQL boundary", async () => {
  const fixture = repositoryFixture();
  await service(fixture.repository).verify(request());
  const rawClaimToken = fixture.calls.claim[0].claim_token;
  const serializedSql = JSON.stringify(fixture.calls.sql);
  const serializedLogs = JSON.stringify(fixture.calls.logs);

  assert.equal(fixture.calls.sql.some(({ params }) => params.some((value) => value === rawClaimToken)), false);
  assert.equal(serializedSql.includes(rawClaimToken), false);
  assert.equal(serializedLogs.includes(rawClaimToken), false);
  assert.equal(
    fixture.calls.sql.some(({ params }) => params.some((value) => Buffer.isBuffer(value) && value.equals(sha256(rawClaimToken)))),
    true
  );
});
