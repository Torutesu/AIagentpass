import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import { createPkceVerifierCodec } from "../../src/hosted-identity/pkce-verifier-codec.mjs";
import {
  POSTGRES_OAUTH_STATE_STORE_ERROR_CODES,
  createPostgresOAuthStateStore
} from "../../src/hosted-identity/postgres-oauth-state-store.mjs";

const ATTEMPT = "11111111-1111-4111-8111-111111111111";
const OAUTH = "22222222-2222-4222-8222-222222222222";
const REDIRECT = "https://console.example.test/api/auth/bootstrap/github/callback";
const STATE = `${OAUTH}.${"S".repeat(43)}`;
const STATE_HASH = crypto.createHash("sha256").update(STATE).digest("hex");
const VERIFIER = "V".repeat(43);
const CHALLENGE = crypto.createHash("sha256").update(VERIFIER).digest("base64url");
const NOW = Date.parse("2026-08-15T00:00:00.000Z");
const EXPIRES = NOW + 600_000;

function harness({ claimNull = false, mutateClaim } = {}) {
  let durable;
  const calls = [];
  const repository = {
    async startOAuthV2(input) {
      calls.push(["start", input]);
      durable = input;
      return { attempt_id: ATTEMPT, oauth_state_id: OAUTH, state_expires_at: new Date(EXPIRES).toISOString(), attempt_expires_at: new Date(EXPIRES + 300_000).toISOString() };
    },
    async claimOAuthStateV2(input) {
      calls.push(["claim", input]);
      if (claimNull) return null;
      const value = {
        attempt_id: ATTEMPT,
        oauth_state_id: OAUTH,
        pkce_challenge: CHALLENGE,
        client_id: "github-client",
        redirect_uri: REDIRECT,
        envelope: { key_id: durable.envelope.key_id, nonce: durable.envelope.nonce, ciphertext: durable.envelope.ciphertext, auth_tag: durable.envelope.auth_tag },
        expires_at: durable.envelope.expires_at
      };
      return mutateClaim ? mutateClaim(value) : value;
    },
    async failOAuthState(input) { calls.push(["fail", input]); return true; }
  };
  const codec = createPkceVerifierCodec({
    activeKeyId: "hosted-pkce-v1",
    keyResolver: () => Buffer.alloc(32, 7),
    randomBytes: () => Buffer.alloc(12, 8),
    now: () => NOW
  });
  return { store: createPostgresOAuthStateStore({ repository, verifierCodec: codec }), calls };
}

function createInput() {
  return { attemptId: ATTEMPT, oauthStateId: OAUTH, state: STATE, stateHash: STATE_HASH, pkceVerifier: VERIFIER, pkceChallenge: CHALLENGE, clientId: "github-client", redirectUri: REDIRECT, expiresAt: EXPIRES };
}

test("persists only an encrypted envelope and releases the verifier after an exact one-use claim", async () => {
  const { store, calls } = harness();
  assert.deepEqual(await store.create(createInput()), { attemptId: ATTEMPT, oauthStateId: OAUTH, expiresAt: EXPIRES });
  const start = calls[0][1];
  assert.equal(Object.hasOwn(start, "pkceVerifier"), false);
  assert.equal(JSON.stringify(start).includes(VERIFIER), false);
  assert.equal(start.state, STATE);
  assert.equal(start.envelope.expires_at, new Date(EXPIRES).toISOString());
  const result = await store.consume({ oauthStateId: OAUTH, state: STATE, stateHash: STATE_HASH, code: "oauth-code", redirectUri: REDIRECT });
  assert.deepEqual(result, { attemptId: ATTEMPT, oauthStateId: OAUTH, pkceVerifier: VERIFIER, pkceChallenge: CHALLENGE, redirectUri: REDIRECT, expiresAt: EXPIRES });
  assert.deepEqual(calls[1][1], { oauth_state_id: OAUTH, state: STATE, code: "oauth-code", redirect_uri: REDIRECT });
});

test("returns null for an absent/replayed durable claim", async () => {
  const { store } = harness({ claimNull: true });
  await store.create(createInput());
  assert.equal(await store.consume({ oauthStateId: OAUTH, state: STATE, stateHash: STATE_HASH, code: "oauth-code", redirectUri: REDIRECT }), null);
});

test("fails closed on envelope or authority substitution without exposing the verifier", async () => {
  const { store } = harness({ mutateClaim(value) { return { ...value, attempt_id: "33333333-3333-4333-8333-333333333333" }; } });
  await store.create(createInput());
  await assert.rejects(
    store.consume({ oauthStateId: OAUTH, state: STATE, stateHash: STATE_HASH, code: "oauth-code", redirectUri: REDIRECT }),
    (error) => error.code === POSTGRES_OAUTH_STATE_STORE_ERROR_CODES.UNAVAILABLE && !String(error).includes(VERIFIER)
  );
});

test("rejects unknown fields and malformed selectors before repository access", async () => {
  const { store, calls } = harness();
  await assert.rejects(store.create({ ...createInput(), role: "owner" }), { code: POSTGRES_OAUTH_STATE_STORE_ERROR_CODES.INPUT });
  await assert.rejects(store.consume({ oauthStateId: OAUTH, state: STATE, stateHash: "bad", code: "oauth-code", redirectUri: REDIRECT }), { code: POSTGRES_OAUTH_STATE_STORE_ERROR_CODES.INPUT });
  assert.equal(calls.length, 0);
});

test("durably fails a consuming callback with a closed failure code", async () => {
  const { store, calls } = harness();
  assert.equal(await store.fail({ oauthStateId: OAUTH, failureCode: "provider_unavailable" }), true);
  assert.deepEqual(calls, [["fail", { oauth_state_id: OAUTH, failure_code: "provider_unavailable" }]]);
  await assert.rejects(store.fail({ oauthStateId: OAUTH, failureCode: "Provider Secret" }), { code: POSTGRES_OAUTH_STATE_STORE_ERROR_CODES.INPUT });
});
