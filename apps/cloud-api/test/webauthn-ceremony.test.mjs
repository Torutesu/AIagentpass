import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";
import { createWebAuthnCeremony, WebAuthnCeremonyError, WEBAUTHN_ERROR_CODES } from "../src/human-auth/webauthn/ceremony.mjs";

const context = Object.freeze({ session_id: "session-01", organization_id: "org-01", operation: "device.enrollment.issue", rp_id: "console.example.test", origin: "https://console.example.test", user_verification: "required" });

function clock(start = 1_900_000_000_000) {
  let value = start;
  return { now: () => value, advance: (ms) => { value += ms; } };
}

function response(challenge, contextOverrides = {}) {
  const merged = { ...context, ...contextOverrides };
  const credential_id = Buffer.from("credential-01").toString("base64url");
  const client_data_json = Buffer.from(JSON.stringify({ type: "webauthn.get", challenge, origin: merged.origin, crossOrigin: false })).toString("base64url");
  const rp_hash = crypto.createHash("sha256").update(merged.rp_id).digest();
  const authenticator_data = Buffer.concat([rp_hash, Buffer.from([0x05]), Buffer.from([0, 0, 0, 1])]).toString("base64url");
  return { challenge, ...merged, challenge_id: contextOverrides.challenge_id, credential_id, client_data_json, authenticator_data, signature: Buffer.alloc(64, 7).toString("base64url") };
}

function verifier() {
  const calls = [];
  const verifyAssertion = async (input) => { calls.push(input); return { verified: true, credential_id: input.assertion.credential_id, sign_count: input.parsed.authenticator_data.sign_count }; };
  return { verifyAssertion, calls };
}

function issue(coordinator, contextOverrides = {}) {
  return coordinator.begin({ ...context, ...contextOverrides });
}

test("issues a short-lived challenge and exposes no raw secret in the coordinator snapshot", () => {
  const time = clock();
  const { verifyAssertion } = verifier();
  const coordinator = createWebAuthnCeremony({ verifyAssertion, now: time.now, ttlMs: 60_000 });
  const issued = issue(coordinator);
  assert.match(issued.challenge, /^[A-Za-z0-9_-]{43}$/);
  assert.equal(issued.challenge_expires_at, new Date(time.now() + 60_000).toISOString());
  const snapshot = coordinator.snapshot();
  assert.equal(snapshot.length, 1);
  assert.equal(Object.hasOwn(snapshot[0], "challenge"), false);
  assert.equal(Object.hasOwn(snapshot[0], "challenge_digest"), false);
  assert.equal(JSON.stringify(snapshot).includes(issued.challenge), false);
  assert.equal(JSON.stringify(snapshot).includes("credential-01"), false);
});

test("strictly validates client data, rp id hash, user verification, and adapter result", async () => {
  const time = clock();
  const { verifyAssertion, calls } = verifier();
  const coordinator = createWebAuthnCeremony({ verifyAssertion, now: time.now });
  const issued = issue(coordinator);
  const request = response(issued.challenge, { challenge_id: issued.challenge_id });
  const result = await coordinator.consume(request);
  assert.equal(result.verified, true);
  assert.equal(result.session_id, context.session_id);
  assert.equal(result.organization_id, context.organization_id);
  assert.equal(result.operation, context.operation);
  assert.equal(result.authenticated_at, time.now());
  assert.equal(calls.length, 1);
  assert.equal(calls[0].ceremony.expected_challenge, issued.challenge);
  assert.equal(calls[0].assertion.signature, request.signature);

  for (const mutation of [
    { client_data_json: Buffer.from(JSON.stringify({ type: "webauthn.create", challenge: issued.challenge, origin: context.origin })).toString("base64url") },
    { authenticator_data: Buffer.concat([Buffer.alloc(32), Buffer.from([0x05]), Buffer.alloc(4)]).toString("base64url") },
    { authenticator_data: Buffer.concat([crypto.createHash("sha256").update(context.rp_id).digest(), Buffer.from([0x01]), Buffer.alloc(4)]).toString("base64url") }
  ]) {
    const c = createWebAuthnCeremony({ verifyAssertion, now: time.now });
    const next = issue(c);
    await assert.rejects(() => c.consume({ ...response(next.challenge, { challenge_id: next.challenge_id }), ...mutation }), (error) => error.code === WEBAUTHN_ERROR_CODES.INVALID_RESPONSE);
  }
});

test("binds a challenge to session, organization, and operation", async () => {
  const time = clock();
  const { verifyAssertion } = verifier();
  const coordinator = createWebAuthnCeremony({ verifyAssertion, now: time.now });
  const issued = issue(coordinator);
  for (const field of ["session_id", "organization_id", "operation"]) {
    const wrong = response(issued.challenge, { challenge_id: issued.challenge_id, [field]: `wrong-${field}` });
    await assert.rejects(() => coordinator.consume(wrong), (error) => error instanceof WebAuthnCeremonyError && error.code === WEBAUTHN_ERROR_CODES.BINDING_MISMATCH);
  }
  const valid = response(issued.challenge, { challenge_id: issued.challenge_id });
  await coordinator.consume(valid);
});

test("rejects replay and atomically permits only one concurrent consume", async () => {
  const time = clock();
  let release;
  const gate = new Promise((resolve) => { release = resolve; });
  let calls = 0;
  const coordinator = createWebAuthnCeremony({ now: time.now, verifyAssertion: async (input) => { calls += 1; await gate; return { verified: true, credential_id: input.assertion.credential_id }; } });
  const issued = issue(coordinator);
  const request = response(issued.challenge, { challenge_id: issued.challenge_id });
  const first = coordinator.consume(request);
  await new Promise((resolve) => setImmediate(resolve));
  const second = coordinator.consume(request);
  await assert.rejects(second, (error) => error.code === WEBAUTHN_ERROR_CODES.CHALLENGE_BUSY);
  release();
  await first;
  assert.equal(calls, 1);
  await assert.rejects(() => coordinator.consume(request), (error) => error.code === WEBAUTHN_ERROR_CODES.CHALLENGE_REPLAYED);
});

test("rejects expiry and challenge substitution without retaining raw challenge material", async () => {
  const time = clock();
  const { verifyAssertion } = verifier();
  const coordinator = createWebAuthnCeremony({ verifyAssertion, now: time.now, ttlMs: 2_000 });
  const issued = issue(coordinator);
  time.advance(2_000);
  await assert.rejects(() => coordinator.consume(response(issued.challenge, { challenge_id: issued.challenge_id })), (error) => error.code === WEBAUTHN_ERROR_CODES.CHALLENGE_EXPIRED);
  const next = issue(coordinator);
  const substitutedBytes = Buffer.from(next.challenge, "base64url");
  substitutedBytes[0] ^= 0x01;
  const substitutedChallenge = substitutedBytes.toString("base64url");
  await assert.rejects(() => coordinator.consume(response(substitutedChallenge, { challenge_id: next.challenge_id })), (error) => error.code === WEBAUTHN_ERROR_CODES.CHALLENGE_MISMATCH);
});

test("burns a challenge after verifier failure and rejects malformed verifier output", async () => {
  const time = clock();
  const coordinator = createWebAuthnCeremony({ now: time.now, verifyAssertion: async () => { throw new Error("signature invalid"); } });
  const issued = issue(coordinator);
  const request = response(issued.challenge, { challenge_id: issued.challenge_id });
  await assert.rejects(() => coordinator.consume(request), (error) => error.code === WEBAUTHN_ERROR_CODES.VERIFICATION_FAILED);
  await assert.rejects(() => coordinator.consume(request), (error) => error.code === WEBAUTHN_ERROR_CODES.CHALLENGE_REPLAYED);

  const malformed = createWebAuthnCeremony({ now: time.now, verifyAssertion: async () => ({ verified: true, credential_id: "other" }) });
  const next = issue(malformed);
  await assert.rejects(() => malformed.consume(response(next.challenge, { challenge_id: next.challenge_id })), (error) => error.code === WEBAUTHN_ERROR_CODES.INVALID_VERIFIER_RESULT);
  await assert.rejects(() => malformed.consume(response(next.challenge, { challenge_id: next.challenge_id })), (error) => error.code === WEBAUTHN_ERROR_CODES.CHALLENGE_REPLAYED);
});
