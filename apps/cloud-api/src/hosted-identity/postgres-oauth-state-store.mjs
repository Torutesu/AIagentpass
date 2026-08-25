import crypto from "node:crypto";

import { PKCE_VERIFIER_CODEC_VERSION } from "./pkce-verifier-codec.mjs";

const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
const SHA256_HEX = /^[0-9a-f]{64}$/u;
const PKCE = /^[A-Za-z0-9_-]{43}$/u;

export const POSTGRES_OAUTH_STATE_STORE_ERROR_CODES = Object.freeze({
  CONFIG: "hosted_oauth_state_store_config_invalid",
  INPUT: "hosted_oauth_state_store_input_invalid",
  UNAVAILABLE: "hosted_oauth_state_store_unavailable"
});

export class PostgresOAuthStateStoreError extends Error {
  constructor(code) {
    super(code === POSTGRES_OAUTH_STATE_STORE_ERROR_CODES.CONFIG
      ? "Hosted OAuth state store configuration is invalid"
      : code === POSTGRES_OAUTH_STATE_STORE_ERROR_CODES.INPUT
        ? "Hosted OAuth state request is invalid"
        : "Hosted OAuth state store is unavailable");
    this.name = "PostgresOAuthStateStoreError";
    this.code = code;
  }
}

/**
 * Bridges the GitHub adapter to migration 0058. PKCE plaintext exists only in
 * this call frame and the codec; PostgreSQL receives an AEAD envelope and
 * returns it exactly once after state/code/redirect binding succeeds.
 */
export function createPostgresOAuthStateStore({ repository, verifierCodec } = {}) {
  requireMethods(repository, ["startOAuthV2", "claimOAuthStateV2", "failOAuthState"], "repository");
  requireMethods(verifierCodec, ["seal", "open"], "verifierCodec");

  async function create(input = {}) {
    const value = normalizeCreate(input);
    const serialized = callCodec(() => verifierCodec.seal({
      verifier: value.pkceVerifier,
      attemptId: value.attemptId,
      oauthStateId: value.oauthStateId,
      redirectUri: value.redirectUri,
      expiresAt: value.expiresAt
    }));
    const envelope = parseCodecEnvelope(serialized, value.expiresAt);
    let result;
    try {
      result = await repository.startOAuthV2({
        attempt_id: value.attemptId,
        oauth_state_id: value.oauthStateId,
        state: value.state,
        pkce_challenge: value.pkceChallenge,
        client_id: value.clientId,
        redirect_uri: value.redirectUri,
        envelope
      });
    } catch {
      throw unavailable();
    }
    const stored = normalizeStartResult(result, value);
    return Object.freeze({ attemptId: stored.attemptId, oauthStateId: stored.oauthStateId, expiresAt: value.expiresAt });
  }

  async function consume(input = {}) {
    const value = normalizeConsume(input);
    let claimed;
    try {
      claimed = await repository.claimOAuthStateV2({
        oauth_state_id: value.oauthStateId,
        state: value.state,
        code: value.code,
        redirect_uri: value.redirectUri
      });
    } catch {
      throw unavailable();
    }
    if (claimed === null) return null;
    const record = normalizeClaimResult(claimed, value);
    const serialized = JSON.stringify({
      version: PKCE_VERIFIER_CODEC_VERSION,
      key_id: record.envelope.key_id,
      nonce: record.envelope.nonce.toString("base64url"),
      ciphertext: record.envelope.ciphertext.toString("base64url"),
      tag: record.envelope.auth_tag.toString("base64url")
    });
    const opened = callCodec(() => verifierCodec.open(serialized, {
      attemptId: record.attemptId,
      oauthStateId: record.oauthStateId,
      redirectUri: record.redirectUri,
      expiresAt: record.expiresAt
    }));
    if (!plainObject(opened) || Object.keys(opened).join("\u0000") !== "verifier" || typeof opened.verifier !== "string" || !/^[A-Za-z0-9._~-]{43,128}$/u.test(opened.verifier)) throw unavailable();
    return Object.freeze({
      attemptId: record.attemptId,
      oauthStateId: record.oauthStateId,
      pkceVerifier: opened.verifier,
      pkceChallenge: record.pkceChallenge,
      redirectUri: record.redirectUri,
      expiresAt: record.expiresAt
    });
  }

  async function fail(input = {}) {
    exact(input, ["oauthStateId", "failureCode"]);
    if (!UUID_V4.test(input.oauthStateId) || !/^[a-z][a-z0-9_]{0,63}$/u.test(input.failureCode)) throw inputError();
    try {
      await repository.failOAuthState({ oauth_state_id: input.oauthStateId.toLowerCase(), failure_code: input.failureCode });
    } catch {
      throw unavailable();
    }
    return true;
  }

  return Object.freeze({ create, consume, fail });
}

function normalizeCreate(value) {
  exact(value, ["attemptId", "oauthStateId", "state", "stateHash", "pkceVerifier", "pkceChallenge", "clientId", "redirectUri", "expiresAt"]);
  if (!UUID_V4.test(value.attemptId) || !UUID_V4.test(value.oauthStateId) || !SHA256_HEX.test(value.stateHash)
    || typeof value.pkceVerifier !== "string" || !/^[A-Za-z0-9._~-]{43,128}$/u.test(value.pkceVerifier)
    || typeof value.pkceChallenge !== "string" || !PKCE.test(value.pkceChallenge)
    || !bounded(value.clientId, 256) || !https(value.redirectUri) || !Number.isSafeInteger(value.expiresAt) || value.expiresAt < 1) throw inputError();
  // The repository owns hashing. Reconstructing the raw state is impossible
  // from stateHash, so the adapter must also provide the exact state selector.
  if (!bounded(value.state, 512) || sha256Hex(value.state) !== value.stateHash) throw inputError();
  return Object.freeze({ ...value, attemptId: value.attemptId.toLowerCase(), oauthStateId: value.oauthStateId.toLowerCase() });
}

function normalizeConsume(value) {
  exact(value, ["oauthStateId", "stateHash", "state", "code", "redirectUri"]);
  if (!UUID_V4.test(value.oauthStateId) || !SHA256_HEX.test(value.stateHash) || !bounded(value.state, 512) || sha256Hex(value.state) !== value.stateHash || !bounded(value.code, 2048) || !https(value.redirectUri)) throw inputError();
  return Object.freeze({ ...value, oauthStateId: value.oauthStateId.toLowerCase() });
}

function parseCodecEnvelope(serialized, expiresAt) {
  let value;
  try { value = JSON.parse(serialized); } catch { throw unavailable(); }
  if (!plainObject(value) || Object.keys(value).join("\u0000") !== "version\u0000key_id\u0000nonce\u0000ciphertext\u0000tag" || value.version !== PKCE_VERIFIER_CODEC_VERSION) throw unavailable();
  return Object.freeze({
    key_id: value.key_id,
    nonce: canonicalBytes(value.nonce),
    ciphertext: canonicalBytes(value.ciphertext),
    auth_tag: canonicalBytes(value.tag),
    expires_at: new Date(expiresAt).toISOString()
  });
}

function normalizeStartResult(value, expected) {
  if (!plainObject(value) || !sameKeys(value, ["attempt_id", "oauth_state_id", "state_expires_at", "attempt_expires_at"])
    || value.attempt_id !== expected.attemptId || value.oauth_state_id !== expected.oauthStateId
    || !validTimestamp(value.state_expires_at) || !validTimestamp(value.attempt_expires_at)
    || Date.parse(value.state_expires_at) < expected.expiresAt || Date.parse(value.attempt_expires_at) < Date.parse(value.state_expires_at)) throw unavailable();
  return { attemptId: value.attempt_id, oauthStateId: value.oauth_state_id };
}

function normalizeClaimResult(value, expected) {
  if (!plainObject(value) || !sameKeys(value, ["attempt_id", "oauth_state_id", "pkce_challenge", "client_id", "redirect_uri", "envelope", "expires_at"])
    || !UUID_V4.test(value.attempt_id) || value.oauth_state_id !== expected.oauthStateId || !PKCE.test(value.pkce_challenge)
    || !bounded(value.client_id, 256) || value.redirect_uri !== expected.redirectUri || !validTimestamp(value.expires_at)
    || !plainObject(value.envelope) || !sameKeys(value.envelope, ["key_id", "nonce", "ciphertext", "auth_tag"])) throw unavailable();
  return Object.freeze({
    attemptId: value.attempt_id.toLowerCase(), oauthStateId: value.oauth_state_id.toLowerCase(), pkceChallenge: value.pkce_challenge,
    redirectUri: value.redirect_uri, expiresAt: Date.parse(value.expires_at),
    envelope: Object.freeze({ key_id: value.envelope.key_id, nonce: Buffer.from(value.envelope.nonce), ciphertext: Buffer.from(value.envelope.ciphertext), auth_tag: Buffer.from(value.envelope.auth_tag) })
  });
}

function exact(value, keys) { if (!plainObject(value) || !sameKeys(value, keys)) throw inputError(); }
function sameKeys(value, keys) { const actual = Object.keys(value).sort(); const expected = [...keys].sort(); return actual.length === expected.length && actual.every((key, index) => key === expected[index]); }
function plainObject(value) { return value !== null && typeof value === "object" && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype; }
function bounded(value, max) { return typeof value === "string" && value.length > 0 && value.length <= max && !/[\u0000-\u001f\u007f]/u.test(value); }
function https(value) { if (!bounded(value, 2048)) return false; try { const url = new URL(value); return url.protocol === "https:" && !url.username && !url.password && !url.hash; } catch { return false; } }
function canonicalBytes(value) { if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/u.test(value)) throw unavailable(); const bytes = Buffer.from(value, "base64url"); if (bytes.toString("base64url") !== value) throw unavailable(); return bytes; }
function validTimestamp(value) { return typeof value === "string" && Number.isFinite(Date.parse(value)); }
function sha256Hex(value) { return crypto.createHash("sha256").update(value, "utf8").digest("hex"); }
function requireMethods(value, methods, name) { if (!value || typeof value !== "object" || methods.some((method) => typeof value[method] !== "function")) throw new PostgresOAuthStateStoreError(POSTGRES_OAUTH_STATE_STORE_ERROR_CODES.CONFIG); void name; }
function callCodec(operation) { try { return operation(); } catch { throw unavailable(); } }
function inputError() { return new PostgresOAuthStateStoreError(POSTGRES_OAUTH_STATE_STORE_ERROR_CODES.INPUT); }
function unavailable() { return new PostgresOAuthStateStoreError(POSTGRES_OAUTH_STATE_STORE_ERROR_CODES.UNAVAILABLE); }

export default createPostgresOAuthStateStore;
