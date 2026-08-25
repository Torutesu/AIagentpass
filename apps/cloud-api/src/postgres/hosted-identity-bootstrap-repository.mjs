import crypto from "node:crypto";

import { normalizeHostedOrganizationName } from "../hosted-identity/organization-name.mjs";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
const DIGEST = /^[0-9a-f]{64}$/iu;
const PKCE = /^[A-Za-z0-9_-]{43,128}$/u;
const FAILURE_CODE = /^[a-z][a-z0-9_]{0,63}$/u;
const IDEMPOTENCY_KEY = /^[A-Za-z0-9._~-]{8,255}$/u;
const RP_ID = /^[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$/u;
const ORIGIN = /^https:\/\/[^/?#@]+(?::[0-9]{1,5})?$/u;
const TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$/u;
const CONTROL = /[\u0000-\u001f\u007f]/u;
const MAX_SELECTOR_BYTES = 16 * 1024;
const MAX_SUBJECT_BYTES = 512;
const KEY_ID = /^[A-Za-z0-9._~-]{1,128}$/u;
const GITHUB_SUBJECT = /^[1-9][0-9]{0,19}$/u;
const OPAQUE_TOKEN = /^[A-Za-z0-9_-]{43}$/u;
const WEBAUTHN_TRANSPORTS = new Set(["ble", "cable", "hybrid", "internal", "nfc", "smart-card", "usb"]);
const OAUTH_COMPLETE_V2_STATES = Object.freeze(["identity_verified", "organization_required", "no_membership"]);

export const HOSTED_IDENTITY_BOOTSTRAP_REPOSITORY_METHODS = Object.freeze([
  "start",
  "startOAuthV2",
  "consumeOAuthState",
  "claimOAuthStateV2",
  "completeOAuthState",
  "completeOAuthStateV2",
  "failOAuthState",
  "issueCsrf",
  "getBootstrapStatus",
  "verifyBootstrapCsrf",
  "commitOrganization",
  "commitOrganizationV2",
  "createChallenge",
  "claimChallengeV2",
  "consumeChallenge",
  "getWebAuthnReplayContext",
  "completeWebAuthnRegistrationV3",
  "completeWebAuthnRegistrationV2",
  "completeChallenge",
  "failChallengeV3",
  "failChallenge"
]);

export const HOSTED_IDENTITY_BOOTSTRAP_REPOSITORY_SQL = Object.freeze({
  start: "SELECT * FROM public.agentpass_hosted_identity_bootstrap_start($1::uuid,$2::uuid,$3::bytea,$4::text,$5::text,$6::text)",
  startOAuthV2: "SELECT * FROM public.agentpass_hosted_identity_bootstrap_start_v2($1::uuid,$2::uuid,$3::bytea,$4::text,$5::text,$6::text,$7::text,$8::bytea,$9::bytea,$10::bytea,$11::timestamptz)",
  consumeOAuthState: "SELECT * FROM public.agentpass_hosted_identity_oauth_state_consume($1::uuid,$2::bytea,$3::text)",
  claimOAuthStateV2: "SELECT * FROM public.agentpass_hosted_identity_oauth_state_claim_v2($1::uuid,$2::bytea,$3::bytea,$4::text)",
  completeOAuthState: "SELECT public.agentpass_hosted_identity_oauth_state_complete($1::uuid,$2::bytea,$3::uuid,$4::text,$5::bytea) AS result",
  completeOAuthStateV2: "SELECT * FROM public.agentpass_hosted_identity_oauth_complete_v2($1::uuid,$2::uuid,$3::bytea,$4::uuid,$5::text,$6::text,$7::bytea)",
  failOAuthState: "SELECT public.agentpass_hosted_identity_oauth_state_fail($1::uuid,$2::text) AS result",
  issueCsrf: "SELECT public.agentpass_hosted_identity_bootstrap_csrf_issue($1::bytea,$2::bytea) AS result",
  getBootstrapStatus: "SELECT * FROM public.agentpass_hosted_identity_bootstrap_status_v2($1::bytea,$2::bytea)",
  verifyBootstrapCsrf: "SELECT public.agentpass_hosted_identity_bootstrap_csrf_verify_v2($1::bytea,$2::bytea) AS result",
  commitOrganization: "SELECT * FROM public.agentpass_hosted_identity_bootstrap_organization_commit($1::bytea,$2::text,$3::bytea,$4::uuid,$5::uuid,$6::jsonb)",
  commitOrganizationV2: "SELECT * FROM public.agentpass_hosted_identity_bootstrap_organization_commit_v2($1::bytea,$2::text,$3::bytea,$4::text,$5::uuid,$6::uuid,$7::uuid)",
  createChallenge: "SELECT * FROM public.agentpass_hosted_identity_bootstrap_challenge_create($1::bytea,$2::uuid,$3::bytea,$4::text,$5::text,$6::timestamptz)",
  claimChallengeV2: "SELECT * FROM public.agentpass_hosted_identity_bootstrap_webauthn_claim_v2($1::bytea,$2::uuid,$3::bytea,$4::bytea)",
  consumeChallenge: "SELECT * FROM public.agentpass_hosted_identity_bootstrap_challenge_consume($1::bytea,$2::uuid,$3::bytea)",
  getWebAuthnReplayContext: "SELECT * FROM public.agentpass_hosted_identity_bootstrap_webauthn_replay_context($1::bytea,$2::uuid,$3::bytea)",
  completeWebAuthnRegistrationV3: "SELECT * FROM public.agentpass_hosted_identity_bootstrap_webauthn_complete_v3($1::uuid,$2::bytea,$3::uuid,$4::bytea,$5::bytea,$6::bigint,$7::bytea,$8::bytea,$9::bytea,$10::bigint,$11::text[],$12::text,$13::boolean,$14::boolean,$15::bytea,$16::bytea)",
  completeWebAuthnRegistrationV2: "SELECT * FROM public.agentpass_hosted_identity_bootstrap_webauthn_complete_v2($1::uuid,$2::bytea,$3::uuid,$4::bytea,$5::bytea,$6::bytea,$7::bytea,$8::bigint,$9::text[],$10::text,$11::boolean,$12::boolean,$13::bytea,$14::bytea)",
  completeChallenge: "SELECT public.agentpass_hosted_identity_bootstrap_challenge_complete($1::bytea,$2::uuid,$3::bytea) AS result",
  failChallengeV3: "SELECT public.agentpass_hosted_identity_bootstrap_webauthn_fail_v3($1::bytea,$2::uuid,$3::bytea,$4::bytea,$5::bigint,$6::text) AS result",
  failChallenge: "SELECT public.agentpass_hosted_identity_bootstrap_challenge_fail($1::bytea,$2::uuid,$3::bytea,$4::text) AS result"
});

export const HOSTED_IDENTITY_BOOTSTRAP_REPOSITORY_ERROR_CODES = Object.freeze({
  CONFIG: "ERR_HOSTED_IDENTITY_BOOTSTRAP_REPOSITORY_CONFIG",
  INPUT: "ERR_HOSTED_IDENTITY_BOOTSTRAP_REPOSITORY_INPUT",
  RESULT: "ERR_HOSTED_IDENTITY_BOOTSTRAP_REPOSITORY_RESULT",
  DATABASE: "ERR_HOSTED_IDENTITY_BOOTSTRAP_REPOSITORY_DATABASE",
  CONFLICT: "ERR_HOSTED_IDENTITY_BOOTSTRAP_REPOSITORY_CONFLICT",
  RETRYABLE: "ERR_HOSTED_IDENTITY_BOOTSTRAP_REPOSITORY_RETRYABLE"
});

const MESSAGES = Object.freeze({
  [HOSTED_IDENTITY_BOOTSTRAP_REPOSITORY_ERROR_CODES.CONFIG]: "Hosted identity bootstrap repository configuration is invalid",
  [HOSTED_IDENTITY_BOOTSTRAP_REPOSITORY_ERROR_CODES.INPUT]: "Hosted identity bootstrap request is invalid",
  [HOSTED_IDENTITY_BOOTSTRAP_REPOSITORY_ERROR_CODES.RESULT]: "Hosted identity bootstrap returned an invalid result",
  [HOSTED_IDENTITY_BOOTSTRAP_REPOSITORY_ERROR_CODES.DATABASE]: "Hosted identity bootstrap storage is unavailable",
  [HOSTED_IDENTITY_BOOTSTRAP_REPOSITORY_ERROR_CODES.CONFLICT]: "Hosted identity bootstrap request conflicts with durable state",
  [HOSTED_IDENTITY_BOOTSTRAP_REPOSITORY_ERROR_CODES.RETRYABLE]: "Hosted identity bootstrap must be retried"
});

export class HostedIdentityBootstrapRepositoryError extends Error {
  constructor(code) {
    super(MESSAGES[code] ?? MESSAGES[HOSTED_IDENTITY_BOOTSTRAP_REPOSITORY_ERROR_CODES.DATABASE]);
    this.name = "HostedIdentityBootstrapRepositoryError";
    this.code = Object.hasOwn(MESSAGES, code)
      ? code
      : HOSTED_IDENTITY_BOOTSTRAP_REPOSITORY_ERROR_CODES.DATABASE;
  }
}

/**
 * Adapter for the 0057/0058 Hosted identity/bootstrap authority.
 *
 * The SQL functions own all state transitions and all timestamps. This layer
 * only validates the closed boundary, hashes browser/provider selectors, and
 * normalizes PostgreSQL results. Raw selectors are never included in query
 * parameters or retained by the repository.
 */
export function createPostgresHostedIdentityBootstrapRepository({ client } = {}) {
  if (!client || typeof client.query !== "function") throw error("CONFIG");

  async function start(input = {}) {
    const value = normalizeStart(input);
    const row = await tableCall("start", [value.attempt_id, value.oauth_state_id, sha256(value.state), value.pkce_challenge, value.client_id, value.redirect_uri]);
    return normalizeStartResult(row);
  }

  async function consumeOAuthState(input = {}) {
    const value = normalizeOAuthConsume(input);
    const row = await optionalTableCall("consumeOAuthState", [value.oauth_state_id, sha256(value.code), value.redirect_uri]);
    return row === null ? null : normalizeOAuthConsumeResult(row);
  }

  async function startOAuthV2(input = {}) {
    const value = normalizeStartV2(input);
    const row = await tableCall("startOAuthV2", [value.attempt_id, value.oauth_state_id, sha256(value.state), value.pkce_challenge, value.client_id, value.redirect_uri, value.envelope.key_id, value.envelope.nonce, value.envelope.ciphertext, value.envelope.auth_tag, value.envelope.expires_at]);
    return normalizeStartResult(row);
  }

  async function claimOAuthStateV2(input = {}) {
    const value = normalizeOAuthClaimV2(input);
    const row = await optionalTableCall("claimOAuthStateV2", [value.oauth_state_id, sha256(value.state), sha256(value.code), value.redirect_uri]);
    return row === null ? null : normalizeOAuthClaimV2Result(row);
  }

  async function completeOAuthState(input = {}) {
    const value = normalizeOAuthComplete(input);
    const result = await scalarCall("completeOAuthState", [value.oauth_state_id, sha256(value.bootstrap_cookie), value.member_id, value.subject, sha256(value.subject),], "uuid");
    return uuid(result, "attempt_id", "RESULT");
  }

  async function completeOAuthStateV2(input = {}) {
    const value = normalizeOAuthCompleteV2(input);
    const row = await optionalTableCall("completeOAuthStateV2", [value.oauth_state_id, value.attempt_id, sha256(value.bootstrap_cookie), value.candidate_member_id, value.provider, value.subject, sha256(value.subject)]);
    return row === null ? null : normalizeOAuthCompleteV2Result(row, value.attempt_id);
  }

  async function failOAuthState(input = {}) {
    const value = normalizeFailure(input, "oauth_state_id");
    await scalarCall("failOAuthState", [value.oauth_state_id, value.failure_code], "void");
    return true;
  }

  async function issueCsrf(input = {}) {
    const value = normalizeCsrf(input);
    const result = await scalarCall("issueCsrf", [sha256(value.bootstrap_cookie), sha256(value.csrf_token)], "boolean");
    if (typeof result !== "boolean") throw error("RESULT");
    return result;
  }

  async function getBootstrapStatus(input = {}) {
    const value = normalizeCsrf(input);
    const row = await optionalTableCall("getBootstrapStatus", [sha256(value.bootstrap_cookie), sha256(value.csrf_token)]);
    return row === null ? null : normalizeBootstrapStatusResult(row);
  }

  async function verifyBootstrapCsrf(input = {}) {
    const value = normalizeCsrf(input);
    const result = await scalarCall("verifyBootstrapCsrf", [sha256(value.bootstrap_cookie), sha256(value.csrf_token)], "boolean");
    if (typeof result !== "boolean") throw error("RESULT");
    return result;
  }

  async function commitOrganization(input = {}) {
    const value = normalizeOrganizationCommit(input);
    const row = await tableCall("commitOrganization", [sha256(value.bootstrap_cookie), value.idempotency_key, value.request_hash, value.organization_id, value.membership_id, JSON.stringify(value.public_response)]);
    return normalizeOrganizationResult(row);
  }

  async function commitOrganizationV2(input = {}) {
    const value = normalizeOrganizationCommitV2(input);
    const row = await tableCall("commitOrganizationV2", [
      sha256(value.bootstrap_cookie),
      value.idempotency_key,
      value.request_hash,
      value.organization_name,
      value.organization_id,
      value.membership_id,
      value.audit_event_id
    ]);
    return normalizeOrganizationResult(row);
  }

  async function createChallenge(input = {}) {
    const value = normalizeChallengeCreate(input);
    const row = await tableCall("createChallenge", [sha256(value.bootstrap_cookie), value.challenge_id, sha256(value.challenge), value.rp_id, value.origin, value.expires_at]);
    return normalizeChallengeResult(row);
  }

  async function consumeChallenge(input = {}) {
    const value = normalizeChallengeProof(input);
    const row = await optionalTableCall("consumeChallenge", [sha256(value.bootstrap_cookie), value.challenge_id, sha256(value.challenge)]);
    return row === null ? null : normalizeChallengeConsumeResult(row);
  }

  async function claimChallengeV2(input = {}) {
    const value = normalizeChallengeClaimV2(input);
    const row = await optionalTableCall("claimChallengeV2", [sha256(value.bootstrap_cookie), value.challenge_id, sha256(value.challenge), sha256(value.claim_token)]);
    return row === null ? null : normalizeChallengeClaimV2Result(row);
  }

  async function getWebAuthnReplayContext(input = {}) {
    const value = normalizeChallengeProof(input);
    const row = await optionalTableCall("getWebAuthnReplayContext", [sha256(value.bootstrap_cookie), value.challenge_id, sha256(value.challenge)]);
    return row === null ? null : normalizeChallengeConsumeResult(row);
  }

  async function completeChallenge(input = {}) {
    const value = normalizeChallengeProof(input);
    const result = await scalarCall("completeChallenge", [sha256(value.bootstrap_cookie), value.challenge_id, sha256(value.challenge)], "uuid");
    return uuid(result, "attempt_id", "RESULT");
  }

  async function completeWebAuthnRegistrationV2(input = {}) {
    const value = normalizeWebAuthnCompleteV2(input);
    const row = await tableCall("completeWebAuthnRegistrationV2", [
      value.attempt_id,
      sha256(value.bootstrap_cookie),
      value.challenge_id,
      sha256(value.challenge),
      completionRequestDigest(value),
      value.credential.id,
      value.credential.public_key,
      value.credential.sign_count,
      value.credential.transports,
      value.credential.label,
      value.credential.backup_eligible,
      value.credential.backup_state,
      sha256(value.session.token),
      sha256(value.session.csrf_token)
    ]);
    return normalizeWebAuthnCompleteV2Result(row, value.attempt_id);
  }

  async function completeWebAuthnRegistrationV3(input = {}) {
    const value = normalizeWebAuthnCompleteV3(input);
    const row = await tableCall("completeWebAuthnRegistrationV3", [
      value.attempt_id,
      sha256(value.bootstrap_cookie),
      value.challenge_id,
      sha256(value.challenge),
      sha256(value.claim_token),
      value.claim_generation,
      completionRequestDigest(value),
      value.credential.id,
      value.credential.public_key,
      value.credential.sign_count,
      value.credential.transports,
      value.credential.label,
      value.credential.backup_eligible,
      value.credential.backup_state,
      sha256(value.session.token),
      sha256(value.session.csrf_token)
    ]);
    return normalizeWebAuthnCompleteV2Result(row, value.attempt_id);
  }

  async function failChallenge(input = {}) {
    const value = normalizeChallengeFailure(input);
    await scalarCall("failChallenge", [sha256(value.bootstrap_cookie), value.challenge_id, sha256(value.challenge), value.failure_code], "void");
    return true;
  }

  async function failChallengeV3(input = {}) {
    const value = normalizeChallengeFailureV3(input);
    await scalarCall("failChallengeV3", [sha256(value.bootstrap_cookie), value.challenge_id, sha256(value.challenge), sha256(value.claim_token), value.claim_generation, value.failure_code], "void");
    return true;
  }

  async function tableCall(name, params) {
    const result = await query(name, params);
    if (!Array.isArray(result?.rows) || result.rows.length !== 1) throw error("RESULT");
    return result.rows[0];
  }

  async function optionalTableCall(name, params) {
    const result = await query(name, params);
    if (!Array.isArray(result?.rows) || result.rows.length > 1) throw error("RESULT");
    return result.rows.length === 0 ? null : result.rows[0];
  }

  async function scalarCall(name, params, kind) {
    const result = await query(name, params);
    if (!Array.isArray(result?.rows) || result.rows.length !== 1 || !isPlainObject(result.rows[0]) || Object.keys(result.rows[0]).join("\u0000") !== "result") throw error("RESULT");
    const value = result.rows[0].result;
    if (kind === "void") return null;
    return value;
  }

  async function query(name, params) {
    let result;
    try {
      result = await client.query(HOSTED_IDENTITY_BOOTSTRAP_REPOSITORY_SQL[name], params);
    } catch (cause) {
      throw classifyDatabaseError(cause);
    }
    return result;
  }

  return Object.freeze({
    start,
    startOAuthV2,
    consumeOAuthState,
    claimOAuthStateV2,
    completeOAuthState,
    completeOAuthStateV2,
    failOAuthState,
    issueCsrf,
    getBootstrapStatus,
    verifyBootstrapCsrf,
    commitOrganization,
    commitOrganizationV2,
    createChallenge,
    claimChallengeV2,
    consumeChallenge,
    getWebAuthnReplayContext,
    completeWebAuthnRegistrationV3,
    completeWebAuthnRegistrationV2,
    completeChallenge,
    failChallengeV3,
    failChallenge
  });
}

function normalizeStart(value) {
  exactObject(value, ["attempt_id", "oauth_state_id", "state", "pkce_challenge", "client_id", "redirect_uri"]);
  return Object.freeze({
    attempt_id: uuid(value.attempt_id, "attempt_id"),
    oauth_state_id: uuid(value.oauth_state_id, "oauth_state_id"),
    state: selector(value.state, "state"),
    pkce_challenge: text(value.pkce_challenge, 128, "pkce_challenge", PKCE),
    client_id: text(value.client_id, 256, "client_id"),
    redirect_uri: httpsUri(value.redirect_uri, "redirect_uri")
  });
}

function normalizeOAuthConsume(value) {
  exactObject(value, ["oauth_state_id", "code", "redirect_uri"]);
  return Object.freeze({
    oauth_state_id: uuid(value.oauth_state_id, "oauth_state_id"),
    code: selector(value.code, "code"),
    redirect_uri: httpsUri(value.redirect_uri, "redirect_uri")
  });
}

function normalizeStartV2(value) {
  exactObject(value, ["attempt_id", "oauth_state_id", "state", "pkce_challenge", "client_id", "redirect_uri", "envelope"]);
  const base = normalizeStart({ attempt_id: value.attempt_id, oauth_state_id: value.oauth_state_id, state: value.state, pkce_challenge: value.pkce_challenge, client_id: value.client_id, redirect_uri: value.redirect_uri });
  exactObject(value.envelope, ["key_id", "nonce", "ciphertext", "auth_tag", "expires_at"]);
  return Object.freeze({ ...base, envelope: Object.freeze({
    key_id: text(value.envelope.key_id, 128, "envelope.key_id", KEY_ID),
    nonce: bytes(value.envelope.nonce, 12),
    ciphertext: bytes(value.envelope.ciphertext, undefined, 43, 256),
    auth_tag: bytes(value.envelope.auth_tag, 16),
    expires_at: timestamp(value.envelope.expires_at, "envelope.expires_at")
  }) });
}

function normalizeOAuthClaimV2(value) {
  exactObject(value, ["oauth_state_id", "state", "code", "redirect_uri"]);
  return Object.freeze({
    oauth_state_id: uuid(value.oauth_state_id, "oauth_state_id"),
    state: selector(value.state, "state"),
    code: selector(value.code, "code"),
    redirect_uri: httpsUri(value.redirect_uri, "redirect_uri")
  });
}

function normalizeOAuthComplete(value) {
  exactObject(value, ["oauth_state_id", "bootstrap_cookie", "member_id", "subject"]);
  const subject = text(value.subject, 512, "subject");
  if (Buffer.byteLength(subject, "utf8") > MAX_SUBJECT_BYTES) throw error("INPUT");
  return Object.freeze({
    oauth_state_id: uuid(value.oauth_state_id, "oauth_state_id"),
    bootstrap_cookie: selector(value.bootstrap_cookie, "bootstrap_cookie"),
    member_id: uuid(value.member_id, "member_id"),
    subject
  });
}

function normalizeOAuthCompleteV2(value) {
  exactObject(value, ["oauth_state_id", "attempt_id", "bootstrap_cookie", "candidate_member_id", "provider", "subject"]);
  const provider = text(value.provider, 32, "provider");
  const subject = text(value.subject, MAX_SUBJECT_BYTES, "subject");
  if (provider !== "github" || !GITHUB_SUBJECT.test(subject) || Buffer.byteLength(subject, "utf8") > MAX_SUBJECT_BYTES) throw error("INPUT");
  return Object.freeze({
    oauth_state_id: uuid(value.oauth_state_id, "oauth_state_id"),
    attempt_id: uuid(value.attempt_id, "attempt_id"),
    bootstrap_cookie: selector(value.bootstrap_cookie, "bootstrap_cookie"),
    candidate_member_id: uuid(value.candidate_member_id, "candidate_member_id"),
    provider,
    subject
  });
}

function normalizeCsrf(value) {
  exactObject(value, ["bootstrap_cookie", "csrf_token"]);
  return Object.freeze({ bootstrap_cookie: selector(value.bootstrap_cookie, "bootstrap_cookie"), csrf_token: selector(value.csrf_token, "csrf_token") });
}

function normalizeOrganizationCommit(value) {
  exactObject(value, ["bootstrap_cookie", "idempotency_key", "request_hash", "organization_id", "membership_id", "public_response"]);
  return Object.freeze({
    bootstrap_cookie: selector(value.bootstrap_cookie, "bootstrap_cookie"),
    idempotency_key: text(value.idempotency_key, 255, "idempotency_key", IDEMPOTENCY_KEY),
    request_hash: digest(value.request_hash, "request_hash"),
    organization_id: uuid(value.organization_id, "organization_id"),
    membership_id: uuid(value.membership_id, "membership_id"),
    public_response: publicResponse(value.public_response)
  });
}

function normalizeOrganizationCommitV2(value) {
  exactObject(value, ["bootstrap_cookie", "idempotency_key", "request_hash", "organization_name", "organization_id", "membership_id", "audit_event_id"]);
  let organizationName;
  try { organizationName = normalizeHostedOrganizationName(value.organization_name, { requireCanonical: true }); }
  catch { throw error("INPUT"); }
  return Object.freeze({
    bootstrap_cookie: selector(value.bootstrap_cookie, "bootstrap_cookie"),
    idempotency_key: text(value.idempotency_key, 255, "idempotency_key", IDEMPOTENCY_KEY),
    request_hash: digest(value.request_hash, "request_hash"),
    organization_name: organizationName,
    organization_id: uuidV4(value.organization_id, "organization_id"),
    membership_id: uuidV4(value.membership_id, "membership_id"),
    audit_event_id: uuidV4(value.audit_event_id, "audit_event_id")
  });
}

function normalizeChallengeCreate(value) {
  exactObject(value, ["bootstrap_cookie", "challenge_id", "challenge", "rp_id", "origin", "expires_at"]);
  return Object.freeze({
    bootstrap_cookie: selector(value.bootstrap_cookie, "bootstrap_cookie"),
    challenge_id: uuid(value.challenge_id, "challenge_id"),
    challenge: selector(value.challenge, "challenge"),
    rp_id: text(value.rp_id, 253, "rp_id", RP_ID),
    origin: text(value.origin, 512, "origin", ORIGIN),
    expires_at: timestamp(value.expires_at, "expires_at")
  });
}

function normalizeChallengeProof(value) {
  exactObject(value, ["bootstrap_cookie", "challenge_id", "challenge"]);
  return Object.freeze({ bootstrap_cookie: selector(value.bootstrap_cookie, "bootstrap_cookie"), challenge_id: uuid(value.challenge_id, "challenge_id"), challenge: selector(value.challenge, "challenge") });
}

function normalizeChallengeClaimV2(value) {
  exactObject(value, ["bootstrap_cookie", "challenge_id", "challenge", "claim_token"]);
  return Object.freeze({
    ...normalizeChallengeProof({ bootstrap_cookie: value.bootstrap_cookie, challenge_id: value.challenge_id, challenge: value.challenge }),
    claim_token: text(value.claim_token, 43, "claim_token", OPAQUE_TOKEN)
  });
}

function normalizeChallengeFailure(value) {
  exactObject(value, ["bootstrap_cookie", "challenge_id", "challenge", "failure_code"]);
  return Object.freeze({ ...normalizeChallengeProof({ bootstrap_cookie: value.bootstrap_cookie, challenge_id: value.challenge_id, challenge: value.challenge }), failure_code: text(value.failure_code, 64, "failure_code", FAILURE_CODE) });
}

function normalizeChallengeFailureV3(value) {
  exactObject(value, ["bootstrap_cookie", "challenge_id", "challenge", "claim_token", "claim_generation", "failure_code"]);
  return Object.freeze({
    ...normalizeChallengeClaimV2({ bootstrap_cookie: value.bootstrap_cookie, challenge_id: value.challenge_id, challenge: value.challenge, claim_token: value.claim_token }),
    claim_generation: positiveInteger(value.claim_generation, "claim_generation", "INPUT"),
    failure_code: text(value.failure_code, 64, "failure_code", FAILURE_CODE)
  });
}

function normalizeWebAuthnCompleteV2(value) {
  exactObject(value, ["attempt_id", "bootstrap_cookie", "challenge_id", "challenge", "credential", "session"]);
  exactObject(value.credential, ["id", "public_key", "sign_count", "transports", "label", "backup_eligible", "backup_state"]);
  exactObject(value.session, ["token", "csrf_token"]);
  const backupEligible = boolean(value.credential.backup_eligible);
  const backupState = boolean(value.credential.backup_state);
  if (backupState && !backupEligible) throw error("INPUT");
  return Object.freeze({
    attempt_id: uuid(value.attempt_id, "attempt_id"),
    bootstrap_cookie: selector(value.bootstrap_cookie, "bootstrap_cookie"),
    challenge_id: uuidV4(value.challenge_id, "challenge_id"),
    challenge: selector(value.challenge, "challenge"),
    credential: Object.freeze({
      id: base64urlBytes(value.credential.id, 16, 1024),
      public_key: bytes(value.credential.public_key, undefined, 32, 4096),
      sign_count: nonNegativeInteger(value.credential.sign_count, "credential.sign_count", "INPUT"),
      transports: transports(value.credential.transports),
      label: text(value.credential.label, 128, "credential.label"),
      backup_eligible: backupEligible,
      backup_state: backupState
    }),
    session: Object.freeze({
      token: text(value.session.token, 43, "session.token", OPAQUE_TOKEN),
      csrf_token: text(value.session.csrf_token, 43, "session.csrf_token", OPAQUE_TOKEN)
    })
  });
}

function normalizeWebAuthnCompleteV3(value) {
  exactObject(value, ["attempt_id", "bootstrap_cookie", "challenge_id", "challenge", "claim_token", "claim_generation", "credential", "session"]);
  return Object.freeze({
    ...normalizeWebAuthnCompleteV2({
      attempt_id: value.attempt_id,
      bootstrap_cookie: value.bootstrap_cookie,
      challenge_id: value.challenge_id,
      challenge: value.challenge,
      credential: value.credential,
      session: value.session
    }),
    claim_token: text(value.claim_token, 43, "claim_token", OPAQUE_TOKEN),
    claim_generation: positiveInteger(value.claim_generation, "claim_generation", "INPUT")
  });
}

function normalizeFailure(value, idKey) {
  exactObject(value, [idKey, "failure_code"]);
  return Object.freeze({ [idKey]: uuid(value[idKey], idKey), failure_code: text(value.failure_code, 64, "failure_code", FAILURE_CODE) });
}

function normalizeStartResult(value) {
  exactObject(value, ["attempt_id", "oauth_state_id", "state_expires_at", "attempt_expires_at"], "RESULT");
  return Object.freeze({ attempt_id: uuid(value.attempt_id, "attempt_id", "RESULT"), oauth_state_id: uuid(value.oauth_state_id, "oauth_state_id", "RESULT"), state_expires_at: timestamp(value.state_expires_at, "state_expires_at", "RESULT"), attempt_expires_at: timestamp(value.attempt_expires_at, "attempt_expires_at", "RESULT") });
}

function normalizeOAuthConsumeResult(value) {
  exactObject(value, ["attempt_id", "pkce_challenge", "pkce_method", "client_id", "redirect_uri"], "RESULT");
  if (value.pkce_method !== "S256") throw error("RESULT");
  return Object.freeze({ attempt_id: uuid(value.attempt_id, "attempt_id", "RESULT"), pkce_challenge: text(value.pkce_challenge, 128, "pkce_challenge", PKCE, "RESULT"), pkce_method: value.pkce_method, client_id: text(value.client_id, 256, "client_id", undefined, "RESULT"), redirect_uri: httpsUri(value.redirect_uri, "redirect_uri", "RESULT") });
}

function normalizeOAuthClaimV2Result(value) {
  exactObject(value, ["attempt_id", "oauth_state_id", "pkce_challenge", "client_id", "redirect_uri", "key_id", "nonce", "ciphertext", "auth_tag", "expires_at"], "RESULT");
  return Object.freeze({
    attempt_id: uuid(value.attempt_id, "attempt_id", "RESULT"),
    oauth_state_id: uuid(value.oauth_state_id, "oauth_state_id", "RESULT"),
    pkce_challenge: text(value.pkce_challenge, 128, "pkce_challenge", PKCE, "RESULT"),
    client_id: text(value.client_id, 256, "client_id", undefined, "RESULT"),
    redirect_uri: httpsUri(value.redirect_uri, "redirect_uri", "RESULT"),
    envelope: Object.freeze({
      key_id: text(value.key_id, 128, "key_id", KEY_ID, "RESULT"),
      nonce: bytes(value.nonce, 12, undefined, undefined, "RESULT"),
      ciphertext: bytes(value.ciphertext, undefined, 43, 256, "RESULT"),
      auth_tag: bytes(value.auth_tag, 16, undefined, undefined, "RESULT")
    }),
    expires_at: timestamp(value.expires_at, "expires_at", "RESULT")
  });
}

function normalizeOAuthCompleteV2Result(value, expectedAttemptId) {
  exactObject(value, ["attempt_id", "state", "organization_count", "expires_at"], "RESULT");
  const attemptId = uuid(value.attempt_id, "attempt_id", "RESULT");
  if (attemptId !== expectedAttemptId || !OAUTH_COMPLETE_V2_STATES.includes(value.state)) throw error("RESULT");
  const organizationCount = nonNegativeInteger(value.organization_count, "organization_count", "RESULT");
  if (value.state === "identity_verified" ? organizationCount < 1 : organizationCount !== 0) throw error("RESULT");
  return Object.freeze({
    attempt_id: attemptId,
    state: value.state,
    organization_count: organizationCount,
    expires_at: timestamp(value.expires_at, "expires_at", "RESULT")
  });
}

function normalizeOrganizationResult(value) {
  exactObject(value, ["response_status", "response_json", "replayed"], "RESULT");
  if (value.response_status !== 200 && value.response_status !== 201) throw error("RESULT");
  if (typeof value.replayed !== "boolean") throw error("RESULT");
  if (value.replayed !== (value.response_status === 200)) throw error("RESULT");
  return Object.freeze({ response_status: value.response_status, response_json: publicResponse(value.response_json, "RESULT"), replayed: value.replayed });
}

function normalizeBootstrapStatusResult(value) {
  exactObject(value, ["state", "organization_count", "webauthn_required", "can_create_first_organization", "expires_at"], "RESULT");
  const states = new Set(["identity_verified", "organization_required", "webauthn_required", "ready", "no_membership", "completed", "expired"]);
  if (!states.has(value.state)
    || typeof value.webauthn_required !== "boolean"
    || typeof value.can_create_first_organization !== "boolean") throw error("RESULT");
  const organizationCount = nonNegativeInteger(value.organization_count, "organization_count", "RESULT");
  if (value.can_create_first_organization !== (value.state === "organization_required" && organizationCount === 0)
    || value.webauthn_required !== (value.state === "webauthn_required")) throw error("RESULT");
  return Object.freeze({
    state: value.state,
    organization_count: organizationCount,
    webauthn_required: value.webauthn_required,
    can_create_first_organization: value.can_create_first_organization,
    expires_at: timestamp(value.expires_at, "expires_at", "RESULT")
  });
}

function normalizeChallengeResult(value) {
  exactObject(value, ["challenge_id", "member_id", "organization_id", "rp_id", "origin", "expires_at"], "RESULT");
  return Object.freeze({ challenge_id: uuid(value.challenge_id, "challenge_id", "RESULT"), member_id: uuid(value.member_id, "member_id", "RESULT"), organization_id: uuid(value.organization_id, "organization_id", "RESULT"), rp_id: text(value.rp_id, 253, "rp_id", RP_ID, "RESULT"), origin: text(value.origin, 512, "origin", ORIGIN, "RESULT"), expires_at: timestamp(value.expires_at, "expires_at", "RESULT") });
}

function normalizeChallengeConsumeResult(value) {
  exactObject(value, ["attempt_id", "member_id", "organization_id", "rp_id", "origin", "user_verification"], "RESULT");
  if (value.user_verification !== "required") throw error("RESULT");
  return Object.freeze({ attempt_id: uuid(value.attempt_id, "attempt_id", "RESULT"), member_id: uuid(value.member_id, "member_id", "RESULT"), organization_id: uuid(value.organization_id, "organization_id", "RESULT"), rp_id: text(value.rp_id, 253, "rp_id", RP_ID, "RESULT"), origin: text(value.origin, 512, "origin", ORIGIN, "RESULT"), user_verification: value.user_verification });
}

function normalizeChallengeClaimV2Result(value) {
  exactObject(value, ["attempt_id", "member_id", "organization_id", "rp_id", "origin", "user_verification", "claim_generation", "claim_expires_at"], "RESULT");
  return Object.freeze({
    ...normalizeChallengeConsumeResult({
      attempt_id: value.attempt_id,
      member_id: value.member_id,
      organization_id: value.organization_id,
      rp_id: value.rp_id,
      origin: value.origin,
      user_verification: value.user_verification
    }),
    claim_generation: positiveInteger(value.claim_generation, "claim_generation", "RESULT"),
    claim_expires_at: timestamp(value.claim_expires_at, "claim_expires_at", "RESULT")
  });
}

function normalizeWebAuthnCompleteV2Result(value, expectedAttemptId) {
  exactObject(value, ["attempt_id", "session_id", "member_id", "organization_id", "membership_id", "role", "created_at", "expires_at", "replayed"], "RESULT");
  const sessionId = uuid(value.session_id, "session_id", "RESULT");
  const attemptId = uuid(value.attempt_id, "attempt_id", "RESULT");
  if (attemptId !== expectedAttemptId || !["owner", "admin", "auditor", "viewer"].includes(value.role) || typeof value.replayed !== "boolean") throw error("RESULT");
  return Object.freeze({
    attempt_id: attemptId,
    membership_id: uuid(value.membership_id, "membership_id", "RESULT"),
    replayed: value.replayed,
    session: Object.freeze({
      version: 1,
      session_id: sessionId,
      member_id: uuid(value.member_id, "member_id", "RESULT"),
      organization_id: uuid(value.organization_id, "organization_id", "RESULT"),
      role: value.role,
      created_at: timestamp(value.created_at, "created_at", "RESULT"),
      expires_at: timestamp(value.expires_at, "expires_at", "RESULT"),
      recent_auth_at: null
    })
  });
}

function publicResponse(value, kind = "INPUT") {
  exactObject(value, ["version", "organization", "onboarding"], kind);
  if (!Number.isSafeInteger(value.version) || value.version !== 1) throw error(kind);
  exactObject(value.organization, ["organization_id", "name", "version", "created_at", "updated_at"], kind);
  const organization = {
    organization_id: uuid(value.organization.organization_id, "organization.organization_id", kind),
    name: text(value.organization.name, 128, "organization.name", undefined, kind),
    version: positiveInteger(value.organization.version, "organization.version", kind),
    created_at: timestamp(value.organization.created_at, "organization.created_at", kind),
    updated_at: timestamp(value.organization.updated_at, "organization.updated_at", kind)
  };
  exactObject(value.onboarding, ["state"], kind);
  if (value.onboarding.state !== "webauthn_required") throw error(kind);
  return Object.freeze({ version: 1, organization: Object.freeze(organization), onboarding: Object.freeze({ state: "webauthn_required" }) });
}

function exactObject(value, expected, kind = "INPUT") {
  if (!isPlainObject(value) || Object.keys(value).sort().join("\u0000") !== [...expected].sort().join("\u0000")) throw error(kind);
}

function isPlainObject(value) { return value !== null && typeof value === "object" && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype; }
function selector(value, name) { return text(value, MAX_SELECTOR_BYTES, name); }
function digest(value, name) {
  if (Buffer.isBuffer(value) && value.length === 32) return Buffer.from(value);
  if (value instanceof Uint8Array && value.length === 32) return Buffer.from(value);
  if (typeof value === "string" && DIGEST.test(value)) return Buffer.from(value, "hex");
  throw error("INPUT");
}
function bytes(value, exact, min = exact, max = exact, kind = "INPUT") {
  if (!(Buffer.isBuffer(value) || value instanceof Uint8Array)) throw error(kind);
  const result = Buffer.from(value);
  if (exact !== undefined ? result.length !== exact : result.length < min || result.length > max) throw error(kind);
  return result;
}
function base64urlBytes(value, min, max) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/u.test(value)) throw error("INPUT");
  let result;
  try { result = Buffer.from(value, "base64url"); } catch { throw error("INPUT"); }
  if (result.length < min || result.length > max || result.toString("base64url") !== value) throw error("INPUT");
  return result;
}
function boolean(value) { if (typeof value !== "boolean") throw error("INPUT"); return value; }
function transports(value) {
  if (!Array.isArray(value) || value.length > WEBAUTHN_TRANSPORTS.size) throw error("INPUT");
  const normalized = [...value];
  if (normalized.some((item) => typeof item !== "string" || !WEBAUTHN_TRANSPORTS.has(item)) || new Set(normalized).size !== normalized.length) throw error("INPUT");
  return Object.freeze(normalized);
}
function sha256(value) { return crypto.createHash("sha256").update(value, "utf8").digest(); }
function completionRequestDigest(value) {
  const hash = crypto.createHash("sha256");
  hash.update("agentpass.hosted-bootstrap-webauthn-completion.v1\0", "utf8");
  for (const part of [
    value.challenge_id,
    sha256(value.challenge),
    value.credential.id,
    value.credential.public_key,
    String(value.credential.sign_count),
    JSON.stringify(value.credential.transports),
    value.credential.label,
    value.credential.backup_eligible ? "1" : "0",
    value.credential.backup_state ? "1" : "0",
    value.attempt_id,
    sha256(value.session.token),
    sha256(value.session.csrf_token)
  ]) {
    const encoded = Buffer.isBuffer(part) ? part : Buffer.from(part, "utf8");
    const length = Buffer.allocUnsafe(4);
    length.writeUInt32BE(encoded.length);
    hash.update(length).update(encoded);
  }
  return hash.digest();
}
function text(value, max, name, pattern = undefined, kind = "INPUT") {
  if (typeof value !== "string" || value.length < 1 || value.length > max || CONTROL.test(value) || Buffer.byteLength(value, "utf8") > max * 4 || (pattern && !pattern.test(value))) throw error(kind);
  return value;
}
function httpsUri(value, name, kind = "INPUT") { return text(value, 2048, name, undefined, kind).startsWith("https://") && !value.includes("#") ? value : (() => { throw error(kind); })(); }
function timestamp(value, name, kind = "INPUT") {
  if (value instanceof Date && !Number.isNaN(value.getTime())) return value.toISOString();
  if (typeof value !== "string" || !TIMESTAMP.test(value) || Number.isNaN(Date.parse(value))) throw error(kind);
  return new Date(value).toISOString();
}
function positiveInteger(value, name, kind = "RESULT") { if (!Number.isSafeInteger(Number(value)) || Number(value) < 1) throw error(kind); return Number(value); }
function nonNegativeInteger(value, name, kind = "RESULT") {
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value) || value < 0) throw error(kind);
    return value;
  }
  if (typeof value === "bigint") {
    if (value < 0n || value > BigInt(Number.MAX_SAFE_INTEGER)) throw error(kind);
    return Number(value);
  }
  if (typeof value === "string" && /^(?:0|[1-9][0-9]*)$/u.test(value)) {
    const number = Number(value);
    if (Number.isSafeInteger(number)) return number;
  }
  throw error(kind);
}
function uuid(value, name, kind = "INPUT") { if (typeof value !== "string" || !UUID.test(value)) throw error(kind); return value.toLowerCase(); }
function uuidV4(value, name, kind = "INPUT") { if (typeof value !== "string" || !UUID_V4.test(value)) throw error(kind); return value.toLowerCase(); }
function classifyDatabaseError(cause) {
  if (cause?.code === "40001") return error("RETRYABLE");
  if (cause?.code === "23505" || cause?.code === "28000") return error("CONFLICT");
  return error("DATABASE");
}
function error(code) { return new HostedIdentityBootstrapRepositoryError(HOSTED_IDENTITY_BOOTSTRAP_REPOSITORY_ERROR_CODES[code] ?? HOSTED_IDENTITY_BOOTSTRAP_REPOSITORY_ERROR_CODES.DATABASE); }

export default createPostgresHostedIdentityBootstrapRepository;
