import crypto from "node:crypto";

const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
const BASE64URL = /^[A-Za-z0-9_-]+$/u;
const RP_ID = /^[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$/u;
const TOKEN_BYTES = 32;
const CHALLENGE_BYTES = 32;
const DEFAULT_CHALLENGE_TTL_MS = 120_000;
const MAX_CLIENT_DATA_BYTES = 16 * 1024;
const MAX_ATTESTATION_BYTES = 64 * 1024;
const MAX_CREDENTIAL_ID_BYTES = 1024;
const TRANSPORTS = new Set(["ble", "cable", "hybrid", "internal", "nfc", "smart-card", "usb"]);

export const HOSTED_WEBAUTHN_BOOTSTRAP_ERROR_CODES = Object.freeze({
  INVALID: "bootstrap_webauthn_invalid",
  REPLAYED: "bootstrap_webauthn_replayed",
  UNAVAILABLE: "bootstrap_unavailable"
});

export class HostedWebAuthnBootstrapError extends Error {
  constructor(code) {
    super(code === HOSTED_WEBAUTHN_BOOTSTRAP_ERROR_CODES.REPLAYED
      ? "Hosted WebAuthn registration has already been used"
      : code === HOSTED_WEBAUTHN_BOOTSTRAP_ERROR_CODES.INVALID
        ? "Hosted WebAuthn registration is invalid"
        : "Hosted WebAuthn registration is unavailable");
    this.name = "HostedWebAuthnBootstrapError";
    this.code = Object.values(HOSTED_WEBAUTHN_BOOTSTRAP_ERROR_CODES).includes(code)
      ? code
      : HOSTED_WEBAUTHN_BOOTSTRAP_ERROR_CODES.UNAVAILABLE;
  }
}

/**
 * Bootstrap-only WebAuthn adapter.
 *
 * The maintained strict verifier is reused, but no ordinary Human Session is
 * fabricated before verification. PostgreSQL owns the attempt/challenge/
 * membership binding and atomically commits the credential plus first Human
 * Session. Session bearer material is deterministic for one exact browser
 * response so a retry after response loss can recover it without storing raw
 * tokens in PostgreSQL.
 */
export function createHostedWebAuthnBootstrapService({
  repository,
  registrationVerifier,
  responseKey,
  rpId,
  origin,
  rpName = "AgentPass",
  challengeTtlMs = DEFAULT_CHALLENGE_TTL_MS,
  now = () => Date.now(),
  randomUUID = crypto.randomUUID,
  randomBytes = crypto.randomBytes
} = {}) {
  assertRepository(repository);
  if (!registrationVerifier || typeof registrationVerifier.generateOptions !== "function" || typeof registrationVerifier.verifyAttestation !== "function") throw new TypeError("registrationVerifier is invalid");
  if (!(Buffer.isBuffer(responseKey) || responseKey instanceof Uint8Array) || responseKey.length !== 32) throw new TypeError("responseKey must be 32 bytes");
  const key = Buffer.from(responseKey);
  if (typeof rpId !== "string" || !RP_ID.test(rpId)) throw new TypeError("rpId is invalid");
  const parsedOrigin = parseOrigin(origin);
  if (parsedOrigin.hostname !== rpId && !parsedOrigin.hostname.endsWith(`.${rpId}`)) throw new TypeError("rpId is not valid for origin");
  if (typeof rpName !== "string" || rpName.length < 1 || rpName.length > 128 || /[\u0000-\u001f\u007f]/u.test(rpName)) throw new TypeError("rpName is invalid");
  boundedDuration(challengeTtlMs, 1_000, 300_000, "challengeTtlMs");
  if (typeof now !== "function" || typeof randomUUID !== "function" || typeof randomBytes !== "function") throw new TypeError("runtime sources are invalid");

  async function options(input = {}) {
    assertRouteContext(input, rpId, origin);
    const issuedAt = clock(now);
    const challengeId = uuidV4(randomUUID());
    const challengeBytes = randomBytes(CHALLENGE_BYTES);
    if (!(Buffer.isBuffer(challengeBytes) || challengeBytes instanceof Uint8Array) || challengeBytes.length !== CHALLENGE_BYTES) throw new TypeError("random challenge source is invalid");
    const challenge = Buffer.from(challengeBytes).toString("base64url");
    const expiresAt = new Date(issuedAt + challengeTtlMs).toISOString();
    let binding;
    try {
      binding = await repository.createChallenge({
        bootstrap_cookie: opaque(input.bootstrap_token),
        challenge_id: challengeId,
        challenge,
        rp_id: rpId,
        origin,
        expires_at: expiresAt
      });
    } catch { fail("UNAVAILABLE"); }
    assertBinding(binding, challengeId, rpId, origin);
    const userId = uuidBytes(binding.member_id).toString("base64url");
    let generated;
    try {
      generated = await registrationVerifier.generateOptions({
        rp: { id: rpId, name: rpName },
        user: { id: userId, name: `member-${binding.member_id}@agentpass.local`, displayName: "AgentPass member" },
        challenge,
        excludeCredentials: [],
        timeout: challengeTtlMs
      });
    } catch { fail("UNAVAILABLE"); }
    const normalized = normalizeGeneratedOptions(generated, { challenge, userId, rpId });
    return Object.freeze({ challenge_id: challengeId, options: normalized });
  }

  async function verify(input = {}) {
    assertRouteContext(input, rpId, origin, ["bootstrap_token", "challenge_id", "credential", "rp_id", "origin", "user_verification"]);
    const challengeId = uuidV4(input.challenge_id);
    const credential = normalizeCredential(input.credential);
    const clientData = decodeClientData(credential.client_data_json, origin);
    const challenge = clientData.challenge;
    const responseBinding = completionBinding(input.bootstrap_token, challengeId, credential);
    const claimToken = deriveToken(key, "claim", responseBinding);
    const proof = {
      bootstrap_cookie: opaque(input.bootstrap_token),
      challenge_id: challengeId,
      challenge,
      claim_token: claimToken
    };

    let binding;
    try {
      binding = await repository.claimChallengeV2(proof);
    } catch { fail("UNAVAILABLE"); }
    if (binding === null) fail("REPLAYED");
    assertBinding(binding, challengeId, rpId, origin, true);

    let verified;
    try {
      verified = normalizeVerified(await registrationVerifier.verifyAttestation(Object.freeze({
        ceremony: Object.freeze({
          challenge_id: challengeId,
          session_id: binding.attempt_id,
          member_id: binding.member_id,
          organization_id: binding.organization_id,
          operation: "bootstrap_registration",
          rp_id: rpId,
          origin,
          user_verification: "required",
          expected_challenge: challenge
        }),
        attestation: credential,
        parsed: Object.freeze({ client_data: clientData })
      })), credential);
    } catch {
      await failClaimBestEffort({ ...proof, claim_generation: binding.claim_generation });
      fail("INVALID");
    }

    const sessionToken = deriveToken(key, "session", responseBinding);
    const csrfToken = deriveToken(key, "csrf", responseBinding);
    let completed;
    try {
      completed = await repository.completeWebAuthnRegistrationV3({
        attempt_id: binding.attempt_id,
        bootstrap_cookie: input.bootstrap_token,
        challenge_id: challengeId,
        challenge,
        claim_token: claimToken,
        claim_generation: binding.claim_generation,
        credential: {
          id: verified.credential_id,
          public_key: verified.public_key,
          sign_count: verified.sign_count,
          transports: verified.transports,
          label: "Passkey",
          backup_eligible: verified.backup_eligible,
          backup_state: verified.backup_state
        },
        session: {
          token: sessionToken,
          csrf_token: csrfToken
        }
      });
    } catch (error) {
      if (error?.code === "ERR_HOSTED_IDENTITY_BOOTSTRAP_REPOSITORY_CONFLICT") fail("REPLAYED");
      fail("UNAVAILABLE");
    }
    if (!completed || completed.attempt_id !== binding.attempt_id || !completed.session) fail("UNAVAILABLE");
    return Object.freeze({ session_token: sessionToken, csrf_token: csrfToken, session: completed.session });
  }

  async function failClaimBestEffort(proof) {
    try { await repository.failChallengeV3({ ...proof, failure_code: "verification_failed" }); } catch { /* terminal public error remains fixed */ }
  }

  return Object.freeze({ options, verify, rpId, origin });
}

function assertRepository(value) {
  for (const method of ["createChallenge", "claimChallengeV2", "completeWebAuthnRegistrationV3", "failChallengeV3"]) {
    if (!value || typeof value[method] !== "function") throw new TypeError(`repository.${method} is required`);
  }
}

function assertRouteContext(value, rpId, origin, keys = ["bootstrap_token", "rp_id", "origin", "user_verification"]) {
  if (!plain(value) || Object.keys(value).sort().join("\0") !== [...keys].sort().join("\0") || value.rp_id !== rpId || value.origin !== origin || value.user_verification !== "required") fail("INVALID");
  opaque(value.bootstrap_token);
}

function assertBinding(value, challengeId, rpId, origin, requireClaim = false) {
  if (!plain(value) || value.challenge_id !== undefined && value.challenge_id !== challengeId || !UUID_V4.test(value.attempt_id ?? challengeId) || !UUID_V4.test(value.member_id) || !UUID_V4.test(value.organization_id) || value.rp_id !== rpId || value.origin !== origin || value.user_verification !== undefined && value.user_verification !== "required" || requireClaim && (!Number.isSafeInteger(value.claim_generation) || value.claim_generation < 1)) fail("UNAVAILABLE");
}

function normalizeGeneratedOptions(value, expected) {
  if (!plain(value) || value.challenge !== expected.challenge || value.rp?.id !== expected.rpId || value.user?.id !== expected.userId || !Array.isArray(value.pubKeyCredParams) || value.pubKeyCredParams.length < 1 || value.authenticatorSelection?.userVerification !== "required") fail("UNAVAILABLE");
  return Object.freeze({ ...value });
}

function normalizeCredential(value) {
  if (!plain(value) || Object.keys(value).some((key) => !["credential_id", "client_data_json", "attestation_object", "transports"].includes(key))) fail("INVALID");
  const credentialId = base64url(value.credential_id, 16, MAX_CREDENTIAL_ID_BYTES);
  const clientData = base64url(value.client_data_json, 1, MAX_CLIENT_DATA_BYTES);
  const attestation = base64url(value.attestation_object, 1, MAX_ATTESTATION_BYTES);
  const transports = value.transports === undefined ? [] : normalizeTransports(value.transports);
  return Object.freeze({ credential_id: credentialId, client_data_json: clientData, attestation_object: attestation, transports });
}

function normalizeVerified(value, credential) {
  if (!plain(value) || value.verified !== true || value.user_verified !== true || value.credential_id !== credential.credential_id || !(Buffer.isBuffer(value.public_key) || value.public_key instanceof Uint8Array) || value.public_key.length < 32 || value.public_key.length > 4096 || !Number.isSafeInteger(value.sign_count) || value.sign_count < 0 || value.sign_count > 0xffffffff) fail("INVALID");
  const transports = normalizeTransports(value.transports ?? credential.transports);
  if (value.credential_device_type !== undefined && !["singleDevice", "multiDevice"].includes(value.credential_device_type)) fail("INVALID");
  if (value.credential_backed_up !== undefined && typeof value.credential_backed_up !== "boolean") fail("INVALID");
  const backupState = value.credential_backed_up ?? false;
  const backupEligible = backupState || value.credential_device_type === "multiDevice";
  if (value.credential_device_type === "singleDevice" && backupState) fail("INVALID");
  return Object.freeze({ credential_id: value.credential_id, public_key: Buffer.from(value.public_key), sign_count: value.sign_count, transports, backup_eligible: backupEligible, backup_state: backupState });
}

function decodeClientData(encoded, expectedOrigin) {
  const bytes = Buffer.from(encoded, "base64url");
  const source = bytes.toString("utf8");
  if (!Buffer.from(source, "utf8").equals(bytes)) fail("INVALID");
  let value;
  try { value = JSON.parse(source); } catch { fail("INVALID"); }
  if (!plain(value) || value.type !== "webauthn.create" || value.origin !== expectedOrigin || value.crossOrigin !== undefined && value.crossOrigin !== false) fail("INVALID");
  base64url(value.challenge, CHALLENGE_BYTES, CHALLENGE_BYTES);
  return Object.freeze({ type: value.type, challenge: value.challenge, origin: value.origin, ...(value.crossOrigin === undefined ? {} : { cross_origin: value.crossOrigin }) });
}

function completionBinding(bootstrapToken, challengeId, credential) {
  const hash = crypto.createHash("sha256");
  hash.update("agentpass.hosted-bootstrap-response.v1\0");
  for (const value of [bootstrapToken, challengeId, credential.credential_id, credential.client_data_json, credential.attestation_object]) {
    const bytes = Buffer.from(value, "utf8");
    const length = Buffer.allocUnsafe(4);
    length.writeUInt32BE(bytes.length);
    hash.update(length).update(bytes);
  }
  return hash.digest();
}

function deriveToken(key, purpose, binding) {
  return crypto.createHmac("sha256", key).update(`agentpass.hosted-bootstrap-${purpose}.v1\0`).update(binding).digest("base64url");
}

function normalizeTransports(value) {
  if (!Array.isArray(value) || value.length > TRANSPORTS.size || value.some((item) => !TRANSPORTS.has(item)) || new Set(value).size !== value.length) fail("INVALID");
  return Object.freeze([...value]);
}

function base64url(value, min, max) {
  if (typeof value !== "string" || !BASE64URL.test(value)) fail("INVALID");
  const decoded = Buffer.from(value, "base64url");
  if (decoded.length < min || decoded.length > max || decoded.toString("base64url") !== value) fail("INVALID");
  return value;
}

function uuidBytes(value) { return Buffer.from(uuidV4(value).replaceAll("-", ""), "hex"); }
function uuidV4(value) { if (typeof value !== "string" || !UUID_V4.test(value)) fail("INVALID"); return value.toLowerCase(); }
function opaque(value) { return base64url(value, TOKEN_BYTES, TOKEN_BYTES); }
function clock(now) { const value = now(); if (!Number.isSafeInteger(value) || value < 0) throw new TypeError("clock is invalid"); return value; }
function boundedDuration(value, minimum, maximum, name) { if (!Number.isSafeInteger(value) || value < minimum || value > maximum) throw new TypeError(`${name} is invalid`); }
function parseOrigin(value) { let parsed; try { parsed = new URL(value); } catch { throw new TypeError("origin is invalid"); } if (parsed.protocol !== "https:" || parsed.origin !== value || parsed.pathname !== "/" || parsed.search || parsed.hash || parsed.username || parsed.password) throw new TypeError("origin is invalid"); return parsed; }
function plain(value) { return value !== null && typeof value === "object" && !Array.isArray(value); }
function fail(code) { throw new HostedWebAuthnBootstrapError(HOSTED_WEBAUTHN_BOOTSTRAP_ERROR_CODES[code] ?? HOSTED_WEBAUTHN_BOOTSTRAP_ERROR_CODES.UNAVAILABLE); }

export default createHostedWebAuthnBootstrapService;
