import { verifyAuthenticationResponse } from "@simplewebauthn/server";

import { normalizeBrowserRegistrationCredential } from "../webauthn/registration.mjs";

const BASE64URL = /^[A-Za-z0-9_-]+$/u;
const MAX_COUNTER = 0xffff_ffff;
const OPERATIONS = Object.freeze({
  registration: "human.recovery.credential.register",
  authentication: "human.recovery.activate"
});

export class OwnerRecoveryWebAuthnCeremonyError extends Error {
  constructor(code) {
    super("Owner recovery WebAuthn ceremony failed");
    this.name = "OwnerRecoveryWebAuthnCeremonyError";
    this.code = code;
  }
}

/**
 * Recovery-session WebAuthn composition boundary.
 *
 * Verification intentionally happens outside a database transaction. The
 * durable coordinator first claims a digest-only challenge and then invokes
 * the supplied mutation inside the transaction that consumes it. Browser
 * assertions, signatures, attestation objects, and raw challenges never cross
 * a repository mutation boundary.
 */
export function createOwnerRecoveryWebAuthnCeremony({
  coordinator,
  recoveryRepository,
  registrationVerifier,
  verifyAuthentication = verifyAuthenticationResponse,
  rpName = "AgentPass",
  timeoutMs = 120_000
} = {}) {
  requireMethods(coordinator, ["begin", "claim", "complete", "burn"], "coordinator");
  requireMethods(recoveryRepository, ["findRecoveryCredential"], "recoveryRepository");
  requireMethods(registrationVerifier, ["generateOptions", "verifyAttestation"], "registrationVerifier");
  if (typeof verifyAuthentication !== "function") throw new TypeError("verifyAuthentication must be a function");
  if (typeof rpName !== "string" || rpName.length < 1 || rpName.length > 128) throw new TypeError("rpName is invalid");
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 30_000 || timeoutMs > 300_000) throw new TypeError("timeoutMs is invalid");

  async function beginRegistration(input = {}) {
    const context = normalizeContext(input, "registration");
    const challenge = await coordinator.begin(context);
    const userId = Buffer.from(context.member_id, "utf8").toString("base64url");
    const options = await registrationVerifier.generateOptions({
      rp: { id: context.rp_id, name: rpName },
      user: { id: userId, name: `recovery-${context.member_id}`, displayName: "Recovered AgentPass owner" },
      challenge: challenge.challenge,
      excludeCredentials: [],
      timeout: timeoutMs
    });
    return Object.freeze({ challenge_id: challenge.challenge_id, expires_at: challenge.expires_at, options: Object.freeze({ ...options, challenge: challenge.challenge }) });
  }

  async function verifyRegistration(input = {}) {
    const context = normalizeContext(input, "registration");
    const challengeId = uuid(input.challenge_id, "challenge_id");
    const attestation = normalizeBrowserRegistrationCredential(input.credential);
    const challenge = clientChallenge(attestation.client_data_json, "webauthn.create", context.origin);
    let claim;
    try {
      claim = await coordinator.claim({ ...context, challenge_id: challengeId, challenge, credential_id: attestation.credential_id });
      if (claim.already_consumed) throw failure("owner_recovery_webauthn_replayed");
      const verified = await registrationVerifier.verifyAttestation({
        ceremony: { expected_challenge: challenge, origin: context.origin, rp_id: context.rp_id },
        attestation
      });
      if (verified?.verified !== true || verified.credential_id !== attestation.credential_id || verified.user_verified !== true) throw failure("owner_recovery_webauthn_verification_failed");
      const durableCredential = publicCredential(verified);
      const completion = await coordinator.complete({
        ...context,
        challenge_id: challengeId,
        credential_id: durableCredential.credential_id,
        claim_started_at: claim.claim_started_at,
        mutate: (tx, binding) => input.complete(tx, binding, durableCredential)
      });
      return Object.freeze({ ...completion, mutation: completion.mutation?.mutation ?? completion.mutation });
    } catch (error) {
      if (claim?.claim_started_at) await safeBurn(coordinator, context.organization_id, challengeId, claim.claim_started_at);
      throw stable(error);
    }
  }

  async function beginActivation(input = {}) {
    const context = normalizeContext(input, "authentication");
    const stored = await findCredential(recoveryRepository, context, input.credential_id);
    const credentialId = credentialIdOf(stored);
    const challenge = await coordinator.begin({ ...context, credential_id: credentialId });
    return Object.freeze({
      challenge_id: challenge.challenge_id,
      expires_at: challenge.expires_at,
      options: Object.freeze({
        challenge: challenge.challenge,
        rpId: context.rp_id,
        timeout: timeoutMs,
        userVerification: "required",
        allowCredentials: Object.freeze([Object.freeze({ id: credentialId, type: "public-key", ...(stored.transports ? { transports: [...stored.transports] } : {}) })])
      })
    });
  }

  async function authorizeActivation(input = {}) {
    const context = normalizeContext(input, "authentication");
    const challengeId = uuid(input.challenge_id, "challenge_id");
    const assertion = normalizeAssertion(input.assertion ?? input.credential);
    const challenge = clientChallenge(assertion.client_data_json, "webauthn.get", context.origin);
    let claim;
    try {
      claim = await coordinator.claim({ ...context, challenge_id: challengeId, challenge, credential_id: assertion.credential_id });
      if (claim.already_consumed) throw failure("owner_recovery_webauthn_replayed");
      const stored = await findCredential(recoveryRepository, context, assertion.credential_id);
      const previousCounter = counter(stored.sign_count ?? stored.counter ?? 0);
      const verification = await verifyAuthentication({
        response: browserAssertion(assertion),
        expectedChallenge: challenge,
        expectedOrigin: context.origin,
        expectedRPID: context.rp_id,
        expectedType: "webauthn.get",
        requireUserVerification: true,
        credential: { id: assertion.credential_id, publicKey: bytes(stored.public_key ?? stored.publicKey, 32, 4096), counter: previousCounter, transports: stored.transports }
      });
      const info = verification?.authenticationInfo;
      if (verification?.verified !== true || info?.credentialID !== assertion.credential_id || info?.userVerified !== true || info?.origin !== context.origin || info?.rpID !== context.rp_id) throw failure("owner_recovery_webauthn_verification_failed");
      const newCounter = counter(info.newCounter);
      if ((previousCounter !== 0 || newCounter !== 0) && newCounter <= previousCounter) throw failure("owner_recovery_webauthn_verification_failed");
      const proof = Object.freeze({ authorization_id: challengeId, credential_id: assertion.credential_id, expected_sign_count: previousCounter, sign_count: newCounter, ...backupTransition(stored, info) });
      const completion = await coordinator.complete({
        ...context,
        challenge_id: challengeId,
        credential_id: assertion.credential_id,
        claim_started_at: claim.claim_started_at,
        mutate: (tx, binding) => input.complete(tx, binding, proof)
      });
      const authenticatedAt = Date.parse(completion.consumed_at);
      if (!Number.isSafeInteger(authenticatedAt)) throw failure("owner_recovery_webauthn_invalid_completion");
      return Object.freeze({
        verified: true,
        consumed: true,
        authorization_id: challengeId,
        challenge_id: challengeId,
        organization_id: context.organization_id,
        member_id: context.member_id,
        operation: context.operation,
        authenticated_at: authenticatedAt,
        mutation: completion.mutation?.mutation ?? completion.mutation
      });
    } catch (error) {
      if (claim?.claim_started_at) await safeBurn(coordinator, context.organization_id, challengeId, claim.claim_started_at);
      throw stable(error);
    }
  }

  return Object.freeze({ beginRegistration, verifyRegistration, beginActivation, authorizeActivation });
}

function normalizeContext(input, ceremony) {
  const session = input.recovery_session;
  if (!session || typeof session !== "object") throw failure("owner_recovery_webauthn_invalid_context");
  const organizationId = uuid(input.organization_id ?? session.organization_id, "organization_id");
  const memberId = uuid(input.member_id ?? session.member_id, "member_id");
  const requestId = uuid(input.request_id ?? session.request_id, "request_id");
  const recoverySessionId = uuid(session.recovery_session_id ?? session.session_id, "recovery_session_id");
  if (organizationId !== session.organization_id || memberId !== session.member_id || requestId !== session.request_id) throw failure("owner_recovery_webauthn_invalid_context");
  const rpId = requiredText(input.rp_id, 253, "rp_id");
  const origin = exactOrigin(input.origin);
  const operation = input.operation ?? OPERATIONS[ceremony];
  if (operation !== OPERATIONS[ceremony]) throw failure("owner_recovery_webauthn_invalid_context");
  return Object.freeze({ organization_id: organizationId, recovery_session_id: recoverySessionId, request_id: requestId, member_id: memberId, ceremony, operation, rp_id: rpId, origin });
}

async function findCredential(repository, context, credentialId) {
  const result = await repository.findRecoveryCredential({ ...context, ...(credentialId === undefined ? {} : { credential_id: credentialId }) });
  if (!result || result.revoked_at || result.status === "revoked") throw failure("owner_recovery_webauthn_credential_unavailable");
  return result;
}

function publicCredential(value) {
  return Object.freeze({ credential_id: credentialIdOf(value), public_key: bytes(value.public_key, 32, 4096), sign_count: counter(value.sign_count), transports: transports(value.transports), credential_device_type: value.credential_device_type, credential_backed_up: value.credential_backed_up });
}

function normalizeAssertion(value) {
  if (!value || typeof value !== "object" || value.type !== "public-key" || value.id !== value.rawId || !value.response || typeof value.response !== "object") throw failure("owner_recovery_webauthn_invalid_assertion");
  return Object.freeze({ credential_id: base64(value.rawId, 16, 1024), client_data_json: base64(value.response.clientDataJSON, 1, 16_384), authenticator_data: base64(value.response.authenticatorData, 1, 4096), signature: base64(value.response.signature, 1, 1024), ...(value.response.userHandle == null ? {} : { user_handle: base64(value.response.userHandle, 1, 64) }) });
}

function browserAssertion(value) { return { id: value.credential_id, rawId: value.credential_id, type: "public-key", clientExtensionResults: {}, response: { clientDataJSON: value.client_data_json, authenticatorData: value.authenticator_data, signature: value.signature, userHandle: value.user_handle ?? null } }; }
function clientChallenge(encoded, type, origin) { let value; try { value = JSON.parse(Buffer.from(base64(encoded, 1, 16_384), "base64url").toString("utf8")); } catch { throw failure("owner_recovery_webauthn_invalid_client_data"); } if (!value || value.type !== type || value.origin !== origin || value.crossOrigin === true) throw failure("owner_recovery_webauthn_invalid_client_data"); return base64(value.challenge, 32, 32); }
function backupTransition(stored, info) { const deviceType=info.credentialDeviceType; const backedUp=info.credentialBackedUp; if (!new Set(["singleDevice","multiDevice"]).has(deviceType)||typeof backedUp!=="boolean"||(deviceType==="singleDevice"&&backedUp)) throw failure("owner_recovery_webauthn_verification_failed"); const eligible=deviceType==="multiDevice"; const oldEligible=stored.backup_eligible ?? eligible; const oldState=stored.backup_state ?? stored.credential_backed_up ?? false; if (oldEligible!==eligible || (stored.credential_device_type!==undefined&&stored.credential_device_type!==deviceType)) throw failure("owner_recovery_webauthn_verification_failed"); return { expected_backup_eligible: oldEligible, expected_backup_state: oldState, credential_device_type: deviceType, credential_backed_up: backedUp, backup_eligible: eligible, backup_state: backedUp }; }
function credentialIdOf(value) { return base64(value.credential_id ?? value.id, 16, 1024); }
function bytes(value,min,max) { const result=Buffer.isBuffer(value)||value instanceof Uint8Array?new Uint8Array(value):typeof value==="string"?new Uint8Array(Buffer.from(base64(value,min,max),"base64url")):null; if(!result||result.length<min||result.length>max) throw failure("owner_recovery_webauthn_invalid_credential"); return result; }
function transports(value) { if(value===undefined)return undefined; if(!Array.isArray(value)||value.length>8||value.some(x=>!["ble","cable","hybrid","internal","nfc","smart-card","usb"].includes(x))) throw failure("owner_recovery_webauthn_invalid_credential"); return Object.freeze([...new Set(value)]); }
function counter(value) { if(!Number.isSafeInteger(value)||value<0||value>MAX_COUNTER) throw failure("owner_recovery_webauthn_invalid_credential"); return value; }
function base64(value,min,max) { if(typeof value!=="string"||!BASE64URL.test(value)) throw failure("owner_recovery_webauthn_invalid_request"); const decoded=Buffer.from(value,"base64url"); if(decoded.length<min||decoded.length>max||decoded.toString("base64url")!==value) throw failure("owner_recovery_webauthn_invalid_request"); return value; }
function uuid(value,label) { if(typeof value!=="string"||!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu.test(value)) throw failure(`owner_recovery_webauthn_invalid_${label}`); return value.toLowerCase(); }
function exactOrigin(value) { let parsed; try { parsed=new URL(value); } catch { throw failure("owner_recovery_webauthn_invalid_origin"); } if(parsed.protocol!=="https:"||parsed.origin!==value||parsed.pathname!=="/"||parsed.username||parsed.password) throw failure("owner_recovery_webauthn_invalid_origin"); return value; }
function requiredText(value,max,label) { if(typeof value!=="string"||value.length<1||value.length>max||/[\u0000-\u001f\u007f]/u.test(value)) throw failure(`owner_recovery_webauthn_invalid_${label}`); return value; }
function requireMethods(value,names,label) { if(!value||names.some(name=>typeof value[name]!=="function")) throw new TypeError(`${label} is invalid`); }
async function safeBurn(coordinator,organizationId,challengeId,claimStartedAt) { try { await coordinator.burn({ organization_id: organizationId, challenge_id: challengeId, claim_started_at: claimStartedAt }); } catch { /* Preserve stable ceremony error. */ } }
function failure(code) { return new OwnerRecoveryWebAuthnCeremonyError(code); }
function stable(error) { return error instanceof OwnerRecoveryWebAuthnCeremonyError ? error : failure(typeof error?.code==="string" ? error.code : "owner_recovery_webauthn_unavailable"); }
