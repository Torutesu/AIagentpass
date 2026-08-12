import { WebAuthnCeremonyError } from "./webauthn/ceremony.mjs";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export function createRecentAuthService({ ceremony, sessionRepository } = {}) {
  if (!ceremony || typeof ceremony.begin !== "function" || typeof ceremony.consume !== "function") throw new TypeError("ceremony is invalid");
  if (!sessionRepository || typeof sessionRepository.bindRecentAuth !== "function" || typeof sessionRepository.consumeRecentAuth !== "function") throw new TypeError("sessionRepository is invalid");

  const begin = ({ session, organization_id, operation, rp_id, origin } = {}) => {
    assertSession(session, organization_id);
    return ceremony.begin({ session_id: session.session_id, organization_id, operation, rp_id, origin, user_verification: "required" });
  };

  const verify = async ({ session, organization_id, operation, assertion } = {}) => {
    assertSession(session, organization_id);
    let verified;
    try {
      verified = await ceremony.consume({ ...assertion, session_id: session.session_id, organization_id, operation, user_verification: "required" });
    } catch (error) {
      if (error instanceof WebAuthnCeremonyError) throw error;
      throw new Error("Recent WebAuthn verification failed");
    }
    const bound = await sessionRepository.bindRecentAuth({
      session_id: session.session_id,
      member_id: session.member_id,
      organization_id,
      operation,
      challenge_id: verified.assertion_id,
      authenticated_at: new Date(verified.authenticated_at).toISOString()
    });
    if (!bound) throw new Error("Recent WebAuthn session binding conflict");
    return Object.freeze({ authorization_id: verified.assertion_id, authenticated_at: verified.authenticated_at, operation });
  };

  const authorize = async ({ proof, principal, organization_id, operation, now } = {}) => {
    if (typeof proof !== "string" || !UUID.test(proof) || !principal || typeof principal.member_id !== "string") return failure(principal, organization_id, operation, now);
    const consumed = await sessionRepository.consumeRecentAuth({
      challenge_id: proof,
      member_id: principal.member_id,
      organization_id,
      operation,
      consumed_at: new Date(now).toISOString()
    });
    if (!consumed) return failure(principal, organization_id, operation, now);
    const authenticatedAt = Date.parse(consumed.authenticated_at);
    if (!Number.isSafeInteger(authenticatedAt)) return failure(principal, organization_id, operation, now);
    return Object.freeze({ verified: true, consumed: true, challenge_id: proof.toLowerCase(), member_id: principal.member_id, organization_id, operation, authenticated_at: authenticatedAt });
  };

  return Object.freeze({ begin, verify, authorize });
}

function assertSession(session, organizationId) {
  if (!session || typeof session !== "object" || !UUID.test(session.session_id) || !UUID.test(session.member_id) || session.organization_id !== organizationId || session.revoked_at) throw new TypeError("human session is invalid");
}

function failure(principal, organizationId, operation, now) {
  return Object.freeze({ verified: false, consumed: false, challenge_id: "00000000-0000-4000-8000-000000000000", member_id: principal?.member_id ?? "", organization_id: organizationId ?? "", operation: operation ?? "", authenticated_at: Number.isSafeInteger(now) ? now : 0 });
}
