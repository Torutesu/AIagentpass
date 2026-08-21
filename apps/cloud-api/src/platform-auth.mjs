const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
const HEX_64 = /^[0-9a-f]{64}$/iu;
const FINGERPRINT_256 = /^(?:[0-9a-f]{2}:){31}[0-9a-f]{2}$/iu;
const SPIFFE_ID = /^spiffe:\/\/[^\u0000-\u0020\u007f]{1,480}$/u;
const WORKLOAD_ID = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$/u;
const AUDIENCE = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$/u;
const OPERATION = /^[a-z][a-z0-9._:-]{0,127}$/u;
const MAX_CERT_TEXT = 4096;
export const PLATFORM_RECENT_AUTH_MAX_AGE_MS = 5 * 60 * 1000;
export const PLATFORM_RECENT_AUTH_MAX_CLOCK_SKEW_MS = 30 * 1000;
export const PLATFORM_WORKLOAD_IDENTITY_MAX_TTL_MS = 5 * 60 * 1000;

// This namespace is deliberately independent from the organization roles in
// auth.mjs. An organization owner/admin is not a platform operator.
export const PLATFORM_ROLES = Object.freeze([
  "platform_admin",
  "platform_operator",
  "platform_auditor"
]);

const PLATFORM_ROLE_LEVEL = Object.freeze({
  platform_auditor: 1,
  platform_operator: 2,
  platform_admin: 3
});

export const PLATFORM_AUTH_ERROR_CODES = Object.freeze({
  INVALID_INPUT: "platform_auth_invalid_input",
  PRINCIPAL_UNAVAILABLE: "platform_principal_unavailable",
  ROLE_REQUIRED: "platform_role_required",
  ROLE_DENIED: "platform_role_denied",
  MTLS_UNAVAILABLE: "platform_mtls_unavailable",
  MTLS_REQUIRED: "platform_mtls_required",
  MTLS_INVALID: "platform_mtls_invalid",
  MTLS_IDENTITY_MISMATCH: "platform_mtls_identity_mismatch",
  WORKLOAD_UNAVAILABLE: "platform_workload_identity_unavailable",
  WORKLOAD_FAILED: "platform_workload_identity_failed",
  WORKLOAD_INVALID: "platform_workload_identity_invalid",
  WORKLOAD_MISMATCH: "platform_workload_identity_mismatch",
  WEBAUTHN_REQUIRED: "platform_webauthn_required",
  WEBAUTHN_UNAVAILABLE: "platform_webauthn_unavailable",
  WEBAUTHN_FAILED: "platform_webauthn_failed",
  WEBAUTHN_STALE: "platform_webauthn_stale",
  WEBAUTHN_INVALID: "platform_webauthn_invalid"
});

const ERROR_MESSAGES = Object.freeze({
  [PLATFORM_AUTH_ERROR_CODES.INVALID_INPUT]: "Platform authentication input is invalid",
  [PLATFORM_AUTH_ERROR_CODES.PRINCIPAL_UNAVAILABLE]: "Platform principal verification is unavailable",
  [PLATFORM_AUTH_ERROR_CODES.ROLE_REQUIRED]: "A platform role is required",
  [PLATFORM_AUTH_ERROR_CODES.ROLE_DENIED]: "Platform role is insufficient",
  [PLATFORM_AUTH_ERROR_CODES.MTLS_UNAVAILABLE]: "Platform mTLS verification is unavailable",
  [PLATFORM_AUTH_ERROR_CODES.MTLS_REQUIRED]: "Authenticated mTLS is required",
  [PLATFORM_AUTH_ERROR_CODES.MTLS_INVALID]: "The mTLS peer identity is invalid",
  [PLATFORM_AUTH_ERROR_CODES.MTLS_IDENTITY_MISMATCH]: "The mTLS peer identity does not match",
  [PLATFORM_AUTH_ERROR_CODES.WORKLOAD_UNAVAILABLE]: "Workload identity verification is unavailable",
  [PLATFORM_AUTH_ERROR_CODES.WORKLOAD_FAILED]: "Workload identity verification failed",
  [PLATFORM_AUTH_ERROR_CODES.WORKLOAD_INVALID]: "The workload identity result is invalid",
  [PLATFORM_AUTH_ERROR_CODES.WORKLOAD_MISMATCH]: "The workload identity does not match",
  [PLATFORM_AUTH_ERROR_CODES.WEBAUTHN_REQUIRED]: "Recent WebAuthn authentication is required",
  [PLATFORM_AUTH_ERROR_CODES.WEBAUTHN_UNAVAILABLE]: "Recent WebAuthn verification is unavailable",
  [PLATFORM_AUTH_ERROR_CODES.WEBAUTHN_FAILED]: "Recent WebAuthn authentication failed",
  [PLATFORM_AUTH_ERROR_CODES.WEBAUTHN_STALE]: "Recent WebAuthn authentication is stale",
  [PLATFORM_AUTH_ERROR_CODES.WEBAUTHN_INVALID]: "The WebAuthn verification result is invalid"
});

export class PlatformAuthError extends Error {
  constructor(code, options = {}) {
    super(ERROR_MESSAGES[code] ?? "Platform authentication failed", options);
    this.name = "PlatformAuthError";
    this.code = code;
  }
}

export const AuthenticationError = PlatformAuthError;

/**
 * Platform role authorization intentionally reads only platform_role. The
 * organization role field is never a fallback for this boundary.
 */
export function platformRoleAllows(actualRole, requiredRole) {
  return PLATFORM_ROLES.includes(actualRole)
    && PLATFORM_ROLES.includes(requiredRole)
    && PLATFORM_ROLE_LEVEL[actualRole] >= PLATFORM_ROLE_LEVEL[requiredRole];
}

export function requirePlatformRole(principal, requiredRole = "platform_operator") {
  if (!isRecord(principal) || !PLATFORM_ROLES.includes(requiredRole)) fail(PLATFORM_AUTH_ERROR_CODES.ROLE_DENIED);
  if (typeof principal.platform_role !== "string") fail(PLATFORM_AUTH_ERROR_CODES.ROLE_REQUIRED);
  if (!platformRoleAllows(principal.platform_role, requiredRole)) fail(PLATFORM_AUTH_ERROR_CODES.ROLE_DENIED);
  return Object.freeze({
    member_id: principal.member_id,
    session_id: principal.session_id,
    ...(principal.organization_id === undefined ? {} : { organization_id: principal.organization_id }),
    platform_role: principal.platform_role
  });
}

/**
 * Verify the TLS transport and a pinned client identity. Header values are
 * intentionally ignored: forwarded client-certificate headers are not an
 * authentication source for this function.
 */
export function verifyPlatformMtls({ request, transport, expected = {}, now = Date.now() } = {}) {
  const socket = transport ?? request?.socket ?? request?.connection;
  if (!isRecord(socket) && (socket === null || typeof socket !== "object")) fail(PLATFORM_AUTH_ERROR_CODES.MTLS_REQUIRED);
  if (socket?.encrypted !== true || socket?.authorized !== true || socket?.authorizationError) fail(PLATFORM_AUTH_ERROR_CODES.MTLS_REQUIRED);
  assertNow(now);
  if (typeof socket.getPeerCertificate !== "function") fail(PLATFORM_AUTH_ERROR_CODES.MTLS_REQUIRED);

  const fingerprint = expected.fingerprint256 ?? expected.fingerprint_256;
  const spiffeId = expected.spiffe_id ?? expected.spiffeId;
  if (typeof fingerprint !== "string" || !FINGERPRINT_256.test(fingerprint)) fail(PLATFORM_AUTH_ERROR_CODES.MTLS_INVALID);
  if (typeof spiffeId !== "string" || !SPIFFE_ID.test(spiffeId)) fail(PLATFORM_AUTH_ERROR_CODES.MTLS_INVALID);

  let certificate;
  try { certificate = socket.getPeerCertificate(true); } catch (error) { throw new PlatformAuthError(PLATFORM_AUTH_ERROR_CODES.MTLS_INVALID, { cause: error }); }
  if (!isRecord(certificate) || typeof certificate.fingerprint256 !== "string" || !FINGERPRINT_256.test(certificate.fingerprint256)) fail(PLATFORM_AUTH_ERROR_CODES.MTLS_INVALID);
  if (certificate.ca === true) fail(PLATFORM_AUTH_ERROR_CODES.MTLS_INVALID);
  if (!validCertificateWindow(certificate, now)) fail(PLATFORM_AUTH_ERROR_CODES.MTLS_INVALID);

  const actualFingerprint = certificate.fingerprint256.toLowerCase();
  if (actualFingerprint !== fingerprint.toLowerCase()) fail(PLATFORM_AUTH_ERROR_CODES.MTLS_IDENTITY_MISMATCH);
  const actualSpiffeId = spiffeUriFromSubjectAltName(certificate.subjectaltname);
  if (actualSpiffeId !== spiffeId) fail(PLATFORM_AUTH_ERROR_CODES.MTLS_IDENTITY_MISMATCH);

  return Object.freeze({ fingerprint256: actualFingerprint, spiffe_id: actualSpiffeId });
}

/**
 * Workload identity must be obtained from a deployment-owned verifier. Raw
 * request headers or caller-supplied claims are never accepted as identity.
 */
export async function verifyPlatformWorkloadIdentity({ request, verifier, workloadId, workload_id, audience, operation, now = Date.now() } = {}) {
  const expectedWorkloadId = workloadId ?? workload_id;
  assertWorkloadId(expectedWorkloadId);
  assertAudience(audience);
  assertOperation(operation);
  assertNow(now);
  if (typeof verifier !== "function") fail(PLATFORM_AUTH_ERROR_CODES.WORKLOAD_UNAVAILABLE);

  let result;
  try {
    result = await verifier({ request, workload_id: expectedWorkloadId, audience, operation, now });
  } catch (error) {
    throw new PlatformAuthError(PLATFORM_AUTH_ERROR_CODES.WORKLOAD_FAILED, { cause: error });
  }
  if (!isRecord(result) || !hasExactKeys(result, ["verified", "workload_id", "audience", "expires_at", "mtls_fingerprint256"]) || result.verified !== true) {
    fail(PLATFORM_AUTH_ERROR_CODES.WORKLOAD_INVALID);
  }
  if (result.workload_id !== expectedWorkloadId) fail(PLATFORM_AUTH_ERROR_CODES.WORKLOAD_MISMATCH);
  if (typeof result.audience !== "string" || result.audience !== audience) fail(PLATFORM_AUTH_ERROR_CODES.WORKLOAD_MISMATCH);
  // A verified workload result is only useful as a short-lived, peer-bound
  // assertion. Accepting either field as optional would let a deployment
  // accidentally turn this into a non-expiring or non-mTLS-bound identity.
  if (!Number.isSafeInteger(result.expires_at)
    || result.expires_at <= now
    || result.expires_at - now > PLATFORM_WORKLOAD_IDENTITY_MAX_TTL_MS) {
    fail(PLATFORM_AUTH_ERROR_CODES.WORKLOAD_INVALID);
  }
  if (!FINGERPRINT_256.test(result.mtls_fingerprint256) || result.mtls_fingerprint256.toLowerCase() === "00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00") fail(PLATFORM_AUTH_ERROR_CODES.WORKLOAD_INVALID);

  return Object.freeze({
    verified: true,
    workload_id: result.workload_id,
    audience: result.audience,
    expires_at: result.expires_at,
    mtls_fingerprint256: result.mtls_fingerprint256.toLowerCase()
  });
}

/**
 * Reuse the existing recent-auth/WebAuthn verifier seam, but validate its
 * complete result and bind it to the exact operation and human principal.
 */
export async function verifyRecentPlatformWebAuthn({ verifier, recentAuthService, proof, principal, organizationId, operation, contextHash, context_hash, now = Date.now() } = {}) {
  if (verifier !== undefined && recentAuthService !== undefined) fail(PLATFORM_AUTH_ERROR_CODES.INVALID_INPUT);
  const resolvedVerifier = recentAuthService === undefined ? verifier : recentAuthService?.authorize?.bind(recentAuthService);
  if (typeof resolvedVerifier !== "function") fail(PLATFORM_AUTH_ERROR_CODES.WEBAUTHN_UNAVAILABLE);
  if (typeof proof !== "string" || !UUID_V4.test(proof) || proof !== proof.toLowerCase()) fail(PLATFORM_AUTH_ERROR_CODES.WEBAUTHN_REQUIRED);
  if (!isRecord(principal) || typeof principal.member_id !== "string" || principal.member_id.length === 0) fail(PLATFORM_AUTH_ERROR_CODES.INVALID_INPUT);
  assertOperation(operation);
  assertNow(now);
  const expectedOrganizationId = organizationId ?? principal.organization_id;
  const expectedContextHash = contextHash ?? context_hash;
  if (expectedContextHash !== undefined && (typeof expectedContextHash !== "string" || !HEX_64.test(expectedContextHash))) fail(PLATFORM_AUTH_ERROR_CODES.INVALID_INPUT);

  let result;
  try {
    result = await resolvedVerifier({
      proof,
      principal: { member_id: principal.member_id, session_id: principal.session_id, organization_id: expectedOrganizationId },
      organization_id: expectedOrganizationId,
      operation,
      ...(expectedContextHash === undefined ? {} : { context_hash: expectedContextHash }),
      now
    });
  } catch (error) {
    throw new PlatformAuthError(PLATFORM_AUTH_ERROR_CODES.WEBAUTHN_FAILED, { cause: error });
  }

  const authenticatedAt = typeof result?.authenticated_at === "string" ? Date.parse(result.authenticated_at) : result?.authenticated_at;
  if (!isRecord(result) || !hasOnlyKeys(result, ["authenticated_at", "challenge_id", "consumed", "member_id", "organization_id", "operation", "verified", "context_hash"]) || result.verified !== true || result.consumed !== true || result.challenge_id !== proof || result.member_id !== principal.member_id || result.operation !== operation || !Number.isSafeInteger(authenticatedAt) || authenticatedAt < 0) {
    fail(PLATFORM_AUTH_ERROR_CODES.WEBAUTHN_INVALID);
  }
  if (expectedOrganizationId !== undefined && result.organization_id !== expectedOrganizationId) fail(PLATFORM_AUTH_ERROR_CODES.WEBAUTHN_INVALID);
  if (expectedContextHash !== undefined && result.context_hash !== expectedContextHash) fail(PLATFORM_AUTH_ERROR_CODES.WEBAUTHN_INVALID);
  if (authenticatedAt > now + PLATFORM_RECENT_AUTH_MAX_CLOCK_SKEW_MS) fail(PLATFORM_AUTH_ERROR_CODES.WEBAUTHN_STALE);
  if (now - authenticatedAt > PLATFORM_RECENT_AUTH_MAX_AGE_MS) fail(PLATFORM_AUTH_ERROR_CODES.WEBAUTHN_STALE);

  return Object.freeze({
    verified: true,
    consumed: true,
    challenge_id: result.challenge_id,
    member_id: result.member_id,
    ...(result.organization_id === undefined ? {} : { organization_id: result.organization_id }),
    operation: result.operation,
    authenticated_at: authenticatedAt,
    ...(result.context_hash === undefined ? {} : { context_hash: result.context_hash })
  });
}

/**
 * Authorize a global Platform operation. All four independent bindings are
 * mandatory: platform role, authenticated mTLS, workload identity, and
 * operation-bound recent WebAuthn.
 */
export async function authorizePlatformOperation({
  request,
  principal,
  requiredRole = "platform_operator",
  mtls,
  mtlsVerifier = verifyPlatformMtls,
  workloadVerifier,
  verifyWorkloadIdentity = workloadVerifier,
  workloadId,
  workload_id,
  audience,
  recentAuthVerifier,
  recentAuthService,
  recentAuthProof,
  proof,
  organizationId,
  operation,
  contextHash,
  context_hash,
  now = Date.now()
} = {}) {
  const authorizedPrincipal = requirePlatformRole(principal, requiredRole);
  const expectedWorkloadId = workloadId ?? workload_id;
  assertWorkloadId(expectedWorkloadId);
  assertAudience(audience);
  const expectedMtls = isRecord(mtls) ? mtls : {};
  if (typeof mtlsVerifier !== "function") fail(PLATFORM_AUTH_ERROR_CODES.MTLS_UNAVAILABLE);
  let mtlsIdentity;
  try {
    mtlsIdentity = await mtlsVerifier({ request, expected: expectedMtls, now });
  } catch (error) {
    if (error instanceof PlatformAuthError) throw error;
    throw new PlatformAuthError(PLATFORM_AUTH_ERROR_CODES.MTLS_INVALID, { cause: error });
  }
  if (!isRecord(mtlsIdentity)
    || !hasExactKeys(mtlsIdentity, ["fingerprint256", "spiffe_id"])
    || !FINGERPRINT_256.test(mtlsIdentity.fingerprint256)
    || mtlsIdentity.fingerprint256.replaceAll(":", "").toLowerCase() === "0".repeat(64)
    || typeof mtlsIdentity.spiffe_id !== "string"
    || !SPIFFE_ID.test(mtlsIdentity.spiffe_id)) {
    fail(PLATFORM_AUTH_ERROR_CODES.MTLS_INVALID);
  }
  mtlsIdentity = Object.freeze({ fingerprint256: mtlsIdentity.fingerprint256.toLowerCase(), spiffe_id: mtlsIdentity.spiffe_id });
  if (mtlsIdentity.spiffe_id !== expectedWorkloadId) fail(PLATFORM_AUTH_ERROR_CODES.MTLS_IDENTITY_MISMATCH);

  const workloadIdentity = await verifyPlatformWorkloadIdentity({
    request,
    verifier: verifyWorkloadIdentity,
    workloadId: expectedWorkloadId,
    audience,
    operation,
    now
  });
  if (workloadIdentity.mtls_fingerprint256 !== undefined && workloadIdentity.mtls_fingerprint256 !== mtlsIdentity.fingerprint256) fail(PLATFORM_AUTH_ERROR_CODES.WORKLOAD_MISMATCH);

  const webauthn = await verifyRecentPlatformWebAuthn({
    verifier: recentAuthVerifier,
    recentAuthService,
    proof: recentAuthProof ?? proof,
    principal,
    organizationId,
    operation,
    contextHash: contextHash ?? context_hash,
    now
  });
  return Object.freeze({ principal: authorizedPrincipal, mtls: mtlsIdentity, workload: workloadIdentity, webauthn });
}

export const PLATFORM_RECENT_AUTH_HEADER = "agentpass-platform-recent-auth";

/**
 * Compose the HTTP-facing Platform authenticator from the four independent
 * trust boundaries. The principal resolver is deployment-owned; no bearer,
 * cookie, or organization session is accepted as a fallback. The function is
 * intentionally lazy about missing dependencies so a partially configured
 * deployment exposes a safe 503 instead of starting an unauthenticated route.
 */
export function createPlatformAuthenticator({
  principalResolver,
  resolvePrincipal = principalResolver,
  mtls,
  expectedMtls = mtls,
  mtlsVerifier = verifyPlatformMtls,
  workloadVerifier,
  recentAuthVerifier,
  recentAuthService,
  webauthnVerifier,
  workloadId,
  workload_id,
  audience,
  requiredRole = "platform_operator",
  recentAuthHeader = PLATFORM_RECENT_AUTH_HEADER,
  now = () => Date.now()
} = {}) {
  if (typeof now !== "function") throw new TypeError("platform authenticator clock is invalid");
  if (typeof recentAuthHeader !== "string" || !/^[a-z][a-z0-9-]{0,127}$/u.test(recentAuthHeader)) throw new TypeError("platform recent-auth header is invalid");

  return async function authenticatePlatform({ request, headers = {}, operation, context_hash, now: requestNow } = {}) {
    const currentTime = requestNow ?? now();
    if (!Number.isSafeInteger(currentTime) || currentTime < 0) throw new PlatformAuthError(PLATFORM_AUTH_ERROR_CODES.INVALID_INPUT);
    if (typeof resolvePrincipal !== "function") throw new PlatformAuthError(PLATFORM_AUTH_ERROR_CODES.PRINCIPAL_UNAVAILABLE);
    if (typeof mtlsVerifier !== "function") throw new PlatformAuthError(PLATFORM_AUTH_ERROR_CODES.MTLS_UNAVAILABLE);
    if (!isRecord(expectedMtls)
      || typeof (expectedMtls.fingerprint256 ?? expectedMtls.fingerprint_256) !== "string"
      || typeof (expectedMtls.spiffe_id ?? expectedMtls.spiffeId) !== "string") {
      throw new PlatformAuthError(PLATFORM_AUTH_ERROR_CODES.MTLS_UNAVAILABLE);
    }
    if (typeof (workloadId ?? workload_id) !== "string" || typeof audience !== "string") {
      throw new PlatformAuthError(PLATFORM_AUTH_ERROR_CODES.WORKLOAD_UNAVAILABLE);
    }

    let principal;
    try {
      principal = await resolvePrincipal({ request, headers: Object.freeze({ ...headers }), operation, now: currentTime });
    } catch (error) {
      throw new PlatformAuthError(PLATFORM_AUTH_ERROR_CODES.PRINCIPAL_UNAVAILABLE, { cause: error });
    }
    if (!isRecord(principal)) throw new PlatformAuthError(PLATFORM_AUTH_ERROR_CODES.PRINCIPAL_UNAVAILABLE);

    const proof = readHeader(headers, recentAuthHeader);
    return authorizePlatformOperation({
      request,
      principal,
      requiredRole,
      mtls: expectedMtls,
      mtlsVerifier,
      workloadVerifier,
      workloadId: workloadId ?? workload_id,
      audience,
      recentAuthVerifier: recentAuthVerifier ?? webauthnVerifier,
      recentAuthService,
      proof,
      contextHash: context_hash,
      operation,
      now: currentTime
    });
  };
}

export const authenticatePlatformRequest = authorizePlatformOperation;
export const requirePlatformAuthorization = authorizePlatformOperation;

function validCertificateWindow(certificate, now) {
  const hasFrom = certificate.valid_from !== undefined;
  const hasTo = certificate.valid_to !== undefined;
  if (!hasFrom && !hasTo) return true;
  if (typeof certificate.valid_from !== "string" || typeof certificate.valid_to !== "string") return false;
  const from = Date.parse(certificate.valid_from);
  const to = Date.parse(certificate.valid_to);
  return Number.isFinite(from) && Number.isFinite(to) && from <= now && now < to;
}

function spiffeUriFromSubjectAltName(subjectAltName) {
  if (typeof subjectAltName !== "string" || subjectAltName.length === 0 || subjectAltName.length > MAX_CERT_TEXT) return undefined;
  const entries = subjectAltName.split(/,\s*/u);
  const uri = entries.find((entry) => entry.startsWith("URI:"))?.slice(4);
  return uri && SPIFFE_ID.test(uri) ? uri : undefined;
}

function assertWorkloadId(value) {
  if (typeof value !== "string" || !WORKLOAD_ID.test(value)) fail(PLATFORM_AUTH_ERROR_CODES.INVALID_INPUT);
}

function assertOperation(value) {
  if (typeof value !== "string" || !OPERATION.test(value)) fail(PLATFORM_AUTH_ERROR_CODES.INVALID_INPUT);
}

function assertAudience(value) {
  if (typeof value !== "string" || !AUDIENCE.test(value)) fail(PLATFORM_AUTH_ERROR_CODES.INVALID_INPUT);
}

function assertNow(value) {
  if (!Number.isSafeInteger(value) || value < 0) fail(PLATFORM_AUTH_ERROR_CODES.INVALID_INPUT);
}

function hasOnlyKeys(value, allowed) {
  return Object.keys(value).every((key) => allowed.includes(key));
}

function hasExactKeys(value, expected) {
  return Object.keys(value).sort().join("\0") === [...expected].sort().join("\0");
}

function readHeader(headers, name) {
  if (!isRecord(headers)) return undefined;
  const keys = Object.keys(headers).filter((candidate) => candidate.toLowerCase() === name.toLowerCase());
  if (keys.length !== 1) return undefined;
  const value = headers[keys[0]];
  return typeof value === "string" ? value : undefined;
}

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function fail(code) {
  throw new PlatformAuthError(code);
}
