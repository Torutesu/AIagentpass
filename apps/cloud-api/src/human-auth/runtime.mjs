import { createHumanSessionService } from "../human-session.mjs";
import { createConsoleIdentityAdapter } from "./console-identity.mjs";
import { createPostgresIdentityResolver } from "./identity/postgres-resolver.mjs";
import { createHumanAuthHttpApi } from "./http-api.mjs";
import { createHumanManagementHttpApi, HUMAN_MANAGEMENT_RECENT_AUTH_OPERATIONS } from "./management/http-api.mjs";
import { createPostgresHumanManagementRepository } from "./management/postgres-adapter.mjs";
import { createHumanOrganizationsHttpApi, HUMAN_ORGANIZATIONS_RECENT_AUTH_OPERATIONS } from "./organizations/http-api.mjs";
import { createPostgresOrganizationService } from "./organizations/postgres-service.mjs";
import { createHumanCursorCodec } from "./pagination/cursor-codec.mjs";
import { createWebAuthnRegistrationHttpApi } from "./registration-http-api.mjs";
import { createRecentAuthService } from "./recent-auth.mjs";
import { createHumanAuthRouter } from "./router.mjs";
import { createHumanSessionHttpApi } from "./session-http-api.mjs";
import { createPostgresWebAuthnCeremony } from "./webauthn/postgres-ceremony.mjs";
import { createPostgresWebAuthnRegistrationCeremony } from "./webauthn/postgres-registration-ceremony.mjs";
import { createSimpleWebAuthnRegistrationVerifier, createWebAuthnRegistrationService } from "./webauthn/registration.mjs";
import { createSimpleWebAuthnAssertionVerifier } from "./webauthn/simplewebauthn-adapter.mjs";

const ALLOWED_RECENT_AUTH_OPERATIONS = Object.freeze([
  "device.enrollment.issue",
  "organization.emergency_stop",
  HUMAN_MANAGEMENT_RECENT_AUTH_OPERATIONS.revokeCredential,
  HUMAN_MANAGEMENT_RECENT_AUTH_OPERATIONS.revokeCurrentSession,
  ...recentAuthOperationValues(HUMAN_ORGANIZATIONS_RECENT_AUTH_OPERATIONS)
]);

export function createHumanAuthRuntime({ postgresRuntime, tokenRecords, origin, rpId, cursorSecret, identityProvider = "chatgpt", now = () => Date.now() } = {}) {
  const repository = postgresRuntime?.humanRepository;
  const organizationRepository = postgresRuntime?.organizationRepository;
  const pool = postgresRuntime?.pool;
  if (!repository || !organizationRepository || !pool) throw new TypeError("postgresRuntime with pool, humanRepository, and organizationRepository is required");
  const cursorCodec = createHumanCursorCodec({ secret: requireCursorSecret(cursorSecret) });

  const identityResolver = createPostgresIdentityResolver({ client: pool, now });
  const consoleIdentity = createConsoleIdentityAdapter({ tokenRecords, identityResolver, provider: identityProvider });
  const humanSession = createHumanSessionService({ repository, identityAdapter: consoleIdentity.identityAdapter, origin, now });
  const verifyAssertion = createSimpleWebAuthnAssertionVerifier({ credentialRepository: repository });
  const ceremony = createPostgresWebAuthnCeremony({ client: pool, verifyAssertion, now });
  const recentAuthService = createRecentAuthService({ ceremony, sessionRepository: repository });
  const registrationVerifier = createSimpleWebAuthnRegistrationVerifier();
  const registrationCeremony = createPostgresWebAuthnRegistrationCeremony({ client: pool, verifyAttestation: registrationVerifier.verifyAttestation, now });
  const registrationService = createWebAuthnRegistrationService({ ceremony: registrationCeremony, credentialRepository: repository, registrationVerifier, rpId, origin, now });
  const sessionApi = createHumanSessionHttpApi({ humanSession, verifyIdentityRequest: consoleIdentity.verifyIdentityRequest, origin });
  const webauthnApi = createHumanAuthHttpApi({
    humanSession,
    recentAuthService,
    credentialAllowList: {
      listCredentials: ({ session, organization_id }) => repository.listCredentialsForSession({ session_id: session.session_id, organization_id })
    },
    rpId,
    origin,
    basePath: "/api/auth",
    allowedOperations: ALLOWED_RECENT_AUTH_OPERATIONS,
    now
  });
  const registrationApi = createWebAuthnRegistrationHttpApi({ humanSession, registrationService, origin, basePath: "/api/auth" });
  const managementRepository = createPostgresHumanManagementRepository({ repository, cursorCodec, now });
  const managementApi = createHumanManagementHttpApi({ humanSession, recentAuthService, repository: managementRepository, origin, now });
  const organizationService = createPostgresOrganizationService({ repository: organizationRepository, cursorCodec, now });
  const organizationApi = createHumanOrganizationsHttpApi({ humanSession, recentAuthService, organizationService, origin, now });
  const api = createHumanAuthRouter({ sessionApi, webauthnApi, registrationApi, managementApi, organizationApi });
  return Object.freeze({ api, humanSession, recentAuthService, ceremony, registrationCeremony, registrationService, identityResolver, managementRepository, organizationRepository, organizationService, sessionApi, webauthnApi, registrationApi, managementApi, organizationApi, allowedOperations: ALLOWED_RECENT_AUTH_OPERATIONS });
}

function requireCursorSecret(value) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]{43}$/u.test(value)) throw new TypeError("cursorSecret must be an exact 32-byte base64url secret");
  let bytes;
  try { bytes = Buffer.from(value, "base64url"); } catch { throw new TypeError("cursorSecret must be an exact 32-byte base64url secret"); }
  if (bytes.length !== 32 || bytes.toString("base64url") !== value) throw new TypeError("cursorSecret must be an exact 32-byte base64url secret");
  return bytes;
}

function recentAuthOperationValues(value) {
  if (Array.isArray(value)) return value;
  if (!value || typeof value !== "object") return [];
  return Object.values(value);
}
