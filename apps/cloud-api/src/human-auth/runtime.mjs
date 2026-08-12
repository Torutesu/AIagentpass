import { createHumanSessionService } from "../human-session.mjs";
import { createConsoleIdentityAdapter } from "./console-identity.mjs";
import { createPostgresIdentityResolver } from "./identity/postgres-resolver.mjs";
import { createHumanAuthHttpApi } from "./http-api.mjs";
import { createHumanManagementHttpApi, HUMAN_MANAGEMENT_RECENT_AUTH_OPERATIONS } from "./management/http-api.mjs";
import { createPostgresHumanManagementRepository } from "./management/postgres-adapter.mjs";
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
  HUMAN_MANAGEMENT_RECENT_AUTH_OPERATIONS.revokeCurrentSession
]);

export function createHumanAuthRuntime({ postgresRuntime, tokenRecords, origin, rpId, identityProvider = "chatgpt", now = () => Date.now() } = {}) {
  const repository = postgresRuntime?.humanRepository;
  const pool = postgresRuntime?.pool;
  if (!repository || !pool) throw new TypeError("postgresRuntime with pool and humanRepository is required");

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
  const managementRepository = createPostgresHumanManagementRepository({ repository, now });
  const managementApi = createHumanManagementHttpApi({ humanSession, recentAuthService, repository: managementRepository, origin, now });
  const api = createHumanAuthRouter({ sessionApi, webauthnApi, registrationApi, managementApi });
  return Object.freeze({ api, humanSession, recentAuthService, ceremony, registrationCeremony, registrationService, identityResolver, managementRepository, sessionApi, webauthnApi, registrationApi, managementApi, allowedOperations: ALLOWED_RECENT_AUTH_OPERATIONS });
}
