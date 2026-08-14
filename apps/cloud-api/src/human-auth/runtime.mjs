import { createHumanSessionService } from "../human-session.mjs";
import { createConsoleIdentityAdapter } from "./console-identity.mjs";
import { createPostgresIdentityResolver } from "./identity/postgres-resolver.mjs";
import { createSignedConsoleIdentityAdapter } from "./identity/signed-console.mjs";
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
import { createSimpleWebAuthnRegistrationVerifier, createWebAuthnRegistrationService, WEBAUTHN_REGISTRATION_OPERATION, WEBAUTHN_REGISTRATION_RECENT_AUTH_OPERATION } from "./webauthn/registration.mjs";
import { createSimpleWebAuthnAssertionVerifier } from "./webauthn/simplewebauthn-adapter.mjs";
import { createHumanAuthAbuseControls } from "./rate-limit.mjs";
import { createHumanAgentSessionGrantHttpApi } from "./agent-sessions/http-api.mjs";
import { createAgentSessionGrantIssuanceService } from "./agent-sessions/issuance-service.mjs";
import { createHumanQualificationGrantBatchHttpApi } from "./agent-sessions/qualification-batch-http-api.mjs";
import { createQualificationGrantBatchService } from "./agent-sessions/qualification-batch-service.mjs";
import { createOwnerRecoveryHttpApi } from "./recovery/http-api.mjs";
import { createOwnerRecoveryDeadLetterHttpApi, OWNER_RECOVERY_DEAD_LETTER_RECENT_AUTH_OPERATIONS } from "./recovery/dead-letter-http-api.mjs";
import { createOwnerRecoveryService } from "./recovery/service.mjs";
import { createOwnerRecoveryWebAuthnCeremony } from "./recovery/webauthn-ceremony.mjs";

const ALLOWED_RECENT_AUTH_OPERATIONS = Object.freeze([
  "device.enrollment.issue",
  "device.revoke",
  "device.refresh.request",
  "organization.emergency_stop",
  "agent.session_grant.issue",
  "qualification.grant_batch.issue",
  WEBAUTHN_REGISTRATION_OPERATION,
  WEBAUTHN_REGISTRATION_RECENT_AUTH_OPERATION,
  HUMAN_MANAGEMENT_RECENT_AUTH_OPERATIONS.revokeCredential,
  HUMAN_MANAGEMENT_RECENT_AUTH_OPERATIONS.revokeCurrentSession,
  ...recentAuthOperationValues(OWNER_RECOVERY_DEAD_LETTER_RECENT_AUTH_OPERATIONS),
  ...recentAuthOperationValues(HUMAN_ORGANIZATIONS_RECENT_AUTH_OPERATIONS)
]);

export function createHumanAuthRuntime({ postgresRuntime, tokenRecords, origin, rpId, cursorSecret, identityProvider = "chatgpt", signedConsoleIdentity = undefined, agentSessionSigner = undefined, qualificationManifestSigner = undefined, now = () => Date.now() } = {}) {
  const repository = postgresRuntime?.humanRepository;
  const organizationRepository = postgresRuntime?.organizationRepository;
  const pool = postgresRuntime?.pool;
  const sharedControlRepository = postgresRuntime?.sharedControlRepository;
  if (!repository || !organizationRepository || !pool || !sharedControlRepository || typeof sharedControlRepository.acquireRateLimit !== "function") throw new TypeError("postgresRuntime with pool, humanRepository, organizationRepository, and sharedControlRepository is required");
  const cursorCodec = createHumanCursorCodec({ secret: requireCursorSecret(cursorSecret) });

  const identityResolver = createPostgresIdentityResolver({ client: pool, now });
  const consoleIdentity = signedConsoleIdentity
    ? createSignedConsoleIdentityAdapter({
      ...signedConsoleIdentity,
      identityResolver,
      replayRepository: signedConsoleIdentity.replayRepository ?? repository,
      provider: signedConsoleIdentity.provider ?? identityProvider,
      origin,
      now
    })
    : createConsoleIdentityAdapter({ tokenRecords, identityResolver, provider: identityProvider });
  const humanSession = createHumanSessionService({ repository, identityAdapter: consoleIdentity.identityAdapter, origin, now });
  const abuseControls = createHumanAuthAbuseControls({ repository: sharedControlRepository, metrics: postgresRuntime.operationalMetrics });
  const verifyAssertion = createSimpleWebAuthnAssertionVerifier({ credentialRepository: repository });
  const ceremony = createPostgresWebAuthnCeremony({ client: pool, verifyAssertion, metrics: postgresRuntime.operationalMetrics, now });
  const recentAuthService = createRecentAuthService({ ceremony, sessionRepository: repository });
  const registrationVerifier = createSimpleWebAuthnRegistrationVerifier();
  const registrationCeremony = createPostgresWebAuthnRegistrationCeremony({ client: pool, verifyAttestation: registrationVerifier.verifyAttestation, metrics: postgresRuntime.operationalMetrics, now });
  const registrationService = createWebAuthnRegistrationService({ ceremony: registrationCeremony, credentialRepository: repository, registrationVerifier, rpId, origin, now });
  const ownerRecoveryRepository = postgresRuntime.ownerRecoveryRepository;
  const ownerRecoveryWebAuthnRepository = postgresRuntime.ownerRecoveryWebAuthnRepository;
  if ((ownerRecoveryRepository === undefined) !== (ownerRecoveryWebAuthnRepository === undefined)) {
    throw new TypeError("owner recovery repositories must be provisioned together");
  }
  let recoveryCeremony;
  let recoveryService;
  let recoveryApi;
  let recoveryDeadLetterApi;
  if (ownerRecoveryRepository !== undefined) {
    recoveryCeremony = createOwnerRecoveryWebAuthnCeremony({
      coordinator: ownerRecoveryWebAuthnRepository,
      recoveryRepository: ownerRecoveryRepository,
      registrationVerifier
    });
    recoveryService = createOwnerRecoveryService({ repository: ownerRecoveryRepository, ceremony: recoveryCeremony, rpId, origin, now });
    recoveryApi = createOwnerRecoveryHttpApi({
      humanSession,
      recentAuthService,
      recoveryService,
      origin,
      abuseControls,
      now
    });
  }
  if (postgresRuntime.ownerRecoveryOutboxManagementRepository !== undefined) {
    recoveryDeadLetterApi = createOwnerRecoveryDeadLetterHttpApi({
      humanSession,
      recentAuthService,
      repository: postgresRuntime.ownerRecoveryOutboxManagementRepository,
      abuseControls,
      origin,
      now
    });
  }
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
    abuseControls,
    now
  });
  const registrationApi = createWebAuthnRegistrationHttpApi({ humanSession, registrationService, abuseControls, origin, basePath: "/api/auth" });
  const managementRepository = createPostgresHumanManagementRepository({ repository, cursorCodec, now });
  const managementApi = createHumanManagementHttpApi({ humanSession, recentAuthService, repository: managementRepository, origin, now });
  const organizationService = createPostgresOrganizationService({ repository: organizationRepository, cursorCodec, now });
  const organizationApi = createHumanOrganizationsHttpApi({ humanSession, recentAuthService, organizationService, abuseControls, origin, now });
  let agentSessionGrantApi;
  let qualificationGrantBatchApi;
  if (agentSessionSigner !== undefined) {
    if (!postgresRuntime.agentSessionIssuanceRepository) throw new TypeError("PostgreSQL Agent Session issuance repository is required");
    agentSessionGrantApi = createHumanAgentSessionGrantHttpApi({
      humanSession,
      recentAuthService,
      repository: postgresRuntime.agentSessionIssuanceRepository,
      signer: agentSessionSigner,
      origin,
      now
    });
    if (qualificationManifestSigner !== undefined) {
      if (!postgresRuntime.qualificationGrantBatchRepository) throw new TypeError("PostgreSQL qualification Grant batch repository is required");
      const grantBuilder = createAgentSessionGrantIssuanceService({
        repository: postgresRuntime.agentSessionIssuanceRepository,
        signer: agentSessionSigner,
        now
      });
      const qualificationBatchService = createQualificationGrantBatchService({
        repository: postgresRuntime.qualificationGrantBatchRepository,
        grantBuilder,
        manifestSigner: qualificationManifestSigner,
        now
      });
      qualificationGrantBatchApi = createHumanQualificationGrantBatchHttpApi({
        humanSession,
        recentAuthService,
        qualificationBatchService,
        origin,
        now
      });
    }
  } else if (qualificationManifestSigner !== undefined) {
    throw new TypeError("Agent Session signer is required for qualification Grant batches");
  }
  const api = createHumanAuthRouter({ sessionApi, webauthnApi, registrationApi, managementApi, organizationApi, ...(recoveryApi ? { recoveryApi } : {}), ...(recoveryDeadLetterApi ? { recoveryDeadLetterApi } : {}), ...(agentSessionGrantApi ? { agentSessionGrantApi } : {}), ...(qualificationGrantBatchApi ? { qualificationGrantBatchApi } : {}) });
  return Object.freeze({ api, humanSession, recentAuthService, abuseControls, ceremony, registrationCeremony, registrationService, identityResolver, consoleIdentity, managementRepository, organizationRepository, organizationService, sessionApi, webauthnApi, registrationApi, managementApi, organizationApi, ...(recoveryCeremony ? { recoveryCeremony } : {}), ...(recoveryService ? { recoveryService } : {}), ...(recoveryApi ? { recoveryApi } : {}), ...(recoveryDeadLetterApi ? { recoveryDeadLetterApi } : {}), ...(agentSessionGrantApi ? { agentSessionGrantApi } : {}), ...(qualificationGrantBatchApi ? { qualificationGrantBatchApi } : {}), allowedOperations: ALLOWED_RECENT_AUTH_OPERATIONS });
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
