import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

import { createCloudApi } from "./server.mjs";
import { createPlatformPromotionHttpApi } from "./platform-promotion-http-api.mjs";
import { createPlatformSessionHttpApi } from "./platform-session-http-api.mjs";
import { createPlatformSessionRateLimiter } from "./platform-session-rate-limit.mjs";
import { createPlatformSessionWebAuthnService } from "./platform-session-webauthn.mjs";
import { createCloudStore } from "./store.mjs";
import { createPersistentReplayCache, verifyDeviceRequest } from "./auth.mjs";
import { createRateLimiter } from "./rate-limit.mjs";
import { createPostgresRuntime } from "./postgres/runtime.mjs";
import { createHumanAuthRuntime } from "./human-auth/runtime.mjs";
import { createSimpleWebAuthnRegistrationVerifier } from "./human-auth/webauthn/registration.mjs";
import { createHostedBootstrapRuntime, loadHostedBootstrapRuntimeConfig } from "./hosted-bootstrap/runtime.mjs";
import { createGithubOAuthConfig } from "./hosted-identity/github-oauth-config.mjs";
import { HOSTED_BOOTSTRAP_HTTP_PATHS } from "./hosted-bootstrap/http-api.mjs";
import { parseCloudRuntimeProfile } from "./runtime-profile.mjs";
import { createRefreshHintService } from "./refresh-hint-service.mjs";
import { createManagedRefreshHintSigner } from "./refresh-hint-signer.mjs";
import { createRefreshNonceCodec } from "./postgres/refresh-nonce-codec.mjs";
import { createHostedAgentSessionGrantSigner, parseAgentSessionSignerConfig } from "./agent-session-signer-config.mjs";
import { createProcessBindingPolicyRegistry } from "./process-binding-policy-registry.mjs";
import { createAgentSessionDeviceApi } from "./agent-session-device-api.mjs";
import { createAgentSessionSigningCapabilityApi } from "./agent-session-signing-capability-api.mjs";
import { createAgentSessionSigningCapabilityIssuanceService } from "./human-auth/agent-sessions/signing-capability-issuance-service.mjs";
import { createAgentLaunchAuthorityHandoffApi } from "./agent-launch-authority-handoff-api.mjs";
import { createQualificationGrantBatchDeviceApi } from "./qualification-grant-batch-device-api.mjs";
import { createHostedQualificationManifestSigner, parseQualificationManifestSignerConfig } from "./qualification-manifest-signer-config.mjs";
import { createOwnerRecoveryNotificationPublisher } from "./postgres/owner-recovery-notification-publisher.mjs";
import { bindHostedManagedSignerProvider } from "./hosted-managed-signer-runtime.mjs";
import { AGENT_SESSION_GRANT_TYPE, AGENT_SESSION_GRANT_VERSION } from "./agent-session-grant.mjs";
import { QUALIFICATION_GRANT_BATCH_MANIFEST_PURPOSE, QUALIFICATION_GRANT_BATCH_MANIFEST_VERSION } from "./qualification-grant-batch-manifest.mjs";
import { createHostedKmsProviders } from "./kms-provider-runtime.mjs";
import { createHostedPossessionReceiptSigner, parsePossessionReceiptSignerConfig } from "./possession-receipt-signer-config.mjs";
import { POSSESSION_RECEIPT_PURPOSE, POSSESSION_RECEIPT_VERSION } from "./possession-receipt-signer.mjs";
import { createHostedCapabilitySigner, CAPABILITY_SIGNER_PURPOSE, CAPABILITY_SIGNER_PROTOCOL_VERSION } from "./capability-signer.mjs";
import { createHostedControlBundleSigner, CONTROL_BUNDLE_MANAGED_SIGNER_PURPOSE, CONTROL_BUNDLE_MANAGED_SIGNER_PROTOCOL_VERSION } from "./control-bundle-managed-signer.mjs";
import { createHostedAuditAnchorSigner } from "./audit-anchor-signer.mjs";
import { AUDIT_ANCHOR_ALGORITHM, AUDIT_ANCHOR_PROTOCOL_VERSION, AUDIT_ANCHOR_PURPOSE } from "./audit-anchor-statement.mjs";
import { createAuditAnchorPublicKeyResolver } from "./audit-anchor-public-key-resolver.mjs";
import { createAuditExportIssuanceService } from "./audit-export-issuance.mjs";
import { verifyOfflineAuditExport } from "./audit-export-offline-verifier.mjs";
import { createPromotionEvidenceV3Signer } from "./promotion-evidence-v3-signer.mjs";
import { createPromotionEvidenceV3Verifier } from "./promotion-evidence-v3-verifier.mjs";
import { createPromotionEvidenceV3PublicKeyResolver } from "./promotion-evidence-v3-public-key-resolver.mjs";
import {
  PROMOTION_EVIDENCE_V3_ALGORITHM,
  PROMOTION_EVIDENCE_V3_MAX_TTL_MS,
  PROMOTION_EVIDENCE_V3_PROTOCOL_VERSION,
  PROMOTION_EVIDENCE_V3_PURPOSE,
  PROMOTION_EVIDENCE_V3_SIGNING_VERSION,
  PROMOTION_EVIDENCE_V3_SIGNATURE_DOMAIN,
  PROMOTION_EVIDENCE_V3_TYPE,
  PROMOTION_EVIDENCE_V3_VERSION,
  promotionEvidenceV3PublicKeyFingerprint
} from "./promotion-evidence-v3-statement.mjs";
import { isPromotionEvidenceV3Signer } from "./promotion-evidence-v3-signer.mjs";
import { createPlatformAuthorizedPromotionService } from "./postgres/platform-authorization-repository.mjs";
import { createPlatformOperatorAuthorizer } from "./platform-operator-authorizer.mjs";
import { PROTOCOL_VERSION, REFRESH_HINT_SIGNATURE_ALGORITHM, REFRESH_HINT_TYPE } from "../../../packages/protocol/src/index.mjs";

const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
const AGENT_SESSION_SIGNING_CAPABILITY_PURPOSE = "git.commit.sign";

/**
 * Compose the F2 signing-capability API at the production boundary.
 *
 * The signer is deliberately an injected, purpose-specific object. This
 * seam does not discover a KMS provider, read signer configuration, or fall
 * back to the generic capability signer. The caller must provide the
 * PostgreSQL session binder and a factory for tenant/session-bound
 * reservation repositories as well.
 */
export function createAgentSessionSigningCapabilityRuntimeComposition({
  deviceRequestVerifier,
  sessionBinder,
  reservationRepositoryFactory,
  signer,
  signerKeyId = undefined,
  grantVerifier,
  repository,
  rateLimiter = undefined,
  now = () => Date.now(),
  requestIdFactory = undefined,
  maxBodyBytes = undefined
} = {}) {
  if (typeof deviceRequestVerifier !== "function") throw new TypeError("signing capability deviceRequestVerifier is required");
  if (!sessionBinder || (typeof sessionBinder !== "function" && typeof sessionBinder.bindAgentSession !== "function")) {
    throw new TypeError("signing capability sessionBinder is required");
  }
  if (typeof reservationRepositoryFactory !== "function") throw new TypeError("signing capability reservationRepositoryFactory is required");
  if (!signer || typeof signer !== "object" || Array.isArray(signer)
    || (typeof signer.signAgentSigningCapability !== "function" && typeof signer.sign !== "function")
    || signer.purpose !== AGENT_SESSION_SIGNING_CAPABILITY_PURPOSE) {
    throw new TypeError("purpose-separated signing capability signer is required");
  }
  const resolvedSignerKeyId = signerKeyId ?? signer.key_id ?? signer.keyId;
  if (typeof resolvedSignerKeyId !== "string" || !IDENTIFIER.test(resolvedSignerKeyId)) {
    throw new TypeError("signing capability signer key id is required");
  }
  if (typeof grantVerifier !== "function") throw new TypeError("Agent Session grant verifier is required");
  if (!repository || typeof repository.consumeAgentSessionGrant !== "function") {
    throw new TypeError("Agent Session repository is required");
  }
  if (typeof now !== "function") throw new TypeError("signing capability now must be a function");

  const signingCapabilityApi = createAgentSessionSigningCapabilityApi({
    deviceRequestVerifier,
    sessionBinder,
    issuanceServiceFactory: async ({ organization_id, device_id, session_id, binding } = {}) => {
      const context = normalizeAgentSessionSigningCapabilityBinding({
        organization_id,
        device_id,
        session_id,
        binding
      });
      const reservationRepository = await reservationRepositoryFactory(context);
      if (!reservationRepository || typeof reservationRepository.reserveCapability !== "function"
        || typeof reservationRepository.commitCapability !== "function"
        || typeof reservationRepository.replayCapability !== "function"
        || typeof reservationRepository.markCapabilityUncertain !== "function") {
        throw new TypeError("signing capability reservation repository is unavailable");
      }
      return createAgentSessionSigningCapabilityIssuanceService({
        repository: reservationRepository,
        signer,
        signerKeyId: resolvedSignerKeyId,
        now
      });
    },
    rateLimiter,
    now,
    ...(requestIdFactory === undefined ? {} : { requestIdFactory }),
    ...(maxBodyBytes === undefined ? {} : { maxBodyBytes })
  });

  // The Device boundary authenticates raw bytes once, then delegates the
  // already-authenticated request to this exact method. Passing the method,
  // rather than the standalone API's handle(), prevents a second Device
  // authentication attempt and keeps the trusted binding explicit.
  const agentSessionDeviceApi = createAgentSessionDeviceApi({
    deviceRequestVerifier,
    grantVerifier,
    repository,
    rateLimiter,
    signingCapabilityHandler: signingCapabilityApi.handleAuthenticated,
    now,
    ...(requestIdFactory === undefined ? {} : { requestIdFactory }),
    ...(maxBodyBytes === undefined ? {} : { maxBodyBytes })
  });

  return Object.freeze({
    agentSessionDeviceApi,
    agentSessionSigningCapabilityApi: signingCapabilityApi,
    signingCapabilityApi
  });
}

function normalizeAgentSessionSigningCapabilityBinding({ organization_id, device_id, session_id, binding } = {}) {
  const bindingValue = binding && typeof binding === "object" && !Array.isArray(binding) ? binding : {};
  const organizationId = bindingValue.organization_id ?? bindingValue.organizationId ?? organization_id;
  const deviceId = bindingValue.device_id ?? bindingValue.deviceId ?? device_id;
  const sessionId = bindingValue.session_id ?? bindingValue.sessionId ?? session_id;
  const grantId = bindingValue.grant_id ?? bindingValue.grantId;
  const agentId = bindingValue.agent_id ?? bindingValue.agentId;
  if (!UUID.test(String(organizationId ?? "")) || !UUID.test(String(deviceId ?? ""))
    || !UUID.test(String(sessionId ?? "")) || !UUID.test(String(grantId ?? "")) || !UUID.test(String(agentId ?? ""))
    || organizationId !== organization_id || deviceId !== device_id || sessionId !== session_id) {
    throw new TypeError("signing capability session binding is unavailable");
  }
  return Object.freeze({
    organizationId: organizationId.toLowerCase(),
    sessionId: sessionId.toLowerCase(),
    grantId: grantId.toLowerCase(),
    deviceId: deviceId.toLowerCase(),
    agentId: agentId.toLowerCase()
  });
}

export async function createCloudRuntime({ env = process.env, logger = console, postgresFactory = createPostgresRuntime, humanAuthFactory = createHumanAuthRuntime, kmsProviderFactory = createHostedKmsProviders, agentSessionSignerProvider, agentSessionSignerFactory = createHostedAgentSessionGrantSigner, agentSessionSigningCapabilitySigner, qualificationManifestSignerProvider, qualificationManifestSignerFactory = createHostedQualificationManifestSigner, possessionReceiptSignerProvider, possessionReceiptSignerFactory = createHostedPossessionReceiptSigner, refreshHintSignerProvider, capabilitySignerProvider, controlBundleSignerProvider, auditAnchorSignerProvider, promotionEvidenceSignerProvider, platformOperatorAuthorizer, ownerRecoveryPublisher, platformSession, platformSessionBootstrapAuthenticator, platformSessionAuthorityResolver, platformSessionWebAuthnVerify, platformSessionOrigin, platformSessionRpId } = {}) {
  const profile = parseCloudRuntimeProfile(env);
  const config = loadRuntimeConfig(env);
  if (profile.isHosted && platformOperatorAuthorizer !== undefined) {
    throw new Error("Hosted platform operator authorization must be composed from PostgreSQL");
  }
  if (profile.isHosted && (platformSessionBootstrapAuthenticator !== undefined
    || platformSessionAuthorityResolver !== undefined
    || platformSessionWebAuthnVerify !== undefined
    || typeof platformSession?.bootstrapAuthenticator === "function"
    || typeof platformSession?.authorityResolver === "function"
    || typeof platformSession?.webauthnVerify === "function")) {
    throw new Error("Hosted platform session authority must be composed from PostgreSQL and the built-in WebAuthn verifier");
  }
  const configuredOwnerRecoveryPublisher = profile.isHosted
    ? ownerRecoveryPublisher ?? createConfiguredOwnerRecoveryPublisher(config.ownerRecoveryNotification)
    : undefined;
  const tokenRecords = profile.isHosted ? [] : readProtectedJson(config.tokenRecordsPath, "token records", 1024 * 1024);
  if (!Array.isArray(tokenRecords) || tokenRecords.length > 256 || (!config.humanAuth && tokenRecords.length < 1)) throw new Error("Cloud token records are invalid");
  let privateKey;
  if (profile.isEvaluation) {
    const privateKeyPEM = readProtectedFile(config.bundlePrivateKeyPath, "bundle private key", 16 * 1024).toString("utf8");
    try { privateKey = crypto.createPrivateKey(privateKeyPEM); } catch { throw new Error("Cloud bundle private key is invalid"); }
    if (privateKey.asymmetricKeyType !== "ed25519") throw new Error("Cloud bundle private key must be Ed25519");
  }
  let refreshHintSigner;
  let refreshNonceCodec;
  let refreshPublicKey;
  let agentSessionSigner;
  let qualificationManifestSigner;
  let possessionReceiptSigner;
  let capabilitySigner;
  let controlBundleSigner;
  let auditAnchorSigner;
  let auditExportIssuanceService;
  let auditExportVerifier;
  let promotionEvidenceSigner;
  let platformPromotionHttpApi;
  let platformPromotionReadiness;
  let platformSessionHttpApi;
  let platformSessionRateLimiter;
  let platformSessionReadiness;
  let effectivePlatformOperatorAuthorizer = platformOperatorAuthorizer;
  let verifyPlatformPromotionEvidence;
  let ownedKmsProviders;
  let processBindingPolicies;
  if (profile.isHosted) {
    try { refreshPublicKey = crypto.createPublicKey(config.refreshPublicKey); } catch { throw new Error("Cloud refresh public key is invalid"); }
    if (refreshPublicKey.asymmetricKeyType !== "ed25519") throw new Error("Cloud refresh public key must be Ed25519");
    const bundlePublic = crypto.createPublicKey(config.controlBundlePublicKey).export({ type: "spki", format: "der" });
    const refreshPublic = refreshPublicKey.export({ type: "spki", format: "der" });
    if (bundlePublic.equals(refreshPublic)) throw new Error("Cloud refresh key must be purpose-separated from the bundle key");
    const capabilityPublic = crypto.createPublicKey(config.capabilityPublicKey).export({ type: "spki", format: "der" });
    if (bundlePublic.equals(capabilityPublic) || refreshPublic.equals(capabilityPublic)) throw new Error("Cloud capability key must be purpose-separated");
    refreshNonceCodec = loadRefreshNonceCodec(config.refreshNonceKeyringPath);
    processBindingPolicies = createProcessBindingPolicyRegistry(readProtectedJson(config.agentSessionProcessPoliciesPath, "Agent Session process policies", 256 * 1024));
  }
  const cursorSecret = config.humanAuth ? requireHumanCursorSecret(env.AGENTPASS_HUMAN_CURSOR_SECRET) : undefined;
  const humanAuthSecret = config.humanAuth ? exactRuntimeSecret(env.AGENTPASS_HUMAN_AUTH_SECRET, "AGENTPASS_HUMAN_AUTH_SECRET") : undefined;
  if (profile.isHosted) {
    const hostedBootstrapConfig = loadHostedBootstrapRuntimeConfig(env, { humanAuthSecret });
    const githubOAuthConfig = createGithubOAuthConfig(env);
    if (githubOAuthConfig.redirectUri !== `${hostedBootstrapConfig.origin}${HOSTED_BOOTSTRAP_HTTP_PATHS.githubCallback}`) {
      throw new Error("Hosted GitHub redirect URI does not match the bootstrap callback");
    }
  }
  const consoleIdentityPublicKey = config.humanAuth
    ? readProtectedFile(config.humanAuth.identityAssertionPublicKeyPath, "console identity public key", 16 * 1024).toString("utf8")
    : undefined;
  // Hosted instances share the Human cursor root, while the audit codec uses
  // its own domain separator. This keeps Cloud audit cursors valid across
  // restarts/instances without exposing another secret in runtime metadata.
  let store;
  let postgresRuntime;
  let humanAuthRuntime;
  let hostedBootstrapRuntime;
  let server;
  let agentSessionSigningCapabilityApi;
  try {
    if (profile.isHosted) {
      postgresRuntime = await postgresFactory({
        env,
        applicationVersion: "0.18.0",
        refreshNonceCodec,
        resolveProcessBindingPolicy: processBindingPolicies.resolve,
        ownerRecoveryPublisher: configuredOwnerRecoveryPublisher,
        platformPromotionVerifyEvidence: async (envelope, context) => {
          if (typeof verifyPlatformPromotionEvidence !== "function") return false;
          return verifyPlatformPromotionEvidence(envelope, context);
        }
      });
      if (!postgresRuntime?.managedSignerOperationGate
        || typeof postgresRuntime.managedSignerOperationGate.track !== "function"
        || typeof postgresRuntime.managedSignerOperationGate.assertAccepting !== "function") {
        throw new Error("PostgreSQL managed signer drain authority is unavailable");
      }
      if (!postgresRuntime?.capabilityAuthorityRepository
        || typeof postgresRuntime.capabilityAuthorityRepository.issueCapabilityMetadata !== "function"
        || typeof postgresRuntime.capabilityAuthorityRepository.listRevokedCapabilityIds !== "function") {
        throw new Error("PostgreSQL capability authority is unavailable");
      }
      if (!postgresRuntime?.controlPlaneStore) throw new Error("PostgreSQL control-plane store is unavailable");
      if (!postgresRuntime?.agentSessionIssuanceRepository || !postgresRuntime?.agentSessionAuthorityRepository) throw new Error("PostgreSQL Agent Session authority is unavailable");
      if (!postgresRuntime?.auditExportIssuanceRepository) throw new Error("PostgreSQL audit export authority is unavailable");
      if (!postgresRuntime?.platformPromotionIssuanceRepository
        || typeof postgresRuntime.createPlatformAuthorizationRepository !== "function") throw new Error("PostgreSQL platform promotion authority is unavailable");
      if (!postgresRuntime?.sharedControlRepository || typeof postgresRuntime.sharedControlRepository.consumeDeviceRequestNonce !== "function" || typeof postgresRuntime.sharedControlRepository.acquireRateLimit !== "function" || typeof postgresRuntime.sharedControlRepository.acquireAnonymousRateLimit !== "function") throw new Error("PostgreSQL shared controls are unavailable");
      store = postgresRuntime.controlPlaneStore;
      if (typeof store.pollDeviceRefresh !== "function" || typeof store.markDeviceRefreshDelivered !== "function") throw new Error("PostgreSQL refresh polling is unavailable");
      if (!postgresRuntime.refreshHintNotifier || typeof postgresRuntime.refreshHintNotifier.waitForRefresh !== "function") throw new Error("PostgreSQL refresh notification is unavailable");
      const platformSessionConfig = normalizePlatformSessionRuntimeConfig({
        platformSession,
        bootstrapAuthenticator: platformSessionBootstrapAuthenticator,
        authorityResolver: platformSessionAuthorityResolver,
        webauthnVerify: platformSessionWebAuthnVerify,
        origin: platformSessionOrigin ?? env.AGENTPASS_PLATFORM_SESSION_ORIGIN ?? config.humanAuth?.origin,
        rpId: platformSessionRpId ?? env.AGENTPASS_PLATFORM_SESSION_RP_ID ?? config.humanAuth?.rpId
      });
      if (platformSessionConfig.enabled) {
        if (!postgresRuntime.platformSessionWebAuthnRepository || !postgresRuntime.platformSessionRepository
          || !postgresRuntime.platformSessionBootstrapRepository) throw new Error("PostgreSQL platform session authority is unavailable");
        const defaultComposition = createHostedPlatformSessionComposition({
          bootstrapRepository: postgresRuntime.platformSessionBootstrapRepository,
          webauthnRepository: postgresRuntime.platformSessionWebAuthnRepository,
          origin: platformSessionConfig.origin,
          rpId: platformSessionConfig.rpId
        });
        const bootstrapAuthenticator = platformSessionConfig.bootstrapAuthenticator ?? defaultComposition.bootstrapAuthenticator;
        const authorityResolver = platformSessionConfig.authorityResolver ?? defaultComposition.authorityResolver;
        const composedPlatformSessionConfig = Object.freeze({
          ...platformSessionConfig,
          bootstrapAuthenticator,
          authorityResolver
        });
        platformSessionReadiness = createPlatformSessionCompositionReadiness(composedPlatformSessionConfig);
        const ceremony = createPlatformSessionWebAuthnService({
          repository: postgresRuntime.platformSessionWebAuthnRepository,
          ...(platformSessionConfig.webauthnVerify === undefined ? {} : { webauthnVerify: platformSessionConfig.webauthnVerify })
        });
        const resolveAuthorityContext = async (input) => {
          const resolved = await authorityResolver(input);
          if (!resolved || resolved.rp_id !== composedPlatformSessionConfig.rpId) throw new Error("platform session RP authority is unavailable");
          return resolved;
        };
        platformSessionRateLimiter = createPlatformSessionRateLimiter({
          repository: postgresRuntime.sharedControlRepository,
          bucketSecret: humanAuthSecret
        });
        platformSessionHttpApi = createPlatformSessionHttpApi({
          platformSessionWebAuthn: ceremony,
          authenticatedBootstrap: bootstrapAuthenticator,
          trustedAuthorityResolver: resolveAuthorityContext,
          revokeService: postgresRuntime.platformSessionRepository,
          rateLimiter: platformSessionRateLimiter,
          origin: composedPlatformSessionConfig.origin
        });
      } else {
        platformSessionReadiness = async () => Object.freeze({ enabled: false, ok: true, code: "disabled" });
      }
      const injectedProviderCount = [agentSessionSignerProvider, qualificationManifestSignerProvider, possessionReceiptSignerProvider, refreshHintSignerProvider, capabilitySignerProvider, controlBundleSignerProvider, auditAnchorSignerProvider, promotionEvidenceSignerProvider]
        .filter((value) => value !== undefined).length;
      if (injectedProviderCount !== 0 && injectedProviderCount !== 8) throw new Error("Cloud managed signer provider set is incomplete");
      if (injectedProviderCount === 0) {
        ownedKmsProviders = await kmsProviderFactory({ env });
        agentSessionSignerProvider = ownedKmsProviders?.agentSessionSignerProvider;
        qualificationManifestSignerProvider = ownedKmsProviders?.qualificationManifestSignerProvider;
        possessionReceiptSignerProvider = ownedKmsProviders?.possessionReceiptSignerProvider;
        refreshHintSignerProvider = ownedKmsProviders?.refreshHintSignerProvider;
        capabilitySignerProvider = ownedKmsProviders?.capabilitySignerProvider;
        controlBundleSignerProvider = ownedKmsProviders?.controlBundleSignerProvider;
        auditAnchorSignerProvider = ownedKmsProviders?.auditAnchorSignerProvider;
        promotionEvidenceSignerProvider = ownedKmsProviders?.promotionEvidenceSignerProvider;
      }
      if ([agentSessionSignerProvider, qualificationManifestSignerProvider, possessionReceiptSignerProvider, refreshHintSignerProvider, capabilitySignerProvider, controlBundleSignerProvider, auditAnchorSignerProvider, promotionEvidenceSignerProvider]
        .some((provider) => provider === undefined)) throw new Error("Cloud managed signer provider set is incomplete");

      const controlBundleFingerprint = publicKeyFingerprint(config.controlBundlePublicKey);
      const durableControlBundle = await bindHostedManagedSignerProvider({
        postgresRuntime,
        operationGate: postgresRuntime.managedSignerOperationGate,
        provider: controlBundleSignerProvider,
        purpose: CONTROL_BUNDLE_MANAGED_SIGNER_PURPOSE,
        keyId: config.keyId,
        version: CONTROL_BUNDLE_MANAGED_SIGNER_PROTOCOL_VERSION,
        algorithm: "ed25519",
        publicKey: config.controlBundlePublicKey,
        publicKeyFingerprint: controlBundleFingerprint
      });
      controlBundleSigner = createHostedControlBundleSigner({
        provider: durableControlBundle.provider,
        keyId: config.keyId,
        publicKey: config.controlBundlePublicKey,
        maxTtlMs: config.ttlMs,
        maxOfflineTtlMs: config.offlineTtlMs
      });

      const capabilityFingerprint = publicKeyFingerprint(config.capabilityPublicKey);
      const durableCapability = await bindHostedManagedSignerProvider({
        postgresRuntime,
        operationGate: postgresRuntime.managedSignerOperationGate,
        provider: capabilitySignerProvider,
        purpose: CAPABILITY_SIGNER_PURPOSE,
        keyId: config.capabilityKeyId,
        version: CAPABILITY_SIGNER_PROTOCOL_VERSION,
        algorithm: "ed25519",
        publicKey: config.capabilityPublicKey,
        publicKeyFingerprint: capabilityFingerprint
      });
      capabilitySigner = createHostedCapabilitySigner({
        provider: durableCapability.provider,
        keyId: config.capabilityKeyId,
        publicKey: config.capabilityPublicKey
      });

      const auditAnchorFingerprint = publicKeyFingerprint(config.auditAnchorPublicKey);
      const durableAuditAnchor = await bindHostedManagedSignerProvider({
        postgresRuntime,
        operationGate: postgresRuntime.managedSignerOperationGate,
        provider: auditAnchorSignerProvider,
        purpose: AUDIT_ANCHOR_PURPOSE,
        keyId: config.auditAnchorKeyId,
        version: AUDIT_ANCHOR_PROTOCOL_VERSION,
        algorithm: AUDIT_ANCHOR_ALGORITHM,
        publicKey: config.auditAnchorPublicKey,
        publicKeyFingerprint: auditAnchorFingerprint
      });
      auditAnchorSigner = createHostedAuditAnchorSigner({
        provider: durableAuditAnchor.provider,
        keyId: config.auditAnchorKeyId,
        keyVersion: durableAuditAnchor.key_version,
        lifecycleVersion: durableAuditAnchor.lifecycle.version,
        publicKey: config.auditAnchorPublicKey,
        timeoutMs: config.auditAnchorTimeoutMs
      });
      const auditAnchorPublicKeyResolver = createAuditAnchorPublicKeyResolver({ repository: durableAuditAnchor.repository });
      auditExportIssuanceService = createAuditExportIssuanceService({
        repository: postgresRuntime.auditExportIssuanceRepository,
        signer: auditAnchorSigner,
        publicKeyResolver: auditAnchorPublicKeyResolver,
        deploymentMode: "hosted"
      });
      auditExportVerifier = Object.freeze({
        verifyAuditExport: (input) => verifyOfflineAuditExport(input, { publicKeyResolver: auditAnchorPublicKeyResolver, now: Date.now() })
      });

      const promotionEvidenceFingerprint = publicKeyFingerprint(config.promotionEvidencePublicKey);
      const durablePromotionEvidence = await bindHostedManagedSignerProvider({
        postgresRuntime,
        operationGate: postgresRuntime.managedSignerOperationGate,
        provider: promotionEvidenceSignerProvider,
        purpose: PROMOTION_EVIDENCE_V3_PURPOSE,
        keyId: config.promotionEvidenceKeyId,
        version: PROMOTION_EVIDENCE_V3_SIGNING_VERSION,
        algorithm: PROMOTION_EVIDENCE_V3_ALGORITHM,
        publicKey: config.promotionEvidencePublicKey,
        publicKeyFingerprint: promotionEvidenceFingerprint
      });
      promotionEvidenceSigner = createPromotionEvidenceV3Signer({
        provider: durablePromotionEvidence.provider,
        keyId: config.promotionEvidenceKeyId,
        keyVersion: durablePromotionEvidence.key_version,
        lifecycleVersion: durablePromotionEvidence.lifecycle.version,
        publicKey: config.promotionEvidencePublicKey,
        timeoutMs: config.promotionEvidenceTimeoutMs
      });
      const promotionEvidenceLifecycleRepository = Object.freeze({
        snapshot: () => durablePromotionEvidence.repository.snapshot()
      });
      const promotionEvidencePublicKeyResolver = createPromotionEvidenceV3PublicKeyResolver({
        repository: promotionEvidenceLifecycleRepository
      });
      verifyPlatformPromotionEvidence = createDynamicPromotionEvidenceVerifier({
        resolver: promotionEvidencePublicKeyResolver,
        maxTtlMs: PROMOTION_EVIDENCE_V3_MAX_TTL_MS
      });
      if (!platformSessionHttpApi || !platformSessionRateLimiter) {
        throw new Error("Hosted Platform promotion requires Platform Session authority");
      }
      const platformAuthorizationRepository = postgresRuntime.createPlatformAuthorizationRepository({
        keyId: config.promotionEvidenceKeyId,
        keyVersion: durablePromotionEvidence.key_version,
        lifecycleVersion: durablePromotionEvidence.lifecycle.version
      });
      const rawPlatformAuthorizedPromotionService = createPlatformAuthorizedPromotionService({
        repository: platformAuthorizationRepository,
        signer: promotionEvidenceSigner,
        publicKeyResolver: promotionEvidencePublicKeyResolver
      });
      const platformAuthorizedPromotionService = trackAuthorizedPlatformPromotionService(
        rawPlatformAuthorizedPromotionService,
        postgresRuntime.trackInFlight
      );
      platformPromotionHttpApi = createPlatformPromotionHttpApi({
        promotionService: platformAuthorizedPromotionService,
        rateLimiter: platformSessionRateLimiter,
        origin: platformSessionHttpApi.expectedOrigin
      });
      platformPromotionReadiness = createPlatformPromotionCompositionReadiness({
        httpApi: platformPromotionHttpApi,
        repository: platformAuthorizationRepository,
        signer: promotionEvidenceSigner,
        lifecycleRepository: durablePromotionEvidence.repository,
        keyId: config.promotionEvidenceKeyId,
        keyVersion: durablePromotionEvidence.key_version,
        lifecycleVersion: durablePromotionEvidence.lifecycle.version
      });
      const refreshFingerprint = crypto.createHash("sha256").update(refreshPublicKey.export({ type: "spki", format: "der" })).digest("hex");
      const durableRefreshHint = await bindHostedManagedSignerProvider({
        postgresRuntime,
        operationGate: postgresRuntime.managedSignerOperationGate,
        provider: refreshHintSignerProvider,
        purpose: REFRESH_HINT_TYPE,
        keyId: config.refreshKeyId,
        version: PROTOCOL_VERSION,
        algorithm: REFRESH_HINT_SIGNATURE_ALGORITHM,
        publicKey: config.refreshPublicKey,
        publicKeyFingerprint: refreshFingerprint
      });
      refreshHintSigner = createManagedRefreshHintSigner({ provider: durableRefreshHint.provider, keyId: config.refreshKeyId });
      const refreshSignerHealth = await refreshHintSigner.health();
      if (refreshSignerHealth.ready !== true || refreshSignerHealth.key_id !== config.refreshKeyId) throw new Error("Cloud refresh hint signer is unavailable");
      // Managed signers are intentionally composed only after PostgreSQL has
      // completed migration/readiness setup. The durable signer layer added at
      // this boundary can therefore bind every provider call to schema-backed
      // lifecycle and idempotency state before Human or Device APIs exist.
      const agentSessionReferences = {
        bundle: { keyId: config.keyId, publicKey: config.controlBundlePublicKey },
        refresh: { keyId: config.refreshKeyId, publicKey: refreshPublicKey }
      };
      const agentSessionSignerConfig = parseAgentSessionSignerConfig(env, agentSessionReferences);
      const durableAgentSession = await bindHostedManagedSignerProvider({
        postgresRuntime,
        operationGate: postgresRuntime.managedSignerOperationGate,
        provider: agentSessionSignerProvider,
        purpose: agentSessionSignerConfig.purpose,
        keyId: agentSessionSignerConfig.keyId,
        version: AGENT_SESSION_GRANT_VERSION,
        algorithm: agentSessionSignerConfig.algorithm,
        publicKey: agentSessionSignerConfig.publicKeyPem,
        publicKeyFingerprint: agentSessionSignerConfig.publicKeyFingerprint
      });
      agentSessionSigner = await agentSessionSignerFactory({
        provider: durableAgentSession.provider,
        env,
        references: agentSessionReferences
      });
      if (!agentSessionSigner || typeof agentSessionSigner.signAgentSessionGrant !== "function"
        || typeof agentSessionSigner.verifyAgentSessionGrant !== "function"
        || typeof agentSessionSigner.verificationKeyMetadata !== "function"
        || typeof agentSessionSigner.health !== "function" || typeof agentSessionSigner.key_id !== "string") throw new Error("Cloud Agent Session signer is unavailable");
      const signerHealth = await agentSessionSigner.health();
      if (signerHealth?.ready !== true || signerHealth.key_id !== agentSessionSigner.key_id) throw new Error("Cloud Agent Session signer is unavailable");
      const agentSessionVerificationKeys = await agentSessionSigner.verificationKeyMetadata();
      const qualificationManifestReferences = {
        bundle: { keyId: config.keyId, publicKey: config.controlBundlePublicKey },
        refresh: { keyId: config.refreshKeyId, publicKey: refreshPublicKey },
        agentSession: agentSessionVerificationKeys.keys.map((key) => ({ keyId: key.key_id, publicKey: key.public_key }))
      };
      const qualificationSignerConfig = parseQualificationManifestSignerConfig(env, qualificationManifestReferences);
      const activeQualificationKey = qualificationSignerConfig.keys.find((key) => key.status === "active");
      const durableQualificationManifest = await bindHostedManagedSignerProvider({
        postgresRuntime,
        operationGate: postgresRuntime.managedSignerOperationGate,
        provider: qualificationManifestSignerProvider,
        purpose: QUALIFICATION_GRANT_BATCH_MANIFEST_PURPOSE,
        keyId: qualificationSignerConfig.keyId,
        version: QUALIFICATION_GRANT_BATCH_MANIFEST_VERSION,
        algorithm: "ed25519",
        publicKey: activeQualificationKey?.public_key,
        publicKeyFingerprint: qualificationSignerConfig.publicKeyFingerprint
      });
      qualificationManifestSigner = await qualificationManifestSignerFactory({
        provider: durableQualificationManifest.provider,
        env,
        references: qualificationManifestReferences
      });
      if (!qualificationManifestSigner || typeof qualificationManifestSigner.signQualificationGrantBatchManifest !== "function"
        || typeof qualificationManifestSigner.verifyQualificationGrantBatchManifest !== "function"
        || typeof qualificationManifestSigner.verificationKeyMetadata !== "function"
        || typeof qualificationManifestSigner.health !== "function" || typeof qualificationManifestSigner.key_id !== "string") throw new Error("Cloud qualification manifest signer is unavailable");
      const qualificationSignerHealth = await qualificationManifestSigner.health();
      if (qualificationSignerHealth?.ready !== true || qualificationSignerHealth.key_id !== qualificationManifestSigner.key_id) throw new Error("Cloud qualification manifest signer is unavailable");
      const possessionReceiptReferences = {
        bundle: { keyId: config.keyId, publicKey: config.controlBundlePublicKey },
        refresh: { keyId: config.refreshKeyId, publicKey: refreshPublicKey },
        agentSession: agentSessionVerificationKeys.keys.map((key) => ({ keyId: key.key_id, publicKey: key.public_key })),
        qualificationManifest: (await qualificationManifestSigner.verificationKeyMetadata()).keys
          .map((key) => ({ keyId: key.key_id, publicKey: key.public_key }))
      };
      const possessionSignerConfig = parsePossessionReceiptSignerConfig(env, possessionReceiptReferences);
      const durablePossessionReceipt = await bindHostedManagedSignerProvider({
        postgresRuntime,
        operationGate: postgresRuntime.managedSignerOperationGate,
        provider: possessionReceiptSignerProvider,
        purpose: possessionSignerConfig.purpose,
        keyId: possessionSignerConfig.keyId,
        version: POSSESSION_RECEIPT_VERSION,
        algorithm: possessionSignerConfig.algorithm,
        publicKey: possessionSignerConfig.publicKeyPem,
        publicKeyFingerprint: possessionSignerConfig.publicKeyFingerprint
      });
      possessionReceiptSigner = await possessionReceiptSignerFactory({
        provider: durablePossessionReceipt.provider,
        env,
        references: possessionReceiptReferences
      });
      if (!possessionReceiptSigner || typeof possessionReceiptSigner.signPossessionReceipt !== "function"
        || typeof possessionReceiptSigner.verificationKeyMetadata !== "function"
        || typeof possessionReceiptSigner.health !== "function" || typeof possessionReceiptSigner.key_id !== "string") throw new Error("Cloud possession receipt signer is unavailable");
      const possessionSignerHealth = await possessionReceiptSigner.health();
      if (possessionSignerHealth?.ready !== true || possessionSignerHealth.key_id !== possessionReceiptSigner.key_id) throw new Error("Cloud possession receipt signer is unavailable");
      humanAuthRuntime = humanAuthFactory({
        postgresRuntime,
        tokenRecords,
        origin: config.humanAuth.origin,
        rpId: config.humanAuth.rpId,
        cursorSecret,
        securitySecret: humanAuthSecret,
        identityProvider: config.humanAuth.identityProvider,
        signedConsoleIdentity: {
          issuer: config.humanAuth.identityAssertionIssuer,
          audience: config.humanAuth.identityAssertionAudience,
          keyId: config.humanAuth.identityAssertionKeyId,
          publicKey: consoleIdentityPublicKey
        },
        agentSessionSigner,
        qualificationManifestSigner
      });
    } else store = await createCloudStore({ dataDir: config.dataDir });
    const hostedRateLimiter = profile.isHosted ? createHostedRateLimiter(postgresRuntime.sharedControlRepository, { secret: humanAuthSecret }) : undefined;
    if (profile.isHosted) {
      hostedBootstrapRuntime = createHostedBootstrapRuntime({
        env,
        repository: postgresRuntime.hostedIdentityBootstrapRepository,
        registrationVerifier: createSimpleWebAuthnRegistrationVerifier(),
        rateLimitRepository: postgresRuntime.sharedControlRepository,
        rateLimitSecret: humanAuthSecret,
        humanAuthSecret
      });
    }
    let agentSessionDeviceApi;
    let agentLaunchAuthorityHandoffApi;
    let qualificationGrantBatchDeviceApi;
    if (profile.isHosted) {
      const deviceRequestVerifier = async (request, options) => {
        const devices = await store.listDevices({ organizationId: options.organizationId });
        const principal = verifyDeviceRequest(request, devices, { ...options, deferReplayConsumption: true });
        const nonce = request.headers?.["agentpass-nonce"] ?? request.headers?.["AgentPass-Nonce"];
        let consumed;
        try { consumed = await postgresRuntime.sharedControlRepository.consumeDeviceRequestNonce({ organizationId: options.organizationId, deviceId: principal.device_id, nonce }); }
        catch { const unavailable = new Error("device replay authority unavailable"); unavailable.code = "ERR_REPOSITORY_UNAVAILABLE"; throw unavailable; }
        if (consumed?.accepted !== true) { const replay = new Error("device request replay denied"); replay.code = "ERR_REPLAY_DETECTED"; throw replay; }
        return principal;
      };
      const agentSessionGrantVerifier = async (grant, context) => {
        await agentSessionSigner.verificationKeyMetadata(grant?.statement?.key_id, { at: context.now });
        return agentSessionSigner.verifyAgentSessionGrant(grant, { at: context.now });
      };
      agentLaunchAuthorityHandoffApi = createAgentLaunchAuthorityHandoffApi({
        deviceRequestVerifier,
        grantVerifier: agentSessionGrantVerifier,
        sessionBinder: postgresRuntime.agentSessionSigningCapabilitySessionBinder ?? (async () => {
          const unavailable = new Error("full Agent Session Lease binding is unavailable");
          unavailable.code = "ERR_SESSION_BINDING_UNAVAILABLE";
          throw unavailable;
        }),
        repository: postgresRuntime.agentLaunchAuthorityHandoffRepository,
        rateLimiter: hostedRateLimiter
      });
      if (agentSessionSigningCapabilitySigner !== undefined) {
        if (!postgresRuntime.agentSessionSigningCapabilitySessionBinder
          || typeof postgresRuntime.createAgentSessionSigningCapabilityReservationRepository !== "function") {
          throw new Error("Agent Session signing capability composition is incomplete");
        }
        const composed = createAgentSessionSigningCapabilityRuntimeComposition({
          deviceRequestVerifier,
          sessionBinder: postgresRuntime.agentSessionSigningCapabilitySessionBinder,
          reservationRepositoryFactory: postgresRuntime.createAgentSessionSigningCapabilityReservationRepository,
          signer: agentSessionSigningCapabilitySigner,
          grantVerifier: agentSessionGrantVerifier,
          repository: postgresRuntime.agentSessionAuthorityRepository,
          rateLimiter: hostedRateLimiter
        });
        agentSessionDeviceApi = composed.agentSessionDeviceApi;
        agentSessionSigningCapabilityApi = composed.agentSessionSigningCapabilityApi;
      } else {
        // Until the dedicated signer is injected by the deployment owner, the
        // route remains present but unavailable. It is never silently wired
        // to the generic capability signer or a local fallback.
        agentSessionDeviceApi = createAgentSessionDeviceApi({
          deviceRequestVerifier,
          grantVerifier: agentSessionGrantVerifier,
          repository: postgresRuntime.agentSessionAuthorityRepository,
          rateLimiter: hostedRateLimiter
        });
      }
      if (!postgresRuntime.qualificationGrantBatchRepository
        || typeof postgresRuntime.qualificationGrantBatchRepository.claimQualificationGrantBatch !== "function") {
        throw new Error("PostgreSQL qualification Grant batch authority is unavailable");
      }
      qualificationGrantBatchDeviceApi = createQualificationGrantBatchDeviceApi({
        deviceRequestVerifier,
        grantVerifier: async (grant, context) => {
          await agentSessionSigner.verificationKeyMetadata(grant?.statement?.key_id, { at: context.now });
          return agentSessionSigner.verifyAgentSessionGrant(grant, { at: context.now });
        },
        manifestVerifier: async (manifest, context) => qualificationManifestSigner.verifyQualificationGrantBatchManifest(manifest, { at: context.now }),
        repository: postgresRuntime.qualificationGrantBatchRepository,
        rateLimiter: hostedRateLimiter
      });
    }
    server = createCloudApi({
      store,
      tokenRecords,
      replayCache: profile.isHosted ? undefined : createPersistentReplayCache(path.join(config.dataDir, "device-replay-cache.json")),
      ...(profile.isHosted ? {
        deviceReplayConsumer: async ({ organizationId, deviceId, nonce }) => (await postgresRuntime.sharedControlRepository.consumeDeviceRequestNonce({ organizationId, deviceId, nonce })).accepted,
        rateLimiter: hostedRateLimiter,
        enrollmentCredentialSecret: Buffer.from(env.AGENTPASS_CAPABILITY_NONCE_SECRET, "base64url"),
        trackInFlight: postgresRuntime.trackInFlight,
        readiness: createHostedReadiness(postgresRuntime.readiness, [
          { name: "agent_session_signer", purpose: AGENT_SESSION_GRANT_TYPE, unavailableCode: "agent_session_signer_unavailable", signer: agentSessionSigner },
          { name: "qualification_manifest_signer", purpose: "agentpass.qualification-grant-batch-manifest", unavailableCode: "qualification_manifest_signer_unavailable", signer: qualificationManifestSigner },
          { name: "possession_receipt_signer", purpose: POSSESSION_RECEIPT_PURPOSE, unavailableCode: "possession_receipt_signer_unavailable", signer: possessionReceiptSigner },
          { name: "refresh_hint_signer", purpose: REFRESH_HINT_TYPE, unavailableCode: "refresh_hint_signer_unavailable", signer: refreshHintSigner },
          { name: "capability_signer", purpose: CAPABILITY_SIGNER_PURPOSE, unavailableCode: "capability_signer_unavailable", signer: capabilitySigner },
          { name: "control_bundle_signer", purpose: CONTROL_BUNDLE_MANAGED_SIGNER_PURPOSE, unavailableCode: "control_bundle_signer_unavailable", signer: controlBundleSigner },
          { name: "audit_anchor_signer", purpose: AUDIT_ANCHOR_PURPOSE, unavailableCode: "audit_anchor_signer_unavailable", signer: auditAnchorSigner },
          { name: "promotion_evidence_signer", purpose: PROMOTION_EVIDENCE_V3_PURPOSE, unavailableCode: "promotion_evidence_signer_unavailable", signer: promotionEvidenceSigner }
        ], platformSessionReadiness, platformPromotionReadiness),
        operationalMetrics: postgresRuntime.operationalReport,
        operationalProbeSecret: exactRuntimeSecret(env.AGENTPASS_OPERATIONAL_PROBE_SECRET, "AGENTPASS_OPERATIONAL_PROBE_SECRET")
      } : { rateLimiter: createRateLimiter({ persistencePath: path.join(config.dataDir, "principal-rate-limits.json") }) }),
      admissionRateLimiter: profile.isHosted ? undefined : createRateLimiter({ persistencePath: path.join(config.dataDir, "admission-rate-limits.json"), human: { capacity: 30, refillPerSecond: 1 }, device: { capacity: 60, refillPerSecond: 2 } }),
      bundleSigner: profile.isHosted
        ? { ...controlBundleSigner, issuer: config.issuer, keyId: config.keyId, ttlMs: config.ttlMs, offlineTtlMs: config.offlineTtlMs }
        : { privateKey, issuer: config.issuer, keyId: config.keyId, ttlMs: config.ttlMs, offlineTtlMs: config.offlineTtlMs },
      ...(profile.isHosted ? { capabilitySigner: { ...capabilitySigner, issuer: config.issuer, keyId: config.capabilityKeyId } } : {}),
      ...(profile.isHosted ? { refreshHintService: createRefreshHintService({ source: store, nonceDeriver: refreshNonceCodec, signer: refreshHintSigner, notifier: postgresRuntime.refreshHintNotifier, metrics: postgresRuntime.operationalMetrics }) } : {}),
      ...(humanAuthRuntime ? { humanAuthApi: humanAuthRuntime.api, humanSession: humanAuthRuntime.humanSession, recentAuthService: humanAuthRuntime.recentAuthService, humanAuthOrigin: config.humanAuth.origin } : {}),
      ...(auditExportIssuanceService ? { auditExportIssuanceService, auditExportVerifier } : {}),
      ...(platformSessionHttpApi ? { platformSessionHttpApi } : {}),
      ...(platformPromotionHttpApi ? { platformPromotionHttpApi } : {}),
      ...(hostedBootstrapRuntime ? { hostedBootstrapHttpApi: hostedBootstrapRuntime.api } : {}),
      ...(agentSessionDeviceApi ? { agentSessionDeviceApi } : {}),
      ...(agentLaunchAuthorityHandoffApi ? { agentLaunchAuthorityHandoffApi } : {}),
      ...(agentSessionSigningCapabilityApi ? { agentSessionSigningCapabilityApi } : {}),
      ...(qualificationGrantBatchDeviceApi ? { qualificationGrantBatchDeviceApi } : {}),
      ...(possessionReceiptSigner ? { possessionReceiptSigner } : {}),
      ...(postgresRuntime?.capabilityAuthorityRepository ? { capabilityAuthorityRepository: postgresRuntime.capabilityAuthorityRepository } : {}),
      ...(postgresRuntime?.capabilityAuthorityRepository ? { capabilityRevocationSource: postgresRuntime.capabilityAuthorityRepository } : {})
    });
  } catch (error) { await ownedKmsProviders?.close?.().catch(() => {}); await postgresRuntime?.close?.().catch(() => {}); await store?.close?.(); throw error; }
  let closed = false;
  let closePromise;
  return Object.freeze({
    config: Object.freeze({ ...config, profile: profile.profile }),
    server,
    store,
    postgresRuntime,
    humanAuthRuntime,
    hostedBootstrapRuntime,
    auditAnchorSigner,
    auditExportIssuanceService,
    auditExportVerifier,
    agentSessionSigningCapabilityApi,
    platformOperatorAuthorizer: effectivePlatformOperatorAuthorizer,
    platformPromotionHttpApi,
    platformPromotionReadiness,
    platformSessionHttpApi,
    platformSessionReadiness,
    async listen() {
      if (server.listening) return server.address();
      await new Promise((resolve, reject) => { server.once("error", reject); server.listen(config.port, config.host, () => { server.off("error", reject); resolve(); }); });
      logger.info?.(`AgentPass Cloud API listening on ${config.host}:${server.address().port}`);
      return server.address();
    },
    async close() {
      if (closed) return;
      if (closePromise) return closePromise;
      closePromise = (async () => {
        const shutdownStartedAt = Date.now();
        const shutdownTimeoutMs = 15_000;
        postgresRuntime?.beginDrain?.();
        const serverClose = server.listening
          ? new Promise((resolve, reject) => {
              server.close((error) => error ? reject(error) : resolve());
              server.closeIdleConnections?.();
            })
          : Promise.resolve();
        const databaseClose = postgresRuntime?.drain ? postgresRuntime.drain() : postgresRuntime?.close?.();
        const results = await runtimeTimeout(Promise.all([serverClose, databaseClose]), shutdownTimeoutMs);
        const drainResult = results?.[1];
        if (drainResult?.drained === false) throw new Error("Cloud runtime drain timed out");
        const remainingMs = Math.max(1, shutdownTimeoutMs - Math.max(0, Date.now() - shutdownStartedAt));
        await runtimeTimeout(Promise.resolve(ownedKmsProviders?.close?.()), remainingMs);
        await store.close?.();
        closed = true;
      })();
      try { return await closePromise; }
      catch (error) { closePromise = undefined; throw error; }
    }
  });
}

export function createHostedPlatformOperatorAuthorizer(postgresRuntime) {
  if (!postgresRuntime?.platformOperatorAssignmentRepository
    || typeof postgresRuntime.platformOperatorAssignmentRepository.findActivePlatformOperatorAssignment !== "function") {
    throw new Error("PostgreSQL platform operator authority is unavailable");
  }
  return createPlatformOperatorAuthorizer({
    repository: postgresRuntime.platformOperatorAssignmentRepository
  });
}

export function loadRuntimeConfig(env = {}) {
  const profile = parseCloudRuntimeProfile(env);
  const dataDir = profile.isEvaluation ? absolute(env.AGENTPASS_CLOUD_DATA_DIR, "AGENTPASS_CLOUD_DATA_DIR") : null;
  const bundlePrivateKeyPath = profile.isEvaluation ? absolute(env.AGENTPASS_CLOUD_BUNDLE_PRIVATE_KEY_PATH, "AGENTPASS_CLOUD_BUNDLE_PRIVATE_KEY_PATH") : null;
  const issuer = env.AGENTPASS_CLOUD_ISSUER ?? "agentpass-cloud";
  const keyId = profile.isHosted ? env.AGENTPASS_CLOUD_CONTROL_BUNDLE_KEY_ID : env.AGENTPASS_CLOUD_KEY_ID ?? "control-v2";
  if (!IDENTIFIER.test(issuer) || !IDENTIFIER.test(keyId)) throw new Error("Cloud signer identifiers are invalid");
  const host = env.AGENTPASS_CLOUD_HOST ?? "127.0.0.1";
  if (!new Set(["127.0.0.1", "::1", "localhost", "0.0.0.0", "::"]).has(host)) throw new Error("Cloud listen host is invalid");
  const port = integer(env.AGENTPASS_CLOUD_PORT ?? "8080", 0, 65_535, "Cloud port");
  const ttlMs = integer(env.AGENTPASS_CLOUD_BUNDLE_TTL_MS ?? "3600000", 1_000, 7 * 24 * 60 * 60 * 1000, "Bundle TTL");
  const offlineTtlMs = integer(env.AGENTPASS_CLOUD_OFFLINE_TTL_MS ?? "3600000", 0, 7 * 24 * 60 * 60 * 1000, "Offline TTL");
  const humanAuth = profile.isHosted ? humanAuthConfig(env) : null;
  const refreshPublicKey = profile.isHosted ? requireHostedPublicKey(env.AGENTPASS_CLOUD_REFRESH_PUBLIC_KEY, "Cloud refresh public key") : null;
  const refreshNonceKeyringPath = profile.isHosted ? absolute(env.AGENTPASS_CLOUD_REFRESH_NONCE_KEYRING_PATH, "AGENTPASS_CLOUD_REFRESH_NONCE_KEYRING_PATH") : null;
  const refreshKeyId = profile.isHosted ? env.AGENTPASS_CLOUD_REFRESH_KEY_ID : null;
  if (profile.isHosted && !IDENTIFIER.test(refreshKeyId ?? "")) throw new Error("Cloud refresh signer identifier is invalid");
  const controlBundlePublicKey = profile.isHosted ? requireHostedPublicKey(env.AGENTPASS_CLOUD_CONTROL_BUNDLE_PUBLIC_KEY, "Cloud ControlBundle public key") : null;
  const capabilityKeyId = profile.isHosted ? env.AGENTPASS_CLOUD_CAPABILITY_KEY_ID : null;
  if (profile.isHosted && !IDENTIFIER.test(capabilityKeyId ?? "")) throw new Error("Cloud capability signer identifier is invalid");
  const capabilityPublicKey = profile.isHosted ? requireHostedPublicKey(env.AGENTPASS_CLOUD_CAPABILITY_PUBLIC_KEY, "Cloud capability public key") : null;
  const auditAnchorKeyId = profile.isHosted ? env.AGENTPASS_CLOUD_AUDIT_ANCHOR_KEY_ID : null;
  if (profile.isHosted && !IDENTIFIER.test(auditAnchorKeyId ?? "")) throw new Error("Cloud audit anchor signer identifier is invalid");
  const auditAnchorPublicKey = profile.isHosted ? requireHostedPublicKey(env.AGENTPASS_CLOUD_AUDIT_ANCHOR_PUBLIC_KEY, "Cloud audit anchor public key") : null;
  const auditAnchorTimeoutMs = profile.isHosted ? integer(env.AGENTPASS_CLOUD_AUDIT_ANCHOR_TIMEOUT_MS, 1, 30_000, "Cloud audit anchor timeout") : null;
  const promotionEvidenceKeyId = profile.isHosted ? env.AGENTPASS_CLOUD_PROMOTION_EVIDENCE_KEY_ID : null;
  if (profile.isHosted && !IDENTIFIER.test(promotionEvidenceKeyId ?? "")) throw new Error("Cloud promotion evidence signer identifier is invalid");
  const promotionEvidencePublicKey = profile.isHosted ? requireHostedPublicKey(env.AGENTPASS_CLOUD_PROMOTION_EVIDENCE_PUBLIC_KEY, "Cloud promotion evidence public key") : null;
  const promotionEvidenceTimeoutMs = profile.isHosted ? integer(env.AGENTPASS_CLOUD_PROMOTION_EVIDENCE_TIMEOUT_MS, 1, 30_000, "Cloud promotion evidence timeout") : null;
  const agentSessionProcessPoliciesPath = profile.isHosted ? absolute(env.AGENTPASS_CLOUD_AGENT_SESSION_PROCESS_POLICIES_PATH, "AGENTPASS_CLOUD_AGENT_SESSION_PROCESS_POLICIES_PATH") : null;
  const ownerRecoveryNotification = profile.isHosted ? ownerRecoveryNotificationConfig(env) : null;
  // Hosted Human Auth never loads the legacy operator bearer database. The
  // token-record file exists only for the explicit evaluation profile.
  const tokenRecordsPath = profile.isHosted ? null : absolute(env.AGENTPASS_CLOUD_TOKEN_RECORDS_PATH, "AGENTPASS_CLOUD_TOKEN_RECORDS_PATH");
  return Object.freeze({ dataDir, tokenRecordsPath, bundlePrivateKeyPath, issuer, keyId, controlBundlePublicKey, capabilityKeyId, capabilityPublicKey, auditAnchorKeyId, auditAnchorPublicKey, auditAnchorTimeoutMs, promotionEvidenceKeyId, promotionEvidencePublicKey, promotionEvidenceTimeoutMs, host, port, ttlMs, offlineTtlMs, humanAuth, refreshPublicKey, refreshNonceKeyringPath, refreshKeyId, agentSessionProcessPoliciesPath, ownerRecoveryNotification });
}

function ownerRecoveryNotificationConfig(env) {
  const webhookUrl = env.AGENTPASS_OWNER_RECOVERY_NOTIFICATION_WEBHOOK_URL;
  const confirmationUrl = env.AGENTPASS_OWNER_RECOVERY_NOTIFICATION_CONFIRMATION_URL;
  const authorizationSecretPath = env.AGENTPASS_OWNER_RECOVERY_NOTIFICATION_AUTHORIZATION_PATH;
  const bindingId = env.AGENTPASS_OWNER_RECOVERY_NOTIFICATION_BINDING_ID;
  const bindingKeyVersion = env.AGENTPASS_OWNER_RECOVERY_NOTIFICATION_BINDING_KEY_VERSION;
  const bindingDigest = env.AGENTPASS_OWNER_RECOVERY_NOTIFICATION_BINDING_DIGEST;
  if ([webhookUrl, confirmationUrl, authorizationSecretPath, bindingId, bindingKeyVersion, bindingDigest].every((value) => value === undefined)) return null;
  if ([webhookUrl, confirmationUrl, authorizationSecretPath, bindingId, bindingKeyVersion, bindingDigest].some((value) => typeof value !== "string")) throw new Error("Owner recovery notification configuration is incomplete");
  let parsed;
  let parsedConfirmation;
  try { parsed = new URL(webhookUrl); } catch { throw new Error("Owner recovery notification webhook URL is invalid"); }
  if (parsed.protocol !== "https:" || parsed.username || parsed.password || parsed.hash || !parsed.hostname || webhookUrl.length > 2_048) throw new Error("Owner recovery notification webhook URL is invalid");
  try { parsedConfirmation = new URL(confirmationUrl); } catch { throw new Error("Owner recovery notification confirmation URL is invalid"); }
  if (parsedConfirmation.protocol !== "https:" || parsedConfirmation.username || parsedConfirmation.password || parsedConfirmation.hash || !parsedConfirmation.hostname || confirmationUrl.length > 2_048) throw new Error("Owner recovery notification confirmation URL is invalid");
  if (!/^[a-z0-9][a-z0-9._:-]{0,127}$/u.test(bindingId)
    || !/^[1-9][0-9]*$/u.test(bindingKeyVersion)
    || !Number.isSafeInteger(Number(bindingKeyVersion)) || Number(bindingKeyVersion) > 2_147_483_647
    || !/^[0-9a-f]{64}$/u.test(bindingDigest)) throw new Error("Owner recovery notification binding is invalid");
  return Object.freeze({
    webhookUrl: parsed.href,
    confirmationUrl: parsedConfirmation.href,
    authorizationSecretPath: absolute(authorizationSecretPath, "AGENTPASS_OWNER_RECOVERY_NOTIFICATION_AUTHORIZATION_PATH"),
    bindingId,
    bindingKeyVersion: Number(bindingKeyVersion),
    bindingDigest
  });
}

function createConfiguredOwnerRecoveryPublisher(config) {
  if (!config) throw new Error("Hosted owner recovery notification publisher is required");
  const authorizationSecret = readProtectedFile(config.authorizationSecretPath, "owner recovery notification authorization", 4_096).toString("utf8");
  try {
    return createOwnerRecoveryNotificationPublisher({
      webhookUrl: config.webhookUrl,
      confirmationUrl: config.confirmationUrl,
      authorizationSecret,
      bindingId: config.bindingId,
      bindingKeyVersion: config.bindingKeyVersion,
      bindingDigest: config.bindingDigest
    });
  }
  catch { throw new Error("Hosted owner recovery notification publisher is invalid"); }
}

function loadRefreshNonceCodec(file) {
  const document = readProtectedJson(file, "refresh nonce keyring", 64 * 1024);
  if (!document || typeof document !== "object" || Array.isArray(document)
    || Object.keys(document).sort().join(",") !== "active_key_id,keys,version"
    || document.version !== 1 || !document.keys || typeof document.keys !== "object" || Array.isArray(document.keys)
    || Object.keys(document.keys).length < 1 || Object.keys(document.keys).length > 8) {
    throw new Error("Cloud refresh nonce keyring is invalid");
  }
  const keys = {};
  for (const [keyId, encoded] of Object.entries(document.keys)) {
    if (typeof encoded !== "string" || !/^[A-Za-z0-9_-]{43}$/u.test(encoded)) throw new Error("Cloud refresh nonce keyring is invalid");
    const bytes = Buffer.from(encoded, "base64url");
    if (bytes.length !== 32 || bytes.toString("base64url") !== encoded) throw new Error("Cloud refresh nonce keyring is invalid");
    keys[keyId] = bytes;
  }
  try { return createRefreshNonceCodec({ keys, activeKeyId: document.active_key_id }); }
  catch { throw new Error("Cloud refresh nonce keyring is invalid"); }
}

function humanAuthConfig(env) {
  const database = env.AGENTPASS_DATABASE_URL;
  const origin = env.AGENTPASS_CONSOLE_ORIGIN;
  const rpId = env.AGENTPASS_WEBAUTHN_RP_ID;
  const identityProvider = env.AGENTPASS_IDENTITY_PROVIDER ?? "chatgpt";
  const identityAssertionIssuer = env.AGENTPASS_IDENTITY_ASSERTION_ISSUER;
  const identityAssertionAudience = env.AGENTPASS_IDENTITY_ASSERTION_AUDIENCE;
  const identityAssertionKeyId = env.AGENTPASS_IDENTITY_ASSERTION_KID;
  const identityAssertionPublicKeyPath = env.AGENTPASS_IDENTITY_ASSERTION_PUBLIC_KEY_PATH;
  if (database === undefined && origin === undefined && rpId === undefined) return null;
  if (typeof database !== "string" || database.length < 1 || typeof origin !== "string" || typeof rpId !== "string") throw new Error("Human auth configuration is incomplete");
  let parsed;
  try { parsed = new URL(origin); } catch { throw new Error("AGENTPASS_CONSOLE_ORIGIN is invalid"); }
  if (parsed.protocol !== "https:" || parsed.origin !== origin || parsed.pathname !== "/" || parsed.username || parsed.password || parsed.search || parsed.hash) throw new Error("AGENTPASS_CONSOLE_ORIGIN is invalid");
  if (!/^[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$/.test(rpId) || (parsed.hostname !== rpId && !parsed.hostname.endsWith(`.${rpId}`))) throw new Error("AGENTPASS_WEBAUTHN_RP_ID is invalid");
  if (!/^[a-z][a-z0-9._-]{0,63}$/.test(identityProvider)) throw new Error("AGENTPASS_IDENTITY_PROVIDER is invalid");
  if (typeof identityAssertionIssuer !== "string" || identityAssertionIssuer.length < 1 || identityAssertionIssuer.length > 256
    || typeof identityAssertionAudience !== "string" || identityAssertionAudience.length < 1 || identityAssertionAudience.length > 256
    || !IDENTIFIER.test(identityAssertionKeyId ?? "")) throw new Error("Human identity assertion configuration is incomplete");
  const publicKeyPath = absolute(identityAssertionPublicKeyPath, "AGENTPASS_IDENTITY_ASSERTION_PUBLIC_KEY_PATH");
  requireHumanCursorSecret(env.AGENTPASS_HUMAN_CURSOR_SECRET);
  exactRuntimeSecret(env.AGENTPASS_HUMAN_AUTH_SECRET, "AGENTPASS_HUMAN_AUTH_SECRET");
  return Object.freeze({ origin, rpId, identityProvider, identityAssertionIssuer, identityAssertionAudience, identityAssertionKeyId, identityAssertionPublicKeyPath: publicKeyPath });
}

function requireHumanCursorSecret(value) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]{43}$/u.test(value)) throw new Error("AGENTPASS_HUMAN_CURSOR_SECRET must be an exact 32-byte base64url secret");
  let bytes;
  try { bytes = Buffer.from(value, "base64url"); } catch { throw new Error("AGENTPASS_HUMAN_CURSOR_SECRET must be an exact 32-byte base64url secret"); }
  if (bytes.length !== 32 || bytes.toString("base64url") !== value) throw new Error("AGENTPASS_HUMAN_CURSOR_SECRET must be an exact 32-byte base64url secret");
  return value;
}

function exactRuntimeSecret(value, name) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]{43}$/u.test(value)) throw new Error(`${name} must be an exact 32-byte base64url secret`);
  const bytes = Buffer.from(value, "base64url");
  if (bytes.length !== 32 || bytes.toString("base64url") !== value) throw new Error(`${name} must be an exact 32-byte base64url secret`);
  return bytes;
}

function requireHostedPublicKey(value, label) {
  let key;
  try {
    if (typeof value !== "string" || /PRIVATE\s+KEY/iu.test(value)) throw new Error("invalid key");
    key = crypto.createPublicKey(value);
  } catch { throw new Error(`${label} is invalid`); }
  if (key.type !== "public" || key.asymmetricKeyType !== "ed25519") throw new Error(`${label} must be Ed25519`);
  return key.export({ type: "spki", format: "pem" }).toString();
}

function publicKeyFingerprint(value) {
  const key = crypto.createPublicKey(value);
  return crypto.createHash("sha256").update(key.export({ type: "spki", format: "der" })).digest("hex");
}

function readProtectedJson(file, label, maxBytes) {
  const bytes = readProtectedFile(file, label, maxBytes);
  try { return JSON.parse(bytes); } catch { throw new Error(`Cloud ${label} JSON is invalid`); }
}

function readProtectedFile(file, label, maxBytes) {
  const descriptor = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  try {
    const stat = fs.fstatSync(descriptor);
    const uid = typeof process.getuid === "function" ? process.getuid() : undefined;
    if (!stat.isFile() || stat.nlink !== 1 || stat.size < 1 || stat.size > maxBytes || (stat.mode & 0o077) !== 0 || (uid !== undefined && stat.uid !== uid)) throw new Error(`Cloud ${label} permissions are unsafe`);
    return fs.readFileSync(descriptor);
  } finally { fs.closeSync(descriptor); }
}

function absolute(value, label) {
  if (typeof value !== "string" || !path.isAbsolute(value) || path.basename(value) === "." || path.basename(value) === "..") throw new Error(`${label} must be an absolute path`);
  return path.resolve(value);
}

function integer(value, min, max, label) {
  if (typeof value !== "string" || !/^\d+$/.test(value)) throw new Error(`${label} is invalid`);
  const result = Number(value);
  if (!Number.isSafeInteger(result) || result < min || result > max) throw new Error(`${label} is invalid`);
  return result;
}

function runtimeTimeout(promise, timeoutMs) {
  let timer;
  return Promise.race([
    promise,
    new Promise((_, reject) => { timer = setTimeout(() => reject(new Error("Cloud runtime shutdown timed out")), timeoutMs); })
  ]).finally(() => clearTimeout(timer));
}

const PLATFORM_PROMOTION_VERIFIER_CONTEXT_FIELDS = Object.freeze([
  "deployment_id",
  "environment",
  "candidate_id",
  "product_pkg_sha256",
  "image_digest",
  "sbom_sha256",
  "platform_approval_id",
  "platform_approval_digest",
  "source_commit",
  "source_tree",
  "release_manifest_sha256",
  "release_manifest_schema_version",
  "qualification_report_digests",
  "purpose",
  "protocol_version",
  "signing_version",
  "key_id",
  "key_version",
  "lifecycle_version",
  "signer_key_fingerprint"
]);

function createDynamicPromotionEvidenceVerifier({ resolver, maxTtlMs, now = () => Date.now() } = {}) {
  if (typeof resolver !== "function" || !Number.isSafeInteger(maxTtlMs) || maxTtlMs < 1 || typeof now !== "function") {
    throw new Error("Cloud promotion evidence verifier is unavailable");
  }
  return async function verifyPlatformPromotionEvidence(envelope, context = {}) {
    try {
      if (envelope === null || typeof envelope !== "object" || Array.isArray(envelope)
        || context === null || typeof context !== "object" || Array.isArray(context)) return false;
      const statement = envelope.statement;
      if (statement === null || typeof statement !== "object" || Array.isArray(statement)) return false;
      const verifierContext = {};
      for (const field of PLATFORM_PROMOTION_VERIFIER_CONTEXT_FIELDS) {
        if (!Object.hasOwn(context, field) || context[field] === undefined) return false;
        verifierContext[field] = context[field];
      }
      const verifier = createPromotionEvidenceV3Verifier({
        publicKeyResolver: resolver,
        maxTtlMs,
        now: now(),
        ...verifierContext
      });
      await verifier.verify(envelope);
      return true;
    } catch {
      return false;
    }
  };
}

function trackAuthorizedPlatformPromotionService(service, trackInFlight) {
  if (!service || typeof service.issuePlatformPromotion !== "function") throw new Error("Authorized Platform promotion service is unavailable");
  if (typeof trackInFlight !== "function") return service;
  return Object.freeze({
    issuePlatformPromotion: (input) => trackInFlight(() => service.issuePlatformPromotion(input))
  });
}

export function createHostedRateLimiter(repository, { secret } = {}) {
  if (!repository || typeof repository.acquireRateLimit !== "function" || typeof repository.acquireAnonymousRateLimit !== "function") throw new Error("PostgreSQL shared rate limiter is unavailable");
  if (!Buffer.isBuffer(secret) || secret.length !== 32) throw new Error("PostgreSQL shared rate limiter is unavailable");
  const policies = Object.freeze({ human: Object.freeze({ capacity: 120, refillPerSecond: 2 }), device: Object.freeze({ capacity: 240, refillPerSecond: 4 }) });
  const anonymousBuckets = Object.freeze({
    human: Object.freeze({ operation: "cloud.transport.human", principalId: deriveHostedAnonymousBucketId(secret, "human") }),
    device: Object.freeze({ operation: "cloud.transport.device", principalId: deriveHostedAnonymousBucketId(secret, "device") })
  });
  return Object.freeze({
    policies,
    async acquire({ tenantId, principalType, principalId } = {}) {
      const policy = policies[principalType];
      if (!policy) throw new Error("rate limiter principal type is invalid");
      // Pre-authentication traffic has no trustworthy organization UUID yet;
      // it remains bounded by one shared, purpose-specific PostgreSQL bucket.
      // Never persist attacker-controlled transport values as anonymous row
      // identifiers: the HMAC-derived UUIDs are stable across instances and
      // restarts, while the domain separator keeps this namespace isolated.
      if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu.test(tenantId ?? "")
        || !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu.test(principalId ?? "")) {
        const bucket = anonymousBuckets[principalType];
        return repository.acquireAnonymousRateLimit({ operation: bucket.operation, principalId: bucket.principalId, capacity: policy.capacity, refillPerSecond: policy.refillPerSecond, cost: 1 });
      }
      return repository.acquireRateLimit({ organizationId: tenantId, principalType, principalId, capacity: policy.capacity, refillPerSecond: policy.refillPerSecond, cost: 1 });
    }
  });
}

function deriveHostedAnonymousBucketId(secret, purpose) {
  const digest = crypto.createHmac("sha256", secret)
    .update("AgentPass-Hosted-Transport-Rate-Limit-v1\0", "utf8")
    .update(purpose, "utf8")
    .digest();
  const bytes = Buffer.from(digest.subarray(0, 16));
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  return `${bytes.subarray(0, 4).toString("hex")}-${bytes.subarray(4, 6).toString("hex")}-${bytes.subarray(6, 8).toString("hex")}-${bytes.subarray(8, 10).toString("hex")}-${bytes.subarray(10, 16).toString("hex")}`;
}

export function createHostedPlatformSessionComposition({ bootstrapRepository, webauthnRepository, origin, rpId } = {}) {
  if (!bootstrapRepository || typeof bootstrapRepository.resolvePlatformSessionBootstrap !== "function"
    || !webauthnRepository || typeof webauthnRepository.findPlatformSessionChallenge !== "function"
    || typeof origin !== "string" || typeof rpId !== "string") {
    throw new Error("PostgreSQL platform session bootstrap authority is unavailable");
  }
  const bootstrapAuthenticator = async ({ phase, intent, session_material_hash } = {}) => {
    if (phase !== "challenge" || !intent || typeof session_material_hash !== "string") return null;
    return bootstrapRepository.resolvePlatformSessionBootstrap({
      session_material_hash,
      organization_id: intent.organization_id,
      operation: intent.operation,
      capability: intent.operation
    });
  };
  const authorityResolver = async ({ phase, challenge_id, bootstrap, intent } = {}) => {
    const source = phase === "challenge"
      ? bootstrap
      : await webauthnRepository.findPlatformSessionChallenge({ challenge_id });
    if (!source) return null;
    return platformSessionAuthorityContext(source, { origin, rpId }, intent);
  };
  return Object.freeze({ bootstrapAuthenticator, authorityResolver });
}

export function normalizePlatformSessionRuntimeConfig({ platformSession, bootstrapAuthenticator, authorityResolver, webauthnVerify, origin, rpId } = {}) {
  if (platformSession !== undefined && platformSession !== false
    && (!platformSession || typeof platformSession !== "object" || Array.isArray(platformSession))) {
    throw new Error("platform session runtime configuration is invalid");
  }
  const override = platformSession && typeof platformSession === "object" ? platformSession : {};
  const enabled = override.enabled !== false && platformSession !== false;
  if (!enabled) return Object.freeze({ enabled: false });
  const effectiveOrigin = override.origin ?? origin;
  const effectiveRpId = override.rpId ?? override.rp_id ?? rpId;
  if (typeof effectiveOrigin !== "string" || effectiveOrigin.length < 1
    || typeof effectiveRpId !== "string" || !/^[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$/u.test(effectiveRpId)) {
    return Object.freeze({ enabled: false, code: "platform_session_configuration_unavailable" });
  }
  return Object.freeze({
    enabled: true,
    origin: effectiveOrigin,
    rpId: effectiveRpId,
    bootstrapAuthenticator: override.bootstrapAuthenticator ?? bootstrapAuthenticator,
    authorityResolver: override.authorityResolver ?? authorityResolver,
    webauthnVerify: override.webauthnVerify ?? webauthnVerify
  });
}

function createPlatformSessionCompositionReadiness(config) {
  return async function platformSessionReadiness() {
    const ok = Boolean(config?.enabled && typeof config.bootstrapAuthenticator === "function"
      && typeof config.authorityResolver === "function" && typeof config.origin === "string" && typeof config.rpId === "string");
    return Object.freeze({
      enabled: config?.enabled === true,
      ok,
      code: ok ? "ready" : config?.code ?? "platform_session_composition_unavailable"
    });
  };
}

function platformSessionAuthorityContext(source, config, intent = undefined) {
  const requestDigest = intent?.request_digest_sha256
    ?? (Buffer.isBuffer(source?.request_digest_sha256) ? source.request_digest_sha256.toString("hex") : source?.request_digest_sha256);
  const allowed = source?.allowed_webauthn_credential_ids ?? source?.allowed_credential_ids;
  if (!source || typeof source !== "object" || !Array.isArray(allowed) || allowed.length < 1) return null;
  const allowedCredentialIds = allowed.map((value) => Buffer.isBuffer(value) ? value.toString("base64url") : value);
  return Object.freeze({
    principal_id: source.principal_id,
    member_id: source.member_id,
    organization_id: source.organization_id,
    assignment_id: source.assignment_id,
    authority_generation: source.authority_generation ?? source.principal_authority_generation,
    operation: source.operation,
    capability: source.capability,
    rp_id: config.rpId,
    origin: config.origin,
    request_digest_sha256: requestDigest,
    allowed_credential_ids: Object.freeze(allowedCredentialIds),
    user_verification: "required"
  });
}

export function createPlatformPromotionCompositionReadiness({ httpApi, repository, signer, lifecycleRepository, keyId, keyVersion, lifecycleVersion } = {}) {
  if (!httpApi || typeof httpApi.handle !== "function" || typeof httpApi.paths?.issue !== "string"
    || !repository || typeof repository.forAuthorization !== "function"
    || !isPromotionEvidenceV3Signer(signer, { keyId, keyVersion, lifecycleVersion })
    || !lifecycleRepository || typeof lifecycleRepository.snapshot !== "function"
    || typeof keyId !== "string" || !Number.isSafeInteger(keyVersion) || keyVersion < 1
    || !Number.isSafeInteger(lifecycleVersion) || lifecycleVersion < 1) {
    throw new Error("Hosted Platform promotion readiness dependencies are unavailable");
  }
  return async function platformPromotionCompositionReadiness() {
    try {
      const [metadata, lifecycle] = await Promise.all([
        signer.publicKeyMetadata(),
        lifecycleRepository.snapshot()
      ]);
      const active = Array.isArray(lifecycle?.keys)
        ? lifecycle.keys.filter((key) => key?.state === "active")
        : [];
      if (!isExactPromotionEvidenceV3Metadata(metadata, { keyId, keyVersion, lifecycleVersion, signer })
        || lifecycle?.version !== lifecycleVersion
        || active.length !== 1 || active[0].key_id !== keyId || active[0].key_version !== keyVersion) {
        throw new Error("Platform promotion lifecycle binding is stale");
      }
      return Object.freeze({ enabled: true, ok: true, code: "ready" });
    } catch {
      return Object.freeze({ enabled: true, ok: false, code: "platform_promotion_unavailable" });
    }
  };
}

function isExactPromotionEvidenceV3Metadata(value, { keyId, keyVersion, lifecycleVersion, signer }) {
  const expectedKeys = [
    "version", "type", "purpose", "domain", "protocol_version", "signing_version",
    "algorithm", "key_id", "key_version", "lifecycle_version", "public_key", "public_key_fingerprint"
  ];
  const keys = value && typeof value === "object" && !Array.isArray(value) ? Reflect.ownKeys(value) : [];
  if (!value || typeof value !== "object" || Array.isArray(value)
    || keys.length !== expectedKeys.length
    || keys.some((key) => {
      if (typeof key !== "string" || !expectedKeys.includes(key)) return true;
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      return !descriptor || descriptor.enumerable !== true || !("value" in descriptor);
    })
    || value.version !== PROMOTION_EVIDENCE_V3_VERSION
    || value.type !== PROMOTION_EVIDENCE_V3_TYPE
    || value.purpose !== PROMOTION_EVIDENCE_V3_PURPOSE
    || value.domain !== PROMOTION_EVIDENCE_V3_SIGNATURE_DOMAIN
    || value.protocol_version !== PROMOTION_EVIDENCE_V3_PROTOCOL_VERSION
    || value.signing_version !== PROMOTION_EVIDENCE_V3_SIGNING_VERSION
    || value.algorithm !== PROMOTION_EVIDENCE_V3_ALGORITHM
    || value.key_id !== keyId || value.key_version !== keyVersion
    || value.lifecycle_version !== lifecycleVersion
    || typeof value.public_key !== "string"
    || typeof value.public_key_fingerprint !== "string"
    || !/^SHA256:[A-Za-z0-9_-]{43}$/u.test(value.public_key_fingerprint)) return false;
  let key;
  try {
    key = crypto.createPublicKey(value.public_key);
    if (key.type !== "public" || key.asymmetricKeyType !== "ed25519"
      || key.export({ type: "spki", format: "pem" }).toString() !== value.public_key) return false;
  } catch {
    return false;
  }
  return signer.public_key_fingerprint === promotionEvidenceV3PublicKeyFingerprint(key)
    && promotionEvidenceV3PublicKeyFingerprint(key) === value.public_key_fingerprint;
}

function createHostedReadiness(databaseReadiness, signers, platformSessionReadiness = undefined, platformPromotionReadiness = undefined) {
  if (typeof databaseReadiness !== "function" || !Array.isArray(signers) || signers.length !== 8
    || signers.some(({ name, purpose, unavailableCode, signer }) => typeof name !== "string" || typeof purpose !== "string" || typeof unavailableCode !== "string"
      || typeof signer?.publicKeyMetadata !== "function")) throw new Error("Hosted readiness dependencies are unavailable");
  return async function hostedReadiness() {
    const databaseReport = await databaseReadiness();
    const checks = {};
    let signerFailure;
    for (const dependency of signers) {
      let report;
      try {
        if (typeof dependency.signer.health === "function" && typeof dependency.signer.verificationKeyMetadata === "function") {
          const [value, keyRing] = await Promise.all([dependency.signer.health(), dependency.signer.verificationKeyMetadata()]);
          if (!value || value.ready !== true || value.purpose !== dependency.purpose || value.algorithm !== "ed25519"
            || typeof value.key_id !== "string" || !/^[0-9a-f]{64}$/u.test(value.public_key_fingerprint ?? "")) throw new Error("invalid signer health");
          const activeKeys = Array.isArray(keyRing?.keys) ? keyRing.keys.filter((key) => key?.status === "active") : [];
          if (!keyRing || keyRing.version !== 1 || keyRing.purpose !== value.purpose || keyRing.active_key_id !== value.key_id
            || !Array.isArray(keyRing.keys) || keyRing.keys.length < 1 || keyRing.keys.length > 4
            || activeKeys.length !== 1
            || !keyRing.keys.some((key) => key?.status === "active" && key.key_id === value.key_id)
            || keyRing.keys.some((key) => !key || key.algorithm !== "ed25519" || typeof key.key_id !== "string"
              || !/^[0-9a-f]{64}$/u.test(key.public_key_fingerprint ?? "") || !["active", "retiring"].includes(key.status))) throw new Error("invalid verification key metadata");
          report = Object.freeze({ ok: true, purpose: value.purpose, algorithm: value.algorithm, key_id: value.key_id, public_key_fingerprint: value.public_key_fingerprint });
        } else {
          const metadata = await dependency.signer.publicKeyMetadata();
          if (!metadata || typeof metadata !== "object" || Array.isArray(metadata)
            || metadata.purpose !== dependency.purpose || metadata.algorithm !== "ed25519"
            || metadata.key_id !== dependency.signer.key_id || typeof metadata.public_key !== "string"
            || /PRIVATE\s+KEY/iu.test(metadata.public_key)) throw new Error("invalid signer metadata");
          const publicKey = crypto.createPublicKey(metadata.public_key);
          if (publicKey.type !== "public" || publicKey.asymmetricKeyType !== "ed25519"
            || publicKey.export({ type: "spki", format: "pem" }).toString() !== metadata.public_key) throw new Error("invalid signer key");
          const der = publicKey.export({ type: "spki", format: "der" });
          const publicKeyFingerprintHex = crypto.createHash("sha256").update(der).digest("hex");
          const publicKeyFingerprintSha256 = `SHA256:${crypto.createHash("sha256").update(der).digest("base64url")}`;
          const configuredFingerprint = dependency.signer.public_key_fingerprint;
          if (configuredFingerprint !== undefined
            && configuredFingerprint !== publicKeyFingerprintHex
            && configuredFingerprint !== publicKeyFingerprintSha256) throw new Error("signer key fingerprint mismatch");
          report = Object.freeze({
            ok: true,
            purpose: metadata.purpose,
            algorithm: metadata.algorithm,
            key_id: metadata.key_id,
            public_key_fingerprint: configuredFingerprint ?? publicKeyFingerprintHex
          });
        }
      } catch {
        signerFailure ??= dependency.unavailableCode;
        report = Object.freeze({ ok: false, purpose: dependency.purpose, algorithm: "ed25519", key_id: null, public_key_fingerprint: null });
      }
      checks[dependency.name] = report;
    }
    if (!databaseReport || typeof databaseReport !== "object" || Array.isArray(databaseReport)) throw new Error("invalid database readiness");
    let platformReport;
    if (platformSessionReadiness !== undefined) {
      if (typeof platformSessionReadiness !== "function") throw new Error("invalid platform session readiness");
      try {
        const value = await platformSessionReadiness();
        if (!value || typeof value !== "object" || typeof value.ok !== "boolean" || typeof value.code !== "string") throw new Error("invalid platform session readiness report");
        platformReport = Object.freeze({ enabled: value.enabled === true, ok: value.ok, code: value.code });
      } catch {
        platformReport = Object.freeze({ enabled: true, ok: false, code: "platform_session_unavailable" });
      }
    }
    if (platformReport) checks.platform_session = platformReport;
    const platformFailure = platformReport && platformReport.ok !== true ? platformReport.code : undefined;
    let promotionReport;
    if (platformPromotionReadiness !== undefined) {
      if (typeof platformPromotionReadiness !== "function") throw new Error("invalid platform promotion readiness");
      try {
        const value = await platformPromotionReadiness();
        if (!value || typeof value !== "object" || typeof value.ok !== "boolean" || typeof value.code !== "string") throw new Error("invalid platform promotion readiness report");
        promotionReport = Object.freeze({ enabled: value.enabled === true, ok: value.ok, code: value.code });
      } catch {
        promotionReport = Object.freeze({ enabled: true, ok: false, code: "platform_promotion_unavailable" });
      }
    }
    if (promotionReport) checks.platform_promotion = promotionReport;
    const promotionFailure = promotionReport && promotionReport.ok !== true ? promotionReport.code : undefined;
    return Object.freeze({
      ...databaseReport,
      ready: databaseReport.ready === true && signerFailure === undefined && platformFailure === undefined && promotionFailure === undefined,
      status: databaseReport.ready !== true ? databaseReport.status : signerFailure === undefined && platformFailure === undefined && promotionFailure === undefined ? databaseReport.status : "not_ready",
      code: databaseReport.ready !== true ? databaseReport.code : signerFailure ?? platformFailure ?? promotionFailure ?? databaseReport.code,
      checks: Object.freeze({ ...(databaseReport.checks ?? {}), ...checks })
    });
  };
}
