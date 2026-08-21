import crypto from "node:crypto";
import http from "node:http";
import { authenticateApiToken, createReplayCache, requireOrganizationRole, verifyDeviceRequest } from "./auth.mjs";
import { MAX_REVOCATIONS, controlBundleStatementHash, issueControlBundle, parseControlBundleJson, verifyControlBundle } from "../../../lib/control-bundle-v2.mjs";
import { canonicalJson, intersectScopes, verifyCapability } from "../../../packages/capability/src/index.mjs";
import {
  bundleAcknowledgementSigningData,
  normalizeRefreshHint,
  parseBundleAcknowledgementJson
} from "../../../packages/protocol/src/index.mjs";
import { RateLimiterCapacityError, createRateLimiter } from "./rate-limit.mjs";
import { OPERATIONAL_GAUGE_KEYS, OPERATIONAL_METRIC_KEYS } from "./postgres/operational-health.mjs";
import { normalizeDeviceReadModels } from "./device-read-model.mjs";
import { createPlatformPromotionHttpApi, isPlatformPromotionPath } from "./platform-promotion-http-api.mjs";
import { canonicalAuditExportEntry, foldAuditExportRoot } from "./postgres/audit-export-snapshot-reader.mjs";
import {
  normalizePossessionReceiptStatement,
  POSSESSION_RECEIPT_PURPOSE,
  POSSESSION_RECEIPT_SIGNATURE_ALGORITHMS,
  POSSESSION_RECEIPT_VERSION
} from "./possession-receipt-signer.mjs";

const MAX_BODY_BYTES = 1024 * 1024;
const HUMAN_AUTH_MAX_BODY_BYTES = 64 * 1024;
const HUMAN_AUTH_SESSION_PATH = "/api/auth/session";
const HUMAN_AUTH_SESSION_SWITCH_PATH = "/api/auth/session/organization-switch";
const HUMAN_AUTH_OPTIONS_PATH = "/api/auth/webauthn/options";
const HUMAN_AUTH_VERIFY_PATH = "/api/auth/webauthn/verify";
const HUMAN_AUTH_REGISTRATION_OPTIONS_PATH = "/api/auth/webauthn/registration/options";
const HUMAN_AUTH_REGISTRATION_VERIFY_PATH = "/api/auth/webauthn/registration/verify";
const HUMAN_AUTH_ORGANIZATIONS_PATH = "/api/auth/organizations";
const HUMAN_AUTH_ACCEPT_INVITATION_PATH = "/api/auth/invitations/accept";
const HUMAN_AUTH_UUID = "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-8][0-9a-fA-F]{3}-[89a-fA-F][0-9a-fA-F]{3}-[0-9a-fA-F]{12}";
const HUMAN_AGENT_SESSION_GRANT_PATH = new RegExp(`^/api/v1/organizations/${HUMAN_AUTH_UUID}/agents/${HUMAN_AUTH_UUID}/session-grants$`);
const HUMAN_QUALIFICATION_GRANT_BATCH_PATH = new RegExp(`^/api/v1/organizations/${HUMAN_AUTH_UUID}/agents/${HUMAN_AUTH_UUID}/qualification-grant-batches$`);
const HUMAN_AUDIT_EXPORT_CREATE_PATH = new RegExp(`^/v1/organizations/(?<organizationId>${HUMAN_AUTH_UUID})/audit/exports$`);
const HUMAN_AUDIT_EXPORT_GET_PATH = new RegExp(`^/v1/organizations/(?<organizationId>${HUMAN_AUTH_UUID})/audit/exports/(?<exportId>${HUMAN_AUTH_UUID})$`);
const HUMAN_AUDIT_EXPORT_DOWNLOAD_PATH = new RegExp(`^/v1/organizations/(?<organizationId>${HUMAN_AUTH_UUID})/audit/exports/(?<exportId>${HUMAN_AUTH_UUID})/download$`);
const HUMAN_AUDIT_EXPORT_VERIFY_PATH = new RegExp(`^/v1/organizations/(?<organizationId>${HUMAN_AUTH_UUID})/audit/exports/verify$`);
const UUID = "([0-9a-fA-F-]{36})";
const UUID_VALUE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
const AGENT_SESSION_DEVICE_CONSUME_PATH = /^\/v1\/organizations\/(?<organizationId>[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})\/devices\/(?<deviceId>[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})\/agent-session-grants\/(?<grantId>[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})\/consume$/u;
const QUALIFICATION_GRANT_BATCH_DEVICE_CLAIM_PATH = /^\/v1\/organizations\/(?<organizationId>[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})\/devices\/(?<deviceId>[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})\/qualification-grant-batches\/(?<batchId>[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})\/claim$/u;
const RFC3339_UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/u;
const RFC3339_MILLISECONDS_UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u;
const SAFE_CANDIDATE_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;
const SHA256_HEX = /^[0-9a-f]{64}$/u;
const SOURCE_COMMIT = /^[0-9a-f]{40}$/u;
const TEAM_ID = /^[A-Z0-9]{10}$/u;
const DEVICE_FINGERPRINT = /^SHA256:[A-Za-z0-9_-]{43}$/u;
const BASE64URL_32 = /^[A-Za-z0-9_-]{43}$/u;
const BASE64URL_SIGNATURE = /^[A-Za-z0-9_-]{86}$/u;
const V2_CANDIDATE_BINDING_KEYS = Object.freeze([
  "version", "enrollment_id", "organization_id", "device_id", "candidate_id",
  "artifact_sha256", "source_commit", "team_id", "device_key_fingerprint", "expires_at"
]);
const V2_COMPLETION_KEYS = new Set(["version", "proof_version", "enrollment_id", "organization_id", "device_id", "label", "platform", "device_key", "candidate_id", "device_key_fingerprint", "challenge"]);
const V2_CHALLENGE_KEYS = new Set(["challenge_id", "nonce", "expires_at", "candidate_id", "device_key_fingerprint"]);
const V2_PROOF_DOMAIN = "AgentPass-Enrollment-Proof-v2\0";
export function createCloudApi({ store, tokenRecords = [], bundleSigner, capabilitySigner, refreshHintService, now = () => Date.now(), monotonicNow, replayCache = createReplayCache(), deviceReplayConsumer, agentSessionDeviceApi, qualificationGrantBatchDeviceApi, platformPromotionApi, platformPromotionRepository, platformAuthenticator, platformAuthBinding, platformAuditAppender, platformPromotionEnabled = false, rateLimiter, admissionRateLimiter, verifyRecentWebAuthn, recentAuthService, humanAuthApi, humanSession, humanAuthOrigin, auditExportIssuanceService, auditExportVerifier, capabilityAuthorityRepository, capabilityRevocationSource, auditRepository, enrollmentCredentialSecret, possessionReceiptSigner, trackInFlight, readiness, operationalMetrics, operationalProbeSecret } = {}) {
  if (!store) throw new TypeError("store is required");
  if (verifyRecentWebAuthn !== undefined && recentAuthService !== undefined) throw new TypeError("configure verifyRecentWebAuthn or recentAuthService, not both");
  if (humanAuthApi !== undefined && (!humanAuthApi || typeof humanAuthApi.handle !== "function")) throw new TypeError("humanAuthApi must expose handle()");
  if (humanSession !== undefined && (!humanSession || typeof humanSession.authenticateRequest !== "function")) throw new TypeError("humanSession must expose authenticateRequest()");
  if (auditExportIssuanceService !== undefined && (!auditExportIssuanceService
    || typeof auditExportIssuanceService.issueAuditExport !== "function"
    || typeof auditExportIssuanceService.retrieveAuditExport !== "function")) {
    throw new TypeError("auditExportIssuanceService must expose issueAuditExport() and retrieveAuditExport()");
  }
  if (auditExportVerifier !== undefined && (!auditExportVerifier || typeof auditExportVerifier.verifyAuditExport !== "function")) {
    throw new TypeError("auditExportVerifier must expose verifyAuditExport()");
  }
  if (auditExportVerifier !== undefined && auditExportIssuanceService === undefined) {
    throw new TypeError("auditExportVerifier requires auditExportIssuanceService");
  }
  const effectiveHumanAuthOrigin = humanAuthOrigin ?? humanSession?.expectedOrigin;
  if (auditExportIssuanceService !== undefined && (humanSession === undefined || recentAuthService === undefined
    || typeof effectiveHumanAuthOrigin !== "string" || !effectiveHumanAuthOrigin)) {
    throw new TypeError("audit export Human API requires humanSession, recentAuthService, and expectedOrigin");
  }
  if (agentSessionDeviceApi !== undefined && (!agentSessionDeviceApi || typeof agentSessionDeviceApi.handle !== "function")) throw new TypeError("agentSessionDeviceApi must expose handle()");
  if (qualificationGrantBatchDeviceApi !== undefined && (!qualificationGrantBatchDeviceApi || typeof qualificationGrantBatchDeviceApi.handle !== "function")) throw new TypeError("qualificationGrantBatchDeviceApi must expose handle()");
  if (platformPromotionApi !== undefined && (!platformPromotionApi || typeof platformPromotionApi.handle !== "function")) throw new TypeError("platformPromotionApi must expose handle()");
  if (platformAuditAppender !== undefined && typeof platformAuditAppender !== "function") throw new TypeError("platformAuditAppender must be a function");
  if ((platformPromotionRepository !== undefined) !== (platformAuthenticator !== undefined)) throw new TypeError("platformPromotionRepository and platformAuthenticator must be configured together");
  if (typeof platformPromotionEnabled !== "boolean") throw new TypeError("platformPromotionEnabled must be a boolean");
  if (platformPromotionEnabled && typeof platformAuditAppender !== "function") throw new TypeError("enabled Platform promotion requires a durable audit appender");
  const effectivePlatformPromotionApi = platformPromotionApi ?? (platformPromotionRepository ? createPlatformPromotionHttpApi({ repository: platformPromotionRepository, authenticate: platformAuthenticator, auditAppender: platformAuditAppender, requireAudit: platformPromotionEnabled, expectedWorkloadAudience: platformAuthBinding?.audience, expectedSpiffeId: platformAuthBinding?.mtls?.spiffe_id, now }) : undefined);
  if (capabilityRevocationSource !== undefined && (!capabilityRevocationSource || typeof capabilityRevocationSource.listRevokedCapabilityIds !== "function")) throw new TypeError("capabilityRevocationSource must expose listRevokedCapabilityIds()");
  if (capabilityAuthorityRepository !== undefined && (!capabilityAuthorityRepository || typeof capabilityAuthorityRepository.issueCapabilityMetadata !== "function")) throw new TypeError("capabilityAuthorityRepository must expose issueCapabilityMetadata()");
  if (auditRepository !== undefined && (!auditRepository || typeof auditRepository.listDeviceAuditEvents !== "function")) throw new TypeError("auditRepository must expose listDeviceAuditEvents()");
  if (refreshHintService !== undefined && (!refreshHintService || typeof refreshHintService.poll !== "function")) throw new TypeError("refreshHintService must expose poll()");
  if (deviceReplayConsumer !== undefined && typeof deviceReplayConsumer !== "function") throw new TypeError("deviceReplayConsumer must be a function");
  if (enrollmentCredentialSecret !== undefined && (!Buffer.isBuffer(enrollmentCredentialSecret) || enrollmentCredentialSecret.length !== 32)) throw new TypeError("enrollmentCredentialSecret must be an exact 32-byte Buffer");
  if (possessionReceiptSigner !== undefined && (!possessionReceiptSigner || typeof possessionReceiptSigner.signPossessionReceipt !== "function")) throw new TypeError("possessionReceiptSigner must expose signPossessionReceipt()");
  if (trackInFlight !== undefined && typeof trackInFlight !== "function") throw new TypeError("trackInFlight must be a function");
  if (readiness !== undefined && typeof readiness !== "function") throw new TypeError("readiness must be a function");
  if (operationalMetrics !== undefined && (!operationalMetrics || typeof operationalMetrics.snapshot !== "function")) throw new TypeError("operationalMetrics must expose snapshot()");
  if (operationalProbeSecret !== undefined && (!Buffer.isBuffer(operationalProbeSecret) || operationalProbeSecret.length !== 32)) throw new TypeError("operationalProbeSecret must be an exact 32-byte Buffer");
  if ((readiness !== undefined || operationalMetrics !== undefined) && operationalProbeSecret === undefined) throw new TypeError("operationalProbeSecret is required for operational endpoints");
  const controlBundleSigner = createControlBundleSigner(bundleSigner, now);
  const capabilityAuthoritySigner = createCapabilityAuthoritySigner(capabilitySigner, bundleSigner);
  if (bundleSigner && !bundleSigner.privateKey && enrollmentCredentialSecret === undefined) throw new TypeError("enrollmentCredentialSecret is required with a managed ControlBundle signer");
  const effectiveEnrollmentCredentialSecret = enrollmentCredentialSecret ?? (bundleSigner?.privateKey
    ? crypto.createHash("sha256").update("AgentPass-Evaluation-Enrollment-Root-v1\0").update(bundleSigner.privateKey.export({ type: "pkcs8", format: "der" })).digest()
    : undefined);
  const recentAuthVerifier = recentAuthService === undefined ? verifyRecentWebAuthn : recentAuthService?.authorize?.bind(recentAuthService);
  if (recentAuthService !== undefined && typeof recentAuthVerifier !== "function") throw new TypeError("recentAuthService must expose authorize()");
  const limiter = rateLimiter ?? createRateLimiter({ now, ...(monotonicNow ? { monotonicNow } : {}) });
  const admission = admissionRateLimiter ?? createRateLimiter({ now, ...(monotonicNow ? { monotonicNow } : {}), human: { capacity: 30, refillPerSecond: 1 }, device: { capacity: 60, refillPerSecond: 2 } });
  const activitySource = auditRepository ?? store;
  if (!limiter || typeof limiter.acquire !== "function") throw new TypeError("rateLimiter must expose acquire()");
  const routes = buildRoutes();

  async function mutateAndAudit(organizationId, mutation, audit) {
    if (typeof store.runAtomicMutation === "function") {
      const result = await store.runAtomicMutation({ organizationId, mutation: ({ store: transactionStore }) => mutation(transactionStore), audit });
      return result.mutation;
    }
    const result = await mutation(store);
    await store.appendAdminAuditEvent(typeof audit === "function" ? await audit({ mutation: result }) : audit);
    return result;
  }

  const server = http.createServer(async (request, response) => {
    const operation = async () => {
      const healthPath = new URL(request.url, "http://agentpass.invalid").pathname;
      if (request.method === "GET" && healthPath === "/health/ready" && readiness) {
        if (!authorizedOperationalProbe(request, operationalProbeSecret)) return send(response, 404, { error: { code: "not_found", message: "Resource not found" } });
        const report = await readiness().then(publicReadinessReport).catch(() => ({ version: 1, ready: false, status: "not_ready", code: "health_unavailable" }));
        return send(response, report.ready === true ? 200 : 503, report);
      }
      if (request.method === "GET" && healthPath === "/health/metrics" && operationalMetrics) {
        if (!authorizedOperationalProbe(request, operationalProbeSecret)) return send(response, 404, { error: { code: "not_found", message: "Resource not found" } });
        const report = await Promise.resolve().then(() => operationalMetrics.snapshot()).then(publicMetricsReport).catch(() => null);
        return report ? send(response, 200, report) : send(response, 503, { version: 1, valid: false, code: "metrics_unavailable" });
      }
      return handleRequest(request, response);
    };
    try { return await (trackInFlight ? trackInFlight(operation) : operation()); }
    catch (error) {
      if (!response.headersSent && error?.code === "draining") return send(response, 503, { error: { code: "draining", message: "Service is draining" }, request_id: crypto.randomUUID() });
      if (!response.headersSent) return send(response, 500, { error: { code: "internal_error", message: "Internal error" }, request_id: crypto.randomUUID() });
      response.destroy();
    }
  });

  async function handleRequest(request, response) {
    const requestId = crypto.randomUUID();
    try {
      const agentSessionRoute = request.method === "POST" ? AGENT_SESSION_DEVICE_CONSUME_PATH.exec(request.url) : null;
      if (agentSessionDeviceApi && agentSessionRoute) {
        const admissionDecision = await acquireRateLimit(admission, {
          tenantId: agentSessionRoute.groups.organizationId,
          principalType: "device",
          principalId: transportPrincipalId(request)
        });
        if (!admissionDecision.allowed) return send(response, 429, { error: { code: "rate_limited", message: "Pre-authentication rate limit exceeded" }, request_id: requestId }, rateLimitHeaders(admissionDecision, true));
        const bodyBytes = await readBody(request);
        const result = await agentSessionDeviceApi.handle({ method: request.method, url: request.url, headers: request.headers, body: bodyBytes });
        const normalized = normalizeAgentSessionDeviceResult(result);
        if (!normalized) throw apiError("agent_session_unavailable", 503, "Agent Session Device API is unavailable");
        return sendRawJson(response, normalized.status, normalized.encoded, normalized.headers);
      }
      const qualificationBatchRoute = request.method === "POST" ? QUALIFICATION_GRANT_BATCH_DEVICE_CLAIM_PATH.exec(request.url) : null;
      if (qualificationGrantBatchDeviceApi && qualificationBatchRoute) {
        const admissionDecision = await acquireRateLimit(admission, {
          tenantId: qualificationBatchRoute.groups.organizationId,
          principalType: "device",
          principalId: transportPrincipalId(request)
        });
        if (!admissionDecision.allowed) return send(response, 429, { error: { code: "rate_limited", message: "Pre-authentication rate limit exceeded" }, request_id: requestId }, rateLimitHeaders(admissionDecision, true));
        const bodyBytes = await readBody(request);
        const result = await qualificationGrantBatchDeviceApi.handle({ method: request.method, url: request.url, headers: request.headers, body: bodyBytes });
        const normalized = normalizeAgentSessionDeviceResult(result);
        if (!normalized) throw apiError("qualification_grant_batch_unavailable", 503, "Qualification Grant batch Device API is unavailable");
        return sendRawJson(response, normalized.status, normalized.encoded, normalized.headers);
      }
      const url = new URL(request.url, "http://agentpass.invalid");
      if (isPlatformPromotionPath(url.pathname)) {
        if (!effectivePlatformPromotionApi) {
          if (platformPromotionEnabled) return send(response, 503, { error: { code: "platform_promotion_unavailable", message: "Platform promotion API is unavailable" }, request_id: requestId });
          return send(response, 404, { error: { code: "not_found", message: "Resource not found" }, request_id: requestId });
        }
        let bodyBytes;
        try { bodyBytes = await readBody(request, 256 * 1024); }
        catch { return send(response, 400, { error: { code: "invalid_platform_request", message: "Platform promotion request is invalid" }, request_id: requestId }); }
        let result;
        try {
          result = await effectivePlatformPromotionApi.handle({ method: request.method, url: request.url, request, headers: request.headers, body: bodyBytes, requestId });
        } catch (error) {
          const status = platformPromotionErrorStatus(error?.status);
          const code = platformPromotionErrorCode(error?.code);
          return send(response, status, { error: { code, message: status === 401 ? "Authentication failed" : status === 403 ? "Authorization denied" : status === 400 ? "Platform promotion request is invalid" : "Platform promotion API is unavailable" }, request_id: requestId });
        }
        const normalized = normalizePlatformPromotionResult({ ...result, body: { ...result?.body, request_id: requestId }, request_id: requestId });
        if (!normalized) return send(response, 503, { error: { code: "platform_promotion_unavailable", message: "Platform promotion API is unavailable" }, request_id: requestId });
        return sendRawJson(response, normalized.status, normalized.encoded, normalized.headers);
      }
      if (auditExportIssuanceService && (HUMAN_AUDIT_EXPORT_CREATE_PATH.test(url.pathname)
        || HUMAN_AUDIT_EXPORT_GET_PATH.test(url.pathname)
        || HUMAN_AUDIT_EXPORT_DOWNLOAD_PATH.test(url.pathname)
        || (auditExportVerifier && HUMAN_AUDIT_EXPORT_VERIFY_PATH.test(url.pathname)))) {
        return await handleHumanAuditExport(request, response, url, requestId);
      }
      if (humanAuthApi && isExactHumanAuthPath(url, request.method)) return await handleHumanAuth(request, response, url, requestId);
      const route = routes.find((candidate) => candidate.method === request.method && candidate.pattern.test(url.pathname));
      if (!route) return send(response, 404, { error: { code: "not_found", message: "Resource not found" }, request_id: requestId });
      const match = route.pattern.exec(url.pathname);
      const organizationId = match?.groups?.organizationId;
      // Public enrollment IDs are attacker-controlled path input. Keep every
      // pre-auth enrollment attempt in one IP-scoped tenant bucket so random
      // UUIDs cannot manufacture fresh admission capacity.
      const rateLimitTenant = organizationId ?? "public-device-enrollment";
      // Admission is keyed only by the transport peer. Untrusted auth headers
      // must not let an attacker mint fresh pre-authentication buckets.
      const admissionId = crypto.createHash("sha256").update(String(request.socket.remoteAddress ?? "unknown")).digest("hex");
      const admitted = await acquireRateLimit(admission, { tenantId: rateLimitTenant, principalType: route.device ? "device" : "human", principalId: admissionId });
      if (!admitted.allowed) throw apiError("rate_limited", 429, "Pre-authentication rate limit exceeded", rateLimitHeaders(admitted, true));
      const bodyBytes = await readBody(request);
      const body = parseBody(bodyBytes);
      let principal;
      if (route.device) {
        const devices = await store.listDevices({ organizationId });
        principal = verifyDeviceRequest({ method: request.method, path: request.url, body: bodyBytes, headers: request.headers }, devices, { organizationId, now: now(), replayCache, deferReplayConsumption: deviceReplayConsumer !== undefined, includeAuthenticationMetadata: true });
        if (deviceReplayConsumer !== undefined) {
          let accepted = false;
          try { accepted = await deviceReplayConsumer({ organizationId, deviceId: principal.device_id, nonce: request.headers["agentpass-nonce"] }); }
          catch { throw apiError("auth_replay_unavailable", 503, "Authentication replay protection is unavailable"); }
          if (accepted !== true) { recordOperationalMetric(operationalMetrics, "recordReplayDenial"); throw apiError("auth_replay_detected", 401, "Authentication failed"); }
        }
      } else if (route.enrollment) {
        principal = { enrollment_id: match?.groups?.enrollmentId, member_id: admissionId };
      } else if (humanSession !== undefined) {
        const authenticated = await humanSession.authenticateRequest({ method: request.method, headers: request.headers });
        if (!authenticated?.session || typeof authenticated.session !== "object" || Array.isArray(authenticated.session)) throw apiError("human_session_invalid", 401, "Authentication failed");
        principal = authenticated.session;
        requireOrganizationRole(principal, organizationId, route.role);
        if (route.recentAuthOperation) await requireRecentWebAuthn({ verifier: recentAuthVerifier, principal, proof: request.headers["agentpass-recent-auth"], organizationId, operation: route.recentAuthOperation, now: now() });
      } else {
        principal = authenticateApiToken(bearerToken(request.headers.authorization), tokenRecords);
        requireOrganizationRole(principal, organizationId, route.role);
        if (route.recentAuthOperation) await requireRecentWebAuthn({ verifier: recentAuthVerifier, principal, proof: request.headers["agentpass-recent-auth"], organizationId, operation: route.recentAuthOperation, now: now() });
      }
      let rateLimit;
      try {
        rateLimit = await limiter.acquire({ tenantId: rateLimitTenant, principalType: route.device ? "device" : "human", principalId: route.device ? principal.device_id : principal.member_id });
        if (!rateLimit || typeof rateLimit !== "object" || typeof rateLimit.allowed !== "boolean" || !Number.isSafeInteger(rateLimit.limit) || rateLimit.limit < 1 || !Number.isSafeInteger(rateLimit.remaining) || rateLimit.remaining < 0 || rateLimit.remaining > rateLimit.limit || !Number.isSafeInteger(rateLimit.retryAfterSeconds) || rateLimit.retryAfterSeconds < 0 || !Number.isSafeInteger(rateLimit.resetAt) || rateLimit.resetAt < 0) throw new Error("invalid rate limiter decision");
      } catch (error) {
        if (error?.code === "RATE_LIMITER_CAPACITY_EXHAUSTED") throw error;
        throw apiError("rate_limiter_unavailable", 503, "Rate limiter is temporarily unavailable", { "Retry-After": "1" });
      }
      if (!rateLimit.allowed) { recordOperationalMetric(operationalMetrics, "recordRateLimitDenial"); throw apiError("rate_limited", 429, "Rate limit exceeded", rateLimitHeaders(rateLimit, true)); }
      const context = { request, url, body, bodyBytes, organizationId, principal, match: match.groups ?? {}, idempotencyKey: idempotencyKey(request, route), requestId };
      const result = await route.handle(context);
      const gapCount = result?.body?.ingestion?.gaps?.length;
      if (Number.isSafeInteger(gapCount) && gapCount > 0) recordOperationalMetric(operationalMetrics, "recordAuditGap", gapCount);
      if (result.status === 204) sendNoContent(response, { ...rateLimitHeaders(rateLimit), ...result.headers });
      else send(response, result.status ?? 200, { ...result.body, request_id: requestId }, { ...rateLimitHeaders(rateLimit), ...result.headers });
    } catch (error) {
      if (error?.code === "ERR_BUNDLE_HEAD_MISMATCH") recordOperationalMetric(operationalMetrics, "recordStaleAck");
      if (hasErrorCode(error, "55P03")) recordOperationalMetric(operationalMetrics, "recordLockTimeout");
      const mapped = mapError(error);
      send(response, mapped.status, { error: { code: mapped.code, message: mapped.message }, request_id: requestId }, mapped.headers);
    }
  }

  async function handleHumanAuditExport(request, response, url, requestId) {
    const createMatch = HUMAN_AUDIT_EXPORT_CREATE_PATH.exec(url.pathname);
    const getMatch = HUMAN_AUDIT_EXPORT_GET_PATH.exec(url.pathname);
    const downloadMatch = HUMAN_AUDIT_EXPORT_DOWNLOAD_PATH.exec(url.pathname);
    const verifyMatch = HUMAN_AUDIT_EXPORT_VERIFY_PATH.exec(url.pathname);
    let responseRateHeaders = {};
    let auditActor;
    let auditAction;
    let auditOrganizationId;
    let auditTargetId;
    try {
      const matched = createMatch ?? getMatch ?? downloadMatch ?? verifyMatch;
      if (!matched) throw apiError("not_found", 404, "Resource not found");
      const organizationId = matched.groups.organizationId.toLowerCase();
      const action = createMatch ? "create" : getMatch ? "retrieve" : downloadMatch ? "download" : "verify";
      auditAction = action;
      auditOrganizationId = organizationId;
      const expectedMethod = action === "create" || action === "verify" ? "POST" : "GET";
      const admitted = await acquireRateLimit(admission, {
        tenantId: organizationId,
        principalType: "human",
        principalId: transportPrincipalId(request)
      });
      if (!admitted.allowed) throw apiError("rate_limited", 429, "Pre-authentication rate limit exceeded", rateLimitHeaders(admitted, true));
      if (request.headers.authorization !== undefined) throw apiError("human_session_invalid", 401, "Authentication failed");
      const expectedOrigin = effectiveHumanAuthOrigin;
      const origin = request.headers.origin;
      if (origin !== expectedOrigin || origin === "null") throw apiError("human_session_request_denied", 403, "Authentication failed");
      if (request.method !== expectedMethod) {
        throw apiError("method_not_allowed", 405, "Method not allowed", { Allow: expectedMethod });
      }
      const bodyBytes = await readBody(request, HUMAN_AUTH_MAX_BODY_BYTES);
      if ((action === "retrieve" || action === "download") && bodyBytes.length !== 0) throw apiError("invalid_audit_export_request", 400, "Audit export request is invalid");
      const mutation = action === "create" || action === "verify";
      const csrfToken = mutation ? request.headers["agentpass-csrf"] : undefined;
      const authenticated = await humanSession.authenticateRequest({
        method: request.method,
        headers: request.headers,
        origin,
        cookie: request.headers.cookie,
        ...(mutation ? { csrfToken } : {})
      });
      const principal = authenticated?.session;
      if (!principal || typeof principal !== "object" || Array.isArray(principal)) throw apiError("human_session_invalid", 401, "Authentication failed");
      if (principal.organization_id !== organizationId) throw apiError("not_found", 404, "Resource not found");
      auditActor = principal.member_id;
      const allowedRoles = action === "create" ? new Set(["owner", "admin"]) : new Set(["owner", "admin", "auditor"]);
      if (!allowedRoles.has(principal.role)) throw apiError("role_denied", 403, "Authorization denied");
      const rateLimit = await acquireRateLimit(limiter, {
        tenantId: organizationId,
        principalType: "human",
        principalId: principal.member_id
      });
      if (!rateLimit.allowed) throw apiError("rate_limited", 429, "Rate limit exceeded", rateLimitHeaders(rateLimit, true));
      responseRateHeaders = rateLimitHeaders(rateLimit);

      let exportId;
      let environment;
      let chain;
      let idempotency;
      let verifyInput;
      if (action === "create") {
        if (url.search || url.hash) throw apiError("invalid_audit_export_request", 400, "Audit export request is invalid");
        const body = parseBody(bodyBytes);
        rejectUnknown(body, new Set(["export_id", "environment", "chain"]), "audit_export");
        if (Object.keys(body).length !== 3 || !canonicalUuid(body.export_id)
          || !["staging", "production"].includes(body.environment)
          || !["admin", "device", "cloud_agent"].includes(body.chain)) {
          throw apiError("invalid_audit_export_request", 400, "Audit export request is invalid");
        }
        exportId = body.export_id;
        environment = body.environment;
        chain = body.chain;
        idempotency = request.headers["idempotency-key"];
        if (typeof idempotency !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._~:-]{7,255}$/u.test(idempotency)) {
          throw apiError("idempotency_key_required", 400, "A valid Idempotency-Key is required");
        }
      } else if (action === "retrieve" || action === "download") {
        if (request.headers["idempotency-key"] !== undefined || (action === "download" && request.headers["agentpass-csrf"] !== undefined) || url.hash) throw apiError("invalid_audit_export_request", 400, "Audit export request is invalid");
        requireExactQueryKeys(url, new Set(["environment", "chain"]));
        const environmentValues = url.searchParams.getAll("environment");
        const chainValues = url.searchParams.getAll("chain");
        if (environmentValues.length !== 1 || chainValues.length !== 1
          || !["staging", "production"].includes(environmentValues[0])
          || !["admin", "device", "cloud_agent"].includes(chainValues[0])) {
          throw apiError("invalid_audit_export_request", 400, "Audit export request is invalid");
        }
        exportId = (getMatch ?? downloadMatch).groups.exportId.toLowerCase();
        environment = environmentValues[0];
        chain = chainValues[0];
      } else {
        if (url.search || url.hash || request.headers["idempotency-key"] !== undefined) throw apiError("invalid_audit_export_request", 400, "Audit export request is invalid");
        verifyInput = normalizeAuditExportVerifyInput(parseBody(bodyBytes), organizationId);
        exportId = verifyInput.export_id;
        environment = verifyInput.environment;
        chain = verifyInput.chain;
      }
      auditTargetId = exportId;

      const contextHash = crypto.createHash("sha256").update(canonicalJson({
        version: 1,
        organization_id: organizationId,
        export_id: exportId,
        environment,
        chain
      }), "utf8").digest("hex");
      await requireAuditExportRecentAuth({
        verifier: recentAuthVerifier,
        principal,
        proof: request.headers["agentpass-recent-auth"],
        organizationId,
        operation: `audit.export.${action}`,
        contextHash,
        now: now()
      });
      if (action === "verify") {
        let verification;
        try { verification = await auditExportVerifier.verifyAuditExport(verifyInput); }
        catch { throw apiError("not_found", 404, "Resource not found"); }
        const publicVerification = normalizeAuditExportVerificationResult(verification);
        await appendAuditExportOperation({ organizationId, actorId: principal.member_id, exportId, action, requestId, outcome: "succeeded", details: { environment, chain, valid: publicVerification.valid, reason: publicVerification.reason } });
        return send(response, 200, publicVerification, {
          "cache-control": "no-store, max-age=0",
          Pragma: "no-cache",
          "X-Content-Type-Options": "nosniff",
          ...responseRateHeaders
        });
      }
      let auditExport;
      try {
        auditExport = action === "create"
          ? await auditExportIssuanceService.issueAuditExport({ organization_id: organizationId, export_id: exportId, environment, chain, idempotency_key: idempotency })
          : await auditExportIssuanceService.retrieveAuditExport({ organization_id: organizationId, export_id: exportId, environment, chain });
      } catch (error) { throw mapAuditExportServiceError(error, action === "create"); }
      const normalized = normalizeAuditExportPublicResult(auditExport, { organizationId, exportId, environment, chain });
      if (action === "download") {
        try { assertAuditExportPublicIntegrity(normalized); }
        catch { throw apiError("audit_export_unavailable", 503, "Audit export is unavailable"); }
        const encoded = Buffer.from(canonicalJson(normalized), "utf8");
        await appendAuditExportOperation({ organizationId, actorId: principal.member_id, exportId, action, requestId, outcome: "succeeded", details: { environment, chain, validity: normalized.validity, payload_digest: normalized.payload_digest } });
        return sendRawJson(response, 200, encoded, {
          "content-type": "application/json",
          "content-disposition": "attachment; filename=\"agentpass-audit-export.json\"",
          "content-length": String(encoded.length),
          "cache-control": "no-store, max-age=0",
          Pragma: "no-cache",
          "X-Content-Type-Options": "nosniff",
          ...responseRateHeaders
        });
      }
      await appendAuditExportOperation({ organizationId, actorId: principal.member_id, exportId, action, requestId, outcome: "succeeded", details: { environment, chain, validity: normalized.validity, payload_digest: normalized.payload_digest } });
      return send(response, action === "create" ? 201 : 200, { audit_export: normalized, request_id: requestId }, {
        "cache-control": "no-store, max-age=0",
        Pragma: "no-cache",
        "X-Content-Type-Options": "nosniff",
        ...responseRateHeaders
      });
    } catch (error) {
      const mapped = mapError(error);
      if (auditActor && auditAction && auditOrganizationId) {
        await appendAuditExportOperation({ organizationId: auditOrganizationId, actorId: auditActor, exportId: auditTargetId, action: auditAction, requestId, outcome: mapped.status === 403 ? "denied" : "failed", details: { status: mapped.status, code: mapped.code } }).catch(() => {});
      }
      return send(response, mapped.status, { error: { code: mapped.code, message: mapped.message }, request_id: requestId }, {
        Pragma: "no-cache",
        "X-Content-Type-Options": "nosniff",
        ...(mapped.headers ?? {})
      });
    }
  }

  async function appendAuditExportOperation({ organizationId, actorId, exportId, action, requestId, outcome, details }) {
    if (typeof store.appendAdminAuditEvent !== "function") return;
    await store.appendAdminAuditEvent({
      organizationId,
      actorId,
      eventType: `audit.export.${action}.${outcome}`,
      targetType: "audit_export",
      ...(exportId ? { targetId: exportId } : {}),
      idempotencyKey: `audit-export:${requestId}:${outcome}`,
      details
    });
  }
  server.requestTimeout = 15_000;
  server.headersTimeout = 10_000;
  server.keepAliveTimeout = 5_000;
  server.maxHeadersCount = 64;
  server.on("connection", (socket) => socket.setTimeout(15_000));
  return server;

  async function handleHumanAuth(request, response, url, requestId) {
    const principalId = transportPrincipalId(request);
    const tenantId = "human-auth";
    const admitted = await acquireRateLimit(admission, { tenantId, principalType: "human", principalId });
    if (!admitted.allowed) throw apiError("rate_limited", 429, "Pre-authentication rate limit exceeded", rateLimitHeaders(admitted, true));
    const rateLimit = await acquireRateLimit(limiter, { tenantId, principalType: "human", principalId });
    if (!rateLimit.allowed) throw apiError("rate_limited", 429, "Rate limit exceeded", rateLimitHeaders(rateLimit, true));

    const bodyBytes = await readBody(request, HUMAN_AUTH_MAX_BODY_BYTES);
    let result;
    try {
      // Preserve the original Node header values. The human-auth boundary
      // authenticates the session from cookie, Origin, and CSRF headers.
      result = await humanAuthApi.handle({ method: request.method, url: `${url.pathname}${url.search}`, headers: request.headers, body: bodyBytes });
    } catch {
      return send(response, 503, { error: { code: "human_auth_unavailable", message: "Human authentication is temporarily unavailable" }, request_id: requestId }, rateLimitHeaders(rateLimit));
    }
    const normalized = normalizeHumanAuthResult(result);
    if (!normalized) return send(response, 503, { error: { code: "human_auth_unavailable", message: "Human authentication is temporarily unavailable" }, request_id: requestId }, rateLimitHeaders(rateLimit));
    sendRawJson(response, normalized.status, normalized.encoded, mergeResponseHeaders(normalized.headers, rateLimitHeaders(rateLimit)));
  }

  function buildRoutes() {
    const route = (method, pattern, role, handle, device = false, enrollment = false, recentAuthOperation = undefined) => ({ method, pattern, role, handle, device, enrollment, recentAuthOperation });
    return [
      route("GET", new RegExp(`^/v1/organizations/(?<organizationId>${UUID})$`), "viewer", async ({ organizationId }) => ({ body: { organization: await store.getOrganization({ organizationId }) } })),
      route("GET", new RegExp(`^/v1/organizations/(?<organizationId>${UUID})/devices$`), "viewer", async ({ organizationId }) => {
        if (typeof store.listDeviceReadModels !== "function") throw apiError("device_read_model_unavailable", 503, "Device read model is unavailable");
        return { body: { devices: normalizeDeviceReadModels(await store.listDeviceReadModels({ organizationId })) } };
      }),
      route("POST", new RegExp(`^/v1/organizations/(?<organizationId>${UUID})/devices/(?<deviceId>${UUID})/refresh-requests$`), "admin", async ({ organizationId, match, body, bodyBytes, idempotencyKey, principal }) => {
        requireExactEmptyJsonObject(body, bodyBytes, "device_refresh_request");
        if (typeof store.requestDeviceWake !== "function") throw apiError("refresh_request_unavailable", 503, "Refresh request is unavailable");
        let refreshRequest;
        try {
          refreshRequest = await mutateAndAudit(
            organizationId,
            (target) => target.requestDeviceWake({
              organizationId,
              deviceId: match.deviceId.toLowerCase(),
              principalId: principal.member_id,
              idempotencyKey,
              requestedAt: new Date(now()).toISOString()
            }),
            ({ mutation }) => ({
              organizationId,
              eventType: "device.refresh_requested",
              actorId: principal.member_id,
              targetType: "device",
              targetId: match.deviceId.toLowerCase(),
              details: { status: mutation.status, desired_generation: mutation.desired_generation },
              idempotencyKey: `${idempotencyKey}:audit`
            })
          );
        } catch (error) {
          throw mapRefreshRequestRepositoryError(error);
        }
        return { status: 202, body: { refresh_request: normalizeRefreshRequestResult(refreshRequest, match.deviceId) } };
      }, false, false, "device.refresh.request"),
      route("POST", new RegExp(`^/v1/organizations/(?<organizationId>${UUID})/devices$`), "admin", async ({ organizationId, body, idempotencyKey, principal }) => ({ status: 201, body: { device: await mutateAndAudit(organizationId, (target) => target.createDevice({ ...body, organizationId, createdBy: principal.member_id, principalId: principal.member_id, idempotencyKey }), ({ mutation }) => ({ organizationId, eventType: "device.created", actorId: principal.member_id, targetType: "device", targetId: mutation.device_id, idempotencyKey: `${idempotencyKey}:audit` })) } })),
      route("POST", new RegExp(`^/v1/organizations/(?<organizationId>${UUID})/device-enrollments$`), "admin", async ({ organizationId, body, idempotencyKey, principal }) => {
        if (body.proof_version === 2) {
          validateV2IssueBody(body);
          const ttlMs = body.ttl_ms ?? 15 * 60 * 1000;
          const enrollmentId = body.enrollment_id ?? deterministicEnrollmentUuid(effectiveEnrollmentCredentialSecret, "enrollment", {
            organization_id: organizationId,
            principal_id: principal.member_id,
            idempotency_key: idempotencyKey,
            candidate_id: body.candidate_id,
            device_key_fingerprint: body.device_key_fingerprint,
            label: body.label,
            platform: body.platform ?? "macos",
            ttl_ms: ttlMs
          });
          const deviceId = body.device_id ?? deterministicEnrollmentUuid(effectiveEnrollmentCredentialSecret, "device", {
            organization_id: organizationId,
            principal_id: principal.member_id,
            idempotency_key: idempotencyKey,
            candidate_id: body.candidate_id,
            device_key_fingerprint: body.device_key_fingerprint,
            label: body.label,
            platform: body.platform ?? "macos",
            ttl_ms: ttlMs
          });
          const createdAt = new Date(now()).toISOString();
          const expiresAt = new Date(now() + ttlMs).toISOString();
          const candidate = await resolveActiveReleaseCandidate(store, body.candidate_id, organizationId);
          const possessionReceiptVerification = await loadPossessionReceiptVerification(possessionReceiptSigner);
          const candidateBinding = makeCandidateBinding({
            enrollmentId,
            organizationId,
            deviceId,
            candidate,
            deviceKeyFingerprint: body.device_key_fingerprint,
            expiresAt
          });
          const credential = deriveEnrollmentV2Credential(effectiveEnrollmentCredentialSecret, {
            organization_id: organizationId,
            principal_id: principal.member_id,
            idempotency_key: idempotencyKey,
            enrollment_id: enrollmentId,
            device_id: deviceId,
            candidate_id: body.candidate_id,
            device_key_fingerprint: body.device_key_fingerprint,
            label: body.label,
            platform: body.platform ?? "macos",
            ttl_ms: ttlMs
          });
          const nonce = deriveEnrollmentV2Nonce(effectiveEnrollmentCredentialSecret, candidateBinding);
          const enrollment = await mutateAndAudit(organizationId,
            (target) => createV2EnrollmentInStore(target, {
              proofVersion: 2,
              organizationId,
              enrollmentId,
              deviceId,
              label: body.label,
              platform: body.platform ?? "macos",
              candidateId: body.candidate_id,
              deviceKeyFingerprint: body.device_key_fingerprint,
              credentialDigest: sha256HexText(credential),
              challengeNonceDigest: sha256Text(nonce),
              createdAt,
              expiresAt,
              createdBy: principal.member_id,
              principalId: principal.member_id,
              idempotencyKey
            }),
            ({ mutation }) => ({
              organizationId,
              eventType: "device.enrollment_v2_issued",
              actorId: principal.member_id,
              targetType: "device",
              targetId: mutation.device_id,
              details: { enrollment_id: mutation.enrollment_id, candidate_id: body.candidate_id, device_key_fingerprint: body.device_key_fingerprint, expires_at: expiresAt },
              idempotencyKey: `${idempotencyKey}:audit`
            }));
          const effectiveEnrollmentId = enrollment?.enrollment_id ?? enrollmentId;
          const effectiveDeviceId = enrollment?.device_id ?? deviceId;
          if (effectiveEnrollmentId !== enrollmentId || effectiveDeviceId !== deviceId) throw apiError("enrollment_binding_unavailable", 503, "Enrollment binding is unavailable");
          return {
            status: 201,
            body: {
              enrollment: {
                version: 2,
                proof_version: 2,
                enrollment_id: enrollmentId,
                organization_id: organizationId,
                device_id: deviceId,
                label: body.label,
                platform: body.platform ?? "macos",
                candidate_binding: candidateBinding,
                challenge_id: enrollmentId,
                nonce,
                expires_at: candidateBinding.expires_at,
                challenge: {
                  challenge_id: enrollmentId,
                  nonce,
                  expires_at: candidateBinding.expires_at,
                  candidate_id: candidateBinding.candidate_id,
                  device_key_fingerprint: candidateBinding.device_key_fingerprint
                },
                credential,
                possession_receipt_verification: possessionReceiptVerification,
                endpoint: `/v1/enrollments/${enrollmentId}`
              }
            }
          };
        }
        rejectUnknown(body, new Set(["enrollment_id", "device_id", "label", "platform", "ttl_ms"]), "device_enrollment_issue");
        const ttl = body.ttl_ms ?? 15 * 60 * 1000;
        if (!Number.isSafeInteger(ttl) || ttl < 60_000 || ttl > 24 * 60 * 60 * 1000) throw apiError("invalid_enrollment_ttl", 400, "Enrollment TTL must be between 1 minute and 24 hours");
        const credential = deriveEnrollmentCredential(effectiveEnrollmentCredentialSecret, { organization_id: organizationId, principal_id: principal.member_id, idempotency_key: idempotencyKey, enrollment_id: body.enrollment_id ?? null, device_id: body.device_id ?? null, label: body.label, platform: body.platform ?? "macos", ttl_ms: ttl });
        const createdAt = new Date(now()).toISOString();
        const enrollment = await mutateAndAudit(organizationId,
          (target) => target.createDeviceEnrollment({ organizationId, enrollmentId: body.enrollment_id, deviceId: body.device_id, label: body.label, platform: body.platform ?? "macos", credentialDigest: crypto.createHash("sha256").update(credential).digest("hex"), createdAt, expiresAt: new Date(now() + ttl).toISOString(), createdBy: principal.member_id, principalId: principal.member_id, idempotencyKey }),
          ({ mutation }) => ({ organizationId, eventType: "device.enrollment_issued", actorId: principal.member_id, targetType: "device", targetId: mutation.device_id, details: { enrollment_id: mutation.enrollment_id, expires_at: mutation.expires_at }, idempotencyKey: `${idempotencyKey}:audit` }));
        return { status: 201, body: { enrollment: { ...enrollment, credential, endpoint: `/v1/enrollments/${enrollment.enrollment_id}` } } };
      }, false, false, "device.enrollment.issue"),
      route("POST", new RegExp(`^/v1/enrollments/(?<enrollmentId>${UUID})$`), null, async ({ match, body, bodyBytes, request, url }) => {
        if (body.proof_version === 2) {
          validateV2CompletionBody(body, match.enrollmentId);
          if (url.search) throw apiError("invalid_enrollment_proof", 401, "Device enrollment proof is invalid");
          const credential = request.headers["agentpass-enrollment-credential"];
          if (typeof credential !== "string" || !BASE64URL_32.test(credential) || Buffer.from(credential, "base64url").length !== 32 || Buffer.from(credential, "base64url").toString("base64url") !== credential) throw apiError("invalid_enrollment_credential", 401, "Device enrollment credential is invalid");
          const candidateBinding = parseV2CandidateBindingHeader(request.headers["agentpass-enrollment-candidate-binding"]);
          const expectedCandidate = await resolveActiveReleaseCandidate(store, body.candidate_id, body.organization_id);
          const expectedBinding = makeCandidateBinding({
            enrollmentId: body.enrollment_id,
            organizationId: body.organization_id,
            deviceId: body.device_id,
            candidate: expectedCandidate,
            deviceKeyFingerprint: body.device_key_fingerprint,
            expiresAt: body.challenge.expires_at
          });
          assertV2CandidateBinding(candidateBinding, expectedBinding);
          if (body.challenge.challenge_id !== body.enrollment_id
            || body.challenge.candidate_id !== body.candidate_id
            || body.challenge.device_key_fingerprint !== body.device_key_fingerprint
            || body.challenge.expires_at !== candidateBinding.expires_at
            || request.headers["agentpass-enrollment-nonce"] !== body.challenge.nonce) {
            throw apiError("invalid_enrollment_proof", 401, "Device enrollment proof is invalid");
          }
          const expectedNonce = deriveEnrollmentV2Nonce(effectiveEnrollmentCredentialSecret, candidateBinding);
          if (body.challenge.nonce !== expectedNonce) throw apiError("invalid_enrollment_proof", 401, "Device enrollment proof is invalid");
          const credentialDigest = sha256HexText(credential);
          const challengeNonceDigest = sha256Text(body.challenge.nonce);
          validateEnrollmentPublicKey("p256-sha256", body.device_key.spki_pem);
          const actualFingerprint = publicKeyFingerprint(body.device_key.spki_pem);
          if (actualFingerprint !== body.device_key_fingerprint) throw apiError("invalid_enrollment_proof", 401, "Device enrollment proof is invalid");
          validateEnrollmentProofV2(url.pathname, bodyBytes, credentialDigest, body.challenge.nonce, candidateBinding, body.device_key.spki_pem, request.headers["agentpass-enrollment-signature"]);
          if (!controlBundleSigner) throw apiError("bundle_signer_unavailable", 503, "Control bundle signer is unavailable");
          const controlMetadata = await loadControlBundlePublicMetadata(controlBundleSigner);
          if (!possessionReceiptSigner) throw apiError("possession_receipt_signer_unavailable", 503, "Possession receipt signer is unavailable");
          const pendingDevice = typeof store.getDevice === "function" ? await store.getDevice({ organizationId: body.organization_id, deviceId: body.device_id }) : undefined;
          const deviceKeyEpoch = nextEnrollmentDeviceKeyEpoch(pendingDevice);
          const issuedAt = new Date(now()).toISOString();
          let possessionReceipt = await existingPossessionReceiptForEnrollment(store, body.organization_id, body.device_id, body.enrollment_id);
          const hadCommittedReceipt = Boolean(possessionReceipt);
          if (!possessionReceipt) {
            possessionReceipt = await signAndValidatePossessionReceipt(possessionReceiptSigner, {
              version: 1,
              enrollment_id: body.enrollment_id,
              organization_id: body.organization_id,
              device_id: body.device_id,
              candidate_id: expectedCandidate.candidate_id,
              artifact_sha256: expectedCandidate.artifact_sha256,
              source_commit: expectedCandidate.source_commit,
              team_id: expectedCandidate.team_id,
              device_key_fingerprint: body.device_key_fingerprint,
              device_key_epoch: deviceKeyEpoch,
              challenge_nonce_digest: challengeNonceDigest,
              issued_at: issuedAt
            });
          }
          const completionInput = {
            proofVersion: 2,
            enrollmentId: body.enrollment_id,
            organizationId: body.organization_id,
            deviceId: body.device_id,
            label: body.label,
            platform: body.platform,
            algorithm: body.device_key.algorithm,
            publicKey: body.device_key.spki_pem,
            deviceKey: body.device_key,
            candidateId: body.candidate_id,
            deviceKeyFingerprint: body.device_key_fingerprint,
            credentialDigest,
            challengeNonceDigest,
            possessionReceipt,
            completedAt: issuedAt
          };
          let device;
          try {
            device = await completeV2EnrollmentInStore(store, completionInput);
          } catch (error) {
            if (error?.code !== "ERR_ENROLLMENT_CONSUMED" || hadCommittedReceipt) throw error;
            const committedReceipt = await existingPossessionReceiptForEnrollment(store, body.organization_id, body.device_id, body.enrollment_id);
            if (!committedReceipt) throw error;
            device = await completeV2EnrollmentInStore(store, { ...completionInput, possessionReceipt: committedReceipt });
          }
          if (typeof store.getDeviceEnrollmentPossessionReceipt !== "function" && typeof store.appendDevicePossessionReceipt === "function") {
            await store.appendDevicePossessionReceipt({ organizationId: body.organization_id, deviceId: body.device_id, receipt: possessionReceipt });
          }
          const refreshHintTrust = await enrollmentRefreshHintTrustMetadata(refreshHintService, controlMetadata.public_key);
          const completedEpoch = positiveDeviceKeyEpoch(device);
          return {
            status: 201,
            body: {
              enrollment: {
                version: 1,
                enrollment_id: body.enrollment_id,
                organization_id: device.organization_id,
                device_id: device.device_id,
                status: device.status,
                key_algorithm: device.key_algorithm,
                device_key_epoch: completedEpoch,
                control: {
                  format_epoch: 2,
                  issuer: controlBundleSigner.issuer,
                  key_id: controlBundleSigner.key_id,
                  public_key: controlMetadata.public_key,
                  bundle_path: `/v1/organizations/${device.organization_id}/bundles/${device.device_id}`,
                  refresh_hint: refreshHintTrust
                }
              }
            }
          };
        }
        rejectUnknown(body, new Set(["version", "enrollment_id", "organization_id", "device_id", "label", "platform", "device_key"]), "device_enrollment");
        if (body.version !== 1 || body.enrollment_id !== match.enrollmentId || !body.device_key || typeof body.device_key !== "object" || Array.isArray(body.device_key)) throw apiError("invalid_enrollment", 400, "Device enrollment request is invalid");
        rejectUnknown(body.device_key, new Set(["algorithm", "spki_pem"]), "device_key");
        if (url.search) throw apiError("invalid_enrollment_proof", 401, "Device enrollment proof is invalid");
        const credential = request.headers["agentpass-enrollment-credential"];
        if (typeof credential !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(credential)) throw apiError("invalid_enrollment_credential", 401, "Device enrollment credential is invalid");
        validateEnrollmentPublicKey(body.device_key.algorithm, body.device_key.spki_pem);
        validateEnrollmentProof(url.pathname, bodyBytes, body.device_key.algorithm, body.device_key.spki_pem, credential, request.headers["agentpass-enrollment-signature"]);
        if (!controlBundleSigner) throw apiError("bundle_signer_unavailable", 503, "Control bundle signer is unavailable");
        const controlMetadata = await loadControlBundlePublicMetadata(controlBundleSigner);
        const refreshHintTrust = await enrollmentRefreshHintTrustMetadata(refreshHintService, controlMetadata.public_key);
        const device = await store.completeDeviceEnrollment({ enrollmentId: match.enrollmentId, organizationId: body.organization_id, deviceId: body.device_id, label: body.label, platform: body.platform, algorithm: body.device_key.algorithm, publicKey: body.device_key.spki_pem, credentialDigest: crypto.createHash("sha256").update(credential).digest("hex"), completedAt: new Date(now()).toISOString() });
        const deviceKeyEpoch = positiveDeviceKeyEpoch(device);
        return { status: 201, body: { enrollment: { version: 1, enrollment_id: match.enrollmentId, organization_id: device.organization_id, device_id: device.device_id, status: device.status, key_algorithm: device.key_algorithm, device_key_epoch: deviceKeyEpoch, control: { format_epoch: 2, issuer: controlBundleSigner.issuer, key_id: controlBundleSigner.key_id, public_key: controlMetadata.public_key, bundle_path: `/v1/organizations/${device.organization_id}/bundles/${device.device_id}`, refresh_hint: refreshHintTrust } } } };
      }, false, true),
      route("GET", new RegExp(`^/v1/organizations/(?<organizationId>${UUID})/agents$`), "viewer", async ({ organizationId }) => ({ body: { agents: await store.listAgents({ organizationId }) } })),
      route("POST", new RegExp(`^/v1/organizations/(?<organizationId>${UUID})/agents$`), "admin", async ({ organizationId, body, idempotencyKey, principal }) => ({ status: 201, body: { agent: await mutateAndAudit(organizationId, (target) => target.createAgent({ ...body, organizationId, createdBy: principal.member_id, principalId: principal.member_id, idempotencyKey }), ({ mutation }) => ({ organizationId, eventType: "agent.created", actorId: principal.member_id, targetType: "agent", targetId: mutation.agent_id, idempotencyKey: `${idempotencyKey}:audit` })) } })),
      route("POST", new RegExp(`^/v1/organizations/(?<organizationId>${UUID})/agents/(?<agentId>${UUID})/revoke$`), "admin", async ({ organizationId, match, body, idempotencyKey, principal }) => {
        rejectUnknown(body, new Set(["reason"]), "agent_revocation");
        const revocation = await mutateAndAudit(organizationId,
          (target) => target.createRevocation({ organizationId, targetType: "agent", targetId: match.agentId, reason: body.reason, createdBy: principal.member_id, principalId: principal.member_id, idempotencyKey }),
          { organizationId, eventType: "agent.revoked", actorId: principal.member_id, targetType: "agent", targetId: match.agentId, idempotencyKey: `${idempotencyKey}:audit` });
        return { status: 201, body: { revocation } };
      }),
      route("POST", new RegExp(`^/v1/organizations/(?<organizationId>${UUID})/devices/(?<deviceId>${UUID})/revoke$`), "admin", async ({ organizationId, match, body, idempotencyKey, principal }) => {
        rejectUnknown(body, new Set(["reason"]), "device_revocation");
        const revocation = await mutateAndAudit(organizationId,
          (target) => target.createRevocation({ organizationId, targetType: "device", targetId: match.deviceId, reason: body.reason, createdBy: principal.member_id, principalId: principal.member_id, idempotencyKey }),
          { organizationId, eventType: "device.revoked", actorId: principal.member_id, targetType: "device", targetId: match.deviceId, idempotencyKey: `${idempotencyKey}:audit` });
        return { status: 201, body: { revocation } };
      }, false, false, "device.revoke"),
      route("GET", new RegExp(`^/v1/organizations/(?<organizationId>${UUID})/policies$`), "viewer", async ({ organizationId }) => ({ body: { policies: await store.listPolicies({ organizationId }) } })),
      route("POST", new RegExp(`^/v1/organizations/(?<organizationId>${UUID})/policies$`), "admin", async ({ organizationId, body, idempotencyKey, principal }) => ({ status: 201, body: { policy: await mutateAndAudit(organizationId, (target) => target.createPolicy({ ...body, organizationId, createdBy: principal.member_id, principalId: principal.member_id, idempotencyKey }), ({ mutation }) => ({ organizationId, eventType: "policy.created", actorId: principal.member_id, targetType: "policy", targetId: mutation.policy_id, idempotencyKey: `${idempotencyKey}:audit` })) } })),
      route("POST", new RegExp(`^/v1/organizations/(?<organizationId>${UUID})/policies/(?<policyId>${UUID})/disable$`), "admin", async ({ organizationId, match, body, idempotencyKey, principal }) => {
        rejectUnknown(body, new Set(["expected_version", "reason"]), "policy_disable");
        const policy = await mutateAndAudit(organizationId,
          (target) => target.updatePolicy({ organizationId, policyId: match.policyId, expectedVersion: body.expected_version, patch: { status: "disabled" }, createdBy: principal.member_id, principalId: principal.member_id, idempotencyKey }),
          { organizationId, eventType: "policy.disabled", actorId: principal.member_id, targetType: "policy", targetId: match.policyId, details: { reason: body.reason ?? "disabled_by_operator" }, idempotencyKey: `${idempotencyKey}:audit` });
        return { body: { policy } };
      }),
      route("GET", new RegExp(`^/v1/organizations/(?<organizationId>${UUID})/capabilities$`), "viewer", async ({ organizationId, url }) => ({ body: { capabilities: (await store.listCapabilities({ organizationId })).slice(-optionalLimit(url)).map(publicCapability) } })),
      route("POST", new RegExp(`^/v1/organizations/(?<organizationId>${UUID})/capabilities$`), "admin", async ({ organizationId, body, idempotencyKey, principal }) => {
        if (!capabilityAuthoritySigner) throw apiError("capability_signer_unavailable", 503, "Capability signer is unavailable");
        rejectUnknown(body, new Set(["capability_id", "agent_id", "device_id", "scope", "ttl_ms", "sequence"]), "capability");
        const ttlMs = body.ttl_ms ?? 15 * 60 * 1000;
        if (!Number.isSafeInteger(ttlMs) || ttlMs < 1_000 || ttlMs > 15 * 60 * 1000) throw apiError("invalid_capability_ttl", 400, "Capability TTL must be between 1 second and 15 minutes");
        const agents = await store.listAgents({ organizationId });
        const devices = await store.listDevices({ organizationId });
        const activePolicy = (await store.listPolicies({ organizationId })).filter((policy) => policy.status === "active").sort((left, right) => right.sequence - left.sequence)[0];
        if (!activePolicy) throw apiError("policy_missing", 409, "No active policy exists");
        const agent = agents.find((item) => item.agent_id === body.agent_id && item.status === "active");
        const device = devices.find((item) => item.device_id === body.device_id && item.status === "active");
        if (!agent || !device || (agent.device_id !== undefined && agent.device_id !== device.device_id)) throw apiError("capability_audience_unavailable", 404, "Capability audience is unavailable");
        if (!body.scope || typeof body.scope !== "object" || Array.isArray(body.scope)) throw apiError("invalid_capability_scope", 400, "Capability scope is required");
        let effectiveScope;
        try { effectiveScope = intersectScopes(activePolicy.scope, body.scope); }
        catch { throw apiError("invalid_capability_scope", 400, "Capability scope is invalid"); }
        const issuedAt = new Date(now()).toISOString();
        let signed;
        try { signed = await mutateAndAudit(organizationId, async (target) => {
          const reserved = await target.reserveCapability({ organizationId, ...(body.capability_id ? { capabilityId: body.capability_id } : {}), issuer: capabilityAuthoritySigner.issuer, keyId: capabilityAuthoritySigner.key_id, agentId: agent.agent_id, deviceId: device.device_id, scope: effectiveScope, sequence: body.sequence, ttlMs, issuedAt, createdBy: principal.member_id, principalId: principal.member_id, idempotencyKey });
          const statement = { version: 1, capability_id: reserved.capability_id, nonce: reserved.nonce, issuer: reserved.issuer, key_id: reserved.key_id, audience: { agent_id: reserved.agent_id, device_id: reserved.device_id }, scope: reserved.scope, not_before: reserved.not_before, expires_at: reserved.expires_at, sequence: reserved.sequence };
          const metadataTarget = typeof target.issueCapabilityMetadata === "function" ? target : capabilityAuthorityRepository;
          if (metadataTarget !== undefined) await metadataTarget.issueCapabilityMetadata({ organization_id: organizationId, capability_id: statement.capability_id, agent_id: statement.audience.agent_id, device_id: statement.audience.device_id, sequence: statement.sequence, statement_hash: crypto.createHash("sha256").update(canonicalJson(statement)).digest("hex"), expires_at: statement.expires_at, issued_by_member_id: principal.member_id });
          return signAndValidateCapability(capabilityAuthoritySigner, statement);
        }, ({ mutation }) => ({ organizationId, eventType: "capability.issued", actorId: principal.member_id, targetType: "capability", targetId: mutation.capability_id, details: { agent_id: agent.agent_id, device_id: device.device_id, expires_at: mutation.expires_at, sequence: mutation.sequence }, idempotencyKey: `${idempotencyKey}:audit` })); }
        catch (error) {
          if (error?.code === "ERR_MEMBER_NOT_ACTIVE" || error?.code === "ERR_MEMBERSHIP_VERSION") throw apiError("capability_issuer_not_active", 403, "Capability issuer membership is not active");
          if (error?.code === "ERR_DATABASE") throw apiError("capability_authority_unavailable", 503, "Capability authority state is unavailable");
          throw error;
        }
        return { status: 201, body: { capability: signed } };
      }),
      route("POST", new RegExp(`^/v1/organizations/(?<organizationId>${UUID})/capabilities/(?<capabilityId>${UUID})/revoke$`), "admin", async ({ organizationId, match, body, idempotencyKey, principal }) => {
        rejectUnknown(body, new Set(["reason"]), "capability_revocation");
        const revocation = await mutateAndAudit(organizationId,
          (target) => target.createRevocation({ organizationId, targetType: "capability", targetId: match.capabilityId, reason: body.reason, createdBy: principal.member_id, principalId: principal.member_id, idempotencyKey }),
          { organizationId, eventType: "capability.revoked", actorId: principal.member_id, targetType: "capability", targetId: match.capabilityId, idempotencyKey: `${idempotencyKey}:audit` });
        return { status: 201, body: { revocation } };
      }),
      route("GET", new RegExp(`^/v1/organizations/(?<organizationId>${UUID})/revocations$`), "viewer", async ({ organizationId, url }) => ({ body: { revocations: (await store.listRevocations({ organizationId })).slice(-optionalLimit(url)) } })),
      route("GET", new RegExp(`^/v1/organizations/(?<organizationId>${UUID})/audit/events$`), "auditor", async ({ organizationId, url }) => {
        requireExactQueryKeys(url, new Set(["device_id", "cursor", "limit"]));
        const page = await activitySource.listDeviceAuditEvents({ organizationId, deviceId: requiredUuidQuery(url, "device_id"), cursor: optionalQuery(url, "cursor"), limit: optionalLimit(url) });
        if (!page || typeof page !== "object" || !Array.isArray(page.events) || (page.next_cursor !== null && typeof page.next_cursor !== "string")) throw new Error("audit repository returned an invalid page");
        return { body: { events: page.events, next_cursor: page.next_cursor } };
      }),
      route("GET", new RegExp(`^/v1/organizations/(?<organizationId>${UUID})/audit/admin-events$`), "auditor", async ({ organizationId, url }) => ({ body: { events: await store.listAdminAuditEvents({ organizationId, limit: optionalLimit(url) }) } })),
      route("GET", new RegExp(`^/v1/organizations/(?<organizationId>${UUID})/audit/health$`), "auditor", async ({ organizationId }) => ({ body: { health: await store.getAuditHealth({ organizationId }) } })),
      route("POST", new RegExp(`^/v1/organizations/(?<organizationId>${UUID})/audit/events$`), null, async ({ organizationId, principal, body }) => {
        rejectUnknown(body, new Set(["batch_id", "events"]), "audit_ingestion");
        return { status: 202, body: { ingestion: await store.ingestDeviceAuditEvents({ organizationId, deviceId: principal.device_id, events: body.events, idempotencyKey: body.batch_id ?? crypto.randomUUID() }) } };
      }, true),
      route("GET", new RegExp(`^/v1/organizations/(?<organizationId>${UUID})/devices/(?<deviceId>${UUID})/refresh$`), null, async ({ organizationId, principal, match, url, request }) => {
        if (principal.device_id !== match.deviceId) throw apiError("audience_mismatch", 403, "Device cannot poll another device's refresh state");
        if (!refreshHintService) throw apiError("refresh_unavailable", 503, "Refresh polling is unavailable");
        requireExactQueryKeys(url, new Set(["after_generation", "wait_ms"]));
        const afterGeneration = optionalBoundedIntegerQuery(url, "after_generation", 0, Number.MAX_SAFE_INTEGER, 0);
        const waitMs = optionalBoundedIntegerQuery(url, "wait_ms", 0, 30_000, 0);
        const abort = new AbortController();
        const previousSocketTimeout = request.socket?.timeout;
        if (request.socket && waitMs > 10_000) request.socket.setTimeout(waitMs + 5_000);
        const disconnected = () => abort.abort();
        request.once("aborted", disconnected);
        request.once("close", disconnected);
        let result;
        try {
          result = await refreshHintService.poll({ organization_id: organizationId, device_id: match.deviceId, after_generation: afterGeneration, wait_ms: waitMs, signal: abort.signal });
        } finally {
          request.off("aborted", disconnected);
          request.off("close", disconnected);
          if (request.socket && Number.isFinite(previousSocketTimeout)) request.socket.setTimeout(previousSocketTimeout);
        }
        if (result === null || result === undefined) return { status: 204, body: undefined };
        const hint = validateRefreshHintResponse(result, { organizationId, deviceId: match.deviceId, afterGeneration, now: now() });
        return { body: { hint } };
      }, true),
      route("GET", new RegExp(`^/v1/organizations/(?<organizationId>${UUID})/devices/(?<deviceId>${UUID})/enrollment-receipt$`), null, async ({ organizationId, principal, match, url }) => {
        if (url.search || principal.device_id !== match.deviceId) throw apiError("audience_mismatch", 403, "Device cannot fetch another device's enrollment receipt");
        const readReceipt = store.getDevicePossessionReceipt ?? store.getDeviceEnrollmentPossessionReceipt;
        if (typeof readReceipt !== "function") throw apiError("possession_receipt_unavailable", 503, "Possession receipt is unavailable");
        const receipt = validatePossessionReceiptResponse(await readReceipt.call(store, { organizationId, deviceId: match.deviceId }), { organizationId, deviceId: match.deviceId });
        return { body: { receipt } };
      }, true),
      route("GET", new RegExp(`^/v1/organizations/(?<organizationId>${UUID})/bundles/(?<deviceId>${UUID})$`), null, async ({ organizationId, principal, match }) => {
        if (principal.device_id !== match.deviceId) throw apiError("audience_mismatch", 403, "Device cannot fetch another device's bundle");
        if (!controlBundleSigner) throw apiError("bundle_signer_unavailable", 503, "Bundle signer is unavailable");
        const issuedMs = now();
        const ttlMs = controlBundleSigner.ttlMs ?? 3_600_000;
        if (typeof store.snapshotAndAssignBundleHead === "function") {
          let preparedStatement;
          const authority = await store.snapshotAndAssignBundleHead({
            organizationId,
            deviceId: match.deviceId,
            minimumSequence: 1,
            issuedAt: new Date(issuedMs).toISOString(),
            expiresAt: new Date(issuedMs + ttlMs).toISOString(),
            statementHashFactory: ({ snapshot, head }) => {
              preparedStatement = {
                format_epoch: 2, issuer: controlBundleSigner.issuer, organization_id: organizationId, device_id: match.deviceId,
                audience: { organization_id: organizationId, device_id: match.deviceId }, issued_at: head.issued_at,
                expires_at: head.expires_at, sequence: head.sequence, policy_scope: snapshot.policy_scope,
                global_revoked: snapshot.global_revoked, revoked_devices: snapshot.revoked_devices,
                revoked_agents: snapshot.revoked_agents, revoked_capabilities: snapshot.revoked_capabilities,
                offline_ttl_ms: controlBundleSigner.offlineTtlMs ?? 3_600_000, key_id: controlBundleSigner.key_id
              };
              return controlBundleStatementHash(preparedStatement);
            }
          });
          const { head } = authority;
          if (!preparedStatement || preparedStatement.sequence !== head.sequence) throw apiError("bundle_statement_unavailable", 503, "Bundle statement is unavailable");
          const bundle = await signAndValidateControlBundle(controlBundleSigner, preparedStatement, {
            now: issuedMs,
            maxTtlMs: ttlMs,
            maxOfflineTtlMs: controlBundleSigner.offlineTtlMs ?? 3_600_000,
            audience: { organization_id: organizationId, device_id: match.deviceId }
          });
          if (controlBundleStatementHash(bundle) !== head.state_fingerprint) throw apiError("bundle_statement_mismatch", 503, "Bundle statement is unavailable");
          return { body: { bundle, desired_generation: positiveGeneration(authority.desired_generation ?? head.sequence) } };
        }
        const policies = await store.listPolicies({ organizationId });
        const active = policies.filter((policy) => policy.status === "active").sort((a, b) => b.sequence - a.sequence)[0];
        if (!active) throw apiError("policy_missing", 409, "No active policy exists");
        const revocations = await store.listRevocations({ organizationId });
        const storedCapabilityRevocations = revocations.filter((item) => item.target_type === "capability" && item.status === "active").map((item) => item.target_id);
        let durableCapabilityRevocations = [];
        if (capabilityRevocationSource !== undefined) {
          try {
            durableCapabilityRevocations = await capabilityRevocationSource.listRevokedCapabilityIds({ organization_id: organizationId, evaluated_at: new Date(issuedMs).toISOString() });
          } catch {
            throw apiError("capability_revocations_unavailable", 503, "Capability revocation state is unavailable");
          }
          if (!Array.isArray(durableCapabilityRevocations) || durableCapabilityRevocations.some((id) => typeof id !== "string" || !UUID_VALUE.test(id))) {
            throw apiError("capability_revocations_unavailable", 503, "Capability revocation state is unavailable");
          }
        }
        const revokedCapabilities = [...new Set([...storedCapabilityRevocations, ...durableCapabilityRevocations])].sort();
        if (revokedCapabilities.length > MAX_REVOCATIONS) throw apiError("capability_revocations_overflow", 503, "Capability revocation state exceeds the ControlBundle limit");
        const stateFingerprint = crypto.createHash("sha256").update(JSON.stringify({ device_id: match.deviceId, policy_id: active.policy_id, policy_sequence: active.sequence, policy_scope: active.scope, revocations: revocations.filter((item) => item.target_type !== "capability").map((item) => [item.revocation_id, item.target_type, item.target_id, item.status]).sort(), revoked_capabilities: revokedCapabilities })).digest("hex");
        const head = await store.assignBundleHead({ organizationId, deviceId: match.deviceId, stateFingerprint, minimumSequence: active.sequence, issuedAt: new Date(issuedMs).toISOString(), expiresAt: new Date(issuedMs + ttlMs).toISOString() });
        const statement = {
            format_epoch: 2,
            issuer: controlBundleSigner.issuer,
            organization_id: organizationId,
            device_id: match.deviceId,
            audience: { organization_id: organizationId, device_id: match.deviceId },
            issued_at: head.issued_at,
            expires_at: head.expires_at,
            sequence: head.sequence,
            policy_scope: active.scope,
            global_revoked: revocations.some((item) => item.target_type === "organization" && item.status === "active"),
            revoked_devices: revocations.filter((item) => item.target_type === "device" && item.status === "active").map((item) => item.target_id).sort(),
            revoked_agents: revocations.filter((item) => item.target_type === "agent" && item.status === "active").map((item) => item.target_id).sort(),
            revoked_capabilities: revokedCapabilities,
            offline_ttl_ms: controlBundleSigner.offlineTtlMs ?? 3_600_000,
            key_id: controlBundleSigner.key_id
          };
        const bundle = await signAndValidateControlBundle(controlBundleSigner, statement, {
          now: issuedMs,
          maxTtlMs: ttlMs,
          maxOfflineTtlMs: controlBundleSigner.offlineTtlMs ?? 3_600_000,
          audience: { organization_id: organizationId, device_id: match.deviceId }
        });
        return { body: { bundle, desired_generation: positiveGeneration(head.desired_generation ?? head.sequence) } };
      }, true),
      route("POST", new RegExp(`^/v1/organizations/(?<organizationId>${UUID})/bundles/(?<deviceId>${UUID})/acknowledgements$`), null, async ({ organizationId, principal, match, bodyBytes }) => {
        if (principal.device_id !== match.deviceId) throw apiError("audience_mismatch", 403, "Device cannot acknowledge another device's bundle");
        if (typeof store.acknowledgeBundle !== "function") throw apiError("acknowledgement_unavailable", 503, "Bundle acknowledgement is unavailable");
        let acknowledgement;
        try { acknowledgement = parseBundleAcknowledgementJson(bodyBytes); }
        catch { throw apiError("invalid_acknowledgement", 400, "Bundle acknowledgement is invalid"); }
        if (acknowledgement.organization_id !== organizationId || acknowledgement.device_id !== match.deviceId) {
          throw apiError("acknowledgement_binding_mismatch", 400, "Bundle acknowledgement binding is invalid");
        }
        if (!Number.isSafeInteger(principal.key_epoch) || principal.key_epoch < 1 || acknowledgement.device_key_epoch !== principal.key_epoch) {
          throw apiError("acknowledgement_key_epoch_mismatch", 409, "Bundle acknowledgement key epoch is stale");
        }
        verifyBundleAcknowledgementSignature(acknowledgement, principal.authentication_public_key);
        const accepted = await store.acknowledgeBundle(acknowledgement);
        if (!accepted || typeof accepted !== "object" || Array.isArray(accepted)
          || typeof accepted.duplicate !== "boolean" || !Number.isSafeInteger(accepted.observed_generation) || accepted.observed_generation < 1
          || !new Set(["pending", "fetching", "applied", "blocked", "stale", "offline", "revoked"]).has(accepted.refresh_state)) {
          throw apiError("acknowledgement_unavailable", 503, "Bundle acknowledgement is unavailable");
        }
        return { status: 202, body: { accepted: true, duplicate: accepted.duplicate, observed_generation: accepted.observed_generation, refresh_state: accepted.refresh_state } };
      }, true),
      route("POST", new RegExp(`^/v1/organizations/(?<organizationId>${UUID})/emergency-stop$`), "owner", async ({ organizationId, body, idempotencyKey, principal }) => {
        rejectUnknown(body, new Set(["reason"]), "emergency_stop");
        const revocation = await mutateAndAudit(organizationId,
          (target) => target.createRevocation({ organizationId, targetType: "organization", targetId: organizationId, reason: body.reason, createdBy: principal.member_id, principalId: principal.member_id, idempotencyKey }),
          { organizationId, eventType: "organization.emergency_stop", actorId: principal.member_id, targetType: "organization", targetId: organizationId, idempotencyKey: `${idempotencyKey}:audit` });
        return { status: 201, body: { revocation } };
      }, false, false, "organization.emergency_stop")
    ];
  }
}

function isExactHumanAuthPath(url, method = undefined) {
  if (url.hash) return false;
  if (HUMAN_AGENT_SESSION_GRANT_PATH.test(url.pathname)) return true;
  if (HUMAN_QUALIFICATION_GRANT_BATCH_PATH.test(url.pathname)) return true;
  if (!url.search && (url.pathname === HUMAN_AUTH_SESSION_PATH || url.pathname === HUMAN_AUTH_SESSION_SWITCH_PATH || url.pathname === HUMAN_AUTH_OPTIONS_PATH || url.pathname === HUMAN_AUTH_VERIFY_PATH || url.pathname === HUMAN_AUTH_REGISTRATION_OPTIONS_PATH || url.pathname === HUMAN_AUTH_REGISTRATION_VERIFY_PATH)) return true;
  if (isExactHumanOrganizationPath(url, method)) return true;
  return /^\/api\/auth\/management\/(?:credentials(?:\/[A-Za-z0-9_-]+(?:\/revoke)?)?|sessions(?:\/[0-9a-fA-F-]{36}\/revoke)?)$/.test(url.pathname);
}

function isExactHumanOrganizationPath(url, method) {
  if (url.hash) return false;
  if (url.pathname === HUMAN_AUTH_ACCEPT_INVITATION_PATH) return !url.search;
  const organizationPath = new RegExp(`^${HUMAN_AUTH_ORGANIZATIONS_PATH}(?:/${HUMAN_AUTH_UUID}(?:/members(?:/${HUMAN_AUTH_UUID}/(?:role|remove))?|/invitations(?:/${HUMAN_AUTH_UUID}/revoke)?)?)?$`);
  if (!organizationPath.test(url.pathname)) return false;
  const requestMethod = String(method ?? "").toUpperCase();
  const list = requestMethod === "GET" && (url.pathname === HUMAN_AUTH_ORGANIZATIONS_PATH || new RegExp(`^${HUMAN_AUTH_ORGANIZATIONS_PATH}/${HUMAN_AUTH_UUID}/(?:members|invitations)$`).test(url.pathname));
  return !url.search || list;
}

function transportPrincipalId(request) {
  return crypto.createHash("sha256").update(String(request.socket?.remoteAddress ?? "unknown")).digest("hex");
}

async function acquireRateLimit(limiter, input) {
  try {
    const decision = await limiter.acquire(input);
    if (!decision || typeof decision !== "object" || typeof decision.allowed !== "boolean" || !Number.isSafeInteger(decision.limit) || decision.limit < 1 || !Number.isSafeInteger(decision.remaining) || decision.remaining < 0 || decision.remaining > decision.limit || !Number.isSafeInteger(decision.retryAfterSeconds) || decision.retryAfterSeconds < 0 || !Number.isSafeInteger(decision.resetAt) || decision.resetAt < 0) throw new Error("invalid rate limiter decision");
    return decision;
  } catch (error) {
    if (error?.code === "RATE_LIMITER_CAPACITY_EXHAUSTED") throw error;
    throw apiError("rate_limiter_unavailable", 503, "Rate limiter is temporarily unavailable", { "Retry-After": "1" });
  }
}

function normalizeHumanAuthResult(result) {
  try {
    if (!result || typeof result !== "object" || Array.isArray(result) || !Number.isSafeInteger(result.status) || result.status < 200 || result.status > 599) return undefined;
    if (!result.body || typeof result.body !== "object" || Array.isArray(result.body)) return undefined;
    const encoded = Buffer.from(canonicalJson(result.body), "utf8");
    if (encoded.length > HUMAN_AUTH_MAX_BODY_BYTES) return undefined;
    if (!result.headers || typeof result.headers !== "object" || Array.isArray(result.headers)) return undefined;
    const headerPrototype = Object.getPrototypeOf(result.headers);
    if (headerPrototype !== Object.prototype && headerPrototype !== null) return undefined;
    const headers = {};
    for (const [name, value] of Object.entries(result.headers)) {
      if (!/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(name) || typeof value !== "string" || value.length > 8192 || /[\u0000-\u001f\u007f]/.test(value)) return undefined;
      const normalizedName = name.toLowerCase();
      if (headers[normalizedName] !== undefined || new Set(["connection", "content-length", "keep-alive", "transfer-encoding", "upgrade"]).has(normalizedName)) return undefined;
      headers[normalizedName] = value;
    }
    if (headers["content-type"] !== undefined && !/^application\/json(?:\s*;|$)/i.test(headers["content-type"])) return undefined;
    headers["content-type"] ??= "application/json; charset=utf-8";
    headers["cache-control"] = "no-store";
    headers["content-length"] = String(encoded.length);
    return { status: result.status, encoded, headers };
  } catch {
    return undefined;
  }
}

function normalizePlatformPromotionResult(result) {
  try {
    if (!result || typeof result !== "object" || Array.isArray(result) || !Number.isSafeInteger(result.status) || result.status < 200 || result.status > 599
      || !result.body || typeof result.body !== "object" || Array.isArray(result.body)) return undefined;
    const responseBody = { ...result.body };
    if (result.request_id !== undefined) responseBody.request_id = result.request_id;
    const encoded = Buffer.from(canonicalJson(responseBody), "utf8");
    if (encoded.length > 256 * 1024) return undefined;
    const headers = {};
    if (result.headers !== undefined && (!result.headers || typeof result.headers !== "object" || Array.isArray(result.headers))) return undefined;
    for (const [name, value] of Object.entries(result.headers ?? {})) {
      if (!/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/u.test(name) || typeof value !== "string" || value.length > 8192 || /[\u0000-\u001f\u007f]/u.test(value)) return undefined;
      const normalizedName = name.toLowerCase();
      if (headers[normalizedName] !== undefined || new Set(["connection", "content-length", "keep-alive", "transfer-encoding", "upgrade"]).has(normalizedName)) return undefined;
      headers[normalizedName] = value;
    }
    headers["content-type"] ??= "application/json; charset=utf-8";
    headers["cache-control"] = "no-store";
    headers["content-length"] = String(encoded.length);
    return { status: result.status, encoded, headers };
  } catch { return undefined; }
}

function normalizeAgentSessionDeviceResult(result) {
  try {
    if (!result || typeof result !== "object" || Array.isArray(result) || !Number.isSafeInteger(result.status) || result.status < 200 || result.status > 599) return undefined;
    if (!result.body || typeof result.body !== "object" || Array.isArray(result.body)) return undefined;
    const encoded = Buffer.from(canonicalJson(result.body), "utf8");
    if (encoded.length > MAX_BODY_BYTES) return undefined;
    const suppliedHeaders = result.headers ?? {};
    if (!suppliedHeaders || typeof suppliedHeaders !== "object" || Array.isArray(suppliedHeaders)) return undefined;
    const headerPrototype = Object.getPrototypeOf(suppliedHeaders);
    if (headerPrototype !== Object.prototype && headerPrototype !== null) return undefined;
    const headers = {};
    const forbidden = new Set(["connection", "content-length", "keep-alive", "transfer-encoding", "upgrade"]);
    for (const [name, value] of Object.entries(suppliedHeaders)) {
      if (!/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(name) || typeof value !== "string" || value.length > 8192 || /[\u0000-\u001f\u007f]/.test(value)) return undefined;
      const normalizedName = name.toLowerCase();
      if (headers[normalizedName] !== undefined || forbidden.has(normalizedName)) return undefined;
      headers[normalizedName] = value;
    }
    if (headers["content-type"] !== undefined && !/^application\/json(?:\s*;|$)/i.test(headers["content-type"])) return undefined;
    headers["content-type"] ??= "application/json; charset=utf-8";
    headers["cache-control"] ??= "no-store";
    headers["content-length"] = String(encoded.length);
    return { status: result.status, encoded, headers };
  } catch {
    return undefined;
  }
}

function mergeResponseHeaders(...sets) {
  const merged = {};
  for (const set of sets) for (const [name, value] of Object.entries(set)) merged[name.toLowerCase()] = value;
  return merged;
}

function sendRawJson(response, status, encoded, headers = {}) {
  response.writeHead(status, headers);
  response.end(encoded);
}

function bearerToken(value) {
  if (typeof value !== "string" || !/^Bearer [^\s]{16,512}$/.test(value)) throw apiError("invalid_api_token", 401, "API token is invalid");
  return value.slice(7);
}

function idempotencyKey(request, route) {
  if (!["POST", "PUT", "PATCH", "DELETE"].includes(request.method) || route.device || route.enrollment) return undefined;
  const value = request.headers["idempotency-key"];
  if (typeof value !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$/.test(value)) throw apiError("idempotency_key_required", 400, "A valid Idempotency-Key is required");
  return value;
}

async function requireRecentWebAuthn({ verifier, principal, proof, organizationId, operation, now }) {
  if (typeof verifier !== "function") throw apiError("recent_auth_unavailable", 503, "Recent WebAuthn verification is unavailable");
  if (typeof proof !== "string" || !UUID_VALUE.test(proof) || proof !== proof.toLowerCase()) throw apiError("recent_auth_required", 401, "Recent WebAuthn authentication is required");
  let result;
  try { result = await verifier({ proof, principal: { ...principal }, organization_id: organizationId, operation, now }); }
  catch { throw apiError("recent_auth_failed", 401, "Recent WebAuthn authentication failed"); }
  const expectedKeys = ["authenticated_at", "challenge_id", "consumed", "member_id", "operation", "organization_id", "verified"];
  if (!result || typeof result !== "object" || Array.isArray(result) || Object.keys(result).sort().join(",") !== expectedKeys.sort().join(",") || result.verified !== true || result.consumed !== true || result.challenge_id !== proof || result.member_id !== principal.member_id || result.organization_id !== organizationId || result.operation !== operation) {
    throw apiError("recent_auth_failed", 401, "Recent WebAuthn authentication failed");
  }
  const authenticatedAt = typeof result.authenticated_at === "string" ? Date.parse(result.authenticated_at) : result.authenticated_at;
  if (!Number.isSafeInteger(authenticatedAt) || authenticatedAt > now + 30_000 || now - authenticatedAt > 5 * 60_000) throw apiError("recent_auth_stale", 401, "Recent WebAuthn authentication is stale");
}

async function requireAuditExportRecentAuth({ verifier, principal, proof, organizationId, operation, contextHash, now }) {
  if (typeof verifier !== "function") throw apiError("recent_auth_unavailable", 503, "Recent WebAuthn verification is unavailable");
  if (typeof proof !== "string" || !UUID_VALUE.test(proof)) throw apiError("recent_auth_required", 401, "Recent WebAuthn authentication is required");
  let result;
  try {
    result = await verifier({ proof, principal: { ...principal }, organization_id: organizationId, operation, context_hash: contextHash, now });
  } catch {
    throw apiError("recent_auth_failed", 401, "Recent WebAuthn authentication failed");
  }
  const expectedKeys = ["authenticated_at", "challenge_id", "consumed", "context_hash", "member_id", "operation", "organization_id", "verified"];
  if (!result || typeof result !== "object" || Array.isArray(result)
    || Object.keys(result).sort().join(",") !== expectedKeys.sort().join(",")
    || result.verified !== true || result.consumed !== true || result.challenge_id !== proof.toLowerCase()
    || result.member_id !== principal.member_id || result.organization_id !== organizationId
    || result.operation !== operation || result.context_hash !== contextHash) {
    throw apiError("recent_auth_failed", 401, "Recent WebAuthn authentication failed");
  }
  const authenticatedAt = typeof result.authenticated_at === "string" ? Date.parse(result.authenticated_at) : result.authenticated_at;
  if (!Number.isSafeInteger(authenticatedAt) || authenticatedAt > now + 30_000 || now - authenticatedAt > 5 * 60_000) {
    throw apiError("recent_auth_stale", 401, "Recent WebAuthn authentication is stale");
  }
}

function mapAuditExportServiceError(error, create) {
  const code = String(error?.code ?? "").toLowerCase();
  if (!create && ["not_found", "absent", "in_progress", "uncertain", "organization_mismatch"].some((value) => code.includes(value))) {
    return apiError("not_found", 404, "Resource not found");
  }
  if (create && code.includes("conflict")) return apiError("idempotency_conflict", 409, "Mutation conflict");
  if (create && code.includes("in_progress")) return apiError("audit_export_in_progress", 409, "Audit export is in progress");
  if (create && code.includes("uncertain")) return apiError("audit_export_uncertain", 503, "Audit export outcome is uncertain");
  if (code.includes("input") || code.includes("binding")) return apiError("invalid_audit_export_request", 400, "Audit export request is invalid");
  return apiError("audit_export_unavailable", 503, "Audit export is unavailable");
}

function normalizeAuditExportPublicResult(value, expected) {
  try {
    const keys = ["organization_id", "export_id", "environment", "chain", "range", "payload_digest", "payload", "audit_anchor", "replayed", "validity"];
    if (!value || typeof value !== "object" || Array.isArray(value)
      || Object.keys(value).sort().join(",") !== keys.sort().join(",")
      || value.organization_id !== expected.organizationId || value.export_id !== expected.exportId
      || value.environment !== expected.environment || value.chain !== expected.chain
      || typeof value.payload_digest !== "string" || !SHA256_HEX.test(value.payload_digest)
      || typeof value.replayed !== "boolean" || !["active", "expired"].includes(value.validity)) throw new Error("identity");
    assertSafeAuditExportTree(value);
    const cloned = structuredClone(value);
    if (Buffer.byteLength(canonicalJson(cloned), "utf8") > 256 * 1024) throw new Error("size");
    const { replayed: _replayed, ...publicValue } = cloned;
    return publicValue;
  } catch {
    throw apiError("audit_export_unavailable", 503, "Audit export is unavailable");
  }
}

function normalizeAuditExportVerifyInput(value, organizationId) {
  try {
    const keys = ["organization_id", "export_id", "environment", "chain", "range", "payload_digest", "payload", "audit_anchor", "validity"];
    if (!value || typeof value !== "object" || Array.isArray(value)
      || Object.keys(value).sort().join(",") !== keys.sort().join(",")
      || value.organization_id !== organizationId || !canonicalUuid(value.export_id)
      || !["staging", "production"].includes(value.environment)
      || !["admin", "device", "cloud_agent"].includes(value.chain)
      || typeof value.payload_digest !== "string" || !SHA256_HEX.test(value.payload_digest)
      || !["active", "expired"].includes(value.validity)) throw new Error("identity");
    assertSafeAuditExportTree(value);
    const cloned = structuredClone(value);
    if (Buffer.byteLength(canonicalJson(cloned), "utf8") > 256 * 1024) throw new Error("size");
    assertAuditExportPublicStructure(cloned);
    return cloned;
  } catch {
    throw apiError("invalid_audit_export_request", 400, "Audit export request is invalid");
  }
}

function assertAuditExportPublicStructure(value) {
  const range = value.range;
  const payload = value.payload;
  if (!range || typeof range !== "object" || Array.isArray(range)
    || Object.keys(range).sort().join(",") !== ["from_audit_position", "to_audit_position", "previous_root_digest", "root_digest", "record_count"].sort().join(",")
    || !Number.isSafeInteger(range.from_audit_position) || range.from_audit_position < 1
    || !Number.isSafeInteger(range.to_audit_position) || range.to_audit_position < range.from_audit_position
    || !Number.isSafeInteger(range.record_count) || range.record_count < 1 || range.record_count > 100
    || !SHA256_HEX.test(range.previous_root_digest) || !SHA256_HEX.test(range.root_digest)
    || range.to_audit_position - range.from_audit_position + 1 !== range.record_count) throw new Error("range");
  if (!payload || typeof payload !== "object" || Array.isArray(payload)
    || payload.organization_id !== value.organization_id || payload.environment !== value.environment || payload.chain !== value.chain
    || canonicalJson(payload.range) !== canonicalJson(range) || !Array.isArray(payload.entries)
    || payload.entries.length !== range.record_count) throw new Error("payload");
  if (!value.audit_anchor || typeof value.audit_anchor !== "object" || Array.isArray(value.audit_anchor)
    || !value.audit_anchor.statement || typeof value.audit_anchor.statement !== "object" || Array.isArray(value.audit_anchor.statement)) throw new Error("anchor");
}

function assertAuditExportPublicIntegrity(value) {
  assertAuditExportPublicStructure(value);
  if (crypto.createHash("sha256").update(canonicalJson(value.payload), "utf8").digest("hex") !== value.payload_digest) throw new Error("digest");
  let root = value.range.previous_root_digest;
  for (const entry of value.payload.entries) root = foldAuditExportRoot(root, canonicalAuditExportEntry(entry));
  if (root !== value.range.root_digest) throw new Error("root");
  const statement = value.audit_anchor.statement;
  if (statement.organization_id !== value.organization_id || statement.export_id !== value.export_id
    || statement.environment !== value.environment || statement.chain !== value.chain
    || statement.audit_position !== value.range.to_audit_position
    || statement.previous_audit_position !== value.range.from_audit_position - 1
    || statement.root_digest !== value.range.root_digest || statement.previous_root_digest !== value.range.previous_root_digest
    || statement.export_digest !== value.payload_digest || statement.record_count !== value.range.record_count) throw new Error("anchor");
}

function normalizeAuditExportVerificationResult(value) {
  try {
    const keys = ["payload_digest", "root", "anchor", "historical_key", "valid", "reason"];
    if (!value || typeof value !== "object" || Array.isArray(value)
      || Object.keys(value).sort().join(",") !== keys.sort().join(",")
      || ["payload_digest", "root", "anchor", "historical_key", "valid"].some((key) => typeof value[key] !== "boolean")
      || !["valid", "invalid_export", "payload_digest_mismatch", "root_mismatch", "anchor_invalid", "historical_key_unavailable"].includes(value.reason)
      || value.valid !== (value.payload_digest && value.root && value.anchor && value.historical_key)
      || (value.valid && value.reason !== "valid")) throw new Error("result");
    return Object.freeze({ ...value });
  } catch {
    throw apiError("audit_export_unavailable", 503, "Audit export is unavailable");
  }
}

function assertSafeAuditExportTree(value, seen = new Set(), depth = 0) {
  if (depth > 32 || value === null || !["object", "string", "number", "boolean"].includes(typeof value)) {
    if (value === null || ["string", "number", "boolean"].includes(typeof value)) return;
    throw new Error("tree");
  }
  if (typeof value !== "object") return;
  if (seen.has(value)) throw new Error("cycle");
  seen.add(value);
  const prototype = Object.getPrototypeOf(value);
  if (!Array.isArray(value) && prototype !== Object.prototype && prototype !== null) throw new Error("prototype");
  if (Array.isArray(value)) {
    for (const item of value) assertSafeAuditExportTree(item, seen, depth + 1);
    seen.delete(value);
    return;
  }
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key !== "string" || /(?:private[_-]?key|claim[_-]?token|provider[_-]?diagnostic|signing[_-]?bytes|raw[_-]?signature|password)/iu.test(key)) throw new Error("private");
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !("value" in descriptor) || !descriptor.enumerable) throw new Error("descriptor");
    assertSafeAuditExportTree(descriptor.value, seen, depth + 1);
  }
  seen.delete(value);
}

function validateEnrollmentPublicKey(algorithm, pem) {
  if (typeof pem !== "string" || Buffer.byteLength(pem) > 8192 || /PRIVATE\s+KEY/i.test(pem)) throw apiError("invalid_device_key", 400, "Device public key is invalid");
  let key;
  try { key = crypto.createPublicKey(pem); } catch { throw apiError("invalid_device_key", 400, "Device public key is invalid"); }
  const valid = algorithm === "ed25519"
    ? key.asymmetricKeyType === "ed25519"
    : algorithm === "p256-sha256" && key.asymmetricKeyType === "ec" && key.asymmetricKeyDetails?.namedCurve === "prime256v1";
  if (!valid) throw apiError("invalid_device_key", 400, "Device key algorithm does not match the public key");
  const canonical = key.export({ type: "spki", format: "pem" }).toString();
  if (canonical !== pem) throw apiError("invalid_device_key", 400, "Device public key must use canonical SPKI PEM encoding");
}

function deriveEnrollmentCredential(secret, identity) {
  return crypto.createHmac("sha256", secret)
    .update("AgentPass-Enrollment-Credential-v1\0", "utf8")
    .update(canonicalJson(identity), "utf8")
    .digest("base64url");
}

function validateEnrollmentProof(requestPath, body, algorithm, pem, credential, encodedSignature) {
  if (typeof encodedSignature !== "string" || !/^(?:[A-Za-z0-9+/]{4}){21}(?:[A-Za-z0-9+/]{2}==)$/.test(encodedSignature)) throw apiError("invalid_enrollment_proof", 401, "Device enrollment proof is invalid");
  const signature = Buffer.from(encodedSignature, "base64");
  if (signature.length !== 64 || signature.toString("base64") !== encodedSignature) throw apiError("invalid_enrollment_proof", 401, "Device enrollment proof is invalid");
  const digest = crypto.createHash("sha256").update(body).digest("hex");
  const credentialDigest = crypto.createHash("sha256").update(credential).digest("hex");
  const proof = Buffer.from(["AgentPass-Enrollment-Proof-v1", "POST", requestPath, digest, credentialDigest].join("\n"), "utf8");
  const key = crypto.createPublicKey(pem);
  let valid = false;
  try {
    valid = algorithm === "ed25519"
      ? crypto.verify(null, proof, key, signature)
      : crypto.verify("sha256", proof, { key, dsaEncoding: "ieee-p1363" }, signature);
  } catch { valid = false; }
  if (!valid) throw apiError("invalid_enrollment_proof", 401, "Device enrollment proof is invalid");
}

function validateV2IssueBody(body) {
  rejectUnknown(body, new Set(["proof_version", "candidate_id", "device_key_fingerprint", "enrollment_id", "device_id", "label", "platform", "ttl_ms"]), "device_enrollment_issue_v2");
  if (body.proof_version !== 2 || !SAFE_CANDIDATE_ID.test(body.candidate_id ?? "") || !DEVICE_FINGERPRINT.test(body.device_key_fingerprint ?? "")
    || (body.enrollment_id !== undefined && !canonicalUuid(body.enrollment_id)) || (body.device_id !== undefined && !canonicalUuid(body.device_id))
    || !boundedEnrollmentLabel(body.label) || (body.platform !== undefined && body.platform !== "macos")
    || (body.ttl_ms !== undefined && (!Number.isSafeInteger(body.ttl_ms) || body.ttl_ms < 60_000 || body.ttl_ms > 24 * 60 * 60 * 1000))) {
    throw apiError("invalid_enrollment", 400, "Device enrollment request is invalid");
  }
}

function validateV2CompletionBody(body, enrollmentId) {
  rejectUnknown(body, V2_COMPLETION_KEYS, "device_enrollment_v2");
  if (body.version !== 2 || body.proof_version !== 2 || body.enrollment_id !== enrollmentId || !canonicalUuid(body.organization_id) || !canonicalUuid(body.device_id)
    || !boundedEnrollmentLabel(body.label) || body.platform !== "macos" || !SAFE_CANDIDATE_ID.test(body.candidate_id ?? "")
    || !DEVICE_FINGERPRINT.test(body.device_key_fingerprint ?? "") || !body.device_key || typeof body.device_key !== "object" || Array.isArray(body.device_key)) {
    throw apiError("invalid_enrollment", 400, "Device enrollment request is invalid");
  }
  rejectUnknown(body.device_key, new Set(["algorithm", "spki_pem"]), "device_key");
  if (body.device_key.algorithm !== "p256-sha256" || typeof body.device_key.spki_pem !== "string") throw apiError("invalid_device_key", 400, "Device public key is invalid");
  const challenge = body.challenge;
  if (!challenge || typeof challenge !== "object" || Array.isArray(challenge)) throw apiError("invalid_enrollment", 400, "Device enrollment request is invalid");
  rejectUnknown(challenge, V2_CHALLENGE_KEYS, "enrollment_challenge");
  if (!canonicalUuid(challenge.challenge_id) || !BASE64URL_32.test(challenge.nonce) || Buffer.from(challenge.nonce, "base64url").length !== 32
    || Buffer.from(challenge.nonce, "base64url").toString("base64url") !== challenge.nonce || !RFC3339_MILLISECONDS_UTC.test(challenge.expires_at)
    || !SAFE_CANDIDATE_ID.test(challenge.candidate_id ?? "") || !DEVICE_FINGERPRINT.test(challenge.device_key_fingerprint ?? "")) {
    throw apiError("invalid_enrollment", 400, "Device enrollment request is invalid");
  }
}

function parseV2CandidateBindingHeader(value) {
  if (typeof value !== "string" || Buffer.byteLength(value, "utf8") > 16 * 1024) throw apiError("invalid_enrollment_proof", 401, "Device enrollment proof is invalid");
  let parsed;
  try { parsed = parseControlBundleJson(Buffer.from(value, "utf8"), { maxBytes: 16 * 1024, maxDepth: 8 }); }
  catch { throw apiError("invalid_enrollment_proof", 401, "Device enrollment proof is invalid"); }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed) || canonicalJson(parsed) !== value) throw apiError("invalid_enrollment_proof", 401, "Device enrollment proof is invalid");
  try { return normalizeCandidateBinding(parsed); }
  catch { throw apiError("invalid_enrollment_proof", 401, "Device enrollment proof is invalid"); }
}

function normalizeCandidateBinding(value) {
  if (!value || typeof value !== "object" || Array.isArray(value) || Object.keys(value).length !== V2_CANDIDATE_BINDING_KEYS.length
    || Object.keys(value).some((key) => !V2_CANDIDATE_BINDING_KEYS.includes(key))) throw new Error("invalid candidate binding");
  const normalized = {
    version: value.version,
    enrollment_id: value.enrollment_id,
    organization_id: value.organization_id,
    device_id: value.device_id,
    candidate_id: value.candidate_id,
    artifact_sha256: value.artifact_sha256,
    source_commit: value.source_commit,
    team_id: value.team_id,
    device_key_fingerprint: value.device_key_fingerprint,
    expires_at: value.expires_at
  };
  if (normalized.version !== 1 || !canonicalUuid(normalized.enrollment_id) || !canonicalUuid(normalized.organization_id) || !canonicalUuid(normalized.device_id)
    || !SAFE_CANDIDATE_ID.test(normalized.candidate_id ?? "") || !SHA256_HEX.test(normalized.artifact_sha256 ?? "") || !SOURCE_COMMIT.test(normalized.source_commit ?? "")
    || !TEAM_ID.test(normalized.team_id ?? "") || !DEVICE_FINGERPRINT.test(normalized.device_key_fingerprint ?? "") || !RFC3339_MILLISECONDS_UTC.test(normalized.expires_at ?? "")) throw new Error("invalid candidate binding");
  if (new Date(normalized.expires_at).toISOString() !== normalized.expires_at) throw new Error("invalid candidate binding");
  return Object.freeze(normalized);
}

function makeCandidateBinding({ enrollmentId, organizationId, deviceId, candidate, deviceKeyFingerprint, expiresAt }) {
  return normalizeCandidateBinding({
    version: 1,
    enrollment_id: enrollmentId,
    organization_id: organizationId,
    device_id: deviceId,
    candidate_id: candidate?.candidate_id,
    artifact_sha256: candidate?.artifact_sha256,
    source_commit: candidate?.source_commit,
    team_id: candidate?.team_id,
    device_key_fingerprint: deviceKeyFingerprint,
    expires_at: expiresAt
  });
}

const CONTROL_BUNDLE_KEY_ID = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$/u;
const CONTROL_BUNDLE_PURPOSE = "agentpass.control-bundle";

/*
 * ControlBundle has a purpose-specific asynchronous boundary. The legacy
 * private-key adapter is retained solely for the explicit evaluation/test
 * shape used by the reference file store; a partially configured managed
 * signer never falls back to that adapter.
 */
function createControlBundleSigner(value, now) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return undefined;
  const managedShape = typeof value.signControlBundle === "function"
    || typeof value.publicKeyMetadata === "function"
    || Object.hasOwn(value, "key_id");
  if (managedShape) {
    return Object.freeze({
      signControlBundle: value.signControlBundle,
      publicKeyMetadata: value.publicKeyMetadata,
      purpose: value.purpose,
      algorithm: value.algorithm,
      key_id: value.key_id,
      issuer: value.issuer,
      ttlMs: value.ttlMs,
      offlineTtlMs: value.offlineTtlMs
    });
  }
  if (!Object.hasOwn(value, "privateKey")) return undefined;
  const privateKey = value.privateKey;
  return Object.freeze({
    purpose: CONTROL_BUNDLE_PURPOSE,
    algorithm: "ed25519",
    key_id: value.keyId,
    issuer: value.issuer,
    ttlMs: value.ttlMs,
    offlineTtlMs: value.offlineTtlMs,
    async publicKeyMetadata() {
      const key = legacyControlBundlePrivateKey(privateKey);
      return { purpose: CONTROL_BUNDLE_PURPOSE, key_id: value.keyId, algorithm: "ed25519", public_key: crypto.createPublicKey(key).export({ type: "spki", format: "pem" }).toString() };
    },
    async signControlBundle(statement) {
      const key = legacyControlBundlePrivateKey(privateKey);
      return issueControlBundle(statement, key, {
        now: typeof now === "function" ? now() : Date.now(),
        maxTtlMs: value.ttlMs ?? 3_600_000,
        maxOfflineTtlMs: value.offlineTtlMs ?? 3_600_000
      });
    }
  });
}

function legacyControlBundlePrivateKey(value) {
  let key;
  try { key = value?.type === "private" ? value : crypto.createPrivateKey(value); }
  catch { throw new Error("legacy ControlBundle signer is invalid"); }
  if (key.type !== "private" || key.asymmetricKeyType !== "ed25519") throw new Error("legacy ControlBundle signer is invalid");
  return key;
}

async function loadControlBundlePublicMetadata(signer) {
  if (!signer || typeof signer.publicKeyMetadata !== "function" || typeof signer.signControlBundle !== "function"
    || signer.purpose !== CONTROL_BUNDLE_PURPOSE || signer.algorithm !== "ed25519"
    || typeof signer.key_id !== "string" || !CONTROL_BUNDLE_KEY_ID.test(signer.key_id)
    || typeof signer.issuer !== "string" || !CONTROL_BUNDLE_KEY_ID.test(signer.issuer)) {
    throw apiError("bundle_signer_unavailable", 503, "Control bundle signer is unavailable");
  }
  let metadata;
  try { metadata = await signer.publicKeyMetadata(); }
  catch { throw apiError("bundle_signer_unavailable", 503, "Control bundle signer is unavailable"); }
  try {
    if (!metadata || typeof metadata !== "object" || Array.isArray(metadata)
      || metadata.key_id !== signer.key_id || metadata.algorithm !== "ed25519") throw new Error("invalid metadata");
    if (metadata.purpose !== undefined && metadata.purpose !== CONTROL_BUNDLE_PURPOSE) throw new Error("invalid metadata purpose");
    if (typeof metadata.public_key === "string" && /PRIVATE\s+KEY/iu.test(metadata.public_key)) throw new Error("private metadata");
    const key = metadata.public_key?.type === "public" ? metadata.public_key : crypto.createPublicKey(metadata.public_key);
    if (key.type !== "public" || key.asymmetricKeyType !== "ed25519") throw new Error("invalid public key");
    const publicKey = key.export({ type: "spki", format: "pem" }).toString();
    if (metadata.public_key !== publicKey) throw new Error("non-canonical public key");
    return Object.freeze({ key_id: signer.key_id, algorithm: "ed25519", public_key: publicKey });
  } catch { throw apiError("bundle_signer_unavailable", 503, "Control bundle signer is unavailable"); }
}

async function signAndValidateControlBundle(signer, statement, { now, maxTtlMs, maxOfflineTtlMs, audience }) {
  const metadata = await loadControlBundlePublicMetadata(signer);
  if (!signer || typeof signer.signControlBundle !== "function") throw apiError("bundle_signer_unavailable", 503, "Control bundle signer is unavailable");
  let bundle;
  try { bundle = await signer.signControlBundle(statement); }
  catch { throw apiError("bundle_signer_unavailable", 503, "Control bundle signing is unavailable"); }
  try {
    if (controlBundleStatementHash(bundle) !== controlBundleStatementHash(statement)) throw new Error("statement hash mismatch");
    verifyControlBundle(bundle, {
      public_key: metadata.public_key,
      issuer: signer.issuer,
      key_id: signer.key_id
    }, { now, maxTtlMs, maxOfflineTtlMs, audience });
    return bundle;
  } catch { throw apiError("bundle_signer_unavailable", 503, "Control bundle signing is unavailable"); }
}

const CAPABILITY_SIGNER_PURPOSE = "agentpass.capability";

function createCapabilityAuthoritySigner(value, legacyBundleSigner) {
  if (value !== undefined) {
    if (!value || typeof value !== "object" || Array.isArray(value)) return undefined;
    return Object.freeze({
      signCapability: value.signCapability,
      publicKeyMetadata: value.publicKeyMetadata,
      purpose: value.purpose,
      algorithm: value.algorithm,
      key_id: value.key_id,
      issuer: value.issuer
    });
  }
  if (!legacyBundleSigner?.privateKey) return undefined;
  const privateKey = legacyControlBundlePrivateKey(legacyBundleSigner.privateKey);
  return Object.freeze({
    purpose: CAPABILITY_SIGNER_PURPOSE,
    algorithm: "ed25519",
    key_id: legacyBundleSigner.keyId,
    issuer: legacyBundleSigner.issuer,
    async publicKeyMetadata() {
      return {
        purpose: CAPABILITY_SIGNER_PURPOSE,
        key_id: legacyBundleSigner.keyId,
        algorithm: "ed25519",
        public_key: crypto.createPublicKey(privateKey).export({ type: "spki", format: "pem" }).toString()
      };
    },
    async signCapability(statement) {
      return {
        ...statement,
        signature: crypto.sign(null, Buffer.from(canonicalJson(statement), "utf8"), privateKey).toString("base64")
      };
    }
  });
}

async function loadCapabilityPublicMetadata(signer) {
  if (!signer || typeof signer.publicKeyMetadata !== "function" || typeof signer.signCapability !== "function"
    || signer.purpose !== CAPABILITY_SIGNER_PURPOSE || signer.algorithm !== "ed25519"
    || typeof signer.key_id !== "string" || !CONTROL_BUNDLE_KEY_ID.test(signer.key_id)
    || typeof signer.issuer !== "string" || !CONTROL_BUNDLE_KEY_ID.test(signer.issuer)) {
    throw apiError("capability_signer_unavailable", 503, "Capability signer is unavailable");
  }
  let metadata;
  try { metadata = await signer.publicKeyMetadata(); }
  catch { throw apiError("capability_signer_unavailable", 503, "Capability signer is unavailable"); }
  try {
    if (!metadata || typeof metadata !== "object" || Array.isArray(metadata)
      || metadata.key_id !== signer.key_id || metadata.algorithm !== "ed25519"
      || (metadata.purpose !== undefined && metadata.purpose !== CAPABILITY_SIGNER_PURPOSE)
      || (typeof metadata.public_key === "string" && /PRIVATE\s+KEY/iu.test(metadata.public_key))) throw new Error("invalid metadata");
    const key = metadata.public_key?.type === "public" ? metadata.public_key : crypto.createPublicKey(metadata.public_key);
    if (key.type !== "public" || key.asymmetricKeyType !== "ed25519") throw new Error("invalid public key");
    return key.export({ type: "spki", format: "pem" }).toString();
  } catch { throw apiError("capability_signer_unavailable", 503, "Capability signer is unavailable"); }
}

async function signAndValidateCapability(signer, statement) {
  const publicKey = await loadCapabilityPublicMetadata(signer);
  let capability;
  try { capability = await signer.signCapability(statement); }
  catch { throw apiError("capability_signer_unavailable", 503, "Capability signing is unavailable"); }
  try {
    const { signature, ...returnedStatement } = capability ?? {};
    if (canonicalJson(returnedStatement) !== canonicalJson(statement)) throw new Error("statement mismatch");
    verifyCapability({ ...returnedStatement, signature }, {
      public_key: publicKey,
      issuer: signer.issuer,
      key_id: signer.key_id
    }, {
      now: Date.parse(statement.not_before),
      audience: statement.audience
    });
    return capability;
  } catch { throw apiError("capability_signer_unavailable", 503, "Capability signing is unavailable"); }
}

function assertV2CandidateBinding(actual, expected) {
  if (canonicalJson(actual) !== canonicalJson(expected)) throw apiError("invalid_enrollment_proof", 401, "Device enrollment proof is invalid");
}

function validateEnrollmentProofV2(requestPath, body, credentialDigest, nonce, candidateBinding, pem, encodedSignature) {
  if (typeof encodedSignature !== "string" || !/^(?:[A-Za-z0-9+/]{4}){21}(?:[A-Za-z0-9+/]{2}==)$/.test(encodedSignature)) throw apiError("invalid_enrollment_proof", 401, "Device enrollment proof is invalid");
  const signature = Buffer.from(encodedSignature, "base64");
  if (signature.length !== 64 || signature.toString("base64") !== encodedSignature) throw apiError("invalid_enrollment_proof", 401, "Device enrollment proof is invalid");
  const bodyDigest = sha256Text(body);
  const bindingDigest = sha256Text(canonicalJson(candidateBinding));
  const proof = Buffer.from(`${V2_PROOF_DOMAIN}POST\n${requestPath}\n${bodyDigest}\n${credentialDigest}\n${nonce}\n${bindingDigest}`, "utf8");
  let valid = false;
  try { valid = crypto.verify("sha256", proof, { key: crypto.createPublicKey(pem), dsaEncoding: "ieee-p1363" }, signature); }
  catch { valid = false; }
  if (!valid) throw apiError("invalid_enrollment_proof", 401, "Device enrollment proof is invalid");
}

async function resolveActiveReleaseCandidate(store, candidateId, organizationId) {
  let candidate;
  const scope = organizationId === undefined ? { candidateId } : { candidateId, organizationId };
  if (typeof store.resolveActiveReleaseCandidate === "function") candidate = await store.resolveActiveReleaseCandidate(scope);
  else if (typeof store.getReleaseCandidate === "function") candidate = await store.getReleaseCandidate(scope);
  else throw apiError("release_candidate_unavailable", 503, "Release candidate registry is unavailable");
  if (!candidate || candidate.candidate_id !== candidateId || candidate.status !== "active") throw apiError("release_candidate_unavailable", 409, "Release candidate is unavailable");
  return candidate;
}

async function existingPossessionReceiptForEnrollment(store, organizationId, deviceId, enrollmentId) {
  const read = store.getDeviceEnrollmentPossessionReceipt ?? store.getDevicePossessionReceipt;
  if (typeof read !== "function") return undefined;
  let receipt;
  try {
    receipt = await read.call(store, { organizationId, deviceId });
  } catch (error) {
    if (error?.code === "ERR_NOT_FOUND" || error?.status === 404) return undefined;
    throw error;
  }
  return receipt?.statement?.enrollment_id === enrollmentId ? receipt : undefined;
}

function validatePossessionReceiptResponse(receipt, { organizationId, deviceId }) {
  try {
    const keys = ["version", "purpose", "key_id", "algorithm", "statement", "statement_hash", "signature"];
    if (!receipt || typeof receipt !== "object" || Array.isArray(receipt) || Object.keys(receipt).sort().join(",") !== keys.slice().sort().join(",")) throw new Error("receipt envelope is invalid");
    const statement = normalizePossessionReceiptStatement(receipt.statement);
    if (statement.organization_id !== organizationId || statement.device_id !== deviceId
      || receipt.version !== POSSESSION_RECEIPT_VERSION || receipt.purpose !== POSSESSION_RECEIPT_PURPOSE
      || !POSSESSION_RECEIPT_SIGNATURE_ALGORITHMS.includes(receipt.algorithm)
      || typeof receipt.key_id !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$/u.test(receipt.key_id)
      || !SHA256_HEX.test(receipt.statement_hash ?? "") || receipt.statement_hash !== sha256Text(canonicalJson(statement))
      || !BASE64URL_SIGNATURE.test(receipt.signature) || Buffer.from(receipt.signature, "base64url").length !== 64
      || Buffer.from(receipt.signature, "base64url").toString("base64url") !== receipt.signature) throw new Error("receipt binding is invalid");
    return Object.freeze({ ...receipt, statement });
  } catch {
    throw apiError("possession_receipt_unavailable", 503, "Possession receipt is invalid");
  }
}

async function createV2EnrollmentInStore(store, input) {
  const method = typeof store.createDeviceEnrollment === "function" ? store.createDeviceEnrollment : store.createDeviceEnrollmentV2;
  if (typeof method !== "function") throw apiError("enrollment_unavailable", 503, "Device enrollment is unavailable");
  return method.call(store, input);
}

async function completeV2EnrollmentInStore(store, input) {
  const method = typeof store.completeDeviceEnrollment === "function" ? store.completeDeviceEnrollment : store.completeDeviceEnrollmentV2;
  if (typeof method !== "function") throw apiError("enrollment_unavailable", 503, "Device enrollment is unavailable");
  return method.call(store, input);
}

async function loadPossessionReceiptVerification(signer) {
  if (!signer || typeof signer.publicKeyMetadata !== "function") {
    throw apiError("possession_receipt_signer_unavailable", 503, "Possession receipt signer is unavailable");
  }
  let metadata;
  try {
    metadata = await signer.publicKeyMetadata();
    if (!metadata || typeof metadata !== "object" || Array.isArray(metadata)) throw new Error("metadata is not an object");
    const keys = Object.keys(metadata).sort().join(",");
    const minimalKeys = ["algorithm", "key_id", "public_key"].join(",");
    const signerKeys = ["algorithm", "key_id", "public_key", "purpose", "version"].join(",");
    if (keys !== minimalKeys && keys !== signerKeys) throw new Error("metadata fields are invalid");
    if (keys === signerKeys && (metadata.version !== POSSESSION_RECEIPT_VERSION || metadata.purpose !== POSSESSION_RECEIPT_PURPOSE)) throw new Error("metadata purpose is invalid");
    if (typeof metadata.key_id !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$/u.test(metadata.key_id)) throw new Error("metadata key id is invalid");
    if (!POSSESSION_RECEIPT_SIGNATURE_ALGORITHMS.includes(metadata.algorithm)) throw new Error("metadata algorithm is invalid");
    if (typeof metadata.public_key !== "string" || Buffer.byteLength(metadata.public_key, "utf8") > 8192 || /PRIVATE KEY/i.test(metadata.public_key)) throw new Error("metadata public key is invalid");
    const publicKey = crypto.createPublicKey(metadata.public_key);
    if (publicKey.type !== "public") throw new Error("metadata key is not public");
    if (metadata.algorithm === "ed25519" && publicKey.asymmetricKeyType !== "ed25519") throw new Error("metadata algorithm does not match key");
    if (metadata.algorithm === "p256-sha256" && (publicKey.asymmetricKeyType !== "ec" || publicKey.asymmetricKeyDetails?.namedCurve !== "prime256v1")) throw new Error("metadata algorithm does not match key");
    const canonicalPublicKey = publicKey.export({ type: "spki", format: "pem" }).toString();
    if (canonicalPublicKey !== metadata.public_key) throw new Error("metadata public key is not canonical");
    return Object.freeze({ key_id: metadata.key_id, algorithm: metadata.algorithm, public_key: canonicalPublicKey });
  } catch {
    throw apiError("possession_receipt_signer_unavailable", 503, "Possession receipt signer is unavailable");
  }
}

async function signAndValidatePossessionReceipt(signer, statement) {
  let receipt;
  try { receipt = await signer.signPossessionReceipt(statement); }
  catch { throw apiError("possession_receipt_signing_unavailable", 503, "Possession receipt signing is unavailable"); }
  try {
    const normalizedStatement = normalizePossessionReceiptStatement(statement);
    const keys = ["version", "purpose", "key_id", "algorithm", "statement", "statement_hash", "signature"];
    if (!receipt || typeof receipt !== "object" || Array.isArray(receipt) || Object.keys(receipt).sort().join(",") !== keys.slice().sort().join(",")
      || receipt.version !== 1 || receipt.purpose !== "device-enrollment-possession-receipt" || !["ed25519", "p256-sha256"].includes(receipt.algorithm)
      || typeof receipt.key_id !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$/u.test(receipt.key_id) || canonicalJson(receipt.statement) !== canonicalJson(normalizedStatement)
      || !SHA256_HEX.test(receipt.statement_hash ?? "") || receipt.statement_hash !== sha256Text(canonicalJson(normalizedStatement))
      || !BASE64URL_SIGNATURE.test(receipt.signature) || Buffer.from(receipt.signature, "base64url").length !== 64 || Buffer.from(receipt.signature, "base64url").toString("base64url") !== receipt.signature) throw new Error("invalid receipt");
    return Object.freeze({ ...receipt, statement: normalizedStatement });
  } catch { throw apiError("possession_receipt_signing_unavailable", 503, "Possession receipt signing is unavailable"); }
}

function deriveEnrollmentV2Credential(secret, identity) {
  return crypto.createHmac("sha256", secret).update("AgentPass-Enrollment-Credential-v2\0", "utf8").update(canonicalJson(identity), "utf8").digest("base64url");
}

function deriveEnrollmentV2Nonce(secret, binding) {
  return crypto.createHmac("sha256", secret).update("AgentPass-Enrollment-Challenge-v2\0", "utf8").update(canonicalJson(binding), "utf8").digest("base64url");
}

function deterministicEnrollmentUuid(secret, purpose, identity) {
  const bytes = crypto.createHmac("sha256", secret).update(`AgentPass-Enrollment-${purpose}-id-v2\0`, "utf8").update(canonicalJson(identity), "utf8").digest().subarray(0, 16);
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = bytes.toString("hex");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

function canonicalUuid(value) { return typeof value === "string" && UUID_VALUE.test(value) && value === value.toLowerCase(); }
function boundedEnrollmentLabel(value) { return typeof value === "string" && value.length >= 1 && value.length <= 128 && Buffer.byteLength(value, "utf8") <= 512 && !/[\u0000-\u001f\u007f]/u.test(value); }
function sha256Text(value) { return crypto.createHash("sha256").update(Buffer.isBuffer(value) ? value : Buffer.from(String(value), "utf8")).digest("hex"); }
function sha256HexText(value) { return sha256Text(value); }
function publicKeyFingerprint(pem) { return `SHA256:${crypto.createHash("sha256").update(crypto.createPublicKey(pem).export({ type: "spki", format: "der" })).digest("base64url")}`; }
function nextEnrollmentDeviceKeyEpoch(device) {
  const current = Number(device?.key_epoch);
  if (device && Number.isSafeInteger(current) && current >= 0) return current + 1;
  return 1;
}

async function readBody(request, maxBytes = MAX_BODY_BYTES) {
  const chunks = [];
  let bytes = 0;
  for await (const chunk of request) {
    bytes += chunk.length;
    if (bytes > maxBytes) throw apiError("request_too_large", 413, "Request body is too large");
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
}

function parseBody(bytes) {
  if (!bytes.length) return {};
  try {
    const value = parseControlBundleJson(bytes, { maxBytes: MAX_BODY_BYTES, maxDepth: 32 });
    if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error();
    return value;
  } catch { throw apiError("invalid_json", 400, "Request body must be a JSON object"); }
}

function requireExactEmptyJsonObject(body, bodyBytes, label) {
  if (!Buffer.isBuffer(bodyBytes) || bodyBytes.length === 0 || !body || typeof body !== "object" || Array.isArray(body) || Object.keys(body).length !== 0) {
    throw apiError("invalid_refresh_request", 400, `${label} body must be exactly an empty JSON object`);
  }
}

function normalizeRefreshRequestResult(value, pathDeviceId) {
  const expectedKeys = ["desired_generation", "device_id", "request_id", "requested_at", "status", "version"];
  if (!value || typeof value !== "object" || Array.isArray(value) || Object.keys(value).sort().join(",") !== expectedKeys.slice().sort().join(",")) {
    throw apiError("refresh_request_unavailable", 503, "Refresh request is unavailable");
  }
  if (value.version !== 1 || typeof value.request_id !== "string" || !UUID_VALUE.test(value.request_id)
    || typeof value.device_id !== "string" || !UUID_VALUE.test(value.device_id) || value.device_id.toLowerCase() !== pathDeviceId.toLowerCase()
    || (value.desired_generation !== null && (!Number.isSafeInteger(value.desired_generation) || value.desired_generation < 1))
    || !["accepted", "coalesced", "no_pending_refresh"].includes(value.status)
    || typeof value.requested_at !== "string" || !RFC3339_UTC.test(value.requested_at) || !Number.isFinite(Date.parse(value.requested_at))) {
    throw apiError("refresh_request_unavailable", 503, "Refresh request is unavailable");
  }
  return Object.freeze({
    version: 1,
    request_id: value.request_id.toLowerCase(),
    device_id: value.device_id.toLowerCase(),
    desired_generation: value.desired_generation,
    status: value.status,
    requested_at: new Date(value.requested_at).toISOString()
  });
}

function rejectUnknown(value, allowed, label) {
  for (const key of Object.keys(value)) if (!allowed.has(key)) throw apiError("unknown_field", 400, `${label} contains an unknown field`);
}

function requiredQuery(url, name) { const value = url.searchParams.get(name); if (!value) throw apiError("invalid_query", 400, `${name} is required`); return value; }
function requireExactQueryKeys(url, allowed) {
  for (const key of url.searchParams.keys()) if (!allowed.has(key)) throw apiError("invalid_query", 400, "query is invalid");
}
function requiredUuidQuery(url, name) {
  const values = url.searchParams.getAll(name);
  if (values.length !== 1 || !UUID_VALUE.test(values[0])) throw apiError("invalid_query", 400, `${name} is invalid`);
  return values[0].toLowerCase();
}
function optionalQuery(url, name) {
  const values = url.searchParams.getAll(name);
  if (values.length > 1 || values[0] === "") throw apiError("invalid_query", 400, `${name} is invalid`);
  return values[0];
}
function optionalLimit(url) {
  const values = url.searchParams.getAll("limit");
  if (values.length > 1) throw apiError("invalid_query", 400, "limit is invalid");
  const value = values[0];
  if (value === undefined) return 100;
  if (!/^[1-9]\d{0,2}$/.test(value) || Number(value) > 500) throw apiError("invalid_query", 400, "limit is invalid");
  return Number(value);
}

function optionalBoundedIntegerQuery(url, name, minimum, maximum, fallback) {
  const values = url.searchParams.getAll(name);
  if (values.length > 1) throw apiError("invalid_query", 400, "query is invalid");
  if (values.length === 0) return fallback;
  if (!/^(?:0|[1-9]\d*)$/u.test(values[0])) throw apiError("invalid_query", 400, "query is invalid");
  const value = Number(values[0]);
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) throw apiError("invalid_query", 400, "query is invalid");
  return value;
}

function positiveGeneration(value) {
  const generation = Number(value);
  if (!Number.isSafeInteger(generation) || generation < 1) throw apiError("bundle_generation_unavailable", 503, "Bundle generation is unavailable");
  return generation;
}

  function validateRefreshHintResponse(input, { organizationId, deviceId, afterGeneration, now }) {
  let hint;
  try { hint = normalizeRefreshHint(input); }
  catch { throw apiError("refresh_unavailable", 503, "Refresh polling is unavailable"); }
  if (hint.organization_id !== organizationId || hint.device_id !== deviceId || hint.authority_generation <= afterGeneration) {
    throw apiError("refresh_unavailable", 503, "Refresh polling is unavailable");
  }

  const publishedAt = Date.parse(hint.published_at);
  const expiresAt = Date.parse(hint.expires_at);
  if (publishedAt > now + 60_000 || expiresAt <= now) throw apiError("refresh_unavailable", 503, "Refresh polling is unavailable");
  return hint;
}

async function enrollmentRefreshHintTrustMetadata(refreshHintService, bundlePublicKeyPEM) {
  if (!refreshHintService || typeof refreshHintService.publicKeyMetadata !== "function") {
    throw apiError("refresh_hint_signer_unavailable", 503, "Refresh hint signer is unavailable");
  }
  let metadata;
  try { metadata = await refreshHintService.publicKeyMetadata(); } catch { throw apiError("refresh_hint_signer_unavailable", 503, "Refresh hint signer is unavailable"); }
  if (!metadata || typeof metadata !== "object" || Array.isArray(metadata)
    || Object.keys(metadata).length !== 3 || Object.keys(metadata).some((key) => !["key_id", "algorithm", "public_key"].includes(key))
    || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$/u.test(metadata.key_id ?? "")
    || metadata.algorithm !== "ed25519" || typeof metadata.public_key !== "string") {
    throw apiError("refresh_hint_signer_unavailable", 503, "Refresh hint signer is unavailable");
  }
  let publicKey;
  try { publicKey = crypto.createPublicKey(metadata.public_key); } catch { throw apiError("refresh_hint_signer_unavailable", 503, "Refresh hint signer is unavailable"); }
  if (publicKey.type !== "public" || publicKey.asymmetricKeyType !== "ed25519") throw apiError("refresh_hint_signer_unavailable", 503, "Refresh hint signer is unavailable");
  const publicKeyPEM = publicKey.export({ type: "spki", format: "pem" }).toString();
  if (publicKeyPEM !== metadata.public_key || publicKeyPEM === bundlePublicKeyPEM) throw apiError("refresh_hint_signer_unavailable", 503, "Refresh hint signer is unavailable");
  return Object.freeze({ key_id: metadata.key_id, algorithm: "ed25519", public_key: publicKeyPEM });
}

function positiveDeviceKeyEpoch(device) {
  const epoch = Number(device?.key_epoch);
  if (!Number.isSafeInteger(epoch) || epoch < 1) throw apiError("device_key_epoch_unavailable", 503, "Device authentication key epoch is unavailable");
  return epoch;
}

function verifyBundleAcknowledgementSignature(acknowledgement, publicKey) {
  if (!publicKey || publicKey.asymmetricKeyType !== "ec" || publicKey.asymmetricKeyDetails?.namedCurve !== "prime256v1") {
    throw apiError("invalid_acknowledgement_signature", 401, "Bundle acknowledgement signature is invalid");
  }
  const signature = Buffer.from(acknowledgement.signature, "base64url");
  let valid = false;
  try { valid = crypto.verify("sha256", bundleAcknowledgementSigningData(acknowledgement), { key: publicKey, dsaEncoding: "ieee-p1363" }, signature); }
  catch { valid = false; }
  if (!valid) throw apiError("invalid_acknowledgement_signature", 401, "Bundle acknowledgement signature is invalid");
}
function publicCapability(capability) {
  const { nonce, ...metadata } = capability;
  return metadata;
}

function rateLimitHeaders(decision, retry = false) {
  const headers = {
    "X-RateLimit-Limit": String(decision.limit),
    "X-RateLimit-Remaining": String(decision.remaining),
    "X-RateLimit-Reset": String(Math.ceil(decision.resetAt / 1000))
  };
  if (retry) headers["Retry-After"] = String(decision.retryAfterSeconds);
  return headers;
}

function authorizedOperationalProbe(request, secret) {
  const supplied = request.headers["agentpass-operational-token"];
  if (typeof supplied !== "string" || !/^[A-Za-z0-9_-]{43}$/u.test(supplied)) return false;
  const bytes = Buffer.from(supplied, "base64url");
  return bytes.length === 32
    && bytes.toString("base64url") === supplied
    && crypto.timingSafeEqual(bytes, secret);
}

function recordOperationalMetric(metrics, method, amount = 1) {
  try { metrics?.[method]?.(amount); } catch { /* Observability must never alter authorization or API behavior. */ }
}

function hasErrorCode(error, expected) {
  let current = error;
  for (let depth = 0; depth < 5 && current && typeof current === "object"; depth += 1) {
    if (current.code === expected) return true;
    current = current.cause;
  }
  return false;
}

function publicReadinessReport(value) {
  if (!value || typeof value !== "object" || Array.isArray(value) || value.version !== 1 || typeof value.ready !== "boolean" || typeof value.status !== "string" || typeof value.code !== "string") throw new Error("invalid readiness report");
  const output = { version: 1, ready: value.ready, status: value.status, code: value.code };
  if (value.checks !== undefined) output.checks = publicReadinessChecks(value.checks);
  if (value.metrics !== undefined) output.metrics = publicMetricsReport(value.metrics);
  if (value.deployment_identity !== undefined) output.deployment_identity = publicDeploymentIdentity(value.deployment_identity);
  return Object.freeze(output);
}

function publicDeploymentIdentity(value) {
  const keys = ["version", "configured", "ready", "source_commit", "source_tree", "image_digest", "deployment_id", "revision", "schema_digest", "catalog_digest", "database_schema_digest"];
  const complete = value?.source_commit !== null && /^[0-9a-f]{40}$/u.test(value?.source_commit ?? "")
    && value?.source_tree !== null && /^[0-9a-f]{40}$/u.test(value?.source_tree ?? "")
    && value?.image_digest !== null && /^sha256:[0-9a-f]{64}$/u.test(value?.image_digest ?? "")
    && value?.deployment_id !== null && /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u.test(value?.deployment_id ?? "")
    && value?.revision !== null && /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u.test(value?.revision ?? "")
    && value?.schema_digest !== null && /^[0-9a-f]{64}$/u.test(value?.schema_digest ?? "")
    && value?.catalog_digest !== null && /^[0-9a-f]{64}$/u.test(value?.catalog_digest ?? "")
    && value?.database_schema_digest !== null && /^[0-9a-f]{64}$/u.test(value?.database_schema_digest ?? "");
  if (!value || typeof value !== "object" || Array.isArray(value) || Object.keys(value).sort().join(",") !== keys.slice().sort().join(",")
    || value.version !== 1 || typeof value.configured !== "boolean" || typeof value.ready !== "boolean"
    || (value.source_commit !== null && !/^[0-9a-f]{40}$/u.test(value.source_commit))
    || (value.source_tree !== null && !/^[0-9a-f]{40}$/u.test(value.source_tree))
    || (value.image_digest !== null && !/^sha256:[0-9a-f]{64}$/u.test(value.image_digest))
    || (value.deployment_id !== null && !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u.test(value.deployment_id))
    || (value.revision !== null && !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u.test(value.revision))
    || (value.schema_digest !== null && !/^[0-9a-f]{64}$/u.test(value.schema_digest))
    || (value.catalog_digest !== null && !/^[0-9a-f]{64}$/u.test(value.catalog_digest))
    || (value.database_schema_digest !== null && !/^[0-9a-f]{64}$/u.test(value.database_schema_digest))
    || (value.configured && (value.ready !== true || !complete)) || (!value.configured && (value.ready !== false || complete))) throw new Error("invalid deployment identity");
  return Object.freeze({ version: 1, configured: value.configured, ready: value.ready, source_commit: value.source_commit, source_tree: value.source_tree, image_digest: value.image_digest, deployment_id: value.deployment_id, revision: value.revision, schema_digest: value.schema_digest, catalog_digest: value.catalog_digest, database_schema_digest: value.database_schema_digest });
}

function publicReadinessChecks(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("invalid readiness checks");
  const { database, schema, pool, drain, owner_recovery_outbox: ownerRecoveryOutbox, managed_signer_provider_operations: managedSignerProviderOperations, managed_signers: managedSigners, agent_session_signer: agentSessionSigner, qualification_manifest_signer: qualificationManifestSigner, possession_receipt_signer: possessionReceiptSigner, refresh_hint_signer: refreshHintSigner, capability_signer: capabilitySigner, control_bundle_signer: controlBundleSigner, audit_anchor_signer: auditAnchorSigner, promotion_evidence_signer: promotionEvidenceSigner } = value;
  if (!database || typeof database.ok !== "boolean" || typeof database.probe !== "string") throw new Error("invalid readiness checks");
  const integerOrNull = (item) => item === null || Number.isSafeInteger(item);
  const nonNegativeIntegerOrNull = (item) => item === null || (Number.isSafeInteger(item) && item >= 0);
  if (!schema || typeof schema.ok !== "boolean" || !integerOrNull(schema.expected_version) || !integerOrNull(schema.applied_version) || !integerOrNull(schema.migration_count) || !integerOrNull(schema.pending_count) || typeof schema.checksum_status !== "string" || (schema.drift !== null && typeof schema.drift !== "boolean")) throw new Error("invalid readiness checks");
  if (!pool || typeof pool.ok !== "boolean" || !integerOrNull(pool.max_connections) || !integerOrNull(pool.total_connections) || !integerOrNull(pool.idle_connections) || !integerOrNull(pool.waiting_connections) || !integerOrNull(pool.utilization_percent) || (pool.saturated !== null && typeof pool.saturated !== "boolean")) throw new Error("invalid readiness checks");
  if (!drain || !["running", "draining", "closed"].includes(drain.state) || typeof drain.accepting !== "boolean" || !Number.isSafeInteger(drain.in_flight) || drain.in_flight < 0) throw new Error("invalid readiness checks");
  if (ownerRecoveryOutbox !== undefined && (!ownerRecoveryOutbox || typeof ownerRecoveryOutbox.ok !== "boolean" || typeof ownerRecoveryOutbox.code !== "string"
    || !["running", "idle", "draining", "closed", "unavailable"].includes(ownerRecoveryOutbox.worker_state)
    || !integerOrNull(ownerRecoveryOutbox.pending_count) || !integerOrNull(ownerRecoveryOutbox.uncertain_count) || !integerOrNull(ownerRecoveryOutbox.dead_letter_count)
    || !integerOrNull(ownerRecoveryOutbox.oldest_pending_age_ms) || !integerOrNull(ownerRecoveryOutbox.oldest_uncertain_age_ms))) throw new Error("invalid readiness checks");
  if (managedSignerProviderOperations !== undefined && (!managedSignerProviderOperations || typeof managedSignerProviderOperations.ok !== "boolean"
    || typeof managedSignerProviderOperations.code !== "string"
    || !["running", "idle", "closing", "closed", "unavailable"].includes(managedSignerProviderOperations.worker_state)
    || !nonNegativeIntegerOrNull(managedSignerProviderOperations.pending_count) || !nonNegativeIntegerOrNull(managedSignerProviderOperations.started_count)
    || !nonNegativeIntegerOrNull(managedSignerProviderOperations.accepted_count) || !nonNegativeIntegerOrNull(managedSignerProviderOperations.uncertain_count)
    || !nonNegativeIntegerOrNull(managedSignerProviderOperations.stale_started_count) || !nonNegativeIntegerOrNull(managedSignerProviderOperations.oldest_nonterminal_age_ms)
    || !nonNegativeIntegerOrNull(managedSignerProviderOperations.last_success_age_ms))) throw new Error("invalid readiness checks");
  if (agentSessionSigner !== undefined && (!agentSessionSigner || typeof agentSessionSigner.ok !== "boolean"
    || typeof agentSessionSigner.purpose !== "string" || agentSessionSigner.algorithm !== "ed25519"
    || (agentSessionSigner.key_id !== null && typeof agentSessionSigner.key_id !== "string")
    || (agentSessionSigner.public_key_fingerprint !== null && !/^[0-9a-f]{64}$/u.test(agentSessionSigner.public_key_fingerprint)))) throw new Error("invalid readiness checks");
  if (qualificationManifestSigner !== undefined && (!qualificationManifestSigner || typeof qualificationManifestSigner.ok !== "boolean"
    || qualificationManifestSigner.purpose !== "agentpass.qualification-grant-batch-manifest" || qualificationManifestSigner.algorithm !== "ed25519"
    || (qualificationManifestSigner.key_id !== null && typeof qualificationManifestSigner.key_id !== "string")
    || (qualificationManifestSigner.public_key_fingerprint !== null && !/^[0-9a-f]{64}$/u.test(qualificationManifestSigner.public_key_fingerprint)))) throw new Error("invalid readiness checks");
  if (possessionReceiptSigner !== undefined && (!possessionReceiptSigner || typeof possessionReceiptSigner.ok !== "boolean"
    || possessionReceiptSigner.purpose !== "device-enrollment-possession-receipt" || possessionReceiptSigner.algorithm !== "ed25519"
    || (possessionReceiptSigner.key_id !== null && typeof possessionReceiptSigner.key_id !== "string")
    || (possessionReceiptSigner.public_key_fingerprint !== null && !/^[0-9a-f]{64}$/u.test(possessionReceiptSigner.public_key_fingerprint)))) throw new Error("invalid readiness checks");
  const additionalSigners = [
    ["refresh_hint_signer", refreshHintSigner, "agentpass.refresh-hint"],
    ["capability_signer", capabilitySigner, "agentpass.capability"],
    ["control_bundle_signer", controlBundleSigner, "agentpass.control-bundle"],
    ["audit_anchor_signer", auditAnchorSigner, "agentpass.audit-anchor"],
    ["promotion_evidence_signer", promotionEvidenceSigner, "agentpass.promotion-evidence"]
  ];
  for (const [, signer, purpose] of additionalSigners) {
    if (signer !== undefined && (!signer || typeof signer.ok !== "boolean" || signer.purpose !== purpose || signer.algorithm !== "ed25519"
      || (signer.key_id !== null && typeof signer.key_id !== "string")
      || (signer.public_key_fingerprint !== null && !/^[0-9a-f]{64}$/u.test(signer.public_key_fingerprint)))) throw new Error("invalid readiness checks");
  }
  if (managedSigners !== undefined) validateManagedSignerReadiness(managedSigners);
  return Object.freeze({
    database: Object.freeze({ ok: database.ok, probe: database.probe }),
    schema: Object.freeze({ ok: schema.ok, expected_version: schema.expected_version, applied_version: schema.applied_version, migration_count: schema.migration_count, pending_count: schema.pending_count, checksum_status: schema.checksum_status, drift: schema.drift }),
    pool: Object.freeze({ ok: pool.ok, max_connections: pool.max_connections, total_connections: pool.total_connections, idle_connections: pool.idle_connections, waiting_connections: pool.waiting_connections, utilization_percent: pool.utilization_percent, saturated: pool.saturated }),
    drain: Object.freeze({ state: drain.state, accepting: drain.accepting, in_flight: drain.in_flight }),
    ...(ownerRecoveryOutbox === undefined ? {} : { owner_recovery_outbox: Object.freeze({ ok: ownerRecoveryOutbox.ok, code: ownerRecoveryOutbox.code, worker_state: ownerRecoveryOutbox.worker_state, pending_count: ownerRecoveryOutbox.pending_count, uncertain_count: ownerRecoveryOutbox.uncertain_count, dead_letter_count: ownerRecoveryOutbox.dead_letter_count, oldest_pending_age_ms: ownerRecoveryOutbox.oldest_pending_age_ms, oldest_uncertain_age_ms: ownerRecoveryOutbox.oldest_uncertain_age_ms }) }),
    ...(managedSignerProviderOperations === undefined ? {} : { managed_signer_provider_operations: Object.freeze({ ok: managedSignerProviderOperations.ok, code: managedSignerProviderOperations.code, worker_state: managedSignerProviderOperations.worker_state, pending_count: managedSignerProviderOperations.pending_count, started_count: managedSignerProviderOperations.started_count, accepted_count: managedSignerProviderOperations.accepted_count, uncertain_count: managedSignerProviderOperations.uncertain_count, stale_started_count: managedSignerProviderOperations.stale_started_count, oldest_nonterminal_age_ms: managedSignerProviderOperations.oldest_nonterminal_age_ms, last_success_age_ms: managedSignerProviderOperations.last_success_age_ms }) }),
    ...(managedSigners === undefined ? {} : { managed_signers: Object.freeze({ version: 1, cardinality: managedSigners.cardinality, ok: managedSigners.ok, code: managedSigners.code, signers: Object.freeze(Object.fromEntries(MANAGED_SIGNER_NAMES.map((name) => [name, Object.freeze({ ...managedSigners.signers[name] })]))) }) }),
    ...(agentSessionSigner === undefined ? {} : { agent_session_signer: Object.freeze({ ok: agentSessionSigner.ok, purpose: agentSessionSigner.purpose, algorithm: agentSessionSigner.algorithm, key_id: agentSessionSigner.key_id, public_key_fingerprint: agentSessionSigner.public_key_fingerprint }) }),
    ...(qualificationManifestSigner === undefined ? {} : { qualification_manifest_signer: Object.freeze({ ok: qualificationManifestSigner.ok, purpose: qualificationManifestSigner.purpose, algorithm: qualificationManifestSigner.algorithm, key_id: qualificationManifestSigner.key_id, public_key_fingerprint: qualificationManifestSigner.public_key_fingerprint }) }),
    ...(possessionReceiptSigner === undefined ? {} : { possession_receipt_signer: Object.freeze({ ok: possessionReceiptSigner.ok, purpose: possessionReceiptSigner.purpose, algorithm: possessionReceiptSigner.algorithm, key_id: possessionReceiptSigner.key_id, public_key_fingerprint: possessionReceiptSigner.public_key_fingerprint }) }),
    ...Object.fromEntries(additionalSigners.filter(([, signer]) => signer !== undefined).map(([name, signer]) => [name, Object.freeze({ ok: signer.ok, purpose: signer.purpose, algorithm: signer.algorithm, key_id: signer.key_id, public_key_fingerprint: signer.public_key_fingerprint })]))
  });
}

const MANAGED_SIGNER_NAMES = Object.freeze(["capability", "control_bundle", "refresh_hint", "possession_receipt", "agent_session_grant", "qualification_manifest", "audit_anchor", "promotion_evidence"]);
const MANAGED_SIGNER_CODES = new Set(["ready", "provider_unavailable", "metadata_invalid", "metadata_mismatch", "keyring_invalid", "lifecycle_unavailable", "lifecycle_inactive", "draining", "closed", "not_ready"]);

function validateManagedSignerReadiness(value) {
  if (!value || typeof value !== "object" || Array.isArray(value) || value.version !== 1 || value.cardinality !== 8 || typeof value.ok !== "boolean" || typeof value.code !== "string" || !MANAGED_SIGNER_CODES.has(value.code) || !value.signers || typeof value.signers !== "object" || Array.isArray(value.signers) || Object.keys(value.signers).sort().join(",") !== [...MANAGED_SIGNER_NAMES].sort().join(",")) throw new Error("invalid managed signer readiness");
  for (const name of MANAGED_SIGNER_NAMES) {
    const signer = value.signers[name];
    if (!signer || typeof signer !== "object" || Array.isArray(signer) || typeof signer.ok !== "boolean" || typeof signer.code !== "string" || !MANAGED_SIGNER_CODES.has(signer.code) || !["active", "failed", "retiring"].includes(signer.state) || typeof signer.purpose !== "string" || typeof signer.domain !== "string" && signer.domain !== null || signer.algorithm !== "ed25519" || !Number.isSafeInteger(signer.registry_version) || signer.registry_version < 1 || !Number.isSafeInteger(signer.protocol_version) || signer.protocol_version < 1 || !Number.isSafeInteger(signer.signing_version) || signer.signing_version < 1 || (signer.key_id !== null && typeof signer.key_id !== "string") || (signer.key_version !== null && (!Number.isSafeInteger(signer.key_version) || signer.key_version < 1)) || (signer.lifecycle_version !== null && (!Number.isSafeInteger(signer.lifecycle_version) || signer.lifecycle_version < 1)) || (signer.public_key_fingerprint !== null && !/^[0-9a-f]{64}$/u.test(signer.public_key_fingerprint))) throw new Error("invalid managed signer readiness");
  }
}

function publicMetricsReport(value) {
  if (!value || typeof value !== "object" || Array.isArray(value) || value.version !== 1 || value.valid !== true || !value.counters || typeof value.counters !== "object" || Array.isArray(value.counters)) throw new Error("invalid metrics report");
  if (Object.keys(value.counters).sort().join(",") !== [...OPERATIONAL_METRIC_KEYS].sort().join(",")) throw new Error("invalid metrics report");
  const counters = {};
  for (const key of OPERATIONAL_METRIC_KEYS) { const count = value.counters[key]; if (!Number.isSafeInteger(count) || count < 0) throw new Error("invalid metrics report"); counters[key] = count; }
  let gauges;
  if (value.gauges !== undefined) {
    if (!value.gauges || typeof value.gauges !== "object" || Array.isArray(value.gauges)
      || Object.keys(value.gauges).sort().join(",") !== [...OPERATIONAL_GAUGE_KEYS].sort().join(",")) throw new Error("invalid metrics report");
    gauges = {};
    for (const key of OPERATIONAL_GAUGE_KEYS) {
      const amount = value.gauges[key];
      if (!Number.isSafeInteger(amount) || amount < 0) throw new Error("invalid metrics report");
      gauges[key] = amount;
    }
  }
  return Object.freeze({ version: 1, counters: Object.freeze(counters), ...(gauges === undefined ? {} : { gauges: Object.freeze(gauges) }), valid: true });
}

function send(response, status, value, headers = {}) {
  const encoded = Buffer.from(canonicalJson(value));
  response.writeHead(status, { "content-type": "application/json; charset=utf-8", "content-length": encoded.length, "cache-control": "no-store", ...headers });
  response.end(encoded);
}

function sendNoContent(response, headers = {}) {
  response.writeHead(204, { "cache-control": "no-store", ...headers });
  response.end();
}

function apiError(code, status, message, headers) { const error = new Error(message); error.code = code; error.status = status; if (headers) error.headers = headers; return error; }
function platformPromotionErrorStatus(status) { return new Set([400, 401, 403, 404, 409, 503]).has(status) ? status : 503; }
function platformPromotionErrorCode(code) {
  return new Set([
    "invalid_platform_request",
    "not_found",
    "platform_authentication_failed",
    "platform_authentication_unavailable",
    "platform_authorization_denied",
    "platform_promotion_conflict",
    "platform_promotion_unavailable",
    "platform_audit_unavailable"
  ]).has(code) ? code : "platform_promotion_unavailable";
}
function mapRefreshRequestRepositoryError(error) {
  if (error?.status) return error;
  if (error?.code === "ERR_NOT_FOUND") return apiError("not_found", 404, "Resource not found");
  if (["ERR_DEVICE_REVOKED", "ERR_DEVICE_UNAVAILABLE"].includes(error?.code)) return apiError("device_unavailable", 409, "Device is not available");
  if (error?.code === "ERR_ACTOR_UNAVAILABLE") return apiError("authorization_denied", 403, "Authorization denied");
  if (["ERR_IDEMPOTENCY_CONFLICT", "ERR_UNIQUE_CONSTRAINT"].includes(error?.code)) return apiError("idempotency_conflict", 409, "Mutation conflict");
  if (["ERR_INPUT", "ERR_INVALID_INPUT", "ERR_INVALID_UUID", "ERR_IDEMPOTENCY_KEY_REQUIRED"].includes(error?.code)) return apiError("invalid_refresh_request", 400, "Refresh request is invalid");
  if (error?.code === "ERR_TENANT_SCOPE") return apiError("authorization_denied", 403, "Authorization denied");
  return apiError("refresh_request_unavailable", 503, "Refresh request is unavailable");
}
function mapError(error) {
  if (error.status) return error;
  if (error.code === "ERR_AUDIT_CURSOR_INVALID") return { status: 400, code: "invalid_cursor", message: "Cursor is invalid" };
  if (["invalid_session_cookie", "session_not_found", "session_revoked", "session_expired"].includes(error.code)) return { status: 401, code: "human_session_invalid", message: "Authentication failed" };
  if (["invalid_origin", "csrf_token_required", "invalid_csrf_token"].includes(error.code)) return { status: 403, code: "human_session_request_denied", message: "Authentication failed" };
  if (error instanceof RateLimiterCapacityError || error.code === "RATE_LIMITER_CAPACITY_EXHAUSTED") return { status: 503, code: "rate_limiter_unavailable", message: "Rate limiter is temporarily unavailable", headers: { "Retry-After": "1" } };
  if (String(error.code).startsWith("auth_") || ["invalid_api_token", "device_auth_failed", "invalid_auth_headers"].includes(error.code)) return { status: 401, code: error.code, message: "Authentication failed" };
  if (["role_denied", "organization_mismatch"].includes(error.code)) return { status: 403, code: error.code, message: "Authorization denied" };
  if (error.code === "ERR_NOT_FOUND") return { status: 404, code: "not_found", message: "Resource not found" };
  if (error.code === "ERR_ENROLLMENT_AUTH") return { status: 401, code: "invalid_enrollment_credential", message: "Device enrollment authentication failed" };
  if (["ERR_ENROLLMENT_EXPIRED", "ERR_ENROLLMENT_CONSUMED", "ERR_ENROLLMENT_STATE", "ERR_ENROLLMENT_BINDING"].includes(error.code)) return { status: 409, code: error.code.toLowerCase(), message: "Device enrollment conflict" };
  if (error.code === "ERR_VERSION_CONFLICT") return { status: 409, code: "version_conflict", message: "Resource version conflict" };
  if (error.code === "ERR_ACK_CONFLICT") return { status: 409, code: "ack_conflict", message: "Bundle acknowledgement conflicts with prior evidence" };
  if (error.code === "ERR_REFRESH_BUSY") return { status: 503, code: "refresh_busy", message: "Refresh polling capacity is exhausted", headers: { "retry-after": "1" } };
  if (["ERR_REFRESH_ABORTED", "ERR_REFRESH_INPUT", "ERR_REFRESH_UNAVAILABLE"].includes(error.code)) return { status: 503, code: "refresh_unavailable", message: "Refresh polling is unavailable" };
  if (error.code === "ERR_IDEMPOTENCY_CONFLICT" || error.code === "ERR_UNIQUE_CONSTRAINT") return { status: 409, code: error.code.toLowerCase(), message: "Mutation conflict" };
  if (String(error.code).startsWith("ERR_")) return { status: 400, code: error.code.toLowerCase(), message: "Request was rejected" };
  return { status: 500, code: "internal_error", message: "Internal error" };
}
