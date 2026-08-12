import crypto from "node:crypto";
import http from "node:http";
import { authenticateApiToken, createReplayCache, requireOrganizationRole, verifyDeviceRequest } from "./auth.mjs";
import { MAX_REVOCATIONS, controlBundleStatementHash, issueControlBundle, parseControlBundleJson } from "../../../lib/control-bundle-v2.mjs";
import { canonicalJson, intersectScopes } from "../../../packages/capability/src/index.mjs";
import {
  bundleAcknowledgementSigningData,
  normalizeRefreshHint,
  parseBundleAcknowledgementJson
} from "../../../packages/protocol/src/index.mjs";
import { RateLimiterCapacityError, createRateLimiter } from "./rate-limit.mjs";
import { OPERATIONAL_METRIC_KEYS } from "./postgres/operational-health.mjs";
import { normalizeDeviceReadModels } from "./device-read-model.mjs";

const MAX_BODY_BYTES = 1024 * 1024;
const HUMAN_AUTH_MAX_BODY_BYTES = 64 * 1024;
const HUMAN_AUTH_SESSION_PATH = "/api/auth/session";
const HUMAN_AUTH_OPTIONS_PATH = "/api/auth/webauthn/options";
const HUMAN_AUTH_VERIFY_PATH = "/api/auth/webauthn/verify";
const HUMAN_AUTH_REGISTRATION_OPTIONS_PATH = "/api/auth/webauthn/registration/options";
const HUMAN_AUTH_REGISTRATION_VERIFY_PATH = "/api/auth/webauthn/registration/verify";
const HUMAN_AUTH_ORGANIZATIONS_PATH = "/api/auth/organizations";
const HUMAN_AUTH_ACCEPT_INVITATION_PATH = "/api/auth/invitations/accept";
const HUMAN_AUTH_UUID = "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-8][0-9a-fA-F]{3}-[89a-fA-F][0-9a-fA-F]{3}-[0-9a-fA-F]{12}";
const UUID = "([0-9a-fA-F-]{36})";
const UUID_VALUE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
const RFC3339_UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/u;
export function createCloudApi({ store, tokenRecords = [], bundleSigner, refreshHintService, now = () => Date.now(), monotonicNow, replayCache = createReplayCache(), deviceReplayConsumer, rateLimiter, admissionRateLimiter, verifyRecentWebAuthn, recentAuthService, humanAuthApi, humanSession, capabilityAuthorityRepository, capabilityRevocationSource, auditRepository, enrollmentCredentialSecret, trackInFlight, readiness, operationalMetrics, operationalProbeSecret } = {}) {
  if (!store) throw new TypeError("store is required");
  if (verifyRecentWebAuthn !== undefined && recentAuthService !== undefined) throw new TypeError("configure verifyRecentWebAuthn or recentAuthService, not both");
  if (humanAuthApi !== undefined && (!humanAuthApi || typeof humanAuthApi.handle !== "function")) throw new TypeError("humanAuthApi must expose handle()");
  if (humanSession !== undefined && (!humanSession || typeof humanSession.authenticateRequest !== "function")) throw new TypeError("humanSession must expose authenticateRequest()");
  if (capabilityRevocationSource !== undefined && (!capabilityRevocationSource || typeof capabilityRevocationSource.listRevokedCapabilityIds !== "function")) throw new TypeError("capabilityRevocationSource must expose listRevokedCapabilityIds()");
  if (capabilityAuthorityRepository !== undefined && (!capabilityAuthorityRepository || typeof capabilityAuthorityRepository.issueCapabilityMetadata !== "function")) throw new TypeError("capabilityAuthorityRepository must expose issueCapabilityMetadata()");
  if (auditRepository !== undefined && (!auditRepository || typeof auditRepository.listDeviceAuditEvents !== "function")) throw new TypeError("auditRepository must expose listDeviceAuditEvents()");
  if (refreshHintService !== undefined && (!refreshHintService || typeof refreshHintService.poll !== "function")) throw new TypeError("refreshHintService must expose poll()");
  if (deviceReplayConsumer !== undefined && typeof deviceReplayConsumer !== "function") throw new TypeError("deviceReplayConsumer must be a function");
  if (enrollmentCredentialSecret !== undefined && (!Buffer.isBuffer(enrollmentCredentialSecret) || enrollmentCredentialSecret.length !== 32)) throw new TypeError("enrollmentCredentialSecret must be an exact 32-byte Buffer");
  if (trackInFlight !== undefined && typeof trackInFlight !== "function") throw new TypeError("trackInFlight must be a function");
  if (readiness !== undefined && typeof readiness !== "function") throw new TypeError("readiness must be a function");
  if (operationalMetrics !== undefined && (!operationalMetrics || typeof operationalMetrics.snapshot !== "function")) throw new TypeError("operationalMetrics must expose snapshot()");
  if (operationalProbeSecret !== undefined && (!Buffer.isBuffer(operationalProbeSecret) || operationalProbeSecret.length !== 32)) throw new TypeError("operationalProbeSecret must be an exact 32-byte Buffer");
  if ((readiness !== undefined || operationalMetrics !== undefined) && operationalProbeSecret === undefined) throw new TypeError("operationalProbeSecret is required for operational endpoints");
  const effectiveEnrollmentCredentialSecret = enrollmentCredentialSecret ?? (bundleSigner?.privateKey
    ? crypto.createHash("sha256").update("AgentPass-Evaluation-Enrollment-Root-v1\0").update(bundleSigner.privateKey.export({ type: "pkcs8", format: "der" })).digest()
    : crypto.randomBytes(32));
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
        const report = (() => { try { return publicMetricsReport(operationalMetrics.snapshot()); } catch { return null; } })();
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
      const url = new URL(request.url, "http://agentpass.invalid");
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
      route("POST", new RegExp(`^/v1/enrollments/(?<enrollmentId>${UUID})$`), null, async ({ match, body, bodyBytes, request }) => {
        rejectUnknown(body, new Set(["version", "enrollment_id", "organization_id", "device_id", "label", "platform", "device_key"]), "device_enrollment");
        if (body.version !== 1 || body.enrollment_id !== match.enrollmentId || !body.device_key || typeof body.device_key !== "object" || Array.isArray(body.device_key)) throw apiError("invalid_enrollment", 400, "Device enrollment request is invalid");
        rejectUnknown(body.device_key, new Set(["algorithm", "spki_pem"]), "device_key");
        const credential = request.headers["agentpass-enrollment-credential"];
        if (typeof credential !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(credential)) throw apiError("invalid_enrollment_credential", 401, "Device enrollment credential is invalid");
        validateEnrollmentPublicKey(body.device_key.algorithm, body.device_key.spki_pem);
        validateEnrollmentProof(request.url, bodyBytes, body.device_key.algorithm, body.device_key.spki_pem, credential, request.headers["agentpass-enrollment-signature"]);
        if (!bundleSigner?.privateKey || !bundleSigner?.issuer || !bundleSigner?.keyId) throw apiError("bundle_signer_unavailable", 503, "Control bundle signer is unavailable");
        const controlPublicKey = crypto.createPublicKey(bundleSigner.privateKey).export({ type: "spki", format: "pem" }).toString();
        const refreshHintTrust = await enrollmentRefreshHintTrustMetadata(refreshHintService, controlPublicKey);
        const device = await store.completeDeviceEnrollment({ enrollmentId: match.enrollmentId, organizationId: body.organization_id, deviceId: body.device_id, label: body.label, platform: body.platform, algorithm: body.device_key.algorithm, publicKey: body.device_key.spki_pem, credentialDigest: crypto.createHash("sha256").update(credential).digest("hex"), completedAt: new Date(now()).toISOString() });
        const deviceKeyEpoch = positiveDeviceKeyEpoch(device);
        return { status: 201, body: { enrollment: { version: 1, enrollment_id: match.enrollmentId, organization_id: device.organization_id, device_id: device.device_id, status: device.status, key_algorithm: device.key_algorithm, device_key_epoch: deviceKeyEpoch, control: { format_epoch: 2, issuer: bundleSigner.issuer, key_id: bundleSigner.keyId, public_key: controlPublicKey, bundle_path: `/v1/organizations/${device.organization_id}/bundles/${device.device_id}`, refresh_hint: refreshHintTrust } } } };
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
        if (!bundleSigner?.privateKey || !bundleSigner?.issuer || !bundleSigner?.keyId) throw apiError("capability_signer_unavailable", 503, "Capability signer is unavailable");
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
          const reserved = await target.reserveCapability({ organizationId, ...(body.capability_id ? { capabilityId: body.capability_id } : {}), issuer: bundleSigner.issuer, keyId: bundleSigner.keyId, agentId: agent.agent_id, deviceId: device.device_id, scope: effectiveScope, sequence: body.sequence, ttlMs, issuedAt, createdBy: principal.member_id, principalId: principal.member_id, idempotencyKey });
          const statement = { version: 1, capability_id: reserved.capability_id, nonce: reserved.nonce, issuer: reserved.issuer, key_id: reserved.key_id, audience: { agent_id: reserved.agent_id, device_id: reserved.device_id }, scope: reserved.scope, not_before: reserved.not_before, expires_at: reserved.expires_at, sequence: reserved.sequence };
          const metadataTarget = typeof target.issueCapabilityMetadata === "function" ? target : capabilityAuthorityRepository;
          if (metadataTarget !== undefined) await metadataTarget.issueCapabilityMetadata({ organization_id: organizationId, capability_id: statement.capability_id, agent_id: statement.audience.agent_id, device_id: statement.audience.device_id, sequence: statement.sequence, statement_hash: crypto.createHash("sha256").update(canonicalJson(statement)).digest("hex"), expires_at: statement.expires_at, issued_by_member_id: principal.member_id });
          return { ...statement, signature: crypto.sign(null, Buffer.from(canonicalJson(statement)), bundleSigner.privateKey).toString("base64") };
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
      route("GET", new RegExp(`^/v1/organizations/(?<organizationId>${UUID})/bundles/(?<deviceId>${UUID})$`), null, async ({ organizationId, principal, match }) => {
        if (principal.device_id !== match.deviceId) throw apiError("audience_mismatch", 403, "Device cannot fetch another device's bundle");
        if (!bundleSigner?.privateKey || !bundleSigner?.issuer || !bundleSigner?.keyId) throw apiError("bundle_signer_unavailable", 503, "Bundle signer is unavailable");
        const issuedMs = now();
        const ttlMs = bundleSigner.ttlMs ?? 3_600_000;
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
                format_epoch: 2, issuer: bundleSigner.issuer, organization_id: organizationId, device_id: match.deviceId,
                audience: { organization_id: organizationId, device_id: match.deviceId }, issued_at: head.issued_at,
                expires_at: head.expires_at, sequence: head.sequence, policy_scope: snapshot.policy_scope,
                global_revoked: snapshot.global_revoked, revoked_devices: snapshot.revoked_devices,
                revoked_agents: snapshot.revoked_agents, revoked_capabilities: snapshot.revoked_capabilities,
                offline_ttl_ms: bundleSigner.offlineTtlMs ?? 3_600_000, key_id: bundleSigner.keyId
              };
              return controlBundleStatementHash(preparedStatement);
            }
          });
          const { head } = authority;
          if (!preparedStatement || preparedStatement.sequence !== head.sequence) throw apiError("bundle_statement_unavailable", 503, "Bundle statement is unavailable");
          const bundle = issueControlBundle(preparedStatement, bundleSigner.privateKey, { now: issuedMs, maxTtlMs: ttlMs, maxOfflineTtlMs: bundleSigner.offlineTtlMs ?? 3_600_000 });
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
        const bundle = issueControlBundle({
            format_epoch: 2,
            issuer: bundleSigner.issuer,
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
            offline_ttl_ms: bundleSigner.offlineTtlMs ?? 3_600_000,
            key_id: bundleSigner.keyId
          }, bundleSigner.privateKey, { now: issuedMs, maxTtlMs: ttlMs, maxOfflineTtlMs: bundleSigner.offlineTtlMs ?? 3_600_000 });
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
  if (!url.search && (url.pathname === HUMAN_AUTH_SESSION_PATH || url.pathname === HUMAN_AUTH_OPTIONS_PATH || url.pathname === HUMAN_AUTH_VERIFY_PATH || url.pathname === HUMAN_AUTH_REGISTRATION_OPTIONS_PATH || url.pathname === HUMAN_AUTH_REGISTRATION_VERIFY_PATH)) return true;
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
  if (typeof proof !== "string" || proof.length < 32 || proof.length > 4096 || /[\u0000-\u001f\u007f]/.test(proof)) throw apiError("recent_auth_required", 401, "Recent WebAuthn authentication is required");
  let result;
  try { result = await verifier({ proof, principal: { ...principal }, organization_id: organizationId, operation, now }); }
  catch { throw apiError("recent_auth_failed", 401, "Recent WebAuthn authentication failed"); }
  const expectedKeys = ["authenticated_at", "challenge_id", "consumed", "member_id", "operation", "organization_id", "verified"];
  if (!result || typeof result !== "object" || Array.isArray(result) || Object.keys(result).sort().join(",") !== expectedKeys.sort().join(",") || result.verified !== true || result.consumed !== true || result.member_id !== principal.member_id || result.organization_id !== organizationId || result.operation !== operation || typeof result.challenge_id !== "string" || !/^[0-9a-f-]{36}$/.test(result.challenge_id)) {
    throw apiError("recent_auth_failed", 401, "Recent WebAuthn authentication failed");
  }
  const authenticatedAt = typeof result.authenticated_at === "string" ? Date.parse(result.authenticated_at) : result.authenticated_at;
  if (!Number.isSafeInteger(authenticatedAt) || authenticatedAt > now + 30_000 || now - authenticatedAt > 5 * 60_000) throw apiError("recent_auth_stale", 401, "Recent WebAuthn authentication is stale");
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
  return bytes.length === 32 && crypto.timingSafeEqual(bytes, secret);
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
  return Object.freeze(output);
}

function publicReadinessChecks(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("invalid readiness checks");
  const { database, schema, pool, drain } = value;
  if (!database || typeof database.ok !== "boolean" || typeof database.probe !== "string") throw new Error("invalid readiness checks");
  const integerOrNull = (item) => item === null || Number.isSafeInteger(item);
  if (!schema || typeof schema.ok !== "boolean" || !integerOrNull(schema.expected_version) || !integerOrNull(schema.applied_version) || !integerOrNull(schema.migration_count) || !integerOrNull(schema.pending_count) || typeof schema.checksum_status !== "string" || (schema.drift !== null && typeof schema.drift !== "boolean")) throw new Error("invalid readiness checks");
  if (!pool || typeof pool.ok !== "boolean" || !integerOrNull(pool.max_connections) || !integerOrNull(pool.total_connections) || !integerOrNull(pool.idle_connections) || !integerOrNull(pool.waiting_connections) || !integerOrNull(pool.utilization_percent) || (pool.saturated !== null && typeof pool.saturated !== "boolean")) throw new Error("invalid readiness checks");
  if (!drain || !["running", "draining", "closed"].includes(drain.state) || typeof drain.accepting !== "boolean" || !Number.isSafeInteger(drain.in_flight) || drain.in_flight < 0) throw new Error("invalid readiness checks");
  return Object.freeze({
    database: Object.freeze({ ok: database.ok, probe: database.probe }),
    schema: Object.freeze({ ok: schema.ok, expected_version: schema.expected_version, applied_version: schema.applied_version, migration_count: schema.migration_count, pending_count: schema.pending_count, checksum_status: schema.checksum_status, drift: schema.drift }),
    pool: Object.freeze({ ok: pool.ok, max_connections: pool.max_connections, total_connections: pool.total_connections, idle_connections: pool.idle_connections, waiting_connections: pool.waiting_connections, utilization_percent: pool.utilization_percent, saturated: pool.saturated }),
    drain: Object.freeze({ state: drain.state, accepting: drain.accepting, in_flight: drain.in_flight })
  });
}

function publicMetricsReport(value) {
  if (!value || typeof value !== "object" || Array.isArray(value) || value.version !== 1 || value.valid !== true || !value.counters || typeof value.counters !== "object" || Array.isArray(value.counters)) throw new Error("invalid metrics report");
  if (Object.keys(value.counters).sort().join(",") !== [...OPERATIONAL_METRIC_KEYS].sort().join(",")) throw new Error("invalid metrics report");
  const counters = {};
  for (const key of OPERATIONAL_METRIC_KEYS) { const count = value.counters[key]; if (!Number.isSafeInteger(count) || count < 0) throw new Error("invalid metrics report"); counters[key] = count; }
  return Object.freeze({ version: 1, counters: Object.freeze(counters), valid: true });
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
