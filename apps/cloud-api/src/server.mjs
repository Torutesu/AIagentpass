import crypto from "node:crypto";
import http from "node:http";
import { authenticateApiToken, createReplayCache, requireOrganizationRole, verifyDeviceRequest } from "./auth.mjs";
import { issueControlBundle, parseControlBundleJson } from "../../../lib/control-bundle-v2.mjs";
import { canonicalJson, intersectScopes } from "../../../packages/capability/src/index.mjs";
import { RateLimiterCapacityError, createRateLimiter } from "./rate-limit.mjs";

const MAX_BODY_BYTES = 1024 * 1024;
const UUID = "([0-9a-fA-F-]{36})";

export function createCloudApi({ store, tokenRecords = [], bundleSigner, now = () => Date.now(), monotonicNow, replayCache = createReplayCache(), rateLimiter, admissionRateLimiter, verifyRecentWebAuthn, recentAuthService } = {}) {
  if (!store) throw new TypeError("store is required");
  if (verifyRecentWebAuthn !== undefined && recentAuthService !== undefined) throw new TypeError("configure verifyRecentWebAuthn or recentAuthService, not both");
  const recentAuthVerifier = recentAuthService === undefined ? verifyRecentWebAuthn : recentAuthService?.authorize?.bind(recentAuthService);
  if (recentAuthService !== undefined && typeof recentAuthVerifier !== "function") throw new TypeError("recentAuthService must expose authorize()");
  const limiter = rateLimiter ?? createRateLimiter({ now, ...(monotonicNow ? { monotonicNow } : {}) });
  const admission = admissionRateLimiter ?? createRateLimiter({ now, ...(monotonicNow ? { monotonicNow } : {}), human: { capacity: 30, refillPerSecond: 1 }, device: { capacity: 60, refillPerSecond: 2 } });
  if (!limiter || typeof limiter.acquire !== "function") throw new TypeError("rateLimiter must expose acquire()");
  const routes = buildRoutes();

  const server = http.createServer(async (request, response) => {
    const requestId = crypto.randomUUID();
    try {
      const url = new URL(request.url, "http://agentpass.invalid");
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
      const admitted = admission.acquire({ tenantId: rateLimitTenant, principalType: route.device ? "device" : "human", principalId: admissionId });
      if (!admitted.allowed) throw apiError("rate_limited", 429, "Pre-authentication rate limit exceeded", rateLimitHeaders(admitted, true));
      const bodyBytes = await readBody(request);
      const body = parseBody(bodyBytes);
      let principal;
      if (route.device) {
        const devices = await store.listDevices({ organizationId });
        principal = verifyDeviceRequest({ method: request.method, path: request.url, body: bodyBytes, headers: request.headers }, devices, { organizationId, now: now(), replayCache });
      } else if (route.enrollment) {
        principal = { enrollment_id: match?.groups?.enrollmentId, member_id: admissionId };
      } else {
        principal = authenticateApiToken(bearerToken(request.headers.authorization), tokenRecords);
        requireOrganizationRole(principal, organizationId, route.role);
        if (route.recentAuthOperation) await requireRecentWebAuthn({ verifier: recentAuthVerifier, principal, proof: request.headers["agentpass-recent-auth"], organizationId, operation: route.recentAuthOperation, now: now() });
      }
      let rateLimit;
      try {
        rateLimit = limiter.acquire({ tenantId: rateLimitTenant, principalType: route.device ? "device" : "human", principalId: route.device ? principal.device_id : principal.member_id });
        if (!rateLimit || typeof rateLimit !== "object" || typeof rateLimit.allowed !== "boolean" || !Number.isSafeInteger(rateLimit.limit) || rateLimit.limit < 1 || !Number.isSafeInteger(rateLimit.remaining) || rateLimit.remaining < 0 || rateLimit.remaining > rateLimit.limit || !Number.isSafeInteger(rateLimit.retryAfterSeconds) || rateLimit.retryAfterSeconds < 0 || !Number.isSafeInteger(rateLimit.resetAt) || rateLimit.resetAt < 0) throw new Error("invalid rate limiter decision");
      } catch (error) {
        if (error?.code === "RATE_LIMITER_CAPACITY_EXHAUSTED") throw error;
        throw apiError("rate_limiter_unavailable", 503, "Rate limiter is temporarily unavailable", { "Retry-After": "1" });
      }
      if (!rateLimit.allowed) throw apiError("rate_limited", 429, "Rate limit exceeded", rateLimitHeaders(rateLimit, true));
      const context = { request, url, body, bodyBytes, organizationId, principal, match: match.groups ?? {}, idempotencyKey: idempotencyKey(request, route), requestId };
      const result = await route.handle(context);
      send(response, result.status ?? 200, { ...result.body, request_id: requestId }, { ...rateLimitHeaders(rateLimit), ...result.headers });
    } catch (error) {
      const mapped = mapError(error);
      send(response, mapped.status, { error: { code: mapped.code, message: mapped.message }, request_id: requestId }, mapped.headers);
    }
  });
  server.requestTimeout = 15_000;
  server.headersTimeout = 10_000;
  server.keepAliveTimeout = 5_000;
  server.maxHeadersCount = 64;
  server.on("connection", (socket) => socket.setTimeout(15_000));
  return server;

  function buildRoutes() {
    const route = (method, pattern, role, handle, device = false, enrollment = false, recentAuthOperation = undefined) => ({ method, pattern, role, handle, device, enrollment, recentAuthOperation });
    return [
      route("GET", new RegExp(`^/v1/organizations/(?<organizationId>${UUID})$`), "viewer", async ({ organizationId }) => ({ body: { organization: await store.getOrganization({ organizationId }) } })),
      route("GET", new RegExp(`^/v1/organizations/(?<organizationId>${UUID})/devices$`), "viewer", async ({ organizationId }) => ({ body: { devices: await store.listDevices({ organizationId }) } })),
      route("POST", new RegExp(`^/v1/organizations/(?<organizationId>${UUID})/devices$`), "admin", async ({ organizationId, body, idempotencyKey }) => ({ status: 201, body: { device: await store.createDevice({ ...body, organizationId, idempotencyKey }) } })),
      route("POST", new RegExp(`^/v1/organizations/(?<organizationId>${UUID})/device-enrollments$`), "admin", async ({ organizationId, body, idempotencyKey, principal }) => {
        rejectUnknown(body, new Set(["enrollment_id", "device_id", "label", "platform", "ttl_ms"]), "device_enrollment_issue");
        const ttl = body.ttl_ms ?? 15 * 60 * 1000;
        if (!Number.isSafeInteger(ttl) || ttl < 60_000 || ttl > 24 * 60 * 60 * 1000) throw apiError("invalid_enrollment_ttl", 400, "Enrollment TTL must be between 1 minute and 24 hours");
        const credential = crypto.randomBytes(32).toString("base64url");
        const createdAt = new Date(now()).toISOString();
        const enrollment = await store.createDeviceEnrollment({ organizationId, enrollmentId: body.enrollment_id, deviceId: body.device_id, label: body.label, platform: body.platform ?? "macos", credentialDigest: crypto.createHash("sha256").update(credential).digest("hex"), createdAt, expiresAt: new Date(now() + ttl).toISOString(), idempotencyKey });
        await store.appendAdminAuditEvent({ organizationId, eventType: "device.enrollment_issued", actorId: principal.member_id, targetType: "device", targetId: enrollment.device_id, details: { enrollment_id: enrollment.enrollment_id, expires_at: enrollment.expires_at }, idempotencyKey: `${idempotencyKey}:audit` });
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
        const device = await store.completeDeviceEnrollment({ enrollmentId: match.enrollmentId, organizationId: body.organization_id, deviceId: body.device_id, label: body.label, platform: body.platform, algorithm: body.device_key.algorithm, publicKey: body.device_key.spki_pem, credentialDigest: crypto.createHash("sha256").update(credential).digest("hex"), completedAt: new Date(now()).toISOString() });
        return { status: 201, body: { enrollment: { version: 1, enrollment_id: match.enrollmentId, organization_id: device.organization_id, device_id: device.device_id, status: device.status, key_algorithm: device.key_algorithm, control: { format_epoch: 2, issuer: bundleSigner.issuer, key_id: bundleSigner.keyId, public_key: controlPublicKey, bundle_path: `/v1/organizations/${device.organization_id}/bundles/${device.device_id}` } } } };
      }, false, true),
      route("GET", new RegExp(`^/v1/organizations/(?<organizationId>${UUID})/agents$`), "viewer", async ({ organizationId }) => ({ body: { agents: await store.listAgents({ organizationId }) } })),
      route("POST", new RegExp(`^/v1/organizations/(?<organizationId>${UUID})/agents$`), "admin", async ({ organizationId, body, idempotencyKey }) => ({ status: 201, body: { agent: await store.createAgent({ ...body, organizationId, idempotencyKey }) } })),
      route("POST", new RegExp(`^/v1/organizations/(?<organizationId>${UUID})/agents/(?<agentId>${UUID})/revoke$`), "admin", async ({ organizationId, match, body, idempotencyKey, principal }) => {
        rejectUnknown(body, new Set(["reason"]), "agent_revocation");
        const revocation = await store.createRevocation({ organizationId, targetType: "agent", targetId: match.agentId, reason: body.reason, idempotencyKey });
        await store.appendAdminAuditEvent({ organizationId, eventType: "agent.revoked", actorId: principal.member_id, targetType: "agent", targetId: match.agentId, idempotencyKey: `${idempotencyKey}:audit` });
        return { status: 201, body: { revocation } };
      }),
      route("POST", new RegExp(`^/v1/organizations/(?<organizationId>${UUID})/devices/(?<deviceId>${UUID})/revoke$`), "admin", async ({ organizationId, match, body, idempotencyKey, principal }) => {
        rejectUnknown(body, new Set(["reason"]), "device_revocation");
        const revocation = await store.createRevocation({ organizationId, targetType: "device", targetId: match.deviceId, reason: body.reason, idempotencyKey });
        await store.appendAdminAuditEvent({ organizationId, eventType: "device.revoked", actorId: principal.member_id, targetType: "device", targetId: match.deviceId, idempotencyKey: `${idempotencyKey}:audit` });
        return { status: 201, body: { revocation } };
      }),
      route("GET", new RegExp(`^/v1/organizations/(?<organizationId>${UUID})/policies$`), "viewer", async ({ organizationId }) => ({ body: { policies: await store.listPolicies({ organizationId }) } })),
      route("POST", new RegExp(`^/v1/organizations/(?<organizationId>${UUID})/policies$`), "admin", async ({ organizationId, body, idempotencyKey }) => ({ status: 201, body: { policy: await store.createPolicy({ ...body, organizationId, idempotencyKey }) } })),
      route("POST", new RegExp(`^/v1/organizations/(?<organizationId>${UUID})/policies/(?<policyId>${UUID})/disable$`), "admin", async ({ organizationId, match, body, idempotencyKey, principal }) => {
        rejectUnknown(body, new Set(["expected_version", "reason"]), "policy_disable");
        const policy = await store.updatePolicy({ organizationId, policyId: match.policyId, expectedVersion: body.expected_version, patch: { status: "disabled" }, idempotencyKey });
        await store.appendAdminAuditEvent({ organizationId, eventType: "policy.disabled", actorId: principal.member_id, targetType: "policy", targetId: match.policyId, details: { reason: body.reason ?? "disabled_by_operator" }, idempotencyKey: `${idempotencyKey}:audit` });
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
        const reserved = await store.reserveCapability({
          organizationId,
          ...(body.capability_id ? { capabilityId: body.capability_id } : {}),
          issuer: bundleSigner.issuer,
          keyId: bundleSigner.keyId,
          agentId: agent.agent_id,
          deviceId: device.device_id,
          scope: effectiveScope,
          sequence: body.sequence,
          ttlMs,
          issuedAt: new Date(now()).toISOString(),
          idempotencyKey
        });
        const statement = {
          version: 1,
          capability_id: reserved.capability_id,
          nonce: reserved.nonce,
          issuer: reserved.issuer,
          key_id: reserved.key_id,
          audience: { agent_id: reserved.agent_id, device_id: reserved.device_id },
          scope: reserved.scope,
          not_before: reserved.not_before,
          expires_at: reserved.expires_at,
          sequence: reserved.sequence
        };
        const signed = { ...statement, signature: crypto.sign(null, Buffer.from(canonicalJson(statement)), bundleSigner.privateKey).toString("base64") };
        await store.appendAdminAuditEvent({ organizationId, eventType: "capability.issued", actorId: principal.member_id, targetType: "capability", targetId: signed.capability_id, details: { agent_id: agent.agent_id, device_id: device.device_id, expires_at: signed.expires_at, sequence: signed.sequence }, idempotencyKey: `${idempotencyKey}:audit` });
        return { status: 201, body: { capability: signed } };
      }),
      route("POST", new RegExp(`^/v1/organizations/(?<organizationId>${UUID})/capabilities/(?<capabilityId>${UUID})/revoke$`), "admin", async ({ organizationId, match, body, idempotencyKey, principal }) => {
        rejectUnknown(body, new Set(["reason"]), "capability_revocation");
        const revocation = await store.createRevocation({ organizationId, targetType: "capability", targetId: match.capabilityId, reason: body.reason, idempotencyKey });
        await store.appendAdminAuditEvent({ organizationId, eventType: "capability.revoked", actorId: principal.member_id, targetType: "capability", targetId: match.capabilityId, idempotencyKey: `${idempotencyKey}:audit` });
        return { status: 201, body: { revocation } };
      }),
      route("GET", new RegExp(`^/v1/organizations/(?<organizationId>${UUID})/revocations$`), "viewer", async ({ organizationId, url }) => ({ body: { revocations: (await store.listRevocations({ organizationId })).slice(-optionalLimit(url)) } })),
      route("GET", new RegExp(`^/v1/organizations/(?<organizationId>${UUID})/audit/events$`), "auditor", async ({ organizationId, url }) => ({ body: { events: await store.listDeviceAuditEvents({ organizationId, deviceId: requiredQuery(url, "device_id"), limit: optionalLimit(url) }) } })),
      route("GET", new RegExp(`^/v1/organizations/(?<organizationId>${UUID})/audit/admin-events$`), "auditor", async ({ organizationId, url }) => ({ body: { events: await store.listAdminAuditEvents({ organizationId, limit: optionalLimit(url) }) } })),
      route("GET", new RegExp(`^/v1/organizations/(?<organizationId>${UUID})/audit/health$`), "auditor", async ({ organizationId }) => ({ body: { health: await store.getAuditHealth({ organizationId }) } })),
      route("POST", new RegExp(`^/v1/organizations/(?<organizationId>${UUID})/audit/events$`), null, async ({ organizationId, principal, body }) => {
        rejectUnknown(body, new Set(["batch_id", "events"]), "audit_ingestion");
        return { status: 202, body: { ingestion: await store.ingestDeviceAuditEvents({ organizationId, deviceId: principal.device_id, events: body.events, idempotencyKey: body.batch_id ?? crypto.randomUUID() }) } };
      }, true),
      route("GET", new RegExp(`^/v1/organizations/(?<organizationId>${UUID})/bundles/(?<deviceId>${UUID})$`), null, async ({ organizationId, principal, match }) => {
        if (principal.device_id !== match.deviceId) throw apiError("audience_mismatch", 403, "Device cannot fetch another device's bundle");
        if (!bundleSigner?.privateKey || !bundleSigner?.issuer || !bundleSigner?.keyId) throw apiError("bundle_signer_unavailable", 503, "Bundle signer is unavailable");
        const policies = await store.listPolicies({ organizationId });
        const active = policies.filter((policy) => policy.status === "active").sort((a, b) => b.sequence - a.sequence)[0];
        if (!active) throw apiError("policy_missing", 409, "No active policy exists");
        const revocations = await store.listRevocations({ organizationId });
        const stateFingerprint = crypto.createHash("sha256").update(JSON.stringify({ device_id: match.deviceId, policy_id: active.policy_id, policy_sequence: active.sequence, policy_scope: active.scope, revocations: revocations.map((item) => [item.revocation_id, item.target_type, item.target_id, item.status]).sort() })).digest("hex");
        const issuedMs = now();
        const ttlMs = bundleSigner.ttlMs ?? 3_600_000;
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
            revoked_capabilities: revocations.filter((item) => item.target_type === "capability" && item.status === "active").map((item) => item.target_id).sort(),
            offline_ttl_ms: bundleSigner.offlineTtlMs ?? 3_600_000,
            key_id: bundleSigner.keyId
          }, bundleSigner.privateKey, { now: issuedMs, maxTtlMs: ttlMs, maxOfflineTtlMs: bundleSigner.offlineTtlMs ?? 3_600_000 });
        return { body: { bundle } };
      }, true),
      route("POST", new RegExp(`^/v1/organizations/(?<organizationId>${UUID})/emergency-stop$`), "owner", async ({ organizationId, body, idempotencyKey, principal }) => {
        rejectUnknown(body, new Set(["reason"]), "emergency_stop");
        const revocation = await store.createRevocation({ organizationId, targetType: "organization", targetId: organizationId, reason: body.reason, idempotencyKey });
        await store.appendAdminAuditEvent({ organizationId, eventType: "organization.emergency_stop", actorId: principal.member_id, targetType: "organization", targetId: organizationId, idempotencyKey: `${idempotencyKey}:audit` });
        return { status: 201, body: { revocation } };
      }, false, false, "organization.emergency_stop")
    ];
  }
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

async function readBody(request) {
  const chunks = [];
  let bytes = 0;
  for await (const chunk of request) {
    bytes += chunk.length;
    if (bytes > MAX_BODY_BYTES) throw apiError("request_too_large", 413, "Request body is too large");
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

function rejectUnknown(value, allowed, label) {
  for (const key of Object.keys(value)) if (!allowed.has(key)) throw apiError("unknown_field", 400, `${label} contains an unknown field`);
}

function requiredQuery(url, name) { const value = url.searchParams.get(name); if (!value) throw apiError("invalid_query", 400, `${name} is required`); return value; }
function optionalLimit(url) { const value = url.searchParams.get("limit"); if (value === null) return 100; if (!/^[1-9]\d{0,2}$/.test(value) || Number(value) > 500) throw apiError("invalid_query", 400, "limit is invalid"); return Number(value); }
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

function send(response, status, value, headers = {}) {
  const encoded = Buffer.from(canonicalJson(value));
  response.writeHead(status, { "content-type": "application/json; charset=utf-8", "content-length": encoded.length, "cache-control": "no-store", ...headers });
  response.end(encoded);
}

function apiError(code, status, message, headers) { const error = new Error(message); error.code = code; error.status = status; if (headers) error.headers = headers; return error; }
function mapError(error) {
  if (error.status) return error;
  if (error instanceof RateLimiterCapacityError || error.code === "RATE_LIMITER_CAPACITY_EXHAUSTED") return { status: 503, code: "rate_limiter_unavailable", message: "Rate limiter is temporarily unavailable", headers: { "Retry-After": "1" } };
  if (String(error.code).startsWith("auth_") || ["invalid_api_token", "device_auth_failed", "invalid_auth_headers"].includes(error.code)) return { status: 401, code: error.code, message: "Authentication failed" };
  if (["role_denied", "organization_mismatch"].includes(error.code)) return { status: 403, code: error.code, message: "Authorization denied" };
  if (error.code === "ERR_NOT_FOUND") return { status: 404, code: "not_found", message: "Resource not found" };
  if (error.code === "ERR_ENROLLMENT_AUTH") return { status: 401, code: "invalid_enrollment_credential", message: "Device enrollment authentication failed" };
  if (["ERR_ENROLLMENT_EXPIRED", "ERR_ENROLLMENT_CONSUMED", "ERR_ENROLLMENT_STATE", "ERR_ENROLLMENT_BINDING"].includes(error.code)) return { status: 409, code: error.code.toLowerCase(), message: "Device enrollment conflict" };
  if (error.code === "ERR_VERSION_CONFLICT") return { status: 409, code: "version_conflict", message: "Resource version conflict" };
  if (error.code === "ERR_IDEMPOTENCY_CONFLICT" || error.code === "ERR_UNIQUE_CONSTRAINT") return { status: 409, code: error.code.toLowerCase(), message: "Mutation conflict" };
  if (String(error.code).startsWith("ERR_")) return { status: 400, code: error.code.toLowerCase(), message: "Request was rejected" };
  return { status: 500, code: "internal_error", message: "Internal error" };
}
