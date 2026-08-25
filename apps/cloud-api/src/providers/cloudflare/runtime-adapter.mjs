import crypto from "node:crypto";

/**
 * Cloudflare is deliberately kept behind this small, provider-neutral
 * boundary.  The adapter does not import wrangler or the Cloudflare SDK: the
 * transport and credential provider are injected by the hosted composition.
 * This keeps credentials out of the domain service and makes plan-only mode
 * safe to use in local development and tests.
 */

export const CLOUDFLARE_RUNTIME_PROVIDER = "cloudflare";
export const CLOUDFLARE_ADAPTER_MODES = Object.freeze(["plan", "live"]);
export const CLOUDFLARE_RESOURCE_KINDS = Object.freeze(["worker", "pages", "r2", "d1"]);

const SHA256 = /^[0-9a-f]{64}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const SAFE_NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const OPERATION_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{7,255}$/;
const ORIGIN = /^https:\/\/[^/]+$/;
const SECRET = /(secret|token|password|private.?key|api.?key|authorization|cookie|credential)/i;
const DEFAULT_LIMITS = Object.freeze({
  maxArtifactBytes: 100 * 1024 * 1024,
  maxResources: 16,
  maxBindings: 32,
  maxRoutes: 16,
  maxOperations: 256,
});
const UNSUPPORTED = Symbol("unsupported");

export const CLOUDFLARE_RUNTIME_ERROR_CODES = Object.freeze({
  INVALID_CONFIGURATION: "cloudflare.invalid_configuration",
  INVALID_INPUT: "cloudflare.invalid_input",
  RUNTIME_UNAVAILABLE: "cloudflare.runtime_unavailable",
  OPERATION_NOT_FOUND: "cloudflare.operation_not_found",
  DIGEST_MISMATCH: "cloudflare.digest_mismatch",
  PROVIDER_REJECTED: "cloudflare.provider_rejected",
  RECONCILIATION_REQUIRED: "cloudflare.reconciliation_required",
  STALE_GENERATION: "cloudflare.stale_generation",
  UNSUPPORTED_RESOURCE: "cloudflare.unsupported_resource",
});

const SAFE_MESSAGES = Object.freeze({
  [CLOUDFLARE_RUNTIME_ERROR_CODES.INVALID_CONFIGURATION]: "Cloudflare runtime configuration is invalid",
  [CLOUDFLARE_RUNTIME_ERROR_CODES.INVALID_INPUT]: "Cloudflare runtime request is invalid",
  [CLOUDFLARE_RUNTIME_ERROR_CODES.RUNTIME_UNAVAILABLE]: "Cloudflare live runtime is unavailable",
  [CLOUDFLARE_RUNTIME_ERROR_CODES.OPERATION_NOT_FOUND]: "Cloudflare runtime operation was not found",
  [CLOUDFLARE_RUNTIME_ERROR_CODES.DIGEST_MISMATCH]: "Cloudflare artifact digest does not match",
  [CLOUDFLARE_RUNTIME_ERROR_CODES.PROVIDER_REJECTED]: "Cloudflare runtime operation was rejected",
  [CLOUDFLARE_RUNTIME_ERROR_CODES.RECONCILIATION_REQUIRED]: "Cloudflare runtime state requires reconciliation",
  [CLOUDFLARE_RUNTIME_ERROR_CODES.STALE_GENERATION]: "Cloudflare runtime generation is stale",
  [CLOUDFLARE_RUNTIME_ERROR_CODES.UNSUPPORTED_RESOURCE]: "Cloudflare resource kind is unsupported",
});

export class CloudflareRuntimeError extends Error {
  constructor(code, details = undefined) {
    super(SAFE_MESSAGES[code] ?? SAFE_MESSAGES[CLOUDFLARE_RUNTIME_ERROR_CODES.INVALID_INPUT]);
    this.name = "CloudflareRuntimeError";
    this.code = code;
    // Details are fixed safe fields only. Never attach provider errors or
    // request/response bodies, which may contain credentials or source text.
    if (details !== undefined) this.details = Object.freeze(safeDetails(details));
  }
}

/**
 * Create an adapter for a Cloudflare Workers-for-Platforms deployment.
 *
 * `mode: "plan"` is the default and performs no network or provider action.
 * `mode: "live"` requires both an injected transport and workload-identity
 * credential provider. If either is absent, operations remain explicit
 * `not_proven` rather than becoming a local/mock success.
 */
export function createCloudflareRuntimeAdapter(options = {}) {
  const config = normalizeConfig(options);
  const operations = new Map();
  const idempotency = new Map();
  const generations = new Map();
  const transport = options.transport;
  const credentialProvider = options.credentialProvider;
  const uuid = options.uuid;
  const clock = options.clock;

  const runtimeAvailable = config.mode === "live"
    && typeof transport?.request === "function"
    && typeof credentialProvider === "function";

  function now() {
    const value = typeof clock?.now === "function" ? clock.now() : new Date().toISOString();
    return typeof value === "string" ? value : new Date().toISOString();
  }

  function operationId() {
    const value = typeof uuid?.randomUUID === "function" ? uuid.randomUUID() : crypto.randomUUID();
    if (!OPERATION_ID.test(value)) throw new CloudflareRuntimeError(CLOUDFLARE_RUNTIME_ERROR_CODES.INVALID_CONFIGURATION, { field: "uuid" });
    return value;
  }

  function planPublication(input = {}) {
    const publication = normalizePublication(input, config);
    const preimage = {
      provider: CLOUDFLARE_RUNTIME_PROVIDER,
      account_id: config.accountId,
      namespace_id: config.namespaceId,
      artifact_digest: publication.artifact_digest,
      request_digest: publication.request_digest,
      target: publication.target,
      resources: publication.resources,
      route: publication.route,
    };
    const planDigest = sha256(canonicalJson(preimage));
    return Object.freeze({
      status: "planned",
      qualification_status: "not_proven",
      qualification_reason: "plan_only",
      provider: CLOUDFLARE_RUNTIME_PROVIDER,
      account_id: config.accountId,
      namespace_id: config.namespaceId,
      artifact_digest: publication.artifact_digest,
      request_digest: publication.request_digest,
      plan_digest: planDigest,
      target: publication.target,
      resources: publication.resources,
      route: publication.route,
      direct_route_allowed: false,
      ingress_origin: config.ingressOrigin,
      limits: config.limits,
    });
  }

  async function reserveOperation(input = {}) {
    const operation = normalizeOperation(input, config);
    const existingId = idempotency.get(operation.idempotency_key);
    if (existingId) {
      const existing = operations.get(existingId);
      if (!existing || existing.request_digest !== operation.request_digest || existing.artifact_digest !== operation.artifact_digest) {
        throw new CloudflareRuntimeError(CLOUDFLARE_RUNTIME_ERROR_CODES.DIGEST_MISMATCH, { field: "idempotency_key" });
      }
      return publicOperation(existing);
    }
    if (operations.size >= config.limits.maxOperations) {
      throw new CloudflareRuntimeError(CLOUDFLARE_RUNTIME_ERROR_CODES.INVALID_INPUT, { field: "maxOperations" });
    }
    const value = {
      operation_id: operation.operation_id,
      idempotency_key: operation.idempotency_key,
      operation: operation.operation,
      artifact_digest: operation.artifact_digest,
      request_digest: operation.request_digest,
      target: operation.target,
      resources: operation.resources,
      route: operation.route,
      expected_generation: operation.expected_generation,
      state: "pending",
      provider_deployment_id: undefined,
      provider_version_id: undefined,
      started_at: now(),
      last_observed_at: undefined,
      provider_result: undefined,
    };
    operations.set(value.operation_id, value);
    idempotency.set(value.idempotency_key, value.operation_id);
    if (config.mode === "plan") return publicOperation({ ...value, state: "planned" });
    if (!runtimeAvailable) return publicNotProven(value, "live_runtime_unavailable");

    try {
      const result = await callProvider("POST", providerPath(config, operation), providerBody(operation), operation);
      const observed = normalizeProviderObservation(result, operation);
      Object.assign(value, observed, { state: "accepted", last_observed_at: now() });
      return publicOperation(value);
    } catch (error) {
      // A request may have reached Cloudflare before the connection failed;
      // preserve uncertainty for reconciliation and never blindly retry.
      Object.assign(value, { state: "uncertain", last_observed_at: now() });
      if (error instanceof CloudflareRuntimeError && error.code === CLOUDFLARE_RUNTIME_ERROR_CODES.DIGEST_MISMATCH) throw error;
      return publicNotProven(value, "provider_response_uncertain");
    }
  }

  async function inspectOperation(input) {
    const id = operationIdentifier(input);
    const operation = operations.get(id);
    if (!operation) throw new CloudflareRuntimeError(CLOUDFLARE_RUNTIME_ERROR_CODES.OPERATION_NOT_FOUND);
    if (operation.state === "planned") return publicOperation(operation);
    if (!runtimeAvailable) return publicNotProven(operation, "live_runtime_unavailable");
    if (operation.state === "pending") return publicOperation(operation);
    try {
      const result = await callProvider("GET", providerPath(config, operation), undefined, operation);
      const observed = normalizeProviderObservation(result, operation);
      Object.assign(operation, observed, { last_observed_at: now() });
      if (observed.state === "active") operation.state = "accepted";
      return publicOperation(operation);
    } catch (error) {
      if (error instanceof CloudflareRuntimeError && error.code === CLOUDFLARE_RUNTIME_ERROR_CODES.DIGEST_MISMATCH) throw error;
      return publicNotProven(operation, "provider_observation_unavailable");
    }
  }

  async function reconcileOperation(input) {
    const id = operationIdentifier(input);
    const operation = operations.get(id);
    if (!operation) throw new CloudflareRuntimeError(CLOUDFLARE_RUNTIME_ERROR_CODES.OPERATION_NOT_FOUND);
    if (config.mode === "plan") return publicNotProven(operation, "plan_only", "reconciliation_required");
    if (!runtimeAvailable) return publicNotProven(operation, "live_runtime_unavailable", "reconciliation_required");
    try {
      const result = await callProvider("GET", providerPath(config, operation), undefined, operation);
      const observed = normalizeProviderObservation(result, operation);
      const generation = observed.active_generation;
      const generationKey = operation.target.name;
      if (generation !== undefined) {
        const prior = generations.get(generationKey) ?? 0;
        if (generation < prior || (operation.expected_generation !== undefined && generation < operation.expected_generation)) {
          operation.state = "uncertain";
          throw new CloudflareRuntimeError(CLOUDFLARE_RUNTIME_ERROR_CODES.STALE_GENERATION, { field: "active_generation" });
        }
        generations.set(generationKey, generation);
      }
      Object.assign(operation, observed, { state: observed.state === "active" ? "reconciled" : "uncertain", last_observed_at: now() });
      return publicOperation(operation);
    } catch (error) {
      if (error instanceof CloudflareRuntimeError && [CLOUDFLARE_RUNTIME_ERROR_CODES.DIGEST_MISMATCH, CLOUDFLARE_RUNTIME_ERROR_CODES.STALE_GENERATION].includes(error.code)) throw error;
      return publicNotProven(operation, "provider_reconciliation_unavailable", "reconciliation_required");
    }
  }

  async function publishArtifact(input = {}) {
    const publication = normalizePublication(input, config);
    // Explicitly verify bytes if the caller supplies them. In normal hosted
    // operation only the immutable digest and an upstream object reference are
    // passed; the adapter never logs or echoes artifact bytes.
    verifyArtifactBytes(publication.artifact_bytes, publication.artifact_digest, config.limits.maxArtifactBytes);
    return reserveOperation({
      operation_id: publication.operation_id ?? operationId(),
      idempotency_key: publication.idempotency_key,
      operation: "publish",
      artifact_digest: publication.artifact_digest,
      request_digest: publication.request_digest,
      target: publication.target,
      resources: publication.resources,
      route: publication.route,
      expected_generation: publication.expected_generation,
    });
  }

  const adapter = {
    provider: CLOUDFLARE_RUNTIME_PROVIDER,
    mode: config.mode,
    runtimeAvailable,
    limits: config.limits,
    planPublication,
    reserveOperation,
    inspectOperation,
    reconcileOperation,
    publishArtifact,
    qualificationStatus() {
      return Object.freeze(runtimeAvailable
        ? { status: "available", provider: CLOUDFLARE_RUNTIME_PROVIDER, mode: config.mode }
        : { status: "not_proven", provider: CLOUDFLARE_RUNTIME_PROVIDER, mode: config.mode, reason: config.mode === "plan" ? "plan_only" : "live_runtime_unavailable" });
    },
  };
  return Object.freeze(adapter);

  async function callProvider(method, path, body, operation) {
    let authHeaders;
    try { authHeaders = await credentialProvider({ provider: CLOUDFLARE_RUNTIME_PROVIDER, operation: operation.operation }); }
    catch { throw new CloudflareRuntimeError(CLOUDFLARE_RUNTIME_ERROR_CODES.RUNTIME_UNAVAILABLE); }
    if (!authHeaders || typeof authHeaders !== "object") throw new CloudflareRuntimeError(CLOUDFLARE_RUNTIME_ERROR_CODES.RUNTIME_UNAVAILABLE);
    let response;
    try {
      response = await transport.request({
        method,
        path,
        headers: authHeaders,
        ...(body === undefined ? {} : { body }),
      });
    } catch { throw new CloudflareRuntimeError(CLOUDFLARE_RUNTIME_ERROR_CODES.RECONCILIATION_REQUIRED); }
    if (!response || typeof response !== "object") throw new CloudflareRuntimeError(CLOUDFLARE_RUNTIME_ERROR_CODES.RECONCILIATION_REQUIRED);
    const status = Number(response.status);
    if (Number.isFinite(status) && (status < 200 || status >= 300)) throw new CloudflareRuntimeError(CLOUDFLARE_RUNTIME_ERROR_CODES.PROVIDER_REJECTED, { status: Math.min(status, 999) });
    return response.body ?? response.result ?? response;
  }
}

// Compatibility aliases make the provider boundary discoverable without
// creating a second implementation or a second credential path.
export const createCloudflareProvider = createCloudflareRuntimeAdapter;
export const createCloudflareRuntimeProvider = createCloudflareRuntimeAdapter;

function normalizeConfig(input) {
  if (!input || typeof input !== "object" || Array.isArray(input)) fail(CLOUDFLARE_RUNTIME_ERROR_CODES.INVALID_CONFIGURATION);
  for (const key of Object.keys(input)) if (SECRET.test(key) && key !== "credentialProvider") fail(CLOUDFLARE_RUNTIME_ERROR_CODES.INVALID_CONFIGURATION, { field: key });
  const mode = input.mode ?? "plan";
  if (!CLOUDFLARE_ADAPTER_MODES.includes(mode)) fail(CLOUDFLARE_RUNTIME_ERROR_CODES.INVALID_CONFIGURATION, { field: "mode" });
  const accountId = input.accountId ?? input.account_id;
  if (typeof accountId !== "string" || !/^[0-9a-f]{32}$/i.test(accountId)) fail(CLOUDFLARE_RUNTIME_ERROR_CODES.INVALID_CONFIGURATION, { field: "accountId" });
  const namespaceId = input.namespaceId ?? input.namespace_id;
  if (typeof namespaceId !== "string" || !SAFE_NAME.test(namespaceId)) fail(CLOUDFLARE_RUNTIME_ERROR_CODES.INVALID_CONFIGURATION, { field: "namespaceId" });
  const apiBaseUrl = input.apiBaseUrl ?? "https://api.cloudflare.com/client/v4";
  let api;
  try { api = new URL(apiBaseUrl); } catch { fail(CLOUDFLARE_RUNTIME_ERROR_CODES.INVALID_CONFIGURATION, { field: "apiBaseUrl" }); }
  if (api.protocol !== "https:" || api.username || api.password || api.hostname !== "api.cloudflare.com") fail(CLOUDFLARE_RUNTIME_ERROR_CODES.INVALID_CONFIGURATION, { field: "apiBaseUrl" });
  const ingressOrigin = input.ingressOrigin;
  if (ingressOrigin !== undefined && (typeof ingressOrigin !== "string" || !ORIGIN.test(ingressOrigin))) fail(CLOUDFLARE_RUNTIME_ERROR_CODES.INVALID_CONFIGURATION, { field: "ingressOrigin" });
  const limits = normalizeLimits(input.limits);
  return Object.freeze({ mode, accountId: accountId.toLowerCase(), namespaceId, apiBaseUrl: api.toString().replace(/\/$/u, ""), ingressOrigin: ingressOrigin ?? undefined, limits });
}

function normalizeLimits(input = {}) {
  if (!input || typeof input !== "object" || Array.isArray(input)) fail(CLOUDFLARE_RUNTIME_ERROR_CODES.INVALID_CONFIGURATION, { field: "limits" });
  const output = {};
  for (const key of Object.keys(DEFAULT_LIMITS)) {
    const value = input[key] ?? DEFAULT_LIMITS[key];
    if (!Number.isSafeInteger(value) || value < 1 || value > DEFAULT_LIMITS[key]) fail(CLOUDFLARE_RUNTIME_ERROR_CODES.INVALID_CONFIGURATION, { field: `limits.${key}` });
    output[key] = value;
  }
  for (const key of Object.keys(input)) if (!(key in DEFAULT_LIMITS)) fail(CLOUDFLARE_RUNTIME_ERROR_CODES.INVALID_CONFIGURATION, { field: `limits.${key}` });
  return Object.freeze(output);
}

function normalizePublication(input, config) {
  if (!input || typeof input !== "object" || Array.isArray(input)) fail(CLOUDFLARE_RUNTIME_ERROR_CODES.INVALID_INPUT);
  rejectSecrets(input);
  const artifactDigest = input.artifact_digest ?? input.artifactDigest;
  if (!SHA256.test(artifactDigest ?? "")) fail(CLOUDFLARE_RUNTIME_ERROR_CODES.INVALID_INPUT, { field: "artifact_digest" });
  const requestDigest = input.request_digest ?? input.requestDigest;
  if (!SHA256.test(requestDigest ?? "")) fail(CLOUDFLARE_RUNTIME_ERROR_CODES.INVALID_INPUT, { field: "request_digest" });
  const target = normalizeTarget(input.target ?? { kind: input.resource_kind ?? "worker", name: input.name ?? config.namespaceId });
  const resources = normalizeResources(input.resources ?? [{ kind: target.kind, name: target.name }], config.limits.maxResources);
  const route = normalizeRoute(input.route, config);
  if (input.operation_id !== undefined && !OPERATION_ID.test(input.operation_id)) fail(CLOUDFLARE_RUNTIME_ERROR_CODES.INVALID_INPUT, { field: "operation_id" });
  const idempotencyKey = input.idempotency_key ?? input.idempotencyKey ?? `publish-${artifactDigest.slice(0, 24)}`;
  if (!OPERATION_ID.test(idempotencyKey)) fail(CLOUDFLARE_RUNTIME_ERROR_CODES.INVALID_INPUT, { field: "idempotency_key" });
  return { artifact_digest: artifactDigest, request_digest: requestDigest, artifact_bytes: input.artifact_bytes, operation_id: input.operation_id, idempotency_key: idempotencyKey, target, resources, route, expected_generation: normalizeGeneration(input.expected_generation) };
}

function normalizeOperation(input, config) {
  const publication = normalizePublication(input, config);
  const operationId = input.operation_id ?? input.operationId;
  if (!OPERATION_ID.test(operationId ?? "")) fail(CLOUDFLARE_RUNTIME_ERROR_CODES.INVALID_INPUT, { field: "operation_id" });
  const operation = input.operation ?? "publish";
  if (!["publish", "deploy", "activate-route", "suspend-route", "delete-deployment"].includes(operation)) fail(CLOUDFLARE_RUNTIME_ERROR_CODES.INVALID_INPUT, { field: "operation" });
  return { ...publication, operation, operation_id: operationId };
}

function normalizeTarget(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) fail(CLOUDFLARE_RUNTIME_ERROR_CODES.INVALID_INPUT, { field: "target" });
  const kind = value.kind;
  const name = value.name;
  if (!CLOUDFLARE_RESOURCE_KINDS.includes(kind)) fail(CLOUDFLARE_RUNTIME_ERROR_CODES.UNSUPPORTED_RESOURCE, { field: "target.kind" });
  if (typeof name !== "string" || !SAFE_NAME.test(name)) fail(CLOUDFLARE_RUNTIME_ERROR_CODES.INVALID_INPUT, { field: "target.name" });
  return Object.freeze({ kind, name });
}

function normalizeResources(input, max) {
  if (!Array.isArray(input) || input.length === 0 || input.length > max) fail(CLOUDFLARE_RUNTIME_ERROR_CODES.INVALID_INPUT, { field: "resources" });
  const seen = new Set();
  return Object.freeze(input.map((value, index) => {
    const resource = normalizeTarget(value);
    const key = `${resource.kind}:${resource.name}`;
    if (seen.has(key)) fail(CLOUDFLARE_RUNTIME_ERROR_CODES.INVALID_INPUT, { field: `resources[${index}]` });
    seen.add(key);
    return resource;
  }));
}

function normalizeRoute(value, config) {
  if (value === undefined) return undefined;
  if (!value || typeof value !== "object" || Array.isArray(value)) fail(CLOUDFLARE_RUNTIME_ERROR_CODES.INVALID_INPUT, { field: "route" });
  rejectSecrets(value);
  if (typeof value.pattern !== "string" || value.pattern.length === 0 || value.pattern.length > 256 || /[\u0000-\u001f\u007f]/u.test(value.pattern)) fail(CLOUDFLARE_RUNTIME_ERROR_CODES.INVALID_INPUT, { field: "route.pattern" });
  // A provider hostname is informational only. The canonical route is always
  // AgentPass ingress and direct provider URLs are never granted authority.
  return Object.freeze({ pattern: value.pattern, direct_route_allowed: false, ingress_origin: config.ingressOrigin });
}

function normalizeGeneration(value) {
  if (value === undefined) return undefined;
  if (!Number.isSafeInteger(value) || value < 1) fail(CLOUDFLARE_RUNTIME_ERROR_CODES.INVALID_INPUT, { field: "expected_generation" });
  return value;
}

function normalizeProviderObservation(value, operation) {
  const object = value && typeof value === "object" && !Array.isArray(value) ? value : {};
  const providerDigest = object.artifact_digest ?? object.artifactDigest ?? object.metadata?.artifact_digest ?? object.metadata?.artifactDigest;
  if (providerDigest !== undefined && providerDigest !== operation.artifact_digest) throw new CloudflareRuntimeError(CLOUDFLARE_RUNTIME_ERROR_CODES.DIGEST_MISMATCH, { field: "artifact_digest" });
  const state = object.state ?? object.status;
  const active = state === "active" || state === "succeeded" || state === "ready" || object.success === true;
  const failed = state === "failed" || object.success === false;
  const activeGeneration = object.active_generation ?? object.activeGeneration;
  if (activeGeneration !== undefined && (!Number.isSafeInteger(activeGeneration) || activeGeneration < 1)) throw new CloudflareRuntimeError(CLOUDFLARE_RUNTIME_ERROR_CODES.RECONCILIATION_REQUIRED, { field: "active_generation" });
  return {
    state: active ? "active" : failed ? "failed" : "uncertain",
    provider_deployment_id: safeProviderId(object.provider_deployment_id ?? object.deployment_id ?? object.id),
    provider_version_id: safeProviderId(object.provider_version_id ?? object.version_id ?? object.version),
    active_generation: activeGeneration,
    route: operation.route,
    provider_result_digest: sha256(canonicalJson(redactProviderMetadata(object))),
  };
}

function providerPath(config, operation) {
  const account = encodeURIComponent(config.accountId);
  const name = encodeURIComponent(operation.target.name);
  if (operation.target.kind === "worker") return `${config.apiBaseUrl}/accounts/${account}/workers/scripts/${name}`;
  if (operation.target.kind === "pages") return `${config.apiBaseUrl}/accounts/${account}/pages/projects/${name}/deployments`;
  if (operation.target.kind === "r2") return `${config.apiBaseUrl}/accounts/${account}/r2/buckets/${name}`;
  if (operation.target.kind === "d1") return `${config.apiBaseUrl}/accounts/${account}/d1/database/${name}`;
  return UNSUPPORTED;
}

function providerBody(operation) {
  return { agentpass: { provider: CLOUDFLARE_RUNTIME_PROVIDER, operation: operation.operation, artifact_digest: operation.artifact_digest, request_digest: operation.request_digest, target: operation.target, resources: operation.resources, route: operation.route, expected_generation: operation.expected_generation } };
}

function verifyArtifactBytes(bytes, digest, max) {
  if (bytes === undefined) return;
  if (!(bytes instanceof Uint8Array) || bytes.byteLength > max) fail(CLOUDFLARE_RUNTIME_ERROR_CODES.INVALID_INPUT, { field: "artifact_bytes" });
  if (sha256(bytes) !== digest) throw new CloudflareRuntimeError(CLOUDFLARE_RUNTIME_ERROR_CODES.DIGEST_MISMATCH, { field: "artifact_bytes" });
}

function operationIdentifier(input) {
  const id = typeof input === "string" ? input : input?.operation_id ?? input?.operationId;
  if (!OPERATION_ID.test(id ?? "")) fail(CLOUDFLARE_RUNTIME_ERROR_CODES.INVALID_INPUT, { field: "operation_id" });
  return id;
}

function publicOperation(value) {
  return Object.freeze({
    status: value.state === "planned" ? "planned" : value.state === "uncertain" ? "uncertain" : "accepted",
    provider: CLOUDFLARE_RUNTIME_PROVIDER,
    operation_id: value.operation_id,
    operation: value.operation,
    state: value.state,
    artifact_digest: value.artifact_digest,
    request_digest: value.request_digest,
    target: value.target,
    resources: value.resources,
    route: value.route,
    provider_deployment_id: value.provider_deployment_id,
    provider_version_id: value.provider_version_id,
    active_generation: value.active_generation,
    started_at: value.started_at,
    observed_at: value.last_observed_at,
    direct_route_allowed: false,
    ...(value.provider_result_digest ? { provider_result_digest: value.provider_result_digest } : {}),
  });
}

function publicNotProven(value, reason, state = "unknown") {
  return Object.freeze({
    ...publicOperation(value),
    status: "not_proven",
    state,
    qualification_status: "not_proven",
    qualification_reason: reason,
  });
}

function safeProviderId(value) {
  if (value === undefined || value === null) return undefined;
  if (typeof value !== "string" || value.length === 0 || value.length > 256 || /[\u0000-\u001f\u007f]/u.test(value)) return undefined;
  return value;
}

function redactProviderMetadata(value) {
  if (Array.isArray(value)) return value.map(redactProviderMetadata);
  if (!value || typeof value !== "object") return typeof value === "string" && value.length > 256 ? "[bounded]" : value;
  return Object.fromEntries(Object.entries(value).filter(([key]) => !SECRET.test(key)).map(([key, child]) => [key, redactProviderMetadata(child)]));
}

function rejectSecrets(value) {
  if (!value || typeof value !== "object") return;
  if (Array.isArray(value)) return value.forEach(rejectSecrets);
  for (const [key, child] of Object.entries(value)) {
    if (SECRET.test(key)) fail(CLOUDFLARE_RUNTIME_ERROR_CODES.INVALID_INPUT, { issue: "secret_like_input" });
    rejectSecrets(child);
  }
}

function safeDetails(value) {
  const details = {};
  if (value && typeof value === "object") {
    for (const key of ["field", "issue", "reason", "status", "stage"]) if (typeof value[key] === "string" || Number.isSafeInteger(value[key])) details[key] = value[key];
  }
  return details;
}

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function canonicalJson(value) {
  return JSON.stringify(value, (_, child) => child && typeof child === "object" && !Array.isArray(child)
    ? Object.fromEntries(Object.keys(child).sort().map((key) => [key, child[key]]))
    : child);
}

function fail(code, details) {
  throw new CloudflareRuntimeError(code, details);
}

