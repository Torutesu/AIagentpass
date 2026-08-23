import { createPostgresAuditRepository } from "./audit-repository.mjs";
import { createPostgresAdminAuditRepository } from "./admin-audit-repository.mjs";
import { createCapabilityAuthorityRepository } from "./capability-authority-repository.mjs";
import { createPostgresCapabilityReservationRepository } from "./capability-reservation-repository.mjs";
import { createControlPlaneAuthorityRepository } from "./control-plane-authority-repository.mjs";
import { createPostgresControlPlaneResourceRepository } from "./control-plane-resource-repository.mjs";
import { createPostgresDeviceManualWakeRepository } from "./device-manual-wake-repository.mjs";
import { createPostgresOrganizationRepository } from "./organization-repository.mjs";
import { createSharedControlRepository } from "./shared-control-repository.mjs";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;

/**
 * The enumerable object contract currently consumed by server.mjs remains
 * unchanged. The facade is intentionally smaller than the repositories it
 * composes; the two non-enumerable transaction primitives are opt-in for
 * callers that can supply a transaction-aware mutation callback.
 */
export const CONTROL_PLANE_STORE_METHODS = Object.freeze([
  "appendAdminAuditEvent",
  "assignBundleHead",
  "completeDeviceEnrollment",
  "createAgent",
  "createDevice",
  "createDeviceEnrollment",
  "createPolicy",
  "createRevocation",
  "getAuditHealth",
  "getOrganization",
  "ingestDeviceAuditEvents",
  "issueCapabilityMetadata",
  "listAdminAuditEvents",
  "listAgents",
  "listCapabilities",
  "listDeviceAuditEvents",
  "listDevices",
  "listDeviceReadModels",
  "listPolicies",
  "listRevocations",
  "listRevokedCapabilityIds",
  "reserveCapability",
  "requestDeviceWake",
  "updatePolicy"
]);

/** Opt-in methods kept non-enumerable so the existing CloudStore contract is unchanged. */
export const CONTROL_PLANE_TRANSACTION_METHODS = Object.freeze([
  "withTransaction",
  "runAtomicMutation"
]);

export const CONTROL_PLANE_STORE_ERROR_CODES = Object.freeze({
  DATABASE: "ERR_DATABASE",
  METHOD_UNAVAILABLE: "ERR_CONTROL_PLANE_UNAVAILABLE",
  TENANT_SCOPE: "ERR_TENANT_SCOPE"
});

const DATABASE_MESSAGE = "control-plane database operation failed";
const UNAVAILABLE_MESSAGE = "control-plane operation is unavailable";
const DATABASE_ERROR_CODES = new Set(["ERR_DATABASE", "ERR_DB_CLIENT", "ERR_DB_RESULT", "XX000", "08000", "08003", "08006"]);
const STORAGE_DIAGNOSTIC_CODES = new Set(["42501", "42P01", "42703", "42883", "23503", "23505", "55P03", "40001", "57014", "08000", "08003", "08006", "XX000"]);
const SAFE_IDENTITY_KEYS = new Set(["member_id", "organization_id", "role", "device_id", "enrollment_id"]);
const DEVICE_PLANE_SENSITIVE_KEYS = new Set([
  "accesstoken", "authorization", "bearertoken", "password", "privatekey", "privatekeypem",
  "secret", "secretkey", "sessionsecret"
]);

export class ControlPlaneStoreError extends Error {
  constructor(code, message, status = undefined, cause = undefined) {
    super(message);
    this.name = "ControlPlaneStoreError";
    this.code = code;
    if (status !== undefined) this.status = status;
    const storageCode = findStorageDiagnosticCode(cause);
    if (storageCode !== undefined) Object.defineProperty(this, "storageCode", { value: storageCode, enumerable: false });
    const storagePhase = findStorageDiagnosticPhase(cause);
    if (storagePhase !== undefined) Object.defineProperty(this, "storagePhase", { value: storagePhase, enumerable: false });
    const storageReason = findStorageDiagnosticReason(cause);
    if (storageReason !== undefined) Object.defineProperty(this, "storageReason", { value: storageReason, enumerable: false });
    const storageIdentity = findStorageDiagnosticIdentity(cause);
    if (storageIdentity !== undefined) Object.defineProperty(this, "storageIdentity", { value: storageIdentity, enumerable: false });
  }
}

/**
 * Compose the PostgreSQL control-plane repositories behind the CloudStore
 * contract.  Repository instances may be injected for tests or for a
 * runtime-owned pool; missing components remain unavailable rather than being
 * replaced with unsafe SQL or inferred authority.
 */
export function createPostgresControlPlaneStore(options = {}) {
  if (!options || typeof options !== "object" || Array.isArray(options)) throw new TypeError("control-plane store options must be an object");

  const client = options.client;
  const now = options.now ?? (() => new Date().toISOString());
  if (typeof now !== "function") throw new TypeError("now must be a function");
  const cursorCodec = options.cursorCodec;
  const cursorSecret = options.cursorSecret ?? options.auditCursorSecret;

  const organizationRepository = options.organizationRepository ?? options.organization ?? (client ? createPostgresOrganizationRepository({ client, now }) : undefined);
  const resourceRepository = options.resourceRepository ?? options.resource ?? (client ? createPostgresControlPlaneResourceRepository({ client, now, onAuthorityReduction: options.onAuthorityReduction, onDeviceEnrollmentActivated: options.onDeviceEnrollmentActivated }) : undefined);
  const authorityRepository = options.authorityRepository ?? options.authority ?? (client && (cursorCodec || cursorSecret) ? createControlPlaneAuthorityRepository({ client, cursorCodec, cursorSecret, refreshNonceCodec: options.refreshNonceCodec, now, onRevocation: options.onRevocation }) : undefined);
  const auditRepository = options.auditRepository ?? options.audit ?? (client && (cursorCodec || cursorSecret) ? createPostgresAuditRepository({ client, cursorCodec, cursorSecret, now: () => clockMillis(now) }) : undefined);
  const adminAuditRepository = options.adminAuditRepository ?? options.adminAudit ?? (client ? createPostgresAdminAuditRepository({ client, now }) : undefined);
  const sharedControlRepository = options.sharedControlRepository ?? options.sharedControl ?? (client ? createSharedControlRepository({ client }) : undefined);
  const capabilityAuthorityRepository = options.capabilityAuthorityRepository ?? options.capabilityAuthority ?? (client ? createCapabilityAuthorityRepository({ client, now }) : undefined);
  const capabilityReservationRepository = options.capabilityReservationRepository ?? options.capabilityReservation
    ?? (client && options.capabilityNonceSecret ? createPostgresCapabilityReservationRepository({ client, nonceSecret: options.capabilityNonceSecret, now }) : undefined);
  const deviceManualWakeRepository = options.deviceManualWakeRepository ?? options.deviceManualWake
    ?? (client ? createPostgresDeviceManualWakeRepository({ client, now }) : undefined);

  const delegate = (repository, method, operation, { tenant = true, context = false } = {}) => async (input = {}) => {
    const fn = repository?.[method];
    if (typeof fn !== "function") throw unavailable(operation);
    const qualified = tenant ? qualifyTenant(input, operation) : cloneInput(input);
    return callRepository(fn, repository, operation, context ? addAuthorityContext(qualified) : qualified);
  };

  const createRevocation = async (input = {}) => {
    const qualified = addAuthorityContext(qualifyTenant(input, "createRevocation"));
    const reduction = authorityRepository?.reduceAuthorityAndEnqueueRefresh;
    if (typeof reduction === "function") {
      const result = await callRepository(reduction, authorityRepository, "createRevocation", { ...qualified, reduction: qualified });
      if (!result || typeof result !== "object" || Array.isArray(result) || !result.revocation) throw unavailable("createRevocation");
      return result.revocation;
    }
    return delegate(authorityRepository, "createRevocation", "createRevocation", { context: true })(input);
  };

  const api = {
    appendAdminAuditEvent: delegate(adminAuditRepository, "appendAdminAuditEvent", "appendAdminAuditEvent", { context: true }),
    assignBundleHead: delegate(authorityRepository, "assignBundleHead", "assignBundleHead", { context: true }),
    completeDeviceEnrollment: delegate(resourceRepository, "completeDeviceEnrollment", "completeDeviceEnrollment", { context: true }),
    createAgent: delegate(resourceRepository, "createAgent", "createAgent", { context: true }),
    createDevice: delegate(resourceRepository, "createDevice", "createDevice", { context: true }),
    createDeviceEnrollment: delegate(resourceRepository, "createDeviceEnrollment", "createDeviceEnrollment", { context: true }),
    createPolicy: delegate(resourceRepository, "createPolicy", "createPolicy", { context: true }),
    createRevocation,
    getAuditHealth: delegate(authorityRepository, "getAuditHealth", "getAuditHealth", { context: true }),
    getOrganization: delegate(organizationRepository, "getOrganization", "getOrganization"),
    ingestDeviceAuditEvents: delegate(authorityRepository, "ingestDeviceAuditEvents", "ingestDeviceAuditEvents", { context: true }),
    issueCapabilityMetadata: delegate(capabilityAuthorityRepository ?? authorityRepository, "issueCapabilityMetadata", "issueCapabilityMetadata", { context: true }),
    listAdminAuditEvents: delegate(adminAuditRepository, "listAdminAuditEvents", "listAdminAuditEvents"),
    listAgents: delegate(resourceRepository, "listAgents", "listAgents"),
    listCapabilities: delegate(capabilityReservationRepository ?? capabilityAuthorityRepository ?? authorityRepository, "listCapabilities", "listCapabilities"),
    listDeviceAuditEvents: delegate(auditRepository ?? authorityRepository, "listDeviceAuditEvents", "listDeviceAuditEvents", { context: true }),
    listDevices: delegate(resourceRepository, "listDevices", "listDevices"),
    listDeviceReadModels: delegate(resourceRepository, "listDeviceReadModels", "listDeviceReadModels"),
    listPolicies: delegate(resourceRepository, "listPolicies", "listPolicies"),
    listRevocations: delegate(authorityRepository, "listRevocations", "listRevocations"),
    listRevokedCapabilityIds: delegate(capabilityAuthorityRepository ?? authorityRepository, "listRevokedCapabilityIds", "listRevokedCapabilityIds"),
    reserveCapability: delegate(capabilityReservationRepository ?? capabilityAuthorityRepository ?? resourceRepository, "reserveCapability", "reserveCapability", { context: true }),
    requestDeviceWake: delegate(deviceManualWakeRepository, "requestDeviceWake", "requestDeviceWake", { context: true }),
    updatePolicy: delegate(resourceRepository, "updatePolicy", "updatePolicy", { context: true })
  };

  Object.defineProperties(api, {
    snapshotAndAssignBundleHead: {
      enumerable: false,
      value: devicePlaneDelegate(authorityRepository, "snapshotAndAssignBundleHead", "snapshotAndAssignBundleHead", { context: true })
    },
    pollDeviceRefresh: {
      enumerable: false,
      value: devicePlaneDelegate(authorityRepository, "pollDeviceRefresh", "pollDeviceRefresh")
    },
    markDeviceRefreshDelivered: {
      enumerable: false,
      value: devicePlaneDelegate(authorityRepository, "markDeviceRefreshDelivered", "markDeviceRefreshDelivered")
    },
    getDeviceRefreshState: {
      enumerable: false,
      value: devicePlaneDelegate(authorityRepository, "getDeviceRefreshState", "getDeviceRefreshState")
    },
    getDevice: {
      enumerable: false,
      value: async (input = {}) => {
        const fn = resourceRepository?.getDevice;
        if (typeof fn !== "function") throw unavailable("getDevice");
        return callRepository(fn, resourceRepository, "getDevice", qualifyTenant(input, "getDevice"));
      }
    },
    // v2 enrollment/release methods are opt-in so older enumerable adapters
    // cannot accidentally depend on the newer possession contract.
    resolveActiveReleaseCandidate: {
      enumerable: false,
      value: async (input = {}) => {
        const fn = resourceRepository?.resolveActiveReleaseCandidate;
        if (typeof fn !== "function") throw unavailable("resolveActiveReleaseCandidate");
        return callRepository(fn, resourceRepository, "resolveActiveReleaseCandidate", cloneInput(input));
      }
    },
    createDeviceEnrollmentV2: {
      enumerable: false,
      value: async (input = {}) => {
        const fn = resourceRepository?.createDeviceEnrollmentV2;
        if (typeof fn !== "function") throw unavailable("createDeviceEnrollmentV2");
        return callRepository(fn, resourceRepository, "createDeviceEnrollmentV2", addAuthorityContext(qualifyTenant(input, "createDeviceEnrollmentV2")));
      }
    },
    completeDeviceEnrollmentV2: {
      enumerable: false,
      value: async (input = {}) => {
        const fn = resourceRepository?.completeDeviceEnrollmentV2;
        if (typeof fn !== "function") throw unavailable("completeDeviceEnrollmentV2");
        return callRepository(fn, resourceRepository, "completeDeviceEnrollmentV2", qualifyTenant(input, "completeDeviceEnrollmentV2"));
      }
    },
    getDeviceEnrollmentPossessionReceipt: {
      enumerable: false,
      value: async (input = {}) => {
        const fn = resourceRepository?.getDeviceEnrollmentPossessionReceipt;
        if (typeof fn !== "function") throw unavailable("getDeviceEnrollmentPossessionReceipt");
        return callRepository(fn, resourceRepository, "getDeviceEnrollmentPossessionReceipt", qualifyTenant(input, "getDeviceEnrollmentPossessionReceipt"));
      }
    },
    acknowledgeBundle: {
      enumerable: false,
      value: devicePlaneDelegate(authorityRepository, "acknowledgeBundle", "acknowledgeBundle")
    },
    withTransaction: {
      enumerable: false,
      value: async (operation) => {
        if (typeof sharedControlRepository?.withTransaction !== "function") throw unavailable("withTransaction");
        if (typeof operation !== "function") throw new ControlPlaneStoreError(CONTROL_PLANE_STORE_ERROR_CODES.METHOD_UNAVAILABLE, UNAVAILABLE_MESSAGE, 503);
        try {
          return await sharedControlRepository.withTransaction(operation);
        } catch (error) {
          throw publicError(error, "withTransaction");
        }
      }
    },
    runAtomicMutation: {
      enumerable: false,
      value: async (input = {}) => {
        if (typeof sharedControlRepository?.withTransaction !== "function"
          || typeof adminAuditRepository?.appendAdminAuditEventInTransaction !== "function") {
          throw unavailable("runAtomicMutation");
        }
        if (!input || typeof input !== "object" || Array.isArray(input)
          || typeof input.mutation !== "function") {
          throw new ControlPlaneStoreError(CONTROL_PLANE_STORE_ERROR_CODES.METHOD_UNAVAILABLE, UNAVAILABLE_MESSAGE, 503);
        }
        const scope = qualifyTenant(input, "runAtomicMutation");
        try {
          return await sharedControlRepository.withTransaction(async (tx) => {
            const transactionClient = transactionBoundClient(tx);
            const transactionStore = createPostgresControlPlaneStore({
              ...options,
              client: transactionClient,
              organizationRepository: undefined, organization: undefined,
              resourceRepository: undefined, resource: undefined,
              authorityRepository: undefined, authority: undefined,
              auditRepository: undefined, audit: undefined,
              adminAuditRepository: undefined, adminAudit: undefined,
              sharedControlRepository: undefined, sharedControl: undefined,
              capabilityAuthorityRepository: undefined, capabilityAuthority: undefined,
              capabilityReservationRepository: undefined, capabilityReservation: undefined,
              deviceManualWakeRepository: undefined, deviceManualWake: undefined
            });
            const mutation = await input.mutation({ tx, store: transactionStore, organizationId: scope.organization_id });
            const auditInput = typeof input.audit === "function"
              ? await input.audit({ tx, mutation })
              : input.audit;
            if (!auditInput || typeof auditInput !== "object" || Array.isArray(auditInput)) {
              throw new ControlPlaneStoreError(CONTROL_PLANE_STORE_ERROR_CODES.METHOD_UNAVAILABLE, UNAVAILABLE_MESSAGE, 503);
            }
            const auditOrganizationId = auditInput.organization_id ?? auditInput.organizationId;
            if (typeof auditOrganizationId !== "string" || auditOrganizationId.toLowerCase() !== scope.organization_id) {
              throw new ControlPlaneStoreError(CONTROL_PLANE_STORE_ERROR_CODES.TENANT_SCOPE, "runAtomicMutation audit organization_id does not match the mutation", 400);
            }
            const audit = await adminAuditRepository.appendAdminAuditEventInTransaction({ ...auditInput, tx });
            return Object.freeze({ mutation, audit });
          });
        } catch (error) {
          throw publicError(error, "runAtomicMutation");
        }
      }
    }
  });

  return Object.freeze(api);

}

function devicePlaneDelegate(repository, method, operation, { context = false } = {}) {
  return async (input = {}) => {
    const fn = repository?.[method];
    if (typeof fn !== "function") throw unavailable(operation);
    const qualified = qualifyTenant(input, operation);
    const safe = stripDevicePlaneSensitiveInput(qualified);
    return callRepository(fn, repository, operation, context ? addAuthorityContext(safe) : safe);
  };
}

export const createControlPlaneStore = createPostgresControlPlaneStore;
export default createPostgresControlPlaneStore;

function qualifyTenant(input, operation) {
  const value = cloneInput(input);
  const organizationId = value.organization_id ?? value.organizationId;
  if (typeof organizationId !== "string" || !UUID.test(organizationId)) throw new ControlPlaneStoreError(CONTROL_PLANE_STORE_ERROR_CODES.TENANT_SCOPE, `${operation} requires a valid organization_id`, 400);
  value.organization_id = organizationId.toLowerCase();
  return value;
}

function addAuthorityContext(input) {
  const value = cloneInput(input);
  const actor = safeIdentity(value.actor);
  const principal = safeIdentity(value.principal);
  const actorId = value.actor_member_id ?? value.actorMemberId ?? value.actor_id ?? value.actorId ?? actor?.member_id;
  const principalId = value.principal_id ?? value.principalId ?? principal?.member_id;
  const createdBy = value.created_by ?? value.createdBy ?? actorId ?? principalId;
  if (actor) value.actor = actor;
  if (principal) value.principal = principal;
  if (actorId !== undefined) value.actor_member_id = actorId;
  if (principalId !== undefined) value.principal_id = principalId;
  if (createdBy !== undefined) value.created_by = createdBy;
  return value;
}

function safeIdentity(value) {
  if (value === undefined) return undefined;
  if (!value || typeof value !== "object" || Array.isArray(value)) return undefined;
  const identity = {};
  for (const key of SAFE_IDENTITY_KEYS) if (typeof value[key] === "string") identity[key] = value[key];
  return Object.keys(identity).length === 0 ? undefined : identity;
}

function cloneInput(input) {
  if (input === undefined) return {};
  if (!input || typeof input !== "object" || Array.isArray(input)) return input;
  return { ...input };
}

function stripDevicePlaneSensitiveInput(input) {
  if (!input || typeof input !== "object" || Array.isArray(input)) return input;
  const result = {};
  for (const [key, value] of Object.entries(input)) {
    if (DEVICE_PLANE_SENSITIVE_KEYS.has(normalizeInputKey(key))) continue;
    result[key] = stripNestedDevicePlaneSensitiveInput(value);
  }
  return result;
}

function stripNestedDevicePlaneSensitiveInput(value) {
  if (Array.isArray(value)) return value.map((item) => stripNestedDevicePlaneSensitiveInput(item));
  if (!value || typeof value !== "object" || Object.getPrototypeOf(value) !== Object.prototype) return value;
  return stripDevicePlaneSensitiveInput(value);
}

function normalizeInputKey(key) {
  return String(key).replace(/[-_]/gu, "").toLowerCase();
}

async function callRepository(fn, repository, operation, input) {
  try {
    return await fn.call(repository, input);
  } catch (error) {
    throw publicError(error, operation);
  }
}

function publicError(error, operation) {
  if (error instanceof ControlPlaneStoreError) return error;
  if (isDatabaseError(error)) return new ControlPlaneStoreError(CONTROL_PLANE_STORE_ERROR_CODES.DATABASE, DATABASE_MESSAGE, 503, error);
  if (error && typeof error.code === "string" && (error.code.startsWith("ERR_") || error.code === "shared_control_unavailable" || error.code === "idempotency_conflict")) return error;
  return new ControlPlaneStoreError(CONTROL_PLANE_STORE_ERROR_CODES.DATABASE, DATABASE_MESSAGE, 503, error);
}

function findStorageDiagnosticCode(error) {
  let current = error;
  for (let depth = 0; depth < 4 && current; depth += 1) {
    const code = typeof current.code === "string" ? current.code.toUpperCase() : "";
    if (STORAGE_DIAGNOSTIC_CODES.has(code)) return code;
    current = current.cause;
  }
  return undefined;
}
function findStorageDiagnosticPhase(error) {
  let current = error;
  for (let depth = 0; depth < 4 && current; depth += 1) {
    if (typeof current.storagePhase === "string" && /^[a-z][a-z0-9_]{0,63}$/u.test(current.storagePhase)) return current.storagePhase;
    current = current.cause;
  }
  return undefined;
}
function findStorageDiagnosticReason(error) {
  let current = error;
  for (let depth = 0; depth < 4 && current; depth += 1) {
    const message = typeof current.message === "string" ? current.message : "";
    if (/permission denied for function/iu.test(message)) return "function_permission";
    if (/permission denied for (?:relation|table)/iu.test(message)) {
      if (/memberships/iu.test(message)) return "table_permission_memberships";
      if (/device_manual_wake/iu.test(message)) return "table_permission_manual_wake";
      return "table_permission";
    }
    if (/SELECT FOR (?:UPDATE|NO KEY UPDATE|SHARE|KEY SHARE) is not allowed/iu.test(message)) return "lock_function";
    if (/must be owner/iu.test(message)) return "owner_required";
    current = current.cause;
  }
  return undefined;
}
function findStorageDiagnosticIdentity(error) {
  let current = error;
  for (let depth = 0; depth < 4 && current; depth += 1) {
    if (typeof current.storageIdentity === "string" && /^[a-z][a-z0-9_]{0,127}$/u.test(current.storageIdentity)) return current.storageIdentity;
    current = current.cause;
  }
  return undefined;
}

function isDatabaseError(error) {
  const code = String(error?.code ?? "");
  return DATABASE_ERROR_CODES.has(code) || code.startsWith("08") || code.startsWith("53") || code === "23505" || code === "23503" || code === "XX000";
}

function unavailable(operation) {
  return new ControlPlaneStoreError(CONTROL_PLANE_STORE_ERROR_CODES.METHOD_UNAVAILABLE, UNAVAILABLE_MESSAGE, 503);
}

function clockMillis(now) {
  const value = now();
  const milliseconds = typeof value === "number" ? value : value instanceof Date ? value.getTime() : Date.parse(value);
  if (!Number.isSafeInteger(milliseconds)) throw new TypeError("now must return a valid time");
  return milliseconds;
}

function transactionBoundClient(tx) {
  return Object.freeze({
    async query(text, params) {
      if (text === "BEGIN" || text === "COMMIT" || text === "ROLLBACK") return { rows: [], rowCount: 0 };
      return tx.query(text, params);
    }
  });
}
