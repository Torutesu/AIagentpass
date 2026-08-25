import { SmallSoftwareError, SMALL_SOFTWARE_ERROR_CODES } from "./errors.mjs";

const requireMethods = (value, methods, kind) => {
  if (!value || typeof value !== "object") throw new SmallSoftwareError(SMALL_SOFTWARE_ERROR_CODES.INVALID_CONFIGURATION);
  for (const method of methods) if (typeof value[method] !== "function") {
    throw new SmallSoftwareError(SMALL_SOFTWARE_ERROR_CODES.INVALID_CONFIGURATION);
  }
  return value;
};
const hostedDependencies = new WeakSet();
const registerHostedDependency = (value) => { if (!value || typeof value !== "object") throw new SmallSoftwareError(SMALL_SOFTWARE_ERROR_CODES.INVALID_CONFIGURATION); hostedDependencies.add(value); return value; };
export const isRegisteredHostedDependency = (value) => hostedDependencies.has(value);

/** Repository authority for app manifests, source bundles, and build receipts. */
export const smallSoftwareRepository = (repository) => requireMethods(repository, ["getApplication", "saveBuildReceipt"], "small-software-repository");
/** Provider adapter: reserve an effect, then inspect its independently observed result. */
export const smallSoftwareProvider = (provider) => requireMethods(provider, ["reserveOperation", "inspectOperation", "reconcileOperation"], "small-software-provider");
export const smallSoftwareClock = (clock) => requireMethods(clock, ["now"], "clock");
export const smallSoftwareUuid = (uuid) => requireMethods(uuid, ["randomUUID"], "uuid");

/** Content-addressed source object boundary. Implementations must not accept
 * credentials or return provider-specific errors to the cloud API. */
export const smallSoftwareSourceStorage = (storage) => requireMethods(storage, ["put", "get", "delete"], "small-software-source-storage");
/** Isolated build runner boundary. A runner receives a digest-bound request,
 * never the cloud API's production credentials. */
export const smallSoftwareBuildRunner = (runner) => requireMethods(runner, ["reserve", "inspect", "reconcile"], "small-software-build-runner");
/** Durable workflow/idempotency repository used by the orchestration service. */
export const smallSoftwareWorkflowRepository = (repository) => requireMethods(repository, ["getWorkflow", "saveWorkflow", "savePublishPlan", "saveDeploymentReceipt"], "small-software-workflow-repository");

/**
 * App authorization authority. Implementations must route mutations through
 * tenant-bound database functions; this service never accepts table DML or a
 * provider SDK. Idempotency records are keyed by the complete request digest.
 */
export const smallSoftwareAuthorizationRepository = (repository) => requireMethods(repository, [
  "getApplication", "listAccessRules", "saveAccessRule", "revokeAccessRule",
  "getInvitation", "saveInvitation", "revokeInvitation", "getRoute",
  "getShare", "saveShare", "revokeShare", "getAuthorizationOperation", "saveAuthorizationOperation",
], "small-software-authorization-repository");

export const isTestOnlyDependency = (dependency) => dependency?.testOnly === true;
