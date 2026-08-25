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

export const isTestOnlyDependency = (dependency) => dependency?.testOnly === true;
