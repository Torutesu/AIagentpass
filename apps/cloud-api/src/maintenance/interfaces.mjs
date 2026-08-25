import { MaintenanceError, MAINTENANCE_ERROR_CODES } from "./errors.mjs";
const requireMethods = (value, methods) => { if (!value || typeof value !== "object" || methods.some((method) => typeof value[method] !== "function")) throw new MaintenanceError(MAINTENANCE_ERROR_CODES.INVALID_CONFIGURATION); return value; };
const hostedDependencies = new WeakSet();
const registerHostedDependency = (value) => { if (!value || typeof value !== "object") throw new MaintenanceError(MAINTENANCE_ERROR_CODES.INVALID_CONFIGURATION); hostedDependencies.add(value); return value; };
export const isRegisteredHostedDependency = (value) => hostedDependencies.has(value);
export const maintenanceRepository = (value) => requireMethods(value, ["getPolicy", "saveReceipt"]);
export const maintenanceProvider = (value) => requireMethods(value, ["reserveOperation", "inspectOperation", "reconcileOperation"]);
export const maintenanceClock = (value) => requireMethods(value, ["now"]);
export const maintenanceUuid = (value) => requireMethods(value, ["randomUUID"]);
export const maintenanceSandbox = (value) => requireMethods(value, ["reserve", "inspect"]);
/** Customer repository snapshot authority; it never exposes repository tokens. */
export const maintenanceSnapshotRepository = (value) => requireMethods(value, ["getSnapshot", "saveSnapshot"]);
/** Usage classification is evidence-only and contains no source or payload data. */
export const maintenanceUsageRepository = (value) => requireMethods(value, ["getAttestation", "saveAttestation"]);
/** Durable job lifecycle authority. Effects are reserved before external work. */
export const maintenanceJobRepository = (value) => requireMethods(value, ["reserveJob", "getJob", "updateJob"]);
export const maintenanceEffectRepository = (value) => requireMethods(value, ["reserve", "complete", "reconcile"]);
export const maintenanceResultRepository = (value) => requireMethods(value, ["saveResult"]);
export const maintenancePullRequestRepository = (value) => requireMethods(value, ["savePullRequest"]);
export const maintenanceReceiptRepository = (value) => requireMethods(value, ["saveReceipt"]);
export const isTestOnlyDependency = (value) => value?.testOnly === true;
