import { MaintenanceError, MAINTENANCE_ERROR_CODES } from "./errors.mjs";
const requireMethods = (value, methods) => { if (!value || typeof value !== "object" || methods.some((method) => typeof value[method] !== "function")) throw new MaintenanceError(MAINTENANCE_ERROR_CODES.INVALID_CONFIGURATION); return value; };
export const HOSTED_ADAPTER_BRAND = Symbol("agentpass.hosted-adapter");
export const maintenanceRepository = (value) => requireMethods(value, ["getPolicy", "saveReceipt"]);
export const maintenanceProvider = (value) => requireMethods(value, ["reserveOperation", "inspectOperation", "reconcileOperation"]);
export const maintenanceClock = (value) => requireMethods(value, ["now"]);
export const maintenanceUuid = (value) => requireMethods(value, ["randomUUID"]);
export const maintenanceSandbox = (value) => requireMethods(value, ["reserve", "inspect"]);
export const isTestOnlyDependency = (value) => value?.testOnly === true;
