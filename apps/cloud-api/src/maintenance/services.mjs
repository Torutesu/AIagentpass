import { MaintenanceError, MAINTENANCE_ERROR_CODES } from "./errors.mjs";
import { maintenanceRepository, maintenanceProvider, maintenanceClock, maintenanceUuid, isTestOnlyDependency } from "./interfaces.mjs";
const fail = (code, cause) => { throw new MaintenanceError(code, cause ? { cause } : {}); };
const hostedDependencies = new WeakSet();
const registerHostedDependency = (value) => { hostedDependencies.add(value); return value; };
export const createMaintenanceService = ({ profile = "hosted", repository, provider, clock, uuid } = {}) => {
  if (!["hosted", "test"].includes(profile) || (profile === "hosted" && ([repository, provider, clock, uuid].some(isTestOnlyDependency) || [repository, provider, clock, uuid].some((dependency) => !hostedDependencies.has(dependency))))) fail(MAINTENANCE_ERROR_CODES.INVALID_CONFIGURATION);
  const repo = maintenanceRepository(repository), external = maintenanceProvider(provider), time = maintenanceClock(clock), ids = maintenanceUuid(uuid);
  return Object.freeze({
    async reservePlan(input) { if (!input || typeof input !== "object") fail(MAINTENANCE_ERROR_CODES.INVALID_INPUT); try { const operationId = ids.randomUUID(); const reservation = await external.reserveOperation({ operationId, kind: "maintenance-plan", input, reservedAt: time.now() }); return Object.freeze({ operationId, reservation }); } catch (error) { fail(MAINTENANCE_ERROR_CODES.OPERATION_FAILED, error); } },
    async inspectPlan(operationId) { if (typeof operationId !== "string" || operationId.length === 0) fail(MAINTENANCE_ERROR_CODES.INVALID_INPUT); try { const result = await external.inspectOperation(operationId); if (result == null) fail(MAINTENANCE_ERROR_CODES.OPERATION_NOT_FOUND); return result; } catch (error) { if (error instanceof MaintenanceError) throw error; fail(MAINTENANCE_ERROR_CODES.OPERATION_FAILED, error); } },
    async reconcilePlan(operationId) { if (typeof operationId !== "string" || operationId.length === 0) fail(MAINTENANCE_ERROR_CODES.INVALID_INPUT); try { return await external.reconcileOperation(operationId); } catch (error) { fail(MAINTENANCE_ERROR_CODES.OPERATION_FAILED, error); } },
    async saveReceipt(applicationId, receipt) { if (typeof applicationId !== "string" || !receipt || typeof receipt !== "object") fail(MAINTENANCE_ERROR_CODES.INVALID_INPUT); try { return await repo.saveReceipt(applicationId, receipt); } catch (error) { fail(MAINTENANCE_ERROR_CODES.DEPENDENCY_UNAVAILABLE, error); } }
  });
};

export const createHostedMaintenanceService = (dependencies = {}) => { Object.values(dependencies).forEach(registerHostedDependency); return createMaintenanceService({ ...dependencies, profile: "hosted" }); };
