export const MAINTENANCE_ERROR_CODES = Object.freeze({
  INVALID_CONFIGURATION: "maintenance.invalid_configuration",
  INVALID_INPUT: "maintenance.invalid_input",
  DEPENDENCY_UNAVAILABLE: "maintenance.dependency_unavailable",
  OPERATION_NOT_FOUND: "maintenance.operation_not_found",
  OPERATION_FAILED: "maintenance.operation_failed"
});
const MESSAGES = Object.freeze({
  [MAINTENANCE_ERROR_CODES.INVALID_CONFIGURATION]: "Maintenance service configuration is invalid",
  [MAINTENANCE_ERROR_CODES.INVALID_INPUT]: "Maintenance request is invalid",
  [MAINTENANCE_ERROR_CODES.DEPENDENCY_UNAVAILABLE]: "Maintenance dependency is unavailable",
  [MAINTENANCE_ERROR_CODES.OPERATION_NOT_FOUND]: "Maintenance operation was not found",
  [MAINTENANCE_ERROR_CODES.OPERATION_FAILED]: "Maintenance operation failed"
});
export class MaintenanceError extends Error {
  constructor(code) { super(MESSAGES[code] ?? MESSAGES[MAINTENANCE_ERROR_CODES.INVALID_INPUT]); this.name = "MaintenanceError"; this.code = code; }
}
