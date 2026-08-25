export const SMALL_SOFTWARE_ERROR_CODES = Object.freeze({
  INVALID_CONFIGURATION: "small_software.invalid_configuration",
  INVALID_INPUT: "small_software.invalid_input",
  DEPENDENCY_UNAVAILABLE: "small_software.dependency_unavailable",
  OPERATION_NOT_FOUND: "small_software.operation_not_found",
  OPERATION_FAILED: "small_software.operation_failed",
  CONFLICT: "small_software.conflict",
  DIGEST_MISMATCH: "small_software.digest_mismatch",
  IDEMPOTENCY_CONFLICT: "small_software.idempotency_conflict",
  NOT_READY: "small_software.not_ready",
  RECONCILIATION_REQUIRED: "small_software.reconciliation_required"
});

const MESSAGES = Object.freeze({
  [SMALL_SOFTWARE_ERROR_CODES.INVALID_CONFIGURATION]: "Small Software service configuration is invalid",
  [SMALL_SOFTWARE_ERROR_CODES.INVALID_INPUT]: "Small Software request is invalid",
  [SMALL_SOFTWARE_ERROR_CODES.DEPENDENCY_UNAVAILABLE]: "Small Software dependency is unavailable",
  [SMALL_SOFTWARE_ERROR_CODES.OPERATION_NOT_FOUND]: "Small Software operation was not found",
  [SMALL_SOFTWARE_ERROR_CODES.OPERATION_FAILED]: "Small Software operation failed",
  [SMALL_SOFTWARE_ERROR_CODES.CONFLICT]: "Small Software state conflicts with the request",
  [SMALL_SOFTWARE_ERROR_CODES.DIGEST_MISMATCH]: "Small Software content digest does not match",
  [SMALL_SOFTWARE_ERROR_CODES.IDEMPOTENCY_CONFLICT]: "Small Software idempotency key was reused with different content",
  [SMALL_SOFTWARE_ERROR_CODES.NOT_READY]: "Small Software operation is not ready",
  [SMALL_SOFTWARE_ERROR_CODES.RECONCILIATION_REQUIRED]: "Small Software provider state requires reconciliation"
});

export class SmallSoftwareError extends Error {
  constructor(code, details = undefined) {
    super(MESSAGES[code] ?? MESSAGES[SMALL_SOFTWARE_ERROR_CODES.INVALID_INPUT]);
    this.name = "SmallSoftwareError";
    this.code = code;
    if (details !== undefined) this.details = Object.freeze({ ...details });
  }
}

export const smallSoftwareMessage = (code) => MESSAGES[code] ?? MESSAGES[SMALL_SOFTWARE_ERROR_CODES.INVALID_INPUT];
