export const SMALL_SOFTWARE_ERROR_CODES = Object.freeze({
  INVALID_CONFIGURATION: "small_software.invalid_configuration",
  INVALID_INPUT: "small_software.invalid_input",
  DEPENDENCY_UNAVAILABLE: "small_software.dependency_unavailable",
  OPERATION_NOT_FOUND: "small_software.operation_not_found",
  OPERATION_FAILED: "small_software.operation_failed"
});

const MESSAGES = Object.freeze({
  [SMALL_SOFTWARE_ERROR_CODES.INVALID_CONFIGURATION]: "Small Software service configuration is invalid",
  [SMALL_SOFTWARE_ERROR_CODES.INVALID_INPUT]: "Small Software request is invalid",
  [SMALL_SOFTWARE_ERROR_CODES.DEPENDENCY_UNAVAILABLE]: "Small Software dependency is unavailable",
  [SMALL_SOFTWARE_ERROR_CODES.OPERATION_NOT_FOUND]: "Small Software operation was not found",
  [SMALL_SOFTWARE_ERROR_CODES.OPERATION_FAILED]: "Small Software operation failed"
});

export class SmallSoftwareError extends Error {
  constructor(code) {
    super(MESSAGES[code] ?? MESSAGES[SMALL_SOFTWARE_ERROR_CODES.INVALID_INPUT]);
    this.name = "SmallSoftwareError";
    this.code = code;
  }
}

export const smallSoftwareMessage = (code) => MESSAGES[code] ?? MESSAGES[SMALL_SOFTWARE_ERROR_CODES.INVALID_INPUT];
