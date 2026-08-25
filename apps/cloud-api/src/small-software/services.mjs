import { SmallSoftwareError, SMALL_SOFTWARE_ERROR_CODES } from "./errors.mjs";
import { smallSoftwareProvider, smallSoftwareRepository, smallSoftwareClock, smallSoftwareUuid, isTestOnlyDependency } from "./interfaces.mjs";

const fail = (code, cause) => { throw new SmallSoftwareError(code, cause ? { cause } : {}); };

export const createSmallSoftwareService = ({ profile = "hosted", repository, provider, clock, uuid } = {}) => {
  if (profile !== "hosted" && profile !== "test") fail(SMALL_SOFTWARE_ERROR_CODES.INVALID_CONFIGURATION);
  if (profile === "hosted" && [repository, provider, clock, uuid].some(isTestOnlyDependency)) {
    fail(SMALL_SOFTWARE_ERROR_CODES.INVALID_CONFIGURATION);
  }
  const repo = smallSoftwareRepository(repository);
  const external = smallSoftwareProvider(provider);
  const time = smallSoftwareClock(clock);
  const ids = smallSoftwareUuid(uuid);
  return Object.freeze({
    async reserveBuild(input) {
      if (!input || typeof input !== "object") fail(SMALL_SOFTWARE_ERROR_CODES.INVALID_INPUT);
      try {
        const operationId = ids.randomUUID();
        const reservation = await external.reserveOperation({ operationId, kind: "build", input, reservedAt: time.now() });
        return Object.freeze({ operationId, reservation });
      } catch (error) { fail(SMALL_SOFTWARE_ERROR_CODES.OPERATION_FAILED, error); }
    },
    async inspectBuild(operationId) {
      if (typeof operationId !== "string" || operationId.length === 0) fail(SMALL_SOFTWARE_ERROR_CODES.INVALID_INPUT);
      try {
        const result = await external.inspectOperation(operationId);
        if (result === undefined || result === null) fail(SMALL_SOFTWARE_ERROR_CODES.OPERATION_NOT_FOUND);
        return result;
      } catch (error) {
        if (error instanceof SmallSoftwareError) throw error;
        fail(SMALL_SOFTWARE_ERROR_CODES.OPERATION_FAILED, error);
      }
    },
    async saveBuildReceipt(applicationId, receipt) {
      if (typeof applicationId !== "string" || !receipt || typeof receipt !== "object") fail(SMALL_SOFTWARE_ERROR_CODES.INVALID_INPUT);
      try { return await repo.saveBuildReceipt(applicationId, receipt); }
      catch (error) { fail(SMALL_SOFTWARE_ERROR_CODES.DEPENDENCY_UNAVAILABLE, error); }
    }
  });
};
