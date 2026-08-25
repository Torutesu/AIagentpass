import { normalizeBuildReceipt } from "../../../../packages/small-software-contracts/src/index.mjs";
import { SmallSoftwareError, SMALL_SOFTWARE_ERROR_CODES } from "./errors.mjs";
import { smallSoftwareBuildRunner, smallSoftwareClock, smallSoftwareUuid } from "./interfaces.mjs";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const fail = (code, details) => { throw new SmallSoftwareError(code, details); };

/**
 * Provider-neutral build boundary. The runner is expected to execute in an
 * isolated environment and return only a normalized build receipt; it is not
 * given AgentPass production credentials by this service.
 */
export function createSmallSoftwareBuildService({ runner, clock, uuid, profile = "hosted" } = {}) {
  if (profile === "hosted" && [runner, clock, uuid].some((value) => value?.testOnly === true)) fail(SMALL_SOFTWARE_ERROR_CODES.INVALID_CONFIGURATION);
  const external = smallSoftwareBuildRunner(runner);
  const time = smallSoftwareClock(clock);
  const ids = smallSoftwareUuid(uuid);
  return Object.freeze({
    async reserve(input = {}) {
      if (!input || typeof input !== "object" || typeof input.source_bundle_digest !== "string") fail(SMALL_SOFTWARE_ERROR_CODES.INVALID_INPUT);
      const operationId = input.operation_id ?? ids.randomUUID();
      if (typeof operationId !== "string" || !UUID.test(operationId)) fail(SMALL_SOFTWARE_ERROR_CODES.INVALID_INPUT, { issue: "operation_id" });
      try {
        const reservation = await external.reserve({
          operation_id: operationId,
          operationId,
          kind: "build",
          source_bundle_digest: input.source_bundle_digest,
          organization_id: input.organization_id,
          app_id: input.app_id,
          request_digest: input.request_digest,
          reserved_at: time.now()
        });
        return Object.freeze({ operationId, reservation });
      } catch { fail(SMALL_SOFTWARE_ERROR_CODES.OPERATION_FAILED); }
    },
    async inspect(operationId, expectedSourceDigest) {
      assertOperationId(operationId);
      let result;
      try { result = await external.inspect(operationId); }
      catch { fail(SMALL_SOFTWARE_ERROR_CODES.OPERATION_FAILED); }
      if (result === undefined || result === null) fail(SMALL_SOFTWARE_ERROR_CODES.OPERATION_NOT_FOUND);
      if (result.status && !["succeeded", "completed", "failed"].includes(result.status) && !result.receipt && !result.build_receipt) {
        fail(SMALL_SOFTWARE_ERROR_CODES.NOT_READY, { stage: "build" });
      }
      const receiptInput = result.receipt ?? result.build_receipt ?? (result.kind === "agentpass.build-receipt" ? result : undefined);
      if (!receiptInput) fail(SMALL_SOFTWARE_ERROR_CODES.NOT_READY, { stage: "build" });
      let receipt;
      try { receipt = normalizeBuildReceipt(receiptInput); }
      catch { fail(SMALL_SOFTWARE_ERROR_CODES.OPERATION_FAILED); }
      if (expectedSourceDigest !== undefined && receipt.source_bundle_digest !== expectedSourceDigest) {
        fail(SMALL_SOFTWARE_ERROR_CODES.DIGEST_MISMATCH, { field: "source_bundle_digest" });
      }
      if (receipt.result !== "succeeded") fail(SMALL_SOFTWARE_ERROR_CODES.OPERATION_FAILED, { stage: "build" });
      return receipt;
    },
    async reconcile(operationId, expectedSourceDigest) {
      assertOperationId(operationId);
      let result;
      try { result = await external.reconcile(operationId); }
      catch { fail(SMALL_SOFTWARE_ERROR_CODES.OPERATION_FAILED); }
      if (result === undefined || result === null) fail(SMALL_SOFTWARE_ERROR_CODES.RECONCILIATION_REQUIRED, { stage: "build" });
      return inspectReceiptResult(result, expectedSourceDigest);
    }
  });
}

function inspectReceiptResult(result, expectedSourceDigest) {
  const receiptInput = result.receipt ?? result.build_receipt ?? (result.kind === "agentpass.build-receipt" ? result : undefined);
  if (!receiptInput) fail(SMALL_SOFTWARE_ERROR_CODES.RECONCILIATION_REQUIRED, { stage: "build" });
  let receipt;
  try { receipt = normalizeBuildReceipt(receiptInput); }
  catch { fail(SMALL_SOFTWARE_ERROR_CODES.OPERATION_FAILED); }
  if (expectedSourceDigest !== undefined && receipt.source_bundle_digest !== expectedSourceDigest) fail(SMALL_SOFTWARE_ERROR_CODES.DIGEST_MISMATCH, { field: "source_bundle_digest" });
  if (receipt.result !== "succeeded") fail(SMALL_SOFTWARE_ERROR_CODES.OPERATION_FAILED, { stage: "build" });
  return receipt;
}

function assertOperationId(operationId) {
  if (typeof operationId !== "string" || !UUID.test(operationId)) fail(SMALL_SOFTWARE_ERROR_CODES.INVALID_INPUT, { issue: "operation_id" });
}
