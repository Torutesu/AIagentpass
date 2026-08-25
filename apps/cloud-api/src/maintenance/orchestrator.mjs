import { sha256, validateMaintenanceReceipt } from "../../../../packages/maintenance-contracts/src/index.mjs";
import { MaintenanceError, MAINTENANCE_ERROR_CODES } from "./errors.mjs";
import { maintenanceEffectRepository, maintenanceJobRepository, maintenancePullRequestRepository, maintenanceReceiptRepository, maintenanceResultRepository } from "./interfaces.mjs";
import { planMaintenanceJob } from "./planner.mjs";
import { createPatchProposal } from "./patch-agent.mjs";
import { verifyMaintenancePatch } from "./verification.mjs";

const fail = (code, cause = undefined) => { const error = new MaintenanceError(code); if (cause !== undefined) error.cause = undefined; throw error; };
const effectId = (value) => typeof value === "string" ? value : value?.effect_id ?? value?.effectId;

/**
 * Durable maintenance orchestration boundary. The agent/workspace is passed
 * only to executeEffect and receives the already-reserved effect metadata; it
 * never receives a repository connector or installation token.
 */
export function createMaintenanceOrchestrator({ jobs, effects, results, pullRequests, receipts } = {}) {
  let jobRepository, effectRepository, resultRepository, pullRequestRepository, receiptRepository;
  try { jobRepository = maintenanceJobRepository(jobs); effectRepository = maintenanceEffectRepository(effects); resultRepository = maintenanceResultRepository(results); pullRequestRepository = maintenancePullRequestRepository(pullRequests); receiptRepository = receipts === undefined ? null : maintenanceReceiptRepository(receipts); }
  catch { fail(MAINTENANCE_ERROR_CODES.INVALID_CONFIGURATION); }
  return Object.freeze({
    planJob: planMaintenanceJob,
    async reserveJob(input) {
      const planned = planMaintenanceJob(input);
      try { const stored = await jobRepository.reserveJob({ plan: planned.plan, job: planned.job, preimage: planned.preimage }); return Object.freeze({ ...planned, stored }); }
      catch (error) { fail(MAINTENANCE_ERROR_CODES.DEPENDENCY_UNAVAILABLE, error); }
    },
    async executeEffect({ job, kind, idempotencyKey, request, execute }) {
      if (!job || typeof job !== "object" || typeof execute !== "function" || typeof kind !== "string" || typeof idempotencyKey !== "string") fail(MAINTENANCE_ERROR_CODES.INVALID_INPUT);
      const requestDigest = sha256(request ?? {});
      let reserved;
      try { reserved = await effectRepository.reserve({ job_id: job.job_id, organization_id: job.organization_id, effect_kind: kind, idempotency_key: idempotencyKey, request_digest: requestDigest }); }
      catch (error) { fail(MAINTENANCE_ERROR_CODES.DEPENDENCY_UNAVAILABLE, error); }
      const id = effectId(reserved);
      if (!id) fail(MAINTENANCE_ERROR_CODES.OPERATION_FAILED);
      try {
        const response = await execute(Object.freeze({ effect_id: id, job_id: job.job_id, request_digest: requestDigest }));
        const responseDigest = sha256(response ?? null);
        await effectRepository.complete(id, responseDigest);
        return Object.freeze({ effect_id: id, state: "completed", response_digest: responseDigest });
      } catch (error) {
        try { await effectRepository.reconcile(id, "uncertain"); } catch { /* preserve the original bounded operation error */ }
        fail(MAINTENANCE_ERROR_CODES.OPERATION_FAILED, error);
      }
    },
    /**
     * Reserve and return a bounded patch proposal. The candidate is structured
     * data only; no shell, repository connector, model, or credential is
     * passed to the maintenance agent boundary.
     */
    async proposePatch({ job, plan, advisory, snapshot, policy, changes, tests, conformance, createdAt } = {}) {
      if (!job || typeof job !== "object") fail(MAINTENANCE_ERROR_CODES.INVALID_INPUT);
      let proposal;
      try { proposal = createPatchProposal({ job, plan, advisory, snapshot, policy, changes, tests, conformance, createdAt }); }
      catch (error) { if (error?.code?.startsWith("maintenance.patch_agent.")) throw error; fail(MAINTENANCE_ERROR_CODES.INVALID_INPUT, error); }
      const effect = await this.executeEffect({ job, kind: "patch_propose", idempotencyKey: proposal.proposal_id, request: { plan_id: proposal.plan_id, patch_digest: proposal.patch_digest, changed_paths: proposal.changed_paths }, execute: async () => proposal });
      return Object.freeze({ proposal, effect });
    },
    /** Aggregate supplied evidence only; this boundary never executes tests. */
    async verifyPatch({ job, proposal, evidence, createdAt } = {}) {
      let result;
      try { result = verifyMaintenancePatch({ job, proposal, evidence, createdAt }); }
      catch (error) { if (error?.code?.startsWith("maintenance.verification.")) throw error; fail(MAINTENANCE_ERROR_CODES.INVALID_INPUT, error); }
      try { return await resultRepository.saveResult(result); } catch (error) { fail(MAINTENANCE_ERROR_CODES.DEPENDENCY_UNAVAILABLE, error); }
    },
    async saveResult(result) { try { return await resultRepository.saveResult(result); } catch (error) { fail(MAINTENANCE_ERROR_CODES.DEPENDENCY_UNAVAILABLE, error); } },
    async savePullRequest(pullRequest) { try { return await pullRequestRepository.savePullRequest(pullRequest); } catch (error) { fail(MAINTENANCE_ERROR_CODES.DEPENDENCY_UNAVAILABLE, error); } },
    async saveReceipt(receipt) {
      if (receiptRepository === null) fail(MAINTENANCE_ERROR_CODES.INVALID_CONFIGURATION);
      try {
        validateMaintenanceReceipt(receipt);
        const receiptDigest = sha256(receipt);
        return await receiptRepository.saveReceipt({ ...receipt, receipt_digest: receiptDigest });
      } catch (error) {
        if (error?.name === "MaintenanceContractError") fail(MAINTENANCE_ERROR_CODES.INVALID_INPUT);
        fail(MAINTENANCE_ERROR_CODES.DEPENDENCY_UNAVAILABLE, error);
      }
    },
    async getJob(subject) { if (!subject || typeof subject !== "object" || typeof (subject.organization_id ?? subject.organizationId) !== "string" || typeof (subject.job_id ?? subject.jobId) !== "string") fail(MAINTENANCE_ERROR_CODES.INVALID_INPUT); try { const job = await jobRepository.getJob(subject); if (job == null) fail(MAINTENANCE_ERROR_CODES.OPERATION_NOT_FOUND); return job; } catch (error) { if (error instanceof MaintenanceError) throw error; fail(MAINTENANCE_ERROR_CODES.DEPENDENCY_UNAVAILABLE, error); } },
    async updateJob(subject, patch) { if (!subject || typeof subject !== "object" || typeof (subject.organization_id ?? subject.organizationId) !== "string" || typeof (subject.job_id ?? subject.jobId) !== "string" || !patch || typeof patch !== "object") fail(MAINTENANCE_ERROR_CODES.INVALID_INPUT); try { return await jobRepository.updateJob(subject, patch); } catch (error) { fail(MAINTENANCE_ERROR_CODES.DEPENDENCY_UNAVAILABLE, error); } }
  });
}
