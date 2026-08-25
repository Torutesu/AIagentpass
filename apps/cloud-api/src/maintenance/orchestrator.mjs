import { sha256 } from "../../../../packages/maintenance-contracts/src/index.mjs";
import { MaintenanceError, MAINTENANCE_ERROR_CODES } from "./errors.mjs";
import { maintenanceEffectRepository, maintenanceJobRepository, maintenancePullRequestRepository, maintenanceResultRepository } from "./interfaces.mjs";
import { planMaintenanceJob } from "./planner.mjs";

const fail = (code, cause = undefined) => { const error = new MaintenanceError(code); if (cause !== undefined) error.cause = undefined; throw error; };
const effectId = (value) => typeof value === "string" ? value : value?.effect_id ?? value?.effectId;

/**
 * Durable maintenance orchestration boundary. The agent/workspace is passed
 * only to executeEffect and receives the already-reserved effect metadata; it
 * never receives a repository connector or installation token.
 */
export function createMaintenanceOrchestrator({ jobs, effects, results, pullRequests } = {}) {
  let jobRepository, effectRepository, resultRepository, pullRequestRepository;
  try { jobRepository = maintenanceJobRepository(jobs); effectRepository = maintenanceEffectRepository(effects); resultRepository = maintenanceResultRepository(results); pullRequestRepository = maintenancePullRequestRepository(pullRequests); }
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
    async saveResult(result) { try { return await resultRepository.saveResult(result); } catch (error) { fail(MAINTENANCE_ERROR_CODES.DEPENDENCY_UNAVAILABLE, error); } },
    async savePullRequest(pullRequest) { try { return await pullRequestRepository.savePullRequest(pullRequest); } catch (error) { fail(MAINTENANCE_ERROR_CODES.DEPENDENCY_UNAVAILABLE, error); } },
    async getJob(jobId) { if (typeof jobId !== "string" || !jobId) fail(MAINTENANCE_ERROR_CODES.INVALID_INPUT); try { const job = await jobRepository.getJob(jobId); if (job == null) fail(MAINTENANCE_ERROR_CODES.OPERATION_NOT_FOUND); return job; } catch (error) { if (error instanceof MaintenanceError) throw error; fail(MAINTENANCE_ERROR_CODES.DEPENDENCY_UNAVAILABLE, error); } },
    async updateJob(jobId, patch) { if (typeof jobId !== "string" || !jobId || !patch || typeof patch !== "object") fail(MAINTENANCE_ERROR_CODES.INVALID_INPUT); try { return await jobRepository.updateJob(jobId, patch); } catch (error) { fail(MAINTENANCE_ERROR_CODES.DEPENDENCY_UNAVAILABLE, error); } }
  });
}
